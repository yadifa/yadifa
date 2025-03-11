/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
 * The YADIFA TM software product is provided under the BSD 3-clause license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *        * Redistributions of source code must retain the above copyright
 *          notice, this list of conditions and the following disclaimer.
 *        * Redistributions in binary form must reproduce the above copyright
 *          notice, this list of conditions and the following disclaimer in the
 *          documentation and/or other materials provided with the distribution.
 *        * Neither the name of EURid nor the names of its contributors may be
 *          used to endorse or promote products derived from this software
 *          without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *----------------------------------------------------------------------------*/

#include <fcntl.h>

/** @defgroup test
 *  @ingroup test
 *  @brief test
 *
 * Sends queries : valid ones, tailored-corrupted ones, garbage ones.
 * All opcodes are tried.
 *
 */

#include <unistd.h>
#include <stddef.h>

#include <dnscore/dnscore.h>

#include <dnscore/random.h>
#include <dnscore/config_cmdline.h>
#include <dnscore/signals.h>
#include <dnscore/dns_message.h>
#include <dnscore/logger.h>
#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnscore/fingerprint.h>
#include <dnscore/dns_packet_reader.h>
#include <dnscore/dns_packet_writer.h>
#include <dnscore/tsig.h>
#include <dnscore/fdtools.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/counter_output_stream.h>
#include <dnscore/network.h>
#include <dnscore/dnsname.h>
#include <dnscore/config_settings.h>

#include <dnscore/thread_pool.h>

#define TIMEOUT_S                  1
#define TIMEOUT_US                 100000

#define PROCOTOL_TEST_SECTION_NAME "protocol-test"

struct protocol_test_settings_s
{
    host_address_t    *server;
    uint8_t           *fqdn;
    struct tsig_key_s *tsig_key_item; // for the -y option
};
typedef struct protocol_test_settings_s protocol_test_settings_t;

#define CONFIG_TYPE protocol_test_settings_t
CONFIG_BEGIN(protocol_test_settings_desc)
CONFIG_HOST_LIST_EX(server, "127.0.0.1", CONFIG_HOST_LIST_FLAGS_DEFAULT, 1)
CONFIG_FQDN(fqdn, ".")
CONFIG_TSIG_ITEM(tsig_key_item, NULL)
CONFIG_END(protocol_test_settings_desc)

CMDLINE_BEGIN(protocol_test_cmdline)
// CMDLINE_FILTER(ctrl_cmdline_filter_callback, NULL) // NULL is passed to the callback as a parameter (callback_owned)
// main hooks
CMDLINE_INDENT(4)
CMDLINE_IMSG("options:", "")
CMDLINE_SECTION(PROCOTOL_TEST_SECTION_NAME)
CMDLINE_OPT("server", 's', "server")
CMDLINE_HELP("<host>", "sets the name server to connect to")
CMDLINE_IMSGS("", "can be an ip address or an ip address with a port number")
CMDLINE_IMSGS("", "e.g. \"192.0.2.1 port 53\"")
CMDLINE_IMSGS("", "note: the quotes are needed")
CMDLINE_IMSGS("@<host>", "equivalent to --server <host>")
CMDLINE_OPT("key", 'y', "tsig_key_item")
CMDLINE_HELP("[hmac:]name:key", "TSIG key to use for authentication (default hmac: hmac-md5)")
CMDLINE_OPT("domain", 'd', "fqdn")

CMDLINE_VERSION_HELP(protocol_test_cmdline)
CMDLINE_END(protocol_test_cmdline)

static protocol_test_settings_t g_protocol_test_settings;

static ya_result                protocol_test_message_udp_with_timeout(dns_message_t *mesg, const host_address_t *server, int seconds, dns_message_t *answ)
{
    yassert(mesg != NULL);
    yassert(server != NULL);

    /* connect the server */

    ya_result ret;

    uint16_t  id;
    uint16_t  rtype = dns_message_parse_query_type(mesg);
    uint16_t  rclass = dns_message_parse_query_class(mesg);
    bool      has_fqdn = false;
    uint8_t   fqdn[DOMAIN_LENGTH_MAX + 1];

    formatln("sending message with ID %i to %{hostaddr} for domain %{dnsname} %{dnstype} %{dnsclass}", dns_message_get_id(mesg), server, dns_message_parse_query_fqdn(mesg), &rtype, &rclass);
    flushout();

    if(ISOK(ret = dns_message_set_sender_from_host_address(mesg, server)))
    {
        int sockfd;

        if((sockfd = socket(dns_message_get_sender_sa(mesg)->sa_family, SOCK_DGRAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_DGRAM))) >= 0)
        {
            ssize_t n;

            fd_setcloseonexec(sockfd);

            tcp_set_recvtimeout(sockfd, seconds, 0); /* half a second for UDP is a lot ... */

            if((n = dns_message_send_udp(mesg, sockfd)) == (ssize_t)dns_message_get_size(mesg))
            {
                socketaddress_t query_sa;
                int             query_sa_size = dns_message_get_sender_size(mesg);
                memcpy(&query_sa, dns_message_get_sender(mesg), query_sa_size);

                id = dns_message_get_id(mesg);

                if(dns_message_get_query_count_ne(mesg) != 0)
                {
                    has_fqdn = true;
                    dnsname_copy(fqdn, dns_message_get_buffer_const(mesg) + 12);
                }

                dns_message_recv_udp_reset(answ);
                dns_message_reset_control_size(mesg);

                int64_t time_limit = seconds;
                time_limit *= 1000000ULL;
                time_limit += timeus();

                ret = SUCCESS;

                for(;;)
                {
                    for(;;)
                    {
                        n = dns_message_recv_udp(answ, sockfd);

                        if(n >= 0)
                        {
                            break;
                        }

                        if(errno != EINTR)
                        {
                            break;
                        }
                    }

                    if(n < 0)
                    {
                        break;
                    }

                    // check the id is right

                    if(dns_message_get_id(answ) == id)
                    {
                        // check that the sender is the one we spoke to

                        if(sockaddr_equals(&query_sa.sa, dns_message_get_sender_sa(answ)))
                        {
                            if(ISOK(ret = dns_message_process_lenient(answ)))
                            {
                                // check the domain is right

                                if(!has_fqdn || dnsname_equals(fqdn, dns_message_get_canonised_fqdn(answ)))
                                {
                                    break;
                                }
                                else
                                {
                                    formatln("ERROR: %{hostaddr} replied for a different domain (%{dnsname})", server, dns_message_get_canonised_fqdn(answ));

                                    ret = MESSAGE_UNEXPECTED_ANSWER_DOMAIN;
                                }
                            }

                            // ret is set to an error
                        }
                        else
                        {
                            formatln("ERROR: %{sockaddr} replied instead of %{hostaddr}", dns_message_get_sender_sa(mesg), server);

                            ret = INVALID_MESSAGE;
                        }
                    }
                    else
                    {
                        formatln("ERROR: %{hostaddr} replied with a different ID (%i", server, dns_message_get_id(mesg));
                        ret = MESSAGE_HAS_WRONG_ID;
                    }

                    int64_t time_now = timeus();

                    if(time_now >= time_limit)
                    {
                        break;
                    }

                    int64_t time_remaining = time_limit - time_now;

                    tcp_set_recvtimeout(sockfd, time_remaining / 1000000ULL, time_remaining % 1000000ULL); /* half a second for UDP is a lot ... */

                    formatln(
                        "WARNING: sending message with ID %i to %{hostaddr} for domain %{dnsname} %{dnstype} "
                        "%{dnsclass} failed",
                        dns_message_get_id(mesg),
                        server,
                        dns_message_parse_query_fqdn(mesg),
                        &rtype,
                        &rclass);
                }

                if((n < 0) && ISOK(ret))
                {
                    ret = ERRNO_ERROR;
                }

                /* timeout */
            }
            else
            {
                ret = (n < 0) ? n : ERROR;
            }

            socketclose_ex(sockfd);
        }
        else
        {
            ret = ERRNO_ERROR;
        }
    }

    return ret;
}

static ya_result hammer_message_udp_with_timeout(dns_message_t *mesg, const host_address_t *server, dns_message_t *answ)
{
    yassert(mesg != NULL);
    yassert(server != NULL);

    /* connect the server */

    ya_result ret;

    // const uint32_t to_us = 5000ULL; // 5 ms
    const uint32_t to_us = 5000000ULL; // 5s

    uint16_t       id;

    if(ISOK(ret = dns_message_set_sender_from_host_address(mesg, server)))
    {
        int sockfd;

        if((sockfd = socket(dns_message_get_sender_sa(mesg)->sa_family, SOCK_DGRAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_DGRAM))) >= 0)
        {
            ssize_t n;

            fd_setcloseonexec(sockfd);

            tcp_set_recvtimeout(sockfd, to_us / 1000000ULL, to_us % 1000000ULL);

            if((n = dns_message_send_udp(mesg, sockfd)) == (ssize_t)dns_message_get_size(mesg))
            {
                socketaddress_t query_sa;
                int             query_sa_size = dns_message_get_sender_size(mesg);
                memcpy(&query_sa, dns_message_get_sender(mesg), query_sa_size);

                id = dns_message_get_id(mesg);

                dns_message_recv_udp_reset(answ);
                dns_message_reset_control_size(mesg);

                int64_t time_limit = timeus();
                time_limit += to_us;

                ret = SUCCESS;

                for(;;)
                {
                    for(;;)
                    {
                        n = dns_message_recv_udp(answ, sockfd);

                        if(n >= 0)
                        {
                            break;
                        }

                        if(errno != EINTR)
                        {
                            break;
                        }
                    }

                    if(n < 0)
                    {
                        break;
                    }

                    // check the id is right

                    if(dns_message_get_id(answ) == id)
                    {
                        // check that the sender is the one we spoke to

                        if(sockaddr_equals(&query_sa.sa, dns_message_get_sender_sa(answ)))
                        {
                            break;

                            // ret is set to an error
                        }
                        else
                        {
                            ret = INVALID_MESSAGE;
                        }
                    }
                    else
                    {
                        ret = MESSAGE_HAS_WRONG_ID;
                    }

                    int64_t time_now = timeus();

                    if(time_now >= time_limit)
                    {
                        break;
                    }

                    int64_t time_remaining = time_limit - time_now;

                    tcp_set_recvtimeout(sockfd, time_remaining / 1000000ULL, time_remaining % 1000000ULL); /* half a second for UDP is a lot ... */
                }

                if((n < 0) && ISOK(ret))
                {
                    ret = ERRNO_ERROR;
                }

                /* timeout */
            }
            else
            {
                ret = (n < 0) ? n : ERROR;
            }

            socketclose_ex(sockfd);
        }
        else
        {
            ret = ERRNO_ERROR;
        }
    }

    return ret;
}

static void update_test(const host_address_t *server, const uint8_t *fqdn)
{
    // send an update packet in UDP
    // check the answer

    formatln("update_test: %{hostaddr} %{dnsname} (begin)", server, fqdn);

    random_ctx_t               rndctx = random_init(0);
    dns_message_t             *mesg = dns_message_new_instance();
    ya_result                  ret;
    uint16_t                   id;
    uint8_t                    ns_fqdn[128];
    uint8_t                    a_ns_fqdn[128];
    struct dns_packet_writer_s pw;

    memcpy(ns_fqdn, "\017udp-update-test", 16);
    dnsname_copy(&ns_fqdn[16], fqdn);

    memcpy(a_ns_fqdn, "\003ns1\017udp-update-test", 20);
    dnsname_copy(&a_ns_fqdn[20], fqdn);

    static const uint8_t ip_rdata[4] = {1, 0, 0, 127};

    id = (uint16_t)random_next(rndctx);
    dns_message_update_init(mesg, id, fqdn, CLASS_IN, dns_message_get_buffer_size_max(mesg), &pw);
    dns_message_update_add_record(mesg, &pw, ns_fqdn, TYPE_NS, CLASS_IN, 86400, dnsname_len(a_ns_fqdn), a_ns_fqdn);
    dns_message_update_add_record(mesg, &pw, a_ns_fqdn, TYPE_A, CLASS_IN, 86400, 4, ip_rdata);
    dns_message_update_finalize(mesg, &pw);

    if(ISOK(ret = protocol_test_message_udp_with_timeout(mesg, server, TIMEOUT_S, mesg)))
    {
        if(dns_message_get_rcode(mesg) != RCODE_NOERROR)
        {
            formatln("WARNING: update_test: %{hostaddr} %{dnsname}: server answered with %s", server, fqdn, dns_message_rcode_get_name(dns_message_get_rcode(mesg)));
        }
    }
    else
    {
        formatln("ERROR: update_test: %{hostaddr} %{dnsname}: %r", server, fqdn, ret);
    }

    id = (uint16_t)random_next(rndctx);
    dns_message_update_init(mesg, id, fqdn, CLASS_IN, dns_message_get_buffer_size_max(mesg), &pw);
    dns_message_update_delete_record(mesg, &pw, ns_fqdn, TYPE_NS, dnsname_len(a_ns_fqdn), a_ns_fqdn);
    dns_message_update_delete_record(mesg, &pw, a_ns_fqdn, TYPE_A, 4, ip_rdata);
    dns_message_update_finalize(mesg, &pw);

    if(ISOK(ret = protocol_test_message_udp_with_timeout(mesg, server, TIMEOUT_S, mesg)))
    {
        if(dns_message_get_rcode(mesg) != RCODE_NOERROR)
        {
        }
    }
    else
    {
        formatln("ERROR: update_test: %{hostaddr} %{dnsname}: %r", server, fqdn, ret);
    }

    random_finalize(rndctx);
    dns_message_delete(mesg);

    formatln("update_test: %{hostaddr} %{dnsname} (end)", server, fqdn);
}

static void message_fingerprint(const dns_message_t *mesg)
{
    format("O=%s,R=%s,C=(%i,%i,%i,%i),F=",
           dns_message_opcode_get_name(dns_message_get_opcode(mesg) >> OPCODE_SHIFT),
           dns_message_rcode_get_name(dns_message_get_rcode(mesg)),
           dns_message_get_section_count(mesg, 0),
           dns_message_get_section_count(mesg, 1),
           dns_message_get_section_count(mesg, 2),
           dns_message_get_section_count(mesg, 3));
    if(dns_message_is_answer(mesg))
    {
        print("+QR");
    }
    if(dns_message_is_authoritative(mesg))
    {
        print("+AA");
    }
    if(dns_message_is_truncated(mesg))
    {
        print("+TC");
    }
    if(dns_message_has_recursion_desired(mesg))
    {
        print("+RD");
    }
    if(dns_message_has_recursion_available(mesg))
    {
        print("+RA");
    }
    if(dns_message_has_authenticated_data(mesg))
    {
        print("+AD");
    }
    if(dns_message_has_checking_disabled(mesg))
    {
        print("+CD");
    }
}

static void hammer_test(const host_address_t *server, const uint8_t *fqdn)
{
    static const uint16_t hammer_types[4] = {TYPE_SOA, TYPE_NS, TYPE_A, TYPE_AAAA};

    static const uint8_t  hammer_soa_rdata[] = {0, 0, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 0, 0, 3, 4};

    static const uint8_t  hammer_ns_rdata[] = {3, 'n', 's', '1', 5, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 2, 'e', 'u', 0};

    static const uint8_t  hammer_a_rdata[] = {127, 0, 0, 1};

    static const uint8_t  hammer_aaaa_rdata[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    static const uint8_t *hammer_rdata[4] = {hammer_soa_rdata, hammer_ns_rdata, hammer_a_rdata, hammer_aaaa_rdata};
    static const uint16_t hammer_rdata_size[4] = {sizeof(hammer_soa_rdata), sizeof(hammer_ns_rdata), sizeof(hammer_a_rdata), sizeof(hammer_aaaa_rdata)};

    //
    random_ctx_t   rndctx = random_init(0);
    dns_message_t *mesg = dns_message_new_instance();
    dns_message_t *answ = dns_message_new_instance();
    ya_result      ret;
    uint16_t       id;
    /*
    uint8_t ns_fqdn[128];
    uint8_t a_ns_fqdn[128];
    */
    struct dns_packet_writer_s pw;
    /*
    memcpy(ns_fqdn, "\017udp-update-test", 16);
    dnsname_copy(&ns_fqdn[16], fqdn);

    memcpy(a_ns_fqdn, "\003ns1\017udp-update-test", 20);
    dnsname_copy(&a_ns_fqdn[20], fqdn);
    */
    // static const uint8_t ip_rdata[4] = {1,0,0,127};

    // send queries with 0 to 2 items etc ...
    // truncate the packet down to 0 bytes long

    for(uint_fast8_t opcode = 0; opcode < 16; ++opcode)
    {
        flushout();

        for(uint_fast16_t qc = 0; qc <= 2; ++qc)
        {
            for(uint_fast16_t ac = 0; ac <= 2; ++ac)
            {
                for(uint_fast16_t nc = 0; nc <= 2; ++nc)
                {
                    for(uint_fast16_t rc = 0; rc <= 2; ++rc)
                    {
                        id = (uint16_t)random_next(rndctx);
                        dns_message_set_id(mesg, id);

                        dns_message_set_flags_hi(mesg, 0);
                        dns_message_set_flags_lo(mesg, 0);

                        dns_message_set_opcode(mesg, dns_message_make_opcode(opcode));

                        dns_message_set_query_answer_authority_additional_counts(mesg, qc, ac, nc, rc);

                        dns_packet_writer_create(&pw, dns_message_get_buffer(mesg), dns_message_get_buffer_size_max(mesg));

                        for(uint_fast16_t i = 0; i < qc; ++i)
                        {
                            // add a query record

                            dns_packet_writer_add_fqdn_uncompressed(&pw, fqdn);
                            dns_packet_writer_add_u16(&pw, hammer_types[i]);
                            dns_packet_writer_add_u16(&pw, CLASS_IN);
                        }

                        for(uint_fast16_t i = 0; i < ac; ++i)
                        {
                            // add an answer record

                            dns_packet_writer_add_fqdn_uncompressed(&pw, fqdn);
                            dns_packet_writer_add_u16(&pw, hammer_types[i]);
                            dns_packet_writer_add_u16(&pw, CLASS_IN);
                            dns_packet_writer_add_u32(&pw, ntohl(86400));
                            dns_packet_writer_add_u16(&pw, ntohs(hammer_rdata_size[i]));
                            dns_packet_writer_add_bytes(&pw, hammer_rdata[i], hammer_rdata_size[i]);
                        }

                        for(uint_fast16_t i = 0; i < ac; ++i)
                        {
                            // add an authority record

                            dns_packet_writer_add_fqdn_uncompressed(&pw, fqdn);
                            dns_packet_writer_add_u16(&pw, hammer_types[i]);
                            dns_packet_writer_add_u16(&pw, CLASS_IN);
                            dns_packet_writer_add_u32(&pw, ntohl(86400));
                            dns_packet_writer_add_u16(&pw, ntohs(hammer_rdata_size[i]));
                            dns_packet_writer_add_bytes(&pw, hammer_rdata[i], hammer_rdata_size[i]);
                        }

                        for(uint_fast16_t i = 0; i < ac; ++i)
                        {
                            // add an additional record

                            dns_packet_writer_add_fqdn_uncompressed(&pw, fqdn);
                            dns_packet_writer_add_u16(&pw, hammer_types[i]);
                            dns_packet_writer_add_u16(&pw, CLASS_IN);
                            dns_packet_writer_add_u32(&pw, ntohl(86400));
                            dns_packet_writer_add_u16(&pw, ntohs(hammer_rdata_size[i]));
                            dns_packet_writer_add_bytes(&pw, hammer_rdata[i], hammer_rdata_size[i]);
                        }

                        for(uint_fast32_t truncate_by = 0; truncate_by <= dns_packet_writer_get_offset(&pw); truncate_by = (truncate_by << 1) + 1)
                        {
                            dns_message_set_size(mesg, dns_packet_writer_get_offset(&pw) - truncate_by);

                            print("Q={");
                            message_fingerprint(mesg);
                            print("},A={");

                            if(ISOK(ret = hammer_message_udp_with_timeout(mesg, server, answ)))
                            {
                                message_fingerprint(answ);
                            }
                            else
                            {
                                format("ERROR=%x", ret);
                            }

                            if(truncate_by > 0)
                            {
                                format("},T={%i/%i", dns_packet_writer_get_offset(&pw) - truncate_by, dns_packet_writer_get_offset(&pw));
                            }

                            println("}");
                        }
                    }
                }
            }
        }
    }

    dns_message_delete(answ);
    dns_message_delete(mesg);
    random_finalize(rndctx);
}

static void corrupt_test(const host_address_t *server, const uint8_t *fqdn)
{
    (void)fqdn;
    println("corrupt_test");

    random_ctx_t   rndctx = random_init(0);
    dns_message_t *mesg = dns_message_new_instance();
    dns_message_t *answ = dns_message_new_instance();
    ya_result      ret;
    uint16_t       id;

    const uint32_t size = 4096;

    for(int_fast32_t count = 0; count < 64; ++count)
    {
        for(uint_fast8_t opcode = 0; opcode < 16; ++opcode)
        {
            flushout();

            for(uint_fast16_t qc = 0; qc <= 2; ++qc)
            {
                for(uint_fast16_t ac = 0; ac <= 2; ++ac)
                {
                    for(uint_fast16_t nc = 0; nc <= 2; ++nc)
                    {
                        for(uint_fast16_t rc = 0; rc <= 2; ++rc)
                        {
                            id = (uint16_t)random_next(rndctx);
                            dns_message_set_id(mesg, id);

                            dns_message_set_flags_hi(mesg, 0);
                            dns_message_set_flags_lo(mesg, 0);

                            dns_message_set_opcode(mesg, dns_message_make_opcode(opcode));

                            dns_message_set_query_answer_authority_additional_counts(mesg, qc, ac, nc, rc);

                            for(int_fast32_t c = 0; c < 256; ++c)
                            {
                                memset(dns_message_get_buffer(mesg) + DNS_HEADER_LENGTH, c, size - DNS_HEADER_LENGTH);

                                for(uint_fast32_t truncate_by = 0; truncate_by <= size; truncate_by = (truncate_by << 4) + 1)
                                {
                                    dns_message_set_size(mesg, size - truncate_by);

                                    print("Q={");
                                    message_fingerprint(mesg);
                                    print("},A={");

                                    if(ISOK(ret = hammer_message_udp_with_timeout(mesg, server, answ)))
                                    {
                                        message_fingerprint(answ);
                                    }
                                    else
                                    {
                                        format("ERROR=%x", ret);
                                    }

                                    if(truncate_by > 0)
                                    {
                                        format("},T={%i/%i", size - truncate_by, size);
                                    }

                                    formatln("},C=%02x", c);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    dns_message_delete(answ);
    dns_message_delete(mesg);
    random_finalize(rndctx);
}

static void compression_loop_test(const host_address_t *server, const uint8_t *fqdn)
{
    (void)fqdn;
    println("compression_loop_test");

    random_ctx_t   rndctx = random_init(0);
    dns_message_t *mesg = dns_message_new_instance();
    dns_message_t *clnr = dns_message_new_instance();
    dns_message_t *answ = dns_message_new_instance();
    ya_result      ret;
    uint16_t       id;
    /*
    static const uint8_t msg[]=
    {
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,

        0xc0, 0x0e, // 0x0c
        0xc0, 0x10, // 0x0e
        0xc0, 0x12, // 0x10
        0xc0, 0x14, // 0x12
        0xc0, 0x16, // 0x14
        0xc0, 0x18, // 0x16
    };
    */

    memset(dns_message_get_buffer(clnr), 63, dns_message_get_buffer_size_max(clnr));
    dns_message_set_flags_hi(clnr, 0);
    dns_message_set_flags_lo(clnr, 0);
    dns_message_set_query_answer_authority_additional_counts(clnr, 1, 65535, 65535, 65535);

    for(int_fast32_t i = 0; i < 64; ++i)
    {
        hammer_message_udp_with_timeout(clnr, server, answ);
    }

    for(uint_fast8_t opcode = 0; opcode < 16; ++opcode)
    {
        flushout();

        id = (uint16_t)random_next(rndctx);
        dns_message_set_id(mesg, id);

        dns_message_set_flags_hi(mesg, 0);
        dns_message_set_flags_lo(mesg, 0);

        dns_message_set_opcode(mesg, dns_message_make_opcode(opcode));

        dns_message_set_query_answer_authority_additional_counts(mesg, 1, 0, 0, 0);

        uint8_t *buffer = dns_message_get_buffer(mesg);

        for(int_fast32_t i = 0; i < 512; i += 2)
        {
            uint16_t o = (i + DNS_HEADER_LENGTH + 2) & 0x3fff;
            buffer[DNS_HEADER_LENGTH + i + 0] = 0xc0 | (o >> 8);
            buffer[DNS_HEADER_LENGTH + i + 1] = o;
        }

        buffer[DNS_HEADER_LENGTH + 512] = 0;
        SET_U16_AT(buffer[DNS_HEADER_LENGTH + 513], TYPE_SOA);
        SET_U16_AT(buffer[DNS_HEADER_LENGTH + 515], CLASS_IN);

        dns_message_set_size(mesg, 517);

        print("Q={");
        message_fingerprint(mesg);
        print("},A={");

        if(ISOK(ret = hammer_message_udp_with_timeout(mesg, server, answ)))
        {
            message_fingerprint(answ);
        }
        else
        {
            format("ERROR=%x", ret);
        }

        println("}");

        //

        hammer_message_udp_with_timeout(clnr, server, answ);

        //

        dns_message_set_size(mesg, 16);

        print("Q={");
        message_fingerprint(mesg);
        print("},A={");

        if(ISOK(ret = hammer_message_udp_with_timeout(mesg, server, answ)))
        {
            message_fingerprint(answ);
        }
        else
        {
            format("ERROR=%x", ret);
        }

        println("}");

        //

        hammer_message_udp_with_timeout(clnr, server, answ);

        //

        buffer[DNS_HEADER_LENGTH + 512] = 0xc0;
        buffer[DNS_HEADER_LENGTH + 513] = 0x0c;
        SET_U16_AT(buffer[DNS_HEADER_LENGTH + 514], TYPE_SOA);
        SET_U16_AT(buffer[DNS_HEADER_LENGTH + 516], CLASS_IN);

        dns_message_set_size(mesg, 517);

        print("Q={");
        message_fingerprint(mesg);
        print("},A={");

        if(ISOK(ret = hammer_message_udp_with_timeout(mesg, server, answ)))
        {
            message_fingerprint(answ);
        }
        else
        {
            format("ERROR=%x", ret);
        }

        println("}");

        //

        hammer_message_udp_with_timeout(clnr, server, answ);

        //
    }

    dns_message_delete(answ);
    dns_message_delete(clnr);
    dns_message_delete(mesg);
    random_finalize(rndctx);
}

static void compression_loop_test2(const host_address_t *server, const uint8_t *fqdn)
{
    println("compression_loop_test2");
    (void)fqdn;

    random_ctx_t   rndctx = random_init(0);
    dns_message_t *mesg = dns_message_new_instance();
    dns_message_t *clnr = dns_message_new_instance();
    dns_message_t *answ = dns_message_new_instance();
    ya_result      ret;
    uint16_t       id;
    /*
    static const uint8_t msg[]=
    {
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,

        0xc0, 0x0e, // 0x0c
        0xc0, 0x10, // 0x0e
        0xc0, 0x12, // 0x10
        0xc0, 0x14, // 0x12
        0xc0, 0x16, // 0x14
        0xc0, 0x18, // 0x16
    };
    */

    memset(dns_message_get_buffer(clnr), 63, dns_message_get_buffer_size_max(clnr));
    dns_message_set_flags_hi(clnr, 0);
    dns_message_set_flags_lo(clnr, 0);
    dns_message_set_query_answer_authority_additional_counts(clnr, 1, 65535, 65535, 65535);

    for(int_fast32_t i = 0; i < 64; ++i)
    {
        hammer_message_udp_with_timeout(clnr, server, answ);
    }

    for(uint_fast8_t opcode = 0; opcode < 16; ++opcode)
    {
        flushout();

        id = (uint16_t)random_next(rndctx);
        dns_message_set_id(mesg, id);

        dns_message_set_flags_hi(mesg, 0);
        dns_message_set_flags_lo(mesg, 0);

        dns_message_set_opcode(mesg, dns_message_make_opcode(opcode));

        dns_message_set_query_answer_authority_additional_counts(mesg, 1, 0, 0, 0);

        uint8_t *buffer = dns_message_get_buffer(mesg);

        buffer[DNS_HEADER_LENGTH + 0] = 3;
        buffer[DNS_HEADER_LENGTH + 1] = 'w';
        buffer[DNS_HEADER_LENGTH + 2] = 'w';
        buffer[DNS_HEADER_LENGTH + 3] = 'w';
        buffer[DNS_HEADER_LENGTH + 4] = 0xc0;
        buffer[DNS_HEADER_LENGTH + 5] = 0x0c;

        dns_message_set_size(mesg, DNS_HEADER_LENGTH + 6);

        print("Q={");
        message_fingerprint(mesg);
        print("},A={");

        if(ISOK(ret = hammer_message_udp_with_timeout(mesg, server, answ)))
        {
            message_fingerprint(answ);
        }
        else
        {
            format("ERROR=%x", ret);
        }

        println("}");

        //

        hammer_message_udp_with_timeout(clnr, server, answ);

        //

        dns_message_set_size(mesg, 16);

        print("Q={");
        message_fingerprint(mesg);
        print("},A={");

        if(ISOK(ret = hammer_message_udp_with_timeout(mesg, server, answ)))
        {
            message_fingerprint(answ);
        }
        else
        {
            format("ERROR=%x", ret);
        }

        println("}");

        //

        hammer_message_udp_with_timeout(clnr, server, answ);

        //

        buffer[DNS_HEADER_LENGTH + 512] = 0xc0;
        buffer[DNS_HEADER_LENGTH + 513] = 0x0c;
        SET_U16_AT(buffer[DNS_HEADER_LENGTH + 514], TYPE_SOA);
        SET_U16_AT(buffer[DNS_HEADER_LENGTH + 516], CLASS_IN);

        dns_message_set_size(mesg, 517);

        print("Q={");
        message_fingerprint(mesg);
        print("},A={");

        if(ISOK(ret = hammer_message_udp_with_timeout(mesg, server, answ)))
        {
            message_fingerprint(answ);
        }
        else
        {
            format("ERROR=%x", ret);
        }

        println("}");

        //

        hammer_message_udp_with_timeout(clnr, server, answ);

        //
    }

    dns_message_delete(answ);
    dns_message_delete(clnr);
    dns_message_delete(mesg);
    random_finalize(rndctx);
}

static void compression_loop_test3(const host_address_t *server, const uint8_t *fqdn)
{
    println("compression_loop_test3");
    flushout();

    random_ctx_t   rndctx = random_init(0);
    dns_message_t *mesg = dns_message_new_instance();
    dns_message_t *clnr = dns_message_new_instance();
    dns_message_t *answ = dns_message_new_instance();
    ya_result      ret;
    uint16_t       id;
    /*
    static const uint8_t msg[]=
    {
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,

        0xc0, 0x0e, // 0x0c
        0xc0, 0x10, // 0x0e
        0xc0, 0x12, // 0x10
        0xc0, 0x14, // 0x12
        0xc0, 0x16, // 0x14
        0xc0, 0x18, // 0x16
    };
    */

    memset(dns_message_get_buffer(clnr), 63, dns_message_get_buffer_size_max(clnr));
    dns_message_set_flags_hi(clnr, 0);
    dns_message_set_flags_lo(clnr, 0);
    dns_message_set_query_answer_authority_additional_counts(clnr, 1, 65535, 65535, 65535);

    for(int_fast32_t i = 0; i < 64; ++i)
    {
        hammer_message_udp_with_timeout(clnr, server, answ);
    }

    dns_message_make_notify(mesg, rand(), fqdn, TYPE_SOA, CLASS_IN);
    uint8_t *p = dns_message_get_buffer(mesg);
    p += DNS_HEADER_LENGTH;
    p += dnsname_len(p);
    p += 4;
    size_t here = p - dns_message_get_buffer(mesg);

    p[0] = 0xc0 | (here >> 8);
    p[1] = here & 0xff;
    p += 2;

    SET_U16_AT_P(p, TYPE_SOA);
    p += 2;

    SET_U16_AT_P(p, CLASS_IN);
    p += 2;

    SET_U32_AT_P(p, 86400);
    p += 4;

    SET_U16_AT_P(p, NU16(24));
    p += 2;

    p[0] = 0xc0 | (here >> 8);
    p[1] = here & 0xff;
    p += 2;

    p[0] = 0xc0 | (here >> 8);
    p[1] = here & 0xff;
    p += 2;

    SET_U32_AT_P(p, 86400);
    p += 4;
    SET_U32_AT_P(p, 86400);
    p += 4;
    SET_U32_AT_P(p, 86400);
    p += 4;
    SET_U32_AT_P(p, 86400);
    p += 4;
    SET_U32_AT_P(p, 86400);
    p += 4;

    dns_message_set_size(mesg, p - dns_message_get_buffer(mesg));
    dns_message_set_additional_count(mesg, 1);

    for(uint_fast32_t i = 0; i < 64; ++i)
    {
        flushout();

        for(uint_fast8_t opcode = 0; opcode < 16; ++opcode)
        {
            id = (uint16_t)random_next(rndctx);
            dns_message_set_id(mesg, id);

            dns_message_set_flags_hi(mesg, 0);
            dns_message_set_flags_lo(mesg, 0);

            dns_message_set_opcode(mesg, dns_message_make_opcode(opcode));

            print("Q={");
            message_fingerprint(mesg);
            print("},A={");

            if(ISOK(ret = hammer_message_udp_with_timeout(mesg, server, answ)))
            {
                message_fingerprint(answ);
            }
            else
            {
                format("ERROR=%x", ret);
            }

            println("}");

            //

            hammer_message_udp_with_timeout(clnr, server, answ);

            print("Q={");
            message_fingerprint(mesg);
            print("},A={");

            if(ISOK(ret = hammer_message_udp_with_timeout(mesg, server, answ)))
            {
                message_fingerprint(answ);
            }
            else
            {
                format("ERROR=%x", ret);
            }

            println("}");

            //
        }
    }

    dns_message_delete(answ);
    dns_message_delete(clnr);
    dns_message_delete(mesg);
    random_finalize(rndctx);
}

static void query_z_opt_test(const host_address_t *server, const uint8_t *fqdn)
{
    // send an update packet in UDP
    // check the answer

    formatln("query_z_opt_test: %{hostaddr} %{dnsname} (begin)", server, fqdn);

    random_ctx_t   rndctx = random_init(0);

    ya_result      ret = SUCCESS;

    dns_message_t *mesg = dns_message_new_instance();

    for(int_fast32_t protocol = 0; protocol <= 1; ++protocol)
    {
        flushout();

        uint16_t                   id;
        dns_packet_reader_t        pr;
        struct dns_packet_writer_s pw;

        id = (uint16_t)random_next(rndctx);
        dns_message_set_id(mesg, id);

        dns_message_set_flags_hi(mesg, 0);
        dns_message_set_flags_lo(mesg, 0);

        dns_message_set_opcode(mesg, OPCODE_QUERY); // note: OPCODE_QUERY is already shifted
        dns_message_set_authenticated_data(mesg);

        dns_message_set_query_answer_authority_additional_counts(mesg, 1, 0, 0, 1);

        dns_packet_writer_create(&pw, dns_message_get_buffer(mesg), dns_message_get_buffer_size_max(mesg));

        // add a query record

        dns_packet_writer_add_fqdn_uncompressed(&pw, fqdn);
        dns_packet_writer_add_u16(&pw, TYPE_SOA);
        dns_packet_writer_add_u16(&pw, CLASS_IN);

        // add an answer record

        dns_packet_writer_add_u8(&pw, (uint8_t)0);
        dns_packet_writer_add_u16(&pw, TYPE_OPT);
        dns_packet_writer_add_u16(&pw, CLASS_IN);
        dns_packet_writer_add_u32(&pw, htonl(0x8000ffff));
        dns_packet_writer_add_u16(&pw, 0);

        dns_message_set_size(mesg, dns_packet_writer_get_offset(&pw));

        if(protocol == 0)
        {
            formatln("query_z_opt_test: querying with udp");
            ret = dns_message_query_udp_with_timeout(mesg, server, TIMEOUT_S, 0);
            if(FAIL(ret))
            {
                formatln("query_z_opt_test: udp query failure: %r", ret);
                break;
            }
        }
        else
        {
            formatln("query_z_opt_test: querying with tcp");
            ret = dns_message_query_tcp_with_timeout(mesg, server, TIMEOUT_S);
            if(FAIL(ret))
            {
                formatln("query_z_opt_test: tcp query failure: %r", ret);
                break;
            }
        }

        if(dns_message_get_additional_count(mesg) == 0)
        {
            formatln("query_z_opt_test: expected at least one additional: %r", ret);
            break;
        }

        dns_packet_reader_init_from_message(&pr, mesg);

        for(int_fast32_t j = 0; j < dns_message_get_query_count(mesg); ++j)
        {
            if(FAIL(ret = dns_packet_reader_skip_fqdn(&pr)))
            {
                formatln("query_z_opt_test: failed to skip query: %r", ret);
                break;
            }

            if(FAIL(ret = dns_packet_reader_skip(&pr, 4)))
            {
                formatln("query_z_opt_test: failed to skip query: %r", ret);
                break;
            }
        }

        for(int_fast32_t j = 0; j < dns_message_get_answer_count(mesg); ++j)
        {
            if(FAIL(ret = dns_packet_reader_skip_record(&pr)))
            {
                formatln("query_z_opt_test: failed to skip answer: %r", ret);
                break;
            }
        }

        for(int_fast32_t j = 0; j < dns_message_get_authority_count(mesg); ++j)
        {
            if(FAIL(ret = dns_packet_reader_skip_record(&pr)))
            {
                formatln("query_z_opt_test: failed to skip answer: %r", ret);
                break;
            }
        }

        for(int_fast32_t j = 0; j < dns_message_get_additional_count(mesg) - 1; ++j)
        {
            if(FAIL(ret = dns_packet_reader_skip_record(&pr)))
            {
                formatln("query_z_opt_test: failed to skip answer: %r", ret);
                break;
            }
        }

        uint16_t rtype;
        uint16_t rclass;
        uint32_t rttl;
        uint16_t rdatasize;
        uint8_t  tmp[1024];
        ret = dns_packet_reader_read_fqdn(&pr, tmp, sizeof(tmp));

        if(FAIL(ret = dns_packet_reader_skip_record(&pr)))
        {
            formatln("query_z_opt_test: failed to parse last answer record: %r", ret);
            break;
        }

        ret = dns_packet_reader_read_u16(&pr, &rtype);

        if(FAIL(ret = dns_packet_reader_skip_record(&pr)))
        {
            formatln("query_z_opt_test: failed to parse last answer record: %r", ret);
            break;
        }

        if(rtype != TYPE_OPT)
        {
            formatln("query_z_opt_test: expected last answer record to be OPT, but it is %{dnstype}", &rtype);
            ret = ERROR;
            break;
        }

        ret = dns_packet_reader_read_u16(&pr, &rclass);

        if(FAIL(ret = dns_packet_reader_skip_record(&pr)))
        {
            formatln("query_z_opt_test: failed to parse last answer record: %r", ret);
            break;
        }

        ret = dns_packet_reader_read_u32(&pr, &rttl);

        if(FAIL(ret = dns_packet_reader_skip_record(&pr)))
        {
            formatln("query_z_opt_test: failed to parse last answer record: %r", ret);
            break;
        }

        if(rttl != MESSAGE_EDNS0_DNSSEC)
        {
            formatln("query_z_opt_test: expected OPT flags to be %08x, they are %08x", MESSAGE_EDNS0_DNSSEC, rttl);
            ret = ERROR;
            break;
        }

        ret = dns_packet_reader_read_u16(&pr, &rdatasize);

        if(FAIL(ret = dns_packet_reader_skip_record(&pr)))
        {
            formatln("query_z_opt_test: failed to parse last answer record: %r", ret);
            break;
        }

        if(rdatasize != 0)
        {
            rdatasize = ntohs(rdatasize);
            ret = dns_packet_reader_skip(&pr, rdatasize);
        }

        formatln("query_z_opt_test: OPT record Z flags are clear");
    }

    formatln("query_z_opt_test: %{hostaddr} %{dnsname} (end) (%r)", server, fqdn, ret);
}

static ya_result query_with_tsig(const host_address_t *server, const uint8_t *fqdn, const tsig_key_t *key)
{
    random_ctx_t   rnd = random_init_auto();
    uint16_t       id = (uint16_t)random_next(rnd);

    dns_message_t *mesg = dns_message_new_instance();

    dns_message_make_query(mesg, id, fqdn, TYPE_A, CLASS_IN);
    if(key != NULL)
    {
        dns_message_tsig_set_key(mesg, key);
        dns_message_sign_query(mesg, key);
    }

    int64_t   duration_us = timeus();
    ya_result ret = dns_message_query_udp_with_timeout(mesg, server, 3, 0);
    duration_us = timeus() - duration_us;

    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 15, duration_us / 1000);

    dns_message_delete(mesg);

    random_finalize(rnd);

    return ret;
}

static ya_result query_invalid_fqdn(const host_address_t *server, const uint8_t *fqdn)
{
    (void)fqdn;
    ya_result      ret = SUCCESS;
    random_ctx_t   rnd = random_init(0);
    static uint8_t bad_message0[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 99,   99,   99,   99,  99, 99,
                                     99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,  99,  99,  99,   99, 99, 99, 99, 99, 99, 99,   99,   99,   99,  99, 99,
                                     99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,  99,  99,  99,   99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    static uint8_t bad_message1[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    static uint8_t bad_message2[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 99,   99,   99,   99,  99, 99,
                                     99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,  99,  99,  99,   99, 99, 99, 99, 99, 99, 99,   99,   99,   99,  99, 99,
                                     99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,  99,  99,  99,   99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    static uint8_t bad_message3[] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    static uint8_t bad_message4[] = {0x01, 0x00, OPCODE_NOTIFY,
                                     0x00, 0x00, 0x01,
                                     0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00,
                                     0x03, 'w',  'w',
                                     'w',  0x40, 99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     0x02, 0x00, 0x01,
                                     0x00};

    static uint8_t bad_message5[] = {0x02, 0x00, OPCODE_NOTIFY, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    static uint8_t bad_message6[] = {0x01, 0x00, OPCODE_NOTIFY,
                                     0x00, 0x01, 0x01,
                                     0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00,
                                     0x03, 'w',  'w',
                                     'w',  0x40, 99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     0x02, 0x00, 0x01,
                                     0x00};

    static uint8_t bad_message7[] = {0x02, 0x00, OPCODE_NOTIFY, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    static uint8_t bad_message8[] = {0x01, 0x00, OPCODE_UPDATE,
                                     0x00, 0x00, 0x01,
                                     0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00,
                                     0x03, 'w',  'w',
                                     'w',  0x40, 99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     0x02, 0x00, 0x01,
                                     0x00};

    static uint8_t bad_message9[] = {0x02, 0x00, OPCODE_UPDATE, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    static uint8_t bad_messageA[] = {0x01, 0x00, OPCODE_UPDATE,
                                     0x00, 0x01, 0x01,
                                     0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00,
                                     0x03, 'w',  'w',
                                     'w',  0x40, 99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     99,   99,   99,
                                     0x02, 0x00, 0x01,
                                     0x00};

    static uint8_t bad_messageB[] = {0x02, 0x00, OPCODE_UPDATE, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    static uint8_t bad_messageC[] = {0x01, 0x00, 0x78, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 99,   99,   99,   99,  99, 99,
                                     99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,  99,  99,  99,   99, 99, 99, 99, 99, 99, 99,   99,   99,   99,  99, 99,
                                     99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,  99,  99,  99,   99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    static uint8_t bad_messageD[] = {0x02, 0x00, 0x78, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    static uint8_t bad_messageE[] = {0x01, 0x00, 0x78, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 99,   99,   99,   99,  99, 99,
                                     99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,  99,  99,  99,   99, 99, 99, 99, 99, 99, 99,   99,   99,   99,  99, 99,
                                     99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,   99,  99,  99,  99,   99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    static uint8_t bad_messageF[] = {0x02, 0x00, 0x78, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x40, 99, 99, 99, 99, 99, 99, 0x02, 0x00, 0x01, 0x00};

    typedef struct
    {
        const uint8_t *message;
        size_t         size;
    } bad_message_t;

    static const bad_message_t bad_messages[] = {{bad_message0, sizeof(bad_message0)},
                                                 {bad_message1, sizeof(bad_message1)},
                                                 {bad_message2, sizeof(bad_message2)},
                                                 {bad_message3, sizeof(bad_message3)},
                                                 {bad_message4, sizeof(bad_message4)},
                                                 {bad_message5, sizeof(bad_message5)},
                                                 {bad_message6, sizeof(bad_message6)},
                                                 {bad_message7, sizeof(bad_message7)},
                                                 {bad_message8, sizeof(bad_message8)},
                                                 {bad_message9, sizeof(bad_message9)},
                                                 {bad_messageA, sizeof(bad_messageA)},
                                                 {bad_messageB, sizeof(bad_messageB)},
                                                 {bad_messageC, sizeof(bad_messageC)},
                                                 {bad_messageD, sizeof(bad_messageD)},
                                                 {bad_messageE, sizeof(bad_messageE)},
                                                 {bad_messageF, sizeof(bad_messageF)},
                                                 {NULL, 0}};

    socketaddress_t            sa;
    host_address2sockaddr(server, &sa);
    socklen_t sa_len;
    switch(sa.sa.sa_family)
    {
        case AF_INET:
        {
            sa_len = sizeof(sa.sa4);
            break;
        }
        case AF_INET6:
        {
            sa_len = sizeof(sa.sa6);
            break;
        }
        default:
        {
            return INVALID_ARGUMENT_ERROR;
        }
    }

    int sockfd;

    if((sockfd = socket(sa.sa.sa_family, SOCK_DGRAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_DGRAM))) >= 0)
    {
        fd_setcloseonexec(sockfd);
    }

    for(const bad_message_t *m = bad_messages; m->message != NULL; ++m)
    {
        /*ssize_t n = */ sendto(sockfd, m->message, m->size, 0, &sa.sa, sa_len);
        usleep(10000);
    }

    static uint8_t bad_messageR[64] = {
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    uint16_t id = 0;
    for(int_fast32_t loops = 10000; loops > 0; --loops)
    {
        static const uint8_t  filler_0[4] = {0x00, 0xff, 0x00, 0x01};
        static const uint8_t  filler_1[4] = {0x00, 0x01, 0x00, 0xff};
        static const uint8_t *fillers[2] = {filler_0, filler_1};
        const uint8_t        *filler = fillers[loops & 1];

        if((loops % 100) == 0)
        {
            formatln("query_invalid_fqdn: %i loops remaining", loops);
            flushout();
        }

        for(int_fast32_t len = sizeof(bad_messageR) - 12; len >= 0; --len)
        {
            uint32_t *p = (uint32_t *)&bad_messageR[12];
            for(int_fast32_t i = 0; i < len / 4; ++i)
            {
                *p++ = random_next(rnd);
            }
            for(size_t i = len; i < sizeof(bad_messageR) - 12; ++i)
            {
                bad_messageR[12 + i] = filler[i & 3];
            }
            SET_U16_AT_P(bad_messageR, htons(id++));
            /*ssize_t n = */ sendto(sockfd, bad_messageR, 12 + len, 0, &sa.sa, sa_len);
            usleep(1000);
        }
    }

    socketclose_ex(sockfd);

    random_finalize(rnd);

    return ret;
}

static void help()
{
    println("parameters: -s server-ip [-y hmac-type:hmac_name:hmac_bytes] -d domain");
    flushout();
}

static void signal_int(uint8_t num)
{
    (void)num;
    dnscore_shutdown();
    exit(0);
}

static ya_result main_config(int argc, char *argv[])
{
    input_stream_t config_is;
    config_error_t cfgerr;
    ya_result      ret;

    ZEROMEMORY(&g_protocol_test_settings, sizeof(g_protocol_test_settings));

    if(FAIL(ret = config_register_struct(PROCOTOL_TEST_SECTION_NAME, protocol_test_settings_desc, &g_protocol_test_settings, 0)))
    {
        return ret; // internal error
    }

    config_set_source(CONFIG_SOURCE_HIGHEST);

    int argc_error;

    if(FAIL(ret = cmdline_parse(protocol_test_cmdline, argc, argv, NULL, NULL, &config_is, &argc_error)))
    {
        if(argc_error > 0)
        {
            formatln("command line: %r at %s", ret, argv[argc_error]);
        }
        else
        {
            formatln("command line: %r", ret);
        }
        flushout();

        return ret;
    }

    config_set_source(CONFIG_SOURCE_CMDLINE);

    uint32_t cmdline_buffer_size = bytearray_input_stream_size(&config_is);
    uint8_t *cmdline_buffer = bytearray_input_stream_detach(&config_is);

    input_stream_close(&config_is);

    config_error_init(&cfgerr);

    if(FAIL(ret = config_read_from_buffer((const char *)cmdline_buffer, cmdline_buffer_size, "command-line", &cfgerr)))
    {
        if(cfgerr.file[0] != '\0')
        {
            formatln("command line: '%s': %r", cfgerr.line, ret);
            flushout();
        }

        free(cmdline_buffer);

        config_error_finalise(&cfgerr);

        return ret;
    }

    free(cmdline_buffer);

    ret = cmdline_help_get() ? 1 : 0;
    ret |= cmdline_version_get() << 1;

    config_error_finalise(&cfgerr);

    // if ret != 0, then specific help has been asked

    if(ret != 0)
    {
        return ret;
    }

    config_set_source(CONFIG_SOURCE_DEFAULT);

    return ret;
}

int main(int argc, char *argv[])
{
    host_address_t *server = NULL;
    const uint8_t  *fqdn = NULL;
    ya_result       ret;

    dnscore_init();

    if(FAIL(ret = main_config(argc, argv)))
    {
        help();
        return EXIT_FAILURE;
    }

    println("protocol-test configured");
    flushout();

    server = g_protocol_test_settings.server;

    if(server == NULL)
    {
        static const uint8_t lo[4] = {127, 0, 0, 1};
        server = host_address_new_instance();
        host_address_set_ipv4(server, lo, NU16(53));
    }

    if(server->port == 0)
    {
        server->port = NU16(53);
    }

    fqdn = g_protocol_test_settings.fqdn;

    if(fqdn == NULL)
    {
        fqdn = dnsname_dup((const uint8_t *)"");
    }

    tsig_key_t *key = g_protocol_test_settings.tsig_key_item;

    formatln("server: %{hostaddr}\nfqdn: %{dnsname}", server, fqdn);
    if(key != NULL)
    {
        formatln("key: %{dnsname}", key->name);
    }
    flushout();

    signal_handler_init();
    signal_handler_set(SIGINT, signal_int);
    signal_handler_set(SIGTERM, signal_int);

    ret = query_with_tsig(server, fqdn, key);

    query_z_opt_test(server, fqdn);
    flushout();
    query_invalid_fqdn(server, fqdn);
    flushout();
    compression_loop_test3(server, fqdn);
    flushout();
    compression_loop_test2(server, fqdn);
    flushout();
    compression_loop_test(server, fqdn);
    flushout();
    corrupt_test(server, fqdn);
    flushout();
    hammer_test(server, fqdn);
    flushout();
    update_test(server, fqdn);

    flushout();
    flusherr();
    fflush(NULL);

    signal_handler_finalize();
    dnscore_finalize();

    return EXIT_SUCCESS;
}

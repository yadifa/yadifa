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

// #define YATEST_SOCKETSERVER_START_NO_FORK 1

#include "yatest.h"
#include "yatest_dns.h"
#include "yatest_socket.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/dns_message_writer.h"
#include "dnscore/ctrl_rfc.h"
#include "dnscore/config_settings.h"
#include "dnscore/dnskey_signature.h"

#include <dnscore/dnscore.h>
#include <dnscore/dns_message.h>
#include <dnscore/dns_message_verify_rrsig.h>
#include <dnscore/dns_packet_writer.h>
#include <dnscore/rfc.h>

logger_handle_t      *g_test_logger = LOGGER_HANDLE_SINK;

static dns_message_t *mesg64K;
static dns_message_t *mesg512;
static uint8_t       *mesg512_buffer;
static const uint32_t mesg512_buffer_size = 512;
static const uint8_t  yadifa_eu[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t  www_yadifa_eu[] = {3, 'w', 'w', 'w', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t  wWw_YaDiFa_eU[] = {3, 'w', 'W', 'w', 6, 'Y', 'a', 'D', 'i', 'F', 'a', 2, 'e', 'U', 0};
static const uint8_t  ns1_yadifa_eu[] = {3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t  ns99_yadifa_eu[] = {4, 'n', 's', '9', '9', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
// static const uint8_t mail_yadifa_eu[] = {4,'m', 'a', 'i', 'l', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t localhost_a_wire[4] = {127, 0, 0, 1};
static const uint8_t ipv4_0[4] = {127, 0, 0, 1};
static const uint8_t ipv4_1[4] = {127, 0, 0, 2};
static const uint8_t ipv6_0[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t ipv6_1[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
static const uint8_t soa_rdata[] = {3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 5, 'a', 'd', 'm', 'i', 'n', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 0, 1, 2, 3, 0, 0, 5, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 2, 0};
static const uint8_t mx_rdata[] = {0, 10, 4, 'm', 'a', 'i', 'l', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t rrsig_over_soa_rdata[] = {0x00, 0x06, 0x08, 0x01, 0x00, 0x01, 0x51, 0x80, 0x66, 0x39, 0xe3, 0x73, 0x66, 0x30, 0x9a, 0xe3, 0x6a, 0x02, 2,    'e',  'u',  0,    0x77, 0x1f, 0xe0, 0x5b, 0x4e, 0xcb, 0x3f, 0xe1,
                                               0xb9, 0xf4, 0x1b, 0x9e, 0x98, 0x29, 0xd7, 0xde, 0xfb, 0xbd, 0xdd, 0x87, 0x08, 0x8c, 0x83, 0x90, 0xef, 0xdb, 0xc3, 0xc9, 0x19, 0x36, 0xde, 0xbe, 0xd2, 0x64, 0x12, 0x8e, 0x75, 0x86,
                                               0x71, 0x27, 0xf9, 0x31, 0x74, 0xbb, 0xa3, 0xdf, 0x0e, 0xac, 0xec, 0xdf, 0x56, 0x14, 0x04, 0x62, 0x91, 0xbc, 0x70, 0xfc, 0x9f, 0x92, 0xaa, 0xda, 0x49, 0xec, 0x2b, 0x2d, 0x7e, 0x7e,
                                               0xab, 0xc3, 0x30, 0x3b, 0x58, 0x7a, 0xd3, 0x4b, 0x9e, 0x20, 0x92, 0x92, 0x77, 0xe7, 0xda, 0x3f, 0x59, 0x0b, 0x59, 0x5d, 0x15, 0x64, 0x7c, 0xa4, 0x9d, 0x03, 0xc1, 0xf7, 0xd2, 0xe1,
                                               0x17, 0xae, 0xf4, 0x01, 0xd0, 0x9b, 0xd1, 0x15, 0x2b, 0xe0, 0x59, 0x2b, 0x73, 0x21, 0xb7, 0x06, 0xa9, 0xfd, 0x4e, 0xb1, 0xd5, 0xd3, 0x18, 0x15, 0x26, 0x67, 0x08, 0xa4, 0x8f, 0x0c};

static const uint8_t rrsig_over_ns_rdata[] = {0x00, 0x02, 0x08, 0x01, 0x00, 0x01, 0x51, 0x80, 0x66, 0x34, 0xdb, 0x75, 0x66, 0x2b, 0x97, 0xc5, 0x6a, 0x02, 2,    'e',  'u',  0,    0x91, 0x8f, 0x56, 0x26, 0x3e, 0x46, 0x7a, 0xbd,
                                              0xe9, 0x56, 0xe1, 0xf0, 0x06, 0x6a, 0xae, 0x2b, 0xec, 0x0e, 0xda, 0xaa, 0xdf, 0x2f, 0xc9, 0x72, 0xa8, 0xc4, 0x5e, 0x7c, 0x5a, 0x44, 0x42, 0xf4, 0xf9, 0x3b, 0x82, 0xb2, 0x52, 0xa7,
                                              0x38, 0xb5, 0xe0, 0xcd, 0x0e, 0x6c, 0x6a, 0xf8, 0x31, 0x3c, 0x7a, 0xf7, 0x03, 0x95, 0xe0, 0x1c, 0xaa, 0x7c, 0xd0, 0xef, 0xd7, 0x3d, 0x9b, 0xb9, 0x33, 0x18, 0x96, 0xd8, 0x82, 0x9b,
                                              0xb1, 0x79, 0xba, 0x85, 0xa0, 0x81, 0x14, 0xf9, 0xa1, 0x1f, 0xa5, 0x89, 0xae, 0x42, 0xc9, 0xf9, 0xb1, 0xc0, 0x37, 0xf4, 0xdc, 0x96, 0x3d, 0xf7, 0x69, 0xa8, 0xd3, 0x18, 0x6b, 0x40,
                                              0x19, 0x97, 0x89, 0xa3, 0x11, 0x0a, 0xde, 0x81, 0xf7, 0xe4, 0x02, 0x41, 0x05, 0xd5, 0xb0, 0xd6, 0x4f, 0xe8, 0x8d, 0xb7, 0xf8, 0x76, 0x94, 0xa4, 0x76, 0x9f, 0x83, 0x5c, 0x3c, 0x84};

static const uint8_t nsec_rdata[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 0x00, 0x07, 0x22, 0x00, 0x80, 0x00, 0x00, 0x03, 0x80};

static socketaddress_t dummy_sa[4];

#define MYKEY_NAME    (const uint8_t *)"\005mykey"
#define NOTMYKEY_NAME (const uint8_t *)"\010notmykey"
static const uint8_t         mykey_mac[] = {0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
static const uint8_t         notmykey_mac[] = {0x91, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

static const char           *server_listen_address_text = "127.0.0.1";
static uint16_t              server_listen_port = 10053;

static yatest_socketserver_t mockserver = YATEST_SOCKETSERVER_UNINITIALISED;
static yatest_socketserver_t mockserver2 = YATEST_SOCKETSERVER_UNINITIALISED;

// if set to true, network_test_udp_handler will flag replies as being truncated
static bool    network_test_udp_handler_truncate_messages = false;

const char    *fqdn;
uint16_t       rtype;
uint16_t       rclass;
int32_t        rttl;
uint16_t       rdata_len;
const uint8_t *rdata;

#define A_RRSET_COUNT    2
#define AAAA_RRSET_COUNT 2
#define NS_RRSET_COUNT   2
#define MX_RRSET_COUNT   1

static yatest_dns_record_t a_rrset[A_RRSET_COUNT] = {{www_yadifa_eu, TYPE_A, CLASS_IN, 86400, sizeof(ipv4_0), ipv4_0}, {www_yadifa_eu, TYPE_A, CLASS_IN, 86400, sizeof(ipv4_1), ipv4_1}};

static yatest_dns_record_t aaaa_rrset[AAAA_RRSET_COUNT] = {{www_yadifa_eu, TYPE_AAAA, CLASS_IN, 86400, sizeof(ipv6_0), ipv6_0}, {www_yadifa_eu, TYPE_AAAA, CLASS_IN, 86400, sizeof(ipv6_1), ipv6_1}};

static yatest_dns_record_t ns_rrset[NS_RRSET_COUNT] = {{yadifa_eu, TYPE_NS, CLASS_IN, 86400, sizeof(ns1_yadifa_eu), ns1_yadifa_eu}, {yadifa_eu, TYPE_NS, CLASS_IN, 86400, sizeof(ns99_yadifa_eu), ns99_yadifa_eu}};

static yatest_dns_record_t mx_rrset[MX_RRSET_COUNT] = {{yadifa_eu, TYPE_MX, CLASS_IN, 86400, sizeof(mx_rdata), mx_rdata}};

static void                init_logger()
{
    int ret;
    logger_init();
    logger_start();
    logger_handle_create("system", &g_system_logger);
    logger_handle_create("database", &g_test_logger);

    int priority = -1; // -1 forces the logger to assume 0 (coverage of 1 line)

    if(FAIL(ret = config_register_logger(NULL, NULL, priority))) // 5 & 6
    {
        yatest_err("config_register_logger failed with %s", error_gettext(ret));
        exit(1);
    }

    if(g_test_logger == &LOGGER_HANDLE_SINK_)
    {
        yatest_err("config_register_logger failed to setup the 'test' logger");
        exit(1);
    }

    if(g_system_logger == &LOGGER_HANDLE_SINK_)
    {
        yatest_err("config_register_logger failed to setup the 'system' logger");
        exit(1);
    }
}

static void init_tsig()
{
    int ret;

    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA1);

    if(FAIL(ret))
    {
        yatest_err("tsig_register failed with %x", ret);
        exit(1);
    }

    ret = tsig_register(NOTMYKEY_NAME, notmykey_mac, sizeof(notmykey_mac), HMAC_SHA1);

    if(FAIL(ret))
    {
        yatest_err("tsig_register failed with %x", ret);
        exit(1);
    }
}

static void init()
{
    dnscore_init();
    mesg512_buffer = (uint8_t *)malloc(mesg512_buffer_size);
    mesg64K = dns_message_new_instance();
    dns_message_debug_trash_buffer(mesg64K);
    mesg512 = dns_message_new_instance_ex(mesg512_buffer, mesg512_buffer_size);
    dns_message_debug_trash_buffer(mesg512);

    dns_message_set_minimum_troughput_default(512.0);
    dns_message_edns0_setmaxsize(4096);

    memset(dummy_sa, 0, sizeof(dummy_sa));

    dummy_sa[0].sa.sa_family = AF_INET;
    dummy_sa[0].sa4.sin_port = htons(53);
    memcpy(&dummy_sa[0].sa4.sin_addr, ipv4_0, sizeof(ipv4_0));

    dummy_sa[1].sa.sa_family = AF_INET6;
    dummy_sa[1].sa6.sin6_port = htons(53);
    memcpy(&dummy_sa[1].sa6.sin6_addr, ipv6_0, sizeof(ipv6_0));

    dummy_sa[2].sa.sa_family = AF_INET;
    dummy_sa[2].sa4.sin_port = htons(53);
    memcpy(&dummy_sa[2].sa4.sin_addr, ipv4_1, sizeof(ipv4_1));

    dummy_sa[3].sa.sa_family = AF_INET6;
    dummy_sa[3].sa6.sin6_port = htons(53);
    memcpy(&dummy_sa[3].sa6.sin6_addr, ipv6_1, sizeof(ipv6_1));

    init_tsig();
    init_logger();
}

static void finalise()
{
    dns_message_delete(mesg512);
    dns_message_delete(mesg64K);
    dnscore_finalize();
}

static void expect_qaaa(dns_message_t *mesg, uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar)
{
    uint16_t query_count = dns_message_get_query_count(mesg);
    uint16_t answer_count = dns_message_get_answer_count(mesg);
    uint16_t authority_count = dns_message_get_authority_count(mesg);
    uint16_t additional_count = dns_message_get_additional_count(mesg);
    uint16_t prerequisite_count = dns_message_get_prerequisite_count(mesg);

    uint16_t query_count_ne = dns_message_get_query_count_ne(mesg);
    uint16_t answer_count_ne = dns_message_get_answer_count_ne(mesg);
    uint16_t authority_count_ne = dns_message_get_authority_count_ne(mesg);
    uint16_t additional_count_ne = dns_message_get_additional_count_ne(mesg);
    uint16_t prerequisite_count_ne = dns_message_get_prerequisite_count_ne(mesg);

    if(query_count != qd)
    {
        yatest_err("query_count expected %04x got %04x", qd, query_count);
        exit(1);
    }
    if(prerequisite_count != an)
    {
        yatest_err("prerequisite_count expected %04x got %04x", qd, answer_count);
        exit(1);
    }
    if(answer_count != an)
    {
        yatest_err("answer_count expected %04x got %04x", qd, answer_count);
        exit(1);
    }
    if(authority_count != ns)
    {
        yatest_err("authority_count expected %04x got %04x", qd, authority_count);
        exit(1);
    }
    if(additional_count != ar)
    {
        yatest_err("additional_count expected %04x got %04x", qd, additional_count);
        exit(1);
    }
    if(query_count != ntohs(query_count_ne))
    {
        yatest_err("query_count network endian fail %04x != %04x", query_count, query_count_ne);
        exit(1);
    }
    if(answer_count != ntohs(answer_count_ne))
    {
        yatest_err("answer_count network endian fail %04x != %04x", answer_count, answer_count_ne);
        exit(1);
    }
    if(prerequisite_count != ntohs(prerequisite_count_ne))
    {
        yatest_err("prerequisite_count network endian fail %04x != %04x", prerequisite_count, prerequisite_count_ne);
        exit(1);
    }
    if(authority_count != ntohs(authority_count_ne))
    {
        yatest_err("authority_count network endian fail %04x != %04x", authority_count, authority_count_ne);
        exit(1);
    }
    if(additional_count != ntohs(additional_count_ne))
    {
        yatest_err("additional_count network endian fail %04x != %04x", additional_count, additional_count_ne);
        exit(1);
    }

    uint16_t counters[4] = {qd, an, ns, ar};

    for(int i = 0; i < 4; ++i)
    {
        int he = dns_message_get_section_count(mesg, i);
        int ne = dns_message_get_section_count_ne(mesg, i);
        if(he != counters[i])
        {
            yatest_err("dns_message_get_section_count[%i] = %04x, expected %04x", he, counters[i]);
            exit(1);
        }
        if(ntohs(ne) != counters[i])
        {
            yatest_err("dns_message_get_section_count[%i] = %04x, expected %04x", ne, ntohs(counters[i]));
            exit(1);
        }
    }

    dns_message_header_t *hdr = dns_message_get_header(mesg);
    if((ntohs(hdr->qdcount) != qd) || (ntohs(hdr->ancount) != an) || (ntohs(hdr->nscount) != ns) || (ntohs(hdr->arcount) != ar))
    {
        yatest_err("dns_message_get_header didn't return the expected header");
        exit(1);
    }
}

static int header_test()
{
    int ret;
    init();
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_make_query(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const);

    ret = dns_message_process_query(mesg);
    if(FAIL(ret))
    {
        yatest_err("dns_message_process_query failed with %s", error_gettext(ret));
        return 1;
    }

    uint16_t query_count = dns_message_get_query_count(mesg);
    uint16_t answer_count = dns_message_get_answer_count(mesg);
    uint16_t authority_count = dns_message_get_authority_count(mesg);
    uint16_t additional_count = dns_message_get_additional_count(mesg);
    if((query_count != 1) || ((answer_count | authority_count | additional_count) != 0))
    {
        yatest_err("dns_message_make_query: expected 1,0,0,0, got %i,%i,%i,%i", query_count, answer_count, authority_count, additional_count);
        return 1;
    }
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 2, 3, 4);
    expect_qaaa(mesg, 1, 2, 3, 4);

    dns_message_set_query_answer_authority_additional_counts_ne(mesg, htons(5), htons(6), htons(7), htons(8));
    expect_qaaa(mesg, 5, 6, 7, 8);

    dns_message_set_authority_additional_counts_ne(mesg, htons(9), htons(10));
    expect_qaaa(mesg, 5, 6, 9, 10);

    dns_message_set_answer_count(mesg, 11);
    dns_message_set_authority_count(mesg, 12);
    dns_message_set_additional_count(mesg, 13);
    expect_qaaa(mesg, 5, 11, 12, 13);

    dns_message_set_answer_count_ne(mesg, htons(14));
    dns_message_set_authority_count_ne(mesg, htons(15));
    dns_message_set_additional_count_ne(mesg, htons(16));
    expect_qaaa(mesg, 5, 14, 15, 16);

    dns_message_set_update_count_ne(mesg, htons(17)); // same as authority
    if(dns_message_get_update_count_ne(mesg) != htons(17))
    {
        yatest_err("dns_message_set_update_count_ne: expected %04x, got %04x", htons(17), dns_message_get_update_count_ne(mesg));
        return 1;
    }
    dns_message_set_update_count(mesg, 18); // same as authority
    if(dns_message_get_update_count(mesg) != 18)
    {
        yatest_err("dns_message_set_update_count: expected %04x, got %04x", htons(18), dns_message_get_update_count(mesg));
        return 1;
    }

    expect_qaaa(mesg, 5, 14, 18, 16);

    dns_message_add_additional_count(mesg, 4);
    expect_qaaa(mesg, 5, 14, 18, 20);

    dns_message_sub_additional_count(mesg, 1);
    expect_qaaa(mesg, 5, 14, 18, 19);

    dns_message_add_update_count(mesg, 3);
    expect_qaaa(mesg, 5, 14, 21, 19);

    // reset the counts to their actual values
    dns_message_set_query_answer_authority_additional_counts_ne(mesg, NU16(1), 0, 0, 0);

    if(dns_message_get_opcode(mesg) != OPCODE_QUERY)
    {
        yatest_err("dns_message_make_query: opcode expected to be QUERY=%i, got %i", OPCODE_QUERY, dns_message_get_opcode(mesg));
        return 1;
    }

    for(int i = 0; i <= 15; ++i)
    {
        dns_message_set_opcode(mesg, dns_message_make_opcode(i));
        if(dns_message_get_opcode(mesg) != dns_message_make_opcode(i))
        {
            yatest_err("dns_message_make_query: opcode expected to be %s=%i, got %i", dns_message_opcode_get_name(i), i, dns_message_get_opcode(mesg));
            return 1;
        }
    }

    if(dns_message_get_referral(mesg) != 0)
    {
        yatest_err("dns_message_make_query: referral expected to be 0, got %i", dns_message_get_referral(mesg));
        return 1;
    }
    dns_message_set_referral(mesg, 1);
    if(dns_message_get_referral(mesg) != 1)
    {
        yatest_err("dns_message_make_query: referral expected to be 1, got %i", dns_message_get_referral(mesg));
        return 1;
    }
    dns_message_set_referral(mesg, 0);

    if(!dns_message_is_query(mesg))
    {
        yatest_err("dns_message_is_query returned false");
        return 1;
    }

    if(dns_message_is_answer(mesg))
    {
        yatest_err("dns_message_is_answer returned true");
        return 1;
    }

    if(dns_message_is_truncated(mesg))
    {
        yatest_err("dns_message_is_truncated returned true");
        return 1;
    }

    dns_message_set_answer(mesg);

    if(dns_message_is_query(mesg))
    {
        yatest_err("dns_message_is_query returned true (dns_message_set_answer)");
        return 1;
    }

    if(!dns_message_is_answer(mesg))
    {
        yatest_err("dns_message_is_answer returned false (dns_message_set_answer)");
        return 1;
    }

    dns_message_set_truncated(mesg, true);

    if(!dns_message_is_truncated(mesg))
    {
        yatest_err("dns_message_is_truncated returned false (dns_message_set_truncated true)");
        return 1;
    }

    dns_message_set_truncated(mesg, false);

    if(dns_message_is_truncated(mesg))
    {
        yatest_err("dns_message_is_truncated returned true (dns_message_set_truncated false)");
        return 1;
    }

    dns_message_clear_answer(mesg);

    if(!dns_message_is_query(mesg))
    {
        yatest_err("dns_message_is_query returned false (dns_message_clear_answer)");
        return 1;
    }

    if(dns_message_is_answer(mesg))
    {
        yatest_err("dns_message_is_answer returned true (dns_message_clear_answer)");
        return 1;
    }

    dns_message_set_authoritative_answer(mesg);

    if(dns_message_is_query(mesg))
    {
        yatest_err("dns_message_is_query returned true (dns_message_set_authoritative_answer)");
        return 1;
    }

    if(!dns_message_is_answer(mesg))
    {
        yatest_err("dns_message_is_answer returned false (dns_message_set_authoritative_answer)");
        return 1;
    }

    if(!dns_message_is_authoritative(mesg))
    {
        yatest_err("dns_message_is_authoritative returned false (dns_message_set_authoritative_answer)");
        return 1;
    }

    dns_message_clear_answer(mesg);

    dns_message_clear_authoritative(mesg);

    if(dns_message_is_authoritative(mesg))
    {
        yatest_err("dns_message_is_authoritative returned true (dns_message_is_authoritative)");
        return 1;
    }

    dns_message_set_truncated_answer(mesg);

    if(dns_message_is_query(mesg))
    {
        yatest_err("dns_message_is_query returned true (dns_message_set_truncated_answer)");
        return 1;
    }

    if(!dns_message_is_answer(mesg))
    {
        yatest_err("dns_message_is_answer returned false (dns_message_set_truncated_answer)");
        return 1;
    }

    dns_message_clear_answer(mesg);
    if(dns_message_has_recursion_desired(mesg))
    {
        yatest_err("dns_message_has_recursion_desired returned true");
        return 1;
    }

    dns_message_set_recursion_desired(mesg);
    if(!dns_message_has_recursion_desired(mesg))
    {
        yatest_err("dns_message_has_recursion_desired returned false (dns_message_set_recursion_desired)");
        return 1;
    }

    if(dns_message_has_recursion_available(mesg))
    {
        yatest_err("dns_message_has_recursion_available returned true");
        return 1;
    }

    if(dns_message_has_authenticated_data(mesg))
    {
        yatest_err("dns_message_has_authenticated_data returned true");
        return 1;
    }
    dns_message_set_authenticated_data(mesg);
    if(!dns_message_has_authenticated_data(mesg))
    {
        yatest_err("dns_message_has_authenticated_data returned false (dns_message_set_authenticated_data)");
        return 1;
    }

    if(dns_message_has_checking_disabled(mesg))
    {
        yatest_err("dns_message_has_checking_disabled returned true");
        return 1;
    }

    if(dns_message_get_rcode(mesg) != RCODE_OK)
    {
        yatest_err("dns_message_get_rcode expected OK, got %i=%s", dns_message_get_rcode(mesg), dns_message_rcode_get_name(dns_message_get_rcode(mesg)));
        return 1;
    }

    dns_message_set_rcode(mesg, RCODE_NOTZONE);

    if(dns_message_get_rcode(mesg) != RCODE_NOTZONE)
    {
        yatest_err("dns_message_get_rcode expected NOTZONE, got %i=%s", dns_message_get_rcode(mesg), dns_message_rcode_get_name(dns_message_get_rcode(mesg)));
        return 1;
    }

    dns_message_set_rcode(mesg, RCODE_OK);

    const uint16_t flags_mask_ne = 0x7b20;
    const uint16_t flags_mask = ntohs(flags_mask_ne);
    uint16_t       flags_org = dns_message_get_flags(mesg);
    dns_message_apply_mask(mesg, flags_mask_ne >> 8, flags_mask_ne & 0xff);
    uint16_t flags_after = dns_message_get_flags(mesg);
    if((flags_org & flags_mask) != flags_after)
    {
        yatest_err("dns_message_apply_mask failed (%04x & %04x != %04x)", flags_org, flags_mask, flags_after);
        return 1;
    }
    uint8_t  flags_lo_org = dns_message_get_flags_lo(mesg);
    uint8_t  flags_hi_org = dns_message_get_flags_hi(mesg);
    uint16_t flags_hilo_org = ntohs(((uint16_t)flags_lo_org) | (((uint16_t)flags_hi_org) << 8));
    if(flags_after != flags_hilo_org)
    {
        yatest_err("flags mismatch %04x != %04x", flags_hilo_org, flags_after);
        return 1;
    }
    const uint8_t lo_mask = 0xdf;
    dns_message_apply_lo_mask(mesg, lo_mask);
    uint8_t flags_lo_after = dns_message_get_flags_lo(mesg);
    if((flags_lo_org & lo_mask) != flags_lo_after)
    {
        yatest_err("dns_message_apply_lo_mask failed: (%02x & %02x != %02x)", flags_lo_org, lo_mask, flags_lo_after);
        return 1;
    }

    dns_message_set_flags_hi(mesg, flags_mask_ne >> 8);
    dns_message_set_flags_lo(mesg, flags_mask_ne & 0xff);
    if(flags_org != dns_message_get_flags(mesg))
    {
        yatest_err("dns_message_set_flags_hi or dns_message_set_flags_lo failed : %04x != %04x", flags_org, dns_message_get_flags(mesg));
        return 1;
    }

    if(dns_message_get_edns0_opt_ttl(mesg) != 0)
    {
        yatest_err("dns_message_get_edns0_opt_ttl expected 0, got %08x", dns_message_get_edns0_opt_ttl(mesg));
        return 1;
    }

    if(dns_message_has_edns0_dnssec(mesg))
    {
        yatest_err("dns_message_has_edns0_dnssec returned true");
        return 1;
    }

    uint16_t query_type = dns_message_get_query_type(mesg);
    if(query_type != *dns_message_get_query_type_ptr(mesg))
    {
        yatest_err("dns_message_get_query_type != dns_message_get_query_type_ptr");
        return 1;
    }
    if(query_type != query_type_const)
    {
        yatest_err("query_type != query_type_const (%04x != %04x)", query_type, query_type_const);
        return 1;
    }

    dns_message_set_query_type(mesg, query_type + 1);
    if(dns_message_get_query_type(mesg) != query_type + 1)
    {
        yatest_err("dns_message_set_query_type didn't set the query type");
        return 1;
    }
    dns_message_set_query_type(mesg, query_type);

    uint16_t query_class = dns_message_get_query_class(mesg);
    if(query_class != *dns_message_get_query_class_ptr(mesg))
    {
        yatest_err("dns_message_get_query_class != dns_message_get_query_class_ptr");
        return 1;
    }
    if(query_class != query_class_const)
    {
        yatest_err("query_class != query_class_const (%04x != %04x)", query_class, query_class_const);
        return 1;
    }

    dns_message_set_query_class(mesg, query_class + 1);
    if(dns_message_get_query_class(mesg) != query_class + 1)
    {
        yatest_err("dns_message_set_query_class didn't set the query class");
        return 1;
    }
    dns_message_set_query_class(mesg, query_class);

    dns_message_clear_recursion_desired(mesg);

    if(dns_message_has_recursion_desired(mesg))
    {
        yatest_err("dns_message_has_recursion_desired returned true");
        return 1;
    }

    dns_message_set_recursion_desired(mesg);

    if(!dns_message_has_recursion_desired(mesg))
    {
        yatest_err("dns_message_has_recursion_desired returned false");
        return 1;
    }

    dns_message_clear_answer(mesg);
    dns_message_set_truncated(mesg, false);
    dns_message_set_status(mesg, FP_RCODE_FORMERR);
    dns_message_update_answer_status(mesg);

    uint8_t rcode;

    if(!dns_message_is_answer(mesg))
    {
        yatest_err("dns_message_is_answer returned false after dns_message_update_answer_status");
        return 1;
    }
    rcode = dns_message_get_rcode(mesg);
    if(rcode != FP_RCODE_FORMERR)
    {
        yatest_err("dns_message_update_answer_status didn't set the rcode properly");
        return 1;
    }
    dns_message_set_rcode(mesg, 0);
    rcode = dns_message_get_rcode(mesg);
    if(rcode != 0)
    {
        yatest_err("dns_message_set_rcode didn't set the rcode properly");
        return 1;
    }
    dns_message_set_status(mesg, FP_RCODE_NOTIMP);
    dns_message_update_truncated_answer_status(mesg);
    if(!dns_message_is_answer(mesg))
    {
        yatest_err("dns_message_is_answer returned false after dns_message_update_truncated_answer_status");
        return 1;
    }
    rcode = dns_message_get_rcode(mesg);
    if(rcode != FP_RCODE_NOTIMP)
    {
        yatest_err("dns_message_update_truncated_answer_status didn't set the rcode properly");
        return 1;
    }
    dns_message_clear_answer(mesg);
    dns_message_set_truncated(mesg, false);
    dns_message_set_rcode(mesg, 0);

    dns_message_set_error_status_from_result(mesg, MAKE_RCODE_ERROR(RCODE_NOTAUTH));
    if(dns_message_get_status(mesg) != RCODE_NOTAUTH)
    {
        yatest_err("dns_message_set_error_status_from_result didn't set the status properly");
        return 1;
    }

    dns_message_set_error_status_from_result(mesg, ERROR);
    if(dns_message_get_status(mesg) != RCODE_SERVFAIL)
    {
        yatest_err("dns_message_set_error_status_from_result didn't set the status properly");
        return 1;
    }

    if(dns_message_get_additional_section_ptr(mesg) != NULL)
    {
        yatest_err("expected dns_message_get_additional_section_ptr to return NULL");
        return 1;
    }

    if(dns_message_get_additional_section_ptr_const(mesg) != NULL)
    {
        yatest_err("expected dns_message_get_additional_section_ptr_const to return NULL");
        return 1;
    }

    dns_message_set_additional_section_ptr(mesg, dns_message_get_buffer(mesg) + 12);

    if(dns_message_get_additional_section_ptr(mesg) != dns_message_get_buffer(mesg) + 12)
    {
        yatest_err(
            "dns_message_set_additional_section_ptr didn't set the pointer properly "
            "(dns_message_get_additional_section_ptr)");
        return 1;
    }

    if(dns_message_get_additional_section_ptr_const(mesg) != dns_message_get_buffer(mesg) + 12)
    {
        yatest_err(
            "dns_message_set_additional_section_ptr didn't set the pointer properly "
            "(dns_message_get_additional_section_ptr_const)");
        return 1;
    }

    finalise();
    return 0;
}

static int buffer_test()
{
    int ret;
    init();
    dns_message_t *mesg = mesg64K;
    size_t         buffer_copy_size = 0x10000; // big enough
    uint8_t       *buffer_copy = (uint8_t *)malloc(buffer_copy_size);
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    memset(buffer_copy, 0xff, buffer_copy_size);

    dns_message_make_query(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const);
    ret = dns_message_process_query(mesg);
    if(FAIL(ret))
    {
        yatest_err("dns_message_process_query failed with %s", error_gettext(ret));
        return 1;
    }

    int buffer_size = dns_message_get_buffer_size(mesg);
    int buffer_size_max = dns_message_get_buffer_size_max(mesg);
    yatest_log("buffer_size_max=%i", buffer_size_max);

    int message_size = dns_message_get_size(mesg);
    if(dns_message_get_size_u16(mesg) != dns_message_get_size(mesg))
    {
        yatest_err("dns_message_get_size_u16 != dns_message_get_size (%04x != %04x)", dns_message_get_size_u16(mesg), dns_message_get_size(mesg));
        return 1;
    }

    dns_message_increase_size(mesg, 1);
    if((message_size + 1) != (int)dns_message_get_size(mesg))
    {
        yatest_err("dns_message_increase_size didn't increase the size as expected (%04x != %04x)", message_size + 1, dns_message_get_size(mesg));
        return 1;
    }
    dns_message_set_size(mesg, message_size);
    if((message_size) != (int)dns_message_get_size(mesg))
    {
        yatest_err("dns_message_set_size set the size as expected (%04x != %04x)", message_size, dns_message_get_size(mesg));
        return 1;
    }

    const uint8_t *buffer = dns_message_get_buffer(mesg);
    const uint8_t *limit = dns_message_get_buffer_limit(mesg);
    if(buffer + message_size != limit)
    {
        yatest_err("buffer[size] != limit (%p + %x != %p)", buffer, message_size, limit);
        return 1;
    }
    if(limit != dns_message_get_buffer_limit_const(mesg))
    {
        yatest_err("dns_message_get_buffer_limit != dns_message_get_buffer_limit_const");
        return 1;
    }

    dns_message_set_buffer_size(mesg, buffer_size / 2);
    if(buffer_size / 2 != (int)dns_message_get_buffer_size(mesg))
    {
        yatest_err("dns_message_get_buffer_size failed: %i != %i", buffer_size / 2, dns_message_get_buffer_size(mesg));
        return 1;
    }
    dns_message_set_buffer_size(mesg, buffer_size);

    dns_message_copy_buffer(mesg, buffer_copy, buffer_copy_size);
    if(memcmp(buffer_copy, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg)) != 0)
    {
        yatest_err("dns_message_copy_buffer failed");
        return 1;
    }
    memset(dns_message_get_buffer(mesg), 0xff, dns_message_get_buffer_size_max(mesg));
    dns_message_copy_into_buffer(mesg, buffer_copy, dns_message_get_size(mesg));
    if(memcmp(buffer_copy, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg)) != 0)
    {
        yatest_err("dns_message_copy_buffer failed");
        return 1;
    }

    memset(buffer_copy, 0xff, buffer_copy_size);

    dns_message_copy_control(mesg, buffer_copy, buffer_copy_size);
    if(memcmp(buffer_copy, mesg->_msghdr.msg_control, dns_message_control_size(mesg)) != 0)
    {
        yatest_err("dns_message_copy_control failed");
        return 1;
    }
    dns_message_set_control(mesg, buffer_copy, dns_message_control_size(mesg));

    dns_message_reset_control_size(mesg);
    dns_message_reset_control(mesg);
    dns_message_clear_control(mesg);

    free(buffer_copy);
    finalise();
    return 0;
}

static int features_test()
{
    int ret;
    init();
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_make_query(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const);
    ret = dns_message_process_query(mesg);
    if(FAIL(ret))
    {
        yatest_err("dns_message_process_query failed with %s", error_gettext(ret));
        return 1;
    }

    dns_message_set_protocol(mesg, IPPROTO_TCP); // note this is useless
    dns_message_get_protocol(mesg);

    finalise();
    return 0;
}

static int edns0_test()
{
    int ret;
    init();
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    ret = dns_message_process_query(mesg);
    if(FAIL(ret))
    {
        yatest_err("dns_message_process_query failed with %s", error_gettext(ret));
        return 1;
    }
    if(dns_message_has_edns0(mesg))
    {
        yatest_err("dns_message_make_query_ex unexpectedly set EDNS0");
        return 1;
    }
    dns_message_set_edns0(mesg, true);
    if(!dns_message_has_edns0(mesg))
    {
        yatest_err("dns_message_set_edns0 true didn't set EDNS0");
        return 1;
    }
    dns_message_set_edns0(mesg, false);
    if(dns_message_has_edns0(mesg))
    {
        yatest_err("dns_message_set_edns0 false didn't clear EDNS0");
        return 1;
    }
    dns_message_edns0_set(mesg);
    if(!dns_message_has_edns0(mesg))
    {
        yatest_err("dns_message_edns0_set didn't set EDNS0");
        return 1;
    }
    dns_message_edns0_clear(mesg);
    if(dns_message_has_edns0(mesg))
    {
        yatest_err("dns_message_edns0_clear didn't clear EDNS0");
        return 1;
    }
    dns_message_edns0_set(mesg);

    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    expect_qaaa(mesg, 1, 0, 0, 1);
    ret = dns_message_process_query(mesg);
    if(FAIL(ret))
    {
        yatest_err("dns_message_process_query failed with %s", error_gettext(ret));
        return 1;
    }

    expect_qaaa(mesg, 1, 0, 0, 0);

    if(dns_message_has_nsid(mesg))
    {
        yatest_err("dns_message_has_nsid returned true");
        return 1;
    }

    dns_message_nsid_set(mesg);

    if(!dns_message_has_nsid(mesg))
    {
        yatest_err("dns_message_has_nsid returned false");
        return 1;
    }

    dns_message_clear_nsid(mesg);

    if(dns_message_has_nsid(mesg))
    {
        yatest_err("dns_message_has_nsid returned true");
        return 1;
    }

    if(dns_message_has_cookie(mesg))
    {
        yatest_err("dns_message_has_cookie returned true");
        return 1;
    }

    dns_message_set_edns0(mesg, true);
    dns_message_nsid_set(mesg);
    dns_message_set_client_cookie_for_server_sockaddr(mesg, &dummy_sa[0]);

    dns_message_make_query_ex_with_edns0(mesg512, 0x1234, yadifa_eu, query_type_const, query_class_const, 0);

    if(dns_message_has_edns0(mesg512))
    {
        yatest_err("dns_message_has_edns0 returned true (before copy)");
        return 1;
    }

    if(dns_message_has_nsid(mesg512))
    {
        yatest_err("dns_message_has_nsid returned true (before copy)");
        return 1;
    }

    if(dns_message_has_cookie(mesg512))
    {
        yatest_err("dns_message_has_cookie returned true (before copy)");
        return 1;
    }

    dns_message_opt_copy_from(mesg512, mesg);
    dns_message_set_edns0(mesg, false);
    dns_message_clear_nsid(mesg);
    dns_message_clear_cookie(mesg);

    if(!dns_message_has_edns0(mesg512))
    {
        yatest_err("dns_message_has_edns0 returned false (after copy)");
        return 1;
    }

    if(!dns_message_has_nsid(mesg512))
    {
        yatest_err("dns_message_has_nsid returned false (after copy)");
        return 1;
    }

    if(!dns_message_has_cookie(mesg512))
    {
        yatest_err("dns_message_has_cookie returned false (after copy)");
        return 1;
    }

    dns_message_opt_get(mesg512);

    dns_message_edns0_clear_undefined_flags(mesg64K);

    finalise();
    return 0;
}

static int tsig_test()
{
    int ret;
    init();
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    ret = dns_message_process_query(mesg);
    if(FAIL(ret))
    {
        yatest_err("dns_message_process_query failed with %s", error_gettext(ret));
        return 1;
    }

    if(dns_message_has_tsig(mesg))
    {
        yatest_err("dns_message_has_tsig returned true");
        return 1;
    }
    dns_message_clear_hmac(mesg); // will do nothing

    tsig_key_t *key = tsig_get(MYKEY_NAME);
    dns_message_tsig_set_key(mesg, key);
    if(dns_message_tsig_get_key(mesg) != key)
    {
        yatest_err("dns_message_tsig_get_key didn't return the key");
        return 1;
    }
    dns_message_tsig_clear_key(mesg);

    dns_message_sign_query(mesg, key);
    int64_t epoch = dns_message_tsig_get_epoch(mesg);
    int64_t fudge = dns_message_tsig_get_fudge(mesg);
    int     mac_size = dns_message_tsig_mac_get_size(mesg);
    uint8_t mac[512];
    dns_message_tsig_mac_copy(mesg, mac);

    dns_message_tsig_copy_from(mesg512, mesg);
    int64_t epoch_copy = dns_message_tsig_get_epoch(mesg512);
    int64_t fudge_copy = dns_message_tsig_get_fudge(mesg512);
    int     mac_size_copy = dns_message_tsig_mac_get_size(mesg512);
    uint8_t mac_copy[512];
    dns_message_tsig_mac_copy(mesg512, mac_copy);

    if(epoch != epoch_copy)
    {
        yatest_err("dns_message_tsig_copy_from failed to copy the epoch");
        return 1;
    }
    if(fudge != fudge_copy)
    {
        yatest_err("dns_message_tsig_copy_from failed to copy the fudge");
        return 1;
    }
    if(mac_size != mac_size_copy)
    {
        yatest_err("dns_message_tsig_copy_from failed to copy the mac size");
        return 1;
    }
    if(memcmp(mac, mac_copy, mac_size) != 0)
    {
        yatest_err("dns_message_tsig_copy_from failed to copy the mac");
        return 1;
    }
    dns_message_clear_hmac(mesg512);

    finalise();
    return 0;
}

static int opt_test()
{
    init();

    edns0_set_nsid(ns1_yadifa_eu, sizeof(ns1_yadifa_eu));

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const);
    dns_message_set_client_cookie_for_server_sockaddr(mesg, &dummy_sa[0]);
    dns_message_add_opt(mesg);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    yatest_log("before dns_message_process");
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
    flushout();

    // "sending" message

    dns_message_t *mesg_server = mesg64K;
    dns_message_copy_into_buffer(mesg_server, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg));

    // processing "received" message

    ret = dns_message_process(mesg_server);

    if(FAIL(ret))
    {
        yatest_err("dns_message_process failed with %08x: %s", ret, error_gettext(ret));
        return 1;
    }

    yatest_log("after dns_message_process");
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg_server), dns_message_get_size(mesg_server), 0xff, 0);
    flushout();

    dns_message_set_answer(mesg);
    dns_message_nsid_set(mesg);
    dns_message_add_opt(mesg);
    dns_message_sign_answer(mesg);

    // "sending" message back

    mesg = dns_message_new_instance();
    dns_message_copy_into_buffer(mesg, dns_message_get_buffer_const(mesg_server), dns_message_get_size(mesg_server));

    yatest_log("before dns_message_process_lenient");
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
    flushout();

    // processing "received back" message

    ret = dns_message_process_lenient(mesg);

    if(FAIL(ret))
    {
        yatest_err("dns_message_process_lenient failed with %08x: %s", ret, error_gettext(ret));
        return 1;
    }

    yatest_log("after dns_message_process_lenient");
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
    flushout();

    dns_message_delete(mesg);

    edns0_set_nsid(NULL, 0);

    finalise();
    return 0;
}

static void network_test_init(struct yatest_socketserver_s *ssctx)
{
    (void)ssctx;
    yatest_log("network_test_init");
}

static void network_test_tcp_handler(struct yatest_socketserver_s *ssctx, yatest_serverclient_t *client)
{
    (void)ssctx;

    int ret;

    yatest_log("network_test_tcp_handler(%p, %p)", ssctx, client);

    dnscore_init();
    init_tsig();

    edns0_set_nsid(ns1_yadifa_eu, sizeof(ns1_yadifa_eu));

    input_stream_t tcpis;
    fd_input_stream_attach(&tcpis, client->sockfd);

    dns_message_t *mesg = dns_message_new_instance();

    yatest_log("network_test_tcp_handler(%p, %p) reading message", ssctx, client);

    ret = dns_message_read_tcp(mesg, &tcpis);
    if(ret < 0)
    {
        yatest_err("network_test_tcp_handler: dns_message_read_tcp failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        input_stream_close(&tcpis);
        return;
    }

    yatest_log("network_test_tcp_handler has received message");

    dns_message_copy_sender_from_socket(mesg, client->sockfd);

    const socketaddress_t *csa = dns_message_get_sender(mesg);
    int                    csa_size = dns_message_get_sender_size(mesg);
    char                  *csa_text = yatest_sockaddr_to_string(&csa->sa);
    yatest_log("network_test_tcp_handler: sender=%s, sender_size=%i", csa_text, csa_size);
    free(csa_text);

    // got a message
    ret = dns_message_process_query(mesg);
    if(ret < 0)
    {
        yatest_err("network_test_tcp_handler: dns_message_process_query failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        input_stream_close(&tcpis);
        return;
    }

    yatest_log("network_test_tcp_handler has processed message");

    if(dns_message_get_query_class(mesg) != CLASS_IN)
    {
        yatest_err("network_test_tcp_handler: query class not IN (%04x)", ntohs(dns_message_get_query_class(mesg)));
        input_stream_close(&tcpis);
        return;
    }

    const socketaddress_t *sau = dns_message_get_sender(mesg);
    const struct sockaddr *sas = dns_message_get_sender_sa(mesg);
    char                  *sau_text = yatest_sockaddr_to_string(&sau->sa);
    char                  *sas_text = yatest_sockaddr_to_string(sas);
    int                    sender_size = dns_message_get_sender_size(mesg);
    yatest_log("network_test_tcp_handler: received message from %s = %s (%i)", sau_text, sas_text, sender_size);
    free(sas_text);
    free(sau_text);

    yatest_log("network_test_tcp_handler preparing reply");
    dns_message_set_answer(mesg);
    dns_message_nsid_set(mesg);
    dns_message_add_opt(mesg);
    dns_message_sign_answer(mesg);

    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
    flushout();

    yatest_log("network_test_tcp_handler sending reply");

    ret = dns_message_send_tcp(mesg, client->sockfd);
    if(ret < 0)
    {
        yatest_err("network_test_tcp_handler: dns_message_send_tcp failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        input_stream_close(&tcpis);
        return;
    }

    input_stream_close(&tcpis);
}

static void network_test_tcp_handler_slow_reply(struct yatest_socketserver_s *ssctx, yatest_serverclient_t *client)
{
    (void)ssctx;

    int ret;

    yatest_log("network_test_tcp_handler_slow_reply(%p, %p)", ssctx, client);

    dnscore_init();
    init_tsig();

    edns0_set_nsid(ns1_yadifa_eu, sizeof(ns1_yadifa_eu));

    input_stream_t tcpis;
    fd_input_stream_attach(&tcpis, client->sockfd);

    dns_message_t *mesg = dns_message_new_instance();

    yatest_log("network_test_tcp_handler_slow_reply(%p, %p) reading message in five seconds", ssctx, client);

    yatest_sleep(5);

    yatest_log("network_test_tcp_handler_slow_reply(%p, %p) reading message", ssctx, client);

    ret = dns_message_read_tcp(mesg, &tcpis);
    if(ret < 0)
    {
        yatest_err("network_test_tcp_handler_slow_reply: dns_message_read_tcp failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        input_stream_close(&tcpis);
        return;
    }

    yatest_log("network_test_tcp_handler_slow_reply has received message");

    dns_message_copy_sender_from_socket(mesg, client->sockfd);

    const socketaddress_t *csa = dns_message_get_sender(mesg);
    int                    csa_size = dns_message_get_sender_size(mesg);
    char                  *csa_text = yatest_sockaddr_to_string(&csa->sa);
    yatest_log("network_test_tcp_handler_slow_reply: sender=%s, sender_size=%i", csa_text, csa_size);
    free(csa_text);

    // got a message
    ret = dns_message_process_query(mesg);
    if(ret < 0)
    {
        yatest_err("network_test_tcp_handler_slow_reply: dns_message_process_query failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        input_stream_close(&tcpis);
        return;
    }

    yatest_log("network_test_tcp_handler_slow_reply has processed message");

    if(dns_message_get_query_class(mesg) != CLASS_IN)
    {
        yatest_err("network_test_tcp_handler_slow_reply: query class not IN (%04x)", ntohs(dns_message_get_query_class(mesg)));
        input_stream_close(&tcpis);
        return;
    }

    const socketaddress_t *sau = dns_message_get_sender(mesg);
    const struct sockaddr *sas = dns_message_get_sender_sa(mesg);
    char                  *sau_text = yatest_sockaddr_to_string(&sau->sa);
    char                  *sas_text = yatest_sockaddr_to_string(sas);
    int                    sender_size = dns_message_get_sender_size(mesg);
    yatest_log("network_test_tcp_handler_slow_reply: received message from %s = %s (%i)", sau_text, sas_text, sender_size);
    free(sas_text);
    free(sau_text);

    yatest_log("network_test_udp_handler preparing reply");
    dns_message_set_answer(mesg);
    dns_message_nsid_set(mesg);
    dns_message_add_opt(mesg);
    dns_message_sign_answer(mesg);

    yatest_log("network_test_tcp_handler_slow_reply sending reply");

    ret = dns_message_send_tcp(mesg, client->sockfd);
    if(ret < 0)
    {
        yatest_err("network_test_tcp_handler_slow_reply: dns_message_send_tcp failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        input_stream_close(&tcpis);
        return;
    }

    input_stream_close(&tcpis);
}

static void network_test_udp_handler(struct yatest_socketserver_s *ssctx, yatest_serverclient_t *client)
{
    (void)ssctx;

    int ret;

    yatest_log("network_test_udp_handler(%p, %p)", ssctx, client);

    dnscore_init();
    init_tsig();

    edns0_set_nsid(ns1_yadifa_eu, sizeof(ns1_yadifa_eu));

    dns_message_t *mesg = dns_message_new_instance();

    yatest_log("network_test_udp_handler(%p, %p) reading message", ssctx, client);

    dns_message_recv_udp_reset(mesg);

    ret = dns_message_recv_udp(mesg, ssctx->server_socket);
    if(ret < 0)
    {
        yatest_err("network_test_udp_handler: dns_message_read_tcp failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        return;
    }

    yatest_log("network_test_udp_handler has received message");

    dns_message_copy_sender_from_socket(mesg, client->sockfd);

    const socketaddress_t *csa = dns_message_get_sender(mesg);
    int                    csa_size = dns_message_get_sender_size(mesg);
    char                  *csa_text = yatest_sockaddr_to_string(&csa->sa);
    yatest_log("network_test_udp_handler: sender=%s, sender_size=%i", csa_text, csa_size);
    free(csa_text);

    // got a message
    ret = dns_message_process_query(mesg);
    if(ret < 0)
    {
        yatest_err("network_test_udp_handler: dns_message_process_query failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        return;
    }

    yatest_log("network_test_udp_handler has processed message");

    if(dns_message_get_query_class(mesg) != CLASS_IN)
    {
        yatest_err("network_test_udp_handler: query class not IN (%04x)", ntohs(dns_message_get_query_class(mesg)));
        return;
    }

    const socketaddress_t *sau = dns_message_get_sender(mesg);
    const struct sockaddr *sas = dns_message_get_sender_sa(mesg);
    char                  *sau_text = yatest_sockaddr_to_string(&sau->sa);
    char                  *sas_text = yatest_sockaddr_to_string(sas);
    int                    sender_size = dns_message_get_sender_size(mesg);
    yatest_log("network_test_udp_handler: received message from %s = %s (%i)", sau_text, sas_text, sender_size);
    free(sas_text);
    free(sau_text);

    yatest_log("network_test_udp_handler preparing reply");
    dns_message_set_answer(mesg);
    if(network_test_udp_handler_truncate_messages)
    {
        yatest_log("network_test_udp_handler truncating reply");
        dns_message_set_truncated(mesg, true);
    }

    if(dns_message_get_query_type(mesg) == TYPE_SOA)
    {
        yatest_log("network_test_udp_handler adding SOA record");

        dns_message_set_authoritative(mesg);

        // create an answer with one SOA
        dns_packet_writer_t pw;
        dns_packet_writer_init_append_to_message(&pw, mesg);
        dns_packet_writer_add_fqdn(&pw, dns_message_get_canonised_fqdn(mesg));
        dns_packet_writer_add_u16(&pw, TYPE_SOA);
        dns_packet_writer_add_u16(&pw, CLASS_IN);
        dns_packet_writer_add_u32(&pw, htonl(86400));
        dns_packet_writer_add_u16(&pw, htons(sizeof(soa_rdata)));
        dns_packet_writer_add_bytes(&pw, soa_rdata, sizeof(soa_rdata));
        dns_message_set_size(mesg, pw.packet_offset);
        dns_message_set_authority_count(mesg, 1);
    }

    dns_message_nsid_set(mesg);

    dns_message_add_opt(mesg);
    if(dns_message_has_tsig(mesg))
    {
        yatest_log("network_test_udp_handler message is signed: signing answer");
        dns_message_sign_answer(mesg);
    }

    yatest_log("network_test_udp_handler sending reply");

    ret = dns_message_send_udp(mesg, ssctx->server_socket);
    if(ret < 0)
    {
        yatest_err("network_test_udp_handler: dns_message_send_tcp failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        return;
    }
}

static void network_test_finalise(struct yatest_socketserver_s *ssctx)
{
    (void)ssctx;
    yatest_log("network_test_finalise");
}

static int network_dns_message_send_recv_tcp_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    yatest_log("creating TCP connection to %s:%i", server_listen_address_text, server_listen_port);

    int sockfd = yatest_socket_create(server_listen_address_text, server_listen_port, SOCK_STREAM);

    yatest_log("dns_message_send_tcp sending message");

    ret = dns_message_send_tcp(mesg, sockfd);

    if(FAIL(ret))
    {
        yatest_err("dns_message_send_tcp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_send_tcp returned %i", ret);

    ret = dns_message_copy_sender_from_socket(mesg512, -1);

    if(ISOK(ret))
    {
        yatest_err("dns_message_copy_sender_from_socket did not fail");
        return 1;
    }

    ret = dns_message_copy_sender_from_socket(mesg512, sockfd);

    if(FAIL(ret))
    {
        yatest_err("dns_message_copy_sender_from_socket failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_recv_tcp remote is %{sockaddr}", dns_message_get_sender_sa(mesg512));

    socketaddress_t ss;
    dns_message_copy_sender_to_sa(mesg512, &ss.sa);
    dns_message_copy_sender_from_sa(mesg512, &ss.sa, socketaddress_len(&ss));

    yatest_log("dns_message_recv_tcp receiving message");

    ret = dns_message_recv_tcp(mesg, sockfd);

    if(FAIL(ret))
    {
        yatest_err("dns_message_recv_tcp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_recv_tcp returned %i", ret);

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_query_tcp_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying using TCP message to %s:%i", server_listen_address_text, server_listen_port);

    ret = dns_message_query_tcp(mesg, server_ha);

    if(FAIL(ret))
    {
        yatest_err("dns_message_query_tcp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_query_tcp returned %i", ret);

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_query_tcp_timeout_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying using TCP message to %s:%i", server_listen_address_text, server_listen_port);

    ret = dns_message_query_tcp_with_timeout(mesg, server_ha, 3);

    if(FAIL(ret))
    {
        yatest_err("dns_message_query_tcp_with_timeout failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_query_tcp_with_timeout returned %i", ret);

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_query_tcp_ex_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying using TCP message to %s:%i", server_listen_address_text, server_listen_port);

    ret = dns_message_query_tcp_ex(mesg, NULL, server_ha, mesg64K);

    if(FAIL(ret))
    {
        yatest_err("dns_message_query_tcp_ex failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_query_tcp_ex returned %i", ret);

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_query_tcp_ex_bindto_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying using TCP message to %s:%i", server_listen_address_text, server_listen_port);

    // attempts several ports in case one is taken already

    for(int tried_port = 40000; tried_port < 40100; ++tried_port)
    {
        host_address_t *client_ha = host_address_new_instance_parse_port("127.0.0.1", tried_port);
        ret = dns_message_query_tcp_ex(mesg, client_ha, server_ha, mesg64K);
        host_address_delete(client_ha);
        if(ISOK(ret))
        {
            break;
        }

        yatest_log("dns_message_query_tcp_ex bind to localhost:%i failed with %08x=%s", tried_port, ret, error_gettext(ret));
    }

    if(FAIL(ret))
    {
        yatest_err("dns_message_query_tcp_ex failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_query_tcp_ex returned %i", ret);

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_query_tcp_timeout_ex_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying using TCP message to %s:%i", server_listen_address_text, server_listen_port);

    ret = dns_message_query_tcp_with_timeout_ex(mesg, server_ha, mesg64K, 3);

    if(FAIL(ret))
    {
        yatest_err("dns_message_query_tcp_with_timeout_ex failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_query_tcp_with_timeout_ex returned %i", ret);

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_write_read_tcp_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    yatest_log("creating TCP connection to %s:%i", server_listen_address_text, server_listen_port);

    int             sockfd = yatest_socket_create(server_listen_address_text, server_listen_port, SOCK_STREAM);

    input_stream_t  tcp_is;
    output_stream_t tcp_os;

    fd_input_stream_attach(&tcp_is, sockfd);
    fd_output_stream_attach_noclose(&tcp_os, sockfd);

    yatest_log("dns_message_write_tcp sending message");

    ret = dns_message_write_tcp(mesg, &tcp_os);

    if(FAIL(ret))
    {
        yatest_err("dns_message_write_tcp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_write_tcp returned %i", ret);

    yatest_log("dns_message_read_tcp receiving message");

    ret = dns_message_read_tcp(mesg, &tcp_is);

    if(FAIL(ret))
    {
        yatest_err("dns_message_read_tcp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_read_tcp returned %i", ret);

    yatest_log("finalising");

    output_stream_close(&tcp_os);
    input_stream_close(&tcp_is);

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_send_recv_tcp_min_throughput_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    yatest_log("creating TCP connection to %s:%i", server_listen_address_text, server_listen_port);

    int sockfd = yatest_socket_create(server_listen_address_text, server_listen_port, SOCK_STREAM);

    yatest_log("dns_message_write_tcp sending message");

    ret = dns_message_send_tcp_with_minimum_throughput(mesg, sockfd, 2.0);

    if(FAIL(ret))
    {
        yatest_err("dns_message_send_tcp_with_minimum_throughput failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_send_tcp_with_minimum_throughput returned %i", ret);

    yatest_log("dns_message_recv_tcp receiving message");

    ret = dns_message_recv_tcp(mesg, sockfd);

    if(FAIL(ret))
    {
        yatest_err("dns_message_recv_tcp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_recv_tcp returned %i", ret);

    yatest_log("finalising");

    socketclose_ex(sockfd);

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_send_recv_tcp_default_min_throughput_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler_slow_reply, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    yatest_log("creating TCP connection to %s:%i", server_listen_address_text, server_listen_port);

    int sockfd = yatest_socket_create(server_listen_address_text, server_listen_port, SOCK_STREAM);

    yatest_log("dns_message_write_tcp sending message");

    ret = dns_message_update_length_send_tcp_with_default_minimum_throughput(mesg, sockfd);

    if(FAIL(ret)) // should not fail because such a small message will get buffered
    {
        yatest_err("dns_message_send_tcp_with_minimum_throughput failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_send_tcp_with_minimum_throughput returned %i", ret);

    yatest_log("dns_message_recv_tcp receiving message");

    ret = dns_message_recv_tcp(mesg, sockfd);

    if(FAIL(ret))
    {
        yatest_err("dns_message_recv_tcp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_recv_tcp returned %i", ret);

    yatest_log("finalising");

    socketclose_ex(sockfd);

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_make_error_and_reply_tcp_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    dns_message_process(mesg);

    yatest_log("creating TCP connection to %s:%i", server_listen_address_text, server_listen_port);

    int sockfd = yatest_socket_create(server_listen_address_text, server_listen_port, SOCK_STREAM);

    yatest_log("dns_message_make_error_and_reply_tcp sending message");

    ret = dns_message_make_error_and_reply_tcp(mesg, RCODE_NOTIMP, sockfd);

    if(FAIL(ret))
    {
        yatest_err("dns_message_make_error_and_reply_tcp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_make_error_and_reply_tcp returned %i", ret);

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_make_error_and_reply_tcp_with_default_minimum_throughput_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    dns_message_process(mesg);

    yatest_log("creating TCP connection to %s:%i", server_listen_address_text, server_listen_port);

    int sockfd = yatest_socket_create(server_listen_address_text, server_listen_port, SOCK_STREAM);

    yatest_log("dns_message_make_error_and_reply_tcp_with_default_minimum_throughput sending message");

    ret = dns_message_make_error_and_reply_tcp_with_default_minimum_throughput(mesg, RCODE_NOTIMP, sockfd);

    if(FAIL(ret))
    {
        yatest_err("dns_message_make_error_and_reply_tcp_with_default_minimum_throughput failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_make_error_and_reply_tcp_with_default_minimum_throughput returned %i", ret);

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_send_recv_udp_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, wWw_YaDiFa_eU, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    yatest_log("creating UDP connection to %s:%i", server_listen_address_text, server_listen_port);

    int                    sockfd = yatest_socket_create(server_listen_address_text, server_listen_port, SOCK_DGRAM);

    yatest_socketaddress_t ss;
    socklen_t              sa_len = yatest_socketaddress_init(&ss, server_listen_address_text, server_listen_port);
    dns_message_copy_sender_from_sa(mesg, &ss.sa, sa_len);

    yatest_log("dns_message_send_udp sending message");

    ret = dns_message_send_udp(mesg, sockfd);

    if(FAIL(ret))
    {
        yatest_err("dns_message_send_udp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_send_udp returned %i", ret);

    if(memcmp(dns_message_parse_query_fqdn(mesg), wWw_YaDiFa_eU, sizeof(www_yadifa_eu)) != 0)
    {
        yatest_err("dns_message_parse_query_fqdn didn't return the expected name");
        return 1;
    }

    if(dns_message_parse_query_type(mesg) != query_type_const)
    {
        yatest_err("dns_message_parse_query_type didn't return the expected type");
        return 1;
    }

    if(dns_message_parse_query_class(mesg) != query_class_const)
    {
        yatest_err("dns_message_parse_query_class didn't return the expected class");
        return 1;
    }

    yatest_log("dns_message_recv_udp receiving message");

    dns_message_recv_udp_reset(mesg);

    ret = dns_message_recv_udp(mesg, sockfd);

    if(FAIL(ret))
    {
        yatest_err("dns_message_recv_udp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_recv_udp returned %i", ret);

    dns_message_process_lenient(mesg);

    const uint8_t *canonised_fqdn = dns_message_get_canonised_fqdn(mesg);
    if(!dnsname_equals(canonised_fqdn, www_yadifa_eu))
    {
        yatest_err("dns_message_get_canonised_fqdn didn't return an expected value: (got/expected)");
        yatest_hexdump(canonised_fqdn, canonised_fqdn + dnsname_len(canonised_fqdn));
        yatest_hexdump(www_yadifa_eu, www_yadifa_eu + dnsname_len(canonised_fqdn));
        return 1;
    }

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_send_debug_recv_udp_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, wWw_YaDiFa_eU, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    yatest_log("creating UDP connection to %s:%i", server_listen_address_text, server_listen_port);

    int                    sockfd = yatest_socket_create(server_listen_address_text, server_listen_port, SOCK_DGRAM);

    yatest_socketaddress_t ss;
    socklen_t              sa_len = yatest_socketaddress_init(&ss, server_listen_address_text, server_listen_port);
    dns_message_copy_sender_from_sa(mesg, &ss.sa, sa_len);

    yatest_log("dns_message_send_udp_debug sending message");

    int32_t dns_message_send_udp_debug(const dns_message_t *mesg, int sockfd);

    ret = dns_message_send_udp_debug(mesg, sockfd);

    if(FAIL(ret))
    {
        yatest_err("dns_message_send_udp_debug failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_send_udp_debug returned %i", ret);

    if(memcmp(dns_message_parse_query_fqdn(mesg), wWw_YaDiFa_eU, sizeof(www_yadifa_eu)) != 0)
    {
        yatest_err("dns_message_parse_query_fqdn didn't return the expected name");
        return 1;
    }

    if(dns_message_parse_query_type(mesg) != query_type_const)
    {
        yatest_err("dns_message_parse_query_type didn't return the expected type");
        return 1;
    }

    if(dns_message_parse_query_class(mesg) != query_class_const)
    {
        yatest_err("dns_message_parse_query_class didn't return the expected class");
        return 1;
    }

    yatest_log("dns_message_recv_udp receiving message");

    dns_message_recv_udp_reset(mesg);

    ret = dns_message_recv_udp(mesg, sockfd);

    if(FAIL(ret))
    {
        yatest_err("dns_message_recv_udp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_recv_udp returned %i", ret);

    dns_message_process_lenient(mesg);

    const uint8_t *canonised_fqdn = dns_message_get_canonised_fqdn(mesg);
    if(!dnsname_equals(canonised_fqdn, www_yadifa_eu))
    {
        yatest_err("dns_message_get_canonised_fqdn didn't return an expected value: (got/expected)");
        yatest_hexdump(canonised_fqdn, canonised_fqdn + dnsname_len(canonised_fqdn));
        yatest_hexdump(www_yadifa_eu, www_yadifa_eu + dnsname_len(canonised_fqdn));
        return 1;
    }

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_query_udp_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying using UDP message to %s:%i", server_listen_address_text, server_listen_port);

    ret = dns_message_query_udp(mesg, server_ha);

    if(FAIL(ret))
    {
        yatest_err("dns_message_query_udp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_query_udp returned %i", ret);

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_query_udp_with_timeout_and_retries_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying using UDP message to %s:%i", server_listen_address_text, server_listen_port);

    ret = dns_message_query_udp_with_timeout_and_retries(mesg, server_ha, 3, 0, 5, 0); // note: MESSAGE_QUERY_UDP_FLAG_RESET_ID will break the signature (duh)

    if(FAIL(ret))
    {
        yatest_err("dns_message_query_udp failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_query_udp returned %i", ret);

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_query_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying message to %s:%i", server_listen_address_text, server_listen_port);

    ret = dns_message_query(mesg, server_ha);

    if(FAIL(ret))
    {
        yatest_err("dns_message_query failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_query returned %i", ret);

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_query_but_truncated_test()
{
    network_test_udp_handler_truncate_messages = true;

    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    yatest_socketserver_start(&mockserver2, server_listen_address_text, server_listen_port, SOCK_STREAM, network_test_init, network_test_tcp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying message to %s:%i", server_listen_address_text, server_listen_port);

    ret = dns_message_query(mesg, server_ha);

    if(FAIL(ret))
    {
        yatest_err("dns_message_query failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_query returned %i", ret);

    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
    flushout();

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server2");
    yatest_socketserver_stop(&mockserver2);

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_query_serial_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying message to %s:%i", server_listen_address_text, server_listen_port);

    uint32_t serial = 0;
    ret = dns_message_query_serial(www_yadifa_eu, server_ha, &serial);

    if(FAIL(ret))
    {
        yatest_err("dns_message_query_serial failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_query_serial returned %i, serial=%u", ret, serial);

    if(serial == 0)
    {
        yatest_err("dns_message_query_serial returned serial is expected to not be zero");
        return 1;
    }

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_ixfr_query_get_serial_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_SOA;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying message to %s:%i", server_listen_address_text, server_listen_port);

    ret = dns_message_query(mesg, server_ha);

    if(FAIL(ret))
    {
        yatest_err("dns_message_query failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_query returned %i", ret);

    uint32_t serial;
    ret = dns_message_ixfr_query_get_serial(mesg, &serial);

    if(FAIL(ret))
    {
        yatest_err("dns_message_ixfr_query_get_serial failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("dns_message_ixfr_query_get_serial returned %i, serial=%u", ret, serial);

    if(serial == 0)
    {
        yatest_err("dns_message_ixfr_query_get_serial returned serial is expected to not be zero");
        return 1;
    }

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int network_dns_message_dup_test()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_DGRAM, network_test_init, network_test_udp_handler, network_test_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);

    init();

    int            ret;
    dns_message_t *mesg = mesg512;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query(mesg, 0x1234, yadifa_eu, query_type_const, query_class_const);
    dns_message_set_client_cookie_for_server_sockaddr(mesg, &dummy_sa[0]);
    dns_message_add_opt(mesg);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    yatest_log("client query");
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
    flushout();

    host_address_t *server_ha = host_address_new_instance_parse_port(server_listen_address_text, server_listen_port);

    yatest_log("querying message to %s:%i", server_listen_address_text, server_listen_port);

    ret = dns_message_query(mesg, server_ha);

    if(FAIL(ret))
    {
        yatest_err("dns_message_query failed with %s", error_gettext(ret));
        return 1;
    }

    yatest_log("server answer");
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
    flushout();

    yatest_log("making duplicate");

    dns_message_t *mesg_dup = dns_message_dup(mesg);

    if(mesg->_msghdr.msg_controllen != mesg_dup->_msghdr.msg_controllen)
    {
        yatest_err("dns_message_dup: msghdr.msg_controllen doesn't match");
        return 1;
    }

    if(dns_message_get_size(mesg) != dns_message_get_size(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_get_size doesn't match");
        return 1;
    }

    if(!sockaddr_equals(dns_message_get_sender_sa(mesg), dns_message_get_sender_sa(mesg_dup)))
    {
        yatest_err("dns_message_dup: sender doesn't match");
        return 1;
    }

    if((dns_message_get_additional_section_ptr_const(mesg) - dns_message_get_buffer_const(mesg)) != (dns_message_get_additional_section_ptr_const(mesg_dup) - dns_message_get_buffer_const(mesg_dup)))
    {
        yatest_err("dns_message_dup: dns_message_get_additional_section_ptr_const doesn't match");
        return 1;
    }

    if(dns_message_get_edns0_opt_ttl(mesg) != dns_message_get_edns0_opt_ttl(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_get_edns0_opt_ttl doesn't match");
        return 1;
    }

    if(dns_message_get_status(mesg) != dns_message_get_status(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_get_status doesn't match");
        return 1;
    }

    if(dns_message_get_query_type(mesg) != dns_message_get_query_type(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_get_query_type doesn't match");
        return 1;
    }

    if(dns_message_get_query_class(mesg) != dns_message_get_query_class(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_get_query_class doesn't match");
        return 1;
    }

    if(dns_message_opt_get(mesg) != dns_message_opt_get(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_get_query_class doesn't match");
        return 1;
    }

    if(dns_message_get_referral(mesg) != dns_message_get_referral(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_get_referral doesn't match");
        return 1;
    }

    if(dns_message_get_buffer_size(mesg) != dns_message_get_buffer_size(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_get_buffer_size doesn't match");
        return 1;
    }

    if(dns_message_get_buffer_size_max(mesg) != dns_message_get_buffer_size_max(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_get_buffer_size_max doesn't match");
        return 1;
    }

    if(dns_message_has_tsig(mesg) != dns_message_has_tsig(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_has_tsig doesn't match");
        return 1;
    }

    if(!dns_message_has_tsig(mesg))
    {
        yatest_err("dns_message_dup: dns_message_has_cookie expected to be true");
        return 1;
    }

    if(dns_message_tsig_get_key(mesg) != dns_message_tsig_get_key(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_tsig_get_key doesn't match");
        return 1;
    }

    if(dns_message_has_cookie(mesg) != dns_message_has_cookie(mesg_dup))
    {
        yatest_err("dns_message_dup: dns_message_has_cookie doesn't match");
        return 1;
    }

    if(!dns_message_has_cookie(mesg))
    {
        yatest_err("dns_message_dup: dns_message_has_cookie expected to be true");
        return 1;
    }

    if(mesg->_control_buffer_size != mesg_dup->_control_buffer_size)
    {
        yatest_err("dns_message_dup: _control_buffer_size doesn't match");
        return 1;
    }

    if(memcmp(mesg->_msghdr_control_buffer, mesg_dup->_msghdr_control_buffer, mesg->_control_buffer_size) != 0)
    {
        yatest_err("dns_message_dup: _msghdr_control_buffer doesn't match");
        return 1;
    }

    size_t mesg_fqdn_size = yatest_dns_name_len(dns_message_get_canonised_fqdn(mesg));
    size_t mesg_dup_fqdn_size = yatest_dns_name_len(dns_message_get_canonised_fqdn(mesg_dup));

    if(mesg_fqdn_size != mesg_dup_fqdn_size)
    {
        yatest_err("dns_message_dup: dns_message_get_canonised_fqdn size doesn't match");
        return 1;
    }

    if(memcmp(dns_message_get_canonised_fqdn(mesg), dns_message_get_canonised_fqdn(mesg_dup), mesg_fqdn_size) != 0)
    {
        yatest_err("dns_message_dup: dns_message_get_canonised_fqdn doesn't match");
        return 1;
    }

    if(mesg->_cookie.size != mesg_dup->_cookie.size)
    {
        yatest_err("dns_message_dup: _cookie.size doesn't match");
        return 1;
    }

    if(memcmp(mesg->_cookie.bytes, mesg_dup->_cookie.bytes, mesg->_cookie.size) != 0)
    {
        yatest_err("dns_message_dup: _cookie.bytes doesn't match");
        return 1;
    }

    if(memcmp(mesg->_buffer, mesg_dup->_buffer, dns_message_get_size(mesg)) != 0)
    {
        yatest_err("dns_message_dup: _buffer doesn't match");
        return 1;
    }

    yatest_log("finalising");

    finalise();

    yatest_log("stopping server");
    yatest_socketserver_stop(&mockserver);

    return 0;
}

static int dns_message_with_buffer()
{
    init();

    dns_message_with_buffer_t *mesg_buff;
    MALLOC_OBJECT_OR_DIE(mesg_buff, dns_message_with_buffer_t, GENERIC_TAG);
    dns_message_t *mesg;
    mesg = dns_message_data_with_buffer_init(mesg_buff);
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    dns_message_delete(mesg);

    finalise();

    return 0;
}

// everything above is only for dns_message.h

static int dns_message_map_test()
{
    init();

    int            ret;
    dns_message_t *mesg = mesg64K;
    const uint16_t query_type_const = TYPE_ANY;
    const uint16_t query_class_const = CLASS_IN;

    dns_message_set_edns0(mesg, true);
    dns_message_make_query(mesg, 0x1234, yadifa_eu, query_type_const, query_class_const);
    dns_message_set_client_cookie_for_server_sockaddr(mesg, &dummy_sa[0]);
    dns_packet_writer_t pw;
    dns_packet_writer_init_append_to_message(&pw, mesg);
    dns_packet_writer_add_record(&pw, www_yadifa_eu, TYPE_MX, CLASS_IN, ntohl(86400), mx_rdata, sizeof(mx_rdata));
    dns_packet_writer_add_record(&pw, www_yadifa_eu, TYPE_NSEC, CLASS_IN, ntohl(86400), nsec_rdata, sizeof(nsec_rdata));
    dns_packet_writer_add_record(&pw, www_yadifa_eu, TYPE_A, CLASS_IN, ntohl(86400), ipv4_0, sizeof(ipv4_0));
    dns_packet_writer_add_record(&pw, www_yadifa_eu, TYPE_A, CLASS_IN, ntohl(86400), ipv4_1, sizeof(ipv4_1));

    dns_packet_writer_add_record(&pw, yadifa_eu, TYPE_RRSIG, CLASS_IN, ntohl(86400), rrsig_over_soa_rdata, sizeof(rrsig_over_soa_rdata));
    dns_packet_writer_add_record(&pw, yadifa_eu, TYPE_SOA, CLASS_IN, ntohl(86400), soa_rdata, sizeof(soa_rdata));
    dns_packet_writer_add_record(&pw, yadifa_eu, TYPE_NS, CLASS_IN, ntohl(86400), ns1_yadifa_eu, sizeof(ns1_yadifa_eu));
    dns_packet_writer_add_record(&pw, yadifa_eu, TYPE_RRSIG, CLASS_IN, ntohl(86400), rrsig_over_ns_rdata, sizeof(rrsig_over_ns_rdata));

    dns_packet_writer_add_record(&pw, ns1_yadifa_eu, TYPE_A, CLASS_IN, ntohl(86400), ipv4_1, sizeof(ipv4_1));
    dns_packet_writer_add_record(&pw, www_yadifa_eu, TYPE_AAAA, CLASS_IN, ntohl(86400), ipv6_0, sizeof(ipv6_0));
    dns_packet_writer_add_record(&pw, www_yadifa_eu, TYPE_AAAA, CLASS_IN, ntohl(86400), ipv6_1, sizeof(ipv6_1));
    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 4, 4, 3);
    dns_message_add_opt(mesg);
    dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));

    yatest_log("message");
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
    flushout();

    uint8_t                       fqdn[FQDN_LENGTH_MAX];
    struct type_class_ttl_rdlen_s tctr;
    const int                     rdata_size = 0x10000;
    uint8_t                      *rdata = (uint8_t *)malloc(rdata_size);

    dns_message_map_t             map;
    dns_message_map_init(&map, mesg);

    int record_count = dns_message_map_record_count(&map);
    int expected_count = dns_message_get_query_count(mesg) + dns_message_get_answer_count(mesg) + dns_message_get_authority_count(mesg) + dns_message_get_additional_count(mesg);

    if(record_count != expected_count)
    {
        yatest_err("record_count != expected_count : %i != %i", record_count, expected_count);
        return 1;
    }

    if((ret = dns_message_map_get_next_record_from(&map, 0, TYPE_NSEC)) != 2)
    {
        yatest_err("dns_message_map_get_next_record_from for TYPE_NSEC expected to return 2, returned %i instead", ret);
        return 1;
    }

    if((ret = dns_message_map_get_next_record_from_section(&map, 1, 0, TYPE_NSEC)) != 1)
    {
        yatest_err("dns_message_map_get_next_record_from_section for TYPE_NSEC expected to return 1, returned %i instead", ret);
        return 1;
    }

    if((ret = dns_message_map_get_next_record_from(&map, 0, 0xffff)) != -1)
    {
        yatest_err(
            "dns_message_map_get_next_record_from for a type that doesn't exist expected to return -1, returned %i "
            "instead",
            ret);
        return 1;
    }

    for(int section_index = 0; section_index < 4; ++section_index)
    {
        int section_offset = dns_message_map_get_section_base(&map, section_index);
        int section_size = dns_message_map_get_section_count(&map, section_index);
        yatest_log("section %i base index = %i", section_index, section_offset);
        for(int i = section_offset; i < section_offset + section_size; ++i)
        {
            if(FAIL(ret = dns_message_map_get_fqdn(&map, i, fqdn, sizeof(fqdn))))
            {
                yatest_err("dns_message_map_get_fqdn(&map, %i, ...) failed with %08x = %s", i, ret, error_gettext(ret));
                return 1;
            }
            if(section_index > 0)
            {
                memset(&tctr, 0, sizeof(tctr));
                if(FAIL(ret = dns_message_map_get_tctr(&map, i, &tctr)))
                {
                    yatest_err("dns_message_map_get_tctr(&map, %i, ...) failed with %08x = %s", i, ret, error_gettext(ret));
                    return 1;
                }
                if(FAIL(ret = dns_message_map_get_rdata(&map, i, rdata, rdata_size)))
                {
                    yatest_err("dns_message_map_get_rdata(&map, %i, ...) failed with %08x = %s", i, ret, error_gettext(ret));
                    return 1;
                }
            }
            else
            {
                if(FAIL(ret = dns_message_map_get_tctr(&map, i, &tctr)))
                {
                    yatest_err("dns_message_map_get_tctr(&map, %i, ...) failed with %08x = %s", i, ret, error_gettext(ret));
                    return 1;
                }
            }

            if(FAIL(ret = dns_message_map_get_type(&map, i)))
            {
                yatest_err("dns_message_map_get_type(&map, %i, ...) failed with %08x = %s", i, ret, error_gettext(ret));
                return 1;
            }

            if(section_index > 0)
            {
                if(ret != tctr.rtype)
                {
                    yatest_err("dns_message_map_get_type and dns_message_map_get_rdata do not agree for record %i", i);
                    return 1;
                }
            }

            yatest_log("record %i is %s", i, dns_type_get_name(ret));
        }
    }

    dns_message_map_reorder(&map);

    yatest_log("reordered message (map-printed)");
    dns_message_map_print(&map, termout);
    flushout();

    dns_message_map_finalize(&map);

    finalise();
    return 0;
}

struct dns_message_generated_flags_s
{
    uint64_t options;
    bool     has_edns0;
    bool     has_cookie;
    bool     is_answer;
    bool     is_truncated;
    bool     has_broken_qd;
    bool     has_broken_an;
    bool     has_broken_ns;
    bool     has_broken_ar;
    bool     has_broken_fqdn;
    bool     has_tsig;
};

typedef struct dns_message_generated_flags_s dns_message_generated_flags_t;

typedef int                                  dns_message_generated_callback(dns_message_t *mesg, dns_message_generated_flags_t *generated_flags);

static int                                   dns_message_generated_test(int opcode, dns_message_generated_callback *callback, const char *callback_name)
{
    init();

    const char    *opcode_name = dns_message_opcode_get_name(opcode >> OPCODE_SHIFT);
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;

    ya_result      ret;

    for(uint64_t options = 0; options < (1ULL << 10); ++options)
    {
        dns_message_t                *mesg = dns_message_new_instance();

        dns_message_generated_flags_t generated_flags;
        memset(&generated_flags, 0, sizeof(generated_flags));
        generated_flags.options = options;

        yatest_log("%s: options: %02x, opcode = %s", callback_name, options, opcode_name);

        if(options & 1)
        {
            dns_message_set_edns0(mesg, true); // option
            yatest_log("%s: EDNS0", callback_name);
            generated_flags.has_edns0 = true;
        }

        switch(opcode)
        {
            case OPCODE_QUERY:
            {
                dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
                break;
            }
            case OPCODE_NOTIFY:
            {
                dns_message_make_notify(mesg, 0x1234, www_yadifa_eu, TYPE_SOA, CLASS_IN);
                break;
            }
            default:
            {
                dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, TYPE_SOA, CLASS_IN, 0);
                dns_message_set_opcode(mesg, opcode);
                break;
            }
        }

        // truncate everything
        dns_message_set_query_answer_authority_additional_counts(mesg, 0, 0, 0, 0);
        dns_message_set_size(mesg, DNS_HEADER_LENGTH);
        struct dns_packet_writer_s pw;
        dns_packet_writer_init_into_message(&pw, mesg);

        // sets the answer flag

        if(options & 2)
        {
            dns_message_set_answer(mesg); // option
            yatest_log("%s: answer", callback_name);
            generated_flags.is_answer = true;
        }

        // sets the truncated flag

        if(options & 4)
        {
            dns_message_set_truncated(mesg, true); // option
            yatest_log("%s: truncated", callback_name);
            generated_flags.is_truncated = true;
        }

        // adds query records (0 to 3)

        int qd_count = (options & 24) >> 3;
        dns_message_set_query_answer_authority_additional_counts(mesg, qd_count, 0, 0, 0);
        yatest_log("%s: generated QD = %i", callback_name, qd_count);
        for(int i = 0; i < qd_count; ++i)
        {
            dns_packet_writer_add_fqdn(&pw, www_yadifa_eu);
            dns_packet_writer_add_u16(&pw, TYPE_A);
            dns_packet_writer_add_u16(&pw, CLASS_IN);
        }
        generated_flags.has_broken_qd = qd_count != 1;

        // adds an AN record

        if(options & 32)
        {
            dns_packet_writer_add_record(&pw, www_yadifa_eu, TYPE_A, CLASS_IN, NU32(86400), localhost_a_wire, sizeof(localhost_a_wire));
            dns_message_set_answer_count(mesg, 1);
            yatest_log("%s: generated AN > 0", callback_name);
            generated_flags.has_broken_an = true;
        }

        // adds an NS record

        if(options & 64)
        {
            dns_packet_writer_add_record(&pw, www_yadifa_eu, TYPE_NS, CLASS_IN, NU32(86400), ns1_yadifa_eu, sizeof(ns1_yadifa_eu));
            dns_message_set_authority_count(mesg, 1);
            yatest_log("%s: generated NS > 0", callback_name);
            generated_flags.has_broken_ns = true;
        }

        if(options & 128)
        {
            dns_packet_writer_add_record(&pw, ns1_yadifa_eu, TYPE_A, CLASS_IN, NU32(86400), localhost_a_wire, sizeof(localhost_a_wire));
            dns_message_set_additional_count(mesg, 1);
            yatest_log("%s: generated AR > 0", callback_name);
            generated_flags.has_broken_ar = true;
        }

        if((options & 256) && (qd_count > 0))
        {
            dns_message_get_buffer(mesg)[12] = 0xff; // breaks the FQDN (and the whole message)
            yatest_log("%s: generated FQDN", callback_name);
            generated_flags.has_broken_fqdn = true;
        }

        dns_message_set_size(mesg, dns_packet_writer_get_offset(&pw));

        if(options & 512)
        {
            dns_message_set_client_cookie(mesg, 0x123456789abcdefULL); // option
            dns_message_add_opt(mesg);
            yatest_log("%s: COOKIE", callback_name);
            generated_flags.has_cookie = true;
        }

        if(options & 1024)
        {
            dns_message_sign_query(mesg, tsig_get(MYKEY_NAME)); // option
            yatest_log("%s: signed", callback_name);
            generated_flags.has_tsig = true;
        }

        dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
        flushout();

        ret = callback(mesg, &generated_flags);

        if(ret != 0)
        {
            return ret;
        }

        dns_message_log(g_test_logger, 0, mesg);

        dns_message_delete(mesg);
    }

    finalise();
    return 0;
}

static int dns_message_process_over_query_test_callback(dns_message_t *mesg, dns_message_generated_flags_t *generated_flags)
{
    int ret;

    ret = dns_message_process(mesg);

    yatest_log("dns_message_process_over_query_test: process returned %08x: %s", ret, error_gettext(ret));

    if(generated_flags->has_broken_qd)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_query_test: should not be able to process a message with a QD != 1");
            return 1;
        }
    }
    else if(generated_flags->has_broken_ar)
    {
        if(ISOK(ret))
        {
            yatest_err(
                "dns_message_process_over_query_test: should not be able to process a message with a AR records not "
                "OPT nor TSIG");
            return 1;
        }
    }
    else if(generated_flags->has_broken_ns)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_query_test: should not be able to process a message with a NS > 0");
            return 1;
        }
    }
    else if(generated_flags->has_broken_fqdn)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_query_test: should not be able to process a message with a generated FQDN");
            return 1;
        }
    }
    else if(generated_flags->is_answer)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_query_test: should not be able to process an answer");
            return 1;
        }
    }
    else if(generated_flags->is_truncated)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_query_test: should not be able to process a truncated query");
            return 1;
        }
    }
    else // should be valid
    {
        if(FAIL(ret))
        {
            yatest_err("dns_message_process_over_query_test: should be able to process a query");
            return 1;
        }
    }

    return 0;
}

static int dns_message_process_over_query_test() { return dns_message_generated_test(OPCODE_QUERY, dns_message_process_over_query_test_callback, "dns_message_process_over_query_test"); }

static int dns_message_process_over_notify_test_callback(dns_message_t *mesg, dns_message_generated_flags_t *generated_flags)
{
    int ret;

    ret = dns_message_process(mesg);

    yatest_log("dns_message_process_over_notify_test: process returned %08x: %s", ret, error_gettext(ret));

    if(generated_flags->has_broken_qd)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_notify_test: should not be able to process a message with a QD != 1");
            return 1;
        }
    }
    else if(generated_flags->has_broken_ar)
    {
        if(ISOK(ret))
        {
            yatest_err(
                "dns_message_process_over_notify_test: should not be able to process a message with a AR records not "
                "OPT nor TSIG");
            return 1;
        }
    }
    else if(generated_flags->has_broken_fqdn)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_notify_test: should not be able to process a message with a generated FQDN");
            return 1;
        }
    }
    else if(generated_flags->is_truncated)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_notify_test: should not be able to process a truncated query");
            return 1;
        }
    }
    else // should be valid
    {
        if(FAIL(ret))
        {
            yatest_err("dns_message_process_over_notify_test: should be able to process a query");
            return 1;
        }
    }

    return 0;
}

static int dns_message_process_over_notify_test() { return dns_message_generated_test(OPCODE_NOTIFY, dns_message_process_over_notify_test_callback, "dns_message_process_over_notify_test"); }

static int dns_message_process_over_update_test_callback(dns_message_t *mesg, dns_message_generated_flags_t *generated_flags)
{
    int ret;

    ret = dns_message_process(mesg);

    yatest_log("dns_message_process_over_update_test: process returned %08x: %s", ret, error_gettext(ret));

    if(generated_flags->has_broken_qd)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_update_test: should not be able to process a message with a QD != 1");
            return 1;
        }
    }
    else if(generated_flags->has_broken_ar)
    {
        if(ISOK(ret))
        {
            yatest_err(
                "dns_message_process_over_update_test: should not be able to process a message with a AR records not "
                "OPT nor TSIG");
            return 1;
        }
    }
    else if(generated_flags->has_broken_fqdn)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_update_test: should not be able to process a message with a generated FQDN");
            return 1;
        }
    }
    else if(generated_flags->is_answer)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_update_test: should not be able to process an answer");
            return 1;
        }
    }
    else if(generated_flags->is_truncated)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_update_test: should not be able to process a truncated query");
            return 1;
        }
    }
    else // should be valid
    {
        if(FAIL(ret))
        {
            yatest_err("dns_message_process_over_update_test: should be able to process a query");
            return 1;
        }
    }

    return 0;
}

static int dns_message_process_over_update_test() { return dns_message_generated_test(OPCODE_UPDATE, dns_message_process_over_update_test_callback, "dns_message_process_over_update_test"); }

static int dns_message_process_over_ctrl_test_callback(dns_message_t *mesg, dns_message_generated_flags_t *generated_flags)
{
    int ret;

    ret = dns_message_process(mesg);

    yatest_log("dns_message_process_over_ctrl_test: process returned %08x: %s", ret, error_gettext(ret));

    if(generated_flags->has_broken_qd)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_ctrl_test: should not be able to process a message with a QD != 1");
            return 1;
        }
    }
    else if(generated_flags->has_broken_ar)
    {
        if(ISOK(ret))
        {
            yatest_err(
                "dns_message_process_over_ctrl_test: should not be able to process a message with a AR records not OPT "
                "nor TSIG");
            return 1;
        }
    }
    else if(generated_flags->has_broken_fqdn)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_ctrl_test: should not be able to process a message with a generated FQDN");
            return 1;
        }
    }
    else if(generated_flags->is_answer)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_ctrl_test: should not be able to process an answer");
            return 1;
        }
    }
    else if(generated_flags->is_truncated)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_over_ctrl_test: should not be able to process a truncated query");
            return 1;
        }
    }
    else // should be valid
    {
        if(FAIL(ret))
        {
            yatest_err("dns_message_process_over_ctrl_test: should be able to process a query");
            return 1;
        }
    }

    return 0;
}

static int dns_message_process_over_ctrl_test()
{
#if DNSCORE_HAS_CTRL
    return dns_message_generated_test(OPCODE_CTRL, dns_message_process_over_ctrl_test_callback, "dns_message_process_over_ctrl_test");
#else
    yatest_log("dns_message_process_over_ctrl_test: OPCODE_CTRL not built-in: test skipped.");
    return 0;
#endif
}

static int dns_message_process_over_iquery_test_callback(dns_message_t *mesg, dns_message_generated_flags_t *generated_flags)
{
    int ret;

    ret = dns_message_process(mesg);

    yatest_log("dns_message_process_over_iquery_test: process returned %08x: %s", ret, error_gettext(ret));

    if(generated_flags->is_answer)
    {
        if(ret != INVALID_MESSAGE)
        {
            yatest_err("dns_message_process_over_iquery_test: expected INVALID_MESSAGE for answer, got %08x = %s instead", error_gettext(ret));
            return 1;
        }
    }
    else
    {
        if(ret != UNPROCESSABLE_MESSAGE)
        {
            yatest_err(
                "dns_message_process_over_iquery_test: expected UNPROCESSABLE_MESSAGE for answer, got %08x = %s "
                "instead",
                error_gettext(ret));
            return 1;
        }
    }

    return 0;
}

static int dns_message_process_over_iquery_test()
{
#if DNSCORE_HAS_CTRL
    return dns_message_generated_test(OPCODE_IQUERY, dns_message_process_over_iquery_test_callback, "dns_message_process_over_iquery_test");
#else
    yatest_log("dns_message_process_over_iquery_test: OPCODE_CTRL not built-in: test skipped.");
    return 0;
#endif
}

static int dns_message_process_lenient_over_query_test_callback(dns_message_t *mesg, dns_message_generated_flags_t *generated_flags)
{
    int ret;

    ret = dns_message_process_lenient(mesg);

    yatest_log("dns_message_process_lenient_over_query_test: process returned %08x: %s", ret, error_gettext(ret));

    if(generated_flags->has_broken_fqdn)
    {
        if(ISOK(ret))
        {
            yatest_err(
                "dns_message_process_lenient_over_query_test: should not be able to process a message with a generated "
                "FQDN");
            return 1;
        }
    }
    else // should be valid
    {
        if(FAIL(ret))
        {
            yatest_err("dns_message_process_lenient_over_query_test: should be able to process a query");
            return 1;
        }
    }

    return 0;
}

static int dns_message_process_lenient_over_query_test() { return dns_message_generated_test(OPCODE_QUERY, dns_message_process_lenient_over_query_test_callback, "dns_message_process_lenient_over_query_test"); }

static int dns_message_process_lenient_over_notify_test_callback(dns_message_t *mesg, dns_message_generated_flags_t *generated_flags)
{
    int ret;

    ret = dns_message_process_lenient(mesg);

    yatest_log("dns_message_process_lenient_over_notify_test: process returned %08x: %s", ret, error_gettext(ret));

    if(generated_flags->has_broken_fqdn)
    {
        if(ISOK(ret))
        {
            yatest_err(
                "dns_message_process_lenient_over_notify_test: should not be able to process a message with a "
                "generated FQDN");
            return 1;
        }
    }
    else // should be valid
    {
        if(FAIL(ret))
        {
            yatest_err("dns_message_process_lenient_over_notify_test: should be able to process a query");
            return 1;
        }
    }

    return 0;
}

static int dns_message_process_lenient_over_notify_test() { return dns_message_generated_test(OPCODE_NOTIFY, dns_message_process_lenient_over_notify_test_callback, "dns_message_process_lenient_over_notify_test"); }

static int dns_message_process_lenient_over_update_test_callback(dns_message_t *mesg, dns_message_generated_flags_t *generated_flags)
{
    int ret;

    ret = dns_message_process_lenient(mesg);

    yatest_log("dns_message_process_lenient_over_update_test: process returned %08x: %s", ret, error_gettext(ret));

    if(generated_flags->has_broken_fqdn)
    {
        if(ISOK(ret))
        {
            yatest_err(
                "dns_message_process_lenient_over_update_test: should not be able to process a message with a "
                "generated FQDN");
            return 1;
        }
    }
    else // should be valid
    {
        if(FAIL(ret))
        {
            yatest_err("dns_message_process_lenient_over_update_test: should be able to process a query");
            return 1;
        }
    }

    return 0;
}

static int dns_message_process_lenient_over_update_test() { return dns_message_generated_test(OPCODE_UPDATE, dns_message_process_lenient_over_update_test_callback, "dns_message_process_lenient_over_update_test"); }

static int dns_message_process_lenient_over_ctrl_test_callback(dns_message_t *mesg, dns_message_generated_flags_t *generated_flags)
{
    int ret;

    ret = dns_message_process_lenient(mesg);

    yatest_log("dns_message_process_lenient_over_ctrl_test: process returned %08x: %s", ret, error_gettext(ret));

    if(generated_flags->has_broken_fqdn)
    {
        if(ISOK(ret))
        {
            yatest_err(
                "dns_message_process_lenient_over_ctrl_test: should not be able to process a message with a generated "
                "FQDN");
            return 1;
        }
    }
    else // should be valid
    {
        if(FAIL(ret))
        {
            yatest_err("dns_message_process_lenient_over_ctrl_test: should be able to process a query");
            return 1;
        }
    }

    return 0;
}

static int dns_message_process_lenient_over_ctrl_test()
{
#if DNSCORE_HAS_CTRL
    return dns_message_generated_test(OPCODE_CTRL, dns_message_process_lenient_over_ctrl_test_callback, "dns_message_process_lenient_over_ctrl_test");
#else
    yatest_log("dns_message_process_lenient_over_ctrl_test: OPCODE_CTRL not built-in: test skipped.");
    return 0;
#endif
}

static int dns_message_process_query_over_query_test_callback(dns_message_t *mesg, dns_message_generated_flags_t *generated_flags)
{
    int ret;

    ret = dns_message_process_query(mesg);

    yatest_log("dns_message_process_query_over_query_test: process returned %08x: %s", ret, error_gettext(ret));

    if(generated_flags->has_broken_qd)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_query_over_query_test: should not be able to process a message with a QD != 1");
            return 1;
        }
    }
    else if(generated_flags->has_broken_ar)
    {
        if(ISOK(ret))
        {
            yatest_err(
                "dns_message_process_query_over_query_test: should not be able to process a message with a AR records "
                "not OPT nor TSIG");
            return 1;
        }
    }
    /*
        IXFR is a counter example.

        else if(generated_flags->has_broken_ns)
        {
            if(ISOK(ret))
            {
                yatest_err("dns_message_process_query_over_query_test: should not be able to process a message with a NS
       > 0"); return 1;
            }
        }
    */
    else if(generated_flags->has_broken_fqdn)
    {
        if(ISOK(ret))
        {
            yatest_err(
                "dns_message_process_query_over_query_test: should not be able to process a message with a generated "
                "FQDN");
            return 1;
        }
    }
    else if(generated_flags->is_answer)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_query_over_query_test: should not be able to process an answer");
            return 1;
        }
    }
    else if(generated_flags->is_truncated)
    {
        if(ISOK(ret))
        {
            yatest_err("dns_message_process_query_over_query_test: should not be able to process a truncated query");
            return 1;
        }
    }
    else // should be valid
    {
        if(FAIL(ret))
        {
            yatest_err("dns_message_process_query_over_query_test: should be able to process a query");
            return 1;
        }
    }

    return 0;
}

static int dns_message_process_query_over_query_test() { return dns_message_generated_test(OPCODE_QUERY, dns_message_process_query_over_query_test_callback, "dns_message_process_query_over_query_test"); }

static int dns_message_transform_to_error_test()
{
    init();
    for(int error_code_index = 0; error_code_index < 2; ++error_code_index)
    {
        dns_message_t *mesg = dns_message_new_instance();
        int            ret;
        const uint16_t query_type_const = TYPE_A;
        const uint16_t query_class_const = CLASS_IN;
        dns_message_set_edns0(mesg, true); // option
        dns_message_make_query_ex(mesg, 0x1234, wWw_YaDiFa_eU, query_type_const, query_class_const, 0);
        dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));
        // the message looks like a signed query, but it cannot be given like this else there is an internal logic
        // conflict (client/server on the same message instance)

        yatest_log("signed query:");
        ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
        flushout();
        if(FAIL(ret))
        {
            yatest_err("dns_message_make_signed_error_test: failed to print the query message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        dns_message_t *mesg_server = dns_message_new_instance();
        dns_message_copy_into_buffer(mesg_server, dns_message_get_buffer(mesg), dns_message_get_size(mesg));

        ret = dns_message_process(mesg_server);
        if(FAIL(ret))
        {
            yatest_err("dns_message_transform_to_error_test: failed to process query message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        dns_message_set_status(mesg_server, (error_code_index == 0) ? RCODE_FORMERR : RCODE_NOTAUTH);
        // and now it can be transformed to an error
        dns_message_transform_to_signed_error(mesg_server); // only works on answers

        if(!dns_message_is_answer(mesg_server))
        {
            yatest_err("dns_message_transform_to_error_test: dns_message_make_error didn't result in an answer");
            return 1;
        }

        if(dns_message_get_rcode(mesg_server) != ((error_code_index == 0) ? RCODE_FORMERR : RCODE_NOTAUTH))
        {
            yatest_err("dns_message_make_signed_error_test: record didn't match expectations: %x instead of %x", dns_message_get_rcode(mesg_server), (error_code_index == 0) ? RCODE_FORMERR : RCODE_NOTAUTH);
            return 1;
        }

        yatest_log("signed answer (error):");
        ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg_server), dns_message_get_size(mesg_server), 0xff, 0);
        flushout();
        if(FAIL(ret))
        {
            yatest_err("dns_message_transform_to_error_test: failed to print the answer message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        dns_message_copy_into_buffer(mesg, dns_message_get_buffer(mesg_server), dns_message_get_size(mesg_server));

        ret = dns_message_process_lenient(mesg);
        if(FAIL(ret))
        {
            yatest_err("dns_message_transform_to_error_test: failed to process answer message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        yatest_log("signed received processed answer:");
        ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
        flushout();
        if(FAIL(ret))
        {
            yatest_err("dns_message_transform_to_error_test: failed to print the processed answer message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        if((dns_message_get_rcode(mesg_server) == RCODE_FORMERR) && (dns_message_get_size(mesg) != DNS_HEADER_LENGTH))
        {
            yatest_err("dns_message_transform_to_error_test: message size wasn't truncated to its headers: %i bytes", dns_message_get_size(mesg));
            return 1;
        }

        if((dns_message_get_rcode(mesg_server) == RCODE_FORMERR) && (dns_message_get_canonised_fqdn(mesg)[0] != 0))
        {
            yatest_err("dns_message_transform_to_error_test: fqdn wasn't reset");
            return 1;
        }

        dns_message_delete(mesg_server);
        dns_message_delete(mesg);
    }
    finalise();
    return 0;
}

static int dns_message_make_error_test()
{
    init();
    for(int error_code_index = 0; error_code_index < 2; ++error_code_index)
    {
        dns_message_t *mesg = dns_message_new_instance();
        int            ret;
        const uint16_t query_type_const = TYPE_A;
        const uint16_t query_class_const = CLASS_IN;
        dns_message_set_edns0(mesg, true); // option
        dns_message_make_query(mesg, 0x1234, wWw_YaDiFa_eU, query_type_const, query_class_const);
        dns_message_make_error(mesg, (error_code_index == 0) ? RCODE_FORMERR : RCODE_NOTAUTH);
        if(!dns_message_is_answer(mesg))
        {
            yatest_err("dns_message_make_error_test: dns_message_make_error didn't result in an answer");
            return 1;
        }
        if(dns_message_get_rcode(mesg) != ((error_code_index == 0) ? RCODE_FORMERR : RCODE_NOTAUTH))
        {
            yatest_err("dns_message_make_error_test: record didn't match expectations: %x instead of %x", dns_message_get_rcode(mesg), (error_code_index == 0) ? RCODE_FORMERR : RCODE_NOTAUTH);
            return 1;
        }

        ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
        flushout();
        if(FAIL(ret))
        {
            yatest_err("dns_message_make_error_test: failed to print the message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        ret = dns_message_process_lenient(mesg);
        if(FAIL(ret))
        {
            yatest_err("dns_message_make_error_test: failed to process answer message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        if(!dnsname_equals(dns_message_get_canonised_fqdn(mesg), www_yadifa_eu))
        {
            yatest_err("dns_message_make_error_test: fqdn not matching expectation");
            return 1;
        }

        dns_message_delete(mesg);
    }
    finalise();
    return 0;
}

static int dns_message_make_signed_error_test()
{
    init();
    for(int error_code_index = 0; error_code_index < 2; ++error_code_index)
    {
        dns_message_t *mesg = dns_message_new_instance();
        int            ret;
        const uint16_t query_type_const = TYPE_A;
        const uint16_t query_class_const = CLASS_IN;
        dns_message_set_edns0(mesg, true); // option
        dns_message_make_query(mesg, 0x1234, wWw_YaDiFa_eU, query_type_const, query_class_const);
        dns_message_sign_query(mesg, tsig_get(MYKEY_NAME));
        // the message looks like a signed query, but it cannot be given like this else there is an internal logic
        // conflict (client/server on the same message instance)

        yatest_log("signed query:");
        ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
        flushout();
        if(FAIL(ret))
        {
            yatest_err("dns_message_make_signed_error_test: failed to print the query message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        dns_message_t *mesg_server = dns_message_new_instance();
        dns_message_copy_into_buffer(mesg_server, dns_message_get_buffer(mesg), dns_message_get_size(mesg));

        ret = dns_message_process(mesg_server);
        if(FAIL(ret))
        {
            yatest_err("dns_message_make_signed_error_test: failed to process query message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        dns_message_make_signed_error(mesg_server, (error_code_index == 0) ? RCODE_FORMERR : RCODE_NOTAUTH);

        if(!dns_message_is_answer(mesg_server))
        {
            yatest_err("dns_message_make_signed_error_test: dns_message_make_error didn't result in an answer");
            return 1;
        }

        if(dns_message_get_rcode(mesg_server) != ((error_code_index == 0) ? RCODE_FORMERR : RCODE_NOTAUTH))
        {
            yatest_err("dns_message_make_signed_error_test: record didn't match expectations: %x instead of %x", dns_message_get_rcode(mesg_server), (error_code_index == 0) ? RCODE_FORMERR : RCODE_NOTAUTH);
            return 1;
        }

        yatest_log("signed answer (error):");
        ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg_server), dns_message_get_size(mesg_server), 0xff, 0);
        flushout();
        if(FAIL(ret))
        {
            yatest_err("dns_message_make_signed_error_test: failed to print the answer message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        dns_message_copy_into_buffer(mesg, dns_message_get_buffer(mesg_server), dns_message_get_size(mesg_server));

        ret = dns_message_process_lenient(mesg);
        if(FAIL(ret))
        {
            yatest_err("dns_message_make_signed_error_test: failed to process answer message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        if(!dnsname_equals(dns_message_get_canonised_fqdn(mesg), www_yadifa_eu))
        {
            yatest_err("dns_message_make_signed_error_test: fqdn not matching expectation");
            return 1;
        }

        yatest_log("signed received processed answer:");
        ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
        flushout();
        if(FAIL(ret))
        {
            yatest_err("dns_message_make_signed_error_test: failed to print the processed answer message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        dns_message_delete(mesg_server);
        dns_message_delete(mesg);
    }
    finalise();
    return 0;
}

static int dns_message_make_message_test()
{
    init();
    dns_packet_writer_t pw;
    dns_message_t      *mesg = dns_message_new_instance();
    int                 ret;
    const uint16_t      query_type_const = TYPE_A;
    const uint16_t      query_class_const = CLASS_IN;
    dns_message_make_message(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, &pw);

    ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
    flushout();
    if(FAIL(ret))
    {
        yatest_err("dns_message_make_message_test: failed to print the message: %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    ret = dns_message_process(mesg);
    if(FAIL(ret))
    {
        yatest_err("dns_message_make_message_test: failed to process message: %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    if(!dnsname_equals(dns_message_get_canonised_fqdn(mesg), www_yadifa_eu))
    {
        yatest_err("dns_message_make_message_test: fqdn not matching expectation");
        return 1;
    }

    if(pw.packet_offset != dns_message_get_size(mesg))
    {
        yatest_err("dns_message_make_message_test: packet offset = %i != message size = %i", pw.packet_offset, dns_message_get_size(mesg));
        return 1;
    }

    dns_message_delete(mesg);
    finalise();
    return 0;
}

static int dns_message_make_ixfr_query_test()
{
    init();
    dns_message_t *mesg = dns_message_new_instance();
    int            ret;
    int            soa_ttl = 86400;
    const uint8_t  soa_rdata[] = {3, 'n', 's', '1', 0, 4, 'm', 'a', 'i', 'l', 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 3, 0};
    dns_message_make_ixfr_query(mesg, 0x1234, www_yadifa_eu, soa_ttl, sizeof(soa_rdata), soa_rdata);

    ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
    flushout();
    if(FAIL(ret))
    {
        yatest_err("dns_message_make_ixfr_query_test: failed to print the message: %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    ret = dns_message_process_lenient(mesg);
    if(FAIL(ret))
    {
        yatest_err("dns_message_make_ixfr_query_test: failed to process message: %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    if(!dnsname_equals(dns_message_get_canonised_fqdn(mesg), www_yadifa_eu))
    {
        yatest_err("dns_message_make_ixfr_query_test: fqdn not matching expectation");
        return 1;
    }

    dns_message_delete(mesg);
    finalise();
    return 0;
}

static int dns_message_sign_query_by_name_test()
{
    init();
    dns_message_t *mesg = dns_message_new_instance();
    int            ret;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;
    dns_message_set_edns0(mesg, true); // option
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query_by_name(mesg, MYKEY_NAME);
    // the message looks like a signed query
    ret = dns_message_process(mesg);
    if(FAIL(ret))
    {
        yatest_err("dns_message_sign_query_by_name_test: failed to process query message: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int dns_message_sign_query_by_name_with_epoch_and_fudge_test()
{
    init();
    dns_message_t *mesg = dns_message_new_instance();
    int            ret;
    const uint16_t query_type_const = TYPE_A;
    const uint16_t query_class_const = CLASS_IN;
    dns_message_set_edns0(mesg, true); // option
    dns_message_make_query_ex(mesg, 0x1234, www_yadifa_eu, query_type_const, query_class_const, 0);
    dns_message_sign_query_by_name_with_epoch_and_fudge(mesg, MYKEY_NAME, time(NULL), 300);
    // the message looks like a signed query
    ret = dns_message_process(mesg);
    if(FAIL(ret))
    {
        yatest_err("dns_message_sign_query_by_name_test: failed to process query message: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int dns_message_cookie_test()
{
    init();
    for(int ip_index_base = 0; ip_index_base < 4; ++ip_index_base)
    {
        int ip_index = ip_index_base & 1;

        // client side

        dns_message_t *mesg = dns_message_new_instance();
        int            ret;
        const uint16_t query_type_const = TYPE_A;
        const uint16_t query_class_const = CLASS_IN;
        dns_message_set_edns0(mesg, true); // option
        dns_message_make_query(mesg, 0x1234, wWw_YaDiFa_eU, query_type_const, query_class_const);
        if(ip_index_base < 2)
        {
            dns_message_set_client_cookie_for_server_sockaddr(mesg, &dummy_sa[ip_index + 2]);
        }
        else
        {
            host_address_t *ha = host_address_new_instance_socketaddress(&dummy_sa[ip_index + 2]);
            dns_message_set_client_cookie_for_server_host_address(mesg, ha);
            host_address_delete(ha);
        }
        dns_message_add_opt(mesg);

        yatest_log("client query:");
        ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
        flushout();
        if(FAIL(ret))
        {
            yatest_err("dns_message_cookie_test: failed to print the query message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        // server side

        dns_message_t *mesg_server = dns_message_new_instance();
        dns_message_copy_into_buffer(mesg_server, dns_message_get_buffer(mesg), dns_message_get_size(mesg));

        dns_message_copy_sender_from_sa(mesg_server, &dummy_sa[ip_index].sa, sizeof(dummy_sa[ip_index]));
        dns_message_set_sender_port(mesg_server, 1234);

        size_t expected_dns_message_get_sender_sa_family_size = (ip_index == 0) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        yatest_log("dns_message_cookie_test: expected sender_sa_family_size: %i", expected_dns_message_get_sender_sa_family_size);
        if(dns_message_get_sender_sa_family_size(mesg_server) != expected_dns_message_get_sender_sa_family_size)
        {
            yatest_err("dns_message_cookie_test: dns_message_get_sender_sa_family_size returned %i instead of %i", dns_message_get_sender_sa_family_size(mesg_server), expected_dns_message_get_sender_sa_family_size);
            return 1;
        }

        ret = dns_message_process(mesg_server);
        if(FAIL(ret))
        {
            yatest_err("dns_message_cookie_test: failed to process query message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        {
            int client_cookie_size = dns_message_client_cookie_size(mesg_server);
            if(client_cookie_size == DNS_MESSAGE_COOKIE_CLIENT_SIZE)
            {
                yatest_log("client cookie:");
                yatest_hexdump(dns_message_client_cookie_ptr(mesg_server), dns_message_client_cookie_ptr(mesg_server) + client_cookie_size);
            }
            else
            {
                yatest_err("dns_message_cookie_test: client cookie seen on server is wrong (%i)", client_cookie_size);
                return 1;
            }
        }
        {
            int server_cookie_size = dns_message_server_cookie_size(mesg_server);
            if(server_cookie_size == DNS_MESSAGE_COOKIE_SERVER_SIZE)
            {
                yatest_log("server cookie:");
                yatest_hexdump(dns_message_server_cookie_ptr(mesg_server), dns_message_server_cookie_ptr(mesg_server) + server_cookie_size);
            }
            else
            {
                yatest_err("dns_message_cookie_test: server cookie seen on server is wrong (%i)", server_cookie_size);
                return 1;
            }
        }
        yatest_log("client address:");
        yatest_hexdump(dns_message_get_sender_address_ptr(mesg_server), dns_message_get_sender_address_ptr(mesg_server) + dns_message_get_sender_address_size(mesg_server));

        dns_message_set_answer(mesg_server);
        dns_message_cookie_server_set(mesg_server);
        dns_message_add_opt(mesg_server);

        yatest_log("cookied answer:");
        ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg_server), dns_message_get_size(mesg_server), 0xff, 0);
        flushout();
        if(FAIL(ret))
        {
            yatest_err("dns_message_make_signed_error_test: failed to print the answer message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        // client side again

        dns_message_copy_into_buffer(mesg, dns_message_get_buffer(mesg_server), dns_message_get_size(mesg_server));

        ret = dns_message_process_lenient(mesg);
        if(FAIL(ret))
        {
            yatest_err("dns_message_make_signed_error_test: failed to process answer message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        yatest_log("received cookied answer:");
        ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
        flushout();
        if(FAIL(ret))
        {
            yatest_err("dns_message_make_signed_error_test: failed to print the processed answer message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        {
            int client_cookie_size = dns_message_client_cookie_size(mesg_server);
            if(client_cookie_size == DNS_MESSAGE_COOKIE_CLIENT_SIZE)
            {
                yatest_log("client cookie:");
                yatest_hexdump(dns_message_client_cookie_ptr(mesg), dns_message_client_cookie_ptr(mesg) + client_cookie_size);
            }
            else
            {
                yatest_err("dns_message_cookie_test: client cookie seen on client is wrong (%i)", client_cookie_size);
                return 1;
            }
        }
        {
            int server_cookie_size = dns_message_server_cookie_size(mesg);
            if(server_cookie_size == DNS_MESSAGE_COOKIE_SERVER_SIZE)
            {
                yatest_log("server cookie:");
                yatest_hexdump(dns_message_server_cookie_ptr(mesg), dns_message_server_cookie_ptr(mesg) + server_cookie_size);
            }
            else
            {
                yatest_err("dns_message_cookie_test: server cookie seen on client is wrong (%i)", server_cookie_size);
                return 1;
            }
        }

        // go through it again

        dns_message_clear_answer(mesg);
        dns_message_set_id(mesg, ~dns_message_get_id(mesg));
        // DO NOT: dns_message_set_client_cookie_for_server_sockaddr(mesg, &dummy_sa[ip_index + 2].sa);
        dns_message_add_opt(mesg);

        yatest_log("client query (again):");
        ret = dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0xff, 0);
        flushout();
        if(FAIL(ret))
        {
            yatest_err("dns_message_cookie_test: failed to print the query again message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        // server side again

        dns_message_t *mesg_server_again = dns_message_new_instance();
        dns_message_copy_into_buffer(mesg_server_again, dns_message_get_buffer(mesg), dns_message_get_size(mesg));
        dns_message_copy_sender_from_sa(mesg_server_again, &dummy_sa[ip_index].sa, sizeof(dummy_sa[ip_index]));

        ret = dns_message_process(mesg_server_again);
        if(FAIL(ret))
        {
            yatest_err("dns_message_cookie_test: failed to process query again message: %08x = %s", ret, error_gettext(ret));
            return 1;
        }

        {
            int client_cookie_size = dns_message_client_cookie_size(mesg_server);
            if(client_cookie_size == DNS_MESSAGE_COOKIE_CLIENT_SIZE)
            {
                yatest_log("client cookie:");
                yatest_hexdump(dns_message_client_cookie_ptr(mesg), dns_message_client_cookie_ptr(mesg) + client_cookie_size);
            }
            else
            {
                yatest_err("dns_message_cookie_test: client cookie seen on server again is wrong (%i)", client_cookie_size);
                return 1;
            }
        }
        {
            int server_cookie_size = dns_message_server_cookie_size(mesg);
            if(server_cookie_size == DNS_MESSAGE_COOKIE_SERVER_SIZE)
            {
                yatest_log("server cookie:");
                yatest_hexdump(dns_message_server_cookie_ptr(mesg), dns_message_server_cookie_ptr(mesg) + server_cookie_size);
            }
            else
            {
                yatest_err("dns_message_cookie_test: server cookie seen on server again is wrong (%i)", server_cookie_size);
                return 1;
            }
        }

        dns_message_delete(mesg_server);
        dns_message_delete(mesg);
    }

    finalise();
    return 0;
}

static int dns_message_set_sender_port_test()
{
    int ret;

    init();

    dns_message_t  *mesg = dns_message_new_instance();
    host_address_t *ha;

    ha = host_address_new_instance_parse_port("127.0.0.1", 53);
    dns_message_set_sender_from_host_address(mesg, ha);
    host_address_delete(ha);
    ret = dns_message_set_sender_port(mesg, 10053);
    if(FAIL(ret))
    {
        yatest_err("dns_message_set_sender_port (v4) failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    ha = host_address_new_instance_parse_port("::1", 53);
    dns_message_set_sender_from_host_address(mesg, ha);
    host_address_delete(ha);
    ret = dns_message_set_sender_port(mesg, 10053);
    if(FAIL(ret))
    {
        yatest_err("dns_message_set_sender_port (v6) failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    mesg->_sender.sa.sa_family = 0; // corrupt the sender

    ret = dns_message_set_sender_port(mesg, 10053);
    if(ISOK(ret))
    {
        yatest_err("dns_message_set_sender_port (broken) expected to fail, instead returned %08x", ret);
        return 1;
    }

    finalise();
    return 0;
}

static int dns_message_get_sender_address_ptr_test()
{
    init();

    dns_message_t  *mesg = dns_message_new_instance();
    host_address_t *ha;

    ha = host_address_new_instance_parse_port("127.0.0.1", 53);
    dns_message_set_sender_from_host_address(mesg, ha);
    host_address_delete(ha);

    if(dns_message_get_sender_address_ptr(mesg) == NULL)
    {
        yatest_err("dns_message_get_sender_address_ptr (v4) returned NULL");
        return 1;
    }

    ha = host_address_new_instance_parse_port("::1", 53);
    dns_message_set_sender_from_host_address(mesg, ha);
    host_address_delete(ha);

    if(dns_message_get_sender_address_ptr(mesg) == NULL)
    {
        yatest_err("dns_message_get_sender_address_ptr (v6) returned NULL");
        return 1;
    }

    mesg->_sender.sa.sa_family = 0; // corrupt the sender

    if(dns_message_get_sender_address_ptr(mesg) != NULL)
    {
        yatest_err("dns_message_get_sender_address_ptr (v4) expected to return NULL");
        return 1;
    }

    finalise();
    return 0;
}

static int dns_message_get_sender_address_size_test()
{
    int ret;

    init();

    dns_message_t  *mesg = dns_message_new_instance();
    host_address_t *ha;

    ha = host_address_new_instance_parse_port("127.0.0.1", 53);
    dns_message_set_sender_from_host_address(mesg, ha);
    host_address_delete(ha);
    ret = dns_message_get_sender_address_size(mesg);
    if(ret != 4)
    {
        yatest_err("dns_message_get_sender_address_size (v4) didn't return 4 (%i)", ret);
        return 1;
    }

    ha = host_address_new_instance_parse_port("::1", 53);
    dns_message_set_sender_from_host_address(mesg, ha);
    host_address_delete(ha);
    ret = dns_message_get_sender_address_size(mesg);
    if(ret != 16)
    {
        yatest_err("dns_message_get_sender_address_size (v6) didn't return 16 (%i)", ret);
        return 1;
    }

    mesg->_sender.sa.sa_family = 0; // corrupt the sender

    ret = dns_message_get_sender_address_size(mesg);
    if(ret != 0)
    {
        yatest_err("dns_message_get_sender_address_size (broken) didn't return 0 (%i)", ret);
        return 1;
    }

    finalise();
    return 0;
}

static int dns_message_get_sender_sa_family_size_test()
{
    int ret;

    init();

    dns_message_t  *mesg = dns_message_new_instance();
    host_address_t *ha;

    ha = host_address_new_instance_parse_port("127.0.0.1", 53);
    dns_message_set_sender_from_host_address(mesg, ha);
    host_address_delete(ha);
    ret = dns_message_get_sender_sa_family_size(mesg);
    if(ret != sizeof(struct sockaddr_in))
    {
        yatest_err("dns_message_get_sender_sa_family_size (v4) didn't return %i (%i)", sizeof(struct sockaddr_in), ret);
        return 1;
    }

    ha = host_address_new_instance_parse_port("::1", 53);
    dns_message_set_sender_from_host_address(mesg, ha);
    host_address_delete(ha);
    ret = dns_message_get_sender_sa_family_size(mesg);
    if(ret != sizeof(struct sockaddr_in6))
    {
        yatest_err("dns_message_get_sender_sa_family_size (v6) didn't return %i (%i)", sizeof(struct sockaddr_in6), ret);
        return 1;
    }

    mesg->_sender.sa.sa_family = 0; // corrupt the sender

    ret = dns_message_get_sender_sa_family_size(mesg);
    if(ret != 0)
    {
        yatest_err("dns_message_get_sender_sa_family_size (broken) didn't return 0 (%i)", ret);
        return 1;
    }

    dns_message_delete(mesg);

    finalise();
    return 0;
}

static ya_result dns_message_verify_rrsig_result_test(const dns_message_t *mesg, const struct dnskey_keyring_s *keyring, const dns_message_verify_rrsig_result_t *result, void *args)
{
    yatest_log("dns_message_verify_rrsig_result_test(%p, %p, %p, %p)", mesg, keyring, result, args);
    switch(result->result_type)
    {
        case MESSAGE_VERIFY_RRSIG_RESULT_TYPE_SUMMARY:
        {
            yatest_log(
                "summary: verified: %i verifiable: %i unverifiable: %i wrong: %i", result->data.summary->verified_count, result->data.summary->verifiable_count, result->data.summary->unverifiable_count, result->data.summary->wrong_count);
            break;
        }
        case MESSAGE_VERIFY_RRSIG_RESULT_TYPE_VERIFY:
        {
            yatest_log("verify: section %i: covered type: %s", result->section, dns_type_get_name(result->ctype));
            yatest_log("verify: signature size: %i, result: %i, section: %i", result->data.detail->signature_size, result->data.detail->result, result->data.detail->section);

            format_writer_t fw = {dns_message_verify_rrsig_format_handler, &result->data.detail->result};
            char           *text = NULL;
            asnformat(&text, 65536, "DNSKEY: RRSIG: %{dnstype}: %{dnsname}+%03hhu+%05hu: %w", &result->ctype, result->data.detail->signer_name, result->data.detail->algorithm, ntohs(result->data.detail->tag), &fw);
            yatest_log("verify: %s", text);
            free(text);
            break;
        }
        default:
        {
            break;
        }
    }

    return SUCCESS;
}

static int dns_message_verify_rrsig_test()
{
    int ret;

    init();

    // get a message

    dns_message_t *mesg = mesg64K;

    // write records into it

    dns_packet_writer_t pw;
    dns_packet_writer_init_into_message(&pw, mesg);
    dns_packet_writer_add_fqdn_uncompressed(&pw, www_yadifa_eu);
    dns_packet_writer_add_u16(&pw, TYPE_A);
    dns_packet_writer_add_u16(&pw, CLASS_IN);

    // generate a DNSKEY and a keyring

    dnskey_keyring_t *keyring = dnskey_keyring_new();
    dnskey_t         *key = NULL;
    ret = dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, "yadifa.eu", &key);
    if(FAIL(ret))
    {
        yatest_err("dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, yadifa.eu, &key): %08x: %s", ret, error_gettext(ret));
        return 1;
    }
    dnskey_keyring_add(keyring, key);

    // use the

    struct resource_record_view_s rrv;
    dns_resource_record_resource_record_view_init(&rrv);

    // create an RRSET and sign it

    ptr_vector_t rrset;
    ptr_vector_init_ex(&rrset, 16);

    {
        for(int i = 0; i < A_RRSET_COUNT; ++i)
        {
            yatest_dns_record_t   *record = &a_rrset[i];
            dns_resource_record_t *rr = dns_resource_record_new_instance();
            dns_resource_record_init_record(rr, record->fqdn, record->rtype, record->rclass, record->rttl, record->rdata_len, record->rdata);
            ptr_vector_append(&rrset, rr);
            dns_packet_writer_add_dnsrr(&pw, rr);
        }

        dnskey_signature_t ds;
        dnskey_signature_init(&ds);
        dnskey_signature_set_validity(&ds, 0, 0x7fffffff);
        dnskey_signature_set_view(&ds, &rrv);
        dnskey_signature_set_rrset_reference(&ds, &rrset);

        void *rrsig_rr = NULL;
        ret = dnskey_signature_sign(&ds, key, &rrsig_rr);
        dns_packet_writer_add_dnsrr(&pw, (dns_resource_record_t *)rrsig_rr);
        dnskey_signature_finalize(&ds);
        ptr_vector_clear(&rrset);
    }

    {
        for(int i = 0; i < AAAA_RRSET_COUNT; ++i)
        {
            yatest_dns_record_t   *record = &aaaa_rrset[i];
            dns_resource_record_t *rr = dns_resource_record_new_instance();
            dns_resource_record_init_record(rr, record->fqdn, record->rtype, record->rclass, record->rttl, record->rdata_len, record->rdata);
            ptr_vector_append(&rrset, rr);
            dns_packet_writer_add_dnsrr(&pw, rr);
        }

        dnskey_signature_t ds;
        dnskey_signature_init(&ds);
        dnskey_signature_set_validity(&ds, 0, 0x7fffffff);
        dnskey_signature_set_view(&ds, &rrv);
        dnskey_signature_set_rrset_reference(&ds, &rrset);

        void *rrsig_rr = NULL;
        ret = dnskey_signature_sign(&ds, key, &rrsig_rr);
        dns_packet_writer_add_dnsrr(&pw, (dns_resource_record_t *)rrsig_rr);
        dnskey_signature_finalize(&ds);
        ptr_vector_clear(&rrset);
    }

    {
        for(int i = 0; i < NS_RRSET_COUNT; ++i)
        {
            yatest_dns_record_t   *record = &ns_rrset[i];
            dns_resource_record_t *rr = dns_resource_record_new_instance();
            dns_resource_record_init_record(rr, record->fqdn, record->rtype, record->rclass, record->rttl, record->rdata_len, record->rdata);
            ptr_vector_append(&rrset, rr);
            dns_packet_writer_add_dnsrr(&pw, rr);
        }

        dnskey_signature_t ds;
        dnskey_signature_init(&ds);
        dnskey_signature_set_validity(&ds, 0, 0x7fffffff);
        dnskey_signature_set_view(&ds, &rrv);
        dnskey_signature_set_rrset_reference(&ds, &rrset);

        void *rrsig_rr = NULL;
        ret = dnskey_signature_sign(&ds, key, &rrsig_rr);
        dns_packet_writer_add_dnsrr(&pw, (dns_resource_record_t *)rrsig_rr);
        dnskey_signature_finalize(&ds);
        ptr_vector_clear(&rrset);
    }

    {
        for(int i = 0; i < MX_RRSET_COUNT; ++i)
        {
            yatest_dns_record_t   *record = &mx_rrset[i];
            dns_resource_record_t *rr = dns_resource_record_new_instance();
            dns_resource_record_init_record(rr, record->fqdn, record->rtype, record->rclass, record->rttl, record->rdata_len, record->rdata);
            ptr_vector_append(&rrset, rr);
            dns_packet_writer_add_dnsrr(&pw, rr);
        }

        dnskey_signature_t ds;
        dnskey_signature_init(&ds);
        dnskey_signature_set_validity(&ds, 0, 0x7fffffff);
        dnskey_signature_set_view(&ds, &rrv);
        dnskey_signature_set_rrset_reference(&ds, &rrset);

        void *rrsig_rr = NULL;
        ret = dnskey_signature_sign(&ds, key, &rrsig_rr);
        dns_packet_writer_add_dnsrr(&pw, (dns_resource_record_t *)rrsig_rr);
        dnskey_signature_finalize(&ds);
        ptr_vector_clear(&rrset);
    }

    ptr_vector_finalise(&rrset);

    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 2 + 1 + 2 + 1 + 2 + 1 + 1 + 1, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, dns_message_verify_rrsig_result_test, NULL);

    if(FAIL(ret))
    {
        yatest_err("dns_message_verify_rrsig failed with %08x: %s", ret, error_gettext(ret));
        return 1;
    }

    // coverage over all flags

    uint8_t         results_all_flags = ~0;
    format_writer_t fw = {dns_message_verify_rrsig_format_handler, &results_all_flags};
    char           *text = NULL;
    asnformat(&text, 65536, "%w", &fw);
    yatest_log("verify: %s", text);
    if(strcmp(text, "not-signed,wrong,verified,wrong-time-frame,no-key") != 0)
    {
        yatest_err("dns_message_verify_rrsig_format_handler output didn't match expectations");
        return 1;
    }
    free(text);

    dns_resource_record_resource_record_view_finalise(&rrv);

    finalise();
    return 0;
}

static int dns_message_verify_rrsig_wrong_message_test()
{
    int ret;

    init();

    // get a message

    dns_message_t *mesg = mesg64K;

    // write records into it

    dns_packet_writer_t pw;
    dns_packet_writer_init_into_message(&pw, mesg);

    // generate a DNSKEY and a keyring

    dnskey_keyring_t *keyring = dnskey_keyring_new();
    dnskey_t         *key = NULL;
    ret = dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, "yadifa.eu", &key);
    if(FAIL(ret))
    {
        yatest_err("dnskey_newinstance(1024, DNSKEY_ALGORITHM_RSASHA256_NSEC3, DNSKEY_FLAGS_ZSK, yadifa.eu, &key): %08x: %s", ret, error_gettext(ret));
        return 1;
    }
    dnskey_keyring_add(keyring, key);

    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 0, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_message_verify_rrsig expected to fail with UNEXPECTED_EOF=%08x, got %08x: %s (qd-no-fqdn)", UNEXPECTED_EOF, ret, error_gettext(ret));
        return 1;
    }

    dns_packet_writer_add_fqdn_uncompressed(&pw, www_yadifa_eu);
    dns_packet_writer_add_u16(&pw, TYPE_A);

    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 0, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_message_verify_rrsig expected to fail with UNEXPECTED_EOF=%08x, got %08x: %s (qd-no-class)", UNEXPECTED_EOF, ret, error_gettext(ret));
        return 1;
    }

    dns_packet_writer_add_u16(&pw, CLASS_IN);

    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 1, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_message_verify_rrsig expected to fail with UNEXPECTED_EOF=%08x, got %08x: %s (an-no-fqdn)", UNEXPECTED_EOF, ret, error_gettext(ret));
        return 1;
    }

    dns_packet_writer_add_fqdn(&pw, yadifa_eu);
    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 1, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_message_verify_rrsig expected to fail with UNEXPECTED_EOF=%08x, got %08x: %s (an-no-type)", UNEXPECTED_EOF, ret, error_gettext(ret));
        return 1;
    }

    dns_packet_writer_add_u16(&pw, TYPE_MX);
    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 1, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_message_verify_rrsig expected to fail with UNEXPECTED_EOF=%08x, got %08x: %s (an-no-class)", UNEXPECTED_EOF, ret, error_gettext(ret));
        return 1;
    }

    dns_packet_writer_add_u16(&pw, CLASS_IN);
    dns_packet_writer_add_u32(&pw, 0); // ttl

    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 1, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_message_verify_rrsig expected to fail with UNEXPECTED_EOF=%08x, got %08x: %s (an-no-rdata-size)", UNEXPECTED_EOF, ret, error_gettext(ret));
        return 1;
    }

    dns_packet_writer_add_u16(&pw, ntohs(sizeof(mx_rdata)));
    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 1, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_message_verify_rrsig expected to fail with UNEXPECTED_EOF=%08x, got %08x: %s (an-no-rdata)", UNEXPECTED_EOF, ret, error_gettext(ret));
        return 1;
    }

    // keep the current offset to rewind the changes

    uint16_t       offset = pw.packet_offset;
    static uint8_t broken_mx_rdata[sizeof(mx_rdata)] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    dns_packet_writer_add_bytes(&pw, broken_mx_rdata, sizeof(broken_mx_rdata) / 2);
    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 1, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_message_verify_rrsig expected to fail with UNEXPECTED_EOF=%08x, got %08x: %s (an-short-rdata)", UNEXPECTED_EOF, ret, error_gettext(ret));
        return 1;
    }

    pw.packet_offset = offset;
    dns_packet_writer_add_bytes(&pw, mx_rdata, sizeof(mx_rdata));

    dns_packet_writer_add_fqdn(&pw, yadifa_eu);
    dns_packet_writer_add_u16(&pw, TYPE_RRSIG);
    dns_packet_writer_add_u16(&pw, CLASS_IN);
    dns_packet_writer_add_u32(&pw, 0);
    offset = pw.packet_offset;
    dns_packet_writer_add_u16(&pw, htons(RRSIG_RDATA_HEADER_LEN - 1));
    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 2, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != INCORRECT_RDATA)
    {
        yatest_err("dns_message_verify_rrsig expected to fail with INCORRECT_RDATA=%08x, got %08x: %s (an-rrsig-short-rdata)", INCORRECT_RDATA, ret, error_gettext(ret));
        return 1;
    }

    pw.packet_offset = offset;
    dns_packet_writer_add_u16(&pw, htons(RRSIG_RDATA_HEADER_LEN));
    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 2, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_message_verify_rrsig expected to fail with UNEXPECTED_EOF=%08x, got %08x: %s (an-rrsig-short-rdata)", INCORRECT_RDATA, ret, error_gettext(ret));
        return 1;
    }

    offset = pw.packet_offset;
    dns_packet_writer_add_u16(&pw, TYPE_RRSIG);
    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 2, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != RRSIG_UNSUPPORTED_COVERED_TYPE)
    {
        yatest_err(
            "dns_message_verify_rrsig expected to fail with RRSIG_UNSUPPORTED_COVERED_TYPE=%08x, got %08x: %s "
            "(an-rrsig-short-rdata)",
            INCORRECT_RDATA,
            ret,
            error_gettext(ret));
        return 1;
    }

    pw.packet_offset = offset;
    dns_packet_writer_add_u16(&pw, TYPE_MX);
    dns_packet_writer_add_u8(&pw, DNSKEY_ALGORITHM_ECDSAP256SHA256);
    dns_message_set_size(mesg, pw.packet_offset);
    dns_message_set_query_answer_authority_additional_counts(mesg, 1, 2, 0, 0);

    // generate a message with signed records

    ret = dns_message_verify_rrsig(mesg, keyring, NULL, NULL);

    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_message_verify_rrsig expected to fail with UNEXPECTED_EOF=%08x, got %08x: %s (an-rrsig-short-rdata)", INCORRECT_RDATA, ret, error_gettext(ret));
        return 1;
    }

    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(header_test)
YATEST(buffer_test)
YATEST(features_test)
YATEST(edns0_test)
YATEST(tsig_test)
YATEST(opt_test)
YATEST(network_dns_message_send_recv_tcp_test)
YATEST(network_dns_message_query_tcp_test)
YATEST(network_dns_message_query_tcp_timeout_test)
YATEST(network_dns_message_query_tcp_ex_test)
YATEST(network_dns_message_query_tcp_ex_bindto_test)
YATEST(network_dns_message_query_tcp_timeout_ex_test)
YATEST(network_dns_message_write_read_tcp_test)
YATEST(network_dns_message_send_recv_tcp_min_throughput_test)
YATEST(network_dns_message_send_recv_tcp_default_min_throughput_test)
YATEST(network_dns_message_make_error_and_reply_tcp_test)
YATEST(network_dns_message_make_error_and_reply_tcp_with_default_minimum_throughput_test)
YATEST(network_dns_message_send_recv_udp_test)
YATEST(network_dns_message_send_debug_recv_udp_test)
YATEST(network_dns_message_query_udp_test)
YATEST(network_dns_message_query_udp_with_timeout_and_retries_test)
YATEST(network_dns_message_query_test)
YATEST(network_dns_message_query_but_truncated_test)
YATEST(network_dns_message_query_serial_test)
YATEST(network_dns_message_ixfr_query_get_serial_test)
YATEST(network_dns_message_dup_test)
YATEST(dns_message_with_buffer)
YATEST(dns_message_map_test)
YATEST(dns_message_process_over_query_test)
YATEST(dns_message_process_over_notify_test)
YATEST(dns_message_process_over_update_test)
YATEST(dns_message_process_over_ctrl_test)
YATEST(dns_message_process_over_iquery_test)
YATEST(dns_message_process_lenient_over_query_test)
YATEST(dns_message_process_lenient_over_notify_test)
YATEST(dns_message_process_lenient_over_update_test)
YATEST(dns_message_process_lenient_over_ctrl_test)
YATEST(dns_message_process_query_over_query_test)
YATEST(dns_message_transform_to_error_test)
YATEST(dns_message_make_error_test)
YATEST(dns_message_make_signed_error_test)
YATEST(dns_message_make_message_test)
YATEST(dns_message_make_ixfr_query_test)
YATEST(dns_message_sign_query_by_name_test)
YATEST(dns_message_sign_query_by_name_with_epoch_and_fudge_test)
YATEST(dns_message_cookie_test)
YATEST(dns_message_set_sender_port_test)
YATEST(dns_message_get_sender_address_ptr_test)
YATEST(dns_message_get_sender_address_size_test)
YATEST(dns_message_get_sender_sa_family_size_test)
YATEST(dns_message_verify_rrsig_test)
YATEST(dns_message_verify_rrsig_wrong_message_test)
YATEST_TABLE_END

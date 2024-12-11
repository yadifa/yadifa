/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

/**-----------------------------------------------------------------------------
 * @defgroup test
 * @ingroup test
 * @brief skeleton file
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * skeleton test program, will not be installed with a "make install"
 *
 * To create a new test based on the skeleton:
 *
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 *----------------------------------------------------------------------------*/

#include <dnscore/dnscore.h>
#include <dnscore/dnsname.h>
#include <dnscore/format.h>
#include <dnscore/base64.h>
#include <dnscore/tsig.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/dns_message.h>
#include <dnscore/config_settings.h>
#include <dnscore/random.h>
#include <dnscore/dns_packet_reader.h>
#include <dnscore/nsec3_hash.h>
#include <dnscore/base32hex.h>
#include <dnscore/xfr_input_stream.h>
#include <dnscore/timems.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/dnskey_keyring.h>
#include <dnscore/dns_message_verify_rrsig.h>

#include <dnscore/logger.h>
#include <dnscore/logger_channel_stream.h>

#define VERBOSE    1
#define TIMEOUT    3 // seconds
#define LOADFIRST  0

#define LOG_ENABLE 1 // enable dnscore system log to get

struct nsec3param_record
{
    uint8_t  alg;
    uint8_t  flags;
    uint16_t iterations;
    uint8_t  salt_size;
    uint8_t  salt[255];
};

typedef struct nsec3param_record nsec3param_record;

struct zone_chain
{
    nsec3param_record n3;

    int               zone_index;
    int               fqdn_index;

    uint8_t           self[64][21];
    uint8_t           star[64][21];
};

#define NSEC3PARAM_RECORD_MAX 8

static int              verbose = VERBOSE;

static dnskey_keyring_t zone_keyring = EMPTY_DNSKEY_KEYRING;

#if LOG_ENABLE

static void logger_setup()
{
    logger_init();
    logger_start();

    logger_handle_create_to_stdout("system", MSG_ALL_MASK);
}

#endif

static void      zone_keyring_init(const host_address_t *ip, const uint8_t *zone_fqdn) { dnskey_keyring_add_from_nameserver(&zone_keyring, ip, zone_fqdn); }

static ya_result message_verify_rrsig_callback(const dns_message_t *mesg, const struct dnskey_keyring_s *keyring, const dns_message_verify_rrsig_result_t *result, void *args)
{
    (void)mesg;
    (void)keyring;
    (void)args;

    switch(result->result_type)
    {
        case MESSAGE_VERIFY_RRSIG_RESULT_TYPE_VERIFY:
        {
            formatln("DNSKEY: RRSIG: %{dnstype}: %{dnsname}+%03hhu+%05hu: %hhx", &result->ctype, result->data.detail->signer_name, result->data.detail->algorithm, ntohs(result->data.detail->tag), result->data.detail->result);

            if(result->ctype == TYPE_DNSKEY)
            {
                if((result->data.detail->result & MESSAGE_VERIFY_RRSIG_VERIFIED) != 0)
                {
                    formatln("DNSKEY: DNSKEY have been verified by this key");
                }
            }

            break;
        }
        case MESSAGE_VERIFY_RRSIG_RESULT_TYPE_SUMMARY:
        {
            formatln("DNSKEY: RRSIG: %{dnstype}: verifiable=%hhu verified=%hhu wrong=%hhu", &result->ctype, result->data.summary->verifiable_count, result->data.summary->verified_count, result->data.summary->wrong_count);

            if(result->ctype == TYPE_DNSKEY)
            {
                if(result->data.summary->verified_count > 0)
                {
                    formatln("DNSKEY: DNSKEY have been verified and will be added to the keyring");
                }
                else
                {
                    formatln("DNSKEY: DNSKEY have not been verified");

                    // SECURETEST

                    return MESSAGE_VERIFY_RRSIG_FEEDBACK_ERROR;
                }
            }

            break;
        }
    }

    return MESSAGE_VERIFY_RRSIG_FEEDBACK_CONTINUE;
}

static int nsec3_relation_to_digest(const uint8_t *n3_digest, const uint8_t *n3_next, const uint8_t *d)
{
    int ret = memcmp(n3_digest, d, n3_digest[0] + 1);

    if(ret == 0)
    {
        return 0;
    }

    if(ret < 0)
    {
        ret = memcmp(n3_next, d, n3_next[0] + 1);

        if(ret > 0)
        {
            return 1;
        }

        // ret == 0 is unlikely and means it's not related
        // ret < 0 means it's not related
    }

    return -1;
}

static ya_result nsec3_test(const host_address_t *ip, const uint8_t *zone_fqdn, const uint8_t *fqdn, uint16_t qtype)
{
    random_ctx_t        rndctx = random_init_auto();
    dns_message_t      *mesg = dns_message_new_instance();
    ya_result           ret;
    uint16_t            id;
    uint16_t            n;
    uint8_t             nsec3param_count = 0;
    bool                has_nsec3 = false;
    bool                has_useless = false;
    dns_packet_reader_t pr;
    uint8_t             buffer[2048];
    struct zone_chain   zone_chain[NSEC3PARAM_RECORD_MAX];

    uint64_t            start = timeus();
    uint64_t            stop;
    double              dt;

    ZEROMEMORY(zone_chain, sizeof(zone_chain));

    dns_message_edns0_setmaxsize(4096);

    for(int_fast32_t tries = 0;; ++tries)
    {
        id = (uint16_t)random_next(rndctx);
        dns_message_make_query_ex(mesg, id, zone_fqdn, TYPE_NSEC3PARAM, CLASS_IN, MESSAGE_EDNS0_DNSSEC);
        if(FAIL(ret = dns_message_query_udp_with_timeout(mesg, ip, TIMEOUT, 0)))
        {
            if(ret == MAKE_ERRNO_ERROR(EAGAIN))
            {
                formatln("... tries: %i", tries);
                continue;
            }

            formatln("error: %{dnsname} NSEC3PARAM network failed with: %r %i", zone_fqdn, ret, ret);
            goto nsec3_test_cleanup;
        }

        break;
    }

    if(verbose)
    {
        dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 15, 0);
    }

    if((dns_message_get_rcode(mesg) != RCODE_NOERROR) && (dns_message_get_rcode(mesg) != RCODE_NXDOMAIN))
    {
        ret = RCODE_ERROR_CODE(dns_message_get_rcode(mesg));
        formatln("error: %{dnsname} NSEC3PARAM: query failed with: %s", zone_fqdn, dns_message_rcode_get_name(dns_message_get_rcode(mesg)));
        goto nsec3_test_cleanup;
    }

    if(!dnskey_keyring_isempty(&zone_keyring))
    {
        if(FAIL(ret = dns_message_verify_rrsig(mesg, &zone_keyring, message_verify_rrsig_callback, NULL)))
        {
            formatln("error: RRSIG verification failed");
            goto nsec3_test_cleanup;
        }
    }

    // for each NSEC3PARAM, compute the digests

    dns_packet_reader_init_from_message(&pr, mesg);

    n = dns_message_get_query_count(mesg);

    while(n-- > 0)
    {
        dns_packet_reader_skip_fqdn(&pr);
        dns_packet_reader_skip(&pr, 4);
    }

    n = dns_message_get_answer_count(mesg);

    while(n-- > 0)
    {
        if(FAIL(ret = dns_packet_reader_read_record(&pr, buffer, sizeof(buffer))))
        {
            goto nsec3_test_cleanup;
        }

        uint8_t *p = buffer + dnsname_len(buffer);
        uint16_t rtype = GET_U16_AT(*p);
        if(rtype == TYPE_NSEC3PARAM)
        {
            // got one

            p += 2 + 2 + 4;
            // u16 rdata_size = GET_U16_AT_P(p);
            p += 2;

            zone_chain[nsec3param_count].n3.alg = *p++;
            zone_chain[nsec3param_count].n3.flags = *p++;
            zone_chain[nsec3param_count].n3.iterations = ntohs(GET_U16_AT_P(p));
            p += 2;
            zone_chain[nsec3param_count].n3.salt_size = *p++;
            memcpy(zone_chain[nsec3param_count].n3.salt, p, zone_chain[nsec3param_count].n3.salt_size);
            if(++nsec3param_count == NSEC3PARAM_RECORD_MAX)
            {
                break;
            }
        }
    }

    if(nsec3param_count == 0)
    {
        formatln("error: %{dnsname} %{dnstype} no NSEC3PARAM found in zone", fqdn, &qtype);
        ret = ERROR;
        goto nsec3_test_cleanup;
    }

    for(uint_fast8_t i = 0; i < nsec3param_count; ++i)
    {
        nsec3param_record           *nsec3param = &zone_chain[i].n3;

        nsec3_hash_function_t *const digestfunction = nsec3_hash_get_function(nsec3param->alg);

        const uint8_t               *name = fqdn;

        if(verbose)
        {
            format("[%i] NSEC3PARAM %i %i %i ", i, nsec3param->alg, nsec3param->flags, nsec3param->iterations);
            osprint_dump(termout, nsec3param->salt, nsec3param->salt_size, 20, OSPRINT_DUMP_BASE16);
            println("");
        }

        zone_chain[i].zone_index = dnsname_getdepth(zone_fqdn);
        zone_chain[i].fqdn_index = dnsname_getdepth(fqdn);

        for(int_fast32_t index = zone_chain[i].fqdn_index;; --index)
        {
            uint8_t *digest;
            digest = &zone_chain[i].self[index][0];
            digest[0] = 20;
            digestfunction(name, dnsname_len(name), nsec3param->salt, nsec3param->salt_size, nsec3param->iterations, &digest[1], false);
            if(verbose)
            {
                formatln("[%i] %{dnsname} : %{digest32h}", i, name, digest);
            }
            digest = &zone_chain[i].star[index][0];
            digest[0] = 20;
            digestfunction(name, dnsname_len(name), nsec3param->salt, nsec3param->salt_size, nsec3param->iterations, &digest[1], true);
            if(verbose)
            {
                formatln("[%i] *.%{dnsname} : %{digest32h}", i, name, digest);
            }
            if(*name == 0)
            {
                break;
            }
            name += *name + 1;
        }
    }

    for(int_fast32_t tries = 0;; ++tries)
    {
        id = (uint16_t)random_next(rndctx);
        dns_message_make_query_ex(mesg, id, fqdn, qtype, CLASS_IN, MESSAGE_EDNS0_DNSSEC);
        dns_message_set_recursion_desired(mesg);
        dns_message_set_authenticated_data(mesg); // dig does it
        if(FAIL(ret = dns_message_query_udp_with_timeout(mesg, ip, TIMEOUT, 0)))
        {
            if(ret == MAKE_ERRNO_ERROR(EAGAIN))
            {
                formatln("... tries: %i", tries);
                continue;
            }

            formatln("error: %{dnsname} %{dnstype} network failed: %r", fqdn, &qtype, ret);
            goto nsec3_test_cleanup;
        }

        break;
    }

    if(verbose)
    {
        dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 15, 0);
    }

    if((dns_message_get_rcode(mesg) != RCODE_NOERROR) && (dns_message_get_rcode(mesg) != RCODE_NXDOMAIN))
    {
        ret = RCODE_ERROR_CODE(dns_message_get_rcode(mesg));
        formatln("error: %{dnsname} %{dnstype}: query failed with: %s", zone_fqdn, &qtype, dns_message_rcode_get_name(dns_message_get_rcode(mesg)));
        goto nsec3_test_cleanup;
    }

    dns_packet_reader_init_from_message(&pr, mesg);

    n = dns_message_get_query_count(mesg);

    while(n-- > 0)
    {
        dns_packet_reader_skip_fqdn(&pr);
        dns_packet_reader_skip(&pr, 4);
    }

    n = dns_message_get_answer_count(mesg);

    while(n-- > 0)
    {
        if(FAIL(ret = dns_packet_reader_read_record(&pr, buffer, sizeof(buffer))))
        {
            formatln("error: %{dnsname} %{dnstype} could not read answer %i: %r", fqdn, &qtype, dns_message_get_answer_count(mesg) - n, ret);
            goto nsec3_test_cleanup;
        }
    }

    n = dns_message_get_authority_count(mesg);

    while(n-- > 0)
    {
        if(FAIL(ret = dns_packet_reader_read_record(&pr, buffer, sizeof(buffer))))
        {
            formatln("error: %{dnsname} %{dnstype} could not read authority %i: %r", fqdn, &qtype, dns_message_get_authority_count(mesg) - n, ret);
            goto nsec3_test_cleanup;
        }

        uint8_t *zone_fqdn = buffer;
        size_t   zone_fqdn_size = dnsname_len(zone_fqdn);

        uint8_t *p = buffer + zone_fqdn_size;
        uint16_t rtype = GET_U16_AT(*p);
        p += 2;
        uint16_t rclass = GET_U16_AT(*p);
        p += 2;
        int32_t ttl = (int32_t)GET_U32_AT(*p);
        p += 4;
        uint16_t rdata_size = GET_U16_AT(*p);
        p += 2;
        uint8_t *rdata = p;

        (void)rclass;
        (void)ttl;
        (void)rdata_size;
        (void)rdata;

        if(rtype == TYPE_NSEC3)
        {
            has_nsec3 = true;

            // find what this record represents: find the interval

            int     used = 0;

            uint8_t n3_digest[21];

            ret = base32hex_decode((char *)&zone_fqdn[1], zone_fqdn[0], &n3_digest[1]);
            if(FAIL(ret))
            {
                formatln("error: %{dnsname} %{dnstype} could not decode base32hex: %r", fqdn, &qtype, ret);
                goto nsec3_test_cleanup;
            }

            if(ret != 20)
            {
                formatln("error: %{dnsname} %{dnstype} could not decode base32hex size is not 20", fqdn, &qtype);
                ret = ERROR;
                goto nsec3_test_cleanup;
            }

            n3_digest[0] = ret;

            uint8_t n3_alg = *p++;
            uint8_t n3_flags = *p++;
            (void)n3_flags;
            uint16_t n3_iterations = ntohs(GET_U16_AT_P(p));
            p += 2;
            uint8_t  n3_salt_size = *p++;
            uint8_t *n3_salt = p;
            p += n3_salt_size;
            uint8_t *n3_next = p;
            p += *n3_next + 1;
            // p = type bitmap

            // formatln("from %{digest32h} %{digest32h}", n3_digest, n3_next);

            for(uint_fast8_t i = 0; i < nsec3param_count; ++i)
            {
                struct zone_chain *zc = &zone_chain[i];

                nsec3param_record *nsec3param = &zc->n3;

                if(!((nsec3param->alg == n3_alg) && (nsec3param->iterations == n3_iterations) && (nsec3param->salt_size == n3_salt_size) && (memcmp(nsec3param->salt, n3_salt, n3_salt_size) == 0)))
                {
                    continue;
                }

                // find all records comparing to the record

                const uint8_t *name = fqdn;

                for(int_fast32_t level = zc->fqdn_index; level >= zc->zone_index; --level)
                {
                    // formatln("against %{digest32h}", &zc->self[level][0]);
                    switch(nsec3_relation_to_digest(n3_digest, n3_next, &zc->self[level][0]))
                    {
                        case 0: // equals
                        {
                            if(level == zc->fqdn_index)
                            {
                                formatln("%{digest32h} %{digest32h}: proves %{dnsname} exists but is not an answer", n3_digest, n3_next, name);
                                ++used;
                            }
                            else if(level == zc->zone_index)
                            {
                                formatln("%{digest32h} %{digest32h}: proves %{dnsname} encloser exists (zone)", n3_digest, n3_next, name);
                                ++used;
                            }
                            else if(level > zc->zone_index)
                            {
                                formatln("%{digest32h} %{digest32h}: proves %{dnsname} encloser exists", n3_digest, n3_next, name);
                                ++used;
                            }
                            else
                            {
                                formatln("%{digest32h} %{digest32h}: pointlessly proves %{dnsname} exists", n3_digest, n3_next, name);
                            }
                            break;
                        }
                        case 1: // in
                        {
                            if(level == zc->fqdn_index)
                            {
                                formatln(
                                    "%{digest32h} %{digest32h}: proves %{dnsname} (%{digest32h}) does not exist (in "
                                    "the NSEC3 chain)",
                                    n3_digest,
                                    n3_next,
                                    name,
                                    &zc->self[level][0]);
                                ++used;
                            }
                            else
                            {
                                formatln(
                                    "%{digest32h} %{digest32h}: pointlessly proves %{dnsname} (%{digest32h}) does not "
                                    "exist (in the NSEC3 chain)",
                                    n3_digest,
                                    n3_next,
                                    name,
                                    &zc->self[level][0]);
                            }
                            break;
                        }
                        default: // not related
                        {
                        }
                    }

                    switch(nsec3_relation_to_digest(n3_digest, n3_next, &zc->star[level][0]))
                    {
                        case 0: // equals
                        {
                            formatln(
                                "%{digest32h} %{digest32h}: proves *.%{dnsname} (%{digest32h}) exists but is not an "
                                "answer",
                                n3_digest,
                                n3_next,
                                name,
                                &zc->star[level][0]);
                            ++used;
                            break;
                        }
                        case 1: // in
                        {
                            formatln("%{digest32h} %{digest32h}: proves *.%{dnsname} (%{digest32h}) does not exist", n3_digest, n3_next, name, &zc->star[level][0]);
                            ++used;
                            break;
                        }
                        default: // not related
                        {
                        }
                    }

                    name += *name + 1;
                }
            }

            if(used == 0)
            {
                has_useless = true;
                formatln("%{digest32h} NSEC3 is useless", n3_digest);
                ret = ERROR;
            }
        }
    }

    if(!has_nsec3)
    {
        formatln("query: %{dnsname} %{dnstype} gave no NSEC3 error", fqdn, &qtype);
    }

nsec3_test_cleanup:

    stop = timeus();

    if(!verbose && FAIL(ret))
    {
        if(has_useless)
        {
            for(uint_fast8_t i = 0; i < nsec3param_count; ++i)
            {
                nsec3param_record *nsec3param = &zone_chain[i].n3;

                const uint8_t     *name = fqdn;

                format("[%i] NSEC3PARAM %i %i %i ", i, nsec3param->alg, nsec3param->flags, nsec3param->iterations);
                osprint_dump(termout, nsec3param->salt, nsec3param->salt_size, 20, OSPRINT_DUMP_BASE16);
                println("");

                zone_chain[i].zone_index = dnsname_getdepth(zone_fqdn);
                zone_chain[i].fqdn_index = dnsname_getdepth(fqdn);

                for(int_fast32_t index = zone_chain[i].fqdn_index;; --index)
                {
                    uint8_t *digest;
                    digest = &zone_chain[i].self[index][0];

                    formatln("[%i] %{dnsname} : %{digest32h}", i, name, digest);

                    digest = &zone_chain[i].star[index][0];

                    formatln("[%i] *.%{dnsname} : %{digest32h}", i, name, digest);

                    if(*name == 0)
                    {
                        break;
                    }
                    name += *name + 1;
                }
            }
        }

        dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 15, stop - start);
    }
    else
    {
        dt = stop - start;
        dt /= ONE_SECOND_US_F;
        formatln("time: %.3f", dt);
    }

    dns_message_delete(mesg);
    random_finalize(rndctx);

    return ret;
}

static ya_result zone_forall(const host_address_t *ip, const uint8_t *zone_fqdn)
{
    random_ctx_t   rndctx = random_init_auto();
    dns_message_t *query = dns_message_new_instance();
    dns_message_make_query(query, (uint16_t)random_next(rndctx), zone_fqdn, TYPE_AXFR, CLASS_IN);

    /*
     * connect & send
     */

    input_stream_t  xfris;
    input_stream_t  is;
    output_stream_t os;
#if LOADFIRST
    output_stream_t baos;
    input_stream_t  bais;
#endif
    uint8_t  *fqdn;
    ya_result ret;
    int       fd;
    int       soa_count = 0;

    // connect
    uint16_t rtype;
    uint16_t rclass;
    int32_t  rttl;
    uint16_t rdata_size;
    uint8_t  brol_fqdn[256];
#if LOADFIRST
    uint8_t prev_fqdn[256];
#endif

    brol_fqdn[0] = 4;
    brol_fqdn[1] = 'b';
    brol_fqdn[2] = 'r';
    brol_fqdn[3] = 'o';
    brol_fqdn[4] = 'l';

    fqdn = &brol_fqdn[5];

    input_stream_set_sink(&is);
    input_stream_set_sink(&xfris);
    output_stream_set_sink(&os);

#if LOADFIRST
    output_stream_set_sink(&baos);
    input_stream_set_sink(&bais);
#endif

    if(FAIL(ret = tcp_input_output_stream_connect_host_address(ip, &is, &os, 3)))
    {
        goto zone_forall_cleanup;
    }

    if(FAIL(ret = dns_message_write_tcp(query, &os)))
    {
        goto zone_forall_cleanup;
    }

    output_stream_flush(&os);

    fd = fd_input_stream_get_filedescriptor(&is);

    tcp_set_sendtimeout(fd, TIMEOUT, 0);
    tcp_set_recvtimeout(fd, TIMEOUT, 0);

    if(FAIL(ret = xfr_input_stream_init(&xfris, zone_fqdn, &is, query, 0, XFR_ALLOW_AXFR)))
    {
        goto zone_forall_cleanup;
    }

#if LOADFIRST
    bytearray_output_stream_init_ex(&baos, NULL, 0x10000000, BYTEARRAY_DYNAMIC);
#endif

    int record_count = 0;

    while(soa_count < 2)
    {
        if(FAIL(ret = input_stream_read_dnsname(&xfris, fqdn)))
        {
            break;
        }

        if(FAIL(ret = input_stream_read_u16(&xfris, &rtype)))
        {
            break;
        }

        if(rtype == TYPE_SOA)
        {
            ++soa_count;
        }

        if(FAIL(ret = input_stream_read_u16(&xfris, &rclass)))
        {
            break;
        }

        if(FAIL(ret = input_stream_read_u32(&xfris, (uint32_t *)&rttl)))
        {
            break;
        }

        if(FAIL(ret = input_stream_read_u16(&xfris, &rdata_size)))
        {
            break;
        }

        rdata_size = ntohs(rdata_size);

        if(FAIL(ret = input_stream_skip(&xfris, rdata_size)))
        {
            break;
        }

#if LOADFIRST
        if(!dnsname_equals(fqdn, prev_fqdn))
        {
            output_stream_write_u8(&baos, 0xff);
            output_stream_write_dnsname(&baos, fqdn);
        }
        else
        {
            dnsname_copy(prev_fqdn, fqdn);
        }
        output_stream_write_u8(&baos, 0xfe);
        output_stream_write_u16(&baos, rtype);
#else
        // got a name from the zone

        if(FAIL(ret = nsec3_test(ip, zone_fqdn, fqdn, rtype)))
        {
            formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, fqdn, &rtype, ret);
        }

        if(FAIL(ret = nsec3_test(ip, zone_fqdn, brol_fqdn, rtype)))
        {
            formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, brol_fqdn, &rtype, ret);
        }

        if((record_count < 64) || ((record_count % 97) == 0))
        {
            if(FAIL(ret = nsec3_test(ip, zone_fqdn, fqdn, 65535 - record_count)))
            {
                formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, fqdn, &rtype, ret);
            }

            if(FAIL(ret = nsec3_test(ip, zone_fqdn, brol_fqdn, 65535 - record_count)))
            {
                formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, brol_fqdn, &rtype, ret);
            }
        }

        ++record_count;
#endif
    }

#if LOADFIRST
    // now the stream can be replayed

    bytearray_input_stream_init(&bais, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos), false);
    while(bytearray_input_stream_remaining(&bais) > 0)
    {
        uint16_t rcode;
        uint8_t  code;
        input_stream_read_u8(&bais, &code);
        switch(code)
        {
            case 0xff:
            {
                input_stream_read_dnsname(&bais, fqdn);
                break;
            }
            case 0xfe:
            {
                input_stream_read_u16(&bais, &rcode);

                // got a name from the zone

                if(FAIL(ret = nsec3_test(ip, zone_fqdn, fqdn, rtype)))
                {
                    formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, fqdn, &rtype, ret);
                }

                if(FAIL(ret = nsec3_test(ip, zone_fqdn, brol_fqdn, rtype)))
                {
                    formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, brol_fqdn, &rtype, ret);
                }

                if((record_count < 64) || ((record_count % 97) == 0))
                {
                    if(FAIL(ret = nsec3_test(ip, zone_fqdn, fqdn, 65535 - record_count)))
                    {
                        formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, fqdn, &rtype, ret);
                    }

                    if(FAIL(ret = nsec3_test(ip, zone_fqdn, brol_fqdn, 65535 - record_count)))
                    {
                        formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, brol_fqdn, &rtype, ret);
                    }
                }

                ++record_count;

                break;
            }
            default:
            {
                formatln("ERROR: unexpected code %x", code);
                goto zone_forall_cleanup;
            }
        }
    }
#endif

zone_forall_cleanup:

#if LOADFIRST
    input_stream_close(&bais);
    output_stream_close(&baos);
#endif

    input_stream_close(&xfris);
    input_stream_close(&is);
    output_stream_close(&os);

    dns_message_delete(query);
    return ret;
}

static ya_result zone_for_all_in_axfr(const host_address_t *ip, const uint8_t *zone_fqdn, const char *filename)
{
    input_stream_t        is;
    dns_resource_record_t rr;
    uint8_t              *fqdn;
    ya_result             ret;

    if(FAIL(ret = file_input_stream_open(&is, filename)))
    {
        return ret;
    }

    uint8_t brol_fqdn[256];

    brol_fqdn[0] = 4;
    brol_fqdn[1] = 'b';
    brol_fqdn[2] = 'r';
    brol_fqdn[3] = 'o';
    brol_fqdn[4] = 'l';

    fqdn = &brol_fqdn[5];

    buffer_input_stream_init(&is, &is, 4096);

    dns_resource_record_init(&rr);

    int record_count = 0;

    for(int_fast32_t soa_count = 0; soa_count < 2;)
    {
        if(FAIL(ret = dns_resource_record_read(&rr, &is)))
        {
            goto zone_for_all_in_axfr_cleanup;
        }

        if(rr.tctr.rtype == TYPE_SOA)
        {
            ++soa_count;
        }

        if(FAIL(ret = nsec3_test(ip, zone_fqdn, rr.name, rr.tctr.rtype)))
        {
            formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, rr.name, &rr.tctr.rtype, ret);
        }

        dnsname_copy(fqdn, rr.name);

        if(FAIL(ret = nsec3_test(ip, zone_fqdn, brol_fqdn, rr.tctr.rtype)))
        {
            formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, brol_fqdn, &rr.tctr.rtype, ret);
        }

        if((record_count < 64) || ((record_count % 97) == 0))
        {
            if(FAIL(ret = nsec3_test(ip, zone_fqdn, fqdn, 65535 - record_count)))
            {
                formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, fqdn, &rr.tctr.rtype, ret);
            }

            if(FAIL(ret = nsec3_test(ip, zone_fqdn, brol_fqdn, 65535 - record_count)))
            {
                formatln("ERROR: %{hostaddr}: %{dnsname}: %{dnsname}: %{dnstype}: %r", ip, zone_fqdn, brol_fqdn, &rr.tctr.rtype, ret);
            }
        }

        ++record_count;
    }

zone_for_all_in_axfr_cleanup:

    dns_resource_record_clear(&rr);
    input_stream_close(&is);
    return ret;
}

static void help()
{
    println("parameters: server-ip zone [axfr-image-path]|[fqdn type]*");
    flushout();
}

int main(int argc, char *argv[])
{
    host_address_t *ip = NULL;
    ya_result       ret;
    uint16_t        query_type;
    uint8_t         zone_fqdn[256];
    uint8_t         fqdn[256];

    /* initialises the core library */
    dnscore_init();

    if(argc < 3)
    {
        help();
        return EXIT_FAILURE;
    }

    anytype defaults = {._8u8 = {CONFIG_HOST_LIST_FLAGS_DEFAULT, 128, 0, 0, 0, 0, 0, 0}};
    if(FAIL(ret = config_set_host_list(argv[1], &ip, defaults)))
    {
        formatln("%s is an invalid ip: %r", argv[1], ret);
        help();
        return EXIT_FAILURE;
    }

    if(ip->port == 0)
    {
        ip->port = NU16(53);
    }

    if(FAIL(ret = dnsname_init_check_star_with_cstr(zone_fqdn, argv[2])))
    {
        formatln("%s is an invalid zone: %r", argv[2], ret);
        help();
        return EXIT_FAILURE;
    }

#if LOG_ENABLE
    logger_setup();
#endif

    if(argc >= 5)
    {
        zone_keyring_init(ip, zone_fqdn);

        for(int_fast32_t i = 3; i < argc; i += 2)
        {
            if(FAIL(ret = dnsname_init_check_star_with_cstr(fqdn, argv[i])))
            {
                formatln("%s is an invalid fqdn: %r", argv[i], ret);
                help();
                return EXIT_FAILURE;
            }

            if(FAIL(ret = dns_type_from_case_name(argv[i + 1], &query_type)))
            {
                formatln("%s is an invalid type: %r", argv[i + 1], ret);
                help();
                return EXIT_FAILURE;
            }

            if(ISOK(nsec3_test(ip, zone_fqdn, fqdn, query_type)))
            {
                println("SUCCESS");
            }
            else
            {
                println("FAILURE");
            }
        }
    }
    else if(argc == 4)
    {
        zone_keyring_init(ip, zone_fqdn);

        // expects a path
        zone_for_all_in_axfr(ip, zone_fqdn, argv[3]);
    }
    else // argc == 3
    {
        zone_keyring_init(ip, zone_fqdn);

        ret = zone_forall(ip, zone_fqdn);

        formatln("zone_forall(%{hostaddr}, %{dnsname}) failed with %r", ip, zone_fqdn, ret);
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return ISOK(ret) ? EXIT_SUCCESS : EXIT_FAILURE;
}

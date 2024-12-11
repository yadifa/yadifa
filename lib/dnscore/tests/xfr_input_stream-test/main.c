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

#include "yatest.h"
#include "yatest_stream.h"
#include "yatest_socket.h"
#include "yatest_dns.h"
#include "dnscore/parsing.h"
#include "dnscore/tcp_io_stream.h"

#include <dnscore/dnscore.h>
#include <dnscore/zalloc.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/dns_message.h>
#include <dnscore/dns_packet_reader.h>
#include <dnscore/dns_packet_writer.h>

#include <dnscore/xfr_input_stream.h>

static const char *server_listen_address_text = "127.0.0.1";
static uint16_t    server_listen_port = 10053;
static const int   server_connection_tries = 3;

//

static yatest_socketserver_t mockserver = YATEST_SOCKETSERVER_UNINITIALISED;

// if > 0, will count down after each answer message and trigger an error when reaching 0
static int  mockserver_answer_dns_error_countdown = -1;
static int  mockserver_answer_dns_error_override_tcp_size = -1;
static int  mockserver_answer_dns_error_override_dnserror = -1;
static bool mockserver_answer_dns_error_override_tsig_bytes = false;
static bool mockserver_answer_dns_error_override_authoritative = false;
static bool mockserver_answer_dns_error_remove_tsig = false;
static bool mockserver_answer_dns_error_break_tsig = false;
static bool mockserver_answer_dns_error_replace_tsig = false;
// these error settings have no countdown
static int  mockserver_answer_dns_group_records_by = 1;
static int  mockserver_answer_dns_break_at_lenght = -1;
static int  mockserver_answer_dns_replace_query_type = -1;
static int  mockserver_answer_dns_replace_query_class = -1;
static bool mockserver_answer_dns_close_after_accept = false;
static bool mockserver_answer_dns_change_query_origin = false;
static bool mockserver_answer_dns_break_query_origin = false;

#define YADIFA_EU_AXFR_SERIAL 4

static const uint8_t yadifa_eu[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t error0_eu[] = {6, 'e', 'r', 'r', 'o', 'r', '0', 2, 'e', 'u', 0};
static const uint8_t error1_eu[] = {6, 'e', 'r', 'r', 'o', 'r', '1', 2, 'e', 'u', 0};
static const uint8_t error2_eu[] = {6, 'e', 'r', 'r', 'o', 'r', '2', 2, 'e', 'u', 0};
static const uint8_t error3_eu[] = {6, 'e', 'r', 'r', 'o', 'r', '3', 2, 'e', 'u', 0};
static const uint8_t error4_eu[] = {6, 'e', 'r', 'r', 'o', 'r', '4', 2, 'e', 'u', 0};
static const uint8_t error5_eu[] = {6, 'e', 'r', 'r', 'o', 'r', '5', 2, 'e', 'u', 0};
static const uint8_t error6_eu[] = {6, 'e', 'r', 'r', 'o', 'r', '6', 2, 'e', 'u', 0};
static const uint8_t error7_eu[] = {6, 'e', 'r', 'r', 'o', 'r', '7', 2, 'e', 'u', 0};
static const uint8_t nosuchdomain_eu[] = {12, 'n', 'o', 's', 'u', 'c', 'h', 'd', 'o', 'm', 'a', 'i', 'n', 2, 'e', 'u', 0};

static const uint8_t soa_rdata_sn1[] = {                                        // SOA wire, SN=1
    3, 'n', 's', '1', 6,   'y', 'a', 'd', 'i', 'f', 'a', 2,   'e', 'u', 0,      // 15
    4, 'm', 'a', 'i', 'l', 6,   'y', 'a', 'd', 'i', 'f', 'a', 2,   'e', 'u', 0, // 16
    0, 0,   0,   1,   0,   1,   0,   0,                                         // refresh = 65536
    0, 1,   0,   0,   0,   1,   0,   0,   0,   1,   0,   0};

static const uint8_t soa_rdata_sn2[] = {                                        // SOA wire, SN=2
    3, 'n', 's', '1', 6,   'y', 'a', 'd', 'i', 'f', 'a', 2,   'e', 'u', 0,      // 15
    4, 'm', 'a', 'i', 'l', 6,   'y', 'a', 'd', 'i', 'f', 'a', 2,   'e', 'u', 0, // 16
    0, 0,   0,   2,   0,   1,   0,   0,   0,   1,   0,   0,   0,   1,   0,   0, 0, 1, 0, 0};

static const uint8_t soa_rdata_sn3[] = {                                        // SOA wire, SN=3
    3, 'n', 's', '1', 6,   'y', 'a', 'd', 'i', 'f', 'a', 2,   'e', 'u', 0,      // 15
    4, 'm', 'a', 'i', 'l', 6,   'y', 'a', 'd', 'i', 'f', 'a', 2,   'e', 'u', 0, // 16
    0, 0,   0,   3,   0,   1,   0,   0,   0,   1,   0,   0,   0,   1,   0,   0, 0, 1, 0, 0};

static const uint8_t soa_rdata_sn4[] = { // SOA wire, SN=3
    3,   'n', 's', '1',
    6,   'y', 'a', 'd',
    'i', 'f', 'a', 2,
    'e', 'u', 0, // 15
    4,   'm', 'a', 'i',
    'l', 6,   'y', 'a',
    'd', 'i', 'f', 'a',
    2,   'e', 'u', 0, // 16
    0,   0,   0,   YADIFA_EU_AXFR_SERIAL,
    0,   1,   0,   0,
    0,   1,   0,   0,
    0,   1,   0,   0,
    0,   1,   0,   0};

static const uint8_t soa_rdata_broken[] = { // SOA wire, bad
    1,   '*', 6,   'y',
    'a', 'd', 'i', 'f',
    'a', 2,   'e', 'u',
    0, // 12
    4,   'm', 'a', 'i',
    'l', 6,   'y', 'a',
    'd', 'i', 'f', 'a',
    2,   'e', 'u', 0, // 16
    0,   0,   0,   YADIFA_EU_AXFR_SERIAL,
    0,   1,   0,   0,
    0,   1,   0,   0,
    0,   1,   0,   0,
    0,   1,   0,   0};

static const uint8_t soa_rdata_truncated[] = {
    // SOA wire, SN=1
    3, 'n', 's', '1', 6,   'y', 'a', 'd', 'i', 'f', 'a', 2,   'e', 'u', 0,      // 15
    4, 'm', 'a', 'i', 'l', 6,   'y', 'a', 'd', 'i', 'f', 'a', 2,   'e', 'u', 0, // 16
    0, 0,   0,   1,   0,   1,   0,   0                                          // refresh = 65536
};

static const uint8_t                  a_rdata_127_0_0_1[] = {127, 0, 0, 1};

static const uint8_t                  a_rdata_127_0_0_2[] = {127, 0, 0, 2};

static const uint8_t                  a_rdata_127_0_0_3[] = {127, 0, 0, 3};

static const yatest_dns_record_text_t yadifa_eu_axfr_answer[] = {{"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // begin
                                                                 {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1},
                                                                 {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},
                                                                 {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_3), a_rdata_127_0_0_3},
                                                                 {"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // end
                                                                 {NULL, 0, 0, 0, 0, NULL}};

static const yatest_dns_record_text_t error0_eu_axfr_incomplete_answer[] = {{"error0.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // begin
                                                                            {"error0.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1},
                                                                            {"error0.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},
                                                                            {NULL, 0, 0, 0, 0, NULL}};

static const yatest_dns_record_text_t error1_eu_axfr_broken_answer[] = {
    {"error1.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1}, {"error1.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2}, {NULL, 0, 0, 0, 0, NULL}};

static const yatest_dns_record_text_t           error2_eu_axfr_mismatched_origins_answer[] = {{"error2.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // begin
                                                                                              {"error2.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1},
                                                                                              {"error2.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},
                                                                                              {"error2.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_3), a_rdata_127_0_0_3},
                                                                                              {"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // end
                                                                                              {NULL, 0, 0, 0, 0, NULL}};

static const yatest_dns_record_text_t           error3_eu_badsoaformat_answer[] = {{"error3.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_broken), soa_rdata_broken}, // begin
                                                                                   {"error3.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1},
                                                                                   {"error3.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},
                                                                                   {"error3.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_3), a_rdata_127_0_0_3},
                                                                                   {"error3.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_broken), soa_rdata_broken}, // end
                                                                                   {NULL, 0, 0, 0, 0, NULL}};

static const yatest_dns_record_text_t           error4_eu_badrecordtype_answer[] = {{"error4.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // begin
                                                                                    {"error4.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1},
                                                                                    {"error4.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},
                                                                                    {"error4.eu.", TYPE_AXFR, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_3), a_rdata_127_0_0_3},
                                                                                    {"error4.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // end
                                                                                    {NULL, 0, 0, 0, 0, NULL}};

static const yatest_dns_record_text_t           error5_eu_unsupportedtype_answer[] = {{"error5.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // begin
                                                                                      {"error5.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1},
                                                                                      {"error5.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},
                                                                                      {"error5.eu.", TYPE_TSIG, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_3), a_rdata_127_0_0_3}, // UNSUPPORTED_TYPE
                                                                                      {"error5.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4},          // end
                                                                                      {NULL, 0, 0, 0, 0, NULL}};

static const yatest_dns_record_text_t           error6_eu_badorigin_answer[] = {{"error.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // begin
                                                                                {"error.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1},
                                                                                {"error.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},
                                                                                {"error.eu.", TYPE_TSIG, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_3), a_rdata_127_0_0_3}, // UNSUPPORTED_TYPE
                                                                                {"error.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4},          // end
                                                                                {NULL, 0, 0, 0, 0, NULL}};

static const yatest_dns_record_text_t           error7_eu_truncatedsoa_answer[] = {{"error7.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_truncated), soa_rdata_truncated}, // begin
                                                                                   {"error7.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1},
                                                                                   {"error7.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},
                                                                                   {"error7.eu.", TYPE_SIG, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_3), a_rdata_127_0_0_3},     // UNSUPPORTED_TYPE
                                                                                   {"error7.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_truncated), soa_rdata_truncated}, // end
                                                                                   {NULL, 0, 0, 0, 0, NULL}};

static const yatest_dns_record_text_t           yadifa_eu_ixfr_answer[] = {{"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // begin

                                                                           {"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn1), soa_rdata_sn1}, // -
                                                                           {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1},
                                                                           {"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn2), soa_rdata_sn2}, // +
                                                                           {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},

                                                                           {"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn2), soa_rdata_sn2}, // -
                                                                           {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},
                                                                           {"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn3), soa_rdata_sn3}, // +
                                                                           {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_3), a_rdata_127_0_0_3},

                                                                           {"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn3), soa_rdata_sn3}, // -
                                                                           {"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4},
                                                                           {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1},
                                                                           {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},

                                                                           {"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // end
                                                                           {NULL, 0, 0, 0, 0, NULL}};

static const yatest_dns_query_t                 yadifa_eu_axfr_query = {"yadifa.eu.", TYPE_AXFR, CLASS_IN};
static const yatest_dns_query_t                 yadifa_eu_ixfr_query = {"yadifa.eu.", TYPE_IXFR, CLASS_IN};
static const yatest_dns_query_t                 error0_eu_axfr_query = {"error0.eu.", TYPE_AXFR, CLASS_IN};
static const yatest_dns_query_t                 error1_eu_axfr_query = {"error1.eu.", TYPE_AXFR, CLASS_IN};
static const yatest_dns_query_t                 error2_eu_axfr_query = {"error2.eu.", TYPE_AXFR, CLASS_IN};
static const yatest_dns_query_t                 error3_eu_axfr_query = {"error3.eu.", TYPE_AXFR, CLASS_IN};
static const yatest_dns_query_t                 error4_eu_axfr_query = {"error4.eu.", TYPE_AXFR, CLASS_IN};
static const yatest_dns_query_t                 error5_eu_axfr_query = {"error5.eu.", TYPE_AXFR, CLASS_IN};
static const yatest_dns_query_t                 error6_eu_axfr_query = {"error6.eu.", TYPE_AXFR, CLASS_IN};
static const yatest_dns_query_t                 error7_eu_axfr_query = {"error7.eu.", TYPE_AXFR, CLASS_IN};

static const yatest_dns_query_to_records_text_t query_to_answer[] = {{&yadifa_eu_axfr_query, yadifa_eu_axfr_answer},
                                                                     {&yadifa_eu_ixfr_query, yadifa_eu_ixfr_answer},
                                                                     {&error0_eu_axfr_query, error0_eu_axfr_incomplete_answer},
                                                                     {&error1_eu_axfr_query, error1_eu_axfr_broken_answer},
                                                                     {&error2_eu_axfr_query, error2_eu_axfr_mismatched_origins_answer},
                                                                     {&error3_eu_axfr_query, error3_eu_badsoaformat_answer},
                                                                     {&error4_eu_axfr_query, error4_eu_badrecordtype_answer},
                                                                     {&error5_eu_axfr_query, error5_eu_unsupportedtype_answer},
                                                                     {&error6_eu_axfr_query, error6_eu_badorigin_answer},
                                                                     {&error7_eu_axfr_query, error7_eu_truncatedsoa_answer},
                                                                     {NULL, NULL}};

#define MYKEY_NAME    (const uint8_t *)"\005mykey"
#define NOTMYKEY_NAME (const uint8_t *)"\010notmykey"

static const uint8_t                   mykey_mac[] = {0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
static const uint8_t                   notmykey_mac[] = {0x91, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

static const yatest_dns_record_text_t *yatest_dns_query_to_records_answer_get(const yatest_dns_query_to_records_text_t *table, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass)
{
    uint8_t fqdn_wire[256];
    char    fqdn_text[256];
    cstr_init_with_dnsname(fqdn_text, fqdn);
    yatest_log("yatest_dns_query_to_records_answer_get(%p,'%s',%04x,%04x)", table, fqdn_text, rtype, rclass);
    for(const yatest_dns_query_to_records_text_t *q2a = query_to_answer; q2a->query != NULL; ++q2a)
    {
        if((q2a->query->rtype == rtype) && (q2a->query->rclass == rclass))
        {
            cstr_to_dnsname(fqdn_wire, q2a->query->fqdn);
            if(dnsname_equals_ignorecase(fqdn, fqdn_wire))
            {
                yatest_log("yatest_dns_query_to_records_answer_get is '%s', %04x, %04x", q2a->query->fqdn, q2a->query->rtype, q2a->query->rclass);
                return q2a->answer;
            }
        }
    }
    yatest_log("yatest_dns_query_to_records_answer_get(%p,'%s',%04x,%04x) nothing matches", table, fqdn_text, rtype, rclass);
    return NULL;
}

int yatest_dns_record_text_to_wire(const yatest_dns_record_text_t *rr, void *buffer_, size_t buffer_size)
{
    int      ret;
    uint8_t *buffer = (uint8_t *)buffer_;
    uint8_t *base = buffer;
    size_t   fqdn_len = cstr_get_dnsname_len(rr->fqdn);
    if(buffer_size < fqdn_len)
    {
        yatest_err("yatest_dns_record_text_to_wire: buffer would overflow");
        exit(1);
    }
    ret = cstr_to_dnsname(buffer, rr->fqdn);
    if(ret < 0)
    {
        yatest_err("yatest_dns_record_text_to_wire: cstr_to_dnsname(%s) failed with %i/%08x", rr->fqdn, ret, ret);
        exit(1);
    }
    buffer += ret;
    buffer_size -= ret;
    if(buffer_size < 10ULL + rr->rdata_len)
    {
        yatest_err("yatest_dns_record_text_to_wire: buffer would overflow");
        exit(1);
    }
    memcpy(buffer, &rr->rtype, 2);
    buffer += 2;
    memcpy(buffer, &rr->rclass, 2);
    buffer += 2;
    int32_t ttl = htonl(rr->rttl);
    memcpy(buffer, &ttl, 4);
    buffer += 4;
    uint16_t rdata_len = htons(rr->rdata_len);
    memcpy(buffer, &rdata_len, 2);
    buffer += 2;
    memcpy(buffer, rr->rdata, rr->rdata_len);
    buffer += rr->rdata_len;
    return buffer - base;
}

static void xfr_query_tsig_enable()
{
    int ret;
    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA1);
    if(FAIL(ret))
    {
        yatest_err("xfr_query_tsig_enable failed with %i/%08x (mykey)", ret, ret);
        exit(1);
    }
    ret = tsig_register(NOTMYKEY_NAME, notmykey_mac, sizeof(notmykey_mac), HMAC_SHA1);
    if(FAIL(ret))
    {
        yatest_err("xfr_query_tsig_enable failed with %i/%08x (notmykey)", ret, ret);
        exit(1);
    }
}

static ssize_t mockserver_answer_dns_message_send_tcp(dns_message_t *mesg, int sockfd)
{
    ssize_t       ret;
    struct msghdr tcp_msghdr;
    struct iovec  tcp_data[2];
    uint16_t      tcp_len = dns_message_get_size_u16(mesg);

    yatest_log("mockserver_answer_dns_message_send_tcp(%p, %i), original tcp_len = %i", mesg, sockfd, (int)tcp_len);

    if(mockserver_answer_dns_error_override_tcp_size >= 0)
    {
        yatest_log("mockserver_answer_dns_message_send_tcp: tcp_len=%i", mockserver_answer_dns_error_override_tcp_size);
        tcp_len = (uint16_t)mockserver_answer_dns_error_override_tcp_size;
    }

    if(mockserver_answer_dns_error_override_dnserror >= 0)
    {
        dns_message_set_status(mesg, mockserver_answer_dns_error_override_dnserror);
        dns_message_update_answer_status(mesg);
    }

    if(mockserver_answer_dns_error_override_authoritative)
    {
        dns_message_clear_authoritative(mesg);
    }

    if(mockserver_answer_dns_error_override_tsig_bytes || mockserver_answer_dns_error_remove_tsig || mockserver_answer_dns_error_break_tsig)
    {
        yatest_log("mockserver_answer_dns_message_send_tcp: mac override");

        yatest_hexdump(dns_message_get_buffer(mesg), dns_message_get_buffer(mesg) + dns_message_get_size(mesg));

        dns_packet_reader_t purd;
        dns_packet_reader_init_from_message(&purd, mesg);
        ret = dns_packet_reader_skip_section(&purd, 0);
        if(FAIL(ret))
        {
            yatest_log("mockserver_answer_dns_message_send_tcp: section 0 skip error: %s", error_gettext(ret));
        }
        ret = dns_packet_reader_skip_section(&purd, 1);
        if(FAIL(ret))
        {
            yatest_log("mockserver_answer_dns_message_send_tcp: section 1 skip error: %s", error_gettext(ret));
        }
        ret = dns_packet_reader_skip_section(&purd, 2);
        if(FAIL(ret))
        {
            yatest_log("mockserver_answer_dns_message_send_tcp: section 2 skip error: %s", error_gettext(ret));
        }
        // additional section

        uint16_t additional_count = dns_message_get_additional_count(mesg);
        yatest_log("mockserver_answer_dns_message_send_tcp: %i records in the additional section", additional_count);
        for(uint16_t i = 0; i < additional_count; ++i)
        {
            uint32_t record_offset = purd.packet_offset;

            ret = dns_packet_reader_skip_fqdn(&purd);
            if(FAIL(ret))
            {
                yatest_log("mockserver_answer_dns_message_send_tcp: fqdn skip error: %s", error_gettext(ret));
                break;
            }

            uint16_t rtype;
            uint16_t rdata_len;
            dns_packet_reader_read_u16_unchecked(&purd, &rtype);
            if(FAIL(ret))
            {
                yatest_log("mockserver_answer_dns_message_send_tcp: rtype read error: %s", error_gettext(ret));
                break;
            }
            dns_packet_reader_skip_bytes(&purd, 6); // rclass, rttl
            if(FAIL(ret))
            {
                yatest_log("mockserver_answer_dns_message_send_tcp: rclass+rttl skip error: %s", error_gettext(ret));
                break;
            }
            dns_packet_reader_read_u16_unchecked(&purd, &rdata_len);
            if(FAIL(ret))
            {
                yatest_log("mockserver_answer_dns_message_send_tcp: rdata_len read error: %s", error_gettext(ret));
                break;
            }
            if(rtype == TYPE_TSIG)
            {
                if(mockserver_answer_dns_error_break_tsig)
                {
                    yatest_log("mockserver_answer_dns_message_send_tcp: breaking TSIG at %i", record_offset);
                    dns_message_get_buffer(mesg)[record_offset] = 0xff;
                }

                if(mockserver_answer_dns_error_override_tsig_bytes || mockserver_answer_dns_error_remove_tsig)
                {
                    dns_packet_reader_skip_fqdn(&purd);     // algorithm name
                    dns_packet_reader_skip_bytes(&purd, 8); // time & fudge
                    uint16_t mac_size;
                    dns_packet_reader_read_u16_unchecked(&purd, &mac_size);
                    yatest_log("mockserver_answer_dns_message_send_tcp: zeroing %i bytes at %i", ntohs(rdata_len), purd.packet_offset);
                    memset(dns_message_get_buffer(mesg) + purd.packet_offset, 0, ntohs(mac_size));
                }

                if(mockserver_answer_dns_error_remove_tsig)
                {
                    yatest_log("mockserver_answer_dns_message_send_tcp: cutting TSIG at %i", record_offset);
                    dns_message_set_size(mesg, record_offset);
                    dns_message_set_additional_count(mesg, dns_message_get_additional_count(mesg) - 1);
                }
                break;
            }
            yatest_log("mockserver_answer_dns_message_send_tcp: %i is a %04x = %s, size is %i", i, rtype, dns_type_get_name(rtype), rdata_len);
            dns_packet_reader_skip_bytes(&purd, ntohs(rdata_len));
        }
    }

    uint16_t tcp_native_len = htons(tcp_len);

    tcp_data[0].iov_base = &tcp_native_len;
    tcp_data[0].iov_len = 2;
    tcp_data[1].iov_base = mesg->_buffer;
    tcp_data[1].iov_len = tcp_len;
    tcp_msghdr.msg_name = mesg->_msghdr.msg_name;
    tcp_msghdr.msg_namelen = mesg->_msghdr.msg_namelen;
    tcp_msghdr.msg_iov = &tcp_data[0];
    tcp_msghdr.msg_iovlen = 2;
    tcp_msghdr.msg_control = mesg->_msghdr.msg_control;
#if __unix__
    tcp_msghdr.msg_controllen = mesg->_msghdr.msg_controllen;
#endif
    tcp_msghdr.msg_flags = 0;

    int32_t remain = tcp_len + 2;

    for(;;)
    {
        ret = sendmsg(sockfd, &tcp_msghdr, 0);

        if(ret < 0)
        {
            int err = ERRNO_ERROR;
            if(err == MAKE_ERRNO_ERROR(EINTR))
            {
                continue;
            }

            if(err == MAKE_ERRNO_ERROR(EAGAIN))
            {
                usleep(100);
                continue;
            }

            ret = err;

            break;
        }

        remain -= ret;

        if(remain == 0)
        {
            break;
        }

        while(tcp_msghdr.msg_iovlen > 0)
        {
            if((size_t)ret < tcp_msghdr.msg_iov[0].iov_len)
            {
                uint8_t *p = (uint8_t *)tcp_msghdr.msg_iov[0].iov_base;
                p += ret;
                tcp_msghdr.msg_iov[0].iov_base = p;
                tcp_msghdr.msg_iov[0].iov_len -= (size_t)ret;
                break;
            }
            else
            {
                ret -= (size_t)tcp_msghdr.msg_iov[0].iov_len;

                ++tcp_msghdr.msg_iov;
                --tcp_msghdr.msg_iovlen;

                if(ret == 0)
                {
                    break;
                }
            }
        }
    }

    return ret;
}

static void mockserver_answer_dns(yatest_serverclient_t *client, dns_message_t *mesg, const yatest_dns_record_text_t *records)
{
    // for each record
    // create a message based on the original one
    // set one record
    // send
    // loop until no more records
    // close connection

    size_t   record_buffer_size = 65536;
    uint8_t *record_buffer = (uint8_t *)malloc(record_buffer_size);

    dns_message_set_authoritative_answer(mesg);

    if(mockserver_answer_dns_change_query_origin)
    {
        if(dns_message_get_buffer(mesg)[12] == 0)
        {
            yatest_err("mockserver_answer_dns changing query origin doesn't work with .");
        }
        else
        {
            yatest_log("mockserver_answer_dns changing query origin");
            dns_message_get_buffer(mesg)[13] ^= 1;
        }
    }

    if(mockserver_answer_dns_replace_query_type >= 0)
    {
        uint8_t *p = &dns_message_get_buffer(mesg)[12];
        p += dnsname_len(p);
        *(uint16_t *)p = mockserver_answer_dns_replace_query_type;
    }

    if(mockserver_answer_dns_replace_query_class >= 0)
    {
        uint8_t *p = &dns_message_get_buffer(mesg)[12];
        p += dnsname_len(p) + 2;
        *(uint16_t *)p = mockserver_answer_dns_replace_query_class;
    }

    const uint8_t                  *first_soa_rdata = NULL;
    const yatest_dns_record_text_t *next_record = records;
    int                             pos = TSIG_NOWHERE;
    int                             message_index = 0;
    uint16_t                        first_soa_rdata_len = 0;
    bool                            last_record_written = false;
    while(!last_record_written)
    {
        // keep only the query

        yatest_log("mockserver_answer_dns preparing message");

        struct dns_packet_reader_s purd;
        dns_packet_reader_init_from_message(&purd, mesg);
        dns_packet_reader_skip_query_section(&purd);
        uint32_t position = dns_packet_reader_position(&purd);
        dns_message_set_size(mesg, position);
        dns_message_set_answer_count(mesg, 0);
        dns_message_set_additional_count(mesg, 0);
        dns_message_set_authority_count(mesg, 0);

        // append one record in the answer section

        yatest_log("mockserver_answer_dns append record (message %i)", message_index);

        struct dns_packet_writer_s pw;
        dns_packet_writer_init_append_to_message(&pw, mesg);

        int group_by_countdown = mockserver_answer_dns_group_records_by;
        int record_count = 0;
        while((group_by_countdown > 0) && (next_record->fqdn != NULL))
        {
            if(next_record->rtype == TYPE_SOA)
            {
                if(first_soa_rdata == NULL)
                {
                    yatest_log("mockserver_answer_dns first SOA");
                    first_soa_rdata = next_record->rdata;
                    first_soa_rdata_len = next_record->rdata_len;
                    pos = TSIG_START;
                }
                else
                {
                    if(next_record->rdata_len == first_soa_rdata_len)
                    {
                        if(memcmp(next_record->rdata, first_soa_rdata, first_soa_rdata_len) == 0)
                        {
                            yatest_log("mockserver_answer_dns last SOA");
                            pos = TSIG_END;
                        }
                    }
                }
            }

            yatest_log("mockserver_answer_dns: [%02i,%02i] %s %s %s %i (%i bytes)",
                       message_index,
                       mockserver_answer_dns_group_records_by - group_by_countdown,
                       next_record->fqdn,
                       dns_type_get_name(next_record->rtype),
                       dns_class_get_name(next_record->rclass),
                       next_record->rttl,
                       next_record->rdata_len);
            yatest_dns_record_text_to_wire(next_record, record_buffer, record_buffer_size);

            const uint8_t *p = record_buffer;
            dns_packet_writer_add_fqdn(&pw, p);
            p += dnsname_len(p);
            dns_packet_writer_add_bytes(&pw, p, 10);
            p += 8;
            uint16_t rdata_len = ntohs(*(uint16_t *)p);
            p += 2;
            dns_packet_writer_add_bytes(&pw, p, rdata_len);
            p += rdata_len;
            // p - buffer bytes have been read

            --group_by_countdown;
            ++next_record;
        }

        last_record_written = (next_record->fqdn == NULL) || (mockserver_answer_dns_group_records_by <= 0);

        record_count = mockserver_answer_dns_group_records_by - group_by_countdown;

        dns_message_set_answer_count(mesg, record_count);

        dns_message_set_size(mesg, dns_packet_writer_get_offset(&pw));

        uint8_t mockserver_answer_dns_break_query_origin_bak;

        if(mockserver_answer_dns_break_query_origin)
        {
            yatest_log("mockserver_answer_dns breaking query origin");
            mockserver_answer_dns_break_query_origin_bak = dns_message_get_buffer(mesg)[12];
            dns_message_get_buffer(mesg)[12] = 0xff;
        }
        else
        {
            mockserver_answer_dns_break_query_origin_bak = 0;
        }

        // sign the message if it needs to be

        if(dns_message_has_tsig(mesg))
        {
            if(mockserver_answer_dns_error_countdown == 0)
            {
                if(mockserver_answer_dns_error_replace_tsig)
                {
                    yatest_log("mockserver_answer_dns replacing TSIG key (index=%i, pos=%i)", message_index, pos);
                    dns_message_tsig_set_key(mesg, tsig_get(NOTMYKEY_NAME));
                }
            }

            int ret;
            if(pos != TSIG_START)
            {
                yatest_log("mockserver_answer_dns signing (index=%i, pos=%i)", message_index, pos);
                ret = tsig_sign_tcp_message(mesg, pos);
            }
            else // pos = TSIG_START
            {
                yatest_log("mockserver_answer_dns signing start (index=%i)", message_index);
                ret = tsig_sign_tcp_message(mesg, pos);
                pos = TSIG_MIDDLE;
            }
            if(FAIL(ret))
            {
                yatest_err("mockserver_answer_dns signature failed with %i/%08x (%s)", ret, ret, error_gettext(ret));
            }
            yatest_log("mockserver_answer_dns signed (%i)", ret);
        }

        // send the message

        if(mockserver_answer_dns_break_at_lenght >= 0)
        {
            // only sends the mockserver_answer_dns_break_at_lenght bytes
            yatest_log("mockserver_answer_dns sending first %i bytes", mockserver_answer_dns_break_at_lenght);
            uint16_t tcplen = htons(mockserver_answer_dns_break_at_lenght);
            writefully(client->sockfd, &tcplen, 2);
            writefully(client->sockfd, dns_message_get_buffer(mesg), mockserver_answer_dns_break_at_lenght);
        }
        else
        {
            if(mockserver_answer_dns_error_countdown != 0)
            {
                yatest_log("mockserver_answer_dns sending");
                dns_message_send_tcp(mesg, client->sockfd);
            }
            else // mockserver_answer_dns_error_countdown == 0
            {
                yatest_log("mockserver_answer_dns sending corrupted");
                mockserver_answer_dns_message_send_tcp(mesg, client->sockfd);
            }
        }

        if(mockserver_answer_dns_break_query_origin)
        {
            yatest_log("mockserver_answer_dns repairing query origin");
            dns_message_get_buffer(mesg)[12] = mockserver_answer_dns_break_query_origin_bak;
        }

        ++message_index;
        --mockserver_answer_dns_error_countdown;
    }

    yatest_log("mockserver_answer_dns done");

    free(record_buffer);
}

static void mockserver_client_init(struct yatest_socketserver_s *ssctx)
{
    (void)ssctx;
    yatest_log("mockserver_client_init");
}

static void mockserver_client_handler(struct yatest_socketserver_s *ssctx, yatest_serverclient_t *client)
{
    (void)ssctx;
    // reads a TCP DNS query from the client

    if(mockserver_answer_dns_close_after_accept)
    {
        yatest_log("mockserver_answer_dns_close_after_accept is true: closing connection");
        return;
    }

    // answers

    int ret;
    dnscore_init();
    xfr_query_tsig_enable();
    input_stream_t tcpis;
    fd_input_stream_attach(&tcpis, client->sockfd);

    dns_message_t *mesg = dns_message_new_instance();
    ret = dns_message_read_tcp(mesg, &tcpis);
    if(ret < 0)
    {
        yatest_err("mockserver_client_handler: dns_message_read_tcp failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        input_stream_close(&tcpis);
        return;
    }
    // got a message

    output_stream_t os;
    bytearray_output_stream_init(&os, NULL, 65535);
    dns_message_print_format_dig_buffer(&os, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), UINT16_MAX);
    output_stream_write_u8(&os, 0);
    yatest_log("message size: %i", dns_message_get_size(mesg));
    yatest_log("'%s'", bytearray_output_stream_buffer(&os));

    ret = dns_message_process_lenient(mesg);
    if(ret < 0)
    {
        yatest_err("mockserver_client_handler: dns_message_process_query failed: %i/%08x (%s)", ret, ret, error_gettext(ret));
        input_stream_close(&tcpis);
        return;
    }

    if(dns_message_get_query_class(mesg) != CLASS_IN)
    {
        yatest_err("mockserver_client_handler: query class not IN (%04x)", ntohs(dns_message_get_query_class(mesg)));
        input_stream_close(&tcpis);
        return;
    }

    const yatest_dns_record_text_t *answer_records = yatest_dns_query_to_records_answer_get(query_to_answer, dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type(mesg), dns_message_get_query_class(mesg));

    if(answer_records != NULL)
    {
        mockserver_answer_dns(client, mesg, answer_records);
    }
    else
    {
        yatest_err("mockserver_client_handler: query is unknown", ntohs(dns_message_get_query_type(mesg)));
    }

    yatest_log("mockserver_client_handler: waiting 5 seconds");

    yatest_sleep(5);

    yatest_log("mockserver_client_handler: closing stream");

    input_stream_close(&tcpis);
}

static void mockserver_client_finalise(struct yatest_socketserver_s *ssctx)
{
    (void)ssctx;
    yatest_log("mockserver_client_finalise");
}

static void mockserver_kill();

/// initialises the mockserver

static void mockserver_init()
{
    yatest_socketserver_start(&mockserver, server_listen_address_text, server_listen_port, SOCK_STREAM, mockserver_client_init, mockserver_client_handler, mockserver_client_finalise, 0, YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE);
    yatest_sleep(1);
    atexit(mockserver_kill);
}

/// kills the mockserver

static void mockserver_kill() { yatest_socketserver_stop(&mockserver); }

static int  xfr_query_init(input_stream_t *xfris, dns_message_t *mesg, const char *server_listen_address_text, int server_listen_port, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int serial, uint32_t xfr_flags)
{
    input_stream_t  tcpis;
    output_stream_t tcpos;
    int             ret;
    uint8_t         ip_raw[16];

    host_address_t *server;
    ret = parse_ip_address(server_listen_address_text, strlen(server_listen_address_text), ip_raw, sizeof(ip_raw));
    if(ret < 0)
    {
        yatest_err("parse_ip_address failed with %i/%08x", ret, ret);
        exit(1);
    }
    switch(ret)
    {
        case 4:
        {
            server = host_address_new_instance_ipv4(ip_raw, htons(server_listen_port));
            break;
        }
        case 16:
        {
            server = host_address_new_instance_ipv6(ip_raw, htons(server_listen_port));
            break;
        }
        default:
        {
            yatest_err("parse_ip_address failed returned an unexpeced value: %i", ret);
            exit(1);
        }
    }

    dns_message_make_query(mesg, 1234, fqdn, rtype, rclass);
    tsig_key_t *key = tsig_get(MYKEY_NAME);
    if(key != NULL)
    {
        yatest_log("xfr_query_init: %s", MYKEY_NAME);
        ret = dns_message_sign_query(mesg, key);
        if(FAIL(ret))
        {
            yatest_err("dns_message_sign_query failed with: %i/%08x", ret, ret);
            exit(1);
        }
    }

    for(int tries = 0; tries < server_connection_tries; ++tries)
    {
        // ret = dns_message_query_tcp_with_timeout(mesg, server, 1);

        ret = tcp_input_output_stream_connect_host_address(server, &tcpis, &tcpos, serial);

        if(ISOK(ret))
        {
            if(is_fd_input_stream(&tcpis))
            {
                tcp_set_sendtimeout(fd_input_stream_get_filedescriptor(&tcpis), 3, 0);
                tcp_set_recvtimeout(fd_input_stream_get_filedescriptor(&tcpis), 3, 0);
            }
            break;
        }
    }

    if(FAIL(ret))
    {
        yatest_err("tcp_input_output_stream_connect_host_address failed with %i/%08x", ret, ret);
        exit(1);
    }

    ret = dns_message_write_tcp(mesg, &tcpos);

    if(FAIL(ret))
    {
        yatest_err("dns_message_write_tcp failed with %i/%08x", ret, ret);
        exit(1);
    }

    // serial MUST be 0 (else it's already up-to-date)
    // AXFR MUST be allowed

    ret = xfr_input_stream_init(xfris, dns_message_get_canonised_fqdn(mesg), &tcpis, mesg, 0, xfr_flags);

    return ret;
}

static int ixfr_query_init(input_stream_t *xfris, const char *server_listen_address_text, int server_listen_port, const uint8_t *fqdn, const uint8_t *soa_rdata, uint16_t soa_rdata_len, uint32_t xfr_flags, bool signs)
{
    int             ret;
    uint8_t         ip_raw[16];

    host_address_t *server;
    ret = parse_ip_address(server_listen_address_text, strlen(server_listen_address_text), ip_raw, sizeof(ip_raw));
    if(ret < 0)
    {
        yatest_err("parse_ip_address failed with %i/%08x", ret, ret);
        exit(1);
    }
    switch(ret)
    {
        case 4:
        {
            server = host_address_new_instance_ipv4(ip_raw, htons(server_listen_port));
            break;
        }
        case 16:
        {
            server = host_address_new_instance_ipv6(ip_raw, htons(server_listen_port));
            break;
        }
        default:
        {
            yatest_err("parse_ip_address failed returned an unexpeced value: %i", ret);
            exit(1);
        }
    }

    if(signs)
    {
        server->tsig = tsig_get(MYKEY_NAME);
        if(server->tsig == NULL)
        {
            yatest_err("ixfr_query_init: signature requested but key is not registered");
            exit(1);
        }
    }

    ret = xfr_input_stream_init_with_query(xfris, server, fqdn, 86400, soa_rdata, soa_rdata_len, xfr_flags);

    return ret;
}

static int axfr_query_no_error_test(const char *test_name, const uint8_t *query_fqdn, uint16_t rtype, uint16_t rclass, uint32_t xfr_flags, uint32_t serial)
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    char           fqdn_text[256];
    char           fqdn_text2[256];

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, rtype, rclass, serial, xfr_flags);

    if(ret < 0)
    {
        yatest_err("%s xfr_query_init failed with %i/%08x (%s)", test_name, ret, ret, error_gettext(ret));
        return 1;
    }

    ret = xfr_input_stream_get_type(&xfris);
    if(ret != TYPE_AXFR)
    {
        yatest_err("%s expected an AXFR reply, got %i/%08x (%s) instead", test_name, ret, ret, error_gettext(ret));
        return 1;
    }

    const uint8_t *xfr_origin = xfr_input_stream_get_origin(&xfris);
    if(!dnsname_equals(xfr_origin, yadifa_eu))
    {
        cstr_init_with_dnsname(fqdn_text, xfr_origin);
        cstr_init_with_dnsname(fqdn_text2, yadifa_eu);
        yatest_err("%s origin doesn't match query '%s' != '%s'", fqdn_text, fqdn_text2);
        return 1;
    }

    ret = xfr_input_stream_get_serial(&xfris);
    if(ret != YADIFA_EU_AXFR_SERIAL)
    {
        yatest_err("%s expected serial %i reply, got %i/%08x (%s) instead", test_name, YADIFA_EU_AXFR_SERIAL, ret, ret, error_gettext(ret));
        return 1;
    }

    ret = xfr_input_stream_get_refresh(&xfris);
    if(ret != 65536)
    {
        yatest_err("%s expected refresh %i reply, got %i/%08x (%s) instead", test_name, 65536, ret, ret, error_gettext(ret));
        return 1;
    }

    dns_resource_record_t *dnsrr = dns_resource_record_new_instance();
    for(int index = 0;; ++index)
    {
        ret = dns_resource_record_read(dnsrr, &xfris);
        if(ret <= 0)
        {
            if(ret < 0)
            {
                yatest_err("%s dns_resource_record_read failed with %i/%08x (%s)", test_name, ret, ret, error_gettext(ret));
                exit(1);
            }
            break;
        }
        cstr_init_with_dnsname(fqdn_text, dnsrr->name);
        yatest_log("[%02i] '%s' %s %s (%i bytes)", index, fqdn_text, dns_type_get_name(dnsrr->tctr.rtype), dns_class_get_name(dnsrr->tctr.rclass), dnsrr->rdata_size);
    }

    input_stream_close(&xfris);
    dns_message_delete(mesg);
    mockserver_kill();
    return 0;
}

static int axfr_simple_test() { return axfr_query_no_error_test("axfr_simple_test", yadifa_eu, TYPE_AXFR, CLASS_IN, XFR_ALLOW_AXFR, 0); }

static int axfr_simple_by2_test()
{
    mockserver_answer_dns_group_records_by = 2;
    return axfr_query_no_error_test("axfr_simple_by2_test", yadifa_eu, TYPE_AXFR, CLASS_IN, XFR_ALLOW_AXFR, 0);
}

static int axfr_simple_by3_test()
{
    mockserver_answer_dns_group_records_by = 3;
    return axfr_query_no_error_test("axfr_simple_by3_test", yadifa_eu, TYPE_AXFR, CLASS_IN, XFR_ALLOW_AXFR, 0);
}

static int axfr_simple_whole_test()
{
    mockserver_answer_dns_group_records_by = 65535;
    return axfr_query_no_error_test("axfr_simple_whole_test", yadifa_eu, TYPE_AXFR, CLASS_IN, XFR_ALLOW_AXFR, 0);
}

static int axfr_loose_test() { return axfr_query_no_error_test("axfr_simple_whole_test", yadifa_eu, TYPE_AXFR, CLASS_IN, XFR_ALLOW_AXFR | XFR_LOOSE_AUTHORITY, 0); }

static int axfr_uptodate_test() { return axfr_query_no_error_test("axfr_simple_test", yadifa_eu, TYPE_AXFR, CLASS_IN, XFR_ALLOW_AXFR, 4); }

static int axfr_noaxfr_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_AXFR, CLASS_IN, 0, 0);

    if(ret < 0)
    {
        if(ret == INVALID_PROTOCOL)
        {
            yatest_log("axfr_noaxfr_test xfr_query_init failed with INVALID_PROTOCOL");
            return 0;
        }
        else
        {
            yatest_err("axfr_noaxfr_test xfr_query_init failed with %i/%08x", ret, ret);
            return 1;
        }
    }

    yatest_err("axfr_noaxfr_test xfr_query_init should not have succeeded: %i", ret);

    return 1;
}

static int ixfr_noixfr_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_IXFR, CLASS_IN, 0, 0);

    if(ret < 0)
    {
        if(ret == INVALID_PROTOCOL)
        {
            yatest_log("ixfr_noixfr_test xfr_query_init failed with INVALID_PROTOCOL");
            return 0;
        }
        else
        {
            yatest_err("ixfr_noixfr_test xfr_query_init failed with %i/%08x", ret, ret);
            return 1;
        }
    }

    yatest_err("ixfr_noixfr_test xfr_query_init should not have succeeded: %i", ret);

    return 1;
}

static int axfr_tsig_test()
{
    mockserver_answer_dns_error_remove_tsig = true;
    mockserver_init();
    dnscore_init();
    xfr_query_tsig_enable();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    char           fqdn_text[256];
    char           fqdn_text2[256];

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        yatest_err("axfr_tsig_test xfr_query_init failed with %i/%08x (%s)", ret, ret, error_gettext(ret));
        return 1;
    }

    ret = xfr_input_stream_get_type(&xfris);
    if(ret != TYPE_AXFR)
    {
        yatest_err("axfr_tsig_test expected an AXFR reply, got %i/%08x instead", ret, ret);
        return 1;
    }

    const uint8_t *xfr_origin = xfr_input_stream_get_origin(&xfris);
    if(!dnsname_equals(xfr_origin, yadifa_eu))
    {
        cstr_init_with_dnsname(fqdn_text, xfr_origin);
        cstr_init_with_dnsname(fqdn_text2, yadifa_eu);
        yatest_err("axfr_tsig_test origin doesn't match query '%s' != '%s'", fqdn_text, fqdn_text2);
        return 1;
    }

    ret = xfr_input_stream_get_serial(&xfris);
    if(ret != YADIFA_EU_AXFR_SERIAL)
    {
        yatest_err("axfr_tsig_test expected serial %i reply, got %i/%08x instead", YADIFA_EU_AXFR_SERIAL, ret, ret);
        return 1;
    }

    ret = xfr_input_stream_get_refresh(&xfris);
    if(ret != 65536)
    {
        yatest_err("axfr_tsig_test expected refresh %i reply, got %i/%08x instead", 65536, ret, ret);
        return 1;
    }

    dns_resource_record_t *dnsrr = dns_resource_record_new_instance();
    for(int index = 0;; ++index)
    {
        ret = dns_resource_record_read(dnsrr, &xfris);
        if(ret <= 0)
        {
            if(ret < 0)
            {
                yatest_err("dns_resource_record_read failed with %i/%08x", ret, ret);
                exit(1);
            }
            break;
        }
        cstr_init_with_dnsname(fqdn_text, dnsrr->name);
        yatest_log("[%02i] '%s' %s %s (%i bytes)", index, fqdn_text, dns_type_get_name(dnsrr->tctr.rtype), dns_class_get_name(dnsrr->tctr.rclass), dnsrr->rdata_size);
    }

    input_stream_close(&xfris);
    dns_message_delete(mesg);
    mockserver_kill();
    return 0;
}

static int axfr_notsiginreply_test()
{
    mockserver_answer_dns_error_countdown = 0;
    mockserver_answer_dns_error_remove_tsig = true;
    mockserver_init();
    dnscore_init();
    xfr_query_tsig_enable();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == MAKE_RCODE_ERROR(RCODE_BADSIG))
        {
            yatest_log("axfr_notsiginreply_test xfr_query_init failed with RCODE_BADSIG");
            return 0;
        }
        else
        {
            yatest_err("axfr_notsiginreply_test xfr_query_init failed with %i/%08x (%s)", ret, ret, error_gettext(ret));
            return 1;
        }
    }

    yatest_err("axfr_notsiginreply_test xfr_query_init succeeded with %i", ret);

    input_stream_close(&xfris);
    dns_message_delete(mesg);
    mockserver_kill();
    return 1;
}

static int axfr_brokentsig_test()
{
    mockserver_answer_dns_error_countdown = 0;
    mockserver_answer_dns_error_break_tsig = true;
    mockserver_init();
    dnscore_init();
    xfr_query_tsig_enable();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == MAKE_RCODE_ERROR(RCODE_FORMERR))
        {
            yatest_log("axfr_brokentsig_test xfr_query_init failed with RCODE_FORMERR");
            dns_message_delete(mesg);
            return 0;
        }
        else
        {
            yatest_err("axfr_brokentsig_test xfr_query_init failed with %i/%08x (%s)", ret, ret, error_gettext(ret));
            dns_message_delete(mesg);
            return 1;
        }
    }

    yatest_err("axfr_brokentsig_test xfr_query_init succeeded with %i", ret);

    input_stream_close(&xfris);
    dns_message_delete(mesg);
    mockserver_kill();
    return 1;
}

static int axfr_replacedtsig_test()
{
    mockserver_answer_dns_error_countdown = 0;
    mockserver_answer_dns_error_replace_tsig = true;
    mockserver_init();
    dnscore_init();
    xfr_query_tsig_enable();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == MAKE_RCODE_ERROR(RCODE_BADSIG))
        {
            yatest_log("axfr_replacedtsig_test xfr_query_init failed with RCODE_BADSIG");
            dns_message_delete(mesg);
            return 0;
        }
        else
        {
            yatest_err("axfr_replacedtsig_test xfr_query_init failed with %i/%08x (%s)", ret, ret, error_gettext(ret));
            dns_message_delete(mesg);
            return 1;
        }
    }

    yatest_err("axfr_replacedtsig_test xfr_query_init succeeded with %i", ret);

    input_stream_close(&xfris);
    dns_message_delete(mesg);
    mockserver_kill();
    return 1;
}

static int axfr_delayed_tcplen_test(int delay, int tcplen)
{
    mockserver_answer_dns_error_countdown = delay;
    mockserver_answer_dns_error_override_tcp_size = tcplen;

    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == UNEXPECTED_EOF)
        {
            yatest_log("axfr_delayed%i_tcplen%i_test xfr_query_init failed with UNEXPECTED_EOF", delay, tcplen);
            return 0;
        }

        yatest_err("axfr_delayed%i_tcplen%i_test xfr_query_init failed with %i/%08x = %s", delay, tcplen, ret, ret, error_gettext(ret));
        return 1;
    }

    yatest_err("axfr_delayed%i_tcplen%i_test xfr_query_init didn't fail: %i", delay, tcplen, ret);
    return 1;
}

static int axfr_delayed0_tcplen0_test() { return axfr_delayed_tcplen_test(0, 0); }

static int axfr_delayed0_tcplen1_test() { return axfr_delayed_tcplen_test(0, 1); }

static int axfr_delayed0_tcplen11_test() { return axfr_delayed_tcplen_test(0, 11); }

static int axfr_delayed0_tcplen12_test() { return axfr_delayed_tcplen_test(0, 12); }

static int axfr_delayed0_tcplen14_test() { return axfr_delayed_tcplen_test(0, 14); }

static int axfr_delayed2_tcplen0_test() { return axfr_delayed_tcplen_test(2, 0); }

static int axfr_delayed2_tcplen1_test() { return axfr_delayed_tcplen_test(2, 1); }

static int axfr_delayed2_tcplen11_test() { return axfr_delayed_tcplen_test(2, 11); }

static int axfr_delayed2_tcplen12_test() { return axfr_delayed_tcplen_test(2, 12); }

static int axfr_delayed2_tcplen14_test() { return axfr_delayed_tcplen_test(2, 14); }

static int axfr_delayed4_tcplen0_test() { return axfr_delayed_tcplen_test(4, 0); }

static int axfr_delayed_tsig_test(int delay)
{
    mockserver_answer_dns_error_countdown = delay;
    mockserver_answer_dns_error_override_tsig_bytes = true;

    mockserver_init();
    dnscore_init();
    xfr_query_tsig_enable(); // else no signature will take place
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    dns_message_delete(mesg);

    if(ret < 0)
    {
        if(ret == MAKE_RCODE_ERROR(RCODE_BADSIG))
        {
            yatest_log("axfr_delayed%i_tsig_test xfr_query_init failed with BADSIG", delay);
            return 0;
        }

        yatest_err("axfr_delayed%i_tsig_test xfr_query_init failed with %i/%08x", delay, ret, ret);
        return 1;
    }

    yatest_err("axfr_delayed%i_tsig_test xfr_query_init didn't fail: %i", delay, ret);
    return 1;
}

static int axfr_delayed0_tsig_test() { return axfr_delayed_tsig_test(0); }

static int axfr_delayed4_tsig_test() { return axfr_delayed_tsig_test(4); }

static int axfr_delayed_dnserror_test(int delay, int code)
{
    mockserver_answer_dns_error_countdown = delay;
    mockserver_answer_dns_error_override_dnserror = code;

    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == MAKE_RCODE_ERROR(code))
        {
            yatest_log("axfr_delayed%i_dnserror_test xfr_query_init failed with %s", delay, error_gettext(ret));
            return 0;
        }

        yatest_err("axfr_delayed%i_dnserror_test xfr_query_init failed with %i/%08x", delay, ret, ret);
        return 1;
    }

    yatest_err("axfr_delayed%i_dnserror_test xfr_query_init didn't fail: %i", delay, ret);
    return 1;
}

static int axfr_delayed0_dnserror_test() { return axfr_delayed_dnserror_test(0, RCODE_NI); }

static int axfr_delayed4_dnserror_test() { return axfr_delayed_dnserror_test(4, RCODE_NI); }

static int axfr_delayed_notauthoritative_test(int delay)
{
    mockserver_answer_dns_error_countdown = delay;
    mockserver_answer_dns_error_override_authoritative = true;

    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == UNPROCESSABLE_MESSAGE)
        {
            yatest_log("axfr_delayed%i_dnserror_test xfr_query_init failed with UNPROCESSABLE_MESSAGE", delay);
            return 0;
        }

        yatest_err("axfr_delayed%i_dnserror_test xfr_query_init failed with %i/%08x", delay, ret, ret);
        return 1;
    }

    yatest_err("axfr_delayed%i_dnserror_test xfr_query_init didn't fail: %i", delay, ret);
    return 1;
}

static int axfr_delayed0_notauthoritative_test() { return axfr_delayed_notauthoritative_test(0); }

static int axfr_delayed4_notauthoritative_test() { return axfr_delayed_notauthoritative_test(4); }

static int axfr_read1_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    char           fqdn_text[256];
    char           fqdn_text2[256];

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        yatest_err("axfr_read1_test xfr_query_init failed with %i/%08x", ret, ret);
        return 1;
    }

    ret = xfr_input_stream_get_type(&xfris);
    if(ret != TYPE_AXFR)
    {
        yatest_err("axfr_read1_test expected an AXFR reply, got %i/%08x instead", ret, ret);
        return 1;
    }

    const uint8_t *xfr_origin = xfr_input_stream_get_origin(&xfris);
    if(!dnsname_equals(xfr_origin, yadifa_eu))
    {
        cstr_init_with_dnsname(fqdn_text, xfr_origin);
        cstr_init_with_dnsname(fqdn_text2, yadifa_eu);
        yatest_err("axfr_read1_test origin doesn't match query '%s' != '%s'", fqdn_text, fqdn_text2);
        return 1;
    }

    ret = xfr_input_stream_get_serial(&xfris);
    if(ret != YADIFA_EU_AXFR_SERIAL)
    {
        yatest_err("axfr_read1_test expected serial %i reply, got %i/%08x instead", YADIFA_EU_AXFR_SERIAL, ret, ret);
        return 1;
    }

    ret = xfr_input_stream_get_refresh(&xfris);
    if(ret != 65536)
    {
        yatest_err("axfr_read1_test expected refresh %i reply, got %i/%08x instead", 65536, ret, ret);
        return 1;
    }

    uint32_t count = 0;

    for(;;)
    {
        uint8_t value;
        ret = input_stream_read(&xfris, &value, 1);
        if(ret <= 0)
        {
            if(ret < 0)
            {
                yatest_err("input_stream_read_u8 failed with %i/%08x (count=%u)", ret, ret, count);
                exit(1);
            }
            break;
        }
        ++count;
    }

    input_stream_close(&xfris);
    dns_message_delete(mesg);
    mockserver_kill();
    return 0;
}

static int axfr_skip1_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    char           fqdn_text[256];
    char           fqdn_text2[256];

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        yatest_err("axfr_simple_test xfr_query_init failed with %i/%08x", ret, ret);
        return 1;
    }

    ret = xfr_input_stream_get_type(&xfris);
    if(ret != TYPE_AXFR)
    {
        yatest_err("axfr_simple_test expected an AXFR reply, got %i/%08x instead", ret, ret);
        return 1;
    }

    const uint8_t *xfr_origin = xfr_input_stream_get_origin(&xfris);
    if(!dnsname_equals(xfr_origin, yadifa_eu))
    {
        cstr_init_with_dnsname(fqdn_text, xfr_origin);
        cstr_init_with_dnsname(fqdn_text2, yadifa_eu);
        yatest_err("axfr_simple_test origin doesn't match query '%s' != '%s'", fqdn_text, fqdn_text2);
        return 1;
    }

    ret = xfr_input_stream_get_serial(&xfris);
    if(ret != YADIFA_EU_AXFR_SERIAL)
    {
        yatest_err("axfr_simple_test expected serial %i reply, got %i/%08x instead", YADIFA_EU_AXFR_SERIAL, ret, ret);
        return 1;
    }

    ret = xfr_input_stream_get_refresh(&xfris);
    if(ret != 65536)
    {
        yatest_err("axfr_simple_test expected refresh %i reply, got %i/%08x instead", 65536, ret, ret);
        return 1;
    }

    for(;;)
    {
        ret = input_stream_skip(&xfris, 1);
        if(ret <= 0)
        {
            if(ret < 0)
            {
                yatest_err("input_stream_skip failed with %i/%08x", ret, ret);
                exit(1);
            }
            break;
        }
    }

    input_stream_close(&xfris);
    dns_message_delete(mesg);
    mockserver_kill();
    return 0;
}

static int ixfr_simple_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    char           fqdn_text[256];
    char           fqdn_text2[256];

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, yadifa_eu, TYPE_IXFR, CLASS_IN, 0, XFR_ALLOW_IXFR);

    if(ret < 0)
    {
        yatest_err("ixfr_simple_test xfr_query_init failed with %i/%08x = %s", ret, ret, error_gettext(ret));
        return 1;
    }

    ret = xfr_input_stream_get_type(&xfris);
    if(ret != TYPE_IXFR)
    {
        yatest_err("ixfr_simple_test expected an IXFR reply, got %i/%08x instead", ret, ret);
        return 1;
    }

    const uint8_t *xfr_origin = xfr_input_stream_get_origin(&xfris);
    if(!dnsname_equals(xfr_origin, yadifa_eu))
    {
        cstr_init_with_dnsname(fqdn_text, xfr_origin);
        cstr_init_with_dnsname(fqdn_text2, yadifa_eu);
        yatest_err("ixfr_simple_test origin doesn't match query '%s' != '%s'", fqdn_text, fqdn_text2);
        return 1;
    }

    ret = xfr_input_stream_get_serial(&xfris);
    if(ret != YADIFA_EU_AXFR_SERIAL)
    {
        yatest_err("ixfr_simple_test expected serial %i reply, got %i/%08x instead", YADIFA_EU_AXFR_SERIAL, ret, ret);
        return 1;
    }

    ret = xfr_input_stream_get_refresh(&xfris);
    if(ret != 65536)
    {
        yatest_err("ixfr_simple_test expected refresh %i reply, got %i/%08x instead", 65536, ret, ret);
        return 1;
    }

    dns_resource_record_t *dnsrr = dns_resource_record_new_instance();
    for(int index = 0;; ++index)
    {
        ret = dns_resource_record_read(dnsrr, &xfris);
        if(ret <= 0)
        {
            if(ret < 0)
            {
                yatest_err("dns_resource_record_read failed with %i/%08x", ret, ret);
                exit(1);
            }
            break;
        }
        cstr_init_with_dnsname(fqdn_text, dnsrr->name);
        yatest_log("[%02i] '%s' %s %s (%i bytes)", index, fqdn_text, dns_type_get_name(dnsrr->tctr.rtype), dns_class_get_name(dnsrr->tctr.rclass), dnsrr->rdata_size);
    }

    input_stream_close(&xfris);
    dns_message_delete(mesg);
    mockserver_kill();
    return 0;
}

static int ixfr_query_test()
{
    mockserver_init();
    dnscore_init();

    input_stream_t xfris;
    int            ret;
    char           fqdn_text[256];
    char           fqdn_text2[256];

    ret = ixfr_query_init(&xfris, server_listen_address_text, server_listen_port, yadifa_eu, soa_rdata_sn1, sizeof(soa_rdata_sn1), XFR_ALLOW_BOTH, false);

    if(ret < 0)
    {
        yatest_err("ixfr_query_test xfr_query_init failed with %i/%08x = %s", ret, ret, error_gettext(ret));
        return 1;
    }

    ret = xfr_input_stream_get_type(&xfris);
    if(ret != TYPE_IXFR)
    {
        yatest_err("ixfr_query_test expected an IXFR reply, got %i/%08x instead", ret, ret);
        return 1;
    }

    const uint8_t *xfr_origin = xfr_input_stream_get_origin(&xfris);
    if(!dnsname_equals(xfr_origin, yadifa_eu))
    {
        cstr_init_with_dnsname(fqdn_text, xfr_origin);
        cstr_init_with_dnsname(fqdn_text2, yadifa_eu);
        yatest_err("ixfr_query_test origin doesn't match query '%s' != '%s'", fqdn_text, fqdn_text2);
        return 1;
    }

    ret = xfr_input_stream_get_serial(&xfris);
    if(ret != YADIFA_EU_AXFR_SERIAL)
    {
        yatest_err("ixfr_query_test expected serial %i reply, got %i/%08x instead", YADIFA_EU_AXFR_SERIAL, ret, ret);
        return 1;
    }

    ret = xfr_input_stream_get_refresh(&xfris);
    if(ret != 65536)
    {
        yatest_err("ixfr_query_test expected refresh %i reply, got %i/%08x instead", 65536, ret, ret);
        return 1;
    }

    dns_resource_record_t *dnsrr = dns_resource_record_new_instance();
    for(int index = 0;; ++index)
    {
        ret = dns_resource_record_read(dnsrr, &xfris);
        if(ret <= 0)
        {
            if(ret < 0)
            {
                yatest_err("dns_resource_record_read failed with %i/%08x", ret, ret);
                exit(1);
            }
            break;
        }
        cstr_init_with_dnsname(fqdn_text, dnsrr->name);
        yatest_log("[%02i] '%s' %s %s (%i bytes)", index, fqdn_text, dns_type_get_name(dnsrr->tctr.rtype), dns_class_get_name(dnsrr->tctr.rclass), dnsrr->rdata_size);
    }

    input_stream_close(&xfris);
    mockserver_kill();
    return 0;
}

static int ixfr_uptodate_test()
{
    mockserver_init();
    dnscore_init();

    input_stream_t xfris;
    int            ret;

    yatest_log("ixfr_query_init");

    ret = ixfr_query_init(&xfris, server_listen_address_text, server_listen_port, yadifa_eu, soa_rdata_sn4, sizeof(soa_rdata_sn4), XFR_ALLOW_BOTH, false);

    if(ret < 0)
    {
        if(ret == ZONE_ALREADY_UP_TO_DATE)
        {
            yatest_log("ixfr_uptodate_test xfr_query_init failed with ZONE_ALREADY_UP_TO_DATE");
            input_stream_close(&xfris);
            mockserver_kill();
            return 0;
        }
        else
        {
            yatest_err("ixfr_uptodate_test xfr_query_init failed with %i/%08x = %s", ret, ret, error_gettext(ret));
            input_stream_close(&xfris);
            mockserver_kill();
            return 1;
        }
    }

    yatest_err("ixfr_uptodate_test didn't fail (%i)", ret);

    input_stream_close(&xfris);
    mockserver_kill();
    return 1;
}

static int ixfr_tsig_test()
{
    mockserver_init();
    dnscore_init();
    xfr_query_tsig_enable();

    input_stream_t xfris;
    int            ret;
    char           fqdn_text[256];
    char           fqdn_text2[256];

    ret = ixfr_query_init(&xfris, server_listen_address_text, server_listen_port, yadifa_eu, soa_rdata_sn1, sizeof(soa_rdata_sn1), XFR_ALLOW_BOTH, true);

    if(ret < 0)
    {
        yatest_err("ixfr_tsig_test xfr_query_init failed with %i/%08x", ret, ret);
        return 1;
    }

    ret = xfr_input_stream_get_type(&xfris);
    if(ret != TYPE_IXFR)
    {
        yatest_err("ixfr_tsig_test expected an IXFR reply, got %i/%08x instead", ret, ret);
        return 1;
    }

    const uint8_t *xfr_origin = xfr_input_stream_get_origin(&xfris);
    if(!dnsname_equals(xfr_origin, yadifa_eu))
    {
        cstr_init_with_dnsname(fqdn_text, xfr_origin);
        cstr_init_with_dnsname(fqdn_text2, yadifa_eu);
        yatest_err("ixfr_tsig_test origin doesn't match query '%s' != '%s'", fqdn_text, fqdn_text2);
        return 1;
    }

    ret = xfr_input_stream_get_serial(&xfris);
    if(ret != YADIFA_EU_AXFR_SERIAL)
    {
        yatest_err("ixfr_tsig_test expected serial %i reply, got %i/%08x instead", YADIFA_EU_AXFR_SERIAL, ret, ret);
        return 1;
    }

    ret = xfr_input_stream_get_refresh(&xfris);
    if(ret != 65536)
    {
        yatest_err("ixfr_tsig_test expected refresh %i reply, got %i/%08x instead", 65536, ret, ret);
        return 1;
    }

    dns_resource_record_t *dnsrr = dns_resource_record_new_instance();
    for(int index = 0;; ++index)
    {
        ret = dns_resource_record_read(dnsrr, &xfris);
        if(ret <= 0)
        {
            if(ret < 0)
            {
                yatest_err("dns_resource_record_read failed with %i/%08x", ret, ret);
                exit(1);
            }
            break;
        }
        cstr_init_with_dnsname(fqdn_text, dnsrr->name);
        yatest_log("[%02i] '%s' %s %s (%i bytes)", index, fqdn_text, dns_type_get_name(dnsrr->tctr.rtype), dns_class_get_name(dnsrr->tctr.rclass), dnsrr->rdata_size);
    }

    input_stream_close(&xfris);
    mockserver_kill();
    return 0;
}

static int axfr_incomplete_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = error0_eu;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == MAKE_ERRNO_ERROR(EAGAIN))
        {
            yatest_log("axfr_incomplete_test xfr_query_init returned EAGAIN");
            ret = 0;
        }
        else if(ret == UNABLE_TO_COMPLETE_FULL_READ)
        {
            yatest_log("axfr_incomplete_test xfr_query_init returned UNABLE_TO_COMPLETE_FULL_READ");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_incomplete_test xfr_query_init failed with %i/%08x = %s", ret, ret, error_gettext(ret));
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_incomplete_test xfr_query_init returned %i/%08x = %s", ret, ret, error_gettext(ret));
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_notxfr_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = error1_eu;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == INVALID_PROTOCOL)
        {
            yatest_log("axfr_notxfr_test xfr_query_init returned INVALID_PROTOCOL");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_notxfr_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_notxfr_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_mismatched_origins_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = error2_eu;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == MAKE_RCODE_ERROR(RCODE_FORMERR))
        {
            yatest_log("axfr_mismatched_origins_test xfr_query_init returned FORMERR");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_mismatched_origins_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_mismatched_origins_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_badsoaformat_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = error3_eu;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == INVALID_RECORD)
        {
            yatest_log("axfr_badsoaformat_test xfr_query_init returned INVALID_RECORD");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_badsoaformat_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_badsoaformat_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_badrecordtype_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = error4_eu;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == INVALID_PROTOCOL)
        {
            yatest_log("axfr_badrecordtype_test xfr_query_init returned INVALID_PROTOCOL");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_badrecordtype_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_badrecordtype_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_unsupportedtype_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = error5_eu;
    char           fqdn_text[256];

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        yatest_err("axfr_unsupportedtype_test xfr_query_init failed with %i/%08x = %s", ret, ret, error_gettext(ret));
        return 1;
    }

    ret = xfr_input_stream_get_type(&xfris);
    if(ret != TYPE_AXFR)
    {
        yatest_err("axfr_unsupportedtype_test expected an AXFR reply, got %i/%08x instead", ret, ret);
        return 1;
    }

    ret = xfr_input_stream_get_serial(&xfris);
    if(ret != YADIFA_EU_AXFR_SERIAL)
    {
        yatest_err("axfr_unsupportedtype_test expected serial %i reply, got %i/%08x instead", YADIFA_EU_AXFR_SERIAL, ret, ret);
        return 1;
    }

    ret = xfr_input_stream_get_refresh(&xfris);
    if(ret != 65536)
    {
        yatest_err("axfr_unsupportedtype_test expected refresh %i reply, got %i/%08x instead", 65536, ret, ret);
        return 1;
    }

    dns_resource_record_t *dnsrr = dns_resource_record_new_instance();
    for(int index = 0;; ++index)
    {
        ret = dns_resource_record_read(dnsrr, &xfris);
        if(ret <= 0)
        {
            if(ret < 0)
            {
                yatest_err("dns_resource_record_read failed with %i/%08x", ret, ret);
                exit(1);
            }
            break;
        }
        cstr_init_with_dnsname(fqdn_text, dnsrr->name);
        yatest_log("[%02i] '%s' %s %s (%i bytes)", index, fqdn_text, dns_type_get_name(dnsrr->tctr.rtype), dns_class_get_name(dnsrr->tctr.rclass), dnsrr->rdata_size);
    }

    input_stream_close(&xfris);
    dns_message_delete(mesg);
    mockserver_kill();
    return 0;
}

static int axfr_badqueryorigin_test()
{
    mockserver_answer_dns_change_query_origin = true;
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = error6_eu;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == INVALID_PROTOCOL)
        {
            yatest_log("axfr_badqueryorigin_test xfr_query_init returned INVALID_PROTOCOL");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_badqueryorigin_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_badqueryorigin_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_badorigin_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = error6_eu;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == INVALID_PROTOCOL)
        {
            yatest_log("axfr_badorigin_test xfr_query_init returned INVALID_PROTOCOL");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_badorigin_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_badorigin_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_brokenqueryorigin_test()
{
    mockserver_answer_dns_break_query_origin = true;
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = error6_eu;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == INVALID_PROTOCOL)
        {
            yatest_log("axfr_brokenqueryorigin_test xfr_query_init returned INVALID_PROTOCOL");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_brokenqueryorigin_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_brokenqueryorigin_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_truncatedsoa_test()
{
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = error7_eu;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == INVALID_RECORD)
        {
            yatest_log("axfr_badqueryorigin_test xfr_query_init returned INVALID_RECORD");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_badqueryorigin_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_badqueryorigin_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_badquerytype_test()
{
    mockserver_answer_dns_replace_query_type = TYPE_A;
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = yadifa_eu;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == INVALID_PROTOCOL)
        {
            yatest_log("axfr_badquerytype_test xfr_query_init returned INVALID_PROTOCOL");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_badquerytype_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_badquerytype_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_badqueryclass_test()
{
    mockserver_answer_dns_replace_query_class = CLASS_ANY;
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = yadifa_eu;

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == INVALID_PROTOCOL)
        {
            yatest_log("axfr_badqueryclass_test xfr_query_init returned INVALID_PROTOCOL");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_badqueryclass_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_badqueryclass_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_truncated_at_half_query_type_test()
{
    mockserver_answer_dns_break_at_lenght = 12 + 11 + 1;
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = yadifa_eu; // 11 bytes long

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == UNEXPECTED_EOF)
        {
            yatest_log("axfr_truncated_at_half_query_type_test xfr_query_init returned UNEXPECTED_EOF");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_truncated_at_half_query_type_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_truncated_at_half_query_type_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_truncated_at_half_query_class_test()
{
    mockserver_answer_dns_break_at_lenght = 12 + 11 + 2 + 1;
    mockserver_init();
    dnscore_init();
    dns_message_t *mesg = dns_message_new_instance();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = yadifa_eu; // 11 bytes long

    ret = xfr_query_init(&xfris, mesg, server_listen_address_text, server_listen_port, query_fqdn, TYPE_AXFR, CLASS_IN, 0, XFR_ALLOW_AXFR);

    if(ret < 0)
    {
        if(ret == UNEXPECTED_EOF)
        {
            yatest_log("axfr_truncated_at_half_query_class_test xfr_query_init returned UNEXPECTED_EOF");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_truncated_at_half_query_class_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_truncated_at_half_query_class_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    dns_message_delete(mesg);
    mockserver_kill();
    return ret;
}

static int axfr_nosuchdomain_test()
{
    mockserver_init();
    dnscore_init();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = nosuchdomain_eu;

    ret = ixfr_query_init(&xfris, server_listen_address_text, server_listen_port, query_fqdn, soa_rdata_sn1, sizeof(soa_rdata_sn1), XFR_ALLOW_BOTH, false);

    if(ret < 0)
    {
        if(ret == MAKE_ERRNO_ERROR(EAGAIN)) // because the server closes the connection when it doesn't know the query
        {
            yatest_log("axfr_nosuchdomain_test xfr_query_init returned EAGAIN");
            ret = 0;
        }
        else if(ret == UNABLE_TO_COMPLETE_FULL_READ) // because the server closes the connection when it doesn't know the query
        {
            yatest_log("axfr_nosuchdomain_test xfr_query_init returned UNABLE_TO_COMPLETE_FULL_READ");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_nosuchdomain_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_nosuchdomain_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    mockserver_kill();
    return ret;
}

static int axfr_noserver_test()
{
    mockserver_init();
    dnscore_init();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = nosuchdomain_eu;

    ret = ixfr_query_init(&xfris, "192.168.1.255", 65535, query_fqdn, soa_rdata_sn1, sizeof(soa_rdata_sn1), XFR_ALLOW_BOTH, false);

    if(ret < 0)
    {
        if(ret == MAKE_ERRNO_ERROR(EAGAIN)) // because the server closes the connection when it doesn't know the query
        {
            yatest_log("axfr_noserver_test xfr_query_init returned EAGAIN");
            ret = 0;
        }
        else if(ret == MAKE_ERRNO_ERROR(ETIMEDOUT)) // because the server closes the connection when it doesn't know the query
        {
            yatest_log("axfr_noserver_test xfr_query_init returned ETIMEDOUT");
            ret = 0;
        }
        else if(ret == MAKE_ERRNO_ERROR(ENETUNREACH))
        {
            yatest_log("axfr_noserver_test xfr_query_init returned ENETUNREACH");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_noserver_test xfr_query_init failed with %i/%08x = %s", ret, ret, error_gettext(ret));
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_noserver_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    mockserver_kill();
    return ret;
}

static int axfr_cantsend_test()
{
    mockserver_answer_dns_close_after_accept = true;

    mockserver_init();
    dnscore_init();
    input_stream_t xfris;
    int            ret;
    const uint8_t *query_fqdn = nosuchdomain_eu;

    ret = ixfr_query_init(&xfris, server_listen_address_text, server_listen_port, query_fqdn, soa_rdata_sn1, sizeof(soa_rdata_sn1), XFR_ALLOW_BOTH, false);

    if(ret < 0)
    {
        if(ret == MAKE_ERRNO_ERROR(EAGAIN)) // because the server closes the connection when it doesn't know the query
        {
            yatest_log("axfr_cantsend_test xfr_query_init returned EAGAIN");
            ret = 0;
        }
        else
        {
            yatest_err("axfr_cantsend_test xfr_query_init failed with %i/%08x", ret, ret);
            ret = 1;
        }
    }
    else
    {
        yatest_log("axfr_cantsend_test xfr_query_init returned %i/%08x", ret, ret);
        ret = 1;
    }

    mockserver_kill();
    return ret;
}

YATEST_TABLE_BEGIN
YATEST(axfr_simple_test)
YATEST(axfr_simple_by2_test)
YATEST(axfr_simple_by3_test)
YATEST(axfr_simple_whole_test)
YATEST(axfr_loose_test)
YATEST(axfr_uptodate_test)
YATEST(axfr_noaxfr_test)
YATEST(ixfr_noixfr_test)
YATEST(axfr_tsig_test)
YATEST(axfr_notsiginreply_test)
YATEST(axfr_brokentsig_test)
YATEST(axfr_replacedtsig_test)
YATEST(axfr_delayed0_tcplen0_test)
YATEST(axfr_delayed0_tcplen1_test)
YATEST(axfr_delayed0_tcplen11_test)
YATEST(axfr_delayed0_tcplen12_test)
YATEST(axfr_delayed0_tcplen14_test)
YATEST(axfr_delayed2_tcplen0_test)
YATEST(axfr_delayed2_tcplen1_test)
YATEST(axfr_delayed2_tcplen11_test)
YATEST(axfr_delayed2_tcplen12_test)
YATEST(axfr_delayed2_tcplen14_test)
YATEST(axfr_delayed4_tcplen0_test)
YATEST(axfr_delayed0_tsig_test)
YATEST(axfr_delayed4_tsig_test)
YATEST(axfr_delayed0_dnserror_test)
YATEST(axfr_delayed4_dnserror_test)
YATEST(axfr_delayed0_notauthoritative_test)
YATEST(axfr_delayed4_notauthoritative_test)
YATEST(axfr_read1_test)
YATEST(axfr_skip1_test)
YATEST(ixfr_simple_test)
YATEST(ixfr_uptodate_test)
YATEST(ixfr_query_test)
YATEST(ixfr_tsig_test)
YATEST(axfr_incomplete_test)
YATEST(axfr_notxfr_test)
YATEST(axfr_mismatched_origins_test)
YATEST(axfr_badsoaformat_test)
YATEST(axfr_badrecordtype_test)
YATEST(axfr_unsupportedtype_test)
YATEST(axfr_badorigin_test)
YATEST(axfr_badqueryorigin_test)
YATEST(axfr_brokenqueryorigin_test)
YATEST(axfr_truncatedsoa_test)
YATEST(axfr_badquerytype_test)
YATEST(axfr_badqueryclass_test)
YATEST(axfr_truncated_at_half_query_type_test)
YATEST(axfr_truncated_at_half_query_class_test)
YATEST(axfr_nosuchdomain_test)
YATEST(axfr_noserver_test)
YATEST(axfr_cantsend_test)
YATEST_TABLE_END

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
#include "dnscore/base64.h"
#include "dnscore/dns_message.h"
#include "dnscore/bytearray_input_stream.h"
#include "dnscore/dns_message_writer.h"
#include <dnscore/dns_packet_writer.h>
#include "yatest_dns.h"
#include <dnscore/dns_packet_reader.h>
#include <dnscore/dnscore.h>
#include <dnscore/tsig.h>

#define MYKEY_NAME    (const uint8_t *)"\005mykey"
#define NOTMYKEY_NAME (const uint8_t *)"\010notmykey"

static const uint8_t mykey_mac[] = {0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
// static const uint8_t notmykey_mac[] = {0x91, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

struct key_data_s
{
    const char *name;
    const char *alg_name;
    const char *key_base64;
};

static const struct key_data_s key_data[] = {{"hmac-sha256-64-key", "hmac-sha256", "t5MhhsjxvsdK5+Qql53qBiI8Vj7gTxL9pkFWCehnLJWypLJPBlpKs+FNe+UqTcOMC1E+ma9sga1hmxbDse2ItQ=="},

                                             {"hmac-md5-1-key", "hmac-md5", "0A=="},
                                             {"hmac-md5-7-key", "hmac-md5", "tujmrz0YCA=="},
                                             {"hmac-md5-8-key", "hmac-md5", "yvyn6LV/CQU="},
                                             {"hmac-md5-16-key", "hmac-md5", "xL6Ep2Am1pUrLzt93wR+2A=="},
                                             {"hmac-md5-64-key", "hmac-md5", "clxDGzgWUqYR8T7bcJqrENoNQOFF8fOSOB8gn/Y47i7A2w/w/TKUbrLZ8YP8SpCnk6bh6qNK208fXRo17vJjMg=="},
                                             {"hmac-sha1-1-key", "hmac-sha1", "ig=="},
                                             {"hmac-sha1-7-key", "hmac-sha1", "BUVB4zLFzQ=="},
                                             {"hmac-sha1-8-key", "hmac-sha1", "D6MAHoNBhGs="},
                                             {"hmac-sha1-16-key", "hmac-sha1", "bOtu7o5eIhu5HgioZ+lgKA=="},
                                             {"hmac-sha1-64-key", "hmac-sha1", "AtUK2n9e1BjjyxwCWgswiqDYE6jogOeExVQ+76nDfCIcJpXqwme0dDLjMTtojizqnhr+R9/2F2nK6Dw6r0i0QQ=="},
                                             {"hmac-sha224-1-key", "hmac-sha224", "qg=="},
                                             {"hmac-sha224-7-key", "hmac-sha224", "H4I0k0GB+A=="},
                                             {"hmac-sha224-8-key", "hmac-sha224", "7ZRV9kKc7YU="},
                                             {"hmac-sha224-16-key", "hmac-sha224", "eKdWJPpW0O8Yf4sG07vx5w=="},
                                             {"hmac-sha224-64-key", "hmac-sha224", "1slgES11bj4nqOsN8qW1LV4Djhg3e+yoqT+K9yFTwA+7u91ye3UU+h/ijCt3LFQh6HigFT12ecRvLR/mLEOoNg=="},
                                             {"hmac-sha256-1-key", "hmac-sha256", "Cw=="},
                                             {"hmac-sha256-7-key", "hmac-sha256", "DKpQ5eUHjA=="},
                                             {"hmac-sha256-8-key", "hmac-sha256", "oc0y1Jk9ZeM="},
                                             {"hmac-sha256-16-key", "hmac-sha256", "sWq2bN0wFqAJvPytt143XA=="},
                                             {"hmac-sha256-64-key", "hmac-sha256", "t5MhhsjxvsdK5+Qql53qBiI8Vj7gTxL9pkFWCehnLJWypLJPBlpKs+FNe+UqTcOMC1E+ma9sga1hmxbDse2ItQ=="},
                                             {"hmac-sha384-1-key", "hmac-sha384", "pQ=="},
                                             {"hmac-sha384-7-key", "hmac-sha384", "Kh6/cxPE0w=="},
                                             {"hmac-sha384-8-key", "hmac-sha384", "XdLvuFqP4Sc="},
                                             {"hmac-sha384-16-key", "hmac-sha384", "vS69sMxUCyAnTqZb657xWw=="},
                                             {"hmac-sha384-64-key", "hmac-sha384", "A/qt9li/C+4smwvwzrX5GZ3md2K1F71H4UNTFE+/UtV8OHOcIU1UlIiTERRTVt8o/74tq59gCqfYQRIyr/rBoA=="},
                                             {"hmac-sha512-1-key", "hmac-sha512", "Og=="},
                                             {"hmac-sha512-7-key", "hmac-sha512", "uzhCK9vSKA=="},
                                             {"hmac-sha512-8-key", "hmac-sha512", "d/nBexG3WHw="},
                                             {"hmac-sha512-16-key", "hmac-sha512", "q9ynRZRulgxWuPr5Mn4gVQ=="},
                                             {"hmac-sha512-64-key", "hmac-sha512", "q50r4X14+CGVgz+kxnXRQ9yhIQABlIsSXd0YUWYmPEgJDizr7lgnuz55FMtqmOnkVEtrXiDq0uFUrnbJ7tkEug=="},
                                             {NULL, NULL, NULL}};

static const uint8_t           ip[4] = {127, 0, 0, 1};

#define YADIFA_EU_AXFR_SERIAL 4

static const uint8_t                  soa_rdata_sn4[] = { // SOA wire, SN=3
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

static const uint8_t                  a_rdata_127_0_0_1[] = {127, 0, 0, 1};

static const uint8_t                  a_rdata_127_0_0_2[] = {127, 0, 0, 2};

static const uint8_t                  a_rdata_127_0_0_3[] = {127, 0, 0, 3};

static const yatest_dns_record_text_t yadifa_eu_axfr_answer[] = {{"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // begin
                                                                 {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_1), a_rdata_127_0_0_1},
                                                                 {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_2), a_rdata_127_0_0_2},
                                                                 {"yadifa.eu.", TYPE_A, CLASS_IN, 86400, sizeof(a_rdata_127_0_0_3), a_rdata_127_0_0_3},
                                                                 {"yadifa.eu.", TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata_sn4), soa_rdata_sn4}, // end
                                                                 {NULL, 0, 0, 0, 0, NULL}};

static void                           tsig_test_register()
{
    uint8_t  fqdn[DOMAIN_LENGTH_MAX];
    uint8_t *tmp_buffer = malloc(65536);

    for(int_fast32_t i = 0; key_data[i].name != NULL; ++i)
    {
        ya_result alg = tsig_get_hmac_algorithm_from_friendly_name(key_data[i].alg_name);
        if(FAIL(alg))
        {
            yatest_err("failed to get algorithm from '%s': %08x", key_data[i].alg_name, alg);
            exit(1); // bug
        }
        ya_result size = base64_decode(key_data[i].key_base64, strlen(key_data[i].key_base64), tmp_buffer);
        if(FAIL(size))
        {
            yatest_err("failed to get bytes from '%s': %08x", key_data[i].key_base64, size);
            exit(1); // bug
        }

        ya_result ret = dnsname_init_with_cstr(fqdn, key_data[i].name);
        if(FAIL(ret))
        {
            yatest_err("failed to convert name '%s' to fqdn: %08x", key_data[i].name, ret);
            exit(1);
        }

        ret = tsig_register(fqdn, tmp_buffer, size, alg);
        if(FAIL(ret))
        {
            yatest_err("failed to register key '%s', '%s', '%s': %08x", key_data[i].name, key_data[i].alg_name, key_data[i].key_base64, ret);
            exit(1);
        }

        tsig_key_t *key = tsig_get_with_ascii_name(key_data[i].name);
        if(key == NULL)
        {
            yatest_err("tsig_get_with_ascii_name %s failed", key_data[i].name);
            exit(1);
        }
    }

    yatest_log("%i keys registered", tsig_get_count());

    for(int i = 0; i < (int)tsig_get_count() + 1; ++i)
    {
        tsig_key_t *key = tsig_get_at_index(i); // inefficient function (iterates the collection every time)
        if(key == NULL)
        {
            continue;
        }
        yatest_log("key %i algorithm is %s", key->mac_algorithm, tsig_get_friendly_name_from_hmac_algorithm(key->mac_algorithm));
    }

    free(tmp_buffer);
}

static void send_receive_message(dns_message_t *msg_out, dns_message_t *msg_in)
{
    output_stream_t os;
    input_stream_t  is;
    char            fqdn_text[256];

    if(dns_message_get_canonised_fqdn(msg_out) != NULL)
    {
        cstr_init_with_dnsname(fqdn_text, dns_message_get_canonised_fqdn(msg_out));
    }
    else
    {
        strcpy(fqdn_text, "?");
    }
    bytearray_output_stream_init(&os, NULL, 65536);
    ssize_t mesg_query_send_tcp_size = dns_message_write_tcp(msg_out, &os); // scan-build false positive, msg_out has been instantiated by the caller

    if(FAIL(mesg_query_send_tcp_size))
    {
        yatest_err("ERROR: %s: failed to send query: %08x", fqdn_text, (int)mesg_query_send_tcp_size);
        exit(1);
    }

    bytearray_input_stream_init(&is, bytearray_output_stream_buffer(&os), mesg_query_send_tcp_size + 2, false);
    ssize_t mesg_query_recv_tcp_size = dns_message_read_tcp(msg_in, &is);
    if(FAIL(mesg_query_recv_tcp_size))
    {
        yatest_err("ERROR: %s: failed to read query: %08x", fqdn_text, (int)mesg_query_recv_tcp_size);
        exit(1);
    }
    input_stream_close(&is);
    output_stream_close(&os);
}

static void key_test(const uint8_t *fqdn)
{
    ya_result      ret;
    dns_message_t *mesg_query = dns_message_new_instance();
    dns_message_t *mesg_svrsd = dns_message_new_instance(); // server-side
    dns_message_t *mesg_answer = dns_message_new_instance();

    char           fqdn_text[256];
    cstr_init_with_dnsname(fqdn_text, fqdn);
    yatest_log("key_test(%s)", fqdn_text);

    /*
     * client side:
     * _ create the message
     * _ sign it
     * _ send it
     *
     */

    dns_message_make_query(mesg_query, 0x1234, (const uint8_t *)"\003www\006yadifa\002eu", TYPE_A, CLASS_IN);
    ret = dns_message_sign_query(mesg_query, tsig_get(fqdn));
    if(FAIL(ret))
    {
        yatest_err("ERROR: failed to sign query: %08x", ret);
        exit(1);
    }

    send_receive_message(mesg_query, mesg_svrsd);

    yatest_log("# client sent:");
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg_query), dns_message_get_size(mesg_query), DNS_MESSAGE_WRITER_SIMPLE_QUERY | DNS_MESSAGE_WRITER_WITH_TSIG, 0);
    flushout();

    /*
     * server side:
     * _ read the message
     * _ process it (get the tsig)
     * _ add a record
     * _ flag it as an authoritative answer
     * _ sign it
     * _ send it
     *
     */

    yatest_log("# server received:");
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg_svrsd), dns_message_get_size(mesg_svrsd), DNS_MESSAGE_WRITER_SIMPLE_QUERY | DNS_MESSAGE_WRITER_WITH_TSIG, 0);
    flushout();

    if(!dns_message_is_query(mesg_svrsd))
    {
        yatest_err("ERROR: %s: message is not an query", fqdn_text);
        exit(1);
    }

    ret = dns_message_process(mesg_svrsd);
    // ret = tsig_extract_and_process(mesg_svrsd);

    if(FAIL(ret))
    {
        yatest_err("ERROR: %s: failed to process query: %08x", fqdn_text, ret);
        exit(1);
    }

    dns_packet_writer_t pw;
    dns_packet_writer_init_from_message(&pw, mesg_svrsd);
    dns_packet_writer_add_record(&pw, dns_message_get_canonised_fqdn(mesg_svrsd), TYPE_A, CLASS_IN, htonl(86400), ip, sizeof(ip));
    dns_message_set_answer_count(mesg_svrsd, 1);
    dns_message_set_authoritative_answer(mesg_svrsd);
    dns_message_set_size(mesg_svrsd, dns_packet_writer_get_offset(&pw));

    // This call is wrong. It erases the MAC and thus breaks the TSIG answer computation:
    // ret = message_sign_answer(mesg_svrsd, tsig_get(fqdn));
    ret = tsig_sign_answer(mesg_svrsd);
    if(FAIL(ret))
    {
        yatest_err("ERROR: %s: failed to sign answer: %08x", fqdn_text, ret);
        exit(1);
    }

    send_receive_message(mesg_svrsd, mesg_answer);

    yatest_log("# server sent:");
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg_svrsd), dns_message_get_size(mesg_svrsd), DNS_MESSAGE_WRITER_SIMPLE_QUERY | DNS_MESSAGE_WRITER_WITH_TSIG, 0);
    flushout();

    /*
     * client side:
     * _ read the message
     * _ process it (verify it)
     *
     */

    yatest_log("# client received:");
    dns_message_print_format_dig(termout, dns_message_get_buffer_const(mesg_answer), dns_message_get_size(mesg_answer), DNS_MESSAGE_WRITER_SIMPLE_QUERY | DNS_MESSAGE_WRITER_WITH_TSIG, 0);
    flushout();

    if(!dns_message_is_answer(mesg_answer))
    {
        yatest_err("ERROR: %s: message is not an answer", fqdn_text);
        exit(1);
    }

    dns_message_tsig_copy_from(mesg_answer, mesg_query);

    ret = dns_message_process_lenient(mesg_answer);
    // ret = tsig_extract_and_process(mesg_answer);
    if(FAIL(ret))
    {
        yatest_err("ERROR: %s: failed to process answer: %08x", fqdn_text, ret);
        exit(1);
    }

    yatest_log("SUCCESS: %s", fqdn_text);

    dns_message_delete(mesg_answer);
    dns_message_delete(mesg_svrsd);
    dns_message_delete(mesg_query);
}

static int algorithms_test()
{
    uint8_t fqdn[DOMAIN_LENGTH_MAX];
    dnscore_init();
    tsig_test_register();
    for(int_fast32_t i = 0; key_data[i].name != NULL; ++i)
    {
        int alg = tsig_get_hmac_algorithm_from_friendly_name(key_data[i].alg_name);
        yatest_log("algorithm: %s (%i %s)", key_data[i].name, alg, tsig_get_friendly_name_from_hmac_algorithm(alg));
        yatest_log("------------------------------------------------");
        dnsname_init_with_cstr(fqdn, key_data[i].name); // this cannot fail (as it has been tested already)
        key_test(fqdn);
    }
    dnscore_finalize();
    return 0;
}

static int tsig_register_test()
{
    int ret;
    dnscore_init();
    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA256);
    if(ret != SUCCESS)
    {
        yatest_err("tsig_register MYKEY_NAME failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA256);
    if(ret != SUCCESS)
    {
        yatest_err("tsig_register MYKEY_NAME failed with %08x = %s (twice)", ret, error_gettext(ret));
        return 1;
    }
    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA512);
    if(ret != TSIG_DUPLICATE_REGISTRATION)
    {
        yatest_err("tsig_register MYKEY_NAME expected to fail with TSIG_DUPLICATE_REGISTRATION, failed with %08x = %s (twice)", ret, error_gettext(ret));
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int xfr_test()
{
    int ret;

    dnscore_init();

    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA256);
    if(ret != SUCCESS)
    {
        yatest_err("tsig_register MYKEY_NAME failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    dns_message_t *mesg_query = dns_message_new_instance();
    dns_message_t *mesg_svrsd = dns_message_new_instance(); // server-side
    dns_message_t *mesg_answer = dns_message_new_instance();

    dns_message_make_query(mesg_query, 0x1234, (const uint8_t *)"\006yadifa\002eu", TYPE_AXFR, CLASS_IN);
    ret = dns_message_sign_query(mesg_query, tsig_get(MYKEY_NAME));
    if(FAIL(ret))
    {
        yatest_err("ERROR: failed to sign query: %08x", ret);
        exit(1);
    }

    send_receive_message(mesg_query, mesg_svrsd);

    ret = dns_message_process(mesg_svrsd);

    if(FAIL(ret))
    {
        yatest_err("ERROR: failed to process query: %08x", ret);
        exit(1);
    }

    tsig_tcp_message_position pos = TSIG_NOWHERE;
    int                       old_mac_size;
    uint8_t                   old_mac[HMAC_BUFFER_SIZE];
    old_mac_size = dns_message_tsig_mac_get_size(mesg_query);
    dns_message_tsig_mac_copy(mesg_query, old_mac);

    dns_packet_writer_t pw;
    dns_packet_writer_init_append_to_message(&pw, mesg_svrsd);
    uint16_t packet_offset = pw.packet_offset;
    for(int i = 0; i < 1000; ++i)
    {
        for(int record_index = 0; yadifa_eu_axfr_answer[record_index].fqdn != NULL; ++record_index)
        {
            // take the message
            // add record
            // sign
            // send
            // receive
            uint8_t fqdn[256];
            dns_message_set_answer_count(mesg_svrsd, 0);
            dns_message_set_additional_count(mesg_svrsd, 0);
            pw.packet_offset = packet_offset;
            dnsname_init_with_cstr(fqdn, yadifa_eu_axfr_answer[record_index].fqdn);
            dns_packet_writer_add_fqdn(&pw, fqdn);
            dns_packet_writer_add_u16(&pw, yadifa_eu_axfr_answer[record_index].rtype);
            dns_packet_writer_add_u16(&pw, yadifa_eu_axfr_answer[record_index].rclass);
            dns_packet_writer_add_u32(&pw, htonl(yadifa_eu_axfr_answer[record_index].rttl));
            dns_packet_writer_add_u16(&pw, htons(yadifa_eu_axfr_answer[record_index].rdata_len));
            dns_packet_writer_add_bytes(&pw, yadifa_eu_axfr_answer[record_index].rdata, yadifa_eu_axfr_answer[record_index].rdata_len);
            dns_message_set_size(mesg_svrsd, pw.packet_offset);
            dns_message_set_answer_count(mesg_svrsd, 1);

            if((i == 0) && (record_index == 0))
            {
                yatest_log("TSIG_START");
                pos = TSIG_START;
            }
            else if((i == 999) && (yadifa_eu_axfr_answer[record_index + 1].fqdn == NULL))
            {
                yatest_log("TSIG_END");
                pos = TSIG_END;
            }
            else
            {
                pos = TSIG_MIDDLE;
            }

            ret = tsig_sign_tcp_message(mesg_svrsd, pos);
            if(ret < 0)
            {
                yatest_err("tsig_sign_tcp_message %i failed (i=%i, record_index=%i) %08x = %s", pos, i, record_index, ret, error_gettext(ret));
                return 1;
            }

            send_receive_message(mesg_svrsd, mesg_answer);

            if(pos == TSIG_START)
            {
                tsig_message_extract(mesg_answer);
                ret = tsig_verify_tcp_first_message(mesg_answer, old_mac, old_mac_size);
                if(ret < 0)
                {
                    yatest_err("tsig_verify_tcp_first_message %i failed (i=%i, record_index=%i) %08x = %s", pos, i, record_index, ret, error_gettext(ret));
                    return 1;
                }
            }
            else
            {
                dns_message_tsig_clear_key(mesg_answer); // so a newly found tsig can be obtained
                tsig_message_extract(mesg_answer);
                ret = tsig_verify_tcp_next_message(mesg_answer);
                if(ret < 0)
                {
                    yatest_err("tsig_verify_tcp_next_message %i failed (i=%i, record_index=%i) %08x = %s", pos, i, record_index, ret, error_gettext(ret));
                    return 1;
                }
            }
            if(pos == TSIG_END)
            {
                tsig_verify_tcp_last_message(mesg_answer);
            }
        }
    }

    dnscore_finalize();
    return 0;
}

static int xfr_unknown_test()
{
    int ret;

    dnscore_init();

    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA256);
    if(ret != SUCCESS)
    {
        yatest_err("tsig_register MYKEY_NAME failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    dns_message_t *mesg_query = dns_message_new_instance();
    dns_message_t *mesg_svrsd = dns_message_new_instance(); // server-side

    dns_message_make_query(mesg_query, 0x1234, (const uint8_t *)"\006yadifa\002eu", TYPE_AXFR, CLASS_IN);
    ret = dns_message_sign_query(mesg_query, tsig_get(MYKEY_NAME));
    if(FAIL(ret))
    {
        yatest_err("ERROR: failed to sign query: %08x", ret);
        exit(1);
    }

    send_receive_message(mesg_query, mesg_svrsd);

    tsig_unregister(MYKEY_NAME);

    ret = dns_message_process(mesg_svrsd);

    if(ret != TSIG_BADKEY)
    {
        yatest_err("ERROR: expected TSIG_BADKEY, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    dnscore_finalize();
    return 0;
}

static int xfr_fudge_test()
{
    int ret;

    dnscore_init();

    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA256);
    if(ret != SUCCESS)
    {
        yatest_err("tsig_register MYKEY_NAME failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    dns_message_fudge_set(1);

    dns_message_t *mesg_query = dns_message_new_instance();
    dns_message_t *mesg_svrsd = dns_message_new_instance(); // server-side

    dns_message_make_query(mesg_query, 0x1234, (const uint8_t *)"\006yadifa\002eu", TYPE_AXFR, CLASS_IN);
    ret = dns_message_sign_query(mesg_query, tsig_get(MYKEY_NAME));
    if(FAIL(ret))
    {
        yatest_err("ERROR: failed to sign query: %08x", ret);
        exit(1);
    }

    send_receive_message(mesg_query, mesg_svrsd);

    yatest_sleep(5); // fudge will be too old

    ret = dns_message_process(mesg_svrsd);

    if(ret != TSIG_BADTIME)
    {
        yatest_err("ERROR: expected TSIG_BADTIME, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    dnscore_finalize();
    return 0;
}

static int xfr_badsig_test()
{
    int ret;

    dnscore_init();

    ret = tsig_register(MYKEY_NAME, mykey_mac, sizeof(mykey_mac), HMAC_SHA256);
    if(ret != SUCCESS)
    {
        yatest_err("tsig_register MYKEY_NAME failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    dns_message_t *mesg_query = dns_message_new_instance();
    dns_message_t *mesg_svrsd = dns_message_new_instance(); // server-side

    dns_message_make_query(mesg_query, 0x1234, (const uint8_t *)"\006yadifa\002eu", TYPE_AXFR, CLASS_IN);
    ret = dns_message_sign_query(mesg_query, tsig_get(MYKEY_NAME));
    if(FAIL(ret))
    {
        yatest_err("ERROR: failed to sign query: %08x", ret);
        exit(1);
    }

    send_receive_message(mesg_query, mesg_svrsd);

    // corrupt the message: (changes the second letter of the query fqdn)
    dns_message_get_buffer(mesg_svrsd)[DNS_HEADER_LENGTH + 2]++;

    ret = dns_message_process(mesg_svrsd);

    if(ret != TSIG_BADSIG)
    {
        yatest_err("ERROR: expected TSIG_BADSIG, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(tsig_register_test)
YATEST(algorithms_test)
YATEST(xfr_test)
YATEST(xfr_unknown_test)
YATEST(xfr_fudge_test)
YATEST(xfr_badsig_test)
YATEST_TABLE_END

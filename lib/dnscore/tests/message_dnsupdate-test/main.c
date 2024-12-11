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
#include "dnscore/dns_message_writer.h"
#include <dnscore/dnscore.h>
#include <dnscore/dns_message_update.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/zone_reader_text.h>

static const uint8_t origin[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t empty[] = {5, 'e', 'm', 'p', 't', 'y', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t replace[] = {7, 'r', 'e', 'p', 'l', 'a', 'c', 'e', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t ipv4[] = {4, 'i', 'p', 'v', '4', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t ip4[] = {127, 0, 0, 1};
static const uint8_t ip4b[] = {127, 0, 0, 2};
static const char    dnskey_public_record[] =
    "example.eu. IN DNSKEY 256 3 13 sMept+nZXEKJtdgbqRKTSSMj8O/11kdqcinORHrSNoeF4sv56jxbIs4/ "
    "l/mk2n263pfJ9FnRSPOb0rPXtS3riQ==";

static dnskey_t *dnskey_parse()
{
    input_stream_t     is;
    resource_record_t *rr = (resource_record_t *)yatest_malloc(sizeof(resource_record_t));
    bytearray_input_stream_init_const(&is, dnskey_public_record, sizeof(dnskey_public_record) - 1);

    yatest_log("PUBLIC KEY:");
    yatest_log("-----------");
    yatest_log(dnskey_public_record);

    zone_reader_t zr;
    ya_result     ret = zone_reader_text_parse_stream(&zr, &is);
    if(ret < 0)
    {
        yatest_err("failed to init zone reader");
        exit(1);
    }

    zone_reader_text_ignore_missing_soa(&zr);

    ret = zone_reader_read_record(&zr, rr);
    if(ret < 0)
    {
        yatest_err("failed to read record: %08x = %s", ret, error_gettext(ret));
        exit(1);
    }

    zone_reader_close(&zr);

    dnskey_t *key = NULL;
    if(dnskey_new_from_rdata(rr->rdata, rr->rdata_size, rr->name, &key) < 0)
    {
        yatest_err("dnskey_new_from_rdata failed");
        exit(1);
    }
    free(rr);
    return key;
}

static int dns_message_update_test()
{
    int ret;
    dnscore_init();
    dns_message_t      *mesg = dns_message_new_instance();
    dns_packet_writer_t pw;
    dns_message_update_init(mesg, 0x1234, origin, CLASS_IN, 32768, &pw);
    ret = dns_message_update_delete_all_rrsets(mesg, &pw, empty);
    if(ret < 0)
    {
        yatest_err("dns_message_update_delete_all_rrsets failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = dns_message_update_delete_rrset(mesg, &pw, replace, TYPE_A);
    if(ret < 0)
    {
        yatest_err("dns_message_update_delete_rrset failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = dns_message_update_delete_record(mesg, &pw, ipv4, TYPE_A, 4, ip4);
    if(ret < 0)
    {
        yatest_err("dns_message_update_delete_record failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    dns_resource_record_t *rr = dns_resource_record_new_instance();
    dns_resource_record_set_record(rr, ipv4, TYPE_A, CLASS_IN, 86400, 4, ip4);
    ret = dns_message_update_delete_dns_resource_record(mesg, &pw, rr);
    if(ret < 0)
    {
        yatest_err("dns_message_update_delete_dns_resource_record failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = dns_message_update_add_record(mesg, &pw, ipv4, TYPE_A, CLASS_IN, 86400, 4, ip4b);
    if(ret < 0)
    {
        yatest_err("dns_message_update_add_record failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    dns_resource_record_set_record(rr, ipv4, TYPE_A, CLASS_IN, 86400, 4, ip4b);
    ret = dns_message_update_add_dns_resource_record(mesg, &pw, rr);
    if(ret < 0)
    {
        yatest_err("dns_message_update_add_dns_resource_record failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    dnskey_t *key = dnskey_parse();
    ret = dns_message_update_add_dnskey(mesg, &pw, key, 86400);
    if(ret < 0)
    {
        yatest_err("dns_message_update_add_dnskey failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = dns_message_update_delete_dnskey(mesg, &pw, key);
    if(ret < 0)
    {
        yatest_err("dns_message_update_delete_dnskey failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    dns_message_edns0_set(mesg);
    ret = dns_message_update_finalize(mesg, &pw);
    if(ret < 0)
    {
        yatest_err("dns_message_update_finalize failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    output_stream_t os;
    bytearray_output_stream_init(&os, NULL, 65535);
    dns_message_print_format_dig_buffer(&os, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), DNS_MESSAGE_WRITER_SIMPLE_QUERY);
    output_stream_write_u8(&os, 0);
    yatest_log("message size: %i", dns_message_get_size(mesg));
    yatest_log("'%s'", bytearray_output_stream_buffer(&os));

    const char expected[] =
        ";; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id: 13330\n"
        ";; flags: ZONE: 1, PREREQUISITES: 0, UPDATE: 8, ADDITIONAL: 1\n"
        "\n"
        ";; ZONE:\n"
        ";yadifa.eu.                      IN      SOA\n"
        "\n"
        ";; PREREQUISITES:\n"
        "\n"
        ";; UPDATE RECORDS:\n"
        "empty.yadifa.eu.         0       ANY     ANY     \\# 0 \n"
        "replace.yadifa.eu.       0       ANY     A       \n"
        "ipv4.yadifa.eu.          0       NONE    A       127.0.0.1\n"
        "ipv4.yadifa.eu.          0       NONE    A       127.0.0.1\n"
        "ipv4.yadifa.eu.          86400   IN      A       127.0.0.2\n"
        "ipv4.yadifa.eu.          86400   IN      A       127.0.0.2\n"
        "example.eu.              86400   IN      DNSKEY  256 3 13 "
        "sMept+nZXEKJtdgbqRKTSSMj8O/11kdqcinORHrSNoeF4sv56jxbIs4/l/mk2n26 3pfJ9FnRSPOb0rPXtS3riQ==\n"
        "example.eu.              0       NONE    DNSKEY  256 3 13 "
        "sMept+nZXEKJtdgbqRKTSSMj8O/11kdqcinORHrSNoeF4sv56jxbIs4/l/mk2n26 3pfJ9FnRSPOb0rPXtS3riQ==\n"
        "\n"
        ";; ADDITIONAL RECORDS:\n"
        ";; OPT: UDP payload size: 128\n"
        ";; OPT: extended RCODE and flags: 00000000\n"
        "\n"
        ";; MSG SIZE: 313\n"
        "\n";

    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("expectations differs");
        yatest_err("got");
        yatest_hexdump_err(bytearray_output_stream_buffer(&os), bytearray_output_stream_buffer(&os) + bytearray_output_stream_size(&os));
        yatest_err("expected");
        yatest_hexdump_err(expected, expected + sizeof(expected));
        return 1;
    }

    dnscore_finalize();
    return 0;
}

static int dns_message_update_overflow_test()
{
    int ret;
    dnscore_init();
    dns_message_t      *mesg = dns_message_new_instance_ex(NULL, 27);
    dns_packet_writer_t pw;
    ret = dns_message_update_init(mesg, 0x1234, origin, CLASS_IN, 32768, &pw);
    if(ret < 0)
    {
        yatest_err("dns_message_update_init failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = dns_message_update_delete_all_rrsets(mesg, &pw, empty);
    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("dns_message_update_delete_all_rrsets expected to fail with BUFFER_WOULD_OVERFLOW=%08x, returned %08x", BUFFER_WOULD_OVERFLOW, ret);
        return 1;
    }
    ret = dns_message_update_delete_rrset(mesg, &pw, replace, TYPE_A);
    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("dns_message_update_delete_all_rrsets expected to fail with BUFFER_WOULD_OVERFLOW=%08x, returned %08x", BUFFER_WOULD_OVERFLOW, ret);
        return 1;
    }
    ret = dns_message_update_delete_record(mesg, &pw, ipv4, TYPE_A, 4, ip4);
    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("dns_message_update_delete_all_rrsets expected to fail with BUFFER_WOULD_OVERFLOW=%08x, returned %08x", BUFFER_WOULD_OVERFLOW, ret);
        return 1;
    }
    dns_resource_record_t *rr = dns_resource_record_new_instance();
    dns_resource_record_set_record(rr, ipv4, TYPE_A, CLASS_IN, 86400, 4, ip4);
    ret = dns_message_update_delete_dns_resource_record(mesg, &pw, rr);
    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("dns_message_update_delete_all_rrsets expected to fail with BUFFER_WOULD_OVERFLOW=%08x, returned %08x", BUFFER_WOULD_OVERFLOW, ret);
        return 1;
    }
    ret = dns_message_update_add_record(mesg, &pw, ipv4, TYPE_A, CLASS_IN, 86400, 4, ip4b);
    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("dns_message_update_delete_all_rrsets expected to fail with BUFFER_WOULD_OVERFLOW=%08x, returned %08x", BUFFER_WOULD_OVERFLOW, ret);
        return 1;
    }
    dns_resource_record_set_record(rr, ipv4, TYPE_A, CLASS_IN, 86400, 4, ip4b);
    ret = dns_message_update_add_dns_resource_record(mesg, &pw, rr);
    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("dns_message_update_delete_all_rrsets expected to fail with BUFFER_WOULD_OVERFLOW=%08x, returned %08x", BUFFER_WOULD_OVERFLOW, ret);
        return 1;
    }
    dnskey_t *key = dnskey_parse();
    ret = dns_message_update_add_dnskey(mesg, &pw, key, 86400);
    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("dns_message_update_delete_all_rrsets expected to fail with BUFFER_WOULD_OVERFLOW=%08x, returned %08x", BUFFER_WOULD_OVERFLOW, ret);
        return 1;
    }
    ret = dns_message_update_delete_dnskey(mesg, &pw, key);
    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("dns_message_update_delete_all_rrsets expected to fail with BUFFER_WOULD_OVERFLOW=%08x, returned %08x", BUFFER_WOULD_OVERFLOW, ret);
        return 1;
    }
    dns_message_edns0_set(mesg);
    ret = dns_message_update_finalize(mesg, &pw);
    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("dns_message_update_delete_all_rrsets expected to fail with BUFFER_WOULD_OVERFLOW=%08x, returned %08x", BUFFER_WOULD_OVERFLOW, ret);
        return 1;
    }

    output_stream_t os;
    bytearray_output_stream_init(&os, NULL, 65535);
    dns_message_print_format_dig_buffer(&os, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), UINT16_MAX);
    output_stream_write_u8(&os, 0);
    yatest_log("message size: %i", dns_message_get_size(mesg));
    yatest_log("'%s'", bytearray_output_stream_buffer(&os));

    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(dns_message_update_test)
YATEST(dns_message_update_overflow_test)
YATEST_TABLE_END

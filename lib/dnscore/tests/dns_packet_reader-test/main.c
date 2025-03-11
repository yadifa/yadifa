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

#include "yatest.h"
#include <dnscore/dnscore.h>
#include <dnscore/dns_packet_reader.h>

#define YADIFA_EU     6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0 // 11 bytes
// #define TYPE8(x_) (((x_) >> 8) & 0xff),((x_) & 0xff)
#define TYPE8(x_)     ((x_) & 0xff), (((x_) >> 8) & 0xff)
#define CLASS8_IN     0, 1
#define CLASS8_IN_TTL 0, 1, 0, 1, 0x51, 0x80
#define RDATA8(x_)    (((x_) >> 8) & 0xff), ((x_) & 0xff)

static const uint8_t yadifa_eu[] = {YADIFA_EU};
static const uint8_t key_name[] = {3, 'k', 'e', 'y', 0};
static const uint8_t key_mac[] = {0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09};

static const uint8_t packet[] = {
    0x12,
    0x34,
    0x80,
    0x00,
    0x00,
    0x01,
    0x00,
    0x07,
    0x00,
    0x00,
    0x00,
    0x00,
    //
    YADIFA_EU,
    TYPE8(TYPE_ANY),
    CLASS8_IN, // ANY
    //
    YADIFA_EU,
    TYPE8(TYPE_A),
    CLASS8_IN_TTL,
    RDATA8(4),
    127,
    0,
    0,
    1, // 127.0.0.1
    YADIFA_EU,
    TYPE8(TYPE_AAAA),
    CLASS8_IN_TTL,
    RDATA8(16),
    32,
    2,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1, // 2002::1
    YADIFA_EU,
    TYPE8(TYPE_MX),
    CLASS8_IN_TTL,
    RDATA8(18),
    0,
    10,
    4,
    'm',
    'a',
    'i',
    'l',
    YADIFA_EU, // mail.yadifa.eu.
    YADIFA_EU,
    TYPE8(TYPE_SOA),
    CLASS8_IN_TTL,
    RDATA8(52),
    3,
    'n',
    's',
    '1',
    YADIFA_EU, // 15
    5,
    'a',
    'd',
    'm',
    'i',
    'n',
    YADIFA_EU, // + 17
    0,
    1,
    2,
    3,
    0,
    0,
    5,
    0,
    0,
    0,
    4,
    0,
    0,
    0,
    3,
    0,
    0,
    0,
    2,
    0, // + 20
    YADIFA_EU,
    TYPE8(TYPE_RRSIG),
    CLASS8_IN_TTL,
    RDATA8(157),
    0x00,
    0x06,
    0x08,
    0x01,
    0x00,
    0x01,
    0x51,
    0x80,
    0x66,
    0x39,
    0xe3,
    0x73,
    0x66,
    0x30,
    0x9a,
    0xe3, //
    0x6a,
    0x02,      // 18
    YADIFA_EU, // + 11
    0x77,
    0x1f,
    0xe0,
    0x5b,
    0x4e,
    0xcb,
    0x3f,
    0xe1, // + 128
    0xb9,
    0xf4,
    0x1b,
    0x9e,
    0x98,
    0x29,
    0xd7,
    0xde,
    0xfb,
    0xbd,
    0xdd,
    0x87,
    0x08,
    0x8c,
    0x83,
    0x90,
    0xef,
    0xdb,
    0xc3,
    0xc9,
    0x19,
    0x36,
    0xde,
    0xbe,
    0xd2,
    0x64,
    0x12,
    0x8e,
    0x75,
    0x86,
    0x71,
    0x27,
    0xf9,
    0x31,
    0x74,
    0xbb,
    0xa3,
    0xdf,
    0x0e,
    0xac,
    0xec,
    0xdf,
    0x56,
    0x14,
    0x04,
    0x62,
    0x91,
    0xbc,
    0x70,
    0xfc,
    0x9f,
    0x92,
    0xaa,
    0xda,
    0x49,
    0xec,
    0x2b,
    0x2d,
    0x7e,
    0x7e,
    0xab,
    0xc3,
    0x30,
    0x3b,
    0x58,
    0x7a,
    0xd3,
    0x4b,
    0x9e,
    0x20,
    0x92,
    0x92,
    0x77,
    0xe7,
    0xda,
    0x3f,
    0x59,
    0x0b,
    0x59,
    0x5d,
    0x15,
    0x64,
    0x7c,
    0xa4,
    0x9d,
    0x03,
    0xc1,
    0xf7,
    0xd2,
    0xe1,
    0x17,
    0xae,
    0xf4,
    0x01,
    0xd0,
    0x9b,
    0xd1,
    0x15,
    0x2b,
    0xe0,
    0x59,
    0x2b,
    0x73,
    0x21,
    0xb7,
    0x06,
    0xa9,
    0xfd,
    0x4e,
    0xb1,
    0xd5,
    0xd3,
    0x18,
    0x15,
    0x26,
    0x67,
    0x08,
    0xa4,
    0x8f,
    0x0c,
    YADIFA_EU,
    TYPE8(TYPE_NSEC),
    CLASS8_IN_TTL,
    RDATA8(20),
    YADIFA_EU,
    0x00,
    0x07,
    0x22,
    0x00,
    0x80,
    0x00,
    0x00,
    0x03,
    0x80,
    YADIFA_EU,
    TYPE8(TYPE_NS),
    CLASS8_IN_TTL,
    RDATA8(15),
    3,
    'n',
    's',
    '1',
    YADIFA_EU, // ns1.yadifa.eu.
};

static const uint8_t packet_utf8[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'u', 't', 'f', '8', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};

static const uint8_t packet_remote[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x34, 127, 0, 0, 1, 0, 53, 3, 'k', 'e', 'y', 0, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

dns_packet_reader_t  pr;
dns_message_t       *mesg = NULL;

static void          dns_packet_reader_init_test(int init_type, dns_packet_reader_t *prp, dns_message_t **mesgp)
{
    dns_message_t *mesg = dns_message_new_instance(NULL, sizeof(packet));
    memcpy(dns_message_get_buffer(mesg), packet, sizeof(packet));
    dns_message_set_size(mesg, sizeof(packet));
    *mesgp = mesg;
    switch(init_type)
    {
        case 0:
        {
            dns_packet_reader_init(prp, packet, sizeof(packet));
            dns_packet_reader_skip(prp, DNS_HEADER_LENGTH);
            break;
        }
        case 1:
        {
            dns_packet_reader_init_from_message_at(prp, mesg, DNS_HEADER_LENGTH);
            break;
        }
        case 2:
        {
            dns_packet_reader_init_from_message(prp, mesg);
            break;
        }
        default:
        {
            yatest_err("dns_packet_reader_init_test unsupported type %i", init_type);
            exit(1);
        }
    }
}

static void init(int init_type)
{
    dnscore_init();
    dns_packet_reader_init_test(init_type, &pr, &mesg);
}

static void finalise() { dnscore_finalize(); }

static int  dns_packet_reader_skip_section_test()
{
    int ret;
    init(0);
    for(int section_index = 0; section_index < 4; ++section_index)
    {
        ret = dns_packet_reader_skip_section(&pr, section_index);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_skip_query_section couldn't skip the query section %i", section_index);
            return 1;
        }
    }
    if(!dns_packet_reader_eof(&pr))
    {
        yatest_err("dns_packet_reader_eof did not return true");
        return 1;
    }
    finalise();
    return 0;
}

static int dns_packet_reader_packet_reader_read_record_test()
{
    int ret;
    init(1);
    size_t   buffer_size = 65536;
    uint8_t *buffer = malloc(buffer_size);
    dns_packet_reader_skip_section(&pr, 0);
    int an = dns_message_get_answer_count(mesg);
    for(int i = 0; i < an; ++i)
    {
        ret = dns_packet_reader_read_record(&pr, buffer, buffer_size);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_record failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
    }
    ret = dns_packet_reader_read_record(&pr, buffer, buffer_size);
    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_packet_reader_read_record expected UNEXPECTED_EOF, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    free(buffer);
    finalise();
    return 0;
}

static int dns_packet_reader_read_dns_resource_record_test()
{
    int ret;
    init(2);
    dns_resource_record_t *rr = dns_resource_record_new_instance();
    dns_packet_reader_skip_section(&pr, 0);
    int an = dns_message_get_answer_count(mesg);
    for(int i = 0; i < an; ++i)
    {
        ret = dns_packet_reader_read_dns_resource_record(&pr, rr);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_dns_resource_record failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
    }
    ret = dns_packet_reader_read_dns_resource_record(&pr, rr);
    if(ret != UNEXPECTED_EOF)
    {
        yatest_err("dns_packet_reader_read_record expected UNEXPECTED_EOF, got %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int dns_packet_reader_read_test()
{
    int ret;
    init(2);
    size_t   buffer_size = 65536;
    uint8_t *buffer = malloc(buffer_size);

    ret = dns_packet_reader_skip_query(&pr, yadifa_eu, TYPE_ANY, CLASS_IN);
    if(ret < 0)
    {
        yatest_err("dns_packet_reader_skip_query failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    int an = dns_message_get_answer_count(mesg);
    for(int i = 0; i < an; ++i)
    {
        yatest_log("record %i", i);
        ret = dns_packet_reader_read_fqdn(&pr, buffer, buffer_size);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_fqdn failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        ret = dns_packet_reader_read_dnstype(&pr);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_dnstype failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        uint16_t rtype = ntohs(ret);
        ret = dns_packet_reader_read_dnsclass(&pr);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_dnsclass failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        // uint16_t rclass = ntohs(ret);
        int32_t ttl;
        ret = dns_packet_reader_read_s32(&pr, &ttl);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_dnsclass failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        ttl = ntohl(ttl);
        uint16_t rdata_size;
        ret = dns_packet_reader_read_u16(&pr, &rdata_size);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_u16 failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        rdata_size = ntohs(rdata_size);
        ret = dns_packet_reader_read_rdata(&pr, rtype, rdata_size, buffer, buffer_size);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_rdata failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
    }

    if(!dns_packet_reader_eof(&pr))
    {
        yatest_err("dns_packet_reader_eof did not return true");
        return 1;
    }

    finalise();
    return 0;
}

static int dns_packet_reader_skip_bytes_test()
{
    int ret;
    init(2);
    size_t   buffer_size = 65536;
    uint8_t *buffer = malloc(buffer_size);

    ret = dns_packet_reader_skip_query(&pr, yadifa_eu, TYPE_ANY, CLASS_IN);
    if(ret < 0)
    {
        yatest_err("dns_packet_reader_skip_query failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    int an = dns_message_get_answer_count(mesg);
    for(int i = 0; i < an; ++i)
    {
        yatest_log("record %i", i);
        ret = dns_packet_reader_read_fqdn(&pr, buffer, buffer_size);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_fqdn failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        ret = dns_packet_reader_read_dnstype(&pr);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_dnstype failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        // uint16_t rtype = ntohs(ret);
        ret = dns_packet_reader_read_dnsclass(&pr);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_dnsclass failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        // uint16_t rclass = ntohs(ret);
        int32_t ttl;
        ret = dns_packet_reader_read_s32(&pr, &ttl);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_dnsclass failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        ttl = ntohl(ttl);
        uint16_t rdata_size;
        ret = dns_packet_reader_read_u16(&pr, &rdata_size);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_read_u16 failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        rdata_size = ntohs(rdata_size);
        ret = dns_packet_reader_skip_bytes(&pr, rdata_size);
        if(ret < 0)
        {
            yatest_err("dns_packet_reader_skip_bytes failed with %08x = %s", ret, error_gettext(ret));
            return 1;
        }
    }

    if(!dns_packet_reader_eof(&pr))
    {
        yatest_err("dns_packet_reader_eof did not return true");
        return 1;
    }

    finalise();
    return 0;
}

static int dns_packet_reader_read_utf8_test()
{
    int ret;
    dnscore_init();
    dns_packet_reader_init(&pr, packet_utf8, sizeof(packet_utf8));
    dns_packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    char *txt = NULL;
    ret = dns_packet_reader_read_utf8(&pr, sizeof(packet_utf8) - DNS_HEADER_LENGTH, CLASS_IN, &txt, false);
    if(ret < 0)
    {
        yatest_err("dns_packet_reader_read_utf8 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    pr.packet_offset = DNS_HEADER_LENGTH;
    ret = dns_packet_reader_read_utf8(&pr, 0, CLASS_ANY, &txt, false);
    if(ret < 0)
    {
        yatest_err("dns_packet_reader_read_utf8 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

static int dns_packet_reader_read_remote_server_test()
{
    int ret;
    dnscore_init();

    ret = tsig_register(key_name, key_mac, sizeof(key_mac), HMAC_SHA1);

    if(FAIL(ret))
    {
        yatest_err("tsig_register failed with %x", ret);
        exit(1);
    }

    dns_packet_reader_init(&pr, packet_remote, sizeof(packet_remote));
    dns_packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    host_address_t *ha = NULL;
    ret = dns_packet_reader_read_remote_server(&pr, 12, CLASS_IN, &ha, false);
    if(ret < 0)
    {
        yatest_err("dns_packet_reader_read_utf8 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = dns_packet_reader_read_remote_server(&pr, 17, CLASS_IN, &ha, false);
    if(ret < 0)
    {
        yatest_err("dns_packet_reader_read_utf8 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    pr.packet_offset = DNS_HEADER_LENGTH;
    ret = dns_packet_reader_read_remote_server(&pr, 0, CLASS_ANY, &ha, false);
    if(ret < 0)
    {
        yatest_err("dns_packet_reader_read_utf8 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(dns_packet_reader_skip_section_test)
YATEST(dns_packet_reader_packet_reader_read_record_test)
YATEST(dns_packet_reader_read_dns_resource_record_test)
YATEST(dns_packet_reader_read_test)
YATEST(dns_packet_reader_skip_bytes_test)
YATEST(dns_packet_reader_read_utf8_test)
YATEST(dns_packet_reader_read_remote_server_test)
YATEST_TABLE_END

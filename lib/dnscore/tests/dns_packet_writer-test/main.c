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
#include <dnscore/dns_packet_reader.h>
#include <dnscore/dnscore.h>
#include <dnscore/dns_packet_writer.h>

static dns_packet_writer_t    pw;
static dns_packet_reader_t    pr;
static dns_resource_record_t *rr = NULL;
static uint8_t               *packet = NULL;
static size_t                 packet_size = 65536;

#define YADIFA_EU 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0 // 11 bytes
static const uint8_t yadifa_eu[] = {YADIFA_EU};

static const uint8_t ns1_yadifa_eu[] = {3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t ipv4_0[4] = {127, 0, 0, 1};
static const uint8_t ipv6_0[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t soa_rdata[] = {3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 5, 'a', 'd', 'm', 'i', 'n', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 0, 1, 2, 3, 0, 0, 5, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 2, 0};
static const uint8_t mx_rdata[] = {0, 10, 4, 'm', 'a', 'i', 'l', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};

static const uint8_t sha1digest[20] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};

static void          init()
{
    dnscore_init();
    packet = malloc(packet_size);
    dns_packet_writer_init(&pw, packet, DNS_HEADER_LENGTH, packet_size);
}

static void finalise() { dnscore_finalize(); }

static void dns_packet_writer_reader_add_read(const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, uint16_t rdata_size, const uint8_t *rdata)
{
    int ret;
    ret = dns_packet_writer_add_fqdn(&pw, fqdn);
    if(ret < 0)
    {
        yatest_err("packet_writer_add_fqdn failed with %08x = %s", ret, error_gettext(ret));
        exit(1);
    }
    dns_packet_writer_add_u16(&pw, rtype);
    dns_packet_writer_add_u16(&pw, rclass);
    dns_packet_writer_add_u32(&pw, htonl(ttl));
    ret = dns_packet_writer_add_rdata(&pw, rtype, rdata, rdata_size);
    if(ret < 0)
    {
        yatest_err("dns_packet_writer_add_rdata failed with %08x = %s", ret, error_gettext(ret));
        exit(1);
    }

    dns_packet_reader_read_dns_resource_record(&pr, rr);
    if(!dnsname_equals(fqdn, rr->name))
    {
        yatest_err("fqdn doesn't match");
        exit(1);
    }
    if(rr->tctr.rtype != rtype)
    {
        yatest_err("rtype doesn't match");
        exit(1);
    }
    if(rr->tctr.rclass != rclass)
    {
        yatest_err("rtype doesn't match");
        exit(1);
    }
    if(rr->tctr.ttl != (int32_t)htonl(ttl))
    {
        yatest_err("ttl doesn't match");
        exit(1);
    }
    if(rr->rdata_size != rdata_size)
    {
        yatest_err("rdata_size doesn't match");
        exit(1);
    }
    if(memcmp(rr->rdata, rdata, rr->rdata_size) != 0)
    {
        yatest_err("rdata doesn't match");
        exit(1);
    }
}

static int dns_packet_writer_add_test()
{
    int ret;
    init();

    dns_packet_reader_init(&pr, packet, packet_size);
    dns_packet_reader_skip(&pr, DNS_HEADER_LENGTH);

    rr = dns_resource_record_new_instance();

    ret = dns_packet_writer_add_fqdn_uncompressed(&pw, yadifa_eu);
    if(FAIL(ret))
    {
        yatest_err("packet_writer_add_test: dns_packet_writer_add_fqdn_uncompressed returned %08x", ret);
        return 1;
    }
    dns_packet_writer_add_u16(&pw, TYPE_A);
    dns_packet_writer_add_u16(&pw, CLASS_IN);
    dns_packet_writer_add_u32(&pw, htonl(86400));
    ret = dns_packet_writer_add_rdata(&pw, TYPE_A, ipv4_0, sizeof(ipv4_0));
    if(FAIL(ret))
    {
        yatest_err("packet_writer_add_test: dns_packet_writer_add_rdata A returned %08x", ret);
        return 1;
    }

    dns_packet_reader_read_dns_resource_record(&pr, rr);
    if(!dnsname_equals(yadifa_eu, rr->name))
    {
        yatest_err("fqdn doesn't match");
        return 1;
    }
    if(rr->tctr.rtype != TYPE_A)
    {
        yatest_err("rtype doesn't match");
        return 1;
    }
    if(rr->tctr.rclass != CLASS_IN)
    {
        yatest_err("rtype doesn't match");
        return 1;
    }
    if(rr->tctr.ttl != (int32_t)htonl(86400))
    {
        yatest_err("ttl doesn't match");
        return 1;
    }
    if(rr->rdata_size != sizeof(ipv4_0))
    {
        yatest_err("rdata_size doesn't match");
        return 1;
    }
    if(memcmp(rr->rdata, ipv4_0, sizeof(ipv4_0)) != 0)
    {
        yatest_err("rdata doesn't match");
        return 1;
    }

    dns_packet_writer_reader_add_read(yadifa_eu, TYPE_AAAA, CLASS_IN, 86400, sizeof(ipv6_0), ipv6_0);
    dns_packet_writer_reader_add_read(yadifa_eu, TYPE_NS, CLASS_IN, 86400, sizeof(ns1_yadifa_eu), ns1_yadifa_eu);
    dns_packet_writer_reader_add_read(yadifa_eu, TYPE_SOA, CLASS_IN, 86400, sizeof(soa_rdata), soa_rdata);
    dns_packet_writer_reader_add_read(yadifa_eu, TYPE_MX, CLASS_IN, 86400, sizeof(mx_rdata), mx_rdata);

    ret = dns_packet_writer_encode_base32hex_digest(&pw, sha1digest);
    if(FAIL(ret))
    {
        yatest_err("packet_writer_add_test: dns_packet_writer_encode_base32hex_digest returned %08x", ret);
        return 1;
    }

    dns_packet_writer_add_u16(&pw, TYPE_MX);
    dns_packet_writer_add_u16(&pw, CLASS_IN);
    dns_packet_writer_add_u32(&pw, htonl(86400));
    ret = dns_packet_writer_add_rdata(&pw, TYPE_MX, mx_rdata, sizeof(mx_rdata));
    if(FAIL(ret))
    {
        yatest_err("packet_writer_add_test: dns_packet_writer_add_rdata MX returned %08x", ret);
        return 1;
    }

    pr.packet_offset = pw.packet_offset;

    while(pw.packet_offset < 0x8000)
    {
        char    tmp[256];
        uint8_t fqdn[256];
        snprintf(tmp, sizeof(tmp), "ns%i.yadifa.eu.", pw.packet_offset);
        dnsname_init_with_cstr(fqdn, tmp);

        dns_packet_writer_reader_add_read(fqdn, TYPE_AAAA, CLASS_IN, 86400, sizeof(ipv6_0), ipv6_0);
    }

    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    ret = dns_packet_write_tcp(&pw, &baos);

    if(FAIL(ret))
    {
        yatest_err("dns_packet_writer_add_test: dns_packet_write_tcp returned %08x", ret);
        return 1;
    }

    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(dns_packet_writer_add_test)
YATEST_TABLE_END

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
#include "yatest_dns.h"
#include <dnscore/dnscore.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/bytearray_output_stream.h>

static const uint8_t       yadifa_eu[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t       www_yadifa_eu[] = {3, 'w', 'w', 'w', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t       ipv4_0[4] = {127, 0, 0, 1};
static const uint8_t       ipv4_1[4] = {127, 0, 0, 2};
static const uint8_t       ipv6_0[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t       ipv6_1[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
static const uint8_t       ns1_yadifa_eu[] = {3, 'n', 's', '1', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t       ns99_yadifa_eu[] = {4, 'n', 's', '9', '9', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t       mx_rdata[] = {0, 10, 4, 'm', 'a', 'i', 'l', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};

static yatest_dns_record_t rr_rrset[] = {{www_yadifa_eu, TYPE_A, CLASS_IN, 86400, sizeof(ipv4_0), ipv4_0},
                                         {www_yadifa_eu, TYPE_A, CLASS_IN, 86400, sizeof(ipv4_1), ipv4_1},
                                         {www_yadifa_eu, TYPE_AAAA, CLASS_IN, 86400, sizeof(ipv6_0), ipv6_0},
                                         {www_yadifa_eu, TYPE_AAAA, CLASS_IN, 86400, sizeof(ipv6_1), ipv6_1},
                                         {yadifa_eu, TYPE_NS, CLASS_IN, 86400, sizeof(ns1_yadifa_eu), ns1_yadifa_eu},
                                         {yadifa_eu, TYPE_NS, CLASS_IN, 86400, sizeof(ns99_yadifa_eu), ns99_yadifa_eu},
                                         {yadifa_eu, TYPE_MX, CLASS_IN, 86400, sizeof(mx_rdata), mx_rdata},
                                         {NULL, 0, 0, 0, 0, NULL}};

static int                 init_test()
{
    dnscore_init();

    int                    ret;
    dns_resource_record_t *rr = dns_resource_record_new_instance();
    for(int i = 0; rr_rrset[i].fqdn != NULL; ++i)
    {
        yatest_dns_record_t *yrr = &rr_rrset[i];
        ret = dns_resource_record_init_record(rr, yrr->fqdn, yrr->rtype, yrr->rclass, yrr->rttl, yrr->rdata_len, yrr->rdata);
        if(ret < 0)
        {
            yatest_err("dns_resource_record_init_record failed with %08 = %s", ret, error_gettext(ret));
            return 1;
        }
        if(rr->name_len != yatest_dns_name_len(yrr->fqdn))
        {
            yatest_err("rr->name_len has unexpected size = %i != %i", rr->name_len, yatest_dns_name_len(yrr->fqdn));
            return 1;
        }
        if(memcmp(rr->name, yrr->fqdn, rr->name_len) != 0)
        {
            yatest_err("rr->name value unexpected");
            return 1;
        }
        if(rr->tctr.rtype != yrr->rtype)
        {
            yatest_err("rr->tctr.qtype has unexpected value = %i != %i", rr->tctr.rtype, yrr->rtype);
            return 1;
        }
        if(rr->tctr.rclass != yrr->rclass)
        {
            yatest_err("rr->tctr.qclass has unexpected value = %i != %i", rr->tctr.rclass, yrr->rclass);
            return 1;
        }
        if((int32_t)ntohl(rr->tctr.ttl) != yrr->rttl)
        {
            yatest_err("rr->tctr.ttl has unexpected value = %i != %i", ntohl(rr->tctr.ttl), yrr->rttl);
            return 1;
        }
        if(ntohs(rr->tctr.rdlen) != yrr->rdata_len)
        {
            yatest_err("rr->tctr.rdlen has unexpected value = %i != %i", ntohs(rr->tctr.rdlen), yrr->rdata_len);
            return 1;
        }
        if(rr->rdata_size != yrr->rdata_len)
        {
            yatest_err("rr->rdata_size has unexpected value = %i != %i", rr->rdata_size, yrr->rdata_len);
            return 1;
        }
        if(memcmp(rr->rdata, yrr->rdata, rr->rdata_size) != 0)
        {
            yatest_err("rr->rdata value unexpected");
            return 1;
        }

        dns_resource_record_t *rr_copy = dns_resource_record_new_instance();

        if((i & 1) == 0)
        {
            dns_resource_init_from_record(rr_copy, rr);
        }
        else
        {
            dns_resource_set_from_record(rr_copy, rr);
        }

        if(!dns_resource_record_equals(rr_copy, rr))
        {
            yatest_err("dns_resource_record_equals returned false");
            return 1;
        }

        if(dns_resource_record_compare(rr_copy, rr) != 0)
        {
            yatest_err("dns_resource_record_compare didn't return 0");
            return 1;
        }

        if(ptr_treemap_dns_resource_record_node_compare(rr_copy, rr) != 0)
        {
            yatest_err("ptr_treemap_dns_resource_record_node_compare didn't return 0");
            return 1;
        }

        if(!dns_resource_record_match(rr_copy, rr))
        {
            yatest_err("dns_resource_record_match returned false");
            return 1;
        }

        rr_copy->tctr.ttl++;

        if(!dns_resource_record_match(rr_copy, rr))
        {
            yatest_err("dns_resource_record_match returned false (different TTL)");
            return 1;
        }

        rr_copy->tctr.rclass++;

        if(dns_resource_record_equals(rr_copy, rr))
        {
            yatest_err("dns_resource_record_equals returned true (different class)");
            return 1;
        }

        if(dns_resource_record_compare(rr_copy, rr) == 0)
        {
            yatest_err("dns_resource_record_compare returned 0 (different class)");
            return 1;
        }

        if(ptr_treemap_dns_resource_record_node_compare(rr_copy, rr) == 0)
        {
            yatest_err("ptr_treemap_dns_resource_record_node_compare returned 0 (different class)");
            return 1;
        }

        if(dns_resource_record_match(rr_copy, rr))
        {
            yatest_err("dns_resource_record_match returned true (different class)");
            return 1;
        }

        dns_resource_record_clear(rr_copy);

        output_stream_t os;
        input_stream_t  is;
        bytearray_output_stream_init(&os, NULL, 0);
        ret = dns_resource_record_write(rr, &os);
        if(ret < 0)
        {
            yatest_err("dns_resource_record_write failed with %08 = %s", ret, error_gettext(ret));
            return 1;
        }
        size_t      buffer_size = bytearray_output_stream_size(&os);
        const void *buffer = bytearray_output_stream_buffer(&os);
        bytearray_input_stream_init(&is, buffer, buffer_size, false);
        ret = dns_resource_record_read(rr_copy, &is);
        if(ret < 0)
        {
            yatest_err("dns_resource_record_read failed with %08 = %s", ret, error_gettext(ret));
            return 1;
        }

        if(!dns_resource_record_equals(rr_copy, rr))
        {
            yatest_err("dns_resource_record_equals returned false after write & read");
            return 1;
        }

        dns_resource_record_delete(rr_copy);

        dns_resource_record_clear(rr);
    }
    dns_resource_record_delete(rr);

    dnscore_finalize();

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(init_test)
YATEST_TABLE_END

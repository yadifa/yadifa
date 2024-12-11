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
#include "dnscore/format.h"
#include "dnscore/ctrl_rfc.h"
#include <dnscore/dnscore.h>
#include <dnscore/dnsformat.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/network.h>
#include <dnscore/host_address.h>
#include <dnscore/dns_resource_record.h>

// "digest32h"
// "dnsname"
// "dnsnamevector"
// "dnsnamestack"
// "dnslabel"
// "dnsclass"
// "dnstype"
// "sockaddr"
// "hostaddr"
// "hostaddrip"
// "hostaddrlist"
// "sockaddrip"
// "rdatadesc"
// "typerdatadesc"
// "recordwire"
// "dnsrr"
// "dnszrr"

static output_stream_t os;

static const uint8_t   yadifa_eu[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const uint8_t   www_yadifa_eu[] = {3, 'w', 'w', 'w', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const char     *www_yadifa_eu_txt = "www.yadifa.eu.";
static const char     *www_txt = "www";
static const uint8_t   mx_rdata[] = {0, 10, 4, 'm', 'a', 'i', 'l', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const char     *mx_rdata_txt = "10 mail.yadifa.eu.";
static const char     *mx_type_rdata_txt = "MX 10 mail.yadifa.eu.";
static const uint8_t   yadifa_mx_wire[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0, 0, 15, 0, 1, 0, 0, 0, 0, 0, 18, 0, 10, 4, 'm', 'a', 'i', 'l', 6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};
static const char     *yadifa_mx_wire_txt = "yadifa.eu. IN MX 10 mail.yadifa.eu.";
static const char     *yadifa_dnsrr_txt = "yadifa.eu. MX 10 mail.yadifa.eu.";
static const char     *yadifa_dnszrr_txt = "yadifa.eu.     0 MX 10 mail.yadifa.eu.";

static void            init()
{
    dnscore_init();
    netformat_class_init();
    dnsformat_class_init();

    bytearray_output_stream_init(&os, NULL, 0);
}

static void finalise() { dnscore_finalize(); }

static int  digest32h_test()
{
    static yatest_kstr_vstr_t digest32h_table[] = {{"\0011", "64======"},
                                                   {"\00212", "64P0===="},
                                                   {"\003123", "64P36==="},
                                                   {"\0041234", "64P36D0="},
                                                   {"\00512345", "64P36D1L"},
                                                   {"\006123456", "64P36D1L6O======"},
                                                   {"\024123456789abcdefghijl", "64P36D1L6ORJGEB1C9HM8PB6CTK6IQJC"},
                                                   {NULL, NULL}};
    init();
    for(int i = 0; digest32h_table[i].key != NULL; ++i)
    {
        bytearray_output_stream_reset(&os);
        osformat(&os, "%{digest32h}", digest32h_table[i].key);
        format("[%i]  '%s' => '", digest32h_table[i].key[0], digest32h_table[i].key + 1);
        output_stream_write(termout, bytearray_output_stream_buffer(&os), bytearray_output_stream_size(&os));
        println("'");
        if((bytearray_output_stream_size(&os) != strlen(digest32h_table[i].value)) || (memcmp(bytearray_output_stream_buffer(&os), digest32h_table[i].value, bytearray_output_stream_size(&os)) != 0))
        {
            yatest_err("digest32h: unexpected value at index %i", i);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int dnsname_test()
{
    init();
    bytearray_output_stream_reset(&os);
    osformat(&os, "%{dnsname}", www_yadifa_eu);
    if((bytearray_output_stream_size(&os) != strlen(www_yadifa_eu_txt)) || (memcmp(bytearray_output_stream_buffer(&os), www_yadifa_eu_txt, bytearray_output_stream_size(&os)) != 0))
    {
        yatest_err("dnsname: unexpected value (got, expected)");
        yatest_hexdump(bytearray_output_stream_buffer(&os), bytearray_output_stream_buffer(&os) + bytearray_output_stream_size(&os));
        yatest_hexdump(www_yadifa_eu_txt, www_yadifa_eu_txt + strlen(www_yadifa_eu_txt));
        return 1;
    }
    finalise();
    return 0;
}

static int dnsnamevector_test()
{
    init();
    dnsname_vector_t v;
    dnsname_to_dnsname_vector(www_yadifa_eu, &v);
    bytearray_output_stream_reset(&os);
    osformat(&os, "%{dnsnamevector}", &v);
    if((bytearray_output_stream_size(&os) != strlen(www_yadifa_eu_txt)) || (memcmp(bytearray_output_stream_buffer(&os), www_yadifa_eu_txt, bytearray_output_stream_size(&os)) != 0))
    {
        yatest_err("dnsnamevector: unexpected value (got, expected)");
        yatest_hexdump(bytearray_output_stream_buffer(&os), bytearray_output_stream_buffer(&os) + bytearray_output_stream_size(&os));
        yatest_hexdump(www_yadifa_eu_txt, www_yadifa_eu_txt + strlen(www_yadifa_eu_txt));
        return 1;
    }
    finalise();
    return 0;
}

static int dnsnamestack_test()
{
    init();
    dnsname_stack_t v;
    dnsname_to_dnsname_stack(www_yadifa_eu, &v);
    bytearray_output_stream_reset(&os);
    osformat(&os, "%{dnsnamestack}", &v);
    if((bytearray_output_stream_size(&os) != strlen(www_yadifa_eu_txt)) || (memcmp(bytearray_output_stream_buffer(&os), www_yadifa_eu_txt, bytearray_output_stream_size(&os)) != 0))
    {
        yatest_err("dnsnamestack: unexpected value (got, expected)");
        yatest_hexdump(bytearray_output_stream_buffer(&os), bytearray_output_stream_buffer(&os) + bytearray_output_stream_size(&os));
        yatest_hexdump(www_yadifa_eu_txt, www_yadifa_eu_txt + strlen(www_yadifa_eu_txt));
        return 1;
    }
    finalise();
    return 0;
}

static int dnslabel_test()
{
    init();
    bytearray_output_stream_reset(&os);
    osformat(&os, "%{dnslabel}", www_yadifa_eu);
    if((bytearray_output_stream_size(&os) != strlen(www_txt)) || (memcmp(bytearray_output_stream_buffer(&os), www_txt, bytearray_output_stream_size(&os)) != 0))
    {
        yatest_err("dnslabel: unexpected value (got, expected)");
        yatest_hexdump(bytearray_output_stream_buffer(&os), bytearray_output_stream_buffer(&os) + bytearray_output_stream_size(&os));
        yatest_hexdump(www_txt, www_txt + strlen(www_txt));
        return 1;
    }
    finalise();
    return 0;
}

static int dnsclass_test()
{
    init();
    static const uint16_t classes[] = {
        CLASS_IN,
        CLASS_CH,
        CLASS_HS,
        CLASS_CTRL,
#if HAS_WHOIS
        CLASS_WHOIS,
#endif
        CLASS_NONE,
        CLASS_ANY,
        NU16(0x1234),
        0xffff,
    };

    char tmp_name[64];

    for(int i = 0; classes[i] != 0xffff; ++i)
    {
        bytearray_output_stream_reset(&os);
        osformat(&os, "%{dnsclass}", &classes[i]);
        output_stream_write_u8(&os, 0);

        const char *expected_name = dns_class_get_name(classes[i]);
        if(expected_name == NULL)
        {
            snprintf(tmp_name, sizeof(tmp_name), "CLASS%i", ntohs(classes[i]));
            expected_name = tmp_name;
        }

        formatln("class #%i = %{dnsclass} (%s)", i, &classes[i], expected_name);

        if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected_name) != 0)
        {
            yatest_err("dnsclass: unexpected value for class %s", expected_name);
            return 1;
        }
    }

    finalise();
    return 0;
}

static int dnstype_test()
{
    init();
    static const uint16_t types[] = {
        TYPE_A,
        TYPE_NS,
        TYPE_MD,
        TYPE_MF,
        TYPE_CNAME,
        TYPE_SOA,
        TYPE_MB,
        TYPE_MG,
        TYPE_MR,
        TYPE_NULL,
        TYPE_WKS,
        TYPE_PTR,
        TYPE_HINFO,
        TYPE_MINFO,
        TYPE_MX,
        TYPE_TXT,
        TYPE_RP,
        TYPE_AFSDB,
        TYPE_X25,
        TYPE_ISDN,
        TYPE_RT,
        TYPE_NSAP,
        TYPE_NSAP_PTR,
        TYPE_SIG,
        TYPE_KEY,
        TYPE_PX,
        TYPE_GPOS,
        TYPE_AAAA,
        TYPE_LOC,
        TYPE_NXT,
        TYPE_EID,
        TYPE_NIMLOC,
        TYPE_SRV,
        TYPE_ATMA,
        TYPE_NAPTR,
        TYPE_KX,
        TYPE_CERT,
        TYPE_A6,
        TYPE_DNAME,
        TYPE_SINK,
        TYPE_OPT,
        TYPE_APL,
        TYPE_DS,
        TYPE_SSHFP,
        TYPE_IPSECKEY,
        TYPE_RRSIG,
        TYPE_NSEC,
        TYPE_DNSKEY,
        TYPE_DHCID,
        TYPE_NSEC3,
        TYPE_NSEC3PARAM,
        TYPE_TLSA,
        TYPE_HIP,
        TYPE_NINFO,
        TYPE_RKEY,
        TYPE_TALINK,
        TYPE_CDS,
        TYPE_CDNSKEY,
        TYPE_OPENPGPKEY,
        TYPE_SPF,
        TYPE_UINFO,
        TYPE_UID,
        TYPE_GID,
        TYPE_UNSPEC,
        TYPE_NID,
        TYPE_L32,
        TYPE_L64,
        TYPE_LP,
        TYPE_EUI48,
        TYPE_EUI64,
        TYPE_TKEY,
        TYPE_TSIG,
        TYPE_IXFR,
        TYPE_AXFR,
        TYPE_MAILB,
        TYPE_MAILA,
        TYPE_ANY,
        TYPE_URI,
        TYPE_CAA,
        TYPE_AVC,
        TYPE_TA,
        TYPE_DLV,
#if DNSCORE_HAS_CTRL
        TYPE_CTRL_SRVCFGRELOAD,
        TYPE_CTRL_SRVLOGREOPEN,
        TYPE_CTRL_SRVLOGLEVEL,
        TYPE_CTRL_SRVSHUTDOWN,
        TYPE_CTRL_SRVQUERYLOG,
        TYPE_CTRL_ZONECFGRELOAD,
        TYPE_CTRL_ZONECFGRELOADALL,
        TYPE_CTRL_ZONEFREEZE,
        TYPE_CTRL_ZONEUNFREEZE,
        TYPE_CTRL_ZONERELOAD,
        TYPE_CTRL_ZONEFREEZEALL,
        TYPE_CTRL_ZONEUNFREEZEALL,
        TYPE_CTRL_ZONESYNC,
        TYPE_CTRL_ZONENOTIFY,
#endif
        NU16(0x1234),
        0xffff,
    };

    char tmp_name[64];

    for(int i = 0; types[i] != 0xffff; ++i)
    {
        bytearray_output_stream_reset(&os);
        osformat(&os, "%{dnstype}", &types[i]);
        output_stream_write_u8(&os, 0);
        const char *expected_name = dns_type_get_name(types[i]);
        if(expected_name == NULL)
        {
            snprintf(tmp_name, sizeof(tmp_name), "TYPE%i", ntohs(types[i]));
            expected_name = tmp_name;
        }

        formatln("type #%i = %{dnstype} (%s)", i, &types[i], expected_name);

        if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected_name) != 0)
        {
            yatest_err("dnstype: unexpected value for type %s", expected_name);
            return 1;
        }
    }

    finalise();
    return 0;
}

static int sockaddr_test()
{
    init();
    char               ip_port[64];
    static const char *ips[] = {"127.0.0.1", "::1", NULL};

    for(int i = 0; ips[i] != NULL; ++i)
    {
        const char      *ip = ips[i];
        int              port = 53;
        struct sockaddr *sa = NULL;
        host_address_t  *ha = host_address_new_instance_parse(ip);
        if(ha == NULL)
        {
            yatest_err("sockaddr: internal error");
            return 1;
        }
        ha->port = htons(port);
        host_address2allocated_sockaddr(ha, &sa);
        bytearray_output_stream_reset(&os);
        osformat(&os, "%{sockaddr}", sa);
        output_stream_write_u8(&os, 0);
        snprintf(ip_port, sizeof(ip_port), "%s#%i", ip, port);
        formatln("sockaddr: %s", ip_port);
        if(strcmp((const char *)bytearray_output_stream_buffer(&os), ip_port) != 0)
        {
            yatest_err("sockaddr: failed with '%s' != '%s'", bytearray_output_stream_buffer(&os), ip_port);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int sockaddrip_test()
{
    init();
    char               ip_port[64];
    static const char *ips[] = {"127.0.0.1", "::1", NULL};

    for(int i = 0; ips[i] != NULL; ++i)
    {
        const char      *ip = ips[i];
        int              port = 53;
        struct sockaddr *sa = NULL;
        host_address_t  *ha = host_address_new_instance_parse(ip);
        if(ha == NULL)
        {
            yatest_err("sockaddrip: internal error");
            return 1;
        }
        ha->port = htons(port);
        host_address2allocated_sockaddr(ha, &sa);
        bytearray_output_stream_reset(&os);
        osformat(&os, "%{sockaddrip}", sa);
        output_stream_write_u8(&os, 0);
        snprintf(ip_port, sizeof(ip_port), "%s", ip);
        formatln("sockaddrip: %s", ip_port);
        if(strcmp((const char *)bytearray_output_stream_buffer(&os), ip_port) != 0)
        {
            yatest_err("sockaddrip: failed with '%s' != '%s'", bytearray_output_stream_buffer(&os), ip_port);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int hostaddr_test()
{
    init();
    char               ip_port[64];
    static const char *ips[] = {"127.0.0.1", "::1", "www.yadifa.eu.", NULL};

    for(int i = 0; ips[i] != NULL; ++i)
    {
        const char     *ip = ips[i];
        int             port = 53;
        host_address_t *ha = host_address_new_instance_parse(ip);
        if(ha == NULL)
        {
            yatest_err("hostaddr: internal error");
            return 1;
        }
        ha->port = htons(port);
        bytearray_output_stream_reset(&os);
        osformat(&os, "%{hostaddr}", ha);
        output_stream_write_u8(&os, 0);
        snprintf(ip_port, sizeof(ip_port), "%s#%i", ip, port);
        formatln("hostaddr: %s", ip_port);
        if(strcmp((const char *)bytearray_output_stream_buffer(&os), ip_port) != 0)
        {
            yatest_err("hostaddr: failed with '%s' != '%s'", bytearray_output_stream_buffer(&os), ip_port);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int hostaddrip_test()
{
    init();
    char               ip_without_port[64];
    static const char *ips[] = {"127.0.0.1", "::1", "www.yadifa.eu.", NULL};

    for(int i = 0; ips[i] != NULL; ++i)
    {
        const char     *ip = ips[i];
        int             port = 53;
        host_address_t *ha = host_address_new_instance_parse(ip);
        if(ha == NULL)
        {
            yatest_err("hostaddrip: internal error");
            return 1;
        }
        ha->port = htons(port);
        bytearray_output_stream_reset(&os);
        osformat(&os, "%{hostaddrip}", ha);
        output_stream_write_u8(&os, 0);
        snprintf(ip_without_port, sizeof(ip_without_port), "%s", ip);
        formatln("hostaddrip: %s", ip_without_port);
        if(strcmp((const char *)bytearray_output_stream_buffer(&os), ip_without_port) != 0)
        {
            yatest_err("hostaddrip: failed with '%s' != '%s'", bytearray_output_stream_buffer(&os), ip_without_port);
            return 1;
        }
    }
    finalise();
    return 0;
}

static int hostaddrlist_test()
{
    init();
    char               ip_port[64];
    static const char *ips[] = {"127.0.0.1", "::1", "www.yadifa.eu.", NULL};

    host_address_t    *ha = NULL;

    for(int i = 0; ips[i] != NULL; ++i)
    {
        const char     *ip = ips[i];
        int             port = 53;
        host_address_t *ha_item = host_address_new_instance_parse(ip);
        if(ha_item == NULL)
        {
            yatest_err("hostaddrlist: internal error");
            return 1;
        }
        ha_item->port = htons(port);

        if(ha == NULL)
        {
            ha = ha_item;
        }
        else
        {
            host_address_append_host_address(ha, ha_item);
        }
    }

    static const char *ip_list = "127.0.0.1 port 53,::1 port 53,www.yadifa.eu. port 53";

    bytearray_output_stream_reset(&os);
    osformat(&os, "%{hostaddrlist}", ha);
    output_stream_write_u8(&os, 0);
    snprintf(ip_port, sizeof(ip_port), "%s", ip_list);
    formatln("hostaddrlist: %s", ip_port);
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), ip_port) != 0)
    {
        yatest_err("hostaddrlist: failed with '%s' != '%s'", bytearray_output_stream_buffer(&os), ip_list);
        return 1;
    }

    finalise();
    return 0;
}

static int rdatadesc_test()
{
    init();
    bytearray_output_stream_reset(&os);
    rdata_desc_t mx_rdata_desc = {TYPE_MX, sizeof(mx_rdata), mx_rdata};
    osformat(&os, "%{rdatadesc}", &mx_rdata_desc);
    output_stream_write_u8(&os, 0);
    println((const char *)bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), mx_rdata_txt) != 0)
    {
        yatest_err("rdatadesc: value mismatch: '%s' != '%s'", bytearray_output_stream_buffer(&os), mx_rdata_txt);
        return 1;
    }
    finalise();
    return 0;
}

static int typerdatadesc_test()
{
    init();
    bytearray_output_stream_reset(&os);
    rdata_desc_t mx_rdata_desc = {TYPE_MX, sizeof(mx_rdata), mx_rdata};
    osformat(&os, "%{typerdatadesc}", &mx_rdata_desc);
    output_stream_write_u8(&os, 0);
    println((const char *)bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), mx_type_rdata_txt) != 0)
    {
        yatest_err("typerdatadesc: value mismatch: '%s' != '%s'", bytearray_output_stream_buffer(&os), mx_type_rdata_txt);
        return 1;
    }
    finalise();
    return 0;
}

static int recordwire_test()
{
    init();
    bytearray_output_stream_reset(&os);
    osformat(&os, "%{recordwire}", &yadifa_mx_wire);
    output_stream_write_u8(&os, 0);
    println((const char *)bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), yadifa_mx_wire_txt) != 0)
    {
        yatest_err("recordwire: value mismatch: '%s' != '%s'", bytearray_output_stream_buffer(&os), yadifa_mx_wire_txt);
        return 1;
    }
    finalise();
    return 0;
}

static int dnsrr_test()
{
    init();
    dns_resource_record_t *rr = dns_resource_record_new_instance();
    dns_resource_record_init_record(rr, yadifa_eu, TYPE_MX, CLASS_IN, 0, sizeof(mx_rdata), mx_rdata);
    bytearray_output_stream_reset(&os);
    osformat(&os, "%{dnsrr}", rr);
    output_stream_write_u8(&os, 0);
    println((const char *)bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), yadifa_dnsrr_txt) != 0)
    {
        yatest_err("dnsrr: value mismatch: '%s' != '%s'", bytearray_output_stream_buffer(&os), yadifa_dnsrr_txt);
        return 1;
    }
    finalise();
    return 0;
}

static int dnszrr_test()
{
    init();
    dns_resource_record_t *rr = dns_resource_record_new_instance();
    dns_resource_record_init_record(rr, yadifa_eu, TYPE_MX, CLASS_IN, 0, sizeof(mx_rdata), mx_rdata);
    bytearray_output_stream_reset(&os);
    osformat(&os, "%{dnszrr}", rr);
    output_stream_write_u8(&os, 0);
    println((const char *)bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), yadifa_dnszrr_txt) != 0)
    {
        yatest_err("dnszrr: value mismatch: '%s' != '%s'", bytearray_output_stream_buffer(&os), yadifa_dnszrr_txt);
        return 1;
    }
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(digest32h_test)
YATEST(dnsname_test)
YATEST(dnsnamevector_test)
YATEST(dnsnamestack_test)
YATEST(dnslabel_test)
YATEST(dnsclass_test)
YATEST(dnstype_test)
YATEST(sockaddr_test)
YATEST(sockaddrip_test)
YATEST(hostaddr_test)
YATEST(hostaddrip_test)
YATEST(hostaddrlist_test)
YATEST(rdatadesc_test)
YATEST(typerdatadesc_test)
YATEST(recordwire_test)
YATEST(dnsrr_test)
YATEST(dnszrr_test)
YATEST_TABLE_END

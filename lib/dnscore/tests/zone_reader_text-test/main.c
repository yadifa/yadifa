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
#include "dnscore/parser.h"

#include <dnscore/dnscore.h>
#include <dnscore/zone_reader_text.h>

#define ZONE_FILE_NAME         "/tmp/dnscore-zone_reader_text-test.zone"
#define ZONE_INCLUDE_FILE_NAME "/tmp/dnscore-zone_reader_text-test.inc"

static const char zone_file[] =
    "$ORIGIN example.\n"
    "$TTL 3600\n"
    "@ 86400 IN SOA ns2.example. hostmaster.example. 1397051952 5 5 1814400 3600\n"
    " 3600 NS ns2.example.\n"
    " 3600 IN NS ns3.example.\n"
    "a01.example.            3600    IN      A       0.0.0.0\n"
    "a02.example.            3600    IN      A       255.255.255.255\n"
    "aaaa01.example.         3600    IN      AAAA    ::1\n"
    "aaaa02.example.         3600    IN      AAAA    fd92:7065:b8e:ffff::5\n"
    "afsdb01.example.        3600    IN      AFSDB   0 hostname.example.\n"
    "afsdb02.example.        3600    IN      AFSDB   65535 .\n"
    "caa01.example.          3600    IN      CAA     0 issue \"ca.example.net; policy=ev\"\n"
    "caa02.example.          3600    IN      CAA     128 tbs \"Unknown\"\n"
    "caa03                   3600    IN      CAA     128 tbs \"\"\n"
    "cdnskey01.example.      3600    IN      CDNSKEY 512 255 1 "
    "AQMFD5raczCJHViKtLYhWGz8hMY9UGRuniJDBzC7w0aRyzWZriO6i2od GWWQVucZqKVsENW91IOW4vqudngPZsY3GvQ/xVA8/7pyFj6b7Esga60z "
    "yGW6LFe9r8n6paHrlG5ojqf0BaqHT+8=\n"
    "cds01.example.          3600    IN      CDS     30795 1 1 310D27F4D82C1FC2400704EA9939FE6E1CEAA3B9\n"
    "cert01.example.         3600    IN      CERT    65534 65535 PRIVATEOID "
    "MxFcby9k/yvedMfQgKzhH5er0Mu/vILz45IkskceFGgiWCn/GxHhai6V AuHAoNUz4YoU1tVfSCSqQYn6//11U6Nld80jEeC8aTrO+KKmCaY=\n"
    "cname01.example.        3600    IN      CNAME   cname-target.\n"
    "cname02.example.        3600    IN      CNAME   cname-target.example.\n"
    "cname03.example.        3600    IN      CNAME   .\n"
    "csync01.example.        3600    IN      CSYNC   0 0 A NS AAAA\n"
    "csync02.example.        3600    IN      CSYNC   0 0\n"
    "dlv.example.            3600    IN      DLV     30795 1 1 310D27F4D82C1FC2400704EA9939FE6E1CEAA3B9\n"
    "dnskey01.example.       3600    IN      DNSKEY  512 255 1 "
    "AQMFD5raczCJHViKtLYhWGz8hMY9UGRuniJDBzC7w0aRyzWZriO6i2od GWWQVucZqKVsENW91IOW4vqudngPZsY3GvQ/xVA8/7pyFj6b7Esga60z "
    "yGW6LFe9r8n6paHrlG5ojqf0BaqHT+8=\n"
    "ds01.example.           3600    IN      DS      12892 5 2 "
    "26584835CA80C81C91999F31CFAF2A0E89D4FF1C8FAFD0DDB31A85C7 19277C13\n"
    "ds01.example.           3600    IN      NS      ns42.example.\n"
    "ds02.example.           3600    IN      DS      12892 5 1 7AA4A3F416C2F2391FB7AB0D434F762CD62D1390\n"
    "ds02.example.           3600    IN      NS      ns43.example.\n"
    "eui48.example.          3600    IN      EUI48   01-23-45-67-89-ab\n"
    "eui64.example.          3600    IN      EUI64   01-23-45-67-89-ab-cd-ef\n"
    "gid01.example.          3600    IN      GID     \\# 1 03\n"
    "hinfo01.example.        3600    IN      HINFO   \"Generic PC clone\" \"NetBSD-1.4\"\n"
    "hinfo02.example.        3600    IN      HINFO   \"PC\" \"NetBSD\"\n"
    "keydata.example.        3600    IN      TYPE65533 \\# 0\n"
    "keydata.example.        3600    IN      TYPE65533 \\# 6 010203040506\n"
    "keydata.example.        3600    IN      TYPE65533 \\# 18 010203040506010203040506010203040506\n"
    "l32.example.            3600    IN      L32     10 1.2.3.4\n"
    "l64.example.            3600    IN      L64     10 14:4fff:ff20:ee64\n"
    "lp.example.             3600    IN      LP      10 example.net.\n"
    "mb01.example.           3600    IN      MG      madname.example.\n"
    "mb02.example.           3600    IN      MG      .\n"
    "mg01.example.           3600    IN      MG      mgmname.example.\n"
    "mg02.example.           3600    IN      MG      .\n"
    "mr01.example.           3600    IN      MR      mrname.example.\n"
    "mr02.example.           3600    IN      MR      .\n"
    "mx01.example.           3600    IN      MX      10 mail.example.\n"
    "mx02.example.           3600    IN      MX      10 .\n"
    "nid.example.            3600    IN      NID     10 14:4fff:ff20:ee64\n"
    "ns2.example.            3600    IN      A       10.53.0.2\n"
    "ns3.example.            3600    IN      A       10.53.0.3\n"
    "nsec01.example.         3600    IN      NSEC    a.secure.nil. NS SOA MX LOC RRSIG NSEC DNSKEY\n"
    "nsec02.example.         3600    IN      NSEC    . NSAP-PTR NSEC\n"
    "nsec03.example.         3600    IN      NSEC    . A\n"
    "nsec04.example.         3600    IN      NSEC    . TYPE127\n"
    "openpgpkey.example.     3600    IN      OPENPGPKEY AQMFD5raczCJHViKtLYhWGz8hMY9UGRuniJDBzC7w0aRyzWZriO6i2od "
    "GWWQVucZqKVsENW91IOW4vqudngPZsY3GvQ/xVA8/7pyFj6b7Esga60z yGW6LFe9r8n6paHrlG5ojqf0BaqHT+8=\n"
    "ptr01.example.          3600    IN      PTR     example.\n"
    "rp01.example.           3600    IN      RP      mbox-dname.example. txt-dname.example.\n"
    "rp02.example.           3600    IN      RP      . .\n"
    "rrsig01.example.        3600    IN      RRSIG   NSEC 1 3 3600 20000102030405 19961211100908 2143 foo.nil. "
    "MxFcby9k/yvedMfQgKzhH5er0Mu/vILz45IkskceFGgiWCn/GxHhai6V AuHAoNUz4YoU1tVfSCSqQYn6//11U6Nld80jEeC8aTrO+KKmCaY=\n"
    "spf01.example.          3600    IN      SPF     \"v=spf1 -all\"\n"
    "spf02.example.          3600    IN      SPF     \"v=spf1\" \" -all\"\n"
    "srv01.example.          3600    IN      SRV     0 0 0 .\n"
    "srv02.example.          3600    IN      SRV     65535 65535 65535 old-slow-box.example.\n"
    "sshfp01.example.        3600    IN      SSHFP   4 2 C76D8329954DA2835751E371544E963EFDA099080D6C58DD2BFD9A31 "
    "6E162C83\n"
    "sshfp02.example.        3600    IN      SSHFP   1 2 BF29468C83AC58CCF8C85AB7B3BEB054ECF1E38512B8353AB36471FA "
    "88961DCC\n"
    "txt01.example.          3600    IN      TXT     \"foo\"\n"
    "txt02.example.          3600    IN      TXT     \"foo\" \"bar\"\n"
    "txt03.example.          3600    IN      TXT     \"foo\"\n"
    "txt04.example.          3600    IN      TXT     \"foo\" \"bar\"\n"
    "txt05.example.          3600    IN      TXT     \"foo bar\"\n"
    "txt06.example.          3600    IN      TXT     \"foo bar\"\n"
    "txt07.example.          3600    IN      TXT     \"foo bar\"\n"
    "txt08.example.          3600    IN      TXT     \"foo\\010bar\"\n"
    "txt09.example.          3600    IN      TXT     \"foo\\010bar\"\n"
    "txt10.example.          3600    IN      TXT     \"foo bar\"\n"
    "txt11.example.          3600    IN      TXT     \"\\\"foo\\\"\"\n"
    "txt12.example.          3600    IN      TXT     \"\\\"foo\\\"\"\n"
    "txt13.example.          3600    IN      TXT     \"foo;\"\n"
    "txt14.example.          3600    IN      TXT     \"foo;\"\n"
    "txt15.example.          3600    IN      TXT     \"bar\\\\;\"\n"
    "uid01.example.          3600    IN      UID     \\# 1 02\n"
    "uinfo01.example.        3600    IN      UINFO   \\# 1 01\n"
    "unspec01.example.       3600    IN      UNSPEC  \\# 1 04\n"
    "wks01.example.          3600    IN      WKS     10.0.0.1 6 0 1 2 21 23\n"
    "wks02.example.          3600    IN      WKS     10.0.0.1 17 0 1 2 53\n"
    "wks03.example.          3600    IN      WKS     10.0.0.2 6 7 8\n"
    "nsec3param 0 NSEC3PARAM 1 0 0 -\n"
    "dhcid DHCID AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=\n"
    "naptr NAPTR 100  100  \"s\"   \"http+I2R\"   \"\"    _http._tcp.foo.com.\n"
    "tlsa TLSA 3 1 1 EFDDF0D915C7BDC5782C0881E1B2A95AD099FBDD06D7B1F77982D9364338D955\n"
    "8f1tmio9avcom2k0frp92lgcumak0cad.example. 3600 IN NSEC3 1 0 10 D2CF0294C020CE6C 8FPNS2UCT7FBS643THP2B77PEQ77K6IU "
    "A NS SOA MX AAAA RRSIG DNSKEY NSEC3PARAM\n"
    "kcd3juae64f9c5csl1kif1htaui7un0g.example. 3600 IN NSEC3 1 0 10 D2CF0294C020CE6C KD5MN2M20340DGO0BL7NTSB8JP4BSC7E\n"
    "mr5ukvsk1l37btu4q7b1dfevft4hkqdk.example. 3600 IN NSEC3 1 0 10 D2CF0294C020CE6C MT38J6VG7S0SN5G17MCUF6IQIKFUAJ05 "
    "A AAAA RRSIG\n"
    "\n"
    "$INCLUDE " ZONE_INCLUDE_FILE_NAME
    "\n"
    "\n";

static const char zone_file_include[] =
    ";\n"
    "; nothing to see here\n"
    ";\n"
    //"$GENERATE ?\n"
    //"$CLASS IN\n"
    "$RETURN\n"
    "\n";

static int file_reader_test()
{
    int ret;
    yatest_file_create_with(ZONE_FILE_NAME, zone_file, sizeof(zone_file) - 1);
    yatest_file_create_with(ZONE_INCLUDE_FILE_NAME, zone_file_include, sizeof(zone_file_include) - 1);
    dnscore_init();
    zone_reader_t zr;
    ret = zone_reader_text_open(&zr, ZONE_FILE_NAME);
    if(ret < 0)
    {
        yatest_err("zone_reader_text_open failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    zone_reader_text_set_origin(&zr, (const uint8_t *)"\007example");
    if(!zone_reader_canwriteback(&zr))
    {
        yatest_err("zone_reader_canwriteback returned false");
        return 1;
    }

    resource_record_t rr;
    resource_record_init(&rr);

    bool soa_replaying = false;
    bool soa_replayed = false;

    for(;;)
    {
        ret = zone_reader_read_record(&zr, &rr);
        if(ret <= 0)
        {
            if(ret == 0)
            {
                break;
            }

            if(ret == ZONEFILE_FEATURE_NOT_SUPPORTED)
            {
                continue;
            }

            yatest_err("zone_reader_read_record returned %08x = %s", ret, error_gettext(ret));
            yatest_err("last error message: '%s'", STRNULL(zone_reader_get_last_error_message(&zr)));
            return 1;
        }
        yatest_log("parsed %s type record", dns_type_get_name(rr.type));

        if(!soa_replayed)
        {
            if(rr.type == TYPE_SOA)
            {
                zone_reader_unread_record(&zr, &rr);
                soa_replaying = true;
                soa_replayed = true;
            }
        }
        else if(soa_replaying)
        {
            if(rr.type != TYPE_SOA)
            {
                yatest_err("replay failed");
                return 1;
            }
            soa_replaying = false;
        }

        resource_record_resetcontent(&rr);
    }
    resource_record_freecontent(&rr);

    yatest_log("last error message: '%s'", STRNULL(zone_reader_get_last_error_message(&zr)));

    zone_reader_text_ignore_missing_soa(&zr); // just because it's only a flag
    zone_reader_free_record(&zr, &rr);
    zone_reader_close(&zr);

    dnscore_finalize();
    return 0;
}

static int stream_reader_test()
{
    int ret;
    yatest_file_create_with(ZONE_INCLUDE_FILE_NAME, zone_file_include, sizeof(zone_file_include) - 1);
    dnscore_init();
    input_stream_t bais;
    bytearray_input_stream_init(&bais, zone_file, sizeof(zone_file) - 1, false);
    zone_reader_t zr;
    ret = zone_reader_text_parse_stream(&zr, &bais); // will close the stream
    if(ret < 0)
    {
        yatest_err("zone_reader_text_open failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    zone_reader_text_set_origin(&zr, (const uint8_t *)"\007example");
    if(!zone_reader_canwriteback(&zr))
    {
        yatest_err("zone_reader_canwriteback returned false");
        return 1;
    }

    resource_record_t rr;
    resource_record_init(&rr);

    for(;;)
    {
        ret = zone_reader_read_record(&zr, &rr);
        if(ret <= 0)
        {
            if(ret == 0)
            {
                break;
            }

            yatest_err("zone_reader_read_record returned %08x = %s", ret, error_gettext(ret));
            return 1;
        }
        yatest_log("parsed %s type record", dns_type_get_name(rr.type));
#if 0
        // Used to generate input for zone_reader_axfr-test

        uint8_t wire[16384];
        uint8_t *p = wire;
        memcpy(p, rr.name, dnsname_len(rr.name));
        p += dnsname_len(rr.name);
        SET_U16_AT_P(p, rr.type);
        p += 2;
        SET_U16_AT_P(p, rr.class);
        p += 2;
        SET_U16_AT_P(p, ntohl(rr.ttl));
        p += 4;
        SET_U16_AT_P(p, ntohs(rr.rdata_size));
        p += 2;
        memcpy(p, rr.rdata, rr.rdata_size);
        p += rr.rdata_size;
        int column = 0;

        printf("// %s\n", dns_type_get_name(rr.type));
        for(uint8_t *q = wire; q < p; ++q)
        {
            printf("0x%02x, ", *q);
            if(++column == 19)
            {
                puts("");
                column = 0;
            }
        }
        puts("");
#endif
        resource_record_resetcontent(&rr);
    }

    zone_reader_unread_record(&zr, &rr);

    resource_record_freecontent(&rr);

    yatest_log("last error message: '%s'", STRNULL(zone_reader_get_last_error_message(&zr)));

    zone_reader_free_record(&zr, &rr);
    zone_reader_close(&zr);

    dnscore_finalize();
    return 0;
}

static int zone_reader_text_copy_rdata_test()
{
    int           ret;
    uint8_t       a_rdata[4] = {0, 0, 0, 0};
    const uint8_t localhost_rdata[4] = {127, 0, 0, 1};
    dnscore_init();
    ret = zone_reader_text_copy_rdata("127.0.0.1", TYPE_A, a_rdata, sizeof(a_rdata), (const uint8_t *)"\011localhost");
    if(ret != 4)
    {
        yatest_err("zone_reader_text_copy_rdata expected to return 4, got %i = %08x", ret, ret);
        return 1;
    }
    if(memcmp(a_rdata, localhost_rdata, 4) != 0)
    {
        yatest_err("rdata content doesn't match got/expected");
        yatest_hexdump_err(a_rdata, a_rdata + 4);
        yatest_hexdump_err(localhost_rdata, localhost_rdata + 4);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int zone_reader_text_len_copy_rdata_test()
{
    int           ret;
    uint8_t       a_rdata[4] = {0, 0, 0, 0};
    const uint8_t localhost_rdata[4] = {127, 0, 0, 1};
    dnscore_init();
    char input[] = "127.0.0.1";
    ret = zone_reader_text_len_copy_rdata(input, sizeof(input) - 1, TYPE_A, a_rdata, sizeof(a_rdata), (const uint8_t *)"\011localhost");
    if(ret != 4)
    {
        yatest_err("zone_reader_text_copy_rdata expected to return 4, got %i = %08x", ret, ret);
        return 1;
    }
    if(memcmp(a_rdata, localhost_rdata, 4) != 0)
    {
        yatest_err("rdata content doesn't match got/expected");
        yatest_hexdump_err(a_rdata, a_rdata + 4);
        yatest_hexdump_err(localhost_rdata, localhost_rdata + 4);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(file_reader_test)
YATEST(stream_reader_test)
YATEST(zone_reader_text_copy_rdata_test)
YATEST(zone_reader_text_len_copy_rdata_test)
YATEST_TABLE_END

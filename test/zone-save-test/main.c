/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
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
 *------------------------------------------------------------------------------
 *
 */

/** @defgroup test
 *  @ingroup test
 *  @brief skeleton file
 * 
 * skeleton test program, will not be installed with a "make install"
 * 
 * To create a new test based on the skeleton:
 * 
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */

#include <dnscore/dnscore.h>
#include <dnsdb/zdb.h>
#include <dnsdb/zdb_zone_load.h>
#include <dnscore/format.h>
#include <dnsdb/zdb_zone_write.h>
#include <dnscore/zone_reader_text.h>
#include <dnscore/bytearray_input_stream.h>

static char zone_sample_1[] =
"$TTL    86400   ; 24 hours\n"
"$ORIGIN somedomain7.eu.\n"
"\n"
"somedomain7.eu.      86400   IN  SOA ns1.somedomain7.eu.  info.somedomain7.eu. 1 3600 1800 3600000 600\n"
"\n"
"                     86400   IN  MX  10 mail.somedomain7.eu.\n"
"                     86400   IN  NS  ns1.somedomain7.eu.\n"
"                     86400   IN  NS  \\@.somedomain7.com.\n"
"                     86400   IN  NS  \\$.somedomain7.com.\n"
"                     86400   IN  NS  prefix\\@.somedomain7.com.\n"
"                     86400   IN  NS  prefix\\$.somedomain7.com.\n"
"                     86400   IN  NS  \\@suffix.somedomain7.com.\n"
"                     86400   IN  NS  \\$suffix.somedomain7.com.\n"
"\n"
"ns1.somedomain7.eu.  86400   IN  A   192.0.2.2\n"
"mail.somedomain7.eu. 86400   IN  A   192.0.2.3\n"
"www.somedomain7.eu.  86400   IN  A   192.0.2.4\n"
"\n"
"201710._domainkey 14400 IN TXT \"v=DKIM1\\; p=MIIBIjANBgkqhkiG9w0CAQEFAAOCAQ8AMIIBCgKCAQEAm0U5huZyt0d7l094J0yhmaCGrE4c3zeV9+xNADy3zyIVHHzAsG0oHZ10oNvEIkqHyuk7uLy/GJNvk6M/xQ8fZ8fm6SnigGhaihAT1+FhiYMuW+xnCsrLQGwz2L7D8VjOf7qAKc5+mB3gITtjjzzN8BPLPxpoWBmHPUh69T2WxuGrwGD81tqplWNlQRCVLo6oP64is6xn\" \"sVzFDGWdsbJSRFetCMMFhXbeUei+wkbiq+cms9SO30fV1YfKEA8zT7gE/sp7YattMG51R5+iOWjtnr5C7O7e5EKNfblonXmx/1bwWpaobFNTQ7mq8Ij7aWyY+b4QJ0wuhdz8zRKUxFKhZQIDAQAB\\;\"\n"
"backslash.somedomain7.eu. 86400 IN TXT \"back\\\\slash\"\n"
"withspace.somedomain7.eu. 86400 IN TXT \"one space\"\n"
"twowords.somedomain7.eu. 86400 IN TXT two word\n"
"\n"
"\\@ 3600 IN TXT \"at\"\n"
"\\$ 3600 IN TXT \"dollar\"\n";

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* initializes the core library */
    dnscore_init();
    zdb_init();


    zdb_zone *zone = NULL;
    zdb_zone *zone_reloaded = NULL;
    ya_result ret;
    zone_reader zr;
    u8 fqdn[256];

    cstr_to_dnsname(fqdn, "somedomain7.eu.");

    input_stream is;

    bytearray_input_stream_init(&is, zone_sample_1, sizeof(zone_sample_1) - 1, FALSE);

    ret = zone_reader_text_parse_stream(&is, &zr);

    if(FAIL(ret))
    {
        formatln("zone load failed (reader): %r", ret);
        return EXIT_FAILURE;
    }

    ret = zdb_zone_load(NULL, &zr, &zone, fqdn, 0);

    if(FAIL(ret))
    {
        formatln("zone load failed: %r", ret);
        return EXIT_FAILURE;
    }

    zdb_zone_acquire(zone);
    zdb_zone_lock(zone, ZDB_MUTEX_READER);
    ret =  zdb_zone_write_text_file(zone, "/tmp/somedomain7.eu.", ZDB_ZONE_WRITE_TEXT_FILE_FORCE_LABEL);
    zdb_zone_unlock(zone, ZDB_MUTEX_READER);

    if(FAIL(ret))
    {
        formatln("zone save failed: %r", ret);
        zdb_zone_release(zone);
        return EXIT_FAILURE;
    }

    ret = zone_reader_text_open("/tmp/somedomain7.eu.", &zr);

    if(FAIL(ret))
    {
        formatln("zone reload failed (reader): %r", ret);
        zdb_zone_release(zone);
        return EXIT_FAILURE;
    }

    ret = zdb_zone_load(NULL, &zr, &zone_reloaded, fqdn, 0);

    if(FAIL(ret))
    {
        formatln("zone reload failed: %r", ret);
        zdb_zone_release(zone);
        return EXIT_FAILURE;
    }

    zdb_zone_acquire(zone_reloaded);

    zdb_zone_release(zone);
    zdb_zone_release(zone_reloaded);

    // compare

    flushout();
    flusherr();
    fflush(NULL);

    zdb_finalize();
    dnscore_finalize();

    return EXIT_SUCCESS;
}

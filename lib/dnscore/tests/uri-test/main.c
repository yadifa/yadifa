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
#include <dnscore/uri.h>

static char      uri_allgood[] = "GET /api/1.0/distance?name=eurid%2Eeu&text=Hello%20world";
static char      uri_noarg0[] = "GET /api/1.0/distance";
static char      uri_noarg1[] = "GET /api/1.0/distance";
static char      uri_wrongencoding0[] = "GET /api/1.0/distance?name=eurid%2Zeu&text=Hello%20world";
static char      uri_wrongencoding1[] = "GET /api/1.0/distance?name=eurid%Z2eu&text=Hello%20world";
static char      uri_wrongencoding2[] = "GET /api/1.0/distance?name=eurid%2";
static char      uri_wronguri0[] = "GET /api/1.0/distance?name";

static ya_result decode_test_uri_callback(void *args, const char *name, const char *value)
{
    if(value == NULL)
    {
        yatest_log("%p : page=%s", args, name);
    }
    else
    {
        yatest_log("%p : '%s'='%s'", args, name, value);
    }

    return SUCCESS;
}

static int decode_test()
{
    ya_result ret;

    dnscore_init();
    if(FAIL(ret = uri_path_decode(uri_allgood, uri_allgood + sizeof(uri_allgood), decode_test_uri_callback, &ret)))
    {
        yatest_err("URI path decoding failed with %08x", ret);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int noarg0_test()
{
    ya_result ret;

    dnscore_init();
    if(FAIL(ret = uri_path_decode(uri_noarg0, uri_noarg0 + sizeof(uri_noarg0), decode_test_uri_callback, &ret)))
    {
        yatest_err("URI path decoding failed with %08x", ret);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int noarg1_test()
{
    ya_result ret;

    dnscore_init();
    if(FAIL(ret = uri_path_decode(uri_noarg1, uri_noarg1 + sizeof(uri_noarg1), decode_test_uri_callback, &ret)))
    {
        yatest_err("URI path decoding failed with %08x", ret);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int wrongencoding0_test()
{
    ya_result ret;

    dnscore_init();
    if(ISOK(ret = uri_path_decode(uri_wrongencoding0, uri_wrongencoding0 + sizeof(uri_wrongencoding0), decode_test_uri_callback, &ret)))
    {
        yatest_err("URI path decoding succeeded with %08x", ret);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int wrongencoding1_test()
{
    ya_result ret;

    dnscore_init();
    if(ISOK(ret = uri_path_decode(uri_wrongencoding1, uri_wrongencoding1 + sizeof(uri_wrongencoding1), decode_test_uri_callback, &ret)))
    {
        yatest_err("URI path decoding succeeded with %08x", ret);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int wrongencoding2_test()
{
    ya_result ret;

    dnscore_init();
    if(ISOK(ret = uri_path_decode(uri_wrongencoding2, uri_wrongencoding2 + sizeof(uri_wrongencoding2), decode_test_uri_callback, &ret)))
    {
        yatest_err("URI path decoding succeeded with %08x", ret);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int wronguri0_test()
{
    ya_result ret;

    dnscore_init();
    if(ISOK(ret = uri_path_decode(uri_wronguri0, uri_wronguri0 + sizeof(uri_wronguri0), decode_test_uri_callback, &ret)))
    {
        yatest_err("URI path decoding succeeded with %08x", ret);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(decode_test)
YATEST(noarg0_test)
YATEST(noarg1_test)
YATEST(wrongencoding0_test)
YATEST(wrongencoding1_test)
YATEST(wrongencoding2_test)
YATEST(wronguri0_test)
YATEST_TABLE_END

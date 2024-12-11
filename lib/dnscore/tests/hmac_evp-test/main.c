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
#include "dnscore/hmac.h"
#include <dnscore/dnscore.h>

struct id_name_hmac_size_s
{
    int         algorithm_id;
    const char *name;
    uint8_t     expected_hmac[HMAC_BUFFER_SIZE];
    int         expected_hmac_size;
};

static const struct id_name_hmac_size_s algorithms[] = {
#ifndef OPENSSL_NO_MD5
    {HMAC_MD5, "MD5", {0xe8, 0xfb, 0xad, 0x84, 0xf2, 0xc8, 0x68, 0x12, 0x4b, 0x86, 0xe5, 0xfc, 0x2a, 0x72, 0x5d, 0x85}, 16},
#endif
#ifndef OPENSSL_NO_SHA
    {HMAC_SHA1, "SHA1", {0xbb, 0x3b, 0xd8, 0x26, 0x49, 0x5d, 0x21, 0xad, 0xaf, 0x8c, 0xaf, 0xcf, 0x88, 0x99, 0x55, 0x33, 0x03, 0x50, 0x10, 0x90}, 20},
#endif
#ifndef OPENSSL_NO_SHA256
    {HMAC_SHA224, "SHA224", {0xb6, 0xfa, 0x31, 0x69, 0x80, 0x10, 0x3e, 0x4d, 0xec, 0x00, 0x49, 0xed, 0x8e, 0xe3, 0x5c, 0xb1, 0xea, 0x3a, 0x2f, 0x34, 0xdc, 0xc7, 0xdc, 0xf1, 0x61, 0xe5, 0x6c, 0x4d}, 28},
    {HMAC_SHA256, "SHA256", {0xbc, 0x37, 0x0a, 0x74, 0x22, 0xb8, 0x6e, 0x58, 0xfd, 0x0f, 0x96, 0x82, 0x53, 0xc6, 0xab, 0x6a, 0x5d, 0xcd, 0x52, 0x6b, 0xcf, 0xd4, 0x74, 0x80, 0x99, 0x64, 0x6c, 0xd0, 0x5d, 0xe8, 0x8e, 0xd4}, 32},
#endif
#ifndef OPENSSL_NO_SHA512
    {HMAC_SHA384,
     "SHA384",
     {0x68, 0x9b, 0xc0, 0x5e, 0xd1, 0x5c, 0x5e, 0x68, 0x8d, 0x48, 0x11, 0x59, 0x9f, 0x63, 0xe0, 0xcf, 0xd1, 0xfe, 0x05, 0x02, 0xe5, 0x68, 0xb3, 0x80,
      0x43, 0xb6, 0x60, 0x0f, 0x44, 0x99, 0x2c, 0xec, 0x42, 0x28, 0x64, 0x5b, 0x84, 0xc2, 0x40, 0xa4, 0x6b, 0xf4, 0x33, 0x46, 0x4f, 0x11, 0x06, 0x54},
     48},
    {HMAC_SHA512,
     "SHA512",
     {0x0e, 0x14, 0xc9, 0xe0, 0x93, 0x5e, 0x8a, 0x89, 0x46, 0x09, 0x5f, 0xda, 0x6e, 0x01, 0x57, 0x1c, 0x83, 0x07, 0xa8, 0x27, 0x40, 0x35, 0xe1, 0xd6, 0xce, 0x52, 0xca, 0x7f, 0x1d, 0x5e, 0x84, 0xf5,
      0x0d, 0xbb, 0x89, 0x38, 0x26, 0x6f, 0x49, 0x28, 0x92, 0x95, 0xc7, 0xfc, 0x46, 0xb3, 0xab, 0x3f, 0x7c, 0xfc, 0x36, 0x9f, 0x97, 0x06, 0x1d, 0x03, 0x8e, 0xd8, 0xf0, 0x32, 0xee, 0x1d, 0xa5, 0xb8},
     64},
#endif
    {-1, NULL, {0}, 0}};

static const char key[] = "This is not a very good key.";

static int        hmac_evp_test()
{
    int          ret;
    unsigned int hmac_len;
    uint8_t      hmac[HMAC_BUFFER_SIZE];

    dnscore_init();

    for(int i = 0; algorithms[i].algorithm_id >= 0; ++i)
    {
        yatest_log("algorithm: %s", algorithms[i].name);
        tsig_hmac_t t = tsig_hmac_allocate();
        ret = hmac_init(t, key, sizeof(key), algorithms[i].algorithm_id);
        if(ret < 0)
        {
            yatest_err("hmac_init failed with %08x", ret);
            return 1;
        }
        ret = hmac_update(t, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum));
        if(ret < 0)
        {
            yatest_err("hmac_update failed with %08x", ret);
            return 1;
        }
        hmac_len = 64;
        memset(hmac, 0, sizeof(hmac));
        ret = hmac_final(t, hmac, &hmac_len);
        if(ret < 0)
        {
            yatest_err("hmac_final failed with %08x", ret);
            return 1;
        }
        if(hmac_len != (unsigned int)algorithms[i].expected_hmac_size)
        {
            yatest_err("hmac size got %u, expected %u", hmac_len, algorithms[i].expected_hmac_size);
            return 1;
        }
        if(memcmp(hmac, algorithms[i].expected_hmac, algorithms[i].expected_hmac_size) != 0)
        {
            yatest_err("got:");
            yatest_hexdump_err(hmac, hmac + hmac_len);
            yatest_err("expected:");
            yatest_hexdump_err(algorithms[i].expected_hmac, algorithms[i].expected_hmac + algorithms[i].expected_hmac_size);
            return 1;
        }
        memset(hmac, 0, sizeof(hmac));
        hmac_reset(t);
        ret = hmac_init(t, key, sizeof(key), algorithms[i].algorithm_id);
        if(ret < 0)
        {
            yatest_err("hmac_init failed with %08x (after reset)", ret);
            return 1;
        }
        ret = hmac_update(t, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum));
        if(ret < 0)
        {
            yatest_err("hmac_update failed with %08x (after reset)", ret);
            return 1;
        }
        hmac_len = 64;
        memset(hmac, 0, sizeof(hmac));
        ret = hmac_final(t, hmac, &hmac_len);
        if(ret < 0)
        {
            yatest_err("hmac_final failed with %08x (after reset)", ret);
            return 1;
        }
        if(hmac_len != (unsigned int)algorithms[i].expected_hmac_size)
        {
            yatest_err("hmac size got %u, expected %u (after reset)", hmac_len, algorithms[i].expected_hmac_size);
            return 1;
        }
        if(memcmp(hmac, algorithms[i].expected_hmac, algorithms[i].expected_hmac_size) != 0)
        {
            yatest_err("got: (after reset)");
            yatest_hexdump_err(hmac, hmac + hmac_len);
            yatest_err("expected: (after reset)");
            yatest_hexdump_err(algorithms[i].expected_hmac, algorithms[i].expected_hmac + algorithms[i].expected_hmac_size);
            return 1;
        }
    }

    dnscore_finalize();

    return 0;
}

static int hmac_evp_error_test()
{
    int ret;
    dnscore_init();
    tsig_hmac_t t = tsig_hmac_allocate();
    ret = hmac_init(t, key, sizeof(key), -1);
    if(ret != INVALID_ARGUMENT_ERROR)
    {
        yatest_err("hmac_init with the wrong algorithm expected to return INVALID_ARGUMENT_ERROR, returned %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    ret = hmac_init(t, key, sizeof(key), algorithms[0].algorithm_id);
    ret = hmac_init(t, key, sizeof(key), algorithms[0].algorithm_id);
    if(ret != INVALID_STATE_ERROR)
    {
        yatest_err("double hmac_init expected to return INVALID_STATE_ERROR, returned %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(hmac_evp_test)
YATEST(hmac_evp_error_test)
YATEST_TABLE_END

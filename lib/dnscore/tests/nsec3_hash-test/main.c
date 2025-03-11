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
#include "dnscore/dnssec_errors.h"
#include <dnscore/dnscore.h>
#include <dnscore/nsec3_hash.h>

static const uint8_t yadifa_eu[] = {6, 'y', 'a', 'd', 'i', 'f', 'a', 2, 'e', 'u', 0};

static const uint8_t digest_0[] = {0xee, 0x4d, 0xf1, 0x32, 0x60, 0x93, 0x7e, 0x26, 0x4e, 0x20, 0xde, 0x50, 0xaa, 0x13, 0x4b, 0xeb, 0xdc, 0x60, 0x24, 0x78};

static const uint8_t salt_1[] = {0xba, 0x11};

static const uint8_t digest_1[] = {0xf7, 0xac, 0x08, 0x1c, 0xf1, 0x0f, 0x51, 0x6f, 0x7c, 0x4f, 0xb5, 0xe4, 0x91, 0x94, 0x75, 0x67, 0x8a, 0x96, 0x05, 0x55};

static int           nsec3_hash_test()
{
    uint8_t digest[64];
    dnscore_init();
    nsec3_hash_function_t *f = nsec3_hash_get_function(1);
    if(nsec3_hash_len(1) != 20)
    {
        yatest_err("nsec3_hash_len(1) didn't return 20");
        return 1;
    }

    memset(digest, 0, sizeof(digest));
    f(yadifa_eu, sizeof(yadifa_eu), NULL, 0, 0, digest, false);
    if(memcmp(digest, digest_0, sizeof(digest_0)) != 0)
    {
        yatest_err("nsec3_hash yadifa.eu failed");
        return 1;
    }

    memset(digest, 0, sizeof(digest));
    f(yadifa_eu, sizeof(yadifa_eu), salt_1, sizeof(salt_1), 10, digest, true);
    if(memcmp(digest, digest_1, sizeof(digest_1)) != 0)
    {
        yatest_err("nsec3_hash *.yadifa.eu ba11 10 failed");
        return 1;
    }

    dnscore_finalize();
    return 0;
}

static int nsec3_hash_unsupported_test()
{
    uint8_t digest[64];
    dnscore_init();
    for(int i = 0; i < 256; ++i)
    {
        if(i == 1)
        {
            continue;
        }

        nsec3_hash_function_t *f = nsec3_hash_get_function(i);

        int                    ret = f(yadifa_eu, sizeof(yadifa_eu), NULL, 0, 0, digest, false);

        if(ret != DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM)
        {
            yatest_err(
                "nsec3_hash function for algorithm %i expected to return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM,"
                " returned %08x = %s instead",
                ret,
                error_gettext(ret));
            return 1;
        }

        if(nsec3_hash_len(i) != 0)
        {
            yatest_err("nsec3_hash_len(%i) didn't return 0", i);
            return 1;
        }
    }
    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(nsec3_hash_test)
YATEST(nsec3_hash_unsupported_test)
YATEST_TABLE_END

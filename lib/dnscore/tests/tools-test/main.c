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
#include "dnscore/tools.h"
#include <dnscore/dnscore.h>
#include <dnscore/timems.h>

static const size_t text_array_size = 5;

static const char  *text_array[5] = {"oNe", "TwO", "threE", "fouR", "fiVe"};

static const int    text_index = 2;

static const char   match_case[] = "threE";
static const char   match[] = "three";
static const char   nomatch[] = "six";

static int          bytes_swap_test()
{
    dnscore_init();
    size_t   odd_size = 255;
    size_t   even_size = 254;
    uint8_t *odd = yatest_malloc(odd_size);
    for(size_t i = 0; i < odd_size; ++i)
    {
        odd[i] = (uint8_t)i;
    }
    uint8_t *even = yatest_malloc(even_size);
    for(size_t i = 0; i < even_size; ++i)
    {
        even[i] = (uint8_t)i;
    }
    bytes_swap(odd, odd_size);
    for(size_t i = 0; i < odd_size; ++i)
    {
        if(odd[odd_size - i - 1] != (uint8_t)i)
        {
            yatest_err("error at position %i (odd)", i);
            return 1;
        }
    }
    bytes_swap(even, even_size);
    for(size_t i = 0; i < even_size; ++i)
    {
        if(even[even_size - i - 1] != (uint8_t)i)
        {
            yatest_err("error at position %i (even)", i);
            return 1;
        }
    }

    dnscore_finalize();
    return 0;
}

static int bytes_copy_swap_test()
{
    dnscore_init();
    size_t   odd_size = 255;
    size_t   even_size = 254;
    uint8_t *odd = yatest_malloc(odd_size);
    for(size_t i = 0; i < odd_size; ++i)
    {
        odd[i] = (uint8_t)i;
    }
    uint8_t *even = yatest_malloc(even_size);
    for(size_t i = 0; i < even_size; ++i)
    {
        even[i] = (uint8_t)i;
    }
    uint8_t *odd_dst = yatest_malloc(odd_size);
    bytes_copy_swap(odd_dst, odd, odd_size);
    for(size_t i = 0; i < odd_size; ++i)
    {
        if(odd_dst[odd_size - i - 1] != (uint8_t)i)
        {
            yatest_err("error at position %i (odd)", i);
            return 1;
        }
    }
    uint8_t *even_dst = yatest_malloc(even_size);
    bytes_copy_swap(even_dst, even, even_size);
    for(size_t i = 0; i < even_size; ++i)
    {
        if(even_dst[even_size - i - 1] != (uint8_t)i)
        {
            yatest_err("error at position %i (even)", i);
            return 1;
        }
    }

    dnscore_finalize();
    return 0;
}

static int text_in_test()
{
    dnscore_init();
    if(!text_in(match_case, text_array, text_array_size))
    {
        yatest_err("text_in should have matched");
        return 1;
    }
    if(text_in(match, text_array, text_array_size))
    {
        yatest_err("text_in should not have matched (case)");
        return 1;
    }
    if(text_in(nomatch, text_array, text_array_size))
    {
        yatest_err("text_in should not have matched");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int text_in_ignorecase_test()
{
    dnscore_init();
    if(!text_in_ignorecase(match_case, text_array, text_array_size))
    {
        yatest_err("text_in should have matched");
        return 1;
    }
    if(!text_in_ignorecase(match, text_array, text_array_size))
    {
        yatest_err("text_in should have matched");
        return 1;
    }
    if(text_in_ignorecase(nomatch, text_array, text_array_size))
    {
        yatest_err("text_in should not have matched");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int text_index_in_test()
{
    dnscore_init();
    if(text_index_in(match_case, text_array, text_array_size) != text_index)
    {
        yatest_err("text_in should have matched");
        return 1;
    }
    if(text_index_in(match, text_array, text_array_size) != -1)
    {
        yatest_err("text_in should not have matched (case)");
        return 1;
    }
    if(text_index_in(nomatch, text_array, text_array_size) != -1)
    {
        yatest_err("text_in should not have matched");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int text_index_in_ignorecase_test()
{
    dnscore_init();
    if(text_index_in_ignorecase(match_case, text_array, text_array_size) != text_index)
    {
        yatest_err("text_in should have matched");
        return 1;
    }
    if(text_index_in_ignorecase(match, text_array, text_array_size) != text_index)
    {
        yatest_err("text_in should have matched (case)");
        return 1;
    }
    if(text_index_in_ignorecase(nomatch, text_array, text_array_size) != -1)
    {
        yatest_err("text_in should not have matched");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int isqrt_test()
{
    dnscore_init();
    int64_t t;
    yatest_timer_start(&t);
    for(int64_t i = 0; i < 0x100000000LL; ++i)
    {
        if((i & 0xffffff) == 0)
        {
            yatest_timer_stop(&t);
            yatest_log("%08llx / %08llx (%f seconds)", i, UINT32_MAX, yatest_timer_seconds(&t));
            yatest_timer_start(&t);
            i += 0x10000000LL;
            if(i > UINT32_MAX)
            {
                i = UINT32_MAX;
            }
        }
        int64_t j = isqrt(i);
        int64_t j2 = j * j;
        if(j2 != i)
        {
            int64_t j2l = (j - 1) * (j - 1);
            int64_t j2h = (j + 1) * (j + 1);
            if((j2l < i) && (j2h > i))
            {
                continue;
            }
            else
            {
                yatest_err("isqrt failed for %lli = %lli : [ %lli ; %lli ; %lli ]", i, j, j2l, j2, j2h);
                return 1;
            }
        }
    }
    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(bytes_swap_test)
YATEST(bytes_copy_swap_test)
YATEST(text_in_test)
YATEST(text_in_ignorecase_test)
YATEST(text_index_in_test)
YATEST(text_index_in_ignorecase_test)
YATEST(isqrt_test)
YATEST_TABLE_END

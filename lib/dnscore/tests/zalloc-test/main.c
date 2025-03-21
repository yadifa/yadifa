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
#include <dnscore/zalloc.h>

#define THREE_POOLS_SIZE 0x2004000 // 32MB + 16KB

static int zalloc_test()
{
#if DNSCORE_HAS_ZALLOC_SUPPORT
    dnscore_init();

    int64_t **allocated = yatest_malloc((THREE_POOLS_SIZE / 8) * sizeof(int64_t *));

    for(int64_t size = 8; size <= 2048 + 8; size += 8)
    {
        yatest_log("size %lli", size);

        int64_t count = THREE_POOLS_SIZE / size;

        // allocate and fill

        for(int64_t i = 0; i < count; ++i)
        {
            int64_t *ptr = zalloc(size
#if DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_HAS_BLOCK_TAG
                                  ,
                                  GENERIC_TAG
#endif
            );
            if(ptr == NULL)
            {
                yatest_err("out of memory");
                return 1;
            }
            allocated[i] = ptr;
            memset(ptr, 0xac, size);
            *ptr = i;
        }

        for(int64_t i = 0; i < count; ++i)
        {
            if(allocated[i][0] != i)
            {
                yatest_err("memory of block %lli[0] overwritten", i);
                return 1;
            }
            if(size > 8)
            {
                int fills = size >> 3;
                for(int j = 1; j < fills; ++j)
                {
                    if(allocated[i][j] != (int64_t)0xacacacacacacacacLL)
                    {
                        yatest_err("memory of block %lli[%i] overwritten", i, j);
                        return 1;
                    }
                }
            }
        }

        int line = size / 8;
        yatest_log("line %i: zheap_line_total = %llu, zheap_line_avail = %llu, zallocatedtotal = %lli", line, zheap_line_total(line), zheap_line_avail(line), zallocatedtotal());

        for(int64_t i = 0; i < count; ++i)
        {
            zfree(allocated[i], size);
        }
    }

    zalloc_print_stats(termout);
    flushout();

    free(allocated);

    dnscore_finalize();
    return 0;
#else
    yatest_log("SKIPPED");
    return 0;
#endif
}

static int zalloc_unaligned_test()
{
#if DNSCORE_HAS_ZALLOC_SUPPORT
    dnscore_init();

    int64_t **allocated = yatest_malloc((THREE_POOLS_SIZE / 8) * sizeof(int64_t *));

    for(int64_t size = 8; size <= 2048 + 8; size += 8)
    {
        yatest_log("size %lli", size);

        int64_t count = THREE_POOLS_SIZE / size;

        // allocate and fill

        for(int64_t i = 0; i < count; ++i)
        {
            int64_t *ptr = zalloc_unaligned(size
#if DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_HAS_BLOCK_TAG
                                            ,
                                            GENERIC_TAG
#endif
            );
            if(ptr == NULL)
            {
                yatest_err("out of memory");
                return 1;
            }
            allocated[i] = ptr;
            memset(ptr, 0xac, size);
            *ptr = i;
        }

        for(int64_t i = 0; i < count; ++i)
        {
            if(allocated[i][0] != i)
            {
                yatest_err("memory of block %lli[0] overwritten", i);
                return 1;
            }
            if(size > 8)
            {
                int fills = size >> 3;
                for(int j = 1; j < fills; ++j)
                {
                    if(allocated[i][j] != (int64_t)0xacacacacacacacacLL)
                    {
                        yatest_err("memory of block %lli[%i] overwritten", i, j);
                        return 1;
                    }
                }
            }
        }

        int line = size / 8;
        yatest_log("line %i: zheap_line_total = %llu, zheap_line_avail = %llu, zallocatedtotal = %lli", line, zheap_line_total(line), zheap_line_avail(line), zallocatedtotal());

        for(int64_t i = 0; i < count; ++i)
        {
            zfree_unaligned(allocated[i]);
        }
    }

    zalloc_print_stats(termout);
    flushout();

    free(allocated);

    dnscore_finalize();
    return 0;
#else
    yatest_log("SKIPPED");
    return 0;
#endif
}

YATEST_TABLE_BEGIN
YATEST(zalloc_test)
YATEST(zalloc_unaligned_test)
YATEST_TABLE_END

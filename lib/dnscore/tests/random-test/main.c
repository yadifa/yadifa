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
#include <dnscore/dnscore.h>
#include <dnscore/random.h>

#define BUCKET_COUNT 0x1000000
#define SHIFTER      8

static int random_test_base(bool auto_init)
{
    dnscore_init();
    random_ctx_t rnd;
    if(!auto_init)
    {
        rnd = random_mt_init(0);
    }
    else
    {
        rnd = random_mt_init_auto();
    }

    uint32_t *d = yatest_malloc(BUCKET_COUNT * sizeof(uint32_t));
    uint32_t *etd = yatest_malloc(BUCKET_COUNT * sizeof(uint32_t));
    memset(etd, 0, BUCKET_COUNT * sizeof(uint32_t));
    for(int i = 0; i < BUCKET_COUNT; ++i)
    {
        uint32_t r = random_mt_next(rnd);
        d[r >> SHIFTER]++;
    }
    uint32_t mean = 0;
    for(int i = 0; i < BUCKET_COUNT; ++i)
    {
        mean += d[i];
    }
    uint32_t et_max = 0;
    mean /= BUCKET_COUNT;
    for(int i = 0; i < BUCKET_COUNT; ++i)
    {
        uint32_t et = (uint32_t)abs((int32_t)d[i] - (int32_t)mean);
        etd[et]++;
        // yatest_log("et[%6i] = %i", i, et);
        if(et > et_max)
        {
            et_max = et;
        }
    }
    yatest_log("et_max=%i", et_max);
    for(uint32_t i = 0; i <= et_max; ++i)
    {
        yatest_log("et[%i] = %i", i, etd[i]);
    }
    uint32_t et_sum = 0;
    for(uint32_t i = 0; i <= MIN(4, et_max); ++i)
    {
        et_sum += etd[i];
    }
    yatest_log("et_sum=%i", et_sum);
    double ratio = (100.0 * et_sum) / BUCKET_COUNT;
    yatest_log("ratio=%f%%", ratio);
    if(ratio < 98)
    {
        yatest_err("lower quality than expected");
        return 1;
    }
    random_mt_finalize(rnd);
    return 0;
}

static int random_test() { return random_test_base(false); }

static int random_auto_test() { return random_test_base(true); }

YATEST_TABLE_BEGIN
YATEST(random_test)
YATEST(random_auto_test)
YATEST_TABLE_END

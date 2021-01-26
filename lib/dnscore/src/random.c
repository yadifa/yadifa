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

/** @defgroup dnscoretools Generic Tools
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <dnscore/mutex.h>

#include "dnscore/random.h"

// #define restrict 

#define RNDCTX_TAG 0x585443444e52

/*
 * I've written two optimizations over the algorithm (both are avoiding modulos)
 *
 */

#define IFJUMP_OVER_MODULO	    2	/* 6M ->  7M */
#define SPLITTEDLOOP_OVER_MODULO    2	/* 7M -> 10M : The v2 is slightly faster than the v1 */

/**
 *
 * Mersene Twister random generator.
 *
 */

/* Create a length 624 array to store the state of the generator */

#define MERSERNE_TWISTER_STATE_SIZE 624

/* used by the auto init to randomise the seed further */

static smp_int random_serial = SMP_INT_INITIALIZER_AT(0x7565edf1);

typedef struct random_context random_context;

struct random_context
{
    u32 MT[MERSERNE_TWISTER_STATE_SIZE];
#if IFJUMP_OVER_MODULO < 2
    u32 MT_index /*= 0*/;
#else
    u32* MT_offset /*= MT*/;
#endif
};

random_ctx
random_init(u32 seed)
{
    random_context *ctx;
    u32 i;

    MALLOC_OBJECT_OR_DIE(ctx, random_context, RNDCTX_TAG);

    u32 *MT = &ctx->MT[0];
    
    MT[0] = seed;

    for(i = 1; i < MERSERNE_TWISTER_STATE_SIZE; i++)
    {
        u32 MT_im1 = MT[i - 1];

        MT[i] = (0x6c078965L * (MT_im1 ^ ((MT_im1) >> 30))) + i;
    }

#if IFJUMP_OVER_MODULO < 2
    ctx->MT_index = 0;
#else
    ctx->MT_offset = &ctx->MT[0];
#endif

    return (random_ctx)ctx;
}

random_ctx
random_init_auto()
{
    u64 now = timeus();
    now ^= (now >> 32);
    now ^= (u32)thread_self();

    now ^= smp_int_get(&random_serial);
    smp_int_add(&random_serial, 0xc18e2a1d);
    return random_init((u32)now);
}


void
random_finalize(random_ctx ctx)
{
    free(ctx);
}

// Generate an array of 624 untempered numbers

static void
random_generate(random_context *ctx)
{
#if SPLITTEDLOOP_OVER_MODULO == 2

    u32 *MT = &ctx->MT[0];

    u32 * restrict MT_i = &MT[0];

    u32 * restrict MT_limit_1 = &MT[MERSERNE_TWISTER_STATE_SIZE - 397];
    u32 * restrict MT_limit_2 = &MT[MERSERNE_TWISTER_STATE_SIZE - 1 ];

    do
    {
        u32 y = (MT_i[0] & 0x80000000L) | (MT_i[1] & 0x7fffffffL);

        MT_i[0] = MT_i[397] ^ (y >> 1);

        if((y & 1) == 1)
        {
            MT_i[0] ^= 0x9908b0dfL;
        }
    }
    while(++MT_i < MT_limit_1);

    /* i = MERSERNE_TWISTER_STATE_SIZE - 397 */

    do
    {
        u32 y = (MT_i[0] & 0x80000000L) | (MT_i[1] & 0x7fffffffL);

        MT_i[0] = MT_i[-(MERSERNE_TWISTER_STATE_SIZE - 397)] ^ (y >> 1);

        if((y & 1) == 1)
        {
            MT_i[0] ^= 0x9908b0dfL;
        }
    }
    while(++MT_i < MT_limit_2);

    /* i = MERSERNE_TWISTER_STATE_SIZE - 1 */

    {
        u32 y = (MT[MERSERNE_TWISTER_STATE_SIZE - 1]&0x80000000L) | (MT[ 0 ] & 0x7fffffffL);

        MT[MERSERNE_TWISTER_STATE_SIZE - 1] = MT[ 396 ] ^ (y >> 1);

        if((y & 1) == 1)
        {
            MT[MERSERNE_TWISTER_STATE_SIZE - 1] ^= 0x9908b0dfL;
        }
    }

#elif SPLITTEDLOOP_OVER_MODULO == 1

    u32 *MT = &ctx->MT[0];

    u32 i;

    for(i = 0; i < MERSERNE_TWISTER_STATE_SIZE - 397; i++)
    {
        u32 y = (MT[i]&0x80000000L) | (MT[ i + 1 ] & 0x7fffffffL);

        MT[i] = MT[ i + 397 ] ^ (y >> 1);

        if((y & 1) == 1)
        {
            MT[i] ^= 0x9908b0dfL;
        }
    }

    /* i = MERSERNE_TWISTER_STATE_SIZE - 397 */

    for(; i < MERSERNE_TWISTER_STATE_SIZE - 1; i++)
    {
        u32 y = (MT[i]&0x80000000L) | (MT[ i + 1 ] & 0x7fffffffL);

        MT[i] = MT[i - (MERSERNE_TWISTER_STATE_SIZE - 397) ] ^ (y >> 1);

        if((y & 1) == 1)
        {
            MT[i] ^= 0x9908b0dfL;
        }
    }

    /* i = MERSERNE_TWISTER_STATE_SIZE - 1 */

    {
        u32 y = (MT[MERSERNE_TWISTER_STATE_SIZE - 1]&0x80000000L) | (MT[ 0 ] & 0x7fffffffL);

        MT[MERSERNE_TWISTER_STATE_SIZE - 1] = MT[ 396 ] ^ (y >> 1);

        if((y & 1) == 1)
        {
            MT[MERSERNE_TWISTER_STATE_SIZE - 1] ^= 0x9908b0dfL;
        }
    }

#else
    
    u32 *MT = &ctx->MT[0];

    u32 i;

    for(i = 0; i < MERSERNE_TWISTER_STATE_SIZE; i++)
    {
        u32 y = (MT[i]&0x80000000L) | (MT[(i + 1) % MERSERNE_TWISTER_STATE_SIZE] & 0x7fffffffL);

        MT[i] = MT[(i + 397) % MERSERNE_TWISTER_STATE_SIZE] ^ (y >> 1);

        if((y & 1) == 1)
        {
            MT[i] ^= 0x9908b0dfL;
        }
    }
#endif
}

u32
random_next(random_ctx ctx_)
{
    random_context *ctx = (random_context*)ctx_;

#if IFJUMP_OVER_MODULO < 2
    if(ctx->MT_index == 0)
    {
        random_generate(ctx);
    }
#else
    if(ctx->MT_offset == ctx->MT)
    {
        random_generate(ctx);
    }
#endif

#if IFJUMP_OVER_MODULO == 0
    u32 y = ctx->MT[ctx->MT_index++];

    ctx->MT_index %= MERSERNE_TWISTER_STATE_SIZE;

#elif IFJUMP_OVER_MODULO == 1
    u32 y = ctx->MT[ctx->MT_index++];

    if(ctx->MT_index == MERSERNE_TWISTER_STATE_SIZE)
    {
        ctx->MT_index = 0;
    }

#elif IFJUMP_OVER_MODULO == 2

    u32 y = *ctx->MT_offset++;

    if(ctx->MT_offset == &ctx->MT[MERSERNE_TWISTER_STATE_SIZE])
    {
        ctx->MT_offset = ctx->MT;
    }
#endif

    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680L;
    y ^= (y << 15) & 0xefc60000L;
    y ^= (y >> 18);

    return y;
}

/** @} */

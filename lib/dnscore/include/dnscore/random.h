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

/**-----------------------------------------------------------------------------
 * @defgroup dnscoretools Generic Tools
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _RANDOM_H
#define _RANDOM_H

#include <dnscore/thread.h>
#include <dnscore/sys_types.h>
#include <dnscore/timems.h>
#include <dnscore/pcg_basic.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define RANDOM_MODE_MERSENE_TWISTER                 0
#define RANDOM_MODE_PERMUTED_CONGRUENTIAL_GENERATOR 1

#ifndef RANDOM_MODE
#define RANDOM_MODE RANDOM_MODE_PERMUTED_CONGRUENTIAL_GENERATOR
#endif

typedef void *random_ctx_t;

/**
 * For IDs ensure that seed is enough randomised.
 *
 * @param seed
 * @return
 */

random_ctx_t random_mt_init(uint32_t seed);

/**
 * Chooses a seed with little change of collision.
 * @return
 */

random_ctx_t random_mt_init_auto();

uint32_t     random_mt_next(random_ctx_t ctx);

void         random_mt_finalize(random_ctx_t ctx);

#if RANDOM_MODE == RANDOM_MODE_MERSENE_TWISTER

random_ctx random_init(uint32_t seed) { return random_mt_init(seed); }

random_ctx random_init_auto() { return random_mt_init_auto(); }

uint32_t   random_next(random_ctx ctx) { return random_mt_next(ctx); }

void       random_finalize(random_ctx ctx) { random_mt_finalize(ctx); }

#elif RANDOM_MODE == RANDOM_MODE_PERMUTED_CONGRUENTIAL_GENERATOR

static inline random_ctx_t random_init(uint32_t seed)
{
    pcg32_random_t *ctx;
    MALLOC_OBJECT_OR_DIE(ctx, pcg32_random_t, GENERIC_TAG);
    uint64_t initstate = 0x853c49e6748fea9bULL * seed;
    uint64_t initseq = 0xda3e39cb94b95bdbULL * seed;
    pcg32_srandom_r(ctx, initstate, initseq);
    return (random_ctx_t)ctx;
}

static inline random_ctx_t random_init_auto()
{
    pcg32_random_t *ctx;
    MALLOC_OBJECT_OR_DIE(ctx, pcg32_random_t, GENERIC_TAG);
    int64_t  now = timeus();
    uint64_t initstate = 0x853c49e6748fea9bULL * now;
    uint64_t initseq = 0xda3e39cb94b95bdbULL * now;
    pcg32_srandom_r(ctx, initstate, initseq);
    return (random_ctx_t)ctx;
}

static inline uint32_t random_next(random_ctx_t ctx) { return pcg32_random_r((pcg32_random_t *)ctx); }

static inline void     random_finalize(random_ctx_t ctx) { free(ctx); }

#else
#error "RANDOM_MODE value is not supported"
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RANDOM_H */
/** @} */

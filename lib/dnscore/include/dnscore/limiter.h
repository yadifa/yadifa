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

#pragma once

#include <dnscore/sys_types.h>

#if 0 /* fix */
#else
#define LIMITER_WINDOW_COUNT    1
#define LIMITER_WINDOW_DURATION 1000000 // 1s
#endif

typedef u32 limiter_count_t;

struct limiter_t
{
    u64 time_base;
    u64 last_time;
    u64 wait_time;
    u32 window_current;
    limiter_count_t rate_max;
    limiter_count_t window[LIMITER_WINDOW_COUNT];
};

typedef struct limiter_t limiter_t;

void limiter_init(limiter_t *r, limiter_count_t amount_max);

void limiter_set_wait_time(limiter_t *r, u64 time_to_wait_between_two);

void limiter_finalize(limiter_t *r);

/**
 * Computes the quota for adding a given amount
 * Sends the result back in two variables.
 * 
 * @param r the limiter
 * @param amount_to_add the amount to add
 * @param quota_available_now a pointer to a variable to hold how much can be added right now (can be NULL)
 * @param time_to_wait_for_more a pointer to a variable to hold how much time (us) needs to be waited before probing again (can be NULL)
 * 
 * Returns timeus() at the time of the call (not at the return of the call)
 */
u64 limiter_quota(limiter_t *r, limiter_count_t amount_to_add, limiter_count_t* quota_available_now, u64* time_to_wait_for_more);

void limiter_add(limiter_t *r, limiter_count_t amount_to_add, limiter_count_t* amount_added, u64* time_to_wait_for_more);

void limiter_add_anyway(limiter_t *r, limiter_count_t amount_to_add, limiter_count_t* amount_added, u64* time_to_wait_for_more);

void limiter_wait(limiter_t *r, limiter_count_t amount_to_add);

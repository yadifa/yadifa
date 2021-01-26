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

#include "dnscore/dnscore-config.h"
#include "dnscore/limiter.h"
#include "dnscore/timems.h"
#include "dnscore/logger.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#define DUMP 0

void
limiter_init(limiter_t *r, limiter_count_t rate_max)
{
    r->time_base = timeus();
    r->last_time = 0;
    r->wait_time = 0;
    r->window_current = 0;
    r->rate_max = rate_max;
    
    for(int i = 0; i < LIMITER_WINDOW_COUNT; ++i)
    {
        r->window[i] = 0; /*rate_max / LIMITER_WINDOW_COUNT;*/
    }
}

void
limiter_finalize(limiter_t *r)
{
    (void)r;
}

void limiter_set_wait_time(limiter_t *r, u64 time_to_wait_between_two)
{
    r->wait_time = time_to_wait_between_two;
}

u64
limiter_quota(limiter_t *r, limiter_count_t amount_to_add, limiter_count_t* quota_available_now, u64* time_to_wait_for_more)
{
    limiter_count_t avail;
    u64 ttw;
    
    u64 now = timeus();
        
    // d is the time elapsed since last measurement in us

    if(now - r->last_time > r->wait_time)
    {
        u64 delta_time_us = now - r->time_base;
        // get the window index

        u32 absolute_window = (u32)(delta_time_us / LIMITER_WINDOW_DURATION);
    
#if LIMITER_WINDOW_COUNT > 1
    
        u32 clear_from = r->window_current + 1;
        u32 clear_until = r->window_current + MIN(absolute_window, LIMITER_WINDOW_COUNT);
    
#if DUMP
        formatln("limiter: %-9u.%6u clear from %u to %u",
            (u32)(delta_time_us / 1000000ULL),
            (u32)(delta_time_us % 1000000ULL),
            clear_from, clear_until);
#endif
    
        for(u32 i = clear_from; i < clear_until; ++i)
        {
            r->window[i % LIMITER_WINDOW_COUNT] = 0;
        }

        r->window_current = absolute_window;

#if DUMP
        format("limiter: current window: %u [ ", r->window_current);
#endif
    
        limiter_count_t current_amount = 0;

        for(u32 i = 0; i < LIMITER_WINDOW_COUNT; ++i)
        {
            current_amount += r->window[i];
        
#if DUMP
            format("%9llu ", r->window[i]);
#endif
        }

    #if DUMP
        format("] = %llu", current_amount);
    #endif
    
#else // LIMITER_WINDOW_COUNT <= 1
    
        limiter_count_t current_amount;

        if(absolute_window == r->window_current)
        {
            current_amount = r->window[0];
        }
        else
        {
            r->window[0] = 0;
            current_amount = 0;
            r->time_base = now;
            r->window_current = 0;
        }

#endif
    
        if(r->rate_max > current_amount)
        {
            avail = r->rate_max - current_amount;

            if(avail < amount_to_add)
            {
                ttw = 0;
            }
            else
            {
                avail = amount_to_add;
                ttw = LIMITER_WINDOW_DURATION - (delta_time_us % LIMITER_WINDOW_DURATION);
            }
        }
        else
        {
            avail = 0;
            ttw = LIMITER_WINDOW_DURATION - (delta_time_us % LIMITER_WINDOW_DURATION);
        }
    
#if DUMP
        formatln(" available = %9llu, time to wait = %9llu", avail, ttw);
#endif
    
    }
    else
    {
        avail = 0;
        ttw = r->wait_time - (now - r->last_time);
    }
    
    if(quota_available_now != NULL)
    {
        *quota_available_now = avail;
    }
    
    if(time_to_wait_for_more != NULL)
    {
        *time_to_wait_for_more = ttw;
    }
    
    return now;
}

void
limiter_add(limiter_t *r, limiter_count_t amount_to_add, limiter_count_t* amount_added, u64* time_to_wait_for_more)
{
    limiter_count_t tmp;
    if(amount_added == NULL)
    {
        amount_added = &tmp;
    }
    u64 now = limiter_quota(r, amount_to_add, amount_added, time_to_wait_for_more);
    
    if(*amount_added > 0)
    {
        r->last_time = now;
        r->window[r->window_current % LIMITER_WINDOW_COUNT] += *amount_added;
    }
}

void
limiter_add_anyway(limiter_t *r, limiter_count_t amount_to_add, limiter_count_t* amount_added, u64* time_to_wait_for_more)
{
    limiter_count_t tmp_added;
    u64 tmp_time;
    
    if(amount_added == NULL)
    {
        amount_added = &tmp_added;
    }
    
    if(time_to_wait_for_more == NULL)
    {
        time_to_wait_for_more = &tmp_time;
    }
    
    u64 now = limiter_quota(r, amount_to_add, amount_added, time_to_wait_for_more);
    
    r->last_time = now;
    r->window[r->window_current % LIMITER_WINDOW_COUNT] += *amount_added;
}

void
limiter_wait(limiter_t *r, limiter_count_t amount_to_add)
{
    limiter_count_t amount_added;
    u64 time_to_wait_for_more;
    
    for(;;)
    {
        limiter_add(r, amount_to_add, &amount_added, &time_to_wait_for_more);
        
        if(amount_added >= amount_to_add)
        {
            break;
        }
        
        amount_to_add -= amount_added;
        
#if DUMP
        format("limiter: waiting %llu [ ", time_to_wait_for_more + 10);
#endif
        
        usleep(time_to_wait_for_more + 10);
    }
}

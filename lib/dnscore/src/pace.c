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
#include <unistd.h>

#include "dnscore/logger.h"
#include "dnscore/pace.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#define PACE_DUMP 0

#define PACE_MODE_SMOOTH 0
#define PACE_MODE_HARD   1

#define PACE_MODE PACE_MODE_HARD

void
pace_init(pace_s *pace, u64 min_us, u64 max_us, const char *name)
{
    if(min_us > max_us)
    {
        u64 tmp = max_us;
        max_us = min_us;
        min_us = tmp;
    }
    
    pace->min_us = min_us;
    pace->max_us = max_us;
#if PACE_MODE == PACE_MODE_SMOOTH
    pace->current_us = (max_us + min_us) >> 1;
#else
    pace->current_us = min_us;
#endif
    pace->counter = 0;
    
    pace->name = name;
}

/**
 * Will pause for a while
 */

void
pace_wait(pace_s *pace)
{
    u64 start = timeus();
    
    if((pace->counter > 0) && ((pace->counter & 3) != 0))
    {
#if defined(PACE_DUMP) && (PACE_DUMP > 0)
        u64 current = pace->current_us;
#endif
        pace->current_us <<= 1;
        
        if(pace->current_us == 0)
        {
            pace->current_us = 1;
        }
        
        if(pace->current_us > pace->max_us)
        {
            pace->current_us = pace->max_us;
        }

#if defined(PACE_DUMP) && (PACE_DUMP > 0)
        if(current != pace->current_us)
        {
            log_debug("pace: '%s' waiting for %lluµs (#%llu)", pace->name, pace->current_us, pace->counter);
        }
#endif
    }
    else
    {
        pace->wait_start = start;
        
#if defined(PACE_DUMP) && (PACE_DUMP > 0)
        log_debug("pace: '%s' waiting for %lluµs (#%llu)", pace->name, pace->current_us, pace->counter);
#endif
    }
    
    pace->counter++;
        
    u64 elapsed = 0;
    u64 current = pace->current_us;
    do
    {
         if(elapsed > current)
         {
             log_err("pace_wait: impossible! elapsed = %llu > %llu", elapsed, current);
             break;
         }
        
        usleep(current - elapsed);
        u64 now = timeus();
        
        if(now < start)
        {
            log_err("pace_wait: now=%llu < start=%llu (%llu)", now, start, start-now);
            break;
        }
        elapsed = now - start;
    }
    while(elapsed < current);
}

/**
 * Will update the pace taking the fact that now we have work to do
 */

void
pace_work(pace_s *pace)
{    
    pace->wait_end = timeus();
    
#if defined(PACE_DUMP) && (PACE_DUMP > 0)
    log_debug("pace: '%s' working after %lluµs (%lluµs #%llu)",
            pace->name, pace->wait_end - pace->wait_start, pace->current_us, pace->counter);
#endif
    
    pace->counter = 0;
#if PACE_MODE == PACE_MODE_SMOOTH
    pace->current_us >>= 1;
    if(pace->current_us < pace->min_us)
    {
        pace->current_us = pace->min_us;
    }
#else
    pace->current_us = pace->min_us;
#endif
}

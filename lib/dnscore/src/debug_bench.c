/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2023, EURid vzw. All rights reserved.
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

/** @defgroup debug Debug functions
 *  @ingroup dnscore
 *  @brief Debug functions.
 *
 *  Definitions of debug functions/hooks, mainly memory related.
 *
 * @{
 */
#include "dnscore/dnscore-config.h"
#include "dnscore/debug_config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dnscore/timems.h"

#include "dnscore/sys_types.h"
#include "dnscore/format.h"
#include "dnscore/logger.h"
#include "dnscore/debug.h"

#undef malloc
#undef free
#undef realloc
#undef calloc
#undef debug_mtest
#undef debug_stat
#undef debug_mallocated

#define MODULE_MSG_HANDLE g_system_logger

#if DEBUG

static pthread_mutex_t debug_bench_mtx = PTHREAD_MUTEX_INITIALIZER;
static debug_bench_s *debug_bench_first = NULL;
static bool debug_bench_init_done = FALSE;

void debug_bench_malloc_init();

void
debug_bench_init()
{
    if(debug_bench_init_done)
    {
        return;
    }

    debug_bench_malloc_init();

    pthread_mutexattr_t mta;
    int err;
    
    err = pthread_mutexattr_init(&mta);
    
    if(err == 0)
    {
        err = pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);
    
        if(err == 0)
        {
            err = pthread_mutex_init(&debug_bench_mtx, &mta);

            if(err == 0)
            {
                debug_bench_init_done = TRUE;
            }
            else
            {
                formatln("debug_bench_init: pthread_mutex_init: %r", MAKE_ERRNO_ERROR(err));
            }
        }
        else
        {
            formatln("debug_bench_init: pthread_mutexattr_settype: %r", MAKE_ERRNO_ERROR(err));
        }
        
        pthread_mutexattr_destroy(&mta);
    }
    else
    {
        formatln("debug_bench_init: pthread_mutexattr_init: %r", MAKE_ERRNO_ERROR(err));
    }
}

void
debug_bench_register(debug_bench_s *bench, const char *name)
{
    if((bench == NULL) || (name == NULL))
    {
        return;
    }

    pthread_mutex_lock(&debug_bench_mtx);
    
    debug_bench_s *b = debug_bench_first;
    while((b != bench) && (b != NULL))
    {
        b = b->next;
    }
    
    if(b == NULL)
    {
        bench->next = debug_bench_first;
        bench->name = strdup(name);
        bench->time_min = MAX_U64;
        bench->time_max = 0;
        bench->time_total = 0;
        bench->time_count = 0;
        debug_bench_first = bench;
    }
    else
    {
        log_debug("debug_bench_register(%p,%s): duplicate", bench, name);
    }
    pthread_mutex_unlock(&debug_bench_mtx);
}

void
debug_bench_commit(debug_bench_s *bench, u64 delta)
{
    pthread_mutex_lock(&debug_bench_mtx);
    bench->time_min = MIN(bench->time_min, delta);
    bench->time_max = MAX(bench->time_max, delta);
    bench->time_total += delta;
    bench->time_count++;
    pthread_mutex_unlock(&debug_bench_mtx);
}

void debug_bench_logdump_all()
{
    pthread_mutex_lock(&debug_bench_mtx);
    debug_bench_s *p = debug_bench_first;
    while(p != NULL)
    {
        double min = p->time_min;
        min /= ONE_SECOND_US_F;
        double max = p->time_max;
        max /= ONE_SECOND_US_F;
        double total = p->time_total;
        total /= ONE_SECOND_US_F;
        u32 count = p->time_count;
        double total_mean = (count != 0)?total/count:0;
        double total_rate = (total != 0)?count/total:0;
        if(logger_is_running())
        {
            log_info("bench: %16s: [%9.6fs:%9.6fs] total=%9.6fs mean=%9.6fs rate=%12.3f/s calls=%9u", p->name, min, max, total, total_mean, total_rate, count);
        }
        else
        {
            formatln("bench: %16s: [%9.6fs:%9.6fs] total=%9.6fs mean=%9.6fs rate=%12.3f/s calls=%9u", p->name, min, max, total, total_mean, total_rate, count);
        }
        p = p->next;
    }
    pthread_mutex_unlock(&debug_bench_mtx);
}

void debug_bench_print_all(output_stream *os)
{
    pthread_mutex_lock(&debug_bench_mtx);
    debug_bench_s *p = debug_bench_first;
    while(p != NULL)
    {
        double min = p->time_min;
        min /= ONE_SECOND_US_F;
        double max = p->time_max;
        max /= ONE_SECOND_US_F;
        double total = p->time_total;
        total /= ONE_SECOND_US_F;
        u32 count = p->time_count;
        double total_mean = (count != 0)?total/count:0;
        double total_rate = (total != 0)?count/total:0;
        osformatln(os, "bench: %16s: [%9.6fs:%9.6fs] total=%9.6fs mean=%9.6fs rate=%12.3f/s calls=%9u", p->name, min, max, total, total_mean, total_rate, count);
        p = p->next;
    }
    pthread_mutex_unlock(&debug_bench_mtx);
}

void debug_bench_unregister_all()
{
    pthread_mutex_lock(&debug_bench_mtx);
    debug_bench_s *p = debug_bench_first;
    while(p != NULL)
    {
        debug_bench_s *tmp = p;
        p = p->next;
#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
        debug_free((void*)tmp->name,__FILE__,__LINE__);
#else
        free((void*)tmp->name);
#endif
    }
    debug_bench_first = NULL;
    pthread_mutex_unlock(&debug_bench_mtx);
}
#else

void
debug_bench_init()
{
}

void
debug_bench_register(debug_bench_s *bench, const char *name)
{
    (void)bench;
    (void)name;
}

void
debug_bench_commit(debug_bench_s *bench, u64 delta)
{
    (void)bench;
    (void)delta;
}

void debug_bench_logdump_all()
{
}

void
debug_bench_unregister_all()
{
}

#endif

/** @} */

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
 * @defgroup threading mutexes, ...
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#if !DNSCORE_MUTEX_MUTEX_H
#error "dnscore/mutex_debug.h should only be included from mutex_mutex.h"
#endif

#include <dnscore/dnscore_config_features.h>
#include <dnscore/sys_types.h>
#include <dnscore/thread.h>

#include <dnscore/timems.h>

#include <dnscore/mutex_contention_monitor.h>

#include <pthread.h>

#if defined(__MACH__)
#include <dnscore/osx_clock_gettime.h>
#endif

#if !_POSIX_TIMERS
#ifndef _TIMEMS_H
uint64_t timeus();
#endif
#endif

#define DNSCORE_COND_WAIT_AUTO_TIME_OUT_DEBUG 0

#if DEBUG

void mutex_init_recursive(mutex_t *mtx);

#if MUTEX_PROCESS_SHARED_SUPPORTED
int mutex_init_process_shared(mutex_t *mtx);
#endif

void               mutex_init(mutex_t *mtx);
void               mutex_destroy(mutex_t *mtx);

static inline void mutex_finalize(mutex_t *mtx) { mutex_destroy(mtx); }

#if !DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

static inline void mutex_lock(mutex_t *mtx)
{
    int ret = pthread_mutex_lock(mtx);

    if(ret != 0)
    {
        abort();
    }
}

static inline bool mutex_trylock(mutex_t *mtx)
{
    int ret = pthread_mutex_trylock(mtx);
    if((ret != 0) && (ret != EBUSY))
    {
        abort();
    }
    return ret == 0;
}

static inline void mutex_unlock(mutex_t *mtx)
{
    int ret = pthread_mutex_unlock(mtx);
    if(ret != 0)
    {
        abort();
    }
}

static inline int mutex_lock_unchecked(mutex_t *mtx)
{
    int ret = pthread_mutex_lock(mtx);
    return ret;
}

static inline int mutex_unlock_unchecked(mutex_t *mtx)
{
    int ret = pthread_mutex_unlock(mtx);
    return ret;
}

#else

void mutex_lock(mutex_t *mtx);
bool mutex_trylock(mutex_t *mtx);
void mutex_unlock(mutex_t *mtx);
int  mutex_lock_unchecked(mutex_t *mtx);
int  mutex_unlock_unchecked(mutex_t *mtx);

#endif

#if MUTEX_PROCESS_SHARED_SUPPORTED
int cond_init_process_shared(cond_t *cond);
#endif

static inline void cond_init(cond_t *cond) { pthread_cond_init(cond, NULL); }

static inline void cond_wait(cond_t *cond, mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_wait_with_mutex(thread_self(), mtx);
#endif
#endif
    int ret = pthread_cond_wait(cond, mutex_pthread_mutex_get(mtx));

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_resume_with_mutex(thread_self(), mtx);
#endif
#endif

    if(ret != 0)
    {
        perror("cond_wait");
        fflush(stderr);
    }
}

static inline int cond_timedwait(cond_t *cond, mutex_t *mtx, uint64_t usec)
{
    struct timespec ts;
#if(defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0)) || defined(__MACH__)
    clock_gettime(CLOCK_REALTIME, &ts);
    usec *= 1000;
    ts.tv_nsec += usec;
    if(ts.tv_nsec > 1000000000LL)
    {
        ts.tv_sec += ts.tv_nsec / 1000000000LL;
        ts.tv_nsec = ts.tv_nsec % 1000000000LL;
    }
#else
    usec += timeus();
    usec *= 1000ULL;
    ts.tv_nsec = usec % 1000000000LL;
    ts.tv_sec = usec / 1000000000LL;
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_wait_with_mutex(thread_self(), mtx);
#endif
#endif

    int ret = pthread_cond_timedwait(cond, mutex_pthread_mutex_get(mtx), &ts);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_resume_with_mutex(thread_self(), mtx);
#endif
#endif

    return ret;
}

static inline int cond_timedwait_absolute(cond_t *cond, mutex_t *mtx, uint64_t usec_epoch)
{
    struct timespec ts;

    ts.tv_sec = usec_epoch / ONE_SECOND_US;
    ts.tv_nsec = (usec_epoch % ONE_SECOND_US) * 1000LL;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_wait_with_mutex(thread_self(), mtx);
#endif // DNSCORE_MUTEX_CONTENTION_MONITOR
#endif // DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

    int ret = pthread_cond_timedwait(cond, mutex_pthread_mutex_get(mtx), &ts);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_resume_with_mutex(thread_self(), mtx);
#endif // DNSCORE_MUTEX_CONTENTION_MONITOR
#endif // DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

    return ret;
}

static inline int cond_timedwait_absolute_ts(cond_t *cond, mutex_t *mtx, struct timespec *ts)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_wait_with_mutex(thread_self(), mtx);
#endif
#endif

    int ret = pthread_cond_timedwait(cond, mutex_pthread_mutex_get(mtx), ts);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_resume_with_mutex(thread_self(), mtx);
#endif
#endif

    return ret;
}

static inline void cond_wait_auto_time_out(cond_t *cond, mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_wait_with_mutex(thread_self(), mtx);
#endif
#endif

    int ret = pthread_cond_timedwait(cond, mutex_pthread_mutex_get(mtx), &__alarm__approximate_time_10s);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_resume_with_mutex(thread_self(), mtx);
#endif
#endif
#if __unix__
    if(ret != 0)
    {
#if DNSCORE_COND_WAIT_AUTO_TIME_OUT_DEBUG
        fprintf(stderr, "cond_wait_auto_time_out: %s\n", strerror(ret));
        fflush(stderr);
#endif
        time_t now = time(NULL);
        __alarm__approximate_time_10s.tv_sec = now + 10;
    }
#endif
}

// Only use this if there is only one possible thread waiting on
// the condition.

static inline void cond_notify_one(cond_t *cond) { pthread_cond_signal(cond); }

static inline void cond_notify(cond_t *cond) { pthread_cond_broadcast(cond); }

static inline void cond_finalize(cond_t *cond)
{
    for(;;)
    {
        int ret = pthread_cond_destroy(cond);

        if(ret == 0)
        {
            break;
        }

        if(ret != EBUSY)
        {
            // osformat(termerr, "async_wait_finalize: pthread_cond_destroy returned another error than EBUSY: %r",
            // MAKE_ERRNO_ERROR(ret)); flusherr();
            break;
        }

        usleep(5000);
    }
}

#endif // DEBUG

/** @} */

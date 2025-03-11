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

#include <dnscore/dnscore_config_features.h>
#include <dnscore/sys_types.h>
#include <dnscore/thread.h>

#include <dnscore/timems.h>
#if defined(__MACH__)
#include <dnscore/osx_clock_gettime.h>
#endif

#include <dnscore/mutex_defines.h>

#include <pthread.h>

#if !_POSIX_TIMERS
#ifndef _TIMEMS_H
int64_t timeus();
#endif
#endif

extern struct timespec __alarm__approximate_time_10s;

#if !DNSCORE_HAS_MUTEX_NOLOCK_CHECK

typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t  cond_t;
#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define COND_INITIALIZER  PTHREAD_COND_INITIALIZER

static inline pthread_mutex_t *mutex_pthread_mutex_get(mutex_t *mtx) { return mtx; }

#else

struct mutex_owner_s
{
    struct mutex_owner_s *next;
    thread_t              owner;
};

typedef struct mutex_owner_s mutex_owner_t;

struct mutex_s
{
    pthread_mutex_t _mtx;
    mutex_owner_t  *_owner;
    stacktrace      _st;
};

typedef struct mutex_s         mutex_t;

#define MUTEX_INITIALIZER {PTHREAD_MUTEX_INITIALIZER, NULL, NULL}
#define COND_INITIALIZER  PTHREAD_COND_INITIALIZER

static inline pthread_mutex_t *mutex_pthread_mutex_get(mutex_t *mtx) { return &mtx->_mtx; }

#endif

#if !DEBUG

void mutex_init_recursive(mutex_t *mtx);

#if MUTEX_PROCESS_SHARED_SUPPORTED
int mutex_init_process_shared(mutex_t *mtx);
#endif

void               mutex_init(mutex_t *mtx);
void               mutex_destroy(mutex_t *mtx);

static inline void mutex_finalize(mutex_t *mtx) { mutex_destroy(mtx); }

static inline int  mutex_lock(mutex_t *mtx)
{
    int ret = pthread_mutex_lock(mtx);
    return ret;
}

static inline bool mutex_trylock(mutex_t *mtx)
{
    bool ret = pthread_mutex_lock(mtx) == 0;
    return ret;
}

static inline int mutex_unlock(mutex_t *mtx)
{
    int ret = pthread_mutex_unlock(mtx);
    return ret;
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

#if MUTEX_PROCESS_SHARED_SUPPORTED
int cond_init_process_shared(cond_t *cond);
#endif

static inline void cond_init(cond_t *cond) { pthread_cond_init(cond, NULL); }

static inline int  cond_wait(cond_t *cond, mutex_t *mtx)
{
    int ret = pthread_cond_wait(cond, mtx);
    return ret;
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
    int ret = pthread_cond_timedwait(cond, mutex_pthread_mutex_get(mtx), &ts);
    return ret;
}

static inline int cond_timedwait_absolute(cond_t *cond, mutex_t *mtx, uint64_t usec_epoch)
{
    struct timespec ts;
    ts.tv_sec = usec_epoch / ONE_SECOND_US;
    ts.tv_nsec = (usec_epoch % ONE_SECOND_US) * 1000LL;
    int ret = pthread_cond_timedwait(cond, mutex_pthread_mutex_get(mtx), &ts);
    return ret;
}

static inline int cond_timedwait_absolute_ts(cond_t *cond, mutex_t *mtx, struct timespec *ts)
{
    int ret = pthread_cond_timedwait(cond, mutex_pthread_mutex_get(mtx), ts);
    return ret;
}

static inline void cond_wait_auto_time_out(cond_t *cond, mutex_t *mtx)
{
    int ret = pthread_cond_timedwait(cond, mutex_pthread_mutex_get(mtx), &__alarm__approximate_time_10s);
#if __unix__
    if(ret != 0) // not zero -> error -> push the time 10 seconds in the future
    {
        time_t now = time(NULL);
        __alarm__approximate_time_10s.tv_sec = now + 10;
    }
#endif // __unix__
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

#else

#define DNSCORE_MUTEX_MUTEX_H 1

#include <dnscore/mutex_debug.h>

#undef DNSCORE_MUTEX_MUTEX_H

#endif

/** @} */

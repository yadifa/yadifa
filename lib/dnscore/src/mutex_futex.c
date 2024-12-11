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

/**-----------------------------------------------------------------------------
 * @defgroup threading mutexes, ...
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"

#if DNSCORE_FUTEX_SUPPORT

#define DNSCORE_FUTEX_DEBUG 0

#if DNSCORE_FUTEX_DEBUG
#if !DNSCORE_FUTEX_TRACKING
#error "DNSCORE_FUTEX_DEBUG enabled without DNSCORE_FUTEX_TRACKING"
#endif
#endif

#if __linux__
#include <linux/futex.h>
#elif __OpenBSD__
#include <sys/futex.h>
#endif

#include <sys/syscall.h>
#include <stdint.h>
#include <sys/time.h>

#define FUTEX_EXPLICIT 0

void mutex_futex_init(mutex_futex_t *mtx)
{
#if FUTEX_EXPLICIT
    atomic_store_explicit(&mtx->addr, 0, memory_order_relaxed);
#else
    atomic_store(&mtx->addr, 0);
#endif
}

void               mutex_futex_finalise(mutex_futex_t *mtx) { (void)mtx; }

static inline int  sys_futex(atomic_uint *uaddr, int futex_op, uint32_t val) { return syscall(SYS_futex, uaddr, futex_op, val, NULL, NULL, 0); }

static inline int  sys_futex_timeout(atomic_uint *uaddr, int futex_op, uint32_t val, const struct timespec *timeout) { return syscall(SYS_futex, uaddr, futex_op, val, timeout, NULL, 0); }

static inline uint cas(atomic_uint *addr, uint expected, uint exchange_with)
{
    uint *expectedp = &expected;
#if FUTEX_EXPLICIT
    atomic_compare_exchange_strong_explicit(addr, expectedp, exchange_with, memory_order_relaxed, memory_order_relaxed);
#else
    atomic_compare_exchange_strong(addr, expectedp, exchange_with);
#endif
    return expected;
}

#if __linux__ && 0
#define FUTEX_WAIT_OP (FUTEX_WAIT | FUTEX_PRIVATE_FLAG) // 25% faster if not process-shared
#define FUTEX_WAKE_OP (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#else
#define FUTEX_WAIT_OPERATION FUTEX_WAIT
#define FUTEX_WAKE_OPERATION FUTEX_WAKE
#endif

int mutex_futex_lock(mutex_futex_t *mtx)
{
    int val;
    int ret;

#if DNSCORE_FUTEX_DEBUG
    debug_osformatln(termout, "mutex_futex_lock(%p) lock", mtx);
#endif

    if((val = cas(&mtx->addr, 0, 1)) == 0)
    {
#if DNSCORE_FUTEX_TRACKING
        atomic_store(&mtx->owner, gettid());
#endif
#if DNSCORE_FUTEX_DEBUG
        debug_osformatln(termout, "mutex_futex_lock(%p) locked", mtx);
#endif
        return SUCCESS;
    }

    // wait

    do
    {
        if((val == 2) || (cas(&mtx->addr, 1, 2) != 0))
        {
            ret = sys_futex(&mtx->addr, FUTEX_WAIT_OPERATION, 2);

            if(ret < 0)
            {
                int err = errno;
                if(err != EAGAIN)
                {
#if DNSCORE_FUTEX_DEBUG
                    debug_osformatln(termout, "mutex_futex_lock(%p) error=%i", mtx, err);
#endif
                    return MAKE_ERRNO_ERROR(err);
                }
            }
        }
    } while((val = cas(&mtx->addr, 0, 2)) != 0);

#if DNSCORE_FUTEX_TRACKING
    atomic_store(&mtx->owner, gettid());
#endif

#if DNSCORE_FUTEX_DEBUG
    debug_osformatln(termout, "mutex_futex_lock(%p) locked", mtx);
#endif

    return SUCCESS;
}

bool mutex_futex_trylock(mutex_futex_t *mtx)
{
    if((cas(&mtx->addr, 0, 1)) == 0)
    {
#if DNSCORE_FUTEX_TRACKING
        atomic_store(&mtx->owner, gettid());
#endif
        return true;
    }

    return false;
}

int mutex_futex_lock_timeout(mutex_futex_t *mtx, int64_t relative_usec)
{
    int val;
    int ret;

    if((val = cas(&mtx->addr, 0, 1)) == 0)
    {
#if DNSCORE_FUTEX_TRACKING
        atomic_store(&mtx->owner, gettid());
#endif
        return SUCCESS;
    }

    int64_t last = timeus();

    relative_usec *= 1000;

    // wait

    do
    {
        if((val == 2) || (cas(&mtx->addr, 1, 2) != 0))
        {
            struct timespec timeout = {relative_usec / ONE_SECOND_NS, relative_usec % ONE_SECOND_NS};

            ret = sys_futex_timeout(&mtx->addr, FUTEX_WAIT_OPERATION, 2, &timeout);

            if(ret < 0)
            {
                int err = errno;

                if(err == ETIMEDOUT)
                {
                    return MAKE_ERRNO_ERROR(ETIMEDOUT);
                }

                if(err != EAGAIN)
                {
                    return MAKE_ERRNO_ERROR(err);
                }

                int64_t now = timeus() * 1000LL;
                int64_t dt = now - last;
                relative_usec -= dt;
                last = now;
            }
        }
    } while((val = cas(&mtx->addr, 0, 2)) != 0);

#if DNSCORE_FUTEX_TRACKING
    atomic_store(&mtx->owner, gettid());
#endif

    return SUCCESS;
}

int mutex_futex_unlock(mutex_futex_t *mtx)
{
    int ret = SUCCESS;

#if DNSCORE_FUTEX_DEBUG
    debug_osformatln(termout, "mutex_futex_unlock(%p) unlock", mtx);
#endif

#if DNSCORE_FUTEX_TRACKING
    atomic_store(&mtx->owner, 0);
#endif

    if(
#if FUTEX_EXPLICIT
        atomic_fetch_sub_explicit(&mtx->addr, 1, memory_order_relaxed)
#else
        atomic_fetch_sub(&mtx->addr, 1)
#endif
        != 1)
    {
#if FUTEX_EXPLICIT
        atomic_store_explicit(&mtx->addr, 0, memory_order_relaxed);
#else
        atomic_store(&mtx->addr, 0);
#endif
        ret = sys_futex(&mtx->addr, FUTEX_WAKE_OPERATION, 1);
        if(ret < 0)
        {
            int err = errno;
            if(err != EAGAIN)
            {
#if DNSCORE_FUTEX_DEBUG
                debug_osformatln(termout, "mutex_futex_unlock(%p) error=%i", mtx, err);
#endif
                return MAKE_ERRNO_ERROR(err);
            }
        }
    }

#if DNSCORE_FUTEX_DEBUG
    debug_osformatln(termout, "mutex_futex_unlock(%p) unlocked", mtx);
#endif

    return ret;
}

void cond_futex_init(cond_futex_t *cond)
{
    atomic_init(&cond->addr, 0);
#if DNSCORE_FUTEX_TRACKING
    atomic_init(&cond->count, 0);
#endif
}

void cond_futex_finalise(cond_futex_t *cond) { (void)cond; }

int  cond_futex_wait(cond_futex_t *cond, mutex_futex_t *mtx)
{
#if DNSCORE_FUTEX_DEBUG
#if DNSCORE_FUTEX_TRACKING
    debug_osformatln(termout, "cond_futex_wait(%p={%08x,%u},%p) wait", cond, atomic_load(&cond->addr), atomic_load(&cond->count), mtx);
#endif
#endif
#if FUTEX_EXPLICIT
    uint current = atomic_fetch_add_explicit(&cond->addr, 1, memory_order_relaxed) + 1;
#else
    uint current = atomic_fetch_add(&cond->addr, 1) + 1;
#endif
#if DNSCORE_FUTEX_TRACKING
    atomic_fetch_add(&cond->count, 1);
#endif
    for(;;)
    {
#if DNSCORE_FUTEX_DEBUG
        debug_osformatln(termout, "cond_futex_wait(%p={%08x,%u},%p) futex", cond, atomic_load(&cond->addr), atomic_load(&cond->count), mtx);
#endif
        mutex_futex_unlock(mtx);

        int ret = sys_futex(&cond->addr, FUTEX_WAIT_OPERATION, current);
#if DNSCORE_FUTEX_DEBUG
        debug_osformatln(termout, "cond_futex_wait(%p={%08x,%u},%p) sys_futex=%i, was=%i", cond, atomic_load(&cond->addr), atomic_load(&cond->count), mtx, ret, current);
#endif
        if(ret < 0)
        {
            int err = errno;
#if DNSCORE_FUTEX_DEBUG
            debug_osformatln(termout, "cond_futex_wait(%p={%08x,%u},%p) sys_futex=%i, err=%s", cond, atomic_load(&cond->addr), atomic_load(&cond->count), mtx, ret, strerror(err));
#endif
            if(err != EAGAIN)
            {
#if DNSCORE_FUTEX_TRACKING
                atomic_fetch_sub(&cond->count, 1);
#endif
                return MAKE_ERRNO_ERROR(err);
            }
        }
        mutex_futex_lock(mtx);
        if(
#if FUTEX_EXPLICIT
            atomic_load_explicit(&cond->addr, memory_order_relaxed)
#else
            atomic_load(&cond->addr)
#endif
            != current)
        {
            break;
        }
    }

#if DNSCORE_FUTEX_TRACKING
    atomic_fetch_sub(&cond->count, 1);
#endif
#if DNSCORE_FUTEX_DEBUG
    debug_osformatln(termout, "cond_futex_wait(%p={%08x,%u},%p) != %i", cond, atomic_load(&cond->addr), atomic_load(&cond->count), mtx, current);
#endif
    return SUCCESS;
}

int cond_futex_timedwait(cond_futex_t *cond, mutex_futex_t *mtx, int64_t relative_usec)
{
    int64_t last = timeus();
    relative_usec *= 1000LL; // because it has to be NSEC
#if FUTEX_EXPLICIT
    uint current = atomic_fetch_add_explicit(&cond->addr, 1, memory_order_relaxed) + 1;
#else
    uint current = atomic_fetch_add(&cond->addr, 1) + 1;
#endif
#if DNSCORE_FUTEX_TRACKING
    atomic_fetch_add(&cond->count, 1);
#endif
    for(;;)
    {
        mutex_futex_unlock(mtx);
        struct timespec timeout = {relative_usec / ONE_SECOND_NS, relative_usec % ONE_SECOND_NS};
        int             ret = sys_futex_timeout(&cond->addr, FUTEX_WAIT_OPERATION, current, &timeout);
        if(ret < 0)
        {
            int err = errno;
            if(err != EAGAIN)
            {
#if DNSCORE_FUTEX_TRACKING
                atomic_fetch_sub(&cond->count, 1);
#endif
                return MAKE_ERRNO_ERROR(err);
            }
        }
        mutex_futex_lock(mtx);
        if(
#if FUTEX_EXPLICIT
            atomic_load_explicit(&cond->addr, memory_order_relaxed)
#else
            atomic_load(&cond->addr)
#endif
            != current)
        {
            break;
        }

        int64_t now = timeus() * 1000LL;
        int64_t dt = now - last;
        relative_usec -= dt;
        if(relative_usec < 0)
        {
            relative_usec = 0;
        }
        last = now;
    }

#if DNSCORE_FUTEX_TRACKING
    atomic_fetch_sub(&cond->count, 1);
#endif

    return SUCCESS;
}

int cond_futex_notify(cond_futex_t *cond)
{
#if DNSCORE_FUTEX_DEBUG
    debug_osformatln(termout, "cond_futex_notify(%p={%08x,%u})", cond, atomic_load(&cond->addr), atomic_load(&cond->count));
#endif
#if FUTEX_EXPLICIT
    atomic_fetch_add_explicit(&cond->addr, 1, memory_order_relaxed);
#else
    atomic_fetch_add(&cond->addr, 1);
#endif
    sys_futex(&cond->addr, FUTEX_WAKE_OPERATION, INT32_MAX);
    return SUCCESS;
}

int cond_futex_notify_one(cond_futex_t *cond)
{
#if DNSCORE_FUTEX_DEBUG
    debug_osformatln(termout, "cond_futex_notify(%p={%08x,%u})", cond, atomic_load(&cond->addr), atomic_load(&cond->count));
#endif
#if FUTEX_EXPLICIT
    atomic_fetch_add_explicit(&cond->addr, 1, memory_order_relaxed);
#else
    atomic_fetch_add(&cond->addr, 1);
#endif
    sys_futex(&cond->addr, FUTEX_WAKE_OPERATION, 1);
    return SUCCESS;
}
#else

void dnscore_futex_not_supported() {}

#endif

/** @} */

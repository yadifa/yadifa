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

#include "dnscore/mutex_shared_group.h"
#include "dnscore/mutex_contention_monitor.h"

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
static const char *shared_group_mutex_type_name = "shared_group_mutex_lock";
#endif
#endif

/*
 * Group mutex lock
 */

void shared_group_shared_mutex_init(shared_group_shared_mutex_t *smtx)
{
    mutex_init(&smtx->mutex);
    cond_init(&smtx->cond);
    smtx->rc = 0;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(smtx, false);
#endif
#endif
}

void shared_group_shared_mutex_init_recursive(shared_group_shared_mutex_t *smtx)
{
    mutex_init_recursive(&smtx->mutex);
    cond_init(&smtx->cond);
    smtx->rc = 0;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(smtx, true);
#endif
#endif
}

void shared_group_shared_mutex_destroy(shared_group_shared_mutex_t *smtx)
{
    yassert(smtx->rc == 0);

    cond_finalize(&smtx->cond);
    mutex_destroy(&smtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_object_destroy(smtx);
#endif
#endif
}

void shared_group_mutex_init(shared_group_mutex_t *mtx, shared_group_shared_mutex_t *smtx, const char *name)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: init mutex@%p+%p '%s'", mtx, smtx, name);
#endif
#else
    (void)name;
#endif

    mutex_lock(&smtx->mutex);
    smtx->rc++;
    mutex_unlock(&smtx->mutex);
    mtx->shared_mutex = smtx;

    mtx->count = 0;
    mtx->owner = GROUP_MUTEX_NOBODY;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(mtx, true);
#endif
#endif
}

bool shared_group_mutex_islocked(shared_group_mutex_t *mtx)
{
    mutex_lock(&mtx->shared_mutex->mutex);
    bool r = mtx->owner != 0;
    mutex_unlock(&mtx->shared_mutex->mutex);
    return r;
}

bool shared_group_mutex_islocked_by(shared_group_mutex_t *mtx, uint8_t owner)
{
    mutex_lock(&mtx->shared_mutex->mutex);
    bool r = mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG);
    mutex_unlock(&mtx->shared_mutex->mutex);
    return r;
}

void shared_group_mutex_lock(shared_group_mutex_t *mtx, uint8_t owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: locking mutex@%p for %x", mtx, owner);
#endif
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), shared_group_mutex_type_name);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);

    for(;;)
    {
        /*
            A simple way to ensure that a lock can be shared
            by similar entities or not.
            Sharable entities have their msb off.
        */

        uint8_t co = mtx->owner & GROUP_MUTEX_LOCKMASK_FLAG;

        if(co == GROUP_MUTEX_NOBODY || co == owner)
        {
            yassert(mtx->count != INT32_MAX);

            mtx->owner = owner & GROUP_MUTEX_LOCKMASK_FLAG;
            mtx->count++;
            break;
        }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_wait(mcm);
#endif
#endif
        cond_wait(&mtx->shared_mutex->cond, &mtx->shared_mutex->mutex);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_resume(mcm);
#endif
#endif
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_end(mcm);
#endif
#endif

    mutex_unlock(&mtx->shared_mutex->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif
}

bool shared_group_mutex_trylock(shared_group_mutex_t *mtx, uint8_t owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: trying to lock mutex@%p for %x", mtx, owner);
#endif
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), shared_group_mutex_type_name);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);

    uint8_t co = mtx->owner & GROUP_MUTEX_LOCKMASK_FLAG;

    if(co == GROUP_MUTEX_NOBODY || co == owner)
    {
        yassert(mtx->count != INT32_MAX);

        mtx->owner = owner & GROUP_MUTEX_LOCKMASK_FLAG;
        mtx->count++;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_end(mcm);
#endif
#endif
        mutex_unlock(&mtx->shared_mutex->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
        log_debug7("shared_group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif
        return true;
    }
    else
    {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_fail(mcm);
#endif
#endif
        mutex_unlock(&mtx->shared_mutex->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
        log_debug7("shared_group_mutex: failed to lock mutex@%p for %x", mtx, owner);
#endif
#endif

        return false;
    }
}

void shared_group_mutex_unlock(shared_group_mutex_t *mtx, uint8_t owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: unlocking mutex@%p for %x (owned by %x)", mtx, owner, mtx->owner);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);

    yassert(mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->count != 0);

    (void)owner;

    mtx->count--;

    if(mtx->count == 0)
    {
        mtx->owner = GROUP_MUTEX_NOBODY;

        // wake up all the ones that were waiting for a clean ownership

        cond_notify(&mtx->shared_mutex->cond);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), mtx);
#endif
#endif

    mutex_unlock(&mtx->shared_mutex->mutex);
}

bool shared_group_mutex_transferlock(shared_group_mutex_t *mtx, uint8_t owner, uint8_t newowner)
{
    bool r;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: transferring ownership of mutex@%p from %x to %x (owned by %x)", mtx, owner, newowner, mtx->owner);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);

    uint8_t co = owner & GROUP_MUTEX_LOCKMASK_FLAG;

    if((r = (co == mtx->owner)))
    {
        mtx->owner = newowner;
    }

    mutex_unlock(&mtx->shared_mutex->mutex);

    return r;
}

void shared_group_mutex_destroy(shared_group_mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: destroy mutex@%p", mtx);
#endif
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_object_destroy(mtx);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);
    mtx->shared_mutex->rc--;
    mutex_unlock(&mtx->shared_mutex->mutex);
}

/** @} */

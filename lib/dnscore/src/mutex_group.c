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

#include "dnscore/mutex_group.h"
#include "dnscore/mutex_contention_monitor.h"

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
static const char *group_mutex_type_name = "group_mutex_lock";
#endif
#endif

void group_mutex_init(group_mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: init mutex@%p", mtx);
#endif
#endif

    mutex_init(&mtx->mutex);
    cond_init(&mtx->cond);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(mtx, false);
#endif
#endif
    mtx->count = 0;
    mtx->owner = GROUP_MUTEX_NOBODY;
    mtx->reserved_owner = GROUP_MUTEX_NOBODY;
}

bool group_mutex_islocked(group_mutex_t *mtx)
{
    mutex_lock(&mtx->mutex);
    bool r = mtx->owner != 0;
    mutex_unlock(&mtx->mutex);
    return r;
}

void group_mutex_lock(group_mutex_t *mtx, uint8_t owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), group_mutex_type_name);
#endif
#endif
    mutex_lock(&mtx->mutex);

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
        /*
        #if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        #if DNSCORE_MUTEX_CONTENTION_MONITOR
                mutex_contention_lock_wait(mcm); // counts the loops
        #endif
        #endif
        */
        cond_wait(&mtx->cond, &mtx->mutex);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_end(mcm);
#endif
#endif

    mutex_unlock(&mtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif
}

bool group_mutex_trylock(group_mutex_t *mtx, uint8_t owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: trying to lock mutex@%p for %x", mtx, owner);
#endif
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), group_mutex_type_name);
#endif
#endif
    mutex_lock(&mtx->mutex);

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

        mutex_unlock(&mtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
        log_debug7("group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif
        return true;
    }
    else
    {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#if DNSCORE_MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_fail(mcm);
#endif
#endif
        mutex_unlock(&mtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
        log_debug7("group_mutex: failed to lock mutex@%p for %x", mtx, owner);
#endif
#endif
        return false;
    }
}

void group_mutex_unlock(group_mutex_t *mtx, uint8_t owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: unlocking mutex@%p for %x (owned by %x)", mtx, owner, mtx->owner);
#endif
#endif
    mutex_lock(&mtx->mutex);

    yassert(mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->count != 0);

    (void)owner;

    mtx->count--;

    if(mtx->count == 0)
    {
        mtx->owner = GROUP_MUTEX_NOBODY;

        // wake up all the ones that were waiting for a clean ownership

        cond_notify(&mtx->cond);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), mtx);
#endif
#endif

    mutex_unlock(&mtx->mutex);
}

void group_mutex_double_lock(group_mutex_t *mtx, uint8_t owner, uint8_t secondary_owner)
{
    yassert(owner == GROUP_MUTEX_READ);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1

#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: double-locking mutex@%p for %x", mtx, secondary_owner);
#endif

#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), group_mutex_type_name);
#endif
#endif
    mutex_lock(&mtx->mutex);

    for(;;)
    {
        /*
         * A simple way to ensure that a lock can be shared
         * by similar entities or not.
         * Sharable entities have their msb off.
         */

        uint8_t so = mtx->reserved_owner & GROUP_MUTEX_LOCKMASK_FLAG;

        if(so == GROUP_MUTEX_NOBODY || so == secondary_owner)
        {
            uint8_t co = mtx->owner & GROUP_MUTEX_LOCKMASK_FLAG;

            if(co == GROUP_MUTEX_NOBODY || co == owner)
            {
                yassert(!SIGNED_VAR_VALUE_IS_MAX(mtx->count));

                mtx->owner = owner & GROUP_MUTEX_LOCKMASK_FLAG;
                mtx->count++;
                mtx->reserved_owner = secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG;

                break;
            }
        }
        else
        {
            // the secondary owner is already taken
        }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_wait(mcm);
#endif
#endif
        cond_wait(&mtx->cond, &mtx->mutex);
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

    mutex_unlock(&mtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: double-locked mutex@%p for %x", mtx, secondary_owner);
#endif
#endif
}

void group_mutex_double_unlock(group_mutex_t *mtx, uint8_t owner, uint8_t secondary_owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: double-unlocking mutex@%p for %x (owned by %x)", mtx, secondary_owner, mtx->reserved_owner);
#endif
#endif

    yassert(owner == GROUP_MUTEX_READ);

    mutex_lock(&mtx->mutex);

    yassert(mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->reserved_owner == (secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->count != 0);

    (void)owner;
    (void)secondary_owner;

    mtx->reserved_owner = GROUP_MUTEX_NOBODY;

    --mtx->count;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: double-unlocked mutex@%p for %x,%x", mtx, owner, secondary_owner);
#endif
#endif

    yassert((mtx->owner & 0xc0) == 0);

    if(mtx->count == 0)
    {
        mtx->owner = GROUP_MUTEX_NOBODY;
        cond_notify(&mtx->cond);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), mtx);
#endif
#endif

    mutex_unlock(&mtx->mutex);
}

void group_mutex_exchange_locks(group_mutex_t *mtx, uint8_t owner, uint8_t secondary_owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: exchanging-locks of mutex@%p %x,%x (", mtx, owner, secondary_owner, mtx->owner, mtx->reserved_owner);
#endif
#endif

    yassert(owner == GROUP_MUTEX_READ || secondary_owner == GROUP_MUTEX_READ);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    int64_t start = timeus();
#endif

    mutex_lock(&mtx->mutex);

    if((mtx->owner != (owner & GROUP_MUTEX_LOCKMASK_FLAG)) || (mtx->reserved_owner != (secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG)) || (mtx->count == 0))
    {
#ifdef MODULE_MSG_HANDLE
        debug_log_stacktrace(g_system_logger, MSG_ERR, "group_mutex_exchange_locks");
#endif
        abort();
    }
#else
    mutex_lock(&mtx->mutex);

    yassert(mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->reserved_owner == (secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->count != 0);
#endif

#if DEBUG
    if((mtx->owner != (owner & GROUP_MUTEX_LOCKMASK_FLAG)) || (mtx->count == 0))
    {
        mutex_unlock(&mtx->mutex);
        yassert(mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG));
        yassert(mtx->count != 0);
        abort(); // unreachable
    }

    if(mtx->reserved_owner != (secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG))
    {
        mutex_unlock(&mtx->mutex);
        yassert(mtx->reserved_owner != (secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG));
        abort(); // unreachable
    }
#endif

    // wait to be the last one

    while(mtx->count != 1)
    {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
        int64_t d = timeus() - start;
        if(d > MUTEX_WAITED_TOO_MUCH_TIME_US)
        {
            log_warn("group_mutex_exchange_locks(%p,%x,%x) : waited for %llius already ...", mtx, owner, secondary_owner, d);
            debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_WARNING, "group_mutex_exchange_locks:");
        }
#endif
#endif
        cond_timedwait(&mtx->cond, &mtx->mutex, 100);
    }

    mtx->owner = secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG;
    mtx->reserved_owner = owner & GROUP_MUTEX_LOCKMASK_FLAG;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: exchanged locks of mutex@%p to %x, %x", mtx, secondary_owner, owner);
#endif
#endif

    if((secondary_owner & GROUP_MUTEX_EXCLUSIVE_FLAG) == 0)
    {
        cond_notify(&mtx->cond);
    }

    mutex_unlock(&mtx->mutex);
}

void group_mutex_destroy(group_mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: destroy mutex@%p", mtx);
#endif
#endif

    mutex_lock(&mtx->mutex);
    yassert(mtx->count == 0);

    mutex_unlock(&mtx->mutex);

    group_mutex_lock(mtx, GROUP_MUTEX_DESTROY);
    group_mutex_unlock(mtx, GROUP_MUTEX_DESTROY);

    cond_notify(&mtx->cond);
    cond_finalize(&mtx->cond);
    mutex_destroy(&mtx->mutex);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_object_destroy(mtx);
#endif
#endif
}

/** @} */

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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <unistd.h>
#include <arpa/inet.h>

#include <dnscore/mutex.h>

#include <dnscore/dnscore.h>

#include <dnscore/logger.h>
#include <dnsdb/zdb-zone-lock-monitor.h>

#include "dnsdb/zdb.h"

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_error.h"

#include "dnsdb/dnsrdata.h"

#if ZDB_HAS_NSEC_SUPPORT
#include "dnsdb/nsec.h"
#endif
#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#include <dnscore/ptr_set.h>
#include <dnsdb/zdb-zone-lock-monitor.h>
#endif

#if DEBUG
#define ZONE_MUTEX_LOG 0    // set this to 0 to disable in DEBUG
#else
#define ZONE_MUTEX_LOG 0
#endif

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define MUTEX_LOCKED_TOO_MUCH_TIME_US 5000000
#define MUTEX_WAITED_TOO_MUCH_TIME_US 2000000

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

static mutex_t zdb_zone_lock_set_mtx = MUTEX_INITIALIZER;
static ptr_set zdb_zone_lock_set = PTR_SET_PTR_EMPTY;

void
zdb_zone_lock_set_add(zdb_zone *zone)
{
    mutex_lock(&zdb_zone_lock_set_mtx);
    ptr_node *node = ptr_set_insert(&zdb_zone_lock_set, zone);
    node->value = zone;
    mutex_unlock(&zdb_zone_lock_set_mtx);
}

void
zdb_zone_lock_set_del(zdb_zone *zone)
{
    mutex_lock(&zdb_zone_lock_set_mtx);
    ptr_set_delete(&zdb_zone_lock_set, zone);
    mutex_unlock(&zdb_zone_lock_set_mtx);
}

static s64 zdb_zone_lock_set_monitor_last_duration = 0;
static s64 zdb_zone_lock_set_monitor_last_time = 0;

#if DEBUG
const char* zdb_zone_lock_names[11]=
{
    "NOBODY",       // 0x00
    "SIMPLEREADER", // 0x01 non-conflicting
    "RRSIG_UPDATER",// 0x82 conflicting
    "3?",
    "XFR",          // 0x84 conflicting
    "REFRESH",      // 0x85 conflicting
    "DYNUPDATE",    // 0x86 conflicting
    "UNFREEZE",     // 0x87 conflicting
    "INVALIDATE",   // 0x88 conflicting
    "REPLACE",      // 0x89 conflicting
    "LOAD"          // 0x8a conflicting
    // "DESTROY"       // 0xFF conflicting, can never be launched more than once.  The zone will be destroyed before unlock.
};

#endif

void
zdb_zone_lock_set_monitor()
{
    s64 now = timeus();
    
    if(now - zdb_zone_lock_set_monitor_last_time < zdb_zone_lock_set_monitor_last_duration)
    {
        return;
    }
    
    zdb_zone_lock_set_monitor_last_time = now;
    
    mutex_lock(&zdb_zone_lock_set_mtx);
    ptr_set_iterator iter;
    ptr_set_iterator_init(&zdb_zone_lock_set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        zdb_zone *zone = (zdb_zone*)node->key;
        
        u8 owner = zone->lock_owner;
        if(owner == GROUP_MUTEX_NOBODY)
        {
            continue;
        }
        
        s64 ts = zone->lock_timestamp;
        stacktrace trace = zone->lock_trace;
        thread_t id = zone->lock_id;
        if(ts < now)
        {
            u64 dt = now - ts;
            if(dt > MUTEX_LOCKED_TOO_MUCH_TIME_US)
            {
                // locked for 5 seconds ... trouble
#if !DEBUG
                log_warn("zdb_zone_lock@%p: %{dnsname}: locked by %x for %lluus by %p", zone, zone->origin, owner, dt, (intptr)id);
#else
                if(owner <= 10)
                {
                    log_warn("zdb_zone_lock@%p: %{dnsname}: locked by %s for %lluus by %p", zone, zone->origin, zdb_zone_lock_names[owner], dt, (intptr)id);
                }
                else
                {
                    log_warn("zdb_zone_lock@%p: %{dnsname}: locked by %x for %lluus by %p", zone, zone->origin, owner, dt, (intptr)id);
                }
#endif
                debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, trace);
            }
        }
    }
    mutex_unlock(&zdb_zone_lock_set_mtx);
    s64 after = timeus();
    if(after - now > zdb_zone_lock_set_monitor_last_duration)
    {
        zdb_zone_lock_set_monitor_last_duration = after - now;
    }
}
#endif

bool
zdb_zone_islocked(zdb_zone *zone)
{
    mutex_t *mutex = &zone->lock_mutex;   
    mutex_lock(mutex);
    u8 owner = zone->lock_owner;
    mutex_unlock(mutex);
    
    return owner != 0;
}

bool
zdb_zone_islocked_weak(const zdb_zone *zone)
{
    u8 owner = zone->lock_owner;
    
    return owner != 0;
}

/**
 * Returns TRUE iff the zone is locked by a writer (any other owner value than nobody and simple reader)
 * 
 * @param zone
 * @return 
 */

bool
zdb_zone_iswritelocked(zdb_zone *zone)
{
    mutex_t *mutex = &zone->lock_mutex;   
    mutex_lock(mutex);
    u8 owner = zone->lock_owner;
    mutex_unlock(mutex);
    
    return owner > ZDB_ZONE_MUTEX_SIMPLEREADER;
}

void
zdb_zone_lock(zdb_zone *zone, u8 owner)
{

#if ZONE_MUTEX_LOG
    log_debug7("acquiring lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
    u64 start = timeus();
#endif
#endif

#if MUTEX_CONTENTION_MONITOR
    struct mutex_contention_monitor_s *mcm = mutex_contention_lock_begin(thread_self(), zone, debug_stacktrace_get(), "zdb_zone");
#endif

    mutex_t *mutex = &zone->lock_mutex;
    mutex_lock(mutex);
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    struct zdb_zone_lock_monitor *holder = zdb_zone_lock_monitor_new(zone, owner, 0);
#endif
    
    for(;;)
    {
        /*
        A simple way to ensure that a lock can be shared
        by similar entities or not.
        Sharable entities have their msb off.
        */

        u8 co = zone->lock_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
        
        if(co == GROUP_MUTEX_NOBODY || co == owner)
        {
            yassert(!SIGNED_VAR_VALUE_IS_MAX(zone->lock_count));

            zone->lock_owner = owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
            zone->lock_count++;

            break;
        }
        
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
        zdb_zone_lock_monitor_waits(holder);
#endif
        
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
        s64 d = timeus() - start;
        if(d > MUTEX_WAITED_TOO_MUCH_TIME_US)
        {
            log_warn("zdb_zone_lock(%{dnsname},%x) : waited for %llius already ...", zone->origin, owner, d);
            debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_WARNING, "zdb_zone_double_lock:");
        }
        cond_timedwait(&zone->lock_cond, mutex, MUTEX_WAITED_TOO_MUCH_TIME_US);
#else
        cond_wait(&zone->lock_cond, mutex);
#endif
        
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
        zdb_zone_lock_monitor_resumes(holder);
#endif
    }

#if ZDB_ZONE_LOCK_HAS_OWNER_ID
    zone->lock_last_owner_id = thread_self();
#endif
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    zdb_zone_lock_monitor_locks(holder);
#endif
    
    mutex_unlock(mutex);

#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_end(mcm);
#endif
    
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = debug_stacktrace_get();
    zone->lock_id = thread_self();
    zone->lock_timestamp = timeus();

    zdb_zone_lock_set_add(zone);
#endif
}

bool
zdb_zone_trylock(zdb_zone *zone, u8 owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("trying to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

#if MUTEX_CONTENTION_MONITOR
    struct mutex_contention_monitor_s *mcm = mutex_contention_lock_begin(thread_self(), zone, debug_stacktrace_get(), "zdb_zone");
#endif

    mutex_lock(&zone->lock_mutex);
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    struct zdb_zone_lock_monitor *holder = zdb_zone_lock_monitor_new(zone, owner, 0);
#endif

    u8 co = zone->lock_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
    
    if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
    {
        yassert(!SIGNED_VAR_VALUE_IS_MAX(zone->lock_count));

        zone->lock_owner = owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
        zone->lock_count++;

#if ZONE_MUTEX_LOG
        log_debug7("acquired lock for zone %{dnsname}@%p for %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif
        
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
        zdb_zone_lock_monitor_locks(holder);
#endif

#if ZDB_ZONE_LOCK_HAS_OWNER_ID
        zone->lock_last_owner_id = thread_self();
#endif

        mutex_unlock(&zone->lock_mutex);
        
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
        zone->lock_trace = debug_stacktrace_get();
        zone->lock_id = thread_self();
        zone->lock_timestamp = timeus();

        zdb_zone_lock_set_add(zone);
#endif

#if MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_end(mcm);
#endif
        return TRUE;
    }
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    zdb_zone_lock_monitor_cancels(holder);
#endif

    mutex_unlock(&zone->lock_mutex);

#if ZONE_MUTEX_LOG
    log_debug7("failed to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_fail(mcm);
#endif

    return FALSE;
}

bool
zdb_zone_trylock_wait(zdb_zone *zone, u64 usec, u8 owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("trying to acquire lock for %lluus for zone %{dnsname}@%p for %x", usec, zone->origin, zone, owner);
#endif

#if MUTEX_CONTENTION_MONITOR
    struct mutex_contention_monitor_s *mcm = mutex_contention_lock_begin(thread_self(), zone, debug_stacktrace_get(), "zdb_zone");
#endif
    
    u64 start = timeus();
    bool ret = FALSE;

    mutex_t *mutex = &zone->lock_mutex;
    
    mutex_lock(mutex);
    
    for(;;)
    {
        /*
        A simple way to ensure that a lock can be shared
        by similar entities or not.
        Sharable entities have their msb off.
        */

        u8 co = zone->lock_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
        
        if(co == GROUP_MUTEX_NOBODY || co == owner)
        {
            yassert(!SIGNED_VAR_VALUE_IS_MAX(zone->lock_count));

            zone->lock_owner = owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
            zone->lock_count++;

            ret = TRUE;
            break;
        }
        
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        s64 d = timeus() - start;
        if(d > MUTEX_WAITED_TOO_MUCH_TIME_US)
        {
            log_warn("zdb_zone_lock(%{dnsname},%x) : waited for %llius already ...", zone->origin, owner, d);
            debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_WARNING, "zdb_zone_double_lock:");
        }
        cond_timedwait(&zone->lock_cond, mutex, MIN(MUTEX_WAITED_TOO_MUCH_TIME_US, usec));
#else
        cond_timedwait(&zone->lock_cond, mutex, usec);
#endif
        u64 now = timeus();
        
        if(now - start >= usec)
        {
            break;
        }
    }

#if ZDB_ZONE_LOCK_HAS_OWNER_ID
    if(ret)
    {
        zone->lock_last_owner_id = thread_self();
    }
#endif
    
    mutex_unlock(mutex);
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = debug_stacktrace_get();
    zone->lock_id = thread_self();
    zone->lock_timestamp = timeus();

    zdb_zone_lock_set_add(zone);
#endif

#if MUTEX_CONTENTION_MONITOR
    if(ISOK(ret))
    {
        mutex_contention_lock_end(mcm);
    }
    else
    {
        mutex_contention_lock_fail(mcm);
    }
#endif
    
    return ret;
}

void
zdb_zone_unlock(zdb_zone *zone, u8 owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("releasing lock for zone %{dnsname}@%p by %x (owned by %x)", zone->origin, zone, owner, zone->lock_owner);
#else
    (void)owner;
#endif

    mutex_lock(&zone->lock_mutex);
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    struct zdb_zone_lock_monitor *holder = zdb_zone_lock_monitor_get(zone);
#endif

#if DEBUG
    if(((zone->lock_owner & ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG) != (owner & ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG)) || (zone->lock_count == 0))
    {
        yassert((zone->lock_owner == ZDB_ZONE_MUTEX_DESTROY) || (zone->lock_owner == (owner & ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG)));
        yassert(zone->lock_count != 0);
        abort(); // unreachable
    }
#endif

    --zone->lock_count;

#if ZONE_MUTEX_LOG
    log_debug7("released lock for zone %{dnsname}@%p by %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif
    
    if(zone->lock_count == 0)
    {
        zone->lock_owner = ZDB_ZONE_MUTEX_NOBODY;
        cond_notify(&zone->lock_cond);
    }
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    zdb_zone_lock_monitor_unlocks(holder);
#endif

#if ZDB_ZONE_LOCK_HAS_OWNER_ID
    thread_t tid = thread_self();
    if(zone->lock_last_owner_id == tid)
    {
        zone->lock_last_owner_id = 0;
    }
#endif
    
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = NULL;
    zone->lock_id = 0;
    zone->lock_timestamp = 0;

    zdb_zone_lock_set_del(zone);
#endif
    
    mutex_unlock(&zone->lock_mutex);

#if MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), zone);
#endif
}

void
zdb_zone_double_lock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if MUTEX_CONTENTION_MONITOR
    struct mutex_contention_monitor_s *mcm = mutex_contention_lock_begin(thread_self(), zone, debug_stacktrace_get(), "zdb_zone");
#endif

#if ZONE_MUTEX_LOG
    log_debug7("acquiring lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
    u64 start = timeus();
#endif
#endif
    
    mutex_lock(&zone->lock_mutex);
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    struct zdb_zone_lock_monitor *holder = zdb_zone_lock_monitor_new(zone, owner, secondary_owner);
#endif
    
    for(;;)
    {
        /*
         * A simple way to ensure that a lock can be shared
         * by similar entities or not.
         * Sharable entities have their msb off.
         */
        
        u8 so = zone->lock_reserved_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
        
        if(so == ZDB_ZONE_MUTEX_NOBODY || so == secondary_owner)
        {
            u8 co = zone->lock_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;

            if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
            {
                yassert(!SIGNED_VAR_VALUE_IS_MAX(zone->lock_count));

                zone->lock_owner = owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
                zone->lock_count++;
                zone->lock_reserved_owner = secondary_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;

#if ZDB_ZONE_LOCK_HAS_OWNER_ID
                thread_t tid = thread_self();
                zone->lock_last_owner_id = tid;
                zone->lock_last_reserved_owner_id = tid;
#endif
            
#if ZONE_MUTEX_LOG
                log_debug7("acquired lock for zone %{dnsname}@%p for %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif

                break;
            }
        }
        else
        {
            // the secondary owner is already taken
        }

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
        zdb_zone_lock_monitor_waits(holder);
#endif
        
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
        s64 d = timeus() - start;
        if(d > MUTEX_WAITED_TOO_MUCH_TIME_US)
        {
            log_warn("zdb_zone_double_lock(%{dnsname},%x,%x) : waited for %llius already ...", zone->origin, owner, secondary_owner, d);
            debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_WARNING, "zdb_zone_double_lock:");
        }
        cond_timedwait(&zone->lock_cond, &zone->lock_mutex, MUTEX_WAITED_TOO_MUCH_TIME_US);
#else
        cond_wait(&zone->lock_cond, &zone->lock_mutex);
#endif
    }
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    zdb_zone_lock_monitor_locks(holder);
#endif
    
    mutex_unlock(&zone->lock_mutex);
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = debug_stacktrace_get();
    zone->lock_id = thread_self();
    zone->lock_timestamp = timeus();

    zdb_zone_lock_set_add(zone);
#endif

#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_end(mcm);
#endif
}

bool
zdb_zone_try_double_lock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if MUTEX_CONTENTION_MONITOR
    struct mutex_contention_monitor_s *mcm = mutex_contention_lock_begin(thread_self(), zone, debug_stacktrace_get(), "zdb_zone");
#endif

#if ZONE_MUTEX_LOG
    log_debug7("trying to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif
    mutex_lock(&zone->lock_mutex);
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    struct zdb_zone_lock_monitor *holder = zdb_zone_lock_monitor_new(zone, owner, secondary_owner);
#endif

    u8 so = zone->lock_reserved_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;

    if(so == ZDB_ZONE_MUTEX_NOBODY || so == secondary_owner)
    {
        u8 co = zone->lock_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
    
        if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
        {
            yassert(!SIGNED_VAR_VALUE_IS_MAX(zone->lock_count));

            zone->lock_owner = owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
            zone->lock_count++;
            zone->lock_reserved_owner = secondary_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;

#if ZDB_ZONE_LOCK_HAS_OWNER_ID
            thread_t tid = thread_self();
            zone->lock_last_owner_id = tid;
            zone->lock_last_reserved_owner_id = tid;
#endif

#if ZONE_MUTEX_LOG
            log_debug7("acquired lock for zone %{dnsname}@%p for %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif
            
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
            zdb_zone_lock_monitor_locks(holder);
#endif

            mutex_unlock(&zone->lock_mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
            zone->lock_trace = debug_stacktrace_get();
            zone->lock_id = thread_self();
            zone->lock_timestamp = timeus();

            zdb_zone_lock_set_add(zone);
#endif
#if MUTEX_CONTENTION_MONITOR
            mutex_contention_lock_end(mcm);
#endif
            
            return TRUE;
        }
    }
    /*
    else
    {
        // already double-owned
    }
    */
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    zdb_zone_lock_monitor_cancels(holder);
#endif

    mutex_unlock(&zone->lock_mutex);

#if ZONE_MUTEX_LOG
    log_debug7("failed to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_fail(mcm);
#endif

    return FALSE;
}

bool
zdb_zone_try_double_lock_ex(zdb_zone *zone, u8 owner, u8 secondary_owner, u8 *current_ownerp, u8 *current_reserved_ownerp)
{
#if MUTEX_CONTENTION_MONITOR
    struct mutex_contention_monitor_s *mcm = mutex_contention_lock_begin(thread_self(), zone, debug_stacktrace_get(), "zdb_zone");
#endif

#if ZONE_MUTEX_LOG
    log_debug7("trying to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif
    mutex_lock(&zone->lock_mutex);

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    struct zdb_zone_lock_monitor *holder = zdb_zone_lock_monitor_new(zone, owner, secondary_owner);
#endif

    *current_ownerp = zone->lock_owner;
    *current_reserved_ownerp = zone->lock_reserved_owner;

    u8 so = zone->lock_reserved_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;

    if(so == ZDB_ZONE_MUTEX_NOBODY || so == secondary_owner)
    {
        u8 co = zone->lock_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;

        if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
        {
            yassert(!SIGNED_VAR_VALUE_IS_MAX(zone->lock_count));

            zone->lock_owner = owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
            zone->lock_count++;
            zone->lock_reserved_owner = secondary_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;

#if ZDB_ZONE_LOCK_HAS_OWNER_ID
            thread_t tid = thread_self();
            zone->lock_last_owner_id = tid;
            zone->lock_last_reserved_owner_id = tid;
#endif

#if ZONE_MUTEX_LOG
            log_debug7("acquired lock for zone %{dnsname}@%p for %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
            zdb_zone_lock_monitor_locks(holder);
#endif

            mutex_unlock(&zone->lock_mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
            zone->lock_trace = debug_stacktrace_get();
            zone->lock_id = thread_self();
            zone->lock_timestamp = timeus();

            zdb_zone_lock_set_add(zone);
#endif
#if MUTEX_CONTENTION_MONITOR
            mutex_contention_lock_end(mcm);
#endif

            return TRUE;
        }
    }
    /*
    else
    {
        // already double-owned
    }
    */

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    zdb_zone_lock_monitor_cancels(holder);
#endif

    mutex_unlock(&zone->lock_mutex);

#if ZONE_MUTEX_LOG
    log_debug7("failed to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_fail(mcm);
#endif

    return FALSE;
}

void
zdb_zone_double_unlock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("releasing lock for zone %{dnsname}@%p by %x and %x (owned by %x and %x)", zone->origin, zone, owner, secondary_owner, zone->lock_owner, zone->lock_reserved_owner);
#else
    (void)owner;
    (void)secondary_owner;
#endif

    mutex_lock(&zone->lock_mutex);

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    struct zdb_zone_lock_monitor *holder = zdb_zone_lock_monitor_get(zone);
#endif
    
#if ZDB_ZONE_LOCK_HAS_OWNER_ID
    thread_t tid = thread_self();
    if(zone->lock_last_owner_id == tid)
    {
        zone->lock_last_owner_id = 0;
    }
    if(zone->lock_last_reserved_owner_id == tid)
    {
        zone->lock_last_reserved_owner_id = 0;
    }
#endif

    assert(zone->lock_reserved_owner == (secondary_owner & ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG));
    assert(zone->lock_owner == (owner & ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG));
    
    zone->lock_reserved_owner = ZDB_ZONE_MUTEX_NOBODY;

    --zone->lock_count;
    
#if ZONE_MUTEX_LOG
    log_debug7("released lock for zone %{dnsname}@%p by %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif
    
    yassert((zone->lock_owner & 0xc0) == 0);
    // NO, because it does not always to a transfer lock yassert(zone->lock_count == 0);
    
    if(zone->lock_count == 0)
    {
        zone->lock_owner = ZDB_ZONE_MUTEX_NOBODY;
        cond_notify(&zone->lock_cond);
    }
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    zdb_zone_lock_monitor_unlocks(holder);
#endif
    
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = NULL;
    zone->lock_id = 0;
    zone->lock_timestamp = 0;

    zdb_zone_lock_set_del(zone);
#endif
    
    mutex_unlock(&zone->lock_mutex);

#if MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), zone);
#endif
}

void
zdb_zone_exchange_locks(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("exchanging locks for zone %{dnsname}@%p from %x to %x (owned by %x:%x)", zone->origin, zone, owner, secondary_owner, zone->lock_owner, zone->lock_reserved_owner);
#endif
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
    u64 start = timeus();
#endif
#endif

    mutex_lock(&zone->lock_mutex);
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    struct zdb_zone_lock_monitor *holder = zdb_zone_lock_monitor_new(zone, owner, secondary_owner);
#endif

#if DEBUG
    if((zone->lock_owner != (owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG)) || (zone->lock_count == 0))
    {
        yassert(zone->lock_owner == (owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG));
        yassert(zone->lock_count != 0);
        abort(); // unreachable
    }
    
    if(zone->lock_reserved_owner != (secondary_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG))
    {
        yassert(zone->lock_reserved_owner != (secondary_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG));
        abort(); // unreachable
    }
#endif
    
    // wait to be the last one
    
    while(zone->lock_count != 1)
    {
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
        zdb_zone_lock_monitor_waits(holder);
#endif
        
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
        s64 d = timeus() - start;
        if(d > MUTEX_WAITED_TOO_MUCH_TIME_US)
        {
            log_warn("zdb_zone_transfer_lock(%{dnsname},%x,%x) : waited for %llius already ...", zone->origin, owner, secondary_owner, d);
            debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_WARNING, "zdb_zone_double_lock:");
        }
#endif
        cond_timedwait(&zone->lock_cond, &zone->lock_mutex, 100);
        
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
        zdb_zone_lock_monitor_resumes(holder);
#endif
    }
    
    zone->lock_owner = secondary_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
    zone->lock_reserved_owner = owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;

#if ZONE_MUTEX_LOG
    log_debug7("exchanged locks for zone %{dnsname}@%p from %x to %x (#%i)", zone->origin, zone, owner, secondary_owner, zone->lock_count);
#endif
    
    if((secondary_owner & ZDB_ZONE_MUTEX_EXCLUSIVE_FLAG) == 0)
    {
        cond_notify(&zone->lock_cond);
    }
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    zdb_zone_lock_monitor_exchanges(holder);
    zdb_zone_lock_monitor_release(holder);
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = debug_stacktrace_get();
    zone->lock_id = thread_self();
    zone->lock_timestamp = timeus();

    zdb_zone_lock_set_add(zone);
#endif

    mutex_unlock(&zone->lock_mutex);
}

/** @} */

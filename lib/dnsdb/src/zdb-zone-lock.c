/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2017, EURid. All rights reserved.
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

#include "dnsdb/zdb.h"

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_error.h"

#include "dnsdb/dnsrdata.h"

#include "dnsdb/zdb_listener.h"

#if ZDB_HAS_NSEC_SUPPORT != 0
#include "dnsdb/nsec.h"
#endif
#if ZDB_HAS_NSEC3_SUPPORT != 0
#include "dnsdb/nsec3.h"
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#include <dnscore/ptr_set.h>
#endif

#ifdef DEBUG
#define ZONE_MUTEX_LOG 1    // set this to 0 to disable in DEBUG
#else
#define ZONE_MUTEX_LOG 0
#endif

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define MUTEX_LOCKED_TOO_MUCH_TIME_US 5000000
#define MUTEX_WAITED_TOO_MUCH_TIME_US 2000000

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

static pthread_mutex_t zdb_zone_lock_set_mtx = PTHREAD_MUTEX_INITIALIZER;
static ptr_set zdb_zone_lock_set = PTR_SET_PTR_EMPTY;

void
zdb_zone_lock_set_add(zdb_zone *zone)
{
    pthread_mutex_lock(&zdb_zone_lock_set_mtx);
    ptr_node *node = ptr_set_avl_insert(&zdb_zone_lock_set, zone);
    node->value = zone;
    pthread_mutex_unlock(&zdb_zone_lock_set_mtx);
}

void
zdb_zone_lock_set_del(zdb_zone *zone)
{
    pthread_mutex_lock(&zdb_zone_lock_set_mtx);
    ptr_set_avl_delete(&zdb_zone_lock_set, zone);
    pthread_mutex_unlock(&zdb_zone_lock_set_mtx);
}

static s64 zdb_zone_lock_set_monitor_last_duration = 0;
static s64 zdb_zone_lock_set_monitor_last_time = 0;

#ifdef DEBUG
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
    u64 now = timeus();
    
    if(now - zdb_zone_lock_set_monitor_last_time < zdb_zone_lock_set_monitor_last_duration)
    {
        return;
    }
    
    zdb_zone_lock_set_monitor_last_time = now;
    
    pthread_mutex_lock(&zdb_zone_lock_set_mtx);
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&zdb_zone_lock_set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        zdb_zone *zone = (zdb_zone*)node->key;
        
        u8 owner = zone->lock_owner;
        if(owner == GROUP_MUTEX_NOBODY)
        {
            continue;
        }
        
        u64 ts = zone->lock_timestamp;
        stacktrace trace = zone->lock_trace;
        pthread_t id = zone->lock_id;
        if(ts < now)
        {
            u64 dt = now - ts;
            if(dt > MUTEX_LOCKED_TOO_MUCH_TIME_US)
            {
                // locked for 5 seconds ... trouble
#ifndef DEBUG
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
    pthread_mutex_unlock(&zdb_zone_lock_set_mtx);
    u64 after = timeus();
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
    u64 start = timeus();
#endif

    mutex_t *mutex = &zone->lock_mutex;   
    
    mutex_lock(mutex);
    
    for(;;)
    {
		/*
			A simple way to ensure that a lock can be shared
			by similar entities or not.
			Sharable entities have their msb off.
		*/

        u8 co = zone->lock_owner & 0x7f;
        
        if(co == GROUP_MUTEX_NOBODY || co == owner)
        {
            yassert(zone->lock_count != 255);

            zone->lock_owner = owner & 0x7f;
            zone->lock_count++;

            break;
        }
        
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
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
    }
    
    mutex_unlock(mutex);
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = debug_stacktrace_get();
    zone->lock_id = pthread_self();
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

    mutex_lock(&zone->lock_mutex);

    u8 co = zone->lock_owner & 0x7f;
    
    if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
    {
        yassert(zone->lock_count != 255);

        zone->lock_owner = owner & 0x7f;
        zone->lock_count++;

#if ZONE_MUTEX_LOG
        log_debug7("acquired lock for zone %{dnsname}@%p for %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif

        mutex_unlock(&zone->lock_mutex);
        
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        zone->lock_trace = debug_stacktrace_get();
        zone->lock_id = pthread_self();
        zone->lock_timestamp = timeus();

        zdb_zone_lock_set_add(zone);
#endif

        return TRUE;
    }

    mutex_unlock(&zone->lock_mutex);

#if ZONE_MUTEX_LOG
    log_debug7("failed to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

    return FALSE;
}

void
zdb_zone_unlock(zdb_zone *zone, u8 owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("releasing lock for zone %{dnsname}@%p by %x (owned by %x)", zone->origin, zone, owner, zone->lock_owner);
#endif

    mutex_lock(&zone->lock_mutex);

#ifdef DEBUG
    if((zone->lock_owner != (owner & 0x7f)) || (zone->lock_count == 0))
    {
        mutex_unlock(&zone->lock_mutex);
        yassert(zone->lock_owner == (owner & 0x7f));
        yassert(zone->lock_count != 0);
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
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = NULL;
    zone->lock_id = 0;
    zone->lock_timestamp = 0;

    zdb_zone_lock_set_del(zone);
#endif
    
    mutex_unlock(&zone->lock_mutex);
}

void
zdb_zone_double_lock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("acquiring lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    u64 start = timeus();
#endif
    
    mutex_lock(&zone->lock_mutex);
    
    for(;;)
    {
        /*
         * A simple way to ensure that a lock can be shared
         * by similar entities or not.
         * Sharable entities have their msb off.
         */
        
        u8 so = zone->lock_reserved_owner & 0x7f;
        
        if(so == ZDB_ZONE_MUTEX_NOBODY || so == secondary_owner)
        {
            u8 co = zone->lock_owner & 0x7f;

            if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
            {
                yassert(zone->lock_count != 255);

                zone->lock_owner = owner & 0x7f;
                zone->lock_count++;
                zone->lock_reserved_owner = secondary_owner & 0x7f;
            
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

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
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
    
    mutex_unlock(&zone->lock_mutex);
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = debug_stacktrace_get();
    zone->lock_id = pthread_self();
    zone->lock_timestamp = timeus();

    zdb_zone_lock_set_add(zone);
#endif
}

bool
zdb_zone_try_double_lock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("trying to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

    mutex_lock(&zone->lock_mutex);

    u8 so = zone->lock_reserved_owner & 0x7f;
        
    if(so == ZDB_ZONE_MUTEX_NOBODY || so == secondary_owner)
    {
        u8 co = zone->lock_owner & 0x7f;
    
        if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
        {
            yassert(zone->lock_count != 255);

            zone->lock_owner = owner & 0x7f;
            zone->lock_count++;
            zone->lock_reserved_owner = secondary_owner & 0x7f;

#if ZONE_MUTEX_LOG
            log_debug7("acquired lock for zone %{dnsname}@%p for %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif

            mutex_unlock(&zone->lock_mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
            zone->lock_trace = debug_stacktrace_get();
            zone->lock_id = pthread_self();
            zone->lock_timestamp = timeus();

            zdb_zone_lock_set_add(zone);
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
    
    mutex_unlock(&zone->lock_mutex);

#if ZONE_MUTEX_LOG
    log_debug7("failed to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

    return FALSE;
}

void
zdb_zone_double_unlock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("releasing lock for zone %{dnsname}@%p by %x (owned by %x)", zone->origin, zone, owner, zone->lock_owner);
#endif

    mutex_lock(&zone->lock_mutex);

#ifdef DEBUG
    if((zone->lock_owner != (owner & 0x7f)) || (zone->lock_count == 0))
    {
        mutex_unlock(&zone->lock_mutex);
        yassert(zone->lock_owner == (owner & 0x7f));
        yassert(zone->lock_count != 0);
    }
    
    if(zone->lock_reserved_owner != (secondary_owner & 0x7f))
    {
        mutex_unlock(&zone->lock_mutex);
        yassert(zone->lock_reserved_owner != (secondary_owner & 0x7f));
    }
#endif
    
    zone->lock_reserved_owner = ZDB_ZONE_MUTEX_NOBODY;

    --zone->lock_count;
    
#if ZONE_MUTEX_LOG
    log_debug7("released lock for zone %{dnsname}@%p by %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif
    
    if(zone->lock_count == 0)
    {
        zone->lock_owner = ZDB_ZONE_MUTEX_NOBODY;
        cond_notify(&zone->lock_cond);
    }
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = NULL;
    zone->lock_id = 0;
    zone->lock_timestamp = 0;

    zdb_zone_lock_set_del(zone);
#endif
    
    mutex_unlock(&zone->lock_mutex);
}

void
zdb_zone_transfer_lock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("transferring lock for zone %{dnsname}@%p from %x to %x (owned by %x:%x)", zone->origin, zone, owner, secondary_owner, zone->lock_owner, zone->lock_reserved_owner);
#endif
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    u64 start = timeus();
#endif

    mutex_lock(&zone->lock_mutex);

#ifdef DEBUG
    if((zone->lock_owner != (owner & 0x7f)) || (zone->lock_count == 0))
    {
        mutex_unlock(&zone->lock_mutex);
        yassert(zone->lock_owner == (owner & 0x7f));
        yassert(zone->lock_count != 0);
    }
    
    if(zone->lock_reserved_owner != (secondary_owner & 0x7f))
    {
        mutex_unlock(&zone->lock_mutex);
        yassert(zone->lock_reserved_owner != (secondary_owner & 0x7f));
    }
#endif
    
    // wait to be the last one
    
    while(zone->lock_count != 1)
    {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        s64 d = timeus() - start;
        if(d > MUTEX_WAITED_TOO_MUCH_TIME_US)
        {
            log_warn("zdb_zone_transfer_lock(%{dnsname},%x,%x) : waited for %llius already ...", zone->origin, owner, secondary_owner, d);
            debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_WARNING, "zdb_zone_double_lock:");
        }
#endif
        
        cond_timedwait(&zone->lock_cond, &zone->lock_mutex, 100);
    }
    
    zone->lock_owner = secondary_owner & 0x7f;
    zone->lock_reserved_owner = ZDB_ZONE_MUTEX_NOBODY;
    

#if ZONE_MUTEX_LOG
    log_debug7("transferred lock for zone %{dnsname}@%p from %x to %x (#%i)", zone->origin, zone, owner, secondary_owner, zone->lock_count);
#endif
    
    if((secondary_owner & 0x80) == 0)
    {
        cond_notify(&zone->lock_cond);
    }

    mutex_unlock(&zone->lock_mutex);
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = debug_stacktrace_get();
    zone->lock_id = pthread_self();
    zone->lock_timestamp = timeus();

    zdb_zone_lock_set_add(zone);
#endif
}

bool
zdb_zone_try_transfer_lock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("transferring lock for zone %{dnsname}@%p from %x to %x (owned by %x:%x)", zone->origin, zone, owner, secondary_owner, zone->lock_owner, zone->lock_reserved_owner);
#endif
    
    mutex_lock(&zone->lock_mutex);

#ifdef DEBUG
    if((zone->lock_owner != (owner & 0x7f)) || (zone->lock_count == 0))
    {
        mutex_unlock(&zone->lock_mutex);
        yassert(zone->lock_owner == (owner & 0x7f));
        yassert(zone->lock_count != 0);
    }
    
    if(zone->lock_reserved_owner != (secondary_owner & 0x7f))
    {
        mutex_unlock(&zone->lock_mutex);
        yassert(zone->lock_reserved_owner != (secondary_owner & 0x7f));
    }
#endif
    
    // wait to be the last one
    
    if(zone->lock_count == 1)
    {
        zone->lock_owner = secondary_owner & 0x7f;
        zone->lock_reserved_owner = ZDB_ZONE_MUTEX_NOBODY;
        
        if((secondary_owner & 0x80) == 0)
        {
            cond_notify(&zone->lock_cond);
        }
        
        mutex_unlock(&zone->lock_mutex);
        
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        zone->lock_trace = debug_stacktrace_get();
        zone->lock_id = pthread_self();
        zone->lock_timestamp = timeus();

        zdb_zone_lock_set_add(zone);
#endif
        
        return TRUE;
    }
    
    mutex_unlock(&zone->lock_mutex);
    
    return FALSE;
}

void
zdb_zone_exchange_locks(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("exchanging locks for zone %{dnsname}@%p from %x to %x (owned by %x:%x)", zone->origin, zone, owner, secondary_owner, zone->lock_owner, zone->lock_reserved_owner);
#endif
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    u64 start = timeus();
#endif

    mutex_lock(&zone->lock_mutex);

#ifdef DEBUG
    if((zone->lock_owner != (owner & 0x7f)) || (zone->lock_count == 0))
    {
        mutex_unlock(&zone->lock_mutex);
        yassert(zone->lock_owner == (owner & 0x7f));
        yassert(zone->lock_count != 0);
    }
    
    if(zone->lock_reserved_owner != (secondary_owner & 0x7f))
    {
        mutex_unlock(&zone->lock_mutex);
        yassert(zone->lock_reserved_owner != (secondary_owner & 0x7f));
    }
#endif
    
    // wait to be the last one
    
    while(zone->lock_count != 1)
    {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        s64 d = timeus() - start;
        if(d > MUTEX_WAITED_TOO_MUCH_TIME_US)
        {
            log_warn("zdb_zone_transfer_lock(%{dnsname},%x,%x) : waited for %llius already ...", zone->origin, owner, secondary_owner, d);
            debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_WARNING, "zdb_zone_double_lock:");
        }
#endif
        
        cond_timedwait(&zone->lock_cond, &zone->lock_mutex, 100);
    }
    
    zone->lock_owner = secondary_owner & 0x7f;
    zone->lock_reserved_owner = owner & 0x7f;
    

#if ZONE_MUTEX_LOG
    log_debug7("exchanged locks for zone %{dnsname}@%p from %x to %x (#%i)", zone->origin, zone, owner, secondary_owner, zone->lock_count);
#endif
    
    if((secondary_owner & 0x80) == 0)
    {
        cond_notify(&zone->lock_cond);
    }

    mutex_unlock(&zone->lock_mutex);
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = debug_stacktrace_get();
    zone->lock_id = pthread_self();
    zone->lock_timestamp = timeus();

    zdb_zone_lock_set_add(zone);
#endif
}

/** @} */

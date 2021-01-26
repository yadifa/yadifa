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
#include "dnsdb/zdb-config-features.h"
#include <unistd.h>
#include <arpa/inet.h>

#if DEBUG
#include <dnscore/format.h>
#endif

#include <dnscore/mutex.h>

#include <dnscore/dnscore.h>

#include <dnscore/logger.h>

#include "dnsdb/zdb.h"

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb-zone-garbage.h"
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

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
#include "dnsdb/zdb-zone-lock-monitor.h"
#endif

#if DEBUG
#define ZONE_MUTEX_LOG 0        // set this to 0 to disable in DEBUG
#define DEBUG_ARC 0             // set this to 0 do disable in DEBUG
#else
#define ZONE_MUTEX_LOG 0        // never enable if not in DEBUG
#define DEBUG_ARC 0             // never enable if not in DEBUG
#endif

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#if DEBUG_ARC

static inline bool zdb_zone_change_rc(zdb_zone *zone, s32 n, const char * txt)
{
    char prefix[64];
    int old_rc = zone->rc;
    int new_rc = old_rc + n;
    log_debug7("%s: %p going from %i to %i", txt, zone, old_rc, new_rc);
    snformat(prefix, sizeof(prefix), "%s: %p", txt, zone);
    debug_log_stacktrace(g_database_logger, MSG_DEBUG7, prefix);

    if(new_rc < 0)
    {
        abort();
    }
    
    zone->rc = new_rc;
    
    if(new_rc == 0)
    {
        log_debug7("%s: good for the garbage", txt);
    }
    
    return new_rc == 0;
}

#define ZONE_RC_INC(zone_) zdb_zone_change_rc(zone_,  1, "rc++")
#define ZONE_RC_DEC(zone_) zdb_zone_change_rc(zone_, -1, "rc--")

#else

#define ZONE_RC_INC(zone_) (++(zone_)->rc)
#define ZONE_RC_DEC(zone_) ((--(zone_)->rc) == 0)

#endif

/**
 * 
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 * 
 * @param db
 * @param exact_match_origin
 * @param owner
 * @return 
 */

static inline zdb_zone *
zdb_acquire_zone_resume_lock_from_label(zdb *db, const zdb_zone_label *label, u8 owner, u8 db_locktype)
{
    yassert(zdb_islocked(db));
    
    if(label != NULL && label->zone != NULL)
    {
        zdb_zone *zone = label->zone;        
        mutex_t *mutex = &zone->lock_mutex;
        mutex_lock(mutex);
        zdb_unlock(db, db_locktype);
        
        ZONE_RC_INC(zone);
        
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

#if ZDB_ZONE_LOCK_HAS_OWNER_ID // if the owner changes, update the owning thread
                if(zone->lock_last_owner_id == 0)
                {
                    zone->lock_last_owner_id = thread_self();
                }
#endif
                break;
            }
            
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
            zdb_zone_lock_monitor_waits(holder);
#endif

            cond_wait(&zone->lock_cond, mutex);
      
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
            zdb_zone_lock_monitor_resumes(holder);
#endif
        }

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
        zdb_zone_lock_monitor_locks(holder);
#endif

        mutex_unlock(mutex);
        
        return zone;
    }
    else
    {
        zdb_unlock(db, db_locktype);
        
        return NULL;
    }
}

static inline zdb_zone *
zdb_acquire_zone_resume_trylock_from_label(zdb *db, const zdb_zone_label *label, u8 owner, u8 db_locktype)
{
    yassert(zdb_islocked(db));
    
    if(label != NULL && label->zone != NULL)
    {
        zdb_zone *zone = label->zone;
        
        mutex_t *mutex = &zone->lock_mutex;
        
        mutex_lock(mutex);
        
        zdb_unlock(db, db_locktype);
        
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
        struct zdb_zone_lock_monitor *holder = zdb_zone_lock_monitor_new(zone, owner, 0);
#endif
        
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

#if ZDB_ZONE_LOCK_HAS_OWNER_ID // if the owner changes, update the owning thread
            if(zone->lock_last_owner_id == 0)
            {
                zone->lock_last_owner_id = thread_self();
            }
#endif

            ZONE_RC_INC(zone);
            
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
            zdb_zone_lock_monitor_locks(holder);
#endif

            mutex_unlock(mutex);

            return zone;
        }
        else
        {
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
            zdb_zone_lock_monitor_cancels(holder);
#endif
            mutex_unlock(mutex);
        
            return NULL;
        }
    }
    else
    {
        zdb_unlock(db, db_locktype);
        
        return NULL;
    }
}

/**
 * Internal.
 * Second part of a double lock.
 * Works on a locked DB.
 * On success returns the double-locked zone.
 * On error, unlocks the DB and return NULL.
 * 
 * @param db
 * @param label
 * @param owner
 * @param nextowner
 * @param db_locktype
 * @return 
 */

static inline zdb_zone *
zdb_acquire_zone_resume_double_lock_from_label(zdb *db, const zdb_zone_label *label, u8 owner, u8 nextowner, u8 db_locktype)
{
    yassert((owner & 0x80) == 0); // the new standard use
    
    yassert(zdb_islocked(db));
    
    if(label != NULL && label->zone != NULL)
    {
        zdb_zone *zone = label->zone;
        
        mutex_t *mutex = &zone->lock_mutex;
        
        mutex_lock(mutex);
        
        zdb_unlock(db, db_locktype);
        
        ZONE_RC_INC(zone);
        
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
        struct zdb_zone_lock_monitor *holder = zdb_zone_lock_monitor_new(zone, owner, nextowner);
#endif

        for(;;)
        {
            /*
                A simple way to ensure that a lock can be shared
                by similar entities or not.
                Sharable entities have their msb off.
            */

            u8 so = zone->lock_reserved_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
        
            if(so == ZDB_ZONE_MUTEX_NOBODY || so == nextowner)
            {
                u8 co = zone->lock_owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;

                if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
                {
                    yassert(!SIGNED_VAR_VALUE_IS_MAX(zone->lock_count));

                    zone->lock_owner = owner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;
                    zone->lock_count++;
                    zone->lock_reserved_owner = nextowner & ZDB_ZONE_MUTEX_LOCKMASK_FLAG;

#if ZDB_ZONE_LOCK_HAS_OWNER_ID
                    if(zone->lock_last_owner_id == 0)
                    {
                        zone->lock_last_owner_id = thread_self();
                    }
#endif

#if ZONE_MUTEX_LOG
                    log_debug7("acquired lock for zone %{dnsname}@%p for %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif
                    break;
                }
            }

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
            zdb_zone_lock_monitor_waits(holder);
#endif
            cond_wait(&zone->lock_cond, mutex);
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
            zdb_zone_lock_monitor_resumes(holder);
#endif
        }
        
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
        zdb_zone_lock_monitor_locks(holder);
#endif

        mutex_unlock(mutex);
        
        return zone;
    }
    else
    {
        zdb_unlock(db, db_locktype);
        
        return NULL;
    }
}

zdb_zone *
zdb_acquire_zone_read(zdb *db, const dnsname_vector *exact_match_origin)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    
    const zdb_zone_label *label = zdb_zone_label_find(db, exact_match_origin);

    if(label != NULL && label->zone != NULL)
    {
        zdb_zone *zone = label->zone;
        
        mutex_t *mutex = &zone->lock_mutex;
        
        mutex_lock(mutex);
        
        zdb_unlock(db, ZDB_MUTEX_READER);
        
        ZONE_RC_INC(zone);
        
        mutex_unlock(mutex);
        
        return zone;
    }
    else
    {
        zdb_unlock(db, ZDB_MUTEX_READER);
        
        return NULL;
    }
}

zdb_zone *
zdb_acquire_zone_read_from_fqdn(zdb *db, const u8 *fqdn)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    
    zdb_zone_label *label = zdb_zone_label_find_from_dnsname(db, fqdn);

    if(label != NULL && label->zone != NULL)
    {
        zdb_zone *zone = label->zone;
        
        mutex_t *mutex = &zone->lock_mutex;
        
        mutex_lock(mutex);
        
        zdb_unlock(db, ZDB_MUTEX_READER);
        
        ZONE_RC_INC(zone);
        
        mutex_unlock(mutex);
        
        return zone;
    }
    else
    {
        zdb_unlock(db, ZDB_MUTEX_READER);
        
        return NULL;
    }
}

zdb_zone *
zdb_acquire_zone_read_trylock(zdb *db, dnsname_vector *exact_match_origin, u8 owner)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    zdb_zone_label *label = zdb_zone_label_find(db, exact_match_origin);
    if(label != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_trylock_from_label(db, label, owner, ZDB_MUTEX_READER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_READER);
    return NULL;
}

zdb_zone *
zdb_acquire_zone_read_trylock_from_name(zdb *db, const char *name, u8 owner)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    zdb_zone_label *label = zdb_zone_label_find_from_name(db, name);
    if(label != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_trylock_from_label(db, label, owner, ZDB_MUTEX_READER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_READER);
    return NULL;
}

zdb_zone *
zdb_acquire_zone_read_trylock_from_fqdn(zdb *db, const u8 *fqdn, u8 owner)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    zdb_zone_label *label = zdb_zone_label_find_from_dnsname(db, fqdn);
    if(label != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_trylock_from_label(db, label, owner, ZDB_MUTEX_READER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_READER);
    return NULL;
}

zdb_zone *
zdb_acquire_zone_read_lock(zdb *db, dnsname_vector *exact_match_origin, u8 owner)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    zdb_zone_label *label = zdb_zone_label_find(db, exact_match_origin);
    if(label != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_lock_from_label(db, label, owner, ZDB_MUTEX_READER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_READER);
    return NULL;
}

zdb_zone *
zdb_acquire_zone_read_lock_from_name(zdb *db, const char *name, u8 owner)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    zdb_zone_label *label = zdb_zone_label_find_from_name(db, name);
    if(label != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_lock_from_label(db, label, owner, ZDB_MUTEX_READER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_READER);
    return NULL;
}

zdb_zone *
zdb_acquire_zone_read_lock_from_fqdn(zdb *db, const u8 *fqdn, u8 owner)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    zdb_zone_label *label = zdb_zone_label_find_from_dnsname(db, fqdn);
    if(label != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_lock_from_label(db, label, owner, ZDB_MUTEX_READER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_READER);
    return NULL;
}

zdb_zone *
zdb_acquire_zone_write_lock(zdb *db, dnsname_vector *exact_match_origin, u8 owner)
{
    zdb_lock(db, ZDB_MUTEX_WRITER);
    zdb_zone_label *label = zdb_zone_label_find(db, exact_match_origin);
    if(label != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_lock_from_label(db, label, owner, ZDB_MUTEX_WRITER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_WRITER);
    return NULL;
}

zdb_zone *
zdb_acquire_zone_write_lock_from_name(zdb *db, const char *name, u8 owner)
{
    zdb_lock(db, ZDB_MUTEX_WRITER);
    zdb_zone_label *label = zdb_zone_label_find_from_name(db, name);
    if(label != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_lock_from_label(db, label, owner, ZDB_MUTEX_WRITER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_WRITER);
    return NULL;
}

zdb_zone *
zdb_acquire_zone_write_lock_from_fqdn(zdb *db, const u8 *fqdn, u8 owner)
{
    zdb_lock(db, ZDB_MUTEX_WRITER);
    zdb_zone_label *label = zdb_zone_label_find_from_dnsname(db, fqdn);
    if(label != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_lock_from_label(db, label, owner, ZDB_MUTEX_WRITER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_WRITER);
    return NULL;
}

zdb_zone *
zdb_acquire_zone_read_double_lock(zdb *db, dnsname_vector *exact_match_origin, u8 owner, u8 nextowner)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    zdb_zone_label *label = zdb_zone_label_find(db, exact_match_origin);
    if(label != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_double_lock_from_label(db, label, owner, nextowner, ZDB_MUTEX_READER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_READER);
    return NULL;
}

zdb_zone *
zdb_acquire_zone_read_double_lock_from_name(zdb *db, const char *name, u8 owner, u8 nextowner)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    zdb_zone_label *label = zdb_zone_label_find_from_name(db, name);
    if(label != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_double_lock_from_label(db, label, owner, nextowner, ZDB_MUTEX_READER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_READER);
    return NULL;
}

zdb_zone *
zdb_acquire_zone_read_double_lock_from_fqdn(zdb *db, const u8 *fqdn, u8 owner, u8 nextowner)
{
    zdb_lock(db, ZDB_MUTEX_READER);
    zdb_zone_label *label = zdb_zone_label_find_from_dnsname(db, fqdn);
    if(fqdn != NULL)
    {
        zdb_zone *zone = zdb_acquire_zone_resume_double_lock_from_label(db, label, owner, nextowner, ZDB_MUTEX_READER);
        return zone;
    }

    zdb_unlock(db, ZDB_MUTEX_READER);
    return NULL;
}

void
zdb_zone_acquire(zdb_zone *zone)
{
    mutex_lock(&zone->lock_mutex);

    ZONE_RC_INC(zone);
    
    mutex_unlock(&zone->lock_mutex);
}
/**
 * 
 * Dereference and unlocks the zone.
 * If the RC reached 0, enqueues it for destruction
 * 
 * @param zone
 * @param owner
 */

void
zdb_zone_release(zdb_zone *zone)
{
    mutex_lock(&zone->lock_mutex);
    
    if(ZONE_RC_DEC(zone))
    {
        if(!zdb_zone_garbage_collect(zone)) // zone mutex locked, as MUST be
        {
            // zone was not collected: it was destroyed
            return;
        }
    }
    
    mutex_unlock(&zone->lock_mutex);
}

void
zdb_zone_release_unlock(zdb_zone *zone, u8 owner)
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
    if((zone->lock_owner != (owner & ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG)) || (zone->lock_count == 0))
    {
        mutex_unlock(&zone->lock_mutex);
        yassert(zone->lock_owner == (owner & ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG));
        yassert(zone->lock_count != 0);
        abort(); // unreachable
    }
#endif

    zone->lock_count--;

#if ZONE_MUTEX_LOG
    log_debug7("released lock for zone %{dnsname}@%p by %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    zdb_zone_lock_monitor_unlocks(holder);
#endif

#if ZDB_ZONE_LOCK_HAS_OWNER_ID
    if(zone->lock_last_owner_id == thread_self())
    {
        zone->lock_last_owner_id = 0;
    }
#endif
    
    if(zone->lock_count == 0)
    {
        zone->lock_owner = ZDB_ZONE_MUTEX_NOBODY;
        cond_notify(&zone->lock_cond);
    }
    
    if(ZONE_RC_DEC(zone))
    {
        if(!zdb_zone_garbage_collect(zone)) // zone mutex locked, as MUST be
        {
            // zone was not collected: it was destroyed
            return;
        }
    }
    
    cond_notify(&zone->lock_cond);
    mutex_unlock(&zone->lock_mutex);
}

void
zdb_zone_release_double_unlock(zdb_zone *zone, u8 owner, u8 nextowner)
{
    mutex_lock(&zone->lock_mutex);

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    struct zdb_zone_lock_monitor *holder = zdb_zone_lock_monitor_get(zone);
#else
    (void)owner;
    (void)nextowner;
#endif
    
#if DEBUG
    if((zone->lock_owner != (owner & ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG)) || (zone->lock_count == 0))
    {
        yassert(zone->lock_owner == (owner & ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG));
        yassert(zone->lock_count != 0);
    }
    
    if(zone->lock_reserved_owner != (nextowner & ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG))
    {
        yassert(zone->lock_reserved_owner != (nextowner & ZDB_ZONE_MUTEX_UNLOCKMASK_FLAG));
    }
#endif
    
    zone->lock_reserved_owner = ZDB_ZONE_MUTEX_NOBODY;

    --zone->lock_count;
    
#if ZONE_MUTEX_LOG
    log_debug7("released lock for zone %{dnsname}@%p by %x (#%i)", zone->origin, zone, owner, zone->lock_count);
#endif
    
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
    zdb_zone_lock_monitor_unlocks(holder);
#endif
    
    yassert((zone->lock_owner & 0xc0) == 0);
    // NO, because it does not always to a transfer lock yassert(zone->lock_count == 0);
    
    if(zone->lock_count == 0)
    {
        zone->lock_owner = ZDB_ZONE_MUTEX_NOBODY;
    }

#if ZDB_ZONE_LOCK_HAS_OWNER_ID
    if(zone->lock_last_owner_id == thread_self())
    {
        zone->lock_last_owner_id = 0;
    }
#endif
    
    if(ZONE_RC_DEC(zone))
    {
#if !DEBUG_ARC
#if DEBUG
        debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_DEBUG6, "GC: ");
#endif
#endif
        if(!zdb_zone_garbage_collect(zone)) // zone mutex locked, as MUST be
        {
            // zone was not collected: it was destroyed
            return;
        }
    }
    
    cond_notify(&zone->lock_cond);
    mutex_unlock(&zone->lock_mutex);
}

/** @} */

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

/** @defgroup database Routines for database manipulations
 *  @ingroup yadifad
 *  @brief database functions
 *
 *  Implementation of routines for the database
 *   - add zone file(s)
 *   - clear zone file(s)
 *   - print zone files(s)
 *   - load db
 *   - unload db
 *   - lookup database result of a message
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "server-config.h"

#include <dnscore/logger.h>

#include <dnsdb/zdb-lock.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb.h>

#include "database-service.h"

#if HAS_RRSIG_MANAGEMENT_SUPPORT && HAS_DNSSEC_SUPPORT
#include "database-service-zone-resignature.h"
#endif

#include "notify.h"

#define MODULE_MSG_HANDLE g_server_logger

#define DBLOADQ_TAG 0x5144414f4c4244

void
database_service_zone_mount(zone_desc_s *zone_desc)
{
    ya_result return_value;
    
#if DEBUG
    log_debug("database_service_zone_mount(%{dnsname}@%p=%i)", zone_origin(zone_desc), zone_desc, zone_desc->rc);
#endif
    
    if(zone_desc == NULL)
    {
        log_err("zone NULL: tried to mount NULL zone");
        return;
    }
    
    log_debug1("%{dnsname}: locking for mounting (database_service_zone_mount)", zone_origin(zone_desc));
    
    if(FAIL(return_value = zone_lock(zone_desc, ZONE_LOCK_MOUNT)))
    {
        log_err("%{dnsname}: failed to lock zone settings for (database_service_zone_mount)", zone_origin(zone_desc));
        return;
    }
    
    zone_set_status(zone_desc, ZONE_STATUS_MOUNTING);
    
    zdb_zone *zone = zone_get_loaded_zone(zone_desc); // RC++, because we get to keep a reference
    
    if(zone == NULL)
    {
        log_err("%{dnsname}: no zone loaded that could be mounted", zone_origin(zone_desc));
        zone_clear_status(zone_desc, ZONE_STATUS_STARTING_UP|ZONE_STATUS_MOUNTING|ZONE_STATUS_PROCESSING);
        
        database_fire_zone_mounted(zone_desc, NULL, ERROR);
        zone_unlock(zone_desc, ZONE_LOCK_MOUNT);
        return;
    }
        
    log_info("%{dnsname}: mount", zone_origin(zone_desc));
                    
    /*
     * If the zone descriptor (config) exists and it can be locked by the loader ...
     */
            
    u32 now = time(NULL);
    zone_desc->refresh.refreshed_time = now;
    zone_desc->refresh.retried_time = now;
    
    log_debug1("%{dnsname}: locking zone for mounting (database_service_zone_mount)", zone->origin);
    
    // locks the descriptor with the loader identity

#if DEBUG
    zone_desc_log(MODULE_MSG_HANDLE, MSG_DEBUG1, zone_desc, "database_service_zone_mount");
#endif

    zdb *db = g_config->database;

#if HAS_ACL_SUPPORT
    zone->acl = &zone_desc->ac;
    zone->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);
#endif

    zdb_zone *old_zone = zdb_set_zone(db, zone); // RC++, because the zone is put into the database
    
    bool send_notify_to_slaves = TRUE;
    
    if(old_zone != NULL)
    {
        if(zone != old_zone)
        {
            // there is already a different zone mounted

            zdb_zone_lock(old_zone, ZDB_ZONE_MUTEX_REPLACE);
            // set old zone as invalid
            zdb_zone_set_invalid(old_zone);
            zdb_zone_unlock(old_zone, ZDB_ZONE_MUTEX_REPLACE);
        }
        else
        {
            log_debug2("%{dnsname}: tried to mount a zone in place of itself (%p is %p) (database_service_zone_mount)",
                    zone->origin, old_zone, zone);
            
            send_notify_to_slaves = FALSE;
        }
        
        zdb_zone_release(old_zone);
    }
       
    //
    
    if(send_notify_to_slaves)
    {
#if HAS_MASTER_SUPPORT
        if(zone_desc->type == ZT_MASTER)
        {
            log_debug("%{dnsname}: will notify slaves", zone_origin(zone_desc));

            notify_slaves(zone_origin(zone_desc)); // RC++
        }
        else
#endif
        if(zone_desc->type == ZT_SLAVE)
        {
            log_debug("%{dnsname}: will notify explicit slaves", zone_origin(zone_desc));

            notify_slaves(zone_origin(zone_desc)); // RC++
            
            if(((zone_desc->flags & ZONE_FLAG_NO_MASTER_UPDATES) == 0))
            {
                if(zone_desc->masters != NULL)
                {
                    log_debug("%{dnsname}: querying changes to the master at %{hostaddr}", zone_origin(zone_desc), zone_desc->masters);

                    database_zone_ixfr_query(zone_origin(zone_desc));
                }
                else
                {
                    log_err("%{dnsname}: no master set", zone_origin(zone_desc));
                }
            }
        }
        // else nothing to do
    }
    else
    {
        log_debug("%{dnsname}: no need to send notify to slaves", zone_origin(zone_desc));
    }

#if HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
    if(zone_desc->type == ZT_MASTER)
    {
        if(zone_maintains_dnssec(zone_desc))
        {
            if(zdb_zone_is_maintained(zone))
            {
                database_service_zone_dnskey_set_alarms(zone);
            }
        }
    }
#endif

    zone_clear_status(zone_desc, ZONE_STATUS_STARTING_UP|ZONE_STATUS_MOUNTING|ZONE_STATUS_PROCESSING);

    database_fire_zone_mounted(zone_desc, zone, SUCCESS); // RC++
    
    zdb_zone_release(zone); // RC--
    zone = NULL;

    log_debug1("%{dnsname}: unlocking zone for mounting (database_service_zone_mount)", zone_origin(zone_desc));
    
    zone_unlock(zone_desc, ZONE_LOCK_MOUNT);
}

/**
 * @}
 */

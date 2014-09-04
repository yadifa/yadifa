/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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

#include "config.h"

#include <dnscore/logger.h>

#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_label.h>

#include "database-service.h"

#include "notify.h"

#define MODULE_MSG_HANDLE g_server_logger

#define DBLOADQ_TAG 0x5144414f4c4244

void
database_service_zone_mount(zone_desc_s *zone_desc)
{
    ya_result return_value;
    
#ifdef DEBUG
    log_debug("database_service_zone_mount(%{dnsname}@%p=%i)", zone_desc->origin, zone_desc, zone_desc->rc);
#endif
    
    if(zone_desc == NULL)
    {
        log_err("zone mount: NULL zone");
        return;
    }
    
    log_debug1("database_service_zone_mount: locking zone '%{dnsname}' for mounting", zone_desc->origin);
    
    if(FAIL(return_value = zone_lock(zone_desc, ZONE_LOCK_MOUNT)))
    {
        log_err("database_service_zone_mount: failed to lock zone settings for '%{dnsname}'", zone_desc->origin);
        return;
    }
    
    zone_desc->status_flags |= ZONE_STATUS_MOUNTING;
    
    zdb_zone *zone = zone_desc->loaded_zone;
    
    if(zone == NULL)
    {
        log_err("zone mount: no zone loaded for '%{dnsname}'", zone_desc->origin);
        zone_desc->status_flags &= ~(ZONE_STATUS_STARTING_UP|ZONE_STATUS_MOUNTING|ZONE_STATUS_PROCESSING);
        
        /// @todo check why the two commands were reversed
        database_fire_zone_mounted(zone_desc, NULL, ERROR);
        zone_unlock(zone_desc, ZONE_LOCK_MOUNT);        
        return;
    }
        
    log_info("zone mount: %{dnsname}", zone_desc->origin);
                    
    /*
     * If the zone descriptor (config) exists and it can be locked by the loader ...
     */
            
    u32 now = time(NULL);
    zone_desc->refresh.refreshed_time = now;
    zone_desc->refresh.retried_time = now;
    
    /// @todo arm an alarm for refresh
    
    log_debug1("database_service_zone_mount: locking zone '%{dnsname}' for mounting", zone->origin);
    
    // locks the descriptor with the loader identity
        
    zone_desc_log(MODULE_MSG_HANDLE, MSG_DEBUG1, zone_desc, "database_service_zone_mount");

    zdb *db = g_config->database;

    group_mutex_lock(&db->mutex, ZDB_MUTEX_WRITER);
    
#if HAS_ACL_SUPPORT
    zone->extension = &zone_desc->ac;
    zone->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);
#endif
    
    zdb_zone_label *zone_label = zdb_zone_label_find_nolock(db, &zone->origin_vector);
    
    bool send_notify_to_slaves = FALSE;
    
    if(zone_label == NULL)
    {
        // no label exist yet
        
        log_debug2("database_service_zone_mount: no label yet");
        
        // add the label (will lock/unlock for a writer)
        
        zone_label = zdb_zone_label_add_nolock(db, &zone->origin_vector);
        zone_label->zone = zone;
                
        group_mutex_unlock(&db->mutex, ZDB_MUTEX_WRITER);        
        
        send_notify_to_slaves = TRUE;
    }
    else
    {
        // there is a label at that location
        
        log_debug2("database_service_zone_mount: label exists in the database");
        
        zdb_zone *old_zone = zone_label->zone;
                
        if(old_zone != NULL)
        {
            if(zone != old_zone)
            {
                // there is already a different zone mounted

                zdb_zone_lock(old_zone, ZDB_ZONE_MUTEX_REPLACE);

                // the old zone is not invalid

                log_debug2("database_service_zone_mount: changing zone from %p to %p", old_zone, zone);

                // mount new zone
                zone_label->zone = zone;

                // set old zone as invalid                
                old_zone->apex->flags |= ZDB_RR_LABEL_INVALID_ZONE;
                zdb_zone_unlock(old_zone, ZDB_ZONE_MUTEX_REPLACE);

                group_mutex_unlock(&db->mutex, ZDB_MUTEX_WRITER);
                
                send_notify_to_slaves = TRUE;

                // destroy the old zone

                database_zone_unload(/*zone_desc->origin, */old_zone/*, NULL*/);
            }
            else
            {
                group_mutex_unlock(&db->mutex, ZDB_MUTEX_WRITER);
                
                log_debug2("database_service_zone_mount: this instance of the zone is already mounted (%p is %p)", old_zone, zone);
            }
            
            zone = NULL;
        }
        else
        {
            // the label exists, but no zone is present
            
            log_debug2("database_service_zone_mount: label exists without a zone, setting up new zone");
            
            // mount the zone
            zone_label->zone = zone;
            
            group_mutex_unlock(&db->mutex, ZDB_MUTEX_WRITER);
            
            send_notify_to_slaves = TRUE;
            
            zone = NULL;
        }
    }
 
    if(send_notify_to_slaves)
    {
#if HAS_MASTER_SUPPORT
        if(zone_desc->type == ZT_MASTER)
        {
            if(send_notify_to_slaves)
            {
                log_debug("notifying slaves of zone %{dnsname}", zone_desc->origin);

                notify_slaves(zone_desc->origin);
            }
        }
        else
#endif
        if(zone_desc->type == ZT_SLAVE)
        {
            if(((zone_desc->flags & ZONE_FLAG_NO_MASTER_UPDATES) == 0))
            {
                if(zone_desc->masters != NULL)
                {
                    log_debug("querying changes of zone %{dnsname} to the master at %{hostaddr}", zone_desc->origin, zone_desc->masters);

                    database_zone_ixfr_query(zone_desc->origin);
                }
                else
                {
                    log_err("zone %{dnsname} has no master defined", zone_desc->origin);
                }
            }
        }
        // else nothing to do
    }
    else
    {
        log_debug("no need to send notify to slaves of zone %{dnsname}", zone_desc->origin);
    }
    
    database_fire_zone_mounted(zone_desc, zone_label->zone, SUCCESS);
    
    zone_desc->status_flags &= ~(ZONE_STATUS_STARTING_UP|ZONE_STATUS_MOUNTING|ZONE_STATUS_PROCESSING);
    
    log_debug1("database_service_zone_mount: unlocking zone '%{dnsname}' for mounting", zone_desc->origin);
    
    zone_unlock(zone_desc, ZONE_LOCK_MOUNT);
}

/**
 * @}
 */

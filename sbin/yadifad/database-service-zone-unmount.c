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

#include <dnscore/logger.h>

#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_label.h>

#include "database-service.h"

#include "notify.h"

#define MODULE_MSG_HANDLE g_server_logger

#define DBLOADQ_TAG 0x5144414f4c4244

void
database_service_zone_unmount(zone_desc_s *zone_desc)
{
    ya_result return_value;
    
    if(zone_desc == NULL)
    {
        log_err("database_service_zone_unmount(NULL)");
        return;
    }
    
    log_debug1("database_service_zone_unmount(%{dnsname}@%p=%i)", zone_desc->origin, zone_desc, zone_desc->rc);
    
    log_debug1("database_service_zone_unmount: locking zone '%{dnsname}' for unmounting", zone_desc->origin);
    
    // locks the descriptor with the loader identity
    
    if(FAIL(return_value = zone_lock(zone_desc, ZONE_LOCK_UNMOUNT)))
    {
        log_err("database_service_zone_unmount: failed to lock zone settings for '%{dnsname}'", zone_desc->origin);
        return;
    }
    
    const u8 *origin = zone_desc->origin;
    
    log_info("zone unmount: %{dnsname}", origin);
    
    zone_desc->status_flags |= ZONE_STATUS_UNMOUNTING;
                    
    /*
     * Find the zone
     * 
     * Invalidate the zone
     * 
     * Set the zone pointer in the label to NULL
     * 
     * Queue the zone for unload
     */

    zdb *db;

    dnsname_vector origin_vector;

    notify_clear(zone_desc->origin);
    /// @todo signature maintenance clear, ie: dnssec_maintenance_clear(zone_desc->origin);
    /// @todo retry clearn, ie: retry_clear(zone_desc->origin);
        
    /// @todo arm an alarm for refresh
        
    zone_desc_log(MODULE_MSG_HANDLE, MSG_DEBUG1, zone_desc, "database_service_zone_unmount");

    db = g_config->database;

    group_mutex_lock(&db->mutex, ZDB_MUTEX_WRITER);
        
    dnsname_to_dnsname_vector(origin, &origin_vector);
    
    zdb_zone_label *zone_label = zdb_zone_label_find_nolock(db, &origin_vector);

    if(zone_label != NULL)
    {
        // there is a label at that location
        
        log_debug2("database_service_zone_unmount: label exists with a zone");
        
        zdb_zone *old_zone = zone_label->zone;
                
        if(old_zone != NULL)
        {
            // there is already a zone mounted
            
            zdb_zone_lock(old_zone, ZDB_ZONE_MUTEX_DESTROY);
            
            // the old zone is not invalid

            log_debug2("database_service_zone_unmount: removing zone@%p", old_zone);
            
            // mount new zone
            zone_label->zone = NULL;

            // set old zone as invalid                
            old_zone->apex->flags |= ZDB_RR_LABEL_INVALID_ZONE;
            zdb_zone_unlock(old_zone, ZDB_ZONE_MUTEX_DESTROY);

            group_mutex_unlock(&db->mutex, ZDB_MUTEX_WRITER);

            // destroy the old zone

            database_zone_unload(old_zone);
        }
        else
        {
            // the label exists, but no zone is present
            
            log_debug2("database_service_zone_unmount: label exists without a zone");
            
            group_mutex_unlock(&db->mutex, ZDB_MUTEX_WRITER);
        }
    }
    else
    {
        // no label exist
        
        log_debug2("database_service_zone_unmount: no label");
        
        // add the label (will lock/unlock for a writer)
        
        group_mutex_unlock(&db->mutex, ZDB_MUTEX_WRITER);        
    }
    
    zone_desc->status_flags &= ~(ZONE_STATUS_STARTING_UP|ZONE_STATUS_UNMOUNTING|ZONE_STATUS_PROCESSING);
    
    log_debug1("database_service_zone_unmount: unlocking zone '%{dnsname}' for unmounting", origin);
    
    database_fire_zone_unmounted(zone_desc, SUCCESS);
    
    zone_unlock(zone_desc, ZONE_LOCK_UNMOUNT);
}

/**
 * @}
 */


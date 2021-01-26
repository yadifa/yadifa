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

#include <dnsdb/zdb.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb-lock.h>

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
    
    log_debug1("database_service_zone_unmount(%{dnsname}@%p=%i)", zone_origin(zone_desc), zone_desc, zone_desc->rc);
    
    log_debug1("database_service_zone_unmount: locking zone '%{dnsname}' for unmounting", zone_origin(zone_desc));
    
    // locks the descriptor with the loader identity
    
    if(FAIL(return_value = zone_lock(zone_desc, ZONE_LOCK_UNMOUNT)))
    {
        log_err("database_service_zone_unmount: failed to lock zone settings for '%{dnsname}'", zone_origin(zone_desc));
        return;
    }
    
    const u8 *origin = zone_origin(zone_desc);
    
    log_info("zone unmount: %{dnsname}", origin);
    
    zone_set_status(zone_desc, ZONE_STATUS_UNMOUNTING);
                    
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

    notify_clear(zone_origin(zone_desc));

#if DEBUG
    zone_desc_log(MODULE_MSG_HANDLE, MSG_DEBUG1, zone_desc, "database_service_zone_unmount");
#endif

    db = g_config->database;

    zdb_zone *old_zone = zdb_remove_zone_from_dnsname(db, origin);
    
    if(old_zone != NULL)
    {
        log_debug2("database_service_zone_unmount: zone %{dnsname} @%p removed from the database", origin, old_zone);
        
        database_zone_unload(old_zone); // RC should mostly be one at this point
        
        zdb_zone_release(old_zone); // it's now the responsibility of database_zone_unload to drop the zone
    }
    else
    {
        log_debug2("database_service_zone_unmount: zone %{dnsname} not found in the database", origin);
    }

    if((zone_get_status(zone_desc) & ZONE_STATUS_LOAD_AFTER_DROP) != 0)
    {
        zdb_zone *invalid_zone = zdb_zone_create(zone_origin(zone_desc)); // RC = 1
        zdb_zone_invalidate(invalid_zone);

        zdb_zone *old_zone = zdb_set_zone(db, invalid_zone); // RC ++
        yassert(old_zone == NULL);
        (void)old_zone;

        zdb_zone_release(invalid_zone);
    }

    zone_clear_status(zone_desc, ZONE_STATUS_STARTING_UP|ZONE_STATUS_UNMOUNTING|ZONE_STATUS_PROCESSING);
    
    log_debug1("database_service_zone_unmount: unlocking zone '%{dnsname}' for unmounting", origin);
    
    database_fire_zone_unmounted(zone_desc);
    
    zone_unlock(zone_desc, ZONE_LOCK_UNMOUNT);
}

/**
 * @}
 */


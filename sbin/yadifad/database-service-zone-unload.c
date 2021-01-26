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
#include <dnsdb/zdb-zone-garbage.h>

#include "database-service.h"

#define MODULE_MSG_HANDLE g_server_logger

#define DBLOADQ_TAG 0x5144414f4c4244

/**********************************************************************************************************************/

#define DSZZUPRM_TAG 0x4d5250555a5a5344

struct database_service_zone_unload_parms_s
{
    zone_desc_s *zone_desc;
    zdb_zone *zone;
};

typedef struct database_service_zone_unload_parms_s database_service_zone_unload_parms_s;

static void*
database_service_zone_unload_thread(void *parms)
{
    database_service_zone_unload_parms_s *database_service_zone_unload_parms = (database_service_zone_unload_parms_s*)parms;
    zdb_zone *zone = database_service_zone_unload_parms->zone;
    
    u8 origin[MAX_DOMAIN_LENGTH];
    
    if(zone->origin != NULL)
    {    
        dnsname_copy(origin, zone->origin);
    }
    else
    {
        memcpy(origin, "\004NULL", 6);
    }
    
    log_debug("database-service: %{dnsname}: releasing old instance of zone", origin);
    log_debug7("database-service: %{dnsname}: rc=%i", origin, zone->rc);
    
    zdb_zone_release(zone);
    zone = NULL;
    
    zdb_zone_garbage_run();
    
    zone_release(database_service_zone_unload_parms->zone_desc);
    free(database_service_zone_unload_parms);
    
    return NULL;
}

/**
 * Replace a zone by another
 * The replaced zone will be destroyed as soon as it is not referenced yet
 * @param zone_desc
 * @param zone the zone to unload, note that it has been acquired for the call and must be released
 */

void
database_service_zone_unload(zone_desc_s *zone_desc, zdb_zone *zone)
{
    log_debug("database_service_zone_unload(%{dnsname}@%p=%i,%{dnsname})",
            zone_origin(zone_desc), zone_desc, zone_desc->rc,
            (zone != NULL)?zone->origin:(const u8*)"\004NULL");

    zdb_zone *work_zone = NULL;

    if(zone != NULL)
    {
        work_zone = zone; // zone will be released by the thread
        zone_lock(zone_desc, ZONE_LOCK_UNLOAD);
        if(zone == zone_desc->loaded_zone) // UNLOAD
        {
            log_warn("database_service_zone_unload: forced unload of %p = loaded_zone", zone);
            
            log_debug7("database_service_zone_unload: %{dnsname}@%p: loaded_zone@%p (was %p)",
                    zone_origin(zone_desc),
                    zone_desc,
                    NULL,
                    zone_desc->loaded_zone); // UNLOAD
            zdb_zone_release(zone_desc->loaded_zone);
            zone_desc->loaded_zone = NULL; // UNLOAD
        }
        // else the zone in the descriptor has changed : don't touch it
        zone_unlock(zone_desc, ZONE_LOCK_UNLOAD);
    }
    else
    {
        zone_lock(zone_desc, ZONE_LOCK_UNLOAD);
        work_zone = zone_desc->loaded_zone; // UNLOAD
        
        log_debug7("database_service_zone_unload: %{dnsname}@%p: loaded_zone@%p (was %p)",
                zone_origin(zone_desc),
                zone_desc,
                NULL,
                zone_desc->loaded_zone); // UNLOAD
        
        if(zone_desc->loaded_zone != NULL)
        {
            // the zone we are about to unload will be released by the thread
            //zdb_zone_release(zone_desc->loaded_zone);
            zone_desc->loaded_zone = NULL; // UNLOAD
        }
        zone_unlock(zone_desc, ZONE_LOCK_UNLOAD);
    }
    
    if(work_zone != NULL)
    {
        database_service_zone_unload_parms_s *parm;
        MALLOC_OBJECT_OR_DIE(parm, database_service_zone_unload_parms_s, DSZZUPRM_TAG);
        parm->zone_desc = zone_desc;
        parm->zone = work_zone;
    
        zone_acquire(zone_desc);
        database_service_zone_unload_queue_thread(database_service_zone_unload_thread, parm, NULL, "database_service_zone_unload_thread");
    }
    else
    {
        log_debug7("database_service_zone_unload: %{dnsname}@%p: nothing to unload",
                zone_origin(zone_desc),
                zone_desc);                   
    }
    zone_lock(zone_desc, ZONE_LOCK_UNLOAD);
    zone_clear_status(zone_desc, ZONE_STATUS_PROCESSING);
    zone_unlock(zone_desc, ZONE_LOCK_UNLOAD);
}

/**
 * @}
 */


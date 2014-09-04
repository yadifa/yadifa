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

#include "database-service.h"

#define MODULE_MSG_HANDLE g_server_logger

#define DBLOADQ_TAG 0x5144414f4c4244

/**********************************************************************************************************************/

struct database_service_zone_unload_parms_s
{
    zone_desc_s *zone_desc;
    zdb_zone *zone;
    zdb_zone *replacement_zone;
};

typedef struct database_service_zone_unload_parms_s database_service_zone_unload_parms_s;

static void*
database_service_zone_unload_thread(void *parms)
{
    database_service_zone_unload_parms_s *database_service_zone_unload_parms = (database_service_zone_unload_parms_s*)parms;
    zdb_zone *zone = database_service_zone_unload_parms->zone;
    zdb_zone *replacement_zone = database_service_zone_unload_parms->replacement_zone;
    
#ifdef DEBUG    
    log_debug("database_service_zone_unload_thread(%p,%p,%p)", database_service_zone_unload_parms->zone_desc, zone, replacement_zone);
    
    u8 origin[MAX_DOMAIN_LENGTH];
    
    if(zone->origin != NULL)
    {    
        dnsname_copy(origin, zone->origin);
    }
    else
    {
        memcpy(origin, "\004NULL", 6);
    }
    
    log_debug("database_service_zone_unload_thread(%{dnsname},%{dnsname})", origin, (replacement_zone != NULL)?replacement_zone->origin:(const u8*)"\004NULL");
#endif
    
    zdb_zone_destroy(zone);
   
#ifdef DEBUG
    zone = NULL;
    log_debug("database_service_zone_unload_thread(%{dnsname},%{dnsname}) done", origin, (replacement_zone != NULL)?replacement_zone->origin:(const u8*)"\004NULL");
#endif
    
    if(replacement_zone != NULL)
    {
        database_fire_zone_unloaded(replacement_zone, SUCCESS);
    }
    
    zone_release(database_service_zone_unload_parms->zone_desc);
    free(database_service_zone_unload_parms);
    
    return NULL;
}

void
database_service_zone_unload(zone_desc_s *zone_desc, zdb_zone *zone, zdb_zone *replacement_zone)
{
    log_debug("database_service_zone_unload(%{dnsname}@%p=%i,%{dnsname},%{dnsname})",
            zone_desc->origin, zone_desc, zone_desc->rc,
            (zone != NULL)?zone->origin:(const u8*)"\004NULL",
            (replacement_zone != NULL)?replacement_zone->origin:(const u8*)"\004NULL");
    
    database_service_zone_unload_parms_s *parm;
    MALLOC_OR_DIE(database_service_zone_unload_parms_s*, parm, sizeof(database_service_zone_unload_parms_s), GENERIC_TAG);
    parm->zone_desc = zone_desc;
    if(zone != NULL)
    {
        parm->zone = zone;
        
        if(zone == zone_desc->loaded_zone)
        {
            log_warn("database_service_zone_unload: forced unload of %p = loaded_zone", zone);
            
            log_debug7("database_service_zone_unload: %{dnsname}@%p: loaded_zone@%p (was %p)",
                zone_desc->origin,
                zone_desc,
                NULL,
                zone_desc->loaded_zone);
            
            zone_desc->loaded_zone = NULL;
        }
    }
    else
    {
        parm->zone = zone_desc->loaded_zone;
        
        log_debug7("database_service_zone_unload: %{dnsname}@%p: loaded_zone@%p (was %p)",
                zone_desc->origin,
                zone_desc,
                NULL,
                zone_desc->loaded_zone);
        
        zone_desc->loaded_zone = NULL;
    }
    parm->replacement_zone = replacement_zone;
    
    zone_acquire(zone_desc);
    database_service_zone_unload_queue_thread(database_service_zone_unload_thread, parm, NULL, "database_service_zone_unload_thread");
    
    zone_desc->status_flags &= ~ZONE_STATUS_PROCESSING;
}

/**
 * @}
 */


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

#include "zone.h"
#include "database-service.h"

#define MODULE_MSG_HANDLE g_server_logger

extern logger_handle *g_server_logger;
extern zone_data_set database_zone_desc;

void
database_service_zone_desc_unload(zone_desc_s *zone_desc)
{
    // Ensure that the zone is not mounted

    yassert(zone_desc != NULL);
    
    log_debug1("database_service_zone_desc_unload(%{dnsname}@%p=%i)", zone_origin(zone_desc), zone_desc, zone_desc->rc);
    
    log_info("zone: %{dnsname}: %p: will unregister", zone_origin(zone_desc), zone_desc);
    
    if(FAIL(zone_lock(zone_desc, ZONE_LOCK_DESC_UNLOAD)))
    {
        log_err("zone: %{dnsname}: %p: config: failed to lock zone settings", zone_origin(zone_desc), zone_desc);
        return;
    }
    
    if((zone_get_status(zone_desc) & ZONE_STATUS_REGISTERED) == 0)
    {
        log_err("zone: %{dnsname}: %p: config: is not registered", zone_origin(zone_desc), zone_desc);
        zone_clear_status(zone_desc, ZONE_STATUS_PROCESSING);
        zone_unlock(zone_desc, ZONE_LOCK_DESC_UNLOAD);
        return;
    }
    
    if(database_zone_desc_is_mounted(zone_origin(zone_desc)))
    {
        // mounted : unmount and unload, then try again
        
#if DEBUG
        database_zone_desc_is_mounted(zone_origin(zone_desc));
#endif
        yassert(zone_has_loaded_zone(zone_desc));
        if(zone_has_loaded_zone(zone_desc))
        {
            log_info("zone: %{dnsname}: %p: config: zone is mounted: unmounting", zone_origin(zone_desc), zone_desc);
            
            zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_UNMOUNT, NULL, TRUE);
            zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_UNLOAD, NULL, TRUE); // default zone
        }
        else
        {
            log_warn("zone: %{dnsname}: %p: config: zone is mounted but not referenced in its descriptor", zone_origin(zone_desc), zone_desc);
        }
        zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_DESC_UNLOAD, NULL, TRUE);
        
        zone_clear_status(zone_desc, ZONE_STATUS_PROCESSING);
        zone_unlock(zone_desc, ZONE_LOCK_DESC_UNLOAD);
    }
    else
    {
        /*
         * Remove the zone desc from the registered zones
         * Remove the zone desc from any alarm/task
         * Garbage the zone desc (new tool I have to make that mostly answers the dyn-prov-del issue)
         * ...
         * At some point in the future, free/destroy the zone desc
         */
        
        log_info("zone: %{dnsname}: %p: config: unregistering", zone_origin(zone_desc), zone_desc);
        
        u32 queue_size = bpqueue_size(&zone_desc->commands);

        if(queue_size > 0)
        {
            log_warn("zone: %{dnsname}: %p: config: still has %i commands in the queue", zone_origin(zone_desc), zone_desc, queue_size);
        }
        
        zone_unlock(zone_desc, ZONE_LOCK_DESC_UNLOAD);
        
        zone_desc_s *zone_unregistered_desc = zone_unregister(&database_zone_desc, zone_origin(zone_desc));

        if(zone_desc == zone_unregistered_desc)
        {
            zone_clear_status(zone_desc, ZONE_STATUS_REGISTERED);
            
            zone_release(zone_desc);
        }
        else
        {
            log_err("zone: %{dnsname}: %p: config: the registered descriptor is %p", zone_origin(zone_desc), zone_desc, zone_unregistered_desc);
            
            if(zone_unregistered_desc != NULL)
            {
                zone_release(zone_unregistered_desc);
            }
            else
            {
                log_err("zone: %{dnsname}: %p: config: not registered at all", zone_origin(zone_desc), zone_desc, zone_unregistered_desc);
            }
        }
        
        log_info("zone: %{dnsname}: unregistered", zone_origin(zone_desc));
        
        zone_clear_status(zone_desc, ZONE_STATUS_PROCESSING);
        zone_set_status(zone_desc, ZONE_STATUS_MARKED_FOR_DESTRUCTION);
    }
    
    log_debug1("database_service_zone_desc_unload(%p) done", zone_desc);
}

/**
 * @}
 */

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
#include <dnsdb/zdb_zone.h>

#include "zone.h"
#include "server.h"

#define MODULE_MSG_HANDLE g_server_logger

#define DBLOADQ_TAG 0x5144414f4c4244

/**********************************************************************************************************************/

void
database_service_zone_freeze(zone_desc_s *zone_desc)
{
    ya_result return_value;

#if DEBUG
    log_debug("database_service_zone_freeze(%{dnsname}@%p=%i)", zone_origin(zone_desc), zone_desc, zone_desc->rc);
#endif

    if(zone_desc == NULL)
    {
        log_err("zone freeze: NULL zone");
        return;
    }

    log_debug1("database_service_zone_freeze: locking zone '%{dnsname}' for freezing", zone_origin(zone_desc));

    if(FAIL(return_value = zone_lock(zone_desc, ZONE_LOCK_FREEZE)))
    {
        log_err("database_service_zone_freeze: failed to lock zone settings for '%{dnsname}'", zone_origin(zone_desc));
        return;
    }
    
    zdb_zone *zone = zone_get_loaded_zone(zone_desc); // ACQUIRES
    
    if(zone == NULL)
    {
        log_err("zone freeze: no zone loaded for '%{dnsname}'", zone_origin(zone_desc));
        zone_clear_status(zone_desc, ZONE_STATUS_PROCESSING);
        
        log_debug1("database_service_zone_freeze: unlocking zone '%{dnsname}' for freezing", zone_origin(zone_desc));
        
        zone_unlock(zone_desc, ZONE_LOCK_FREEZE);
        
        return;
    }
    
    // This REALLY is the simple reader lock.  This operation does not interfere
    // with readers, only with writers.  There is no point preventing queries
    // in the database while setting the zone read-only.
    
    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    if(zdb_zone_is_frozen(zone))
    {
        log_warn("zone freeze: %{dnsname} already frozen", zone->origin);
    }

    zdb_zone_set_frozen(zone);

    zdb_zone_release_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    log_info("zone freeze: %{dnsname}", zone_origin(zone_desc));
    
    zone_set_status(zone_desc, ZONE_STATUS_FROZEN);
    zone_clear_status(zone_desc, ZONE_STATUS_PROCESSING);
    
    log_debug1("database_service_zone_freeze: unlocking zone '%{dnsname}' for freezing", zone_origin(zone_desc));
    
    zone_unlock(zone_desc, ZONE_LOCK_FREEZE);
}

/**
 * @}
 */

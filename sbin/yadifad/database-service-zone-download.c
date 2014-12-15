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
 *   - download db
 *   - lookup database result of a message
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "config.h"

#include <dnscore/logger.h>
#include <dnscore/serial.h>
#include <dnscore/timeformat.h>

#include <dnsdb/zdb_zone.h>

#include "database-service.h"
#include "axfr.h"
#include "ixfr.h"

#define MODULE_MSG_HANDLE g_server_logger

#define DBLOADQ_TAG 0x5144414f4c4244

/**********************************************************************************************************************/

struct database_service_zone_download_parms_s
{
    u16  qtype;
    u8 origin[MAX_DOMAIN_LENGTH];
};

typedef struct database_service_zone_download_parms_s database_service_zone_download_parms_s;

static ya_result
database_service_zone_download_xfr(u16 qtype, const u8 *origin)
{
    ya_result return_value;
    
#ifdef DEBUG
    log_debug("database_service_zone_download_xfr(%{dnstype},%{dnsname})", &qtype, origin);
#endif
    
    zone_desc_s *zone_desc = zone_acquirebydnsname(origin);

    /*
     * If the zone descriptor (config) exists and it can be locked by the loader ...
     */

    if(zone_desc == NULL)
    {
        log_debug1("database_service_zone_download_thread: no zone settings for '%{dnsname}'", origin);
        return ERROR;
    }
    
    log_debug1("database_service_zone_download_thread: locking zone '%{dnsname}' for loading", origin);
    
    // locks the descriptor with the loader identity

    if(FAIL(return_value = zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC)))
    {
        log_debug1("database_service_zone_download_thread: failed to lock zone settings for '%{dnsname}'", origin);
        zone_release(zone_desc);
        return return_value;
    }
    
    const u32 must_be_off = ZONE_STATUS_DOWNLOADING_XFR_FILE;
    
    if((zone_desc->status_flags & must_be_off) != 0)
    {
        zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                
        log_debug1("database_service_zone_download_thread: invalid status for '%{dnsname}'", origin);
        zone_release(zone_desc);
        return ERROR;
    }
    
    zone_desc->status_flags |= ZONE_STATUS_DOWNLOADING_XFR_FILE;
    
    zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
    
    zdb_zone *zone = zdb_zone_find_from_dnsname(g_config->database, origin, CLASS_IN);

    if(zone != NULL)
    {
        soa_rdata soa;
        u32 local_serial;
        
        zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        return_value = zdb_zone_getsoa(zone, &soa);
        //return_value = zdb_zone_getserial(zone, &local_serial);
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        local_serial = soa.serial;
        
        if(ISOK(return_value))
        {
            log_debug("database_service_zone_download_thread: serial of %{dnsname} on the server is %d", origin, local_serial);
            
            u32 master_serial;
            
            zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
            
            return_value = message_query_serial(origin, zone_desc->masters, &master_serial);
            
            zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
            
            if(ISOK(return_value))
            {
                log_debug("database_service_zone_download_thread: serial of %{dnsname} on the master is %d", origin, master_serial);

                if(serial_le(master_serial, local_serial))
                {
                    if(serial_lt(master_serial, local_serial))
                    {
                        log_warn("database_service_zone_download_thread: serial of %{dnsname} is lower on the master", origin);
                    }
                            
                    log_debug("database_service_zone_download_thread: serial of %{dnsname} is not lower than the one on the master", origin);
                    
                    zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                               
                    zone_desc->status_flags &= ~(ZONE_STATUS_DOWNLOADING_XFR_FILE|ZONE_STATUS_PROCESSING);
                    zone_desc->refresh.refreshed_time = time(NULL);
                    zone_desc->refresh.retried_time = zone_desc->refresh.refreshed_time;

                    u32 next_refresh = zone_desc->refresh.refreshed_time + soa.refresh;
                    EPOCH_DEF(next_refresh);
                    log_info("database: refresh: zone %{dnsname}: refreshed, next one at %w", origin, EPOCH_REF(next_refresh));

                    database_zone_refresh_maintenance_wih_zone(zone, next_refresh);
                    
                    database_fire_zone_downloaded(origin, TYPE_NONE, local_serial, SUCCESS);

                    zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                    zone_release(zone_desc);
                    
                    return SUCCESS;
                }
            }
        }
    }
    
    // get ready with the download of the AXFR/IXFR
    
    zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
    
    host_address *servers = host_address_copy_list(zone_desc->masters);
    
    zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
    
    u32 loaded_serial = ~0;
    u16 transfer_type = 0;
    
    switch(qtype)
    {
        case TYPE_AXFR:
        {
            log_info("slave: %{dnsname} AXFR query to the master", origin);
            
            if(ISOK(return_value = axfr_query(servers, origin, &loaded_serial)))
            {
                zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                zone_desc->refresh.refreshed_time = time(NULL);
                zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                
                transfer_type = (u16)return_value;
                                
                if(transfer_type != 0)
                {
                    log_info("slave: loaded %{dnstype} for domain %{dnsname} from master at %{hostaddr}, serial is %d", &qtype, origin, servers, loaded_serial);
                }
            }
            else
            {
                log_err("slave: query error for domain %{dnsname} from master at %{hostaddr}: %r", origin, servers, return_value);
            }
            
            break;
        }
        
        case TYPE_IXFR:
        {
            log_info("slave: %{dnsname} IXFR query to the master", origin);

            if(zone == NULL)
            {
                log_err("slave: zone %{dnsname} is not in the database", origin);

                return_value = ERROR;
                break;
            }

            if((zone_desc->flags & ZONE_FLAG_NO_MASTER_UPDATES) == 0)
            {
                if(ISOK(return_value = ixfr_query(servers, zone, &loaded_serial)))
                {
                    zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                    zone_desc->refresh.refreshed_time = time(NULL);
                    zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                    
                    transfer_type = (u16)return_value;

                    if(transfer_type != 0)
                    {
                        log_info("slave: loaded %{dnstype} for domain %{dnsname} from master at %{hostaddr}, new serial is %d", &qtype, origin, servers, loaded_serial);
                    }
                }
                else
                {
                    log_err("slave: query error for domain %{dnsname} from master at %{hostaddr}: %r", origin, servers, return_value);
                }
            }
            else
            {
                loaded_serial = 0;
            }
            // else XFRs to the master are disabled
            
            break;
        }
        default:
        {
            
        }
    }

    
    zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
    
    zone_desc->status_flags &= ~(ZONE_STATUS_DOWNLOADING_XFR_FILE|ZONE_STATUS_PROCESSING);
        
    database_fire_zone_downloaded(origin, transfer_type, loaded_serial, return_value);
    
    zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
   
#ifdef DEBUG
    log_debug("database_service_zone_download_thread(%{dnstype},%{dnsname}) done", &qtype, origin);
#endif
    
    zone_release(zone_desc);
    
    host_address_delete_list(servers);
       
    return SUCCESS;
}

static void*
database_service_zone_download_thread(void *parms)
{
#ifdef DEBUG
    log_debug("database_service_zone_download_thread(%p)", parms);
#endif
    
    database_service_zone_download_parms_s *database_service_zone_download_parms = (database_service_zone_download_parms_s*)parms;
    const u8 *origin = database_service_zone_download_parms->origin;
    u16 qtype = database_service_zone_download_parms->qtype;
    
    database_service_zone_download_xfr(qtype, origin);
    
    free(database_service_zone_download_parms);
    database_service_zone_download_parms = NULL;
    
    return NULL;
}

void
database_service_zone_axfr_query(const u8 *origin)
{
#ifdef DEBUG
    log_debug("database_service_zone_axfr_query(%{dnsname})", origin);
#endif
    
    database_service_zone_download_parms_s *parm;
    MALLOC_OR_DIE(database_service_zone_download_parms_s*, parm, sizeof(database_service_zone_download_parms_s), GENERIC_TAG);
    parm->qtype = TYPE_AXFR;
    dnsname_copy(parm->origin, origin);
    
    database_service_zone_download_queue_thread(database_service_zone_download_thread, parm, NULL, "database_service_zone_download_thread");
}

void
database_service_zone_ixfr_query(const u8 *origin)
{
#ifdef DEBUG
    log_debug("database_service_zone_ixfr_query(%{dnsname})", origin);
#endif
    
    database_service_zone_download_parms_s *parm;
    MALLOC_OR_DIE(database_service_zone_download_parms_s*, parm, sizeof(database_service_zone_download_parms_s), GENERIC_TAG);
    parm->qtype = TYPE_IXFR;
    dnsname_copy(parm->origin, origin);
        
    database_service_zone_download_queue_thread(database_service_zone_download_thread, parm, NULL, "database_service_zone_download_thread");
}

/**
 * @}
 */

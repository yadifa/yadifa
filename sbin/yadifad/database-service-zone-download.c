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
 *   - download db
 *   - lookup database result of a message
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "server-config.h"

#include <dnscore/logger.h>
#include <dnscore/serial.h>
#include <dnscore/timeformat.h>

#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb-zone-path-provider.h>
#define ZDB_JOURNAL_CODE 1
#include <dnsdb/journal.h>

#include "database-service.h"
#include "axfr.h"
#include "ixfr.h"

#define MODULE_MSG_HANDLE g_server_logger

#define DBLOADQ_TAG 0x5144414f4c4244

/**********************************************************************************************************************/

#define DSZDLPRM_TAG 0x4d52504c445a5344

#define ARBITRARY_REFRESH_VALUE 3600 // seconds

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
    
#if DEBUG
    log_debug("database_service_zone_download_xfr(%{dnstype},%{dnsname})", &qtype, origin);
#endif
        
    zone_desc_s *zone_desc = zone_acquirebydnsname(origin);
    host_address *servers = NULL;
    u32 loaded_serial = ~0;
    u32 loaded_refresh = ~0;
    u16 transfer_type = 0;
    bool may_try_next_master = FALSE;
    
    /*
     * If the zone descriptor (config) exists and it can be locked by the loader ...
     */

    if(zone_desc == NULL)
    {
        log_debug1("database_service_zone_download_thread: no zone settings for '%{dnsname}'", origin);
        return INVALID_STATE_ERROR;
    }
    
    log_debug1("database_service_zone_download_thread: locking zone '%{dnsname}' for loading", origin);
    
    // locks the descriptor with the loader identity

    if(FAIL(return_value = zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC)))
    {
        log_debug1("database_service_zone_download_thread: failed to lock zone settings for '%{dnsname}'", origin);
        
        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        return return_value;
    }
        
    if(zone_desc->type != ZT_SLAVE)
    {
        log_warn("database_service_zone_download_thread: zone '%{dnsname}' is not a slave", origin);
        zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
        
        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        return return_value;
    }
    
    const u32 must_be_off = ZONE_STATUS_DOWNLOADING_XFR_FILE | ZONE_STATUS_DOWNLOADED | ZONE_STATUS_LOAD | ZONE_STATUS_LOADING;
    
    if((zone_get_status(zone_desc) & must_be_off) != 0)
    {
        zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);

        log_debug1("database_service_zone_download_thread: invalid status for '%{dnsname}'", origin);
        
        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        return INVALID_STATE_ERROR;
    }
    
    if(dnscore_shuttingdown())
    {
        zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
        
        log_debug("zone download: zone download cancelled by shutdown");
        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        
        return STOPPED_BY_APPLICATION_SHUTDOWN;
    }
    
    zone_set_status(zone_desc, ZONE_STATUS_DOWNLOADING_XFR_FILE);
    
    bool is_multimaster = zone_is_multimaster(zone_desc);
    bool is_true_multimaster = zone_is_true_multimaster(zone_desc);
    bool force_load = (zone_desc->flags & ZONE_FLAG_DROP_CURRENT_ZONE_ON_LOAD) != 0;
        
    zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
    
    bool retry;

    do
    {
        retry = FALSE;
        
        zdb_zone *zone = zdb_acquire_zone_read_from_fqdn(g_config->database, origin); // ACQUIRES (obviously)

        if(zone != NULL)
        {
            soa_rdata soa;

            zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
            return_value = zdb_zone_getsoa(zone, &soa); // zone is locked
            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

            if(ISOK(return_value))
            {
                u32 local_serial;
                local_serial = soa.serial;

                log_debug("database_service_zone_download_thread: serial of %{dnsname} on the server is %d", origin, local_serial);

                u32 master_serial;

                zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                host_address *zone_desc_masters = host_address_copy_list(zone_desc->masters);
                zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);

                return_value = message_query_serial(origin, zone_desc_masters , &master_serial);

                host_address_delete_list(zone_desc_masters);

                if(ISOK(return_value))
                {
                    log_debug("database_service_zone_download_thread: serial of %{dnsname} on the master is %d", origin, master_serial);

                    // compare serials

                    if(!force_load && serial_le(master_serial, local_serial))
                    {
                        if(serial_lt(master_serial, local_serial))
                        {
                            log_warn("database_service_zone_download_thread: serial of %{dnsname} is lower on the master", origin);
                        }

                        log_debug("database_service_zone_download_thread: serial of %{dnsname} is not lower than the one on the master", origin);

                        zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                        zone_clear_status(zone_desc, ZONE_STATUS_DOWNLOADING_XFR_FILE|ZONE_STATUS_PROCESSING);
                        zone_desc->refresh.refreshed_time = time(NULL);
                        zone_desc->refresh.retried_time = zone_desc->refresh.refreshed_time;

                        u32 next_refresh = zone_desc->refresh.refreshed_time + soa.refresh;

                        log_info("database: refresh: %{dnsname}: zone didn't need a refresh, next refresh currently scheduled for %T", origin, next_refresh);

                        database_zone_refresh_maintenance_wih_zone(zone, next_refresh);

                        zdb_zone_release(zone);

                        database_fire_zone_downloaded(origin, TYPE_NONE, local_serial, SUCCESS);

                        zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                        zone_release(zone_desc);

                        return SUCCESS;
                    }
                }
                else
                {
                    log_warn("database: could not get the serial of %{dnsname} from the master @%{hostaddr}: %r", zone_origin(zone_desc), zone_desc->masters, return_value);
                }
            }
        }

        if(dnscore_shuttingdown())
        {
            log_debug("zone download: zone download cancelled by shutdown (loop)");
            database_fire_zone_processed(zone_desc);
            zone_release(zone_desc);

            return STOPPED_BY_APPLICATION_SHUTDOWN;
        }

        // get ready with the download of the AXFR/IXFR

        zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
        servers = host_address_copy_list(zone_desc->masters);
        zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);

        loaded_serial = ~0;
        transfer_type = 0;
        may_try_next_master = FALSE;

        switch(qtype)
        {
            case TYPE_AXFR:
            {
                log_info("slave: %{dnsname} AXFR query to the master", origin);

                if(ISOK(return_value = axfr_query_ex(servers, origin, &loaded_serial, &loaded_refresh)))
                {
                    zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                    zone_desc->refresh.refreshed_time = time(NULL);
                    zone_desc->multimaster_failures = 0;
                    zone_set_status(zone_desc, ZONE_STATUS_DOWNLOADED);
                    zone_desc->download_failure_count = 0;
                    zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);

                    u32 next_refresh = zone_desc->refresh.refreshed_time + loaded_refresh;
                    database_zone_refresh_maintenance_wih_zone(zone, next_refresh);

                    transfer_type = (u16)return_value; /// @note comes from axfr_query_master_ex, take care not overwriting it

                    if(transfer_type != 0)
                    {
                        log_info("slave: %{dnsname}: got %{dnstype} from master at %{hostaddr}, serial is %u", origin, &qtype, servers, loaded_serial);
                    }
                }
                else
                {
                    if(return_value != STOPPED_BY_APPLICATION_SHUTDOWN)
                    {
                        log_err("slave: %{dnsname}: axfr query error from master at %{hostaddr}: %r", origin, servers, return_value);
                    }

                    may_try_next_master = is_multimaster;

                    zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                    ++zone_desc->download_failure_count;
                    zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                }

                break;
            }

            case TYPE_IXFR:
            {
                log_info("slave: %{dnsname}: IXFR query to the master", origin);

                if(zone == NULL)
                {
                    log_err("slave: %{dnsname}: zone is not in the database", origin);

                    return_value = ZDB_ERROR_ZONE_NOT_IN_DATABASE;
                    break;
                }

                if(zdb_zone_isinvalid(zone))
                {
                    zdb_zone *current_zone = zdb_acquire_zone_read_from_fqdn(g_config->database, origin); // ACQUIRES (obviously)
                    
                    if(zone != current_zone)
                    {
                        retry = TRUE;
                    }
                    else
                    {
                        log_err("slave: %{dnsname}: cannot start an incremental transfer from an invalid zone", origin);
                    }
                    
                    zdb_zone_release(current_zone);
    
                    return_value = ZDB_ERROR_ZONE_INVALID;
                    break;
                }

                if((zone_desc->flags & ZONE_FLAG_NO_MASTER_UPDATES) == 0)
                {
                    return_value = ixfr_query(servers, zone, &loaded_serial);
                            
                    if(ISOK(return_value) || (return_value == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY))
                    {
                        zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                        zone_desc->refresh.refreshed_time = time(NULL);
                        zone_desc->multimaster_failures = 0;
                        zone_desc->download_failure_count = 0;
                        zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);

                        transfer_type = (u16)return_value;

                        if(ISOK(return_value) && (transfer_type != 0))
                        {
                            log_info("slave: %{dnsname}: got %{dnstype} from master at %{hostaddr}, new serial is %u", origin, &qtype, servers, loaded_serial);
                        }
                        
                        // the stream query may have been cut by the journal because it was full (or one of the many equivalent states)
                        // the zone needs to be stored on disk so the journal can go further
                        
                        if(return_value == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                        {
                            zdb_zone_info_background_store_zone(zone->origin);
                        }
                        else
                        {
                            soa_rdata soa;
                            u32 next_refresh;
                            zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                            return_value = zdb_zone_getsoa(zone, &soa); // zone is locked
                            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                            if(ISOK(return_value))
                            {
                                next_refresh = zone_desc->refresh.refreshed_time + soa.refresh;
                            }
                            else
                            {
                                log_warn("slave: %{dnsname}: ixfr query error from master at %{hostaddr}: there was an issue getting the refresh value from the SOA: %r (defaulting to %i)", origin, servers, return_value, ARBITRARY_REFRESH_VALUE);
                                next_refresh = zone_desc->refresh.refreshed_time + ARBITRARY_REFRESH_VALUE;
                            }

                            database_zone_refresh_maintenance_wih_zone(zone, next_refresh);
                        }
                        
                        return_value = SUCCESS;
                    }
                    else if(return_value == MAKE_DNSMSG_ERROR(RCODE_NOTIMP))
                    {
                        log_warn("slave: %{dnsname}: ixfr query error from master at %{hostaddr}: it does not support incremental transfers and does not falls back to AXFR, switching to AXFR", origin, servers);
                        
                        qtype = TYPE_AXFR;
                        retry = TRUE;
                    }
                    else
                    {
                        if(return_value != STOPPED_BY_APPLICATION_SHUTDOWN)
                        {
                            log_err("slave: %{dnsname}: ixfr query error from master at %{hostaddr}: %r", origin, servers, return_value);
                        }

                        may_try_next_master = is_multimaster;

                        zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                        ++zone_desc->download_failure_count;
                        zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
                    }
                }
                else
                {
                    log_info("slave: master updates for domain %{dnsname} disabled by configuration", origin);
                    loaded_serial = 0;
                }
                // else XFRs to the master are disabled

                break;
            }
            default:
            {
                log_err("slave: %{dnsname}: %{hostaddr} gave unexpected answer of type %{dnstype}", servers, &qtype, origin);
                break;
            }
        } // switch(qtype)

        if(zone != NULL)
        {
            zdb_zone_release(zone);
        }
    }
    while(retry);

    if(dnscore_shuttingdown())
    {
        log_debug("zone download: zone download cancelled by shutdown (rearm)");
        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);

        return STOPPED_BY_APPLICATION_SHUTDOWN;
    }
    
    zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
    
    zone_clear_status(zone_desc, ZONE_STATUS_DOWNLOADING_XFR_FILE|ZONE_STATUS_PROCESSING);

    if(!may_try_next_master)
    {
        database_fire_zone_downloaded(origin, transfer_type, loaded_serial, return_value);

        if(FAIL(return_value))
        {
            random_ctx rndctx = thread_pool_get_random_ctx();
            u32 jitter = random_next(rndctx);
            if(g_config->axfr_retry_jitter > 0)
            {
                jitter %= g_config->axfr_retry_jitter;
            }

            time_t next_try = time(NULL) + g_config->axfr_retry_delay + jitter +
                    MIN(zone_desc->download_failure_count * g_config->axfr_retry_failure_delay_multiplier, g_config->axfr_retry_failure_delay_max);
            
            if(qtype == TYPE_AXFR)
            {
                log_warn("slave: %{dnsname}: master %{hostaddr} failed to answer AXFR query for domain retrying at %T", origin, servers, next_try);
                
                database_zone_axfr_query_at(zone_origin(zone_desc), next_try); // should not be lower than 5
            }
            else
            {
                log_warn("slave: %{dnsname}: master %{hostaddr} failed to answer IXFR query for domain retrying at %T", origin, servers, next_try);
                
                database_zone_ixfr_query_at(zone_origin(zone_desc), next_try); // should not be lower than 5
            }
        }
        // else success
    }
    else // failure + multimaster
    {
        random_ctx rndctx = thread_pool_get_random_ctx();
        u32 jitter = random_next(rndctx);
        if(g_config->axfr_retry_jitter > 0)
        {
            jitter %= g_config->axfr_retry_jitter;
        }
        
        time_t next_try = time(NULL) + g_config->axfr_retry_delay + jitter;
                
        if(zone_desc->multimaster_failures < zone_desc->multimaster_retries)
        {
            next_try += MIN(zone_desc->download_failure_count * g_config->axfr_retry_failure_delay_multiplier, g_config->axfr_retry_failure_delay_max);
            
            if(zone_desc->multimaster_failures < MAX_U8)
            {
                ++zone_desc->multimaster_failures;
            }
            
            if(qtype == TYPE_AXFR)
            {
                log_warn("slave: %{dnsname}: master %{hostaddr} failed to answer AXFR query for domain retrying at %T (retry %u)", origin, servers, next_try, zone_desc->multimaster_failures);
                
                database_zone_axfr_query_at(zone_origin(zone_desc), next_try); // should not be lower than 5
            }
            else
            {
                log_warn("slave: %{dnsname}: master %{hostaddr} failed to answer IXFR query for domain retrying at %T (retry %u)", origin, servers, next_try, zone_desc->multimaster_failures);
                
                database_zone_ixfr_query_at(zone_origin(zone_desc), next_try); // should not be lower than 5
            }
        }
        else
        {
            // next master
            host_address_list_roll(&zone_desc->masters);
            zone_desc->multimaster_failures = 0;
            
            if(is_true_multimaster)
            {
                char file_name[PATH_MAX];
                
                log_warn("slave: %{dnsname}: master %{hostaddr} failed to answer query for domain, will load a new zone with master %{hostaddr} at %T", origin, servers, zone_desc->masters, next_try);
                
                /// @note 20160623 edf -- true multimaster : destroying local zone is the only way to go 
                
                journal_truncate(origin);

                // delete zone file, axfr file, journal
                snformat(file_name, sizeof(file_name), "%s%s", g_config->data_path, zone_desc->file_name);
                log_debug("slave: %{dnsname}: deleting '%s'", origin, file_name);
                unlink(file_name);

                if(ISOK(return_value = zdb_zone_path_get_provider()(
                        origin, 
                        file_name, sizeof(file_name) - 6,
                        ZDB_ZONE_PATH_PROVIDER_AXFR_FILE|ZDB_ZONE_PATH_PROVIDER_MKDIR)))
                {
                    log_debug("slave: %{dnsname}: deleting '%s'", origin, file_name);
                    unlink(file_name);
                }               
                
                zone_desc->flags |= ZONE_FLAG_DROP_CURRENT_ZONE_ON_LOAD;
                
                database_zone_axfr_query_at(zone_origin(zone_desc), next_try);
            }
            else
            {
                if(qtype == TYPE_AXFR)
                {
                    log_warn("slave: %{dnsname}: master %{hostaddr} failed to answer AXFR query for domain trying with master %{hostaddr} at %T", origin, servers, zone_desc->masters, next_try);
                    
                    database_zone_axfr_query_at(zone_origin(zone_desc), next_try);
                }
                else if(qtype == TYPE_IXFR)
                {
                    log_warn("slave: %{dnsname}: master %{hostaddr} failed to answer IXFR query for domain trying with master %{hostaddr} at %T", origin, servers, zone_desc->masters, next_try);
                    
                    database_zone_ixfr_query_at(zone_origin(zone_desc), next_try);
                }
            }
        }
    }
    
    // all branches leading to this point are setting an alarm to try again in case of failure
        
    zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
   
#if DEBUG
    log_debug("database_service_zone_download_thread(%{dnstype},%{dnsname}) done", &qtype, origin);
#endif
    
    zone_release(zone_desc);
    
    host_address_delete_list(servers);
       
    return SUCCESS;
}

static void*
database_service_zone_download_thread(void *parms)
{
#if DEBUG
    log_debug("database_service_zone_download_thread(%p)", parms);
#endif
    database_service_zone_download_parms_s *database_service_zone_download_parms = (database_service_zone_download_parms_s*)parms;

    if(!dnscore_shuttingdown())
    {
        const u8 *origin = database_service_zone_download_parms->origin;
        u16 qtype = database_service_zone_download_parms->qtype;

        database_service_zone_download_xfr(qtype, origin);
    }
    
    free(database_service_zone_download_parms);
    database_service_zone_download_parms = NULL;
    
    return NULL;
}

void
database_service_zone_axfr_query(const u8 *origin)
{
#if DEBUG
    log_debug("database_service_zone_axfr_query(%{dnsname})", origin);
#endif
    
    database_service_zone_download_parms_s *parm;
    MALLOC_OBJECT_OR_DIE(parm, database_service_zone_download_parms_s, DSZDLPRM_TAG);
    parm->qtype = TYPE_AXFR;
    dnsname_copy(parm->origin, origin);
    
    database_service_zone_download_queue_thread(database_service_zone_download_thread, parm, NULL, "database_service_zone_download_thread");
}

void
database_service_zone_ixfr_query(const u8 *origin)
{
#if DEBUG
    log_debug("database_service_zone_ixfr_query(%{dnsname})", origin);
#endif
    
    database_service_zone_download_parms_s *parm;
    MALLOC_OBJECT_OR_DIE(parm, database_service_zone_download_parms_s, DSZDLPRM_TAG);
    parm->qtype = TYPE_IXFR;
    dnsname_copy(parm->origin, origin);
        
    database_service_zone_download_queue_thread(database_service_zone_download_thread, parm, NULL, "database_service_zone_download_thread");
}

/**
 * @}
 */

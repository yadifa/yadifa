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
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb_zone_write.h>
#include <dnsdb/zdb-lock.h>
#define ZDB_JOURNAL_CODE 1
#include <dnsdb/journal.h>

#include "zone.h"
#include "server.h"
#include "database-service.h"

#if HAS_RRSIG_MANAGEMENT_SUPPORT
#include "database-service-zone-resignature.h"
#include "database-service-zone-download.h"

#endif

#define MODULE_MSG_HANDLE g_server_logger

/**
 * Saves a zone in the current thread using the provided locks (0 meaning: do not try to lock)
 * Not locking puts the responsibility of the lock to the caller as having this code running
 * without any lock whatsoever on the descriptor/zone will give undefined results, a.k.a : crash.
 * 
 * @param zone_desc
 * @param desclockowner
 * @param zonelockowner
 * @return 
 */

ya_result
database_service_zone_store_ex(zone_desc_s *zone_desc, u8 desclockowner, u8 zonelockowner, u8 flags)
{
    // not implemented yet
    log_debug("zone store: %{dnsname}@%p#%i", zone_origin(zone_desc), zone_desc, zone_desc->rc);
    
    // for all modified zones descriptors
    //   if the file source is defined AND the source is not a template
    //     if the zone is valid
    //       save the text representation of the zone to the disk

    //bool must_be_on = ZONE_STATUS_READONLY|ZONE_STATUS_MODIFIED;
    
    bool save_unmodified = flags & DATABASE_SERVICE_ZONE_SAVE_UNMODIFIED;
    // bool ignore_shutdown = flags & DATABASE_SERVICE_ZONE_SAVE_IGNORE_SHUTDOWN;
    
    const u32 must_be_off  = ZONE_STATUS_TEMPLATE_SOURCE_FILE | ZONE_STATUS_STARTING_UP |
                             ZONE_STATUS_LOADING | ZONE_STATUS_MOUNTING | ZONE_STATUS_UNMOUNTING |
                             ZONE_STATUS_DROPPING | ZONE_STATUS_SAVING_ZONE_FILE |
                             ZONE_STATUS_SAVING_AXFR_FILE | ZONE_STATUS_SIGNATURES_UPDATING |
                             ZONE_STATUS_DYNAMIC_UPDATING | /*ZONE_STATUS_DOWNLOADING_XFR_FILE |*/
                             ZONE_STATUS_UNREGISTERING;
    
    if(desclockowner != 0)
    {
        zone_lock(zone_desc, desclockowner);
    }



    if(zone_desc->file_name == NULL)
    {
        log_notice("zone store: %{dnsname}: has no source file set", zone_origin(zone_desc));
        zone_clear_status(zone_desc, ZONE_STATUS_SAVETO_ZONE_FILE|ZONE_STATUS_SAVING_ZONE_FILE|ZONE_STATUS_PROCESSING);
        if(desclockowner != 0)
        {
            zone_unlock(zone_desc, desclockowner);
        }
        
        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);        
        return INVALID_STATE_ERROR;
    }
    
    if((zone_get_status(zone_desc) & ZONE_STATUS_TEMPLATE_SOURCE_FILE) != 0)
    {
        log_notice("zone store: %{dnsname}: source is a template", zone_origin(zone_desc));
        zone_clear_status(zone_desc, ZONE_STATUS_SAVETO_ZONE_FILE|ZONE_STATUS_SAVING_ZONE_FILE|ZONE_STATUS_PROCESSING);
        if(desclockowner != 0)
        {
            zone_unlock(zone_desc, desclockowner);
        }
        
        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        return INVALID_STATE_ERROR;
    }
    
    if((zone_get_status(zone_desc) & must_be_off) != 0)
    {
        log_info("zone store: %{dnsname}: cannot be stored at this time (%08x & %08x = %08x)",
                zone_origin(zone_desc), zone_get_status(zone_desc), must_be_off, zone_get_status(zone_desc) & must_be_off);
        zone_clear_status(zone_desc, ZONE_STATUS_SAVETO_ZONE_FILE|ZONE_STATUS_SAVING_ZONE_FILE|ZONE_STATUS_PROCESSING);
        if(desclockowner != 0)
        {
            zone_unlock(zone_desc, desclockowner);
        }
        
        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        return INVALID_STATE_ERROR;
    }
    
    zone_set_status(zone_desc, ZONE_STATUS_SAVING_ZONE_FILE);
    
    zdb *db = g_config->database;

    zdb_zone *zone;
    
    if(zonelockowner != 0)
    {
        zone = zdb_acquire_zone_read_lock_from_fqdn(db, zone_origin(zone_desc), zonelockowner); // ACQUIRES & LOCKS
    }
    else
    {
        zone = zdb_acquire_zone_read_from_fqdn(db, zone_origin(zone_desc)); // ACQUIRES
    }
    
    ya_result ret = ZDB_ERROR_ZONE_NOT_IN_DATABASE; // no zone acquired (could not acquire zone error code)
    
    if(zone != NULL)
    {
        if(!save_unmodified)
        {
            bool modified = zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_MODIFIED;

            if(!modified)
            {
                if(zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_NEED_REFRESH)
                {
                    if(!dnscore_shuttingdown())
                    {
                        log_info("zone store: %{dnsname}: will resume interrupted transfer", zone_origin(zone_desc));
                        database_service_zone_ixfr_query(zone->origin);
                    }

                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_NEED_REFRESH);
                }

                if(zonelockowner != 0)
                {
                    zdb_zone_release_unlock(zone, zonelockowner);
                }
                else
                {
                    zdb_zone_release(zone);
                }

                log_debug("zone store: %{dnsname}: hasn't been modified", zone_origin(zone_desc));

                if((zone_get_status(zone_desc) & ZONE_STATUS_MUST_CLEAR_JOURNAL) != 0)
                {
                    log_info("zone store: %{dnsname}: clearing journal", zone_origin(zone_desc));
                    journal_truncate(zone_origin(zone_desc));
                }

                zone_clear_status(zone_desc, ZONE_STATUS_SAVETO_ZONE_FILE|ZONE_STATUS_SAVING_ZONE_FILE|ZONE_STATUS_PROCESSING|ZONE_STATUS_MUST_CLEAR_JOURNAL);

                if(desclockowner != 0)
                {
                    zone_unlock(zone_desc, desclockowner);
                }

                database_fire_zone_processed(zone_desc);
                zone_release(zone_desc);
                return SUCCESS;
            }
        }

        if(zdb_zone_isvalid(zone))
        {
            char file_name[PATH_MAX];    
            snformat(file_name, sizeof(file_name), "%s/%s", g_config->data_path, zone_desc->file_name);
    
            log_info("zone store: %{dnsname}: storing zone to file '%s'", zone_origin(zone_desc), file_name);
            
            ret = zdb_zone_write_text_file(zone, file_name, flags); // zone is locked, clears the modified flag when successful
            
            if(ISOK(ret))
            {
                zdb_zone_getserial(zone, &zone_desc->stored_serial); // zone is locked

                bool clear_journal = zone_get_status(zone_desc) & ZONE_STATUS_MUST_CLEAR_JOURNAL;
                
                if(clear_journal)
                {
                    log_info("zone store: %{dnsname}: clearing journal", zone_origin(zone_desc));
                    
                    journal_truncate(zone_origin(zone_desc));
                    zone_clear_status(zone_desc, ZONE_STATUS_MUST_CLEAR_JOURNAL);
                }

                log_info("zone store: %{dnsname}: stored zone to file '%s'", zone_origin(zone_desc), file_name);

                if(zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_NEED_REFRESH)
                {
                    log_info("zone store: %{dnsname}: will resume interrupted transfer", zone_origin(zone_desc));
                    database_service_zone_ixfr_query(zone->origin);
                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_NEED_REFRESH);
                }
            }
            else
            {
                if(ret != STOPPED_BY_APPLICATION_SHUTDOWN)
                {
                    log_err("zone store: %{dnsname}: failed to store as '%s': %r", zone_origin(zone_desc), file_name, ret);
                }
                else
                {
                    log_debug("zone store: %{dnsname}: cancelled by shutdown", zone_origin(zone_desc), file_name, ret);
                }
            }
        }
        else
        {
            log_err("zone store: %{dnsname}: cannot be stored because its current instance in the database is marked as invalid", zone_origin(zone_desc));
        }
        
        if(zonelockowner != 0)
        {
            zdb_zone_release_unlock(zone, zonelockowner);
        }
        else
        {
            zdb_zone_release(zone);
        }
    }
    
    // zdb_unlock(db, ZDB_MUTEX_READER);
    
    zone_clear_status(zone_desc, ZONE_STATUS_SAVETO_ZONE_FILE|ZONE_STATUS_SAVING_ZONE_FILE|ZONE_STATUS_PROCESSING);
    
    if(desclockowner != 0)
    {
        zone_unlock(zone_desc, desclockowner);
    }

#if ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
    if(ISOK(ret))
    {
        if(zdb_zone_is_maintenance_paused(zone))
        {
            log_info("zone store: %{dnsname}: resuming zone maintenance", zone_origin(zone_desc));
            zdb_zone_set_maintenance_paused(zone, FALSE);
            ya_result internal_ret;
            if(FAIL(internal_ret = database_service_zone_dnssec_maintenance_lock_for(zone_desc, desclockowner)))
            {
                log_info("zone store: %{dnsname}: failed to resume zone maintenance: %r", zone_origin(zone_desc), internal_ret);
            }
        }
    }
#endif

    database_fire_zone_processed(zone_desc);
    zone_release(zone_desc);
    
    return ret;
}

static void*
database_service_zone_store_thread(void *params)
{
    zone_desc_s *zone_desc = (zone_desc_s*)params;
    database_service_zone_store_ex(zone_desc, ZONE_LOCK_SAVE, ZDB_ZONE_MUTEX_SIMPLEREADER, DATABASE_SERVICE_ZONE_SAVE_DEFAULTS);
    return NULL;
}

/**
 * 
 * Triggers the standard background save of a zone
 * 
 * @param zone_desc
 * @return 
 */

ya_result
database_service_zone_store(zone_desc_s *zone_desc)
{
    if(zone_desc == NULL)
    {
        log_err("database_service_zone_store(NULL)");
        return ERROR;
    }

    const u8 *origin = zone_origin(zone_desc);
    
    log_debug1("database_service_zone_store(%{dnsname}@%p=%i)", origin, zone_desc, zone_desc->rc);
    
    log_debug1("database_service_zone_store: locking zone '%{dnsname}' for saving", zone_origin(zone_desc));
    
    if(FAIL(zone_lock(zone_desc, ZONE_LOCK_SAVE)))
    {
        log_err("database_service_zone_store: failed to lock zone settings for '%{dnsname}'", origin);
        return ERROR;
    }

    log_debug("zone store: %{dnsname}", origin);
                    
    /*
     * Invalidate the zone
     * Empty the current zone if any
     */

    /*
     * If the zone descriptor (config) exists and it can be locked by the saveer ...
     */
    
    // locks the descriptor with the saveer identity
    
    if(zone_get_status(zone_desc) & (ZONE_STATUS_SAVETO_ZONE_FILE|ZONE_STATUS_SAVING_ZONE_FILE))
    {
        // already saving

#if DEBUG
        zone_desc_log(MODULE_MSG_HANDLE, MSG_DEBUG1, zone_desc, "database_service_zone_store");
#endif
        
        log_debug("database_service_zone_store: '%{dnsname}' already busy storing", origin);
        
        zone_unlock(zone_desc, ZONE_LOCK_SAVE);
                        
        return ERROR;
    }
    
    zone_set_status(zone_desc, ZONE_STATUS_SAVETO_ZONE_FILE);

    zone_acquire(zone_desc);
    database_service_zone_store_queue_thread(database_service_zone_store_thread, zone_desc, NULL,
                                             "database_zone_store_thread");
    
    log_debug1("database_service_zone_store: unlocking zone '%{dnsname}' for storage", origin);
    
    zone_unlock(zone_desc, ZONE_LOCK_SAVE);
    
    return SUCCESS;
}

/**
 * @}
 */

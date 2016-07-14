/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2016, EURid. All rights reserved.
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

#define DATABASE_SERVICE_C 1

#include "server-config.h"
#include "config.h"

#include <dnscore/format.h>
#include <dnscore/serial.h>
#include <dnscore/threaded_queue.h>
#include <dnscore/thread_pool.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/fdtools.h>
#include <dnscore/tcp_io_stream.h>

#include <dnscore/service.h>
#include <dnscore/async.h>
#include <dnscore/chroot.h>
#include <dnscore/ptr_set.h>

#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_record.h>
#include <dnsdb/zdb_zone_write.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/zdb_utils.h>
#include <dnsdb/zdb-zone-dnssec.h>

#include <dnsdb/zdb_zone_load.h>
#if ZDB_HAS_DNSSEC_SUPPORT
#include <dnsdb/dnssec_task.h>
#endif
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb-lock.h>
#include <dnsdb/zdb.h>
#include <dnsdb/zdb-zone-garbage.h>

#include <dnszone/zone_file_reader.h>
#include <dnszone/zone_axfr_reader.h>

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "database-service.h"
#include "database-service-zone-desc-load.h"
#include "database-service-zone-desc-unload.h"
#include "database-service-zone-load.h"
#include "database-service-zone-unload.h"
#include "database-service-zone-mount.h"
#include "database-service-zone-unmount.h"
#include "database-service-zone-download.h"
#if HAS_RRSIG_MANAGEMENT_SUPPORT &&  ZDB_HAS_DNSSEC_SUPPORT
#include "database-service-zone-resignature.h"
#include "zone-signature-policy.h"
#endif
#include "database-service-zone-freeze.h"
#include "database-service-zone-unfreeze.h"
#include "database-service-zone-save.h"

#include "server.h"
#include "notify.h"
#include "ixfr.h"

#if HAS_CTRL
#include "ctrl.h"
#endif

#include "server_error.h"
#include "zone_desc.h"
#include "config_error.h"

#define DBLOADQ_TAG 0x5144414f4c4244

//#define DATABASE_SERVICE_QUEUE_SIZE 0x4000
#define DATABASE_SERVICE_QUEUE_SIZE 0x1000000
#define DATABASE_SERVICE_DOWNLOAD_QUEUE_SIZE 0x10000
#define DATABASE_SERVICE_LOAD_QUEUE_SIZE 0x10000
#define DATABASE_SERVICE_UNLOAD_QUEUE_SIZE 0x10000
#define DATABASE_SERVICE_SAVE_QUEUE_SIZE 0x10000
#define DATABASE_SERVICE_RESIGN_QUEUE_SIZE 0x10000


#ifdef DEBUG
#define DATABASE_SERVICE_BENCH_MESSAGES_PER_SECOND 1
#else
#define DATABASE_SERVICE_BENCH_MESSAGES_PER_SECOND 0
#endif

static struct service_s database_handler = UNINITIALIZED_SERVICE;
static async_queue_s database_handler_queue;
static bool database_handler_initialised = FALSE;
static int database_service(struct service_worker_s *worker);

/* Zone file variables */
zone_data_set database_zone_desc = {PTR_SET_DNSNAME_EMPTY, GROUP_MUTEX_INITIALIZER, 0};
/* Zones meant to be merged with zones */


static struct thread_pool_s *database_zone_load_thread_pool = NULL;
static struct thread_pool_s *database_zone_save_thread_pool = NULL;
static struct thread_pool_s *database_zone_unload_thread_pool = NULL;
static struct thread_pool_s *database_zone_download_thread_pool = NULL;

#if ZDB_HAS_DNSSEC_SUPPORT
#if HAS_RRSIG_MANAGEMENT_SUPPORT
static struct thread_pool_s *database_zone_resignature_thread_pool = NULL;
static struct thread_pool_s *database_zone_rrsig_thread_pool = NULL;
#endif
#endif

static const u8 database_all_origins[] = "\003ALL\005ZONES";

static const char* database_service_operation[DATABASE_SERVICE_OPERATION_COUNT]=
{
    "NOTHING",
    
    // messages queue
    
    "ZONE-DESC-LOAD",
    "ZONE-DESC-UNLOAD",
    "ZONE-DESC-DESTROY",
    "ZONE-DESC-PROCESS",
    
    "ORIGIN-PROCESS", // not used
    
    // zone desc queue
    
    "ZONE-LOAD",
    "ZONE-MOUNT",
    "ZONE-UNMOUNT",
    "ZONE-UNLOAD",
    "ZONE-WRITE-TEXT",
    
    "ZONE-QUERY-AXFR",
    "ZONE-QUERY-IXFR",
    
    "SET-DROP-AFTER-RELOAD",
    "DO-DROP-AFTER-RELOAD",
    "ZONE-MOUNTED-EVENT",
    "ZONE-LOADED-EVENT",
    "ZONE-UNLOADED-EVENT",
    "ZONE-UNMOUNTED-EVENT",
    "ZONE-DOWNLOADED-EVENT",
    
    "ZONE-RECONFIGURE-BEGIN",
    "ZONE-RECONFIGURE-END",
    
    "ZONE-UPDATE-SIGNATURES"
};

static volatile bool database_reconfigure_enabled = FALSE;

const char*
database_service_operation_get_name(u32 id)
{
    if(id < DATABASE_SERVICE_OPERATION_COUNT)
    {
        return database_service_operation[id];
    }
    
    return "?";
}

static database_message *
database_load_message_alloc(const u8 *origin, u8 type)
{
    database_message *message;
    
    MALLOC_OR_DIE(database_message*, message, sizeof(database_message), DBLOADQ_TAG);
    ZEROMEMORY(message, sizeof(database_message));
    
    message->origin = dnsname_dup(origin);
    message->payload.type = type;
    
    return message;
}

static void
database_load_message_free(database_message *message)
{
    free(message->origin);    
    free(message);
}

static void
database_service_icmtl_listener_callback(u8 state, const zdb_icmtl* icmtl, void *args)
{
    (void)args;
    
    switch(state)
    {
        case ZDB_ICMTL_LISTENER_BEGIN:
#ifdef DEBUG
            log_debug("database: icmtl %{dnsname} begin", icmtl->zone->origin);
#endif
            break;
        case ZDB_ICMTL_LISTENER_CANCEL:
#ifdef DEBUG
            log_debug("database: icmtl %{dnsname} cancel", icmtl->zone->origin);
#endif
            break;
        case ZDB_ICMTL_LISTENER_END:
#ifdef DEBUG
            log_debug("database: icmtl %{dnsname} end", icmtl->zone->origin);
#endif
            // notify slaves
            if(icmtl->modified)
            {
                notify_slaves(icmtl->zone->origin);
            }
            break;
    }
}

/**********************************************************************************************************************/

ya_result
database_service_init()
{
    int err = SUCCESS;
    
    if(!database_handler_initialised)
    {
        if(database_zone_load_thread_pool == NULL)
        {
            database_zone_load_thread_pool = thread_pool_init_ex(g_config->zone_load_thread_count, DATABASE_SERVICE_LOAD_QUEUE_SIZE, "db-zone-load-tp"); /// @todo 20150415 edf -- configure parameters

            if(database_zone_load_thread_pool == NULL)
            {
                return ERROR;
            }
        }
        
        if(database_zone_save_thread_pool == NULL)
        {
            database_zone_save_thread_pool = thread_pool_init_ex(1, DATABASE_SERVICE_SAVE_QUEUE_SIZE, "db-zone-save-tp"); /// @todo 20150415 edf -- configure parameters

            if(database_zone_save_thread_pool == NULL)
            {
                return ERROR;
            }
        }
        
        if(database_zone_unload_thread_pool == NULL)
        {
            database_zone_unload_thread_pool = thread_pool_init_ex(1, DATABASE_SERVICE_UNLOAD_QUEUE_SIZE, "db-zone-unload-tp"); /// @todo 20150415 edf -- configure parameters

            if(database_zone_unload_thread_pool == NULL)
            {
                return ERROR;
            }
        }
        
        if(database_zone_download_thread_pool == NULL)
        {
            database_zone_download_thread_pool = thread_pool_init_ex(g_config->zone_download_thread_count, DATABASE_SERVICE_DOWNLOAD_QUEUE_SIZE, "db-download-tp"); /// @todo 20150415 edf -- configure parameters

            if(database_zone_download_thread_pool == NULL)
            {
                return ERROR;
            }
        }       
#if ZDB_HAS_DNSSEC_SUPPORT                
#if HAS_RRSIG_MANAGEMENT_SUPPORT
        if(database_zone_resignature_thread_pool == NULL)
        {
            database_zone_resignature_thread_pool = thread_pool_init_ex(1, DATABASE_SERVICE_RESIGN_QUEUE_SIZE, "db-resign-tp"); /// @todo 20150415 edf -- configure parameters

            if(database_zone_resignature_thread_pool == NULL)
            {
                return ERROR;
            }
        }
        
        if(database_zone_rrsig_thread_pool == NULL)
        {
            database_zone_rrsig_thread_pool = thread_pool_init_ex(/*g_config->dnssec_thread_count + 1*/2, 32, "db-rrsig-tp"); /// @todo 20140205 edf -- configure parameters

            if(database_zone_rrsig_thread_pool == NULL)
            {
                return ERROR;
            }
            
            dnssec_process_set_default_pool(database_zone_rrsig_thread_pool);
        }  
#endif
#endif
        
        async_message_pool_init();
        
        if(ISOK(err = service_init_ex(&database_handler, database_service, "database", 1)))
        {
            async_queue_init(&database_handler_queue, DATABASE_SERVICE_QUEUE_SIZE, 1, 100000, "database");
            database_handler_initialised = TRUE;
        }
        
        zdb_icmtl_listener_add(database_service_icmtl_listener_callback, NULL);
    }
    
    return err;
}

bool
database_service_started()
{
    return database_handler_initialised && !service_stopped(&database_handler);
}

ya_result
database_service_start()
{
    int err = ERROR;

    if(database_handler_initialised)
    {
        if(service_stopped(&database_handler))
        {
            err = service_start(&database_handler);
        }
    }

    return err;
}

ya_result
database_service_stop()
{
    int err = ERROR;
    
    if(database_handler_initialised)
    {
        if(!service_stopped(&database_handler))
        {
            err = service_stop(&database_handler);
            service_wait(&database_handler);
        }
    }
    
    return err;
}

ya_result
database_service_finalise()
{
    int err = SUCCESS;
    
    if(database_handler_initialised)
    {
        zdb_icmtl_listener_remove(database_service_icmtl_listener_callback);
        
        zone_set_lock(&database_zone_desc);

        ptr_set_avl_iterator iter;
        ptr_set_avl_iterator_init(&database_zone_desc.set, &iter);

        while(ptr_set_avl_iterator_hasnext(&iter))
        {
            ptr_node *zone_node = ptr_set_avl_iterator_next_node(&iter);
            zone_desc_s *zone_desc = (zone_desc_s *)zone_node->value;

            zone_lock(zone_desc, ZONE_LOCK_UNLOAD);
            zdb_zone *zone = zone_get_loaded_zone(zone_desc);
            if(zone != NULL)
            {
                alarm_close(zone->alarm_handle);
                zone->alarm_handle = ALARM_HANDLE_INVALID;
                zdb_zone_release(zone);
            }
            zone_unlock(zone_desc, ZONE_LOCK_UNLOAD);
        }

        zone_set_unlock(&database_zone_desc);
        
        err = database_service_stop();
        
        if(database_zone_load_thread_pool != NULL)
        {
            thread_pool_destroy(database_zone_load_thread_pool);
            database_zone_load_thread_pool = NULL;
        }
        
        if(database_zone_save_thread_pool != NULL)
        {
            thread_pool_destroy(database_zone_save_thread_pool);
            database_zone_save_thread_pool = NULL;
        }
        
        if(database_zone_unload_thread_pool != NULL)
        {
            thread_pool_destroy(database_zone_unload_thread_pool);
            database_zone_unload_thread_pool = NULL;
        }
        
        if(database_zone_download_thread_pool != NULL)
        {
            thread_pool_destroy(database_zone_download_thread_pool);
            database_zone_download_thread_pool = NULL;
        }
   

#if ZDB_HAS_DNSSEC_SUPPORT
#if HAS_RRSIG_MANAGEMENT_SUPPORT
                
        if(database_zone_resignature_thread_pool != NULL)
        {
            thread_pool_destroy(database_zone_resignature_thread_pool);
            database_zone_resignature_thread_pool = NULL;
        }
        
        if(database_zone_rrsig_thread_pool != NULL)
        {
            dnssec_process_set_default_pool(NULL);
            thread_pool_destroy(database_zone_rrsig_thread_pool);
            database_zone_rrsig_thread_pool = NULL;
        }
        
#endif
#endif
        service_finalize(&database_handler);

        async_queue_finalize(&database_handler_queue);
        
        /// destroy all the descs
        
        log_debug("dropping zone settings");
        
        zone_free_all(&database_zone_desc);
        

        
        database_handler_initialised = FALSE;
    }

    return err;
}

/**********************************************************************************************************************/


bool
database_origin_is_mounted(const u8 *origin)
{
    // get the zone
    // look if it is valid or not
    
    zdb *db = g_config->database;
    bool mounted = FALSE;
    
    zdb_lock(db, ZDB_MUTEX_READER);
    
    zdb_zone_label *zone_label = zdb_zone_label_find_from_dnsname_nolock(db, origin);
    if(zone_label != NULL)
    {
        zdb_zone *zone = zone_label->zone; // OK (ARC)
        mounted = zdb_zone_isvalid(zone);
    }
    
    zdb_unlock(db, ZDB_MUTEX_READER);
    
    return mounted;
}

bool
database_zone_desc_is_mounted(const u8 *origin)
{
    // get the origin
    // get the zone
    // look if it is valid or not
    
    bool mounted = database_origin_is_mounted(origin);
    
    return mounted;
}



static void
database_service_set_drop_after_reload()
{
    zone_set_lock(&database_zone_desc);

    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_avl_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->value;

        zone_desc->status_flags |= ZONE_STATUS_DROP_AFTER_RELOAD;
    }

    zone_set_unlock(&database_zone_desc);
}

static void
database_service_do_drop_after_reload()
{
    log_debug1("database_service_do_drop_after_reload()");
    
    zone_set_lock(&database_zone_desc);

    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_avl_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->value;

        if((zone_desc->status_flags & ZONE_STATUS_DROP_AFTER_RELOAD) != 0)
        {
            // drop the zone & zone desc
            
            log_debug2("database_service_do_drop_after_reload: queuing %{dnsname} for unload", zone_desc->origin);

            database_zone_desc_unload(zone_desc->origin);
        }
    }

    zone_set_unlock(&database_zone_desc);
    
    log_debug1("database_service_do_drop_after_reload() done");
}

static void
database_service_process_command(zone_desc_s *zone_desc, zone_command_s* command)
{
    switch(command->id)
    {
        case DATABASE_SERVICE_ZONE_DESC_UNLOAD:
        {
            database_service_zone_desc_unload(zone_desc);
            break;
        }

        case DATABASE_SERVICE_ZONE_LOAD:
        {
            database_service_zone_load(zone_desc);
            break;
        }
        case DATABASE_SERVICE_ZONE_MOUNT:
        {
            database_service_zone_mount(zone_desc);
            break;
        }
        case DATABASE_SERVICE_ZONE_UNMOUNT:
        {
            database_service_zone_unmount(zone_desc);
            break;
        }
        case DATABASE_SERVICE_ZONE_UNLOAD:
        {
            database_service_zone_unload(zone_desc, command->parm.zone);
            break;
        }
#if ZDB_HAS_DNSSEC_SUPPORT
#if HAS_RRSIG_MANAGEMENT_SUPPORT
        case DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES:
        {
            database_service_zone_resignature(zone_desc);
            break;
        }
#endif
#endif
        case DATABASE_SERVICE_ZONE_FREEZE:
        {
            database_service_zone_freeze(zone_desc);
            break;
        }
        case DATABASE_SERVICE_ZONE_UNFREEZE:
        {
            database_service_zone_unfreeze(zone_desc);
            break;
        }
        case DATABASE_SERVICE_ZONE_SAVE_TEXT:
        {
            if(ISOK(zone_lock(zone_desc, ZONE_LOCK_SAVE)))
            {
                if(command->parm.ptr != NULL)
                {
                    zone_desc->status_flags |= ZONE_STATUS_MUST_CLEAR_JOURNAL;
                }
                
                zone_unlock(zone_desc, ZONE_LOCK_SAVE);
                
                database_service_zone_save(zone_desc); // text
            }
            else
            {
                log_err("database_service_zone_save: failed to lock zone settings for '%{dnsname}'", zone_desc->origin);
            }
            break;
        }
        default:
        {
            log_err("unexpected command %d", command->id);
        }
    }
}

static int
database_service(struct service_worker_s *worker)
{
    zone_desc_s *zone_desc = NULL;
    
#if DATABASE_SERVICE_BENCH_MESSAGES_PER_SECOND
    u64 sbmps_epoch_us = timeus();
    u32 sbmps_count = 0;
#endif
    /*
     * while the program is running
     */
    
    log_info("database: service starting");
    
    zdb_zone_dnssec_keys_refresh();
    
    log_info("database: service started");
    
    while(service_shouldrun(worker) || !async_queue_emtpy(&database_handler_queue))
    {
        if(!zdb_zone_garbage_empty())
        {
            // do a zdb_zone_garbage_run in the background
            if(thread_pool_queue_size(database_zone_unload_thread_pool) == 0)
            {
                database_service_run_garbage_collector();
            }
        }
        
        /*
         * dequeue command
         */
        
        zone_desc = NULL;
        
        async_message_s *async = async_message_next(&database_handler_queue);

        if(async == NULL)
        {
            continue;
        }
        
        database_message *message = (database_message*)async->args;

        if(message == NULL)
        {
            log_err("database: NULL message");
            continue;
        }
        
#if DATABASE_SERVICE_BENCH_MESSAGES_PER_SECOND
        {
            u64 now = timeus();
            if(now - sbmps_epoch_us >= 1000000)
            {
                double mps = sbmps_count;
                mps *= 1000000.0;
                mps /= (now - sbmps_epoch_us);
                log_info("database: %12.3fmsg/s", mps);
                sbmps_epoch_us = now;
                sbmps_count = 0;
            }
            sbmps_count++;
        }
#endif
        
#ifdef DEBUG
        if(message->payload.type < DATABASE_SERVICE_OPERATION_COUNT)
        {
            log_debug("database: %{dnsname}: dequeued operation %s", message->origin, database_service_operation[message->payload.type]);
        }
        else
        {       
            log_debug("database: %{dnsname}: dequeued operation #%d", message->origin, message->payload.type);
        }
#endif
        /*
         * NULL => shutdown the thread
         */
        
        /*
         * load command ?
         */
        
        switch(message->payload.type)
        {
            case DATABASE_SERVICE_ZONE_DESC_LOAD:
            {
                // desc
                database_load_zone_desc(message->payload.zone_desc_load.zone_desc);
                zone_release(message->payload.zone_desc_load.zone_desc);
                break;
            }
            
            // DISPATCH TO THE ZONE DESCRIPTOR
            
            case DATABASE_SERVICE_ZONE_DESC_UNLOAD:
            {
                // no desc
                zone_desc = zone_acquirebydnsname(message->origin);
                if(zone_desc != NULL)
                {
                    if((zone_desc->status_flags & ZONE_STATUS_UNREGISTERING) == 0)
                    {
                        zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_DESC_UNLOAD, NULL, FALSE);
                        zone_desc->status_flags |= ZONE_STATUS_UNREGISTERING;
                    }
                    else
                    {
                        log_debug("database: %{dnsname}: cannot unload configuration: zone already unregistering", message->origin);
                    }
                }
                else
                {
                    log_debug("database: %{dnsname}: cannot unload configuration: zone is not registered", message->origin);
                }
                break;
            }



            case DATABASE_SERVICE_ZONE_LOAD:
            {
                // no desc
                zone_desc = zone_acquirebydnsname(message->origin);
                
                if(zone_desc != NULL)
                {
                    log_debug("database: %{dnsname}: load, @%p", message->origin, zone_desc);
                    
                    if((zone_desc->status_flags & (ZONE_STATUS_LOAD|ZONE_STATUS_LOADING)) == 0)
                    {                    
                        zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_LOAD, NULL, FALSE);
                    }
                    else
                    {
                        log_warn("database: %{dnsname}: ignoring load command for: already loading", message->origin);
                    }
                }
                else
                {
                    log_debug("database: %{dnsname}: cannot load: zone is not configured", message->origin);
                }

                break;
            }

            case DATABASE_SERVICE_ZONE_UNLOAD:
            {
                // no desc
                zone_desc = zone_acquirebydnsname(message->origin);
                if(zone_desc != NULL)
                {
                    // zone has been acquired for this call
                    // references are passed to the command
                    zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_UNLOAD, message->payload.zone_unload.zone, TRUE);
                    message->payload.zone_unload.zone = NULL;
                }
                else
                {
                    if(message->payload.zone_unload.zone != NULL)
                    {
                        zdb_zone_release(message->payload.zone_unload.zone);
                        message->payload.zone_unload.zone = NULL;
                    }
                    
                    log_debug("database: %{dnsname}: cannot unload: zone is not configured", message->origin);
                }
                break;
            }
            case DATABASE_SERVICE_ZONE_FREEZE:
            {
                // no desc
                zone_desc = zone_acquirebydnsname(message->origin);
                if(zone_desc != NULL)
                {
                    zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_FREEZE, NULL, FALSE);
                }
                else
                {
                    log_err("database: %{dnsname}: cannot freeze: zone is not configured", message->origin);
                }

                break;
            }
            case DATABASE_SERVICE_ZONE_UNFREEZE:
            {
                // no desc
                zone_desc = zone_acquirebydnsname(message->origin);
                if(zone_desc != NULL)
                {
                    zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_UNFREEZE, NULL, FALSE);
                }
                else
                {
                    log_err("database: %{dnsname}: cannot unfreeze: zone is not configured", message->origin);
                }
                break;
            }
            case DATABASE_SERVICE_ZONE_SAVE_TEXT:
            {
                // no desc
                zone_desc = zone_acquirebydnsname(message->origin);
                if(zone_desc != NULL)
                {
                    zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_SAVE_TEXT, (message->payload.zone_save.clear)?(void*)1:(void*)0, FALSE);
                }
                else
                {
                    log_err("database: %{dnsname}: cannot save to disk as text: zone is not configured", message->origin);
                }
                break;
            }
            case DATABASE_SERVICE_QUERY_AXFR:
            {
                database_service_zone_axfr_query(message->origin);
                
                break;
            }
            
            case DATABASE_SERVICE_QUERY_IXFR:
            {
                database_service_zone_ixfr_query(message->origin);
                
                break;
            }
            
            case DATABASE_SERVICE_SET_DROP_AFTER_RELOAD:
            {
                // ZONE_STATUS_DROP_AFTER_RELOAD
                
                database_service_set_drop_after_reload();
                                
                break;
            }
            
            case DATABASE_SERVICE_DO_DROP_AFTER_RELOAD:
            {
                database_service_do_drop_after_reload();
                
                break;
            }
            
            //
            
            case DATABASE_SERVICE_RECONFIGURE_BEGIN:
            {
                if(!database_reconfigure_enabled)
                {
                    log_debug("database: re-configuration enabled");
                    
                    database_reconfigure_enabled = TRUE;
                }
                else
                {
                    log_debug("database: re-configuration already enabled");
                }
                
                break;
            }
            
            case DATABASE_SERVICE_RECONFIGURE_END:
            {
                if(database_reconfigure_enabled)
                {
#ifdef DEBUG
                    zone_dump_allocated();
#endif        
                    log_debug("database: re-configuration disabled");
                    
                    database_reconfigure_enabled = FALSE;
                }
                else
                {
                    log_debug("database: re-configuration already disabled");
                }
                
                break;
            }
            
#if ZDB_HAS_DNSSEC_SUPPORT
#if HAS_RRSIG_MANAGEMENT_SUPPORT
            
            case DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES:
            {
                // desc
                zone_desc = zone_acquirebydnsname(message->origin);
                
                // current zone desc is the one we wanted to update the signatures on ?
                
                yassert(zone_desc != NULL);
                
                if(zone_desc == message->payload.zone_update_signatures.expected_zone_desc)
                {
                    zone_lock(zone_desc, ZONE_LOCK_SERVICE);
                    zdb_zone *zone = zone_get_loaded_zone(zone_desc); // RC++
                    zone_unlock(zone_desc, ZONE_LOCK_SERVICE);
                    
                    if(zone != NULL)
                    {
                        // zone is the one we wanted to update the signatures on ?
                        
                        if(zone == message->payload.zone_update_signatures.expected_zone)
                        {
                            log_info("database: %{dnsname}: zone signature triggered", zone_desc->origin);
                            zone_enqueue_command(zone_desc, DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES, NULL, FALSE);
                        }
                        else
                        {
                            log_warn("database: %{dnsname}: zone signature triggered for another instance of the zone, ignoring", zone_desc->origin);

                            zone_release(zone_desc);
                            zone_desc = NULL;
                        }
                        
                        zdb_zone_release(zone);
#ifdef DEBUG
                        zone = NULL;
#endif
                    }
                }
                else
                {
                    log_warn("database: %{dnsname}: zone signature triggered for another instance of the zone settings, ignoring", message->payload.zone_update_signatures.expected_zone_desc->origin);
                    zone_release(zone_desc);
#ifdef DEBUG
                    zone_desc = NULL;
#endif
                }
                
                zdb_zone_release(message->payload.zone_update_signatures.expected_zone);
#ifdef DEBUG
                message->payload.zone_update_signatures.expected_zone = NULL;
#endif
                zone_release(message->payload.zone_update_signatures.expected_zone_desc);
#ifdef DEBUG
                message->payload.zone_update_signatures.expected_zone_desc = NULL;
#endif

                break;
            }
            
#endif
#endif // ZDB_HAS_DNSSEC_SUPPORT
            // EVENTS
            
            case DATABASE_SERVICE_ZONE_LOADED_EVENT:
            {
                // desc
                zone_desc = message->payload.zone_loaded_event.zone_desc;
                
                if(ISOK(message->payload.zone_loaded_event.result_code))
                {
                    if(message->payload.zone_loaded_event.result_code == 1)
                    {
                        log_info("database: %{dnsname}: zone successfully loaded", message->origin);

                        zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_MOUNT, NULL, FALSE);
                    }
                    else
                    {
                        log_info("database: %{dnsname}: there was no need to load the zone", message->origin);
                    }
                }
                else if((message->payload.zone_loaded_event.result_code == ZRE_NO_VALID_FILE_FOUND) && (zone_desc->type == ZT_SLAVE))
                {
                    log_debug("database: %{dnsname}: no local copy of the zone is available: download required", message->origin);
                }
                else
                {
                    log_err("database: %{dnsname}: failed to load the zone: %r", message->origin, message->payload.zone_loaded_event.result_code);
                }
                
                if(message->payload.zone_loaded_event.zone != NULL)
                {
                    zdb_zone_release(message->payload.zone_loaded_event.zone);
                    message->payload.zone_loaded_event.zone = NULL;
                }

                break;
            }
                
            case DATABASE_SERVICE_ZONE_MOUNTED_EVENT:
            {
                // desc
                zone_desc = message->payload.zone_mounted_event.zone_desc;
                
                if(ISOK(message->payload.zone_mounted_event.result_code))
                {
                    log_info("database: %{dnsname}: zone successfully mounted", message->origin);
                    
#if HAS_MASTER_SUPPORT && ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT
                    if(zone_desc->type == ZT_MASTER)
                    {
                        // verify policies
                        
                        zone_policy_process(zone_desc);
                        
                        //
                        
                        if(zdb_zone_is_dnssec(message->payload.zone_mounted_event.zone))
                        {
                            if(zone_maintains_dnssec(zone_desc))
                            {
                                if(message->payload.zone_mounted_event.zone != NULL)
                                {
                                    zdb_zone_lock(message->payload.zone_mounted_event.zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                                    const zdb_packed_ttlrdata *dnskey_rrset = zdb_record_find(&message->payload.zone_mounted_event.zone->apex->resource_record_set, TYPE_DNSKEY);
                                    zdb_zone_unlock(message->payload.zone_mounted_event.zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                                    
                                    if(dnskey_rrset != NULL)
                                    {
                                        log_info("database: %{dnsname}: signature maintenance initialisation", message->origin);

                                        database_service_zone_resignature_init(
                                                message->payload.zone_mounted_event.zone_desc,
                                                message->payload.zone_mounted_event.zone);
                                    }
                                    else
                                    {
                                        log_info("database: %{dnsname}: signature maintenance postponed until keys are activated", message->origin);
                                    }
                                }
                                else
                                {
                                    log_debug("database: %{dnsname}: no zone passed with mount event", message->origin);
                                }
                            }
                            else
                            {
                                log_info("database: %{dnsname}: signature maintenance disabled", message->origin);
                            }
                        }
                    }
                    else // ... else slave ?
#endif
                    if(zone_desc->type == ZT_SLAVE)
                    {
                        database_zone_refresh_maintenance(g_config->database, message->origin, 0); // means next refresh from now // database_zone_refresh_maintenance_wih_zone(zone_desc->loaded_zone, 0);
                    }
                }
                else
                {
                    log_err("database: %{dnsname}: failed to mount the zone: %r", message->origin, message->payload.zone_mounted_event.result_code);
                }
                
                if(message->payload.zone_mounted_event.zone != NULL)
                {
                    zdb_zone_release(message->payload.zone_mounted_event.zone);
                    message->payload.zone_mounted_event.zone = NULL;
                }
#ifdef DEBUG
                //zone_release(message->payload.zone_mounted_event.zone_desc);
                message->payload.zone_mounted_event.zone_desc = NULL;
#endif
                // do not release zone_desc because we will try to push the event
                break;
            }
            
            case DATABASE_SERVICE_ZONE_UNMOUNTED_EVENT:
            {
                // desc (both)
                zone_desc = zone_acquirebydnsname(message->origin);
                
                if(ISOK(message->payload.zone_unmounted_event.result_code))
                {
                    log_info("database: %{dnsname}: zone successfully unmounted", message->origin);
                }
                else
                {
                    log_err("database: %{dnsname}: failed to unmount the zone: %r", message->origin, message->payload.zone_unmounted_event.result_code);
                }
                
                zone_release(message->payload.zone_unmounted_event.zone_desc);
                message->payload.zone_unmounted_event.zone_desc = NULL;
                break;
            }
            case DATABASE_SERVICE_ZONE_UNLOADED_EVENT:
            {
                /// @todo 20140425 edf -- WHAT IF THE EVENT FAILED ? WHAT ABOUT THE REMAINING OF THE QUEUE ???
                ///       WE FORGOT TO TAKE THIS INTO ACCOUNT : THERE IS SOME SORT OF RETRY OR
                ///       CANCEL ALL MECHANISM NEEDED ...
                
                // desc (both)
                zone_desc = zone_acquirebydnsname(message->origin);
                
                if(ISOK(message->payload.zone_unmounted_event.result_code))
                {
                    log_info("database: %{dnsname}: zone successfully unloaded", message->origin);
                }
                else
                {
                    log_err("database: %{dnsname}: failed to unload the zone: %r", message->origin, message->payload.zone_unmounted_event.result_code);
                }
                
                zone_release(message->payload.zone_unloaded_event.zone_desc);
                message->payload.zone_unloaded_event.zone_desc = NULL;
                break;
            }
            
            case DATABASE_SERVICE_ZONE_DOWNLOADED_EVENT:
            {
                // no desc
                zone_desc = zone_acquirebydnsname(message->origin);
                
                if(ISOK(message->payload.zone_downloaded_event.result_code))
                {
                    log_info("database: %{dnsname}: zone successfully downloaded (%{dnstype})", message->origin, &message->payload.zone_downloaded_event.download_type);
                    
                    if(message->payload.zone_downloaded_event.download_type == TYPE_AXFR)
                    {
                        database_zone_load(message->origin); // the downloaded file can now be loaded
                    }
                }
                else
                {
                    log_err("database: %{dnsname}: failed to download the zone: %r", message->origin, message->payload.zone_downloaded_event.result_code);
                }
                break;
            }
            
            default:
            {
                break;
            }
        }
        
        if(zone_desc != NULL)
        {
            if(FAIL(zone_lock(zone_desc, ZONE_LOCK_SERVICE)))
            {
                log_err("database: %{dnsname}: unable to lock zone", message->origin);
            }
            
            while((zone_desc->status_flags & ZONE_STATUS_PROCESSING) == 0)
            {
                zone_desc_log(g_server_logger, LOG_DEBUG, zone_desc, "database-service");
                        
                zone_command_s* command = zone_dequeue_command(zone_desc);
                
                if(command != NULL)
                {
                    zone_desc->status_flags |= ZONE_STATUS_PROCESSING;
                    zone_desc->last_processor = command->id;
                    
                    log_debug("database: %{dnsname}: processing zone @%p (%s)", message->origin, zone_desc, database_service_operation_get_name(zone_desc->last_processor));
                       
                    zone_unlock(zone_desc, ZONE_LOCK_SERVICE);
                    
                    database_service_process_command(zone_desc, command);
                    
                    if(FAIL(zone_lock(zone_desc, ZONE_LOCK_SERVICE)))
                    {
                        log_err("database: %{dnsname}: zone cannot be locked", message->origin);
                    }

                    zone_command_free(command);
                }
                else
                {
                    if(zone_desc->status_flags & ZONE_STATUS_MARKED_FOR_DESTRUCTION)
                    {
                        log_debug("database: %{dnsname}: zone @%p is marked for destruction", zone_desc->origin, zone_desc);
                    }
                    if(!(zone_desc->status_flags & ZONE_STATUS_PROCESSING))
                    {
                        zone_desc->last_processor = 0;
                    }
                    break;
                }
            }

            log_debug7("database: %{dnsname}: zone @%p is processed by %s", message->origin, zone_desc, database_service_operation_get_name(zone_desc->last_processor));
            
            zone_unlock(zone_desc, ZONE_LOCK_SERVICE);
            zone_release(zone_desc);
#ifdef DEBUG
            zone_desc = NULL;
#endif
        }
        
        database_load_message_free(message);
        
        async_message_release(async);
    }
    
    service_set_stopping(worker);
    
    log_info("database: service stopped");
        
    return 0;
}

void
database_load_all_zones()
{
    u8 buffer[4096];
    
    // builds a set of names to load, batch loads the names
    // iterates the above process until there are no names left to load
    
    zone_set_lock(&database_zone_desc);
    ptr_node *node = ptr_set_avl_get_first(&database_zone_desc.set);
    
    for(;;)
    {
        u8 *name = buffer;
        const u8 *last = NULL;
        
        for(; node != NULL; node = ptr_set_avl_node_next(node))
        {
            zone_desc_s *zone_desc = (zone_desc_s *)node->value;
            int name_len = dnsname_len(zone_desc->origin);
            if(name_len > (&buffer[sizeof(buffer)] - name))
            {
                break;
            }
            memcpy(name, zone_desc->origin, name_len);
            last = name;
            name += name_len;
        }
        
        zone_set_unlock(&database_zone_desc);

        if(last == NULL)
        {
            // no name has been inserted : nothing more to do
            
            break;
        }

        name = buffer;

        for(;;)
        {
            database_zone_load(name);
            
            if(name == last)
            {
                break;
            }
            
            name += dnsname_len(name);
        }
        
        zone_set_lock(&database_zone_desc);
        
        // get back the last name
        
        node = ptr_set_avl_find(&database_zone_desc.set, last);
        
        if(node != NULL)
        {
            // and get the one that follows
            
            node = ptr_set_avl_node_next(node);
        }
    }
}

void
database_zone_load(const u8 *origin)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_LOAD", origin);
    
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_ZONE_LOAD);
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT

void
database_zone_update_signatures(const u8 *origin, zone_desc_s *expected_zone_desc, zdb_zone *expected_zone)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES", origin);
    
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES);
    
    zone_acquire(expected_zone_desc);
    zdb_zone_acquire(expected_zone);
    
    message->payload.zone_update_signatures.expected_zone_desc = expected_zone_desc;
    message->payload.zone_update_signatures.expected_zone = expected_zone;
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

#endif

void
database_zone_unload(zdb_zone *zone)
{ 
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_UNLOAD", zone->origin, zone);
    
    zdb_zone_acquire(zone);
    
    database_message *message = database_load_message_alloc(zone->origin, DATABASE_SERVICE_ZONE_UNLOAD);
    message->payload.zone_unload.zone = zone;
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void database_zone_freeze(const u8 *origin)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_FREEZE", origin);
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_ZONE_FREEZE);
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void database_zone_unfreeze(const u8 *origin)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_UNFREEZE", origin);
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_ZONE_UNFREEZE);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void database_zone_save_ex(const u8 *origin, bool clear)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_SAVE_TEXT (clear=%i)", origin, clear);
    
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_ZONE_SAVE_TEXT);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    message->payload.zone_save.clear = clear;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void database_zone_save(const u8 *origin)
{
    database_zone_save_ex(origin, FALSE);
}

void
database_zone_desc_load(zone_desc_s *zone_desc)
{
    if(zone_desc != NULL)
    {
        log_debug("database: %{dnsname}: loading settings", zone_desc->origin);
        
        zone_desc_log(MODULE_MSG_HANDLE, LOG_DEBUG, zone_desc, "database_zone_desc_load");
 
        if(service_started(&database_handler))
        {
            log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_DESC_LOAD", zone_desc->origin);
            
            database_message *message = database_load_message_alloc(zone_desc->origin, DATABASE_SERVICE_ZONE_DESC_LOAD);
            zone_acquire(zone_desc);
            message->payload.zone_desc_load.zone_desc = zone_desc;

            async_message_s *async = async_message_alloc();
            async->id = message->payload.type;
            async->args = message;
            async->handler = NULL;
            async->handler_args = NULL;
            async_message_call(&database_handler_queue, async);
        }
        else
        {
            log_debug("database: %{dnsname}: loading setting with offline database", zone_desc->origin);
            
            database_load_zone_desc(zone_desc);
        }
    }
    else
    {
        log_err("database: loading settings asked for NULL settings");
    }
}

void
database_zone_desc_unload(const u8 *origin)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_DESC_UNLOAD", origin);
    
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_ZONE_DESC_UNLOAD);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_zone_axfr_query(const u8 *origin)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_QUERY_AXFR", origin);
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_QUERY_AXFR);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

static ya_result
database_zone_axfr_query_alarm(void *args, bool cancel)
{
    async_message_s* async = (async_message_s*)args;
    database_message* message = (database_message*)async->args;
    if(!cancel)
    {
        log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_QUERY_AXFR (alarm)", message->origin);
        async_message_call(&database_handler_queue, async);
    }
    else
    {
        log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_QUERY_AXFR cancelled (alarm)", message->origin);
        async_message_release(async);
        database_load_message_free((database_message*)async->args);
    }
    
    return SUCCESS;
}

void
database_zone_axfr_query_at(const u8 *origin, time_t at)
{    
    log_debug("database: %{dnsname}: will enqueue operation DATABASE_SERVICE_QUERY_AXFR at %T", origin, at);
    
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_QUERY_AXFR);
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    
    alarm_event_node *event = alarm_event_new(
            at,
            ALARM_KEY_ZONE_AXFR_QUERY,
            database_zone_axfr_query_alarm,
            async,
            ALARM_DUP_REMOVE_LATEST,
            "database-zone-axfr-query-alarm");
    
    alarm_set(event->handle, event);
}


void
database_zone_ixfr_query(const u8 *origin)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_QUERY_IXFR", origin);
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_QUERY_IXFR);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

static ya_result
database_zone_ixfr_query_alarm(void *args, bool cancel)
{
    async_message_s* async = (async_message_s*)args;
    database_message* message = (database_message*)async->args;
    if(!cancel)
    {
        log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_QUERY_IXFR (alarm)", message->origin);
        async_message_call(&database_handler_queue, async);
    }
    else
    {
        log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_QUERY_IXFR cancelled (alarm)", message->origin);
        async_message_release(async);
        database_load_message_free((database_message*)async->args);
    }
    
    return SUCCESS;
}


void
database_zone_ixfr_query_at(const u8 *origin, time_t at)
{    
    log_debug("database: %{dnsname}: will enqueue operation DATABASE_SERVICE_QUERY_IXFR at %T", origin, at);
    
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_QUERY_IXFR);
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    
    alarm_event_node *event = alarm_event_new(
            at,
            ALARM_KEY_ZONE_AXFR_QUERY,
            database_zone_ixfr_query_alarm,
            async,
            ALARM_DUP_REMOVE_LATEST,
            "database-zone-ixfr-query-alarm");
    
    alarm_set(event->handle, event);
}

void
database_zone_reconfigure_begin()
{
    if(database_service_is_running())
    {
        log_debug("database: enqueue operation DATABASE_SERVICE_RECONFIGURE_BEGIN");
        database_message *message = database_load_message_alloc(database_all_origins, DATABASE_SERVICE_RECONFIGURE_BEGIN);

        async_message_s *async = async_message_alloc();
        async->id = message->payload.type;
        async->args = message;
        async->handler = NULL;
        async->handler_args = NULL;
        async_message_call(&database_handler_queue, async);
    }
    else
    {
        database_reconfigure_enabled = TRUE;
    }
}

void
database_zone_reconfigure_end()
{
    if(database_service_is_running())
    {
        log_debug("database: enqueue operation DATABASE_SERVICE_RECONFIGURE_END");
        database_message *message = database_load_message_alloc(database_all_origins, DATABASE_SERVICE_RECONFIGURE_END);

        async_message_s *async = async_message_alloc();
        async->id = message->payload.type;
        async->args = message;
        async->handler = NULL;
        async->handler_args = NULL;
        async_message_call(&database_handler_queue, async);
    }
    else
    {
        database_reconfigure_enabled = FALSE;
    }
}

bool
database_zone_is_reconfigure_enabled()
{
    return database_reconfigure_enabled;
}

void
database_set_drop_after_reload()
{
    log_debug("database: enqueue operation DATABASE_SERVICE_SET_DROP_AFTER_RELOAD");
    database_message *message = database_load_message_alloc(database_all_origins, DATABASE_SERVICE_SET_DROP_AFTER_RELOAD);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_do_drop_after_reload()
{
    log_debug("database: enqueue operation DATABASE_SERVICE_DO_DROP_AFTER_RELOAD");
    database_message *message = database_load_message_alloc(database_all_origins, DATABASE_SERVICE_DO_DROP_AFTER_RELOAD);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_fire_zone_loaded(zone_desc_s *zone_desc, zdb_zone *zone, ya_result result_code)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_LOADED_EVENT (%r)", zone_desc->origin, result_code);
    database_message *message = database_load_message_alloc(zone_desc->origin, DATABASE_SERVICE_ZONE_LOADED_EVENT);
    
    zone_acquire(zone_desc);
    if(zone != NULL)
    {
        zdb_zone_acquire(zone);
    }
    
    message->payload.zone_loaded_event.zone_desc = zone_desc;
    message->payload.zone_loaded_event.zone = zone;
    message->payload.zone_loaded_event.result_code = result_code;
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_fire_zone_mounted(zone_desc_s *zone_desc, zdb_zone *zone, ya_result result_code)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_MOUNTED_EVENT (%r)", zone_desc->origin, result_code);
    database_message *message = database_load_message_alloc(zone_desc->origin, DATABASE_SERVICE_ZONE_MOUNTED_EVENT);
    
    zone_acquire(zone_desc);
    if(zone != NULL)
    {
        zdb_zone_acquire(zone);
    }
    
    message->payload.zone_mounted_event.zone_desc = zone_desc;
    message->payload.zone_mounted_event.zone = zone;
    message->payload.zone_mounted_event.result_code = result_code;
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_fire_zone_unloaded(zdb_zone *zone, ya_result result_code)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_UNLOADED_EVENT (%r)", zone->origin, zone, result_code);
    database_message *message = database_load_message_alloc(zone->origin, DATABASE_SERVICE_ZONE_UNLOADED_EVENT);
    
    zdb_zone_acquire(zone);
    
    message->payload.zone_unloaded_event.zone = zone;
    message->payload.zone_unloaded_event.result_code = result_code;
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_fire_zone_unmounted(zone_desc_s *zone_desc, ya_result result_code)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_UNMOUNTED_EVENT (%r)", zone_desc->origin, result_code);
    database_message *message = database_load_message_alloc(zone_desc->origin, DATABASE_SERVICE_ZONE_UNMOUNTED_EVENT);
    
    zone_acquire(zone_desc);
    
    message->payload.zone_unmounted_event.zone_desc = zone_desc;
    message->payload.zone_unmounted_event.result_code = result_code;
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_fire_zone_downloaded(const u8 *origin, u16 qtype, u32 serial, ya_result result_code)
{
    if(ISOK(result_code))
    {
        log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_DOWNLOADED_EVENT type=%{dnstype} serial=%u (%r)", origin, &qtype, serial, result_code);
    }
    else
    {
        log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_DOWNLOADED_EVENT (%r)", origin, result_code);
    }
    
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_ZONE_DOWNLOADED_EVENT);
    message->payload.zone_downloaded_event.download_type = qtype;
    message->payload.zone_downloaded_event.serial = serial;
    message->payload.zone_downloaded_event.result_code = result_code;
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_service_zone_load_queue_thread(thread_pool_function func, void *parm, thread_pool_task_counter *counter, const char* categoryname)
{
    thread_pool_enqueue_call(database_zone_load_thread_pool, func, parm, counter, categoryname);
}

void
database_service_zone_save_queue_thread(thread_pool_function func, void *parm, thread_pool_task_counter *counter, const char* categoryname)
{
    thread_pool_enqueue_call(database_zone_save_thread_pool, func, parm, counter, categoryname);
}

void
database_service_zone_unload_queue_thread(thread_pool_function func, void *parm, thread_pool_task_counter *counter, const char* categoryname)
{
    thread_pool_enqueue_call(database_zone_unload_thread_pool, func, parm, counter, categoryname);
}

static void*
database_service_run_garbage_collector_thread(void *parms_)
{
    (void)parms_;
    zdb_zone_garbage_run();
    return NULL;
}

void
database_service_run_garbage_collector()
{
    thread_pool_enqueue_call(database_zone_unload_thread_pool, database_service_run_garbage_collector_thread, NULL, NULL, "garbage");
}

void
database_service_zone_download_queue_thread(thread_pool_function func, void *parm, thread_pool_task_counter *counter, const char* categoryname)
{
    thread_pool_enqueue_call(database_zone_download_thread_pool, func, parm, counter, categoryname);
}

#if ZDB_HAS_DNSSEC_SUPPORT
#if HAS_RRSIG_MANAGEMENT_SUPPORT
void
database_service_zone_resignature_queue_thread(thread_pool_function func, void *parm, thread_pool_task_counter *counter, const char* categoryname)
{
    thread_pool_enqueue_call(database_zone_resignature_thread_pool, func, parm, counter, categoryname);
}
#endif
#endif

void
database_service_create_invalid_zones()
{
    zone_set_lock(&database_zone_desc);
    
    if(!ptr_set_avl_isempty(&database_zone_desc.set))
    {
        ptr_set_avl_iterator iter;
        ptr_set_avl_iterator_init(&database_zone_desc.set, &iter);

        while(ptr_set_avl_iterator_hasnext(&iter))
        {
            ptr_node *zone_node = ptr_set_avl_iterator_next_node(&iter);
            zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;

            zdb_zone *invalid_zone = zdb_zone_create(zone_desc->origin); // RC = 1
            zdb_zone_invalidate(invalid_zone);
            
            zdb_zone *old_zone = zdb_set_zone(g_config->database, invalid_zone); // RC ++
            yassert(old_zone == NULL);
            (void)old_zone;
            
            zdb_zone_release(invalid_zone);
        }
    }
    
    zone_set_unlock(&database_zone_desc);
}

bool
database_service_is_running()
{
    return service_started(&database_handler);
}

/**
 * @}
 */

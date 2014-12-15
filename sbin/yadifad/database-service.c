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

#define DATABASE_SERVICE_C 1

#include "config.h"

#include <dnscore/format.h>
#include <dnscore/serial.h>
#include <dnscore/threaded_queue.h>
#include <dnscore/thread_pool.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/fdtools.h>
#include <dnscore/xfr_copy.h>
#include <dnscore/tcp_io_stream.h>

#include <dnscore/service.h>
#include <dnscore/async.h>
#include <dnscore/chroot.h>
#include <dnscore/treeset.h>

#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_record.h>
#include <dnsdb/zdb_zone_write.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/zdb_utils.h>
#include <dnsdb/journal.h>
#include <dnsdb/zdb_zone_load.h>
#include <dnsdb/dnssec_task.h>
#include <dnsdb/zdb_zone_label.h>

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
#if HAS_RRSIG_MANAGEMENT_SUPPORT
#include "database-service-zone-resignature.h"
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
#define DATABASE_SERVICE_QUEUE_SIZE 0x100000

static struct service_s database_handler = UNINITIALIZED_SERVICE;
static async_queue_s database_handler_queue;
static bool database_handler_initialised = FALSE;
static int database_service(struct service_worker_s *worker);

/* Zone file variables */
zone_data_set database_zone_desc = {TREESET_DNSNAME_EMPTY, MUTEX_INITIALIZER};
/* Zones meant to be merged with zones */
zone_data_set database_dynamic_zone_desc = {TREESET_DNSNAME_EMPTY, MUTEX_INITIALIZER};

static struct thread_pool_s *database_zone_load_thread_pool = NULL;
static struct thread_pool_s *database_zone_save_thread_pool = NULL;
static struct thread_pool_s *database_zone_unload_thread_pool = NULL;
static struct thread_pool_s *database_zone_download_thread_pool = NULL;

#if HAS_RRSIG_MANAGEMENT_SUPPORT
static struct thread_pool_s *database_zone_resignature_thread_pool = NULL;
static struct thread_pool_s *database_zone_rrsig_thread_pool = NULL;
#endif

static const u8 database_all_origins[] = "\003ALL\005ZONES";

static const char* database_service_operation[DATABASE_SERVICE_OPERATION_COUNT]=
{
    "STOP",
    
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

/**********************************************************************************************************************/

ya_result
database_service_init()
{
    int err = SUCCESS;
    
    if(!database_handler_initialised)
    {
        if(database_zone_load_thread_pool == NULL)
        {
            database_zone_load_thread_pool = thread_pool_init_ex(1, 4096, "db-zone-load-tp"); /// @todo configure parameters

            if(database_zone_load_thread_pool == NULL)
            {
                return ERROR;
            }
        }
        
        if(database_zone_save_thread_pool == NULL)
        {
            database_zone_save_thread_pool = thread_pool_init_ex(1, 4096, "db-zone-save-tp"); /// @todo configure parameters

            if(database_zone_save_thread_pool == NULL)
            {
                return ERROR;
            }
        }
        
        if(database_zone_unload_thread_pool == NULL)
        {
            database_zone_unload_thread_pool = thread_pool_init_ex(1, 4096, "db-zone-unload-tp"); /// @todo configure parameters

            if(database_zone_unload_thread_pool == NULL)
            {
                return ERROR;
            }
        }
        
        if(database_zone_download_thread_pool == NULL)
        {
            database_zone_download_thread_pool = thread_pool_init_ex(4, 4096, "db-download-tp"); /// @todo configure parameters

            if(database_zone_download_thread_pool == NULL)
            {
                return ERROR;
            }
        }       
                
#if HAS_RRSIG_MANAGEMENT_SUPPORT
        if(database_zone_resignature_thread_pool == NULL)
        {
            database_zone_resignature_thread_pool = thread_pool_init_ex(1, 4096, "db-resign-tp"); /// @todo configure parameters

            if(database_zone_resignature_thread_pool == NULL)
            {
                return ERROR;
            }
        }
        
        if(database_zone_rrsig_thread_pool == NULL)
        {
            database_zone_rrsig_thread_pool = thread_pool_init_ex(/*g_config->dnssec_thread_count + 1*/2, 32, "db-rrsig-tp"); /// @todo configure parameters

            if(database_zone_rrsig_thread_pool == NULL)
            {
                return ERROR;
            }
            
            dnssec_process_set_default_pool(database_zone_rrsig_thread_pool);
        }
        
#endif
        
        async_message_pool_init();
        
        if(ISOK(err = service_init_ex(&database_handler, database_service, "database", 1)))
        {
            async_queue_init(&database_handler_queue, DATABASE_SERVICE_QUEUE_SIZE, 1, 100000, "database");
            database_handler_initialised = TRUE;
        }
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
        err = database_service_stop();
        
        service_finalize(&database_handler);

        async_queue_finalize(&database_handler_queue);
        
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
        
        /// destroy all the descs
        
        log_debug("dropping zone settings");
        
        zone_free_all(&database_zone_desc);
        
        log_debug("dropping dynamic zone settings");
        
        zone_free_all(&database_dynamic_zone_desc);
        
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
    
    group_mutex_lock(&db->mutex, ZDB_MUTEX_READER);
    
    zdb_zone_label *zone_label = zdb_zone_label_find_from_dnsname_nolock(db, origin);
    if(zone_label != NULL)
    {
        zdb_zone *zone = zone_label->zone;
        mounted = zdb_zone_isvalid(zone);
    }
    
    group_mutex_unlock(&db->mutex, ZDB_MUTEX_READER);
    
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

    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&database_zone_desc.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->data;

        zone_desc->status_flags |= ZONE_STATUS_DROP_AFTER_RELOAD;
    }

    zone_set_unlock(&database_zone_desc);
}

static void
database_service_do_drop_after_reload()
{
    log_debug1("database_service_do_drop_after_reload()");
    
    zone_set_lock(&database_zone_desc);

    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&database_zone_desc.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->data;

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
            database_service_zone_unload(zone_desc, command->parm.zone, NULL);
            break;
        }
#if HAS_RRSIG_MANAGEMENT_SUPPORT
        case DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES:
        {
            database_service_zone_resignature(zone_desc);
            break;
        }
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
            database_service_zone_save(zone_desc); // text
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
    /*
     * while the program is running
     */
    
    log_debug("database service started");
    
    while(service_shouldrun(worker) || !async_queue_emtpy(&database_handler_queue))
    {
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
            log_err("database_service: NULL message");
            continue;
        }
        
#ifdef DEBUG
        if(message->payload.type < DATABASE_SERVICE_OPERATION_COUNT)
        {
            log_debug("database-service: dequeued operation %s on %{dnsname}", database_service_operation[message->payload.type], message->origin);
        }
        else
        {       
            log_debug("database-service: dequeued operation %d on %{dnsname}", message->payload.type, message->origin);
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
                        log_debug("cannot unload configuration for '%{dnsname}': zone already unregistering", message->origin);
                    }
                }
                else
                {
                    log_debug("cannot unload configuration for '%{dnsname}': zone is not registered", message->origin);
                }
                break;
            }



            case DATABASE_SERVICE_ZONE_LOAD:
            {
                // no desc
                zone_desc = zone_acquirebydnsname(message->origin);
                
                if(zone_desc != NULL)
                {
                    log_debug("load of '%{dnsname}'@%p", message->origin, zone_desc);
                    
                    zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_LOAD, NULL, FALSE);
                }
                else
                {
                    log_debug("cannot load '%{dnsname}' (not configured)", message->origin);
                }

                break;
            }
            /*
            case DATABASE_SERVICE_ZONE_MOUNT:
            {
                zone_desc = zone_acquirebydnsname(message->origin);
                if(zone_desc != NULL)
                {
                    zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_MOUNT, NULL, FALSE);
                }
                else
                {
                    log_err("error mounting '%{dnsname}': zone is not configured", message->origin);
                }

                break;
            }
            
            case DATABASE_SERVICE_ZONE_UNMOUNT:
            {
                zone_desc = zone_acquirebydnsname(message->origin);
                if(zone_desc != NULL)
                {
                    zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_UNMOUNT, NULL, FALSE);
                }
                else
                {
                    log_err("error unmounting '%{dnsname}': zone is not configured", message->origin);
                }
                break;
            }
            */
            case DATABASE_SERVICE_ZONE_UNLOAD:
            {
                // no desc
                zone_desc = zone_acquirebydnsname(message->origin);
                if(zone_desc != NULL)
                {
                    zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_UNLOAD, message->payload.zone_unload.zone, FALSE);
                }
                else
                {
                    log_debug("cannot load '%{dnsname}' (not configured)", message->origin);
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
                    log_err("error freezing '%{dnsname}': zone is not configured", message->origin);
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
                    log_err("error unfreezing '%{dnsname}': zone is not configured", message->origin);
                }
                break;
            }
            case DATABASE_SERVICE_ZONE_SAVE_TEXT:
            {
                // no desc
                zone_desc = zone_acquirebydnsname(message->origin);
                if(zone_desc != NULL)
                {
                    zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_SAVE_TEXT, NULL, FALSE);
                }
                else
                {
                    log_err("error saving '%{dnsname}': zone is not configured", message->origin);
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
                    log_debug("re-configuration enabled");
                    
                    database_reconfigure_enabled = TRUE;
                }
                else
                {
                    log_debug("re-configuration already enabled");
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
                    log_debug("re-configuration disabled");
                    
                    database_reconfigure_enabled = FALSE;
                }
                else
                {
                    log_debug("re-configuration already disabled");
                }
                
                break;
            }
            
#if HAS_RRSIG_MANAGEMENT_SUPPORT
            
            case DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES:
            {
                // desc
                zone_desc = zone_acquirebydnsname(message->origin);
                
                if(zone_desc == message->payload.zone_update_signatures.expected_zone_desc)
                {
                    if(zone_desc->loaded_zone == message->payload.zone_update_signatures.expected_zone)
                    {
                        log_info("zone signature of '%{dnsname}' triggered",
                                zone_desc->origin);
                        zone_enqueue_command(zone_desc, DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES, zone_desc->loaded_zone, FALSE);
                    }
                    else
                    {
                        log_warn("zone signature of '%{dnsname}' triggered for another instance of the zone, ignoring",
                                zone_desc->origin);
                                            
                        zone_release(zone_desc);
                        zone_desc = NULL;
                    }
                }
                else
                {
                    log_warn("zone signature of '%{dnsname}' triggered for another instance of the zone settings, ignoring",
                            zone_desc->origin);
                    zone_release(zone_desc);
                    zone_desc = NULL;
                }
                
                zone_release(message->payload.zone_update_signatures.expected_zone_desc);

                break;
            }
            
#endif
            
            // EVENTS
            
            case DATABASE_SERVICE_ZONE_LOADED_EVENT:
            {
                // desc
                zone_desc = message->payload.zone_loaded_event.zone_desc;
                
                if(ISOK(message->payload.zone_loaded_event.result_code))
                {
                    log_info("successfully loaded the zone for %{dnsname}", message->origin);
                    
                    zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_MOUNT, NULL, FALSE);
                }
                else if((message->payload.zone_loaded_event.result_code == ZRE_NO_VALID_FILE_FOUND) && (zone_desc->type == ZT_SLAVE))
                {
                    log_debug("no local copy of the zone for %{dnsname} is available, download required", message->origin);
                }
                else
                {
                    log_err("failed to load the zone for %{dnsname}: %r", message->origin, message->payload.zone_loaded_event.result_code);
                }
                
                /// @todo why ? zone_desc = zone_acquirebydnsname(message->origin);
                
                break;
            }
                
            case DATABASE_SERVICE_ZONE_MOUNTED_EVENT:
            {
                // desc
                zone_desc = message->payload.zone_mounted_event.zone_desc;
                
                if(ISOK(message->payload.zone_mounted_event.result_code))
                {
                    log_info("successfully mounted the zone for %{dnsname}", message->origin);
                    
#if HAS_RRSIG_MANAGEMENT_SUPPORT
#if HAS_MASTER_SUPPORT
                    if(zone_desc->type == ZT_MASTER)
                    {
                        if(zdb_zone_is_dnssec(message->payload.zone_mounted_event.zone))
                        {
                            log_info("signature maintenance initialisation for %{dnsname}", message->origin);

                            database_service_zone_resignature_init(
                                    message->payload.zone_mounted_event.zone_desc,
                                    message->payload.zone_mounted_event.zone);
                        }
                    }
                    else
#endif
#endif
                    if(zone_desc->type == ZT_SLAVE)
                    {
                        database_zone_refresh_maintenance(g_config->database, message->origin, 0); // means next refresh from now
                    }
                }
                else
                {
                    log_err("failed to mount the zone for %{dnsname}: %r", message->origin, message->payload.zone_mounted_event.result_code);
                }
                break;
            }
            
            case DATABASE_SERVICE_ZONE_UNMOUNTED_EVENT:
            {
                /// @todo WHAT IF THE EVENT FAILED ? WHAT ABOUT THE REMAINING OF THE QUEUE ???
                ///       WE FORGOT TO TAKE THIS INTO ACCOUNT : THERE IS SOME SORT OF RETRY OR
                ///       CANCEL ALL MECHANISM NEEDED ...
                
                // desc (both)
                zone_desc = zone_acquirebydnsname(message->origin);
                
                if(ISOK(message->payload.zone_unmounted_event.result_code))
                {
                    log_info("successfully unmounted zone for %{dnsname}", message->origin);
                }
                else
                {
                    log_err("failed to unmount the zone for %{dnsname}: %r", message->origin, message->payload.zone_unmounted_event.result_code);
                }
                
                zone_release(message->payload.zone_unmounted_event.zone_desc);
                break;
            }
            case DATABASE_SERVICE_ZONE_UNLOADED_EVENT:
            {
                /// @todo WHAT IF THE EVENT FAILED ? WHAT ABOUT THE REMAINING OF THE QUEUE ???
                ///       WE FORGOT TO TAKE THIS INTO ACCOUNT : THERE IS SOME SORT OF RETRY OR
                ///       CANCEL ALL MECHANISM NEEDED ...
                
                // desc (both)
                zone_desc = zone_acquirebydnsname(message->origin);
                
                if(ISOK(message->payload.zone_unmounted_event.result_code))
                {
                    log_info("successfully unloaded zone for %{dnsname}", message->origin);
                }
                else
                {
                    log_err("failed to unload the zone for %{dnsname}: %r", message->origin, message->payload.zone_unmounted_event.result_code);
                }
                
                zone_release(message->payload.zone_unloaded_event.zone_desc);
                break;
            }
            
            case DATABASE_SERVICE_ZONE_DOWNLOADED_EVENT:
            {
                // no desc
                zone_desc = zone_acquirebydnsname(message->origin);
                
                if(ISOK(message->payload.zone_downloaded_event.result_code))
                {
                    log_info("database: successfully downloaded the zone for %{dnsname} (%{dnstype})", message->origin, &message->payload.zone_downloaded_event.download_type);
                    
                    if(message->payload.zone_downloaded_event.download_type == TYPE_AXFR)
                    {
                        database_zone_load(message->origin); // the downloaded file can now be loaded
                    }
                }
                else
                {
                    log_err("database: failed to download the zone for %{dnsname}: %r", message->origin, message->payload.zone_downloaded_event.result_code);
                    
                    /// @todo retry ?
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
                log_err("unable to lock zone '%{dnsname}'", message->origin);
            }
            
            while((zone_desc->status_flags & ZONE_STATUS_PROCESSING) == 0)
            {
                zone_desc_log(g_server_logger, LOG_DEBUG, zone_desc, "database-service");
                        
                zone_command_s* command = zone_dequeue_command(zone_desc);
                
                if(command != NULL)
                {
                    zone_desc->status_flags |= ZONE_STATUS_PROCESSING;
                    zone_desc->last_processor = command->id;
                    
                    log_debug("zone '%{dnsname}'@%p processing (%s)", message->origin, zone_desc, database_service_operation_get_name(zone_desc->last_processor));
                       
                    zone_unlock(zone_desc, ZONE_LOCK_SERVICE);
                    
                    database_service_process_command(zone_desc, command);
                    
                    if(FAIL(zone_lock(zone_desc, ZONE_LOCK_SERVICE)))
                    {
                        log_err("unable to re-lock zone '%{dnsname}'", message->origin);
                    }

                    zone_command_free(command);
                }
                else
                {
                    if(zone_desc->status_flags & ZONE_STATUS_MARKED_FOR_DESTRUCTION)
                    {
                        log_debug("zone desc '%{dnsname}'@%p is marked for destruction", zone_desc->origin, zone_desc);
                    }
                    break;
                }
            }

            log_debug7("zone '%{dnsname}' is processed by %s", message->origin, database_service_operation_get_name(zone_desc->last_processor));
            
            zone_unlock(zone_desc, ZONE_LOCK_SERVICE);
            
            zone_release(zone_desc);
            
            zone_desc = NULL;
        }
        
        database_load_message_free(message);
        
        async_message_release(async);
    }
    
    service_set_stopping(worker);
    
    log_debug("database service stopped");
        
    return 0;
}

void
database_load_all_zones()
{
    u8 buffer[4096];
    
    // builds a set of names to load, batch loads the names
    // iterates the above process until there are no names left to load
    
    zone_set_lock(&database_zone_desc);
    treeset_node *node = treeset_avl_get_first(&database_zone_desc.set);
    
    for(;;)
    {
        u8 *name = buffer;
        const u8 *last = NULL;
        
        for(; node != NULL; node = treeset_avl_node_next(node))
        {
            zone_desc_s *zone_desc = (zone_desc_s *)node->data;
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
        
        node = treeset_avl_find(&database_zone_desc.set, last);
        
        if(node != NULL)
        {
            // and get the one that follows
            
            node = treeset_avl_node_next(node);
        }
    }
}

void
database_zone_load(const u8 *origin)
{
    log_debug("database_load_zone_file: %{dnsname}", origin);
    
    log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_LOAD on %{dnsname}", origin);
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_ZONE_LOAD);
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

#if HAS_RRSIG_MANAGEMENT_SUPPORT

void
database_zone_update_signatures(const u8 *origin, zone_desc_s *expected_zone_desc, const zdb_zone *expected_zone)
{
    log_debug("database_zone_update_signatures: %{dnsname}, %p, %p", origin, expected_zone_desc, expected_zone);
    
    log_debug("database_service: enqueue operation DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES on %{dnsname}", origin);
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES);
    zone_acquire(expected_zone_desc);
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
    log_debug("database_load_zone_unload: %{dnsname}", zone->origin);
    
    log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_UNLOAD on %{dnsname}@%p", zone->origin, zone);
    database_message *message = database_load_message_alloc(zone->origin, DATABASE_SERVICE_ZONE_UNLOAD);
    message->payload.zone_unload.zone = zone;
    //message->payload.zone_unload.replacement_zone = replacement_zone;
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void database_zone_freeze(const u8 *origin)
{
    log_debug("database_zone_freeze: %{dnsname}", origin);
    
    log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_FREEZE on %{dnsname}", origin);
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
    log_debug("database_zone_unfreeze: %{dnsname}", origin);
    
    log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_UNFREEZE on %{dnsname}", origin);
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_ZONE_UNFREEZE);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void database_zone_save(const u8 *origin)
{
    log_debug("database_zone_save: %{dnsname}", origin);
    
    log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_SAVE_TEXT on %{dnsname}", origin);
    
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_ZONE_SAVE_TEXT);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_zone_desc_load(zone_desc_s *zone_desc)
{
    if(zone_desc != NULL)
    {
        log_debug("database_zone_desc_load: %{dnsname}", zone_desc->origin);
        
        zone_desc_log(MODULE_MSG_HANDLE, LOG_DEBUG, zone_desc, "database_zone_desc_load");
 
        if(service_started(&database_handler))
        {
            log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_DESC_LOAD on %{dnsname}", zone_desc->origin);
            
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
            log_debug("database_zone_desc_load: %{dnsname} (offline)", zone_desc->origin);
            
            database_load_zone_desc(zone_desc);
        }
    }
    else
    {
        log_err("database_load_zone_desc_load: NULL");
    }
}

void
database_zone_desc_unload(const u8 *origin)
{
    log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_DESC_UNLOAD on %{dnsname}", origin);
    
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
    log_debug("database_service: enqueue operation DATABASE_SERVICE_QUERY_AXFR on %{dnsname}", origin);
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_QUERY_AXFR);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_zone_ixfr_query(const u8 *origin)
{
    log_debug("database_service: enqueue operation DATABASE_SERVICE_QUERY_IXFR on %{dnsname}", origin);
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_QUERY_IXFR);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_zone_reconfigure_begin()
{
    if(database_service_is_running())
    {
        log_debug("database_service: enqueue operation DATABASE_SERVICE_RECONFIGURE_BEGIN");
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
        log_debug("database_service: enqueue operation DATABASE_SERVICE_RECONFIGURE_END");
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
    log_debug("database_service: enqueue operation DATABASE_SERVICE_SET_DROP_AFTER_RELOAD");
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
    log_debug("database_service: enqueue operation DATABASE_SERVICE_DO_DROP_AFTER_RELOAD");
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
    log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_LOADED_EVENT on %{dnsname} %p %r", zone_desc->origin, zone, result_code);
    database_message *message = database_load_message_alloc(zone_desc->origin, DATABASE_SERVICE_ZONE_LOADED_EVENT);
    zone_acquire(zone_desc);
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
    log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_MOUNTED_EVENT on %{dnsname} %p %r", zone_desc->origin, zone, result_code);
    database_message *message = database_load_message_alloc(zone_desc->origin, DATABASE_SERVICE_ZONE_MOUNTED_EVENT);
    zone_acquire(zone_desc);
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
    log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_UNLOADED_EVENT on %{dnsname} %p %r", zone->origin, zone, result_code);
    database_message *message = database_load_message_alloc(zone->origin, DATABASE_SERVICE_ZONE_UNLOADED_EVENT);
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
    log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_UNMOUNTED_EVENT on %{dnsname} %r", zone_desc->origin, result_code);
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
        log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_DOWNLOADED_EVENT on %{dnsname} %{dnstype} serial=%u: %r", origin, &qtype, serial, result_code);
    }
    else
    {
        log_debug("database_service: enqueue operation DATABASE_SERVICE_ZONE_DOWNLOADED_EVENT on %{dnsname}: %r", origin, result_code);
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

void
database_service_zone_download_queue_thread(thread_pool_function func, void *parm, thread_pool_task_counter *counter, const char* categoryname)
{
    thread_pool_enqueue_call(database_zone_download_thread_pool, func, parm, counter, categoryname);
}

#if HAS_RRSIG_MANAGEMENT_SUPPORT

void
database_service_zone_resignature_queue_thread(thread_pool_function func, void *parm, thread_pool_task_counter *counter, const char* categoryname)
{
    thread_pool_enqueue_call(database_zone_resignature_thread_pool, func, parm, counter, categoryname);
}

#endif

void
database_service_create_invalid_zones()
{
    zone_set_lock(&database_zone_desc);
    
    if(!treeset_avl_isempty(&database_zone_desc.set))
    {
        dnsname_vector name;
        treeset_avl_iterator iter;
        treeset_avl_iterator_init(&database_zone_desc.set, &iter);

        while(treeset_avl_iterator_hasnext(&iter))
        {
            treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
            zone_desc_s *zone_desc = (zone_desc_s*)zone_node->data;

            
            dnsname_to_dnsname_vector(zone_desc->origin, &name);
            
            group_mutex_lock(&g_config->database->mutex, ZDB_MUTEX_WRITER);
            
            zdb_zone_label *zone_label = zdb_zone_label_add_nolock(g_config->database, &name);

            yassert(zone_label->zone == NULL);

            zdb_zone *invalid_zone = zdb_zone_create(zone_desc->origin, CLASS_IN);
            invalid_zone->apex->flags |= ZDB_RR_LABEL_INVALID_ZONE;
            zone_label->zone = invalid_zone;
            
            group_mutex_unlock(&g_config->database->mutex, ZDB_MUTEX_WRITER);
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

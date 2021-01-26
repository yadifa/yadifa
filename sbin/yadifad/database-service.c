/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
 * The YADIFA TM software product is provided undecannr the BSD 3-clause license:
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

#define DATABASE_ZONE_RRSIG_THREAD_POOL 0 // now obsolete

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
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb-lock.h>
#include <dnsdb/zdb.h>
#include <dnsdb/zdb-zone-garbage.h>

#define ZDB_JOURNAL_CODE 1
#include <dnsdb/journal.h>

#include <dnscore/zone_reader_text.h>
#include <dnscore/zone_reader_axfr.h>

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
#include "database-service-zone-store.h"

#include "server.h"
#include "notify.h"
#include "ixfr.h"

#if HAS_CTRL
#include "ctrl.h"
#endif

#include "zone-signature-policy.h"

#include "server_error.h"
#include "zone_desc.h"
#include "config_error.h"

#ifndef HAS_DYNUPDATE_DIFF_ENABLED
#error "HAS_DYNUPDATE_DIFF_ENABLED not defined"
#endif

#define DBLOADQ_TAG 0x5144414f4c4244

//#define DATABASE_SERVICE_QUEUE_SIZE 0x4000
#define DATABASE_SERVICE_QUEUE_SIZE 0x1000000
#define DATABASE_SERVICE_DOWNLOAD_QUEUE_SIZE 0x10000
#define DATABASE_SERVICE_LOAD_QUEUE_SIZE 0x10000
#define DATABASE_SERVICE_UNLOAD_QUEUE_SIZE 0x10000
#define DATABASE_SERVICE_STORE_QUEUE_SIZE 0x10000
#define DATABASE_SERVICE_RESIGN_QUEUE_SIZE 0x10000
#define DATABASE_SERVICE_CALLBACK_QUEUE_SIZE 0x1000

#if DEBUG
#define DATABASE_SERVICE_BENCH_MESSAGES_PER_SECOND 1
#else
#define DATABASE_SERVICE_BENCH_MESSAGES_PER_SECOND 0
#endif

static void database_callback_run(database_message *message);
static void database_clear_drop_after_reload();
static void database_do_drop_after_reload();


static struct service_s database_handler = UNINITIALIZED_SERVICE;
static async_queue_s database_handler_queue;
static bool database_handler_initialised = FALSE;
static int database_service(struct service_worker_s *worker);

/* Zone file variables */
zone_data_set database_zone_desc = {PTR_SET_DNSNAME_EMPTY, GROUP_MUTEX_INITIALIZER, 0};
/* Zones meant to be merged with zones */


static struct thread_pool_s *database_zone_load_thread_pool = NULL;
static struct thread_pool_s *database_zone_store_thread_pool = NULL;
static struct thread_pool_s *database_zone_unload_thread_pool = NULL;
static struct thread_pool_s *database_zone_download_thread_pool = NULL;
static struct thread_pool_s *database_callback_thread_pool = NULL;

#if ZDB_HAS_DNSSEC_SUPPORT
#if HAS_RRSIG_MANAGEMENT_SUPPORT
static struct thread_pool_s *database_zone_resignature_thread_pool = NULL;
#if DATABASE_ZONE_RRSIG_THREAD_POOL
static struct thread_pool_s *database_zone_rrsig_thread_pool = NULL;
#endif
#endif
#endif

static const u8 database_all_origins[] = "\003ALL\005ZONES";

static const char* database_service_operation[DATABASE_SERVICE_OPERATION_COUNT]=
{
    "NOTHING",

    "ZONE-DESC-LOAD",
    "ZONE-DESC-UNLOAD",
    
    "ZONE-LOAD",
    "ZONE-LOADED-EVENT",
    
    "ZONE-MOUNT",
    "ZONE-MOUNTED-EVENT",
    
    "ZONE-UNMOUNT",
    "ZONE-UNMOUNTED-EVENT",
    
    "ZONE-UNLOAD",
    "ZONE-UNLOADED-EVENT",
    
    "ZONE-SAVE-TEXT",
    
    "ZONE-QUERY-AXFR",
    "ZONE-QUERY-IXFR",
    
    "ZONE-DOWNLOADED-EVENT",
    
    "SET-DROP-AFTER-RELOAD",
    "CLEAR-DROP-AFTER-RELOAD",
    "DO-DROP-AFTER-RELOAD",
    
    "ZONE-RECONFIGURE-BEGIN",
    "ZONE-RECONFIGURE-END",
    
    "ZONE-UPDATE-SIGNATURES",
    
    "ZONE-FREEZE",
    "ZONE-UNFREEZE",
    
    "ZONE-PROCESS",
    
    "CALLBACK"
};

static smp_int database_reconfigure_enable_count = SMP_INT_INITIALIZER;

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
    ZALLOC_OBJECT_OR_DIE(message, database_message, DBLOADQ_TAG);
    ZEROMEMORY(message, sizeof(database_message));
    
    message->origin = dnsname_dup(origin);
    message->payload.type = type;
    
    return message;
}

static void
database_load_message_free(database_message *message)
{
    if(message != NULL)
    {
        dnsname_free(message->origin);
        ZFREE_OBJECT(message);
    }
}

/**********************************************************************************************************************/

static void database_service_finalize_destroy_threadpools();

ya_result
database_service_init()
{
    int err = SERVICE_ALREADY_INITIALISED;
    
    if(!database_handler_initialised)
    {
#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
        if(FAIL(err = database_service_zone_resignature_init()))
        {
            return err;
        }
#endif
        if(database_zone_load_thread_pool == NULL)
        {
            database_zone_load_thread_pool = thread_pool_init_ex(g_config->zone_load_thread_count, DATABASE_SERVICE_LOAD_QUEUE_SIZE, "dbload");

            if(database_zone_load_thread_pool == NULL)
            {
                return SERVICE_INITIALISATION_ERROR;
            }
        }
        
        if(database_zone_store_thread_pool == NULL)
        {
            database_zone_store_thread_pool = thread_pool_init_ex(g_config->zone_store_thread_count, DATABASE_SERVICE_STORE_QUEUE_SIZE, "dbstore");

            if(database_zone_store_thread_pool == NULL)
            {
                database_service_finalize_destroy_threadpools();
                return SERVICE_INITIALISATION_ERROR;
            }
        }
        
        if(database_zone_unload_thread_pool == NULL)
        {
            database_zone_unload_thread_pool = thread_pool_init_ex(1, DATABASE_SERVICE_UNLOAD_QUEUE_SIZE, "dbunload");

            if(database_zone_unload_thread_pool == NULL)
            {
                database_service_finalize_destroy_threadpools();
                return SERVICE_INITIALISATION_ERROR;
            }
        }
        
        if(database_zone_download_thread_pool == NULL)
        {
            database_zone_download_thread_pool = thread_pool_init_ex(g_config->zone_download_thread_count, DATABASE_SERVICE_DOWNLOAD_QUEUE_SIZE, "dbdownld");

            if(database_zone_download_thread_pool == NULL)
            {
                database_service_finalize_destroy_threadpools();
                return SERVICE_INITIALISATION_ERROR;
            }
        }
        
        if(database_callback_thread_pool == NULL)
        {
            database_callback_thread_pool = thread_pool_init_ex(1, DATABASE_SERVICE_CALLBACK_QUEUE_SIZE, "callback"); /// @note thread count MUST be set to 1

            if(database_callback_thread_pool == NULL)
            {
                database_service_finalize_destroy_threadpools();
                return SERVICE_INITIALISATION_ERROR;
            }
        }
        
#if ZDB_HAS_DNSSEC_SUPPORT                
#if HAS_RRSIG_MANAGEMENT_SUPPORT
        if(database_zone_resignature_thread_pool == NULL)
        {
            database_zone_resignature_thread_pool = thread_pool_init_ex((!g_config->hidden_master)?1:8, DATABASE_SERVICE_RESIGN_QUEUE_SIZE, "dbresign"); /// @note thread count MUST be set to 1

            if(database_zone_resignature_thread_pool == NULL)
            {
                database_service_finalize_destroy_threadpools();
                return SERVICE_INITIALISATION_ERROR;
            }
        }

#if DATABASE_ZONE_RRSIG_THREAD_POOL
        if(database_zone_rrsig_thread_pool == NULL)
        {
            database_zone_rrsig_thread_pool = thread_pool_init_ex(/*g_config->dnssec_thread_count + 1*/2, 32, "dbrrsig");

            if(database_zone_rrsig_thread_pool == NULL)
            {
                database_service_finalize_destroy_threadpools();
                return SERVICE_INITIALISATION_ERROR;
            }
        }
#endif

#endif
#endif
        
        async_message_pool_init();
        
        if(ISOK(err = service_init_ex(&database_handler, database_service, "DBsrvice", 1)))
        {
            async_queue_init(&database_handler_queue, DATABASE_SERVICE_QUEUE_SIZE, 1, /*100000*/1, "dbsrvice");
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
    int err = SERVICE_ALREADY_INITIALISED;

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
    int err = SERVICE_NOT_INITIALISED;
    
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

static void database_service_message_clear(database_message *message);

static void
database_service_finalize_destroy_threadpools()
{
    if(database_zone_load_thread_pool != NULL)
    {
        thread_pool_destroy(database_zone_load_thread_pool);
        database_zone_load_thread_pool = NULL;
    }

    if(database_zone_store_thread_pool != NULL)
    {
        thread_pool_destroy(database_zone_store_thread_pool);
        database_zone_store_thread_pool = NULL;
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

    if(database_callback_thread_pool != NULL)
    {
        thread_pool_destroy(database_callback_thread_pool);
        database_callback_thread_pool = NULL;
    }

#if ZDB_HAS_DNSSEC_SUPPORT
#if HAS_RRSIG_MANAGEMENT_SUPPORT

    if(database_zone_resignature_thread_pool != NULL)
    {
        thread_pool_destroy(database_zone_resignature_thread_pool);
        database_zone_resignature_thread_pool = NULL;
    }

#if DATABASE_ZONE_RRSIG_THREAD_POOL
    if(database_zone_rrsig_thread_pool != NULL)
    {
        thread_pool_destroy(database_zone_rrsig_thread_pool);
        database_zone_rrsig_thread_pool = NULL;
    }
#endif

#endif
#endif
}

ya_result
database_service_finalize()
{
    int err = SUCCESS;
    
    if(database_handler_initialised)
    {
#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
        database_service_zone_resignature_finalize();
#endif
        zone_set_lock(&database_zone_desc); // unlock checked

        ptr_set_iterator iter;
        ptr_set_iterator_init(&database_zone_desc.set, &iter);

        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
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

        database_service_finalize_destroy_threadpools();

        service_finalize(&database_handler);

        while(!async_queue_empty(&database_handler_queue))
        {
            async_message_s *async = async_message_next(&database_handler_queue);
            database_message *message = (database_message*)async->args;
            if(message != NULL)
            {
                log_debug("clearing message on %{dnsname}", message->origin);
                
                database_service_message_clear(message);
                database_load_message_free(message);
            }
            else
            {
                log_debug("clearing empty message");
            }
            async_message_release(async);
        }
        
        async_queue_finalize(&database_handler_queue);
        
        database_service_run_garbage_collector();
        
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
    zone_set_lock(&database_zone_desc); // unlock checked

    ptr_set_iterator iter;
    ptr_set_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->value;

        zone_set_status(zone_desc, ZONE_STATUS_DROP_AFTER_RELOAD);
    }

    zone_set_unlock(&database_zone_desc);
}

static void
database_service_set_drop_after_reload_for_set(const ptr_set *fqdn_set)
{
    if(fqdn_set != NULL)
    {
        zone_set_lock(&database_zone_desc); // unlock checked
    
        ptr_set_iterator iter;
        ptr_set_iterator_init(fqdn_set, &iter);

        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *fqdn_node = ptr_set_iterator_next_node(&iter);
            ptr_node *zone_node = ptr_set_find(&database_zone_desc.set, fqdn_node->key);
            if(zone_node != NULL)
            {
                zone_desc_s *zone_desc = (zone_desc_s *)zone_node->value;
                if(zone_desc != NULL)
                {
                    zone_set_status(zone_desc, ZONE_STATUS_DROP_AFTER_RELOAD);
                    if(zone_desc->loaded_zone != NULL)
                    {
#if HAS_RRSIG_MANAGEMENT_SUPPORT
                        zdb_zone_set_maintained(zone_desc->loaded_zone, zdb_rr_label_flag_isclear(zone_desc->loaded_zone->apex, ZDB_ZONE_IS_SLAVE));
#else
                        // the preprocessor exclusion could go around the 'if' but
                        // I'd rather keep this as a "what to do when a zone has been loaded" marker
#endif
                    }
                }
            }
        }

        zone_set_unlock(&database_zone_desc);
    }
    else
    {
        database_service_set_drop_after_reload();
    }
}

static void
database_service_clear_drop_after_reload()
{
    zone_set_lock(&database_zone_desc); // unlock checked

    ptr_set_iterator iter;
    ptr_set_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->value;

        zone_clear_status(zone_desc, ZONE_STATUS_DROP_AFTER_RELOAD);
    }

    zone_set_unlock(&database_zone_desc);
}



static void
database_service_do_drop_after_reload()
{
    log_debug1("database_service_do_drop_after_reload()");
    
    zone_set_lock(&database_zone_desc); // unlock checked

    ptr_set_iterator iter;
    ptr_set_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->value;

        if((zone_get_status(zone_desc) & ZONE_STATUS_DROP_AFTER_RELOAD) != 0)
        {
            // drop the zone & zone desc
            
            log_debug2("database_service_do_drop_after_reload: queuing %{dnsname} for unload", zone_origin(zone_desc));

            database_zone_desc_unload(zone_origin(zone_desc));
        }
    }

    zone_set_unlock(&database_zone_desc);
    
    log_debug1("database_service_do_drop_after_reload() done");
}

static ya_result
database_service_process_command(zone_desc_s *zone_desc, zone_command_s* command)
{
    ya_result ret = SUCCESS;

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
#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
        case DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES:
        {
            ret = database_service_zone_dnssec_maintenance(zone_desc);
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
            if(ISOK(ret = zone_lock(zone_desc, ZONE_LOCK_SAVE)))
            {
                if(command->parm.ptr != NULL)
                {
                    zone_set_status(zone_desc, ZONE_STATUS_MUST_CLEAR_JOURNAL);
                }
                
                zone_unlock(zone_desc, ZONE_LOCK_SAVE);

                database_service_zone_store(zone_desc); // text
            }
            else
            {
                log_err("database_service_zone_store: failed to lock zone settings for '%{dnsname}'", zone_origin(zone_desc));
            }
            break;
        }
        case DATABASE_SERVICE_ZONE_PROCESSED:
        {
            break;
        }
        default:
        {
            ret = INVALID_STATE_ERROR;
            log_err("unexpected command %d", command->id);
        }
    }

    return ret;
}

static void database_service_message_clear_free_fqdn_node(ptr_node *node)
{
    dnsname_zfree(node->key);
}

static void
database_service_message_clear(database_message *message)
{
    switch(message->payload.type)
    {
        case DATABASE_SERVICE_ZONE_DESC_LOAD:
        {
            zone_release(message->payload.zone_desc_load.zone_desc);
            message->payload.zone_desc_load.zone_desc = NULL;
            break;
        }
        case DATABASE_SERVICE_ZONE_DESC_UNLOAD:
        case DATABASE_SERVICE_ZONE_LOAD:
        case DATABASE_SERVICE_ZONE_UNLOAD:
        case DATABASE_SERVICE_ZONE_FREEZE:
        case DATABASE_SERVICE_ZONE_UNFREEZE:            
        case DATABASE_SERVICE_QUERY_AXFR:
        case DATABASE_SERVICE_QUERY_IXFR:
        {
            break;
        }
        case DATABASE_SERVICE_SET_DROP_AFTER_RELOAD:
        {
            if(message->payload.drop_after_reload.do_subset)
            {
                ptr_set_callback_and_destroy(&message->payload.drop_after_reload.zone_set, database_service_message_clear_free_fqdn_node);
            }
            break;
        }
        case DATABASE_SERVICE_DO_DROP_AFTER_RELOAD:
        {
            break;
        }
        case DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES:
        {
            if(message->payload.zone_update_signatures.expected_zone != NULL)
            {
                zdb_zone_release(message->payload.zone_update_signatures.expected_zone);
                message->payload.zone_update_signatures.expected_zone = NULL;
            }
            zone_release(message->payload.zone_update_signatures.expected_zone_desc);
            message->payload.zone_update_signatures.expected_zone_desc = NULL;
            break;
        }
        case DATABASE_SERVICE_ZONE_LOADED_EVENT:
        {
            if(message->payload.zone_loaded_event.zone != NULL)
            {
                zdb_zone_release(message->payload.zone_loaded_event.zone);
                message->payload.zone_loaded_event.zone = NULL;
            }
            break;
        }
        case DATABASE_SERVICE_ZONE_MOUNTED_EVENT:
        {
            if(message->payload.zone_mounted_event.zone != NULL)
            {
                zdb_zone_release(message->payload.zone_mounted_event.zone);
                message->payload.zone_mounted_event.zone = NULL;
            }

            zone_release(message->payload.zone_mounted_event.zone_desc);
            message->payload.zone_mounted_event.zone_desc = NULL;
            break;
        }
        case DATABASE_SERVICE_ZONE_UNMOUNTED_EVENT:
        {
            zone_release(message->payload.zone_unmounted_event.zone_desc);
            message->payload.zone_unmounted_event.zone_desc = NULL;
            break;
        }
        case DATABASE_SERVICE_ZONE_UNLOADED_EVENT:
        {
            zone_release(message->payload.zone_unloaded_event.zone_desc);
            message->payload.zone_unloaded_event.zone_desc = NULL;
            break;
        }
        case DATABASE_SERVICE_ZONE_DOWNLOADED_EVENT:
        default:
        {
            break;
        }
        case DATABASE_SERVICE_ZONE_SAVE_TEXT:
        case DATABASE_SERVICE_ZONE_PROCESSED:
        {
            break;
        }
        case DATABASE_SERVICE_CALLBACK:
        {
            message->payload.callback.callback(message->payload.callback.args, TRUE);
            break;
        }
    }
}

#if HAS_RRSIG_MANAGEMENT_SUPPORT

static zone_desc_s *
database_service_on_update_zone_signatures_event(database_message *message)
{
    // desc
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);

    // current zone desc is the one we wanted to update the signatures on ?

    if(zone_desc != NULL)
    {
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
                    // check

                    log_debug("database: %{dnsname}: zone signature triggered", zone_origin(zone_desc));

                    zone_enqueue_command(zone_desc, DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES, NULL, FALSE);
                }
                else
                {
                    log_warn("database: %{dnsname}: zone signature triggered for another instance of the zone, ignoring", zone_origin(zone_desc));

                    zone_release(zone_desc);
                    zone_desc = NULL;
                }

                zdb_zone_release(zone);
#if DEBUG
                zone = NULL;
#endif
            }
        }
        else
        {
            log_warn("database: %{dnsname}: zone signature triggered for another instance of the zone settings, ignoring", zone_origin(message->payload.zone_update_signatures.expected_zone_desc));
            zone_release(zone_desc);
#if DEBUG
            zone_desc = NULL;
#endif
        }
    }
    else  // zone_desc == NULL ie: shutdown, reconfigure
    {
        log_warn("database: %{dnsname}: zone signature triggered but zone settings are not available, ignoring", zone_origin(message->payload.zone_update_signatures.expected_zone_desc));
    }

    zdb_zone_release(message->payload.zone_update_signatures.expected_zone);
    message->payload.zone_update_signatures.expected_zone = NULL;
    zone_release(message->payload.zone_update_signatures.expected_zone_desc);
    message->payload.zone_update_signatures.expected_zone_desc = NULL;
    
    return zone_desc;
}

#endif

static zone_desc_s*
database_service_on_zone_mounted_event(database_message* message)
{
    // desc
    zone_desc_s *zone_desc = message->payload.zone_mounted_event.zone_desc;

    if(ISOK(message->payload.zone_mounted_event.result_code))
    {
        log_info("database: %{dnsname}: zone successfully mounted", message->origin);

#if ZDB_HAS_MASTER_SUPPORT && ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT
        if(zone_desc->type == ZT_MASTER)
        {
            if((message->payload.zone_mounted_event.zone != NULL) &&
                zdb_zone_is_store_clear_journal_after_mount(message->payload.zone_mounted_event.zone))
            {
                database_zone_store_ex(message->origin, TRUE);

                zdb_zone_clear_store_clear_journal_after_mount(message->payload.zone_mounted_event.zone);
            }

            // verify policies

            ya_result ret;

            if(ISOK(ret = zone_policy_process(zone_desc)))
            {
                log_debug("database: %{dnsname}: on-mount policy process done", message->origin);
            }
            else
            {
                log_err("database: %{dnsname}: on-mount policy process failed: %r", message->origin, ret);
            }

            if((message->payload.zone_mounted_event.zone != NULL) && zdb_zone_is_maintained(message->payload.zone_mounted_event.zone))
            {
                if(zone_maintains_dnssec(zone_desc))
                {
                    if(message->payload.zone_mounted_event.zone != NULL)
                    {
                        zdb_zone_lock(message->payload.zone_mounted_event.zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                        const zdb_packed_ttlrdata *dnskey_rrset = zdb_record_find(&message->payload.zone_mounted_event.zone->apex->resource_record_set, TYPE_DNSKEY); // zone is locked
                        zdb_zone_unlock(message->payload.zone_mounted_event.zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

                        if(dnskey_rrset != NULL)
                        {
                            log_info("database: %{dnsname}: signature maintenance initialisation", message->origin);

                            if((zdb_zone_get_flags(message->payload.zone_mounted_event.zone) & ZDB_ZONE_MAINTENANCE_ON_MOUNT) != 0)
                            {
                                message->payload.zone_mounted_event.zone->progressive_signature_update.earliest_signature_expiration = 0;
                                database_zone_update_signatures(
                                        message->origin,
                                        message->payload.zone_mounted_event.zone_desc,
                                        message->payload.zone_mounted_event.zone
                                        );
                            }
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

#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
            zdb_zone *zone = message->payload.zone_mounted_event.zone;

            u8 zone_dnssec_type = zone_policy_guess_dnssec_type(zone);

            switch(zone_dnssec_type)
            {
                case ZONE_DNSSEC_FL_NOSEC:
                    log_debug("database: %{dnsname}: slave zone is not DNSSEC", message->origin);
                    break;
                case ZONE_DNSSEC_FL_NSEC:
                    log_debug("database: %{dnsname}: slave zone is NSEC", message->origin);
                    break;
                case ZONE_DNSSEC_FL_NSEC3:
                    log_debug("database: %{dnsname}: slave zone is NSEC3", message->origin);
                    break;
                case ZONE_DNSSEC_FL_NSEC3_OPTOUT:
                    log_debug("database: %{dnsname}: slave zone is NSEC3 OPT-OUT", message->origin);
                    break;
            }

            zone_dnssec_status_update(zone);
#endif
            database_zone_refresh_maintenance(g_config->database, message->origin, 0); // means next refresh from now // database_zone_refresh_maintenance_wih_zone(zone_desc->loaded_zone, 0);
        }
    }
    else
    {
        log_err("database: %{dnsname}: failed to mount the zone: %r", message->origin, message->payload.zone_mounted_event.result_code);
    }

    if(message->payload.zone_mounted_event.zone != NULL)
    {
        zdb_zone_clear_flags(message->payload.zone_mounted_event.zone, ZDB_ZONE_MAINTENANCE_ON_MOUNT);

        zdb_zone_release(message->payload.zone_mounted_event.zone);
        message->payload.zone_mounted_event.zone = NULL;
    }

    // do NOT release zone_desc
    message->payload.zone_mounted_event.zone_desc = NULL;

    // do not release zone_desc because we will try to push the event

    return zone_desc;
}

static zone_desc_s*
database_service_on_zone_loaded_event(database_message *message)
{
    // desc
    zone_desc_s *zone_desc = message->payload.zone_loaded_event.zone_desc;

    if(ISOK(message->payload.zone_loaded_event.result_code))
    {
        if(message->payload.zone_loaded_event.result_code == 1)
        {
            log_info("database: %{dnsname}: zone successfully loaded", message->origin);

            if((message->payload.zone_mounted_event.zone != NULL) &&
                zdb_zone_is_store_clear_journal_after_mount(message->payload.zone_mounted_event.zone))
            {
                journal_truncate(zone_origin(zone_desc));
            }

            zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_MOUNT, NULL, FALSE);
        }
        else
        {
            log_debug("database: %{dnsname}: there was no need to load the zone", message->origin);
        }
    }
    else if((message->payload.zone_loaded_event.result_code == ZRE_NO_VALID_FILE_FOUND) && (zone_desc->type == ZT_SLAVE))
    {
        log_debug("database: %{dnsname}: no local copy of the zone is available: download required", message->origin);
    }
    else
    {
        if(message->payload.zone_loaded_event.result_code != STOPPED_BY_APPLICATION_SHUTDOWN)
        {
            log_err("database: %{dnsname}: failed to load the zone: %r", message->origin, message->payload.zone_loaded_event.result_code);
        }
        else
        {
            log_debug("database: %{dnsname}: zone load cancelled by shutdown", message->origin);
        }
    }

    if(message->payload.zone_loaded_event.zone != NULL)
    {
        zdb_zone_release(message->payload.zone_loaded_event.zone);
        message->payload.zone_loaded_event.zone = NULL;
    }

    return zone_desc;
}

static zone_desc_s*
database_service_on_zone_unmounted_event(database_message *message)
{
    // desc (both)
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);

    log_info("database: %{dnsname}: zone successfully unmounted", message->origin);

    zone_release(message->payload.zone_unmounted_event.zone_desc);
    message->payload.zone_unmounted_event.zone_desc = NULL;
    return zone_desc;
}

static zone_desc_s *
database_service_on_zone_desc_unload(database_message *message)
{
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);
    
    if(zone_desc != NULL)
    {
        if((zone_get_status(zone_desc) & ZONE_STATUS_UNREGISTERING) == 0)
        {
            zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_DESC_UNLOAD, NULL, FALSE);
            zone_set_status(zone_desc, ZONE_STATUS_UNREGISTERING);
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

    return zone_desc;
}

static zone_desc_s*
database_service_on_zone_load(database_message *message)
{
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);

    if(zone_desc != NULL)
    {
        log_debug("database: %{dnsname}: load, @%p", message->origin, zone_desc);

        if((zone_get_status(zone_desc) & (ZONE_STATUS_LOAD|ZONE_STATUS_LOADING)) == 0)
        {                    
            zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_LOAD, NULL, FALSE);
        }
        else
        {
            log_debug("database: %{dnsname}: ignoring load command for: already loading", message->origin);
        }
    }
    else
    {
        log_debug("database: %{dnsname}: cannot load: zone is not configured", message->origin);
    }

    return zone_desc;
}

static zone_desc_s *
database_service_on_service_zone_unload(database_message *message)
{
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);
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
    
    return zone_desc;
}

static zone_desc_s *
database_service_on_zone_freeze(database_message *message)
{
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);
    if(zone_desc != NULL)
    {
        zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_FREEZE, NULL, FALSE);
    }
    else
    {
        log_err("database: %{dnsname}: cannot freeze: zone is not configured", message->origin);
    }
    
    return zone_desc;
}

static zone_desc_s*
database_service_on_zone_unfreeze(database_message *message)
{
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);
    if(zone_desc != NULL)
    {
        zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_UNFREEZE, NULL, FALSE);
    }
    else
    {
        log_err("database: %{dnsname}: cannot unfreeze: zone is not configured", message->origin);
    }

    return zone_desc;
}

static zone_desc_s*
database_service_on_zone_store_text(database_message *message)
{
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);
    
    if(zone_desc != NULL)
    {
        zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_SAVE_TEXT, (message->payload.zone_store.clear)?(void*)1:(void*)0, FALSE);
    }
    else
    {
        log_err("database: %{dnsname}: cannot write to disk as text: zone is not configured", message->origin);
    }
    
    return zone_desc;
}

static zone_desc_s*
database_service_on_zone_downloaded_event(database_message *message)
{
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);

    if(ISOK(message->payload.zone_downloaded_event.result_code))
    {
        //log_info("database: %{dnsname}: zone successfully downloaded (%{dnstype})", message->origin, &message->payload.zone_downloaded_event.download_type);

        if(message->payload.zone_downloaded_event.download_type != TYPE_NONE)
        {
            log_info("database: %{dnsname}: zone successfully downloaded", message->origin);

            if(message->payload.zone_downloaded_event.download_type == TYPE_AXFR)
            {
                database_zone_load(message->origin); // the downloaded file can now be loaded
            }
        }
    }
    else
    {
        log_err("database: %{dnsname}: failed to download the zone: %r", message->origin, message->payload.zone_downloaded_event.result_code);
    }

    return zone_desc;
}

static zone_desc_s *
database_service_on_zone_unloaded_event(database_message *message)
{
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);

    if(ISOK(message->payload.zone_unloaded_event.result_code))
    {
        log_info("database: %{dnsname}: zone successfully unloaded", message->origin);
    }
    else
    {
        log_err("database: %{dnsname}: failed to unload the zone: %r", message->origin, message->payload.zone_unloaded_event.result_code);
    }

    zone_release(message->payload.zone_unloaded_event.zone_desc);
    message->payload.zone_unloaded_event.zone_desc = NULL;

    return zone_desc;
}

static zone_desc_s*
database_serice_on_zone_processed(database_message *message)
{
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);
    if(zone_desc != NULL)
    {
        log_debug("database: %{dnsname}: processing done", message->origin);
    }
    else
    {
        log_debug("database: %{dnsname}: processed zone is not configured", message->origin);
    }

    return zone_desc;
}

static void
database_service_zone_destroyed_callback(const u8 *origin)
{
    log_debug("database: %{dnsname}: memory freed", origin);

    zone_desc_s *zone_desc = zone_acquirebydnsname(origin);
    if(zone_desc != NULL)
    {
        zone_lock(zone_desc, ZONE_LOCK_LOAD);
        if((zone_get_status(zone_desc) & ZONE_STATUS_LOAD_AFTER_DROP) != 0)
        {
            zone_clear_status(zone_desc, ZONE_STATUS_LOAD_AFTER_DROP);
            // load the zone
            //database_service_zone_load(zone_desc);

            //zone_lock(zone_desc, ZONE_LOCK_LOAD);
            //zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_LOAD, NULL, TRUE);
            //zone_unlock(zone_desc, ZONE_LOCK_LOAD);

            database_zone_load(origin);
        }
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
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
    
    bool running;

    zdb_zone_garbage_run_callback_add(database_service_zone_destroyed_callback);
    
    while((running = service_should_run(worker)) || !async_queue_empty(&database_handler_queue))
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
            if(now - sbmps_epoch_us >= ONE_SECOND_US)
            {
                double mps = sbmps_count;
                mps *= ONE_SECOND_US_F;
                mps /= (now - sbmps_epoch_us);
                log_info("database: %12.3f msg/s", mps);
                sbmps_epoch_us = now;
                sbmps_count = 0;
            }
            sbmps_count++;
        }
#endif
        
#if DEBUG
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
        
        if(!running)
        {
            switch(message->payload.type)
            {
                case DATABASE_SERVICE_ZONE_DESC_LOAD:
                case DATABASE_SERVICE_ZONE_DESC_UNLOAD:
                case DATABASE_SERVICE_ZONE_LOAD:
                case DATABASE_SERVICE_ZONE_UNLOAD:
                case DATABASE_SERVICE_ZONE_FREEZE:
                case DATABASE_SERVICE_ZONE_UNFREEZE:            
                case DATABASE_SERVICE_QUERY_AXFR:
                case DATABASE_SERVICE_QUERY_IXFR:
                case DATABASE_SERVICE_SET_DROP_AFTER_RELOAD:
                case DATABASE_SERVICE_DO_DROP_AFTER_RELOAD:
                case DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES:
                case DATABASE_SERVICE_ZONE_LOADED_EVENT:
                case DATABASE_SERVICE_ZONE_MOUNTED_EVENT:
                case DATABASE_SERVICE_ZONE_UNMOUNTED_EVENT:
                case DATABASE_SERVICE_ZONE_UNLOADED_EVENT:
                case DATABASE_SERVICE_ZONE_DOWNLOADED_EVENT:
                case DATABASE_SERVICE_CALLBACK:
                default:
                {
                    log_debug("database: shutting down: cleaning message %i", message->payload.type);
                    
                    database_service_message_clear(message);
                    database_load_message_free(message);
                    async_message_release(async);
                    continue;
                }
                case DATABASE_SERVICE_ZONE_SAVE_TEXT:
                case DATABASE_SERVICE_ZONE_PROCESSED:
                {
                    log_debug("database: shutting down: not ignoring message %i", message->payload.type);
                    
                    break;
                }
            }
        }
        
        /*
         * load command ?
         */
        
        switch(message->payload.type)
        {
            case DATABASE_SERVICE_ZONE_DESC_LOAD:
            {
                // desc
                database_load_zone_desc(message->payload.zone_desc_load.zone_desc); // foreground
                zone_release(message->payload.zone_desc_load.zone_desc);
                message->payload.zone_desc_load.zone_desc = NULL;
                break;
            }
            
            // DISPATCH TO THE ZONE DESCRIPTOR
            
            case DATABASE_SERVICE_ZONE_DESC_UNLOAD:
            {
                zone_desc = database_service_on_zone_desc_unload(message);
                
                break;
            }
            case DATABASE_SERVICE_ZONE_LOAD:
            {
                zone_desc = database_service_on_zone_load(message);
                break;
            }

            case DATABASE_SERVICE_ZONE_UNLOAD:
            {
                zone_desc = database_service_on_service_zone_unload(message);
                break;
            }
            case DATABASE_SERVICE_ZONE_FREEZE:
            {
                zone_desc = database_service_on_zone_freeze(message);
                break;
            }
            case DATABASE_SERVICE_ZONE_UNFREEZE:
            {
                zone_desc = database_service_on_zone_unfreeze(message);
                break;
            }
            case DATABASE_SERVICE_ZONE_SAVE_TEXT:
            {
                zone_desc = database_service_on_zone_store_text(message);
                break;
            }
            case DATABASE_SERVICE_QUERY_AXFR:
            {
                // no desc
                database_service_zone_axfr_query(message->origin); // background, triggers 'downloaded' event
                
                break;
            }
            
            case DATABASE_SERVICE_QUERY_IXFR:
            {
                // no desc
                database_service_zone_ixfr_query(message->origin); // background, triggers 'downloaded' event
                
                break;
            }
            
            case DATABASE_SERVICE_SET_DROP_AFTER_RELOAD:
            {
                // no desc
                // ZONE_STATUS_DROP_AFTER_RELOAD
                
                if(message->payload.drop_after_reload.do_subset)
                {
                    database_service_set_drop_after_reload_for_set(&message->payload.drop_after_reload.zone_set); // foreground
                    
                    if(message->payload.drop_after_reload.do_subset)
                    {
                        ptr_set_callback_and_destroy(&message->payload.drop_after_reload.zone_set, database_service_message_clear_free_fqdn_node);
                    }
                }
                else
                {
                    database_service_set_drop_after_reload();
                }
                                
                break;
            }
            
            case DATABASE_SERVICE_DO_DROP_AFTER_RELOAD:
            {
                // no desc
                database_service_do_drop_after_reload(); // foreground
                
                break;
            }
            
            case DATABASE_SERVICE_CLEAR_DROP_AFTER_RELOAD:
            {
                database_service_clear_drop_after_reload(); // foreground
                
                break;
            }
            
            //

#if ZDB_HAS_DNSSEC_SUPPORT
#if HAS_RRSIG_MANAGEMENT_SUPPORT
            
            case DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES:
            {                
                zone_desc = database_service_on_update_zone_signatures_event(message);
                break;
            }
            
#endif
#endif // ZDB_HAS_DNSSEC_SUPPORT
            // EVENTS
            
            case DATABASE_SERVICE_ZONE_LOADED_EVENT:
            {
                zone_desc = database_service_on_zone_loaded_event(message);
                break;
            }
                
            case DATABASE_SERVICE_ZONE_MOUNTED_EVENT:
            {
                zone_desc = database_service_on_zone_mounted_event(message);
                break;
            }
            
            case DATABASE_SERVICE_ZONE_UNMOUNTED_EVENT:
            {
                zone_desc = database_service_on_zone_unmounted_event(message);
                break;
            }
            case DATABASE_SERVICE_ZONE_UNLOADED_EVENT:
            {
                zone_desc = database_service_on_zone_unloaded_event(message);
                break;
            }
            
            case DATABASE_SERVICE_ZONE_DOWNLOADED_EVENT:
            {
                zone_desc = database_service_on_zone_downloaded_event(message);
                break;
            }
            
            case DATABASE_SERVICE_ZONE_PROCESSED:
            {
                zone_desc = database_serice_on_zone_processed(message);
                break;
            }
            
            case DATABASE_SERVICE_CALLBACK:
            {
                log_debug("database: queuing %s callback from %llT", message->payload.callback.name, message->payload.callback.timestamp);
                database_callback_run(message);
                break;
            }
            
            default:
            {
                break;
            }
        }
        
        if(zone_desc != NULL)
        {
            ya_result ret;

            if(FAIL(ret = zone_lock(zone_desc, ZONE_LOCK_SERVICE)))
            {
                log_err("database: %{dnsname}: unable to lock zone: %r", message->origin, ret);
            }

#if DEBUG
            log_debug("database: %{dnsname}: zone status: %x", message->origin, zone_get_status(zone_desc));
#endif

            while((zone_get_status(zone_desc) & ZONE_STATUS_PROCESSING) == 0)
            {
#if DEBUG
                zone_desc_log(g_server_logger, LOG_DEBUG, zone_desc, "database-service");
#endif
                zone_command_s* command = zone_dequeue_command(zone_desc);
                
                if(command != NULL)
                {
                    zone_set_status(zone_desc, ZONE_STATUS_PROCESSING);
                    zone_desc->last_processor = command->id;
                    
                    log_debug("database: %{dnsname}: processing zone @%p (%s)", message->origin, zone_desc, database_service_operation_get_name(zone_desc->last_processor));
                       
                    zone_unlock(zone_desc, ZONE_LOCK_SERVICE);

                    if(ISOK(ret = database_service_process_command(zone_desc, command)))
                    {
                        if(FAIL(zone_lock(zone_desc, ZONE_LOCK_SERVICE)))
                        {
                            log_err("database: %{dnsname}: zone cannot be locked", message->origin);
                        }
                    }
                    else
                    {
                        if((ret != FEATURE_NOT_SUPPORTED) && (ret != SERVICE_ALREADY_RUNNING))
                        {
                            log_err("database: %{dnsname}: cannot execute command: %08x: %r", message->origin, command->id, ret);
                        }
                        else
                        {
                            log_debug("database: %{dnsname}: cannot execute command: %08x: %r", message->origin, command->id, ret);
                        }

                        if(FAIL(ret = zone_lock(zone_desc, ZONE_LOCK_SERVICE)))
                        {
                            log_err("database: %{dnsname}: unable to re-lock zone following an internal error: %r", message->origin, ret);
                        }

                        zone_clear_status(zone_desc, ZONE_STATUS_PROCESSING);
                    }

                    zone_command_free(command);
                }
                else
                {
                    if(zone_get_status(zone_desc) & ZONE_STATUS_MARKED_FOR_DESTRUCTION)
                    {
                        log_debug("database: %{dnsname}: zone @%p is marked for destruction", zone_origin(zone_desc), zone_desc);
                    }
                    if(!(zone_get_status(zone_desc) & ZONE_STATUS_PROCESSING))
                    {
                        zone_desc->last_processor = 0;
                    }
                    break;
                }
            }

#if DEBUG
            log_debug("database: %{dnsname}: zone @%p is processed by %s", message->origin, zone_desc, database_service_operation_get_name(zone_desc->last_processor));
#endif
            
            zone_unlock(zone_desc, ZONE_LOCK_SERVICE);
            zone_release(zone_desc);
#if DEBUG
            zone_desc = NULL;
#endif
        }
        
        database_load_message_free(message);
        async_message_release(async);
    }

    zdb_zone_garbage_run_callback_remove(database_service_zone_destroyed_callback);
    
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
    
    zone_set_lock(&database_zone_desc);  // unlock checked

    ptr_node *node = ptr_set_get_first(&database_zone_desc.set);
    
    for(;;)
    {
        u8 *name = buffer;
        const u8 *last = NULL;
        
        for(; node != NULL; node = ptr_set_node_next(node))
        {
            zone_desc_s *zone_desc = (zone_desc_s *)node->value;
            int name_len = dnsname_len(zone_origin(zone_desc));
            if(name_len > (&buffer[sizeof(buffer)] - name))
            {
                break;
            }
            memcpy(name, zone_origin(zone_desc), name_len);
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
        
        zone_set_lock(&database_zone_desc);  // unlock checked
        
        // get back the last name
        
        node = ptr_set_find(&database_zone_desc.set, last);
        
        if(node != NULL)
        {
            // and get the one that follows
            
            node = ptr_set_node_next(node);
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

static void
database_zone_update_signatures_common(const u8 *origin, zone_desc_s *expected_zone_desc, zdb_zone *expected_zone)
{
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

void
database_zone_update_signatures_resume(const u8 *origin, zone_desc_s *expected_zone_desc, zdb_zone *expected_zone)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES (resume)", origin);
    database_zone_update_signatures_common(origin, expected_zone_desc, expected_zone);
}

void
database_zone_update_signatures(const u8 *origin, zone_desc_s *expected_zone_desc, zdb_zone *expected_zone)
{
    if(expected_zone->progressive_signature_update.earliest_signature_expiration >= MAX_S32) // can only be == as it's an s32
    {
        log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES ignored", origin);
        return;
    }

    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES", origin);

    if(zdb_zone_set_maintenance_queued(expected_zone))
    {
        database_zone_update_signatures_common(origin, expected_zone_desc, expected_zone);
    }
    else
    {
#if DEBUG
        log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES ignored (already queued)", origin);
#endif
    }
}

void
database_zone_update_signatures_allow_queue(const u8 *origin, zone_desc_s *expected_zone_desc, zdb_zone *expected_zone)
{
    log_debug("database: %{dnsname}: maintenance done", expected_zone->origin);
    (void)origin;
    (void)expected_zone_desc;
    (void)expected_zone;
}

static ya_result
database_zone_update_signatures_alarm(void *args_, bool cancel)
{
    zdb_zone *zone = (zdb_zone*)args_;
    if(!cancel)
    {
        zone_desc_s *zone_desc = zone_acquirebydnsname(zone->origin);
        
        if(zone_desc != NULL)
        {
            log_debug("database: %{dnsname}: maintenance triggered by time", zone->origin);

            database_zone_update_signatures(zone->origin, zone_desc, zone);
            zone_release(zone_desc);
        }
    }
    zdb_zone_release(zone);

    return SUCCESS;
}

/**
 * 
 * Sets an alarm to enqueue a zone maintenance at a given time (best effort)
 * 
 * @param zone
 * @param at
 */

void
database_zone_update_signatures_at(zdb_zone *zone, u32 at)
{
    log_debug("database: %{dnsname}: will enqueue operation DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES at %T", zone->origin, at);

    zdb_zone_acquire(zone);
    alarm_event_node *event = alarm_event_new(
                        at,
                        ALARM_KEY_ZONE_SIGNATURE_UPDATE,
                        database_zone_update_signatures_alarm,
                        zone,
                        ALARM_DUP_REMOVE_LATEST,
                        "database-service-zone-maintenance");

    alarm_set(zone->alarm_handle, event);
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

void database_zone_store_ex(const u8 *origin, bool clear)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_SAVE_TEXT (clear=%i)", origin, clear);
    
    database_message *message = database_load_message_alloc(origin, DATABASE_SERVICE_ZONE_SAVE_TEXT);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    message->payload.zone_store.clear = clear;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void database_zone_store(const u8 *origin)
{
    database_zone_store_ex(origin, FALSE);
}

void
database_zone_desc_load(zone_desc_s *zone_desc)
{
    if(zone_desc != NULL)
    {
        log_debug("database: %{dnsname}: loading settings", zone_origin(zone_desc));

#if DEBUG
        zone_desc_log(MODULE_MSG_HANDLE, LOG_DEBUG, zone_desc, "database_zone_desc_load");
#endif

        if(service_started(&database_handler))
        {
            log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_DESC_LOAD", zone_origin(zone_desc));
            
            database_message *message = database_load_message_alloc(zone_origin(zone_desc), DATABASE_SERVICE_ZONE_DESC_LOAD);
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
            log_debug("database: %{dnsname}: loading setting with offline database", zone_origin(zone_desc));
            
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
        database_load_message_free((database_message*)async->args);
        async_message_release(async);
    }
    
    return SUCCESS;
}

void
database_zone_axfr_query_at(const u8 *origin, time_t at)
{    
    log_debug("database: %{dnsname}: will enqueue operation DATABASE_SERVICE_QUERY_AXFR at %T", origin, at);
    
    zdb_zone *zone = zdb_acquire_zone_read_from_fqdn(g_config->database, origin);
    
    if(zone == NULL)
    {
        log_warn("database: %{dnsname}: arming AXFR query: zone not in database", origin);
        return;
    }
    
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
    
    alarm_set(zone->alarm_handle, event);
    
    zdb_zone_release(zone);
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
        database_load_message_free((database_message*)async->args);
        async_message_release(async);
    }
    
    return SUCCESS;
}

void
database_zone_ixfr_query_at(const u8 *origin, time_t at)
{    
    log_debug("database: %{dnsname}: will enqueue operation DATABASE_SERVICE_QUERY_IXFR at %T", origin, at);
    
    zdb_zone *zone = zdb_acquire_zone_read_from_fqdn(g_config->database, origin);
    
    if(zone == NULL)
    {
        log_warn("database: %{dnsname}: arming IXFR query: zone not in database", origin);
        return;
    }
    
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
        
    alarm_set(zone->alarm_handle, event);
    
    zdb_zone_release(zone);
}



#define DATABASE_ZONE_RECONFIGURE_ALL   3
#define DATABASE_ZONE_RECONFIGURE_ZONES 2
#define DATABASE_ZONE_RECONFIGURE_ZONE  1

// keys+zones (a.k.a everything), zones, zone
static smp_int database_zone_reconfigure_queued = SMP_INT_INITIALIZER;
static ptr_set database_zone_reconfigure_fqdn = PTR_SET_DNSNAME_EMPTY;

bool
database_zone_is_reconfigure_enabled()
{
    return smp_int_get(&database_reconfigure_enable_count) > 0;
}

bool
database_zone_try_reconfigure_enable()
{
    bool ret = smp_int_setifequal(&database_reconfigure_enable_count, 0, 1);
    if(ret)
    {
        log_info("database: reconfigure started");
    }
    else
    {
        log_info("database: reconfigure already running");
    }
    return ret;
}

static void
database_zone_postpone_reconfigure_fqdn_destroy_cb(ptr_node *node)
{
    dnsname_zfree(node->key);
    node->key = NULL;
    node->value = NULL;
}

static void
database_zone_postpone_reconfigure_fqdn_destroy()
{
    ptr_set_callback_and_destroy(&database_zone_reconfigure_fqdn, database_zone_postpone_reconfigure_fqdn_destroy_cb);
}

void
database_zone_postpone_reconfigure_all()
{
    log_info("database: postponing reconfigure all");
    
    mutex_lock(&database_zone_reconfigure_queued.mutex);
    database_zone_reconfigure_queued.value = DATABASE_ZONE_RECONFIGURE_ALL;
    database_zone_postpone_reconfigure_fqdn_destroy();
    mutex_unlock(&database_zone_reconfigure_queued.mutex);
}

void
database_zone_postpone_reconfigure_zones()
{
    log_info("database: postponing reconfigure zones");
    
    mutex_lock(&database_zone_reconfigure_queued.mutex);
    if(database_zone_reconfigure_queued.value < DATABASE_ZONE_RECONFIGURE_ZONES)
    {
        database_zone_reconfigure_queued.value = DATABASE_ZONE_RECONFIGURE_ZONES;
        database_zone_postpone_reconfigure_fqdn_destroy();
    }
    mutex_unlock(&database_zone_reconfigure_queued.mutex);
}

void
database_zone_postpone_reconfigure_zone(const ptr_set *fqdn_set)
{
    log_info("database: postponing reconfigure of a set of zones");
    
    mutex_lock(&database_zone_reconfigure_queued.mutex);
    if(database_zone_reconfigure_queued.value <= DATABASE_ZONE_RECONFIGURE_ZONE)
    {
        database_zone_reconfigure_queued.value = DATABASE_ZONE_RECONFIGURE_ZONE;
        ptr_set_iterator iter;
        ptr_set_iterator_init(fqdn_set, &iter);
        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *src_node = ptr_set_iterator_next_node(&iter);
            ptr_node *node = ptr_set_insert(&database_zone_reconfigure_fqdn, src_node->key);
            if(node->value == NULL)
            {
                node->key = dnsname_zdup((const u8*)src_node->key);
                node->value = node->key;
            }
        }
    }
    mutex_unlock(&database_zone_reconfigure_queued.mutex);
}



static void
database_service_config_update_callback(void *args_, bool delete_only)
{
    (void)args_;
    if(!delete_only)
    {
        log_debug("database: try running postponed reconfigure");
        yadifad_config_update(g_config->config_file);
    }
}

void
database_service_config_update()
{
    log_debug("database: will run postponed reconfigure");
    database_post_callback(database_service_config_update_callback, NULL, "reconfigure-update-all");
}

static void
database_service_config_update_all_zones_callback(void *args_, bool delete_only)
{
    (void)args_;
    if(!delete_only)
    {
        log_debug("database: try running postponed reconfigure all zones");
        yadifad_config_update_zone(g_config->config_file, NULL);
    }
}

void
database_service_config_update_all_zones()
{
    log_debug("database: will run postponed reconfigure all zones");
    database_post_callback(database_service_config_update_all_zones_callback, NULL, "reconfigure-update-all-zones");
}

static void
database_service_config_update_zones_callback(void *args_, bool delete_only)
{
    ptr_set fqdn_set = {args_, ptr_set_dnsname_node_compare};
    
    if(!delete_only)
    {
        log_debug("database: try running postponed reconfigure some zones");        
        
        yadifad_config_update_zone(g_config->config_file, &fqdn_set);
    }
    
    ptr_set_callback_and_destroy(&fqdn_set, database_zone_postpone_reconfigure_fqdn_destroy_cb);
}

void
database_service_config_update_zones(ptr_set *fqdn_set)
{
    yassert(fqdn_set->compare == ptr_set_dnsname_node_compare);
    log_debug("database: running postponed reconfigure of a set of zones");
    database_post_callback(database_service_config_update_zones_callback, fqdn_set->root, "reconfigure-update-some-zones");
}

void
database_zone_reconfigure_disable()
{
    log_info("database: reconfigure done");
    
    mutex_lock(&database_zone_reconfigure_queued.mutex);
    
    int queue = database_zone_reconfigure_queued.value;
    database_zone_reconfigure_queued.value = 0;
    
    ptr_set fqdn_set = database_zone_reconfigure_fqdn;  // move the tree
    database_zone_reconfigure_fqdn.root = NULL;
    
    mutex_unlock(&database_zone_reconfigure_queued.mutex);
    
    // a copy of the queue and the fqdns is ready
    
    smp_int_set(&database_reconfigure_enable_count, 0);
    
    switch(queue)
    {
        case DATABASE_ZONE_RECONFIGURE_ALL:
        {
            database_service_config_update();
            break;
        }
        case DATABASE_ZONE_RECONFIGURE_ZONES:
        {
            database_service_config_update_all_zones();
            break;
        }
        case DATABASE_ZONE_RECONFIGURE_ZONE:
        default:
        {
            if(!ptr_set_isempty(&fqdn_set))
            {
                database_service_config_update_zones(&fqdn_set);
            }
            break;
        }
    }
    
    ptr_set_callback_and_destroy(&fqdn_set, database_zone_postpone_reconfigure_fqdn_destroy_cb);
}

void
database_set_drop_after_reload_for_set(const ptr_set* set)
{
    log_debug("database: enqueue operation DATABASE_SERVICE_SET_DROP_AFTER_RELOAD of a subset");
    database_message *message = database_load_message_alloc(database_all_origins, DATABASE_SERVICE_SET_DROP_AFTER_RELOAD);

    if(set != NULL)
    {
        message->payload.drop_after_reload.zone_set.root = NULL;
        message->payload.drop_after_reload.zone_set.compare = ptr_set_dnsname_node_compare;
        message->payload.drop_after_reload.do_subset = TRUE;

        ptr_set_iterator iter;
        ptr_set_iterator_init(set, &iter);
        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *node = ptr_set_insert(&message->payload.drop_after_reload.zone_set, ptr_set_iterator_next_node(&iter)->key);
            node->key = dnsname_zdup(node->key);
        }
    }
    else
    {
        message->payload.drop_after_reload.do_subset = FALSE;
    }
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

static void
database_clear_drop_after_reload()
{
    log_debug("database: enqueue operation DATABASE_SERVICE_CLEAR_DROP_AFTER_RELOAD");
    database_message *message = database_load_message_alloc(database_all_origins, DATABASE_SERVICE_CLEAR_DROP_AFTER_RELOAD);

    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

static void
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

/// Chain of events: reconfigure end (last part)

static void
database_zone_reconfigure_disable_when_processed_part2(void *args_, bool delete_only)
{
    (void)args_;
    (void)delete_only;
    database_zone_reconfigure_disable();
}

/// Chain of events: reconfigure end (first part)

static void
database_zone_reconfigure_disable_when_processed_part1(void *args_, bool delete_only)
{
    if(!delete_only)
    {
        if(args_ != NULL)
        {
            log_info("database: will drop marked zones not defined in current configuration");
            database_do_drop_after_reload();
        }
        else
        {
            log_info("database: will clear drop marked zone status");
            database_clear_drop_after_reload();
        }
    }
    else
    {
        log_info("database: deleting event ?");
    }
    
    database_post_callback(database_zone_reconfigure_disable_when_processed_part2, NULL, "reconfigure-queue-disable");
}

/**
 * Chain of events: reconfigure end (init)
 * 
 * When the database will have finished processing the queue at its current state, a callback handling drop-after-reload will be called
 * Then, after this handling has been done, the reconfigure mode will be disabled (enabling configure again)
 * 
 * @param do_drop_after_reload
 */

void
database_zone_reconfigure_do_drop_and_disable(bool do_drop_after_reload)
{
    if(do_drop_after_reload)
    {
        log_debug("database: will run reconfigure do drop and disable");
    }
    else
    {
        log_debug("database: will run reconfigure clear drop and disable");
    }
    void *args = do_drop_after_reload?(void*)1:(void*)0;
    database_post_callback(database_zone_reconfigure_disable_when_processed_part1, args, "reconfigure-queue-handle-drop-after-reload");
}


void
database_fire_zone_loaded(zone_desc_s *zone_desc, zdb_zone *zone, ya_result result_code)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_LOADED_EVENT (%r)", zone_origin(zone_desc), result_code);
    database_message *message = database_load_message_alloc(zone_origin(zone_desc), DATABASE_SERVICE_ZONE_LOADED_EVENT);
    
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
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_MOUNTED_EVENT (%r)", zone_origin(zone_desc), result_code);
    database_message *message = database_load_message_alloc(zone_origin(zone_desc), DATABASE_SERVICE_ZONE_MOUNTED_EVENT);
    
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
database_fire_zone_unmounted(zone_desc_s *zone_desc)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_UNMOUNTED_EVENT", zone_origin(zone_desc));
    database_message *message = database_load_message_alloc(zone_origin(zone_desc), DATABASE_SERVICE_ZONE_UNMOUNTED_EVENT);
    
    zone_acquire(zone_desc);
    
    message->payload.zone_unmounted_event.zone_desc = zone_desc;
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_fire_zone_processed(zone_desc_s *zone_desc)
{
    log_debug("database: %{dnsname}: enqueue operation DATABASE_SERVICE_ZONE_PROCESSED", zone_origin(zone_desc));
    database_message *message = database_load_message_alloc(zone_origin(zone_desc), DATABASE_SERVICE_ZONE_PROCESSED);
    
    async_message_s *async = async_message_alloc();
    async->id = message->payload.type;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&database_handler_queue, async);
}

void
database_post_callback(database_message_callback_function callback, void *args, const char * const name)
{
    log_debug("database: enqueue operation DATABASE_SERVICE_CALLBACK %s", name);
    database_message *message = database_load_message_alloc(database_all_origins, DATABASE_SERVICE_CALLBACK);
    message->payload.callback.callback = callback;
    message->payload.callback.args = args;
    message->payload.callback.timestamp = timeus();
    message->payload.callback.name = name;
    
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
database_service_zone_store_queue_thread(thread_pool_function func, void *parm, thread_pool_task_counter *counter,
                                         const char *categoryname)
{
    thread_pool_enqueue_call(database_zone_store_thread_pool, func, parm, counter, categoryname);
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
    if(database_zone_unload_thread_pool != NULL)
    {
        thread_pool_enqueue_call(database_zone_unload_thread_pool, database_service_run_garbage_collector_thread, NULL, NULL, "garbage");
    }
}

static void*
database_callback_thread(void *parms_)
{
    database_message_callback_s *callback = (database_message_callback_s*)parms_;
    
    if(callback->type == DATABASE_SERVICE_CALLBACK)
    {
        log_debug("database: executing %s callback from %llT", callback->name, callback->timestamp);
        callback->callback(callback->args, FALSE);
        ZFREE_OBJECT(callback);
    }
    else
    {
        log_err("database: got an invalid callback");
    }
    return NULL;
}

static void
database_callback_run(database_message *message)
{
    database_message_callback_s *cb;
    ZALLOC_OBJECT_OR_DIE(cb, database_message_callback_s, DBCB_TAG);
    *cb = message->payload.callback;
    thread_pool_enqueue_call(database_callback_thread_pool, database_callback_thread, cb, NULL, "callback");
}

//

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
    zone_set_lock(&database_zone_desc); // unlock checked
    
    if(!ptr_set_isempty(&database_zone_desc.set))
    {
        ptr_set_iterator iter;
        ptr_set_iterator_init(&database_zone_desc.set, &iter);

        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
            zone_desc_s *zone_desc = (zone_desc_s*)zone_node->value;

            zdb_zone *invalid_zone = zdb_zone_create(zone_origin(zone_desc)); // RC = 1
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

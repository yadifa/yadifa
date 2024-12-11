/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup ### #######
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnscore/thread_pool.h>
#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_write.h>

#include "server.h"

#include "config_error.h"

#include "zone.h"

#define DATABASE_SERVICE_STOP                    0

#define DATABASE_SERVICE_ZONE_DESC_LOAD          1
#define DATABASE_SERVICE_ZONE_DESC_UNLOAD        2

#define DATABASE_SERVICE_ZONE_LOAD               3
#define DATABASE_SERVICE_ZONE_LOADED_EVENT       4

#define DATABASE_SERVICE_ZONE_MOUNT              5
#define DATABASE_SERVICE_ZONE_MOUNTED_EVENT      6

#define DATABASE_SERVICE_ZONE_UNMOUNT            7
#define DATABASE_SERVICE_ZONE_UNMOUNTED_EVENT    8

#define DATABASE_SERVICE_ZONE_UNLOAD             9
#define DATABASE_SERVICE_ZONE_UNLOADED_EVENT     10

#define DATABASE_SERVICE_ZONE_SAVE_TEXT          11

#define DATABASE_SERVICE_QUERY_AXFR              12
#define DATABASE_SERVICE_QUERY_IXFR              13
#define DATABASE_SERVICE_ZONE_DOWNLOADED_EVENT   14

#define DATABASE_SERVICE_SET_DROP_AFTER_RELOAD   15
#define DATABASE_SERVICE_CLEAR_DROP_AFTER_RELOAD 16
#define DATABASE_SERVICE_DO_DROP_AFTER_RELOAD    17

#define DATABASE_SERVICE_RECONFIGURE_BEGIN       18
#define DATABASE_SERVICE_RECONFIGURE_END         19
#define DATABASE_SERVICE_UPDATE_ZONE_SIGNATURES  20
#define DATABASE_SERVICE_ZONE_FREEZE             21
#define DATABASE_SERVICE_ZONE_UNFREEZE           22

#define DATABASE_SERVICE_ZONE_PROCESSED          23

#define DATABASE_SERVICE_CALLBACK                24

//
#define DATABASE_SERVICE_OPERATION_COUNT         25

struct database_message_stop_s
{
    uint8_t type;
};

/// @note HAS_DYNAMIC_PROVISIONING

struct database_message_zone_desc_load_s
{
    uint8_t      type;
    zone_desc_t *zone_desc;
};

struct database_message_zone_desc_unload_s
{
    uint8_t type;
};

struct database_message_zone_desc_destroy_s
{
    uint8_t      type;
    zone_desc_t *zone_desc;
};

struct database_message_zone_desc_process_s
{
    uint8_t      type;
    zone_desc_t *zone_desc;
};

struct database_message_origin_process_s
{
    uint8_t      type;
    zone_desc_t *zone_desc;
};

struct database_message_zone_load_s
{
    uint8_t type;
};

struct database_message_zone_store_s
{
    uint8_t type;
    bool    clear;
};

struct database_message_zone_unload_s
{
    uint8_t     type;
    zdb_zone_t *zone; // to be destroyed
};

struct database_message_zone_update_signatures_s
{
    uint8_t      type;
    zone_desc_t *expected_zone_desc;
    zdb_zone_t  *expected_zone; // to be destroyed
};

struct database_message_zone_loaded_event_s
{
    uint8_t      type;
    ya_result    result_code; // yes, I meant to put this 32 bits field before the pointers ...
    zone_desc_t *zone_desc;
    zdb_zone_t  *zone; // to be mounted
};

struct database_message_zone_mounted_event_s
{
    uint8_t      type;
    ya_result    result_code; // yes, I meant to put this 32 bits field before the pointers ...
    zone_desc_t *zone_desc;
    zdb_zone_t  *zone; // mounted
};

struct database_message_zone_unloaded_event_s
{
    uint8_t      type;
    ya_result    result_code; // yes, I meant to put this 32 bits field before the pointers ...
    zone_desc_t *zone_desc;
    zdb_zone_t  *zone; // to be unloaded
};

struct database_message_zone_unmounted_event_s
{
    uint8_t      type;
    zone_desc_t *zone_desc; //
};

struct database_message_zone_downloaded_event_s
{
    uint8_t   type;
    uint16_t  download_type; // yes, I meant to put this 16 bits field before the 32 bits ones ...
    uint32_t  serial;
    ya_result result_code;
};

struct database_message_drop_after_reload_s
{
    uint8_t       type;
    ptr_treemap_t zone_set;
    bool          do_subset;
};

/**
 * void* args
 * bool delete_only (do not run the task, just cleanup the args)
 */

typedef void (*database_message_callback_function)(void *, bool);

struct database_message_callback_s
{
    uint8_t                            type;
    database_message_callback_function callback;
    void                              *args;
    uint64_t                           timestamp;
    const char                        *name;
};

typedef struct database_message_callback_s database_message_callback_s;

///

typedef struct database_message_s database_message_t;

struct database_message_s
{
    uint8_t *origin;

    union
    {
        uint8_t                        type;

        struct database_message_stop_s stop;

        /// @note HAS_DYNAMIC_PROVISIONING
        struct database_message_zone_desc_load_s         zone_desc_load;
        struct database_message_zone_desc_unload_s       zone_desc_unload;
        struct database_message_zone_desc_destroy_s      zone_desc_destroy;
        struct database_message_zone_desc_process_s      zone_desc_process;
        struct database_message_origin_process_s         origin_process;

        struct database_message_zone_load_s              zone_load;
        struct database_message_zone_store_s             zone_store;
        struct database_message_zone_unload_s            zone_unload;

        struct database_message_zone_update_signatures_s zone_update_signatures;
        ///
        struct database_message_zone_loaded_event_s     zone_loaded_event;
        struct database_message_zone_mounted_event_s    zone_mounted_event;
        struct database_message_zone_unloaded_event_s   zone_unloaded_event;
        struct database_message_zone_unmounted_event_s  zone_unmounted_event;
        struct database_message_zone_downloaded_event_s zone_downloaded_event;
        // struct database_message_zone_processed_event_s zone_processed_event;

        struct database_message_drop_after_reload_s drop_after_reload;
        struct database_message_callback_s          callback;

    } payload;
};

bool      database_service_started();

ya_result database_service_init();
ya_result database_service_start();
ya_result database_service_stop();
ya_result database_service_finalize();

void      database_load_all_zones();

/**
 * Loads then mounts a zone in the database.
 * This is using the registered zone settings (zone_desc_s) to do so.
 * The task is done in the background.
 */

void database_zone_load(const uint8_t *origin);

/**
 * Unloads a zone from memory.  If the zone is mounted it will be first be unmounted.
 * The task is done in the background.
 */

void database_zone_unload(zdb_zone_t *zone);

void database_zone_freeze(const uint8_t *origin);

void database_zone_unfreeze(const uint8_t *origin);

/**
 * Enqueues the storage of a zone
 *
 * @param origin
 */

void database_zone_store(const uint8_t *origin);

/**
 * Enqueues the storage of a zone, optionally clearing its journal
 *
 * @param origin
 */

void database_zone_store_ex(const uint8_t *origin, bool clear_journal);

/**
 * Saves a zone in the current thread using the provided locks (0 meaning: do not try to lock)
 * Not locking puts the responsibility of the lock to the caller as having this code running
 * without any lock whatsoever on the descriptor/zone will give undefined results, a.k.a : crash.
 *
 * @param zone_desc
 * @param desclockowner
 * @param zonelockowner
 * @param save_unmodified
 * @return
 */

#define DATABASE_SERVICE_ZONE_SAVE_DEFAULTS        ZDB_ZONE_WRITE_TEXT_FILE_DEFAULTS
#define DATABASE_SERVICE_ZONE_SAVE_FORCE_LABEL     ZDB_ZONE_WRITE_TEXT_FILE_FORCE_LABEL
#define DATABASE_SERVICE_ZONE_SAVE_IGNORE_SHUTDOWN ZDB_ZONE_WRITE_TEXT_FILE_IGNORE_SHUTDOWN
#define DATABASE_SERVICE_ZONE_SAVE_UNMODIFIED      4

ya_result database_service_zone_store_ex(zone_desc_t *zone_desc, uint8_t desclockowner, uint8_t zonelockowner, uint8_t flags);

/// @note HAS_DYNAMIC_PROVISIONING

/**
 *
 * Loads or updates the zone settings.
 *
 * If the service is running,
 *   the task is done in the background,
 * else
 *   the zone is registered.
 *   Note that direct registration is only meant to be used at program startup.
 *
 * @param zone_desc
 */

void database_zone_desc_load(zone_desc_t *zone_desc);

/**
 * Unloads the zone settings.
 * The zone will be unmounted and unloaded first.
 * The task is done in the background.
 *
 * @param origin
 */

void database_zone_desc_unload(const uint8_t *origin);

/**
 * Returns true if the zone with the origin is mounted
 *
 * @param origin
 * @return
 */

bool database_zone_desc_is_mounted(const uint8_t *origin);

/**
 *
 * Does an AXFR query for the origin.
 * If a new zone is downloaded, its loading is queued.
 *
 * @param origin
 */

void database_zone_axfr_query(const uint8_t *origin);

/**
 *
 * Does an AXFR query for the origin at a given time
 * If a new zone is downloaded, its loading is queued.
 *
 * @param origin
 * @param at epoch
 */

void database_zone_axfr_query_at(const uint8_t *origin, time_t at);

/**
 * Does an IXFR query for the origin.
 * If changes are downloaded, they are loaded into the zone.
 *
 * @param origin
 */

void database_zone_ixfr_query(const uint8_t *origin);

/**
 *
 * Does an IXFR query for the origin at a given time
 * If changes are downloaded, they are loaded into the zone.
 *
 * @param origin
 * @param at epoch
 */

void database_zone_ixfr_query_at(const uint8_t *origin, time_t at);

/**
 * Creates an empty zone setting for the given origin.
 *
 * @param origin
 * @return
 */

ya_result database_zone_create(const uint8_t *origin);

/**
 * Updates the file path of a zone setting
 *
 * @param origin
 * @param file_path
 * @return
 */

ya_result database_zone_set_file(const uint8_t *origin, const char *file_path);

/**
 *
 * Updates the zone type of a zone setting
 *
 * @param origin
 * @param primary_secondary_etc
 * @return
 */

ya_result database_zone_set_type(const uint8_t *origin, uint8_t primary_secondary_etc);

/**
 * Commits the changes to a zone setting.
 *
 * @param origin
 * @return
 */

ya_result database_zone_apply(const uint8_t *origin);

void      database_set_drop_after_reload_for_set(const ptr_treemap_t *fqdn_set);
/*
void database_clear_drop_after_reload();
void database_do_drop_after_reload();
*/

void database_zone_reconfigure_do_drop_and_disable(bool do_drop_after_reload);

bool database_zone_is_reconfigure_enabled();

bool database_zone_try_reconfigure_enable();

void database_zone_reconfigure_disable();

void database_zone_postpone_reconfigure_all();
void database_zone_postpone_reconfigure_zones();
void database_zone_postpone_reconfigure_zone(const ptr_treemap_t *fqdn_set);

/**
 * Queues a function in the thread pool for loading zones
 *
 * @param func
 * @param parm
 * @param counter
 * @param categoryname
 */

void database_service_zone_load_queue_thread(thread_pool_function_t func, void *parm, thread_pool_task_counter_t *counter, const char *categoryname);

/**
 * Queues a function in the thread pool for saving zones
 *
 * @param func
 * @param parm
 * @param counter
 * @param categoryname
 */

void database_service_zone_store_queue_thread(thread_pool_function_t func, void *parm, thread_pool_task_counter_t *counter, const char *categoryname);

/**
 * Queues a function in the thread pool for unloading zones
 *
 * @param func
 * @param parm
 * @param counter
 * @param categoryname
 */

void database_service_zone_unload_queue_thread(thread_pool_function_t func, void *parm, thread_pool_task_counter_t *counter, const char *categoryname);

/**
 * Queues a function in the thread pool for downloading zones
 *
 * @param func
 * @param parm
 * @param counter
 * @param categoryname
 */

void database_service_zone_download_queue_thread(thread_pool_function_t func, void *parm, thread_pool_task_counter_t *counter, const char *categoryname);

void database_service_zone_resignature_queue_thread(thread_pool_function_t func, void *parm, thread_pool_task_counter_t *counter, const char *categoryname);

/**
 * Tells the database service that a zone has been loaded or failed to load.
 * Meant to be used internally.
 *
 * @param zone_desc     the descriptor
 * @param zone          the zone structure that contains the zone (may be NULL)
 * @param result_code   the error code
 */

void database_fire_zone_loaded(zone_desc_t *zone_desc, zdb_zone_t *zone, ya_result result_code);

/**
 * Tells the database service that a zone has been mounted or failed to mount.
 * Meant to be used internally.
 *
 * @param zone_desc     the descriptor
 * @param zone          the zone structure that contains the zone (may be NULL)
 * @param result_code   the error code
 */

void database_fire_zone_mounted(zone_desc_t *zone_desc, zdb_zone_t *zone, ya_result result_code);

/**
 * Tells the database service that a zone has been unloaded.
 * Although there is a result code, it most likely cannot fail with the current implementation.
 * Meant to be used internally.
 *
 * @param zone          a zone to mount in its place
 * @param result_code
 */

void database_fire_zone_unloaded(zdb_zone_t *zone, ya_result result_code);

/**
 * Tells the database service that a zone has been unloaded.
 * Meant to be used internally.
 *
 * @param zone_desc
 */

void database_fire_zone_unmounted(zone_desc_t *zone_desc);

/**
 * Tells the database service that a zone has been downloaded.
 * Meant to be used internally.
 *
 * @param origin
 * @param rtype AXFR/IXFR
 * @param serial the last serial of the zone
 * @param result_code
 */

void database_fire_zone_downloaded(const uint8_t *origin, uint16_t rtype, uint32_t serial, ya_result result_code);

/**
 * Return the name of a command id.  Used for debugging/logging.
 *
 * @param id
 * @return
 */

const char *database_service_operation_get_name(uint32_t id);

/**
 * Triggers a re-signature, should only be used by database-service-zone-resignature
 *
 * @param origin
 * @param expected_zone_desc
 * @param expected_zone
 */

void database_zone_update_signatures(const uint8_t *origin, zone_desc_t *expected_zone_desc, zdb_zone_t *expected_zone);
void database_zone_update_signatures_resume(const uint8_t *origin, zone_desc_t *expected_zone_desc, zdb_zone_t *expected_zone);
void database_zone_update_signatures_allow_queue(const uint8_t *origin, zone_desc_t *expected_zone_desc, zdb_zone_t *expected_zone);
/**
 *
 * Sets an alarm to enqueue a zone maintenance at a given time (best effort)
 *
 * @param zone
 * @param at
 */

void database_zone_update_signatures_at(zdb_zone_t *zone, uint32_t at);

void database_zone_enable_maintenance_and_update_signatures_at(zdb_zone_t *zone, uint32_t at);
/**
 *
 * Creates an empty, invalid zone for every single registered zone descriptor (config)
 *
 */

void database_service_create_invalid_zones();

bool database_service_is_running();

void database_service_run_garbage_collector();

void database_fire_zone_processed(zone_desc_t *zone_desc);

void database_post_callback(database_message_callback_function callback, void *args, const char *const name);

bool database_server_down_cache_query(const host_address_t *ha);
void database_server_down_cache_add(const host_address_t *ha);

/** @} */

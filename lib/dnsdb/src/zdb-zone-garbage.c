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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <dnscore/logger.h>
#include <dnscore/threaded_dll_cw.h>

#include "dnsdb/dnsdb-config.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb-zone-garbage.h"
#define ZDB_JOURNAL_CODE 1 // to be allowed to close it
#include "dnsdb/journal.h"

#if HAS_TRACK_ZONES_DEBUG_SUPPORT
#include <dnscore/ptr_set.h>
#endif

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

union zdb_zone_garbage_run_destroyed_cb_ptr
{
    zdb_zone_garbage_run_destroyed_cb *cb;
    void *ptr;
};

static threaded_dll_cw zone_garbage_queue;

static ptr_vector zdb_zone_garbage_run_destroyed_callbacks = PTR_VECTOR_EMPTY;
static mutex_t zdb_zone_garbage_run_destroyed_callbacks_mtx = MUTEX_INITIALIZER;


#if HAS_TRACK_ZONES_DEBUG_SUPPORT
extern smp_int g_zone_instanciated_count;
extern ptr_set g_zone_instanciated_set;
#endif


void zdb_zone_garbage_run();

static bool zdb_zone_garbage_initialised = FALSE;

void
zdb_zone_garbage_init()
{
    if(!zdb_zone_garbage_initialised)
    {
        threaded_dll_cw_init(&zone_garbage_queue, 0x100000);    // 1M zones
        zdb_zone_garbage_initialised = TRUE;
    }
}

void
zdb_zone_garbage_finalize()
{
    if(zdb_zone_garbage_initialised)
    {
        log_debug("zdb_zone_garbage_finalize: releasing zones ");
        
        zdb_zone_garbage_run();
        
#if HAS_TRACK_ZONES_DEBUG_SUPPORT
        int count;
        if((count = smp_int_get(&g_zone_instanciated_count)) > 0)
        {            
            log_err("zdb_zone_garbage_finalize: there are still %i zones instanciated (leaked?)", count);
            logger_flush();
            
            ptr_set_iterator iter;
            ptr_set_iterator_init(&g_zone_instanciated_set, &iter);

            while(ptr_set_iterator_hasnext(&iter))
            {
                ptr_node *node = ptr_set_iterator_next_node(&iter);
                zdb_zone *zone = (zdb_zone*)node->key;
                log_err("%p: %{dnsname} is referenced %i times",zone, zone->origin, zone->rc);
            }
        }
#endif
    
        threaded_dll_cw_finalize(&zone_garbage_queue);
        
        zdb_zone_garbage_initialised = FALSE;
    }
}

bool
zdb_zone_garbage_collect(zdb_zone *zone)
{
    yassert(zdb_rr_label_is_apex(zone->apex));
    yassert(zone->rc == 0);

#pragma message("add a zone freed callback")

    zdb_rr_label_flag_and(zone->apex, ~ZDB_RR_LABEL_APEX);

#if ZDB_ZONE_HAS_JNL_REFERENCE
    journal *jh = zone->journal; // pointed to, to be closed as the zone is about to be destroyed
    journal_close(jh);
#endif
    
    if(zdb_zone_garbage_initialised)
    {
#if DEBUG
        log_debug("zdb_zone_garbage_collect: queuing zone %{dnsname}@%p for the collector", zone->origin, zone);
#endif
        threaded_dll_cw_enqueue(&zone_garbage_queue, zone);
        return TRUE;
    }
    else
    {
        log_warn("zdb_zone_garbage_collect: collector disabled, destroying zone %{dnsname}@%p now", zone->origin, zone);
#if DEBUG
        logger_flush();
#endif
        zdb_zone_destroy_nolock(zone);
        return FALSE;
    }
}

zdb_zone *
zdb_zone_garbage_get()
{
    if(zdb_zone_garbage_initialised)
    {
        zdb_zone *zone = (zdb_zone*)threaded_dll_cw_try_dequeue(&zone_garbage_queue);
        return zone;
    }
    else
    {
        log_warn("zdb_zone_garbage_get: collector disabled");
        return NULL;
    }
}

bool
zdb_zone_garbage_empty()
{
    return threaded_dll_cw_size(&zone_garbage_queue) == 0;
}

void
zdb_zone_garbage_run()
{
    u8 fqdn[MAX_DOMAIN_LENGTH];

#if DEBUG
    log_debug("zdb_zone_garbage_run (%i)", zdb_zone_garbage_initialised);
#endif

    if(zdb_zone_garbage_initialised)
    {
        bool has_callback = !ptr_vector_isempty(&zdb_zone_garbage_run_destroyed_callbacks);

        while(threaded_dll_cw_size(&zone_garbage_queue) > 0)
        {
            zdb_zone *zone = (zdb_zone*)threaded_dll_cw_try_dequeue(&zone_garbage_queue);

            if(zone != NULL)
            {
                if(has_callback)
                {
                    dnsname_copy(fqdn, zone->origin);
                }
#if DEBUG
                log_debug("zdb_zone_garbage_run: %{dnsname}@%p", zone->origin, zone);
                //logger_flush();
#endif

                zdb_zone_destroy(zone);

                if(has_callback)
                {
                    mutex_lock(&zdb_zone_garbage_run_destroyed_callbacks_mtx);
                    for(int i = 0; i <= ptr_vector_last_index(&zdb_zone_garbage_run_destroyed_callbacks); ++i)
                    {
                        union zdb_zone_garbage_run_destroyed_cb_ptr cb_ptr;
                        cb_ptr.ptr = ptr_vector_get(&zdb_zone_garbage_run_destroyed_callbacks, i);
                        cb_ptr.cb(fqdn);
                    }
                    mutex_unlock(&zdb_zone_garbage_run_destroyed_callbacks_mtx);
                }
            }
        }
    }
    else
    {
        log_warn("zdb_zone_garbage_run: collector disabled");
    }

#if DEBUG
    log_debug("zdb_zone_garbage_run done (%i)", zdb_zone_garbage_initialised);
#endif
}

void
zdb_zone_garbage_run_ex(zdb_zone_garbage_run_cb *destroyer)
{
    u8 fqdn[MAX_DOMAIN_LENGTH];

#if DEBUG
    log_debug("zdb_zone_garbage_run_ex (%i)", zdb_zone_garbage_initialised);
#endif

    if(zdb_zone_garbage_initialised)
    {
        if(destroyer == NULL)
        {
            destroyer = zdb_zone_destroy;
        }

        bool has_callback = !ptr_vector_isempty(&zdb_zone_garbage_run_destroyed_callbacks);
        
        while(threaded_dll_cw_size(&zone_garbage_queue) > 0)
        {
            zdb_zone *zone = (zdb_zone*)threaded_dll_cw_try_dequeue(&zone_garbage_queue);
            if(zone != NULL)
            {
                if(has_callback)
                {
                    dnsname_copy(fqdn, zone->origin);
                }
#if DEBUG
                log_debug("zdb_zone_garbage_run_ex: %{dnsname}", zone->origin);
                //logger_flush();
#endif
                destroyer(zone);

                if(has_callback)
                {
                    mutex_lock(&zdb_zone_garbage_run_destroyed_callbacks_mtx);
                    for(int i = 0; i <= ptr_vector_last_index(&zdb_zone_garbage_run_destroyed_callbacks); ++i)
                    {
                        union zdb_zone_garbage_run_destroyed_cb_ptr cb_ptr;
                        cb_ptr.ptr = ptr_vector_get(&zdb_zone_garbage_run_destroyed_callbacks, i);
                        cb_ptr.cb(fqdn);
                    }
                    mutex_unlock(&zdb_zone_garbage_run_destroyed_callbacks_mtx);
                }
            }
        }
    }
    else
    {
        log_warn("zdb_zone_garbage_run: collector disabled");
    }

#if DEBUG
    log_debug("zdb_zone_garbage_run_ex done (%i)", zdb_zone_garbage_initialised);
#endif
}

void
zdb_zone_garbage_run_callback_add(zdb_zone_garbage_run_destroyed_cb *cb)
{
    mutex_lock(&zdb_zone_garbage_run_destroyed_callbacks_mtx);
    union zdb_zone_garbage_run_destroyed_cb_ptr cb_ptr;
    cb_ptr.cb = cb;
    ptr_vector_append(&zdb_zone_garbage_run_destroyed_callbacks, cb_ptr.ptr);
    mutex_unlock(&zdb_zone_garbage_run_destroyed_callbacks_mtx);
}

void
zdb_zone_garbage_run_callback_remove(zdb_zone_garbage_run_destroyed_cb *cb)
{
    union zdb_zone_garbage_run_destroyed_cb_ptr cb_ptr;
    cb_ptr.cb = cb;
    mutex_lock(&zdb_zone_garbage_run_destroyed_callbacks_mtx);
    for(int i = 0; i <= ptr_vector_last_index(&zdb_zone_garbage_run_destroyed_callbacks); ++i)
    {
        if(cb_ptr.ptr == ptr_vector_get(&zdb_zone_garbage_run_destroyed_callbacks, i))
        {
            ptr_vector_remove_at(&zdb_zone_garbage_run_destroyed_callbacks, i);
            break;
        }
    }
    mutex_unlock(&zdb_zone_garbage_run_destroyed_callbacks_mtx);
}

/** @} */

/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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

#include "dnsdb/dnsdb_config.h"
#include "dnsdb/zdb_config_features.h"

#include <dnscore/ptr_treemap_debug.h>
#include <dnscore/list_dl.h>
#include <dnscore/logger.h>

#include "dnsdb/zdb_zone_lock_monitor.h"

extern logger_handle_t *g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#if ZDB_HAS_LOCK_DEBUG_SUPPORT

#define ZNLCKMNT_TAG 0x544e4d4b434c4e5a

#define log_arc      log_debug6
#define MSG_ARC      MSG_DEBUG6

struct zdb_zone_lock_monitor_s
{
    const zdb_zone_t *zone; // not RCed, this is the key
    // stack trace
    stacktrace trace;
    // thread
    thread_t tid;
    //
    volatile uint8_t owner;
    volatile uint8_t secondary;
    // when
    int64_t timestamp;
    // how many time waited
    volatile int waited;
    // how many are blocked
    volatile int blocks;
    // rc
    atomic_int rc;
};

typedef struct zdb_zone_lock_monitor_s zdb_zone_lock_monitor_t;

static ptr_treemap_debug_t             zdb_zone_arc_set = PTR_TREEMAP_DEBUG_EMPTY;
static mutex_t                         zdb_zone_arc_set_mtx = MUTEX_INITIALIZER;
static mutex_t                         zdb_zone_lock_monitor_mtx = MUTEX_INITIALIZER;
static int64_t                         zdb_zone_lock_set_monitor_last_duration = 0;
static int64_t                         zdb_zone_lock_set_monitor_last_time = 0;
/*
static const char* zdb_zone_lock_names[11]=
{
    "NOBODY",       // 0x00
    "SIMPLEREADER", // 0x01 non-conflicting
    "RRSIG_UPDATER",// 0x82 conflicting
    "3?",
    "XFR",          // 0x84 conflicting
    "REFRESH",      // 0x85 conflicting
    "DYNUPDATE",    // 0x86 conflicting
    "UNFREEZE",     // 0x87 conflicting
    "INVALIDATE",   // 0x88 conflicting
    "REPLACE",      // 0x89 conflicting
    "LOAD"          // 0x8a conflicting
    // "DESTROY"       // 0xFF conflicting, can never be launched more than once.  The zone will be destroyed before
unlock.
};
*/
bool zdb_zone_lock_monitor_release(zdb_zone_lock_monitor_t *holder)
{
    mutex_lock(&zdb_zone_lock_monitor_mtx);
    int rc = --holder->rc;
    mutex_unlock(&zdb_zone_lock_monitor_mtx);
    if(rc > 0)
    {
        return false;
    }
    else
    {
        // do NOT try to free the track trace
        memset(holder, 0xfe, sizeof(zdb_zone_lock_monitor_t));
        free(holder);
        return true;
    }
}

/**
 * RC=2
 *
 * @param zone
 * @return
 */

zdb_zone_lock_monitor_t *zdb_zone_lock_monitor_new(const zdb_zone_t *zone, uint8_t owner, uint8_t secondary)
{
    zdb_zone_lock_monitor_t *holder;
    mutex_lock(&zdb_zone_arc_set_mtx);
    ptr_treemap_node_debug_t *node = ptr_treemap_debug_insert(&zdb_zone_arc_set, (zdb_zone_t *)zone);

    list_dl_s                *list;

    if(node->value != NULL)
    {
        list = (list_dl_s *)node->value;
    }
    else
    {
        list = list_dl_new_instance();
        node->value = list;
    }

    MALLOC_OR_DIE(zdb_zone_lock_monitor_t *, holder, sizeof(zdb_zone_lock_monitor_t), ZNLCKMNT_TAG);
    holder->zone = zone;
    holder->trace = debug_stacktrace_get();
    holder->tid = thread_self();
    holder->owner = owner;
    holder->secondary = secondary;
    holder->timestamp = timeus();
    holder->waited = 0;
    holder->blocks = 0;
    holder->rc = 2;

    list_dl_append(list, holder);

    mutex_unlock(&zdb_zone_arc_set_mtx);

    log_arc("zone-lock: %p %{dnsname}@%p (%02x/%02x): locking", holder->tid, zone->origin, zone, holder->owner, holder->secondary);
    debug_stacktrace_log(g_database_logger, MSG_ARC, holder->trace);

    return holder;
}

/*
 * RC++
 */

zdb_zone_lock_monitor_t *zdb_zone_lock_monitor_get(const zdb_zone_t *zone)
{
    mutex_lock(&zdb_zone_arc_set_mtx);
    ptr_treemap_node_debug_t *node = ptr_treemap_debug_find(&zdb_zone_arc_set, zone);

    if(node != NULL)
    {
        list_dl_s *list = (list_dl_s *)node->value;
        if(list != NULL)
        {
            if(list_dl_size(list) > 0)
            {
                zdb_zone_lock_monitor_t *holder = (zdb_zone_lock_monitor_t *)list_dl_peek_first(list);

                ++holder->rc;

                mutex_unlock(&zdb_zone_arc_set_mtx);

                log_arc("zone-lock: %p %{dnsname}@%p (%02x/%02x): owner for %llu us", holder->tid, zone->origin, zone, holder->owner, holder->secondary, timeus() - holder->timestamp);
                debug_stacktrace_log(g_database_logger, MSG_ARC, holder->trace);

                return holder;
            }
            else
            {
                log_err("zone-lock: ? %{dnsname}@%p: zone has an empty list", zone->origin, zone);
            }
        }
        else
        {
            // weird
            log_err("zone-lock: ? %{dnsname}@%p: zone has no list", zone->origin, zone);
        }
    }
    else
    {
        // weird
        log_err("zone-lock: ? %{dnsname}@%p: zone has no key", zone->origin, zone);
    }

    mutex_unlock(&zdb_zone_arc_set_mtx);
    return NULL;
}

void zdb_zone_lock_monitor_waits(zdb_zone_lock_monitor_t *holder)
{
    if(holder != NULL)
    {
        mutex_lock(&zdb_zone_lock_monitor_mtx);
        int waited = ++holder->waited;
        mutex_unlock(&zdb_zone_lock_monitor_mtx);
        zdb_zone_lock_monitor_t *blocker = zdb_zone_lock_monitor_get(holder->zone);
        if(blocker != NULL)
        {
            mutex_lock(&zdb_zone_lock_monitor_mtx);
            int blocked = ++blocker->blocks;
            mutex_unlock(&zdb_zone_lock_monitor_mtx);

            log_arc("zone-lock: %p %{dnsname}@%p (%02x/%02x): waited %i time(s) for %lluus", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary, waited, timeus() - holder->timestamp);
            debug_stacktrace_log(g_database_logger, MSG_ARC, holder->trace);

            log_arc("zone-lock: %p %{dnsname}@%p (%02x/%02x): blocked %i attempts in a period of %lluus", blocker->tid, blocker->zone->origin, blocker->zone, blocker->owner, blocker->secondary, blocked, timeus() - blocker->timestamp);
            debug_stacktrace_log(g_database_logger, MSG_ARC, blocker->trace);

            zdb_zone_lock_monitor_release(blocker);
        }
        else
        {
            // weird
            log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): should not be waiting (no known reason)", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
        }
    }
    else
    {
        // weird
        log_err("zone-lock: null holder");
    }
}

void zdb_zone_lock_monitor_resumes(zdb_zone_lock_monitor_t *holder)
{
    if(holder != NULL)
    {
        // nothing do do anyway

        log_arc("zone-lock: %p %{dnsname}@%p (%02x/%02x): resumed %i time(s) for %lluus", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary, holder->waited, timeus() - holder->timestamp);
        debug_stacktrace_log(g_database_logger, MSG_ARC, holder->trace);
    }
    else
    {
        // weird
        log_err("zone-lock: null holder");
    }
}

void zdb_zone_lock_monitor_exchanges(zdb_zone_lock_monitor_t *holder)
{
    mutex_lock(&zdb_zone_arc_set_mtx);

    if(holder == NULL)
    {
        log_err("zone-lock: null holder");
        mutex_unlock(&zdb_zone_arc_set_mtx);
        return;
    }

    ptr_treemap_node_debug_t *node = ptr_treemap_debug_find(&zdb_zone_arc_set, holder->zone);

    if(node != NULL)
    {
        list_dl_s *list = (list_dl_s *)node->value;
        if(list != NULL)
        {
            if(list_dl_size(list) > 0)
            {
                mutex_lock(&zdb_zone_lock_monitor_mtx);
                uint8_t o = holder->owner;
                uint8_t s = holder->secondary;
                holder->secondary = o;
                holder->owner = s;
                mutex_unlock(&zdb_zone_lock_monitor_mtx);

                if((holder->owner & 0x80) != 0)
                {
                    zdb_zone_lock_monitor_t *head = (zdb_zone_lock_monitor_t *)list_dl_peek_first(list);

                    if(holder != head)
                    {
                        // move it to the head
                        list_dl_remove(list, holder);
                        list_dl_insert(list, holder);
                    }

                    log_arc("zone-lock: %p %{dnsname}@%p (%02x/%02x): exchanged after %i tries for %lluus", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary, holder->waited, timeus() - holder->timestamp);
                }
                else
                {
                    log_arc(
                        "zone-lock: %p %{dnsname}@%p (%02x/%02x): locked after %i tries for %lluus (shared)", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary, holder->waited, timeus() - holder->timestamp);
                }

                debug_stacktrace_log(g_database_logger, MSG_ARC, holder->trace);

                // no release here
                // zdb_zone_lock_monitor_release(holder);
            }
            else
            {
                log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): is from an empty list", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
            }
        }
        else
        {
            // weird
            log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): no list", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
        }
    }
    else
    {
        // weird
        log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): has no key)", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
    }

    mutex_unlock(&zdb_zone_arc_set_mtx);
}

/*
 * RC--
 */

void zdb_zone_lock_monitor_locks(zdb_zone_lock_monitor_t *holder)
{
    mutex_lock(&zdb_zone_arc_set_mtx);
    ptr_treemap_node_debug_t *node = ptr_treemap_debug_find(&zdb_zone_arc_set, holder->zone);

    if(node != NULL)
    {
        list_dl_s *list = (list_dl_s *)node->value;
        if(list != NULL)
        {
            if(list_dl_size(list) > 0)
            {
                if((holder->owner & 0x80) != 0)
                {
                    zdb_zone_lock_monitor_t *head = (zdb_zone_lock_monitor_t *)list_dl_peek_first(list);

                    if(holder != head)
                    {
                        // move it to the head
                        list_dl_remove(list, holder);
                        list_dl_insert(list, holder);
                    }

                    log_arc("zone-lock: %p %{dnsname}@%p (%02x/%02x): locked after %i tries for %lluus", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary, holder->waited, timeus() - holder->timestamp);
                }
                else
                {
                    log_arc(
                        "zone-lock: %p %{dnsname}@%p (%02x/%02x): locked after %i tries for %lluus (shared)", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary, holder->waited, timeus() - holder->timestamp);
                }

                debug_stacktrace_log(g_database_logger, MSG_ARC, holder->trace);

                zdb_zone_lock_monitor_release(holder);
            }
            else
            {
                log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): is from an empty list", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
            }
        }
        else
        {
            // weird
            log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): no list", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
        }
    }
    else
    {
        // weird
        log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): has no key)", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
    }

    mutex_unlock(&zdb_zone_arc_set_mtx);
}

/*
 * RC -= 2
 */

void zdb_zone_lock_monitor_cancels(zdb_zone_lock_monitor_t *holder)
{
    mutex_lock(&zdb_zone_arc_set_mtx);
    ptr_treemap_node_debug_t *node = ptr_treemap_debug_find(&zdb_zone_arc_set, holder->zone);

    if(node != NULL)
    {
        list_dl_s *list = (list_dl_s *)node->value;
        if(list != NULL)
        {
            if(list_dl_size(list) > 0)
            {
                log_arc("zone-lock: %p %{dnsname}@%p (%02x/%02x): cancelled after %i tries for %lluus", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary, holder->waited, timeus() - holder->timestamp);
                debug_stacktrace_log(g_database_logger, MSG_ARC, holder->trace);

                bool deleted = false;
                if(list_dl_remove(list, holder))
                {
                    deleted = zdb_zone_lock_monitor_release(holder);
                    yassert(list_dl_indexof(list, holder) < 0);
                }

                if(!deleted)
                {
                    zdb_zone_lock_monitor_release(holder);
                    yassert(list_dl_indexof(list, holder) < 0);
                }
                else
                {
                    // weird
                }
            }
            else
            {
                log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): is from an empty list", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
            }
        }
        else
        {
            // weird
            log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): no list", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
        }
    }
    else
    {
        // weird
        log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): has no key)", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
    }

    mutex_unlock(&zdb_zone_arc_set_mtx);
}

/*
 * RC -= 2
 */

void zdb_zone_lock_monitor_unlocks(zdb_zone_lock_monitor_t *holder)
{
    if(holder == NULL)
    {
        log_err("zone-lock: unlocking NULL");
        return;
    }

    mutex_lock(&zdb_zone_arc_set_mtx);
    ptr_treemap_node_debug_t *node = ptr_treemap_debug_find(&zdb_zone_arc_set, holder->zone);

    if(node != NULL)
    {
        list_dl_s *list = (list_dl_s *)node->value;
        if(list != NULL)
        {
            if(list_dl_size(list) > 0)
            {
                log_arc(
                    "zone-lock: %p %{dnsname}@%p (%02x/%02x): unlocked after blocking %i others for %lluus, zone is "
                    "(%02x/%02x+%3i)",
                    holder->tid,
                    holder->zone->origin,
                    holder->zone,
                    holder->owner,
                    holder->secondary,
                    holder->blocks,
                    timeus() - holder->timestamp,
                    holder->zone->lock_owner,
                    holder->zone->lock_reserved_owner,
                    holder->zone->lock_count);
                debug_stacktrace_log(g_database_logger, MSG_ARC, holder->trace);

                bool deleted = false;
                if(list_dl_remove(list, holder))
                {
                    deleted = zdb_zone_lock_monitor_release(holder);
                    yassert(list_dl_indexof(list, holder) < 0);
                }

                if(!deleted)
                {
                    zdb_zone_lock_monitor_release(holder);
                    yassert(list_dl_indexof(list, holder) < 0);
                }
                else
                {
                    // weird
                    log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): bogus RC", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
                }
            }
            else
            {
                log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): is from an empty list", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
            }
        }
        else
        {
            // weird
            log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): no list", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
        }
    }
    else
    {
        // weird
        log_err("zone-lock: %p %{dnsname}@%p (%02x/%02x): has no key)", holder->tid, holder->zone->origin, holder->zone, holder->owner, holder->secondary);
    }

    mutex_unlock(&zdb_zone_arc_set_mtx);
}

void zdb_zone_lock_monitor_log()
{
    int64_t now = timeus();

    if((now - zdb_zone_lock_set_monitor_last_time) < zdb_zone_lock_set_monitor_last_duration)
    {
        return;
    }

    zdb_zone_lock_set_monitor_last_time = now;

    mutex_lock(&zdb_zone_arc_set_mtx);

    ptr_treemap_debug_iterator_t iter;
    ptr_treemap_debug_iterator_init(&zdb_zone_arc_set, &iter);

    while(ptr_treemap_debug_iterator_hasnext(&iter))
    {
        ptr_treemap_node_debug_t *node = ptr_treemap_debug_iterator_next_node(&iter);

        list_dl_s                *list = (list_dl_s *)node->value;
        if(list != NULL)
        {
            if(list_dl_size(list) > 0)
            {
                list_dl_iterator_s listiter;
                list_dl_iterator_init(list, &listiter);

                if(list_dl_iterator_has_next(&listiter))
                {
                    zdb_zone_lock_monitor_t *locker = (zdb_zone_lock_monitor_t *)list_dl_iterator_next(&listiter);

                    int64_t                  duration = timeus() - locker->timestamp;
                    const char              *toolong = (duration >= MUTEX_LOCKED_TOO_MUCH_TIME_US) ? ", which is too long" : "";

                    log_arc("zone-lock: lock: %p %{dnsname}@%p (%02x/%02x): blocked %i attempts in a period of %lluus%s",
                            locker->tid,
                            locker->zone->origin,
                            locker->zone,
                            locker->owner,
                            locker->secondary,
                            locker->blocks,
                            timeus() - locker->timestamp,
                            toolong);
                    debug_stacktrace_log(g_database_logger, MSG_ARC, locker->trace);

                    while(list_dl_iterator_has_next(&listiter))
                    {
                        zdb_zone_lock_monitor_t *holder = (zdb_zone_lock_monitor_t *)list_dl_iterator_next(&listiter);
                        duration = timeus() - locker->timestamp;
                        toolong = (duration >= MUTEX_LOCKED_TOO_MUCH_TIME_US) ? ", which is too long" : "";

                        log_arc("zone-lock: wait: %p %{dnsname}@%p (%02x/%02x): waited %i time(s) for %lluus",
                                holder->tid,
                                holder->zone->origin,
                                holder->zone,
                                holder->owner,
                                holder->secondary,
                                holder->waited,
                                timeus() - holder->timestamp,
                                toolong);
                        debug_stacktrace_log(g_database_logger, MSG_ARC, holder->trace);
                    }
                }
            }
        }
    }

    mutex_unlock(&zdb_zone_arc_set_mtx);

    int64_t after = timeus();
    if((after - now) > zdb_zone_lock_set_monitor_last_duration)
    {
        zdb_zone_lock_set_monitor_last_duration = after - now;
    }
}

#endif

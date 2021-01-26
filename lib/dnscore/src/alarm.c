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

/** @defgroup alarm
 *  @ingroup dnscore
 *  @brief Alarm functions
 *
 * @{
 */

#include <dnscore/timems.h>
#include "dnscore/dnscore-config.h"
#include "dnscore/logger.h"
#include "dnscore/alarm.h"
#include "dnscore/mutex.h"
#include "dnscore/zalloc.h"
#if DEBUG
#include "dnscore/timeformat.h"
#endif // DEBUG

#define HAS_ALARM_DUMP 0

#define MODULE_MSG_HANDLE g_system_logger

/*
 * List of events (double-linked), sorted by epoch (then insersion time).
 * Array of handles (expandable), with the list of events they hold. (so they can easily be foud by id and closed)
 * 
 * The descriptions are stored in both collections. (two double-linked structures)
 *
 * TIMELIST->[TIME#0]->[TIME#1]->...->[TIME#n]
 *              |         |
 *              v       [NODE]
 * HNDLLIST->[NODE]--+    |
 *                   +->[NODE]-- ...
 */

#define ALARM_NODE_LIST_TAG 0x5453494c4d524c41
#define ALARM_NODE_DESC_TAG 0x4353444e4d524c41
#define ALARM_NODE_TIME_TAG 0x454d49544d524c41
#define ALARM_HANDLE_TAG    0x4c444e484d524c41

struct alarm_event_list
{
    alarm_event_node *first;
    alarm_event_node *last;
};

typedef struct alarm_event_list alarm_event_list;

struct alarm_handle
{
    alarm_event_list events; // events for that handle
    const u8 *owner_dnsname;
};

typedef struct alarm_handle alarm_handle;

struct alarm_time_node
{
    struct alarm_time_node *next;
    alarm_event_list events;
    u32 epoch;
};

typedef struct alarm_time_node alarm_time_node;

static ptr_vector alarm_handles = PTR_VECTOR_EMPTY;
static alarm_time_node doomsday = { NULL, {NULL, NULL}, MAX_U32 }; // nothing after this point
static alarm_time_node time_list = { &doomsday, {NULL, NULL}, 0 };
static mutex_t alarm_mutex = MUTEX_INITIALIZER;
static int alarm_handles_next_free = -1;
#if DEBUG
static volatile bool alarm_mutex_locked = FALSE;
static volatile u32 alarm_event_in_handles_count = 0;
static volatile u32 alarm_event_in_time_count = 0;
static volatile u32 alarm_event_alarm_set_count = 0;
static smp_int alarm_event_instanciated = SMP_INT_INITIALIZER;
#endif

static void alarm_handle_close(alarm_handle *handle_struct);

/**/

#if HAS_ALARM_DUMP
void alarm_log_dump_nolock(bool check);
void alarm_log_dump();
#endif

struct timespec __alarm__approximate_time_10s = { 0, 0 };
struct timespec __alarm__approximate_time_30s = { 0, 0 };

/**
 * Allocates an uninitialised event node.
 * 
 * @return 
 */

static alarm_event_node *
alarm_event_alloc()
{
    alarm_event_node *node;
    ZALLOC_OBJECT_OR_DIE(node, alarm_event_node, ALARM_NODE_DESC_TAG);

#if DEBUG
    memset(node, 0xac,sizeof(alarm_event_node));
    int total = smp_int_inc_get(&alarm_event_instanciated);
    log_debug6("alarm_event_alloc(%p) (total=%d)", node, total);
#endif
    
    return node;
}

/**
 * Instanciates an event node
 * 
 * @param epoch
 * @param key
 * @param function
 * @param args
 * @param flags
 * @param text
 * @return 
 */

alarm_event_node*
alarm_event_new(
    u32 epoch,
    u32 key,
    alarm_function_callback *function,
    void *args,
    u8 flags,
    const char *text)    
{
    alarm_event_node *event = alarm_event_alloc();
    event->epoch = epoch;
    event->key = key;
    event->function = function;
    event->args = args;
    
    event->flags = flags;
    event->text = text;
    
#if DEBUG
    int total = smp_int_get(&alarm_event_instanciated);
    log_debug6("alarm_event_new(%p %08x '%s' %T) (total=%d)", event, event->key, event->text, event->epoch, total);
#endif
    
    return event;
}

/**
 * Destroys an event node
 * 
 * @param node
 */

void
alarm_event_free(alarm_event_node *node)
{
#if DEBUG
    int total = smp_int_dec_get(&alarm_event_instanciated);
    log_debug6("alarm_event_free(%p %08x '%s' %T) (total=%d)", node, node->key, node->text, node->epoch, total);
    memset(node, 0xfe,sizeof(alarm_event_node));
#endif
    ZFREE_OBJECT(node);
}

static void
alarm_event_list_init(alarm_event_list *head)   
{
    head->first = alarm_event_alloc();
    head->last = head->first;
    ZEROMEMORY(head->first, sizeof(alarm_event_node));
#if DEBUG
    head->first->text = "ALARM EVENT LIST SENTINEL";
#endif
}

static void
alarm_event_list_finalize(alarm_event_list *head)
{
    if(head->first != NULL && head->first == head->last)
    {
        alarm_event_free(head->first);
        head->first = NULL;
        head->last = NULL;
    }
#if DEBUG
    else
    {
        log_warn("alarm_event_list_finalize called on an non-empty list");
    }
#endif
}

static bool
alarm_event_list_isempty(alarm_event_list *head)
{
    assert(alarm_mutex_locked);
    
    return head->first == head->last;
}

static alarm_event_node *
alarm_event_list_removefirst(alarm_event_list *time_event)
{
    assert(alarm_mutex_locked);
    assert(!alarm_event_list_isempty(time_event));
    assert((time_event->first != NULL) && (time_event->last != NULL));
    
    // prerequisite: (time node) list is not empty
    
    // detach from the (time node) list

    alarm_event_node *time_node = time_event->first;
    time_event->first = time_node->time_next;
    time_event->first->time_prev = NULL;
    
#if DEBUG
    --alarm_event_in_time_count;
#endif

    assert(time_node->hndl_next != NULL);
    
    // detach from the handle list

    if(time_node->hndl_prev != NULL)
    {
        // in the middle of the list : easy
        time_node->hndl_prev->hndl_next = time_node->hndl_next;
    }
    else
    {
        // at the beginning of the list : have to find the list first
        alarm_event_list *handler_list = ptr_vector_get(&alarm_handles, time_node->handle);
        handler_list->first = time_node->hndl_next;
    }
        
    /* if(node->hndl_next != NULL) There is at least the sentinel */
    
    time_node->hndl_next->hndl_prev = time_node->hndl_prev;
    
#if DEBUG
    
    time_node->hndl_next = (alarm_event_node*)~0;
    time_node->hndl_prev = (alarm_event_node*)~0;
    
    time_node->time_next = (alarm_event_node*)~0;
    time_node->time_prev = (alarm_event_node*)~0;
    
    --alarm_event_in_handles_count;
#endif
    
#if DEBUG
    log_debug6("alarm_event_list_removefirst(%p %08x '%s' %T)", time_node, time_node->key, time_node->text, time_node->epoch);
#endif

    return time_node;
}

/*
 * Append at end.
 */

static void
alarm_event_append(alarm_event_list *handle_list, alarm_event_list *time_list, alarm_event_node *node)
{
    assert(alarm_mutex_locked);
    
    /*
     * List not empty ?
     */
    
#if DEBUG
    log_debug6("alarm_event_append(%p,%p,%p %08x '%s' %T)", handle_list, time_list, node, node->key, node->text, node->epoch);
#endif
    
    if(handle_list->first != handle_list->last)
    {
        /*
         * Insert the node before the last one.
         */
        
        handle_list->last->hndl_prev->hndl_next = node;    // BL ->N   L
        node->hndl_prev = handle_list->last->hndl_prev;    // BL<->N   L

        handle_list->last->hndl_prev = node;               // BL<->N<- L
        node->hndl_next = handle_list->last;               // BL<->N<->L
    }
    else
    {
        handle_list->first = node;                         // F = N   L
        node->hndl_next = handle_list->last;               //   ->F ->L
        handle_list->last->hndl_prev = node;               //   ->F<->L
        node->hndl_prev = NULL;                     // 0<->F<->L
    }
    
#if DEBUG
    ++alarm_event_in_handles_count;
#endif
    
    if(time_list->first != time_list->last)
    {
        time_list->last->time_prev->time_next = node;
        node->time_prev = time_list->last->time_prev;

        time_list->last->time_prev = node;
        node->time_next = time_list->last;
    }
    else
    {
        time_list->first = node;
        node->time_next = time_list->last;
        time_list->last->time_prev = node;
        node->time_prev = NULL;
    }
    
#if DEBUG
    ++alarm_event_in_time_count;
#endif
}

/**
 * Removes the node from both the handle list and the time list.
 * Does not releases memory.
 * 
 * @param handle_list
 * @param time_list
 * @param node
 */

static void
alarm_event_remove(alarm_event_list *handle_list, alarm_event_list *time_list, alarm_event_node *node)
{
    assert(alarm_mutex_locked);
    assert(time_list != NULL);
    assert(node != NULL);
    
#if DEBUG
    log_debug6("alarm_event_remove(%p,%p,%p %08x '%s' %T)", handle_list, time_list, node, node->key, node->text, node->epoch);
#endif
    
    if(node->hndl_prev != NULL)                             // A<- N<->B ?
    {
        node->hndl_prev->hndl_next = node->hndl_next;       // N<--N<->B
    }
    else
    {
        handle_list->first = node->hndl_next;                      // F = N<->B
    }
    
    node->hndl_next->hndl_prev = node->hndl_prev;           // 0/A<-?B
    
#if DEBUG
    --alarm_event_in_handles_count;
#endif    

    if(node->time_prev != NULL)
    {
        node->time_prev->time_next = node->time_next;
    }
    else
    {
        time_list->first = node->time_next;
        // scan-build false positive : time cannot be null because the call
        // that provides the value only gives a null for non-existing nodes
        // AND the call is made using an existing node (not null).
    }

    node->time_next->time_prev = node->time_prev;
    
#if DEBUG
    
    node->hndl_next = (alarm_event_node*)~0;
    node->hndl_prev = (alarm_event_node*)~0;
    
    node->time_next = (alarm_event_node*)~0;
    node->time_prev = (alarm_event_node*)~0;
    
    --alarm_event_in_time_count;
#endif    

}

static alarm_time_node *
alarm_time_alloc()
{
    alarm_time_node *time_node;
    ZALLOC_OBJECT_OR_DIE(time_node, alarm_time_node, ALARM_NODE_TIME_TAG);

#if DEBUG
    memset(time_node, 0xf0,sizeof(alarm_time_node));
    log_debug6("alarm_time_alloc() = %p", time_node);
#endif

    assert(alarm_mutex_locked);
    
    alarm_event_list_init(&time_node->events); /* newly allocated : NO LOCK */

    /* node->next : for the caller */
    return time_node;
}

static void
alarm_time_free(alarm_time_node *time_node)
{
    assert(alarm_mutex_locked);
    assert(time_node->events.first == time_node->events.last);
#if DEBUG
    log_debug6("alarm_time_free(%p)", time_node);
    
    alarm_event_list_finalize(&time_node->events);
    
    memset(time_node, 0xfe,sizeof(alarm_time_node));
#endif
    ZFREE_OBJECT(time_node);
}

/*
 * Get the time node for the exact epoch ...
 */

static alarm_time_node *
alarm_time_get(u32 epoch)
{
    assert(alarm_mutex_locked);
    assert(epoch != MAX_U32);

    alarm_time_node *time_node = time_list.next;

    while(time_node->epoch < epoch)
    {
        time_node = time_node->next;
    }

    if(time_node->epoch == epoch)
    {
#if DEBUG
        log_debug6("alarm_time_get(%T) = %p", epoch, time_node);
#endif
        return time_node;
    }
    else
    {
#if DEBUG
        log_debug6("alarm_time_get(%T) = %p", epoch, NULL);
#endif
        return NULL;
    }
}

static alarm_time_node *
alarm_time_create(u32 epoch)
{
    assert(alarm_mutex_locked);

    assert(epoch != MAX_U32);
    if(epoch == 0)

    {
        epoch = time(NULL);
    }
        
    alarm_time_node *time_prev = &time_list;
    alarm_time_node *time_node = time_list.next;
    
    // find a node at or after the one we need

    while(time_node->epoch < epoch)
    {
        time_prev = time_node;
        time_node = time_node->next;
        
        assert(time_node->epoch > time_prev->epoch);
    }

    // if it's a match, return it

    if(time_node->epoch == epoch)
    {
#if DEBUG
        log_debug6("alarm_time_create(%T) = %p", epoch, time_node);
#endif

        return time_node;
    }
    else // else insert a node just after it
    {

        alarm_time_node *new_time_node = alarm_time_alloc();
        time_prev->next = new_time_node;
        new_time_node->next = time_node;
        new_time_node->epoch = epoch;

#if DEBUG
        log_debug6("alarm_time_create(%T) = %p", epoch, new_time_node);
#endif

        return new_time_node;
    }
}

void
alarm_init()
{
    if(ptr_vector_size(&alarm_handles) == 0)
    {
        ptr_vector_resize(&alarm_handles, 64);

        alarm_event_list_init(&time_list.events); /* init: NO LOCK */

        s32 now_s = time(NULL);
        now_s += 10;
        __alarm__approximate_time_10s.tv_sec = now_s;
        now_s += 20;
        __alarm__approximate_time_30s.tv_sec = now_s;
    }
}

void
alarm_finalize()
{
    ptr_vector to_close = PTR_VECTOR_EMPTY;
    mutex_lock(&alarm_mutex);
#if DEBUG
    alarm_mutex_locked = TRUE;
    
    log_debug("alarm: %u handles, %u times, %u sets, %i events",
            alarm_event_in_handles_count,
            alarm_event_in_time_count,
            alarm_event_alarm_set_count,
            smp_int_get(&alarm_event_instanciated));
#endif

    if(ptr_vector_size(&alarm_handles) > 0) // guarantees ptr_vector_last_index(&alarm_handles); is >= 0
    {
        intptr alarm_handles_last_index = (intptr)ptr_vector_last_index(&alarm_handles);
        for(intptr i = 0; i <= alarm_handles_last_index; ++i)
        {
            alarm_handle *handle_struct = (alarm_handle*)ptr_vector_get(&alarm_handles, i);

            if(((intptr)handle_struct > alarm_handles_last_index) && ((intptr)handle_struct != (intptr)ALARM_HANDLE_INVALID))
            {
#if DEBUG
                log_err("alarm: handle %i was not closed at shutdown", i);
#else
                log_debug("alarm: handle %i was not closed at shutdown", i);
#endif
                ptr_vector_append(&to_close, handle_struct);
            }
        }
        
        mutex_unlock(&alarm_mutex);    
        
        for(int i = 0; i <= ptr_vector_last_index(&to_close); ++i)
        {
            alarm_handle *handle_struct = (alarm_handle*)ptr_vector_get(&to_close, i);
            alarm_handle_close(handle_struct);
        }
        
        mutex_lock(&alarm_mutex);
        
        if(alarm_event_list_isempty(&time_list.events))
        {
            alarm_event_list_finalize(&time_list.events);
        }
        else
        {
            log_debug("alarm: event list not empty");
        }
    }
    
    ptr_vector_destroy(&alarm_handles);

#if DEBUG
    alarm_mutex_locked = FALSE;
#endif
    mutex_unlock(&alarm_mutex);    
}

alarm_t
alarm_open(const u8 *owner_dnsname)
{
    alarm_handle *handle_struct;
    ZALLOC_OBJECT_OR_DIE(handle_struct, alarm_handle, ALARM_HANDLE_TAG);

#if DEBUG
    memset(handle_struct, 0xac, sizeof(alarm_handle));
#endif

    alarm_event_list_init(&handle_struct->events); /* newly allocated: NO LOCK */
    handle_struct->owner_dnsname = owner_dnsname;

    mutex_lock(&alarm_mutex);
#if DEBUG
    alarm_mutex_locked = TRUE;
#endif
    
    intptr h;
    
    if(alarm_handles_next_free >= 0)
    {
        h = (intptr)alarm_handles_next_free;    // unsigned value
        // get the next one if any
        alarm_handles_next_free = (intptr)ptr_vector_get(&alarm_handles, h);
        ptr_vector_set(&alarm_handles, (intptr)h, handle_struct);
    }
    else
    {    
        ptr_vector_append(&alarm_handles, handle_struct);
        h = (intptr)alarm_handles.offset;
    }
    
#if DEBUG
    alarm_mutex_locked = FALSE;
#endif
    mutex_unlock(&alarm_mutex);

    log_debug("alarm_open(%{dnsname}) opened alarm with handle %x", handle_struct->owner_dnsname, (int)h);
    
    return (alarm_t)h;
}

static alarm_handle *
alarm_get_struct_from_handle(alarm_t hndl)
{
    assert(alarm_mutex_locked);
    
    if((hndl > alarm_handles.offset) || (hndl < 0))
    {
        /* ERROR ! */

#if DEBUG
        log_debug("invalid alarm handle: %x", hndl);
#endif

        return NULL;
    }

    alarm_handle *handle_struct = ptr_vector_get(&alarm_handles, hndl);

    return handle_struct;
}

static void
alarm_clear_struct_from_handle(alarm_t hndl)
{
    assert(alarm_mutex_locked);
    
    if((hndl > alarm_handles.offset) || (hndl < 0))
    {
        /* ERROR ! */

#if DEBUG
        log_debug("invalid alarm handle: %x", hndl);
#endif

        return;
    }
    
    ptr_vector_set(&alarm_handles, hndl, (void*)(intptr)alarm_handles_next_free);
    alarm_handles_next_free = (intptr)hndl;
}

static void
alarm_handle_close(alarm_handle *handle_struct)
{    
    alarm_event_node *node = handle_struct->events.first;
#if DEBUG
#if HAS_ALARM_DUMP
    alarm_log_dump_nolock(FALSE);
#endif
    u32 removed_events = 0;
#endif
    
    bool obsolete_times = FALSE;

    while(node != NULL)
    {   
        alarm_event_node *node_next = node->hndl_next;
        
        alarm_time_node *time_node = alarm_time_get(node->epoch);
        
        if(time_node != NULL)
        {
            alarm_event_list *time_list = &time_node->events;

            alarm_event_remove(&handle_struct->events, time_list, node);
            
            if(alarm_event_list_isempty(&time_node->events))
            {
                obsolete_times = TRUE;
            }
            
#if DEBUG
            ++removed_events;
#endif
        }
        
        if(node->function != NULL)
        {
            node->function(node->args, TRUE);
        }
        
        alarm_event_free(node);
        
        node = node_next;
    }
    
    // clear the obsolete times
    
#if DEBUG
#if HAS_ALARM_DUMP
    alarm_log_dump_nolock(FALSE);
#endif
#endif
    
    if(obsolete_times)
    {
        
        alarm_time_node *time_node_prev = &time_list;
        alarm_time_node *time_node = time_node_prev->next;
        
        while(time_node->next != NULL)
        {
            if(!alarm_event_list_isempty(&time_node->events))
            {
                time_node_prev = time_node;
                time_node = time_node->next;
            }
            else
            {
                time_node_prev->next = time_node->next;                
                alarm_time_free(time_node);
                time_node = time_node_prev->next;
            }
        }
    }
    
#if DEBUG
    log_debug("alarm_handle_close(%p) removed %u events for %{dnsname}",
            handle_struct,
            removed_events,
            handle_struct->owner_dnsname);

    memset(handle_struct, 0xe4, sizeof(alarm_event_list));
    
#if HAS_ALARM_DUMP
    alarm_log_dump_nolock(FALSE);
#endif
#endif

    ZFREE_OBJECT(handle_struct);
}

void 
alarm_close(alarm_t hndl)
{
    if(hndl == ALARM_HANDLE_INVALID)
    {
        return;
    }
    
   mutex_lock(&alarm_mutex);    
    
#if DEBUG
    alarm_mutex_locked = TRUE;
#endif
    alarm_handle *handle_struct = alarm_get_struct_from_handle(hndl);
    
    if(handle_struct == NULL)
    {
#if DEBUG
        alarm_mutex_locked = FALSE;
#endif
        mutex_unlock(&alarm_mutex);
        
        log_err("alarm_close(%x) invalid alarm handle", hndl);

        return;
    }
    
    log_debug("alarm_close(%x) closing alarm for %{dnsname}", hndl, handle_struct->owner_dnsname);

    alarm_handle_close(handle_struct);
    
    alarm_clear_struct_from_handle(hndl);
    
#if DEBUG
    alarm_mutex_locked = FALSE;
#endif
    
    mutex_unlock(&alarm_mutex);
}

void
alarm_set(alarm_t hndl, alarm_event_node *desc)
{
    mutex_lock(&alarm_mutex);
    
#if DEBUG
    alarm_mutex_locked = TRUE;
    ++alarm_event_alarm_set_count;
#endif

    // get the handle struct, if it exists
    
    alarm_handle *handle_struct = alarm_get_struct_from_handle(hndl);
    
    if(handle_struct == NULL)
    {
        
#if DEBUG
        alarm_mutex_locked = FALSE;
#endif

        mutex_unlock(&alarm_mutex);

        log_err("alarm_set(%p,%x = '%s') invalid alarm handle", hndl, desc, STRNULL(desc->text));
        
        return;
    }

    if(desc->epoch == MAX_U32)
    {

#if DEBUG
        alarm_mutex_locked = FALSE;
#endif

        mutex_unlock(&alarm_mutex);

        log_debug("alarm_set(%p,%x = '%s') alarm set for doomsday.", hndl, desc, STRNULL(desc->text));
        
        return;
    }
    
    alarm_event_list *head = &handle_struct->events;

#if DEBUG
    log_debug("alarm_set: %p: at %T, for '%{dnsname}' call key=%x '%s', %p(%p) (call #%i)", desc, desc->epoch, handle_struct->owner_dnsname, desc->key, STRNULL(desc->text), desc->function, desc->args, alarm_event_alarm_set_count);
#endif

    if(desc->flags != ALARM_DUP_NOP)
    {
        /* Cleanup first */

        if(desc->flags == ALARM_DUP_REMOVE_EARLIER)
        {
            alarm_event_node* node = head->first;
            
            while(node != head->last)
            {
                /// the list is not sorted by time, as in practice there are relatively few events registered by handle
                
                if(node->key == desc->key)
                {
                    log_debug("alarm_set: %p: dropping earliest dup", desc);
                    
                    if(desc->epoch < node->epoch)
                    {
                        /* desc is earlier : cancel and destroy */

                        if(desc->function != NULL)
                        {
                            desc->function(desc->args, TRUE);
                        }
                        
                        alarm_event_free(desc);

#if DEBUG
                        alarm_mutex_locked = FALSE;
#endif
                        
                        mutex_unlock(&alarm_mutex);
                        
                        return;
                    }

                    alarm_event_node *node_next = node->hndl_next;
                    
                    alarm_time_node *events_node_at_epoch = alarm_time_get(node->epoch);
#if DEBUG
                    log_debug6("about to alarm_event_remove(%p,%p,%p %08x '%s' %T) (earlier)", hndl, &events_node_at_epoch->events, node, node->key, node->text, node->epoch);
#endif
                    yassert(events_node_at_epoch != NULL);
                    alarm_event_remove(head, &events_node_at_epoch->events, node);
                    
                    // cancel the event
                    node->function(node->args, TRUE);
                    ZFREE_OBJECT(node);
                    node = node_next;
                }
                else
                {
                    node = node->hndl_next;
                }
            }
        }
        else
        {
            alarm_event_node* node = head->first;
            while(node != head->last)
            {
                if(node->key == desc->key)
                {
#if DEBUG
                    log_debug("alarm_set: %p: dropping latest dup", desc);
#endif
                    if(desc->epoch > node->epoch)
                    {
                        /* desc is later */

                        if(desc->function != NULL)
                        {
                            desc->function(desc->args, TRUE);
                        }
                        alarm_event_free(desc);

#if DEBUG
                        alarm_mutex_locked = FALSE;
#endif
                        
                        mutex_unlock(&alarm_mutex);

                        return;
                    }
                    
                    alarm_event_node *node_next = node->hndl_next;
                    alarm_time_node *events_node_at_epoch = alarm_time_get(node->epoch);
#if DEBUG
                    log_debug6("alarm_set: about to alarm_event_remove(%p,%p,%p %08x '%s' %T) (latest)", head, &events_node_at_epoch->events, node, node->key, node->text, node->epoch);
#endif
                    yassert(events_node_at_epoch != NULL);
                    alarm_event_remove(head, &events_node_at_epoch->events, node);
                    
                    // cancel the event
                    node->function(node->args, TRUE);
                    ZFREE_OBJECT(node);
                    node = node_next;
                }
                else
                {
                    node = node->hndl_next;
                }
            }
        }
    }

#if DEBUG
    log_debug("alarm_set: %p: added", desc);
#endif

    /* Create/get the time head */

    alarm_time_node *time_node = alarm_time_create(desc->epoch);

    /* Link desc at the end of time list and in the hndl list */

    desc->handle = hndl;
    alarm_event_append(head, &time_node->events, desc);

#if DEBUG
    alarm_mutex_locked = FALSE;
#endif
    
    mutex_unlock(&alarm_mutex);
}

void
alarm_run_tick(u32 epoch)
{
    assert(epoch != MAX_U32);
    
    mutex_lock(&alarm_mutex);
    
#if DEBUG
    alarm_mutex_locked = TRUE;
#endif

#if DEBUG
#if HAS_ALARM_DUMP
    alarm_log_dump_nolock(TRUE);
#endif
#endif
    s32 now_s;
    s64 fetch_start = timeus_and_s(&now_s);
    s32 event_count = 0;

    now_s += 10;
    __alarm__approximate_time_10s.tv_sec = now_s;
    now_s += 20;
    __alarm__approximate_time_30s.tv_sec = now_s;

    // while the time node is in the past or the present
    
    alarm_event_node event_dummy;
    alarm_event_node *event_stack = &event_dummy;
    
    for(;;)
    {
        // detach the node
        
        alarm_time_node *time_node = time_list.next;
                
        if(time_node->epoch > epoch)
        {
            break;
        }
        
        time_list.next = time_node->next;
        
        // while there are events in the time node
                
        while(!alarm_event_list_isempty(&time_node->events))
        {
            // process all the events at that time
            
            // take the next event of the time node
            alarm_event_node *event = alarm_event_list_removefirst(&time_node->events);
            
            event_stack->time_next = event;
            event_stack = event;
            
            ++event_count;
        }
        
        yassert(time_node->events.first->time_prev == NULL);
        yassert(time_node->events.last->time_next == NULL);
        yassert(time_node->events.first == time_node->events.last);
        
#if DEBUG
        log_debug("alarm: releasing time node %d@%p, next time node is %d@%p",
                time_node->epoch, time_node,
                time_node->next->epoch, time_node->next
                );
#endif
        
        alarm_time_free(time_node);
    }
    
    s64 fetch_stop = timeus();
    
    double fetch_delta_ms = (double)(fetch_stop - fetch_start);
    fetch_delta_ms /= 1000.0;
    
    log_debug("alarm: fetched %u events in %.3fms", event_count, fetch_delta_ms);
    
    event_stack->time_next = NULL;
    
    // event_dummy is the head of all events to execute
    
    s64 total_run = 0;
    
#if DEBUG
#if HAS_ALARM_DUMP
    alarm_log_dump_nolock(TRUE);
    alarm_mutex_locked = FALSE;
#endif
#endif
    
    mutex_unlock(&alarm_mutex);
    
    ptr_vector rearm = PTR_VECTOR_EMPTY;
    
    for(alarm_event_node *event = event_dummy.time_next; event != NULL; )
    {
#if 1
        if(!dnscore_shuttingdown())
        {
#endif
            /* EXECUTE EVENT */

            log_debug("alarm: '%s': %p: %p(%p) running (expected for %T)", event->text, event, event->function, event->args, event->epoch);

            s64 event_run_start = timeus();

            ya_result ret = event->function(event->args, FALSE);

            s64 event_run_stop = timeus();

            total_run += event_run_stop - event_run_start;
            double event_run_delta_ms = (double)(event_run_stop - event_run_start);
            event_run_delta_ms /= 1000.0;

            log_debug("alarm: '%s': %p: %p(%p) returned %r (%.3fms elapsed)", event->text, event, event->function, event->args, ret, event_run_delta_ms);

            alarm_event_node *event_time_next;

            if(ret == ALARM_REARM)
            {
                ptr_vector_append(&rearm, event);
                event_time_next = event->time_next;
            }
            else
            {        
                event_time_next = event->time_next;
                alarm_event_free(event);
            }
            
            event = event_time_next;
        }
        else
        {
            alarm_event_node *event_time_next = event->time_next;
                        
            log_debug("alarm: '%s': %p: %p(%p): cancelling (expected for %T)", event->text, event, event->function, event->args, event->epoch);
            
            s64 event_run_start = timeus();
            ya_result ret = event->function(event->args, TRUE);
            s64 event_run_stop = timeus();
            
            total_run += event_run_stop - event_run_start;
            double event_run_delta_ms = (double)(event_run_stop - event_run_start);
            event_run_delta_ms /= 1000.0;
            
            log_debug("alarm: '%s': %p: %p(%p) cancelled %r (%.3fms elapsed)", event->text, event, event->function, event->args, ret, event_run_delta_ms);
            
            event = event_time_next;
        }
    }
    
    for(int i = 0; i <= ptr_vector_last_index(&rearm); ++i)
    {    
        alarm_event_node *event = (alarm_event_node*)ptr_vector_get(&rearm, i);
        event->epoch = epoch + 5;
        alarm_set(event->handle, event); // can use the handle as it's a re-arm
    }
    ptr_vector_destroy(&rearm);
    
    double total_run_ms = total_run;
    total_run_ms /= 1000.0;

    log_debug("alarm: tick times fetch %.3fms + run %.3fms = total %.3fms)", fetch_delta_ms, total_run_ms, fetch_delta_ms + total_run_ms);
}

void
alarm_lock()
{
    mutex_lock(&alarm_mutex);
    
#if DEBUG
    alarm_mutex_locked = TRUE;
#endif
    
}

void
alarm_unlock()
{
#if DEBUG
    alarm_mutex_locked = FALSE;
#endif
    
    mutex_unlock(&alarm_mutex);
}

alarm_event_node *
alarm_get_first(alarm_t hndl)
{
    assert(alarm_mutex_locked);
    
    alarm_handle *handle_struct = alarm_get_struct_from_handle(hndl);

    return handle_struct->events.first;
}

#if HAS_ALARM_DUMP

void alarm_log_dump_nolock(bool check)
{
#if DEBUG
    u32 handles_count = 0;
    u32 time_count = 0;
    int events_count = smp_int_get(&alarm_event_instanciated);
    log_debug("alarm_log_dump: begin %u / %u ; %u ; instantiated=%d",
    alarm_event_in_handles_count, alarm_event_in_time_count, alarm_event_alarm_set_count, events_count);
        
    for(int i = 0; i <= ptr_vector_last_index(&alarm_handles); ++i)
    {
        alarm_handle *handle = (alarm_handle*)ptr_vector_get(&alarm_handles, i);
        intptr handle_as_index = (intptr)handle;
        if((handle == NULL) || (handle_as_index <= (intptr)ptr_vector_last_index(&alarm_handles)) || (handle_as_index == MAX_U64))
        {
            continue;
        }
        log_debug("alarm_handle: %2i@%p: %{dnsname}", i, handle, handle->owner_dnsname);
        for(alarm_event_node *node = handle->events.first; node != handle->events.last; node = node->hndl_next)
        {
            log_debug("alarm_event: %p %08x '%s' %T", node, node->key, node->text, node->epoch);
            ++handles_count;
        }
    }
    
    for(alarm_time_node *time_node = &time_list; time_node != NULL; time_node = time_node->next)
    {
        log_debug("alarm_time: %T:", time_node->epoch);
        for(alarm_event_node *node = time_node->events.first; node != time_node->events.last; node = node->time_next)
        {
            log_debug("alarm_event: %p %08x '%s' %T", node, node->key, node->text, node->epoch);
            ++time_count;
        }
        
        yassert(time_node != time_node->next);
    }
    
    log_debug("alarm_log_dump: end %u / %u ; instantiated=%d", handles_count, time_count, events_count);
    
    if(check)
    {
        yassert(handles_count == alarm_event_in_handles_count);
        yassert(time_count == alarm_event_in_time_count);
    }
#endif
}

void alarm_log_dump()
{
    mutex_lock(&alarm_mutex);
    
    alarm_log_dump_nolock(FALSE);
    
    mutex_unlock(&alarm_mutex);
}

#endif

/** @} */

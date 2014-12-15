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
/** @defgroup alarm
 *  @ingroup dnscore
 *  @brief Alarm functions
 *
 * @{
 */

#include "dnscore/logger.h"
#include "dnscore/alarm.h"
#include "dnscore/mutex.h"
#include "dnscore/timeformat.h"

#define MODULE_MSG_HANDLE g_system_logger
extern logger_handle *g_system_logger;

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
    alarm_event_list events;
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

static ptr_vector alarm_handles = EMPTY_PTR_VECTOR;
static alarm_time_node doomsday = { NULL, {NULL, NULL}, MAX_U32 };
static alarm_time_node time_list = { &doomsday, {NULL, NULL}, 0 };
static mutex_t alarm_mutex = MUTEX_INITIALIZER;
static int alarm_handles_next_free = -1;
#ifdef DEBUG
static volatile bool alarm_mutex_locked = FALSE;
static u32 alarm_event_count = 0;
#endif


/**/

static void
alarm_event_list_init(alarm_event_list *head)
{
    head->first = alarm_event_alloc();
    head->last = head->first;
    ZEROMEMORY(head->first, sizeof(alarm_event_node));
}

static bool
alarm_event_list_isempty(alarm_event_list *head)
{
    assert(alarm_mutex_locked);
    
    return head->first == head->last;
}

static alarm_event_node *
alarm_event_list_removefirst(alarm_event_list *event)
{
    assert(alarm_mutex_locked);
    assert(!alarm_event_list_isempty(event));
    assert((event->first != NULL) && (event->last != NULL));
    
    /**
     * 
     * AT THIS POINT WE KNOW THE LIST HAS AT LEAST ONE ITEM AND THE SENTINEL
     * 
     */

    alarm_event_node *node = event->first;
    event->first = node->time_next;
    
    event->first->time_prev = NULL;

    assert(node->hndl_next != NULL);

    if(node->hndl_prev != NULL)
    {
        node->hndl_prev->hndl_next = node->hndl_next;
    }
    else
    {
        /* move the "first" ptr ... */
        alarm_event_list *head = ptr_vector_get(&alarm_handles, node->handle);
        head->first = node->hndl_next;
    }
    
    /* if(node->hndl_next != NULL) There is at least the sentinel */
    
    node->hndl_next->hndl_prev = node->hndl_prev;

    return node;
}

alarm_event_node *
alarm_event_alloc()
{
    alarm_event_node *node;
    MALLOC_OR_DIE(alarm_event_node*, node, sizeof(alarm_event_node), ALARM_NODE_DESC_TAG);

#ifdef DEBUG
    memset(node, 0xff,sizeof(alarm_event_node));
#endif

    return node;
}

void
alarm_event_free(alarm_event_node *node)
{
#ifdef DEBUG
    memset(node, 0xff,sizeof(alarm_event_node));
#endif
    free(node);
}

/*
 * Append at end.
 */

static void
alarm_event_append(alarm_event_list *hndl, alarm_event_list *time, alarm_event_node *node)
{
    assert(alarm_mutex_locked);
    
    /*
     * List not empty ?
     */
    
    if(hndl->first != hndl->last)
    {
        /*
         * Insert the node before the last one.
         */
        
        hndl->last->hndl_prev->hndl_next = node;    // BL ->N   L
        node->hndl_prev = hndl->last->hndl_prev;    // BL<->N   L

        hndl->last->hndl_prev = node;               // BL<->N<- L
        node->hndl_next = hndl->last;               // BL<->N<->L
    }
    else
    {
        hndl->first = node;                         // F = N   L
        node->hndl_next = hndl->last;               //   ->F ->L
        hndl->last->hndl_prev = node;               //   ->F<->L
        node->hndl_prev = NULL;                     // 0<->F<->L
    }

    if(time->first != time->last)
    {
        time->last->time_prev->time_next = node;
        node->time_prev = time->last->time_prev;

        time->last->time_prev = node;
        node->time_next = time->last;
    }
    else
    {
        time->first = node;
        node->time_next = time->last;
        time->last->time_prev = node;
        node->time_prev = NULL;
    }
}

static void
alarm_event_remove(alarm_event_list *hndl, alarm_event_list *time, alarm_event_node *node)
{
    assert(alarm_mutex_locked);
    assert(time != NULL);
    
    if(node->hndl_prev != NULL)                             // A<- N<->B ?
    {
        node->hndl_prev->hndl_next = node->hndl_next;       // N<--N<->B
    }
    else
    {
        hndl->first = node->hndl_next;                      // F = N<->B
    }
    
    node->hndl_next->hndl_prev = node->hndl_prev;           // 0/A<-?B
    
    if(node->time_prev != NULL)
    {
        node->time_prev->time_next = node->time_next;
    }
    else
    {
        time->first = node->time_next;
    }

    node->time_next->time_prev = node->time_prev;
}

static alarm_time_node *
alarm_time_alloc()
{
    alarm_time_node *node;
    MALLOC_OR_DIE(alarm_time_node*, node, sizeof(alarm_time_node), ALARM_NODE_TIME_TAG);

#ifdef DEBUG
    memset(node, 0xff,sizeof(alarm_time_node));
#endif

    alarm_event_list_init(&node->events); /* newly allocated : NO LOCK */

    /* node->next : for the caller */
    return node;
}

static void
alarm_time_free(alarm_time_node *node)
{
#ifdef DEBUG
    memset(node, 0xff,sizeof(alarm_time_node));
#endif
    free(node);
}

/*
 * Get the time node for the exact epoch ...
 */

static alarm_time_node *
alarm_time_get(u32 epoch)
{
    assert(alarm_mutex_locked);
    assert(epoch != MAX_U32);

    alarm_time_node *node = time_list.next;

    while(node->epoch < epoch)
    {
        node = node->next;
    }

    if(node->epoch == epoch)
    {
        return node;
    }
    else
    {
        return NULL;
    }
}

static alarm_time_node *
alarm_time_create(u32 epoch)
{
    assert(alarm_mutex_locked);
    assert(epoch != MAX_U32);
    
    alarm_time_node *prev = &time_list;
    alarm_time_node *node = time_list.next;

    while(node->epoch < epoch)
    {
        prev = node;
        node = node->next;
    }

    if(node->epoch == epoch)
    {
        return node;
    }
    else
    {
        alarm_time_node *timenode = alarm_time_alloc();
        prev->next = timenode;
        timenode->next = node;
        timenode->epoch = epoch;
        return timenode;
    }
}

void
alarm_init()
{
    ptr_vector_resize(&alarm_handles, 64);

    alarm_event_list_init(&time_list.events); /* init: NO LOCK */
}

void
alarm_finalise()
{
}

alarm_t
alarm_open(const u8 *owner_dnsname)
{
    alarm_handle *handle_struct;
    MALLOC_OR_DIE(alarm_handle*, handle_struct, sizeof(alarm_handle), ALARM_HANDLE_TAG);

#ifdef DEBUG
    memset(handle_struct, 0xac,sizeof(alarm_handle));
#endif

    alarm_event_list_init(&handle_struct->events); /* newly allocated: NO LOCK */

    mutex_lock(&alarm_mutex);
#ifdef DEBUG
    alarm_mutex_locked = TRUE;
#endif
    
    intptr h;
    
    if(alarm_handles_next_free >= 0)
    {
        h = alarm_handles_next_free;
        // get the next one if any
        alarm_handles_next_free = (intptr)ptr_vector_get(&alarm_handles, h);
        ptr_vector_set(&alarm_handles, (intptr)h, handle_struct);
    }
    else
    {    
        ptr_vector_append(&alarm_handles, handle_struct);
        h = (intptr)alarm_handles.offset;
    }
    
#ifdef DEBUG
    alarm_mutex_locked = FALSE;
#endif
    mutex_unlock(&alarm_mutex);

    handle_struct->owner_dnsname = owner_dnsname;
    
    log_debug("alarm_open(%{dnsname}) opened alarm with handle %x", handle_struct->owner_dnsname, (int)h);
    
    return (alarm_t)h;
}

static alarm_handle *
alarm_get_struct_from_handle(alarm_t hndl)
{
    assert(alarm_mutex_locked);
    
    if(hndl > alarm_handles.offset || hndl < 0)
    {
        /* ERROR ! */

#ifdef DEBUG
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
    
    if(hndl > alarm_handles.offset || hndl < 0)
    {
        /* ERROR ! */

#ifdef DEBUG
        log_debug("invalid alarm handle: %x", hndl);
#endif

        return;
    }
    
    ptr_vector_set(&alarm_handles, hndl, (void*)(intptr)alarm_handles_next_free);
    alarm_handles_next_free = (intptr)hndl;
}

void 
alarm_close(alarm_t hndl)
{
    if(hndl == ALARM_HANDLE_INVALID)
    {
        return;
    }
    
    mutex_lock(&alarm_mutex);    
    
#ifdef DEBUG
    alarm_mutex_locked = TRUE;
#endif
    alarm_handle *handle_struct = alarm_get_struct_from_handle(hndl);
    
    if(handle_struct == NULL)
    {
#ifdef DEBUG
        alarm_mutex_locked = FALSE;
#endif
        mutex_unlock(&alarm_mutex);
        
        log_err("alarm_close(%x) invalid alarm handle", hndl);

        return;
    }
    
    log_debug("alarm_close(%x) closing alarm for %{dnsname}", hndl, handle_struct->owner_dnsname);

    alarm_event_node *node = handle_struct->events.first;

    while(node != NULL)
    {   
        alarm_event_node *node_next = node->hndl_next;
        
        alarm_time_node *time_node = alarm_time_get(node->epoch);
        
        if(time_node != NULL)
        {
            alarm_event_list *time_list = &time_node->events;

            alarm_event_remove(&handle_struct->events, time_list, node);
            
#ifdef DEBUG
            alarm_event_count--;
#endif
        }

        alarm_event_free(node);
        
        node = node_next;
    }
    
    alarm_clear_struct_from_handle(hndl);

#ifdef DEBUG
    memset(handle_struct, 0xe4,sizeof(alarm_event_list));
#endif

    free(handle_struct);

#ifdef DEBUG
    alarm_mutex_locked = FALSE;
#endif
    
    mutex_unlock(&alarm_mutex);
}

void
alarm_set(alarm_t hndl, alarm_event_node *desc)
{
    mutex_lock(&alarm_mutex);
    
#ifdef DEBUG
    alarm_mutex_locked = TRUE;
#endif

    //assert(alarm_mutex_locked);
    
    alarm_handle *handle_struct = alarm_get_struct_from_handle(hndl);
    
    if(handle_struct == NULL)
    {
        
#ifdef DEBUG
        alarm_mutex_locked = FALSE;
#endif

        mutex_unlock(&alarm_mutex);

        log_err("alarm_set(%p,%x) invalid alarm handle: %x", hndl, desc);
        
        return;
    }

    if(desc->epoch == MAX_U32)
    {

#ifdef DEBUG
        alarm_mutex_locked = FALSE;
#endif

        mutex_unlock(&alarm_mutex);

        log_err("alarm_set(%p,%x) outside of the supported time frame", hndl, desc);
        
        return;
    }
    
    if(desc->epoch == time(NULL))
    {

#ifdef DEBUG
        alarm_mutex_locked = FALSE;
#endif

        mutex_unlock(&alarm_mutex);

        log_err("alarm_set(%p,%x) is NOW", hndl, desc);
        
        return;
    }

    alarm_event_list *head = &handle_struct->events;

#ifdef DEBUG
    
    char epoch_buffer[64];
    time_t epoch_time = desc->epoch;
    ctime_r(&epoch_time, epoch_buffer);
    epoch_buffer[strlen(epoch_buffer)-1] = '\0';
    
    log_debug("alarm_set: %p: at %s, for '%{dnsname}' call key=%x '%s', %p(%p)", desc, epoch_buffer, handle_struct->owner_dnsname, desc->key, desc->text, desc->function, desc->args);
    
#endif

    if(desc->flags != ALARM_DUP_NOP)
    {
        /* Cleanup first */

        if(desc->flags == ALARM_DUP_REMOVE_EARLIER)
        {
            alarm_event_node* node = head->first;
            while(node != head->last)
            {
                if(node->key == desc->key)
                {
                    log_debug("alarm_set: %p: dropping earliest dup", desc);
                    
                    if(desc->epoch < node->epoch)
                    {
                        /* desc is earlier */

                        alarm_event_free(desc);

#ifdef DEBUG
                        alarm_mutex_locked = FALSE;
#endif
                        
                        mutex_unlock(&alarm_mutex);
                        
                        return;
                    }

                    alarm_event_node *node_next = node->hndl_next;
                    alarm_event_remove(head, &alarm_time_get(node->epoch)->events, node);
                    free(node);
                    node = node_next;

#ifdef DEBUG
                    alarm_event_count--;
#endif

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
#ifdef DEBUG
                    log_debug("alarm_set: %p: dropping latest dup", desc);
#endif
                    if(desc->epoch > node->epoch)
                    {
                        /* desc is later */

                        alarm_event_free(desc);

#ifdef DEBUG
                        alarm_mutex_locked = FALSE;
#endif
                        
                        mutex_unlock(&alarm_mutex);

                        return;
                    }

                    alarm_event_node *node_next = node->hndl_next;
                    alarm_event_remove(head, &alarm_time_get(node->epoch)->events, node);
                    free(node);
                    node = node_next;

#ifdef DEBUG
                    alarm_event_count--;
#endif
                }
                else
                {
                    node = node->hndl_next;
                }
            }
        }
    }

#ifdef DEBUG
    log_debug("alarm_set: %p: added", desc);
#endif

    /* Create/get the time head */

    alarm_time_node *timenode = alarm_time_create(desc->epoch);

    /* Link desc at the end of time list and in the hndl list */

    desc->handle = hndl;
    alarm_event_append(head, &timenode->events, desc);

#ifdef DEBUG
    alarm_event_count++;
#endif

#ifdef DEBUG
    alarm_mutex_locked = FALSE;
#endif
    
    mutex_unlock(&alarm_mutex);
}

void
alarm_run_tick(u32 epoch)
{
    assert(epoch != MAX_U32);

    mutex_lock(&alarm_mutex);
    
#ifdef DEBUG
    alarm_mutex_locked = TRUE;
#endif

    alarm_time_node *node = time_list.next;

#ifdef DEBUG
    if(alarm_event_count > 0)
    {
        static u32 last_alarm_debug_dump = 0;
        if(epoch - last_alarm_debug_dump > 60)
        {
            u32 next_epoch = MAX(node->epoch, epoch);
            EPOCH_DEF(next_epoch);
            log_debug("alarm: processing alarms. %d events in queue. (next on %w in %i seconds)", alarm_event_count, EPOCH_REF(next_epoch), next_epoch - epoch);
            last_alarm_debug_dump = epoch;
        }
    }
#endif

    while(node->epoch <= epoch)
    {
        while(!alarm_event_list_isempty(&node->events))
        {
            alarm_event_node *event = alarm_event_list_removefirst(&node->events);

#ifdef DEBUG
            alarm_event_count--;
#endif
            
#ifdef DEBUG
            alarm_mutex_locked = FALSE;
#endif
            
            mutex_unlock(&alarm_mutex);

            /* EXECUTE EVENT */

            log_debug("alarm: running %p: %p(%p) '%s'", event, event->function, event->args, event->text);

            ya_result return_value = event->function(event->args);

            log_debug("alarm: %p returned %r", event, return_value);

            if(return_value == ALARM_REARM)
            {
                event->epoch = epoch + 5;

                alarm_set(event->handle, event);

                mutex_lock(&alarm_mutex);
                
#ifdef DEBUG
                alarm_mutex_locked = TRUE;
#endif
            }
            else
            {
                mutex_lock(&alarm_mutex);
                
#ifdef DEBUG
                alarm_mutex_locked = TRUE;
#endif
                alarm_event_free(event);
            }
        }

        alarm_time_node *prev = node;
        node = node->next;
        
        alarm_time_free(prev);

        time_list.next = node;
    }
    
#ifdef DEBUG
    alarm_mutex_locked = FALSE;
#endif

    mutex_unlock(&alarm_mutex);
}

void
alarm_lock()
{
    mutex_lock(&alarm_mutex);
    
#ifdef DEBUG
    alarm_mutex_locked = TRUE;
#endif
    
}

void
alarm_unlock()
{
#ifdef DEBUG
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

/** @} */

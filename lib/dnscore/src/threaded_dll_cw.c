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

/** @defgroup threading Threading, pools, queues, ...
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{ *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore-config.h"
#include <stdlib.h>
#include <unistd.h>

#include <dnscore/logger.h>

#include "dnscore/threaded_dll_cw.h"

#define MODULE_MSG_HANDLE		g_system_logger

#define THREADED_QUEUE_TAG	    0x455545555154	/* TQUEUE */

#define DLL_POOL 1

/*
 * Note:
 *
 * If a mutex_init fails, it's because of a resource, memory or rights issue.
 * So the application will fail soon enough.
 * I still should check this and exit.
 *
 * mutex_lock will fail only if the current thread aleady owns the mutex
 *
 * mutex_unlock will fail only if the current thread does not owns the mutex
 *
 */

void
threaded_dll_cw_init(threaded_dll_cw *queue, int max_size)
{
#if DEBUG
    memset(queue, 0xff, sizeof(threaded_dll_cw));
#endif  
    list_dl_init(&queue->queue);
#if DLL_POOL
    queue->pool = NULL;
#endif
    
    mutex_init(&queue->mutex);
    cond_init(&queue->cond_read);
    cond_init(&queue->cond_write);

    queue->max_size = max_size;
}

void
threaded_dll_cw_finalize(threaded_dll_cw *queue)
{
    /**
     * If the queue is not empty : too bad !
     *
     * It's the responsibility of the caller to ensure the queue and  set of listeners is empty.
     */

    mutex_lock(&queue->mutex);
    while(list_dl_size(&queue->queue) > 0)
    {
        void *leaked_data = list_dl_dequeue(&queue->queue);
        log_err("threaded_dll_cw_finalize: leaked data @%p", leaked_data);
    }
    
#if DLL_POOL
    list_dl_node_s *node = queue->pool;
    while(node != NULL)
    {
        list_dl_node_s *node_next = node->next;
        list_dl_node_free(node);
        node = node_next;
    }
#endif
    
    mutex_unlock(&queue->mutex);
    
    cond_finalize(&queue->cond_write);
    cond_finalize(&queue->cond_read);
    mutex_destroy(&queue->mutex);
#if DEBUG
    memset(queue, 0xde, sizeof(threaded_dll_cw));
#endif
}

void
threaded_dll_cw_enqueue(threaded_dll_cw *queue, void *constant_pointer)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);
    while(list_dl_size(&queue->queue) >= queue->max_size)
    {
        cond_wait(&queue->cond_write, &queue->mutex);
    }

#if DLL_POOL
    list_dl_node_s *node;
    if(queue->pool != NULL)
    {
        node = queue->pool;
        queue->pool = node->next;
    }
    else
    {
        node = list_dl_node_alloc();
    }
    node->data = constant_pointer;
    list_dl_insert_node(&queue->queue, node);
#else
    list_dl_enqueue(&queue->queue, constant_pointer);
#endif
    
    /*
     * We are done here, we can always signal the readers
     */

    cond_notify(&queue->cond_read);
    mutex_unlock(&queue->mutex);
}

bool
threaded_dll_cw_try_enqueue(threaded_dll_cw* queue, void* constant_pointer)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    if(!mutex_trylock(&queue->mutex))
    {
        return FALSE;
    }

    if( list_dl_size(&queue->queue) >= queue->max_size )
    {
        mutex_unlock(&queue->mutex);
        return FALSE;
    }

    /*
     * Set the data to the write position,
     * and move the write position to the next slot
     *
     */

#if DLL_POOL
    list_dl_node_s *node;
    if(queue->pool != NULL)
    {
        node = queue->pool;
        queue->pool = node->next;
    }
    else
    {
        node = list_dl_node_alloc();
    }
    node->data = constant_pointer;
    list_dl_insert_node(&queue->queue, node);
#else
    list_dl_enqueue(&queue->queue, constant_pointer);
#endif
   
    cond_notify(&queue->cond_read);
    mutex_unlock(&queue->mutex);

    return TRUE;
}

void*
threaded_dll_cw_dequeue(threaded_dll_cw *queue)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);

    while(list_dl_size(&queue->queue) == 0)
    {
        cond_wait(&queue->cond_read, &queue->mutex);
    }

    bool write_blocked = (list_dl_size(&queue->queue) == queue->max_size);
    
#if DLL_POOL
    list_dl_node_s *node = list_dl_remove_last_node(&queue->queue);
    
    void *data = node->data;
    node->next = queue->pool;
    queue->pool = node;
#else
    void *data = list_dl_dequeue(&queue->queue);
#endif
    

    if(write_blocked) /* enqueue has just been locked  -> unlock */
    {
        /*
         * The queue is full : the queuers are waiting.
         * Since we will are removing something, we can free (one of) them.
         * (They will however still be locked until the queue mutex is released)
         */

        cond_notify(&queue->cond_write);
    }

    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);

    return data;
}

void*
threaded_dll_cw_try_dequeue(threaded_dll_cw *queue)
{
    mutex_lock(&queue->mutex);

    if(list_dl_size(&queue->queue) == 0)
    {
        mutex_unlock(&queue->mutex);

        return NULL;
    }

    /*
     * Get the data from the read position,
     * and move the read position to the next slot
     *
     */
    
    bool write_blocked = (list_dl_size(&queue->queue) == queue->max_size);

#if DLL_POOL
    list_dl_node_s *node = list_dl_remove_last_node(&queue->queue);
    
    void *data = node->data;
    node->next = queue->pool;
    queue->pool = node;
#else
    void *data = list_dl_dequeue(&queue->queue);
#endif

    if(write_blocked) /* enqueue has just been locked  -> unlock */
    {
        /*
        * The queue is full : the queuers are waiting.
        * Since we will are removing something, we car free (one of) them.
        * (They will however still be locked until the queue mutex is released)
        */

        cond_notify(&queue->cond_write);
    }

    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);

    return data;
}

void*
threaded_dll_cw_dequeue_with_timeout(threaded_dll_cw *queue, s64 timeout_us)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);

    while(list_dl_size(&queue->queue) == 0)
    {
        if(cond_timedwait(&queue->cond_read, &queue->mutex, timeout_us) != 0)
        {
            // timed-out
            mutex_unlock(&queue->mutex);

            return NULL;
        }
    }

    bool write_blocked = (list_dl_size(&queue->queue) == queue->max_size);

#if DLL_POOL
    list_dl_node_s *node = list_dl_remove_last_node(&queue->queue);

    void *data = node->data;
    node->next = queue->pool;
    queue->pool = node;
#else
    void *data = list_dl_dequeue(&queue->queue);
#endif


    if(write_blocked) /* enqueue has just been locked  -> unlock */
    {
        /*
         * The queue is full : the queuers are waiting.
         * Since we will are removing something, we can free (one of) them.
         * (They will however still be locked until the queue mutex is released)
         */

        cond_notify(&queue->cond_write);
    }

    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);

    return data;
}

void
threaded_dll_cw_wait_empty(threaded_dll_cw *queue)
{
    int size;

    for(;;)
    {
        mutex_lock(&queue->mutex);

        size = list_dl_size(&queue->queue);

        mutex_unlock(&queue->mutex);

        if(size == 0)
        {
            break;
        }

        usleep(1000);
    }
}

int
threaded_dll_cw_size(threaded_dll_cw *queue)
{
    int size;

    mutex_lock(&queue->mutex);

    size = list_dl_size(&queue->queue);

    mutex_unlock(&queue->mutex);

    return size;
}

int
threaded_dll_cw_room(threaded_dll_cw *queue)
{
    int room;

    mutex_lock(&queue->mutex);

    room = queue->max_size - list_dl_size(&queue->queue);

    mutex_unlock(&queue->mutex);

    return room;
}

ya_result
threaded_dll_cw_set_maxsize(threaded_dll_cw *queue, int max_size)
{
    ya_result ret;

    mutex_lock(&queue->mutex);

    if(max_size >= (int)list_dl_size(&queue->queue))
    {
        queue->max_size = max_size;
    }
    
    ret = queue->max_size;
    
    // can only grow : wake up the writers that may be blocked because there was no room left in the queue
    
    cond_notify(&queue->cond_write);
    
    mutex_unlock(&queue->mutex);

    return ret;
}

/** @} */

/*----------------------------------------------------------------------------*/


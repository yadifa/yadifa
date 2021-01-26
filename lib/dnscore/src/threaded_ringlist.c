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
 * @{
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore-config.h"

#include <stdlib.h>
#include <unistd.h>

#include "dnscore/threaded_ringlist.h"

#ifndef DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#error "DNSCORE_HAS_MUTEX_DEBUG_SUPPORT not defined"
#endif

#define MUTEX_USE_SPINLOCK 0

#include "dnscore/mutex.h"

#define THREADED_QUEUE_TAG	    0x455545555154	/* TQUEUE */

/*
 * The maximum number of nodes I should ever require is the queue size + 1
 *
 * A good way to handle this is :
 *
 * Node allocator, node destroyer
 *
 * But the node allocator only allocates a node if none are free
 * And the node destroyer does not release a node but queue it instead.
 *
 * If I enforce the requirement that the allocation/destruction is done
 * by a single thread I could gain some cpu cycles.
 *
 * This reasoning is also valid for the thread_pool_task
 *
 */

typedef struct threaded_ringlist_node threaded_ringlist_node;

struct threaded_ringlist_node
{
    /* DO NOT MOVE THESE POINTERS */
    threaded_ringlist_node *next;
    threaded_ringlist_node *prev;
    /* -------------------------- */

    void* data;
};

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
threaded_ringlist_init(threaded_ringlist *queue, int max_size)
{
    queue->prev = (threaded_ringlist_node*)queue;
    queue->next = (threaded_ringlist_node*)queue;
    queue->pool = NULL;

    mutex_init(&queue->mutex);
    mutex_init(&queue->mutex_enqueue);
    mutex_init(&queue->mutex_dequeue);

    queue->max_size = max_size;
    queue->size = 0;

    mutex_lock(&queue->mutex_dequeue);
}

void
threaded_ringlist_finalize(threaded_ringlist *queue)
{
    threaded_ringlist_node* node;

    /**
     * If the queue is not empty : too bad !
     *
     * It's the responsibility of the caller to ensure the queue and  set of listeners is empty.
     */

    mutex_lock(&queue->mutex);

    node = queue->next;
    queue->next = NULL;

    while(node != (threaded_ringlist_node*)queue)
    {
        threaded_ringlist_node* tmp;
        tmp = node;
        node = node->next;
        free(tmp);
    }

    node = queue->pool;
    queue->pool = NULL;

    while(node != NULL)
    {
#if DEBUG
        assert(node->data == (void*)~0);
#endif

        threaded_ringlist_node* tmp;
        tmp = node;
        node = node->next;
        free(tmp);
    }

    mutex_unlock(&queue->mutex);

    mutex_destroy(&queue->mutex);
    mutex_destroy(&queue->mutex_enqueue);
    mutex_destroy(&queue->mutex_dequeue);
}

void
threaded_ringlist_enqueue(threaded_ringlist* queue, void* constant_pointer)
{
    /*
     * Ensure I'm allowed to enqueue (only one enqueuer and queue not full)
     */

    mutex_lock(&queue->mutex_enqueue);

    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);

    threaded_ringlist_node* node = queue->pool;

    /* If there was a node in the pool : use it, else allocate a new one */

    if(node != NULL)
    {
        queue->pool = node->next;
    }
    else
    {
        MALLOC_OBJECT_OR_DIE(node, threaded_ringlist_node, THREADED_QUEUE_TAG);
    }

    node->prev = queue->prev;
    node->next = (threaded_ringlist_node*)queue;
    node->data = constant_pointer;

    queue->prev->next = node;
    queue->prev = node;

    if(queue->size == 0)
    {
        /*
         * The queue is empty : the dequeuers are waiting.
         * Since we will add something for them, we car free (one of) them.
         * (They will however still be locked until the queue mutex is released)
         */

        mutex_unlock(&queue->mutex_dequeue);
    }

    queue->size++;

    if(queue->size < queue->max_size) /* Too much -> lock the pushes, will be unlocked by a pop */
    {
        /*
         * This new addition made the queue full.  So we will not unlock the enqueuers.
         * The dequeuers will do that when they see fit. (ie: queue not full anymore)
         */

        mutex_unlock(&queue->mutex_enqueue);
    }

    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);
}

bool
threaded_ringlist_try_enqueue(threaded_ringlist* queue, void* constant_pointer)
{
    /*
     * Ensure I'm allowed to enqueue (only one enqueuer and queue not full)
     */

    if(!mutex_trylock(&queue->mutex_enqueue))
    {
        return FALSE;
    }

    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    if(!mutex_trylock(&queue->mutex))
    {
        mutex_unlock(&queue->mutex_enqueue);

        return FALSE;
    }

    threaded_ringlist_node* node = queue->pool;

    /* If there was a node in the pool : use it, else allocate a new one */

    if(node != NULL)
    {
        queue->pool = node->next;
    }
    else
    {
        MALLOC_OBJECT_OR_DIE(node, threaded_ringlist_node, THREADED_QUEUE_TAG);
    }

    node->prev = queue->prev;
    node->next = (threaded_ringlist_node*)queue;
    node->data = constant_pointer;

    queue->prev->next = node;
    queue->prev = node;

    if(queue->size == 0)
    {
        /*
         * The queue is empty : the dequeuers are waiting.
         * Since we will add something for them, we car free (one of) them.
         * (They will however still be locked until the queue mutex is released)
         */

        mutex_unlock(&queue->mutex_dequeue);
    }

    queue->size++;

    if(queue->size < queue->max_size) /* Too much -> lock the pushes, will be unlocked by a pop */
    {
        /*
         * This new addition made the queue full.  So we will not unlock the enqueuers.
         * The dequeuers will do that when they see fit. (ie: queue not full anymore)
         */

        mutex_unlock(&queue->mutex_enqueue);
    }

    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);

    return TRUE;
}

void*
threaded_ringlist_peek(threaded_ringlist *queue)
{
    threaded_ringlist_node* node;

    /*
     * Ensure I'm allowed to dequeue (not empty and only one on it)
     */

    mutex_lock(&queue->mutex_dequeue);

    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);


    node = queue->next;

    void* data = node->data;
    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);

    mutex_unlock(&queue->mutex_dequeue);

    return data;
}

void*
threaded_ringlist_try_peek(threaded_ringlist *queue)
{
    threaded_ringlist_node* node;

    /*
     * Ensure I'm allowed to dequeue (not empty and only one on it)
     */

    if(!mutex_trylock(&queue->mutex_dequeue))
    {
        return (void*)~0;
    }

    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    if(!mutex_trylock(&queue->mutex))
    {
        mutex_unlock(&queue->mutex_dequeue);

        return (void*)~0;
    }

    node = queue->next;

    void* data = node->data;

    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);

    mutex_unlock(&queue->mutex_dequeue);

    return data;
}

void*
threaded_ringlist_dequeue(threaded_ringlist *queue)
{
    threaded_ringlist_node* node;

    /*
     * Ensure I'm allowed to dequeue (not empty and only one on it)
     */

    mutex_lock(&queue->mutex_dequeue);

    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);


    node = queue->next;
    queue->next = node->next;
    node->next->prev = node->prev;

    void* data = node->data;

#if DEBUG
    node->prev = (threaded_ringlist_node*)~0;
    node->data = (void*)~0;
#endif

    /* Pool the node */

    node->next = queue->pool;
    queue->pool = node;

    if(queue->size == queue->max_size) /* enqueue has just been locked  -> unlock */
    {
        /*
         * The queue is full : the queuers are waiting.
         * Since we will are removing something, we car free (one of) them.
         * (They will however still be locked until the queue mutex is released)
         */

        mutex_unlock(&queue->mutex_enqueue);
    }

    queue->size--;

    if(queue->size > 0) /* at 0, locks the next dequeue */
    {
        /*
         * This removal made the queue empty.  So we will not unlock the dequeuers.
         * The enqueuers will do that when they see fit. (ie: queue not full anymore)
         */

        mutex_unlock(&queue->mutex_dequeue);
    }

    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);

    return data;
}

void*
threaded_ringlist_try_dequeue(threaded_ringlist *queue)
{
    threaded_ringlist_node* node;

    /*
     * Ensure I'm allowed to dequeue (not empty and only one on it)
     */

    if(!mutex_trylock(&queue->mutex_dequeue))
    {
        return (void*)~0;
    }

    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    if(!mutex_trylock(&queue->mutex))
    {
        mutex_unlock(&queue->mutex_dequeue);

        return (void*)~0;
    }


    node = queue->next;
    queue->next = node->next;
    node->next->prev = node->prev;

    void* data = node->data;

#if DEBUG
    node->prev = (threaded_ringlist_node*)~0;
    node->data = (void*)~0;
#endif

    /* Pool the node */

    node->next = queue->pool;
    queue->pool = node;

    if(queue->size == queue->max_size) /* enqueue has just been locked  -> unlock */
    {
        /*
         * The queue is full : the queuers are waiting.
         * Since we will are removing something, we car free (one of) them.
         * (They will however still be locked until the queue mutex is released)
         */

        mutex_unlock(&queue->mutex_enqueue);
    }

    queue->size--;

    if(queue->size > 0) /* at 0, locks the next dequeue */
    {
        /*
         * This removal made the queue empty.  So we will not unlock the dequeuers.
         * The enqueuers will do that when they see fit. (ie: queue not full anymore)
         */

        mutex_unlock(&queue->mutex_dequeue);
    }

    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);

    return data;
}

u32
threaded_ringlist_dequeue_set(threaded_ringlist* queue, void** array, u32 array_size)
{
    threaded_ringlist_node* node;

    /*
     * Ensure I'm allowed to dequeue (not empty and only one on it)
     */

    mutex_lock(&queue->mutex_dequeue);

    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);

    bool unlock_enqueue = queue->size == queue->max_size; /* enqueue has just been locked -> schedule unlock */

    u32 loops = MIN(queue->size, array_size); /* The amount we will be able to extract */
    void ** const limit = &array[loops];

    while(array < limit)
    {
        node = queue->next;
        queue->next = node->next;
        node->next->prev = node->prev;

        *array++ = node->data;

        /* Pool the node */

        node->next = queue->pool;
        queue->pool = node;

        if(node->data == NULL) /* Break if a terminator is found*/
        {
            loops -= limit - array;
            break;
        }
    }

    if(unlock_enqueue) /* enqueue has just been locked -> unlock */
    {
        /*
         * The queue is full : the queuers are waiting.
         * Since we will are removing something, we car free (one of) them.
         * (They will however still be locked until the queue mutex is released)
         */

        mutex_unlock(&queue->mutex_enqueue);
    }

    queue->size -= loops;

    if(queue->size > 0) /* at 0, locks the next dequeue */
    {
        /*
         * This removal made the queue empty.  So we will not unlock the dequeuers.
         * The enqueuers will do that when they see fit. (ie: queue not full anymore)
         */

        mutex_unlock(&queue->mutex_dequeue);
    }

    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);

    return loops;
}

void
threaded_ringlist_wait_empty(threaded_ringlist *queue)
{
    int size;

    for(;;)
    {
        mutex_lock(&queue->mutex);

        size = queue->size;

        mutex_unlock(&queue->mutex);

        if(size == 0)
        {
            break;
        }

        usleep(1);
    }
}

int
threaded_ringlist_size(threaded_ringlist *queue)
{
    int size;

    mutex_lock(&queue->mutex);

    size = queue->size;

    mutex_unlock(&queue->mutex);

    return size;

}

ya_result
threaded_ringlist_set_maxsize(threaded_ringlist *queue, int max_size)
{
    mutex_lock(&queue->mutex);

    queue->max_size = max_size;

    mutex_unlock(&queue->mutex);

    return SUCCESS;
}

/** @} */

/*----------------------------------------------------------------------------*/


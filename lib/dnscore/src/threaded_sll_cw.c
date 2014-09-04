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
/** @defgroup threading Threading, pools, queues, ...
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{ *
 *----------------------------------------------------------------------------*/
#include <stdlib.h>
#include <unistd.h>

#include "dnscore/threaded_sll_cw.h"

#define THREADED_QUEUE_TAG	    0x455545555154	/* TQUEUE */


/*
 * Note:
 *
 * If a pthread_mutex_init fails, it's because of a resource, memory or rights issue.
 * So the application will fail soon enough.
 * I still should check this and exit.
 *
 * pthread_mutex_lock will fail only if the current thread aleady owns the mutex
 *
 * pthread_mutex_unlock will fail only if the current thread does not owns the mutex
 *
 */

void
threaded_sll_cw_init(threaded_sll_cw *queue, int max_size)
{
#ifdef DEBUG
    memset(queue, 0xff, sizeof(threaded_sll_cw));
#endif  
    queue->first = NULL;
    queue->last = NULL;
    queue->allocator = &libc_allocator;
    
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond_read, NULL);
    pthread_cond_init(&queue->cond_write, NULL);

    queue->max_size = max_size;
    queue->size = 0;
}

void
threaded_sll_cw_finalize(threaded_sll_cw *queue)
{
    /**
     * If the queue is not empty : too bad !
     *
     * It's the responsibility of the caller to ensure the queue and  set of listeners is empty.
     */

    pthread_mutex_lock(&queue->mutex);
    while(queue->size-- > 0)
    {
        threaded_sll_cw_node *node = queue->first;
        queue->first = node->next;
        afree(queue->allocator, node);
        //free(node);
    }
    pthread_mutex_unlock(&queue->mutex);
    
    pthread_cond_destroy(&queue->cond_write);
    pthread_cond_destroy(&queue->cond_read);
    pthread_mutex_destroy(&queue->mutex);
#ifdef DEBUG
    memset(queue, 0xde, sizeof(threaded_sll_cw));
#endif
}

void
threaded_sll_cw_enqueue(threaded_sll_cw *queue, void *constant_pointer)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    pthread_mutex_lock(&queue->mutex);
    while( queue->size >= queue->max_size )
    {
        pthread_cond_wait(&queue->cond_write, &queue->mutex);
    }

    /*
     * Set the data to the write position,
     * and move the write position to the next slot
     *
     */

    /**
     * @note: "if(overflow) reset" is (much) faster than MOD(limit)
     */
    
    threaded_sll_cw_node *node;
    node = (threaded_sll_cw_node *)aalloc(queue->allocator, sizeof(threaded_sll_cw_node));
    node->data = constant_pointer;
    
    if(queue->size != 0)
    {
        queue->last->next = node;
        queue->last = node;
    }
    else
    {
        queue->first = node;
        queue->last = node;
    }
    
    queue->size++;

    /*
     * We are done here, we can always signal the readers
     */

    pthread_cond_broadcast(&queue->cond_read);
    pthread_mutex_unlock(&queue->mutex);
}

bool
threaded_sll_cw_try_enqueue(threaded_sll_cw* queue, void* constant_pointer)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    if(pthread_mutex_trylock(&queue->mutex) != 0)
    {
        return FALSE;
    }

    if( queue->size >= queue->max_size )
    {
        return FALSE;
    }

    /*
     * Set the data to the write position,
     * and move the write position to the next slot
     *
     */

    /**
     * @note: "if(overflow) reset" is (much) faster than MOD(limit)
     */

    threaded_sll_cw_node *node;
    node = (threaded_sll_cw_node *)aalloc(queue->allocator, sizeof(threaded_sll_cw_node));
    //MALLOC_OR_DIE(threaded_sll_cw_node*, node, sizeof(threaded_sll_cw_node), GENERIC_TAG);
    node->data = constant_pointer;
    
    if(queue->size != 0)
    {
        queue->last->next = node;
        queue->last = node;
    }
    else
    {
        queue->first = node;
        queue->last = node;
    }
    
    queue->size++;

    /*
     * We are done here, we can always signal the readers
     */

    pthread_cond_broadcast(&queue->cond_read);
    pthread_mutex_unlock(&queue->mutex);

    return TRUE;
}

void*
threaded_sll_cw_peek(threaded_sll_cw *queue)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    pthread_mutex_lock(&queue->mutex);

    while( queue->size == 0 )
    {
        pthread_cond_wait(&queue->cond_read,&queue->mutex);
    }

    /*
     * Get the data from the read position,
     * and move the read position to the next slot
     *
     */

    void* data = queue->first->data;
       
    /*
     * We are done here.
     */

    pthread_mutex_unlock(&queue->mutex);

    return data;
}

void*
threaded_sll_cw_try_peek(threaded_sll_cw *queue)
{
    pthread_mutex_lock(&queue->mutex);

    if( queue->size == 0 )
    {
        pthread_mutex_unlock(&queue->mutex);

        return NULL;
    }

    /*
     * Get the data from the read position,
     * and move the read position to the next slot
     *
     */

    void* data = queue->first->data;

    /*
     * We are done here.
     */

    pthread_mutex_unlock(&queue->mutex);

    return data;
}


void*
threaded_sll_cw_dequeue(threaded_sll_cw *queue)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    pthread_mutex_lock(&queue->mutex);

    while( queue->size == 0 )
    {
        pthread_cond_wait(&queue->cond_read,&queue->mutex);
    }

    /*
     * Get the data from the read position,
     * and move the read position to the next slot
     *
     */

    threaded_sll_cw_node *node = queue->first;
    void* data = node->data;
    queue->first = node->next;
    afree(queue->allocator, node);
    //free(node);

    if(queue->size-- == queue->max_size) /* enqueue has just been locked  -> unlock */
    {
        /*
         * The queue is full : the queuers are waiting.
         * Since we will are removing something, we can free (one of) them.
         * (They will however still be locked until the queue mutex is released)
         */

        pthread_cond_broadcast(&queue->cond_write);
    }

    /*
     * We are done here.
     */

    pthread_mutex_unlock(&queue->mutex);

    return data;
}

void*
threaded_sll_cw_try_dequeue(threaded_sll_cw *queue)
{
    pthread_mutex_lock(&queue->mutex);

    if( queue->size == 0 )
    {
        pthread_mutex_unlock(&queue->mutex);

        return NULL;
    }

    /*
     * Get the data from the read position,
     * and move the read position to the next slot
     *
     */

    threaded_sll_cw_node *node = queue->first;
    void* data = node->data;
    queue->first = node->next;
    afree(queue->allocator, node);
    //free(node);

    if(queue->size-- == queue->max_size) /* enqueue has just been locked  -> unlock */
    {
        /*
        * The queue is full : the queuers are waiting.
        * Since we will are removing something, we car free (one of) them.
        * (They will however still be locked until the queue mutex is released)
        */

        pthread_cond_broadcast(&queue->cond_write);
    }

    /*
     * We are done here.
     */

    pthread_mutex_unlock(&queue->mutex);

    return data;
}

u32
threaded_sll_cw_dequeue_set(threaded_sll_cw *queue, void **array, u32 array_size)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    pthread_mutex_lock(&queue->mutex);

    while( queue->size == 0 )
    {
        pthread_cond_wait(&queue->cond_read,&queue->mutex);
    }

    /*
     * Get up to array_size times the data from the read position,
     * and move the read position to the next slot
     *
     */

    bool unlock_enqueue = queue->size == queue->max_size; /* enqueue has just been locked -> schedule unlock */

    u32 loops = MIN(queue->size, array_size);		  /* The amount we will be able to extract */
    
    void ** const limit = &array[loops];		  /* compute the limit so we only have one increment and one compare */

    while(array < limit)
    {
        threaded_sll_cw_node *node = queue->first;
        void* data = node->data;
        queue->first = node->next;
        afree(queue->allocator, node);
        //free(node);

        *array++ = data;
    }

    queue->size -= loops;				  /* adjust the size */

    if(unlock_enqueue) /* enqueue has just been locked -> unlock */
    {
        /*
         * The queue is full : the queuers are waiting.
         * Since we will are removing something, we car free (one of) them.
         * (They will however still be locked until the queue mutex is released)
         */

        pthread_cond_broadcast(&queue->cond_write);
    }   

    /*
     * We are done here.
     */

    pthread_mutex_unlock(&queue->mutex);

    return loops;	    /* Return the amount we got from the queue */
}

void
threaded_sll_cw_wait_empty(threaded_sll_cw *queue)
{
    int size;

    for(;;)
    {
        pthread_mutex_lock(&queue->mutex);

        size = queue->size;

        pthread_mutex_unlock(&queue->mutex);

        if(size == 0)
        {
            break;
        }

        usleep(1000);
    }
}

int
threaded_sll_cw_size(threaded_sll_cw *queue)
{
    int size;

    pthread_mutex_lock(&queue->mutex);

    size = queue->size;

    pthread_mutex_unlock(&queue->mutex);

    return size;
}

int
threaded_sll_cw_room(threaded_sll_cw *queue)
{
    int room;

    pthread_mutex_lock(&queue->mutex);

    room = queue->max_size - queue->size;

    pthread_mutex_unlock(&queue->mutex);

    return room;
}

ya_result
threaded_sll_cw_set_maxsize(threaded_sll_cw *queue, int max_size)
{
    ya_result ret = ERROR;

    pthread_mutex_lock(&queue->mutex);

    if(max_size >= queue->size)
    {
        queue->max_size = max_size;
    }
    
    ret = queue->max_size;
    
    pthread_mutex_unlock(&queue->mutex);

    return ret;
}

/** @} */

/*----------------------------------------------------------------------------*/


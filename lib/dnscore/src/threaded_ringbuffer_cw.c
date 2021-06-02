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

#include "dnscore/threaded_ringbuffer_cw.h"

#define THREADED_QUEUE_TAG	    0x455545555154	/* TQUEUE */

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
threaded_ringbuffer_cw_init(threaded_ringbuffer_cw *queue, int max_size)
{
#if DEBUG
    memset(queue, 0xff, sizeof(threaded_ringbuffer_cw));
#endif  
    
    MALLOC_OR_DIE(void**, queue->buffer, sizeof(void*) * max_size, THREADED_QUEUE_TAG);
 
    queue->buffer_limit = &queue->buffer[max_size];
    queue->write_slot = queue->buffer;
    queue->read_slot = queue->buffer;

    mutex_init(&queue->mutex);
    cond_init(&queue->cond_read);
    cond_init(&queue->cond_write);

    queue->max_size = max_size;
    queue->size = 0;
}

void
threaded_ringbuffer_cw_finalize(threaded_ringbuffer_cw *queue)
{
    /**
     * If the queue is not empty : too bad !
     *
     * It's the responsibility of the caller to ensure the queue and  set of listeners is empty.
     */

    free(queue->buffer);
    queue->buffer = NULL;

    cond_finalize(&queue->cond_write);
    cond_finalize(&queue->cond_read);

    mutex_destroy(&queue->mutex);
#if DEBUG
    memset(queue, 0xde, sizeof(threaded_ringbuffer_cw));
#endif
}

void
threaded_ringbuffer_cw_enqueue(threaded_ringbuffer_cw *queue, void *constant_pointer)
{
    assert(queue->max_size > 0);
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);
    while( queue->size >= queue->max_size )
    {
        cond_wait(&queue->cond_write, &queue->mutex);
    }

    /*
     * Set the data to the write position,
     * and move the write position to the next slot
     *
     */

    /**
     * @note: "if(overflow) reset" is (much) faster than MOD(limit)
     */

    *queue->write_slot++ = constant_pointer;

    if(queue->write_slot == queue->buffer_limit)
    {
        queue->write_slot = queue->buffer;
    }

    queue->size++;

    /*
     * We are done here, we can always signal the readers
     */

    cond_notify(&queue->cond_read);
    mutex_unlock(&queue->mutex);
}

void
threaded_ringbuffer_cw_enqueue_set(threaded_ringbuffer_cw *queue, void **constant_pointer_array, u32 count)
{
    assert(queue->max_size > 0);
    assert(queue->max_size >= count);
    
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */
    
    mutex_lock(&queue->mutex);
    while( queue->size + count > queue->max_size )
    {
        cond_wait(&queue->cond_write, &queue->mutex);
    }

    /*
     * Set the data to the write position,
     * and move the write position to the next slot
     *
     */

    /**
     * @note: "if(overflow) reset" is (much) faster than MOD(limit)
     */

    for(u32 i = 0; i < count; ++i)
    {
        *queue->write_slot++ = constant_pointer_array[i];

        if(queue->write_slot == queue->buffer_limit)
        {
            queue->write_slot = queue->buffer;
        }
    }
    
    queue->size += count;

    /*
     * We are done here, we can always signal the readers
     */

    cond_notify(&queue->cond_read);
    mutex_unlock(&queue->mutex);
}

bool
threaded_ringbuffer_cw_try_enqueue(threaded_ringbuffer_cw* queue, void* constant_pointer)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    if(!mutex_trylock(&queue->mutex))
    {
        return FALSE;
    }

    if( queue->size >= queue->max_size )
    {
        mutex_unlock(&queue->mutex);
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

    *queue->write_slot++ = constant_pointer;

    if(queue->write_slot == queue->buffer_limit)
    {
        queue->write_slot = queue->buffer;
    }

    queue->size++;

    /*
     * We are done here, we can always signal the readers
     */

    cond_notify(&queue->cond_read);
    mutex_unlock(&queue->mutex);

    return TRUE;
}

void*
threaded_ringbuffer_cw_peek(threaded_ringbuffer_cw *queue)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);

    while( queue->size == 0 )
    {
        cond_wait(&queue->cond_read,&queue->mutex);
    }

    /*
     * Get the data from the read position,
     * and move the read position to the next slot
     *
     */

    void* data = *queue->read_slot;
   
    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);

    return data;
}

void*
threaded_ringbuffer_cw_try_peek(threaded_ringbuffer_cw *queue)
{
    mutex_lock(&queue->mutex);

    if( queue->size == 0 )
    {
        mutex_unlock(&queue->mutex);

        return NULL;
    }

    /*
     * Get the data from the read position,
     * and move the read position to the next slot
     *
     */

    void* data = *queue->read_slot;

    /*
     * We are done here.
     */

    mutex_unlock(&queue->mutex);

    return data;
}

void*
threaded_ringbuffer_cw_dequeue(threaded_ringbuffer_cw *queue)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);

    while( queue->size == 0 )
    {
        cond_wait(&queue->cond_read,&queue->mutex);
    }

    /*
     * Get the data from the read position,
     * and move the read position to the next slot
     *
     */

    void* data = *queue->read_slot++;
    if(queue->read_slot == queue->buffer_limit)
    {
        queue->read_slot = queue->buffer;
    }

    if(queue->size-- == queue->max_size) /* enqueue has just been locked  -> unlock */
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
threaded_ringbuffer_cw_dequeue_with_timeout(threaded_ringbuffer_cw *queue, s64 timeout_us)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);

    while( queue->size == 0 )
    {
        if(cond_timedwait(&queue->cond_read,&queue->mutex, timeout_us) != 0)
        {
            mutex_unlock(&queue->mutex);
            return NULL;
        }
    }

    /*
     * Get the data from the read position,
     * and move the read position to the next slot
     *
     */

    void* data = *queue->read_slot++;
    if(queue->read_slot == queue->buffer_limit)
    {
        queue->read_slot = queue->buffer;
    }

    if(queue->size-- == queue->max_size) /* enqueue has just been locked  -> unlock */
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
threaded_ringbuffer_cw_try_dequeue(threaded_ringbuffer_cw *queue)
{
    mutex_lock(&queue->mutex);

    if( queue->size == 0 )
    {
        mutex_unlock(&queue->mutex);

        return NULL;
    }

    /*
     * Get the data from the read position,
     * and move the read position to the next slot
     *
     */

    void* data = *queue->read_slot++;
    if(queue->read_slot == queue->buffer_limit)
    {
        queue->read_slot = queue->buffer;
    }

    if(queue->size-- == queue->max_size) /* enqueue has just been locked  -> unlock */
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

u32
threaded_ringbuffer_cw_dequeue_set(threaded_ringbuffer_cw *queue, void **array, u32 array_size)
{
    /*
     * Ensure I'm allowed to work on queue (only one working on it)
     */

    mutex_lock(&queue->mutex);

    while( queue->size == 0 )
    {
        cond_wait(&queue->cond_read,&queue->mutex);
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
        void* data = *queue->read_slot++;
        *array++ = data;

        if(queue->read_slot == queue->buffer_limit)
        {
            queue->read_slot = queue->buffer;
        }

        if(data == NULL)				    /* Break if a terminator is found*/
        {
            loops -= limit - array;
            break;
        }
    }

    queue->size -= loops;				  /* adjust the size */

    if(unlock_enqueue) /* enqueue has just been locked -> unlock */
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

    return loops;	    /* Return the amount we got from the queue */
}

void
threaded_ringbuffer_cw_wait_empty(threaded_ringbuffer_cw *queue)
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

        usleep(1000);
    }
}

u32
threaded_ringbuffer_cw_size(threaded_ringbuffer_cw *queue)
{
    u32 size;

    mutex_lock(&queue->mutex);

    size = queue->size;

    mutex_unlock(&queue->mutex);

    return size;
}

int
threaded_ringbuffer_cw_room(threaded_ringbuffer_cw *queue)
{
    int room;

    mutex_lock(&queue->mutex);

    room = queue->max_size - queue->size;

    mutex_unlock(&queue->mutex);

    return room;
}

ya_result
threaded_ringbuffer_cw_set_maxsize(threaded_ringbuffer_cw *queue, int max_size)
{
    ya_result ret = INVALID_ARGUMENT_ERROR; // can only grow

    mutex_lock(&queue->mutex);

    if(max_size >= (int)queue->size)
    {
        void** tmp;
        MALLOC_OR_DIE(void**, tmp, sizeof(void*) * max_size, THREADED_QUEUE_TAG);

        /*
         * Copy from the read to the write position
         */

        void** p = tmp;
        u32 count = queue->size;

        while(count-- > 0)
        {
            *p++ = *queue->read_slot++;

            // wrap when the end is reached
            
            if(queue->read_slot == queue->buffer_limit)
            {
                queue->read_slot = queue->buffer;
            }
        }

        /*
         * At this point ...
         *
         * tmp is the new "read"
         * p is the new "write", but it could be at the limit
         *
         */

        free(queue->buffer);
        queue->buffer = tmp;
        queue->buffer_limit = &tmp[max_size];
        queue->read_slot = tmp;

        if(p == queue->buffer_limit)
        {
            p = tmp;
        }

        queue->write_slot = p;
        queue->max_size = max_size;
    }
    
    ret = queue->max_size;
    
    mutex_unlock(&queue->mutex);

    return ret;
}

/** @} */

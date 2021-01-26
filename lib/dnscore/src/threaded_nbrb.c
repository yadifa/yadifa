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

#include "dnscore/threaded_nbrb.h"

#define HAS_ATOMIC_FEATURES 0

#if HAS_ATOMIC_FEATURES

#define THREADED_QUEUE_TAG	    0x455545555154	/* TQUEUE */

#define BASE_WAIT               5               // us
#define BASE_WAIT_MAX           500000          // so about 0.5 secs max

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

#define SENTINEL ((void*)~0)

#define DO_YIELD 0

#define LOOP_WAIT(t)            \
        if(t == BASE_WAIT)      \
        {                       \
            sched_yield();      \
            t += BASE_WAIT;     \
            continue;           \
        }                       \
                                \
        usleep(t);              \
                                \
        t += BASE_WAIT;         \
        if(t > BASE_WAIT_MAX)   \
        {                       \
            t = BASE_WAIT_MAX;  \
        }

void
threaded_nbrb_init(threaded_nbrb *queue, int max_size)
{
    u32 real_size = 1;
    while(real_size <= max_size)
    {
        real_size <<= 1;
    }
    real_size >>= 1;
    
    if(real_size < 4)
    {
        real_size = 4;
    }
    else if(real_size > 0x1000000)
    {
        real_size = 0x1000000;
    }

    MALLOC_OR_DIE(void**, queue->buffer, sizeof(void*)* real_size, THREADED_QUEUE_TAG);
    queue->empty_slots = real_size;
    queue->filled_slots = 0;
    queue->write_offset = 0;
    queue->read_offset = 0;

    queue->size_mask = real_size - 1;

    for(u32 i = 0; i < real_size; i++)
    {
        queue->buffer[i] = SENTINEL;
    }
}

void
threaded_nbrb_finalize(threaded_nbrb *queue)
{
    /**
     * If the queue is not empty : too bad !
     *
     * It's the responsibility of the caller to ensure the queue and  set of listeners is empty.
     */

    free(queue->buffer);
    queue->buffer = NULL;
}

void
threaded_nbrb_enqueue(threaded_nbrb* queue, void* constant_pointer)
{
    const u32 one = 1;
    
    int t = BASE_WAIT;

    s32 e;

    for(;;)
    {
        e = __sync_fetch_and_sub(&queue->empty_slots, one);

        if(e > 0)
        {
            break;
        }
        
        __sync_fetch_and_add(&queue->empty_slots, one);

        LOOP_WAIT(t)
    }

    s32 wo = __sync_fetch_and_add(&queue->write_offset, one);

#if 0 /* fix */
#elif 1
    //__sync_synchronize();
    queue->buffer[wo & queue->size_mask] = constant_pointer;
    //__sync_synchronize();
#else
    //while(!__sync_bool_compare_and_swap(&queue->buffer[wo & queue->size_mask],queue->buffer[wo & queue->size_mask],constant_pointer));
    while(!__sync_bool_compare_and_swap(&queue->buffer[wo & queue->size_mask], SENTINEL, constant_pointer));
#endif
    
    __sync_fetch_and_add(&queue->filled_slots, one);
}

bool
threaded_nbrb_try_enqueue(threaded_nbrb* queue, void* constant_pointer)
{
    const u32 one = 1;

    s32 e = __sync_fetch_and_sub(&queue->empty_slots, one);

    if(e <= 0)
    {
        __sync_fetch_and_add(&queue->empty_slots, one);

        return FALSE;
    }

    s32 wo = __sync_fetch_and_add(&queue->write_offset, one);

    //queue->buffer[wo & queue->size_mask] = constant_pointer;

    queue->buffer[wo & queue->size_mask] = constant_pointer;

    __sync_fetch_and_add(&queue->filled_slots, one);

    return TRUE;
}

void*
threaded_nbrb_try_peek(threaded_nbrb *queue)
{
    const s32 zero = 0;
    const s32 one = 1;

    s32 e = __sync_fetch_and_sub(&queue->filled_slots, one);

    if(e <= 0)
    {
        __sync_fetch_and_add(&queue->filled_slots, one);

        return NULL;
    }

    s32 ro = __sync_fetch_and_add(&queue->read_offset, zero);

    void* p = queue->buffer[ro & queue->size_mask];

    __sync_fetch_and_add(&queue->filled_slots, one);

    return p;
}

void*
threaded_nbrb_peek(threaded_nbrb *queue)
{
    const s32 zero = 0;
    const s32 one = 1;

    int t = BASE_WAIT;

    s32 e;

    for(;;)
    {
        e = __sync_fetch_and_sub(&queue->filled_slots, one);

        if(e > 0)
        {
            break;
        }

        __sync_fetch_and_add(&queue->filled_slots, one);

        LOOP_WAIT(t)
    }

    s32 ro = __sync_fetch_and_add(&queue->read_offset, zero);

    void* p = queue->buffer[ro & queue->size_mask];

    __sync_fetch_and_add(&queue->filled_slots, one);

    return p;
}

void*
threaded_nbrb_dequeue(threaded_nbrb *queue)
{
    const s32 one = 1;

    int t = BASE_WAIT;

    s32 e;

    for(;;)
    {
        e = __sync_fetch_and_sub(&queue->filled_slots, one);

        if(e > 0)
        {
            break;
        }

        __sync_fetch_and_add(&queue->filled_slots, one);

        LOOP_WAIT(t)
    }

    s32 ro = __sync_fetch_and_add(&queue->read_offset, one);

#if 0 /* fix */
#elif 1
    void * volatile *pp = (void* volatile *)&queue->buffer[ro & queue->size_mask];
    void* p;
    
    for(;;)
    {
        //__sync_synchronize();
        p = *pp;
        if(p != SENTINEL)
        {
            queue->buffer[ro & queue->size_mask] = SENTINEL;
            break;
        }

        //sched_yield();
        __sync_synchronize();
    }
    //__sync_synchronize();
#else
    //while(!__sync_val_compare_and_swap(&queue->buffer[ro & queue->size_mask], SENTINEL,
#endif
    __sync_fetch_and_add(&queue->empty_slots, one);

    return p;
}

void*
threaded_nbrb_try_dequeue(threaded_nbrb *queue)
{
    const u32 one = 1;

    s32 e = __sync_fetch_and_sub(&queue->filled_slots, one);

    if(e <= 0)
    {
        __sync_fetch_and_add(&queue->filled_slots, one);

        return NULL;
    }

    s32 ro = __sync_fetch_and_add(&queue->read_offset, one);

    void* p = queue->buffer[ro & queue->size_mask];

    __sync_fetch_and_add(&queue->empty_slots, one);

    return p;
}

u32
threaded_nbrb_dequeue_set(threaded_nbrb* queue, void** array, u32 array_size)
{
    u32 loops = 0;
    return loops; /* Return the amount we got from the queue */
}

void
threaded_nbrb_wait_empty(threaded_nbrb *queue)
{
   const u32 zero = 0;

   //u32 m = queue->size_mask;

   int t = BASE_WAIT;

   for(;;)
   {
       s32 f = __sync_fetch_and_add(&queue->filled_slots, zero);

       if(f == 0)
       {
           break;
       }

       LOOP_WAIT(t)
   }
   
}

int
threaded_nbrb_size(threaded_nbrb *queue)
{
    const u32 zero = 0;

    s32 f = __sync_fetch_and_add(&queue->filled_slots, zero);

    return f;
}

ya_result
threaded_nbrb_set_maxsize(threaded_nbrb *queue, int max_size)
{
    ya_result ret = FEATURE_NOT_IMPLEMENTED_ERROR;

    return ret;
}

#endif

/** @} */

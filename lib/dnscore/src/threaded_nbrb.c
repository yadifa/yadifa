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

/**-----------------------------------------------------------------------------
 * @defgroup threading Threading, pools, queues, ...
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"
#include <stdlib.h>
#include <unistd.h>

#include "dnscore/threaded_nbrb.h"

#define HAS_ATOMIC_FEATURES 0

#if HAS_ATOMIC_FEATURES

#define THREADED_QUEUE_NBRB_TAG 0x4252424e5154 /* TQUEUE */

#define BASE_WAIT               5      // us
#define BASE_WAIT_MAX           500000 // so about 0.5 secs max

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

#define SENTINEL                ((void *)~0)

#define DO_YIELD                0

#define LOOP_WAIT(t)                                                                                                                                                                                                                           \
    if(t == BASE_WAIT)                                                                                                                                                                                                                         \
    {                                                                                                                                                                                                                                          \
        sched_yield();                                                                                                                                                                                                                         \
        t += BASE_WAIT;                                                                                                                                                                                                                        \
        continue;                                                                                                                                                                                                                              \
    }                                                                                                                                                                                                                                          \
                                                                                                                                                                                                                                               \
    usleep(t);                                                                                                                                                                                                                                 \
                                                                                                                                                                                                                                               \
    t += BASE_WAIT;                                                                                                                                                                                                                            \
    if(t > BASE_WAIT_MAX)                                                                                                                                                                                                                      \
    {                                                                                                                                                                                                                                          \
        t = BASE_WAIT_MAX;                                                                                                                                                                                                                     \
    }

void threaded_nbrb_init(threaded_nbrb *queue, int max_size)
{
    uint32_t real_size = 1;
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

    MALLOC_OR_DIE(void **, queue->buffer, sizeof(void *) * real_size, THREADED_QUEUE_NBRB_TAG);
    queue->empty_slots = real_size;
    queue->filled_slots = 0;
    queue->write_offset = 0;
    queue->read_offset = 0;

    queue->size_mask = real_size - 1;

    for(uint_fast32_t i = 0; i < real_size; i++)
    {
        queue->buffer[i] = SENTINEL;
    }
}

void threaded_nbrb_finalize(threaded_nbrb *queue)
{
    /**
     * If the queue is not empty : too bad !
     *
     * It's the responsibility of the caller to ensure the queue and  set of listeners is empty.
     */

    free(queue->buffer);
    queue->buffer = NULL;
}

void threaded_nbrb_enqueue(threaded_nbrb *queue, void *constant_pointer)
{
    const uint32_t one = 1;

    int            t = BASE_WAIT;

    int32_t        e;

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

    int32_t wo = __sync_fetch_and_add(&queue->write_offset, one);

    //__sync_synchronize();
    queue->buffer[wo & queue->size_mask] = constant_pointer;
    //__sync_synchronize();

    __sync_fetch_and_add(&queue->filled_slots, one);
}

bool threaded_nbrb_try_enqueue(threaded_nbrb *queue, void *constant_pointer)
{
    const uint32_t one = 1;

    int32_t        e = __sync_fetch_and_sub(&queue->empty_slots, one);

    if(e <= 0)
    {
        __sync_fetch_and_add(&queue->empty_slots, one);

        return false;
    }

    int32_t wo = __sync_fetch_and_add(&queue->write_offset, one);

    // queue->buffer[wo & queue->size_mask] = constant_pointer;

    queue->buffer[wo & queue->size_mask] = constant_pointer;

    __sync_fetch_and_add(&queue->filled_slots, one);

    return true;
}

void *threaded_nbrb_try_peek(threaded_nbrb *queue)
{
    const int32_t zero = 0;
    const int32_t one = 1;

    int32_t       e = __sync_fetch_and_sub(&queue->filled_slots, one);

    if(e <= 0)
    {
        __sync_fetch_and_add(&queue->filled_slots, one);

        return NULL;
    }

    int32_t ro = __sync_fetch_and_add(&queue->read_offset, zero);

    void   *p = queue->buffer[ro & queue->size_mask];

    __sync_fetch_and_add(&queue->filled_slots, one);

    return p;
}

void *threaded_nbrb_peek(threaded_nbrb *queue)
{
    const int32_t zero = 0;
    const int32_t one = 1;

    int           t = BASE_WAIT;

    int32_t       e;

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

    int32_t ro = __sync_fetch_and_add(&queue->read_offset, zero);

    void   *p = queue->buffer[ro & queue->size_mask];

    __sync_fetch_and_add(&queue->filled_slots, one);

    return p;
}

void *threaded_nbrb_dequeue(threaded_nbrb *queue)
{
    const int32_t one = 1;

    int           t = BASE_WAIT;

    int32_t       e;

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

    int32_t         ro = __sync_fetch_and_add(&queue->read_offset, one);

    void *volatile *pp = (void *volatile *)&queue->buffer[ro & queue->size_mask];
    void           *p;

    for(;;)
    {
        //__sync_synchronize();
        p = *pp;
        if(p != SENTINEL)
        {
            queue->buffer[ro & queue->size_mask] = SENTINEL;
            break;
        }

        // sched_yield();
        __sync_synchronize();
    }
    //__sync_synchronize();
    __sync_fetch_and_add(&queue->empty_slots, one);

    return p;
}

void *threaded_nbrb_try_dequeue(threaded_nbrb *queue)
{
    const uint32_t one = 1;

    int32_t        e = __sync_fetch_and_sub(&queue->filled_slots, one);

    if(e <= 0)
    {
        __sync_fetch_and_add(&queue->filled_slots, one);

        return NULL;
    }

    int32_t ro = __sync_fetch_and_add(&queue->read_offset, one);

    void   *p = queue->buffer[ro & queue->size_mask];

    __sync_fetch_and_add(&queue->empty_slots, one);

    return p;
}

uint32_t threaded_nbrb_dequeue_set(threaded_nbrb *queue, void **array, uint32_t array_size)
{
    uint32_t loops = 0;
    return loops; /* Return the amount we got from the queue */
}

void threaded_nbrb_wait_empty(threaded_nbrb *queue)
{
    const uint32_t zero = 0;

    // uint32_t m = queue->size_mask;

    int t = BASE_WAIT;

    for(;;)
    {
        int32_t f = __sync_fetch_and_add(&queue->filled_slots, zero);

        if(f == 0)
        {
            break;
        }

        LOOP_WAIT(t)
    }
}

int threaded_nbrb_size(threaded_nbrb *queue)
{
    const uint32_t zero = 0;

    int32_t        f = __sync_fetch_and_add(&queue->filled_slots, zero);

    return f;
}

ya_result threaded_nbrb_set_maxsize(threaded_nbrb *queue, int max_size)
{
    ya_result ret = FEATURE_NOT_IMPLEMENTED_ERROR;

    return ret;
}

#endif

/** @} */

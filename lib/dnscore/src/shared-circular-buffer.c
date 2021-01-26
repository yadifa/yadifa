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

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "dnscore/dnscore.h"
#include "dnscore/fdtools.h"
#include "dnscore/mutex.h"
#include "dnscore/shared-circular-buffer.h"

#define L1_DATA_LINE_SIZE 0x40
#define L1_DATA_LINE_MASK (L1_DATA_LINE_SIZE - 1)

struct shared_circular_buffer
{
    mutex_t mtx;
    cond_t cond_r;
    cond_t cond_w;
    size_t mask;
    size_t total_size;
    size_t additional_buffer_size;
    u8 *additional_buffer_ptr;
#ifndef WIN32
    volatile s64 enqueue_index __attribute__ ((aligned (L1_DATA_LINE_SIZE)));
    volatile s64 dequeue_index __attribute__ ((aligned (L1_DATA_LINE_SIZE)));
    struct shared_circular_buffer_slot base[] __attribute__ ((aligned (L1_DATA_LINE_SIZE)));
#else
    volatile s64 enqueue_index;
    volatile s64 dequeue_index;
    struct shared_circular_buffer_slot base[];
#endif
};

u8 *shared_circular_buffer_additional_space_ptr(struct shared_circular_buffer* buffer)
{
    return buffer->additional_buffer_ptr;
}

size_t shared_circular_buffer_additional_space_size(struct shared_circular_buffer* buffer)
{
    return buffer->additional_buffer_size;
}

struct shared_circular_buffer*
shared_circular_buffer_create_ex(u8 log_2_buffer_size, u32 additional_space_bytes)
{
    struct shared_circular_buffer *buffer;

    const size_t header_size = (sizeof(struct shared_circular_buffer) + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;
    size_t buffer_size = sizeof(struct shared_circular_buffer_slot) << log_2_buffer_size;

    size_t additional_space_real_bytes = (additional_space_bytes + 4095) & ~4095;

    const size_t total_buffer_size = ((header_size + buffer_size + 4095) & ~4095) + additional_space_real_bytes;

    buffer = (struct shared_circular_buffer*)mmap(NULL, total_buffer_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

     if(buffer != ((struct shared_circular_buffer*)MAP_FAILED))
    {
        memset(buffer, 0, header_size);

        if(mutex_init_process_shared(&buffer->mtx) != 0)
        {
            munmap(buffer, total_buffer_size);
            return NULL;
        }
        if(cond_init_process_shared(&buffer->cond_r) != 0)
        {
            mutex_destroy(&buffer->mtx);
            munmap(buffer, total_buffer_size);
            return NULL;
        }

        if(cond_init_process_shared(&buffer->cond_w) != 0)
        {
            cond_finalize(&buffer->cond_r);
            mutex_destroy(&buffer->mtx);
            munmap(buffer, total_buffer_size);
            return NULL;
        }

        buffer->enqueue_index = 0;
        buffer->dequeue_index = 0;
        buffer->mask = (1 << log_2_buffer_size) - 1;
        buffer->total_size = total_buffer_size;
        buffer->additional_buffer_size = additional_space_real_bytes;
        buffer->additional_buffer_ptr = &((u8*)buffer)[total_buffer_size - additional_space_real_bytes];

        return buffer;
    }
    else
    {
        return NULL;
    }
}

struct shared_circular_buffer*
shared_circular_buffer_create(u8 log_2_buffer_size)
{
    struct shared_circular_buffer* ret = shared_circular_buffer_create_ex(log_2_buffer_size, 0);
    return ret;
}

void
shared_circular_buffer_destroy(struct shared_circular_buffer* buffer)
{
    if(buffer != NULL)
    {
        cond_finalize(&buffer->cond_w);
        cond_finalize(&buffer->cond_r);
        mutex_destroy(&buffer->mtx);
        munmap(buffer, buffer->total_size);
    }
}

struct shared_circular_buffer_slot*
shared_circular_buffer_prepare_enqueue(struct shared_circular_buffer* buffer)
{
    struct shared_circular_buffer_slot *ret;
    
    mutex_lock(&buffer->mtx);
    
    for(;;)
    {
        s64 di = buffer->dequeue_index;
        s64 ei = buffer->enqueue_index;
        
        if((ei >= di) && ((ei - di) <= (s64)buffer->mask))
        {

            ret = (struct shared_circular_buffer_slot*)&buffer->base[ei & buffer->mask];
            ret->state = 0;
#if DEBUG
            memset(ret->data, 'E', sizeof(ret->data));
#endif
            buffer->enqueue_index = ei + 1;
                
            break;
        }

        cond_wait(&buffer->cond_w, &buffer->mtx); // wait to write
    }
    
    // cond_notify(&buffer->cond_r); // notify reader
    
    mutex_unlock(&buffer->mtx);
    
    return ret;
}

struct shared_circular_buffer_slot*
shared_circular_buffer_try_prepare_enqueue(struct shared_circular_buffer* buffer)
{
    struct shared_circular_buffer_slot *ret;
    
    if(mutex_trylock(&buffer->mtx))
    {
        s64 di = buffer->dequeue_index;
        s64 ei = buffer->enqueue_index;

        if((ei >= di) && ((ei - di) <= (s64)buffer->mask))
        {
            ret = (struct shared_circular_buffer_slot*)&buffer->base[ei & buffer->mask];
            ret->state = 0;

#if DEBUG
            memset(ret->data, 'e', sizeof(ret->data));
#endif

            buffer->enqueue_index = ei + 1;
        }
        else
        {
            ret = NULL;
        }


        mutex_unlock(&buffer->mtx);
    
        return ret;
    }

    return NULL;
}

void
shared_circular_buffer_commit_enqueue(struct shared_circular_buffer* buffer, struct shared_circular_buffer_slot* slot)
{
    mutex_lock(&buffer->mtx);
    slot->state = 1;
    cond_notify(&buffer->cond_r);
    mutex_unlock(&buffer->mtx);
}

size_t
shared_circular_buffer_get_index(struct shared_circular_buffer* buffer, struct shared_circular_buffer_slot* slot)
{
    return slot - buffer->base;
}

bool
shared_circular_buffer_empty(struct shared_circular_buffer* buffer)
{
    bool ret;
    mutex_lock(&buffer->mtx);
    ret = buffer->dequeue_index == buffer->enqueue_index;
    mutex_unlock(&buffer->mtx);
    return ret;
}

size_t
shared_circular_buffer_size(struct shared_circular_buffer* buffer)
{
    size_t ret;
    mutex_lock(&buffer->mtx);
    ret = buffer->enqueue_index - buffer->dequeue_index;
    mutex_unlock(&buffer->mtx);
    return ret;
}

size_t
shared_circular_buffer_avail(struct shared_circular_buffer* buffer)
{
    return buffer->mask - shared_circular_buffer_size(buffer);
}

void
shared_circular_buffer_lock(struct shared_circular_buffer* buffer)
{
    mutex_lock(&buffer->mtx);
}

void
shared_circular_buffer_unlock(struct shared_circular_buffer* buffer)
{
    mutex_unlock(&buffer->mtx);
}

struct shared_circular_buffer_slot*
shared_circular_buffer_prepare_dequeue(struct shared_circular_buffer* buffer)
{
    struct shared_circular_buffer_slot *ret;
    
    mutex_lock(&buffer->mtx);
    
    for(;;)
    {
        s64 di = buffer->dequeue_index;
        s64 ei = buffer->enqueue_index;
        if(di < ei)
        {
            ret = (struct shared_circular_buffer_slot*)&buffer->base[di & buffer->mask];
            u8 * volatile state = &ret->state;
            
            while(*state != 1)
            {
                cond_wait(&buffer->cond_r, &buffer->mtx); // wait to read // there is only one dequeuer so there is no need to reload this slot
            }
            
#if DEBUG
            *state = 2;
#endif
            break;
        }

        cond_wait(&buffer->cond_r, &buffer->mtx); // wait to read
    }

    mutex_unlock(&buffer->mtx);
    
    return ret;
}

struct shared_circular_buffer_slot*
shared_circular_buffer_prepare_dequeue_with_timeout(struct shared_circular_buffer* buffer, s64 timeoutus)
{
    struct shared_circular_buffer_slot *ret;
    
    mutex_lock(&buffer->mtx);
    
    for(;;)
    {
        s64 di = buffer->dequeue_index;
        s64 ei = buffer->enqueue_index;
        if(di < ei)
        {
            ret = (struct shared_circular_buffer_slot*)&buffer->base[di & buffer->mask];
            u8 * volatile state = &ret->state;
            
            while(*state != 1)
            {
                if(cond_timedwait(&buffer->cond_r, &buffer->mtx, timeoutus) != 0) // wait to read // there is only one dequeuer so there is no need to reload this slot
                {
                    ret = NULL;
                    break;
                }
            }
            
#if DEBUG
            *state = 2;
#endif
            break;
        }

        if(cond_timedwait(&buffer->cond_r, &buffer->mtx, timeoutus) != 0) // wait to read
        {
            ret = NULL;
            break;
        }
    }

    mutex_unlock(&buffer->mtx);
    
    return ret;
}

void
shared_circular_buffer_commit_dequeue(struct shared_circular_buffer* buffer)
{
    mutex_lock(&buffer->mtx);
    
#if DEBUG
    struct shared_circular_buffer_slot *ret;
    ret = (struct shared_circular_buffer_slot*)&buffer->base[buffer->dequeue_index & buffer->mask];
    memset(ret->data, 'D', sizeof(ret->data));
#endif
    
    if(++buffer->dequeue_index == buffer->enqueue_index)
    {
        buffer->enqueue_index = 0;
        buffer->dequeue_index = 0;
    }

    cond_notify(&buffer->cond_w); // notify writers
    
    mutex_unlock(&buffer->mtx);
}

/** @} */

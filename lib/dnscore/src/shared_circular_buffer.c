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
 * @defgroup
 * @ingroup
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <dnscore/format.h>

#include "dnscore/dnscore.h"
#include "dnscore/fdtools.h"
#include "dnscore/mutex.h"
#include "dnscore/shared_circular_buffer.h"

#define L1_DATA_LINE_SIZE                        0x40
#define L1_DATA_LINE_MASK                        (L1_DATA_LINE_SIZE - 1)

#define DEBUG_SHARED_CIRCULAR_BUFFER_MEM_USAGE   0
#define DEBUG_SHARED_CIRCULAR_BUFFER_SELF_REPORT 0

#define SHARED_CIRCULAR_BUFFER_FUTEX_PRIORITY    0

#if SHARED_CIRCULAR_BUFFER_FUTEX_PRIORITY

#if DNSCORE_FUTEX_SUPPORT
#define SHARED_CIRCULAR_BUFFER_USES_FUTEX 1
#elif MUTEX_PROCESS_SHARED_SUPPORTED
#define SHARED_CIRCULAR_BUFFER_USES_FUTEX 0
#endif

#else

#if MUTEX_PROCESS_SHARED_SUPPORTED
#define SHARED_CIRCULAR_BUFFER_USES_FUTEX 0
#elif DNSCORE_FUTEX_SUPPORT
#define SHARED_CIRCULAR_BUFFER_USES_FUTEX 1
#endif

#endif // SHARED_CIRCULAR_BUFFER_FUTEX_PRIORITY

#ifndef SHARED_CIRCULAR_BUFFER_USES_FUTEX
#error "No support for process-shared mutexes nor for futexes"
#endif

struct shared_circular_buffer_s
{
#if !SHARED_CIRCULAR_BUFFER_USES_FUTEX
    mutex_t mtx;
    cond_t  cond_r;
    cond_t  cond_w;
#else
    mutex_futex_t mtx __attribute__((aligned(L1_DATA_LINE_SIZE)));
    cond_futex_t  cond_r __attribute__((aligned(L1_DATA_LINE_SIZE)));
    cond_futex_t  cond_w __attribute__((aligned(L1_DATA_LINE_SIZE)));
#endif
    size_t   mask;
    size_t   total_size;
    size_t   additional_buffer_size;
    uint8_t *additional_buffer_ptr;
#if DEBUG_SHARED_CIRCULAR_BUFFER_MEM_USAGE && DNSCORE_DEBUG_HAS_BLOCK_TAG
    debug_memory_by_tag_context_t *mem_ctx;
#endif
#if DEBUG_SHARED_CIRCULAR_BUFFER_SELF_REPORT
    int64_t last_report_time;
    int64_t peak_usage;
#endif
#if __unix__
    volatile int64_t                     enqueue_index __attribute__((aligned(L1_DATA_LINE_SIZE)));
    volatile int64_t                     dequeue_index __attribute__((aligned(L1_DATA_LINE_SIZE)));
    struct shared_circular_buffer_slot_s base[] __attribute__((aligned(L1_DATA_LINE_SIZE)));
#else
    volatile int64_t                   enqueue_index;
    volatile int64_t                   dequeue_index;
    struct shared_circular_buffer_slot base[];
#endif
};

#if !SHARED_CIRCULAR_BUFFER_USES_FUTEX
static inline int  shared_circular_buffer_mutex_init(mutex_t *mtx) { return mutex_init_process_shared(mtx); }
static inline void shared_circular_buffer_mutex_finalise(mutex_t *mtx) { mutex_destroy(mtx); }
static inline void shared_circular_buffer_mutex_lock(mutex_t *mtx) { mutex_lock(mtx); }
static inline bool shared_circular_buffer_mutex_trylock(mutex_t *mtx) { return mutex_trylock(mtx); }
static inline void shared_circular_buffer_mutex_unlock(mutex_t *mtx) { mutex_unlock(mtx); }
static inline int  shared_circular_buffer_cond_init(cond_t *cond) { return cond_init_process_shared(cond); }
static inline void shared_circular_buffer_cond_finalise(cond_t *cond) { cond_finalize(cond); }
static inline void shared_circular_buffer_cond_wait(cond_t *cond, mutex_t *mtx) { cond_wait(cond, mtx); }
static inline int  shared_circular_buffer_cond_timedwait(cond_t *cond, mutex_t *mtx, int64_t timeoutus) { return cond_timedwait(cond, mtx, timeoutus); }
static inline void shared_circular_buffer_cond_notify(cond_t *cond) { cond_notify(cond); }
#else
static inline int shared_circular_buffer_mutex_init(mutex_futex_t *mtx)
{
    mutex_futex_init(mtx);
    return SUCCESS;
}
static inline void shared_circular_buffer_mutex_finalise(mutex_futex_t *mtx) { mutex_futex_finalise(mtx); }
static inline void shared_circular_buffer_mutex_lock(mutex_futex_t *mtx) { mutex_futex_lock(mtx); }
static inline bool shared_circular_buffer_mutex_trylock(mutex_futex_t *mtx) { return mutex_futex_trylock(mtx); }
static inline void shared_circular_buffer_mutex_unlock(mutex_futex_t *mtx) { mutex_futex_unlock(mtx); }
static inline int  shared_circular_buffer_cond_init(cond_futex_t *cond)
{
    cond_futex_init(cond);
    return SUCCESS;
}
static inline void shared_circular_buffer_cond_finalise(cond_futex_t *cond) { cond_futex_finalise(cond); }
static inline void shared_circular_buffer_cond_wait(cond_futex_t *cond, mutex_futex_t *mtx) { cond_futex_wait(cond, mtx); }
static inline int  shared_circular_buffer_cond_timedwait(cond_futex_t *cond, mutex_futex_t *mtx, int64_t timeoutus) { return cond_futex_timedwait(cond, mtx, timeoutus); }
static inline void shared_circular_buffer_cond_notify(cond_futex_t *cond) { cond_futex_notify(cond); }
#endif

#if DEBUG_SHARED_CIRCULAR_BUFFER_SELF_REPORT
static void shared_circular_buffer_stats(struct shared_circular_buffer *buffer)
{
    int64_t now = timeus();
    if(now - buffer->last_report_time > 60 * ONE_SECOND_US)
    {
        buffer->last_report_time = now;
        int64_t size = buffer->mask + 1;
        int64_t used = buffer->enqueue_index - buffer->dequeue_index;
        if(used < 0)
        {
            used = size - used;
        }
        if(buffer->peak_usage < used)
        {
            buffer->peak_usage = used;
        }

        formatln("shared_circular_buffer@%p: free=%lli, used=%lli, peak=%lli, enqueue=%lli, dequeue=%lli", buffer, size - used, used, buffer->peak_usage, buffer->enqueue_index, buffer->dequeue_index);
    }
}
#endif

uint8_t                         *shared_circular_buffer_additional_space_ptr(struct shared_circular_buffer_s *buffer) { return buffer->additional_buffer_ptr; }

size_t                           shared_circular_buffer_additional_space_size(struct shared_circular_buffer_s *buffer) { return buffer->additional_buffer_size; }

struct shared_circular_buffer_s *shared_circular_buffer_create_ex(uint8_t log_2_buffer_size, uint32_t additional_space_bytes)
{
    struct shared_circular_buffer_s *buffer;

    const size_t                     header_size = (sizeof(struct shared_circular_buffer_s) + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;
    size_t                           buffer_size = sizeof(struct shared_circular_buffer_slot_s) << log_2_buffer_size;

    size_t                           additional_space_real_bytes = (additional_space_bytes + 4095) & ~4095;

    const size_t                     total_buffer_size = ((header_size + buffer_size + 4095) & ~4095) + additional_space_real_bytes;

    buffer = (struct shared_circular_buffer_s *)mmap(NULL, total_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if(buffer != ((struct shared_circular_buffer_s *)MAP_FAILED))
    {
        memset(buffer, 0, header_size);

        if(shared_circular_buffer_mutex_init(&buffer->mtx) != 0)
        {
            munmap(buffer, total_buffer_size);
            return NULL;
        }

        if(shared_circular_buffer_cond_init(&buffer->cond_r) != 0)
        {
            shared_circular_buffer_mutex_finalise(&buffer->mtx);
            munmap(buffer, total_buffer_size);
            return NULL;
        }

        if(shared_circular_buffer_cond_init(&buffer->cond_w) != 0)
        {
            shared_circular_buffer_cond_finalise(&buffer->cond_r);
            shared_circular_buffer_mutex_finalise(&buffer->mtx);
            munmap(buffer, total_buffer_size);
            return NULL;
        }

        buffer->enqueue_index = 0;
        buffer->dequeue_index = 0;
        buffer->mask = (1 << log_2_buffer_size) - 1;
        buffer->total_size = total_buffer_size;
        buffer->additional_buffer_size = additional_space_real_bytes;
        buffer->additional_buffer_ptr = &((uint8_t *)buffer)[total_buffer_size - additional_space_real_bytes];

#if DEBUG_SHARED_CIRCULAR_BUFFER_MEM_USAGE && DNSCORE_DEBUG_HAS_BLOCK_TAG
        buffer->mem_ctx = debug_memory_by_tag_new_instance("shrqueue");
#endif
#if DEBUG_SHARED_CIRCULAR_BUFFER_SELF_REPORT
        buffer->last_report_time = 0;
        buffer->peak_usage = 0;
#endif

        return buffer;
    }
    else
    {
        return NULL;
    }
}

struct shared_circular_buffer_s *shared_circular_buffer_create(uint8_t log_2_buffer_size)
{
    struct shared_circular_buffer_s *ret = shared_circular_buffer_create_ex(log_2_buffer_size, 0);
    return ret;
}

void shared_circular_buffer_destroy(struct shared_circular_buffer_s *buffer)
{
    if(buffer != NULL)
    {
#if DEBUG_SHARED_CIRCULAR_BUFFER_MEM_USAGE && DNSCORE_DEBUG_HAS_BLOCK_TAG
        debug_memory_by_tag_delete(buffer->mem_ctx);
#endif
        shared_circular_buffer_cond_finalise(&buffer->cond_w);
        shared_circular_buffer_cond_finalise(&buffer->cond_r);
        shared_circular_buffer_mutex_finalise(&buffer->mtx);
        munmap(buffer, buffer->total_size);
    }
}

struct shared_circular_buffer_slot_s *shared_circular_buffer_prepare_enqueue(struct shared_circular_buffer_s *buffer)
{
    struct shared_circular_buffer_slot_s *ret;

    shared_circular_buffer_mutex_lock(&buffer->mtx);

    for(;;)
    {
        int64_t di = buffer->dequeue_index;
        int64_t ei = buffer->enqueue_index;

        if((ei >= di) && ((ei - di) <= (int64_t)buffer->mask))
        {

            ret = (struct shared_circular_buffer_slot_s *)&buffer->base[ei & buffer->mask];
            ret->state = 0;
#if DEBUG
            memset(ret->data, 'E', sizeof(ret->data));
#endif
            buffer->enqueue_index = ei + 1;

#if DEBUG_SHARED_CIRCULAR_BUFFER_SELF_REPORT
            shared_circular_buffer_stats(buffer);
#endif
            break;
        }

        shared_circular_buffer_cond_wait(&buffer->cond_w, &buffer->mtx); // wait to write
    }

    // shared_circular_buffer_cond_notify(&buffer->cond_r); // notify reader

    shared_circular_buffer_mutex_unlock(&buffer->mtx);

    return ret;
}

struct shared_circular_buffer_slot_s *shared_circular_buffer_try_prepare_enqueue(struct shared_circular_buffer_s *buffer)
{
    struct shared_circular_buffer_slot_s *ret;

    if(shared_circular_buffer_mutex_trylock(&buffer->mtx))
    {
        int64_t di = buffer->dequeue_index;
        int64_t ei = buffer->enqueue_index;

        if((ei >= di) && ((ei - di) <= (int64_t)buffer->mask))
        {
            ret = (struct shared_circular_buffer_slot_s *)&buffer->base[ei & buffer->mask];
            ret->state = 0;
#if DEBUG
            memset(ret->data, 'e', sizeof(ret->data));
#endif
            buffer->enqueue_index = ei + 1;

#if DEBUG_SHARED_CIRCULAR_BUFFER_SELF_REPORT
            shared_circular_buffer_stats(buffer);
#endif
        }
        else
        {
            ret = NULL;
        }

        shared_circular_buffer_mutex_unlock(&buffer->mtx);

        return ret;
    }

    return NULL;
}

void shared_circular_buffer_commit_enqueue(struct shared_circular_buffer_s *buffer, struct shared_circular_buffer_slot_s *slot)
{
    shared_circular_buffer_mutex_lock(&buffer->mtx);
    slot->state = 1;
#if DEBUG
#if DEBUG_SHARED_CIRCULAR_BUFFER_MEM_USAGE && DNSCORE_DEBUG_HAS_BLOCK_TAG
    debug_memory_by_tag_alloc_notify(buffer->mem_ctx, DBGMEMBY_TAG, sizeof(*slot));
#endif
#endif

#if DEBUG_SHARED_CIRCULAR_BUFFER_SELF_REPORT
    shared_circular_buffer_stats(buffer);
#endif
    shared_circular_buffer_cond_notify(&buffer->cond_r);
    shared_circular_buffer_mutex_unlock(&buffer->mtx);
}

size_t shared_circular_buffer_get_index(struct shared_circular_buffer_s *buffer, struct shared_circular_buffer_slot_s *slot) { return slot - buffer->base; }

bool   shared_circular_buffer_empty(struct shared_circular_buffer_s *buffer)
{
    bool ret;
    shared_circular_buffer_mutex_lock(&buffer->mtx);
    ret = buffer->dequeue_index == buffer->enqueue_index;
    shared_circular_buffer_mutex_unlock(&buffer->mtx);
    return ret;
}

size_t shared_circular_buffer_size(struct shared_circular_buffer_s *buffer)
{
    size_t ret;
    shared_circular_buffer_mutex_lock(&buffer->mtx);
    ret = buffer->enqueue_index - buffer->dequeue_index;
    shared_circular_buffer_mutex_unlock(&buffer->mtx);
    return ret;
}

size_t                                shared_circular_buffer_avail(struct shared_circular_buffer_s *buffer) { return buffer->mask - shared_circular_buffer_size(buffer); }

void                                  shared_circular_buffer_lock(struct shared_circular_buffer_s *buffer) { shared_circular_buffer_mutex_lock(&buffer->mtx); }

void                                  shared_circular_buffer_unlock(struct shared_circular_buffer_s *buffer) { shared_circular_buffer_mutex_unlock(&buffer->mtx); }

struct shared_circular_buffer_slot_s *shared_circular_buffer_prepare_dequeue(struct shared_circular_buffer_s *buffer)
{
    struct shared_circular_buffer_slot_s *ret;

    shared_circular_buffer_mutex_lock(&buffer->mtx);

    for(;;)
    {
        int64_t di = buffer->dequeue_index;
        int64_t ei = buffer->enqueue_index;
        if(di < ei)
        {
            ret = (struct shared_circular_buffer_slot_s *)&buffer->base[di & buffer->mask];
            uint8_t *volatile state = &ret->state;

            while(*state != 1)
            {
                shared_circular_buffer_cond_wait(&buffer->cond_r,
                                                 &buffer->mtx); // wait to read // there is only one dequeuer so there is no need to reload this slot
            }

#if DEBUG
            *state = 2;
#endif
#if DEBUG_SHARED_CIRCULAR_BUFFER_SELF_REPORT
            shared_circular_buffer_stats(buffer);
#endif
            break;
        }

        shared_circular_buffer_cond_wait(&buffer->cond_r, &buffer->mtx); // wait to read
    }

    shared_circular_buffer_mutex_unlock(&buffer->mtx);

    return ret;
}

struct shared_circular_buffer_slot_s *shared_circular_buffer_prepare_dequeue_with_timeout(struct shared_circular_buffer_s *buffer, int64_t timeoutus)
{
    struct shared_circular_buffer_slot_s *ret;

    shared_circular_buffer_mutex_lock(&buffer->mtx);

    for(;;)
    {
        int64_t di = buffer->dequeue_index;
        int64_t ei = buffer->enqueue_index;
        if(di < ei)
        {
            ret = (struct shared_circular_buffer_slot_s *)&buffer->base[di & buffer->mask];
            uint8_t *volatile state = &ret->state;

            while(*state != 1)
            {
                if(shared_circular_buffer_cond_timedwait(&buffer->cond_r, &buffer->mtx, timeoutus) != 0) // wait to read // there is only one dequeuer so there is no need to reload this slot
                {
                    ret = NULL;
                    break;
                }
            }

#if DEBUG
            *state = 2;
#endif
#if DEBUG_SHARED_CIRCULAR_BUFFER_SELF_REPORT
            shared_circular_buffer_stats(buffer);
#endif
            break;
        }

        if(shared_circular_buffer_cond_timedwait(&buffer->cond_r, &buffer->mtx, timeoutus) != 0) // wait to read
        {
            ret = NULL;
            break;
        }
    }

    shared_circular_buffer_mutex_unlock(&buffer->mtx);

    return ret;
}

void shared_circular_buffer_commit_dequeue(struct shared_circular_buffer_s *buffer)
{
    shared_circular_buffer_mutex_lock(&buffer->mtx);

#if DEBUG
    struct shared_circular_buffer_slot_s *ret;
    ret = (struct shared_circular_buffer_slot_s *)&buffer->base[buffer->dequeue_index & buffer->mask];
    memset(ret->data, 'D', sizeof(ret->data));

#if DEBUG_SHARED_CIRCULAR_BUFFER_MEM_USAGE && DNSCORE_DEBUG_HAS_BLOCK_TAG
    debug_memory_by_tag_free_notify(buffer->mem_ctx, DBGMEMBY_TAG, sizeof(*ret));
#endif
#endif

    if(++buffer->dequeue_index == buffer->enqueue_index)
    {
#if __unix__
        if(buffer->enqueue_index > 65535) // don't advise for less than a few pages
        {
            intptr_t ptr = (intptr_t)&buffer->base[0];
            ptr += 4095;
            ptr &= ~4095;
            size_t size = buffer->total_size - buffer->additional_buffer_size;
            if(size > 8192)
            {
                size -= 8192;
                madvise((void *)ptr, size, MADV_DONTNEED);
            }
        }
#endif
        buffer->enqueue_index = 0;
        buffer->dequeue_index = 0;

#if DEBUG_SHARED_CIRCULAR_BUFFER_SELF_REPORT
        shared_circular_buffer_stats(buffer);
#endif
    }

    shared_circular_buffer_cond_notify(&buffer->cond_w); // notify writers

    shared_circular_buffer_mutex_unlock(&buffer->mtx);
}

/** @} */

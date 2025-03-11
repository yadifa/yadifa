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

#include "dnscore/dnscore_config.h"
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>

#include "dnscore/dnscore.h"
#include "dnscore/fdtools.h"
#include "dnscore/shared_heap.h"

/** @defgroup
 *  @ingroup
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include <sys/mman.h>
#include <dnscore/mutex.h>
#include <dnscore/format.h>

#define L1_DATA_LINE_SIZE          0x40
#define L1_DATA_LINE_MASK          (L1_DATA_LINE_SIZE - 1)

#define SHARED_HEAP_ALLOC_DEBUG    0
#define SHARED_HEAP_ALLOC_PRINT    0

#define SHARED_HEAP_FUTEX_PRIORITY 0

#if SHARED_HEAP_FUTEX_PRIORITY

#if DNSCORE_FUTEX_SUPPORT
#define SHARED_HEAP_USES_FUTEX 1
#elif MUTEX_PROCESS_SHARED_SUPPORTED
#define SHARED_HEAP_USES_FUTEX 0
#endif

#else

#if MUTEX_PROCESS_SHARED_SUPPORTED
#define SHARED_HEAP_USES_FUTEX 0
#elif DNSCORE_FUTEX_SUPPORT
#define SHARED_HEAP_USES_FUTEX 1
#endif

#endif // SHARED_HEAP_FUTEX_PRIORITY

#ifndef SHARED_HEAP_USES_FUTEX
#error "No support for process-shared mutexes nor for futexes"
#endif

struct shared_heap_bloc_s
{
    int32_t  prev_size;
    int32_t  real_size;

    uint8_t  heap_index;
    uint8_t  allocated;
    uint16_t _reserved0;
    int32_t  size;
};

struct shared_heap_free_bloc_s
{
    int32_t                         prev_size;
    int32_t                         real_size;

    uint8_t                         heap_index;
    uint8_t                         allocated;
    uint16_t                        _reserved0;
    int32_t                         size;

    struct shared_heap_free_bloc_s *next;
    struct shared_heap_free_bloc_s *prev;
};

#define SHARED_HEAP_BLOC_SIZE ((sizeof(struct shared_heap_bloc_s) + 7) & ~7)

struct shared_heap_ctx_s
{
#if !SHARED_HEAP_USES_FUTEX
    mutex_t mtx;
    cond_t  cond;
#else
    mutex_futex_t mtx;
    cond_futex_t  cond;
// #else
//     semaphore_t sem;
#endif
#if DEBUG
#if SHARED_HEAP_ALLOC_DEBUG
    debug_memory_by_tag_context_t *mem_ctx;
#endif
#endif
    struct shared_heap_bloc_s     *base;
    struct shared_heap_free_bloc_s free;
    struct shared_heap_bloc_s     *limit;
    size_t                         size;
};

static struct shared_heap_ctx_s *shared_heaps = NULL;
static int                       shared_heap_next = -1;

#if !SHARED_HEAP_USES_FUTEX

static inline int shared_heap_lock_init(struct shared_heap_ctx_s *ctx)
{
    int ret;
    if((ret = mutex_init_process_shared(&ctx->mtx)) == 0)
    {
        if((ret = cond_init_process_shared(&ctx->cond)) != 0)
        {
            mutex_destroy(&ctx->mtx);
            ret = MAKE_ERRNO_ERROR(ret);
        }
    }
    else
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

static inline void shared_heap_lock_finalize(struct shared_heap_ctx_s *ctx)
{
    cond_finalize(&ctx->cond);
    mutex_destroy(&ctx->mtx);
}

static inline void shared_heap_lock(struct shared_heap_ctx_s *ctx) { mutex_lock(&ctx->mtx); }

static inline bool shared_heap_try_lock(struct shared_heap_ctx_s *ctx)
{
    bool ret = mutex_trylock(&ctx->mtx);
    return ret;
}

static inline void shared_heap_unlock(struct shared_heap_ctx_s *ctx) { mutex_unlock(&ctx->mtx); }

static inline void shared_heap_wait(struct shared_heap_ctx_s *ctx)
{
    // cond_wait(&ctx->cond, &ctx->mtx);
    cond_wait_auto_time_out(&ctx->cond, &ctx->mtx);
}

static inline void shared_heap_notify_unlock(struct shared_heap_ctx_s *ctx)
{
    cond_notify(&ctx->cond); // @NOTE https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=884776
    mutex_unlock(&ctx->mtx);
}

#else

static inline int shared_heap_lock_init(shared_heap_ctx *ctx)
{
    mutex_futex_init(&ctx->mtx);
    cond_futex_init(&ctx->cond);
    return SUCCESS;
}

static inline void shared_heap_lock_finalize(shared_heap_ctx *ctx)
{
    cond_futex_finalise(&ctx->cond);
    mutex_futex_finalise(&ctx->mtx);
}

static inline void shared_heap_lock(shared_heap_ctx *ctx) { mutex_futex_lock(&ctx->mtx); }

static inline bool shared_heap_try_lock(shared_heap_ctx *ctx)
{
    bool ret = mutex_futex_trylock(&ctx->mtx);
    return ret;
}

static inline void shared_heap_unlock(shared_heap_ctx *ctx) { mutex_futex_unlock(&ctx->mtx); }

static inline void shared_heap_wait(shared_heap_ctx *ctx)
{
    // cond_wait(&ctx->cond, &ctx->mtx);
    cond_futex_timedwait(&ctx->cond, &ctx->mtx, ONE_SECOND_US * 10);
}

static inline void shared_heap_notify_unlock(shared_heap_ctx *ctx)
{
    cond_futex_notify(&ctx->cond); // @NOTE https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=884776
    mutex_futex_unlock(&ctx->mtx);
}
#endif

#if 0

static inline void shared_heap_lock_init(shared_heap_ctx *ctx)
{
    semaphone_init_process_shared(&ctx->sem);
}

static inline void shared_heap_lock_finalize(shared_heap_ctx *ctx)
{
    semaphore_finalize(&ctx->sem);
}

static inline void shared_heap_lock(shared_heap_ctx *ctx)
{
    semaphore_lock(&ctx->sem);
}

static inline void shared_heap_unlock(shared_heap_ctx *ctx)
{
    semaphore_unlock(&ctx->sem);
}

static inline void shared_heap_wait(shared_heap_ctx *ctx)
{
    semaphore_unlock(&ctx->sem);
    semaphore_lock(&ctx->sem);
}

static inline void shared_heap_notify_unlock(shared_heap_ctx *ctx)
{
    semaphore_unlock(&ctx->sem);
}

#endif

void shared_heap_check_bloc(uint8_t id, void *bloc_, uint8_t allocated)
{
#if DEBUG
    struct shared_heap_bloc_s *bloc = (struct shared_heap_bloc_s *)bloc_;
    assert(bloc->heap_index == id);
    assert((size_t)bloc->prev_size < shared_heaps[id].size);
    assert((size_t)bloc->real_size < shared_heaps[id].size);
    assert((bloc >= shared_heaps[id].base) && (bloc < shared_heaps[id].limit));

    if(allocated <= 1)
    {
        assert(bloc->allocated == allocated);

        if(bloc->allocated != allocated)
        {
            if(allocated == 1)
            {
                osformatln(termerr, "%i: shared-heap[%i] : double free at %p", getpid(), id, bloc_);
                flusherr();
            }
            else
            {
                osformatln(termerr, "%i: shared-heap[%i] : corruption at %p", id, bloc_);
                flusherr();
            }

            osprint_dump(termerr, bloc, bloc->size, 16, OSPRINT_DUMP_ADDRESS | OSPRINT_DUMP_HEX | OSPRINT_DUMP_TEXT);
            flusherr();
        }
    }

    if(bloc->allocated == 1)
    {
#ifndef NDEBUG
        size_t real_size = (bloc->size + SHARED_HEAP_BLOC_SIZE + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;
        assert((size_t)bloc->real_size == real_size);
#endif
    }
#endif
    (void)id;
    (void)bloc_;
    (void)allocated;
}

void shared_heap_check_ptr(uint8_t id, void *ptr)
{
#if DEBUG
    struct shared_heap_bloc *bloc = (struct shared_heap_bloc *)&(((uint8_t *)ptr)[-SHARED_HEAP_BLOC_SIZE]);
    shared_heap_check_bloc(id, bloc, 1);
#endif
    (void)id;
    (void)ptr;
}

ya_result shared_heap_init()
{
    if(shared_heaps == NULL)
    {
        const size_t ctx_size = (sizeof(struct shared_heap_ctx_s) + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;
        const size_t ctx_array_size = ((ctx_size * 256) + 4095) & ~4095;

        shared_heaps = (struct shared_heap_ctx_s *)mmap(NULL, ctx_array_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

        if(shared_heaps != ((struct shared_heap_ctx_s *)MAP_FAILED))
        {
            memset(shared_heaps, 0, ctx_array_size);
            shared_heap_next = 0;
            return SUCCESS;
        }
        else
        {
            return ERRNO_ERROR;
        }
    }

    return SUCCESS;
}

void shared_heap_finalize()
{
    if(shared_heaps != NULL)
    {
        const size_t ctx_size = (sizeof(struct shared_heap_ctx_s) + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;
        const size_t ctx_array_size = ((ctx_size * 256) + 4095) & ~4095;

        munmap(shared_heaps, ctx_array_size);

        shared_heaps = NULL;
    }
}

ya_result shared_heap_create(size_t size)
{
    if(shared_heap_next < 0)
    {
        return OBJECT_NOT_INITIALIZED;
    }

    size = (size + 4093) & ~4093;

    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if(ptr == MAP_FAILED)
    {
        return ERRNO_ERROR;
    }

    struct shared_heap_ctx_s *ctx = &shared_heaps[shared_heap_next];

    ya_result                 ret;
    if(FAIL(ret = shared_heap_lock_init(ctx)))
    {
        munmap(ptr, size);
        return ret;
    }

    ctx->base = (struct shared_heap_bloc_s *)ptr;
    ctx->limit = (struct shared_heap_bloc_s *)&((uint8_t *)ptr)[size];
    ctx->free.prev_size = 0;
    ctx->free.real_size = 0;
    ctx->free.heap_index = (uint8_t)shared_heap_next;
    ctx->free.allocated = 1;
    ctx->free.next = (struct shared_heap_free_bloc_s *)&((uint8_t *)ptr)[L1_DATA_LINE_SIZE];
    ctx->free.prev = ctx->free.next;
    ctx->size = size;

    ctx->free.next->prev_size = L1_DATA_LINE_SIZE;
    ctx->free.next->real_size = size - L1_DATA_LINE_SIZE * 2;
    ctx->free.next->heap_index = (uint8_t)shared_heap_next;
    ctx->free.next->allocated = 0;
    ctx->free.next->size = 0;
    ctx->free.next->next = &ctx->free;
    ctx->free.next->prev = &ctx->free;

#if DEBUG
#if SHARED_HEAP_ALLOC_DEBUG
    ctx->mem_ctx = debug_memory_by_tag_new_instance("shared-heap");
#endif
#endif

    struct shared_heap_bloc_s *header = (struct shared_heap_bloc_s *)&(((uint8_t *)ptr)[0]);
    header->real_size = L1_DATA_LINE_SIZE;
    header->prev_size = 0;
    header->heap_index = (uint8_t)shared_heap_next;
    header->allocated = 1;
#if DEBUG
    header->_reserved0 = 0x4848;
#endif
    header->size = 0;
    memset((struct shared_heap_bloc_s *)&(((uint8_t *)ptr)[SHARED_HEAP_BLOC_SIZE]), 'H', L1_DATA_LINE_SIZE - SHARED_HEAP_BLOC_SIZE);

    struct shared_heap_bloc_s *footer = (struct shared_heap_bloc_s *)&(((uint8_t *)ptr)[size - L1_DATA_LINE_SIZE]);
    footer->real_size = L1_DATA_LINE_SIZE;
    footer->prev_size = size - L1_DATA_LINE_SIZE * 2;
    footer->heap_index = (uint8_t)shared_heap_next;
    footer->allocated = 1;
#if DEBUG
    footer->_reserved0 = 0x4646;
#endif
    footer->size = 0;
    memset((struct shared_heap_bloc_s *)&(((uint8_t *)ptr)[size - L1_DATA_LINE_SIZE + SHARED_HEAP_BLOC_SIZE]), 'F', L1_DATA_LINE_SIZE - SHARED_HEAP_BLOC_SIZE);

    ret = shared_heap_next;

    while(shared_heap_next < 256)
    {
        ++shared_heap_next;
        if(shared_heaps[shared_heap_next].base == NULL)
        {
            return ret;
        }
    }

    shared_heap_next = 0;

    while(shared_heap_next < ret)
    {
        if(shared_heaps[shared_heap_next].base == NULL)
        {
            return ret;
        }

        shared_heap_next++;
    }

    shared_heap_next = -1;

    return ret;
}

void shared_heap_destroy(uint8_t id)
{
    if(shared_heaps[id].base != NULL)
    {
        shared_heap_lock_finalize(&shared_heaps[id]);
#if DEBUG
        memset(shared_heaps[id].base, 0xfe, shared_heaps[id].size);
#endif
        munmap(shared_heaps[id].base, shared_heaps[id].size);
        shared_heaps[id].base = NULL;
        shared_heaps[id].free.next = NULL;
        shared_heaps[id].free.prev = NULL;
        shared_heaps[id].size = 0;
#if DEBUG
#if SHARED_HEAP_ALLOC_DEBUG
        debug_memory_by_tag_delete(shared_heaps[id].mem_ctx);
        shared_heaps[id].mem_ctx = NULL;
#endif
#endif
    }
    if(shared_heap_next < 0)
    {
        shared_heap_next = id;
    }
}

void *shared_heap_alloc_from_ctx(struct shared_heap_ctx_s *ctx, size_t size)
{
    size_t real_size = (SHARED_HEAP_BLOC_SIZE + size + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;

    shared_heap_lock(ctx);

    struct shared_heap_free_bloc_s *bloc = ctx->free.next;

    while(bloc != &ctx->free)
    {
        assert(bloc->allocated == 0);
        // will be wrong: assert(bloc->real_size >= bloc->size);

        if((size_t)bloc->real_size >= real_size)
        {
            // take from this bloc

            if((size_t)bloc->real_size == real_size)
            {
                // perfect match

                bloc->next->prev = bloc->prev;
                bloc->prev->next = bloc->next;

                // bloc prev & next are now irrelevant

                bloc->allocated = 1;
#if DEBUG
                if(bloc->_reserved0 == 0)
                {
                    bloc->_reserved0 = 0x4141;
                }
#if SHARED_HEAP_ALLOC_DEBUG
                debug_memory_by_tag_alloc_notify(ctx->mem_ctx, DBGMEMBY_TAG, size);
#endif
#endif
                bloc->size = size;

                shared_heap_unlock(ctx);

                return &((uint8_t *)bloc)[SHARED_HEAP_BLOC_SIZE];
            }
            else
            {
                // cut the bloc

                struct shared_heap_free_bloc_s *next_bloc = (struct shared_heap_free_bloc_s *)&(((uint8_t *)bloc)[real_size]);
                next_bloc->real_size = bloc->real_size - real_size;
                next_bloc->prev_size = real_size;

                next_bloc->next = bloc->next;
                next_bloc->prev = bloc->prev;
                bloc->next->prev = next_bloc;
                bloc->prev->next = next_bloc;

                // bloc prev & next are now irrelevant

                next_bloc->heap_index = bloc->heap_index;
                next_bloc->allocated = 0;
#if DEBUG
                next_bloc->_reserved0 = 0x4343;
#endif

                struct shared_heap_free_bloc_s *next_next_bloc = (struct shared_heap_free_bloc_s *)&((uint8_t *)next_bloc)[next_bloc->real_size];
                next_next_bloc->prev_size = next_bloc->real_size;

                bloc->real_size = real_size;

                bloc->allocated = 1;
                bloc->size = size;

#if DEBUG
                shared_heap_check_bloc(bloc->heap_index, bloc, 1);
                shared_heap_check_bloc(bloc->heap_index, next_bloc, 0);
                shared_heap_check_bloc(bloc->heap_index, next_next_bloc, 2);
#if SHARED_HEAP_ALLOC_DEBUG
                debug_memory_by_tag_alloc_notify(ctx->mem_ctx, DBGMEMBY_TAG, size);
#endif
#endif

                shared_heap_unlock(ctx);

                return &((uint8_t *)bloc)[SHARED_HEAP_BLOC_SIZE];
            }
        }
        else
        {
            bloc = bloc->next;
        }
    }

    shared_heap_unlock(ctx);

    return NULL;
}

void *shared_heap_try_alloc_from_ctx(struct shared_heap_ctx_s *ctx, size_t size)
{
    size_t real_size = (SHARED_HEAP_BLOC_SIZE + size + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;

    if(shared_heap_try_lock(ctx))
    {
        struct shared_heap_free_bloc_s *bloc = ctx->free.next;

        while(bloc != &ctx->free)
        {
            assert(bloc->allocated == 0);
            // will be wrong: assert(bloc->real_size >= bloc->size);

            if((size_t)bloc->real_size >= real_size)
            {
                // take from this bloc

                if((size_t)bloc->real_size == real_size)
                {
                    // perfect match

                    bloc->next->prev = bloc->prev;
                    bloc->prev->next = bloc->next;

                    // bloc prev & next are now irrelevant

                    bloc->allocated = 1;
#if DEBUG
                    if(bloc->_reserved0 == 0)
                    {
                        bloc->_reserved0 = 0x4141;
                    }
#if SHARED_HEAP_ALLOC_DEBUG
                    debug_memory_by_tag_alloc_notify(ctx->mem_ctx, DBGMEMBY_TAG, size);
#endif
#endif
                    bloc->size = size;

                    shared_heap_unlock(ctx);

                    return &((uint8_t *)bloc)[SHARED_HEAP_BLOC_SIZE];
                }
                else
                {
                    // cut the bloc

                    struct shared_heap_free_bloc_s *next_bloc = (struct shared_heap_free_bloc_s *)&(((uint8_t *)bloc)[real_size]);
                    next_bloc->real_size = bloc->real_size - real_size;
                    next_bloc->prev_size = real_size;

                    next_bloc->next = bloc->next;
                    next_bloc->prev = bloc->prev;
                    bloc->next->prev = next_bloc;
                    bloc->prev->next = next_bloc;

                    // bloc prev & next are now irrelevant

                    next_bloc->heap_index = bloc->heap_index;
                    next_bloc->allocated = 0;
#if DEBUG
                    next_bloc->_reserved0 = 0x4343;
#endif

                    struct shared_heap_free_bloc_s *next_next_bloc = (struct shared_heap_free_bloc_s *)&((uint8_t *)next_bloc)[next_bloc->real_size];
                    next_next_bloc->prev_size = next_bloc->real_size;

                    bloc->real_size = real_size;

                    bloc->allocated = 1;
                    bloc->size = size;

#if DEBUG
                    shared_heap_check_bloc(bloc->heap_index, bloc, 1);
                    shared_heap_check_bloc(bloc->heap_index, next_bloc, 0);
                    shared_heap_check_bloc(bloc->heap_index, next_next_bloc, 2);
#if SHARED_HEAP_ALLOC_DEBUG
                    debug_memory_by_tag_alloc_notify(ctx->mem_ctx, DBGMEMBY_TAG, size);
#endif
#endif

                    shared_heap_unlock(ctx);

                    return &((uint8_t *)bloc)[SHARED_HEAP_BLOC_SIZE];
                }
            }
            else
            {
                bloc = bloc->next;
            }
        }

        shared_heap_unlock(ctx);
    }

    return NULL;
}

void *shared_heap_wait_alloc_from_ctx(struct shared_heap_ctx_s *ctx, size_t size)
{
    size_t real_size = (SHARED_HEAP_BLOC_SIZE + size + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;

    shared_heap_lock(ctx);

    for(;;)
    {
        struct shared_heap_free_bloc_s *bloc = ctx->free.next;

        while(bloc != &ctx->free)
        {
            assert(bloc->allocated == 0);
            // will be wrong: assert(bloc->real_size >= bloc->size);
#if DEBUG
            shared_heap_check_bloc(bloc->heap_index, bloc, 0);
#endif
            if((size_t)bloc->real_size >= real_size)
            {
                // take from this bloc

                if((size_t)bloc->real_size == real_size)
                {
                    // perfect match

                    bloc->next->prev = bloc->prev;
                    bloc->prev->next = bloc->next;

                    // bloc prev & next are now irrelevant

                    bloc->allocated = 1;
#if DEBUG
                    if(bloc->_reserved0 == 0)
                    {
                        bloc->_reserved0 = 0x4141;
                    }
#if SHARED_HEAP_ALLOC_DEBUG
                    debug_memory_by_tag_alloc_notify(ctx->mem_ctx, DBGMEMBY_TAG, size);
#endif
#endif
                    bloc->size = size;
#if DEBUG
                    shared_heap_check_bloc(bloc->heap_index, bloc, 1);
#endif
                    shared_heap_unlock(ctx);
#if DEBUG
                    memset(&((uint8_t *)bloc)[SHARED_HEAP_BLOC_SIZE], 'A', bloc->real_size - SHARED_HEAP_BLOC_SIZE);
#endif
                    return &((uint8_t *)bloc)[SHARED_HEAP_BLOC_SIZE];
                }
                else
                {
                    // cut the bloc

                    struct shared_heap_free_bloc_s *next_bloc = (struct shared_heap_free_bloc_s *)&(((uint8_t *)bloc)[real_size]);
                    next_bloc->real_size = bloc->real_size - real_size;
                    next_bloc->prev_size = real_size;

                    next_bloc->next = bloc->next;
                    next_bloc->prev = bloc->prev;
                    bloc->next->prev = next_bloc;
                    bloc->prev->next = next_bloc;

                    // bloc prev & next are now irrelevant

                    next_bloc->heap_index = bloc->heap_index;
                    next_bloc->allocated = 0;
#if DEBUG
                    next_bloc->_reserved0 = 0x4343;
#endif
                    struct shared_heap_free_bloc_s *next_next_bloc = (struct shared_heap_free_bloc_s *)&((uint8_t *)next_bloc)[next_bloc->real_size];
                    next_next_bloc->prev_size = next_bloc->real_size;

                    bloc->allocated = 1;
                    bloc->real_size = real_size;
                    bloc->size = size;
#if DEBUG
                    shared_heap_check_bloc(bloc->heap_index, bloc, 1);
                    shared_heap_check_bloc(bloc->heap_index, next_bloc, 0);
                    shared_heap_check_bloc(bloc->heap_index, next_next_bloc, 2);
#if SHARED_HEAP_ALLOC_DEBUG
                    debug_memory_by_tag_alloc_notify(ctx->mem_ctx, DBGMEMBY_TAG, size);
#endif
#endif
                    shared_heap_unlock(ctx);
#if DEBUG
                    memset(&((uint8_t *)bloc)[SHARED_HEAP_BLOC_SIZE], 'a', bloc->real_size - SHARED_HEAP_BLOC_SIZE);
#endif
                    return &((uint8_t *)bloc)[SHARED_HEAP_BLOC_SIZE];
                }
            }
            else
            {
                bloc = bloc->next;
            }
        } // while bloc != ctx->free

        shared_heap_wait(ctx);
    }
}

static void shared_heap_grow_allocated_with_following_free_bloc(struct shared_heap_free_bloc_s *bloc, struct shared_heap_free_bloc_s *next_bloc)
{
#if DEBUG
    shared_heap_check_bloc(bloc->heap_index, bloc, 1);
    shared_heap_check_bloc(next_bloc->heap_index, next_bloc, 0);
#endif

    next_bloc->next->prev = next_bloc->prev;
    next_bloc->prev->next = next_bloc->next;

    bloc->real_size += next_bloc->real_size;

#if DEBUG
    bloc->size = bloc->real_size - SHARED_HEAP_BLOC_SIZE;
#endif

    struct shared_heap_free_bloc_s *next_next_bloc = (struct shared_heap_free_bloc_s *)&((uint8_t *)next_bloc)[next_bloc->real_size];

    next_next_bloc->prev_size = bloc->real_size;
}

/**
 * Merge two blocks in specific states.
 * After the call, the allocated block will nolonger be (obviously).
 */

static void shared_heap_merge_allocated_with_following_free_bloc(struct shared_heap_free_bloc_s *bloc, struct shared_heap_free_bloc_s *next_bloc)
{
#if DEBUG
    shared_heap_check_bloc(bloc->heap_index, bloc, 1);
    shared_heap_check_bloc(next_bloc->heap_index, next_bloc, 0);
#endif

    bloc->real_size += next_bloc->real_size;

#if DEBUG
    bloc->size = bloc->real_size - SHARED_HEAP_BLOC_SIZE;
#endif

    bloc->next = next_bloc->next;
    bloc->next->prev = bloc;

    bloc->prev = next_bloc->prev;
    bloc->prev->next = bloc;

    bloc->allocated = 0;

    struct shared_heap_free_bloc_s *next_next_bloc = (struct shared_heap_free_bloc_s *)&((uint8_t *)next_bloc)[next_bloc->real_size];
    next_next_bloc->prev_size = bloc->real_size;

#if DEBUG
    memset(next_bloc, 'T', L1_DATA_LINE_SIZE);
#endif
}

/**
 * Merge two blocks in specific states.
 * After the call, the allocated block will nolonger be (obviously).
 */

static void shared_heap_merge_free_with_following_allocated_bloc(struct shared_heap_free_bloc_s *bloc, struct shared_heap_free_bloc_s *next_bloc)
{
#if DEBUG
    shared_heap_check_bloc(bloc->heap_index, bloc, 0);
    shared_heap_check_bloc(next_bloc->heap_index, next_bloc, 1);
#endif

    bloc->real_size += next_bloc->real_size;

#if DEBUG
    bloc->size = bloc->real_size - SHARED_HEAP_BLOC_SIZE;
#endif

    struct shared_heap_free_bloc_s *next_next_bloc = (struct shared_heap_free_bloc_s *)&((uint8_t *)next_bloc)[next_bloc->real_size];
    next_next_bloc->prev_size = bloc->real_size;

#if DEBUG
    memset(next_bloc, 'U', L1_DATA_LINE_SIZE);
#endif
}

/**
 * Merge three blocks in specific states.
 * After the call, the allocated block will nolonger be (obviously).
 */

static void shared_heap_merge_allocated_with_surrounding_free_blocs(struct shared_heap_free_bloc_s *prev_bloc, struct shared_heap_free_bloc_s *bloc, struct shared_heap_free_bloc_s *next_bloc)
{
#if DEBUG
    shared_heap_check_bloc(prev_bloc->heap_index, prev_bloc, 0);
    shared_heap_check_bloc(bloc->heap_index, bloc, 1);
    shared_heap_check_bloc(next_bloc->heap_index, next_bloc, 0);
#endif

    // detach the next bloc from the chain
    // merge the 3
    next_bloc->next->prev = next_bloc->prev;
    next_bloc->prev->next = next_bloc->next;

    prev_bloc->real_size += bloc->real_size + next_bloc->real_size;

#if DEBUG
    prev_bloc->size = bloc->real_size - SHARED_HEAP_BLOC_SIZE;
#endif

    struct shared_heap_free_bloc_s *next_next_bloc = (struct shared_heap_free_bloc_s *)&((uint8_t *)next_bloc)[next_bloc->real_size];
    next_next_bloc->prev_size = prev_bloc->real_size;

#if DEBUG
    memset(bloc, 'V', L1_DATA_LINE_SIZE);
    memset(next_bloc, 'W', L1_DATA_LINE_SIZE);
#endif
}

void shared_heap_free_from_ctx(struct shared_heap_ctx_s *ctx, void *ptr)
{
    struct shared_heap_free_bloc_s *bloc = (struct shared_heap_free_bloc_s *)&(((uint8_t *)ptr)[-SHARED_HEAP_BLOC_SIZE]);

    shared_heap_lock(ctx);

#if DEBUG
    shared_heap_check_bloc(bloc->heap_index, bloc, 1);
#if SHARED_HEAP_ALLOC_DEBUG
    debug_memory_by_tag_free_notify(ctx->mem_ctx, DBGMEMBY_TAG, bloc->size);
#endif
#endif

    struct shared_heap_free_bloc_s *next_bloc = (struct shared_heap_free_bloc_s *)&(((uint8_t *)bloc)[bloc->real_size]);

#if DEBUG
    shared_heap_check_bloc(bloc->heap_index, next_bloc, 2);
#endif

    if(next_bloc->allocated == 0)
    {
        struct shared_heap_free_bloc_s *prev_bloc = (struct shared_heap_free_bloc_s *)&(((uint8_t *)bloc)[-bloc->prev_size]);
#if DEBUG
        shared_heap_check_bloc(bloc->heap_index, prev_bloc, 2);
#endif
        if(prev_bloc->allocated == 0)
        {
            // merge 3
#if DEBUG
            prev_bloc->_reserved0 = 0xfe03;
            bloc->_reserved0 = 0xfe13;
            next_bloc->_reserved0 = 0xfe23;
#endif
            shared_heap_merge_allocated_with_surrounding_free_blocs(prev_bloc, bloc, next_bloc);
            bloc = prev_bloc;
        }
        else
        {
            // merge 2
#if DEBUG
            bloc->_reserved0 = 0xfe02;
            next_bloc->_reserved0 = 0xfe12;
#endif

            shared_heap_merge_allocated_with_following_free_bloc(bloc, next_bloc);
        }
    }
    else
    {
        struct shared_heap_free_bloc_s *prev_bloc = (struct shared_heap_free_bloc_s *)&(((uint8_t *)bloc)[-bloc->prev_size]);

#if DEBUG
        shared_heap_check_bloc(bloc->heap_index, prev_bloc, 2);
#endif

        if(prev_bloc->allocated == 0)
        {
            // merge 2
#if DEBUG
            prev_bloc->_reserved0 = 0xfe01;
            bloc->_reserved0 = 0xfe11;
#endif
            shared_heap_merge_free_with_following_allocated_bloc(prev_bloc, bloc);
            bloc = prev_bloc;
        }
        else
        {
#if DEBUG
            bloc->_reserved0 = 0xfe00;
#endif
            bloc->next = &ctx->free;
            bloc->prev = ctx->free.prev;
            ctx->free.prev = bloc;
            bloc->prev->next = bloc;
            bloc->allocated = 0;
        }
    }

#if DEBUG
    assert(bloc->_reserved0 != 0);
#endif

    shared_heap_notify_unlock(ctx);
}

void *shared_heap_realloc_from_ctx(struct shared_heap_ctx_s *ctx, void *ptr, size_t new_size)
{
    struct shared_heap_free_bloc_s *bloc = (struct shared_heap_free_bloc_s *)&(((uint8_t *)ptr)[-SHARED_HEAP_BLOC_SIZE]);

    assert(bloc->allocated == 1);

    if(new_size <= (size_t)bloc->real_size)
    {
        return ptr;
    }

    shared_heap_lock(ctx);

    struct shared_heap_free_bloc_s *next_bloc = (struct shared_heap_free_bloc_s *)&(((uint8_t *)bloc)[bloc->real_size]);

    if(next_bloc->allocated == 0)
    {
        // maybe the next bloc can be stolen from

        size_t real_size = (SHARED_HEAP_BLOC_SIZE + new_size + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;

        size_t needed_size = real_size - bloc->real_size;

        if((size_t)next_bloc->real_size >= needed_size)
        {
            // steal some memory from the next bloc
            //   create a new bloc in the next bloc
            //   update pointers

            if((size_t)next_bloc->real_size == needed_size)
            {
                // remove the bloc from the free chain
                // add its space to the current bloc

                shared_heap_grow_allocated_with_following_free_bloc(bloc, next_bloc);

                shared_heap_unlock(ctx);
            }
            else
            {
                // split the bloc

                struct shared_heap_free_bloc_s *split_bloc = (struct shared_heap_free_bloc_s *)&(((uint8_t *)next_bloc)[needed_size]);
                split_bloc->real_size -= needed_size;
                split_bloc->prev_size = real_size;

                split_bloc->next = next_bloc->next;
                split_bloc->prev = next_bloc->prev;
                split_bloc->next->prev = split_bloc;
                split_bloc->prev->next = split_bloc;

                // bloc prev & next are now irrelevant

                split_bloc->heap_index = next_bloc->heap_index;
                split_bloc->allocated = 0;

                bloc->real_size = real_size;

                shared_heap_unlock(ctx);
            }

            return ptr;
        }
    }

    // cannot grow : allocate a new bloc and free the current one

    shared_heap_unlock(ctx);

    void *new_ptr = shared_heap_alloc_from_ctx(ctx, new_size);
    memcpy(new_ptr, ptr, bloc->size);
    shared_heap_free_from_ctx(ctx, ptr);
    return new_ptr;
}

void *shared_heap_alloc(uint8_t id, size_t size)
{
    void *ptr = shared_heap_alloc_from_ctx(&shared_heaps[id], size);
#if DEBUG && SHARED_HEAP_ALLOC_DEBUG
#if SHARED_HEAP_ALLOC_PRINT
    osformatln(termout, "%i : shared_heap_alloc(%i, %lli) = %p", getpid(), id, size, ptr);
#endif
    if(ptr != NULL)
    {
        shared_heap_ctx *ctx = &shared_heaps[id];
        debug_memory_by_tag_alloc_notify(ctx->mem_ctx, 0, size);
    }
#endif
    return ptr;
}

void *shared_heap_wait_alloc(uint8_t id, size_t size)
{
    void *ptr = shared_heap_wait_alloc_from_ctx(&shared_heaps[id], size);
#if DEBUG && SHARED_HEAP_ALLOC_DEBUG
#if SHARED_HEAP_ALLOC_PRINT
    osformatln(termout, "%i : shared_heap_wait_alloc(%i, %lli) = %p", getpid(), id, size, ptr);
#endif
    if(ptr != NULL)
    {
        shared_heap_ctx *ctx = &shared_heaps[id];
        debug_memory_by_tag_alloc_notify(ctx->mem_ctx, 0, size);
    }
#endif
    return ptr;
}

void *shared_heap_try_alloc(uint8_t id, size_t size)
{
    void *ptr = shared_heap_try_alloc_from_ctx(&shared_heaps[id], size);
#if DEBUG && SHARED_HEAP_ALLOC_DEBUG
#if SHARED_HEAP_ALLOC_PRINT
    osformatln(termout, "%i : shared_heap_try_alloc(%i, %lli) = %p", getpid(), id, size, ptr);
#endif
    if(ptr != NULL)
    {
        shared_heap_ctx *ctx = &shared_heaps[id];
        debug_memory_by_tag_alloc_notify(ctx->mem_ctx, 0, size);
    }
#endif
    return ptr;
}

void shared_heap_free(void *ptr)
{
    assert(ptr != NULL);
    struct shared_heap_free_bloc_s *bloc = (struct shared_heap_free_bloc_s *)&(((uint8_t *)ptr)[-SHARED_HEAP_BLOC_SIZE]);

#if DEBUG && SHARED_HEAP_ALLOC_DEBUG
    shared_heap_ctx *ctx = &shared_heaps[bloc->heap_index];
#if SHARED_HEAP_ALLOC_PRINT
    osformatln(termout, "%i : shared_heap_free(%p) of size=%i", getpid(), ptr, bloc->size);
#endif
    debug_memory_by_tag_free_notify(ctx->mem_ctx, 0, bloc->size);
#endif

    shared_heap_free_from_ctx(&shared_heaps[bloc->heap_index], ptr);
}

void                     *shared_heap_realloc(uint8_t id, void *ptr, size_t new_size) { return shared_heap_realloc_from_ctx(&shared_heaps[id], ptr, new_size); }

struct shared_heap_ctx_s *shared_heap_context_from_id(uint8_t id) { return &shared_heaps[id]; }

void                      shared_heap_check(uint8_t id)
{
    struct shared_heap_ctx_s *ctx = &shared_heaps[id];

    shared_heap_lock(ctx);

    void                            *ptr = ctx->base;
    size_t                           size = ctx->size;

    const struct shared_heap_bloc_s *header = (const struct shared_heap_bloc_s *)&(((uint8_t *)ptr)[0]);
    assert(header->real_size == L1_DATA_LINE_SIZE);
    assert(header->prev_size == 0);
    assert(header->heap_index == id);
    assert(header->allocated == 1);
    assert(header->size == 0);
    // memset((struct shared_heap_bloc *)&(((uint8_t*)ptr)[SHARED_HEAP_BLOC_SIZE]), 'H', L1_DATA_LINE_SIZE -
    // SHARED_HEAP_BLOC_SIZE);

    const struct shared_heap_bloc_s *footer = (const struct shared_heap_bloc_s *)&(((uint8_t *)ptr)[size - L1_DATA_LINE_SIZE]);
    assert(footer->real_size == L1_DATA_LINE_SIZE);
    // assert(footer->prev_size == size - L1_DATA_LINE_SIZE * 2);
    assert(footer->heap_index == id);
    assert(footer->allocated == 1);
    assert(footer->size == 0);
    // memset((struct shared_heap_bloc *)&(((uint8_t*)ptr)[size - L1_DATA_LINE_SIZE + SHARED_HEAP_BLOC_SIZE]), 'F',
    // L1_DATA_LINE_SIZE - SHARED_HEAP_BLOC_SIZE);

    const struct shared_heap_bloc_s *prev_bloc = header;

    for(;;)
    {
        const struct shared_heap_bloc_s *bloc = (const struct shared_heap_bloc_s *)&(((uint8_t *)prev_bloc)[prev_bloc->real_size]);
        if(bloc >= footer)
        {
            assert(bloc == footer);
            break;
        }
        assert(bloc->prev_size == prev_bloc->real_size);
        assert(bloc->heap_index == id);
        prev_bloc = bloc;
    }

    const struct shared_heap_free_bloc_s *pf = &ctx->free;
    for(;;)
    {
        const struct shared_heap_free_bloc_s *f = pf->next;

        assert(f->heap_index == id);
        assert(f->prev == pf);

        if(f == &ctx->free)
        {
            break;
        }

        assert(f->allocated == 0);

        pf = f;
    }

    // assert(footer->prev_size == prev_bloc->real_size);

    shared_heap_unlock(ctx);
}

void shared_heap_count_allocated(uint8_t id, size_t *totalp, size_t *countp)
{
    struct shared_heap_ctx_s *ctx = &shared_heaps[id];

    shared_heap_lock(ctx);

    const void                      *ptr = ctx->base;
    size_t                           size = ctx->size;

    const struct shared_heap_bloc_s *header = (const struct shared_heap_bloc_s *)&(((uint8_t *)ptr)[L1_DATA_LINE_SIZE]);
    const struct shared_heap_bloc_s *footer = (const struct shared_heap_bloc_s *)&(((uint8_t *)ptr)[size - L1_DATA_LINE_SIZE]);
    const struct shared_heap_bloc_s *prev_bloc = header;

    size_t                           total = 0;
    size_t                           count = 0;

    for(;;)
    {
        const struct shared_heap_bloc_s *bloc = (const struct shared_heap_bloc_s *)&(((uint8_t *)prev_bloc)[prev_bloc->real_size]);

        if(bloc >= footer)
        {
            break;
        }

        if(bloc->allocated == 1)
        {
            total += bloc->real_size;
            ++count;
        }

        prev_bloc = bloc;
    }

    shared_heap_unlock(ctx);

    if(totalp != NULL)
    {
        *totalp = total;
    }

    if(countp != NULL)
    {
        *countp = count;
    }
}

void shared_heap_print_map(uint8_t id, size_t *totalp, size_t *countp)
{
#if DEBUG
    struct shared_heap_ctx_s *ctx = &shared_heaps[id];

    shared_heap_lock(ctx);

    const void                      *ptr = ctx->base;
    size_t                           size = ctx->size;

    const struct shared_heap_bloc_s *header = (const struct shared_heap_bloc_s *)&(((uint8_t *)ptr)[L1_DATA_LINE_SIZE]);
    const struct shared_heap_bloc_s *footer = (const struct shared_heap_bloc_s *)&(((uint8_t *)ptr)[size - L1_DATA_LINE_SIZE]);

    size_t                           total = 0;
    size_t                           count = 0;

    uint8_t                          allocated = 255;
    const uint8_t                   *range_start = NULL;

    const struct shared_heap_bloc_s *bloc = header;

    for(;;)
    {
        if(bloc >= footer)
        {
            if(range_start != NULL)
            {
                formatln("shared-heap[%i] [%p ; %p] %8x allocated=%i", id, range_start, ((uint8_t *)bloc) - 1, (uint8_t *)bloc - range_start, allocated);
            }

            break;
        }

        if(bloc->allocated != allocated)
        {
            if(range_start != NULL)
            {
                formatln("shared-heap[%i] [%p ; %p] %8x allocated=%i", id, range_start, ((uint8_t *)bloc) - 1, (uint8_t *)bloc - range_start, allocated);
            }

            range_start = (const uint8_t *)bloc;
            allocated = bloc->allocated;
        }

        if(bloc->allocated == 1)
        {
            total += bloc->real_size;
            ++count;
        }

        const struct shared_heap_bloc_s *next_bloc = (const struct shared_heap_bloc_s *)&(((uint8_t *)bloc)[bloc->real_size]);
        bloc = next_bloc;
    }

    shared_heap_unlock(ctx);

    if(totalp != NULL)
    {
        *totalp = total;
    }

    if(countp != NULL)
    {
        *countp = count;
    }

    formatln("shared-heap[%i] total=%llu count=%llu", id, total, count);
#else
    (void)id;
    (void)totalp;
    (void)countp;
#endif
}

/** @} */

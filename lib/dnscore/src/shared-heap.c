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

#include "dnscore/dnscore-config.h"
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>

#include "dnscore/dnscore.h"
#include "dnscore/fdtools.h"
#include "dnscore/shared-heap.h"


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

#define L1_DATA_LINE_SIZE 0x40
#define L1_DATA_LINE_MASK (L1_DATA_LINE_SIZE - 1)

#define MUTEX_PROCESS_SHARED_SUPPORTED 1
//#define MUTEX_PROCESS_SHARED_SUPPORTED 0 // experimental, not enough resources to make this work

struct shared_heap_bloc
{
    s32 prev_size;
    s32 real_size;
    
    u8 heap_index;
    u8 allocated;
    u16 _reserved0;
    s32 size;
};

struct shared_heap_free_bloc
{
    s32 prev_size;
    s32 real_size;
    
    u8 heap_index;
    u8 allocated;
    u16 _reserved0;
    s32 size;
    
    struct shared_heap_free_bloc *next;
    struct shared_heap_free_bloc *prev;
};

#define SHARED_HEAP_BLOC_SIZE ((sizeof(struct shared_heap_bloc) + 7) & ~7)

struct shared_heap_ctx
{
#if MUTEX_PROCESS_SHARED_SUPPORTED
    mutex_t mtx;
    cond_t cond;
#else
    semaphore_t sem;
#endif
    struct shared_heap_bloc *base;
    struct shared_heap_free_bloc free;
    struct shared_heap_bloc *limit;
    size_t size;
};

static struct shared_heap_ctx *shared_heaps = NULL;
static int shared_heap_next = -1;

#if MUTEX_PROCESS_SHARED_SUPPORTED

static inline int shared_heap_lock_init(shared_heap_ctx *ctx)
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

static inline void shared_heap_lock_finalize(shared_heap_ctx *ctx)
{
    cond_finalize(&ctx->cond);
    mutex_destroy(&ctx->mtx);
}

static inline void shared_heap_lock(shared_heap_ctx *ctx)
{
    mutex_lock(&ctx->mtx);
}

static inline bool shared_heap_try_lock(shared_heap_ctx *ctx)
{
    bool ret = mutex_trylock(&ctx->mtx);
    return ret;
}

static inline void shared_heap_unlock(shared_heap_ctx *ctx)
{
    mutex_unlock(&ctx->mtx);
}

static inline void shared_heap_wait(shared_heap_ctx *ctx)
{
    // cond_wait(&ctx->cond, &ctx->mtx);
    cond_wait_auto_time_out(&ctx->cond, &ctx->mtx);
}

static inline void shared_heap_notify_unlock(shared_heap_ctx *ctx)
{
    cond_notify(&ctx->cond); // @NOTE https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=884776
    mutex_unlock(&ctx->mtx);
}

#else

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


void
shared_heap_check_bloc(u8 id, void *bloc_, u8 allocated)
{
#if DEBUG
    struct shared_heap_bloc *bloc = (struct shared_heap_bloc*)bloc_;
    assert(bloc->heap_index == id);
    assert((size_t)bloc->prev_size < shared_heaps[id].size);
    assert((size_t)bloc->real_size < shared_heaps[id].size);
    assert((bloc >= shared_heaps[id].base) && (bloc < shared_heaps[id].limit));
    
    if(allocated <= 1)
    {
        assert(bloc->allocated == allocated);
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

void
shared_heap_check_ptr(u8 id, void *ptr)
{
#if DEBUG
    struct shared_heap_bloc *bloc = (struct shared_heap_bloc *)&(((u8*)ptr)[-SHARED_HEAP_BLOC_SIZE]);
    shared_heap_check_bloc(id, bloc, 1);
#endif
    (void)id;
    (void)ptr;
}

ya_result
shared_heap_init()
{
    if(shared_heaps == NULL)
    {
        const size_t ctx_size = (sizeof(struct shared_heap_ctx) + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;
        const size_t ctx_array_size = ((ctx_size * 256) + 4095) & ~4095;

        shared_heaps = (struct shared_heap_ctx*)mmap(NULL, ctx_array_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

        if(shared_heaps != ((struct shared_heap_ctx*)MAP_FAILED))
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

void
shared_heap_finalize()
{
    if(shared_heaps != NULL)
    {
        const size_t ctx_size = (sizeof(struct shared_heap_ctx) + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;
        const size_t ctx_array_size = ((ctx_size * 256) + 4095) & ~4095;
    
        munmap(shared_heaps, ctx_array_size);
        
        shared_heaps = NULL;
    }
}

ya_result
shared_heap_create(size_t size)
{
    if(shared_heap_next < 0)
    {
        return OBJECT_NOT_INITIALIZED;
    }
    
    size = (size + 4093) & ~4093;
    
    void *ptr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    
    if(ptr == MAP_FAILED)
    {
        return ERRNO_ERROR;
    }

    struct shared_heap_ctx *ctx = &shared_heaps[shared_heap_next];

    ya_result ret;
    if(FAIL(ret = shared_heap_lock_init(ctx)))
    {
        munmap(ptr, size);
        return ret;
    }

    ctx->base = (struct shared_heap_bloc*)ptr;
    ctx->limit = (struct shared_heap_bloc*)&((u8*)ptr)[size];
    ctx->free.prev_size = 0;
    ctx->free.real_size = 0;
    ctx->free.heap_index = (u8)shared_heap_next;
    ctx->free.allocated = 1;        
    ctx->free.next = (struct shared_heap_free_bloc*)&((u8*)ptr)[L1_DATA_LINE_SIZE];
    ctx->free.prev = ctx->free.next;
    ctx->size = size;
    
    ctx->free.next->prev_size = L1_DATA_LINE_SIZE;
    ctx->free.next->real_size = size - L1_DATA_LINE_SIZE * 2;
    ctx->free.next->heap_index = (u8)shared_heap_next;
    ctx->free.next->allocated = 0;
    ctx->free.next->size = 0;
    ctx->free.next->next = &ctx->free;
    ctx->free.next->prev = &ctx->free;
    
    struct shared_heap_bloc *header = (struct shared_heap_bloc *)&(((u8*)ptr)[0]);
    header->real_size = L1_DATA_LINE_SIZE;
    header->prev_size = 0;
    header->heap_index = (u8)shared_heap_next;
    header->allocated = 1;
#if DEBUG
    header->_reserved0 = 0x4848;
#endif
    header->size = 0;
    memset((struct shared_heap_bloc *)&(((u8*)ptr)[SHARED_HEAP_BLOC_SIZE]), 'H', L1_DATA_LINE_SIZE - SHARED_HEAP_BLOC_SIZE);

    struct shared_heap_bloc *footer = (struct shared_heap_bloc *)&(((u8*)ptr)[size - L1_DATA_LINE_SIZE]);
    footer->real_size = L1_DATA_LINE_SIZE;
    footer->prev_size = size - L1_DATA_LINE_SIZE * 2;
    footer->heap_index = (u8)shared_heap_next;
    footer->allocated = 1;
#if DEBUG
    footer->_reserved0 = 0x4646;
#endif
    footer->size = 0;
    memset((struct shared_heap_bloc *)&(((u8*)ptr)[size - L1_DATA_LINE_SIZE + SHARED_HEAP_BLOC_SIZE]), 'F', L1_DATA_LINE_SIZE - SHARED_HEAP_BLOC_SIZE);
    
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

void
shared_heap_destroy(u8 id)
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
    }
    if(shared_heap_next < 0)
    {
        shared_heap_next = id;
    }
}

void*
shared_heap_alloc_from_ctx(struct shared_heap_ctx *ctx, size_t size)
{
    size_t real_size = (SHARED_HEAP_BLOC_SIZE + size + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;
    
    shared_heap_lock(ctx);
    
    struct shared_heap_free_bloc *bloc = ctx->free.next;
    
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
#endif
                bloc->size = size;
                
                shared_heap_unlock(ctx);
                
                return &((u8*)bloc)[SHARED_HEAP_BLOC_SIZE];
            }
            else
            {
                // cut the bloc

                struct shared_heap_free_bloc *next_bloc = (struct shared_heap_free_bloc*)&(((u8*)bloc)[real_size]);
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
                
                struct shared_heap_free_bloc *next_next_bloc = (struct shared_heap_free_bloc*)&((u8*)next_bloc)[next_bloc->real_size];
                next_next_bloc->prev_size = next_bloc->real_size;
                
                bloc->real_size = real_size;
                
                bloc->allocated = 1;
                bloc->size = size;
                
#if DEBUG
                shared_heap_check_bloc(bloc->heap_index, bloc, 1);
                shared_heap_check_bloc(bloc->heap_index, next_bloc, 0);
                shared_heap_check_bloc(bloc->heap_index, next_next_bloc, 2);
#endif
                
                shared_heap_unlock(ctx);
                
                return &((u8*)bloc)[SHARED_HEAP_BLOC_SIZE];
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

void*
shared_heap_try_alloc_from_ctx(struct shared_heap_ctx *ctx, size_t size)
{
    size_t real_size = (SHARED_HEAP_BLOC_SIZE + size + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;

    if(shared_heap_try_lock(ctx))
    {
        struct shared_heap_free_bloc *bloc = ctx->free.next;

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
#endif
                    bloc->size = size;

                    shared_heap_unlock(ctx);

                    return &((u8*)bloc)[SHARED_HEAP_BLOC_SIZE];
                }
                else
                {
                    // cut the bloc

                    struct shared_heap_free_bloc *next_bloc = (struct shared_heap_free_bloc*)&(((u8*)bloc)[real_size]);
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

                    struct shared_heap_free_bloc *next_next_bloc = (struct shared_heap_free_bloc*)&((u8*)next_bloc)[next_bloc->real_size];
                    next_next_bloc->prev_size = next_bloc->real_size;

                    bloc->real_size = real_size;

                    bloc->allocated = 1;
                    bloc->size = size;

#if DEBUG
                    shared_heap_check_bloc(bloc->heap_index, bloc, 1);
                    shared_heap_check_bloc(bloc->heap_index, next_bloc, 0);
                    shared_heap_check_bloc(bloc->heap_index, next_next_bloc, 2);
#endif

                    shared_heap_unlock(ctx);

                    return &((u8*)bloc)[SHARED_HEAP_BLOC_SIZE];
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

void*
shared_heap_wait_alloc_from_ctx(struct shared_heap_ctx *ctx, size_t size)
{
    size_t real_size = (SHARED_HEAP_BLOC_SIZE + size + L1_DATA_LINE_MASK) & ~L1_DATA_LINE_MASK;
    
    shared_heap_lock(ctx);
    
    for(;;)
    {
        struct shared_heap_free_bloc *bloc = ctx->free.next;
        
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
#endif
                    bloc->size = size;
#if DEBUG
                    shared_heap_check_bloc(bloc->heap_index, bloc, 1);
#endif
                    shared_heap_unlock(ctx);
#if DEBUG
                    memset(&((u8*)bloc)[SHARED_HEAP_BLOC_SIZE], 'A', bloc->real_size - SHARED_HEAP_BLOC_SIZE);
#endif
                    return &((u8*)bloc)[SHARED_HEAP_BLOC_SIZE];
                }
                else
                {
                    // cut the bloc

                    struct shared_heap_free_bloc *next_bloc = (struct shared_heap_free_bloc*)&(((u8*)bloc)[real_size]);
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
                    struct shared_heap_free_bloc *next_next_bloc = (struct shared_heap_free_bloc*)&((u8*)next_bloc)[next_bloc->real_size];
                    next_next_bloc->prev_size = next_bloc->real_size;

                    bloc->allocated = 1;
                    bloc->real_size = real_size;
                    bloc->size = size;
#if DEBUG
                    shared_heap_check_bloc(bloc->heap_index, bloc, 1);
                    shared_heap_check_bloc(bloc->heap_index, next_bloc, 0);
                    shared_heap_check_bloc(bloc->heap_index, next_next_bloc, 2);
#endif
                    shared_heap_unlock(ctx);
#if DEBUG
                    memset(&((u8*)bloc)[SHARED_HEAP_BLOC_SIZE], 'a', bloc->real_size - SHARED_HEAP_BLOC_SIZE);
#endif
                    return &((u8*)bloc)[SHARED_HEAP_BLOC_SIZE];
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

static void
shared_heap_grow_allocated_with_following_free_bloc(struct shared_heap_free_bloc *bloc, struct shared_heap_free_bloc *next_bloc)
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
    
    struct shared_heap_free_bloc *next_next_bloc = (struct shared_heap_free_bloc*)&((u8*)next_bloc)[next_bloc->real_size];

    next_next_bloc->prev_size = bloc->real_size;
}

/**
 * Merge two blocks in specific states.
 * After the call, the allocated block will nolonger be (obviously).
 */

static void
shared_heap_merge_allocated_with_following_free_bloc(struct shared_heap_free_bloc *bloc, struct shared_heap_free_bloc *next_bloc)
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

    struct shared_heap_free_bloc *next_next_bloc = (struct shared_heap_free_bloc*)&((u8*)next_bloc)[next_bloc->real_size];
    next_next_bloc->prev_size = bloc->real_size;
    
#if DEBUG
    memset(next_bloc, 'T', L1_DATA_LINE_SIZE);
#endif
}

/**
 * Merge two blocks in specific states.
 * After the call, the allocated block will nolonger be (obviously).
 */

static void
shared_heap_merge_free_with_following_allocated_bloc(struct shared_heap_free_bloc *bloc, struct shared_heap_free_bloc *next_bloc)
{
#if DEBUG
    shared_heap_check_bloc(bloc->heap_index, bloc, 0);
    shared_heap_check_bloc(next_bloc->heap_index, next_bloc, 1);
#endif
    
    bloc->real_size += next_bloc->real_size;
    
#if DEBUG
    bloc->size = bloc->real_size - SHARED_HEAP_BLOC_SIZE;
#endif
            
    struct shared_heap_free_bloc *next_next_bloc = (struct shared_heap_free_bloc*)&((u8*)next_bloc)[next_bloc->real_size];
    next_next_bloc->prev_size = bloc->real_size;

#if DEBUG
    memset(next_bloc, 'U', L1_DATA_LINE_SIZE);
#endif
}

/**
 * Merge three blocks in specific states.
 * After the call, the allocated block will nolonger be (obviously).
 */

static void
shared_heap_merge_allocated_with_surrounding_free_blocs(struct shared_heap_free_bloc *prev_bloc, struct shared_heap_free_bloc *bloc, struct shared_heap_free_bloc *next_bloc)
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
        
    struct shared_heap_free_bloc *next_next_bloc = (struct shared_heap_free_bloc*)&((u8*)next_bloc)[next_bloc->real_size];
    next_next_bloc->prev_size = prev_bloc->real_size;
    
#if DEBUG
    memset(bloc, 'V', L1_DATA_LINE_SIZE);
    memset(next_bloc, 'W', L1_DATA_LINE_SIZE);
#endif
}

void
shared_heap_free_from_ctx(struct shared_heap_ctx *ctx, void *ptr)
{
    struct shared_heap_free_bloc *bloc = (struct shared_heap_free_bloc *)&(((u8*)ptr)[-SHARED_HEAP_BLOC_SIZE]);
    
    shared_heap_lock(ctx);
    
#if DEBUG
    shared_heap_check_bloc(bloc->heap_index, bloc, 1);
#endif
    
    struct shared_heap_free_bloc *next_bloc = (struct shared_heap_free_bloc*)&(((u8*)bloc)[bloc->real_size]);
    
#if DEBUG
    shared_heap_check_bloc(bloc->heap_index, next_bloc, 2);
#endif
    
    if(next_bloc->allocated == 0)
    {
        struct shared_heap_free_bloc *prev_bloc = (struct shared_heap_free_bloc*)&(((u8*)bloc)[-bloc->prev_size]);
        
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
        struct shared_heap_free_bloc *prev_bloc = (struct shared_heap_free_bloc*)&(((u8*)bloc)[-bloc->prev_size]);
        
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

void*
shared_heap_realloc_from_ctx(struct shared_heap_ctx *ctx, void *ptr, size_t new_size)
{
    struct shared_heap_free_bloc *bloc = (struct shared_heap_free_bloc *)&(((u8*)ptr)[-SHARED_HEAP_BLOC_SIZE]);

    assert(bloc->allocated == 1);
    
    if(new_size <= (size_t)bloc->real_size)
    {
        return ptr;
    }
    
    shared_heap_lock(ctx);
    
    struct shared_heap_free_bloc *next_bloc = (struct shared_heap_free_bloc*)&(((u8*)bloc)[bloc->real_size]);
    
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
                
                struct shared_heap_free_bloc *split_bloc = (struct shared_heap_free_bloc*)&(((u8*)next_bloc)[needed_size]);
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

void*
shared_heap_alloc(u8 id, size_t size)
{
    return shared_heap_alloc_from_ctx(&shared_heaps[id], size);
}

void*
shared_heap_wait_alloc(u8 id, size_t size)
{
    return shared_heap_wait_alloc_from_ctx(&shared_heaps[id], size);
}

void*
shared_heap_try_alloc(u8 id, size_t size)
{
    return shared_heap_wait_alloc_from_ctx(&shared_heaps[id], size);
}

void
shared_heap_free(void *ptr)
{
    assert(ptr != NULL);
    struct shared_heap_free_bloc *bloc = (struct shared_heap_free_bloc *)&(((u8*)ptr)[-SHARED_HEAP_BLOC_SIZE]);
    
    shared_heap_free_from_ctx(&shared_heaps[bloc->heap_index], ptr);
}

void*
shared_heap_realloc(u8 id, void *ptr, size_t new_size)
{
    return shared_heap_realloc_from_ctx(&shared_heaps[id], ptr, new_size);
}

struct shared_heap_ctx *
shared_heap_context_from_id(u8 id)
{
    return &shared_heaps[id];
}

void
shared_heap_check(u8 id)
{
    struct shared_heap_ctx *ctx = &shared_heaps[id];
    
    shared_heap_lock(ctx);
    
    void *ptr = ctx->base;
    size_t size = ctx->size;
    
    const struct shared_heap_bloc *header = (const struct shared_heap_bloc *)&(((u8*)ptr)[0]);
    assert(header->real_size == L1_DATA_LINE_SIZE);
    assert(header->prev_size == 0);
    assert(header->heap_index == id);
    assert(header->allocated == 1);
    assert(header->size == 0);
    //memset((struct shared_heap_bloc *)&(((u8*)ptr)[SHARED_HEAP_BLOC_SIZE]), 'H', L1_DATA_LINE_SIZE - SHARED_HEAP_BLOC_SIZE);
    
    const struct shared_heap_bloc *footer = (const struct shared_heap_bloc *)&(((u8*)ptr)[size - L1_DATA_LINE_SIZE]);
    assert(footer->real_size == L1_DATA_LINE_SIZE);
    //assert(footer->prev_size == size - L1_DATA_LINE_SIZE * 2);
    assert(footer->heap_index == id);
    assert(footer->allocated == 1);
    assert(footer->size == 0);
    //memset((struct shared_heap_bloc *)&(((u8*)ptr)[size - L1_DATA_LINE_SIZE + SHARED_HEAP_BLOC_SIZE]), 'F', L1_DATA_LINE_SIZE - SHARED_HEAP_BLOC_SIZE);

    const struct shared_heap_bloc *prev_bloc = header;

    for(;;)
    {
        const struct shared_heap_bloc *bloc = (const struct shared_heap_bloc *)&(((u8*)prev_bloc)[prev_bloc->real_size]);
        if(bloc >= footer)
        {
            assert(bloc == footer);
            break;
        }
        assert(bloc->prev_size == prev_bloc->real_size);
        assert(bloc->heap_index == id);
        prev_bloc = bloc;
    }
    
    const struct shared_heap_free_bloc *pf = &ctx->free;
    for(;;)
    {
        const struct shared_heap_free_bloc *f = pf->next;
        
        assert(f->heap_index == id);
        assert(f->prev == pf);
        
        if(f == &ctx->free)
        {
            break;
        }
        
        assert(f->allocated == 0);
        
        pf = f;
    }
        
    //assert(footer->prev_size == prev_bloc->real_size);
    
    shared_heap_unlock(ctx);
}

void
shared_heap_count_allocated(u8 id, size_t* totalp, size_t* countp)
{
    struct shared_heap_ctx *ctx = &shared_heaps[id];
    
    shared_heap_lock(ctx);
    
    const void *ptr = ctx->base;
    size_t size = ctx->size;
    
    const struct shared_heap_bloc *header = (const struct shared_heap_bloc *)&(((u8*)ptr)[L1_DATA_LINE_SIZE]);
    const struct shared_heap_bloc *footer = (const struct shared_heap_bloc *)&(((u8*)ptr)[size - L1_DATA_LINE_SIZE]);
    const struct shared_heap_bloc *prev_bloc = header;

    size_t total = 0;
    size_t count = 0;
    
    for(;;)
    {
        const struct shared_heap_bloc *bloc = (const struct shared_heap_bloc *)&(((u8*)prev_bloc)[prev_bloc->real_size]);
        
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

/** @} */

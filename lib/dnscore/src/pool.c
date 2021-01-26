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
#include "dnscore/pool.h"
#include "dnscore/logger.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

static mutex_t pool_chain_mtx = MUTEX_INITIALIZER;
static pool_s *pool_chain = NULL;

static void pool_reset_nop(void *ptr, void *args)
{
    (void)ptr;
    (void)args;
}

void pool_init_ex(pool_s *pool, pool_allocate_callback *allocate_, pool_free_callback *free_, pool_reset_callback *reset_, void *allocate_args, const char* name)
{
#if DEBUG
    
    // ensure there are no double initialisations
    
    pool_s *first = pool_chain;
    while(first != NULL)
    {
        if(first == pool)
        {   
            abort();
        }
        first = first->next;
    }
#endif
    ptr_vector_init(&pool->pool);
    pool->allocate_method = allocate_;
    pool->free_method = free_;
    pool->reset_method = reset_;
    pool->allocate_args = allocate_args;
    mutex_init(&pool->mtx);
    pool->allocated_count = 0;
    pool->released_count = 0;
    pool->name = name;
    pool->max_size = 0;
    pool->current_count = 0;
    pool->peak_count = 0;
    pool->hard_limit = FALSE;
    pool->maxed = FALSE;
    
    pool_set_size(pool, 0x10000);
    
    mutex_lock(&pool_chain_mtx);
    pool->next = pool_chain;
    pool_chain = pool;
    mutex_unlock(&pool_chain_mtx);
}

void
pool_init(pool_s *pool, pool_allocate_callback *allocate_, pool_free_callback *free_, void *allocate_args, const char *name)
{
    pool_init_ex(pool, allocate_, free_, pool_reset_nop, allocate_args, name);
}

void
pool_log_stats_ex(pool_s *pool, logger_handle* handle, u32 level)
{
    if(pool != NULL)
    {
        logger_handle_msg(handle, level, "pool '%s' handled %llu allocations and %llu releases; pooled %i maxed at %i; using %u peaked at %u",
                pool->name, pool->allocated_count, pool->released_count,
                pool->pool.offset + 1, pool->max_size,
                pool->current_count, pool->peak_count);
    }
    else
    {
        logger_handle_msg(handle, MSG_ERR, "pool is NULL");
    }
}

void
pool_log_stats(pool_s *pool)
{
    pool_log_stats_ex(pool, MODULE_MSG_HANDLE, MSG_DEBUG);
}

void
pool_log_all_stats_ex(logger_handle* handle, u32 level)
{
    mutex_lock(&pool_chain_mtx);
    pool_s *p = pool_chain;
    while(p != NULL)
    {
        pool_log_stats_ex(p, handle, level);
        p = p->next;
    }
    mutex_unlock(&pool_chain_mtx);
}

void
pool_log_all_stats()
{
    pool_log_all_stats_ex(MODULE_MSG_HANDLE, MSG_DEBUG);
}

void
pool_finalize(pool_s *pool)
{
#if DEBUG
    pool_log_stats(pool);
#endif
    
    mutex_lock(&pool_chain_mtx);
    pool_s **pp = &pool_chain;
    while(*pp != NULL)
    {
        if(*pp == pool)
        {
            *pp = pool->next;
            break;
        }
        pp = &(*pp)->next;
    }
    mutex_unlock(&pool_chain_mtx);
    
    u64 delta;
    mutex_lock(&pool->mtx);
    delta = pool->allocated_count - pool->released_count;
    for(s32 i = 0; i <= pool->pool.offset; i++)
    {
        pool->free_method(pool->pool.data[i], pool->allocate_args);
        pool->pool.data[i] = NULL;
    }
    ptr_vector_destroy(&pool->pool);
    mutex_unlock(&pool->mtx);
    mutex_destroy(&pool->mtx);
    
    pool_log_stats(pool);
    
    if(delta != 0)
    {
        log_warn("pool '%s' leaked: %d items", pool->name, delta);
    }

#if DEBUG
    memset(pool, 0xe0, sizeof(pool_s));
#endif
}

void*
pool_alloc(pool_s *pool)
{
    void *p;
    mutex_lock(&pool->mtx);
    
    if(pool->hard_limit)
    {
        if(pool->current_count >= pool->max_size + 1)
        {
            if(!pool->maxed)    // the maxed flag helps to only complain once the limit is reached
            {
                log_warn("pool '%s' : pool usage reached maximum %i > %i", pool->name, pool->peak_count, pool->max_size);
                pool->maxed = TRUE;
            }
            
            mutex_unlock(&pool->mtx);
            
            return NULL;
        }
        
        pool->maxed = FALSE;
    }
    
    pool->allocated_count++;
    
    if(++pool->current_count > pool->peak_count)
    {
        pool->peak_count = pool->current_count;
    }
    
    if(pool->pool.offset >= 0)
    {
        p = ptr_vector_pop(&pool->pool);
        mutex_unlock(&pool->mtx);
        pool->reset_method(p, pool->allocate_args);
    }
    else
    {
        mutex_unlock(&pool->mtx);
        p = pool->allocate_method(pool->allocate_args);
    }

    log_debug7("pool '%s': alloc %p", pool->name, p);

    return p;
}

void
pool_release(pool_s *pool, void *p)
{
    log_debug7("pool '%s': release %p", pool->name, p);
    
    mutex_lock(&pool->mtx);
    
    if((--pool->current_count) < 0)
    {
        log_err("pool '%s': <0: %d", pool->name, pool->current_count);
    }
    
    if(pool->pool.offset < pool->max_size)
    {
        ptr_vector_append(&pool->pool, p);
    }
    else
    {
        pool->free_method(p, pool->allocate_args);
    }
    pool->released_count++;
    mutex_unlock(&pool->mtx);
}

void
pool_set_size(pool_s *pool, s32 max_size)
{
    yassert(ptr_vector_size(&pool->pool) <= max_size);
    
    ptr_vector_resize(&pool->pool, max_size);
    pool->max_size = max_size - 1;
}

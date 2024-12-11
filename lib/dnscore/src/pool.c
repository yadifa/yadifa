/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
#include "dnscore/pool.h"
#include "dnscore/logger.h"

extern logger_handle_t *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

static mutex_t pool_chain_mtx = MUTEX_INITIALIZER;
static pool_t *pool_chain = NULL;

static void    pool_reset_nop(void *ptr, void *args)
{
    (void)ptr;
    (void)args;
}

void pool_init_ex(pool_t *pool, pool_allocate_callback *allocate_, pool_free_callback *free_, pool_reset_callback *reset_, void *allocate_args, const char *name)
{
#if DEBUG

    // ensure there are no double initialisations

    pool_t *first = pool_chain;
    while(first != NULL)
    {
        if(first == pool)
        {
            abort();
        }
        first = first->next;
    }
#endif
    mutex_init(&pool->mtx);
    cond_init(&pool->cond);
    ptr_vector_init(&pool->pool);
    pool->allocate_method = allocate_;
    pool->free_method = free_;
    pool->reset_method = reset_;
    pool->allocate_args = allocate_args;
    pool->allocated_count = 0;
    pool->released_count = 0;
    pool->name = name;
    pool->max_size = 0;
    pool->wait_count = 0;
    pool->current_count = 0;
    pool->peak_count = 0;
    pool->hard_limit = false;
    pool->maxed = false;

    pool_set_size(pool, 0x10000);

    mutex_lock(&pool_chain_mtx);
    pool->next = pool_chain;
    pool_chain = pool;
    mutex_unlock(&pool_chain_mtx);
}

void pool_init(pool_t *pool, pool_allocate_callback *allocate_, pool_free_callback *free_, void *allocate_args, const char *name) { pool_init_ex(pool, allocate_, free_, pool_reset_nop, allocate_args, name); }

void pool_log_stats_ex(pool_t *pool, logger_handle_t *handle, uint32_t level)
{
    if(pool != NULL)
    {
        logger_handle_msg(handle,
                          level,
                          "pool '%s' handled %llu allocations and %llu releases; pooled %i maxed at %i; using %u peaked at %u",
                          pool->name,
                          pool->allocated_count,
                          pool->released_count,
                          pool->pool.offset + 1,
                          pool->max_size,
                          pool->current_count,
                          pool->peak_count);
    }
    else
    {
        logger_handle_msg(handle, MSG_ERR, "pool is NULL");
    }
}

void pool_log_stats(pool_t *pool) { pool_log_stats_ex(pool, MODULE_MSG_HANDLE, MSG_DEBUG); }

void pool_log_all_stats_ex(logger_handle_t *handle, uint32_t level)
{
    mutex_lock(&pool_chain_mtx);
    pool_t *p = pool_chain;
    while(p != NULL)
    {
        pool_log_stats_ex(p, handle, level);
        p = p->next;
    }
    mutex_unlock(&pool_chain_mtx);
}

void pool_log_all_stats() { pool_log_all_stats_ex(MODULE_MSG_HANDLE, MSG_DEBUG); }

void pool_finalize(pool_t *pool)
{
#if DEBUG
    pool_log_stats(pool);
#endif

    mutex_lock(&pool_chain_mtx);
    pool_t **pp = &pool_chain;
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

    uint64_t delta;
    mutex_lock(&pool->mtx);

    // wait for all the blocked allocations to finish
    // no new blocking allocation should be made when this function is called
    // it's the responsibility of the developer to ensure this

    while(pool->wait_count > 0)
    {
        cond_timedwait(&pool->cond, &pool->mtx, ONE_SECOND_US);
    }

    delta = pool->allocated_count - pool->released_count;
    for(int_fast32_t i = 0; i <= pool->pool.offset; i++)
    {
        pool->free_method(pool->pool.data[i], pool->allocate_args);
        pool->pool.data[i] = NULL;
    }
    ptr_vector_finalise(&pool->pool);
    mutex_unlock(&pool->mtx);
    mutex_destroy(&pool->mtx);

    pool_log_stats(pool);

    if(delta != 0)
    {
        log_warn("pool '%s' leaked: %d items", pool->name, delta);
    }

#if DEBUG
    memset(pool, 0xe0, sizeof(pool_t));
#endif
}

void *pool_alloc(pool_t *pool)
{
    void *p;
    mutex_lock(&pool->mtx);

    if(pool->hard_limit)
    {
        if(pool->current_count > pool->max_size)
        {
            if(!pool->maxed) // the maxed flag helps to only complain once the limit is reached
            {
                log_warn("pool '%s' : pool usage reached maximum %i > %i", pool->name, pool->peak_count, pool->max_size);
                pool->maxed = true;
            }

            mutex_unlock(&pool->mtx);

            return NULL;
        }

        pool->maxed = false;
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

void pool_wait(pool_t *pool)
{
    mutex_lock(&pool->mtx);
    ++pool->wait_count; // keep track of how many are waiting
    while(pool->current_count > pool->max_size)
    {
        cond_wait(&pool->cond, &pool->mtx);
    }
    --pool->wait_count;
    cond_notify(&pool->cond);
    mutex_unlock(&pool->mtx);
}

void pool_timedwait(pool_t *pool, int64_t timeoutus)
{
    mutex_lock(&pool->mtx);
    ++pool->wait_count; // keep track of how many are waiting
    while(pool->current_count > pool->max_size)
    {
        cond_timedwait(&pool->cond, &pool->mtx, timeoutus);
    }
    --pool->wait_count;
    cond_notify(&pool->cond);
    mutex_unlock(&pool->mtx);
}

void *pool_alloc_wait(pool_t *pool)
{
    void *p;
    mutex_lock(&pool->mtx);

    if(pool->current_count > pool->max_size)
    {
        ++pool->wait_count; // keep track of how many are waiting
        do
        {
            cond_timedwait(&pool->cond, &pool->mtx, ONE_SECOND_US);
        } while(pool->current_count > pool->max_size);
        --pool->wait_count;

        cond_notify(&pool->cond);
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

void *pool_alloc_wait_timeout(pool_t *pool, int64_t timeoutus)
{
    void *p;
    mutex_lock(&pool->mtx);

    if(pool->current_count > pool->max_size)
    {
        ++pool->wait_count; // keep track of how many are waiting
        ya_result ret = cond_timedwait(&pool->cond, &pool->mtx, timeoutus);
        if(ret != 0) // timed-out
        {
            --pool->wait_count;
            cond_notify(&pool->cond);
            mutex_unlock(&pool->mtx);
            return NULL;
        }
        --pool->wait_count;
        cond_notify(&pool->cond);
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

void pool_release(pool_t *pool, void *p)
{
    log_debug7("pool '%s': release %p", pool->name, p);

    mutex_lock(&pool->mtx);

    if((--pool->current_count) < 0)
    {
        log_err("pool '%s': <0: %d", pool->name, (int)pool->current_count);
    }

    if(pool->pool.offset <= pool->max_size)
    {
        ptr_vector_append(&pool->pool, p);
    }
    else
    {
        pool->free_method(p, pool->allocate_args);
    }
    pool->released_count++;
    cond_notify(&pool->cond);
    mutex_unlock(&pool->mtx);
}

void pool_set_size(pool_t *pool, int32_t max_size)
{
    yassert(ptr_vector_size(&pool->pool) <= max_size);

    ptr_vector_resize(&pool->pool, max_size);
    pool->max_size = max_size - 1;
}

int32_t pool_get_allocated(pool_t *pool)
{
    mutex_lock(&pool->mtx);
    int32_t ret = pool->current_count;
    mutex_unlock(&pool->mtx);
    return ret;
}

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

#ifndef POOL_H
#define POOL_H

#include <dnscore/ptr_vector.h>
#include <dnscore/mutex.h>

struct pool_s;

typedef void *pool_allocate_callback(void *args);
typedef void  pool_reset_callback(void *ptr, void *args);
typedef void  pool_free_callback(void *ptr, void *args); // for destruction

struct pool_s
{
    mutex_t                 mtx;
    cond_t                  cond;
    ptr_vector_t            pool;
    pool_allocate_callback *allocate_method;
    pool_free_callback     *free_method;
    pool_reset_callback    *reset_method;
    void                   *allocate_args;
    atomic_uint64_t         allocated_count;
    atomic_uint64_t         released_count;
    const char             *name;
    int32_t                 max_size; // do not retain more than this, stored as "max_size - 1"
    atomic_int              current_count;
    atomic_int              peak_count;
    atomic_int              wait_count;

    struct pool_s          *next; // used to keep track of all the memory pools
    bool                    hard_limit;
    bool                    maxed;
};

typedef struct pool_s pool_t;
typedef pool_t        pool_s; // for compatibility

struct logger_handle;

/**
 *
 * @param pool
 * @param allocate
 * @param free
 * @param reset a method to make the pre-used allocated object like new
 * @param allocate_args
 * @param name
 */

void pool_init_ex(pool_t *pool, pool_allocate_callback *allocate, pool_free_callback *free, pool_reset_callback *reset, void *allocate_args, const char *name);
void pool_init(pool_t *pool, pool_allocate_callback *allocate, pool_free_callback *free, void *allocate_args, const char *name);

/**
 * Destroys the pool.
 * Before calling it, all pool users need to have been stopped and memory should have been released.
 */

void  pool_finalize(pool_t *pool);

void  pool_log_stats(pool_t *pool);
void  pool_log_all_stats();

void  pool_log_stats_ex(pool_t *pool, struct logger_handle_s *handle, uint32_t level);
void  pool_log_all_stats_ex(struct logger_handle_s *handle, uint32_t level);

void *pool_alloc(pool_t *pool);

/**
 * Blocs while the maximum number of allocations has been reached.
 * Does NOT guarantee the next allocation will succeed. (race condition)
 *
 * It's unlikely to be the function to use as it does not check for any side shutdown state.
 */

void pool_wait(pool_t *pool);

/**
 * Blocs while the maximum number of allocations has been reached or until the time in us as elapsed.
 * Does NOT guarantee the next allocation will succeed. (race condition)
 *
 * Allows to poll for shutdown states at interval.
 */

void pool_timedwait(pool_t *pool, int64_t timeoutus);

/**
 * Allocates an item but always work in hard-limit mode.
 * It will only return after allocating the item.
 */

void *pool_alloc_wait(pool_t *pool);

/**
 * Allocates an item but always work in hard-limit mode.
 * It will only return after allocating the item or the timeout has elapsed (then it's a NULL).
 */

void   *pool_alloc_wait_timeout(pool_t *pool, int64_t timeoutus);

void    pool_release(pool_t *pool, void *p);

void    pool_set_size(pool_t *pool, int32_t max_size);

int32_t pool_get_allocated(pool_t *pool);

#endif

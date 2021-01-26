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

#ifndef POOL_H
#define POOL_H

#include <dnscore/ptr_vector.h>
#include <dnscore/mutex.h>

struct pool_s;

typedef void *pool_allocate_callback(void *args);
typedef void pool_reset_callback(void *ptr, void *args);
typedef void pool_free_callback(void *ptr, void* args);            // for destruction

struct pool_s
{
    ptr_vector pool;
    pool_allocate_callback *allocate_method;
    pool_free_callback *free_method;
    pool_reset_callback *reset_method;
    mutex_t mtx;
    void *allocate_args;
    volatile u64 allocated_count;
    volatile u64 released_count;
    const char* name;
    s32 max_size;       // do not retain more than this, stored as "max_size - 1"
    volatile s32 current_count;
    volatile s32 peak_count;
    
    struct pool_s *next;
    bool hard_limit;
    bool maxed;
};

typedef struct pool_s pool_s;

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

void pool_init_ex(pool_s *pool, pool_allocate_callback *allocate, pool_free_callback *free, pool_reset_callback *reset, void *allocate_args, const char* name);
void pool_init(pool_s *pool, pool_allocate_callback *allocate, pool_free_callback *free, void *allocate_args, const char* name);
void pool_finalize(pool_s *pool);

void pool_log_stats(pool_s *pool);
void pool_log_all_stats();

void pool_log_stats_ex(pool_s *pool, struct logger_handle* handle, u32 level);
void pool_log_all_stats_ex(struct logger_handle* handle, u32 level);

void *pool_alloc(pool_s *pool);
void pool_release(pool_s *pool, void *p);

void pool_set_size(pool_s *pool, s32 max_size);

#endif

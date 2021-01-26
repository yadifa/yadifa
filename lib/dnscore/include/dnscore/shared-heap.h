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

#pragma once

#include <dnscore/sys_types.h>

struct shared_heap_ctx;

typedef struct shared_heap_ctx shared_heap_ctx;

void shared_heap_check_ptr(u8 id, void *ptr);
void shared_heap_check(u8 id);

ya_result shared_heap_init();
void shared_heap_finalize();

ya_result shared_heap_create(size_t size);
void shared_heap_destroy(u8 id);

void *shared_heap_alloc_from_ctx(struct shared_heap_ctx *ctx, size_t size);
void *shared_heap_try_alloc_from_ctx(struct shared_heap_ctx *ctx, size_t size);
void shared_heap_free_from_ctx(struct shared_heap_ctx *ctx, void *ptr);
void *shared_heap_realloc_from_ctx(struct shared_heap_ctx *ctx, void *ptr, size_t new_size);

void *shared_heap_alloc(u8 id, size_t size);
void *shared_heap_try_alloc(u8 id, size_t size);
void shared_heap_free(void *ptr);
void *shared_heap_realloc(u8 id, void *ptr, size_t new_size);

struct shared_heap_ctx *shared_heap_context_from_id(u8 id);

void* shared_heap_wait_alloc(u8 id, size_t size);
void shared_heap_count_allocated(u8 id, size_t* totalp, size_t* countp);

/** @} */

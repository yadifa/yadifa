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

struct shared_circular_buffer;

struct shared_circular_buffer_slot
{
    u8 state; // allocated (building) / forward / ready / ready-forward
    u8 data[/*L1_DATA_LINE_SIZE - 1*/63];
};

typedef struct shared_circular_buffer shared_circular_buffer;
typedef struct shared_circular_buffer_slot shared_circular_buffer_slot;

struct shared_circular_buffer* shared_circular_buffer_create_ex(u8 log_2_buffer_size, u32 additional_space_bytes);

struct shared_circular_buffer* shared_circular_buffer_create(u8 log_2_buffer_size);

void shared_circular_buffer_destroy(struct shared_circular_buffer* buffer);

struct shared_circular_buffer_slot* shared_circular_buffer_prepare_enqueue(struct shared_circular_buffer* buffer);
struct shared_circular_buffer_slot* shared_circular_buffer_try_prepare_enqueue(struct shared_circular_buffer* buffer);

void shared_circular_buffer_commit_enqueue(struct shared_circular_buffer* buffer, struct shared_circular_buffer_slot *slot);

struct shared_circular_buffer_slot* shared_circular_buffer_prepare_dequeue(struct shared_circular_buffer* buffer);
struct shared_circular_buffer_slot* shared_circular_buffer_prepare_dequeue_with_timeout(struct shared_circular_buffer* buffer, s64 timeoutus);
void shared_circular_buffer_commit_dequeue(struct shared_circular_buffer* buffer);

size_t shared_circular_buffer_get_index(struct shared_circular_buffer* buffer, struct shared_circular_buffer_slot* slot);

bool shared_circular_buffer_empty(struct shared_circular_buffer* buffer);

size_t shared_circular_buffer_size(struct shared_circular_buffer* buffer);
size_t shared_circular_buffer_avail(struct shared_circular_buffer* buffer);

void shared_circular_buffer_lock(struct shared_circular_buffer* buffer);
void shared_circular_buffer_unlock(struct shared_circular_buffer* buffer);

u8 *shared_circular_buffer_additional_space_ptr(struct shared_circular_buffer* buffer);
size_t shared_circular_buffer_additional_space_size(struct shared_circular_buffer* buffer);

/** @} */

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

#ifndef ASYNC_H
#define	ASYNC_H

#define ASYNC_QUEUE_TYPE_RINGBUFFER 1
#define ASYNC_QUEUE_TYPE_DLL        2

#define ASYNC_QUEUE_TYPE ASYNC_QUEUE_TYPE_DLL

#if ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_DLL
#include <dnscore/threaded_dll_cw.h>
#elif ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_RINGBUFFER
#include <dnscore/threaded_ringbuffer_cw.h>
#else
#error "ASYNC_QUEUE_TYPE not set"
#endif
#include <dnscore/pace.h>

#define ASYNC_WAIT_TAG 1

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * 
 * Typically, the handler will be a small function that pushes the message in another processing queue,
 * with or without changing the id (so processors can be chained)
 * 
 * The handler can also be a function that allows another function to proceed (delegation mechanism, in the .net linguo)
 * This would make the handling synchronous but the processing parallel
 * 
 */

#define FREEBSD12_TEST 0
    
// used by threads to process a task then push it further in the assembly line

struct async_message_s;
    
typedef void async_done_callback(struct async_message_s *msg);

struct async_wait_s
{
    mutex_t mutex;
    cond_t  cond_wait;
    volatile s32 wait_count;
    volatile s32 error_code;
#if ASYNC_WAIT_TAG
    u32 tag;
#endif
};

typedef struct async_wait_s async_wait_s;

struct async_queue_s
{
#if ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_DLL
    threaded_dll_cw queue;
#elif ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_RINGBUFFER
    threaded_ringbuffer_cw queue;
#else
    threaded_queue queue;
#endif
    
    pace_s pace;
};

typedef struct async_queue_s async_queue_s;

struct async_message_s
{
    s32 id;         // the message id for the processor
    s32 error_code; // the error code to be set by the processor
    void *args;     // the arguments for the processor
    
    async_done_callback *handler; // what must be called when the processor has finished working
    void *handler_args;             // complementary arguments for the handler
    
    volatile s64 start_time;
};

typedef struct async_message_s async_message_s;

/**
 * 
 * Initialises a synchronisation point
 * count is the number of releases to do before the async_wait call returns
 * 
 * @param aw
 * @param count
 * @return 
 */

void async_wait_init(async_wait_s *aw, s32 count);

/**
 * 
 * Destroys the synchronisation point
 * 
 * @param aw
 * @return 
 */

void async_wait_finalize(async_wait_s *aw);

/**
 * 
 * Initialises a synchronisation point
 * count is the number of releases to do before the async_wait call returns
 * 
 * @param aw
 * @param count
 * @return 
 */

async_wait_s *async_wait_new_instance(s32 count);
void async_wait_destroy(async_wait_s *aw);

async_wait_s *async_wait_create_shared(u8 id, s32 count);
void async_wait_destroy_shared(async_wait_s *aw);

/**
 * Waits until the count has be reduced to 0 (or below if something bad is going on)
 * 
 * @param aw
 * @return 
 */

void async_wait(async_wait_s *aw);

/**
 * Waits until the count has be reduced to 0 (or below if something bad is going on)
 *    OR until the amount of microseconds has elapsed.
 * 
 * @param aw
 * @param usec
 * @return true if and only if the wait counter reached 0
 */

bool async_wait_timeout(async_wait_s *aw, u64 usec);

/**
 * Waits until the count has be reduced to 0 (or below if something bad is going on)
 *    OR until the epoch in microseconds has been reached.
 * 
 * @param aw
 * @param usec
 * @return true if and only if the wait counter reached 0
 */

bool async_wait_timeout_absolute(async_wait_s *aw, u64 epoch_usec);

/**
 * Returns the current value of the counter
 * 
 * @param aw
 * @return 
 */

s32 async_wait_get_counter(async_wait_s *aw);

/**
 * 
 * Decreases the count of that amount
 * 
 * @param aw
 * @param count
 * @return 
 */

void async_wait_progress(async_wait_s *aw, s32 count);

void async_wait_set_first_error(async_wait_s *aw, s32 error);

s32 async_wait_get_error(async_wait_s *aw);

void async_queue_init(async_queue_s *q, u32 size, u64 min_us, u64 max_us, const char* name);

void async_queue_finalize(async_queue_s *q);

bool async_queue_empty(async_queue_s *q);

u32 async_queue_size(async_queue_s *q);

async_message_s *async_message_next(async_queue_s *queue);

async_message_s* async_message_try_next(async_queue_s *queue);

/**
 * 
 * Pushes the message to the queue.
 * The queue is supposed to be read in another thread
 * 
 * @param queue
 * @param msg
 */

void async_message_call(async_queue_s *queue, async_message_s *msg);

/**
 * Sets the handler and handler_args fields to make the message a waiter
 * Restores the fields before returning
 * 
 * @param msg
 */

int async_message_call_and_wait(async_queue_s *queue, async_message_s *msg);

/**
 * Sets the handler and handler_args fields to ignore the result
 * (fire and forget)
 *
 * @param msg
 */

void async_message_call_and_forget(async_queue_s *queue, async_message_s *msg);

/**
 * Sets the handler and handler_args fields to ignore the result
 * (fire and forget)
 *
 * @param msg
 */

void async_message_call_and_release(async_queue_s *queue, async_message_s *msg);

void async_message_pool_init();
async_message_s *async_message_alloc();
void async_message_release(async_message_s *msg);
void async_message_pool_finalize();

#ifdef	__cplusplus
}
#endif

#endif	/* ASYNC_H */


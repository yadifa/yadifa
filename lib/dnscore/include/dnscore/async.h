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

#ifndef ASYNC_H
#define ASYNC_H

#define ASYNC_QUEUE_TYPE_RINGBUFFER 1
#define ASYNC_QUEUE_TYPE_DLL        2

#define ASYNC_QUEUE_TYPE            ASYNC_QUEUE_TYPE_DLL

#if ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_DLL
#include <dnscore/threaded_dll_cw.h>
#elif ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_RINGBUFFER
#include <dnscore/threaded_ringbuffer_cw.h>
#else
#error "ASYNC_QUEUE_TYPE not set"
#endif
#include <dnscore/pace.h>

#define ASYNC_WAIT_TAG       1

#define ASYNC_FUTEX_PRIORITY 0

#if ASYNC_FUTEX_PRIORITY

#if DNSCORE_FUTEX_SUPPORT
#define ASYNC_USES_FUTEX 1
#elif MUTEX_PROCESS_SHARED_SUPPORTED
#define ASYNC_USES_FUTEX 0
#endif

#else

#if MUTEX_PROCESS_SHARED_SUPPORTED
#define ASYNC_USES_FUTEX 0
#elif DNSCORE_FUTEX_SUPPORT
#define ASYNC_USES_FUTEX 1
#endif

#endif // ASYNC_FUTEX_PRIORITY

#ifndef ASYNC_USES_FUTEX
#error "No support for process-shared mutexes nor for futexes"
#endif

#ifdef __cplusplus
extern "C"
{
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
#if ASYNC_USES_FUTEX
    mutex_futex_t mutex_futex;
    cond_futex_t  cond_futex;
#else
    mutex_t mutex;
    cond_t  cond_wait;
#endif
    volatile int32_t wait_count;
    volatile int32_t error_code;
#if ASYNC_WAIT_TAG
    uint32_t tag;
#endif
};

typedef struct async_wait_s async_wait_t;

struct async_queue_s
{
#if ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_DLL
    threaded_dll_cw_t queue;
#elif ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_RINGBUFFER
    threaded_ringbuffer_cw queue;
#else
    threaded_queue queue;
#endif

    pace_t pace;
};

typedef struct async_queue_s async_queue_t;

struct async_message_s
{
    int32_t              id;         // the message id for the processor
    int32_t              error_code; // the error code to be set by the processor
    void                *args;       // the arguments for the processor

    async_done_callback *handler;      // what must be called when the processor has finished working
    void                *handler_args; // complementary arguments for the handler

    volatile int64_t     start_time;
};

typedef struct async_message_s async_message_t;

/**
 *
 * Initialises a synchronisation point
 * count is the number of releases to do before the async_wait call returns
 *
 * @param aw
 * @param count
 * @return
 */

void async_wait_init(async_wait_t *aw, int32_t count);

/**
 *
 * Destroys the synchronisation point
 * Does NOT wait (async_wait is the name of the type)
 *
 * @param aw
 * @return
 */

void async_wait_finalize(async_wait_t *aw);

/**
 *
 * Instantiates a synchronisation point
 * count is the number of "progress" to do before the async_wait call returns
 *
 * @param count the value of the counter, should be > 0
 * @return
 */

async_wait_t *async_wait_new_instance(int32_t count);

/**
 * Uninitialises and frees a synchronisation point
 *
 * @param aw the synchronisation point
 */

void async_wait_finalise(async_wait_t *aw);

/**
 * Creates a new synchronisation point instance, shared among processes.
 * (provided they have access to the same mmap-backed shared memory pool.
 *
 * @param the id of the shared memory pool
 * @param count the value of the counter, should be > 0
 * @return the synchronisation point
 *
 * example:
 *
 * ret = shared_heap_init();
 * ret = shared_heap_create(SHARED_HEAP_SIZE);
 * shared_heap_id = (uint8_t)ret;
 * thread_sync = async_wait_new_instance_shared(shared_heap_id, AW_COUNT);
 *
 */

async_wait_t *async_wait_new_instance_shared(uint8_t id, int32_t count);

/**
 * Uninitialises and frees a synchronisation point.
 *
 * @param aw the synchronisation point
 */

void async_wait_delete_shared(async_wait_t *aw);

/**
 * Waits until the count has be reduced to 0 (or below if something bad is going on)
 *
 * @param aw
 */

void async_wait(async_wait_t *aw);

/**
 * Waits until the count has be reduced to 0 (or below if something bad is going on)
 *    OR until the amount of microseconds has elapsed.
 *
 * @param aw
 * @param relative_usec
 * @return true if and only if the wait counter reached 0
 */

bool async_wait_timeout(async_wait_t *aw, int64_t relative_usec);

/**
 * Waits until the count has be reduced to 0 (or below if something bad is going on)
 *    OR until the epoch in microseconds has been reached.
 *
 * @param aw
 * @param usec
 * @return true if and only if the wait counter reached 0
 */

bool async_wait_timeout_absolute(async_wait_t *aw, int64_t epoch_usec);

/**
 * Returns the current value of the counter
 *
 * @param aw
 * @return
 */

int32_t async_wait_get_counter(async_wait_t *aw);

/**
 *
 * Decreases the count of that amount
 *
 * @param aw
 * @param count
 * @return
 */

void async_wait_progress(async_wait_t *aw, int32_t count);

/**
 * Sets the first error on the async_wait
 * After an error has been set, subsequent calls don't change the value anymore
 *
 * @param aw the async_wait
 * @param error the error code
 */

void async_wait_set_first_error(async_wait_t *aw, int32_t error);

/**
 * Returns the error code in a synchronisation point
 *
 * @param aw the synchronisation point
 * @return the error code
 */

int32_t async_wait_get_error(async_wait_t *aw);

/**
 * Initialises a message queue
 *
 * @param q the queue to initialise
 * @param size the size of the queue
 * @param min_us the smallest pacing time in us
 * @param max_us the biggest pacing time in us
 * @param name the name of the queue (mostly for monitoring)
 */

void async_queue_init(async_queue_t *q, uint32_t size, uint64_t min_us, uint64_t max_us, const char *name);

/**
 * Finalises a message queue
 *
 * @param q the message queue
 */

void async_queue_finalize(async_queue_t *q);

/**
 * Returns true iff the message queue is empty
 *
 * @param q the message queue
 * @return true iff th message queue is empty
 */

bool async_queue_empty(async_queue_t *q);

/**
 * Returns the size of the message queue
 *
 * @param q the message queue
 * @return the size of the message queue
 */

uint32_t async_queue_size(async_queue_t *q);

/**
 * Dequeues the next message from the queue with a timeout of 1 second.
 *
 * @param queue the queue
 * @return the next message or NULL if none was available after 1 second.
 */

async_message_t *async_message_next(async_queue_t *queue);

/**
 * Tries to dequeue the next message from the queue
 *
 * @param queue the queue
 * @return the next message or NULL if none was available
 */

async_message_t *async_message_try_next(async_queue_t *queue);

/**
 * Pushes the message to the queue.
 * The queue is supposed to be read in another thread
 *
 * @param queue the queue
 * @param am the async message to queue
 */

void async_message_call(async_queue_t *queue, async_message_t *am);

/**
 * Sets the handler and handler_args fields to make the message a waiter
 * Restores the fields before returning
 *
 * @param msg
 */

int async_message_call_and_wait(async_queue_t *queue, async_message_t *msg);

/**
 * Sets the handler and handler_args fields to ignore the result
 * (fire and forget)
 *
 * @param am
 */

void async_message_call_and_forget(async_queue_t *queue, async_message_t *am);

/**
 * Sets the handler and handler_args fields to ignore the result
 * (fire and forget)
 *
 * @param queue
 * @param am
 */

void async_message_call_and_release(async_queue_t *queue, async_message_t *am);

/**
 * Initialises the async message pool
 */

void async_message_pool_init();

/**
 * Instantiates a new message, allocating it from the pool.
 *
 * @return a pointer to a new async_message_t
 */

async_message_t *async_message_new_instance();

/**
 * Alias for async_message_new_instance
 *
 * @return a pointer to a new async_message_t
 */

static inline async_message_t *async_message_alloc() { return async_message_new_instance(); }

/**
 * Releases a message to the pool.
 *
 * @param msg the message
 */

void async_message_release(async_message_t *msg);

/**
 * Destroy the message pool.
 */

void async_message_pool_finalize();

#ifdef __cplusplus
}
#endif

#endif /* ASYNC_H */

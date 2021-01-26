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

/** @defgroup threading Threading, pools, queues, ...
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _THREAD_POOL_H
#define	_THREAD_POOL_H

#include <dnscore/thread.h>

#include <dnscore/sys_types.h>
#include <dnscore/random.h>
#include <dnscore/mutex.h>
#include <dnscore/service.h>

#ifdef	__cplusplus
extern "C"
{
#endif

    /*
     * There are two ideas behind the thread_pool
     *
     * _ The thread are launched once so using
     *   a thread is "instant" (about 0.00001 s)
     *
     * _ The tasks can be associated to a counter
     *   so we know exactly how much of these are
     *   running.  Some thread are "irrelevant" for
     *   our concurrence issues (axfr, ixfr)
     *
     *   We just have to have a counter on relevant
     *   threads so we know when we are able to update
     *
     *   NOTE: I actually do not know how many are
     *   scheduled so I could add this in the counter
     *
     */
	
#define THREAD_STATUS_STARTING      0
#define THREAD_STATUS_WAITING       1
#define THREAD_STATUS_WORKING       2
#define THREAD_STATUS_TERMINATING   3
#define THREAD_STATUS_TERMINATED    4

#define THREAD_POOL_SIZE_LIMIT_MIN  1
#define THREAD_POOL_SIZE_LIMIT_DEFAULT   4096
#define THREAD_POOL_SIZE_LIMIT_MAX  65536

typedef void *thread_pool_function(void*);

typedef struct thread_pool_task_counter thread_pool_task_counter;

struct thread_pool_task_counter
{
    mutex_t mutex;
    cond_t cond;
    volatile s32 value;
};

u32 thread_pool_get_max_thread_per_pool_limit();
u32 thread_pool_set_max_thread_per_pool_limit(u32 max_thread_per_pool_limit);

void thread_pool_counter_init(thread_pool_task_counter *counter, s32 value);
void thread_pool_counter_destroy(thread_pool_task_counter *counter);
s32 thread_pool_counter_get_value(thread_pool_task_counter *counter);
s32 thread_pool_counter_add_value(thread_pool_task_counter *counter, s32 value);
s32 thread_pool_counter_wait_below_or_equal(thread_pool_task_counter *counter, s32 value);
s32 thread_pool_counter_wait_equal(thread_pool_task_counter *counter, s32 value);
ya_result thread_pool_counter_wait_equal_with_timeout(thread_pool_task_counter *counter, s32 value, u64 usec);

struct thread_pool_s;

/**
 * Initialises a thread pool
 * 
 * @param thread_count number of threads in the pool (max 255)
 * @param queue_size size of the task queue (when full, enqueue will block until not full)
 * @param pool_name the friendly name of the thread pool
 * @return 
 */

struct thread_pool_s *thread_pool_init_ex(u32 thread_count, u32 queue_size, const char* pool_name);

/**
 * Initialises a thread pool
 * 
 * @param thread_count number of threads in the pool (max 255)
 * @param queue_size size of the task queue (when full, enqueue will block until not full)
 * @return 
 */

struct thread_pool_s *thread_pool_init(u32 thread_count, u32 queue_size);

/**
 * Enqueues a function to be executed by a thread pool
 * Do NOT use this function for concurrent producer-consumer spawning on the same pool as
 * you will end up with a situation where no slots are available for consumers and everybody is waiting.
 * Instead, when spawning a group, use thread_pool_enqueue_calls
 * 
 * @param tp            the thread pool
 * @param func          the function
 * @param parm          the parameter for the function
 * @param counter       an optional counter that will be incremented just before the function is called, and decremented just after
 * @param categoryname  an optional string that will be along the thread, mostly for debugging
 * 
 * @return SUCCESS
 */

ya_result thread_pool_enqueue_call(struct thread_pool_s *tp, thread_pool_function func, void *parm, thread_pool_task_counter *counter, const char *categoryname);

/**
 * Tries to enqueue a function to be executed by a thread pool
 * If the queue is not available (high concurrency or full), the function will give up and return ERROR.
 * 
 * @param tp            the thread pool
 * @param func          the function
 * @param parm          the parameter for the function
 * @param counter       an optional counter that will be incremented just before the function is called, and decremented just after
 * @param categoryname  an optional string that will be along the thread, mostly for debugging
 * 
 * @return SUCCESS if the call has been queued, ERROR if the queue was not available for pushing
 */

ya_result thread_pool_try_enqueue_call(struct thread_pool_s* tp, thread_pool_function func, void* parm, thread_pool_task_counter *counter, const char* categoryname);

struct thread_pool_enqueue_call_item
{
    thread_pool_function *func;
    void *parm;
    thread_pool_task_counter *counter;
    const char *categoryname;
};

typedef struct thread_pool_enqueue_call_item thread_pool_enqueue_call_item;



ya_result thread_pool_stop(struct thread_pool_s* tp);
ya_result thread_pool_destroy(struct thread_pool_s *tp);

/**
 * Waits until all threads in the pool are up and ready
 * 
 * @param tp
 * @return 
 */

ya_result thread_pool_wait_all_running(struct thread_pool_s *tp);

/**
 * Returns the new size of the pool or an error.
 * 
 * @param tp
 * @param new_size
 * @return 
 */

ya_result thread_pool_resize(struct thread_pool_s* tp, u32 new_size);

random_ctx thread_pool_get_random_ctx();
void thread_pool_setup_random_ctx();
void thread_pool_destroy_random_ctx();

u32 thread_pool_get_size(struct thread_pool_s *tp);

/**
 * 
 * Returns the current size of the thread pool
 * 
 * @param tp
 * @return 
 */

int thread_pool_queue_size(struct thread_pool_s *tp);

void thread_pool_wait_queue_empty(struct thread_pool_s *tp);

// before and after a fork

ya_result thread_pool_stop_all();
// fork
ya_result thread_pool_start_all();

#ifdef	__cplusplus
}
#endif

#endif	/* _THREAD_POOL_H */
/** @} */

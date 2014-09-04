/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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

#include <pthread.h>

#include <dnscore/sys_types.h>
#include <dnscore/random.h>

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
	
typedef void *thread_pool_function(void*);

typedef struct thread_pool_task_counter thread_pool_task_counter;

struct thread_pool_task_counter
{
    pthread_mutex_t mutex;
    volatile s32 value;
};

void thread_pool_counter_init(thread_pool_task_counter *counter, s32 value);
void thread_pool_counter_destroy(thread_pool_task_counter *counter);
s32 thread_pool_counter_get_value(thread_pool_task_counter *counter);
s32 thread_pool_counter_add_value(thread_pool_task_counter *counter, s32 value);

struct thread_pool_s;

struct thread_pool_s *thread_pool_init_ex(u8 thread_count, u32 queue_size, const char* pool_name);

struct thread_pool_s *thread_pool_init(u8 thread_count, u32 queue_size);

ya_result thread_pool_enqueue_call(struct thread_pool_s *tp, thread_pool_function func, void *parm, thread_pool_task_counter *counter, const char *categoryname);

ya_result thread_pool_destroy(struct thread_pool_s *tp);

/**
 * Returns the new size of the pool or an error.
 * 
 * @param tp
 * @param new_size
 * @return 
 */

ya_result thread_pool_resize(struct thread_pool_s* tp, u8 new_size);
u8 thread_pool_get_pool_size(struct thread_pool_s *tp);

random_ctx thread_pool_get_random_ctx();
void thread_pool_setup_random_ctx();
void thread_pool_destroy_random_ctx();

u8 thread_pool_get_size(struct thread_pool_s *tp);

// before and after a fork

ya_result thread_pool_stop_all();
// fork
ya_result thread_pool_start_all();

#ifdef	__cplusplus
}
#endif

#endif	/* _THREAD_POOL_H */
/** @} */

/*----------------------------------------------------------------------------*/


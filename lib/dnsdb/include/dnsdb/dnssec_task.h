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
/** @defgroup dnsdbdnssec DNSSEC functions
 *  @ingroup dnsdb
 *  @brief 
 *
 * @{
 */
/*----------------------------------------------------------------------------*/
#ifndef _DNSSEC_TASK_H
#define	_DNSSEC_TASK_H
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include <dnscore/thread_pool.h>

#include <dnsdb/zdb_types.h>
#include <dnsdb/dnssec_keystore.h>
#include <dnsdb/nsec3_item.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dnssec_task_s dnssec_task_s;

#define DNSSEC_THREAD_TASK_FILTER_IGNORE 0
#define DNSSEC_THREAD_TASK_FILTER_ACCEPT 1

typedef ya_result dnssec_thread_task_init_method(dnssec_task_s*);
typedef ya_result dnssec_thread_task_create_context_method(dnssec_task_s*, s32 processor, void**);
typedef void dnssec_thread_task_destroy_context_method(dnssec_task_s*, s32 processor, void*);
typedef ya_result dnssec_thread_task_filter_label_method(dnssec_task_s*, zdb_rr_label *rr_label);
typedef ya_result dnssec_thread_task_filter_nsec3_item_method(dnssec_task_s*, nsec3_zone_item *item, nsec3_zone_item *next);
typedef ya_result dnssec_thread_task_finalise_method(dnssec_task_s*);

typedef struct dnssec_task_vtbl dnssec_task_vtbl;

struct dnssec_task_vtbl
{
    dnssec_thread_task_init_method *init;
    dnssec_thread_task_create_context_method *create_context;
    dnssec_thread_task_destroy_context_method *destroy_context;
    dnssec_thread_task_filter_label_method *filter_label;
    dnssec_thread_task_filter_nsec3_item_method *filter_nsec3_item;
    thread_pool_function *process;
    thread_pool_function *result;
    dnssec_thread_task_finalise_method *finalise;
    const char* name;
};

struct processor_thread_context;
struct dnssec_task_s
{
    const dnssec_task_vtbl *vtbl;       // the specific set of functions for this task (rrsig/rrsig nsec3)
    zdb_zone *zone;                     // the zone being worked on
    void *args;                         // the specific parameters for the set of functions ?
    void **contexts;                    // one for each thread
    struct thread_pool_s *pool;         // thread pool for the parallel processing
    
    volatile ya_result error_code;      // an error code
    volatile bool stop_task;            // stop
    
    /** The do task query queue */
    threaded_queue dnssec_task_query_queue;     //
    /** The do answer query queue */
    threaded_queue dnssec_answer_query_queue;   //
    
    s32 processor_threads_count;        // the number of threads used in the thread pool
};

ya_result dnssec_process_set_default_pool(struct thread_pool_s *pool);

/**
 * Initialises a task with two threads (given by the descriptor)
 * Sets the start time of the task.
 * 
 * @param task task to initialise
 * @param desc structure pointing to the two threads an a friendly name
 */

void dnssec_process_initialize(dnssec_task_s *task, dnssec_task_vtbl *vtbl, struct thread_pool_s *pool, zdb_zone *zone);
ya_result dnssec_process_begin(dnssec_task_s *task);
void dnssec_process_end(dnssec_task_s *task);
void dnssec_process_finalize(dnssec_task_s *task);


/**
 *
 * Processes all the labels of the zone using dnssec_process_task
 *
 * @param db
 * @param task
 * @return
 */

ya_result dnssec_process_zone(dnssec_task_s *task);

#if ZDB_HAS_NSEC3_SUPPORT != 0
ya_result dnssec_process_zone_nsec3(dnssec_task_s* task);
#endif

/**
 * Clears the threads and name of a task.
 * Sets the stop time of the task.
 * 
 * @param task
 */

typedef ya_result dnssec_process_task_callback(dnssec_task_s* task, void* whatyouwant);

/**
 * Using the parameters in task,
 * creates a task and an answer MT queues
 * queues task and answer threads to a thread pool
 * then calls the callback to work on the task/zone.
 * 
 * When the callback returns,
 * waits for the end of the threads,
 * releases resoures,
 * exits with the callback return code.
 * 
 * @param task the task structure
 * @param callback the callback to call
 * @param whatyouwant a pointer passer to the callback
 * 
 * @return an error code
 * 
 */

ya_result dnssec_process_task(dnssec_task_s *task, dnssec_process_task_callback *callback, void *whatyouwant);

#ifdef	__cplusplus
}
#endif

#endif	/* _DNSSEC_KEY_H */


    /*    ------------------------------------------------------------    */

/** @} */

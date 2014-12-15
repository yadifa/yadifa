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
/**
 * @todo Test, debug then do the optimizations. (LATER)
 *
 */

#define RRSIGN_TASKS_C

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>

#include <pthread.h>
#include <sys/timeb.h>

#include <arpa/inet.h>

#include <dnscore/dnsname.h>
#include <dnscore/format.h>

#include <dnscore/thread_pool.h>

#include <dnscore/logger.h>
#include <dnscore/sys_get_cpu_count.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/dnssec.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

/*****************************************************************************/

#define ZDB_THREAD_TAG                  0x444145524854          /* THREAD   */
#define ZDB_THREAD_CONTEXT_TAG          0x545854435450          /* PTCTXT   */
#define THREADED_QUEUE_NODE_TAG         0x444E455545555154	/* TQUEUEND */
#define ZDB_RRSIGUPQ_TAG                0x5150554749535252	/* RRSIGUPQ */

struct thread_pool_s *dnssec_process_default_pool = NULL;


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
 * @param zone the zone to process
 * @param callback the callback to call
 * @param whatyouwant a pointer passer to the callback
 * 
 * @return an error code
 */

ya_result
dnssec_process_begin(dnssec_task_s *task)
{
    if(task == NULL || task->vtbl == NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }
    
    // setup the thread pool.
    // if none was set in the parameters (usual case), use the default dnssec one
    
    struct thread_pool_s *pool;
    s32 processor_threads_count;
    
    if(task->pool != NULL)
    {
        processor_threads_count = thread_pool_get_pool_size(task->pool);
    
        if(processor_threads_count < 2)
        {
            return INVALID_ARGUMENT_ERROR; // at least 2 threads are required
        }
        
        pool = task->pool;
    }
    else
    {
        if(dnssec_process_default_pool == NULL)
        {
            return INVALID_STATE_ERROR;
        }
        
        processor_threads_count = thread_pool_get_pool_size(dnssec_process_default_pool);
        
        pool = dnssec_process_default_pool;
    }
    
    processor_threads_count--;

#if DNSSEC_DEBUGLEVEL>1
    formatln("processor_threads_count = %i", processor_threads_count);
#endif

    /*
     * Prepare & Start the threads
     */

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: starting answer processor");
#endif

    ya_result ret;
    
    void *processor_context;
    
    if(FAIL(ret = task->vtbl->create_context(task, 0, &processor_context)))
    {
        log_err("dnssec_process_zone: create context : %r", ret);

        return ret;
    }

    if(FAIL(ret = thread_pool_enqueue_call(pool, task->vtbl->result, processor_context, NULL, task->vtbl->name)))
    {
        DIE(DNSSEC_ERROR_CANTPOOLTHREAD);
    }
    
    /* The array of contextes for each thread */
    void** contexts;
    MALLOC_OR_DIE(void**, contexts, sizeof(void*) * (processor_threads_count + 1), ZDB_THREAD_CONTEXT_TAG);
    ZEROMEMORY(contexts, sizeof(void*) * (processor_threads_count + 1));
    contexts[0] = processor_context;

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: starting %d query processors", processor_threads_count);
#endif

    for(int processor = 1; processor <= processor_threads_count; processor++)
    {
        if(FAIL(ret = task->vtbl->create_context(task, processor, &processor_context)))
        {
            log_err("dnssec_process_zone: create context : %r", ret);
            break;
        }

        contexts[processor] = processor_context;
        
        if(FAIL(ret = thread_pool_enqueue_call(pool, task->vtbl->process, processor_context, NULL, task->vtbl->name)))
        {
            log_err("dnssec_process_zone: thread_pool_enqueue_call, critical fail: %r", ret);
            logger_flush();
            log_quit("dnssec_process_zone: thread_pool_enqueue_call: %r", ret);
            break;
        }
    }
    
    task->contexts = contexts;
    task->processor_threads_count = processor_threads_count;
    
    return ret;
}

void
dnssec_process_end(dnssec_task_s *task)
{
    for(int i = 1; i <= task->processor_threads_count; i++)
    {
        threaded_queue_enqueue(&task->dnssec_task_query_queue, NULL);
    }

    task->processor_threads_count = 0;
    
    /* Wait until the last thread has read its "NULL" query
     * This also means that the last answer has been posted.
     */

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: wait for queries");
#endif

    threaded_queue_wait_empty(&task->dnssec_task_query_queue);

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: destroy queries");
#endif

    /* Wait until the last answer has been processed */

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: post NULL answer");
#endif

    threaded_queue_enqueue(&task->dnssec_answer_query_queue, NULL);

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: wait for answer");
#endif
    /* Wait until the NULL answer has been processed */
    threaded_queue_wait_empty(&task->dnssec_answer_query_queue);

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: destroy answer");
#endif
}

ya_result
dnssec_process_task(dnssec_task_s *task, dnssec_process_task_callback *callback, void *whatyouwant)
{
#if DNSSEC_DEBUGLEVEL > 1
    log_debug("dnssec_process_task: begin");
#endif

    ya_result ret = dnssec_process_begin(task);
    
    /*
     * This is the actual core of the function, everything beside this couple of lines is setup
     *
     * @TODO handle possible error code
     */

    if(ISOK(ret))
    {
#if DNSSEC_DEBUGLEVEL > 1
        log_debug("dnssec_process_task: doing the job");
#endif
        if(FAIL(ret = callback(task, whatyouwant)))
        {
            log_err("dnssec_process_zone: task failed with %r", ret, task->vtbl->name);
        }
    }
    else
    {
#if DNSSEC_DEBUGLEVEL > 1
        log_debug("dnssec_process_task: cannot work, all stop");
#endif
    }

    dnssec_process_end(task);
    
#if DNSSEC_DEBUGLEVEL > 1
    log_debug("dnssec_process_task: end");
#endif

    return ret;
}

ya_result
dnssec_process_set_default_pool(struct thread_pool_s *pool)
{
    if(pool == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    s32 processor_threads_count = thread_pool_get_pool_size(pool);
    
    if(processor_threads_count >= 2)
    {
        dnssec_process_default_pool = pool;
        
        return SUCCESS;
    }
    else
    {
        return INVALID_ARGUMENT_ERROR; // at least 2 threads are required
    }
}

/**
 * Initialises a task with two threads (given by the descriptor)
 * 
 * @param task task to initialise
 * @param desc structure pointing to the two threads an a friendly name
 */

void
dnssec_process_initialize(dnssec_task_s *task, dnssec_task_vtbl *vtbl, struct thread_pool_s *pool, zdb_zone *zone)
{
#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_initialize(%s)", desc->name);
#endif
    
    ZEROMEMORY(task, sizeof(dnssec_task_s));
    task->vtbl = vtbl;
    task->zone = zone;
    task->pool = pool;

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_initialize: creating queues");
#endif

    u32 dnssec_process_queue_size = QUEUE_MAX_SIZE;

    threaded_queue_init(&task->dnssec_task_query_queue, dnssec_process_queue_size);
    threaded_queue_init(&task->dnssec_answer_query_queue, dnssec_process_queue_size);
}

/**
 * Clears the threads and name of a task.
 * 
 * @param task the task structure
 */

void
dnssec_process_finalize(dnssec_task_s *task)
{
#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_finalize(%s)", task->descriptor_name);
#endif
    
    threaded_queue_finalize(&task->dnssec_task_query_queue);
    
#ifdef DEBUG
    memset(&task->dnssec_task_query_queue, 0xfe, sizeof(threaded_queue));
#endif
    
    threaded_queue_finalize(&task->dnssec_answer_query_queue);
    
#ifdef DEBUG
    memset(&task->dnssec_answer_query_queue, 0xfe, sizeof(threaded_queue));
#endif
    
    if(task->contexts != NULL)
    {
        for(int processor = 0; processor <= task->processor_threads_count; processor++)
        {
            if(task->contexts[processor] != NULL)
            {
                task->vtbl->destroy_context(task, processor, task->contexts[processor]);
                task->contexts[processor] = NULL;
            }
        }

#if DNSSEC_DEBUGLEVEL>1
        log_debug("dnssec_process_finalize: free contexts");
#endif

#ifdef DEBUG
        memset(task->contexts, 0xfe, sizeof(void*) * (task->processor_threads_count + 1));
#endif

        free(task->contexts);
        task->contexts = NULL;
    }
    
    task->vtbl = NULL;
}

#if ZDB_HAS_NSEC3_SUPPORT != 0

/**
 * 
 * Applies the defined task to the NSEC3 items of the specified zone, registering changes in the journal.
 * The task is done multithreaded, one label per processing thread.
 * NSEC3 are not processed
 * This function uses dnssec_process_task
 * 
 * @param task the task structure
 * @param zone the zone to process
 * 
 * @return 
 */

static ya_result
dnssec_process_zone_nsec3_body(dnssec_task_s *task, void *not_used)
{
    (void)not_used;
    
    zdb_zone *zone = task->zone;

#if DNSSEC_DEBUGLEVEL>2
    log_debug("dnssec_process_zone_nsec3_body: begin %{dnsname} (%s)", &zone->origin, task->descriptor_name);
#endif
    
    nsec3_zone* n3 = zone->nsec.nsec3;
    
    while(n3 != NULL)
    {
#if DNSSEC_DEBUGLEVEL>2
        u32 nsec3_count = 0;
        log_debug("dnssec_process_zone_nsec3_body: processing NSEC3 collection");
#endif
        
        nsec3_avl_iterator nsec3_items_iter;
        nsec3_avl_iterator_init(&n3->items, &nsec3_items_iter);

        if(nsec3_avl_iterator_hasnext(&nsec3_items_iter))
        {
            nsec3_zone_item* first = nsec3_avl_iterator_next_node(&nsec3_items_iter);
            nsec3_zone_item* item = first;
            nsec3_zone_item* next;

            do
            {
                if(dnscore_shuttingdown())
                {
#if DNSSEC_DEBUGLEVEL>2
                    log_debug("dnssec_process_zone_nsec3_body: STOPPED_BY_APPLICATION_SHUTDOWN");
#endif
                    return STOPPED_BY_APPLICATION_SHUTDOWN;
                }
                
                if(task->stop_task)
                {
                    return SUCCESS;
                }
                
                if(nsec3_avl_iterator_hasnext(&nsec3_items_iter))
                {
                    next = nsec3_avl_iterator_next_node(&nsec3_items_iter);
                }
                else
                {
                    next = first;
                }

                if(task->vtbl->filter_nsec3_item(task, item, next) == DNSSEC_THREAD_TASK_FILTER_ACCEPT)
                {
                    nsec3_rrsig_update_item_s* query;

                    MALLOC_OR_DIE(nsec3_rrsig_update_item_s*, query, sizeof (nsec3_rrsig_update_item_s), ZDB_RRSIGUPQ_TAG);

                    query->zone = zone;
                    query->item = item;
                    query->next = next;
                    query->added_rrsig_sll = NULL;
                    query->removed_rrsig_sll = NULL;

                    yassert(query->item != NULL);

                    threaded_queue_enqueue(&task->dnssec_task_query_queue, query);
                }
                else
                {
                    log_debug7("rrsig: nsec3: ignore %{digest32h}", item->digest);
                    task->vtbl->filter_nsec3_item(task, item, next);
                }

                item = next;

#if DNSSEC_DEBUGLEVEL>2
                nsec3_count++;
#endif
            }
            while(next != first);

        } /* If there is a first item*/
        
#if DNSSEC_DEBUGLEVEL>2
        log_debug("dnssec_process_zone_nsec3_body: processed NSEC3 collection (%d items)", nsec3_count);
#endif

        n3 = n3->next;

    } /* while n3 != NULL */
    
#if DNSSEC_DEBUGLEVEL>2
    log_debug("dnssec_process_zone_nsec3_body: end %{dnsname} (%s)", &zone->origin, task->descriptor_name);
#endif
    
    return SUCCESS;
}

/**
 * 
 * Applies the defined task to NSEC3 part of the specified zone (registering changes in the journal?)
 * The task is done multithreaded, one label per processing thread.
 * 
 * @param task
 * @param zone
 * @return 
 */

ya_result
dnssec_process_zone_nsec3(dnssec_task_s *task)
{
#if DNSSEC_DEBUGLEVEL>2
    log_debug("dnssec_process_zone_nsec3: begin %{dnsname} (%s)", &zone->origin, task->descriptor_name);
#endif
    
    ya_result return_code = dnssec_process_task(task, &dnssec_process_zone_nsec3_body, NULL);
    
#if DNSSEC_DEBUGLEVEL>2
    log_debug("dnssec_process_zone_nsec3: end %{dnsname} (%s): %r", &zone->origin, task->descriptor_name, return_code);
#endif

    return return_code;
}

#endif

/** @} */

/*----------------------------------------------------------------------------*/


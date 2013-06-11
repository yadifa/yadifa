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
* DOCUMENTATION */
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

#if ZDB_USE_THREADPOOL != 0
#include <dnscore/thread_pool.h>
#endif

#include <dnscore/logger.h>
#include <dnscore/sys_get_cpu_count.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/rrsig.h"
#include "dnsdb/dnssec.h"
#include "dnsdb/zdb_icmtl.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

static int processor_threads_count = -1; /*SIGNER_THREAD_COUNT;*/

/*****************************************************************************/

#define ZDB_THREAD_TAG		    0x444145524854	    /* THREAD   */
#define ZDB_THREAD_CONTEXT_TAG  0x545854435450	    /* PTCTXT   */
#define THREADED_QUEUE_NODE_TAG 0x444E455545555154	/* TQUEUEND */
#define ZDB_RRSIGUPQ_TAG	    0x5150554749535252	/* RRSIGUPQ */

static int dnssec_process_threadcount = -1;

static const char *dnssec_xfr_path = NULL;

void
dnssec_set_xfr_path(const char* xfr_path)
{
    dnssec_xfr_path = xfr_path;
}

int
dnssec_process_getthreadcount()
{
    if(dnssec_process_threadcount <= 0)
    {
        ya_result count = sys_get_cpu_count();

        if(FAIL(count))
        {
            count = DEFAULT_ASSUMED_CPU_COUNT; /* default */
        }

        return count;
    }

    return dnssec_process_threadcount;
}

void
dnssec_process_setthreadcount(int count)
{
    if(count < 1)
    {
        count = -1;
    }

    processor_threads_count = count;
}

/**
 * @todo use the dnscore_shuttingdown() call to stop processing if the system is shutting down
 */

static void
dnssec_process_rr_label(zdb_zone* zone, zdb_rr_label* rr_label, dnssec_task* task)
{
#if DNSSEC_DEBUGLEVEL>2
    log_debug("dnssec_process_rr_label: begin %{dnsnamestack}", &task->path);
#endif

    /*
     * Queue task
     */

    /*
     * NOTE:
     *
     * If we are not at the apex AND there is an NS record, THEN we are at a
     * delegation.
     *
     * At a delegation, we only sign the DS record.
     *
     * At a delegation, we stop recursion.
     *
     * The NSEC3 records have a flag change if we cover some delegation
     * (ie: there are labels under this one)
     *
     * Here, we just mark "delegation" and handle the "stop recursion" part.
     *
     */

    if(dnscore_shuttingdown())
    {
        return;
    }

    zdb_packed_ttlrdata* ns_sll = NULL;

    if(LABEL_HAS_RECORDS(rr_label))
    {
        rrsig_update_query* query;

        MALLOC_OR_DIE(rrsig_update_query*, query, sizeof (rrsig_update_query), ZDB_RRSIGUPQ_TAG);

        query->label = rr_label;

        MEMCOPY(&query->path.labels[0], &task->path.labels[0], (task->path.size + 1) * sizeof (u8*));
        query->path.size = task->path.size;

        query->added_rrsig_sll = NULL;
        query->removed_rrsig_sll = NULL;

        query->delegation = FALSE;

        query->zone = zone;

        /*
         * The label from root TLD and the zone cut have one thing in common:
         * The label (relative path from the previous node) has got a size of 0
         */

        if(rr_label->name[0] != 0)
        {
            ns_sll = zdb_record_find(&rr_label->resource_record_set, TYPE_NS);
            /** NOTE: Should I set a "delegation" flag (?) */

            query->delegation = (ns_sll != NULL);
        }

        threaded_queue_enqueue(task->query, query);
    }

    /*
     * If we are not on a delegation: recurse
     *
     * == NULL => No NS => Not a delegation
     *
     */

    if(ns_sll == NULL)
    {
        dictionary_iterator iter;
        dictionary_iterator_init(&rr_label->sub, &iter);

        while(dictionary_iterator_hasnext(&iter))
        {
            if(dnscore_shuttingdown())
            {
                break;
            }

            rr_label = *(zdb_rr_label**)dictionary_iterator_next(&iter);

            dnsname_stack_push_label(&task->path, rr_label->name);
            dnssec_process_rr_label(zone, rr_label, task);
            dnsname_stack_pop_label(&task->path);
        }
    }

    /* NOTE: Do I Filter ?
     *       Any RRSIG below that point is wrong.
     *       Any record below that point that is not an A or AAAA is wrong
     */

#if DNSSEC_DEBUGLEVEL>2
    log_debug("dnssec_process_rr_label: end %{dnsnamestack}", &task->path);
#endif
}

ya_result
dnssec_process_task(zdb_zone* zone, dnssec_task* task, dnssec_process_task_callback *callback, void *whatyouwant)
{
    /** The do task query queue */
    threaded_queue dnssec_task_query_queue;
    /** The do answer query queue */
    threaded_queue dnssec_answer_query_queue;

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: creating queues");
#endif

    u32 dnssec_process_queue_size = QUEUE_MAX_SIZE;

    threaded_queue_init(&dnssec_task_query_queue, dnssec_process_queue_size);
    threaded_queue_init(&dnssec_answer_query_queue, dnssec_process_queue_size);

    processor_threads_count = dnssec_process_getthreadcount(); /* for debugging : 1 */

#if DNSSEC_DEBUGLEVEL>1
    formatln("processor_threads_count = %i", processor_threads_count);
#endif

    task->query = &dnssec_task_query_queue;

    /*
     * Prepare & Start the threads
     */

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: starting answer processor");
#endif

    ya_result ret;

#if ZDB_USE_THREADPOOL!=0
    if(FAIL(ret = thread_pool_schedule_job(task->answer_thread, &dnssec_answer_query_queue, NULL, task->descriptor_name)))
    {
        DIE(DNSSEC_ERROR_CANTPOOLTHREAD);
    }
#else
    /* The handle of the thread handling the answers */
    pthread_t dnssec_answer_thread;

    if((ret = pthread_create(&dnssec_answer_thread, NULL, task->answer_thread, &dnssec_answer_query_queue)) != 0)
    {
        /* Critical error : kill */

        DIE(DNSSEC_ERROR_CANTCREATETHREAD);
    }

    /* The handleS of the threadS handling the queries */
    pthread_t* dnssec_task_threads;
    MALLOC_OR_DIE(pthread_t*, dnssec_task_threads, sizeof (pthread_t) * processor_threads_count, ZDB_THREAD_TAG);

#endif

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: starting %d query processors", processor_threads_count);
#endif

    /* The array of contextes for each thread */
    processor_thread_context* context;
    MALLOC_OR_DIE(processor_thread_context*, context, sizeof(processor_thread_context) * processor_threads_count, ZDB_THREAD_CONTEXT_TAG);

    u32 valid_from = time(NULL);

    int processor;
    
    for(processor = 0; processor < processor_threads_count; processor++)
    {
        if(FAIL(ret = rrsig_initialize_context(zone, &context[processor].sig_context, DEFAULT_ENGINE_NAME, valid_from))) /* zone */
        {
            log_err("dnssec_process_zone: rrsig_initialize_context : %r", ret);
            break;
        }

        context[processor].id = processor;
        context[processor].job_count = 0;
        context[processor].query_queue = &dnssec_task_query_queue;
        context[processor].answer_queue = &dnssec_answer_query_queue;

#if ZDB_USE_THREADPOOL!=0
        if(FAIL(ret = thread_pool_schedule_job(task->query_thread, &context[processor], NULL, task->descriptor_name)))
        {
            log_err("dnssec_process_zone: thread_pool_schedule_job, critical fail: %r", ret);
            logger_flush();
            log_quit("dnssec_process_zone: thread_pool_schedule_job: %r", ret);
            break;
        }
#else
        if((ret = pthread_create(&dnssec_task_threads[processor], NULL, task->query_thread, &context[processor])) != 0)
        {
            OSDEBUG(termout, "dnssec_process_zone: pthread_create : Oops: (%i) %s\n", ret, strerror(ret));
            DIE(DNSSEC_ERROR_CANTCREATETHREAD);
        }

#endif
    }

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: doing the job");
#endif

    /*
     * This is the actual core of the function, everything beside this couple of lines is setup
     *
     * @TODO handle possible error code
     */

    if(ISOK(ret))
    {
        callback(zone, task, whatyouwant);
    }

    /*
     * End of the core of the function
     */

    /*
     * Wait for the answer thread
     */

    /*
     * Stop the threads
     *
     * Send an empty data to each task, so it knows it has to stop working
     *
     */

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: posting %d NULL queries", processor_threads_count);
#endif

    for(int i = 0; i < processor; i++)
    {
        threaded_queue_enqueue(&dnssec_task_query_queue, NULL);
    }

    /* Wait until the last thread has read its "NULL" query
     * This also means that the last answer has been posted.
     */

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: wait for queries");
#endif

    threaded_queue_wait_empty(&dnssec_task_query_queue);

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: destroy queries");
#endif

    threaded_queue_finalize(&dnssec_task_query_queue);

#ifndef NDEBUG
    memset(&dnssec_task_query_queue, 0xfe, sizeof(dnssec_task_query_queue));
#endif

    /* Wait until the last answer has been processed */

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: post NULL answer");
#endif

    threaded_queue_enqueue(&dnssec_answer_query_queue, NULL);

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: wait for answer");
#endif
    /* Wait until the NULL answer has been processed */
    threaded_queue_wait_empty(&dnssec_answer_query_queue);

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: destroy answer");
#endif

    threaded_queue_finalize(&dnssec_answer_query_queue);

#ifndef NDEBUG
    memset(&dnssec_answer_query_queue, 0xfe, sizeof(dnssec_answer_query_queue));
#endif

    u32 good_signatures = 0;
    u32 expired_signatures = 0;
    u32 wrong_signatures = 0;

    for(int i = 0; i < processor; i++)
    {
        good_signatures += context[i].sig_context.good_signatures;
        expired_signatures += context[i].sig_context.expired_signatures;
        wrong_signatures += context[i].sig_context.wrong_signatures;

        rrsig_destroy_context(&context[i].sig_context);

#if ZDB_USE_THREADPOOL!=0
        /* Nothing to do */
#else
        pthread_detach(dnssec_task_threads[i]);
#endif
    }

#if ZDB_USE_THREADPOOL!=0
    /* Nothing to do */
#else
    pthread_detach(dnssec_answer_thread);
#endif

    log_debug("dnssec_process_zone: good: %u expired: %u wrong: %u",
              good_signatures, expired_signatures, wrong_signatures);

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: free contexts");
#endif

#ifndef NDEBUG
    memset(context, 0xfe, sizeof(processor_thread_context));
#endif

    free(context);

#if ZDB_USE_THREADPOOL != 0
    /* Nothing to do */
#else
#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: free threads");
#endif

    free(dnssec_task_threads);
#endif

    task->query = NULL;

    /*
     * NSEC3 handling
     *
     */

    //ret = SUCCESS;

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone: end");
#endif

    return ret;
}

static ya_result
dnssec_process_zone_label(zdb_zone_label* zone_label, dnssec_task* task)
{
#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone_label: begin");
#endif

    ya_result ret = SUCCESS;

    /*
     * If the label contains a zone, then process the zone
     */

    if(zone_label->zone != NULL)
    {
        if(FAIL(ret = dnssec_process_zone(zone_label->zone, task)))
        {
            return ret;
        }
    }

    /*
     * Then process all the children of the label
     */

    dictionary_iterator iter;
    dictionary_iterator_init(&zone_label->sub, &iter);

    while(dictionary_iterator_hasnext(&iter))
    {
        zone_label = *(zdb_zone_label**)dictionary_iterator_next(&iter);

        if(FAIL(ret = dnssec_process_zone_label(zone_label, task)))
        {
            break;
        }
    }

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_zone_label: end");
#endif

    return ret;
}

/*****************************************************************************/

/**
 * Process all zones of all classes with the given task
 *
 * @param db
 * @param task
 */

void
dnssec_process_database(zdb *db, dnssec_task* task) // dnssec checked
{
#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_database: begin");
#endif

    u16 zclass;

    for(zclass = HOST_CLASS_IN - 1; zclass < ZDB_RECORDS_MAX_CLASS; zclass++)
    {
        zdb_zone_label* zone_label = db->root[zclass]; /* native order */

        dnssec_process_zone_label(zone_label, task);

        /* There is no "next" at the top ... */
    }

#if DNSSEC_DEBUGLEVEL>1
    log_debug("dnssec_process_database: end");
#endif
}

/*****************************************************************************/

ya_result
dnssec_process_initialize(dnssec_task* task, dnssec_task_descriptor* desc)
{
    task->query_thread = desc->query_thread;
    task->answer_thread = desc->answer_thread;
    task->descriptor_name = desc->name;
    return SUCCESS;
}

void
dnssec_process_finalize(dnssec_task* task)
{
    task->query_thread = NULL;
    task->answer_thread = NULL;
    task->descriptor_name = "NULL";
}

/**
 *
 * With the new RRSIG model, the context is zone-based.
 * So I should "launch" the threads for each zone.
 * This will be efficient for the TLD, but probably not for small zones.
 *
 * Anyway I'll improve this later (pool of threads & cie).
 *
 * @TODO have the init and finalize of this process done in two other functions so the body of this one would
 *       be like:
 *
 *       init
 *       dnsname_to_dnsname_stack(zone->origin, &task->path);
 *       dnssec_process_rr_label(zone->apex, task);
 *       finalize
 *
 *       And then I'll be able to move init & finalize on more specialized functions (ie: list of labels to process
 *       instead of working on the whole zone file)
 *
 * @param zone
 * @param task
 * @return
 */

static ya_result
dnssec_process_zone_body(zdb_zone* zone, dnssec_task* task, void* whatyouwant)
{
    dnsname_to_dnsname_stack(zone->origin, &task->path);
    dnssec_process_rr_label(zone, zone->apex, task);
    
    /*
     * At this point every label has been sent.
     * We need to wait for the end of the signers.
     */


    return SUCCESS;
}

ya_result
dnssec_process_zone(zdb_zone* zone, dnssec_task* task)
{
    /*************************************************************************************************
     *
     * Try to create a context for the zone.
     * No need to start threads & queues if it's not possible.
     *
     ************************************************************************************************/

    ya_result return_code;
    
    if(dnssec_xfr_path == NULL)
    {
        return ERROR;
    }

    /* @todo use a dynamic (server configuration-set) time period (LATER) */

    u32 valid_from = time(NULL);

    rrsig_context dummy_context;

    return_code = rrsig_initialize_context(zone, &dummy_context, DEFAULT_ENGINE_NAME, valid_from); /* nsec3 */

    rrsig_destroy_context(&dummy_context);

    if(FAIL(return_code))
    {
        /* Cancel the signature task.  Notify this. */

        return return_code;
    }

    zdb_icmtl icmtl;

    if(ISOK(return_code = zdb_icmtl_begin(zone, &icmtl, dnssec_xfr_path)))
    {
        if(ISOK(return_code = dnssec_process_task(zone, task, &dnssec_process_zone_body, NULL)))
        {
            if(!dnscore_shuttingdown())
            {
                zdb_icmtl_end(&icmtl, dnssec_xfr_path);
            }
            else
            {
                return_code = STOPPED_BY_APPLICATION_SHUTDOWN;
            }

            return return_code; /* why not fall ? */
        }

        /** @todo zdb_icmtl_cancel(&icmtl, data_path); */
    }
    
    return return_code;
}

#if ZDB_NSEC3_SUPPORT != 0

static ya_result
dnssec_process_zone_nsec3_body(zdb_zone* zone, dnssec_task* task, void *whatyouwant)
{
    dnsname_to_dnsname_stack(zone->origin, &task->path);

    nsec3_zone* n3 = zone->nsec.nsec3;
    
    while(n3 != NULL)
    {
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
                    return STOPPED_BY_APPLICATION_SHUTDOWN;
                }
                
                if(nsec3_avl_iterator_hasnext(&nsec3_items_iter))
                {
                    next = nsec3_avl_iterator_next_node(&nsec3_items_iter);
                }
                else
                {
                    next = first;
                }

                nsec3_rrsig_update_query* query;

                MALLOC_OR_DIE(nsec3_rrsig_update_query*, query, sizeof (nsec3_rrsig_update_query), ZDB_RRSIGUPQ_TAG);

                query->zone = zone;
                query->item = item;
                query->next = next;
                query->added_rrsig_sll = NULL;
                query->removed_rrsig_sll = NULL;

                zassert(query->item != NULL);

                threaded_queue_enqueue(task->query, query);

                item = next;
            }
            while(next != first);

        } /* If there is a first item*/

        n3 = n3->next;

    } /* while n3 != NULL */
    
    return SUCCESS;
}

ya_result
dnssec_process_zone_nsec3(zdb_zone* zone, dnssec_task* task)
{
    dnssec_process_task(zone, task, &dnssec_process_zone_nsec3_body, NULL);

    return SUCCESS;
}

#endif

/** @} */

/*----------------------------------------------------------------------------*/


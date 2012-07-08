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
/** @defgroup rrsig RRSIG functions
 *  @ingroup dnsdbdnssec
 *  @brief
 *
 *
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#include <dnscore/logger.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/dnssec.h"
#include "dnsdb/rrsig.h"

#include "dnsdb/zdb_listener.h"

#include <dnscore/scheduler.h>

#define MODULE_MSG_HANDLE g_dnssec_logger

/*****************************************************************************
 *****************************************************************************
 *
 * UPDATER
 *
 *****************************************************************************
 *****************************************************************************/

/** @todo: Use the rrsig.c methods here instead  */

/* MULTIPLE INSTANCES */

static void*
rrsig_updater_thread(void* context_)
{
    /* Initialization */

    processor_thread_context* context = (processor_thread_context*)context_;
    threaded_queue* dnssec_task_query_queue = context->query_queue;
    threaded_queue* dnssec_task_answer_queue = context->answer_queue;

    int id = context->id;
    u8 origin[MAX_DOMAIN_LENGTH];

    dnsname_copy(origin, context->sig_context.origin);

    log_debug("rrsig: updater thread %i start %{dnsname}", id, origin);

    zassert(context != NULL);

#if DNSSEC_DEBUGLEVEL>0
    log_debug("rrsig_updater_thread(%i): starting an UPDATER thread", id);
#endif

    /*
     * The caller has already initialized the signature context for us.
     * The zone & everything are ready.
     *
     */

    /* Main loop  */

    for(;;)
    {
#if DNSSEC_DEBUGLEVEL>1
        log_debug("rrsig_updater_thread(%i): dequeue (WAIT)", id);
#endif

        rrsig_update_query* query = (rrsig_update_query*)threaded_queue_dequeue(dnssec_task_query_queue);

        if(query == NULL)
        {
            /* From this point I should not use the context anymore */

#if DNSSEC_DEBUGLEVEL>1
            log_debug("rrsig_updater_thread(%i): stop", id);
#endif
            break;
        }

#if DNSSEC_DEBUGLEVEL>3
        { /* DEBUG */
            char label[MAX_DOMAIN_LENGTH + 1];
            dnsname_stack_to_cstr(&query->path, label);
            log_debug("rrsig_updater_thread(): processing records for '%s'", label);
        }
#endif

        /**
         * The path to the label to sign is in the query.
         * @todo: use the path from the query :
         *
         * rrsig_update_context_add_label
         * rrsig_update_context_remove_label
         *
         */

#ifndef NDEBUG
        zassert(query->added_rrsig_sll != ((zdb_packed_ttlrdata*)0xfefefefefefefefe));
#endif

        rrsig_update_context_push_label(&context->sig_context, query->label);
        rrsig_update_label(&context->sig_context, query->label, query->delegation);

        /*
         * Retrieve the old signatures (to be deleted)
         * Retrieve the new signatures (to be added)
         *
         * This has to be injected as an answer query.
         */

        query->added_rrsig_sll = context->sig_context.added_rrsig_sll;
        query->removed_rrsig_sll = context->sig_context.removed_rrsig_sll;

        rrsig_update_context_pop_label(&context->sig_context);

        /* All the signatures for this set have been computer.  Queue the result. */

        /*******************************************************************
         * QUEUE THE ANSWER
         ******************************************************************/

#if DNSSEC_DEBUGLEVEL>1
        log_debug("rrsig_updater_thread(%i): enqueue (RESULT)", id);
#endif

#ifndef NDEBUG
        if(query != NULL)
        {
            zassert(query->added_rrsig_sll != ((zdb_packed_ttlrdata*)0xfefefefefefefefe));
        }
#endif

        if(query->added_rrsig_sll != NULL || query->removed_rrsig_sll != NULL)
        {
            threaded_queue_enqueue(dnssec_task_answer_queue, query);
        }
        else
        {
            free(query);
        }

#if DNSSEC_DEBUGLEVEL>1
        log_debug("rrsig_updater_thread(%i): done", id);
#endif
    }

    ERR_remove_state(0);

    log_debug("rrsig: updater thread %i stop %{dnsname}", id, origin);

    /* We don't need this anymore */

#if DNSSEC_DEBUGLEVEL>0
    log_debug("rrsig_updater_thread(%i): exit", id);
#endif

    logger_flush();

#if ZDB_USE_THREADPOOL != 0
    /* calling pthread_exit would kill the thread from the pool : not good */
#else
    pthread_exit(NULL);
#endif

    return NULL;
}

/* ONE INSTANCE */

static void*
rrsig_updater_result_process(threaded_queue* dnssec_answer_query_queue, bool schedule)
{
#if DNSSEC_DEBUGLEVEL>0
    log_debug("dnssec_updater_result_thread(): start");
#endif

    log_debug("rrsig: updater thread result start");

#if DNSSEC_DUMPSIGNCOUNT!=0
    u64 sign_start = timems();
#endif

    u32 count;

    for(count = 1;; count++)
    {
#if DNSSEC_DEBUGLEVEL>1
        log_debug("dnssec_updater_result_thread(): loop #%i", count);
#endif

        rrsig_update_query* task = (rrsig_update_query*)threaded_queue_dequeue(dnssec_answer_query_queue);

        if(task == NULL)
        {
            /* Terminating ... */

#if DNSSEC_DEBUGLEVEL>1
            log_debug("dnssec_updater_result_thread(): stop #%i", count);
#endif
            break;
        }

#if DNSSEC_DEBUGLEVEL>3
        { /* DEBUG */
            char label[MAX_DOMAIN_LENGTH + 1];
            dnsname_stack_to_cstr(&task->path, label);
            log_debug("dnssec_updater_result_thread() : retrieving results for %s", label);
        }
#endif

        if(schedule)
        {
           /**
            * The "task" structure will be destroyed at the end of the scheduled task
            */
            scheduler_task_rrsig_update_commit(task->removed_rrsig_sll, task->added_rrsig_sll, task->label, task->zone, &task->path, task);

        }
        else
        {
            rrsig_update_commit(task->removed_rrsig_sll, task->added_rrsig_sll, task->label, task->zone, &task->path);

#ifndef NDEBUG
            memset(task, 0xfe, sizeof(rrsig_update_query));
#endif

            free(task);
        }

#if DNSSEC_DUMPSIGNCOUNT!=0
        if((count & 0x3fff) == 0)
        {
            u64 elapsed = timems() - sign_start;
            // count / (elapsed * 0.001)
            // count
            float rate = (1000.f * count) / MAX((1.0f*elapsed),1.000f);
            log_debug("rrsig: updater thread result : %u in %llums (%f/s)", count, elapsed, rate);
        }
#endif
    }

#if DNSSEC_DUMPSIGNCOUNT!=0
    u64 elapsed = timems() - sign_start;
    float rate = (1000.f * count) / MAX((1.0f*elapsed),1.000f);
    log_debug("rrsig: updater thread result : %u in %llums (%f/s)", count, elapsed, rate);
#endif

    ERR_remove_state(0);

    log_debug("rrsig: updater thread result end");

#if DNSSEC_DEBUGLEVEL>0
    log_debug("dnssec_updater_result_thread(): exit");
#endif

    logger_flush();

#if ZDB_USE_THREADPOOL != 0
    /* calling pthread_exit would kill the thread from the pool : not good */
#else
    pthread_exit(NULL);
#endif

    return NULL;
}


static void*
rrsig_updater_result_thread(void* context)
{
    threaded_queue* dnssec_answer_query_queue = (threaded_queue*)context;

    return rrsig_updater_result_process(dnssec_answer_query_queue, FALSE);
}

static void*
rrsig_updater_result_thread_scheduled(void* context)
{
    threaded_queue* dnssec_answer_query_queue = (threaded_queue*)context;

    return rrsig_updater_result_process(dnssec_answer_query_queue, TRUE);
}

static ya_result
rrsig_updater_init(dnssec_task* task)
{
    dnssec_inittask(0, task);
    
    return SUCCESS;
}

static ya_result
rrsig_updater_finalize(dnssec_task* task)
{
    task->task_flags = 0;
    
    return SUCCESS;
}

dnssec_task_descriptor dnssec_updater_task_descriptor = {
    rrsig_updater_init,
    rrsig_updater_finalize,
    rrsig_updater_thread,
    rrsig_updater_result_thread,
    "RRSIG updater"
};

dnssec_task_descriptor dnssec_updater_task_descriptor_scheduled = {
    rrsig_updater_init,
    rrsig_updater_finalize,
    rrsig_updater_thread,
    rrsig_updater_result_thread_scheduled,
    "RRSIG scheduled updater"
};

/** @} */

/*----------------------------------------------------------------------------*/


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
#include "dnsdb/rrsig_updater.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_zone_label_iterator.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

/*****************************************************************************
 *****************************************************************************
 *
 * UPDATER
 *
 *****************************************************************************
 *****************************************************************************/

struct rrsig_updater_result_process_item_s
{
    struct rrsig_updater_result_process_item_s *next;
    zdb_packed_ttlrdata *added_rrsig_sll;
    zdb_packed_ttlrdata *removed_rrsig_sll;
    u8 internal_fqdn[1];
};

typedef struct rrsig_updater_result_process_item_s rrsig_updater_result_process_item_s;

struct rrsig_answer_context_s
{
    dnssec_task_s *task;
    struct rrsig_updater_result_process_item_s *items;
};

typedef struct rrsig_answer_context_s rrsig_answer_context_s;

ya_result nsec3_rrsig_updater_process_zone(rrsig_updater_parms *parms);

static ya_result
rrsig_updater_thread_init(dnssec_task_s *task)
{
    u32 valid_from = time(NULL);

    rrsig_context_s dummy_context;
    ya_result return_code = rrsig_context_initialize(&dummy_context, task->zone, DEFAULT_ENGINE_NAME, valid_from, NULL); /* nsec3 */
    rrsig_context_destroy(&dummy_context);
    
    return return_code;
}

static ya_result
rrsig_updater_thread_finalise(dnssec_task_s *task)
{
    return SUCCESS;
}

/**
 * 
 * @param task
 * @param processor ==0 = answer, >0 = query
 * @param ctxp
 * @return 
 */

static ya_result
rrsig_updater_thread_create_context(dnssec_task_s *task, s32 processor, void **ctxp)
{
    yassert((task != NULL) && (task->args != NULL) && (task->zone != NULL));
    
    if(processor > 0)
    {
        rrsig_context_s *ctx;
        MALLOC_OR_DIE(rrsig_context_s*, ctx, sizeof(rrsig_context_s), GENERIC_TAG);

        u32 valid_from = time(NULL);    
        rrsig_updater_parms *parms = (rrsig_updater_parms*)task->args;

        ya_result return_code = rrsig_context_initialize(ctx, task->zone, DEFAULT_ENGINE_NAME, valid_from, (parms->quota >0)?&parms->remaining_quota:NULL);

        if(ISOK(return_code))
        {
            ctx->task = task;
            *ctxp = ctx;
        }
        else
        {
            free(ctx);
            ctx = NULL;
        }
                
        return return_code;
    }
    else
    {
        rrsig_answer_context_s *ctx;
        MALLOC_OR_DIE(rrsig_answer_context_s*, ctx, sizeof(rrsig_answer_context_s), GENERIC_TAG);
        ctx->task = task;
        ctx->items = NULL;
        *ctxp = ctx;
        
        return SUCCESS;
    }
}

static void
rrsig_updater_thread_destroy_context(dnssec_task_s *task, s32 processor, void *ctx_)
{
    (void)task;
    
    if(processor > 0)
    {
        rrsig_updater_parms *parms = (rrsig_updater_parms*)task->args;
        rrsig_context_s *ctx = (rrsig_context_s*)ctx_;

        parms->good_signatures += ctx->good_signatures;
        parms->expired_signatures += ctx->expired_signatures;
        parms->wrong_signatures += ctx->wrong_signatures;

        rrsig_context_destroy(ctx);
        free(ctx);
    }
    else
    {
        rrsig_answer_context_s *ctx = (rrsig_answer_context_s*)ctx_;
        ctx->task = NULL;
        free(ctx);
    }
}

/**
 * Updates the signatures on the label of a zone based on a signature context
 */

static s32
rrsig_updater_update_label(rrsig_context_s *sig_context, rrsig_update_item_s *query)
{
    rrsig_context_push_label(sig_context, query->label);
    
    s32 sig_count = rrsig_update_label(sig_context, query->label);
    
    rrsig_context_update_quota(sig_context, sig_count);

    /*
     * Retrieve the old signatures (to be deleted)
     * Retrieve the new signatures (to be added)
     *
     * This has to be injected as an answer query.
     */

    query->added_rrsig_sll = sig_context->added_rrsig_sll;
    query->removed_rrsig_sll = sig_context->removed_rrsig_sll;

    rrsig_context_pop_label(sig_context);
    
    return sig_count;
}

/**
 * 
 * This thread takes rrsig_update_query inputs to compute signatures and
 * sends them back to the result thread.
 * 
 * MULTIPLE INSTANCES RUNNING
 * 
 * @param context_
 * @return 
 */

static void*
rrsig_updater_thread(void *context_)
{
    /* Initialization */

    rrsig_context_s *sig_context = (rrsig_context_s*)context_;
    dnssec_task_s *task = sig_context->task;
    
    threaded_queue *dnssec_task_query_queue = &task->dnssec_task_query_queue;
    threaded_queue *dnssec_task_answer_queue = &task->dnssec_answer_query_queue;

    int id = (int)pthread_self();
    u8 origin[MAX_DOMAIN_LENGTH];

    dnsname_copy(origin, sig_context->origin);

    log_debug("rrsig: updater thread %x start %{dnsname}", id, origin);

#if DNSSEC_DEBUGLEVEL>0
    log_debug("rrsig_updater_thread(%i): starting an UPDATER thread", id);
#endif

    /*
     * The caller has already initialized the signature context for us.
     * The zone & everything are ready.
     *
     */

    u32  signatures_made = 0;
    u32  labels_ignored = 0;
    bool first_job = TRUE;
    bool first_signature = TRUE;
    
    /* Main loop  */

    for(;;)
    {
#if DNSSEC_DEBUGLEVEL>1
        log_debug("rrsig_updater_thread(%i): dequeue (WAIT)", id);
#endif

        rrsig_update_item_s* query = (rrsig_update_item_s*)threaded_queue_dequeue(dnssec_task_query_queue);

        if(query == NULL)
        {
            /* From this point I should not use the context anymore */

#if DNSSEC_DEBUGLEVEL>1
            log_debug("rrsig_updater_thread(%i): stop", id);
#endif
            break;
        }
        
        if(first_job)
        {
            log_debug("rrsig_updater_thread(%i): first query", id);
            first_job = FALSE;
        }
        
        if(rrsig_context_get_quota(sig_context) <= 0)
        {
            log_debug("quota exceeded, ignoring nsec3 signature query");
            free(query);
            
            task->stop_task = true;
            
            continue;
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

#ifdef DEBUG
        yassert(query->added_rrsig_sll != ((zdb_packed_ttlrdata*)0xfefefefefefefefe));
#endif

        if(rrsig_updater_update_label(sig_context, query) > 0)
        {
            if(first_signature)
            {
                log_debug("rrsig_updater_thread(%i): first signature", id);
                first_signature = FALSE;
            }
            
            signatures_made++;
        }
        else
        {
            labels_ignored++;
        }

        /* All the signatures for this set have been computer.  Queue the result. */

        /*******************************************************************
         * QUEUE THE ANSWER
         ******************************************************************/

#if DNSSEC_DEBUGLEVEL>1
        log_debug("rrsig_updater_thread(%i): enqueue (RESULT)", id);
#endif

#ifdef DEBUG
        if(query != NULL)
        {
            yassert(query->added_rrsig_sll != ((zdb_packed_ttlrdata*)0xfefefefefefefefe));
        }
#endif
        // if there is work to do, enqueue the result, else free the query

#if 1
        threaded_queue_enqueue(dnssec_task_answer_queue, query);
#else        
        if(query->added_rrsig_sll != NULL || query->removed_rrsig_sll != NULL)
        {
            threaded_queue_enqueue(dnssec_task_answer_queue, query);
        }
        else
        {
            free(query);
        }
#endif

#if DNSSEC_DEBUGLEVEL>1
        log_debug("rrsig_updater_thread(%i): done", id);
#endif
    }

    ERR_remove_state(0);

    log_debug("rrsig: updater thread %x stop %{dnsname} (made=%d,ignored=%d)", id, origin, signatures_made, labels_ignored);

    /* We don't need this anymore */

#if DNSSEC_DEBUGLEVEL>0
    log_debug("rrsig_updater_thread(%i): exit", id);
    logger_flush();
#endif

    return NULL;
}

/* ONE INSTANCE RUNNING */

static void*
rrsig_updater_result_process(rrsig_answer_context_s *answer_context)
{
    dnssec_task_s *task = answer_context->task;
    threaded_queue* dnssec_answer_query_queue = &task->dnssec_answer_query_queue;
    
#if DNSSEC_DEBUGLEVEL>0
    log_debug("dnssec_updater_result_thread(): start");
#endif

    log_debug("rrsig: updater thread result start");

#if DNSSEC_DUMPSIGNCOUNT!=0
    u64 sign_start = timems();
#endif

    u32 count;
    
    struct rrsig_updater_result_process_item_s *to_commit = NULL;
    rrsig_update_item_s *previous_query = NULL;

    for(count = 1;; count++)
    {
#if DNSSEC_DEBUGLEVEL>1
        log_debug("dnssec_updater_result_thread(): loop #%i", count);
#endif

        rrsig_update_item_s *query = (rrsig_update_item_s*)threaded_queue_dequeue(dnssec_answer_query_queue);

        if(query == NULL)
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
            dnsname_stack_to_cstr(&query->path, label);
            log_debug("dnssec_updater_result_thread() : retrieving results for %s", label);
        }
#endif
        if(query->added_rrsig_sll != NULL || query->removed_rrsig_sll != NULL)
        {
            rrsig_updater_result_process_item_s *item;
            u32 fqdn_len = dnsname_stack_len(&query->path);
            ZALLOC_ARRAY_OR_DIE(rrsig_updater_result_process_item_s *, item, sizeof(rrsig_updater_result_process_item_s) - 1 + fqdn_len, GENERIC_TAG);
            item->next = to_commit;
            to_commit = item;
            item->added_rrsig_sll = query->added_rrsig_sll;
            item->removed_rrsig_sll = query->removed_rrsig_sll;
            dnsname_stack_to_dnsname(&query->path, &item->internal_fqdn[0]);
            //rrsig_update_commit(query->removed_rrsig_sll, query->added_rrsig_sll, query->label, query->zone, &query->path);
        }
        
        // this is the last processed point
        
        if(previous_query != NULL)
        {
        
#ifdef DEBUG
            memset(previous_query, 0xfe, sizeof(rrsig_update_item_s));
#endif

            free(previous_query);
        }
        
        previous_query = query;

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
    
    //
    
    answer_context->items = to_commit;
    
    //
    
    if(previous_query != NULL)
    {
        // remember the last processed point
        
        // the next iteration will start from/after this point
        
        u32 path_len = dnsname_stack_len(&previous_query->path);
        u32 origin_len = dnsname_len(previous_query->zone->origin);
        
        // allocate path_len - origin_len        
        // copy the name below the origin
        // set it as sig_last_processed_node
        
        if(previous_query->zone->sig_last_processed_node == NULL)
        {
            ZFREE_STRING(previous_query->zone->sig_last_processed_node);
            previous_query->zone->sig_last_processed_node = NULL;
        }

        u8 *sig_last_processed_node;
        u32 len = path_len - origin_len;
        ZALLOC_ARRAY_OR_DIE(u8 *,sig_last_processed_node, len + 1, GENERIC_TAG);
        sig_last_processed_node[0] = len;
        sig_last_processed_node++;
        previous_query->zone->sig_last_processed_node = sig_last_processed_node;
        const u8 *sig_last_processed_node_limit = &sig_last_processed_node[len];
        for(s32 size = previous_query->path.size; (sig_last_processed_node < sig_last_processed_node_limit) && (size >= 0); size--)
        {
            sig_last_processed_node += dnslabel_copy(sig_last_processed_node, previous_query->path.labels[size]);
        }
        
        // release
        
#ifdef DEBUG
        memset(previous_query, 0xfe, sizeof(rrsig_update_item_s));
#endif

        free(previous_query);
        
        previous_query = NULL;
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
    logger_flush();
#endif

    return NULL;
}

static void*
rrsig_updater_result_thread(void *context_)
{
    rrsig_answer_context_s *context = (rrsig_answer_context_s*)context_;

    return rrsig_updater_result_process(context);
}

static bool
rrsig_updater_filter_label_rrsig(dnssec_task_s *task, zdb_rr_label *rr_label)
{
    rrsig_updater_parms *parms = (rrsig_updater_parms*)task->args;
           
    if(parms->signatures_are_verified)
    {        
        zdb_packed_ttlrdata * rrsig = zdb_record_find(&rr_label->resource_record_set, TYPE_RRSIG);
        
        if(rrsig != NULL)
        {
            u32 now = time(NULL);

            do
            {
                u32 until = RRSIG_VALID_UNTIL(rrsig);

                if(until < now)
                {
                    return TRUE;
                }

                rrsig = rrsig->next;
            }
            while(rrsig != NULL);
        }
        else
        {
            return TRUE;
        }
    }
    
    return FALSE;
}

static ya_result
rrsig_updater_filter_label(dnssec_task_s *task, zdb_rr_label *rr_label)
{
    if(LABEL_HAS_RECORDS(rr_label))
    {
        if(ZDB_LABEL_ISAPEX(rr_label))
        {
            if(rrsig_updater_filter_label_rrsig(task, rr_label))
            {
                return DNSSEC_THREAD_TASK_FILTER_ACCEPT;
            }
        }
        
        if(ZDB_LABEL_ATDELEGATION(rr_label))
        {
            if(zdb_record_find(&rr_label->resource_record_set, TYPE_DS) != NULL)
            {
                if(rrsig_updater_filter_label_rrsig(task, rr_label))
                {
                    return DNSSEC_THREAD_TASK_FILTER_ACCEPT;
                }
            }
        }
        else if(!ZDB_LABEL_UNDERDELEGATION(rr_label))
        {
            if(rrsig_updater_filter_label_rrsig(task, rr_label))
            {
                return DNSSEC_THREAD_TASK_FILTER_ACCEPT;
            }
        }
    }

    return DNSSEC_THREAD_TASK_FILTER_IGNORE;
}

static ya_result
rrsig_updater_filter_nsec3_item(dnssec_task_s *task, nsec3_zone_item *item, nsec3_zone_item *next)
{
    (void)task;
    (void)item;
    (void)next;
    return DNSSEC_THREAD_TASK_FILTER_IGNORE;
}

static dnssec_task_vtbl rrsig_updater_task_descriptor =
{
    rrsig_updater_thread_init,
    rrsig_updater_thread_create_context,
    rrsig_updater_thread_destroy_context,
    rrsig_updater_filter_label,
    rrsig_updater_filter_nsec3_item,
    rrsig_updater_thread,
    rrsig_updater_result_thread,
    rrsig_updater_thread_finalise,
    "RRSIG updater"
};

rrsig_updater_parms*
rrsig_updater_parms_alloc()
{
    rrsig_updater_parms *parms;
    
    ZALLOC_OR_DIE(rrsig_updater_parms*, parms, rrsig_updater_parms, GENERIC_TAG);
    ZEROMEMORY(parms, sizeof(rrsig_updater_parms));
    
    return parms;
}

void
rrsig_updater_parms_free(rrsig_updater_parms *parms)
{
    if(parms != NULL)
    {
        ZFREE(parms, rrsig_updater_parms);
    }
}

/**
 * creates the communication queues 
 * 
 * takes hold of the threads from the pool
 * 1 for the answers (maybe answers is irrelevant and could be replaced
 * by a mutex and a ptr to the item list
 * 
 * the rest for the signatures
 * 
 * the threads must know the zone and the keys
 * 
 * should be followed by rrsig_updater_process_zone
 */

void
rrsig_updater_init(rrsig_updater_parms *parms, zdb_zone *zone)
{
    log_debug1("rrsig_updater_init(%p,%{dnsname})", parms, zone->origin);
    
    smp_int *quota = NULL;
    
    if(parms->quota != 0)
    {
        quota = &parms->remaining_quota;
        smp_int_init_set(quota, parms->quota);
    }
    
    parms->to_commit = NULL;
    
    dnssec_process_initialize(&parms->task, &rrsig_updater_task_descriptor, NULL, zone);
    parms->task.args = parms;
}

/**
 * sends the labels to the signature queue
 * waits for a stop signal (stop signing or program shutdown)
 * 
 * @param parms
 * @return 
 */

ya_result
rrsig_updater_process_zone(rrsig_updater_parms *parms)
{
    log_debug1("rrsig_updater_process_zone(%p)", parms);
    
    dnssec_task_s *task = &parms->task;
    ya_result return_code;
    zdb_zone_label_iterator iter;
    dnsname_stack fqdn_stack;
    
    // initialises the queues, puts the processors and the answer threads into
    // the pool
    
    if(FAIL(return_code = dnssec_process_begin(task)))
    {
        return return_code;
    }
    
    if(task->zone->sig_last_processed_node == NULL)
    {
        zdb_zone_label_iterator_init_from(task->zone, &iter, task->zone->sig_last_processed_node);
    }
    else
    {
        u8 len = task->zone->sig_last_processed_node[-1];
        u8 fqdn[MAX_DOMAIN_LENGTH];
        memcpy(fqdn, task->zone->sig_last_processed_node, len);
        memcpy(&fqdn[len], task->zone->origin, dnsname_len(task->zone->origin));
        zdb_zone_label_iterator_init_from(task->zone, &iter, fqdn);
    }
    
    while(zdb_zone_label_iterator_hasnext(&iter))
    {
        memcpy(&fqdn_stack.labels[0], &iter.dnslabels[0], (iter.top + 1) * sizeof(u8*));
        fqdn_stack.size = iter.top;
        
        zdb_rr_label *rr_label = zdb_zone_label_iterator_next(&iter);
        
        if(task->vtbl->filter_label(task, rr_label) == DNSSEC_THREAD_TASK_FILTER_ACCEPT)
        {
            rrsig_update_item_s *query;

            MALLOC_OR_DIE(rrsig_update_item_s*, query, sizeof (rrsig_update_item_s), ZDB_RRSIGUPQ_TAG);
            query->label = rr_label;

            memcpy(&query->path.labels[0], &fqdn_stack.labels[0], (fqdn_stack.size + 1) * sizeof(u8*));
            query->path.size = fqdn_stack.size;
            
            query->added_rrsig_sll = NULL;
            query->removed_rrsig_sll = NULL;
            query->zone = task->zone;

            /*
             * The label from root TLD and the zone cut have one thing in common:
             * The label (relative path from the previous node) has got a size of 0
             */

            threaded_queue_enqueue(&task->dnssec_task_query_queue, query);
        }
        
        if(task->stop_task)
        {
            break;
        }
        
        if(dnscore_shuttingdown())
        {
            break;
        }
    }
    
    dnssec_process_end(task);
            
    return_code = parms->quota - smp_int_get(&parms->remaining_quota);
    
    return return_code;
}

/*
* commits the results from the answers (or the list already built)
*/

void
rrsig_updater_commit(rrsig_updater_parms *parms)
{
    log_debug1("rrsig_updater_commit(%p)", parms);
            
    dnssec_task_s *task = &parms->task;
    
    rrsig_answer_context_s *context = (rrsig_answer_context_s*)task->contexts[0];
    if(context != NULL && context->items != NULL)
    {
        // commit all the signatures changes
        
        struct rrsig_updater_result_process_item_s *to_commit = context->items;
        
        context->items = NULL;
        
        while(to_commit != NULL)
        {
            rrsig_updater_result_process_item_s *item = to_commit;
            dnsname_stack path;
            dnsname_to_dnsname_stack(item->internal_fqdn, &path);
            zdb_zone *zone = task->zone;
            // find label in zone ...
            zdb_rr_label *label = zdb_rr_label_stack_find(task->zone->apex, path.labels, path.size, zone->origin_vector.size + 1);
            
            if(label != NULL)
            {
                rrsig_update_commit(item->removed_rrsig_sll, item->added_rrsig_sll, label, zone, &path);
            }
            else
            {
                log_err("rrsig: label %{dnsname} or zone %{dnsname} disappeared while signing", item->internal_fqdn, zone->origin);
            }
            
            to_commit = to_commit->next;
            
            ZFREE_ARRAY(item, sizeof(rrsig_updater_result_process_item_s) - 1 + dnsname_len(item->internal_fqdn));
        }
    }
}

void
rrsig_updater_finalize(rrsig_updater_parms *parms)
{
    log_debug1("rrsig_updater_finalize(%p)", parms);
    
    log_debug("rrsig_updater_finalize: good: %u expired: %u wrong: %u",
            parms->good_signatures,
            parms->expired_signatures,
            parms->wrong_signatures);
        
    if(parms->quota != 0)
    {
        smp_int_destroy(&parms->remaining_quota);
    }
    
    dnssec_process_finalize(&parms->task);
}

/** @} */

/*----------------------------------------------------------------------------*/

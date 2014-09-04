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
/** @defgroup nsec3 NSEC3 functions
 *  @ingroup dnsdbdnssec
 *  @brief
 * 
 *  Thread functions to sign the RRSIG records of the NSEC3 of a zone.
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

#include <dnscore/base32hex.h>
#include <dnscore/typebitmap.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/dnssec.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/nsec3.h"

#include "dnsdb/rrsig_updater.h"
#include "dnsdb/nsec3_rrsig_updater.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

/*****************************************************************************
 *****************************************************************************
 *
 * UPDATER
 *
 *****************************************************************************
 *****************************************************************************/

#define NSEC3_RRSIG_TTLRDATA_TAG	0x5254474953334e /* RRSIGTR */


static ya_result
nsec3_rrsig_updater_thread_init(dnssec_task_s *task)
{
    u32 valid_from = time(NULL);

    rrsig_context_s dummy_context;
    ya_result return_code = rrsig_context_initialize(&dummy_context, task->zone, DEFAULT_ENGINE_NAME, valid_from, NULL); /* nsec3 */
    rrsig_context_destroy(&dummy_context);
    
    return return_code;
}

static ya_result
nsec3_rrsig_updater_thread_finalise(dnssec_task_s *task)
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
nsec3_rrsig_updater_thread_create_context(dnssec_task_s *task, s32 processor, void **ctxp)
{
    yassert((task != NULL) && (task->args != NULL) && (task->zone != NULL));
    
    if(processor > 0)
    {
        rrsig_context_s *ctx;
        MALLOC_OR_DIE(rrsig_context_s*, ctx, sizeof(rrsig_context_s), GENERIC_TAG);

        u32 valid_from = time(NULL);    
        nsec3_rrsig_updater_parms *parms = (nsec3_rrsig_updater_parms*)task->args;

        ya_result return_code = rrsig_context_initialize(ctx, task->zone, DEFAULT_ENGINE_NAME, valid_from, (parms->quota>0)?&parms->remaining_quota:NULL);

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
        nsec3_rrsig_answer_context_s *ctx;
        MALLOC_OR_DIE(nsec3_rrsig_answer_context_s*, ctx, sizeof(nsec3_rrsig_answer_context_s), GENERIC_TAG);
        ctx->task = task;
        ctx->items = NULL;
        *ctxp = ctx;
        
        return SUCCESS;
    }
}

static void
nsec3_rrsig_updater_thread_destroy_context(dnssec_task_s *task, s32 processor, void *ctx_)
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
        nsec3_rrsig_answer_context_s *ctx = (nsec3_rrsig_answer_context_s*)ctx_;
        ctx->task = NULL;
        free(ctx);
    }
}

/**
 * 
 * Updates the signatures on the NSEC3 record of a label of a zone based on a signature context
 * 
 * @param sig_context the signature context
 * @param query details about the nsec3 entry to sign
 * @param tmp_nsec3_ttlrdata a record of TMP_NSEC3_TTLRDATA_SIZE bytes for temporary work
 */

static void
nsec3_rrsig_updater_update_nsec3(rrsig_context_s *sig_context, nsec3_rrsig_update_item_s *query, zdb_packed_ttlrdata *tmp_nsec3_ttlrdata)
{
    u8 digest_len = NSEC3_NODE_DIGEST_SIZE(query->item);
    u8 digest_to_dnsname[MAX_DOMAIN_LENGTH + 1];
    digest_to_dnsname[0] = BASE32HEX_ENCODED_LEN(digest_len);
    base32hex_encode(NSEC3_NODE_DIGEST_PTR(query->item), digest_len, (char*)& digest_to_dnsname[1]);

#if DNSSEC_DEBUGLEVEL>3
    { /* DEBUG */
        log_debug("nsec3_rrsig_updater_thread(): processing records for '%{dnslabel}'", digest_to_dnsname);
    }
#endif

    /*
     * The path to the label to sign is in the query.
     *
     * rrsig_update_context_add_label
     * rrsig_update_context_remove_label
     *
     */

    nsec3_zone* n3 = query->zone->nsec.nsec3;
    nsec3_zone_item* item = query->item;
    nsec3_zone_item* next = query->next;

    rrsig_context_push_name_rrsigsll(sig_context, digest_to_dnsname, item->rrsig);

    dnssec_key_sll* key_sll;

    /* Build a temporary record into nsec3_ttlrdata */

    tmp_nsec3_ttlrdata->next = NULL;
    tmp_nsec3_ttlrdata->ttl = sig_context->min_ttl;
    u32 n3_rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
    MEMCOPY(&tmp_nsec3_ttlrdata->rdata_start[0], &n3->rdata[0], n3_rdata_size);
    MEMCOPY(&tmp_nsec3_ttlrdata->rdata_start[n3_rdata_size], next->digest, digest_len + 1);
    n3_rdata_size += digest_len + 1;
    MEMCOPY(&tmp_nsec3_ttlrdata->rdata_start[n3_rdata_size], item->type_bit_maps, item->type_bit_maps_size);
    n3_rdata_size += item->type_bit_maps_size;
    tmp_nsec3_ttlrdata->rdata_size = n3_rdata_size;

    /* While we have signing keys ... */
    
    s32 sig_count = 0;

    for(key_sll = sig_context->key_sll; key_sll != NULL; key_sll = key_sll->next)
    {
        /* Take the real key from the key container */

        dnssec_key* key = key_sll->key;

        if(key->flags == (DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY))
        {
            /* KSK */

            continue;
        }

        rrsig_context_set_key(sig_context, key);

        sig_count += rrsig_update_records(sig_context, key, tmp_nsec3_ttlrdata, TYPE_NSEC3, TRUE);
    }
    
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
}

/* MULTIPLE INSTANCES */

static void*
nsec3_rrsig_updater_thread(void* context_)
{
    /* Initialization */

    yassert(context_ != NULL);

    rrsig_context_s *sig_context = (rrsig_context_s*)context_;
    dnssec_task_s *task = sig_context->task;
    threaded_queue* dnssec_task_query_queue = &task->dnssec_task_query_queue;
    threaded_queue* dnssec_task_answer_queue = &task->dnssec_answer_query_queue;

    zdb_packed_ttlrdata* tmp_nsec3_ttlrdata;
    MALLOC_OR_DIE(zdb_packed_ttlrdata*, tmp_nsec3_ttlrdata, TMP_NSEC3_TTLRDATA_SIZE, NSEC3_RRSIG_TTLRDATA_TAG);

#if DNSSEC_DEBUGLEVEL>0
    int id = context->id;

    log_debug("nsec3_rrsig_updater_thread(%i): starting an UPDATER thread", id);
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
        log_debug("nsec3_rrsig_updater_thread(%i): dequeue (WAIT)", id);
#endif

        nsec3_rrsig_update_item_s *query = (nsec3_rrsig_update_item_s*)threaded_queue_dequeue(dnssec_task_query_queue);

        if(query == NULL)
        {
#if DNSSEC_DEBUGLEVEL>1
            log_debug("nsec3_rrsig_updater_thread(%i): stop", id);
#endif

            break;
        }
        
        if(rrsig_context_get_quota(sig_context) <= 0)
        {
            log_debug("quota exceeded, ignoring signature query");
            free(query);
            
            task->stop_task = true;
            
            continue;
        }
        
        // NSEC3 updater does not care about going over quota, but it updates it

        yassert(query->item != NULL);

        nsec3_rrsig_updater_update_nsec3(sig_context, query, tmp_nsec3_ttlrdata);

        /* All the signatures for this set have been computed.  Queue the result. */

        /*******************************************************************
         * QUEUE THE ANSWER
         ******************************************************************/

#if DNSSEC_DEBUGLEVEL>1
        log_debug("nsec3_rrsig_updater_thread(%i): enqueue (RESULT)", id);
#endif

        yassert(query->item != NULL);

        threaded_queue_enqueue(dnssec_task_answer_queue, query);

#if DNSSEC_DEBUGLEVEL>1
        log_debug("nsec3_rrsig_updater_thread(%i): done", id);
#endif
    }

    free(tmp_nsec3_ttlrdata);

    ERR_remove_state(0);

#if DNSSEC_DEBUGLEVEL>0
    log_debug("nsec3_rrsig_updater_thread(%i): exit", id);
#endif

    return NULL;
}

/* ONE INSTANCE */

static void*
nsec3_rrsig_updater_result_process(nsec3_rrsig_answer_context_s *answer_context)
{
#if DNSSEC_DEBUGLEVEL>0
    log_debug("nsec3_rrsig_updater_result_process(): start");
#endif

#if DNSSEC_DUMPSIGNCOUNT!=0
    u64 sign_start = timems();
#endif
    
    nsec3_rrsig_updater_result_process_item_s *to_commit = NULL;
    threaded_queue *dnssec_answer_query_queue = &answer_context->task->dnssec_answer_query_queue;
    
    u32 count;

    for(count = 1;; count++)
    {
#if DNSSEC_DEBUGLEVEL>1
        log_debug("nsec3_rrsig_updater_result_process(): loop #%i", count);
#endif
        nsec3_rrsig_update_item_s* task = (nsec3_rrsig_update_item_s*)threaded_queue_dequeue(dnssec_answer_query_queue);

        if(task == NULL)
        {
            /* Terminating ... */

#if DNSSEC_DEBUGLEVEL>1
            log_debug("nsec3_rrsig_updater_result_process(): stop #%i", count);
#endif
            break;
        }

#if DNSSEC_DEBUGLEVEL>3
        { /* DEBUG */
            log_debug("nsec3_rrsig_updater_result_process() : retrieving results for");
        }
#endif
        if((task->removed_rrsig_sll != NULL) || (task->added_rrsig_sll != NULL))
        {
            nsec3_rrsig_updater_result_process_item_s *item;
            ZALLOC_ARRAY_OR_DIE(nsec3_rrsig_updater_result_process_item_s *, item, sizeof(nsec3_rrsig_updater_result_process_item_s), GENERIC_TAG);
            item->next = to_commit;
            to_commit = item;
            item->added_rrsig_sll = task->added_rrsig_sll;
            item->removed_rrsig_sll = task->removed_rrsig_sll;
            item->item = task->item;
            //nsec3_update_rrsig_commit(task->removed_rrsig_sll, task->added_rrsig_sll, task->item, context->task->zone);
        }
        
        free(task);

#if DNSSEC_DUMPSIGNCOUNT!=0
        if((count & 0x3fff) == 0)
        {
            u64 elapsed = timems() - sign_start;
            float rate = (1000.f * count) / MAX(elapsed, 1.0f);
            log_debug("signatures updates: %u in %ums (%f/s)", count, elapsed, rate);
        }
#endif
    }

    answer_context->items = to_commit;
    
    ERR_remove_state(0);

#if DNSSEC_DEBUGLEVEL>0
    log_debug("nsec3_rrsig_updater_result_process(): exit");
#endif

    return NULL;
}

static void*
nsec3_rrsig_updater_result_thread(void* context)
{
#if DNSSEC_DEBUGLEVEL>0
    log_debug("dnssec_updater_result_thread(): start");
#endif
    
    nsec3_rrsig_answer_context_s *answer_context = (nsec3_rrsig_answer_context_s*)context;

    void *return_ptr;
    
    return_ptr = nsec3_rrsig_updater_result_process(answer_context);
    
    return return_ptr;
}

static ya_result
nsec3_rrsig_updater_filter_label(dnssec_task_s* task, zdb_rr_label *rr_label)
{
    return DNSSEC_THREAD_TASK_FILTER_IGNORE;
}

static ya_result
nsec3_rrsig_updater_filter_nsec3_item(dnssec_task_s* task, nsec3_zone_item *item, nsec3_zone_item *next)
{   
    rrsig_updater_parms *parms = (rrsig_updater_parms*)task->args;
           
    if(parms->signatures_are_verified)
    {        
        zdb_packed_ttlrdata *rrsig = item->rrsig;
        
        if(rrsig != NULL)
        {
            u32 now = time(NULL);

            do
            {
                u32 until = RRSIG_VALID_UNTIL(rrsig);

                if(until < now)
                {
                    return DNSSEC_THREAD_TASK_FILTER_ACCEPT;
                }

                rrsig = rrsig->next;
            }
            while(rrsig != NULL);
        }
        else
        {
            return DNSSEC_THREAD_TASK_FILTER_ACCEPT;
        }
        
        return DNSSEC_THREAD_TASK_FILTER_IGNORE;
    }
    
    return DNSSEC_THREAD_TASK_FILTER_ACCEPT;
}

static dnssec_task_vtbl nsec3_rrsig_updater_task_descriptor =
{
    nsec3_rrsig_updater_thread_init,
    nsec3_rrsig_updater_thread_create_context,
    nsec3_rrsig_updater_thread_destroy_context,
    nsec3_rrsig_updater_filter_label,
    nsec3_rrsig_updater_filter_nsec3_item,
    nsec3_rrsig_updater_thread,
    nsec3_rrsig_updater_result_thread,
    nsec3_rrsig_updater_thread_finalise,
    "NSEC3 RRSIG updater"
};

void
nsec3_rrsig_updater_init(nsec3_rrsig_updater_parms *parms, zdb_zone *zone)
{
    smp_int *quota = NULL;
    
    if(parms->quota != 0)
    {
        quota = &parms->remaining_quota;
        smp_int_init_set(quota, parms->quota);
    }
    
    parms->to_commit = NULL;
    
    dnssec_process_initialize(&parms->task, &nsec3_rrsig_updater_task_descriptor, NULL, zone);
    parms->task.args = parms;
}

ya_result
nsec3_rrsig_updater_process_zone(nsec3_rrsig_updater_parms *parms)
{
    yassert(parms != NULL);
    
    dnssec_task_s *task = &parms->task;

    zdb_zone *zone = task->zone;
    
    yassert(zone != NULL);
    
    ya_result  return_code = SUCCESS;
    
    if(zdb_zone_is_nsec3(zone))
    {
        /** @note: the scheduled one was not used here ... */
        
        task->args = parms;
        /* work */
        return_code = dnssec_process_zone_nsec3(task);
        /* release */
    }
    
    return return_code;
}

/*
* commits the results from the answers (or the list already built)
*/

void
nsec3_rrsig_updater_commit(nsec3_rrsig_updater_parms *parms)
{
    log_debug1("rrsig_updater_commit(%p)", parms);
            
    dnssec_task_s *task = &parms->task;
    
    nsec3_rrsig_answer_context_s *context = (nsec3_rrsig_answer_context_s*)task->contexts[0];
    
    if(context != NULL && context->items != NULL)
    {
        // commit all the signatures changes
        
        struct nsec3_rrsig_updater_result_process_item_s *to_commit = context->items;
        
        context->items = NULL;
        
        while(to_commit != NULL)
        {
            nsec3_rrsig_updater_result_process_item_s *item = to_commit;
            
            nsec3_update_rrsig_commit(item->removed_rrsig_sll, item->added_rrsig_sll, item->item, context->task->zone);
            
            to_commit = to_commit->next;
            
            ZFREE_ARRAY(item, sizeof(nsec3_rrsig_updater_result_process_item_s));
        }
    }
}

void
nsec3_rrsig_updater_finalize(nsec3_rrsig_updater_parms *parms)
{
    log_debug("rrsig_updater_finalize: good: %u expired: %u wrong: %u",
            parms->good_signatures,
            parms->expired_signatures,
            parms->wrong_signatures);
        
    if(parms->quota != 0)
    {
        smp_int_destroy(&parms->remaining_quota);
    }
}

/** @} */

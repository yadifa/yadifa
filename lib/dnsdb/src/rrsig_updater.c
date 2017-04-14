/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2017, EURid. All rights reserved.
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
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#include <dnscore/logger.h>
#include <dnscore/u32_set.h>

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

#define RRSURPI_TAG 0x49505255535252
#define RRSULPN_TAG 0x4e504c55535252

struct rrsig_updater_result_process_item_s
{
    struct rrsig_updater_result_process_item_s *next;
    zdb_packed_ttlrdata *added_rrsig_sll;
    zdb_packed_ttlrdata *removed_rrsig_sll;
    u8 internal_fqdn[1];
};

typedef struct rrsig_updater_result_process_item_s rrsig_updater_result_process_item_s;

#define RRSACTX_TAG 0x58544341535252

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
        MALLOC_OR_DIE(rrsig_context_s*, ctx, sizeof(rrsig_context_s), RRSIGCTX_TAG);

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
        MALLOC_OR_DIE(rrsig_answer_context_s*, ctx, sizeof(rrsig_answer_context_s), RRSACTX_TAG);
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
        rrsig_updater_parms *parms = (rrsig_updater_parms*)task->args;
        rrsig_answer_context_s *ctx = (rrsig_answer_context_s*)ctx_;
        yassert(parms->to_commit == NULL);
        parms->to_commit = ctx->items;
        ctx->items = NULL;
        ctx->task = NULL;
        free(ctx);
    }
}

/**
 * Computes updates of all the RR set in the label.
 * 
 * @param context the signature context
 * @param label the label to sign
 * @return an error code or the number of signature computed
 * 
 */

ya_result
rrsig_updater_update_label_signatures(rrsig_context_s *context, zdb_rr_label *label)
{
    yassert(context != NULL);

    if(context->key_sll == NULL)
    {
        /* nothing to do */

        return DNSSEC_ERROR_RRSIG_NOSIGNINGKEY;
    }
    
    u8 nsec_flags = context->nsec_flags;
    //bool at_apex = (label->name[0] == 0);

    /* Get all the signatures on this label (NULL if there are no signatures) */

    /**
     * If there are signatures here:
     *   Verify the expiration time :
     *
     *     If it is expired, then destroy it (mark them for destruction)
     *
     *     If it will expire soon AND we are supposed to work on the type AND we have the private key available,
     *     then remove it
     *
     * Don't forget to set UPDATED_SIGNATURES if any change is made
     */

    /* Sign relevant resource records */
    
    s32 sig_count = 0;
    
    if(!ZDB_LABEL_UNDERDELEGATION(label))
    {

        bool has_ksk = FALSE;
        
        btree_iterator iter;
        btree_iterator_init(label->resource_record_set, &iter);

        /* Sign only APEX and DS and NSEC records at delegation */

        while(btree_iterator_hasnext(&iter))
        {
            btree_node *rr_node = btree_iterator_next_node(&iter);
            u16 type = (u16)rr_node->hash;

            /* cannot sign a signature */
            
            if(type == TYPE_RRSIG)
            {
                continue;
            }
            
            if(ZDB_LABEL_ATDELEGATION(label))
            {
                if(!(type == TYPE_DS || type == TYPE_NSEC))
                {
                    continue;
                }
            }
                        
            // not delegation: sign everything
            // delegation: sign only DS and NSEC
            
            if(type == TYPE_DNSKEY)
            {
                // ensure there are KSK
                
                for(const dnssec_key_sll *key_sll = context->key_sll; key_sll != NULL; key_sll = key_sll->next)
                {
                    const dnssec_key* key = key_sll->key;
                    
                    if(key->flags == (DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY))
                    {
                        has_ksk = TRUE;
                        break;
                    }
                }
            }


            for(dnssec_key_sll *key_sll = context->key_sll; key_sll != NULL; key_sll = key_sll->next)
            {
                /* Take the real key from the key container */

                dnssec_key* key = key_sll->key;

                rrsig_context_set_current_key(context, key);

                /* can the key sign this kind of record */

                if(key->flags == (DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY))
                {
                    /* KSK can only sign a DNSKEY */

                    if(type != TYPE_DNSKEY)
                    {
#if RRSIG_DUMP >= 3
                        log_debug5("rrsig: skipping : KSK of !DNSKEY (%{dnstype}/%{dnslabel}.%{dnsnamestack})", &type, label->name, &context->rr_dnsname);
#endif

                        continue;
                    }
                }
                else if(key->flags == DNSKEY_FLAG_ZONEKEY)
                {
                    /* ZSK should not sign a DNSKEY, except if there is no KSK */

                    if((type == TYPE_DNSKEY) && has_ksk)
                    {
#if RRSIG_DUMP >= 3
                        log_debug5("rrsig: skipping ; ZSK of RRSIG (%{dnstype}/%{dnslabel}.%{dnsnamestack})", &type, label->name, &context->rr_dnsname);
#endif
                        continue;
                    }

                    /* if not at apex then only sign the DS */

                    switch(nsec_flags)
                    {
                        case RRSIG_CONTEXT_NSEC3_OPTOUT:
                        {
                            if(ZDB_LABEL_ATDELEGATION(label))
                            {
                                if(type != TYPE_DS) /* at delegation, only sign DS records (not NSEC here) */
                                {
                                    continue;
                                }                                
                            }
                            else
                            {
                                /* sign everything else */
                            }

                            break;
                        }
                        case RRSIG_CONTEXT_NSEC3:
                        {
                            /* sign everything not filtered out yet */
                            break;
                        }
                        case RRSIG_CONTEXT_NSEC:
                        {
                            /* sign everything not filtered out yet */

                            if(ZDB_LABEL_ATDELEGATION(label))
                            {
                                if((type != TYPE_DS) && (type != TYPE_NSEC)) /* at delegation, only sign DS & NSEC records */
                                {
                                    continue;
                                }                                
                            }
                            else
                            {
                                /* sign everything else */
                            }

                            break;
                        }
                    }
                }
                else
                {
                    /* key type is not supported */

                    continue;
                }

                /*
                 * Update signatures of the rrset with that key.
                 */

                zdb_packed_ttlrdata* rr_sll = (zdb_packed_ttlrdata*)rr_node->data;

                ya_result return_code;

                if(FAIL(return_code = rrsig_update_rrset_with_key(context, rr_sll, type, key, type != TYPE_SOA)))
                {
                    return return_code;
                }
                
                sig_count += return_code;
                
            }   /* for every key */
        }
        
        /// remove all expired signatures
        
        zdb_packed_ttlrdata* rrsig_sll = zdb_record_find(&label->resource_record_set, TYPE_RRSIG);

        time_t now = time(NULL);
        
        while(rrsig_sll != NULL)
        {
            u16 covered_type = RRSIG_TYPE_COVERED(rrsig_sll);
            if(ZDB_LABEL_ATDELEGATION(label) && ((covered_type != TYPE_DS) && (covered_type != TYPE_NSEC)))
            {
#if RRSIG_DUMP >= 3
                log_debug5("rrsig: destroying irrelevant signature (%{dnslabel}.%{dnsnamestack} %{dnstype})", label->name, &context->rr_dnsname, &covered_type);
#endif
                rrsig_context_append_delete_signature(context, rrsig_sll);
            }            
            else if(RRSIG_VALID_UNTIL(rrsig_sll) < now)
            {
#if RRSIG_DUMP >= 3
                log_debug5("rrsig: destroying expired signature (%{dnslabel}.%{dnsnamestack} %{dnstype})", label->name, &context->rr_dnsname, &covered_type);
#endif
                rrsig_context_append_delete_signature(context, rrsig_sll);
            }
            
            rrsig_sll = rrsig_sll->next;
        }
    }
    else
    {
        /* no signature under delegation : destroy all signatures */

#if RRSIG_DUMP >= 3        
        log_debug5("rrsig: destroy: %{dnsnamestack} %04x", &context->rr_dnsname, label->flags);
#endif

        zdb_packed_ttlrdata* rrsig_sll = zdb_record_find(&label->resource_record_set, TYPE_RRSIG);

        while(rrsig_sll != NULL)
        {
#if RRSIG_DUMP >= 3
            log_debug5("rrsig: destroying illegaly placed signatures (%{dnslabel}.%{dnsnamestack})", label->name, &context->rr_dnsname);
#endif

            rrsig_context_append_delete_signature(context, rrsig_sll);
            
            rrsig_sll = rrsig_sll->next;
        }
    }

    /* All the signatures for this label have been processed. */

    return sig_count;
}

/**
 * Updates the signatures on the label of a zone based on a signature context
 * 
 * @return the number of signatures worked on or an error code
 */

static ya_result
rrsig_updater_update_label_from_query(rrsig_context_s *sig_context, rrsig_update_item_s *query)
{
    rrsig_context_push_label(sig_context, query->label);
    
    s32 sig_count = rrsig_updater_update_label_signatures(sig_context, query->label); // context has been set with the current label, now signatures can be updated
    
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

    log_debug("rrsig: %{dnsname}: updater thread %x start", origin, id);

#if DNSSEC_DEBUGLEVEL>0
    log_debug("rrsig_updater_thread(%x): starting an UPDATER thread", id);
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
        log_debug("rrsig_updater_thread(%x): dequeue (WAIT)", id);
#endif

        rrsig_update_item_s *query = (rrsig_update_item_s*)threaded_queue_dequeue(dnssec_task_query_queue);

        if(query == NULL)
        {
            /* From this point I should not use the context anymore */

#if DNSSEC_DEBUGLEVEL>1
            log_debug("rrsig_updater_thread(%x): stop", id);
#endif
            break;
        }
        
        if(first_job)
        {
            log_debug1("rrsig: %{dnsname}: rrsig_updater_thread(%x): first query", query->zone->origin, id);
            first_job = FALSE;
        }
        
        if(rrsig_context_get_quota(sig_context) <= 0)
        {
            log_debug1("rrsig: %{dnsname}: quota exceeded, postponing NSEC3 signature query", query->zone->origin);
            rrsig_update_item_free(query);
            
            task->stop_task = true;
            
            continue;
        }
        
        log_debug("rrsig: %{dnsname}: updating %{dnsnamestack}", query->zone->origin, &query->path);
        
#if DNSSEC_DEBUGLEVEL>3
        { /* DEBUG */
            char label[MAX_DOMAIN_LENGTH + 1];
            dnsname_stack_to_cstr(&query->path, label);
            log_debug("rrsig_updater_thread(): processing records for '%s'", label);
        }
#endif

        /**
         * The path to the label to sign is in the query.
         * @todo 20100820 edf -- use the path from the query :
         *
         * rrsig_update_context_add_label
         * rrsig_update_context_remove_label
         *
         */

#ifdef DEBUG
        yassert(query->added_rrsig_sll != ((zdb_packed_ttlrdata*)0xfefefefefefefefe));
#endif
        ya_result made;
        
        if((made = rrsig_updater_update_label_from_query(sig_context, query)) > 0)
        {
            if(first_signature)
            {
                log_debug1("rrsig: %{dnsname}: rrsig_updater_thread(%x): first signature", query->zone->origin, id);
                first_signature = FALSE;
            }
            
            signatures_made += made;
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
        log_debug("rrsig_updater_thread(%x): enqueue (RESULT)", id);
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
            rrsig_update_item_free(query);
        }
#endif

#if DNSSEC_DEBUGLEVEL>1
        log_debug("rrsig_updater_thread(%x): done", id);
#endif
    }

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    ERR_remove_state(0);
#endif

    log_debug1("rrsig: %{dnsname}: updater thread %x stop (made=%d,ignored=%d)", origin, id, signatures_made, labels_ignored);

    /* We don't need this anymore */

#if DNSSEC_DEBUGLEVEL>0
    log_debug("rrsig_updater_thread(%x): exit", id);
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
    
    u8 origin[MAX_DOMAIN_LENGTH];

    dnsname_copy(origin, task->zone->origin);
    
#if DNSSEC_DEBUGLEVEL>0
    log_debug("dnssec_updater_result_thread(): start");
#endif

    log_debug("rrsig: %{dnsname}: updater thread result start", origin);

#if DNSSEC_DUMPSIGNCOUNT
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
            ZALLOC_ARRAY_OR_DIE(rrsig_updater_result_process_item_s *, item, sizeof(rrsig_updater_result_process_item_s) - 1 + fqdn_len, RRSURPI_TAG);
            item->next = to_commit;
            to_commit = item;
            item->added_rrsig_sll = query->added_rrsig_sll;
            item->removed_rrsig_sll = query->removed_rrsig_sll;
            dnsname_stack_to_dnsname(&query->path, &item->internal_fqdn[0]);
            /// @note 20160502 edf -- DO NOT DO THIS ANYMORE : rrsig_update_commit(query->removed_rrsig_sll, query->added_rrsig_sll, query->label, query->zone, &query->path); // in rrsig_updater_thread(void *context_)
        }
        
        // this is the last processed point
        
        if(previous_query != NULL)
        {
#ifdef DEBUG
            memset(previous_query, 0xfe, sizeof(rrsig_update_item_s));
#endif
            rrsig_update_item_free(previous_query);
        }
        
        previous_query = query;

#if DNSSEC_DUMPSIGNCOUNT
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
    
    if(answer_context->items == NULL)
    {
        answer_context->items = to_commit;
    }
    else
    {
        struct rrsig_updater_result_process_item_s *last = answer_context->items;
        while(last->next != NULL)
        {
            last = last->next;
        }
        last->next = to_commit;
    }
    
    //
    
    if(previous_query != NULL)
    {
        // remember the last processed point
        
        // the next iteration will start from/after this point
        
        u32 path_len = dnsname_stack_len(&previous_query->path);
        u32 origin_len = dnsname_len(previous_query->zone->origin);
        
#ifdef DEBUG
        log_debug("rrsig: %{dnsname}: updater thread next iteration will start from path=%{dnsnamestack} (path lenght=%u, origin lenght=%u)",
                previous_query->zone->origin, &previous_query->path, path_len, origin_len);
#endif
        
        // allocate path_len - origin_len        
        // copy the name below the origin
        // set it as sig_last_processed_node
        
        if(previous_query->zone->sig_last_processed_node != NULL)
        {
            ZFREE_STRING(previous_query->zone->sig_last_processed_node);
            previous_query->zone->sig_last_processed_node = NULL;
        }
        
        u8 *sig_last_processed_node;
        u32 len = path_len - origin_len;
        
        if(len > 0)
        {
            ZALLOC_STRING_OR_DIE(u8 *,sig_last_processed_node, len, RRSULPN_TAG);
            previous_query->zone->sig_last_processed_node = sig_last_processed_node;
            const u8 *sig_last_processed_node_limit = &sig_last_processed_node[len];
            for(s32 size = previous_query->path.size; (sig_last_processed_node < sig_last_processed_node_limit) && (size >= 0); size--)
            {
                sig_last_processed_node += dnslabel_copy(sig_last_processed_node, previous_query->path.labels[size]);
            }
        }
        
        // release
        
#ifdef DEBUG
        memset(previous_query, 0xfe, sizeof(rrsig_update_item_s));
#endif

        rrsig_update_item_free(previous_query);
        
        previous_query = NULL;
    }

#if DNSSEC_DUMPSIGNCOUNT
    u64 elapsed = timems() - sign_start;
    float rate = (1000.f * count) / MAX((1.0f*elapsed),1.000f);
    log_debug("rrsig: updater thread result : %u in %llums (%f/s)", count, elapsed, rate);
#endif

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    ERR_remove_state(0);
#endif

    log_debug("rrsig: %{dnsname}: updater thread result end", origin);

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
    void *ret = rrsig_updater_result_process(context);
    return ret;
}

/**
 * Return TRUE iff the label should be resigned.
 * Expected to be called at apex.
 * 
 * @param task
 * @param rr_label
 * @return 
 */

static bool
rrsig_updater_filter_label_apex(dnssec_task_s *task, zdb_rr_label *rr_label)
{
    rrsig_updater_parms *parms = (rrsig_updater_parms*)task->args;
    
    if(parms->signatures_are_verified)
    {
        zdb_packed_ttlrdata *rrsig_set = zdb_record_find(&rr_label->resource_record_set, TYPE_RRSIG);
        int unknown_zsk = 0;
        int unknown_ksk = 0;
        bool has_dnskey = false;

        u32 now = time(NULL);
        
        btree_iterator iter;
        btree_iterator_init(rr_label->resource_record_set, &iter);

        /* Sign only APEX and DS and NSEC records at delegation */

        while(btree_iterator_hasnext(&iter))
        {
            btree_node *rr_node = btree_iterator_next_node(&iter);
            
            u16 type = (u16)rr_node->hash;
            
            if(type == TYPE_RRSIG)
            {
                continue;
            }
            
            if(rrsig_set != NULL)
            {
                zdb_packed_ttlrdata *rrsig = rrsig_set;
                
                do
                {
                    u32 until = RRSIG_VALID_UNTIL(rrsig);

                    if(until < now)
                    {
                        return TRUE; // resign, or update (remove signature)
                    }
                    
                    task->earliest_signature_expiration = MIN(task->earliest_signature_expiration, until);
                    
                    if(RRSIG_TYPE_COVERED(rrsig) == type)
                    {
                        if(type == TYPE_DNSKEY)
                        {
                            unknown_zsk += rrsig_updater_mark_tag(&parms->zsk_tag_set, RRSIG_KEY_TAG(rrsig));
                        }
                        else
                        {                        
                            unknown_ksk += rrsig_updater_mark_tag(&parms->ksk_tag_set, RRSIG_KEY_TAG(rrsig));
                            has_dnskey = TRUE;
                        }
                    }
                    
                    rrsig = rrsig->next;
                }
                while(rrsig != NULL);
                
                bool redo_zsk = rrsig_updater_clear_tags(&parms->zsk_tag_set);
                bool redo_ksk = FALSE;
                
                if(has_dnskey)
                {
                    redo_ksk = rrsig_updater_clear_tags(&parms->ksk_tag_set);
                }
                
                if(redo_zsk|redo_ksk|(unknown_zsk != 0)|(unknown_ksk != 0))
                {
                    // not pristine : do it
                    
                    return TRUE;
                }
            }
            else
            {
                // not signed : do it
                return TRUE;
            }
        }
        
        return FALSE;
    }
    else
    {
        // signatures need to be verified

        return TRUE;
    }
}


/**
 * Return TRUE iff the label should be resigned.
 * Expected to be called outside of a delegation and not at apex.
 * 
 * @param task
 * @param rr_label
 * @return 
 */

static bool
rrsig_updater_filter_label_rrsig(dnssec_task_s *task, zdb_rr_label *rr_label)
{
    rrsig_updater_parms *parms = (rrsig_updater_parms*)task->args;
    
    if(parms->signatures_are_verified)
    {
        zdb_packed_ttlrdata *rrsig_set = zdb_record_find(&rr_label->resource_record_set, TYPE_RRSIG);
        int unknown_zsk = 0;

        u32 now = time(NULL);
        
        btree_iterator iter;
        btree_iterator_init(rr_label->resource_record_set, &iter);

        /* Sign only APEX and DS and NSEC records at delegation */

        while(btree_iterator_hasnext(&iter))
        {
            btree_node *rr_node = btree_iterator_next_node(&iter);
            
            u16 type = (u16)rr_node->hash;
            
            if(type == TYPE_RRSIG)
            {
                continue;
            }
            
            if(rrsig_set != NULL)
            {
                zdb_packed_ttlrdata *rrsig = rrsig_set;
                
                do
                {
                    u32 until = RRSIG_VALID_UNTIL(rrsig);

                    if(until < now)
                    {
                        return TRUE; // resign, or update (remove signature)
                    }
                    
                    task->earliest_signature_expiration = MIN(task->earliest_signature_expiration, until);
                    
                    if(RRSIG_TYPE_COVERED(rrsig) == type)
                    {
                        unknown_zsk += rrsig_updater_mark_tag(&parms->zsk_tag_set, RRSIG_KEY_TAG(rrsig));
                    }
                    
                    rrsig = rrsig->next;
                }
                while(rrsig != NULL);
                
                bool redo_zsk = rrsig_updater_clear_tags(&parms->zsk_tag_set);
                
                if(redo_zsk|(unknown_zsk != 0))
                {
                    // not pristine : do it
                    
                    return TRUE;
                }
            }
            else
            {
                // not signed : do it
                return TRUE;
            }
        }
        
        return FALSE;
    }
    else
    {
        // signatures need to be verified

        return TRUE;
    }
}

/**
 * Return TRUE iff the label should be resigned.
 * Expected to be called at a delegation.
 * 
 * @param task
 * @param rr_label
 * @return 
 */

static bool
rrsig_updater_filter_label_delegation(dnssec_task_s *task, zdb_rr_label *rr_label)
{
    rrsig_updater_parms *parms = (rrsig_updater_parms*)task->args;
    
    if(parms->signatures_are_verified)
    {
        zdb_packed_ttlrdata *rrsig_set = zdb_record_find(&rr_label->resource_record_set, TYPE_RRSIG);
        int unknown_zsk = 0;

        u32 now = time(NULL);
        
        btree_iterator iter;
        btree_iterator_init(rr_label->resource_record_set, &iter);

        /* Sign only APEX and DS and NSEC records at delegation */

        while(btree_iterator_hasnext(&iter))
        {
            btree_node *rr_node = btree_iterator_next_node(&iter);
            
            u16 type = (u16)rr_node->hash;
            
            if(type == TYPE_RRSIG)
            {
                continue;
            }
            
            bool must_be_signed = (type == TYPE_NSEC) || (type == TYPE_DS);
            
            if(rrsig_set != NULL)
            {
                zdb_packed_ttlrdata *rrsig = rrsig_set;
                
                do
                {                    
                    u32 until = RRSIG_VALID_UNTIL(rrsig);

                    if(until < now)
                    {
                        return TRUE; // remove or update
                    }
                    
                    task->earliest_signature_expiration = MIN(task->earliest_signature_expiration, until);
                    
                    if(RRSIG_TYPE_COVERED(rrsig) == type)
                    {
                        if(must_be_signed)
                        {
                            unknown_zsk += rrsig_updater_mark_tag(&parms->zsk_tag_set, RRSIG_KEY_TAG(rrsig));
                        }
                        else
                        {
                            return TRUE; // cannot be signed, remove signature
                        }
                    }
                    
                    rrsig = rrsig->next;
                }
                while(rrsig != NULL);
                
                if(must_be_signed)
                {
                    bool redo_zsk = rrsig_updater_clear_tags(&parms->zsk_tag_set);

                    if(redo_zsk|(unknown_zsk != 0))
                    {
                        // not pristine : do it

                        return TRUE;
                    }
                }
            }
            else
            {
                if(must_be_signed)
                {
                    // not signed : do it
                    return TRUE;
                }
            }
        }
        
        return FALSE;
    }
    else
    {
        // signatures need to be verified

        return TRUE;
    }
}


/**
 * Return TRUE iff the label should be resigned.
 * Expected to be called at a delegation.
 * 
 * @param task
 * @param rr_label
 * @return 
 */

static bool
rrsig_updater_filter_label_under_delegation(dnssec_task_s *task, zdb_rr_label *rr_label)
{
    zdb_packed_ttlrdata * rrsig = zdb_record_find(&rr_label->resource_record_set, TYPE_RRSIG);

    // no signature allowed
    
    return (rrsig != NULL);
}

static ya_result
rrsig_updater_filter_label(dnssec_task_s *task, zdb_rr_label *rr_label)
{
    if(LABEL_HAS_RECORDS(rr_label)) // there are records on this domain/label
    {
        if(ZDB_LABEL_ISAPEX(rr_label)) // it's the apex : everything must be signed
        {
            if(rrsig_updater_filter_label_apex(task, rr_label))
            {
                return DNSSEC_THREAD_TASK_FILTER_ACCEPT;
            }
        }
        else
        {
            // not the apex
            // at delegation: only DS & NSEC records must be signed

            if(ZDB_LABEL_ATDELEGATION(rr_label))
            {
                if(rrsig_updater_filter_label_delegation(task, rr_label))
                {
                    return DNSSEC_THREAD_TASK_FILTER_ACCEPT;
                }

                return DNSSEC_THREAD_TASK_FILTER_IGNORE;
            }
            else
            {
                // not under a delegation: sign

                if(!ZDB_LABEL_UNDERDELEGATION(rr_label))
                {
                    if(rrsig_updater_filter_label_rrsig(task, rr_label))
                    {
                        return DNSSEC_THREAD_TASK_FILTER_ACCEPT;
                    }
                }
                else
                {
                    // under a delegation, there are no signatures
                    if(rrsig_updater_filter_label_under_delegation(task, rr_label))
                    {
                        return DNSSEC_THREAD_TASK_FILTER_ACCEPT;
                    }
                }
            }
        }
    }

    return DNSSEC_THREAD_TASK_FILTER_IGNORE;
}

#if ZDB_HAS_NSEC3_SUPPORT
static ya_result
rrsig_updater_filter_nsec3_item(dnssec_task_s *task, nsec3_zone_item *item, nsec3_zone_item *next)
{
    (void)task;
    (void)item;
    (void)next;
    return DNSSEC_THREAD_TASK_FILTER_IGNORE;
}
#endif

static dnssec_task_vtbl rrsig_updater_task_descriptor =
{
    rrsig_updater_thread_init,
    rrsig_updater_thread_create_context,
    rrsig_updater_thread_destroy_context,
    rrsig_updater_filter_label,
#if ZDB_HAS_NSEC3_SUPPORT
    rrsig_updater_filter_nsec3_item,
#endif
    rrsig_updater_thread,
    rrsig_updater_result_thread,
    rrsig_updater_thread_finalise,
    "RRSIG updater"
};

rrsig_updater_parms*
rrsig_updater_parms_alloc()
{
    rrsig_updater_parms *parms;
    
    ZALLOC_OR_DIE(rrsig_updater_parms*, parms, rrsig_updater_parms, RRSUPRMS_TAG);
    ZEROMEMORY(parms, sizeof(rrsig_updater_parms));
    
    return parms;
}

void
rrsig_updater_parms_free(rrsig_updater_parms *parms)
{
    if(parms != NULL)
    {
        u32_set_avl_destroy(&parms->ksk_tag_set);
        u32_set_avl_destroy(&parms->zsk_tag_set);
        ZFREE(parms, rrsig_updater_parms);
    }
}

/**
 * Clears all the usage marks of the tags.
 * Returns the number of missing marks.
 * 
 * @param tag set
 * @return the number of missing marks
 */

u32
rrsig_updater_clear_tags(u32_set *set)
{
    u32 missing = 0;
    u32_set_avl_iterator iter;    
    u32_set_avl_iterator_init(set, &iter);
    while(u32_set_avl_iterator_hasnext(&iter))
    {
        u32_node *node = u32_set_avl_iterator_next_node(&iter);
        if(node->value == NULL)
        {
            ++missing;
        }
        node->value = NULL;
    }
    return missing;
}

/**
 * Adds a tag in the set
 * 
 * @param set
 * @param tag
 */

void
rrsig_updater_add_tag(u32_set *set, u32 tag)
{
    u32_set_avl_insert(set, tag);
}

/**
 * Marks a tag in the set.
 * Returns 1 if the tag was not found, 0 otherwise
 *  * 
 * @param set
 * @param tag
 * 
 * @return 1 if the tag was not found, 0 otherwise
 */

int
rrsig_updater_mark_tag(u32_set *set, u32 tag)
{
    u32_node *node = u32_set_avl_find(set, tag);
    if(node != NULL)
    {
        node->value = (void*)(((intptr)node->value) + 1);
        return 0;
    }
    else
    {
        return 1;  // not found
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
    
    parms->ksk_tag_set = NULL;
    parms->zsk_tag_set = NULL;

    dnssec_process_initialize(&parms->task, &rrsig_updater_task_descriptor, NULL, zone);
    parms->task.args = parms;
    
    log_debug1("rrsig_updater_init(%p,%{dnsname}) done", parms, zone->origin);
}

/**
 * Prepares the DNSKEYs and the parameters.
 * Loads the (missing) private keys.
 * Marks the tags of the keys in the parms
 * Returns a mask of ZSK(1) or KSK(2) found, or an error code
 * 
 * @param parms
 * @param zone
 * @return 
 */

ya_result
rrsig_updater_prepare_keys(rrsig_updater_parms *parms, zdb_zone *zone)
{
    const zdb_packed_ttlrdata *dnskey_rrset = zdb_record_find(&zone->apex->resource_record_set, TYPE_DNSKEY);
    
    if(dnskey_rrset == NULL)
    {
        return ZDB_ERROR_ZONE_NO_ACTIVE_DNSKEY_FOUND;
    }
    
    ya_result has_zsk = 0;
    ya_result has_ksk = 0;
    
    ya_result ret;
    
    char origin_ascii[MAX_DOMAIN_LENGTH];
    
    dnsname_to_cstr(origin_ascii, zone->origin);
    
    do
    {
        const u8 *rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(dnskey_rrset);
        const u16 rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(dnskey_rrset);
        
        u16 tag = dnskey_get_key_tag_from_rdata(rdata, rdata_size);
        u16 key_flags = DNSKEY_FLAGS_FROM_RDATA(rdata); // native
        u8 algorithm = rdata[3];
        
        switch(algorithm)
        {
            case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            case DNSKEY_ALGORITHM_DSASHA1:
            case DNSKEY_ALGORITHM_RSASHA1:
            case DNSKEY_ALGORITHM_ECDSAP256SHA256:
            case DNSKEY_ALGORITHM_ECDSAP384SHA384:
            {
                if(key_flags == DNSKEY_FLAGS_ZSK)
                {
                    dnssec_key *key;
                    if(ISOK(ret = dnssec_keystore_load_private_key_from_parameters(algorithm, tag, key_flags, zone->origin, &key))) // converted
                    {
                        // good to go
                        dnskey_release(key);
                        
                        rrsig_updater_add_tag(&parms->zsk_tag_set, tag);
                        
                        has_zsk = RRSIG_UPDATER_PREPARE_KEYS_ZSK;
                    }
                }
                else if(key_flags == DNSKEY_FLAGS_KSK)
                {
                    dnssec_key *key;
                    if(ISOK(ret = dnssec_keystore_load_private_key_from_parameters(algorithm, tag, key_flags, zone->origin, &key))) // converted
                    {
                        // good to go
                        dnskey_release(key);
                        has_ksk = RRSIG_UPDATER_PREPARE_KEYS_KSK;
                        rrsig_updater_add_tag(&parms->ksk_tag_set, tag);
                    }
                }
                break;
            }
            default:
            {
                ret = DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM; // value will not be used
                break;
            }
        }
        
        dnskey_rrset = dnskey_rrset->next;
    }
    while(dnskey_rrset != NULL);
    
    ret = has_zsk|has_ksk;
    
    if(ret == 0)
    {
        ret = ZDB_ERROR_ZONE_NO_ZSK_PRIVATE_KEY_FILE;
    }
    
    return ret;
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
    log_debug1("rrsig_updater_process_zone(%p{%{dnsname}})", parms, parms->task.zone->origin);
    
    dnssec_task_s *task = &parms->task;
    ya_result ret;
    zdb_zone_label_iterator iter;
    dnsname_stack fqdn_stack;
    
    // initialises the queues, puts the processors and the answer threads into
    // the pool
    
    if(FAIL(ret = dnssec_process_begin(task)))
    {
        log_debug1("rrsig_updater_process_zone(%p{%{dnsname}}): failed to begin: %r", parms, parms->task.zone->origin, ret);
        return ret;
    }
    
    // starts iterating from the APEX or continues from the the last label.
    
    if(task->zone->sig_last_processed_node == NULL)
    {
        zdb_zone_label_iterator_init(&iter, task->zone);
    }
    else
    {
        u8 len = task->zone->sig_last_processed_node[-1];
        u8 fqdn[MAX_DOMAIN_LENGTH];
        memcpy(fqdn, task->zone->sig_last_processed_node, len);
        memcpy(&fqdn[len], task->zone->origin, dnsname_len(task->zone->origin));
        zdb_zone_label_iterator_init_from(&iter, task->zone, fqdn);
        ZFREE_STRING(task->zone->sig_last_processed_node);
        task->zone->sig_last_processed_node = NULL;
    }
    
    while(zdb_zone_label_iterator_hasnext(&iter))
    {
        memcpy(&fqdn_stack.labels[0], &iter.dnslabels[0], (iter.top + 1) * sizeof(u8*));
        fqdn_stack.size = iter.top;

#ifdef DEBUG
        log_debug2("rrsig: %{dnsname}: check %{dnsnamestack}", task->zone->origin, &fqdn_stack);
#endif  
        
        zdb_rr_label *rr_label = zdb_zone_label_iterator_next(&iter);
        
        if(task->vtbl->filter_label(task, rr_label) == DNSSEC_THREAD_TASK_FILTER_ACCEPT)
        {
#ifdef DEBUG
            log_debug1("rrsig: %{dnsname}: queuing %{dnsnamestack} for update", task->zone->origin, &fqdn_stack);
#endif    
            rrsig_update_item_s *query = rrsig_update_item_alloc();
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
        else
        {
#ifdef DEBUG
            log_debug1("rrsig: %{dnsname}: ignore %{dnsnamestack}", task->zone->origin, &fqdn_stack);
#endif
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
            
    ret = parms->quota - smp_int_get(&parms->remaining_quota);
    
    log_debug1("rrsig_updater_process_zone(%p{%{dnsname}}): %i", parms, parms->task.zone->origin, ret);
    
    return ret;
}

/*
* commits the results from the answers (or the list already built)
*/

void
rrsig_updater_commit(rrsig_updater_parms *parms)
{
    log_debug1("rrsig_updater_commit(%p{%{dnsname}})", parms, parms->task.zone->origin);
            
    dnssec_task_s *task = &parms->task;
    
    struct rrsig_updater_result_process_item_s *to_commit = NULL;
    
    if(parms->to_commit != NULL)
    {
        to_commit = parms->to_commit;
    }
    else if(task->contexts != NULL && task->processor_threads_count > 0)
    {
        rrsig_answer_context_s *context = (rrsig_answer_context_s*)task->contexts[0];        
        if(context != NULL && context->items != NULL)
        {
            to_commit = context->items;
            context->items = NULL;
        }
    }
    
    // commit all the signatures changes
    
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
            rrsig_update_commit(item->removed_rrsig_sll, item->added_rrsig_sll, label, zone, &path); // in rrsig_updater_commit(rrsig_updater_parms*)
        }
        else
        {
            log_err("rrsig: %{dnsname}: label %{dnsname} disappeared while signing", zone->origin, item->internal_fqdn);
        }

        to_commit = to_commit->next;

        ZFREE_ARRAY(item, sizeof(rrsig_updater_result_process_item_s) - 1 + dnsname_len(item->internal_fqdn));
    }
    
    log_debug1("rrsig_updater_commit(%p{%{dnsname}}) done", parms, parms->task.zone->origin);
}

void
rrsig_updater_finalize(rrsig_updater_parms *parms)
{
#ifdef DEBUG
    log_debug1("rrsig_updater_finalize(%p{%{dnsname}}) begin", parms, parms->task.zone->origin);
#endif
    log_debug("rrsig: %{dnsname}: good: %u expired: %u wrong: %u",
            parms->task.zone->origin,
            parms->good_signatures,
            parms->expired_signatures,
            parms->wrong_signatures);
        
    if(parms->quota != 0)
    {
        smp_int_destroy(&parms->remaining_quota);
    }
    
    u32_set_avl_destroy(&parms->ksk_tag_set);
    u32_set_avl_destroy(&parms->zsk_tag_set);
    
    log_debug1("rrsig_updater_finalize(%p{%{dnsname}}) done", parms, parms->task.zone->origin);
    
    dnssec_process_finalize(&parms->task);
}

/** @} */

/*----------------------------------------------------------------------------*/

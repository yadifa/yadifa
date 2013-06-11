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
/** @defgroup nsec3 NSEC3 functions
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

#include <dnscore/base32hex.h>
#include <dnscore/typebitmap.h>

#include "dnsdb/zdb_types.h"

#include "dnsdb/zdb_record.h"

#include "dnsdb/dnssec.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/nsec3.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

/*****************************************************************************
 *****************************************************************************
 *
 * UPDATER
 *
 *****************************************************************************
 *****************************************************************************/

#define NSEC3_RRSIG_TTLRDATA_TAG	0x5254474953334e /* RRSIGTR */

/* MULTIPLE INSTANCES */

static void*
nsec3_rrsig_updater_thread(void* context_)
{
    /* Initialization */

    zassert(context_ != NULL);

    processor_thread_context* context = (processor_thread_context*)context_;
    threaded_queue* dnssec_task_query_queue = context->query_queue;
    threaded_queue* dnssec_task_answer_queue = context->answer_queue;

    zdb_packed_ttlrdata* nsec3_ttlrdata;

    MALLOC_OR_DIE(zdb_packed_ttlrdata*, nsec3_ttlrdata, 1 + 1 + 2 + 1 + 255 + 1 + 255 + TYPE_BIT_MAPS_MAX_RDATA_SIZE, NSEC3_RRSIG_TTLRDATA_TAG);

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

        nsec3_rrsig_update_query* query = (nsec3_rrsig_update_query*)threaded_queue_dequeue(dnssec_task_query_queue);

        if(query == NULL)
        {
#if DNSSEC_DEBUGLEVEL>1
            log_debug("nsec3_rrsig_updater_thread(%i): stop", id);
#endif

            break;
        }

        zassert(query->item != NULL);

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

        rrsig_update_context_push_name_rrsigsll(&context->sig_context, digest_to_dnsname, item->rrsig);

        dnssec_key_sll* key_sll;

        /* Build a temporary record into nsec3_ttlrdata */

        nsec3_ttlrdata->next = NULL;
        nsec3_ttlrdata->ttl = context->sig_context.min_ttl;
        u32 n3_rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
        MEMCOPY(&nsec3_ttlrdata->rdata_start[0], &n3->rdata[0], n3_rdata_size);
        MEMCOPY(&nsec3_ttlrdata->rdata_start[n3_rdata_size], next->digest, digest_len + 1);
        n3_rdata_size += digest_len + 1;
        MEMCOPY(&nsec3_ttlrdata->rdata_start[n3_rdata_size], item->type_bit_maps, item->type_bit_maps_size);
        n3_rdata_size += item->type_bit_maps_size;
        nsec3_ttlrdata->rdata_size = n3_rdata_size;

        /* While we have signing keys ... */

        for(key_sll = context->sig_context.key_sll; key_sll != NULL; key_sll = key_sll->next)
        {
            /* Take the real key from the key container */

            dnssec_key* key = key_sll->key;

            if(key->flags == (DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY))
            {
                /* KSK */

                continue;
            }

            rrsig_update_context_set_key(&context->sig_context, key);

            rrsig_update_records(&context->sig_context, key, nsec3_ttlrdata, TYPE_NSEC3, TRUE);
        }

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
        log_debug("nsec3_rrsig_updater_thread(%i): enqueue (RESULT)", id);
#endif

        zassert(query->item != NULL);

        threaded_queue_enqueue(dnssec_task_answer_queue, query);

#if DNSSEC_DEBUGLEVEL>1
        log_debug("nsec3_rrsig_updater_thread(%i): done", id);
#endif
    }

    free(nsec3_ttlrdata);

    ERR_remove_state(0);

#if DNSSEC_DEBUGLEVEL>0
    log_debug("nsec3_rrsig_updater_thread(%i): exit", id);
#endif

#if ZDB_USE_THREADPOOL != 0
    /* calling pthread_exit would kill the thread from the pool : not good */
#else

    pthread_exit(NULL);
#endif

    return NULL;
}

/* ONE INSTANCE */

static void*
nsec3_rrsig_updater_result_process(threaded_queue* dnssec_answer_query_queue, bool schedule)
{
#if DNSSEC_DEBUGLEVEL>0
    log_debug("nsec3_rrsig_updater_result_process(): start");
#endif

#if DNSSEC_DUMPSIGNCOUNT!=0
    u64 sign_start = timems();
#endif
    
    u32 count;

    for(count = 1;; count++)
    {
#if DNSSEC_DEBUGLEVEL>1
        log_debug("nsec3_rrsig_updater_result_process(): loop #%i", count);
#endif

        nsec3_rrsig_update_query* task = (nsec3_rrsig_update_query*)threaded_queue_dequeue(dnssec_answer_query_queue);

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

        if(schedule)
        {
            scheduler_task_nsec3_rrsig_update_commit(task->removed_rrsig_sll, task->added_rrsig_sll, task->item, task->zone, task);
        }
        else
        {
            nsec3_update_rrsig_commit(task->removed_rrsig_sll, task->added_rrsig_sll, task->item, task->zone);
            free(task);
        }


#if DNSSEC_DUMPSIGNCOUNT!=0
        if((count & 0x3fff) == 0)
        {
            u64 elapsed = timems() - sign_start;
            float rate = (1000.f * count) / MAX(elapsed, 1.0f);
            log_debug("signatures updates: %u in %ums (%f/s)", count, elapsed, rate);
        }
#endif
    }

    ERR_remove_state(0);

#if DNSSEC_DEBUGLEVEL>0
    log_debug("nsec3_rrsig_updater_result_process(): exit");
#endif

#if ZDB_USE_THREADPOOL != 0
    /* calling pthread_exit would kill the thread from the pool : not good */
#else
    pthread_exit(NULL);
#endif
    return NULL;
}

static void*
nsec3_rrsig_updater_result_thread(void* context)
{
#if DNSSEC_DEBUGLEVEL>0
    log_debug("dnssec_updater_result_thread(): start");
#endif

    threaded_queue* dnssec_answer_query_queue = (threaded_queue*)context;

    return nsec3_rrsig_updater_result_process(dnssec_answer_query_queue, FALSE);
}

static void*
nsec3_rrsig_updater_result_thread_scheduled(void* context)
{
#if DNSSEC_DEBUGLEVEL>0
    log_debug("dnssec_updater_result_thread(): start");
#endif

    threaded_queue* dnssec_answer_query_queue = (threaded_queue*)context;

    return nsec3_rrsig_updater_result_process(dnssec_answer_query_queue, TRUE);
}

static ya_result
nsec3_rrsig_updater_init(dnssec_task* task)
{
    dnssec_inittask(0, task);
    
    return SUCCESS;
}

static ya_result
nsec3_rrsig_updater_finalize(dnssec_task* task)
{
    task->task_flags = 0;
    
    return SUCCESS;
}

dnssec_task_descriptor dnssec_nsec3_updater_task_descriptor =
{
    nsec3_rrsig_updater_init,
    nsec3_rrsig_updater_finalize,
    nsec3_rrsig_updater_thread,
    nsec3_rrsig_updater_result_thread,
    "NSEC3 RRSIG updater"
};

dnssec_task_descriptor dnssec_nsec3_updater_task_descriptor_scheduled = {
    nsec3_rrsig_updater_init,
    nsec3_rrsig_updater_finalize,
    nsec3_rrsig_updater_thread,
    nsec3_rrsig_updater_result_thread_scheduled,
    "NSEC3 RRSIG scheduled updater"
};


/** @} */

/*----------------------------------------------------------------------------*/


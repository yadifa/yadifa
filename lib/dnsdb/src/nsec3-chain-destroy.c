/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2016, EURid. All rights reserved.
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

#include "dnsdb/dnsdb-config.h"
#include <dnscore/ptr_vector.h>
#include <dnscore/logger.h>

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_icmtl.h"
#include "dnsdb/zdb_listener.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/rrsig.h"

#include "dnsdb/nsec_common.h"
#include "dnsdb/nsec3.h"
#include "dnsdb/nsec3_types.h"
#include "dnsdb/nsec3_item.h"
#include "dnsdb/nsec3-forall-label.h"
#include "dnsdb/nsec3_rrsig_updater.h"
#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#define NSEC3_CHAIN_DESTROY_BATCH_SIZE 64 // records at once

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

static struct thread_pool_s* nsec3_chain_destroy_pool = NULL;

#define NSEC3CD_TAG 0x4443334345534e

struct nsec3_chain_destroy_s
{
    ptr_vector label_fqdn;
    ptr_vector label_digest;
    zdb_zone *zone;
    nsec3_chain_callback *callback;
    void *callback_args;
    s8 chain_index;
};

typedef struct nsec3_chain_destroy_s nsec3_chain_destroy_s;


static bool nsec3_chain_destroy_swap_two_first_chains(zdb_zone *zone)
{
    nsec3_zone *n3a = zone->nsec.nsec3;
    
    if(n3a == NULL)
    {
        return FALSE;
    }
    
    nsec3_zone *n3b = n3a->next;
    
    if(n3b == NULL)
    {
        return FALSE;
    }
    
    // for all labels,
    // take its first nsec3 extension and the following one and swap them
    
    zdb_zone_label_iterator label_iterator;
    zdb_zone_label_iterator_init(&label_iterator, zone);

    while(zdb_zone_label_iterator_hasnext(&label_iterator))
    {
        zdb_rr_label* label = zdb_zone_label_iterator_next(&label_iterator);
        nsec3_label_extension *ext_a = label->nsec.nsec3;
        
        if(ext_a != NULL)
        {
            nsec3_label_extension *ext_b = ext_a->next;
            
            yassert(ext_b != NULL);
            
            label->nsec.nsec3 = ext_b;
            ext_a->next = ext_b->next;
            ext_b->next = ext_a;
        }
    }
    
    zone->nsec.nsec3 = n3b;
    n3a->next = n3b->next;
    n3b->next = n3a;
    
    return TRUE;
}

static void*
nsec3_chain_destroy_thread(void* args)
{
    nsec3_chain_destroy_s* ctx = (nsec3_chain_destroy_s*)args;
    //nsec3_forall_label(nsec3_chain_update->zone, nsec3_chain_update->chain_index,
    //                  TRUE, nsec3_chain_update->opt_out,
    //                  nsec3_chain_create_callback, nsec3_chain_update);
    //nsec3_chain_update->zone->nsec.nsec3.
    u32 min_ttl = 600; /// @todo 20151102 edf -- fix me
    zdb_icmtl icmtl;
    
    if(ctx->chain_index == 0)
    {
        // swap witch chain 1
        
        zdb_zone_lock(ctx->zone, ZDB_ZONE_MUTEX_NSEC3);
        
        if(!nsec3_chain_destroy_swap_two_first_chains(ctx->zone))
        {
            // the operation can fail if there are less than 2 nsec3 chains.
            // this case is not supported
            
            zdb_zone_unlock(ctx->zone, ZDB_ZONE_MUTEX_NSEC3);
            
            ZFREE(ctx, nsec3_chain_destroy_s);
            return NULL;
        }
        
        // ensure the label<->nsec3 links are OK
        
        nsec3_zone_update_chain0_links(ctx->zone);
        
        zdb_zone_unlock(ctx->zone, ZDB_ZONE_MUTEX_NSEC3);
                
        ctx->chain_index = 1;
    }
    
    nsec3_zone* n3 = zdb_zone_get_nsec3chain(ctx->zone, ctx->chain_index);
    
    
    
/* 
 *  Take N and signatures
 *  Remove them
 *  Remove the previous and signature and add the updated previous (not signature)
 *
    nsec3_avl_iterator iter;
    nsec3_avl_iterator_init(&n3->items, &iter);

    while(nsec3_avl_iterator_hasnext(&iter))
    {
        nsec3_zone_item* node = nsec3_avl_iterator_next_node(&iter);

        zdb_listener_notify_add_nsec3(zone, node, n3, min_ttl);
    }
 */
    nsec3_zone_item *node_to_remove[NSEC3_CHAIN_DESTROY_BATCH_SIZE];
    
    ya_result ret;
    
    while(!nsec3_avl_isempty(&n3->items))
    {
        nsec3_zone_item *prev = NULL;
        nsec3_zone_item *node = NULL;
        int node_to_remove_index = 0;
        nsec3_avl_iterator iter;
        nsec3_avl_iterator_init(&n3->items, &iter);

        while(FAIL(ret = zdb_icmtl_begin(&icmtl, ctx->zone)))
        {
            log_debug1("nsec3: rrsig: %{dnsname}[%d]: zone is already being edited: %r", ctx->zone->origin, ctx->chain_index, ret);
            usleep(1000);
        }
        
        //bool update_prev = TRUE;

        while((node_to_remove_index < NSEC3_CHAIN_DESTROY_BATCH_SIZE) && nsec3_avl_iterator_hasnext(&iter))
        {
            node = nsec3_avl_iterator_next_node(&iter);

            if(prev == NULL)
            {
                prev = nsec3_avl_node_mod_prev(node);
                zdb_listener_notify_remove_nsec3(ctx->zone, prev, n3, min_ttl);
            }
            
            if((prev == node) && (node_to_remove_index > 0))
            {
                // already processed
                
                continue;
            }

            if(node->rrsig != NULL)
            {
                zdb_listener_notify_update_nsec3rrsig(ctx->zone, node->rrsig, NULL, node);
            }
            
            zdb_listener_notify_remove_nsec3(ctx->zone, node, n3, min_ttl);
            
            node_to_remove[node_to_remove_index++] = node;
        }

        bool collection_empty = !nsec3_avl_iterator_hasnext(&iter);
        
        if(!collection_empty && prev != NULL)
        {
            // the previous node has to be updated
            
            zdb_listener_notify_add_nsec3(ctx->zone, prev, n3, min_ttl);
            if(prev->rrsig != NULL)
            {
                zdb_listener_notify_update_nsec3rrsig(ctx->zone, prev->rrsig, NULL, prev);
            }
            
            for(int i = 0; i < node_to_remove_index; ++i)
            {
                if(node_to_remove[i] == prev)
                {
                    node_to_remove[i] = node_to_remove[node_to_remove_index - 1];
                    --node_to_remove_index;
                    break;
                }
            }
        }
        
        for(int i = 0; i < node_to_remove_index; ++i)
        {
            nsec3_node* node = node_to_remove[i];
            
            log_debug2("nsec3: %{dnsname}[%d]: removing NSEC3 node %{digest32h} rc=%i sc=%i", ctx->zone->origin, ctx->chain_index, node->digest, node->rc, node->sc);
            
            nsec3_avl_delete(&n3->items, node->digest);
            nsec3_zone_item_empties(node);
        }
        
        zdb_icmtl_end(&icmtl);
        
        // and now update the database
    }
    
    nsec3_zone_destroy(ctx->zone, n3);
    
    ctx->callback(ctx->zone, ctx->chain_index, ctx->callback_args);
    
    /*
    nsec3_zone **n3p = &ctx->zone->nsec.nsec3;

    while(*n3p != n3 && n3p != NULL)
    {
        n3p = &(*n3p)->next;
    }
    if(*n3p == n3)
    {
        *n3p = n3->next;
        nsec3_zone_free(n3);
    }
    */
    ZFREE(ctx, nsec3_chain_destroy_s);
    return NULL;
}

void
nsec3_chain_destroy(zdb_zone *zone, s8 chain_index, nsec3_chain_callback *callback, void *callback_args)
{
    if(nsec3_chain_destroy_pool == NULL)
    {
        nsec3_chain_destroy_pool = thread_pool_init_ex(1, 256, "nsec3-c-d");
    }
        
    /*
     * What should be done:
     * 
     * For all nodes in the collection at the index
     *   Remove the node, detach the node from the label and *.label
     *   Remove the signature
     * 
     * Do this batching node & signature by ~64
     * 
     */
    
    yassert(nsec3_chain_destroy_pool != NULL);
    
    if(callback == NULL)
    {
        callback = nsec3_chain_callback_nop;
    }
    
    nsec3_chain_destroy_s* nsec3_chain_update;
    ZALLOC_OR_DIE(nsec3_chain_destroy_s*, nsec3_chain_update, nsec3_chain_destroy_s, NSEC3CD_TAG);
    ptr_vector_init(&nsec3_chain_update->label_fqdn);
    ptr_vector_init(&nsec3_chain_update->label_digest);
    nsec3_chain_update->zone = zone;
    nsec3_chain_update->callback = callback;
    nsec3_chain_update->callback_args = callback_args;
    nsec3_chain_update->chain_index = chain_index;
    thread_pool_enqueue_call(nsec3_chain_destroy_pool, nsec3_chain_destroy_thread, nsec3_chain_update, NULL, "nsec3-c-c");
}

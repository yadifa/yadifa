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

#define NSEC3_CHAIN_CREATE_BATCH_SIZE 64 // records at once

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

static struct thread_pool_s* nsec3_chain_create_pool = NULL;

#define N3CCDAN_TAG 0x4e41444343334e

struct nsec3_digest_and_node_s
{
    nsec3_zone_item *node;
    nsec3_zone_item *node_prev;
    zdb_rr_label *label;
    u8 digest[MAX_DIGEST_LENGTH];
    
};

typedef struct nsec3_digest_and_node_s nsec3_digest_and_node_s;

////////////////////////////////////////////////////////////////////////////////

#define NSEC3CC_TAG 0x4e41444343334e

struct nsec3_chain_create_s
{
    ptr_vector label_fqdn;
    ptr_vector label_digest;
    zdb_zone *zone;
    nsec3_chain_callback *callback;
    void *callback_args;
    s8 chain_index;
    u8 lock_owner;
    u8 reserved_owner;
    bool opt_out;
    bool can_ignore_signatures;
};

typedef struct nsec3_chain_create_s nsec3_chain_create_s;

/**
 * This function creates a chunk of an NSEC3 chain, updates the database and stores it to the journal.
 * 
 * @param ctx
 * @return 
 */

static ya_result
nsec3_chain_create_callback_last_call(nsec3_forall_label_s* ctx)
{
    /*
     * All NSEC3 records have been generated for this chain.
     * The * records should be linked, then the RRSIG should be generated.                 
     */

    // Note that the *.label NSEC3 operation will lock the database so only readers (that should not care about the chain being built)
    // can access it

    // this step is not mandatory, just preferred
    // nsec3_forall_label(nsec3_chain_update->zone, nsec3_chain_update->chain_index, TRUE, nsec3_chain_update->opt_out, nsec3_chain_update_callback, nsec3_chain_update);

    // Iterate through chain and generate signatures bit by bit

    // grab the ZSK keys to sign with
#if 1 // needed for prod
    // signature_context_s signature_context;
    // rrsig_init_signature_context

    ya_result ret;
    
    nsec3_zone* n3 = zdb_zone_get_nsec3chain(ctx->zone, ctx->chain_index);
    zdb_icmtl icmtl;

    ptr_vector signed_nodes;

    ptr_vector_init_ex(&signed_nodes, 32);

    rrsig_context_s signature_context;

    if(FAIL(ret = rrsig_context_initialize(&signature_context, ctx->zone, NULL, time(NULL), NULL)))
    {
        return ret;
    }

    nsec3_avl_iterator iter;
    nsec3_avl_iterator_init(&n3->items, &iter);

    if(nsec3_avl_iterator_hasnext(&iter)) // has one node or more
    {
        nsec3_zone_item* node_first = nsec3_avl_iterator_next_node(&iter);
        nsec3_zone_item* node_prev = node_first;
        u32 wire_size = 0;
        u32 wire_size_step = 21 + 4 + 10;
        bool has_next;

        // get all other nodes in the collection
        // when no more nodes are available, give the first one (last loop iteration)

        while((has_next = nsec3_avl_iterator_hasnext(&iter)) || (node_first != NULL))
        {
            nsec3_zone_item* node;

            if(has_next)
            {
                node = nsec3_avl_iterator_next_node(&iter);
            }
            else
            {
                node = node_first;
                node_first = NULL;
            }
            
            // link the label to the nsec3 node
            
            nsec3_update_labels_links(ctx->zone, ctx->chain_index, node);

            if(node_prev->rrsig == NULL)
            {
                // better: Keep the generated signatures on the side.
                //         when they are all done, push them up
                //         this way the time the DB will be locked will be much smaller

                // generate node_as_rrset
                // rrsig_generate_signatures(&signature_context, &node_as_rrset, resulting_signatures_array);
                // or ...
                // nsec3_item_generate_signatures(&signature_context, node, resulting_signatures_array);

                nsec3_rrsig_generate_signatures(&signature_context, n3, node_prev, node);

                ptr_vector_append(&signed_nodes, node_prev);

                for(zdb_packed_ttlrdata *rrsig = node_prev->rrsig; rrsig != NULL; rrsig = rrsig->next)
                {
                    wire_size += wire_size_step + rrsig->rdata_size;
                }
            }

            if(wire_size > 16384 || node_first == NULL)
            {                            
                // if no update is running, open a new one

                ya_result ret;

                while(FAIL(ret = zdb_icmtl_begin(&icmtl, ctx->zone)))
                {
                    log_err("nsec3: rrsig: %{dnsname}[%d]: zone is already being edited: %r", ctx->zone->origin, ctx->chain_index, ret);
                    usleep(1000);
                }

                for(int i = 0; i <= ptr_vector_last_index(&signed_nodes); ++i)
                {
                    // notify rrsig add

                    nsec3_node* node = (nsec3_node*)ptr_vector_get(&signed_nodes, i);

                    zdb_listener_notify_update_nsec3rrsig(ctx->zone, NULL, node->rrsig, node);
                }

                zdb_icmtl_end(&icmtl);

                ptr_vector_empties(&signed_nodes);

                wire_size = 0;
            }

            node_prev = node;
        }
    }

    ptr_vector_destroy(&signed_nodes);
#else
    rrsig_context_s signature_context;
    zdb_icmtl icmtl;    
    rrsig_context_initialize(&signature_context, ctx->zone, NULL, time(NULL), NULL);
    nsec3_zone* n3 = zdb_zone_get_nsec3chain(ctx->zone, ctx->chain_index);
#endif
    // now the chain should be made available

    while(FAIL(ret = zdb_icmtl_begin(&icmtl, ctx->zone)))
    {
        log_err("nsec3: rrsig: %{dnsname}[%d]: zone is already being edifed: %r", ctx->zone->origin, ctx->chain_index, ret);
        usleep(1000);
    }

    // add the NSEC3PARAM
    // remove the TYPE_NSEC3PARAMADD

    zdb_packed_ttlrdata* nsec3param_rr;
    zdb_ttlrdata nsec3paramadd_rr;

    u16 rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
    bool record_is_new;
    bool placeholder_existed;
            
    nsec3paramadd_rr.next = NULL;
    nsec3paramadd_rr.ttl = 0;
    nsec3paramadd_rr.rdata_size = rdata_size;
    nsec3paramadd_rr.rdata_pointer = n3->rdata;

    ZDB_RECORD_ZALLOC(nsec3param_rr, 0, rdata_size, n3->rdata);

    record_is_new = zdb_record_insert_checked(&ctx->zone->apex->resource_record_set, TYPE_NSEC3PARAM, nsec3param_rr);                   // no feedback
    placeholder_existed = ISOK(zdb_record_delete_exact(&ctx->zone->apex->resource_record_set, TYPE_NSEC3PARAMADD, &nsec3paramadd_rr));  // no feedback // safe delete of record
    
#if ZDB_CHANGE_FEEDBACK_SUPPORT
    
    // feedback(s) to the listener(s), A.K.A: the icmtl / journal needs to be called
    
    if(record_is_new || placeholder_existed)
    {
        zdb_ttlrdata unpacked_ttlrdata;
        unpacked_ttlrdata.rdata_pointer = &nsec3param_rr->rdata_start[0];
        unpacked_ttlrdata.rdata_size = nsec3param_rr->rdata_size;
        unpacked_ttlrdata.ttl = nsec3param_rr->ttl;
        
        if(record_is_new)
        {
            zdb_listener_notify_add_record(ctx->zone, ctx->zone->origin_vector.labels, ctx->zone->origin_vector.size, TYPE_NSEC3PARAM, &unpacked_ttlrdata);
        }
        if(placeholder_existed)
        {
            zdb_listener_notify_remove_record(ctx->zone, ctx->zone->origin, TYPE_NSEC3PARAMADD, &unpacked_ttlrdata);
        }
    }
#endif // ZDB_CHANGE_FEEDBACK_SUPPOT
    
    if(!record_is_new)
    {
        /* It's a dup */
        ZDB_RECORD_ZFREE(nsec3param_rr);
    }
    else
    {
        /// @note  edf -- to fix before commit -- NSEC3PARAM signature event on the journal has no name and breaks everything.
        
        rrsig_delete(ctx->zone, ctx->zone->origin, ctx->zone->apex, TYPE_NSEC3PARAM); //gives feedback
        // generate new signature for NSEC3PARAM
        const zdb_packed_ttlrdata *nsec3param_rrset = zdb_record_find(&ctx->zone->apex->resource_record_set, TYPE_NSEC3PARAM);
        zdb_packed_ttlrdata *nsec3param_rrsig_rrset;
        if(ISOK(ret = rrsig_generate_signatures(&signature_context, ctx->zone->origin, TYPE_NSEC3PARAM, nsec3param_rrset, &nsec3param_rrsig_rrset)))
        {   // NSEC3PARAM signature event on the journal has no name and breaks everything.
            if(nsec3param_rrsig_rrset != NULL)
            {
                if(ctx->zone_lock_owner != 0)
                {
                    if(ctx->zone_reserved_owner != 0)
                    {
                        zdb_zone_exchange_locks(ctx->zone, ctx->zone_lock_owner, ctx->zone_reserved_owner);
                    }
                }
                rrsig_update_commit(NULL, nsec3param_rrsig_rrset, ctx->zone->apex, ctx->zone, &signature_context.rr_dnsname);
                if(ctx->zone_lock_owner != 0)
                {
                    if(ctx->zone_reserved_owner != 0)
                    {
                        zdb_zone_exchange_locks(ctx->zone, ctx->zone_reserved_owner, ctx->zone_lock_owner);
                    }
                }
            }
        }
    }
    
    rrsig_delete(ctx->zone, ctx->zone->origin, ctx->zone->apex, TYPE_NSEC3PARAMADD);
    
    //zdb_zone_update_signatures_for_type_with_context(&signature_context, ctx->zone, 
    
    rrsig_context_destroy(&signature_context);
    
    zdb_icmtl_end(&icmtl);                

    return 0; // all done
}

static ya_result
nsec3_chain_create_callback(nsec3_forall_label_s* ctx)
{
    zdb_icmtl icmtl;
    nsec3_zone* n3 = zdb_zone_get_nsec3chain(ctx->zone, ctx->chain_index);
    nsec3_chain_create_s* current = (nsec3_chain_create_s*)ctx->callback_args;
    u32 min_ttl = 600; /// @todo 20150918 edf -- fix me
    //u8 digest[1 + MAX_DIGEST_LENGTH];
    if(n3 == NULL)
    {
        // the structure has to be created first ...
        
        log_err("nsec3: %{dnsname}[%d] chain not initialised", ctx->zone->origin, ctx->chain_index);
        
        return ERROR;
    }
    
#if DEBUG
    log_debug("nsec3: %{dnsname}[%d]: %{dnsname}", ctx->zone->origin, ctx->chain_index, ctx->name);
#endif
    
    if(ctx->nsec3_covered || ctx->last_call)
    {
        // accumulate the fqdn
        // when we have enough, compute the NSEC3 and do the job
        // It would be more efficient to not store the current label in the collection and start from it
        // but it would also be a bit more difficult to read.
        
        if(!ctx->last_call)
        {
            nsec3_digest_and_node_s* digest_node;
            ZALLOC_OR_DIE(nsec3_digest_and_node_s*, digest_node, nsec3_digest_and_node_s, N3CCDAN_TAG);
            digest_node->node = NULL;
            digest_node->node_prev = NULL;
            digest_node->label = NULL;
            nsec3_compute_digest_from_fqdn_with_len(n3, ctx->name, ctx->name_len, digest_node->digest, FALSE);
            ptr_vector_append(&current->label_fqdn, dnsname_zdup(ctx->name));
            ptr_vector_append(&current->label_digest, digest_node);

            // not enough data yet ? (or end of the job ...)

            if(ptr_vector_size(&current->label_fqdn) < NSEC3_CHAIN_CREATE_BATCH_SIZE)
            {
                return 1; // wait for more
            }
        }
        else // last call
        {
            if(ptr_vector_size(&current->label_fqdn) == 0)
            {
#if DEBUG
                log_debug("nsec3: %{dnsname}[%d]: done", ctx->zone->origin, ctx->chain_index);
#endif
                ya_result ret = nsec3_chain_create_callback_last_call(ctx);
                
                return ret;
            }
            else
            {
#if DEBUG
                log_debug("nsec3: %{dnsname}[%d]: flushing %i labels", ctx->zone->origin, ctx->chain_index, ptr_vector_size(&current->label_fqdn));
#endif
            }
        }
        
        // process the batch
        
        ya_result return_code;
        while(FAIL(return_code = zdb_icmtl_begin(&icmtl, ctx->zone)))
        {
            log_err("nsec3: %{dnsname}[%d]: zone is already being edited: %r", ctx->zone->origin, ctx->chain_index, return_code);
            usleep(1000);
        }
        
        icmtl.can_ignore_signatures = ctx->can_ignore_signatures;
        
        u8 nsec3_base_flags = (ctx->optout)?NSEC3_FLAGS_OPTOUT:0;

        yassert(ptr_vector_last_index(&current->label_fqdn) == ptr_vector_last_index(&current->label_digest));
        
        /*
         * For each modified node (added), find the node to insert.
         * If the node to insert exists already, do nothing.
         * If the node is not marked, mark as "deleted" and store the record.
         */

        for(int i = 0; i <= ptr_vector_last_index(&current->label_fqdn); ++i)
        {
            u8 *name = ptr_vector_get(&current->label_fqdn, i);
            nsec3_digest_and_node_s* digest_node = (nsec3_digest_and_node_s*)ptr_vector_get(&current->label_digest, i);

            zdb_rr_label *label = zdb_rr_label_find_from_name(ctx->zone, name);

            if(label == NULL)
            {
                // label has been destroyed in the mean time
                ptr_vector_end_swap(&current->label_fqdn, i);
                ptr_vector_end_swap(&current->label_digest, i);                        
                --i;

                dnsname_zfree(name);
                ZFREE(digest_node, nsec3_digest_and_node_s);

                continue;
            }

            digest_node->label = label;

            if(!nsec3_avl_isempty(&n3->items))
            {
                u8 *digest = digest_node->digest;
                nsec3_zone_item *node = nsec3_avl_find_interval_start(&n3->items, digest);

                if(node != NULL)
                {
                    if(memcmp(node->digest, digest, digest[0]) == 0)
                    {
                        // nothing to do
                        continue;
                    }

                    if((node->flags & NSEC3_FLAGS_MARKED_FOR_ICMTL_DEL) == 0)
                    {
#if DEBUG
                        const u8* name = ptr_vector_get(&current->label_fqdn, i);
                        log_debug("nsec3: %{dnsname}[%d]: %{dnsname}: del %{digest32h}@%p", ctx->zone->origin, ctx->chain_index, name, node->digest, node);
#endif
                        zdb_listener_notify_remove_nsec3(ctx->zone, node, n3, min_ttl);
                        node->flags |= NSEC3_FLAGS_MARKED_FOR_ICMTL_DEL;
                        digest_node->node_prev = node;
                    }
                }
            }
        }

        for(int i = 0; i <= ptr_vector_last_index(&current->label_fqdn); ++i)
        {
            nsec3_digest_and_node_s* digest_node = (nsec3_digest_and_node_s*)ptr_vector_get(&current->label_digest, i);
            if(digest_node->node_prev != NULL)
            {
                digest_node->node_prev->flags &= ~NSEC3_FLAGS_MARKED_FOR_ICMTL_DEL;
                digest_node->node_prev->flags |= NSEC3_FLAGS_MARKED_FOR_ICMTL_ADD;
            }
        }
        

        // all the nodes that will be destroyed in this batch are now marked and stored
        // no new node will be modified that way

        for(int i = 0; i <= ptr_vector_last_index(&current->label_fqdn); ++i)
        {
            // get a name
            // generate the NSEC3 item/record

#ifdef DEBUG
            const u8 *name = ptr_vector_get(&current->label_fqdn, i);
#endif
            nsec3_digest_and_node_s* digest_node = (nsec3_digest_and_node_s*)ptr_vector_get(&current->label_digest, i);
            u8 *digest = digest_node->digest;

            // first, do the additions (the nodes are known anyway)
            // then, for all added node:

            //   notify add of all the added set

            nsec3_zone_item* node;
            node = nsec3_avl_find(&n3->items, digest);

            if(node == NULL)
            {
                // change of the collection
                // previous node is affected but it has already been marked deleted
                node = nsec3_avl_insert(&n3->items, digest);
                
                node->flags = nsec3_base_flags;

                // the types must be updated

                type_bit_maps_context type_context;

                u16 type_bit_maps_size = type_bit_maps_initialize(&type_context, digest_node->label, FALSE, TRUE);

                if(type_bit_maps_size > 0)
                {
                    ZALLOC_ARRAY_OR_DIE(u8*, node->type_bit_maps, type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);
                    type_bit_maps_write(node->type_bit_maps, &type_context);
                    node->type_bit_maps_size = type_bit_maps_size;
                }

                // the links must be established

                nsec3_add_owner(node, digest_node->label); // links NSEC3->LABEL, but NOT LABEL->NSEC3
#ifdef DEBUG
                log_debug("nsec3: %{dnsname}[%d]: %{dnsname}: added node %{digest32h}@%p", ctx->zone->origin, ctx->chain_index, name, digest, node);
#endif
                node->flags |= NSEC3_FLAGS_MARKED_FOR_ICMTL_ADD;

                digest_node->node = node;
            }
            else
            {
                // already exists (update ? records types ?)
#ifdef DEBUG
                log_debug("nsec3: %{dnsname}[%d]: %{dnsname}: marked node %{digest32h}@%p", ctx->zone->origin, ctx->chain_index, name, digest, node);
#endif            
                digest_node->node = node;
            }
        }

        // at this point:
        //  _ all the nodes to be added are marked
        //  _ all the nodes to be updated are marked

        for(int i = 0; i <= ptr_vector_last_index(&current->label_fqdn); ++i)
        {
            u8* name = ptr_vector_get(&current->label_fqdn, i);
            nsec3_digest_and_node_s* digest_node = (nsec3_digest_and_node_s*)ptr_vector_get(&current->label_digest, i);

            // first, do the additions (the nodes are known anyway)
            // then, for all added node:
            //   notify delete/update of previous that is not in the added set
            //   notify add of all the added set

            nsec3_zone_item* node = digest_node->node;

            u8 node_flags = node->flags;
            node->flags &= ~(NSEC3_FLAGS_MARKED_FOR_ICMTL_ADD|NSEC3_FLAGS_MARKED_FOR_ICMTL_DEL);


            if((node_flags & NSEC3_FLAGS_MARKED_FOR_ICMTL_ADD) != 0)
            {
#ifdef DEBUG
                log_debug("nsec3: %{dnsname}[%d]: %{dnsname}: add %{digest32h}@%p", ctx->zone->origin, ctx->chain_index, name, node->digest, node);
#endif
                zdb_listener_notify_add_nsec3(ctx->zone, node, n3, min_ttl);
            }

            if((digest_node->node_prev != NULL) && (digest_node->node_prev->flags & NSEC3_FLAGS_MARKED_FOR_ICMTL_ADD) != 0)
            {
#ifdef DEBUG
                log_debug("nsec3: %{dnsname}[%d]: %{dnsname}: add %{digest32h}@%p", ctx->zone->origin, ctx->chain_index, name, digest_node->node_prev->digest, node);
#endif
                digest_node->node_prev->flags &= ~NSEC3_FLAGS_MARKED_FOR_ICMTL_ADD;
                zdb_listener_notify_add_nsec3(ctx->zone, digest_node->node_prev, n3, min_ttl);
            }

            dnsname_zfree(name);
            ZFREE(digest_node, nsec3_digest_and_node_s);
        }

        ptr_vector_empties(&current->label_fqdn);
        ptr_vector_empties(&current->label_digest);
        
        ya_result len = zdb_icmtl_end(&icmtl);
        
        if(ctx->last_call)
        {
#ifdef DEBUG
            log_debug("nsec3: %{dnsname}[%d]: done", ctx->zone->origin, ctx->chain_index);
#endif
            ya_result ret = nsec3_chain_create_callback_last_call(ctx);

            if(FAIL(ret))
            {
                len = ret;
            }
        }

        return len;
    } // end if(ctx->nsec3_covered || ctx->last_call)
    
    return 0;
}

static void*
nsec3_chain_create_thread(void* args)
{
    nsec3_chain_create_s *nsec3_chain_update = (nsec3_chain_create_s*)args;
    nsec3_forall_label(nsec3_chain_update->zone, nsec3_chain_update->chain_index, TRUE,
            nsec3_chain_update->opt_out, nsec3_chain_update->can_ignore_signatures, nsec3_chain_update->lock_owner, nsec3_chain_update->reserved_owner,
            nsec3_chain_create_callback, nsec3_chain_update);
    nsec3_chain_update->callback(nsec3_chain_update->zone, nsec3_chain_update->chain_index, nsec3_chain_update->callback_args);
    ZFREE(nsec3_chain_update, nsec3_chain_create_s);
    return NULL;
}

/**
 * Creates an NSEC3 chain for the zone at the index position, asynchronously.
 * 
 * The zone needs to be
 * either write-locked,
 * either double-locked and in the read position.
 * 
 * If the zone is double-locked, the lock_owner and reserved owner parameters have to be set accordingly (read, write)
 * If the zone is locked, both parameters have to be set to ZDB_ZONE_MUTEX_NOBODY ( = 0 )
 * 
 * @param zone the zone
 * @param chain_index the index of the chain (0 for the one visible to the queries)
 * @param opt_out has the chain to be generated "optout"
 * @param lock_owner 0 or the read double-lock owner
 * @param reserved_owner 0 or the write double-lock owner
 * @param callback function that will be called at the end of the asynchronous generation, can be NULL
 * @param callback_args parameter passed to the callback at the end of the asynchronous generation
 */

void
nsec3_chain_create(zdb_zone *zone, s8 chain_index, bool opt_out, u8 lock_owner, u8 reserved_owner, nsec3_chain_callback *callback, void *callback_args)
{
    if(nsec3_chain_create_pool == NULL)
    {
        nsec3_chain_create_pool = thread_pool_init_ex(1, 256, "nsec3-c-c");
    }
    
    yassert(nsec3_chain_create_pool != NULL);
    
    if(callback == NULL)
    {
        callback = nsec3_chain_callback_nop;
    }
    
    nsec3_chain_create_s* nsec3_chain_update;
    ZALLOC_OR_DIE(nsec3_chain_create_s*, nsec3_chain_update, nsec3_chain_create_s, NSEC3CC_TAG);
    ZEROMEMORY(nsec3_chain_update, sizeof(nsec3_chain_create_s));
    ptr_vector_init(&nsec3_chain_update->label_fqdn);
    ptr_vector_init(&nsec3_chain_update->label_digest);
    nsec3_chain_update->zone = zone;
    nsec3_chain_update->callback = callback;
    nsec3_chain_update->callback_args = callback_args;
    nsec3_chain_update->chain_index = chain_index;
    nsec3_chain_update->lock_owner = lock_owner;
    nsec3_chain_update->reserved_owner = reserved_owner;
    nsec3_chain_update->opt_out = opt_out;
    nsec3_chain_update->can_ignore_signatures = FALSE;
    thread_pool_enqueue_call(nsec3_chain_create_pool, nsec3_chain_create_thread, nsec3_chain_update, NULL, "nsec3-c-c");
}

/**
 * Creates an NSEC3 chain for the zone at the index position.
 * 
 * The zone needs to be
 * either write-locked,
 * either double-locked and in the read position.
 * 
 * If the zone is double-locked, the lock_owner and reserved owner parameters have to be set accordingly (read, write)
 * If the zone is locked, both parameters have to be set to ZDB_ZONE_MUTEX_NOBODY ( = 0 )
 * 
 * @param zone the zone
 * @param chain_index the index of the chain (0 for the one visible to the queries)
 * @param opt_out has the chain to be generated "optout"
 * @param lock_owner 0 or the read double-lock owner
 * @param reserved_owner 0 or the write double-lock owner
 */

void
nsec3_chain_create_now(zdb_zone *zone, s8 chain_index, bool opt_out, u8 lock_owner, u8 reserved_owner)
{
    nsec3_chain_create_s* nsec3_chain_update;
    ZALLOC_OR_DIE(nsec3_chain_create_s*, nsec3_chain_update, nsec3_chain_create_s, NSEC3CC_TAG);
    ZEROMEMORY(nsec3_chain_update, sizeof(nsec3_chain_create_s));
    ptr_vector_init(&nsec3_chain_update->label_fqdn);
    ptr_vector_init(&nsec3_chain_update->label_digest);
    nsec3_chain_update->zone = zone;
    nsec3_chain_update->callback = nsec3_chain_callback_nop;
    nsec3_chain_update->callback_args = NULL;
    nsec3_chain_update->chain_index = chain_index;
    nsec3_chain_update->lock_owner = lock_owner;
    nsec3_chain_update->reserved_owner = reserved_owner;
    nsec3_chain_update->opt_out = opt_out;
    nsec3_chain_update->can_ignore_signatures = TRUE;
    nsec3_chain_create_thread(nsec3_chain_update);
    nsec3_edit_zone_end(zone);
}

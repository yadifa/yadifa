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
/** @defgroup dnsdbupdate Dynamic update functions
 *  @ingroup dnsdb
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <dnscore/rfc.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/threaded_queue.h>
#include <dnscore/treeset.h>
#include <dnscore/logger.h>
#include <dnscore/dnsname.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/dynupdate.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_sanitize.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_listener.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger


#if ZDB_HAS_DNSSEC_SUPPORT != 0
#include "dnsdb/dnssec.h"
#include "dnsdb/rrsig_updater.h"

#if ZDB_HAS_NSEC_SUPPORT != 0
#include "dnsdb/nsec.h"
#include "dnsdb/nsec_collection.h"
#endif

#if ZDB_HAS_NSEC3_SUPPORT != 0
#include "dnsdb/nsec3_rrsig_updater.h"
#endif

/*
 * The dynamic update is made in the main thread (so it can write)
 */

#endif

#define ZDB_RRSIGUPQ_TAG	    0x5150554749535252	/* RRSIGUPQ @TODO put the tags in a centralised place */

/**
 * IXFR is prepared here.
 * Update query => IXFR
 *
 * The catch is in "=>"
 *
 * +X +Y +Z -Y => +X +Z
 *
 * So I have to get all modified records in a collection that gets the adds and
 * subs and then use this collection to generate the IXFR
 *
 * If a sub succeeded: add the record in "-" mode, merge previous mode
 * If a sub failed: do nothing
 * If an add succeeded: add the record in "+" mode, merge previous mode
 *
 * -+ => NOP
 * +- => NOP
 * -- => -
 * ++ => +
 * +  => +
 * -  => -
 *
 * @todo check remove NSEC3PARAM
 */

#define MAX_HANDLED_UPDATES_RECORDS 5956

typedef struct label_update_status label_update_status;
/* At most 5956 entries */
struct label_update_status
{
    zdb_rr_label *label;
    u8 *dname;
    u16 rtype;
    bool remove;
    bool inversed;
};

#if ZDB_HAS_DNSSEC_SUPPORT != 0

static ya_result
dynupdate_update_rrsig_body(zdb_zone *zone, treeset_tree *lus_set)
{
    ya_result return_code;
    dnsname_stack path;
    rrsig_updater_parms parms;
    ZEROMEMORY(&parms, sizeof(rrsig_updater_parms));
    rrsig_updater_init(&parms, zone);
    
    //rrsig_updater_process_zone(&parms); // with only the required labels
    
    if(FAIL(return_code = dnssec_process_begin(&parms.task)))
    {
        return return_code;
    }
    
    treeset_avl_iterator lus_iter;
    treeset_avl_iterator_init(lus_set, &lus_iter);
    while(treeset_avl_iterator_hasnext(&lus_iter))
    {
        treeset_node *lus_node = treeset_avl_iterator_next_node(&lus_iter);
        label_update_status *lus = (label_update_status *)lus_node->data;

        if(!lus->inversed)
        {
            dnsname_to_dnsname_stack(lus->dname, &path);
        }
        else
        {
            /* the only difference is the order of the map */
            dnsname_to_dnsname_vector(lus->dname, (dnsname_vector*)&path);
        }

        /*
         * If the label is marked as "updating" and contains records ...
         */

        if(((lus->label->flags & ZDB_RR_LABEL_UPDATING) != 0) && LABEL_HAS_RECORDS(lus->label))
        {
            lus->label->flags &= ~ZDB_RR_LABEL_UPDATING;

            rrsig_update_item_s *query;

            MALLOC_OR_DIE(rrsig_update_item_s*, query, sizeof(rrsig_update_item_s), ZDB_RRSIGUPQ_TAG);

            query->label = lus->label;
            MEMCOPY(&query->path.labels[0], &path.labels[0], (path.size + 1) * sizeof (u8*));
            query->path.size = path.size;
            
            query->added_rrsig_sll = NULL;
            query->removed_rrsig_sll = NULL;
            query->zone = zone;

            /*
             * The label from root TLD and the zone cut have one thing in common:
             * The label (relative path from the previous node) has got a size of 0
             */

            if(lus->label->name[0] != 0)
            {
                bool delegation = (zdb_record_find(&lus->label->resource_record_set, TYPE_NS) != NULL);
                
                if(delegation)
                {
                    lus->label->flags |= ZDB_RR_LABEL_DELEGATION;
                }
            }

#ifdef DEBUG
            log_debug("dynupdate_update_rrsig_body: queuing %{dnsnamestack}", &path);
#endif

            threaded_queue_enqueue(&parms.task.dnssec_task_query_queue, query);
        }
    }
    
    dnssec_process_end(&parms.task);
    
    rrsig_updater_commit(&parms);
    rrsig_updater_finalize(&parms);

    return SUCCESS;
}

#if ZDB_HAS_NSEC3_SUPPORT != 0

static inline void
dynupdate_update_nsec3_body_postdel(zdb_zone *zone, ptr_vector *candidates, treeset_tree *nsec3_del, zdb_rr_label *label, u8 *dname)
{
    if(!RR_LABEL_HASSUBORREC(label))
    {
        ptr_vector_append(candidates, dnsname_dup(dname));
        
        if(!ZDB_LABEL_ISAPEX(label))
        {
            /*
            * Now maybe a parent has got the same issue.  So ..
            * for all parents of label
            *   if the parent only exists because of ONE sub and the dnssec, then
            *     add its NSEC3 to the del list and
            *     add its name to this array
            */
            
            dnslabel_vector name_path;        
            s32 path_index = dnsname_to_dnslabel_stack(dname, name_path);
            zdb_rr_label *label_path[128];
            int index = zone->origin_vector.size;
            zdb_rr_label *rr_label = zone->apex;
            label_path[index++] = rr_label;

            while(index < path_index)
            {
                const u8* dns_label = name_path[index];

                rr_label = zdb_rr_label_find_child(rr_label, dns_label);

                if(rr_label == NULL)
                {
                    break;
                }

                label_path[index++] = rr_label;
            }

            for(index = path_index - 1; index > zone->origin_vector.size; index--)
            {
                dname += *dname + 1;

                zdb_rr_label *rr_label = label_path[index];

                if(btree_notempty(rr_label->resource_record_set))
                {
                    break;
                }

                if(dictionary_size(&rr_label->sub) > 1)
                {
                    break;
                }

                // no records and only one child that is about to be removed

                if(rr_label->nsec.nsec3 != NULL)
                {
                    treeset_avl_insert(nsec3_del, rr_label->nsec.nsec3->self)->data = rr_label;
                }

                ptr_vector_append(candidates, dnsname_dup(dname));
            }
        }
    }
}

static inline void
dynupdate_update_nsec_body_postdel(zdb_zone *zone, ptr_vector *candidates, treeset_tree *nsec_del, zdb_rr_label *label, u8 *dname)
{
    if(!RR_LABEL_HASSUBORREC(label))
    {
        if(label->nsec.nsec.node != NULL)
        {
            treeset_avl_insert(nsec_del, label->nsec.nsec.node)->data = label;
        }
        
        ptr_vector_append(candidates, dnsname_dup(dname));        
        
        
        if(!ZDB_LABEL_ISAPEX(label))
        {
            /*
            * Now maybe a parent has got the same issue.  So ..
            * for all parents of label
            *   if the parent only exists because of ONE sub and the dnssec, then
            *     add its NSEC3 to the del list and
            *     add its name to this array
            */
            
            dnslabel_vector name_path;        
            s32 path_index = dnsname_to_dnslabel_stack(dname, name_path);
            zdb_rr_label *label_path[128];
            int index = zone->origin_vector.size;
            zdb_rr_label *rr_label = zone->apex;
            label_path[index++] = rr_label;

            while(index < path_index)
            {
                const u8* dns_label = name_path[index];

                rr_label = zdb_rr_label_find_child(rr_label, dns_label);

                if(rr_label == NULL)
                {
                    break;
                }

                label_path[index++] = rr_label;
            }

            for(index = path_index - 1; index > zone->origin_vector.size; index--)
            {
                dname += *dname + 1;

                zdb_rr_label *rr_label = label_path[index];

                if(btree_notempty(rr_label->resource_record_set))
                {
                    break;
                }

                if(dictionary_size(&rr_label->sub) > 1)
                {
                    break;
                }

                // no records and only one child that is about to be removed

                if(rr_label->nsec.nsec.node != NULL)
                {
                    treeset_avl_insert(nsec_del, rr_label->nsec.nsec.node)->data = rr_label;
                }

                ptr_vector_append(candidates, dnsname_dup(dname));
            }
        }
    }
}

static ya_result
dynupdate_update_nsec3_body(zdb_zone *zone, treeset_tree *lus_set)
{
    bool opt_out = ((zone->apex->flags & ZDB_RR_LABEL_NSEC3_OPTOUT) != 0);
    
    treeset_tree nsec3_del = TREESET_EMPTY;
    treeset_tree nsec3_upd = TREESET_EMPTY;
    ptr_vector label_del = EMPTY_PTR_VECTOR;
    
    dnsname_stack path;

    ya_result return_code;
        
    treeset_avl_iterator lus_iter;
    treeset_avl_iterator_init(lus_set, &lus_iter);
    while(treeset_avl_iterator_hasnext(&lus_iter))
    {
        treeset_node *lus_node = treeset_avl_iterator_next_node(&lus_iter);
        label_update_status *lus = (label_update_status *)lus_node->data;

        dnsname_to_dnsname_stack(lus->dname, &path);

        zdb_rr_label *label = lus->label;

        /* dnssec_process_rr_label(lus->label, task); */

        if(((label->flags & ZDB_RR_LABEL_UPDATING) != 0))
        {
            label->flags &= ~ZDB_RR_LABEL_UPDATING;

            if(LABEL_HAS_RECORDS(label))
            {
                /*
                 * @TODO: check rules of NSEC3 coverage
                 * 
                 * Check if the label needs nsec
                 * If it does, update it if needed then request for a signature
                 * If it does not, delete it if needed along with its signature
                 */
                /*
                bool has_ds = zdb_record_find(&label->resource_record_set, TYPE_DS) != NULL;
                bool has_no_ns = zdb_record_find(&label->resource_record_set, TYPE_NS) == NULL;
                bool nsec_covered = (zone->apex == label) || has_ds || has_no_ns;
                */
                bool nsec_covered = nsec3_is_label_covered(label, opt_out);

                if(nsec_covered)
                {
                    dnslabel_vector labels;
                    s32 labels_top = dnsname_to_dnslabel_vector(lus->dname, labels);

                    bool new_one = label->nsec.nsec3 == NULL;

                    nsec3_update_label(zone, label, labels, labels_top);

                    treeset_avl_insert(&nsec3_upd, label->nsec.nsec3->self)->data = label;

                    if(new_one) /* if it's a new insert, the previous nsec3 will have to be updated */
                    {
                        nsec3_zone_item *pred = nsec3_avl_node_mod_prev(label->nsec.nsec3->self);

                        if(pred != NULL)
                        {
                            treeset_avl_insert(&nsec3_upd, pred)->data = label;
                            
                            nsec3_zone* n3 = nsec3_zone_from_item(zone, pred);
                            zdb_listener_notify_remove_nsec3(pred, n3, 0);
                        }
                    }
                    
                    nsec3_zone* n3 = nsec3_zone_from_item(zone, label->nsec.nsec3->self);
                    if(!new_one)
                    {
                        zdb_listener_notify_remove_nsec3(label->nsec.nsec3->self, n3, 0);
                    }
                }
                else
                {
                    /* @TODO remove nsec3 for label
                     *       The previous NSEC3 will have to be processed for re-signature
                     */

                    if(label->nsec.nsec3 != NULL)
                    {
                        treeset_avl_insert(&nsec3_del, label->nsec.nsec3->self)->data = label;
                    }
                    
                    /* check if the label will need to be destroyed after the NSEC3 is removed */
                    
                    dynupdate_update_nsec3_body_postdel(zone, &label_del, &nsec3_del, label, lus->dname);
                }
            }
            else
            {
                /* remove nsec3, update the pred */

                if(label->nsec.nsec3 != NULL)
                {
                    treeset_avl_insert(&nsec3_del, label->nsec.nsec3->self)->data = label;
                }
                
                dynupdate_update_nsec3_body_postdel(zone, &label_del, &nsec3_del, label, lus->dname);
            }
        }
    }

    /*
     * The treeset does not contain any dup and is sorted already
     */


    /*
     * Remove the nsec3 of the del set from the upd set and from the db
     */

    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&nsec3_del, &iter);
    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *node = treeset_avl_iterator_next_node(&iter);

        nsec3_zone_item *nsec3_item = (nsec3_zone_item*)node->key;
        zdb_rr_label *label = (zdb_rr_label*)node->data;

        nsec3_zone_item *pred = nsec3_avl_node_mod_prev(nsec3_item);
        /* Add the del's pred to the 'to update' */
        treeset_avl_insert(&nsec3_upd, pred);
        
        nsec3_zone* n3 = nsec3_zone_from_item(zone, nsec3_item);
        zdb_listener_notify_remove_nsec3(pred, n3, 0);
        zdb_listener_notify_remove_nsec3(nsec3_item, n3, 0);
                
        /* Remove the del from the 'to update' */
        treeset_avl_delete(&nsec3_upd, nsec3_item);

        nsec3_remove_label(zone, label);
    }
    
    /*
     * All nsec3 candidates to be resigned are in nsec3_upd
     */
    
    nsec3_rrsig_updater_parms parms;
    ZEROMEMORY(&parms, sizeof(nsec3_rrsig_updater_parms));
    nsec3_rrsig_updater_init(&parms, zone);
    
    if(FAIL(return_code = dnssec_process_begin(&parms.task)))
    {
        return return_code;
    }

    treeset_avl_iterator_init(&nsec3_upd, &iter);
    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *node = treeset_avl_iterator_next_node(&iter);

        nsec3_zone_item *nsec3_item = (nsec3_zone_item*)node->key;
        /*zdb_rr_label *label = (zdb_rr_label*)node->data;*/

        /* dnssec_process_rr_label(lus->label, task); */
        
        nsec3_zone* n3 = nsec3_zone_from_item(zone, nsec3_item);
        zdb_listener_notify_add_nsec3(nsec3_item, n3, 0);

        nsec3_rrsig_update_item_s* query;

        MALLOC_OR_DIE(nsec3_rrsig_update_item_s*, query, sizeof (nsec3_rrsig_update_item_s), ZDB_RRSIGUPQ_TAG);

        query->zone = zone;
        query->item = nsec3_item;
        query->next = nsec3_avl_node_mod_next(nsec3_item);
        query->added_rrsig_sll = NULL;
        query->removed_rrsig_sll = NULL;

        threaded_queue_enqueue(&parms.task.dnssec_task_query_queue, query);
    }
    
    dnssec_process_end(&parms.task);
    
    nsec3_rrsig_updater_commit(&parms);
    
    nsec3_rrsig_updater_finalize(&parms);
    
    treeset_avl_destroy(&nsec3_upd);
    treeset_avl_destroy(&nsec3_del);
    
    for(s32 i = 0; i <= label_del.offset; i++)
    {
        u8 *qname = (u8*)label_del.data[i];
        /* delete qname */
        
        dnslabel_vector name_path;
        
        s32 path_index = dnsname_to_dnslabel_stack(qname, name_path);
                
        zdb_rr_label_delete_record(zone, name_path, (path_index - zone->origin_vector.size) - 1, TYPE_ANY);
        
        free(qname);
    }

    return SUCCESS;
}

#endif

#if ZDB_HAS_NSEC_SUPPORT != 0

/**
 *
 * For each label
 *      If the label needs an NSEC node
 *          If the label has no NSEC record/node
 *              Add the node, not the record
 *          Else
 *              It's for later
 *          Fi
 *
 *          Add in the "update" set
 *      Else
 *          Add in the "delete" set
 *      Fi
 * Rof
 *
 * For each "deletion" (preferably in reverse order)
 *      Remove the node & record & signature & "update" set
 *      Add the pred in the "update" set
 * Rof
 *
 * For each "addition"
 *      Update the node & record
 * Rof
 *
 * @param zone
 * @param lus_set
 * @return
 */

/**
 * 
 * Returns true if the tree contains only RRSIG and NSEC records
 * 
 * @TODO rewrite in a more compact form after debugging
 *
 * @param tree
 * @return 
 */

static bool dynupdate_update_is_empty_nsec(zdb_rr_collection tree)
{
    btree_node *node = tree;
    if(node != NULL)
    {
        if(node->hash == TYPE_RRSIG)
        {
            if(node->children.lr.left == NULL)
            {
                if(node->children.lr.right != NULL)
                {
                    if(node->children.lr.right->hash == TYPE_NSEC)
                    {
                        if(node->children.lr.right->children.lr.left == NULL)
                        {
                            if(node->children.lr.right->children.lr.right == NULL)
                            {
                                return TRUE;
                            }
                        }
                    }
                }
            }
        }
        else if(node->hash == TYPE_NSEC)
        {
            if(node->children.lr.left == NULL)
            {
                if(node->children.lr.right == NULL)
                {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;


}

static ya_result
dynupdate_update_nsec(zdb_zone* zone, treeset_tree *lus_set)
{
    dnsname_stack dname_stack;

    treeset_tree nsec_del = TREESET_EMPTY;
    treeset_tree nsec_upd = TREESET_EMPTY;
    ptr_vector label_del = EMPTY_PTR_VECTOR;

    treeset_avl_iterator lus_iter;
    treeset_avl_iterator_init(lus_set, &lus_iter);
    while(treeset_avl_iterator_hasnext(&lus_iter))
    {
        treeset_node *lus_node = treeset_avl_iterator_next_node(&lus_iter);
        label_update_status *lus = (label_update_status *)lus_node->data;

        dnsname_to_dnsname_stack(lus->dname, &dname_stack);

        zdb_rr_label* label = lus->label;

        if((label->flags & ZDB_RR_LABEL_UPDATING) != 0)
        {
            label->flags &= ~ZDB_RR_LABEL_UPDATING;
            
            if(LABEL_HAS_RECORDS(label))
            {
#ifdef DEBUG
                log_debug("dynupdate_update_nsec: pre-processing %{dnsname}", lus->dname);
#endif

                bool hasonlynsec = dynupdate_update_is_empty_nsec(label->resource_record_set);

                bool nsec_covered = !zdb_rr_label_is_glue(label) && !hasonlynsec;

                if(nsec_covered)
                {
                    dnslabel_vector labels;
                    s32 labels_top = dnsname_to_dnslabel_vector(lus->dname, labels);

                    bool new_one = label->nsec.nsec.node == NULL;

                    nsec_update_label_node(zone, label, labels, labels_top);

#ifdef DEBUG
                    log_debug("dynupdate_update_nsec: marking for update %{dnsname}", lus->dname);
#endif

                    treeset_avl_insert(&nsec_upd, label->nsec.nsec.node); /* I only need the label, I don't set the data */

                    if(new_one)
                    {
                        treeset_avl_insert(&nsec_upd, nsec_avl_node_mod_prev(label->nsec.nsec.node));
                    }
                }
                else
                {
                    /* @TODO remove nsec for label
                    *       The previous NSEC will have to be processed for re-signature
                    */

                    if(lus->label->nsec.nsec.node != NULL)
                    {
                        /* I only need the label, I don't set the data */

#ifdef DEBUG
                        log_debug("dynupdate_update_nsec: marking for delete %{dnslabel}", label->name);
#endif

                        treeset_avl_insert(&nsec_del, label->nsec.nsec.node);

                        /*
                        * If I do it now, it is possible that an insert is made after
                        * => said insert will itself require the pred to be done.  Good for me.
                        * If I do it now, it is possible that a delete remove it (I don't care)
                        * => said delete will itself require the update of a pred
                        * => A B C D, del C-> up B, del B -> up A
                        * => A B C D, del B -> up A, del C -> up B
                        *
                        * So I can schedule the pred for update here
                        */

                        nsec_node *pred = nsec_avl_node_mod_prev(label->nsec.nsec.node);

                        /*
                        * I don't care about collisions because content is not allocated
                        */

                        if(pred != NULL)
                        {
#ifdef DEBUG
                            log_debug("dynupdate_update_nsec: marking for update %{dnslabel} (pred del)", pred->label->name);
#endif

                            treeset_avl_insert(&nsec_upd, pred); /* I only need the label, I don't set the data */
                        }
                    }
                }
            }
            else if(!RR_LABEL_HASSUB(label))
            {
                /* No recs nor subs */
                
                if(label->nsec.nsec.node != NULL)
                {
                    dynupdate_update_nsec_body_postdel(zone, &label_del, &nsec_del, label, lus->dname);
                }
            }
        }
    }

    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&nsec_del, &iter);
    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *node = treeset_avl_iterator_next_node(&iter);

        nsec_node *nsec_item = (nsec_node*)node->key;
        // Remove the record & signature & "update" set & node

        zdb_rr_label *label = nsec_item->label;
        
        u8 tmp_name[MAX_DOMAIN_LENGTH];
        nsec_inverse_name(tmp_name, nsec_item->inverse_relative_name);
        
        zdb_packed_ttlrdata *nsec_record = zdb_record_find(&label->resource_record_set, TYPE_NSEC);
        while(nsec_record != NULL)
        {
            zdb_ttlrdata unpacked_ttlrdata;

            unpacked_ttlrdata.ttl = nsec_record->ttl;
            unpacked_ttlrdata.rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec_record);
            unpacked_ttlrdata.rdata_pointer = ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec_record);

            zdb_listener_notify_remove_record(tmp_name, TYPE_NSEC, &unpacked_ttlrdata);
            
            nsec_record = nsec_record->next;
        }
        
        zdb_record_delete(&label->resource_record_set, TYPE_NSEC);
        rrsig_delete(tmp_name, label, TYPE_NSEC);  /* Empty-terminal issue ? */

        nsec_node *pred = nsec_avl_node_mod_prev(nsec_item);
        treeset_avl_insert(&nsec_upd, pred); /* I only need the label, I don't set the data */

        treeset_avl_delete(&nsec_upd, nsec_item);

        if(label->resource_record_set == NULL)
        {
            /* remove the label from the db */
            dnslabel_vector name_path;
            s32 path_index = dnsname_to_dnslabel_stack(nsec_item->inverse_relative_name, name_path);
            label->nsec.nsec.node = NULL;
            zdb_rr_label_delete_record(zone, name_path, (path_index - zone->origin_vector.size) - 1, TYPE_ANY);

            /* remove LABEL from the lus */

            treeset_node *lus_node = treeset_avl_find(lus_set, label);
            if(lus_node != NULL)
            {
                ZFREE(lus_node->data, label_update_status);
                treeset_avl_delete(lus_set, label);
            }
        }

        nsec_avl_delete(&zone->nsec.nsec, nsec_item->inverse_relative_name);
    }

    /*
     * All nsec candidates to be resigned are in nsec_upd
     */

    soa_rdata soa;
    zdb_zone_getsoa(zone, &soa);

    treeset_avl_iterator_init(&nsec_upd, &iter);
    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *node = treeset_avl_iterator_next_node(&iter);

        nsec_node *nsec_item = (nsec_node*)node->key;
        nsec_node *next_nsec_item = nsec_avl_node_mod_next(nsec_item);

        u8 name[MAX_DOMAIN_LENGTH];

        nsec_inverse_name(name, nsec_item->inverse_relative_name);

        if(nsec_update_label_record(nsec_item->label, nsec_item, next_nsec_item, name, soa.minimum))
        {
            /*
             * NSEC are signed the same way as any record, do a simple signature here
             *
             * So I could just ask for an update of the labels instead
             */

            
#ifdef DEBUG
            log_debug("dynupdate_update_nsec: %{dnsname} changed: scheduling", nsec_item->inverse_relative_name);
#endif

            nsec_item->label->flags |= ZDB_RR_LABEL_UPDATING;

            treeset_node *lus_node = treeset_avl_insert(lus_set, nsec_item->label);

            if(lus_node->data == NULL)
            {
                label_update_status *lus;

                ZALLOC_OR_DIE(label_update_status*,lus,label_update_status,GENERIC_TAG);

                lus->label = nsec_item->label;
                lus->dname = nsec_item->inverse_relative_name;
                lus->rtype = TYPE_NSEC;
                lus->remove = FALSE;
                lus->inversed = TRUE;

                lus_node->data = lus;
            }
        }
        else
        {
#ifdef DEBUG
            log_debug("dynupdate_update_nsec: %{dnsname} didn't changed", nsec_item->inverse_relative_name);
#endif
        }
    }

    treeset_avl_destroy(&nsec_upd);
    treeset_avl_destroy(&nsec_del);
    
    for(s32 i = 0; i <= label_del.offset; i++)
    {
        u8 *qname = (u8*)label_del.data[i];
        /* delete qname */
        
        dnslabel_vector name_path;
        
        s32 path_index = dnsname_to_dnslabel_stack(qname, name_path);
                
        zdb_rr_label_delete_record(zone, name_path, (path_index - zone->origin_vector.size) - 1, TYPE_ANY);
        
        free(qname);
    }
    
    return SUCCESS;
}

#endif

#endif

static void label_update_status_destroy(treeset_tree* lus_setp)
{
    treeset_avl_iterator lus_iter;
    treeset_avl_iterator_init(lus_setp, &lus_iter);
    while(treeset_avl_iterator_hasnext(&lus_iter))
    {
        treeset_node *lus_node = treeset_avl_iterator_next_node(&lus_iter);
        label_update_status *lus = (label_update_status *)lus_node->data;
        ZFREE(lus,label_update_status);
    }
    treeset_avl_destroy(lus_setp);
}

ya_result
dynupdate_update(zdb_zone* zone, packet_unpack_reader_data *reader, u16 count, bool dryrun)
{
    if(ZDB_ZONE_INVALID(zone))
    {
        return ZDB_ERROR_ZONE_INVALID;
    }
     
    if(count == 0)
    {
        return SUCCESS;
    }
     
    dnsname_vector origin_path;
    dnsname_vector name_path;

#ifdef DEBUG
    memset(&origin_path, 0xff, sizeof(origin_path));
    memset(&name_path, 0xff, sizeof(name_path));
#endif
    
    /*ptr_vector rrsets;*/
    
    ptr_vector nsec3param_rrset;

    u8* rname;
    u8* rdata;
    u32 rname_size;
    u32 rttl;
    u16 rtype;
    u16 rclass;
    u16 rdata_size;    
    //bool soa_changed = false;
    u8 wire[MAX_DOMAIN_LENGTH + 10 + 65535];
    
#ifdef DEBUG
    rdata = (u8*)~0; // DEBUG
    rname_size = ~0; // DEBUG
    rttl = ~0;       // DEBUG
    rtype = ~0;      // DEBUG
    rclass = ~0;     // DEBUG
    rdata_size = ~0; // DEBUG
#endif

    ya_result edit_status;
    
#if ZDB_HAS_DNSSEC_SUPPORT != 0
    bool dnssec_zone = (zone->apex->nsec.dnssec != NULL);
    
    if(dnssec_zone)
    {
        ya_result return_code = SUCCESS;
        
        /* ensure all the private keys are available or servfail */
        
        const zdb_packed_ttlrdata *dnskey = zdb_zone_get_dnskey_rrset(zone);
                                                        
        if(dnskey != NULL)
        {
            char origin[MAX_DOMAIN_LENGTH];

            dnsname_to_cstr(origin, zone->origin);

            do
            {
                u16 flags = DNSKEY_FLAGS(*dnskey);
                //u8  protocol = DNSKEY_PROTOCOL(*dnskey);
                u8  algorithm = DNSKEY_ALGORITHM(*dnskey);
                u16 tag = DNSKEY_TAG(*dnskey);                  // note: expensive
                dnssec_key *key = NULL;

                if(FAIL(return_code = dnssec_key_load_private(algorithm, tag, flags, origin, &key)))
                {
                    log_err("update: unable to load private key 'K%{dnsname}+%03d+%05d': %r", zone->origin, algorithm, tag, return_code);
                    break;
                }

                dnskey = dnskey->next;
            }
            while(dnskey != NULL);
        }
        else
        {
            log_err("update: there are no private keys in the zone %{dnsname}", zone->origin);

            return_code = DNSSEC_ERROR_RRSIG_NOZONEKEYS;
        }
        
        if(FAIL(return_code))
        {
            return return_code;
        }
    }
#endif
    treeset_tree lus_set = TREESET_EMPTY;
    treeset_avl_iterator lus_iter;
    
#ifdef DEBUG
    memset(&lus_iter, 0xff, sizeof(lus_iter));
#endif

#if ZDB_HAS_DNSSEC_SUPPORT != 0
    ptr_vector_init(&nsec3param_rrset);
    
    zdb_packed_ttlrdata *n3prrset = zdb_record_find(&zone->apex->resource_record_set, TYPE_NSEC3PARAM);
                                        
    while(n3prrset != NULL)
    {
        ptr_vector_append(&nsec3param_rrset, n3prrset);
        
        n3prrset = n3prrset->next;
    }
#endif
    dnsname_to_dnsname_vector(zone->origin, &origin_path);
    
    do
    {
        ya_result return_value;
        
        if(FAIL(return_value = packet_reader_read_record(reader, wire, sizeof(wire))))
        {
            /* if the return code says that the record was invalid, then the buffer has been filled up and including rdata_size */
            
            switch(return_value)
            {
                case INVALID_RECORD:
                case INCORRECT_IPADDRESS:
                case UNSUPPORTED_RECORD:
                {
                    rname = wire;
                    rname_size = dnsname_len(wire);
                    rtype = ntohs(GET_U16_AT(wire[rname_size]));

                    log_err("update: %{dnsname} bogus %{dnstype} record: %r", rname, &rtype, return_value);
                    break;
                }
                default:
                {
                    log_err("update: reading update for zone %{dnsname}: %r", zone->origin, return_value);
                    break;
                }
            }
            
            label_update_status_destroy(&lus_set);
            ptr_vector_destroy(&nsec3param_rrset);

            return SERVER_ERROR_CODE(RCODE_FORMERR);
        }        

        rname = wire;
        rname_size = dnsname_len(wire);
        rtype = GET_U16_AT(wire[rname_size]);
        rclass = GET_U16_AT(wire[rname_size + 2]);
        rttl = ntohl(GET_U32_AT(wire[rname_size + 4]));
        rdata_size = ntohs(GET_U16_AT(wire[rname_size + 8]));        
        rdata = &wire[rname_size + 10];

        /*
         * Simple consistency test:
         */
        
        if((rdata_size == 0) && (rclass != CLASS_ANY))
        {
            label_update_status_destroy(&lus_set);
            ptr_vector_destroy(&nsec3param_rrset);
            
            return SERVER_ERROR_CODE(RCODE_FORMERR);
        }

        dnsname_to_dnsname_vector(rname, &name_path);

        s32 idx;

        for(idx = 0; idx < origin_path.size; idx++)
        {
            if(!dnslabel_equals(origin_path.labels[origin_path.size - idx], name_path.labels[name_path.size - idx]))
            {
                log_err("update: %{dnsname} manual add/del of %{dnstype} records refused", rname, &rtype);
                
                label_update_status_destroy(&lus_set);
                ptr_vector_destroy(&nsec3param_rrset);

                return SERVER_ERROR_CODE(RCODE_NOTZONE);
            }
        }
        
        if((rtype == TYPE_NSEC) || (rtype == TYPE_NSEC3))
        {
            // reject any dynupdate operation on a dnssec-maintained record.
            
            log_err("update: %{dnsname} manual add/del of %{dnstype} records refused", rname, &rtype);
            
            label_update_status_destroy(&lus_set);
            ptr_vector_destroy(&nsec3param_rrset);

            return SERVER_ERROR_CODE(RCODE_REFUSED);
        }
        
#if ZDB_HAS_DNSSEC_SUPPORT != 0
        if((rtype == TYPE_NSEC3PARAM) && dnsname_equals_ignorecase(zone->origin, rname)) /* don't care about NSEC3PARAM put anywhere else than the apex*/
        {
            if(!ZONE_HAS_NSEC3PARAM(zone))
            {
                // don't add/del NSEC3PARAM on a zone that is not already NSEC3 (it works if the zone is not secure
                // but only if the zone has keys already. So for now : disabled
                
                log_err("update: %{dnsname} NSEC3PARAM add/del refused on an non-dnssec3 zone", rname);
                
                label_update_status_destroy(&lus_set);
                ptr_vector_destroy(&nsec3param_rrset);

                return SERVER_ERROR_CODE(RCODE_REFUSED);
            }
            else
            {
                if(NSEC3_RDATA_ALGORITHM(rdata) != DNSSEC_DIGEST_TYPE_SHA1)
                {
                    // don't touch an unsupported digest
                    
                    log_err("update: %{dnsname} NSEC3PARAM with unsupported digest algorithm", rname);
                    
                    label_update_status_destroy(&lus_set);
                    ptr_vector_destroy(&nsec3param_rrset);

                    return SERVER_ERROR_CODE(RCODE_REFUSED);
                }
                
                if(rclass == CLASS_ANY)
                {
                    // don't remove all NSEC3PARAMs from an NSEC3 zone
                    
                    log_err("update: %{dnsname} cannot remove all NSEC3PARAM of an NSEC3 zone", rname);
                    
                    label_update_status_destroy(&lus_set);
                    ptr_vector_destroy(&nsec3param_rrset);

                    return SERVER_ERROR_CODE(RCODE_REFUSED);
                }
                else if(rclass == CLASS_NONE)
                {
                    for(s32 i = 0; i <= nsec3param_rrset.offset; i++)
                    {
                        zdb_packed_ttlrdata *n3prrset = (zdb_packed_ttlrdata*)nsec3param_rrset.data[i];
                        
                        if( rdata_size == ZDB_PACKEDRECORD_PTR_RDATASIZE(n3prrset) )
                        {
                            if(memcmp(rdata , ZDB_PACKEDRECORD_PTR_RDATAPTR(n3prrset), rdata_size) == 0)
                            {
                                nsec3param_rrset.data[i] = nsec3param_rrset.data[nsec3param_rrset.offset];
                                nsec3param_rrset.data[nsec3param_rrset.offset] = NULL;
                                nsec3param_rrset.offset--;
                            }
                        }
                    }
                    
                    if(nsec3param_rrset.offset < 0)
                    {
                        // don't remove the last NSEC3PARAM from an NSEC3 zone
                        
                        log_err("update: %{dnsname} cannot remove the last NSEC3PARAM of an NSEC3 zone", rname);
                    
                        label_update_status_destroy(&lus_set);
                        ptr_vector_destroy(&nsec3param_rrset);

                        return SERVER_ERROR_CODE(RCODE_REFUSED);
                    }
                }
            }
        }
#endif
        if(rclass == CLASS_NONE)
        {
            /* delete from an rrset */

            if(rttl != 0)
            {
                label_update_status_destroy(&lus_set);
                ptr_vector_destroy(&nsec3param_rrset);

                return SERVER_ERROR_CODE(RCODE_FORMERR);
            }
            
            if(name_path.size <= origin_path.size)
            {
                if((rtype == TYPE_SOA) || (rtype == TYPE_ANY))
                {
                    // refused
                    
                    return SERVER_ERROR_CODE(RCODE_REFUSED);
                }
            }
            
            if(!dryrun)
            {

#ifdef DEBUG
                log_debug("update: delete %{dnsname} %{dnstype} ...", rname, &rtype);
#endif
                
                zdb_rr_label* label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - origin_path.size) - 1);
                
                if(label != NULL)
                {
                    zdb_ttlrdata ttlrdata_tmp;

                    ttlrdata_tmp.ttl = 0;
                    ttlrdata_tmp.rdata_size = rdata_size;
                    ttlrdata_tmp.rdata_pointer = rdata;

                    /*
                     * Check if we are about to remove the label.  Add an NSEC/NSEC3 pre-processing here.
                     *
                     * NSEC is not a problem but with NSEC3 it's possible that we removed everything
                     */

                    if(ISOK(edit_status = zdb_rr_label_delete_record_exact(zone, name_path.labels, (name_path.size - origin_path.size) - 1, rtype, &ttlrdata_tmp)))
                    {
                        /*
                         * Don't update IXFR: It has already been done in zdb_rr_label_delete_record_exact
                         */

                        if(edit_status < ZDB_RR_LABEL_DELETE_NODE)  /* node was not deleted */
                        {
                            if(rtype != TYPE_ANY)
                            {
#if ZDB_HAS_DNSSEC_SUPPORT != 0
                                rrsig_delete(rname, label, rtype);
#endif

                                if(RR_LABEL_RELEVANT(label))    /* Empty-termninal issue ! */
                                {
                                    label->flags |= ZDB_RR_LABEL_UPDATING;

                                    treeset_node *lus_node = treeset_avl_insert(&lus_set, label);

                                    if(lus_node->data == NULL)
                                    {
                                        label_update_status *lus;

                                        ZALLOC_OR_DIE(label_update_status*,lus,label_update_status,GENERIC_TAG);

                                        lus->label = label;
                                        lus->dname = rname;
                                        lus->rtype = rtype;
                                        lus->remove = TRUE;
                                        lus->inversed = FALSE;

                                        lus_node->data = lus;
                                    }
                                }
                                else
                                {
                                    /* remove node */
                                                                        
                                    zdb_rr_label_delete_record(zone, name_path.labels, (name_path.size - origin_path.size) - 1, TYPE_ANY);
                                }
                            }
                            /* @TODO if only the dnssec remains, delete */
                        }
                    }
                }
            }
        }
        else if(rclass == CLASS_ANY)
        {   
            if((rttl != 0) || (rdata_size != 0))
            {
                label_update_status_destroy(&lus_set);
                ptr_vector_destroy(&nsec3param_rrset);

                return SERVER_ERROR_CODE(RCODE_FORMERR);
            }
            
            if(name_path.size <= origin_path.size)
            {
                if((rtype == TYPE_SOA) || (rtype == TYPE_ANY))
                {
                    // refused
                    
                    return SERVER_ERROR_CODE(RCODE_REFUSED);
                }
            }

            if(!dryrun)
            {
#ifdef DEBUG
                log_debug("update: delete %{dnsname} %{dnstype} ...", rname, &rtype);
#endif

                zdb_rr_label* label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - origin_path.size) - 1);

                if(label != NULL)
                {
                    /*
                     * Don't update IXFR (remove rrset): Will be done in zdb_rr_label_delete_record
                     */

                    if(ISOK(edit_status = zdb_rr_label_delete_record(zone, name_path.labels, (name_path.size - origin_path.size) - 1, rtype)))
                    {
                        /*
                         * NSEC, NSEC3, RRSIG
                         */

                        if(edit_status < ZDB_RR_LABEL_DELETE_NODE)
                        {
#if ZDB_HAS_DNSSEC_SUPPORT != 0
                            rrsig_delete(rname, label, rtype);
#endif
                            /*
                             * The label may only be there because it contains NSEC/NSEC3 records.
                             * In this case, delete has to be asked again after dnssec fields have been detached and placed on a dummy.
                             *  
                             */
                            
                            if(RR_LABEL_RELEVANT(label)) /* Empty-terminal issue ! */
                            //if( (dictionary_notempty(&(label)->sub))||(btree_notempty((label)->resource_record_set)) )
                            {
                                // something remains in the label
                                
                                label->flags |= ZDB_RR_LABEL_UPDATING;

                                treeset_node *lus_node = treeset_avl_insert(&lus_set, label);
                                
                                if(lus_node->data == NULL)
                                {
                                    label_update_status *lus;

                                    ZALLOC_OR_DIE(label_update_status*,lus,label_update_status,GENERIC_TAG);

                                    lus->label = label;
                                    lus->dname = rname;
                                    lus->rtype = rtype;
                                    lus->remove = TRUE;
                                    lus->inversed = FALSE;

                                    lus_node->data = lus;
                                }
                            }
                            else
                            {
                                /* remove node */
                                zdb_rr_label_delete_record(zone, name_path.labels, (name_path.size - origin_path.size) - 1, TYPE_ANY);
                            }

                            /* @TODO if only the dnssec remains, delete */
                        }
                    }
                }
            }
        }
        else
        {
            /* add to an rrset */

            if(!dryrun)
            {
                zdb_rr_label *label = zdb_rr_label_add(zone, name_path.labels, (name_path.size - origin_path.size) - 1);

#ifdef DEBUG
                log_debug("update: add %{dnsname} %{dnstype} ...", rname, &rtype);
#endif

                u16 flag_mask = 0; /** @todo there is potential for wrongness here ...
                                    *        why don't I store directly in the label ?
                                    *        test dynamic updates around CNAME
                                    */
                bool record_accepted = TRUE;

                switch(rtype)
                {
                    case TYPE_CNAME:
                    {
                        if((label->flags & ZDB_RR_LABEL_DROPCNAME) != 0)
                        {
                            log_err("update: add %{dnsname} CNAME: ignoring CNAME add on non-CNAME", zone->origin);
                            record_accepted = FALSE;
                        }
                        else
                        {
                            flag_mask = ZDB_RR_LABEL_HASCNAME;
                        }
                        break;
                    }
                    case TYPE_RRSIG:
                    case TYPE_NSEC:
                        break;
                    case TYPE_NS:
                        if( (label->flags & ZDB_RR_LABEL_APEX) == 0)
                        {
                            label->flags |= ZDB_RR_LABEL_DELEGATION;
                        }
                        /* falltrough */
                    default:
                    {
                        if( (label->flags & ZDB_RR_LABEL_HASCNAME) != 0)
                        {
                            log_err("update: add %{dnsname} %{dnstype}: ignoring non-CNAME add on CNAME", zone->origin, &rtype);
                            
                            record_accepted = FALSE;
                        }
                        else
                        {
                            flag_mask = ZDB_RR_LABEL_DROPCNAME;

                            if(rtype == TYPE_SOA)
                            {
                                /*
                                 * Ensure there are no other SOA
                                 */
                                //soa_changed = TRUE;

                                zdb_record_delete(&label->resource_record_set, TYPE_SOA);
                                
                                rr_soa_get_minimumttl(rdata, rdata_size, &zone->min_ttl);
                            }
                        }
                        break;
                    }
                }

                label->flags |= flag_mask; /** @TODO : check */

                if(record_accepted)
                {
                    zdb_packed_ttlrdata* record;

                    ZDB_RECORD_ZALLOC(record, rttl, rdata_size, rdata);

                    if(zdb_record_insert_checked(&label->resource_record_set, rtype, record)) /*  FB done (THIS IS A BOOLEAN !!!) */
                    {

#if ZDB_HAS_DNSSEC_SUPPORT != 0
                        rrsig_delete(rname, label, rtype); /* No empty-termninal issue */
#endif
                        if((rtype == TYPE_NS) && ((label->flags & ZDB_RR_LABEL_APEX) == 0))
                        {
                            label->flags |= ZDB_RR_LABEL_DELEGATION;
                        }

#if ZDB_HAS_DNSSEC_SUPPORT != 0
                        if(dnssec_zone)
                        {
                            label->flags |= ZDB_RR_LABEL_UPDATING;
                        }
#endif

                        treeset_node *lus_node = treeset_avl_insert(&lus_set, label);

                        if(lus_node->data == NULL)
                        {
                            label_update_status *lus;

                            ZALLOC_OR_DIE(label_update_status*,lus,label_update_status,GENERIC_TAG);

                            lus->label = label;
                            lus->dname = rname;
                            lus->rtype = rtype;
                            lus->remove = FALSE;
                            lus->inversed = FALSE;

                            lus_node->data = lus;
                        }

                        /*
                         * Add the label to the post-processing queue (NSEC, NSEC3, RRSIG)
                         */

#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0

                        /*
                         * Update IXFR.
                         *
                         * NOTE: the zdb_rr_label set of functions are zdb_listener-aware but the zdb_record ones are not.
                         * That's why this one needs a call to the listener.
                         *
                         */

                        if(rtype != TYPE_SOA)
                        {
                            zdb_ttlrdata unpacked_ttlrdata;
                            unpacked_ttlrdata.rdata_pointer = &record->rdata_start[0];
                            unpacked_ttlrdata.rdata_size = record->rdata_size;
                            unpacked_ttlrdata.ttl = record->ttl;

                            zdb_listener_notify_add_record(name_path.labels, name_path.size, rtype, &unpacked_ttlrdata);
                        }
#endif
                    }
                    else
                    {
                        ZDB_RECORD_ZFREE(record);
                    }
                }
            }
        }
    }
    while(--count > 0);

    if(!dryrun)
    {
        ya_result return_value;
        dnsname_stack name_stack;        

        treeset_avl_iterator_init(&lus_set, &lus_iter);
        
        while(treeset_avl_iterator_hasnext(&lus_iter))
        {
            treeset_node *lus_node = treeset_avl_iterator_next_node(&lus_iter);
            label_update_status *lus = (label_update_status *)lus_node->data;
            
#ifdef DEBUG
            memset(&name_stack, 0xff, sizeof(name_stack));
#endif
            
            dnsname_to_dnsname_stack(lus->dname, &name_stack);

#ifdef DEBUG
            log_debug("update: sanitise %{dnsnamestack}", &name_stack);
#endif

            if(((return_value = zdb_sanitize_rr_label_with_parent(zone, lus->label, &name_stack)) & SANITY_MUSTDROPZONE) != 0)
            {
                /**
                 * Something bad happened.
                 *
                 * What do I do ? I can't really rollback because I already destroyed sets of records.
                 * On another hand AFAIK only multiple SOAs can do this ...
                 * 
                 */

                log_err("update: sanitise reports that the zone should be dropped: %r", return_value);
            }
        }
    }
    
    ya_result return_value = SUCCESS;

#if ZDB_HAS_DNSSEC_SUPPORT != 0
    
    if( !dryrun && (zone->apex->nsec.dnssec != NULL) )
    {
        /*
         * @TODO
         *
         * Actually all I should need to do here is build the list of labels to process with their full path
         * Then initialize a dnssec task, process the list using the right (to be written) callback on
         * dnssec_process_task and using the 'update' task
         *
         * Then I wait that all the tasks are done and from that point the zone should be ok.
         *
         * All text beyond this should be more or less obsolete (I made the callback system a few minutes ago)
         *
         */

#if ZDB_HAS_NSEC_SUPPORT != 0
        if((zone->apex->flags & ZDB_RR_LABEL_NSEC) != 0)
        {
            treeset_avl_iterator_init(&lus_set, &lus_iter);
            while(treeset_avl_iterator_hasnext(&lus_iter))
            {
                treeset_node *lus_node = treeset_avl_iterator_next_node(&lus_iter);
                label_update_status *lus = (label_update_status *)lus_node->data;
                lus->label->flags |= ZDB_RR_LABEL_UPDATING;
            }

            /*
             * Will increase the lus_set content
             */

            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_DYNUPDATE); /** @todo : "give" the mutex instead of this */
            dynupdate_update_nsec(zone, &lus_set);
            zdb_zone_lock(zone, ZDB_ZONE_MUTEX_DYNUPDATE); /** @todo : "give" the mutex instead of this */
        }
#endif

        dynupdate_update_rrsig_body(zone, &lus_set);
                
#if ZDB_HAS_NSEC3_SUPPORT != 0
        if(ISOK(return_value) && ((zone->apex->flags & ZDB_RR_LABEL_NSEC3) != 0))
        {
            treeset_avl_iterator_init(&lus_set, &lus_iter);
            while(treeset_avl_iterator_hasnext(&lus_iter))
            {
                treeset_node *lus_node = treeset_avl_iterator_next_node(&lus_iter);
                label_update_status *lus = (label_update_status *)lus_node->data;
                lus->label->flags |= ZDB_RR_LABEL_UPDATING;
            }

            dynupdate_update_nsec3_body(zone, &lus_set);
        }
#endif

    }

#endif

    label_update_status_destroy(&lus_set);
    ptr_vector_destroy(&nsec3param_rrset);

    return return_value;
}


/*----------------------------------------------------------------------------*/


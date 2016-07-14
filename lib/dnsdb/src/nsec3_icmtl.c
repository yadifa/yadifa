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
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/logger.h>
#include <dnscore/base32hex.h>
#include <dnscore/ptr_set.h>

#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_rr_label.h"

#include "dnsdb/nsec3_icmtl.h"

#include "dnsdb/nsec3_item.h"
#include "dnsdb/nsec3_owner.h"
#include "dnsdb/nsec3_zone.h"

#include "dnsdb/zdb_zone_label_iterator.h"

#include "dnsdb/rrsig.h"
#include "dnsdb/nsec3.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

extern logger_handle *g_dnssec_logger;



/**
 * Returns TRUE if the rdata is a match for an NSEC3PARAM record in the collection.
 * Meant to be used with the NSEC3 chains.
 * 
 * @param collection
 * @param nsec3param_rdata
 * @return 
 */    

bool
nsec3_has_nsec3param(zdb_rr_collection *collection, const u8 *nsec3param_rdata)
{
    zdb_packed_ttlrdata *nsec3param = zdb_record_find(collection, TYPE_NSEC3PARAM);
    while(nsec3param != NULL)
    {
        if(nsec3param_compare_by_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3param), nsec3param_rdata) == 0)
        {
            // match
            return TRUE;
        }
        
        nsec3param = nsec3param->next;
    }
    
    return FALSE;
}

static void
nsec3_add_nsec3paramdel(zdb_rr_collection *collection, const zdb_ttlrdata *nsec3param)
{
    zdb_packed_ttlrdata *nsec3paramdel;
    ZDB_RECORD_ZALLOC(nsec3paramdel, 0, nsec3param->rdata_size, nsec3param->rdata_pointer);
    zdb_record_insert_checked(collection, TYPE_NSEC3PARAMDEL, nsec3paramdel);
}

bool
nsec3_remove_nsec3paramdel(zdb_rr_collection *collection, const u8 *nsec3param_rdata)
{
    zdb_packed_ttlrdata *nsec3paramdel = zdb_record_find(collection, TYPE_NSEC3PARAMDEL);
    while(nsec3paramdel != NULL)
    {
        if(nsec3param_compare_by_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3paramdel), nsec3param_rdata) == 0)
        {
            // match
            const zdb_ttlrdata ttlrdata = {NULL, 0, NSEC3PARAM_RDATA_SIZE_FROM_RDATA(nsec3param_rdata), 0, (u8*)nsec3param_rdata};
            zdb_record_delete_exact(collection, TYPE_NSEC3PARAMDEL, &ttlrdata); // potentially unsafe if the callers uses the record (unlikely and not done at the moment)
            return TRUE;
        }
        
        nsec3paramdel = nsec3paramdel->next;
    }
    
    return FALSE;
}

static bool
nsec3_has_nsec3paramdel(const zdb_rr_collection *collection, const zdb_ttlrdata *nsec3)
{
    zdb_packed_ttlrdata *nsec3paramdel = zdb_record_find(collection, TYPE_NSEC3PARAMDEL);
    while(nsec3paramdel != NULL)
    {
        if(nsec3param_compare_by_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3paramdel), nsec3->rdata_pointer) == 0)
        {
            return TRUE;
        }
        
        nsec3paramdel = nsec3paramdel->next;
    }
    
    return FALSE;
}

static bool
nsec3_has_nsec3param_chain(const zdb_zone *zone, const zdb_ttlrdata *nsec3)
{
    nsec3_zone *n3 = zone->nsec.nsec3;
    while(n3 != NULL)
    {
        if(nsec3param_compare_by_rdata(n3->rdata, nsec3->rdata_pointer) == 0)
        {
            return TRUE;
        }
        
        n3 = n3->next;
    }
    
    return FALSE;
}

/*
 * Finds the nsec3param's alter-ego and removes all the nsec3 records associated to it.
 * (icmtl)
 *
 */

void
nsec3_remove_nsec3param_by_record(zdb_zone* zone, zdb_packed_ttlrdata* nsec3param)
{

    
    nsec3_zone* n3 = zone->nsec.nsec3;

    while(n3 != NULL)
    {
        if(nsec3param_compare_by_rdata(n3->rdata, nsec3param->rdata_start) == 0)
        {
            nsec3_zone_destroy(zone, n3);

            break;
        }

        n3 = n3->next;
    }
}

void
nsec3_add_nsec3param_by_record(zdb_zone* zone, zdb_packed_ttlrdata* nsec3param)
{

    
    nsec3_zone* n3 = zone->nsec.nsec3;

    while(n3 != NULL)
    {
        if(nsec3param_compare_by_rdata(n3->rdata, nsec3param->rdata_start) == 0)
        {
            // already exists

            break;
        }

        n3 = n3->next;
    }
}

/*
 * Remove an NSEC3 without touching any of its siblings (icmtl)
 */

void
nsec3_remove_nsec3(zdb_zone* zone, zdb_packed_ttlrdata* nsec3param)
{

    
    nsec3_zone* n3 = zone->nsec.nsec3;

    while(n3 != NULL)
    {
        if(nsec3param_compare_by_rdata(n3->rdata, nsec3param->rdata_start) == 0)
        {
            u8 digest[256];

            ya_result digest_len = base32hex_decode((char*)&nsec3param->rdata_start[1], (u32)nsec3param->rdata_start[0], digest);

            if(ISOK(digest_len))
            {
                digest[0] = digest_len;

                nsec3_zone_item* item = nsec3_avl_find(&n3->items, digest);

                if(item != NULL)
                {
                    nsec3_zone_item_empties(item);

                    nsec3_avl_delete(&n3->items, item->digest);
                }
            }

            break;
        }

        n3 = n3->next;
    }
}

void
nsec3_remove_nsec3_by_name(zdb_zone* zone, const u8 *nsec3_label, const u8* nsec3_rdata, u16 nsec3_rdata_size)
{   

    
    nsec3_zone* n3 = zone->nsec.nsec3;

    while(n3 != NULL)
    {
        if(nsec3param_compare_by_rdata(n3->rdata, nsec3_rdata) == 0)
        {
            u8 digest[256];

#ifdef DEBUG
            memset(digest, 0xd1, sizeof(digest));
#endif

            ya_result digest_len = base32hex_decode((char*)&nsec3_label[1], nsec3_label[0], &digest[1]);
            
            if(ISOK(digest_len))
            {
                digest[0] = digest_len;

                nsec3_zone_item *item = nsec3_avl_find(&n3->items, digest);

                if(item != NULL)
                {
                    log_debug("nsec3_remove_nsec3_by_name: destroying %{digest32h}", item->digest);

					/*
					 * GOT IT : AN NSEC3 RECORD IS REMOVED BY IXFR BUT THE LABEL HAS NOT BEEN CHANGED
					 * I PRESUME IT IS BECAUSE THE AXFR CHAIN IS CHANGED
					 * I NEED A REPLACE FUNCTION, I NEED TO SORT THE IXFR NSEC(3) OPERATIONS
					 */

                    if(item->sc > 0)
                    {
                        nsec3_zone_item *prev = nsec3_avl_node_mod_prev(item);
                        
                        log_debug("nsec3_remove_nsec3_by_name: prev of %{digest32h} is %{digest32h}", item->digest, prev->digest);
                        
                        yassert(prev != NULL);
                        
                        if(prev != item) // because it can be the last item
                        {
                            nsec3_move_all_star(item, prev);
                        }
                        else
                        {
                            nsec3_remove_all_star(item);
                        }
                    }
                    nsec3_remove_all_owners(item);

                    yassert(item->rc == 0 && item->sc == 0);

                    ZFREE_ARRAY(item->type_bit_maps, item->type_bit_maps_size);

                    item->type_bit_maps = NULL;
                    item->type_bit_maps_size = 0;

                    nsec3_zone_item_rrsig_delete_all(item);

                    nsec3_avl_delete(&n3->items, item->digest);

                }
            }

            break;
        }

        n3 = n3->next;
    }
}

void
nsec3_remove_nsec3_by_digest(zdb_zone* zone, const u8 *nsec3_digest, const u8* nsec3_rdata, u16 nsec3_rdata_size)
{

    
    nsec3_zone* n3 = zone->nsec.nsec3;

    while(n3 != NULL)
    {
        if(nsec3param_compare_by_rdata(n3->rdata, nsec3_rdata) == 0)
        {
            nsec3_zone_item* item = nsec3_avl_find(&n3->items, nsec3_digest);

            if(item != NULL)
            {
                log_debug("nsec3_remove_nsec3_by_digest: destroying %{digest32h}", item->digest);

                /*
                GOT IT : AN NSEC3 RECORD IS REMOVED BY IXFR BUT THE LABEL HAS NOT BEEN CHANGED
                I PRESUME IT IS BECAUSE THE AXFR CHAIN IS CHANGED
                I NEED A REPLACE FUNCTION, I NEED TO SORT THE IXFR NSEC(3) OPERATIONS
                */

                if(item->sc > 0)
                {
                    nsec3_zone_item* prev = nsec3_avl_node_mod_prev(item);
                    if(prev != NULL)
                    {
                        nsec3_move_all_star(item, prev);
                    }
                    else
                    {
                        nsec3_remove_all_star(item);
                    }
                }
                nsec3_remove_all_owners(item);

                yassert(item->rc == 0 && item->sc == 0);

                ZFREE_ARRAY(item->type_bit_maps, item->type_bit_maps_size);

                item->type_bit_maps = NULL;
                item->type_bit_maps_size = 0;

                nsec3_zone_item_rrsig_delete_all(item);

                nsec3_avl_delete(&n3->items, item->digest);

            }
                
            break;
        }

        n3 = n3->next;
    }
}

/*
 * Remove the RRSIG of an NSEC3 (icmtl)
 */

void
nsec3_remove_rrsig(zdb_zone* zone, zdb_packed_ttlrdata* nsec3param)
{

    
    nsec3_zone* n3 = zone->nsec.nsec3;

    while(n3 != NULL)
    {
        if(nsec3param_compare_by_rdata(n3->rdata, nsec3param->rdata_start) == 0)
        {
            u8 digest[256];

            ya_result digest_len = base32hex_decode((char*)&nsec3param->rdata_start[1], (u32)nsec3param->rdata_start[0], digest);

            if(ISOK(digest_len))
            {
                digest[0] = digest_len;

                nsec3_zone_item* item = nsec3_avl_find(&n3->items, digest);

                if(item != NULL)
                {
                    nsec3_zone_item_rrsig_delete_all(item);
                }
            }

            break;
        }

        n3 = n3->next;
    }
}

void
nsec3_add_nsec3_by_name(zdb_zone* zone, const u8 *nsec3_label, const u8* nsec3_rdata, u16 nsec3_rdata_size)
{

    
    nsec3_zone* n3 = zone->nsec.nsec3;

    while(n3 != NULL)
    {
        if(nsec3param_compare_by_rdata(n3->rdata, nsec3_rdata) == 0)
        {
            u8 digest[256];

#ifdef DEBUG
            memset(digest, 0xd1, sizeof(digest));
#endif

            ya_result digest_len = base32hex_decode((char*)&nsec3_label[1], nsec3_label[0], &digest[1]);

            if(ISOK(digest_len))
            {
                digest[0] = digest_len;

#ifndef NDEBUG
                nsec3_zone_item* item = nsec3_avl_find(&n3->items, digest);
                assert(item == NULL);
#endif  
                nsec3_zone_item *self = nsec3_avl_insert(&n3->items, digest);

                self->flags = nsec3_rdata[1];
                /*
                self->rc = 0;
                self->sc = 0;

                self->type_bit_maps = NULL;
                self->type_bit_maps_size = 0;
                */
                nsec3_zone_item_update_bitmap(self, nsec3_rdata, nsec3_rdata_size);
                
                /// @note 20150910 edf -- Some of the *.label links from the predecessor may be invalid
                ///                       Brief explanation of the architecture:
                ///                       Every nsec3-covered labels points to all its nsec3 items/records (one by nsec3param chain)
                ///                       But it also points into the nsec3 record that would cover *.label.parents
                ///                       This helps being very fast for a lot of NSEC3-error answers.
                ///                       Only, the information about the hash is not kept (expensive), so instead destroy the *.link and
                ///                       rebuild when needed (relatively slowly) in the query.
                
                nsec3_zone_item *self_prev = nsec3_avl_node_mod_prev(self);
                nsec3_remove_all_star(self_prev);
            }

            break;
        }

        n3 = n3->next;
    }
}

/**/

static int
nsec3_icmtl_ptr_set_nsec3param_compare(const void *a, const void *b)
{
    u8 *nsec3_rdata_a = (u8*)a;
    u8 *nsec3_rdata_b = (u8*)b;

    return nsec3param_compare_by_rdata(nsec3_rdata_a, nsec3_rdata_b);
}

void nsec3_icmtl_replay_init(nsec3_icmtl_replay *replay, zdb_zone *zone)
{
    ZEROMEMORY(replay, sizeof(nsec3_icmtl_replay));
    
    replay->nsec3_add.compare = ptr_set_dnsname_node_compare;
    replay->nsec3_del.compare = ptr_set_dnsname_node_compare;
    replay->nsec3rrsig_add.compare = ptr_set_dnsname_node_compare;
    replay->nsec3rrsig_del.compare = ptr_set_dnsname_node_compare;
    replay->nsec3_labels.compare = ptr_set_dnsname_node_compare;
    replay->nsec3param_add.compare = nsec3_icmtl_ptr_set_nsec3param_compare;
    replay->nsec3param_del.compare = nsec3_icmtl_ptr_set_nsec3param_compare;
    
    replay->nsec3paramadd_add.compare = nsec3_icmtl_ptr_set_nsec3param_compare;
    replay->nsec3add_add.compare = ptr_set_dnsname_node_compare;
    replay->nsec3add_del.compare = ptr_set_dnsname_node_compare;
    
    replay->zone = zone;
}

static void
nsec3_icmtl_destroy_nsec3(ptr_set *tree)
{
    if(!ptr_set_avl_isempty(tree))
    {
        /* stuff to delete */

        ptr_set_avl_iterator ts_avl_iter;
        ptr_set_avl_iterator_init(tree, &ts_avl_iter);

        while(ptr_set_avl_iterator_hasnext(&ts_avl_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&ts_avl_iter);
            u8 *fqdn = (u8*)node->key;
            zdb_ttlrdata *ttlrdata = (zdb_ttlrdata*)node->value;
            
            free(fqdn);
            
            if(ttlrdata != NULL)
            {
                zdb_ttlrdata_delete(ttlrdata);
            }
        }
        
        ptr_set_avl_destroy(tree);
    }
}

static void
nsec3_icmtl_destroy_nsec3rrsig_add(ptr_set *tree)
{
    if(!ptr_set_avl_isempty(tree))
    {
        /* stuff to delete */

        ptr_set_avl_iterator ts_avl_iter;
        ptr_set_avl_iterator_init(tree, &ts_avl_iter);

        while(ptr_set_avl_iterator_hasnext(&ts_avl_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&ts_avl_iter);
            u8 *fqdn = (u8*)node->key;
            zdb_ttlrdata *ttlrdata = (zdb_ttlrdata*)node->value;
            
            free(fqdn);
            
            while(ttlrdata != NULL)
            {
                zdb_ttlrdata *tmp = ttlrdata->next;
                ZDB_RECORD_ZFREE(ttlrdata);                
                ttlrdata = tmp;
            }
        }
        
        ptr_set_avl_destroy(tree);
    }
}

static void
nsec3_icmtl_destroy_nsec3rrsig_del(ptr_set *tree)
{
    if(!ptr_set_avl_isempty(tree))
    {
        /* stuff to delete */

        ptr_set_avl_iterator ts_avl_iter;
        ptr_set_avl_iterator_init(tree, &ts_avl_iter);

        while(ptr_set_avl_iterator_hasnext(&ts_avl_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&ts_avl_iter);
            u8 *fqdn = (u8*)node->key;
            zdb_ttlrdata *ttlrdata = (zdb_ttlrdata*)node->value;
            
            free(fqdn);
            
            while(ttlrdata != NULL)
            {
                zdb_ttlrdata *tmp = ttlrdata->next;
                zdb_ttlrdata_delete(ttlrdata);
                ttlrdata = tmp;
            }
        }
        
        ptr_set_avl_destroy(tree);
    }
}

static void
nsec3_icmtl_destroy_nsec3param(ptr_set *tree)
{
    if(!ptr_set_avl_isempty(tree))
    {
        ptr_set_avl_iterator n3p_avl_iter;
        ptr_set_avl_iterator_init(tree, &n3p_avl_iter);

        while(ptr_set_avl_iterator_hasnext(&n3p_avl_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&n3p_avl_iter);
            zdb_ttlrdata* nsec3param = (zdb_ttlrdata*)node->value;
                        
            if(nsec3param != NULL)
            {
                zdb_ttlrdata_delete(nsec3param);
            }
            
            node->key = NULL;
            node->value = NULL;
        }
        
        ptr_set_avl_destroy(tree);
    }
}

void
nsec3_icmtl_replay_destroy(nsec3_icmtl_replay *replay)
{    
    nsec3_icmtl_destroy_nsec3(&replay->nsec3_add);
    nsec3_icmtl_destroy_nsec3(&replay->nsec3_del);    
    
    nsec3_icmtl_destroy_nsec3rrsig_add(&replay->nsec3rrsig_add);
    nsec3_icmtl_destroy_nsec3rrsig_del(&replay->nsec3rrsig_del);
    
    nsec3_icmtl_destroy_nsec3param(&replay->nsec3param_add);
    nsec3_icmtl_destroy_nsec3param(&replay->nsec3param_del);
    
    replay->zone = NULL;
}

void nsec3_icmtl_replay_nsec3param_del(nsec3_icmtl_replay *replay, const zdb_ttlrdata *ttlrdata)
{
    assert(ttlrdata->next == NULL);
    
#ifdef DEBUG
    rdata_desc nsec3param_rdata = { TYPE_NSEC3PARAM, ttlrdata->rdata_size, ttlrdata->rdata_pointer};    
    log_debug("journal: %{dnsname}: will del %{typerdatadesc}", replay->zone->origin, &nsec3param_rdata);
#endif
    
    ptr_node *node = ptr_set_avl_find(&replay->nsec3param_del, ttlrdata->rdata_pointer);
    
    if(node == NULL)
    {
        zdb_ttlrdata* clone = zdb_ttlrdata_clone(ttlrdata);
        
        ptr_node *node = ptr_set_avl_insert(&replay->nsec3param_del, clone->rdata_pointer);
        node->value = clone;
        
        /* If the node was previously added, don't add it anymore */
        
        ptr_node *added_node = ptr_set_avl_find(&replay->nsec3param_add, ttlrdata->rdata_pointer);
        
        if(added_node != NULL)
        {
#ifdef DEBUG
            log_debug("journal: %{dnsname}: would not add %{typerdatadesc} anymore", replay->zone->origin, &nsec3param_rdata);
#endif
            
            ptr_set_avl_delete(&replay->nsec3param_add, ttlrdata->rdata_pointer);

            zdb_ttlrdata* nsec3param = (zdb_ttlrdata*)added_node->value;
            
#ifdef DEBUG
            nsec3param_rdata.len = nsec3param->rdata_size;
            nsec3param_rdata.rdata = nsec3param->rdata_pointer;
            log_debug("journal: %{dnsname}: would not add %{typerdatadesc} anymore", replay->zone->origin, &nsec3param_rdata);
#endif
            
            ptr_set_avl_delete(&replay->nsec3param_add, nsec3param->rdata_pointer);
            zdb_ttlrdata_delete(nsec3param);
        }
    }
}

void nsec3_icmtl_replay_nsec3param_add(nsec3_icmtl_replay *replay, const zdb_ttlrdata *ttlrdata)
{
    assert(ttlrdata->next == NULL);
    
#ifdef DEBUG
    rdata_desc nsec3param_rdata = { TYPE_NSEC3PARAM, ttlrdata->rdata_size, ttlrdata->rdata_pointer};    
    log_debug("journal: %{dnsname}: will add %{typerdatadesc}", replay->zone->origin, &nsec3param_rdata);
#endif
    
    ptr_node *node = ptr_set_avl_find(&replay->nsec3param_add, ttlrdata->rdata_pointer);
    
    if(node == NULL)
    {
        zdb_ttlrdata *clone = zdb_ttlrdata_clone_resized(ttlrdata, NSEC3PARAM_RDATA_SIZE_FROM_RDATA(ttlrdata->rdata_pointer));
        nsec3param_set_flags(clone->rdata_pointer, 0); // clear the potential opt-out flag
        ptr_node *node = ptr_set_avl_insert(&replay->nsec3param_add, clone->rdata_pointer);
        node->value = clone;
        
        /* If the node was previously marked as deleted, don't delete it anymore */
        
        ptr_node *added_node = ptr_set_avl_find(&replay->nsec3param_del, ttlrdata->rdata_pointer);
        
        if(added_node != NULL)
        {
            zdb_ttlrdata* nsec3param = (zdb_ttlrdata*)added_node->value;
#ifdef DEBUG
            log_debug("journal: %{dnsname}: would not delete %{typerdatadesc} anymore", replay->zone->origin, &nsec3param_rdata);
            nsec3param_rdata.len = nsec3param->rdata_size;
            nsec3param_rdata.rdata = nsec3param->rdata_pointer;
            log_debug("journal: %{dnsname}: would not delete %{typerdatadesc} anymore", replay->zone->origin, &nsec3param_rdata);
#endif
            ptr_set_avl_delete(&replay->nsec3param_del, ttlrdata->rdata_pointer);
            ptr_set_avl_delete(&replay->nsec3param_del, nsec3param->rdata_pointer);
            zdb_ttlrdata_delete(nsec3param);
        }
    }
}

void nsec3_icmtl_replay_nsec3paramadd_del(nsec3_icmtl_replay *replay, const zdb_ttlrdata *ttlrdata)
{
}

void nsec3_icmtl_replay_nsec3paramadd_add(nsec3_icmtl_replay *replay, const zdb_ttlrdata *ttlrdata)
{
    assert(ttlrdata->next == NULL);
    
#ifdef DEBUG
    rdata_desc nsec3param_rdata = { TYPE_NSEC3PARAM, ttlrdata->rdata_size, ttlrdata->rdata_pointer};    
    log_debug("journal: %{dnsname}: will add %{typerdatadesc} placeholder", replay->zone->origin, &nsec3param_rdata);
#endif
    
    /// @note must be done "find->insert" instead of the usually more efficient "insert" because ...
    
    // if the node does not exist, then I have to insert it.
    // the key is the data of the pointer (not the pointer itself)
    // the pointer should not be already in the database
    
    ptr_node *node = ptr_set_avl_find(&replay->nsec3paramadd_add, ttlrdata->rdata_pointer);
    
    if(node == NULL)
    {
        zdb_ttlrdata *clone = zdb_ttlrdata_clone(ttlrdata);
        
        ptr_node *node = ptr_set_avl_insert(&replay->nsec3paramadd_add, clone->rdata_pointer);
        node->value = clone;
        
        /* If the node was previously marked as deleted, don't delete it anymore */
        
        ptr_node *added_node = ptr_set_avl_find(&replay->nsec3param_del, ttlrdata->rdata_pointer);
        
        if(added_node != NULL)
        {
            zdb_ttlrdata *nsec3param = (zdb_ttlrdata*)added_node->value;
#ifdef DEBUG
            log_debug("journal: %{dnsname}: would not delete %{typerdatadesc} anymore", replay->zone->origin, &nsec3param_rdata);
            nsec3param_rdata.len = nsec3param->rdata_size;
            nsec3param_rdata.rdata = nsec3param->rdata_pointer;
            log_debug("journal: %{dnsname}: would not delete %{typerdatadesc} anymore", replay->zone->origin, &nsec3param_rdata);
#endif
            ptr_set_avl_delete(&replay->nsec3param_del, ttlrdata->rdata_pointer);
            ptr_set_avl_delete(&replay->nsec3param_del, nsec3param->rdata_pointer);
            zdb_ttlrdata_delete(nsec3param);
        }
    }
}

void nsec3_icmtl_replay_nsec3_del(nsec3_icmtl_replay *replay, const u8* fqdn, const zdb_ttlrdata *ttlrdata)
{
    assert(ttlrdata->next == NULL);

    
    ptr_node *node = ptr_set_avl_insert(&replay->nsec3_del, (u8*)fqdn);
    if(node->value == NULL)
    {
        node->key = dnsname_dup(fqdn);
        node->value = zdb_ttlrdata_clone(ttlrdata);
    }
    else
    {
        zdb_ttlrdata_delete(node->value);
        node->value = zdb_ttlrdata_clone(ttlrdata);
    }
}

void nsec3_icmtl_replay_nsec3_add(nsec3_icmtl_replay *replay, const u8* fqdn, const zdb_ttlrdata *ttlrdata)
{
    assert(ttlrdata->next == NULL);

    
    ptr_node *node;
    
    // if there is no NSEC3PARAM chain already
    // if there is no NSEC3PARAM DELETE record already ...
    if(!nsec3_has_nsec3paramdel(&replay->zone->apex->resource_record_set, ttlrdata) &&
       !nsec3_has_nsec3param_chain(replay->zone, ttlrdata))
    {       
        node = ptr_set_avl_find(&replay->nsec3param_add, ttlrdata->rdata_pointer);
        if(node == NULL)
        {
        

            nsec3_icmtl_replay_nsec3param_add(replay, ttlrdata);

        }
    }
    
    replay->optout |= NSEC3_RDATA_IS_OPTOUT(ttlrdata->rdata_pointer);
    
    node = ptr_set_avl_insert(&replay->nsec3_add, (u8*)fqdn);
    if(node->value == NULL)
    {
        node->key = dnsname_dup(fqdn);
        node->value = zdb_ttlrdata_clone(ttlrdata);
    }
    else
    {
        zdb_ttlrdata_delete(node->value);
        node->value = zdb_ttlrdata_clone(ttlrdata);
    }
}

void nsec3_icmtl_replay_nsec3_rrsig_del(nsec3_icmtl_replay *replay, const u8* fqdn, const zdb_ttlrdata *ttlrdata)
{
    assert(ttlrdata->next == NULL);
    


    ptr_node *node;

    // ensure we are not working for no good reason
    
    node = ptr_set_avl_find(&replay->nsec3rrsig_add, (u8*)fqdn);
    
    if(node != NULL)
    {
        // there are signatures for this fqdn
        
        // if the one we are about to add is also deleted, let's cancel them both
        
        zdb_packed_ttlrdata **nsec3_rrsig_ptr = (zdb_packed_ttlrdata **)&node->value;
        zdb_packed_ttlrdata *nsec3_rrsig = (zdb_packed_ttlrdata *)node->value;

        while(nsec3_rrsig != NULL)
        {
            if((nsec3_rrsig->rdata_size == ttlrdata->rdata_size) && (RRSIG_KEY_NATIVETAG(nsec3_rrsig) == GET_U16_AT(((u8*)ttlrdata->rdata_pointer)[16])))
            {
                /* got a match ? */
                
                if(memcmp(&nsec3_rrsig->rdata_start[0], ttlrdata->rdata_pointer, nsec3_rrsig->rdata_size) == 0)
                {

                    // got a match ! delete the addition and forget the removal
                    *nsec3_rrsig_ptr = nsec3_rrsig->next;
                    ZDB_RECORD_ZFREE(nsec3_rrsig);
                    
                    return;
                }
            }
            
            nsec3_rrsig_ptr = &nsec3_rrsig->next;
            nsec3_rrsig = nsec3_rrsig->next;
        }
    }
    
    // done checking for jobs cancelling each-other
    
    node = ptr_set_avl_insert(&replay->nsec3rrsig_del, (u8*)fqdn);
    
    if(node->value == NULL)
    {
        node->key = dnsname_dup(fqdn);
        node->value = zdb_ttlrdata_clone(ttlrdata);
    }
    else
    {
        // insert in front
        
        zdb_ttlrdata *newone = zdb_ttlrdata_clone(ttlrdata);
        newone->next = (zdb_ttlrdata*)node->value;
        node->value = newone;
    }
}

/*
 * No chaining, this is only to add the key in the pool ... and that's the problem.
 */

void nsec3_icmtl_replay_nsec3_rrsig_add(nsec3_icmtl_replay *replay, const u8* fqdn, zdb_packed_ttlrdata *packed_ttlrdata)
{

    
    ptr_node *node;
    
    node = ptr_set_avl_find(&replay->nsec3rrsig_del, (u8*)fqdn);
    
    if(node != NULL)
    {
        zdb_ttlrdata **ttlrdata_ptr = (zdb_ttlrdata**)&node->value;
        zdb_ttlrdata *ttlrdata = (zdb_ttlrdata*)node->value;
        while(ttlrdata != NULL)
        {
            if((ttlrdata->rdata_size == packed_ttlrdata->rdata_size) && ((GET_U16_AT(((u8*)ttlrdata->rdata_pointer)[16])) == RRSIG_KEY_NATIVETAG(packed_ttlrdata)))
            {
                /* got a match ? */
                
                if(memcmp(ttlrdata->rdata_pointer, &packed_ttlrdata->rdata_start[0], packed_ttlrdata->rdata_size) == 0)
                {

                    // got a match ! delete the addition and forget the removal
                    
                    *ttlrdata_ptr = ttlrdata->next;
                    zdb_ttlrdata_delete(ttlrdata);
                    
                    ZDB_RECORD_ZFREE(packed_ttlrdata);
                    
                    return;
                }
            }
            
            ttlrdata_ptr = &ttlrdata->next;
            ttlrdata = ttlrdata->next;
        }
    }
    
    node = ptr_set_avl_insert(&replay->nsec3rrsig_add, (u8*)fqdn);
    
    if(node->value == NULL)
    {
        // new entry
        
        node->key = dnsname_dup(fqdn);
        node->value = packed_ttlrdata;
    }
    else
    {
        // already had this entry: append at the end

        zdb_packed_ttlrdata **nsec3_rrsig_ptr = (zdb_packed_ttlrdata **)&node->value;
        zdb_packed_ttlrdata *nsec3_rrsig = (zdb_packed_ttlrdata *)node->value;

        while(nsec3_rrsig != NULL)
        {
            if((nsec3_rrsig->rdata_size == packed_ttlrdata->rdata_size) && (RRSIG_KEY_NATIVETAG(nsec3_rrsig) == RRSIG_KEY_NATIVETAG(packed_ttlrdata)))
            {
                /* got a match ? */
                
                if(memcmp(&nsec3_rrsig->rdata_start[0], &packed_ttlrdata->rdata_start[0], nsec3_rrsig->rdata_size) == 0)
                {
                    /* got a match ! delete the previous one (?) */
                    packed_ttlrdata->next = nsec3_rrsig->next;
                    ZDB_RECORD_ZFREE(nsec3_rrsig);
                    break;
                }
            }
            
            nsec3_rrsig_ptr = &nsec3_rrsig->next;
            nsec3_rrsig = nsec3_rrsig->next;
        }
        
        *nsec3_rrsig_ptr = packed_ttlrdata;
    }
}

void
nsec3_icmtl_replay_label_add(nsec3_icmtl_replay *replay, const u8 *fqdn, dnslabel_vector_reference labels, s32 label_top)
{

    
    zdb_rr_label *rr_label = zdb_rr_label_add(replay->zone, labels, label_top);

    u16 flags = rr_label->flags;

    if((flags & ZDB_RR_LABEL_UNDERDELEGATION) == 0) /** @todo 20111208 edf -- !zdb_rr_label_is_glue(label) */
    {
        /* APEX or NS+DS */

        if( ((flags & ZDB_RR_LABEL_APEX) != 0) ||
            (((flags & ZDB_RR_LABEL_DELEGATION) != 0) && (zdb_record_find(&rr_label->resource_record_set, TYPE_DS) != NULL) ) )
        {
            ptr_node *node = ptr_set_avl_insert(&replay->nsec3_labels, (u8*)fqdn);

            if(node->value == NULL)
            {
#ifdef DEBUG
                log_debug("journal: NSEC3: queue: %{dnsname} for NSEC3 update", fqdn);
#endif
                node->key = dnsname_dup(fqdn);
                node->value = rr_label;
            }

        }
    }
}

ya_result
nsec3_icmtl_replay_execute(nsec3_icmtl_replay *replay)
{

    
    bool nsec3param_added = FALSE;
    
    int cleared_nsec3_zone_post_check_count = 0;
    nsec3_zone *cleared_nsec3_zone_post_check[16]; // arbitrary maximum number of nsec3 chains
    

    
    if(!ptr_set_avl_isempty(&replay->nsec3param_add))
    {
        ptr_set_avl_iterator n3p_avl_iter;
        ptr_set_avl_iterator_init(&replay->nsec3param_add, &n3p_avl_iter);
        
        while(ptr_set_avl_iterator_hasnext(&n3p_avl_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&n3p_avl_iter);
            zdb_ttlrdata* nsec3param = (zdb_ttlrdata*)node->value;
            
            nsec3_zone* n3 = nsec3_zone_get_from_rdata(replay->zone, nsec3param->rdata_size, nsec3param->rdata_pointer);
            

            
            if(n3 == NULL)
            {
                /*
                 * add the record
                 */
                
                zdb_packed_ttlrdata *packed_ttlrdata;
                ZDB_RECORD_ZALLOC(packed_ttlrdata, 0, nsec3param->rdata_size ,nsec3param->rdata_pointer);
                zdb_record_insert(&replay->zone->apex->resource_record_set, TYPE_NSEC3PARAM, packed_ttlrdata);
                
                nsec3_zone_add_from_rdata(replay->zone, nsec3param->rdata_size, nsec3param->rdata_pointer);
                
                replay->zone->apex->flags |= ZDB_RR_LABEL_NSEC3;
                if(replay->optout)
                {
                    replay->zone->apex->flags |= ZDB_RR_LABEL_NSEC3_OPTOUT;
                }
                
                nsec3param_added = TRUE;
            }
            
            zdb_ttlrdata_delete(nsec3param);
            
            node->key = NULL;
            node->value = NULL;
        }
        
        ptr_set_avl_destroy(&replay->nsec3param_add);
    }
    

    
    if(!ptr_set_avl_isempty(&replay->nsec3_del))
    {        
        /* stuff to delete */

        ptr_set_avl_iterator ts_avl_iter;
        ptr_set_avl_iterator_init(&replay->nsec3_del, &ts_avl_iter);

        while(ptr_set_avl_iterator_hasnext(&ts_avl_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&ts_avl_iter);
            u8 *fqdn = (u8*)node->key;
            zdb_ttlrdata *ttlrdata = (zdb_ttlrdata*)node->value;

#ifdef DEBUG
            log_debug("journal: NSEC3: post/del %{dnsname}", fqdn);
#endif
            ptr_node *add_node;

            if((add_node = ptr_set_avl_find(&replay->nsec3_add, fqdn)) != NULL)
            {
                /* replace */

#ifdef DEBUG
                log_debug("journal: NSEC3: upd %{dnsname}", fqdn);

                rdata_desc type_len_rdata = {TYPE_NSEC3, ttlrdata->rdata_size, ttlrdata->rdata_pointer };
                log_debug("journal: NSEC3: - %{typerdatadesc}", &type_len_rdata);
#endif
                zdb_ttlrdata *add_ttlrdata = (zdb_ttlrdata *)add_node->value;
#ifdef DEBUG
                rdata_desc add_type_len_rdata = {TYPE_NSEC3, add_ttlrdata->rdata_size, add_ttlrdata->rdata_pointer };
                log_debug("journal: NSEC3: + %{typerdatadesc}", &add_type_len_rdata);
#endif
                /*
                 * The node may need an update of the type bitmap
                 * After all changes (del/upd/add) all the added records should be matched again (check)
                 *
                 * nsec3_zone_item_get_by_name();
                 * nsec3_zone_item_update_bitmap(item, rdata, rdata_len)
                 */

                nsec3_zone_item *add_item = nsec3_zone_item_find_by_record(replay->zone, fqdn, ttlrdata->rdata_size, ttlrdata->rdata_pointer);
                
                if(add_item != NULL)
                {
                    nsec3_zone_item_update_bitmap(add_item, add_ttlrdata->rdata_pointer, add_ttlrdata->rdata_size);

                    u8* add_key = add_node->key;
                    ptr_set_avl_delete(&replay->nsec3_add, fqdn);
                    zdb_ttlrdata_delete(add_ttlrdata);
                    free(add_key);
                }
                else
                {
                    log_err("journal: NSEC3: %{dnsname} has not been found in the NSEC3 database (del/add)", fqdn);

                    return ZDB_JOURNAL_NSEC3_LABEL_NOT_FOUND_IN_DB;
                }
            }
            else
            {
#ifdef DEBUG
                log_debug("journal: NSEC3: del %{dnsname}", fqdn);

                rdata_desc type_len_rdata = {TYPE_NSEC3, ttlrdata->rdata_size, ttlrdata->rdata_pointer };
                log_debug("journal: NSEC3: - %{typerdatadesc}", &type_len_rdata);
#endif

                /* delete */
                
                // if the last NSEC3 of an NSEC3PARAM chain has been removed, it needs to be known for doing a test and fix later
                
                nsec3_zone *n3 = nsec3_zone_get_from_rdata(replay->zone, ttlrdata->rdata_size, ttlrdata->rdata_pointer);
    
                nsec3_zone_item *del_item = NULL;

                if(n3 != NULL)
                {
                    del_item = nsec3_zone_item_find_by_name(n3, fqdn);
                }

                if(del_item != NULL)
                {
                    nsec3_remove_nsec3_by_name(replay->zone, fqdn, ttlrdata->rdata_pointer, ttlrdata->rdata_size);
                    
                    if(nsec3_avl_isempty(&n3->items))
                    {
                        // this n3 will have to be tested
                        bool cleared_nsec3_zone_post_check_already_in = FALSE;
                        for(int i = 0; i < cleared_nsec3_zone_post_check_count; ++i)
                        {
                            if(cleared_nsec3_zone_post_check[i] == n3)
                            {
                                cleared_nsec3_zone_post_check_already_in = TRUE;
                                break;
                            }
                        }
                        
                        if(!cleared_nsec3_zone_post_check_already_in)
                        {
                            cleared_nsec3_zone_post_check[cleared_nsec3_zone_post_check_count++] = n3;
                        }
                    }
                }
                else
                {
                    log_err("journal: NSEC3: %{dnsname} has not been found in the NSEC3 database (del)", fqdn);
                }

                /*
                 * The node has to be deleted
                 */
            }

            zdb_ttlrdata_delete(ttlrdata);
            free(fqdn);
            
            node->key = NULL;
            node->value = NULL;
        }

        ptr_set_avl_destroy(&replay->nsec3_del);
    }
    

    
    if(!ptr_set_avl_isempty(&replay->nsec3_add))
    {
        /* stuff to add */

        ptr_set_avl_iterator ts_avl_iter;
        ptr_set_avl_iterator_init(&replay->nsec3_add, &ts_avl_iter);

        while(ptr_set_avl_iterator_hasnext(&ts_avl_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&ts_avl_iter);
            u8 *fqdn = (u8*)node->key;

#ifdef DEBUG
            log_debug("journal: NSEC3: post/add %{dnsname}", fqdn);
#endif

            zdb_ttlrdata *ttlrdata = (zdb_ttlrdata*)node->value;

#ifdef DEBUG
            log_debug("journal: NSEC3: add %{dnsname}", fqdn);

            rdata_desc type_len_rdata = {TYPE_NSEC3, ttlrdata->rdata_size, ttlrdata->rdata_pointer };
            log_debug("journal: NSEC3: + %{typerdatadesc}", &type_len_rdata);
#endif

            /*
             * The node must be added.  It should not exist already.
             * After all changes (del/upd/add) all the added records should be matched again (check)
             */

            nsec3_zone_item *add_item = nsec3_zone_item_find_by_record(replay->zone, fqdn, ttlrdata->rdata_size, ttlrdata->rdata_pointer);
            
            if(add_item != NULL)
            {
                log_err("journal: NSEC3: already exists");
                
                nsec3_zone *n3 = replay->zone->nsec.nsec3;
                
                if(n3 != NULL )
                {
#ifdef DEBUG
                    zdb_packed_ttlrdata *nsec3;
                    const zdb_packed_ttlrdata *nsec3_rrsig;
                    u8 *owner;
                    u8 *pool;
                    u8 pool_buffer[NSEC3_ZONE_ITEM_TO_NEW_ZDB_PACKED_TTLRDATA_SIZE];
                    pool = pool_buffer;
                    
                    nsec3_zone_item_to_new_zdb_packed_ttlrdata_parm nsec3_parms =
                    {
                        n3,
                        add_item,
                        replay->zone->origin,
                        &pool,
                        600
                    };
                    
                    nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                            &nsec3_parms,
                            &owner,
                            &nsec3,
                            &nsec3_rrsig);
                    
                    rdata_desc type_len_rdata = {TYPE_NSEC3, nsec3->rdata_size, nsec3->rdata_start };
                    log_debug("journal: NSEC3: ? %{typerdatadesc}", &type_len_rdata);
#endif                    
                    nsec3_remove_nsec3_by_digest(replay->zone, add_item->digest, ttlrdata->rdata_pointer, ttlrdata->rdata_size);
                }
            }

            // only adds the NSEC3, does not link with the label
            
            /// @note 20150909 edf -- Brief reminder of what is happening: when this record is being fed, there is no information as to its owner.
            ///                       finding it may require to scan the whole database for an nsec3-covered label
            ///                       without a nsec3 item (record) linked.
            ///                       The only alternative is to keep the link empty and do the link when an opportunity presents itself.
            ///                       For an example, if a query on a label needs access to the record, and it's nsec3 covered, and the item
            ///                       is not linked, then and then only its hash will be computed, the item found (except if the database is corrupted)
            ///                       and the link will be established.
            
            nsec3_add_nsec3_by_name(replay->zone, fqdn, ttlrdata->rdata_pointer, ttlrdata->rdata_size);

            zdb_ttlrdata_delete(ttlrdata);
            free(fqdn);
            
            node->key = NULL;
            node->value = NULL;
        }

        ptr_set_avl_destroy(&replay->nsec3_add);
    }
    

    
    if(!ptr_set_avl_isempty(&replay->nsec3rrsig_del))
    {
        /* stuff to add */

        ptr_set_avl_iterator ts_avl_iter;
        ptr_set_avl_iterator_init(&replay->nsec3rrsig_del, &ts_avl_iter);

        while(ptr_set_avl_iterator_hasnext(&ts_avl_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&ts_avl_iter);
            u8 *fqdn = (u8*)node->key;
            
#ifdef DEBUG
            log_debug("journal: NSEC3: post/add %{dnsname}", fqdn);
#endif

            zdb_ttlrdata *nsec3_rrsig = (zdb_ttlrdata*)node->value;

#ifdef DEBUG
            log_debug("journal: NSEC3: add %{dnsname}", fqdn);

            rdata_desc type_len_rdata = {TYPE_RRSIG, ZDB_RECORD_PTR_RDATASIZE(nsec3_rrsig), ZDB_RECORD_PTR_RDATAPTR(nsec3_rrsig) };
            log_debug("journal: NSEC3: + %{typerdatadesc}", &type_len_rdata);
#endif

            /*
             * The node must be added.  It should not exist already.
             * After all changes (del/upd/add) all the added records should be matched again (check)
             */
            nsec3_zone_item *item = nsec3_zone_item_find_by_name_ext(replay->zone, fqdn, NULL);

            if(item != NULL)
            {
                nsec3_zone_item_rrsig_del(item, nsec3_rrsig);
            }

            zdb_ttlrdata_delete(nsec3_rrsig);
            free(fqdn);
            
            node->key = NULL;
            node->value = NULL;
        }

        ptr_set_avl_destroy(&replay->nsec3rrsig_del);
    }
    

    
    if(!ptr_set_avl_isempty(&replay->nsec3rrsig_add))
    {
        /* stuff to add */

        ptr_set_avl_iterator ts_avl_iter;
        ptr_set_avl_iterator_init(&replay->nsec3rrsig_add, &ts_avl_iter);

        while(ptr_set_avl_iterator_hasnext(&ts_avl_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&ts_avl_iter);
            u8 *fqdn = (u8*)node->key;

#ifdef DEBUG
            log_debug("journal: NSEC3: post/add %{dnsname}", fqdn);
#endif

            zdb_packed_ttlrdata *nsec3_rrsig = (zdb_packed_ttlrdata*)node->value;

#ifdef DEBUG
            log_debug("journal: NSEC3: add %{dnsname}", fqdn);

            rdata_desc type_len_rdata = {TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec3_rrsig), ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3_rrsig) };
            log_debug("journal: NSEC3: + %{typerdatadesc}", &type_len_rdata);
#endif

            /*
             * The node must be added.  It should not exist already.
             * After all changes (del/upd/add) all the added records should be matched again (check)
             */
            nsec3_zone_item *item = nsec3_zone_item_find_by_name_ext(replay->zone, fqdn, NULL);

            if(item != NULL)
            {
                nsec3_zone_item_rrsig_add(item, nsec3_rrsig);
            }
            else
            {
                ZDB_RECORD_ZFREE(nsec3_rrsig);
            }

            free(fqdn);
            
            node->key = NULL;
            node->value = NULL;
        }

        ptr_set_avl_destroy(&replay->nsec3rrsig_add);
    }
    

    
    if(!ptr_set_avl_isempty(&replay->nsec3_labels))
    {
        /* labels to update */

        ptr_set_avl_iterator ts_avl_iter;
        ptr_set_avl_iterator_init(&replay->nsec3_labels, &ts_avl_iter);

        while(ptr_set_avl_iterator_hasnext(&ts_avl_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&ts_avl_iter);
            u8 *fqdn = (u8*)node->key;
            zdb_rr_label *rr_label = (zdb_rr_label*)node->value;

#ifdef DEBUG
            log_debug("journal: NSEC3: lbl %{dnsname} (%{dnslabel})", fqdn, rr_label->name);
#endif
            
            /*
             * The fqdn/label should be updated for self & star match.
             */

            if(rr_label->nsec.nsec3 == NULL)
            {

                nsec3_label_link(replay->zone, rr_label, fqdn);

            }
            
            free(fqdn);
            
            node->key = NULL;
            node->value = NULL;
        }

        ptr_set_avl_destroy(&replay->nsec3_labels);
    }
    
    /**/
    
    if(nsec3param_added)
    {

        /*
         * ALL the labels of the zone have to be linked again.
         */
        
        zdb_zone_label_iterator label_iterator;
        
        u8 fqdn[MAX_DOMAIN_LENGTH];
        
        
        zdb_zone_label_iterator_init(&label_iterator, replay->zone);

        while(zdb_zone_label_iterator_hasnext(&label_iterator))
        {
            zdb_zone_label_iterator_nextname(&label_iterator, fqdn);
            zdb_rr_label* label = zdb_zone_label_iterator_next(&label_iterator);
            nsec3_label_link(replay->zone, label, fqdn);
        }
    }
    

    
    if(!ptr_set_avl_isempty(&replay->nsec3param_del))
    {
        ptr_set_avl_iterator n3p_avl_iter;
        ptr_set_avl_iterator_init(&replay->nsec3param_del, &n3p_avl_iter);

        while(ptr_set_avl_iterator_hasnext(&n3p_avl_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&n3p_avl_iter);
            zdb_ttlrdata* nsec3param = (zdb_ttlrdata*)node->value;
            
            nsec3_zone* n3 = nsec3_zone_get_from_rdata(replay->zone, nsec3param->rdata_size, nsec3param->rdata_pointer);



            if(n3 != NULL)
            {
                //nsec3_zone_destroy(replay->zone, n3);

                while(zdb_record_delete_exact(&replay->zone->apex->resource_record_set, TYPE_NSEC3PARAM, nsec3param) != ZDB_ERROR_KEY_NOTFOUND) // safe use (source is the journal)
                {
                    // again ...

                }
                
                // put a placeholder record to remember we are destroying the chain
                
                nsec3_add_nsec3paramdel(&replay->zone->apex->resource_record_set, nsec3param);
            }
   
            zdb_ttlrdata_delete(nsec3param);
            
            // if we remove the nsec3 chain now, the bind-style smooth update will break
            //
            nsec3_zone_destroy(replay->zone, n3);
            
            node->key = NULL;
            node->value = NULL;
        }
        
        ptr_set_avl_destroy(&replay->nsec3param_del);
    }
    
    // for all nsec3_zone with their last item removed on this call, check the nsec3param exists
    // if not, remove it
    
    {
        for(int i = 0; i < cleared_nsec3_zone_post_check_count; ++i)
        {
            nsec3_zone *n3 = cleared_nsec3_zone_post_check[i];

            bool nsec3_zone_obsolete = TRUE;
            
            if(nsec3_avl_isempty(&n3->items))
            {
                // find the nsec3param in the zone
                int n3_salt_len = NSEC3PARAM_RDATA_SIZE_FROM_RDATA(n3->rdata);
                zdb_packed_ttlrdata* nsec3param = zdb_record_find(&replay->zone->apex->resource_record_set, TYPE_NSEC3PARAM);
                while(nsec3param != NULL)
                {
                    int nsec3param_salt_len = NSEC3PARAM_RDATA_SIZE_FROM_RDATA(ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3param));
                    if(n3_salt_len == nsec3param_salt_len)
                    {
                        if(memcmp(n3->rdata, ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3param), n3_salt_len) == 0)
                        {
                            // hit
                            nsec3_zone_obsolete = FALSE;
                            break;
                        }
                    }
                    
                    nsec3param = nsec3param->next;
                }
            }
            
            if(nsec3_zone_obsolete)
            {
                bool done = nsec3_zone_detach(replay->zone, n3);
                if(done)
                {
                    nsec3_zone_free(n3);
                }
                else
                {
                    log_err("journal: %{dnsname} empty NSEC3PARAM chain marked to be removed but does not exists in the zone", replay->zone->origin);
                }
            }
        }
    }
    
    return SUCCESS;
}

/** @} */

/*----------------------------------------------------------------------------*/


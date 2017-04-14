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

/*
 *  RFC 5155
 *
 *  Server Response to a Run-Time Collision
 *
 *  If the hash of a non-existing QNAME collides with the owner name of
 *  an existing NSEC3 RR, then the server will be unable to return a
 *  response that proves that QNAME does not exist.  In this case, the
 *  server MUST return a response with an RCODE of 2 (server failure).
 *
 *  Note that with the hash algorithm specified in this document, SHA-1,
 *  such collisions are highly unlikely.
 *
 */

#include "dnsdb/zdb_types.h"



#if ZDB_HAS_NSEC3_SUPPORT == 0
#error nsec3.c should not be compiled when ZDB_HAS_NSEC3_SUPPORT == 0
#endif

#include <dnscore/dnsname.h>
#include <dnscore/base32hex.h>
#include <dnscore/rfc.h>
#include <dnscore/ptr_vector.h>

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/nsec3.h"
#include "dnsdb/nsec_common.h"
#include "dnsdb/nsec3_owner.h"
#include "dnsdb/zdb_listener.h"
#include "dnsdb/rrsig.h"

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;



static group_mutex_t nsec3_owners_readers_write_locks = GROUP_MUTEX_INITIALIZER;

static nsec3_label_extension*
nsec3_update_label_links_get_extension(zdb_rr_label *label, int nsec3_chain_index)
{
    nsec3_label_extension **n3lep = &label->nsec.nsec3;
    nsec3_label_extension *n3le = NULL;
    for(int i = 0; i <= nsec3_chain_index; ++i)
    {
        if(*n3lep == NULL)
        {
            // a node of the chain is missing.
            *n3lep = nsec3_label_extension_alloc();
            ZEROMEMORY(*n3lep, sizeof(nsec3_label_extension));
        }
        n3le = *n3lep;
        n3lep = &(*n3lep)->next;
    }
    
    // the link for the chain we need is now available
    
    return n3le;
}

static void
nsec3_update_label_links_owner(zdb_rr_label *label, int nsec3_chain_index, nsec3_zone_item *item)
{
    nsec3_label_extension *n3le = nsec3_update_label_links_get_extension(label, nsec3_chain_index);            
    
    yassert(n3le->self == NULL || n3le->self == item);
    
    if(n3le->self == NULL)
    {
        n3le->self = item;
    }
}

static void
nsec3_update_label_links_star(zdb_rr_label *label, int nsec3_chain_index, nsec3_zone_item *item)
{
    nsec3_label_extension *n3le = nsec3_update_label_links_get_extension(label, nsec3_chain_index);            
    
    yassert(n3le->star == NULL || n3le->star == item);
    
    if(n3le->star == NULL)
    {
        n3le->star = item;
    }
}

/**
 * Looks for all labels linked to the nsec3 record (RC / SC) and ensure they are properly linked.
 * This is the other side of nsec3_add_owner and nsec3_add_star, when all informations are available.
 * Used by the chain create.
 */

void
nsec3_update_labels_links(zdb_zone *zone, int nsec3_chain_index, nsec3_zone_item *item)
{
    if(item->rc > 0)
    {
        if(item->rc == 1)
        {
            zdb_rr_label *label = item->label.owner;
            nsec3_update_label_links_owner(label, nsec3_chain_index, item);
        }
        else
        {
            for(int i = 0; i < item->rc; ++i)
            {
                zdb_rr_label *label = item->label.owners[i];
                nsec3_update_label_links_owner(label, nsec3_chain_index, item);
            }
        }            
    }
    if(item->sc > 0)
    {
        if(item->sc == 1)
        {
            zdb_rr_label *label = item->star_label.owner;
            nsec3_update_label_links_star(label, nsec3_chain_index, item);
        }
        else
        {
            for(int i = 0; i < item->rc; ++i)
            {
                zdb_rr_label *label = item->star_label.owners[i];
                nsec3_update_label_links_star(label, nsec3_chain_index, item);
            }
        }            
    }
}

bool
nsec3_update_label(zdb_zone *zone, zdb_rr_label* label, dnslabel_vector_reference labels, s32 labels_top)
{

    /*
     * If label has no nsec3 ->  nsec3_add_label
     *
     * Else
     *
     * Check the types, change if required.
     */

    if(label->nsec.nsec3 == NULL)
    {
        nsec3_add_label(zone, label, labels, labels_top);
        
        return TRUE;
    }
    
    nsec3_zone_item *nsec3_item = label->nsec.nsec3->self;

    if(nsec3_item == NULL)
    {
        yassert((label->nsec.nsec3->self == NULL) && (label->nsec.nsec3->star == NULL) && (label->nsec.nsec3->next == NULL));
        nsec3_label_extension_free(label->nsec.nsec3);
        label->nsec.nsec3 = NULL;
        
        nsec3_add_label(zone, label, labels, labels_top);

        return TRUE;
    }

    type_bit_maps_context type_context;

    u16 type_bit_maps_size = type_bit_maps_initialize(&type_context, label, FALSE, TRUE);
    
    if(type_bit_maps_size > 0)
    {
        u8 *type_bit_maps;
        
        ZALLOC_ARRAY_OR_DIE(u8*, type_bit_maps, type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);
        type_bit_maps_write(type_bit_maps, &type_context);
        
        bool type_map_did_change = TRUE;
        if(nsec3_item->type_bit_maps_size == type_bit_maps_size)
        {
            if(memcmp(nsec3_item->type_bit_maps, type_bit_maps, type_bit_maps_size) == 0)
            {
                type_map_did_change = FALSE; 
            }
        }

        if(type_map_did_change)
        {
            // notify the removal of NSEC3 before going further
            
            nsec3_zone* n3 = nsec3_zone_from_item(zone, nsec3_item);
            zdb_listener_notify_update_nsec3rrsig(zone, nsec3_item->rrsig, NULL, nsec3_item);
            zdb_listener_notify_remove_nsec3(zone, nsec3_item, n3, 0);
            nsec3_zone_item_rrsig_delete_all(nsec3_item);
            
            type_bit_maps_merge(&type_context, nsec3_item->type_bit_maps, nsec3_item->type_bit_maps_size, type_bit_maps, type_bit_maps_size);

            /*
             * Try to re-use one of the buffers
             */

            if(type_context.type_bit_maps_size == nsec3_item->type_bit_maps_size)
            {
                ZFREE_ARRAY(type_bit_maps, type_bit_maps_size);
            }
            else if(type_context.type_bit_maps_size == type_bit_maps_size)
            {
                ZFREE_ARRAY(nsec3_item->type_bit_maps, nsec3_item->type_bit_maps_size);

                nsec3_item->type_bit_maps = type_bit_maps;
                nsec3_item->type_bit_maps_size = type_bit_maps_size;
            }
            else
            {
                ZFREE_ARRAY(type_bit_maps, type_bit_maps_size);
                ZFREE_ARRAY(nsec3_item->type_bit_maps, nsec3_item->type_bit_maps_size);

                ZALLOC_ARRAY_OR_DIE(u8*, nsec3_item->type_bit_maps, type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);
                nsec3_item->type_bit_maps_size = type_bit_maps_size;
            }

            type_bit_maps_write(nsec3_item->type_bit_maps, &type_context);

            return TRUE;
        }
        else
        {
            // nothing to do

            ZFREE_ARRAY(type_bit_maps, type_bit_maps_size);

            return FALSE;
        }
    }
    else
    {
        /*
         * Empty terminator ...
         */

        log_quit("nsec3_update_label called on an empty terminator.  nsec3_remove_label should have been called instead.");

        return FALSE; /* NEVER REACHED */
    }
}

/*
 * Adds NSEC3 records to a label.  This is NOT an update.
 * We assume that the labels are not a fqdn bigger than MAX_DOMAIN_LENGTH
 */

void
nsec3_add_label(zdb_zone *zone, zdb_rr_label* label, dnslabel_vector_reference labels, s32 labels_top)
{
    /*
     * All the intermediary labels are supposed to be ready, the caller
     * MUST call this function each time it adds a new label
     *
     * Compute the stuff
     * Create/Link the NSEC3
     *	    From the PREVIOUS NSEC3 record, recompute the ones that are now
     *	    supposed to be put in the new one
     * Increase the relevant SC
     * A signature should be ordered for this one and for the previous one
     *
     */

    type_bit_maps_context type_context;

    /*
     * All the labels from (included) the root to the zone have to be added
     */

    u32 name_len;
    u8 name[2 + MAX_DOMAIN_LENGTH];
    u8 digest[1 + MAX_DIGEST_LENGTH];

    name[0] = 1;
    name[1] = '*';

    /* NOTE: the final 0 is taken in account in the returned length */

    /* - 1 because of said final 0 */
    name_len = dnslabel_vector_to_dnsname(labels, labels_top, &name[2])/* - 1*/;

    log_debug("nsec3_add_label: %{dnsname}: adding", &name[2]);

    bool opt_out = zdb_zone_is_nsec3_optout(zone);

    u8 default_flags = (opt_out)?1:0;
    
    bool force_rrsig;
    
    if(ZDB_LABEL_UNDERDELEGATION(label))
    {
        force_rrsig = FALSE;
    }
    else
    {
        /* opt-in */
        
        if(!opt_out)
        {
            force_rrsig = TRUE;
        }
        else /* opt-out */
        {            
            if(ZDB_LABEL_ATDELEGATION(label))
            {
                force_rrsig =  (zdb_record_find(&label->resource_record_set, TYPE_DS) != NULL);    /* Has NS & DS */
            }
            else
            {
                force_rrsig = TRUE;
            }
        }
    }
    
    /*
     * These two slots are for the owner label but have to be stored in
     * (and owned by) the NSEC3 item.
     */

    u16 type_bit_maps_size = type_bit_maps_initialize(&type_context, label, FALSE, force_rrsig);
    nsec3_zone* n3 = zone->nsec.nsec3;
    nsec3_label_extension* next_n3_ext = NULL;

    yassert(n3 != NULL);

    do
    {
        nsec3_compute_digest_from_fqdn_with_len(n3, &name[2], name_len, digest, FALSE);

        log_debug("nsec3_add_label: %{dnsname}: NSEC3 name is %{digest32h}", &name[2], digest);

        /*
         * Creates or return the existing nsec3 node for the digest
         *
         */

        nsec3_zone_item *self = nsec3_avl_insert(&n3->items, digest);

        // self->type_bit_maps is NULL => new one

        /*
         * Destroy the previous NSEC3's signature
         */

        nsec3_zone_item *self_prev = nsec3_avl_node_mod_prev(self);

        yassert(self_prev != NULL);

        if(self_prev->rrsig != NULL)
        {
            ZDB_RECORD_ZFREE(self_prev->rrsig);
            self_prev->rrsig = NULL;
        }

        /*
         * Destroy the prev's star references.
         */

#ifdef DEBUG
        if(self_prev->sc > 0)
        {
            log_debug("nsec3_add_label: %{dnsname}: clearing %{digest32h} (predecessor)", &name[2], self_prev->digest);
        }
#endif

        nsec3_remove_all_star(self_prev);

        /** @todo 20140526 edf -- self_prev needs to be signed */

        /*
         *  self -> rc++
         *  self -> owner += label (list + 1 item)
         */

#ifdef DEBUG
        if(self->rc != 0)
        {
            log_debug("nsec3_add_label: %{dnsname}: %{digest32h} has got owner collisions", &name[2], self->digest);
        }
#endif

        nsec3_add_owner(self, label);

        /*
         * Note: the self is edited later
         */
        
        self->flags = default_flags;

        if(self->type_bit_maps_size == 0)
        {
            /*
             * Set the bitmap
             */

            self->type_bit_maps = NULL;
            self->type_bit_maps_size = type_bit_maps_size;

            if(type_bit_maps_size > 0)
            {
                ZALLOC_ARRAY_OR_DIE(u8*, self->type_bit_maps, type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);
                type_bit_maps_write(self->type_bit_maps, &type_context);
            }
            
            zdb_listener_notify_add_nsec3(zone, self, n3, zone->min_ttl);
        }
        else
        {
            /* Merge the existing bitmap with the new one */

            u8* tmp_type_bit_maps;

            ZALLOC_ARRAY_OR_DIE(u8*, tmp_type_bit_maps, MAX(type_bit_maps_size, 1), NSEC3_TYPEBITMAPS_TAG);

            /* type_bit_maps_size > 0 */

            type_bit_maps_write(tmp_type_bit_maps, &type_context);

            if(type_bit_maps_merge(&type_context, self->type_bit_maps, self->type_bit_maps_size, tmp_type_bit_maps, type_bit_maps_size))
            {
                /* TRUE : a merge occurred */

                /**
                 * @todo 20110926 edf -- nsec3_update has got this operation added:
                 *
                 * Check if this is a mistake to have not put it here
                 *
                 * If it was, do the requested factorization (nsec3_update)

                if((node->flags&NSEC3_FLAGS_MARKED_FOR_ICMTL_ADD)==0)
                {
                    zdb_listener_notify_remove_nsec3(zone, node, n3);
                    node->flags|=NSEC3_FLAGS_MARKED_FOR_ICMTL_ADD;
                }
                 */

                yassert(type_bit_maps_size > 0);

                type_bit_maps_size = type_context.type_bit_maps_size;

                ZFREE_ARRAY(self->type_bit_maps, self->type_bit_maps_size);

                ZALLOC_ARRAY_OR_DIE(u8*, self->type_bit_maps, type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);

                self->type_bit_maps_size = type_bit_maps_size;

                type_bit_maps_write(self->type_bit_maps, &type_context);

                /*
                 * This case does not exist:  A merge of something of size > 0
                 * with anything will always give a size > 0
                 *
                 * else
                 * {
                 *   self->type_bit_maps_size = 0;
                 * }
                 *
                 */
            }

            ZFREE_ARRAY(tmp_type_bit_maps, type_bit_maps_size);
        }

        /* nsec3_set_label_extension */

        if(next_n3_ext == NULL)
        {
            yassert(label->nsec.nsec3 == NULL);
            next_n3_ext = nsec3_label_extension_alloc();

#ifdef DEBUG
            memset(next_n3_ext, 0xac, sizeof(nsec3_label_extension));
#endif

            label->nsec.nsec3 = next_n3_ext;
        }
        else
        {
            yassert(next_n3_ext->next == NULL);
            next_n3_ext->next = nsec3_label_extension_alloc();

#ifdef DEBUG
            memset(next_n3_ext->next, 0xca, sizeof(nsec3_label_extension));
#endif

            next_n3_ext = next_n3_ext->next;
        }

        /*
         * Are an array (More than one NSEC3PARAM)
         */

        yassert(self != NULL);


        next_n3_ext->self = self;

        /** @todo 20140526 edf -- self needs to be signed */

        nsec3_compute_digest_from_fqdn_with_len(n3, name, name_len + 2, digest, FALSE);
        //digestname(name, name_len + 2, NSEC3_ZONE_SALT(n3), NSEC3_ZONE_SALT_LEN(n3), nsec3_zone_get_iterations(n3), &digest[1], FALSE);

        nsec3_zone_item* star = nsec3_avl_find_interval_start(&n3->items, digest);

        nsec3_add_star(star, label);

        next_n3_ext->star = star;
        next_n3_ext->next = NULL;

        n3 = n3->next;
    }
    while(n3 != NULL);

    label->flags |= ZDB_RR_LABEL_NSEC3;
}

/**
 * used by nsec3_label_link
 * 
 * It will find if the label has got a matching NSEC3 record (by digest)
 * If so, it will link to it.
 */

static nsec3_zone_item *
nsec3_label_link_seeknode(nsec3_zone* n3, const u8 *fqdn, s32 fqdn_len, u8 *digest)
{
    nsec3_compute_digest_from_fqdn_with_len(n3, fqdn, fqdn_len, digest, FALSE);
    
#if DEBUG
    log_debug("nsec3: seeking node for %{dnsname} with %{digest32h}", fqdn, digest);
#endif

    nsec3_zone_item *self = nsec3_avl_find(&n3->items, digest);

    return self;
}

/**
 * used by nsec3_label_link
 * 
 * It will find if the *.label has got a matching NSEC3 record (by digest)
 * If so, it will link to it.
 */

static nsec3_zone_item *
nsec3_label_link_seekstar(nsec3_zone* n3, const u8 *fqdn, s32 fqdn_len, u8 *digest)
{
    nsec3_compute_digest_from_fqdn_with_len(n3, fqdn, fqdn_len, digest, TRUE);
    
#if DEBUG
    log_debug("nsec3: seeking star for %{dnsname} with %{digest32h}", fqdn, digest);
#endif

    nsec3_zone_item* star = nsec3_avl_find_interval_start(&n3->items, digest);

    return star;
}

/**
  * 
  * Links a label to already existing nsec3 items
  * 
  * This function is for when a label has been added "without intelligence".
  * It will find if the function has got a matching NSEC3 record (by digest)
  * If so, it will link to it.
  * Link is thus made both ways (NSEC3<->LABEL)
  * 
  * @param zone
  * @param label
  * @param fqdn
  *
  */
 
void
nsec3_label_link(zdb_zone *zone, zdb_rr_label* label, const u8 *fqdn)
{
    nsec3_zone* n3 = zone->nsec.nsec3;
    
#ifdef DEBUG
    if(n3 == NULL)
    {
        log_err("zone %{dnsname} has invalid NSEC3 data");
        return;
    }
#endif
    
    nsec3_label_extension **n3lep = &label->nsec.nsec3;

    
    u8 digest[1 + MAX_DIGEST_LENGTH];
    
    // yassert(label->nsec.nsec3 == NULL);

    yassert(n3 != NULL);

    s32 fqdn_len = dnsname_len(fqdn);
    s32 add_count = 0;
    bool linked = FALSE;

    do
    {
        nsec3_label_extension *n3le = *n3lep;
        
        if(n3le == NULL)
        {
            nsec3_zone_item *self = nsec3_label_link_seeknode(n3, fqdn, fqdn_len, digest);
            /// @note 20150908 edf -- investigation: the self returned both has label and *.label pointing to the apex
            if(self == NULL)
            {
                /* no associated node */

                log_debug("nsec3_label_link: %{dnsname} => %{digest32h}: no NSEC3", fqdn, digest);
            }
            
            /**/

            *n3lep = nsec3_label_extension_alloc();
            n3le = *n3lep;            
            ZEROMEMORY(n3le, sizeof(nsec3_label_extension));
            //n3le->next = NULL;
            
            if(self != NULL)
            {
                /**/

                nsec3_add_owner(self, label);
                n3le->self = self;
#if SUPERDUMP
                nsec3_superdump_integrity_check_label_nsec3_self_points_back(label,0);
                nsec3_superdump_integrity_check_nsec3_owner_self_points_back(self,0);
#endif
                /**/

                nsec3_zone_item* star = nsec3_label_link_seekstar(n3, fqdn, fqdn_len, digest);
                //nsec3_superdump_integrity_check_label_nsec3_star_points_back(label,0);
                nsec3_add_star(star, label);
                n3le->star = star;
#if SUPERDUMP
                nsec3_superdump_integrity_check_label_nsec3_star_points_back(label,0);
                nsec3_superdump_integrity_check_nsec3_owner_star_points_back(star,0);
#endif
                /**/
                
                linked = TRUE;

                add_count++;
            }

            n3lep = &n3le->next;
        }
        else
        {
            nsec3_label_extension *n3le = *n3lep;
            
            /* a node exists already, maybe it's not associated yet */
            
            if(n3le->self == NULL)
            {
                nsec3_zone_item *self = nsec3_label_link_seeknode(n3, fqdn, fqdn_len, digest);
                
                if(self != NULL)
                {
                    nsec3_add_owner(self, label); // there is an empty n3e in the label right now
                    n3le->self = self;
#if SUPERDUMP
                    nsec3_superdump_integrity_check_nsec3_owner_self_points_back(self,0);
                    nsec3_superdump_integrity_check_label_nsec3_self_points_back(label,0);
#endif
                    nsec3_zone_item* star = nsec3_label_link_seekstar(n3, fqdn, fqdn_len, digest);
                    assert(star != NULL);
                    //nsec3_superdump_integrity_check_label_nsec3_star_points_back(label,0);
                    nsec3_add_star(star, label);
                    n3le->star = star;
#if SUPERDUMP
                    nsec3_superdump_integrity_check_label_nsec3_star_points_back(label,0);
                    nsec3_superdump_integrity_check_nsec3_owner_star_points_back(star,0);
#endif
                    
                    linked = TRUE;
                }
            }
            
            n3lep = &n3le->next;
        }
        
        n3 = n3->next;
    }
    while(n3 != NULL);

    /* Partial update = BAD */
    
    yassert((n3 == NULL) || (n3 != NULL  && add_count == 0));

    if(linked)
    {
        label->flags |= ZDB_RR_LABEL_NSEC3;
    }
}

/**
 * Unlinks the label from the NSEC3
 *
 * Destroy everything NSEC3 from the label
 *
 * @param zone
 * @param label
 */

void
nsec3_remove_label(zdb_zone *zone, zdb_rr_label* label)
{
    /*
     *
     * 1)
     *
     * Decrease the RC
     * Decrease the SC
     *
     * 2)
     *
     * If RC == 0 (most likely)
     *	    Move all star references to the PREVIOUS NSEC3 record
     *	    destroy the NSEC3 record
     */

    nsec3_label_extension* n3le = label->nsec.nsec3;

    yassert(n3le != NULL);

    //assert_mallocated(n3le);

    log_debug("nsec3_remove_label: %{dnslabel} . %{dnsname}", label->name, zone->origin);

    /* 1) */

    do
    {
        nsec3_zone_item *item = n3le->self;

        if(n3le->star != NULL)
        {
            log_debug("nsec3_remove_label: releasing star %{digest32h}", n3le->star->digest);

            nsec3_remove_star(n3le->star, label);
            n3le->star = NULL;
        }

        if(item != NULL)    /* item = n3le->self */
        {
            log_debug("nsec3_remove_label: releasing self %{digest32h}", item->digest);
            
            nsec3_remove_owner(item, label);
            n3le->self = NULL;

            /* 2) */

            if(item->rc == 0)
            {
                if(item->sc > 0)
                {
                    nsec3_zone_item* prev = nsec3_avl_node_mod_prev(item);
                    
                    yassert(prev != NULL);

                    /*
                     * Take all the star nodes from item
                     *
                     * For each of these nodes, update the NSEC3 reference to "prev"
                     *
                     * Add all the star nodes of item to prev, in one go
                     */

                    if(prev != item)
                    {
                        nsec3_move_all_star(item, prev);
                    }
                    else
                    {
                        nsec3_remove_all_star(item);
                    }
                }

                yassert(item->rc == 0 && item-> sc == 0 && label->nsec.nsec3->self == NULL);

                /* Destroy item */

                /* First, get the root */

                nsec3_zone* n3 = nsec3_zone_from_item(zone, item);

                yassert(n3 != NULL);

                ZFREE_ARRAY(item->type_bit_maps, item->type_bit_maps_size);
                item->type_bit_maps = NULL;

                nsec3_avl_delete(&n3->items, item->digest);
                
                /** @todo 20120306 edf -- if incremental is on, feedback */
            }
        }

        nsec3_label_extension *n3le_tmp = n3le;

        n3le = n3le->next;

        // free the nsec3 label extension of the label being removed
        
        nsec3_label_extension_free(n3le_tmp);
    }
    while(n3le != NULL);

    label->nsec.nsec3 = NULL;
}

/**
 * Initializes an RDATA for an NSEC3PARAM using an hash algorithm, flags, iterations, salt length and salt.
 */

static ya_result
nsec3_build_nsec3param_rdata(u8* nsec3param_rdata, const u8* origin, u8 default_hash_alg, u8 default_flags, u16 default_iterations, u8 default_salt_len, const u8* default_salt)
{
    /* Size of the digest in Base32 Hex */

    u32 b32h_hash_len = ((nsec3_hash_len(default_hash_alg) + 4) / 5) << 3;

    if((b32h_hash_len == 0) || (1 + b32h_hash_len + dnsname_len(origin)) > MAX_DOMAIN_LENGTH - 2) /* - 2 for the '*.' */
    {
        return DNSSEC_ERROR_NSEC3_DIGESTORIGINOVERFLOW; /* name would be too big */
    }

    nsec3param_rdata[0] = default_hash_alg;
    nsec3param_rdata[1] = default_flags;
    SET_U16_AT(nsec3param_rdata[2], htons(default_iterations));
    nsec3param_rdata[4] = default_salt_len;
    MEMCOPY(NSEC3PARAM_RDATA_SALT(nsec3param_rdata), default_salt, default_salt_len);
    
    return NSEC3PARAM_MINIMUM_LENGTH + default_salt_len;
}

/**
 * Adds an nsec3param in the zone (both "DB" and "NSEC3" sides).
 *
 * Delegates to nsec3_zone_add_from_rdata
 *
 */

ya_result
nsec3_add_nsec3param(zdb_zone *zone, u8 default_hash_alg, u8 default_flags, u16 default_iterations, u8 default_salt_len, u8* default_salt)
{
    yassert(default_hash_alg == 1);

    ya_result return_code;

    u16 nsec3param_rdata_size;
    
    u8 nsec3param_rdata[NSEC3PARAM_MINIMUM_LENGTH + MAX_SALT_LENGTH];

    if(FAIL(return_code = nsec3_build_nsec3param_rdata(nsec3param_rdata, zone->origin, default_hash_alg, default_flags, default_iterations, default_salt_len, default_salt)))
    {
        return return_code;
    }

    nsec3param_rdata_size = (u16)return_code;

    nsec3_zone* n3 = nsec3_zone_get_from_rdata(zone, nsec3param_rdata_size, nsec3param_rdata);

    if(n3 == NULL)
    {
        /*n3 =*/nsec3_zone_add_from_rdata(zone, nsec3param_rdata_size, nsec3param_rdata);

        zdb_packed_ttlrdata* nsec3param;

        ZDB_RECORD_ZALLOC(nsec3param, NSEC3PARAM_DEFAULT_TTL, nsec3param_rdata_size, nsec3param_rdata); /** @todo 20110825 edf -- NSEC3PARAM_DEFAULT_TTL : put the real value here*/

        /*
         * Add the NSEC3PARAM to the zone apex
         * Don't do dups
         */

        if(zdb_record_insert_checked(&zone->apex->resource_record_set, TYPE_NSEC3PARAM, nsec3param)) /* FB done (and yes: this returns a boolean) */
        {
#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0

            /*
             * Update ICMTL.
             *
             * NOTE: the zdb_rr_label set of functions are zdb_listener-aware but the zdb_record ones are not.
             * That's why this one needs a call to the listener.
             *
             */

            zdb_ttlrdata unpacked_ttlrdata;
            unpacked_ttlrdata.rdata_pointer = &nsec3param->rdata_start[0];
            unpacked_ttlrdata.rdata_size = nsec3param->rdata_size;
            unpacked_ttlrdata.ttl = nsec3param->ttl;
            
            zdb_listener_notify_add_record(zone, zone->origin_vector.labels, zone->origin_vector.size, TYPE_NSEC3PARAM, &unpacked_ttlrdata);
#endif
        }

        /** @note if we add an nsec3param, we are about to edit the zone.
         *  @todo 20110825 edf -- have an "atomic" way to do all this (mark edit + add param + update nsec3 + update sigs + unmark edit)
         */

        nsec3_edit_zone_start(zone);
    }

    return SUCCESS;
}

/**
 * 
 * Removes an NSEC3PARAM record and its associated structure.
 *
 */

ya_result
nsec3_remove_nsec3param(zdb_zone *zone, u8 hash_alg, u8 flags, u16 iterations, u8 salt_len, const u8* salt)
{
    ya_result return_code;

    /* Build the wire */

    u16 nsec3param_rdata_size;
    u8 nsec3param_rdata[NSEC3PARAM_MINIMUM_LENGTH + MAX_SALT_LENGTH];

    if(FAIL(return_code = nsec3_build_nsec3param_rdata(nsec3param_rdata, zone->origin, hash_alg, flags, iterations, salt_len, salt)))
    {
        return return_code;
    }

    nsec3param_rdata_size = (u16)return_code;

    /* Remove the NSEC3PARAM record */

    zdb_ttlrdata nsec3param_record;
    nsec3param_record.next = NULL;
    nsec3param_record.rdata_size = nsec3param_rdata_size;
    nsec3param_record.rdata_pointer = nsec3param_rdata;
    nsec3param_record.ttl = NSEC3PARAM_DEFAULT_TTL;

    if(ISOK(zdb_record_delete_exact(&zone->apex->resource_record_set, TYPE_NSEC3PARAM, &nsec3param_record))) // safe delete of record
    {
#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0

       /*
        * Update ICMTL.
        *
        * NOTE: the zdb_rr_label set of functions are zdb_listener-aware but the zdb_record ones are not.
        * That's why this one needs a call to the listener.
        *
        */

        zdb_listener_notify_remove_record(zone, zone->origin, TYPE_NSEC3PARAM, &nsec3param_record);
#endif
    }

    /* Retrieve the NSEC3PARAM structure from the zone */

    nsec3_zone* n3 = nsec3_zone_get_from_rdata(zone, nsec3param_rdata_size, nsec3param_rdata);

    if(n3 != NULL)
    {
        /* Destroy said structure and all its associations (NSEC3 item + label's references to it) */

        nsec3_zone_destroy(zone, n3);
    }

    return SUCCESS;
}

/*
 * This destroy all the NSEC3 structures from the zone, starting from the NSEC3PARAM.
 * The zdb_rr_label are also affected by the call.
 */

void
nsec3_destroy_zone(zdb_zone *zone)
{
    if((zone->apex->flags & ZDB_RR_LABEL_NSEC3) != 0)
    {
        while(zone->nsec.nsec3 != NULL)
        {
            nsec3_zone_destroy(zone, zone->nsec.nsec3);
        }
    }
}

/******************************************************************************
 *
 * NSEC3 - queries
 *
 *****************************************************************************/

/**
 * This sets the flags of each NSEC3PARAM of the zone
 *
 */

void
nsec3_set_nsec3param_flags(zdb_zone *zone, u8 flags)
{
    if(zdb_zone_is_nsec3(zone))
    {
        zdb_packed_ttlrdata* rr_sll = zdb_record_find(&zone->apex->resource_record_set, TYPE_NSEC3PARAM);

        while(rr_sll != NULL)
        {
            rr_sll->rdata_start[1] = flags;
            rr_sll = rr_sll->next;
        }
    }
}

/**
 * This sets the flags of each NSEC3PARAM of the zone to 1
 * This should be called before modifying an NSEC3 zone.
 * Note that NSEC3PARAM signature are not affected : the signed version has
 * alsways the flags set to 0
 *
 * If an NSEC3PARAM RR is present at the apex of a zone with a Flags
 * field value of zero, then there MUST be an NSEC3 RR using the same
 * hash algorithm, iterations, and salt parameters present at every
 * hashed owner name in the zone.  That is, the zone MUST contain a
 * complete set of NSEC3 RRs with the same hash algorithm, iterations,
 * and salt parameters.
 */

void
nsec3_edit_zone_start(zdb_zone *zone)
{
    zone->apex->flags |= ZDB_RR_LABEL_DNSSEC_EDIT;

    nsec3_set_nsec3param_flags(zone, 1);
}

/**
 * This sets the flags of each NSEC3PARAM of the zone to 0
 * This should be called after modifying an NSEC3 zone.
 *
 */

void
nsec3_edit_zone_end(zdb_zone *zone)
{
    nsec3_set_nsec3param_flags(zone, 0);

    zone->apex->flags &= ~ZDB_RR_LABEL_DNSSEC_EDIT;
}

/**
 * @brief Finds the provable resource record label matching a path of labels starting from another rr label
 *
 * Finds the resource record label matching a path of labels starting from another rr label
 * Typically the starting label is a zone cut.
 * The starting point MUST be provable (ie: the apex in NSEC and in NSEC3 zones)
 *
 * @param[in] apex the starting label
 * @param[in] path a stack of labels
 * @param[in] path_index the index of the top of the stack
 *
 * @return the matching label or NULL if it has not been found
 */

/* NSEC3: Zone possible */
static int
nsec3_get_closest_provable_encloser_match(const void *label, const dictionary_node *node)
{
    zdb_rr_label* rr_label = (zdb_rr_label*) node;
    return dnslabel_equals(rr_label->name, label);
}

/**
 * 
 * Finds what is the closest provable encloser for a label in a zone
 * 
 * @param apex
 * @param sections
 * @param sections_topp
 * @return 
 */

const zdb_rr_label*
nsec3_get_closest_provable_encloser(const zdb_rr_label *apex, const_dnslabel_vector_reference sections, s32 *sections_topp)
{
    yassert(apex != NULL && sections != NULL && sections_topp != NULL);

    s32 index = *sections_topp;
    const zdb_rr_label* rr_label = apex; /* the zone cut */

    const zdb_rr_label* provable = apex;

    /*
     * the apex is already known, so we don't loop for it
     */

    index--;

    /* look into the sub level*/

    while(index >= 0)
    {
        const u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);

        rr_label = (zdb_rr_label*) dictionary_find(&rr_label->sub, hash, label, nsec3_get_closest_provable_encloser_match);

        if(rr_label == NULL)
        {
            index++;
            break;
        }

        if(rr_label->nsec.dnssec != NULL)
        {
            provable = rr_label;
            *sections_topp = index;
        }

        index--;
    }

    return provable;
}

/**
 * Computes the closest closer proof for a name in a zone
 * Results are returned in 3 pointers
 * The last one of them can be set NULL if the information is not needed.
 * 
 * @param zone
 * @param qname the fqdn of the query
 * @param apex_index the index of the apex in qname
 * @param encloser_nsec3p will point to the encloser
 * @param closest_provable_encloser_nsec3p will point to the closest provable encloser
 * @param wild_closest_provable_encloser_nsec3p will point to the *.closest provable encloser
 * 
 */

void
nsec3_closest_encloser_proof(
                        const zdb_zone *zone,
                        const dnsname_vector *qname, s32 apex_index,
                        const nsec3_zone_item **encloser_nsec3p,
                        const nsec3_zone_item **closest_provable_encloser_nsec3p,
                        const nsec3_zone_item **wild_closest_provable_encloser_nsec3p
                        )
{
    u8 closest_provable_encloser[MAX_DOMAIN_LENGTH];
    u8 encloser[MAX_DOMAIN_LENGTH];
    u8 digest[64 + 1];
    digest[0] = 20;
    
    yassert(encloser_nsec3p != NULL);
    yassert(closest_provable_encloser_nsec3p != NULL);
    // wild_closest_provable_encloser_nsec3p can be NULL 

    const_dnslabel_vector_reference qname_sections = qname->labels;
    s32 closest_encloser_index_limit = qname->size - apex_index + 1; /* not "+1'" because it starts at the apex */

    nsec3_zone* n3 = zone->nsec.nsec3;
    
#ifdef DEBUG
    if((n3 == NULL) || (n3->items == NULL))
    {
        log_err("zone %{dnsname} has invalid NSEC3 data");
        return;
    }
#endif
    
    if(closest_encloser_index_limit > 0)
    {
        const zdb_rr_label* closest_provable_encloser_label = nsec3_get_closest_provable_encloser(zone->apex, qname_sections, &closest_encloser_index_limit);

        //log_debug("closest_provable_encloser_label: %{dnslabel}: %{digest32h}", closest_provable_encloser_label->name, closest_provable_encloser_label->nsec.nsec3->self->digest);
        //log_debug("*.closest_provable_encloser_label: %{dnslabel}: %{digest32h}", closest_provable_encloser_label->name, closest_provable_encloser_label->nsec.nsec3->star->digest);

        /*
         * Convert from closest_encloser_label_bottom to name.size into a dnslabel
         */

        /* Get ZONE NSEC3PARAM */
        u16 iterations = nsec3_zone_get_iterations(n3);
        u8 salt_len = NSEC3_ZONE_SALT_LEN(n3);
        u8* salt = NSEC3_ZONE_SALT(n3);

        nsec3_hash_function* digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3)); /// @note 20150917 edf -- do not use nsec3_compute_digest_from_fqdn_with_len

        /** @note log_* cannot be used here (except yassert because if that one logs it will abort anyway ...) */

        // encloser_nsec3p
        
        if(closest_encloser_index_limit > 0) // if the closest encloser is itself, we should not be here
        {
            yassert(closest_provable_encloser_label != NULL); 

            nsec3_zone_item* encloser_nsec3;
            dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit - 1, encloser);
            digestname(encloser, dnsname_len(encloser), salt, salt_len, iterations, &digest[1], FALSE);
            //OSDEBUG("nsec3_closest_encloser_proof: next digest %{dnsname}: %{digest32h}", encloser, encloser_nsec3->digest);
            encloser_nsec3 = nsec3_zone_item_find(n3, digest);
            *encloser_nsec3p = encloser_nsec3;
            //OSDEBUG("nsec3_closest_encloser_proof: next encloser %{dnsname}: %{digest32h}", encloser, encloser_nsec3->digest);
        }
        else
        {
            *encloser_nsec3p = NULL;
        }

        // closest_provable_encloser_nsec3p

        dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit  , closest_provable_encloser);

        nsec3_zone_item* closest_provable_encloser_nsec3;
        if((closest_provable_encloser_nsec3 = closest_provable_encloser_label->nsec.nsec3->self) == NULL)
        {
            /*
             * @note 20150910 edf -- IMPORTANT: at this point, the database is locked for the readers.
             *                       Calling nsec3_add_owner betrays this.
             *                       Re-locking as writer may lead to starvation.
             *                       All that's needed is to ensure that no two nsec3_add_owner calls are made at the same time from here.
             *                       Two (not very pretty) ways that should have minimal impact: a global mutex OR a global mutex and a set.
             *                       nsec3_add_owner is at most a couple ZALLOC and a few assignations.  The mutex seems a good compromise.
             */
            digestname(closest_provable_encloser, dnsname_len(closest_provable_encloser), salt, salt_len, iterations, &digest[1], FALSE);
            if((closest_provable_encloser_nsec3 = nsec3_avl_find(&n3->items, digest)) != NULL)
            {          
                group_mutex_lock(&nsec3_owners_readers_write_locks, GROUP_MUTEX_WRITE);
                if(closest_provable_encloser_label->nsec.nsec3->self == NULL)
                {
                    nsec3_add_owner(closest_provable_encloser_nsec3, closest_provable_encloser_label);
                    closest_provable_encloser_label->nsec.nsec3->self = closest_provable_encloser_nsec3; /* @todo 20150814 edf -- check multiples */
                }
                group_mutex_unlock(&nsec3_owners_readers_write_locks, GROUP_MUTEX_WRITE);
            }
        }
        *closest_provable_encloser_nsec3p = closest_provable_encloser_nsec3;
        //OSDEBUG("nsec3_closest_encloser_proof: closest_provable_encloser %{dnsname}: %{digest32h}",closest_provable_encloser,closest_provable_encloser_nsec3->digest);

        // wild_closest_provable_encloser_nsec3p
        
        if(wild_closest_provable_encloser_nsec3p != NULL)
        {
            if(closest_provable_encloser_nsec3p == NULL)
            {
                dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit  , closest_provable_encloser);
            }

            nsec3_zone_item* wild_closest_provable_encloser_nsec3;

            if((wild_closest_provable_encloser_nsec3 = closest_provable_encloser_label->nsec.nsec3->star) == NULL)
            {
                /*
                 * @note 20150910 edf -- IMPORTANT: at this point, the database is locked for the readers.
                 *                       Calling nsec3_add_owner betrays this.
                 *                       Re-locking as writer may lead to starvation.
                 *                       All that's needed is to ensure that no two nsec3_add_owner calls are made at the same time from here.
                 *                       Two (not very pretty) ways that should have minimal impact: a global mutex OR a global mutex and a set.
                 *                       nsec3_add_owner is at most a couple ZALLOC and a few assignations.  The mutex seems a good compromise.
                 */
                digestname(closest_provable_encloser, dnsname_len(closest_provable_encloser), salt, salt_len, iterations, &digest[1], TRUE);
                if((wild_closest_provable_encloser_nsec3 = nsec3_avl_find_interval_start(&n3->items, digest)) != NULL)
                {
                    group_mutex_lock(&nsec3_owners_readers_write_locks, GROUP_MUTEX_WRITE);
                    if(closest_provable_encloser_label->nsec.nsec3->star == NULL)
                    {
                        nsec3_add_star(wild_closest_provable_encloser_nsec3, closest_provable_encloser_label);
                        closest_provable_encloser_label->nsec.nsec3->star = wild_closest_provable_encloser_nsec3; /* @todo 20150928 edf -- check multiples */
                    }
                    group_mutex_unlock(&nsec3_owners_readers_write_locks, GROUP_MUTEX_WRITE);
                }
            }                

            *wild_closest_provable_encloser_nsec3p = wild_closest_provable_encloser_nsec3;
            //OSDEBUG("nsec3_closest_encloser_proof: *.closest_provable_encloser *.%{dnsname}: %{digest32h}",closest_provable_encloser,wild_closest_provable_encloser_nsec3->digest);
        }
    }
    else // the closest is the item itself ...
    {
        *encloser_nsec3p = zone->apex->nsec.nsec3->self;
        *closest_provable_encloser_nsec3p = zone->apex->nsec.nsec3->self;
        if(wild_closest_provable_encloser_nsec3p != NULL)
        {
            *wild_closest_provable_encloser_nsec3p = zone->apex->nsec.nsec3->self;
        }
    }
}

void
nsec3_check_item_dump_label(zdb_rr_label *label)
{
    log_debug("%{dnslabel} %04x", label->name, label->flags);

    int n3i = 0;
    
    nsec3_label_extension *n3le = label->nsec.nsec3;
    
    while(n3le != NULL)
    {
        log_debug("NSEC3PARAM #%i", n3i);

        if(n3le->self != NULL)
        {
            log_debug("\tself: %{digest32h}", n3le->self->digest);
        }
        if(n3le->star != NULL)
        {
            log_debug("\tstar: %{digest32h}", n3le->star->digest);
        }

        n3i++;

        n3le = n3le->next;
    }
}

bool
nsec3_check_item(nsec3_zone_item *item, u32 param_index_base)
{
    yassert(item != NULL);

    u16 n = nsec3_owner_count(item);

    for(u16 i = 0; i < n; i++)
    {
        zdb_rr_label *label = nsec3_owner_get(item, i);

        yassert(label != NULL && label->nsec.nsec3 != NULL);
        
        if(ZDB_LABEL_UNDERDELEGATION(label))
        {
            log_debug("nsec3_check: %{digest32h} label nsec3 reference under a delegation (%{dnslabel})", item->digest, label);
        }

        nsec3_label_extension *n3le = label->nsec.nsec3;

        u32 param_index = param_index_base;
        while(param_index > 0)
        {
            yassert(n3le != NULL);



            n3le = n3le->next;

            param_index--;
        }

        yassert(n3le != NULL);


        // the nsec3 structure reference to the item linked to the label does not links back to the item
#if 0 /* fix */
#else
        yassert(n3le->self == item);
#endif
    }

    n = nsec3_star_count(item);

    for(u16 i = 0; i < n; i++)
    {
        zdb_rr_label *label = nsec3_star_get(item, i);
        
        if(!((label != NULL) && (label->nsec.nsec3 != NULL)))
        {
            log_debug("nsec3_check: %{digest32h} (#self=%d/#star=%d) corrupted", item->digest, item->rc, item->sc);
        }

        yassert(label != NULL && label->nsec.nsec3 != NULL);
        
        if(ZDB_LABEL_UNDERDELEGATION(label))
        {
            log_debug("nsec3_check: %{digest32h} *.label nsec3 reference under a delegation (%{dnslabel})", item->digest, label);
        }

        nsec3_label_extension *n3le = label->nsec.nsec3;

        u32 param_index = param_index_base;
        while(param_index > 0)
        {
            yassert(n3le != NULL);



            n3le = n3le->next;

            param_index--;
        }

        yassert(n3le != NULL);



        if(n3le->star != item)
        {
            if(n3le->star != NULL)
            {
                log_debug("nsec3_check: %{digest32h} (#self=%d/#star=%d) failing %{dnslabel} expected %{digest32h}", item->digest, item->rc, item->sc, label->name, n3le->star->digest);
            }
            else
            {
                log_debug("nsec3_check: %{digest32h} (#self=%d/#star=%d) *.%{dnslabel} is NULL", item->digest, item->rc, item->sc, label->name, n3le->star->digest);
            }
        }

        if(n3le->self == NULL)
        {
            log_debug("nsec3_check: %{digest32h} (#self=%d/#star=%d) failing %{dnslabel}: no self", item->digest, item->rc, item->sc, label->name);
        }
        
#if 0 /* fix */
#else
        yassert(n3le->star == item);
        yassert(n3le->self != NULL);
#endif
    }

    return TRUE;
}

bool
nsec3_check(zdb_zone *zone)
{
    log_debug("nsec3_check: %{dnsname}", zone->origin);
    
    const nsec3_zone *n3 = zone->nsec.nsec3;

    if(n3 == NULL)
    {
        log_debug("nsec3_check: %{dnsname} : no NSEC3", zone->origin);
        
        return TRUE;
    }

    /*
     * For each node, check if the owners and stars are coherent
     */

    u32 param_index = 0;

    while(n3 != NULL)
    {
        nsec3_avl_iterator n3iter;
        nsec3_avl_iterator_init(&n3->items, &n3iter);
        while(nsec3_avl_iterator_hasnext(&n3iter))
        {
            nsec3_zone_item* item = nsec3_avl_iterator_next_node(&n3iter);

            nsec3_check_item(item, param_index);
        }

        param_index++;

        n3 = n3->next;
    }
    
    log_debug("nsec3_check: %{dnsname} : done", zone->origin);

    return TRUE;
}

void
nsec3_compute_digest_from_fqdn_with_len(const nsec3_zone *n3, const u8 *fqdn, u32 fqdn_len, u8 *digest, bool isstar)
{
    digest[0] = nsec3_hash_len(NSEC3_ZONE_ALGORITHM(n3));
    
    nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3))(
                                    fqdn,
                                    fqdn_len,
                                    NSEC3_ZONE_SALT(n3),
                                    NSEC3_ZONE_SALT_LEN(n3),
                                    nsec3_zone_get_iterations(n3),
                                    &digest[1],
                                    isstar);
}

/**
 * Updates links for the first NSEC3 chain of the zone
 * Only links to existing NSEC3 records.
 * Only links label with an extension and self/wild set to NULL
 * 
 * @param zone
 */

void
nsec3_zone_update_chain0_links(zdb_zone *zone)
{
    nsec3_zone *n3 = zone->nsec.nsec3;
    
    if(n3 == NULL)
    {
        return;
    }
    
    zdb_zone_label_iterator label_iterator;
    u8 fqdn[MAX_DOMAIN_LENGTH + 1];
    u8 digest[1 + MAX_DIGEST_LENGTH];
    
    zdb_zone_label_iterator_init(&label_iterator, zone);

    while(zdb_zone_label_iterator_hasnext(&label_iterator))
    {
        zdb_zone_label_iterator_nextname(&label_iterator, fqdn);
        zdb_rr_label* label = zdb_zone_label_iterator_next(&label_iterator);
        nsec3_label_extension *n3le = label->nsec.nsec3;
        
        if(n3le != NULL)
        {
            if(n3le->self == NULL || n3le->star == NULL)
            {
                s32 fqdn_len = dnsname_len(fqdn);
                
                if(n3le->self == NULL)
                {
                    nsec3_zone_item *self = nsec3_label_link_seeknode(n3, fqdn, fqdn_len, digest);
                    if(self != NULL)
                    {
                        nsec3_add_owner(self, label);
                        n3le->self = self;
#if SUPERDUMP
                        nsec3_superdump_integrity_check_label_nsec3_self_points_back(label,0);
                        nsec3_superdump_integrity_check_nsec3_owner_self_points_back(self,0);
#endif
                    }
                }
                if(n3le->star == NULL)
                {
                    nsec3_zone_item *star = nsec3_label_link_seekstar(n3, fqdn, fqdn_len, digest);
                    if(star != NULL)
                    {
                        //nsec3_superdump_integrity_check_label_nsec3_star_points_back(label,0);
                        nsec3_add_star(star, label);
                        n3le->star = star;
#if SUPERDUMP
                        nsec3_superdump_integrity_check_label_nsec3_star_points_back(label,0);
                        nsec3_superdump_integrity_check_nsec3_owner_star_points_back(star,0);
#endif
                    }
                }
            }
        }
    }
}



/** @} */

/*----------------------------------------------------------------------------*/


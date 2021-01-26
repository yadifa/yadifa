/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
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
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/rfc.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/ptr_set.h>
#include <dnscore/u32_set.h>
#include <dnscore/logger.h>
#include <dnscore/dnsname.h>

#include <dnscore/dnskey-signature.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/nsec.h"

#include <dnscore/format.h>
#include <dnscore/dnsformat.h>
#include "dnsdb/dnssec.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/dnssec-keystore.h"
#include "dnsdb/zdb_utils.h"

#include "dnsdb/dynupdate-diff.h"

#define MODULE_MSG_HANDLE g_database_logger
extern logger_handle *g_database_logger;

#define NSECNODE_TAG 0x45444f4e4345534e

struct dnssec_chain_node_nsec
{
    nsec_node *prev;
    nsec_node *self;
    nsec_node *next;
    u8 *fqdn;
    u8 state;
    u8 inverse_relative_name[MAX_DOMAIN_LENGTH];
};

typedef struct dnssec_chain_node_nsec dnssec_chain_node_nsec;

static const u8* dnssec_chain_node_nsec_get_inverse_fqdn(const dnssec_chain_node_nsec *node)
{
    
    return (node->self != NULL)?node->self->inverse_relative_name:node->inverse_relative_name;
}

static bool dnssec_chain_node_nsec_fqdn_is_covered(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex || (!diff_fqdn->under_delegation && (diff_fqdn->will_be_non_empty /*|| diff_fqdn->will_have_children*/));
}

static bool dnssec_chain_node_nsec_fqdn_was_covered(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex || (!diff_fqdn->was_under_delegation && (diff_fqdn->was_non_empty /*|| diff_fqdn->will_have_children*/));
}

static dnssec_chain_node_t
dnssec_chain_node_nsec_new(const u8 *fqdn, dnssec_chain_head_t chain)
{
    // compute the inverse of the fqdn for the chain
    // find if the node already exists
    // return the appropriate node
    
    nsec_zone* nsec_chain = (nsec_zone*)chain;
    
    u8 inverse_name[MAX_DOMAIN_LENGTH];
    
    nsec_inverse_name(inverse_name, fqdn);
    
    nsec_zone_item *self = NULL;
    nsec_zone_item *prev;
    nsec_zone_item *next;
    bool empty = nsec_isempty(&nsec_chain); // true if there is not a single node in the NSEC chain
        
    if(!empty)
    {
        prev = nsec_find_interval_prev_mod(&nsec_chain, (const u8*)inverse_name);
        next = nsec_node_mod_next(prev);
        
        if(dnsname_compare(next->inverse_relative_name, inverse_name) == 0)
        {
            // exists
            self = next;
            next = nsec_node_mod_next(self);
        }
    }
    else
    {
        prev = NULL;
        next = NULL;
    }
    
    dnssec_chain_node_nsec *node;
    
    ZALLOC_OBJECT_OR_DIE(node, dnssec_chain_node_nsec, NSECNODE_TAG);
    node->prev = prev;
    node->self = self;
    node->next = next;
    node->fqdn = dnsname_zdup(fqdn);
    
    if(!empty)
    {
        if(self != NULL)
        {
            node->state = DNSSEC_CHAIN_EXISTS;
        }
        else
        {
            node->state = DNSSEC_CHAIN_ADD;
            dnsname_copy(node->inverse_relative_name, inverse_name);
        }

        if(node->prev != NULL)
        {
            if(node->next != NULL)   
            {
                log_debug1("update: nsec: %{dnsname} has node %{dnsname} [ %{dnsname} ; %{dnsname} ] (%02x)", fqdn,
                        dnssec_chain_node_nsec_get_inverse_fqdn(node),
                        node->prev->inverse_relative_name,
                        node->next->inverse_relative_name,
                        node->state);
            }
            else
            {
                log_debug1("update: nsec: %{dnsname} has node %{dnsname} [ %{dnsname} ; ? [ (%02x)", fqdn,
                        dnssec_chain_node_nsec_get_inverse_fqdn(node),
                        node->prev->inverse_relative_name,
                        node->state);
            }
        }
        else
        {
            log_debug1("update: nsec: %{dnsname} has node %{dnsname} [ ? ; %{dnsname} [ (%02x)", fqdn,
                        dnssec_chain_node_nsec_get_inverse_fqdn(node),
                        node->next->inverse_relative_name,
                        node->state);
        }
    }
    else
    {
        node->state = DNSSEC_CHAIN_ADD;
        dnsname_copy(node->inverse_relative_name, inverse_name);
    }
    
    return (dnssec_chain_node_t)node;
}

static void dnssec_chain_node_nsec_delete(dnssec_chain_node_t node_)
{
    dnssec_chain_node_nsec *nsec_node = (dnssec_chain_node_nsec*)node_;
    if(nsec_node->fqdn != NULL)
    {
        dnsname_zfree(nsec_node->fqdn);
    }
    ZFREE_OBJECT(nsec_node);
}

static bool dnssec_chain_node_nsec_has_bits_map(const dnssec_chain_node_nsec *node)
{
    return (node->self != NULL) && (node->self->label != NULL) && (zdb_record_find(&node->self->label->resource_record_set, TYPE_NSEC) != NULL);
}


static int dnssec_chain_node_nsec_compare(const void *a_, const void *b_)
{
    const dnssec_chain_node_nsec *a = (const dnssec_chain_node_nsec*)a_;
    const dnssec_chain_node_nsec *b = (const dnssec_chain_node_nsec*)b_;
    
    const u8 *a_inverse_fqdn = dnssec_chain_node_nsec_get_inverse_fqdn(a);
    const u8 *b_inverse_fqdn = dnssec_chain_node_nsec_get_inverse_fqdn(b);
    
    int ret = dnsname_compare(a_inverse_fqdn, b_inverse_fqdn);
    
    return ret;
}

static dnssec_chain_node_t dnssec_chain_node_nsec_prev(const dnssec_chain_node_t node_)
{
    dnssec_chain_node_nsec *self = (dnssec_chain_node_nsec*)node_;
    dnssec_chain_node_nsec *node;
    
    u8 fqdn[MAX_DOMAIN_LENGTH];
    
    ZALLOC_OBJECT_OR_DIE(node, dnssec_chain_node_nsec, NSECNODE_TAG);
    node->prev = NULL;
    node->self = self->prev;
    node->next = self->next;
    
    nsec_inverse_name(fqdn, self->prev->inverse_relative_name);
    
    node->fqdn = dnsname_zdup(fqdn);
    node->state = DNSSEC_CHAIN_EXISTS|DNSSEC_CHAIN_BEGIN;
    
    log_debug1("update: prev is %{dnsname} (%02x)", node->self->inverse_relative_name, node->state);
    
    return (dnssec_chain_node_t)node;
}

static dnssec_chain_node_t dnssec_chain_node_nsec_next(const dnssec_chain_node_t node_)
{
    dnssec_chain_node_nsec *self = (dnssec_chain_node_nsec*)node_;
    dnssec_chain_node_nsec *node;
    
    u8 fqdn[MAX_DOMAIN_LENGTH];
    
    ZALLOC_OBJECT_OR_DIE(node, dnssec_chain_node_nsec, NSECNODE_TAG);
    node->prev = self->prev;
    node->self = self->next;
    node->next = NULL;

    nsec_inverse_name(fqdn, self->next->inverse_relative_name);
    
    node->fqdn = dnsname_zdup(fqdn);
    node->state = DNSSEC_CHAIN_EXISTS|DNSSEC_CHAIN_END;
    
    log_debug1("update: next is %{dnsname} (%02x)", node->self->inverse_relative_name, node->state);
    
    return (dnssec_chain_node_t)node;
}

static u8 dnssec_chain_node_nsec_state_get(const dnssec_chain_node_t node_)
{
    const dnssec_chain_node_nsec *self = (const dnssec_chain_node_nsec*)node_;
    return self->state;
}

static void dnssec_chain_node_nsec_state_set(dnssec_chain_node_t node_, u8 value)
{
    dnssec_chain_node_nsec *self = (dnssec_chain_node_nsec*)node_;
    log_debug1("update: status %{dnsname} from %02x to %02x", dnssec_chain_node_nsec_get_inverse_fqdn(self), self->state, value);
    self->state = value;
}

static void dnssec_chain_node_nsec_merge(dnssec_chain_node_t node, dnssec_chain_node_t with)
{
    u8 node_state = dnssec_chain_node_nsec_state_get(node);
    u8 with_state = dnssec_chain_node_nsec_state_get(with);
    
    if((node_state & DNSSEC_CHAIN_END) && (with_state & DNSSEC_CHAIN_BEGIN))
    {
        dnssec_chain_node_nsec_state_set(node, dnssec_chain_node_nsec_state_get(node) & ~DNSSEC_CHAIN_END);
    }
    
    if((node_state & DNSSEC_CHAIN_BEGIN) && (with_state & DNSSEC_CHAIN_END))
    {
        dnssec_chain_node_nsec_state_set(node, dnssec_chain_node_nsec_state_get(node) & ~DNSSEC_CHAIN_BEGIN);
    }
        
    dnssec_chain_node_nsec_delete(with);
}

/**
 * 
 * 
 * 
 * @param nsec_chain
 * @param from
 * @param to
 * @param diff
 * @param collection
 * @param mask ZONE_DIFF_REMOVE: get the new state, ZONE_DIFF_ADD: get the old state
 * @param append_signatures append the signature (used so they can be removed)
 */

static void dnssec_chain_node_nsec_publish_record(nsec_zone *nsec_chain,
        dnssec_chain_node_nsec *from, dnssec_chain_node_nsec *to,
        zone_diff *diff, ptr_vector *collection, u8 mask, bool append_signatures)
{
    (void)nsec_chain;
    const u8 *inverse_fqdn = dnssec_chain_node_nsec_get_inverse_fqdn(from);
    const u8 *next_inverse_fqdn = dnssec_chain_node_nsec_get_inverse_fqdn(to);
      
    log_debug1("update: %{dnsname}: %{dnsname}: %x: %{dnsname} -> %{dnsname}", diff->origin, inverse_fqdn, mask, inverse_fqdn, next_inverse_fqdn);
    
    // generate the label
    
    // previous and future bitmaps can be computed from zone_diff

    // generate the type map
    
    if(!dnssec_chain_node_nsec_has_bits_map(from) || ((mask & ZONE_DIFF_RR_REMOVE) && (from->state & DNSSEC_CHAIN_REMAP)))
    {
        type_bit_maps_context bitmap;

        u16 bitmap_size = zone_diff_type_bit_map_generate(diff, from->fqdn, &bitmap, mask | ZONE_DIFF_RR_REMOVE, 0,
                                                          from->fqdn, append_signatures);

        if(mask & ZONE_DIFF_RR_REMOVE)
        {
            type_bit_maps_set_type(&bitmap, TYPE_NSEC);
            type_bit_maps_set_type(&bitmap, TYPE_RRSIG);
            bitmap_size = type_bit_maps_update_size(&bitmap);
        }

        yassert(bitmap_size != 0);

        int to_fqdn_len = dnsname_len(to->fqdn);

        u16 rdata_size = to_fqdn_len + bitmap_size;
        
#if C11_VLA_AVAILABLE
        u8 rdata[rdata_size];
#else
        u8* const rdata = (u8* const)stack_alloc(rdata_size);
#endif

        memcpy(&rdata, to->fqdn, to_fqdn_len);
        type_bit_maps_write(&bitmap, &rdata[to_fqdn_len]);
        type_bit_maps_finalize(&bitmap);

        // the record can be created

        zone_diff_label_rr *nsec_rr = zone_diff_label_rr_new(
                from->fqdn, TYPE_NSEC, CLASS_IN, diff->nttl, rdata, rdata_size, TRUE);
        nsec_rr->state |= ZONE_DIFF_RR_VOLATILE;
        
        ptr_vector_append(collection, nsec_rr);
    }
    else // bitmap already present
    {
        // get existing NSEC record
        
        const zdb_rr_label *label = from->self->label;
        
        const zdb_packed_ttlrdata* nsec_sll = zdb_record_find(&label->resource_record_set, TYPE_NSEC);
        
        yassert(nsec_sll != NULL);
        
        // get its type bitmap
        
        const u8 *nsec_rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec_sll);
        u16 nsec_rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec_sll);
        s32 next_fqdn_len = dnsname_len(nsec_rdata);
        
        yassert(nsec_rdata_size >= next_fqdn_len);
        
        u16 bitmap_size = nsec_rdata_size - next_fqdn_len; // dnssec_chain_node_nsec_get_bits_map_size(from)
        
        int to_fqdn_len = dnsname_len(to->fqdn);

        u16 rdata_size = to_fqdn_len + bitmap_size;

#if C11_VLA_AVAILABLE
        u8 rdata[rdata_size];
#else
        u8* const rdata = (u8* const)stack_alloc(rdata_size);
#endif
        
        memcpy(&rdata, to->fqdn, to_fqdn_len);
        memcpy(&rdata[to_fqdn_len], &nsec_rdata[next_fqdn_len], bitmap_size);
        
        zone_diff_label_rr *nsec_rr = zone_diff_label_rr_new(from->fqdn, TYPE_NSEC, CLASS_IN, diff->nttl, rdata, rdata_size, TRUE);
        nsec_rr->state |= ZONE_DIFF_RR_VOLATILE;
        
        ptr_vector_append(collection, nsec_rr);
        
        if(append_signatures)
        {
            zdb_packed_ttlrdata* rrsig_sll = zdb_record_find(&label->resource_record_set, TYPE_RRSIG);
            while(rrsig_sll != NULL)
            {
                if(RRSIG_TYPE_COVERED(rrsig_sll) == TYPE_NSEC)
                {
                    zone_diff_label_rr *new_nsec_rr = zone_diff_label_rr_new(
                        from->fqdn, TYPE_RRSIG, CLASS_IN, rrsig_sll->ttl,
                        ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig_sll),
                        ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig_sll),
                        TRUE);
                    new_nsec_rr->state |= ZONE_DIFF_RR_VOLATILE;
                    ptr_vector_append(collection, new_nsec_rr);
                }

                rrsig_sll = rrsig_sll->next;
            }
        }
    }
}

static void dnssec_chain_node_nsec_publish_log(dnssec_chain_node_t from_, dnssec_chain_node_t to_)
{
    dnssec_chain_node_nsec *from = (dnssec_chain_node_nsec*)from_;
    dnssec_chain_node_nsec *to = (dnssec_chain_node_nsec*)to_;

    const u8 *inverse_fqdn = dnssec_chain_node_nsec_get_inverse_fqdn(from);    
    if(to != NULL)
    {
        const u8 *next_inverse_fqdn = dnssec_chain_node_nsec_get_inverse_fqdn(to);
    
        log_debug1("update: %{dnsname} -> %{dnsname}", inverse_fqdn, next_inverse_fqdn);
    }
    else
    {
        log_debug1("update: %{dnsname} -> ?", inverse_fqdn);
    }
}

static void dnssec_chain_node_nsec_publish_add(dnssec_chain_head_t chain_, dnssec_chain_node_t from_, dnssec_chain_node_t to_, zone_diff *diff, ptr_vector *collection)
{
    dnssec_chain_node_nsec *from = (dnssec_chain_node_nsec*)from_;
    dnssec_chain_node_nsec *to = (dnssec_chain_node_nsec*)to_;
    
    nsec_zone *nsec_chain = (nsec_zone*)chain_;
    dnssec_chain_node_nsec_publish_record(nsec_chain, from, to, diff, collection, ZONE_DIFF_RR_REMOVE, FALSE);
}

static void dnssec_chain_node_nsec_publish_delete(dnssec_chain_head_t chain_, dnssec_chain_node_t from_, dnssec_chain_node_t to_, zone_diff *diff, ptr_vector *collection)
{
    dnssec_chain_node_nsec *from = (dnssec_chain_node_nsec*)from_;
    dnssec_chain_node_nsec *to = (dnssec_chain_node_nsec*)to_;
     
    nsec_zone *nsec_chain = (nsec_zone*)chain_;
    dnssec_chain_node_nsec_publish_record(nsec_chain, from, to, diff, collection, ZONE_DIFF_RR_ADD, TRUE);
}

static bool dnssec_chain_nsec_isempty(dnssec_chain_head_t chain_)
{
    nsec_zone *nsec_chain = (nsec_zone*)chain_;
    bool ret = (nsec_chain != NULL)?nsec_isempty(&nsec_chain):TRUE;
    return ret;
}

static void
dnssec_chain_nsec_finalize_delete_callback(ptr_node *node)
{
    dnssec_chain_node_nsec_delete(node->value);
}

static void dnssec_chain_node_nsec_format_writer_init(dnssec_chain_node_t node_, format_writer *outfw)
{
    dnssec_chain_node_nsec *node = (dnssec_chain_node_nsec*)node_;
    outfw->callback = dnsname_format_handler_method;
    outfw->value = node->fqdn;
}

static bool dnssec_chain_node_nsec_rrset_should_be_signed(const zone_diff_fqdn *diff_fqdn, const zone_diff_fqdn_rr_set *rr_set)
{
    if(diff_fqdn->at_delegation || diff_fqdn->under_delegation)
    {
        return (rr_set->rtype == TYPE_DS) || (rr_set->rtype == TYPE_NSEC);
    }
    else
    {
        return TRUE;
    }
}

static dnssec_chain_node_vtbl dnssec_chain_node_nsec_vtbl = 
{
    dnssec_chain_node_nsec_fqdn_is_covered,
    dnssec_chain_node_nsec_fqdn_was_covered,
    dnssec_chain_node_nsec_new,
    dnssec_chain_node_nsec_prev,
    dnssec_chain_node_nsec_merge,
    dnssec_chain_node_nsec_next,
    dnssec_chain_node_nsec_state_set,
    dnssec_chain_node_nsec_state_get,
    dnssec_chain_node_nsec_delete,
    dnssec_chain_node_nsec_publish_delete,
    dnssec_chain_node_nsec_publish_add,
    dnssec_chain_node_nsec_publish_log,
    dnssec_chain_node_nsec_compare,
    dnssec_chain_nsec_finalize_delete_callback,
    dnssec_chain_nsec_isempty,
    dnssec_chain_node_nsec_format_writer_init,
    dnssec_chain_node_nsec_rrset_should_be_signed,
    "nsec"
};

const dnssec_chain_node_vtbl *
dynupdate_nsec_chain_get_vtbl()
{
    return &dnssec_chain_node_nsec_vtbl;
}

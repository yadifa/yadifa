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
#include <dnscore/logger.h>
#include <dnscore/dnsname.h>
#include <dnscore/digest.h>

#include <dnscore/dnskey-signature.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/nsec.h"
#include "dnsdb/nsec3.h"

#include <dnscore/base32hex.h>
#include <dnscore/format.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/bytearray_input_stream.h>

#include "dnsdb/dnssec.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/dnssec-keystore.h"
#include "dnsdb/zdb_utils.h"

#include "dnsdb/dynupdate-diff.h"

#define ZDB_JOURNAL_CODE 1
#include "dnsdb/journal.h"

ya_result zdb_icmtl_replay_commit(zdb_zone *zone, input_stream *is, u32 *current_serialp);

#define MODULE_MSG_HANDLE g_database_logger
extern logger_handle *g_database_logger;

#define ZDFFLABL_TAG 0x4c42414c4646445a
#define ZDFFLBRR_TAG 0x4242424c4646445a
#define ZDFFFQDN_TAG 0x4e4451464646445a
#define ZDFFRRST_TAG 0x545352524646445a
#define DMSGPCKT_TAG 0x544b435047534d44

#define DYNUPDATE_DIFF_DETAILLED_LOG 1

///////////////////////////////////////////////////////////////////////////////

static char zone_diff_record_state_format_letters[6] = {'+','-','O','V','E','A'};

void
zone_diff_record_state_format(const void* data, output_stream* os, s32 a, char b , bool c, void* reserved_for_method_parameters)
{
    u8 state = *((u8*)data);
    for(int i = 0; i < sizeof(zone_diff_record_state_format_letters); ++i)
    {
        char c = ((state & (1 << i)) != 0)?zone_diff_record_state_format_letters[i]:'_';
        output_stream_write(os, &c, 1);
    }
}

#ifdef DEBUG
static char zone_diff_chain_state_format_letters[8] = {'+','-',' ','r','E','{','}','!'};

static void
zone_diff_chain_state_format(const void* data, output_stream* os, s32 a, char b , bool c, void* reserved_for_method_parameters)
{
    u8 state = *((u8*)data);
    for(int i = 0; i < sizeof(zone_diff_chain_state_format_letters); ++i)
    {
        char c = ((state & (1 << i)) != 0)?zone_diff_chain_state_format_letters[i]:'_';
        output_stream_write(os, &c, 1);
    }
}
#endif

static void
zone_diff_fqdn_changes_format(const void* data, output_stream* os, s32 a, char b , bool c, void* reserved_for_method_parameters)
{
    zone_diff_fqdn *diff = (zone_diff_fqdn*)data;
    
    if(diff->type_map_changed) output_stream_write(os, "MAP ", 4);
    if(diff->all_rrset_added) output_stream_write(os, "+ALL ", 5);
    if(diff->all_rrset_removed) output_stream_write(os, "-ALL ", 5);
    if(diff->is_apex) output_stream_write(os, "APEX ", 5);
    
    output_stream_write(os, "AT(", 3);
    output_stream_write_u8(os, diff->was_at_delegation?'1':'0');
    output_stream_write(os, "->", 2);
    output_stream_write_u8(os, diff->at_delegation?'1':'0');
    output_stream_write(os, ") ", 2);
    
    output_stream_write(os, "UNDER(", 6);
    output_stream_write_u8(os, diff->was_under_delegation?'1':'0');
    output_stream_write(os, "->", 2);
    output_stream_write_u8(os, diff->under_delegation?'1':'0');
    output_stream_write(os, ") ", 2);
    
    output_stream_write(os, "DS(", 3);
    output_stream_write_u8(os, diff->had_ds?'1':'0');
    output_stream_write(os, "->", 2);
    output_stream_write_u8(os, diff->will_have_ds?'1':'0');
    output_stream_write(os, ") ", 2);
    
    output_stream_write(os, "CHILDREN(", 9);
    output_stream_write_u8(os, diff->had_children?'1':'0');
    output_stream_write(os, "->", 2);
    output_stream_write_u8(os, diff->will_have_children?'1':'0');
    output_stream_write(os, ") ", 2);
    
    output_stream_write(os, "NON-EMPTY(", 10);
    output_stream_write_u8(os, diff->was_non_empty?'1':'0');
    output_stream_write(os, "->", 2);
    output_stream_write_u8(os, diff->will_be_non_empty?'1':'0');
    output_stream_write(os, ") ", 2);
}

static const u8 *
zone_diff_label_rr_rrv_get_fqdn(void *data, const void* p)
{
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr*)p;
    return rr->fqdn;
}

static u16
zone_diff_label_rr_rrv_get_type(void *data, const void* p)
{
    /*
    zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)data;
    (void)p;
    return rrset->rtype;
    */
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr*)p;
    return rr->rtype;
}

static u16
zone_diff_label_rr_rrv_get_class(void *data, const void* p)
{
    /*
    zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)data;
    (void)p;
    return rrset->rclass;
    */
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr*)p;
    return rr->rclass;
}

static s32
zone_diff_label_rr_rrv_get_ttl(void *data, const void* p)
{
    /*
    zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)data;
    (void)p;
    return rrset->new_ttl;
    */
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr*)p;
    return rr->ttl;
}

static u16
zone_diff_label_rr_rrv_get_rdata_size(void *data, const void* p)
{
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr*)p;
    return rr->rdata_size;
}

static const u8 *
zone_diff_label_rr_rrv_get_rdata(void *data, const void* p)
{
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr*)p;
    return (const u8*)rr->rdata;
}

static void *
zone_diff_label_rr_rrv_new_instance(void *data, const u8 *fqdn, u16 rtype, u16 rclass, s32 ttl, u16 rdata_size, const u8 *rdata)
{
    (void)data;
    zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, rtype, rclass, ttl, (void*)rdata, rdata_size, TRUE);
    return rr;
}

static const struct resource_record_view_vtbl zone_diff_label_rr_rrv_vtbl =
{
    zone_diff_label_rr_rrv_get_fqdn,
    zone_diff_label_rr_rrv_get_type,
    zone_diff_label_rr_rrv_get_class,
    zone_diff_label_rr_rrv_get_ttl,
    zone_diff_label_rr_rrv_get_rdata_size,
    zone_diff_label_rr_rrv_get_rdata,
    zone_diff_label_rr_rrv_new_instance
};

///////////////////////////////////////////////////////////////////////////////

/**
 * Initialises a dnssec chain (editor).
 * NSEC and NSEC3 chains cannot be mixed.
 * The actual chain must be set using dnssec_chain_add_chain
 * 
 * @param dc
 * @param chain_functions
 */

void dnssec_chain_init(dnssec_chain *dc, const dnssec_chain_node_vtbl *chain_functions, zone_diff *diff)
{
    dc->diff = diff;
    ptr_set_avl_init(&dc->chain_diff);
    dc->chain_diff.compare = chain_functions->compare;
    dc->chain = chain_functions;
    dc->chains_count = 0;
}

/**
 * Adds a chain to the chain editor.
 * 
 * NSEC3: every nsec3_zone* of the zone (one at a time).
 * NSEC: the nsec_zone of the zone.
 * 
 * @param dc
 * @param chain
 */

void dnssec_chain_add_chain(dnssec_chain *dc, dnssec_chain_head_t chain, bool being_deleted)
{
    if(dc->chains_count < DNSSEC_CHAIN_SUPPORTED_MAX)
    {
        dc->chains[dc->chains_count] = chain;
        dc->chain_being_deleted[dc->chains_count] = being_deleted;
        ++dc->chains_count;
    }
}

static void dnssec_chain_add_node(dnssec_chain *dc, const u8 *fqdn, u16 rtype, u8 asked_or_mask)
{
    // compute the hash
    // find the prev & next in the current set
    // store a node with "prev new next"
    // store a node with "prev" marked as begin (if !E)
    // store a node with "next" marked as end (if !E)
    
    (void)rtype;
    
    for(int chain_index = 0; chain_index < dc->chains_count; ++chain_index)
    {
        void *chain = dc->chains[chain_index];
        
        // need to know if it's under delegation
        
        //
#ifdef DEBUG
        log_debug("NEW NODE %{dnsname} (0)", fqdn);
#endif
        
        void *chain_node = dc->chain->node_new(fqdn, chain);

        ptr_node *node = ptr_set_avl_insert(&dc->chain_diff, chain_node);
        
        // TODO: if chain is empty, ignore remove and discard most intelligence
        
        if(!dc->chain->isempty(chain))
        {
            u8 or_mask = (!dc->chain_being_deleted[chain_index])?asked_or_mask:DNSSEC_CHAIN_DELETE;

            if(node->value == NULL)
            {
                node->value = chain_node;

                // create a node for the prev & next

                void *chain_begin = dc->chain->node_prev(chain_node);
                
                // zone_diff_add_fqdn(dc->diff, node->fqdn, rr_label);
                
                yassert(chain_begin != NULL);
                ptr_node *node_prev = ptr_set_avl_insert(&dc->chain_diff, chain_begin);
                if(node_prev->value == NULL)
                {
                    node_prev->value = chain_begin;
                }
                else
                {
                    dc->chain->node_merge(node_prev->value, chain_begin);
                }

                void *chain_end = dc->chain->node_next(chain_node);
                yassert(chain_end != NULL);
                ptr_node *node_next = ptr_set_avl_insert(&dc->chain_diff, chain_end);
                if(node_next->value == NULL)
                {
                    node_next->value = chain_end;
                }
                else
                {
                    dc->chain->node_merge(node_next->value, chain_end);
                }
            }
            else
            {
                // node exists already ...

                dc->chain->state_set(node->value, dc->chain->state_get(node->value) & ~(DNSSEC_CHAIN_BEGIN|DNSSEC_CHAIN_END));

                dc->chain->node_delete(chain_node);
            }

            if(or_mask != 0)
            {
                dc->chain->state_set(node->value, dc->chain->state_get(node->value) | or_mask);
            }
        }
        else
        {
            // instead of the doing diff computations the chain will be fully created
            node->value = chain_node;
        }
    }
}

static void dnssec_chain_add_node_neighbours(dnssec_chain *dc, const zone_diff_fqdn *diff_fqdn, void *chain_node, int chain_index)
{

    void *chain_begin = dc->chain->node_prev(chain_node);
    yassert(chain_begin != NULL);
#ifdef DEBUG
    format_writer chain_node_prev_fw;
    dc->chain->format_writer_init(chain_node, &chain_node_prev_fw);
#endif
    ptr_node *node_prev = ptr_set_avl_insert(&dc->chain_diff, chain_begin);
    if(node_prev->value == NULL)
    {
        node_prev->value = chain_begin;
#ifdef DEBUG
        log_debug("dnssec-chain: %{dnsname}: chain[%i]: previous node is %w", diff_fqdn->fqdn, chain_index, &chain_node_prev_fw);
#endif
    }
    else
    {
#ifdef DEBUG
        log_debug("dnssec-chain: %{dnsname}: chain[%i]: previous node %w already in chain, merging", diff_fqdn->fqdn, chain_index, &chain_node_prev_fw);
#endif
        dc->chain->node_merge(node_prev->value, chain_begin);
    }

    void *chain_end = dc->chain->node_next(chain_node);
    yassert(chain_end != NULL);
#ifdef DEBUG
    format_writer chain_node_next_fw;
    dc->chain->format_writer_init(chain_node, &chain_node_next_fw);
#endif
    ptr_node *node_next = ptr_set_avl_insert(&dc->chain_diff, chain_end);
    if(node_next->value == NULL)
    {
#ifdef DEBUG
        log_debug("dnssec-chain: %{dnsname}: chain[%i]: next node is %w", diff_fqdn->fqdn, chain_index, &chain_node_next_fw);
#endif
        node_next->value = chain_end;
    }
    else
    {
#ifdef DEBUG
        log_debug("dnssec-chain: %{dnsname}: chain[%i]: next node %w already in chain, merging", diff_fqdn->fqdn, chain_index, &chain_node_next_fw);
#endif
        dc->chain->node_merge(node_next->value, chain_end);
    }
}

static int
dnssec_chain_add_node_from_diff_fqdn(dnssec_chain *dc, const zone_diff_fqdn *diff_fqdn, u16 rtype, u8 asked_or_mask)
{
    int ret = 0;
    // compute the hash
    // find the prev & next in the current set
    // store a node with "prev new next"
    // store a node with "prev" marked as begin (if !E)
    // store a node with "next" marked as end (if !E)
    
    (void)rtype;
    
    for(int chain_index = 0; chain_index < dc->chains_count; ++chain_index)
    {
        void *chain = dc->chains[chain_index];
        
        // need to know if it's under delegation
        
        if(asked_or_mask & DNSSEC_CHAIN_DELETE)
        {
            // IT HAD TO EXIST FIRST!
            if(!dc->chain->fqdn_was_covered(diff_fqdn))
            {
#ifdef DEBUG
                log_debug("dnssec-chain: %{dnsname}: chain[%i]: did not cover", diff_fqdn->fqdn, chain_index);
#endif
                continue;
            }

        }
        else
        {
            if(!dc->chain->fqdn_is_covered(diff_fqdn))
            {
#ifdef DEBUG
                log_debug("dnssec-chain: %{dnsname}: chain[%i]: does not covers", diff_fqdn->fqdn, chain_index);
#endif
                continue;
            }
        }
        
#ifdef DEBUG
        log_debug("dnssec-chain: %{dnsname}: chain[%i]: covers", diff_fqdn->fqdn, chain_index);
#endif
        
        //
        
#ifdef DEBUG
        log_debug("NEW NODE %{dnsname} (1)", diff_fqdn->fqdn);
#endif
      
        void *chain_node = dc->chain->node_new(diff_fqdn->fqdn, chain);
        
#ifdef DEBUG
        format_writer chain_node_fw;
        dc->chain->format_writer_init(chain_node, &chain_node_fw);
        log_debug("dnssec-chain: %{dnsname}: chain[%i]: node is %w", diff_fqdn->fqdn, chain_index, &chain_node_fw);
#endif

        ptr_node *node = ptr_set_avl_insert(&dc->chain_diff, chain_node);
        
        if(!dc->chain->isempty(chain))
        {
            u8 or_mask = (!dc->chain_being_deleted[chain_index])?asked_or_mask:DNSSEC_CHAIN_DELETE;

            if(node->value == NULL)
            {
#ifdef DEBUG
                log_debug("dnssec-chain: %{dnsname}: chain[%i]: node %w is new, getting both neighbours", diff_fqdn->fqdn, chain_index, &chain_node_fw);
#endif
                node->value = chain_node;

                // create a node for the prev & next

                dnssec_chain_add_node_neighbours(dc, diff_fqdn, chain_node, chain_index);
            }
            else
            {
#ifdef DEBUG
                log_debug("dnssec-chain: %{dnsname}: chain[%i]: node %w already exists", diff_fqdn->fqdn, chain_index, &chain_node_fw);
#endif
                // node exists already ...
                dnssec_chain_add_node_neighbours(dc, diff_fqdn, chain_node, chain_index);
                dc->chain->node_merge(node->value, chain_node);
                dc->chain->state_set(node->value, dc->chain->state_get(node->value) & ~(DNSSEC_CHAIN_BEGIN|DNSSEC_CHAIN_END));
            }
            
            // check if any of the RRSET of the label have been added or removed

            //
            u8 prev_state = dc->chain->state_get(node->value);
            
            if(prev_state & DNSSEC_CHAIN_EXISTS)
            {
                bool type_map_changed = zone_diff_fqdn_type_map_changed(diff_fqdn);

                if(type_map_changed)
                {
                    or_mask |= DNSSEC_CHAIN_REMAP;
                }
            }
            
            if(or_mask != 0)
            {
                dc->chain->state_set(node->value, prev_state | or_mask);
            }
            if(((prev_state & DNSSEC_CHAIN_EXISTS) == 0) || ((or_mask & (DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_REMAP)) != 0))
            {
                ++ret;
            }
        }
        else
        {
#ifdef DEBUG
            log_debug("dnssec-chain: %{dnsname}: chain[%i] was empty", diff_fqdn->fqdn, chain_index);
#endif
            // instead of the doing diff computations the chain will be fully created
            node->value = chain_node;
            
            ++ret;
        }
    }
    
    return ret;
}

/**
 * Adds a node to the chain.
 * 
 * @param dc
 * @param fqdn
 * @param rtype
 */

void dnssec_chain_add(dnssec_chain *dc, const u8 *fqdn, u16 rtype)
{
    dnssec_chain_add_node(dc, fqdn, rtype, DNSSEC_CHAIN_ADD);
    // It used to be :
    // dnssec_chain_add_node(dc, fqdn, rtype, 0);
}

int dnssec_chain_add_from_diff_fqdn(dnssec_chain *dc, const zone_diff_fqdn* diff_fqdn, u16 rtype)
{
    int ret = dnssec_chain_add_node_from_diff_fqdn(dc, diff_fqdn, rtype, DNSSEC_CHAIN_ADD);
    return ret;
}

/**
 * Removes a node from the chain.
 * 
 * @param dc
 * @param fqdn
 * @param rtype
 */

void dnssec_chain_del(dnssec_chain *dc, const u8 *fqdn, u16 rtype)
{
    dnssec_chain_add_node(dc, fqdn, rtype, DNSSEC_CHAIN_DELETE);
}

int dnssec_chain_del_from_diff_fqdn(dnssec_chain *dc, const zone_diff_fqdn* diff_fqdn, u16 rtype)
{
    int ret = dnssec_chain_add_node_from_diff_fqdn(dc, diff_fqdn, rtype, DNSSEC_CHAIN_DELETE);
    return ret;
}

static void dnssec_chain_store_diff_publish_chain_node(dnssec_chain *dc, zone_diff *diff, ptr_vector *keys,
        void *chain, void *prev, void *prev_next, ptr_vector *add)
{
    ya_result ret;
    s32 from_offset = ptr_vector_size(add);
                        
    dc->chain->publish_add(chain, prev, prev_next, diff, add);

    // and its signature(s)

    s32 to_offset = ptr_vector_size(add);
    // make a ptr_vector that's a view of the last added records
    ptr_vector rrset = {&add->data[from_offset], 0, to_offset - from_offset};
    
    struct resource_record_view rrv = {NULL, &zone_diff_label_rr_rrv_vtbl};
    u16 rrset_type = TYPE_NONE;
    for(int i = 0; i <= ptr_vector_last_index(&rrset); ++i)
    {
        void* data = ptr_vector_get(&rrset, i);
        const void *fqdn = rrv.vtbl->get_fqdn(rrv.data, data);
        u16 rtype = rrv.vtbl->get_type(rrv.data, data);
        u16 rclass = rrv.vtbl->get_class(rrv.data, data);
        s32 ttl = rrv.vtbl->get_ttl(rrv.data, data);
        u16 rdata_size = rrv.vtbl->get_rdata_size(rrv.data, data);
        const void *rdata = rrv.vtbl->get_rdata(rrv.data, data);
        
        rrset_type = rtype;
        
        rdata_desc rdt = {rtype, rdata_size, rdata};
        log_debug("update: %{dnsname}: will sign chain record #%i: %{dnsname} %i %{dnsclass} %{typerdatadesc}",
                diff->origin, i, fqdn, ttl, &rclass, &rdt);
    }

    bool canonize = TRUE;

    for(int j = 0; j <= ptr_vector_last_index(keys); ++j)
    {
        const dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, j);

        zone_diff_label_rr *rrsig_rr = NULL;

        // rrset_to_sign;
        if(ISOK(ret = dnskey_signature_rrset_sign_with_key(key, &rrset, canonize, &rrv, (void**)&rrsig_rr)))
        {
            canonize = FALSE;

            // add the key to the add set

            rdata_desc rdt = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
            log_debug("update: %{dnsname}: signed chain rrset %{dnstype} with key %03i %05i: %{dnsname} %i %{dnsclass} %{typerdatadesc}",
                    diff->origin, &rrset_type, dnssec_key_get_algorithm(key), dnssec_key_get_tag_const(key),
                    rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr->rclass, &rdt
                    );

            rrsig_rr->state |= ZONE_DIFF_VOLATILE;
            ptr_vector_append(add, rrsig_rr);
            
            // since we are mapping inside the array and the array could have been replaced by a bigger one ...
            rrset.data = &add->data[from_offset];
        }
#ifdef DEBUG
        else
        {
            log_debug("update: %{dnsname}: didn not sign rrset %{dnstype} with key %03i %05i: %r",
                diff->origin, &rrset_type, dnssec_key_get_algorithm(key), dnssec_key_get_tag_const(key), ret);
        }
#endif
    }
}

/**
 * Computes the changes of the chain into a del and an add records vector.
 * 
 * @param diff
 * @param origin
 * @param nttl
 */

void dnssec_chain_store_diff(dnssec_chain *dc, zone_diff *diff, ptr_vector *keys, ptr_vector *del, ptr_vector *add)
{
    // simplify then apply the changes
    
    // put all the nodes in an array
    
    ptr_vector nodes;

    ptr_vector_init(&nodes);
    
    // for every chain
    
    for(int chain_index = 0; chain_index < dc->chains_count; ++chain_index)
    {
        void *chain = dc->chains[chain_index];
        
        ptr_vector_clear(&nodes);

        ptr_set_avl_iterator iter;
        ptr_set_avl_iterator_init(&dc->chain_diff, &iter);
        while(ptr_set_avl_iterator_hasnext(&iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
            yassert(node->value != NULL);
            ptr_vector_append(&nodes, node->value);
        }

        // look in a circular pattern for all the nodes that have the "delete" status
        
        log_debug("update: %{dnsname}: %i nodes in dnssec chain #%i", diff->origin, ptr_vector_size(&nodes), chain_index);
        
        if(ptr_vector_size(&nodes) == 0)
        {
            continue;
        }
        
#ifdef DEBUG
        for(int i = 0; i <= ptr_vector_last_index(&nodes); ++i)
        {
            void *node = ptr_vector_get_mod(&nodes, i);
            void *next = (i < ptr_vector_last_index(&nodes))?ptr_vector_get_mod(&nodes, i + 1) : NULL;
            u8 state = dc->chain->state_get(node);
            
            format_writer temp_fw_0 = {zone_diff_chain_state_format, &state};
            log_debug1("update: %{dnsname}: %3i: %02x %w", diff->origin, i, state, &temp_fw_0);
            dc->chain->publish_log(node, next);
        }
#endif
        
        int first_begin = -1;
        int last_end;

        bool whole_chain = FALSE; // does the operation covers the whole chain
        
        if(!dc->chain->isempty(chain))
        {
            // chain is not empty but may be too small (1 item)
            
            if(ptr_vector_last_index(&nodes) > 0) // if true, then it has more than one item
            {
                int exists = 0;
                int begin = 0;
                int end = 0;
                int both = 0;
                
                bool prev_does_not_alter_the_chain = FALSE;
                
                {
                    void *node = ptr_vector_last(&nodes);
                    u8 state = dc->chain->state_get(node);
  
                    if(state & DNSSEC_CHAIN_EXISTS)
                    {
                        ++exists;
                        // if the node exists and is not deleted
                        prev_does_not_alter_the_chain = ((state & (DNSSEC_CHAIN_ADD|DNSSEC_CHAIN_DELETE)) != DNSSEC_CHAIN_DELETE);
                    }
                    else // the node did not exist (and thus will be added, as there is no other reason being here)
                    {
                        prev_does_not_alter_the_chain = FALSE;
                    }
                }
                
                // this loop marks nodes with the next field changed
                
                for(int i = 0; i <= ptr_vector_last_index(&nodes); ++i)
                {
                    void *node = ptr_vector_get(&nodes, i);
                    u8 state = dc->chain->state_get(node);
                    
                    if(state & DNSSEC_CHAIN_BEGIN) // the node exists already in the chain and is the start of an update
                    {
                        first_begin = i;
                        ++begin;
                    }
                    
                    if(state & DNSSEC_CHAIN_END) // the node exists already in the chain and is the end of an update
                    {
                        ++end;
                        if(state & DNSSEC_CHAIN_BEGIN) // if it's also the start of an update, some merging will happen
                        {
                            ++both;
                        }
                    }
                    
                    bool does_not_alter_the_chain; // as in : the label is not new and is not deleted
                    
                    if(state & DNSSEC_CHAIN_EXISTS)
                    {
                        ++exists;
                        // if the node exists and is not deleted
                        does_not_alter_the_chain = ((state & (DNSSEC_CHAIN_ADD|DNSSEC_CHAIN_DELETE)) != DNSSEC_CHAIN_DELETE);
                    }
                    else // the node did not exist (and thus will be added, as there is no other reason being here)
                    {
                        does_not_alter_the_chain = FALSE;
                    }
                    
                    if(!does_not_alter_the_chain && prev_does_not_alter_the_chain) // since this one is added and not the previous one, the previous one has to be
                    {                                          // updated
                        void *prev_node = ptr_vector_get_mod(&nodes, i - 1);
                        u8 prev_state = dc->chain->state_get(prev_node);
                        dc->chain->state_set(prev_node, prev_state | (DNSSEC_CHAIN_ADD|DNSSEC_CHAIN_DELETE));
                    }
                    
                    prev_does_not_alter_the_chain = does_not_alter_the_chain;
                }
                
                int chain_loops = 0;
                
                if(begin + end == 0)
                {
                    // the chain is looping on itself, take the first exist and mark it as begin & end
                    
                    for(int i = 0; i <= ptr_vector_last_index(&nodes); ++i)
                    {
                        void *node = ptr_vector_get(&nodes, i);
                        u8 state = dc->chain->state_get(node);
                        u8 masked_state = state & (DNSSEC_CHAIN_EXISTS|DNSSEC_CHAIN_ADD|DNSSEC_CHAIN_DELETE);
                        if((masked_state == DNSSEC_CHAIN_EXISTS) ||
                           (masked_state == (DNSSEC_CHAIN_EXISTS | DNSSEC_CHAIN_ADD)) ||
                           (masked_state == (DNSSEC_CHAIN_EXISTS | DNSSEC_CHAIN_ADD | DNSSEC_CHAIN_DELETE)))
                        {
                            dc->chain->state_set(node, state | (DNSSEC_CHAIN_BEGIN|DNSSEC_CHAIN_END));
                            first_begin = i;
                            chain_loops = 1;
                            break;
                        }
                    }
                }
                else if((begin == 1) && (end == 1) && (both == 1))
                {
                    whole_chain = TRUE;
                }
                
                if(first_begin < 0)
                {
                    // no begin/end have been found : empty chain ?
                    
                    if(exists == 1) // only one item exists : only one node in the current chain
                    {
                        // one item exists : this is the case where the SOA node is in there, but nothing else
                        //                   this single existing node will be marked as BEGIN+END+DELETE+ADD
                        for(int i = 0; i <= ptr_vector_last_index(&nodes); ++i)
                        {
                            void *node = ptr_vector_get(&nodes, i);
                            u8 state = dc->chain->state_get(node);
                            if(state & DNSSEC_CHAIN_EXISTS)
                            {
                                u8 state_or = (ptr_vector_last_index(&nodes) > 0)?DNSSEC_CHAIN_BEGIN|DNSSEC_CHAIN_END|DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_ADD:DNSSEC_CHAIN_BEGIN|DNSSEC_CHAIN_END;
                                dc->chain->state_set(node, state|state_or);
                                //whole_chain = TRUE;
                                first_begin = i;
                                chain_loops = 1;
                                //last_end = first_begin + ptr_vector_last_index(&nodes) + 1;
                                break;
                            }
                        }
                        
                        abort();
                    }
                    else
                    {
                        //last_end = first_begin + ptr_vector_last_index(&nodes);
                    }
                }
                else
                {
                    //last_end = first_begin + ptr_vector_last_index(&nodes);
                }
                
                last_end = first_begin + ptr_vector_last_index(&nodes) + chain_loops;
            }
            else // there is only one item in the chain update
            {
                log_debug("update: %{dnsname}: chain #%i update has only one item", diff->origin, chain_index);
                
                first_begin = 0;
                last_end = ptr_vector_last_index(&nodes);
            }
        }
        else // chain is empty, we add everything
        {
            log_debug("update: %{dnsname}: chain #%i is empty", diff->origin, chain_index);
            
            first_begin = 0;
            last_end = ptr_vector_last_index(&nodes);
        }
        
        //yassert(dc->chain->isempty(chain) || (first_begin >= 0) || ((first_begin == 0) && (last_end == 0)));
        
#ifdef DEBUG
        for(int i = first_begin; i <= last_end; ++i)
        {
            void *node = ptr_vector_get_mod(&nodes, i);
            u8 state = dc->chain->state_get(node);
            void *next = ((state & (DNSSEC_CHAIN_BEGIN|DNSSEC_CHAIN_END)) != DNSSEC_CHAIN_END) ? ptr_vector_get_mod(&nodes, i + 1) : NULL;
            
            format_writer temp_fw_0 = {zone_diff_chain_state_format, &state};
            log_debug1("update: %{dnsname}: %3i: %02x %w: %p -> %p", diff->origin, i, state, &temp_fw_0, node, next);
            dc->chain->publish_log(node, next);
        }
#endif
        
        if(dc->chain->isempty(chain) || whole_chain || ((first_begin == 0) && (last_end == 0)))
        {
            // we are processing a new/whole chain, or the chain chain is made of one record
            
            for(int i = first_begin; i <= last_end; ++i)
            {
                int j = i + 1;
                void *node = ptr_vector_get_mod(&nodes, i);
                void *node_next = ptr_vector_get_mod(&nodes, j);
                u8 state = dc->chain->state_get(node);
                
                if(state & (DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_REMAP))
                {
#ifdef DEBUG
                    u8 next_state = dc->chain->state_get(node_next);
                    yassert((next_state & DNSSEC_CHAIN_EXISTS) != 0);
#endif
                    dc->chain->publish_delete(chain, node, node_next, diff, del);
                }
                
                if(state & DNSSEC_CHAIN_ADD)
                {
                    dnssec_chain_store_diff_publish_chain_node(dc, diff, keys, chain, node, node_next, add);
                }
            }
                
            continue;
        }
        
        yassert(first_begin != last_end);

        void *next_did_exist_node = NULL;
        void *next_will_exist_node = NULL;
        int next_did_exist_index = -1;
        int next_will_exist_index = -1;
        
        for(int i = first_begin; i < last_end; ++i)
        {
            void *node = ptr_vector_get_mod(&nodes, i);
            u8 state = dc->chain->state_get(node);
            
            if(state & (DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_REMAP))
            {
                yassert(state & DNSSEC_CHAIN_EXISTS); // trips on an empty terminal : the node to delete does not exists.
                
                if(next_did_exist_index <= i)
                {
                    for(int j = i + 1; j <= last_end; ++j)
                    {
                        void *next_node = ptr_vector_get_mod(&nodes, j);
                        u8 next_state = dc->chain->state_get(next_node);
                        if(next_state & DNSSEC_CHAIN_EXISTS)
                        {
                            next_did_exist_node = next_node;
                            next_did_exist_index = j;
                            break;
                        }
                    }
                }
                
                yassert(next_did_exist_index > i);
                
                dc->chain->publish_delete(chain, node, next_did_exist_node, diff, del);
            }
            
            switch(state & (DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_ADD|DNSSEC_CHAIN_EXISTS|DNSSEC_CHAIN_REMAP))
            {
                case DNSSEC_CHAIN_ADD:
                case DNSSEC_CHAIN_ADD|DNSSEC_CHAIN_REMAP:
                case DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_ADD|DNSSEC_CHAIN_EXISTS:
                case DNSSEC_CHAIN_ADD|DNSSEC_CHAIN_EXISTS|DNSSEC_CHAIN_REMAP:
                case DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_ADD|DNSSEC_CHAIN_EXISTS|DNSSEC_CHAIN_REMAP:
                {
                    if(next_will_exist_index <= i)
                    {
                        for(int j = i + 1; j <= last_end; ++j)
                        {
                            void *next_node = ptr_vector_get_mod(&nodes, j);
                            u8 next_state = dc->chain->state_get(next_node);
                            if((next_state & DNSSEC_CHAIN_ADD) || ((next_state & (DNSSEC_CHAIN_DELETE | DNSSEC_CHAIN_EXISTS)) == DNSSEC_CHAIN_EXISTS))
                            {
                                next_will_exist_node = next_node;
                                next_will_exist_index = j;
                                break;
                            }
                        }
                    }
                    
                    yassert(next_will_exist_index > i);
                    
                    dnssec_chain_store_diff_publish_chain_node(dc, diff, keys, chain, node, next_will_exist_node, add);
                    
                    break;
                }
                default:
                {
                    break;
                }
            }
        } // for all items in [begin;end[
    }
    
    ptr_vector_destroy(&nodes);
}

/**
 * Releases the memory used by a chain
 */

void dnssec_chain_finalise(dnssec_chain *dc)
{
    ptr_set_avl_callback_and_destroy(&dc->chain_diff, dc->chain->ptr_set_node_delete_callback);
}

static int zone_diff_label_rr_compare(const void *node_a, const void *node_b)
{
    const zone_diff_label_rr *a = (const zone_diff_label_rr*)node_a;
    const zone_diff_label_rr *b = (const zone_diff_label_rr*)node_b;
    
    int d;
    
    d = a->rclass;
    d -= b->rclass;
    
    if(d == 0)
    {
        d = a->rtype;
        d -= b->rtype;
        
        if(d == 0)
        {
            d = dnsname_getdepth(a->fqdn);
            d -= dnsname_getdepth(b->fqdn);
            
            if(d == 0)
            {
                d = dnsname_compare(a->fqdn, b->fqdn);

                if(d == 0)
                {
                    u16 len = MIN(a->rdata_size, b->rdata_size);
                    d = memcmp(a->rdata, b->rdata, len);

                    if(d == 0)
                    {
                        d = a->rdata_size;
                        d -= b->rdata_size;
                    }
                }
            }
        }
        else
        {
            // SOA have to be first
            
            if(a->rtype == TYPE_SOA)
            {
                d = -1;
            }
            else
            {
                d = 1;
            }
        }
    }
    
    return d;
}

zone_diff_label_rr *
zone_diff_label_rr_new(const u8 *fqdn, u16 rtype, u16 rclass, s32 ttl, void *rdata, u16 rdata_size, bool copy)
{
    zone_diff_label_rr *rr;
    ZALLOC_OBJECT_OR_DIE(rr, zone_diff_label_rr, ZDFFLABL_TAG);
    rr->fqdn = dnsname_zdup(fqdn);
    rr->ttl = ttl;
    rr->rtype = rtype;
    rr->rclass = rclass;
    rr->rdata_size = rdata_size;
    if(copy)
    {
        ZALLOC_ARRAY_OR_DIE(u8*, rr->rdata, rdata_size, ZDFFLBRR_TAG);
        memcpy(rr->rdata, rdata, rdata_size);
        rr->state = ZONE_DIFF_RDATA_OWNED;
    }
    else
    {
        rr->rdata = rdata;
        rr->state = 0;
    }
    return rr;
}

static void zone_diff_label_rr_delete(zone_diff_label_rr *rr)
{

    dnsname_zfree(rr->fqdn);
    
    if(rr->state & ZONE_DIFF_RDATA_OWNED)
    {
#ifdef DEBUG
        memset(rr->rdata, 0xff, rr->rdata_size);
#endif
        ZFREE_ARRAY(rr->rdata, rr->rdata_size);
    }
#ifdef DEBUG
    memset(rr, 0xff, sizeof(zone_diff_label_rr));
#endif
    ZFREE(rr, zone_diff_label_rr);
}

static void zone_diff_label_rr_vector_clear(ptr_vector *records)
{
    for(int i = 0; i <= ptr_vector_last_index(records); ++i)
    {
        zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(records, i);
        if((rr->state & ZONE_DIFF_VOLATILE) != 0)
        {
            zone_diff_label_rr_delete(rr);
        }
    }
    ptr_vector_clear(records);
}

static void zone_diff_label_rr_delete_void(ptr_node *node)
{
    zone_diff_label_rr *rr = (zone_diff_label_rr*)node->value;
#ifdef DEBUG
    log_debug7("update: %{dnsname}: deleting %{dnstype} structure", rr->fqdn, &rr->rtype);
#endif
    zone_diff_label_rr_delete(rr);
}

zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_set_new(u16 rtype)
{
    zone_diff_fqdn_rr_set *rr_set;
    ZALLOC_OBJECT_OR_DIE(rr_set, zone_diff_fqdn_rr_set, ZDFFRRST_TAG);
    ptr_set_avl_init(&rr_set->rr);
    rr_set->rr.compare = zone_diff_label_rr_compare;
    rr_set->org_ttl = -1;
    rr_set->new_ttl = -1;
    rr_set->rtype = rtype;
    rr_set->rclass = CLASS_IN;
    return rr_set;
}

static void zone_diff_fqdn_rr_set_delete(zone_diff_fqdn_rr_set *rr_set)
{
    ptr_set_avl_callback_and_destroy(&rr_set->rr, zone_diff_label_rr_delete_void);
    ZFREE(rr_set, zone_diff_fqdn_rr_set);
}

static zone_diff_label_rr *zone_diff_fqdn_rr_set_add(zone_diff_fqdn_rr_set *rr_set, zone_diff_label_rr *rr)
{
    ptr_node *node = ptr_set_avl_insert(&rr_set->rr, rr);
    
    if(node->value == NULL)
    {
        node->value = rr;
    }
    else
    {
        zone_diff_label_rr_delete(rr);
        rr = (zone_diff_label_rr*)node->value;
    }
    
    return rr;
}

//

static zone_diff_fqdn *zone_diff_fqdn_new(const u8 *fqdn)
{
    zone_diff_fqdn *zdl;
    ZALLOC_OBJECT_OR_DIE(zdl, zone_diff_fqdn, ZDFFFQDN_TAG);
    memset(zdl, 0, sizeof(zone_diff_fqdn));
    u32_set_avl_init(&zdl->rrset);
    zdl->fqdn = dnsname_zdup(fqdn);
    //zdl->type_map_changed = FALSE;
    return zdl;
}

static void zone_diff_fqdn_delete(zone_diff_fqdn *zdl)
{
    u32_set_avl_iterator iter;
    u32_set_avl_iterator_init(&zdl->rrset, &iter);
    while(u32_set_avl_iterator_hasnext(&iter))
    {
        u32_node *node = u32_set_avl_iterator_next_node(&iter);
        
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)node->value;
        zone_diff_fqdn_rr_set_delete(rrset);
    }
#ifdef DEBUG
    log_debug1("update: %{dnsname}: deleting diff fqdn", zdl->fqdn);
#endif
    dnsname_zfree(zdl->fqdn);
    ZFREE(zdl, zone_diff_fqdn);
}

static void zone_diff_fqdn_delete_void(ptr_node *node)
{
    zone_diff_fqdn *zdl = (zone_diff_fqdn*)node->value;
    zone_diff_fqdn_delete(zdl);
}

static zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_set_get(zone_diff_fqdn *diff_fqdn, u16 rtype)
{
    u32_node *node = u32_set_avl_insert(&diff_fqdn->rrset, rtype);
    if(node->value == NULL)
    {
        node->value = zone_diff_fqdn_rr_set_new(rtype);
    }
    return (zone_diff_fqdn_rr_set*)node->value;
}

/**
 * Returns the local copy of the specified RRSET
 * 
 * @param diff_fqdn
 * @param rtype
 * @return 
 */

zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_get(zone_diff_fqdn *diff_fqdn, u16 rtype)
{
    u32_node *node = u32_set_avl_insert(&diff_fqdn->rrset, rtype);
    
    return (zone_diff_fqdn_rr_set*)node->value;
}

/**
 * Deletes an RRSET if it's empty.
 * 
 * @param diff_fqdn
 * @param rtype
 */

void
zone_diff_fqdn_rr_clear(zone_diff_fqdn *diff_fqdn, u16 rtype)
{
    u32_node *node = u32_set_avl_insert(&diff_fqdn->rrset, rtype);
    if(node != NULL)
    {
        if(node->value == NULL)
        {
            u32_set_avl_delete(&diff_fqdn->rrset, rtype);
        }
    }
}

/**
 * Returns TRUE iff an rrset as been added or removed from the label.
 * Stressing out this concerns RRSET as a whole.
 * 
 * @param diff_fqdn
 * @return 
 */

bool zone_diff_fqdn_type_map_changed(const zone_diff_fqdn *diff_fqdn)
{
    u32_set_avl_iterator iter;
    ptr_set_avl_iterator rr_iter;
    
    u32_set_avl_iterator_init(&diff_fqdn->rrset, &iter);
    while(u32_set_avl_iterator_hasnext(&iter))
    {
        u32_node *node = u32_set_avl_iterator_next_node(&iter);
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)node->value;
        if(rrset != NULL)
        {
            ptr_set_avl_iterator_init(&rrset->rr, &rr_iter);
            u8 rr_state = 0;
            while(ptr_set_avl_iterator_hasnext(&rr_iter))
            {
                ptr_node *rr_node = ptr_set_avl_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->key;

                if(rr->state == 0)
                {
                    // previously existing record : no change on this set
                    rr_state = 0;
                    break;
                }

                rr_state |= rr->state & (ZONE_DIFF_REMOVE|ZONE_DIFF_ADD);
            }
            if((rr_state != 0) && ((rr_state & (ZONE_DIFF_REMOVE|ZONE_DIFF_ADD)) != (ZONE_DIFF_REMOVE|ZONE_DIFF_ADD)))
            {
                // this set is completely added or completely removed
                return TRUE;
            }
        }
    }
    
    return FALSE;
}

/**
 * Initialises a zone diff
 * 
 * @param diff
 * @param origin
 * @param nttl
 */

void zone_diff_init(zone_diff *diff, const u8 *origin, u16 nttl, bool rrsig_push_allowed)
{
    ptr_set_avl_init(&diff->fqdn);
    ptr_set_avl_init(&diff->root.sub);
    diff->root.sub.compare = ptr_set_dnslabel_node_compare;
    diff->fqdn.compare = ptr_set_fqdn_node_compare;
    diff->origin = origin;
    diff->nttl = nttl;
    diff->rrsig_update_allowed = rrsig_push_allowed;
}

static zone_diff_label_tree*
zone_diff_label_tree_add_fqdn(zone_diff *diff, const u8 *fqdn)
{
#ifdef DEBUG
    log_debug("zone-diff: %{dnsname}: label tree add %{dnsname}",
            diff->origin, fqdn);
#endif
    
    if(fqdn[0] != 0)
    {
        zone_diff_label_tree *label_node;
        ptr_node *label_tree_node;
        const u8 *parent_fqdn = fqdn + fqdn[0] + 1;
        zone_diff_label_tree *parent = zone_diff_label_tree_add_fqdn(diff, parent_fqdn);
        
        label_tree_node = ptr_set_avl_insert(&parent->sub, (u8*)fqdn);
        
        if(label_tree_node->value != NULL)
        {
            label_node = (zone_diff_label_tree*)label_tree_node->value;
        }
        else
        {
            ZALLOC_OBJECT_OR_DIE(label_node, zone_diff_label_tree, GENERIC_TAG);
            label_node->label = fqdn;
            label_node->diff_fqdn = (zone_diff_fqdn*)zone_diff_get_fqdn(diff, fqdn);
            ptr_set_avl_init(&label_node->sub);
            label_node->sub.compare = ptr_set_dnslabel_node_compare;
            label_tree_node->value = label_node;
        }
        
        return label_node;
    }
    else
    {
        return &diff->root;
    }
}

static void zone_diff_label_tree_destroy_callback(ptr_node* node)
{
    zone_diff_label_tree* dlt = (zone_diff_label_tree*)node->value;
    if(dlt != NULL)
    {
        if(!ptr_set_avl_isempty(&dlt->sub))
        {
            ptr_set_avl_callback_and_destroy(&dlt->sub, zone_diff_label_tree_destroy_callback);
        }
        ZFREE_OBJECT(dlt);
    }
}

static void zone_diff_label_tree_destroy(zone_diff *diff)
{
    ptr_set_avl_callback_and_destroy(&diff->root.sub, zone_diff_label_tree_destroy_callback);
}

static zone_diff_label_tree*
zone_diff_fqdn_label_find(zone_diff_label_tree* parent, const u8 *fqdn)
{
    if(fqdn[0] != 0)
    {
        parent = zone_diff_fqdn_label_find(parent, fqdn + fqdn[0] + 1);
        if(parent != NULL)
        {
            ptr_node *node = ptr_set_avl_find(&parent->sub, fqdn);
            parent = (zone_diff_label_tree*)node->value;
        }
    }
    return parent;
}

bool
zone_diff_fqdn_has_children(zone_diff *diff, const u8 *fqdn)
{
    zone_diff_label_tree* parent = &diff->root;
    parent = zone_diff_fqdn_label_find(parent, fqdn);
    return parent != NULL;
}

//#define ZONE_DIFF_FQDN_LABEL_STATE_RECORDS_EXISTED 1
//#define ZONE_DIFF_FQDN_LABEL_STATE_RECORDS_ADDED   2 
//#define ZONE_DIFF_FQDN_LABEL_STATE_RECORDS_EXISTS  3
#define ZONE_DIFF_FQDN_LABEL_STATE_NONEMPTY 2
#define ZONE_DIFF_FQDN_LABEL_STATE_CHILDREN 1

static u8
zone_diff_fqdn_children_state_find(zone_diff_label_tree* parent)
{
    u8 ret = (parent->diff_fqdn != NULL)?parent->diff_fqdn->is_apex:0;
    
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&parent->sub, &iter);
    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node* node = ptr_set_avl_iterator_next_node(&iter);
        
        zone_diff_label_tree* fqdn_node = (zone_diff_label_tree*)node->value;
        
        /*
        if(fqdn_node->diff_fqdn->will_be_non_empty)
        {
            // ret |= ZONE_DIFF_FQDN_LABEL_STATE_NONEMPTY;
        }
        */
        if(fqdn_node->diff_fqdn != NULL)
        {
            if(!fqdn_node->diff_fqdn->children_flags_set)
            {
                if(!ptr_set_avl_isempty(&fqdn_node->sub))
                {
                    if(zone_diff_fqdn_children_state_find(fqdn_node) != 0)
                    {
                        // ret |= ZONE_DIFF_FQDN_LABEL_STATE_CHILDREN;

                        fqdn_node->diff_fqdn->will_have_children = 1;
                    }
                }

                fqdn_node->diff_fqdn->children_flags_set = 1;
            }
            
            ret |= fqdn_node->diff_fqdn->will_be_non_empty | fqdn_node->diff_fqdn->will_have_children;
        }
        else
        {
            if(!ptr_set_avl_isempty(&fqdn_node->sub))
            {
                if(zone_diff_fqdn_children_state_find(fqdn_node) != 0)
                {
                    ret |= ZONE_DIFF_FQDN_LABEL_STATE_CHILDREN;
                }
            }
        }
    }
    
    return ret;
}

u8
zone_diff_fqdn_children_state(zone_diff *diff, const u8 *fqdn)
{
    zone_diff_label_tree* fqdn_node = zone_diff_fqdn_label_find(&diff->root, fqdn);
    
    if(fqdn_node != NULL)
    {       
/*
        zone_diff_fqdn_children_state_parm parms;
        int fqdn_len = dnsname_len(fqdn);
        parms.fqdn = &parms.fqdn_storage[256 - fqdn_len];
        memcpy(parms.fqdn, fqdn, fqdn_len);
*/                
        // if node has sub, set it
        // for all sub
        //      if sub has all records removed, set it
        //      if sub has records added, set it
        //      if +- are both set, stop seeking (all needed answers are ready)
        //      if sub has sub, go deeper

        zone_diff_fqdn_children_state_find(fqdn_node);
    }
    
    return 0;
}

/**
 * Finalises a zone diff
 * 
 * @param diff
 */

void zone_diff_finalise(zone_diff *diff)
{
    log_debug1("update: %{dnsname}: deleting diff", diff->origin);
    zone_diff_label_tree_destroy(diff);
    ptr_set_avl_callback_and_destroy(&diff->fqdn, zone_diff_fqdn_delete_void);
}

/**
 * label will be replaced ...
 * 
 * @param diff
 * @param fqdn
 * @param label
 * @return 
 */

zone_diff_fqdn*
zone_diff_add_fqdn(zone_diff *diff, const u8 *fqdn, zdb_rr_label *label)
{    
    ptr_node *node = ptr_set_avl_insert(&diff->fqdn, (u8*)fqdn);
    
    if(node->value == NULL)
    {
#ifdef DEBUG
        log_debug("update: %{dnsname} (%p) ...", fqdn, label);
#endif
    
        zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_new(fqdn);
        node->key = diff_fqdn->fqdn; // to guarantee the const
        node->value = diff_fqdn;
        
        zone_diff_label_tree *diff_fqdn_label = zone_diff_label_tree_add_fqdn(diff, diff_fqdn->fqdn);
        diff_fqdn_label->diff_fqdn = diff_fqdn;
        
        // copy all records
        if(label != NULL)
        {
            diff_fqdn->is_apex = ZDB_LABEL_ISAPEX(label);
            diff_fqdn->at_delegation = ZDB_LABEL_ATDELEGATION(label);
            diff_fqdn->under_delegation = ZDB_LABEL_UNDERDELEGATION(label);
            diff_fqdn->will_have_ds = zdb_rr_label_has_rrset(label, TYPE_DS);
            diff_fqdn->was_at_delegation = diff_fqdn->at_delegation;
            diff_fqdn->was_under_delegation = diff_fqdn->under_delegation;
            diff_fqdn->had_ds = diff_fqdn->will_have_ds;
            diff_fqdn->was_non_empty = btree_notempty(label->resource_record_set);
            diff_fqdn->had_children = dictionary_notempty(&label->sub);
            //diff_fqdn->will_be_non_empty = diff_fqdn->was_non_empty;
            diff_fqdn->will_have_children = diff_fqdn->is_apex;
            
            btree_iterator iter;
            btree_iterator_init(label->resource_record_set, &iter);

            while(btree_iterator_hasnext(&iter))
            {
                btree_node *rr_node = btree_iterator_next_node(&iter);
                u16 type = (u16)rr_node->hash;
                
#ifdef DEBUG
                log_debug("update: %{dnsname} (%p) copying %{dnstype} RRSET", fqdn, label, &type);
#endif

                zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_get(diff_fqdn, type);

                zdb_packed_ttlrdata *rr_sll = (zdb_packed_ttlrdata*)rr_node->data;
                yassert(rr_sll != NULL);

                if(rr_set->org_ttl == -1) rr_set->org_ttl = rr_sll->ttl;
                rr_set->new_ttl = rr_sll->ttl;

                do
                {                
                    zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, type, CLASS_IN, rr_sll->ttl, ZDB_PACKEDRECORD_PTR_RDATAPTR(rr_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(rr_sll), FALSE);
                    rr->state |= ZONE_DIFF_IN_ZONE;
                    /** rr = */ zone_diff_fqdn_rr_set_add(rr_set,rr);
                    rr_sll = rr_sll->next;
                }
                while(rr_sll != NULL);
            }
        }
        else
        {
#ifdef DEBUG
            log_debug("update: %{dnsname} (%p) label is not in the zone", fqdn, label);
#endif
            /*
            diff_fqdn->is_apex = FALSE;
            diff_fqdn->at_delegation = FALSE;
            diff_fqdn->under_delegation = FALSE;
            diff_fqdn->will_have_ds = FALSE;
            diff_fqdn->was_at_delegation = FALSE;
            diff_fqdn->was_under_delegation = FALSE;
            diff_fqdn->had_ds = FALSE;
            diff_fqdn->was_non_empty = FALSE;
            */
        }
    }
#ifdef DEBUG
    else
    {
        log_debug("update: %{dnsname} (%p) already known", fqdn, label);
    }
#endif
    
    return (zone_diff_fqdn*)node->value;
}

zone_diff_fqdn*
zone_diff_add_static_fqdn(zone_diff *diff, const u8 *fqdn, zdb_rr_label *label)
{ 
    zone_diff_fqdn *diff_fqdn = zone_diff_add_fqdn(diff, fqdn, label);
    diff_fqdn->will_be_non_empty = diff_fqdn->was_non_empty;
    diff_fqdn->will_have_children = diff_fqdn->will_have_children;
    diff_fqdn->will_have_ds = diff_fqdn->had_ds;
    return diff_fqdn;
}

void
zone_diff_add_fqdn_children(zone_diff *diff, const u8 *fqdn, zdb_rr_label *label)
{
    dictionary_iterator iter;
    u8 sub_fqdn[MAX_DOMAIN_LENGTH];
    dictionary_iterator_init(&label->sub, &iter);

    while(dictionary_iterator_hasnext(&iter))
    {
        zdb_rr_label *sub_label =  *(zdb_rr_label**)dictionary_iterator_next(&iter);
        dnsname_copy(&sub_fqdn[dnslabel_copy(sub_fqdn, sub_label->name)], fqdn);
        zone_diff_add_fqdn(diff, sub_fqdn, sub_label);
                
        if(dictionary_notempty(&sub_label->sub))
        {
            zone_diff_add_fqdn_children(diff, sub_fqdn, sub_label);
        }
    }
}

zone_diff_fqdn*
zone_diff_add_fqdn_from_zone(zone_diff *diff, const u8 *fqdn, const zdb_zone *zone)
{
    dnsname_vector origin_path;
    dnsname_vector name_path;

    dnsname_to_dnsname_vector(zone->origin, &origin_path);
    dnsname_to_dnsname_vector(fqdn, &name_path);

    zdb_rr_label* rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - origin_path.size) - 1);
    
    if(rr_label != NULL)
    {
        zone_diff_fqdn *diff_fqdn = zone_diff_add_fqdn(diff, fqdn, rr_label);
        return diff_fqdn;
    }
    else
    {
        return NULL;
    }
}

/**
 * Enables the or_state flags in every record of the set.
 * 
 * @param rrset
 * @param or_state
 */

void
zone_diff_fqdn_rr_set_set_state(zone_diff_fqdn_rr_set *rrset, u8 or_state)
{
    ptr_set_avl_iterator rr_iter;
    ptr_set_avl_iterator_init(&rrset->rr, &rr_iter);
    while(ptr_set_avl_iterator_hasnext(&rr_iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;
        rr->state |= or_state;
    }
}

/**
 * Returns true iff an rrset of the given type will be present after applying
 * the diff.
 * 
 * @param diff_fqdn
 * @param rtype
 * @return 
 */

bool
zone_diff_will_have_rrset_type(const zone_diff_fqdn *diff_fqdn, u16 rtype)
{
    u32_node *rrset_node = u32_set_avl_find(&diff_fqdn->rrset, rtype);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrset != NULL);
        
        ptr_set_avl_iterator rr_iter;
        ptr_set_avl_iterator_init(&rrset->rr, &rr_iter);
        while(ptr_set_avl_iterator_hasnext(&rr_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

            if((rr->state & ZONE_DIFF_REMOVE) == 0)
            {
                // this record was present or is being added
                return TRUE;
            }
        }
    }
    return FALSE;
}

/**
 * Returns true iff an rrset of the given type will be present after applying
 * the diff.
 * 
 * @param diff_fqdn
 * @param rtype
 * @return 
 */

bool
zone_diff_will_have_dnskey(const zone_diff_fqdn *diff_fqdn, u8 algorithm, u16 flags, u16 tag)
{
    u32_node *rrset_node = u32_set_avl_find(&diff_fqdn->rrset, TYPE_DNSKEY);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrset != NULL);
        
        ptr_set_avl_iterator rr_iter;
        ptr_set_avl_iterator_init(&rrset->rr, &rr_iter);
        while(ptr_set_avl_iterator_hasnext(&rr_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

            if((rr->state & ZONE_DIFF_REMOVE) == 0)
            {
                // this record was present or is being added
                if(rr->rdata_size > 3)
                {
                    if(dnskey_get_algorithm_from_rdata(rr->rdata) == algorithm)
                    {
                        if(dnskey_get_flags_from_rdata(rr->rdata) == flags)
                        {
                            if(dnskey_get_key_tag_from_rdata(rr->rdata, rr->rdata_size) == tag)
                            {
                                return TRUE;
                            }
                        }
                    }
                }
            }
        }
    }
    return FALSE;
}

/**
 * Releases keys that will not be in the apex after the diff is applied.
 * 
 * @param diff
 * @param keys
 */

void
zone_diff_filter_out_keys(const zone_diff *diff, ptr_vector *keys)
{
    const zone_diff_fqdn *diff_fqdn = zone_diff_get_fqdn(diff, diff->origin);
    if(diff_fqdn != NULL)
    {
        for(int i = 0; i <= ptr_vector_last_index(keys); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, i);

            if(!zone_diff_will_have_dnskey(diff_fqdn, dnssec_key_get_algorithm(key), dnssec_key_get_flags(key), dnssec_key_get_tag(key)))
            {
                ptr_vector_end_swap(keys, i);
                ptr_vector_pop(keys);
                dnskey_release(key);
            }
        }
    }
}

/**
 * find label for fqdn ...
 * 
 * @param diff
 * @param fqdn
 * @param label
 * @return 
 */

const zone_diff_fqdn*
zone_diff_get_fqdn(const zone_diff *diff, const u8 *fqdn)
{
    zone_diff_fqdn *ret = NULL;
    ptr_node *node = ptr_set_avl_find(&diff->fqdn, (u8*)fqdn);
    if(node != NULL)
    {
        ret = (zone_diff_fqdn*)node->value;
    }
    return ret;
}

/**
 * Generates a type bit map based on the diff including records matching:
 * 
 * (status & mask) == masked
 * 
 * mask,masked
 *      all pre records : ZONE_DIFF_REMOVE|ZONE_DIFF_ADD == 0
 *      all post records: ZONE_DIFF_REMOVE = 0
 *
 * @param diff
 * @param fqdn
 * @param bitmap
 * @param mask
 * @param masked
 * @return 
 */

u16
zone_diff_type_bit_map_generate(const zone_diff *diff, const u8 *fqdn, type_bit_maps_context *bitmap, u8 mask, u8 masked, const u8 *chain_node_fqdn)
{
    type_bit_maps_init(bitmap);
    
    const zone_diff_fqdn* zdf = zone_diff_get_fqdn(diff, fqdn);
    
    if(zdf != NULL)
    {
        ptr_set_avl_iterator rr_iter;
        u32_set_avl_iterator iter;
        u32_set_avl_iterator_init(&zdf->rrset, &iter);
        while(u32_set_avl_iterator_hasnext(&iter))
        {
            u32_node *node = u32_set_avl_iterator_next_node(&iter);
            u16 rtype = (u16)node->key;
            zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)node->value;

            ptr_set_avl_iterator_init(&rrset->rr, &rr_iter);
            while(ptr_set_avl_iterator_hasnext(&rr_iter))
            {
                ptr_node *node = ptr_set_avl_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;
                
                if((rr->state & mask) == masked)
                {
                    log_debug1("update: %{dnsname}: %{dnsname}: %x: %{dnstype}", diff->origin, chain_node_fqdn, mask, &rtype);
                    
                    type_bit_maps_set_type(bitmap, rtype);
                    break;
                }
            }
        }
    }

    u16 bitmap_size = type_bit_maps_update_size(bitmap);
    
    return bitmap_size;
}

/**
 * Adds a record on a diff
 * 
 * @param diff
 * @param rr_label
 * @param fqdn
 * @param rtype
 * @param rttl
 * @param rdata_size
 * @param rdata
 */

zone_diff_label_rr*
zone_diff_record_add(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn, u16 rtype, s32 rttl, u16 rdata_size, void *rdata)
{
#ifdef DEBUG
    rdata_desc rd = {rtype, rdata_size, rdata};
    log_debug2("update: %{dnsname}: will add %{dnsname} %5i %{typerdatadesc}", diff->origin, fqdn, rttl, &rd);
#endif
    zone_diff_fqdn *diff_fqdn = zone_diff_add_fqdn(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_get(diff_fqdn, rtype);
    zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, rtype, CLASS_IN, rttl, rdata, rdata_size, TRUE);
    rr = zone_diff_fqdn_rr_set_add(rr_set, rr);
    if((rr->state & ZONE_DIFF_IN_ZONE) == 0)
    {
        rr->state |= ZONE_DIFF_ADD;
    }
    return rr;
}

/**
 * 
 * Adds the removal of a specific record on a diff
 * 
 * @param diff
 * @param rr_label
 * @param fqdn
 * @param rtype
 * @param rttl
 * @param rdata_size
 * @param rdata
 */

void
zone_diff_record_remove(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn, u16 rtype, s32 rttl, u16 rdata_size, void *rdata)
{
#ifdef DEBUG
    rdata_desc rd = {rtype, rdata_size, rdata};
    log_debug2("update: %{dnsname}: will del %{dnsname} %5i %{typerdatadesc}", diff->origin, fqdn, rttl, &rd);
#endif
    (void)rttl;
    zone_diff_fqdn *diff_fqdn = zone_diff_add_fqdn(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_get(diff_fqdn, rtype);
    zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, rtype, CLASS_IN, 0, rdata, rdata_size, TRUE);
    rr = zone_diff_fqdn_rr_set_add(rr_set, rr);
    rr->state |= ZONE_DIFF_REMOVE;
}

static void
zone_diff_record_remove_automated(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn, u16 rtype, s32 rttl, u16 rdata_size, void *rdata)
{
#ifdef DEBUG
    rdata_desc rd = {rtype, rdata_size, rdata};
    log_debug2("update: %{dnsname}: will del %{dnsname} %5i %{typerdatadesc}", diff->origin, fqdn, rttl, &rd);
#endif
    (void)rttl;
    zone_diff_fqdn *diff_fqdn = zone_diff_add_fqdn(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_get(diff_fqdn, rtype);
    zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, rtype, CLASS_IN, 0, rdata, rdata_size, TRUE);
    rr = zone_diff_fqdn_rr_set_add(rr_set, rr);
    rr->state |= ZONE_DIFF_REMOVE|ZONE_DIFF_AUTOMATED;
}

/**
 * Adds the removal of a record set on a diff
 * 
 * @param diff
 * @param rr_label
 * @param fqdn
 * @param rtype
 */

void zone_diff_record_remove_all(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn, u16 rtype)
{
    zone_diff_fqdn *diff_fqdn = zone_diff_add_fqdn(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_get(diff_fqdn, rtype);
    
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&rr_set->rr, &iter);
    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;
        rr->state |= ZONE_DIFF_REMOVE;
    }
}

/**
 * Adds the removal all record sets on a diff
 * 
 * @param diff
 * @param rr_label
 * @param fqdn
 * @param rtype
 */

void
zone_diff_record_remove_all_sets(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn)
{
    zone_diff_fqdn *diff_fqdn = zone_diff_add_fqdn(diff, fqdn, rr_label);
    
    u32_set_avl_iterator typeiter;
    u32_set_avl_iterator_init(&diff_fqdn->rrset, &typeiter);
    while(u32_set_avl_iterator_hasnext(&typeiter))
    {
        zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)u32_set_avl_iterator_next_node(&typeiter);

        ptr_set_avl_iterator iter;
        ptr_set_avl_iterator_init(&rr_set->rr, &iter);
        while(ptr_set_avl_iterator_hasnext(&iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;
            rr->state |= ZONE_DIFF_REMOVE;
        }
    }
}

/**
 * Adds the SOA records for the incremental update.
 * 
 * @param diff
 * @return 
 */

ya_result
zone_diff_set_soa(zone_diff *diff, zdb_rr_label *label)
{
    /**************************************************************************
     * SOA HANDLING
     **************************************************************************/
    
    // check the SOA
    // expects 1 record, "removed", then add 1 added with incremented serial
    // else one and only one should be seen as "added" (and not removed), then do nothing
    // else still add 1 added incremented serial
    
    // if one (and only one, more being an error) SOA is marked as added, then do nothing
    // else add one with incremented serial based on the highest found serial
    
    zone_diff_fqdn *apex = zone_diff_add_fqdn(diff, diff->origin, label);
    zone_diff_fqdn_rr_set *soa_rrset = zone_diff_fqdn_rr_set_get(apex, TYPE_SOA);
    
    //ptr_set_avl_iterator fqdn_iter;
    ptr_set_avl_iterator rr_iter;
    
    zone_diff_label_rr *rr_soa_removed = NULL;
    zone_diff_label_rr *rr_soa_added = NULL;
    u32 soa_latest_serial;
    ya_result ret;
    
    ptr_set_avl_iterator_init(&soa_rrset->rr, &rr_iter);
    while(ptr_set_avl_iterator_hasnext(&rr_iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

#ifdef DEBUG        
        rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
        log_debug1("update: %{dnsname}: SOA[%x] %{dnsname} %9i %{typerdatadesc}", diff->origin, rr->state, rr->fqdn, rr->ttl, &rd);
#endif
        
        if(rr->state & ZONE_DIFF_REMOVE)
        {
            u32 soa_serial;
            
            if(FAIL(ret = rr_soa_get_serial(rr->rdata, rr->rdata_size, &soa_serial)))
            {
                // error
                return ret;
            }
            
            if(rr_soa_removed == NULL)
            {
                soa_latest_serial = soa_serial;
                rr_soa_removed = rr;
            }
            else
            {
                soa_latest_serial = serial_max(soa_latest_serial, soa_serial);
                if(serial_lt(soa_latest_serial, soa_serial))
                {
                    rr_soa_removed = rr;
                }
            }
        }
        
        if((rr->state & (ZONE_DIFF_ADD | ZONE_DIFF_REMOVE)) == ZONE_DIFF_ADD)
        {
            if(rr_soa_added != NULL)
            {
                return ERROR; // two SOA added ...
            }
            
            rr_soa_added = rr;
        }
    }
    
    if(rr_soa_removed == NULL)
    {
        return ERROR;
    }
    
    if(rr_soa_added != NULL)
    {
        u32 soa_serial;
            
        if(FAIL(ret = rr_soa_get_serial(rr_soa_added->rdata, rr_soa_added->rdata_size, &soa_serial)))
        {
            // error
            
            return ret;
        }

        if(serial_le(soa_serial, soa_latest_serial))
        {
            // error
            
            return ERROR;
        }
    }
    else
    {
        // add the SOA add record
        u8 tmp_rdata[rr_soa_removed->rdata_size];
        memcpy(tmp_rdata, rr_soa_removed->rdata, rr_soa_removed->rdata_size);
        rr_soa_increase_serial(tmp_rdata, rr_soa_removed->rdata_size, 1);
        rr_soa_added = zone_diff_label_rr_new(rr_soa_removed->fqdn, TYPE_SOA, CLASS_IN, rr_soa_removed->ttl, tmp_rdata, rr_soa_removed->rdata_size, TRUE);
        rr_soa_added = zone_diff_fqdn_rr_set_add(soa_rrset, rr_soa_added);
        rr_soa_added->state |= ZONE_DIFF_ADD  | ZONE_DIFF_AUTOMATED;
    }
    
    return SUCCESS;
}

/**
 * Updates status and validates a diff.
 * 
 * @param diff
 * @return 
 */

ya_result
zone_diff_validate(zone_diff *diff)
{
    ptr_set_avl_iterator fqdn_iter;
    
    ptr_set_avl_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_set_avl_iterator_hasnext(&fqdn_iter))
    {
        ptr_node *diff_fqdn_node = ptr_set_avl_iterator_next_node(&fqdn_iter);
        const u8 *diff_fqdn_name = (const u8*)diff_fqdn_node->key;
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;
        
        // update status flags
        // do validation tests
        
        log_debug("update: %{dnsname}: validating %{dnsname}", diff->origin, diff_fqdn_name);
        
        if(diff_fqdn->is_apex)
        {
            // only check for CNAME
            
            if(zone_diff_will_have_rrset_type(diff_fqdn, TYPE_CNAME))
            {
                log_err("update: %{dnsname}: update would add CNAME on apex", diff->origin);
                
                //dnssec_chain_finalise(&dc);
                
                return ERROR;
            }
        }
        else
        {
            // check for CNAME
            
            // update under-delegation
            //
            //      for all labels above, look in the diff if they are present and if their delegation status will be changed
            
            bool under_delegation = FALSE;
            
            const u8 *above_fqdn = diff_fqdn->fqdn;
            while(*above_fqdn != 0)
            {
                above_fqdn += *above_fqdn + 1;
                
                const zone_diff_fqdn *parent = zone_diff_get_fqdn(diff, above_fqdn);
                
                if(parent != NULL)
                {
                    if(parent->is_apex)
                    {
                        break;
                    }
                    
                    if(parent->under_delegation)
                    {
                        if(!diff_fqdn->under_delegation)
                        {
                            log_debug("update: %{dnsname}: %{dnsname} under under delegation %{dnsname}", diff->origin,
                                    diff_fqdn->fqdn, parent->fqdn);
                        }
                        under_delegation = TRUE;
                        break;
                    }
                    
                    if(parent->at_delegation)
                    {
                        if(!diff_fqdn->under_delegation)
                        {
                            log_debug("update: %{dnsname}: %{dnsname} under delegation %{dnsname}", diff->origin,
                                    diff_fqdn->fqdn, parent->fqdn);
                        }
                        under_delegation = TRUE;
                        break;
                    }
                }
            }
            
            if(diff_fqdn->under_delegation && !under_delegation)
            {
                log_debug("update: %{dnsname}: %{dnsname} not under delegation anymore", diff->origin, diff_fqdn->fqdn); // + should be signed ?
            }
            
            diff_fqdn->under_delegation = under_delegation;
            
            // update delegation
            //
            //
            
            if(zone_diff_will_have_rrset_type(diff_fqdn, TYPE_NS))
            {
                diff_fqdn->at_delegation = TRUE;
                
                // check there will be only glue records under this level
            }
            else
            {
                diff_fqdn->at_delegation = FALSE;
            }
            
            diff_fqdn->will_have_ds = zone_diff_will_have_rrset_type(diff_fqdn, TYPE_DS);
        }
        
        log_debug("update: %{dnsname}: validating %{dnsname}: apex=%i at=%i under=%i ds=%i",
                diff->origin, diff_fqdn_name,
                diff_fqdn->is_apex, diff_fqdn->at_delegation, diff_fqdn->under_delegation, diff_fqdn->will_have_ds
                );
    }
    
    return SUCCESS;
}

struct zone_diff_get_changes_update_rr_parm
{
    u8 changes;
    bool rrset_removed;
    bool all_rrset_added;
    bool all_rrset_removed;
    bool non_empty;
};

static void
zone_diff_get_changes_update_rrsig_rr(zone_diff_fqdn_rr_set *rr_set, struct zone_diff_get_changes_update_rr_parm *parm, ptr_vector *remove, ptr_vector *add)
{
    u8 changes = parm->changes;
    bool rrset_removed = parm->rrset_removed;
    bool all_rrset_added = parm->all_rrset_added;
    bool all_rrset_removed = parm->all_rrset_removed;
            
    ptr_set_avl_iterator rr_iter;
    
    // for all marked rr
            
    ptr_set_avl_iterator_init(&rr_set->rr, &rr_iter);
    while(ptr_set_avl_iterator_hasnext(&rr_iter))
    {
        ptr_node *rr_node = ptr_set_avl_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;
        
        yassert(rr->rtype == TYPE_RRSIG);
        
        if((rr->state & (ZONE_DIFF_IN_ZONE|ZONE_DIFF_ADD|ZONE_DIFF_REMOVE|ZONE_DIFF_ADDED)) == ZONE_DIFF_ADD)
        {
            // add
#ifdef DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug("update: add %w %{dnsname} %9i %{typerdatadesc}",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd);
#endif
            
            ptr_vector_append(add, rr);
            rr->state |= ZONE_DIFF_ADDED;

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_ADD;
            rrset_removed = FALSE;
            all_rrset_removed = FALSE;
        }
        else if((rr->state & (ZONE_DIFF_IN_ZONE|ZONE_DIFF_ADD|ZONE_DIFF_REMOVE|ZONE_DIFF_REMOVED)) == (ZONE_DIFF_REMOVE|ZONE_DIFF_IN_ZONE))
        {
            // remove
            
#ifdef DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug("update: del %w %{dnsname} %9i %{typerdatadesc} (rrsig-rr)",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd);
#endif

            ptr_vector_append(remove, rr);
            rr->state |= ZONE_DIFF_REMOVED;

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_REMOVE;
            all_rrset_added = FALSE;
        }
        else if((rr->state & (ZONE_DIFF_ADD|ZONE_DIFF_REMOVE)) == 0)
        {
            // stays
            
#ifdef DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug("update: nop %w %{dnsname} %9i %{typerdatadesc}",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd);
#endif
            
            changes |= ZONE_DIFF_CHANGES_KEPT;
            rrset_removed = FALSE;
            all_rrset_removed = FALSE;
            all_rrset_added = FALSE;
        }
        else
        {
#ifdef DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug("update: ign %w %{dnsname} %9i %{typerdatadesc}",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd);
#endif
        }
    }
    
    parm->changes = changes;
    parm->rrset_removed = rrset_removed;
    parm->all_rrset_added = all_rrset_added;
    parm->all_rrset_removed = all_rrset_removed;
}

static void
zone_diff_get_changes_update_rr(zone_diff_fqdn_rr_set *rr_set, struct zone_diff_get_changes_update_rr_parm *parm, ptr_vector *remove, ptr_vector *add)
{
    
    u8 changes = parm->changes;
    bool rrset_removed = parm->rrset_removed;
    bool all_rrset_added = parm->all_rrset_added;
    bool all_rrset_removed = parm->all_rrset_removed;
    bool non_empty = parm->non_empty;
            
    ptr_set_avl_iterator rr_iter;
    
    // for all marked rr
            
    ptr_set_avl_iterator_init(&rr_set->rr, &rr_iter);
    while(ptr_set_avl_iterator_hasnext(&rr_iter))
    {
        ptr_node *rr_node = ptr_set_avl_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;

        if((rr->state & (ZONE_DIFF_ADD|ZONE_DIFF_REMOVE|ZONE_DIFF_ADDED)) == ZONE_DIFF_ADD)
        {
            // add
            
#ifdef DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug("update: add %w %{dnsname} %9i %{typerdatadesc}",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd);
#endif
            ptr_vector_append(add, rr);
            rr->state |= ZONE_DIFF_ADDED;

            if(rr->rtype == TYPE_SOA)
            {
                ptr_vector_end_swap(add, 0);
            }

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_ADD;
            rrset_removed = FALSE;
            all_rrset_removed = FALSE;
            non_empty = TRUE;
        }
        else if((rr->state & (ZONE_DIFF_ADD|ZONE_DIFF_REMOVE|ZONE_DIFF_REMOVED)) == ZONE_DIFF_REMOVE)
        {
            // remove
            
#ifdef DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug("update: del %w %{dnsname} %9i %{typerdatadesc} (rr)",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd);
#endif

            ptr_vector_append(remove, rr);
            rr->state |= ZONE_DIFF_REMOVED;

            if(rr->rtype == TYPE_SOA)
            {
                ptr_vector_end_swap(remove, 0);
            }

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_REMOVE;
            all_rrset_added = FALSE;
        }
        else if((rr->state & (ZONE_DIFF_ADD|ZONE_DIFF_REMOVE)) == 0)
        {
            
#ifdef DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug("update: nop %w %{dnsname} %9i %{typerdatadesc}",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd);
#endif
            // stays
            changes |= ZONE_DIFF_CHANGES_KEPT;
            rrset_removed = FALSE;
            all_rrset_removed = FALSE;
            all_rrset_added = FALSE;
            non_empty = TRUE;
        }
        else if((rr->state & ZONE_DIFF_IN_ZONE) != 0)
        {
            // check if it's a delegation that's about to not become a delegation
            // ... or the reverse
        }
    }
    
    parm->changes = changes;
    parm->rrset_removed = rrset_removed;
    parm->all_rrset_added = all_rrset_added;
    parm->all_rrset_removed = all_rrset_removed;
    parm->non_empty = non_empty;
}

/**
 * Stores changes of a diff into two vectors.
 * Optionally keep track of record sets that need to be signed.
 * Optionally notify a chain about changes.
 * 
 * @param diff
 * @param dc can be NULL
 * @param rrset_to_sign_vector can be NULL
 * @param remove
 * @param add
 * @return TRUE iff there is a DNSKEY rrset in the diff
 */

bool
zone_diff_get_changes(zone_diff *diff, dnssec_chain* dc, ptr_vector *rrset_to_sign_vector, ptr_vector *remove, ptr_vector *add)
{
    ptr_set_avl_iterator fqdn_iter;
    ptr_set_avl_iterator rr_iter;
      
    time_t now = time(NULL);
    
    bool dnskey_set_update = FALSE;
    
    // for all fqdn
    
    ptr_set_avl_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_set_avl_iterator_hasnext(&fqdn_iter))
    {
        ptr_node *diff_fqdn_node = ptr_set_avl_iterator_next_node(&fqdn_iter);
        const u8 *diff_fqdn_name = (const u8*)diff_fqdn_node->key;
               
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;
                
        // for all rrset
        
        bool type_map_changed = FALSE;
        bool all_rrset_added = TRUE;
        bool all_rrset_removed = TRUE;
        bool non_empty = FALSE;
        
        zone_diff_fqdn_rr_set *rrsig_rr_set = NULL;
        
        u32_node *rrset_node = u32_set_avl_find(&diff_fqdn->rrset, TYPE_RRSIG);
        if(rrset_node != NULL)
        {
            rrsig_rr_set = (zone_diff_fqdn_rr_set*)rrset_node->value;
        }
        
        type_map_changed = (rrsig_rr_set == NULL);
        
        // for all records
        
        u32_set_avl_iterator rrset_iter;
        u32_set_avl_iterator_init(&diff_fqdn->rrset, &rrset_iter);
        while(u32_set_avl_iterator_hasnext(&rrset_iter))
        {
            u32_node *rrset_node = u32_set_avl_iterator_next_node(&rrset_iter);
            
            zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)rrset_node->value;
            
            if(rr_set == NULL)
            {
                continue;
            }
            
#if DYNUPDATE_DIFF_DETAILLED_LOG
            {
                // enumerate records
                
                ptr_set_avl_iterator rr_iter;
                ptr_set_avl_iterator_init(&rr_set->rr, &rr_iter);
                rdata_desc rdatadesc = {rr_set->rtype, 0, NULL};
                while(ptr_set_avl_iterator_hasnext(&rr_iter))
                {
                    ptr_node *rr_node = ptr_set_avl_iterator_next_node(&rr_iter);
                    zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->key;
                    rdatadesc.len = rr->rdata_size;
                    rdatadesc.rdata = rr->rdata;
                    log_debug("update: %02x %{dnsname} %i %{typerdatadesc}", rr->state, rr->fqdn, rr->ttl, &rdatadesc);
                }
            }
#endif  
            
            if(rr_set->rtype == TYPE_RRSIG)
            {
                // if allowed ...
                
                if(diff->rrsig_update_allowed)
                {
                    u8 changes = ZONE_DIFF_CHANGES_NONE;
                    bool rrset_removed = TRUE;

                    struct zone_diff_get_changes_update_rr_parm parms = {changes, rrset_removed, all_rrset_added, all_rrset_removed, non_empty};
                    zone_diff_get_changes_update_rrsig_rr(rr_set, &parms, remove, add);
                }
#ifdef DEBUG
                else
                {
                    log_debug("update: not updating rrsig-rr at this point");
                }
#endif
                
                continue;
            }
            
            if(rr_set->rtype == TYPE_NSEC)
            {
                //rrsig_rr_set = rr_set;
                continue;
            }
            
            u8 changes = ZONE_DIFF_CHANGES_NONE;
            bool rrset_removed = TRUE;
            
            struct zone_diff_get_changes_update_rr_parm parms = {changes, rrset_removed, all_rrset_added, all_rrset_removed, non_empty};
            zone_diff_get_changes_update_rr(rr_set, &parms, remove, add);
            
            changes = parms.changes;
            rrset_removed = parms.rrset_removed;
            all_rrset_added = parms.all_rrset_added;
            all_rrset_removed = parms.all_rrset_removed;
            non_empty = parms.non_empty;
            
            /*
             * If the status is 0, then all the added records that have been added have also been removed => no map change, and no signature change
             * If the status is 1, then the rrset has completely been removed => map change and remove all signatures
             * If the status is 2, then the rrset has completely been added => map change, and add (new) signatures
             * If the status is 4, then the rrset existed and still exists => no map change, and no signature change
             * 
             * Any other combination having 1 or 2 on will make no map change but update the signature
             * 
             */
            
            if((changes == ZONE_DIFF_CHANGES_ADD) || (changes == ZONE_DIFF_CHANGES_REMOVE))
            {
                type_map_changed = TRUE;
            }
            
            if((rr_set->rtype == TYPE_DNSKEY) && (changes & (ZONE_DIFF_CHANGES_ADD|ZONE_DIFF_CHANGES_REMOVE)))
            {
                dnskey_set_update = TRUE;
            }

            if(rrset_node->key == TYPE_RRSIG)
            {
                continue;
            }
            
            bool rrset_updated = (changes & (ZONE_DIFF_CHANGES_ADD|ZONE_DIFF_CHANGES_REMOVE));
            bool rrset_covered_with_chain_rules = (!rrset_removed && (dc != NULL) && dc->chain->fqdn_is_covered(diff_fqdn));
            bool came_under_delegation = (!diff_fqdn->was_under_delegation && diff_fqdn->under_delegation);
            bool came_out_of_delegation = (diff_fqdn->was_under_delegation && !diff_fqdn->under_delegation);
#if 1
            // for all rrsig, enumerate properly covered types
            
            bool rrset_already_covered = FALSE;
            
            if(!rrset_updated && !all_rrset_removed && (rrsig_rr_set != NULL)) // else this would be pointless
            {
                ptr_set_avl_iterator_init(&rrsig_rr_set->rr, &rr_iter);
                while(ptr_set_avl_iterator_hasnext(&rr_iter))
                {
                    ptr_node *rr_node = ptr_set_avl_iterator_next_node(&rr_iter);
                    zone_diff_label_rr *rrsig_rr = (zone_diff_label_rr *)rr_node->key;
                    if(rrsig_rr->rdata_size > 18)
                    {
                        u16 rtype = GET_U16_AT_P(rrsig_rr->rdata);

                        if(rtype != rr_set->rtype)
                        {
                            continue;
                        }
                        
                        // check if the signature is with a valid key and is in its validity period
                        // if it's not valid yet, keep it
                        // if its expired, remove it
                        // if no valid signatures are available, may mark the record for signing
                        
                        u8 algorithm = rrsig_get_algorithm_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);
                        u16 tag = rrsig_get_key_tag_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);
                        
                        if(dnssec_keystore_is_key_active(diff->origin, algorithm, tag, now))
                        {                        
                            u32 valid_until = rrsig_get_valid_until_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);
                            u32 valid_from = rrsig_get_valid_from_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

                            if((valid_from <= now) && (valid_until >= now))
                            {
                                rrset_already_covered = TRUE;
                                break;
                            }
                        }
                    }
                }
            }
#endif
            
            bool remove_rrset_signatures =  rrset_updated || came_under_delegation;
            bool add_rrset_signatures =  !rrset_already_covered && (rrset_covered_with_chain_rules || came_out_of_delegation);

            if(remove_rrset_signatures && (rrsig_rr_set != NULL))
            {
                log_debug("update: %{dnsname}: dnssec: %{dnsname} %{dnstype} rrset @%p will have its old signatures removed", diff->origin,
                        diff_fqdn_name, &rr_set->rtype, rr_set);
                
                // remove all signatures for the rrset

                ptr_set_avl_iterator_init(&rrsig_rr_set->rr, &rr_iter);
                while(ptr_set_avl_iterator_hasnext(&rr_iter))
                {
                    ptr_node *rr_node = ptr_set_avl_iterator_next_node(&rr_iter);
                    zone_diff_label_rr *rrsig_rr = (zone_diff_label_rr*)rr_node->value;

                    if((rrsig_rr->state & ZONE_DIFF_ADD) != 0)
                    {
                        continue;
                    }

                    u16 type_covered = GET_U16_AT_P(rrsig_rr->rdata);

                    if(type_covered == rr_set->rtype)
                    {
                        if((rrsig_rr->state & ZONE_DIFF_REMOVED) == 0)
                        {
                            rrsig_rr->state |= ZONE_DIFF_REMOVE|ZONE_DIFF_AUTOMATED;
                        
#ifdef DEBUG
                            {
                                rdata_desc rrsig_rr_rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                                format_writer temp_fw_0 = {zone_diff_record_state_format, &rrsig_rr->state};
                                log_debug("update: del %w %{dnsname} %9i %{typerdatadesc} (rrsig)",
                                        &temp_fw_0, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_rd);
                            }
#endif
                        
                            ptr_vector_append(remove, rrsig_rr);
                            rrsig_rr->state |= ZONE_DIFF_REMOVED;
                        }
                    }
                }
            }

            // If the chain believes it has to handle the fqdn, add the rrset to the "to sign"
            // This does not work with mixed chains (NSEC & NSEC3)

            if(add_rrset_signatures && (rrset_to_sign_vector != NULL))
            {
                // will generate new signatures for the rrset (postponed)
                
                // verify that signatures are not already present

                log_debug("update: %{dnsname}: dnssec: %{dnsname} %{dnstype} rrset @%p should be signed", diff->origin,
                        diff_fqdn_name, &rr_set->rtype, rr_set);

                ptr_vector_append(rrset_to_sign_vector, rr_set);
            }
        }
        
        // if type_map_changes, the type map has to be updated and the signature too, obviously
        
        diff_fqdn->type_map_changed = type_map_changed;
        diff_fqdn->all_rrset_added = all_rrset_added;
        diff_fqdn->all_rrset_removed = all_rrset_removed;
        diff_fqdn->will_be_non_empty = non_empty;
        
        diff_fqdn->records_flags_set = 1;
    }

    if(dc != NULL)
    {    
        ptr_set_avl_iterator_init(&diff->fqdn, &fqdn_iter);
        while(ptr_set_avl_iterator_hasnext(&fqdn_iter))
        {
            ptr_node *diff_fqdn_node = ptr_set_avl_iterator_next_node(&fqdn_iter);
            const u8 *diff_fqdn_name = (const u8*)diff_fqdn_node->key;

            zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;
        
            zone_diff_fqdn_children_state(diff, diff_fqdn->fqdn);

            // calling dnssec_chain_del_from_diff_fqdn and dnssec_chain_add_from_diff_fqdn respectively
            // tell to remove or to add a chain node (NSEC/NSEC3) for the given fqdn in the zone.
            
            // Note the "was" or "is" covered means "IF the fqdn existed, was the past state covering it, is the new state covering it."
            
            // This table gives the del/add for a node given the various states
            
            // Was covered | Is covered | +ALL | -ALL | REMAP | NODE
            // -----------------------------------------------+------
            //      0            0          1      0      ?   |
            //      0            0          0      1      ?   |
            //      0            0          0      0      0   |
            //      0            0          0      0      1   |
            // -----------------------------------------------+------
            //      0            1          1      0      ?   |  +
            //      0            1          0      1      ?   |        There is nothing anymore
            //      0            1          0      0      0   |  +
            //      0            1          0      0      1   |  +
            // -----------------------------------------------+------
            //      1            0          1      0      ?   |        There was nothing before
            //      1            0          0      1      ?   |  -
            //      1            0          0      0      0   |  -
            //      1            0          0      0      1   |  -
            // -----------------------------------------------+------
            //      1            1          1      0      ?   |  +     There was nothing before
            //      1            1          0      1      ?   |  -
            //      1            1          0      0      0   |        There is no changed of state on this regard
            //      1            1          0      0      1   | -+
            // -----------------------------------------------+------

#define CHAIN_NODE_NOP 0            
#define CHAIN_NODE_DEL 1
#define CHAIN_NODE_ADD 2
            bool is_covered = dc->chain->fqdn_is_covered(diff_fqdn);
            bool was_covered = dc->chain->fqdn_was_covered(diff_fqdn);
            
            log_debug("update: %{dnsname}: dnssec: %{dnsname}: +ALL(%i) -ALL(%i) COVERED(%i->%i) CHILDREN(%i->%i) AT(%i->%i) UNDER(%i->%i) MAP(%i)",
                    diff->origin,
                    diff_fqdn_name,
                    diff_fqdn->all_rrset_added,
                    diff_fqdn->all_rrset_removed,
                    was_covered, is_covered,
                    diff_fqdn->had_children, diff_fqdn->will_have_children,
                    diff_fqdn->was_at_delegation, diff_fqdn->at_delegation,
                    diff_fqdn->was_under_delegation, diff_fqdn->under_delegation,
                    diff_fqdn->type_map_changed);
            
            if(was_covered || is_covered) // quickly cull the first 4 states of the table
            {
                bool did_exist = diff_fqdn->had_children || diff_fqdn->was_non_empty;
                bool will_exist = diff_fqdn->will_have_children || diff_fqdn->will_be_non_empty;
                u8 ops = 0;
                
                if( (diff_fqdn->had_children != diff_fqdn->will_have_children) ||
                    (diff_fqdn->all_rrset_added) ||
                    (diff_fqdn->all_rrset_removed) ||
                    (diff_fqdn->type_map_changed))
                {
                    if(was_covered && did_exist)
                    {
                        ops |= CHAIN_NODE_DEL;
                    }

                    if(is_covered && will_exist)
                    {
                        ops |= CHAIN_NODE_ADD;
                    }
                }

#ifdef DEBUG
                log_debug("update: %{dnsname}: dnssec: %{dnsname}: operation %x", diff->origin, diff_fqdn_name, ops);
#endif
                if(ops & CHAIN_NODE_DEL)
                {
                    log_debug("update: %{dnsname}: dnssec: %{dnsname}: removing chain node", diff->origin, diff_fqdn_name);
                    dnssec_chain_del_from_diff_fqdn(dc, diff_fqdn, 0);
                }
                
                if(ops & CHAIN_NODE_ADD)
                {
                    log_debug("update: %{dnsname}: dnssec: %{dnsname}: adding chain node", diff->origin, diff_fqdn_name);
                    dnssec_chain_add_from_diff_fqdn(dc, diff_fqdn, 0);
                }
            }
        }
    }
    
    return dnskey_set_update;
}

/**
 * Returns TRUE iff there are changes in the diff
 * 
 * @param diff
 * @param dc can be NULL
 * @param rrset_to_sign_vector can be NULL
 * 
 * @return TRUE iff there are changes in the diff
 */

bool
zone_diff_has_changes(zone_diff *diff, ptr_vector *rrset_to_sign_vector)
{
    if(ptr_vector_last_index(rrset_to_sign_vector) >= 0)
    {
        return TRUE;
    }
    
    ptr_set_avl_iterator fqdn_iter;
    ptr_set_avl_iterator rr_iter;

    // for all fqdn
    
    ptr_set_avl_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_set_avl_iterator_hasnext(&fqdn_iter))
    {
        ptr_node *diff_fqdn_node = ptr_set_avl_iterator_next_node(&fqdn_iter);
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;
#if 0
        bool type_map_changed = FALSE;
        bool all_rrset_added = TRUE;
        bool all_rrset_removed = TRUE;
#endif
        // for all records
        
        u32_set_avl_iterator rrset_iter;
        u32_set_avl_iterator_init(&diff_fqdn->rrset, &rrset_iter);
        while(u32_set_avl_iterator_hasnext(&rrset_iter))
        {
            u32_node *rrset_node = u32_set_avl_iterator_next_node(&rrset_iter);
            
            zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)rrset_node->value;
#if 0
            u8 changes = ZONE_DIFF_CHANGES_NONE;
#endif
            // for all marked rr
            
            ptr_set_avl_iterator_init(&rr_set->rr, &rr_iter);
            while(ptr_set_avl_iterator_hasnext(&rr_iter))
            {
                ptr_node *rr_node = ptr_set_avl_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;
#ifdef DEBUG
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
                log_debug1("update: %{dnsname}: has-changes: state %02x: %{dnsname} %9i %{typerdatadesc}", diff->origin, rr->state, rr->fqdn, rr->ttl, &rd);
#endif
                if((rr->state & (ZONE_DIFF_ADD|ZONE_DIFF_REMOVE)) == ZONE_DIFF_ADD)
                {
                    // add
                    return TRUE;
                }
                else if((rr->state & (ZONE_DIFF_ADD|ZONE_DIFF_REMOVE)) == ZONE_DIFF_REMOVE)
                {
                    // remove
                    return TRUE;
                }
#if 0
                else if((rr->state & (ZONE_DIFF_ADD|ZONE_DIFF_REMOVE)) == 0)
                {
                    // stays
                    changes |= ZONE_DIFF_CHANGES_KEPT;
                    all_rrset_removed = FALSE;
                    all_rrset_added = FALSE;
                }
#endif
            }
        }
        
#if 0
        // if type_map_changes, the type map has to be updated and the signature too, obviously
        
        if(type_map_changed||all_rrset_added||all_rrset_removed)
        {
#ifdef DEBUG
            log_debug1("update: %{dnsname}: has-changes: typemap=%i *rrset+=%i *rrset-=%i",
                    diff->origin, type_map_changed, all_rrset_added, all_rrset_removed);
#endif
            return TRUE;
        }
#endif
    }
    
    return FALSE;
}

void
zone_diff_fqdn_log(const u8 *origin, const zone_diff_fqdn* diff_fqdn)
{
    // for all rrset
    
    const u8 *diff_fqdn_name = diff_fqdn->fqdn;
    zone_diff_fqdn_rr_set *rrsig_rr_set = NULL;
    u32_node *rrset_node = u32_set_avl_find(&diff_fqdn->rrset, TYPE_RRSIG);
    
    bool type_map_changed = FALSE;
    
    if(rrset_node != NULL)
    {
        rrsig_rr_set = (zone_diff_fqdn_rr_set*)rrset_node->value;
    }

    type_map_changed = (rrsig_rr_set == NULL);

    if(origin == NULL)
    {
        origin = (const u8 *)"\004NULL";
    }

    format_writer temp_fw_1 = {zone_diff_fqdn_changes_format, diff_fqdn};
    log_debug("zone-diff: %{dnsname}: %{dnsname}: %w (map changed: %i)", origin, diff_fqdn_name, &temp_fw_1, type_map_changed);
    
    // for all records

    u32_set_avl_iterator rrset_iter;
    u32_set_avl_iterator_init(&diff_fqdn->rrset, &rrset_iter);
    while(u32_set_avl_iterator_hasnext(&rrset_iter))
    {
        u32_node *rrset_node = u32_set_avl_iterator_next_node(&rrset_iter);

        zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)rrset_node->value;

        if(rr_set == NULL)
        {
            log_debug("zone-diff: %{dnsname}: %{dnsname} has no record set (%i)", origin, diff_fqdn_name, rrset_node->key);
            continue;
        }

        ptr_set_avl_iterator rr_iter;

        // for all marked rr

        ptr_set_avl_iterator_init(&rr_set->rr, &rr_iter);
        while(ptr_set_avl_iterator_hasnext(&rr_iter))
        {
            ptr_node *rr_node = ptr_set_avl_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;

            rdata_desc rdatadesc = {rr->rtype, rr->rdata_size, rr->rdata};


            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};

            log_debug("zone-diff: %{dnsname}: %{dnsname}: %02x: %w: %{dnsname} %i %{typerdatadesc}", origin, diff_fqdn_name,
                    rr->state, &temp_fw_0, rr->fqdn, rr->ttl, &rdatadesc);
        }
    }
}

void
zone_diff_log(const zone_diff *diff)
{
    ptr_set_avl_iterator fqdn_iter;
    
    // for all fqdn
    
    ptr_set_avl_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_set_avl_iterator_hasnext(&fqdn_iter))
    {
        ptr_node *diff_fqdn_node = ptr_set_avl_iterator_next_node(&fqdn_iter);
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;
        zone_diff_fqdn_log(diff->origin, diff_fqdn);
    }
}

/**
 * Appends RRSIGs to remove/add vector, following the the need-to-be-signed RR set, using keys from KSK and ZSK vectors.
 * 
 * @param diff
 * @param rrset_to_sign_vector
 * @param ksks
 * @param zsks
 * @param remove
 * @param add
 */

void
zone_diff_sign(zone_diff *diff, zdb_zone *zone, ptr_vector* rrset_to_sign_vector, ptr_vector *ksks, ptr_vector *zsks, ptr_vector *remove, ptr_vector* add)
{
    /**************************************************************************
     * SIGNATURES HANDLING
     **************************************************************************/
    
    /*
     * for each rrset in rrset_to_sign
     *   for each valid zsk in the keyring
     *     start new signature
     *     add each record
     *     generate signature
     */
    
    log_debug("update: %{dnsname}: signing differences", diff->origin);
#ifdef DEBUG
    zone_diff_log(diff);
    logger_flush();
#endif
    
    // if there is a chain, proceed with the changes
    
    ptr_vector rrset = EMPTY_PTR_VECTOR;
    dnskey_signature ds;
    dnskey_signature_init(&ds);
    
    struct resource_record_view rrv = {NULL, &zone_diff_label_rr_rrv_vtbl};
    
    for(int i = 0; i <= ptr_vector_last_index(rrset_to_sign_vector); ++i)
    {
        zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)ptr_vector_get(rrset_to_sign_vector, i);
        
        log_debug("update: %{dnsname}: signing (trying) %{dnstype} rrset @%p", diff->origin, &rr_set->rtype, rr_set);

        rrv.data = rr_set;
        
        ptr_vector_clear(&rrset);
        
        u8 rrsig_state_mask = ZONE_DIFF_AUTOMATED;
        
        FOREACH_PTR_SET(void*,value, &rr_set->rr)
        {
            zone_diff_label_rr* rr = (zone_diff_label_rr*)value;
            
            if((rr->state & ZONE_DIFF_REMOVE) == 0)
            {
#ifdef DEBUG        
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
                format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
                log_debug("update: %{dnsname}: covers %w %{dnsname} %9i %{typerdatadesc}", diff->origin, &temp_fw_0, rr->fqdn, rr->ttl, &rd);

                if(rr->state & ZONE_DIFF_AUTOMATED)
                {
                    log_debug("automated");
                }
#endif                
                rrsig_state_mask &= rr->state;
                
                ptr_vector_append(&rrset, value);
            }
            else
            {
#ifdef DEBUG        
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
                format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
                log_debug("update: %{dnsname}: ignore %w %{dnsname} %9i %{typerdatadesc}", diff->origin, &temp_fw_0, rr->fqdn, rr->ttl, &rd);
#endif
            }
        }
        
        rrsig_state_mask |= ZONE_DIFF_ADD;
                
        // for all keys
        
        bool canonize = TRUE;

        ptr_vector *keys;
        
        if(rr_set->rtype != TYPE_DNSKEY)
        {
            keys = zsks;
        }
        else
        {
            keys = ksks;
        }
        for(int j = 0; j <= ptr_vector_last_index(keys); ++j)
        {
            const dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, j);
            
            if(!dnssec_key_is_private(key))
            {
                log_debug("update: %{dnsname}: key %03i %05i is not private", diff->origin,
                        dnssec_key_get_domain(key), dnssec_key_get_algorithm(key), dnssec_key_get_tag_const(key));
                continue;
            }
            
            zone_diff_label_rr *rrsig_rr = NULL;
            
            ya_result ret;
            
            // rrset_to_sign;
            if(ISOK(ret = dnskey_signature_rrset_sign_with_key(key, &rrset, canonize, &rrv, (void**)&rrsig_rr)))
            {
                canonize = FALSE;

                // add the key to the add set
                
                log_debug("update: %{dnsname}: signed %{dnsname} %{dnstype} rrset with key %03i %05i",diff->origin,
                        rrsig_rr->fqdn, &rr_set->rtype,
                        dnssec_key_get_algorithm(key), dnssec_key_get_tag_const(key));
                
                u32 valid_until = rrsig_get_valid_until_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);
                
                if(zone->progressive_signature_update.earliest_signature_expiration > valid_until)
                {
                    zone->progressive_signature_update.earliest_signature_expiration = valid_until;
                }
                
                rrsig_rr->state |= rrsig_state_mask;
                
                zone_diff_fqdn *rrsig_label = zone_diff_add_fqdn(diff, rrsig_rr->fqdn, NULL);
                
                yassert(rrsig_label != NULL);
                
                zone_diff_fqdn_rr_set *rrsig_label_rrset = zone_diff_fqdn_rr_set_get(rrsig_label, TYPE_RRSIG);
                
                yassert(rrsig_label_rrset != NULL);
                
                rrsig_rr = zone_diff_fqdn_rr_set_add(rrsig_label_rrset, rrsig_rr); /// @note not VOLATILE
                
                ptr_vector_append(add, rrsig_rr);
                //(void)rrsig_rr_set;
            }
            else
            {
                log_warn("update: %{dnsname}: failed to sign with key %03i %05i",
                        diff->origin,
                        dnssec_key_get_algorithm(key), dnssec_key_get_tag_const(key));
                // ...
            }
        }
    }
    
    dnskey_signature_finalise(&ds);
    ptr_vector_destroy(&rrset);
}


static ya_result
zone_diff_store_diff(zone_diff *diff, zdb_zone *zone, ptr_vector *remove, ptr_vector *add)
{
    // for all fqdn
    //   for all rrset
    //     for all marked rr (add or remove)
    //       put the rr(s) in the relevant vector
    //       proceed with dnssec on the side
    //     if changed and the rr must be signed
    //       put all signatures rr in the remove set
    //       generate relevant signatures and add them to the add set
    
    // add the dnssec changes, including signatures
    
    // then, because it's Y2 and not Y3, apply the changes into the DB with the journal ready to write
    
    // so ..
    
    ya_result ret;
    
    if(FAIL(ret = zone_diff_set_soa(diff, NULL)))
    {
        return ret;
    }
      
    /**************************************************************************
     * DIFF COMPUTATIONS
     **************************************************************************/

    // initialise the chain(s)
    
    dnssec_chain dc;
    
    bool dnskey_set_update = FALSE;
    
    u8 maintain_mode = zone_get_maintain_mode(zone);

    switch(maintain_mode)
    {
        case ZDB_ZONE_MAINTAIN_NSEC3:
        case ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:
        {
            dnssec_chain_init(&dc, (maintain_mode == ZDB_ZONE_MAINTAIN_NSEC3)?dynupdate_nsec3_chain_get_vtbl():dynupdate_nsec3_optout_chain_get_vtbl(), diff);

            nsec3_zone *n3 = zone->nsec.nsec3;
            while(n3 != NULL)
            {
                const u8 *nsec3param_rdata = n3->rdata;
                u8 nsec3_chain_status = 0;
                nsec3_zone_get_status_from_rdata(zone, nsec3param_rdata, NSEC3_ZONE_RDATA_SIZE(n3), &nsec3_chain_status);

                dnssec_chain_add_chain(&dc, (dnssec_chain_head_t)n3, (nsec3_chain_status & NSEC3_ZONE_REMOVING) != 0);
                n3 = n3->next;
            }
            break;
        }
        case ZDB_ZONE_MAINTAIN_NSEC:
        {
            u8 nsec_chain_status = 0;
            nsec_zone_get_status(zone, &nsec_chain_status);

            dnssec_chain_init(&dc, dynupdate_nsec_chain_get_vtbl(), diff);
            dnssec_chain_add_chain(&dc, (dnssec_chain_head_t)zone->nsec.nsec, (nsec_chain_status & NSEC_ZONE_REMOVING) != 0);
            break;
        }
        default:
        {
            dnssec_chain_init(&dc, dynupdate_nosec_chain_get_vtbl(), diff);
            break;
        }
    }
    
    // update statuses, validates
    
    if(ISOK(ret = zone_diff_validate(diff)))
    {
        ptr_vector rrset_to_sign = EMPTY_PTR_VECTOR;

        // store changes in vectors and get the RR sets to sign

        dnskey_set_update = zone_diff_get_changes(diff, &dc, &rrset_to_sign, remove, add);
        
        int real_changes = 0;
        
        for(int i = 0; i <= ptr_vector_last_index(remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(remove, i);
            
#ifdef DEBUG        
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug("update: %{dnsname}: pre-changes: del: %w %{dnsname} %9i %{typerdatadesc}", diff->origin, &temp_fw_0, rr->fqdn, rr->ttl, &rd);
#endif
            
            if(rr->state & ZONE_DIFF_AUTOMATED)
            {
                continue;
            }
            
            ++real_changes;
        }
        
        for(int i = 0; i <= ptr_vector_last_index(add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add, i);
            
#ifdef DEBUG        
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug("update: %{dnsname}: pre-changes: add: %w %{dnsname} %9i %{typerdatadesc}", diff->origin, &temp_fw_0, rr->fqdn, rr->ttl, &rd);
#endif
            
            if(rr->state & ZONE_DIFF_AUTOMATED)
            {
                continue;
            }
            
            ++real_changes;
        }
        
        ret = real_changes;
        
        if(real_changes == 0)
        {
            zone_diff_label_rr_vector_clear(remove);
            zone_diff_label_rr_vector_clear(add);
        }
        else
        {
            ptr_vector ksks = EMPTY_PTR_VECTOR;
            ptr_vector zsks = EMPTY_PTR_VECTOR;

            // no need to populate the KSKs if we are not working on an DNSKEY anywhere

            dnssec_keystore_acquire_activated_keys_from_fqdn_to_vectors(diff->origin, (dnskey_set_update)?&ksks:NULL, &zsks);
            
            // the above function returns keys that are supposed to be active
            // we must also ensure that these keys are/will be in the zone so we can sign using them
            zone_diff_filter_out_keys(diff, &ksks);
            zone_diff_filter_out_keys(diff, &zsks);

            // sign the records, store the changes in vectors

            zone_diff_sign(diff, zone, &rrset_to_sign, &ksks, &zsks, remove, add);

            ptr_vector_destroy(&rrset_to_sign);

            // chain deletes should use the existing maps if possible (speed) or generate from the local state (all 'exists')
            // chain adds should use the local state (all exists not removed + all adds)

#ifdef DEBUG
            zone_diff_log(diff);
#endif

            dnssec_chain_store_diff(&dc, diff, &zsks, remove, add);

            dnssec_keystore_release_keys_from_vector(&zsks);
            dnssec_keystore_release_keys_from_vector(&ksks);

            ptr_vector_destroy(&zsks);
            ptr_vector_destroy(&ksks);
        }
    }
    
    dnssec_chain_finalise(&dc);
    
    
    return ret;
}

#if ZDB_HAS_DNSSEC_SUPPORT

/**
 * Get all DNSKEY records from the zone.
 * Load the private keys of these DNSKEY records in the keystore.
 * 
 * @param zone
 * @return 
 */

ya_result
dynupdate_diff_load_private_keys(zdb_zone *zone)
{
    ya_result return_code = SUCCESS;

    /* ensure all the private keys are available or servfail */

    const zdb_packed_ttlrdata *dnskey_rrset = zdb_zone_get_dnskey_rrset(zone); // zone is locked

    int ksk_count = 0;
    int zsk_count = 0;

    if(dnskey_rrset != NULL)
    {
        do
        {
            u16 flags = DNSKEY_FLAGS(*dnskey_rrset);
            //u8  protocol = DNSKEY_PROTOCOL(*dnskey_rrset);
            u8  algorithm = DNSKEY_ALGORITHM(*dnskey_rrset);
            u16 tag = DNSKEY_TAG(*dnskey_rrset);                  // note: expensive
            dnssec_key *key = NULL;

            if(FAIL(return_code = dnssec_keystore_load_private_key_from_parameters(algorithm, tag, flags, zone->origin, &key)))
            {
                log_warn("update: unable to load the private key 'K%{dnsname}+%03d+%05d': %r", zone->origin, algorithm, tag, return_code);
            }

            if(flags == DNSKEY_FLAGS_KSK)
            {
                ++ksk_count;
            }
            else if(flags == DNSKEY_FLAGS_ZSK)
            {
                ++zsk_count;
            }

            dnskey_rrset = dnskey_rrset->next;
        }
        while(dnskey_rrset != NULL);
    }
    else
    {
        log_warn("update: there are no private keys in the zone %{dnsname}", zone->origin);

        return_code = DNSSEC_ERROR_RRSIG_NOZONEKEYS;
    }

    return return_code;
}

#endif

/**
 * Writes the del then add records to the journal,
 * deletes the records marked as volatile,
 * exchanges the locks of the zone,
 * replays the journal
 * exchanges the locks back.
 * 
 * Returns the result of the replay or SUCCESS if there was nothing to replay.
 * 
 * @param zone
 * @param secondary_lock
 * @param del_vector
 * @param add_vector
 * @return 
 */

ya_result
dynupdate_diff_write_to_journal_and_replay(zdb_zone *zone, u8 secondary_lock, ptr_vector *del_vector, ptr_vector *add_vector)
{
    ya_result ret = 0;
    
    bool changes_occurred = (ptr_vector_size(add_vector) + ptr_vector_size(del_vector)) > 2;
        
    if(changes_occurred)
    {
        // instead of storing to a buffer and back, could write an inputstream
        // translating the ptr_vector content on the fly

        s32 total = 0;

        for(int i = 0; i <= ptr_vector_last_index(del_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(del_vector, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            
            log_debug("update: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);

            total += dnsname_len(rr->fqdn);
            total += 10;
            total += rr->rdata_size;
        }

        for(int i = 0; i <= ptr_vector_last_index(add_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add_vector, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            
            log_debug("update: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
            
#ifdef DEBUG
            switch(rr->rtype)
            {
                case TYPE_NSEC:
                {
                    const u8 *fqdn = rr->rdata;
                    const u8 *tbm = &fqdn[dnsname_len(fqdn)];
                    
                    if((tbm - fqdn) == 0)
                    {
                        log_err("NSEC record has no type bitmap");
                        abort();
                    }
                    
                    break;
                }
                default:
                {
                    break;
                }
            }
#endif

            total += dnsname_len(rr->fqdn);
            total += 10;
            total += rr->rdata_size;
        }
        
        log_debug("update: %{dnsname}: writing message", zone->origin);

        output_stream baos;

        bytearray_output_stream_init(&baos, NULL, total);

        for(int i = 0; i <= ptr_vector_last_index(del_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(del_vector, i);
#ifdef DEBUG
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            log_debug("update: %{dnsname}: sending - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
#endif
            output_stream_write_dnsname(&baos, rr->fqdn);
            output_stream_write_u16(&baos, rr->rtype);
            output_stream_write_u16(&baos, rr->rclass);
            output_stream_write_nu32(&baos, rr->ttl);
            output_stream_write_nu16(&baos, rr->rdata_size);
            output_stream_write(&baos, rr->rdata, rr->rdata_size);

            if((rr->state & ZONE_DIFF_VOLATILE) != 0)
            {
                zone_diff_label_rr_delete(rr);
            }
        }

        for(int i = 0; i <= ptr_vector_last_index(add_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add_vector, i);
#ifdef DEBUG
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            log_debug("update: %{dnsname}: sending + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
#endif
            output_stream_write_dnsname(&baos, rr->fqdn);
            output_stream_write_u16(&baos, rr->rtype);
            output_stream_write_u16(&baos, rr->rclass);
            output_stream_write_nu32(&baos, rr->ttl);
            output_stream_write_nu16(&baos, rr->rdata_size);
            output_stream_write(&baos, rr->rdata, rr->rdata_size);

            if((rr->state & ZONE_DIFF_VOLATILE) != 0)
            {
                zone_diff_label_rr_delete(rr);
            }
        }
        
        log_debug("update: %{dnsname}: message ready", zone->origin);

        input_stream bais;

        bytearray_input_stream_init(&bais, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos), FALSE);
        
        log_debug("update: %{dnsname}: acquiring journal", zone->origin);

        journal* jnl = NULL;
        if(ISOK(ret = journal_acquire_from_zone_ex(&jnl, zone, TRUE)))
        {
            if(ISOK(ret = journal_append_ixfr_stream(jnl, &bais))) // writes a single page
            {
                log_debug("update: %{dnsname}: wrote %i bytes to the journal", zone->origin, total);

                bytearray_input_stream_reset(&bais);

                u32 current_serial = 0;

                if(secondary_lock != 0)
                {
                    zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, secondary_lock);
                }

                ret = zdb_icmtl_replay_commit(zone, &bais, &current_serial);

                if(secondary_lock != 0)
                {
                    zdb_zone_exchange_locks(zone, secondary_lock, ZDB_ZONE_MUTEX_SIMPLEREADER);
                }
                
                if(ISOK(ret))
                {
                    log_debug("update: %{dnsname}: applied journal changes", zone->origin, total);
                                        
                    ret = total;
                }
                else
                {
                    log_err("update: %{dnsname}: could not apply journal changes: %r", zone->origin, total, ret);
                }
            }
            else
            {
                log_err("update: %{dnsname}: could not write %i bytes to the journal: %r", zone->origin, total, ret);
            }

            journal_release(jnl);
        }
        
        input_stream_close(&bais);
        output_stream_close(&baos);
    }
    
    return ret;
}

/**
 * 
 * Computes the diff of an update.
 * 
 * @param zone
 * @param reader
 * @param count
 * @param dryrun
 * @return 
 */

ya_result
dynupdate_diff(zdb_zone *zone, packet_unpack_reader_data *reader, u16 count, u8 secondary_lock, bool dryrun)
{
    yassert(zdb_zone_islocked(zone));
    
#ifdef DEBUG
    log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i)",
            zone->origin, zone, reader, count, secondary_lock, dryrun);
#endif    
    
    if(ZDB_ZONE_INVALID(zone))
    {
        return ZDB_ERROR_ZONE_INVALID;
    }
     
    if(count == 0)
    {
        return SUCCESS;
    }
    
    zdb_packed_ttlrdata* soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);
    
    if(soa == NULL)
    {
        return ZDB_ERROR_NOSOAATAPEX;
    }
    
    zone_diff diff;
    zone_diff_init(&diff, zone->origin, zone->min_ttl, zdb_zone_get_rrsig_push_allowed(zone));
     
    dnsname_vector origin_path;
    dnsname_vector name_path;

#ifdef DEBUG
    memset(&origin_path, 0xff, sizeof(origin_path));
    memset(&name_path, 0xff, sizeof(name_path));
#endif

    u8 *rname;
    u8 *rdata;
    u32 rname_size;
    u32 rttl;
    ya_result ret;
    u16 rtype;
    u16 rclass;
    u16 rdata_size;
    
    u8 wire[MAX_DOMAIN_LENGTH + 10 + 65535];
    
#ifdef DEBUG
    rdata = (u8*)~0; // DEBUG
    rname_size = ~0; // DEBUG
    rttl = ~0;       // DEBUG
    rtype = ~0;      // DEBUG
    rclass = ~0;     // DEBUG
    rdata_size = ~0; // DEBUG
#endif

    bool changes_occurred = FALSE;
    
#if ZDB_HAS_DNSSEC_SUPPORT
    // zone load private keys
    
    bool dnssec_zone = zdb_zone_is_maintained(zone);
    
    if(dnssec_zone)
    {
        dynupdate_diff_load_private_keys(zone);
    }
#endif
    
    dnsname_to_dnsname_vector(zone->origin, &origin_path);
    
    log_debug1("update: %{dnsname}: reading message", zone->origin);
    
    zone_diff_record_remove_automated(&diff, zone->apex, zone->origin, TYPE_SOA, soa->ttl, ZDB_PACKEDRECORD_PTR_RDATASIZE(soa), ZDB_PACKEDRECORD_PTR_RDATAPTR(soa));
    
    do
    {
        if(FAIL(ret = packet_reader_read_record(reader, wire, sizeof(wire))))
        {
            // if the return code says that the record was invalid, then the buffer has been filled up and including rdata_size
            
            switch(ret)
            {
                case INVALID_RECORD:
                case INCORRECT_IPADDRESS:
                case UNSUPPORTED_RECORD:
                {
                    rname = wire;
                    rname_size = dnsname_len(wire);
                    rtype = ntohs(GET_U16_AT(wire[rname_size]));

                    log_err("update: %{dnsname}: failed reading record %{dnsname} %{dnstype}: %r",zone->origin,  rname, &rtype, ret);
                    break;
                }
                default:
                {
                    log_err("update: %{dnsname}: failed reading next record: %r", zone->origin, ret);
                    break;
                }
            }

            zone_diff_finalise(&diff);

            return SERVER_ERROR_CODE(RCODE_FORMERR);
        }        

        rname = wire;
        
        if(!dnsname_is_subdomain(rname, zone->origin))
        {
            zone_diff_finalise(&diff);
            
            return SERVER_ERROR_CODE(RCODE_NOTZONE);
        }
        
        rname_size = dnsname_len(wire);
        rtype = GET_U16_AT(wire[rname_size]);
        rclass = GET_U16_AT(wire[rname_size + 2]);
        rttl = ntohl(GET_U32_AT(wire[rname_size + 4]));
        rdata_size = ntohs(GET_U16_AT(wire[rname_size + 8]));        
        rdata = &wire[rname_size + 10];
        
        rdata_desc wire_rdatadesc = {rtype, rdata_size, rdata};
        log_debug1("update: %{dnsname}: %{dnsname} %i %{dnstype} %{dnsclass} %{rdatadesc}", 
                zone->origin, rname, rttl, &rtype, &rclass, &wire_rdatadesc);

        /*
         * Simple consistency test:
         */
        
        if((rdata_size == 0) && (rclass != CLASS_ANY))
        {
            log_err("update: %{dnsname}: empty rdata with a different class than ANY: %r", zone->origin, ret, SERVER_ERROR_CODE(RCODE_FORMERR));

            zone_diff_finalise(&diff);
            
            return SERVER_ERROR_CODE(RCODE_FORMERR);
        }

        dnsname_to_dnsname_vector(rname, &name_path);

        s32 idx;

        for(idx = 0; idx < origin_path.size; idx++)
        {
            if(!dnslabel_equals(origin_path.labels[origin_path.size - idx], name_path.labels[name_path.size - idx]))
            {
                log_err("update: %{dnsname}: %{dnsname} manual add/del of %{dnstype} records refused", zone->origin, rname, &rtype);

                zone_diff_finalise(&diff);

                return SERVER_ERROR_CODE(RCODE_NOTZONE);
            }
        }
        
        if((rtype == TYPE_NSEC) || (rtype == TYPE_NSEC3))
        {
            // reject any dynupdate operation on a dnssec-maintained record.
            
            log_err("update: %{dnsname}: %{dnsname} manual add/del of %{dnstype} records refused", zone->origin, rname, &rtype);

            zone_diff_finalise(&diff);

            return SERVER_ERROR_CODE(RCODE_REFUSED);
        }

#if ZDB_HAS_NSEC3_SUPPORT // sanity checks
        // If the record is an NSEC3PARAM at the APEX
        if(rtype == TYPE_NSEC3PARAM)
        {
            if(!dnsname_equals_ignorecase(zone->origin, rname))
            {
                // reject adding NSEC3PARAM anywhere else than in the apex
                
                log_err("update: %{dnsname}: %{dnsname} NSEC3PARAM : type is only allowed in the apex", zone->origin, rname);
                
                zone_diff_finalise(&diff);

                return SERVER_ERROR_CODE(RCODE_REFUSED);
            }

            if(!ZONE_HAS_NSEC3PARAM(zone))
            {
                // don't add/del NSEC3PARAM on a zone that is not already NSEC3 (it works if the zone is not secure but only if the zone has keys already. So for now : disabled)
                
                log_err("update: %{dnsname}: %{dnsname} NSEC3PARAM add/del refused on an non-dnssec3 zone", zone->origin, rname);

                zone_diff_finalise(&diff);

                return SERVER_ERROR_CODE(RCODE_REFUSED);
            }
            else
            {
                if(NSEC3_RDATA_ALGORITHM(rdata) != NSEC3_DIGEST_ALGORITHM_SHA1)
                {
                    // don't touch an unsupported digest
                    
                    log_err("update: %{dnsname}: %{dnsname} NSEC3PARAM with unsupported digest algorithm %d", zone->origin, rname, NSEC3_RDATA_ALGORITHM(rdata));
      
                    zone_diff_finalise(&diff);

                    return SERVER_ERROR_CODE(RCODE_NOTIMP);
                }
                
                if(rclass == CLASS_ANY) // remove all
                {
                    // don't remove all NSEC3PARAMs from an NSEC3 zone
                    
                    log_err("update: %{dnsname}: %{dnsname} cannot remove all NSEC3PARAM of an NSEC3 zone", zone->origin, rname);

                    zone_diff_finalise(&diff);

                    return SERVER_ERROR_CODE(RCODE_REFUSED);
                }
                else if(rclass == CLASS_NONE) // remove one
                {
                    /// @note important: don't remove the first NSEC3PARAM from an NSEC3 zone if no other is available
                    ///       also note that given the new mechanisms, an NSEC3PARAM being added will not count as one until
                    ///       the whole chain has been created

                }
            }
        } // type == TYPE_NSEC3PARAM
#endif // ZDB_HAS_NSEC3_SUPPORT
        
        if(rclass == CLASS_NONE)
        {
            // delete from an rrset

            if(rttl != 0)
            {
                zone_diff_finalise(&diff);
                
                log_err("update: %{dnsname}: %{dnsname} record delete expected a TTL set to 0", zone->origin, rname);
                
                return SERVER_ERROR_CODE(RCODE_FORMERR);
            }
            
            if(name_path.size <= origin_path.size)
            {
                if((rtype == TYPE_SOA) || (rtype == TYPE_ANY))
                {
                    // refused
                    
                    zone_diff_finalise(&diff);
                    
                    return SERVER_ERROR_CODE(RCODE_REFUSED);
                }
            }

#ifdef DEBUG
            log_debug("update: %{dnsname}: delete %{dnsname} %{dnstype} any", zone->origin, rname, &rtype);
#endif
            zdb_rr_label* rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - origin_path.size) - 1);
            if(rr_label != NULL)
            {
#ifdef DEBUG
                if(RR_LABEL_IRRELEVANT(rr_label))
                {
                    log_debug("update: %{dnsname}: %{dnsname} is irrelevant (0)", zone->origin, rname);
                }
#endif
                zdb_packed_ttlrdata *rr;
                if((rr = zdb_record_find(&rr_label->resource_record_set, rtype)) != NULL)
                {
                    bool exists = FALSE;
                    do
                    {
                        if(ZDB_PACKEDRECORD_PTR_RDATASIZE(rr) == rdata_size)
                        {
                            if(memcmp(ZDB_PACKEDRECORD_PTR_RDATAPTR(rr), rdata, rdata_size) == 0)
                            {
                                exists = TRUE;
                                break;
                            }
                        }
                        rr = rr->next;
                    }
                    while(rr != NULL);
                    
                    if(exists)
                    {
                        if((rr_label != zone->apex) && (rtype == TYPE_NS))
                        {
                            // check if some non-glue records are becoming glues ...
                            // this is a delegation

                            if(dictionary_notempty(&rr_label->sub))
                            {
                                // add the labels below
                                zone_diff_add_fqdn_children(&diff, rname, rr_label);
                            }
                        }
                        
                        zone_diff_record_remove(&diff, rr_label, rname, rtype, rttl, rdata_size, rdata);
                    }
                    else
                    {
                        log_debug("update: %{dnsname}: delete %{dnsname} %{dnstype} NONE: no record match", zone->origin, rname, &rtype);
                    }
                }
                else
                {
                    log_debug("update: %{dnsname}: delete %{dnsname} %{dnstype} NONE: no type match", zone->origin, rname, &rtype);
                }
            }
            else
            {
                log_debug("update: %{dnsname}: delete %{dnsname} %{dnstype} NONE: no label match", zone->origin, rname, &rtype);
            }
        }
        else if(rclass == CLASS_ANY)
        {
            if((rttl != 0) || (rdata_size != 0))
            {
                zone_diff_finalise(&diff);

                return SERVER_ERROR_CODE(RCODE_FORMERR);
            }
            
            if(name_path.size <= origin_path.size)
            {
                if((rtype == TYPE_SOA) || (rtype == TYPE_ANY))
                {
                    // refused

                    zone_diff_finalise(&diff);

                    return SERVER_ERROR_CODE(RCODE_REFUSED);
                }
            }
            
            if(rtype != TYPE_ANY)
            {
                // delete an rrset

#ifdef DEBUG
                log_debug("update: %{dnsname}: delete %{dnsname} %{dnstype} ...", zone->origin, rname, &rtype);
#endif
                zdb_rr_label* rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - origin_path.size) - 1);
                if(rr_label != NULL)
                {
#ifdef DEBUG
                    if(RR_LABEL_IRRELEVANT(rr_label))
                    {
                        log_debug("update: %{dnsname}: %{dnsname} is irrelevant (1)", zone->origin, rname);
                    }
#endif
                    if(zdb_record_find(&rr_label->resource_record_set, rtype) != NULL)
                    {
                        if((rtype == TYPE_NS) && (rr_label != zone->apex))
                        {
                            // this is a delegation

                            if(dictionary_notempty(&rr_label->sub))
                            {
                                // add the labels below
                                zone_diff_add_fqdn_children(&diff, rname, rr_label);
                            }
                        }
                        
                        zone_diff_record_remove_all(&diff, rr_label, rname, rtype);
                    }
                    else
                    {
                        log_debug("update: %{dnsname}: delete %{dnsname} %{dnstype} ANY: no type match", zone->origin, rname, &rtype);
                    }
                }
                else
                {
                    log_debug("update: %{dnsname}: delete %{dnsname} %{dnstype} ANY: no label match", zone->origin, rname, &rtype);
                }
            }
            else
            {
                // delete all rrsets
                
#ifdef DEBUG
                log_debug("update: %{dnsname}: delete %{dnsname} %{dnstype} ...", zone->origin, rname, &rtype);
#endif
                zdb_rr_label* rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - origin_path.size) - 1);
                if(rr_label != NULL)
                {
#ifdef DEBUG
                    if(RR_LABEL_IRRELEVANT(rr_label))
                    {
                        log_debug("update: %{dnsname}: %{dnsname} is irrelevant (2)", zone->origin, rname);
                    }
#endif
                    if((rr_label != zone->apex) && (zdb_record_find(&rr_label->resource_record_set, TYPE_NS) != NULL))
                    {
                        // check if some non-glue records are becoming glues ...
                        // this is a delegation

                        if(dictionary_notempty(&rr_label->sub))
                        {
                            // add the labels below
                            zone_diff_add_fqdn_children(&diff, rname, rr_label);
                        }
                    }
                    
                    zone_diff_record_remove_all_sets(&diff, rr_label, rname);
                }
                else
                {
                    log_debug("update: %{dnsname}: delete %{dnsname} %{dnstype} ANY: no label match", zone->origin, rname, &rtype);
                }
            }
        }
        else
        {
            // add record to an rrset
            zdb_rr_label* rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - origin_path.size) - 1);
            zone_diff_record_add(&diff, rr_label, rname, rtype, rttl, rdata_size, rdata);
            
            if((rr_label != NULL) && (rtype == TYPE_NS) && (rr_label != zone->apex))
            {
                if(zdb_record_find(&rr_label->resource_record_set, TYPE_NS) == NULL)
                {
                    // check if some non-glue records are becoming glues ...
                    // this is a delegation
                    
                    if(dictionary_notempty(&rr_label->sub))
                    {
                        // add the labels below
                        zone_diff_add_fqdn_children(&diff, rname, rr_label);
                    }
                }
            }
        }
    }
    while(--count > 0);

    ret = SUCCESS;
    
    if(!dryrun)
    {
        ptr_vector add = EMPTY_PTR_VECTOR;
        ptr_vector del = EMPTY_PTR_VECTOR;
        
#ifdef DEBUG
        log_debug1("update: %{dnsname}: storing diff", zone->origin);
#endif
        
        zone_diff_store_diff(&diff, zone, &del, &add);
        
#ifdef DEBUG
        log_debug1("update: %{dnsname}: stored diff", zone->origin);
        
        for(int i = 0; i <= ptr_vector_last_index(&del); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&del, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            log_debug1("update: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int i = 0; i <= ptr_vector_last_index(&add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&add, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            log_debug1("update: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
        }
#endif
        
        changes_occurred = (ptr_vector_size(&add) + ptr_vector_size(&del)) > 2;
        
#ifdef DEBUG
        log_debug1("update: %{dnsname}: changes: %i", zone->origin, changes_occurred);
#endif
        
        if(changes_occurred)
        {
            // instead of storing to a buffer and back, could write an inputstream
            // translating the ptr_vector content on the fly
            
            s32 total = 0;
            
            for(int i = 0; i <= ptr_vector_last_index(&del); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&del, i);
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
                
                log_debug("update: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                
                total += dnsname_len(rr->fqdn);
                total += 10;
                total += rr->rdata_size;
            }
            
            for(int i = 0; i <= ptr_vector_last_index(&add); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&add, i);
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
                
                log_debug("update: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                
                total += dnsname_len(rr->fqdn);
                total += 10;
                total += rr->rdata_size;
            }
            
            output_stream baos;
            
            bytearray_output_stream_init(&baos, NULL, total);
            
            for(int i = 0; i <= ptr_vector_last_index(&del); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&del, i);
                /*
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
                log_debug("update: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                */
                output_stream_write_dnsname(&baos, rr->fqdn);
                output_stream_write_u16(&baos, rr->rtype);
                output_stream_write_u16(&baos, rr->rclass);
                output_stream_write_nu32(&baos, rr->ttl);
                output_stream_write_nu16(&baos, rr->rdata_size);
                output_stream_write(&baos, rr->rdata, rr->rdata_size);
            }
            
            for(int i = 0; i <= ptr_vector_last_index(&add); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&add, i);
                /*
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
                log_debug("update: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                */
                output_stream_write_dnsname(&baos, rr->fqdn);
                output_stream_write_u16(&baos, rr->rtype);
                output_stream_write_u16(&baos, rr->rclass);
                output_stream_write_nu32(&baos, rr->ttl);
                output_stream_write_nu16(&baos, rr->rdata_size);
                output_stream_write(&baos, rr->rdata, rr->rdata_size);
            }
            
            input_stream bais;
            
            bytearray_input_stream_init(&bais, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos), FALSE);
            
            journal* jnl = NULL;
            if(ISOK(ret = journal_acquire_from_zone_ex(&jnl, zone, TRUE)))
            {
                if(ISOK(ret = journal_append_ixfr_stream(jnl, &bais))) // writes a single page
                {                
                    log_debug("update: %{dnsname}: wrote %i bytes to the journal", zone->origin, total);
                    
                    bytearray_input_stream_reset(&bais);
            
                    u32 current_serial = 0;
                    
                    if(secondary_lock != 0)
                    {
                        zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, secondary_lock);
                    }
                    
                    ret = zdb_icmtl_replay_commit(zone, &bais, &current_serial);

                    if(secondary_lock != 0)
                    {
                        zdb_zone_exchange_locks(zone, secondary_lock, ZDB_ZONE_MUTEX_SIMPLEREADER);
                    }
                    
                    if(ISOK(ret))
                    {
                        log_debug("update: %{dnsname}: applied journal changes", zone->origin, total);
                    }
                    else
                    {
                        log_err("update: %{dnsname}: could not apply journal changes: %r", zone->origin, total, ret);
                    }
                }
                else
                {
                    log_err("update: %{dnsname}: could not write %i bytes to the journal: %r", zone->origin, total, ret);
                }
                
                journal_release(jnl);
            }
            
            zone_diff_label_rr_vector_clear(&del);
            zone_diff_label_rr_vector_clear(&add);
            
            input_stream_close(&bais);
            output_stream_close(&baos);
        }
        
        ptr_vector_destroy(&add);
        ptr_vector_destroy(&del);
    }
    
    log_debug("update: %{dnsname}: done", zone->origin);
    
    zone_diff_finalise(&diff);
    
    return ret;
}

/**
 * Initialises a simple update buffer
 * 
 * @param dmsg
 */

void
dynupdate_message_init(dynupdate_message *dmsg, const u8 *origin, u16 rclass)
{
    dmsg->size = MAX_U16;
    MALLOC_OR_DIE(u8*, dmsg->packet, dmsg->size, DMSGPCKT_TAG);
    // packet_writer_init is for valid messages.  For writing a new message use:
    packet_writer_create(&dmsg->pw, dmsg->packet, dmsg->size);
    dmsg->rclass = rclass;
    message_header *hdr = (message_header*)dmsg->packet;
#ifdef DEBUG
    memset(dmsg->packet, 0xcc, dmsg->size);
#endif
    ZEROMEMORY(hdr, DNS_HEADER_LENGTH);
    hdr->opcode = NU16(OPCODE_UPDATE);
    packet_writer_add_fqdn(&dmsg->pw, origin);
    packet_writer_add_u16(&dmsg->pw, TYPE_SOA);
    packet_writer_add_u16(&dmsg->pw, rclass);
    hdr->qdcount = NU16(1);
}

/**
 * Releases resources.
 * 
 * @param dmsg
 */

void
dynupdate_message_finalise(dynupdate_message *dmsg)
{
    //packet_writer_finalise(&dmsg->pw);
    free(dmsg->packet);
}

/**
 * Sets a reader up for the buffer.
 * 
 * @param dmsg
 * @param purd
 */

void
dynupdate_message_set_reader(dynupdate_message *dmsg, packet_unpack_reader_data *purd)
{
    yassert(dmsg->pw.packet_offset >= DNS_HEADER_LENGTH);
    
    packet_reader_init(purd, dmsg->packet, dmsg->pw.packet_offset);
}

/**
 * Return the number of update records.
 * 
 * @param dmsg
 * @return 
 */

u16
dynupdate_message_get_count(dynupdate_message *dmsg)
{
    message_header *hdr = (message_header*)dmsg->packet;
    u16 count = ntohs(hdr->nscount);
    return count;
}

/**
 * Adds a dnskey record to the buffer
 * 
 * @param dmsg
 * @param ttl
 * @param key
 * @return 
 */

ya_result
dynupdate_message_add_dnskey(dynupdate_message *dmsg, s32 ttl, dnssec_key *key)
{
    u32 rdata_size = key->vtbl->dnskey_key_rdatasize(key);
    u32 remaining = packet_writer_get_remaining_capacity(&dmsg->pw);
    
    ya_result ret = ERROR;
    
    // the first 2 is assuming compression will take place
    // which is as it should be since the messages are initialised with the fqdn of the zone
        
    if(remaining >= 2 + 2 + 2 + 4 + 2 + rdata_size)
    {
        if(ISOK(ret = packet_writer_add_fqdn(&dmsg->pw, &dmsg->packet[DNS_HEADER_LENGTH])))
        {
            packet_writer_add_u16(&dmsg->pw, TYPE_DNSKEY);
            packet_writer_add_u16(&dmsg->pw, dmsg->rclass);
            packet_writer_add_u32(&dmsg->pw, htonl(ttl));
            packet_writer_add_u16(&dmsg->pw, htons(rdata_size));
            key->vtbl->dnskey_key_writerdata(key, packet_writer_get_next_u8_ptr(&dmsg->pw));
            packet_writer_forward(&dmsg->pw, rdata_size);
            message_header *hdr = (message_header*)dmsg->packet;
            hdr->nscount = htons(ntohs(hdr->nscount) + 1);
        }
    }
    
    return ret;
}

/**
 * Deletes a dnskey record to the buffer
 * 
 * @param dmsg
 * @param ttl
 * @param key
 * @return 
 */

ya_result
dynupdate_message_del_dnskey(dynupdate_message *dmsg, dnssec_key *key)
{
    u32 rdata_size = key->vtbl->dnskey_key_rdatasize(key);
    u32 remaining = packet_writer_get_remaining_capacity(&dmsg->pw);
    
    ya_result ret = ERROR;
        
    if(remaining >= 2 + 2 + 2 + 4 + 2 + rdata_size)
    {
        if(ISOK(ret = packet_writer_add_fqdn(&dmsg->pw, &dmsg->packet[DNS_HEADER_LENGTH])))
        {
            packet_writer_add_u16(&dmsg->pw, TYPE_DNSKEY);
            packet_writer_add_u16(&dmsg->pw, CLASS_NONE);
            packet_writer_add_u32(&dmsg->pw, 0);
            packet_writer_add_u16(&dmsg->pw, htons(rdata_size));
            key->vtbl->dnskey_key_writerdata(key, packet_writer_get_next_u8_ptr(&dmsg->pw));
            packet_writer_forward(&dmsg->pw, rdata_size);
            message_header *hdr = (message_header*)dmsg->packet;
            hdr->nscount = htons(ntohs(hdr->nscount) + 1);
        }
    }
    
    return ret;
}

/**
 * Appends a "add RR" command to the buffer.
 * 
 * @param dmsg
 * @param fqdn
 * @param rtype
 * @param ttl
 * @param rdata_size
 * @param rdata
 * @return 
 */

ya_result
dynupdate_message_add_record(dynupdate_message *dmsg, const u8 *fqdn, u16 rtype, s32 ttl, u16 rdata_size, void *rdata)
{
    ya_result ret;
    if(ISOK(ret = packet_writer_add_record(&dmsg->pw, fqdn, rtype, dmsg->rclass, ttl, rdata, rdata_size)))
    {
        message_header *hdr = (message_header*)dmsg->packet;
        hdr->nscount = htons(ntohs(hdr->nscount) + 1);
    }
    return ret;
}

/**
 * Appends a "delete RR" command to the buffer.
 * 
 * @param dmsg
 * @param fqdn
 * @param rtype
 * @param ttl
 * @param rdata_size
 * @param rdata
 * @return 
 */

ya_result
dynupdate_message_del_record(dynupdate_message *dmsg, const u8 *fqdn, u16 rtype, s32 ttl, u16 rdata_size, void *rdata)
{
    ya_result ret;
    if(ISOK(ret = packet_writer_add_record(&dmsg->pw, fqdn, rtype, TYPE_NONE, ttl, rdata, rdata_size)))
    {
        message_header *hdr = (message_header*)dmsg->packet;
        hdr->nscount = htons(ntohs(hdr->nscount) + 1);
    }
    return ret;
}

/**
 * 
 * Appends a "delete RRSET" command to the buffer.
 * 
 * @param dmsg
 * @param fqdn
 * @param rtype
 * @return 
 */

ya_result
dynupdate_message_del_record_set(dynupdate_message *dmsg, const u8 *fqdn, u16 rtype)
{
    ya_result ret;
    if(ISOK(ret = packet_writer_add_record(&dmsg->pw, fqdn, rtype, TYPE_ANY, 0, NULL, 0)))
    {
        message_header *hdr = (message_header*)dmsg->packet;
        hdr->nscount = htons(ntohs(hdr->nscount) + 1);
    }
    return ret;
}

/**
 * Appends a "delete fqdn" command to the buffer.
 * 
 * @param dmsg
 * @param fqdn
 * @return 
 */

ya_result
dynupdate_message_del_fqdn(dynupdate_message *dmsg, const u8 *fqdn)
{
    ya_result ret;
    if(ISOK(ret = packet_writer_add_record(&dmsg->pw, fqdn, TYPE_ANY, TYPE_ANY, 0, NULL, 0)))
    {
        message_header *hdr = (message_header*)dmsg->packet;
        hdr->nscount = htons(ntohs(hdr->nscount) + 1);
    }
    return ret;
}

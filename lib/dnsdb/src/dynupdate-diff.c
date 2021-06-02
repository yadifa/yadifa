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
#include <dnsdb/zdb-zone-maintenance.h>

#include "dnsdb/dnssec.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/dnssec-keystore.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/dynupdate-diff.h"
#include "dnsdb/zdb-zone-path-provider.h"
#include "dnsdb/zdb_icmtl.h"
#if HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif

#define ZDB_JOURNAL_CODE 1
#include "dnsdb/journal.h"

#define MODULE_MSG_HANDLE g_database_logger
extern logger_handle *g_database_logger;

// Disable detailed diff log even in debug builds

#define DYNUPDATE_DIFF_DETAILED_LOG 0

#ifndef DYNUPDATE_DIFF_DETAILED_LOG
#if DEBUG
#define DYNUPDATE_DIFF_DETAILED_LOG 1
#else
#define DYNUPDATE_DIFF_DETAILED_LOG 0
#endif
#endif

#if DYNUPDATE_DIFF_DETAILED_LOG
#pragma message("WARNING: DYNUPDATE_DIFF_DETAILED_LOG is not set to 0")
#endif

#define DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG 0

#ifndef DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
#if DEBUG
#define DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG 1
#else
#define DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG 0
#endif
#endif

#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
#pragma message("WARNING: DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG is not set to 0")
#endif

///////////////////////////////////////////////////////////////////////////////

static char zone_diff_record_state_format_letters[6] = {'+','-','O','V','E','A'};

void
zone_diff_record_state_format(const void* data, output_stream* os, s32 a, char b , bool c, void* reserved_for_method_parameters)
{
    (void)a;
    (void)b;
    (void)c;
    (void)reserved_for_method_parameters;

    u8 state = *((u8*)data);
    for(u32 i = 0; i < sizeof(zone_diff_record_state_format_letters); ++i)
    {
        char c = ((state & (1 << i)) != 0)?zone_diff_record_state_format_letters[i]:'_';
        output_stream_write(os, &c, 1);
    }
}

#if DEBUG
static char zone_diff_chain_state_format_letters[8] = {'+','-',' ','r','E','{','}','!'};

static void
zone_diff_chain_state_format(const void* data, output_stream* os, s32 a, char b , bool c, void* reserved_for_method_parameters)
{
    (void)a;
    (void)b;
    (void)c;
    (void)reserved_for_method_parameters;

    u8 state = *((u8*)data);
    for(u32 i = 0; i < sizeof(zone_diff_chain_state_format_letters); ++i)
    {
        char c = ((state & (1 << i)) != 0)?zone_diff_chain_state_format_letters[i]:'_';
        output_stream_write(os, &c, 1);
    }
}
#endif

static void
zone_diff_fqdn_changes_format(const void* data, output_stream* os, s32 a, char b , bool c, void* reserved_for_method_parameters)
{
    (void)a;
    (void)b;
    (void)c;
    (void)reserved_for_method_parameters;

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
    
    output_stream_write(os, "RECORDS(", 8);
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
    ptr_set_init(&dc->chain_diff);
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
#if DEBUG
        log_debug("NEW NODE %{dnsname} (0)", fqdn);
#endif
        void *chain_node = dc->chain->node_new(fqdn, chain);

        ptr_node *node = ptr_set_insert(&dc->chain_diff, chain_node);
        
        // if chain is not empty, edit it, else create it with one node
        
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
                ptr_node *node_prev = ptr_set_insert(&dc->chain_diff, chain_begin);
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
                ptr_node *node_next = ptr_set_insert(&dc->chain_diff, chain_end);
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


    (void)diff_fqdn;
    (void)chain_index;

    void *chain_begin = dc->chain->node_prev(chain_node);
    yassert(chain_begin != NULL);
#if DEBUG
    format_writer chain_node_prev_fw;
    dc->chain->format_writer_init(chain_begin, &chain_node_prev_fw);
#endif
    ptr_node *node_prev = ptr_set_insert(&dc->chain_diff, chain_begin);
    if(node_prev->value == NULL)
    {
        node_prev->value = chain_begin;
#if DEBUG
        log_debug2("dnssec-chain: %{dnsname}: chain[%i]: previous node is %w", diff_fqdn->fqdn, chain_index, &chain_node_prev_fw);
#endif
    }
    else
    {
#if DEBUG
        log_debug2("dnssec-chain: %{dnsname}: chain[%i]: previous node %w already in chain, merging", diff_fqdn->fqdn, chain_index, &chain_node_prev_fw);
#endif
        dc->chain->node_merge(node_prev->value, chain_begin);
#if DEBUG
        dc->chain->format_writer_init(node_prev->value, &chain_node_prev_fw);
        log_debug2("dnssec-chain: %{dnsname}: chain[%i]: previous node %w merged", diff_fqdn->fqdn, chain_index, &chain_node_prev_fw);
#endif
    }

    void *chain_end = dc->chain->node_next(chain_node);
    yassert(chain_end != NULL);
#if DEBUG
    format_writer chain_node_next_fw;
    dc->chain->format_writer_init(chain_end, &chain_node_next_fw);
#endif
    ptr_node *node_next = ptr_set_insert(&dc->chain_diff, chain_end);
    if(node_next->value == NULL)
    {
#if DEBUG
        log_debug2("dnssec-chain: %{dnsname}: chain[%i]: next node is %w", diff_fqdn->fqdn, chain_index, &chain_node_next_fw);
#endif
        node_next->value = chain_end;
    }
    else
    {
#if DEBUG
        log_debug2("dnssec-chain: %{dnsname}: chain[%i]: next node %w already in chain, merging", diff_fqdn->fqdn, chain_index, &chain_node_next_fw);
#endif
        dc->chain->node_merge(node_next->value, chain_end);
#if DEBUG
        dc->chain->format_writer_init(node_next->value, &chain_node_next_fw);
        log_debug2("dnssec-chain: %{dnsname}: chain[%i]: next node %w merged", diff_fqdn->fqdn, chain_index, &chain_node_next_fw);
#endif
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
#if DEBUG
                log_debug2("dnssec-chain: %{dnsname}: chain[%i]: did not cover", diff_fqdn->fqdn, chain_index);
#endif
                continue;
            }

        }
        else
        {
            if(!dc->chain->fqdn_is_covered(diff_fqdn))
            {
#if DEBUG
                log_debug2("dnssec-chain: %{dnsname}: chain[%i]: does not covers", diff_fqdn->fqdn, chain_index);
#endif
                continue;
            }
        }
        
#if DEBUG
        log_debug2("dnssec-chain: %{dnsname}: chain[%i]: covers", diff_fqdn->fqdn, chain_index);
#endif
        
        //
        
#if DEBUG
        log_debug3("NEW NODE %{dnsname} (1)", diff_fqdn->fqdn);
#endif
      
        void *chain_node = dc->chain->node_new(diff_fqdn->fqdn, chain);
        
#if DEBUG
        format_writer chain_node_fw;
        dc->chain->format_writer_init(chain_node, &chain_node_fw);
        log_debug2("dnssec-chain: %{dnsname}: chain[%i]: node is %w", diff_fqdn->fqdn, chain_index, &chain_node_fw);
#endif

        ptr_node *node = ptr_set_insert(&dc->chain_diff, chain_node);
        
        if(!dc->chain->isempty(chain))
        {
            u8 or_mask = (!dc->chain_being_deleted[chain_index])?asked_or_mask:DNSSEC_CHAIN_DELETE;

            if(node->value == NULL)
            {
#if DEBUG
                log_debug2("dnssec-chain: %{dnsname}: chain[%i]: node %w is new, getting both neighbours", diff_fqdn->fqdn, chain_index, &chain_node_fw);
#endif
                node->value = chain_node;

                // create a node for the prev & next

                dnssec_chain_add_node_neighbours(dc, diff_fqdn, chain_node, chain_index);
            }
            else
            {
#if DEBUG
                log_debug2("dnssec-chain: %{dnsname}: chain[%i]: node %w already exists", diff_fqdn->fqdn, chain_index, &chain_node_fw);
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
#if DEBUG
            log_debug("dnssec-chain: %{dnsname}: chain[%i] was empty", diff_fqdn->fqdn, chain_index);
#endif
            // instead of the doing diff computations the chain will be fully created
            
            if(node->value != NULL)
            {
#if DEBUG
                log_debug("dnssec-chain: %{dnsname}: chain[%i]: node %w already exists", diff_fqdn->fqdn, chain_index, &chain_node_fw);
#endif
                // node exists already ...
                assert(dc->chain->compare(node->value, chain_node) == 0);
                
                dc->chain->node_merge(node->value, chain_node);
                dc->chain->state_set(node->value, dc->chain->state_get(node->value) & ~(DNSSEC_CHAIN_BEGIN|DNSSEC_CHAIN_END));
            }
            else
            {
                node->value = chain_node;
            }
               
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

        s32 maxinterval = diff_generate_signature_interval(diff);

        // rrset_to_sign;
        if(ISOK(ret = dnskey_sign_rrset_with_maxinterval(key, &rrset, canonize, &rrv, maxinterval, (void **) &rrsig_rr)))
        {
            canonize = FALSE;

            // add the key to the add set

            rdata_desc rdt = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
            log_debug("update: %{dnsname}: signed chain rrset %{dnstype} with key %03d %05d: %{dnsname} %i %{dnsclass} %{typerdatadesc}",
                    diff->origin, &rrset_type, dnskey_get_algorithm(key), dnskey_get_tag_const(key),
                    rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr->rclass, &rdt
                    );

            rrsig_rr->state |= ZONE_DIFF_RR_VOLATILE;
            ptr_vector_append(add, rrsig_rr);
            
            // since we are mapping inside the array and the array could have been replaced by a bigger one ...
            rrset.data = &add->data[from_offset];
        }
#if DEBUG
        else
        {
            log_debug("update: %{dnsname}: did not sign rrset %{dnstype} with key %03d %05d: %r",
                diff->origin, &rrset_type, dnskey_get_algorithm(key), dnskey_get_tag_const(key), ret);
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

        // gather all the nodes in the chain in an array
        // they are inserted in sorted order (ptr_set_iterator does this)

        ptr_set_iterator iter;
        ptr_set_iterator_init(&dc->chain_diff, &iter);
        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *node = ptr_set_iterator_next_node(&iter);
            yassert(node->value != NULL);
            ptr_vector_append(&nodes, node->value);
        }

        // look in a circular pattern for all the nodes that have the "delete" status
        
        log_debug("update: %{dnsname}: %i nodes in dnssec chain #%i", diff->origin, ptr_vector_size(&nodes), chain_index);
        
        if(ptr_vector_size(&nodes) == 0)
        {
            continue;
        }
        
#if DEBUG
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
        
        int first_begin = -1; // the first chain node at the begin of a change
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

                yassert(first_begin >= 0);

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
        
#if DEBUG
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

                if(state & DNSSEC_CHAIN_EXISTS)
                {
                    if((state & DNSSEC_CHAIN_REMAP) || ((state & (DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_ADD)) == (DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_ADD)))
                    {
#if DEBUG
                        log_debug3("update: %{dnsname}: chain %i state (%02x) del/add", diff->origin, chain_index, state);
#endif
                        dc->chain->publish_delete(chain, node, node_next, diff, del);
                        dnssec_chain_store_diff_publish_chain_node(dc, diff, keys, chain, node, node_next, add);
                    }
                    else if(state & DNSSEC_CHAIN_DELETE)
                    {
#if DEBUG
                        log_debug3("update: %{dnsname}: chain %i state (%02x) del", diff->origin, chain_index, state);
#endif
                        dc->chain->publish_delete(chain, node, node_next, diff, del);
                    }
                }
                else
                {
                    if((state & DNSSEC_CHAIN_EXISTS) == 0)
                    {
                        state &= ~DNSSEC_CHAIN_DELETE;      // cannot delete what does not exists
                        if(state & DNSSEC_CHAIN_REMAP)
                        {
                            state &= ~DNSSEC_CHAIN_REMAP;   // do not remap, create
                            state |= DNSSEC_CHAIN_ADD;
                        }

                        dc->chain->state_set(node, state);
                    }

                    if(state & DNSSEC_CHAIN_ADD)
                    {
#if DEBUG
                        log_debug3("update: %{dnsname}: chain %i state (%02x) add", diff->origin, chain_index, state);
#endif
                        dnssec_chain_store_diff_publish_chain_node(dc, diff, keys, chain, node, node_next, add);
                    }
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

            if((state & DNSSEC_CHAIN_EXISTS) == 0)
            {
                state &= ~DNSSEC_CHAIN_DELETE;      // cannot delete what does not exists
                if(state & DNSSEC_CHAIN_REMAP)
                {
                    state &= ~DNSSEC_CHAIN_REMAP;   // do not remap, create
                    state |= DNSSEC_CHAIN_ADD;
                }

                dc->chain->state_set(node, state);
            }
            
            if(state & (DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_REMAP))
            {
#if DEBUG
                if((state & DNSSEC_CHAIN_EXISTS) == 0)
                {
                    format_writer chain_node_fw;
                    dc->chain->format_writer_init(node, &chain_node_fw);
                    format_writer temp_fw_0 = {zone_diff_chain_state_format, &state};
                    log_err("dnssec-chain: %{dnsname}: chain %i node %w with state %w should be remapped or deleted but does not exist ?",
                        diff->origin, chain_index, &chain_node_fw, &temp_fw_0);
                    logger_flush();
                }
#endif
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

#if DEBUG
                    log_debug3("update: %{dnsname}: chain %i state (%02x) publish chain node", diff->origin, chain_index, state);
#endif
                    
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

void dnssec_chain_finalize(dnssec_chain *dc)
{
    ptr_set_callback_and_destroy(&dc->chain_diff, dc->chain->ptr_set_node_delete_callback);
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
        rr->state = ZONE_DIFF_RR_RDATA_OWNED;
    }
    else
    {
        rr->rdata = rdata;
        rr->state = 0;
    }
    return rr;
}

void
zone_diff_label_rr_init_tmp(zone_diff_label_rr *rr, const u8 *fqdn, u16 rtype, u16 rclass, s32 ttl, void *rdata, u16 rdata_size)
{
    rr->fqdn = (u8*)fqdn;
    rr->ttl = ttl;
    rr->rtype = rtype;
    rr->rclass = rclass;
    rr->rdata_size = rdata_size;
    rr->rdata = rdata;
    rr->state = 0;
}

zone_diff_label_rr *
zone_diff_label_rr_new_nordata(const u8 *fqdn, u16 rtype, u16 rclass, s32 ttl, u16 rdata_size)
{
    zone_diff_label_rr *rr;
    ZALLOC_OBJECT_OR_DIE(rr, zone_diff_label_rr, ZDFFLABL_TAG);
    rr->fqdn = dnsname_zdup(fqdn);
    rr->ttl = ttl;
    rr->rtype = rtype;
    rr->rclass = rclass;
    rr->rdata_size = rdata_size;
    ZALLOC_ARRAY_OR_DIE(u8*, rr->rdata, rdata_size, ZDFFLBRR_TAG);
    rr->state = ZONE_DIFF_RR_RDATA_OWNED;

    return rr;
}

static void zone_diff_label_rr_delete(zone_diff_label_rr *rr)
{
    dnsname_zfree(rr->fqdn);
    
    if(rr->state & ZONE_DIFF_RR_RDATA_OWNED)
    {
#if DEBUG
        memset(rr->rdata, 0xff, rr->rdata_size);
#endif
        ZFREE_ARRAY(rr->rdata, rr->rdata_size);
    }
#if DEBUG
    memset(rr, 0xff, sizeof(zone_diff_label_rr));
#endif
    ZFREE_OBJECT(rr);
}

static void zone_diff_label_rr_vector_clear(ptr_vector *records)
{
    for(int i = 0; i <= ptr_vector_last_index(records); ++i)
    {
        zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(records, i);
        if((rr->state & ZONE_DIFF_RR_VOLATILE) != 0)
        {
            zone_diff_label_rr_delete(rr);
        }
    }
    ptr_vector_clear(records);
}

zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_set_new(u16 rtype)
{
    zone_diff_fqdn_rr_set *rr_set;
    ZALLOC_OBJECT_OR_DIE(rr_set, zone_diff_fqdn_rr_set, ZDFFRRST_TAG);
    ptr_set_init(&rr_set->rr);
    rr_set->rr.compare = zone_diff_label_rr_compare;
    rr_set->key_mask = 0;
    rr_set->org_ttl = -1;
    rr_set->new_ttl = -1;
    rr_set->rtype = rtype;
    rr_set->rclass = CLASS_IN;
    return rr_set;
}

static void zone_diff_fqdn_rr_set_delete_cb(ptr_node *node)
{
    zone_diff_label_rr *rr = (zone_diff_label_rr*)node->value;
#if DEBUG
    log_debug7("update: %{dnsname}: deleting %{dnstype} structure", rr->fqdn, &rr->rtype);
#endif
    zone_diff_label_rr_delete(rr);
}

static void zone_diff_fqdn_rr_set_delete(zone_diff_fqdn_rr_set *rr_set)
{
    if(rr_set != NULL)
    {
        ptr_set_callback_and_destroy(&rr_set->rr, zone_diff_fqdn_rr_set_delete_cb);
        ZFREE_OBJECT(rr_set);
    }
}

void zone_diff_fqdn_rr_set_rr_add_replace(zone_diff_fqdn_rr_set *rr_set, zone_diff_label_rr *rr)
{
    ptr_node *node = ptr_set_insert(&rr_set->rr, rr);
    
    if(node->value == NULL)
    {
        node->value = rr;
    }
    else
    {
        zone_diff_label_rr_delete((zone_diff_label_rr*)node->value);
        node->key = rr;
        node->value = rr;
    }
}

zone_diff_label_rr*
zone_diff_fqdn_rr_set_rr_add_get(zone_diff_fqdn_rr_set *rr_set, zone_diff_label_rr *rr)
{
    ptr_node *node = ptr_set_insert(&rr_set->rr, rr);

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

static zone_diff_label_rr *
zone_diff_fqdn_rr_set_get_existing_rr(zone_diff_fqdn_rr_set *rr_set, const zone_diff_label_rr *rr)
{
    ptr_node *node = ptr_set_find(&rr_set->rr, rr);

    if(node != NULL)
    {
        return (zone_diff_label_rr*)node->value;
    }

    return NULL;
}

//

static zone_diff_fqdn *zone_diff_fqdn_new(const u8 *fqdn)
{
    zone_diff_fqdn *diff_fqdn;
    ZALLOC_OBJECT_OR_DIE(diff_fqdn, zone_diff_fqdn, ZDFFFQDN_TAG);
    memset(diff_fqdn, 0, sizeof(zone_diff_fqdn));
    u32_set_init(&diff_fqdn->rrset);
    diff_fqdn->fqdn = dnsname_zdup(fqdn);
    //diff_fqdn->type_map_changed = FALSE;
    return diff_fqdn;
}

static void zone_diff_fqdn_delete_cb(u32_node *node)
{
    zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)node->value;
#if DEBUG
    if(rrset == NULL)
    {
        u16 rtype = (u16)node->key;
        log_debug1("zone_diff_fqdn_delete_cb empty set for type %{dnstype}", &rtype);
    }
#endif
    zone_diff_fqdn_rr_set_delete(rrset);
}

static void zone_diff_fqdn_delete(zone_diff_fqdn *diff_fqdn)
{
    u32_set_callback_and_destroy(&diff_fqdn->rrset, zone_diff_fqdn_delete_cb);
    
#if DEBUG
    log_debug1("update: %{dnsname}: deleting diff fqdn", diff_fqdn->fqdn);
#endif
    dnsname_zfree(diff_fqdn->fqdn);
    ZFREE_OBJECT(diff_fqdn);
}

zone_diff_fqdn_rr_set*
zone_diff_fqdn_rr_set_add(zone_diff_fqdn *diff_fqdn, u16 rtype)
{
    u32_node *node = u32_set_insert(&diff_fqdn->rrset, rtype);
    if(node->value == NULL)
    {
        node->value = zone_diff_fqdn_rr_set_new(rtype);
    }
    return (zone_diff_fqdn_rr_set*)node->value;
}

/**
 * Returns the local copy of the specified RRSET
 * Creates an emtpy set if it does not exist.
 * 
 * @param diff_fqdn
 * @param rtype
 * @return 
 */

zone_diff_fqdn_rr_set *
zone_diff_fqdn_rr_set_get(const zone_diff_fqdn *diff_fqdn, u16 rtype)
{
#if 0 /* fix */
#else
    u32_node *node = u32_set_find(&diff_fqdn->rrset, rtype);
    if(node != NULL)
    {
        return (zone_diff_fqdn_rr_set*)node->value;
    }
    return NULL;
#endif
}

/**
 * Returns the local copy of the specified RRSET
 *
 * @param diff_fqdn
 * @param rtype
 * @return
 */

const zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_get_const(const zone_diff_fqdn *diff_fqdn, u16 rtype)
{
    u32_node *node = u32_set_find(&diff_fqdn->rrset, rtype);

    if(node != NULL)
    {
        return (zone_diff_fqdn_rr_set*)node->value;
    }

    return NULL;
}

s32
zone_diff_fqdn_rr_set_get_ttl(zone_diff_fqdn_rr_set *rrset)
{
    // @note 20170228 edf -- issue detection
    // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
    // the intent of putting records in it.
    // Find it and call zone_diff_will_have_rrset_type instead.
    yassert(rrset != NULL);

    ptr_set_iterator rr_iter;
    ptr_set_iterator_init(&rrset->rr, &rr_iter);
    while(ptr_set_iterator_hasnext(&rr_iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

        if((rr->state & ZONE_DIFF_RR_REMOVE) == 0)
        {
            // this record was present or is being added
            return rr->ttl;
        }
    }

    return -1;
}

s32
zone_diff_fqdn_rr_get_ttl(const zone_diff_fqdn *diff_fqdn, u16 rtype)
{
    s32 ttl = -1;
    u32_node *rrset_node = u32_set_find(&diff_fqdn->rrset, rtype);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)rrset_node->value;
        ttl = zone_diff_fqdn_rr_set_get_ttl(rrset);
    }
    return ttl;  // TTL is signed, 32 bits and >= 0
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
    u32_node *node = u32_set_insert(&diff_fqdn->rrset, rtype);
    if(node != NULL)
    {
        if(node->value == NULL)
        {
            u32_set_delete(&diff_fqdn->rrset, rtype);
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
    if(diff_fqdn->rrsig_kept == 0)
    {
        if(diff_fqdn->rrsig_added || diff_fqdn->rrsig_removed)
        {
            return TRUE;        // RRSIG type bitmap has changed;
        }
    }

    u32_set_iterator iter;
    ptr_set_iterator rr_iter;
    
    u32_set_iterator_init(&diff_fqdn->rrset, &iter);
    while(u32_set_iterator_hasnext(&iter))
    {
        u32_node *node = u32_set_iterator_next_node(&iter);
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)node->value;
        if(rrset != NULL)
        {
            ptr_set_iterator_init(&rrset->rr, &rr_iter);
            u8 rr_state = 0;
            while(ptr_set_iterator_hasnext(&rr_iter))
            {
                ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->key;

                if(rr->state == 0)
                {
                    // previously existing record : no change on this set
                    rr_state = 0;
                    break;
                }

                rr_state |= rr->state & (ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_ADD);
            }

            if((rr_state != 0) && ((rr_state & (ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_ADD)) != (ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_ADD)))
            {
                // this set is completely added or completely removed

                if(rrset->rtype != TYPE_RRSIG) // exceptional test
                {
                    return TRUE;
                }
                else
                {
                    if(!diff_fqdn->is_apex)
                    {
                        if(diff_fqdn->has_active_zsk)
                        {
                            rr_state |= ZONE_DIFF_RR_ADD;

                            if((rr_state != 0) && ((rr_state & (ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_ADD)) != (ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_ADD)))
                            {
                                return TRUE;
                            }
                        }
                    }
                    else
                    {
                        if(diff_fqdn->has_active_zsk||diff_fqdn->has_active_ksk)
                        {
                            rr_state |= ZONE_DIFF_RR_ADD;

                            if((rr_state != 0) && ((rr_state & (ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_ADD)) != (ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_ADD)))
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
 * Initialises a zone diff
 * 
 * @param diff
 * @param origin
 * @param nttl
 */

void zone_diff_init(zone_diff *diff, zdb_zone *zone, bool rrsig_update_allowed)
{
    log_debug1("update: %{dnsname}: initialising diff @%p", zone->origin, diff);

    ptr_set_init(&diff->fqdn);
    ptr_set_init(&diff->root.sub);
    diff->root.sub.compare = ptr_set_dnslabel_node_compare;
    diff->fqdn.compare = ptr_set_fqdn_node_compare;
    diff->origin = zone->origin;

    diff->rrsig_validity_interval = MAX(zone->sig_validity_interval_seconds, 0);
    diff->rrsig_validity_regeneration = MAX(zone->sig_validity_regeneration_seconds, 0);
    diff->rrsig_validity_jitter = MAX( zone->sig_validity_jitter_seconds, 0);
    diff->nttl = zone->min_ttl;
    diff->rrsig_update_allowed = rrsig_update_allowed;
    diff->has_active_zsk = FALSE;
    diff->has_active_ksk = FALSE;

    u8 maintain_mode = zone_get_maintain_mode(zone);

    switch(maintain_mode)
    {
        case ZDB_ZONE_MAINTAIN_NSEC3:
        case ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:
        {
            diff->maintain_nsec = FALSE;
            diff->maintain_nsec3 = TRUE;
            break;
        }
        case ZDB_ZONE_MAINTAIN_NSEC:
        {
            diff->maintain_nsec = TRUE;
            diff->maintain_nsec3 = FALSE;
            break;
        }
        default:
        {
            diff->maintain_nsec = FALSE;
            diff->maintain_nsec3 = FALSE;
            break;
        }
    }

    // NOTE: set the apex at the end of the function

    diff->apex = zone_diff_fqdn_add(diff, zone->origin, zone->apex);
}

static zone_diff_label_tree*
zone_diff_label_tree_add_fqdn(zone_diff *diff, const u8 *fqdn)
{
#if DEBUG
    log_debug2("zone-diff: %{dnsname}: label tree add %{dnsname}", diff->origin, fqdn);
#endif
    
    if(fqdn[0] != 0)
    {
        zone_diff_label_tree *label_node;
        ptr_node *label_tree_node;
        const u8 *parent_fqdn = fqdn + fqdn[0] + 1;
        zone_diff_label_tree *parent = zone_diff_label_tree_add_fqdn(diff, parent_fqdn);
        
        label_tree_node = ptr_set_insert(&parent->sub, (u8*)fqdn);
        
        if(label_tree_node->value != NULL)
        {
            label_node = (zone_diff_label_tree*)label_tree_node->value;
        }
        else
        {
            ZALLOC_OBJECT_OR_DIE(label_node, zone_diff_label_tree, ZDLABELT_TAG);
            label_node->label = fqdn;
            label_node->diff_fqdn = zone_diff_fqdn_get(diff, fqdn);
            ptr_set_init(&label_node->sub);
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

static void zone_diff_label_tree_destroy_cb(ptr_node* node)
{
    zone_diff_label_tree* dlt = (zone_diff_label_tree*)node->value;
    if(dlt != NULL)
    {
        if(!ptr_set_isempty(&dlt->sub))
        {
            ptr_set_callback_and_destroy(&dlt->sub, zone_diff_label_tree_destroy_cb);
        }
        ZFREE_OBJECT(dlt);
    }
}

static void zone_diff_label_tree_destroy(zone_diff *diff)
{
    ptr_set_callback_and_destroy(&diff->root.sub, zone_diff_label_tree_destroy_cb);
}

static zone_diff_label_tree*
zone_diff_fqdn_label_find(zone_diff_label_tree* parent, const u8 *fqdn)
{
    if(fqdn[0] != 0)
    {
        parent = zone_diff_fqdn_label_find(parent, fqdn + fqdn[0] + 1);
        if(parent != NULL)
        {
            ptr_node *node = ptr_set_find(&parent->sub, fqdn);
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
    u8 ret;

    if(parent->diff_fqdn != NULL)
    {
        ret = parent->diff_fqdn->is_apex;

        if(parent->diff_fqdn->children_flags_set)
        {
            ret |= parent->diff_fqdn->will_be_non_empty | parent->diff_fqdn->will_have_children;
#if DYNUPDATE_DIFF_DETAILED_LOG
            log_debug3("zone_diff_fqdn_children_state_find(%{dnsname}) = %x (already known)", parent->diff_fqdn->fqdn, ret);
#endif
            return ret;
        }
    }
    else
    {
        ret = 0;
    }

    ptr_set_iterator iter;
    ptr_set_iterator_init(&parent->sub, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node* node = ptr_set_iterator_next_node(&iter);
        
        zone_diff_label_tree* fqdn_node = (zone_diff_label_tree*)node->value;

        if(fqdn_node->diff_fqdn != NULL)
        {
            if(!fqdn_node->diff_fqdn->children_flags_set)
            {
                if(!ptr_set_isempty(&fqdn_node->sub))
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
            if(!ptr_set_isempty(&fqdn_node->sub))
            {
                if(zone_diff_fqdn_children_state_find(fqdn_node) != 0)
                {
                    ret |= ZONE_DIFF_FQDN_LABEL_STATE_CHILDREN;
                }
            }
        }
    }

#if DYNUPDATE_DIFF_DETAILED_LOG
    log_debug3("zone_diff_fqdn_children_state_find(%{dnsname}) = %x", parent->diff_fqdn->fqdn, ret);
#endif
    
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

static void zone_diff_finalize_cb(ptr_node *node)
{
    zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)node->value;
    zone_diff_fqdn_delete(diff_fqdn);
}

void zone_diff_finalize(zone_diff *diff)
{
    log_debug1("update: %{dnsname}: deleting diff @%p", diff->origin, diff);
    zone_diff_label_tree_destroy(diff);
    ptr_set_callback_and_destroy(&diff->fqdn, zone_diff_finalize_cb);
}

zone_diff_fqdn*
zone_diff_fqdn_add_empty(zone_diff *diff, const u8 *fqdn)
{
    ptr_node *node = ptr_set_insert(&diff->fqdn, (u8*)fqdn);

    if(node->value == NULL)
    {
#if DEBUG
        log_debug2("update: %{dnsname} ...", fqdn);
#endif

        zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_new(fqdn);
        node->key = diff_fqdn->fqdn; // to guarantee the const
        node->value = diff_fqdn;
    }

    return (zone_diff_fqdn*)node->value;
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
zone_diff_fqdn_add(zone_diff *diff, const u8 *fqdn, zdb_rr_label *label)
{    
    ptr_node *node = ptr_set_insert(&diff->fqdn, (u8*)fqdn);
    
    if(node->value == NULL)
    {
#if DEBUG
        log_debug2("update: %{dnsname} (%p) ...", fqdn, label);
#endif

        zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_new(fqdn);
        node->key = diff_fqdn->fqdn; // to guarantee the const
        node->value = diff_fqdn;
        
        zone_diff_label_tree *diff_fqdn_label = zone_diff_label_tree_add_fqdn(diff, diff_fqdn->fqdn);
        diff_fqdn_label->diff_fqdn = diff_fqdn;
        
        // copy all records
        if(label != NULL)
        {
            diff_fqdn->is_apex = zdb_rr_label_is_apex(label);
            diff_fqdn->at_delegation = ZDB_LABEL_ATDELEGATION(label);
            diff_fqdn->under_delegation = ZDB_LABEL_UNDERDELEGATION(label);
            diff_fqdn->had_ds = zdb_rr_label_has_rrset(label, TYPE_DS);
            diff_fqdn->was_at_delegation = diff_fqdn->at_delegation;
            diff_fqdn->was_under_delegation = diff_fqdn->under_delegation;
            diff_fqdn->was_non_empty = btree_notempty(label->resource_record_set);
            diff_fqdn->had_children = dictionary_notempty(&label->sub);
            //diff_fqdn->will_be_non_empty = diff_fqdn->was_non_empty;
            diff_fqdn->will_have_children = diff_fqdn->is_apex;
            diff_fqdn->will_have_ds = diff_fqdn->had_ds;
            diff_fqdn->children_added = 0;

            diff_fqdn->has_active_zsk = diff->has_active_zsk;
            diff_fqdn->has_active_ksk = diff->has_active_ksk;

            diff_fqdn->is_in_database = 1;
            
            btree_iterator iter;
            btree_iterator_init(label->resource_record_set, &iter);

            while(btree_iterator_hasnext(&iter))
            {
                btree_node *rr_node = btree_iterator_next_node(&iter);
                u16 type = (u16)rr_node->hash;
                
#if DEBUG
                log_debug2("update: %{dnsname} (%p) copying %{dnstype} RRSET", fqdn, label, &type);
#endif

                zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, type);

                zdb_packed_ttlrdata *rr_sll = (zdb_packed_ttlrdata*)rr_node->data;
                yassert(rr_sll != NULL);

                if(rr_set->org_ttl == -1)
                {
                    rr_set->org_ttl = rr_sll->ttl;
                }

                rr_set->new_ttl = rr_sll->ttl;

                do
                {                
                    zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, type, CLASS_IN, rr_sll->ttl, ZDB_PACKEDRECORD_PTR_RDATAPTR(rr_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(rr_sll), FALSE);
                    rr->state |= ZONE_DIFF_RR_IN_ZONE;
                    /** rr = */ zone_diff_fqdn_rr_set_rr_add_replace(rr_set, rr); /// NOTE: there should not be any collision here
                    rr_sll = rr_sll->next;
                }
                while(rr_sll != NULL);
            }
        }
        else
        {
#if DEBUG
            log_debug2("update: %{dnsname} (%p) label is not in the zone", fqdn, label);
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
#if DEBUG
    else
    {
        log_debug2("update: %{dnsname} (%p) already known (add)", fqdn, label);
    }
#endif
    
    return (zone_diff_fqdn*)node->value;
}

#if ZDB_HAS_NSEC3_SUPPORT
zone_diff_fqdn*
zone_diff_add_nsec3(zone_diff *diff, const nsec3_zone* n3, const nsec3_node *item, s32 ttl, zone_diff_fqdn_rr_set **out_nsec3_rrset)
{
    u8 digest_len = NSEC3_NODE_DIGEST_SIZE(item);
    u8 fqdn[MAX_DOMAIN_LENGTH];

    fqdn[0] = base32hex_encode(NSEC3_NODE_DIGEST_PTR(item), digest_len, (char*)&fqdn[1]);
    dnsname_copy(&fqdn[fqdn[0] + 1], diff->origin);

    ptr_node *node = ptr_set_insert(&diff->fqdn, fqdn);

    if(node->value == NULL)
    {
#if DEBUG
        log_debug2("update: %{dnsname} (%p) ...", fqdn, item);
#endif

        zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_new(fqdn);
        node->key = diff_fqdn->fqdn; // to guarantee the const
        node->value = diff_fqdn;

        zone_diff_label_tree *diff_fqdn_label = zone_diff_label_tree_add_fqdn(diff, diff_fqdn->fqdn);
        diff_fqdn_label->diff_fqdn = diff_fqdn;

        // copy all records
        //diff_fqdn->is_apex = 0;
        //diff_fqdn->at_delegation = 0;
        //diff_fqdn->under_delegation = 0;
        //diff_fqdn->will_have_ds = 0;
        //diff_fqdn->was_at_delegation = 0;
        //diff_fqdn->was_under_delegation = 0;
        //diff_fqdn->had_ds = 0;
        diff_fqdn->was_non_empty = 1;
        //diff_fqdn->had_children = 0;
        //diff_fqdn->will_have_children = 0;
        //diff_fqdn->children_added = 0;
        diff_fqdn->is_nsec3 = 1;

        diff_fqdn->has_active_zsk = diff->has_active_zsk;
        diff_fqdn->has_active_ksk = diff->has_active_ksk;

#if DEBUG
        log_debug2("update: %{dnsname} (%p) copying NSEC3 record", fqdn, item);
#endif
        u32 param_rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
        u8 hash_len = NSEC3_NODE_DIGEST_SIZE(item);
        u32 type_bit_maps_size = item->type_bit_maps_size;

        /* Whatever the editor says: rdata_size is used. */
        u32 rdata_size = param_rdata_size + 1 + hash_len + type_bit_maps_size;

        zone_diff_fqdn_rr_set *nsec3_rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, TYPE_NSEC3);
        zone_diff_label_rr *rr = zone_diff_label_rr_new_nordata(fqdn, TYPE_NSEC3, CLASS_IN, ttl, rdata_size);
        nsec3_zone_item_to_rdata(n3, item, rr->rdata, rdata_size);

        rr->state |= ZONE_DIFF_RR_IN_ZONE;
        zone_diff_fqdn_rr_set_rr_add_replace(nsec3_rr_set, rr); /// NOTE: there should not be any collision here
        if(out_nsec3_rrset != NULL)
        {
            *out_nsec3_rrset = nsec3_rr_set;
        }

        zdb_packed_ttlrdata *nsec3_rrsig_rr_sll = (zdb_packed_ttlrdata*)item->rrsig;

        if(nsec3_rrsig_rr_sll != NULL)
        {
            zone_diff_fqdn_rr_set *nsec3_rrsig_rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, TYPE_RRSIG);

            nsec3_rrsig_rr_set->org_ttl = ttl;
            nsec3_rrsig_rr_set->new_ttl = ttl;

            while(nsec3_rrsig_rr_sll != NULL)
            {
                zone_diff_label_rr *new_rr = zone_diff_label_rr_new(fqdn, TYPE_RRSIG, CLASS_IN, ttl, ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3_rrsig_rr_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec3_rrsig_rr_sll), FALSE);
                new_rr->state |= ZONE_DIFF_RR_IN_ZONE;
                /** rr = */ zone_diff_fqdn_rr_set_rr_add_replace(nsec3_rrsig_rr_set, new_rr); /// NOTE: there should not be any collision here
                nsec3_rrsig_rr_sll = nsec3_rrsig_rr_sll->next;
            }
        }
    }
#if DEBUG
    else
    {
        log_debug2("update: %{dnsname} (%p) already known (add nsec3)", fqdn, item);
    }
#endif

    return (zone_diff_fqdn*)node->value;
}

zone_diff_fqdn*
zone_diff_add_nsec3_ex(zone_diff *diff, const ptr_vector *zsk_keys, const nsec3_zone* n3, const nsec3_node *item, s32 ttl, zone_diff_fqdn_rr_set **out_nsec3_rrset, s32 now, s32 regeneration)
{
    u8 digest_len = NSEC3_NODE_DIGEST_SIZE(item);
    u8 fqdn[MAX_DOMAIN_LENGTH];

    fqdn[0] = base32hex_encode(NSEC3_NODE_DIGEST_PTR(item), digest_len, (char*)&fqdn[1]);
    dnsname_copy(&fqdn[fqdn[0] + 1], diff->origin);

    ptr_node *node = ptr_set_insert(&diff->fqdn, fqdn);

    if(node->value == NULL)
    {
#if DEBUG
        log_debug2("update: %{dnsname} (%p) ...", fqdn, item);
#endif

        zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_new(fqdn);
        node->key = diff_fqdn->fqdn; // to guarantee the const
        node->value = diff_fqdn;

        zone_diff_label_tree *diff_fqdn_label = zone_diff_label_tree_add_fqdn(diff, diff_fqdn->fqdn);
        diff_fqdn_label->diff_fqdn = diff_fqdn;

        // copy all records
        //diff_fqdn->is_apex = 0;
        //diff_fqdn->at_delegation = 0;
        //diff_fqdn->under_delegation = 0;
        //diff_fqdn->will_have_ds = 0;
        //diff_fqdn->was_at_delegation = 0;
        //diff_fqdn->was_under_delegation = 0;
        //diff_fqdn->had_ds = 0;
        diff_fqdn->was_non_empty = 1;
        //diff_fqdn->had_children = 0;
        //diff_fqdn->will_have_children = 0;
        //diff_fqdn->children_added = 0;
        diff_fqdn->is_nsec3 = 1;

        diff_fqdn->has_active_zsk = diff->has_active_zsk;
        diff_fqdn->has_active_ksk = diff->has_active_ksk;

#if DEBUG
        log_debug2("update: %{dnsname} (%p) copying NSEC3 record", fqdn, item);
#endif
        u32 param_rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
        u8 hash_len = NSEC3_NODE_DIGEST_SIZE(item);
        u32 type_bit_maps_size = item->type_bit_maps_size;

        /* Whatever the editor says: rdata_size is used. */
        u32 rdata_size = param_rdata_size + 1 + hash_len + type_bit_maps_size;

        zone_diff_fqdn_rr_set *nsec3_rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, TYPE_NSEC3);
        zone_diff_label_rr *rr = zone_diff_label_rr_new_nordata(fqdn, TYPE_NSEC3, CLASS_IN, ttl, rdata_size);
        nsec3_zone_item_to_rdata(n3, item, rr->rdata, rdata_size);

        rr->state |= ZONE_DIFF_RR_IN_ZONE;
        zone_diff_fqdn_rr_set_rr_add_replace(nsec3_rr_set, rr); /// NOTE: there should not be any collision here
        if(out_nsec3_rrset != NULL)
        {
            *out_nsec3_rrset = nsec3_rr_set;
        }

        zdb_packed_ttlrdata *nsec3_rrsig_rr_sll = (zdb_packed_ttlrdata*)item->rrsig;

        if(nsec3_rrsig_rr_sll != NULL)
        {
            zone_diff_fqdn_rr_set *nsec3_rrsig_rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, TYPE_RRSIG);

            nsec3_rrsig_rr_set->org_ttl = ttl;
            nsec3_rrsig_rr_set->new_ttl = ttl;

            while(nsec3_rrsig_rr_sll != NULL)
            {
                zone_diff_label_rr *new_rr = zone_diff_label_rr_new(fqdn, TYPE_RRSIG, CLASS_IN, ttl, ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3_rrsig_rr_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec3_rrsig_rr_sll), FALSE);
                new_rr->state |= ZONE_DIFF_RR_IN_ZONE;
                s32 matching_key_index = -2;
                if(rrsig_should_remove_signature_from_rdata(
                        ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3_rrsig_rr_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec3_rrsig_rr_sll),
                        zsk_keys, now, regeneration, &matching_key_index) /* unnecessary: || (matching_key_index == -1)*/)
                {
                    new_rr->state |= ZONE_DIFF_RR_REMOVE;
                }

                /** rr = */ zone_diff_fqdn_rr_set_rr_add_replace(nsec3_rrsig_rr_set, new_rr); /// NOTE: there should not be any collision here
                nsec3_rrsig_rr_sll = nsec3_rrsig_rr_sll->next;
            }
        }
    }
#if DEBUG
    else
    {
        log_debug2("update: %{dnsname} (%p) already known (add nsec3 ex)", fqdn, item);
    }
#endif

    return (zone_diff_fqdn*)node->value;
}

#endif // HAS_NSEC3_SUPPORT

zone_diff_fqdn*
zone_diff_add_static_fqdn(zone_diff *diff, const u8 *fqdn, zdb_rr_label *label)
{ 
    zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, label);
    diff_fqdn->will_be_non_empty = diff_fqdn->was_non_empty;
    diff_fqdn->will_have_children = diff_fqdn->had_children;
    diff_fqdn->will_have_ds = diff_fqdn->had_ds && diff_fqdn->at_delegation;
    if(diff_fqdn->will_have_ds != diff_fqdn->had_ds)
    {
        // may be looking at a broken zone
        // it it only contains DS records (and RRSIG records) then it should be marked empty

        btree_iterator iter;
        btree_iterator_init(label->resource_record_set, &iter);

        while(btree_iterator_hasnext(&iter))
        {
            btree_node *rr_node = btree_iterator_next_node(&iter);
            u16 type = (u16)rr_node->hash;
            if((type != TYPE_RRSIG) && (type != TYPE_DS))
            {
                return diff_fqdn;
            }
        }

        // the label will be emptied by validation later, the the NSEC3 chain doesn't know that yet.

        log_warn("update: %{dnsname}: %{dnsname} label only contained DS and RRSIG resource record sets: they will be removed", diff->origin, fqdn);

        diff_fqdn->will_be_non_empty = 0;
    }
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
        zone_diff_fqdn *parent = zone_diff_fqdn_add(diff, sub_fqdn, sub_label);
        parent->children_added = 1;

        if(dictionary_notempty(&sub_label->sub))
        {
            zone_diff_add_fqdn_children(diff, sub_fqdn, sub_label);
        }
    }
}

void
zone_diff_add_fqdn_parents_up_to_below_apex(zone_diff *diff, const u8 *fqdn, zdb_zone *zone)
{
    size_t origin_len = dnsname_len(diff->origin);
    fqdn += fqdn[0] + 1;
    while(dnsname_len(fqdn) > origin_len)
    {
        zdb_rr_label *fqdn_label = zdb_rr_label_find_from_name(zone, fqdn);
        zone_diff_fqdn *parent = zone_diff_fqdn_add(diff, fqdn, fqdn_label);
        parent->children_added = 1;
        fqdn += fqdn[0] + 1;
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
    ptr_set_iterator rr_iter;
    ptr_set_iterator_init(&rrset->rr, &rr_iter);
    while(ptr_set_iterator_hasnext(&rr_iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
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
    u32_node *rrset_node = u32_set_find(&diff_fqdn->rrset, rtype);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrset != NULL);
        
        ptr_set_iterator rr_iter;
        ptr_set_iterator_init(&rrset->rr, &rr_iter);
        while(ptr_set_iterator_hasnext(&rr_iter))
        {
            ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

            if((rr->state & ZONE_DIFF_RR_REMOVE) == 0)
            {
                // this record was present or is being added
                return TRUE;
            }
        }
    }
    return FALSE;
}

bool
zone_diff_remove_rrsig_covering_type(zone_diff_fqdn *diff_fqdn, u16 rtype)
{
    u32_node *rrsig_rrset_node = u32_set_find(&diff_fqdn->rrset, TYPE_RRSIG);
    if(rrsig_rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrsig_rrset = (zone_diff_fqdn_rr_set*)rrsig_rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrsig_rrset != NULL);

        ptr_vector to_remove = PTR_VECTOR_EMPTY;

        ptr_set_iterator rr_iter;
        ptr_set_iterator_init(&rrsig_rrset->rr, &rr_iter);
        while(ptr_set_iterator_hasnext(&rr_iter))
        {
            ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr*)node->key;

            if(rrsig_get_type_covered_from_rdata(rr->rdata, rr->rdata_size) == rtype)
            {
                if((rr->state & ZONE_DIFF_RR_IN_ZONE) != 0) // did exist ?
                {
                    // remove
                    rr->state |= ZONE_DIFF_RR_REMOVE;

                    log_debug2("update: %{dnsname} RRSIG covering %{dnstype} record will be removed from zone", rr->fqdn, &rtype);
                }
                else if((rr->state & ZONE_DIFF_RR_ADD) != 0) // was  being added ?
                {
                    // remove the entry instead (postponed)
                    ptr_vector_append(&to_remove, rr);

                    log_debug2("update: %{dnsname} RRSIG covering %{dnstype} record will not be added to zone", rr->fqdn, &rtype);
                }
                else
                {
                    //

                    log_warn("update: %{dnsname} RRSIG covering %{dnstype} record has state %02x, which is not expected", rr->fqdn, &rtype, rr->state);
                }
            }
        }

        for(int i = 0; i <= ptr_vector_last_index(&to_remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&to_remove, i);
            ptr_set_delete(&rrsig_rrset->rr, rr);
            zone_diff_label_rr_delete(rr);
        }

        if(ptr_set_isempty(&rrsig_rrset->rr))
        {
            u32_set_delete(&diff_fqdn->rrset, TYPE_RRSIG);
        }

        ptr_vector_destroy(&to_remove);
    }
    return FALSE;
}

/**
 *
 * Removes existing records as well as cancels additions of new ones.
 *
 * This is called by zone_diff_validate.
 * This means there is no rrset_to_sign collection yet.
 *
 */

bool
zone_diff_remove_rrset_type(zone_diff_fqdn *diff_fqdn, u16 rtype)
{
    u32_node *rrset_node = u32_set_find(&diff_fqdn->rrset, rtype);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrset != NULL);

        ptr_vector to_remove = PTR_VECTOR_EMPTY;

        ptr_set_iterator rr_iter;
        ptr_set_iterator_init(&rrset->rr, &rr_iter);
        while(ptr_set_iterator_hasnext(&rr_iter))
        {
            ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr*)node->key;

            if((rr->state & ZONE_DIFF_RR_IN_ZONE) != 0) // did exist ?
            {
                // remove
                rr->state |= ZONE_DIFF_RR_REMOVE;

                log_debug2("update: %{dnsname} %{dnstype} record will be removed from zone", rr->fqdn, &rtype);
            }
            else if((rr->state & ZONE_DIFF_RR_ADD) != 0) // was  being added ?
            {
                // remove the entry instead (postponed)
                ptr_vector_append(&to_remove, rr);

                log_debug2("update: %{dnsname} %{dnstype} record will not be added to zone", rr->fqdn, &rtype);
            }
            else
            {
                //

                log_warn("update: %{dnsname} %{dnstype} record has state %02x, which is not expected", rr->fqdn, &rtype, rr->state);
            }
        }

        for(int i = 0; i <= ptr_vector_last_index(&to_remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&to_remove, i);
            ptr_set_delete(&rrset->rr, rr);
            zone_diff_label_rr_delete(rr);
        }

        if(ptr_vector_last_index(&to_remove) >= 0)
        {
            if(ptr_set_isempty(&rrset->rr))
            {
                u32_set_delete(&diff_fqdn->rrset, rtype);
            }

            zone_diff_remove_rrsig_covering_type(diff_fqdn, rtype);
        }

        ptr_vector_destroy(&to_remove);
    }
    return FALSE;
}

/**
 * Returns true iff a DNSKEY with these exact parameters will be present in the zone after the diff.
 * 
 * @param diff_fqdn
 * @param algorithm
 * @param flags
 * @param tag
 * @return 
 */

bool
zone_diff_will_have_dnskey_with_algorithm_flags_tag(const zone_diff_fqdn *diff_fqdn, u8 algorithm, u16 flags, u16 tag)
{
    u32_node *rrset_node = u32_set_find(&diff_fqdn->rrset, TYPE_DNSKEY);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrset != NULL);
        
        ptr_set_iterator rr_iter;
        ptr_set_iterator_init(&rrset->rr, &rr_iter);
        while(ptr_set_iterator_hasnext(&rr_iter))
        {
            ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

            if((rr->state & ZONE_DIFF_RR_REMOVE) == 0)
            {
                // this record was present or is being added
                if(rr->rdata_size > 3)
                {
                    if(dnskey_get_algorithm_from_rdata(rr->rdata) == algorithm)
                    {
                        if(dnskey_get_flags_from_rdata(rr->rdata) == flags)
                        {
                            if(dnskey_get_tag_from_rdata(rr->rdata, rr->rdata_size) == tag)
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
 * Returns true iff a DNSKEY with these exact parameters will be present in the zone after the diff.
 *
 * @param diff_fqdn
 * @param algorithm
 * @param flags
 * @param tag
 * @return
 */

bool
zone_diff_will_have_dnskey_with_algorithm_tag(const zone_diff_fqdn *diff_fqdn, u8 algorithm, u16 tag)
{
    u32_node *rrset_node = u32_set_find(&diff_fqdn->rrset, TYPE_DNSKEY);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrset != NULL);

        ptr_set_iterator rr_iter;
        ptr_set_iterator_init(&rrset->rr, &rr_iter);
        while(ptr_set_iterator_hasnext(&rr_iter))
        {
            ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

            if((rr->state & ZONE_DIFF_RR_REMOVE) == 0)
            {
                // this record was present or is being added
                if(rr->rdata_size > 3)
                {
                    if(dnskey_get_algorithm_from_rdata(rr->rdata) == algorithm)
                    {
                        if(dnskey_get_tag_from_rdata(rr->rdata, rr->rdata_size) == tag)
                        {
                            return TRUE;
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
    const zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_get_const(diff, diff->origin);
    if(diff_fqdn != NULL)
    {
        for(int i = 0; i <= ptr_vector_last_index(keys); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, i);

#if !DEBUG
            if(!dnskey_is_private(key) || !zone_diff_will_have_dnskey_with_algorithm_flags_tag(diff_fqdn,
                                                                                               dnskey_get_algorithm(
                                                                                                   key),
                                                                                               dnskey_get_flags(key),
                                                                                               dnskey_get_tag(key)))
            {
                ptr_vector_end_swap(keys, i);
                ptr_vector_pop(keys);
                dnskey_release(key);
            }
#else
            /*if(!dnskey_is_private(key))
            {
                log_debug3("zone_diff_filter_out_keys: 'K%{dnsname}+%03d+%05hd' is not private", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));

                ptr_vector_end_swap(keys, i);
                ptr_vector_pop(keys);
                dnskey_release(key);
            }
            else*/ if(!zone_diff_will_have_dnskey_with_algorithm_flags_tag(diff_fqdn, dnskey_get_algorithm(key), dnskey_get_flags(key), dnskey_get_tag(key)))
            {
                log_debug3("zone_diff_filter_out_keys: 'K%{dnsname}+%03d+%05hd' will not be in the zone", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));

                ptr_vector_end_swap(keys, i);
                ptr_vector_pop(keys);
                dnskey_release(key);
            }
#endif
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
zone_diff_fqdn_get_const(const zone_diff *diff, const u8 *fqdn)
{
    zone_diff_fqdn *ret = NULL;
    ptr_node *node = ptr_set_find(&diff->fqdn, (u8*)fqdn);
    if(node != NULL)
    {
        ret = (zone_diff_fqdn*)node->value;
    }
    return ret;
}

zone_diff_fqdn*
zone_diff_fqdn_get(const zone_diff *diff, const u8 *fqdn)
{
    zone_diff_fqdn *ret = NULL;
    ptr_node *node = ptr_set_find(&diff->fqdn, (u8*)fqdn);
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
 * Note: it ignores A and AAAA records at or under a delegation
 *
 * @param diff
 * @param fqdn
 * @param bitmap
 * @param mask
 * @param masked
 * @return
 */

u16
zone_diff_type_bit_map_generate(const zone_diff *diff, const u8 *fqdn, type_bit_maps_context *bitmap, u8 mask,
                                u8 masked, const u8 *chain_node_fqdn, bool append_existing_signatures)
{
    type_bit_maps_init(bitmap);

    const zone_diff_fqdn* zdf = zone_diff_fqdn_get_const(diff, fqdn);

    if(zdf != NULL)
    {
        if(zdf->at_delegation || zdf->under_delegation)
        {
            ptr_set_iterator rr_iter;
            u32_set_iterator iter;
            u32_set_iterator_init(&zdf->rrset, &iter);
            while(u32_set_iterator_hasnext(&iter))
            {
                u32_node *node = u32_set_iterator_next_node(&iter);
                u16 rtype = (u16)node->key;

                if((rtype == TYPE_A) || (rtype == TYPE_AAAA))
                {
                    continue;
                }

                zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)node->value;

                ptr_set_iterator_init(&rrset->rr, &rr_iter);
                while(ptr_set_iterator_hasnext(&rr_iter))
                {
                    ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
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
        else
        {
            ptr_set_iterator rr_iter;
            u32_set_iterator iter;
            u32_set_iterator_init(&zdf->rrset, &iter);
            while(u32_set_iterator_hasnext(&iter))
            {
                u32_node *node = u32_set_iterator_next_node(&iter);
                u16 rtype = (u16)node->key;

                zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)node->value;

                ptr_set_iterator_init(&rrset->rr, &rr_iter);
                while(ptr_set_iterator_hasnext(&rr_iter))
                {
                    ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
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

        if(append_existing_signatures)
        {
            if((zdf->rrsig_kept == 0) && zdf->rrsig_added)
            {
                type_bit_maps_set_type(bitmap, TYPE_RRSIG);
            }
        }
    }
    else
    {
        log_debug1("update: %{dnsname}: %{dnsname}: %x: no matching fqdn in the diff", diff->origin, chain_node_fqdn, mask);
    }

    u16 bitmap_size = type_bit_maps_update_size(bitmap);

    return bitmap_size;
}

/**
 * Adds a record on a diff
 *
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
    zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, rtype);
    zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, rtype, CLASS_IN, rttl, rdata, rdata_size, TRUE);
    rr = zone_diff_fqdn_rr_set_rr_add_get(rr_set, rr);

#if DEBUG
    rdata_desc rd = {rtype, rdata_size, rdata};
    log_debug2("update: %{dnsname}: will add [%02x] %{dnsname} %5i %{typerdatadesc}", diff->origin, rr->state, fqdn, rttl, &rd);
#endif

    if( ((rr->state & ZONE_DIFF_RR_IN_ZONE) != 0) && ((rr->state & ZONE_DIFF_RR_REMOVE) != 0) )
    {
        //rr->state |= ZONE_DIFF_RR_ADD;
        rr->state &= ~ZONE_DIFF_RR_REMOVE;
#if DEBUG
        log_debug2("update: %{dnsname}: will add [%02x] %{dnsname} %5i %{typerdatadesc} (no add needed, cleared del)", diff->origin, rr->state, fqdn, rttl, &rd);
#endif
    }
    else if( ((rr->state & ZONE_DIFF_RR_IN_ZONE) == 0) || ((rr->state & ZONE_DIFF_RR_REMOVE) != 0) )
    {
        rr->state |= ZONE_DIFF_RR_ADD;
#if DEBUG
        log_debug2("update: %{dnsname}: will add [%02x] %{dnsname} %5i %{typerdatadesc} (set  add)", diff->origin, rr->state, fqdn, rttl, &rd);
#endif
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
#if DEBUG
    rdata_desc rd = {rtype, rdata_size, rdata};
    log_debug2("update: %{dnsname}: will del %{dnsname} %5i %{typerdatadesc}", diff->origin, fqdn, rttl, &rd);
#endif
    (void)rttl;
    zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, rtype);
    zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, rtype, CLASS_IN, 0, rdata, rdata_size, TRUE);
    rr = zone_diff_fqdn_rr_set_rr_add_get(rr_set, rr);
    rr->state |= ZONE_DIFF_RR_REMOVE;
}

bool
zone_diff_record_remove_existing(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn, u16 rtype, s32 rttl, u16 rdata_size, void *rdata)
{
#if DEBUG
    rdata_desc rd = {rtype, rdata_size, rdata};
    log_debug2("update: %{dnsname}: will del %{dnsname} %5i %{typerdatadesc}", diff->origin, fqdn, rttl, &rd);
#endif
    (void)rttl;
    zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_get(diff_fqdn, rtype);
    if(rr_set != NULL)
    {
        zone_diff_label_rr tmp_rr;
        zone_diff_label_rr_init_tmp(&tmp_rr, fqdn, rtype, CLASS_IN, 0, rdata, rdata_size);
        zone_diff_label_rr *rr = zone_diff_fqdn_rr_set_get_existing_rr(rr_set, &tmp_rr);
        if(rr != NULL)
        {
            rr->state |= ZONE_DIFF_RR_REMOVE;
            return TRUE;
        }
    }

    return FALSE;
}

void
zone_diff_record_remove_automated(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn, u16 rtype, s32 rttl, u16 rdata_size, void *rdata)
{
#if DEBUG
    rdata_desc rd = {rtype, rdata_size, rdata};
    log_debug2("update: %{dnsname}: will del %{dnsname} %5i %{typerdatadesc}", diff->origin, fqdn, rttl, &rd);
#endif
    (void)rttl;
    zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, rtype);
    zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, rtype, CLASS_IN, 0, rdata, rdata_size, TRUE);
    rr = zone_diff_fqdn_rr_set_rr_add_get(rr_set, rr);
    rr->state |= ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_AUTOMATED;
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
    zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, rtype);
    
    ptr_set_iterator iter;
    ptr_set_iterator_init(&rr_set->rr, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;
        rr->state |= ZONE_DIFF_RR_REMOVE;
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
    zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);
    
    u32_set_iterator typeiter;
    u32_set_iterator_init(&diff_fqdn->rrset, &typeiter);
    while(u32_set_iterator_hasnext(&typeiter))
    {
        u32_node* node = u32_set_iterator_next_node(&typeiter);

        yassert((node != NULL) && (node->value != NULL));

        zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)node->value;

        ptr_set_iterator iter;
        ptr_set_iterator_init(&rr_set->rr, &iter);
        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *node = ptr_set_iterator_next_node(&iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;
            rr->state |= ZONE_DIFF_RR_REMOVE;
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
    
    zone_diff_fqdn *apex = zone_diff_fqdn_add(diff, diff->origin, label);
    zone_diff_fqdn_rr_set *soa_rrset = zone_diff_fqdn_rr_set_add(apex, TYPE_SOA);
    
    //ptr_set_iterator fqdn_iter;
    ptr_set_iterator rr_iter;
    
    zone_diff_label_rr *rr_soa_removed = NULL;
    zone_diff_label_rr *rr_soa_added = NULL;
    u32 soa_latest_serial;
    ya_result ret;
    
    ptr_set_iterator_init(&soa_rrset->rr, &rr_iter);
    while(ptr_set_iterator_hasnext(&rr_iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

#if DEBUG        
        rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
        log_debug1("update: %{dnsname}: SOA[%x] %{dnsname} %9i %{typerdatadesc}", diff->origin, rr->state, rr->fqdn, rr->ttl, &rd);
#endif
        
        if(rr->state & ZONE_DIFF_RR_REMOVE)
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
                soa_latest_serial = serial_max(soa_latest_serial, soa_serial); // soa_latest_serial is initialized
                if(serial_lt(soa_latest_serial, soa_serial))
                {
                    rr_soa_removed = rr;
                }
            }
        }
        
        if((rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_ADD) // VS false positive: rr is a key and can't be NULL
        {
            if(rr_soa_added != NULL)
            {
                return INVALID_STATE_ERROR; // two SOA added ...
            }
            
            rr_soa_added = rr;
        }
    }
    
    if(rr_soa_removed == NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    if(rr_soa_added != NULL)
    {
        u32 soa_serial;
            
        if(FAIL(ret = rr_soa_get_serial(rr_soa_added->rdata, rr_soa_added->rdata_size, &soa_serial)))
        {
            // error
            
            return ret;
        }

        if(serial_le(soa_serial, soa_latest_serial)) // soa_latest_serial is initialized
        {
            // error
            
            return INVALID_STATE_ERROR;
        }
    }
    else
    {
        // add the SOA add record

#if C11_VLA_AVAILABLE
        u8 tmp_rdata[rr_soa_removed->rdata_size];
#else
        u8* const tmp_rdata = (u8* const)stack_alloc(rr_soa_removed->rdata_size);
#endif

        memcpy(tmp_rdata, rr_soa_removed->rdata, rr_soa_removed->rdata_size);
        rr_soa_increase_serial(tmp_rdata, rr_soa_removed->rdata_size, 1);
        rr_soa_added = zone_diff_label_rr_new(rr_soa_removed->fqdn, TYPE_SOA, CLASS_IN, rr_soa_removed->ttl, tmp_rdata, rr_soa_removed->rdata_size, TRUE);
        rr_soa_added = zone_diff_fqdn_rr_set_rr_add_get(soa_rrset, rr_soa_added); // add_get
        rr_soa_added->state |= ZONE_DIFF_RR_ADD  | ZONE_DIFF_RR_AUTOMATED;
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
    ptr_set_iterator fqdn_iter;

    ptr_vector diff_fqdn_to_remove = EMPTY_PTR_VECTOR;
    
    ptr_set_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_set_iterator_hasnext(&fqdn_iter))
    {
        ptr_node *diff_fqdn_node = ptr_set_iterator_next_node(&fqdn_iter);

        const u8 *diff_fqdn_name = (const u8*)diff_fqdn_node->key;
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;
        
        // update status flags
        // do validation tests
        
        log_debug2("update: %{dnsname}: validating %{dnsname}", diff->origin, diff_fqdn_name);

        if(diff_fqdn->is_apex)
        {
            // only check for CNAME
            
            if(zone_diff_will_have_rrset_type(diff_fqdn, TYPE_CNAME))
            {
                log_err("update: %{dnsname}: update would add CNAME on apex", diff->origin);
                
                //dnssec_chain_finalize(&dc);
                
                return INVALID_STATE_ERROR;
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
            bool is_right_above = TRUE;
            while(*above_fqdn != 0)
            {
                above_fqdn += *above_fqdn + 1;
                
                const zone_diff_fqdn *parent = zone_diff_fqdn_get_const(diff, above_fqdn);
                
                if(parent != NULL)
                {
                    if(parent->is_apex)
                    {
                        break;
                    }

                    if(is_right_above)
                    {
                        if((parent->was_at_delegation || parent->was_under_delegation) && !diff_fqdn->was_under_delegation)
                        {
                            // then we are at delegation
#if DEBUG
                            if(diff_fqdn->is_in_database)
                            {
                                log_warn("update: %{dnsname}: %{dnsname} expected to be marked as being under delegation in the database as %{dnsname} at=%i under=%i (fixing)", diff->origin,
                                          diff_fqdn->fqdn, parent->fqdn, parent->was_at_delegation, parent->was_under_delegation);
                            }
#endif
                            diff_fqdn->was_under_delegation = TRUE;
                        }
                        else if(!((parent->was_at_delegation || parent->was_under_delegation)) && diff_fqdn->was_under_delegation)
                        {
                            // then we are at delegation
#if DEBUG
                            if(diff_fqdn->is_in_database)
                            {
                                log_warn("update: %{dnsname}: %{dnsname} not expected to be marked as being under delegation in the database as %{dnsname} at=%i under=%i (fixing)", diff->origin,
                                         diff_fqdn->fqdn, parent->fqdn, parent->was_at_delegation, parent->was_under_delegation);
                            }
#endif
                            diff_fqdn->was_under_delegation = FALSE;
                        }

                        is_right_above = FALSE;
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
                            log_debug1("update: %{dnsname}: %{dnsname} under delegation %{dnsname}", diff->origin,
                                    diff_fqdn->fqdn, parent->fqdn);
                        }
                        under_delegation = TRUE;
                        break;
                    }
                }
                /*else
                {
                    under_delegation = diff_fqdn->under_delegation;
                }*/
            }
            
            if(diff_fqdn->under_delegation && !under_delegation)
            {
                log_debug1("update: %{dnsname}: %{dnsname} not under delegation anymore", diff->origin, diff_fqdn->fqdn);
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

            if(diff_fqdn->will_have_ds && !diff_fqdn->at_delegation)
            {
                log_debug1("update: %{dnsname}: %{dnsname} will have a DS but no NS : removing all DS", diff->origin, diff_fqdn->fqdn);

                zone_diff_remove_rrset_type(diff_fqdn, TYPE_DS);
                diff_fqdn->will_have_ds = 0;

                if(u32_set_isempty(&diff_fqdn->rrset))
                {
                    ptr_vector_append(&diff_fqdn_to_remove, diff_fqdn_node);
                }

                // TODO: remove NSEC3 record
            }
        }
        
        log_debug2("update: %{dnsname}: validating %{dnsname}: apex=%i at=%i under=%i ds=%i was-at=%i was-under=%i had-ds=%i",
                diff->origin, diff_fqdn_name,
                diff_fqdn->is_apex, diff_fqdn->at_delegation, diff_fqdn->under_delegation, diff_fqdn->will_have_ds,
                diff_fqdn->was_at_delegation, diff_fqdn->was_under_delegation, diff_fqdn->had_ds
                );
    }

    for(int i = 0; i <= ptr_vector_last_index(&diff_fqdn_to_remove); ++i)
    {
        ptr_node *diff_fqdn_node = (ptr_node*)ptr_vector_get(&diff_fqdn_to_remove, i);
        //const u8 *diff_fqdn_name = (const u8*)diff_fqdn_node->key;
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;
        ptr_set_delete(&diff->fqdn, diff_fqdn->fqdn);   // remove the node

        // if diff_fqdn is not in the database
        //   from diff->root, remove the fqdn with attention to empty terminal not in the database
        //   and

        // zone_diff_fqdn_delete(diff_fqdn);               // delete the data
    }
    ptr_vector_destroy(&diff_fqdn_to_remove);
    
    return SUCCESS;
}

struct zone_diff_get_changes_update_rr_parm
{
    u8 changes;
    bool rrset_removed;
    bool rrset_new;
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
    bool rrset_new = TRUE;
            
    ptr_set_iterator rr_iter;
    
    // for all marked rr
            
    ptr_set_iterator_init(&rr_set->rr, &rr_iter);
    while(ptr_set_iterator_hasnext(&rr_iter))
    {
        ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;
        
        yassert(rr->rtype == TYPE_RRSIG);
        
        if((rr->state & (ZONE_DIFF_RR_IN_ZONE|ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_ADDED)) == ZONE_DIFF_RR_ADD)
        {
            // add
#if DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: add %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rrsig_rr %p)",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif
            
            ptr_vector_append(add, rr);
            rr->state |= ZONE_DIFF_RR_ADDED;

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_ADD;
            rrset_removed = FALSE;
            all_rrset_removed = FALSE;
        }
        else if((rr->state & (ZONE_DIFF_RR_IN_ZONE|ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_REMOVED)) == (ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_IN_ZONE))
        {
            // remove
            
#if DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: del %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rrsig_rr %p)",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif

            ptr_vector_append(remove, rr);
            rr->state |= ZONE_DIFF_RR_REMOVED;

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_REMOVE;
            all_rrset_added = FALSE;
        }
        else if((rr->state & (ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE)) == 0)
        {
            // stays
            
#if DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: nop %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rrsig_rr %p)",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif
            
            changes |= ZONE_DIFF_CHANGES_KEPT;
            rrset_removed = FALSE;
            all_rrset_removed = FALSE;
            all_rrset_added = FALSE;

            rrset_new = TRUE;
        }
        else
        {
#if DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: ign %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rrsig_rr %p)",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif
        }
    }
    
    parm->changes = changes;
    parm->rrset_removed = rrset_removed;
    parm->rrset_new = rrset_new;
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
            
    ptr_set_iterator rr_iter;
    
    // for all marked rr
            
    ptr_set_iterator_init(&rr_set->rr, &rr_iter);
    while(ptr_set_iterator_hasnext(&rr_iter))
    {
        ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;

        if((rr->state & (ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_ADDED)) == ZONE_DIFF_RR_ADD)
        {
            // add
            
#if DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: add %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rr %p)",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif
            ptr_vector_append(add, rr);
            rr->state |= ZONE_DIFF_RR_ADDED;

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
        else if((rr->state & (ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_REMOVED)) == ZONE_DIFF_RR_REMOVE)
        {
            // remove
            
#if DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: del %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rr %p)",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif

            ptr_vector_append(remove, rr);
            rr->state |= ZONE_DIFF_RR_REMOVED;

            if(rr->rtype == TYPE_SOA)
            {
                ptr_vector_end_swap(remove, 0);
            }

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_REMOVE;
            all_rrset_added = FALSE;
        }
        else if((rr->state & (ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE)) == 0)
        {
            
#if DEBUG
            rdata_desc rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: nop %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rr %p)",
                    &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif
            // stays
            changes |= ZONE_DIFF_CHANGES_KEPT;
            rrset_removed = FALSE;
            all_rrset_removed = FALSE;
            all_rrset_added = FALSE;
            non_empty = TRUE;
        }
    }
    
    parm->changes = changes;
    parm->rrset_removed = rrset_removed;
    parm->all_rrset_added = all_rrset_added;
    parm->all_rrset_removed = all_rrset_removed;
    parm->non_empty = non_empty;
}

u64
zone_diff_key_vector_get_mask(ptr_vector *keys, time_t now)
{
    u64 mask = 0;
    for(int i = 0; i <= ptr_vector_last_index(keys); ++i)
    {
        dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, i);

        bool is_private = dnskey_is_private(key);

        if((is_private && dnskey_is_activated(key, now)) || !is_private)
        {
            mask |= 1ULL << i;
        }
    }

    return mask;
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

s32
zone_diff_get_changes(zone_diff *diff, ptr_vector *rrset_to_sign_vector, ptr_vector *ksks, ptr_vector *zsks, ptr_vector *remove, ptr_vector *add)
{
    s32 mandatory_changes = 0;
    ya_result err = SUCCESS;

    // first fill the arrays with the relevant keys

    zone_diff_store_diff_dnskey_get_keys(diff, ksks, zsks);

    ptr_set_iterator fqdn_iter;
    ptr_set_iterator rr_iter;
      
    time_t now = time(NULL);

    u64 ksks_mask = zone_diff_key_vector_get_mask(ksks, now);
    u64 zsks_mask = zone_diff_key_vector_get_mask(zsks, now);

    //bool may_have_empty_terminals = FALSE;

    // for all fqdn

    ptr_set_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_set_iterator_hasnext(&fqdn_iter))
    {
        ptr_node *diff_fqdn_node = ptr_set_iterator_next_node(&fqdn_iter);
#if DYNUPDATE_DIFF_DETAILED_LOG
        const u8 *diff_fqdn_name = (const u8*)diff_fqdn_node->key;
#endif
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;

        // for all rrset

        bool type_map_changed = FALSE;
        bool all_rrset_added = TRUE;
        bool all_rrset_removed = TRUE;
        bool non_empty = FALSE;

        zone_diff_fqdn_rr_set *rrsig_rr_set = NULL;

        u32_node *rrset_node = u32_set_find(&diff_fqdn->rrset, TYPE_RRSIG);
        if(rrset_node != NULL)
        {
            rrsig_rr_set = (zone_diff_fqdn_rr_set*)rrset_node->value;
        }

        type_map_changed = (rrsig_rr_set == NULL);

        // for all records

        if(!u32_set_isempty(&diff_fqdn->rrset))
        {
            u32_set_iterator rrset_iter;
            u32_set_iterator_init(&diff_fqdn->rrset, &rrset_iter);
            while(u32_set_iterator_hasnext(&rrset_iter))
            {
                u32_node *rrset_node = u32_set_iterator_next_node(&rrset_iter);

                zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)rrset_node->value;

                if(rr_set == NULL)
                {
                    continue;
                }

#if DYNUPDATE_DIFF_DETAILED_LOG
                {
                    // enumerate records

                    ptr_set_iterator rr_iter;
                    ptr_set_iterator_init(&rr_set->rr, &rr_iter);
                    rdata_desc rdatadesc = {rr_set->rtype, 0, NULL};
                    while(ptr_set_iterator_hasnext(&rr_iter))
                    {
                        ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
                        zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->key;
                        rdatadesc.len = rr->rdata_size;
                        rdatadesc.rdata = rr->rdata;
                        log_debug("update: %02x [%llx] %{dnsname} %i %{typerdatadesc}", rr->state, rr_set->key_mask, rr->fqdn, rr->ttl, &rdatadesc);
                    }
                }
#endif
                if(rr_set->rtype == TYPE_RRSIG)
                {
                    // if allowed ...

                    if(diff->rrsig_update_allowed)
                    {
                        ptr_set_iterator_init(&rr_set->rr, &rr_iter);
                        bool rrsig_added = FALSE;
                        bool rrsig_kept = FALSE;
                        bool rrsig_removed = FALSE;
                        bool key_will_be_present = FALSE;
                        bool key_will_be_present_DNSKEY = FALSE;
                        bool key_will_be_present_not_DNSKEY = FALSE;

                        while(ptr_set_iterator_hasnext(&rr_iter))
                        {
                            ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
                            zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;
                            if((rr->state & (ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_ADD)
                            {
                                rdata_desc rdt = {rr->rtype, rr->rdata_size, rr->rdata};

                                log_debug("update: %{dnsname}: checking for signing key of RRSIG record %{dnsname} %i %{dnsclass} %{typerdatadesc}",
                                          diff->origin, rr->fqdn, rr->ttl, &rr->rclass, &rdt);

                                u8 algorithm = rrsig_get_algorithm_from_rdata(rr->rdata, rr->rdata_size);
                                u16 tag = rrsig_get_key_tag_from_rdata(rr->rdata, rr->rdata_size);

                                rrsig_added = TRUE;

                                if(zone_diff_will_have_dnskey_with_algorithm_tag(diff_fqdn, algorithm, tag))
                                {
                                    key_will_be_present = TRUE;
                                    if(rrsig_get_type_covered_from_rdata(rr->rdata, rr->rdata_size) == TYPE_DNSKEY)
                                    {
                                        key_will_be_present_DNSKEY = TRUE;
                                    }
                                    else
                                    {
                                        key_will_be_present_not_DNSKEY = TRUE;
                                    }
                                    break;
                                }
                            }
                            else if((rr->state & (ZONE_DIFF_RR_IN_ZONE|ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_REMOVE)
                            {
                                rrsig_removed = TRUE;
                            }
                            else if((rr->state & (ZONE_DIFF_RR_IN_ZONE/*|ZONE_DIFF_RR_ADD*/|ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_IN_ZONE)
                            {
                                rrsig_kept = TRUE; // if it's added but already in zone, it does not count does it ...
                            }
                        }

                        diff_fqdn->rrsig_added = rrsig_added;
                        diff_fqdn->rrsig_kept = rrsig_kept;
                        diff_fqdn->rrsig_removed = rrsig_removed;

                        if(!rrsig_added || (rrsig_added && key_will_be_present))
                        {
                            u8 changes = ZONE_DIFF_CHANGES_NONE;
                            bool rrset_removed = TRUE;

                            struct zone_diff_get_changes_update_rr_parm parms = {changes, rrset_removed, FALSE, all_rrset_added, all_rrset_removed, non_empty};
                            zone_diff_get_changes_update_rrsig_rr(rr_set, &parms, remove, add);

                            diff_fqdn->rrsig_kept = !parms.rrset_new;
                        }
                        else
                        {
                            if(!key_will_be_present_DNSKEY)
                            {
                                log_info("update: %{dnsname}: DNSKEY RRSIG without signing DNSKEY present (probably on purpose)", diff_fqdn->fqdn);
                            }
                            if(!key_will_be_present_not_DNSKEY)
                            {
                                log_err("update: %{dnsname}: RRSIG without signing DNSKEY present (probably bad)", diff_fqdn->fqdn);
                            }

                            err = INVALID_STATE_ERROR;
                        }
                    }
#if DEBUG
                    else
                    {
                        log_debug1("update: %{dnsname}: not updating RRSIG rr_set at this point (rrsig_update_allowed is false)", diff_fqdn->fqdn);
                        ptr_set_iterator_init(&rr_set->rr, &rr_iter);
                        while(ptr_set_iterator_hasnext(&rr_iter))
                        {
                            ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
                            zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;
                            if((rr->state & (ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_ADD)
                            {
                                rdata_desc rdt = {rr->rtype, rr->rdata_size, rr->rdata};

                                log_debug("update: %{dnsname}: (ignoring) [%02x] %{dnsname} %i %{dnsclass} %{typerdatadesc}",
                                          diff->origin, rr->state, rr->fqdn, rr->ttl, &rr->rclass, &rdt);
                            }
                        }
                    }
#endif

                    continue;
                }
                u8 changes = ZONE_DIFF_CHANGES_NONE;
                bool rrset_removed = TRUE;

                struct zone_diff_get_changes_update_rr_parm parms = {changes, FALSE, rrset_removed, all_rrset_added, all_rrset_removed, non_empty};
                zone_diff_get_changes_update_rr(rr_set, &parms, remove, add);

                changes = parms.changes;
                rrset_removed = parms.rrset_removed;
                if(rr_set->rtype != TYPE_NSEC)
                {
                    all_rrset_added = parms.all_rrset_added;
                    all_rrset_removed = parms.all_rrset_removed;
                    non_empty = parms.non_empty;
                }

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

                ptr_vector *keys = zsks;
                u64 keys_mask = zsks_mask;

                if(rr_set->rtype == TYPE_DNSKEY)
                {
                    keys = ksks;
                    keys_mask = ksks_mask;
                }

                if(rrset_node->key == TYPE_RRSIG)
                {
                    continue;
                }

                bool rrset_updated = (changes & (ZONE_DIFF_CHANGES_ADD|ZONE_DIFF_CHANGES_REMOVE)); // || type_map_changed ?

                if((rr_set->rtype != TYPE_SOA) && rrset_updated)
                {
                    ++mandatory_changes;
                }

    #if 0 /* fix */
#else
                bool rrset_expected_to_be_covered =
                        !(diff_fqdn->at_delegation || diff_fqdn->under_delegation) ||
                        (!diff_fqdn->under_delegation &&
                            (diff_fqdn->at_delegation && ((rr_set->rtype == TYPE_DS) || (rr_set->rtype == TYPE_NSEC)))
                        );

                bool rrset_rrsig_covered_with_chain_rules = (!rrset_removed && rrset_expected_to_be_covered);
    #endif
                bool came_under_delegation = (!diff_fqdn->was_under_delegation && diff_fqdn->under_delegation);
                //bool came_out_of_delegation = (diff_fqdn->was_under_delegation && !diff_fqdn->under_delegation);

                // blanket bombing

                if((rrsig_rr_set != NULL) &&
                   (rrset_updated ||
                   all_rrset_removed ||
                   came_under_delegation ||
    #if 0 /* fix */
#else
                    !rrset_rrsig_covered_with_chain_rules
    #endif
                    )
                   )
                {
                    ptr_set_iterator_init(&rrsig_rr_set->rr, &rr_iter);
                    while(ptr_set_iterator_hasnext(&rr_iter))
                    {
                        ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
                        zone_diff_label_rr *rrsig_rr = (zone_diff_label_rr *)rr_node->key;

                        if(rrsig_get_type_covered_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size) != rr_set->rtype)
                        {
                            continue;
                        }

                        if(rrsig_rr->state & ZONE_DIFF_RR_ADD)
                        {
                            // manually added
                            continue;
                        }

                        if((rrsig_rr->state & ZONE_DIFF_RR_REMOVED) == 0) // the signature is not marked for removal (e.g.: expired)
                        {
                            rrsig_rr->state |= ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_AUTOMATED;
    #if DEBUG
                            {
                                rdata_desc rrsig_rr_rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                                format_writer temp_fw_0 = {zone_diff_record_state_format, &rrsig_rr->state};
                                log_debug1("update: del %w %{dnsname} %9i %{typerdatadesc} (rrsig A zone_diff_get_changes %p)",
                                           &temp_fw_0, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_rd, rrsig_rr);
                            }
    #endif
                            ptr_vector_append(remove, rrsig_rr);
                            rrsig_rr->state |= ZONE_DIFF_RR_REMOVED;
                        }
                    }
                }

                // for all rrsig, enumerate properly covered types

                //bool rrset_already_covered = FALSE;

                if(!all_rrset_removed &&
    #if 0 /* fix */
#else
                    rrset_rrsig_covered_with_chain_rules
    #endif
                    ) // else this would be pointless
                {
                    if(rrsig_rr_set != NULL)
                    {
                        u64 coverage = 0;

                        ptr_set_iterator_init(&rrsig_rr_set->rr, &rr_iter);
                        while(ptr_set_iterator_hasnext(&rr_iter))
                        {
                            ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
                            zone_diff_label_rr *rrsig_rr = (zone_diff_label_rr *)rr_node->key;

                            if(rrsig_get_type_covered_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size) != rr_set->rtype)
                            {
                                continue;
                            }

                            if((rrsig_rr->state & (ZONE_DIFF_RR_ADDED|ZONE_DIFF_RR_RDATA_OWNED)) == (ZONE_DIFF_RR_ADDED|ZONE_DIFF_RR_RDATA_OWNED))
                            {
                                continue;
                            }

                            if((rrsig_rr->state & ZONE_DIFF_RR_REMOVED) != 0) // the signature is not marked for removal (e.g.: expired)
                            {
                                continue;
                            }

                            // check if the signature is with a valid key and is in its validity period
                            // if it's not valid yet, keep it
                            // if its expired, remove it
                            // if no valid signatures are available, may mark the record for signing

                            s32 key_index = -2;

                            if(rrsig_should_remove_signature_from_rdata(
                                rrsig_rr->rdata, rrsig_rr->rdata_size,
                                keys, now, diff->rrsig_validity_regeneration, &key_index) || (key_index == -1))
                            {
                                rrsig_rr->state |= ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_AUTOMATED;

#if DEBUG
                                {
                                    rdata_desc rrsig_rr_rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                                    format_writer temp_fw_0 = {zone_diff_record_state_format, &rrsig_rr->state};
                                    log_debug1("update: del %w %{dnsname} %9i %{typerdatadesc} (rrsig B zone_diff_get_changes %p)",
                                               &temp_fw_0, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_rd, rrsig_rr);
                                }
#endif

                                ptr_vector_append(remove, rrsig_rr);
                                rrsig_rr->state |= ZONE_DIFF_RR_REMOVED;
                                ++mandatory_changes;
                                continue;
                            }

                            // the signature will be kept

                            coverage |= (1ULL << key_index);
                        }

                        rr_set->key_mask = keys_mask ^ coverage;
                    }
                    else
                    {
                        rr_set->key_mask = keys_mask;
                    }
                }

                // If the chain believes it has to handle the fqdn, add the rrset to the "to sign"
                // This does not work with mixed chains (NSEC & NSEC3)

                if((rr_set->key_mask != 0) && (rrset_to_sign_vector != NULL))
                {
                    if(rr_set->rtype != TYPE_SOA)
                    {
                        ++mandatory_changes;
                    }

                    // will generate new signatures for the rrset (postponed)

                    // verify that signatures are not already present


#if DYNUPDATE_DIFF_DETAILED_LOG
                        log_debug("update: %{dnsname}: dnssec: %{dnsname} %{dnstype} rrset @%p should be signed (%08llx/%08llx)", diff->origin,
                                diff_fqdn_name, &rr_set->rtype, rr_set, rr_set->key_mask, keys_mask);
#endif
                        ptr_vector_append(rrset_to_sign_vector, rr_set);

                }
            }
        }
        else
        {
#if DYNUPDATE_DIFF_DETAILED_LOG
            {
                // empty
                log_debug("update: ?? [?] %{dnsname} has no records", diff_fqdn->fqdn);
            }
#endif
            type_map_changed = FALSE;
            all_rrset_added = FALSE;
            all_rrset_removed = FALSE;
            non_empty = FALSE;

            //may_have_empty_terminals = TRUE;
        }

        // if type_map_changes, the type map has to be updated and the signature too, obviously

        diff_fqdn->type_map_changed = type_map_changed || (!diff_fqdn->rrsig_kept && (diff_fqdn->rrsig_added != diff_fqdn->rrsig_removed));
        diff_fqdn->all_rrset_added = all_rrset_added;
        diff_fqdn->all_rrset_removed = all_rrset_removed;
        diff_fqdn->will_be_non_empty = non_empty;

        /**/
        diff_fqdn->type_map_changed &= non_empty;
        diff_fqdn->all_rrset_added &= non_empty;

        /**/

        diff_fqdn->records_flags_set = 1;

#if DYNUPDATE_DIFF_DETAILED_LOG
        {
            // empty
            log_debug("update: -- --- %{dnsname} remap=%i +all=%i -all=%i !empty=%i", diff_fqdn->fqdn, type_map_changed, all_rrset_added, all_rrset_removed, non_empty);
        }
#endif
    }

    if(ISOK(err))
    {
        return mandatory_changes;
    }
    else
    {
        return err;
    }
}

#if 0 && DYNUPDATE_DIFF_DETAILED_LOG
    if(may_have_empty_terminals)
    {
        ptr_set_iterator_init(&diff->fqdn, &fqdn_iter);
        while(ptr_set_iterator_hasnext(&fqdn_iter))
        {
            ptr_node *diff_fqdn_node = ptr_set_iterator_next_node(&fqdn_iter);
            const u8 *diff_fqdn_name = (const u8*)diff_fqdn_node->key;

            zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;
        }
    }
#endif

void
zone_diff_get_chain_changes(zone_diff *diff, dnssec_chain* dc/*, ptr_vector *rrset_to_sign_vector, ptr_vector *ksks, ptr_vector *zsks, ptr_vector *remove, ptr_vector *add*/)
{
    ptr_set_iterator fqdn_iter;

    if(dc != NULL)
    {
        ptr_set_iterator_init(&diff->fqdn, &fqdn_iter);
        while(ptr_set_iterator_hasnext(&fqdn_iter))
        {
            ptr_node *diff_fqdn_node = ptr_set_iterator_next_node(&fqdn_iter);
            const u8 *diff_fqdn_name = (const u8*)diff_fqdn_node->key;

            zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;
        
            zone_diff_fqdn_children_state(diff, diff_fqdn->fqdn);

            // calling dnssec_chain_del_from_diff_fqdn and dnssec_chain_add_from_diff_fqdn respectively
            // tell to remove or to add a chain node (NSEC/NSEC3) for the given fqdn in the zone.
            
            // Note the "was" or "is" covered means "IF the fqdn existed, was the past state covering it, is the new state covering it."
            
            // This table gives the del/add for a node given the various states
            //                          (+-R => sumrises to "has changed")
            // Was covered | Is covered | +ALL | -ALL | REMAP | NODE
            // -----------------------------------------------+------
            //      0            0          1      0      ?   |
            //      0            0          0      1      ?   |
            //      0            0          0      0      0   |
            //      0            0          0      0      1   |
            // -----------------------------------------------+------
            //      0            1          1      0      ?   |  +
            //      0            1          0      1      ?   |        There is nothing anymore (empty non-terminal ? => +)
            //      0            1          0      0      0   |  +
            //      0            1          0      0      1   |  +
            // -----------------------------------------------+------
            //      1            0          1      0      ?   |        There was nothing before
            //      1            0          0      1      ?   |  -
            //      1            0          0      0      0   |  -
            //      1            0          0      0      1   |  -
            // -----------------------------------------------+------
            //      1            1          1      0      ?   |  +     There was nothing before
            //      1            1          0      1      ?   |  -                              (empty non-terminal ? => -+)
            //      1            1          0      0      0   |        There is no changed of state on this regard
            //      1            1          0      0      1   | -+
            // -----------------------------------------------+------

#define CHAIN_NODE_NOP 0            
#define CHAIN_NODE_DEL 1
#define CHAIN_NODE_ADD 2

            bool is_covered = dc->chain->fqdn_is_covered(diff_fqdn);
            bool was_covered = dc->chain->fqdn_was_covered(diff_fqdn);

#if DYNUPDATE_DIFF_DETAILED_LOG
            log_debug("update: %{dnsname}: dnssec: %{dnsname}: +ALL(%i) -ALL(%i) RECORDS(%i->%i) COVERED(%i->%i) CHILDREN(%i->%i) AT(%i->%i) UNDER(%i->%i) MAP(%i)",
                    diff->origin,
                    diff_fqdn_name,
                    diff_fqdn->all_rrset_added,
                    diff_fqdn->all_rrset_removed,
                    diff_fqdn->was_non_empty, diff_fqdn->will_be_non_empty,
                    was_covered, is_covered,
                    diff_fqdn->had_children, diff_fqdn->will_have_children,
                    diff_fqdn->was_at_delegation, diff_fqdn->at_delegation,
                    diff_fqdn->was_under_delegation, diff_fqdn->under_delegation,
                    diff_fqdn->type_map_changed);
#endif
            if(was_covered || is_covered) // quickly cull the first 4 states of the table
            {
                bool did_exist = diff_fqdn->had_children || diff_fqdn->was_non_empty;
                bool will_exist = diff_fqdn->will_have_children || diff_fqdn->will_be_non_empty;

                u8 ops = 0;
                
                if( (diff_fqdn->had_children != diff_fqdn->will_have_children) ||
                    (diff_fqdn->all_rrset_added) ||
                    (diff_fqdn->all_rrset_removed) ||
                    (diff_fqdn->type_map_changed) ||
                    (is_covered != was_covered)
                    )
                {
                    //ops_index = 3;  // means change
                    
                    if(was_covered && did_exist)
                    {
                        //ops_index |= 8;
                        ops |= CHAIN_NODE_DEL;
                    }

                    if(is_covered && will_exist)
                    {
                        //ops_index |= 4;
                        ops |= CHAIN_NODE_ADD;
                    }
                }

#if DEBUG
                log_debug2("update: %{dnsname}: dnssec: %{dnsname}: operation %x", diff->origin, diff_fqdn_name, ops);
#endif
                if(ops & CHAIN_NODE_DEL)
                {
                    log_debug2("update: %{dnsname}: dnssec: %{dnsname}: removing chain node", diff->origin, diff_fqdn_name);
                    dnssec_chain_del_from_diff_fqdn(dc, diff_fqdn, 0);
                }
                
                if(ops & CHAIN_NODE_ADD)
                {
                    log_debug2("update: %{dnsname}: dnssec: %{dnsname}: adding chain node", diff->origin, diff_fqdn_name);
                    dnssec_chain_add_from_diff_fqdn(dc, diff_fqdn, 0);
                }
            }
        } // while fqdn names
    }
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
#if DEBUG
        for(s32 i = 0; i <= ptr_vector_last_index(rrset_to_sign_vector); ++i)
        {
            zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)ptr_vector_get(rrset_to_sign_vector, i);

            ptr_set_iterator rr_iter;

            // for all marked rr

            ptr_set_iterator_init(&rr_set->rr, &rr_iter);
            while(ptr_set_iterator_hasnext(&rr_iter))
            {
                ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;

                rdata_desc rdatadesc = {rr->rtype, rr->rdata_size, rr->rdata};


                format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};

                log_debug1("zone-diff: changes: %{dnsname}: %02x: %w: %{dnsname} %i %{typerdatadesc}", diff->origin, rr->state, &temp_fw_0, rr->fqdn, rr->ttl, &rdatadesc);
            }
        }
#endif

        return TRUE;
    }
    
    ptr_set_iterator fqdn_iter;
    ptr_set_iterator rr_iter;

    // for all fqdn
    
    ptr_set_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_set_iterator_hasnext(&fqdn_iter))
    {
        ptr_node *diff_fqdn_node = ptr_set_iterator_next_node(&fqdn_iter);
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;

        // for all records
        
        u32_set_iterator rrset_iter;
        u32_set_iterator_init(&diff_fqdn->rrset, &rrset_iter);
        while(u32_set_iterator_hasnext(&rrset_iter))
        {
            u32_node *rrset_node = u32_set_iterator_next_node(&rrset_iter);
            
            zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)rrset_node->value;

            // for all marked rr
            
            ptr_set_iterator_init(&rr_set->rr, &rr_iter);
            while(ptr_set_iterator_hasnext(&rr_iter))
            {
                ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;
#if DEBUG
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
                log_debug1("update: %{dnsname}: has-changes: state %02x: %{dnsname} %9i %{typerdatadesc}", diff->origin, rr->state, rr->fqdn, rr->ttl, &rd);
#endif
                if((rr->state & (ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_ADD)
                {
                    // add
                    return TRUE;
                }
                else if((rr->state & (ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_REMOVE)
                {
                    // remove
                    return TRUE;
                }
            }
        }
    }
    
    return FALSE;
}

void
zone_diff_fqdn_rr_set_log(const zone_diff_fqdn_rr_set *rr_set, const u8* origin, logger_handle *handle, int level)
{
    ptr_set_iterator rr_iter;

    // for all marked rr

    ptr_set_iterator_init(&rr_set->rr, &rr_iter);
    while(ptr_set_iterator_hasnext(&rr_iter))
    {
        ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;

        rdata_desc rdatadesc = {rr->rtype, rr->rdata_size, rr->rdata};

        format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};

        logger_handle_msg_nocull(handle, level, LOG_TEXT_PREFIX "zone-diff: %{dnsname}: %{dnsname}: %02x: %w: %{dnsname} %i %{typerdatadesc}",
                origin, rr->fqdn,
                rr->state, &temp_fw_0, rr->fqdn, rr->ttl, &rdatadesc);
    }
}

void
zone_diff_fqdn_log(const zone_diff_fqdn* diff_fqdn, const u8 *origin, logger_handle *handle, int level)
{
    if(!log_is_set(handle, level))
    {
        return;
    }

    // for all rrset
    
    const u8 *diff_fqdn_name = diff_fqdn->fqdn;

    if(origin == NULL)
    {
        origin = (const u8 *)"\004NULL";
    }

    format_writer temp_fw_1 = {zone_diff_fqdn_changes_format, diff_fqdn};

    logger_handle_msg_nocull(handle, level, LOG_TEXT_PREFIX "zone-diff: %{dnsname}: %{dnsname}: %w", origin, diff_fqdn_name, &temp_fw_1);

    // for all records

    u32_set_iterator rrset_iter;
    u32_set_iterator_init(&diff_fqdn->rrset, &rrset_iter);
    while(u32_set_iterator_hasnext(&rrset_iter))
    {
        u32_node *rrset_node = u32_set_iterator_next_node(&rrset_iter);

        zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)rrset_node->value;

        if(rr_set == NULL)
        {
            log_debug("zone-diff: %{dnsname}: %{dnsname} has no record set", origin, diff_fqdn_name);
            continue;
        }

        format_writer temp_fw_1 = {zone_diff_fqdn_changes_format, diff_fqdn};
        logger_handle_msg_nocull(handle, level, LOG_TEXT_PREFIX "zone-diff: %{dnsname}: %{dnsname}: %w", origin, diff_fqdn_name, &temp_fw_1);

        zone_diff_fqdn_rr_set_log(rr_set, origin, handle, level);
    }
}

void
zone_diff_log(const zone_diff *diff, logger_handle *handle, int level)
{
    if(!log_is_set(handle, level))
    {
        return;
    }

    ptr_set_iterator fqdn_iter;
    
    // for all fqdn
    
    ptr_set_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_set_iterator_hasnext(&fqdn_iter))
    {
        ptr_node *diff_fqdn_node = ptr_set_iterator_next_node(&fqdn_iter);
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;
        zone_diff_fqdn_log(diff_fqdn, diff->origin, handle, level);
    }
}

int
zone_diff_check_changes(const zone_diff *diff, logger_handle *handle, int level)
{
    ptr_set_iterator fqdn_iter;

    int changes = 0;

    ptr_set_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_set_iterator_hasnext(&fqdn_iter))
    {
        ptr_node *diff_fqdn_node = ptr_set_iterator_next_node(&fqdn_iter);
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;

        u32_set_iterator rrset_iter;
        u32_set_iterator_init(&diff_fqdn->rrset, &rrset_iter);
        while(u32_set_iterator_hasnext(&rrset_iter))
        {
            u32_node *rrset_node = u32_set_iterator_next_node(&rrset_iter);

            zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)rrset_node->value;

            ptr_set_iterator rr_iter;

            ptr_set_iterator_init(&rr_set->rr, &rr_iter);
            while(ptr_set_iterator_hasnext(&rr_iter))
            {
                ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;

                if(!(rr->state & ZONE_DIFF_RR_AUTOMATED))
                {
                    if(rr->state & (ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE))
                    {
                        ++changes;
                    }
                }
            }
        }
    }


    if(changes == 0)
    {
        zone_diff_log(diff, handle, level);
    }

    return changes;
}

/**
 * Signs RRSET with all active keys found in keys.
 * Doesn't do any pertinence tests.
 * It's only use now is to add RRSIG records to NSEC3 rrsets that have no valid signatures
 *
 */

void
zone_diff_sign_rrset(zone_diff *diff, zdb_zone *zone, ptr_vector *keys, ptr_vector *add, zone_diff_fqdn_rr_set *rr_set, zone_diff_fqdn_rr_set *rrsig_rr_set)
{
    ptr_vector rrset = PTR_VECTOR_EMPTY;
    dnskey_signature ds;
    dnskey_signature_init(&ds);

    // setup the view for the RRSET (RRSET abstraction for the part that generates signatures)

    struct resource_record_view rrv = {NULL, &zone_diff_label_rr_rrv_vtbl};
    rrv.data = rr_set;

    ptr_vector_clear(&rrset);

    //const u8* rr_fqdn = NULL;

    u8 rrsig_state_mask = ZONE_DIFF_RR_AUTOMATED;

    // accumulate records

    FOREACH_PTR_SET(void*,value, &rr_set->rr)
    {
        zone_diff_label_rr* rr = (zone_diff_label_rr*)value;
        //rr_fqdn = rr->fqdn;

        // if the RR will exist in the zone (A.K.A: not removed), add it to the collection to sign
        if((rr->state & ZONE_DIFF_RR_REMOVE) == 0)
        {
#if DEBUG
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug2("update: %{dnsname}: covers %w %{dnsname} %9i %{typerdatadesc}%s", diff->origin, &temp_fw_0, rr->fqdn, rr->ttl, &rd,
                       ((rr->state & ZONE_DIFF_RR_AUTOMATED)!=0)?"<AUTOMATED>":"");
#endif
            rrsig_state_mask &= rr->state;

            ptr_vector_append(&rrset, value);
        }
        else
        {
#if DEBUG
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug2("update: %{dnsname}: ignore %w %{dnsname} %9i %{typerdatadesc}", diff->origin, &temp_fw_0, rr->fqdn, rr->ttl, &rd);
#endif
        }
    }

    for(int j = 0; j <= ptr_vector_last_index(keys); ++j)
    {
        const dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, j);

        // check if the key has private components

        if(!dnskey_is_private(key))
        {
            log_debug("update: %{dnsname}: key K%{dnsname}+%03d+%05d is not private", diff->origin,
                      dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key));
            continue;
        }

        zone_diff_label_rr *rrsig_rr = NULL;

        ya_result ret;

        s32 maxinterval = diff_generate_signature_interval(diff);

        // rrset_to_sign;
        if(ISOK(ret = dnskey_sign_rrset_with_maxinterval(key, &rrset, TRUE, &rrv, maxinterval, (void **) &rrsig_rr)))
        {
            // add the key to the add set

            log_debug2("update: %{dnsname}: signed %{dnsname} %{dnstype} rrset with key %03d %05d",diff->origin,
                       rrsig_rr->fqdn, &rr_set->rtype,
                       dnskey_get_algorithm(key), dnskey_get_tag_const(key));

            s32 signature_valid_until = rrsig_get_valid_until_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

            // if the signature expires in this time

            if(signature_valid_until > 0)
            {
                if(signature_valid_until < dnskey_get_inactive_epoch(key))
                {
                    s32 signature_regeneration_time = signature_valid_until - diff->rrsig_validity_regeneration;

                    if(zone->progressive_signature_update.earliest_signature_expiration > signature_regeneration_time)
                    {
                        zone->progressive_signature_update.earliest_signature_expiration = signature_regeneration_time;
                    }
                }
                else
                {
                    if(zone->progressive_signature_update.earliest_signature_expiration > signature_valid_until)
                    {
                        zone->progressive_signature_update.earliest_signature_expiration = signature_valid_until;
                    }
                }
            }

            rrsig_rr->state |= rrsig_state_mask;
#if 0 /* fix */
#else
            zone_diff_label_rr *final_rrsig_rr = zone_diff_fqdn_rr_set_rr_add_get(rrsig_rr_set, rrsig_rr);
            if((final_rrsig_rr->state & ZONE_DIFF_RR_IN_ZONE) == 0)
            {
                ptr_vector_append(add, final_rrsig_rr);
            }
#endif
        }
        else
        {
            log_warn("update: %{dnsname}: failed to sign with key %03d %05d: %r",
                     diff->origin,
                     dnskey_get_algorithm(key), dnskey_get_tag_const(key), ret);
            // ...
        }
    } // for each key
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

ya_result
zone_diff_sign(zone_diff *diff, zdb_zone *zone, ptr_vector* rrset_to_sign_vector, ptr_vector *ksks, ptr_vector *zsks, ptr_vector *remove, ptr_vector* add)
{
    /**************************************************************************
     * SIGNATURES HANDLING
     **************************************************************************/

    (void)remove;

    // if there are no rrset to be signed, don't bother going further

    if(ptr_vector_last_index(rrset_to_sign_vector) < 0)
    {
        return SUCCESS;
    }

    // eliminate potential duplicates (rare case)

    {
        ptr_vector_qsort(rrset_to_sign_vector, ptr_vector_compare_pointers_callback);

        void *prev = ptr_vector_get(rrset_to_sign_vector, 0);
        for(s32 i = 1; i <= ptr_vector_last_index(rrset_to_sign_vector);)
        {
            void *item = ptr_vector_get(rrset_to_sign_vector, i);
            if(item == prev)
            {
                ptr_vector_remove_at(rrset_to_sign_vector, i);
                continue;
            }

            prev = item;

            ++i;
        }
    }
    
    /*
     * for each rrset in rrset_to_sign
     *   for each valid zsk in the keyring
     *     start new signature
     *     add each record
     *     generate signature
     */
    
    log_debug("update: %{dnsname}: signing differences", diff->origin);

#if DEBUG
    zone_diff_log(diff, MODULE_MSG_HANDLE, MSG_DEBUG2);
#endif
    
    // if there is a chain, proceed with the changes
    
    ptr_vector rrset = PTR_VECTOR_EMPTY;
    dnskey_signature ds;
    dnskey_signature_init(&ds);

    // setup the view for the RRSET (RRSET abstraction for the part that generates signatures)

    struct resource_record_view rrv = {NULL, &zone_diff_label_rr_rrv_vtbl};

    // for each RRSET

    for(int i = 0; i <= ptr_vector_last_index(rrset_to_sign_vector); ++i)
    {
        zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)ptr_vector_get(rrset_to_sign_vector, i);
        
        log_debug1("update: %{dnsname}: signing (trying) %{dnstype} rrset @%p", diff->origin, &rr_set->rtype, rr_set);

        rrv.data = rr_set;
        
        ptr_vector_clear(&rrset);
        
        u8 rrsig_state_mask = ZONE_DIFF_RR_AUTOMATED;

        // for each record in the RRSET

        const u8* rr_fqdn = NULL;

        // accumulate records

        FOREACH_PTR_SET(void*,value, &rr_set->rr)
        {
            zone_diff_label_rr* rr = (zone_diff_label_rr*)value;
            rr_fqdn = rr->fqdn; // keep the fqdn from the first match

#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
            if(rr_set->rtype == TYPE_DNSKEY)
            {
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
                log_info("update: %{dnsname}: [%02x] %{dnsname} %9i %{typerdatadesc}", diff->origin, rr->state, rr->fqdn, rr->ttl, &rd);
            }
#endif

            // if the RR will exist in the zone (A.K.A: not removed), add it to the collection to sign
            if((rr->state & ZONE_DIFF_RR_REMOVE) == 0)
            {
#if DEBUG        
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
                format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
                log_debug2("update: %{dnsname}: covers %w %{dnsname} %9i %{typerdatadesc}%s", diff->origin, &temp_fw_0, rr->fqdn, rr->ttl, &rd,
                          ((rr->state & ZONE_DIFF_RR_AUTOMATED)!=0)?"<AUTOMATED>":"");
#endif
                rrsig_state_mask &= rr->state;
                
                ptr_vector_append(&rrset, value);
            }
            else
            {
#if DEBUG        
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
                format_writer temp_fw_0 = {zone_diff_record_state_format, &rr->state};
                log_debug2("update: %{dnsname}: ignore %w %{dnsname} %9i %{typerdatadesc}", diff->origin, &temp_fw_0, rr->fqdn, rr->ttl, &rd);
#endif
            }
        }

        if(rr_fqdn == NULL)
        {
            continue;
        }

#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
        if(rr_set->rtype == TYPE_DNSKEY)
        {
            log_info("update: %{dnsname}: DNSKEY records may be updated", diff->origin);
        }
#endif

        // if the collection is empty, nothing more to do for this RRSET

        zone_diff_fqdn *rrsig_label = zone_diff_fqdn_add(diff, rr_fqdn, NULL);

        if(ptr_vector_last_index(&rrset) < 0)
        {
            // except removing all signatures associated with it ...

            if(rrsig_label != NULL)
            {

#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
                if(rr_set->rtype == TYPE_DNSKEY)
                {
                    log_info("update: %{dnsname}: DNSKEY rrset empty, all its signatures will be removed", diff->origin);
                }
#endif

                zone_diff_fqdn_rr_set *rrsig_label_rrset = zone_diff_fqdn_rr_set_add(rrsig_label, TYPE_RRSIG);

                FOREACH_PTR_SET(void*,value, &rrsig_label_rrset->rr)
                {
                    zone_diff_label_rr* rrsig_rr = (zone_diff_label_rr*)value;

                    if(rrsig_get_type_covered_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size) == rr_set->rtype)
                    {
#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
                        if(rr_set->rtype == TYPE_DNSKEY)
                        {
                            rdata_desc rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                            log_info("update: %{dnsname}: will remove %{dnsname} %9i %{typerdatadesc}", diff->origin, rrsig_rr->fqdn, rrsig_rr->ttl, &rd);
                        }
#endif
                        if((rrsig_rr->state & ZONE_DIFF_RR_REMOVED) == 0)
                        {
                            rrsig_rr->state &= ~ZONE_DIFF_RR_ADD;
                            rrsig_rr->state |= ZONE_DIFF_RR_REMOVE;
#if DEBUG
                            rdata_desc rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                            log_debug("update: %{dnsname}: will remove %{dnsname} %9i %{typerdatadesc}", diff->origin, rrsig_rr->fqdn, rrsig_rr->ttl, &rd);
#endif
                            ptr_vector_append(remove, rrsig_rr);
                            rrsig_rr->state |= ZONE_DIFF_RR_REMOVED;
                        }
                    }
                }
            }
            continue;
        }

        yassert(rrsig_label != NULL);

        zone_diff_fqdn_rr_set *rrsig_label_rrset = zone_diff_fqdn_rr_set_add(rrsig_label, TYPE_RRSIG);

        yassert(rrsig_label_rrset != NULL);

        // take note that some RRSIG records will be added
        
        rrsig_state_mask |= ZONE_DIFF_RR_ADD;
                
        bool canonize = TRUE;

        ptr_vector *keys;

        yassert(rr_set->rtype != TYPE_RRSIG);

        // use the adequate DNSKEY collection
        
        keys = (rr_set->rtype != TYPE_DNSKEY)?zsks:ksks;

        // for all keys from said collection

        for(int j = 0; j <= ptr_vector_last_index(keys); ++j)
        {
            const dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, j);

            // check if the key is to be used (using the key_mask)

            if((rr_set->key_mask & (1ULL << j)) == 0)
            {
#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
                if(rr_set->rtype == TYPE_DNSKEY)
                {
                    log_info("update: %{dnsname} DNSKEY will not use key %03d %05d as the signature doesn't need an update", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                }
#endif

#if DEBUG
                zone_diff_label_rr* rr = ptr_vector_get(&rrset, 0);

                log_debug2("update: %{dnsname}: %{dnsname} %{dnstype} does not need a signature update for key %03d %05d",
                        diff->origin,
                        rr->fqdn, &rr->rtype,
                        dnskey_get_algorithm(key), dnskey_get_tag_const(key));
#endif
                continue; // skip
            }

            // check if the key has private components

            if(!dnskey_is_private(key))
            {
#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
                if(rr_set->rtype == TYPE_DNSKEY)
                {
                    log_info("update: %{dnsname} DNSKEY cannot use key %03d %05d as it is not private",
                            diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                }
#endif
                log_debug("update: %{dnsname}: key K%{dnsname}+%03d+%05d is not private", diff->origin,
                        dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                continue;
            }

            if(dnskey_is_deactivated(key, time(NULL) - 5)) // don't generate it if it's about to expire
            {
#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
                if(rr_set->rtype == TYPE_DNSKEY)
                {
                    log_info("update: %{dnsname} DNSKEY cannot use key %03d %05d as its deactivated",
                            diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                }
#endif
                log_debug("update: %{dnsname}: key K%{dnsname}+%03d+%05d is about to be deactivated", diff->origin,
                          dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                continue;
            }

            zone_diff_label_rr *rrsig_rr = NULL;
            
            ya_result ret;

            s32 maxinterval = diff_generate_signature_interval(diff);
            
            // rrset_to_sign;
            if(ISOK(ret = dnskey_sign_rrset_with_maxinterval(key, &rrset, canonize, &rrv, maxinterval, (void **)&rrsig_rr)))
            {
                canonize = FALSE;

                // add the key to the add set

#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
                if(rr_set->rtype == TYPE_DNSKEY)
                {
                    log_info("update: %{dnsname} DNSKEY has been signed with key %03d %05d", diff->origin, dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                }
#endif
                
                log_debug2("update: %{dnsname}: signed %{dnsname} %{dnstype} rrset with key %03d %05d",diff->origin,
                        rrsig_rr->fqdn, &rr_set->rtype,
                        dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                
                s32 signature_valid_until = rrsig_get_valid_until_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

                // if the signature expires in this time

                if(signature_valid_until > 0)
                {
                    if(signature_valid_until < dnskey_get_inactive_epoch(key))
                    {
                        s32 signature_regeneration_time = signature_valid_until - diff->rrsig_validity_regeneration;

                        if(zone->progressive_signature_update.earliest_signature_expiration > signature_regeneration_time)
                        {
                            zone->progressive_signature_update.earliest_signature_expiration = signature_regeneration_time;
                        }
                    }
                    else
                    {
                        if(zone->progressive_signature_update.earliest_signature_expiration > signature_valid_until)
                        {
                            zone->progressive_signature_update.earliest_signature_expiration = signature_valid_until;
                        }
                    }
                }
                
                rrsig_rr->state |= rrsig_state_mask;
#if 0 /* fix */
#else
#if DEBUG
                {
                    rdata_desc rrsig_rr_desc = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                    log_debug6("update: %{dnsname}: signature <= %p [%02x] %{dnsname} %i %{typerdatadesc}", diff->origin, rrsig_rr, rrsig_rr->state, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_desc);
                }
#endif
                zone_diff_label_rr *final_rrsig_rr = zone_diff_fqdn_rr_set_rr_add_get(rrsig_label_rrset, rrsig_rr); // replace is right (should be unique)
#if DEBUG
                {
                    rdata_desc rrsig_rr_desc = {final_rrsig_rr->rtype, final_rrsig_rr->rdata_size, final_rrsig_rr->rdata};
                    log_debug6("update: %{dnsname}: signature => %p [%02x] %{dnsname} %i %{typerdatadesc}", diff->origin, final_rrsig_rr, final_rrsig_rr->state, final_rrsig_rr->fqdn, final_rrsig_rr->ttl, &rrsig_rr_desc);
                }
#endif
                if((final_rrsig_rr->state & ZONE_DIFF_RR_IN_ZONE) == 0)
                {
                    ptr_vector_append(add, final_rrsig_rr);

                    if(rrsig_label != NULL)
                    {
                        // int rrsig_count = 0;

                        FOREACH_PTR_SET(void*,value, &rrsig_label_rrset->rr)
                        {
                            zone_diff_label_rr* rrsig_rr = (zone_diff_label_rr*)value;

                            if((rrsig_rr->state & (ZONE_DIFF_RR_IN_ZONE|ZONE_DIFF_RR_REMOVE|ZONE_DIFF_RR_REMOVED)) == ZONE_DIFF_RR_IN_ZONE)   // if the key is marked as being removed, no need to remove it twice
                            {
                                // key is kept or added

                                u16 ctype = rrsig_get_type_covered_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size); // type covered by the signature
                                if(ctype == rr_set->rtype)
                                {
                                    u16 keytag = rrsig_get_key_tag_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

                                    if(keytag == dnskey_get_tag_const(key))
                                    {
                                        u8 keyalg = rrsig_get_algorithm_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

                                        if(keyalg == dnskey_get_algorithm(key))
                                        {
#if DEBUG
                                            rdata_desc rrsig_rr_desc = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                                            log_debug6("update: %{dnsname}: [%02x] %{dnsname} %i %{typerdatadesc} is obsolete", diff->origin, rrsig_rr->state, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_desc);
#endif
                                            rrsig_rr->state |= ZONE_DIFF_RR_REMOVE;
                                            ptr_vector_append(remove, rrsig_rr);
                                            rrsig_rr->state |= ZONE_DIFF_RR_REMOVED;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
#endif
                //(void)rrsig_rr_set;
            }
            else
            {
                log_warn("update: %{dnsname}: failed to sign with key %03d %05d: %r",
                        diff->origin,
                        dnskey_get_algorithm(key), dnskey_get_tag_const(key), ret);
                // ...
            }
        } // for each key

        // remove signatures not covered by an active key

        if(rrsig_label != NULL)
        {
            int rrsig_count = 0;
            int rrsig_known = 0;
            int rrsig_ignored = 0;

            FOREACH_PTR_SET(void*,value, &rrsig_label_rrset->rr)
            {
                ++rrsig_known;

                zone_diff_label_rr* rrsig_rr = (zone_diff_label_rr*)value;
#if DEBUG
                rdata_desc rrsig_rr_desc = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                log_debug6("update: %{dnsname}: [%02x] %{dnsname} %i %{typerdatadesc}", diff->origin, rrsig_rr->state, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_desc);
#endif
                if(rrsig_rr->state & ZONE_DIFF_RR_REMOVE)   // if the key is marked as being removed, no need to remove it twice
                {
                    rrsig_label->rrsig_removed = 1;
                    continue;
                }

                // key is kept or added

                u16 ctype = rrsig_get_type_covered_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size); // type covered by the signature
                if(ctype == rr_set->rtype)
                {
                    u16 keytag = rrsig_get_key_tag_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);
                    u8 keyalg = rrsig_get_algorithm_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

                    bool keep = FALSE;

                    ++rrsig_ignored;

                    for(int j = 0; j <= ptr_vector_last_index(keys); ++j)
                    {
                        const dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, j);

                        if((dnskey_get_algorithm(key) == keyalg) && (dnskey_get_tag_const(key) == keytag))
                        {
                            --rrsig_ignored;
                            ++rrsig_count;
                            keep = TRUE;
                            break;
                        }
                    }

                    if(keep)
                    {
                        if(rrsig_rr->state & ZONE_DIFF_RR_ADD)
                        {
                            rrsig_label->rrsig_added = 1;       // new
                        }
                        else
                        {
                            rrsig_label->rrsig_kept = 1;        // already in zone
                        }
                    }
                    else
                    {
#if DEBUG
                        rdata_desc rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                        log_debug("update: %{dnsname}: will remove %{dnsname} %9i %{typerdatadesc}", diff->origin, rrsig_rr->fqdn, rrsig_rr->ttl, &rd);
#endif
                        rrsig_rr->state |= ZONE_DIFF_RR_REMOVE;
                        ptr_vector_append(remove, rrsig_rr);
                        rrsig_rr->state |= ZONE_DIFF_RR_REMOVED;
                    }
                }
            } // for all RRSIG in the RRSIG rrset

            if(rrsig_count == 0)
            {
                // record set cannot be properly signed

                log_warn("update: %{dnsname}: %{dnsname} %{dnstype} not covered by a signature (%i signatures in the set, %i ignored for the type)",
                        diff->origin, rr_fqdn, &rr_set->rtype,
                        rrsig_known, rrsig_ignored);

                if(rrsig_label != NULL)
                {
                    int rrsig_index = 0;
                    FOREACH_PTR_SET(void*,value, &rrsig_label_rrset->rr)
                    {
                        zone_diff_label_rr* rrsig_rr = (zone_diff_label_rr*)value;

                        rdata_desc rrsig_record = {TYPE_RRSIG, rrsig_rr->rdata_size, rrsig_rr->rdata};
                        log_warn("update: %{dnsname}: %02i [%02x] %{dnsname} %5i %{typerdatadesc}", diff->origin, rrsig_index, rrsig_rr->state, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_record);
                        ++rrsig_index;
                    }
                }

                dnskey_signature_finalize(&ds);
                ptr_vector_destroy(&rrset);

                return DNSSEC_ERROR_RRSIG_NOUSABLEKEYS;
            }
            else
            {
                // record set cannot be properly signed and has no valid signatures
#if DEBUG
                log_debug1("update: %{dnsname}: %{dnsname} %{dnstype} is covered by a signature", diff->origin, rr_fqdn, &rr_set->rtype);
#endif
            }
        } // if(rrsig_label != NULL)
    } // for(int i = 0; i <= ptr_vector_last_index(rrset_to_sign_vector); ++i) // FOR EACH RRSET

    dnskey_signature_finalize(&ds);
    ptr_vector_destroy(&rrset);

    return SUCCESS;
}

void
zone_diff_store_diff_dnskey_get_keys(zone_diff *diff, ptr_vector *ksks, ptr_vector *zsks)
{
    // remove all signing keys that are about to be removed
    // add all activated signing keys that are being added

    const zone_diff_fqdn *apex = diff->apex;
    const zone_diff_fqdn_rr_set *dnskey_rrset = zone_diff_fqdn_rr_get_const(apex, TYPE_DNSKEY);

    if(dnskey_rrset != NULL)
    {
        // for all keys, handle added and removed ones

        time_t now = time(NULL);

        dnssec_key *key;

        ptr_set_iterator rr_iter;
        ptr_set_iterator_init(&dnskey_rrset->rr, &rr_iter);
        while(ptr_set_iterator_hasnext(&rr_iter))
        {
            ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;
#if DEBUG
            log_debug("update: DNSKEY: 'K%{dnsname}+%03d+%05hd': key listed (%02x)", diff->origin,
                     dnskey_get_algorithm_from_rdata(rr->rdata),
                     dnskey_get_tag_from_rdata(rr->rdata, rr->rdata_size), rr->state);
#endif
            if((rr->state & ZONE_DIFF_RR_REMOVE) == 0) // exists or is being added
            {
                key = NULL;
                ya_result ret = dnssec_keystore_load_private_key_from_rdata(rr->rdata, rr->rdata_size, rr->fqdn, &key);

                if(ISOK(ret))
                {
                    ptr_vector *keys = NULL;

                    if(dnskey_get_flags(key) == DNSKEY_FLAGS_KSK)
                    {
                        keys = ksks;
                    }
                    else if(dnskey_get_flags(key) == DNSKEY_FLAGS_ZSK)
                    {
                        keys = zsks;
                    }

                    // if key is activated, and not already in the (signing) set, add it
#if DEBUG
                    log_debug("update: DNSKEY: 'K%{dnsname}+%03d+%05hd': key found, exists or is about to be added", diff->origin,
                             dnskey_get_algorithm(key), dnskey_get_tag_const(key));
#endif
                    if(dnskey_is_activated_lenient(key, now, 5))
                    {
#if DEBUG
                        log_debug("update: DNSKEY: 'K%{dnsname}+%03d+%05hd': private key is active", diff->origin,
                                 dnskey_get_algorithm(key), dnskey_get_tag_const(key));
#endif

#if DEBUG
                        log_debug("update: DNSKEY: 'K%{dnsname}+%03d+%05hd': private key added in signers", diff->origin,
                                 dnskey_get_algorithm(key), dnskey_get_tag_const(key));
#endif
                        ptr_vector_append(keys, key);
                    }
                    else
                    {
#if DEBUG
                        log_debug("update: DNSKEY: 'K%{dnsname}+%03d+%05hd': private key is not active", diff->origin,
                                  dnskey_get_algorithm(key), dnskey_get_tag_const(key));
#endif
                    }
                }
                else // key is being removed
                {
                    ya_result ret = dnssec_keystore_load_public_key_from_rdata(rr->rdata, rr->rdata_size, rr->fqdn, &key);

                    if(ISOK(ret))
                    {
#if DEBUG
                        log_debug("update: DNSKEY: 'K%{dnsname}+%03d+%05hd': key found, about to be removed", diff->origin,
                                  dnskey_get_algorithm(key), dnskey_get_tag_const(key));
#endif
                        ptr_vector *keys = NULL;

                        if(dnskey_get_flags(key) == DNSKEY_FLAGS_KSK)
                        {
                            keys = ksks;
                        }
                        else if(dnskey_get_flags(key) == DNSKEY_FLAGS_ZSK)
                        {
                            keys = zsks;
                        }
#if DEBUG
                        log_debug("update: DNSKEY: 'K%{dnsname}+%03d+%05hd': private key not loaded: %r", diff->origin,
                                 dnskey_get_algorithm_from_rdata(rr->rdata),
                                 dnskey_get_tag_from_rdata(rr->rdata, rr->rdata_size), ret);
#endif
                        ptr_vector_append(keys, key);
                    }
                    else
                    {
                        log_err("update: DNSKEY: 'K%{dnsname}+%03d+%05hd': public key not loaded: %r", diff->origin,
                                 dnskey_get_algorithm_from_rdata(rr->rdata),
                                 dnskey_get_tag_from_rdata(rr->rdata, rr->rdata_size), ret);
                    }
                }
            }
        }

    } // else would be surprising

#if DEBUG
    for(int i = 0; i <= ptr_vector_last_index(ksks); ++i)
    {
        dnssec_key *key = (dnssec_key*)ptr_vector_get(ksks, i);
        log_debug3("update: DNSKEY: KSK: 'K%{dnsname}+%03d+%05hd': final state", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
    }

    for(int i = 0; i <= ptr_vector_last_index(zsks); ++i)
    {
        dnssec_key *key = (dnssec_key*)ptr_vector_get(zsks, i);
        log_debug3("update: DNSKEY: ZSK: 'K%{dnsname}+%03d+%05hd': final state", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
    }
#endif
}

static ya_result
zone_diff_verify_dnskey_presence(zone_diff *diff, zdb_zone *zone, ptr_vector *rrset_to_sign, ptr_vector *ksks, ptr_vector *zsks)
{
    ya_result ret = SUCCESS;
    u8 maintain_mode = zone_get_maintain_mode(zone);

    if(maintain_mode > ZDB_ZONE_MAINTAIN_NOSEC)
    {
        for(int i = 0; i <= ptr_vector_last_index(ksks); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(ksks, i);
            log_debug3("update: DNSKEY: KSK: 'K%{dnsname}+%03d+%05hd': key visible", zone->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
        }

        for(int i = 0; i <= ptr_vector_last_index(zsks); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(zsks, i);
            log_debug3("update: DNSKEY: ZSK: 'K%{dnsname}+%03d+%05hd': key visible", zone->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
        }

        zone_diff_fqdn *apex = zone_diff_fqdn_get(diff, diff->origin);

        if(!zone_diff_will_have_rrset_type(apex, TYPE_DNSKEY))
        {
            log_err("update: %{dnsname}: there are no DNSKEY in the zone", zone->origin);
            ret = ZDB_ERROR_ZONE_NO_ACTIVE_DNSKEY_FOUND;
        }

        for(int i = 0; i <= ptr_vector_last_index(rrset_to_sign); ++i)
        {
            zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set*)ptr_vector_get(rrset_to_sign, i);

            if(!diff->rrsig_update_allowed)
            {
                if(rr_set->rtype != TYPE_DNSKEY)
                {
                    if(ptr_vector_last_index(zsks) < 0)
                    {
                        log_warn("update: %{dnsname}: %{dnstype} record set is being modified but no ZSK can sign it", zone->origin, &rr_set->rtype);
                    }
                }
                else
                {
                    if(ptr_vector_last_index(ksks) < 0)
                    {
                        log_warn("update: %{dnsname} DNSKEY record set is being modified but no KSK can sign it", zone->origin);
                    }
                }
            }
        }
    }

    return ret;
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
        ptr_vector ksks = PTR_VECTOR_EMPTY;
        ptr_vector zsks = PTR_VECTOR_EMPTY;
        ptr_vector rrset_to_sign = PTR_VECTOR_EMPTY;

        // store changes in vectors and get the RR sets to sign

        s32 mandatory_changes = zone_diff_get_changes(diff, &rrset_to_sign, &ksks, &zsks, remove, add);

#if DYNUPDATE_DIFF_DETAILED_LOG
        for(int i = 0; i <= ptr_vector_last_index(remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(remove, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug3("update: changes: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int i = 0; i <= ptr_vector_last_index(add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug3("update: changes: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
        }
#endif

#if DEBUG
        log_debug1("update: %{dnsname}: diff changes edited", zone->origin);
        zone_diff_log(diff, MODULE_MSG_HANDLE, MSG_DEBUG2);
#endif

        const bool changes_happened = (mandatory_changes > 0);

        if(changes_happened)
        {
            ret = zone_diff_verify_dnskey_presence(diff, zone, &rrset_to_sign, &ksks, &zsks);

            if(ISOK(ret))
            {
                // sign the records, store the changes in vectors

                ret = zone_diff_sign(diff, zone, &rrset_to_sign, &ksks, &zsks, remove, add);

#if DYNUPDATE_DIFF_DETAILED_LOG
                for(int i = 0; i <= ptr_vector_last_index(remove); ++i)
                {
                    zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(remove, i);
                    rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                    log_debug3("update: sign: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                }

                for(int i = 0; i <= ptr_vector_last_index(add); ++i)
                {
                    zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add, i);
                    rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                    log_debug3("update: sign: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                }
#endif

                ptr_vector_destroy(&rrset_to_sign);

                if(ISOK(ret))
                {
                    zone_diff_get_chain_changes(diff, &dc);

                    // chain deletes should use the existing maps if possible (speed) or generate from the local state (all 'exists')
                    // chain adds should use the local state (all exists not removed + all adds)
#if DEBUG
                    zone_diff_log(diff, MODULE_MSG_HANDLE, MSG_DEBUG2);
#endif
                    dnssec_chain_store_diff(&dc, diff, &zsks, remove, add);

#if DYNUPDATE_DIFF_DETAILED_LOG
                    for(int i = 0; i <= ptr_vector_last_index(remove); ++i)
                    {
                        zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(remove, i);
                        rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                        log_debug3("update: store: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                    }

                    for(int i = 0; i <= ptr_vector_last_index(add); ++i)
                    {
                        zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add, i);
                        rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                        log_debug3("update: store: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                    }
#endif
                }
            }
            else
            {
                zone_diff_label_rr_vector_clear(remove);
                zone_diff_label_rr_vector_clear(add);
                ptr_vector_destroy(&rrset_to_sign);
            }
        }
        else
        {
            zone_diff_label_rr_vector_clear(remove);
            zone_diff_label_rr_vector_clear(add);
            ptr_vector_destroy(&rrset_to_sign);

            if(FAIL(mandatory_changes))
            {
                log_warn("update: %{dnsname} update rejected: %r", zone->origin, mandatory_changes);
            }
        }

        dnssec_keystore_release_keys_from_vector(&zsks);
        dnssec_keystore_release_keys_from_vector(&ksks);

        ptr_vector_destroy(&zsks);
        ptr_vector_destroy(&ksks);
    }
    
    dnssec_chain_finalize(&dc);

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

    // ensure all the private keys are available or servfail

    const zdb_packed_ttlrdata *dnskey_rrset = zdb_zone_get_dnskey_rrset(zone); // zone is locked

    int ksk_count = 0;
    int zsk_count = 0;

    if(dnskey_rrset != NULL)
    {
        do
        {
            u16 flags = DNSKEY_FLAGS(*dnskey_rrset);
            u8  algorithm = DNSKEY_ALGORITHM(*dnskey_rrset);
            u16 tag = DNSKEY_TAG(*dnskey_rrset);                  // note: expensive
            dnssec_key *key = NULL;

            if(!((flags == DNSKEY_FLAGS_KSK) && zdb_zone_get_rrsig_push_allowed(zone)))
            {
                if(ISOK(return_code = dnssec_keystore_load_private_key_from_parameters(algorithm, tag, flags, zone->origin, &key))) // key properly released
                {
                    dnskey_release(key);
                }
                else
                {
                    log_warn("update: unable to load the private key 'K%{dnsname}+%03d+%05hd': %r", zone->origin, algorithm, tag, return_code);
                }
            }
            else
            {
                // on an RRSIG-push-allowed zone, don't try to load a KSK
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

        return_code = ksk_count + zsk_count;
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

        s32 total_size_in_bytes = 0;

        for(int i = 0; i <= ptr_vector_last_index(del_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(del_vector, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            
            log_debug2("update: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);

            total_size_in_bytes += dnsname_len(rr->fqdn);
            total_size_in_bytes += 10;
            total_size_in_bytes += rr->rdata_size;
        }

        for(int i = 0; i <= ptr_vector_last_index(add_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add_vector, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};
            
            log_debug2("update: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
            
#if DEBUG
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

            total_size_in_bytes += dnsname_len(rr->fqdn);
            total_size_in_bytes += 10;
            total_size_in_bytes += rr->rdata_size;
        }
        
        log_debug("update: %{dnsname}: writing message", zone->origin);

        output_stream baos;

        bytearray_output_stream_init(&baos, NULL, total_size_in_bytes);

        for(int i = 0; i <= ptr_vector_last_index(del_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(del_vector, i);

            output_stream_write_dnsname(&baos, rr->fqdn);
            output_stream_write_u16(&baos, rr->rtype);
            output_stream_write_u16(&baos, rr->rclass);
            output_stream_write_nu32(&baos, rr->ttl);
            output_stream_write_nu16(&baos, rr->rdata_size);
            output_stream_write(&baos, rr->rdata, rr->rdata_size);

            if((rr->state & ZONE_DIFF_RR_VOLATILE) != 0)
            {
                zone_diff_label_rr_delete(rr);
            }
        }

        for(int i = 0; i <= ptr_vector_last_index(add_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add_vector, i);

            output_stream_write_dnsname(&baos, rr->fqdn);
            output_stream_write_u16(&baos, rr->rtype);
            output_stream_write_u16(&baos, rr->rclass);
            output_stream_write_nu32(&baos, rr->ttl);
            output_stream_write_nu16(&baos, rr->rdata_size);
            output_stream_write(&baos, rr->rdata, rr->rdata_size);

            if((rr->state & ZONE_DIFF_RR_VOLATILE) != 0)
            {
                zone_diff_label_rr_delete(rr);
            }
        }
        
        log_debug1("update: %{dnsname}: message ready", zone->origin);

        input_stream bais;

        bytearray_input_stream_init(&bais, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos), FALSE);
        
        log_debug("update: %{dnsname}: acquiring journal", zone->origin);

        journal* jnl = NULL;
        if(ISOK(ret = journal_acquire_from_zone_ex(&jnl, zone, TRUE)))
        {
            jnl->vtbl->minimum_serial_update(jnl, zone->text_serial);
            
            u32 journal_max_size = zone->wire_size / 3;
            zdb_zone_info_get_zone_max_journal_size(zone->origin, &journal_max_size);
            jnl->vtbl->maximum_size_update(jnl, journal_max_size);
            
            if(ISOK(ret = journal_append_ixfr_stream(jnl, &bais))) // writes a single page
            {
                log_debug("update: %{dnsname}: wrote %i bytes to the journal", zone->origin, total_size_in_bytes);

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
                    log_info("update: %{dnsname}: applied %u changes (%u bytes), serial=%u", zone->origin, ret, total_size_in_bytes, current_serial);
                                        
                    ret = total_size_in_bytes;
                }
                else
                {
                    log_err("update: %{dnsname}: could not apply changes: %r", zone->origin, total_size_in_bytes, ret);
                }
            }
            else if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
            {
                log_info("update: %{dnsname}: could not write %i bytes to the journal as it is full and the zone needs to be locally stored first", zone->origin, total_size_in_bytes);
            }
            else
            {
                log_err("update: %{dnsname}: could not write %i bytes to the journal: %r", zone->origin, total_size_in_bytes, ret);
            }

            journal_release(jnl);
        }
        else
        {
            log_err("update: %{dnsname}: could not acquire journal: %r", zone->origin, ret);
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
    
#if DEBUG
    log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i)",
            zone->origin, zone, reader, count, secondary_lock, dryrun);
#endif    
    
    if(zdb_zone_invalid(zone))
    {
#if DEBUG
        log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with ZDB_ERROR_ZONE_INVALID",
            zone->origin, zone, reader, count, secondary_lock, dryrun);
#endif
        return ZDB_ERROR_ZONE_INVALID;
    }
     
    if(count == 0)
    {
#if DEBUG
        log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) success with count == 0",
            zone->origin, zone, reader, count, secondary_lock, dryrun);
#endif
        return SUCCESS;
    }

    if(packet_reader_opcode(reader) != (OPCODE_UPDATE >> OPCODE_SHIFT))
    {
#if DEBUG
        log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) not an update message",
                  zone->origin, zone, reader, count, secondary_lock, dryrun);
#endif
        return INVALID_STATE_ERROR;
    }

    // if the status was already set, stop

    if((zdb_zone_set_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF) & ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF) != 0)
    {
        return INVALID_STATE_ERROR; // already
    }

    zdb_packed_ttlrdata* soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);
    
    if(soa == NULL)
    {
#if DEBUG
        log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with ZDB_ERROR_NOSOAATAPEX",
            zone->origin, zone, reader, count, secondary_lock, dryrun);
#endif

        zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

        return ZDB_ERROR_NOSOAATAPEX;
    }

#if DEBUG
    {
        u32 soa_serial = 0;
        rr_soa_get_serial(ZDB_PACKEDRECORD_PTR_RDATAPTR(soa), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa), &soa_serial);
        log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) from serial %u",
                zone->origin, zone, reader, count, secondary_lock, dryrun, soa_serial);
    }
#endif

    zone_diff diff;
    zone_diff_init(&diff, zone, zdb_zone_get_rrsig_push_allowed(zone));

    dnsname_vector name_path;

#if DEBUG
    memset(&name_path, 0xff, sizeof(name_path));
#endif

    u8 *rname;
    u8 *rdata;
    //u32 rname_size;
    u32 rttl;
    ya_result ret; // = SUCCESS;
    ya_result ret_status = 0;
    //s32 zsk_key_update_mask = 0;
    u16 rtype;
    u16 rclass;
    u16 rdata_size;
    s8 has_valid_ksk = -1; // unknown (don't care yet)
    
    u8 wire[MAX_DOMAIN_LENGTH + 10 + 65535];
    
#if DEBUG
    //rdata = (u8*)~0; // DEBUG
    //rname_size = ~0; // DEBUG
    //rttl = ~0;       // DEBUG
    rtype = ~0;      // DEBUG
    rclass = ~0;     // DEBUG
    //rdata_size = ~0; // DEBUG
#endif

    bool changes_occurred = FALSE;
    
#if ZDB_HAS_DNSSEC_SUPPORT
    // zone load private keys
    
    bool dnssec_zone = zdb_zone_is_maintained(zone);
    bool check_for_last_nsec3param_removal = FALSE;
    
    if(dnssec_zone)
    {
        dynupdate_diff_load_private_keys(zone);
    }
#endif

    log_debug1("update: %{dnsname}: reading message", zone->origin);

    // marks the SOA as being automatically removed (as the serial will increase)
    
    zone_diff_record_remove_automated(&diff, zone->apex, zone->origin, TYPE_SOA, soa->ttl, ZDB_PACKEDRECORD_PTR_RDATASIZE(soa), ZDB_PACKEDRECORD_PTR_RDATAPTR(soa));

    int record_index = 0;

    do
    {
        u8 *p = wire;
        int s = sizeof(wire);

        if(FAIL(ret = packet_reader_read_fqdn(reader, p, s)))
        {
            log_err("update: %{dnsname}: failed reading next record fqdn: %r", zone->origin, ret);

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed at fqdn with %r",
                    zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }

        rname = p;
        //rname_size = ret;
        p += ret;
        s -= ret;

        if(!dnsname_locase_verify_charspace(rname))
        {
            log_err("update: %{dnsname}: fqdn contains illegal characters", zone->origin);
            log_memdump(MODULE_MSG_HANDLE,MSG_ERR, rname, dnsname_len(rname), 32);

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                    zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif

            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }

        if(!dnsname_is_subdomain(rname, zone->origin))
        {
            log_err("update: %{dnsname}: %{dnsname} is not a sub-domain", zone->origin, rname);

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                    zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_NOTZONE));
#endif
            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_NOTZONE);
        }

        if((ret = packet_reader_read(reader, p, 10)) != 10)
        {
            ret = UNEXPECTED_EOF;

            log_err("update: %{dnsname}: failed reading next record fields: %r", zone->origin, ret);

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                    zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif

            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }

        rtype = GET_U16_AT(p[0]);
        rclass = GET_U16_AT(p[2]);
        rttl = ntohl(GET_U32_AT(p[4]));
        rdata_size = ntohs(GET_U16_AT(p[8]));

        if((rdata_size > 0) && (rclass == CLASS_ANY))
        {
            log_err("update: %{dnsname}: next record has non-empty rdata with class ANY: %r", zone->origin, RCODE_ERROR_CODE(RCODE_FORMERR));

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                    zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }

        /*
         * Simple consistency test:
         */

        if((rdata_size == 0) && (rclass != CLASS_ANY))
        {
            log_err("update: %{dnsname}: next record has empty rdata with non-ANY class: %r", zone->origin, ret, RCODE_ERROR_CODE(RCODE_FORMERR));

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                    zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }

        if(rdata_size > 0)
        {
            if(FAIL(ret = packet_reader_read_rdata(reader, rtype, rdata_size, p, s)))
            {
                log_err("update: %{dnsname}: failed reading next record rdata: %r", zone->origin, ret);

                zone_diff_finalize(&diff);

#if DEBUG
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                        zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                return RCODE_ERROR_CODE(RCODE_FORMERR);
            }

            rdata = p;
            rdata_size = ret;

            rdata_desc wire_rdatadesc = {rtype, rdata_size, rdata};
            log_debug1("update: %{dnsname}: record [%2i]: %{dnsname} %i %{dnsclass} %{dnstype} %{rdatadesc}",
                       zone->origin, record_index, rname, rttl, &rclass, &rtype, &wire_rdatadesc);
        }
        else
        {
            rdata = NULL;

            log_debug1("update: %{dnsname}: record [%2i]: %{dnsname} %i %{dnsclass} %{dnstype}",
                       zone->origin, record_index, rname, rttl, &rclass, &rtype);
        }

        ++record_index;

        dnsname_to_dnsname_vector(rname, &name_path);

        s32 idx;

        for(idx = 0; idx < zone->origin_vector.size; idx++)
        {
            if(!dnslabel_equals(zone->origin_vector.labels[zone->origin_vector.size - idx], name_path.labels[name_path.size - idx]))
            {
                log_err("update: %{dnsname}: %{dnsname} manual add/del of %{dnstype} records refused", zone->origin, rname, &rtype);

                zone_diff_finalize(&diff);
#if DEBUG
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                        zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_NOTZONE));
#endif
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                return RCODE_ERROR_CODE(RCODE_NOTZONE);
            }
        }
        
        if((rtype == TYPE_NSEC) || (rtype == TYPE_NSEC3))
        {
            // reject any dynupdate operation on a dnssec-maintained record.
            
            log_err("update: %{dnsname}: %{dnsname} manual add/del of %{dnstype} records refused", zone->origin, rname, &rtype);

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                    zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
#endif
            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_REFUSED);
        }

#if ZDB_HAS_NSEC3_SUPPORT // sanity checks
        // If the record is an NSEC3PARAM at the APEX
        if(rtype == TYPE_NSEC3PARAM)
        {
            if(!dnsname_equals_ignorecase(zone->origin, rname))
            {
                // reject adding NSEC3PARAM anywhere else than in the apex
                
                log_err("update: %{dnsname}: %{dnsname} NSEC3PARAM : type is only allowed in the apex", zone->origin, rname);
                
                zone_diff_finalize(&diff);

                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                return RCODE_ERROR_CODE(RCODE_REFUSED);
            }

            if(!ZONE_HAS_NSEC3PARAM(zone) && zdb_zone_has_nsec_chain(zone))
            {
                // don't add/del NSEC3PARAM on a zone that is not already NSEC3 (it works if the zone is not secure but only if the zone has keys already. So for now : disabled)

                log_err("update: %{dnsname}: %{dnsname} NSEC3PARAM add/del refused on an non-dnssec3 zone", zone->origin, rname);

                zone_diff_finalize(&diff);

#if DEBUG
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                        zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
#endif
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                return RCODE_ERROR_CODE(RCODE_REFUSED);
            }
            else
            {
                if((rdata != NULL) && (NSEC3_RDATA_ALGORITHM(rdata) != NSEC3_DIGEST_ALGORITHM_SHA1))
                {
                    // don't touch an unsupported digest
                    
                    log_err("update: %{dnsname}: %{dnsname} NSEC3PARAM with unsupported digest algorithm %d", zone->origin, rname, NSEC3_RDATA_ALGORITHM(rdata));
#if DEBUG
                    log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                        zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_NOTIMP));
#endif
                    zone_diff_finalize(&diff);

                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                    return RCODE_ERROR_CODE(RCODE_NOTIMP);
                }
                
                if(rclass == CLASS_ANY) // remove all
                {
                    // don't remove all NSEC3PARAMs from an NSEC3 zone
                    
                    log_err("update: %{dnsname}: %{dnsname} cannot remove all NSEC3PARAM of an NSEC3 zone", zone->origin, rname);

                    zone_diff_finalize(&diff);
#if DEBUG
                    log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                        zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
#endif
                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                    return RCODE_ERROR_CODE(RCODE_REFUSED);
                }
                else if(rclass == CLASS_NONE) // remove one
                {
                    /// @note important: don't remove the first NSEC3PARAM from an NSEC3 zone if no other is available
                    ///       also note that given the new mechanisms, an NSEC3PARAM being added will not count as one until
                    ///       the whole chain has been created
                    ///       This condition is tested later.

                    check_for_last_nsec3param_removal = TRUE;
                }
                else
                {
                    // scan-build false positive : assumes rdata_size < 0 => impossible
                    //                                  or ((rdata_size == 0) & (rclass == CLASS_ANY)) => this would branch in the first "if" a few lines above
                    ret = nsec3_zone_set_status(zone, ZDB_ZONE_MUTEX_DYNUPDATE, NSEC3PARAM_RDATA_ALGORITHM(rdata), 0, NSEC3PARAM_RDATA_ITERATIONS(rdata), NSEC3PARAM_RDATA_SALT(rdata), NSEC3PARAM_RDATA_SALT_LEN(rdata), NSEC3_ZONE_ENABLED|NSEC3_ZONE_GENERATING);
                    continue;
                }
            }
        } // type == TYPE_NSEC3PARAM
#endif // ZDB_HAS_NSEC3_SUPPORT
        
        if(rclass == CLASS_NONE)
        {
            assert(rdata != NULL);

            // delete from an rrset

            if(rttl != 0)
            {
                zone_diff_finalize(&diff);
                
                log_err("update: %{dnsname}: %{dnsname} record delete expected a TTL set to 0", zone->origin, rname);

#if DEBUG
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                        zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);
                
                return RCODE_ERROR_CODE(RCODE_FORMERR);
            }
            
            if(name_path.size <= zone->origin_vector.size)
            {
                if((rtype == TYPE_SOA) || (rtype == TYPE_ANY))
                {
                    // refused

                    log_err("update: %{dnsname}: refused", zone->origin, rname);
                    
                    zone_diff_finalize(&diff);

#if DEBUG
                    log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                            zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
#endif
                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);
                    
                    return RCODE_ERROR_CODE(RCODE_REFUSED);
                }

                if(rtype == TYPE_DNSKEY)
                {
                    u16 key_flags = DNSKEY_FLAGS_FROM_RDATA(rdata); // scan-build false positive
                                                                    // (rdata == NULL) && (rdata_size == 0) can only occur if (rclass == CLASS_ANY)
                                                                    // the condition is tested and exited for a FORMERR around line 5557

                    if(key_flags == DNSKEY_FLAGS_ZSK)
                    {
                        ret_status |= DYNUPDATE_DIFF_RETURN_DNSKEY_REMOVED;
                    }

                    if(has_valid_ksk < 0)
                    {
                        has_valid_ksk = dnssec_keystore_has_usable_ksk(zone->origin, time(NULL))?1:0;
                    }
                }
            }

#if DEBUG
            log_debug("update: %{dnsname}: delete %{dnsname} %{dnstype} any", zone->origin, rname, &rtype);
#endif
            zdb_rr_label* rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - zone->origin_vector.size) - 1);
            if(rr_label != NULL)
            {
#if DEBUG
                if(RR_LABEL_IRRELEVANT(rr_label)) // debug
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
                            // scan-build false positive : rdata cannot be NULL
                            // (rdata == NULL) && (rdata_size == 0) can only occur if (rclass == CLASS_ANY)
                            // the condition is tested and exited for a FORMERR around line 5557

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
                        if(rr_label != zone->apex)
                        {
#if 0 /* fix */
#else
                            zone_diff_add_fqdn_children(&diff, rname, rr_label);
                            zone_diff_add_fqdn_parents_up_to_below_apex(&diff, rname, zone);
#endif
                        }
#if 0 /* fix */
#else
                        if(!zone_diff_record_remove_existing(&diff, rr_label, rname, rtype, rttl, rdata_size, rdata))
                        {
                            rdata_desc rd = {rtype, rdata_size, rdata};
                            log_warn("update: %{dnsname}: delete %{dnsname} %{typerdatadesc} not in zone", zone->origin, rname, &rd);
                        }
#endif
                    }
                    else
                    {
                        log_debug("update: %{dnsname}: delete %{dnsname} NONE %{dnstype}: no record match", zone->origin, rname, &rtype);
                    }
                }
                else
                {
                    log_debug("update: %{dnsname}: delete %{dnsname} NONE %{dnstype}: no type match", zone->origin, rname, &rtype);
                }
            }
            else
            {
                log_debug("update: %{dnsname}: delete %{dnsname} NONE %{dnstype}: no label match", zone->origin, rname, &rtype);
            }
        }
        else if(rclass == CLASS_ANY) // delete all RRSETs
        {
            if((rttl != 0) || (rdata_size != 0))
            {
                log_err("update: %{dnsname}: format error", zone->origin, rname);

                zone_diff_finalize(&diff);
#if DEBUG
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                        zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                return RCODE_ERROR_CODE(RCODE_FORMERR);
            }
            
            if(name_path.size <= zone->origin_vector.size)
            {
                if((rtype == TYPE_SOA) || (rtype == TYPE_ANY))
                {
                    // refused

                    log_err("update: %{dnsname}: refused", zone->origin, rname);
                    zone_diff_finalize(&diff);
#if DEBUG
                    log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                            zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
#endif
                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                    return RCODE_ERROR_CODE(RCODE_REFUSED);
                }

                if(rtype == TYPE_DNSKEY)
                {
                    // get all keys from the zone_diff
                    // if one of these keys is a ZSK, set the ret_status flag accordingly

                    const zone_diff_fqdn *apex = zone_diff_fqdn_get_const(&diff, zone->origin);
                    const zone_diff_fqdn_rr_set *dnskey_rrset = zone_diff_fqdn_rr_get_const(apex, TYPE_DNSKEY);

                    if(dnskey_rrset != NULL)
                    {
                        ptr_set_iterator rr_iter;

                        ptr_set_iterator_init(&dnskey_rrset->rr, &rr_iter);

                        while(ptr_set_iterator_hasnext(&rr_iter))
                        {
                            ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
                            zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;
                            if((rr->state & ZONE_DIFF_RR_IN_ZONE) != 0)
                            {
                                u16 key_flags = DNSKEY_FLAGS_FROM_RDATA(rr->rdata);
                                if(key_flags == DNSKEY_FLAGS_ZSK)
                                {
                                    ret_status |= DYNUPDATE_DIFF_RETURN_DNSKEY_REMOVED;
                                }

                                if(has_valid_ksk < 0)
                                {
                                    has_valid_ksk = dnssec_keystore_has_usable_ksk(zone->origin, time(NULL))?1:0;
                                }

                                diff.may_add_dnskey = TRUE;
                                break;
                            }
                        }

                        diff.may_remove_dnskey = TRUE;

                        if(has_valid_ksk < 0)
                        {
                            has_valid_ksk = dnssec_keystore_has_usable_ksk(zone->origin, time(NULL))?1:0;
                        }
                    }
                    else
                    {
                        diff.may_remove_dnskey = FALSE;
                        has_valid_ksk = FALSE;
                    }
                }
            }
            
            if(rtype != TYPE_ANY)
            {
                // delete an rrset

#if DEBUG
                log_debug2("update: %{dnsname}: delete %{dnsname} %{dnstype} ...", zone->origin, rname, &rtype);
#endif
                zdb_rr_label *rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - zone->origin_vector.size) - 1);
                if(rr_label != NULL)
                {
#if DEBUG
                    if(RR_LABEL_IRRELEVANT(rr_label)) // debug
                    {
                        log_debug2("update: %{dnsname}: %{dnsname} is irrelevant (1)", zone->origin, rname);
                    }
#endif
                    if(zdb_record_find(&rr_label->resource_record_set, rtype) != NULL)
                    {
                        if(rr_label != zone->apex)
                        {
#if 0 /* fix */
#else
                            zone_diff_add_fqdn_children(&diff, rname, rr_label);
                            zone_diff_add_fqdn_parents_up_to_below_apex(&diff, rname, zone);
#endif
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
                
#if DEBUG
                log_debug2("update: %{dnsname}: delete %{dnsname} %{dnstype} ...", zone->origin, rname, &rtype);
#endif
                zdb_rr_label* rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - zone->origin_vector.size) - 1);
                if(rr_label != NULL)
                {
#if DEBUG
                    if(RR_LABEL_IRRELEVANT(rr_label)) // debug
                    {
                        log_debug2("update: %{dnsname}: %{dnsname} is irrelevant (2)", zone->origin, rname);
                    }
                    if(RR_LABEL_EMPTY_TERMINAL(rr_label))
                    {
                        log_debug2("update: %{dnsname}: %{dnsname} is an empty terminal (2)", zone->origin, rname);
                    }
#endif
                    if(rr_label != zone->apex)
                    {
#if 0 /* fix */
#else
                        zone_diff_add_fqdn_children(&diff, rname, rr_label);
                        zone_diff_add_fqdn_parents_up_to_below_apex(&diff, rname, zone);
#endif
                        zone_diff_record_remove_all_sets(&diff, rr_label, rname);
                    }
                    else
                    {
                        // apex

                        log_err("update: %{dnsname}: removing all records from the apex is forbidden", zone->origin, rname);

                        zone_diff_finalize(&diff);

#if DEBUG
                        log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                                zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
#endif
                        zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                        return RCODE_ERROR_CODE(RCODE_REFUSED);
                    }
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

            assert(rdata != NULL); // to help scan-build

            // scan-build false positive : rdata cannot be NULL
            // (rdata == NULL) && (rdata_size == 0) can only occur if (rclass == CLASS_ANY)
            // the condition is tested and exited for a FORMERR around line 5557

            zdb_rr_label* rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - zone->origin_vector.size) - 1);
            zone_diff_record_add(&diff, rr_label, rname, rtype, rttl, rdata_size, rdata);

            const u8 *above_fqdn = rname;
            for(int index = 1; index < name_path.size; ++index)
            {
                zdb_rr_label* above_rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels + index, (name_path.size - index - zone->origin_vector.size) - 1);
                above_fqdn += above_fqdn[0] + 1;
                zone_diff_fqdn_add(&diff, above_fqdn, above_rr_label);
            }

            if(rr_label != NULL)
            {
                if(rr_label != zone->apex)
                {
#if 0 /* fix */
#else
                    zone_diff_add_fqdn_children(&diff, rname, rr_label);
                    zone_diff_add_fqdn_parents_up_to_below_apex(&diff, rname, zone);
#endif
                }
                else
                {
                    if(rtype == TYPE_DNSKEY)
                    {
                        u16 key_flags = DNSKEY_FLAGS_FROM_RDATA(rdata);
                        if(key_flags == DNSKEY_FLAGS_ZSK)
                        {
                            ret_status |= DYNUPDATE_DIFF_RETURN_DNSKEY_ADDED;
                        }

                        diff.may_add_dnskey = TRUE;
                    }
                }
            }
        }
    }
    while(--count > 0);

    if(check_for_last_nsec3param_removal)
    {
        bool at_least_one_nsec3param_remains = FALSE;

        // look if there is any NSEC3PARAM remaining in the zone
        const zone_diff_fqdn *apex = zone_diff_fqdn_get_const(&diff, zone->origin);
        const zone_diff_fqdn_rr_set *nsec3param_rrset = zone_diff_fqdn_rr_get_const(apex, TYPE_NSEC3PARAM);

        if(nsec3param_rrset != NULL)
        {
            ptr_set_iterator rr_iter;

            ptr_set_iterator_init(&nsec3param_rrset->rr, &rr_iter);

            while(ptr_set_iterator_hasnext(&rr_iter))
            {
                ptr_node *rr_node = ptr_set_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr*)rr_node->value;
                if((rr->state & (ZONE_DIFF_RR_ADD|ZONE_DIFF_RR_REMOVE)) != ZONE_DIFF_RR_REMOVE)
                {
                    at_least_one_nsec3param_remains = TRUE;
                    break;
                }
            }

            if(!at_least_one_nsec3param_remains)
            {
                log_err("update: %{dnsname}: %{dnsname} cannot remove the last NSEC3PARAM of an NSEC3 zone", zone->origin, rname);

                zone_diff_finalize(&diff);

#if DEBUG
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r",
                        zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
#endif
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                return RCODE_ERROR_CODE(RCODE_REFUSED);
            }
        }
        // else there was no NSEC3PARAM to begin with
    }

    if(ISOK(ret) && !dryrun)
    {
        ptr_vector add = PTR_VECTOR_EMPTY;
        ptr_vector del = PTR_VECTOR_EMPTY;
        
#if DEBUG
        log_debug1("update: %{dnsname}: storing diff", zone->origin);
        zone_diff_log(&diff, MODULE_MSG_HANDLE, MSG_DEBUG2);
#endif
        if(ISOK(ret = zone_diff_store_diff(&diff, zone, &del, &add)))
        {
            zdb_zone_error_status_clear(zone, ZDB_ZONE_ERROR_STATUS_DIFF_FAILEDNOUSABLE_KEYS);

#if DEBUG
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
        
#if DEBUG
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

                    log_debug2("update: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);

                    total += dnsname_len(rr->fqdn);
                    total += 10;
                    total += rr->rdata_size;
                }

                for(int i = 0; i <= ptr_vector_last_index(&add); ++i)
                {
                    zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&add, i);
                    rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                    log_debug2("update: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);

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
                    jnl->vtbl->minimum_serial_update(jnl, zone->text_serial);

                    u32 journal_max_size = zone->wire_size / 3;
                    zdb_zone_info_get_zone_max_journal_size(zone->origin, &journal_max_size);
                    jnl->vtbl->maximum_size_update(jnl, journal_max_size);

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

                            if(ret_status & (DYNUPDATE_DIFF_RETURN_DNSKEY_ADDED|DYNUPDATE_DIFF_RETURN_DNSKEY_REMOVED))
                            {
                                ret_status |= DYNUPDATE_DIFF_RETURN_DNSKEY_UPDATED;
                            }
                        }
                        else
                        {
                            log_err("update: %{dnsname}: could not apply journal changes: %r", zone->origin, total, ret);
                        }
                    }
                    else
                    {
                        if(ret == ZDB_JOURNAL_SERIAL_RANGE_LOCKED)
                        {
                            log_notice("update: %{dnsname}: could not write %i bytes to the journal as it is full and busy", zone->origin, total);
                        }
                        else if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                        {
                            log_info("update: %{dnsname}: could not write %i bytes to the journal as it is full and the zone needs to be locally stored first", zone->origin, total);
                        }
                        else
                        {
                            log_err("update: %{dnsname}: could not write %i bytes to the journal: %r", zone->origin, total, ret);
                        }
                    }

                    journal_release(jnl);
                }

                input_stream_close(&bais);
                output_stream_close(&baos);
            }
        } // storediff succeeded
        else
        {
            if(zdb_zone_error_status_getnot_set(zone, ZDB_ZONE_ERROR_STATUS_DIFF_FAILEDNOUSABLE_KEYS))
            {
                log_err("update: %{dnsname}: diff failed: %r", zone->origin, ret);
            }
        }

        zone_diff_label_rr_vector_clear(&del);
        zone_diff_label_rr_vector_clear(&add);
        
        ptr_vector_destroy(&add);
        ptr_vector_destroy(&del);
    }

#if DEBUG
    {
        zdb_packed_ttlrdata *soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);
        if(soa != NULL)
        {
            u32 soa_serial = 0;
            rr_soa_get_serial(ZDB_PACKEDRECORD_PTR_RDATAPTR(soa), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa), &soa_serial);
            log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) to serial %u",
                    zone->origin, zone, reader, count, secondary_lock, dryrun, soa_serial);
        }
        else
        {
            log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) has no SOA anymore",
                      zone->origin, zone, reader, count, secondary_lock, dryrun);
        }
    }
#endif
    
    log_debug("update: %{dnsname}: done", zone->origin);
    
    zone_diff_finalize(&diff);

    if(ISOK(ret))
    {
        ret = ret_status;
    }

#if DEBUG
    log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) returned with %r",
                        zone->origin, zone, reader, count, secondary_lock, dryrun, ret);
#endif
    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

    return ret;
}

/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup dnsdbupdate Dynamic update functions
 * @ingroup dnsdb
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/rfc.h>
#include <dnscore/logger.h>
#include <dnscore/dnsname.h>
#include <dnscore/digest.h>
#include <dnscore/serial.h>

#include <dnscore/dnskey_signature.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/nsec.h"
#include "dnsdb/nsec3.h"

#include <dnscore/base32hex.h>
#include <dnscore/format.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnsdb/zdb_zone_maintenance.h>

#include "dnsdb/dnssec.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/dnssec_keystore.h"

#include "dnsdb/dynupdate_diff.h"
#include "dnsdb/zdb_zone_path_provider.h"
#include "dnsdb/zdb_icmtl.h"
#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif

#define ZDB_JOURNAL_CODE 1
#include "dnsdb/journal.h"

#define MODULE_MSG_HANDLE g_database_logger
extern logger_handle_t *g_database_logger;

// Disable detailed diff log even in debug builds

#define DYNUPDATE_DIFF_DO_NOT_ADD_NSEC3_ON_NON_NSEC3_ZONE 0

#define DYNUPDATE_DIFF_DETAILED_LOG                       0

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

static char zone_diff_record_state_format_letters[9] = {'+', '-', 'O', 'V', 'E', 'A', '+', '-', 'T'};

void        zone_diff_record_state_format(const void *data, output_stream_t *os, int32_t a, char b, bool c, void *reserved_for_method_parameters)
{
    (void)a;
    (void)b;
    (void)c;
    (void)reserved_for_method_parameters;

    uint16_t state = *((uint16_t *)data);
    for(uint_fast32_t i = 0; i < sizeof(zone_diff_record_state_format_letters); ++i)
    {
        char c = ((state & (1 << i)) != 0) ? zone_diff_record_state_format_letters[i] : '_';
        output_stream_write(os, &c, 1);
    }
}

#if DEBUG
static char zone_diff_chain_state_format_letters[8] = {'+', '-', ' ', 'r', 'E', '{', '}', '!'};

static void zone_diff_chain_state_format(const void *data, output_stream_t *os, int32_t a, char b, bool c, void *reserved_for_method_parameters)
{
    (void)a;
    (void)b;
    (void)c;
    (void)reserved_for_method_parameters;

    uint8_t state = *((uint8_t *)data);
    for(uint_fast32_t i = 0; i < sizeof(zone_diff_chain_state_format_letters); ++i)
    {
        char c = ((state & (1 << i)) != 0) ? zone_diff_chain_state_format_letters[i] : '_';
        output_stream_write(os, &c, 1);
    }
}
#endif

static void zone_diff_fqdn_changes_format(const void *data, output_stream_t *os, int32_t a, char b, bool c, void *reserved_for_method_parameters)
{
    (void)a;
    (void)b;
    (void)c;
    (void)reserved_for_method_parameters;

    zone_diff_fqdn *diff = (zone_diff_fqdn *)data;

    if(diff->type_map_changed)
    {
        output_stream_write(os, "MAP ", 4);
    }
    if(diff->all_rrset_added)
    {
        output_stream_write(os, "+ALL ", 5);
    }
    if(diff->all_rrset_removed)
    {
        output_stream_write(os, "-ALL ", 5);
    }
    if(diff->is_apex)
    {
        output_stream_write(os, "APEX ", 5);
    }

    output_stream_write(os, "AT(", 3);
    output_stream_write_u8(os, diff->was_at_delegation ? '1' : '0');
    output_stream_write(os, "->", 2);
    output_stream_write_u8(os, diff->at_delegation ? '1' : '0');
    output_stream_write(os, ") ", 2);

    output_stream_write(os, "UNDER(", 6);
    output_stream_write_u8(os, diff->was_under_delegation ? '1' : '0');
    output_stream_write(os, "->", 2);
    output_stream_write_u8(os, diff->under_delegation ? '1' : '0');
    output_stream_write(os, ") ", 2);

    output_stream_write(os, "DS(", 3);
    output_stream_write_u8(os, diff->had_ds ? '1' : '0');
    output_stream_write(os, "->", 2);
    output_stream_write_u8(os, diff->will_have_ds ? '1' : '0');
    output_stream_write(os, ") ", 2);

    output_stream_write(os, "CHILDREN(", 9);
    output_stream_write_u8(os, diff->had_children ? '1' : '0');
    output_stream_write(os, "->", 2);
    output_stream_write_u8(os, diff->will_have_children ? '1' : '0');
    output_stream_write(os, ") ", 2);

    output_stream_write(os, "RECORDS(", 8);
    output_stream_write_u8(os, diff->was_non_empty ? '1' : '0');
    output_stream_write(os, "->", 2);
    output_stream_write_u8(os, diff->will_be_non_empty ? '1' : '0');
    output_stream_write(os, ") ", 2);
}

static const uint8_t *zone_diff_label_rr_rrv_get_fqdn(void *data, const void *p)
{
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr *)p;
    return rr->fqdn;
}

static uint16_t zone_diff_label_rr_rrv_get_type(void *data, const void *p)
{
    /*
    zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)data;
    (void)p;
    return rrset->rtype;
    */
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr *)p;
    return rr->rtype;
}

static uint16_t zone_diff_label_rr_rrv_get_class(void *data, const void *p)
{
    /*
    zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)data;
    (void)p;
    return rrset->rclass;
    */
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr *)p;
    return rr->rclass;
}

static int32_t zone_diff_label_rr_rrv_get_ttl(void *data, const void *p)
{
    /*
    zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set*)data;
    (void)p;
    return rrset->new_ttl;
    */
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr *)p;
    return rr->ttl;
}

static uint16_t zone_diff_label_rr_rrv_get_rdata_size(void *data, const void *p)
{
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr *)p;
    return rr->rdata_size;
}

static const uint8_t *zone_diff_label_rr_rrv_get_rdata(void *data, const void *p)
{
    (void)data;
    zone_diff_label_rr *rr = (zone_diff_label_rr *)p;
    return (const uint8_t *)rr->rdata;
}

static void *zone_diff_label_rr_rrv_new_instance(void *data, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, uint16_t rdata_size, const uint8_t *rdata)
{
    (void)data;
    zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, rtype, rclass, ttl, (void *)rdata, rdata_size, true);
    return rr;
}

static const struct resource_record_view_vtbl zone_diff_label_rr_rrv_vtbl = {zone_diff_label_rr_rrv_get_fqdn,
                                                                             zone_diff_label_rr_rrv_get_type,
                                                                             zone_diff_label_rr_rrv_get_class,
                                                                             zone_diff_label_rr_rrv_get_ttl,
                                                                             zone_diff_label_rr_rrv_get_rdata_size,
                                                                             zone_diff_label_rr_rrv_get_rdata,
                                                                             zone_diff_label_rr_rrv_new_instance};

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
        ptr_treemap_init(&dc->chain_diff[dc->chains_count]);
        dc->chain_diff[dc->chains_count].compare = dc->chain->compare;
        dc->chains[dc->chains_count] = chain;
        dc->chain_being_deleted[dc->chains_count] = being_deleted;
        ++dc->chains_count;
    }
}

static void dnssec_chain_add_node(dnssec_chain *dc, const uint8_t *fqdn, uint16_t rtype, uint8_t asked_or_mask)
{
    // compute the hash
    // find the prev & next in the current set
    // store a node with "prev new next"
    // store a node with "prev" marked as begin (if !E)
    // store a node with "next" marked as end (if !E)

    (void)rtype;

    for(int_fast32_t chain_index = 0; chain_index < dc->chains_count; ++chain_index)
    {
        void *chain = dc->chains[chain_index];

        // need to know if it's under delegation

        //
#if DEBUG
        log_debug("NEW NODE %{dnsname} (0)", fqdn);
#endif
        void               *chain_node = dc->chain->node_new(fqdn, chain);

        ptr_treemap_node_t *node = ptr_treemap_insert(&dc->chain_diff[chain_index], chain_node);

        // if chain is not empty, edit it, else create it with one node

        if(!dc->chain->isempty(chain))
        {
            uint8_t or_mask = (!dc->chain_being_deleted[chain_index]) ? asked_or_mask : DNSSEC_CHAIN_DELETE;

            if(node->value == NULL)
            {
                node->value = chain_node;

                // create a node for the prev & next

                void *chain_begin = dc->chain->node_prev(chain_node);

                // zone_diff_add_fqdn(dc->diff, node->fqdn, rr_label);

                yassert(chain_begin != NULL);
                ptr_treemap_node_t *node_prev = ptr_treemap_insert(&dc->chain_diff[chain_index], chain_begin);
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
                ptr_treemap_node_t *node_next = ptr_treemap_insert(&dc->chain_diff[chain_index], chain_end);
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

                dc->chain->state_set(node->value, dc->chain->state_get(node->value) & ~(DNSSEC_CHAIN_BEGIN | DNSSEC_CHAIN_END));

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

    void *chain_begin = dc->chain->node_prev(chain_node);
    yassert(chain_begin != NULL);
#if DEBUG
    format_writer_t chain_node_prev_fw;
    dc->chain->format_writer_init(chain_begin, &chain_node_prev_fw);
#endif
    ptr_treemap_node_t *node_prev = ptr_treemap_insert(&dc->chain_diff[chain_index], chain_begin);
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
    format_writer_t chain_node_next_fw;
    dc->chain->format_writer_init(chain_end, &chain_node_next_fw);
#endif
    ptr_treemap_node_t *node_next = ptr_treemap_insert(&dc->chain_diff[chain_index], chain_end);
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

static int dnssec_chain_add_node_from_diff_fqdn(dnssec_chain *dc, zone_diff_fqdn *diff_fqdn, uint16_t rtype, uint8_t asked_or_mask)
{
    int ret = 0;
    // compute the hash
    // find the prev & next in the current set
    // store a node with "prev new next"
    // store a node with "prev" marked as begin (if !E)
    // store a node with "next" marked as end (if !E)

    (void)rtype;

    for(int_fast32_t chain_index = 0; chain_index < dc->chains_count; ++chain_index)
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
        format_writer_t chain_node_fw;
        dc->chain->format_writer_init(chain_node, &chain_node_fw);
        log_debug2("dnssec-chain: %{dnsname}: chain[%i]: node is %w", diff_fqdn->fqdn, chain_index, &chain_node_fw);
#endif

        ptr_treemap_node_t *node = ptr_treemap_insert(&dc->chain_diff[chain_index], chain_node);

        if(!dc->chain->isempty(chain))
        {
            uint8_t or_mask = (!dc->chain_being_deleted[chain_index]) ? asked_or_mask : DNSSEC_CHAIN_DELETE;

            if(node->value == NULL)
            {
#if DEBUG
                log_debug2("dnssec-chain: %{dnsname}: chain[%i]: node %w is new, getting both neighbours", diff_fqdn->fqdn, chain_index, &chain_node_fw);
#endif
                diff_fqdn->will_have_new_nsec = 1;
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
                dc->chain->state_set(node->value, dc->chain->state_get(node->value) & ~(DNSSEC_CHAIN_BEGIN | DNSSEC_CHAIN_END));
            }

            // check if any of the RRSET of the label have been added or removed

            //
            uint8_t prev_state = dc->chain->state_get(node->value);

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
            if(((prev_state & DNSSEC_CHAIN_EXISTS) == 0) || ((or_mask & (DNSSEC_CHAIN_DELETE | DNSSEC_CHAIN_REMAP)) != 0))
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
                dc->chain->state_set(node->value, dc->chain->state_get(node->value) & ~(DNSSEC_CHAIN_BEGIN | DNSSEC_CHAIN_END));
            }
            else
            {
                diff_fqdn->will_have_new_nsec = 1;
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

void dnssec_chain_add(dnssec_chain *dc, const uint8_t *fqdn, uint16_t rtype)
{
    dnssec_chain_add_node(dc, fqdn, rtype, DNSSEC_CHAIN_ADD);
    // It used to be :
    // dnssec_chain_add_node(dc, fqdn, rtype, 0);
}

int dnssec_chain_add_from_diff_fqdn(dnssec_chain *dc, zone_diff_fqdn *diff_fqdn, uint16_t rtype)
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

void dnssec_chain_del(dnssec_chain *dc, const uint8_t *fqdn, uint16_t rtype) { dnssec_chain_add_node(dc, fqdn, rtype, DNSSEC_CHAIN_DELETE); }

int  dnssec_chain_del_from_diff_fqdn(dnssec_chain *dc, zone_diff_fqdn *diff_fqdn, uint16_t rtype)
{
    int ret = dnssec_chain_add_node_from_diff_fqdn(dc, diff_fqdn, rtype, DNSSEC_CHAIN_DELETE);
    return ret;
}

static void dnssec_chain_store_diff_publish_chain_node(dnssec_chain *dc, zone_diff *diff, ptr_vector_t *keys, void *chain, void *prev, void *prev_next, ptr_vector_t *add)
{
    ya_result ret;
    int32_t   from_offset = ptr_vector_size(add);

    dc->chain->publish_add(chain, prev, prev_next, diff, add);

    // and its signature(s)

    int32_t to_offset = ptr_vector_size(add);
    // make a ptr_vector_t that's a view of the last added records
    ptr_vector_t                  rrset = {{&add->data[from_offset]}, 0, to_offset - from_offset};

    struct resource_record_view_s rrv = {NULL, &zone_diff_label_rr_rrv_vtbl};
    uint16_t                      rrset_type = TYPE_NONE;
    for(int_fast32_t i = 0; i <= ptr_vector_last_index(&rrset); ++i)
    {
        void       *data = ptr_vector_get(&rrset, i);
        const void *fqdn = rrv.vtbl->get_fqdn(rrv.data, data);
        uint16_t    rtype = rrv.vtbl->get_type(rrv.data, data);
        uint16_t    rclass = rrv.vtbl->get_class(rrv.data, data);
        int32_t     ttl = rrv.vtbl->get_ttl(rrv.data, data);
        uint16_t    rdata_size = rrv.vtbl->get_rdata_size(rrv.data, data);
        const void *rdata = rrv.vtbl->get_rdata(rrv.data, data);

        rrset_type = rtype;

        rdata_desc_t rdt = {rtype, rdata_size, rdata};
        log_debug("update: %{dnsname}: will sign chain record #%i: %{dnsname} %i %{dnsclass} %{typerdatadesc}", diff->origin, i, fqdn, ttl, &rclass, &rdt);
    }

    bool canonize = true;

    for(int_fast32_t j = 0; j <= ptr_vector_last_index(keys); ++j)
    {
        dnskey_t           *key = (dnskey_t *)ptr_vector_get(keys, j);

        zone_diff_label_rr *rrsig_rr = NULL;

        int32_t             maxinterval = diff_generate_signature_interval(diff);

        // rrset_to_sign;
        if(ISOK(ret = dnskey_sign_rrset_with_maxinterval(key, &rrset, canonize, &rrv, maxinterval, (void **)&rrsig_rr)))
        {
            canonize = false;

            // add the key to the add set

            rdata_desc_t rdt = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
            log_debug(
                "update: %{dnsname}: signed chain rrset %{dnstype} with key %03d %05d: %{dnsname} %i %{dnsclass} "
                "%{typerdatadesc}",
                diff->origin,
                &rrset_type,
                dnskey_get_algorithm(key),
                dnskey_get_tag_const(key),
                rrsig_rr->fqdn,
                rrsig_rr->ttl,
                &rrsig_rr->rclass,
                &rdt);

            rrsig_rr->state |= ZONE_DIFF_RR_VOLATILE;
            ptr_vector_append(add, rrsig_rr);

            // since we are mapping inside the array and the array could have been replaced by a bigger one ...
            rrset.data = &add->data[from_offset];
        }
#if DEBUG
        else
        {
            log_debug("update: %{dnsname}: did not sign rrset %{dnstype} with key %03d %05d: %r", diff->origin, &rrset_type, dnskey_get_algorithm(key), dnskey_get_tag_const(key), ret);
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

void dnssec_chain_store_diff(dnssec_chain *dc, zone_diff *diff, ptr_vector_t *keys, ptr_vector_t *del, ptr_vector_t *add)
{
    // simplify then apply the changes

    // put all the nodes in an array

    ptr_vector_t nodes;

    ptr_vector_init(&nodes);

    // for every chain

    for(int_fast32_t chain_index = 0; chain_index < dc->chains_count; ++chain_index)
    {
        void *chain = dc->chains[chain_index];

        // clear the nodes (from a previous chain)

        ptr_vector_clear(&nodes);

        // gather all the nodes in the chain in an array
        // they are inserted in sorted order (ptr_treemap_iterator_t does this)

        ptr_treemap_iterator_t iter;
        ptr_treemap_iterator_init(&dc->chain_diff[chain_index], &iter);
        while(ptr_treemap_iterator_hasnext(&iter))
        {
            ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
            yassert(node->value != NULL);
            ptr_vector_append(&nodes, node->value);
        }

        // "nodes" is the list of all the nodes

        // look in a circular pattern for all the nodes that have the "delete" status

        log_debug("update: %{dnsname}: %i nodes in dnssec chain #%i", diff->origin, ptr_vector_size(&nodes), chain_index);

        if(ptr_vector_size(&nodes) == 0)
        {
            continue;
        }

#if DEBUG
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&nodes); ++i)
        {
            void           *node = ptr_vector_get_mod(&nodes, i);
            void           *next = (i < ptr_vector_last_index(&nodes)) ? ptr_vector_get_mod(&nodes, i + 1) : NULL;
            uint8_t         state = dc->chain->state_get(node);

            format_writer_t temp_fw_0 = {zone_diff_chain_state_format, &state};
            log_debug1("update: %{dnsname}: %3i: %02x %w", diff->origin, i, state, &temp_fw_0);
            dc->chain->publish_log(node, next);
        }
#endif

        int  first_begin = -1; // the first chain node at the begin of a change
        int  last_end;

        bool whole_chain = false; // does the operation covers the whole chain

        // if the chain isn't empty

        if(!dc->chain->isempty(chain))
        {
            // chain is not empty but may be too small (1 item)

            if(ptr_vector_last_index(&nodes) > 0) // if true, then it has more than one item
            {
                // the chain has more than one item

                // int exists = 0;
                int  begin = 0;
                int  end = 0;
                int  both = 0;

                bool prev_does_not_alter_the_chain = false;

                // note: this block is the initial step of the loop that follows
                // check if the last node of the chain exists already
                {
                    void   *node = ptr_vector_last(&nodes);
                    uint8_t state = dc->chain->state_get(node);

                    if(state & DNSSEC_CHAIN_EXISTS)
                    {
                        //++exists;
                        // if the node exists and is not deleted
                        // 00 != 01 = 1
                        // 01       = 0
                        // 10       = 1
                        // 11       = 1
                        // only false if the node exists, hasn't been added and is being deleted

                        prev_does_not_alter_the_chain = ((state & (DNSSEC_CHAIN_ADD | DNSSEC_CHAIN_DELETE)) != DNSSEC_CHAIN_DELETE);
                    }
                    else // the node did not exist (and thus will be added, as there is no other reason being here)
                    {
                        prev_does_not_alter_the_chain = false; // the chain will be altered
                    }
                }

                // this loop marks nodes with the next field changed

                for(int_fast32_t i = 0; i <= ptr_vector_last_index(&nodes); ++i)
                {
                    void   *node = ptr_vector_get(&nodes, i);
                    uint8_t state = dc->chain->state_get(node);

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
                        //++exists;
                        // if the node exists and is not deleted
                        // only false if the node exists, hasn't been added and is being deleted (same as on the
                        // previous block)
                        does_not_alter_the_chain = ((state & (DNSSEC_CHAIN_ADD | DNSSEC_CHAIN_DELETE)) != DNSSEC_CHAIN_DELETE);
                    }
                    else // the node did not exist (and thus will be added, as there is no other reason being here)
                    {
                        does_not_alter_the_chain = false; // the chain will be altered
                    }

                    // if the current node alters the chain but not the previous one

                    if(!does_not_alter_the_chain && prev_does_not_alter_the_chain) // since this one is added and not the previous one, the previous
                                                                                   // one has to be updated
                    {
                        void   *prev_node = ptr_vector_get_mod(&nodes, i - 1);
                        uint8_t prev_state = dc->chain->state_get(prev_node);
                        dc->chain->state_set(prev_node,
                                             prev_state | (DNSSEC_CHAIN_ADD | DNSSEC_CHAIN_DELETE)); // means "updated"
                    }

                    prev_does_not_alter_the_chain = does_not_alter_the_chain;
                }

                int chain_loops = 0;

                if(begin + end == 0) // there are no blocks marked as "begin" nor "end"
                {
                    // the chain is looping on itself, take the first exist and mark it as begin & end

                    int delete = 0;
                    for(int_fast32_t i = 0; i <= ptr_vector_last_index(&nodes); ++i)
                    {
                        void   *node = ptr_vector_get(&nodes, i);
                        uint8_t state = dc->chain->state_get(node);
                        uint8_t masked_state = state & (DNSSEC_CHAIN_EXISTS | DNSSEC_CHAIN_ADD | DNSSEC_CHAIN_DELETE);

                        // if the node exists, exists and is added or exists and is updated

                        if((masked_state == DNSSEC_CHAIN_EXISTS) || (masked_state == (DNSSEC_CHAIN_EXISTS | DNSSEC_CHAIN_ADD)) || (masked_state == (DNSSEC_CHAIN_EXISTS | DNSSEC_CHAIN_ADD | DNSSEC_CHAIN_DELETE)))
                        {
                            // then mark it as the "begin" and the "end" as well
                            dc->chain->state_set(node, state | (DNSSEC_CHAIN_BEGIN | DNSSEC_CHAIN_END));
                            first_begin = i; // this node is the first (and last) "begin" node
                            chain_loops = 1; // one loop on this whole chain
                            break;
                        }

                        if(masked_state == (DNSSEC_CHAIN_EXISTS | DNSSEC_CHAIN_DELETE))
                        {
                            ++delete;
                        }
                    }

                    // are all nodes deleted?

                    if(delete == ptr_vector_size(&nodes))
                    {
                        void   *node = ptr_vector_get(&nodes, 0);
                        uint8_t state = dc->chain->state_get(node);
                        dc->chain->state_set(node, state | (DNSSEC_CHAIN_BEGIN | DNSSEC_CHAIN_END));
                        first_begin = 0;
                        chain_loops = 1;
                    }
                }
                else if((begin == 1) && (end == 1) && (both == 1)) // there is exactly one "begin", one "end" and one that's both
                {
                    whole_chain = true;
                }

                yassert(first_begin >= 0);

                // chain_loops is 1 iff one node was set as begin & end manually
                // the last "end" is at (modulo) the first "begin" + the number of nodes

                last_end = first_begin + ptr_vector_last_index(&nodes) + chain_loops;
            }
            else // there is only one item in the chain update
            {
                log_debug("update: %{dnsname}: chain #%i update has only one item", diff->origin, chain_index);

                first_begin = 0;
                last_end = ptr_vector_last_index(&nodes); // should be 0
            }
        }
        else // chain is empty, we add everything
        {
            log_debug("update: %{dnsname}: chain #%i is empty", diff->origin, chain_index);

            first_begin = 0;
            last_end = ptr_vector_last_index(&nodes);
        }

        // yassert(dc->chain->isempty(chain) || (first_begin >= 0) || ((first_begin == 0) && (last_end == 0)));

#if DEBUG
        for(int_fast32_t i = first_begin; i <= last_end; ++i)
        {
            void           *node = ptr_vector_get_mod(&nodes, i);
            uint8_t         state = dc->chain->state_get(node);
            void           *next = ((state & (DNSSEC_CHAIN_BEGIN | DNSSEC_CHAIN_END)) != DNSSEC_CHAIN_END) ? ptr_vector_get_mod(&nodes, i + 1) : NULL;

            format_writer_t temp_fw_0 = {zone_diff_chain_state_format, &state};
            log_debug1("update: %{dnsname}: %3i: %02x %w: %p -> %p", diff->origin, i, state, &temp_fw_0, node, next);
            dc->chain->publish_log(node, next);
        }
#endif

        if(dc->chain->isempty(chain) || whole_chain || ((first_begin == 0) && (last_end == 0)))
        {
            // we are processing a new/whole chain, or the chain is made of one record

            // for all nodes from the first to the last (modulo)
            for(int_fast32_t i = first_begin; i <= last_end; ++i)
            {
                int j = i + 1;

                // get the node and its follower

                void   *node = ptr_vector_get_mod(&nodes, i);
                void   *node_next = ptr_vector_get_mod(&nodes, j);

                uint8_t state = dc->chain->state_get(node);

                // if the node exists

                if(state & DNSSEC_CHAIN_EXISTS)
                {
                    // if the node is remapped (bitmask change) or the node is updated
                    if((state & DNSSEC_CHAIN_REMAP) || ((state & (DNSSEC_CHAIN_DELETE | DNSSEC_CHAIN_ADD)) == (DNSSEC_CHAIN_DELETE | DNSSEC_CHAIN_ADD)))
                    {
#if DEBUG
                        log_debug3("update: %{dnsname}: chain %i state (%02x) del/add", diff->origin, chain_index, state);
#endif
                        // delete then add the node
                        dc->chain->publish_delete(chain, node, node_next, diff, del);
                        dnssec_chain_store_diff_publish_chain_node(dc, diff, keys, chain, node, node_next, add);
                    } // if the node is deleted
                    else if(state & DNSSEC_CHAIN_DELETE)
                    {
#if DEBUG
                        log_debug3("update: %{dnsname}: chain %i state (%02x) del", diff->origin, chain_index, state);
#endif
                        // delete the node
                        dc->chain->publish_delete(chain, node, node_next, diff, del);
                    }
                }
                else // if the node doesn't exists
                {
                    if((state & DNSSEC_CHAIN_EXISTS) == 0) // always true at this point
                    {
                        // remove any delete mark
                        state &= ~DNSSEC_CHAIN_DELETE; // cannot delete what does not exists
                        // if the node was marked as a remap (bitmap change)
                        if(state & DNSSEC_CHAIN_REMAP)
                        {
                            state &= ~DNSSEC_CHAIN_REMAP; // do not remap, create
                            state |= DNSSEC_CHAIN_ADD;
                        }

                        dc->chain->state_set(node, state);
                    }

                    // if the node is being added

                    if(state & DNSSEC_CHAIN_ADD)
                    {
#if DEBUG
                        log_debug3("update: %{dnsname}: chain %i state (%02x) add", diff->origin, chain_index, state);
#endif
                        // publish the node
                        dnssec_chain_store_diff_publish_chain_node(dc, diff, keys, chain, node, node_next, add);
                    }
                }
            }

            continue;
        }

        yassert(first_begin != last_end);

        void *next_did_exist_node = NULL;
        void *next_will_exist_node = NULL;
        int   next_did_exist_index = -1;
        int   next_will_exist_index = -1;

        // for all nodes from the first to the last (modulo)

        for(int_fast32_t i = first_begin; i < last_end; ++i)
        {
            void   *node = ptr_vector_get_mod(&nodes, i);
            uint8_t state = dc->chain->state_get(node);

#if DEBUG
            {
                format_writer_t chain_node_fw;
                dc->chain->format_writer_init(node, &chain_node_fw);
                format_writer_t temp_fw_0 = {zone_diff_chain_state_format, &state};
                log_debug1("dnssec-chain: %{dnsname}: chain %i node %w with state %w", diff->origin, chain_index, &chain_node_fw, &temp_fw_0);
            }
#endif

            // if the node doesn't exists

            if((state & DNSSEC_CHAIN_EXISTS) == 0)
            {
                // remove any delete mark
                state &= ~DNSSEC_CHAIN_DELETE; // cannot delete what does not exists

                // if the is marked as remap
                if(state & DNSSEC_CHAIN_REMAP)
                {
                    // remove the remap mark and add it instead
                    state &= ~DNSSEC_CHAIN_REMAP; // do not remap, create
                    state |= DNSSEC_CHAIN_ADD;
                }

                dc->chain->state_set(node, state);
            }

            // if the node is marked as deleted or remapped (note: the node must be marked as "exists" too)

            if(state & (DNSSEC_CHAIN_DELETE | DNSSEC_CHAIN_REMAP))
            {
#if DEBUG
                if((state & DNSSEC_CHAIN_EXISTS) == 0) // impossible, given the previous block
                {
                    format_writer_t chain_node_fw;
                    dc->chain->format_writer_init(node, &chain_node_fw);
                    format_writer_t temp_fw_0 = {zone_diff_chain_state_format, &state};
                    log_err(
                        "dnssec-chain: %{dnsname}: chain %i node %w with state %w should be remapped or deleted but "
                        "does not exist?",
                        diff->origin,
                        chain_index,
                        &chain_node_fw,
                        &temp_fw_0);
                    logger_flush();
                }
#endif
                yassert(state & DNSSEC_CHAIN_EXISTS); // trips on an empty terminal : the node to delete does not exists.

                if(next_did_exist_index <= i) // always true on the first iteration
                {
                    // for all nodes following this one (modulo)

                    for(int_fast32_t j = i + 1; j <= last_end; ++j)
                    {
                        void   *next_node = ptr_vector_get_mod(&nodes, j);
                        uint8_t next_state = dc->chain->state_get(next_node);

#if DEBUG
                        {
                            format_writer_t chain_node_fw;
                            dc->chain->format_writer_init(next_node, &chain_node_fw);
                            format_writer_t temp_fw_0 = {zone_diff_chain_state_format, &next_state};
                            log_debug1(
                                "dnssec-chain: %{dnsname}: chain %i next-node [%i] %w with state %w (delete/remap "
                                "loop)",
                                diff->origin,
                                chain_index,
                                j,
                                &chain_node_fw,
                                &temp_fw_0);
                        }
#endif
                        // if the following node exists, then keep it aside

                        if(next_state & DNSSEC_CHAIN_EXISTS)
                        {
                            next_did_exist_node = next_node;
                            next_did_exist_index = j;
                            break;
                        }
                    }
                }

#if DEBUG
                logger_flush();
#endif
                yassert(next_did_exist_index > i);

                // publish that interval being deleted ...

                dc->chain->publish_delete(chain, node, next_did_exist_node, diff, del);
            }

            // if the node is ...

            switch(state & (DNSSEC_CHAIN_DELETE | DNSSEC_CHAIN_ADD | DNSSEC_CHAIN_EXISTS | DNSSEC_CHAIN_REMAP))
            {
                // added
                // added with a remapped
                // updated
                // existing and added with a remap
                // existing, updated with a remap
                case DNSSEC_CHAIN_ADD:
                case DNSSEC_CHAIN_ADD | DNSSEC_CHAIN_REMAP:
                case DNSSEC_CHAIN_DELETE | DNSSEC_CHAIN_ADD | DNSSEC_CHAIN_EXISTS:
                case DNSSEC_CHAIN_ADD | DNSSEC_CHAIN_EXISTS | DNSSEC_CHAIN_REMAP:
                case DNSSEC_CHAIN_DELETE | DNSSEC_CHAIN_ADD | DNSSEC_CHAIN_EXISTS | DNSSEC_CHAIN_REMAP:
                {
                    if(next_will_exist_index <= i) // always true on the first iteration
                    {
                        // for all nodes following this one (modulo)

                        for(int_fast32_t j = i + 1; j <= last_end; ++j)
                        {
                            void   *next_node = ptr_vector_get_mod(&nodes, j);
                            uint8_t next_state = dc->chain->state_get(next_node);

#if DEBUG
                            {
                                format_writer_t chain_node_fw;
                                dc->chain->format_writer_init(next_node, &chain_node_fw);
                                format_writer_t temp_fw_0 = {zone_diff_chain_state_format, &next_state};
                                log_debug1(
                                    "dnssec-chain: %{dnsname}: chain %i next-node [%i] %w with state %w "
                                    "(add/update/remap loop)",
                                    diff->origin,
                                    chain_index,
                                    j,
                                    &chain_node_fw,
                                    &temp_fw_0);
                            }
#endif
                            // if the node is added, or exist (and will keep existing)
                            // a.k.a
                            // if the node will exist after this operation ...
                            //
                            // then keep it aside

                            if((next_state & DNSSEC_CHAIN_ADD) || ((next_state & (DNSSEC_CHAIN_DELETE | DNSSEC_CHAIN_EXISTS)) == DNSSEC_CHAIN_EXISTS))
                            {
                                next_will_exist_node = next_node;
                                next_will_exist_index = j;
                                break;
                            }
                        }
                    }

#if DEBUG
                    logger_flush();
#endif

                    yassert(next_will_exist_index > i);

#if DEBUG
                    log_debug3("update: %{dnsname}: chain %i state (%02x) publish chain node", diff->origin, chain_index, state);
#endif
                    // publish that interval

                    dnssec_chain_store_diff_publish_chain_node(dc, diff, keys, chain, node, next_will_exist_node, add);

                    break;
                }
                default:
                {
                    break;
                }
            }
        } // for all items in [begin;end[
    } // for all chains

    ptr_vector_finalise(&nodes);
}

/**
 * Releases the memory used by a chain
 */

void dnssec_chain_finalize(dnssec_chain *dc)
{
    for(int_fast32_t chain_index = 0; chain_index < dc->chains_count; ++chain_index)
    {
        ptr_treemap_callback_and_finalise(&dc->chain_diff[chain_index], dc->chain->ptr_treemap_node_delete_callback);
    }
}

static int zone_diff_label_rr_compare(const void *node_a, const void *node_b)
{
    const zone_diff_label_rr *a = (const zone_diff_label_rr *)node_a;
    const zone_diff_label_rr *b = (const zone_diff_label_rr *)node_b;

    int                       d;

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
                    uint16_t len = MIN(a->rdata_size, b->rdata_size);
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

zone_diff_label_rr *zone_diff_label_rr_new(const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, void *rdata, uint16_t rdata_size, bool copy)
{
    zone_diff_label_rr *rr;
    ZALLOC_OBJECT_OR_DIE(rr, zone_diff_label_rr, ZDFFLABL_TAG);
    rr->fqdn = dnsname_zdup(fqdn);
    rr->org_ttl = ttl;
    rr->ttl = ttl;
    rr->rtype = rtype;
    rr->rclass = rclass;
    rr->rdata_size = rdata_size;
    if(copy)
    {
        ZALLOC_ARRAY_OR_DIE(uint8_t *, rr->rdata, rdata_size, ZDFFLBRR_TAG);
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

void zone_diff_label_rr_init_tmp(zone_diff_label_rr *rr, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, void *rdata, uint16_t rdata_size)
{
    rr->fqdn = (uint8_t *)fqdn;
    rr->org_ttl = ttl;
    rr->ttl = ttl;
    rr->rtype = rtype;
    rr->rclass = rclass;
    rr->rdata_size = rdata_size;
    rr->rdata = rdata;
    rr->state = 0;
}

zone_diff_label_rr *zone_diff_label_rr_new_nordata(const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, uint16_t rdata_size)
{
    zone_diff_label_rr *rr;
    ZALLOC_OBJECT_OR_DIE(rr, zone_diff_label_rr, ZDFFLABL_TAG);
    rr->fqdn = dnsname_zdup(fqdn);
    rr->org_ttl = ttl;
    rr->ttl = ttl;
    rr->rtype = rtype;
    rr->rclass = rclass;
    rr->rdata_size = rdata_size;
    ZALLOC_ARRAY_OR_DIE(uint8_t *, rr->rdata, rdata_size, ZDFFLBRR_TAG);
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

static void zone_diff_label_rr_vector_clear(ptr_vector_t *records)
{
    for(int_fast32_t i = 0; i <= ptr_vector_last_index(records); ++i)
    {
        zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(records, i);
        if((rr->state & ZONE_DIFF_RR_VOLATILE) != 0)
        {
            zone_diff_label_rr_delete(rr);
        }
    }
    ptr_vector_clear(records);
}

zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_set_new(uint16_t rtype)
{
    zone_diff_fqdn_rr_set *rr_set;
    ZALLOC_OBJECT_OR_DIE(rr_set, zone_diff_fqdn_rr_set, ZDFFRRST_TAG);
    ptr_treemap_init(&rr_set->rr);
    rr_set->rr.compare = zone_diff_label_rr_compare;
    rr_set->key_mask = 0;
    rr_set->org_ttl = -1;
    rr_set->new_ttl = -1;
    rr_set->rtype = rtype;
    rr_set->rclass = CLASS_IN;
    return rr_set;
}

static void zone_diff_fqdn_rr_set_delete_cb(ptr_treemap_node_t *node)
{
    zone_diff_label_rr *rr = (zone_diff_label_rr *)node->value;
#if DEBUG
    log_debug7("update: %{dnsname}: deleting %{dnstype} structure", rr->fqdn, &rr->rtype);
#endif
    zone_diff_label_rr_delete(rr);
}

static void zone_diff_fqdn_rr_set_delete(zone_diff_fqdn_rr_set *rr_set)
{
    if(rr_set != NULL)
    {
        ptr_treemap_callback_and_finalise(&rr_set->rr, zone_diff_fqdn_rr_set_delete_cb);
        ZFREE_OBJECT(rr_set);
    }
}

void zone_diff_fqdn_rr_set_rr_add_replace(zone_diff_fqdn_rr_set *rr_set, zone_diff_label_rr *rr)
{
    ptr_treemap_node_t *node = ptr_treemap_insert(&rr_set->rr, rr);

    if(node->value == NULL)
    {
        node->value = rr;
    }
    else
    {
        zone_diff_label_rr_delete((zone_diff_label_rr *)node->value);
        node->key = rr;
        node->value = rr;
    }
}

zone_diff_label_rr *zone_diff_fqdn_rr_set_rr_add_get(zone_diff_fqdn_rr_set *rr_set, zone_diff_label_rr *rr)
{
    ptr_treemap_node_t *node = ptr_treemap_insert(&rr_set->rr, rr);

    if(node->value == NULL)
    {
        node->value = rr;
    }
    else
    {
        zone_diff_label_rr *old_rr = (zone_diff_label_rr *)node->value;
        if(old_rr->ttl != rr->ttl)
        {
            old_rr->ttl = rr->ttl;
            old_rr->state |= ZONE_DIFF_RR_TTL_UPDATED;
            rr_set->new_ttl = rr->ttl;
        }

        zone_diff_label_rr_delete(rr);
        rr = (zone_diff_label_rr *)node->value;
    }
    return rr;
}

static zone_diff_label_rr *zone_diff_fqdn_rr_set_get_existing_rr(zone_diff_fqdn_rr_set *rr_set, const zone_diff_label_rr *rr)
{
    ptr_treemap_node_t *node = ptr_treemap_find(&rr_set->rr, rr);

    if(node != NULL)
    {
        return (zone_diff_label_rr *)node->value;
    }

    return NULL;
}

//

static zone_diff_fqdn *zone_diff_fqdn_new(const uint8_t *fqdn)
{
    zone_diff_fqdn *diff_fqdn;
    ZALLOC_OBJECT_OR_DIE(diff_fqdn, zone_diff_fqdn, ZDFFFQDN_TAG);
    memset(diff_fqdn, 0, sizeof(zone_diff_fqdn));
    u32_treemap_init(&diff_fqdn->rrset);
    diff_fqdn->fqdn = dnsname_zdup(fqdn);
    // diff_fqdn->type_map_changed = false;
    return diff_fqdn;
}

static void zone_diff_fqdn_delete_cb(u32_treemap_node_t *node)
{
    zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)node->value;
#if DEBUG
    if(rrset == NULL)
    {
        uint16_t rtype = (uint16_t)node->key;
        log_debug1("zone_diff_fqdn_delete_cb empty set for type %{dnstype}", &rtype);
    }
#endif
    zone_diff_fqdn_rr_set_delete(rrset);
}

static void zone_diff_fqdn_delete(zone_diff_fqdn *diff_fqdn)
{
    u32_treemap_callback_and_finalise(&diff_fqdn->rrset, zone_diff_fqdn_delete_cb);

#if DEBUG
    log_debug1("update: %{dnsname}: deleting diff fqdn", diff_fqdn->fqdn);
#endif
    dnsname_zfree(diff_fqdn->fqdn);
    ZFREE_OBJECT(diff_fqdn);
}

zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_set_add(zone_diff_fqdn *diff_fqdn, uint16_t rtype)
{
    u32_treemap_node_t *node = u32_treemap_insert(&diff_fqdn->rrset, rtype);
    if(node->value == NULL)
    {
        node->value = zone_diff_fqdn_rr_set_new(rtype);
    }
    return (zone_diff_fqdn_rr_set *)node->value;
}

/**
 * Returns the local copy of the specified RRSET
 * Creates an emtpy set if it does not exist.
 *
 * @param diff_fqdn
 * @param rtype
 * @return
 */

zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_set_get(const zone_diff_fqdn *diff_fqdn, uint16_t rtype)
{
    u32_treemap_node_t *node = u32_treemap_find(&diff_fqdn->rrset, rtype);
    if(node != NULL)
    {
        return (zone_diff_fqdn_rr_set *)node->value;
    }
    return NULL;
}

/**
 * Returns the local copy of the specified RRSET
 *
 * @param diff_fqdn
 * @param rtype
 * @return
 */

const zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_get_const(const zone_diff_fqdn *diff_fqdn, uint16_t rtype)
{
    u32_treemap_node_t *node = u32_treemap_find(&diff_fqdn->rrset, rtype);

    if(node != NULL)
    {
        return (zone_diff_fqdn_rr_set *)node->value;
    }

    return NULL;
}

int32_t zone_diff_fqdn_rr_set_get_ttl(zone_diff_fqdn_rr_set *rrset)
{
    // @note 20170228 edf -- issue detection
    // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
    // the intent of putting records in it.
    // Find it and call zone_diff_will_have_rrset_type instead.
    yassert(rrset != NULL);

    ptr_treemap_iterator_t rr_iter;
    ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
    while(ptr_treemap_iterator_hasnext(&rr_iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

        if((rr->state & ZONE_DIFF_RR_REMOVE) == 0)
        {
            // this record was present or is being added
            return rr->ttl;
        }
    }

    return -1;
}

int32_t zone_diff_fqdn_rr_get_ttl(const zone_diff_fqdn *diff_fqdn, uint16_t rtype)
{
    int32_t             ttl = -1;
    u32_treemap_node_t *rrset_node = u32_treemap_find(&diff_fqdn->rrset, rtype);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)rrset_node->value;
        ttl = zone_diff_fqdn_rr_set_get_ttl(rrset);
    }
    return ttl; // TTL is signed, 32 bits and >= 0
}

/**
 * Deletes an RRSET if it's empty.
 *
 * @param diff_fqdn
 * @param rtype
 */

void zone_diff_fqdn_rr_clear(zone_diff_fqdn *diff_fqdn, uint16_t rtype)
{
    u32_treemap_node_t *node = u32_treemap_insert(&diff_fqdn->rrset, rtype);
    if(node != NULL)
    {
        if(node->value == NULL)
        {
            u32_treemap_delete(&diff_fqdn->rrset, rtype);
        }
    }
}

/**
 * Returns true iff an rrset as been added or removed from the label.
 * Stressing out this concerns RRSET as a whole.
 *
 * @param diff_fqdn
 * @return
 */

bool zone_diff_fqdn_type_map_changed(const zone_diff_fqdn *diff_fqdn)
{
    if(diff_fqdn->rrsig_kept == 0)
    {
        if(diff_fqdn->rrsig_added || diff_fqdn->rrsig_removed || diff_fqdn->rrsig_expect_new_rrsig)
        {
            return true; // RRSIG type bitmap has changed;
        }
    }

    u32_treemap_iterator_t iter;
    ptr_treemap_iterator_t rr_iter;

    u32_treemap_iterator_init(&diff_fqdn->rrset, &iter);
    while(u32_treemap_iterator_hasnext(&iter))
    {
        u32_treemap_node_t    *node = u32_treemap_iterator_next_node(&iter);
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)node->value;
        if(rrset != NULL)
        {
            ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
            uint8_t rr_state = 0;
            while(ptr_treemap_iterator_hasnext(&rr_iter))
            {
                ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->key;

                if(rr->state == 0)
                {
                    // previously existing record : no change on this set
                    rr_state = 0;
                    break;
                }

                rr_state |= rr->state & (ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_ADD);
            }

            if((rr_state != 0) && ((rr_state & (ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_ADD)) != (ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_ADD)))
            {
                // this set is completely added or completely removed

                if(rrset->rtype != TYPE_RRSIG) // exceptional test
                {
                    return true;
                }
                else
                {
                    if(!diff_fqdn->is_apex)
                    {
                        if(diff_fqdn->has_active_zsk)
                        {
                            rr_state |= ZONE_DIFF_RR_ADD;

                            if((rr_state != 0) && ((rr_state & (ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_ADD)) != (ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_ADD)))
                            {
                                return true;
                            }
                        }
                    }
                    else
                    {
                        if(diff_fqdn->has_active_zsk || diff_fqdn->has_active_ksk)
                        {
                            rr_state |= ZONE_DIFF_RR_ADD;

                            if((rr_state != 0) && ((rr_state & (ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_ADD)) != (ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_ADD)))
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    return false;
}

/**
 * Initialises a zone diff
 *
 * @param diff
 * @param origin
 * @param nttl
 */

void zone_diff_init(zone_diff *diff, zdb_zone_t *zone, bool rrsig_update_allowed)
{
    log_debug1("update: %{dnsname}: initialising diff @%p", zone->origin, diff);

    ptr_treemap_init(&diff->fqdn);
    ptr_treemap_init(&diff->root.sub);
    diff->root.sub.compare = ptr_treemap_dnslabel_node_compare;
    diff->fqdn.compare = ptr_treemap_fqdn_node_compare;
    diff->origin = zone->origin;

    diff->rrsig_validity_interval = MAX(zone->sig_validity_interval_seconds, 0);
    diff->rrsig_validity_regeneration = MAX(zone->sig_validity_regeneration_seconds, 0);
    diff->rrsig_validity_jitter = MAX(zone->sig_validity_jitter_seconds, 0);
#if NSEC3_MIN_TTL_ERRATA
    diff->nttl = zone->min_ttl_soa;
#else
    diff->nttl = zone->min_ttl;
#endif
    diff->rrsig_update_allowed = rrsig_update_allowed;
    diff->has_active_zsk = false;
    diff->has_active_ksk = false;

    uint8_t maintain_mode = zone_get_maintain_mode(zone);

    switch(maintain_mode)
    {
        case ZDB_ZONE_MAINTAIN_NSEC3:
        case ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:
        {
            diff->maintain_nsec = false;
            diff->maintain_nsec3 = true;
            break;
        }
        case ZDB_ZONE_MAINTAIN_NSEC:
        {
            diff->maintain_nsec = true;
            diff->maintain_nsec3 = false;
            break;
        }
        default:
        {
            diff->maintain_nsec = false;
            diff->maintain_nsec3 = false;
            break;
        }
    }

    // NOTE: set the apex at the end of the function

    diff->apex = zone_diff_fqdn_add(diff, zone->origin, zone->apex);
}

static zone_diff_label_tree *zone_diff_label_tree_add_fqdn(zone_diff *diff, const uint8_t *fqdn)
{
#if DEBUG
    log_debug2("zone-diff: %{dnsname}: label tree add %{dnsname}", diff->origin, fqdn);
#endif

    if(fqdn[0] != 0)
    {
        zone_diff_label_tree *label_node;
        ptr_treemap_node_t   *label_tree_node;
        const uint8_t        *parent_fqdn = fqdn + fqdn[0] + 1;
        zone_diff_label_tree *parent = zone_diff_label_tree_add_fqdn(diff, parent_fqdn);

        label_tree_node = ptr_treemap_insert(&parent->sub, (uint8_t *)fqdn);

        if(label_tree_node->value != NULL)
        {
            label_node = (zone_diff_label_tree *)label_tree_node->value;
        }
        else
        {
            ZALLOC_OBJECT_OR_DIE(label_node, zone_diff_label_tree, ZDLABELT_TAG);
            label_node->label = fqdn;
            label_node->diff_fqdn = zone_diff_fqdn_get(diff, fqdn);
            ptr_treemap_init(&label_node->sub);
            label_node->sub.compare = ptr_treemap_dnslabel_node_compare;
            label_tree_node->value = label_node;
        }

        return label_node;
    }
    else
    {
        return &diff->root;
    }
}

static void zone_diff_label_tree_destroy_cb(ptr_treemap_node_t *node)
{
    zone_diff_label_tree *dlt = (zone_diff_label_tree *)node->value;
    if(dlt != NULL)
    {
        if(!ptr_treemap_isempty(&dlt->sub))
        {
            ptr_treemap_callback_and_finalise(&dlt->sub, zone_diff_label_tree_destroy_cb);
        }
        ZFREE_OBJECT(dlt);
    }
}

static void                  zone_diff_label_tree_destroy(zone_diff *diff) { ptr_treemap_callback_and_finalise(&diff->root.sub, zone_diff_label_tree_destroy_cb); }

static zone_diff_label_tree *zone_diff_fqdn_label_find(zone_diff_label_tree *parent, const uint8_t *fqdn)
{
    if(fqdn[0] != 0)
    {
        parent = zone_diff_fqdn_label_find(parent, fqdn + fqdn[0] + 1);
        if(parent != NULL)
        {
            ptr_treemap_node_t *node = ptr_treemap_find(&parent->sub, fqdn);
            parent = (zone_diff_label_tree *)node->value;
        }
    }
    return parent;
}

bool zone_diff_fqdn_has_children(zone_diff *diff, const uint8_t *fqdn)
{
    zone_diff_label_tree *parent = &diff->root;
    parent = zone_diff_fqdn_label_find(parent, fqdn);
    return parent != NULL;
}

// #define ZONE_DIFF_FQDN_LABEL_STATE_RECORDS_EXISTED 1
// #define ZONE_DIFF_FQDN_LABEL_STATE_RECORDS_ADDED   2
// #define ZONE_DIFF_FQDN_LABEL_STATE_RECORDS_EXISTS  3
#define ZONE_DIFF_FQDN_LABEL_STATE_NONEMPTY 2
#define ZONE_DIFF_FQDN_LABEL_STATE_CHILDREN 1

static uint8_t zone_diff_fqdn_children_state_find(zone_diff_label_tree *parent)
{
    uint8_t ret;

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

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&parent->sub, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t   *node = ptr_treemap_iterator_next_node(&iter);

        zone_diff_label_tree *fqdn_node = (zone_diff_label_tree *)node->value;

        if(fqdn_node->diff_fqdn != NULL)
        {
            if(!fqdn_node->diff_fqdn->children_flags_set)
            {
                if(!ptr_treemap_isempty(&fqdn_node->sub))
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
            if(!ptr_treemap_isempty(&fqdn_node->sub))
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

uint8_t zone_diff_fqdn_children_state(zone_diff *diff, const uint8_t *fqdn)
{
    zone_diff_label_tree *fqdn_node = zone_diff_fqdn_label_find(&diff->root, fqdn);

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

static void zone_diff_finalize_cb(ptr_treemap_node_t *node)
{
    zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn *)node->value;
    zone_diff_fqdn_delete(diff_fqdn);
}

void zone_diff_finalize(zone_diff *diff)
{
    log_debug1("update: %{dnsname}: deleting diff @%p", diff->origin, diff);
    zone_diff_label_tree_destroy(diff);
    ptr_treemap_callback_and_finalise(&diff->fqdn, zone_diff_finalize_cb);
}

zone_diff_fqdn *zone_diff_fqdn_add_empty(zone_diff *diff, const uint8_t *fqdn)
{
    ptr_treemap_node_t *node = ptr_treemap_insert(&diff->fqdn, (uint8_t *)fqdn);

    if(node->value == NULL)
    {
#if DEBUG
        log_debug2("update: %{dnsname} ...", fqdn);
#endif

        zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_new(fqdn);
        node->key = diff_fqdn->fqdn; // to guarantee the const
        node->value = diff_fqdn;
    }

    return (zone_diff_fqdn *)node->value;
}

/**
 * label will be replaced ...
 *
 * @param diff
 * @param fqdn
 * @param label
 * @return
 */

zone_diff_fqdn *zone_diff_fqdn_add(zone_diff *diff, const uint8_t *fqdn, zdb_rr_label_t *label)
{
    ptr_treemap_node_t *node = ptr_treemap_insert(&diff->fqdn, (uint8_t *)fqdn);

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
            diff_fqdn->was_non_empty = !zdb_resource_record_sets_set_isempty(&label->resource_record_set);
            diff_fqdn->had_children = dictionary_notempty(&label->sub);
            // diff_fqdn->will_be_non_empty = diff_fqdn->was_non_empty;
            diff_fqdn->will_have_children = diff_fqdn->is_apex;
            diff_fqdn->will_have_ds = diff_fqdn->had_ds;
            diff_fqdn->children_added = 0;

            diff_fqdn->has_active_zsk = diff->has_active_zsk;
            diff_fqdn->has_active_ksk = diff->has_active_ksk;

            diff_fqdn->is_in_database = 1;

            zdb_resource_record_sets_set_iterator_t iter;
            zdb_resource_record_sets_set_iterator_init(&label->resource_record_set, &iter);
            while(zdb_resource_record_sets_set_iterator_hasnext(&iter))
            {
                zdb_resource_record_sets_node_t *rr_node = zdb_resource_record_sets_set_iterator_next_node(&iter);
                uint16_t                         type = zdb_resource_record_set_type(&rr_node->value);

#if DEBUG
                log_debug2("update: %{dnsname} (%p) copying %{dnstype} RRSET", fqdn, label, &type);
#endif

                zone_diff_fqdn_rr_set     *rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, type);

                zdb_resource_record_set_t *rrset = (zdb_resource_record_set_t *)&rr_node->value;

                if(type != TYPE_RRSIG)
                {
                    int32_t                          ttl = zdb_resource_record_set_ttl(rrset);

                    zdb_resource_record_set_iterator iter;
                    zdb_resource_record_set_iterator_init(rrset, &iter);
                    if(zdb_resource_record_set_iterator_has_next(&iter))
                    {
                        zdb_resource_record_data_t *record = zdb_resource_record_set_iterator_next(&iter);

                        if(rr_set->org_ttl == -1)
                        {
                            rr_set->org_ttl = ttl;
                        }

                        rr_set->new_ttl = ttl;

                        for(;;)
                        {
                            zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, type, CLASS_IN, ttl, zdb_resource_record_data_rdata(record), zdb_resource_record_data_rdata_size(record), false);
                            rr->org_ttl = ttl;
                            rr->state |= ZONE_DIFF_RR_IN_ZONE;
                            /** rr = */ zone_diff_fqdn_rr_set_rr_add_replace(rr_set, rr); /// NOTE: there should not be any collision here

                            if(!zdb_resource_record_set_iterator_has_next(&iter))
                            {
                                break;
                            }

                            record = zdb_resource_record_set_iterator_next(&iter);
                        }
                    }
                }
                else
                {
                    zdb_resource_record_set_iterator iter;
                    zdb_resource_record_set_iterator_init(rrset, &iter);
                    if(zdb_resource_record_set_iterator_has_next(&iter))
                    {
                        zdb_resource_record_data_t *record = zdb_resource_record_set_iterator_next(&iter);

                        int32_t                     ttl = zdb_resource_record_set_ttl(rrset);

                        if(rr_set->org_ttl == -1)
                        {
                            rr_set->org_ttl = ttl;
                        }

                        rr_set->new_ttl = ttl;

                        for(;;)
                        {
                            ttl = rrsig_get_original_ttl_from_rdata(zdb_resource_record_data_rdata(record), zdb_resource_record_data_rdata_size(record));

                            uint16_t                         covered_type = rrsig_get_type_covered_from_rdata(zdb_resource_record_data_rdata(record), zdb_resource_record_data_rdata_size(record));
                            zdb_resource_record_sets_node_t *covered_rr_node = zdb_resource_record_sets_set_find(&label->resource_record_set, covered_type);
                            if(covered_rr_node != NULL)
                            {
                                zdb_resource_record_set_t *covered_rrset = (zdb_resource_record_set_t *)&covered_rr_node->value;
                                if(covered_rrset != NULL)
                                {
                                    ttl = zdb_resource_record_set_ttl(covered_rrset);
                                }
                            }

                            zone_diff_label_rr *rr = zone_diff_label_rr_new(fqdn, type, CLASS_IN, ttl, zdb_resource_record_data_rdata(record), zdb_resource_record_data_rdata_size(record), false);
                            rr->org_ttl = ttl;
                            rr->state |= ZONE_DIFF_RR_IN_ZONE;
                            /** rr = */ zone_diff_fqdn_rr_set_rr_add_replace(rr_set, rr); /// NOTE: there should not be any collision here

                            if(!zdb_resource_record_set_iterator_has_next(&iter))
                            {
                                break;
                            }

                            record = zdb_resource_record_set_iterator_next(&iter);
                        }
                    }
                }
            }
        }
        else
        {
#if DEBUG
            log_debug2("update: %{dnsname} (%p) label is not in the zone", fqdn, label);
#endif
            /*
            diff_fqdn->is_apex = false;
            diff_fqdn->at_delegation = false;
            diff_fqdn->under_delegation = false;
            diff_fqdn->will_have_ds = false;
            diff_fqdn->was_at_delegation = false;
            diff_fqdn->was_under_delegation = false;
            diff_fqdn->had_ds = false;
            diff_fqdn->was_non_empty = false;
            */
        }
    }
#if DEBUG
    else
    {
        log_debug2("update: %{dnsname} (%p) already known (add)", fqdn, label);
    }
#endif

    return (zone_diff_fqdn *)node->value;
}

#if ZDB_HAS_NSEC3_SUPPORT
zone_diff_fqdn *zone_diff_add_nsec3(zone_diff *diff, const nsec3_zone_t *n3, const nsec3_zone_item_t *item, int32_t ttl, zone_diff_fqdn_rr_set **out_nsec3_rrset)
{
    uint8_t digest_len = NSEC3_NODE_DIGEST_SIZE(item);
    uint8_t fqdn[DOMAIN_LENGTH_MAX];

    fqdn[0] = base32hex_encode_lc(NSEC3_NODE_DIGEST_PTR(item), digest_len, (char *)&fqdn[1]);
    dnsname_copy(&fqdn[fqdn[0] + 1], diff->origin);

    ptr_treemap_node_t *node = ptr_treemap_insert(&diff->fqdn, fqdn);

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
        // diff_fqdn->is_apex = 0;
        // diff_fqdn->at_delegation = 0;
        // diff_fqdn->under_delegation = 0;
        // diff_fqdn->will_have_ds = 0;
        // diff_fqdn->was_at_delegation = 0;
        // diff_fqdn->was_under_delegation = 0;
        // diff_fqdn->had_ds = 0;
        diff_fqdn->was_non_empty = 1;
        // diff_fqdn->had_children = 0;
        // diff_fqdn->will_have_children = 0;
        // diff_fqdn->children_added = 0;
        diff_fqdn->is_nsec3 = 1;

        diff_fqdn->has_active_zsk = diff->has_active_zsk;
        diff_fqdn->has_active_ksk = diff->has_active_ksk;

#if DEBUG
        log_debug2("update: %{dnsname} (%p) copying NSEC3 record", fqdn, item);
#endif
        uint32_t param_rdata_size = NSEC3PARAM_RDATA_SIZE_FROM_CHAIN(n3);
        uint8_t  hash_len = NSEC3_NODE_DIGEST_SIZE(item);
        uint32_t type_bit_maps_size = item->type_bit_maps_size;

        /* Whatever the editor says: rdata_size is used. */
        uint32_t               rdata_size = param_rdata_size + 1 + hash_len + type_bit_maps_size;

        zone_diff_fqdn_rr_set *nsec3_rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, TYPE_NSEC3);
        zone_diff_label_rr    *rr = zone_diff_label_rr_new_nordata(fqdn, TYPE_NSEC3, CLASS_IN, ttl, rdata_size);
        nsec3_zone_item_to_rdata(n3, item, rr->rdata, rdata_size);
        rr->org_ttl = ttl;
        rr->state |= ZONE_DIFF_RR_IN_ZONE;
        zone_diff_fqdn_rr_set_rr_add_replace(nsec3_rr_set, rr); /// NOTE: there should not be any collision here
        if(out_nsec3_rrset != NULL)
        {
            *out_nsec3_rrset = nsec3_rr_set;
        }

        zdb_resource_record_set_t *nsec3_rrsig_rr_sll = item->rrsig_rrset;

        if(nsec3_rrsig_rr_sll != NULL)
        {
            zdb_resource_record_set_iterator iter;
            zdb_resource_record_set_iterator_init(nsec3_rrsig_rr_sll, &iter);
            if(zdb_resource_record_set_iterator_has_next(&iter))
            {
                zdb_resource_record_data_t *nsec3_rrsig_record = zdb_resource_record_set_iterator_next(&iter);

                zone_diff_fqdn_rr_set      *nsec3_rrsig_rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, TYPE_RRSIG);

                nsec3_rrsig_rr_set->org_ttl = ttl;
                nsec3_rrsig_rr_set->new_ttl = ttl;

                for(;;)
                {
                    zone_diff_label_rr *new_rr = zone_diff_label_rr_new(fqdn, TYPE_RRSIG, CLASS_IN, ttl, zdb_resource_record_data_rdata(nsec3_rrsig_record), zdb_resource_record_data_rdata_size(nsec3_rrsig_record), false);
                    new_rr->org_ttl = ttl;
                    new_rr->state |= ZONE_DIFF_RR_IN_ZONE;
                    /** rr = */ zone_diff_fqdn_rr_set_rr_add_replace(nsec3_rrsig_rr_set, new_rr); /// NOTE: there should not be any collision here

                    if(!zdb_resource_record_set_iterator_has_next(&iter))
                    {
                        break;
                    }

                    nsec3_rrsig_record = zdb_resource_record_set_iterator_next(&iter);
                }
            }
        }
    }
#if DEBUG
    else
    {
        log_debug2("update: %{dnsname} (%p) already known (add nsec3)", fqdn, item);
    }
#endif

    return (zone_diff_fqdn *)node->value;
}

zone_diff_fqdn *zone_diff_add_nsec3_ex(zone_diff *diff, const ptr_vector_t *zsk_keys, const nsec3_zone_t *n3, const nsec3_zone_item_t *item, int32_t ttl, zone_diff_fqdn_rr_set **out_nsec3_rrset, int32_t now, int32_t regeneration)
{
    uint8_t digest_len = NSEC3_NODE_DIGEST_SIZE(item);
    uint8_t fqdn[DOMAIN_LENGTH_MAX];

    fqdn[0] = base32hex_encode_lc(NSEC3_NODE_DIGEST_PTR(item), digest_len, (char *)&fqdn[1]);
    dnsname_copy(&fqdn[fqdn[0] + 1], diff->origin);

    ptr_treemap_node_t *node = ptr_treemap_insert(&diff->fqdn, fqdn);

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
        // diff_fqdn->is_apex = 0;
        // diff_fqdn->at_delegation = 0;
        // diff_fqdn->under_delegation = 0;
        // diff_fqdn->will_have_ds = 0;
        // diff_fqdn->was_at_delegation = 0;
        // diff_fqdn->was_under_delegation = 0;
        // diff_fqdn->had_ds = 0;
        diff_fqdn->was_non_empty = 1;
        // diff_fqdn->had_children = 0;
        // diff_fqdn->will_have_children = 0;
        // diff_fqdn->children_added = 0;
        diff_fqdn->is_nsec3 = 1;

        diff_fqdn->has_active_zsk = diff->has_active_zsk;
        diff_fqdn->has_active_ksk = diff->has_active_ksk;

#if DEBUG
        log_debug2("update: %{dnsname} (%p) copying NSEC3 record", fqdn, item);
#endif
        uint32_t param_rdata_size = NSEC3PARAM_RDATA_SIZE_FROM_CHAIN(n3);
        uint8_t  hash_len = NSEC3_NODE_DIGEST_SIZE(item);
        uint32_t type_bit_maps_size = item->type_bit_maps_size;

        /* Whatever the editor says: rdata_size is used. */
        uint32_t               rdata_size = param_rdata_size + 1 + hash_len + type_bit_maps_size;

        zone_diff_fqdn_rr_set *nsec3_rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, TYPE_NSEC3);
        zone_diff_label_rr    *rr = zone_diff_label_rr_new_nordata(fqdn, TYPE_NSEC3, CLASS_IN, ttl, rdata_size);
        nsec3_zone_item_to_rdata(n3, item, rr->rdata, rdata_size);
        rr->org_ttl = ttl;
        rr->state |= ZONE_DIFF_RR_IN_ZONE;
        zone_diff_fqdn_rr_set_rr_add_replace(nsec3_rr_set, rr); /// NOTE: there should not be any collision here
        if(out_nsec3_rrset != NULL)
        {
            *out_nsec3_rrset = nsec3_rr_set;
        }

        zdb_resource_record_set_t *nsec3_rrsig_rrset = item->rrsig_rrset;

        if(nsec3_rrsig_rrset != NULL)
        {
            zone_diff_fqdn_rr_set *nsec3_rrsig_rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, TYPE_RRSIG);

            nsec3_rrsig_rr_set->org_ttl = ttl;
            nsec3_rrsig_rr_set->new_ttl = ttl;

            zdb_resource_record_set_iterator iter;
            zdb_resource_record_set_iterator_init(nsec3_rrsig_rrset, &iter);
            while(zdb_resource_record_set_iterator_has_next(&iter))
            {
                zdb_resource_record_data_t *nsec3_rrsig_record = zdb_resource_record_set_iterator_next(&iter);

                zone_diff_label_rr         *new_rr = zone_diff_label_rr_new(fqdn, TYPE_RRSIG, CLASS_IN, ttl, zdb_resource_record_data_rdata(nsec3_rrsig_record), zdb_resource_record_data_rdata_size(nsec3_rrsig_record), false);
                new_rr->org_ttl = ttl;
                new_rr->state |= ZONE_DIFF_RR_IN_ZONE;
                int32_t matching_key_index = -2;
                if(rrsig_should_remove_signature_from_rdata(
                       zdb_resource_record_data_rdata(nsec3_rrsig_record), zdb_resource_record_data_rdata_size(nsec3_rrsig_record), zsk_keys, now, regeneration, &matching_key_index) /* unnecessary: || (matching_key_index == -1)*/)
                {
                    new_rr->state |= ZONE_DIFF_RR_REMOVE;
                }

                /** rr = */ zone_diff_fqdn_rr_set_rr_add_replace(nsec3_rrsig_rr_set, new_rr); /// NOTE: there should not be any collision here
            }
        }
    }
#if DEBUG
    else
    {
        log_debug2("update: %{dnsname} (%p) already known (add nsec3 ex)", fqdn, item);
    }
#endif

    return (zone_diff_fqdn *)node->value;
}

#endif // HAS_NSEC3_SUPPORT

zone_diff_fqdn *zone_diff_add_static_fqdn(zone_diff *diff, const uint8_t *fqdn, zdb_rr_label_t *label)
{
    zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, label);
    diff_fqdn->will_be_non_empty = diff_fqdn->was_non_empty;
    diff_fqdn->will_have_children = diff_fqdn->had_children;
    diff_fqdn->will_have_ds = diff_fqdn->had_ds && diff_fqdn->at_delegation;
    if(diff_fqdn->will_have_ds != diff_fqdn->had_ds)
    {
        // may be looking at a broken zone
        // it it only contains DS records (and RRSIG records) then it should be marked empty

        zdb_resource_record_sets_set_iterator_t iter;
        zdb_resource_record_sets_set_iterator_init(&label->resource_record_set, &iter);
        while(zdb_resource_record_sets_set_iterator_hasnext(&iter))
        {
            zdb_resource_record_sets_node_t *node = zdb_resource_record_sets_set_iterator_next_node(&iter);
            uint16_t                         type = zdb_resource_record_set_type(&node->value);

            if((type != TYPE_RRSIG) && (type != TYPE_DS))
            {
                return diff_fqdn;
            }
        }

        // the label will be emptied by validation later, the NSEC3 chain doesn't know that yet.

        log_warn(
            "update: %{dnsname}: %{dnsname} label only contained DS and RRSIG resource record sets: they will be "
            "removed",
            diff->origin,
            fqdn);

        diff_fqdn->will_be_non_empty = 0;
    }
    return diff_fqdn;
}

void zone_diff_add_fqdn_children(zone_diff *diff, const uint8_t *fqdn, zdb_rr_label_t *label)
{
    dictionary_iterator_t iter;
    uint8_t               sub_fqdn[DOMAIN_LENGTH_MAX];
    dictionary_iterator_init(&label->sub, &iter);

    while(dictionary_iterator_hasnext(&iter))
    {
        zdb_rr_label_t *sub_label = *(zdb_rr_label_t **)dictionary_iterator_next(&iter);
        dnsname_copy(&sub_fqdn[dnslabel_copy(sub_fqdn, sub_label->name)], fqdn);
        zone_diff_fqdn *parent = zone_diff_fqdn_add(diff, sub_fqdn, sub_label);
        parent->children_added = 1;

        if(dictionary_notempty(&sub_label->sub))
        {
            zone_diff_add_fqdn_children(diff, sub_fqdn, sub_label);
        }
    }
}

void zone_diff_add_fqdn_parents_up_to_below_apex(zone_diff *diff, const uint8_t *fqdn, zdb_zone_t *zone)
{
    size_t origin_len = dnsname_len(diff->origin);
    fqdn += fqdn[0] + 1;
    while(dnsname_len(fqdn) > origin_len)
    {
        zdb_rr_label_t *fqdn_label = zdb_rr_label_find_from_name(zone, fqdn);
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

void zone_diff_fqdn_rr_set_set_state(zone_diff_fqdn_rr_set *rrset, uint8_t or_state)
{
    ptr_treemap_iterator_t rr_iter;
    ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
    while(ptr_treemap_iterator_hasnext(&rr_iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
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

bool zone_diff_will_have_rrset_type(const zone_diff_fqdn *diff_fqdn, uint16_t rtype)
{
    u32_treemap_node_t *rrset_node = u32_treemap_find(&diff_fqdn->rrset, rtype);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrset != NULL);

        ptr_treemap_iterator_t rr_iter;
        ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
        while(ptr_treemap_iterator_hasnext(&rr_iter))
        {
            ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

            if((rr->state & ZONE_DIFF_RR_REMOVE) == 0)
            {
                // this record was present or is being added
                return true;
            }
        }
    }
    return false;
}

bool zone_diff_remove_rrsig_covering_type(zone_diff_fqdn *diff_fqdn, uint16_t rtype)
{
    u32_treemap_node_t *rrsig_rrset_node = u32_treemap_find(&diff_fqdn->rrset, TYPE_RRSIG);
    if(rrsig_rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrsig_rrset = (zone_diff_fqdn_rr_set *)rrsig_rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrsig_rrset != NULL);

        ptr_vector_t           to_remove = PTR_VECTOR_EMPTY;

        ptr_treemap_iterator_t rr_iter;
        ptr_treemap_iterator_init(&rrsig_rrset->rr, &rr_iter);
        while(ptr_treemap_iterator_hasnext(&rr_iter))
        {
            ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

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

                    log_warn("update: %{dnsname} RRSIG covering %{dnstype} record has state %03x, which is not expected", rr->fqdn, &rtype, rr->state);
                }
            }
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&to_remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&to_remove, i);
            ptr_treemap_delete(&rrsig_rrset->rr, rr);
            zone_diff_label_rr_delete(rr);
        }

        if(ptr_treemap_isempty(&rrsig_rrset->rr))
        {
            u32_treemap_delete(&diff_fqdn->rrset, TYPE_RRSIG);
        }

        ptr_vector_finalise(&to_remove);
    }
    return false;
}

/**
 *
 * Removes existing records as well as cancels additions of new ones.
 *
 * This is called by zone_diff_validate.
 * This means there is no rrset_to_sign collection yet.
 *
 */

bool zone_diff_remove_rrset_type(zone_diff_fqdn *diff_fqdn, uint16_t rtype)
{
    u32_treemap_node_t *rrset_node = u32_treemap_find(&diff_fqdn->rrset, rtype);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrset != NULL);

        ptr_vector_t           to_remove = PTR_VECTOR_EMPTY;

        ptr_treemap_iterator_t rr_iter;
        ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
        while(ptr_treemap_iterator_hasnext(&rr_iter))
        {
            ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

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

                log_warn("update: %{dnsname} %{dnstype} record has state %03x, which is not expected", rr->fqdn, &rtype, rr->state);
            }
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&to_remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&to_remove, i);
            ptr_treemap_delete(&rrset->rr, rr);
            zone_diff_label_rr_delete(rr);
        }

        if(ptr_vector_last_index(&to_remove) >= 0)
        {
            if(ptr_treemap_isempty(&rrset->rr))
            {
                u32_treemap_delete(&diff_fqdn->rrset, rtype);
            }

            zone_diff_remove_rrsig_covering_type(diff_fqdn, rtype);
        }

        ptr_vector_finalise(&to_remove);
    }
    return false;
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

bool zone_diff_will_have_dnskey_with_algorithm_flags_tag(const zone_diff_fqdn *diff_fqdn, uint8_t algorithm, uint16_t flags, uint16_t tag)
{
    u32_treemap_node_t *rrset_node = u32_treemap_find(&diff_fqdn->rrset, TYPE_DNSKEY);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrset != NULL);

        ptr_treemap_iterator_t rr_iter;
        ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
        while(ptr_treemap_iterator_hasnext(&rr_iter))
        {
            ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
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
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    return false;
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

bool zone_diff_will_have_dnskey_with_algorithm_tag(const zone_diff_fqdn *diff_fqdn, uint8_t algorithm, uint16_t tag)
{
    u32_treemap_node_t *rrset_node = u32_treemap_find(&diff_fqdn->rrset, TYPE_DNSKEY);
    if(rrset_node != NULL)
    {
        zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)rrset_node->value;

        // @note 20170228 edf -- issue detection
        // If this aborts, it's likely somebody called zone_diff_fqdn_rr_get without
        // the intent of putting records in it.
        // Find it and call zone_diff_will_have_rrset_type instead.
        yassert(rrset != NULL);

        ptr_treemap_iterator_t rr_iter;
        ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
        while(ptr_treemap_iterator_hasnext(&rr_iter))
        {
            ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
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
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

/**
 * Releases keys that will not be in the apex after the diff is applied.
 *
 * @param diff
 * @param keys
 */

void zone_diff_filter_out_keys(const zone_diff *diff, ptr_vector_t *keys)
{
    const zone_diff_fqdn *diff_fqdn = zone_diff_fqdn_get_const(diff, diff->origin);
    if(diff_fqdn != NULL)
    {
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(keys); ++i)
        {
            dnskey_t *key = (dnskey_t *)ptr_vector_get(keys, i);

#if !DEBUG
            if(!dnskey_is_private(key) || !zone_diff_will_have_dnskey_with_algorithm_flags_tag(diff_fqdn, dnskey_get_algorithm(key), dnskey_get_flags(key), dnskey_get_tag(key)))
            {
                ptr_vector_end_swap(keys, i);
                ptr_vector_pop(keys);
                dnskey_release(key);
            }
#else
            /*if(!dnskey_is_private(key))
            {
                log_debug3("zone_diff_filter_out_keys: 'K%{dnsname}+%03d+%05hd' is not private", diff->origin,
            dnskey_get_algorithm(key), dnskey_get_tag_const(key));

                ptr_vector_end_swap(keys, i);
                ptr_vector_pop(keys);
                dnskey_release(key);
            }
            else*/
            if(!zone_diff_will_have_dnskey_with_algorithm_flags_tag(diff_fqdn, dnskey_get_algorithm(key), dnskey_get_flags(key), dnskey_get_tag(key)))
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

const zone_diff_fqdn *zone_diff_fqdn_get_const(const zone_diff *diff, const uint8_t *fqdn)
{
    zone_diff_fqdn     *ret = NULL;
    ptr_treemap_node_t *node = ptr_treemap_find(&diff->fqdn, (uint8_t *)fqdn);
    if(node != NULL)
    {
        ret = (zone_diff_fqdn *)node->value;
    }
    return ret;
}

zone_diff_fqdn *zone_diff_fqdn_get(const zone_diff *diff, const uint8_t *fqdn)
{
    zone_diff_fqdn     *ret = NULL;
    ptr_treemap_node_t *node = ptr_treemap_find(&diff->fqdn, (uint8_t *)fqdn);
    if(node != NULL)
    {
        ret = (zone_diff_fqdn *)node->value;
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

uint16_t zone_diff_type_bit_map_generate(const zone_diff *diff, const uint8_t *fqdn, type_bit_maps_context_t *bitmap, uint8_t mask, uint8_t masked, const uint8_t *chain_node_fqdn, bool append_existing_signatures)
{
    type_bit_maps_init(bitmap);

    const zone_diff_fqdn *zdf = zone_diff_fqdn_get_const(diff, fqdn);

    if(zdf != NULL)
    {
        if(zdf->at_delegation || zdf->under_delegation)
        {
            ptr_treemap_iterator_t rr_iter;
            u32_treemap_iterator_t iter;
            u32_treemap_iterator_init(&zdf->rrset, &iter);
            while(u32_treemap_iterator_hasnext(&iter))
            {
                u32_treemap_node_t *node = u32_treemap_iterator_next_node(&iter);
                uint16_t            rtype = (uint16_t)node->key;

                if((rtype == TYPE_A) || (rtype == TYPE_AAAA))
                {
                    continue;
                }

                zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)node->value;

                ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
                while(ptr_treemap_iterator_hasnext(&rr_iter))
                {
                    ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
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
            ptr_treemap_iterator_t rr_iter;
            u32_treemap_iterator_t iter;
            u32_treemap_iterator_init(&zdf->rrset, &iter);
            while(u32_treemap_iterator_hasnext(&iter))
            {
                u32_treemap_node_t    *node = u32_treemap_iterator_next_node(&iter);
                uint16_t               rtype = (uint16_t)node->key;

                zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)node->value;

                ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
                while(ptr_treemap_iterator_hasnext(&rr_iter))
                {
                    ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
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

    uint16_t bitmap_size = type_bit_maps_update_size(bitmap);

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

zone_diff_label_rr *zone_diff_record_add(zone_diff *diff, zdb_rr_label_t *rr_label, const uint8_t *fqdn, uint16_t rtype, int32_t rttl, uint16_t rdata_size, void *rdata)
{
    zone_diff_fqdn        *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, rtype);
    zone_diff_label_rr    *rr = zone_diff_label_rr_new(fqdn, rtype, CLASS_IN, rttl, rdata, rdata_size, true);
    rr = zone_diff_fqdn_rr_set_rr_add_get(rr_set, rr);

#if DEBUG
    rdata_desc_t rd = {rtype, rdata_size, rdata};
    log_debug2("update: %{dnsname}: will add [%03x] %{dnsname} %5i %{typerdatadesc}", diff->origin, rr->state, fqdn, rttl, &rd);
#endif

    if(!(rr->state & ZONE_DIFF_RR_TTL_UPDATED))
    {
        if(((rr->state & ZONE_DIFF_RR_IN_ZONE) != 0) && ((rr->state & ZONE_DIFF_RR_REMOVE) != 0))
        {
            // rr->state |= ZONE_DIFF_RR_ADD;
            rr->state &= ~ZONE_DIFF_RR_REMOVE;
#if DEBUG
            log_debug2("update: %{dnsname}: will add [%03x] %{dnsname} %5i %{typerdatadesc} (no add needed, cleared del)", diff->origin, rr->state, fqdn, rttl, &rd);
#endif
        }
        else if(((rr->state & ZONE_DIFF_RR_IN_ZONE) == 0) || ((rr->state & ZONE_DIFF_RR_REMOVE) != 0))
        {
            rr->state |= ZONE_DIFF_RR_ADD;
#if DEBUG
            log_debug2("update: %{dnsname}: will add [%03x] %{dnsname} %5i %{typerdatadesc} (set  add)", diff->origin, rr->state, fqdn, rttl, &rd);
#endif
        }
    }
    else
    {
        rr->state |= ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE;
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

void zone_diff_record_remove(zone_diff *diff, zdb_rr_label_t *rr_label, const uint8_t *fqdn, uint16_t rtype, int32_t rttl, uint16_t rdata_size, void *rdata)
{
#if DEBUG
    rdata_desc_t rd = {rtype, rdata_size, rdata};
    log_debug2("update: %{dnsname}: will del %{dnsname} %5i %{typerdatadesc}", diff->origin, fqdn, rttl, &rd);
#endif
    (void)rttl;
    zone_diff_fqdn        *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, rtype);
    zone_diff_label_rr    *rr = zone_diff_label_rr_new(fqdn, rtype, CLASS_IN, rttl, rdata, rdata_size, true);
    rr = zone_diff_fqdn_rr_set_rr_add_get(rr_set, rr);
    rr->state |= ZONE_DIFF_RR_REMOVE;
}

bool zone_diff_record_remove_existing(zone_diff *diff, zdb_rr_label_t *rr_label, const uint8_t *fqdn, uint16_t rtype, int32_t rttl, uint16_t rdata_size, void *rdata)
{
#if DEBUG
    rdata_desc_t rd = {rtype, rdata_size, rdata};
    log_debug2("update: %{dnsname}: will del %{dnsname} %5i %{typerdatadesc}", diff->origin, fqdn, rttl, &rd);
#endif
    (void)rttl;
    zone_diff_fqdn        *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_get(diff_fqdn, rtype);
    if(rr_set != NULL)
    {
        zone_diff_label_rr tmp_rr;
        zone_diff_label_rr_init_tmp(&tmp_rr, fqdn, rtype, CLASS_IN, rttl, rdata, rdata_size);
        zone_diff_label_rr *rr = zone_diff_fqdn_rr_set_get_existing_rr(rr_set, &tmp_rr);
        if(rr != NULL)
        {
            rr->state |= ZONE_DIFF_RR_REMOVE;
            return true;
        }
    }

    return false;
}

void zone_diff_record_remove_automated(zone_diff *diff, zdb_rr_label_t *rr_label, const uint8_t *fqdn, uint16_t rtype, int32_t rttl, uint16_t rdata_size, void *rdata)
{
#if DEBUG
    rdata_desc_t rd = {rtype, rdata_size, rdata};
    log_debug2("update: %{dnsname}: will del %{dnsname} %5i %{typerdatadesc}", diff->origin, fqdn, rttl, &rd);
#endif
    (void)rttl;
    zone_diff_fqdn        *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, rtype);
    zone_diff_label_rr    *rr = zone_diff_label_rr_new(fqdn, rtype, CLASS_IN, rttl, rdata, rdata_size, true);
    rr = zone_diff_fqdn_rr_set_rr_add_get(rr_set, rr);
    rr->state |= ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_AUTOMATED;
}

/**
 * Adds the removal of a record set on a diff
 *
 * @param diff
 * @param rr_label
 * @param fqdn
 * @param rtype
 */

void zone_diff_record_remove_all(zone_diff *diff, zdb_rr_label_t *rr_label, const uint8_t *fqdn, uint16_t rtype)
{
    zone_diff_fqdn        *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);
    zone_diff_fqdn_rr_set *rr_set = zone_diff_fqdn_rr_set_add(diff_fqdn, rtype);

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&rr_set->rr, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
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

void zone_diff_record_remove_all_sets(zone_diff *diff, zdb_rr_label_t *rr_label, const uint8_t *fqdn)
{
    zone_diff_fqdn        *diff_fqdn = zone_diff_fqdn_add(diff, fqdn, rr_label);

    u32_treemap_iterator_t typeiter;
    u32_treemap_iterator_init(&diff_fqdn->rrset, &typeiter);
    while(u32_treemap_iterator_hasnext(&typeiter))
    {
        u32_treemap_node_t *node = u32_treemap_iterator_next_node(&typeiter);

        yassert((node != NULL) && (node->value != NULL));

        zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set *)node->value;

        ptr_treemap_iterator_t iter;
        ptr_treemap_iterator_init(&rr_set->rr, &iter);
        while(ptr_treemap_iterator_hasnext(&iter))
        {
            ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
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

ya_result zone_diff_set_soa(zone_diff *diff, zdb_rr_label_t *label)
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

    zone_diff_fqdn        *apex = zone_diff_fqdn_add(diff, diff->origin, label);
    zone_diff_fqdn_rr_set *soa_rrset = zone_diff_fqdn_rr_set_add(apex, TYPE_SOA);

    // ptr_treemap_iterator_t fqdn_iter;
    ptr_treemap_iterator_t rr_iter;

    zone_diff_label_rr    *rr_soa_removed = NULL;
    zone_diff_label_rr    *rr_soa_added = NULL;
    uint32_t               soa_latest_serial;
    ya_result              ret;

    ptr_treemap_iterator_init(&soa_rrset->rr, &rr_iter);
    while(ptr_treemap_iterator_hasnext(&rr_iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

#if DEBUG
        rdata_desc_t rd = {rr->rtype, rr->rdata_size, rr->rdata};
        log_debug1("update: %{dnsname}: SOA[%x] %{dnsname} %9i %{typerdatadesc}", diff->origin, rr->state, rr->fqdn, rr->ttl, &rd);
#endif

        if(rr->state & ZONE_DIFF_RR_REMOVE)
        {
            uint32_t soa_serial;

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
        uint32_t soa_serial;

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
        uint8_t tmp_rdata[rr_soa_removed->rdata_size];
#else
        uint8_t *const tmp_rdata = (uint8_t *const)stack_alloc(rr_soa_removed->rdata_size);
#endif

        memcpy(tmp_rdata, rr_soa_removed->rdata, rr_soa_removed->rdata_size);
        rr_soa_increase_serial(tmp_rdata, rr_soa_removed->rdata_size, 1);
        rr_soa_added = zone_diff_label_rr_new(rr_soa_removed->fqdn, TYPE_SOA, CLASS_IN, rr_soa_removed->ttl, tmp_rdata, rr_soa_removed->rdata_size, true);
        rr_soa_added = zone_diff_fqdn_rr_set_rr_add_get(soa_rrset, rr_soa_added); // add_get
        rr_soa_added->state |= ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_AUTOMATED;
    }

    return SUCCESS;
}

/**
 * Updates status and validates a diff.
 *
 * @param diff
 * @return
 */

ya_result zone_diff_validate(zone_diff *diff)
{
    ptr_treemap_iterator_t fqdn_iter;

    ptr_vector_t           diff_fqdn_to_remove = EMPTY_PTR_VECTOR;

    ptr_treemap_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_treemap_iterator_hasnext(&fqdn_iter))
    {
        ptr_treemap_node_t *diff_fqdn_node = ptr_treemap_iterator_next_node(&fqdn_iter);

        const uint8_t      *diff_fqdn_name = (const uint8_t *)diff_fqdn_node->key;
        zone_diff_fqdn     *diff_fqdn = (zone_diff_fqdn *)diff_fqdn_node->value;

        // update status flags
        // do validation tests

        log_debug2("update: %{dnsname}: validating %{dnsname}", diff->origin, diff_fqdn_name);

        if(diff_fqdn->is_apex)
        {
            // only check for CNAME

            if(zone_diff_will_have_rrset_type(diff_fqdn, TYPE_CNAME))
            {
                log_err("update: %{dnsname}: update would add CNAME on apex", diff->origin);

                // dnssec_chain_finalize(&dc);

                return INVALID_STATE_ERROR;
            }
        }
        else
        {
            // check for CNAME

            // update under-delegation
            //
            //      for all labels above, look in the diff if they are present and if their delegation status will be
            //      changed

            bool           under_delegation = false;

            const uint8_t *above_fqdn = diff_fqdn->fqdn;
            bool           is_right_above = true;
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
                                log_warn(
                                    "update: %{dnsname}: %{dnsname} expected to be marked as being under delegation in "
                                    "the database as %{dnsname} at=%i under=%i (fixing)",
                                    diff->origin,
                                    diff_fqdn->fqdn,
                                    parent->fqdn,
                                    parent->was_at_delegation,
                                    parent->was_under_delegation);
                            }
#endif
                            diff_fqdn->was_under_delegation = true;
                        }
                        else if(!((parent->was_at_delegation || parent->was_under_delegation)) && diff_fqdn->was_under_delegation)
                        {
                            // then we are at delegation
#if DEBUG
                            if(diff_fqdn->is_in_database)
                            {
                                log_warn(
                                    "update: %{dnsname}: %{dnsname} not expected to be marked as being under "
                                    "delegation in the database as %{dnsname} at=%i under=%i (fixing)",
                                    diff->origin,
                                    diff_fqdn->fqdn,
                                    parent->fqdn,
                                    parent->was_at_delegation,
                                    parent->was_under_delegation);
                            }
#endif
                            diff_fqdn->was_under_delegation = false;
                        }

                        is_right_above = false;
                    }

                    if(parent->under_delegation)
                    {
                        if(!diff_fqdn->under_delegation)
                        {
                            log_debug("update: %{dnsname}: %{dnsname} under under delegation %{dnsname}", diff->origin, diff_fqdn->fqdn, parent->fqdn);
                        }
                        under_delegation = true;
                        break;
                    }

                    if(parent->at_delegation)
                    {
                        if(!diff_fqdn->under_delegation)
                        {
                            log_debug1("update: %{dnsname}: %{dnsname} under delegation %{dnsname}", diff->origin, diff_fqdn->fqdn, parent->fqdn);
                        }
                        under_delegation = true;
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
                diff_fqdn->at_delegation = true;

                // check there will be only glue records under this level
            }
            else
            {
                diff_fqdn->at_delegation = false;
            }

            diff_fqdn->will_have_ds = zone_diff_will_have_rrset_type(diff_fqdn, TYPE_DS);

            if(diff_fqdn->will_have_ds && !diff_fqdn->at_delegation)
            {
                log_debug1("update: %{dnsname}: %{dnsname} will have a DS but no NS : removing all DS", diff->origin, diff_fqdn->fqdn);

                zone_diff_remove_rrset_type(diff_fqdn, TYPE_DS);
                diff_fqdn->will_have_ds = 0;

                if(u32_treemap_isempty(&diff_fqdn->rrset))
                {
                    ptr_vector_append(&diff_fqdn_to_remove, diff_fqdn_node);
                }

                // TODO: remove NSEC3 record -- @note 20220805 edf -- I'm pretty sure this TODO is invalid
            }
        }

        log_debug2("update: %{dnsname}: validating %{dnsname}: apex=%i at=%i under=%i ds=%i was-at=%i was-under=%i had-ds=%i",
                   diff->origin,
                   diff_fqdn_name,
                   diff_fqdn->is_apex,
                   diff_fqdn->at_delegation,
                   diff_fqdn->under_delegation,
                   diff_fqdn->will_have_ds,
                   diff_fqdn->was_at_delegation,
                   diff_fqdn->was_under_delegation,
                   diff_fqdn->had_ds);
    }

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(&diff_fqdn_to_remove); ++i)
    {
        ptr_treemap_node_t *diff_fqdn_node = (ptr_treemap_node_t *)ptr_vector_get(&diff_fqdn_to_remove, i);
        // const uint8_t *diff_fqdn_name = (const uint8_t*)diff_fqdn_node->key;
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn *)diff_fqdn_node->value;
        ptr_treemap_delete(&diff->fqdn, diff_fqdn->fqdn); // remove the node

        // if diff_fqdn is not in the database
        //   from diff->root, remove the fqdn with attention to empty terminal not in the database
        //   and

        // zone_diff_fqdn_delete(diff_fqdn);               // delete the data
    }
    ptr_vector_finalise(&diff_fqdn_to_remove);

    return SUCCESS;
}

struct zone_diff_get_changes_update_rr_parm
{
    uint8_t changes;
    bool    rrset_removed;
    bool    rrset_new;
    bool    all_rrset_added;
    bool    all_rrset_removed;
    bool    non_empty;
};

static void zone_diff_get_changes_update_rrsig_rr(zone_diff_fqdn_rr_set *rr_set, struct zone_diff_get_changes_update_rr_parm *parm, ptr_vector_t *remove, ptr_vector_t *add)
{
    uint8_t                changes = parm->changes;
    bool                   rrset_removed = parm->rrset_removed;
    bool                   all_rrset_added = parm->all_rrset_added;
    bool                   all_rrset_removed = parm->all_rrset_removed;
    bool                   rrset_new = true;

    ptr_treemap_iterator_t rr_iter;

    // for all marked rr

    ptr_treemap_iterator_init(&rr_set->rr, &rr_iter);
    while(ptr_treemap_iterator_hasnext(&rr_iter))
    {
        ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->value;

        yassert(rr->rtype == TYPE_RRSIG);

        if((rr->state & (ZONE_DIFF_RR_IN_ZONE | ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_ADDED)) == ZONE_DIFF_RR_ADD)
        {
            // add
#if DEBUG
            rdata_desc_t    rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: add %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rrsig_rr %p)", &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif

            ptr_vector_append(add, rr);
            rr->state |= ZONE_DIFF_RR_ADDED;

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_ADD;
            rrset_removed = false;
            all_rrset_removed = false;
        }
        else if((rr->state & (ZONE_DIFF_RR_IN_ZONE | ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_REMOVED)) == (ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_IN_ZONE))
        {
            // remove

#if DEBUG
            rdata_desc_t    rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: del %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rrsig_rr %p)", &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif

            ptr_vector_append(remove, rr);
            rr->state |= ZONE_DIFF_RR_REMOVED;

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_REMOVE;
            all_rrset_added = false;
        }
        else if((rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE)) == 0)
        {
            // stays

#if DEBUG
            rdata_desc_t    rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: nop %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rrsig_rr %p)", &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif

            changes |= ZONE_DIFF_CHANGES_KEPT;
            rrset_removed = false;
            all_rrset_removed = false;
            all_rrset_added = false;

            rrset_new = true;
        }
        else
        {
#if DEBUG
            rdata_desc_t    rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: ign %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rrsig_rr %p)", &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif
        }
    }

    parm->changes = changes;
    parm->rrset_removed = rrset_removed;
    parm->rrset_new = rrset_new;
    parm->all_rrset_added = all_rrset_added;
    parm->all_rrset_removed = all_rrset_removed;
}

static void zone_diff_get_changes_update_rr(zone_diff_fqdn_rr_set *rr_set, struct zone_diff_get_changes_update_rr_parm *parm, ptr_vector_t *remove, ptr_vector_t *add)
{

    uint8_t                changes = parm->changes;
    bool                   rrset_removed = parm->rrset_removed;
    bool                   all_rrset_added = parm->all_rrset_added;
    bool                   all_rrset_removed = parm->all_rrset_removed;
    bool                   non_empty = parm->non_empty;

    ptr_treemap_iterator_t rr_iter;

    // for all marked rr

    ptr_treemap_iterator_init(&rr_set->rr, &rr_iter);
    while(ptr_treemap_iterator_hasnext(&rr_iter))
    {
        ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->value;

        if((rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_ADDED)) == ZONE_DIFF_RR_ADD)
        {
            // add

#if DEBUG
            rdata_desc_t    rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: add %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rr %p)", &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif
            ptr_vector_append(add, rr);
            rr->state |= ZONE_DIFF_RR_ADDED;

            if(rr->rtype == TYPE_SOA)
            {
                ptr_vector_end_swap(add, 0);
            }

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_ADD;
            rrset_removed = false;
            all_rrset_removed = false;
            non_empty = true;
        }
        else if((rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_REMOVED)) == ZONE_DIFF_RR_REMOVE)
        {
            // remove

#if DEBUG
            rdata_desc_t    rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: del %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rr %p)", &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif

            ptr_vector_append(remove, rr);
            rr->state |= ZONE_DIFF_RR_REMOVED;

            if(rr->rtype == TYPE_SOA)
            {
                ptr_vector_end_swap(remove, 0);
            }

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_REMOVE;
            all_rrset_added = false;
        }
        else if((rr->state & ZONE_DIFF_RR_TTL_UPDATED) == ZONE_DIFF_RR_TTL_UPDATED)
        {
            // remove

#if DEBUG
            rdata_desc_t    rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: ttl %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rr %p)", &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif
            ptr_vector_append(add, rr);
            ptr_vector_append(remove, rr);
            rr->state |= ZONE_DIFF_RR_ADDED;
            rr->state |= ZONE_DIFF_RR_REMOVED;

            if(rr->rtype == TYPE_SOA)
            {
                ptr_vector_end_swap(remove, 0);
            }

            // proceed with the chain if needed

            changes |= ZONE_DIFF_CHANGES_ADD | ZONE_DIFF_CHANGES_REMOVE;
            rrset_removed = false;
            all_rrset_added = false;
            non_empty = true;
        }
        else if((rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE)) == 0)
        {

#if DEBUG
            rdata_desc_t    rrsig_rr_rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug1("update: nop %w %{dnsname} %9i %{typerdatadesc} (zone_diff_get_changes_update_rr %p)", &temp_fw_0, rr->fqdn, rr->ttl, &rrsig_rr_rd, rr);
#endif
            // stays
            changes |= ZONE_DIFF_CHANGES_KEPT;
            rrset_removed = false;
            all_rrset_removed = false;
            all_rrset_added = false;
            non_empty = true;
        }
    }

    parm->changes = changes;
    parm->rrset_removed = rrset_removed;
    parm->all_rrset_added = all_rrset_added;
    parm->all_rrset_removed = all_rrset_removed;
    parm->non_empty = non_empty;
}

uint64_t zone_diff_key_vector_get_mask(ptr_vector_t *keys, time_t now, uint32_t regeneration_seconds)
{
    uint64_t mask = 0;
    for(int_fast32_t i = 0; i <= ptr_vector_last_index(keys); ++i)
    {
        dnskey_t *key = (dnskey_t *)ptr_vector_get(keys, i);

        bool      is_private = dnskey_is_private(key);

        if((is_private && dnskey_is_activated_lenient(key, now, regeneration_seconds)) || !is_private)
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
 * @return true iff there is a DNSKEY rrset in the diff
 */

int32_t zone_diff_get_changes(zone_diff *diff, ptr_vector_t *rrset_to_sign_vector, ptr_vector_t *ksks, ptr_vector_t *zsks, ptr_vector_t *remove, ptr_vector_t *add, int32_t regeneration_seconds)
{
    int32_t   mandatory_changes = 0;
    ya_result err = SUCCESS;

    // first fill the arrays with the relevant keys

    zone_diff_store_diff_dnskey_get_keys(diff, ksks, zsks, regeneration_seconds);

    ptr_treemap_iterator_t fqdn_iter;
    ptr_treemap_iterator_t rr_iter;

    time_t                 now = time(NULL);

    uint64_t               ksks_mask = zone_diff_key_vector_get_mask(ksks, now, regeneration_seconds);
    uint64_t               zsks_mask = zone_diff_key_vector_get_mask(zsks, now, regeneration_seconds);

    // bool may_have_empty_terminals = false;

    // for all fqdn

    ptr_treemap_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_treemap_iterator_hasnext(&fqdn_iter))
    {
        ptr_treemap_node_t *diff_fqdn_node = ptr_treemap_iterator_next_node(&fqdn_iter);
#if DYNUPDATE_DIFF_DETAILED_LOG
        const uint8_t *diff_fqdn_name = (const uint8_t *)diff_fqdn_node->key;
#endif
        zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn *)diff_fqdn_node->value;

        if(diff_fqdn->will_have_new_nsec)
        {
            ++mandatory_changes;
        }

        // for all rrset

        bool                   type_map_changed = false;
        bool                   all_rrset_added = true;
        bool                   all_rrset_removed = true;
        bool                   non_empty = false;

        zone_diff_fqdn_rr_set *rrsig_rr_set = NULL;

        u32_treemap_node_t    *rrset_node = u32_treemap_find(&diff_fqdn->rrset, TYPE_RRSIG);
        if(rrset_node != NULL)
        {
            rrsig_rr_set = (zone_diff_fqdn_rr_set *)rrset_node->value;
        }

        type_map_changed = (rrsig_rr_set == NULL);

        // for all records

        if(!u32_treemap_isempty(&diff_fqdn->rrset))
        {
            u32_treemap_iterator_t rrset_iter;
            u32_treemap_iterator_init(&diff_fqdn->rrset, &rrset_iter);
            while(u32_treemap_iterator_hasnext(&rrset_iter))
            {
                u32_treemap_node_t    *rrset_node = u32_treemap_iterator_next_node(&rrset_iter);

                zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set *)rrset_node->value;

                if(rr_set == NULL)
                {
                    continue;
                }

#if DYNUPDATE_DIFF_DETAILED_LOG
                {
                    // enumerate records

                    ptr_treemap_iterator_t rr_iter;
                    ptr_treemap_iterator_init(&rr_set->rr, &rr_iter);
                    rdata_desc_t rdatadesc = {rr_set->rtype, 0, NULL};
                    while(ptr_treemap_iterator_hasnext(&rr_iter))
                    {
                        ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
                        zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->key;
                        rdatadesc.len = rr->rdata_size;
                        rdatadesc.rdata = rr->rdata;
                        log_debug("update: %03x [%llx] %{dnsname} %i %{typerdatadesc}", rr->state, rr_set->key_mask, rr->fqdn, rr->ttl, &rdatadesc);
                    }
                }
#endif
                if(rr_set->rtype == TYPE_RRSIG)
                {
                    // if allowed ...

                    if(diff->rrsig_update_allowed)
                    {
                        ptr_treemap_iterator_init(&rr_set->rr, &rr_iter);
                        bool rrsig_added = false;
                        bool rrsig_kept = false;
                        bool rrsig_removed = false;
                        bool key_will_be_present = false;
                        bool key_will_be_present_DNSKEY = false;
                        bool key_will_be_present_not_DNSKEY = false;

                        while(ptr_treemap_iterator_hasnext(&rr_iter))
                        {
                            ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
                            zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->value;
                            if((rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_ADD)
                            {
                                rdata_desc_t rdt = {rr->rtype, rr->rdata_size, rr->rdata};

                                log_debug(
                                    "update: %{dnsname}: checking for signing key of RRSIG record %{dnsname} %i "
                                    "%{dnsclass} %{typerdatadesc}",
                                    diff->origin,
                                    rr->fqdn,
                                    rr->ttl,
                                    &rr->rclass,
                                    &rdt);

                                uint8_t  algorithm = rrsig_get_algorithm_from_rdata(rr->rdata, rr->rdata_size);
                                uint16_t tag = rrsig_get_key_tag_from_rdata(rr->rdata, rr->rdata_size);

                                rrsig_added = true;

                                if(zone_diff_will_have_dnskey_with_algorithm_tag(diff_fqdn, algorithm, tag))
                                {
                                    key_will_be_present = true;
                                    if(rrsig_get_type_covered_from_rdata(rr->rdata, rr->rdata_size) == TYPE_DNSKEY)
                                    {
                                        key_will_be_present_DNSKEY = true;
                                    }
                                    else
                                    {
                                        key_will_be_present_not_DNSKEY = true;
                                    }
                                    break;
                                }
                            }
                            else if((rr->state & (ZONE_DIFF_RR_IN_ZONE | ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_REMOVE)
                            {
                                rrsig_removed = true;
                            }
                            else if((rr->state & (ZONE_DIFF_RR_IN_ZONE /*|ZONE_DIFF_RR_ADD*/ | ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_IN_ZONE)
                            {
                                rrsig_kept = true; // if it's added but already in zone, it does not count does it ...
                            }
                        }

                        diff_fqdn->rrsig_added = rrsig_added;
                        diff_fqdn->rrsig_kept = rrsig_kept;
                        diff_fqdn->rrsig_removed = rrsig_removed;

                        if(!rrsig_added || (rrsig_added && key_will_be_present))
                        {
                            uint8_t                                     changes = ZONE_DIFF_CHANGES_NONE;
                            bool                                        rrset_removed = true;

                            struct zone_diff_get_changes_update_rr_parm parms = {changes, rrset_removed, false, all_rrset_added, all_rrset_removed, non_empty};
                            zone_diff_get_changes_update_rrsig_rr(rr_set, &parms, remove, add);

                            diff_fqdn->rrsig_kept = !parms.rrset_new;
                        }
                        else
                        {
                            if(!key_will_be_present_DNSKEY)
                            {
                                log_info(
                                    "update: %{dnsname}: DNSKEY RRSIG without signing DNSKEY present (probably on "
                                    "purpose)",
                                    diff_fqdn->fqdn);
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
                        log_debug1(
                            "update: %{dnsname}: not updating RRSIG rr_set at this point (rrsig_update_allowed is "
                            "false)",
                            diff_fqdn->fqdn);
                        ptr_treemap_iterator_init(&rr_set->rr, &rr_iter);
                        while(ptr_treemap_iterator_hasnext(&rr_iter))
                        {
                            ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
                            zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->value;
                            if((rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_ADD)
                            {
                                rdata_desc_t rdt = {rr->rtype, rr->rdata_size, rr->rdata};

                                log_debug("update: %{dnsname}: (ignoring) [%03x] %{dnsname} %i %{dnsclass} %{typerdatadesc}", diff->origin, rr->state, rr->fqdn, rr->ttl, &rr->rclass, &rdt);
                            }
                        }
                    }
#endif
                    continue;
                }

                uint8_t                                     changes = ZONE_DIFF_CHANGES_NONE;
                bool                                        rrset_removed = true;

                struct zone_diff_get_changes_update_rr_parm parms = {changes, false, rrset_removed, all_rrset_added, all_rrset_removed, non_empty};
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
                 * If the status is 0, then all the added records that have been added have also been removed => no map
                 * change, and no signature change If the status is 1, then the rrset has completely been removed => map
                 * change and remove all signatures If the status is 2, then the rrset has completely been added => map
                 * change, and add (new) signatures If the status is 4, then the rrset existed and still exists => no
                 * map change, and no signature change
                 *
                 * Any other combination having 1 or 2 on will make no map change but update the signature
                 *
                 */

                if((changes == ZONE_DIFF_CHANGES_ADD) || (changes == ZONE_DIFF_CHANGES_REMOVE))
                {
                    type_map_changed = true;
                }

                ptr_vector_t *keys = zsks;
                uint64_t      keys_mask = zsks_mask;

                if(rr_set->rtype == TYPE_DNSKEY)
                {
                    if(!ptr_vector_isempty(ksks))
                    {
                        keys = ksks;
                        keys_mask = ksks_mask;
                    }
                }

                if(rrset_node->key == TYPE_RRSIG)
                {
                    continue;
                }

                bool rrset_updated = (changes & (ZONE_DIFF_CHANGES_ADD | ZONE_DIFF_CHANGES_REMOVE)); // || type_map_changed ?

                if((rr_set->rtype != TYPE_SOA) && rrset_updated)
                {
                    ++mandatory_changes;
                }

                bool rrset_expected_to_be_covered = !(diff_fqdn->at_delegation || diff_fqdn->under_delegation) || (!diff_fqdn->under_delegation && (diff_fqdn->at_delegation && ((rr_set->rtype == TYPE_DS) || (rr_set->rtype == TYPE_NSEC))));

                bool rrset_rrsig_covered_with_chain_rules = (!rrset_removed && rrset_expected_to_be_covered);
                bool came_under_delegation = (!diff_fqdn->was_under_delegation && diff_fqdn->under_delegation);
                // bool came_out_of_delegation = (diff_fqdn->was_under_delegation && !diff_fqdn->under_delegation);

                // blanket bombing

                if((rrsig_rr_set != NULL) && (rrset_updated || all_rrset_removed || came_under_delegation || !rrset_rrsig_covered_with_chain_rules))
                {
                    ptr_treemap_iterator_init(&rrsig_rr_set->rr, &rr_iter);
                    while(ptr_treemap_iterator_hasnext(&rr_iter))
                    {
                        ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
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
                            rrsig_rr->state |= ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_AUTOMATED;
#if DEBUG
                            {
                                rdata_desc_t    rrsig_rr_rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                                format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rrsig_rr->state};
                                log_debug1("update: del %w %{dnsname} %9i %{typerdatadesc} (rrsig A zone_diff_get_changes %p)", &temp_fw_0, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_rd, rrsig_rr);
                            }
#endif
                            ptr_vector_append(remove, rrsig_rr);
                            rrsig_rr->state |= ZONE_DIFF_RR_REMOVED;
                        }
                    }
                }

                // for all rrsig, enumerate properly covered types

                // bool rrset_already_covered = false;

                if(!all_rrset_removed && rrset_rrsig_covered_with_chain_rules) // else this would be pointless
                {
                    if(rrsig_rr_set != NULL)
                    {
                        uint64_t coverage = 0;

                        ptr_treemap_iterator_init(&rrsig_rr_set->rr, &rr_iter);
                        while(ptr_treemap_iterator_hasnext(&rr_iter))
                        {
                            ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
                            zone_diff_label_rr *rrsig_rr = (zone_diff_label_rr *)rr_node->key;

                            if(rrsig_get_type_covered_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size) != rr_set->rtype)
                            {
                                continue;
                            }

                            if((rrsig_rr->state & (ZONE_DIFF_RR_ADDED | ZONE_DIFF_RR_RDATA_OWNED)) == (ZONE_DIFF_RR_ADDED | ZONE_DIFF_RR_RDATA_OWNED))
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

                            int32_t key_index = -2;

                            if(rrsig_should_remove_signature_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size, keys, now, diff->rrsig_validity_regeneration, &key_index) || (key_index == -1))
                            {
                                rrsig_rr->state |= ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_AUTOMATED;

#if DEBUG
                                {
                                    rdata_desc_t    rrsig_rr_rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                                    format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rrsig_rr->state};
                                    log_debug1(
                                        "update: del %w %{dnsname} %9i %{typerdatadesc} (rrsig B zone_diff_get_changes "
                                        "%p)",
                                        &temp_fw_0,
                                        rrsig_rr->fqdn,
                                        rrsig_rr->ttl,
                                        &rrsig_rr_rd,
                                        rrsig_rr);
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
                    log_debug("update: %{dnsname}: dnssec: %{dnsname} %{dnstype} rrset @%p should be signed (%08llx/%08llx)", diff->origin, diff_fqdn_name, &rr_set->rtype, rr_set, rr_set->key_mask, keys_mask);
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
            type_map_changed = false;
            all_rrset_added = false;
            all_rrset_removed = false;
            non_empty = false;

            // may_have_empty_terminals = true;
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
            log_debug("update: -- --- %{dnsname} remap=%i +all=%i -all=%i !empty=%i mandatory = %i + %i + %i",
                      diff_fqdn->fqdn,
                      type_map_changed,
                      all_rrset_added,
                      all_rrset_removed,
                      non_empty,
                      mandatory_changes,
                      diff->nsec_change_count,
                      diff->nsec3_change_count);
        }
#endif
    }

    if(ISOK(err))
    {
        // mandatory_changes += diff->nsec_change_count + diff->nsec3_change_count;
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
        ptr_treemap_iterator_init(&diff->fqdn, &fqdn_iter);
        while(ptr_treemap_iterator_hasnext(&fqdn_iter))
        {
            ptr_treemap_node_t *diff_fqdn_node = ptr_treemap_iterator_next_node(&fqdn_iter);
            const uint8_t *diff_fqdn_name = (const uint8_t*)diff_fqdn_node->key;

            zone_diff_fqdn *diff_fqdn = (zone_diff_fqdn*)diff_fqdn_node->value;
        }
    }
#endif

bool zone_diff_adds_nsec3param(zone_diff *diff)
{
    ptr_treemap_iterator_t fqdn_iter;
    ptr_treemap_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_treemap_iterator_hasnext(&fqdn_iter))
    {
        ptr_treemap_node_t *diff_fqdn_node = ptr_treemap_iterator_next_node(&fqdn_iter);
        zone_diff_fqdn     *diff_fqdn = (zone_diff_fqdn *)diff_fqdn_node->value;
        if(!dnsname_equals(diff->origin, diff_fqdn->fqdn))
        {
            continue;
        }

        u32_treemap_node_t *rrset_node = u32_treemap_find(&diff_fqdn->rrset, /*TYPE_NSEC3PARAM*/ TYPE_NSEC3PARAMQUEUED);
        if(rrset_node != NULL)
        {
            zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)rrset_node->value;

            ptr_treemap_iterator_t rr_iter;
            ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
            while(ptr_treemap_iterator_hasnext(&rr_iter))
            {
                ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

                if((rr->state & ZONE_DIFF_RR_ADDED) != 0)
                {
                    return true;
                }
            }
        }
    }

    return false;
}

bool zone_diff_has_or_adds_nsec3param(zone_diff *diff)
{
    ptr_treemap_iterator_t fqdn_iter;
    ptr_treemap_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_treemap_iterator_hasnext(&fqdn_iter))
    {
        ptr_treemap_node_t *diff_fqdn_node = ptr_treemap_iterator_next_node(&fqdn_iter);
        zone_diff_fqdn     *diff_fqdn = (zone_diff_fqdn *)diff_fqdn_node->value;
        if(!dnsname_equals(diff->origin, diff_fqdn->fqdn))
        {
            continue;
        }

        u32_treemap_node_t *rrset_node;

        rrset_node = u32_treemap_find(&diff_fqdn->rrset, TYPE_NSEC3PARAM);
        if(rrset_node != NULL)
        {
            zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)rrset_node->value;

            ptr_treemap_iterator_t rr_iter;
            ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
            while(ptr_treemap_iterator_hasnext(&rr_iter))
            {
                ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

                if((rr->state & (ZONE_DIFF_RR_IN_ZONE | ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_ADDED)) != 0)
                {
                    return true;
                }
            }
        }

        rrset_node = u32_treemap_find(&diff_fqdn->rrset, TYPE_NSEC3PARAMQUEUED);
        if(rrset_node != NULL)
        {
            zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)rrset_node->value;

            ptr_treemap_iterator_t rr_iter;
            ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
            while(ptr_treemap_iterator_hasnext(&rr_iter))
            {
                ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

                if((rr->state & (ZONE_DIFF_RR_IN_ZONE | ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_ADDED)) != 0)
                {
                    return true;
                }
            }
        }
    }

    return false;
}

bool zone_diff_has_zsk(zone_diff *diff)
{
    ptr_treemap_iterator_t fqdn_iter;
    ptr_treemap_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_treemap_iterator_hasnext(&fqdn_iter))
    {
        ptr_treemap_node_t *diff_fqdn_node = ptr_treemap_iterator_next_node(&fqdn_iter);
        zone_diff_fqdn     *diff_fqdn = (zone_diff_fqdn *)diff_fqdn_node->value;
        if(!dnsname_equals(diff->origin, diff_fqdn->fqdn))
        {
            continue;
        }

        u32_treemap_node_t *rrset_node = u32_treemap_find(&diff_fqdn->rrset, TYPE_DNSKEY);
        if(rrset_node != NULL)
        {
            zone_diff_fqdn_rr_set *rrset = (zone_diff_fqdn_rr_set *)rrset_node->value;

            ptr_treemap_iterator_t rr_iter;
            ptr_treemap_iterator_init(&rrset->rr, &rr_iter);
            while(ptr_treemap_iterator_hasnext(&rr_iter))
            {
                ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;

                if((rr->state & ZONE_DIFF_RR_ADDED) != 0)
                {
                    if((rr->rdata_size >= 2) && DNSKEY_FLAGS_FROM_RDATA(rr->rdata) == DNSKEY_FLAGS_ZSK)
                    {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

void zone_diff_get_chain_changes(zone_diff *diff, dnssec_chain *dc /*, ptr_vector_t *rrset_to_sign_vector, ptr_vector_t *ksks, ptr_vector_t *zsks, ptr_vector_t *remove, ptr_vector_t *add*/)
{
    ptr_treemap_iterator_t fqdn_iter;

    if(dc != NULL)
    {
        ptr_treemap_iterator_init(&diff->fqdn, &fqdn_iter);
        while(ptr_treemap_iterator_hasnext(&fqdn_iter))
        {
            ptr_treemap_node_t *diff_fqdn_node = ptr_treemap_iterator_next_node(&fqdn_iter);
            const uint8_t      *diff_fqdn_name = (const uint8_t *)diff_fqdn_node->key;

            zone_diff_fqdn     *diff_fqdn = (zone_diff_fqdn *)diff_fqdn_node->value;

            zone_diff_fqdn_children_state(diff, diff_fqdn->fqdn);

            // calling dnssec_chain_del_from_diff_fqdn and dnssec_chain_add_from_diff_fqdn respectively
            // tell to remove or to add a chain node (NSEC/NSEC3) for the given fqdn in the zone.

            // Note the "was" or "is" covered means "IF the fqdn existed, was the past state covering it, is the new
            // state covering it."

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
            //      0            1          0      1      ?   |        There is nothing anymore (empty non-terminal ? =>
            //      +) 0            1          0      0      0   |  + 0            1          0      0      1   |  +
            // -----------------------------------------------+------
            //      1            0          1      0      ?   |        There was nothing before
            //      1            0          0      1      ?   |  -
            //      1            0          0      0      0   |  -
            //      1            0          0      0      1   |  -
            // -----------------------------------------------+------
            //      1            1          1      0      ?   |  +     There was nothing before
            //      1            1          0      1      ?   |  -                              (empty non-terminal ? =>
            //      -+) 1            1          0      0      0   |        There is no changed of state on this regard
            //      1            1          0      0      1   | -+
            // -----------------------------------------------+------

#define CHAIN_NODE_NOP 0
#define CHAIN_NODE_DEL 1
#define CHAIN_NODE_ADD 2

            bool is_covered = dc->chain->fqdn_is_covered(diff_fqdn);
            bool was_covered = dc->chain->fqdn_was_covered(diff_fqdn);

#if DYNUPDATE_DIFF_DETAILED_LOG
            log_debug(
                "update: %{dnsname}: dnssec: %{dnsname}: +ALL(%i) -ALL(%i) RECORDS(%i->%i) COVERED(%i->%i) "
                "CHILDREN(%i->%i) AT(%i->%i) UNDER(%i->%i) MAP(%i)",
                diff->origin,
                diff_fqdn_name,
                diff_fqdn->all_rrset_added,
                diff_fqdn->all_rrset_removed,
                diff_fqdn->was_non_empty,
                diff_fqdn->will_be_non_empty,
                was_covered,
                is_covered,
                diff_fqdn->had_children,
                diff_fqdn->will_have_children,
                diff_fqdn->was_at_delegation,
                diff_fqdn->at_delegation,
                diff_fqdn->was_under_delegation,
                diff_fqdn->under_delegation,
                diff_fqdn->type_map_changed);
#endif
            if(was_covered || is_covered) // quickly cull the first 4 states of the table
            {
                bool    did_exist = diff_fqdn->had_children || diff_fqdn->was_non_empty;
                bool    will_exist = diff_fqdn->will_have_children || diff_fqdn->will_be_non_empty;

                uint8_t ops = 0;

                if((diff_fqdn->had_children != diff_fqdn->will_have_children) || (diff_fqdn->all_rrset_added) || (diff_fqdn->all_rrset_removed) || (diff_fqdn->type_map_changed) || (is_covered != was_covered))
                {
                    // ops_index = 3;  // means change

                    if(was_covered && did_exist)
                    {
                        // ops_index |= 8;
                        ops |= CHAIN_NODE_DEL;
                    }

                    if(is_covered && will_exist)
                    {
                        // ops_index |= 4;
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
 * Returns true iff there are changes in the diff
 *
 * @param diff
 * @param dc can be NULL
 * @param rrset_to_sign_vector can be NULL
 *
 * @return true iff there are changes in the diff
 */

bool zone_diff_has_changes(zone_diff *diff, ptr_vector_t *rrset_to_sign_vector)
{
    if(ptr_vector_last_index(rrset_to_sign_vector) >= 0)
    {
#if DEBUG
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(rrset_to_sign_vector); ++i)
        {
            zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set *)ptr_vector_get(rrset_to_sign_vector, i);

            ptr_treemap_iterator_t rr_iter;

            // for all marked rr

            ptr_treemap_iterator_init(&rr_set->rr, &rr_iter);
            while(ptr_treemap_iterator_hasnext(&rr_iter))
            {
                ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->value;

                rdata_desc_t        rdatadesc = {rr->rtype, rr->rdata_size, rr->rdata};

                format_writer_t     temp_fw_0 = {zone_diff_record_state_format, &rr->state};

                log_debug1("zone-diff: changes: %{dnsname}: %03x: %w: %{dnsname} %i %{typerdatadesc}", diff->origin, rr->state, &temp_fw_0, rr->fqdn, rr->ttl, &rdatadesc);
            }
        }
#endif

        return true;
    }

    ptr_treemap_iterator_t fqdn_iter;
    ptr_treemap_iterator_t rr_iter;

    // for all fqdn

    ptr_treemap_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_treemap_iterator_hasnext(&fqdn_iter))
    {
        ptr_treemap_node_t *diff_fqdn_node = ptr_treemap_iterator_next_node(&fqdn_iter);
        zone_diff_fqdn     *diff_fqdn = (zone_diff_fqdn *)diff_fqdn_node->value;

        // for all records

        u32_treemap_iterator_t rrset_iter;
        u32_treemap_iterator_init(&diff_fqdn->rrset, &rrset_iter);
        while(u32_treemap_iterator_hasnext(&rrset_iter))
        {
            u32_treemap_node_t    *rrset_node = u32_treemap_iterator_next_node(&rrset_iter);

            zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set *)rrset_node->value;

            // for all marked rr

            ptr_treemap_iterator_init(&rr_set->rr, &rr_iter);
            while(ptr_treemap_iterator_hasnext(&rr_iter))
            {
                ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->value;
#if DEBUG
                rdata_desc_t rd = {rr->rtype, rr->rdata_size, rr->rdata};
                log_debug1("update: %{dnsname}: has-changes: state %03x: %{dnsname} %9i %{typerdatadesc}", diff->origin, rr->state, rr->fqdn, rr->ttl, &rd);
#endif
                if((rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_ADD)
                {
                    // add
                    return true;
                }
                else if((rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE)) == ZONE_DIFF_RR_REMOVE)
                {
                    // remove
                    return true;
                }
            }
        }
    }

    return false;
}

void zone_diff_fqdn_rr_set_log(const zone_diff_fqdn_rr_set *rr_set, const uint8_t *origin, logger_handle_t *handle, int level)
{
    ptr_treemap_iterator_t rr_iter;

    // for all marked rr

    ptr_treemap_iterator_init(&rr_set->rr, &rr_iter);
    while(ptr_treemap_iterator_hasnext(&rr_iter))
    {
        ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
        zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->value;

        rdata_desc_t        rdatadesc = {rr->rtype, rr->rdata_size, rr->rdata};

        format_writer_t     temp_fw_0 = {zone_diff_record_state_format, &rr->state};

        logger_handle_msg_nocull(handle, level, LOG_TEXT_PREFIX "zone-diff: %{dnsname}: %{dnsname}: %03x: %w: %{dnsname} %i %{typerdatadesc}", origin, rr->fqdn, rr->state, &temp_fw_0, rr->fqdn, rr->ttl, &rdatadesc);
    }
}

void zone_diff_fqdn_log(const zone_diff_fqdn *diff_fqdn, const uint8_t *origin, logger_handle_t *handle, int level)
{
    if(!log_is_set(handle, level))
    {
        return;
    }

    // for all rrset

    const uint8_t *diff_fqdn_name = diff_fqdn->fqdn;

    if(origin == NULL)
    {
        origin = (const uint8_t *)"\004NULL";
    }

    format_writer_t temp_fw_1 = {zone_diff_fqdn_changes_format, diff_fqdn};

    logger_handle_msg_nocull(handle, level, LOG_TEXT_PREFIX "zone-diff: %{dnsname}: %{dnsname}: %w", origin, diff_fqdn_name, &temp_fw_1);

    // for all records

    u32_treemap_iterator_t rrset_iter;
    u32_treemap_iterator_init(&diff_fqdn->rrset, &rrset_iter);
    while(u32_treemap_iterator_hasnext(&rrset_iter))
    {
        u32_treemap_node_t    *rrset_node = u32_treemap_iterator_next_node(&rrset_iter);

        zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set *)rrset_node->value;

        if(rr_set == NULL)
        {
            log_debug("zone-diff: %{dnsname}: %{dnsname} has no record set", origin, diff_fqdn_name);
            continue;
        }

        format_writer_t temp_fw_1 = {zone_diff_fqdn_changes_format, diff_fqdn};
        logger_handle_msg_nocull(handle, level, LOG_TEXT_PREFIX "zone-diff: %{dnsname}: %{dnsname}: %w", origin, diff_fqdn_name, &temp_fw_1);

        zone_diff_fqdn_rr_set_log(rr_set, origin, handle, level);
    }
}

void zone_diff_log(const zone_diff *diff, logger_handle_t *handle, int level)
{
    if(!log_is_set(handle, level))
    {
        return;
    }

    ptr_treemap_iterator_t fqdn_iter;

    // for all fqdn

    ptr_treemap_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_treemap_iterator_hasnext(&fqdn_iter))
    {
        ptr_treemap_node_t *diff_fqdn_node = ptr_treemap_iterator_next_node(&fqdn_iter);
        zone_diff_fqdn     *diff_fqdn = (zone_diff_fqdn *)diff_fqdn_node->value;
        zone_diff_fqdn_log(diff_fqdn, diff->origin, handle, level);
    }
}

int zone_diff_check_changes(const zone_diff *diff, logger_handle_t *handle, int level)
{
    ptr_treemap_iterator_t fqdn_iter;

    int                    changes = 0;

    ptr_treemap_iterator_init(&diff->fqdn, &fqdn_iter);
    while(ptr_treemap_iterator_hasnext(&fqdn_iter))
    {
        ptr_treemap_node_t    *diff_fqdn_node = ptr_treemap_iterator_next_node(&fqdn_iter);
        zone_diff_fqdn        *diff_fqdn = (zone_diff_fqdn *)diff_fqdn_node->value;

        u32_treemap_iterator_t rrset_iter;
        u32_treemap_iterator_init(&diff_fqdn->rrset, &rrset_iter);
        while(u32_treemap_iterator_hasnext(&rrset_iter))
        {
            u32_treemap_node_t    *rrset_node = u32_treemap_iterator_next_node(&rrset_iter);

            zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set *)rrset_node->value;

            ptr_treemap_iterator_t rr_iter;

            ptr_treemap_iterator_init(&rr_set->rr, &rr_iter);
            while(ptr_treemap_iterator_hasnext(&rr_iter))
            {
                ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->value;

                if(!(rr->state & ZONE_DIFF_RR_AUTOMATED))
                {
                    if(rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE))
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

void zone_diff_sign_rrset(zone_diff *diff, zdb_zone_t *zone, ptr_vector_t *keys, ptr_vector_t *add, zone_diff_fqdn_rr_set *rr_set, zone_diff_fqdn_rr_set *rrsig_rr_set)
{
    ptr_vector_t       rrset = PTR_VECTOR_EMPTY;
    dnskey_signature_t ds;
    dnskey_signature_init(&ds);

    // setup the view for the RRSET (RRSET abstraction for the part that generates signatures)

    struct resource_record_view_s rrv = {NULL, &zone_diff_label_rr_rrv_vtbl};
    rrv.data = rr_set;

    ptr_vector_clear(&rrset);

    // const uint8_t* rr_fqdn = NULL;

    uint8_t rrsig_state_mask = ZONE_DIFF_RR_AUTOMATED;

    // accumulate records

    FOREACH_PTR_TREEMAP(void *, value, &rr_set->rr)
    {
        zone_diff_label_rr *rr = (zone_diff_label_rr *)value;
        // rr_fqdn = rr->fqdn;

        // if the RR will exist in the zone (A.K.A: not removed), add it to the collection to sign
        if((rr->state & ZONE_DIFF_RR_REMOVE) == 0)
        {
#if DEBUG
            rdata_desc_t    rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug2("update: %{dnsname}: covers %w %{dnsname} %9i %{typerdatadesc}%s", diff->origin, &temp_fw_0, rr->fqdn, rr->ttl, &rd, ((rr->state & ZONE_DIFF_RR_AUTOMATED) != 0) ? "<AUTOMATED>" : "");
#endif
            rrsig_state_mask &= rr->state;

            ptr_vector_append(&rrset, value);
        }
        else
        {
#if DEBUG
            rdata_desc_t    rd = {rr->rtype, rr->rdata_size, rr->rdata};
            format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
            log_debug2("update: %{dnsname}: ignore %w %{dnsname} %9i %{typerdatadesc}", diff->origin, &temp_fw_0, rr->fqdn, rr->ttl, &rd);
#endif
        }
    }

    for(int_fast32_t j = 0; j <= ptr_vector_last_index(keys); ++j)
    {
        dnskey_t *key = (dnskey_t *)ptr_vector_get(keys, j);

        // check if the key has private components

        if(!dnskey_is_private(key))
        {
            log_debug("update: %{dnsname}: key K%{dnsname}+%03d+%05d is not private", diff->origin, dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key));
            continue;
        }

        zone_diff_label_rr *rrsig_rr = NULL;

        ya_result           ret;

        int32_t             maxinterval = diff_generate_signature_interval(diff);

        // rrset_to_sign;
        if(ISOK(ret = dnskey_sign_rrset_with_maxinterval(key, &rrset, true, &rrv, maxinterval, (void **)&rrsig_rr)))
        {
            // add the key to the add set

            log_debug2("update: %{dnsname}: signed %{dnsname} %{dnstype} rrset with key %03d %05d", diff->origin, rrsig_rr->fqdn, &rr_set->rtype, dnskey_get_algorithm(key), dnskey_get_tag_const(key));

            int32_t signature_valid_until = rrsig_get_valid_until_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

            // if the signature expires in this time

            if(signature_valid_until > 0)
            {
                if(signature_valid_until < dnskey_get_inactive_epoch(key))
                {
                    int32_t signature_regeneration_time = signature_valid_until - diff->rrsig_validity_regeneration;

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
            zone_diff_label_rr *final_rrsig_rr = zone_diff_fqdn_rr_set_rr_add_get(rrsig_rr_set, rrsig_rr);
            if((final_rrsig_rr->state & ZONE_DIFF_RR_IN_ZONE) == 0)
            {
                ptr_vector_append(add, final_rrsig_rr);
            }
        }
        else
        {
            log_warn("update: %{dnsname}: failed to sign with key %03d %05d: %r", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key), ret);
            // ...
        }
    } // for each key
}

/**
 * Appends RRSIGs to remove/add vector, following the need-to-be-signed RR set, using keys from KSK and ZSK vectors.
 *
 * @param diff
 * @param rrset_to_sign_vector
 * @param ksks
 * @param zsks
 * @param remove
 * @param add
 */

ya_result zone_diff_sign(zone_diff *diff, zdb_zone_t *zone, ptr_vector_t *rrset_to_sign_vector, ptr_vector_t *ksks, ptr_vector_t *zsks, ptr_vector_t *remove, ptr_vector_t *add)
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
        for(int_fast32_t i = 1; i <= ptr_vector_last_index(rrset_to_sign_vector);)
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

    ptr_vector_t       rrset = PTR_VECTOR_EMPTY;
    dnskey_signature_t ds;
    dnskey_signature_init(&ds);

    // setup the view for the RRSET (RRSET abstraction for the part that generates signatures)

    struct resource_record_view_s rrv = {NULL, &zone_diff_label_rr_rrv_vtbl};

    // for each RRSET

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(rrset_to_sign_vector); ++i)
    {
        zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set *)ptr_vector_get(rrset_to_sign_vector, i);

        log_debug1("update: %{dnsname}: signing (trying) %{dnstype} rrset @%p", diff->origin, &rr_set->rtype, rr_set);

        rrv.data = rr_set;

        ptr_vector_clear(&rrset);

        uint8_t rrsig_state_mask = ZONE_DIFF_RR_AUTOMATED;

        // for each record in the RRSET

        const uint8_t *rr_fqdn = NULL;

        // accumulate records

        FOREACH_PTR_TREEMAP(void *, value, &rr_set->rr)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)value;
            rr_fqdn = rr->fqdn; // keep the fqdn from the first match

#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
            if(rr_set->rtype == TYPE_DNSKEY)
            {
                rdata_desc_t rd = {rr->rtype, rr->rdata_size, rr->rdata};
                log_info("update: %{dnsname}: [%03x] %{dnsname} %9i %{typerdatadesc}", diff->origin, rr->state, rr->fqdn, rr->ttl, &rd);
            }
#endif

            // if the RR will exist in the zone (A.K.A: not removed), add it to the collection to sign
            if(((rr->state & ZONE_DIFF_RR_REMOVE) == 0) || ((rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_TTL_UPDATED)) == (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_TTL_UPDATED)))
            {
#if DEBUG
                rdata_desc_t    rd = {rr->rtype, rr->rdata_size, rr->rdata};
                format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
                log_debug2("update: %{dnsname}: covers %w %{dnsname} %9i %{typerdatadesc}%s", diff->origin, &temp_fw_0, rr->fqdn, rr->ttl, &rd, ((rr->state & ZONE_DIFF_RR_AUTOMATED) != 0) ? "<AUTOMATED>" : "");
#endif
                rrsig_state_mask &= rr->state;

                ptr_vector_append(&rrset, value);
            }
            else
            {
#if DEBUG
                rdata_desc_t    rd = {rr->rtype, rr->rdata_size, rr->rdata};
                format_writer_t temp_fw_0 = {zone_diff_record_state_format, &rr->state};
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

                FOREACH_PTR_TREEMAP(void *, value, &rrsig_label_rrset->rr)
                {
                    zone_diff_label_rr *rrsig_rr = (zone_diff_label_rr *)value;

                    if(rrsig_get_type_covered_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size) == rr_set->rtype)
                    {
#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
                        if(rr_set->rtype == TYPE_DNSKEY)
                        {
                            rdata_desc_t rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                            log_info("update: %{dnsname}: will remove %{dnsname} %9i %{typerdatadesc}", diff->origin, rrsig_rr->fqdn, rrsig_rr->ttl, &rd);
                        }
#endif
                        if((rrsig_rr->state & ZONE_DIFF_RR_REMOVED) == 0)
                        {
                            rrsig_rr->state &= ~ZONE_DIFF_RR_ADD;
                            rrsig_rr->state |= ZONE_DIFF_RR_REMOVE;
#if DEBUG
                            rdata_desc_t rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
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

        bool          canonize = true;

        ptr_vector_t *keys;

        yassert(rr_set->rtype != TYPE_RRSIG);

        // use the adequate DNSKEY collection

        if(rr_set->rtype != TYPE_DNSKEY)
        {
            keys = zsks;
        }
        else
        {
            if(!ptr_vector_isempty(ksks))
            {
                keys = ksks;
            }
            else
            {
                keys = zsks;
            }
        }

        // for all keys from said collection

        for(int_fast32_t j = 0; j <= ptr_vector_last_index(keys); ++j)
        {
            dnskey_t *key = (dnskey_t *)ptr_vector_get(keys, j);

#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
            log_debug("update: considering key %{dnsname} %03d %05d", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
#endif

#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
            if(rr_set->rtype == TYPE_DNSKEY)
            {
                log_info("update: %{dnsname} DNSKEY cannot use key %03d %05d as it is not private", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
            }
#endif

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
                zone_diff_label_rr *rr = ptr_vector_get(&rrset, 0);

                log_debug2("update: %{dnsname}: %{dnsname} %{dnstype} does not need a signature update for key %03d %05d", diff->origin, rr->fqdn, &rr->rtype, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
#endif
                continue; // skip
            }

            // check if the key has private components

            if(!dnskey_is_private(key))
            {
#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
                if(rr_set->rtype == TYPE_DNSKEY)
                {
                    log_info("update: %{dnsname} DNSKEY cannot use key %03d %05d as it is not private", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                }
#endif
                log_debug("update: %{dnsname}: key K%{dnsname}+%03d+%05d is not private", diff->origin, dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                continue;
            }

            if(dnskey_is_deactivated(key, time(NULL) - 5)) // don't generate it if it's about to expire
            {
#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
                if(rr_set->rtype == TYPE_DNSKEY)
                {
                    log_info("update: %{dnsname} DNSKEY cannot use key %03d %05d as its deactivated", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                }
#endif
                log_debug("update: %{dnsname}: key K%{dnsname}+%03d+%05d is about to be deactivated", diff->origin, dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                continue;
            }

            zone_diff_label_rr *rrsig_rr = NULL;

            ya_result           ret;

            int32_t             maxinterval = diff_generate_signature_interval(diff);

            // rrset_to_sign;
            if(ISOK(ret = dnskey_sign_rrset_with_maxinterval(key, &rrset, canonize, &rrv, maxinterval, (void **)&rrsig_rr)))
            {
                canonize = false;

                // add the key to the add set

#if DYNUPDATE_DIFF_DETAILED_DNSKEY_LOG
                if(rr_set->rtype == TYPE_DNSKEY)
                {
                    log_info("update: %{dnsname} DNSKEY has been signed with key %03d %05d", diff->origin, dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key));
                }
#endif

                log_debug2("update: %{dnsname}: signed %{dnsname} %{dnstype} rrset with key %03d %05d", diff->origin, rrsig_rr->fqdn, &rr_set->rtype, dnskey_get_algorithm(key), dnskey_get_tag_const(key));

                int32_t signature_valid_until = rrsig_get_valid_until_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

                // if the signature expires in this time

                if(signature_valid_until > 0)
                {
                    if(signature_valid_until < dnskey_get_inactive_epoch(key))
                    {
                        int32_t signature_regeneration_time = signature_valid_until - diff->rrsig_validity_regeneration;

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
#if DEBUG
                {
                    rdata_desc_t rrsig_rr_desc = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                    log_debug6("update: %{dnsname}: signature <= %p [%03x] %{dnsname} %i %{typerdatadesc}", diff->origin, rrsig_rr, rrsig_rr->state, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_desc);
                }
#endif
                zone_diff_label_rr *final_rrsig_rr = zone_diff_fqdn_rr_set_rr_add_get(rrsig_label_rrset, rrsig_rr); // replace is right (should be unique)
#if DEBUG
                {
                    rdata_desc_t rrsig_rr_desc = {final_rrsig_rr->rtype, final_rrsig_rr->rdata_size, final_rrsig_rr->rdata};
                    log_debug6("update: %{dnsname}: signature => %p [%03x] %{dnsname} %i %{typerdatadesc}", diff->origin, final_rrsig_rr, final_rrsig_rr->state, final_rrsig_rr->fqdn, final_rrsig_rr->ttl, &rrsig_rr_desc);
                }
#endif
                if((final_rrsig_rr->state & ZONE_DIFF_RR_IN_ZONE) == 0)
                {
                    ptr_vector_append(add, final_rrsig_rr);

                    if(rrsig_label != NULL)
                    {
                        // int rrsig_count = 0;

                        FOREACH_PTR_TREEMAP(void *, value, &rrsig_label_rrset->rr)
                        {
                            zone_diff_label_rr *rrsig_rr = (zone_diff_label_rr *)value;

                            if((rrsig_rr->state & (ZONE_DIFF_RR_IN_ZONE | ZONE_DIFF_RR_REMOVE | ZONE_DIFF_RR_REMOVED)) == ZONE_DIFF_RR_IN_ZONE) // if the key is marked as being removed, no need to remove it
                                                                                                                                                // twice
                            {
                                // key is kept or added

                                uint16_t ctype = rrsig_get_type_covered_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size); // type covered by the signature
                                if(ctype == rr_set->rtype)
                                {
                                    uint16_t keytag = rrsig_get_key_tag_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

                                    if(keytag == dnskey_get_tag_const(key))
                                    {
                                        uint8_t keyalg = rrsig_get_algorithm_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

                                        if(keyalg == dnskey_get_algorithm(key))
                                        {
#if DEBUG
                                            rdata_desc_t rrsig_rr_desc = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                                            log_debug6("update: %{dnsname}: [%03x] %{dnsname} %i %{typerdatadesc} is obsolete", diff->origin, rrsig_rr->state, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_desc);
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
                //(void)rrsig_rr_set;
            }
            else
            {
                log_warn("update: %{dnsname}: failed to sign with key %03d %05d: %r", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key), ret);
                // ...
            }
        } // for each key

        // remove signatures not covered by an active key

        if(rrsig_label != NULL)
        {
            int rrsig_count = 0;
            int rrsig_known = 0;
            int rrsig_ignored = 0;

            FOREACH_PTR_TREEMAP(void *, value, &rrsig_label_rrset->rr)
            {
                ++rrsig_known;

                zone_diff_label_rr *rrsig_rr = (zone_diff_label_rr *)value;
#if DEBUG
                rdata_desc_t rrsig_rr_desc = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                log_debug6("update: %{dnsname}: [%03x] %{dnsname} %i %{typerdatadesc}", diff->origin, rrsig_rr->state, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_desc);
#endif
                if(rrsig_rr->state & ZONE_DIFF_RR_REMOVE) // if the key is marked as being removed, no need to remove it twice
                {
                    rrsig_label->rrsig_removed = 1;
                    continue;
                }

                // key is kept or added

                uint16_t ctype = rrsig_get_type_covered_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size); // type covered by the signature
                if(ctype == rr_set->rtype)
                {
                    uint16_t keytag = rrsig_get_key_tag_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);
                    uint8_t  keyalg = rrsig_get_algorithm_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

                    bool     keep = false;

                    ++rrsig_ignored;

                    for(int_fast32_t j = 0; j <= ptr_vector_last_index(keys); ++j)
                    {
                        const dnskey_t *key = (dnskey_t *)ptr_vector_get(keys, j);

                        if((dnskey_get_algorithm(key) == keyalg) && (dnskey_get_tag_const(key) == keytag))
                        {
                            --rrsig_ignored;
                            ++rrsig_count;
                            keep = true;
                            break;
                        }
                    }

                    if(keep)
                    {
                        if(rrsig_rr->state & ZONE_DIFF_RR_ADD)
                        {
                            rrsig_label->rrsig_added = 1; // new
                        }
                        else
                        {
                            rrsig_label->rrsig_kept = 1; // already in zone
                        }
                    }
                    else
                    {
#if DEBUG
                        rdata_desc_t rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
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

                log_warn(
                    "update: %{dnsname}: %{dnsname} %{dnstype} not covered by a signature (%i signatures in the set, "
                    "%i ignored for the type)",
                    diff->origin,
                    rr_fqdn,
                    &rr_set->rtype,
                    rrsig_known,
                    rrsig_ignored);

                if(rrsig_label != NULL)
                {
                    int rrsig_index = 0;
                    FOREACH_PTR_TREEMAP(void *, value, &rrsig_label_rrset->rr)
                    {
                        zone_diff_label_rr *rrsig_rr = (zone_diff_label_rr *)value;

                        rdata_desc_t        rrsig_record = {TYPE_RRSIG, rrsig_rr->rdata_size, rrsig_rr->rdata};
                        log_warn("update: %{dnsname}: %02i [%03x] %{dnsname} %5i %{typerdatadesc}", diff->origin, rrsig_index, rrsig_rr->state, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_record);
                        ++rrsig_index;
                    }
                }

                dnskey_signature_finalize(&ds);
                ptr_vector_finalise(&rrset);

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
    } // for(int_fast32_t i = 0; i <= ptr_vector_last_index(rrset_to_sign_vector); ++i) // FOR EACH RRSET

    dnskey_signature_finalize(&ds);
    ptr_vector_finalise(&rrset);

    return SUCCESS;
}

void zone_diff_label_state_flags_long_format(const void *value, output_stream_t *os, int32_t padding, char pad_char, bool left_justified, void *reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;

    static char separator[1] = {','};

    if(value == NULL)
    {
        return;
    }

    uint8_t state = *(uint8_t *)value;
    int     separator_size = 0;
    if(state & ZONE_DIFF_RR_ADD)
    {
        output_stream_write(os, "add", 3);
        separator_size = 1;
    }
    if(state & ZONE_DIFF_RR_REMOVE)
    {
        output_stream_write(os, separator, separator_size);
        output_stream_write(os, "remove", 6);
        separator_size = 1;
    }
    if(state & ZONE_DIFF_RR_RDATA_OWNED)
    {
        output_stream_write(os, separator, separator_size);
        output_stream_write(os, "owned", 5);
        separator_size = 1;
    }
    if(state & ZONE_DIFF_RR_VOLATILE)
    {
        output_stream_write(os, separator, separator_size);
        output_stream_write(os, "volatile", 8);
        separator_size = 1;
    }
    if(state & ZONE_DIFF_RR_IN_ZONE)
    {
        output_stream_write(os, separator, separator_size);
        output_stream_write(os, "inzone", 6);
        separator_size = 1;
    }
    if(state & ZONE_DIFF_RR_AUTOMATED)
    {
        output_stream_write(os, separator, separator_size);
        output_stream_write(os, "auto", 4);
        separator_size = 1;
    }
    if(state & ZONE_DIFF_RR_ADDED)
    {
        output_stream_write(os, separator, separator_size);
        output_stream_write(os, "added", 5);
        separator_size = 1;
    }
    if(state & ZONE_DIFF_RR_REMOVED)
    {
        output_stream_write(os, separator, separator_size);
        output_stream_write(os, "removed", 7);
    }
}

void zone_diff_store_diff_dnskey_get_keys(zone_diff *diff, ptr_vector_t *ksks, ptr_vector_t *zsks, int32_t regeneration_seconds)
{
    // remove all signing keys that are about to be removed
    // add all activated signing keys that are being added

    const zone_diff_fqdn        *apex = diff->apex;
    const zone_diff_fqdn_rr_set *dnskey_rrset = zone_diff_fqdn_rr_get_const(apex, TYPE_DNSKEY);

    if(dnskey_rrset != NULL)
    {
        // for all keys, handle added and removed ones

        time_t                 now = time(NULL);

        dnskey_t              *key;

        ptr_treemap_iterator_t rr_iter;
        ptr_treemap_iterator_init(&dnskey_rrset->rr, &rr_iter);
        while(ptr_treemap_iterator_hasnext(&rr_iter))
        {
            ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&rr_iter);
            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;
#if DEBUG
            format_writer_t state_flags = {zone_diff_label_state_flags_long_format, &rr->state};
            log_debug("maintenance: DNSKEY: 'K%{dnsname}+%03d+%05hd': key listed (%w)", diff->origin, dnskey_get_algorithm_from_rdata(rr->rdata), dnskey_get_tag_from_rdata(rr->rdata, rr->rdata_size), &state_flags);
#endif
            if((rr->state & ZONE_DIFF_RR_REMOVE) == 0) // exists or is being added
            {
                key = NULL;
                ya_result ret = dnssec_keystore_load_private_key_from_rdata(rr->rdata, rr->rdata_size, rr->fqdn, &key);

                if(ISOK(ret))
                {
                    ptr_vector_t *keys = NULL;

                    if(dnskey_get_flags(key) == DNSKEY_FLAGS_KSK)
                    {
                        keys = ksks;
                    }
                    else if(dnskey_get_flags(key) == DNSKEY_FLAGS_ZSK)
                    {
                        keys = zsks;
                    }
                    else
                    {
                        log_err("maintenance: DNSKEY: 'K%{dnsname}+%03d+%05hd': unexpected flags: %u",
                                diff->origin,
                                dnskey_get_algorithm_from_rdata(rr->rdata),
                                dnskey_get_tag_from_rdata(rr->rdata, rr->rdata_size),
                                htons(dnskey_get_flags(key)));
                        dnskey_release(key);
                        continue;
                    }

                    // if key is activated, and not already in the (signing) set, add it
#if DEBUG
                    log_debug("maintenance: DNSKEY: 'K%{dnsname}+%03d+%05hd': key found, exists or is about to be added", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
#endif
                    if(dnskey_is_activated_lenient(key, now, regeneration_seconds))
                    {
#if DEBUG
                        log_debug(
                            "maintenance: DNSKEY: 'K%{dnsname}+%03d+%05hd': private key is active (or will soon be) "
                            "(%T)",
                            diff->origin,
                            dnskey_get_algorithm(key),
                            dnskey_get_tag_const(key),
                            (uint32_t)dnskey_get_activate_epoch(key));
#endif

#if DEBUG
                        log_debug("maintenance: DNSKEY: 'K%{dnsname}+%03d+%05hd': private key added in signers", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
#endif
                        ptr_vector_append(keys, key);
                    }
                    else
                    {
#if DEBUG
                        log_debug("maintenance: DNSKEY: 'K%{dnsname}+%03d+%05hd': private key is not active (%T)", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key), (uint32_t)dnskey_get_activate_epoch(key));
#endif
                    }
                }
                else // key is being removed
                {
                    ya_result ret = dnssec_keystore_load_public_key_from_rdata(rr->rdata, rr->rdata_size, rr->fqdn, &key);

                    if(ISOK(ret))
                    {
#if DEBUG
                        log_debug("maintenance: DNSKEY: 'K%{dnsname}+%03d+%05hd': key found, private key not available", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
#endif
                        ptr_vector_t *keys = NULL;

                        if(dnskey_get_flags(key) == DNSKEY_FLAGS_KSK)
                        {
                            keys = ksks;
                        }
                        else if(dnskey_get_flags(key) == DNSKEY_FLAGS_ZSK)
                        {
                            keys = zsks;
                        }
                        else
                        {
                            log_err("maintenance: DNSKEY: 'K%{dnsname}+%03d+%05hd': unexpected flags: %u",
                                    diff->origin,
                                    dnskey_get_algorithm_from_rdata(rr->rdata),
                                    dnskey_get_tag_from_rdata(rr->rdata, rr->rdata_size),
                                    htons(dnskey_get_flags(key)));
                            dnskey_release(key);
                            continue;
                        }

#if DEBUG
                        log_debug("maintenance: DNSKEY: 'K%{dnsname}+%03d+%05hd': private key not loaded: %r", diff->origin, dnskey_get_algorithm_from_rdata(rr->rdata), dnskey_get_tag_from_rdata(rr->rdata, rr->rdata_size), ret);
#endif
                        ptr_vector_append(keys, key);
                    }
                    else // no private key and public record could not be loaded
                    {
                        log_err("maintenance: DNSKEY: 'K%{dnsname}+%03d+%05hd': public key not loaded: %r", diff->origin, dnskey_get_algorithm_from_rdata(rr->rdata), dnskey_get_tag_from_rdata(rr->rdata, rr->rdata_size), ret);
                    }
                }
            } // else key is being removed
        }

    } // else would be surprising

#if DEBUG
    for(int_fast32_t i = 0; i <= ptr_vector_last_index(ksks); ++i)
    {
        dnskey_t *key = (dnskey_t *)ptr_vector_get(ksks, i);
        log_debug3("maintenance: DNSKEY: KSK: 'K%{dnsname}+%03d+%05hd': final state", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
    }

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(zsks); ++i)
    {
        dnskey_t *key = (dnskey_t *)ptr_vector_get(zsks, i);
        log_debug3("maintenance: DNSKEY: ZSK: 'K%{dnsname}+%03d+%05hd': final state", diff->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
    }
#endif
}

static ya_result zone_diff_verify_dnskey_presence(zone_diff *diff, zdb_zone_t *zone, ptr_vector_t *rrset_to_sign, ptr_vector_t *ksks, ptr_vector_t *zsks)
{
    ya_result ret = SUCCESS;
    uint8_t   maintain_mode = zone_get_maintain_mode(zone);

    if(maintain_mode > ZDB_ZONE_MAINTAIN_NOSEC)
    {
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(ksks); ++i)
        {
            dnskey_t *key = (dnskey_t *)ptr_vector_get(ksks, i);
            log_debug3("update: DNSKEY: KSK: 'K%{dnsname}+%03d+%05hd': key visible", zone->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(zsks); ++i)
        {
            dnskey_t *key = (dnskey_t *)ptr_vector_get(zsks, i);
            log_debug3("update: DNSKEY: ZSK: 'K%{dnsname}+%03d+%05hd': key visible", zone->origin, dnskey_get_algorithm(key), dnskey_get_tag_const(key));
        }

        zone_diff_fqdn *apex = zone_diff_fqdn_get(diff, diff->origin);

        if(!zone_diff_will_have_rrset_type(apex, TYPE_DNSKEY))
        {
            log_err("update: %{dnsname}: there are no DNSKEY in the zone", zone->origin);
            ret = ZDB_ERROR_ZONE_NO_ACTIVE_DNSKEY_FOUND;
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(rrset_to_sign); ++i)
        {
            zone_diff_fqdn_rr_set *rr_set = (zone_diff_fqdn_rr_set *)ptr_vector_get(rrset_to_sign, i);

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

static ya_result zone_diff_store_diff(zone_diff *diff, zdb_zone_t *zone, ptr_vector_t *remove, ptr_vector_t *add)
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

    uint8_t      maintain_mode = zone_get_maintain_mode(zone);

    switch(maintain_mode)
    {
        case ZDB_ZONE_MAINTAIN_NSEC3:
        case ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:
        {
            dnssec_chain_init(&dc, (maintain_mode == ZDB_ZONE_MAINTAIN_NSEC3) ? dynupdate_nsec3_chain_get_vtbl() : dynupdate_nsec3_optout_chain_get_vtbl(), diff);

            nsec3_zone_t *n3 = zone->nsec.nsec3;

            while(n3 != NULL)
            {
                const uint8_t *nsec3param_rdata = n3->rdata;
                uint8_t        nsec3_chain_status = 0;
                nsec3_zone_get_status_from_rdata(zone, nsec3param_rdata, NSEC3PARAM_RDATA_SIZE_FROM_CHAIN(n3), &nsec3_chain_status);

                dnssec_chain_add_chain(&dc, (dnssec_chain_head_t)n3, (nsec3_chain_status & NSEC3_ZONE_REMOVING) != 0);
                n3 = n3->next;
            }
            break;
        }
        case ZDB_ZONE_MAINTAIN_NSEC:
        {
            uint8_t nsec_chain_status = 0;
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
        ptr_vector_t ksks = PTR_VECTOR_EMPTY;
        ptr_vector_t zsks = PTR_VECTOR_EMPTY;
        ptr_vector_t rrset_to_sign = PTR_VECTOR_EMPTY;

        // store changes in vectors and get the RR sets to sign

        int32_t mandatory_changes = zone_diff_get_changes(diff, &rrset_to_sign, &ksks, &zsks, remove, add, zone->sig_validity_regeneration_seconds);

#if DYNUPDATE_DIFF_DETAILED_LOG
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(remove, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug3("update: changes: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(add, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

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
                for(int_fast32_t i = 0; i <= ptr_vector_last_index(remove); ++i)
                {
                    zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(remove, i);
                    rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

                    log_debug3("update: sign: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                }

                for(int_fast32_t i = 0; i <= ptr_vector_last_index(add); ++i)
                {
                    zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(add, i);
                    rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

                    log_debug3("update: sign: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                }
#endif

                ptr_vector_finalise(&rrset_to_sign);

                if(ISOK(ret))
                {
                    zone_diff_get_chain_changes(diff, &dc);

                    // chain deletes should use the existing maps if possible (speed) or generate from the local state
                    // (all 'exists') chain adds should use the local state (all exists not removed + all adds)
#if DEBUG
                    zone_diff_log(diff, MODULE_MSG_HANDLE, MSG_DEBUG2);
#endif
                    dnssec_chain_store_diff(&dc, diff, &zsks, remove, add);

#if DYNUPDATE_DIFF_DETAILED_LOG
                    for(int_fast32_t i = 0; i <= ptr_vector_last_index(remove); ++i)
                    {
                        zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(remove, i);
                        rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

                        log_debug3("update: store: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                    }

                    for(int_fast32_t i = 0; i <= ptr_vector_last_index(add); ++i)
                    {
                        zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(add, i);
                        rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

                        log_debug3("update: store: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
                    }
#endif
                }
            }
            else
            {
                zone_diff_label_rr_vector_clear(remove);
                zone_diff_label_rr_vector_clear(add);
                ptr_vector_finalise(&rrset_to_sign);
            }
        }
        else
        {
            zone_diff_label_rr_vector_clear(remove);
            zone_diff_label_rr_vector_clear(add);
            ptr_vector_finalise(&rrset_to_sign);

            if(FAIL(mandatory_changes))
            {
                log_warn("update: %{dnsname} update rejected: %r", zone->origin, mandatory_changes);
            }
        }

        dnssec_keystore_release_keys_from_vector(&zsks);
        dnssec_keystore_release_keys_from_vector(&ksks);

        ptr_vector_finalise(&zsks);
        ptr_vector_finalise(&ksks);
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

ya_result dynupdate_diff_load_private_keys(zdb_zone_t *zone)
{
    ya_result return_code = SUCCESS;

    // ensure all the private keys are available or servfail

    const zdb_resource_record_set_t *dnskey_rrset = zdb_zone_get_dnskey_rrset(zone); // zone is locked

    int                              ksk_count = 0;
    int                              zsk_count = 0;

    if(dnskey_rrset != NULL)
    {
        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(dnskey_rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *dnskey_record = zdb_resource_record_set_const_iterator_next(&iter);

            uint16_t                          flags = DNSKEY_FLAGS(dnskey_record);
            uint8_t                           algorithm = DNSKEY_ALGORITHM(dnskey_record);
            uint16_t                          tag = DNSKEY_TAG(dnskey_record); // note: expensive
            dnskey_t                         *key = NULL;

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
            else
            {
                // not a KSK nor a ZSK
            }
        }

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

ya_result dynupdate_diff_write_to_journal_and_replay(zdb_zone_t *zone, uint8_t secondary_lock, ptr_vector_t *del_vector, ptr_vector_t *add_vector)
{
    ya_result ret = 0;

    bool      changes_occurred = (ptr_vector_size(add_vector) + ptr_vector_size(del_vector)) > 2;

    if(changes_occurred)
    {
        // instead of storing to a buffer and back, could write an inputstream
        // translating the ptr_vector_t content on the fly

        int32_t total_size_in_bytes = 0;

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(del_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(del_vector, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug2("update: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);

            total_size_in_bytes += dnsname_len(rr->fqdn);
            total_size_in_bytes += 10;
            total_size_in_bytes += rr->rdata_size;
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(add_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(add_vector, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug2("update: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);

#if DEBUG
            switch(rr->rtype)
            {
                case TYPE_NSEC:
                {
                    const uint8_t *fqdn = rr->rdata;
                    const uint8_t *tbm = &fqdn[dnsname_len(fqdn)];

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

        output_stream_t baos;

        bytearray_output_stream_init(&baos, NULL, total_size_in_bytes);

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(del_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(del_vector, i);

            output_stream_write_dnsname(&baos, rr->fqdn);
            output_stream_write_u16(&baos, rr->rtype);
            output_stream_write_u16(&baos, rr->rclass);
            output_stream_write_nu32(&baos, rr->org_ttl);
            output_stream_write_nu16(&baos, rr->rdata_size);
            output_stream_write(&baos, rr->rdata, rr->rdata_size);

            if((rr->state & ZONE_DIFF_RR_VOLATILE) != 0)
            {
                zone_diff_label_rr_delete(rr);
            }
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(add_vector); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(add_vector, i);

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

        input_stream_t bais;

        bytearray_input_stream_init(&bais, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos), false);

        log_debug("update: %{dnsname}: acquiring journal", zone->origin);

        journal *jnl = NULL;
        if(ISOK(ret = journal_acquire_from_zone_ex(&jnl, zone, true)))
        {
            jnl->vtbl->minimum_serial_update(jnl, zone->text_serial);

            uint32_t journal_max_size = zone->wire_size / 3;
            zdb_zone_info_get_zone_max_journal_size(zone->origin, &journal_max_size);
            jnl->vtbl->maximum_size_update(jnl, journal_max_size);

            if(ISOK(ret = journal_append_ixfr_stream(jnl, &bais))) // writes a single page
            {
                log_debug("update: %{dnsname}: wrote %i bytes to the journal", zone->origin, total_size_in_bytes);

                bytearray_input_stream_reset(&bais);

                uint32_t current_serial = 0;

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
                log_info(
                    "update: %{dnsname}: could not write %i bytes to the journal as it is full and the zone needs to "
                    "be locally stored first",
                    zone->origin,
                    total_size_in_bytes);
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

ya_result dynupdate_diff(zdb_zone_t *zone, dns_packet_reader_t *reader, uint16_t count, uint8_t secondary_lock, uint32_t flags)
{
    yassert(zdb_zone_islocked(zone));
    const bool dryrun = (flags & DYNUPDATE_DIFF_DRYRUN) != 0;
    const bool external = (flags & DYNUPDATE_DIFF_EXTERNAL) != 0;

#if DEBUG
    log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i)", zone->origin, zone, reader, count, secondary_lock, dryrun);
#endif

    if(zdb_zone_invalid(zone))
    {
#if DEBUG
        log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with ZDB_ERROR_ZONE_INVALID", zone->origin, zone, reader, count, secondary_lock, dryrun);
#endif
        return ZDB_ERROR_ZONE_INVALID;
    }

    if(count == 0)
    {
#if DEBUG
        log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) success with count == 0", zone->origin, zone, reader, count, secondary_lock, dryrun);
#endif
        return SUCCESS;
    }

    if(dns_packet_reader_opcode(reader) != (OPCODE_UPDATE >> OPCODE_SHIFT))
    {
#if DEBUG
        log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) not an update message", zone->origin, zone, reader, count, secondary_lock, dryrun);
#endif
        return INVALID_STATE_ERROR;
    }

    // if the status was already set, stop

    if((zdb_zone_set_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF) & ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF) != 0)
    {
        return INVALID_STATE_ERROR; // already
    }

    int32_t                     soa_ttl;
    zdb_resource_record_data_t *soa = zdb_resource_record_sets_find_soa_and_ttl(&zone->apex->resource_record_set, &soa_ttl);

    if(soa == NULL)
    {
#if DEBUG
        log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with ZDB_ERROR_NOSOAATAPEX", zone->origin, zone, reader, count, secondary_lock, dryrun);
#endif

        zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

        return ZDB_ERROR_NOSOAATAPEX;
    }

#if DEBUG
    {
        uint32_t soa_serial = 0;
        rr_soa_get_serial(zdb_resource_record_data_rdata(soa), zdb_resource_record_data_rdata_size(soa), &soa_serial);
        log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) from serial %u", zone->origin, zone, reader, count, secondary_lock, dryrun, soa_serial);
    }
#endif

    zone_diff diff;
    zone_diff_init(&diff, zone, zdb_zone_get_rrsig_push_allowed(zone));

    dnsname_vector_t name_path;

#if DEBUG
    memset(&name_path, 0xff, sizeof(name_path));
#endif

    uint8_t *rname;
    uint8_t *rdata;
    // uint32_t rname_size;
    uint32_t  rttl;
    ya_result ret; // = SUCCESS;
    ya_result ret_status = 0;
    // int32_t zsk_key_update_mask = 0;
    uint16_t rtype;
    uint16_t rclass;
    uint16_t rdata_size;
    int8_t   has_valid_ksk = -1; // unknown (don't care yet)

    uint8_t  wire[DOMAIN_LENGTH_MAX + 10 + 65535];

#if DEBUG
    // rdata = (uint8_t*)~0; // DEBUG
    // rname_size = ~0; // DEBUG
    // rttl = ~0;       // DEBUG
    rtype = ~0;  // DEBUG
    rclass = ~0; // DEBUG
    // rdata_size = ~0; // DEBUG
#endif

    bool changes_occurred = false;

#if ZDB_HAS_DNSSEC_SUPPORT
    // zone load private keys

    bool dnssec_zone = zdb_zone_is_maintained(zone);
    bool check_for_last_nsec3param_removal = false;

    if(dnssec_zone)
    {
        dynupdate_diff_load_private_keys(zone);
    }
#endif

    log_debug1("update: %{dnsname}: reading message", zone->origin);

    // marks the SOA as being automatically removed (as the serial will increase)

    zone_diff_record_remove_automated(&diff, zone->apex, zone->origin, TYPE_SOA, soa_ttl, zdb_resource_record_data_rdata_size(soa), zdb_resource_record_data_rdata(soa));

    int record_index = 0;

    do
    {
        uint8_t *p = wire;
        int      s = sizeof(wire);

        if(FAIL(ret = dns_packet_reader_read_fqdn(reader, p, s)))
        {
            log_err("update: %{dnsname}: failed reading next record fqdn: %r", zone->origin, ret);

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed at fqdn with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }

        rname = p;
        // rname_size = ret;
        p += ret;
        s -= ret;

        if(!dnsname_locase_verify_charspace(rname))
        {
            log_err("update: %{dnsname}: fqdn contains illegal characters", zone->origin);
            log_memdump(MODULE_MSG_HANDLE, MSG_ERR, rname, dnsname_len(rname), 32);

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif

            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }

        if(!dnsname_is_subdomain(rname, zone->origin))
        {
            log_err("update: %{dnsname}: %{dnsname} is not a sub-domain", zone->origin, rname);

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_NOTZONE));
#endif
            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_NOTZONE);
        }

        if((ret = dns_packet_reader_read(reader, p, 10)) != 10)
        {
            ret = UNEXPECTED_EOF;

            log_err("update: %{dnsname}: failed reading next record fields: %r", zone->origin, ret);

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif

            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }

        rtype = GET_U16_AT(p[0]);
        rclass = GET_U16_AT(p[2]);
        rttl = ntohl(GET_U32_AT(p[4]));
        rdata_size = ntohs(GET_U16_AT(p[8]));

        /**
         * Some records are used internally by yadifad to track chain creation states.
         * They shouldn't be received externally (e.g. DNS dynamic update) as it could wreak havoc with the logic.
         * This change avoids having to handle a legion of pitfalls.
         *
         * In the future, we may give the option to change the value of these 3 records at build time.
         * It may be useful for some specific use cases.
         * Alternatively, we may document how to change their value manually.
         */

        if(external)
        {
            switch(rtype)
            {
                case TYPE_NSECCHAINSTATE:
                case TYPE_NSEC3CHAINSTATE:
                case TYPE_NSEC3PARAMQUEUED:
                {
                    log_err("update: %{dnsname}: reserved record found in update message: %r", zone->origin, ret);
                    zone_diff_finalize(&diff);
                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                    return RCODE_ERROR_CODE(RCODE_REFUSED);
                }
            }
        }

        if((rdata_size > 0) && (rclass == CLASS_ANY))
        {
            log_err("update: %{dnsname}: next record has non-empty rdata with class ANY: %r", zone->origin, RCODE_ERROR_CODE(RCODE_FORMERR));

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }

        /*
         * Simple consistency test:
         */

        if((rdata_size == 0) && (rclass != CLASS_ANY))
        {
            log_err("update: %{dnsname}: next record has empty rdata with non-ANY class: %r", zone->origin, RCODE_ERROR_CODE(RCODE_FORMERR));

            zone_diff_finalize(&diff);

#if DEBUG
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }

        if(rdata_size > 0)
        {
            if(FAIL(ret = dns_packet_reader_read_rdata(reader, rtype, rdata_size, p, s)))
            {
                log_err("update: %{dnsname}: failed reading next record rdata: %r", zone->origin, ret);

                zone_diff_finalize(&diff);

#if DEBUG
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                return RCODE_ERROR_CODE(RCODE_FORMERR);
            }

            rdata = p;
            rdata_size = ret;

            rdata_desc_t wire_rdatadesc = {rtype, rdata_size, rdata};
            log_debug1("update: %{dnsname}: record [%2i]: %{dnsname} %i %{dnsclass} %{dnstype} %{rdatadesc}", zone->origin, record_index, rname, rttl, &rclass, &rtype, &wire_rdatadesc);
        }
        else
        {
            rdata = NULL;

            log_debug1("update: %{dnsname}: record [%2i]: %{dnsname} %i %{dnsclass} %{dnstype}", zone->origin, record_index, rname, rttl, &rclass, &rtype);
        }

        ++record_index;

        dnsname_to_dnsname_vector(rname, &name_path);

        int32_t idx;

        for(idx = 0; idx < zone->origin_vector.size; idx++)
        {
            if(!dnslabel_equals(zone->origin_vector.labels[zone->origin_vector.size - idx], name_path.labels[name_path.size - idx]))
            {
                log_err("update: %{dnsname}: %{dnsname} manual add/del of %{dnstype} records refused", zone->origin, rname, &rtype);

                zone_diff_finalize(&diff);
#if DEBUG
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_NOTZONE));
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
            log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
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

            if(zdb_zone_has_nsec_chain(zone))
            {
                // don't add/del NSEC3PARAM on a zone that is not already NSEC3 (it works if the zone is not secure but
                // only if the zone has keys already. So for now : disabled)
                log_err("update: %{dnsname}: %{dnsname} NSEC3PARAM add/del refused on an non-dnssec3 zone", zone->origin, rname);

                zone_diff_finalize(&diff);

#if DEBUG
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
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
                    log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_NOTIMP));
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
                    log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
#endif
                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                    return RCODE_ERROR_CODE(RCODE_REFUSED);
                }
                else if(rclass == CLASS_NONE) // remove one
                {
                    /// @note important: don't remove the first NSEC3PARAM from an NSEC3 zone if no other is available
                    ///       also note that given the new mechanisms, an NSEC3PARAM being added will not count as one
                    ///       until the whole chain has been created This condition is tested later.

                    check_for_last_nsec3param_removal = true;

                    ret_status |= DYNUPDATE_DIFF_RETURN_NSEC3PARAM;
                    zdb_zone_set_status(zone, ZDB_ZONE_STATUS_GENERATE_CHAIN);
                }
                else // add one
                {
                    assert(rdata != NULL);

                    // scan-build false positive : assumes rdata_size < 0 => impossible
                    //                                  or ((rdata_size == 0) & (rclass == CLASS_ANY)) => this would
                    //                                  branch in the first "if" a few lines above
                    /*
                    ret = nsec3_zone_set_status(zone, ZDB_ZONE_MUTEX_DYNUPDATE, NSEC3PARAM_RDATA_ALGORITHM(rdata), 0,
                    NSEC3PARAM_RDATA_ITERATIONS(rdata), NSEC3PARAM_RDATA_SALT(rdata), NSEC3PARAM_RDATA_SALT_LEN(rdata),
                    NSEC3_ZONE_ENABLED|NSEC3_ZONE_GENERATING);
                    */
#if DYNUPDATE_DIFF_DO_NOT_ADD_NSEC3_ON_NON_NSEC3_ZONE
                    ret = 0; // nsec3_zone_set_status recursively calls to dynupdate_diff : don't do it here.
                    continue;
#else
                    bool                       nsec3param_exists = false;
                    zdb_resource_record_set_t *nsec3param_rrset;
                    nsec3param_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_NSEC3PARAM);
                    zdb_resource_record_set_iterator iter;
                    zdb_resource_record_set_iterator_init(nsec3param_rrset, &iter);
                    while(zdb_resource_record_set_iterator_has_next(&iter))
                    {
                        zdb_resource_record_data_t *rrdata = zdb_resource_record_set_iterator_next(&iter);
                        if(rdata_size == zdb_resource_record_data_rdata_size(rrdata))
                        {
                            if(memcmp(rdata, zdb_resource_record_data_rdata(rrdata), rdata_size) == 0)
                            {
                                // found
                                nsec3param_exists = true;
                                break;
                            }
                        }
                    }

                    if(!nsec3param_exists)
                    {
                        rtype = TYPE_NSEC3PARAMQUEUED;
                        ret_status |= DYNUPDATE_DIFF_RETURN_NSEC3PARAM;
                        zdb_zone_set_status(zone, ZDB_ZONE_STATUS_GENERATE_CHAIN);
                    }
#endif
                }
            }
        } // type == TYPE_NSEC3PARAM
        else if(((rtype == TYPE_NSEC3PARAMQUEUED) || (rtype == TYPE_NSEC3CHAINSTATE)) && (rdata != NULL))
        {
            uint16_t expected_rdata_size = NSEC3PARAM_RDATA_SIZE_FROM_SALT(NSEC3PARAM_RDATA_SALT_LEN(rdata));

            if(rtype == TYPE_NSEC3CHAINSTATE)
            {
                ++expected_rdata_size;
                /// @todo 20211202 edf -- check the status byte (last one in the rdata) makes sense
            }

            if(rdata_size != expected_rdata_size)
            {
                log_warn("update: %{dnsname}: %{dnsname} %{dnstype} has as a size of %d when it should be %d", zone->origin, rname, &rtype, rdata_size, expected_rdata_size);
                zone_diff_finalize(&diff);
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);
                return RCODE_ERROR_CODE(RCODE_NOTIMP);
            }

            // check the content is looking like an NSEC3PARAM
            if(NSEC3PARAM_RDATA_ALGORITHM(rdata) != NSEC3_DIGEST_ALGORITHM_SHA1)
            {
                log_warn("update: %{dnsname}: %{dnsname} %{dnstype} with unsupported digest algorithm %d", zone->origin, rname, &rtype, NSEC3PARAM_RDATA_ALGORITHM(rdata));
                zone_diff_finalize(&diff);
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);
                return RCODE_ERROR_CODE(RCODE_NOTIMP);
            }

            if(NSEC3PARAM_RDATA_FLAGS(rdata) > 1)
            {
                log_warn("update: %{dnsname}: %{dnsname} %{dnstype} with unsupported flags %d", zone->origin, rname, &rtype, NSEC3PARAM_RDATA_FLAGS(rdata));
                zone_diff_finalize(&diff);
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);
                return RCODE_ERROR_CODE(RCODE_NOTIMP);
            }

            /// @todo 20211202 edf -- check if there are operations about this record going on and maybe reject this
            /// update because of it
        }

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
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);
                return RCODE_ERROR_CODE(RCODE_FORMERR);
            }

            if(name_path.size <= zone->origin_vector.size)
            {
                if((rtype == TYPE_SOA) || (rtype == TYPE_ANY))
                {
                    // refused
                    log_err("update: %{dnsname}: refused", zone->origin);
                    zone_diff_finalize(&diff);
#if DEBUG
                    log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
#endif
                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                    return RCODE_ERROR_CODE(RCODE_REFUSED);
                }

                if(rtype == TYPE_DNSKEY)
                {
                    uint16_t key_flags = DNSKEY_FLAGS_FROM_RDATA(rdata); // scan-build false positive
                                                                         // (rdata == NULL) && (rdata_size == 0) can only occur if (rclass == CLASS_ANY)
                                                                         // the condition is tested and exited for a FORMERR around line 5557

                    if(key_flags == DNSKEY_FLAGS_ZSK)
                    {
                        ret_status |= DYNUPDATE_DIFF_RETURN_DNSKEY_REMOVED;
                    }

                    if(has_valid_ksk < 0)
                    {
                        has_valid_ksk = dnssec_keystore_has_usable_ksk(zone->origin, time(NULL)) ? 1 : 0;
                    }
                }
            }

#if DEBUG
            log_debug("update: %{dnsname}: delete %{dnsname} %{dnstype} any", zone->origin, rname, &rtype);
#endif
            zdb_rr_label_t *rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - zone->origin_vector.size) - 1);
            if(rr_label != NULL)
            {
#if DEBUG
                if(RR_LABEL_IRRELEVANT(rr_label)) // debug
                {
                    log_debug("update: %{dnsname}: %{dnsname} is irrelevant (0)", zone->origin, rname);
                }
#endif
                zdb_resource_record_set_const_t *rr_set;
                if((rr_set = (zdb_resource_record_set_const_t *)zdb_resource_record_sets_find(&rr_label->resource_record_set, rtype)) != NULL)
                {
                    bool                                   exists = false;

                    zdb_resource_record_set_const_iterator iter;
                    zdb_resource_record_set_const_iterator_init(rr_set, &iter);
                    while(zdb_resource_record_set_const_iterator_has_next(&iter))
                    {
                        const zdb_resource_record_data_t *record = zdb_resource_record_set_const_iterator_next(&iter);

                        if(zdb_resource_record_data_rdata_size(record) == rdata_size)
                        {
                            // scan-build false positive : rdata cannot be NULL
                            // (rdata == NULL) && (rdata_size == 0) can only occur if (rclass == CLASS_ANY)
                            // the condition is tested and exited for a FORMERR around line 5557

                            if(memcmp(zdb_resource_record_data_rdata_const(record), rdata, rdata_size) == 0)
                            {
                                exists = true;
                                break;
                            }
                        }
                    }

                    if(exists)
                    {
                        if(rr_label != zone->apex)
                        {
                            zone_diff_add_fqdn_children(&diff, rname, rr_label);
                            zone_diff_add_fqdn_parents_up_to_below_apex(&diff, rname, zone);
                        }
                        if(!zone_diff_record_remove_existing(&diff, rr_label, rname, rtype, rttl, rdata_size, rdata))
                        {
                            rdata_desc_t rd = {rtype, rdata_size, rdata};
                            log_warn("update: %{dnsname}: delete %{dnsname} %{typerdatadesc} not in zone", zone->origin, rname, &rd);
                        }
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
                log_err("update: %{dnsname}: format error", zone->origin);

                zone_diff_finalize(&diff);
#if DEBUG
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_FORMERR));
#endif
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                return RCODE_ERROR_CODE(RCODE_FORMERR);
            }

            if(name_path.size <= zone->origin_vector.size)
            {
                if((rtype == TYPE_SOA) || (rtype == TYPE_ANY))
                {
                    // refused
                    log_err("update: %{dnsname}: refused", zone->origin);
                    zone_diff_finalize(&diff);
#if DEBUG
                    log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
#endif
                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                    return RCODE_ERROR_CODE(RCODE_REFUSED);
                }

                if(rtype == TYPE_DNSKEY)
                {
                    // get all keys from the zone_diff
                    // if one of these keys is a ZSK, set the ret_status flag accordingly

                    const zone_diff_fqdn        *apex = zone_diff_fqdn_get_const(&diff, zone->origin);
                    const zone_diff_fqdn_rr_set *dnskey_rrset = zone_diff_fqdn_rr_get_const(apex, TYPE_DNSKEY);

                    if(dnskey_rrset != NULL)
                    {
                        ptr_treemap_iterator_t rr_iter;

                        ptr_treemap_iterator_init(&dnskey_rrset->rr, &rr_iter);

                        while(ptr_treemap_iterator_hasnext(&rr_iter))
                        {
                            ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
                            zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->value;
                            if((rr->state & ZONE_DIFF_RR_IN_ZONE) != 0)
                            {
                                uint16_t key_flags = DNSKEY_FLAGS_FROM_RDATA(rr->rdata);
                                if(key_flags == DNSKEY_FLAGS_ZSK)
                                {
                                    ret_status |= DYNUPDATE_DIFF_RETURN_DNSKEY_REMOVED;
                                }

                                if(has_valid_ksk < 0)
                                {
                                    has_valid_ksk = dnssec_keystore_has_usable_ksk(zone->origin, time(NULL)) ? 1 : 0;
                                }

                                diff.may_add_dnskey = true;
                                break;
                            }
                        }

                        diff.may_remove_dnskey = true;

                        if(has_valid_ksk < 0)
                        {
                            has_valid_ksk = dnssec_keystore_has_usable_ksk(zone->origin, time(NULL)) ? 1 : 0;
                        }
                    }
                    else
                    {
                        diff.may_remove_dnskey = false;
                        has_valid_ksk = false;
                    }
                }
            }

            if(rtype != TYPE_ANY)
            {
                // delete an rrset

#if DEBUG
                log_debug2("update: %{dnsname}: delete %{dnsname} %{dnstype} ...", zone->origin, rname, &rtype);
#endif
                zdb_rr_label_t *rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - zone->origin_vector.size) - 1);
                if(rr_label != NULL)
                {
#if DEBUG
                    if(RR_LABEL_IRRELEVANT(rr_label)) // debug
                    {
                        log_debug2("update: %{dnsname}: %{dnsname} is irrelevant (1)", zone->origin, rname);
                    }
#endif
                    if(zdb_resource_record_sets_has_type(&rr_label->resource_record_set, rtype))
                    {
                        if(rr_label != zone->apex)
                        {
                            zone_diff_add_fqdn_children(&diff, rname, rr_label);
                            zone_diff_add_fqdn_parents_up_to_below_apex(&diff, rname, zone);
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
                zdb_rr_label_t *rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - zone->origin_vector.size) - 1);
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
                        zone_diff_add_fqdn_children(&diff, rname, rr_label);
                        zone_diff_add_fqdn_parents_up_to_below_apex(&diff, rname, zone);
                        zone_diff_record_remove_all_sets(&diff, rr_label, rname);
                    }
                    else
                    {
                        // apex

                        log_err("update: %{dnsname}: removing all records from the apex is forbidden", zone->origin);

                        zone_diff_finalize(&diff);

#if DEBUG
                        log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
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

            zdb_rr_label_t *rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - zone->origin_vector.size) - 1);
            zone_diff_record_add(&diff, rr_label, rname, rtype, rttl, rdata_size, rdata);

            const uint8_t *above_fqdn = rname;
            for(int_fast32_t index = 1; index < name_path.size; ++index)
            {
                zdb_rr_label_t *above_rr_label = zdb_rr_label_find_exact(zone->apex, name_path.labels + index, (name_path.size - index - zone->origin_vector.size) - 1);
                above_fqdn += above_fqdn[0] + 1;
                zone_diff_fqdn_add(&diff, above_fqdn, above_rr_label);
            }

            if(rr_label != NULL)
            {
                if(rr_label != zone->apex)
                {
                    zone_diff_add_fqdn_children(&diff, rname, rr_label);
                    zone_diff_add_fqdn_parents_up_to_below_apex(&diff, rname, zone);
                }
                else
                {
                    if(rtype == TYPE_DNSKEY)
                    {
                        uint16_t key_flags = DNSKEY_FLAGS_FROM_RDATA(rdata);
                        if(key_flags == DNSKEY_FLAGS_ZSK)
                        {
                            ret_status |= DYNUPDATE_DIFF_RETURN_DNSKEY_ADDED;
                        }

                        diff.may_add_dnskey = true;
                    }
                }
            }
        }
    } while(--count > 0);

    if(check_for_last_nsec3param_removal)
    {
        bool at_least_one_nsec3param_remains = false;

        // look if there is any NSEC3PARAM remaining in the zone
        const zone_diff_fqdn        *apex = zone_diff_fqdn_get_const(&diff, zone->origin);
        const zone_diff_fqdn_rr_set *nsec3param_rrset = zone_diff_fqdn_rr_get_const(apex, TYPE_NSEC3PARAM);

        if(nsec3param_rrset != NULL)
        {
            ptr_treemap_iterator_t rr_iter;

            ptr_treemap_iterator_init(&nsec3param_rrset->rr, &rr_iter);

            while(ptr_treemap_iterator_hasnext(&rr_iter))
            {
                ptr_treemap_node_t *rr_node = ptr_treemap_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)rr_node->value;
                if((rr->state & (ZONE_DIFF_RR_ADD | ZONE_DIFF_RR_REMOVE)) != ZONE_DIFF_RR_REMOVE)
                {
                    at_least_one_nsec3param_remains = true;
                    break;
                }
            }

            if(!at_least_one_nsec3param_remains)
            {
                log_err("update: %{dnsname}: %{dnsname} cannot remove the last NSEC3PARAM of an NSEC3 zone", zone->origin, rname);

                zone_diff_finalize(&diff);

#if DEBUG
                log_err("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) failed with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, RCODE_ERROR_CODE(RCODE_REFUSED));
#endif
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

                return RCODE_ERROR_CODE(RCODE_REFUSED);
            }

            // remove the record, create the removal placeholder
        }
        // else there was no NSEC3PARAM to begin with
    }

    if(ISOK(ret) && !dryrun)
    {
        ptr_vector_t add = PTR_VECTOR_EMPTY;
        ptr_vector_t del = PTR_VECTOR_EMPTY;

#if DEBUG
        log_debug1("update: %{dnsname}: storing diff", zone->origin);
        zone_diff_log(&diff, MODULE_MSG_HANDLE, MSG_DEBUG2);
#endif
        if(ISOK(ret = zone_diff_store_diff(&diff, zone, &del, &add)))
        {
            zdb_zone_error_status_clear(zone, ZDB_ZONE_ERROR_STATUS_DIFF_FAILEDNOUSABLE_KEYS);

#if DEBUG
            log_debug1("update: %{dnsname}: stored diff", zone->origin);

            for(int_fast32_t i = 0; i <= ptr_vector_last_index(&del); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&del, i);
                rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};
                log_debug1("update: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
            }

            for(int_fast32_t i = 0; i <= ptr_vector_last_index(&add); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&add, i);
                rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};
                log_debug1("update: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
            }
#endif

            changes_occurred = (ptr_vector_size(&add) + ptr_vector_size(&del)) > 2;

#if DEBUG
            log_debug1("update: %{dnsname}: changes: %i", zone->origin, changes_occurred);
#endif

            if(changes_occurred)
            {
                // @note edf 20230926 -- this is the part where the final records are being written into the journal

                // instead of storing to a buffer and back, could write an inputstream
                // translating the ptr_vector_t content on the fly

                int32_t total = 0;

                for(int_fast32_t i = 0; i <= ptr_vector_last_index(&del); ++i)
                {
                    zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&del, i);
                    rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

                    log_debug2("update: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->org_ttl, &rd);

                    total += dnsname_len(rr->fqdn);
                    total += 10;
                    total += rr->rdata_size;
                }

                for(int_fast32_t i = 0; i <= ptr_vector_last_index(&add); ++i)
                {
                    zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&add, i);
                    rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

                    log_debug2("update: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);

                    total += dnsname_len(rr->fqdn);
                    total += 10;
                    total += rr->rdata_size;
                }

                output_stream_t baos;

                bytearray_output_stream_init(&baos, NULL, total);

                for(int_fast32_t i = 0; i <= ptr_vector_last_index(&del); ++i)
                {
                    zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&del, i);
#if 0
                    rdata_desc_t rd = {rr->rtype, rr->rdata_size, rr->rdata};
                    log_debug("update: %{dnsname}: - %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, /*rr->ttl*/ 0, &rd);
#endif
                    output_stream_write_dnsname(&baos, rr->fqdn);
                    output_stream_write_u16(&baos, rr->rtype);
                    output_stream_write_u16(&baos, rr->rclass);
                    output_stream_write_nu32(&baos, rr->org_ttl);
                    output_stream_write_nu16(&baos, rr->rdata_size);
                    output_stream_write(&baos, rr->rdata, rr->rdata_size);
                }

                for(int_fast32_t i = 0; i <= ptr_vector_last_index(&add); ++i)
                {
                    zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&add, i);
#if 0
                    rdata_desc_t rd = {rr->rtype, rr->rdata_size, rr->rdata};
                    log_debug("update: %{dnsname}: + %{dnsname} %9i %{typerdatadesc}", zone->origin, rr->fqdn, rr->ttl, &rd);
#endif
                    output_stream_write_dnsname(&baos, rr->fqdn);
                    output_stream_write_u16(&baos, rr->rtype);
                    output_stream_write_u16(&baos, rr->rclass);
                    output_stream_write_nu32(&baos, rr->ttl);
                    output_stream_write_nu16(&baos, rr->rdata_size);
                    output_stream_write(&baos, rr->rdata, rr->rdata_size);
                }

                input_stream_t bais;

                bytearray_input_stream_init(&bais, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos), false);

                journal *jnl = NULL;
                if(ISOK(ret = journal_acquire_from_zone_ex(&jnl, zone, true)))
                {
                    jnl->vtbl->minimum_serial_update(jnl, zone->text_serial);

                    uint32_t journal_max_size = zone->wire_size / 3;
                    zdb_zone_info_get_zone_max_journal_size(zone->origin, &journal_max_size);
                    jnl->vtbl->maximum_size_update(jnl, journal_max_size);

                    if(ISOK(ret = journal_append_ixfr_stream(jnl, &bais))) // writes a single page
                    {
                        log_debug("update: %{dnsname}: wrote %i bytes to the journal", zone->origin, total);

                        bytearray_input_stream_reset(&bais);

                        uint32_t current_serial = 0;

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
                            log_debug("update: %{dnsname}: applied journal changes", zone->origin);

                            if(ret_status & (DYNUPDATE_DIFF_RETURN_DNSKEY_ADDED | DYNUPDATE_DIFF_RETURN_DNSKEY_REMOVED))
                            {
                                ret_status |= DYNUPDATE_DIFF_RETURN_DNSKEY_UPDATED;
                            }
                        }
                        else
                        {
                            log_err("update: %{dnsname}: could not apply journal changes: %r", zone->origin, ret);
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
                            log_info(
                                "update: %{dnsname}: could not write %i bytes to the journal as it is full and the "
                                "zone needs to be locally stored first",
                                zone->origin,
                                total);
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
#if 0
                if(!zdb_zone_is_maintained(zone) && (zone_get_maintain_mode(zone) == ZDB_ZONE_MAINTAIN_NOSEC))
                {
                    if(zone_diff_adds_nsec3param(&diff))
                    {
                        zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
                        zdb_zone_set_status(zone, ZDB_ZONE_STATUS_GENERATE_CHAIN);
                    }
                    else if(zone_diff_has_zsk(&diff))
                    {
                        zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC);
                        zdb_zone_set_status(zone, ZDB_ZONE_STATUS_GENERATE_CHAIN);
                    }
                }
#else
                if(!zdb_zone_is_maintained(zone))
                {
                    uint8_t maintain_mode = zone_get_maintain_mode(zone);
                    switch(maintain_mode)
                    {
                        case ZDB_ZONE_MAINTAIN_NOSEC:
                        {
                            if(zone_diff_adds_nsec3param(&diff) || zone_diff_has_or_adds_nsec3param(&diff))
                            {
                                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
                                zdb_zone_set_status(zone, ZDB_ZONE_STATUS_GENERATE_CHAIN);
                            }
                            else if(zone_diff_has_zsk(&diff))
                            {
                                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC);
                                zdb_zone_set_status(zone, ZDB_ZONE_STATUS_GENERATE_CHAIN);
                            }

                            break;
                        }
                        case ZDB_ZONE_MAINTAIN_NSEC:
                        {
                            if(zone_diff_adds_nsec3param(&diff))
                            {
                                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
                                zdb_zone_set_status(zone, ZDB_ZONE_STATUS_GENERATE_CHAIN);
                            }
                            else if(zone_diff_has_zsk(&diff))
                            {
                                // zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC);
                                zdb_zone_set_status(zone, ZDB_ZONE_STATUS_GENERATE_CHAIN);
                            }

                            break;
                        }
                        case ZDB_ZONE_MAINTAIN_NSEC3:
                        case ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:
                        {
                            if(zone_diff_adds_nsec3param(&diff) || zone_diff_has_or_adds_nsec3param(&diff))
                            {
                                // zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
                                zdb_zone_set_status(zone, ZDB_ZONE_STATUS_GENERATE_CHAIN);
                            }
                            else if(zone_diff_has_zsk(&diff))
                            {
                                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC);
                                zdb_zone_set_status(zone, ZDB_ZONE_STATUS_GENERATE_CHAIN);
                            }

                            break;
                        }
                        default:
                        {
                            break;
                        }
                    }
                }
#endif
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

        ptr_vector_finalise(&add);
        ptr_vector_finalise(&del);
    }

#if DEBUG
    {
        zdb_resource_record_data_t *soa = zdb_resource_record_sets_find_soa(&zone->apex->resource_record_set);
        if(soa != NULL)
        {
            uint32_t soa_serial = 0;
            rr_soa_get_serial(zdb_resource_record_data_rdata(soa), zdb_resource_record_data_rdata_size(soa), &soa_serial);
            log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) to serial %u", zone->origin, zone, reader, count, secondary_lock, dryrun, soa_serial);
        }
        else
        {
            log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) has no SOA anymore", zone->origin, zone, reader, count, secondary_lock, dryrun);
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
    log_debug("dynupdate_diff(%{dnsname}@%p, %p, %i, %x, %i) returned with %r", zone->origin, zone, reader, count, secondary_lock, dryrun, ret);
#endif
    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_IN_DYNUPDATE_DIFF);

    return ret;
}

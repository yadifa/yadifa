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
#include <dnscore/digest.h>

#include <dnscore/dnskey-signature.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/nsec.h"
#include "dnsdb/nsec3.h"

#include <dnscore/base32hex.h>
#include <dnscore/format.h>
#include <dnscore/dnsformat.h>
#include "dnsdb/dnssec.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/dnssec-keystore.h"
#include "dnsdb/zdb_utils.h"

#include "dnsdb/dynupdate-diff.h"

#define MODULE_MSG_HANDLE g_database_logger
extern logger_handle *g_database_logger;

#define NSC3NODE_TAG 0x45444f4e3343534e

static const u8 UNKNOWN_FQDN[] = "\007UNKNOWN";

struct dnssec_chain_node_nsec3
{
    nsec3_node *prev;
    nsec3_node *self;
    nsec3_node *next;
    u8 *fqdn;
    u8 state;
    u8 reserved[sizeof(void*)-2];
    u8 digest[1 + SHA_DIGEST_LENGTH];
};

typedef struct dnssec_chain_node_nsec3 dnssec_chain_node_nsec3;

static void dnssec_chain_node_nsec3_set_fqdn(dnssec_chain_node_nsec3 *node, const u8 *fqdn)
{
    yassert(node->fqdn == NULL);
    node->fqdn = dnsname_zdup(fqdn);
}

static const u8* dnssec_chain_node_nsec3_get_digest(const dnssec_chain_node_nsec3 *node)
{
    return (node->self != NULL)?node->self->digest:node->digest;
}

static void
dnssec_chain_node_nsec3_format_handler_method(const void *val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void *reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    dnssec_chain_node_nsec3 *node = (dnssec_chain_node_nsec3*)val;
    const u8* digest = dnssec_chain_node_nsec3_get_digest(node);
    output_stream_write_base32hex(stream, &digest[1], *digest);
    output_stream_write_u8(stream, '(');
    if(node->fqdn != NULL)
    {
        dnsname_format_handler_method(node->fqdn, stream, 0, 0, FALSE, NULL);
    }
    else
    {
        output_stream_write_u8(stream, '?');
    }
    output_stream_write_u8(stream, ')');
}

static void dnssec_chain_node_nsec3_format_writer_init(dnssec_chain_node_t node_, format_writer *outfw)
{
    dnssec_chain_node_nsec3 *node = (dnssec_chain_node_nsec3*)node_;
    outfw->callback = dnssec_chain_node_nsec3_format_handler_method;
    outfw->value = node;
}

//#define NSEC3_HANDLE_SUBDELEGATION 1

static bool dnssec_chain_node_nsec3_fqdn_is_covered(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex ||
           (diff_fqdn->at_delegation && !diff_fqdn->under_delegation)||  // has NS records (but is not below NS records)
           (!(diff_fqdn->at_delegation || diff_fqdn->under_delegation) && (diff_fqdn->will_be_non_empty || diff_fqdn->will_have_children))
           // else it's under a delegation
           ;
}

static bool dnssec_chain_node_nsec3_fqdn_was_covered(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex ||
           (diff_fqdn->was_at_delegation && !diff_fqdn->was_under_delegation) ||  // had NS records (but is not below NS records)
           (!(diff_fqdn->was_at_delegation || diff_fqdn->was_under_delegation) && (diff_fqdn->was_non_empty || diff_fqdn->had_children))
            // else it was under a delegation
        ;
}

static bool dnssec_chain_node_nsec3_optout_fqdn_is_covered(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex ||
           (diff_fqdn->at_delegation && !diff_fqdn->under_delegation && diff_fqdn->will_have_ds) ||  // has DS record(s)
           (!(diff_fqdn->at_delegation || diff_fqdn->under_delegation) && (diff_fqdn->will_be_non_empty || diff_fqdn->will_have_children))
        // else it's under a delegation
        ;
}

static bool dnssec_chain_node_nsec3_optout_fqdn_was_covered(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex ||
           (diff_fqdn->was_at_delegation && !diff_fqdn->was_under_delegation && diff_fqdn->had_ds) ||  // had DS record(s)
           (!(diff_fqdn->was_at_delegation || diff_fqdn->was_under_delegation) && (diff_fqdn->was_non_empty || diff_fqdn->had_children))
        // else it was under a delegation
        ;
}

/**
 * Creates a new entry with its pred/next from the zone nsec3 database
 * 
 * @param digest 
 * @param chain nsec3_zone
 * @return 
 */

static dnssec_chain_node_nsec3 *
dnssec_chain_node_nsec3_new_from_digest(const u8 *digest, const nsec3_zone *n3)
{
    // compute the digest of the fqdn for the chain
    // find if the node already exists
    // return the appropriate node

    nsec3_zone_item *self = NULL;
    nsec3_zone_item *prev;
    nsec3_zone_item *next;
    
    bool empty = (n3->items == NULL);

    if(!empty)
    {
        prev = nsec3_find_interval_prev_mod(&n3->items, (u8*)digest);
        next = nsec3_node_mod_next(prev);
        
        if(memcmp(&next->digest[1], &digest[1], digest[0]) == 0)
        {
            // exists
            self = next;
            next = nsec3_node_mod_next(self);
        }
    }
    else
    {
        prev = NULL;
        next = NULL;
    }
    
    dnssec_chain_node_nsec3 *node;
    
    ZALLOC_OBJECT_OR_DIE(node, dnssec_chain_node_nsec3, NSC3NODE_TAG);
    node->prev = prev;
    node->self = self;
    node->next = next;
    node->fqdn = NULL;
    
    if(self != NULL)
    {
        node->state = DNSSEC_CHAIN_EXISTS;
    }
    else
    {
        node->state = DNSSEC_CHAIN_ADD;
        memcpy(node->digest, digest, digest[0] + 1);
    }
    
    return node;
}

static dnssec_chain_node_t dnssec_chain_node_nsec3_new(const u8 *fqdn, dnssec_chain_head_t chain)
{
    // compute the digest of the fqdn for the chain
    // find if the node already exists
    // return the appropriate node

    const nsec3_zone* n3 = (nsec3_zone*)chain;
    u8 digest[1 + SHA_DIGEST_LENGTH];
    
    nsec3_compute_digest_from_fqdn_with_len(n3, fqdn, dnsname_len(fqdn), digest, FALSE);
    
    dnssec_chain_node_nsec3 *node = dnssec_chain_node_nsec3_new_from_digest(digest, n3);
    
    dnssec_chain_node_nsec3_set_fqdn(node, fqdn);
    
    if(node->prev != NULL)
    {
        if(node->next != NULL)   
        {
            log_debug1("update: nsec3: %{dnsname} has node %{digest32h} [ %{digest32h} ; %{digest32h} ] (%02x)", fqdn,
                    dnssec_chain_node_nsec3_get_digest(node),
                    node->prev->digest,
                    node->next->digest,
                    node->state);
        }
        else
        {
            log_debug1("update: nsec3: %{dnsname} has node %{digest32h} [ %{digest32h} ; ? [ (%02x)", fqdn,
                    dnssec_chain_node_nsec3_get_digest(node),
                    node->prev->digest,
                    node->state);
        }
    }
    else
    {
        log_debug1("update: nsec3: %{dnsname} has node %{digest32h} [ ? ; ? [ (%02x)", fqdn,
                    dnssec_chain_node_nsec3_get_digest(node),
                    node->state);
    }
    
    return (dnssec_chain_node_t)node;
}

static void dnssec_chain_node_nsec3_delete(dnssec_chain_node_t node_)
{
    dnssec_chain_node_nsec3 *nsec3_node = (dnssec_chain_node_nsec3*)node_;
    if((nsec3_node->fqdn != NULL) && (nsec3_node->fqdn != UNKNOWN_FQDN))
    {
        dnsname_zfree(nsec3_node->fqdn);
    }
    ZFREE(nsec3_node, dnssec_chain_node_nsec3);
}

static bool dnssec_chain_node_nsec3_has_bits_map(const dnssec_chain_node_nsec3 *node)
{
    return node->self != NULL;
}

static const u8 *dnssec_chain_node_nsec3_get_bits_map(const dnssec_chain_node_nsec3 *node)
{
    return node->self->type_bit_maps;
}

static u16 dnssec_chain_node_nsec3_get_bits_map_size(const dnssec_chain_node_nsec3 *node)
{
    return node->self->type_bit_maps_size;
}

static int dnssec_chain_node_nsec3_compare(const void *a_, const void *b_)
{
    const dnssec_chain_node_nsec3 *a = (const dnssec_chain_node_nsec3*)a_;
    const dnssec_chain_node_nsec3 *b = (const dnssec_chain_node_nsec3*)b_;
    
    const u8 *a_digest = dnssec_chain_node_nsec3_get_digest(a);
    const u8 *b_digest = dnssec_chain_node_nsec3_get_digest(b);
    
    yassert(a_digest[0] == SHA_DIGEST_LENGTH && b_digest[0] == SHA_DIGEST_LENGTH);
    
    int ret = memcmp(&a_digest[1], &b_digest[1], a_digest[0]);
    
    return ret;
}

static dnssec_chain_node_t dnssec_chain_node_nsec3_prev(const dnssec_chain_node_t node_)
{
    dnssec_chain_node_nsec3 *self = (dnssec_chain_node_nsec3*)node_;
    dnssec_chain_node_nsec3 *node;
    ZALLOC_OBJECT_OR_DIE(node, dnssec_chain_node_nsec3, NSC3NODE_TAG);
    node->prev = NULL;
    node->self = self->prev;
    node->next = self->next; // ?
    node->fqdn = (u8*)UNKNOWN_FQDN;
    node->state = DNSSEC_CHAIN_EXISTS|DNSSEC_CHAIN_BEGIN;
    node->digest[0] = 0;
    log_debug1("update: prev is %{digest32h} (%02x) '%{dnsname}'", node->self->digest, node->state, node->fqdn);
    
    return (dnssec_chain_node_t)node;
}

static dnssec_chain_node_t dnssec_chain_node_nsec3_next(const dnssec_chain_node_t node_)
{
    dnssec_chain_node_nsec3 *self = (dnssec_chain_node_nsec3*)node_;
    dnssec_chain_node_nsec3 *node;
    ZALLOC_OBJECT_OR_DIE(node, dnssec_chain_node_nsec3, NSC3NODE_TAG);
    node->prev = self->prev; // ?
    node->self = self->next;
    node->next = NULL;
    node->fqdn = (u8*)UNKNOWN_FQDN;
    node->state = DNSSEC_CHAIN_EXISTS|DNSSEC_CHAIN_END;
    log_debug1("update: next is %{digest32h} (%02x) '%{dnsname}'", node->self->digest, node->state, node->fqdn);
    
    return (dnssec_chain_node_t)node;
}

static u8 dnssec_chain_node_nsec3_state_get(const dnssec_chain_node_t node_)
{
    const dnssec_chain_node_nsec3 *self = (const dnssec_chain_node_nsec3*)node_;
    return self->state;
}

static void dnssec_chain_node_nsec3_state_set(dnssec_chain_node_t node_, u8 value)
{
    dnssec_chain_node_nsec3 *self = (dnssec_chain_node_nsec3*)node_;
    log_debug1("update: status %{digest32h} from %02x to %02x", dnssec_chain_node_nsec3_get_digest(self), self->state, value);
    self->state = value;
}

static void dnssec_chain_node_nsec3_merge(dnssec_chain_node_t chain_node, dnssec_chain_node_t chain_with)
{
    dnssec_chain_node_nsec3 *node = (dnssec_chain_node_nsec3*)chain_node;
    dnssec_chain_node_nsec3 *with = (dnssec_chain_node_nsec3*)chain_with;
    
    u8 node_state = dnssec_chain_node_nsec3_state_get(chain_node);
    u8 with_state = dnssec_chain_node_nsec3_state_get(chain_with);

#if DEBUG
    format_writer node_writer;
    dnssec_chain_node_nsec3_format_writer_init(chain_node, &node_writer);
    format_writer with_writer;
    dnssec_chain_node_nsec3_format_writer_init(chain_with, &with_writer);
    log_debug2("nsec3_merge: %w (%02x) with %w(%02x)", &node_writer, node_state, &with_writer, with_state);
#endif

    if((node_state & DNSSEC_CHAIN_END) && (with_state & DNSSEC_CHAIN_BEGIN))
    {
#if DEBUG
        log_debug("dnssec_chain_node_nsec3_merge(%{digest32h},%{digest32h}) end<->begin (%08x %08x)",
                dnssec_chain_node_nsec3_get_digest(node), dnssec_chain_node_nsec3_get_digest(with),
                node_state, with_state);
#endif
        dnssec_chain_node_nsec3_state_set(chain_node, dnssec_chain_node_nsec3_state_get(chain_node) & ~DNSSEC_CHAIN_END);
    }
    
    if((node_state & DNSSEC_CHAIN_BEGIN) && (with_state & DNSSEC_CHAIN_END))
    {
#if DEBUG
        log_debug("dnssec_chain_node_nsec3_merge(%{digest32h},%{digest32h}) begin<->end (%08x %08x)",
                dnssec_chain_node_nsec3_get_digest(node), dnssec_chain_node_nsec3_get_digest(with),
                node_state, with_state);
#endif
        dnssec_chain_node_nsec3_state_set(chain_node, dnssec_chain_node_nsec3_state_get(chain_node) & ~DNSSEC_CHAIN_BEGIN);
    }
    
    // properly handle merging of the FQDN
    
    if(node->fqdn == UNKNOWN_FQDN)
    {
        if(with->fqdn != UNKNOWN_FQDN)
        {
            node->fqdn = with->fqdn;
            with->fqdn = (u8*)UNKNOWN_FQDN;
        }
    }

    dnssec_chain_node_nsec3_delete(chain_with);
}

/**
 * 
 * @param n3
 * @param from
 * @param to
 * @param diff
 * @param collection
 * @param mask ZONE_DIFF_REMOVE: get the new state, ZONE_DIFF_ADD: get the old state
 * @param append_existing_signatures adds the existing signature to the collection (e.g.: to remove them)
 * @param optout
 */

static void dnssec_chain_node_nsec3_publish_record(nsec3_zone *n3,
        dnssec_chain_node_nsec3 *from, dnssec_chain_node_nsec3 *to,
        zone_diff *diff, ptr_vector *collection, u8 mask,
        bool append_existing_signatures, u8 optout)
{
    
    const u8 *digest = dnssec_chain_node_nsec3_get_digest(from);
    const u8 *next_digest = dnssec_chain_node_nsec3_get_digest(to);
    
    u32 b32_len;
    u32 fqdn_len;
    u8 hash_len;
    u8 digest_fqdn[512];
        
    log_debug1("update: %{dnsname}: %{digest32h}: %x: %{dnsname} -> %{digest32h}", diff->origin, digest, mask, from->fqdn, next_digest);
    // generate the label

    hash_len = digest[0];
    b32_len = base32hex_encode(&digest[1], hash_len, (char*)&digest_fqdn[1]);
    digest_fqdn[0] = b32_len;
    fqdn_len = dnsname_len(diff->origin);
    memcpy(&digest_fqdn[b32_len + 1], diff->origin, fqdn_len );
    
    u32 nsec3param_rdata_size = NSEC3PARAM_RDATA_SIZE_FROM_RDATA(n3->rdata);
        
    if(!dnssec_chain_node_nsec3_has_bits_map(from) || ((mask & ZONE_DIFF_RR_REMOVE) && (from->state & DNSSEC_CHAIN_REMAP))
    /*
     * can only modify if (mask & ZONE_DIFF_RR_REMOVE)
    || ((from->state & (DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_REMAP|DNSSEC_CHAIN_EXISTS)) == (DNSSEC_CHAIN_DELETE|DNSSEC_CHAIN_REMAP|DNSSEC_CHAIN_EXISTS))
    */
            )
    {
        // generate the type map
#if DEBUG
        log_debug2("update: %{dnsname}: %{digest32h}: %x: %{dnsname} -> %{digest32h} regenerating bitmap (%i || (%i && %i [%02x])",
                diff->origin, digest, mask, from->fqdn, next_digest,
                !dnssec_chain_node_nsec3_has_bits_map(from), (mask & ZONE_DIFF_RR_REMOVE), (from->state & DNSSEC_CHAIN_REMAP), from->state);
#endif
        type_bit_maps_context bitmap;

        u16 bitmap_size = zone_diff_type_bit_map_generate(diff, from->fqdn, &bitmap, mask | ZONE_DIFF_RR_REMOVE, 0, digest_fqdn, append_existing_signatures);

        u16 rdata_size = nsec3param_rdata_size + 1 + next_digest[0] + bitmap_size;

#if C11_VLA_AVAILABLE
        u8 rdata[rdata_size];
#else
        u8* const rdata = (u8* const)stack_alloc(rdata_size);
#endif

        memcpy(rdata, n3->rdata, nsec3param_rdata_size);
        rdata[1] = optout;
        memcpy(&rdata[nsec3param_rdata_size], next_digest, 1 + next_digest[0]);    
        type_bit_maps_write(&bitmap, &rdata[nsec3param_rdata_size + 1 + next_digest[0]]);
        type_bit_maps_finalize(&bitmap);
        
        // the record can be created
    
        zone_diff_label_rr *nsec3_rr = zone_diff_label_rr_new(digest_fqdn, TYPE_NSEC3, CLASS_IN, diff->nttl, rdata, rdata_size, TRUE);
        nsec3_rr->state |= ZONE_DIFF_RR_VOLATILE;
        ptr_vector_append(collection, nsec3_rr);
    }
    else // bitmap already present
    {
#if DEBUG
        log_debug2("update: %{dnsname}: %{digest32h}: %x: %{dnsname} -> %{digest32h} keeping bitmap (%i || (%i && %i [%02x])",
                   diff->origin, digest, mask, from->fqdn, next_digest,
                   !dnssec_chain_node_nsec3_has_bits_map(from), (mask & ZONE_DIFF_RR_REMOVE), (from->state & DNSSEC_CHAIN_REMAP),
                   from->state);
#endif
        u16 bitmap_size = dnssec_chain_node_nsec3_get_bits_map_size(from);
        u16 rdata_size = nsec3param_rdata_size + 1 + next_digest[0] + bitmap_size;

#if C11_VLA_AVAILABLE
        u8 rdata[rdata_size];
#else
        u8* const rdata = (u8* const)stack_alloc(rdata_size);
#endif

        memcpy(rdata, n3->rdata, nsec3param_rdata_size);
        rdata[1] = optout;
        memcpy(&rdata[nsec3param_rdata_size], next_digest, 1 + next_digest[0]);    
        memcpy(&rdata[nsec3param_rdata_size + 1 + next_digest[0]], dnssec_chain_node_nsec3_get_bits_map(from), bitmap_size);
        
        // the record can be created
    
        zone_diff_label_rr *nsec3_rr = zone_diff_label_rr_new(
                digest_fqdn, TYPE_NSEC3, CLASS_IN, diff->nttl, rdata, rdata_size, TRUE);
        nsec3_rr->state |= ZONE_DIFF_RR_VOLATILE | (from->state & DNSSEC_CHAIN_EXISTS);
        ptr_vector_append(collection, nsec3_rr);
    }
    
    if(append_existing_signatures && (from->self != NULL))
    {
        zdb_packed_ttlrdata *rrsig = from->self->rrsig;
        while(rrsig != NULL)
        {
            zone_diff_label_rr *rrsig_rr = zone_diff_label_rr_new(digest_fqdn, TYPE_RRSIG, CLASS_IN, diff->nttl,
                    ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig), TRUE);
            rrsig_rr->state |= ZONE_DIFF_RR_VOLATILE;
            ptr_vector_append(collection, rrsig_rr);
            rrsig = rrsig->next;
        }
    }
}

static void dnssec_chain_node_nsec3_publish_log(dnssec_chain_node_t from_, dnssec_chain_node_t to_)
{
    dnssec_chain_node_nsec3 *from = (dnssec_chain_node_nsec3*)from_;
    dnssec_chain_node_nsec3 *to = (dnssec_chain_node_nsec3*)to_;

    const u8 *digest = dnssec_chain_node_nsec3_get_digest(from);    
    if(to != NULL)
    {
        const u8 *next_digest = dnssec_chain_node_nsec3_get_digest(to);
    
        log_debug1("update: %{digest32h} -> %{digest32h}", digest, next_digest);
    }
    else
    {
        log_debug1("update: %{digest32h} -> ?", digest);
    }
}

static void dnssec_chain_node_nsec3_publish_add(dnssec_chain_head_t chain_, dnssec_chain_node_t from_, dnssec_chain_node_t to_, zone_diff *diff, ptr_vector *collection)
{
    dnssec_chain_node_nsec3 *from = (dnssec_chain_node_nsec3*)from_;
    dnssec_chain_node_nsec3 *to = (dnssec_chain_node_nsec3*)to_;
    nsec3_zone *n3 = (nsec3_zone*)chain_;
    dnssec_chain_node_nsec3_publish_record(n3, from, to, diff, collection, ZONE_DIFF_RR_REMOVE, FALSE, 0);
}

static void dnssec_chain_node_nsec3_publish_delete(dnssec_chain_head_t chain_, dnssec_chain_node_t from_, dnssec_chain_node_t to_, zone_diff *diff, ptr_vector *collection)
{
    dnssec_chain_node_nsec3 *from = (dnssec_chain_node_nsec3*)from_;
    dnssec_chain_node_nsec3 *to = (dnssec_chain_node_nsec3*)to_;
    nsec3_zone *n3 = (nsec3_zone*)chain_;
    dnssec_chain_node_nsec3_publish_record(n3, from, to, diff, collection, ZONE_DIFF_RR_ADD, TRUE, 0);
}

static void dnssec_chain_node_nsec3_publish_add_optout(dnssec_chain_head_t chain_, dnssec_chain_node_t from_, dnssec_chain_node_t to_, zone_diff *diff, ptr_vector *collection)
{
    dnssec_chain_node_nsec3 *from = (dnssec_chain_node_nsec3*)from_;
    dnssec_chain_node_nsec3 *to = (dnssec_chain_node_nsec3*)to_;
    nsec3_zone *n3 = (nsec3_zone*)chain_;
    dnssec_chain_node_nsec3_publish_record(n3, from, to, diff, collection, ZONE_DIFF_RR_REMOVE, FALSE, 1);
}

static void dnssec_chain_node_nsec3_publish_delete_optout(dnssec_chain_head_t chain_, dnssec_chain_node_t from_, dnssec_chain_node_t to_, zone_diff *diff, ptr_vector *collection)
{
    dnssec_chain_node_nsec3 *from = (dnssec_chain_node_nsec3*)from_;
    dnssec_chain_node_nsec3 *to = (dnssec_chain_node_nsec3*)to_;
    nsec3_zone *n3 = (nsec3_zone*)chain_;
    dnssec_chain_node_nsec3_publish_record(n3, from, to, diff, collection, ZONE_DIFF_RR_ADD, TRUE, 1);
}

static bool dnssec_chain_nsec3_isempty(dnssec_chain_head_t chain_)
{
    nsec3_zone *nsec3_chain = (nsec3_zone*)chain_;
    bool ret = (nsec3_chain != NULL)?nsec3_isempty(&nsec3_chain->items):TRUE;
    return ret;
}

static void dnssec_chain_nsec3_finalize_delete_callback(ptr_node *node)
{
    dnssec_chain_node_nsec3_delete(node->value);
}

static bool dnssec_chain_node_nsec3_rrset_should_be_signed(const zone_diff_fqdn *diff_fqdn, const zone_diff_fqdn_rr_set *rr_set)
{
    if(diff_fqdn->at_delegation || diff_fqdn->under_delegation)
    {
        return (rr_set->rtype == TYPE_NS) || (rr_set->rtype == TYPE_DS);
    }
    else
    {
        return TRUE;
    }
}


static bool dnssec_chain_node_nsec3_optout_rrset_should_be_signed(const zone_diff_fqdn *diff_fqdn, const zone_diff_fqdn_rr_set *rr_set)
{
    if(diff_fqdn->at_delegation || diff_fqdn->under_delegation)
    {
        return (rr_set->rtype == TYPE_DS);
    }
    else
    {
        return TRUE;
    }
}

static dnssec_chain_node_vtbl dnssec_chain_node_nsec3_vtbl = 
{
    dnssec_chain_node_nsec3_fqdn_is_covered,
    dnssec_chain_node_nsec3_fqdn_was_covered,
    dnssec_chain_node_nsec3_new,
    dnssec_chain_node_nsec3_prev,
    dnssec_chain_node_nsec3_merge,
    dnssec_chain_node_nsec3_next,
    dnssec_chain_node_nsec3_state_set,
    dnssec_chain_node_nsec3_state_get,
    dnssec_chain_node_nsec3_delete,
    dnssec_chain_node_nsec3_publish_delete,
    dnssec_chain_node_nsec3_publish_add,
    dnssec_chain_node_nsec3_publish_log,
    dnssec_chain_node_nsec3_compare,
    dnssec_chain_nsec3_finalize_delete_callback,
    dnssec_chain_nsec3_isempty,
    dnssec_chain_node_nsec3_format_writer_init,
    dnssec_chain_node_nsec3_rrset_should_be_signed,
    "nsec3"
};

const dnssec_chain_node_vtbl *
dynupdate_nsec3_chain_get_vtbl()
{
    return &dnssec_chain_node_nsec3_vtbl;
}

static dnssec_chain_node_vtbl dnssec_chain_node_nsec3_optout_vtbl = 
{
    dnssec_chain_node_nsec3_optout_fqdn_is_covered,
    dnssec_chain_node_nsec3_optout_fqdn_was_covered,
    dnssec_chain_node_nsec3_new,
    dnssec_chain_node_nsec3_prev,
    dnssec_chain_node_nsec3_merge,
    dnssec_chain_node_nsec3_next,
    dnssec_chain_node_nsec3_state_set,
    dnssec_chain_node_nsec3_state_get,
    dnssec_chain_node_nsec3_delete,
    dnssec_chain_node_nsec3_publish_delete_optout,
    dnssec_chain_node_nsec3_publish_add_optout,
    dnssec_chain_node_nsec3_publish_log,
    dnssec_chain_node_nsec3_compare,
    dnssec_chain_nsec3_finalize_delete_callback,
    dnssec_chain_nsec3_isempty,
    dnssec_chain_node_nsec3_format_writer_init,
    dnssec_chain_node_nsec3_optout_rrset_should_be_signed,
    "nsec3-optout"
};

const dnssec_chain_node_vtbl *
dynupdate_nsec3_optout_chain_get_vtbl()
{
    return &dnssec_chain_node_nsec3_optout_vtbl;
}

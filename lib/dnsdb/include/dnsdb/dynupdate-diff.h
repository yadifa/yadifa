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

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 * @{
 */
#pragma once

#include <dnscore/ptr_vector.h>
#include <dnscore/ptr_set.h>
#include <dnscore/u32_set.h>
#include <dnscore/typebitmap.h>
#include <dnscore/dnskey.h>
#include <dnscore/packet_reader.h>
#include <dnscore/packet_writer.h>
#include <dnscore/format.h>

#include <dnsdb/zdb_types.h>

struct logger_handle;

#define DNSSEC_CHAIN_SUPPORTED_MAX 16

#define DNSSEC_CHAIN_ADD    0x01
#define DNSSEC_CHAIN_DELETE 0x02
#define DNSSEC_CHAIN_REMAP  0x08    // to generate an update of the maps
#define DNSSEC_CHAIN_EXISTS 0x10
#define DNSSEC_CHAIN_BEGIN  0x20    // implies that the node is actually in the chain
#define DNSSEC_CHAIN_END    0x40    // implies that the node is actually in the chain
#define DNSSEC_CHAIN_MARK   0x80

#define DYNUPDATE_DIFF_RETURN_DNSKEY_ADDED   1  // only covers ZSK
#define DYNUPDATE_DIFF_RETURN_DNSKEY_REMOVED 2  // only covers ZSK
#define DYNUPDATE_DIFF_RETURN_DNSKEY_UPDATED 4  // the reported ZSK status was actually applied
#define DYNUPDATE_DIFF_RETURN_MASK           7

#define DYNUPDATE_DIFF_DRYRUN   TRUE
#define DYNUPDATE_DIFF_RUN      FALSE

#define ZDLABELT_TAG 0x544c4542414c445a
#define ZDFFLABL_TAG 0x4c42414c4646445a
#define ZDFFLBRR_TAG 0x4242424c4646445a
#define ZDFFFQDN_TAG 0x4e4451464646445a
#define ZDFFRRST_TAG 0x545352524646445a
#define DMSGPCKT_TAG 0x544b435047534d44

struct zone_diff_fqdn;
struct zone_diff_fqdn_rr_set;
struct dnssec_chain;

struct zone_diff_label_tree
{
    const u8 *label;
    struct zone_diff_fqdn *diff_fqdn;
    ptr_set sub;
    // maybe some flags ...
};

typedef struct zone_diff_label_tree zone_diff_label_tree;

struct zone_diff
{
    ptr_set fqdn;
    zone_diff_label_tree root;      // contains everything but the apex (that would be nuts resource-wise)
    const u8 *origin;
    struct zone_diff_fqdn *apex;    // quick access to the apex
    s32 rrsig_validity_interval;
    s32 rrsig_validity_regeneration;
    s32 rrsig_validity_jitter;
    s32 nttl;
    bool rrsig_update_allowed;
    bool has_active_zsk;
    bool has_active_ksk;
    bool may_remove_dnskey;
    bool may_add_dnskey;
    bool maintain_nsec;
    bool maintain_nsec3;
};

typedef struct zone_diff zone_diff;

struct dnssec_chain_node_t_anon { const int hidden; };
typedef struct dnssec_chain_node_t_anon* dnssec_chain_node_t;

struct dnssec_chain_head_t_anon { const int hidden; };
typedef struct dnssec_chain_head_t_anon* dnssec_chain_head_t;

typedef int dnssec_chain_node_compare_method(const void* a_, const void* b_);

typedef bool dnssec_chain_node_fqdn_is_covered_method(const struct zone_diff_fqdn *diff_fqdn);
typedef bool dnssec_chain_node_fqdn_was_covered_method(const struct zone_diff_fqdn *diff_fqdn);
typedef dnssec_chain_node_t dnssec_chain_node_new_method(const u8 *fqdn, dnssec_chain_head_t chain);
typedef dnssec_chain_node_t dnssec_chain_node_prev_method(const dnssec_chain_node_t node_);
typedef void dnssec_chain_node_merge_method(dnssec_chain_node_t node_, dnssec_chain_node_t with_);
typedef dnssec_chain_node_t dnssec_chain_node_next_method(const dnssec_chain_node_t node_);
typedef void dnssec_chain_node_state_set_method(dnssec_chain_node_t node_, u8 value);
typedef u8 dnssec_chain_node_state_get_method(const dnssec_chain_node_t node_);
typedef void dnssec_chain_node_delete_method(dnssec_chain_node_t node_);
typedef void dnssec_chain_node_publish_delete_method(dnssec_chain_head_t chain_, dnssec_chain_node_t from_, dnssec_chain_node_t to_, zone_diff *diff, ptr_vector *collection);
typedef void dnssec_chain_node_publish_add_method(dnssec_chain_head_t chain_, dnssec_chain_node_t from_, dnssec_chain_node_t to_, zone_diff *diff, ptr_vector *collection);
typedef void dnssec_chain_node_publish_log_method(dnssec_chain_node_t from_, dnssec_chain_node_t to_);
typedef bool dnssec_chain_node_isempty_method(dnssec_chain_head_t chain_);
typedef void dnssec_chain_node_format_writer_init(dnssec_chain_node_t node_, format_writer *outfw);
typedef bool dnssec_chain_node_rrset_should_be_signed_method(const struct zone_diff_fqdn *diff_fqdn, const struct zone_diff_fqdn_rr_set *rr_set);

struct dnssec_chain_node_vtbl
{
    dnssec_chain_node_fqdn_is_covered_method *fqdn_is_covered;
    dnssec_chain_node_fqdn_was_covered_method *fqdn_was_covered;
    dnssec_chain_node_new_method *node_new;
    dnssec_chain_node_prev_method *node_prev;
    dnssec_chain_node_merge_method *node_merge;
    dnssec_chain_node_next_method *node_next;
    dnssec_chain_node_state_set_method *state_set;
    dnssec_chain_node_state_get_method *state_get;
    dnssec_chain_node_delete_method *node_delete;
    dnssec_chain_node_publish_delete_method *publish_delete;
    dnssec_chain_node_publish_add_method *publish_add;
    dnssec_chain_node_publish_log_method *publish_log;
    dnssec_chain_node_compare_method *compare;
    void (*ptr_set_node_delete_callback)(ptr_node*);
    dnssec_chain_node_isempty_method *isempty;
    dnssec_chain_node_format_writer_init *format_writer_init;
    dnssec_chain_node_rrset_should_be_signed_method *rrset_should_be_signed;
    const char * const __name__;
};

typedef struct dnssec_chain_node_vtbl dnssec_chain_node_vtbl;

struct dnssec_chain
{
    zone_diff *diff;

    ptr_set chain_diff;
    const dnssec_chain_node_vtbl *chain;
    dnssec_chain_head_t chains[DNSSEC_CHAIN_SUPPORTED_MAX];
    bool chain_being_deleted[DNSSEC_CHAIN_SUPPORTED_MAX];
    int chains_count;
};

typedef struct dnssec_chain dnssec_chain;

const dnssec_chain_node_vtbl *dynupdate_nosec_chain_get_vtbl();
const dnssec_chain_node_vtbl *dynupdate_nsec_chain_get_vtbl();
const dnssec_chain_node_vtbl *dynupdate_nsec3_chain_get_vtbl();
const dnssec_chain_node_vtbl *dynupdate_nsec3_optout_chain_get_vtbl();

/**
 * Initialises a dnssec chain (editor).
 * NSEC and NSEC3 chains cannot be mixed.
 * The actual chain must be set using dnssec_chain_add_chain
 * 
 * @param dc
 * @param chain_functions
 */

void dnssec_chain_init(dnssec_chain *dc, const dnssec_chain_node_vtbl *chain_functions, zone_diff* diff);

/**
 * Adds a chain to the chain editor.
 * 
 * NSEC3: one of the nsec3_zone* of the zone (add them one at a time).
 * NSEC: the nsec_zone* of the zone.
 * 
 * @param dc
 * @param chain
 * @param being_deleted tells the chain is on its way out and records should be removed, not added
 */

void dnssec_chain_add_chain(dnssec_chain *dc, dnssec_chain_head_t chain, bool being_deleted);

/**
 * Adds a node to the chain.
 * 
 * @param dc
 * @param fqdn
 * @param rtype
 */

void dnssec_chain_add(dnssec_chain *dc, const u8 *fqdn, u16 rtype);

/**
 * Removes a node from the chain.
 * 
 * @param dc
 * @param fqdn
 * @param rtype
 */

void dnssec_chain_del(dnssec_chain *dc, const u8 *fqdn, u16 rtype);

/**
 * Computes the changes of the chain into a del and an add records vector.
 * 
 * @param diff
 * @param origin
 * @param nttl
 */

void dnssec_chain_store_diff(dnssec_chain *dc, zone_diff *diff, ptr_vector *keys, ptr_vector *del, ptr_vector *add);

/**
 * Releases the memory used by a chain
 */

void dnssec_chain_finalize(dnssec_chain *dc);

/**
 * Resource Record States
 */

#define ZONE_DIFF_RR_ADD           1 // +
#define ZONE_DIFF_RR_REMOVE        2 // -
#define ZONE_DIFF_RR_RDATA_OWNED   4 // O
#define ZONE_DIFF_RR_VOLATILE      8 // V not in the diff set
#define ZONE_DIFF_RR_IN_ZONE      16 // E
#define ZONE_DIFF_RR_AUTOMATED    32 // A
#define ZONE_DIFF_RR_ADDED        64 // . done
#define ZONE_DIFF_RR_REMOVED     128 // . done

/**
 * Diff changes
 */

#define ZONE_DIFF_CHANGES_NONE      0
#define ZONE_DIFF_CHANGES_ADD       1
#define ZONE_DIFF_CHANGES_REMOVE    2
#define ZONE_DIFF_CHANGES_KEPT      4

struct zone_diff_label_rr
{
    u8 *fqdn;
    void *rdata;
    s32 ttl;
    u16 rtype;
    u16 rclass;
    u16 rdata_size;
    u8 state;
};

typedef struct zone_diff_label_rr zone_diff_label_rr;

struct zone_diff_fqdn_rr_set
{
    ptr_set rr;
    intptr key_mask;
    s32 org_ttl;
    s32 new_ttl;
    u16 rtype;
    u16 rclass;
};

typedef struct zone_diff_fqdn_rr_set zone_diff_fqdn_rr_set;

struct zone_diff_fqdn
{
    u32_set rrset;
    u8 *fqdn;
    /*struct zone_diff_fqdn *direct_parent;
    u32 nonempty_children;*/
    unsigned int type_map_changed:1,
        all_rrset_added:1,              // completely added
        all_rrset_removed:1,            // completely removed
        is_apex:1,
        will_be_removed:1,
        
        at_delegation:1,
        under_delegation:1,
        will_have_ds:1,
        will_be_non_empty:1,
        will_have_children:1,
        
        was_at_delegation:1,
        was_under_delegation:1,
        had_ds:1,
        was_non_empty:1,
        had_children:1,

        rrsig_removed:1,
        rrsig_added:1,
        rrsig_kept:1,
        is_nsec3:1,

        children_added:1,               // tells that the children are available in the diff, else it means that had_children = will_have_children
    
        records_flags_set:1,
        children_flags_set:1,

        has_active_zsk:1,
        has_active_ksk:1,

        is_in_database:1;
};

typedef struct zone_diff_fqdn zone_diff_fqdn;

/**
 * Initialises a zone diff
 * 
 * @param diff
 * @param origin
 * @param nttl
 * @param rrsig_push_allowed allows updating an RRSIG "manually" (external signing process)
 */

void zone_diff_init(zone_diff *diff, zdb_zone *zone, bool rrsig_update_allowed);

/**
 * Adds the SOA records for the incremental update.
 * 
 * @param diff
 * @return 
 */

ya_result zone_diff_set_soa(zone_diff *diff, zdb_rr_label *label);

/**
 * Updates status and validates a diff.
 * 
 * @param diff
 * @return 
 */

ya_result zone_diff_validate(zone_diff *diff);

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

s32 zone_diff_get_changes(zone_diff *diff, ptr_vector *rrset_to_sign_vector, ptr_vector *ksks, ptr_vector *zsks, ptr_vector *remove, ptr_vector *add);

/**
 * Returns TRUE iff there are changes in the diff
 * 
 * @param diff
 * @param rrset_to_sign_vector can be NULL
 * 
 * @return TRUE iff there are changes in the diff
 */

bool zone_diff_has_changes(zone_diff *diff, ptr_vector *rrset_to_sign_vector);

static inline bool zone_diff_fqdn_is_covered_by_nsec3(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex ||
           (diff_fqdn->at_delegation && !diff_fqdn->under_delegation)||  // has NS records (but is not below NS records)
           (!(diff_fqdn->at_delegation || diff_fqdn->under_delegation) && (diff_fqdn->will_be_non_empty || diff_fqdn->will_have_children))
        // else it's under a delegation
        ;
}

static inline bool zone_diff_fqdn_was_covered_by__nsec3(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex ||
           (diff_fqdn->was_at_delegation && !diff_fqdn->was_under_delegation) ||  // had NS records (but is not below NS records)
           (!(diff_fqdn->was_at_delegation || diff_fqdn->was_under_delegation) && (diff_fqdn->was_non_empty || diff_fqdn->had_children))
        // else it was under a delegation
        ;
}

static inline bool zone_diff_fqdn_is_covered_by_nsec3_optout(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex ||
           (diff_fqdn->at_delegation && !diff_fqdn->under_delegation && diff_fqdn->will_have_ds) ||  // has DS record(s)
           (!(diff_fqdn->at_delegation || diff_fqdn->under_delegation) && (diff_fqdn->will_be_non_empty || diff_fqdn->will_have_children))
        // else it's under a delegation
        ;
}

static inline bool zone_diff_fqdn_was_covered_by_nsec3_optout(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex ||
           (diff_fqdn->was_at_delegation && !diff_fqdn->was_under_delegation && diff_fqdn->had_ds) ||  // had DS record(s)
           (!(diff_fqdn->was_at_delegation || diff_fqdn->was_under_delegation) && (diff_fqdn->was_non_empty || diff_fqdn->had_children))
        // else it was under a delegation
        ;
}

static inline bool zone_diff_fqdn_is_covered_by_nsec(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex || (!diff_fqdn->under_delegation && (diff_fqdn->will_be_non_empty /*|| diff_fqdn->will_have_children*/));
}

static inline bool zone_diff_fqdn_was_covered_by_nsec(const zone_diff_fqdn *diff_fqdn)
{
    return diff_fqdn->is_apex || (!diff_fqdn->was_under_delegation && (diff_fqdn->was_non_empty /*|| diff_fqdn->will_have_children*/));
}

/**
 * debug
 *
 * @param rr_set
 * @param origin
 * @param handle
 * @param level
 */


void zone_diff_fqdn_rr_set_log(const zone_diff_fqdn_rr_set *rr_set, const u8* origin, struct logger_handle *handle, int level);

/**
 * debug
 * 
 * @param origin
 * @param diff_fqdn
 * @param level
 */

void zone_diff_fqdn_log(const zone_diff_fqdn* diff_fqdn, const u8 *origin, struct logger_handle *handle, int level);

/**
 * debug
 *
 * @param diff
 * @param handle
 * @param level
 */

void zone_diff_log(const zone_diff *diff, struct logger_handle *handle, int level);

/**
 * debug
 *
 * @param diff
 * @param handle
 * @param level
 */

int  zone_diff_check_changes(const zone_diff *diff, struct logger_handle *handle, int level);

/**
 * Signs RRSET with all active keys found in keys.
 * Doesn't do any pertinence tests.
 * It's only use now is to add RRSIG records to NSEC3 rrsets that have no valid signatures
 *
 */

void zone_diff_sign_rrset(zone_diff *diff, zdb_zone *zone, ptr_vector *keys, ptr_vector *add, zone_diff_fqdn_rr_set *rr_set, zone_diff_fqdn_rr_set *rrsig_rr_set);

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

ya_result zone_diff_sign(zone_diff *diff, zdb_zone *zone, ptr_vector *rrset_to_sign_vector, ptr_vector *ksks, ptr_vector *zsks, ptr_vector *remove, ptr_vector* add);

/**
 * Finalises a zone diff
 * 
 * @param diff
 */

void zone_diff_finalize(zone_diff *diff);

zone_diff_label_rr *zone_diff_label_rr_new(const u8 *fqdn, u16 rtype, u16 rclass, s32 ttl, void *rdata, u16 rdata_size, bool copy);
zone_diff_label_rr *zone_diff_label_rr_new_nordata(const u8 *fqdn, u16 rtype, u16 rclass, s32 ttl, u16 rdata_size);

void zone_diff_label_rr_init_tmp(zone_diff_label_rr *rr, const u8 *fqdn, u16 rtype, u16 rclass, s32 ttl, void *rdata, u16 rdata_size);

zone_diff_fqdn *zone_diff_fqdn_add_empty(zone_diff *diff, const u8 *fqdn);
zone_diff_fqdn *zone_diff_fqdn_add(zone_diff *diff, const u8 *fqdn, zdb_rr_label *label);
zone_diff_fqdn* zone_diff_add_static_fqdn(zone_diff *diff, const u8 *fqdn, zdb_rr_label *label);
void zone_diff_add_fqdn_children(zone_diff *diff, const u8 *fqdn, zdb_rr_label *label);

struct nsec3_node;

zone_diff_fqdn* zone_diff_add_nsec3(zone_diff *diff, const nsec3_zone* n3, const struct nsec3_node *item, s32 ttl, zone_diff_fqdn_rr_set **out_nsec3_rrset);

zone_diff_fqdn* zone_diff_add_nsec3_ex(zone_diff *diff, const ptr_vector *zsk_keys, const nsec3_zone* n3, const struct nsec3_node *item, s32 ttl, zone_diff_fqdn_rr_set **out_nsec3_rrset, s32 now, s32 regeneration);

// to detect empty non-terminals
bool zone_diff_fqdn_has_children(zone_diff *diff, const u8 *fqdn);



/**
 * Enables the or_state flags in every record of the set.
 * 
 * @param rrset
 * @param or_state
 */

void zone_diff_fqdn_rr_set_set_state(zone_diff_fqdn_rr_set *rrset, u8 or_state);

/**
 * Returns true iff an rrset of the given type will be present after applying
 * the diff.
 * 
 * @param diff_fqdn
 * @param rtype
 * @return 
 */

bool zone_diff_will_have_rrset_type(const zone_diff_fqdn *diff_fqdn, u16 rtype);

bool zone_diff_remove_rrset_type(zone_diff_fqdn *diff_fqdn, u16 rtype);


/**
 * Releases keys that will not be in the apex after the diff is applied.
 * 
 * @param diff
 * @param keys
 */

void zone_diff_filter_out_keys(const zone_diff *diff, ptr_vector *keys);

zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_set_add(zone_diff_fqdn *diff_fqdn, u16 rtype);

/**
 * Returns the local copy of the specified RRSET
 * DOES NOT create an emtpy set if it does not exist.
 *
 * @param diff_fqdn
 * @param rtype
 * @return 
 */

zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_set_get(const zone_diff_fqdn *diff_fqdn, u16 rtype);

/**
 * Returns the local copy of the specified RRSET
 *
 * @param diff_fqdn
 * @param rtype
 * @return
 */

const zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_get_const(const zone_diff_fqdn *diff_fqdn, u16 rtype);

zone_diff_fqdn_rr_set *zone_diff_fqdn_rr_get_if_exists(const zone_diff_fqdn *diff_fqdn, u16 rtype);

/**
 * Returns the TTL of the RRSET if it exists
 *
 * @param rrset
 * @return
 */

s32 zone_diff_fqdn_rr_set_get_ttl(zone_diff_fqdn_rr_set *rrset);

/**
 * Returns the TTL of the RRSET if it exists
 *
 * @param diff_fqdn
 * @param rtype
 * @return
 */

s32 zone_diff_fqdn_rr_get_ttl(const zone_diff_fqdn *diff_fqdn, u16 rtype);

// Adds a record, if the record exists already in the set, delete the one in the set

void zone_diff_fqdn_rr_set_rr_add_replace(zone_diff_fqdn_rr_set *rr_set, zone_diff_label_rr *rr);

// Adds a record, if the record exists already in the set, delete the record and returns the one in the set

zone_diff_label_rr* zone_diff_fqdn_rr_set_rr_add_get(zone_diff_fqdn_rr_set *rr_set, zone_diff_label_rr *rr);

/**
 * Deletes an RRSET if it's empty.
 * 
 * @param diff_fqdn
 * @param rtype
 */

void zone_diff_fqdn_rr_clear(zone_diff_fqdn *diff_fqdn, u16 rtype);

/**
 * Returns TRUE iff an rrset as been added or removed from the label.
 * Stressing out this concerns RRSET as a whole.
 * 
 * @param diff_fqdn
 * @return 
 */

bool zone_diff_fqdn_type_map_changed(const zone_diff_fqdn *diff_fqdn);

/**
 * find label for fqdn ...
 * 
 * @param diff
 * @param fqdn
 * @param label
 * @return 
 */

const zone_diff_fqdn *zone_diff_fqdn_get_const(const zone_diff *diff, const u8 *fqdn);

zone_diff_fqdn* zone_diff_fqdn_get(const zone_diff *diff, const u8 *fqdn);

/**
 * Generates a type bit map based on the diff including records matching:
 *
 * (status & mask) == masked
 *
 * mask,masked
 *      all pre records : ZONE_DIFF_REMOVE|ZONE_DIFF_ADD == 0
 *      all post records: ZONE_DIFF_REMOVE = 0
 *
 * Note: it ignores the A and AAAA records when at or under a delegation.
 *
 * @param diff
 * @param fqdn
 * @param bitmap
 * @param mask
 * @param masked
 * @return
 */

u16 zone_diff_type_bit_map_generate(const zone_diff *diff, const u8 *fqdn, type_bit_maps_context *bitmap, u8 mask,
                                    u8 masked, const u8 *chain_node_fqdn, bool append_existing_signatures);

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

zone_diff_label_rr* zone_diff_record_add(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn, u16 rtype, s32 rttl, u16 rdata_size, void *rdata);

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

void zone_diff_record_remove(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn, u16 rtype, s32 rttl, u16 rdata_size, void *rdata);

bool zone_diff_record_remove_existing(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn, u16 rtype, s32 rttl, u16 rdata_size, void *rdata);

void zone_diff_record_remove_automated(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn, u16 rtype, s32 rttl, u16 rdata_size, void *rdata);

/**
 * Adds the removal of a record set on a diff
 * 
 * @param diff
 * @param rr_label
 * @param fqdn
 * @param rtype
 */

void zone_diff_record_remove_all(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn, u16 rtype);

/**
 * Adds the removal all record sets on a diff
 * 
 * @param diff
 * @param rr_label
 * @param fqdn
 * @param rtype
 */

void zone_diff_record_remove_all_sets(zone_diff *diff, zdb_rr_label *rr_label, const u8 *fqdn);

static inline s32 diff_generate_signature_interval(zone_diff *diff)
{
    s32 maxinterval = diff->rrsig_validity_interval + rand() % (diff->rrsig_validity_jitter + 1);
    return maxinterval;
}

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

ya_result dynupdate_diff_write_to_journal_and_replay(zdb_zone *zone, u8 secondary_lock, ptr_vector *del_vector, ptr_vector *add_vector);

void zone_diff_store_diff_dnskey_get_keys(zone_diff *diff, ptr_vector *ksks, ptr_vector *zsks);

/**
 * 
 */

ya_result dynupdate_diff(zdb_zone *zone, packet_unpack_reader_data *reader, u16 count, u8 secondary_lock, bool dryrun);
/*
ya_result dynupdate_diff_chain(zdb_zone *zone, u8 secondary_lock)
{
    zone_diff diff;
    zone_diff_init(&diff, zone->origin, zone->min_ttl);
    zone_diff_fqdn* diff_fqdn = zone_diff_add_fqdn(&diff, fqdn, zdb_rr_label *label)
    zone_diff_finalize(&diff);
}
*/

/**
 * Adds a node to the chain from a zone_diff_fqdn
 * 
 * @param dc
 * @param fqdn
 * @param rtype
 * 
 * @return number of operations counted
 */

int dnssec_chain_add_from_diff_fqdn(dnssec_chain *dc, const zone_diff_fqdn* diff_fqdn, u16 rtype);

/**
 * Removes a node from the chain from a zone_diff_fqdn
 * 
 * @param dc
 * @param fqdn
 * @param rtype
 * 
 * @return number of operations counted
 */

int dnssec_chain_del_from_diff_fqdn(dnssec_chain *dc, const zone_diff_fqdn* diff_fqdn, u16 rtype);

void zone_diff_record_state_format(const void* data, output_stream* os, s32 a, char b , bool c, void* reserved_for_method_parameters);

/** @} */


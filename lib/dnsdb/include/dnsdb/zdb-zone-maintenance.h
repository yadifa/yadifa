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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#pragma once

#include <dnsdb/zdb_types.h>
#include <dnsdb/nsec.h>
#include <dnsdb/nsec3.h>
#include <dnsdb/dynupdate-diff.h>

// struct dnssec_chain

#include <dnscore/dnskey.h>

#ifdef	__cplusplus
extern "C"
{
#endif
    
#define ZDB_ZONE_MAINTENANCE_NSEC3CHAIN_MAX 16
    
struct zdb_zone_maintenance_ctx
{
    dnssec_chain nsec_chain_updater;    // @note 20170119 edf -- Given recent changes, and depending on the post-processing, I may be able to handle NSEC & NSEC3 chains with a single (modified) object.
    dnssec_chain nsec3_chains_updater;
    nsec3_zone* nsec3_chain[ZDB_ZONE_MAINTENANCE_NSEC3CHAIN_MAX];
    u8 nsec3_chain_status[ZDB_ZONE_MAINTENANCE_NSEC3CHAIN_MAX];
    zdb_zone *zone;
    zdb_rr_label *label;
    
    dnssec_key_sll *keys;
    intptr ksk_mask;
    intptr zsk_mask;

    int ksk_count;
    int zsk_count;
    
    ptr_vector ksks;
    ptr_vector zsks;
    
    time_t now;
    u8 nsec_chain_status;
    u8 nsec3_chain_count;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    dnsname_stack fqdn_stack;
};

typedef struct zdb_zone_maintenance_ctx zdb_zone_maintenance_ctx;
 
ya_result zdb_zone_maintenance(zdb_zone* zone);

ya_result zdb_zone_sign(zdb_zone* zone);

/**
 * Called by zdb_zone_maintenance
 * 
 * Marks record sets that needs to be updated.
 * Removes expired signatures.
 *  
 * @param mctx
 * @return 
 */

ya_result zdb_zone_maintenance_rrsig(zdb_zone_maintenance_ctx* mctx, zone_diff_fqdn *diff_fqdn, ptr_vector *rrset_to_sign);

/**
 * Called by zdb_zone_maintenance
 * 
 * Updates the signatures of a zone incrementally.
 * Each call goes a bit further.
 * 
 * @param zone
 * @param signature_count_loose_limit
 * @param present_signatures_are_verified
 * @return the number of actions counted
 */

int zdb_zone_maintenance_nsec(zdb_zone_maintenance_ctx* mctx, const zone_diff_fqdn *diff_fqdn, ptr_vector *rrset_to_sign);

/**
 * Called by zdb_zone_maintenance
 * 
 * Updates the signatures of a zone incrementally.
 * Each call goes a bit further.
 * 
 * @param zone
 * @param signature_count_loose_limit
 * @param present_signatures_are_verified
 * @return the number of actions counted
 */

int zdb_zone_maintenance_nsec3(zdb_zone_maintenance_ctx* mctx, const zone_diff_fqdn *diff_fqdn);

void zdb_zone_maintenance_nsec3_add_rrsig_type(zone_diff *diff, zdb_zone *zone, ptr_vector *rrset_to_sign_vector, ptr_vector *ksks, ptr_vector *zsks, ptr_vector *remove, ptr_vector* add, zone_diff_fqdn *covered_diff_fqdn);

void zdb_zone_maintenance_nsec3_remove_rrsig_type(zone_diff *diff, zdb_zone *zone, ptr_vector *rrset_to_sign_vector, ptr_vector *ksks, ptr_vector *zsks, ptr_vector *remove, ptr_vector* add, zone_diff_fqdn *covered_diff_fqdn);


#ifdef	__cplusplus
}
#endif

/** @} */

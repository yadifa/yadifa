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

#pragma once

#include <dnscore/dnsname.h>

#include <dnsdb/zdb_rr_label.h>

#include <dnsdb/nsec3_types.h>

#include <dnsdb/nsec3_hash.h>
#include <dnsdb/nsec3_item.h>
#include <dnsdb/nsec3_load.h>
#include <dnsdb/nsec3_name_error.h>
#include <dnsdb/nsec3_nodata_error.h>
#include <dnsdb/nsec3_owner.h>
#include <dnsdb/nsec3_zone.h>

/**
 * Set this to 1 to dump a lot more about the NSEC3 updates/generation.
 * I use this whenever something weird happens with NSEC3.
 * (It seems bind is more liberal about handling broken/invalid NSEC3 databases,
 * YADIFA only accepts valid ones)
 */

#define NSEC3_UPDATE_ZONE_DEBUG 0

/**
 * Used to be like this (NSEC3_INCLUDE_ZONE_PATH 1) with older bind
 * Not anymore in 9.7.1 (probably since 9.7.x)
 * Set this to 1 to comply with that old bind issue. (not recommended)
 * 
 */

#define NSEC3_INCLUDE_ZONE_PATH 0

#ifndef DEBUG
#undef NSEC3_UPDATE_ZONE_DEBUG
#define NSEC3_UPDATE_ZONE_DEBUG  0
#endif

#define NSEC3_LABEL_DEBUG 1

#ifdef	__cplusplus
extern "C"
{
#endif

    /* The biggest allowed label is 63 bytes. Let's assume 64. =>
     * Since the digest is base32hex encoded, is un-encoded size is max (64/8)*5 = 40 bytes.
     * This covers more than a SHA-256 (32 bytes), but it (40) should be the upper bound.
     */

#define MAX_DIGEST_LENGTH  40
#define MAX_SALT_LENGTH   255
    
#define NSEC3_DIGEST_ALGORITHM_SHA1 1
    
#define NSEC3_RDATA_IS_OPTIN(__rdata__) ((((u8*)(__rdata__))[1]&NSEC3_FLAGS_OPTOUT) == 0)
#define NSEC3_RDATA_IS_OPTOUT(__rdata__) ((((u8*)(__rdata__))[1]&NSEC3_FLAGS_OPTOUT) != 0)
#define NSEC3_RDATA_ALGORITHM(__rdata__) (((u8*)(__rdata__))[0])
    
#define TYPE_NSEC3PARAMADD   NU16(0xff00)
#define TYPE_NSEC3PARAMDEL   NU16(0xff01)
#define TYPE_NSEC3CHAINSTATE NU16(0xff02)

/* Adds an NSEC3PARAM in a zone (no dups), adds the struct too  */
ya_result nsec3_add_nsec3param(zdb_zone* zone, u8 default_hash_alg, u8 default_flags, u16 default_iterations, u8 default_salt_len, u8* default_salt);

/* Removes an NSEC3PARAM from a zone, along with the struct.  nsec3_remove_nsec3param_by_record does almost the same. (ixfr) */
ya_result nsec3_remove_nsec3param(zdb_zone* zone, u8 hash_alg, u8 flags, u16 iterations, u8 salt_len, const u8* salt);

/**
 * 
 * Links a label to already existing nsec3 items
 * 
 * This function is for when a label has been added "without intelligence".
 * It will find if the function has got a matching NSEC3 record (by digest)
 * If so, it will link to it.
 * 
 * @param n3
 * @param label
 * @param fqdn
 */

void nsec3_zone_label_update_chain0_links(nsec3_zone *n3, zdb_rr_label* label, const u8 *fqdn);

/**
 * Updates links for the first NSEC3 chain of the zone
 * Only links to existing NSEC3 records.
 * Only links label with an extension and self/wild set to NULL
 * 
 * @param zone
 */

void nsec3_zone_update_chain0_links(zdb_zone *zone);

void nsec3_destroy_zone(zdb_zone* zone);

/**
 * This sets the flags of each NSEC3PARAM of the zone
 * Please use nsec3_edit_zone_start and nsec3_edit_zone_end
 *
 */

void nsec3_set_nsec3param_flags(zdb_zone* zone, u8 flags);

const zdb_rr_label* nsec3_get_closest_provable_encloser(
                    const zdb_rr_label* apex,
                    const_dnslabel_vector_reference sections,
                    s32* sections_topp);

void nsec3_closest_encloser_proof(
                    const zdb_zone *zone,
                    const dnsname_vector *qname, s32 apex_index,
                    const nsec3_zone_item **encloser_nsec3p,
                    const nsec3_zone_item **closest_provable_encloser_nsec3p,
                    const nsec3_zone_item **wild_closest_provable_encloser_nsec3p
                    );

#if NSEC3_LABEL_DEBUG
/**
 * Verifies the coherence of the nsec3 database of a zone
 * 
 * @param zone
 * 
 */

void nsec3_check(zdb_zone *zone);
#endif

/**
 * For generates the digest label name of an fqdn for a specified NSEC3PARAM chain
 * 
 * @param n3 the NSEC3PARAM chain
 * @param fqdn the name to digest
 * @param fqdn_len the size of the name of the digest
 * @param out_digest the resulting digest in a Pascal kind of format (1 byte length, then the bytes)
 * 
 * 1 use (zdb_zone_load)
 */

void nsec3_compute_digest_from_fqdn_with_len(const nsec3_zone *n3, const u8 *fqdn, u32 fqdn_len, u8 *digest, bool isstar);

// 1 -> 3 -> 9 => 4
#define NSEC3_ZONE_DISABLED      0
#define NSEC3_ZONE_ENABLED       1
#define NSEC3_ZONE_GENERATING    2
#define NSEC3_ZONE_REMOVING      4
// #define NSEC3_ZONE_REMOVING   8 signing chain

/**
 * Sets the NSEC3 maintenance status for a specific chain.
 * Marks the zone using private records.
 * 
 * @param zone
 * @param algorithm
 * @param optout
 * @param salt
 * @param salt_len
 * @param iterations
 * @param status
 * @return 
 */

ya_result nsec3_zone_set_status(zdb_zone *zone, u8 secondary_lock, u8 algorithm, u8 optout, u16 iterations, const u8 *salt, u8 salt_len, u8 status);

/**
 * Gets the NSEC3 maintenance status for a specific chain.
 * Get the information from the zone using private records.
 * 
 * @param zone
 * @param algorithm
 * @param optout
 * @param salt
 * @param salt_len
 * @param iterations
 * @param status
 * @return 
 */

ya_result nsec3_zone_get_status(zdb_zone *zone, u8 algorithm, u8 optout, u16 iterations, const u8 *salt, u8 salt_len, u8 *statusp);

/**
 * Gets the NSEC3 maintenance status for a specific chain.
 * Get the information from the zone using private records.
 * 
 * The zone must be locked.
 * 
 * @param zone
 * @param rdata
 * @param rdata_size
 * @param statusp
 * @return 
 */

ya_result nsec3_zone_get_status_from_rdata(zdb_zone *zone, const u8 *rdata, u16 rdata_size, u8 *statusp);

/**
 * Returns the number of known chains in the zone.
 * Inactive chains are also counted.
 * Zone must be locked.
 * 
 * @param zone
 * @return 
 */

int nsec3_zone_get_chain_count(zdb_zone *zone);

/**
 * Returns pointers to the chains from the zone.
 * Inactive chains are also counted.
 * Zone must be locked.
 * 
 * @param zone
 * @param n3p
 * @param max_count
 * @return 
 */

int nsec3_zone_get_chains(zdb_zone *zone, nsec3_zone **n3p, int max_count);


    
#ifdef	__cplusplus
}
#endif

/** @} */

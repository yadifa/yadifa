/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
#ifndef _NSEC3_H
#define	_NSEC3_H

#include <dnscore/dnsname.h>

#include <dnsdb/nsec3_types.h>

#include <dnsdb/nsec3_hash.h>
#include <dnsdb/nsec3_item.h>
#include <dnsdb/nsec3_icmtl.h>
#include <dnsdb/nsec3_load.h>
#include <dnsdb/nsec3_name_error.h>
#include <dnsdb/nsec3_nodata_error.h>
#include <dnsdb/nsec3_owner.h>
#include <dnsdb/nsec3_update.h>
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
 * Set this to 1 to comply with that old bind issue.
 * 
 */

#define NSEC3_INCLUDE_ZONE_PATH 0

#ifndef DEBUG
#undef NSEC3_UPDATE_ZONE_DEBUG
#define NSEC3_UPDATE_ZONE_DEBUG  0
#endif


#ifdef	__cplusplus
extern "C"
{
#endif

    /* The biggest allowed label is 63 bytes. Let's assume 64. =>
     * Since the digest is base32hex encoded, is unencoded size is max (64/8)*5 = 40 bytes.
     * This covers more than a SHA-256 (32 bytes), but it (40) should be the upper bound.
     */

#define MAX_DIGEST_LENGTH  40
#define MAX_SALT_LENGTH   255
    
#define NSEC3_RDATA_IS_OPTIN(__rdata__) ((((u8*)(__rdata__))[1]&1) == 0)
#define NSEC3_RDATA_IS_OPTOUT(__rdata__) ((((u8*)(__rdata__))[1]&1) != 0)
#define NSEC3_RDATA_ALGORITHM(__rdata__) (((u8*)(__rdata__))[0])

    /* Adds an NSEC3PARAM in a zone (no dups), adds the struct too  */
    ya_result nsec3_add_nsec3param(zdb_zone* zone, u8 default_hash_alg, u8 default_flags, u16 default_iterations, u8 default_salt_len, u8* default_salt);

    /* Remvoes an NSEC3PARAM from a zone, along with the struct.  nsec3_remove_nsec3param_by_record does almost the same. (ixfr) */
    ya_result nsec3_remove_nsec3param(zdb_zone* zone, u8 hash_alg, u8 flags, u16 iterations, u8 salt_len, const u8* salt);

    void nsec3_update_label_update_record(zdb_zone* zone, zdb_rr_label* label, u16 type);

    /**
     * Update the NSEC3 record on a label.
     * If there is no such record, calls nsec3_add_label
     * Note: Calling this on a non-NSEC3 (ie: basic or NSEC) zone will lead to a crash
     *
     * @param zone
     * @param label
     * @param labels
     * @param labels_top
     * 
     * @return TRUE if a change occurred, FALSE otherwise
     */

    bool nsec3_update_label(zdb_zone* zone, zdb_rr_label* label, dnslabel_vector_reference labels, s32 labels_top);

    void nsec3_add_label(zdb_zone* zone, zdb_rr_label* label, dnslabel_vector_reference labels, s32 labels_top);
    
    void nsec3_remove_label(zdb_zone* zone, zdb_rr_label* label);

    /**
     * This function is for when a label has been added "without intelligence".
     * It will find if the function has got a matching NSEC3 record (by digest)
     * If so, it will link to it.
     */

    void nsec3_label_link(zdb_zone* zone, zdb_rr_label* label, const u8 *fqdn);

    void nsec3_destroy_zone(zdb_zone* zone);

    /**
     * This sets the flags of each NSEC3PARAM of the zone
     * Please use nsec3_edit_zone_start and nsec3_edit_zone_end
     *
     */

    void nsec3_set_nsec3param_flags(zdb_zone* zone, u8 flags);

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

    void nsec3_edit_zone_start(zdb_zone* zone);

    /**
     * This sets the flags of each NSEC3PARAM of the zone to 0
     * This should be called after modifying an NSEC3 zone.
     *
     */

    void nsec3_edit_zone_end(zdb_zone* zone);

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

    bool nsec3_check_item(nsec3_zone_item *item, u32 param_index);

    bool nsec3_check(zdb_zone *zone);

    void nsec3_compute_digest_from_fqdn(const nsec3_zone *n3, const u8 *fqdn, u8 *out_digest);
    
#ifdef	__cplusplus
}
#endif

#endif	/* _NSEC3_H */

/** @} */

/*----------------------------------------------------------------------------*/



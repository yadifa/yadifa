/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @defgroup zone Functions used to manipulate a zone
 * @ingroup dnsdb
 * @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 *----------------------------------------------------------------------------*/

#ifndef _ZDB_SANITIZE_H
#define _ZDB_SANITIZE_H

#include <dnsdb/zdb_zone.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define SANITY_ERROR_BASE           0x800b0000

#define SANITY_UNEXPECTEDSOA        1 // multiple SOA at apex, or SOA(s) oustide of APEX
#define SANITY_MUSTDROPZONE         2
#define SANITY_CNAMENOTALONE        4  // other records along CNAME (only NSEC & RRSIG accepted) of course CNAME is forbidden at APEX
#define SANITY_UNEXPECTEDCNAME      8  // CNAME at apex
#define SANITY_EXPECTEDNS           16 // no NS at apex or DS found without NS
#define SANITY_UNEXPECTEDDS         32 // DS found at APEX
#define SANITY_TRASHATDELEGATION    64
#define SANITY_TRASHUNDERDELEGATION 128
#define SANITY_RRSIGTTLDOESNTMATCH  256 // RRSIG original TTL does not match RRSET
#define SANITY_RRSIGWITHOUTKEYS     512
#define SANITY_RRSIGWITHOUTSET      1024  // RRSIG covers a record set that's not present in the label
#define SANITY_RRSIGOVERRRSIG       2048  // RRSIG covers the RRSIG record set (nonsense)
#define SANITY_RRSIGUNDERDELETATION 4096  // RRSIG under a delegation
#define SANITY_RRSIGBYKSKOVERNONKEY 8192  // RRSIG by a KSK over a type that's not a DNSKEY
#define SANITY_RRSIGBYKSKNOTINAPEX  16384 // RRSIG by a KSK should only appear in APEX (and over a DNSKEY)
#define SANITY_LABEL_DELETED        32768

struct zdb_zone_load_parms;

struct zdb_sanitize_dnskey_algorithm_recommendations_s
{
    bool has_wrong;
    bool has_must_not;
    bool has_not_recommended;
};

typedef struct zdb_sanitize_dnskey_algorithm_recommendations_s zdb_sanitize_dnskey_algorithm_recommendations_t;

struct zdb_sanitize_ds_digest_recommendations_s
{
    bool has_wrong;
    bool has_must_not;
};

typedef struct zdb_sanitize_ds_digest_recommendations_s zdb_sanitize_ds_digest_recommendations_t;

struct zdb_sanitize_parms
{
    zdb_zone_t *zone;
#if ZDB_HAS_DNSSEC_SUPPORT
    u32_treemap_t dnskey_set;
#endif
    struct zdb_zone_load_parms *load_parms;
    uint64_t                    types_mask;
    uint32_t                    domains;
#if ZDB_HAS_DNSSEC_SUPPORT
    uint32_t                                        nsec_extraneous_rrsig;
    uint32_t                                        nsec3in_extraneous_rrsig;
    uint32_t                                        nsec3out_extraneous_rrsig;

    uint32_t                                        nsec_missing_rrsig;
    uint32_t                                        nsec3in_missing_rrsig;
    uint32_t                                        nsec3out_missing_rrsig;
    bool                                            has_bogus_rrsig;

    zdb_sanitize_dnskey_algorithm_recommendations_t dnskey_algorithm;
    zdb_sanitize_ds_digest_recommendations_t        ds_digest;
    zdb_sanitize_ds_digest_recommendations_t        cds_digest;
#endif
};

typedef struct zdb_sanitize_parms zdb_sanitize_parms;

ya_result                         zdb_sanitize_rr_set(zdb_zone_t *zone, zdb_rr_label_t *label);

ya_result                         zdb_sanitize_rr_label(zdb_zone_t *zone, zdb_rr_label_t *label, dnsname_stack_t *name);

ya_result                         zdb_sanitize_rr_label_with_parent(zdb_zone_t *zone, zdb_rr_label_t *label, dnsname_stack_t *name);

ya_result                         zdb_sanitize_zone_ex(zdb_zone_t *zone, struct zdb_zone_load_parms *load_parms);

ya_result                         zdb_sanitize_zone(zdb_zone_t *zone);

void                              zdb_sanitize_parms_finalize(zdb_sanitize_parms *parms);

void                              zdb_sanitize_log_recommendations(struct zdb_zone_load_parms *load_parms, const char *prefix);
/**
 * @param load_parms
 * @param dnssec_modes ZDB_ZONE_NOSEC ZDB_ZONE_NSEC ZDB_ZONE_NSEC3 ZDB_ZONE_NSEC3_OPTOUT
 */

bool      zdb_sanitize_is_good(struct zdb_zone_load_parms *load_parms, uint8_t dnssec_mode);

ya_result zdb_sanitize_zone_rrset_flags(zdb_zone_t *zone);

#ifdef __cplusplus
}
#endif

#endif /* _ZDB_ZONE_H */

/** @} */

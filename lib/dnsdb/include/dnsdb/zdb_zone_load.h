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
#include <dnscore/zone_reader.h>
#include <dnsdb/zdb_sanitize.h>

#ifdef	__cplusplus
extern "C"
{
#endif

/**
 * @brief Load a zone in the database.
 *
 * Load a zone in the database.
 * This is clearly MASTER oriented.
 *
 * @param[in] db a pointer to the database
 * @param[in] filename a pointer to the filename of the zone
 * @param[out] zone_pointer_out will contains a pointer to the loaded zone if the call is successful
 *
 * @return an error code.
 *
 */

#define ZDB_ZONE_NO_MAINTENANCE     0x01   // do not maintain the zone DNSSEC state
#define ZDB_ZONE_REPLAY_JOURNAL     0x02   // replay the journal after the load
#define ZDB_ZONE_DESTROY_JOURNAL    0x04   // destroys the journal after a successful load
#define ZDB_ZONE_IS_SLAVE           0x08   // any NSEC3 inconsistencies must trigger an AXFR reload

#define ZDB_ZONE_DNSSEC_SHIFT           4
#define ZDB_ZONE_DNSSEC_MASK       0x0070
#define ZDB_ZONE_NOSEC             0x0000
#define ZDB_ZONE_NSEC              0x0010
#define ZDB_ZONE_NSEC3             0x0020
#define ZDB_ZONE_NSEC3_OPTOUT      0x0030

struct zdb_zone_load_dnskey_id_fields
{
    u16 tag;
    u8 algorithm;
    u8 must_be_zero;
};

union zdb_zone_load_dnskey_id
{
    u32 id;
    struct zdb_zone_load_dnskey_id_fields fields;
};

#define ZDB_ZONE_LOAD_DNSKEY_STATE_FLAG_HAS_PUBKEY 1
#define ZDB_ZONE_LOAD_DNSKEY_STATE_FLAG_HAS_PRIVKEY 2
#define ZDB_ZONE_LOAD_DNSKEY_STATE_FLAG_MISSING_SIGNATURES 4

#define ZDB_ZONE_LOAD_STATE_SANITIZE_FIELD_AVAIABLE 8
#define ZDB_ZONE_LOAD_STATE_SANITIZE_SUMMARY_AVAILABLE 16
#define ZDB_ZONE_LOAD_STATE_SANITIZE_SUMMARY_MAINTENANCE_REQUIRED 32
#define ZDB_ZONE_LOAD_STATE_SANITIZE_SUMMARY_NSEC3_CHAIN_FIXED 64

#define ZZLDSKEY_TAG 0x59454b53444c5a5a

struct zdb_zone_load_dnskey_state_for_key
{
    s32 signed_until;
    s32 signed_from;
    u32 rrsig_count;
    u16 key_flags;
    u8 flags;
};

typedef u32_set zdb_zone_load_dnskey_state;

struct zdb_zone_load_parms
{
    zone_reader *zr;
    const u8 *expected_origin;
    zdb_zone_load_dnskey_state dnskey_state;
    zdb_zone *out_zone;
    struct zdb_sanitize_parms sanitize_parms;
    ya_result result_code;
    u16 flags;
    u16 state;
    u8 expected_dnssec;
};

void zdb_zone_load_parms_init(struct zdb_zone_load_parms *parms, zone_reader *zr, const u8 *expected_origin, u16 flags);
void zdb_zone_load_parms_dnskey_add(struct zdb_zone_load_parms *parms, const u8 *dnskey_rdata, u16 dnskey_rdata_size);
u16  zdb_zone_load_parms_get_key_flags_from_rrsig_rdata(struct zdb_zone_load_parms *parms, const u8 *rrsig_rdata, u16 rrsig_rdata_size);
void zdb_zone_load_parms_rrsig_add(struct zdb_zone_load_parms *parms, const u8 *rrsig_rdata, u16 rrsig_rdata_size);
zdb_zone *zdb_zone_load_parms_zone_detach(struct zdb_zone_load_parms *parms);
zdb_zone *zdb_zone_load_parms_zone_get(struct zdb_zone_load_parms *parms);
ya_result zdb_zone_load_parms_result_code(struct zdb_zone_load_parms *parms);
void zdb_zone_load_parms_finalize(struct zdb_zone_load_parms *parms);

ya_result zdb_zone_load_ex(struct zdb_zone_load_parms *parms);

/**
 * @brief Load a zone file.
 *
 * Load a zone file.
 *
 * @note It is not a good idea to scan the zone content in here. ie: getting the earliest signature expiration. (It's counter-productive and pointless)
 *
 * @param[in] db_UNUSED a pointer to the database, obsolete, should be set to NULL
 * @param[in] zr a pointer to an opened zone_reader
 * @param[in] zone_pointer_out a pointer to the pointer that will be set with the loaded zone
 * @param[in] expected_origin the expected origin for the loaded file, can be set to NULL
 * @param[in] flags various flags
 *
 * @return an error code.
 *
 */

ya_result zdb_zone_load(zdb* db_UNUSED, zone_reader* zr, zdb_zone** zone_out, const u8 *expected_origin, u16 flags);

/**
 * @brief Load the zone SOA.
 *
 * Load the zone SOA record
 * This is meant mainly for the slave that could choose between, ie: zone file or axfr zone file
 * The SOA MUST BE the first record
 *
 * @param[in] db a pointer to the database
 * @param[in] zone_data a pointer to an opened zone_reader at its start
 * @param[out] zone_pointer_out will contains a pointer to the loaded zone if the call is successful
 *
 * @return an error code.
 *
 */
ya_result zdb_zone_get_soa(zone_reader *zone_data, u16 *rdata_size, u8 *rdata);

#ifdef	__cplusplus
}
#endif

/** @} */

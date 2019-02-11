/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2019, EURid vzw. All rights reserved.
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

#ifndef _ZDB_ZONE_H
#define	_ZDB_ZONE_H

#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>

#if HAS_DNSSEC_SUPPORT
#include <dnscore/dnskey.h>
#endif

#include <dnsdb/zdb_types.h>
#include <dnsdb/dnsrdata.h>

#include <dnsdb/zdb-zone-lock.h>
#include <dnsdb/zdb-zone-arc.h>

#if ZDB_HAS_NSEC3_SUPPORT
#include <dnsdb/nsec3_types.h>
#include <dnsdb/zdb_record.h>
#endif

#ifdef	__cplusplus
extern "C"
{
#endif

#define ZDB_ZONETAG 0x454e4f5a52445a /* "ZDBZONE" */

/**
 * @brief Get the zone with the given name
 *
 * Get the zone with the given name
 *
 * @param[in] db a pointer to the database
 * @param[in] exact_match_origin the name of the zone
 *
 * @return a pointer to zone or NULL if the zone is not in the database
 *
 */

/* 2 USES */
zdb_zone *zdb_zone_find(zdb *db, dnsname_vector* exact_match_origin);

/**
 * @brief Get the zone with the given name
 *
 * Get the zone with the given name
 *
 * @param[in] db a pointer to the database
 * @param[in] name the name of the zone (dotted c-string)
 *
 * @return a pointer to zone or NULL if the zone is not in the database
 *
 */

zdb_zone *zdb_zone_find_from_name(zdb *db, const char* name);

/**
 * @brief Adds a record to a zone
 *
 * Adds a record to a zone.
 *
 * @param[in] zone the zone
 * @param[in] labels the stack of labels of the dns name
 * @param[in] labels_top the index of the top of the stack (the level)
 * @param[in] type the type of the record
 * @param[in] ttlrdata the ttl and rdata of the record.  NOTE: the zone becomes its new owner !!!
 */

/* 2 USES */
void zdb_zone_record_add(zdb_zone* zone, dnslabel_vector_reference labels, s32 labels_top, u16 type, zdb_packed_ttlrdata* ttlrdata); /* class is implicit */

/**
 * @brief Removes a record from a zone
 *
 * Removes a record from a zone and frees its memory.
 * 
 * In the current version (20160513) if the record itself should not be used as
 * the parameter is still used after removal for feedback to the journal.
 *
 * @param[in] zone the zone
 * @param[in] labels the stack of labels of the dns name
 * @param[in] labels_top the index of the top of the stack (the level)
 * @param[in] type the type of the record
 * @param[in] ttlrdata the ttl and rdata of the record.  NOTE: the caller stays the owner
 */

ya_result zdb_zone_record_delete(zdb_zone *zone, dnslabel_vector_reference labels, s32 labels_top, u16 type, zdb_packed_ttlrdata* packed_ttlrdata);

/**
 * @brief Removes a record from a zone
 *
 * Copies the record then removes it from the zone and frees its memory.
 * This allows removing safely a record using itself as a parameter.
 *
 * @param[in] zone the zone
 * @param[in] labels the stack of labels of the dns name
 * @param[in] labels_top the index of the top of the stack (the level)
 * @param[in] type the type of the record
 * @param[in] ttlrdata the ttl and rdata of the record.  NOTE: the caller stays the owner
 */

ya_result zdb_zone_record_delete_self(zdb_zone *zone, dnslabel_vector_reference labels, s32 labels_top, u16 type, zdb_packed_ttlrdata* packed_ttlrdata);

/**
 * @brief Search for a record in a zone
 *
 * Search for a record in a zone
 *
 * @param[in] zone the zone
 * @param[in] labels the stack of labels of the dns name
 * @param[in] labels_top the index of the top of the stack (the level)
 * @param[in] type the type of the record
 */

/* 4 USES */
zdb_packed_ttlrdata* zdb_zone_record_find(zdb_zone *zone, dnslabel_vector_reference labels, s32 labels_top, u16 type);

/**
 * @brief Creates a zone
 *
 * Creates a zone
 *
 * @param[in] zone a pointer to the zone
 */

/* 2 USES */

zdb_zone *zdb_zone_create(const u8 *origin);

/*
 * Sets a zone as invalid.
 * This will put the (content of the) zone in a garbage to be freed at some point in the future (when nolonger used)
 * Also an invalid zone ... the .axfr and journal files should probably be trashed
 * 
 */

void zdb_zone_invalidate(zdb_zone *zone);


void zdb_zone_truncate_invalidate(zdb_zone *zone);

/**
 * @brief Destroys a zone and all its content
 *
 * Destroys a zone and all its content
 *
 * @param[in] zone a pointer to the zone
 */

/* 10 USES */
void zdb_zone_destroy(zdb_zone *zone);

/**
 * @brief Copies the soa of a zone to an soa_rdata structure.
 *
 * Copies the soa of a zone to an soa_rdata structure.
 * No memory is allocated for the soa_rdata.  If the zone is destroyed,
 * the soa_rdata becomes invalid.
 *
 * @param[in] zone a pointer to the zone
 * @param[out] soa_out a pointer to an soa_rdata structure
 */

ya_result zdb_zone_getsoa(const zdb_zone *zone, soa_rdata *soa_out);

ya_result zdb_zone_getsoa_ttl_rdata(const zdb_zone* zone, u32 *ttl, u16 *rdata_size, const u8 **rdata);

/**
 * @brief Retrieve the serial of a zone
 *
 * Retrieve the serial of a zone
 *
 * @param[in] zone a pointer to the zone
 * @param[out] serial a pointer to an u32 that will get the serial
 */

ya_result zdb_zone_getserial(const zdb_zone* zone, u32 *serial);

/**
 * @brief Retrieve the minttl of a zone
 *
 * Retrieve the serial of a zone
 *
 * @param[in] zone a pointer to the zone
 * @param[out] serial a pointer to an u32 that will get the minttl
 */

static inline void zdb_zone_getminttl(const zdb_zone *zone, s32 *minttl)
{
    *minttl = zone->min_ttl;
}


#if ZDB_RECORDS_MAX_CLASS == 1
static inline u16 zdb_zone_getclass(const zdb_zone *zone)
{
    return CLASS_IN;
}

#else
static inline u16 zdb_zone_getclass(const zdb_zone *zone)
{
    return zone->zclass;
}
#endif

ya_result zdb_zone_store_axfr(zdb_zone *zone, output_stream* os);

const zdb_packed_ttlrdata *zdb_zone_get_dnskey_rrset(zdb_zone *zone);

/**
 * Tells if the apex of the zone has an NSEC3 extension
 * 
 * @param zone
 * @return 
 */

static inline bool zdb_zone_is_nsec3(const zdb_zone* zone)
{
#if ZDB_HAS_NSEC3_SUPPORT
    return (zone->apex->flags & ZDB_RR_LABEL_NSEC3) != 0;
#else
    return FALSE;
#endif
}

/**
 * Tells if the apex of the zone has an NSEC3 extension with opt-out
 * 
 * @param zone
 * @return 
 */

static inline bool zdb_zone_is_nsec3_optout(const zdb_zone* zone)
{
#if ZDB_HAS_NSEC3_SUPPORT
    return ((zone->apex->flags & ZDB_RR_LABEL_NSEC3_OPTOUT) != 0);
#else
    return FALSE;
#endif
}

/**
 * Tells if the apex of the zone has an NSEC3 extension without opt-out
 * 
 * @param zone
 * @return 
 */

static inline bool zdb_zone_is_nsec3_optin(const zdb_zone* zone)
{
#if ZDB_HAS_NSEC3_SUPPORT
    return ((zone->apex->flags & ZDB_RR_LABEL_NSEC3_OPTOUT) == 0);
#else
    return FALSE;
#endif
}

#if ZDB_HAS_NSEC3_SUPPORT

/**
 * Returns the nth nsec3 chain or NULL if the chain does not exists
 * 
 * @param zone
 * @param idx
 * @return 
 */

static inline nsec3_zone* zdb_zone_get_nsec3chain(const zdb_zone *zone, s8 idx)
{
    nsec3_zone *n3 = zone->nsec.nsec3;
    while(n3 != NULL && --idx >= 0)
    {
        n3 = n3->next;
    }
    return n3;
}

/**
 * Tells if a zone has an NSEC3 chain
 * 
 * @param zone
 * @return 
 */

static inline bool zdb_zone_has_nsec3_chain(const zdb_zone *zone)
{
    return zone->nsec.nsec3 != NULL;
}

/**
 * Tells if a zone has an NSEC3 chain with opt-out
 * 
 * @param zone
 * @return 
 */

static inline bool zdb_zone_has_nsec3_optout_chain(const zdb_zone *zone)
{
    return (zone->nsec.nsec3 != NULL) && (zone->_flags & ZDB_ZONE_HAS_OPTOUT_COVERAGE); /// and ?
}

static inline bool zdb_zone_has_nsec3_records(const zdb_zone *zone)
{
    nsec3_zone *n3 = zone->nsec.nsec3;
    while(n3 != NULL)
    {
        if(n3->items != NULL)
        {
            return TRUE;
        }
        n3 = n3->next;
    }
    return FALSE;
}

static inline bool zdb_zone_has_nsec3param_records(const zdb_zone *zone)
{
    return zdb_record_find(&zone->apex->resource_record_set, TYPE_NSEC3PARAM) != NULL;
}

#endif

/**
 * Tells if the apex of the zone has an NSEC extension
 * 
 * @param zone
 * @return 
 */

static inline bool zdb_zone_is_nsec(const zdb_zone *zone)
{
#if ZDB_HAS_NSEC_SUPPORT
    return (zone->apex->flags & ZDB_RR_LABEL_NSEC) != 0;
#else
    return FALSE;
#endif
}

#if ZDB_HAS_NSEC_SUPPORT
/**
 * Tells if a zone has an NSEC chain
 * 
 * @param zone
 * @return 
 */

static inline bool zdb_zone_has_nsec_chain(const zdb_zone *zone)
{
    return zone->nsec.nsec != NULL;
}

static inline bool zdb_zone_has_nsec_records(const zdb_zone *zone)
{
    return zdb_zone_has_nsec_chain(zone);
}

#endif

/**
 * True for zones that are to be maintained.
 * This covers DNSSEC zones, but also zones in the process of being
 * DNSSEC.
 * 
 * @param zone
 * @return 
 */

static inline bool zdb_zone_is_maintained(const zdb_zone *zone)
{
    return (zone->apex->flags & ZDB_RR_LABEL_MAINTAINED) != 0;
}

static inline void zdb_zone_set_maintained(const zdb_zone *zone, bool maintained)
{
    if(maintained)
    {
        zone->apex->flags |= ZDB_RR_LABEL_MAINTAINED;
    }
    else
    {
        zone->apex->flags &= ~ZDB_RR_LABEL_MAINTAINED;
    }
}

static inline void zone_set_maintain_mode(zdb_zone *zone, u8 mode)
{
    yassert((mode & ZDB_ZONE_MAINTAIN_MASK) == mode);
    zone->_flags &= ~ZDB_ZONE_MAINTAIN_MASK;
    zone->_flags |= mode;
}

static inline u8 zone_get_maintain_mode(const zdb_zone *zone)
{
    return zone->_flags & ZDB_ZONE_MAINTAIN_MASK;
}

static inline bool zdb_zone_is_dnssec(const zdb_zone *zone)
{
#if ZDB_HAS_DNSSEC_SUPPORT
    return (zone->apex->flags & (ZDB_RR_LABEL_NSEC | ZDB_RR_LABEL_NSEC3)) != 0;
#else
    return FALSE;
#endif    
}

static inline void zdb_zone_set_rrsig_push_allowed(zdb_zone *zone, bool allowed)
{
    if(allowed)
    {
        zone->_flags |= ZDB_ZONE_RRSIG_PUSH_ALLOWED;
    }
    else
    {
        zone->_flags &= ~ZDB_ZONE_RRSIG_PUSH_ALLOWED;
    }
}

static inline bool zdb_zone_get_rrsig_push_allowed(const zdb_zone *zone)
{
    return (zone->_flags & ZDB_ZONE_RRSIG_PUSH_ALLOWED) != 0;
}

bool zdb_zone_isinvalid(zdb_zone *zone);

static inline bool zdb_zone_isvalid(zdb_zone *zone)
{
    return !zdb_zone_isinvalid(zone);
}

#if HAS_DNSSEC_SUPPORT

/**
 * Adds a DNSKEY record in a zone from the dnssec_key object.
 * 
 * @param key
 * @return TRUE iff the record has been added
 */


bool zdb_zone_add_dnskey_from_key(zdb_zone *zone, const dnssec_key *key);

/**
 * Removes a DNSKEY record in a zone from the dnssec_key object.
 * 
 * @param key
 * @return TRUE iff the record has been found and removed
 */


bool zdb_zone_remove_dnskey_from_key(zdb_zone *zone, const dnssec_key *key);

/**
 * 
 * Returns TRUE iff the key is present as a record in the zone
 * 
 * @param zone
 * @param key
 * @return 
 */

bool zdb_zone_contains_dnskey_record_for_key(zdb_zone *zone, const dnssec_key *key);

/**
 * Returns TRUE iff there is at least one RRSIG record with the tag and algorithm of the key
 * 
 * @param zone
 * @param key
 * @return 
 */

bool zdb_zone_apex_contains_rrsig_record_by_key(zdb_zone *zone, const dnssec_key *key);

void zdb_zone_update_keystore_keys_from_zone(zdb_zone *zone, u8 secondary_lock);

#endif

#ifdef DEBUG

/**
 * DEBUG
 */

void zdb_zone_print_indented(zdb_zone* zone, output_stream *os, int indent);
void zdb_zone_print(zdb_zone *zone, output_stream *os);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _ZDB_ZONE_H */

/** @} */

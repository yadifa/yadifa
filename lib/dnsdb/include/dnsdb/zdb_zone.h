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
 * @defgroup dnsdbzone Zone related functions
 * @ingroup dnsdb
 * @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 *----------------------------------------------------------------------------*/

#ifndef _ZDB_ZONE_H
#define _ZDB_ZONE_H

#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>

#if DNSCORE_HAS_DNSSEC_SUPPORT
#include <dnscore/dnskey.h>
#endif

#include <dnsdb/zdb_types.h>

#include <dnsdb/zdb_zone_lock.h>
#include <dnsdb/zdb_zone_arc.h>

#if ZDB_HAS_NSEC3_SUPPORT
#include <dnsdb/nsec3_types.h>
#include <dnsdb/zdb_record.h>
#endif

#ifdef __cplusplus
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
zdb_zone_t *zdb_zone_find(zdb_t *db, dnsname_vector_t *exact_match_origin);

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

zdb_zone_t *zdb_zone_find_from_name(zdb_t *db, const char *name);

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
void zdb_zone_record_add(zdb_zone_t *zone, dnslabel_vector_reference_t labels, int32_t labels_top, uint16_t type, int32_t ttl, zdb_resource_record_data_t *ttlrdata); /* class is implicit */

void zdb_zone_record_add_with_mp(zdb_zone_t *zone, dnslabel_vector_reference_t labels, int32_t labels_top, uint16_t type, int32_t ttl, zdb_resource_record_data_t *ttlrdata, memory_pool_t *mp);

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
zdb_resource_record_set_t *zdb_zone_find_resource_record_set(zdb_zone_t *zone, dnslabel_vector_reference_t labels, int32_t labels_top, uint16_t type);

/**
 * Searches the zone for the zdb_rr_label of an fqdn if it exists.
 *
 * @param[in] zone the zone
 * @parma[in] fqdn the fqdn of the the label
 *
 * @return a pointer the label, or NULL if it was not found.
 */

zdb_rr_label_t *zdb_zone_find_label_from_fqdn(zdb_zone_t *zone, const uint8_t *fqdn);

/**
 * @brief Creates a zone
 *
 * Creates a zone
 *
 * @param[in] zone a pointer to the zone
 */

/* 2 USES */

zdb_zone_t *zdb_zone_create(const uint8_t *origin);

/*
 * Sets a zone as invalid.
 * This will put the (content of the) zone in a garbage to be freed at some point in the future (when nolonger used)
 * Also an invalid zone ... the .axfr and journal files should probably be trashed
 *
 */

void zdb_zone_invalidate(zdb_zone_t *zone);

void zdb_zone_truncate_invalidate(zdb_zone_t *zone);

void zdb_zone_destroy_nolock(zdb_zone_t *zone);

/**
 * @brief Destroys a zone and all its content
 *
 * Destroys a zone and all its content
 *
 * @param[in] zone a pointer to the zone
 */

/* 10 USES */
void zdb_zone_destroy(zdb_zone_t *zone);

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

ya_result zdb_zone_getsoa(const zdb_zone_t *zone, zdb_soa_rdata_t *soa_out);

ya_result zdb_zone_getsoa_ttl_rdata(const zdb_zone_t *zone, uint32_t *ttl, uint16_t *rdata_size, const uint8_t **rdata);

/**
 * @brief Retrieve the serial of a zone
 *
 * Retrieve the serial of a zone
 *
 * @param[in] zone a pointer to the zone
 * @param[out] serial a pointer to an uint32_t that will get the serial
 */

ya_result zdb_zone_getserial(const zdb_zone_t *zone, uint32_t *serial);

/**
 * @brief Retrieve the minttl of a zone
 *
 * @param[in] zone a pointer to the zone
 * @param[out] serial a pointer to an uint32_t that will get the minttl
 */

static inline void zdb_zone_getminttl(const zdb_zone_t *zone, int32_t *minttl) { *minttl = zone->min_ttl; }

/**
 * @brief Retrieve the minimum between the minttl/nttl and the SOA ttl of a zone
 *
 * @param[in] zone a pointer to the zone
 * @param[out] serial a pointer to an uint32_t that will get the minttl
 */

static inline void zdb_zone_getminttlsoa(const zdb_zone_t *zone, int32_t *minttl) { *minttl = zone->min_ttl_soa; }

#if ZDB_RECORDS_CLASS_MAX == 1
static inline uint16_t zdb_zone_getclass(const zdb_zone_t *zone)
{
    (void)zone;
    return CLASS_IN;
}

#else
static inline uint16_t zdb_zone_getclass(const zdb_zone *zone) { return zone->zclass; }
#endif

ya_result                        zdb_zone_store_axfr(zdb_zone_t *zone, output_stream_t *os);

ya_result                        zdb_zone_store_czf(zdb_zone_t *zone, output_stream_t *os);

static inline ya_result          zdb_zone_store_binary(zdb_zone_t *zone, output_stream_t *os) { return zdb_zone_store_axfr(zone, os); }

const zdb_resource_record_set_t *zdb_zone_get_dnskey_rrset(zdb_zone_t *zone);

static inline uint8_t            zdb_zone_get_flags(const zdb_zone_t *zone)
{
    // mutex_lock(&zone->lock_mutex);
    uint8_t ret = zone->_flags;
    // mutex_unlock(&zone->lock_mutex);
    return ret;
}

static inline uint8_t zdb_zone_set_flags(zdb_zone_t *zone, uint8_t flags)
{
    // mutex_lock(&zone->lock_mutex);
    uint8_t ret = zone->_flags;
    zone->_flags |= flags;
    // mutex_unlock(&zone->lock_mutex);
    return ret;
}

static inline uint8_t zdb_zone_clear_flags(zdb_zone_t *zone, uint8_t flags)
{
    // mutex_lock(&zone->lock_mutex);
    uint8_t ret = zone->_flags;
    zone->_flags &= ~flags;
    // mutex_unlock(&zone->lock_mutex);
    return ret;
}

static inline uint8_t zdb_zone_set_clear_flags(zdb_zone_t *zone, uint8_t set_flags, uint8_t clear_flags)
{
    // mutex_lock(&zone->lock_mutex);
    uint8_t ret = zone->_flags;
    zone->_flags &= ~clear_flags;
    zone->_flags |= set_flags;
    // mutex_unlock(&zone->lock_mutex);
    return ret;
}

/**
 * Tells if the apex of the zone has an NSEC3 extension
 *
 * @param zone
 * @return
 */

static inline bool zdb_zone_is_nsec3(const zdb_zone_t *zone)
{
#if ZDB_HAS_NSEC3_SUPPORT
    return (zone->apex->_flags & ZDB_RR_LABEL_NSEC3) != 0;
#else
    return false;
#endif
}

/**
 * Tells if the apex of the zone has an NSEC3 extension with opt-out
 *
 * @param zone
 * @return
 */

static inline bool zdb_zone_is_nsec3_optout(const zdb_zone_t *zone)
{
#if ZDB_HAS_NSEC3_SUPPORT
    return ((zone->apex->_flags & ZDB_RR_LABEL_NSEC3_OPTOUT) != 0);
#else
    return false;
#endif
}

/**
 * Tells if the apex of the zone has an NSEC3 extension without opt-out
 *
 * @param zone
 * @return
 */

static inline bool zdb_zone_is_nsec3_optin(const zdb_zone_t *zone)
{
#if ZDB_HAS_NSEC3_SUPPORT
    return ((zone->apex->_flags & ZDB_RR_LABEL_NSEC3_OPTOUT) == 0);
#else
    return false;
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

static inline nsec3_zone_t *zdb_zone_get_nsec3chain(const zdb_zone_t *zone, int8_t idx)
{
    nsec3_zone_t *n3 = zone->nsec.nsec3;
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

static inline bool zdb_zone_has_nsec3_chain(const zdb_zone_t *zone) { return zone->nsec.nsec3 != NULL; }

/**
 * Tells if a zone has an NSEC3 chain with opt-out
 *
 * @param zone
 * @return
 */

static inline bool zdb_zone_has_nsec3_optout_chain(zdb_zone_t *zone)
{
    return (zone->nsec.nsec3 != NULL) && (zdb_zone_get_flags(zone) & ZDB_ZONE_HAS_OPTOUT_COVERAGE); /// and ?
}

static inline bool zdb_zone_has_nsec3_records(const zdb_zone_t *zone)
{
    nsec3_zone_t *n3 = zone->nsec.nsec3;
    while(n3 != NULL)
    {
        if(n3->items != NULL)
        {
            return true;
        }
        n3 = n3->next;
    }
    return false;
}

static inline bool zdb_zone_has_nsec3param_records(const zdb_zone_t *zone) { return zdb_resource_record_sets_find_set_const(&zone->apex->resource_record_set, TYPE_NSEC3PARAM) != NULL; }

static inline bool zdb_zone_maintenance_queued(zdb_zone_t *zone)
{
    bool ret = (zdb_zone_get_flags(zone) & ZDB_ZONE_MAINTAIN_QUEUED) != 0;
    return ret;
}

/**
 * Returns true if the zne was not already marked as maintained
 */

static inline bool zdb_zone_set_maintenance_queued(zdb_zone_t *zone)
{
    bool not_already_set = (zdb_zone_set_flags(zone, ZDB_ZONE_MAINTAIN_QUEUED) & ZDB_ZONE_MAINTAIN_QUEUED) == 0;
    return not_already_set;
}

static inline void zdb_zone_clear_maintenance_queued(zdb_zone_t *zone) { zdb_zone_clear_flags(zone, ZDB_ZONE_MAINTAIN_QUEUED); }

#endif

/**
 * Tells if the apex of the zone has an NSEC extension
 *
 * @param zone
 * @return
 */

static inline bool zdb_zone_is_nsec(const zdb_zone_t *zone)
{
#if ZDB_HAS_NSEC_SUPPORT
    return (zone->apex->_flags & ZDB_RR_LABEL_NSEC) != 0;
#else
    return false;
#endif
}

#if ZDB_HAS_NSEC_SUPPORT
/**
 * Tells if a zone has an NSEC chain
 *
 * @param zone
 * @return
 */

static inline bool zdb_zone_has_nsec_chain(const zdb_zone_t *zone) { return zone->nsec.nsec != NULL; }

static inline bool zdb_zone_has_nsec_records(const zdb_zone_t *zone) { return zdb_zone_has_nsec_chain(zone); }

#endif

#if HAS_RRSIG_MANAGEMENT_SUPPORT

/**
 * True for zones that are to be maintained.
 * This covers DNSSEC zones, but also zones in the process of being
 * DNSSEC.
 *
 * @param zone
 * @return
 */

static inline bool zdb_zone_is_maintained(zdb_zone_t *zone)
{
    bool ret = (zdb_zone_get_flags(zone) & ZDB_ZONE_MAINTAINED) != 0;
    return ret;
}

static inline void zdb_zone_set_maintained(zdb_zone_t *zone, bool maintained)
{
    if(maintained)
    {
        zdb_zone_set_flags(zone, ZDB_ZONE_MAINTAINED);
    }
    else
    {
        zdb_zone_clear_flags(zone, ZDB_ZONE_MAINTAINED);
    }
}

static inline bool zdb_zone_is_maintenance_paused(zdb_zone_t *zone)
{
    uint8_t flags = zdb_zone_get_flags(zone);
    bool    ret = (flags & (ZDB_ZONE_MAINTENANCE_PAUSED | ZDB_ZONE_MAINTAINED)) == ZDB_ZONE_MAINTENANCE_PAUSED;
    return ret;
}

static inline void zdb_zone_set_maintenance_paused(zdb_zone_t *zone, bool maintenance_paused)
{
    mutex_lock(&zone->lock_mutex);
    if(maintenance_paused)
    {
        zdb_zone_set_clear_flags(zone, ZDB_ZONE_MAINTENANCE_PAUSED, ZDB_ZONE_MAINTAINED);
    }
    else
    {
        zdb_zone_set_clear_flags(zone, ZDB_ZONE_MAINTAINED, ZDB_ZONE_MAINTENANCE_PAUSED);
    }
    mutex_unlock(&zone->lock_mutex);
}

static inline void zone_set_maintain_mode(zdb_zone_t *zone, uint8_t mode)
{
    yassert((mode & ZDB_ZONE_MAINTAIN_MASK) == mode);

    zdb_zone_set_clear_flags(zone, mode, ZDB_ZONE_MAINTAIN_MASK);

    if((mode & ~ZDB_ZONE_HAS_OPTOUT_COVERAGE) == ZDB_ZONE_MAINTAIN_NSEC3)
    {
        uint8_t       flags = mode & ZDB_ZONE_HAS_OPTOUT_COVERAGE;
        nsec3_zone_t *n3 = zone->nsec.nsec3;
        while(n3 != NULL)
        {
            n3->nsec3_rdata_prefix[1] = flags;
            n3 = n3->next;
        }
    }
}

static inline uint8_t zone_get_maintain_mode(zdb_zone_t *zone)
{
    uint8_t ret = zdb_zone_get_flags(zone) & ZDB_ZONE_MAINTAIN_MASK;
    return ret;
}

#else // HAS_RRSIG_MANAGEMENT_SUPPORT

static inline bool zdb_zone_is_maintained(const zdb_zone_t *zone)
{
    (void)zone;
    return false;
}

static inline uint8_t zone_get_maintain_mode(const zdb_zone_t *zone)
{
    (void)zone;
    return 0;
}

static inline void zone_set_maintain_mode(zdb_zone_t *zone, uint8_t mode)
{
    (void)zone;
    (void)mode;
}

#endif

static inline bool zdb_zone_is_dnssec(zdb_zone_t *zone)
{
#if ZDB_HAS_DNSSEC_SUPPORT
    return (zone->apex->_flags & (ZDB_RR_LABEL_NSEC | ZDB_RR_LABEL_NSEC3)) != 0;
#else
    return false;
#endif
}

static inline void zdb_zone_set_rrsig_push_allowed(zdb_zone_t *zone, bool allowed)
{
    if(allowed)
    {
        zdb_zone_set_flags(zone, ZDB_ZONE_RRSIG_PUSH_ALLOWED);
    }
    else
    {
        zdb_zone_clear_flags(zone, ZDB_ZONE_RRSIG_PUSH_ALLOWED);
    }
}

static inline bool zdb_zone_get_rrsig_push_allowed(zdb_zone_t *zone)
{
    bool ret = zdb_zone_get_flags(zone) & ZDB_ZONE_RRSIG_PUSH_ALLOWED;
    return ret;
}

bool               zdb_zone_isinvalid(zdb_zone_t *zone);

static inline bool zdb_zone_isvalid(zdb_zone_t *zone) { return !zdb_zone_isinvalid(zone); }

#if DNSCORE_HAS_DNSSEC_SUPPORT

/**
 * Adds a DNSKEY record in a zone from the dnskey_t object.
 *
 * @param key
 * @return true iff the record has been added
 */

bool zdb_zone_add_dnskey_from_key(zdb_zone_t *zone, const dnskey_t *key);

/**
 * Removes a DNSKEY record in a zone from the dnskey_t object.
 *
 * @param key
 * @return true iff the record has been found and removed
 */

bool zdb_zone_remove_dnskey_from_key(zdb_zone_t *zone, const dnskey_t *key);

/**
 *
 * Returns true iff the key is present as a record in the zone
 *
 * @param zone
 * @param key
 * @return
 */

bool zdb_zone_contains_dnskey_record_for_key(zdb_zone_t *zone, const dnskey_t *key);

/**
 * Returns true iff there is at least one RRSIG record with the tag and algorithm of the key
 *
 * @param zone
 * @param key
 * @return
 */

bool zdb_zone_apex_contains_rrsig_record_by_key(zdb_zone_t *zone, const dnskey_t *key);

void zdb_zone_update_keystore_keys_from_zone(zdb_zone_t *zone, uint8_t secondary_lock);

#endif

#if DEBUG

/**
 * DEBUG
 */

void zdb_zone_print_indented(zdb_zone_t *zone, output_stream_t *os, int indent);
void zdb_zone_print(zdb_zone_t *zone, output_stream_t *os);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _ZDB_ZONE_H */

/** @} */

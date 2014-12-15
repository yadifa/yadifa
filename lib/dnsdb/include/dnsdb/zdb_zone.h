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

#include <dnsdb/zdb_types.h>
#include <dnsdb/dnsrdata.h>
#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#define ZDB_ZONETAG 0x454e4f5a52445a /* "ZDBZONE" */

/**
 * @brief Unloads and destroys a zone.
 *
 * Unloads and destroys a zone.
 *
 * @param[in] db a pointer to the database
 * @param[in] exact_match_origin the name of the zone
 * @param[in] zclass the class of the zone
 *
 * @return an error code.
 *
 */

/* Never called, keep it anyway : it will be useful */

ya_result zdb_zone_unload(zdb *db, dnsname_vector* exact_match_origin, u16 zclass);

/**
 * @brief Get the zone with the given name
 *
 * Get the zone with the given name
 *
 * @param[in] db a pointer to the database
 * @param[in] exact_match_origin the name of the zone
 * @param[in] zclass the class of the zone
 *
 * @return a pointer to zone or NULL if the zone is not in the database
 *
 */

/* 2 USES */
zdb_zone *zdb_zone_find(zdb *db, dnsname_vector* exact_match_origin, u16 zclass);

/**
 * @brief Get the zone with the given name
 *
 * Get the zone with the given name
 *
 * @param[in] db a pointer to the database
 * @param[in] name the name of the zone (dotted c-string)
 * @param[in] zclass the class of the zone
 *
 * @return a pointer to zone or NULL if the zone is not in the database
 *
 */

zdb_zone *zdb_zone_find_from_name(zdb *db, const char* name, u16 class);

/**
 * @brief Get the zone with the given dns name
 *
 * Get the zone with the given dns name
 *
 * @param[in] db a pointer to the database
 * @param[in] name the name of the zone (dns name)
 * @param[in] zclass the class of the zone
 *
 * @return a pointer to zone or NULL if the zone is not in the database
 *
 */

zdb_zone *zdb_zone_find_from_dnsname(zdb *db, const u8 *dns_name, u16 qclass);

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
 * Removes a record from a zone
 *
 * @param[in] zone the zone
 * @param[in] labels the stack of labels of the dns name
 * @param[in] labels_top the index of the top of the stack (the level)
 * @param[in] type the type of the record
 * @param[in] ttlrdata the ttl and rdata of the record.  NOTE: the caller stays the owner
 *
 * @return an error code
 */


ya_result zdb_zone_record_delete(zdb_zone* zone, dnslabel_vector_reference labels, s32 labels_top, u16 type, zdb_packed_ttlrdata* ttlrdata); /* class is implicit */

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

zdb_zone* zdb_zone_create(const u8 *origin, u16 zclass);

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

static inline ya_result zdb_zone_getminttl(const zdb_zone *zone, u32 *minttl)
{
    *minttl = zone->min_ttl;
    return SUCCESS;
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

/**
 * @brief Updates a zone from an IXFR input stream
 *
 * Loads a zone from an IXFR input stream
 *
 * The function does not closes the input stream
 *
 * If the IXFR is wrong, the zone will be messed up.
 * Please check that the general structure of the stream is right
 * before calling this.
 *
 * SOA x+n
 *	SOA x+0
 *	...
 *	SOA x+1
 *	...
 *
 *	SOA x+1
 *	...
 *	SOA x+2
 *	...
 * SOA x+n
 *
 * @param[in] db a pointer to the database
 * @param[in] is a pointer to an input stream containing the IXFR
 *
 * @return an error code
 */

ya_result zdb_zone_update_ixfr(zdb *db, input_stream *is);

ya_result zdb_zone_store_axfr(zdb_zone *zone, output_stream* os);

const zdb_packed_ttlrdata*
zdb_zone_get_dnskey_rrset(zdb_zone *zone);

static inline bool zdb_zone_is_nsec3(const zdb_zone* zone)
{
#if ZDB_HAS_NSEC3_SUPPORT != 0
    return (zone->apex->flags & ZDB_RR_LABEL_NSEC3) != 0;
#else
    return FALSE;
#endif
}

static inline bool zdb_zone_is_nsec(const zdb_zone *zone)
{
#if ZDB_HAS_NSEC_SUPPORT != 0
    return (zone->apex->flags & ZDB_RR_LABEL_NSEC) != 0;
#else
    return FALSE;
#endif
}

static inline bool zdb_zone_is_dnssec(const zdb_zone *zone)
{
#if ZDB_HAS_DNSSEC_SUPPORT != 0
    return (zone->apex->flags & (ZDB_RR_LABEL_NSEC | ZDB_RR_LABEL_NSEC3)) != 0;
#else
    return FALSE;
#endif    
}

/**
 * Zone locking
 * 
 * Sets the owner of a zone.
 * 
 * The owner id has a format: the msb is reserved to say that the access is
 * exclusive to only one instance of the owner.
 * The remaining bits are the id.
 * 
 * Mostly used for the simple reader and various writers.
 * 
 * A new feature needs to be added: being able to pre-lock for an owner.
 * 
 * Explanation: I want to lock for the signing process.  But that process
 * is done in two or three phases.  The first phase is read-only (thus allowing
 * the server to work normally).  But I don't want sombody else, say, a dynamic
 * update, to lock the zone in the mean time. (Which would happen when the lock
 * is transferred from the reader to the signer (at the commit phase).
 * So I'll add a secondary owner, meant to tell "I lock as a reader BUT I also
 * reserve the right for myself later".  And later a transfer can be done to
 * the secondary as soon as the last reader unlocks.
 * 
 * zdb_zone_double_lock(zone, owner, secondary owner)
 * zdb_zone_try_double_lock(zone, owner, secondary owner)
 * zdb_zone_transfer_lock(zone, secondary owner)
 * 
 * The parameter would need to be repeated to detect inconsistencies (bugs)
 * 
 * This should have no effect on the normal locking mechanism, thus ensuring
 * no loss of speed.  The only goal is to avoid a race changing the owner.
 * 
 * Having only zdb_zone_transfer_lock(zone, old owner, new owner) cannot work
 * because nothing prevents two soon-to-be writers to lock and work in tandem.
 * 
 */

void zdb_zone_lock(zdb_zone *zone, u8 owner);

bool zdb_zone_trylock(zdb_zone *zone, u8 owner);

void zdb_zone_unlock(zdb_zone *zone, u8 owner);

/**
 * Reserves the secondary owner and to locks for the owner
 * 
 * @param zone
 * @param owner
 * @param secondary_owner
 */

void zdb_zone_double_lock(zdb_zone *zone, u8 owner, u8 secondary_owner);

/**
 * Tries to reserve the secondary owner and to lock for the owner
 * 
 * @param zone
 * @param owner
 * @param secondary_owner
 */

bool zdb_zone_try_double_lock(zdb_zone *zone, u8 owner, u8 secondary_owner);

/**
 * 
 * Unlocks one owner and sets the secondary owner to nobody
 * 
 * @param zone
 * @param owner
 * @param secondary_owner
 */

void zdb_zone_double_unlock(zdb_zone *zone, u8 owner, u8 secondary_owner);

/**
 * 
 * Puts the secondary lock in place of the lock when the locker count reaches 1
 * Followed by a zdb_zone_unlock
 * 
 * @param zone
 * @param owner
 * @param secondary_owner
 */

void zdb_zone_transfer_lock(zdb_zone *zone, u8 owner, u8 secondary_owner);

/**
 * 
 * Exchange the primary and secondary locks when the locker count reaches 1
 * Followed by a zdb_zone_unlock
 * 
 * @param zone
 * @param owner
 * @param secondary_owner
 */

void zdb_zone_exchange_locks(zdb_zone *zone, u8 owner, u8 secondary_owner);

/**
 * Exchange the current zone with a dummy invalid one.
 * Do nothing if the zone in place is already invalid.
 * Returns the previous zone.
 * 
 * @param db
 * @param origin
 * @param zclass
 * @return 
 */

zdb_zone *zdb_zone_xchg_with_invalid(zdb *db, const u8 *origin, u16 zclass, u16 or_flags);

bool zdb_zone_isinvalid(zdb_zone *zone);

static inline bool zdb_zone_isvalid(zdb_zone *zone)
{
    return !zdb_zone_isinvalid(zone);
}

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

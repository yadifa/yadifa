/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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

#pragma once

#include <dnsdb/zdb_types.h>
#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>

/**
 *
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 *
 * The read series implies no changes will be done to the database structure (no zone labels added/removed)
 *
 * @param db
 * @param exact_match_origin
 * @param owner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_read(zdb_t *db, const dnsname_vector_t *exact_match_origin);

/**
 *
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 *
 * The read series implies no changes will be done to the database structure (no zone labels added/removed)
 *
 * @param db
 * @param fqdn
 * @param owner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_read_from_fqdn(zdb_t *db, const uint8_t *fqdn);

/**
 *
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 *
 * The read series implies no changes will be done to the database structure (no zone labels added/removed)
 *
 * @param db
 * @param exact_match_origin
 * @param owner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_read_trylock(zdb_t *db, dnsname_vector_t *exact_match_origin, uint8_t owner);

/**
 *
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 *
 * The read series implies no changes will be done to the database structure (no zone labels added/removed)
 *
 * @param db
 * @param name
 * @param owner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_read_trylock_from_name(zdb_t *db, const char *name, uint8_t owner);

/**
 *
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 *
 * The read series implies no changes will be done to the database structure (no zone labels added/removed)
 *
 * @param db
 * @param fqdn
 * @param owner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_read_trylock_from_fqdn(zdb_t *db, const uint8_t *fqdn, uint8_t owner);

/**
 *
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 *
 * The read series implies no changes will be done to the database structure (no zone labels added/removed)
 *
 * @param db
 * @param exact_match_origin
 * @param owner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_read_lock(zdb_t *db, dnsname_vector_t *exact_match_origin, uint8_t owner);

/**
 *
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 *
 * The read series implies no changes will be done to the database structure (no zone labels added/removed)
 *
 * @param db
 * @param name
 * @param owner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_read_lock_from_name(zdb_t *db, const char *name, uint8_t owner);

/**
 *
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 *
 * The read series implies no changes will be done to the database structure (no zone labels added/removed)
 *
 * @param db
 * @param fqdn
 * @param owner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_read_lock_from_fqdn(zdb_t *db, const uint8_t *fqdn, uint8_t owner);

/**
 *
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 *
 * The write series implies changes will be done to the database structure.  Most likely a removal of a zone label.
 *
 * @param db
 * @param exact_match_origin
 * @param owner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_write_lock(zdb_t *db, dnsname_vector_t *exact_match_origin, uint8_t owner);

/**
 *
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 *
 * The write series implies changes will be done to the database structure.  Most likely a removal of a zone label.
 *
 * @param db
 * @param name
 * @param owner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_write_lock_from_name(zdb_t *db, const char *name, uint8_t owner);

/**
 *
 * Locks the database
 * Gets the zone
 * Starts locking the zone for the owner
 * Increment the zone RC
 * Unlocks the database
 * Resume locking the zone for the owner
 * returns the locked zone
 *
 * The write series implies changes will be done to the database structure.  Most likely a removal of a zone label.
 *
 * @param db
 * @param fqdn
 * @param owner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_write_lock_from_fqdn(zdb_t *db, const uint8_t *fqdn, uint8_t owner);

/**
 * The double lock allows the caller to lock a zone for an owner with dibs to change the owner.
 * Typically: lock for the simple reader and then change the lock to a writer.
 * This is useful when lock-out the readers is not needed yet, but will most likely be in the near future.
 *
 * ie: lock reader + dynupdate
 *     verify prerequisites
 *     do the dry run
 *     transfer lock to dynupdate
 *     do the actual update
 *     unlock
 *
 * @param db
 * @param exact_match_origin
 * @param owner
 * @param nextowner
 * @return
 */

zdb_zone_t *zdb_acquire_zone_read_double_lock(zdb_t *db, dnsname_vector_t *exact_match_origin, uint8_t owner, uint8_t nextowner);
zdb_zone_t *zdb_acquire_zone_read_double_lock_from_name(zdb_t *db, const char *name, uint8_t owner, uint8_t nextowner);
zdb_zone_t *zdb_acquire_zone_read_double_lock_from_fqdn(zdb_t *db, const uint8_t *fqdn, uint8_t owner, uint8_t nextowner);

/**
 *
 * Dereference and unlocks the zone.
 * If the RC reached 0, enqueues it for destruction
 *
 * @param zone
 * @param owner
 */

void zdb_zone_acquire(zdb_zone_t *zone);

void zdb_zone_release(zdb_zone_t *zone);

void zdb_zone_release_unlock(zdb_zone_t *zone, uint8_t owner);

void zdb_zone_release_double_unlock(zdb_zone_t *zone, uint8_t owner, uint8_t nextowner);

/** @} */

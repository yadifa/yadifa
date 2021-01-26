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

#ifdef	__cplusplus
extern "C"
{
#endif

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
 * the server to work normally).  But I don't want somebody else, say, a dynamic
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

bool zdb_zone_trylock_wait(zdb_zone *zone, u64 usec, u8 owner);

void zdb_zone_unlock(zdb_zone *zone, u8 owner);

bool zdb_zone_islocked(zdb_zone *zone);

/**
 * Functions for internal testing, do not use.
 * 
 * @param zone
 * @return 
 */

bool zdb_zone_islocked_weak(const zdb_zone *zone);

/**
 * Functions for internal testing, do not use.
 * 
 * @param zone
 * @return 
 */

bool zdb_zone_islocked_weak(const zdb_zone *zone);

/**
 * Functions for internal testing, do not use.
 * 
 * @param zone
 * @return 
 */

bool zdb_zone_islocked_weak(const zdb_zone *zone);

/**
 * Functions for internal testing, do not use.
 * 
 * @param zone
 * @return 
 */

bool zdb_zone_islocked_weak(const zdb_zone *zone);

/**
 * Returns TRUE iff the zone is locked by a writer (any other owner value than nobody and simple reader)
 * 
 * @param zone
 * @return 
 */

bool zdb_zone_iswritelocked(zdb_zone *zone);

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
 * Tries to reserve the secondary owner and to lock for the owner.
 * Gets the current owner if the lock fails.
 * If the lock succeeds the current_ownerp and current_reserved_ownerp poited values's content is undefined.
 *
 * @param zone
 * @param owner
 * @param secondary_owner
 * @param current_ownerp
 * @param current_reserved_ownerp
 */

bool zdb_zone_try_double_lock_ex(zdb_zone *zone, u8 owner, u8 secondary_owner, u8 *current_ownerp, u8 *current_reserved_ownerp);

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
 * Puts the secondary lock in place of the lock when the locker count reaches 1
 * Followed by a zdb_zone_unlock
 * 
 * @param zone
 * @param owner
 * @param secondary_owner
 */

bool zdb_zone_try_transfer_lock(zdb_zone *zone, u8 owner, u8 secondary_owner);

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

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
void zdb_zone_lock_set_monitor();
#endif

/** @} */

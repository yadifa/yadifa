/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2016, EURid. All rights reserved.
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
#pragma once
#include <dnsdb/nsec3.h>

/**
 * Creates an NSEC3 chain for the zone at the index position, asynchronously.
 * 
 * The zone needs to be
 * either write-locked,
 * either double-locked and in the read position.
 * 
 * If the zone is double-locked, the lock_owner and reserved owner parameters have to be set accordingly (read, write)
 * If the zone is locked, both parameters have to be set to ZDB_ZONE_MUTEX_NOBODY ( = 0 )
 * 
 * @param zone the zone
 * @param chain_index the index of the chain (0 for the one visible to the queries)
 * @param opt_out has the chain to be generated "optout"
 * @param lock_owner 0 or the read double-lock owner
 * @param reserved_owner 0 or the write double-lock owner
 * @param callback function that will be called at the end of the asynchronous generation, can be NULL
 * @param callback_args parameter passed to the callback at the end of the asynchronous generation
 */

void nsec3_chain_create(zdb_zone *zone, s8 chain_index, bool opt_out, u8 lock_owner, u8 reserved_owner, nsec3_chain_callback *callback, void *callback_args);

/**
 * Creates an NSEC3 chain for the zone at the index position.
 * 
 * The zone needs to be
 * either write-locked,
 * either double-locked and in the read position.
 * 
 * If the zone is double-locked, the lock_owner and reserved owner parameters have to be set accordingly (read, write)
 * If the zone is locked, both parameters have to be set to ZDB_ZONE_MUTEX_NOBODY ( = 0 )
 * 
 * @param zone the zone
 * @param chain_index the index of the chain (0 for the one visible to the queries)
 * @param opt_out has the chain to be generated "optout"
 * @param lock_owner 0 or the read double-lock owner
 * @param reserved_owner 0 or the write double-lock owner
 */

void nsec3_chain_create_now(zdb_zone *zone, s8 chain_index, bool opt_out, u8 lock_owner, u8 reserved_owner);

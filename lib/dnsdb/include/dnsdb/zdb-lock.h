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

/** @defgroup dnsdb Zone database
 *  @brief The zone database
 *
 *  Implementation of structures and functions for the database
 *
 *  Memory usage approxymation:
 *
 *  let:
 *
 *  "digest" the size of a digest
 *  "n3pc" the number of nsec3param
 *  "r" the number of records
 *
 *  Memory usage =~ (233.3333 + ((446.666+digest) * n3pc) * r
 *
 *  Or, if the digest size is different for each n3p:
 *
 *  With "digest(n)" being the size of the digest for the n-th nsec3param
 *
 *  =~ (233.3333 + SUM[n=1..n3pc](446.666+digest(n))) * r
 *
 * @{
 */

#pragma once

#include <dnsdb/zdb_types.h>

static inline void zdb_lock(zdb *db, u8 owner)
{
    group_mutex_lock(&db->mutex, owner);
}

static inline void zdb_unlock(zdb *db, u8 owner)
{
    group_mutex_unlock(&db->mutex, owner);
}

static inline bool zdb_islocked(zdb *db)
{
    mutex_lock(&db->mutex.mutex);
    bool r = db->mutex.owner != 0;
    mutex_unlock(&db->mutex.mutex);
    return r;
}

static inline bool zdb_islocked_by(zdb *db, u8 owner)
{
    mutex_lock(&db->mutex.mutex);
    bool r = (db->mutex.owner == (owner & 0x7f));
    mutex_unlock(&db->mutex.mutex);
    return r;
}

/** @} */

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
 * @defgroup
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include <dnscore/mutex_defines.h>
#include <dnscore/mutex_mutex.h>

/**
 * A group mutex is a mutex that can be used by a group with or without exclusive access.
 * A mutex is private if the msb is set, it means only one of that group can own it
 * A mutex is shared if the msb is not set, it means many owner of the same type can own it
 */

#define GROUP_MUTEX_NOBODY         0x00
#define GROUP_MUTEX_READ           0x01 // default
#define GROUP_MUTEX_WRITE          0x82 // default
#define GROUP_MUTEX_PRIVATE        0x80 // THIS IS A MASK, ADD IT TO THE OWNER ID
#define GROUP_MUTEX_DESTROY        0xfe

#define GROUP_MUTEX_LOCKMASK_FLAG  0x7f
#define GROUP_MUTEX_EXCLUSIVE_FLAG 0x80

typedef struct group_mutex_t group_mutex_t;

struct group_mutex_t
{
    cond_t           cond;
    mutex_t          mutex;
    volatile int32_t count;
    volatile uint8_t owner;
    volatile uint8_t reserved_owner;
};

#define GROUP_MUTEX_INITIALIZER {COND_INITIALIZER, MUTEX_INITIALIZER, 0, 0, 0}

void               group_mutex_init(group_mutex_t *mtx);
void               group_mutex_lock(group_mutex_t *mtx, uint8_t owner);
bool               group_mutex_trylock(group_mutex_t *mtx, uint8_t owner);
void               group_mutex_unlock(group_mutex_t *mtx, uint8_t owner);
bool               group_mutex_transferlock(group_mutex_t *mtx, uint8_t owner, uint8_t newowner);
void               group_mutex_destroy(group_mutex_t *mtx);
bool               group_mutex_islocked(group_mutex_t *mtx);

void               group_mutex_double_lock(group_mutex_t *mtx, uint8_t owner, uint8_t secondary_owner);
void               group_mutex_double_unlock(group_mutex_t *mtx, uint8_t owner, uint8_t secondary_owner);
void               group_mutex_exchange_locks(group_mutex_t *mtx, uint8_t owner, uint8_t secondary_owner);

static inline void group_mutex_read_lock(group_mutex_t *mtx) { group_mutex_lock(mtx, GROUP_MUTEX_READ); }

static inline void group_mutex_read_unlock(group_mutex_t *mtx) { group_mutex_unlock(mtx, GROUP_MUTEX_READ); }

static inline void group_mutex_write_lock(group_mutex_t *mtx) { group_mutex_lock(mtx, GROUP_MUTEX_WRITE); }

static inline void group_mutex_write_unlock(group_mutex_t *mtx) { group_mutex_unlock(mtx, GROUP_MUTEX_WRITE); }

/** @} */

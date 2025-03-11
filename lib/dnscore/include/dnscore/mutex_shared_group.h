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
 * @defgroup
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

/**
 * The shared group mutex is a group mutex that only uses N mutex(es) and N condition(s).
 * This is especially useful when millions of instances are required.
 * The mutex is used commonly by each structure as its own.
 * The downside is that every waiting task on the same mutex will be woken up each time one of them broadcasts the
 * condition.
 *
 * The current implementation uses N=1
 */

#include <dnscore/mutex.h>

struct shared_group_shared_mutex_s
{
    mutex_t          mutex;
    cond_t           cond;
    volatile int32_t rc;
};

typedef struct shared_group_shared_mutex_s shared_group_shared_mutex_t;

#define SHARED_GROUP_SHARED_MUTEX_INTIALIZER {MUTEX_INITIALIZER, COND_INITIALIZER, 0}

struct shared_group_mutex_s
{
    shared_group_shared_mutex_t *shared_mutex;
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    struct mutex_contention_monitor_s *mcm;
#else
    stacktrace        trace;
    volatile thread_t id;
    volatile uint64_t timestamp;
#endif
#endif

    volatile int32_t count;
    volatile uint8_t owner;
};

#define SHARED_GROUP_MUTEX_INTIALIZER THIS_CANNOT_WORK

typedef struct shared_group_mutex_s shared_group_mutex_t;

void                                shared_group_shared_mutex_init(shared_group_shared_mutex_t *smtx);
void                                shared_group_shared_mutex_init_recursive(shared_group_shared_mutex_t *smtx);
void                                shared_group_shared_mutex_destroy(shared_group_shared_mutex_t *smtx);

void                                shared_group_mutex_init(shared_group_mutex_t *mtx, shared_group_shared_mutex_t *smtx, const char *name);
void                                shared_group_mutex_lock(shared_group_mutex_t *mtx, uint8_t owner);
bool                                shared_group_mutex_trylock(shared_group_mutex_t *mtx, uint8_t owner);
void                                shared_group_mutex_unlock(shared_group_mutex_t *mtx, uint8_t owner);
bool                                shared_group_mutex_transferlock(shared_group_mutex_t *mtx, uint8_t owner, uint8_t newowner);
void                                shared_group_mutex_destroy(shared_group_mutex_t *mtx);
bool                                shared_group_mutex_islocked(shared_group_mutex_t *mtx);
bool                                shared_group_mutex_islocked_by(shared_group_mutex_t *mtx, uint8_t owner);

/** @} */

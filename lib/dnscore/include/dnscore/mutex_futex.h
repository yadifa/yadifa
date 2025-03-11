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

#include <dnscore/dnscore_config_features.h>
#include <dnscore/sys_types.h>

#include <unistd.h>
#if DNSCORE_HAVE_STDATOMIC_H
#include <stdatomic.h>
#elif __windows__
#include <stdatomic.h>
#else
#include "dnscore/thirdparty/stdatomic.h"
#endif

#if __linux__ || __OpenBSD__

// Linux and OpenBSD have the futex syscall
#define DNSCORE_FUTEX_SUPPORT  1

// tracking is used essentially for debugging now
// it can also be used to ensure stuff like recursive locks or unlocking something locked by another thread
#define DNSCORE_FUTEX_TRACKING 0

struct mutex_futex_s
{
    atomic_uint addr;
#if DNSCORE_FUTEX_TRACKING
    atomic_uint owner;
#endif
};

typedef struct mutex_futex_s mutex_futex_t;

struct cond_futex_s
{
    atomic_uint addr;
#if DNSCORE_FUTEX_TRACKING
    atomic_uint count;
#endif
};

typedef struct cond_futex_s cond_futex_t;

void                        mutex_futex_init(mutex_futex_t *mtx);
int                         mutex_futex_lock_timeout(mutex_futex_t *mtx, int64_t relative_usec);
void                        mutex_futex_finalise(mutex_futex_t *mtx);
int                         mutex_futex_lock(mutex_futex_t *mtx);
bool                        mutex_futex_trylock(mutex_futex_t *mtx);
int                         mutex_futex_unlock(mutex_futex_t *mtx);

void                        cond_futex_init(cond_futex_t *cond);
void                        cond_futex_finalise(cond_futex_t *cond);
int                         cond_futex_wait(cond_futex_t *cond, mutex_futex_t *mtx);
int                         cond_futex_timedwait(cond_futex_t *cond, mutex_futex_t *mtx, int64_t relative_usec);
int                         cond_futex_notify(cond_futex_t *cond);
int                         cond_futex_notify_one(cond_futex_t *cond);

#else

#define DNSCORE_FUTEX_SUPPORT 0

void dnscore_futex_not_supported();

#endif

/** @} */

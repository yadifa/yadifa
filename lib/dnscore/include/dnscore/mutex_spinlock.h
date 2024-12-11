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
#pragma once

#include <pthread.h>

#define SPINLOCK_IS_MUTEX 0

#if __APPLE__
#undef SPINLOCK_IS_MUTEX 1
#define SPINLOCK_IS_MUTEX 1
#endif

#if SPINLOCK_IS_MUTEX

typedef pthread_mutex_t spinlock_t;

static inline void      spinlock_init(spinlock_t *spin) { pthread_mutex_init(spin, NULL); }

static inline void      spinlock_destroy(spinlock_t *spin) { pthread_mutex_destroy(spin); }

static inline void      spinlock_lock(spinlock_t *spin) { pthread_mutex_lock(spin); }

static inline void      spinlock_unlock(spinlock_t *spin) { pthread_mutex_unlock(spin); }

#else

typedef pthread_spinlock_t spinlock_t;

static inline void         spinlock_init(spinlock_t *spin) { pthread_spin_init(spin, 0); }

static inline void         spinlock_destroy(spinlock_t *spin) { pthread_spin_destroy(spin); }

static inline void         spinlock_lock(spinlock_t *spin) { pthread_spin_lock(spin); }

static inline void         spinlock_unlock(spinlock_t *spin) { pthread_spin_unlock(spin); }

#endif

/** @} */

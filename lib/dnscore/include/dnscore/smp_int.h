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

#define SMP_USES_ATOMICS 1

#if SMP_USES_ATOMICS

#if DNSCORE_HAVE_STDATOMIC_H
#include <stdatomic.h>
#elif __windows__
#include <stdatomic.h>
#else
#include "dnscore/thirdparty/stdatomic.h"
#endif

typedef atomic_int smp_int;

#define SMP_INT_INITIALIZER            (0)
#define SMP_INT_INITIALIZER_AT(value_) (value_)

static inline void smp_int_init(smp_int *v) { atomic_store(v, 0); }

static inline void smp_int_init_set(smp_int *v, int value) { atomic_store(v, value); }

static inline void smp_int_set(smp_int *v, int i) { atomic_store(v, i); }

static inline void smp_int_inc(smp_int *v) { atomic_fetch_add(v, 1); }

static inline void smp_int_add(smp_int *v, int value) { atomic_fetch_add(v, value); }

static inline void smp_int_or(smp_int *v, int value) { atomic_fetch_or(v, value); }

static inline void smp_int_and(smp_int *v, int value) { atomic_fetch_and(v, value); }

static inline int  smp_int_inc_get(smp_int *v)
{
    int ret = atomic_fetch_add(v, 1) + 1;
    return ret;
}

static inline void smp_int_dec(smp_int *v) { atomic_fetch_sub(v, 1); }

static inline void smp_int_sub(smp_int *v, int value) { atomic_fetch_sub(v, value); }

static inline int  smp_int_dec_get(smp_int *v)
{
    int ret = atomic_fetch_sub(v, 1) - 1;
    return ret;
}

static inline int smp_int_get_dec(smp_int *v)
{
    int ret = atomic_fetch_sub(v, 1);
    return ret;
}

static inline bool smp_int_setifequal(smp_int *v, int from, int to)
{
    bool didit = false;
#if __unix__
    int *fromp = &from;
    didit = atomic_compare_exchange_strong(v, fromp, to);
#else
    int  from_tmp = from;
    int *fromp = &from_tmp;
    didit = atomic_compare_exchange_strong(v, fromp, to);
#endif
    return didit;
}

static inline int smp_int_get(smp_int *v)
{
    int ret = atomic_load(v);
    return ret;
}

static inline int smp_int_get_set(smp_int *v, int newvalue)
{
    int ret = atomic_exchange(v, newvalue);
    return ret;
}

static inline void smp_int_finalise(smp_int *v) { (void)v; }

#else

#include <pthread.h>

struct smp_int
{
    pthread_mutex_t mutex;
    volatile int    value;
};

#define SMP_INT_INITIALIZER            {PTHREAD_MUTEX_INITIALIZER, 0}
#define SMP_INT_INITIALIZER_AT(value_) {PTHREAD_MUTEX_INITIALIZER, (value_)}

typedef struct smp_int smp_int;

static inline void     smp_int_init(smp_int *v)
{
    pthread_mutex_init(&v->mutex, NULL);
    v->value = 0;
}

static inline void smp_int_init_set(smp_int *v, int value)
{
    pthread_mutex_init(&v->mutex, NULL);
    v->value = value;
}

static inline void smp_int_set(smp_int *v, int i)
{
    pthread_mutex_lock(&v->mutex);
    v->value = i;
    pthread_mutex_unlock(&v->mutex);
}

static inline void smp_int_inc(smp_int *v)
{
    pthread_mutex_lock(&v->mutex);
    v->value++;
    pthread_mutex_unlock(&v->mutex);
}

static inline void smp_int_add(smp_int *v, int value)
{
    pthread_mutex_lock(&v->mutex);
    v->value += value;
    pthread_mutex_unlock(&v->mutex);
}

static inline void smp_int_or(smp_int *v, int value)
{
    pthread_mutex_lock(&v->mutex);
    v->value |= value;
    pthread_mutex_unlock(&v->mutex);
}

static inline void smp_int_and(smp_int *v, int value)
{
    pthread_mutex_lock(&v->mutex);
    v->value &= value;
    pthread_mutex_unlock(&v->mutex);
}

static inline int smp_int_inc_get(smp_int *v)
{
    uint32_t ret;
    pthread_mutex_lock(&v->mutex);
    ret = ++v->value;
    pthread_mutex_unlock(&v->mutex);
    return ret;
}

static inline void smp_int_dec(smp_int *v)
{
    pthread_mutex_lock(&v->mutex);
    v->value--;
    pthread_mutex_unlock(&v->mutex);
}

static inline void smp_int_sub(smp_int *v, int value)
{
    pthread_mutex_lock(&v->mutex);
    v->value -= value;
    pthread_mutex_unlock(&v->mutex);
}

static inline int smp_int_dec_get(smp_int *v)
{
    int ret;
    pthread_mutex_lock(&v->mutex);
    ret = --v->value;
    pthread_mutex_unlock(&v->mutex);
    return ret;
}

static inline int smp_int_get_dec(smp_int *v)
{
    int ret;
    pthread_mutex_lock(&v->mutex);
    ret = v->value--;
    pthread_mutex_unlock(&v->mutex);
    return ret;
}

static inline bool smp_int_setifequal(smp_int *v, int from, int to)
{
    bool didit = false;

    pthread_mutex_lock(&v->mutex);

    if(v->value == from)
    {
        v->value = to;
        didit = true;
    }

    pthread_mutex_unlock(&v->mutex);

    return didit;
}

static inline int smp_int_get(smp_int *v)
{
    int ret;
    pthread_mutex_lock(&v->mutex);
    ret = v->value;
    pthread_mutex_unlock(&v->mutex);
    return ret;
}

static inline int smp_int_get_set(smp_int *v, int newvalue)
{
    int ret;
    pthread_mutex_lock(&v->mutex);
    ret = v->value;
    v->value = newvalue;
    pthread_mutex_unlock(&v->mutex);
    return ret;
}

static inline void smp_int_finalise(smp_int *v) { pthread_mutex_destroy(&v->mutex); }

#endif

/** @} */

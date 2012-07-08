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
* DOCUMENTATION */
/** @defgroup 
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _MUTEX_H
#define	_MUTEX_H

/**
 * This helper header allows to chose the kind of mutex used.
 * This is part of the sendto queue experiment.
 */

#include <pthread.h>
#include <dnscore/sys_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#ifndef MUTEX_USE_SPINLOCK
#define MUTEX_USE_SPINLOCK 0
#endif
    
#if MUTEX_USE_SPINLOCK == 0

typedef pthread_mutex_t mutex_t;

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

#define mutex_init(mtx)    pthread_mutex_init((mtx), NULL)
#define mutex_destroy(mtx) pthread_mutex_destroy(mtx)
#define mutex_lock(mtx)    pthread_mutex_lock(mtx)
#define mutex_trylock(mtx) pthread_mutex_trylock(mtx)
#define mutex_unlock(mtx)  pthread_mutex_unlock(mtx)

#else

typedef pthread_spinlock_t mutex_t;

#define MUTEX_INITIALIZER 0

#define mutex_init(mtx)    pthread_spin_init((mtx), 0)
#define mutex_destroy(mtx) pthread_spin_destroy(mtx)
#define mutex_lock(mtx)    pthread_spin_lock(mtx)
#define mutex_trylock(mtx) pthread_spin_trylock(mtx)
#define mutex_unlock(mtx)  pthread_spin_unlock(mtx)

#endif

typedef struct cond_t cond_t;

struct cond_t
{
    pthread_mutex_t lock; 
    pthread_cond_t  cond;
    u8              value;
};

void cond_init(cond_t *cond);
void cond_set(cond_t *cond, u8 value);
void cond_wait(cond_t *cond, u8 value);

struct smp_int
{
    mutex_t mutex;
    volatile int value;
};

#define SMP_INT_INITIALIZER {MUTEX_INITIALIZER,0}

typedef struct smp_int smp_int;

static inline void smp_int_init(smp_int *v)
{
    mutex_init(&v->mutex);
    v->value = 0;
}

static inline void smp_int_set(smp_int *v, int i)
{
    mutex_lock(&v->mutex);
    v->value = i;
    mutex_unlock(&v->mutex);
}


static inline void smp_int_inc(smp_int *v)
{
    mutex_lock(&v->mutex);
    v->value++;
    mutex_unlock(&v->mutex);
}

static inline void smp_int_dec(smp_int *v)
{
    mutex_lock(&v->mutex);
    v->value--;
    mutex_unlock(&v->mutex);
}

static inline bool smp_int_setifequal(smp_int *v, int from, int to)
{
    bool didit = FALSE;
    
    mutex_lock(&v->mutex);
    
    if(v->value == from)
    {
        v->value = to;
        didit = TRUE;
    }
    
    mutex_unlock(&v->mutex);
    
    return didit;
}

static inline int smp_int_get(smp_int *v)
{
    int ret;
    mutex_lock(&v->mutex);
    ret = v->value;
    mutex_unlock(&v->mutex);
    return ret;
}

static inline void smp_int_destroy(smp_int v)
{
    mutex_destroy(&v.mutex);
}

#ifdef	__cplusplus
}
#endif

#endif	/* _MUTEX_H */
/** @} */

/*----------------------------------------------------------------------------*/


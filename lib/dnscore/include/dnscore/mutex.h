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
*/
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

#include <unistd.h>
#include <pthread.h>

#include <dnscore/sys_types.h>
#include <dnscore/logger.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#ifndef MUTEX_USE_SPINLOCK
#define MUTEX_USE_SPINLOCK 0
#endif
    
#ifdef DEBUG
#define DEBUG_GROUP_MUTEX 1 // set to 0 do disable even in debug mode
#else
#define DEBUG_GROUP_MUTEX 0
#endif
    
#if MUTEX_USE_SPINLOCK == 0

typedef pthread_mutex_t mutex_t;

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

void mutex_init_recursive(mutex_t *mtx);
void mutex_init(mutex_t *mtx);
void mutex_destroy(mutex_t *mtx);

#ifndef DEBUG
//#define mutex_init(mtx)    pthread_mutex_init((mtx), NULL)
//#define mutex_destroy(mtx) pthread_mutex_destroy(mtx)
#define mutex_lock(mtx)    pthread_mutex_lock(mtx)
#define mutex_trylock(mtx) (pthread_mutex_trylock(mtx)==0)
#define mutex_unlock(mtx)  pthread_mutex_unlock(mtx)
#else

extern logger_handle *g_system_logger;
extern volatile bool mutex_ultraverbose;

static inline void mutex_lock(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_lock(%p)", mtx);
    }
    
    int err = pthread_mutex_lock(mtx);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_lock(%p): %r", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
    
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_lock(%p): locked", mtx);
    }
}

static inline bool mutex_trylock(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_trylock(%p)", mtx);
    }
    
    int err = pthread_mutex_trylock(mtx);
    
    if((err != 0) && (err != EBUSY))
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_trylock(%p): %r", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
    
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_trylock(%p): %s", mtx, (err == 0)?"locked":"failed");
    }
    
    return err == 0;
}

static inline void mutex_unlock(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_unlock(%p)", mtx);
    }
    
    int err = pthread_mutex_unlock(mtx);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_unlock(%p): %r", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
}

#endif

#else

typedef pthread_spinlock_t mutex_t;

#define MUTEX_INITIALIZER 0

#define mutex_init(mtx)    pthread_spin_init((mtx), 0)
#define mutex_destroy(mtx) pthread_spin_destroy(mtx)
#define mutex_lock(mtx)    pthread_spin_lock(mtx)
#define mutex_trylock(mtx) (pthread_spin_trylock(mtx)==0)
#define mutex_unlock(mtx)  pthread_spin_unlock(mtx)

#endif

typedef pthread_cond_t  cond_t;

static inline void cond_init(cond_t *cond)
{
    pthread_cond_init(cond, NULL);
}

static inline void cond_wait(cond_t *cond, mutex_t *mtx)
{
    pthread_cond_wait(cond, mtx);
}

static inline void cond_notify(cond_t *cond)
{
    pthread_cond_broadcast(cond);
}

static inline void cond_finalize(cond_t *cond)
{
    pthread_cond_destroy(cond);
}

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

static inline void smp_int_init_set(smp_int *v, int value)
{
    mutex_init(&v->mutex);
    v->value = value;
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

static inline void smp_int_add(smp_int *v, int value)
{
    mutex_lock(&v->mutex);
    v->value += value;
    mutex_unlock(&v->mutex);
}

static inline int smp_int_inc_get(smp_int *v)
{
    u32 ret;
    mutex_lock(&v->mutex);
    ret = ++v->value;
    mutex_unlock(&v->mutex);
    return ret;
}

static inline void smp_int_dec(smp_int *v)
{
    mutex_lock(&v->mutex);
    v->value--;
    mutex_unlock(&v->mutex);
}

static inline void smp_int_sub(smp_int *v, int value)
{
    mutex_lock(&v->mutex);
    v->value -= value;
    mutex_unlock(&v->mutex);
}

static inline int smp_int_dec_get(smp_int *v)
{
    int ret;
    mutex_lock(&v->mutex);
    ret = --v->value;
    mutex_unlock(&v->mutex);
    return ret;
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

static inline void smp_int_destroy(smp_int *v)
{
    mutex_destroy(&v->mutex);
}

#define GROUP_MUTEX_NOBODY  0x00
#define GROUP_MUTEX_DESTROY 0xfe

typedef struct group_mutex_t group_mutex_t;

struct group_mutex_t
{
    mutex_t mutex;
#ifdef DEBUG_GROUP_MUTEX
    const char *name; /* used for debugging */
#endif
    volatile u16 count;
    volatile u8 owner;
};

void group_mutex_init(group_mutex_t* mtx, const char *name);
void group_mutex_lock(group_mutex_t *mtx, u8 owner);
bool group_mutex_trylock(group_mutex_t *mtx, u8 owner);
void group_mutex_unlock(group_mutex_t *mtx, u8 owner);
bool group_mutex_transferlock(group_mutex_t *mtx, u8 owner, u8 newowner);
void group_mutex_destroy(group_mutex_t* mtx);

#ifdef	__cplusplus
}
#endif

#endif	/* _MUTEX_H */
/** @} */

/*----------------------------------------------------------------------------*/


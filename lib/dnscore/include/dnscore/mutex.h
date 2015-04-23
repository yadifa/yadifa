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
#include <time.h>

#include <dnscore/sys_types.h>
#include <dnscore/logger.h>

#if defined(__MACH__)
#include <dnscore/osx_clock_gettime.h>
#endif

#ifdef	__cplusplus
extern "C"
{
#endif
    
#ifndef DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#error "DNSCORE_HAS_MUTEX_DEBUG_SUPPORT must be set to either 0 or 1"
#endif

#ifndef MUTEX_USE_SPINLOCK
#define MUTEX_USE_SPINLOCK 0 // keep it that way
#endif

// DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    
#if !MUTEX_USE_SPINLOCK // do not use SPINLOCK

#if !DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
typedef pthread_mutex_t mutex_t;

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

#define mutex_lock(mtx)    pthread_mutex_lock(mtx)
#define mutex_trylock(mtx) (pthread_mutex_trylock(mtx)==0)
#define mutex_unlock(mtx)  pthread_mutex_unlock(mtx)

#else

struct mutex_t
{
    pthread_mutex_t mtx;
    volatile stacktrace trace;
    volatile pthread_t id;
    volatile u64 timestamp;
    char _MTXs[4];
};

typedef struct mutex_t mutex_t;

#define MUTEX_INITIALIZER {PTHREAD_MUTEX_INITIALIZER, 0, 0, 0, {'M', 'T', 'X', sizeof(mutex_t)}}

extern logger_handle *g_system_logger;
extern volatile bool mutex_ultraverbose;

void mutex_locked_set_add(mutex_t *mtx);
void mutex_locked_set_del(mutex_t *mtx);
void mutex_locked_set_monitor();

static inline void mutex_lock(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_lock(%p)", mtx);
    }
    
    int err = pthread_mutex_lock(&mtx->mtx);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_lock(%p): %r", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }

    mtx->trace = debug_stacktrace_get();
    mtx->id = pthread_self();
    mtx->timestamp = timeus();
    
    mutex_locked_set_add(mtx);
    
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
    
    int err = pthread_mutex_trylock(&mtx->mtx);
    
    if((err != 0) && (err != EBUSY))
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_trylock(%p): %r", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
    
    if(err == 0)
    {
        mtx->trace = debug_stacktrace_get();
        mtx->id = pthread_self();
        mtx->timestamp = timeus();

        mutex_locked_set_add(mtx);
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
   

    
    mutex_locked_set_del(mtx);
        
    stacktrace o_trace = mtx->trace;
    pthread_t o_id = mtx->id;
    u64 o_timestamp = mtx->timestamp;
    mtx->trace = NULL;
    mtx->id = 0;
    mtx->timestamp = 0;
        
    int err = pthread_mutex_unlock(&mtx->mtx);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_unlock(%p = {%p,%llu}) self=%p: %r", mtx, (intptr)o_id, o_timestamp, (intptr)pthread_self(), MAKE_ERRNO_ERROR(err));
        debug_stacktrace_log(g_system_logger, MSG_ERR, o_trace);
        logger_flush();
        abort();
    }
}

#endif

void mutex_init_recursive(mutex_t *mtx);
void mutex_init(mutex_t *mtx);
void mutex_destroy(mutex_t *mtx);

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

#define COND_INITIALIZER PTHREAD_COND_INITIALIZER

static inline void cond_init(cond_t *cond)
{
    pthread_cond_init(cond, NULL);
}

#if !DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
static inline void cond_wait(cond_t *cond, mutex_t *mtx)
{
    pthread_cond_wait(cond, mtx);
}
#else
static inline void cond_wait(cond_t *cond, mutex_t *mtx)
{
    pthread_cond_wait(cond, &mtx->mtx);
}
#endif

#if !_POSIX_TIMERS
u64 timeus();
#endif

static inline void cond_timedwait(cond_t *cond, mutex_t *mtx, u64 usec)
{
    struct timespec ts;
#if (defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0)) || defined(__MACH__)
    clock_gettime(CLOCK_REALTIME, &ts);
    
    usec *= 1000;
    
    ts.tv_nsec += usec;
        
    if(ts.tv_nsec > 1000000000LL)
    {
        ts.tv_sec += ts.tv_nsec / 1000000000LL;
        ts.tv_nsec = ts.tv_nsec % 1000000000LL;
    }
#else
    usec += timeus();
    usec *= 1000;
    ts.tv_nsec = usec % 1000000000LL;
    ts.tv_sec = usec / 1000000000LL;
#endif
    
#if !DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    pthread_cond_timedwait(cond, mtx, &ts);
#else
    pthread_cond_timedwait(cond, &mtx->mtx, &ts);
#endif
}

static inline void cond_notify_one(cond_t *cond)
{
    pthread_cond_signal(cond);
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

/**
 * A group mutex is a mutex that can be used by a group with or without exclusive access.
 * A mutex is private if the msb is set, it means only one of that group can own it
 * A mutex is shared if the msb is not set, it means many owner of the same type can own it
 */

#define GROUP_MUTEX_NOBODY  0x00
#define GROUP_MUTEX_READ    0x01    // default
#define GROUP_MUTEX_WRITE   0x82    // default
#define GROUP_MUTEX_PRIVATE 0x80    // THIS IS A MASK, ADD IT TO THE OWNER ID
#define GROUP_MUTEX_DESTROY 0xfe

typedef struct group_mutex_t group_mutex_t;

struct group_mutex_t
{
    mutex_t mutex;
    cond_t cond;
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    stacktrace trace;
    volatile pthread_t id;
    volatile u64 timestamp;
#endif
    volatile s32 count;
    volatile u8 owner;
};

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#define GROUP_MUTEX_INITIALIZER {MUTEX_INITIALIZER, COND_INITIALIZER, NULL, 0, 0, 0, 0}
#else
#define GROUP_MUTEX_INITIALIZER {MUTEX_INITIALIZER, COND_INITIALIZER, 0, 0}
#endif

void group_mutex_init(group_mutex_t* mtx);
void group_mutex_lock(group_mutex_t *mtx, u8 owner);
bool group_mutex_trylock(group_mutex_t *mtx, u8 owner);
void group_mutex_unlock(group_mutex_t *mtx, u8 owner);
bool group_mutex_transferlock(group_mutex_t *mtx, u8 owner, u8 newowner);
void group_mutex_destroy(group_mutex_t* mtx);
bool group_mutex_islocked(group_mutex_t* mtx);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
void group_mutex_locked_set_monitor();
#endif

/**
 * The shared group mutex is a group mutex that only uses N mutex(es) and N condition(s).
 * This is especially useful when millions of instances are required.
 * The mutex is used commonly by each structure as its own.
 * The downside is that every waiting task on the same mutex will be woken up each time one of them broadcasts the condition.
 * 
 * The current implementation uses N=1
 */

struct shared_group_shared_mutex_t
{
    mutex_t mutex;
    cond_t cond;
    volatile s32 rc;
};

typedef struct shared_group_shared_mutex_t shared_group_shared_mutex_t;

#define SHARED_GROUP_SHARED_MUTEX_INTIALIZER {MUTEX_INITIALIZER, COND_INITIALIZER, 0}

struct shared_group_mutex_t
{
    shared_group_shared_mutex_t *shared_mutex;
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    stacktrace trace;
    volatile pthread_t id;
    volatile u64 timestamp;
#endif

    volatile s32 count;
    volatile u8 owner;
};

#define SHARED_GROUP_MUTEX_INTIALIZER THIS_CANNOT_WORK

typedef struct shared_group_mutex_t shared_group_mutex_t;

void shared_group_shared_mutex_init(shared_group_shared_mutex_t* smtx);
void shared_group_shared_mutex_init_recursive(shared_group_shared_mutex_t* smtx);
void shared_group_shared_mutex_destroy(shared_group_shared_mutex_t* smtx);

void shared_group_mutex_init(shared_group_mutex_t* mtx, shared_group_shared_mutex_t* smtx, const char *name);
void shared_group_mutex_lock(shared_group_mutex_t *mtx, u8 owner);
bool shared_group_mutex_trylock(shared_group_mutex_t *mtx, u8 owner);
void shared_group_mutex_unlock(shared_group_mutex_t *mtx, u8 owner);
bool shared_group_mutex_transferlock(shared_group_mutex_t *mtx, u8 owner, u8 newowner);
void shared_group_mutex_destroy(shared_group_mutex_t* mtx);
bool shared_group_mutex_islocked(shared_group_mutex_t* mtx);
bool shared_group_mutex_islocked_by(shared_group_mutex_t *mtx, u8 owner);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
void shared_group_mutex_locked_set_monitor();
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _MUTEX_H */
/** @} */

/*----------------------------------------------------------------------------*/


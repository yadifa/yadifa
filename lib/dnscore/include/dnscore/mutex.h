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
#include <dnscore/thread.h>
#include <time.h>

#define SEMAPHORE_SUPPORT 0

#if SEMAPHORE_SUPPORT
#include <semaphore.h>
#endif

#include <dnscore/sys_types.h>
#include "timems.h"

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
    
#if MUTEX_USE_SPINLOCK && DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#error "Cannot mix spinlock and mutex debug support"
#endif

// these two are for error reporting in debug builds
#define MUTEX_LOCKED_TOO_MUCH_TIME_US 5000000
#define MUTEX_WAITED_TOO_MUCH_TIME_US 2000000

typedef pthread_cond_t cond_t;

#define COND_INITIALIZER PTHREAD_COND_INITIALIZER

// DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    
#if !MUTEX_USE_SPINLOCK // do not use SPINLOCK

#if !DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

typedef pthread_mutex_t mutex_t;

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

static inline int mutex_lock_unchecked(mutex_t* mtx)
{
    int ret = pthread_mutex_lock(mtx);
    return ret;
}

static inline int mutex_unlock_unchecked(mutex_t* mtx)
{
    int ret = pthread_mutex_unlock(mtx);
    return ret;
}

#if !DEBUG
#define mutex_lock(mtx__)    pthread_mutex_lock(mtx__)
#define mutex_trylock(mtx__) (pthread_mutex_trylock(mtx__)==0)
#define mutex_unlock(mtx__)  pthread_mutex_unlock(mtx__)
#else

static inline void mutex_lock(mutex_t* mtx)
{
    int ret = pthread_mutex_lock(mtx);

    if(ret != 0)
    {
        abort();
    }
}

static inline bool mutex_trylock(mutex_t* mtx)
{
    int ret = pthread_mutex_trylock(mtx);
    if((ret != 0) && (ret != EBUSY))
    {
        abort();
    }
    return ret == 0;
}

static inline void mutex_unlock(mutex_t* mtx)
{
    int ret = pthread_mutex_unlock(mtx);
    if(ret != 0)
    {
        abort();
    }
}

#if SEMAPHORE_SUPPORT

typedef sem_t semaphore_t;

static inline int semaphone_init(semaphore_t *sem)
{
    int ret = sem_init(sem, 0, 0);
    return ret;
}

static inline int semaphone_init_process_shared(semaphore_t *sem)
{
    int ret = sem_init(sem, 1, 1);
    return ret;
}

static inline void semaphore_finalize(semaphore_t *sem)
{
    sem_destroy(sem);
}

static inline void semaphore_lock(semaphore_t *sem)
{
    for(;;)
    {
        if(sem_wait(sem) == 0)
        {
            return;
        }

        int err = errno;
        if(err != EINTR)
        {
            abort();
        }
    }
}

static inline bool semaphore_trylock(semaphore_t *sem)
{
    int ret = sem_trywait(sem); // fails if
    return ret == 0;
}

static inline void semaphore_unlock(semaphore_t *sem)
{
    sem_post(sem);
}

#endif

#endif

#else // #if !DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

#define MUTEX_CONTENTION_MONITOR 0

#if MUTEX_CONTENTION_MONITOR
#pragma message("***********************************************************")
#pragma message("***********************************************************")
#pragma message("MUTEX_CONTENTION_MONITOR 1")
#pragma message("***********************************************************")
#pragma message("***********************************************************")
#endif

#if MUTEX_CONTENTION_MONITOR
struct mutex_contention_monitor_s;
void mutex_contention_object_create(void *mutex_ptr, bool recursive);
void mutex_contention_object_destroy(void *mutex_ptr);
struct mutex_contention_monitor_s * mutex_contention_lock_begin(thread_t thread, void *mutex_ptr, stacktrace st, const char *type_name);
void mutex_contention_lock_wait(struct mutex_contention_monitor_s *mcm);
void mutex_contention_lock_wait_with_mutex(thread_t thread, void *mutex_ptr);
void mutex_contention_lock_resume(struct mutex_contention_monitor_s *mcm);
void mutex_contention_lock_resume_with_mutex(thread_t thread, void *mutex_ptr);
void mutex_contention_lock_end(struct mutex_contention_monitor_s *mcm);
void mutex_contention_lock_fail(struct mutex_contention_monitor_s *mcm);
void mutex_contention_unlock(thread_t thread, void *mutex_ptr);
void mutex_contention_unlock_with_monitor(struct mutex_contention_monitor_s *mcm);

void mutex_contention_monitor_start();
void mutex_contention_monitor_stop();
#endif

typedef pthread_mutex_t mutex_t;

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

void mutex_lock(mutex_t *mtx);
bool mutex_trylock(mutex_t *mtx);
void mutex_unlock(mutex_t *mtx);

int mutex_lock_unchecked(mutex_t* mtx);
int mutex_unlock_unchecked(mutex_t* mtx);

#ifdef UNDEF_MSG_ERR
#undef MSG_ERR
#undef UNDEF_MSG_ERR
#endif

#endif // DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

void mutex_init_recursive(mutex_t *mtx);
int mutex_init_process_shared(mutex_t *mtx);
void mutex_init(mutex_t *mtx);
void mutex_destroy(mutex_t *mtx);

#if __APPLE__
typedef mutex_t spinlock_t;

static inline void spinlock_init(spinlock_t *spin)
{
    mutex_init(spin);
}

static inline void spinlock_destroy(spinlock_t *spin)
{
    mutex_destroy(spin);
}

static inline void spinlock_lock(spinlock_t *spin)
{
    mutex_lock(spin);
}

static inline void spinlock_unlock(spinlock_t *spin)
{
    mutex_unlock(spin);
}
#else

typedef pthread_spinlock_t spinlock_t;

static inline void spinlock_init(spinlock_t *spin)
{
    pthread_spin_init(spin, 0);
}

static inline void spinlock_destroy(spinlock_t *spin)
{
    pthread_spin_destroy(spin);
}

static inline void spinlock_lock(spinlock_t *spin)
{
    pthread_spin_lock(spin);
}

static inline void spinlock_unlock(spinlock_t *spin)
{
    pthread_spin_unlock(spin);
}

#endif

static inline void cond_wait(cond_t *cond, mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_wait_with_mutex(thread_self(), mtx);
#endif
#endif
    int ret = pthread_cond_wait(cond, mtx);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_resume_with_mutex(thread_self(), mtx);
#endif
#endif

    if(ret != 0)
    {
        perror("cond_wait");
        fflush(stderr);
    }
}

extern struct timespec __alarm__approximate_time_10s;

static inline void cond_wait_auto_time_out(cond_t *cond, mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_wait_with_mutex(thread_self(), mtx);
#endif
#endif

    int ret = pthread_cond_timedwait(cond, mtx, &__alarm__approximate_time_10s);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_resume_with_mutex(thread_self(), mtx);
#endif
#endif
#ifndef WIN32
    if(ret != 0)
    {
#if DEBUG
        fprintf(stderr, "cond_wait_auto_time_out: %s\n", strerror(ret));
        fflush(stderr);
#endif
        time_t now = time(NULL);
        __alarm__approximate_time_10s.tv_sec =  now + 10;
    }
#endif
}

#else

typedef pthread_spinlock_t mutex_t;

#define MUTEX_INITIALIZER 0

#define mutex_init(mtx)    pthread_spin_init((mtx), 0)
#define mutex_destroy(mtx) pthread_spin_destroy(mtx)
#define mutex_lock(mtx)    pthread_spin_lock(mtx)
#define mutex_trylock(mtx) (pthread_spin_trylock(mtx)==0)
#define mutex_unlock(mtx)  pthread_spin_unlock(mtx)

static inline void cond_wait(cond_t *cond, mutex_t *mtx)
{
    pthread_cond_wait(cond, mtx);
}

#endif

int cond_init_process_shared(cond_t *cond);

static inline void cond_init(cond_t *cond)
{
    pthread_cond_init(cond, NULL);
}

#if !_POSIX_TIMERS
#ifndef _TIMEMS_H
u64 timeus();
#endif
#endif

static inline int cond_timedwait(cond_t *cond, mutex_t *mtx, u64 usec)
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
    usec *= 1000ULL;
    ts.tv_nsec = usec % 1000000000LL;
    ts.tv_sec = usec / 1000000000LL;
#endif


#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_wait_with_mutex(thread_self(), mtx);
#endif
#endif

    int ret = pthread_cond_timedwait(cond, mtx, &ts);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_resume_with_mutex(thread_self(), mtx);
#endif
#endif

    return ret;
}

static inline int cond_timedwait_absolute(cond_t *cond, mutex_t *mtx, u64 usec_epoch)
{
    struct timespec ts;

    ts.tv_sec = usec_epoch / ONE_SECOND_US;
    ts.tv_nsec = (usec_epoch % ONE_SECOND_US) * 1000LL;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    #if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_wait_with_mutex(thread_self(), mtx);
#endif
#endif

    int ret = pthread_cond_timedwait(cond, mtx, &ts);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    #if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_resume_with_mutex(thread_self(), mtx);
#endif
#endif

    return ret;
}

static inline int cond_timedwait_absolute_ts(cond_t *cond, mutex_t *mtx, struct timespec *ts)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    #if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_wait_with_mutex(thread_self(), mtx);
#endif
#endif

    int ret = pthread_cond_timedwait(cond, mtx, ts);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    #if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_resume_with_mutex(thread_self(), mtx);
#endif
#endif

    return ret;
}

// Only use this if there is only one possible thread waiting on
// the condition.

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
    for(;;)
    {
        int ret = pthread_cond_destroy(cond);

        if(ret == 0)
        {
            break;
        }

        if(ret != EBUSY)
        {
            //osformat(termerr, "async_wait_finalize: pthread_cond_destroy returned another error than EBUSY: %r", MAKE_ERRNO_ERROR(ret));
            //flusherr();
            break;
        }

        usleep(5000);
    }
}

struct smp_int
{
    pthread_mutex_t mutex;
    volatile int value;
};

#define SMP_INT_INITIALIZER {PTHREAD_MUTEX_INITIALIZER,0}
#define SMP_INT_INITIALIZER_AT(value_) {PTHREAD_MUTEX_INITIALIZER, (value_)}

typedef struct smp_int smp_int;

static inline void smp_int_init(smp_int *v)
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
    u32 ret;
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
    bool didit = FALSE;
    
    pthread_mutex_lock(&v->mutex);
    
    if(v->value == from)
    {
        v->value = to;
        didit = TRUE;
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

static inline void smp_int_destroy(smp_int *v)
{
    pthread_mutex_destroy(&v->mutex);
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

#define GROUP_MUTEX_LOCKMASK_FLAG 0x7f
#define GROUP_MUTEX_EXCLUSIVE_FLAG 0x80

typedef struct group_mutex_t group_mutex_t;

struct group_mutex_t
{
    cond_t cond;
    mutex_t mutex;
    volatile s32 count;
    volatile u8 owner;
    volatile u8 reserved_owner;
};

#define GROUP_MUTEX_INITIALIZER {COND_INITIALIZER, MUTEX_INITIALIZER, 0, 0, 0}

void group_mutex_init(group_mutex_t* mtx);
void group_mutex_lock(group_mutex_t *mtx, u8 owner);
bool group_mutex_trylock(group_mutex_t *mtx, u8 owner);
void group_mutex_unlock(group_mutex_t *mtx, u8 owner);
bool group_mutex_transferlock(group_mutex_t *mtx, u8 owner, u8 newowner);
void group_mutex_destroy(group_mutex_t* mtx);
bool group_mutex_islocked(group_mutex_t* mtx);

void group_mutex_double_lock(group_mutex_t *mtx, u8 owner, u8 secondary_owner);
void group_mutex_double_unlock(group_mutex_t *mtx, u8 owner, u8 secondary_owner);
void group_mutex_exchange_locks(group_mutex_t *mtx, u8 owner, u8 secondary_owner);

static inline void group_mutex_read_lock(group_mutex_t *mtx)
{
    group_mutex_lock(mtx, GROUP_MUTEX_READ);
}

static inline void group_mutex_read_unlock(group_mutex_t *mtx)
{
    group_mutex_unlock(mtx, GROUP_MUTEX_READ);
}

static inline void group_mutex_write_lock(group_mutex_t *mtx)
{
    group_mutex_lock(mtx, GROUP_MUTEX_WRITE);
}

static inline void group_mutex_write_unlock(group_mutex_t *mtx)
{
    group_mutex_unlock(mtx, GROUP_MUTEX_WRITE);
}

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
#if MUTEX_CONTENTION_MONITOR
    struct mutex_contention_monitor_s *mcm;
#else
    stacktrace trace;
    volatile thread_t id;
    volatile u64 timestamp;
#endif
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

#ifdef	__cplusplus
}
#endif

#endif	/* _MUTEX_H */
/** @} */

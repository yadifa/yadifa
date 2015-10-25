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
/** @defgroup threading mutexes, ...
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

// CentOS 5.9 requires this to have PTHREAD_MUTEX_RECURSIVE
#define  _GNU_SOURCE 1

#include <pthread.h>

#include <sys/types.h>
#include <unistd.h>

#include "dnscore/mutex.h"

#define MODULE_MSG_HANDLE		g_system_logger
extern logger_handle *g_system_logger;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

#include "dnscore/ptr_set.h"

volatile bool mutex_ultraverbose = FALSE;

static pthread_mutex_t mutex_locked_set_mtx = PTHREAD_MUTEX_INITIALIZER;
static ptr_set mutex_locked_set = PTR_SET_PTR_EMPTY;

static pthread_mutex_t group_mutex_locked_set_mtx = PTHREAD_MUTEX_INITIALIZER;
static ptr_set group_mutex_locked_set = PTR_SET_PTR_EMPTY;

static pthread_mutex_t shared_group_mutex_locked_set_mtx = PTHREAD_MUTEX_INITIALIZER;
static ptr_set shared_group_mutex_locked_set = PTR_SET_PTR_EMPTY;

#if !DEBUG
void
mutex_locked_set_add(mutex_t *mtx)
{
    pthread_mutex_lock(&mutex_locked_set_mtx);
    ptr_node *node = ptr_set_avl_insert(&mutex_locked_set, mtx);
    node->value = mtx;
    pthread_mutex_unlock(&mutex_locked_set_mtx);
}

void
mutex_locked_set_del(mutex_t *mtx)
{
    pthread_mutex_lock(&mutex_locked_set_mtx);
    ptr_set_avl_delete(&mutex_locked_set, mtx);
    pthread_mutex_unlock(&mutex_locked_set_mtx);
}
#else
void
mutex_locked_set_add(mutex_t *mtx)
{
    int err;
    if((err = pthread_mutex_lock(&mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_locked_set_add(%p): pthread_mutex_lock: ", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
    
    ptr_node *node = ptr_set_avl_insert(&mutex_locked_set, mtx);

    node->value = mtx;

    if((err = pthread_mutex_unlock(&mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_locked_set_add(%p): pthread_mutex_unlock: ", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
}

void
mutex_locked_set_del(mutex_t *mtx)
{
    int err;
    if((err = pthread_mutex_lock(&mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_locked_set_del(%p): pthread_mutex_lock: ", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }

    ptr_set_avl_delete(&mutex_locked_set, mtx);
    
    if((err = pthread_mutex_unlock(&mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_locked_set_del(%p): pthread_mutex_unlock: ", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
}
#endif

void
mutex_locked_set_monitor()
{
    u64 now = timeus();
    pthread_mutex_lock(&mutex_locked_set_mtx);
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&mutex_locked_set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        mutex_t *mtx = (mutex_t*)node->key;
        u64 ts = mtx->timestamp;
        stacktrace trace = mtx->trace;
        pthread_t id = mtx->id;
        if((ts != 0) && (ts < now))
        {
            u64 dt = now - ts;
            if(dt > MUTEX_LOCKED_TOO_MUCH_TIME_US)
            {
                // locked for 5 seconds ... trouble
                log_warn("mutex@%p locked for %lluus by %p", mtx, dt, (intptr)id);
                debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, trace);
            }
        }
    }
    pthread_mutex_unlock(&mutex_locked_set_mtx);
}

#if !DEBUG
void
group_mutex_locked_set_add(group_mutex_t *mtx)
{
    pthread_mutex_lock(&group_mutex_locked_set_mtx);
    ptr_node *node = ptr_set_avl_insert(&group_mutex_locked_set, mtx);
    node->value = mtx;
    pthread_mutex_unlock(&group_mutex_locked_set_mtx);
}

void
group_mutex_locked_set_del(group_mutex_t *mtx)
{
    pthread_mutex_lock(&group_mutex_locked_set_mtx);
    ptr_set_avl_delete(&group_mutex_locked_set, mtx);
    pthread_mutex_unlock(&group_mutex_locked_set_mtx);
}

#else
void
group_mutex_locked_set_add(group_mutex_t *mtx)
{
    int err;
    if((err = pthread_mutex_lock(&group_mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "group_mutex_locked_set_add: pthread_mutex_lock: ", MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
    
    ptr_node *node = ptr_set_avl_insert(&group_mutex_locked_set, mtx);
    node->value = mtx;
    
    if((err = pthread_mutex_unlock(&group_mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "group_mutex_locked_set_add: pthread_mutex_unlock: ", MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
}

void
group_mutex_locked_set_del(group_mutex_t *mtx)
{
    int err;
    if((err = pthread_mutex_lock(&group_mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "group_mutex_locked_set_del: pthread_mutex_lock: ", MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
    
    ptr_set_avl_delete(&group_mutex_locked_set, mtx);

    if((err = pthread_mutex_unlock(&group_mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "group_mutex_locked_set_del: pthread_mutex_unlock: ", MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
}
#endif

void
group_mutex_locked_set_monitor()
{
    u64 now = timeus();
    pthread_mutex_lock(&group_mutex_locked_set_mtx);
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&group_mutex_locked_set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        group_mutex_t *mtx = (group_mutex_t*)node->key;
        u8 owner = mtx->owner;
        u64 ts = mtx->timestamp;
        stacktrace trace = mtx->trace;
        pthread_t id = mtx->id;
        if((ts != 0) && (ts < now))
        {
            u64 dt = now - ts;
            if(dt > MUTEX_LOCKED_TOO_MUCH_TIME_US)
            {
                // locked for 5 seconds ... trouble
                log_warn("group_mutex@%p locked by %x for %lluus by %p", mtx, owner, dt, (intptr)id);
                debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, trace);
            }
        }
    }
    pthread_mutex_unlock(&group_mutex_locked_set_mtx);
}

#if !DEBUG
void
shared_group_mutex_locked_set_add(shared_group_mutex_t *mtx)
{
    pthread_mutex_lock(&shared_group_mutex_locked_set_mtx);
    ptr_node *node = ptr_set_avl_insert(&shared_group_mutex_locked_set, mtx);
    node->value = mtx;
    pthread_mutex_unlock(&shared_group_mutex_locked_set_mtx);
}

void
shared_group_mutex_locked_set_del(shared_group_mutex_t *mtx)
{
    pthread_mutex_lock(&shared_group_mutex_locked_set_mtx);
    ptr_set_avl_delete(&shared_group_mutex_locked_set, mtx);
    pthread_mutex_unlock(&shared_group_mutex_locked_set_mtx);
}
#else
void
shared_group_mutex_locked_set_add(shared_group_mutex_t *mtx)
{
    int err;
    if((err = pthread_mutex_lock(&shared_group_mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "shared_group_mutex_locked_set_add: pthread_mutex_lock: ", MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
    
    ptr_node *node = ptr_set_avl_insert(&shared_group_mutex_locked_set, mtx);
    node->value = mtx;
    
    if((err = pthread_mutex_unlock(&shared_group_mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "shared_group_mutex_locked_set_add: pthread_mutex_unlock: ", MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
}

void
shared_group_mutex_locked_set_del(shared_group_mutex_t *mtx)
{
    int err;
    if((err = pthread_mutex_lock(&shared_group_mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "shared_group_mutex_locked_set_del: pthread_mutex_lock: ", MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
    
    ptr_set_avl_delete(&shared_group_mutex_locked_set, mtx);
    
    if((err = pthread_mutex_unlock(&shared_group_mutex_locked_set_mtx)) != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "shared_group_mutex_locked_set_del: pthread_mutex_unlock: ", MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
}
#endif

void
shared_group_mutex_locked_set_monitor()
{
    u64 now = timeus();
    pthread_mutex_lock(&shared_group_mutex_locked_set_mtx);
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&shared_group_mutex_locked_set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        shared_group_mutex_t *mtx = (shared_group_mutex_t*)node->key;
        u8 owner = mtx->owner;
        u64 ts = mtx->timestamp;
        stacktrace trace = mtx->trace;
        pthread_t id = mtx->id;
        if((ts != 0) && (ts < now))
        {
            u64 dt = now - ts;
            if(dt > MUTEX_LOCKED_TOO_MUCH_TIME_US)
            {
                // locked for 5 seconds ... trouble
                log_warn("shared_group_mutex@%p locked by %x for %lluus by %p", mtx, owner, dt, (intptr)id);
                debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, trace);
            }
        }
    }
    pthread_mutex_unlock(&shared_group_mutex_locked_set_mtx);
}

#endif

/*
 * Group mutex lock
 */

void
group_mutex_init(group_mutex_t* mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: init mutex@%p", mtx);
#endif
#endif
    
    mutex_init(&mtx->mutex);
    cond_init(&mtx->cond);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    mtx->trace = NULL;
    mtx->id = 0;
    mtx->timestamp = 0;
#endif
    mtx->count = 0;
    mtx->owner = GROUP_MUTEX_NOBODY;
}

bool
group_mutex_islocked(group_mutex_t *mtx)
{
    mutex_lock(&mtx->mutex);
    bool r = mtx->owner != 0;
    mutex_unlock(&mtx->mutex);
    return r;
}

void
group_mutex_lock(group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: locking mutex@%p for %x", mtx, owner);
#endif
    s64 start = timeus();
    
    pthread_t tid = pthread_self();
    
    if(tid == mtx->id)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "group_mutex_lock(%p): double lock from the same thread on a non-recursive mutex", mtx);
        debug_log_stacktrace(g_system_logger, MSG_ERR, "group_mutex_lock");
        logger_handle_msg(g_system_logger,MSG_ERR, "group_mutex_lock(%p): already locked by", mtx);
        debug_stacktrace_log(g_system_logger, MSG_ERR, mtx->trace);
        
        logger_flush();
        abort();
    }
    
#endif

    mutex_lock(&mtx->mutex);
    
    for(;;)
    {
		/*
			A simple way to ensure that a lock can be shared
			by similar entities or not.
			Sharable entities have their msb off.
		*/

        u8 co = mtx->owner & 0x7f;
        
        if(co == GROUP_MUTEX_NOBODY || co == owner)
        {
            yassert(mtx->count != MAX_S32);

            mtx->owner = owner & 0x7f;
            mtx->count++;

            break;
        }
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        s64 now = timeus();
        s64 d = now - start;
        pthread_t culprit = mtx->id;
        stacktrace trace = mtx->trace;
        s64 ts = mtx->timestamp;
        
        if(d > MUTEX_WAITED_TOO_MUCH_TIME_US)
        {
            log_warn("group_mutex(%p): waited for %llius already ...", mtx, d);
            debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_WARNING, "group_mutex");
        

            if(culprit != 0)
            {
                if(trace != NULL && ts != 0)
                {
                    log_warn("group_mutex(%p): the mutex has been locked for %llius already by %p", mtx, now - ts, culprit);
                    debug_stacktrace_log(g_system_logger, MSG_WARNING, trace);
                }
                else
                {
                    log_warn("shared_group_mutex(%p): the mutex was locked by %p", mtx, now - ts, culprit);
                }
            }
        }
        
        cond_timedwait(&mtx->cond, &mtx->mutex, MUTEX_WAITED_TOO_MUCH_TIME_US);
#else
        cond_wait(&mtx->cond, &mtx->mutex);
#endif
    }
    
    mutex_unlock(&mtx->mutex);
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    mtx->trace = debug_stacktrace_get();
    mtx->id = tid;
    mtx->timestamp = timeus();

    group_mutex_locked_set_add(mtx);
#endif
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif

}

bool
group_mutex_trylock(group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: trying to lock mutex@%p for %x", mtx, owner);
#endif
#endif

    mutex_lock(&mtx->mutex);

    u8 co = mtx->owner & 0x7f;
    
    if(co == GROUP_MUTEX_NOBODY || co == owner)
    {
        yassert(mtx->count != MAX_S32);

        mtx->owner = owner & 0x7f;
        mtx->count++;

        mutex_unlock(&mtx->mutex);
        
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        mtx->trace = debug_stacktrace_get();
        mtx->id = pthread_self();
        mtx->timestamp = timeus();
        
        group_mutex_locked_set_add(mtx);
#endif
        
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
        log_debug7("group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif
        return TRUE;
    }
    else
    {
        mutex_unlock(&mtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
        log_debug7("group_mutex: failed to lock mutex@%p for %x", mtx, owner);
#endif
#endif
        return FALSE;
    }
}

void
group_mutex_unlock(group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: unlocking mutex@%p for %x (owned by %x)", mtx, owner, mtx->owner);
#endif
#endif

    mutex_lock(&mtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    if((mtx->owner != (owner & 0x7f)) || (mtx->count == 0))
    {
        if(mtx->count > 0)
        {
            s64 now = timeus();

            log_err("group_mutex(%p): the mutex has been locked by %p/%x for %llius (count = %i) but is being unlocked by %p/%i",
                mtx,
                mtx->id, mtx->owner, now - mtx->timestamp, mtx->count,
                pthread_self(), owner);
        }
        else
        {
            log_err("group_mutex(%p): the mutex is not locked but is being unlocked by %p/%x",
                mtx, pthread_self(), owner);
        }

        debug_log_stacktrace(g_system_logger, MSG_ERR, "group_mutex_unlock");

        abort();
    }
#else
    yassert(mtx->owner == (owner & 0x7f));
    yassert(mtx->count != 0);
#endif

    mtx->count--;

    if(mtx->count == 0)
    {
        mtx->owner = GROUP_MUTEX_NOBODY;
        
        // wake up all the ones that were waiting for a clean ownership
        
        cond_notify(&mtx->cond);
    }
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    mtx->trace = NULL;
    mtx->id = 0;
    mtx->timestamp = 0;
    
    group_mutex_locked_set_del(mtx);
#endif
        
    mutex_unlock(&mtx->mutex);
}

bool
group_mutex_transferlock(group_mutex_t *mtx, u8 owner, u8 newowner)
{   
    bool r;
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: transferring ownership of mutex@%p from %x to %x (owned by %x)", mtx, owner, newowner, mtx->owner);
#endif
#endif

    mutex_lock(&mtx->mutex);

    u8 co = mtx->owner & 0x7f;
    
    if((r = (co == owner)))
    {
        mtx->owner = newowner;
    }

    mutex_unlock(&mtx->mutex);
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    mtx->trace = debug_stacktrace_get();
    mtx->id = pthread_self();
    mtx->timestamp = timeus();
#endif

    return r;
}

void
group_mutex_destroy(group_mutex_t* mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: destroy mutex@%p", mtx);
#endif
#endif
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    mutex_lock(&mtx->mutex);
    bool locked = (mtx->count > 0);
    mutex_unlock(&mtx->mutex);
    if(locked)
    {
        s64 now = timeus();

        log_err("group_mutex(%p): the mutex is locked by %p/%x for %llius (count = %i) but is being destroyed by %p",
            mtx,
            mtx->id, mtx->owner, now - mtx->timestamp, mtx->count,
            pthread_self());
        debug_log_stacktrace(g_system_logger, MSG_ERR, "group_mutex_destroy");
    }
#else
    yassert(mtx->count == 0);
#endif
    
    group_mutex_lock(mtx, GROUP_MUTEX_DESTROY);
    group_mutex_unlock(mtx, GROUP_MUTEX_DESTROY);
    
    cond_notify(&mtx->cond);
    cond_finalize(&mtx->cond);
    mutex_destroy(&mtx->mutex);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    mtx->trace = (stacktrace)~0;
    mtx->id = (pthread_t)~0;
    mtx->timestamp = ~0;
#endif
}

void
mutex_init_recursive(mutex_t *mtx)
{
    int err;
    
    ZEROMEMORY(mtx, sizeof(mutex_t));

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    mtx->recursive = TRUE;
    mtx->_MTXs[0] = 'M';
    mtx->_MTXs[1] = 'T';
    mtx->_MTXs[2] = 'X';
    mtx->_MTXs[3] = sizeof(mutex_t);
#endif

    pthread_mutexattr_t   mta;
    
    err = pthread_mutexattr_init(&mta);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init_recursive: attr %r", MAKE_ERRNO_ERROR(err));
    }
    
    err = pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init_recursive: set %r", MAKE_ERRNO_ERROR(err));
    }
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    err = pthread_mutex_init(&mtx->mtx, &mta);
#else
    err = pthread_mutex_init(mtx, &mta);
#endif
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init_recursive: %r", MAKE_ERRNO_ERROR(err));
    }
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_init(%p)", mtx);
    }
#endif
}

void
mutex_init(mutex_t *mtx)
{
#if !DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    int err = pthread_mutex_init(mtx, NULL);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init: %r", MAKE_ERRNO_ERROR(err));
    }
#else
    int err;
    
    ZEROMEMORY(mtx, sizeof(mutex_t));

    mtx->recursive = FALSE;
    mtx->_MTXs[0] = 'M';
    mtx->_MTXs[1] = 'T';
    mtx->_MTXs[2] = 'X';
    mtx->_MTXs[3] = sizeof(mutex_t);
    
    pthread_mutexattr_t   mta;
    
    err = pthread_mutexattr_init(&mta);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init (errorcheck): attr %r", MAKE_ERRNO_ERROR(err));
    }
    
    err = pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_ERRORCHECK);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init (errorcheck): set %r", MAKE_ERRNO_ERROR(err));
    }
    
    err = pthread_mutex_init(&mtx->mtx, &mta);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init (errorcheck): %r", MAKE_ERRNO_ERROR(err));
    }
    
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_init(%p)", mtx);
    }
    
#endif
}

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

void mutex_lock(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_lock(%p)", mtx);
    }
    
    pthread_t tid = pthread_self();
    
    if(tid == mtx->id && !mtx->recursive)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_lock(%p): double lock from the same thread on a non-recursive mutex", mtx);
        debug_log_stacktrace(g_system_logger, MSG_ERR, "mutex_lock");
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_lock(%p): already locked by", mtx);
        debug_stacktrace_log(g_system_logger, MSG_ERR, mtx->trace);
        logger_flush();
        abort();
    }
    
    s64 start = timeus();
    
    for(;;)
    {
        s64 timeout = timeus() + MUTEX_WAITED_TOO_MUCH_TIME_US;
        struct timespec lts;
        int err;
        
        lts.tv_sec = timeout / 1000000;
        lts.tv_nsec = (timeout % 1000000) * 1000;
    
        if((err = pthread_mutex_timedlock(&mtx->mtx, &lts)) == 0)
        {
            break;
        }
        
        if(err == ETIMEDOUT)
        {
            s64 now = timeus();
            s64 d = now - start;
            pthread_t culprit = mtx->id;
            stacktrace trace = mtx->trace;
            s64 ts = mtx->timestamp;
            log_warn("mutex_lock(%p): waited for %llius already ...", mtx, d);
            debug_log_stacktrace(g_system_logger, MSG_WARNING, "mutex");
            if(culprit != 0)
            {
                if(trace != NULL && ts != 0)
                {
                    log_warn("mutex_lock(%p): the mutex has been locked for %llius already by %p", mtx, now - ts, culprit);
                    debug_stacktrace_log(g_system_logger, MSG_WARNING, trace);
                }
                else
                {
                    log_warn("mutex_lock(%p): the mutex was locked by %p", mtx, now - ts, culprit);
                }
            }
            continue;
        }
        
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_lock(%p): %r", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
    

    mtx->trace = debug_stacktrace_get();
    mtx->id = tid;
    mtx->timestamp = timeus();
    
    mutex_locked_set_add(mtx);
    
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_lock(%p): locked", mtx);
    }
}
#endif

void
mutex_destroy(mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    int ebusy_count = 0;
    
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_destroy(%p)", mtx);
    }
    
#endif
    
    for(;;)
    {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        int err = pthread_mutex_destroy(&mtx->mtx);
        mtx->trace = (stacktrace)~0;
        mtx->id = (pthread_t)~0;
        mtx->timestamp = ~0;
        mtx->_MTXs[0]='m';
#else
        int err = pthread_mutex_destroy(mtx);
#endif
        
        switch(err)
        {
            case 0:
            {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
                if(ebusy_count > 0)
                {
                    logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_destroy: EBUSY #%i", ebusy_count);
                }
#endif
                return;
            }
            case EBUSY:
            {               
                usleep(1000);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
                ebusy_count++;
                
                if((ebusy_count & 0xfffff) == 0)
                {
                    debug_stacktrace_log(g_system_logger, MSG_DEBUG7,  mtx->trace);
                }
                
                if((ebusy_count & 0xfff) == 0)
                {
                    logger_handle_msg(g_system_logger,MSG_ERR, "mutex_destroy: EBUSY #%i", ebusy_count);
                }
#endif
                break;
            }
            default:
            {
                logger_handle_msg(g_system_logger,MSG_ERR, "mutex_destroy: %r", MAKE_ERRNO_ERROR(err));
                logger_flush();
                abort();
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

/*
 * Group mutex lock
 */

void
shared_group_shared_mutex_init(shared_group_shared_mutex_t* smtx)
{
    mutex_init(&smtx->mutex);
    cond_init(&smtx->cond);
    smtx->rc = 0;
}

void
shared_group_shared_mutex_init_recursive(shared_group_shared_mutex_t* smtx)
{
    mutex_init_recursive(&smtx->mutex);
    cond_init(&smtx->cond);
    smtx->rc = 0;
}

void
shared_group_shared_mutex_destroy(shared_group_shared_mutex_t* smtx)
{
    yassert(smtx->rc == 0);
    
    cond_finalize(&smtx->cond);
    mutex_destroy(&smtx->mutex);
}

void
shared_group_mutex_init(shared_group_mutex_t* mtx, shared_group_shared_mutex_t* smtx, const char *name)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: init mutex@%p+%p '%s'", mtx, smtx, name);
#endif
#endif
    
    mutex_lock(&smtx->mutex);
    smtx->rc++;
    mutex_unlock(&smtx->mutex);
    mtx->shared_mutex = smtx;
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    mtx->trace = NULL;
    mtx->id = 0;
    mtx->timestamp = 0;
#endif
    mtx->count = 0;
    mtx->owner = GROUP_MUTEX_NOBODY;
}

bool
shared_group_mutex_islocked(shared_group_mutex_t *mtx)
{
    mutex_lock(&mtx->shared_mutex->mutex);
    bool r = mtx->owner != 0;
    mutex_unlock(&mtx->shared_mutex->mutex);
    return r;
}

bool
shared_group_mutex_islocked_by(shared_group_mutex_t *mtx, u8 owner)
{
    mutex_lock(&mtx->shared_mutex->mutex);
    bool r = mtx->owner == (owner & 0x7f);
    mutex_unlock(&mtx->shared_mutex->mutex);
    return r;
}

void
shared_group_mutex_lock(shared_group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: locking mutex@%p for %x", mtx, owner);
#endif
    s64 start = timeus();
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    pthread_t tid = pthread_self();
    bool add;
    if(tid == mtx->id)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "shared_group_mutex(%p): double lock from the same thread on a non-recursive mutex", mtx);
        debug_log_stacktrace(g_system_logger, MSG_ERR, "shared_group_mutex");
        logger_handle_msg(g_system_logger,MSG_ERR, "shared_group_mutex(%p): already locked by", mtx);
        debug_stacktrace_log(g_system_logger, MSG_ERR, mtx->trace);
        logger_flush();
        abort();
    }
#endif
    
    mutex_lock(&mtx->shared_mutex->mutex);
        
    for(;;)
    {
		/*
			A simple way to ensure that a lock can be shared
			by similar entities or not.
			Sharable entities have their msb off.
		*/

        u8 co = mtx->owner & 0x7f;
        
        if(co == GROUP_MUTEX_NOBODY || co == owner)
        {
            yassert(mtx->count != MAX_S32);

            mtx->owner = owner & 0x7f;
            
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
            add = mtx->count == 0;
#endif
            
            mtx->count++;
            
            break;
        }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        s64 now = timeus();
        s64 d = now - start;
        pthread_t culprit = mtx->id;
        stacktrace trace = mtx->trace;
        s64 ts = mtx->timestamp;
        
        if(d > MUTEX_WAITED_TOO_MUCH_TIME_US)
        {
            log_warn("shared_group_mutex(%p): waited for %llius already ...", mtx, d);
            debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_WARNING, "shared_group_mutex");
        

            if(culprit != 0)
            {
                if(trace != NULL && ts != 0)
                {
                    log_warn("shared_group_mutex(%p): the mutex has been locked for %llius already by %p", mtx, now - ts, culprit);
                    debug_stacktrace_log(g_system_logger, MSG_WARNING, trace);
                }
                else
                {
                    log_warn("shared_group_mutex(%p): the mutex was locked by %p", mtx, now - ts, culprit);
                }
            }
        }
            
        cond_timedwait(&mtx->shared_mutex->cond, &mtx->shared_mutex->mutex, MUTEX_WAITED_TOO_MUCH_TIME_US);
#else
        cond_wait(&mtx->shared_mutex->cond, &mtx->shared_mutex->mutex);
#endif
    }
    
    mutex_unlock(&mtx->shared_mutex->mutex);
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    mtx->trace = debug_stacktrace_get();
    mtx->id = tid;
    mtx->timestamp = timeus();
    
    if(add)
    {
        shared_group_mutex_locked_set_add(mtx);
    }
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif

}

bool
shared_group_mutex_trylock(shared_group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: trying to lock mutex@%p for %x", mtx, owner);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);

    u8 co = mtx->owner & 0x7f;
        
    if(co == GROUP_MUTEX_NOBODY || co == owner)
    {
        yassert(mtx->count != MAX_S32);

        mtx->owner = owner & 0x7f;
        
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        bool add = mtx->count == 0;
#endif
        
        mtx->count++;
        
        mutex_unlock(&mtx->shared_mutex->mutex);
        
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
        log_debug7("shared_group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        mtx->trace = debug_stacktrace_get();
        mtx->id = pthread_self();
        mtx->timestamp = timeus();
        
        if(add)
        {
            shared_group_mutex_locked_set_add(mtx);
        }
#endif

        return TRUE;
    }
    else
    {
        mutex_unlock(&mtx->shared_mutex->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
        log_debug7("shared_group_mutex: failed to lock mutex@%p for %x", mtx, owner);
#endif
#endif

        return FALSE;
    }
}

void
shared_group_mutex_unlock(shared_group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: unlocking mutex@%p for %x (owned by %x)", mtx, owner, mtx->owner);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);

    yassert(mtx->owner == (owner & 0x7f));
    yassert(mtx->count != 0);
    
    mtx->count--;

    if(mtx->count == 0)
    {
        mtx->owner = GROUP_MUTEX_NOBODY;
        
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
        shared_group_mutex_locked_set_del(mtx);
#endif
        
        // wake up all the ones that were waiting for a clean ownership
        
        cond_notify(&mtx->shared_mutex->cond);
    }
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT    
    mtx->trace = NULL;
    mtx->id = 0;
    mtx->timestamp = 0;
#endif        
    mutex_unlock(&mtx->shared_mutex->mutex);
}

bool
shared_group_mutex_transferlock(shared_group_mutex_t *mtx, u8 owner, u8 newowner)
{   
    bool r;
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: transferring ownership of mutex@%p from %x to %x (owned by %x)", mtx, owner, newowner, mtx->owner);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);

    u8 co = mtx->owner & 0x7f;
    
    if((r = (co == owner)))
    {
        mtx->owner = newowner;
    }
    
    mutex_unlock(&mtx->shared_mutex->mutex);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    mtx->trace = debug_stacktrace_get();
    mtx->id = pthread_self();
    mtx->timestamp = timeus();
#endif
    
    return r;
}

void
shared_group_mutex_destroy(shared_group_mutex_t* mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: destroy mutex@%p", mtx);
#endif
#endif
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    mtx->trace = (stacktrace)~0;
    mtx->id = (pthread_t)~0;
    mtx->timestamp = ~0;
#endif
    
    mutex_lock(&mtx->shared_mutex->mutex);
    mtx->shared_mutex->rc--;
    mutex_unlock(&mtx->shared_mutex->mutex);
}


/** @} */

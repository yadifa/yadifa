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

#ifdef DEBUG
volatile bool mutex_ultraverbose = FALSE;
#endif

/*
 * Group mutex lock
 */

void
group_mutex_init(group_mutex_t* mtx, const char *name)
{
#if DEBUG_GROUP_MUTEX
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: init mutex@%p '%s'", mtx, name);
#endif
#endif
    
    mutex_init(&mtx->mutex);
#ifdef DEBUG_GROUP_MUTEX
    mtx->name = name;
#endif
    mtx->count = 0;
    mtx->owner = GROUP_MUTEX_NOBODY;
}

void
group_mutex_lock(group_mutex_t *mtx, u8 owner)
{
#if DEBUG_GROUP_MUTEX
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: locking mutex@%p '%s' for %x", mtx, mtx->name, owner);
#endif
#endif
    
    for(;;)
    {
        mutex_lock(&mtx->mutex);

		/*
			An simple way to ensure that a lock can be shared
			by similar entities or not.
			Sharable entities have their msb off.
		*/

        u8 co = mtx->owner & 0x7f;
        
        if(co == GROUP_MUTEX_NOBODY || co == owner)
        {
            yassert(mtx->count != 255);

            mtx->owner = owner & 0x7f;
            mtx->count++;
            
            mutex_unlock(&mtx->mutex);
            
            break;
        }

        mutex_unlock(&mtx->mutex);

        /*
         * Don't set this too low.
         * A lock basically slows down a task to 100000Hz
         * Waiting close to 0.00001 seconds is counterproductive.
         * Given that we are using locks for slow tasks, waiting 1ms seems reasonable.
         * 
         * todo: use broadcasts
         */

        usleep(1000);
    }
    
#if DEBUG_GROUP_MUTEX
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: locked mutex@%p '%s' for %x", mtx, mtx->name, owner);
#endif
#endif

}

bool
group_mutex_trylock(group_mutex_t *mtx, u8 owner)
{
#if DEBUG_GROUP_MUTEX
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: trying to lock mutex@%p '%s' for %x", mtx, mtx->name, owner);
#endif
#endif

    mutex_lock(&mtx->mutex);

    u8 co = mtx->owner & 0x7f;
    
    if(co == GROUP_MUTEX_NOBODY || co == owner)
    {
        yassert(mtx->count != 255);

        mtx->owner = owner & 0x7f;
        mtx->count++;

        mutex_unlock(&mtx->mutex);
        
#if DEBUG_GROUP_MUTEX
#ifdef MODULE_MSG_HANDLE
        log_debug7("group_mutex: locked mutex@%p '%s' for %x", mtx, mtx->name, owner);
#endif
#endif


        return TRUE;
    }

    mutex_unlock(&mtx->mutex);

#if DEBUG_GROUP_MUTEX
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: failed to lock mutex@%p '%s' for %x", mtx, mtx->name, owner);
#endif
#endif

    return FALSE;
}

void
group_mutex_unlock(group_mutex_t *mtx, u8 owner)
{
#if DEBUG_GROUP_MUTEX
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: unlocking mutex@%p '%s' for %x (owned by %x)", mtx, mtx->name, owner, mtx->owner);
#endif
#endif

    mutex_lock(&mtx->mutex);

    yassert(mtx->owner == (owner & 0x7f));
    yassert(mtx->count != 0);

    mtx->count--;

    if(mtx->count == 0)
    {
        mtx->owner = GROUP_MUTEX_NOBODY;
    }
    
    mutex_unlock(&mtx->mutex);
}

bool
group_mutex_transferlock(group_mutex_t *mtx, u8 owner, u8 newowner)
{   
    bool r;
    
#if DEBUG_GROUP_MUTEX
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: transferring ownership of mutex@%p '%s' from %x to %x (owned by %x)", mtx, mtx->name, owner, newowner, mtx->owner);
#endif
#endif

    mutex_lock(&mtx->mutex);

    u8 co = mtx->owner & 0x7f;
    
    if((r = (co == owner)))
    {
        mtx->owner = newowner;
    }

    mutex_unlock(&mtx->mutex);

    return r;
}

void
group_mutex_destroy(group_mutex_t* mtx)
{
#if DEBUG_GROUP_MUTEX
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: destroy mutex@%p '%s'", mtx, mtx->name);
#endif
#endif

    group_mutex_lock(mtx, GROUP_MUTEX_DESTROY);
    mutex_destroy(&mtx->mutex);
}

void
mutex_init_recursive(mutex_t *mtx)
{
    int err;
    
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
    
    err = pthread_mutex_init(mtx, &mta);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init_recursive: %r", MAKE_ERRNO_ERROR(err));
    }
    
#ifdef DEBUG
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_init(%p)", mtx);
    }
#endif
}

void
mutex_init(mutex_t *mtx)
{
#ifndef DEBUG
    int err = pthread_mutex_init(mtx, NULL);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init: %r", MAKE_ERRNO_ERROR(err));
    }
#else
    int err;
    
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
    
    err = pthread_mutex_init(mtx, &mta);
    
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

void
mutex_destroy(mutex_t *mtx)
{
#ifdef DEBUG
    int ebusy_count = 0;
    
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_destroy(%p)", mtx);
    }
    
#endif
    
    for(;;)
    {
        int err = pthread_mutex_destroy(mtx);
        
        switch(err)
        {
            case 0:
            {
#ifdef DEBUG
                if(ebusy_count > 0)
                {
                    logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_destroy: EBUSY #%i", ebusy_count);
                }
#endif
                return;
            }
            case EBUSY:
            {               
                usleep(10);
#ifdef DEBUG
                ebusy_count++;
                
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

/** @} */

/*----------------------------------------------------------------------------*/


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
 * @defgroup threading mutexes, ...
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include <dnscore/mutex.h>
#include <dnscore/mutex_logger.h>

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
static const char *mutex_type_name = "mutex_lock";
#endif
#endif

const bool mutex_ultraverbose = false;

void       mutex_init_recursive(mutex_t *mtx)
{
    int err;

    ZEROMEMORY(mtx, sizeof(mutex_t));

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(mtx, false);
#endif
#endif

    pthread_mutexattr_t mta;

    err = pthread_mutexattr_init(&mta);

    if(err != 0)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger, MSG_ERR, "mutex_init_recursive: attr %r", MAKE_ERRNO_ERROR(err));
#endif
    }

    err = pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);

    if(err != 0)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger, MSG_ERR, "mutex_init_recursive: set %r", MAKE_ERRNO_ERROR(err));
#endif
    }

    err = pthread_mutex_init(mutex_pthread_mutex_get(mtx), &mta);

#if DNSCORE_HAS_MUTEX_NOLOCK_CHECK
    mtx->_owner = NULL;
    mtx->_st = NULL;
#endif

    if(err != 0)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger, MSG_ERR, "mutex_init_recursive: %r", MAKE_ERRNO_ERROR(err));
#endif
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_init(%p)", mtx);
    }
#endif

    pthread_mutexattr_destroy(&mta);
}

int mutex_init_process_shared(mutex_t *mtx)
{
#if MUTEX_PROCESS_SHARED_SUPPORTED
    int ret;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(mtx, false);
#endif
#endif

    pthread_mutexattr_t attr;
    if((ret = pthread_mutexattr_init(&attr)) == 0)
    {
        ret = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

        if(ret == 0)
        {
            if((ret = pthread_mutex_init(mutex_pthread_mutex_get(mtx), &attr)) != 0)
            {
                ret = MAKE_ERRNO_ERROR(ret);
            }

#if DNSCORE_HAS_MUTEX_NOLOCK_CHECK
            mtx->_owner = NULL;
            mtx->_st = NULL;
#endif
        }
        else
        {
            ret = MAKE_ERRNO_ERROR(ret);
        }

        pthread_mutexattr_destroy(&attr);
    }
    else
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }

    return ret;
#else
    (void)mtx;
    return FEATURE_NOT_IMPLEMENTED_ERROR;
#endif
}

void mutex_init(mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(mtx, false);
#endif
#endif
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_NONE);
    int err = pthread_mutex_init(mutex_pthread_mutex_get(mtx), &attr);

#if DNSCORE_HAS_MUTEX_NOLOCK_CHECK
    mtx->_owner = NULL;
    mtx->_st = NULL;
#endif

    if(err != 0)
    {
        logger_handle_msg(g_system_logger, MSG_ERR, "mutex_init: %r", MAKE_ERRNO_ERROR(err));
    }
}

void mutex_destroy(mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    int ebusy_count = 0;

    if(mutex_ultraverbose)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_destroy(%p)", mtx);
#endif
    }
#endif

    for(;;)
    {
        int err = pthread_mutex_destroy(mutex_pthread_mutex_get(mtx));

        switch(err)
        {
            case 0:
            {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if DNSCORE_MUTEX_CONTENTION_MONITOR
                mutex_contention_object_destroy(mtx);
#endif
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
                if(ebusy_count > 0)
                {
                    logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_destroy: EBUSY #%i", ebusy_count);
                }
#endif
#if DNSCORE_HAS_MUTEX_NOLOCK_CHECK
                mtx->_st = debug_stacktrace_get();
#endif
                return;
            }
            case EBUSY:
            {
                usleep(1000);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
                ebusy_count++;

#ifdef MODULE_MSG_HANDLE
                if((ebusy_count & 0xfffff) == 0)
                {
                    debug_stacktrace_log(g_system_logger, MSG_DEBUG7, debug_stacktrace_get());
                }

                if((ebusy_count & 0xfff) == 0)
                {
                    logger_handle_msg(g_system_logger, MSG_ERR, "mutex_destroy: EBUSY #%i", ebusy_count);
                }
#endif
#endif
                break;
            }
            default:
            {
#ifdef MODULE_MSG_HANDLE
                logger_handle_msg(g_system_logger, MSG_ERR, "mutex_destroy: %r", MAKE_ERRNO_ERROR(err));
                logger_flush();
#endif
                abort();
            }
        }
    }
}

int cond_init_process_shared(cond_t *cond)
{
#if MUTEX_PROCESS_SHARED_SUPPORTED
    int                ret;
    pthread_condattr_t attr;
    if((ret = pthread_condattr_init(&attr)) == 0)
    {
        if((ret = pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) == 0)
        {
            ret = pthread_cond_init(cond, &attr);

            if(ret != 0)
            {
                ret = MAKE_ERRNO_ERROR(ret);
            }
        }
        else
        {
            ret = MAKE_ERRNO_ERROR(ret);
        }

        pthread_condattr_destroy(&attr);
    }
    else
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;

#else
    (void)cond;
    return FEATURE_NOT_IMPLEMENTED_ERROR;
#endif
}

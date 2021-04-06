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

/** @defgroup threading Threading, pools, queues, ...
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#pragma once

#include <pthread.h>
#include <signal.h>
#if HAVE_STDNORETURN_H
#include <stdnoreturn.h>
#else
#define noreturn
#endif
#include <dnscore/sys_types.h>

#if !DNSCORE_HAVE_GETTID
#include <sys/types.h>
#include <unistd.h>

static inline pid_t gettid()
{
    return getpid();
}
#endif

#ifdef	__cplusplus
extern "C"
{
#endif


typedef pthread_t thread_t;
typedef pthread_key_t thread_key_t;
typedef pthread_once_t thread_once_t;

#if DNSCORE_HAS_LOG_THREAD_TAG

/**
 * @note edf 20180118 -- tags are only read by the logger.  Given the current direction setting a tag will likely be sent trough the logger.
 * 
 */

#define THREAD_TAG_SIZE 8 /** @note edf 20180118 -- please do not change this value */

const char *thread_get_tag_with_pid_and_tid(pid_t pid, thread_t tid);
char *thread_copy_tag_with_pid_and_tid(pid_t pid, thread_t tid, char *out_9_bytes);
void thread_set_tag_with_pid_and_tid(pid_t pid, thread_t tid, const char *tag8chars);
void thread_clear_tag_with_pid_and_tid(pid_t pid, thread_t tid);

void thread_make_tag(const char *prefix, u32 index, u32 count, char *service_tag);

#endif

// system name (visible in top with threads enabled)

void thread_set_name(const char *name, int index, int count);

static inline thread_t thread_self()
{
    return pthread_self();
}

ya_result thread_create(thread_t *t, void* (*function_thread)(void*), void *function_args);

ya_result thread_kill(thread_t t, int signo);

static inline ya_result thread_join(thread_t t, void **thread_returnp)
{
    int ret = pthread_join(t, thread_returnp);
    if(ret != 0)
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

static noreturn inline void thread_exit(void *parm)
{
    pthread_exit(parm);
}

static inline ya_result thread_key_create(thread_key_t *k, void (*destructor) (void *))
{
    int ret = pthread_key_create(k, destructor);

    if(ret != 0)
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

static inline ya_result thread_key_destroy(thread_key_t k)
{
    int ret = pthread_key_delete(k);
    if(ret != 0)
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

static inline ya_result thread_key_set(thread_key_t k, const void *ptr)
{
    int ret = pthread_setspecific(k, ptr);
    if(ret != 0)
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

static inline void *thread_key_get(thread_key_t k)
{
    void* ret = pthread_getspecific(k);
    return ret;
}

static inline int thread_once(thread_once_t *once, void (*function) (void))
{
    int ret = pthread_once(once, function);
    if(ret != 0)
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

#ifdef	__cplusplus
}
#endif

/** @} */

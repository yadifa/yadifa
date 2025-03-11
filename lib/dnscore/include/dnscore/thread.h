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
 * @defgroup threading Threading, pools, queues, ...
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <pthread.h>
#include <signal.h>
#if HAVE_STDNORETURN_H
#include <stdnoreturn.h>
#elif __windows__
#define _Noreturn __declspec(noreturn)
#else
#define noreturn
#endif
#include <dnscore/sys_types.h>

#if !DNSCORE_HAVE_GETTID
#include <sys/types.h>
#include <unistd.h>
#include <stdatomic.h>
static inline pid_t gettid() { return getpid(); }
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef __THREAD_C__
extern atomic_int g_thread_starting;
extern atomic_int g_thread_running;
#endif

#define THREAD_ONCE_INIT PTHREAD_ONCE_INIT

typedef pthread_t      thread_t;
typedef pthread_key_t  thread_key_t;
typedef pthread_once_t thread_once_t;

#if DNSCORE_HAS_LOG_THREAD_TAG

/**
 * @note edf 20180118 -- tags are only read by the logger.  Given the current direction setting a tag will likely be
 * sent trough the logger.
 *
 */

#define THREAD_TAG_SIZE 8 /** @note edf 20180118 -- please do not change this value */

/**
 * Get the tag associated to that pid+thread
 *
 * @param pid
 * @param tid
 * @return
 */

const char *thread_get_tag_with_pid_and_tid(pid_t pid, thread_t tid);

/**
 * Copies the tag associated to that pid+thread into the given buffer
 *
 * @param pid
 * @param tid
 * @return
 */

char       *thread_copy_tag_with_pid_and_tid(pid_t pid, thread_t tid, char *out_9_bytes);

/**
 * Sets the tag of a pid+thread
 *
 * @param pid
 * @param tid
 * @return
 */

void        thread_set_tag_with_pid_and_tid(pid_t pid, thread_t tid, const char *tag8chars);

/**
 * Clears the tag of a pid+thread
 *
 * @param pid
 * @param tid
 * @return
 */

void        thread_clear_tag_with_pid_and_tid(pid_t pid, thread_t tid);

/**
 * Applies the defined tags once more.
 */

void thread_tag_push_tags();

/**
 *
 * Makes a tag based on a prefix, an index and a maximum value for that index
 *
 * @param prefix
 * @param index
 * @param count
 * @param service_tag
 */

void thread_make_tag(const char *prefix, uint32_t index, uint32_t count, char *service_tag);

/**
 * Logs all the pid/thread tags in the system logger.
 */

void thread_tag_log_tags();

#endif

/**
 * Sets the name of the current thread.
 *
 * @param name
 * @param index
 * @param count
 */
void thread_set_name(const char *name, int index, int count);

/**
 * Returns the current thread
 *
 * @return the current thread
 */
static inline thread_t  thread_self() { return pthread_self(); }

/**
 * Creates a thread
 *
 * @param t will recieve the thread handle
 * @param function_thread the function of the thread
 * @param function_args arguments passed to the thread function
 * @return an error code
 */

ya_result thread_create(thread_t *t, void *(*function_thread)(void *), void *function_args);

/**
 * Sends a signal to a thread
 *
 * @param t
 * @param signo
 * @return
 */

ya_result thread_kill(thread_t t, int signo);

/**
 * Waits until a thread terminates
 *
 * @param t
 * @param thread_returnp
 * @return
 */

static inline ya_result thread_join(thread_t t, void **thread_returnp)
{
    int ret = pthread_join(t, thread_returnp);
    if(ret != 0)
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

/**
 * Terminates a thread.
 *
 * @param parm
 */
static _Noreturn inline void thread_exit(void *parm)
{
    --g_thread_running;
    pthread_exit(parm);
}

/**
 * Create a key for a thread
 *
 * @param k
 * @param destructor
 * @return
 */

static inline ya_result thread_key_create(thread_key_t *k, void (*destructor)(void *))
{
    int ret = pthread_key_create(k, destructor);

    if(ret != 0)
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

/**
 * Destroys a thread key
 *
 * @param k
 * @return
 */

static inline ya_result thread_key_destroy(thread_key_t k)
{
    int ret = pthread_key_delete(k);
    if(ret != 0)
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

/**
 * Sets a value to a thread key
 *
 * @param k
 * @param ptr
 * @return
 */

static inline ya_result thread_key_set(thread_key_t k, const void *ptr)
{
    int ret = pthread_setspecific(k, ptr);
    if(ret != 0)
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

/**
 * Gets the value of a thread key
 *
 * @param k
 * @return
 */

static inline void *thread_key_get(thread_key_t k)
{
    void *ret = pthread_getspecific(k);
    return ret;
}

/**
 * Executes a function exactly once
 *
 * @param once needs to be intialised with THREAD_ONCE_INIT
 * @param function
 * @return
 */
static inline int thread_once(thread_once_t *once, void (*function)(void))
{
    int ret = pthread_once(once, function);
    if(ret != 0)
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

/**
 *
 * Attempts to hint the kernel about putting a thread on a core.
 *
 * @param t
 * @param cpu_index
 *
 * @return an error code
 */

ya_result thread_setaffinity(thread_t t, int cpu_index);

#ifdef __cplusplus
}
#endif

/** @} */

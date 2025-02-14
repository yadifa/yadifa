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
 * @defgroup threading Threading, pools, queues, ...
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"

#define __THREAD_C__ 1

#if HAS_PTHREAD_SETNAME_NP
#define _GNU_SOURCE 1
#endif

#include <sys/types.h>
#include <unistd.h>
#include <stdatomic.h>

atomic_int g_thread_starting = 0;
atomic_int g_thread_running = 0; // for this to be accurate, thread functions need to return

#include <dnscore/thread.h>

#include "dnscore/logger.h"

#define MODULE_MSG_HANDLE g_system_logger
#define PTHCWRAP_TAG      0x5041525743485450

#if HAS_PTHREAD_SETNAME_NP

static int thread_count_get_nibbles(uint32_t count)
{
    int ret = 0;

    do
    {
        ++ret;
        count >>= 4;
    } while(count > 0);

    return ret;
}

void thread_set_name(const char *name, int index, int count)
{
    // 16 is the size limit for this, cfr man page
    char tmp[16 + 1];
    char fmt[32]; // :%010x/%010x

    if(--count <= 0)
    {
        strcpy_ex(tmp, name, sizeof(tmp));
    }
    else
    {
        int count_digits = thread_count_get_nibbles((uint32_t)count);
        if(count_digits < 5)
        {
            // name:xx/xx
            int suffix_len = count_digits * 2 + 2;
            int avail = sizeof(tmp) - 1 - suffix_len;
            strcpy_ex(tmp, name, avail);
            int size = strlen(tmp);
            snformat(fmt, sizeof(fmt), ":%%0%ix/%%0%ix", count_digits,
                     count_digits); // 11 bytes long as count_digits is at most 4 so 1 byte long
            snprintf(&tmp[size], sizeof(tmp) - size, fmt, index, count);
        }
        else
        {
            // name:xx

            assert(count_digits <= 8);

            int suffix_len = count_digits + 1;
            int avail = sizeof(tmp) - 1 - suffix_len;
            strcpy_ex(tmp, name, avail);
            int size = strlen(tmp);
            snformat(fmt, sizeof(fmt), ":%%0%ix", count_digits); // 6 bytes as count_digits is at most 8 so 1 byte long
            snprintf(&tmp[size], sizeof(tmp) - size, fmt, index, count);
        }
    }

#if __APPLE__
    pthread_setname_np(tmp);
#elif __NetBSD__
    pthread_setname_np(thread_self(), tmp, strlen(tmp));
#else
    pthread_setname_np(thread_self(), tmp);
#endif // __APPLE__
}
#else
void thread_set_name(const char *name, int index, int count)
{
    (void)name;
    (void)index;
    (void)count;
}
#endif

struct pthead_create_wrapper_s
{
    void *(*function_thread)(void *);
    void *function_args;
};

/**
 * This wrapper allows to intercept thread creation.
 * The goal is to update collections and statistics.
 *
 * @param args_
 * @return
 */

static void *pthead_create_wrapper(void *args_)
{
    ++g_thread_running;
    --g_thread_starting;
    char name_buffer[32];
    strcpy(name_buffer, "unnamed");

#if __linux__
    pthread_getname_np(thread_self(), name_buffer, sizeof(name_buffer));
#endif

    struct pthead_create_wrapper_s *args = (struct pthead_create_wrapper_s *)args_;
    log_debug1("thread: %p (%i) started (%s)", (void *)pthread_self(), gettid(), name_buffer);
    struct pthead_create_wrapper_s targs = *args;
    free(args);
    void *thread_ret = targs.function_thread(targs.function_args);
    log_debug1("thread: %p (%i) stopped (%s) with %p", (void *)pthread_self(), gettid(), name_buffer, thread_ret);
    --g_thread_running;
    return thread_ret;
}

/**
 * Creates a thread
 *
 * @param t will recieve the thread handle
 * @param function_thread the function of the thread
 * @param function_args arguments passed to the thread function
 * @return an error code
 */

ya_result thread_create(thread_t *t, void *(*function_thread)(void *), void *function_args)
{
    int                             ret;

    struct pthead_create_wrapper_s *pthead_create_wrapper_args;
    // MUST be malloc
    MALLOC_OBJECT_OR_DIE(pthead_create_wrapper_args, struct pthead_create_wrapper_s, PTHCWRAP_TAG);
    pthead_create_wrapper_args->function_thread = function_thread;
    pthead_create_wrapper_args->function_args = function_args;
    ret = pthread_create(t, NULL, pthead_create_wrapper, pthead_create_wrapper_args);
    if(ret == 0)
    {
        ++g_thread_starting;
    }
    else
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}

/**
 * Sends a signal to a thread
 *
 * @param t
 * @param signo
 * @return
 */

ya_result thread_kill(thread_t t, int signo)
{
#if __unix__
    int ret = pthread_kill(t, signo);
    if(ret != 0)
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
#else
    return ERROR;
#endif
}

#if __APPLE__
ya_result pthread_setaffinity_macos(pthread_t t, int cpu_index);
#endif

/**
 *
 * Attempts to hint the kernel about putting a thread on a core.
 *
 * @param t
 * @param cpu_index
 *
 * @return an error code
 */

ya_result thread_setaffinity(thread_t t, int cpu_index)
{
    ya_result ret;
#if __linux__ || __FreeBSD__
    cpu_set_t mycpu;
    CPU_ZERO(&mycpu);
    CPU_SET(cpu_index, &mycpu);
    int code = pthread_setaffinity_np(t, sizeof(cpu_set_t), &mycpu);
    if(code == 0)
    {
        ret = SUCCESS;
    }
    else
    {
        ret = MAKE_ERRNO_ERROR(code);
    }
#elif __NetBSD__
    cpuset_t *mycpu = cpuset_create();
    if(mycpu != NULL)
    {
        cpuset_zero(mycpu);
        cpuset_set((cpuid_t)affinity_with, mycpu);
        int code;
        if((code = pthread_setaffinity_np(t, cpuset_size(mycpu), mycpu)) == 0)
        {
            ret = SUCCESS;
        }
        else
        {
            ret = MAKE_ERRNO_ERROR(code)
        }
        cpuset_destroy(mycpu);
    }
#elif __APPLE__
    ret = pthread_setaffinity_apple((pthread_t)t, cpu_index);
#else
    ret = FEATURE_NOT_IMPLEMENTED_ERROR;
#endif
    return ret;
}

/** @} */

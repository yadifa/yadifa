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

/**
 * @defgroup mutex-test
 * @ingroup test
 * @brief mutex test
 * 
 * This test just shows the cost of a mutex applied around a relatively expensive (~40ms) operation
 * on a single-threaded task.
 * 
 * As expected, it appears negligible. (Looking for a bottleneck in an accelerator)
 */

#include <dnscore/dnscore.h>
#include <dnscore/sys_types.h>
#include <dnscore/mutex.h>
#include <dnscore/timems.h>
#include <dnscore/format.h>
#include <dnscore/thread_pool.h>

#define BUFFER_SIZE 0x1000000

static u8 *buffer = NULL;
static size_t buffer_size = 0;

static void something_callback_1(void* notused)
{
    (void)notused;
    for(size_t i = 0; i < buffer_size; ++i)
    {
        buffer[i] = i ^ (i >> 7);
    }
}

static void something_callback_2(void* notused)
{
    (void)notused;
    size_t n = MIN(buffer_size, 1024);
    for(size_t i = 0; i < n; ++i)
    {
        buffer[i] = i ^ (i >> 7);
    }
}


static void loop(size_t n, callback_function *cb, const char *name)
{
    s64 start = timeus();
    for(size_t i = 0; i < n; ++i)
    {
        cb(NULL);
    }
    s64 stop = timeus();

    s64 d = stop - start;
    
    double total = (1.0 * d) / ONE_SECOND_US_F;
    double unit = total / n;
    
    formatln("loop: %s: %llu: total = %12.6fus, unit = %12.6fus", name, n, total, unit);
}


static void mutex_lock_unlock_loop(size_t n, callback_function *cb, const char *name)
{
    mutex_t mtx;
    mutex_init(&mtx);
    s64 start = timeus();
    for(size_t i = 0; i < n; ++i)
    {
        mutex_lock(&mtx);
        cb(NULL);
        mutex_unlock(&mtx);
    }
    s64 stop = timeus();
    mutex_destroy(&mtx);
    s64 d = stop - start;
    
    double total = (1.0 * d) / ONE_SECOND_US_F;
    double unit = total / n;
    
    formatln("mutex_lock_unlock_loop: %s: %llu: total = %12.6fus, unit = %12.6fus", name, n, total, unit);
}

static void group_mutex_lock_unlock_loop(size_t n, callback_function *cb, const char *name)
{
    group_mutex_t mtx;
    group_mutex_init(&mtx);
    s64 start = timeus();
    for(size_t i = 0; i < n; ++i)
    {
        group_mutex_lock(&mtx, GROUP_MUTEX_WRITE);
        cb(NULL);
        group_mutex_unlock(&mtx, GROUP_MUTEX_WRITE);
    }
    s64 stop = timeus();
    group_mutex_destroy(&mtx);
    s64 d = stop - start;
    
    double total = (1.0 * d) / ONE_SECOND_US_F;
    double unit = total / n;
    
    formatln("group_mutex_lock_unlock_loop: %s: %llu: total = %12.6fus, unit = %12.6fus", name, n, total, unit);
}

static ya_result
speed_test()
{
    MALLOC_OBJECT_ARRAY_OR_DIE(buffer, u8, BUFFER_SIZE, GENERIC_TAG);
    buffer_size = BUFFER_SIZE;

    loop(1, something_callback_1, "one pass");

    for(size_t i = 1; i <= 32; i <<= 1)
    {
        println("-------------------------------------------------------------");
        formatln("slow: loop for  %llu", i);
        println("-------------------------------------------------------------");
        loop(i, something_callback_1, "slow set");
        println("");
        mutex_lock_unlock_loop(i, something_callback_1, "slow set");
        println("");
        group_mutex_lock_unlock_loop(i, something_callback_1, "slow set");
        println("");
        flushout();
    }

    for(size_t i = 1; i <= 32; i <<= 1)
    {
        println("-------------------------------------------------------------");
        formatln("fast: loop for  %llu", i);
        println("-------------------------------------------------------------");
        loop(i, something_callback_2, "fast set");
        println("");
        mutex_lock_unlock_loop(i, something_callback_2, "fast set");
        println("");
        group_mutex_lock_unlock_loop(i, something_callback_2, "fast set");
        println("");
        flushout();
    }

    return 0;
}

struct exclusion_arg
{
    mutex_t mtx;
    s64 loops;
    s64 current;
    s64 workers;
};

static void*
exclusion_mutex_thread(void *_arg)
{
    struct exclusion_arg *arg = (struct exclusion_arg*)_arg;

    mutex_lock(&arg->mtx);
    ++arg->workers;
    mutex_unlock(&arg->mtx);

    for(s64 i = 0; i < arg->loops; ++i)
    {
        mutex_lock(&arg->mtx);
        ++arg->current;
        mutex_unlock(&arg->mtx);
    }

    return NULL;
}

static bool
exclusion_test(int workers, s64 loops)
{
    struct exclusion_arg parms = {MUTEX_INITIALIZER, loops, 0, 0};
    struct thread_pool_s *tp = thread_pool_init(workers, 8);

    if(tp == NULL)
    {
        println("tp");
        exit(EXIT_FAILURE);
    }

    thread_pool_task_counter task_counter;
    thread_pool_counter_init(&task_counter, 0);

    for(int i = 0; i < workers; ++i)
    {
        char tmp[16];
        snformat(tmp, sizeof(tmp), "xmtx%i", i);
        thread_pool_enqueue_call(tp, exclusion_mutex_thread, &parms, &task_counter, tmp);
    }

    for(;;)
    {
        usleep_ex(10000);
        mutex_lock(&parms.mtx);
        bool all_started = (int)parms.workers == workers;
        mutex_unlock(&parms.mtx);

        if(all_started)
        {
            break;
        }
    }

    for(;;)
    {
        if(thread_pool_counter_get_value(&task_counter) == 0)
        {
            break;
        }
        usleep_ex(10000);
    }

    s64 expected = parms.workers * parms.loops;

    formatln("exclusion_test: expected %lli, got %lli", expected, parms.current);

    thread_pool_destroy(tp);
    tp = NULL;

    return expected == parms.current;
}

struct exclusion_group_arg
{
    group_mutex_t mtx;
    s64 loops;
    s64 current;
    s64 workers;
};

static void*
exclusion_group_mutex_thread(void *_arg)
{
    struct exclusion_group_arg *arg = (struct exclusion_group_arg*)_arg;

    group_mutex_lock(&arg->mtx, GROUP_MUTEX_WRITE);
    ++arg->workers;
    group_mutex_unlock(&arg->mtx, GROUP_MUTEX_WRITE);

    for(s64 i = 0; i < arg->loops; ++i)
    {
        group_mutex_lock(&arg->mtx, GROUP_MUTEX_WRITE);
        ++arg->current;
        group_mutex_unlock(&arg->mtx, GROUP_MUTEX_WRITE);
    }

    return NULL;
}

static bool
exclusion_group_test(int workers, s64 loops)
{
    struct exclusion_group_arg parms = {GROUP_MUTEX_INITIALIZER, loops, 0, 0};
    struct thread_pool_s *tp = thread_pool_init(workers, 8);
    thread_pool_task_counter task_counter;
    thread_pool_counter_init(&task_counter, 0);

    for(int i = 0; i < workers; ++i)
    {
        char tmp[16];
        snformat(tmp, sizeof(tmp), "xgmtx%i", i);
        thread_pool_enqueue_call(tp, exclusion_group_mutex_thread, &parms, &task_counter, tmp);
    }

    for(;;)
    {
        usleep_ex(10000);
        group_mutex_lock(&parms.mtx, GROUP_MUTEX_READ);
        bool all_started = (int)parms.workers == workers;
        group_mutex_unlock(&parms.mtx, GROUP_MUTEX_READ);

        if(all_started)
        {
            break;
        }
    }
/*
    for(;;)
    {
        if(thread_pool_counter_get_value(&task_counter) == 0)
        {
            break;
        }
        usleep_ex(10000);
    }
*/
    thread_pool_counter_wait_below_or_equal(&task_counter, 0);

    s64 expected = parms.workers * parms.loops;

    formatln("exclusion_group_test: expected %lli, got %lli", expected, parms.current);

    thread_pool_destroy(tp);
    tp = NULL;

    return expected == parms.current;
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* initializes the core library */
    dnscore_init();

    exclusion_test(2, 1000000);
    exclusion_test(4, 2000000);
    exclusion_test(8, 4000000);
    exclusion_group_test(2, 1000000);
    exclusion_group_test(4, 2000000);
    exclusion_group_test(8, 4000000);
    speed_test();
    
    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}

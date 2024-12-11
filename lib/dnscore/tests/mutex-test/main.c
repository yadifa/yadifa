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

#include "yatest.h"
#include "dnscore/thread_pool.h"
#include "dnscore/mutex_logger.h"
#include <dnscore/dnscore.h>
#include <dnscore/mutex.h>

static void init() { dnscore_init(); }

static void finalise() { dnscore_finalize(); }

#define BUFFER_SIZE 0x1000000

static uint8_t *buffer = NULL;
static size_t   buffer_size = 0;

static void     something_callback_1(void *notused)
{
    (void)notused;
    for(size_t i = 0; i < buffer_size; ++i)
    {
        buffer[i] = i ^ (i >> 7);
    }
}

static void something_callback_2(void *notused)
{
    (void)notused;
    size_t n = MIN(buffer_size, 1024);
    for(size_t i = 0; i < n; ++i)
    {
        buffer[i] = i ^ (i >> 7);
    }
}

static void loop(size_t n, callback_function_t *cb, const char *name)
{
    int64_t start = timeus();
    for(size_t i = 0; i < n; ++i)
    {
        cb(NULL);
    }
    int64_t stop = timeus();

    int64_t d = stop - start;

    double  total = (1.0 * d) / ONE_SECOND_US_F;
    double  unit = total / n;

    yatest_log("loop: %s: %llu: total = %12.6fus, unit = %12.6fus", name, n, total, unit);
}

static void mutex_lock_unlock_loop(size_t n, callback_function_t *cb, const char *name)
{
    mutex_t mtx;
    mutex_init(&mtx);
    int64_t start = timeus();
    for(size_t i = 0; i < n; ++i)
    {
        mutex_lock(&mtx);
        cb(NULL);
        mutex_unlock(&mtx);
    }
    int64_t stop = timeus();
    mutex_destroy(&mtx);
    int64_t d = stop - start;

    double  total = (1.0 * d) / ONE_SECOND_US_F;
    double  unit = total / n;

    yatest_log("mutex_lock_unlock_loop: %s: %llu: total = %12.6fus, unit = %12.6fus", name, n, total, unit);
}

static void group_mutex_lock_unlock_loop(size_t n, callback_function_t *cb, const char *name)
{
    group_mutex_t mtx;
    group_mutex_init(&mtx);
    int64_t start = timeus();
    for(size_t i = 0; i < n; ++i)
    {
        group_mutex_lock(&mtx, GROUP_MUTEX_WRITE);
        cb(NULL);
        group_mutex_unlock(&mtx, GROUP_MUTEX_WRITE);
    }
    int64_t stop = timeus();
    group_mutex_destroy(&mtx);
    int64_t d = stop - start;

    double  total = (1.0 * d) / ONE_SECOND_US_F;
    double  unit = total / n;
    yatest_log("group_mutex_lock_unlock_loop: %s: %llu: total = %12.6fus, unit = %12.6fus", name, n, total, unit);
}

static int speed_test()
{
    init();

    MALLOC_OBJECT_ARRAY_OR_DIE(buffer, uint8_t, BUFFER_SIZE, GENERIC_TAG);
    buffer_size = BUFFER_SIZE;

    loop(1, something_callback_1, "one pass");

    for(size_t i = 1; i <= 32; i <<= 1)
    {
        yatest_log("-------------------------------------------------------------");
        yatest_log("slow: loop for  %llu", i);
        yatest_log("-------------------------------------------------------------");
        loop(i, something_callback_1, "slow set");
        yatest_log("");
        mutex_lock_unlock_loop(i, something_callback_1, "slow set");
        yatest_log("");
        group_mutex_lock_unlock_loop(i, something_callback_1, "slow set");
        yatest_log("");
        flushout();
    }

    for(size_t i = 1; i <= 32; i <<= 1)
    {
        yatest_log("-------------------------------------------------------------");
        yatest_log("fast: loop for  %llu", i);
        yatest_log("-------------------------------------------------------------");
        loop(i, something_callback_2, "fast set");
        yatest_log("");
        mutex_lock_unlock_loop(i, something_callback_2, "fast set");
        yatest_log("");
        group_mutex_lock_unlock_loop(i, something_callback_2, "fast set");
        yatest_log("");
        flushout();
    }

    finalise();

    return 0;
}

struct exclusion_arg
{
    mutex_t mtx;
    int64_t loops;
    int64_t current;
    int64_t workers;
};

static void exclusion_mutex_thread(void *_arg)
{
    struct exclusion_arg *arg = (struct exclusion_arg *)_arg;
    int64_t               lock_count = 0;
    int64_t               unlock_count = 0;

    mutex_lock(&arg->mtx);
    ++arg->workers;
    mutex_unlock(&arg->mtx);

    for(int_fast64_t i = 0; i < arg->loops; ++i)
    {
        mutex_lock(&arg->mtx);
        ++arg->current;
        mutex_unlock(&arg->mtx);
    }
    yatest_log("lock count %lli, unlock count %lli", lock_count, unlock_count);
}

static bool exclusion_test(int workers, int64_t loops, bool recursive)
{
    struct exclusion_arg  parms = {MUTEX_INITIALIZER, loops, 0, 0};
    struct thread_pool_s *tp = thread_pool_init(workers, 8);

    if(tp == NULL)
    {
        yatest_log("tp");
        exit(EXIT_FAILURE);
    }

    if(recursive)
    {
        mutex_init_recursive(&parms.mtx);
    }

    thread_pool_task_counter_t task_counter;
    thread_pool_counter_init(&task_counter, 0);

    for(int_fast32_t i = 0; i < workers; ++i)
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

    int64_t expected = parms.workers * parms.loops;

    yatest_log("exclusion_test: expected %lli, got %lli", expected, parms.current);
    if(expected != parms.current)
    {
        yatest_err("exclusion_test: expected %lli, got %lli", expected, parms.current);
        exit(1);
    }

    thread_pool_destroy(tp);
    tp = NULL;

    mutex_finalize(&parms.mtx);

    return expected == parms.current;
}

struct exclusion_group_arg
{
    group_mutex_t mtx;
    int64_t       loops;
    int64_t       current;
    int64_t       workers;
};

static void exclusion_group_mutex_thread(void *_arg)
{
    struct exclusion_group_arg *arg = (struct exclusion_group_arg *)_arg;
    int64_t                     lock_count = 0;
    int64_t                     unlock_count = 0;

    group_mutex_write_lock(&arg->mtx);
    ++arg->workers;
    group_mutex_write_unlock(&arg->mtx);

    for(int_fast64_t i = 0; i < arg->loops; ++i)
    {
        if(group_mutex_islocked(&arg->mtx))
        {
            ++lock_count;
        }
        else
        {
            ++unlock_count;
        }

        group_mutex_write_lock(&arg->mtx);
        ++arg->current;
        group_mutex_write_unlock(&arg->mtx);
    }
    yatest_log("lock count %lli, unlock count %lli", lock_count, unlock_count);
}

static bool exclusion_group_test(int workers, int64_t loops)
{
    struct exclusion_group_arg parms = {GROUP_MUTEX_INITIALIZER, loops, 0, 0};
    struct thread_pool_s      *tp = thread_pool_init(workers, 8);

    if(tp == NULL)
    {
        yatest_log("%r", THREAD_CREATION_ERROR);
        return false;
    }

    thread_pool_task_counter_t task_counter;
    thread_pool_counter_init(&task_counter, 0);

    for(int_fast32_t i = 0; i < workers; ++i)
    {
        char tmp[16];
        snformat(tmp, sizeof(tmp), "xgmtx%i", i);
        thread_pool_enqueue_call(tp, exclusion_group_mutex_thread, &parms, &task_counter, tmp);
    }

    for(;;)
    {
        usleep_ex(10000);
        group_mutex_read_lock(&parms.mtx);
        bool all_started = (int)parms.workers == workers;
        group_mutex_read_unlock(&parms.mtx);

        if(all_started)
        {
            break;
        }
    }

    thread_pool_counter_wait_below_or_equal(&task_counter, 0);

    int64_t expected = parms.workers * parms.loops;

    yatest_log("exclusion_group_test: expected %lli, got %lli", expected, parms.current);
    if(expected != parms.current)
    {
        yatest_err("exclusion_group_test: expected %lli, got %lli", expected, parms.current);
        exit(1);
    }

    thread_pool_destroy(tp);
    tp = NULL;

    return expected == parms.current;
}

struct exclusion_shared_group_arg
{
    shared_group_mutex_t mtx;
    int64_t              loops;
    int64_t              current;
    int64_t              workers;
};

static void exclusion_shared_group_mutex_thread(void *_arg)
{
    struct exclusion_shared_group_arg *arg = (struct exclusion_shared_group_arg *)_arg;
    int64_t                            lock_count = 0;
    int64_t                            unlock_count = 0;
    int64_t                            r_lock_count = 0;
    int64_t                            r_unlock_count = 0;
    int64_t                            w_lock_count = 0;
    int64_t                            w_unlock_count = 0;

    shared_group_mutex_lock(&arg->mtx, GROUP_MUTEX_WRITE);
    ++arg->workers;
    shared_group_mutex_unlock(&arg->mtx, GROUP_MUTEX_WRITE);

    for(int_fast64_t i = 0; i < arg->loops; ++i)
    {
        if(shared_group_mutex_islocked(&arg->mtx))
        {
            ++lock_count;
        }
        else
        {
            ++unlock_count;
        }
        if(shared_group_mutex_islocked_by(&arg->mtx, GROUP_MUTEX_READ))
        {
            ++r_lock_count;
        }
        else
        {
            ++r_unlock_count;
        }
        if(shared_group_mutex_islocked_by(&arg->mtx, GROUP_MUTEX_WRITE))
        {
            ++w_lock_count;
        }
        else
        {
            ++w_unlock_count;
        }

        shared_group_mutex_lock(&arg->mtx, GROUP_MUTEX_WRITE);
        ++arg->current;
        shared_group_mutex_unlock(&arg->mtx, GROUP_MUTEX_WRITE);
    }
    yatest_log("lock count %lli, unlock count %lli", lock_count, unlock_count);
    yatest_log("read: lock count %lli, unlock count %lli", r_lock_count, r_unlock_count);
    yatest_log("write: lock count %lli, unlock count %lli", w_lock_count, w_unlock_count);
}

static bool exclusion_shared_group_test(int workers, int64_t loops, bool recursive)
{
    shared_group_shared_mutex_t sgs_mutex;
    if(recursive)
    {
        shared_group_shared_mutex_init_recursive(&sgs_mutex);
    }
    else
    {
        shared_group_shared_mutex_init(&sgs_mutex);
    }

    struct exclusion_shared_group_arg parms = {{0}, loops, 0, 0};
    struct thread_pool_s             *tp = thread_pool_init(workers, 8);

    if(tp == NULL)
    {
        yatest_log("%r", THREAD_CREATION_ERROR);
        return false;
    }

    shared_group_mutex_init(&parms.mtx, &sgs_mutex, "shared-mutex");

    thread_pool_task_counter_t task_counter;
    thread_pool_counter_init(&task_counter, 0);

    for(int_fast32_t i = 0; i < workers; ++i)
    {
        char tmp[16];
        snformat(tmp, sizeof(tmp), "xgmtx%i", i);
        thread_pool_enqueue_call(tp, exclusion_shared_group_mutex_thread, &parms, &task_counter, tmp);
    }

    for(;;)
    {
        usleep_ex(10000);
        shared_group_mutex_lock(&parms.mtx, GROUP_MUTEX_READ);
        bool all_started = (int)parms.workers == workers;
        shared_group_mutex_unlock(&parms.mtx, GROUP_MUTEX_READ);

        if(all_started)
        {
            break;
        }
    }

    thread_pool_counter_wait_below_or_equal(&task_counter, 0);

    int64_t expected = parms.workers * parms.loops;

    yatest_log("exclusion_shared_group_test: expected %lli, got %lli", expected, parms.current);
    if(expected != parms.current)
    {
        yatest_err("exclusion_shared_group_test: expected %lli, got %lli", expected, parms.current);
        exit(1);
    }

    thread_pool_destroy(tp);
    tp = NULL;

    shared_group_mutex_destroy(&parms.mtx);
    shared_group_shared_mutex_destroy(&sgs_mutex);

    return expected == parms.current;
}

static void exclusion_shared_group_mutex_try_thread(void *_arg)
{
    struct exclusion_shared_group_arg *arg = (struct exclusion_shared_group_arg *)_arg;
    int64_t                            lock_count = 0;
    int64_t                            unlock_count = 0;
    int64_t                            r_lock_count = 0;
    int64_t                            r_unlock_count = 0;
    int64_t                            w_lock_count = 0;
    int64_t                            w_unlock_count = 0;

    while(!shared_group_mutex_trylock(&arg->mtx, GROUP_MUTEX_WRITE))
    {
    }
    ++arg->workers;
    shared_group_mutex_unlock(&arg->mtx, GROUP_MUTEX_WRITE);

    for(int_fast64_t i = 0; i < arg->loops; ++i)
    {
        if(shared_group_mutex_islocked(&arg->mtx))
        {
            ++lock_count;
        }
        else
        {
            ++unlock_count;
        }
        if(shared_group_mutex_islocked_by(&arg->mtx, GROUP_MUTEX_READ))
        {
            ++r_lock_count;
        }
        else
        {
            ++r_unlock_count;
        }
        if(shared_group_mutex_islocked_by(&arg->mtx, GROUP_MUTEX_WRITE))
        {
            ++w_lock_count;
        }
        else
        {
            ++w_unlock_count;
        }

        while(!shared_group_mutex_trylock(&arg->mtx, GROUP_MUTEX_WRITE))
        {
        }
        ++arg->current;
        shared_group_mutex_unlock(&arg->mtx, GROUP_MUTEX_WRITE);
    }
    yatest_log("lock count %lli, unlock count %lli", lock_count, unlock_count);
    yatest_log("read: lock count %lli, unlock count %lli", r_lock_count, r_unlock_count);
    yatest_log("write: lock count %lli, unlock count %lli", w_lock_count, w_unlock_count);
}

static bool exclusion_shared_group_try_test(int workers, int64_t loops, bool recursive)
{
    shared_group_shared_mutex_t sgs_mutex;
    if(recursive)
    {
        shared_group_shared_mutex_init_recursive(&sgs_mutex);
    }
    else
    {
        shared_group_shared_mutex_init(&sgs_mutex);
    }

    struct exclusion_shared_group_arg parms = {{0}, loops, 0, 0};
    struct thread_pool_s             *tp = thread_pool_init(workers, 8);

    if(tp == NULL)
    {
        yatest_log("%r", THREAD_CREATION_ERROR);
        return false;
    }

    shared_group_mutex_init(&parms.mtx, &sgs_mutex, "shared-mutex");

    thread_pool_task_counter_t task_counter;
    thread_pool_counter_init(&task_counter, 0);

    for(int_fast32_t i = 0; i < workers; ++i)
    {
        char tmp[16];
        snformat(tmp, sizeof(tmp), "xgmtx%i", i);
        thread_pool_enqueue_call(tp, exclusion_shared_group_mutex_try_thread, &parms, &task_counter, tmp);
    }

    for(;;)
    {
        usleep_ex(10000);
        shared_group_mutex_lock(&parms.mtx, GROUP_MUTEX_READ);
        bool all_started = (int)parms.workers == workers;
        shared_group_mutex_unlock(&parms.mtx, GROUP_MUTEX_READ);

        if(all_started)
        {
            break;
        }
    }

    thread_pool_counter_wait_below_or_equal(&task_counter, 0);

    int64_t expected = parms.workers * parms.loops;

    yatest_log("exclusion_shared_group_test: expected %lli, got %lli", expected, parms.current);
    if(expected != parms.current)
    {
        yatest_err("exclusion_shared_group_test: expected %lli, got %lli", expected, parms.current);
        exit(1);
    }

    thread_pool_destroy(tp);
    tp = NULL;

    shared_group_mutex_destroy(&parms.mtx);
    shared_group_shared_mutex_destroy(&sgs_mutex);

    return expected == parms.current;
}

static int exclusion2_test()
{
    init();
    exclusion_test(2, 1000000, false);
    finalise();
    return 0;
}

static int exclusion4_test()
{
    init();
    exclusion_test(4, 2000000, false);
    finalise();
    return 0;
}

static int exclusion8_test()
{
    init();
    exclusion_test(8, 4000000, false);
    finalise();
    return 0;
}

static int exclusion_recursive2_test()
{
    init();
    exclusion_test(2, 1000000, true);
    finalise();
    return 0;
}

static int exclusion_recursive4_test()
{
    init();
    exclusion_test(4, 2000000, true);
    finalise();
    return 0;
}

static int exclusion_recursive8_test()
{
    init();
    exclusion_test(8, 4000000, true);
    finalise();
    return 0;
}

static int exclusion_group2_test()
{
    init();
    exclusion_group_test(2, 1000000);
    finalise();
    return 0;
}

static int exclusion_group4_test()
{
    init();
    exclusion_group_test(4, 2000000);
    finalise();
    return 0;
}

static int exclusion_group8_test()
{
    init();
    exclusion_group_test(8, 4000000);
    finalise();
    return 0;
}

static int exclusion_shared_mutex2_test()
{
    init();
    exclusion_shared_group_test(2, 1000000, false);
    finalise();
    return 0;
}

static int exclusion_shared_mutex4_test()
{
    init();
    exclusion_shared_group_test(4, 2000000, false);
    finalise();
    return 0;
}

static int exclusion_shared_mutex8_test()
{
    init();
    exclusion_shared_group_test(8, 4000000, false);
    finalise();
    return 0;
}

static int exclusion_shared_mutex_try2_test()
{
    init();
    exclusion_shared_group_try_test(2, 1000000, false);
    finalise();
    return 0;
}

static int exclusion_shared_mutex_recursive2_test()
{
    init();
    exclusion_shared_group_test(2, 1000000, true);
    finalise();
    return 0;
}

static int exclusion_shared_mutex_recursive4_test()
{
    init();
    exclusion_shared_group_test(4, 2000000, true);
    finalise();
    return 0;
}

static int exclusion_shared_mutex_recursive8_test()
{
    init();
    exclusion_shared_group_test(8, 4000000, true);
    finalise();
    return 0;
}

static int shared_group_mutex_transferlock_test()
{
    init();
    shared_group_shared_mutex_t sgs_mutex;
    shared_group_mutex_t        mtx;
    shared_group_shared_mutex_init(&sgs_mutex);
    shared_group_mutex_init(&mtx, &sgs_mutex, "shared-mutex");
    shared_group_mutex_lock(&mtx, GROUP_MUTEX_WRITE);
    if(shared_group_mutex_transferlock(&mtx, GROUP_MUTEX_READ, GROUP_MUTEX_READ))
    {
        yatest_err("shared_group_mutex_transferlock W => R, R should have failed.");
        return 1;
    }
    if(!shared_group_mutex_transferlock(&mtx, GROUP_MUTEX_WRITE, GROUP_MUTEX_READ))
    {
        yatest_err("shared_group_mutex_transferlock W => W, R should have succeeded.");
        return 1;
    }
    shared_group_mutex_unlock(&mtx, GROUP_MUTEX_READ);
    shared_group_mutex_destroy(&mtx);
    finalise();
    return 0;
}

static int mutex_debug_test()
{
    init();
    stacktrace st = debug_stacktrace_get();
    mutex_debug_stacktrace_log(g_system_logger, MSG_INFO, st);

    mutex_debug_logger_handle_msg(g_system_logger, MSG_INFO, "Hello World!");

    mutex_debug_log_stacktrace(g_system_logger, MSG_INFO, "prefix-");
    finalise();
    return 0;
}

static int mutex_futex_test()
{
#if DNSCORE_FUTEX_SUPPORT
    return 0;
#else
    dnscore_futex_not_supported();
    return 0;
#endif
}

// cond_timedwait
// cond_wait_auto_time_out
// shared_group_mutex_trylock
// shared_group_mutex_transferlock

YATEST_TABLE_BEGIN
YATEST(exclusion2_test)
YATEST(exclusion4_test)
YATEST(exclusion8_test)
YATEST(exclusion_recursive2_test)
YATEST(exclusion_recursive4_test)
YATEST(exclusion_recursive8_test)
YATEST(exclusion_group2_test)
YATEST(exclusion_group4_test)
YATEST(exclusion_group8_test)
YATEST(exclusion_shared_mutex2_test)
YATEST(exclusion_shared_mutex4_test)
YATEST(exclusion_shared_mutex8_test)
YATEST(exclusion_shared_mutex_try2_test)
YATEST(exclusion_shared_mutex_recursive2_test)
YATEST(exclusion_shared_mutex_recursive4_test)
YATEST(exclusion_shared_mutex_recursive8_test)
YATEST(shared_group_mutex_transferlock_test)
YATEST(speed_test)
YATEST(mutex_debug_test)
YATEST(mutex_futex_test)
YATEST_TABLE_END

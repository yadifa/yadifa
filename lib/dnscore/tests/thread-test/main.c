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
#include "dnscore/logger.h"
#include "dnscore/sys_get_cpu_count.h"

#include <dnscore/dnscore.h>
#include <dnscore/thread.h>
#include <dnscore/thread_pool.h>

#define THREAD_COUNT 256

static atomic_int                 count = 0;
static atomic_bool                run = true;
static thread_pool_task_counter_t counter;
static thread_pool_task_counter_t counter2;

static void                      *thread_main(void *args)
{
    (void)args;

    yatest_log("thread start");
    ++count;
    while(run)
    {
        yatest_sleep(1);
    }
    return NULL;
}

static int thread_test()
{
    int ret;
    int cpu_count = sys_get_cpu_count();

    thread_t tids[THREAD_COUNT];

    if(cpu_count < 0)
    {
        cpu_count = 1;
    }

    for(int i = 0; i < THREAD_COUNT; ++i)
    {
        thread_t id;
        yatest_log("creating thread %i", i);
        ret = thread_create(&id, thread_main, NULL);
        if(ret < 0)
        {
            yatest_err("thread_create %i failed");
            for(int j = 0; j < i; ++j)
            {
                thread_kill(tids[j], SIGINT);
                thread_join(tids[j], NULL);
            }
            exit(1);
        }

        tids[i] = id;
        if(i < THREAD_COUNT / 2)
        {
            thread_set_name("test", i, THREAD_COUNT);
        }
        else
        {
            thread_set_name("test", i * 65536, THREAD_COUNT * 65536);
        }

        yatest_log("thread_setaffinity(%i)", i % cpu_count);
        ret = thread_setaffinity(id, i % cpu_count);
        yatest_log("thread_setaffinity returned %08x", ret);
    }

    yatest_log("waiting count = %i = %i", count, THREAD_COUNT);

    for(int i = 0; (i < 60) && (count < THREAD_COUNT); ++i)
    {
        yatest_log("count: %i", count);
        yatest_sleep(1);
    }
    if(count != THREAD_COUNT)
    {
        yatest_err("timeout");
    }
    yatest_log("killing threads");
    run = false;
    for(int j = 0; j < THREAD_COUNT; ++j)
    {
        // thread_kill(tids[j], SIGUSR1);
        thread_join(tids[j], NULL);
    }
    return 0;
}

#if DNSCORE_HAS_LOG_THREAD_TAG
void thread_tag_log_tags();
void thread_tag_push_tags();
#endif

static int tag_test()
{
    dnscore_init();
    pid_t             pid = getpid();
    thread_t          tid = thread_self();
    static const char tagtext[] = "thrdtest";
    char              buffer[16];
    memset(buffer, 0xff, sizeof(buffer));
    thread_set_tag_with_pid_and_tid(pid, tid, tagtext);
    const char *tag_back = thread_get_tag_with_pid_and_tid(pid, tid);
    if(memcmp(tag_back, tagtext, 8) != 0)
    {
        yatest_err("thread_get_tag_with_pid_and_tid failed");
        return 1;
    }
    char *tag_copy = thread_copy_tag_with_pid_and_tid(pid, tid, buffer);
    if(strcmp(tag_copy, tagtext) != 0)
    {
        yatest_err("thread_copy_tag_with_pid_and_tid failed");
        return 1;
    }
    memset(buffer, 0xff, sizeof(buffer));
    thread_clear_tag_with_pid_and_tid(pid, tid);
    const char *clear_tag_back = thread_get_tag_with_pid_and_tid(pid, tid);
    if(memcmp(clear_tag_back, tagtext, 8) == 0)
    {
        yatest_err("thread_get_tag_with_pid_and_tid failed (after clear)");
        return 1;
    }
    char *clear_tag_copy = thread_copy_tag_with_pid_and_tid(pid, tid, buffer);
    if(strcmp(clear_tag_copy, tagtext) == 0)
    {
        yatest_err("thread_copy_tag_with_pid_and_tid failed (after clear)");
        return 1;
    }

    thread_make_tag("test", 0, 0x100, buffer);
    if(strcmp(buffer, "test  00") != 0)
    {
        yatest_err("thread_make_tag 0x100 failed");
        return 1;
    }

    thread_make_tag("test", 0, 0x1000, buffer);
    if(strcmp(buffer, "test 000") != 0)
    {
        yatest_err("thread_make_tag 0x1000 failed");
        return 1;
    }

    thread_make_tag("test", 0, 0x10000, buffer);
    if(strcmp(buffer, "test0000") != 0)
    {
        yatest_err("thread_make_tag 0x10000 failed");
        return 1;
    }

    thread_make_tag("test", 0, 0x100000, buffer);
    if(strcmp(buffer, "tes00000") != 0)
    {
        yatest_err("thread_make_tag 0x100000 failed");
        return 1;
    }

    thread_make_tag("test", 0, 0x1000000, buffer);
    if(strcmp(buffer, "t0") != 0)
    {
        yatest_err("thread_make_tag 0x1000000 failed");
        return 1;
    }

#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_start();
    thread_tag_log_tags();
    thread_tag_push_tags();
#endif

    dnscore_finalize();
    return 0;
}

static void thread_pool_function_test(void *args)
{
    (void)args;
    yatest_log("thread_pool_function_test: %p thread_pool_thread_index_get: %u", thread_self(), thread_pool_thread_index_get());
    for(int i = 0; i < 10; ++i)
    {
        thread_pool_counter_add_value(&counter2, 1);
        yatest_log("counter value: %i", thread_pool_counter_get_value(&counter2));
        yatest_sleep(1);
    }
    for(int i = 0; i < 10; ++i)
    {
        thread_pool_counter_add_value(&counter2, -1);
        yatest_log("counter value: %i", thread_pool_counter_get_value(&counter2));
        yatest_sleep(1);
    }
}

static void thread_pool_try_function_test(void *args)
{
    (void)args;
    yatest_log("thread_pool_try_function_test: %p thread_pool_thread_index_get: %u", thread_self(), thread_pool_thread_index_get());
}

static int thread_pool_test()
{
    int ret;
    dnscore_init();
    uint32_t tpl = thread_pool_get_max_thread_per_pool_limit();
    yatest_log("thread_pool_get_max_thread_per_pool_limit: %u", tpl);
    if(tpl > 256)
    {
        thread_pool_set_max_thread_per_pool_limit(256);
    }
    else
    {
        thread_pool_set_max_thread_per_pool_limit(tpl);
    }
    tpl = thread_pool_get_max_thread_per_pool_limit();

    struct thread_pool_s *tp = thread_pool_init(tpl, 0x10000);
    if(tp == NULL)
    {
        yatest_err("thread_pool_init failed");
        return 1;
    }
    thread_pool_counter_init(&counter, 0);
    thread_pool_counter_init(&counter2, 0);

    ret = thread_pool_enqueue_call(tp, thread_pool_function_test, NULL, &counter, "tp-test");
    if(ret < 0)
    {
        yatest_err("thread_pool_enqueue_call failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    for(;;)
    {
        ret = thread_pool_try_enqueue_call(tp, thread_pool_try_function_test, NULL, &counter, "try-tp-test");
        if(ret < 0)
        {
            yatest_err("thread_pool_try_enqueue_call failed with %08x = %s", ret, error_gettext(ret));
            usleep_ex(1000);
            continue;
        }
        break;
    }

    thread_pool_set_max_thread_per_pool_limit(tpl + 2);

    yatest_log("resize up");

    ret = thread_pool_resize(tp, tpl + 1);
    if(ret < 0)
    {
        yatest_err("thread_pool_resize + 1 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

#if FREEZES
    yatest_sleep(5);
    yatest_log("resize down");

    ret = thread_pool_resize(tp, tpl - 1);
    if(ret < 0)
    {
        yatest_err("thread_pool_resize - 1 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
#endif

    yatest_log("thread_pool_wait_queue_empty");

    thread_pool_wait_queue_empty(tp);

    int current_size = thread_pool_queue_size(tp);
    if(current_size != 0)
    {
        yatest_err("thread_pool_wait_queue_empty failed");
        return 1;
    }

    yatest_log("counter2 value: %i (==5)", thread_pool_counter_get_value(&counter2));

    thread_pool_counter_wait_equal(&counter2, 5);

    yatest_log("counter2 value: %i (==10 + to)", thread_pool_counter_get_value(&counter2));

    thread_pool_counter_wait_equal_with_timeout(&counter2, 10, 2000000);

    yatest_log("counter2 value: %i (<=5)", thread_pool_counter_get_value(&counter2));

    thread_pool_counter_wait_below_or_equal(&counter2, 5);

    yatest_log("finishing");

    thread_pool_counter_finalise(&counter);

    ret = thread_pool_stop_all();
    if(ret < 0)
    {
        yatest_err("thread_pool_stop_all failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    ret = thread_pool_start_all();
    if(ret < 0)
    {
        yatest_err("thread_pool_start_all failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    ret = thread_pool_stop(tp);
    if(ret < 0)
    {
        yatest_err("thread_pool_stop failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    thread_pool_start_all();

    ret = thread_pool_destroy(tp);
    if(ret < 0)
    {
        yatest_err("thread_pool_destroy failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }

    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(thread_test)
YATEST(tag_test)
YATEST(thread_pool_test)
YATEST_TABLE_END

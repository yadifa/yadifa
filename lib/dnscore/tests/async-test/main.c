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

#include "yatest.h"
#include "dnscore/shared_heap.h"

#include <dnscore/dnscore.h>
#include <dnscore/async.h>
#include <dnscore/thread.h>

#define QUEUE_SIZE       64
#define AW_COUNT         100
#define FAIL_TIMEOUT_US  10000000LL // 10s
#define SHARED_HEAP_SIZE 65536

static async_queue_t queue;
static thread_t      processing_thread;
static int64_t       thread_delayed_start_us = 0;
static bool          thread_release_message = true;
static bool          async_wait_is_shared = false;
static bool          async_wait_progress_overflow = false;
static async_wait_t *thread_sync = NULL;
static uint8_t       shared_heap_id = 0;

static void         *dequeue_thread_function(void *args)
{
    (void)args;
    int64_t start_time;
    yatest_time_now(&start_time);

    yatest_time_sleep(thread_delayed_start_us);

    for(;;)
    {
        int64_t now;
        yatest_time_now(&now);
        if(now - start_time > FAIL_TIMEOUT_US)
        {
            yatest_err("timeout");
            kill(getpid(), SIGKILL);
            exit(1);
        }
        if(async_queue_empty(&queue))
        {
            usleep(1000);
            continue;
        }
        int queue_size = async_queue_size(&queue);
        yatest_log("async_queue_size = %i", queue_size);
        if(queue_size <= 0)
        {
            yatest_err("async_queue_size unexpectedly returned %i <= 0 ", queue_size);
            exit(1);
        }

        yatest_log("async_message_next");
        async_message_t *am = async_message_next(&queue);
        yatest_log("async_wait_progress %p %p", am->handler, am->handler_args);
        am->handler(am);
        if(thread_release_message)
        {
            yatest_log("async_message_release");
            async_message_release(am);
        }
        yatest_log("done");
        break;
    }

    return NULL;
}

static void *dequeue_try_thread_function(void *args)
{
    (void)args;
    int64_t start_time;
    yatest_time_now(&start_time);

    yatest_time_sleep(thread_delayed_start_us);

    for(;;)
    {
        int64_t now;
        yatest_time_now(&now);
        if(now - start_time > FAIL_TIMEOUT_US)
        {
            yatest_err("timeout");
            kill(getpid(), SIGKILL);
            exit(1);
        }
        if(async_queue_empty(&queue))
        {
            usleep(1000);
            continue;
        }
        yatest_log("async_message_try_next");
        async_message_t *am = async_message_try_next(&queue);
        yatest_log("async_wait_progress");
        am->handler(am);
        yatest_log("async_message_release");
        async_message_release(am);
        yatest_log("done");
        break;
    }

    return NULL;
}

static void *waiting_thread_function(void *args)
{
    (void)args;
    int64_t start_time;
    yatest_time_now(&start_time);

    yatest_time_sleep(thread_delayed_start_us);

    for(;;)
    {
        int64_t now;
        yatest_time_now(&now);
        if(now - start_time > FAIL_TIMEOUT_US)
        {
            yatest_err("timeout");
            kill(getpid(), SIGKILL);
            exit(1);
        }

        int32_t counter = async_wait_get_counter(thread_sync);
        int32_t error = async_wait_get_error(thread_sync);
        if(error != SUCCESS)
        {
            yatest_err("expected a SUCCESS error code");
            exit(1);
        }
        yatest_log("async_wait_set_first_error (counter=%i, error=%i)", counter, error);
        async_wait_set_first_error(thread_sync, -1);
        error = async_wait_get_error(thread_sync);
        if(error != -1)
        {
            yatest_err("expected a -1 error code");
            exit(1);
        }
        yatest_log("async_wait_progress (counter=%i, error=%i)", counter, error);
        if(!async_wait_progress_overflow)
        {
            for(int i = 0; i < counter; ++i)
            {
                async_wait_progress(thread_sync, 1);
            }
        }
        else
        {
            async_wait_progress(thread_sync, counter * 2);
        }
        yatest_log("done");
        break;
    }

    return NULL;
}

static void init()
{
    yatest_log("init");
    dnscore_init();
    async_message_pool_init();
    async_queue_init(&queue, QUEUE_SIZE, 1, ONE_SECOND_US, "test-queue");
}

static void init_queue_thread()
{
    int ret;
    ret = thread_create(&processing_thread, dequeue_thread_function, NULL);
    if(FAIL(ret))
    {
        yatest_err("thread_create failed with %s", error_gettext(ret));
        exit(1);
    }
}

static void init_queue_try_thread()
{
    int ret;
    ret = thread_create(&processing_thread, dequeue_try_thread_function, NULL);
    if(FAIL(ret))
    {
        yatest_err("thread_create failed with %s", error_gettext(ret));
        exit(1);
    }
}

static void init_wait_thread()
{
    int ret;
    if(!async_wait_is_shared)
    {
        thread_sync = async_wait_new_instance(AW_COUNT);
    }
    else
    {
        if(FAIL(ret = shared_heap_init()))
        {
            yatest_err("shared_heap_init() failed: %s", error_gettext(ret));
            exit(1);
        }
        if(FAIL(ret = shared_heap_create(SHARED_HEAP_SIZE)))
        {
            yatest_err("shared_heap_create() failed: %s", error_gettext(ret));
            exit(1);
        }
        shared_heap_id = (uint8_t)ret;
        thread_sync = async_wait_new_instance_shared(shared_heap_id, AW_COUNT);
    }
    ret = thread_create(&processing_thread, waiting_thread_function, NULL);
    if(FAIL(ret))
    {
        yatest_err("thread_create failed with %s", error_gettext(ret));
        exit(1);
    }
}

static void finalise()
{
    yatest_log("thread_join");
    thread_join(processing_thread, NULL);
    yatest_log("async_queue_finalize");
    async_queue_finalize(&queue);
    yatest_log("async_message_pool_finalize");
    async_message_pool_finalize();
    if(thread_sync != NULL)
    {
        if(!async_wait_is_shared)
        {
            yatest_log("async_wait_destroy");
            async_wait_finalise(thread_sync);
        }
        else
        {
            yatest_log("async_wait_destroy_shared");
            async_wait_delete_shared(thread_sync);

            shared_heap_destroy(shared_heap_id);
            shared_heap_finalize();
        }
    }
    dnscore_finalize();
}

static int success_test()
{
    init();
    init_wait_thread();
    yatest_log("async_message_call");
    async_message_t *msg = async_message_new_instance();
    async_message_call(&queue, msg);
    yatest_log("async_wait");
    async_wait(thread_sync);
    finalise();
    return 0;
}

static int success_progress_overflow_test()
{
    async_wait_progress_overflow = true;
    init();
    init_wait_thread();
    yatest_log("async_message_call");
    async_message_t *msg = async_message_new_instance();
    async_message_call(&queue, msg);
    yatest_log("async_wait");
    async_wait(thread_sync);
    finalise();
    return 0;
}

static int success_shared_test()
{
    async_wait_is_shared = true;
    init();
    init_wait_thread();
    yatest_log("async_message_call");
    async_message_t *msg = async_message_new_instance();
    async_message_call(&queue, msg);
    yatest_log("async_wait");
    async_wait(thread_sync);
    finalise();
    return 0;
}

static int timeout_test()
{
    init();
    init_wait_thread();
    thread_delayed_start_us = 1000000LL;
    yatest_log("async_wait_new_instance");
    for(;;)
    {
        yatest_log("async_wait_timeout");
        if(async_wait_timeout(thread_sync, 100000LL))
        {
            break;
        }
    }
    finalise();
    return 0;
}

static int timeout_absolute_test()
{
    init();
    init_wait_thread();
    thread_delayed_start_us = 1000000LL;
    yatest_log("async_message_call");
    async_message_t *msg = async_message_new_instance();
    async_message_call(&queue, msg);
    for(;;)
    {
        yatest_log("async_wait_timeout");
        int64_t absolute_end;
        yatest_time_now(&absolute_end);
        absolute_end += 100000LL;
        if(async_wait_timeout(thread_sync, absolute_end))
        {
            break;
        }
    }
    finalise();
    return 0;
}

static void message_test_callback(struct async_message_s *am)
{
    (void)am;
    yatest_log("message_test_callback");
}

static int message_test()
{
    init();
    init_queue_thread();
    async_message_t *am = async_message_new_instance();
    am->handler = message_test_callback;
    am->handler_args = NULL;
    yatest_log("async_message_call");
    async_message_call(&queue, am);
    yatest_log("finalise");
    finalise();
    return 0;
}

static int message_try_test()
{
    init();
    init_queue_try_thread();
    async_message_t *am = async_message_new_instance();
    am->handler = message_test_callback;
    am->handler_args = NULL;
    yatest_log("async_message_call");
    async_message_call(&queue, am);
    yatest_log("finalise");
    finalise();
    return 0;
}

static int message_call_and_wait_test()
{
    init();
    init_queue_thread();
    async_message_t *am = async_message_new_instance();
    am->handler = message_test_callback;
    am->handler_args = NULL;
    yatest_log("async_message_call_and_wait %p %p", am->handler, am->handler_args);
    async_message_call_and_wait(&queue, am);
    yatest_log("finalise");
    finalise();
    return 0;
}

static int message_call_and_forget_test()
{
    init();
    init_queue_thread();
    async_message_t *am = async_message_new_instance();
    yatest_log("async_message_call_and_forget");
    async_message_call_and_forget(&queue, am);
    yatest_log("finalise");
    finalise();
    return 0;
}

static int message_call_and_release_test()
{
    thread_release_message = false;
    init();
    init_queue_thread();
    async_message_t *am = async_message_new_instance();
    yatest_log("async_message_call_and_forget");
    async_message_call_and_release(&queue, am);
    yatest_log("finalise");
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(success_test)
YATEST(success_progress_overflow_test)
YATEST(success_shared_test)
YATEST(timeout_test)
YATEST(timeout_absolute_test)
YATEST(message_test)
YATEST(message_try_test)
YATEST(message_call_and_wait_test)
YATEST(message_call_and_forget_test)
YATEST(message_call_and_release_test)
YATEST_TABLE_END

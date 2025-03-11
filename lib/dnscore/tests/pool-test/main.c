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
#include <dnscore/logger_handle.h>
#include <dnscore/dnscore.h>
#include <dnscore/pool.h>

static pool_t pool;

static int    test_pool_allocated = 0;

static void  *test_pool_allocate_callback(void *args)
{
    (void)args;
    ++test_pool_allocated;
    return malloc(16);
}

static void test_pool_free_callback(void *ptr, void *args)
{
    (void)args;
    --test_pool_allocated;
    free(ptr);
}

#define TEST_POOL_SIZE 16

static void *allocated[TEST_POOL_SIZE];

static void *pool_test_thread(void *arg)
{
    (void)arg;
    yatest_log("thread starting");
    yatest_log("sleep");
    yatest_sleep(2);
    yatest_log("pool_release 0");
    pool_release(&pool, allocated[0]);
    yatest_log("sleep");
    yatest_sleep(2);
    yatest_log("pool_release 1");
    pool_release(&pool, allocated[1]);
    yatest_log("thread ending");
    return NULL;
}

static int pool_test()
{
    dnscore_init();
    pool_init(&pool, test_pool_allocate_callback, test_pool_free_callback, NULL, "pool");
    int n = TEST_POOL_SIZE;
    pool_set_size(&pool, n);
    for(int i = 0; i < n; ++i)
    {
        allocated[i] = pool_alloc(&pool);
    }

    yatest_log("test_pool_allocated=%i (after %i pool_alloc)", pool_get_allocated(&pool), n);

    void *should_be_null = pool_alloc_wait_timeout(&pool, ONE_SECOND_US);
    if(should_be_null != NULL)
    {
        yatest_err("expected pool_alloc_wait_timeout to return NULL");
        return 1;
    }

    yatest_log("test_pool_allocated=%i (after pool_alloc_wait_timeout)", pool_get_allocated(&pool));

    yatest_log("starting thread");
    pthread_t tid;
    pthread_create(&tid, NULL, pool_test_thread, NULL);
    yatest_log("pool_wait");
    yatest_log("test_pool_allocated=%i (before pool_wait)", pool_get_allocated(&pool));
    pool_wait(&pool);
    yatest_log("test_pool_allocated=%i (after pool_wait)", pool_get_allocated(&pool));
    yatest_log("pool_alloc");
    void *should_not_be_null = pool_alloc(&pool);
    if(should_not_be_null == NULL)
    {
        yatest_err("expected pool_alloc to return a pointer");
        return 1;
    }
    yatest_log("test_pool_allocated=%i (after pool_alloc)", pool_get_allocated(&pool));
    yatest_log("pool_alloc_wait");
    void *should_not_be_null_either = pool_alloc_wait(&pool);
    if(should_not_be_null_either == NULL)
    {
        yatest_err("expected pool_alloc_wait to return a pointer");
        return 1;
    }
    yatest_log("test_pool_allocated=%i (after pool_alloc_wait)", pool_get_allocated(&pool));

    pool_release(&pool, should_not_be_null);
    pool_release(&pool, should_not_be_null_either);

    for(int i = 2; i < TEST_POOL_SIZE; ++i)
    {
        yatest_log("pool_release %i", i);
        pool_release(&pool, allocated[i]);
        yatest_log("test_pool_allocated=%i (after release #%i)", pool_get_allocated(&pool), i);
    }

    yatest_log("test_pool_allocated=%i (before join)", pool_get_allocated(&pool));

    pool_timedwait(&pool, ONE_SECOND_US);
    should_not_be_null = pool_alloc_wait_timeout(&pool, ONE_SECOND_US);
    if(should_not_be_null == NULL)
    {
        yatest_err("expected pool_alloc_wait_timeout to return a pointer");
        return 1;
    }
    pool_release(&pool, should_not_be_null);

    yatest_log("thread join");

    pthread_join(tid, NULL);

    // pool_log_all_stats_ex(g_system_logger, MSG_INFO);
    pool_log_all_stats();

    yatest_log("pool_finalize");
    pool_finalize(&pool);

    pool_log_stats_ex(NULL, NULL, MSG_INFO);

    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(pool_test)
YATEST_TABLE_END

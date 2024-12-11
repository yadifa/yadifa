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
#include "dnscore/process.h"
#include "dnscore/mutex.h"
#include <dnscore/dnscore.h>
#include <dnscore/shared_heap.h>

#define HEAP_COUNT       3
#define SHARED_HEAP_SIZE 0x200000

struct mutex_cond_s
{
    mutex_t              mtx;
    cond_t               cond;
    callback_function_t *callback;
    void                *data;
    bool                 ready;
};

static int                  heaps[HEAP_COUNT] = {-1};
static pid_t                pid = 0;
static struct mutex_cond_s *mtx_cond;
static bool                 running = true;

static void                 init(callback_function_t *child_function)
{
    int ret;
    dnscore_init();
    ret = shared_heap_init();
    if(ret < 0)
    {
        yatest_err("shared_heap_init failed with %08x = %s", ret, error_gettext(ret));
        exit(1);
    }
    for(int i = 0; i < HEAP_COUNT; ++i)
    {
        ret = shared_heap_create(SHARED_HEAP_SIZE);
        if(ret < 0)
        {
            yatest_err("shared_heap_create failed with %08x = %s", ret, error_gettext(ret));
            exit(1);
        }
        heaps[i] = ret;
    }

    mtx_cond = shared_heap_alloc(heaps[HEAP_COUNT - 1], sizeof(*mtx_cond));
    if(mtx_cond == NULL)
    {
        yatest_err("failed to allocate shared mutex");
        exit(1);
    }
    ret = mutex_init_process_shared(&mtx_cond->mtx);
    if(ret < 0)
    {
        yatest_err("mutex_init_process_shared failed with %08x = %s", ret, error_gettext(ret));
        exit(1);
    }
    ret = cond_init_process_shared(&mtx_cond->cond);
    if(ret < 0)
    {
        yatest_err("cond_init_process_shared failed with %08x = %s", ret, error_gettext(ret));
        exit(1);
    }
    mtx_cond->callback = NULL;
    mtx_cond->data = NULL;
    mtx_cond->ready = false;

    pid = fork_ex();
    if(pid < 0)
    {
        yatest_err("fork failed");
        exit(1);
    }
    if(pid == 0)
    {
        yatest_log("child pid = %i", getpid());
        child_function(NULL);
        exit(0);
    }
}

static void finalise()
{
    if(pid == 0)
    {
        yatest_err("finalise called from the child");
        exit(2);
    }
    yatest_log("killing child");
    kill(pid, SIGINT);
    yatest_log("waiting for child");
    waitpid_ex(pid, NULL, 0);
    yatest_log("destroying mtx_cond");
    cond_finalize(&mtx_cond->cond);
    mutex_finalize(&mtx_cond->mtx);
    shared_heap_free(mtx_cond);
    yatest_log("destroying heaps");
    for(int i = HEAP_COUNT - 1; i >= 0; --i)
    {
        shared_heap_check(heaps[i]);

        if(heaps[i] > 0)
        {
            shared_heap_destroy((uint8_t)heaps[i]);
        }
    }
    yatest_log("finalising heaps");
    shared_heap_finalize();
    yatest_log("finalising");
    dnscore_finalize();
}

static void wait_forever_child()
{
    for(;;)
    {
        yatest_log("waiting ...");
        yatest_sleep(1);
    }
}

static int init_finalise_test()
{
    init(wait_forever_child);
    for(int i = 0; i < HEAP_COUNT; ++i)
    {
        yatest_log("heap[%i] id = %i, context @ %p", i, heaps[i], shared_heap_context_from_id(heaps[i]));
    }
    yatest_sleep(1);
    finalise();
    return 0;
}

static void rpc_child()
{
    signal(SIGINT, SIG_IGN);
    while(running)
    {
        mutex_lock(&mtx_cond->mtx);
        while(!mtx_cond->ready)
        {
            cond_wait_auto_time_out(&mtx_cond->cond, &mtx_cond->mtx);
        }
        mtx_cond->callback(mtx_cond->data);
        mtx_cond->ready = false;
        cond_notify(&mtx_cond->cond);
        mutex_unlock(&mtx_cond->mtx);
    }
}

static void shared_heap_free_callback(void *data)
{
    yatest_log("rpc free");
    shared_heap_free(data);
}

static void running_false_callback(void *data)
{
    (void)data;
    yatest_log("rpc running = false");
    running = false;
}

static int alloc_free_test()
{
    const int block_size = 64;
    const int block_count = 10;
    char    **texts = malloc(sizeof(char *) * block_count);
    init(rpc_child);
    for(int i = 0; i < block_count; ++i)
    {
        char *text = shared_heap_alloc(heaps[0], block_size);
        if(text == NULL)
        {
            yatest_err("failed to allocate memory");
            finalise();
            exit(1);
        }
        shared_heap_check_ptr(heaps[0], text); // debug function, does nothing

        snprintf(text, block_size, "item-%i", i);
        texts[i] = text;
    }
    for(int i = 0; i < block_count; ++i)
    {
        yatest_log("calling rpc for item %i", i);
        mutex_lock(&mtx_cond->mtx);
        mtx_cond->callback = shared_heap_free_callback;
        mtx_cond->data = texts[i];
        mtx_cond->ready = true;
        cond_notify(&mtx_cond->cond);
        int64_t t;
        yatest_timer_start(&t);
        while(mtx_cond->ready)
        {
            cond_wait_auto_time_out(&mtx_cond->cond, &mtx_cond->mtx);
        }
        yatest_timer_stop(&t);
        mutex_unlock(&mtx_cond->mtx);
        yatest_log("caller waited for %f seconds", yatest_timer_seconds(&t));
    }
    mutex_lock(&mtx_cond->mtx);
    mtx_cond->callback = running_false_callback;
    mtx_cond->data = NULL;
    mtx_cond->ready = true;
    cond_notify(&mtx_cond->cond);
    mutex_unlock(&mtx_cond->mtx);

    finalise();
    return 0;
}

static int try_alloc_free_test()
{
    const int block_size = 64;
    const int block_count = 10;
    char    **texts = malloc(sizeof(char *) * block_count);
    init(rpc_child);
    for(int i = 0; i < block_count; ++i)
    {
        char *text = shared_heap_try_alloc(heaps[0], block_size);
        if(text == NULL)
        {
            yatest_err("failed to allocate memory");
            finalise();
            exit(1);
        }
        snprintf(text, block_size, "item-%i", i);
        texts[i] = text;
    }
    for(int i = 0; i < block_count; ++i)
    {
        yatest_log("calling rpc for item %i", i);
        mutex_lock(&mtx_cond->mtx);
        mtx_cond->callback = shared_heap_free_callback;
        mtx_cond->data = texts[i];
        mtx_cond->ready = true;
        cond_notify(&mtx_cond->cond);
        int64_t t;
        yatest_timer_start(&t);
        while(mtx_cond->ready)
        {
            cond_wait_auto_time_out(&mtx_cond->cond, &mtx_cond->mtx);
        }
        yatest_timer_stop(&t);
        mutex_unlock(&mtx_cond->mtx);
        yatest_log("caller waited for %f seconds", yatest_timer_seconds(&t));
    }
    mutex_lock(&mtx_cond->mtx);
    mtx_cond->callback = running_false_callback;
    mtx_cond->data = NULL;
    mtx_cond->ready = true;
    cond_notify(&mtx_cond->cond);
    mutex_unlock(&mtx_cond->mtx);

    finalise();
    return 0;
}

static int realloc_free_test()
{
    const int block_size = 64;
    const int block_count = 10;
    char    **texts = malloc(sizeof(char *) * block_count);
    init(rpc_child);
    for(int i = 0; i < block_count; ++i)
    {
        char *text = shared_heap_alloc(heaps[0], block_size / 2);
        if(text == NULL)
        {
            yatest_err("failed to allocate memory");
            finalise();
            exit(1);
        }
        text = shared_heap_realloc(heaps[0], text, block_size * 8);
        if(text == NULL)
        {
            yatest_err("failed to re-allocate memory");
            finalise();
            exit(1);
        }
        snprintf(text, block_size, "item-%i", i);
        texts[i] = text;
    }
    for(int i = 0; i < block_count; ++i)
    {
        yatest_log("calling rpc for item %i", i);
        mutex_lock(&mtx_cond->mtx);
        mtx_cond->callback = shared_heap_free_callback;
        mtx_cond->data = texts[i];
        mtx_cond->ready = true;
        cond_notify(&mtx_cond->cond);
        int64_t t;
        yatest_timer_start(&t);
        while(mtx_cond->ready)
        {
            cond_wait_auto_time_out(&mtx_cond->cond, &mtx_cond->mtx);
        }
        yatest_timer_stop(&t);
        mutex_unlock(&mtx_cond->mtx);
        yatest_log("caller waited for %f seconds", yatest_timer_seconds(&t));
    }
    mutex_lock(&mtx_cond->mtx);
    mtx_cond->callback = running_false_callback;
    mtx_cond->data = NULL;
    mtx_cond->ready = true;
    cond_notify(&mtx_cond->cond);
    mutex_unlock(&mtx_cond->mtx);

    finalise();
    return 0;
}

static int wait_alloc_free_test()
{
    const int block_size = 64;
    const int block_count = 10;
    char    **texts = malloc(sizeof(char *) * block_count);
    init(rpc_child);
    for(int i = 0; i < block_count; ++i)
    {
        char *text = shared_heap_wait_alloc(heaps[0], block_size);
        if(text == NULL)
        {
            yatest_err("failed to allocate memory");
            finalise();
            exit(1);
        }
        snprintf(text, block_size, "item-%i", i);
        texts[i] = text;
    }

    size_t total;
    size_t count;

    shared_heap_count_allocated(heaps[0], &total, &count);

    yatest_log("shared_heap_count_allocated(heap[0]) total=%llu count=%llu", total, count);

    shared_heap_print_map(heaps[0], &total, &count); // debug function, does nothing

    for(int i = 0; i < block_count; ++i)
    {
        yatest_log("calling rpc for item %i", i);
        mutex_lock(&mtx_cond->mtx);
        mtx_cond->callback = shared_heap_free_callback;
        mtx_cond->data = texts[i];
        mtx_cond->ready = true;
        cond_notify(&mtx_cond->cond);
        int64_t t;
        yatest_timer_start(&t);
        while(mtx_cond->ready)
        {
            cond_wait_auto_time_out(&mtx_cond->cond, &mtx_cond->mtx);
        }
        yatest_timer_stop(&t);
        mutex_unlock(&mtx_cond->mtx);
        yatest_log("caller waited for %f seconds", yatest_timer_seconds(&t));
    }
    mutex_lock(&mtx_cond->mtx);
    mtx_cond->callback = running_false_callback;
    mtx_cond->data = NULL;
    mtx_cond->ready = true;
    cond_notify(&mtx_cond->cond);
    mutex_unlock(&mtx_cond->mtx);

    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(init_finalise_test)
YATEST(alloc_free_test)
YATEST(try_alloc_free_test)
YATEST(realloc_free_test)
YATEST(wait_alloc_free_test)
YATEST_TABLE_END

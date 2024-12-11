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
#include <dnscore/dnscore.h>
#include <dnscore/threaded_queue_slg.h>
#include <dnscore/thread.h>

#define N 0x100000
#define T 8
static mutex_t              mtx;
static uint8_t             *all_values;
static thread_t             threads[T];

static threaded_queue_slg_t collection;

static void                *writer(void *argp)
{
    uint32_t *arg = argp;
    uint32_t  base = *arg;
    yatest_log("writer #%u start", base);
    for(uint32_t i = base; i < N; i += T / 2)
    {
        uint32_t *item = yatest_malloc(sizeof(uint32_t));
        *item = i;
        threaded_queue_slg_enqueue(&collection, item);
    }
    yatest_log("writer #%u wait", base);
    threaded_queue_slg_wait_empty(&collection);
    yatest_log("writer #%u stop", base);
    return NULL;
}

static void *reader(void *argp)
{
    uint32_t *arg = argp;
    uint32_t  base = *arg;
    yatest_log("reader #%u start", base);
    for(uint32_t i = 0; i < N; i += T / 2)
    {
        uint32_t *item = threaded_queue_slg_dequeue(&collection);
        uint32_t  index = *item;
        if(index < N)
        {
            mutex_lock(&mtx);
            all_values[index]++;
            mutex_unlock(&mtx);
        }
        else
        {
            yatest_err("Item with wrong value found: %u not in [0;%u]", index, N);
            exit(1);
        }
    }
    yatest_log("reader #%u stop", base);
    return NULL;
}

static void *try_writer(void *argp)
{
    uint32_t *arg = argp;
    uint32_t  base = *arg;
    yatest_log("try_writer #%u start", base);
    for(uint32_t i = base; i < N; i += T / 2)
    {
        uint32_t *item = yatest_malloc(sizeof(uint32_t));
        *item = i;
        while(!threaded_queue_slg_try_enqueue(&collection, item))
        {
            usleep(1000);
        }
    }
    yatest_log("try_writer #%u wait", base);
    threaded_queue_slg_wait_empty(&collection);
    yatest_log("try_writer #%u stop", base);
    return NULL;
}

static void *try_reader(void *argp)
{
    uint32_t *arg = argp;
    uint32_t  base = *arg;
    yatest_log("try_reader #%u start", base);
    for(uint32_t i = 0; i < N; i += T / 2)
    {
        uint32_t *item;

        do
        {
            item = threaded_queue_slg_try_dequeue(&collection);
            if(item == NULL)
            {
                usleep(1000);
            }
        } while(item == NULL);

        uint32_t index = *item;
        if(index < N)
        {
            mutex_lock(&mtx);
            all_values[index]++;
            mutex_unlock(&mtx);
        }
        else
        {
            yatest_err("Item with wrong value found: %u not in [0;%u]", index, N);
            exit(1);
        }
    }
    yatest_log("try_reader #%u stop", base);
    return NULL;
}

static void init(void *(*r)(void *), void *(*w)(void *))
{
    dnscore_init();
    mutex_init(&mtx);
    threaded_queue_slg_init(&collection, N / 2);

    threaded_queue_slg_set_maxsize(&collection, N / 2);

    if(threaded_queue_slg_room(&collection) != INT32_MAX)
    {
        yatest_err("threaded_queue_slg_room returned %u instead of %u", threaded_queue_slg_room(&collection), INT32_MAX);
        exit(1);
    }

    all_values = yatest_malloc(N);
    for(int i = 0; i < T / 2; ++i)
    {
        uint32_t *arg = yatest_malloc(sizeof(uint32_t));
        *arg = i;
        thread_create(&threads[i], w, arg);
    }
    for(int i = 0; i < T / 2; ++i)
    {
        uint32_t *arg = yatest_malloc(sizeof(uint32_t));
        *arg = i + T / 2;
        thread_create(&threads[i + T / 2], r, arg);
    }
    while((threaded_queue_slg_size(&collection) == 0) || (all_values[0] == 0))
    {
        yatest_log("waiting ...");
        usleep(1000);
    }
}

static void finalise()
{
    threaded_queue_slg_wait_empty(&collection);

    for(int i = 0; i < T; ++i)
    {
        thread_join(threads[i], NULL);
    }

    for(int i = 0; i < N; ++i)
    {
        if(all_values[i] != 1)
        {
            yatest_err("all_values[%u] = %u, expected to be 1", i, all_values[i]);
            exit(1);
        }
    }

    threaded_queue_slg_finalize(&collection);
    dnscore_finalize();
}

static int enqueue_dequeue_test()
{
    init(reader, writer);
    finalise();
    return 0;
}

static int try_enqueue_try_dequeue_test()
{
    init(try_reader, try_writer);
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(enqueue_dequeue_test)
YATEST(try_enqueue_try_dequeue_test)
YATEST_TABLE_END

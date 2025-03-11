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
#include "dnscore/process.h"
#include <dnscore/dnscore.h>
#include <dnscore/shared_circular_buffer.h>

#define ITEM_COUNT 1000000
#define LOG2_ITEM  20

static shared_circular_buffer_t *scb = NULL;
static pid_t                     pid = 0;

static void                      exit_child() {}

static void                      init(callback_function_t *child_function)
{
    dnscore_init();

    scb = shared_circular_buffer_create(LOG2_ITEM);

    if(scb == NULL)
    {
        yatest_err("shared_circular_buffer_create failed");
        exit(1);
    }

    yatest_log("buffer size: %llu, available: %llu", shared_circular_buffer_size(scb), shared_circular_buffer_avail(scb));

    yatest_log("additional_space: %p of size %llu", shared_circular_buffer_additional_space_ptr(scb), shared_circular_buffer_additional_space_size(scb));

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

    shared_circular_buffer_destroy(scb);

    yatest_log("finalising");
    dnscore_finalize();
}

static int init_finalise_test()
{
    init(exit_child);

    finalise();
    return 0;
}

static void dequeue_child()
{
    yatest_log("dequeue_child begin");
    for(int i = 0; i < ITEM_COUNT; ++i)
    {
        struct shared_circular_buffer_slot_s *slot = shared_circular_buffer_prepare_dequeue(scb);
        yatest_log("slot-%i: %s", i, slot->data);
        shared_circular_buffer_commit_dequeue(scb);
    }
    yatest_log("dequeue_child end");
}

static int queue_test()
{
    init(dequeue_child);

    for(int i = 0; i < ITEM_COUNT; ++i)
    {
        struct shared_circular_buffer_slot_s *slot = shared_circular_buffer_prepare_enqueue(scb);
        snprintf((char *)slot->data, sizeof(slot->data), "item-%i", i);
        shared_circular_buffer_commit_enqueue(scb, slot);
    }
    yatest_log("waiting for child");
    int status;
    waitpid_ex(pid, &status, 0);
    yatest_log("child status: %08x", status);
    if(status != 0)
    {
        yatest_err("expected child status to be 0");
        exit(1);
    }

    finalise();
    return 0;
}

static void timeout_dequeue_child()
{
    yatest_log("dequeue_child begin");
    for(int i = 0; i < ITEM_COUNT; ++i)
    {
        struct shared_circular_buffer_slot_s *slot = shared_circular_buffer_prepare_dequeue_with_timeout(scb, 1000000);
        if(slot == NULL)
        {
            --i;
            yatest_log("timeout dequeue ...");
        }
        yatest_log("slot-%i: %s at index", i, slot->data, shared_circular_buffer_get_index(scb, slot));
        shared_circular_buffer_commit_dequeue(scb);
    }
    yatest_log("dequeue_child end");
}
static int try_queue_test()
{
    init(timeout_dequeue_child);

    for(int i = 0; i < ITEM_COUNT; ++i)
    {
        struct shared_circular_buffer_slot_s *slot = shared_circular_buffer_try_prepare_enqueue(scb);
        if(slot == NULL)
        {
            yatest_log("retry enqueue ...");
            --i;
            continue;
        }
        snprintf((char *)slot->data, sizeof(slot->data), "item-%i", i);
        shared_circular_buffer_commit_enqueue(scb, slot);
    }

    while(!shared_circular_buffer_empty(scb))
    {
        yatest_log("waiting for the buffer to be empty");
        yatest_sleep(1);
    }

    yatest_log("waiting for child");
    int status;
    waitpid_ex(pid, &status, 0);
    yatest_log("child status: %08x", status);
    if(status != 0)
    {
        yatest_err("expected child status to be 0");
        exit(1);
    }

    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(init_finalise_test)
YATEST(queue_test)
YATEST(try_queue_test)
YATEST_TABLE_END

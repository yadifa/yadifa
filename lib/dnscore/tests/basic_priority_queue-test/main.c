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
#include <dnscore/dnscore.h>
#include <dnscore/basic_priority_queue.h>

static int priority_test()
{
    dnscore_init();

    uint64_t rnd;
    uint32_t queue_size = 1000;
    yatest_random_init(&rnd);

    bpqueue_t queue;

    bpqueue_init(&queue);

    for(uint32_t i = 0; i < queue_size; ++i)
    {
        uint32_t value = yatest_random_next32(&rnd);
        bpqueue_enqueue(&queue, (void *)(intptr_t)value, value);
    }

    if(bpqueue_size(&queue) != queue_size)
    {
        yatest_err("bpqueue_size returned %u instead of %u", bpqueue_size(&queue), queue_size);
        return 1;
    }

    uint32_t prev = (uint32_t)(intptr_t)bpqueue_dequeue(&queue);
    while(bpqueue_size(&queue) > 0)
    {
        uint32_t next = (uint32_t)(intptr_t)bpqueue_dequeue(&queue);
        if(prev > next)
        {
            yatest_err("out of priority order: %08x > %08x", prev, next);
            return 1;
        }
        prev = next;
    }

    void *item;
    if((item = bpqueue_dequeue(&queue)) != NULL)
    {
        yatest_err("bpqueue_dequeue expected to return NULL instead of %p", item);
        return 1;
    }

    bpqueue_clear(&queue);

    if(bpqueue_size(&queue) != 0)
    {
        yatest_err("bpqueue_size returned %u instead of %u", bpqueue_size(&queue), 0);
        return 1;
    }

    return 0;
}

static int clear_test()
{
    dnscore_init();

    uint64_t rnd;
    uint32_t queue_size = 1000;
    yatest_random_init(&rnd);

    bpqueue_t queue;

    bpqueue_init(&queue);

    for(uint32_t i = 0; i < queue_size; ++i)
    {
        uint32_t  value = yatest_random_next32(&rnd);
        uint32_t *valuep = (uint32_t *)malloc(sizeof(uint32_t));
        *valuep = value;
        bpqueue_enqueue(&queue, valuep, value);
    }

    if(bpqueue_size(&queue) != queue_size)
    {
        yatest_err("bpqueue_size returned %u instead of %u", bpqueue_size(&queue), queue_size);
        return 1;
    }

    bpqueue_clear(&queue);

    if(bpqueue_size(&queue) != 0)
    {
        yatest_err("bpqueue_size returned %u instead of %u", bpqueue_size(&queue), 0);
        return 1;
    }

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(priority_test)
YATEST(clear_test)
YATEST_TABLE_END

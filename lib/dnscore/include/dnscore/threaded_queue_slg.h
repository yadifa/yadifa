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

/** @defgroup threading Threading, pools, queues, ...
 *  @ingroup dnscore
 *  @brief 
 *
 *  This version of the ring buffer uses the condition-wait mechanism instead of the 3-mutex one.
 *  I'll have to bench both versions but the main incentive is to get rid of complains from helgrind
 * 
 * @{
 *
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnscore/thread.h>

#include <dnscore/mutex.h>
#include <dnscore/list-sl.h>

#define L1_DATA_LINE_SIZE 0x40

#ifdef	__cplusplus
extern "C" {
#endif

#define THREADED_QUEUE_PAGE_SIZE 4096
#define THREADED_QUEUE_SQL_SLOTS ((THREADED_QUEUE_PAGE_SIZE / __SIZEOF_POINTER__) - 2)

struct threaded_queue_slg_page_s
{
    intptr size;
    void *data[THREADED_QUEUE_SQL_SLOTS];
    struct threaded_queue_slg_page_s *next;
};

typedef struct threaded_queue_slg_page_s threaded_queue_slg_page_t;

struct threaded_queue_slg_s
{
    mutex_t mtx;
    cond_t read_cond;
    intptr read_index;
    threaded_queue_slg_page_t *page_pool;
#ifndef WIN32
    threaded_queue_slg_page_t *read_page __attribute__ ((aligned (L1_DATA_LINE_SIZE)));
    threaded_queue_slg_page_t *write_page __attribute__ ((aligned (L1_DATA_LINE_SIZE)));
#else
    threaded_queue_slg_page_t* read_page;
    threaded_queue_slg_page_t* write_page;
#endif
};

typedef struct threaded_queue_slg_s threaded_queue_slg_t;

#define THREADED_QUEUE_SLG_EMPTY {MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, NULL, NULL, NULL}

void threaded_queue_slg_init(threaded_queue_slg_t *q, int ignored_size);

void threaded_queue_slg_finalize(threaded_queue_slg_t *q);

void threaded_queue_slg_enqueue(threaded_queue_slg_t *q, void *data);

static inline bool threaded_queue_slg_try_enqueue(threaded_queue_slg_t *q, void *data)
{
    threaded_queue_slg_enqueue(q, data);
    return TRUE;
}

void* threaded_queue_slg_dequeue(threaded_queue_slg_t *q);

void threaded_queue_slg_wait_empty(threaded_queue_slg_t *q);

bool  threaded_queue_slg_try_enqueue(threaded_queue_slg_t *queue,void* constant_pointer);

void* threaded_queue_slg_try_dequeue(threaded_queue_slg_t *queue);
void* threaded_queue_slg_dequeue_with_timeout(threaded_queue_slg_t *queue, s64 timeout_us);

int threaded_queue_slg_size(threaded_queue_slg_t *q);
int threaded_queue_slg_room(threaded_queue_slg_t *q);

/*
 * The queue will block (write) if bigger than this.
 * Note that if the key is already bigger it will blocked (write) until
 * the content is emptied by the readers.
 */

ya_result threaded_queue_slg_set_maxsize(threaded_queue_slg_t *q, int max_size);

#ifdef	__cplusplus
}
#endif

/** @} */

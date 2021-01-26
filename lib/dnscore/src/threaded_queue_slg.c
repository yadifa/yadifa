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
 *  
 *
 * @{ *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore-config.h"
#include <stdlib.h>
#include <unistd.h>

#include <dnscore/logger.h>

#include "dnscore/threaded_queue_slg.h"

#define MODULE_MSG_HANDLE		g_system_logger

#define THREADED_QUEUE_TAG	    0x455545555154	/* TQUEUE */

void threaded_queue_slg_init(threaded_queue_slg_t *q, int ignored_size)
{
    (void)ignored_size;
    threaded_queue_slg_page_t *page = NULL;
    ZALLOC_OBJECT_OR_DIE(page, threaded_queue_slg_page_t, GENERIC_TAG);
    page->size = 0;
    page->next = NULL;

    mutex_init(&q->mtx);
    q->page_pool = NULL;
    q->read_page = page;
    cond_init(&q->read_cond);
    q->read_index = 0;
    q->write_page = page;
}

void threaded_queue_slg_finalize(threaded_queue_slg_t *q)
{
    mutex_lock(&q->mtx);

    int pool_released_count = 0;
    int read_released_count = 0;
    bool write_auto_cleared = (q->write_page == NULL);

    threaded_queue_slg_page_t *page = q->page_pool;

    while(page != NULL)
    {
        threaded_queue_slg_page_t *tmp = page;
        page = page->next;
        ZFREE_OBJECT(tmp);

        ++pool_released_count;
    }

    q->page_pool = NULL;

    page = q->read_page;

    while(page != NULL)
    {
        threaded_queue_slg_page_t *tmp = page;
        page = page->next;
        ZFREE_OBJECT(tmp);

        ++read_released_count;

        if(q->write_page == tmp)
        {
            q->write_page = NULL;

            write_auto_cleared = TRUE;
        }
    }

    q->read_page = NULL;
    q->read_index = 0;

    mutex_unlock(&q->mtx);

    log_debug("threaded_queue_slg_finalize: %i pooled, %i released, write %s", pool_released_count, read_released_count, ((write_auto_cleared)?"auto-cleared":"not cleared"));

    cond_finalize(&q->read_cond);
    mutex_destroy(&q->mtx);
}

int
threaded_queue_slg_room(threaded_queue_slg_t *q)
{
    (void)q;
    return MAX_S32;
}

ya_result
threaded_queue_slg_set_maxsize(threaded_queue_slg_t *q, int max_size)
{
    (void)q;
    (void)max_size;
    return SUCCESS;
}

void
threaded_queue_slg_enqueue(threaded_queue_slg_t *q, void *data)
{
    mutex_lock(&q->mtx);
    threaded_queue_slg_page_t *page = q->write_page;

    if(page->size < THREADED_QUEUE_SQL_SLOTS)
    {
        page->data[page->size++] = data;
    }
    else
    {
        threaded_queue_slg_page_t *next_page;


            if(q->page_pool != NULL)
            {
                next_page = q->page_pool;
                q->page_pool = next_page->next;
            }
            else
            {
                ZALLOC_OBJECT_OR_DIE(next_page, threaded_queue_slg_page_t, GENERIC_TAG);
            }

            next_page->data[0] = data;
            next_page->size = 1;
            next_page->next = NULL;
            page->next = next_page;
            q->write_page = next_page;

    }

    cond_notify(&q->read_cond);
    mutex_unlock(&q->mtx);
}

void* threaded_queue_slg_dequeue(threaded_queue_slg_t *q)
{
    void *data;

    mutex_lock(&q->mtx);
    for(;;)
    {
        volatile threaded_queue_slg_page_t *page = (volatile threaded_queue_slg_page_t*)q->read_page;

        intptr d = (volatile intptr)page->size - (volatile intptr)q->read_index;

        if(d > 0)
        {
            data = page->data[q->read_index++];

            if(d == 1)
            {
                cond_notify(&q->read_cond);
            }

            mutex_unlock(&q->mtx);
            return data;
        }
        else
        {
#if 1
            if(page->size == THREADED_QUEUE_SQL_SLOTS)
            {
                if(page->next == NULL)
                {
                    // buffer can be reset

                    page->size = 0;
                    q->read_index = 0;

                    // wait
                    cond_wait(&q->read_cond, &q->mtx);
                }
                else
                {
                    threaded_queue_slg_page_t *tmp = (threaded_queue_slg_page_t*)page;
                    page = page->next;
                    tmp->next = q->page_pool;
                    q->page_pool = tmp;
                    q->read_page = (threaded_queue_slg_page_t*)page;
                    q->read_index = 0;
                }
            }
            else
            {
                // buffer can be reset

                page->size = 0;
                q->read_index = 0;
                
                cond_wait(&q->read_cond, &q->mtx);
            }
#else
            cond_wait(&q->read_cond, &q->mtx);
#endif
        }
    }
}

void threaded_queue_slg_wait_empty(threaded_queue_slg_t *q)
{
    mutex_lock(&q->mtx);

    while(!((q->read_page->next == NULL) && ((q->read_page->size - q->read_index) == 0)))
    {
        cond_wait(&q->read_cond, &q->mtx);
    }

    cond_notify_one(&q->read_cond);
    mutex_unlock(&q->mtx);
}

int
threaded_queue_slg_size(threaded_queue_slg_t *q)
{
    intptr ret = q->read_page->size;

    mutex_lock(&q->mtx);
    threaded_queue_slg_page_t *page = q->read_page->next;
    while(page != NULL)
    {
        ret += page->size;
        page = page->next;
    }

    ret -= q->read_index;
    mutex_unlock(&q->mtx);

    return (int)ret;
}

/** @} */


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

#include "dnscore/process.h"
#include "dnscore/dnscore_config.h"
#include "dnscore/zalloc.h"
#include "dnscore/pool.h"
#include "dnscore/mutex.h"
#include "dnscore/format.h"
#include "dnscore/shared_heap.h"
#include "dnscore/format.h"
#include "dnscore/logger.h"
#include "dnscore/async.h"

#define ASYNC_WAIT_DUMP        0

#define ASYNC_NO_TIMEOUT       0

#define ASYNC_FAKE_SHARED_HEAP 0

#if __FreeBSD__
// To avoid some funky stuff with FreeBSD
#define ASYNC_WAIT_FINALIZE_DELAY_COUNT       64
#define ASYNC_WAIT_DESTROY_SHARED_DELAY_COUNT 64
#else
#define ASYNC_WAIT_FINALIZE_DELAY_COUNT       0
#define ASYNC_WAIT_DESTROY_SHARED_DELAY_COUNT 0
#endif

#define MODULE_MSG_HANDLE g_system_logger

#define ASYNCMSG_TAG      0x47534d434e595341
#define ASYNCWAIT_TAG     0x5457434e595341

static pool_t              async_message_pool;

static initialiser_state_t async_message_pool_init_state = INITIALISE_STATE_INIT;

/**
 * Pushes the message to the queue.
 * The queue is supposed to be read in another thread
 *
 * @param queue the queue
 * @param am the async message to queue
 */

void async_message_call(async_queue_t *queue, async_message_t *msg)
{
    msg->start_time = timeus();

#if ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_DLL
    threaded_dll_cw_enqueue(&queue->queue, msg);
#elif ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_RINGBUFFER
    threaded_ringbuffer_cw_enqueue(&queue->queue, msg);
#else
    threaded_queue_enqueue(&queue->queue, msg);
#endif
}

/**
 * Dequeues the next message from the queue with a timeout of 1 second.
 *
 * @param queue the queue
 * @return the next message or NULL if none was available after 1 second.
 */

async_message_t *async_message_next(async_queue_t *queue)
{
#if ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_DLL
    // async_message_s* async = (async_message_s*)threaded_dll_cw_try_dequeue(&queue->queue);
    async_message_t *async = (async_message_t *)threaded_dll_cw_dequeue_with_timeout(&queue->queue, /*queue->pace.max_us*/ 1000000);
#elif ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_RINGBUFFER
    async_message_s *async = (async_message_s *)threaded_ringbuffer_cw_try_dequeue(&queue->queue);
#else
    async_message_s *async = (async_message_s *)threaded_queue_try_dequeue(&queue->queue);
#endif

    if(async == NULL)
    {
        pace_wait(&queue->pace);
    }
    else
    {
        pace_work(&queue->pace);
    }

    return async;
}

/**
 * Tries to dequeue the next message from the queue
 *
 * @param queue the queue
 * @return the next message or NULL if none was available
 */

async_message_t *async_message_try_next(async_queue_t *queue)
{
#if ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_DLL
    async_message_t *async = (async_message_t *)threaded_dll_cw_try_dequeue(&queue->queue);
#elif ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_RINGBUFFER
    async_message_s *async = (async_message_s *)threaded_ringbuffer_cw_try_dequeue(&queue->queue);
#else
    async_message_s *async = (async_message_s *)threaded_queue_try_dequeue(&queue->queue);
#endif

    return async;
}

/**
 *
 * Initialises a synchronisation point
 * count is the number of releases to do before the async_wait call returns
 *
 * @param aw
 * @param count
 * @return
 */

void async_wait_init(async_wait_t *aw, int32_t count)
{
#if ASYNC_WAIT_DUMP
    formatln("[%5i][%p] async_wait_init(%p, %i)", getpid_ex(), thread_self(), aw, count);
    flushout();
#endif
#if ASYNC_USES_FUTEX
    mutex_futex_init(&aw->mutex_futex);
    cond_futex_init(&aw->cond_futex);
#else
    mutex_init(&aw->mutex);
    cond_init(&aw->cond_wait);
#endif
    aw->wait_count = count;
    aw->error_code = SUCCESS;
#if ASYNC_WAIT_TAG
    aw->tag = 0x50505050;
#endif
}

#if ASYNC_WAIT_FINALIZE_DELAY_COUNT > 0

static mutex_t       async_wait_finalize_delay_mtx = MUTEX_INITIALIZER;
static async_wait_t *async_wait_finalize_delay[ASYNC_WAIT_FINALIZE_DELAY_COUNT] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};
static int           async_wait_finalize_delay_index = 0;

static mutex_t       async_wait_destroy_delay_mtx = MUTEX_INITIALIZER;
static async_wait_t *async_wait_destroy_delay[ASYNC_WAIT_FINALIZE_DELAY_COUNT] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};
static int async_wait_destroy_delay_index = 0;

#endif

#if ASYNC_WAIT_DESTROY_SHARED_DELAY_COUNT > 0

static mutex_t       async_wait_destroy_shared_delay_mtx = MUTEX_INITIALIZER;
static async_wait_t *async_wait_destroy_shared_delay[ASYNC_WAIT_DESTROY_SHARED_DELAY_COUNT] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};
static int async_wait_destroy_shared_delay_index = 0;

#endif
/**
 *
 * Destroys the synchronisation point
 *
 * @param aw
 * @return
 */
#if ASYNC_WAIT_FINALIZE_DELAY_COUNT > 0
static void async_wait_finalize_now(async_wait_t *aw);

void        async_wait_finalize(async_wait_t *aw)
{
    mutex_lock(&async_wait_finalize_delay_mtx);
    if(async_wait_finalize_delay[async_wait_finalize_delay_index] != NULL)
    {
        async_wait_finalize_now(async_wait_finalize_delay[async_wait_finalize_delay_index]);
    }
    async_wait_finalize_delay[async_wait_finalize_delay_index] = aw;
    async_wait_finalize_delay_index = (async_wait_finalize_delay_index + 1) % ASYNC_WAIT_FINALIZE_DELAY_COUNT;
    mutex_unlock(&async_wait_finalize_delay_mtx);
}

/**
 *
 * Destroys the synchronisation point
 * Does NOT wait (async_wait is the name of the type)
 *
 * @param aw
 * @return
 */

static void async_wait_finalize_now(async_wait_t *aw)
#else

/**
 *
 * Destroys the synchronisation point
 * Does NOT wait (async_wait is the name of the type)
 *
 * @param aw
 * @return
 */

void async_wait_finalize(async_wait_t *aw)
#endif
{
#if ASYNC_WAIT_DUMP
    formatln("[%5i][%p] async_wait_finalize(%p)", getpid_ex(), thread_self(), aw);
    flushout();
#endif

#if ASYNC_USES_FUTEX
    mutex_futex_lock(&aw->mutex_futex);
#else
    mutex_lock(&aw->mutex);
#endif

    int32_t wait_count = aw->wait_count;

#if ASYNC_USES_FUTEX
    mutex_futex_unlock(&aw->mutex_futex);
#else
    mutex_unlock(&aw->mutex);
#endif

    if(wait_count > 0)
    {
        osformat(termerr, "async_wait_finalize: wait_count = %i > 0: finalisation before logical end of life", wait_count);
        flusherr();
    }

#if ASYNC_USES_FUTEX
    cond_futex_finalise(&aw->cond_futex);
    mutex_futex_finalise(&aw->mutex_futex);
#else
    cond_finalize(&aw->cond_wait);
    mutex_destroy(&aw->mutex);
#endif

#if DEBUG
    memset(aw, 0x5e, sizeof(async_wait_t));
#endif
#if ASYNC_WAIT_TAG
    aw->tag &= 0x10101010;
#endif
}

async_wait_t *async_wait_new_instance(int32_t count)
{
    async_wait_t *ret;
    ZALLOC_OBJECT_OR_DIE(ret, async_wait_t, ASYNCWAIT_TAG);
    async_wait_init(ret, count);
    return ret;
}

#if ASYNC_WAIT_FINALIZE_DELAY_COUNT > 0

static void async_wait_destroy_now(async_wait_t *aw);

/**
 * Uninitialises and frees a synchronisation point
 *
 * @param aw the synchronisation point
 */

void async_wait_finalise(async_wait_t *aw)
{
    mutex_lock(&async_wait_destroy_delay_mtx);
    if(async_wait_destroy_delay[async_wait_destroy_delay_index] != NULL)
    {
        async_wait_destroy_now(async_wait_destroy_delay[async_wait_destroy_delay_index]);
    }
    async_wait_destroy_delay[async_wait_destroy_delay_index] = aw;
    async_wait_destroy_delay_index = (async_wait_destroy_delay_index + 1) % ASYNC_WAIT_FINALIZE_DELAY_COUNT;
    mutex_unlock(&async_wait_destroy_delay_mtx);
}

static void async_wait_destroy_now(async_wait_t *aw)
{
    async_wait_finalize_now(aw);
    ZFREE_OBJECT(aw);
}
#else

/**
 * Uninitialises and frees a synchronisation point
 *
 * @param aw the synchronisation point
 */

void async_wait_finalise(async_wait_t *aw)
{
    async_wait_finalize(aw);
    ZFREE_OBJECT(aw);
}
#endif

/**
 * Creates a new synchronisation point instance, shared among processes.
 * (provided they have access to the same mmap-backed shared memory pool.
 *
 * @param the id of the shared memory pool
 * @param count the value of the counter, should be > 0
 * @return the synchronisation point
 *
 * example:
 *
 * ret = shared_heap_init();
 * ret = shared_heap_create(SHARED_HEAP_SIZE);
 * shared_heap_id = (uint8_t)ret;
 * thread_sync = async_wait_new_instance_shared(shared_heap_id, AW_COUNT);
 *
 */

async_wait_t *async_wait_new_instance_shared(uint8_t id, int32_t count)
{
#if !ASYNC_FAKE_SHARED_HEAP
    async_wait_t *aw = (async_wait_t *)shared_heap_wait_alloc(id, sizeof(async_wait_t));
#else
    async_wait_s *aw = (async_wait_t *)malloc(sizeof(async_wait_s));
#endif

#if ASYNC_WAIT_DUMP
    formatln("[%5i][%p] async_wait_new_instance_shared(%i,%i) -> %p", getpid_ex(), thread_self(), id, count, aw);
    flushout();
#endif

    assert(aw != NULL);

#if ASYNC_USES_FUTEX
    mutex_futex_init(&aw->mutex_futex);
    cond_futex_init(&aw->cond_futex);
#else

    int err;

    err = mutex_init_process_shared(&aw->mutex);

    if(err != 0)
    {
        logger_handle_msg(g_system_logger, MSG_ERR, "async_wait_new_instance_shared: init condition failed: %r", MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }

    err = cond_init_process_shared(&aw->cond_wait);

    if(err != 0)
    {
        logger_handle_msg(g_system_logger, MSG_ERR, "async_wait_new_instance_shared: init condition failed: %r", MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }
#endif
    aw->wait_count = count;
    aw->error_code = SUCCESS;

#if ASYNC_WAIT_TAG
    aw->tag = 0x53535353;
#endif
    return aw;
}

#if ASYNC_WAIT_DESTROY_SHARED_DELAY_COUNT > 0
static void async_wait_delete_shared_now(async_wait_t *aw);

/**
 * Uninitialises and frees a synchronisation point.
 *
 * @param aw the synchronisation point
 */

void async_wait_delete_shared(async_wait_t *aw)
{
    mutex_lock(&async_wait_destroy_shared_delay_mtx);
    if(async_wait_destroy_shared_delay[async_wait_destroy_shared_delay_index] != NULL)
    {
        async_wait_delete_shared_now(async_wait_destroy_shared_delay[async_wait_destroy_shared_delay_index]);
    }
    async_wait_destroy_shared_delay[async_wait_destroy_shared_delay_index] = aw;
    async_wait_destroy_shared_delay_index = (async_wait_destroy_shared_delay_index + 1) % ASYNC_WAIT_DESTROY_SHARED_DELAY_COUNT;
    mutex_unlock(&async_wait_destroy_shared_delay_mtx);
}

static void async_wait_delete_shared_now(async_wait_t *aw)
{
#else

/**
 * Uninitialises and frees a synchronisation point.
 *
 * @param aw the synchronisation point
 */

void async_wait_delete_shared(async_wait_t *aw)
{
#endif

#if ASYNC_WAIT_DUMP
    formatln("[%5i][%p] async_wait_delete_shared(%p)", getpid_ex(), thread_self(), aw);
    flushout();
#endif
#if ASYNC_WAIT_FINALIZE_DELAY_COUNT > 0
    async_wait_finalize_now(aw);
#else
    async_wait_finalize(aw);
#endif
#if !ASYNC_FAKE_SHARED_HEAP
    shared_heap_free(aw);
#else
    free(aw);
#endif
}

/**
 * Waits until the count has be reduced to 0 (or below if something bad is going on)
 *
 * @param aw
 */

void async_wait(async_wait_t *aw)
{
#if ASYNC_WAIT_DUMP
    formatln("[%5i][%p] async_wait(%p)", getpid_ex(), thread_self(), aw);
    flushout();
#endif
#if ASYNC_USES_FUTEX
    mutex_futex_lock(&aw->mutex_futex);
    while(aw->wait_count > 0)
    {
        cond_futex_wait(&aw->cond_futex, &aw->mutex_futex);
    }
    mutex_futex_unlock(&aw->mutex_futex);
#else
    int err = mutex_lock_unchecked(&aw->mutex);

    if(err == 0)
    {
        while(aw->wait_count > 0)
        {
#if !__FreeBSD__
            cond_wait(&aw->cond_wait, &aw->mutex);
#else
            cond_timedwait(&aw->cond_wait, &aw->mutex, ONE_SECOND_US);
#endif
        }
        mutex_unlock(&aw->mutex);
    }
    else
    {
        formatln("[%5i][%p] async_wait(%p) failed to lock mutex: %r", getpid_ex(), thread_self(), aw, MAKE_ERRNO_ERROR(err));
        flushout();
        abort();
    }
#endif
}

bool async_wait_timeout_absolute(async_wait_t *aw, int64_t epoch_usec)
{
#if ASYNC_USES_FUTEX
    int64_t relative_usec = epoch_usec - timeus();
    if(relative_usec < 0)
    {
        relative_usec = 0;
    }
    bool ret = async_wait_timeout(&aw->mutex_futex, relative_usec);
    return ret;
#else
#if !ASYNC_NO_TIMEOUT
    struct timespec ts;
    int             err = mutex_lock_unchecked(&aw->mutex);
    if(err == 0)
    {
        ts.tv_sec = epoch_usec / 1000000L;
        ts.tv_nsec = (epoch_usec % 1000000L) * 1000L;

        int32_t awc;
        while((awc = aw->wait_count) > 0)
        {
            int err;

            err = cond_timedwait_absolute_ts(&aw->cond_wait, &aw->mutex, &ts);

            if(err == ETIMEDOUT)
            {
#if ASYNC_WAIT_DUMP
                formatln("[%5i][%p] async_wait_timeout_absolute(%p,%llu) : TIMEOUT (awc=%i)", getpid_ex(), thread_self(), aw, epoch_usec, awc);
#endif
                break;
            }

            if(err != 0)
            {
                log_err("async_wait_timeout: %r", MAKE_ERRNO_ERROR(err));
            }
        }

        err = mutex_unlock_unchecked(&aw->mutex);

        if(err == 0)
        {
            return awc == 0;
        }
        else
        {
            formatln("[%5i][%p] async_wait_timeout_absolute(%p) failed to unlock mutex: %r", getpid_ex(), thread_self(), aw, MAKE_ERRNO_ERROR(err));
            flushout();
            abort();
        }
    }
    else
    {
        formatln("[%5i][%p] async_wait_timeout_absolute(%p) failed to lock mutex: %r", getpid_ex(), thread_self(), aw, MAKE_ERRNO_ERROR(err));
        flushout();
        abort();
    }
#else // ASYNC_NO_TIMEOUT

    // timeout disabled

    async_wait(aw);
    return true;
#endif
#endif
}

/**
 * Returns true if the wait is done, false if it timed-out.
 */

bool async_wait_timeout(async_wait_t *aw, int64_t relative_usec)
{
#if ASYNC_WAIT_DUMP
    formatln("[%5i][%p] async_wait_timeout(%p, %llu)", getpid_ex(), thread_self(), aw, usec);
    flushout();
#endif

#if ASYNC_USES_FUTEX
    int64_t   last = timeus();
    ya_result ret = mutex_futex_lock_timeout(&aw->mutex_futex, relative_usec);

    if(FAIL(ret))
    {
        return false;
    }

    while(aw->wait_count > 0)
    {
        int64_t now = timeus();
        int64_t dt = now - last;
        relative_usec -= dt;
        if(relative_usec <= 0)
        {
            mutex_futex_unlock(&aw->mutex_futex);
            return false;
        }
        ret = cond_futex_timedwait(&aw->cond_futex, &aw->mutex_futex, relative_usec);
        if(FAIL(ret))
        {
            mutex_futex_unlock(&aw->mutex_futex);
            return false;
        }
    }
    mutex_futex_unlock(&aw->mutex_futex);

    return true;
#else
    relative_usec += timeus();
    return async_wait_timeout_absolute(aw, relative_usec);
#endif
}

int32_t async_wait_get_counter(async_wait_t *aw)
{
    int32_t counter;

#if ASYNC_USES_FUTEX
    mutex_futex_lock(&aw->mutex_futex);
#else
    mutex_lock(&aw->mutex);
#endif

    counter = aw->wait_count;

#if ASYNC_USES_FUTEX
    mutex_futex_unlock(&aw->mutex_futex);
#else
    mutex_unlock(&aw->mutex);
#endif

    return counter;
}

/**
 *
 * Decreases the count of that amount
 *
 * @param aw
 * @param count
 * @return
 */

void async_wait_progress(async_wait_t *aw, int32_t count)
{
#if ASYNC_WAIT_DUMP
    formatln("[%5i][%p] async_wait_progress(%p, %i) (lock)", getpid_ex(), thread_self(), aw, count);
#endif

#if ASYNC_USES_FUTEX
    mutex_futex_lock(&aw->mutex_futex);
    if(aw->wait_count - count >= 0)
    {
        aw->wait_count -= count;
#if ASYNC_WAIT_DUMP
        formatln("[%5i][%p] async_wait_progress(%p, %i) (unlock)", getpid_ex(), thread_self(), aw, count);
#endif
    }
    else
    {
        log_err("async_wait_progress: count=%i, trying to add %i", aw->wait_count, count);
        aw->wait_count = 0;
    }
    cond_futex_notify(&aw->cond_futex);
    mutex_futex_unlock(&aw->mutex_futex);
#else
    int err = mutex_lock_unchecked(&aw->mutex);
    if(err == 0)
    {
        if(aw->wait_count - count >= 0)
        {
            aw->wait_count -= count;

            cond_notify(&aw->cond_wait);

#if ASYNC_WAIT_DUMP
            formatln("[%5i][%p] async_wait_progress(%p, %i) (unlock)", getpid_ex(), thread_self(), aw, count);
#endif
            err = mutex_unlock_unchecked(&aw->mutex);
#if ASYNC_WAIT_DUMP
            formatln("[%5i][%p] async_wait_progress(%p, %i) (done)", getpid_ex(), thread_self(), aw, count);
#endif
            if(err != 0)
            {
                formatln("[%5i][%p] async_wait_progress(%p) failed to unlock mutex: %r", getpid_ex(), thread_self(), aw, MAKE_ERRNO_ERROR(err));
                flushout();
                abort();
            }
        }
        else
        {
            log_err("async_wait_progress: count=%i, trying to add %i", aw->wait_count, count);

            aw->wait_count = 0;
            cond_notify(&aw->cond_wait);

            void *p = aw;
            err = mutex_unlock_unchecked(&aw->mutex);

#if ASYNC_WAIT_DUMP
            formatln("[%5i][%p] async_wait_progress(%p, %i) (done)", getpid_ex(), thread_self(), p, count);
#endif
            if(err != 0)
            {
                formatln("[%5i][%p] async_wait_progress(%p) failed to unlock mutex: %r (alt)", getpid_ex(), thread_self(), p, MAKE_ERRNO_ERROR(err));
                flushout();
                abort();
            }
        }
    }
    else
    {
        formatln("[%5i][%p] async_wait_progress(%p) failed to lock mutex: %r", getpid_ex(), thread_self(), aw, MAKE_ERRNO_ERROR(err));
        flushout();
        abort();
    }
#endif
}

/**
 * Sets the first error on the async_wait
 * After an error has been set, subsequent calls don't change the value anymore
 *
 * @param aw the async_wait
 * @param error the error code
 */

void async_wait_set_first_error(async_wait_t *aw, int32_t error)
{
#if ASYNC_USES_FUTEX
    mutex_futex_lock(&aw->mutex_futex);
#else
    mutex_lock(&aw->mutex);
#endif
    if(ISOK(aw->error_code))
    {
        aw->error_code = error;
    }
#if ASYNC_USES_FUTEX
    mutex_futex_unlock(&aw->mutex_futex);
#else
    mutex_unlock(&aw->mutex);
#endif
}

/**
 * Returns the error code in a synchronisation point
 *
 * @param aw the synchronisation point
 * @return the error code
 */

int32_t async_wait_get_error(async_wait_t *aw)
{
    int32_t err;

#if ASYNC_USES_FUTEX
    mutex_futex_lock(&aw->mutex_futex);
#else
    mutex_lock(&aw->mutex);
#endif

    err = aw->error_code;

#if ASYNC_USES_FUTEX
    mutex_futex_unlock(&aw->mutex_futex);
#else
    mutex_unlock(&aw->mutex);
#endif

    return err;
}

/**
 * Initialises a message queue
 *
 * @param q the queue to initialise
 * @param size the size of the queue
 * @param min_us the smallest pacing time in us
 * @param max_us the biggest pacing time in us
 * @param name the name of the queue (mostly for monitoring)
 */

void async_queue_init(async_queue_t *q, uint32_t size, uint64_t min_us, uint64_t max_us, const char *name)
{
#if ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_DLL
    threaded_dll_cw_init(&q->queue, size);
#elif ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_RINGBUFFER
    threaded_ringbuffer_cw_init(&q->queue, size);
#else
    threaded_queue_init(&q->queue, size);
#endif

    pace_init(&q->pace, min_us, max_us, name);
}

/**
 * Finalises a message queue
 *
 * @param q the message queue
 */

void async_queue_finalize(async_queue_t *q)
{
    int32_t n;
#if ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_DLL
    if((n = threaded_dll_cw_size(&q->queue)) > 0)
    {
        log_warn("async_dll_cw_finalize: queue still contains %i items", n);
    }
    threaded_dll_cw_finalize(&q->queue);
#elif ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_RINGBUFFER
    if((n = threaded_ringbuffer_cw_size(&q->queue)) > 0)
    {
        log_warn("async_ringbuffer_cw_finalize: queue still contains %i items", n);
    }
    threaded_ringbuffer_cw_finalize(&q->queue);
#else
    if((n = threaded_queue_size(&q->queue)) > 0)
    {
        log_warn("async_queue_finalize: queue still contains %i items", n);
    }
    threaded_queue_finalize(&q->queue);
#endif
}

/**
 * Returns true iff the message queue is empty
 *
 * @param q the message queue
 * @return true iff th message queue is empty
 */

bool async_queue_empty(async_queue_t *q)
{
#if ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_DLL
    return threaded_dll_cw_size(&q->queue) == 0;
#elif ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_RINGBUFFER
    return threaded_ringbuffer_cw_size(&q->queue) == 0;
#else
    return threaded_queue_size(&q->queue) == 0;
#endif
}

/**
 * Returns the size of the message queue
 *
 * @param q the message queue
 * @return the size of the message queue
 */

uint32_t async_queue_size(async_queue_t *q)
{
#if ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_DLL
    return (uint32_t)threaded_dll_cw_size(&q->queue);
#elif ASYNC_QUEUE_TYPE == ASYNC_QUEUE_TYPE_RINGBUFFER
    return threaded_ringbuffer_cw_size(&q->queue);
#else
    return threaded_queue_size(&q->queue);
#endif
}

static void async_message_wait_handler(struct async_message_s *msg)
{
    struct async_wait_s *args = (struct async_wait_s *)msg->handler_args;
    async_wait_progress(args, 1);
}

static void async_message_nop_handler(struct async_message_s *msg) { (void)msg; }

static void async_message_release_handler(struct async_message_s *msg) { async_message_release(msg); }

int         async_message_call_and_wait(async_queue_t *queue, async_message_t *msg)
{
    async_done_callback *old_handler = msg->handler;
    void                *old_handler_args = msg->handler_args;

#if __FreeBSD__
    struct async_wait_s *message_wait_argsp = async_wait_new_instance(1);
#else
    struct async_wait_s  message_wait_args;
    struct async_wait_s *message_wait_argsp = &message_wait_args;
    async_wait_init(message_wait_argsp, 1);
#endif
    msg->error_code = SUCCESS;
    msg->handler = async_message_wait_handler;
    msg->handler_args = message_wait_argsp;

    async_message_call(queue, msg);

    async_wait(message_wait_argsp);

    msg->handler = old_handler;
    msg->handler_args = old_handler_args;

#if !DNSCORE_HAS_LOGGING_DISABLED
    uint64_t wait_time = (uint64_t)(timeus() - msg->start_time);
#endif

#if __FreeBSD__
    async_wait_finalize(message_wait_argsp);
#else
    async_wait_finalize(message_wait_argsp); // local stack
#endif

    log_debug5("async waited %lluus on '%i@%s'", wait_time, msg->id, queue->pace.name);

    return msg->error_code;
}

void async_message_call_and_forget(async_queue_t *queue, async_message_t *am)
{
    am->handler = async_message_nop_handler;
    am->handler_args = NULL;

    async_message_call(queue, am);
}

void async_message_call_and_release(async_queue_t *queue, async_message_t *am)
{
    am->handler = async_message_release_handler;
    am->handler_args = NULL;

    async_message_call(queue, am);
}

static void *async_message_pool_alloc(void *_ignored_)
{
    async_message_t *msg;

    (void)_ignored_;

    ZALLOC_OBJECT_OR_DIE(msg, async_message_t, ASYNCMSG_TAG); // POOL
    ZEROMEMORY(msg, sizeof(async_message_t));                 // false positive: msg cannot be NULL
    return msg;
}

static void async_message_pool_free(void *msg, void *_ignored_)
{
    (void)_ignored_;

    memset(msg, 0xe2, sizeof(async_message_t));
    ZFREE(msg, async_message_t); // POOL
}

/**
 * Initialises the async message pool
 */

void async_message_pool_init()
{
    if(initialise_state_begin(&async_message_pool_init_state))
    {
        pool_init(&async_message_pool, async_message_pool_alloc, async_message_pool_free, NULL, "async message");
        pool_set_size(&async_message_pool, 0x80000);
        // for valgrind
#ifdef VALGRIND_FRIENDLY
        pool_set_size(&async_message_pool, 0);
#endif
        initialise_state_ready(&async_message_pool_init_state);
    }
}

/**
 * Destroy the message pool.
 */

void async_message_pool_finalize()
{
    if(initialise_state_unready(&async_message_pool_init_state))
    {
        pool_finalize(&async_message_pool);

#if ASYNC_WAIT_FINALIZE_DELAY_COUNT > 0
        mutex_lock(&async_wait_finalize_delay_mtx);
        for(int_fast32_t i = 0; i < ASYNC_WAIT_DESTROY_SHARED_DELAY_COUNT; ++i)
        {
            if(async_wait_finalize_delay[i] != NULL)
            {
                async_wait_finalize_now(async_wait_finalize_delay[i]);
                async_wait_finalize_delay[i] = NULL;
            }
        }
        mutex_unlock(&async_wait_finalize_delay_mtx);

        mutex_lock(&async_wait_destroy_delay_mtx);
        for(int_fast32_t i = 0; i < ASYNC_WAIT_DESTROY_SHARED_DELAY_COUNT; ++i)
        {
            if(async_wait_destroy_delay[i] != NULL)
            {
                async_wait_destroy_now(async_wait_destroy_delay[i]);
                async_wait_destroy_delay[i] = NULL;
            }
        }
        mutex_unlock(&async_wait_destroy_delay_mtx);
#endif

#if ASYNC_WAIT_DESTROY_SHARED_DELAY_COUNT > 0
        mutex_lock(&async_wait_destroy_shared_delay_mtx);
        for(int_fast32_t i = 0; i < ASYNC_WAIT_DESTROY_SHARED_DELAY_COUNT; ++i)
        {
            if(async_wait_destroy_shared_delay[i] != NULL)
            {
                async_wait_delete_shared_now(async_wait_destroy_shared_delay[i]);
                async_wait_destroy_shared_delay[i] = NULL;
            }
        }
        mutex_unlock(&async_wait_destroy_shared_delay_mtx);
#endif
        initialise_state_end(&async_message_pool_init_state);
    }
}

/**
 * Instantiates a new message, allocating it from the pool.
 *
 * @return a pointer to a new async_message_t
 */

async_message_t *async_message_new_instance()
{
    async_message_t *msg = (async_message_t *)pool_alloc(&async_message_pool);
    ZEROMEMORY(msg, sizeof(async_message_t));
    return msg;
}

/**
 * Releases a message to the pool.
 *
 * @param msg the message
 */

void async_message_release(async_message_t *msg)
{
#if DEBUG
    memset(msg, 0xe3, sizeof(async_message_t));
#endif
    pool_release(&async_message_pool, msg);
}

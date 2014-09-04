/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
#include "dnscore/dnscore.h"

#include "dnscore/async.h"
#include "dnscore/pool.h"
#include "dnscore/format.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#define ASYNCMSG_TAG 0x47534d434e595341

struct async_message_wait_args
{
    pthread_mutex_t mutex;
    pthread_cond_t  cond_wait;
    s32 wait_count;
};

static pool_s async_message_pool;

static bool async_message_pool_initialized = FALSE;

void
async_message_call(async_queue_s *queue, async_message_s *msg)
{
    msg->start_time = timeus();
    threaded_queue_enqueue(&queue->queue, msg);
}

async_message_s*
async_message_next(async_queue_s *queue)
{
    async_message_s* async = (async_message_s*)threaded_queue_try_dequeue(&queue->queue);
        
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

async_message_s*
async_message_try_next(async_queue_s *queue)
{
    async_message_s* async = (async_message_s*)threaded_queue_try_dequeue(&queue->queue);
            
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

void
async_wait_init(async_wait_s *aw, s32 count)
{
    pthread_mutex_init(&aw->mutex, NULL);
    pthread_cond_init(&aw->cond_wait, NULL);
    aw->wait_count = count;
    aw->error_code = SUCCESS;
}

/**
 * Waits until the count has be reduced to 0 (or below if something bad is going on)
 * 
 * @param aw
 * @return 
 */

void
async_wait(async_wait_s *aw)
{
    pthread_mutex_lock(&aw->mutex);
    
    while(aw->wait_count > 0)
    {
        pthread_cond_wait(&aw->cond_wait, &aw->mutex);
    }
    
    pthread_mutex_unlock(&aw->mutex);
}


bool
async_wait_timeout_absolute(async_wait_s *aw, u64 epoch_usec)
{
    struct timespec ts;
    
    ts.tv_sec = epoch_usec / 1000000L;
    ts.tv_nsec = (epoch_usec % 1000000L) * 1000L;
    
    pthread_mutex_lock(&aw->mutex);
    
    while(aw->wait_count > 0)
    {
        int err;
        
        err = pthread_cond_timedwait(&aw->cond_wait, &aw->mutex, &ts);
        
        if(err == ETIMEDOUT)
        {
            break;
        }
        
        if(err != 0)
        {
            log_err("async_wait_timeout: %r", MAKE_ERRNO_ERROR(err));
        }
    }
    
    pthread_mutex_unlock(&aw->mutex);
    
    return aw->wait_count == 0;
}

bool
async_wait_timeout(async_wait_s *aw, u64 usec)
{
    usec += timeus();
    
    return async_wait_timeout_absolute(aw, usec);
}

s32
async_wait_get_counter(async_wait_s *aw)
{
    s32 counter;
    
    pthread_mutex_lock(&aw->mutex);
    
    counter = aw->wait_count;
    
    pthread_mutex_unlock(&aw->mutex);
    
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

void
async_wait_progress(async_wait_s *aw, s32 count)
{
    pthread_mutex_lock(&aw->mutex);
    aw->wait_count -= count;

    pthread_cond_broadcast(&aw->cond_wait);
    pthread_mutex_unlock(&aw->mutex);

}

void
async_wait_set_first_error(async_wait_s *aw, s32 error)
{
    pthread_mutex_lock(&aw->mutex);
    if(ISOK(aw->error_code))
    {
        aw->error_code = error;
    }
    pthread_mutex_unlock(&aw->mutex);
}

s32
async_wait_get_error(async_wait_s *aw)
{
    s32 err;
    
    pthread_mutex_lock(&aw->mutex);
    
    err = aw->error_code;
    
    pthread_mutex_unlock(&aw->mutex);
    
    return err;
}

/**
 * 
 * Destroys the synchronisation point
 * 
 * @param aw
 * @return 
 */

void
async_wait_finalize(async_wait_s *aw)
{
    pthread_mutex_lock(&aw->mutex);
    s32 wait_count = aw->wait_count;
    pthread_mutex_unlock(&aw->mutex);
    
    if(wait_count > 0)
    {
        osformat(termerr, "async_wait_finalize: wait_count = %i > 0: finalisation before logical end of life", wait_count);
        flusherr();
    }
    
    pthread_cond_destroy(&aw->cond_wait);
    pthread_mutex_destroy(&aw->mutex);
}

void
async_queue_init(async_queue_s *q, u32 size, u64 min_us, u64 max_us, const char* name)
{
    threaded_queue_init(&q->queue, size);
    pace_init(&q->pace, min_us, max_us, name);    
}

void
async_queue_finalize(async_queue_s *q)
{
    u32 n;
    if((n = threaded_queue_size(&q->queue)) > 0)
    {
        log_warn("async_queue_finalize: queue still contains %u items");
    }
    threaded_queue_finalize(&q->queue);
}

bool
async_queue_emtpy(async_queue_s *q)
{
    return threaded_queue_size(&q->queue) == 0;
}

u32
async_queue_size(async_queue_s *q)
{
    return threaded_queue_size(&q->queue);
}

static void
async_message_wait_handler(struct async_message_s *msg)
{
    struct async_wait_s *args = (struct async_wait_s *)msg->handler_args;
    
    async_wait_progress(args, 1);
}

static void
async_message_nop_handler(struct async_message_s *msg)
{
}

static void
async_message_release_handler(struct async_message_s *msg)
{
    async_message_release(msg);
}

int
async_message_call_and_wait(async_queue_s *queue, async_message_s *msg)
{
    async_done_callback *old_handler = msg->handler;
    void *old_handler_args = msg->handler_args;

    struct async_wait_s message_wait_args;
    
    async_wait_init(&message_wait_args, 1);
    msg->error_code = SUCCESS;
    msg->handler = async_message_wait_handler;
    msg->handler_args = &message_wait_args;
    
    async_message_call(queue, msg);
    
    async_wait(&message_wait_args);
        
    msg->handler = old_handler;
    msg->handler_args = old_handler_args;
    
    u64 wait_time = timeus() - msg->start_time;
    
    async_wait_finalize(&message_wait_args);
    
    log_debug5("async waited %lluus on '%i@%s'", wait_time, msg->id, queue->pace.name);
    
    return msg->error_code;
}

void
async_message_call_and_forget(async_queue_s *queue, async_message_s *msg)
{
    msg->handler = async_message_nop_handler;
    msg->handler_args = NULL;
    
    async_message_call(queue, msg);
}

void
async_message_call_and_release(async_queue_s *queue, async_message_s *msg)
{
    msg->handler = async_message_release_handler;
    msg->handler_args = NULL;
    
    async_message_call(queue, msg);
}

static void *
async_message_pool_alloc(void *_ignored_)
{
    async_message_s *msg;
    
    (void)_ignored_;
    
    MALLOC_OR_DIE(async_message_s*, msg, sizeof(async_message_s), ASYNCMSG_TAG); // POOL
    ZEROMEMORY(msg, sizeof(async_message_s));
    return msg;
}

static void
async_message_pool_free(void *msg, void *_ignored_)
{
    (void)_ignored_;
    
    memset(msg, 0xe2, sizeof(async_message_s));
    free(msg); // POOL
}

void
async_message_pool_init()
{
    if(!async_message_pool_initialized)
    {
        pool_init(&async_message_pool, async_message_pool_alloc, async_message_pool_free, NULL, "async message");
        pool_set_size(&async_message_pool, 0x80000);
        // for valgrind
#ifdef VALGRIND_FRIENDLY
        pool_set_size(&async_message_pool, 0);
#endif
        
        async_message_pool_initialized = TRUE;
    }
}

void
async_message_pool_finalize()
{
    if(async_message_pool_initialized)
    {
        pool_finalize(&async_message_pool);
        
        async_message_pool_initialized = FALSE;
    }
}

async_message_s*
async_message_alloc()
{
    async_message_s *msg = (async_message_s *)pool_alloc(&async_message_pool);
    ZEROMEMORY(msg, sizeof(async_message_s));
    return msg;
}

void async_message_release(async_message_s *msg)
{
    memset(msg, 0xe3, sizeof(async_message_s));
    pool_release(&async_message_pool, msg);
}

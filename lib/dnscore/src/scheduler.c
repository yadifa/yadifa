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
* DOCUMENTATION */
/** @defgroup scheduler Scheduler
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <pthread.h>

#include "dnscore/threaded_queue.h"
#include "dnscore/thread_pool.h"
#include "dnscore/logger.h"

#include "dnscore/dnscore.h"
#include "dnscore/scheduler.h"
#include "dnscore/fdtools.h"

#define SCHDPAKT_TAG 0x544b415044484353
#define SCHDTHRD_TAG 0x4452485444484353

#define MODULE_MSG_HANDLE g_system_logger

/*
 *
 */

static thread_pool_task_counter scheduler_threads_counter = {PTHREAD_MUTEX_INITIALIZER, 0};

typedef struct scheduler_task scheduler_task;

struct scheduler_task
{
    scheduler_task_callback *task;
    void* args;
};

#ifndef NDEBUG
static u32 debug_count_current = 0;
#endif

typedef struct scheduler_thread scheduler_thread;

struct scheduler_thread
{
    scheduler_thread* next;
    scheduler_task_callback *task_init; /* ST call to make before launching the thread */
    thread_pool_function *task;
    void* args;
    const char* categoryname;
#ifndef NDEBUG
    u32 debug_count;
#endif
};

/************************************************/

typedef struct scheduler_thread_queue scheduler_thread_queue;

struct scheduler_thread_queue
{
    scheduler_thread* first;
    scheduler_thread* last;
};

static volatile bool scheduler_thread_running = FALSE;

static bool
scheduler_thread_queue_isempty(scheduler_thread_queue *queue)
{
    return queue->first == NULL;
}

static void
scheduler_thread_queue_enqueue(scheduler_thread_queue *queue, scheduler_thread *node)
{
    if(queue->first != NULL)
    {
        queue->last->next = node;
    }
    else
    {
        queue->first = node;
    }

    queue->last = node;

    node->next = NULL;
}

static scheduler_thread *
scheduler_thread_queue_dequeue(scheduler_thread_queue *queue)
{
    scheduler_thread *node = queue->first;

    if(node != NULL)
    {
        queue->first = queue->first->next;

        if(queue->first == NULL)
        {
            queue->last = NULL;
        }
    }
    return node;
}

/************************************************/

#define SCHEDULER_PACKET_LEN sizeof(scheduler_task)

typedef struct scheduler_task scheduler_packet;

/* A mutex on the writer flag */

/* The next tasks queue */
static threaded_queue scheduler_queue;
/*
 * The queue where MT tasks are waiting for concurrents to end
 * When a concurrent (most of the MT task) ends, it signals it and the next one is taken from here.
 */
static scheduler_thread_queue scheduler_delayed_queue = {NULL, NULL};
static pthread_mutex_t scheduler_delayed_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

static int g_write_fd = CLEARED_SOCKET;
static int g_read_fd = CLEARED_SOCKET;

/**
 * THREAD-UNSAFE
 */

int
scheduler_init()
{
    if(g_read_fd != CLEARED_SOCKET)
    {
        return -2;
    }
    
    /* convention : 0: read 1: write */

    int sv[2];

    if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
    {
        int err = ERRNO_ERROR;
        log_quit("scheduler: socketpair error %r", err);
        return err;
    }

    g_read_fd = sv[0];
    g_write_fd = sv[1];

    threaded_queue_init(&scheduler_queue, SCHEDULER_MAX_TASKS);

    return g_read_fd;
}

void
scheduler_finalize()
{
    if(g_read_fd == CLEARED_SOCKET)
    {
        return;
    }

    threaded_queue_finalize(&scheduler_queue);
    
    assert((g_write_fd < 0)||(g_write_fd >2));
    assert((g_read_fd < 0)||(g_read_fd >2));
    
    close_ex(g_write_fd);
    close_ex(g_read_fd);
        
    g_write_fd = CLEARED_SOCKET;
    g_read_fd = CLEARED_SOCKET;
}

/**
 * THREAD-SAFE
 */

void
scheduler_process()
{
    scheduler_packet *packet;

    if(g_read_fd < 0)
    {
        return;
    }
    
    MALLOC_OR_DIE(scheduler_packet*, packet, sizeof (scheduler_packet), SCHDPAKT_TAG);

    int len = SCHEDULER_PACKET_LEN;
    u8* p = (u8*)packet;
    
    do
    {
        int n = read(g_read_fd, p, len);

        if(n < 0)
        {
            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

            log_quit("scheduler: read error: %r", ERRNO_ERROR);
            
            free(packet);
            
            return;
        }

        len -= n;
        p += n;
    }
    while(len > 0);

    /* packet is the native-order pointer to the scheduler_task to add to the queue */

    threaded_queue_enqueue(&scheduler_queue, packet);
}

/**
 * THREAD-SAFE
 */

bool
scheduler_has_jobs()
{
    return threaded_queue_size(&scheduler_queue) != 0;
}

/**
 * THREAD-SAFE
 */

bool
scheduler_task_running()
{
    bool running;
    
    pthread_mutex_lock(&scheduler_delayed_queue_mutex);
    
    running = scheduler_thread_running;
    
    pthread_mutex_unlock(&scheduler_delayed_queue_mutex);
    
    return running;
}

/**
 * THREAD-UNSAFE
 */

static ya_result
scheduler_task_dequeue_delayed(void* not_used)
{
    return SCHEDULER_TASK_DEQUEUE_DELAYED;
}

ya_result
scheduler_do_next_job()
{
    /** @todo use the pool counters
     *	    _ Readers
     *	    _ Writers
     *	    _ Current Task : I can have a task that works bit by bit and continues until the last bit is done (RRSIG)
     */

    /* Dequeue a job */

    if(threaded_queue_size(&scheduler_queue) == 0)
    {
        return SCHEDULER_TASK_NOTHING;
    }

    scheduler_task *task = threaded_queue_dequeue(&scheduler_queue);

    /* Do (part) of the job */

    scheduler_task_callback *callback = task->task;
    void* args = task->args;
    free(task);

    ya_result return_code;

    switch(return_code = callback(args))
    {
        default:
            /* An error occurred */

            log_err("scheduler: unexpected callback return code %r", return_code);

        case SCHEDULER_TASK_FINISHED:

#ifndef NDEBUG
            log_debug("scheduler: task finished");
#endif
            /**
             * Retrieve and start the next thread
             * 
             * @todo EXCEPT IF A SHUTDOWN HAS BEEN REQUESTED ?
             */
            
        case SCHEDULER_TASK_DEQUEUE_DELAYED:
            
            if(dnscore_shuttingdown())
            {
                log_info("scheduler: shutdown in progress : ignoring next job");
                logger_flush();
                
                return STOPPED_BY_APPLICATION_SHUTDOWN;
            }

            pthread_mutex_lock(&scheduler_delayed_queue_mutex);

            scheduler_thread_running = FALSE;

            if(!scheduler_thread_queue_isempty(&scheduler_delayed_queue))
            {
                scheduler_thread* thread = scheduler_thread_queue_dequeue(&scheduler_delayed_queue);

#ifndef NDEBUG
                log_debug("scheduler: dequeued thread %s::(%p, %p, %p, %p@%u)", thread->categoryname, thread->task_init, thread->task, thread->args, thread, thread->debug_count);
                log_debug("scheduler: starting thread %u", thread->debug_count);

                log_debug("scheduler: next thread init");
#endif
                if(thread->task_init != NULL)
                {
                    thread->task_init(thread->args);
                }

#ifndef NDEBUG
                log_debug("scheduler: next thread ready");
#endif
                
                if(thread->task != NULL)
                {
#ifndef NDEBUG
                    log_debug("scheduler: next thread start");
#endif
                    scheduler_thread_running = TRUE;

                    thread_pool_schedule_job(thread->task, thread->args, &scheduler_threads_counter, thread->categoryname);
                }

                free(thread);
            }

            pthread_mutex_unlock(&scheduler_delayed_queue_mutex);

            break;

        case SCHEDULER_TASK_PROGRESS:
            /* NOP */
#ifndef NDEBUG
            log_debug("scheduler: task progress");
#endif
            break;
    }

    return return_code;
}

void
scheduler_schedule_task(scheduler_task_callback* function, void* args)
{
    scheduler_packet packet;
    u8* p = (u8*) & packet;
    ssize_t len = sizeof (scheduler_packet);
    ssize_t n;
/*
#ifndef NDEBUG
    log_debug("scheduler: scheduler_schedule_task(%P,%p)'", function, args);
#endif
  */
    packet.task = function;
    packet.args = args;
    
    if(g_write_fd < 0)
    {
        return;
    }

    do
    {
        n = write(g_write_fd, p, len);

        if(n <= 0)
        {
            int err = errno;

            if(err == EINTR)
            {
                continue;
            }

            log_quit("scheduler: write error: %r", err, ERRNO_ERROR);
            
            break;
        }

        len -= n;
        p += n;
    }
    while(len > 0);
}

void
scheduler_schedule_thread(scheduler_task_callback* init_function, thread_pool_function* thread_function, void* args, const char* categoryname)
{
#ifndef NDEBUG
    log_debug("scheduler: scheduler_schedule_thread(%P, %P, %p, %s)", init_function, thread_function, args, categoryname);
#endif
    
    pthread_mutex_lock(&scheduler_delayed_queue_mutex);

    scheduler_thread* thread;

    MALLOC_OR_DIE(scheduler_thread*, thread, sizeof (scheduler_thread), SCHDTHRD_TAG);
    thread->task = thread_function;
    thread->task_init = init_function;
    thread->args = args;
    thread->categoryname = categoryname;

#ifndef NDEBUG
    thread->debug_count = debug_count_current++;

    log_debug("scheduler: enqueue thread %s::(%p, %P, %P, %p@%u)", categoryname, init_function, thread_function, args, thread, thread->debug_count);
#endif


    scheduler_thread_queue_enqueue(&scheduler_delayed_queue, thread);

    // refire

    if(!scheduler_thread_running)
    {
        scheduler_schedule_task(scheduler_task_dequeue_delayed, NULL);
    }

    pthread_mutex_unlock(&scheduler_delayed_queue_mutex);
}

s32 scheduler_get_running_threads_count()
{
    s32 val;
    
    pthread_mutex_lock(&scheduler_threads_counter.mutex);
    val = scheduler_threads_counter.value;
    pthread_mutex_unlock(&scheduler_threads_counter.mutex);

    return val;
}

void scheduler_print_queue()
{
    pthread_mutex_lock(&scheduler_delayed_queue_mutex);
    
    u32 index = 0;
    
    scheduler_thread *item = scheduler_delayed_queue.first;
    
    while(item != NULL)
    {
#ifndef NDEBUG
        log_debug("scheduler: [%4i] category=%s init@%p task@%p args@%p %i", index, item->categoryname, item->task_init, item->task, item->args, item->debug_count);
#else
        log_debug("scheduler: [%4i] category=%s init@%p task@%p args@%p", index, item->categoryname, item->task_init, item->task, item->args);
#endif   
        index++;
        item = item->next;
    }
    
    pthread_mutex_unlock(&scheduler_delayed_queue_mutex);
}

/** @} */

/*----------------------------------------------------------------------------*/


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
/** @defgroup threading Threading, pools, queues, ...
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include <sys/types.h>
#include <unistd.h>

#include "dnscore/threaded_queue.h"

#include "dnscore/thread_pool.h"

#include "dnscore/logger.h"

#include "dnscore/format.h"

/* 0 = nothing, 1 = warns and worse, 2 = info and worse, 3 = debug and worse */
#define VERBOSE_THREAD_LOG      0

/* Disable when in release mode */

#ifndef NDEBUG
#undef VERBOSE_THREAD_LOG
#define VERBOSE_THREAD_LOG      0
#endif

#define MODULE_MSG_HANDLE		g_system_logger
extern logger_handle *g_system_logger;

#define THREADPOOL_TAG			0x4c4f4f5044524854 /* THRDPOOL */

#define THREADPOOL_QUEUE_SIZE_FACTOR	4096 /* 2 */

typedef struct threaded_queue_task threaded_queue_task;

struct threaded_queue_task
{
    thread_pool_function* function;
    void* parm;
    thread_pool_task_counter* counter;

    const char* categoryname;           /* so it's easy to know what thread is running*/
};

typedef struct thread_descriptor thread_descriptor;

struct thread_descriptor
{
    pthread_t id;
    volatile u8 status;
    char info[255];
};

/* The array of thread desctipros*/

static pthread_mutex_t thread_descriptors_mutex = PTHREAD_MUTEX_INITIALIZER;
static thread_descriptor** thread_descriptors = NULL;
static u8 thread_pool_size = 0;

static threaded_queue thread_pool_queue;

static pthread_key_t pthread_pool_random_key = ~0;
static pthread_once_t pthread_pool_random_key_once = PTHREAD_ONCE_INIT;

void
thread_pool_counter_init(thread_pool_task_counter* counter, s32 value)
{
    pthread_mutex_init(&counter->mutex, NULL);
    counter->value = value;
}

void
thread_pool_counter_destroy(thread_pool_task_counter* counter)
{
    pthread_mutex_destroy(&counter->mutex);
}

s32
thread_pool_counter_get_value(thread_pool_task_counter* counter)
{
    s32 ret;
    pthread_mutex_lock(&counter->mutex);
    ret = counter->value;
    pthread_mutex_unlock(&counter->mutex);
    return ret;
}

s32
thread_pool_counter_add_value(thread_pool_task_counter* counter, s32 value)
{
    s32 ret;
    pthread_mutex_lock(&counter->mutex);
    counter->value += value;
    ret = counter->value;
    pthread_mutex_unlock(&counter->mutex);
    return ret;
}

static void
pthread_pool_random_key_finalize(void *unused)
{
#if VERBOSE_THREAD_LOG > 2
    log_debug("thread: random thread-local key finalize");
#endif
}

static void
pthread_pool_random_key_init()
{
#if VERBOSE_THREAD_LOG > 2
    log_debug("thread: random thread-local key init");
#endif
    
    if(pthread_key_create(&pthread_pool_random_key, pthread_pool_random_key_finalize) < 0)
    {
        log_quit("pthread_key_create = %r", ERRNO_ERROR);
    }
}

static void*
thread_pool_thread(void* args)
{
    /*
     * Dequeue from the task queue
     * If what we got is NULL then it's time to stop
     * Else we run it
     */

    thread_descriptor* desc = (thread_descriptor*)args;

//    pthread_t id = desc->id;

#if VERBOSE_THREAD_LOG > 2
    log_debug("thread: %x started", desc->id);
#endif

    if(pthread_getspecific(pthread_pool_random_key) == NULL)
    {
        random_ctx rndctx = random_init((int)time(NULL) + (int)desc->id); /* OSX darwin gcc complains but it's working fine (and it should)*/
        
        if(pthread_setspecific(pthread_pool_random_key, rndctx) < 0)
        {
            log_quit("pthread_setspecific = %r", ERRNO_ERROR);
        }
    }

#if VERBOSE_THREAD_LOG > 2
    log_debug("thread: %x random thread-local variable ready", desc->id);
#endif

    for(;;)
    {
        desc->status = THREAD_STATUS_WAITING;

        void* data = threaded_queue_dequeue(&thread_pool_queue);

        if(data == NULL)
        {
#if VERBOSE_THREAD_LOG > 1
            log_debug("thread: %x got terminate", id);
#endif

            desc->status = THREAD_STATUS_TERMINATING;
            break;
        }

        desc->status = THREAD_STATUS_WORKING;

        threaded_queue_task* task = (threaded_queue_task*)data;

        thread_pool_task_counter* counter = task->counter;
        thread_pool_function* function = task->function;
        void* parm = task->parm;
        const char* categoryname = task->categoryname;

        free(task);

        strcpy(desc->info, categoryname);

        if(counter != NULL)
        {
            thread_pool_counter_add_value(counter, +1);
        }

#if VERBOSE_THREAD_LOG > 3
        log_debug("thread: %x %s::%p(%p) begin", id, categoryname, function, parm);
#endif

        function(parm);
        
#if VERBOSE_THREAD_LOG > 3
        log_debug("thread: %x %s::%p(%p) end", id, categoryname, function, parm);
#endif

        if(counter != NULL)
        {
            thread_pool_counter_add_value(counter, -1);
        }

        memcpy(desc->info, "IDLE", 5);
    }

#if VERBOSE_THREAD_LOG > 2
    log_debug("thread: %x finalising random thread-local variable", desc->id);
#endif

    random_ctx rndctx = pthread_getspecific(pthread_pool_random_key);
    random_finalize(rndctx);
    (void) pthread_setspecific(pthread_pool_random_key, NULL);

#if VERBOSE_THREAD_LOG > 1
    log_debug("thread: %x stopped", id);
#endif

    pthread_exit(NULL);

    return NULL;
}

random_ctx thread_pool_get_random_ctx()
{
    random_ctx rndctx = pthread_getspecific(pthread_pool_random_key);
    
    return rndctx;
}

/**
 * This MUST be called at the start or a thread that will, one way or another, use
 * the random function.  In doubt, do it.  So just do it.
 * 
 * @note: It's automatically done for all threads from the pool.
 * @note: It's made on the core alarm function (the one also responsible for
 *        flushing & cie)
 */

void thread_pool_setup_random_ctx()
{
    (void) pthread_once(&pthread_pool_random_key_once, pthread_pool_random_key_init);
    
    if(pthread_getspecific(pthread_pool_random_key) == NULL)
    {
        random_ctx rndctx = random_init(time(NULL));

        if(pthread_setspecific(pthread_pool_random_key, rndctx) < 0)
        {
            log_quit("pthread_setspecific = %r", ERRNO_ERROR);
        }
    }
}

ya_result
thread_pool_init(u16 thread_count)
{
#if VERBOSE_THREAD_LOG > 1
    log_debug("thread_pool_init(%d)", thread_count);
#endif
    
    if(thread_count == 0)
    {
        return ERROR;
    }
    
    thread_pool_setup_random_ctx();

    thread_descriptor** new_thread_descriptors;

    int ret; /* thread creation return code */

    u8 i; /* thread creation loop counter */

    pthread_mutex_lock(&thread_descriptors_mutex);

    /*
     * The pool already has that much thread count
     */    
        
    if(thread_count <= thread_pool_size)
    {
        pthread_mutex_unlock(&thread_descriptors_mutex);
        return thread_pool_size;
    }

    if(thread_descriptors == NULL)
    {
        threaded_queue_init(&thread_pool_queue, thread_count * THREADPOOL_QUEUE_SIZE_FACTOR);
    }
    else
    {
        threaded_queue_set_maxsize(&thread_pool_queue, thread_count * THREADPOOL_QUEUE_SIZE_FACTOR);
    }

    MALLOC_OR_DIE(thread_descriptor**, new_thread_descriptors, thread_count * sizeof (thread_descriptor*), THREADPOOL_TAG);

    for(i = 0; i < thread_pool_size; i++)
    {
        new_thread_descriptors[i] = thread_descriptors[i];
    }

    for(i = thread_pool_size; i < thread_count; i++)
    {
        MALLOC_OR_DIE(thread_descriptor*, new_thread_descriptors[i], sizeof(thread_descriptor), THREADPOOL_TAG);
        
        ZEROMEMORY(new_thread_descriptors[i], sizeof(thread_descriptor));

        new_thread_descriptors[i]->status = THREAD_STATUS_STARTING;

        if((ret = pthread_create(&new_thread_descriptors[i]->id, NULL, thread_pool_thread, new_thread_descriptors[i])) != 0)
        {
            OSDEBUG(termerr, "thread_pool_set_pool_size: pthread_create : Oops: (%i) %s\n", ret, strerror(ret));

            free(new_thread_descriptors);

            pthread_mutex_unlock(&thread_descriptors_mutex);

            return THREAD_CREATION_ERROR;
        }
    }

    free(thread_descriptors);

    thread_descriptors = new_thread_descriptors;

    thread_pool_size = thread_count;

    pthread_mutex_unlock(&thread_descriptors_mutex);

    return thread_pool_size;
}

ya_result
thread_pool_schedule_job(thread_pool_function func, void* parm, thread_pool_task_counter* counter, const char* categoryname)
{
    threaded_queue_task* task;

    MALLOC_OR_DIE(threaded_queue_task*, task, sizeof (threaded_queue_task), THREADPOOL_TAG);

    task->function = func;
    task->parm = parm;
    task->counter = counter;

    if(categoryname == NULL)
    {
        categoryname = "anonymous";
    }
    
    task->categoryname = categoryname;

    threaded_queue_enqueue(&thread_pool_queue, task);

    return SUCCESS;
}

ya_result
thread_pool_destroy()
{
    thread_descriptor** td;
    u8 tps = thread_pool_size;
    u8 i;

    pthread_mutex_lock(&thread_descriptors_mutex);
    td = thread_descriptors;
    thread_descriptors = NULL;
    pthread_mutex_unlock(&thread_descriptors_mutex);

    if(td == NULL)
    {
#if VERBOSE_THREAD_LOG > 1
        log_debug("thread_pool_destroy called on a NULL set (already done)");
#endif
        return THREAD_DOUBLEDESTRUCTION_ERROR; /* double call */
    }

    thread_pool_size = 0;

    /*
     * Sending a node with data == NULL will kill one thread
     *
     * I have to launch one for each thread.
     */

    for(i = 0; i < tps; i++)
    {
        switch(td[i]->status) /* Unimportant W -> R race */
        {
            case THREAD_STATUS_TERMINATING:
#if VERBOSE_THREAD_LOG > 1
                log_debug("thread: #%i [%x]: already terminating", i, td[i]->id);
#endif
                threaded_queue_enqueue(&thread_pool_queue, NULL);
                break;
            case THREAD_STATUS_TERMINATED:
#if VERBOSE_THREAD_LOG > 1
                log_debug("thread: #%i [%x]: already terminated", i, td[i]->id);
#endif
                threaded_queue_enqueue(&thread_pool_queue, NULL);
                break;
            case THREAD_STATUS_WORKING:
#if VERBOSE_THREAD_LOG > 2
                log_debug("thread: #%i [%x]: working: sending stop", i, td[i]->id);
#endif
                threaded_queue_enqueue(&thread_pool_queue, NULL);
                break;
            case THREAD_STATUS_WAITING:
#if VERBOSE_THREAD_LOG > 2
                log_debug("thread: #%i [%x]: waiting: sending stop", i, td[i]->id);
#endif
                threaded_queue_enqueue(&thread_pool_queue, NULL);
                break;
            default:
#if VERBOSE_THREAD_LOG > 2
                log_debug("thread: #%i [%x]: sending stop on %i status", i, td[i]->id, td[i]->status);
#endif
                threaded_queue_enqueue(&thread_pool_queue, NULL);
                break;
        }
    }

    /*
     * I need to wait for each thread
     */

    for(i = 0; i < tps; i++)
    {
        int err;

        /*
         * @NOTE: helgrind will complain here about a r/w race condition
         *        This is not a problem. The thread keeps its working status (in a volatile)
         *        And this loop only tries to wait if the status is not "done" yet.
         *
         * @TODO: look at PTHREAD_CREATE_JOINABLE
         */

        if(td[i]->status != THREAD_STATUS_TERMINATING && td[i]->status != THREAD_STATUS_TERMINATED)
        {
#if VERBOSE_THREAD_LOG > 2
            log_debug("thread: #%i [%x]: waiting termination", i, td[i]->id);
#endif

            if((err = pthread_join(td[i]->id, NULL)) != 0)
            {
#if VERBOSE_THREAD_LOG > 3
                log_debug("thread: error joining #%i [%x] %i %r", i, td[i]->id, err, ERRNO_ERROR);
#endif
            }
        }

        td[i]->status = THREAD_STATUS_TERMINATED;

#if VERBOSE_THREAD_LOG > 2
        log_debug("thread: #%i: terminated", i);
#endif

        pthread_detach(td[i]->id);

        free(td[i]);

        td[i] = NULL;
    }

    free(td);

#if VERBOSE_THREAD_LOG > 2
    log_debug("thread: thread_pool_destroy: finalize");
#endif

    threaded_queue_finalize(&thread_pool_queue);

    return SUCCESS;
}

u8
thread_pool_get_pool_size()
{
    return thread_pool_size;
}

/** @} */

/*----------------------------------------------------------------------------*/


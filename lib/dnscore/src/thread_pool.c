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
/** @defgroup threading Threading, pools, queues, ...
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore-config.h"

#if HAS_PTHREAD_SETNAME_NP
#ifdef DEBUG
#define _GNU_SOURCE 1
#endif
#endif

#include <sys/types.h>
#include <unistd.h>

#include <pthread.h>

#include "dnscore/threaded_queue.h"
#include "dnscore/thread_pool.h"
#include "dnscore/logger.h"
#include "dnscore/format.h"
#include "dnscore/u32_set.h"

#include "dnscore/mutex.h"

/* 0 = nothing, 1 = warns and worse, 2 = info and worse, 3 = debug and worse */
#define VERBOSE_THREAD_LOG      3

/* Disable when in release mode */

#ifndef DEBUG
#undef VERBOSE_THREAD_LOG
#define VERBOSE_THREAD_LOG      0
#endif

#define MODULE_MSG_HANDLE		g_system_logger
extern logger_handle *g_system_logger;

#define THREADPOOL_TAG			0x4c4f4f5044524854 /* THRDPOOL */

#define THREADPOOL_QUEUE_SIZE_FACTOR	4096 /* 2 */

#define THREADPOOL_FLAG_PAUSED          1

typedef struct threaded_queue_task threaded_queue_task;

struct threaded_queue_task
{
    thread_pool_function* function;
    void* parm;
    thread_pool_task_counter *counter;

    const char* categoryname;           /* so it's easy to know what thread is running*/
};

typedef struct thread_descriptor_s thread_descriptor_s;

struct thread_descriptor_s
{
    struct thread_pool_s *pool;
    pthread_t id;
    volatile u8 status;
    char info[255];
};

/* The array of thread descriptors*/
/*
static pthread_mutex_t thread_descriptors_mutex = PTHREAD_MUTEX_INITIALIZER;
static thread_descriptor_s** thread_descriptors = NULL;
static u8 thread_pool_size = 0;
static threaded_queue thread_pool_queue;
*/
static pthread_key_t pthread_pool_random_key = ~0;
static pthread_once_t pthread_pool_random_key_once = PTHREAD_ONCE_INIT;

static mutex_t thread_pool_set_mutex = MUTEX_INITIALIZER;
static u32_set thread_pool_set = U32_SET_EMPTY;
static u32 thread_pool_id_next = 0;

#ifdef DEBUG
static smp_int thread_pool_waiting = SMP_INT_INITIALIZER;
static smp_int thread_pool_running = SMP_INT_INITIALIZER;
#endif

struct thread_pool_s
{
    mutex_t mtx;
    struct thread_descriptor_s **descriptors;
    threaded_queue queue;
    u8 thread_pool_size;
    u8 flags;
    char *pool_name;
    u32 id;
};

typedef struct thread_pool_s thread_pool_s;

void
thread_pool_counter_init(thread_pool_task_counter *counter, s32 value)
{
    pthread_mutex_init(&counter->mutex, NULL);
    counter->value = value;
}

void
thread_pool_counter_destroy(thread_pool_task_counter *counter)
{
    pthread_mutex_destroy(&counter->mutex);
}

s32
thread_pool_counter_get_value(thread_pool_task_counter *counter)
{
    s32 ret;
    pthread_mutex_lock(&counter->mutex);
    ret = counter->value;
    pthread_mutex_unlock(&counter->mutex);
    return ret;
}

s32
thread_pool_counter_add_value(thread_pool_task_counter *counter, s32 value)
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
thread_pool_thread(void *args)
{
    /*
     * Dequeue from the task queue
     * If what we got is NULL then it's time to stop
     * Else we run it
     */

    thread_descriptor_s* desc = (thread_descriptor_s*)args;
    threaded_queue *queue = &desc->pool->queue;

#if VERBOSE_THREAD_LOG > 1
    pthread_t id = desc->id;
#endif
    
#if VERBOSE_THREAD_LOG > 2
    log_debug("thread: %x started (pool '%s')", desc->id, STRNULL(desc->pool->pool_name));
#endif

    if(pthread_getspecific(pthread_pool_random_key) == NULL)
    {
        random_ctx rndctx = random_init_auto();
        
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
#ifdef DEBUG
#ifdef HAS_PTHREAD_SETNAME_NP        
        if(desc->pool->pool_name != NULL)
        {
            pthread_setname_np(pthread_self(), desc->pool->pool_name);
        }
#endif
#endif
        
#ifdef DEBUG
        smp_int_inc(&thread_pool_waiting);
#endif
                
        desc->status = THREAD_STATUS_WAITING;

        void* data = threaded_queue_dequeue(queue);

#ifdef DEBUG
        smp_int_dec(&thread_pool_waiting);
#endif
        
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

        thread_pool_task_counter *counter = task->counter;
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
       
#ifdef HAS_PTHREAD_SETNAME_NP        
#ifdef DEBUG
        pthread_setname_np(pthread_self(), desc->info);
#endif
#endif

#ifdef DEBUG
        smp_int_inc(&thread_pool_running);
#endif
        
        function(parm);
        
#ifdef DEBUG
        smp_int_dec(&thread_pool_running);
#endif
        
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
    if(rndctx != NULL)
    {
        random_finalize(rndctx);
        (void) pthread_setspecific(pthread_pool_random_key, NULL);
    }

#if VERBOSE_THREAD_LOG > 1
    log_debug("thread: %x stopped", id);
#endif

    pthread_exit(NULL); // end of the thread from the pool

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

void
thread_pool_setup_random_ctx()
{
#ifdef DEBUG
    log_debug7("thread_pool_setup_random_ctx()", ERRNO_ERROR);
#endif
    
    (void) pthread_once(&pthread_pool_random_key_once, pthread_pool_random_key_init);
    
    if(pthread_getspecific(pthread_pool_random_key) == NULL)
    {
        random_ctx rndctx = random_init_auto();

        if(pthread_setspecific(pthread_pool_random_key, rndctx) != 0)
        {
            log_quit("pthread_setspecific = %r", ERRNO_ERROR);
        }
    }
}

void
thread_pool_destroy_random_ctx()
{
    random_ctx rndctx;
    
#ifdef DEBUG
    log_debug7("thread_pool_destroy_random_ctx()", ERRNO_ERROR);
#endif
    
    (void) pthread_once(&pthread_pool_random_key_once, pthread_pool_random_key_init);
    
    if((rndctx = pthread_getspecific(pthread_pool_random_key)) != NULL)
    {
        random_finalize(rndctx);

        if(pthread_setspecific(pthread_pool_random_key, NULL) != 0)
        {
            log_quit("pthread_setspecific = %r", ERRNO_ERROR);
        }
    }
    else
    {
        log_warn("no random context for thread");
    }
}

static thread_descriptor_s*
thread_pool_create_thread(thread_pool_s *tp)
{
    thread_descriptor_s *td = NULL;
    
    MALLOC_OR_DIE(thread_descriptor_s*, td, sizeof(thread_descriptor_s), THREADPOOL_TAG);    
    ZEROMEMORY(td, sizeof(thread_descriptor_s));

    td->pool = tp;
    td->status = THREAD_STATUS_STARTING;

    int ret;
    if((ret = pthread_create(&td->id, NULL, thread_pool_thread, td)) != 0)
    {
        OSDEBUG(termerr, "thread_pool_set_pool_size: pthread_create : oops: (%i) %s\n", ret, strerror(ret));

        free(td);

        return NULL;
    }
    
    return td;
}

struct thread_pool_s*
thread_pool_init_ex(u8 thread_count, u32 queue_size, const char *pool_name)
{
#if VERBOSE_THREAD_LOG > 1
    log_debug("thread_pool_init(%d, %d, %s)", thread_count, queue_size, STRNULL(pool_name));
#endif
    
    if(thread_count == 0)
    {
        return NULL;
    }
    
    if(queue_size == 0)
    {
        queue_size = thread_count;
    }
    
    if(pool_name == NULL)
    {
        pool_name = "thread-pool";
    }
        
    thread_pool_setup_random_ctx();
    
    thread_pool_s *tp;
    MALLOC_OR_DIE(thread_pool_s*, tp, sizeof(thread_pool_s), GENERIC_TAG);
    ZEROMEMORY(tp, sizeof(thread_pool_s));
    
#ifdef HAS_PTHREAD_SETNAME_NP
#ifdef DEBUG
    tp->pool_name = strdup(pool_name);
#endif
#endif
    
    thread_descriptor_s** thread_descriptors;

    u8 i; /* thread creation loop counter */

    threaded_queue_init(&tp->queue, queue_size);

    MALLOC_OR_DIE(thread_descriptor_s**, thread_descriptors, thread_count * sizeof (thread_descriptor_s*), THREADPOOL_TAG);

    for(i = 0; i < thread_count; i++)
    {
        thread_descriptor_s *td;
        
        if((td = thread_pool_create_thread(tp)) == NULL)
        {
            free(thread_descriptors);
            threaded_queue_finalize(&tp->queue);
            return NULL;
        }
        
        thread_descriptors[i] = td;
    }
    
    mutex_init(&tp->mtx);

    tp->descriptors = thread_descriptors;
    tp->thread_pool_size = thread_count;
    
    for(;;)
    {
        mutex_lock(&thread_pool_set_mutex);
        u32 id = thread_pool_id_next++;
        u32_node *node = u32_set_avl_insert(&thread_pool_set, id);
        mutex_unlock(&thread_pool_set_mutex);
        
        if(node->value == NULL)
        {
            tp->id = id;
            node->value = tp;
            break;
        }
    }

    return tp;
}

struct thread_pool_s*
thread_pool_init(u8 thread_count, u32 queue_size)
{
    struct thread_pool_s* tp = thread_pool_init_ex(thread_count, queue_size, NULL);
    
    return tp;
}

u8
thread_pool_get_size(struct thread_pool_s *tp)
{
    return tp->thread_pool_size;
}

#ifdef DEBUG
static void
thread_pool_debug_dump(struct thread_pool_s* tp)
{
    struct thread_descriptor_s **d = tp->descriptors;
    u8 n = tp->thread_pool_size;
    u8 i = 0;
    while(n-- > 0)
    {
        log_debug("thread_pool_debug_dump %d, %x, %x, %s", i, d[i]->id, d[i]->status, d[i]->info);
        i++;
    }
}
#endif

/**
 * Enqueues a function to be executed by a thread pool
 * 
 * @param tp            the thread pool
 * @param func          the function
 * @param parm          the parameter for the function
 * @param counter       an optional counter that will be incremented just before the function is called, and decremented just after
 * @param categoryname  an optional string that will be along the thread, mostly for debugging
 * 
 * @return SUCCESS
 */

ya_result
thread_pool_enqueue_call(struct thread_pool_s* tp, thread_pool_function func, void* parm, thread_pool_task_counter *counter, const char* categoryname)
{
#ifdef DEBUG
    int running = smp_int_get(&thread_pool_running);
    int waiting = smp_int_get(&thread_pool_waiting);

    log_debug("thread_pool_enqueue_call(%p,%p,%p,%s), queue size = %d+1, wait=%d, run=%d",func,parm,counter,(categoryname!=NULL)?categoryname:"NULL",threaded_queue_size(&tp->queue), waiting, running);
    
    static u32 last_dump_time = 0;
    u32 now = time(NULL);
    
    if(now - last_dump_time > 30)
    {    
        thread_pool_debug_dump(tp);
        last_dump_time = now;
    }
    
#endif
    
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

    threaded_queue_enqueue(&tp->queue, task);

    return SUCCESS;
}

static ya_result
thread_pool_stop(struct thread_pool_s* tp)
{
    if(tp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    thread_descriptor_s** td;
    u8 tps = tp->thread_pool_size;
    u8 i;

    pthread_mutex_lock(&tp->mtx);
    td = tp->descriptors;
    pthread_mutex_unlock(&tp->mtx);

    if(td == NULL)
    {
#if VERBOSE_THREAD_LOG > 1
        log_debug("thread_pool_stop called on a NULL set");
#endif
        return SERVICE_NOT_RUNNING;
    }
    
    if((tp->flags & THREADPOOL_FLAG_PAUSED) != 0)
    {
#if VERBOSE_THREAD_LOG > 1
        log_debug("thread_pool_stop called on a NULL set");
#endif
        return SERVICE_ALREADY_PAUSED;
    }

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
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_TERMINATED:
#if VERBOSE_THREAD_LOG > 1
                log_debug("thread: #%i [%x]: already terminated", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_WORKING:
#if VERBOSE_THREAD_LOG > 2
                log_debug("thread: #%i [%x]: working: sending stop", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_WAITING:
#if VERBOSE_THREAD_LOG > 2
                log_debug("thread: #%i [%x]: waiting: sending stop", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            default:
#if VERBOSE_THREAD_LOG > 2
                log_debug("thread: #%i [%x]: sending stop on %i status", i, td[i]->id, td[i]->status);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
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
        log_debug("thread: #%i: stopped", i);
#endif
        // keep the descriptor for the resume
    }
    
    tp->flags |= THREADPOOL_FLAG_PAUSED;

    return SUCCESS;
}

static ya_result
thread_pool_start(struct thread_pool_s* tp)
{
    if(tp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    if((tp->flags & THREADPOOL_FLAG_PAUSED) == 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    thread_descriptor_s** thread_descriptors = tp->descriptors;
    u8 tps = tp->thread_pool_size;
    u8 i;
    
    if(thread_descriptors == NULL)
    {
#if VERBOSE_THREAD_LOG > 1
        log_debug("thread_pool_stop called on a NULL set");
#endif
        return SERVICE_NOT_RUNNING;
    }
    
    for(i = 0; i < tps; i++)
    {
        /*
         * @NOTE: helgrind will complain here about a r/w race condition
         *        This is not a problem. The thread keeps its working status (in a volatile)
         *        And this loop only tries to wait if the status is not "done" yet.
         *
         * @TODO: look at PTHREAD_CREATE_JOINABLE
         */

        u8 status = thread_descriptors[i]->status;
        
        switch(status)
        {
            case THREAD_STATUS_TERMINATING:
            case THREAD_STATUS_TERMINATED:
                // all good
                break;
            default:
                log_err("thread_pool_stop: '%s' has status %hhu", STRNULL(tp->pool_name), status);
                return SERVICE_HAS_RUNNING_THREADS;
        }
    }

    for(i = 0; i < tps; i++)
    {
        int ret;
        
        thread_descriptors[i]->status = THREAD_STATUS_STARTING;
        
        if((ret = pthread_create(&thread_descriptors[i]->id, NULL, thread_pool_thread, thread_descriptors[i])) != 0)
        {
            return ret;
        }

#if VERBOSE_THREAD_LOG > 2
        log_debug("thread: #%i: started again", i);
#endif
        // keep the descriptor for the resume
    }
    
    tp->flags &= ~THREADPOOL_FLAG_PAUSED;
        
    return SUCCESS;
}

ya_result
thread_pool_resize(struct thread_pool_s* tp, u8 new_size)
{
    if(tp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    pthread_mutex_lock(&tp->mtx);
    
    thread_descriptor_s** tds;
    u8 tps = tp->thread_pool_size;
    u8 i;
    
    if(tps == new_size)
    {
        // nothing to do
        
        pthread_mutex_unlock(&tp->mtx);        
        return tps;
    }
    
    tds = tp->descriptors;
    tp->descriptors = NULL;
    
    // allocate a new struct, reuse thestructs
    
    thread_descriptor_s** thread_descriptors;
    MALLOC_OR_DIE(thread_descriptor_s**, thread_descriptors, sizeof (thread_descriptor_s*) * new_size, THREADPOOL_TAG);
    
    // if grow
    
    if(new_size > tps)
    {
        // copy the current ones
        
        memcpy(thread_descriptors, tds, sizeof(thread_descriptor_s*) * tps);
        
        // create new threads [tps;new_size[
        
        for(i = tps; i < new_size; i++)
        {
            thread_descriptor_s *td;

            if((td = thread_pool_create_thread(tp)) == NULL)
            {
                // failed to allocate one thread ...
                // it's bad.  keep what we have.
                
                log_err("thread_pool: could not resize from %u to %u, cutting at %u", tps, new_size, i - 1);
                logger_flush();
                
                if(i == tps)
                {
                    free(thread_descriptors);
                    thread_descriptors = tds;
                    new_size = tps;
                }
                else
                {
                    free(tds);
                    new_size = i - 1;
                }
                
                tp->descriptors = thread_descriptors;
                tp->thread_pool_size = new_size;

                pthread_mutex_unlock(&tp->mtx);

                return new_size;
            }

            thread_descriptors[i] = td;
        }
    }
    else
    {
        // copy what we can
        
        memcpy(thread_descriptors, tds, sizeof(thread_descriptor_s*) * new_size);
        
        // stop threads [new_size;tps[
        
        for(i = new_size; i < tps; i++)
        {
            switch(tds[i]->status) /* Unimportant W -> R race */
            {
                case THREAD_STATUS_TERMINATING:
#if VERBOSE_THREAD_LOG > 1
                    log_debug("thread: #%i [%x]: already terminating", i, tds[i]->id);
#endif
                    threaded_queue_enqueue(&tp->queue, NULL);
                    break;
                case THREAD_STATUS_TERMINATED:
#if VERBOSE_THREAD_LOG > 1
                    log_debug("thread: #%i [%x]: already terminated", i, tds[i]->id);
#endif
                    threaded_queue_enqueue(&tp->queue, NULL);
                    break;
                case THREAD_STATUS_WORKING:
#if VERBOSE_THREAD_LOG > 2
                    log_debug("thread: #%i [%x]: working: sending stop", i, tds[i]->id);
#endif
                    threaded_queue_enqueue(&tp->queue, NULL);
                    break;
                case THREAD_STATUS_WAITING:
#if VERBOSE_THREAD_LOG > 2
                    log_debug("thread: #%i [%x]: waiting: sending stop", i, tds[i]->id);
#endif
                    threaded_queue_enqueue(&tp->queue, NULL);
                    break;
                default:
#if VERBOSE_THREAD_LOG > 2
                    log_debug("thread: #%i [%x]: sending stop on %i status", i, tds[i]->id, tds[i]->status);
#endif
                    threaded_queue_enqueue(&tp->queue, NULL);
                    break;
            }
        }
        
       /*
        * I need to wait for each thread
        */

       for(i = new_size; i < tps; i++)
       {
           int err;

           /*
            * @NOTE: helgrind will complain here about a r/w race condition
            *        This is not a problem. The thread keeps its working status (in a volatile)
            *        And this loop only tries to wait if the status is not "done" yet.
            *
            * @TODO: look at PTHREAD_CREATE_JOINABLE
            */

           if(tds[i]->status != THREAD_STATUS_TERMINATING && tds[i]->status != THREAD_STATUS_TERMINATED)
           {
   #if VERBOSE_THREAD_LOG > 2
               log_debug("thread: #%i [%x]: waiting termination", i, tds[i]->id);
   #endif

               if((err = pthread_join(tds[i]->id, NULL)) != 0)
               {
   #if VERBOSE_THREAD_LOG > 3
                   log_debug("thread: error joining #%i [%x] %i %r", i, tds[i]->id, err, ERRNO_ERROR);
   #endif
               }
           }

           tds[i]->status = THREAD_STATUS_TERMINATED;

   #if VERBOSE_THREAD_LOG > 2
           log_debug("thread: #%i: terminated", i);
   #endif

           free(tds[i]);

           tds[i] = NULL;
       }
    }
    
    free(tds);
    tp->descriptors = thread_descriptors;
    tp->thread_pool_size = new_size;
    
    pthread_mutex_unlock(&tp->mtx);

    return new_size;
}

ya_result
thread_pool_destroy(struct thread_pool_s* tp)
{
    if(tp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    thread_descriptor_s** td;
    u8 tps = tp->thread_pool_size;
    u8 i;

    pthread_mutex_lock(&tp->mtx);
    td = tp->descriptors;
    tp->descriptors = NULL;
    pthread_mutex_unlock(&tp->mtx);

    if(td == NULL)
    {
#if VERBOSE_THREAD_LOG > 1
        log_debug("thread_pool_destroy called on a NULL set (already done)");
#endif
        return THREAD_DOUBLEDESTRUCTION_ERROR; /* double call */
    }
    
    mutex_lock(&thread_pool_set_mutex);
    u32_set_avl_delete(&thread_pool_set, tp->id);
    mutex_unlock(&thread_pool_set_mutex);

    tp->thread_pool_size = 0;

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
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_TERMINATED:
#if VERBOSE_THREAD_LOG > 1
                log_debug("thread: #%i [%x]: already terminated", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_WORKING:
#if VERBOSE_THREAD_LOG > 2
                log_debug("thread: #%i [%x]: working: sending stop", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_WAITING:
#if VERBOSE_THREAD_LOG > 2
                log_debug("thread: #%i [%x]: waiting: sending stop", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            default:
#if VERBOSE_THREAD_LOG > 2
                log_debug("thread: #%i [%x]: sending stop on %i status", i, td[i]->id, td[i]->status);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
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

        free(td[i]);

        td[i] = NULL;
    }

    free(td);

#if VERBOSE_THREAD_LOG > 2
    log_debug("thread: thread_pool_destroy: finalize");
#endif

    threaded_queue_finalize(&tp->queue);
    
    if(tp->pool_name != NULL)
    {
        free(tp->pool_name);
    }
    
    free(tp);

    return SUCCESS;
}

u8
thread_pool_get_pool_size(struct thread_pool_s* tp)
{
    return tp->thread_pool_size;
}


ya_result
thread_pool_stop_all()
{
    ya_result err = SUCCESS;

    mutex_lock(&thread_pool_set_mutex);    
    u32_set_avl_iterator iter;
    u32_set_avl_iterator_init(&thread_pool_set, &iter);
    while(u32_set_avl_iterator_hasnext(&iter))
    {
        u32_node *node = u32_set_avl_iterator_next_node(&iter);
        if(node->value != NULL)
        {
            thread_pool_s *tp = (thread_pool_s*)node->value;
            
            log_debug("stopping thread pool '%s'", STRNULL(tp->pool_name));
            
            if(FAIL(err = thread_pool_stop(tp)))
            {
                log_err("thread_pool_stop_all failed on '%s' with %r", STRNULL(tp->pool_name), err);
                break;
            }
        }
    }
    
    mutex_unlock(&thread_pool_set_mutex);
    
    return err;
}

ya_result
thread_pool_start_all()
{
    ya_result err = SUCCESS;
    
    mutex_lock(&thread_pool_set_mutex);
    
    u32_set_avl_iterator iter;
    u32_set_avl_iterator_init(&thread_pool_set, &iter);
    while(u32_set_avl_iterator_hasnext(&iter))
    {
        u32_node *node = u32_set_avl_iterator_next_node(&iter);
        if(node->value != NULL)
        {
            thread_pool_s *tp = (thread_pool_s*)node->value;
            
            log_debug("starting thread pool '%s'", STRNULL(tp->pool_name));
            
            if(FAIL(err = thread_pool_start(tp)))
            {
                log_err("thread_pool_start_all failed on '%s' with %r", STRNULL(tp->pool_name), err);
                break;
            }
        }
    }
    
    mutex_unlock(&thread_pool_set_mutex);
    
    return err;
}

/** @} */

/*----------------------------------------------------------------------------*/

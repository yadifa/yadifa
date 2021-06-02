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
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"

#if HAS_PTHREAD_SETNAME_NP
#if DEBUG
#define _GNU_SOURCE 1
#endif
#endif

#include <sys/types.h>
#include <unistd.h>

#include <dnscore/thread.h>
#include <sys/wait.h>

#define THREADED_QUEUE_MODE 6

#include "dnscore/threaded_queue.h"

#include "dnscore/thread_pool.h"
#include "dnscore/logger.h"
#include "dnscore/format.h"
#include "dnscore/u32_set.h"
#include "dnscore/zalloc.h"
#include "dnscore/process.h"
#include "dnscore/mutex.h"

// 0 = nothing, 1 = warns and worse, 2 = info and worse, 3 = debug and worse
#define VERBOSE_THREAD_LOG      3

// Enabling this will slow down the starting and stopping parts of the threads, testing only
#define THREADPOOL_DEBUG_SLOW_ARCH 0

// Disable when in release mode

#if !DEBUG
#undef VERBOSE_THREAD_LOG
#define VERBOSE_THREAD_LOG      0
#endif

#define MODULE_MSG_HANDLE		g_system_logger

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
    struct thread_pool_s *pool; //  8
    thread_t id;                //  8
    u32 index;                  //  4
    volatile u8 status;         //  1
    u8 reserved1;               //  1
    u16 reserved2;              //  2
    char info[16];              // 16
};

/* The array of thread descriptors*/

static thread_key_t thread_pool_random_key = ~0;
static thread_once_t thread_pool_random_key_once = PTHREAD_ONCE_INIT;

static mutex_t thread_pool_set_mutex = MUTEX_INITIALIZER;
static u32_set thread_pool_set = U32_SET_EMPTY;
static u32 thread_pool_id_next = 0;

#if DEBUG
static smp_int thread_pool_waiting = SMP_INT_INITIALIZER;
static smp_int thread_pool_running = SMP_INT_INITIALIZER;
#endif

#define THRDPOOL_TAG 0x4c4f4f5044524854

struct thread_pool_s
{
    mutex_t mtx;
    struct thread_descriptor_s **descriptors;
    threaded_queue queue;
    u32 thread_pool_size;
    u8 flags;
#if DEBUG
    volatile u8 created;
    volatile u8 destroying;
    volatile u8 destroyed;
#endif
    char *pool_name;

    u32 id;
};

typedef struct thread_pool_s thread_pool_s;

u32 g_max_thread_per_pool_limit = THREAD_POOL_SIZE_LIMIT_DEFAULT;

#if THREADPOOL_DEBUG_SLOW_ARCH

static void thread_pool_debug_slow_arch_wait()
{
    s64 now = timeus();
    s64 stop = now + 1000000 + (rand() & 0xfffff); // between about 1 to 2 seconds.
    do
    {
        s64 delta = stop - now;
        usleep(delta);
        now = timeus();
    }
    while(now < stop);
}

#endif

u32
thread_pool_get_max_thread_per_pool_limit()
{
    return g_max_thread_per_pool_limit;
}

u32
thread_pool_set_max_thread_per_pool_limit(u32 max_thread_per_pool_limit)
{
    if((max_thread_per_pool_limit >= THREAD_POOL_SIZE_LIMIT_MIN) && (max_thread_per_pool_limit <= THREAD_POOL_SIZE_LIMIT_MAX))
    {
        g_max_thread_per_pool_limit = max_thread_per_pool_limit;
    }

    return g_max_thread_per_pool_limit;
}

void
thread_pool_counter_init(thread_pool_task_counter *counter, s32 value)
{
    mutex_init(&counter->mutex);
    cond_init(&counter->cond);
    counter->value = value;
}

void
thread_pool_counter_destroy(thread_pool_task_counter *counter)
{
    cond_finalize(&counter->cond);
    mutex_destroy(&counter->mutex);
}

s32
thread_pool_counter_get_value(thread_pool_task_counter *counter)
{
    s32 ret;
    mutex_lock(&counter->mutex);
    ret = counter->value;
    mutex_unlock(&counter->mutex);
    return ret;
}

s32
thread_pool_counter_add_value(thread_pool_task_counter *counter, s32 value)
{
    s32 ret;
    mutex_lock(&counter->mutex);
    counter->value += value;
    ret = counter->value;
    cond_notify(&counter->cond);
    mutex_unlock(&counter->mutex);
    return ret;
}

s32
thread_pool_counter_wait_below_or_equal(thread_pool_task_counter *counter, s32 value)
{
    s32 ret;
    mutex_lock(&counter->mutex);
    for(;;)
    {
        ret = counter->value;
        if(ret <= value)
        {
            break;
        }
        cond_wait(&counter->cond, &counter->mutex);
    }
    mutex_unlock(&counter->mutex);
    return ret;
}

ya_result
thread_pool_counter_wait_equal(thread_pool_task_counter *counter, s32 value)
{
    mutex_lock(&counter->mutex);
    for(;;)
    {
        if(counter->value == value)
        {
            break;
        }
        cond_wait(&counter->cond, &counter->mutex);
    }
    mutex_unlock(&counter->mutex);
    return SUCCESS;
}

ya_result
thread_pool_counter_wait_equal_with_timeout(thread_pool_task_counter *counter, s32 value, u64 usec)
{
    s32 ret;
    s64 until = timeus() + usec;
    mutex_lock(&counter->mutex);
    for(;;)
    {
        if(counter->value == value)
        {
            ret = SUCCESS;
            break;
        }
        cond_timedwait(&counter->cond, &counter->mutex, usec);
        if(timeus() >= until)
        {
            ret = MAKE_ERRNO_ERROR(ETIMEDOUT);
            break;
        }
    }
    mutex_unlock(&counter->mutex);
    return ret;
}

static void
thread_pool_random_key_finalize(void *unused)
{
#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread: random thread-local key finalize");
#endif
    (void)unused;
}

static void
thread_pool_random_key_init()
{
#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread: random thread-local key init");
#endif

    ya_result ret;
    
    if((ret = thread_key_create(&thread_pool_random_key, thread_pool_random_key_finalize)) < 0)
    {
        log_quit("thread_key_create = %r", ret);
    }
}

int
thread_pool_queue_size(thread_pool_s *tp)
{
    int size = threaded_queue_size(&tp->queue);
    return size;
}

void
thread_pool_wait_queue_empty(struct thread_pool_s *tp)
{
    threaded_queue_wait_empty(&tp->queue);
}

static noreturn void*
thread_pool_thread(void *args)
{
    /*
     * Dequeue from the task queue
     * If what we got is NULL then it's time to stop
     * Else we run it
     */

    thread_descriptor_s* desc = (thread_descriptor_s*)args;

    threaded_queue *queue = &desc->pool->queue;

#if VERBOSE_THREAD_LOG >= 1
    thread_t id = desc->id;
#endif

#if THREADPOOL_DEBUG_SLOW_ARCH
    thread_pool_debug_slow_arch_wait();
#endif

    ya_result ret;

#if DNSCORE_HAS_LOG_THREAD_TAG
    char service_tag[9];
    memset(service_tag,'=', sizeof(service_tag) - 1);
    service_tag[sizeof(service_tag) - 1] = '\0';

    thread_make_tag(STRNULL(desc->pool->pool_name), desc->index, desc->pool->thread_pool_size, service_tag);
    logger_handle_set_thread_tag(service_tag);
#endif
    
#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread: %p (%i) %x started (pool '%s')", (void*)thread_self(), gettid(), desc->id, STRNULL(desc->pool->pool_name));
#endif

    if(thread_key_get(thread_pool_random_key) == NULL)
    {
        random_ctx rndctx = random_init_auto();
        
        if(FAIL(ret = thread_key_set(thread_pool_random_key, rndctx)))
        {
            log_quit("thread_key_set = %r", ret);
        }
    }   

#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread: %x random thread-local variable ready", desc->id);
#endif

    for(;;)
    {
#if HAS_PTHREAD_SETNAME_NP
        thread_set_name(desc->pool->pool_name, desc->index, desc->pool->thread_pool_size);
#endif
        
#if DEBUG
        smp_int_inc(&thread_pool_waiting);
#endif
        desc->status = THREAD_STATUS_WAITING;

        void* data = threaded_queue_dequeue(queue);

#if DEBUG
        smp_int_dec(&thread_pool_waiting);
#endif
        
        if(data == NULL)
        {        
#if VERBOSE_THREAD_LOG >= 1
            log_debug("thread: %x got terminate", id);
#endif

            desc->status = THREAD_STATUS_TERMINATING;
            break;
        }

        desc->status = THREAD_STATUS_WORKING;

        threaded_queue_task* task = (threaded_queue_task*)data;

        thread_pool_task_counter *counter = task->counter;
        thread_pool_function* function = task->function;
        void *parm = task->parm;
        const char *categoryname = task->categoryname;

        ZFREE_OBJECT(task);

        strcpy_ex(desc->info, categoryname, sizeof(desc->info));

        if(counter != NULL)
        {
            thread_pool_counter_add_value(counter, +1);
        }
#if VERBOSE_THREAD_LOG >= 3
        log_debug("thread: %x %s::%p(%p) begin", id, categoryname, function, parm);
#endif
        thread_set_name(desc->info, 0, 0);
#if DEBUG
        smp_int_inc(&thread_pool_running);
#endif  
        function(parm);
#if DEBUG
        smp_int_dec(&thread_pool_running);
#endif

#if VERBOSE_THREAD_LOG >= 3
        log_debug("thread: %x %s::%p(%p) end", id, categoryname, function, parm);
#endif
        if(counter != NULL)
        {
            thread_pool_counter_add_value(counter, -1);
        }

        memcpy(desc->info, "IDLE", 5);
    }

#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread: %x finalising random thread-local variable", desc->id);
#endif

    random_ctx rndctx = (random_ctx)thread_key_get(thread_pool_random_key);
    if(rndctx != NULL)
    {
        random_finalize(rndctx);
        thread_key_set(thread_pool_random_key, NULL);
    }

#if VERBOSE_THREAD_LOG >= 1
    log_debug("thread: %p (%i) %x stopped", (void*)thread_self(), gettid(), id);
#endif

#if THREADPOOL_DEBUG_SLOW_ARCH
    thread_pool_debug_slow_arch_wait();
#endif
    
#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_clear_thread_tag();
#endif

#if THREADPOOL_DEBUG_SLOW_ARCH
    thread_pool_debug_slow_arch_wait();
#endif
    
    thread_exit(NULL); // end of the thread from the pool

    // unreachable
    // return NULL;
}

random_ctx thread_pool_get_random_ctx()
{
    random_ctx rndctx = (random_ctx)thread_key_get(thread_pool_random_key);
    
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
#if DEBUG
    log_debug7("thread_pool_setup_random_ctx()", ERRNO_ERROR);
#endif

    ya_result ret;
    
    thread_once(&thread_pool_random_key_once, thread_pool_random_key_init);
    
    if(thread_key_get(thread_pool_random_key) == NULL)
    {
        random_ctx rndctx = random_init_auto();

        if(FAIL(ret = thread_key_set(thread_pool_random_key, rndctx)))
        {
            log_quit("thread_key_set = %r", ERRNO_ERROR);
        }
    }
}

void
thread_pool_destroy_random_ctx()
{
    random_ctx rndctx;

    ya_result ret;
    
#if DEBUG
    log_debug7("thread_pool_destroy_random_ctx()", ERRNO_ERROR);
#endif
    
    thread_once(&thread_pool_random_key_once, thread_pool_random_key_init);
    
    if((rndctx = thread_key_get(thread_pool_random_key)) != NULL)
    {
        random_finalize(rndctx);

        if(FAIL(ret = thread_key_set(thread_pool_random_key, NULL)))
        {
            log_quit("thread_key_set = %r", ret);
        }
    }
    else
    {
        log_warn("no random context for thread");
    }
}

static thread_descriptor_s*
thread_pool_create_thread(thread_pool_s *tp, int index)
{
    thread_descriptor_s *td = NULL;
    
    MALLOC_OBJECT_OR_DIE(td, thread_descriptor_s, THREADPOOL_TAG);    
    ZEROMEMORY(td, sizeof(thread_descriptor_s));

    td->pool = tp;
    td->status = THREAD_STATUS_STARTING;
    td->index = index;
    
    int ret;
    if((ret = thread_create(&td->id, thread_pool_thread, td)) != 0)
    {
        OSDEBUG(termerr, "thread_pool_set_pool_size: thread_create : oops: (%r) %s\n", ret, strerror(ret&0xffff));

        free(td);

        return NULL;
    }
    
    return td;
}

struct thread_pool_s*
thread_pool_init_ex(u32 thread_count, u32 queue_size, const char *pool_name)
{
#if VERBOSE_THREAD_LOG >= 1
    log_debug("thread_pool_init(%d, %d, %s)", thread_count, queue_size, STRNULL(pool_name));
#endif
    
    if((thread_count > g_max_thread_per_pool_limit) || (thread_count < THREAD_POOL_SIZE_LIMIT_MIN))
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
    MALLOC_OBJECT_OR_DIE(tp, thread_pool_s, THRDPOOL_TAG);
    ZEROMEMORY(tp, sizeof(thread_pool_s));
    
    tp->pool_name = strdup(pool_name);

    log_debug("thread-pool: '%s' init", pool_name);
 
    thread_descriptor_s** thread_descriptors;
    
    mutex_init(&tp->mtx);

    tp->thread_pool_size = thread_count;

    u16 i; /* thread creation loop counter */

    threaded_queue_init(&tp->queue, queue_size);

    MALLOC_OR_DIE(thread_descriptor_s**, thread_descriptors, thread_count * sizeof(thread_descriptor_s*), THREADPOOL_TAG);

    for(i = 0; i < thread_count; i++)
    {
        thread_descriptor_s *td;
        
        if((td = thread_pool_create_thread(tp, i)) == NULL)
        {
            log_err("thread-pool: '%s' failed to create thread #%i/%i", pool_name, i, thread_count);

            free(thread_descriptors);
            threaded_queue_finalize(&tp->queue);
            return NULL;
        }
        
        thread_descriptors[i] = td;
    }
    
    tp->descriptors = thread_descriptors;
    
    for(;;)
    {
        mutex_lock(&thread_pool_set_mutex);
        u32 id = thread_pool_id_next++;
        u32_node *node = u32_set_insert(&thread_pool_set, id);
        mutex_unlock(&thread_pool_set_mutex);
        
        if(node->value == NULL)
        {
            tp->id = id;
            node->value = tp;
            break;
        }
    }

#if DEBUG
    tp->created = (u8)rand() | 0x40;
    tp->destroying = 0;
    tp->destroyed = 0;
#endif

    log_debug("thread-pool: '%s' ready", pool_name);    

    return tp;
}

struct thread_pool_s*
thread_pool_init(u32 thread_count, u32 queue_size)
{
    struct thread_pool_s* tp = thread_pool_init_ex(thread_count, queue_size, NULL);
    
    return tp;
}

u32
thread_pool_get_size(struct thread_pool_s *tp)
{
    return tp->thread_pool_size;
}

#if DEBUG
static void
thread_pool_debug_dump(struct thread_pool_s* tp)
{
    struct thread_descriptor_s **d = tp->descriptors;
    u32 n = tp->thread_pool_size;
    u32 i = 0;
    while(n-- > 0)
    {
        log_debug("thread_pool_debug_dump %d, %x, %x, %s", i, d[i]->id, d[i]->status, d[i]->info);
        i++;
    }
}
#endif

/**
 * Enqueues a function to be executed by a thread pool
 * Do NOT use this function for concurrent producer-consumer spawning on the same pool as
 * you will end up with a situation where no slots are available for consumers and everybody is waiting.
 * Instead, when spawning a group, use thread_pool_enqueue_calls
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
    if(tp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

#if DEBUG
    if(tp->destroying == tp->created)
    {
        abort();
    }
    if(tp->destroyed == tp->created)
    {
        abort();
    }
#endif

#if DEBUG
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
    ZALLOC_OBJECT_OR_DIE( task, threaded_queue_task, THREADPOOL_TAG);

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

/**
 * Tries to enqueue a function to be executed by a thread pool
 * If the queue is not available (high concurrency or full), the function will give up and return ERROR.
 * 
 * @param tp            the thread pool
 * @param func          the function
 * @param parm          the parameter for the function
 * @param counter       an optional counter that will be incremented just before the function is called, and decremented just after
 * @param categoryname  an optional string that will be along the thread, mostly for debugging
 * 
 * @return SUCCESS if the call has been queued, ERROR if the queue was not available for pushing
 */

ya_result
thread_pool_try_enqueue_call(struct thread_pool_s* tp, thread_pool_function func, void* parm, thread_pool_task_counter *counter, const char* categoryname)
{
    if(tp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

#if DEBUG
    if(tp->destroying == tp->created)
    {
        abort();
    }
    if(tp->destroyed == tp->created)
    {
        abort();
    }
#endif

    threaded_queue_task* task;
    ZALLOC_OBJECT_OR_DIE(task, threaded_queue_task, THREADPOOL_TAG);

    task->function = func;
    task->parm = parm;
    task->counter = counter;

    if(categoryname == NULL)
    {
        categoryname = "anonymous";
    }
    
    task->categoryname = categoryname;
    
    if(threaded_queue_try_enqueue(&tp->queue, task))
    {
        return SUCCESS;
    }
    else
    {
        ZFREE_OBJECT(task);
        return LOCK_TIMEOUT;   // full
    }
}



ya_result
thread_pool_stop(struct thread_pool_s* tp)
{
    if(tp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

#if DEBUG
    if(tp->destroying == tp->created)
    {
        abort();
    }
    if(tp->destroyed == tp->created)
    {
        abort();
    }
#endif
    
    thread_descriptor_s** td;
    u32 tps = tp->thread_pool_size;
    u32 i;

    mutex_lock(&tp->mtx);
    td = tp->descriptors;
    mutex_unlock(&tp->mtx);

    if(td == NULL)
    {
#if VERBOSE_THREAD_LOG >= 1
        log_debug("thread_pool_stop called on a NULL set");
#endif
        return SERVICE_NOT_RUNNING;
    }
    
    if((tp->flags & THREADPOOL_FLAG_PAUSED) != 0)
    {
#if VERBOSE_THREAD_LOG >= 1
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
#if VERBOSE_THREAD_LOG >= 1
                log_debug("thread: #%i [%x]: already terminating", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_TERMINATED:
#if VERBOSE_THREAD_LOG >= 1
                log_debug("thread: #%i [%x]: already terminated", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_WORKING:
#if VERBOSE_THREAD_LOG >= 2
                log_debug("thread: #%i [%x]: working: sending stop", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_WAITING:
#if VERBOSE_THREAD_LOG >= 2
                log_debug("thread: #%i [%x]: waiting: sending stop", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            default:
#if VERBOSE_THREAD_LOG >= 2
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
         * @note  by default, threads are PTHREAD_CREATE_JOINABLE
         */

        if(td[i]->status != THREAD_STATUS_TERMINATING && td[i]->status != THREAD_STATUS_TERMINATED)
        {
#if VERBOSE_THREAD_LOG >= 2
            log_debug("thread: #%i [%x]: waiting termination", i, td[i]->id);
#endif

            if((err = thread_join(td[i]->id, NULL)) != 0)
            {
#if VERBOSE_THREAD_LOG >= 3
                log_debug("thread: error joining #%i [%x] %r (%x)", i, td[i]->id, err, err);
#endif
            }
        }

        td[i]->status = THREAD_STATUS_TERMINATED;

#if VERBOSE_THREAD_LOG >= 2
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

#if DEBUG
    if(tp->destroying == tp->created)
    {
        abort();
    }
    if(tp->destroyed == tp->created)
    {
        abort();
    }
#endif
    
    if((tp->flags & THREADPOOL_FLAG_PAUSED) == 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    thread_descriptor_s** thread_descriptors = tp->descriptors;
    u32 tps = tp->thread_pool_size;
    u32 i;
    
    if(thread_descriptors == NULL)
    {
#if VERBOSE_THREAD_LOG >= 1
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
         * @note  by default, threads are PTHREAD_CREATE_JOINABLE
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
        thread_descriptors[i]->index = tps;
        if((ret = thread_create(&thread_descriptors[i]->id, thread_pool_thread, thread_descriptors[i])) != 0)
        {
            return ret;
        }

#if VERBOSE_THREAD_LOG >= 2
        log_debug("thread: #%i: started again", i);
#endif
        // keep the descriptor for the resume
    }
    
    tp->flags &= ~THREADPOOL_FLAG_PAUSED;
        
    return SUCCESS;
}

ya_result
thread_pool_resize(struct thread_pool_s* tp, u32 new_size)
{
    if(tp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

#if DEBUG
    if(tp->destroying == tp->created)
    {
        abort();
    }
    if(tp->destroyed == tp->created)
    {
        abort();
    }
#endif

    if((new_size > g_max_thread_per_pool_limit) || (new_size < THREAD_POOL_SIZE_LIMIT_MIN))
    {
        return INVALID_ARGUMENT_ERROR;
    }
    
    mutex_lock(&tp->mtx);
    
    thread_descriptor_s** tds;
    u32 tps = tp->thread_pool_size;
    u32 i;
    
    if(tps == new_size)
    {
        // nothing to do
        
        mutex_unlock(&tp->mtx);        
        return tps;
    }
    
    tds = tp->descriptors;
    tp->descriptors = NULL;
    
    // allocate a new struct, reuse thestructs
    
    thread_descriptor_s** thread_descriptors;
    MALLOC_OR_DIE(thread_descriptor_s**, thread_descriptors, sizeof(thread_descriptor_s*) * new_size, THREADPOOL_TAG);
    
    // if grow
    
    if(new_size > tps)
    {
        // copy the current ones
        
        memcpy(thread_descriptors, tds, sizeof(thread_descriptor_s*) * tps);
        
        // create new threads [tps;new_size[
        
        for(i = tps; i < new_size; i++)
        {
            thread_descriptor_s *td;

            if((td = thread_pool_create_thread(tp, i)) == NULL)
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

                mutex_unlock(&tp->mtx);

                return new_size;
            }

            thread_descriptors[i] = td; // VS false positive (nonsense)
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
#if VERBOSE_THREAD_LOG >= 1
                    log_debug("thread: #%i [%x]: already terminating", i, tds[i]->id);
#endif
                    threaded_queue_enqueue(&tp->queue, NULL);
                    break;
                case THREAD_STATUS_TERMINATED:
#if VERBOSE_THREAD_LOG >= 1
                    log_debug("thread: #%i [%x]: already terminated", i, tds[i]->id);
#endif
                    threaded_queue_enqueue(&tp->queue, NULL);
                    break;
                case THREAD_STATUS_WORKING:
#if VERBOSE_THREAD_LOG >= 2
                    log_debug("thread: #%i [%x]: working: sending stop", i, tds[i]->id);
#endif
                    threaded_queue_enqueue(&tp->queue, NULL);
                    break;
                case THREAD_STATUS_WAITING:
#if VERBOSE_THREAD_LOG >= 2
                    log_debug("thread: #%i [%x]: waiting: sending stop", i, tds[i]->id);
#endif
                    threaded_queue_enqueue(&tp->queue, NULL);
                    break;
                default:
#if VERBOSE_THREAD_LOG >= 2
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
            * @note  by default, threads are PTHREAD_CREATE_JOINABLE
            */

           if(tds[i]->status != THREAD_STATUS_TERMINATING && tds[i]->status != THREAD_STATUS_TERMINATED)
           {
   #if VERBOSE_THREAD_LOG >= 2
               log_debug("thread: #%i [%x]: waiting termination", i, tds[i]->id);
   #endif

               if((err = thread_join(tds[i]->id, NULL)) != 0)
               {
   #if VERBOSE_THREAD_LOG >= 3
                   log_debug("thread: error joining #%i [%x] %r %x", i, tds[i]->id, err, err);
   #endif
               }
           }

           tds[i]->status = THREAD_STATUS_TERMINATED;

   #if VERBOSE_THREAD_LOG >= 2
           log_debug("thread: #%i: terminated", i);
   #endif

           free(tds[i]);

           tds[i] = NULL;
       }
    }
    
    free(tds);
    tp->descriptors = thread_descriptors;
    tp->thread_pool_size = new_size;
    
    mutex_unlock(&tp->mtx);

    return new_size;
}

ya_result
thread_pool_destroy(struct thread_pool_s* tp)
{
    if(tp == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

#if DEBUG
    if(tp->destroying == tp->created)
    {
        abort();
    }
    if(tp->destroyed == tp->created)
    {
        abort();
    }

    tp->destroying = tp->created;
#endif

    thread_descriptor_s** td;
    u32 tps = tp->thread_pool_size;
    u32 i;

    mutex_lock(&tp->mtx);
    td = tp->descriptors;
    tp->descriptors = NULL;
    mutex_unlock(&tp->mtx);

    if(td == NULL)
    {
#if VERBOSE_THREAD_LOG >= 1
        log_debug("thread_pool_destroy called on a NULL set (already done)");
#endif
        return THREAD_DOUBLEDESTRUCTION_ERROR; /* double call */
    }
    
    mutex_lock(&thread_pool_set_mutex);
    u32_set_delete(&thread_pool_set, tp->id);
    mutex_unlock(&thread_pool_set_mutex);

    tp->thread_pool_size = 0;

    /*
     * Sending a node with data == NULL will kill one thread-pool thread
     *
     * I have to launch one for each thread.
     */

    for(i = 0; i < tps; i++)
    {
        threaded_queue_wait_empty(&tp->queue);

        switch(td[i]->status) /* Unimportant W -> R race */
        {
            case THREAD_STATUS_TERMINATING:
#if VERBOSE_THREAD_LOG >= 1
                log_debug("thread: #%i [%x]: already terminating", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_TERMINATED:
#if VERBOSE_THREAD_LOG >= 1
                log_debug("thread: #%i [%x]: already terminated", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_WORKING:
#if VERBOSE_THREAD_LOG >= 2
                log_debug("thread: #%i [%x]: working: sending stop", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            case THREAD_STATUS_WAITING:
#if VERBOSE_THREAD_LOG >= 2
                log_debug("thread: #%i [%x]: waiting: sending stop", i, td[i]->id);
#endif
                threaded_queue_enqueue(&tp->queue, NULL);
                break;
            default:
#if VERBOSE_THREAD_LOG >= 2
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
         * @note  by default, threads are PTHREAD_CREATE_JOINABLE
         */

        //if(td[i]->status != THREAD_STATUS_TERMINATING && td[i]->status != THREAD_STATUS_TERMINATED)
        {
#if VERBOSE_THREAD_LOG >= 2
            log_debug("thread: #%i [%x]: waiting termination", i, td[i]->id);
#endif

            if((err = thread_join(td[i]->id, NULL)) != 0)
            {
                log_err("thread: error joining #%i [%x] %r %x", i, td[i]->id, err, err);
                logger_flush();
            }
        }

        td[i]->status = THREAD_STATUS_TERMINATED;

#if VERBOSE_THREAD_LOG >= 2
        log_debug("thread: #%i: terminated", i);
#endif

        free(td[i]);

        td[i] = NULL;
    }

    free(td);

#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread: thread_pool_destroy: finalize");
#endif

    threaded_queue_finalize(&tp->queue);

    if(tp->pool_name != NULL)
    {
        free(tp->pool_name);
    }

#if DEBUG
    tp->destroyed = tp->created;
#endif

    free(tp);

    return SUCCESS;
}

ya_result
thread_pool_stop_all()
{
    ya_result err = SUCCESS;

    mutex_lock(&thread_pool_set_mutex);    
    u32_set_iterator iter;
    u32_set_iterator_init(&thread_pool_set, &iter);
    while(u32_set_iterator_hasnext(&iter))
    {
        u32_node *node = u32_set_iterator_next_node(&iter);
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
    
    u32_set_iterator iter;
    u32_set_iterator_init(&thread_pool_set, &iter);
    while(u32_set_iterator_hasnext(&iter))
    {
        u32_node *node = u32_set_iterator_next_node(&iter);
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

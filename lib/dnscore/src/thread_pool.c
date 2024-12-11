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

/**-----------------------------------------------------------------------------
 * @defgroup threading Threading, pools, queues, ...
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"

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
#include "dnscore/u32_treemap.h"
#include "dnscore/zalloc.h"
#include "dnscore/process.h"
#include "dnscore/mutex.h"

// 0 = nothing, 1 = warns and worse, 2 = info and worse, 3 = debug and worse
#define VERBOSE_THREAD_LOG         0

// Enabling this will slow down the starting and stopping parts of the threads, testing only
#define THREADPOOL_DEBUG_SLOW_ARCH 0

// Disable when in release mode

#if !DEBUG
#undef VERBOSE_THREAD_LOG
#define VERBOSE_THREAD_LOG 0
#endif

#define MODULE_MSG_HANDLE            g_system_logger

#define THREADPOOL_TAG               0x4c4f4f5044524854 /* THRDPOOL */

#define THREADPOOL_QUEUE_SIZE_FACTOR 4096 /* 2 */

#define THREADPOOL_FLAG_PAUSED       1

struct threaded_queue_task_s
{
    thread_pool_function_t     *function;
    void                       *parm;
    thread_pool_task_counter_t *counter;

    const char                 *categoryname; /* so it's easy to know what thread is running*/
};

typedef struct threaded_queue_task_s threaded_queue_task_t;

struct thread_descriptor_s
{
    struct thread_pool_s *pool;      //  8
    thread_t              id;        //  8
    uint32_t              index;     //  4
    atomic_uchar          status;    //  1
    uint8_t               reserved1; //  1
    uint16_t              reserved2; //  2
    char                  info[16];  // 16
};

typedef struct thread_descriptor_s thread_descriptor_t;

/* The array of thread descriptors*/

static thread_key_t  thread_pool_random_key = ~0;
static thread_once_t thread_pool_random_key_once = PTHREAD_ONCE_INIT;

static thread_key_t  thread_pool_thread_index_key = ~0;
static thread_once_t thread_pool_thread_index_key_once = PTHREAD_ONCE_INIT;

static mutex_t       thread_pool_set_mutex = MUTEX_INITIALIZER;
static u32_treemap_t thread_pool_set = U32_TREEMAP_EMPTY;
static uint32_t      thread_pool_id_next = 0;

#if DEBUG
static smp_int thread_pool_waiting = SMP_INT_INITIALIZER;
static smp_int thread_pool_running = SMP_INT_INITIALIZER;
#endif

#define THRDPOOL_TAG 0x4c4f4f5044524854

struct thread_pool_s
{
    mutex_t                      mtx;
    struct thread_descriptor_s **descriptors;
    threaded_queue               queue;
    uint32_t                     thread_pool_size;
    uint8_t                      flags;
#if DEBUG
    volatile uint8_t created;
    volatile uint8_t destroying;
    volatile uint8_t destroyed;
#endif
    char    *pool_name;

    uint32_t id;
};

typedef struct thread_pool_s thread_pool_s;

uint32_t                     g_max_thread_per_pool_limit = THREAD_POOL_SIZE_LIMIT_DEFAULT;

#if THREADPOOL_DEBUG_SLOW_ARCH

static void thread_pool_debug_slow_arch_wait()
{
    int64_t now = timeus();
    int64_t stop = now + 1000000 + (rand() & 0xfffff); // between about 1 to 2 seconds.
    do
    {
        int64_t delta = stop - now;
        usleep(delta);
        now = timeus();
    } while(now < stop);
}

#endif

uint32_t thread_pool_get_max_thread_per_pool_limit() { return g_max_thread_per_pool_limit; }

uint32_t thread_pool_set_max_thread_per_pool_limit(uint32_t max_thread_per_pool_limit)
{
    if((max_thread_per_pool_limit >= THREAD_POOL_SIZE_LIMIT_MIN) && (max_thread_per_pool_limit <= THREAD_POOL_SIZE_LIMIT_MAX))
    {
        g_max_thread_per_pool_limit = max_thread_per_pool_limit;
    }

    return g_max_thread_per_pool_limit;
}

void thread_pool_counter_init(thread_pool_task_counter_t *counter, int32_t value)
{
    mutex_init(&counter->mutex);
    cond_init(&counter->cond);
    counter->value = value;
}

void thread_pool_counter_finalise(thread_pool_task_counter_t *counter)
{
    cond_finalize(&counter->cond);
    mutex_destroy(&counter->mutex);
}

int32_t thread_pool_counter_get_value(thread_pool_task_counter_t *counter)
{
    int32_t ret;
    mutex_lock(&counter->mutex);
    ret = counter->value;
    mutex_unlock(&counter->mutex);
    return ret;
}

int32_t thread_pool_counter_add_value(thread_pool_task_counter_t *counter, int32_t value)
{
    int32_t ret;
    mutex_lock(&counter->mutex);
    counter->value += value;
    ret = counter->value;
    cond_notify(&counter->cond);
    mutex_unlock(&counter->mutex);
    return ret;
}

int32_t thread_pool_counter_wait_below_or_equal(thread_pool_task_counter_t *counter, int32_t value)
{
    int32_t ret;
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

ya_result thread_pool_counter_wait_equal(thread_pool_task_counter_t *counter, int32_t value)
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

ya_result thread_pool_counter_wait_equal_with_timeout(thread_pool_task_counter_t *counter, int32_t value, uint64_t usec)
{
    int32_t ret;
    int64_t until = timeus() + usec;
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

static void thread_pool_random_key_finalize(void *unused)
{
#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread-pool: thread: random thread-local key finalize");
#endif
    (void)unused;
}

static void thread_pool_random_key_init(void)
{
#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread-pool: thread: random thread-local key init");
#endif

    ya_result ret;

    if((ret = thread_key_create(&thread_pool_random_key, thread_pool_random_key_finalize)) < 0)
    {
        log_quit("thread_key_create = %r", ret);
    }
}

static void thread_pool_thread_index_init(void)
{
#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread-pool: thread: random thread-local key init");
#endif

    ya_result ret;

    if((ret = thread_key_create(&thread_pool_thread_index_key, NULL)) < 0)
    {
        log_quit("thread_key_create = %r", ret);
    }
}

int thread_pool_queue_size(thread_pool_s *tp)
{
    int size = threaded_queue_size(&tp->queue);
    return size;
}

void     thread_pool_wait_queue_empty(struct thread_pool_s *tp) { threaded_queue_wait_empty(&tp->queue); }

uint32_t thread_pool_thread_index_get()
{
    uint32_t *idp = (uint32_t *)thread_key_get(thread_pool_thread_index_key);

    if(idp != NULL)
    {
        return *idp;
    }
    else
    {
        return U32_MAX;
    }
}

static /*_Noreturn*/ void *thread_pool_thread(void *args)
{
    /*
     * Dequeue from the task queue
     * If what we got is NULL then it's time to stop
     * Else we run it
     */

    thread_descriptor_t *desc = (thread_descriptor_t *)args;
    threaded_queue      *queue = &desc->pool->queue;

#if THREADPOOL_DEBUG_SLOW_ARCH
    thread_pool_debug_slow_arch_wait();
#endif

    ya_result ret;

#if DNSCORE_HAS_LOG_THREAD_TAG
    char service_tag[9];
    memset(service_tag, '=', sizeof(service_tag) - 1);
    service_tag[sizeof(service_tag) - 1] = '\0';

    thread_make_tag(STRNULL(desc->pool->pool_name), desc->index, desc->pool->thread_pool_size, service_tag);
    logger_handle_set_thread_tag(service_tag);
#endif

#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread-pool-thread: %s: #%i [%llx] %p (%i) started (pool '%s')", STRNULL(desc->pool->pool_name), desc->index, desc->id, (void *)thread_self(), gettid(), STRNULL(desc->pool->pool_name));
#endif

    if(thread_key_get(thread_pool_random_key) == NULL)
    {
        random_ctx_t rndctx = random_init_auto();

        if(FAIL(ret = thread_key_set(thread_pool_random_key, rndctx)))
        {
            log_quit("thread_key_set(thread_pool_random_key) = %r", ret);
        }
    }

    if(thread_key_get(thread_pool_thread_index_key) == NULL)
    {
        if(FAIL(ret = thread_key_set(thread_pool_thread_index_key, &desc->index)))
        {
            log_quit("thread_key_set(thread_pool_thread_index_key) = %r", ret);
        }
    }

#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread-pool-thread: %s: #%i [%llx] random thread-local variable ready", STRNULL(desc->pool->pool_name), desc->index, desc->id);
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

        void *data = threaded_queue_dequeue(queue);

#if DEBUG
        smp_int_dec(&thread_pool_waiting);
#endif

        if(data == NULL)
        {
#if VERBOSE_THREAD_LOG >= 1
            log_debug("thread-pool-thread: %s: #%i [%llx] got terminate", STRNULL(desc->pool->pool_name), desc->index, desc->id);
#endif

            desc->status = THREAD_STATUS_TERMINATING;
            break;
        }

        desc->status = THREAD_STATUS_WORKING;

        threaded_queue_task_t      *task = data;

        thread_pool_task_counter_t *counter = task->counter;
        thread_pool_function_t     *function = task->function;
        void                       *parm = task->parm;
        const char                 *categoryname = task->categoryname;

        ZFREE_OBJECT(task);

        strcpy_ex(desc->info, categoryname, sizeof(desc->info));

        if(counter != NULL)
        {
            thread_pool_counter_add_value(counter, +1);
        }
#if VERBOSE_THREAD_LOG >= 3
        log_debug("thread-pool-thread: %s: #%i [%llx] %s::%p(%p) begin", STRNULL(desc->pool->pool_name), desc->index, desc->id, categoryname, function, parm);
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
        log_debug("thread-pool-thread: %s: #%i [%llx] %s::%p(%p) end", STRNULL(desc->pool->pool_name), desc->index, desc->id, categoryname, function, parm);
#endif
        if(counter != NULL)
        {
            thread_pool_counter_add_value(counter, -1);
        }

        memcpy(desc->info, "IDLE", 5);
    }

#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread-pool-thread: %s: #%i [%llx] finalising random thread-local variable", STRNULL(desc->pool->pool_name), desc->index, desc->id);
#endif

    random_ctx_t rndctx = (random_ctx_t)thread_key_get(thread_pool_random_key);
    if(rndctx != NULL)
    {
        random_finalize(rndctx);
        thread_key_set(thread_pool_random_key, NULL);
    }

#if VERBOSE_THREAD_LOG >= 1
    log_debug("thread-pool-thread: %s: #%i [%llx] stopped", STRNULL(desc->pool->pool_name), desc->index, desc->id);
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
    return NULL;
}

random_ctx_t thread_pool_get_random_ctx()
{
    random_ctx_t rndctx = (random_ctx_t)thread_key_get(thread_pool_random_key);

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
#if DEBUG
    log_debug7("thread_pool_setup_random_ctx()", ERRNO_ERROR);
#endif

    ya_result ret;

    thread_once(&thread_pool_random_key_once, thread_pool_random_key_init);

    if(thread_key_get(thread_pool_random_key) == NULL)
    {
        random_ctx_t rndctx = random_init_auto();

        if(FAIL(ret = thread_key_set(thread_pool_random_key, rndctx)))
        {
            log_quit("thread_key_set = %r", ERRNO_ERROR);
        }
    }
}

void thread_pool_destroy_random_ctx()
{
    random_ctx_t rndctx;

    ya_result    ret;

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

static thread_descriptor_t *thread_pool_create_thread(thread_pool_s *tp, int index)
{
    thread_descriptor_t *td = NULL;

    MALLOC_OBJECT_OR_DIE(td, thread_descriptor_t, THREADPOOL_TAG);
    ZEROMEMORY(td, sizeof(thread_descriptor_t));

    td->pool = tp;
    td->status = THREAD_STATUS_STARTING;
    td->index = index;

    int ret;
    if((ret = thread_create(&td->id, thread_pool_thread, td)) != 0)
    {
        osformatln(termerr, "thread_pool_set_pool_size: thread_create failed: (%r) %s\n", ret, strerror(ret & 0xffff));

        free(td);

        return NULL;
    }

    return td;
}

struct thread_pool_s *thread_pool_init_ex(uint32_t thread_count, uint32_t queue_size, const char *pool_name)
{
#if VERBOSE_THREAD_LOG >= 1
    log_debug("thread_pool_init_ex(%d, %d, %s)", thread_count, queue_size, STRNULL(pool_name));
#endif

    if((thread_count > g_max_thread_per_pool_limit) || (thread_count < THREAD_POOL_SIZE_LIMIT_MIN))
    {
        return NULL;
    }

    thread_once(&thread_pool_thread_index_key_once, thread_pool_thread_index_init);

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

    log_debug("thread-pool: %s: init", pool_name);

    thread_descriptor_t **thread_descriptors;

    mutex_init(&tp->mtx);

    tp->thread_pool_size = thread_count;

    uint16_t i; /* thread creation loop counter */

    threaded_queue_init(&tp->queue, queue_size);

    MALLOC_OR_DIE(thread_descriptor_t **, thread_descriptors, thread_count * sizeof(thread_descriptor_t *), THREADPOOL_TAG);

    for(i = 0; i < thread_count; i++)
    {
        thread_descriptor_t *td;

        if((td = thread_pool_create_thread(tp, i)) == NULL)
        {
            log_err("thread-pool: %s: failed to create thread #%i/%i", pool_name, i, thread_count);

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
        uint32_t            id = thread_pool_id_next++;
        u32_treemap_node_t *node = u32_treemap_insert(&thread_pool_set, id);
        mutex_unlock(&thread_pool_set_mutex);

        if(node->value == NULL)
        {
            tp->id = id;
            node->value = tp;
            break;
        }
    }

#if DEBUG
    tp->created = (uint8_t)rand() | 0x40;
    tp->destroying = 0;
    tp->destroyed = 0;
#endif

    log_debug("thread-pool: %s: ready", pool_name);

    return tp;
}

struct thread_pool_s *thread_pool_init(uint32_t thread_count, uint32_t queue_size)
{
    struct thread_pool_s *tp = thread_pool_init_ex(thread_count, queue_size, NULL);

    return tp;
}

uint32_t thread_pool_get_size(struct thread_pool_s *tp) { return tp->thread_pool_size; }

#if DEBUG
static void thread_pool_debug_dump(struct thread_pool_s *tp)
{
    thread_descriptor_t **d = tp->descriptors;
    uint32_t              n = tp->thread_pool_size;
    uint32_t              i = 0;
    while(n-- > 0)
    {
        log_debug("thread_pool_debug_dump %d, %llx, %x, %s", i, d[i]->id, d[i]->status, d[i]->info);
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
 * @param counter       an optional counter that will be incremented just before the function is called, and decremented
 * just after
 * @param categoryname  an optional string that will be along the thread, mostly for debugging
 *
 * @return SUCCESS
 */

ya_result thread_pool_enqueue_call(struct thread_pool_s *tp, thread_pool_function_t func, void *parm, thread_pool_task_counter_t *counter, const char *categoryname)
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

    log_debug("thread_pool_enqueue_call(%p \"%s\", %p, %p, %p, \"%s\"), queue size = %d+1, wait=%d, run=%d", tp, STRNULL(tp->pool_name), func, parm, counter, STRNULL(categoryname), threaded_queue_size(&tp->queue), waiting, running);

    static uint32_t last_dump_time = 0;
    uint32_t        now = time(NULL);

    if(now - last_dump_time > 30)
    {
        thread_pool_debug_dump(tp);
        last_dump_time = now;
    }

#endif

    threaded_queue_task_t *task;
    ZALLOC_OBJECT_OR_DIE(task, threaded_queue_task_t, THREADPOOL_TAG);

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
 * @param counter       an optional counter that will be incremented just before the function is called, and decremented
 * just after
 * @param categoryname  an optional string that will be along the thread, mostly for debugging
 *
 * @return SUCCESS if the call has been queued, ERROR if the queue was not available for pushing
 */

ya_result thread_pool_try_enqueue_call(struct thread_pool_s *tp, thread_pool_function_t func, void *parm, thread_pool_task_counter_t *counter, const char *categoryname)
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

    threaded_queue_task_t *task;
    ZALLOC_OBJECT_OR_DIE(task, threaded_queue_task_t, THREADPOOL_TAG);

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
        return LOCK_TIMEOUT; // full
    }
}

static ya_result thread_pool_stop_ex(struct thread_pool_s *tp, bool destroying)
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

    if(destroying)
    {
        tp->destroying = tp->created;
    }
#endif

    thread_descriptor_t **td;
    uint32_t              tps = tp->thread_pool_size;
    uint32_t              i;

    mutex_lock(&tp->mtx);
    td = tp->descriptors;
    if(destroying)
    {
        // do NOT : free(tp->descriptors);
        tp->descriptors = NULL;
    }
    mutex_unlock(&tp->mtx);

    if(td == NULL)
    {
#if VERBOSE_THREAD_LOG >= 1
        log_debug("thread_pool_stop_ex(%p \"%s\", %i) called on a NULL set", tp, STRNULL(tp->pool_name), destroying);
#endif
        return SERVICE_NOT_RUNNING;
    }

    if((tp->flags & THREADPOOL_FLAG_PAUSED) != 0)
    {
#if VERBOSE_THREAD_LOG >= 1
        log_debug("thread_pool_stop_ex(%p \"%s\", %i) called on a NULL set", tp, STRNULL(tp->pool_name), destroying);
#endif
        return SERVICE_ALREADY_PAUSED;
    }

    /*
     * Sending a node with data == NULL will kill one thread
     *
     * I have to launch one for each thread.
     */

    int64_t thread_pool_stop_report_time = timeus();

    // send NULLs to relevant threads

    int null_send_count = 0;

    for(i = 0; i < tps; i++)
    {
        int64_t now = timeus();
        if(now - thread_pool_stop_report_time > ONE_SECOND_US)
        {
            log_info("thread-pool: %s: busy stopping thread %i/%i", STRNULL(tp->pool_name), i + 1, tps);
            thread_pool_stop_report_time = now;
        }

        uint8_t td_status = td[i]->status;

        switch(td_status) /* Unimportant W -> R race */
        {
            case THREAD_STATUS_TERMINATING:
#if VERBOSE_THREAD_LOG >= 1
                log_debug("thread-pool: %s: thread: #%i [%llx]: already terminating", STRNULL(tp->pool_name), i, td[i]->id);
#endif
                // no need to wake it up
                break;
            case THREAD_STATUS_TERMINATED:
#if VERBOSE_THREAD_LOG >= 1
                log_debug("thread-pool: %s: thread: #%i [%llx]: already terminated", STRNULL(tp->pool_name), i, td[i]->id);
#endif
                // no need to wake it up
                break;
            case THREAD_STATUS_WORKING:
#if VERBOSE_THREAD_LOG >= 2
                log_debug("thread-pool: %s: thread: #%i [%llx]: working, sending stop", STRNULL(tp->pool_name), i, td[i]->id);
#endif
                ++null_send_count;
                break;
            case THREAD_STATUS_WAITING:
#if VERBOSE_THREAD_LOG >= 2
                log_debug("thread-pool: %s: thread: #%i [%llx]: waiting, sending stop", STRNULL(tp->pool_name), i, td[i]->id);
#endif
                ++null_send_count;
                break;
            default:
#if VERBOSE_THREAD_LOG >= 2
                log_debug("thread-pool: %s: thread: #%i [%llx]: status=%i, sending stop", STRNULL(tp->pool_name), i, td[i]->id, td_status);
#endif
                ++null_send_count;
                break;
        }
    }

    log_debug("thread-pool: %s: sending %i stop messages", STRNULL(tp->pool_name), null_send_count);

    while(null_send_count > 0)
    {
        threaded_queue_enqueue(&tp->queue, NULL);
        --null_send_count;
    }

    // wait for each thread to stop

    for(i = 0; i < tps; i++)
    {
#if VERBOSE_THREAD_LOG >= 3
        int err;
#endif

#if VERBOSE_THREAD_LOG >= 2
        log_debug("thread-pool: %s: thread: #%i [%llx]: waiting termination", STRNULL(tp->pool_name), i, td[i]->id);
#endif

        if((
#if VERBOSE_THREAD_LOG >= 3
               err =
#endif
                   thread_join(td[i]->id, NULL)) != 0)
        {
#if VERBOSE_THREAD_LOG >= 3
            log_debug("thread-pool: %s: thread: error joining #%i [%llx] %r (%x)", STRNULL(tp->pool_name), i, td[i]->id, err, err);
#endif
        }

        td[i]->status = THREAD_STATUS_TERMINATED;

#if VERBOSE_THREAD_LOG >= 2
        log_debug("thread-pool: %s: thread: #%i: stopped", STRNULL(tp->pool_name), i);
#endif
        // keep the descriptor for the resume

        if(destroying)
        {
            free(td[i]);
        }
    }

    if(destroying)
    {
        free(td);
    }

    return SUCCESS;
}

ya_result thread_pool_stop(struct thread_pool_s *tp)
{
    ya_result ret;
    if(ISOK(ret = thread_pool_stop_ex(tp, false)))
    {
        tp->flags |= THREADPOOL_FLAG_PAUSED;
    }
    return ret;
}

static ya_result thread_pool_start(struct thread_pool_s *tp)
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

    thread_descriptor_t **thread_descriptors = tp->descriptors;
    uint32_t              tps = tp->thread_pool_size;
    uint32_t              i;

    if(thread_descriptors == NULL)
    {
#if VERBOSE_THREAD_LOG >= 1
        log_debug("thread_pool_start called on a NULL set");
#endif
        return SERVICE_NOT_RUNNING;
    }

    int64_t thread_pool_start_report_time = timeus();

    for(i = 0; i < tps; i++)
    {
        /*
         * @NOTE: helgrind will complain here about a r/w race condition
         *        This is not a problem. The thread keeps its working status (in a volatile)
         *        And this loop only tries to wait if the status is not "done" yet.
         *
         * @note  by default, threads are PTHREAD_CREATE_JOINABLE
         */

        int64_t now = timeus();
        if(now - thread_pool_start_report_time > ONE_SECOND_US)
        {
            log_info("thread-pool: %s: busy starting thread %i/%i", STRNULL(tp->pool_name), i + 1, tps);
            thread_pool_start_report_time = now;
        }

        uint8_t status = thread_descriptors[i]->status;

        switch(status)
        {
            case THREAD_STATUS_TERMINATING:
            case THREAD_STATUS_TERMINATED:
                // all good
                break;
            default:
                log_err("thread-pool: %s: start called but has status %hhu", STRNULL(tp->pool_name), status);
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
        log_debug("thread-pool: %s: thread: #%i: started again", STRNULL(tp->pool_name), i);
#endif
        // keep the descriptor for the resume
    }

    tp->flags &= ~THREADPOOL_FLAG_PAUSED;

    return SUCCESS;
}

ya_result thread_pool_resize(struct thread_pool_s *tp, uint32_t new_thread_pool_size)
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

    if((new_thread_pool_size > g_max_thread_per_pool_limit) || (new_thread_pool_size < THREAD_POOL_SIZE_LIMIT_MIN))
    {
        return INVALID_ARGUMENT_ERROR;
    }

    mutex_lock(&tp->mtx);

    thread_descriptor_t **thread_descriptors;
    uint32_t              thread_pool_size = tp->thread_pool_size;
    uint32_t              i;

    if(new_thread_pool_size <= thread_pool_size)
    {
        // nothing to do

        mutex_unlock(&tp->mtx);
        return thread_pool_size;
    }

    thread_descriptors = tp->descriptors;
    tp->descriptors = NULL;

    // allocate a new struct, reuse thestructs

    thread_descriptor_t **new_thread_descriptors;
    MALLOC_OR_DIE(thread_descriptor_t **, new_thread_descriptors, sizeof(thread_descriptor_t *) * new_thread_pool_size, THREADPOOL_TAG);

    // if grow

    if(new_thread_pool_size > thread_pool_size)
    {
        // copy the current ones

        memcpy(new_thread_descriptors, thread_descriptors, sizeof(thread_descriptor_t *) * thread_pool_size);

        // create new threads [tps;new_size[

        for(i = thread_pool_size; i < new_thread_pool_size; i++)
        {
            thread_descriptor_t *td;

            if((td = thread_pool_create_thread(tp, i)) == NULL)
            {
                // failed to allocate one thread ...
                // it's bad.  keep what we have.

                log_err("thread_pool: could not resize from %u to %u, cutting at %u", thread_pool_size, new_thread_pool_size, i - 1);
                logger_flush();

                if(i == thread_pool_size)
                {
                    free(new_thread_descriptors);
                    new_thread_descriptors = thread_descriptors;
                    new_thread_pool_size = thread_pool_size;
                }
                else
                {
                    free(thread_descriptors);
                    new_thread_pool_size = i - 1;
                }

                tp->descriptors = new_thread_descriptors;
                tp->thread_pool_size = new_thread_pool_size;

                mutex_unlock(&tp->mtx);

                return new_thread_pool_size;
            }

            new_thread_descriptors[i] = td; // VS false positive (nonsense)
        }
    }

    free(thread_descriptors);
    tp->descriptors = new_thread_descriptors;
    tp->thread_pool_size = new_thread_pool_size;

    mutex_unlock(&tp->mtx);

    return new_thread_pool_size;
}

ya_result thread_pool_finalise(struct thread_pool_s *tp)
{
    ya_result ret;
    if(FAIL(ret = thread_pool_stop_ex(tp, true)))
    {
        if(ret == SERVICE_NOT_RUNNING)
        {
            ret = THREAD_DOUBLEDESTRUCTION_ERROR; /* double call */
        }
        return ret;
    }

    // all the threads are stopped

    mutex_lock(&thread_pool_set_mutex);
    u32_treemap_delete(&thread_pool_set, tp->id);
    mutex_unlock(&thread_pool_set_mutex);
    tp->thread_pool_size = 0;

#if VERBOSE_THREAD_LOG >= 2
    log_debug("thread-pool: %s: thread: thread_pool_destroy: finalize", STRNULL(tp->pool_name));
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

ya_result thread_pool_stop_all()
{
    ya_result err = SUCCESS;

    mutex_lock(&thread_pool_set_mutex);
    u32_treemap_iterator_t iter;
    u32_treemap_iterator_init(&thread_pool_set, &iter);
    while(u32_treemap_iterator_hasnext(&iter))
    {
        u32_treemap_node_t *node = u32_treemap_iterator_next_node(&iter);
        if(node->value != NULL)
        {
            thread_pool_s *tp = (thread_pool_s *)node->value;

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

ya_result thread_pool_start_all()
{
    ya_result err = SUCCESS;

    mutex_lock(&thread_pool_set_mutex);

    u32_treemap_iterator_t iter;
    u32_treemap_iterator_init(&thread_pool_set, &iter);
    while(u32_treemap_iterator_hasnext(&iter))
    {
        u32_treemap_node_t *node = u32_treemap_iterator_next_node(&iter);
        if(node->value != NULL)
        {
            thread_pool_s *tp = (thread_pool_s *)node->value;

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

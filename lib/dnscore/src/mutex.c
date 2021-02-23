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

/** @defgroup threading mutexes, ...
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

// CentOS 5.9 requires this to have PTHREAD_MUTEX_RECURSIVE
#define  _GNU_SOURCE 1

#include "dnscore/dnscore-config.h"
#include "dnscore/thread.h"

#include <sys/types.h>
#include <unistd.h>
#include "dnscore/ptr_set.h"
#include "dnscore/timems.h"
#include "dnscore/bytezarray_output_stream.h"
#include "dnscore/format.h"
#include "dnscore/thread-tag.h"
#include "dnscore/process.h"

#if __OpenBSD__
#error "OpenBSD doesn't handle PTHREAD_PROCESS_SHARED"
#endif

#include "dnscore/logger.h"

#include "dnscore/mutex.h"

// export TSAN_OPTIONS=detect_deadlocks=1:second_deadlock_stack=1
// -sanitize=thread

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
static void
mutex_debug_logger_handle_msg(const void* handle, u32 level, const char* fmt, ...)
{
    (void)handle;
    (void)level;

    format("%llT | %i | %p | ", timeus(), getpid(), thread_self());

    output_stream baos;
    bytezarray_output_stream_context baos_context;

    va_list args;
    va_start(args, fmt);
    u8 text_buffer[512];
    bytezarray_output_stream_init_ex_static(&baos, text_buffer, sizeof(text_buffer), 0, &baos_context);

    if(FAIL(vosformat(&baos, fmt, args)))
    {
        bytezarray_output_stream_reset(&baos);
        osprint(&baos, "*** ERROR : MESSAGE FORMATTING FAILED ***");
    }

    //output_stream_write_u8(&baos, 0);
    output_stream_write(termout, bytezarray_output_stream_buffer(&baos), bytezarray_output_stream_buffer_offset(&baos));
    output_stream_write_u8(termout, (u8)'\n');
}
#endif

void
mutex_debug_stacktrace_log(void* handle, u32 level, stacktrace trace)
{
    (void)handle;
    (void)level;
    debug_stacktrace_print(termout, trace);
    output_stream_write_u8(termout, (u8)'\n');
}

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
static void
mutex_debug_log_stacktrace(void* handle, u32 level, const char *prefix)
{
    println(prefix);
    stacktrace trace = debug_stacktrace_get();
    mutex_debug_stacktrace_log(handle, level, trace);
}

#define logger_handle_msg mutex_debug_logger_handle_msg
#define debug_stacktrace_log mutex_debug_stacktrace_log
#define debug_log_stacktrace mutex_debug_log_stacktrace
#define logger_flush flushout

#define MODULE_MSG_HANDLE NULL
#define LOG_TEXT_PREFIX ""
#define MSG_DEBUG7 0
#define MSG_DEBUG6 0
#define MSG_DEBUG5 0
#define MSG_DEBUG4 0
#define MSG_DEBUG3 0
#define MSG_DEBUG2 0
#define MSG_DEBUG1 0
#define MSG_DEBUG 0
#define MSG_WARNING 0
#define MSG_ERR 0

#define log_debug7(...) logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug6(...) logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug5(...) logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug4(...) logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug3(...) logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug2(...) logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug1(...) logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_debug(...)  logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_notice(...) logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_info(...)   logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_warn(...)   logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_err(...)    logger_handle_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)

#define log_try_debug7(...) logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug6(...) logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug5(...) logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug4(...) logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug3(...) logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug2(...) logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug1(...) logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_debug(...)  logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_notice(...) logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_info(...)   logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_warn(...)   logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#define log_try_err(...)    logger_handle_try_msg(0,0,LOG_TEXT_PREFIX __VA_ARGS__)
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

volatile bool mutex_ultraverbose = FALSE;
//volatile bool mutex_ultraverbose = TRUE;

#if MUTEX_CONTENTION_MONITOR

struct mutex_contention_point_s
{
    stacktrace st;  // stack trace to that point
    s64 lock_wait;  // time spent waiting for the lock (but successfully acquired)
    s64 lock_loops; // loops made before acquiring the lock
    s64 owner_time; // time spent owning that mutex on that stack trace
    s64 use_count;
    s64 lock_fail;  // try-locks that failed
};

typedef struct mutex_contention_point_s mutex_contention_point_t;

struct mutex_contention_object_s
{
    void *mutex;
    ptr_set threads;    // set of mutex_contention_monitor
    bool recursive;
};

typedef struct mutex_contention_object_s mutex_contention_object_t;

typedef ptr_set mutex_contention_thread_t;

struct mutex_contention_monitor_s
{
    thread_t owning_thread;
    mutex_contention_point_t *contention_point;
    //
    mutex_contention_object_t *mutex_object;
    mutex_contention_thread_t *mutex_thread;
    const char *type_name;
    s64 lock_begin_timestamp;
    s64 lock_wait_loops;
    s64 lock_end_timestamp;         // 0 until the mutex is acquired
    s32 multi_lock_count;
    pid_t pid;
    bool used_by_condition;         // true means not really locked
};

typedef struct mutex_contention_monitor_s mutex_contention_monitor_t;

void mutex_contention_monitor_lock_count_inc(mutex_contention_monitor_t *mcm)
{
    //log_info("mutex_contention_monitor_lock_count_inc(%p) (%i -> %i)", mcm, mcm->multi_lock_count, mcm->multi_lock_count + 1);
    ++mcm->multi_lock_count;
}

bool mutex_contention_monitor_lock_count_dec(mutex_contention_monitor_t *mcm)
{
    //log_info("mutex_contention_monitor_lock_count_dec(%p) (%i -> %i)", mcm, mcm->multi_lock_count, mcm->multi_lock_count - 1);
    assert(mcm->multi_lock_count > 0);

    return (--mcm->multi_lock_count == 0);
}

static pthread_mutex_t mutex_contention_mtx = PTHREAD_MUTEX_INITIALIZER;
static ptr_set mutex_contention_mutex_to_threads_set = PTR_SET_PTR_EMPTY;           // mutex -> mutex_contention_object_t
static ptr_set mutex_contention_stacktrace_to_point_set = PTR_SET_EMPTY;            // stacktrace -> mutex_contention_point_t
static ptr_set mutex_contention_thread_to_monitor_set = PTR_SET_EMPTY;
// thread -> mutex_contention_monitor_t

static const char *mutex_type_name = "mutex_lock";
static const char *group_mutex_type_name = "group_mutex_lock";
static const char *shared_group_mutex_type_name = "shared_group_mutex_lock";

void mutex_contention_object_create(void *mutex_ptr, bool recursive)
{
    mutex_contention_object_t *mcu;
    pthread_mutex_lock(&mutex_contention_mtx);
    ptr_node *mutex_node = ptr_set_insert(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node->value == NULL)
    {
        MALLOC_OBJECT_OR_DIE(mcu, mutex_contention_object_t, GENERIC_TAG);
        mcu->mutex = mutex_ptr;
        ptr_set_init(&mcu->threads);
        mcu->threads.compare = ptr_set_ptr_node_compare;
        mcu->recursive = recursive;
    }
    else
    {
        logger_flush();
        abort(); // already exists
    }
    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_object_destroy(void *mutex_ptr)
{
    pthread_mutex_lock(&mutex_contention_mtx);
    ptr_node *mutex_node = ptr_set_find(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node != NULL)
    {
        if(mutex_node->value != NULL)
        {
            mutex_contention_object_t *mcu = (mutex_contention_object_t*)mutex_node->value;
            s64 now = timeus();

            if(!ptr_set_isempty(&mcu->threads))
            {
                ptr_set_iterator iter;
                ptr_set_iterator_init(&mcu->threads, &iter);
                while(ptr_set_iterator_hasnext(&iter))
                {
                    ptr_node *node = ptr_set_iterator_next_node(&iter);
                    mutex_contention_monitor_t* other_mcm = (mutex_contention_monitor_t*)node->value;

                    if(other_mcm->lock_end_timestamp == 0)
                    {
                        s64 other_wait_time = (now - other_mcm->lock_begin_timestamp);
                        log_err("mutex-monitor: unsafe destruction: thread %p has also been waiting for mutex @%p for %llius (looped %lli)",
                                 other_mcm->owning_thread, other_mcm->mutex_object->mutex, other_wait_time, other_mcm->lock_wait_loops);
                        mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, other_mcm->contention_point->st);
                    }
                    else
                    {
                        s64 other_wait_time = (now - other_mcm->lock_end_timestamp);
                        log_err("mutex-monitor: unsafe destruction: thread %p has been owning the mutex @%p for %llius (a)",
                                 other_mcm->owning_thread, other_mcm->mutex_object->mutex, other_wait_time, other_mcm->lock_wait_loops);
                        mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, other_mcm->contention_point->st);
                    }
                }

                logger_flush();
                abort();
            }
        }

        ptr_set_delete(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    }
    else
    {
        abort(); // already exists
    }
    pthread_mutex_unlock(&mutex_contention_mtx);
}

mutex_contention_monitor_t *
mutex_contention_lock_begin(thread_t thread, void *mutex_ptr, stacktrace st, const char *type_name)
{
    mutex_contention_object_t *mco;
    mutex_contention_point_t *mcp;
    mutex_contention_thread_t *mct;
    mutex_contention_monitor_t *mcm;

    pthread_mutex_lock(&mutex_contention_mtx);

    // insert/find mutex contention users
    // mutex->currently locking threads

    ptr_node *mutex_node = ptr_set_insert(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node->value != NULL)
    {
        mco = (mutex_contention_object_t*)mutex_node->value;
    }
    else
    {
        log_info("mutex monitor: %p has not been passed to mutex_contention_object_create(void*,bool): static?", mutex_ptr);

        MALLOC_OBJECT_OR_DIE(mco, mutex_contention_object_t, GENERIC_TAG);
        mco->mutex = mutex_ptr;
        ptr_set_init(&mco->threads);
        mco->threads.compare = ptr_set_ptr_node_compare;
        mco->recursive = FALSE;
        mutex_node->value = mco;
    }

    // insert/find mutex contention points
    // stacktrace->lock statistics

    ptr_node *contention_node = ptr_set_insert(&mutex_contention_stacktrace_to_point_set, st);
    if(contention_node->value != NULL)
    {
        mcp = (mutex_contention_point_t*)contention_node->value;
    }
    else
    {
        MALLOC_OBJECT_OR_DIE(mcp, mutex_contention_point_t, GENERIC_TAG);
        mcp->st = st;
        mcp->lock_wait = 0;
        mcp->lock_loops = 0;
        mcp->owner_time = 0;
        mcp->use_count = 0;
        mcp->lock_fail = 0;
        contention_node->value = mcp;
    }

    ++mcp->use_count;

    // insert/find threads using mutexes
    // thread->monitored mutexes set

    ptr_node *thread_node = ptr_set_insert(&mutex_contention_thread_to_monitor_set, (void*)thread);

    if(thread_node->value != NULL)
    {
        mct = (mutex_contention_thread_t*)thread_node->value;
    }
    else
    {
        MALLOC_OBJECT_OR_DIE(mct, mutex_contention_thread_t, GENERIC_TAG);
        ptr_set_init(mct);
        mct->compare = ptr_set_ptr_node_compare;
        thread_node->value = mct;
    }

    // insert/find mutexes in the thread monitored set

    ptr_node *monitor_node = ptr_set_insert(mct, st);
    if(monitor_node->value != NULL)
    {
        mcm = (mutex_contention_monitor_t*)monitor_node->value;
        // double lock ... ?
        mutex_contention_monitor_lock_count_inc(mcm);
    }
    else
    {
        MALLOC_OBJECT_OR_DIE(mcm, mutex_contention_monitor_t, GENERIC_TAG);
        mcm->owning_thread = thread;
        mcm->contention_point = mcp;
        mcm->mutex_object = mco;
        mcm->mutex_thread = mct;
        mcm->type_name = type_name;
        mcm->lock_begin_timestamp = timeus();
        mcm->lock_end_timestamp = 0;
        mcm->lock_wait_loops = 0;
        mcm->multi_lock_count = 1;
        mcm->pid = getpid_ex();
        monitor_node->value = mcm;
        mcm->used_by_condition = FALSE;
    }

    ptr_node *user_thread_node = ptr_set_insert(&mco->threads, (void*)thread);
    if(user_thread_node->value == NULL)
    {
        user_thread_node->value = mcm;
    }
    else
    {
        mutex_contention_monitor_t *old_mcm = (mutex_contention_monitor_t*)user_thread_node->value;
        log_err("lock monitor: mutex %p already locked by %p (old@%p now@%p)", mutex_ptr, old_mcm->lock_begin_timestamp, old_mcm, mcm);
        log_err("lock monitor: locked by");
        mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_ERR, old_mcm->contention_point->st);
        log_err("lock monitor: failed by");
        mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_ERR, mcm->contention_point->st);

        debug_stacktrace_print(termout, old_mcm->contention_point->st);
        debug_stacktrace_print(termout, mcm->contention_point->st);
        logger_flush();
        flushout();
        assert(user_thread_node->value == mcm);
    }

    pthread_mutex_unlock(&mutex_contention_mtx);

    return mcm;
}

void mutex_contention_lock_wait(mutex_contention_monitor_t *mcm)
{
    // insert/find mutex_contention_users

    pthread_mutex_lock(&mutex_contention_mtx);
    ++mcm->lock_end_timestamp;

    if(mutex_contention_monitor_lock_count_dec(mcm))
    {
        mcm->contention_point->owner_time += timeus() - mcm->lock_end_timestamp;

        mcm->used_by_condition = TRUE;
    }

    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_lock_wait_with_mutex(thread_t thread, void *mutex_ptr)
{
    mutex_contention_object_t *mco;
    mutex_contention_monitor_t *mcm;

    pthread_mutex_lock(&mutex_contention_mtx);

    ptr_node *mutex_node = ptr_set_find(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node == NULL)
    {
        log_err("mutex monitor: can't wait on %p as it has not been passed to mutex_contention_object_create(void*,bool)");
        abort();
    }

    mco = (mutex_contention_object_t*)mutex_node->value;

    ptr_node *monitor_node = ptr_set_find(&mco->threads, (void*)thread);
    if(monitor_node == NULL)
    {
        log_err("mutex monitor: can't wait on %p as it's not used by thread %p", thread);
        abort();
    }

    mcm = (mutex_contention_monitor_t*)monitor_node->value;

    if(mutex_contention_monitor_lock_count_dec(mcm))
    {
        mcm->contention_point->owner_time += timeus() - mcm->lock_end_timestamp;
    }

    mcm->used_by_condition = TRUE;

    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_lock_resume(mutex_contention_monitor_t *mcm)
{
    // insert/find mutex_contention_users

    pthread_mutex_lock(&mutex_contention_mtx);
    ++mcm->lock_end_timestamp;
    mutex_contention_monitor_lock_count_inc(mcm);
    mcm->used_by_condition = FALSE;
    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_lock_resume_with_mutex(thread_t thread, void *mutex_ptr)
{
    mutex_contention_object_t *mco;
    mutex_contention_monitor_t *mcm;

    pthread_mutex_lock(&mutex_contention_mtx);

    ptr_node *mutex_node = ptr_set_find(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node == NULL)
    {
        log_err("mutex monitor: can't wait on %p as it has not been passed to mutex_contention_object_create(void*,bool)");
        abort();
    }

    mco = (mutex_contention_object_t*)mutex_node->value;

    ptr_node *monitor_node = ptr_set_find(&mco->threads, (void*)thread);
    if(monitor_node == NULL)
    {
        log_err("mutex monitor: can't wait on %p as it's not used by thread %p", thread);
        abort();
    }

    mcm = (mutex_contention_monitor_t*)monitor_node->value;

    assert(mcm->used_by_condition);

    mutex_contention_monitor_lock_count_inc(mcm);
    mcm->used_by_condition = FALSE;

    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_lock_end(mutex_contention_monitor_t *mcm)
{
    pthread_mutex_lock(&mutex_contention_mtx);

    mcm->lock_end_timestamp = timeus();

    s64 wait_time = mcm->lock_end_timestamp - mcm->lock_begin_timestamp;

    mcm->contention_point->lock_wait += wait_time;
    mcm->contention_point->lock_loops += mcm->lock_wait_loops;

    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_lock_fail(mutex_contention_monitor_t *mcm)
{
    pthread_mutex_lock(&mutex_contention_mtx);

    mcm->lock_end_timestamp = timeus();

    s64 wait_time = mcm->lock_end_timestamp - mcm->lock_begin_timestamp;

    mcm->contention_point->lock_wait += wait_time;
    mcm->contention_point->lock_loops += mcm->lock_wait_loops;
    ++mcm->contention_point->lock_fail;

    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_unlock(thread_t thread, void *mutex_ptr)
{
    mutex_contention_object_t *mco;
    mutex_contention_monitor_t *mcm;

    pthread_mutex_lock(&mutex_contention_mtx);

    ptr_node *mutex_node = ptr_set_find(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node == NULL)
    {
        log_err("mutex monitor: can't unlock %p as it has not been passed to mutex_contention_object_create(void*,bool)");
        abort();
    }

    mco = (mutex_contention_object_t*)mutex_node->value;

    ptr_node *monitor_node = ptr_set_find(&mco->threads, (void*)thread);
    if(monitor_node == NULL)
    {
        log_err("mutex monitor: can't unlock %p as it's not used by thread %p", thread);
        abort();
    }

    mcm = (mutex_contention_monitor_t*)monitor_node->value;

    if(mutex_contention_monitor_lock_count_dec(mcm))
    {
        mcm->contention_point->owner_time += timeus() - mcm->lock_end_timestamp;

        ptr_set_delete(&mco->threads, (void*)mcm->owning_thread);
        ptr_set_delete(mcm->mutex_thread, mcm->contention_point->st);

        free(mcm);
    }
    else
    {
        log_info("mutex monitor: mcm@%p multi_lock_count = %i", mcm, mcm->multi_lock_count);
        logger_flush();
        flushout();
    }

    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_unlock_with_monitor(mutex_contention_monitor_t *mcm)
{
    pthread_mutex_lock(&mutex_contention_mtx);

    thread_t tid = thread_self();

    if(mcm->owning_thread != tid)
    {
    log_err("mutex-monitor: locked with %p, unlocked with %p", mcm->owning_thread, tid);
    }

    if(mutex_contention_monitor_lock_count_dec(mcm))
    {
        mcm->contention_point->owner_time += timeus() - mcm->lock_end_timestamp;

        ptr_set_delete(&mcm->mutex_object->threads, (void*)mcm->owning_thread);

        ptr_set_delete(mcm->mutex_thread, mcm->contention_point->st);

        free(mcm);
    }

    pthread_mutex_unlock(&mutex_contention_mtx);
}

static smp_int mutex_contention_monitor_thread_should_stop = SMP_INT_INITIALIZER_AT(0);
static pthread_mutex_t mutex_contention_monitor_thread_mtx = PTHREAD_MUTEX_INITIALIZER;
static thread_t mutex_contention_monitor_thread_id = 0;

static void*
mutex_contention_monitor_thread(void* args_)
{
    (void)args_;

    while(smp_int_get(&mutex_contention_monitor_thread_should_stop) == 0)
    {
        pthread_mutex_lock(&mutex_contention_mtx);

        ptr_set_iterator thread_iter;
        ptr_set_iterator monitor_iter;
        ptr_set_iterator other_iter;
        ptr_set_iterator_init(&mutex_contention_thread_to_monitor_set, &thread_iter);

        log_info("mutex-monitor: tick");

        while(ptr_set_iterator_hasnext(&thread_iter))
        {
            s64 now = timeus();

            ptr_node *thread_node = ptr_set_iterator_next_node(&thread_iter);
            mutex_contention_thread_t *mct = (mutex_contention_thread_t*)thread_node->value;

            ptr_set_iterator_init(mct, &monitor_iter);
            while(ptr_set_iterator_hasnext(&monitor_iter))
            {
                ptr_node *monitor_node = ptr_set_iterator_next_node(&monitor_iter);
                mutex_contention_monitor_t *mcm = (mutex_contention_monitor_t*)monitor_node->value;

                if(mcm->lock_end_timestamp == 0)
                {
                    s64 wait_time = (now - mcm->lock_begin_timestamp);

                    if(wait_time >= MUTEX_LOCKED_TOO_MUCH_TIME_US)
                    {
                        // not fine at all
                        // tell this thread has been waiting for this node for quite some time
                        // tell who is owning the mutex and since when
                        log_warn("mutex-monitor: thread %p (%s) has been waiting for mutex @%p for %llius (looped %lli)",
                                mcm->owning_thread, thread_get_tag_with_pid_and_tid(getpid_ex(), mcm->owning_thread),
                                mcm->mutex_object->mutex, wait_time, mcm->lock_wait_loops);
                        mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, mcm->contention_point->st);

                        ptr_set_iterator_init(&mcm->mutex_object->threads, &other_iter);
                        while(ptr_set_iterator_hasnext(&other_iter))
                        {
                            ptr_node *other_node = ptr_set_iterator_next_node(&other_iter);
                            mutex_contention_monitor_t* other_mcm = (mutex_contention_monitor_t*)other_node->value;

                            if(other_mcm->lock_end_timestamp == 0)
                            {
                                s64 other_wait_time = (now - other_mcm->lock_begin_timestamp);
                                log_warn("mutex-monitor: thread %p (%s) has also been waiting for mutex @%p for %llius (looped %lli)",
                                        other_mcm->owning_thread, thread_get_tag_with_pid_and_tid(getpid_ex(), other_mcm->owning_thread),
                                        other_mcm->mutex_object->mutex, other_wait_time, other_mcm->lock_wait_loops);
                                mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, other_mcm->contention_point->st);
                            }
                            else
                            {
                                s64 other_wait_time = (now - other_mcm->lock_end_timestamp);
                                log_warn("mutex-monitor: thread %p (%s) has been owning the mutex @%p for %llius (b)",
                                        other_mcm->owning_thread, thread_get_tag_with_pid_and_tid(getpid_ex(), other_mcm->owning_thread),
                                        other_mcm->mutex_object->mutex, other_wait_time, other_mcm->lock_wait_loops);
                                mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, other_mcm->contention_point->st);
                            }
                        }
                    }
                }
                else
                {
                    if(!mcm->used_by_condition)
                    {
                        s64 lock_time = (now - mcm->lock_end_timestamp);

                        if(lock_time >= MUTEX_LOCKED_TOO_MUCH_TIME_US)
                        {
                            log_warn("mutex-monitor: thread %p (%s) has been owning the mutex @%p for %llius (looped %lli) (a long time)",
                                     mcm->owning_thread, thread_get_tag_with_pid_and_tid(getpid_ex(), mcm->owning_thread),
                                     mcm->mutex_object->mutex, lock_time, mcm->lock_wait_loops);
                            mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, mcm->contention_point->st);
                        }
                    }
                    else
                    {
                        // mutex is used by a condition

                        s64 wait_time = (now - mcm->lock_end_timestamp);

                        if(wait_time >= MUTEX_WAITED_TOO_MUCH_TIME_US)
                        {
                            log_warn("mutex-monitor: thread %p (%s) has been waiting for %llius (looped %lli) (a long time)",
                                     mcm->owning_thread, thread_get_tag_with_pid_and_tid(getpid_ex(), mcm->owning_thread),
                                     wait_time, mcm->lock_wait_loops);
                            mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, mcm->contention_point->st);
                        }
                    }
                }
            }
        }

        pthread_mutex_unlock(&mutex_contention_mtx);

        sleep(1);
    }

    return NULL;
}

void mutex_contention_monitor_start()
{
    pthread_mutex_lock(&mutex_contention_monitor_thread_mtx);
    if(mutex_contention_monitor_thread_id == 0)
    {
        thread_t tid;
        int ret = thread_create(&tid, mutex_contention_monitor_thread, NULL);
        if(ret == 0)
        {
            mutex_contention_monitor_thread_id = tid;
        }
    }
    pthread_mutex_unlock(&mutex_contention_monitor_thread_mtx);
}

void mutex_contention_monitor_stop()
{
    pthread_mutex_lock(&mutex_contention_monitor_thread_mtx);
    if(mutex_contention_monitor_thread_id != 0)
    {
        smp_int_add(&mutex_contention_monitor_thread_should_stop, 1);

        thread_join(mutex_contention_monitor_thread_id, NULL);

        smp_int_sub(&mutex_contention_monitor_thread_should_stop, 1);
        mutex_contention_monitor_thread_id = 0;
    }
    pthread_mutex_unlock(&mutex_contention_monitor_thread_mtx);
}

#endif // !MUTEX_CONTENTION_MONITOR

#endif

int cond_init_process_shared(cond_t *cond)
{
    int ret;
    pthread_condattr_t attr;
    if((ret = pthread_condattr_init(&attr)) == 0)
    {
        if((ret = pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) == 0)
        {
            ret = pthread_cond_init(cond, &attr);

            if(ret != 0)
            {
                ret = MAKE_ERRNO_ERROR(ret);
            }
        }
        else
        {
            ret = MAKE_ERRNO_ERROR(ret);
        }

        pthread_condattr_destroy(&attr);
    }
    else
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    return ret;
}


/*
 * Group mutex lock
 */

void
group_mutex_init(group_mutex_t* mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: init mutex@%p", mtx);
#endif
#endif
    
    mutex_init(&mtx->mutex);
    cond_init(&mtx->cond);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(mtx, FALSE);
#endif
#endif
    mtx->count = 0;
    mtx->owner = GROUP_MUTEX_NOBODY;
    mtx->reserved_owner = GROUP_MUTEX_NOBODY;
}

bool
group_mutex_islocked(group_mutex_t *mtx)
{
    mutex_lock(&mtx->mutex);
    bool r = mtx->owner != 0;
    mutex_unlock(&mtx->mutex);
    return r;
}

void
group_mutex_lock(group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), group_mutex_type_name);
#endif
#endif
    mutex_lock(&mtx->mutex);

    for(;;)
    {
		/*
			A simple way to ensure that a lock can be shared
			by similar entities or not.
			Sharable entities have their msb off.
		*/

        u8 co = mtx->owner & GROUP_MUTEX_LOCKMASK_FLAG;
        
        if(co == GROUP_MUTEX_NOBODY || co == owner)
        {
            yassert(mtx->count != MAX_S32);

            mtx->owner = owner & GROUP_MUTEX_LOCKMASK_FLAG;
            mtx->count++;

            break;
        }
/*
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_wait(mcm); // counts the loops
#endif
#endif
*/
        cond_wait(&mtx->cond, &mtx->mutex);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_end(mcm);
#endif
#endif

    mutex_unlock(&mtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif
}

bool
group_mutex_trylock(group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: trying to lock mutex@%p for %x", mtx, owner);
#endif
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), group_mutex_type_name);
#endif
#endif
    mutex_lock(&mtx->mutex);

    u8 co = mtx->owner & GROUP_MUTEX_LOCKMASK_FLAG;
    
    if(co == GROUP_MUTEX_NOBODY || co == owner)
    {
        yassert(mtx->count != MAX_S32);

        mtx->owner = owner & GROUP_MUTEX_LOCKMASK_FLAG;
        mtx->count++;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_end(mcm);
#endif
#endif

        mutex_unlock(&mtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
        log_debug7("group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif
        return TRUE;
    }
    else
    {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#if MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_fail(mcm);
#endif
#endif
        mutex_unlock(&mtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
        log_debug7("group_mutex: failed to lock mutex@%p for %x", mtx, owner);
#endif
#endif
        return FALSE;
    }
}

void
group_mutex_unlock(group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: unlocking mutex@%p for %x (owned by %x)", mtx, owner, mtx->owner);
#endif
#endif
    mutex_lock(&mtx->mutex);

    yassert(mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->count != 0);

    (void)owner;

    mtx->count--;

    if(mtx->count == 0)
    {
        mtx->owner = GROUP_MUTEX_NOBODY;
        
        // wake up all the ones that were waiting for a clean ownership
        
        cond_notify(&mtx->cond);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), mtx);
#endif
#endif
        
    mutex_unlock(&mtx->mutex);
}

void
group_mutex_double_lock(group_mutex_t *mtx, u8 owner, u8 secondary_owner)
{
    yassert(owner == GROUP_MUTEX_READ);
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
    
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: double-locking mutex@%p for %x", mtx, secondary_owner);
#endif

#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), group_mutex_type_name);
#endif
#endif
    mutex_lock(&mtx->mutex);
    
    for(;;)
    {
        /*
         * A simple way to ensure that a lock can be shared
         * by similar entities or not.
         * Sharable entities have their msb off.
         */
        
        u8 so = mtx->reserved_owner & GROUP_MUTEX_LOCKMASK_FLAG;
        
        if(so == GROUP_MUTEX_NOBODY || so == secondary_owner)
        {
            u8 co = mtx->owner & GROUP_MUTEX_LOCKMASK_FLAG;

            if(co == GROUP_MUTEX_NOBODY || co == owner)
            {
                yassert(!SIGNED_VAR_VALUE_IS_MAX(mtx->count));

                mtx->owner = owner & GROUP_MUTEX_LOCKMASK_FLAG;
                mtx->count++;
                mtx->reserved_owner = secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG;

                break;
            }
        }
        else
        {
            // the secondary owner is already taken
        }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_wait(mcm);
#endif
#endif
        cond_wait(&mtx->cond, &mtx->mutex);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_resume(mcm);
#endif
#endif
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_end(mcm);
#endif
#endif

    mutex_unlock(&mtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: double-locked mutex@%p for %x", mtx, secondary_owner);
#endif
#endif
}

void
group_mutex_double_unlock(group_mutex_t *mtx, u8 owner, u8 secondary_owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: double-unlocking mutex@%p for %x (owned by %x)", mtx, secondary_owner, mtx->reserved_owner);
#endif
#endif
    
    yassert(owner == GROUP_MUTEX_READ);

    mutex_lock(&mtx->mutex);
    
    yassert(mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->reserved_owner == (secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->count != 0);

    (void)owner;
    (void)secondary_owner;

    mtx->reserved_owner = GROUP_MUTEX_NOBODY;

    --mtx->count;
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: double-unlocked mutex@%p for %x,%x", mtx, owner, secondary_owner);
#endif
#endif
    
    yassert((mtx->owner & 0xc0) == 0);

    if(mtx->count == 0)
    {
        mtx->owner = GROUP_MUTEX_NOBODY;
        cond_notify(&mtx->cond);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), mtx);
#endif
#endif
    
    mutex_unlock(&mtx->mutex);
}

void
group_mutex_exchange_locks(group_mutex_t *mtx, u8 owner, u8 secondary_owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: exchanging-locks of mutex@%p %x,%x (", mtx, owner, secondary_owner, mtx->owner, mtx->reserved_owner);
#endif
#endif
    
    yassert(owner == GROUP_MUTEX_READ || secondary_owner == GROUP_MUTEX_READ);
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
    s64 start = timeus();
#endif

    mutex_lock(&mtx->mutex);

    if((mtx->owner != (owner & GROUP_MUTEX_LOCKMASK_FLAG)) || (mtx->reserved_owner != (secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG)) || (mtx->count == 0))
    {
#ifdef MODULE_MSG_HANDLE
        debug_log_stacktrace(g_system_logger, MSG_ERR, "group_mutex_exchange_locks");
#endif
        abort();
    }
#else
    mutex_lock(&mtx->mutex);

    yassert(mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->reserved_owner == (secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->count != 0);
#endif

#if DEBUG
    if((mtx->owner != (owner & GROUP_MUTEX_LOCKMASK_FLAG)) || (mtx->count == 0))
    {
        mutex_unlock(&mtx->mutex);
        yassert(mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG));
        yassert(mtx->count != 0);
        abort(); // unreachable
    }
    
    if(mtx->reserved_owner != (secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG))
    {
        mutex_unlock(&mtx->mutex);
        yassert(mtx->reserved_owner != (secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG));
        abort(); // unreachable
    }
#endif
    
    // wait to be the last one
    
    while(mtx->count != 1)
    {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#ifdef MODULE_MSG_HANDLE
        s64 d = timeus() - start;
        if(d > MUTEX_WAITED_TOO_MUCH_TIME_US)
        {
            log_warn("group_mutex_exchange_locks(%p,%x,%x) : waited for %llius already ...", mtx, owner, secondary_owner, d);
            debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_WARNING, "group_mutex_exchange_locks:");
        }
#endif
#endif
        cond_timedwait(&mtx->cond, &mtx->mutex, 100);
    }
    
    mtx->owner = secondary_owner & GROUP_MUTEX_LOCKMASK_FLAG;
    mtx->reserved_owner = owner & GROUP_MUTEX_LOCKMASK_FLAG;
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: exchanged locks of mutex@%p to %x, %x", mtx, secondary_owner, owner);
#endif
#endif
    
    if((secondary_owner & GROUP_MUTEX_EXCLUSIVE_FLAG) == 0)
    {
        cond_notify(&mtx->cond);
    }

    mutex_unlock(&mtx->mutex);
}

void
group_mutex_destroy(group_mutex_t* mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("group_mutex: destroy mutex@%p", mtx);
#endif
#endif
    
    mutex_lock(&mtx->mutex);
    yassert(mtx->count == 0);

    mutex_unlock(&mtx->mutex);
    
    group_mutex_lock(mtx, GROUP_MUTEX_DESTROY);
    group_mutex_unlock(mtx, GROUP_MUTEX_DESTROY);
    
    cond_notify(&mtx->cond);
    cond_finalize(&mtx->cond);
    mutex_destroy(&mtx->mutex);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_object_destroy(mtx);
#endif
#endif
}

void
mutex_init_recursive(mutex_t *mtx)
{
    int err;
    
    ZEROMEMORY(mtx, sizeof(mutex_t));

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(mtx, FALSE);
#endif
#endif

    pthread_mutexattr_t   mta;
    
    err = pthread_mutexattr_init(&mta);

    if(err != 0)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init_recursive: attr %r", MAKE_ERRNO_ERROR(err));
#endif
    }
    
    err = pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);
    
    if(err != 0)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init_recursive: set %r", MAKE_ERRNO_ERROR(err));
#endif
    }

    err = pthread_mutex_init(mtx, &mta);

    if(err != 0)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init_recursive: %r", MAKE_ERRNO_ERROR(err));
#endif
    }
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_init(%p)", mtx);
    }
#endif
    
    pthread_mutexattr_destroy(&mta);
}

int
mutex_init_process_shared(mutex_t *mtx)
{
    int ret;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(mtx, FALSE);
#endif
#endif
    
    pthread_mutexattr_t attr;
    if((ret = pthread_mutexattr_init(&attr)) == 0)
    {
        ret = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    
        if(ret == 0)
        {
            if((ret = pthread_mutex_init(mtx, &attr)) != 0)
            {
                ret = MAKE_ERRNO_ERROR(ret);
            }
        }
        else
        {
            ret = MAKE_ERRNO_ERROR(ret);
        }

        pthread_mutexattr_destroy(&attr);
    }
    else
    {
        ret = MAKE_ERRNO_ERROR(ret);
    }
    
    return ret;
}

void
mutex_init(mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(mtx, FALSE);
#endif
#endif
    int err = pthread_mutex_init(mtx, NULL);
    
    if(err != 0)
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_init: %r", MAKE_ERRNO_ERROR(err));
    }
}

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT

void
mutex_lock(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_lock(%p)", mtx);
#endif
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), mutex_type_name);
#endif
#endif

    pthread_mutex_lock(mtx);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_end(mcm);
#endif
#endif

    if(mutex_ultraverbose)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_lock(%p): locked", mtx);
#endif
    }
}

bool
mutex_trylock(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger, MSG_DEBUG7, "mutex_trylock(%p)", mtx);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), mutex_type_name);
#endif
#endif

    int err = pthread_mutex_trylock(mtx);

    if((err != 0) && (err != EBUSY))
    {
        logger_handle_msg(g_system_logger,MSG_ERR, "mutex_trylock(%p): %r", mtx, MAKE_ERRNO_ERROR(err));
        logger_flush();
        abort();
    }

    if(err == 0)
    {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_end(mcm);
#endif
#endif
    }
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    else
    {
        mutex_contention_lock_fail(mcm);
    }
#endif
#endif

    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_trylock(%p): %s", mtx, (err == 0)?"locked":"failed");
    }

    return err == 0;
}

void
mutex_unlock(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_unlock(%p)", mtx);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), mtx);
#endif
#endif

    int err = pthread_mutex_unlock(mtx);

    if(err != 0)
    {
        logger_handle_msg(g_system_logger, MSG_ERR, "mutex_unlock(%p) self=%p: %r", mtx, (intptr)thread_self(), MAKE_ERRNO_ERROR(err));
        debug_stacktrace_log(g_system_logger, MSG_ERR, debug_stacktrace_get());
        logger_flush();
        abort();
    }
}

int
mutex_lock_unchecked(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_lock(%p)", mtx);
#endif
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), mutex_type_name);
#endif
#endif

    int ret = pthread_mutex_lock(mtx);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_end(mcm);
#endif
#endif

    if(mutex_ultraverbose)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_lock(%p): locked", mtx);
#endif
    }

    return ret;
}

int
mutex_unlock_unchecked(mutex_t *mtx)
{
    if(mutex_ultraverbose)
    {
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_unlock(%p)", mtx);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), mtx);
#endif
#endif

    int ret = pthread_mutex_unlock(mtx);

    if(ret != 0)
    {
        logger_handle_msg(g_system_logger, MSG_ERR, "mutex_unlock(%p) self=%p: %r", mtx, (intptr)thread_self(), MAKE_ERRNO_ERROR(ret));
        debug_stacktrace_log(g_system_logger, MSG_ERR, debug_stacktrace_get());
        logger_flush();
    }

    return ret;
}

#endif

void
mutex_destroy(mutex_t *mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
    int ebusy_count = 0;
    
    if(mutex_ultraverbose)
    {
#ifdef MODULE_MSG_HANDLE
        logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_destroy(%p)", mtx);
#endif
    }
#endif
    
    for(;;)
    {
        int err = pthread_mutex_destroy(mtx);

        switch(err)
        {
            case 0:
            {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
                mutex_contention_object_destroy(mtx);
#endif
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
                if(ebusy_count > 0)
                {
                    logger_handle_msg(g_system_logger,MSG_DEBUG7, "mutex_destroy: EBUSY #%i", ebusy_count);
                }
#endif
                return;
            }
            case EBUSY:
            {               
                usleep(1000);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
                ebusy_count++;

#ifdef MODULE_MSG_HANDLE
                if((ebusy_count & 0xfffff) == 0)
                {
                    debug_stacktrace_log(g_system_logger, MSG_DEBUG7,  debug_stacktrace_get());
                }
                
                if((ebusy_count & 0xfff) == 0)
                {
                    logger_handle_msg(g_system_logger,MSG_ERR, "mutex_destroy: EBUSY #%i", ebusy_count);
                }
#endif
#endif
                break;
            }
            default:
            {
#ifdef MODULE_MSG_HANDLE
                logger_handle_msg(g_system_logger,MSG_ERR, "mutex_destroy: %r", MAKE_ERRNO_ERROR(err));
                logger_flush();
#endif
                abort();
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

/*
 * Group mutex lock
 */

void
shared_group_shared_mutex_init(shared_group_shared_mutex_t* smtx)
{
    mutex_init(&smtx->mutex);
    cond_init(&smtx->cond);
    smtx->rc = 0;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(smtx, FALSE);
#endif
#endif
}

void
shared_group_shared_mutex_init_recursive(shared_group_shared_mutex_t* smtx)
{
    mutex_init_recursive(&smtx->mutex);
    cond_init(&smtx->cond);
    smtx->rc = 0;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(smtx, TRUE);
#endif
#endif
}

void
shared_group_shared_mutex_destroy(shared_group_shared_mutex_t* smtx)
{
    yassert(smtx->rc == 0);
    
    cond_finalize(&smtx->cond);
    mutex_destroy(&smtx->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_object_destroy(smtx);
#endif
#endif
}

void
shared_group_mutex_init(shared_group_mutex_t* mtx, shared_group_shared_mutex_t* smtx, const char *name)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: init mutex@%p+%p '%s'", mtx, smtx, name);
#endif
#else
    (void)name;
#endif
    
    mutex_lock(&smtx->mutex);
    smtx->rc++;
    mutex_unlock(&smtx->mutex);
    mtx->shared_mutex = smtx;

    mtx->count = 0;
    mtx->owner = GROUP_MUTEX_NOBODY;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_object_create(mtx, TRUE);
#endif
#endif
}

bool
shared_group_mutex_islocked(shared_group_mutex_t *mtx)
{
    mutex_lock(&mtx->shared_mutex->mutex);
    bool r = mtx->owner != 0;
    mutex_unlock(&mtx->shared_mutex->mutex);
    return r;
}

bool
shared_group_mutex_islocked_by(shared_group_mutex_t *mtx, u8 owner)
{
    mutex_lock(&mtx->shared_mutex->mutex);
    bool r = mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG);
    mutex_unlock(&mtx->shared_mutex->mutex);
    return r;
}

void
shared_group_mutex_lock(shared_group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: locking mutex@%p for %x", mtx, owner);
#endif
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), shared_group_mutex_type_name);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);
        
    for(;;)
    {
		/*
			A simple way to ensure that a lock can be shared
			by similar entities or not.
			Sharable entities have their msb off.
		*/

        u8 co = mtx->owner & GROUP_MUTEX_LOCKMASK_FLAG;
        
        if(co == GROUP_MUTEX_NOBODY || co == owner)
        {
            yassert(mtx->count != MAX_S32);

            mtx->owner = owner & GROUP_MUTEX_LOCKMASK_FLAG;
            mtx->count++;
            break;
        }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_wait(mcm);
#endif
#endif
        cond_wait(&mtx->shared_mutex->cond, &mtx->shared_mutex->mutex);
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_resume(mcm);
#endif
#endif
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_lock_end(mcm);
#endif
#endif

    mutex_unlock(&mtx->shared_mutex->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif
}

bool
shared_group_mutex_trylock(shared_group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: trying to lock mutex@%p for %x", mtx, owner);
#endif
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_monitor_t *mcm = mutex_contention_lock_begin(thread_self(), mtx, debug_stacktrace_get(), shared_group_mutex_type_name);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);

    u8 co = mtx->owner & GROUP_MUTEX_LOCKMASK_FLAG;
        
    if(co == GROUP_MUTEX_NOBODY || co == owner)
    {
        yassert(mtx->count != MAX_S32);

        mtx->owner = owner & GROUP_MUTEX_LOCKMASK_FLAG;
        mtx->count++;

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_end(mcm);
#endif
#endif
        mutex_unlock(&mtx->shared_mutex->mutex);
        
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
        log_debug7("shared_group_mutex: locked mutex@%p for %x", mtx, owner);
#endif
#endif
        return TRUE;
    }
    else
    {
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
        mutex_contention_lock_fail(mcm);
#endif
#endif
        mutex_unlock(&mtx->shared_mutex->mutex);

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
        log_debug7("shared_group_mutex: failed to lock mutex@%p for %x", mtx, owner);
#endif
#endif

        return FALSE;
    }
}

void
shared_group_mutex_unlock(shared_group_mutex_t *mtx, u8 owner)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: unlocking mutex@%p for %x (owned by %x)", mtx, owner, mtx->owner);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);

    yassert(mtx->owner == (owner & GROUP_MUTEX_LOCKMASK_FLAG));
    yassert(mtx->count != 0);

    (void)owner;
    
    mtx->count--;

    if(mtx->count == 0)
    {
        mtx->owner = GROUP_MUTEX_NOBODY;

        // wake up all the ones that were waiting for a clean ownership
        
        cond_notify(&mtx->shared_mutex->cond);
    }

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_unlock(thread_self(), mtx);
#endif
#endif

    mutex_unlock(&mtx->shared_mutex->mutex);
}

bool
shared_group_mutex_transferlock(shared_group_mutex_t *mtx, u8 owner, u8 newowner)
{   
    bool r;
    
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: transferring ownership of mutex@%p from %x to %x (owned by %x)", mtx, owner, newowner, mtx->owner);
#endif
#endif

    mutex_lock(&mtx->shared_mutex->mutex);

    u8 co = mtx->owner & GROUP_MUTEX_LOCKMASK_FLAG;
    
    if((r = (co == owner)))
    {
        mtx->owner = newowner;
    }
    
    mutex_unlock(&mtx->shared_mutex->mutex);

    return r;
}

void
shared_group_mutex_destroy(shared_group_mutex_t* mtx)
{
#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT > 1
#ifdef MODULE_MSG_HANDLE
    log_debug7("shared_group_mutex: destroy mutex@%p", mtx);
#endif
#endif

#if DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#if MUTEX_CONTENTION_MONITOR
    mutex_contention_object_destroy(mtx);
#endif
#endif
    
    mutex_lock(&mtx->shared_mutex->mutex);
    mtx->shared_mutex->rc--;
    mutex_unlock(&mtx->shared_mutex->mutex);
}


/** @} */

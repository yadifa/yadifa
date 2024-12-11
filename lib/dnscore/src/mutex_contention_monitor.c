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

#include "dnscore/smp_int.h"
#include "dnscore/mutex.h"
#include "dnscore/mutex_contention_monitor.h"
#include "dnscore/mutex_logger.h"
#include "dnscore/process.h"

#if DNSCORE_MUTEX_CONTENTION_MONITOR

#define MTXCOBJ_TAG  0x4a424f4358544d
#define MTXCPT_TAG   0x54504358544d
#define MTXCTHRD_TAG 0x445248544358544d
#define MTXCMON_TAG  0x4e4f4d5358544d

static smp_int         mutex_contention_monitor_thread_should_stop = SMP_INT_INITIALIZER_AT(0);
static pthread_mutex_t mutex_contention_monitor_thread_mtx = PTHREAD_MUTEX_INITIALIZER;
static thread_t        mutex_contention_monitor_thread_id = 0;

static pthread_mutex_t mutex_contention_mtx = PTHREAD_MUTEX_INITIALIZER;
static ptr_treemap_t   mutex_contention_mutex_to_threads_set = PTR_TREEMAP_PTR_EMPTY; // mutex -> mutex_contention_object_t
static ptr_treemap_t   mutex_contention_stacktrace_to_point_set = PTR_TREEMAP_EMPTY;  // stacktrace -> mutex_contention_point_t
static ptr_treemap_t   mutex_contention_thread_to_monitor_set = PTR_TREEMAP_EMPTY;
// thread -> mutex_contention_monitor_t

void mutex_contention_monitor_lock_count_inc(mutex_contention_monitor_t *mcm)
{
    // log_info("mutex_contention_monitor_lock_count_inc(%p) (%i -> %i)", mcm, mcm->multi_lock_count,
    // mcm->multi_lock_count + 1);
    ++mcm->multi_lock_count;
}

bool mutex_contention_monitor_lock_count_dec(mutex_contention_monitor_t *mcm)
{
    // log_info("mutex_contention_monitor_lock_count_dec(%p) (%i -> %i)", mcm, mcm->multi_lock_count,
    // mcm->multi_lock_count - 1);
    assert(mcm->multi_lock_count > 0);

    return (--mcm->multi_lock_count == 0);
}

void mutex_contention_object_create(void *mutex_ptr, bool recursive)
{
    mutex_contention_object_t *mcu;
    pthread_mutex_lock(&mutex_contention_mtx);
    ptr_treemap_node_t *mutex_node = ptr_treemap_insert(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node->value == NULL)
    {
        MALLOC_OBJECT_OR_DIE(mcu, mutex_contention_object_t, MTXCOBJ_TAG);
        mcu->mutex = mutex_ptr;
        ptr_treemap_init(&mcu->threads);
        mcu->threads.compare = ptr_treemap_ptr_node_compare;
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
    ptr_treemap_node_t *mutex_node = ptr_treemap_find(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node != NULL)
    {
        if(mutex_node->value != NULL)
        {
            mutex_contention_object_t *mcu = (mutex_contention_object_t *)mutex_node->value;
            int64_t                    now = timeus();

            if(!ptr_treemap_isempty(&mcu->threads))
            {
                ptr_treemap_iterator_t iter;
                ptr_treemap_iterator_init(&mcu->threads, &iter);
                while(ptr_treemap_iterator_hasnext(&iter))
                {
                    ptr_treemap_node_t         *node = ptr_treemap_iterator_next_node(&iter);
                    mutex_contention_monitor_t *other_mcm = (mutex_contention_monitor_t *)node->value;

                    if(other_mcm->lock_end_timestamp == 0)
                    {
                        int64_t other_wait_time = (now - other_mcm->lock_begin_timestamp);
                        log_err(
                            "mutex-monitor: unsafe destruction: thread %p has also been waiting for mutex @%p for "
                            "%llius (looped %lli)",
                            other_mcm->owning_thread,
                            other_mcm->mutex_object->mutex,
                            other_wait_time,
                            other_mcm->lock_wait_loops);
                        mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, other_mcm->contention_point->st);
                    }
                    else
                    {
                        int64_t other_wait_time = (now - other_mcm->lock_end_timestamp);
                        log_err("mutex-monitor: unsafe destruction: thread %p has been owning the mutex @%p for %llius (a)", other_mcm->owning_thread, other_mcm->mutex_object->mutex, other_wait_time, other_mcm->lock_wait_loops);
                        mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, other_mcm->contention_point->st);
                    }
                }

                logger_flush();
                abort();
            }
        }

        ptr_treemap_delete(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    }
    else
    {
        abort(); // already exists
    }
    pthread_mutex_unlock(&mutex_contention_mtx);
}

mutex_contention_monitor_t *mutex_contention_lock_begin(thread_t thread, void *mutex_ptr, stacktrace st, const char *type_name)
{
    mutex_contention_object_t  *mco;
    mutex_contention_point_t   *mcp;
    mutex_contention_thread_t  *mct;
    mutex_contention_monitor_t *mcm;

    pthread_mutex_lock(&mutex_contention_mtx);

    // insert/find mutex contention users
    // mutex->currently locking threads

    ptr_treemap_node_t *mutex_node = ptr_treemap_insert(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node->value != NULL)
    {
        mco = (mutex_contention_object_t *)mutex_node->value;
    }
    else
    {
        log_info("mutex monitor: %p has not been passed to mutex_contention_object_create(void*,bool): static?", mutex_ptr);

        MALLOC_OBJECT_OR_DIE(mco, mutex_contention_object_t, MTXCOBJ_TAG);
        mco->mutex = mutex_ptr;
        ptr_treemap_init(&mco->threads);
        mco->threads.compare = ptr_treemap_ptr_node_compare;
        mco->recursive = false;
        mutex_node->value = mco;
    }

    // insert/find mutex contention points
    // stacktrace->lock statistics

    ptr_treemap_node_t *contention_node = ptr_treemap_insert(&mutex_contention_stacktrace_to_point_set, st);
    if(contention_node->value != NULL)
    {
        mcp = (mutex_contention_point_t *)contention_node->value;
    }
    else
    {
        MALLOC_OBJECT_OR_DIE(mcp, mutex_contention_point_t, MTXCPT_TAG);
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

    ptr_treemap_node_t *thread_node = ptr_treemap_insert(&mutex_contention_thread_to_monitor_set, (void *)thread);

    if(thread_node->value != NULL)
    {
        mct = (mutex_contention_thread_t *)thread_node->value;
    }
    else
    {
        MALLOC_OBJECT_OR_DIE(mct, mutex_contention_thread_t, MTXCTHRD_TAG);
        ptr_treemap_init(mct);
        mct->compare = ptr_treemap_ptr_node_compare;
        thread_node->value = mct;
    }

    // insert/find mutexes in the thread monitored set

    ptr_treemap_node_t *monitor_node = ptr_treemap_insert(mct, st);
    if(monitor_node->value != NULL)
    {
        mcm = (mutex_contention_monitor_t *)monitor_node->value;
        // double lock ... ?
        mutex_contention_monitor_lock_count_inc(mcm);
    }
    else
    {
        MALLOC_OBJECT_OR_DIE(mcm, mutex_contention_monitor_t, MTXCMON_TAG);
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
        mcm->used_by_condition = false;
    }

    ptr_treemap_node_t *user_thread_node = ptr_treemap_insert(&mco->threads, (void *)thread);
    if(user_thread_node->value == NULL)
    {
        user_thread_node->value = mcm;
    }
    else
    {
        mutex_contention_monitor_t *old_mcm = (mutex_contention_monitor_t *)user_thread_node->value;
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

        mcm->used_by_condition = true;
    }

    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_lock_wait_with_mutex(thread_t thread, void *mutex_ptr)
{
    mutex_contention_object_t  *mco;
    mutex_contention_monitor_t *mcm;

    pthread_mutex_lock(&mutex_contention_mtx);

    ptr_treemap_node_t *mutex_node = ptr_treemap_find(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node == NULL)
    {
        log_err("mutex monitor: can't wait on %p as it has not been passed to mutex_contention_object_create(void*,bool)");
        abort();
    }

    mco = (mutex_contention_object_t *)mutex_node->value;

    ptr_treemap_node_t *monitor_node = ptr_treemap_find(&mco->threads, (void *)thread);
    if(monitor_node == NULL)
    {
        log_err("mutex monitor: can't wait on %p as it's not used by thread %p", thread);
        abort();
    }

    mcm = (mutex_contention_monitor_t *)monitor_node->value;

    if(mutex_contention_monitor_lock_count_dec(mcm))
    {
        mcm->contention_point->owner_time += timeus() - mcm->lock_end_timestamp;
    }

    mcm->used_by_condition = true;

    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_lock_resume(mutex_contention_monitor_t *mcm)
{
    // insert/find mutex_contention_users

    pthread_mutex_lock(&mutex_contention_mtx);
    ++mcm->lock_end_timestamp;
    mutex_contention_monitor_lock_count_inc(mcm);
    mcm->used_by_condition = false;
    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_lock_resume_with_mutex(thread_t thread, void *mutex_ptr)
{
    mutex_contention_object_t  *mco;
    mutex_contention_monitor_t *mcm;

    pthread_mutex_lock(&mutex_contention_mtx);

    ptr_treemap_node_t *mutex_node = ptr_treemap_find(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node == NULL)
    {
        log_err("mutex monitor: can't wait on %p as it has not been passed to mutex_contention_object_create(void*,bool)");
        abort();
    }

    mco = (mutex_contention_object_t *)mutex_node->value;

    ptr_treemap_node_t *monitor_node = ptr_treemap_find(&mco->threads, (void *)thread);
    if(monitor_node == NULL)
    {
        log_err("mutex monitor: can't wait on %p as it's not used by thread %p", thread);
        abort();
    }

    mcm = (mutex_contention_monitor_t *)monitor_node->value;

    assert(mcm->used_by_condition);

    mutex_contention_monitor_lock_count_inc(mcm);
    mcm->used_by_condition = false;

    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_lock_end(mutex_contention_monitor_t *mcm)
{
    pthread_mutex_lock(&mutex_contention_mtx);

    mcm->lock_end_timestamp = timeus();

    int64_t wait_time = mcm->lock_end_timestamp - mcm->lock_begin_timestamp;

    mcm->contention_point->lock_wait += wait_time;
    mcm->contention_point->lock_loops += mcm->lock_wait_loops;

    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_lock_fail(mutex_contention_monitor_t *mcm)
{
    pthread_mutex_lock(&mutex_contention_mtx);

    mcm->lock_end_timestamp = timeus();

    int64_t wait_time = mcm->lock_end_timestamp - mcm->lock_begin_timestamp;

    mcm->contention_point->lock_wait += wait_time;
    mcm->contention_point->lock_loops += mcm->lock_wait_loops;
    ++mcm->contention_point->lock_fail;

    pthread_mutex_unlock(&mutex_contention_mtx);
}

void mutex_contention_unlock(thread_t thread, void *mutex_ptr)
{
    mutex_contention_object_t  *mco;
    mutex_contention_monitor_t *mcm;

    pthread_mutex_lock(&mutex_contention_mtx);

    ptr_treemap_node_t *mutex_node = ptr_treemap_find(&mutex_contention_mutex_to_threads_set, mutex_ptr);
    if(mutex_node == NULL)
    {
        log_err("mutex monitor: can't unlock %p as it has not been passed to mutex_contention_object_create(void*,bool)");
        abort();
    }

    mco = (mutex_contention_object_t *)mutex_node->value;

    ptr_treemap_node_t *monitor_node = ptr_treemap_find(&mco->threads, (void *)thread);
    if(monitor_node == NULL)
    {
        log_err("mutex monitor: can't unlock %p as it's not used by thread %p", thread);
        abort();
    }

    mcm = (mutex_contention_monitor_t *)monitor_node->value;

    if(mutex_contention_monitor_lock_count_dec(mcm))
    {
        mcm->contention_point->owner_time += timeus() - mcm->lock_end_timestamp;

        ptr_treemap_delete(&mco->threads, (void *)mcm->owning_thread);
        ptr_treemap_delete(mcm->mutex_thread, mcm->contention_point->st);

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

        ptr_treemap_delete(&mcm->mutex_object->threads, (void *)mcm->owning_thread);

        ptr_treemap_delete(mcm->mutex_thread, mcm->contention_point->st);

        free(mcm);
    }

    pthread_mutex_unlock(&mutex_contention_mtx);
}

static void *mutex_contention_monitor_thread(void *args_)
{
    (void)args_;

    while(smp_int_get(&mutex_contention_monitor_thread_should_stop) == 0)
    {
        pthread_mutex_lock(&mutex_contention_mtx);

        ptr_treemap_iterator_t thread_iter;
        ptr_treemap_iterator_t monitor_iter;
        ptr_treemap_iterator_t other_iter;
        ptr_treemap_iterator_init(&mutex_contention_thread_to_monitor_set, &thread_iter);

        log_info("mutex-monitor: tick");

        while(ptr_treemap_iterator_hasnext(&thread_iter))
        {
            int64_t                    now = timeus();

            ptr_treemap_node_t        *thread_node = ptr_treemap_iterator_next_node(&thread_iter);
            mutex_contention_thread_t *mct = (mutex_contention_thread_t *)thread_node->value;

            ptr_treemap_iterator_init(mct, &monitor_iter);
            while(ptr_treemap_iterator_hasnext(&monitor_iter))
            {
                ptr_treemap_node_t         *monitor_node = ptr_treemap_iterator_next_node(&monitor_iter);
                mutex_contention_monitor_t *mcm = (mutex_contention_monitor_t *)monitor_node->value;

                if(mcm->lock_end_timestamp == 0)
                {
                    int64_t wait_time = (now - mcm->lock_begin_timestamp);

                    if(wait_time >= MUTEX_LOCKED_TOO_MUCH_TIME_US)
                    {
                        // not fine at all
                        // tell this thread has been waiting for this node for quite some time
                        // tell who is owning the mutex and since when
                        log_warn("mutex-monitor: thread %p (%s) has been waiting for mutex @%p for %llius (looped %lli)",
                                 mcm->owning_thread,
                                 thread_get_tag_with_pid_and_tid(getpid_ex(), mcm->owning_thread),
                                 mcm->mutex_object->mutex,
                                 wait_time,
                                 mcm->lock_wait_loops);
                        mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, mcm->contention_point->st);

                        ptr_treemap_iterator_init(&mcm->mutex_object->threads, &other_iter);
                        while(ptr_treemap_iterator_hasnext(&other_iter))
                        {
                            ptr_treemap_node_t         *other_node = ptr_treemap_iterator_next_node(&other_iter);
                            mutex_contention_monitor_t *other_mcm = (mutex_contention_monitor_t *)other_node->value;

                            if(other_mcm->lock_end_timestamp == 0)
                            {
                                int64_t other_wait_time = (now - other_mcm->lock_begin_timestamp);
                                log_warn(
                                    "mutex-monitor: thread %p (%s) has also been waiting for mutex @%p for %llius "
                                    "(looped %lli)",
                                    other_mcm->owning_thread,
                                    thread_get_tag_with_pid_and_tid(getpid_ex(), other_mcm->owning_thread),
                                    other_mcm->mutex_object->mutex,
                                    other_wait_time,
                                    other_mcm->lock_wait_loops);
                                mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, other_mcm->contention_point->st);
                            }
                            else
                            {
                                int64_t other_wait_time = (now - other_mcm->lock_end_timestamp);
                                log_warn("mutex-monitor: thread %p (%s) has been owning the mutex @%p for %llius (b)",
                                         other_mcm->owning_thread,
                                         thread_get_tag_with_pid_and_tid(getpid_ex(), other_mcm->owning_thread),
                                         other_mcm->mutex_object->mutex,
                                         other_wait_time,
                                         other_mcm->lock_wait_loops);
                                mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, other_mcm->contention_point->st);
                            }
                        }
                    }
                }
                else
                {
                    if(!mcm->used_by_condition)
                    {
                        int64_t lock_time = (now - mcm->lock_end_timestamp);

                        if(lock_time >= MUTEX_LOCKED_TOO_MUCH_TIME_US)
                        {
                            log_warn(
                                "mutex-monitor: thread %p (%s) has been owning the mutex @%p for %llius (looped %lli) "
                                "(a long time)",
                                mcm->owning_thread,
                                thread_get_tag_with_pid_and_tid(getpid_ex(), mcm->owning_thread),
                                mcm->mutex_object->mutex,
                                lock_time,
                                mcm->lock_wait_loops);
                            mutex_debug_stacktrace_log(MODULE_MSG_HANDLE, MSG_WARNING, mcm->contention_point->st);
                        }
                    }
                    else
                    {
                        // mutex is used by a condition

                        int64_t wait_time = (now - mcm->lock_end_timestamp);

                        if(wait_time >= MUTEX_WAITED_TOO_MUCH_TIME_US)
                        {
                            log_warn(
                                "mutex-monitor: thread %p (%s) has been waiting for %llius (looped %lli) (a long time)", mcm->owning_thread, thread_get_tag_with_pid_and_tid(getpid_ex(), mcm->owning_thread), wait_time, mcm->lock_wait_loops);
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
        int      ret = thread_create(&tid, mutex_contention_monitor_thread, NULL);
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

#endif

/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2017, EURid. All rights reserved.
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

#include "dnscore/dnscore-config.h"
#include "dnscore/dnscore-config.h"

#if HAS_PTHREAD_SETNAME_NP
#ifdef DEBUG
#define _GNU_SOURCE 1
#endif
#endif

#include <unistd.h>
#include <signal.h>

#include <pthread.h>

#include "dnscore/ptr_set.h"
#include "dnscore/logger.h"
#include "dnscore/thread_pool.h"

#include "dnscore/service.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

static int service_ptr_set_compare(const void *node_a, const void *node_b)
{
    
    struct service_s *a = (struct service_s *)node_a;
    struct service_s *b = (struct service_s *)node_b;
    
    return strcmp(a->name, b->name);
}

static ptr_set service_set = {NULL, service_ptr_set_compare};
static mutex_t service_set_mutex = MUTEX_INITIALIZER;

static void*
service_thread(void *args)
{
    struct service_worker_s *worker = (struct service_worker_s *)args;
    
    yassert(worker != NULL);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGSTOP);
    sigaddset(&set, SIGCONT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    
    struct service_s *desc = (struct service_s *)worker->service;
        
    thread_pool_setup_random_ctx();
    
    if(worker->service->worker_count == 1)
    {
        log_debug("service: %s starting", desc->name);

#if HAS_PTHREAD_SETNAME_NP
#ifdef DEBUG
#if __APPLE__
        pthread_setname_np(desc->name);
#else
        pthread_setname_np(pthread_self(), desc->name);
#endif // __APPLE__
#endif
#endif
        
    }
    else
    {
        log_debug("service: %s starting (%i/%i)", desc->name, worker->worker_index + 1, worker->service->worker_count);

#if HAS_PTHREAD_SETNAME_NP        
#ifdef DEBUG
        // 16 is the size limit for this, cfr man page
        if(strlen(desc->name) >= 16)
        {
#if __APPLE__
            pthread_setname_np(desc->name);
#else
            pthread_setname_np(pthread_self(), desc->name);
#endif // __APPLE__
        }
        else
        {
            char tmp_name[16];
            snformat(tmp_name, sizeof(tmp_name), "%s:%d", desc->name, worker->worker_index + 1);
#if __APPLE__
            pthread_setname_np(tmp_name);
#else
            pthread_setname_np(pthread_self(), tmp_name);
#endif // __APPLE__
        }
#endif
#endif
    }
    
    if(desc->entry_point != NULL)
    {
        worker->return_code = desc->entry_point(worker);
        
        log_debug("service: %s terminated with: %r", desc->name, worker->return_code);
        
        mutex_lock(&worker->lock);
        worker->flags = SERVICE_OFF;
        mutex_unlock(&worker->lock);
    }
    else
    {
        worker->return_code = SERVICE_WITHOUT_ENTRY_POINT;
        
        log_debug("service: NULL entry point", worker->return_code);
    }
    
    thread_pool_destroy_random_ctx();
    
    mutex_lock(&worker->service->wait_lock);
    cond_notify(&worker->service->wait_cond);
    mutex_unlock(&worker->service->wait_lock);
    
    pthread_exit(NULL);
    return NULL;
}

static void*
service_on_main_thread(void *args)
{
    struct service_worker_s *worker = (struct service_worker_s *)args;
    
    if(worker == NULL)
    {
        log_err("service: with NULL entry point");
        
        mutex_lock(&worker->service->wait_lock);
        cond_notify(&worker->service->wait_cond);
        mutex_unlock(&worker->service->wait_lock);

        return NULL;
    }

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGSTOP);
    sigaddset(&set, SIGCONT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    
    struct service_s *desc = (struct service_s *)worker->service;
        
    thread_pool_setup_random_ctx();
    
    yassert(worker->service->worker_count == 1);

    log_debug("service: %s starting", desc->name);

#if HAS_PTHREAD_SETNAME_NP
#ifdef DEBUG
#if __APPLE__
    pthread_setname_np(desc->name);
#else
    pthread_setname_np(pthread_self(), desc->name);
#endif // __APPLE__
#endif
#endif
    
    if(desc->entry_point != NULL)
    {
        worker->return_code = desc->entry_point(worker);
        
        log_debug("service: %s terminated with: %r", desc->name, worker->return_code);
        
        mutex_lock(&worker->lock);
        worker->flags = SERVICE_OFF;
        mutex_unlock(&worker->lock);
    }
    else
    {
        worker->return_code = SERVICE_WITHOUT_ENTRY_POINT;
        
        log_debug("service: NULL entry point", worker->return_code);
    }
    
    thread_pool_destroy_random_ctx();
    
    mutex_lock(&worker->service->wait_lock);
    cond_notify(&worker->service->wait_cond);
    mutex_unlock(&worker->service->wait_lock);

    return NULL;
}

/**
 * Initialises service with an entry point, a name, and a number of workers
 * Each worker will know its index (from 0 to count-1).
 * No threads are started yet after this call.
 * 
 * @param desc the service
 * @param entry_point the function of the service, it must be of the type service_main
 * @param name the name of the service
 * @param count the number of workers for the service
 * @return an error code
 */

int
service_init_ex(struct service_s *desc, service_main *entry_point, const char* name, u32 count)
{
    if(count == 0)
    {
        return INVALID_ARGUMENT_ERROR;
    }
    
    ZEROMEMORY(desc, sizeof(struct service_s));
    
    mutex_init(&desc->wait_lock);
    cond_init(&desc->wait_cond);
    
    desc->name = (char*)name;
    
    mutex_lock(&service_set_mutex);
    ptr_node *node = ptr_set_avl_find(&service_set, desc);
    mutex_unlock(&service_set_mutex);
    
    if(node == NULL)
    {
        log_debug("service: %s init %i workers", name, count);
        
        desc->entry_point = entry_point;
        desc->name = strdup(name);
        MALLOC_OR_DIE(struct service_worker_s*, desc->worker, sizeof(struct service_worker_s) * count, SRVCWRKR_TAG); // DON'T POOL
        desc->worker_count = count;
        for(u32 i = 0; i < count; i++)
        {
            mutex_init(&desc->worker[i].lock);
            desc->worker[i].service = desc;
            desc->worker[i].tid = 0;
            desc->worker[i].worker_index = i;
            desc->worker[i].return_code = 0;
            desc->worker[i].flags = 0;
        }
    
        mutex_lock(&service_set_mutex);
        ptr_set_avl_insert(&service_set, desc);
        mutex_unlock(&service_set_mutex);
        
        return SUCCESS;
    }
    else
    {
        log_debug("service: %s already initialized", name);
        
        desc->name = NULL;
        return SERVICE_ALREADY_INITIALISED;
    }
}

/**
 * Initialises service with an entry point, a name, and one worker
 * No threads are started yet after this call.
 * 
 * This is basically calling service_init_ex(desc, entry_point, name, 1);
 * 
 * @param desc the service
 * @param entry_point the function of the service, it must be of the type service_main
 * @param name the name of the service
 * @return an error code
 */

int
service_init(struct service_s *desc, service_main *entry_point, const char* name)
{
    int ret = service_init_ex(desc, entry_point, name, 1);
    return ret;
}

/**
 * Stops then waits for all workers of the service.
 * Then destroy the service and release its content.
 * 
 * @param desc the service
 * @return an error code
 */

int
service_finalize(struct service_s *desc)
{
    log_debug("service: %s finalize", STRNULL(desc->name));
    
    if(desc->name == NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    service_stop(desc);
    service_wait(desc);
    
    mutex_lock(&service_set_mutex);
    ptr_set_avl_delete(&service_set, desc);
    mutex_unlock(&service_set_mutex);
    
    for(u32 i = 0; i < desc->worker_count; i++)
    {
        mutex_destroy(&desc->worker[i].lock);
    }
    ZEROMEMORY(desc->worker, sizeof(struct service_worker_s) * desc->worker_count);
    free(desc->worker);
    desc->worker = NULL;
    desc->worker_count = 0;
    desc->entry_point = NULL;
    
    cond_finalize(&desc->wait_cond);
    mutex_destroy(&desc->wait_lock);
    
    free(desc->name);
    desc->name = NULL;
    
    return SUCCESS;
}

/**
 * Starts all workers of the service
 * If a worker is already running, it is left alone with undefined results.
 * A service should be fully stopped and waited on before being started again.
 * 
 * @param desc the service
 * @return an error code
 */

int
service_start(struct service_s *desc)
{
    log_debug("service: %s start", desc->name);
    
    u32 success = 0;
    u32 failure = 0;
    
    u32 now = time(NULL);
    desc->last_seen_alive = now;
    
    for(u32 i = 0; i < desc->worker_count; i++)
    {
        struct service_worker_s *worker = &desc->worker[i];
        
        mutex_lock(&worker->lock);
        if(worker->flags == SERVICE_OFF)
        {
            worker->flags = SERVICE_START;

            mutex_unlock(&worker->lock);
        }
        else
        {
            worker->return_code = SERVICE_ALREADY_RUNNING;
            mutex_unlock(&worker->lock);

            log_warn("service_start: %s worker #%u already up and running", desc->name, i);
            
            // service worker already up, ignore
            continue;            
        }
        

        if(pthread_create(&worker->tid, NULL, service_thread, worker) == 0)
        {
            success++;
        }
        else
        {
            int err = ERRNO_ERROR;

            mutex_lock(&worker->lock);

            worker->last_seen_alive = now;
            worker->tid = 0;
            worker->return_code = err;
            worker->flags = SERVICE_OFF;

            mutex_unlock(&worker->lock);
            
            log_err("service_start: failed with: %r", err);

            failure++;
        }
    }
    
    if(failure > 0)
    {
        log_err("service_start: service workers did not initialise properly (%u failures over %u workers)", failure, desc->worker_count);
        
        if(success > 0)
        {
            log_err("service_start: but %u of the workers have been properly initialised", success);
        }
        
        return INVALID_STATE_ERROR;
    }
    
    return success;
}

/**
 * Starts a service and waits for its end.
 * This is meant for services with only one thread.
 * If used with such a service, no new thread will be started and the service
 * will be run on the current thread.
 * It is useful when you have a model where the main thread of the program
 * could change behaviour with an option.
 * ie: the server service (nudge nudge, wink wink ...)
 * 
 * @param desc
 * @return 
 */

int
service_start_and_wait(struct service_s *desc)
{
    int ret;
    if(desc->worker_count != 1)
    {
        ret = service_start(desc);
        if(ISOK(ret))
        {
            ret = service_wait(desc);
        }
    }
    else
    {
        log_debug("service: %s start", desc->name);

        u32 now = time(NULL);
        desc->last_seen_alive = now;

        struct service_worker_s *worker = &desc->worker[0];

        mutex_lock(&worker->lock);
        if(worker->flags == SERVICE_OFF)
        {
            worker->flags = SERVICE_START;

            mutex_unlock(&worker->lock);
            
            service_on_main_thread(worker);
            
            ret = SUCCESS;
        }
        else
        {
            worker->return_code = SERVICE_ALREADY_RUNNING;
            mutex_unlock(&worker->lock);

            log_warn("service_start: %s worker #%u already up and running", desc->name);

            // service worker already up : cannot main-thread run it
            ret = service_wait(desc);
        }
    }
    
    return ret;
}

/**
 * Set the status of all workers of the service to "STOP" and sends SIGUSR1 to
 * each of them.
 * 
 * The signal is meant to interrupt blocking IOs and the worker should notice
 * it 'in time' and finish.
 * 
 * @param desc the service
 * 
 * @return an error code
 */

int
service_stop(struct service_s *desc)
{
    log_debug("service: %s stop", desc->name);

    int err = SERVICE_NOT_RUNNING;
    
    for(u32 i = 0; i < desc->worker_count; i++)
    {
        struct service_worker_s *worker = &desc->worker[i];
        
        mutex_lock(&worker->lock);
        
        u8 f = worker->flags;

        if((f & (SERVICE_START|SERVICE_STOP)) == SERVICE_START)
        {
            worker->flags |= SERVICE_STOP;
            err = SUCCESS;
        }

        mutex_unlock(&worker->lock);
        
        if((f != 0) && (worker->tid != 0))
        {
            pthread_kill(worker->tid, SIGUSR1);
        }
    }
    
    return err;
}

/**
 * Waits for all threads of the service to be stopped.
 * 
 * @param desc the service descriptor
 * @return 
 */

int
service_wait(struct service_s *desc)
{
    log_debug("service: %s wait", desc->name);
    
    mutex_lock(&desc->wait_lock);
    for(;;)
    {
        u32 running = desc->worker_count;
        
        for(u32 i = 0; i < desc->worker_count; i++)
        {
            struct service_worker_s *worker = &desc->worker[i];

            mutex_lock(&worker->lock);
            u8 f = worker->flags;    
            mutex_unlock(&worker->lock);
            
            if(f == SERVICE_OFF)
            {
                running--;
            }
            else
            {
                if(pthread_kill(worker->tid, 0) != 0)
                {
                    log_err("service: %s thread %p died on us", desc->name, worker->tid);
                    running--;
                    mutex_lock(&worker->lock);
                    worker->flags = SERVICE_OFF;
                    mutex_unlock(&worker->lock);
                }
                else
                {
                    // if the worker is meant to stop but is not stopping yet, then signal it
                    
                    if((worker->flags & (SERVICE_STOP|SERVICE_STOPPING)) == SERVICE_STOP)
                    {
                        pthread_kill(worker->tid, SIGINT);
                    }
                }
            }
        }
        
        if(running == 0)
        {
            break;
        }
        
        cond_wait(&desc->wait_cond, &desc->wait_lock);

        log_debug("service: %s wait ... (%u/%u running)", desc->name, running, desc->worker_count);
    }
    mutex_unlock(&desc->wait_lock);
    
    for(u32 i = 0; i < desc->worker_count; i++)
    {
        struct service_worker_s *worker = &desc->worker[i];
        
        if(worker->tid == 0)
        {
            continue;
        }
        
        log_debug("service: %s join ... (%u/%u)", desc->name, i, desc->worker_count);
        
        int err = pthread_join(worker->tid, NULL);
        
        switch(err)
        {
            case 0:
            {
                // success
                break;
            }
            case EINVAL:
            {
                log_err("service: %s thread %p is not joinable", desc->name, worker->tid);
                break;
            }
            case ESRCH:
            {
                log_debug("service: %s thread %p does not exist", desc->name, worker->tid);
                break;
            }
            case EDEADLK:
            {
                log_err("service: %s thread %p is deadlocked", desc->name, worker->tid);
                break;
            }
            default:
            {
                log_warn("service: %s thread %p joining returned an unexpected error code %i", desc->name, worker->tid, err);
            }
        }
        
        worker->flags = 0;
        worker->tid = 0;
    }
    
    log_debug("service: %s all %u workers are stopped", desc->name, desc->worker_count);
    
    return 0;
}

/**
 * Returns TRUE if all the workers of the service have notified they had started
 * 
 * @param desc the service
 * @return TRUE iff all the workers of the service have notified they started
 */

bool
service_servicing(struct service_s *desc)
{
    for(u32 i = 0; i < desc->worker_count; i++)
    {
        struct service_worker_s *worker = &desc->worker[i];

        mutex_lock(&worker->lock);
        u8 f = worker->flags;    
        mutex_unlock(&worker->lock);

        if((f & (SERVICE_START|SERVICE_STOP|SERVICE_SERVICING|SERVICE_STOPPING)) != (SERVICE_START|SERVICE_SERVICING))
        {
            return FALSE;
        }
    }
    
    return TRUE;
}

/**
 * Only to be called by the worker of the service itself when it has started.
 * Calling it is not mandatory but give more accuracy to the status of the service.
 * 
 * @param worker the worker calling this function
 */

int
service_set_servicing(struct service_worker_s *worker)
{
    int err = SERVICE_NOT_RUNNING;
    
    log_debug("service: %s running", worker->service->name);
    
    mutex_lock(&worker->lock);
    if((worker->flags & (SERVICE_START|SERVICE_STOP)) == SERVICE_START)
    {
        worker->flags |= SERVICE_SERVICING;
        err = SUCCESS;
    }
    mutex_unlock(&worker->lock);
    
    return err;
}

/**
 * Returns TRUE if none of the workers of the service are running
 * 
 * @param desc the service
 * @return TRUE iff none of the workers of the service are running
 */

bool
service_stopped(struct service_s *desc)
{
    for(u32 i = 0; i < desc->worker_count; i++)
    {
        struct service_worker_s *worker = &desc->worker[i];

        mutex_lock(&worker->lock);
        u8 f = worker->flags;    
        mutex_unlock(&worker->lock);

        if(f != SERVICE_OFF)
        {
            return FALSE;
        }
    }
    
    return TRUE;
}

/**
 * Only to be called by the worker of the service itself when it is stopping.
 * Calling it is not mandatory but give more accuracy to the status of the service.
 * 
 * @param worker the worker calling this function
 */

int
service_set_stopping(struct service_worker_s *worker)
{
    int err = SERVICE_NOT_RUNNING;
    
    log_debug("service: %s stopping", worker->service->name);
    
    mutex_lock(&worker->lock);
    if((worker->flags & SERVICE_STOP) != 0)
    {
        worker->flags |= SERVICE_STOPPING;
        worker->flags &= ~SERVICE_SERVICING;
        err = SUCCESS;
    }
    mutex_unlock(&worker->lock);
    
    return err;
}

/**
 * Waits until all workers have notified they were servicing.
 * Calling this on a service that does not call service_set_servicing will
 * potentially wait forever (or until the program is shutting down).
 * 
 * @param desc the service
 * @return an error code
 */

ya_result
service_wait_servicing(struct service_s *desc)
{
    while(service_started(desc))
    {
        if(service_servicing(desc))
        {
            return SUCCESS;
        }
        else
        {
            if(dnscore_shuttingdown())
            {
                return STOPPED_BY_APPLICATION_SHUTDOWN;
            }
            
            sleep(1);
        }
    }
    
    return SERVICE_NOT_RUNNING;
}

int
service_shouldrun(struct service_worker_s *worker)
{
    mutex_lock(&worker->lock);
    u8 f = worker->flags;    
    mutex_unlock(&worker->lock);
    
    time_t now = time(NULL);
    
    worker->last_seen_alive = now;
    worker->service->last_seen_alive = now;
    
    return (f & (SERVICE_START | SERVICE_STOP)) == SERVICE_START;
}

int
service_check_all_alive()
{
    time_t now = time(NULL);
    
    mutex_lock(&service_set_mutex);
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&service_set, &iter);
    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        struct service_s *desc = (struct service_s *)node->key;
        
        if(desc->last_seen_alive > 0)
        {
            s32 adt = now - desc->last_seen_alive;
            
            if(adt > 5)
            {
                log_warn("service '%s' has not been seen alive for %u seconds", desc->name, adt);

                for(u32 i = 0; i < desc->worker_count; i++)
                {
                    adt = now - desc->worker[i].last_seen_alive;

                    if(adt > 5)
                    {
                        log_warn("service '%s' worker #%u has not been seen alive for %u seconds", desc->name, i, adt);
                    }
                }
            }
        }
        else
        {
            // not started yet
            // ignore it
        }
    }
    
    mutex_unlock(&service_set_mutex);
    
    return SUCCESS;
}

/**
 * Appends all services references to the array.
 * 
 * Services are supposed to be defined statically.
 * Their reference will never point to an unmapped space.
 * 
 * @param services a pointer to the ptr_vector to append the services to
 * @return the number of services added to the vector
 */

int
service_get_all(ptr_vector *services)
{
    int ret = 0;
    mutex_lock(&service_set_mutex);
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&service_set, &iter);
    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        struct service_s *desc = (struct service_s *)node->key;
        
        ptr_vector_append(services, desc);
        ++ret;
    }
    
    return ret;
}

struct service_worker_s*
service_worker_get_sibling(const struct service_worker_s* worker, u32 idx)
{
    if(worker != NULL)
    {
        if(worker->service != NULL)
        {
            if(worker->service->worker_count > idx)
            {
                return &worker->service->worker[idx];
            }
        }
    }
    
    return NULL;
}

struct service_worker_s*
service_get_worker(const struct service_s *service, u32 idx)
{
    if(service != NULL)
    {
        if(service->worker_count > idx)
        {
            return &service->worker[idx];
        }
    }
    
    return NULL;
}


void
service_signal_worker(const struct service_s *service, u32 idx, int signo)
{
    if(service != NULL)
    {
        if(service->worker_count > idx)
        {
            struct service_worker_s* worker = &service->worker[idx];
            
            if(worker->tid != 0)
            {
                pthread_kill(worker->tid, signo);
            }
        }
    }
}

void
service_signal_all_workers(const struct service_s *service, int signo)
{
    if(service != NULL)
    {
        for(u32 i = 0; i < service->worker_count; i++)
        {
            struct service_worker_s *worker = &service->worker[i];

            if(worker->tid == 0)
            {
                continue;
            }

            pthread_kill(worker->tid, signo);
        }
    }
}

void
service_stop_all()
{
    mutex_lock(&service_set_mutex);
    ptr_set_avl_iterator iter;
    
    ptr_set_avl_iterator_init(&service_set, &iter);
    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        struct service_s *desc = (struct service_s *)node->key;
    
        log_debug("service_stop_all: stop '%s'", STRNULL(desc->name));
        
        service_stop(desc);    
    }
    
    ptr_set_avl_iterator_init(&service_set, &iter);
    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        struct service_s *desc = (struct service_s *)node->key;
    
        log_debug("service_stop_all: wait '%s'", STRNULL(desc->name));
        
        service_wait(desc);    
    }
    
    mutex_unlock(&service_set_mutex);
}

void
service_start_all()
{
    mutex_lock(&service_set_mutex);
    ptr_set_avl_iterator iter;
    
    ptr_set_avl_iterator_init(&service_set, &iter);
    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        struct service_s *desc = (struct service_s *)node->key;
    
        log_debug("service_start_all: start '%s'", STRNULL(desc->name));
        
        service_start(desc);    
    }
    mutex_unlock(&service_set_mutex);
}

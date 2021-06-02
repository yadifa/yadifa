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

#include "dnscore/dnscore-config.h"

#if HAS_PTHREAD_SETNAME_NP
#if DEBUG
#define _GNU_SOURCE 1
#endif
#endif

#include <unistd.h>

#include <dnscore/thread.h>

#include "dnscore/ptr_set.h"
#include "dnscore/logger.h"
#include "dnscore/thread_pool.h"

#include "dnscore/service.h"
#include "dnscore/thread.h"
#include "dnscore/signals.h"

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#define SERVICE_WAKE_USING_SIGUSR2 0 // don't use signals

static int service_ptr_set_compare(const void *node_a, const void *node_b)
{
    
    struct service_s *a = (struct service_s *)node_a;
    struct service_s *b = (struct service_s *)node_b;
    
    return strcmp(a->name, b->name);
}

static ptr_set service_set = {NULL, service_ptr_set_compare};
static mutex_t service_set_mutex = MUTEX_INITIALIZER;

static noreturn void*
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

    thread_set_name(desc->name, worker->worker_index, worker->service->worker_count);

    if(worker->service->worker_count == 1)
    {
#if DNSCORE_HAS_LOG_THREAD_TAG
        char service_tag[9];
        service_tag[8] = '\0';
        thread_make_tag(desc->name, worker->worker_index, desc->worker_count, service_tag);
        logger_handle_set_thread_tag(service_tag);

        log_debug("service: %s tagged '%s' (pid=%i, thread=%p)", desc->name, service_tag, getpid(), thread_self());
#endif
        log_debug("service: %s starting", desc->name);
    }
    else
    {
#if DNSCORE_HAS_LOG_THREAD_TAG
        char service_tag[9];
        service_tag[8] = '\0';
        thread_make_tag(desc->name, worker->worker_index, desc->worker_count, service_tag);
        logger_handle_set_thread_tag(service_tag);

        log_debug("service: %s tagged '%s' (pid=%i, thread=%p) (%i/%i)", desc->name, service_tag, getpid(), thread_self(), worker->worker_index + 1, worker->service->worker_count);
#endif
        log_debug("service: %s starting (%i/%i)", desc->name, worker->worker_index + 1, worker->service->worker_count);
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

#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_clear_thread_tag();
#endif
    
    thread_exit(NULL);

    // unreachable
    // return NULL;
}

static void*
service_on_main_thread(void *args)
{
    struct service_worker_s *worker = (struct service_worker_s *)args;

    if(worker == NULL)
    {
        log_err("service: with NULL worker");

        return NULL;
    }

    if(worker->service == NULL)
    {
        log_err("service: worker not linked to a service");

        return NULL;
    }

    if(worker->service->entry_point == NULL)
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

    thread_set_name(desc->name, 0, 0);

#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_set_thread_tag(desc->name);
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

#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_clear_thread_tag();
#endif



    return NULL;
}

static void service_wakeup_no_operation(struct service_s *desc)
{
    (void)desc;
}

/**
 * Initialises service with an entry point, a name, and a number of workers
 * Each worker will know its index (from 0 to count-1).
 * No threads are started yet after this call.
 * 
 * @param desc the service
 * @param entry_point the function of the service, it must be of the type service_main
 * @param wakeup_function a function that will wakup-up all the workers of the service (e.g. so they can notice a reconfiguration or shutdown)
 * @param name the name of the service
 * @param count the number of workers for the service
 * @return an error code
 */

int
service_init_ex2(struct service_s *desc, service_main *entry_point, service_wakeup *wakeup_function, const char* name, u32 count)
{
    if(count == 0)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    mutex_lock(&service_set_mutex);
    bool already_initialised = !desc->_not_initialised;
    mutex_unlock(&service_set_mutex);

    if(already_initialised)
    {
        log_debug("service: %s instance %p already initialized", name, desc);
        return SERVICE_ALREADY_INITIALISED;
    }

    mutex_init(&desc->wait_lock);
    cond_init(&desc->wait_cond);
    
    desc->name = (char*)name;
    
    mutex_lock(&service_set_mutex);
    ptr_node *node = ptr_set_find(&service_set, desc);
    mutex_unlock(&service_set_mutex);
    
    if(node == NULL)
    {
        log_debug("service: %s init %i workers", name, count);

        desc->entry_point = entry_point;
        desc->wakeup_all_workers = wakeup_function;
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

        desc->args = NULL;

        mutex_lock(&service_set_mutex);
        desc->_not_initialised = FALSE;
        ptr_set_insert(&service_set, desc);
        mutex_unlock(&service_set_mutex);
        
        return SUCCESS;
    }
    else
    {
        log_err("service: %s instance %p already initialized, but marked as if not", name, desc);

        return SERVICE_ALREADY_INITIALISED;
    }
}

/**
 * Initialises service with an entry point, a name, and a number of workers
 * Each worker will know its index (from 0 to count-1).
 * No threads are started yet after this call.
 *
 * @param desc the service
 * @param entry_point the function of the service, it must be of the type service_main
 * @param wakeup_function a function that will wakup-up all the workers of the service (e.g. so they can notice a reconfiguration or shutdown)
 * @param name the name of the service
 * @param count the number of workers for the service
 * @return an error code
 */

int
service_init_ex(struct service_s *desc, service_main *entry_point, const char* name, u32 count)
{
    int ret = service_init_ex2(desc, entry_point, service_wakeup_no_operation, name, count);
    return ret;
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

bool
service_initialised(struct service_s *desc)
{
    return !desc->_not_initialised;
}

/**
 * Set service args.
 * 
 * @param desc a pointer to the service
 * @param args a pointer to the args
 */

void
service_args_set(struct service_s *desc, void *args)
{
    mutex_lock(&desc->wait_lock);
    desc->args = args;
    mutex_unlock(&desc->wait_lock);
}

/**
 * Get service args.
 * 
 * @param desc a pointer to the service
 *
 * @return a pointer to the args
 */

void*
service_args_get(struct service_s *desc)
{
    mutex_lock(&desc->wait_lock);
    void *ret = desc->args;
    mutex_unlock(&desc->wait_lock);
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
    ptr_set_delete(&service_set, desc);
    mutex_unlock(&service_set_mutex);

    mutex_lock(&desc->wait_lock);

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

    free(desc->name);
    desc->name = NULL;
    mutex_lock(&service_set_mutex);
    desc->_not_initialised = TRUE;
    mutex_unlock(&service_set_mutex);

    mutex_unlock(&desc->wait_lock);

    mutex_destroy(&desc->wait_lock);

    static const struct service_s dummy_uninitialised_service = UNINITIALIZED_SERVICE;
    *desc = dummy_uninitialised_service;
    
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

#if SERVICE_HAS_LAST_SEEN_ALIVE_SUPPORT
    u32 now = time(NULL);
    desc->last_seen_alive = now;
#endif

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
        

        if(thread_create(&worker->tid, service_thread, worker) == 0)
        {
            log_debug("service_start: worker %i created with id %p", i, worker->tid);

            success++;
        }
        else
        {
            int err = ERRNO_ERROR;

            mutex_lock(&worker->lock);

#if SERVICE_HAS_LAST_SEEN_ALIVE_SUPPORT
            worker->last_seen_alive = now;
#endif
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

#if SERVICE_HAS_LAST_SEEN_ALIVE_SUPPORT
        u32 now = time(NULL);
        desc->last_seen_alive = now;
#endif

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
 * Set the status of all workers of the service to "STOP" and sends SIGUSR2 to
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
        
#if SERVICE_WAKE_USING_SIGUSR2
        if((f != 0) && (worker->tid != 0))
        {
            thread_kill(worker->tid, SIGUSR2);
        }
#endif
    }

    desc->wakeup_all_workers(desc);
    
    return err;
}

/**
 * Set the status of all workers of the service to "RECONFIGURE" and sends SIGUSR2 to
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
service_reconfigure(struct service_s *desc)
{
    log_debug("service: %s stop", desc->name);

    int err = SERVICE_NOT_RUNNING;
    
    for(u32 i = 0; i < desc->worker_count; i++)
    {
        struct service_worker_s *worker = &desc->worker[i];
        
        mutex_lock(&worker->lock);
        
        u8 f = worker->flags;

        if((f & SERVICE_RECONFIGURE) != SERVICE_RECONFIGURE)
        {
            worker->flags |= SERVICE_RECONFIGURE;
            err = SUCCESS;
        }

        mutex_unlock(&worker->lock);
        
#if SERVICE_WAKE_USING_SIGUSR2
        if((f != 0) && (worker->tid != 0))
        {
            thread_kill(worker->tid, SIGUSR2);
        }
#endif
    }

    desc->wakeup_all_workers(desc);
    
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
    for(int tries = 0;;++tries)
    {
        u32 running = desc->worker_count;
        
        for(u32 i = 0; i < desc->worker_count; i++)
        {
            struct service_worker_s *worker = &desc->worker[i];
            mutex_lock(&worker->lock);
            u8 f = worker->flags;    
            thread_t tid = worker->tid;
            mutex_unlock(&worker->lock);
            
            if(f == SERVICE_OFF)
            {
                running--;
            }
            else
            {
                if(tid != 0)
                {
#ifndef WIN32
                    if(thread_kill(tid, 0) != 0)
                    {
                        log_err("service: %s thread %p died on us", desc->name, tid);
                        running--;
                        mutex_lock(&worker->lock);
                        worker->flags = SERVICE_OFF;
                        mutex_unlock(&worker->lock);
                    }
                    else
#endif
                    {
                        // if the worker is meant to stop but is not stopping yet, then signal it

                        if((worker->flags & (SERVICE_STOP|SERVICE_STOPPING)) == SERVICE_STOP)
                        {
                            if(tries > 0)
                            {
                                if(tries <= 2)
                                {
                                    log_warn("service: %s thread %p hasn't stopped yet ...", desc->name, tid);
#if DEBUG
                                    logger_flush();
#endif
                                    usleep_ex(500000);
                                }
                                else
                                {
                                    log_warn("service: %s thread %p is not stopping ...", desc->name, tid);
#if DEBUG
                                    logger_flush();
#endif
#ifndef WIN32
                                    thread_kill(tid, SIGINT);
#endif
                                }
                            }
                        }
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
        
        int err = thread_join(worker->tid, NULL);
        
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
                break;
            }
        }
        
        mutex_lock(&worker->lock);
        worker->flags = SERVICE_OFF;
        worker->tid = 0;
        mutex_unlock(&worker->lock);
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
 * Only to be called by the worker of the service itself when it has reconfigured.
 * Calling it is not mandatory but give more accuracy to the status of the service.
 * 
 * @param worker the worker calling this function
 */

int service_clear_reconfigure(struct service_worker_s *worker)
{
    int err = SERVICE_NOT_RUNNING;
    
    log_debug("service: %s reconfigured", worker->service->name);
    
    mutex_lock(&worker->lock);
    if((worker->flags & SERVICE_RECONFIGURE) != 0)
    {
        worker->flags &= ~SERVICE_RECONFIGURE;
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
service_should_run(struct service_worker_s *worker)
{
    mutex_lock(&worker->lock);
    u8 f = worker->flags;    
    mutex_unlock(&worker->lock);

#if SERVICE_HAS_LAST_SEEN_ALIVE_SUPPORT
    time_t now = time(NULL);
    mutex_lock(&worker->lock);
    worker->last_seen_alive = now;
    worker->service->last_seen_alive = now;
    mutex_unlock(&worker->lock);
#endif
    
    return (f & (SERVICE_START | SERVICE_STOP)) == SERVICE_START;
}

int
service_should_reconfigure(struct service_worker_s *worker)
{
    mutex_lock(&worker->lock);
    u8 f = worker->flags;    
    mutex_unlock(&worker->lock);

#if SERVICE_HAS_LAST_SEEN_ALIVE_SUPPORT
    time_t now = time(NULL);
    worker->last_seen_alive = now;
    worker->service->last_seen_alive = now;
#endif
    
    return (f & (SERVICE_START | SERVICE_STOP | SERVICE_STOPPING | SERVICE_RECONFIGURE)) == (SERVICE_START | SERVICE_RECONFIGURE);
}

int
service_should_reconfigure_or_stop(struct service_worker_s *worker)
{
    mutex_lock(&worker->lock);
    u8 f = worker->flags;    
    mutex_unlock(&worker->lock);

#if SERVICE_HAS_LAST_SEEN_ALIVE_SUPPORT
    time_t now = time(NULL);
    worker->last_seen_alive = now;
    worker->service->last_seen_alive = now;
#endif
    
    return f & (SERVICE_STOP | SERVICE_STOPPING | SERVICE_RECONFIGURE);
}

#if SERVICE_HAS_LAST_SEEN_ALIVE_SUPPORT
int
service_check_all_alive()
{
    time_t now = time(NULL);
    
    mutex_lock(&service_set_mutex);
    ptr_set_iterator iter;
    ptr_set_iterator_init(&service_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
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
#else
int
service_check_all_alive()
{
    // not available in release
    return SUCCESS;
}
#endif

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
    ptr_set_iterator iter;
    ptr_set_iterator_init(&service_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
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
service_stop_all()
{
    mutex_lock(&service_set_mutex);
    ptr_set_iterator iter;
    
    ptr_set_iterator_init(&service_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        struct service_s *desc = (struct service_s *)node->key;
    
        log_debug("service_stop_all: stop '%s'", STRNULL(desc->name));
        
        service_stop(desc);    
    }
    
    ptr_set_iterator_init(&service_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
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
    ptr_set_iterator iter;
    
    ptr_set_iterator_init(&service_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        struct service_s *desc = (struct service_s *)node->key;
    
        log_debug("service_start_all: start '%s'", STRNULL(desc->name));
        
        service_start(desc);    
    }
    mutex_unlock(&service_set_mutex);
}

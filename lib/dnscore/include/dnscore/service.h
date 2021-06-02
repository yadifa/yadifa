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

#ifndef SERVICE_H
#define	SERVICE_H

#include <dnscore/logger.h>
#include <dnscore/pace.h>
#include <dnscore/mutex.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef WIN32
#undef SERVICE_START
#undef SERVICE_STOP
#endif

#define SERVICE_OFF         0
#define SERVICE_START       1
#define SERVICE_SERVICING   2
#define SERVICE_STOP        4
#define SERVICE_STOPPING    8
#define SERVICE_RECONFIGURE 16  // tells the service should ensure its configuration matches the current one and act accordingly

#define SERVICE_HAS_LAST_SEEN_ALIVE_SUPPORT 0
  
// this macro checks the function succeeded,
// elses sends a general shutdown and returns
// meant to be used in a service for the *_init() calls

#define SHUTDOWN_RETURN_ON_FAIL(function__)\
    { int err; if(FAIL((err = function__()))) {        \
        log_err( #function__ ": failed with %r", err); \
        dnscore_shutdown();                            \
        return err;                                    \
    } }

#define SHUTDOWN_RETURN_ON_FAIL_WITH_ARGS(function__,...)\
    { int err; if(FAIL((err = function__(__VA_ARGS__)))) {        \
        log_err( #function__ "(" #__VA_ARGS__ "): failed with %r", err); \
        dnscore_shutdown();                            \
        return err;                                    \
    } }
    
struct service_s;
struct service_worker_s;
    
typedef int service_main(struct service_worker_s *);
typedef void service_wakeup(struct service_s *);

#if SERVICE_HAS_LAST_SEEN_ALIVE_SUPPORT
#define UNINITIALIZED_SERVICE {MUTEX_INITIALIZER, COND_INITIALIZER, NULL, NULL, NULL, NULL, 0, 0, NULL, TRUE}
#else
#define UNINITIALIZED_SERVICE {MUTEX_INITIALIZER, COND_INITIALIZER, NULL, NULL, NULL, NULL, 0, NULL, TRUE}
#endif

#define SRVCWRKR_TAG 0x524b525743565253

struct service_worker_s
{
    struct service_s *service;
    mutex_t lock;
    thread_t tid;
    u32 worker_index;
#if SERVICE_HAS_LAST_SEEN_ALIVE_SUPPORT
    volatile u32 last_seen_alive;
#endif
    volatile int return_code;
    volatile u8 flags;
};

struct service_s
{
    mutex_t wait_lock;
    cond_t wait_cond;
    service_main *entry_point;
    service_wakeup *wakeup_all_workers; // so they may act
    char *name;
    struct service_worker_s *worker;
    u32 worker_count;
#if SERVICE_HAS_LAST_SEEN_ALIVE_SUPPORT
    volatile u32 last_seen_alive;
#endif
    void *args; // private data for the service (initialised to NULL)
    bool _not_initialised;
};

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

int service_init(struct service_s *desc, service_main *entry_point, const char* name);

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

int service_init_ex(struct service_s *desc, service_main *entry_point, const char* name, u32 count);

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

int service_init_ex2(struct service_s *desc, service_main *entry_point, service_wakeup *wakeup_function, const char* name, u32 count);

/**
 * Set service args.
 * 
 * @param desc a pointer to the service
 * @param args a pointer to the args
 */

void service_args_set(struct service_s *desc, void *args);

/**
 * Get service args.
 * 
 * @param desc a pointer to the service
 *
 * @return a pointer to the args
 */

void* service_args_get(struct service_s *desc);

/**
 * Stops then waits for all workers of the service.
 * Then destroy the service and release its content.
 * 
 * @param desc the service
 * @return an error code
 */

int service_finalize(struct service_s *desc);

/**
 * Starts all workers of the service
 * If a worker is already running, it is left alone with undefined results.
 * A service should be fully stopped and waited on before being started again.
 * 
 * @param desc the service
 * @return an error code
 */

int service_start(struct service_s *desc);

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

int service_start_and_wait(struct service_s *desc);

/**
 * Set the status of all workers of the service to "STOP" and sends SIGUSR2 to
 * each of them.
 * 
 * The signal is meant to interrupt blocking IOs and the worker should notice
 * it 'in time' and finish.
 * 
 * @param desc the service
 * @return an error code
 */

int service_stop(struct service_s *desc);

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

int service_reconfigure(struct service_s *desc);

/**
 * Waits for all threads of the service to be stopped.
 * 
 * @param desc the service
 * @return an error code
 */

int service_wait(struct service_s *desc);

/**
 * Only to be called by the worker of the service itself when it has started.
 * Calling it is not mandatory but give more accuracy to the status of the service.
 * 
 * @param worker the worker calling this function
 */

int service_set_servicing(struct service_worker_s *worker);

/**
 * Only to be called by the worker of the service itself when it is stopping.
 * Calling it is not mandatory but give more accuracy to the status of the service.
 * 
 * @param worker the worker calling this function
 */

int service_set_stopping(struct service_worker_s *worker);

/**
 * Only to be called by the worker of the service itself when it has reconfigured.
 * Calling it is not mandatory but give more accuracy to the status of the service.
 * 
 * @param worker the worker calling this function
 */

int service_clear_reconfigure(struct service_worker_s *worker);

int service_should_run(struct service_worker_s *worker);

int service_should_reconfigure(struct service_worker_s *worker);

int service_should_reconfigure_or_stop(struct service_worker_s *worker);

/**
 * Returns TRUE if all the workers of the service have notified they are running
 * 
 * @param desc the service
 * @return TRUE iff all the workers of the service have notified they are running
 */

bool service_servicing(struct service_s *desc);

/**
 * Returns TRUE if none of the workers of the service are running
 * 
 * @param desc the service
 * @return TRUE iff none of the workers of the service are running
 */

bool service_stopped(struct service_s *desc);

/**
 * Waits until all workers have notified they were servicing.
 * Calling this on a service that does not call service_set_servicing will
 * potentially wait forever (or until the program is shutting down).
 * 
 * @param desc the service
 * @return an error code
 */

ya_result service_wait_servicing(struct service_s *desc);

bool service_initialised(struct service_s *desc);

static inline bool
service_started(struct service_s *desc)
{
    return !service_stopped(desc);
}

/**
 * check that all services/workers are alive
 * logs warnings when blocked-looking workers/services are found
 */

int service_check_all_alive();

/**
 * Appends all services references to the array.
 * 
 * Services are supposed to be defined statically.
 * Their reference will never point to an unmapped space.
 * 
 * @param services a pointer to the ptr_vector to append the services to
 * @return the number of services added to the vector
 */
int service_get_all(ptr_vector *services);

struct service_worker_s *service_worker_get_sibling(const struct service_worker_s *worker, u32 idx);

struct service_worker_s *service_get_worker(const struct service_s *service, u32 idx);

void service_stop_all();
void service_start_all();

#ifdef	__cplusplus
}
#endif

#endif	/* SERVICE_H */


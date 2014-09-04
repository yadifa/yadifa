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

#ifndef SERVICE_H
#define	SERVICE_H

#include <dnscore/mutex.h>
#include <dnscore/logger.h>

#include <dnscore/pace.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define SERVICE_OFF         0
#define SERVICE_START       1
#define SERVICE_SERVICING   2
#define SERVICE_STOP        4
#define SERVICE_STOPPING    8

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

#define UNINITIALIZED_SERVICE {NULL, NULL, NULL, 0, 0}

struct service_worker_s
{
    struct service_s *service;
    mutex_t lock;
    pthread_t tid;
    u32 worker_index;
    volatile u32 last_seen_alive;
    volatile int return_code;
    volatile u8 flags;
};

struct service_s
{
    service_main *entry_point;
    char* name;
    struct service_worker_s *worker;
    u32 worker_count;
    volatile u32 last_seen_alive;
};

int service_init(struct service_s *desc, service_main *entry_point, const char* name);
int service_init_ex(struct service_s *desc, service_main *entry_point, const char* name, u32 count);
int service_finalize(struct service_s *desc);
int service_start(struct service_s *desc);
int service_stop(struct service_s *desc);
int service_wait(struct service_s *desc);

/**
 * Only to be called by the service itself when it noticed it has to shut down.
 */
int service_set_servicing(struct service_worker_s *worker);
/**
 * Only to be called by the service itself when it noticed it has to shut down.
 */
int service_set_stopping(struct service_worker_s *worker);

int service_shouldrun(struct service_worker_s *worker);

bool service_servicing(struct service_s *desc);
bool service_stopped(struct service_s *desc);

ya_result service_wait_servicing(struct service_s *desc);

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

struct service_worker_s *service_worker_get_sibling(const struct service_worker_s *worker, u32 idx);

struct service_worker_s *service_get_worker(const struct service_s *service, u32 idx);

void service_signal_worker(const struct service_s *service, u32 idx, int signo);

void service_signal_all_workers(const struct service_s *service, int signo);

void service_stop_all();
void service_start_all();

#ifdef	__cplusplus
}
#endif

#endif	/* SERVICE_H */


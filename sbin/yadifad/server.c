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
 * @defgroup server Server
 * @ingroup yadifad
 * @brief Server initialisation and launch
 *
 *  Starts server
 *
 * @{
 *----------------------------------------------------------------------------*/

#define SERVER_C_

/** @note: here we define the variable that is holding the default logger handle for the current source file
 *         Such a handle should NEVER been set in an include file.
 */

#include "server_config.h"

#include <dnscore/sys_types.h>

#include <dnscore/logger.h>
#include <dnscore/fdtools.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/thread_pool.h>
#include <dnscore/ctrl_rfc.h>
#include <dnscore/service.h>
#include <dnscore/process.h>
#include <dnscore/socket_server.h>
#include <dnscore/error_state.h>
#include <sys/mman.h>

logger_handle_t *g_server_logger = LOGGER_HANDLE_SINK;
#define MODULE_MSG_HANDLE g_server_logger

#include "signals.h"
#include "database_service.h"
#include "log_query.h"
#include "server_sm.h"
#include "server_rw.h"
#if HAVE_SENDMMSG && !__OpenBSD__
#include "server_mm.h"
#endif
#if DNSCORE_HAS_CTRL
#include "server_rndc.h"
#endif
#include "notify.h"
#include "server_context.h"
#include "axfr.h"
#include "ixfr.h"
#include "process_class_ch.h"
#if HAS_DYNUPDATE_SUPPORT
#include "dynupdate_query_service.h"
#endif
#if HAS_CTRL
#include "ctrl.h"
#include "ctrl_query.h"

#endif
#if HAS_RRL_SUPPORT
#include "rrl.h"
#endif

#if HAS_EVENT_DYNAMIC_MODULE
#include "dynamic_module_handler.h"
#endif

void server_process_message_tcp_set_database(zdb_t *db);

/**
 * 20210922 edf -- this appears to be more efficient.  It may be enabled for production builds after thorough testing.
 */

#define SERVER_TCP_USE_LAZY_MAPPING                0

#define NETWORK_AUTO_RECONFIGURE_COUNTDOWN_DEFAULT 10

#define SVRPOOLB_TAG                               0x424c4f4f50525653

// DEBUG build: log debug 5 of incoming wire
#define DUMP_TCP_RECEIVED_WIRE                     0

// DEBUG build: log debug 5 of outgoing wire
#define DUMP_TCP_OUTPUT_WIRE                       0

#if SERVER_TCP_USE_LAZY_MAPPING
struct tcp_thread_memory_s
{
    // server_process_tcp_thread_parm parm;
    dns_message_with_buffer_t message_data __attribute__((aligned(64)));
    uint8_t                   pool_buffer[SERVER_POOL_BUFFER_SIZE] __attribute__((aligned(4096)));
    uint8_t                   padding_buffer[0x8000] __attribute__((aligned(4096)));
};

typedef struct tcp_thread_memory_s tcp_thread_memory_t;

#endif

static struct thread_pool_s *server_tcp_thread_pool = NULL;
struct thread_pool_s        *server_disk_thread_pool = NULL;
#if SERVER_TCP_USE_LAZY_MAPPING
static tcp_thread_memory_t *tcp_thread_memory = NULL;
static uint32_t             thread_memory_size = 0;
#endif

#include "server.h"
#include "server_dns_tcp.h"
#if HAS_DNS_OVER_TLS_SUPPORT
#include "server_dns_tls.h"
#endif

#if DEBUG_BENCH_FD && !DNSCORE_HAS_TCP_MANAGER
static debug_bench_s debug_accept;
static debug_bench_s debug_accept_reject;
static debug_bench_s debug_server_process_tcp_task;
static debug_bench_s debug_tcp_reply;
static debug_bench_s debug_tcp_read_size;
static debug_bench_s debug_tcp_read_message;
#endif

#define WAIT_TAG 0x54494157

struct wait_s
{
    mutex_t       mtx;
    cond_t        cond;
    volatile int  wait;
    volatile bool dontsleep;
};

typedef struct wait_s wait_t;

static void           wait_wake(wait_t *w)
{
    mutex_lock(&w->mtx);
    if(w->wait > 0)
    {
        w->wait = 0;
        cond_notify(&w->cond);
    }
    w->dontsleep = true;
    mutex_unlock(&w->mtx);
}

static void wait_wait(wait_t *w)
{
    mutex_lock(&w->mtx);
    ++w->wait;
    while(!w->dontsleep && (w->wait > 0))
    {
        cond_wait(&w->cond, &w->mtx);
    }
    mutex_unlock(&w->mtx);
}

static void wait_init(wait_t *w)
{
    mutex_init(&w->mtx);
    cond_init(&w->cond);
    w->wait = 0;
    w->dontsleep = false;
}

static wait_t *wait_new_instance()
{
    wait_t *w;
    ZALLOC_OBJECT_OR_DIE(w, wait_t, WAIT_TAG);
    wait_init(w);
    return w;
}

static void wait_finalise(wait_t *w)
{
    mutex_lock(&w->mtx);
    while(w->wait != 0)
    {
        cond_wait(&w->cond, &w->mtx);
    }
    w->wait = 0x80ffffff;
    w->dontsleep = true;
    mutex_unlock(&w->mtx);
}

static initialiser_state_t server_statistics_init_state = INITIALISE_STATE_INIT;

volatile int               program_mode = SA_CONT; /** @note must be volatile */

// #if !__linux__ || !HAVE_SENDMMSG
#if !HAVE_SENDMMSG || __OpenBSD__
static ya_result server_notsupported_query_loop(struct service_worker_s *worker)
{
    (void)worker;
    log_err("Model is not supported on this architecture.");
    return FEATURE_NOT_SUPPORTED;
}

static ya_result server_notsupported_context_init(int workers_per_interface)
{
    (void)workers_per_interface;
    log_err("Model is not supported on this architecture.");
    return FEATURE_NOT_SUPPORTED;
}
#endif

// #if !__unix__ || !(__linux__ && HAVE_SENDMMSG)
#if !HAVE_SENDMMSG || __OpenBSD__
static ya_result server_dns_init_instance_not_implemented(network_server_t *server)
{
    (void)server;
    return FEATURE_NOT_IMPLEMENTED_ERROR;
}
#endif

static server_init_instance_callback dns_udp_server_init_instance[] = {server_sm_init_instance,
#if __unix__
                                                                       server_rw_init_instance,
#else
                                                                       server_dns_init_instance_not_implemented,
#endif
#if HAVE_SENDMMSG && !__OpenBSD__
                                                                       server_mm_init_instance,
#else
                                                                       server_dns_init_instance_not_implemented,
#endif
                                                                       NULL};

/*******************************************************************************************************************
 *
 * TCP protocol
 *
 ******************************************************************************************************************/

/*******************************************************************************************************************
 *
 * Server init, load, start, stop and exit
 *
 ******************************************************************************************************************/

static struct service_s    server_service_handler = UNINITIALIZED_SERVICE;
static initialiser_state_t server_handler_init_state = INITIALISE_STATE_INIT;

#define NETWORK_SERVER_STACK_SIZE_MAX 16 // only 4 actually needed so far

static network_server_t network_server_stack[NETWORK_SERVER_STACK_SIZE_MAX] = {0};
static int              network_server_stack_index = -1;

static void             network_server_stack_clear() { network_server_stack_index = -1; }

static ya_result        network_server_stack_init_instance_push(ya_result (*init_instance)(network_server_t *))
{
    ya_result ret;
    if(network_server_stack_index <= NETWORK_SERVER_STACK_SIZE_MAX - 1)
    {
        ret = init_instance(&network_server_stack[++network_server_stack_index]);

        if(FAIL(ret))
        {
            --network_server_stack_index;
        }
    }
    else
    {
        ret = BUFFER_WOULD_OVERFLOW;
    }

    return ret;
}

static network_server_t *network_server_stack_at(int index)
{
    if((index >= 0) && (index <= network_server_stack_index))
    {
        return &network_server_stack[index];
    }
    else
    {
        return NULL;
    }
}

static int  network_server_stack_top() { return network_server_stack_index; }

static void server_network_finalise()
{
    for(int_fast32_t i = network_server_stack_top(); i >= 0; --i)
    {
        network_server_t *network_server = network_server_stack_at(i);
        const char       *name = network_server->vtbl->long_name();

        log_info("finalising network server '%s'", name);
        network_server->vtbl->finalise(network_server);
    }

    network_server_stack_clear();
}

static ya_result server_network_init()
{
    ya_result ret;

    if(FAIL(ret = server_context_create()))
    {
        return ret;
    }

    // push all the network servers on the dedicated stack

    network_server_stack_init_instance_push(server_dns_tcp_init_instance);
#if HAS_DNS_OVER_TLS_SUPPORT
    if((g_config->tls_cert != NULL) && (g_config->tls_key != NULL))
    {
        network_server_stack_init_instance_push(server_dns_tls_init_instance);
    }
#endif

    for(int_fast32_t i = 0; dns_udp_server_init_instance[i] != NULL; ++i)
    {
        if(i == g_config->network_model)
        {
            ya_result ret;

            ret = network_server_stack_init_instance_push(dns_udp_server_init_instance[i]);

            if(FAIL(ret))
            {
                log_err("network model %i cannot be instanced: %r", i, ret);

                // attempt to correct if the network_model isn't 0

                if(i != 0)
                {
                    g_config->network_model = 0;
                    i = -1;
                }
                else
                {
                    network_server_stack_clear();
                    return ret;
                }
            }
        }
    }

#if DNSCORE_HAS_CTRL
    network_server_stack_init_instance_push(server_rndc_init_instance);
#endif

    int network_server_index;
    for(network_server_index = 0; network_server_index <= network_server_stack_top(); ++network_server_index)
    {
        network_server_t *network_server = network_server_stack_at(network_server_index);
        const char       *name = network_server->vtbl->long_name();
        log_info("spawned %s", name);

        if(FAIL(ret = network_server->vtbl->configure(network_server)))
        {
            log_err("network server '%s' cannot be configured: %r", name, ret);
            break;
        }
    }

    if(FAIL(ret))
    {
        for(int_fast32_t i = network_server_index; i >= 0; --i)
        {
            network_server_t *network_server = network_server_stack_at(i);
            const char       *name = network_server->vtbl->long_name();
            log_info("finalising network server '%s'", name);
            network_server->vtbl->finalise(network_server);
        }

        network_server_stack_clear();
    }

    return ret;
}

static alarm_t   statistics_alarm = 0;

static ya_result server_run_statistics_alarm(void *arg, bool cancel)
{
    (void)arg;
    if(!cancel)
    {
        alarm_event_node_t *event = alarm_event_new(time(NULL) + 1, 0, server_run_statistics_alarm, NULL, 0, "query-statistics");
        alarm_set(statistics_alarm, event);
    }

    log_statistics();
    return SUCCESS;
}

/** @brief Startup server with all its processes
 *
 * Returns when all the servers are stopped (or an error occurred)
 */

static ya_result server_run(struct service_worker_s *worker)
{
    ya_result ret = SUCCESS;

    int       network_server_index;
    for(network_server_index = 0; network_server_index <= network_server_stack_top(); ++network_server_index)
    {
        network_server_t *network_server = network_server_stack_at(network_server_index);
        const char       *name = network_server->vtbl->long_name();

        if(FAIL(ret = network_server->vtbl->start(network_server)))
        {
            log_err("network server '%s' cannot be started: %r", name, ret);
            break;
        }
    }

    if(ISOK(ret))
    {
        statistics_alarm = alarm_open((const uint8_t *)"\020query-statistics");
        alarm_event_node_t *event = alarm_event_new(time(NULL) + 60, 0, server_run_statistics_alarm, NULL, 0, "query-statistics");
        alarm_set(statistics_alarm, event);
        --network_server_index;

        // wait to stop or reconfigure?
        wait_t *w = (wait_t *)service_args_get(worker->service);
        wait_wait(w);

        alarm_close(statistics_alarm);
        statistics_alarm = 0;
    }

    for(int_fast32_t i = network_server_index; i >= 0; --i)
    {
        network_server_t *network_server = network_server_stack_at(i);
        const char       *name = network_server->vtbl->long_name();

        log_info("stopping network server '%s'", name);
        network_server->vtbl->stop(network_server);
    }

    for(int_fast32_t i = network_server_index; i >= 0; --i)
    {
        network_server_t *network_server = network_server_stack_at(i);
        const char       *name = network_server->vtbl->long_name();

        log_info("joining network server '%s'", name);
        network_server->vtbl->join(network_server);
    }

    for(int_fast32_t i = network_server_index; i >= 0; --i)
    {
        network_server_t *network_server = network_server_stack_at(i);
        const char       *name = network_server->vtbl->long_name();

        log_info("de-configuring network server '%s'", name);
        network_server->vtbl->deconfigure(network_server);
    }

    return ret;
}

void       server_process_tcp_init();
void       server_process_tcp_finalize();

static int server_service_apply_configuration()
{
    int ret;

    if(ISOK(ret = server_network_init()))
    {
        if((server_tcp_thread_pool != NULL) && (((int)thread_pool_get_size(server_tcp_thread_pool) != g_config->max_tcp_queries)))
        {
            // the thread-pool size is wrong
            ya_result return_code;

            server_process_tcp_finalize();

            if(FAIL(return_code = thread_pool_resize(server_tcp_thread_pool, g_config->max_tcp_queries)))
            {
                return return_code;
            }

            server_process_tcp_init();

            if(return_code != g_config->max_tcp_queries)
            {
                log_err("could not properly set the TCP handlers");
                return INVALID_STATE_ERROR;
            }
        }

        if((server_tcp_thread_pool == NULL) && (g_config->max_tcp_queries > 0))
        {
            uint32_t max_thread_pool_size = thread_pool_get_max_thread_per_pool_limit();
            if(max_thread_pool_size < (uint32_t)g_config->max_tcp_queries)
            {
                log_warn("updating the maximum thread pool size to match the number of TCP queries (from %i to %i)", max_thread_pool_size, g_config->max_tcp_queries);
                thread_pool_set_max_thread_per_pool_limit(g_config->max_tcp_queries);
            }

            server_tcp_thread_pool = thread_pool_init_ex(g_config->max_tcp_queries, g_config->max_tcp_queries * 2, "svrtcp");

            if(server_tcp_thread_pool == NULL)
            {
                log_err("tcp thread pool init failed");

                return THREAD_CREATION_ERROR;
            }

            server_process_tcp_init();
        }

        if(FAIL(axfr_process_init()))
        {
            log_warn("disk thread pool init failed");
            return THREAD_CREATION_ERROR;
        }

        /* Initialises the TCP usage limit structure (It's global and defined at the beginning of server.c */

        log_debug("thread count by address: %i", g_config->thread_count_by_address);
    }

    return ret;
}

void        server_context_destroy();

static void server_service_deconfigure()
{
    /* Proper shutdown. All this could be simply dropped since it takes time for "nothing".
     * But it's good to check that nothing is broken.
     */
#if DEBUG
    log_info("server_service_deconfigure()");
#endif

    server_context_close();

    if((server_tcp_thread_pool != NULL) && (g_config->max_tcp_queries > 0))
    {
        log_info("destroying TCP pool");
        thread_pool_destroy(server_tcp_thread_pool);
        server_tcp_thread_pool = NULL;

        server_process_tcp_finalize();
    }

    log_info("destroying disk pool");
    axfr_process_finalise();

    log_info("clearing server context");

    /* Clear config struct and close all fd's */
    server_context_stop();

    log_info("destroying server context");

    server_context_destroy();
}

static void server_service_wake(struct service_s *service)
{
    wait_t *w = (wait_t *)service_args_get(service);
    wait_wake(w);
}

static int server_service_main(struct service_worker_s *worker)
{
    ya_result ret = SUCCESS;

    server_process_message_udp_set_database(g_config->database);
    server_process_message_tcp_set_database(g_config->database);

    service_set_servicing(worker);

    log_info("server starting with pid %lu", getpid_ex());

#if HAS_RRL_SUPPORT
    // Sets the RRL

    rrl_init();
#endif

    // initialises the statistics

    if(initialise_state_begin(&server_statistics_init_state))
    {
        log_statistics_init();
        initialise_state_ready(&server_statistics_init_state);
    }

#if HAS_EVENT_DYNAMIC_MODULE
    dynamic_module_settings();
#endif

    if(g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE)
    {
        log_info("unprocessable messages will be dumped to the logs as hexadecimal");
    }
    else
    {
        log_info("unprocessable messages will not be dumped to the logs as hexadecimal");
    }

    if(g_config->server_flags & SERVER_FL_ANSWER_FORMERR)
    {
        log_info("format-broken messages will be replied to");
    }
    else
    {
        log_info("format-broken messages will not be replied to");
    }

    /*
     * If not FE, or if we answer FE
     *
     * ... && (message_is_query(mesg) ??? and if the query number is > 0 ???
     */

    bool    reconfigure = true;

    int64_t network_setup_complain_last = 0;
    bool    network_worked_once = false;

    int     network_auto_reconfigure_countdown = NETWORK_AUTO_RECONFIGURE_COUNTDOWN_DEFAULT;

    while(service_should_run(worker))
    {
        if(reconfigure) // because we may not really have to reconfigure
        {
            if(ISOK(ret = server_service_apply_configuration()))
            {
                log_info("server setup ready");

                network_worked_once = true;

                service_clear_reconfigure(worker);

#if HAS_EVENT_DYNAMIC_MODULE
                dynamic_module_settings();
#endif
            }
            else
            {
                int64_t now = timeus();

                if((ret == MAKE_ERRNO_ERROR(EPIPE)) || (ret == MAKE_ERRNO_ERROR(EACCES)) || (ret == INVALID_STATE_ERROR))
                {
                    log_err("socket server connection broken");
                    dnscore_shutdown();
                    break;
                }

                if(ret == MAKE_ERRNO_ERROR(ENFILE))
                {
                    uint32_t count = host_address_count(g_config->listen) * g_config->thread_count_by_address;

                    log_err("insufficient file open limit. It should be bigger than %u", count + 1024);
                    dnscore_shutdown();
                    break;
                }

                if((now - network_setup_complain_last) > ONE_SECOND_US * 60)
                {
                    log_err("failed to setup the network: %r", ret);
                    network_setup_complain_last = now;

                    if(!network_worked_once)
                    {
                        if((ret == MAKE_ERRNO_ERROR(EADDRINUSE)) || (ret == MAKE_ERRNO_ERROR(EADDRNOTAVAIL)) || (ret == MAKE_ERRNO_ERROR(EPERM)))
                        {
                            dnscore_shutdown();
                            break;
                        }
                    }
                    else
                    {
                        ret = SUCCESS; //
                    }
                }

                server_service_deconfigure();

                if(ret == THREAD_CREATION_ERROR)
                {
                    log_err("it's likely that the number of allowed TCP connection (%i) is beyond this system capabilities", g_config->max_tcp_queries);
                    dnscore_shutdown();
                    break;
                }

                if(ret == MAKE_ERRNO_ERROR(EADDRNOTAVAIL))
                {
                    if(!network_worked_once && (socket_server_uid() != 0))
                    {
                        log_err(
                            "yadifad hasn't been started as root. This network error is irrecoverable: stopping the "
                            "server");
                        dnscore_shutdown();
                        break;
                    }
                    else
                    {
                        if(--network_auto_reconfigure_countdown == 0)
                        {
                            network_auto_reconfigure_countdown = NETWORK_AUTO_RECONFIGURE_COUNTDOWN_DEFAULT;

                            if(ISOK(yadifad_config_update(g_config->config_file)))
                            {
                                logger_reopen();

                                if(!server_context_matches_config())
                                {
                                    log_try_debug1("network configuration has changed");

                                    server_service_reconfigure();
                                }
                                else
                                {
                                    log_try_debug1("network configuration has not changed");
                                }
                            }
                        }
                    }
                }

                service_clear_reconfigure(worker);

                /// @todo 20210304 edf -- instead of a sleep, wait for a reconfigured/shutdown event
                sleep(1); // used to pace the system if something wrong happens

                continue;
            }
        }

        network_setup_complain_last = 0;

        if(FAIL(ret = server_run(worker)))
        {
            log_err("failed to start the server workers: %r", ret);
        }

        if(!service_should_run(worker))
        {
            server_service_deconfigure();
            break;
        }

        /// reconfigure = true;
        /// check if configuration has changed (difficult before cfgv3)

        if(reconfigure)
        {
            server_service_deconfigure();
        }
    } // while(service_should_run(worker))

    server_network_finalise();

#if HAS_RRL_SUPPORT
    rrl_finalize();
#endif

    service_set_stopping(worker);

    return ret;
}

/**
 * Initialises the DNS server service.
 *
 * @return
 */

ya_result server_service_init()
{
    ya_result ret = SERVICE_ALREADY_INITIALISED;

    tcp_manager_init();

    if(initialise_state_begin(&server_handler_init_state))
    {
        if(ISOK(ret = service_init_ex2(&server_service_handler, server_service_main, server_service_wake, "yadifad", 1)))
        {
            service_args_set(&server_service_handler, wait_new_instance());
            error_register(SUCCESS_DROPPED, "DROPPED");

#if DEBUG_BENCH_FD && !DNSCORE_HAS_TCP_MANAGER
            debug_bench_register(&debug_accept, "accept");
            debug_bench_register(&debug_accept_reject, "accept-reject");
            debug_bench_register(&debug_server_process_tcp_task, "process_tcp_task");
            debug_bench_register(&debug_tcp_reply, "tcp_reply");
            debug_bench_register(&debug_tcp_read_size, "tcp_read_size");
            debug_bench_register(&debug_tcp_read_message, "tcp_read_message");
#endif
            initialise_state_ready(&server_handler_init_state);
        }
        else
        {
            initialise_state_cancel(&server_handler_init_state);
        }
    }

    return ret;
}

bool      server_service_started() { return initialise_state_initialised(&server_handler_init_state) && !service_stopped(&server_service_handler); }

ya_result server_service_start()
{
    int err = SERVICE_NOT_INITIALISED;

    if(initialise_state_initialised(&server_handler_init_state))
    {
        if(service_stopped(&server_service_handler))
        {
            err = service_start(&server_service_handler);
        }
    }

    return err;
}

ya_result server_service_start_and_wait()
{
    int ret = SERVICE_NOT_INITIALISED;

    if(initialise_state_initialised(&server_handler_init_state))
    {
        if(service_stopped(&server_service_handler))
        {
            ret = service_start_and_wait(&server_service_handler);
        }
    }

    return ret;
}

ya_result server_service_wait()
{
    int ret = SERVICE_NOT_INITIALISED;
    if(initialise_state_initialised(&server_handler_init_state))
    {
        if(ISOK(ret = service_wait_servicing(&server_service_handler)))
        {
            ret = SERVICE_NOT_RUNNING;
            if(service_servicing(&server_service_handler))
            {
                ret = service_wait(&server_service_handler);
            }
        }
    }
    return ret;
}

ya_result server_service_stop_nowait()
{
    int err = SERVICE_NOT_INITIALISED;

    if(initialise_state_initialised(&server_handler_init_state))
    {
        err = SERVICE_NOT_RUNNING;
#if ZDB_HAS_PRIMARY_SUPPORT && ZDB_HAS_DYNUPDATE_SUPPORT
        dynupdate_query_service_reset();
#endif
        if(!service_stopped(&server_service_handler))
        {
            err = service_stop(&server_service_handler);
        }
    }

    return err;
}

ya_result server_service_stop()
{
    int err = SERVICE_NOT_INITIALISED;

    if(initialise_state_initialised(&server_handler_init_state))
    {
        err = SERVICE_NOT_RUNNING;
#if ZDB_HAS_PRIMARY_SUPPORT && ZDB_HAS_DYNUPDATE_SUPPORT
        dynupdate_query_service_reset();
#endif
        if(!service_stopped(&server_service_handler))
        {
            err = service_stop(&server_service_handler);
            service_wait(&server_service_handler);
        }
    }

    return err;
}

ya_result server_service_reconfigure()
{
    int err = SERVICE_NOT_INITIALISED;

    if(initialise_state_initialised(&server_handler_init_state))
    {
        err = SERVICE_NOT_RUNNING;

        if(!service_stopped(&server_service_handler))
        {
#if ZDB_HAS_PRIMARY_SUPPORT && ZDB_HAS_DYNUPDATE_SUPPORT
            dynupdate_query_service_reset();
#endif
            err = service_reconfigure(&server_service_handler);
        }
    }

    return err;
}

ya_result server_service_finalize()
{
    int err = SERVICE_NOT_INITIALISED;

    if(initialise_state_unready(&server_handler_init_state))
    {
        err = server_service_stop();

        wait_t *w = (wait_t *)service_args_get(&server_service_handler);
        wait_finalise(w);

        service_finalise(&server_service_handler);

        initialise_state_end(&server_handler_init_state);
    }

    return err;
}

/** @} */

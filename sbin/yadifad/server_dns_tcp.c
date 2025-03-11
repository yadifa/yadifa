/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 * @brief multithreaded reader-writer server
 *
 *  Multiples threads for UDP on a different socket per interface.
 *  One thread per interface for TCP, dispatching accepts to worker threads. (for now)
 *
 *  One weakness: every single test of a similar mechanism shows that this is MUCH slower than the simple "mt" model.
 *
 *              This is tested in hope that although the maximum throughput will be reduced, no packets will be lost
 *              in case of long DB locks.
 *
 *              As a side note, it is trivial that a different model of database would also solve the issue.
 *              The most obvious one being using two zones images, alternating the visible and edited one.
 *              This solution is of course unacceptable for a big zone as it greatly increases the resident memory
 *usage.
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
// keep this order -->
 *
 *----------------------------------------------------------------------------*/

#include "server_config.h"
#include <dnscore/dnscore_config_features.h>

#if __unix__
#ifndef __USE_GNU
#define __USE_GNU 1
#endif
#define _GNU_SOURCE 1

#include <sched.h>

#endif

// <-- keep this order

#include "server_context.h"

#include <dnscore/sys_types.h>
#include <dnscore/logger.h>
#include <dnscore/fdtools.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/dns_message.h>
#include <dnscore/timems.h>
#include <dnscore/thread_pool.h>
#include <dnscore/sys_get_cpu_count.h>
#include <dnscore/host_address.h>
#include <dnscore/process.h>
#include <dnscore/error_state.h>

#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb_zone_lock.h>

#define ZDB_JOURNAL_CODE          1

// #define THREAD_POOL_START_TIMEOUT (ONE_SECOND_US * 5)
#define THREAD_POOL_START_TIMEOUT (ONE_SECOND_US * 30)

#include <dnsdb/journal.h>

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
#include "dnsdb/zdb_zone_lock_monitor.h"
#endif

#include "server.h"
#include "server_context.h"
#include "log_query.h"
#include "rrl.h"
#include "process_class_ch.h"
#include "notify.h"
#include "log_statistics.h"
#include "signals.h"
#include "dynupdate_query_service.h"
#include "axfr.h"
#include "dnscore/tcp_manager2.h"

#if HAS_EVENT_DYNAMIC_MODULE
#include "dynamic_module_handler.h"
#endif

int server_process_channel_message(tcp_manager_channel_t *tmc, dns_message_t *mesg /*, server_statistics_t * const local_statistics*/, int svr_sockfd);

#define SVRPLBIN_TAG 0x4e49424c50525653
#define SVRPLBOT_TAG 0x544f424c50525653
#define RWNTCTXS_TAG 0x53585443544e5752
#define RWNTCTX_TAG  0x585443544e5752
#define NETTHCTX_TAG 0x585443485454454e

static error_state_t server_process_tcp_error_state = ERROR_STATE_INITIALIZER;

// note: MODULE_MSG_HANDLE is defined in server_error.h

struct network_thread_context_s
{
    network_thread_context_base_t base;

    // should be aligned with 64

    mutex_t mtx;
    cond_t  cond;

    // should be aligned with 64

#if __unix__
#if !USE_SERVER_STATISTICS_ATOMICS
    server_statistics_t statistics __attribute__((aligned(SERVER_L1_DATA_LINE_ALIGNED_SIZE)));
#endif
#else
    server_statistics_t statistics;
#endif
};

typedef struct network_thread_context_s network_thread_context_t;

struct server_dns_tcp_data_s
{
    struct service_s          service_handler;
    int                      *sockets;
    int                       socket_count;
    int                       thread_count_by_address;
    network_thread_context_t *contexts; // socket_count times
};

static struct server_dns_tcp_data_s server_dns_tcp_data = {UNINITIALIZED_SERVICE, NULL, 0, 0, NULL};

struct server_process_tcp_thread_parm
{
    tcp_manager_channel_t    *tmc;
    network_thread_context_t *ctx;
    dns_message_t            *mesg;
};

typedef struct server_process_tcp_thread_parm server_process_tcp_thread_parm;

static struct thread_pool_s                  *server_tcp_thread_pool = NULL;

static void server_dns_tcp_thread_context_init(network_thread_context_t *ctx, struct service_worker_s *worker, uint16_t sockfd_idx)
{
    assert(ctx != NULL);

    memset(ctx, 0, sizeof(network_thread_context_t));
    ctx->base.worker = worker;
    ctx->base.idx = sockfd_idx;
    ctx->base.sockfd = server_dns_tcp_data.sockets[sockfd_idx];
    // ctx->base.must_stop = false; // implicit with the memset
#if USE_SERVER_STATISTICS_ATOMICS
    ctx->base.statisticsp = log_statistics_get();
#else
    ctx->base.statisticsp = log_statistics_alloc_register();
#endif

    mutex_init(&ctx->mtx);
    cond_init(&ctx->cond);
}

static void server_dns_tcp_set_cpu_affinity(int index)
{
    int cpu_count = sys_get_cpu_count();
    if(cpu_count < 0)
    {
        cpu_count = 1;
    }

    int affinity_with = g_config->thread_affinity_base + (index * g_config->thread_affinity_multiplier);
    affinity_with += affinity_with / cpu_count;
    affinity_with %= cpu_count;
    log_info("server-dns-tcp: worker setting affinity with virtual cpu %i", affinity_with);

    thread_setaffinity(thread_self(), affinity_with);
}

ya_result server_process_tcp_init()
{
#if SERVER_TCP_USE_LAZY_MAPPING
    if(thread_memory_size == 0)
    {
        uint32_t thread_count = thread_pool_get_size(server_tcp_thread_pool);
        uint32_t tmp_thread_memory_size = thread_count * sizeof(tcp_thread_memory_t);
        void    *tmp_tcp_thread_memory = mmap(NULL, tmp_thread_memory_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

        if(tmp_tcp_thread_memory == MAP_FAILED)
        {
            return ERRNO_ERROR;
        }
#if DEBUG
        uint8_t *tcp_thread_memory_ptr = (uint8_t *)tmp_tcp_thread_memory;
        for(uint_fast64_t i = 0; i < tmp_thread_memory_size; i += 4096)
        {
            tcp_thread_memory_ptr[i] = 1;
        }
        madvise(tmp_tcp_thread_memory, tmp_thread_memory_size, MADV_DONTNEED);
#endif
        tcp_thread_memory = (tcp_thread_memory_t *)tmp_tcp_thread_memory;
        thread_memory_size = tmp_thread_memory_size;

        return SUCCESS;
    }
    else
    {
        return INVALID_STATE_ERROR;
    }
#else
    return SUCCESS;
#endif
}

void server_process_tcp_finalize()
{
#if SERVER_TCP_USE_LAZY_MAPPING
    if(thread_memory_size > 0)
    {
        munmap(tcp_thread_memory, thread_memory_size);
        thread_memory_size = 0;
        tcp_thread_memory = NULL;
    }
#endif
}

/**
 * Both TCP & TLS are using this
 */

static void server_process_channel_message_thread(void *parm)
{
    server_process_tcp_thread_parm *channel_message_parm = (server_process_tcp_thread_parm *)parm;
    tcp_manager_channel_t          *tmc = channel_message_parm->tmc;
    dns_message_t                  *mesg = channel_message_parm->mesg;
    server_process_channel_message(tmc, mesg /*, channel_message_parm->ctx->base.statisticsp*/, channel_message_parm->ctx->base.sockfd);
    tcp_manager_channel_release(tmc);
#if DNS_MESSAGE_HAS_POOL
    free(dns_message_get_pool_buffer(mesg));
    dns_message_set_pool_buffer(mesg, NULL, 0);
#endif
    dns_message_delete(mesg);
    ZFREE_OBJECT(channel_message_parm);
}

void server_process_channel_thread(void *parm)
{
    /** forever :
     * _ read the next message
     *   => not read idle anymore
     * _ send message to processing
     * _ mark as read idle
     */
#if DEBUG
    log_debug("tcp: begin");
#endif
    server_process_tcp_thread_parm *channel_parm = (server_process_tcp_thread_parm *)parm;

#if DEBUG
    log_debug("tcp: processing stream from %{sockaddr}", &channel_parm->tmc->ss.sa);
#endif

#if DEBUG_BENCH_FD && !DNSCORE_HAS_TCP_MANAGER
    uint64_t bench = debug_bench_start(&debug_server_process_tcp_task);
#endif

    ya_result ret;
    mutex_init(&channel_parm->ctx->mtx);

    dns_message_t *mesg;

    for(;;)
    {
        /*#if SERVER_TCP_USE_LAZY_MAPPING
                uint32_t thread_index = thread_pool_thread_index_get();
                tcp_thread_memory_t *thread_memory = &tcp_thread_memory[thread_index];
                dns_message_t *mesg = message_data_with_buffer_init(&thread_memory->message_data); // tcp
                pool_buffer = &thread_memory->pool_buffer[0];
        */
        // = dns_message_data_with_buffer_init(&mesg_buff); // tcp
        mesg = dns_message_new_instance_ex(NULL, NETWORK_BUFFER_SIZE);

        dns_message_copy_sender_from_sa(mesg, &channel_parm->tmc->ss.sa, channel_parm->tmc->ss_len);

        ret = channel_parm->tmc->vtbl->read(channel_parm->tmc, mesg);

        if(ret <= 0) // error or EOF
        {
            break;
        }

        if(dnscore_shuttingdown())
        {
            break;
        }

#if DNS_MESSAGE_HAS_POOL
        size_t   pool_buffer_size = SERVER_POOL_BUFFER_SIZE; // 128KB
        uint8_t *pool_buffer;
        MALLOC_OBJECT_ARRAY_OR_DIE(pool_buffer, uint8_t, pool_buffer_size, SVRPOOLB_TAG);
        dns_message_set_pool_buffer(mesg, pool_buffer, pool_buffer_size);
#endif

        server_process_tcp_thread_parm *channel_message_parm;
        ZALLOC_OBJECT_OR_DIE(channel_message_parm, server_process_tcp_thread_parm, TPROCPRM_TAG);
        channel_message_parm->tmc = channel_parm->tmc; // socket, rc = 1
        channel_message_parm->ctx = channel_parm->ctx; // server fd to find the ip back
        channel_message_parm->mesg = mesg;

        mesg = NULL;

        tcp_manager_channel_acquire(channel_parm->tmc);
        thread_pool_enqueue_call(server_tcp_thread_pool, server_process_channel_message_thread, channel_message_parm, NULL, "srvprcmsg");
    }

    dns_message_delete(mesg);
    mesg = NULL;

    tcp_manager_channel_release(channel_parm->tmc);
    /*
    #if SERVER_TCP_USE_LAZY_MAPPING
        formatln("thread: %p: madvise(%p, %d = %x, MADV_DONTNEED)", pthread_self(), thread_memory,
    (sizeof(tcp_thread_memory_t) + 4095) & ~4095, (sizeof(tcp_thread_memory_t) + 4095) & ~4095); madvise(thread_memory,
    (sizeof(tcp_thread_memory_t) + 4095) & ~4095, MADV_DONTNEED); #endif
    */
    ZFREE_OBJECT(channel_parm);

#if DEBUG
    log_debug("tcp: end");
#endif
}

void        tcp_manager_accept_epoll_wake_all();

static void server_dns_tcp_worker_wakeup(struct service_s *desc)
{
    (void)desc;

    for(uint_fast32_t i = 0; i < desc->worker_count; ++i)
    {
        struct service_worker_s  *worker = &desc->worker[i];
        network_thread_context_t *ctx = &server_dns_tcp_data.contexts[worker->worker_index];
        log_debug("server_dns_tcp_worker_wakeup: socket %i", ctx->base.sockfd);
        socketclose_ex(ctx->base.sockfd);
    }
}

static int server_dns_tcp_worker_thread(struct service_worker_s *worker)
{
    network_thread_context_t *ctx = &server_dns_tcp_data.contexts[worker->worker_index];

    ctx->base.idr = thread_self();

    int  sockfd = ctx->base.sockfd;

    bool log_statistics_enabled = (g_statistics_logger != NULL) && (g_config->server_flags & SERVER_FL_STATISTICS) != 0;

    log_debug("statistics are %s", (log_statistics_enabled) ? "enabled" : "disabled");

    if(log_statistics_enabled)
    {
        log_statistics_legend();
    }

    log_debug("server_dns_tcp_worker_thread(%i, %i): started", ctx->base.idx, sockfd);

    // fd_setnonblocking(sockfd);

    socketaddress_t sa;
    socklen_t       sa_len = sizeof(sa);
    getsockname(sockfd, &sa.sa, &sa_len);
    log_info("waiting to accept connections for %{sockaddr}", &sa);

    server_dns_tcp_set_cpu_affinity(ctx->base.idx);

    while(service_should_run(worker))
    {
        log_statistics();

        ya_result              ret;
        tcp_manager_channel_t *tmc;

        ret = tcp_manager_channel_accept(ctx->base.sockfd, &tmc);

        if(ISOK(ret))
        {
            TCPSTATS(tcp_input_count++);

            error_state_clear(&server_process_tcp_error_state, MODULE_MSG_HANDLE, MSG_NOTICE, "tcp: accept call");

            assert(tmc != NULL);

            log_debug("server_dns_tcp_accept: scheduling job");
            server_process_tcp_thread_parm *parm;
            ZALLOC_OBJECT_OR_DIE(parm, server_process_tcp_thread_parm, TPROCPRM_TAG);
            parm->tmc = tmc; // socket, rc = 1
            parm->ctx = ctx; // server fd to find the ip back

            thread_pool_enqueue_call(server_tcp_thread_pool, server_process_channel_thread, parm, NULL, "srvprctcp");
        }
        else
        {
            if(ret != MAKE_ERRNO_ERROR(ETIMEDOUT))
            {
                if((ret & 0xffff0000) == ERRNO_ERROR_BASE)
                {
                    if(error_state_log(&server_process_tcp_error_state, ret))
                    {
                        if((ret != MAKE_ERRNO_ERROR(EBADF)) || (ret == MAKE_ERRNO_ERROR(EBADF) && service_should_run(worker)))
                        {
                            log_err("tcp: accept returned %r", ret);
                        }
                    }
                }
            }

            TCPSTATS(tcp_overflow_count++);
        }
    }

    // fd_setblocking(sockfd);

#if DEBUG
    log_debug("server_dns_tcp_worker_thread(%i, %i): stopped", ctx->base.idx, sockfd);
#endif
    return SUCCESS;
}

static ya_result server_dns_tcp_deconfigure(network_server_t *server)
{
    // stop all connections from the TCP manager

    // There is no close all mechanism on this implementation.
    // tcp_manager_socket_close_all();
    //
    (void)server;
    service_stop(&server_dns_tcp_data.service_handler);
    service_finalise(&server_dns_tcp_data.service_handler);

    server_context_socket_close_multiple(server_dns_tcp_data.sockets, server_dns_tcp_data.socket_count);
    free(server_dns_tcp_data.sockets);
    server_dns_tcp_data.sockets = NULL;
    server_dns_tcp_data.socket_count = 0;

    if(server_tcp_thread_pool != NULL)
    {
        thread_pool_stop(server_tcp_thread_pool);
        thread_pool_destroy(server_tcp_thread_pool);
        server_tcp_thread_pool = NULL;
    }

    axfr_process_finalise();
    return SUCCESS;
}

static ya_result server_dns_tcp_configure(network_server_t *server)
{
    if(server->data != NULL)
    {
        // return INVALID_STATE_ERROR;
    }

    ya_result      ret;
    uint32_t       tcp_interface_count = server_context_tcp_interface_count();
    const uint32_t worker_per_interface = 1;
    int            socket_count = tcp_interface_count * worker_per_interface;
    if(socket_count <= 0)
    {
        return INVALID_STATE_ERROR;
    }
    int *sockets;
    MALLOC_OBJECT_ARRAY_OR_DIE(sockets, int, socket_count, SOCKET_TAG);
    for(uint_fast32_t i = 0; i < tcp_interface_count; ++i)
    {
        if(FAIL(ret = server_context_socket_open_bind_multiple(server_context_tcp_interface(i), SOCK_STREAM, true, &sockets[i * worker_per_interface], worker_per_interface)))
        {
            server_context_socket_close_multiple(sockets, i * worker_per_interface);
            free(sockets);
            return ret;
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

            server_context_socket_close_multiple(sockets, tcp_interface_count);
            free(sockets);
            return THREAD_CREATION_ERROR;
        }
    }

    if(FAIL(axfr_process_init()))
    {
        log_err("axfr disk thread pool init failed");

        if(server_tcp_thread_pool != NULL)
        {
            // set disk write thread pool for AXFR

            thread_pool_destroy(server_tcp_thread_pool);
            server_tcp_thread_pool = NULL;
        }

        server_context_socket_close_multiple(sockets, tcp_interface_count);
        free(sockets);
        return THREAD_CREATION_ERROR;
    }

    server_dns_tcp_data.sockets = sockets;
    server_dns_tcp_data.socket_count = socket_count;
    ret = service_init_ex2(&server_dns_tcp_data.service_handler, server_dns_tcp_worker_thread, server_dns_tcp_worker_wakeup, "srvtcp", socket_count);

    if(ISOK(ret))
    {
        MALLOC_OBJECT_ARRAY_OR_DIE(server_dns_tcp_data.contexts, network_thread_context_t, socket_count, NETTHCTX_TAG);

        for(int_fast32_t i = 0; i < socket_count; ++i)
        {
            server_dns_tcp_thread_context_init(&server_dns_tcp_data.contexts[i], service_get_worker(&server_dns_tcp_data.service_handler, i), i);
        }

        server->data = &server_dns_tcp_data;
    }
    else
    {
        server_dns_tcp_deconfigure(server);
    }

    return ret;
}

static ya_result server_dns_tcp_start(network_server_t *server)
{
    ya_result ret;
    assert(server->data == &server_dns_tcp_data);
    (void)server;
    ret = service_start(&server_dns_tcp_data.service_handler);
    return ret;
}

static ya_result server_dns_tcp_join(network_server_t *server)
{
    ya_result ret;
    assert(server->data == &server_dns_tcp_data);
    (void)server;
    ret = service_wait(&server_dns_tcp_data.service_handler);
    return ret;
}

static ya_result server_dns_tcp_stop(network_server_t *server)
{
    ya_result ret;
    assert(server->data == &server_dns_tcp_data);
    (void)server;
    ret = service_stop(&server_dns_tcp_data.service_handler);
    return ret;
}

static ya_result server_dns_tcp_finalise(network_server_t *server)
{
    assert(server->data == &server_dns_tcp_data);
    (void)server;
    network_server_t uninitialised = NETWORK_SERVICE_UNINITIALISED;
    *server = uninitialised;
    return 0;
}

static ya_result server_dns_tcp_state(network_server_t *server)
{
    assert(server->data == &server_dns_tcp_data);
    (void)server;
    return 0;
}

static const char                        *server_dns_tcp_long_name() { return "DNS over TCP server"; }

static const struct network_server_vtbl_s server_dns_tcp_vtbl = {server_dns_tcp_configure,
                                                                 server_dns_tcp_start,
                                                                 server_dns_tcp_join,
                                                                 server_dns_tcp_stop, // could return instantly, only waits in finalise & start
                                                                 server_dns_tcp_deconfigure,
                                                                 server_dns_tcp_finalise,
                                                                 server_dns_tcp_state,
                                                                 server_dns_tcp_long_name};

/**
 * Initialises the object, not the server
 */

ya_result server_dns_tcp_init_instance(network_server_t *server)
{
    server_dns_tcp_data.thread_count_by_address = MAX(g_config->thread_count_by_address, 1);
    server->data = &server_dns_tcp_data;
    server->vtbl = &server_dns_tcp_vtbl;
    return SUCCESS;
}

network_server_t *server_dns_tcp_new_instance()
{
    network_server_t *server;
    ZALLOC_OBJECT_OR_DIE(server, network_server_t, SVRINSTS_TAG);
    if(ISOK(server_dns_tcp_init_instance(server)))
    {
        return server;
    }
    else
    {
        ZFREE_OBJECT(server);
        return NULL;
    }
}

/**
 * @}
 */

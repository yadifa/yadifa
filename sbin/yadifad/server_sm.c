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

#if __unix__ || __APPLE__
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

#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb_zone_lock.h>

#define ZDB_JOURNAL_CODE 1

#include <dnsdb/journal.h>

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
#include "dnsdb/zdb_zone_lock_monitor.h"
#endif

#include "server.h"
#include "log_query.h"
#include "rrl.h"
#include "process_class_ch.h"
#include "notify.h"
#include "log_statistics.h"
#include "signals.h"
#include "dynupdate_query_service.h"

#if HAS_EVENT_DYNAMIC_MODULE
#include "dynamic_module_handler.h"
#endif

#define TRY_EPOLL 0
#define TRY_POLL  0

#if TRY_EPOLL
#include <sys/epoll.h>
#endif

#if TRY_POLL
#include <poll.h>
#endif

#define SVRPLBIN_TAG                              0x4e49424c50525653
#define SVRPLBOT_TAG                              0x544f424c50525653
#define SSMPOOLB_TAG                              0x424c4f4f504d5353
#define RWNTCTXS_TAG                              0x53585443544e5752
#define RWNTCTX_TAG                               0x585443544e5752
#define NETTHCTX_TAG                              0x585443485454454e

// allow an external definition of the backlog queue size and L1 parameters

#define NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT 3 // do NOT change this value

#ifndef SERVER_SM_L1_DATA_LINE_ALIGNED_SIZE

#define SERVER_SM_L1_DATA_LINE_ALIGNED_SIZE  128
#define SERVER_SM_L1_DATA_LINE_ALIGNED_SHIFT 7

#define SERVER_SM_PACKETS_AT_ONCE            1

#elif((1 << SERVER_SM_L1_DATA_LINE_ALIGNED_SHIFT) != SERVER_SM_L1_DATA_LINE_ALIGNED_SIZE)
#error "2^" TOSTRING(SERVER_SM_L1_DATA_LINE_ALIGNED_SHIFT) " != " TOSTRING(SERVER_SM_L1_DATA_LINE_ALIGNED_SIZE) " : please fix"
#endif

// DEBUG build: log debug level 5 of incoming wire
#define DUMP_UDP_SM_RECEIVED_WIRE 0

// DEBUG build: log debug 5 of outgoing wire
#define DUMP_UDP_SM_OUTPUT_WIRE   0

extern logger_handle_t *g_statistics_logger;

#define RWNTCTXS_TAG 0x53585443544e5752
#define RWNTCTX_TAG  0x585443544e5752

// note: MODULE_MSG_HANDLE is defined in server_error.h

struct network_thread_context_s
{
    network_thread_context_base_t base;

    // should be aligned with 64

    mutex_t mtx;
    cond_t  cond;

    // should be aligned with 64

#if __unix__
#else
    server_statistics_t statistics;
#endif
};

typedef struct network_thread_context_s network_thread_context_t;

struct server_sm_data_s
{
    struct service_s          service_handler;
    int                      *sockets;
    int                       socket_count;
    int                       thread_count_by_address;
    network_thread_context_t *contexts; // socket_count times
};

static struct server_sm_data_s server_sm_data = {UNINITIALIZED_SERVICE, NULL, 0, 0, NULL};

static void                    server_sm_thread_context_init(network_thread_context_t *ctx, struct service_worker_s *worker, uint16_t sockfd_idx)
{
    assert(ctx != NULL);

    memset(ctx, 0, sizeof(network_thread_context_t));
    ctx->base.worker = worker;
    ctx->base.idx = sockfd_idx;
    ctx->base.sockfd = server_sm_data.sockets[sockfd_idx];
    // ctx->base.must_stop = false
    //  ; // implicit with the memset
#if USE_SERVER_STATISTICS_ATOMICS
    ctx->base.statisticsp = log_statistics_get();
#else
    ctx->base.statisticsp = log_statistics_alloc_register();
#endif

    mutex_init(&ctx->mtx);
    cond_init(&ctx->cond);
}

static void server_sm_set_cpu_affinity(int index)
{
    int cpu_count = sys_get_cpu_count();
    if(cpu_count < 0)
    {
        cpu_count = 1;
    }

    int affinity_with = g_config->thread_affinity_base + (index * g_config->thread_affinity_multiplier);
    affinity_with += affinity_with / cpu_count;
    affinity_with %= cpu_count;
    log_info("server-sm: worker setting affinity with virtual cpu %i", affinity_with);

    thread_setaffinity(thread_self(), affinity_with);
}

static int server_sm_udp_worker_thread(struct service_worker_s *worker)
{
    network_thread_context_t *ctx = &server_sm_data.contexts[worker->worker_index];
#if !USE_SERVER_STATISTICS_ATOMICS
    uint64_t *udp_output_size_totalp = &ctx->base.statisticsp->udp_output_size_total;
#endif
    int fd = ctx->base.sockfd;

    log_debug("server_sm_udp_worker_thread(%i, %i): started", ctx->base.idx, fd);

    socketaddress_t sa;
    socklen_t       sa_len = sizeof(sa);
    getsockname(fd, &sa.sa, &sa_len);
    log_info("waiting for udp messages for %{sockaddr}", &sa);

    server_sm_set_cpu_affinity(ctx->base.idx);

#if DNS_MESSAGE_HAS_POOL
    uint8_t *pool_buffer;
    size_t   pool_buffer_size = 65536;
    MALLOC_OBJECT_ARRAY_OR_DIE(pool_buffer, uint8_t, pool_buffer_size, SSMPOOLB_TAG);
#endif

    dns_message_t *mesg;
    mesg = dns_message_new_instance();
#if DNS_MESSAGE_HAS_POOL
    dns_message_set_pool_buffer(mesg, pool_buffer, pool_buffer_size);
#endif
    dns_message_reset_control(mesg);
    tcp_set_recvtimeout(fd, 1, 0);

    for(;;)
    {
#if DEBUG
        log_debug("server_sm_udp_worker_thread(%i, %i): recvmsg", ctx->base.idx, fd);
#endif
        dns_message_recv_udp_reset(mesg);
        dns_message_reset_control_size(mesg);
        ya_result ret = dns_message_recv_udp(mesg, fd);
#if DEBUG
        log_debug("server_sm_udp_worker_thread(%i, %i): recvmsg: %i", ctx->base.idx, fd, ret);
#endif
        if(FAIL(ret))
        {
#if DEBUG
            int err = ERRNO_ERROR;
            log_debug("dns_message_recv_udp %i returned %i : %r", fd, ret, err);
#endif
            if(service_should_reconfigure_or_stop(ctx->base.worker))
            {
                log_debug("server_sm_udp_receiver_thread(%i, %i): will stop (reconfigure or stop)", ctx->base.idx, fd);
                break;
            }

            continue;
        }
#if DEBUG
        log_debug("server_sm_udp_worker_thread: received %u packets (DEBUG)", ret);
#endif
#if DNSCORE_MESSAGE_HAS_TIMINGS
        mesg->recv_us = timeus();
        log_debug("server_sm_udp_worker_thread: recvfrom: got %d bytes from %{sockaddr}", dns_message_get_size(mesg), dns_message_get_sender_sa(mesg));
#if DUMP_UDP_SM_RECEIVED_WIRE
        log_memdump_ex(g_server_logger, MSG_DEBUG5, mesg->buffer, n, 16, OSPRINT_DUMP_HEXTEXT);
#endif
#endif
        int32_t dest_port = sockaddr_inet_port(dns_message_get_sender_sa(mesg));

        if(dest_port > 0)
        {
            ya_result ret = server_process_message_udp((network_thread_context_base_t *)ctx, mesg);

            if(ISOK(ret))
            {
                // that message will be replied to
                ret = dns_message_send_udp(mesg, fd);

                if(ISOK(ret))
                {
#if USE_SERVER_STATISTICS_ATOMICS
                    log_statistics_atomic.udp_output_size_total += ret;
#else
                    *udp_output_size_totalp += ret;
#endif
                }
                else
                {
                    log_err("server-sm: could not reply though UDP (socket %i): %r", fd, ret);
                }
            }
            else
            {
                if(ret == SUCCESS_DROPPED) // should rename to SUCCESS_IGNORE
                {
                    //  ignore
#if DEBUG
                    log_debug("server_sm_udp_worker_thread: good-dropped %d bytes from %{sockaddr}", dns_message_get_size(mesg), dns_message_get_sender_sa(mesg));
                    dns_message_log(MODULE_MSG_HANDLE, LOG_INFO, mesg);
#endif
                }
                else if(ret == STOPPED_BY_APPLICATION_SHUTDOWN)
                {
#if DEBUG
                    log_debug("server_sm_udp_worker_thread: STOPPED_BY_APPLICATION_SHUTDOWN ?");
#endif
                    if(service_should_reconfigure_or_stop(ctx->base.worker))
                    {
#if DEBUG
                        log_debug("server_sm_udp_worker_thread: STOPPED_BY_APPLICATION_SHUTDOWN !");
#endif
                        /*
                         * GOTO!
                         *
                         * Break out of two loops
                         */

                        goto server_sm_udp_worker_thread_end;
                    }
                }
                else
                {
                    // something happened
#if DEBUG
                    log_debug("server_sm_udp_worker_thread: bad-dropped %d bytes from %{sockaddr}", dns_message_get_size(mesg), dns_message_get_sender_sa(mesg));
                    dns_message_log(MODULE_MSG_HANDLE, LOG_INFO, mesg);
#endif
                }
            }
        }
        else if(dest_port == 0)
        {
            log_err(
                "server-sm: error replying to message %04hx %{dnsname} %{dnstype} from %{sockaddr}: invalid "
                "destination port",
                ntohs(dns_message_get_id(mesg)),
                dns_message_get_canonised_fqdn(mesg),
                dns_message_get_query_type_ptr(mesg),
                mesg->_msghdr.msg_name);
        }
        else // if(dest_port < 0)
        {
            log_err("server-sm: error replying to message %04hx %{dnsname} %{dnstype} invalid IP family", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg));
        }

    } // for "ever" loop

server_sm_udp_worker_thread_end:

#if DEBUG
    log_debug("server_sm_udp_worker_thread(%i, %i): stopping", ctx->base.idx, fd);
#endif

#if TRY_EPOLL
    close_ex(epoll_fd);
#endif

#if DNS_MESSAGE_HAS_POOL
    free(pool_buffer);
    dns_message_set_pool_buffer(mesg, NULL, pool_buffer_size);
#endif

    dns_message_delete(mesg);

#if DEBUG
    log_debug("server_sm_udp_worker_thread(%i, %i): stopped", ctx->base.idx, fd);
#endif

    return 0;
}

static ya_result server_sm_deconfigure(network_server_t *server)
{
    (void)server;
    service_stop(&server_sm_data.service_handler);
    service_finalise(&server_sm_data.service_handler);

    server_context_socket_close_multiple(server_sm_data.sockets, server_sm_data.socket_count);
    free(server_sm_data.sockets);
    server_sm_data.sockets = NULL;
    server_sm_data.socket_count = 0;

    return SUCCESS;
}

static ya_result server_sm_configure(network_server_t *server)
{
    ya_result ret;
    uint32_t  tcp_interface_count = server_context_udp_interface_count();
    uint32_t  worker_per_interface = g_config->thread_count_by_address;
    int       socket_count = tcp_interface_count * worker_per_interface;
    int      *sockets;
    MALLOC_OBJECT_ARRAY_OR_DIE(sockets, int, socket_count, SOCKET_TAG);
    for(uint_fast32_t i = 0; i < tcp_interface_count; ++i)
    {
        if(FAIL(ret = server_context_socket_open_bind_multiple(server_context_tcp_interface(i), SOCK_DGRAM, true, &sockets[i * worker_per_interface], worker_per_interface)))
        {
            server_context_socket_close_multiple(sockets, i * worker_per_interface);
            free(sockets);
            return ret;
        }
    }

    server_sm_data.sockets = sockets;
    server_sm_data.socket_count = socket_count;

    ret = service_init_ex(&server_sm_data.service_handler, server_sm_udp_worker_thread, "srvudpsm", socket_count);

    if(ISOK(ret))
    {
        MALLOC_OBJECT_ARRAY_OR_DIE(server_sm_data.contexts, network_thread_context_t, socket_count, NETTHCTX_TAG);

        for(int_fast32_t i = 0; i < socket_count; ++i)
        {
            server_sm_thread_context_init(&server_sm_data.contexts[i], service_get_worker(&server_sm_data.service_handler, i), i);
        }

        server->data = &server_sm_data;
    }
    else
    {
        server_sm_deconfigure(server);
    }

    return ret;
}

static ya_result server_sm_start(network_server_t *server)
{
    (void)server;
    ya_result ret;
    ret = service_start(&server_sm_data.service_handler);
    return ret;
}

static ya_result server_sm_join(network_server_t *server)
{
    (void)server;
    ya_result ret;
    ret = service_wait(&server_sm_data.service_handler);
    return ret;
}

static ya_result server_sm_stop(network_server_t *server)
{
    (void)server;
    ya_result ret;
    ret = service_stop(&server_sm_data.service_handler);
    return ret;
}

static ya_result server_sm_finalise(network_server_t *server)
{
    network_server_t uninitialised = NETWORK_SERVICE_UNINITIALISED;
    *server = uninitialised;
    return 0;
}

static ya_result server_sm_state(network_server_t *server)
{
    (void)server;
    return 0;
}

static const char                        *server_sm_long_name() { return "UDP sendmsg DNS server"; }

static const struct network_server_vtbl_s server_sm_vtbl = {server_sm_configure,
                                                            server_sm_start,
                                                            server_sm_join,
                                                            server_sm_stop, // could return instantly, only waits in finalise & start
                                                            server_sm_deconfigure,
                                                            server_sm_finalise,
                                                            server_sm_state,
                                                            server_sm_long_name};

/**
 * Initialises the object, not the server
 */

ya_result server_sm_init_instance(network_server_t *server)
{
    server_sm_data.thread_count_by_address = g_config->thread_count_by_address;
    server->data = &server_sm_data;
    server->vtbl = &server_sm_vtbl;
    return SUCCESS;
}

network_server_t *server_sm_new_instance()
{
    network_server_t *server;
    ZALLOC_OBJECT_OR_DIE(server, network_server_t, SVRINSTS_TAG);
    if(ISOK(server_sm_init_instance(server)))
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

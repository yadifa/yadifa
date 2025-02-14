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
#include <dnscore/dnscore_config_features.h>

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
#include <dnscore/dns_message.h>
#include <dnscore/timems.h>
#include <dnscore/thread_pool.h>
#include <dnscore/sys_get_cpu_count.h>
#include <dnscore/host_address.h>
#include <dnscore/process.h>

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

#define SVRPLBIN_TAG                              0x4e49424c50525653
#define SVRPLBOT_TAG                              0x544f424c50525653
#define NETTHCTX_TAG                              0x585443485454454e

// allow an external definition of the backlog queue size and L1 parameters

#define NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT 3 // do NOT change this value

#define SERVER_MM_PACKETS_AT_ONCE                 16

// DEBUG build: log debug level 5 of incoming wire
#define DUMP_UDP_RW_RECEIVED_WIRE                 0

// DEBUG build: log debug 5 of outgoing wire
#define DUMP_UDP_RW_OUTPUT_WIRE                   0

extern logger_handle_t *g_statistics_logger;

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

struct server_mm_data_s
{
    struct service_s          service_handler;
    int                      *sockets;
    int                       socket_count;
    int                       thread_count_by_address;
    network_thread_context_t *contexts; // socket_count times
};

static struct server_mm_data_s server_mm_data = {UNINITIALIZED_SERVICE, NULL, 0, 0, NULL};

static void server_mm_thread_context_init(network_thread_context_t *ctx, struct service_worker_s *worker, uint16_t sockfd_idx)
{
    assert(ctx != NULL);

    memset(ctx, 0, sizeof(network_thread_context_t));
    ctx->base.worker = worker;
    ctx->base.idx = sockfd_idx;
    ctx->base.sockfd = server_mm_data.sockets[sockfd_idx];
    // ctx->base.must_stop = false; // implicit with the memset
#if USE_SERVER_STATISTICS_ATOMICS
    ctx->base.statisticsp = log_statistics_get();
#else
    ctx->base.statisticsp = log_statistics_alloc_register();
#endif

    mutex_init(&ctx->mtx);
    cond_init(&ctx->cond);
}

static void server_mm_set_cpu_affinity(int index)
{
    int cpu_count = sys_get_cpu_count();
    if(cpu_count < 0)
    {
        cpu_count = 1;
    }

    int affinity_with = g_config->thread_affinity_base + (index * g_config->thread_affinity_multiplier);
    affinity_with += affinity_with / cpu_count;
    affinity_with %= cpu_count;
    log_info("server-mm: worker setting affinity with virtual cpu %i", affinity_with);

    thread_setaffinity(thread_self(), affinity_with);
}

static int server_mm_udp_worker_thread(struct service_worker_s *worker)
{
    network_thread_context_t *ctx = &server_mm_data.contexts[worker->worker_index];
#if !USE_SERVER_STATISTICS_ATOMICS
    uint64_t *udp_output_size_totalp = &ctx->base.statisticsp->udp_output_size_total;
#endif
    ctx->base.idr = thread_self();

    int fd = ctx->base.sockfd;

    log_debug("server_mm_udp_worker_thread(%i, %i): started", ctx->base.idx, fd);

    socketaddress_t sa;
    socklen_t       sa_len = sizeof(sa);
    getsockname(fd, &sa.sa, &sa_len);
    log_info("waiting for udp messages for %{sockaddr}", &sa);

    server_mm_set_cpu_affinity(ctx->base.idx);

    // struct timespec read_timeout = { 1, 0};

    struct mmsghdr *udp_packets = NULL;
    struct mmsghdr *udp_packets_send = NULL;
    unsigned int    udp_packets_count = SERVER_MM_PACKETS_AT_ONCE;

    const size_t    packet_size = (g_config->edns0_max_size + 4095) & ~4095;
#if !DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
    uint8_t *packet_buffers = aligned_alloc(4096, udp_packets_count * packet_size);
#if DNS_MESSAGE_HAS_POOL
    uint8_t *pool_buffers = aligned_alloc(4096, udp_packets_count * packet_size);
#endif
#else // aligned_alloc isn't supported by the DNSCORE_HAS_MALLOC_DEBUG_SUPPORT feature
    uint8_t *packet_buffers = malloc(udp_packets_count * packet_size);
#if DNS_MESSAGE_HAS_POOL
    uint8_t *pool_buffers = malloc(udp_packets_count * packet_size);
#endif
#endif

    if(packet_buffers == NULL)
    {
        log_debug("server_mm_udp_worker_thread(%i, %i): out of memory", ctx->base.idx, fd);
        dnscore_shutdown();
        return MAKE_ERRNO_ERROR(ENOMEM);
    }

    dns_message_t **messages;
    MALLOC_OBJECT_ARRAY_OR_DIE(messages, dns_message_t *, udp_packets_count, SMMMSGS_TAG);
    MALLOC_OBJECT_ARRAY_OR_DIE(udp_packets, struct mmsghdr, udp_packets_count, MMSGHDR_TAG);
    MALLOC_OBJECT_ARRAY_OR_DIE(udp_packets_send, struct mmsghdr, udp_packets_count, MMSGHDR_TAG);

    for(uint_fast32_t i = 0; i < udp_packets_count; ++i)
    {
        messages[i] = dns_message_new_instance_ex(&packet_buffers[packet_size * i], packet_size);
#if DNS_MESSAGE_HAS_POOL
        dns_message_set_pool_buffer(messages[i], &pool_buffers[packet_size * i], packet_size);
#endif
        dns_message_reset_control(messages[i]);
        dns_message_copy_msghdr(messages[i], &udp_packets[i].msg_hdr);
        udp_packets[i].msg_len = 0;
    }

    for(;;)
    {
#if DEBUG
        log_debug("server_mm_udp_worker_thread(%i, %i): recvmmsg for %i packets", ctx->base.idx, fd, udp_packets_count);
#endif

        /// @note 20210107 edf -- recvmmsg timeout doesnt work as intended (cfr: man recvmmsg)
        ///                       a convoluted mechanism has been put in place to force getting out of the call when
        ///                       needed (search for "static const uint8_t dummy" in this file)

#if DEBUG_MM_BUFFERS
        for(uint_fast32_t i = 0; i < udp_packets_count; ++i)
        {
            log_info("packet[%2u] ctrl@%p/%u name@%p/%u iov@%p/%u iov[0]@%p/%u len=%u",
                     i,
                     udp_packets[i].msg_hdr.msg_control,
                     udp_packets[i].msg_hdr.msg_controllen,
                     udp_packets[i].msg_hdr.msg_name,
                     udp_packets[i].msg_hdr.msg_namelen,
                     udp_packets[i].msg_hdr.msg_iov,
                     udp_packets[i].msg_hdr.msg_iovlen,
                     udp_packets[i].msg_hdr.msg_iov->iov_base,
                     udp_packets[i].msg_hdr.msg_iov->iov_len,
                     udp_packets[i].msg_len);
        }
#endif
        int recvmmsg_ret = recvmmsg(fd, udp_packets, udp_packets_count, MSG_WAITFORONE, NULL /*&read_timeout*/);
#if DEBUG
        log_debug("server_mm_udp_worker_thread(%i, %i): recvmmsg: %i", ctx->base.idx, fd, recvmmsg_ret);
#endif
        if(recvmmsg_ret <= 0)
        {
            // note that due to an implementation detail (see BUGS in man recvmmsg) the errno code is unreliable

            int err = ERRNO_ERROR;

#if DEBUG
            log_info("recvmmsg %i returned %i : %r", fd, recvmmsg_ret, err);
#endif

            if(service_should_reconfigure_or_stop(ctx->base.worker))
            {
                log_debug("server_mm_udp_receiver_thread(%i, %i): will stop (reconfigure or stop)", ctx->base.idx, fd);
                break;
            }

            if(recvmmsg_ret == 0)
            {
                continue;
            }
            else
            {
                log_err("server_mm_udp_worker_thread(%i, %i): recvmmsg: %r", ctx->base.idx, fd, err);
                break;
            }
        }

        int udp_packets_index = 0;

#if DEBUG
        log_info("server_mm_udp_worker_thread: received %u packets (DEBUG)", recvmmsg_ret);
#endif

        for(int_fast32_t i = 0; i < recvmmsg_ret; ++i)
        {
            dns_message_t *mesg = messages[i];

            unsigned int   n = udp_packets[i].msg_len;

            if(n >= DNS_HEADER_LENGTH)
            {
                // this direct access to internals is unacceptable, I have to fix that

                mesg->_msghdr.msg_namelen = udp_packets[i].msg_hdr.msg_namelen;
                mesg->_msghdr.msg_controllen = udp_packets[i].msg_hdr.msg_controllen;
                mesg->_msghdr.msg_iov->iov_len = udp_packets[i].msg_len;
#if __FreeBSD__
                if(mesg->_msghdr.msg_controllen == 0)
                {
                    mesg->_msghdr.msg_control = NULL;
                }
                else
                {
                    mesg->_msghdr.msg_control = mesg->_msghdr_control_buffer;
                }
#endif

#if DNSCORE_MESSAGE_HAS_TIMINGS
                mesg->recv_us = timeus();
                log_debug("server_mm_udp_worker_thread: recvfrom: got %d bytes from %{sockaddr}", n, dns_message_get_sender_sa(mesg));
#if DUMP_UDP_RW_RECEIVED_WIRE
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

                        dns_message_copy_msghdr(messages[i], &udp_packets_send[udp_packets_index].msg_hdr);
                        ++udp_packets_index;
                    }
                    else
                    {
                        if(ret == SUCCESS_DROPPED) // should rename to SUCCESS_IGNORE
                        {
                            //  ignore
#if DEBUG
                            log_info("server_mm_udp_worker_thread: good-dropped %d bytes from %{sockaddr}", n, dns_message_get_sender_sa(mesg));
                            // DO NOT: message_log(MODULE_MSG_HANDLE, LOG_INFO, mesg);
#endif
                        }
                        else if(ret == STOPPED_BY_APPLICATION_SHUTDOWN)
                        {
#if DEBUG
                            log_info("server_mm_udp_worker_thread: STOPPED_BY_APPLICATION_SHUTDOWN ?");
#endif

                            if(service_should_reconfigure_or_stop(ctx->base.worker))
                            {
#if DEBUG
                                log_info("server_mm_udp_worker_thread: STOPPED_BY_APPLICATION_SHUTDOWN !");
#endif
                                /*
                                 * GOTO!
                                 *
                                 * Break out of two loops
                                 */

                                goto server_mm_udp_worker_thread_end;
                            }
                        }
                        else
                        {
                            // something happened
#if DEBUG
                            log_info("server_mm_udp_worker_thread: bad-dropped %d bytes from %{sockaddr}", n, dns_message_get_sender_sa(mesg));
                            dns_message_log(MODULE_MSG_HANDLE, LOG_INFO, mesg);
#endif
                        }
                    }
                }
                else if(dest_port == 0)
                {
                    log_err(
                        "server-mm: error replying to message %04hx %{dnsname} %{dnstype} from %{sockaddr}: invalid "
                        "destination port",
                        ntohs(dns_message_get_id(mesg)),
                        dns_message_get_canonised_fqdn(mesg),
                        dns_message_get_query_type_ptr(mesg),
                        mesg->_msghdr.msg_name);
                }
                else // if(dest_port < 0)
                {
                    log_err("server-mm: error replying to message %04hx %{dnsname} %{dnstype} invalid IP family", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg));
                } /*
                 else
                 {
                     log_err("server-mm: error replying to message %04hx %{dnsname} %{dnstype} from %{sockaddr}: %r",
                             ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg),
                 message_get_query_type_ptr(mesg), mesg->_msghdr.msg_name, ret);
                 }*/

            } // end of the block if n > DNS_HEADER_LENGTH
            else
            {
                // discard
            }
        } // for all packets received loop

        if(udp_packets_index > 0)
        {
            struct mmsghdr *udp_packets_send_queue = udp_packets_send;
#if DEBUG
            log_info("server_mm_udp_worker_thread: sending %u packets (DEBUG)", udp_packets_index);
#endif
            for(;;)
            {
                int sendmmsg_ret = sendmmsg(fd, udp_packets_send_queue, udp_packets_index, 0);

                if(sendmmsg_ret >= 0)
                {
#if DEBUG
                    log_info("server_mm_udp_worker_thread: sent %u packets (DEBUG)", sendmmsg_ret);
#endif
                    for(int_fast32_t i = 0; i < sendmmsg_ret; ++i)
                    {
#if USE_SERVER_STATISTICS_ATOMICS
                        log_statistics_atomic.udp_output_size_total += udp_packets_send_queue[i].msg_hdr.msg_iov->iov_len;
#else
                        *udp_output_size_totalp += udp_packets_send_queue[i].msg_hdr.msg_iov->iov_len;
#endif
                    }

                    udp_packets_index -= sendmmsg_ret;

                    if(udp_packets_index <= 0)
                    {
                        break;
                    }

                    udp_packets_send_queue += sendmmsg_ret;
                }
                else
                {
                    int err = errno;

                    if(err != EINTR)
                    {
                        log_err("server_mm_udp_worker_thread: send failed: %r", MAKE_ERRNO_ERROR(err));
                        break;
                    }
                }
            } // for(;;)
        }
        else
        {
            if(service_should_reconfigure_or_stop(ctx->base.worker))
            {
                log_debug("server_mm_udp_receiver_thread(%i, %i): will stop (reconfigure or stop) (send)", ctx->base.idx, fd);
                break;
            }
        }

        for(int_fast32_t i = 0; i < recvmmsg_ret; ++i)
        {
            // reset the input

            udp_packets[i].msg_hdr.msg_namelen = sizeof(((dns_message_t *)NULL)->_sender);
            udp_packets[i].msg_hdr.msg_iov->iov_len = packet_size;
            udp_packets[i].msg_hdr.msg_controllen = sizeof(((dns_message_t *)NULL)->_msghdr_control_buffer);
        }
    } // for "ever" loop

server_mm_udp_worker_thread_end:

#if DEBUG
    log_debug("server_mm_udp_worker_thread(%i, %i): stopping", ctx->base.idx, fd);
#endif

    free(udp_packets_send);
    free(udp_packets);
#if DNS_MESSAGE_HAS_POOL
    free(pool_buffers);
#endif
    free(packet_buffers);

    for(uint_fast32_t i = 0; i < udp_packets_count; ++i)
    {
        dns_message_delete(messages[i]);
    }

    free(messages);

#if DEBUG
    log_debug("server_mm_udp_worker_thread(%i, %i): stopped", ctx->base.idx, fd);
#endif
    return SUCCESS;
}

static void server_mm_wakeup(struct service_s *desc)
{
    log_info("server-mm: stopping the threads");

    uint32_t udp_interface_count = server_context_udp_interface_count();
    uint32_t worker_per_interface = g_config->thread_count_by_address;

    int      socket_count = udp_interface_count * worker_per_interface;
    if(socket_count <= 0)
    {
        return;
    }

    bool can_stop;

    do
    {
        for(uint_fast32_t i = 0; i < udp_interface_count; ++i)
        {
            for(uint_fast32_t j = 0; j < worker_per_interface; ++j)
            {
                // network_thread_context_t *context = &server_mm_data.contexts[i];

                // recvmmsg doesn't handle the timeout parameter in a very useful way (listed in the bugs section)
                // This unelegant code is a try to avoid using another system call to handle the issue.

                socketaddress_t     *sa = (socketaddress_t *)server_context_udp_interface(i)->ai_addr;

                static const uint8_t dummy[12] = {
                    0xff,
                    0xff,
                    0xff,
                    0xff, // id = ffff, 15<<OPCODE_SHIFT
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                };

                int sockfd;

                if(sa->sa.sa_family == AF_INET)
                {
                    if((sockfd = socket(AF_INET, SOCK_DGRAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_DGRAM))) >= 0)
                    {
                        for(;;)
                        {
                            log_debug("server-mm: thread #%i of UDPv4 interface: %{sockaddr} will be woken up by a message", j, sa);
                            int ret = sendto(sockfd, dummy, sizeof(dummy), 0, &sa->sa, sizeof(sa->sa4));
                            if(ret > 0)
                            {
                                break;
                            }
                            ret = ERRNO_ERROR;
                            if(ret != MAKE_ERRNO_ERROR(EINTR))
                            {
                                break;
                            }
                        }

                        socketclose_ex(sockfd);
                    }
                }
                else if(sa->sa.sa_family == AF_INET6)
                {
                    if((sockfd = socket(AF_INET6, SOCK_DGRAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_DGRAM))) >= 0)
                    {
                        for(;;)
                        {
                            log_debug("server-mm: thread #%i of UDPv6 interface: %{sockaddr} will be woken up by a message", j, sa);

                            int ret = sendto(sockfd, dummy, sizeof(dummy), 0, &sa->sa, sizeof(sa->sa6));
                            if(ret > 0)
                            {
                                break;
                            }
                            ret = ERRNO_ERROR;
                            if(ret != MAKE_ERRNO_ERROR(EINTR))
                            {
                                break;
                            }
                        }

                        socketclose_ex(sockfd);
                    }
                }
            }
        }

        can_stop = service_stopped(desc);
    } while(!can_stop);
}

static ya_result server_mm_deconfigure(network_server_t *server)
{
    (void)server;
    service_stop(&server_mm_data.service_handler);
    service_finalise(&server_mm_data.service_handler);

    server_context_socket_close_multiple(server_mm_data.sockets, server_mm_data.socket_count);
    free(server_mm_data.sockets);
    server_mm_data.sockets = NULL;
    server_mm_data.socket_count = 0;

    return SUCCESS;
}

static ya_result server_mm_configure(network_server_t *server)
{
    ya_result ret;
    uint32_t  udp_interface_count = server_context_udp_interface_count();
    uint32_t  worker_per_interface = g_config->thread_count_by_address;
    int       socket_count = udp_interface_count * worker_per_interface;
    if(socket_count <= 0)
    {
        return INVALID_STATE_ERROR;
    }
    int *sockets;
    MALLOC_OBJECT_ARRAY_OR_DIE(sockets, int, socket_count, SOCKET_TAG);
    for(uint_fast32_t i = 0; i < udp_interface_count; ++i)
    {
        if(FAIL(ret = server_context_socket_open_bind_multiple(server_context_udp_interface(i), SOCK_DGRAM, true, &sockets[i * worker_per_interface], worker_per_interface)))
        {
            server_context_socket_close_multiple(sockets, i * worker_per_interface);
            free(sockets);
            return ret;
        }
    }

    server_mm_data.sockets = sockets;
    server_mm_data.socket_count = socket_count;

    ret = service_init_ex2(&server_mm_data.service_handler, server_mm_udp_worker_thread, server_mm_wakeup, "srvudpmm", socket_count);

    if(ISOK(ret))
    {
        MALLOC_OBJECT_ARRAY_OR_DIE(server_mm_data.contexts, network_thread_context_t, socket_count, NETTHCTX_TAG);

        for(int_fast32_t i = 0; i < socket_count; ++i)
        {
            server_mm_thread_context_init(&server_mm_data.contexts[i], service_get_worker(&server_mm_data.service_handler, i), i);
        }

        server->data = &server_mm_data;
    }
    else
    {
        server_mm_deconfigure(server);
    }

    return ret;
}

static ya_result server_mm_start(network_server_t *server)
{
    (void)server;
    assert((server != NULL) && (server->data == &server_mm_data));

    ya_result ret;
    ret = service_start(&server_mm_data.service_handler);
    return ret;
}

static ya_result server_mm_join(network_server_t *server)
{
    (void)server;
    assert((server != NULL) && (server->data == &server_mm_data));

    ya_result ret;
    ret = service_wait(&server_mm_data.service_handler);
    return ret;
}

static ya_result server_mm_stop(network_server_t *server)
{
    (void)server;
    assert((server != NULL) && (server->data == &server_mm_data));

    ya_result ret;
    ret = service_stop(&server_mm_data.service_handler);
    return ret;
}

static ya_result server_mm_finalise(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_mm_data));

    network_server_t uninitialised = NETWORK_SERVICE_UNINITIALISED;
    *server = uninitialised;
    return 0;
}

static ya_result server_mm_state(network_server_t *server)
{
    (void)server;
    return 0;
}

static const char *server_mm_long_name() { return "UDP-sendmmsg DNS server"; }

static const struct network_server_vtbl_s server_mm_vtbl = {server_mm_configure,
                                                            server_mm_start,
                                                            server_mm_join,
                                                            server_mm_stop, // could return instantly, only waits in finalise & start
                                                            server_mm_deconfigure,
                                                            server_mm_finalise,
                                                            server_mm_state,
                                                            server_mm_long_name};

/**
 * Initialises the object, not the server
 */

ya_result server_mm_init_instance(network_server_t *server)
{
    server_mm_data.thread_count_by_address = MAX(g_config->thread_count_by_address, 1);
    server->data = &server_mm_data;
    server->vtbl = &server_mm_vtbl;
    return SUCCESS;
}

network_server_t *server_mm_new_instance()
{
    network_server_t *server;
    ZALLOC_OBJECT_OR_DIE(server, network_server_t, SVRINSTS_TAG);
    if(ISOK(server_mm_init_instance(server)))
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

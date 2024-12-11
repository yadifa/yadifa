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

#if __unix__
#ifndef __USE_GNU
#define __USE_GNU 1
#endif
#define _GNU_SOURCE 1
#include <sched.h>
#endif

#if defined __FreeBSD__
#include <sys/param.h>
#include <sys/cpuset.h>
typedef cpuset_t cpu_set_t;
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

// allow an external definition of the backlog queue size and L1 parameters

#ifndef SERVER_RW_BACKLOG_QUEUE_SIZE
// #define SERVER_RW_BACKLOG_QUEUE_SIZE 0x40000 // 256k slots : 16MB
// #define SERVER_RW_BACKLOG_QUEUE_SIZE 0x80000 // 512k slots : 32MB
#define SERVER_RW_BACKLOG_QUEUE_SIZE 0x4000 // 16k slots
#endif

#define NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT 3 // do NOT change this value

#ifndef SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE

#define SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE  128
#define SERVER_RW_L1_DATA_LINE_ALIGNED_SHIFT 7

// #define SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE     512
// #define SERVER_RW_L1_DATA_LINE_ALIGNED_SHIFT    9

#elif((1 << SERVER_RW_L1_DATA_LINE_ALIGNED_SHIFT) != SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE)
#error "2^" TOSTRING(SERVER_RW_L1_DATA_LINE_ALIGNED_SHIFT) " != " TOSTRING(SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE) " : please fix"
#endif

// DEBUG build: log debug 5 of incoming wire
#define DUMP_UDP_RW_RECEIVED_WIRE 0

// DEBUG build: log debug 5 of outgoing wire
#define DUMP_UDP_RW_OUTPUT_WIRE   0

extern logger_handle_t *g_statistics_logger;

#define RWNTCTXS_TAG 0x53585443544e5752
#define RWNTCTX_TAG  0x585443544e5752
#define RWNTCTXS_TAG 0x53585443544e5752
#define RWNTCTX_TAG  0x585443544e5752
#define NETTHCTX_TAG 0x585443485454454e

struct msg_hdr_s
{
    union socketaddress_46 sa;
    uint8_t                ctrl[MESSAGE_DATA_CONTROL_BUFFER_SIZE];
    int                    blk_count; // 16
    int                    msg_size;  // 16
    int                    sa_len;    // 8
    int                    ctrl_len;  // 8
};

struct msg_data_s
{
    struct msg_hdr_s hdr;
    uint8_t          data[1]; // keep this 1 value
};

typedef struct msg_data_s msg_data_s;

union msg_cell_u
{
    struct msg_data_s data;                                         // this is an UNION, l1_data is there to specify the size
    uint8_t           l1_data[SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE]; // L1 data cache line size, ensures the size is right
};

typedef union msg_cell_u msg_cell_u;

struct network_thread_context_s
{
    network_thread_context_base_t base;

    thread_t                      idr;
    thread_t                      idw;
    void                         *malloc_address;

    // should be aligned with 64

#if __unix__
    volatile dns_message_t *next_message __attribute__((aligned(SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE)));
#else
    volatile message_data *next_message;
#endif
    volatile msg_cell_u       *backlog_enqueue;     // __attribute__ ((aligned (SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE)));
    volatile const msg_cell_u *backlog_dequeue;     // __attribute__ ((aligned (SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE)));
    msg_cell_u                *backlog_queue_limit; // &backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE];

    mutex_t                    mtx;
    cond_t                     cond;

    // should be aligned with 64

#if __unix__
#else
    server_statistics_t statistics;
#endif

    // should be aligned with 64

#if __unix__
    dns_message_with_buffer_t in_message[NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT] __attribute__((aligned(SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE))); // used by the reader
#else
    dns_message_with_buffer_t in_message[NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT]; // used by the reader
#endif
    dns_message_with_buffer_t out_message; // used by the writer

    // should be aligned with 64

#if __unix__
    msg_cell_u backlog_queue[/*SERVER_RW_BACKLOG_QUEUE_SIZE*/ +1] __attribute__((aligned(SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE)));
#else
    msg_cell_u backlog_queue[/*SERVER_RW_BACKLOG_QUEUE_SIZE*/ +1];
#endif
};

typedef struct network_thread_context_s network_thread_context_t;

struct server_rw_data_s
{
    struct service_s           service_handler;
    int                       *sockets;
    int                        socket_count;
    int                        thread_count_by_address;
    network_thread_context_t **contexts;
};

static struct server_rw_data_s server_rw_data = {UNINITIALIZED_SERVICE, NULL, 0, 0, NULL};

static void                    server_rw_thread_context_init(network_thread_context_t *ctx, size_t backlog_queue_slots, struct service_worker_s *worker, uint16_t sockfd_idx)
{
    (void)worker;
    memset(ctx, 0, sizeof(network_thread_context_t));
    ctx->base.worker = NULL; // worker;
    ctx->base.idx = sockfd_idx;
    ctx->base.sockfd = server_rw_data.sockets[sockfd_idx];

#if USE_SERVER_STATISTICS_ATOMICS
    ctx->base.statisticsp = log_statistics_get();
#else
    ctx->base.statisticsp = log_statistics_alloc_register();
#endif

    ctx->backlog_enqueue = &ctx->backlog_queue[0];
    ctx->backlog_dequeue = &ctx->backlog_queue[0];
    ctx->backlog_queue_limit = &ctx->backlog_queue[backlog_queue_slots];

    for(int_fast32_t i = 0; i < NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT; ++i)
    {
        dns_message_data_with_buffer_init(&ctx->in_message[i]); // recv
        dns_message_reset_control(&ctx->in_message[i].message);
    }

    dns_message_data_with_buffer_init(&ctx->out_message); // recv reply
    dns_message_reset_control(&ctx->out_message.message);

    ctx->backlog_queue_limit->data.hdr.blk_count = 0; // implicitely done by the memset, but I want to be absolutely clear about this
    ctx->backlog_queue_limit->data.hdr.msg_size = 0;

    mutex_init(&ctx->mtx);
    cond_init(&ctx->cond);
}

static void server_rw_set_cpu_affinity(int index, int w0s1)
{
#if HAS_PTHREAD_SETAFFINITY_NP
    int cpu_count = sys_get_cpu_count();
    if(cpu_count < 0)
    {
        cpu_count = 1;
    }

    int affinity_with = (g_config->thread_affinity_base + (index * 2 + w0s1) * g_config->thread_affinity_multiplier) % cpu_count;
    log_info("server-rw: worker setting affinity with virtual cpu %i", affinity_with);

#if __NetBSD__
    cpuset_t *mycpu = cpuset_create();
    if(mycpu != NULL)
    {
        cpuset_zero(mycpu);
        cpuset_set((cpuid_t)affinity_with, mycpu);
        if(pthread_setaffinity_np(thread_self(), cpuset_size(mycpu), mycpu) != 0)
        {
#pragma message("TODO: report errors") // NetBSD
        }
        cpuset_destroy(mycpu);
    }
    else
    {
    }
#elif __windows__
#pragma message("TODO: implement") // windows
#else
    cpu_set_t mycpu;
    CPU_ZERO(&mycpu);
    CPU_SET(affinity_with, &mycpu);
    pthread_setaffinity_np(thread_self(), sizeof(cpu_set_t), &mycpu);
#endif
#else
    (void)index;
    (void)w0s1;
#endif
}

static int server_rw_udp_receiver_thread(struct service_worker_s *worker)
{
    network_thread_context_t *ctx = server_rw_data.contexts[worker->worker_index >> 1];

    ctx->idr = thread_self();
    ssize_t n;
    int     fd = ctx->base.sockfd;
    int     next_message_index = 0; // ^ 1 ^ 1 ...

    log_debug("server_rw_udp_receiver_thread(%i, %i): started", ctx->base.idx, fd);

    socketaddress_t sa;
    socklen_t       sa_len = sizeof(sa);
    getsockname(fd, &sa.sa, &sa_len);
    log_info("waiting for udp messages for %{sockaddr}", &sa);
    server_rw_set_cpu_affinity(ctx->base.idx, 0);
    tcp_set_recvtimeout(fd, 1, 0);

    for(;;)
    {
        dns_message_t *mesg = &ctx->in_message[next_message_index].message;
        dns_message_recv_udp_reset(mesg);
        dns_message_reset_control_size(mesg);
        n = dns_message_recv_udp(mesg, fd);
        if(n >= DNS_HEADER_LENGTH)
        {
#if DNSCORE_MESSAGE_HAS_TIMINGS
            mesg->recv_us = timeus();
            log_debug("server_rw_udp_receiver_thread: recvfrom: got %d bytes from %{sockaddr}", n, dns_message_get_sender_sa(mesg));
#if DUMP_UDP_RW_RECEIVED_WIRE
            log_memdump_ex(g_server_logger, MSG_DEBUG5, mesg->buffer, n, 16, OSPRINT_DUMP_HEXTEXT);
#endif
#endif

#if __FreeBSD__
            if(dns_message_control_size(mesg) == 0)
            {
                dns_message_clear_control(mesg);
            }
#endif
            // now the trick: either direct queue, either delayed queue
            mutex_lock(&ctx->mtx);
            if(ctx->next_message == NULL)
            {
                // the sender has room for more
                // needs to be fast as this is the (most common) fast lane
                ctx->next_message = mesg;

                // notify the other side it has to do some job
#if DNSCORE_MESSAGE_HAS_TIMINGS
                mesg->pushed_us = timeus();
#endif
                cond_notify_one(&ctx->cond);
                mutex_unlock(&ctx->mtx);
                next_message_index = (next_message_index + 1) % NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT;

                // next_message is only set to NULL when the sender took the previous one
                // and it only takes the previous one when the backlog is empty
                // so ...
#if DEBUG1
                log_debug("server_rw_udp_receiver_thread(%i, %i): queued in the fast lane", ctx->base.idx, fd);
#endif
            }
            else
            {
                // does not need to be fast (as we are already choking)

                // copy the bytes in the delayed queue (if there is room available,
                // else wait ...

                int         blk_count = (dns_message_get_size(mesg) + offsetof(struct msg_data_s, data) + SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE - 1) >> SERVER_RW_L1_DATA_LINE_ALIGNED_SHIFT;
                msg_cell_u *cell = (msg_cell_u *)ctx->backlog_enqueue;
                msg_cell_u *cell_next = cell + blk_count;

                if(cell >= ctx->backlog_dequeue) // we are on the last half
                {
                    // can fill up to the end of the buffer

                    const msg_cell_u *cell_limit = ctx->backlog_queue_limit; //&ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE];

                    if(cell_next <= cell_limit)
                    {
                        // copy the content
#if DEBUG
                        log_debug("%i: push %04hx", fd, ntohs(dns_message_get_id(mesg)));
#endif
                        // keep the relevant data from the message

                        dns_message_copy_sender_to_sa(mesg, &cell->data.hdr.sa.sa);
                        cell->data.hdr.ctrl_len = dns_message_copy_control(mesg, cell->data.hdr.ctrl, sizeof(cell->data.hdr.ctrl));
                        cell->data.hdr.msg_size = dns_message_get_size(mesg);
                        yassert(cell->data.hdr.msg_size <= 4096); // as none of the UDP test are that big (130 max)
                        cell->data.hdr.blk_count = blk_count;
                        cell->data.hdr.sa_len = dns_message_get_sender_size(mesg);
                        yassert((cell->data.hdr.sa_len > 0) && ((uint32_t)cell->data.hdr.sa_len <= sizeof(struct sockaddr_in6)));
                        dns_message_copy_buffer(mesg, &cell->data.data, (blk_count * SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE) - offsetof(msg_data_s, data));

                        //

                        if(cell_next == cell_limit)
                        {
                            if(ctx->backlog_dequeue > &ctx->backlog_queue[0])
                            {
                                // loop
                                cell_next = &ctx->backlog_queue[0];
                            }
#if DEBUG
                            else
                            {
                                // looping here would make the queue look empty : don't do it
                            }
#endif
                        }
#if DEBUG
                        else
                        {
                            // the end hasn't been reached yet
                        }
#endif
                    }
                    else
                    {
                        // mark the cell as unused (a.k.a: looping)
                        cell->data.hdr.msg_size = 0;
                        // loop
                        cell = &ctx->backlog_queue[0];
                        cell_next = cell + blk_count;

                        // now update the limit and test for overflow

                        const msg_cell_u *cell_limit = (const msg_cell_u *)ctx->backlog_dequeue; // we have to leave at least one block

                        if(cell_next < cell_limit)
                        {
                            // copy the content

                            // keep the relevant data from the message
                            dns_message_copy_sender_to_sa(mesg, &cell->data.hdr.sa.sa);
                            cell->data.hdr.ctrl_len = dns_message_copy_control(mesg, cell->data.hdr.ctrl, sizeof(cell->data.hdr.ctrl));
                            cell->data.hdr.msg_size = dns_message_get_size(mesg);
                            yassert(cell->data.hdr.msg_size <= 4096); // as none of the UDP test are that big (130 max)
                            cell->data.hdr.blk_count = blk_count;
                            cell->data.hdr.sa_len = dns_message_get_sender_size(mesg);
                            yassert((cell->data.hdr.sa_len > 0) && ((uint32_t)cell->data.hdr.sa_len <= sizeof(struct sockaddr_in6)));
                            dns_message_copy_buffer(mesg, &cell->data.data, (blk_count * SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE) - offsetof(msg_data_s, data));
                        }
                        else
                        {
                            cell_next = cell; // as the message is discarded
                        }
                    }
                }
                else // we are about to fill the buffer (soon) (cell < ctx->backlog_dequeue)
                {
#if DEBUG
                    assert(cell != NULL);
#endif
                    const msg_cell_u *cell_limit = (const msg_cell_u *)ctx->backlog_dequeue; // we have to leave at least one block

                    if(cell_next < cell_limit)
                    {
                        // copy the content
#if DEBUG
                        log_debug("%i: push %04hx (<)", fd, ntohs(dns_message_get_id(mesg)));
#endif
                        // keep the relevant data from the message

                        dns_message_copy_sender_to_sa(mesg, &cell->data.hdr.sa.sa);
                        cell->data.hdr.ctrl_len = dns_message_copy_control(mesg, cell->data.hdr.ctrl, sizeof(cell->data.hdr.ctrl));
                        cell->data.hdr.msg_size = dns_message_get_size(mesg);
                        yassert(cell->data.hdr.msg_size <= 4096); // as none of the UDP test are that big (130 max)
                        cell->data.hdr.blk_count = blk_count;
                        cell->data.hdr.sa_len = dns_message_get_sender_size(mesg);
                        yassert((cell->data.hdr.sa_len > 0) && ((uint32_t)cell->data.hdr.sa_len <= sizeof(struct sockaddr_in6)));
                        dns_message_copy_buffer(mesg, &cell->data.data, (blk_count * SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE) - offsetof(msg_data_s, data));
                    }
                    else
                    {
                        cell_next = cell; // as the message is discarded
#if DEBUG
                        // full: lose it (?)
                        log_debug("%i: full %04hx", fd, ntohs(dns_message_get_id(mesg)));
#endif
                    }
                }

                ctx->backlog_enqueue = cell_next;
                cond_notify_one(&ctx->cond);
                mutex_unlock(&ctx->mtx);
            }
        }
        else if(n >= 0)
        {
            log_warn("server-rw: received %i bytes garbage from %{sockaddr} (%i)", n, dns_message_get_sender_sa(mesg), fd);
        }
        else // n < 0
        {
            int err = errno;

            if((err != EINTR) && (err != EAGAIN))
            {
                /*
                 * EAGAIN
                 * Resource temporarily unavailable (may be the same value as EWOULDBLOCK) (POSIX.1)
                 */
                if(err != EBADF)
                {
                    log_warn("server-rw: receiver: %r (%i)", MAKE_ERRNO_ERROR(err), fd);
                }
                // else we are shutting down

                log_debug("server_rw_udp_receiver_thread(%i, %i): recvfrom error: %r", ctx->base.idx, fd, MAKE_ERRNO_ERROR(err)); /* most likely: timeout/resource temporarily unavailable */
                break;
            }

            if(service_should_reconfigure_or_stop(worker))
            {
                log_debug("server_rw_udp_receiver_thread(%i, %i): will stop (reconfigure or stop)", ctx->base.idx, fd);
                break;
            }
            // else retry
        }
    }

    log_debug("server_rw_udp_receiver_thread(%i, %i): stopped", ctx->base.idx, fd);

    return 0;
}

#if HAS_DYNUPDATE_SUPPORT
/**
 *
 * Update MUST be delegated to the main thread (not an issue on the st model)
 * BUT the delegation requires all udp threads to stop
 * So it means that we cannot delegate from inside (else we get a deadlock)
 * So a thread must be started to handle the remainder of the processing
 * Said thread will delegate and send answer back to the client
 *
 * This implies I have to copy the message so the original structure can be used
 * for the next query.
 */
#endif

ya_result server_rw_process_message_udp(network_thread_context_t *ctx, dns_message_t *mesg)
{
#if !USE_SERVER_STATISTICS_ATOMICS
    uint64_t *udp_output_size_totalp = &ctx->base.statisticsp->udp_output_size_total;
#endif
    ya_result ret;
    if(ISOK(ret = server_process_message_udp((network_thread_context_base_t *)ctx, mesg)))
    {
        if(ISOK(ret = dns_message_send_udp(mesg, ctx->base.sockfd)))
        {
#if USE_SERVER_STATISTICS_ATOMICS
            log_statistics_atomic.udp_output_size_total += ret;
#else
            *udp_output_size_totalp += ret;
#endif
        }
    }

    return ret;
}

static int server_rw_udp_sender_thread(struct service_worker_s *worker)
{
    network_thread_context_t *ctx = server_rw_data.contexts[worker->worker_index >> 1];
    ctx->idw = thread_self();

    log_debug("server_rw_udp_sender_thread(%i, %i): started", ctx->base.idx, ctx->base.sockfd);

    server_rw_set_cpu_affinity(ctx->base.idx, 1);

#if DNS_MESSAGE_HAS_POOL
    size_t   pool_buffer_size = 0x80000;
    uint8_t *pool_buffer_in;
    MALLOC_OBJECT_ARRAY_OR_DIE(pool_buffer_in, uint8_t, pool_buffer_size, SVRPLBIN_TAG);
    uint8_t *pool_buffer_out;
    MALLOC_OBJECT_ARRAY_OR_DIE(pool_buffer_out, uint8_t, pool_buffer_size, SVRPLBOT_TAG);

    for(int_fast32_t i = 0; i < NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT; ++i)
    {
        dns_message_set_pool_buffer(&ctx->in_message[i].message, pool_buffer_in, pool_buffer_size);
    }
    dns_message_set_pool_buffer(&ctx->out_message.message, pool_buffer_out, pool_buffer_size);
#endif

    for(;;)
    {
#if DEBUG1
        log_debug("server_rw_udp_sender_thread(%i, %i): dequeuing slow queries", ctx->base.idx, fd);
#endif
        dns_message_t *mesg;
        mutex_lock(&ctx->mtx);

        const msg_cell_u *cell = (const msg_cell_u *)ctx->backlog_dequeue;

        if(ctx->backlog_enqueue == cell) // empty backlog (the next to read is also the next to be filled)
        {
            // no item on the backlog
#if DEBUG1
            log_debug("server_rw_backlog_dequeue_message(%i, %i): dequeuing slow queries", ctx->base.idx, ctx->base.sockfd);
#endif
            // wait for an item from the fastlane

            if((mesg = (dns_message_t *)ctx->next_message) == NULL)
            {
                // no item, so wait for an event ...

                cond_timedwait(&ctx->cond, &ctx->mtx, ONE_SECOND_US);

                while((mesg = (dns_message_t *)ctx->next_message) == NULL)
                {
                    if(ctx->base.sockfd >= 0)
                    {
                        int tw = cond_timedwait(&ctx->cond, &ctx->mtx, ONE_SECOND_US);

                        if(tw == ETIMEDOUT)
                        {
                            if(service_should_reconfigure_or_stop(worker))
                            {
                                mutex_unlock(&ctx->mtx);

#if DNS_MESSAGE_HAS_POOL
                                free(pool_buffer_out);
                                free(pool_buffer_in);
#endif

                                log_debug("server_rw_udp_sender_thread(%i, %i): stopped (worker)", ctx->base.idx, ctx->base.sockfd);

                                return SUCCESS;
                            }
                        }
#if DEBUG
                        else
                        {
                            yassert(tw == 0);
                        }
#endif
                    }
                    else
                    {
                        mutex_unlock(&ctx->mtx);
#if DNS_MESSAGE_HAS_POOL
                        free(pool_buffer_out);
                        free(pool_buffer_in);
#endif
                        log_debug("server_rw_udp_sender_thread(%i, %i): stopped (wait->no-socket)", ctx->base.idx, ctx->base.sockfd);

                        return SUCCESS;
                        // exit
                    }
                }
            }

            // there was an item, and it's now on mesg : clear the fast lane slot

            ctx->next_message = NULL;

            mutex_unlock(&ctx->mtx);
#if DNSCORE_MESSAGE_HAS_TIMINGS
            mesg->popped_us = timeus();
            log_debug("server-rw: look: %04hx %lluus %lluus (%i)", ntohs(dns_message_get_id(mesg)), mesg->pushed_us - mesg->recv_us, mesg->popped_us - mesg->pushed_us, ctx->base.sockfd);
#endif
            ya_result ret;
            if(FAIL(ret = server_rw_process_message_udp(ctx, mesg)))
            {
                if(ret != MAKE_ERRNO_ERROR(EBADF))
                {
                    if(ctx->base.sockfd >= 0)
                    {
                        if(ret == MAKE_ERRNO_ERROR(EINVAL))
                        {
                            int32_t dest_port = sockaddr_inet_port((struct sockaddr *)mesg->_msghdr.msg_name);

                            // note dest_port is in network endian

                            if(dest_port == 0)
                            {
                                log_err(
                                    "server-rw: error replying to message %04hx %{dnsname} %{dnstype} from "
                                    "%{sockaddr}: invalid destination port",
                                    ntohs(dns_message_get_id(mesg)),
                                    dns_message_get_canonised_fqdn(mesg),
                                    dns_message_get_query_type_ptr(mesg),
                                    mesg->_msghdr.msg_name);
                            }
                            else if(dest_port < 0)
                            {
                                log_err(
                                    "server-rw: error replying to message %04hx %{dnsname} %{dnstype} invalid IP "
                                    "family",
                                    ntohs(dns_message_get_id(mesg)),
                                    dns_message_get_canonised_fqdn(mesg),
                                    dns_message_get_query_type_ptr(mesg));
                            }
                            else
                            {
                                log_err(
                                    "server-rw: error replying to message %04hx %{dnsname} %{dnstype} from "
                                    "%{sockaddr}: %r",
                                    ntohs(dns_message_get_id(mesg)),
                                    dns_message_get_canonised_fqdn(mesg),
                                    dns_message_get_query_type_ptr(mesg),
                                    mesg->_msghdr.msg_name,
                                    ret);
                            }
                        }

#if DEBUG
                        log_err("server-rw: look: %04hx: %r (%i)", ntohs(dns_message_get_id(mesg)), ret, ctx->base.sockfd);

                        if(mesg->_msghdr.msg_name != NULL)
                        {
                            log_err("server-rw: name %{sockaddr} (%llu)", mesg->_msghdr.msg_name, mesg->_msghdr.msg_namelen);
                        }
#if __unix__
                        if(mesg->_msghdr.msg_control != NULL)
                        {
                            log_err("server-rw: control@%p (%llu)", mesg->_msghdr.msg_control, mesg->_msghdr.msg_controllen);
                            log_memdump(MODULE_MSG_HANDLE, MSG_ERR, mesg->_msghdr.msg_control, mesg->_msghdr.msg_controllen, 32);
                        }
#else
                        if(mesg->_msghdr.msg_control.buf != NULL)
                        {
                            log_err("server-rw: control@%p (%llu)", mesg->_msghdr.msg_control.buf, mesg->_msghdr.msg_control.len);
                            log_memdump(MODULE_MSG_HANDLE, MSG_ERR, mesg->_msghdr.msg_control.buf, mesg->_msghdr.msg_control.len, 32);
                        }
#endif
                        if(mesg->_msghdr.msg_iov != NULL)
                        {
                            log_err("server-rw: iov@%p (%i)", mesg->_msghdr.msg_iov, mesg->_msghdr.msg_iovlen);
                        }

                        if(mesg->_iovec.iov_base != NULL)
                        {
                            log_memdump(MODULE_MSG_HANDLE, MSG_ERR, mesg->_iovec.iov_base, mesg->_iovec.iov_len, 32);
                        }

                        log_err("server-rw: flags %x", mesg->_msghdr.msg_flags);
#endif
                    }
                    else
                    {
                        log_err("server-rw: unexpected negative socket (%i)", ctx->base.sockfd);
                    }

                    dns_message_reset_control(mesg);
                    dns_message_reset_buffer_size(mesg);
                }
                else
                {
#if DNS_MESSAGE_HAS_POOL
                    free(pool_buffer_out);
                    free(pool_buffer_in);
#endif
                    // log_debug("server_rw_udp_sender_thread(%i, %i): stopped (closed)", ctx->base.idx, fd);
                    return ret;
                }
            }
        }
        else // there are items on the backlog
        {
            const msg_cell_u *cell_limit = (const msg_cell_u *)ctx->backlog_enqueue;

            mutex_unlock(&ctx->mtx);

            // until we processed them all (cell until but not included to cell_limit)

#if DNSCORE_MESSAGE_HAS_TIMINGS
            int loop_idx = 0;
#endif

            yassert(cell >= &ctx->backlog_queue[0] && cell <= ctx->backlog_queue_limit);

            if(cell > cell_limit) // go up to the end of the buffer (ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE + 1])
            {
                while(cell < ctx->backlog_queue_limit /*&ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE]*/)
                {
                    if(cell->data.hdr.msg_size == 0) // partial cell (which can only happen if there was no room anymore for a cell
                    {
                        break;
                    }
#if DNSCORE_MESSAGE_HAS_TIMINGS
                    uint64_t retrieve_start = timeus();
#endif
                    mesg = &ctx->out_message.message;

                    dns_message_copy_sender_from_sa(mesg, &cell->data.hdr.sa.sa, cell->data.hdr.sa_len);
#if DEBUG
                    log_debug("%i: cell->data.hdr.ctrl_len=%i cell->data.hdr.blk_count=%i cell->data.hdr.blk_count=%i (>)", ctx->base.sockfd, cell->data.hdr.ctrl_len, cell->data.hdr.blk_count, cell->data.hdr.msg_size);
#endif
                    dns_message_set_control(mesg, cell->data.hdr.ctrl, cell->data.hdr.ctrl_len);
                    yassert(cell->data.hdr.msg_size < 65536);

                    memcpy(dns_message_get_buffer(mesg), &cell->data.data, cell->data.hdr.msg_size);
                    dns_message_set_size(mesg, cell->data.hdr.msg_size);
#if DNSCORE_MESSAGE_HAS_TIMINGS
                    mesg->popped_us = timeus();
                    log_debug("%i: popd: %04hx %lluus (%i) (>)", ctx->base.sockfd, ntohs(dns_message_get_id(mesg)), mesg->popped_us - retrieve_start, loop_idx);
#endif
                    ya_result ret;
                    if(FAIL(ret = server_rw_process_message_udp(ctx, mesg)))
                    {
                        if(ret != MAKE_ERRNO_ERROR(EBADF))
                        {
                            log_err("server-rw: could not process message %04hx (sock %i) (%r) (>)", ntohs(dns_message_get_id(mesg)), ctx->base.sockfd, ret);

                            if(g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE)
                            {
                                log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, dns_message_get_buffer(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_BUFFER);
                            }
                        }
                    }
#if DNSCORE_MESSAGE_HAS_TIMINGS
                    ++loop_idx;
#endif

                    cell += cell->data.hdr.blk_count;

                    yassert(cell >= &ctx->backlog_queue[0] && cell <= ctx->backlog_queue_limit);
                }

                cell = &ctx->backlog_queue[0];
            }

            yassert(cell >= &ctx->backlog_queue[0] && cell <= ctx->backlog_queue_limit);

            while(cell < cell_limit)
            {
#if DNSCORE_MESSAGE_HAS_TIMINGS
                uint64_t retrieve_start = timeus();
#endif
                yassert(cell >= &ctx->backlog_queue[0] && cell <= ctx->backlog_queue_limit);

                mesg = &ctx->out_message.message;

                dns_message_copy_sender_from_sa(mesg, &cell->data.hdr.sa.sa, cell->data.hdr.sa_len);

                log_debug("%i: cell->data.hdr.ctrl_len=%i", ctx->base.sockfd, cell->data.hdr.ctrl_len);

                dns_message_set_control(mesg, cell->data.hdr.ctrl, cell->data.hdr.ctrl_len);
                memcpy(dns_message_get_buffer(mesg), &cell->data.data, cell->data.hdr.msg_size);
                dns_message_set_size(mesg, cell->data.hdr.msg_size);
#if DNSCORE_MESSAGE_HAS_TIMINGS
                mesg->popped_us = timeus();
                log_debug("%i: popd: %04hx %lluus (%i)", ctx->base.sockfd, ntohs(dns_message_get_id(mesg)), mesg->popped_us - retrieve_start, loop_idx);
#endif
                ya_result ret;
                if(FAIL(ret = server_rw_process_message_udp(ctx, mesg)))
                {
                    if(ret != MAKE_ERRNO_ERROR(EBADF))
                    {
                        log_err("server-rw: could not process message %04hx (sock %i) (%r)", ntohs(dns_message_get_id(mesg)), ctx->base.sockfd, ret);
                    }
                }

#if DNSCORE_MESSAGE_HAS_TIMINGS
                ++loop_idx;
#endif
#if DEBUG
                const msg_cell_u *next_cell = cell + cell->data.hdr.blk_count;
                yassert((next_cell >= &ctx->backlog_queue[0]) && (next_cell <= ctx->backlog_queue_limit));
                cell = next_cell;
#else
                cell += cell->data.hdr.blk_count;
                yassert((cell >= &ctx->backlog_queue[0]) && (cell <= ctx->backlog_queue_limit));
#endif
            }

            yassert(cell >= &ctx->backlog_queue[0] && cell <= ctx->backlog_queue_limit);

            mutex_lock(&ctx->mtx);
            // cell
            ctx->backlog_dequeue = cell;
            mutex_unlock(&ctx->mtx);
        }
    }
}

static int server_rw_udp_thread(struct service_worker_s *worker)
{
    int ret;
    if((worker->worker_index & 1) == 0)
    {
        ret = server_rw_udp_receiver_thread(worker);
    }
    else
    {
        ret = server_rw_udp_sender_thread(worker);
    }
    return ret;
}

static ya_result server_rw_deconfigure(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_rw_data));
    (void)server;

    service_stop(&server_rw_data.service_handler);
    service_finalise(&server_rw_data.service_handler);

    server_context_socket_close_multiple(server_rw_data.sockets, server_rw_data.socket_count);

    uint32_t tcp_interface_count = server_context_udp_interface_count();
    uint32_t worker_per_interface = g_config->thread_count_by_address;
    int      socket_count = tcp_interface_count * worker_per_interface;

    for(int_fast32_t i = 0; i < socket_count; ++i)
    {
        free(server_rw_data.contexts[i]->malloc_address);
    }
    free(server_rw_data.contexts);

    free(server_rw_data.sockets);
    server_rw_data.sockets = NULL;
    server_rw_data.socket_count = 0;

    return SUCCESS;
}

static ya_result server_rw_configure(network_server_t *server)
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

    server_rw_data.sockets = sockets;
    server_rw_data.socket_count = socket_count;

    ret = service_init_ex(&server_rw_data.service_handler, server_rw_udp_thread, "srvudprw", socket_count * 2);

    MALLOC_OBJECT_ARRAY_OR_DIE(server_rw_data.contexts, network_thread_context_t *, socket_count, NETTHCTX_TAG);

    if(ISOK(ret))
    {
        for(int_fast32_t i = 0; i < socket_count; ++i)
        {
            size_t   network_thread_context_real_size = sizeof(network_thread_context_t) + sizeof(msg_cell_u) * g_config->worker_backlog_queue_size;
            intptr_t ctx_base = (intptr_t)malloc(network_thread_context_real_size + SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE);
            intptr_t ctx_aligned;
            ctx_aligned = (ctx_base + SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE - 1) & ~(SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE - 1);
            network_thread_context_t *ctx = (network_thread_context_t *)ctx_aligned;
            ctx->malloc_address = (void *)ctx_base;
            server_rw_thread_context_init(ctx, g_config->worker_backlog_queue_size, service_get_worker(&server_rw_data.service_handler, i), i);
            server_rw_data.contexts[i] = ctx;
        }

        server->data = &server_rw_data;
    }
    else
    {
        server_rw_deconfigure(server);
    }

    return ret;
}

static ya_result server_rw_start(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_rw_data));
    (void)server;

    ya_result ret = service_start(&server_rw_data.service_handler);
    return ret;
}

static ya_result server_rw_join(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_rw_data));
    (void)server;

    ya_result ret = service_wait(&server_rw_data.service_handler);
    return ret;
}

static ya_result server_rw_stop(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_rw_data));
    (void)server;

    ya_result ret = service_stop(&server_rw_data.service_handler);
    return ret;
}

static ya_result server_rw_finalise(network_server_t *server)
{
    assert((server != NULL) && (server->data == &server_rw_data));

    network_server_t uninitialised = NETWORK_SERVICE_UNINITIALISED;
    *server = uninitialised;
    return 0;
}

static ya_result server_rw_state(network_server_t *server)
{
    (void)server;
    return 0;
}

static const char                        *server_rw_long_name() { return "UDP multithreaded deferred DNS server"; }

static const struct network_server_vtbl_s server_rw_vtbl = {server_rw_configure,
                                                            server_rw_start,
                                                            server_rw_join,
                                                            server_rw_stop, // could return instantly, only waits in finalise & start
                                                            server_rw_deconfigure,
                                                            server_rw_finalise,
                                                            server_rw_state,
                                                            server_rw_long_name};

/**
 * Initialises the object, not the server
 */

ya_result server_rw_init_instance(network_server_t *server)
{
    server_rw_data.thread_count_by_address = g_config->thread_count_by_address;
    server->data = &server_rw_data;
    server->vtbl = &server_rw_vtbl;
    return SUCCESS;
}

network_server_t *server_rw_new_instance()
{
    network_server_t *server;
    ZALLOC_OBJECT_OR_DIE(server, network_server_t, SVRINSTS_TAG);
    if(ISOK(server_rw_init_instance(server)))
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

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

/**
 *  @defgroup server Server
 *  @ingroup yadifad
 *  @brief multithreaded reader-writer server
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
 *              This solution is of course unacceptable for a big zone as it greatly increases the resident memory usage.
 * 
 * 
 * @{
 */

// keep this order -->

#include "server-config.h"

#ifndef WIN32
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
#include <dnscore/message.h>
#include <dnscore/timems.h>
#include <dnscore/thread_pool.h>
#include <dnscore/sys_get_cpu_count.h>
#include <dnscore/host_address.h>
#include <dnscore/process.h>

#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb-zone-lock.h>

#define ZDB_JOURNAL_CODE 1

#include <dnsdb/journal.h>

#if ZDB_HAS_LOCK_DEBUG_SUPPORT
#include "dnsdb/zdb-zone-lock-monitor.h"
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
#include "dynamic-module-handler.h"
#endif

#define SVRPLBIN_TAG 0x4e49424c50525653
#define SVRPLBOT_TAG 0x544f424c50525653

#if 1 // def SO_REUSEPORT

// allow an external definition of the backlog queue size and L1 parameters

#ifndef SERVER_RW_BACKLOG_QUEUE_SIZE
//#define SERVER_RW_BACKLOG_QUEUE_SIZE 0x40000 // 256k slots : 16MB
//#define SERVER_RW_BACKLOG_QUEUE_SIZE 0x80000 // 512k slots : 32MB
#define SERVER_RW_BACKLOG_QUEUE_SIZE 0x4000 // 16k slots
#endif

#define NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT 3 // do NOT change this value

#ifndef SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE

#define SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE     128
#define SERVER_RW_L1_DATA_LINE_ALIGNED_SHIFT    7

//#define SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE     512
//#define SERVER_RW_L1_DATA_LINE_ALIGNED_SHIFT    9

#elif ((1 << SERVER_RW_L1_DATA_LINE_ALIGNED_SHIFT) != SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE)
#error "2^" TOSTRING(SERVER_RW_L1_DATA_LINE_ALIGNED_SHIFT) " != " TOSTRING(SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE) " : please fix"
#endif

// DEBUG build: log debug 5 of incoming wire
#define DUMP_UDP_RW_RECEIVED_WIRE 0

// DEBUG build: log debug 5 of outgoing wire
#define DUMP_UDP_RW_OUTPUT_WIRE 0

extern logger_handle* g_statistics_logger;

#define RWNTCTXS_TAG 0x53585443544e5752
#define RWNTCTX_TAG 0x585443544e5752

struct msg_hdr_s
{
    union socketaddress_46 sa;
    u8 ctrl[MESSAGE_DATA_CONTROL_BUFFER_SIZE];
    int blk_count;      // 16
    int msg_size;       // 16
    int sa_len;         // 8
    int ctrl_len;       // 8
};

struct msg_data_s
{
    struct msg_hdr_s hdr;
    u8 data[1];                     // keep this 1 value
};

typedef struct msg_data_s msg_data_s;

union msg_cell_u
{
    struct msg_data_s data;         // this is an UNION, l1_data is there to specify the size
    u8 l1_data[SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE];  // L1 data cache line size, ensures the size is right
};

typedef union msg_cell_u msg_cell_u;

struct network_thread_context_s
{
    network_thread_context_base_t base;
    
    thread_t idr;
    thread_t idw;

    // should be aligned with 64
    
#ifndef WIN32
    volatile message_data *next_message __attribute__ ((aligned (SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE)));
#else
    volatile message_data* next_message;
#endif
    volatile msg_cell_u *backlog_enqueue;// __attribute__ ((aligned (SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE)));
    volatile const msg_cell_u *backlog_dequeue;// __attribute__ ((aligned (SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE))); 
    msg_cell_u * backlog_queue_limit; // &backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE];
    
    mutex_t mtx;
    cond_t cond;
    
    // should be aligned with 64
    
#ifndef WIN32
    server_statistics_t statistics __attribute__ ((aligned (SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE)));
#else
    server_statistics_t statistics;
#endif
    
    // should be aligned with 64
    
#ifndef WIN32
    message_data_with_buffer in_message[NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT] __attribute__ ((aligned (SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE))); // used by the reader
#else
    message_data_with_buffer in_message[NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT]; // used by the reader
#endif
    message_data_with_buffer out_message;   // used by the writer
    
    // should be aligned with 64
    
#ifndef WIN32
    msg_cell_u backlog_queue[/*SERVER_RW_BACKLOG_QUEUE_SIZE*/ + 1] __attribute__ ((aligned (SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE)));    
#else
    msg_cell_u backlog_queue[/*SERVER_RW_BACKLOG_QUEUE_SIZE*/ +1];
#endif
};

typedef struct network_thread_context_s network_thread_context_s;

static network_thread_context_s*
network_thread_context_new_instance(size_t backlog_queue_slots, struct service_worker_s *worker, u16 sockfd_idx)
{
    network_thread_context_s *ctx;
    
    size_t network_thread_context_real_size = sizeof(network_thread_context_s) + sizeof(msg_cell_u) * backlog_queue_slots;
    
    ctx = (network_thread_context_s*)malloc(network_thread_context_real_size);
    
    if(ctx == NULL)
    {
        return NULL;
    }
    
    memset(ctx, 0, sizeof(network_thread_context_s));
    ctx->base.worker = worker;
    ctx->base.idx = sockfd_idx;
    ctx->base.sockfd = g_server_context.udp_socket[sockfd_idx];
    ctx->base.statisticsp = &ctx->statistics;
    ctx->backlog_enqueue = &ctx->backlog_queue[0];
    ctx->backlog_dequeue = &ctx->backlog_queue[0];
    ctx->backlog_queue_limit = &ctx->backlog_queue[backlog_queue_slots];

    for(int i = 0; i < NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT; ++i)
    {
        message_data_with_buffer_init(&ctx->in_message[i]); // recv
        message_reset_control(&ctx->in_message[i].message);
    }

    message_data_with_buffer_init(&ctx->out_message);   // recv reply
    message_reset_control(&ctx->out_message.message);

    ctx->backlog_queue_limit->data.hdr.blk_count = 0; // implicitely done by the memset, but I want to be absolutely clear about this
    ctx->backlog_queue_limit->data.hdr.msg_size = 0;

    mutex_init(&ctx->mtx);
    cond_init(&ctx->cond);
    
    return ctx;
}

static void
network_thread_context_delete(network_thread_context_s *ctx)
{
    if(ctx != NULL)
    {
        cond_finalize(&ctx->cond);
        mutex_destroy(&ctx->mtx);
        message_finalize(&ctx->out_message.message);
        for(int i = NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT - 1; i >= 0; --i)
        {
            message_finalize(&ctx->in_message[i].message);
        }

        free(ctx);
    }
}

struct network_thread_context_array
{
    network_thread_context_s **contextes;
    size_t listen_count;
    size_t reader_by_fd;
    size_t backlog_queue_slots;
};

typedef struct network_thread_context_array network_thread_context_array;

static void
network_thread_context_array_finalize(network_thread_context_array *ctxa)
{
    for(size_t listen_idx = 0, sockfd_idx = 0; listen_idx < ctxa->listen_count; ++listen_idx)
    {
        for(u32 r = 0; r < ctxa->reader_by_fd; r++)
        {
            network_thread_context_s *ctx = ctxa->contextes[sockfd_idx];

            if(ctx != NULL)
            {
                log_debug("network_thread_context_array_finalize: %u/%u sockfd %i and thread %p/worker %u", (u32)listen_idx, (u32)ctxa->listen_count, sockfd_idx, ctx->base.worker->tid, ctx->base.worker->worker_index);
                network_thread_context_delete(ctx);
            }
            else
            {
                log_debug("network_thread_context_array_finalize: %u/%u sockfd %i had no context", (u32)listen_idx, (u32)ctxa->listen_count, sockfd_idx);
            }
            ++sockfd_idx;
        }
    }
    
    free(ctxa->contextes);
}

static ya_result
network_thread_context_array_init(network_thread_context_array *ctxa, size_t listen_count, size_t reader_by_fd,
        size_t backlog_queue_slots, struct service_worker_s *worker)
{
    network_thread_context_s **contextes;
    MALLOC_OBJECT_ARRAY(contextes, network_thread_context_s*, listen_count * reader_by_fd, RWNTCTXS_TAG);

    // the memory allocation macro without _OR_DIE suffix will not abort on insufficient memory

    if(contextes == NULL)
    {
        return MAKE_ERRNO_ERROR(ENOMEM);
    }
    
    memset(contextes, 0, listen_count * reader_by_fd * sizeof(network_thread_context_s*)); // there is no leak, the pointer is right there:
    
    ctxa->contextes = contextes;
    ctxa->listen_count = listen_count;
    ctxa->reader_by_fd = reader_by_fd;
    ctxa->backlog_queue_slots = backlog_queue_slots;

    for(size_t listen_idx = 0, sockfd_idx = 0; listen_idx < listen_count; ++listen_idx)
    {
        for(u32 r = 0; r < reader_by_fd; r++)
        {
            network_thread_context_s *ctx;

            ctx = network_thread_context_new_instance(backlog_queue_slots, worker, sockfd_idx);

            if(ctx == NULL)
            {
                network_thread_context_array_finalize(ctxa);
                return MAKE_ERRNO_ERROR(ENOMEM);
            }

            contextes[sockfd_idx] = ctx;

            /*
             * Update the select read set for the current interface (udp + tcp)
             */           

            ++sockfd_idx;
        }
    }

    return SUCCESS;
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
    log_info("server-rw: receiver setting affinity with virtual cpu %i", affinity_with);
#if __NetBSD__
    cpuset_t* mycpu = cpuset_create();
    if(mycpu != NULL)
    {
        cpuset_zero(mycpu);
        cpuset_set((cpuid_t)affinity_with, mycpu);
        if(pthread_setaffinity_np(thread_self(), cpuset_size(mycpu), mycpu) != 0)
        {
#pragma message("TODO: report errors")
        }
        cpuset_destroy(mycpu);
    }
    else
    {
    }
#elif defined(WIN32)
#pragma message("TODO: implement")
#else
    cpu_set_t mycpu;
    CPU_ZERO(&mycpu);
    CPU_SET(affinity_with, &mycpu);
    pthread_setaffinity_np(thread_self(), sizeof(cpu_set_t), &mycpu);
#endif
#endif
}

static void*
server_rw_udp_receiver_thread(void *parms)
{
    struct network_thread_context_s *ctx = (struct network_thread_context_s*)parms;
    u64 *local_statistics_udp_input_count = (u64*)&ctx->statistics.udp_input_count;
    ctx->idr = thread_self();
    ssize_t n;
    int fd = ctx->base.sockfd;
    int next_message_index = 0; // ^ 1 ^ 1 ...
    
    log_debug("server_rw_udp_receiver_thread(%i, %i): started", ctx->base.idx, fd);

    socketaddress sa;
    socklen_t sa_len = sizeof(sa);
    getsockname(fd, &sa.sa, &sa_len);
    log_info("waiting for udp messages for %{sockaddr}", &sa);

    server_rw_set_cpu_affinity(ctx->base.idx, 0);

    // const void *nullptr = NULL;
    
    tcp_set_recvtimeout(fd, 1, 0);
    
    for(;;)
    {
        

        message_data *mesg = &ctx->in_message[next_message_index].message;

        message_recv_udp_reset(mesg);
        message_reset_control_size(mesg);

        n = message_recv_udp(mesg, fd);

        if(n >= DNS_HEADER_LENGTH)
        {
            local_statistics_udp_input_count++;
#if DEBUG
            mesg->recv_us = timeus();
            log_debug("server_rw_udp_receiver_thread: recvfrom: got %d bytes from %{sockaddr}", n, message_get_sender_sa(mesg));
#if DUMP_UDP_RW_RECEIVED_WIRE
            log_memdump_ex(g_server_logger, MSG_DEBUG5, mesg->buffer, n, 16, OSPRINT_DUMP_HEXTEXT);
#endif
#endif

#if __FreeBSD__
            if(message_control_size(mesg) == 0)
            {
                message_clear_control(mesg);
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
#if DEBUG
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
                
                int blk_count = (message_get_size(mesg) + offsetof(struct msg_data_s, data) + SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE - 1) >> SERVER_RW_L1_DATA_LINE_ALIGNED_SHIFT;
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
                        log_debug("%i: push %04hx", fd, ntohs(message_get_id(mesg)));
#endif            
                        // keep the relevant data from the message
                    
                        message_copy_sender_to_sa(mesg, &cell->data.hdr.sa.sa);
                        cell->data.hdr.ctrl_len = message_copy_control(mesg, cell->data.hdr.ctrl, sizeof(cell->data.hdr.ctrl));
                        cell->data.hdr.msg_size = message_get_size(mesg);
                        yassert(cell->data.hdr.msg_size <= 4096);    // as none of the UDP test are that big (130 max)
                        cell->data.hdr.blk_count = blk_count;
                        cell->data.hdr.sa_len = message_get_sender_size(mesg);
                        yassert((cell->data.hdr.sa_len > 0) && ((u32)cell->data.hdr.sa_len <= sizeof(struct sockaddr_in6)));
                        message_copy_buffer(mesg, &cell->data.data, (blk_count * SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE) - offsetof(msg_data_s, data));
                        
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
                            message_copy_sender_to_sa(mesg, &cell->data.hdr.sa.sa);
                            cell->data.hdr.ctrl_len = message_copy_control(mesg, cell->data.hdr.ctrl, sizeof(cell->data.hdr.ctrl));
                            cell->data.hdr.msg_size = message_get_size(mesg);
                            yassert(cell->data.hdr.msg_size <= 4096);    // as none of the UDP test are that big (130 max)
                            cell->data.hdr.blk_count = blk_count;
                            cell->data.hdr.sa_len = message_get_sender_size(mesg);
                            yassert((cell->data.hdr.sa_len > 0) && ((u32)cell->data.hdr.sa_len <= sizeof(struct sockaddr_in6)));
                            message_copy_buffer(mesg, &cell->data.data, (blk_count * SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE) - offsetof(msg_data_s, data));
                        }
                        else
                        {
                            cell_next = cell;   // as the message is discarded
                        }
                    }
                }
                else // we are about to fill the buffer (soon) (cell < ctx->backlog_dequeue)
                {
                    const msg_cell_u *cell_limit = (const msg_cell_u *)ctx->backlog_dequeue; // we have to leave at least one block
                    
                    if(cell_next < cell_limit)
                    {
                        // copy the content
#if DEBUG
                        log_debug("%i: push %04hx (<)", fd, ntohs(message_get_id(mesg)));
#endif                        
                        // keep the relevant data from the message
                    
                        message_copy_sender_to_sa(mesg, &cell->data.hdr.sa.sa);
                        cell->data.hdr.ctrl_len = message_copy_control(mesg, cell->data.hdr.ctrl, sizeof(cell->data.hdr.ctrl));
                        cell->data.hdr.msg_size = message_get_size(mesg);
                        yassert(cell->data.hdr.msg_size <= 4096);    // as none of the UDP test are that big (130 max)
                        cell->data.hdr.blk_count = blk_count;
                        cell->data.hdr.sa_len = message_get_sender_size(mesg);
                        yassert((cell->data.hdr.sa_len > 0) && ((u32)cell->data.hdr.sa_len <= sizeof(struct sockaddr_in6)));
                        message_copy_buffer(mesg, &cell->data.data, (blk_count * SERVER_RW_L1_DATA_LINE_ALIGNED_SIZE) - offsetof(msg_data_s, data));
                    }
                    else
                    {
                        cell_next = cell; // as the message is discarded
#if DEBUG
                        // full: lose it (?)
                        log_debug("%i: full %04hx", fd, ntohs(message_get_id(mesg)));
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
            log_warn("server-rw: received %i bytes garbage from %{sockaddr} (%i)", n, message_get_sender_sa(mesg), fd);
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

            if(service_should_reconfigure_or_stop(ctx->base.worker))
            {
                log_debug("server_rw_udp_receiver_thread(%i, %i): will stop (reconfigure or stop)", ctx->base.idx, fd);
                break;
            }
            // else retry
            

        }
    }
    
    log_debug("server_rw_udp_receiver_thread(%i, %i): stopped", ctx->base.idx, fd);

    return NULL;
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

ya_result
server_rw_process_message_udp(struct network_thread_context_s *ctx, message_data *mesg)
{
    ya_result ret;
    if(ISOK(ret = server_process_message_udp((network_thread_context_base_t*)ctx, mesg)))
    {
        if(ISOK(ret = message_send_udp(mesg, ctx->base.sockfd)))
        {
            ctx->statistics.udp_output_size_total += ret;
        }
    }

    return ret;
}

static void*
server_rw_udp_sender_thread(void *parms)
{
    struct network_thread_context_s *ctx = (struct network_thread_context_s*)parms;
    ctx->idw = thread_self();

    log_debug("server_rw_udp_sender_thread(%i, %i): started", ctx->base.idx, ctx->base.sockfd);
    
    server_rw_set_cpu_affinity(ctx->base.idx, 1);
    
    size_t pool_buffer_size = 0x80000;
    u8 *pool_buffer_in;
    MALLOC_OBJECT_ARRAY_OR_DIE(pool_buffer_in, u8, pool_buffer_size, SVRPLBIN_TAG);
    u8 *pool_buffer_out;
    MALLOC_OBJECT_ARRAY_OR_DIE(pool_buffer_out, u8, pool_buffer_size, SVRPLBOT_TAG);

    for(int i = 0; i < NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT; ++i)
    {
        message_set_pool_buffer(&ctx->in_message[i].message, pool_buffer_in, pool_buffer_size);
    }
    message_set_pool_buffer(&ctx->out_message.message, pool_buffer_out, pool_buffer_size);
    
    for(;;)
    {
#if DEBUG1
        log_debug("server_rw_udp_sender_thread(%i, %i): dequeuing slow queries", ctx->base.idx, fd);
#endif
        
        message_data *mesg;
        
        mutex_lock(&ctx->mtx);

        const msg_cell_u *cell = (const msg_cell_u*)ctx->backlog_dequeue;

        if(ctx->backlog_enqueue == cell) // empty backlog (the next to read is also the next to be filled)
        {
            // no item on the backlog
#if DEBUG1
            log_debug("server_rw_backlog_dequeue_message(%i, %i): dequeuing slow queries", ctx->base.idx, ctx->base.sockfd);
#endif
            // wait for an item from the fastlane
            
            if((mesg = (message_data*)ctx->next_message) == NULL)
            {
                // no item, so wait for an event ...

                cond_timedwait(&ctx->cond, &ctx->mtx, ONE_SECOND_US);
                
                while((mesg = (message_data*)ctx->next_message) == NULL)
                {
                    if(ctx->base.sockfd >= 0)
                    {
                        int tw = cond_timedwait(&ctx->cond, &ctx->mtx, ONE_SECOND_US);
                        
                        if(tw == ETIMEDOUT)
                        {                        
                            if(service_should_reconfigure_or_stop(ctx->base.worker))
                            {
                                mutex_unlock(&ctx->mtx);
                                
                                free(pool_buffer_out);
                                free(pool_buffer_in);
                                
                                log_debug("server_rw_udp_sender_thread(%i, %i): stopped (worker)", ctx->base.idx, ctx->base.sockfd);
    
                                return NULL;
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
                        
                        free(pool_buffer_out);
                        free(pool_buffer_in);
                        
                        log_debug("server_rw_udp_sender_thread(%i, %i): stopped (wait->no-socket)", ctx->base.idx, ctx->base.sockfd);
    
                        return NULL;
                        // exit
                    }
                }
            }
            
            // there was an item, and it's now on mesg : clear the fast lane slot
            
            ctx->next_message = NULL;
                        
            mutex_unlock(&ctx->mtx);
#if DEBUG
            mesg->popped_us = timeus();

            log_debug("server-rw: look: %04hx %lluus %lluus (%i)", ntohs(message_get_id(mesg)), mesg->pushed_us - mesg->recv_us, mesg->popped_us - mesg->pushed_us, ctx->base.sockfd);
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
                            s32 dest_port = sockaddr_inet_port((struct sockaddr*)mesg->_msghdr.msg_name);

                            // note dest_port is in network endian

                            if(dest_port == 0)
                            {
                                log_err("server-rw: error replying to message %04hx %{dnsname} %{dnstype} from %{sockaddr}: invalid destination port",
                                        ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), mesg->_msghdr.msg_name);
                            }
                            else if(dest_port < 0)
                            {
                                log_err("server-rw: error replying to message %04hx %{dnsname} %{dnstype} invalid IP family",
                                        ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), mesg->_msghdr.msg_name);
                            }
                            else
                            {
                                log_err("server-rw: error replying to message %04hx %{dnsname} %{dnstype} from %{sockaddr}: %r",
                                        ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), mesg->_msghdr.msg_name, ret);
                            }
                        }

#if DEBUG
                        log_err("server-rw: look: %04hx: %r (%i)", ntohs(message_get_id(mesg)), ret, ctx->base.sockfd);

                        if(mesg->_msghdr.msg_name != NULL)
                        {
                            log_err("server-rw: name %{sockaddr} (%llu)", mesg->_msghdr.msg_name, mesg->_msghdr.msg_namelen);
                        }
#ifndef WIN32
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

                    message_reset_control(mesg);
                    message_reset_buffer_size(mesg);
                }
                else
                {
                    free(pool_buffer_out);
                    free(pool_buffer_in);

                    // log_debug("server_rw_udp_sender_thread(%i, %i): stopped (closed)", ctx->base.idx, fd);
                    return NULL;
                }
            }
        }
        else // there are items on the backlog
        {
            const msg_cell_u *cell_limit = (const msg_cell_u *)ctx->backlog_enqueue;
            
            mutex_unlock(&ctx->mtx);
            
            // until we processed them all (cell until but not included to cell_limit)
            
            int loop_idx = 0;
            
            yassert(cell >= &ctx->backlog_queue[0] && cell <= ctx->backlog_queue_limit);
            
            if(cell > cell_limit) // go up to the end of the buffer (ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE + 1])
            {
                while(cell < ctx->backlog_queue_limit /*&ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE]*/)
                {
                    if(cell->data.hdr.msg_size == 0) // partial cell (which can only happen if there was no room anymore for a cell
                    {
                        break;
                    }
#if DEBUG
                    u64 retrieve_start = timeus();
#endif
                    mesg = &ctx->out_message.message;

                    message_copy_sender_from_sa(mesg, &cell->data.hdr.sa.sa, cell->data.hdr.sa_len);
#if DEBUG
                    log_debug("%i: cell->data.hdr.ctrl_len=%i cell->data.hdr.blk_count=%i cell->data.hdr.blk_count=%i (>)", ctx->base.sockfd, cell->data.hdr.ctrl_len, cell->data.hdr.blk_count, cell->data.hdr.msg_size);
#endif
                    message_set_control(mesg, cell->data.hdr.ctrl, cell->data.hdr.ctrl_len);
                    yassert(cell->data.hdr.msg_size < 65536);
                    
                    memcpy(message_get_buffer(mesg), &cell->data.data, cell->data.hdr.msg_size);
                    message_set_size(mesg, cell->data.hdr.msg_size);
#if DEBUG
                    mesg->popped_us = timeus();
                    
                    log_debug("%i: popd: %04hx %lluus (%i) (>)", ctx->base.sockfd, ntohs(message_get_id(mesg)), mesg->popped_us - retrieve_start, loop_idx);
#endif
                    ya_result ret;
                    if(FAIL(ret = server_rw_process_message_udp(ctx, mesg)))
                    {
                        if(ret != MAKE_ERRNO_ERROR(EBADF))
                        {
                            log_err("server-rw: could not process message %04hx (sock %i) (%r) (>)", ntohs(message_get_id(mesg)), ctx->base.sockfd, ret);

                            if(g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE)
                            {
                                log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, message_get_buffer(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_ALL);
                            }
                        }
                    }

                    ++loop_idx;

                    cell += cell->data.hdr.blk_count;
                    
                    yassert(cell >= &ctx->backlog_queue[0] && cell <= ctx->backlog_queue_limit);
                }
                
                cell = &ctx->backlog_queue[0];
            }
            
            yassert(cell >= &ctx->backlog_queue[0] && cell <= ctx->backlog_queue_limit);
            
            while(cell < cell_limit)
            {
#if DEBUG
                u64 retrieve_start = timeus();
#endif
                yassert(cell >= &ctx->backlog_queue[0] && cell <= ctx->backlog_queue_limit);

                mesg = &ctx->out_message.message;

                message_copy_sender_from_sa(mesg, &cell->data.hdr.sa.sa, cell->data.hdr.sa_len);

                log_debug("%i: cell->data.hdr.ctrl_len=%i", ctx->base.sockfd, cell->data.hdr.ctrl_len);

                message_set_control(mesg, cell->data.hdr.ctrl, cell->data.hdr.ctrl_len);
                memcpy(message_get_buffer(mesg), &cell->data.data, cell->data.hdr.msg_size);
                message_set_size(mesg, cell->data.hdr.msg_size);
#if DEBUG
                mesg->popped_us = timeus();
                log_debug("%i: popd: %04hx %lluus (%i)", ctx->base.sockfd, ntohs(message_get_id(mesg)), mesg->popped_us - retrieve_start, loop_idx);
#endif
                ya_result ret;
                if(FAIL(ret = server_rw_process_message_udp(ctx, mesg)))
                {
                    if(ret != MAKE_ERRNO_ERROR(EBADF))
                    {
                        log_err("server-rw: could not process message %04hx (sock %i) (%r)", ntohs(message_get_id(mesg)), ctx->base.sockfd, ret);
                    }
                }

                ++loop_idx;
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

static server_statistics_t server_statistics_sum;

ya_result
server_rw_query_loop(struct service_worker_s *worker)
{
    ya_result ret;
    s32 server_run_loop_timeout_countdown = 0;
    int maxfd = -1;

    if(g_config->total_interfaces == 0 )
    {
        return INVALID_STATE_ERROR;
    }
    
    if(g_server_context.tcp_socket_count <= 0)
    {
        return INVALID_STATE_ERROR;
    }
    
    if(g_server_context.listen_count <= 0)
    {
        return INVALID_STATE_ERROR;
    }

    fd_set read_set;
    fd_set read_set_init;

    struct timespec timeout;

    //u32 previous_tick = 0;
    
    log_query_set_mode(g_config->queries_log_type);

    server_run_loop_timeout_countdown = g_config->statistics_max_period;
    
    bool log_statistics_enabled = (g_statistics_logger != NULL) && (g_config->server_flags & SERVER_FL_STATISTICS) != 0;
    
    log_debug("statistics are %s", (log_statistics_enabled)?"enabled":"disabled");
    
    if(log_statistics_enabled)
    {
        log_statistics_legend();
    }

    /* There's a timeout each second, for checking the SA_SHUTDOWN flag */

    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;

    /**
     * For each interface ...
     */

    /* compute maxfd plus one once and for all : begin */

    /* Set sockets on a "template" var, so we will copy it
     * in the one we will use in pselect.  This increases
     * the speed a bit.
     */

    FD_ZERO(&read_set_init);
    s32 reader_by_fd = g_server_context.udp_socket_count / g_server_context.udp_unit_per_interface;
    s32 cpu_count = sys_get_cpu_count();
    if(reader_by_fd > cpu_count)
    {
        log_warn("server-rw: using too many threads per address is counter-productive on highly loaded systems (%d > %d)", reader_by_fd, cpu_count);
    }

    u64 server_run_loop_rate_tick = 0;
    u32 previous_tick = 0;

    log_info("server-rw: UDP working threads to be spawned: %i", (int)g_server_context.udp_interface_count * (int)g_server_context.udp_unit_per_interface * 2);

    struct thread_pool_s *server_udp_thread_pool = thread_pool_init_ex(g_server_context.udp_interface_count * g_server_context.udp_unit_per_interface * 2, 1, "svrudprw");

    if(server_udp_thread_pool == NULL)
    {
        log_err("server-rw: unable to allocate working threads pool");
        return INVALID_STATE_ERROR;
    }
    
    size_t backlog_queue_slots = g_server_context.worker_backlog_queue_size; /* SERVER_RW_BACKLOG_QUEUE_SIZE*/;
    
    network_thread_context_array ctxa;
    if(FAIL(ret = network_thread_context_array_init(&ctxa, g_server_context.udp_interface_count, g_server_context.udp_unit_per_interface,
            backlog_queue_slots, worker)))
    {
        log_err("server-rw: unable to allocate context: %r", ret);
        return ret;
    }

    u32 initialised_context_indexes = 0;
    
    for(u32 udp_interface_index = 0; udp_interface_index < g_server_context.udp_interface_count; ++udp_interface_index)
    {
        for(u32 unit_index = 0; unit_index < g_server_context.udp_unit_per_interface; unit_index++)
        {
            network_thread_context_s *ctx = ctxa.contextes[initialised_context_indexes];

            yassert(ctx != NULL);

            log_info("server-rw: thread #%i of UDP interface: %{sockaddr} using socket %i", unit_index, g_server_context.udp_interface[udp_interface_index]->ai_addr, ctx->base.sockfd);

            log_debug("server_rw_query_loop: pooling #%d=%d fd=%d", initialised_context_indexes, ctx->base.idx, ctx->base.sockfd);
            
            if(FAIL(ret = thread_pool_enqueue_call(server_udp_thread_pool, server_rw_udp_receiver_thread, ctx, NULL, "server-rw-recv")))
            {
                log_err("server-rw: unable to schedule task : %r", ret);

                service_stop(worker->service);
                
                break;
            }
            
            if(FAIL(ret = thread_pool_enqueue_call(server_udp_thread_pool, server_rw_udp_sender_thread, ctx, NULL, "server-rw-send")))
            {
                log_err("server-rw: unable to schedule task : %r", ret);

                service_stop(worker->service);

                mutex_lock(&ctx->mtx);
                cond_notify(&ctx->cond);
                mutex_unlock(&ctx->mtx);

                break;
            }
         
            /*
             * Update the select read set for the current interface (udp + tcp)
             */           
            
            ++initialised_context_indexes;
        }
        
        if(FAIL(ret))
        {
            break;
        }
    }

    if(ISOK(ret))
    {
        log_info("server-rw: UDP threads up");

        for(u32 i = 0; i < g_server_context.tcp_socket_count; ++i)
        {
            int sockfd = g_server_context.tcp_socket[i];

            if(sockfd >= 0)
            {
                maxfd = MAX(maxfd, sockfd);
                FD_SET(sockfd, &read_set_init);
            }
            else
            {
                log_err("server-rw: invalid socket value (%i) in tcp listening sockets", sockfd);
            }
        }

        ++maxfd; /* pselect actually requires maxfd + 1 */

        /* compute maxfd plus one once and for all : done */


    
        log_info("ready to work");

        while(!service_should_reconfigure_or_stop(worker))
        {
            server_statistics.input_loop_count++;

            /* Reset the pselect read set */

            MEMCOPY(&read_set, &read_set_init, sizeof(fd_set));

            /* At this moment waits only for READ SET or timeout of x seconds */

            /*
             * @note (p)select has known bugs on Linux & glibc
             *
             */

            ret = pselect(maxfd,
                    &read_set,
                    NULL,
                    NULL,
                    &timeout,
                    0);

            if(ret > 0) /* Are any bit sets by pselect ? */
            {
                /* If pselect check for the correct sock file descriptor,
                 * at this moment only READ SET
                 */

                /*
                 * This variable will contain the pointer to the processing function.
                 * It has been removed from the mesg structure at the time the latter
                 * has been moved to the core.
                 *
                 * Reasons being: zdb *dependency & server dependency -> dependency loop
                 *
                 * Since the call is only local it should not have side effects.
                 */

                for(u32 i = 0; i < g_server_context.tcp_socket_count; ++i)
                {
                    int sockfd = g_server_context.tcp_socket[i];

                    if(FD_ISSET(sockfd, &read_set))
                    {
                        /* Jumps to the TCP processing function */
                        server_process_tcp(sockfd);
                        server_statistics.loop_rate_counter++;
                    }
                }
            }
            else /* ret <= 0 */
            {
                if(ret == -1)
                {
                    int err = errno;
                    if((err != EINTR) && (err != EBADF))
                    {
                        /**
                         *  From the man page, what we can expect is EBADF (bug) EINVAL (bug) or ENOMEM (critical)
                         *  So I we can kill and notify.
                         */
                        log_err("server-rw: pselect: %r", ERRNO_ERROR);
                    }
                    /*else if(err == EBADF)
                    {
                        break;
                    }*/
                }
                /*else if(dnscore_shuttingdown())
                {
                    break;
                }*/

                /* ret == 0 => no fd set at all and no error => timeout */

                server_run_loop_timeout_countdown--;
                server_statistics.input_timeout_count++;
            }

#if HAS_RRL_SUPPORT
            rrl_cull();
#endif
        
#if ZDB_HAS_LOCK_DEBUG_SUPPORT
            zdb_zone_lock_monitor_log();
#endif
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
            zdb_zone_lock_set_monitor();
#endif
        
            /* handles statistics logging */

            if(log_statistics_enabled)
            {
                u32 tick = dnscore_timer_get_tick();

                if((tick - previous_tick) >= g_config->statistics_max_period)
                {
                    u64 now = timems();
                    u64 delta = now - server_run_loop_rate_tick;

                    if(delta > 0)
                    {
                        /* log_info specifically targeted to the g_statistics_logger handle */

                        server_statistics.loop_rate_elapsed = delta;

                        memcpy(&server_statistics_sum, &server_statistics, sizeof(server_statistics_t));

                        for(u32 udp_interface_index = 0, context_index = 0; udp_interface_index < g_server_context.udp_interface_count; ++udp_interface_index)
                        {
                            for(u32 unit_index = 0; unit_index < g_server_context.udp_unit_per_interface; unit_index++)
                            {
                                server_statistics_t *stats = &(ctxa.contextes[context_index]->statistics);

                                assert(stats != NULL);

                                server_statistics_sum.input_loop_count += stats->input_loop_count;
                                /* server_statistics_sum.input_timeout_count += stats->input_timeout_count; */

                                server_statistics_sum.udp_output_size_total += stats->udp_output_size_total;
                                server_statistics_sum.udp_referrals_count += stats->udp_referrals_count;
                                server_statistics_sum.udp_input_count += stats->udp_input_count;
                                server_statistics_sum.udp_dropped_count += stats->udp_dropped_count;
                                server_statistics_sum.udp_queries_count += stats->udp_queries_count;
                                server_statistics_sum.udp_notify_input_count += stats->udp_notify_input_count;
                                server_statistics_sum.udp_updates_count += stats->udp_updates_count;

                                server_statistics_sum.udp_undefined_count += stats->udp_undefined_count;
#if HAS_RRL_SUPPORT
                                server_statistics_sum.rrl_slip += stats->rrl_slip;
                                server_statistics_sum.rrl_drop += stats->rrl_drop;
#endif
                                for(u32 j = 0; j < SERVER_STATISTICS_ERROR_CODES_COUNT; j++)
                                {
                                    server_statistics_sum.udp_fp[j] += stats->udp_fp[j];
                                }

                                ++context_index;
                            }
                        }

#if HAS_EVENT_DYNAMIC_MODULE
                        if(dynamic_module_statistics_interface_chain_available())
                        {
                            dynamic_module_on_statistics_update(&server_statistics_sum, now);
                        }
#endif
                        log_statistics(&server_statistics_sum);

                        server_run_loop_rate_tick = now;
                        server_run_loop_timeout_countdown = g_config->statistics_max_period;
                        server_statistics.loop_rate_counter = 0;
#if DEBUG
#if HAS_ZALLOC_STATISTICS_SUPPORT
                        zalloc_print_stats(termout);
#endif
#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
                        debug_stat(DEBUG_STAT_SIZES|DEBUG_STAT_TAGS); // do NOT enable the dump
#endif
                        journal_log_status();

                        debug_bench_logdump_all();
#endif
#if HAS_LIBC_MALLOC_DEBUG_SUPPORT
                        debug_malloc_hook_caller_dump();
#endif
                    }

                    previous_tick = tick;
                }
            } // if log_statistics_enabled
        }
    }
    else
    {
        log_err("server-rw: initialisation failed");
    }

    log_info("server-rw: stopping the threads");

    for(u32 udp_interface_index = 0, context_index = 0; udp_interface_index < g_server_context.udp_interface_count; ++udp_interface_index)
    {
        for(u32 unit_index = 0; unit_index < g_server_context.udp_unit_per_interface; unit_index++)
        {
            if(context_index >= initialised_context_indexes) // only happens in case of critical error
            {
                break;
            }

            network_thread_context_s *ctx = ctxa.contextes[context_index];

            if(ctx != NULL)
            {
                log_info("thread #%i of UDP interface: %{sockaddr} using socket %i", unit_index, g_server_context.udp_interface[udp_interface_index]->ai_addr, ctx->base.sockfd);

                mutex_lock(&ctx->mtx);
                cond_notify(&ctx->cond);
                mutex_unlock(&ctx->mtx);
            }

            ++context_index;
        }
    }
        
    /*
     * Close all zone alarm handles
     * Close database alarm handle
     */

    log_info("server-rw: cleaning up");

    thread_pool_destroy(server_udp_thread_pool);
    server_udp_thread_pool = NULL;
    
    network_thread_context_array_finalize(&ctxa);

    log_info("server-rw: stopped", getpid_ex());
    
    return SUCCESS;
}

ya_result
server_rw_context_init(int workers_per_interface)
{
    g_server_context.thread_per_udp_worker_count = 2; // set in stone
    g_server_context.thread_per_tcp_worker_count = 1; // set in stone
    g_server_context.udp_unit_per_interface = MAX(workers_per_interface , 1);
    g_server_context.tcp_unit_per_interface = 1;
#ifdef SO_REUSEPORT
    g_server_context.reuse = 1;
#else
    if(g_server_context.udp_unit_per_interface > 1)
    {
        log_warn("system does not support SO_REUSEPORT, downgrading UDP unit per interface from %i to 1", g_server_context.udp_unit_per_interface);
        g_server_context.udp_unit_per_interface = 1;
    }
    g_server_context.reuse = 0;
#endif

    g_server_context.ready = 1;
    return SUCCESS;
}

#else // SO_REUSEPORT

ya_result
server_rw_query_loop()
{
    log_err("SO_REUSEPORT is not supported on this architecture.");
    return FEATURE_NOT_SUPPORTED;
}

ya_result
server_rw_context_init(int workers_per_interface)
{
    log_err("SO_REUSEPORT is not supported on this architecture.");
    return FEATURE_NOT_SUPPORTED;
}

#endif // SO_REUSEPORT

/**
 * @}
 */

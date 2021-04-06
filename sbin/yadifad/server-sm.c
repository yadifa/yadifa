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

#define TRY_EPOLL 0
#define TRY_POLL 0

#if TRY_EPOLL
#include <sys/epoll.h>
#endif

#if TRY_POLL
#include <poll.h>
#endif

#define SVRPLBIN_TAG 0x4e49424c50525653
#define SVRPLBOT_TAG 0x544f424c50525653

// allow an external definition of the backlog queue size and L1 parameters

#define NETWORK_THREAD_CONTEXT_FAST_MESSAGE_COUNT 3 // do NOT change this value

#ifndef SERVER_SM_L1_DATA_LINE_ALIGNED_SIZE

#define SERVER_SM_L1_DATA_LINE_ALIGNED_SIZE     128
#define SERVER_SM_L1_DATA_LINE_ALIGNED_SHIFT    7

#define SERVER_SM_PACKETS_AT_ONCE   1

#elif ((1 << SERVER_SM_L1_DATA_LINE_ALIGNED_SHIFT) != SERVER_SM_L1_DATA_LINE_ALIGNED_SIZE)
#error "2^" TOSTRING(SERVER_SM_L1_DATA_LINE_ALIGNED_SHIFT) " != " TOSTRING(SERVER_SM_L1_DATA_LINE_ALIGNED_SIZE) " : please fix"
#endif

// DEBUG build: log debug level 5 of incoming wire
#define DUMP_UDP_SM_RECEIVED_WIRE 0

// DEBUG build: log debug 5 of outgoing wire
#define DUMP_UDP_SM_OUTPUT_WIRE 0

extern logger_handle* g_statistics_logger;

#define RWNTCTXS_TAG 0x53585443544e5752
#define RWNTCTX_TAG 0x585443544e5752

// note: MODULE_MSG_HANDLE is defined in server_error.h

struct network_thread_context_s
{
    network_thread_context_base_t base;

    // should be aligned with 64
    
    mutex_t mtx;
    cond_t cond;
    
    // should be aligned with 64
    
#ifndef WIN32
    server_statistics_t statistics __attribute__ ((aligned (SERVER_SM_L1_DATA_LINE_ALIGNED_SIZE)));
#else
    server_statistics_t statistics;
#endif
};

typedef struct network_thread_context_s network_thread_context_s;

static network_thread_context_s*
network_thread_context_new_instance(size_t backlog_queue_slots, struct service_worker_s *worker, u16 sockfd_idx)
{
    network_thread_context_s *ctx;
    (void)backlog_queue_slots;
    
    size_t network_thread_context_real_size = sizeof(network_thread_context_s);
    
    ctx = (network_thread_context_s*)malloc(network_thread_context_real_size);
    
    if(ctx == NULL)
    {
        return NULL;
    }
    
    memset(ctx, 0, sizeof(network_thread_context_s));
    ctx->base.worker = worker;
    ctx->base.idx = sockfd_idx;
    ctx->base.sockfd = g_server_context.udp_socket[sockfd_idx];
    //ctx->base.must_stop = FALSE; // implicit with the memset
    ctx->base.statisticsp = &ctx->statistics;

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

            log_debug("network_thread_context_array_init: %u/%u idx=%i and thread %p/worker %u", (u32)listen_idx, (u32)listen_count, sockfd_idx, worker->tid, worker->worker_index);

            contextes[sockfd_idx] = ctx;

            /*
             * Update the select read set for the current interface (udp + tcp)
             */           

            ++sockfd_idx;
        }
    }

    return SUCCESS;
}

static void server_sm_set_cpu_affinity(int index)
{
#if HAS_PTHREAD_SETAFFINITY_NP
    int cpu_count = sys_get_cpu_count();
    if(cpu_count < 0)
    {
        cpu_count = 1;
    }

    int affinity_with = g_config->thread_affinity_base + (index * g_config->thread_affinity_multiplier);
    affinity_with += affinity_with / cpu_count;
    affinity_with %= cpu_count;
    log_info("server-sm: worker setting affinity with virtual cpu %i", affinity_with);

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
server_sm_udp_worker_thread(void *parms)
{
    struct network_thread_context_s *ctx = (struct network_thread_context_s*)parms;
    u64 *local_statistics_udp_input_count = (u64*)&ctx->statistics.udp_input_count;
    ctx->base.idr = thread_self();

    int fd = ctx->base.sockfd;

    log_debug("server_sm_udp_worker_thread(%i, %i): started", ctx->base.idx, fd);

    socketaddress sa;
    socklen_t sa_len = sizeof(sa);
    getsockname(fd, &sa.sa, &sa_len);
    log_info("waiting for udp messages for %{sockaddr}", &sa);

    server_sm_set_cpu_affinity(ctx->base.idx);

    u8 *pool_buffer;
    size_t pool_buffer_size = 65536;
    MALLOC_OBJECT_ARRAY_OR_DIE(pool_buffer, u8, pool_buffer_size, GENERIC_TAG);

    message_data *mesg;
    mesg = message_new_instance();
    message_set_pool_buffer(mesg, pool_buffer, pool_buffer_size);
    message_reset_control(mesg);
    tcp_set_recvtimeout(fd, 1, 0);

    for(;;)
    {
#if DEBUG
	    log_debug("server_sm_udp_worker_thread(%i, %i): recvmsg", ctx->base.idx, fd);
#endif
	    message_recv_udp_reset(mesg);
	    message_reset_control_size(mesg);
	    ya_result ret = message_recv_udp(mesg, fd);
#if DEBUG
	     log_debug("server_sm_udp_worker_thread(%i, %i): recvmsg: %i", ctx->base.idx, fd, ret);
#endif
        if(FAIL(ret))
        {
#if DEBUG
            int err = ERRNO_ERROR;
            log_debug("message_recv_udp %i returned %i : %r", fd, ret, err);
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
        local_statistics_udp_input_count++;

#if DEBUG
        mesg->recv_us = timeus();
        log_debug("server_sm_udp_worker_thread: recvfrom: got %d bytes from %{sockaddr}", message_get_size(mesg), message_get_sender_sa(mesg));
#if DUMP_UDP_SM_RECEIVED_WIRE
        log_memdump_ex(g_server_logger, MSG_DEBUG5, mesg->buffer, n, 16, OSPRINT_DUMP_HEXTEXT);
#endif
#endif
        s32 dest_port = sockaddr_inet_port(message_get_sender_sa(mesg));

        if(dest_port > 0)
        {
            ya_result ret = server_process_message_udp((network_thread_context_base_t*)ctx, mesg);

            if(ISOK(ret))
            {
                // that message will be replied to
                ret = message_send_udp(mesg, fd);

                if(ISOK(ret))
                {
                    ctx->statistics.udp_output_size_total += ret;
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
                    log_debug("server_sm_udp_worker_thread: good-dropped %d bytes from %{sockaddr}", message_get_size(mesg), message_get_sender_sa(mesg));
                    message_log(MODULE_MSG_HANDLE, LOG_INFO, mesg);
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
                    log_debug("server_sm_udp_worker_thread: bad-dropped %d bytes from %{sockaddr}", message_get_size(mesg), message_get_sender_sa(mesg));
                    message_log(MODULE_MSG_HANDLE, LOG_INFO, mesg);
#endif
                }
            }
        }
        else if(dest_port == 0)
        {
            log_err("server-sm: error replying to message %04hx %{dnsname} %{dnstype} from %{sockaddr}: invalid destination port",
                    ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), mesg->_msghdr.msg_name);
        }
        else // if(dest_port < 0)
        {
            log_err("server-sm: error replying to message %04hx %{dnsname} %{dnstype} invalid IP family",
                    ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), mesg->_msghdr.msg_name);
        }

    } // for "ever" loop

server_sm_udp_worker_thread_end:

#if DEBUG
    log_debug("server_sm_udp_worker_thread(%i, %i): stopping", ctx->base.idx, fd);
#endif

#if TRY_EPOLL
    close_ex(epoll_fd);
#endif

    free(pool_buffer);

    message_set_pool_buffer(mesg, NULL, pool_buffer_size);
    message_free(mesg);

#if DEBUG
    log_debug("server_sm_udp_worker_thread(%i, %i): stopped", ctx->base.idx, fd);
#endif

    return NULL;
}

static server_statistics_t server_statistics_sum;

ya_result
server_sm_query_loop(struct service_worker_s *worker)
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
    
    log_debug("server-sm: statistics are %s", (log_statistics_enabled)?"enabled":"disabled");
    
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
        log_warn("server-sm: using too many threads per address is counter-productive on highly loaded systems (%d > %d)", reader_by_fd, cpu_count);
    }

    u64 server_run_loop_rate_tick = 0;
    u32 previous_tick = 0;

    log_info("server-sm: UDP working threads to be spawned: %i", (int)g_server_context.udp_interface_count * (int)g_server_context.udp_unit_per_interface);

    struct thread_pool_s *server_udp_thread_pool = thread_pool_init_ex(g_server_context.udp_interface_count * g_server_context.udp_unit_per_interface, 1, "svrudpmm");

    if(server_udp_thread_pool == NULL)
    {
        log_err("server-sm: unable to allocate working threads pool");
        return INVALID_STATE_ERROR;
    }
    
    size_t backlog_queue_slots = g_server_context.worker_backlog_queue_size;
    
    network_thread_context_array ctxa;
    if(FAIL(ret = network_thread_context_array_init(&ctxa, g_server_context.udp_interface_count, g_server_context.udp_unit_per_interface,
            backlog_queue_slots, worker)))
    {
        log_err("server-sm: unable to allocate context: %r", ret);
        return ret;
    }

    thread_pool_task_counter running_threads_counter;
    thread_pool_counter_init(&running_threads_counter, 0);

    u32 initialised_context_indexes = 0;
    
    for(u32 udp_interface_index = 0; udp_interface_index < g_server_context.udp_interface_count; ++udp_interface_index)
    {
        for(u32 unit_index = 0; unit_index < g_server_context.udp_unit_per_interface; unit_index++)
        {
            network_thread_context_s *ctx = ctxa.contextes[initialised_context_indexes];

            yassert(ctx != NULL);

            log_info("server-sm: thread #%i of UDP interface: %{sockaddr} using socket %i", unit_index, g_server_context.udp_interface[udp_interface_index]->ai_addr, ctx->base.sockfd);

            log_debug("server_sm_query_loop: pooling #%d=%d fd=%d", initialised_context_indexes, ctx->base.idx, ctx->base.sockfd);
            
            if(FAIL(ret = thread_pool_enqueue_call(server_udp_thread_pool, server_sm_udp_worker_thread, ctx, &running_threads_counter, "server-sm-udp")))
            {
                log_err("server-sm: unable to schedule task : %r", ret);

                service_stop(worker->service);
                
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
        log_info("server-sm: UDP threads up");

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
                log_err("server-sm: invalid socket value (%i) in tcp listening sockets", sockfd);
            }
        }

        ++maxfd; /* pselect actually requires maxfd + 1 */

        /* compute maxfd plus one once and for all : done */

        log_info("server-sm: running");

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
                        log_err("server-sm: pselect: %r", ERRNO_ERROR);
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
        log_err("server-sm: initialisation failed");
    }


#if DEBUG
    {
        s32 threads_still_running_count = thread_pool_counter_get_value(&running_threads_counter);
        log_info("threads_still_running_count = %i", threads_still_running_count);
    }
#endif

    log_info("server-sm: stopping the threads");

    bool can_stop;

    do
    {
        for(u32 udp_interface_index = 0, context_index = 0; udp_interface_index < g_server_context.udp_interface_count; ++udp_interface_index)
        {
            for(u32 unit_index = 0; unit_index < g_server_context.udp_unit_per_interface; unit_index++)
            {
                if(context_index >= initialised_context_indexes) // only happens in case of a critical error
                {
                    break;
                }

                network_thread_context_s *ctx = ctxa.contextes[context_index];

                if(ctx != NULL)
                {
                    ctx->base.must_stop = TRUE;
                }

                ++context_index;
            }
        }

        s32 threads_still_running_count = thread_pool_counter_get_value(&running_threads_counter);

        log_debug("server-sm: threads_still_running_count = %i", threads_still_running_count);

        can_stop = (threads_still_running_count == 0);
    }
    while(!can_stop);

    thread_pool_counter_destroy(&running_threads_counter);

    /*
     * Close all zone alarm handles
     * Close database alarm handle
     */

    log_info("server-sm: cleaning up: stopping thread pool");

    thread_pool_destroy(server_udp_thread_pool);
    server_udp_thread_pool = NULL;

    log_info("server-sm: cleaning up: releasing context");
    
    network_thread_context_array_finalize(&ctxa);

    log_info("server-sm: stopped", getpid_ex());
    
    return SUCCESS;
}

ya_result
server_sm_context_init(int workers_per_interface)
{
    g_server_context.thread_per_udp_worker_count = 1; // set in stone
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

/**
 * @}
 */

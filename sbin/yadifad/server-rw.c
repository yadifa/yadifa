/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2019, EURid vzw. All rights reserved.
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

#ifndef __USE_GNU
#define __USE_GNU 1
#endif
#define _GNU_SOURCE 1
#include <sched.h>

#if defined __FreeBSD__
#include <sys/param.h>
#include <sys/cpuset.h>
typedef cpuset_t cpu_set_t;
#endif

// <-- keep this order

#include "config.h"
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

#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb-zone-lock.h>

#define ZDB_JOURNAL_CODE 1

#include <dnsdb/journal.h>

#if ZDB_HAS_MUTEX_DEBUG_SUPPORT
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

#define SERVER_RW_DEBUG 0

#ifdef SO_REUSEPORT

// allow an external definition of the backlog queue size and L1 parameters

#ifndef SERVER_RW_BACKLOG_QUEUE_SIZE
//#define SERVER_RW_BACKLOG_QUEUE_SIZE 0x40000 // 256k slots : 16MB
#define SERVER_RW_BACKLOG_QUEUE_SIZE 0x80000 // 512k slots : 32MB
#endif

#ifndef L1_DATA_LINE_SIZE
#define L1_DATA_LINE_SIZE 64
#define L1_DATA_LINE_SHIFT 6
#elif ((1 << L1_DATA_LINE_SHIFT) != L1_DATA_LINE_SIZE)
#error "2^" TOSTRING(L1_DATA_LINE_SHIFT) " != " TOSTRING(L1_DATA_LINE_SIZE) " : please fix"
#endif

// DEBUG build: log debug 5 of incoming wire
#define DUMP_UDP_RW_RECEIVED_WIRE 0

// DEBUG build: log debug 5 of outgoing wire
#define DUMP_UDP_RW_OUTPUT_WIRE 0

extern logger_handle* g_statistics_logger;

#define RWNTCTXS_TAG 0x53585443544e5752
#define RWNTCTX_TAG 0x585443544e5752

static zdb *database = NULL;

struct msg_hdr_s
{
    union socketaddress_46 sa;
    //struct msg_data_s *next;
    u8 ctrl[32];
    int blk_count;
    int msg_size;
    int sa_len;
    int ctrl_len;
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
    u8 l1_data[L1_DATA_LINE_SIZE];  // L1 data cache line size, ensures the size is right
};

typedef union msg_cell_u msg_cell_u;

struct network_thread_context_s
{
    pthread_t idr;
    pthread_t idw;
    int sockfd;
    u16 idx;

    volatile u8  status;
        
    // should be aligned with 64
    
    volatile message_data *next_message __attribute__ ((aligned (L1_DATA_LINE_SIZE)));
    volatile msg_cell_u *backlog_enqueue;// __attribute__ ((aligned (L1_DATA_LINE_SIZE)));
    volatile const msg_cell_u *backlog_dequeue;// __attribute__ ((aligned (L1_DATA_LINE_SIZE))); 
    
    mutex_t mtx;
    cond_t cond;
    
    // should be aligned with 64
    
    msg_cell_u backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE + 1] __attribute__ ((aligned (L1_DATA_LINE_SIZE)));
    
#if UDP_USE_MESSAGES
    struct iovec    sender_iovec;
    struct msghdr   sender_msghdr;
#endif
    // should be aligned with 64
    
    server_statistics_t statistics __attribute__ ((aligned (L1_DATA_LINE_SIZE)));
    
    // should be aligned with 64
    
    message_data in_message[3] __attribute__ ((aligned (L1_DATA_LINE_SIZE))); // used by the reader
    message_data out_message;   // used by the writer
};

typedef struct network_thread_context_s network_thread_context_s;

static void*
server_rw_udp_receiver_thread(void *parms)
{
    struct network_thread_context_s *ctx = (struct network_thread_context_s*)parms;
    u64 *local_statistics_udp_input_count = (u64*)&ctx->statistics.udp_input_count;
    ctx->idr = pthread_self();
    ssize_t n;
    int fd = ctx->sockfd;
    int next_message_index = 0; // ^ 1 ^ 1 ...
    
    log_debug("server_rw_udp_receiver_thread(%i, %i): started", ctx->idx, fd);

#if HAS_PTHREAD_SETAFFINITY_NP
    cpu_set_t mycpu;
    CPU_ZERO(&mycpu);
    
    int affinity_with = g_config->thread_affinity_base + (ctx->idx * 2 + 0) * g_config->thread_affinity_multiplier;
    log_info("server-rw: receiver setting affinity with virtual cpu %i", affinity_with);
    CPU_SET(affinity_with, &mycpu);
    
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mycpu);
#endif
    
#if UDP_USE_MESSAGES
    
    struct msghdr   receiver_msghdr;
    struct iovec    receiver_iovec;
    receiver_msghdr.msg_iov = &receiver_iovec;
    receiver_msghdr.msg_iovlen = 1;
    receiver_msghdr.msg_control = NULL;
    receiver_msghdr.msg_controllen = 0;
    receiver_msghdr.msg_flags = 0;

    /* UDP messages handling requires more setup */
#endif
    
    // const void *nullptr = NULL;
    
    for(;;)
    {
        
#if SERVER_RW_DEBUG
        log_debug("%i: recv wait", fd);
#endif
        
        message_data *mesg = &ctx->in_message[next_message_index];        
        
#if !UDP_USE_MESSAGES
        mesg->addr_len = sizeof(socketaddress);
        n = recvfrom(fd, mesg->buffer, MIN(NETWORK_BUFFER_SIZE, sizeof(mesg->buffer)), 0, (struct sockaddr*)&mesg->other.sa, &mesg->addr_len);
#else
        receiver_iovec.iov_base = mesg->buffer;
        receiver_iovec.iov_len = MIN(NETWORK_BUFFER_SIZE, sizeof(mesg->buffer));
        receiver_msghdr.msg_name = &mesg->other.sa;
        receiver_msghdr.msg_namelen = sizeof(socketaddress);
        receiver_msghdr.msg_control = mesg->control_buffer;
        receiver_msghdr.msg_controllen = sizeof(mesg->control_buffer);

        n = recvmsg(fd, &receiver_msghdr, 0);
#endif
        if(n >= DNS_HEADER_LENGTH)
        {
            local_statistics_udp_input_count++;
            
#ifdef DEBUG
            mesg->recv_us = timeus();
#endif
            
#if UDP_USE_MESSAGES
            mesg->addr_len = receiver_msghdr.msg_namelen;
            mesg->control_buffer_size = receiver_msghdr.msg_controllen;
#endif
            
#ifdef DEBUG
            mesg->recv_us = timeus();
            log_debug("server_rw_udp_receiver_thread: recvfrom: got %d bytes from %{sockaddr}", n, &mesg->other.sa);
#if DUMP_UDP_RW_RECEIVED_WIRE
            log_memdump_ex(g_server_logger, MSG_DEBUG5, mesg->buffer, n, 16, OSPRINT_DUMP_HEXTEXT);
#endif
#endif
            // now the trick: either direct queue, either delayed queue
            
            mesg->received = n;
            
            mutex_lock(&ctx->mtx);
            if(ctx->next_message == NULL)
            {
                // the sender has room for more
                // needs to be fast as this is the (most common) fast lane
                
                ctx->next_message = mesg;
                
                // notify the other side it has to do some job
#ifdef DEBUG
                mesg->pushed_us = timeus();
#endif
                cond_notify_one(&ctx->cond);
                mutex_unlock(&ctx->mtx);
                next_message_index = (next_message_index + 1) % 3;
#if SERVER_RW_DEBUG
                log_debug("%i: show %04hx", fd, ntohs(MESSAGE_ID(mesg->buffer)));
#endif
                // next_message is only set to NULL when the sender took the previous one
                // and it only takes the previous one when the backlog is empty
                // so ...
                
#if SERVER_RW_DEBUG
                log_debug("server_rw_udp_receiver_thread(%i, %i): queued in the fast lane", ctx->idx, fd);
#endif
                
            }
            else
            {
                //mutex_unlock(&ctx->mtx);
                // does not need to be fast (as we are already choking)
                
                // copy the bytes in the delayed queue (if there is room available,
                // else wait ...
                
                int blk_count = (mesg->received + offsetof(struct msg_data_s, data) + L1_DATA_LINE_SIZE - 1) >> L1_DATA_LINE_SHIFT;
                msg_cell_u *cell = (msg_cell_u *)ctx->backlog_enqueue;
                msg_cell_u *cell_next = cell + blk_count;
                
                if(cell >= ctx->backlog_dequeue) // we are on the last half
                {
                    // can fill up to the end of the buffer
                    
                    const msg_cell_u *cell_limit = &ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE];
                    
                    if(cell_next <= cell_limit)
                    {
                        // copy the content
#ifdef DEBUG
                        log_debug("%i: push %04hx", fd, ntohs(MESSAGE_ID(mesg->buffer)));
#endif            
                        // keep the relevant data from the message
                    
                        memcpy(&cell->data.hdr.sa, &mesg->other.sa, mesg->addr_len);
#if UDP_USE_MESSAGES
                        memcpy(cell->data.hdr.ctrl, receiver_msghdr.msg_control, receiver_msghdr.msg_controllen);
#endif
                        cell->data.hdr.msg_size = mesg->received;
                        cell->data.hdr.blk_count = blk_count;
                        cell->data.hdr.sa_len = mesg->addr_len;
#if UDP_USE_MESSAGES
                        cell->data.hdr.ctrl_len = receiver_msghdr.msg_controllen;
#endif
                        memcpy(&cell->data.data, mesg->buffer, mesg->received);
                        
                        //
                        
                        if(cell_next == cell_limit)
                        {
                            // loop
                            cell_next = &ctx->backlog_queue[0];
                        }
                    }
                    else
                    {
                        // erase
                        cell->data.hdr.msg_size = 0;
                        // loop
                        cell = &ctx->backlog_queue[0];
                        cell_next = cell + blk_count;
                        
                        // copy the content
                        
                        // keep the relevant data from the message
                    
                        memcpy(&cell->data.hdr.sa, &mesg->other.sa, mesg->addr_len);
#if UDP_USE_MESSAGES
                        memcpy(cell->data.hdr.ctrl, receiver_msghdr.msg_control, receiver_msghdr.msg_controllen);
#endif
                        cell->data.hdr.msg_size = mesg->received;
                        cell->data.hdr.blk_count = blk_count;
                        cell->data.hdr.sa_len = mesg->addr_len;
#if UDP_USE_MESSAGES
                        cell->data.hdr.ctrl_len = receiver_msghdr.msg_controllen;
#endif
                        memcpy(&cell->data.data, mesg->buffer, mesg->received);
                        
                        //
                    }
                }
                else // we are about to fill the buffer (soon)
                {
                    const msg_cell_u *cell_limit = (const msg_cell_u *)ctx->backlog_dequeue; // we have to leave at least one block
                    
                    if(cell_next < cell_limit)
                    {
                        // copy the content
#if SERVER_RW_DEBUG  
                        log_debug("%i: push %04hx (<)", fd, ntohs(MESSAGE_ID(mesg->buffer)));
#endif
                        
                        // keep the relevant data from the message
                    
                        memcpy(&cell->data.hdr.sa, &mesg->other.sa, mesg->addr_len);
#if UDP_USE_MESSAGES
                        memcpy(cell->data.hdr.ctrl, receiver_msghdr.msg_control, receiver_msghdr.msg_controllen);
#endif
                        cell->data.hdr.msg_size = mesg->received;
                        cell->data.hdr.blk_count = blk_count;
                        cell->data.hdr.sa_len = mesg->addr_len;
#if UDP_USE_MESSAGES
                        cell->data.hdr.ctrl_len = receiver_msghdr.msg_controllen;
#endif
                        memcpy(&cell->data.data, mesg->buffer, mesg->received);
                    }
#if SERVER_RW_DEBUG
                    else
                    {
                        // full: lose it (?)
                        log_debug("%i: full %04hx", fd, ntohs(MESSAGE_ID(mesg->buffer)));
                    }
#endif
                }

                ctx->backlog_enqueue = cell_next;
                cond_notify_one(&ctx->cond);
                mutex_unlock(&ctx->mtx);
            }
        }
        else if(n >= 0)
        {
            log_warn("%i: received %i bytes garbage from %{sockaddr}", fd, &mesg->other.sa);
        }
        else // n < 0
        {
            /*
             * errno is not a variable but a macro
             */

            int err = errno;
            
            if(err != EINTR)
            {
                /*
                 * EAGAIN
                 * Resource temporarily unavailable (may be the same value as EWOULDBLOCK) (POSIX.1)
                 */

                if(err != EAGAIN)
                {
                    if(err != EBADF)
                    {
                        log_warn("%i: fail ----: %r", fd, MAKE_ERRNO_ERROR(err));
                    }
                    // else we are shutting down
#ifdef DEBUG
                    log_debug("server_rw_udp_receiver_thread: recvfrom error: %r", MAKE_ERRNO_ERROR(err)); /* most likely: timeout/resource temporarily unavailable */
#endif
                    break;
                }
                // else retry
            }
            // else retry
            
#if SERVER_RW_DEBUG
            log_debug("server_rw_udp_receiver_thread: tick");
#endif
        }
    }
    
    log_debug("server_rw_udp_receiver_thread(%i, %i): stopped", ctx->idx, fd);

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


static void
server_rw_process_udp_update(message_data *mesg)
{
    dynupdate_query_service_enqueue(database, mesg);
}

#endif

static ya_result
server_rw_udp_sender_process_message(struct network_thread_context_s *ctx, message_data *mesg)
{
    server_statistics_t * const local_statistics = &ctx->statistics;
    local_statistics->udp_input_count++;
    ya_result return_code;
    int fd = ctx->sockfd;
    
#ifdef DEBUG1
    log_debug("server_rw_process_message(%i, %i)", ctx->idx, fd);
#endif
    
    switch(MESSAGE_OP(mesg->buffer))
    {
        case OPCODE_QUERY:
        {
            if(ISOK(return_code = message_process_query(mesg)))
            {
                message_edns0_clear_undefined_flags(mesg);
                
                switch(mesg->qclass)
                {
                    case CLASS_IN:
                    {
                        local_statistics->udp_queries_count++;

                        log_query(ctx->sockfd, mesg);

                        switch(mesg->qtype)
                        {
                            default:
                            {
#if HAS_RRL_SUPPORT
                                ya_result rrl = database_query_with_rrl(database, mesg);

                                local_statistics->udp_referrals_count += mesg->referral;
                                local_statistics->udp_fp[mesg->status]++;                                

                                switch(rrl)
                                {
                                    case RRL_SLIP:
                                    {
                                        local_statistics->rrl_slip++;
                                        break;
                                    }
                                    case RRL_DROP:
                                    {
                                        local_statistics->rrl_drop++;
                                        return SUCCESS;
                                    }
                                    case RRL_PROCEED_DROP:
                                    {
                                        local_statistics->rrl_drop++;
                                        break;
                                    }
                                }
#else
                                database_query(database, mesg);

                                local_statistics->udp_referrals_count += mesg->referral;
                                local_statistics->udp_fp[mesg->status]++;
#endif
                                break;
                            }
                            case TYPE_IXFR: // reply with a truncate
                            {
                                MESSAGE_FLAGS_OR(mesg->buffer, QR_BITS|TC_BITS, 0); /** @todo 20160106 edf -- IXFR UDP */
                                SET_U32_AT(mesg->buffer[4], 0);
                                SET_U32_AT(mesg->buffer[8], 0);
                                mesg->send_length = DNS_HEADER_LENGTH;
                                local_statistics->udp_fp[FP_IXFR_UDP]++;
                                break;
                            }
                            case TYPE_AXFR:
                            case TYPE_OPT:
                            {
                                message_make_error(mesg, FP_INCORR_PROTO);
                                local_statistics->udp_fp[FP_INCORR_PROTO]++;
                                break;
                            }
                        } // switch query type
                        
                        break;
                    } // query class IN
                    case CLASS_CH:
                    {
                        class_ch_process(mesg); // thread-safe
                        local_statistics->udp_fp[mesg->status]++;
                        break;
                    } // query class CH
                    default:
                    {
                        message_make_error(mesg, FP_NOT_SUPP_CLASS);
                        local_statistics->udp_fp[FP_NOT_SUPP_CLASS]++;
                        break;
                    }
                } // query class
            } // if message process succeeded
            else // an error occurred : no query to be done at all
            {
                log_warn("query (%04hx) [%02x|%02x] error %i (%r) (%{sockaddrip})",
                        ntohs(MESSAGE_ID(mesg->buffer)),
                        MESSAGE_HIFLAGS(mesg->buffer),
                        MESSAGE_LOFLAGS(mesg->buffer),
                        mesg->status,
                        return_code,
                        &mesg->other.sa);

                local_statistics->udp_fp[mesg->status]++;
                
#ifdef DEBUG
                if(return_code == UNPROCESSABLE_MESSAGE && (g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE))
                {
                    log_memdump_ex(MODULE_MSG_HANDLE, MSG_DEBUG, mesg->buffer, mesg->received, 16, OSPRINT_DUMP_ALL);
                }
#endif
                
                /*
                 * If not FE, or if we answer FE
                 * 
                 * ... && (MESSAGE_QR(mesg->buffer) == 0 ??? and if there the query number is > 0 ???
                 */
                if( (return_code != INVALID_MESSAGE) && ((mesg->status != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)))
                {
                    message_edns0_clear_undefined_flags(mesg);
                    
                    if(!MESSAGEP_HAS_TSIG(mesg))
                    {
                        message_transform_to_error(mesg);
                    }
                }
                else
                {
                    local_statistics->udp_dropped_count++;
                    return SUCCESS;
                }
            }
            
            break;
        } // case query
        case OPCODE_NOTIFY:
        {
            if(ISOK(return_code = message_process(mesg)))
            {
                message_edns0_clear_undefined_flags(mesg);
                
                switch(mesg->qclass)
                {
                    case CLASS_IN:
                    {
                        ya_result return_value;

                        local_statistics->udp_notify_input_count++;

                        log_info("notify (%04hx) %{dnsname} (%{sockaddr})",
                                ntohs(MESSAGE_ID(mesg->buffer)),
                                mesg->qname,
                                &mesg->other.sa);

                        bool answer = MESSAGE_QR(mesg->buffer);
                        
                        return_value = notify_process(mesg); // thread-safe
                        
                        local_statistics->udp_fp[mesg->status]++;
                        
                        if(FAIL(return_value))
                        {
                            log_err("notify (%04hx) %{dnsname} failed : %r",
                                    ntohs(MESSAGE_ID(mesg->buffer)),
                                    mesg->qname,
                                    return_value);
                            
                            if(answer)
                            {
                                return SUCCESS;
                            }
                            
                            if(!MESSAGEP_HAS_TSIG(mesg))
                            {
                                message_transform_to_error(mesg);
                            }
                            break;
                        }
                        else
                        {
                            if(answer)
                            {
                                return SUCCESS;
                            }
                        }
                        
                        break;
                    } // notify class IN
                    default:
                    {
                        /// @todo 20140521 edf -- verify unsupported class error handling
                        /*
                        FP_CLASS_NOTFOUND
                        */
                        message_make_error(mesg, FP_NOT_SUPP_CLASS);
                        local_statistics->udp_fp[FP_NOT_SUPP_CLASS]++;
                        break;
                    }
                } // notify class
            } // if message process succeeded
            else // an error occurred : no query to be done at all
            {
                log_warn("notify (%04hx) [%02x|%02x] error %i (%r) (%{sockaddrip})",
                         ntohs(MESSAGE_ID(mesg->buffer)),
                         MESSAGE_HIFLAGS(mesg->buffer),MESSAGE_LOFLAGS(mesg->buffer),
                         mesg->status,
                         return_code,
                         &mesg->other.sa);

                local_statistics->udp_fp[mesg->status]++;
#ifdef DEBUG
                log_memdump_ex(MODULE_MSG_HANDLE, MSG_DEBUG5, mesg->buffer, mesg->received, 16, OSPRINT_DUMP_ALL);
#endif
                /*
                 * If not FE, or if we answer FE
                 * 
                 * ... && (MESSAGE_QR(mesg->buffer) == 0 ??? and if there the query number is > 0 ???
                 */
                if( (return_code != INVALID_MESSAGE) && ((mesg->status != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)))
                {
                    message_edns0_clear_undefined_flags(mesg);
                    
                    if(!MESSAGEP_HAS_TSIG(mesg))
                    {
                        message_transform_to_error(mesg);
                    }
                }
                else
                {
                    local_statistics->udp_dropped_count++;
                    return SUCCESS;
                }
            }
            break;
        } // case notify

        case OPCODE_UPDATE:
        {
            if(ISOK(return_code = message_process(mesg)))
            {
                message_edns0_clear_undefined_flags(mesg);
                
                switch(mesg->qclass)
                {
                    case CLASS_IN:
                    {
#if HAS_DYNUPDATE_SUPPORT
                        /**
                         * @note It's the responsibility of the called function (or one of its callees) to ensure
                         *       this does not take much time and thus to trigger a background task with the
                         *       scheduler if needed.
                         */

                        local_statistics->udp_updates_count++;
                        mesg->sockfd = fd;
                        server_rw_process_udp_update(mesg);
                        
                        return SUCCESS; // NOT break;
#else
                        message_make_error(mesg, FP_FEATURE_DISABLED);
                        local_statistics->udp_fp[FP_FEATURE_DISABLED]++;
                        break;
#endif
                        
                    } // update class IN
                    default:
                    {
                        /// @todo 20140521 edf -- verify unsupported class error handling
                        /*
                        FP_CLASS_NOTFOUND
                        */
                        message_make_error(mesg, FP_NOT_SUPP_CLASS);
                        local_statistics->udp_fp[FP_NOT_SUPP_CLASS]++;
                        break;
                    }
                } // update class
            } // if message process succeeded
            else // an error occurred : no query to be done at all
            {
                log_warn("update (%04hx) [%02x|%02x] error %i (%r) (%{sockaddrip})",
                         ntohs(MESSAGE_ID(mesg->buffer)),
                         MESSAGE_HIFLAGS(mesg->buffer),MESSAGE_LOFLAGS(mesg->buffer),
                         mesg->status,
                         return_code,
                         &mesg->other.sa);

                local_statistics->udp_fp[mesg->status]++;
#ifdef DEBUG
                log_memdump_ex(MODULE_MSG_HANDLE, MSG_DEBUG5, mesg->buffer, mesg->received, 16, OSPRINT_DUMP_ALL);
#endif
                /*
                 * If not FE, or if we answer FE
                 * 
                 * ... && (MESSAGE_QR(mesg->buffer) == 0 ??? and if there the query number is > 0 ???
                 */
                if( (return_code != INVALID_MESSAGE) && ((mesg->status != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)))
                {
                    message_edns0_clear_undefined_flags(mesg);
                    
                    if(!MESSAGEP_HAS_TSIG(mesg))
                    {
                        message_transform_to_error(mesg);
                    }
                }
                else
                {
                    local_statistics->udp_dropped_count++;
                    return SUCCESS;
                }
            }
            break;
        } // case update

        default:
        {
            return_code = message_process_query(mesg);
            mesg->status = RCODE_NOTIMP;
            
            if(ctx->sockfd < 0)
            {
                return STOPPED_BY_APPLICATION_SHUTDOWN; // shutdown
            }

            log_warn("unknown [%04hx] error: %r", ntohs(MESSAGE_ID(mesg->buffer)), MAKE_DNSMSG_ERROR(mesg->status));
            
            if( (mesg->status != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0))
            {
                message_edns0_clear_undefined_flags(mesg);
                
                if(!MESSAGEP_HAS_TSIG(mesg))
                {
                    message_transform_to_error(mesg);
                }
            }
            else
            {
                local_statistics->udp_dropped_count++;
                return SUCCESS;
            }
        }
    }
    
#if SERVER_RW_DEBUG

#endif
    
#if !UDP_USE_MESSAGES
    
    while(sendto(fd, mesg->buffer, mesg->send_length, 0, (struct sockaddr*)&mesg->other.sa, mesg->addr_len) < 0)
    {
        int error_code = errno;

        if(error_code != EINTR)
        {
            return error_code;
        }
    }
#else
    ctx->sender_iovec.iov_base = mesg->buffer;
    ctx->sender_iovec.iov_len = mesg->send_length;
    ctx->sender_msghdr.msg_name = &mesg->other.sa;
    ctx->sender_msghdr.msg_namelen = mesg->addr_len;
    ctx->sender_msghdr.msg_control = mesg->control_buffer;
    ctx->sender_msghdr.msg_controllen = mesg->control_buffer_size;
    
    ssize_t sent;
    
    while((sent = sendmsg(fd, &ctx->sender_msghdr, 0)) < 0)
    {
        int error_code = errno;

        if(error_code != EINTR)
        {
            return error_code;
        }
    }

    local_statistics->udp_output_size_total += sent;
#endif
        
    return SUCCESS;
}

static void*
server_rw_udp_sender_thread(void *parms)
{
    struct network_thread_context_s *ctx = (struct network_thread_context_s*)parms;
    ctx->idw = pthread_self();
    int fd = ctx->sockfd;
    
    log_debug("server_rw_udp_sender_thread(%i, %i): started", ctx->idx, fd);
    
#if HAS_PTHREAD_SETAFFINITY_NP
    cpu_set_t mycpu;
    CPU_ZERO(&mycpu);
    
    int affinity_with = g_config->thread_affinity_base + (ctx->idx * 2 + 1) * g_config->thread_affinity_multiplier;
    log_info("sender setting affinity with virtual cpu %i", affinity_with);
    CPU_SET(affinity_with, &mycpu);
    
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mycpu);
#endif
    
#if UDP_USE_MESSAGES
    ctx->sender_msghdr.msg_iov = &ctx->sender_iovec;
    ctx->sender_msghdr.msg_iovlen = 1;
    ctx->sender_msghdr.msg_control = NULL;
    ctx->sender_msghdr.msg_controllen = 0;
    ctx->sender_msghdr.msg_flags = 0;
#endif
    
    for(;;)
    {
#ifdef DEBUG1
        log_debug("server_rw_udp_sender_thread(%i, %i): dequeuing slow queries", ctx->idx, fd);
#endif
        
        message_data *mesg;
        
        mutex_lock(&ctx->mtx);

        const msg_cell_u *cell = (const msg_cell_u *)ctx->backlog_dequeue;
        

        if(ctx->backlog_enqueue == cell) // embty backlog (the next to read is also the next to be filled)
        {
            // no item on the backlog
#ifdef DEBUG1
            log_debug("server_rw_backlog_dequeue_message(%i, %i): dequeuing slow queries", ctx->idx, ctx->sockfd);
#endif
            // wait for an item from the fastlane
            
            if((mesg = (message_data*)ctx->next_message) == NULL)
            {
                // no item, so wait for an event ...

                cond_timedwait(&ctx->cond, &ctx->mtx, 1000000);
                
                while((mesg = (message_data*)ctx->next_message) == NULL)
                {
                    if(ctx->sockfd >= 0)
                    {
                        cond_timedwait(&ctx->cond, &ctx->mtx, 1000000);
                    }
                    else
                    {
                        mutex_unlock(&ctx->mtx);
                        
                        log_debug("server_rw_udp_sender_thread(%i, %i): stopped (wait->no-socket)", ctx->idx, fd);
    
                        return NULL;
                        // exit
                    }
                }
            }
            
            // there was an item, and it's now on mesg : clear the fast lane slot
            
            ctx->next_message = NULL;
                        
            mutex_unlock(&ctx->mtx);
            
#if SERVER_RW_DEBUG
            mesg->popped_us = timeus();

            log_debug("%i: look: %04hx %lluus %lluus", ctx->sockfd, ntohs(MESSAGE_ID(mesg->buffer)), mesg->pushed_us - mesg->recv_us, mesg->popped_us - mesg->pushed_us);
#endif
            if(FAIL(server_rw_udp_sender_process_message(ctx, mesg)))
            {
                if(ctx->sockfd >= 0)
                {
                    log_err("%i: look: %04hx", ctx->sockfd, ntohs(MESSAGE_ID(mesg->buffer)));
                }
                return NULL;
            }
        }
        else // there are items on the backlog
        {
            const msg_cell_u *cell_limit = (const msg_cell_u *)ctx->backlog_enqueue;
            
            mutex_unlock(&ctx->mtx);
            
            // until we processed them all (cell until but not included to cell_limit)
            
            int loop_idx = 0;
            
            yassert(cell >= &ctx->backlog_queue[0] && cell < &ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE + 1]);
            
            if(cell > cell_limit) // go up to the end of the buffer (ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE + 1])
            {
                while(cell < &ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE])
                {
                    if(cell->data.hdr.msg_size == 0) // partial cell (which can only happen if there was no room anymore for a cell
                    {
                        break;
                    }
#if SERVER_RW_DEBUG
                    u64 retrieve_start = timeus();
#endif
                    mesg = &ctx->out_message;

                    memcpy(&mesg->other.sa, &cell->data.hdr.sa, cell->data.hdr.sa_len);
#if UDP_USE_MESSAGES
                    ctx->sender_msghdr.msg_control = mesg->control_buffer;
                    memcpy(ctx->sender_msghdr.msg_control, cell->data.hdr.ctrl, cell->data.hdr.ctrl_len);
#endif
                    mesg->received = cell->data.hdr.msg_size;
                    mesg->addr_len = cell->data.hdr.sa_len;
#if UDP_USE_MESSAGES
                    ctx->sender_msghdr.msg_controllen = cell->data.hdr.ctrl_len;
#endif
                    yassert(cell->data.hdr.msg_size < 65536);
                    
                    memcpy(mesg->buffer, &cell->data.data, cell->data.hdr.msg_size);
#if SERVER_RW_DEBUG
                    mesg->popped_us = timeus();
                    
                    log_debug("%i: popd: %04hx %lluus (%i) (>)", ctx->sockfd, ntohs(MESSAGE_ID(mesg->buffer)), mesg->popped_us - retrieve_start, loop_idx);
#endif
                    if(FAIL(server_rw_udp_sender_process_message(ctx, mesg)))
                    {
                        log_err("%i: popd: %04hx (>)", ctx->sockfd, ntohs(MESSAGE_ID(mesg->buffer)));
                        return NULL;
                    }

                    ++loop_idx;

                    cell += cell->data.hdr.blk_count;
                    
                    yassert(cell >= &ctx->backlog_queue[0] && cell < &ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE + 1]);
                }
                
                cell = &ctx->backlog_queue[0];
            }
            
            yassert(cell >= &ctx->backlog_queue[0] && cell < &ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE + 1]);
            
            while(cell < cell_limit)
            {
#if SERVER_RW_DEBUG
                u64 retrieve_start = timeus();
#endif
                yassert(cell >= &ctx->backlog_queue[0] && cell < &ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE + 1]);
                
                mesg = &ctx->out_message;

                memcpy(&mesg->other.sa, &cell->data.hdr.sa, cell->data.hdr.sa_len);
#if UDP_USE_MESSAGES
                ctx->sender_msghdr.msg_control = mesg->control_buffer;
                memcpy(ctx->sender_msghdr.msg_control, cell->data.hdr.ctrl, cell->data.hdr.ctrl_len);
#endif
                mesg->received = cell->data.hdr.msg_size;
                mesg->addr_len = cell->data.hdr.sa_len;
#if UDP_USE_MESSAGES
                ctx->sender_msghdr.msg_controllen = cell->data.hdr.ctrl_len;
#endif
                memcpy(mesg->buffer, &cell->data.data, cell->data.hdr.msg_size);

#if SERVER_RW_DEBUG
                mesg->popped_us = timeus();
                log_debug("%i: popd: %04hx %lluus (%i)", ctx->sockfd, ntohs(MESSAGE_ID(mesg->buffer)), mesg->popped_us - retrieve_start, loop_idx);
#endif
                if(FAIL(server_rw_udp_sender_process_message(ctx, mesg)))
                {
                    log_err("%i: popd: %04hx", ctx->sockfd, ntohs(MESSAGE_ID(mesg->buffer)));
                    return NULL;
                }

                ++loop_idx;

                cell += cell->data.hdr.blk_count;
                
                yassert(cell >= &ctx->backlog_queue[0] && cell < &ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE + 1]);
            }
            
            yassert(cell >= &ctx->backlog_queue[0] && cell < &ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE + 1]);
            
            // cell             
            ctx->backlog_dequeue = cell;
        }
    }
    
    log_debug("server_rw_udp_sender_thread(%i, %i): stopped", ctx->idx, fd);
    
    return NULL;
}

static server_statistics_t server_statistics_sum;

ya_result
server_rw_query_loop()
{
    //u64 server_run_loop_rate_tick         = 0;
    ya_result return_code;
    s32 server_run_loop_timeout_countdown = 0;
    int maxfd = -1;

    if(g_config->total_interfaces == 0 )
    {
        return INVALID_STATE_ERROR;
    }
    
    if(server_context.tcp_socket_count <= 0)
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
    
    database = g_config->database;

    /**
     * For each interface ...
     */

    /* compute maxfd plus one once and for all : begin */

    /* Set sockets on a "template" var, so we will copy it
     * in the one we will use in pselect.  This increases
     * the speed a bit.
     */

    FD_ZERO(&read_set_init);    
    s32 reader_by_fd = g_config->thread_count_by_address / 2;
    s32 cpu_count = sys_get_cpu_count();
    if(reader_by_fd > cpu_count)
    {
        log_warn("server-rw: using too many threads per address is counter-productive on highly loaded systems (%d > %d)", reader_by_fd, cpu_count);
    }
    
    /*
     * 
     */

    // ensure the number of udp thread by interface does not goes "too much" beyond a limit
    // recompute reader_by_fd if it does
    
    if(reader_by_fd * server_context.listen_count <= 255)
    {
        reader_by_fd = MAX(reader_by_fd, 1);
    }
    else
    {
        reader_by_fd = MAX(255 / server_context.listen_count, 1);
    }
    
    //synced_init(itf_count * reader_by_fd);
    
    u64 server_run_loop_rate_tick = 0;
    u32 previous_tick = 0;
    
    extern server_context_s server_context;
    
    struct thread_pool_s *server_udp_thread_pool = thread_pool_init_ex(server_context.listen_count * reader_by_fd * 2, 1, "svrudprw");
        
    network_thread_context_s **contextes;
    MALLOC_OR_DIE(network_thread_context_s**, contextes, sizeof(network_thread_context_s*) * server_context.listen_count * reader_by_fd, RWNTCTXS_TAG);
       
    for(int listen_idx = 0, sockfd_idx = 0; listen_idx < server_context.listen_count; ++listen_idx)
    {
        for(u32 r = 0; r < reader_by_fd; r++)
        {
            network_thread_context_s *ctx;
            MALLOC_OR_DIE(network_thread_context_s*, ctx, sizeof(network_thread_context_s), RWNTCTX_TAG);
            memset(ctx, 0, sizeof(network_thread_context_s));
            contextes[sockfd_idx] = ctx;
            ctx->idx = sockfd_idx;
            ctx->sockfd = server_context.udp_socket[sockfd_idx];
            ctx->backlog_enqueue = &ctx->backlog_queue[0];
            ctx->backlog_dequeue = &ctx->backlog_queue[0];
            
            ctx->in_message[0].process_flags = ~0;
            ctx->in_message[1].process_flags = ~0;
            ctx->in_message[2].process_flags = ~0;
            ctx->out_message.process_flags = ~0;
            
            ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE].data.hdr.blk_count = 0; // implicitely done by the memset, but I want to be absolutely clear about this
            ctx->backlog_queue[SERVER_RW_BACKLOG_QUEUE_SIZE].data.hdr.msg_size = 0;
            
            mutex_init(&ctx->mtx);
            cond_init(&ctx->cond);
            
            //synced_threads.threads[tidx].intf = new_intf;
            
            log_info("thread #%i of UDP interface: %{sockaddr} using socket %i", r, server_context.udp_interface[listen_idx]->ai_addr, ctx->sockfd);

            log_debug("server_rw_query_loop: pooling #%d=%d fd=%d", sockfd_idx, ctx->idx, ctx->sockfd);
            
            if(FAIL(return_code = thread_pool_enqueue_call(server_udp_thread_pool, server_rw_udp_receiver_thread, ctx, NULL, "server-rw-recv")))
            {
                log_err("unable to schedule task : %r", return_code);
                
                return return_code;
            }
            
            if(FAIL(return_code = thread_pool_enqueue_call(server_udp_thread_pool, server_rw_udp_sender_thread, ctx, NULL, "server-rw-send")))
            {
                log_err("unable to schedule task : %r", return_code);
                
                return return_code;
            }
         
            /*
             * Update the select read set for the current interface (udp + tcp)
             */           
            
            ++sockfd_idx;
        }
    }

    for(int i = 0; i < server_context.tcp_socket_count; ++i)
    {
        int sockfd = server_context.tcp_socket[i];
        FD_SET(sockfd, &read_set_init);                    
        maxfd = MAX(maxfd, sockfd);
    }
    
    ++maxfd; /* pselect actually requires maxfd + 1 */
    
    /* compute maxfd plus one once and for all : done */


    
    log_info("ready to work");

    while(program_mode != SA_SHUTDOWN)
    {
        server_statistics.input_loop_count++;

        /* Reset the pselect read set */

        MEMCOPY(&read_set, &read_set_init, sizeof(fd_set));

        /* At this moment waits only for READ SET or timeout of x seconds */

        /*
         * @note (p)select has known bugs on Linux & glibc
         *
         * @todo 20160106 edf -- See man select about said bugs
         */

        return_code = pselect(maxfd,
                &read_set,
                NULL,
                NULL,
                &timeout,
                0);

        if(return_code > 0) /* Are any bit sets by pselect ? */
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
            
            for(int i = 0; i < server_context.tcp_socket_count; ++i)
            {
                int sockfd = server_context.tcp_socket[i];
                
                if(FD_ISSET(sockfd, &read_set))
                {
                    /* Jumps to the correct processing function */
                    server_process_tcp(g_config->database, sockfd);
                    server_statistics.loop_rate_counter++;
                }
            }
        }
        else /* return_code <= 0 */
        {
            if(return_code == -1)
            {
                if(errno != EINTR)
                {
                    /**
                     *  From the man page, what we can expect is EBADF (bug) EINVAL (bug) or ENOMEM (critical)
                     *  So I we can kill and notify.
                     */
                    log_quit("pselect returned a critical error: %r", ERRNO_ERROR);
                }
            }

            /* return_code == 0 => no fd set at all and no error => timeout */

            server_run_loop_timeout_countdown--;
            server_statistics.input_timeout_count++;
        }

#if HAS_RRL_SUPPORT
        rrl_cull();
#endif
        
#if ZDB_HAS_MUTEX_DEBUG_SUPPORT
        zdb_zone_lock_monitor_log();
#endif
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
        zdb_zone_lock_set_monitor();
#endif
        
        /* handles statistics logging */
#if 1
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
                    
                    for(int listen_idx = 0, sockfd_idx = 0; listen_idx < server_context.listen_count; ++listen_idx)
                    {
                        for(u32 r = 0; r < reader_by_fd; r++)
                        {
                            server_statistics_t *stats = &contextes[sockfd_idx]->statistics;

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
                            ++sockfd_idx;
                        }
                    }
                    
                    log_statistics(&server_statistics_sum);

                    server_run_loop_rate_tick = now;
                    server_run_loop_timeout_countdown = g_config->statistics_max_period;
                    server_statistics.loop_rate_counter = 0;
#ifdef DEBUG
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
        }
#endif  
    }

    log_info("stopping the threads");
    //synced_stop();
    
    for(int i = 0; i < 5; ++i) // 5 arbitrary loops (one every second)
    {    
        for(int listen_idx = 0, sockfd_idx = 0; listen_idx < server_context.listen_count; ++listen_idx)
        {
            for(u32 r = 0; r < reader_by_fd; r++)
            {
                network_thread_context_s *ctx = contextes[sockfd_idx];
                
                if(fd_getsockettype(ctx->sockfd) == SOCK_DGRAM)
                {
                    close_ex(ctx->sockfd);

                    for(int i = 0; i < server_context.udp_socket_count; ++i)
                    {
                        if(server_context.udp_socket[i] == ctx->sockfd)
                        {
                            server_context.udp_socket[i] = -1;
                        }
                    }
                }
                else
                {
                    if(ctx->sockfd >= 0)
                    {
                        log_warn("could not close %i: socket is not a datagram", ctx->sockfd);
                    }
                }
                
                ctx->sockfd = -1;

                pthread_t id;

                mutex_lock(&ctx->mtx);
                cond_notify(&ctx->cond);
                mutex_unlock(&ctx->mtx);

                id = ctx->idr;
                if(id != 0)
                {
                    ctx->idr = 0;
                    pthread_kill(id, SIGUSR2); 
                }

                id = ctx->idw;
                if(id != 0)
                {
                    ctx->idw = 0;
                    pthread_kill(id, SIGUSR2); 
                }

                //memset(&ctx->out_message.buffer, 0xff, 13);
                ctx->next_message = &ctx->out_message;

                mutex_lock(&ctx->mtx);
                cond_notify(&ctx->cond);
                mutex_unlock(&ctx->mtx);

                ++sockfd_idx;
            }
        }
    
        sleep(1); // this is happening while shutting down
    }
        
    /*
     * Close all zone alarm handles
     * Close database alarm handle
     */

    log_info("shutting down");
    
    //synced_finalize();
    
    thread_pool_destroy(server_udp_thread_pool);
    server_udp_thread_pool = NULL;

    for(int listen_idx = 0, sockfd_idx = 0; listen_idx < server_context.listen_count; ++listen_idx)
    {
        for(u32 r = 0; r < reader_by_fd; r++)
        {
            free(contextes[sockfd_idx]);
            ++sockfd_idx;
        }
    }
    free(contextes);

    log_debug("shutting down (pid = %u)", getpid());
    
    return SUCCESS;
}

ya_result
server_rw_context_init(int workers_per_interface)
{    
    server_context.thread_per_udp_worker_count = 2; // set in stone
    server_context.thread_per_tcp_worker_count = 1; // set in stone
    server_context.udp_unit_per_interface = MAX(workers_per_interface / 2, 1);
    server_context.tcp_unit_per_interface = 1;    
    server_context.reuse = 1;
    server_context.ready = 1;
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

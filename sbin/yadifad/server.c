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
 *  @brief Server initialisation and launch
 *
 *  Starts server
 *
 * @{
 */

#define SERVER_C_

/** @note: here we define the variable that is holding the default logger handle for the current source file
 *         Such a handle should NEVER been set in an include file.
 */

#include "server-config.h"

#include <dnscore/logger.h>
#include <dnscore/fdtools.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/thread_pool.h>
#include <dnscore/ctrl-rfc.h>
#include <dnscore/service.h>
#include <dnscore/process.h>
#include <dnscore/socket-server.h>
#if DNSCORE_HAS_TCP_MANAGER
#include <dnscore/tcp_manager.h>
#endif

logger_handle *g_server_logger = LOGGER_HANDLE_SINK;
#define MODULE_MSG_HANDLE g_server_logger

#include "signals.h"
#include "database-service.h"
#include "log_query.h"
#if !DNSCORE_HAS_TCP_MANAGER
#include "poll-util.h"
#endif
#include "server-sm.h"
#include "server-rw.h"
#if __linux__ && HAVE_SENDMMSG
#include "server-mm.h"
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
#include "dynamic-module-handler.h"
#endif

#define NETWORK_AUTO_RECONFIGURE_COUNTDOWN_DEFAULT 10

#define SVRPOOLB_TAG 0x424c4f4f50525653

// DEBUG build: log debug 5 of incoming wire
#define DUMP_TCP_RECEIVED_WIRE 0

// DEBUG build: log debug 5 of outgoing wire
#define DUMP_TCP_OUTPUT_WIRE 0

#define POOL_BUFFER_SIZE 0x80000

static struct thread_pool_s *server_tcp_thread_pool = NULL;
struct thread_pool_s *server_disk_thread_pool = NULL;

#include "server.h"

server_statistics_t server_statistics;
static bool server_statistics_initialised = FALSE;

volatile int program_mode = SA_CONT; /** @note must be volatile */

#if !__linux__ || !HAVE_SENDMMSG
static ya_result
server_notsupported_query_loop()
{
    log_err("Model is not supported on this architecture.");
    return FEATURE_NOT_SUPPORTED;
}

static ya_result
server_notsupported_context_init(int workers_per_interface)
{
    (void)workers_per_interface;
    log_err("Model is not supported on this architecture.");
    return FEATURE_NOT_SUPPORTED;
}
#endif

static struct server_desc_s server_type[] =
{
    {
        server_sm_context_init,
        server_sm_query_loop,
        "single message per syscall resolve"
    },
    {
        server_rw_context_init,
        server_rw_query_loop,
        "multithreaded deferred resolve"
    },

#if __linux__ && HAVE_SENDMMSG
    {
        server_mm_context_init,
        server_mm_query_loop,
        "multiple message per syscall resolve"
    },
#else
    {
        server_notsupported_context_init,
        server_notsupported_query_loop,
        "multiple message per syscall resolve (not supported)"
    },
#endif
    { NULL, NULL, "none"}
};

#if DNSCORE_HAS_TCP_MANAGER
/**
 * Wrapper function to send the message and log an eventual error
 *
 * @param mesg
 * @param sockfd
 */

static inline ya_result
server_tcp_reply(message_data *mesg, tcp_manager_socket_context_t *sctx)
{
    ssize_t ret;

#if DEBUG
    log_debug("tcp: %{sockaddr}: replying %i bytes", message_get_sender_sa(mesg), message_get_size(mesg));
#endif

    tcp_manager_write_update(sctx, 0);

    int fd = tcp_manager_socket(sctx);

    if(fd >= 0)
    {
        ret = message_send_tcp(mesg, fd);

        if(ISOK(ret))
        {
            tcp_manager_write_update(sctx, ret);
#if DEBUG
            log_debug("tcp: %{sockaddr}: replied %i bytes", message_get_sender_sa(mesg), message_get_size(mesg));
#endif
        }
        else
        {
            log_err("tcp: %{sockaddr}: could not reply (%i bytes): %r", message_get_sender_sa(mesg), message_get_size(mesg), (ya_result)ret);
        }
    }
    else
    {
#if DEBUG
        log_debug("tcp: %{sockaddr}: could not reply (%i bytes): connection closed", message_get_sender_sa(mesg), message_get_size(mesg));
#endif
    }

    return (ya_result)ret;
}

/**
 * Wrapper function to make an error message, then send it and log an eventual error
 *
 * @param mesg
 * @param sockfd
 */

static inline ya_result
server_tcp_reply_error(message_data *mesg, tcp_manager_socket_context_t *sctx, u16 error_code)
{
    ssize_t ret;

    log_debug("tcp: %{sockaddr}: replying %i bytes (error code %i)", message_get_sender_sa(mesg), message_get_size(mesg), error_code);

#if DNSCORE_HAS_TCP_MANAGER
    /*
    tcp_manager_set_nodelay(sctx, TRUE);
    tcp_manager_set_cork(sctx, FALSE);
     */
#else
    tcp_set_nodelay(sockfd, TRUE);
    tcp_set_cork(sockfd, FALSE);
#endif

    if(ISOK(ret = message_make_error_and_reply_tcp_with_default_minimum_throughput(mesg, error_code, tcp_manager_socket(sctx))))
    {
        tcp_manager_write_update(sctx, ret);
#if DEBUG
        log_debug("tcp: %{sockaddr}: replied %i bytes (error code %i)", message_get_sender_sa(mesg), message_get_size(mesg), error_code);
#endif
    }
    else
    {
        log_err("tcp: %{sockaddr}: could not reply error code %u (%i bytes): %r", message_get_sender_sa(mesg), message_get_size(mesg), error_code, (ya_result)ret);
    }

#if DNSCORE_HAS_TCP_MANAGER
    /*
    tcp_manager_set_nodelay(sctx, FALSE);
    tcp_manager_set_cork(sctx, TRUE);
     */
#else
    tcp_set_nodelay(sockfd, TRUE);
    tcp_set_cork(sockfd, FALSE);
#endif

    return (ya_result)ret;
}
#else

/**
 * Wrapper function to send the message and log an eventual error
 *
 * @param mesg
 * @param sockfd
 */

static inline ya_result
server_tcp_reply(message_data *mesg, int sockfd)
{
    ssize_t ret;

    if(ISOK(ret = message_update_length_send_tcp_with_default_minimum_throughput(mesg, sockfd)))
    {
    }
    else
    {
        log_err("tcp: could not answer: %r", (ya_result)ret);
    }

    return (ya_result)ret;
}

/**
 * Wrapper function to make an error message, then send it and log an eventual error
 *
 * @param mesg
 * @param sockfd
 */

static inline ya_result
server_tcp_reply_error(message_data *mesg, int sockfd, u16 error_code)
{
    ssize_t ret;
    if(ISOK(ret = message_make_error_and_reply_tcp_with_default_minimum_throughput(mesg, error_code, sockfd)))
    {
    }
    else
    {
        log_err("tcp: could not answer: %r", (ya_result)ret);
    }

    return (ya_result)ret;
}
#endif



/*******************************************************************************************************************
 *
 * TCP protocol
 *
 ******************************************************************************************************************/

/** \brief Does the tcp processing
 *
 *  When pselect has an TCP request, this function reads the tcp packet,
 *  processes dns packet and send reply
 *
 *  @param[in,out] mesg
 *
 *  @retval OK
 *  @return status of message is written in message_get_status(mesg)
 */

#if DNSCORE_HAS_TCP_MANAGER
static int
server_process_tcp_task(message_data *mesg, tcp_manager_socket_context_t *sctx, u16 svr_sockfd)
#else
static int
server_process_tcp_task(message_data *mesg, int sockfd, u16 svr_sockfd)
#endif

{
    ya_result                                   ret = SUCCESS;

    u16                                                 dns_query_len;
    ssize_t                                              received = 0;
    ssize_t
    next_message_size;
#if DEBUG
    int log_only_sockfd;
#if DNSCORE_HAS_TCP_MANAGER
    log_only_sockfd = tcp_manager_socket(sctx);
#else
    log_only_sockfd = sockfd;
#endif
#endif

#if DEBUG
    log_debug("tcp: processing %{sockaddr} (socket %i )", message_get_sender_sa(mesg), log_only_sockfd);
#endif
    
    int loop_count = 0;

#if DNSCORE_HAS_TCP_MANAGER
    tcp_manager_set_recvtimeout(sctx, 3, 0);
    tcp_manager_set_sendtimeout(sctx, 3, 0);
    /*
    tcp_manager_set_nodelay(sctx, FALSE);
    tcp_manager_set_cork(sctx, TRUE);
     */
#else
    tcp_set_recvtimeout(sockfd, 1, 0);
    tcp_set_sendtimeout(sockfd, 1, 0);
    tcp_set_nodelay(sockfd, FALSE);
    tcp_set_cork(sockfd, TRUE);
#endif
    
    /** @note do a full read, not one that can be interrupted or deliver only a part of what we need (readfully) */

    s64 time_start;

    for(;;)
    {
        time_start = timeus();
#if DEBUG
        log_debug("tcp: waiting for length prefix, loop %i", loop_count);
#endif

#if DNSCORE_HAS_TCP_MANAGER
        // tcp_manager_cancellable(sctx); // tells that it's about to wait for something new
        next_message_size = tcp_manager_read_fully(sctx, (u8*)&dns_query_len, 2);
#else
        next_message_size = readfully_limited_ex(sockfd, &dns_query_len, 2, 3000000, g_config->tcp_query_min_rate_us);
#endif
        if(next_message_size != 2)
        {
            s64 time_stop = timeus();
            s64 d = MAX(time_stop - time_start, 0);
            double s = d / ONE_SECOND_US_F;

            if(next_message_size < 0)
            {
                ret = (ya_result)next_message_size;

                if(ret != MAKE_ERRNO_ERROR(EBADF))
                {
                    log_err("tcp: %{sockaddr}: loop %i: length prefix not received after %5.3fs: %r", message_get_sender_sa(mesg), loop_count, s, ret);
                }
                else
                {
                    log_info("tcp: %{sockaddr}: loop %i: length prefix not received after %5.3fs: connection closed", message_get_sender_sa(mesg), loop_count, s);
                }
            }
            else
            {
                ret = MAKE_ERRNO_ERROR(ETIMEDOUT);
#if DEBUG
                log_debug("tcp: %{sockaddr}: loop %i: length prefix not received after %5.3fs (%x)", message_get_sender_sa(mesg), loop_count, s, next_message_size);
#endif
            }

            break;
        }

        ++loop_count;
        
#if DEBUG
        log_debug("tcp: %{sockaddr}: loop %i", message_get_sender_sa(mesg), loop_count);
#endif
        u16 native_dns_query_len = ntohs(dns_query_len);

        if(native_dns_query_len == 0)
        {
            log_notice("tcp: %{sockaddr}: message size is 0", message_get_sender_sa(mesg));

            ret = UNPROCESSABLE_MESSAGE;

            break;
        }

        if(dnscore_shuttingdown())
        {
            ret = STOPPED_BY_APPLICATION_SHUTDOWN;

            break;
        }

        /** 
         *  read with an expected rate
         */

#if DEBUG
        log_debug("tcp: %{sockaddr}: waiting for %i bytes", message_get_sender_sa(mesg), native_dns_query_len);
#endif

#if DNSCORE_HAS_TCP_MANAGER
        received = tcp_manager_read_fully(sctx, message_get_buffer(mesg), native_dns_query_len);
#else
        received = readfully_limited_ex(sockfd, message_get_buffer(mesg), native_dns_query_len, 3000000, g_config->tcp_query_min_rate_us);
#endif

        if(received != native_dns_query_len)
        {
            if(ISOK(received))
            {
                log_notice("tcp: %{sockaddr}: message read: received %d bytes but %hd were expected", message_get_sender_sa(mesg), received, native_dns_query_len);
            }
            else
            {
                log_notice("tcp: %{sockaddr}: message read: %r", message_get_sender_sa(mesg), ERRNO_ERROR);
            }
            
            message_set_size(mesg, 0);

#if DNSCORE_HAS_TCP_MANAGER
            //
#else
            tcp_set_abortive_close(sockfd);
#endif

            ret = UNPROCESSABLE_MESSAGE;

            break;
        }

        message_set_size(mesg, received);

#if DEBUG
        log_debug("tcp: %{sockaddr}: received %i bytes", message_get_sender_sa(mesg), native_dns_query_len);
#endif
        
#if DEBUG
#if DUMP_TCP_RECEIVED_WIRE
        log_memdump_ex(g_server_logger, MSG_DEBUG5, message_get_buffer(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif
#endif
        message_set_protocol(mesg, IPPROTO_TCP);
        
        switch(message_get_opcode(mesg))
        {
            case OPCODE_QUERY:
            {
                if(ISOK(ret = message_process_query(mesg)))
                {
                    message_edns0_clear_undefined_flags(mesg);
                    message_reset_buffer_size(mesg);

                    switch(message_get_query_class(mesg))
                    {
                        case CLASS_IN:
                        {
                            log_query(svr_sockfd, mesg);                                                        

                            if(message_get_query_type(mesg) == TYPE_AXFR)
                            {
                                /*
                                 * Start an AXFR "writer" thread
                                 * Give it the tcp fd
                                 * It will store the current AXFR on the disk if it does not exist yet (writers blocked)
                                 * It will then open the stored file and stream it back to the tcp fd (writers freed)
                                 * ACL/TSIG is not taken in account yet.
                                 */

                                TCPSTATS(tcp_axfr_count++);

#if DNSCORE_HAS_TCP_MANAGER
                                ret = axfr_process(mesg, sctx);
#else
                                ret = axfr_process(mesg, sockfd);
#endif

#if DEBUG
                                log_debug("tcp: %{sockaddr}: axfr_process done : %r", message_get_sender_sa(mesg), ret);
#endif
                                return ret; /* AXFR PROCESSING: process then closes: all in background */
                            }

                            if(message_get_query_type(mesg) == TYPE_IXFR)
                            {
                                /*
                                 * Start an IXFR "writer" thread
                                 * Give it the tcp fd
                                 * It will either send the incremental changes (stored on the disk), either answer with an AXFR
                                 * ACL/TSIG is not taken in account yet.
                                 */

                                TCPSTATS(tcp_ixfr_count++);
#if DNSCORE_HAS_TCP_MANAGER
                                ret = ixfr_process(mesg, sctx);
#else
                                ret = ixfr_process(mesg, sockfd);
#endif

#if DEBUG
                                log_debug("tcp: %{sockaddr}: ixfr_process done : %r", message_get_sender_sa(mesg), ret);
#endif
                                return ret; /* IXFR PROCESSING: process then closes: all in background */
                            }

#if DEBUG
                            log_debug("tcp: %{sockaddr}: querying database", message_get_sender_sa(mesg));
#endif

                            TCPSTATS(tcp_queries_count++);

                            /*
                             * This query must go through the task channel.
                             */

                            database_query(g_config->database, mesg);

#if DNSCORE_HAS_TCP_MANAGER
                            ret = server_tcp_reply(mesg, sctx);
#else
                            ret = server_tcp_reply(mesg, sockfd);
#endif
                            TCPSTATS(tcp_referrals_count += message_get_referral(mesg));
                            TCPSTATS(tcp_fp[message_get_status(mesg)]++);
                            TCPSTATS(tcp_output_size_total += message_get_size(mesg));

                            break;
                        } // case query IN
                        case CLASS_CH:
                        {
                            log_query(svr_sockfd, mesg);
                            class_ch_process(mesg);
                            TCPSTATS(tcp_fp[message_get_status(mesg)]++);

#if DNSCORE_HAS_TCP_MANAGER
                            ret = server_tcp_reply(mesg, sctx);
#else
                            ret = server_tcp_reply(mesg, sockfd);
#endif

                            break;
                        }
                        default:
                        {
#if DNSCORE_HAS_TCP_MANAGER
                            server_tcp_reply_error(mesg, sctx, FP_NOT_SUPP_CLASS);
#else
                            server_tcp_reply_error(mesg, sockfd, FP_NOT_SUPP_CLASS);
#endif
                            TCPSTATS(tcp_fp[FP_NOT_SUPP_CLASS]++);
                            break;
                        }
                    } // query class
                } // if message process succeeded
                else // an error occurred : no query to be done at all
                {
                    log_warn("query [%04hx] from %{sockaddr} error %i : %r", ntohs(message_get_id(mesg)), message_get_sender_sa(mesg), message_get_status(mesg), ret);

                    TCPSTATS(tcp_fp[message_get_status(mesg)]++);
                    
                    if(ret == UNPROCESSABLE_MESSAGE && (g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE))
                    {
                        log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, message_get_buffer_const(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_ALL);
                    }
                    
                    if( (ret != INVALID_MESSAGE) &&
                        (((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0) || (message_get_status(mesg) != RCODE_FORMERR)) &&
                        message_isquery(mesg) )
                    {
                        if(!message_has_tsig(mesg))
                        {
                            message_transform_to_error(mesg);
                        }

#if DNSCORE_HAS_TCP_MANAGER
                        ret = server_tcp_reply(mesg, sctx);
#else
                        ret = server_tcp_reply(mesg, sockfd);
#endif
                    }
                    else
                    {
                        TCPSTATS(tcp_dropped_count++);

#if !DNSCORE_HAS_TCP_MANAGER
                        tcp_set_agressive_close(sockfd, 1);
#endif
                    }
                }

                break;
            } // case query

            case OPCODE_NOTIFY:
            {
                if(ISOK(ret = message_process(mesg)))
                {
                    message_reset_buffer_size(mesg);

                    switch(message_get_query_class(mesg))
                    {
                        case CLASS_IN:
                        {
                            // a master sent a notify using TCP ...
                            
                            notify_process(mesg);

#if DNSCORE_HAS_TCP_MANAGER
                            ret = server_tcp_reply(mesg, sctx);
#else
                            ret = server_tcp_reply(mesg, sockfd);
#endif

                            TCPSTATS(tcp_notify_input_count++);
                            break;
                        }
                        default:
                        {
#if DNSCORE_HAS_TCP_MANAGER
                            ret = server_tcp_reply_error(mesg, sctx, FP_NOT_SUPP_CLASS);
#else
                            ret = server_tcp_reply_error(mesg, sockfd, FP_NOT_SUPP_CLASS);
#endif
                            TCPSTATS(tcp_fp[FP_NOT_SUPP_CLASS]++);
                            break;
                        }
                    } // notify class
                } // if message process succeeded
                else // an error occurred : no query to be done at all
                {
                    log_warn("notify [%04hx] from %{sockaddr} error %i : %r", ntohs(message_get_id(mesg)), message_get_sender_sa(mesg), message_get_status(mesg), ret);

                    TCPSTATS(tcp_fp[message_get_status(mesg)]++);
#if DEBUG
                    log_memdump_ex(MODULE_MSG_HANDLE, MSG_DEBUG5, message_get_buffer(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_ALL);
#endif
                    if( (ret != INVALID_MESSAGE) && ((message_get_status(mesg) != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)) && message_isquery(mesg) )
                    {
                        if(!message_has_tsig(mesg))
                        {
                            message_transform_to_error(mesg);
                        }

#if DNSCORE_HAS_TCP_MANAGER
                        ret = server_tcp_reply(mesg, sctx);
#else
                        ret = server_tcp_reply(mesg, sockfd);
#endif
                    }
                    else
                    {
                        TCPSTATS(tcp_dropped_count++);

#if !DNSCORE_HAS_TCP_MANAGER
                        tcp_set_agressive_close(sockfd, 1);
#endif
                    }
                }
                break;
            } // case notify
            case OPCODE_UPDATE:
            {
                if(ISOK(ret = message_process(mesg)))
                {
                    message_edns0_clear_undefined_flags(mesg);

                    switch(message_get_query_class(mesg))
                    {
                        case CLASS_IN:
                        {
                            /*
                             * _ Post an update on the scheduler
                             * _ wait for the end of the update
                             * _ proceed
                             */

                            /**
                             * @note It's the responsibility of the called function (or one of its callees) to ensure
                             *       this does not take much time and thus to trigger a background task with the
                             *       scheduler if needed.
                             */
#if HAS_DYNUPDATE_SUPPORT
                            TCPSTATS(tcp_updates_count++);

                            if(message_get_query_type(mesg) == TYPE_SOA)
                            {
                                log_info("update [%04hx] %{dnsname} from %{sockaddr}",
                                        ntohs(message_get_id(mesg)),
                                        message_get_canonised_fqdn(mesg),
                                        message_get_sender_sa(mesg));
                            }
                            else
                            {
                                log_info("update [%04hx] %{dnsname} %{dnstype} from %{sockaddr}",
                                         ntohs(message_get_id(mesg)),
                                         message_get_canonised_fqdn(mesg),
                                         message_get_query_type_ptr(mesg),
                                         message_get_sender_sa(mesg));
                            }

                            if(FAIL(database_update(g_config->database, mesg)))
                            {
                                if(message_get_status(mesg) == RCODE_NOERROR)
                                {
                                    message_set_status(mesg, FP_RCODE_SERVFAIL);
                                }
                            }

#if DNSCORE_HAS_TCP_MANAGER
                            ret = server_tcp_reply(mesg, sctx);
#else
                            ret = server_tcp_reply(mesg, sockfd);
#endif
                            TCPSTATS(tcp_fp[message_get_status(mesg)]++);
#else
                            ya_result send_ret;
                            if(FAIL(send_ret = message_make_error_and_reply_tcp_with_default_minimum_throughput(mesg, FP_FEATURE_DISABLED, sockfd)))
                            {
                                log_notice("tcp: could not answer: %r", send_ret);
                            }
                            TCPSTATS(tcp_fp[FP_FEATURE_DISABLED]++);
#endif
                            break;
                        } // update class IN
                        default:
                        {
#if DNSCORE_HAS_TCP_MANAGER
                            server_tcp_reply_error(mesg, sctx, FP_NOT_SUPP_CLASS);
#else
                            server_tcp_reply_error(mesg, sockfd, FP_NOT_SUPP_CLASS);
#endif
                            TCPSTATS(tcp_fp[FP_NOT_SUPP_CLASS]++);
                            break;
                        }
                    } // update class
                } // if message process succeeded
                else // an error occurred : no query to be done at all
                {
                    log_warn("update [%04hx] from %{sockaddr} error %i : %r", ntohs(message_get_id(mesg)), message_get_sender_sa(mesg),  message_get_status(mesg), ret);

                    TCPSTATS(tcp_fp[message_get_status(mesg)]++);
#if DEBUG
                    log_memdump_ex(MODULE_MSG_HANDLE, MSG_DEBUG5, message_get_buffer(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_ALL);
#endif
                    if( (ret != INVALID_MESSAGE) && (((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0) || (message_get_status(mesg) != RCODE_FORMERR)) && message_isquery(mesg) )
                    {
                        if(!message_has_tsig(mesg))
                        {
                            message_transform_to_error(mesg);
                        }

#if DNSCORE_HAS_TCP_MANAGER
                        ret = server_tcp_reply(mesg, sctx);
#else
                        ret = server_tcp_reply(mesg, sockfd);
#endif
                    }
                    else
                    {
                        TCPSTATS(tcp_dropped_count++);

#if !DNSCORE_HAS_TCP_MANAGER
                        tcp_set_agressive_close(sockfd, 1);
#endif
                    }
                }
                break;
            } // case update
#if HAS_CTRL
            case OPCODE_CTRL:
            {
#if DNSCORE_HAS_TCP_MANAGER
                int sockfd = tcp_manager_socket(sctx);
#endif
                if(ctrl_query_is_listened(sockfd))
                {
                    // note: ctrl_message_process contains reply code

                    ret = ctrl_message_process(mesg, sockfd);
                }
                else
                {
                    // this IP/port is not configured to listen CTRL queries

                    TCPSTATS(tcp_dropped_count++);
#if !DNSCORE_HAS_TCP_MANAGER
                    tcp_set_agressive_close(sockfd, 1);
#endif
                }

                break;
            } // case ctrl
#endif // HAS_CTRL
            default:
            {
                log_warn("unknown opcode %x [%04hx] from %{sockaddr} error: %r", message_get_opcode(mesg), ntohs(message_get_id(mesg)), message_get_sender_sa(mesg), MAKE_DNSMSG_ERROR(FP_NOT_SUPP_OPC));
                
                if( (ret != INVALID_MESSAGE) && (((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0) || (message_get_status(mesg) != RCODE_FORMERR)) && message_isquery(mesg) )
                {
                    if(ISOK(ret = message_process_lenient(mesg)))
                    {
                        message_set_status(mesg, FP_RCODE_NOTIMP);
                        message_transform_to_error(mesg);

                        if(message_has_tsig(mesg))
                        {
                            tsig_sign_answer(mesg);
                        }

#if DNSCORE_HAS_TCP_MANAGER
                        ret = server_tcp_reply(mesg, sctx);
#else
                        ret = server_tcp_reply(mesg, sockfd);
#endif
                    }
                }
                else
                {
                    TCPSTATS(tcp_dropped_count++);

#if !DNSCORE_HAS_TCP_MANAGER
                    tcp_set_agressive_close(sockfd, 1);
#endif
                }
            }
        } // switch operation code

        if(FAIL(ret))
        {
#if DEBUG
            log_debug("tcp: %{sockaddr}: failed with : %r", message_get_sender_sa(mesg), ret);
#endif
            break;
        }

    } // while received bytes

    if(loop_count > 0)
    {
        // If the next message size is not 2, then we didn't had to expect a message     
        
        if(next_message_size == 2)
        {
            // If we have got an error while receiving (tcp too slow), then abort the connection

            if(ISOK(received))
            {
#if !DNSCORE_HAS_TCP_MANAGER
                tcp_set_agressive_close(sockfd, 1);
#endif
            }
            else
            {
                log_notice("tcp: %{sockaddr} message #%i processing failed: %r", message_get_sender_sa(mesg), loop_count, received);
#if !DNSCORE_HAS_TCP_MANAGER
                tcp_set_abortive_close(sockfd);
#endif
            }
        }
        else
        {
            // We processed at least one message but this last one was either
            // non-existent, or truncated, or too slow :
            //
            // We give it a second and we close.

#if !DNSCORE_HAS_TCP_MANAGER
            tcp_set_agressive_close(sockfd, 1);
#endif
        }

        s64 time_stop = timeus();
        s64 d = MAX(time_stop - time_start, 0);
        double s = d / ONE_SECOND_US_F;

        log_debug("tcp: %{sockaddr}: loop %i took %5.3fs", message_get_sender_sa(mesg), loop_count, s);
    }
    else
    {
        s64 time_stop = timeus();
        s64 d = MAX(time_stop - time_start, 0);
        double s = d / ONE_SECOND_US_F;
        
        if(next_message_size < 0)
        {
            log_notice("tcp: %{sockaddr}: connection didn't sent the message size after %5.3fs: %r", message_get_sender_sa(mesg), s, next_message_size);
        }
        else if(next_message_size > 0) // a.k.a : 1 
        {
            log_notice("tcp: %{sockaddr}: connection didn't sent the message size after %5.3fs", message_get_sender_sa(mesg), s);
        }
        else
        {
            log_notice("tcp: %{sockaddr}: connection closed after %5.3fs", message_get_sender_sa(mesg), s);
        }

#if !DNSCORE_HAS_TCP_MANAGER
        tcp_set_abortive_close(sockfd);
#endif
    }

#if DEBUG
#if DNSCORE_HAS_TCP_MANAGER
    log_debug("tcp: %{sockaddr} closing socket %i, loop %i", message_get_sender_sa(mesg), tcp_manager_socket(sctx), loop_count);
#else
	log_debug("tcp: %{sockaddr} closing socket %i, loop %i", message_get_sender_sa(mesg), sockfd, loop_count);
#endif
#endif

#if DNSCORE_HAS_TCP_MANAGER

	if(FAIL(ret))
    {
	    // should close
	    tcp_manager_context_close_and_release(sctx);
    }
    else
    {
        tcp_manager_context_release(sctx); /// @note don't : tcp_manager_close(sctx);
    }
#else
    shutdown(sockfd, SHUT_RDWR);
    close_ex(sockfd);
#endif

    return ret;
}

typedef struct server_process_tcp_thread_parm server_process_tcp_thread_parm;

struct server_process_tcp_thread_parm
{
#if DNSCORE_HAS_TCP_MANAGER
    tcp_manager_socket_context_t *sctx;
#else
    //zdb *database;
    socketaddress sa;
    socklen_t addr_len;
    int sockfd;
#endif
    int svr_sockfd;
};

static void*
server_process_tcp_thread(void* parm)
{
#if DEBUG
    log_debug("tcp: begin");
#endif
    server_process_tcp_thread_parm* tcp_parm = (server_process_tcp_thread_parm*)parm;
    message_data_with_buffer mesg_buff;

#if DEBUG
    memset(&mesg_buff, 0xff, sizeof(mesg_buff));
#endif
    message_data *mesg = message_data_with_buffer_init(&mesg_buff); // tcp
    
    size_t pool_buffer_size = POOL_BUFFER_SIZE; // 128KB
    u8 *pool_buffer;
    MALLOC_OBJECT_ARRAY_OR_DIE(pool_buffer, u8, pool_buffer_size, SVRPOOLB_TAG);
    message_set_pool_buffer(mesg, pool_buffer, pool_buffer_size);
#if DNSCORE_HAS_TCP_MANAGER
    message_copy_sender_from_sa(mesg, &(tcp_manager_socketaddress(tcp_parm->sctx)->sa), tcp_manager_socklen(tcp_parm->sctx));
#else
    message_copy_sender_from_sa(mesg, &tcp_parm->sa.sa, tcp_parm->addr_len);
#endif

#if DEBUG
    log_debug("tcp: processing stream from %{sockaddr}", message_get_sender_sa(mesg));
#endif

#if DNSCORE_HAS_TCP_MANAGER
    server_process_tcp_task(mesg, tcp_parm->sctx, tcp_parm->svr_sockfd);
#else
    server_process_tcp_task(mesg, tcp_parm->sockfd, tcp_parm->svr_sockfd);
#endif

    free(pool_buffer);
    free(parm);

#if DEBUG
    log_debug("tcp: end");
#endif

    return NULL;
}

void
server_process_tcp(int servfd)
{
    server_process_tcp_thread_parm* parm;

    /*
     * AFAIK there are two relevant fields in mesg at this point: addr & sockfd
     * After the accept only the sockfd is relevant
     */

    /* I know I'm already in an #if with the same condition but I want to mark
     * the code I've c&p from the original do_tcp_process
     */

#if DEBUG
    log_debug("server_process_tcp_thread_start begin");
#endif

#if DNSCORE_HAS_TCP_MANAGER

    ya_result ret;
    tcp_manager_socket_context_t* sctx = (tcp_manager_socket_context_t*)(intptr)0x5a5a5a5a;

    if((ret = tcp_manager_accept(servfd, &sctx)) >= 0)
    {
        TCPSTATS(tcp_input_count++);

        assert(sctx != NULL);

        log_debug("server_process_tcp: scheduling job");

        MALLOC_OBJECT_OR_DIE(parm, server_process_tcp_thread_parm, TPROCPRM_TAG);
        parm->sctx = sctx;
        parm->svr_sockfd = servfd;

        thread_pool_enqueue_call(server_tcp_thread_pool, server_process_tcp_thread, parm, NULL, "server_process_tcp_thread_start");
    }
    else
    {
        log_debug("server_process_tcp: %r", ret);

        TCPSTATS(tcp_overflow_count++);
    }

#else

    socklen_t addr_len;
    socketaddress addr;
    addr_len = sizeof(addr);

    int current_tcp = poll_update();

    /**
     * @note we MAY want to accept & close before rejecting.  But in case of a DOS we lose.
     *       here we will just ignore until it's possible to do something about it (or it's cancelled)
     *
     */

    if(current_tcp >= g_config->max_tcp_queries)
    {
        log_info("tcp: rejecting: already %d/%d handled", current_tcp, g_config->max_tcp_queries);

        int rejected_fd = accept(servfd, &addr.sa, &addr_len);

        tcp_set_abortive_close(rejected_fd);
        close_ex(rejected_fd);

        TCPSTATS(tcp_overflow_count++);
        
        return;
    }

    TCPSTATS(tcp_input_count++);

    MALLOC_OBJECT_OR_DIE(parm, server_process_tcp_thread_parm, TPROCPRM_TAG);

    /* don't test -1, test < 0 instead (test + js instead of add + stall + jz */
    while((parm->sockfd = accept(servfd, &addr.sa, &addr_len)) < 0)
    {
        int err = errno;

        if(err != EINTR)
        {
            log_err("tcp: accept returned %r", MAKE_ERRNO_ERROR(err));
            free(parm);
            return;
        }
    }

    if(addr_len > MAX(sizeof(struct sockaddr_in),sizeof(struct sockaddr_in6)))
    {
        log_err("tcp: addr_len = %i, max allowed is %i", addr_len, MAX(sizeof(struct sockaddr_in),sizeof(struct sockaddr_in6)));

        close_ex(parm->sockfd);
        
        free(parm);

        return;
    }

    memcpy(&parm->sa, &addr, addr_len);
    parm->addr_len = addr_len;
    parm->svr_sockfd = servfd;
    
    if(poll_add(parm->sockfd))
    {
        log_debug("tcp: using slot %d/%d", current_tcp + 1 , g_config->max_tcp_queries);

        /*
         * And here is the AXFR change: if it's an AXFR, then we need to ensure that
         * _ we are allowed (TSIG, time limit between two AXFR "milestones", ...)
         * _ we have the AXFR file ready and if not, fork to generate it
         *
         * The thread is launched anyway and waits for the file with the right serial to be generated.
         * When the file is finally available, it is sent to the caller.
         *
         * If it's not an AXFR, then we do as ever.
         */

#if DEBUG
        log_debug("server_process_tcp_thread_start scheduling job");
#endif

        thread_pool_enqueue_call(server_tcp_thread_pool, server_process_tcp_thread, parm, NULL, "server_process_tcp_thread_start");
    }
    else
    {
        log_debug("server_process_tcp_thread_start tcp overflow");
        
        close_ex(parm->sockfd);
        free(parm);
    }
#endif

#if DEBUG
    log_debug("server_process_tcp_thread_start end");
#endif
}

/*******************************************************************************************************************
 *
 * Server init, load, start, stop and exit
 *
 ******************************************************************************************************************/

static struct service_s server_service_handler = UNINITIALIZED_SERVICE;
static bool server_handler_initialised = FALSE;

static ya_result
server_network_init()
{
    ya_result ret;
    
    // this sets-up variables in g_server_context

    for(int i = 0; server_type[i].name != NULL; ++i)
    {
        if(i == g_config->network_model)
        {
            log_info("spawning %s", server_type[g_config->network_model].name);

            if(FAIL(ret = server_type[g_config->network_model].context_init(g_config->thread_count_by_address)))
            {
                log_err("network model '%s' cannot be initialised: %r", server_type[g_config->network_model].name, ret);
                break;
            }

            log_info("using %i working modules per UDP interface (%i threads per UDP module)", g_server_context.udp_unit_per_interface, g_server_context.thread_per_udp_worker_count);
            log_info("using %i working modules per TCP interface (%i threads per TCP module)", g_server_context.tcp_unit_per_interface, g_server_context.thread_per_tcp_worker_count);

            ret = server_context_create();

            return ret;
        }
    }

    log_err("couldn't not set network model %i: not supported", g_config->network_model);

    if(g_config->network_model != 0)
    {
        g_config->network_model = 0;
        log_warn("switching to network model %i (%s)", g_config->network_model, server_type[g_config->network_model].name);
        ret = server_network_init();
        return ret;
    }
    else
    {
        return FEATURE_NOT_SUPPORTED;
    }
}

/** @brief Startup server with all its processes
 *
 *  Never returns. Ends with the program.
 */

static ya_result
server_run(struct service_worker_s *worker)
{
    ya_result ret = server_type[g_config->network_model].loop(worker);
    

        
    return ret;
}

static int
server_service_apply_configuration()
{
    int ret;
    
    if(ISOK(ret = server_network_init()))
    {
        if((server_tcp_thread_pool != NULL) && (((int)thread_pool_get_size(server_tcp_thread_pool) != g_config->max_tcp_queries)))
        {
            // the thread-pool size is wrong
            ya_result return_code;

            if(FAIL(return_code = thread_pool_resize(server_tcp_thread_pool, g_config->max_tcp_queries)))
            {
                return return_code;
            }

            if(return_code != g_config->max_tcp_queries)
            {
                log_err("could not properly set the TCP handlers");
                return INVALID_STATE_ERROR;
            }
        }

        if((server_tcp_thread_pool == NULL) && (g_config->max_tcp_queries > 0))
        {
            server_tcp_thread_pool = thread_pool_init_ex(g_config->max_tcp_queries, g_config->max_tcp_queries * 2, "svrtcp");

            if(server_tcp_thread_pool == NULL)
            {
                log_err("tcp thread pool init failed");

                return THREAD_CREATION_ERROR;
            }
        }

        if(server_disk_thread_pool == NULL)
        {
            server_disk_thread_pool = thread_pool_init_ex(4, 64, "diskio");

            if(server_disk_thread_pool == NULL)
            {
                log_warn("disk thread pool init failed");

                return THREAD_CREATION_ERROR;
            }
        }
#if DEBUG
        OSDEBUG(termout, "I come to serve ...\n");

        log_info("I come to serve ..."); /** I could not resist ... */
#endif
        /* Initialises the TCP usage limit structure (It's global and defined at the beginning of server.c */

#if !DNSCORE_HAS_TCP_MANAGER
        poll_alloc(g_config->max_tcp_queries);
#endif

        log_debug("thread count by address: %i", g_config->thread_count_by_address);
    }
    
    return ret;
}

void server_context_destroy();

static void
server_service_deconfigure()
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
    }

    if(server_disk_thread_pool != NULL)
    {
        log_info("destroying disk pool");
        thread_pool_destroy(server_disk_thread_pool);
        server_disk_thread_pool = NULL;
    }

#if !DNSCORE_HAS_TCP_MANAGER
    poll_free();
#endif

    log_info("clearing server context");

    /* Clear config struct and close all fd's */
    server_context_stop();

    log_info("destroying server context");

    server_context_destroy();
}

static int
server_service_main(struct service_worker_s *worker)
{
    ya_result ret = SUCCESS;

    server_process_message_udp_set_database(g_config->database);

    service_set_servicing(worker);
    
    log_info("server starting with pid %lu", getpid_ex());
    
#if HAS_RRL_SUPPORT
    // Sets the RRL
    
    rrl_init();
#endif

    // initialises the statistics

    if(!server_statistics_initialised)
    {
        server_statistics_initialised = TRUE;
        
        ZEROMEMORY(&server_statistics, sizeof(server_statistics_t));
        mutex_init(&server_statistics.mtx);
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
     * ... && (message_is_query(mesg) ??? and if there the query number is > 0 ???
     */

    bool reconfigure = TRUE;

    s64 network_setup_complain_last = 0;
    bool network_worked_once = FALSE;

    int network_auto_reconfigure_countdown = NETWORK_AUTO_RECONFIGURE_COUNTDOWN_DEFAULT;
    
    while(service_should_run(worker))
    {
        if(reconfigure) // because we may not really have to reconfigure
        {
            if(ISOK(ret = server_service_apply_configuration()))
            {
                log_info("server setup ready");

                network_worked_once = TRUE;

                service_clear_reconfigure(worker);

#if HAS_EVENT_DYNAMIC_MODULE
                dynamic_module_settings();
#endif
            }
            else
            {
                s64 now = timeus();

                if(ret == MAKE_ERRNO_ERROR(EPIPE))
                {
                    log_err("socket server connection broken");
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
                        log_err("yadifad hasn't been started as root. This network error is irrecoverable: stopping the server");
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
                sleep(1);

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

        /// reconfigure = TRUE; /// check if configuration has changed (difficult before cfgv3)
        
        if(reconfigure)
        {
            server_service_deconfigure();
        }
    }
    
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

ya_result
server_service_init()
{
    ya_result ret = SERVICE_ALREADY_INITIALISED;

#if DNSCORE_HAS_TCP_MANAGER
    tcp_manager_init();
#endif
    
    if(!server_handler_initialised && ISOK(ret = service_init_ex(&server_service_handler, server_service_main, "yadifad", 1)))
    {
        error_register(SUCCESS_DROPPED, "DROPPED");
        server_handler_initialised = TRUE;
    }
    
    return ret;
}

bool
server_service_started()
{
    return server_handler_initialised && !service_stopped(&server_service_handler);
}

ya_result
server_service_start()
{
    int err = SERVICE_NOT_INITIALISED;

    if(server_handler_initialised)
    {
        if(service_stopped(&server_service_handler))
        {
            err = service_start(&server_service_handler);
        }
    }

    return err;
}

ya_result
server_service_start_and_wait()
{
    int ret = SERVICE_NOT_INITIALISED;
    
    if(server_handler_initialised)
    {
        if(service_stopped(&server_service_handler))
        {
            ret = service_start_and_wait(&server_service_handler);
        }
    }
    
    return ret;
}

ya_result
server_service_wait()
{
    int ret = SERVICE_NOT_INITIALISED;
    if(server_handler_initialised)
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

ya_result
server_service_stop_nowait()
{
    int err = SERVICE_NOT_INITIALISED;

    if(server_handler_initialised)
    {
        err = SERVICE_NOT_RUNNING;

        dynupdate_query_service_reset();

        if(!service_stopped(&server_service_handler))
        {
            err = service_stop(&server_service_handler);
        }
    }

    return err;
}


ya_result
server_service_stop()
{
    int err = SERVICE_NOT_INITIALISED;
    
    if(server_handler_initialised)
    {
        err = SERVICE_NOT_RUNNING;

        dynupdate_query_service_reset();

        if(!service_stopped(&server_service_handler))
        {
            err = service_stop(&server_service_handler);
            service_wait(&server_service_handler);
        }
    }
    
    return err;
}

ya_result
server_service_reconfigure()
{
    int err = SERVICE_NOT_INITIALISED;
    
    if(server_handler_initialised)
    {
        err = SERVICE_NOT_RUNNING;

        if(!service_stopped(&server_service_handler))
        {
            dynupdate_query_service_reset();
            err = service_reconfigure(&server_service_handler);
        }
    }
    
    return err;
}

ya_result
server_service_finalize()
{
    int err = SERVICE_NOT_INITIALISED;
    
    if(server_handler_initialised)
    {
        err = server_service_stop();
        
        service_finalize(&server_service_handler);
        
        server_handler_initialised = FALSE;
    }

    return err;
}

/** @} */

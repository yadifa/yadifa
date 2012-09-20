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
* DOCUMENTATION */

/**
 *  @defgroup server Server
 *  @ingroup yadifad
 *  @brief Server initialisation and launch
 *
 *  Starts server
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#define SERVER_C_

/** @note: here we define the variable that is holding the default logger handle for the current source file
 *         Such a handle should NEVER been set in an include file.
 */

#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/fdtools.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/thread_pool.h>

#include "signals.h"
#include "scheduler_database_load_zone.h"
#include "log_query.h"
#include "poll-util.h"
#include "server-st.h"
#include "server-mt.h"
#include "notify.h"
#include "server_context.h"
#include "axfr.h"
#include "ixfr.h"
#include "process_class_ch.h"
#include "process_class_ctrl.h"


#if defined(HAS_MESSAGES_SUPPORT)
#define UDP_USE_MESSAGES 1
#endif

#define MODULE_MSG_HANDLE g_server_logger
logger_handle *g_server_logger;

#include "server.h"

server_statistics_t server_statistics;


volatile int program_mode = SA_CONT; /** @note must be volatile */

/*******************************************************************************************************************
 *
 * TCP protocol
 *
 ******************************************************************************************************************/

void
tcp_send_message_data(message_data* mesg)
{
    ya_result sent;

    mesg->buffer_tcp_len[0]       = (mesg->send_length >> 8);
    mesg->buffer_tcp_len[1]       = (mesg->send_length);

    /*
     * Message status cannot be used here to set the rcode.
     * The main reason being : it is better done when the message is built
     * The other reason being : OPT contains extended codes. A pain to parse and handle here.
     */

    //zassert(((mesg->status < 15) && ((MESSAGE_LOFLAGS(mesg->buffer) & RCODE_BITS) == mesg->status)) || (mesg->status >= 15) );

    log_debug("tcp: answering %d bytes @%p to socket %d", mesg->send_length + 2, mesg->buffer_tcp_len, mesg->sockfd);
    
    /**
     * SAME AS READ : THERE HAS TO BE A RATE !
     */
#if !defined(HAS_DROPALL_SUPPORT)
    if(FAIL(sent = writefully_limited(mesg->sockfd, mesg->buffer_tcp_len, mesg->send_length + 2, g_config->tcp_query_min_rate_us)))
    {
        log_err("tcp write error: %r", sent);

        tcp_set_abortive_close(mesg->sockfd);
    }
#endif
}

/** \brief Does the tcp processing
 *
 *  When pselect has an TCP request, this function reads the tcp packet,
 *  processes dns packet and send reply
 *
 *  @param[in,out] mesg
 *
 *  @retval OK
 *  @return status of message is written in mesg->status
 */

static int
server_process_tcp_task(database_t *database, message_data *mesg, u16 svr_sockfd)
{
    ya_result                                   return_code = SUCCESS;

    u16                                                 dns_query_len;
    ssize_t                                                  received;

#ifndef NDEBUG
    log_info("tcp: processing socket %i (%{sockaddr})", mesg->sockfd, &mesg->other.sa);
    int loop_count = 0;
#endif
    
    tcp_set_recvtimeout(mesg->sockfd, 1, 0);
    
    /** @note do a full read, not one that can be interrupted or deliver only a part of what we need (readfully) */
    while((received = readfully_limited(mesg->sockfd, &dns_query_len, 2, g_config->tcp_query_min_rate_us)) == 2)
    {
#ifndef NDEBUG
        log_debug("tcp: loop count = %d", ++loop_count);
#endif
        
        u16 native_dns_query_len = ntohs(dns_query_len);

        if(native_dns_query_len == 0)
        {
            log_err("tcp: message size is 0");

            /** @todo no linger, check the best place to do it */

            return_code = UNPROCESSABLE_MESSAGE;

            break;
        }

        /** @todo test: timeout
         *  NOTE: A TIMEOUT IS NOT ENOUGH, THERE HAS TO BE A RATE !!!
         */

        if((mesg->received = readfully_limited(mesg->sockfd, mesg->buffer, native_dns_query_len, g_config->tcp_query_min_rate_us)) != native_dns_query_len)
        {
            log_err("tcp: message read (received %i bytes, err=%r)", mesg->received, ERRNO_ERROR);

            tcp_set_abortive_close(mesg->sockfd);

            return_code = UNPROCESSABLE_MESSAGE;

            break;
        }

        mesg->protocol = IPPROTO_TCP;

        if(ISOK(return_code = message_process(mesg)))
        {
            mesg->size_limit = DNSPACKET_MAX_LENGTH;

            switch(mesg->qclass)
            {
                case CLASS_IN:
                {
                    switch(MESSAGE_OP(mesg->buffer))
                    {
                        case OPCODE_QUERY:
                        {
                            log_query(svr_sockfd, mesg);                                                        
                            
                            if(mesg->qtype == TYPE_AXFR)
                            {
                                /*
                                 * Start an AXFR "writer" thread
                                 * Give it the tcp fd
                                 * It will store the current AXFR on the disk if it does not exist yet (writers blocked)
                                 * It will then open the stored file and stream it back to the tcp fd (writers freed)
                                 * ACL/TSIG is not taken in account yet.
                                 */

                                TCPSTATS(tcp_axfr_count++);
                                
                                return_code = axfr_process(mesg);

#ifndef NDEBUG
                                log_debug("server_process_tcp scheduled : %r", return_code);
#endif

                                return return_code; /* AXFR PROCESSING: process then closes: all in background */
                            }

                            if(mesg->qtype == TYPE_IXFR)
                            {
                                /*
                                 * Start an IXFR "writer" thread
                                 * Give it the tcp fd
                                 * It will either send the incremental changes (stored on the disk), either answer with an AXFR
                                 * ACL/TSIG is not taken in account yet.
                                 */

                                TCPSTATS(tcp_ixfr_count++);
                                return_code = ixfr_process(mesg);

#ifndef NDEBUG
                                log_debug("server_process_tcp scheduled : %r", return_code);
#endif

                                return return_code; /* IXFR PROCESSING: process then closes: all in background */
                            }

#ifndef NDEBUG
                            log_debug("server_process_tcp query");
#endif

                            TCPSTATS(tcp_queries_count++);

							/*
							 * This query must go through the task channel.
							 */
                            
#if 0
                            database_delegate_query(database, mesg); /* waits for answer */
#else                       
                            database_query(database, mesg);
#endif
                            
#if 0
                            if(mesg->is_delegation)
                            {
#ifdef DEBUG
                                log_debug("query [%04hx] %{dnsname} %{dnstype} %{dnsclass} : is a referral", ntohs(MESSAGE_ID(mesg->buffer)), mesg->qname, &mesg->qtype, &mesg->qclass);
#endif
                                TCPSTATS(tcp_referrals_count++);
                            }
#endif
#ifndef NDEBUG
                            log_debug("server_process_tcp write");
#endif

                            tcp_send_message_data(mesg);
                            
                            TCPSTATS(tcp_referrals_count += mesg->referral);
                            TCPSTATS(tcp_fp[mesg->status]++);
                            TCPSTATS(tcp_output_size_total += mesg->send_length);

                            break;
                        }
                        case OPCODE_NOTIFY:
                        {
                            TCPSTATS(tcp_notify_input_count++);
                            /**
                             * @todo notify on tcp
                             */
                            break;
                        }
                        case OPCODE_UPDATE:
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

                            TCPSTATS(tcp_updates_count++);

                            log_info("update (%04hx) %{dnsname} %{dnstype} (%{sockaddr})",
                                    ntohs(MESSAGE_ID(mesg->buffer)),
                                    mesg->qname,
                                    &mesg->qtype,
                                    &mesg->other.sa);

                            if(ISOK(database_delegate_update(database, mesg)))
                            {
                                tcp_send_message_data(mesg);
                                TCPSTATS(tcp_fp[mesg->status]++);
                            }

                            break;
                        }
                        default:
                        {
                            TCPSTATS(tcp_undefined_count++);
                            /* Maybe we should only log this with a high verbose level. */

                            log_warn("query (%04hx) Unhandled opcode %i (%{sockaddrip})", ntohs(MESSAGE_ID(mesg->buffer)), (MESSAGE_OP(mesg->buffer) & OPCODE_BITS) >> 3, &mesg->other.sa);

                            /**
                             * Build a notimp answer
                             *
                             */

                            message_make_error(mesg, FP_NOT_SUPP_OPC);
                            TCPSTATS(tcp_fp[FP_NOT_SUPP_OPC]++);
                            
                            break;
                        }
                    }   /* switch opcode */

                    break;
                }
                case CLASS_CH:
                {
                    if(MESSAGE_OP(mesg->buffer) == OPCODE_QUERY)
                    {
                        log_query(svr_sockfd, mesg);
                        
                        process_class_ch(mesg);
                        
                        TCPSTATS(tcp_fp[mesg->status]++);
                    }
                    else
                    {
                        log_warn("query [%04hx] %{dnsname} %{dnstype} CH (%{sockaddrip}) : unsupported operation %x",
                                    ntohs(MESSAGE_ID(mesg->buffer)),
                                    mesg->qname, &mesg->qtype,
                                    &mesg->other.sa, MESSAGE_OP(mesg->buffer));
                        /*
                         * Somebody tried to do something wrong on the CH class
                         */

                        message_make_error(mesg, FP_NOT_SUPP_OPC);
                        TCPSTATS(tcp_fp[FP_NOT_SUPP_OPC]++);
                    }

                    tcp_send_message_data(mesg);

                    break;
                }
                default:
                {
                    /**
                     * @todo Handle unknown classes better
                     */
                    log_warn("query [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : unsupported class",
                                    ntohs(MESSAGE_ID(mesg->buffer)),
                                    mesg->qname, &mesg->qtype, &mesg->qclass,
                                    &mesg->other.sa);
                    
                    mesg->status = FP_CLASS_NOTFOUND;
                    message_transform_to_error(mesg);
                    TCPSTATS(tcp_fp[FP_CLASS_NOTFOUND]++);
                    
                    break;
                }
            } /* switch class */
        }
        else
        {
            log_warn("query [%04hx] error %i : %r", ntohs(MESSAGE_ID(mesg->buffer)), mesg->status, return_code);

            TCPSTATS(tcp_fp[mesg->status]++);
            
            if( (return_code != INVALID_MESSAGE) && (((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0) || mesg->status != RCODE_FORMERR) && (MESSAGE_QR(mesg->buffer) == 0) )
            {
                message_transform_to_error(mesg);
                
                tcp_send_message_data(mesg);
            }
            else
            {
                TCPSTATS(tcp_dropped_count++);
                break;
            }
        }
    }

    if(received != 0)
    {
        log_info("tcp: received = %x", received);

        tcp_set_abortive_close(mesg->sockfd);
    }

#ifndef NDEBUG
	log_info("tcp: closing socket %i, loop count = %d", mesg->sockfd, loop_count);
#endif

    close_ex(mesg->sockfd);
    
    mesg->sockfd = -1;

    return return_code;
}

typedef struct server_process_tcp_thread_parm server_process_tcp_thread_parm;

struct server_process_tcp_thread_parm
{
    database_t *database;
    socketaddress sa;
    socklen_t addr_len;
    int sockfd;
    int svr_sockfd;
};

static void*
server_process_tcp_thread(void* parm)
{
#ifndef NDEBUG
    log_debug("tcp: begin");
#endif

    server_process_tcp_thread_parm* tcp_parm = (server_process_tcp_thread_parm*)parm;
    message_data mesg;

#ifndef NDEBUG
    memset(&mesg, 0xff, sizeof(message_data));
#endif

    mesg.sockfd = tcp_parm->sockfd;

    mesg.process_flags = ~0; /** @todo FIX ME */

    memcpy(&mesg.other, &tcp_parm->sa, tcp_parm->addr_len);
    mesg.addr_len = tcp_parm->addr_len;

    server_process_tcp_task(tcp_parm->database, &mesg, tcp_parm->svr_sockfd);

    free(parm);

#ifndef NDEBUG
    log_debug("tcp: end");
#endif

    return NULL;
}

void
server_process_tcp(database_t *database, tcp *tcp_itf)
{
    server_process_tcp_thread_parm* parm;

    /*
     * AFAIK there are two relevant fields in mesg at this point: addr & sockfd
     * After the accept only the sockfd is relevant
     */

    /* I know I'm already in an #if with the same condition but I want to mark
     * the code I've c&p from the original do_tcp_process
     */

#ifndef NDEBUG
    log_debug("server_process_tcp_thread_start begin");
#endif

    int current_tcp = poll_update();

    /**
     * @note we MAY want to accept & close before rejecting.  But in case of a DOS we lose.
     *       here we will just ignore until it's possible to do something about it (or it's cancelled)
     *
     */

    if(current_tcp >= g_config->max_tcp_queries)
    {
        log_info("tcp: rejecting: already %d/%d handled", current_tcp, g_config->max_tcp_queries);

        TCPSTATS(tcp_overflow_count++);
        
        return;
    }

    TCPSTATS(tcp_input_count++);

    MALLOC_OR_DIE(server_process_tcp_thread_parm*, parm, sizeof(server_process_tcp_thread_parm), TPROCPRM_TAG);
    parm->database = database;

    socketaddress addr;
    socklen_t addr_len = sizeof(addr);

    /** @todo test: timeout */

    /* don't test -1, test < 0 instead (test + js instead of add + stall + jz */
    while((parm->sockfd = accept(tcp_itf->sockfd, &addr.sa, &addr_len)) < 0)
    {
		int err = errno;

        if(err != EINTR)
        {
			log_err("tcp: accept returned %r\n", MAKE_ERRNO_ERROR(err));

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
    parm->svr_sockfd = tcp_itf->sockfd;
    
    poll_add(parm->sockfd);

    log_info("tcp: using slot %d/%d", current_tcp + 1 , g_config->max_tcp_queries);

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

#ifndef NDEBUG
    log_debug("server_process_tcp_thread_start scheduling job");
#endif

    thread_pool_schedule_job(server_process_tcp_thread, parm, NULL, "server_process_tcp_thread_start");

#ifndef NDEBUG
    log_debug("server_process_tcp_thread_start end");
#endif
}

/*******************************************************************************************************************
 *
 * UDP protocol
 *
 ******************************************************************************************************************/

void
udp_send_message_data(message_data* mesg)
{
    ssize_t sent;

#ifndef NDEBUG
    if(mesg->send_length <= 12)
    {
        log_debug("wrong output message of status %i size %i", mesg->status, mesg->send_length);
        
        log_memdump_ex(g_server_logger, LOG_DEBUG, mesg->buffer, mesg->send_length, 32, TRUE, TRUE, FALSE);
    }
#endif

#if !defined(HAS_DROPALL_SUPPORT)
    
#if 1// UDP_USE_MESSAGES == 0
    
#ifdef DEBUG
    log_debug("udp_send_message_data: sendto(%d, %p, %d, %d, %{sockaddr}, %d)", mesg->sockfd, mesg->buffer, mesg->send_length, 0, (struct sockaddr*)&mesg->other.sa, mesg->addr_len);
#endif
    while((sent = sendto(mesg->sockfd, mesg->buffer, mesg->send_length, 0, (struct sockaddr*)&mesg->other.sa, mesg->addr_len)) < 0)
    {
        int error_code = errno;

        if(error_code != EINTR)
        {
            /** @warning server_st_process_udp needs to be modified */
            //log_err("sendto: %r", MAKE_ERRNO_ERROR(error_code));

            return /*ERROR*/;
        }
    }
#else

    udp_iovec.iov_len = mesg->send_length;
    
#ifdef DEBUG
    log_debug("udp_send_message_data: sendmsg(%d, %p, %d", mesg->sockfd, &udp_msghdr, 0);
#endif
    
    while( (sent = sendmsg(mesg->sockfd, &udp_msghdr, 0)) < 0)
    {
        int error_code = errno;

        if(error_code != EINTR)
        {
            /** @warning server_st_process_udp needs to be modified */
            log_err("sendmsg: %r", MAKE_ERRNO_ERROR(error_code));

            server_statistics.udp_send_error_count++;

            return /*ERROR*/;
        }

        server_statistics.udp_send_eintr_count++;
    }
#endif

    server_statistics.udp_output_size_total += sent;

    if(sent != mesg->send_length)
    {
        /** @warning server_st_process_udp needs to be modified */
        log_err("short byte count sent (%i instead of %i)", sent, mesg->send_length);

        /*return ERROR*/;
    }
#else
    log_debug("udp_send_message_data: drop all");
#endif

    /*return SUCCESS*/;
}


/*******************************************************************************************************************
 *
 * Server init, load, start, stop and exit
 *
 ******************************************************************************************************************/

/** @brief Startup server with all its processes
 *
 *  Never returns. Ends with the program.
 */

void
server_run()
{
    ya_result return_code;

    log_info("server starting: pid=%lu", getpid());

    /* Initializing of yadifa database */

    database_init(); /* Inits the db, starts the threads of the pool, resets the timer */

    /* Resets the statistics */

    ZEROMEMORY(&server_statistics, sizeof (server_statistics_t));
    mutex_init(&server_statistics.mtx);
    
    log_info("loading zones");
    
    if(FAIL(return_code = database_load(&g_config->database, &g_config->zones)))
    {
        log_err("loading zones: %r", return_code);

        exit(EXIT_CODE_DATABASE_LOAD_ERROR);
    }

    OSDEBUG(termout, "I come to serve ...\n");

    log_info("I come to serve ..."); /** I could not resist ... */

    /** @todo check this function */
    database_signature_maintenance(g_config->database);

    /* Initialises the TCP usage limit structure (It's global and defined at the beginning of server.c */

    poll_alloc(g_config->max_tcp_queries);

    /* Go to work */
    
    log_info("thread count by address: %i", g_config->thread_count_by_address);

    if(g_config->thread_count_by_address <= 0)
    {
        log_info("single worker engine");
        server_st_query_loop();
    }
    else
    {
        log_info("multiple workers engine");
        server_mt_query_loop();
    }

    notify_shutdown();
    
    database_load_shutdown();

    /* Proper shutdown. All this could be simply dropped since it takes time for "nothing".
     * But it's good to check that nothing is broken.
     */

    poll_free();
    
    log_info("clearing context");
    
    /* Clear config struct and close all fd's */
    server_context_clear(g_config);
    
#if ZDB_DEBUG_MALLOC != 0
    formatln("block_count=%d", debug_get_block_count());
    
    flushout();
    flusherr();
    
    debug_stat(true);

#endif

    flushout();
    flusherr();

    exit(EXIT_SUCCESS);

    /* Never reached ... */
}

/** @} */

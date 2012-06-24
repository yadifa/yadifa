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
 *  @defgroup yadifad
 *  @ingroup server
 *  @brief Single threaded server. This one has the best performance on all of our setups with kernels <= 2.6.32
 *
 *  This is the default and best server available for Yadifa.
 *  It works like this:
 *  A select is made on all network file descriptors with a timeout of 1 second.
 *  Each usable descriptor is then processed.
 *  _ UDP are single threaded (receive, process, send)
 *  _ TCP are multithreaded (accept, thread(process & send))
 *  Then the scheduler tasks are processed.
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#define SERVER_ST_C_

/** @note: here we define the variable that is holding the default logger handle for the current source file
 *         Such a handle should NEVER been set in an include file.
 */

#define MODULE_MSG_HANDLE g_server_logger

#include <dnscore/logger.h>

#include <dnscore/fdtools.h>

#include <dnscore/tcp_io_stream.h>

#include <dnsdb/zdb_types.h>

#include <dnscore/message.h>
#include <dnscore/timems.h>

#include <dnscore/scheduler.h>

#include "server-st.h"

#include "server_context.h"
#include "server_error.h"

#include "signals.h"

#include "axfr.h"
#include "ixfr.h"
#include "notify.h"
#include "process_class_ch.h"
#include "process_class_ctrl.h"

#include "scheduler_database_load_zone.h"

#include "log_statistics.h"
#include "log_query.h"
#include "poll-util.h"

#define POLLFDBF_TAG 0x464244464c4c4f50
#define TPROCPRM_TAG 0x4d5250434f525054
#define MESGDATA_TAG 0x415441444753454d
#define MSGHDR_TAG 0x52444847534d

#if defined(HAS_MIRROR_SUPPORT)
#define DUMB_MIRROR 1
#endif

/**
 * @note This flag enables the alternative send/rcvd for udp (from 'to' to 'msg')
 */

#if defined(HAS_MESSAGES_SUPPORT)
#define UDP_USE_MESSAGES 1
#endif

/* #define UDP_USE_MESSAGES 1 */

#if UDP_USE_MESSAGES != 0

/*
 * from: http://www.mombu.com/programming/c/t-how-to-get-udp-destination-address-on-incoming-packets-7784569.html
 */

#define ANCILIARY_BUFFER_SIZE 65536

#if defined IP_RECVDSTADDR
# define DSTADDR_SOCKOPT IP_RECVDSTADDR
# define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_addr)))
# define dstaddr(x) (CMSG_DATA(x))
#elif defined IP_PKTINFO
# define DSTADDR_SOCKOPT IP_PKTINFO
# define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_pktinfo)))
# define dstaddr(x) (&(((struct in_pktinfo *)(CMSG_DATA(x)))->ipi_addr))
#else
# error "can't determine socket option"
#endif
/*
union cmsghdr_dstaddr {
struct cmsghdr cmsg;
u_char data[DSTADDR_DATASIZE];
};
*/
#endif

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

/* Helper macro to edit a field with a lock.  Named after the only user of that mechanism : tcp handling */


static message_data *udp_mesg = NULL;

static log_query_function* log_query = log_query_yadifa;

#if UDP_USE_MESSAGES != 0

static struct iovec    udp_iovec;
static struct cmsghdr *udp_cmsghdr /*= (struct cmsghdr*)&udp_cmsghdr_dstaddr*/;
static struct msghdr   udp_msghdr;

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
 *  @return status of message is written in mesg->status
 */

static int
server_st_process_tcp_task(database_t *database, message_data *mesg, u16 svr_sockfd)
{
    ya_result                                   return_code = SUCCESS;

    u16                                                 dns_query_len;
    ssize_t                                                  received;

#ifndef NDEBUG
    log_info("tcp: processing socket %i (%{sockaddr})", mesg->sockfd, &mesg->other.sa);
#endif
    
    tcp_set_recvtimeout(mesg->sockfd, 1, 0);
    
    /** @note do a full read, not one that can be interrupted or deliver only a part of what we need (readfully) */
    while((received = readfully_limited(mesg->sockfd, &dns_query_len, 2, g_config->tcp_query_min_rate_us)) == 2)
    {
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

        mesg->protocol = IPPROTO_TCP; /** @note never used ! */

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
                                log_debug("server_st_process_tcp scheduled : %r", return_code);
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
                                log_debug("server_st_process_tcp scheduled : %r", return_code);
#endif

                                return return_code; /* IXFR PROCESSING: process then closes: all in background */
                            }

#ifndef NDEBUG
                            log_debug("server_st_process_tcp query");
#endif

                            TCPSTATS(tcp_queries_count++);

							/*
							 * This has to be a lockable query
							 */
                            
                            database_query(database, mesg);

#ifndef NDEBUG
                            log_debug("server_st_process_tcp write");
#endif

                            tcp_send_message_data(mesg);

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

                            log_query_i("update (%04hx) %{dnsname} %{dnstype} (%{sockaddr})",
                                    ntohs(MESSAGE_ID(mesg->buffer)),
                                    mesg->qname,
                                    &mesg->qtype,
                                    &mesg->other.sa);

                            if(ISOK(database_schedule_update(database, mesg)))
                            {
                                tcp_send_message_data(mesg);
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
                    
                    break;
                }
            } /* switch class */
        }
        else
        {
            log_warn("query [%04hx] error %i : %r", ntohs(MESSAGE_ID(mesg->buffer)), mesg->status, return_code);

            if( (return_code != INVALID_MESSAGE) && (((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0) || mesg->status != RCODE_FORMERR) && (MESSAGE_QR(mesg->buffer) == 0) )
            {
                message_transform_to_error(mesg);
                
                tcp_send_message_data(mesg);
            }
        }
    }

    if(received != 0)
    {
        log_info("tcp: received = %x", received);

        tcp_set_abortive_close(mesg->sockfd);
    }

#ifndef NDEBUG
	log_info("tcp: closing socket %i", mesg->sockfd);
#endif

    close(mesg->sockfd);

    return return_code;
}

typedef struct server_st_process_tcp_thread_parm server_st_process_tcp_thread_parm;

struct server_st_process_tcp_thread_parm
{
    database_t *database;
    socketaddress sa;
    socklen_t addr_len;
    int sockfd;
    int svr_sockfd;
};

static void*
server_st_process_tcp_thread(void* parm)
{
#ifndef NDEBUG
    log_debug("tcp: begin");
#endif

    server_st_process_tcp_thread_parm* tcp_parm = (server_st_process_tcp_thread_parm*)parm;
    message_data mesg;

#ifndef NDEBUG
    memset(&mesg, 0xff, sizeof(message_data));
#endif

    mesg.sockfd = tcp_parm->sockfd;

    mesg.process_flags = ~0; /** @todo FIX ME */

    memcpy(&mesg.other, &tcp_parm->sa, tcp_parm->addr_len);
    mesg.addr_len = tcp_parm->addr_len;

    server_st_process_tcp_task(tcp_parm->database, &mesg, tcp_parm->svr_sockfd);

    free(parm);

#ifndef NDEBUG
    log_debug("tcp: end");
#endif

    return NULL;
}

static void
server_st_process_tcp(database_t *database, tcp *tcp_itf)
{
    server_st_process_tcp_thread_parm* parm;

    /*
     * AFAIK there are two relevant fields in mesg at this point: addr & sockfd
     * After the accept only the sockfd is relevant
     */

    /* I know I'm already in an #if with the same condition but I want to mark
     * the code I've c&p from the original do_tcp_process
     */

#ifndef NDEBUG
    log_debug("server_st_process_tcp_thread_start begin");
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

        return;
    }

    TCPSTATS(tcp_input_count++);

    MALLOC_OR_DIE(server_st_process_tcp_thread_parm*, parm, sizeof(server_st_process_tcp_thread_parm), TPROCPRM_TAG);
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

        close(parm->sockfd);
        
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
    log_debug("server_st_process_tcp_thread_start scheduling job");
#endif

    thread_pool_schedule_job(server_st_process_tcp_thread, parm, NULL, "server_st_process_tcp_thread_start");

#ifndef NDEBUG
    log_debug("server_st_process_tcp_thread_start end");
#endif
}

/*******************************************************************************************************************
 *
 * UDP protocol
 *
 ******************************************************************************************************************/

/** \brief Does the udp processing
 *
 *  When pselect has an UDP request, this function reads the udp packet,
 *  processes dns packet and send reply
 *
 *  @param[in,out] mesg
 *
 *  @retval OK
 *  @return status of message is written in mesg->status
 */

static void
server_st_process_udp(database_t *database, udp *udp_itf)
{
    int return_code;
    int fd = udp_itf->sockfd;

    server_statistics.udp_input_count++;

    message_data *mesg;

    mesg = udp_mesg;

    /*    ------------------------------------------------------------    */

    mesg->sockfd = fd;

    /*
     * It used to be :
     *
     * mesg->received = Recvfrom(fd, mesg->buffer, NETWORK_BUFFER_SIZE, 0, (struct sockaddr*)&mesg->other.sa, &mesg->addr_len);
     *
     * But this is called a LOT.  So the 3 cycles or so lost soley for the call are not something we want to afford.
     *
     */

    ssize_t n;

#if UDP_USE_MESSAGES == 0
    while((n = recvfrom(fd, mesg->buffer, sizeof(mesg->buffer), 0, (struct sockaddr*)&mesg->other.sa, &mesg->addr_len)) < 0)
    {
        /*
         * errno is not a variable but a macro
         *
         */
        int err = errno;

        if(err == EINTR)
        {
            continue;
        }

        /**
         * @todo Do we want this or do we just return ?
         */

        log_quit("recvfrom error : %r", MAKE_ERRNO_ERROR(err));
    }

#else

    udp_iovec.iov_len = sizeof(udp_mesg->buffer);
    udp_msghdr.msg_controllen = ANCILIARY_BUFFER_SIZE;

    while((n = recvmsg(fd, &udp_msghdr, 0)) < 0)
    {
        int err = errno;

        if(err == EINTR)
        {
            continue;
        }

        /**
         * @todo Do we want this or do we just return ?
         */

        log_quit("recvmsg error : %r", MAKE_ERRNO_ERROR(err));
    }

    struct sockadd_in *sav4;

#endif

    mesg->received = n;

    /**
     * In case of processing error, message_process will return UNPROCESSABLE_MESSAGE
     * which means there must be no query/update/... done on it.
     * If the message status is not "dropped" then the message will be sent back as it is to the client.
     */

#if defined(DUMB_MIRROR) && (DUMB_MIRROR == 1)
	mesg->send_length = mesg->received;
#else

    if(ISOK(return_code = message_process(mesg)))
    {

#if defined(DUMB_MIRROR) && (DUMB_MIRROR == 2)

        mesg->send_length = mesg->received;
#else
        switch(mesg->qclass)
        {
            case CLASS_IN:
            {
                switch(MESSAGE_OP(mesg->buffer))
                {
                    case OPCODE_QUERY:
                    {
                        /**
                         * @note Our experiments (old and new) all show that monothread is the way to go for udp queries
                         *
                         */

                        server_statistics.udp_queries_count++;

                        log_query(fd, mesg);
                        
                        switch(mesg->qtype)
                        {
                            default:
                                database_query(database, mesg);
                                server_statistics.udp_fp[mesg->status]++;
                                break;
                            case TYPE_IXFR:
                                MESSAGE_FLAGS_OR(mesg->buffer, QR_BITS|TC_BITS, 0); /** @todo IXFR UDP */
                                SET_U32_AT(mesg->buffer[4], 0);
                                SET_U32_AT(mesg->buffer[8], 0);
                                mesg->send_length = DNS_HEADER_LENGTH;
                                server_statistics.udp_fp[FP_IXFR_UDP]++;
                                break;
                            case TYPE_AXFR:
                            case TYPE_OPT:
                                message_make_error(mesg, FP_INCORR_PROTO);
                                server_statistics.udp_fp[FP_INCORR_PROTO]++;
                                break;
                        }

                        break;
                    }
                    case OPCODE_NOTIFY:
                    {
                        ya_result return_value;

                        server_statistics.udp_notify_input_count++;

                        log_info("notify (%04hx) %{dnsname} (%{sockaddr})",
                                ntohs(MESSAGE_ID(mesg->buffer)),
                                mesg->qname,
                                &mesg->other.sa);

                        bool answer = MESSAGE_QR(mesg->buffer);                        
                        return_value = notify_process(database, mesg);
                        
                        server_statistics.udp_fp[mesg->status]++;
                        
                        if(FAIL(return_value))
                        {
                            log_err("notify (%04hx) %{dnsname} failed : %r",
                                    ntohs(MESSAGE_ID(mesg->buffer)),
                                    mesg->qname,
                                    return_value);
                            
                            if(answer)
                            {
                                return;
                            }
                            
                            message_transform_to_error(mesg);
                            break;
                        }
                        else
                        {
                            if(answer)
                            {
                                return;
                            }
                        }
                    }
                    case OPCODE_UPDATE:
                    {
                        /**
                         * @note It's the responsibility of the called function (or one of its callees) to ensure
                         *       this does not take much time and thus to trigger a background task with the
                         *       scheduler if needed.
                         */

                        ya_result return_value;

                        server_statistics.udp_updates_count++;

                        log_info("update (%04hx) %{dnsname} %{dnstype} (%{sockaddr})",
                                ntohs(MESSAGE_ID(mesg->buffer)),
                                mesg->qname,
                                &mesg->qtype,
                                &mesg->other.sa);

                        if(FAIL(return_value = database_update(database, mesg)))
                        {
                            log_err("update (%04hx) %{dnsname} %{dnstype} failed: %r",
                                    ntohs(MESSAGE_ID(mesg->buffer)),
                                    mesg->qname,
                                    &mesg->qtype,
                                    return_value);
                        }
                        
                        server_statistics.udp_fp[mesg->status]++;

                        break;
                    }
                    default:
                    {
                        /* Maybe we should only log this with a high verbose level. */
                        server_statistics.udp_undefined_count++;

                        log_warn("query (%04hx) Unhandled opcode %i (%{sockaddr})",
                                ntohs(MESSAGE_ID(mesg->buffer)),
                                (MESSAGE_OP(mesg->buffer) & OPCODE_BITS) >> 3,
                                &mesg->other.sa);

                        /**
                         * Build a notimp answer
                         */

                        message_make_error(mesg, FP_NOT_SUPP_OPC);
                        server_statistics.udp_fp[FP_NOT_SUPP_OPC]++;

                        break;
                    }
                }

                break;
            }

            case CLASS_CH:
            {
                if(MESSAGE_OP(mesg->buffer) == OPCODE_QUERY)
                {
                    process_class_ch(mesg);
                    server_statistics.udp_fp[mesg->status]++;
                }
                else
                {
                    log_warn("query [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : unsupported operation",
                                ntohs(MESSAGE_ID(mesg->buffer)),
                                mesg->qname, &mesg->qtype, &mesg->qclass,
                                &mesg->other.sa);
                    /*
                     * Somebody tried to do something wrong on the CH class
                     */

                    message_make_error(mesg, FP_NOT_SUPP_OPC);
                    server_statistics.udp_fp[FP_NOT_SUPP_OPC]++;
                }
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
                server_statistics.udp_fp[FP_CLASS_NOTFOUND]++;
                
                break;
            }

        } /* switch class*/

#endif
    }
    else /* An error occured : no query to be done at all */
    {
        log_warn("query (%04hx) [%02x|%02x] error %i (%r) (%{sockaddrip})",
                 ntohs(MESSAGE_ID(mesg->buffer)),
                 MESSAGE_HIFLAGS(mesg->buffer),MESSAGE_LOFLAGS(mesg->buffer),
                 mesg->status,
                 return_code,
                 &mesg->other.sa);
        
        server_statistics.udp_fp[mesg->status]++;
        
        /*
         * If not FE, or if we answer FE
         * 
         * ... && (MESSAGE_QR(mesg->buffer) == 0 ??? and if there the query number is > 0 ???
         */
        if( (return_code != INVALID_MESSAGE) && ((mesg->status != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)))
        {
            message_transform_to_error(mesg);
        }
        else
        {
            server_statistics.udp_dropped_count++;
            return;
        }

        /** @note Testing of performance in MIRROR_SWITCH mode can only be done in UDP
         *	      Removing completely the mirror_switch feature should improve performance a bit
         */
    }
#endif
    /** @todo still needs to verify RCODE */

	ssize_t sent;

#ifndef NDEBUG
    if(mesg->send_length <= 12)
    {
        log_debug("wrong output message of status %i size %i", mesg->status, mesg->send_length);
        
        log_memdump_ex(g_server_logger, LOG_DEBUG, mesg->buffer, mesg->send_length, 32, TRUE, TRUE, FALSE);
    }
#endif

#if !defined(HAS_DROPALL_SUPPORT)
    
#if UDP_USE_MESSAGES == 0
    
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
    log_debug("sendmsg(%d, %p, %d", mesg->sockfd, &udp_msghdr, 0);
#endif
    
    while( (sent = sendmsg(mesg->sockfd, &udp_msghdr, 0)) < 0)
    {
        int error_code = errno;

        if(error_code != EINTR)
        {
            /** @warning server_st_process_udp needs to be modified */
            log_err("sendmsg: %r", MAKE_ERRNO_ERROR(error_code));

            return /*ERROR*/;
        }
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
}

/*******************************************************************************************************************
 *
 * Server loop
 *
 ******************************************************************************************************************/

/** \brief continuous loop waiting for a query
 *
 *  Each child server runs this function
 *  Waits for a pselect or SA_SHUTDOWN,
 *  if pselect is ready, does the messaging processing and jumps to the
 *  correct function
 *
 *  @param server_context
 *
 *  @retval OK
 */
static u64 server_run_loop_rate_tick         = 0;
static u64 server_run_loop_rate_count        = 0;
static s32 server_run_loop_timeout_countdown = 0;

ya_result
server_st_query_loop()
{
    ya_result return_code;
    interface *intf;

#if ZDB_USES_ZALLOC != 0
    zdb_set_zowner(pthread_self());
#endif

    fd_set read_set;
    fd_set read_set_init;

    struct timespec timeout;
    int maxfd;

    u32 previous_tick = 0;

    if(g_config->total_interfaces == 0)
    {
        return ERROR;
    }
    
    switch(g_config->queries_log_type)
    {
        case 1:
            log_query = log_query_yadifa;
            break;
        case 2:
            log_query = log_query_bind;
            break;
        case 3:
            log_query = log_query_both;
            break;
        default:
            log_query = log_query_none;
            break;
    }

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

    /* Clear and initialize mesg */
    if(udp_mesg == NULL)
    {
        MALLOC_OR_DIE(message_data*, udp_mesg, sizeof (message_data), MESGDATA_TAG);
    }

    ZEROMEMORY(udp_mesg, sizeof (message_data));
    udp_mesg->addr_len      = sizeof(udp_mesg->other);
    udp_mesg->protocol      = IPPROTO_UDP;                  /** @note never used ! */
    udp_mesg->size_limit    = UDPPACKET_MAX_LENGTH;
    udp_mesg->process_flags = ~0; /** @todo FIX ME */

#if UDP_USE_MESSAGES != 0

    /* UDP messages handling requires more setup */

    udp_iovec.iov_base = udp_mesg->buffer;
    udp_iovec.iov_len = sizeof(udp_mesg->buffer);

    udp_msghdr.msg_name = &udp_mesg->other.sa;
    udp_msghdr.msg_namelen = udp_mesg->addr_len;
    udp_msghdr.msg_iov = &udp_iovec;
    udp_msghdr.msg_iovlen = 1;
    MALLOC_OR_DIE(struct msghdr*, udp_msghdr.msg_control, ANCILIARY_BUFFER_SIZE, MSGHDR_TAG);
    udp_msghdr.msg_controllen = ANCILIARY_BUFFER_SIZE;

    udp_msghdr.msg_flags = 0;

#endif

    /**
     * For each interface ...
     */

    /* compute maxfd plus one once and for all : begin */

    maxfd = -1;

    /* Set sockets on a "template" var, so we will copy it
     * in the one we will use in pselect.  This increases
     * the speed a bit.
     */

    FD_ZERO(&read_set_init);

    for(intf = g_config->interfaces; intf < g_config->interfaces_limit; intf++)
    {
        /*
         * Update the max file descriptor
         */

        maxfd = MAX(maxfd, intf->udp.sockfd);
        maxfd = MAX(maxfd, intf->tcp.sockfd);

        /*
         * Update the select read set for the current interface (udp + tcp)
         */

#if UDP_USE_MESSAGES != 0
        int sockopt_dstaddr = 1;
        Setsockopt(intf->udp.sockfd, IPPROTO_IP, IP_PKTINFO, &sockopt_dstaddr, sizeof(sockopt_dstaddr));
#endif

        FD_SET(intf->udp.sockfd, &read_set_init);
        FD_SET(intf->tcp.sockfd, &read_set_init);
    }

    /*
     * Update the select read set with the scheduler's
     */

    FD_SET(g_config->scheduler.sockfd, &read_set_init);

    /*
     * Update the max file descriptor with the sheduler's
     */

    maxfd = MAX(maxfd, g_config->scheduler.sockfd);
    maxfd++; /* pselect actually requires maxfd + 1 */

    /* compute maxfd plus one once and for all : done */

    /**
     * @todo only do this if we are master for at least one zone
     */
    
    log_info("starting notify service");

    notify_startup();
    
    log_info("starting signature maintenance service");

    database_signature_maintenance(g_config->database);

    log_info("ready to work");

    while(program_mode != SA_SHUTDOWN)
    {
        server_statistics.input_loop_count++;

        /* Reset the pselect read set */

        MEMCOPY(&read_set, &read_set_init, sizeof (fd_set));

        /* At this moment waits only for READ SET or timeout of x seconds */

        /*
         * @note (p)select has known bugs on Linux & glibc
         *
         * @todo See man select about said bugs
         */

        return_code = pselect(maxfd,
                &read_set,
                NULL,
                NULL,
                &timeout,
                0);

        if(return_code > 0) /* Are any bit sets by pselect ? */
        {
            int sockfd;

            /* If pselect check for the correct sock file descriptor,
             * at this moment only READ SET
             */

            /*
             * This variable will contain the pointer to the processing function.
             * It has been removed from the mesg structure at the time the latter
             * has been moved to the core.
             *
             * Reasons being: zdb dependency & server dependency -> dependency loop
             *
             * Since the call is only local it should not have side effects.
             */

            for(intf = g_config->interfaces; intf < g_config->interfaces_limit; intf++)
            {
                sockfd = intf->udp.sockfd;

                if(FD_ISSET(sockfd, &read_set))
                {
                    /* Jumps to the correct processing function */
                    //config->udp[i].do_processing(config->database, sockfd);

                    server_st_process_udp(g_config->database, &intf->udp);

                    /* DEBUG static counts */

                    server_statistics.loop_rate_counter++;

                    /*DERROR_MSG("do udp processing :%d, %lu: %d", sockfd, getpid(), server_statistics.udp_input_count);*/
                }

                sockfd = intf->tcp.sockfd;

                if(FD_ISSET(sockfd, &read_set))
                {
                    /* Jumps to the correct processing function */
                    server_st_process_tcp(g_config->database, &intf->tcp);

                    /* DEBUG static counts */

                    server_statistics.loop_rate_counter++;

                    /*break;*/ /** @note with multiple listening interfaces, it will probably be better not to break */
                }
            }

            sockfd = g_config->scheduler.sockfd;

            if(FD_ISSET(sockfd, &read_set))
            {
                /*
                 * The select only tells that the scheduler has got something to process.
                 * Calling scheduler_process will take care of the input from the fd.
                 * Then scheduler_has_jobs() must be used to test if scheduler_do_next_job() can be called.
                 * When it is allowed, calling scheduler_do_next_job() will execute (or process the result of) these jobs.
                 *
                 */

                scheduler_process();

                server_statistics.sched_queries_count++;
            }
        }
        else /* return_code <= 0 */
        {
            /** @note Still needs some work on finding out the correct way to let pselect work with signals */

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

                /*
                 * Instead of looping again (continue)
                 *
                 * so ...
                 *
                 * let's proceed to the scheduler processing.
                 */
            }

            /* return_code == 0 => no fd set at all and no error => timeout */

            server_run_loop_timeout_countdown--;

            server_statistics.input_timeout_count++;
        }

        /* handles scheduler jobs */

        if(scheduler_has_jobs())
        {
#ifndef NDEBUG
            log_debug("chaining scheduler job");
#endif

            scheduler_do_next_job();
        }

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
                    log_statistics(&server_statistics);

                    /*print_payload(termout, mesg.buffer, 30);*/
                    server_run_loop_rate_tick = now;
                    server_run_loop_timeout_countdown = g_config->statistics_max_period;
                    server_statistics.loop_rate_counter = 0;
                }
                
#ifndef NDEBUG
                scheduler_print_queue();
#endif
            	previous_tick = tick;

            }
        }
    }
    
    /*
     * Close all zone alarm handles
     * Close database alarm handle
     */

    log_info("shutting down");

    /**
     * @todo READ THIS
     *
     * At this point, there one or more background readers could still be working.
     * Destroying the database at this time (they do not expect a writer) will crash them.
     * So either we don't destroy the database (required to ensure there has been no corruption nor leaks)
     * Either we wait for them to finish (but signing 3M records takes time)
     * Either ...
     *
     * BTW: the odd "non-reproducible" crash I've got on Yadifa is this ending race happening.
     *
     */

    free(udp_mesg);
    udp_mesg = NULL;

    DERROR_MSG("shutting down (pid = %lu)", getpid());

    return OK;
}

/** @} */

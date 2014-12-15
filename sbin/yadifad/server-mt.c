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
*/
/**
 *  @defgroup server Server
 *  @ingroup yadifad
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

#include "config.h"
#include <dnscore/logger.h>
#include <dnscore/fdtools.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/message.h>
#include <dnscore/timems.h>
#include <dnscore/thread_pool.h>
#include <dnscore/sys_get_cpu_count.h>

#include <dnsdb/zdb_types.h>

#ifdef DEBUG

#define ZDB_JOURNAL_CODE 1

#include <dnsdb/journal.h>
#endif

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "server-mt.h"

#include "server_context.h"
#include "server_error.h"

#include "signals.h"

#include "notify.h"
#include "process_class_ch.h"

#if HAS_CTRL
#include "ctrl.h"
#endif

//#include "database-service.h"

#include "log_statistics.h"
#include "log_query.h"
#include "poll-util.h"

#if HAS_DYNUPDATE_SUPPORT
#include "dynupdate_query_service.h"
#endif

#if HAS_RRL_SUPPORT
#include "rrl.h"
#endif

#define MSGHDR_TAG 0x52444847534d

#ifdef HAS_MIRROR_SUPPORT
#define DUMB_MIRROR 1
#endif

#if HAS_MESSAGES_SUPPORT
#define UDP_USE_MESSAGES 1
#else
#define UDP_USE_MESSAGES 0
#endif

/**
 * This contains the sum of statistics every time they are all summed.
 */

static server_statistics_t server_statistics_sum;

#define SYNCED_THREAD_STATUS_TERMINATED 1
#define PAUSE_ALL_ON_TASK               0
#define SERVER_MAX_UDP_THREADS          255

/**
 * @note This flag enables the alternative send/rcvd for udp (from 'to' to 'msg')
 * 
 * The syncs are slow, but it does not matter.
 */

struct synced_thread_t
{
    interface *intf;
    pthread_t id;
    u16 idx;
#if PAUSE_ALL_ON_TASK != 0
    volatile u32 paused;
#endif
    volatile u8  status;
    
    message_data *udp_mesg;
    
#if UDP_USE_MESSAGES
    struct iovec    udp_iovec;
    struct msghdr   udp_msghdr;
#endif
    
    server_statistics_t statistics;
};

typedef struct synced_thread_t synced_thread_t;

struct synced_threads_t
{
    synced_thread_t* threads;    
    mutex_t mtx;
    u32 thread_count;
#if PAUSE_ALL_ON_TASK != 0
    volatile u32 pause;
#endif
    volatile bool terminate;
};

static struct synced_threads_t synced_threads;

static void
synced_init(u32 count)
{
    yassert(count > 0);
    
    ZEROMEMORY(&synced_threads, sizeof(synced_threads));
    mutex_init(&synced_threads.mtx);
    
    MALLOC_OR_DIE(synced_thread_t*, synced_threads.threads, count * sizeof(synced_thread_t), GENERIC_TAG);
    ZEROMEMORY(synced_threads.threads, count * sizeof(synced_thread_t));
    
    for(u32 t = 0; t < count; t++)
    {
        synced_threads.threads[t].id = 0;
#if PAUSE_ALL_ON_TASK != 0
        synced_threads.threads[t].paused = 0;
#endif
        synced_threads.threads[t].idx = t;
        ZEROMEMORY(&synced_threads.threads[t].statistics, sizeof(server_statistics_t));
        MALLOC_OR_DIE(message_data*, synced_threads.threads[t].udp_mesg, sizeof(message_data), MESGDATA_TAG);
        ZEROMEMORY(synced_threads.threads[t].udp_mesg, sizeof(message_data));
    }
    
    synced_threads.thread_count = count;
}

static void
synced_finalize()
{
    for(u32 t = 0; t < synced_threads.thread_count; t++)
    {
        free(synced_threads.threads[t].udp_mesg);
    }
    
    free(synced_threads.threads);
    ZEROMEMORY(&synced_threads, sizeof(synced_threads));
}

static bool
synced_shouldpause()
{
#if PAUSE_ALL_ON_TASK != 0
    return (synced_threads.pause & 1) != 0;
#else
    return FALSE;
#endif
}



static void
synced_wait(synced_thread_t *st)
{
#if PAUSE_ALL_ON_TASK != 0
#ifdef DEBUG
    log_debug("synced_wait: st %d/%d: waiting ... (%x)", st->idx+1, synced_threads.thread_count, st->paused);
#endif
    
    while(((st->paused = synced_threads.pause) & 1) != 0)
    {
        usleep(1000); // 1ms
    }
    
#ifdef DEBUG
    log_debug("synced_wait: st %d/%d: resuming ... (%x)", st->idx+1, synced_threads.thread_count, st->paused);
#endif
#endif
}

static void
synced_set_terminated(synced_thread_t *st)
{
    st->status |= SYNCED_THREAD_STATUS_TERMINATED;
}

static void
synced_stop()
{
#ifdef DEBUG
    log_debug("synced_stop: stop request");
#endif
    
    /* mark the shutdown */
    
    synced_threads.terminate = TRUE;
    
    /* break everybody's reader */
    
    for(u32 i = 0; i < synced_threads.thread_count; i++)
    {
        close_ex(synced_threads.threads[i].intf->udp.sockfd);
    }
    
    /* wait everybody has stopped */
    
    for(;;)
    {
        u32 pc = 0;
        
        for(u32 i = 0; i < synced_threads.thread_count; i++)
        {
            /* If terminated ... */
            
            if((synced_threads.threads[i].status & SYNCED_THREAD_STATUS_TERMINATED) != 0)
            {
                pc++;
            }
            else
            {
                if(synced_threads.threads[i].id != 0)
                {
                    pthread_kill(synced_threads.threads[i].id, SIGUSR2); /* SIGUSR2 is an "unused" signal that does nothing but break a system call with an EINTR  */
                }
            }
        }

        if(pc == synced_threads.thread_count)
        {
#ifdef DEBUG
            log_debug("synced_stop: stopped");
#endif
            break;
        }
      
#ifdef DEBUG
        log_debug("synced_stop: stopped %d/%d", pc, synced_threads.thread_count);
#endif

        usleep(1000);
    }
}

#if UDP_USE_MESSAGES

/*
 * from: http://www.mombu.com/programming/c/t-how-to-get-udp-destination-address-on-incoming-packets-7784569.html
 */

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

/*******************************************************************************************************************
 *
 * UDP protocol
 *
 ******************************************************************************************************************/

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
server_mt_process_udp_update(zdb *database, synced_thread_t *st)
{
    struct msghdr *msghdr;
    
#if UDP_USE_MESSAGES
    msghdr = &st->udp_msghdr;
#else
    msghdr = NULL;
#endif
    
    dynupdate_query_service_enqueue(database, st->udp_mesg, msghdr);
}

#endif

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
server_mt_process_udp(zdb *database, synced_thread_t *st)
{
    int return_code;
    
    server_statistics_t *local_statistics = &st->statistics;
    
    message_data *mesg = st->udp_mesg;
    
    int fd = mesg->sockfd;

    ssize_t n;
    
    for(;;)
    {
        while(synced_shouldpause())
        {
            // pause
            synced_wait(st);
        }

#if !UDP_USE_MESSAGES
        
        n = recvfrom(fd, mesg->buffer, sizeof(mesg->buffer), 0, (struct sockaddr*)&mesg->other.sa, &mesg->addr_len);
        
        if(n >= 0)
        {
#ifdef DEBUG
            log_debug("server_mt_process_udp: recvfrom: got %d bytes from %{sockaddr}", n, &mesg->other.sa);
            log_memdump_ex(g_server_logger, MSG_DEBUG5, mesg->buffer, n, 16, OSPRINT_DUMP_HEXTEXT);
#endif
            break;
        }
        
        /*
        * errno is not a variable but a macro
        *
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
#ifdef DEBUG
                log_debug("server_mt_process_udp: recvfrom error: %r", MAKE_ERRNO_ERROR(err)); /* most likely: timeout/resource temporarily unavailable */
#endif
                return;
            }
        }
#else

        st->udp_iovec.iov_len = sizeof(st->udp_mesg->buffer);
        st->udp_msghdr.msg_controllen = ANCILIARY_BUFFER_SIZE;

        n = recvmsg(fd, &st->udp_msghdr, 0);
        
        if(n >= 0)
        {
#ifdef DEBUG
            log_debug("server_mt_process_udp: recvmsg: got %d bytes", n);
#endif
            break;
        }
        
        int err = errno;

        if(err != EINTR)
        {
            /*
             * EAGAIN
             * Resource temporarily unavailable (may be the same value as EWOULDBLOCK) (POSIX.1)
             */
            
            if(err != EAGAIN)
            {
#ifdef DEBUG
                log_err("server_mt_process_udp: recvmsg error: %r", MAKE_ERRNO_ERROR(err));
#endif
                return;
            }
        }
#endif
    }

    mesg->received = n;

    /**
     * In case of processing error, message_process will return UNPROCESSABLE_MESSAGE
     * which means there must be no query/update/... done on it.
     * If the message status is not "dropped" then the message will be sent back as it is to the client.
     */

    // see if supposed to pause
    // if yes then pause and tell we are paused
    // wait until can resume
    
    local_statistics->udp_input_count++;
    
    switch(MESSAGE_OP(mesg->buffer))
    {
        case OPCODE_QUERY:
        {
            if(ISOK(return_code = message_process_query(mesg)))
            {
                switch(mesg->qclass)
                {
                    case CLASS_IN:
                    {
                        local_statistics->udp_queries_count++;

                        log_query(fd, mesg);

                        switch(mesg->qtype)
                        {
                            default:
                            {
#if HAS_RRL_SUPPORT
                                ya_result rrl = database_query(database, mesg);

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
                                        return;
                                    }
                                    case RRL_PROCEED_DROP:
                                    {
                                        local_statistics->rrl_drop++;
                                        break;
                                    }
                                }
#else
                                database_query(database, mesg);  // not thread-safe

                                local_statistics->udp_referrals_count += mesg->referral;
                                local_statistics->udp_fp[mesg->status]++;
#endif
                                break;
                            }
                            case TYPE_IXFR:
                            {
                                MESSAGE_FLAGS_OR(mesg->buffer, QR_BITS|TC_BITS, 0); /** @todo IXFR UDP */
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
                        process_class_ch(mesg); // thread-safe
                        local_statistics->udp_fp[mesg->status]++;
                        break;
                    } // query class CH
                    default:
                    {
                        /// @todo 20140521 edf -- verify unsupported class error handling
                        /*
                        FP_CLASS_NOTFOUND
                        log_warn("query [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : unsupported class",
                                ntohs(MESSAGE_ID(mesg->buffer)),
                                mesg->qname, &mesg->qtype, &mesg->qclass,
                                &mesg->other.sa);
                        */
                        /*
                        log_warn("query [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : unsupported operation",
                                ntohs(MESSAGE_ID(mesg->buffer)),
                                mesg->qname, &mesg->qtype, &mesg->qclass,
                                &mesg->other.sa);
                        */
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
                         MESSAGE_HIFLAGS(mesg->buffer),MESSAGE_LOFLAGS(mesg->buffer),
                         mesg->status,
                         return_code,
                         &mesg->other.sa);

                local_statistics->udp_fp[mesg->status]++;
                
                if(return_code == UNPROCESSABLE_MESSAGE)
                {
                    log_memdump_ex(MODULE_MSG_HANDLE, MSG_ERR, mesg->buffer, mesg->received, 16, OSPRINT_DUMP_ALL);
                }
                
                /*
                 * If not FE, or if we answer FE
                 * 
                 * ... && (MESSAGE_QR(mesg->buffer) == 0 ??? and if there the query number is > 0 ???
                 */
                if( (return_code != INVALID_MESSAGE) && ((mesg->status != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)))
                {
                    if(!MESSAGEP_HAS_TSIG(mesg))
                    {
                        message_transform_to_error(mesg);
                    }
                }
                else
                {
                    local_statistics->udp_dropped_count++;
                    return;
                }
            }
            
            break;
        } // case query
        
        case OPCODE_NOTIFY:
        {
            if(ISOK(return_code = message_process(mesg)))
            {
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
                        
                        return_value = notify_process(database, mesg); // thread-safe
                        
                        local_statistics->udp_fp[mesg->status]++;
                        
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
                                return;
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
                    if(!MESSAGEP_HAS_TSIG(mesg))
                    {
                        message_transform_to_error(mesg);
                    }
                }
                else
                {
                    local_statistics->udp_dropped_count++;
                    return;
                }
            }
            break;
        } // case notify

        case OPCODE_UPDATE:
        {
            if(ISOK(return_code = message_process(mesg)))
            {
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

                        server_mt_process_udp_update(database, st);
                        
                        return; // NOT break;
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
                    if(!MESSAGEP_HAS_TSIG(mesg))
                    {
                        message_transform_to_error(mesg);
                    }
                }
                else
                {
                    local_statistics->udp_dropped_count++;
                    return;
                }
            }
            break;
        } // case update

        default:
        {
            return_code = message_process_query(mesg);
            mesg->status = RCODE_NOTIMP;

            log_warn("unknown [%04hx] error: %r", ntohs(MESSAGE_ID(mesg->buffer)), MAKE_DNSMSG_ERROR(mesg->status));
                
            if( (mesg->status != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0))
            {
                if(!MESSAGEP_HAS_TSIG(mesg))
                {
                    message_transform_to_error(mesg);
                }
            }
            else
            {
                local_statistics->udp_dropped_count++;
                return;
            }
        } 

    } // switch operation code
    

#ifdef DEBUG
    if(mesg->send_length < 12)
    {
        log_debug("wrong output message of status %i size %i", mesg->status, mesg->send_length);
        
        log_memdump_ex(g_server_logger, MSG_DEBUG5, mesg->buffer, mesg->send_length, 16, OSPRINT_DUMP_HEXTEXT);
    }
#endif

#if !HAS_DROPALL_SUPPORT

    ssize_t sent;
    
#if !UDP_USE_MESSAGES
    
#ifdef DEBUG
    log_debug("server_mt_process_udp: sendto(%d, %p, %d, %d, %{sockaddr}, %d)", mesg->sockfd, mesg->buffer, mesg->send_length, 0, (struct sockaddr*)&mesg->other.sa, mesg->addr_len);
    log_memdump_ex(g_server_logger, MSG_DEBUG5, mesg->buffer, mesg->send_length, 16, OSPRINT_DUMP_HEXTEXT);
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

    st->udp_iovec.iov_len = mesg->send_length;
    
#ifdef DEBUG
    log_debug("sendmsg(%d, %p, %d", mesg->sockfd, &st->udp_msghdr, 0);
#endif
    
    while( (sent = sendmsg(mesg->sockfd, &st->udp_msghdr, 0)) < 0)
    {
        int error_code = errno;

        if(error_code != EINTR)
        {
            /** @warning server_st_process_udp needs to be modified */

            log_err("query (%04hx) %{dnsname} %{dnstype} send failed: %r",
                        ntohs(MESSAGE_ID(mesg->buffer)),
                        mesg->qname,
                        &mesg->qtype,
                        MAKE_ERRNO_ERROR(error_code));
            
            return /*ERROR*/;
        }
    }
    
#endif

    local_statistics->udp_output_size_total += sent;

    if(sent != mesg->send_length)
    {
        /** @warning server_st_process_udp needs to be modified */
        log_err("short byte count sent (%i instead of %i)", sent, mesg->send_length);

        /*return ERROR*/;
    }
#else
    log_debug("server_mt_process_udp: drop all");
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
//static u64 server_run_loop_rate_count        = 0;
static s32 server_run_loop_timeout_countdown = 0;

void*
server_mt_query_loop_udp(void* parm)
{
    synced_thread_t *st = (synced_thread_t*)parm;
    
    st->id = pthread_self();

    /*    ------------------------------------------------------------    */

    /* Clear and initialize mesg */
    ZEROMEMORY(st->udp_mesg, sizeof (message_data));
    
    st->udp_mesg->addr_len      = sizeof(st->udp_mesg->other);
    st->udp_mesg->protocol      = IPPROTO_UDP;
    st->udp_mesg->size_limit    = UDPPACKET_MAX_LENGTH;
    st->udp_mesg->process_flags = ~0; /** @todo FIX ME */
    st->udp_mesg->sockfd = st->intf->udp.sockfd;
    
    tcp_set_recvtimeout(st->udp_mesg->sockfd, 1, 0);

#ifdef DEBUG
    log_debug("server_mt_query_loop_udp: ready with #%d id=%p fd=%d", st->idx, st->id, st->udp_mesg->sockfd);
#endif

#if UDP_USE_MESSAGES

    /* UDP messages handling requires more setup */

    st->udp_iovec.iov_base = st->udp_mesg->buffer;
    st->udp_iovec.iov_len = sizeof(st->udp_mesg->buffer);

    st->udp_msghdr.msg_name = &st->udp_mesg->other.sa;
    st->udp_msghdr.msg_namelen = st->udp_mesg->addr_len;
    st->udp_msghdr.msg_iov = &st->udp_iovec;
    st->udp_msghdr.msg_iovlen = 1;
    MALLOC_OR_DIE(struct msghdr*, st->udp_msghdr.msg_control, ANCILIARY_BUFFER_SIZE, MSGHDR_TAG);
    st->udp_msghdr.msg_controllen = ANCILIARY_BUFFER_SIZE;

    st->udp_msghdr.msg_flags = 0;

#endif
    
    log_debug("server-mt: reading on %p", st->intf);
    
    while(program_mode != SA_SHUTDOWN)
    {
        st->statistics.input_loop_count++;
        
        server_mt_process_udp(g_config->database, st);
    }
    
    log_debug("server-mt: stop reading on %p", st->intf); 
    
    synced_set_terminated(st);
    
    return NULL;
}

ya_result
server_mt_query_loop()
{
    ya_result return_code;
    interface *intf;

#if ZDB_USES_ZALLOC != 0
    zdb_set_zowner(pthread_self());
#endif
    
    if(g_config->total_interfaces == 0)
    {
        return INVALID_STATE_ERROR;
    }
        


    fd_set read_set;
    fd_set read_set_init;

    struct timespec timeout;
    int maxfd;

    u32 previous_tick = 0;
    
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

    maxfd = -1;

    /* Set sockets on a "template" var, so we will copy it
     * in the one we will use in pselect.  This increases
     * the speed a bit.
     */

    FD_ZERO(&read_set_init);
    
    s32 reader_by_fd = g_config->thread_count_by_address;
    
    s32 cpu_count = sys_get_cpu_count();
    
    if(reader_by_fd >= cpu_count)
    {
        log_warn("server-mt: using too many threads per address is counter-productive on highly loaded systems (%d >= %d)", reader_by_fd, cpu_count);
    }
    
    /*
     * 
     */
            
    u32 itf_count = g_config->interfaces_limit - &g_config->interfaces[0];
    
    // ensure the number of udp thread by interface does not goes "too much" beyond a limit
    // recompute reader_by_fd if it does
    
    if(reader_by_fd * itf_count <= SERVER_MAX_UDP_THREADS)
    {
        reader_by_fd = MAX(reader_by_fd, 1);
    }
    else
    {
        reader_by_fd = MAX(SERVER_MAX_UDP_THREADS / itf_count, 1);
    }
    
    synced_init(itf_count * reader_by_fd);
    
    u32 tidx = 0;
    
    struct thread_pool_s *server_udp_thread_pool = thread_pool_init_ex(itf_count * reader_by_fd, 1, "server-udp-tp");
    
    for(intf = g_config->interfaces; intf < g_config->interfaces_limit; intf++)
    {
        for(u32 r = 0; r < reader_by_fd; r++)
        {
            synced_threads.threads[tidx].intf = intf;
            
            log_debug("server_mt_query_loop: pooling #%d=%d fd=%d", tidx, synced_threads.threads[tidx].idx, intf->udp.sockfd);
            
            if(FAIL(return_code = thread_pool_enqueue_call(server_udp_thread_pool, server_mt_query_loop_udp, &synced_threads.threads[tidx], NULL, "server-mt-task")))
            {
                log_err("unable to schedule task : %r", return_code);
                
                return return_code;
            }
            
            tidx++;
        }

        maxfd = MAX(maxfd, intf->tcp.sockfd);

        /*
         * Update the select read set for the current interface (udp + tcp)
         */

#if UDP_USE_MESSAGES
        int sockopt_dstaddr = 1;
        setsockopt(intf->udp.sockfd, IPPROTO_IP, DSTADDR_SOCKOPT, &sockopt_dstaddr, sizeof(sockopt_dstaddr));
#endif

        FD_SET(intf->tcp.sockfd, &read_set_init);
    }
    
    maxfd++; /* pselect actually requires maxfd + 1 */
    
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
             * Reasons being: zdb *dependency & server dependency -> dependency loop
             *
             * Since the call is only local it should not have side effects.
             */

            for(intf = g_config->interfaces; intf < g_config->interfaces_limit; intf++)
            {
                sockfd = intf->tcp.sockfd;

                if(FD_ISSET(sockfd, &read_set))
                {
                    /* Jumps to the correct processing function */
                    server_process_tcp(g_config->database, &intf->tcp);

                    /* DEBUG static counts */

                    server_statistics.loop_rate_counter++;

                    /*break;*/ /** @note with multiple listening interfaces, it will probably be better not to break */
                }
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

#if HAS_RRL_SUPPORT
        rrl_cull();
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
                    
                    for(u32 i = 0; i < synced_threads.thread_count; i++)
                    {
                        server_statistics_t *stats = &synced_threads.threads[i].statistics;
                        
                        server_statistics_sum.input_loop_count += stats->input_loop_count;
                        /* server_statistics_sum.input_timeout_count += stats->input_timeout_count; */
                        
                        server_statistics_sum.udp_output_size_total += stats->udp_output_size_total;
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
                    }
                    
                    log_statistics(&server_statistics_sum);

                    server_run_loop_rate_tick = now;
                    server_run_loop_timeout_countdown = g_config->statistics_max_period;
                    server_statistics.loop_rate_counter = 0;
#ifdef DEBUG
#if ZDB_ZALLOC_STATISTICS
                    zdb_alloc_print_stats(termout);
#endif
                    journal_log_status();
                    
                    debug_bench_logdump_all();
#endif
                }

                previous_tick = tick;
            }
        }
    }
    
    log_info("stopping the threads");
    synced_stop();
    
    /*
     * Close all zone alarm handles
     * Close database alarm handle
     */

    log_info("shutting down");
    
    synced_finalize();
    
    thread_pool_destroy(server_udp_thread_pool);
    server_udp_thread_pool = NULL;

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

    log_debug("shutting down (pid = %u)", getpid());
    
    return SUCCESS;
}
/** @} */

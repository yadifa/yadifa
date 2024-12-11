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

/*------------------------------------------------------------------------------
 *
// keep this order -->
 *
 *----------------------------------------------------------------------------*/

#include "server_config.h"

#include <dnscore/logger.h>
#include <dnscore/thread.h>
#include <dnscore/ctrl_rfc.h>
#include <dnscore/tcp_manager2.h>

#include "server.h"
#include "process_class_ch.h"
#include "dynupdate_query_service.h"
#include "notify.h"
#if HAS_CTRL
#include "ctrl_notify.h"
#include "ctrl_query.h"
#endif
#include "log_query.h"
#include "server_process_message_common.h"
#include "axfr.h"
#include "ixfr.h"
#include "log_statistics.h"

static zdb_t           *database = NULL;

void                    server_process_message_tcp_set_database(zdb_t *db) { database = db; }

static inline ya_result server_tcp_reply(dns_message_t *mesg, tcp_manager_channel_t *tmc)
{
    ssize_t ret;

#if DEBUG
    log_debug("tcp: %{sockaddr}: replying %i bytes", dns_message_get_sender_sa(mesg), dns_message_get_size(mesg));
#endif

    ret = tcp_manager_channel_send(tmc, mesg);

    if(ISOK(ret))
    {
#if DEBUG
        log_debug("tcp: %{sockaddr}: replied %i bytes", dns_message_get_sender_sa(mesg), dns_message_get_size(mesg));
#endif
    }
    else
    {
        log_err("tcp: %{sockaddr}: could not reply (%i bytes): %r", dns_message_get_sender_sa(mesg), dns_message_get_size(mesg), (ya_result)ret);
    }

    return (ya_result)ret;
}

#if DNSCORE_HAS_TCP_MANAGER

/**
 * Wrapper function to make an error message, then send it and log an eventual error
 *
 * @param mesg
 * @param sockfd
 */

static inline ya_result server_tcp_reply_error(dns_message_t *mesg, tcp_manager_channel_t *tmc, uint16_t error_code)
{
    ssize_t ret = ERROR;

    log_debug("tcp: %{sockaddr}: replying %i bytes (error code %i)", dns_message_get_sender_sa(mesg), dns_message_get_size(mesg), error_code);
#if 0
#error removed in  server_tcp_reply
#if DNSCORE_HAS_TCP_MANAGER
    /*
    tcp_manager_set_nodelay(sctx, true);
    tcp_manager_set_cork(sctx, false);
     */
#else
    tcp_set_nodelay(sockfd, true);
    tcp_set_cork(sockfd, false);
#endif
#endif

    ret = tcp_manager_channel_make_error_and_send(tmc, mesg, error_code);

    if(ISOK(ret))
    {
#if DEBUG
        log_debug("tcp: %{sockaddr}: replied %i bytes (error code %i)", dns_message_get_sender_sa(mesg), dns_message_get_size(mesg), error_code);
#endif
    }
    else
    {
        log_err("tcp: %{sockaddr}: could not reply error code %u (%i bytes): %r", dns_message_get_sender_sa(mesg), dns_message_get_size(mesg), error_code, (ya_result)ret);
    }

    return (ya_result)ret;
}
#else

/**
 * Wrapper function to send the message and log an eventual error
 *
 * @param mesg
 * @param sockfd
 */

static error_state_t    server_tcp_reply_error_state = ERROR_STATE_INITIALIZER;

static inline ya_result server_tcp_reply(dns_message_t *mesg, int sockfd)
{
#if DEBUG_BENCH_FD && !DNSCORE_HAS_TCP_MANAGER
    uint64_t bench = debug_bench_start(&debug_tcp_reply);
#endif

    ssize_t ret;

    if(ISOK(ret = message_update_length_send_tcp_with_default_minimum_throughput(mesg, sockfd)))
    {
        error_state_clear_locked(&server_tcp_reply_error_state, NULL, 0, NULL);
    }
    else
    {
        if(error_state_log_locked(&server_tcp_reply_error_state, ret))
        {
            log_err("tcp: could not answer: %r", (ya_result)ret);
        }
    }

#if DEBUG_BENCH_FD && !DNSCORE_HAS_TCP_MANAGER
    debug_bench_stop(&debug_tcp_reply, bench);
#endif

    return (ya_result)ret;
}

/**
 * Wrapper function to make an error message, then send it and log an eventual error
 *
 * @param mesg
 * @param sockfd
 */

static inline ya_result server_tcp_reply_error(dns_message_t *mesg, int sockfd, uint16_t error_code)
{
    ssize_t ret;
    if(ISOK(ret = message_make_error_and_reply_tcp_with_default_minimum_throughput(mesg, error_code, sockfd)))
    {
        error_state_clear_locked(&server_tcp_reply_error_state, NULL, 0, NULL);
    }
    else
    {
        if(error_state_log_locked(&server_tcp_reply_error_state, ret))
        {
            log_err("tcp: could not answer: %r", (ya_result)ret);
        }
    }

    return (ya_result)ret;
}
#endif

int server_process_channel_message(tcp_manager_channel_t *tmc, dns_message_t *mesg /*, server_statistics_t * const local_statistics*/, int svr_sockfd)
{
    ya_result ret;

    dns_message_set_protocol(mesg, IPPROTO_TCP);

    bool received_query = dns_message_is_query(mesg);

    switch(dns_message_get_opcode(mesg))
    {
        case OPCODE_QUERY:
        {
            if(ISOK(ret = dns_message_process_query(mesg)))
            {
                dns_message_edns0_clear_undefined_flags(mesg);
                dns_message_reset_buffer_size(mesg);

                switch(dns_message_get_query_class(mesg))
                {
                    case CLASS_IN:
                    {
                        log_query(svr_sockfd, mesg);

                        if(dns_message_get_query_type(mesg) == TYPE_AXFR)
                        {
                            /*
                             * Start an AXFR "writer" thread
                             * Give it the tcp fd
                             * It will store the current AXFR on the disk if it does not exist yet (writers blocked)
                             * It will then open the stored file and stream it back to the tcp fd (writers freed)
                             * ACL/TSIG is not taken in account yet.
                             */

                            TCPSTATS(tcp_axfr_count++);

                            ret = axfr_process(mesg, tmc); // should acquire the context (as it's bound to work in the
                                                           // backround) but not close it
#if DEBUG
                            log_debug("tcp: %{sockaddr}: axfr_process done : %r", dns_message_get_sender_sa(mesg), ret);
#endif
                            return ret;
                        }

                        if(dns_message_get_query_type(mesg) == TYPE_IXFR)
                        {
                            /*
                             * Start an IXFR "writer" thread
                             * Give it the tcp fd
                             * It will either send the incremental changes (stored on the disk), either answer with an
                             * AXFR ACL/TSIG is not taken in account yet.
                             */

                            TCPSTATS(tcp_ixfr_count++);

                            const uint8_t *fqdn = dns_message_get_canonised_fqdn(mesg);
                            zone_desc_t   *zone_desc = zone_acquirebydnsname(fqdn);
                            if(zone_desc != NULL)
                            {
                                bool axfr_only = zone_desc->flags & ZONE_FLAG_FULL_ZONE_TRANSFER_ONLY;
                                zone_release(zone_desc);

                                if(axfr_only)
                                {
                                    ret = axfr_process(mesg, tmc);
#if DEBUG
                                    log_debug("tcp: %{sockaddr}: ixfr_process/axfr_process done : %r", dns_message_get_sender_sa(mesg), ret);
#endif
                                    return ret; /* IXFR->AXFR PROCESSING: process then closes: all in background */
                                }
                            }

                            ret = ixfr_process(mesg, tmc);

#if DEBUG
                            log_debug("tcp: %{sockaddr}: ixfr_process done : %r", dns_message_get_sender_sa(mesg), ret);
#endif
                            return ret; /* IXFR PROCESSING: process */
                        }
#if DEBUG
                        log_debug("tcp: %{sockaddr}: querying database", dns_message_get_sender_sa(mesg));
#endif
                        /*
                         * This query must go through the task channel.
                         */

                        database_query(database, mesg);

                        ret = server_tcp_reply(mesg, tmc);

                        TCPSTATS_LOCK();
                        TCPSTATS_FIELD(tcp_queries_count++);
                        TCPSTATS_FIELD(tcp_referrals_count += dns_message_get_referral(mesg));
                        TCPSTATS_FIELD(tcp_fp[dns_message_get_status(mesg)]++);
                        if(ISOK(ret))
                        {
                            TCPSTATS_FIELD(tcp_output_size_total += ret);
                        }
                        TCPSTATS_UNLOCK();

                        break;
                    } // case query IN
                    case CLASS_CH:
                    {
                        log_query(svr_sockfd, mesg);
                        class_ch_process(mesg);

                        ret = server_tcp_reply(mesg, tmc);

                        TCPSTATS_LOCK();
                        TCPSTATS_FIELD(tcp_queries_count++);
                        TCPSTATS_FIELD(tcp_fp[dns_message_get_status(mesg)]++);
                        if(ISOK(ret))
                        {
                            TCPSTATS_FIELD(tcp_output_size_total += ret);
                        }
                        TCPSTATS_UNLOCK();
                        break;
                    }
                    default:
                    {

                        ret = server_tcp_reply_error(mesg, tmc, FP_NOT_SUPP_CLASS);

                        TCPSTATS_LOCK();
                        TCPSTATS_FIELD(tcp_queries_count++);
                        TCPSTATS_FIELD(tcp_fp[FP_NOT_SUPP_CLASS]++);
                        if(ISOK(ret))
                        {
                            TCPSTATS_FIELD(tcp_output_size_total += ret);
                        }
                        TCPSTATS_UNLOCK();
                        break;
                    }
                } // query class
            } // if message process succeeded
            else // an error occurred : no query to be done at all
            {
                server_process_message_query_log_error(mesg, ret);

                // note: message_isquery(mesg) => INVALID_MESSAGE

                if((ret != INVALID_MESSAGE) && (((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0) || (dns_message_get_status(mesg) != RCODE_FORMERR)) && received_query)
                {
                    if(!dns_message_has_tsig(mesg) && (dns_message_get_status(mesg) != FP_RCODE_NOTAUTH))
                    {
                        dns_message_transform_to_error(mesg);
                    }

                    ret = server_tcp_reply(mesg, tmc);

                    TCPSTATS_LOCK();
                    TCPSTATS_FIELD(tcp_queries_count++);
                    TCPSTATS_FIELD(tcp_fp[dns_message_get_status(mesg)]++);
                    if(ISOK(ret))
                    {
                        TCPSTATS_FIELD(tcp_output_size_total += ret);
                    }
                    TCPSTATS_UNLOCK();
                }
                else
                {
                    TCPSTATS_LOCK();
                    TCPSTATS_FIELD(tcp_queries_count++);
                    TCPSTATS_FIELD(tcp_dropped_count++);
                    TCPSTATS_UNLOCK();

#if !DNSCORE_HAS_TCP_MANAGER
                    tcp_set_agressive_close(sockfd, 1);
#endif
                }
            }

            break;
        } // case query

        case OPCODE_NOTIFY:
        {
            if(ISOK(ret = dns_message_process(mesg)))
            {
                dns_message_reset_buffer_size(mesg);

                switch(dns_message_get_query_class(mesg))
                {
                    case CLASS_IN:
                    {
                        // a primary sent a notify using TCP ...
                        notify_process(mesg);

                        ret = server_tcp_reply(mesg, tmc);

                        TCPSTATS_LOCK();
                        TCPSTATS_FIELD(tcp_notify_input_count++);
                        TCPSTATS_FIELD(tcp_fp[dns_message_get_status(mesg)]++);
                        if(ISOK(ret))
                        {
                            TCPSTATS_FIELD(tcp_output_size_total += ret);
                        }
                        TCPSTATS_UNLOCK();
                        break;
                    }
                    default:
                    {
                        ret = server_tcp_reply_error(mesg, tmc, FP_NOT_SUPP_CLASS);

                        TCPSTATS_LOCK();
                        TCPSTATS_FIELD(tcp_notify_input_count++);
                        TCPSTATS_FIELD(tcp_fp[FP_NOT_SUPP_CLASS]++);
                        if(ISOK(ret))
                        {
                            TCPSTATS_FIELD(tcp_output_size_total += ret);
                        }
                        TCPSTATS_UNLOCK();
                        break;
                    }
                } // notify class
            } // if message process succeeded
            else // an error occurred : no query to be done at all
            {
                server_process_message_notify_log_error(mesg, ret);

                if((ret != INVALID_MESSAGE) && ((dns_message_get_status(mesg) != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)) && received_query)
                {
                    if(!dns_message_has_tsig(mesg) && (dns_message_get_status(mesg) != FP_RCODE_NOTAUTH))
                    {
                        dns_message_transform_to_error(mesg);
                    }

                    ret = server_tcp_reply(mesg, tmc);

                    TCPSTATS_LOCK();
                    TCPSTATS_FIELD(tcp_notify_input_count++);
                    TCPSTATS_FIELD(tcp_fp[dns_message_get_status(mesg)]++);
                    if(ISOK(ret))
                    {
                        TCPSTATS_FIELD(tcp_output_size_total += ret);
                    }
                    TCPSTATS_UNLOCK();
                }
                else
                {
                    TCPSTATS_LOCK();
                    TCPSTATS_FIELD(tcp_notify_input_count++);
                    TCPSTATS_FIELD(tcp_dropped_count++);
                    TCPSTATS_UNLOCK();

#if !DNSCORE_HAS_TCP_MANAGER
                    tcp_set_agressive_close(sockfd, 1);
#endif
                }
            }
            break;
        } // case notify
        case OPCODE_UPDATE:
        {
            if(ISOK(ret = dns_message_process(mesg)))
            {
                dns_message_edns0_clear_undefined_flags(mesg);

                switch(dns_message_get_query_class(mesg))
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
#if ZDB_HAS_PRIMARY_SUPPORT && HAS_DYNUPDATE_SUPPORT
                        if(dns_message_get_query_type(mesg) == TYPE_SOA)
                        {
                            log_info("update [%04hx] %{dnsname} from %{sockaddr}", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), dns_message_get_sender_sa(mesg));
                        }
                        else
                        {
                            log_info("update [%04hx] %{dnsname} %{dnstype} from %{sockaddr}", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg), dns_message_get_sender_sa(mesg));
                        }

                        if(FAIL(database_update(database, mesg)))
                        {
                            if(dns_message_get_status(mesg) == RCODE_NOERROR)
                            {
                                dns_message_set_status(mesg, FP_RCODE_SERVFAIL);
                            }
                        }

                        ret = server_tcp_reply(mesg, tmc);

                        TCPSTATS_LOCK();
                        TCPSTATS_FIELD(tcp_updates_count++);
                        TCPSTATS_FIELD(tcp_fp[dns_message_get_status(mesg)]++);
                        if(ISOK(ret))
                        {
                            TCPSTATS_FIELD(tcp_output_size_total += ret);
                        }
                        TCPSTATS_UNLOCK();
#else // ZDB_HAS_PRIMARY_SUPPORT && HAS_DYNUPDATE_SUPPORT

#if DNSCORE_HAS_TCP_MANAGER
                        ret = server_tcp_reply_error(mesg, tmc, FP_FEATURE_DISABLED);
#else
                        ret = server_tcp_reply_error(mesg, sockfd, FP_FEATURE_DISABLED);
#endif // ZDB_HAS_PRIMARY_SUPPORT && HAS_DYNUPDATE_SUPPORT
                        TCPSTATS_LOCK();
                        TCPSTATS_FIELD(tcp_fp[FP_FEATURE_DISABLED]++);
                        if(ISOK(ret))
                        {
                            TCPSTATS_FIELD(tcp_output_size_total += ret);
                        }
                        TCPSTATS_UNLOCK();
#endif
                        break;
                    } // update class IN
                    default:
                    {
                        ret = server_tcp_reply_error(mesg, tmc, FP_NOT_SUPP_CLASS);

                        TCPSTATS_LOCK();
                        TCPSTATS_FIELD(tcp_updates_count++);
                        TCPSTATS_FIELD(tcp_fp[FP_NOT_SUPP_CLASS]++);
                        if(ISOK(ret))
                        {
                            TCPSTATS_FIELD(tcp_output_size_total += ret);
                        }
                        TCPSTATS_UNLOCK();
                        break;
                    }
                } // update class
            } // if message process succeeded
            else // an error occurred : no query to be done at all
            {
                server_process_message_notify_log_error(mesg, ret);

                if((ret != INVALID_MESSAGE) && (((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0) || (dns_message_get_status(mesg) != RCODE_FORMERR)) && received_query)
                {
                    if(!dns_message_has_tsig(mesg) && (dns_message_get_status(mesg) != FP_RCODE_NOTAUTH))
                    {
                        dns_message_transform_to_error(mesg);
                    }

                    ret = server_tcp_reply(mesg, tmc);

                    TCPSTATS_LOCK();
                    TCPSTATS_FIELD(tcp_updates_count++);
                    TCPSTATS_FIELD(tcp_fp[dns_message_get_status(mesg)]++);
                    if(ISOK(ret))
                    {
                        TCPSTATS_FIELD(tcp_output_size_total += ret);
                    }
                    TCPSTATS_UNLOCK();
                }
                else
                {
                    TCPSTATS_LOCK();
                    TCPSTATS_FIELD(tcp_updates_count++);
                    TCPSTATS_FIELD(tcp_dropped_count++);
                    TCPSTATS_UNLOCK();

#if !DNSCORE_HAS_TCP_MANAGER
                    tcp_set_agressive_close(sockfd, 1);
#endif
                }
            }
            break;
        } // case update
#if DNSCORE_HAS_CTRL
        case OPCODE_CTRL:
        {

            int sockfd = tcp_manager_channel_socket(tmc);

            if(ctrl_query_is_listened(sockfd))
            {
                // note: ctrl_message_process contains reply code

                ret = ctrl_message_process(mesg);

                if(ret != SUCCESS_DROPPED)
                {
                    ret = server_tcp_reply(mesg, tmc);

                    TCPSTATS_LOCK();
                    TCPSTATS_FIELD(tcp_queries_count++); // ?
                    TCPSTATS_FIELD(tcp_fp[dns_message_get_status(mesg)]++);
                    if(ISOK(ret))
                    {
                        TCPSTATS_FIELD(tcp_output_size_total += ret);
                    }
                    TCPSTATS_UNLOCK();
                }
                else
                {
                    TCPSTATS_LOCK();
                    TCPSTATS_FIELD(tcp_dropped_count++);
                    TCPSTATS_UNLOCK();
#if !DNSCORE_HAS_TCP_MANAGER
                    tcp_set_agressive_close(sockfd, 1);
#endif
                }
            }
            else
            {
                // this IP/port is not configured to listen CTRL queries

                TCPSTATS_LOCK();
                TCPSTATS_FIELD(tcp_dropped_count++);
                TCPSTATS_UNLOCK();
#if !DNSCORE_HAS_TCP_MANAGER
                tcp_set_agressive_close(sockfd, 1);
#endif
            }

            break;
        } // case ctrl
#endif           // HAS_CTRL
        default: // unexpected opcode
        {
            ret = MAKE_RCODE_ERROR(FP_NOT_SUPP_OPC);
            log_warn("unknown opcode %x [%04hx] from %{sockaddr} error: %r", dns_message_get_opcode(mesg), ntohs(dns_message_get_id(mesg)), dns_message_get_sender_sa(mesg), ret);

            log_notice("opcode-%i (%04hx) [%02x|%02x] QC=%hu AN=%hu NS=%hu AR=%hu : %r (%r) (%{sockaddrip}) size=%hu",
                       (uint32_t)(dns_message_get_opcode(mesg) >> OPCODE_SHIFT),
                       ntohs(dns_message_get_id(mesg)),
                       dns_message_get_flags_hi(mesg),
                       dns_message_get_flags_lo(mesg),
                       dns_message_get_query_count(mesg),      // QC
                       dns_message_get_answer_count(mesg),     // AC
                       dns_message_get_authority_count(mesg),  // NS
                       dns_message_get_additional_count(mesg), // AR
                       MAKE_RCODE_ERROR(dns_message_get_status(mesg)),
                       ret,
                       dns_message_get_sender_sa(mesg),
                       dns_message_get_size_u16(mesg));

            dns_message_process_lenient(mesg);

            if(dns_message_get_status(mesg) == RCODE_OK) // else a TSIG may have some complain
            {
                dns_message_set_status(mesg, FP_RCODE_NOTIMP);
                dns_message_update_answer_status(mesg);
#if DNSCORE_HAS_TSIG_SUPPORT
                if(dns_message_has_tsig(mesg))
                {
                    tsig_sign_answer(mesg);
                }
#endif
            }

            if(g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE)
            {
                log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, dns_message_get_buffer(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_BUFFER);
            }

            if((dns_message_get_status(mesg) != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0))
            {
                if(!dns_message_has_tsig(mesg) && (dns_message_get_status(mesg) != FP_RCODE_NOTAUTH))
                {
                    dns_message_edns0_clear_undefined_flags(mesg);
                    dns_message_transform_to_error(mesg);
                }

                ret = server_tcp_reply(mesg, tmc);

                TCPSTATS_LOCK();
                TCPSTATS_FIELD(tcp_undefined_count++);
                TCPSTATS_FIELD(tcp_fp[dns_message_get_status(mesg)]++);
                if(ISOK(ret))
                {
                    TCPSTATS_FIELD(tcp_output_size_total += ret);
                }
                TCPSTATS_UNLOCK();
            }
            else
            {
                TCPSTATS_LOCK();
                TCPSTATS_FIELD(tcp_undefined_count++);
                TCPSTATS_FIELD(tcp_dropped_count++);
                TCPSTATS_UNLOCK();

#if !DNSCORE_HAS_TCP_MANAGER
                tcp_set_agressive_close(sockfd, 1);
#endif
            }
        }
    } // switch operation code

    return SUCCESS;
}

/**
 * @}
 */

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

// keep this order -->

#include "server-config.h"

#include <dnscore/logger.h>
#include <dnscore/thread.h>
#include "server.h"
#include "process_class_ch.h"
#include "dynupdate_query_service.h"
#include "notify.h"
#if HAS_CTRL
#include "ctrl_notify.h"
#endif
#include "log_query.h"
#include "log_statistics.h"

static zdb *database = NULL;

void server_process_message_udp_set_database(zdb *db)
{
    database = db;
}

int
server_process_message_udp(network_thread_context_base_t *ctx, message_data *mesg)
{
    server_statistics_t * const local_statistics = ctx->statisticsp;
    local_statistics->udp_input_count++;
    ya_result ret;
    int fd = ctx->sockfd;

#if DEBUG
    log_debug("server_process_message_udp(%i, %i)", ctx->idx, fd);
#endif

    switch(message_get_opcode(mesg))
    {
        case OPCODE_QUERY:
        {
            if(ISOK(ret = message_process_query(mesg)))
            {
                message_edns0_clear_undefined_flags(mesg);

                switch(message_get_query_class(mesg))
                {
                    case CLASS_IN:
                    {
                        local_statistics->udp_queries_count++;

                        log_query(ctx->sockfd, mesg);

                        switch(message_get_query_type(mesg))
                        {
                            default:
                            {
#if HAS_RRL_SUPPORT
                                ya_result rrl = database_query_with_rrl(database, mesg);

                                local_statistics->udp_referrals_count += message_get_referral(mesg);
                                local_statistics->udp_fp[message_get_status(mesg)]++;

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
                                        return SUCCESS_DROPPED;
                                    }
                                    case RRL_PROCEED_DROP:
                                    {
                                        local_statistics->rrl_drop++;
                                        break;
                                    }
                                }
#else
                                database_query(database, mesg);

                                local_statistics->udp_referrals_count += message_get_referral(mesg);
                                local_statistics->udp_fp[message_get_status(mesg)]++;
#endif
                                break;
                            }
                            case TYPE_IXFR: // reply with a truncate to force a TCP query
                            {
                                message_set_truncated_answer(mesg);
                                message_set_query_answer_authority_additional_counts_ne(mesg, 0, 0, 0, 0);
                                message_set_size(mesg, DNS_HEADER_LENGTH);
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
                        local_statistics->udp_fp[message_get_status(mesg)]++;
                        break;
                    } // query class CH
                    default:
                    {
                        message_set_status(mesg, FP_NOT_SUPP_CLASS);
                        message_transform_to_error(mesg);
#if DNSCORE_HAS_TSIG_SUPPORT
                        if(message_has_tsig(mesg))  /* NOTE: the TSIG information is in mesg */
                        {
                            tsig_sign_answer(mesg);
                        }
#endif
                        local_statistics->udp_fp[FP_NOT_SUPP_CLASS]++;
                        break;
                    }
                } // query class
            } // if message process succeeded else ...
            else // an error occurred : no query to be done at all
            {
                if(message_get_query_count_ne(mesg) == NETWORK_ONE_16)
                {
                    const u8 *canonized_fqdn = message_get_canonised_fqdn(mesg);

                    if((ret != TSIG_BADTIME) && (ret != TSIG_BADSIG)) // BADKEY doesn't set the time nor the name
                    {
                        if(dnsname_verify_charspace(canonized_fqdn))
                        {
                            log_notice("query (%04hx) [%02x|%02x] %{dnsname} %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu",
                                       ntohs(message_get_id(mesg)),
                                       message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                                       canonized_fqdn,
                                       message_get_query_type_ptr(mesg),
                                       message_get_query_class_ptr(mesg),
                                       RCODE_ERROR_CODE(message_get_status(mesg)),
                                       ret,
                                       message_get_sender_sa(mesg),
                                       message_get_size_u16(mesg));
                        }
                        else
                        {
                            log_notice("query (%04hx) [%02x|%02x] <INVALID> %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu",
                                       ntohs(message_get_id(mesg)),
                                       message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                                       message_get_query_type_ptr(mesg),
                                       message_get_query_class_ptr(mesg),
                                       RCODE_ERROR_CODE(message_get_status(mesg)),
                                       ret,
                                       message_get_sender_sa(mesg),
                                       message_get_size_u16(mesg));
                        }
                    }
                    else
                    {
                        s64 epoch = message_tsig_get_epoch(mesg);
                        s64 fudge = message_tsig_get_fudge(mesg);

                        if(dnsname_verify_charspace(canonized_fqdn))
                        {
                            log_notice("query (%04hx) [%02x|%02x] %{dnsname} %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu key=%{dnsname} epoch=%lli (%T) +-%llis",
                                       ntohs(message_get_id(mesg)),
                                       message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                                       canonized_fqdn,
                                       message_get_query_type_ptr(mesg),
                                       message_get_query_class_ptr(mesg),
                                       RCODE_ERROR_CODE(message_get_status(mesg)),
                                       ret,
                                       message_get_sender_sa(mesg),
                                       message_get_size_u16(mesg),
                                       message_tsig_get_name(mesg),
                                       epoch,
                                       epoch,
                                       fudge);
                        }
                        else
                        {
                            log_notice("query (%04hx) [%02x|%02x] <INVALID> %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu key=%{dnsname} epoch=%lli (%T) +-%llis",
                                       ntohs(message_get_id(mesg)),
                                       message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                                       message_get_query_type_ptr(mesg),
                                       message_get_query_class_ptr(mesg),
                                       RCODE_ERROR_CODE(message_get_status(mesg)),
                                       ret,
                                       message_get_sender_sa(mesg),
                                       message_get_size_u16(mesg),
                                       message_tsig_get_name(mesg),
                                       epoch,
                                       epoch,
                                       fudge);
                        }
                    }
                }
                else
                {
                    log_notice("query (%04hx) [%02x|%02x] QC=%hu AN=%hu NS=%hu AR=%hu : %r (%r) (%{sockaddrip}) size=%hu",
                               ntohs(message_get_id(mesg)),
                               message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                               message_get_query_count(mesg), // QC
                               message_get_answer_count(mesg), // AC
                               message_get_authority_count(mesg), // NS
                               message_get_additional_count(mesg), // AR
                               RCODE_ERROR_CODE(message_get_status(mesg)),
                               ret,
                               message_get_sender_sa(mesg),
                               message_get_size_u16(mesg));
                }

                local_statistics->udp_fp[message_get_status(mesg)]++;

                if((ret == UNPROCESSABLE_MESSAGE) && (g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE))
                {
                    log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, message_get_buffer(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_ALL);
                }

                /*
                 * If not FE, or if we answer FE
                 *
                 * ... && (message_is_query(mesg) ??? and if there the query number is > 0 ???
                 */
                if( (ret != INVALID_MESSAGE) && ((message_get_status(mesg) != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)))
                {
                    message_edns0_clear_undefined_flags(mesg);

                    if(!message_has_tsig(mesg))
                    {
                        message_transform_to_error(mesg);
                    }
                }
                else
                {
                    local_statistics->udp_dropped_count++;
                    return SUCCESS_DROPPED;
                }
            }

            break;
        } // case query
        case OPCODE_NOTIFY:
        {
            if(ISOK(ret = message_process(mesg)))
            {
                message_edns0_clear_undefined_flags(mesg);

                switch(message_get_query_class(mesg))
                {
                    case CLASS_IN:
                    {
                        ya_result return_value;

                        local_statistics->udp_notify_input_count++;

                        log_info("notify (%04hx) %{dnsname} (%{sockaddr})",
                                 ntohs(message_get_id(mesg)),
                                 message_get_canonised_fqdn(mesg),
                                 message_get_sender_sa(mesg));

                        bool answer = message_isanswer(mesg);

                        return_value = notify_process(mesg); // thread-safe

                        local_statistics->udp_fp[message_get_status(mesg)]++;

                        if(FAIL(return_value))
                        {
                            log_err("notify (%04hx) %{dnsname} failed : %r",
                                    ntohs(message_get_id(mesg)),
                                    message_get_canonised_fqdn(mesg),
                                    return_value);

                            if(answer)
                            {
                                return SUCCESS_DROPPED;
                            }

                            if(!message_has_tsig(mesg))
                            {
                                message_transform_to_error(mesg);
                            }
                            break;
                        }
                        else
                        {
                            if(answer)
                            {
                                return SUCCESS_DROPPED;
                            }
                        }

                        break;
                    } // notify class IN
                    default:
                    {
                        log_warn("notify [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : unsupported class",
                                 ntohs(message_get_id(mesg)),
                                 message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg),
                                 message_get_sender_sa(mesg));
                        message_make_error(mesg, FP_NOT_SUPP_CLASS);
                        local_statistics->udp_fp[FP_NOT_SUPP_CLASS]++;
                        break;
                    }
                } // notify class
            } // if message process succeeded
            else // an error occurred : no query to be done at all
            {
                if(message_get_query_count_ne(mesg) == NETWORK_ONE_16)
                {
                    const u8 *canonized_fqdn = message_get_canonised_fqdn(mesg);

                    if(canonized_fqdn != NULL)
                    {
                        if((ret != TSIG_BADTIME) && (ret != TSIG_BADSIG)) // BADKEY doesn't set the time nor the name
                        {
                            log_notice("notify (%04hx) [%02x|%02x] %{dnsname} %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu",
                                       ntohs(message_get_id(mesg)),
                                       message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                                       canonized_fqdn,
                                       message_get_query_type_ptr(mesg),
                                       message_get_query_class_ptr(mesg),
                                       RCODE_ERROR_CODE(message_get_status(mesg)),
                                       ret,
                                       message_get_sender_sa(mesg),
                                       message_get_size_u16(mesg));
                        }
                        else
                        {
                            s64 epoch = message_tsig_get_epoch(mesg);
                            s64 fudge = message_tsig_get_fudge(mesg);

                            log_notice("notify (%04hx) [%02x|%02x] %{dnsname} %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu key=%{dnsname} epoch=%lli (%T) +-%llis",
                                       ntohs(message_get_id(mesg)),
                                       message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                                       canonized_fqdn,
                                       message_get_query_type_ptr(mesg),
                                       message_get_query_class_ptr(mesg),
                                       RCODE_ERROR_CODE(message_get_status(mesg)),
                                       ret,
                                       message_get_sender_sa(mesg),
                                       message_get_size_u16(mesg),
                                       message_tsig_get_name(mesg),
                                       epoch,
                                       epoch,
                                       fudge);
                        }
                    }
                    else
                    {
                        log_notice("notify (%04hx) [%02x|%02x] ? %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu",
                                   ntohs(message_get_id(mesg)),
                                   message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                                   RCODE_ERROR_CODE(message_get_status(mesg)),
                                   message_get_query_type_ptr(mesg),
                                   message_get_query_class_ptr(mesg),
                                   ret,
                                   message_get_sender_sa(mesg),
                                   message_get_size_u16(mesg));
                    }
                }
                else
                {
                    log_notice("notify (%04hx) [%02x|%02x] QC=%hu AN=%hu NS=%hu AR=%hu : %r (%r) (%{sockaddrip}) size=%hu",
                               ntohs(message_get_id(mesg)),
                               message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                               message_get_query_count(mesg), // QC
                               message_get_answer_count(mesg), // AC
                               message_get_authority_count(mesg), // NS
                               message_get_additional_count(mesg), // AR
                               RCODE_ERROR_CODE(message_get_status(mesg)),
                               ret,
                               message_get_sender_sa(mesg),
                               message_get_size_u16(mesg));
                }

                local_statistics->udp_fp[message_get_status(mesg)]++;

                if(ret == UNPROCESSABLE_MESSAGE && (g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE))
                {
                    log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, message_get_buffer(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_ALL);
                }

                /*
                 * If not FE, or if we answer FE
                 *
                 * ... && (message_is_query(mesg) ??? and if there the query number is > 0 ???
                 */
                if( (ret != INVALID_MESSAGE) && ((message_get_status(mesg) != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)))
                {
                    message_edns0_clear_undefined_flags(mesg);

                    if(!message_has_tsig(mesg))
                    {
                        message_transform_to_error(mesg);
                    }
                }
                else
                {
                    local_statistics->udp_dropped_count++;
                    return SUCCESS_DROPPED;
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
#if HAS_DYNUPDATE_SUPPORT
                        /**
                         * @note It's the responsibility of the called function (or one of its callees) to ensure
                         *       this does not take much time and thus to trigger a background task with the
                         *       scheduler if needed.
                         */

                        local_statistics->udp_updates_count++;
                        if(ISOK(dynupdate_query_service_enqueue(database, mesg, fd)))
                        {
                            return SUCCESS_DROPPED; // NOT break;
                        }
                        else
                        {
                            log_warn("update [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : cannot enqueue the update message",
                                     ntohs(message_get_id(mesg)),
                                     message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg),
                                     message_get_sender_sa(mesg));
                            message_make_error(mesg, FP_RCODE_SERVFAIL);
                            local_statistics->udp_fp[FP_RCODE_SERVFAIL]++;
                            return SUCCESS;         // needs to be >= 0: the server will send the SERVFAIL message
                        }
#else
                        message_make_error(mesg, FP_FEATURE_DISABLED);
                        local_statistics->udp_fp[FP_FEATURE_DISABLED]++;
                        break;
#endif

                    } // update class IN
                    default:
                    {
                        log_warn("update [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : unsupported class",
                                 ntohs(message_get_id(mesg)),
                                 message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg),
                                 message_get_sender_sa(mesg));
                        message_make_error(mesg, FP_NOT_SUPP_CLASS);
                        local_statistics->udp_fp[FP_NOT_SUPP_CLASS]++;
                        break;
                    }
                } // update class
            } // if message process succeeded
            else // an error occurred : no query to be done at all
            {
                if(message_get_query_count_ne(mesg) == NETWORK_ONE_16)
                {
                    const u8 *canonized_fqdn = message_get_canonised_fqdn(mesg);

                    if(canonized_fqdn != NULL)
                    {
                        if((ret != TSIG_BADTIME) && (ret != TSIG_BADSIG)) // BADKEY doesn't set the time nor the name
                        {
                            log_notice("update (%04hx) [%02x|%02x] %{dnsname} %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu",
                                       ntohs(message_get_id(mesg)),
                                       message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                                       canonized_fqdn,
                                       message_get_query_type_ptr(mesg),
                                       message_get_query_class_ptr(mesg),
                                       RCODE_ERROR_CODE(message_get_status(mesg)),
                                       ret,
                                       message_get_sender_sa(mesg),
                                       message_get_size_u16(mesg));
                        }
                        else
                        {
                            s64 epoch = message_tsig_get_epoch(mesg);
                            s64 fudge = message_tsig_get_fudge(mesg);

                            log_notice("update (%04hx) [%02x|%02x] %{dnsname} %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu key=%{dnsname} epoch=%lli (%T) +-%llis",
                                       ntohs(message_get_id(mesg)),
                                       message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                                       canonized_fqdn,
                                       message_get_query_type_ptr(mesg),
                                       message_get_query_class_ptr(mesg),
                                       RCODE_ERROR_CODE(message_get_status(mesg)),
                                       ret,
                                       message_get_sender_sa(mesg),
                                       message_get_size_u16(mesg),
                                       message_tsig_get_name(mesg),
                                       epoch,
                                       epoch,
                                       fudge);
                        }
                    }
                    else
                    {
                        log_notice("update (%04hx) [%02x|%02x] ? %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu",
                                   ntohs(message_get_id(mesg)),
                                   message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                                   RCODE_ERROR_CODE(message_get_status(mesg)),
                                   message_get_query_type_ptr(mesg),
                                   message_get_query_class_ptr(mesg),
                                   ret,
                                   message_get_sender_sa(mesg),
                                   message_get_size_u16(mesg));
                    }
                }
                else
                {
                    log_notice("update (%04hx) [%02x|%02x] QC=%hu AN=%hu NS=%hu AR=%hu : %r (%r) (%{sockaddrip}) size=%hu",
                               ntohs(message_get_id(mesg)),
                               message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                               message_get_query_count(mesg), // QC
                               message_get_answer_count(mesg), // AC
                               message_get_authority_count(mesg), // NS
                               message_get_additional_count(mesg), // AR
                               RCODE_ERROR_CODE(message_get_status(mesg)),
                               ret,
                               message_get_sender_sa(mesg),
                               message_get_size_u16(mesg));
                }

                local_statistics->udp_fp[message_get_status(mesg)]++;

                if((ret == UNPROCESSABLE_MESSAGE) && (g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE))
                {
                    log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, message_get_buffer(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_ALL);
                }

                /*
                 * If not FE, or if we answer FE
                 *
                 * ... && (message_is_query(mesg) ??? and if there the query number is > 0 ???
                 */
                if( (ret != INVALID_MESSAGE) && ((message_get_status(mesg) != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)))
                {
                    message_edns0_clear_undefined_flags(mesg);

                    if(!message_has_tsig(mesg))
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

        case (15<<OPCODE_SHIFT):
        {
            if(service_should_reconfigure_or_stop(ctx->worker) || (ctx->must_stop))
            {
                return STOPPED_BY_APPLICATION_SHUTDOWN;
            }
            FALLTHROUGH
        }
        default:
        {
            ret = MAKE_DNSMSG_ERROR(FP_RCODE_NOTIMP);
            /*ret = */ message_process_query(mesg);
            message_set_status(mesg, FP_RCODE_NOTIMP);

            if(ctx->must_stop)
            {
                return STOPPED_BY_APPLICATION_SHUTDOWN; // shutdown
            }

            log_notice("opcode-%i (%04hx) [%02x|%02x] QC=%hu AN=%hu NS=%hu AR=%hu : %r (%r) (%{sockaddrip}) size=%hu",
                       (u32)(message_get_opcode(mesg) >> OPCODE_SHIFT),
                       ntohs(message_get_id(mesg)),
                       message_get_flags_hi(mesg),message_get_flags_lo(mesg),
                       message_get_query_count(mesg), // QC
                       message_get_answer_count(mesg), // AC
                       message_get_authority_count(mesg), // NS
                       message_get_additional_count(mesg), // AR
                       MAKE_DNSMSG_ERROR(message_get_status(mesg)),
                       ret,
                       message_get_sender_sa(mesg),
                       message_get_size_u16(mesg));

            if(g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE)
            {
                log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, message_get_buffer(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_ALL);
            }

            if((message_get_status(mesg) != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0))
            {
                message_edns0_clear_undefined_flags(mesg);

                if(!message_has_tsig(mesg))
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

    return SUCCESS;
}

/**
 * @}
 */

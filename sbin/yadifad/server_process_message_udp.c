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
#include "server.h"
#include "process_class_ch.h"
#include "dynupdate_query_service.h"
#include "notify.h"
#if HAS_CTRL
#include "ctrl_notify.h"
#endif
#include "log_query.h"
#include "log_statistics.h"
#include "server_process_message_common.h"

static zdb_t *database = NULL;

void          server_process_message_udp_set_database(zdb_t *db) { database = db; }

int           server_process_message_udp(network_thread_context_base_t *ctx, dns_message_t *mesg)
{
    server_statistics_t *const local_statistics = ctx->statisticsp;
    local_statistics->udp_input_count++;
    int       fd = ctx->sockfd;

    ya_result ret;

#if DEBUG
    log_debug("server_process_message_udp(%i, %i)", ctx->idx, fd);
#endif

    switch(dns_message_get_opcode(mesg))
    {
        case OPCODE_QUERY:
        {
            if(ISOK(ret = dns_message_process_query(mesg)))
            {
                dns_message_edns0_clear_undefined_flags(mesg);

                switch(dns_message_get_query_class(mesg))
                {
                    case CLASS_IN:
                    {
                        log_query(ctx->sockfd, mesg);

                        local_statistics->udp_queries_count++;

                        switch(dns_message_get_query_type(mesg))
                        {
                            default:
                            {
#if HAS_RRL_SUPPORT
                                ya_result rrl = database_query_with_rrl(database, mesg);

                                local_statistics->udp_referrals_count += dns_message_get_referral(mesg);
                                local_statistics->udp_fp[dns_message_get_status(mesg)]++;

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

                                local_statistics->udp_referrals_count += dns_message_get_referral(mesg);
                                local_statistics->udp_fp[dns_message_get_status(mesg)]++;
#endif
                                break;
                            }
                            case TYPE_IXFR: // reply with a truncate to force a TCP query
                            {
                                dns_message_set_truncated_answer(mesg);
                                dns_message_set_query_answer_authority_additional_counts_ne(mesg, 0, 0, 0, 0);
                                dns_message_set_size(mesg, DNS_HEADER_LENGTH);
                                local_statistics->udp_fp[FP_IXFR_UDP]++;
                                break;
                            }
                            case TYPE_AXFR:
                            case TYPE_OPT:
                            {
                                dns_message_make_error(mesg, FP_INCORR_PROTO);
                                local_statistics->udp_fp[FP_INCORR_PROTO]++;
                                break;
                            }
                        } // switch query type

                        break;
                    } // query class IN
                    case CLASS_CH:
                    {
                        class_ch_process(mesg); // thread-safe
                        local_statistics->udp_fp[dns_message_get_status(mesg)]++;
                        break;
                    } // query class CH
                    default:
                    {
                        dns_message_set_status(mesg, FP_NOT_SUPP_CLASS);
                        dns_message_transform_to_error(mesg);
#if DNSCORE_HAS_TSIG_SUPPORT
                        if(dns_message_has_tsig(mesg)) /* NOTE: the TSIG information is in mesg */
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
                server_process_message_query_log_error(mesg, ret);

                local_statistics->udp_fp[dns_message_get_status(mesg)]++;

                /*
                 * If not FE, or if we answer FE
                 *
                 * ... && (message_is_query(mesg) ??? and if there the query number is > 0 ???
                 */
                if((ret != INVALID_MESSAGE) && ((dns_message_get_status(mesg) != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)))
                {
                    dns_message_edns0_clear_undefined_flags(mesg);

                    if(!dns_message_has_tsig(mesg) && (dns_message_get_status(mesg) != FP_RCODE_NOTAUTH))
                    {
                        dns_message_transform_to_error(mesg);
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
            if(ISOK(ret = dns_message_process(mesg)))
            {
                dns_message_edns0_clear_undefined_flags(mesg);

                switch(dns_message_get_query_class(mesg))
                {
                    case CLASS_IN:
                    {
                        ya_result return_value;

                        local_statistics->udp_notify_input_count++;

                        log_info("notify (%04hx) %{dnsname} (%{sockaddr})", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), dns_message_get_sender_sa(mesg));

                        bool answer = dns_message_is_answer(mesg);

                        return_value = notify_process(mesg); // thread-safe

                        local_statistics->udp_fp[dns_message_get_status(mesg)]++;

                        if(FAIL(return_value))
                        {
                            log_err("notify (%04hx) %{dnsname} failed : %r", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), return_value);

                            if(answer)
                            {
                                return SUCCESS_DROPPED;
                            }

                            if(!dns_message_has_tsig(mesg))
                            {
                                dns_message_transform_to_error(mesg);
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
                                 ntohs(dns_message_get_id(mesg)),
                                 dns_message_get_canonised_fqdn(mesg),
                                 dns_message_get_query_type_ptr(mesg),
                                 dns_message_get_query_class_ptr(mesg),
                                 dns_message_get_sender_sa(mesg));
                        dns_message_make_error(mesg, FP_NOT_SUPP_CLASS);
                        local_statistics->udp_fp[FP_NOT_SUPP_CLASS]++;
                        break;
                    }
                } // notify class
            } // if message process succeeded
            else // an error occurred : no query to be done at all
            {
                server_process_message_notify_log_error(mesg, ret);

                local_statistics->udp_fp[dns_message_get_status(mesg)]++;

                /*
                 * If not FE, or if we answer FE
                 *
                 * ... && (message_is_query(mesg) ??? and if there the query number is > 0 ???
                 */
                if((ret != INVALID_MESSAGE) && ((dns_message_get_status(mesg) != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)))
                {
                    dns_message_edns0_clear_undefined_flags(mesg);

                    if(!dns_message_has_tsig(mesg) && (dns_message_get_status(mesg) != FP_RCODE_NOTAUTH))
                    {
                        dns_message_transform_to_error(mesg);
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
            if(ISOK(ret = dns_message_process(mesg)))
            {
                dns_message_edns0_clear_undefined_flags(mesg);

                switch(dns_message_get_query_class(mesg))
                {
                    case CLASS_IN:
                    {
#if ZDB_HAS_PRIMARY_SUPPORT && ZDB_HAS_DYNUPDATE_SUPPORT
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
                            log_warn(
                                "update [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : cannot enqueue the "
                                "update message",
                                ntohs(dns_message_get_id(mesg)),
                                dns_message_get_canonised_fqdn(mesg),
                                dns_message_get_query_type_ptr(mesg),
                                dns_message_get_query_class_ptr(mesg),
                                dns_message_get_sender_sa(mesg));
                            dns_message_make_error(mesg, FP_RCODE_SERVFAIL);
                            local_statistics->udp_fp[FP_RCODE_SERVFAIL]++;
                            return SUCCESS; // needs to be >= 0: the server will send the SERVFAIL message
                        }
#else
                        dns_message_set_status(mesg, FP_FEATURE_DISABLED);
                        dns_message_transform_to_error(mesg);
                        local_statistics->udp_fp[FP_FEATURE_DISABLED]++;
                        break;
#endif

                    } // update class IN
                    default:
                    {
                        log_warn("update [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : unsupported class",
                                 ntohs(dns_message_get_id(mesg)),
                                 dns_message_get_canonised_fqdn(mesg),
                                 dns_message_get_query_type_ptr(mesg),
                                 dns_message_get_query_class_ptr(mesg),
                                 dns_message_get_sender_sa(mesg));
                        dns_message_make_error(mesg, FP_NOT_SUPP_CLASS);
                        local_statistics->udp_fp[FP_NOT_SUPP_CLASS]++;
                        break;
                    }
                } // update class
            } // if message process succeeded
            else // an error occurred : no query to be done at all
            {
                server_process_message_update_log_error(mesg, ret);

                local_statistics->udp_fp[dns_message_get_status(mesg)]++;

                if((ret == UNPROCESSABLE_MESSAGE) && (g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE))
                {
                    log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, dns_message_get_buffer(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_BUFFER);
                }

                /*
                 * If not FE, or if we answer FE
                 *
                 * ... && (message_is_query(mesg) ??? and if there the query number is > 0 ???
                 */
                if((ret != INVALID_MESSAGE) && ((dns_message_get_status(mesg) != RCODE_FORMERR) || ((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0)))
                {
                    dns_message_edns0_clear_undefined_flags(mesg);

                    if(!dns_message_has_tsig(mesg) && (dns_message_get_status(mesg) != FP_RCODE_NOTAUTH))
                    {
                        dns_message_transform_to_error(mesg);
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
#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING
        case OPCODE_CTRL:
        {
            if(ISOK(ret = message_process(mesg)))
            {
                message_edns0_clear_undefined_flags(mesg);

                switch(message_get_query_class(mesg))
                {
                    case CLASS_CTRL:
                    {
                        if((message_get_opcode(mesg) == OPCODE_NOTIFY) && ((g_config->server_flags & SERVER_FL_DYNAMIC_PROVISIONING) != 0))
                        {
                            ya_result return_value;

                            local_statistics->udp_notify_input_count++;

                            log_info("notify (%04hx) %{dnsname} (%{sockaddr})", ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), message_get_sender_sa(mesg));

                            // remember if it's a query or an answer

                            bool answer = message_is_answer(mesg);
                            return_value = notify_process(mesg); // thread-safe

                            local_statistics->udp_fp[message_get_status(mesg)]++;

                            if(FAIL(return_value))
                            {
                                log_err("notify (%04hx) %{dnsname} failed : %r", ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), return_value);

                                if(answer)
                                {
                                    return;
                                }

                                message_transform_to_error(mesg);
#if DNSCORE_HAS_TSIG_SUPPORT
                                if(message_has_tsig(mesg)) /* NOTE: the TSIG information is in mesg */
                                {
                                    tsig_sign_answer(mesg);
                                }
#endif
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
                        else
                        {
                            log_warn("query (%04hx) unhandled opcode %i (%{sockaddr}) for ", ntohs(message_get_id(mesg)), message_get_opcode(mesg) >> OPCODE_SHIFT, message_get_sender_sa(mesg));
                        }

                        break;
                    }
                    default:
                    {
                        log_warn("ctrl [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : unsupported class",
                                 ntohs(message_get_id(mesg)),
                                 message_get_canonised_fqdn(mesg),
                                 message_get_query_type_ptr(mesg),
                                 message_get_query_class_ptr(mesg),
                                 message_get_sender_sa(mesg));
                        message_make_error(mesg, FP_NOT_SUPP_CLASS);
                        local_statistics->udp_fp[FP_NOT_SUPP_CLASS]++;
                        break;
                    }
                } // ctrl class
            } // if message process succeeded

            break;
        } // case CTRL
#endif // HAS_CTRL_DYNAMIC_PROVISIONING
        case(15 << OPCODE_SHIFT):
        {
            if(service_should_reconfigure_or_stop(ctx->worker) || (ctx->must_stop)) // will fallthrough on purpose
            {
                return STOPPED_BY_APPLICATION_SHUTDOWN;
            }
            FALLTHROUGH
        }
        default:
        {
            log_notice("opcode-%i (%04hx) [%02x|%02x] QC=%hu AN=%hu NS=%hu AR=%hu (%{sockaddrip}) size=%hu",
                       (uint32_t)(dns_message_get_opcode(mesg) >> OPCODE_SHIFT),
                       ntohs(dns_message_get_id(mesg)),
                       dns_message_get_flags_hi(mesg),
                       dns_message_get_flags_lo(mesg),
                       dns_message_get_query_count(mesg),      // QC
                       dns_message_get_answer_count(mesg),     // AC
                       dns_message_get_authority_count(mesg),  // NS
                       dns_message_get_additional_count(mesg), // AR
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

            local_statistics->udp_undefined_count++;

            if(ctx->must_stop)
            {
                return STOPPED_BY_APPLICATION_SHUTDOWN; // shutdown
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

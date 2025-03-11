/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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

void server_process_message_opcode_log_error(dns_message_t *mesg, ya_result ret, const char *opcode_name)
{
    if(dns_message_get_query_count_ne(mesg) == NETWORK_ONE_16)
    {
        const uint8_t *canonized_fqdn = dns_message_get_canonised_fqdn(mesg);

        if((ret != TSIG_BADTIME) && (ret != TSIG_BADSIG)) // BADKEY doesn't set the time nor the name
        {
            if(dnsname_verify_charspace(canonized_fqdn))
            {
                log_notice("%s (%04hx) [%02x|%02x] %{dnsname} %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu",
                           opcode_name,
                           ntohs(dns_message_get_id(mesg)),
                           dns_message_get_flags_hi(mesg),
                           dns_message_get_flags_lo(mesg),
                           canonized_fqdn,
                           dns_message_get_query_type_ptr(mesg),
                           dns_message_get_query_class_ptr(mesg),
                           RCODE_ERROR_CODE(dns_message_get_status(mesg)),
                           ret,
                           dns_message_get_sender_sa(mesg),
                           dns_message_get_size_u16(mesg));
            }
            else
            {
                log_notice("%s (%04hx) [%02x|%02x] <INVALID> %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu",
                           opcode_name,
                           ntohs(dns_message_get_id(mesg)),
                           dns_message_get_flags_hi(mesg),
                           dns_message_get_flags_lo(mesg),
                           dns_message_get_query_type_ptr(mesg),
                           dns_message_get_query_class_ptr(mesg),
                           RCODE_ERROR_CODE(dns_message_get_status(mesg)),
                           ret,
                           dns_message_get_sender_sa(mesg),
                           dns_message_get_size_u16(mesg));
            }
        }
        else
        {
            int64_t epoch = dns_message_tsig_get_epoch(mesg);
            int64_t fudge = dns_message_tsig_get_fudge(mesg);

            if(dnsname_verify_charspace(canonized_fqdn))
            {
                if(dns_message_has_tsig(mesg))
                {
                    log_notice(
                        "%s (%04hx) [%02x|%02x] %{dnsname} %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu "
                        "key=%{dnsname} epoch=%lli (%T) +-%llis",
                        opcode_name,
                        ntohs(dns_message_get_id(mesg)),
                        dns_message_get_flags_hi(mesg),
                        dns_message_get_flags_lo(mesg),
                        canonized_fqdn,
                        dns_message_get_query_type_ptr(mesg),
                        dns_message_get_query_class_ptr(mesg),
                        RCODE_ERROR_CODE(dns_message_get_status(mesg)),
                        ret,
                        dns_message_get_sender_sa(mesg),
                        dns_message_get_size_u16(mesg),
                        dns_message_tsig_get_name(mesg),
                        epoch,
                        epoch,
                        fudge);
                }
                else
                {
                    log_notice("%s (%04hx) [%02x|%02x] %{dnsname} %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu",
                               opcode_name,
                               ntohs(dns_message_get_id(mesg)),
                               dns_message_get_flags_hi(mesg),
                               dns_message_get_flags_lo(mesg),
                               canonized_fqdn,
                               dns_message_get_query_type_ptr(mesg),
                               dns_message_get_query_class_ptr(mesg),
                               RCODE_ERROR_CODE(dns_message_get_status(mesg)),
                               ret,
                               dns_message_get_sender_sa(mesg),
                               dns_message_get_size_u16(mesg));
                }
            }
            else
            {
                if(dns_message_has_tsig(mesg))
                {
                    log_notice(
                        "%s (%04hx) [%02x|%02x] <INVALID> %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu "
                        "key=%{dnsname} epoch=%lli (%T) +-%llis",
                        opcode_name,
                        ntohs(dns_message_get_id(mesg)),
                        dns_message_get_flags_hi(mesg),
                        dns_message_get_flags_lo(mesg),
                        dns_message_get_query_type_ptr(mesg),
                        dns_message_get_query_class_ptr(mesg),
                        RCODE_ERROR_CODE(dns_message_get_status(mesg)),
                        ret,
                        dns_message_get_sender_sa(mesg),
                        dns_message_get_size_u16(mesg),
                        dns_message_tsig_get_name(mesg),
                        epoch,
                        epoch,
                        fudge);
                }
                else
                {
                    log_notice("%s (%04hx) [%02x|%02x] <INVALID> %{dnstype} %{dnsclass} : %r (%r) (%{sockaddrip}) size=%hu",
                               opcode_name,
                               ntohs(dns_message_get_id(mesg)),
                               dns_message_get_flags_hi(mesg),
                               dns_message_get_flags_lo(mesg),
                               dns_message_get_query_type_ptr(mesg),
                               dns_message_get_query_class_ptr(mesg),
                               RCODE_ERROR_CODE(dns_message_get_status(mesg)),
                               ret,
                               dns_message_get_sender_sa(mesg),
                               dns_message_get_size_u16(mesg));
                }
            }
        }
    }
    else
    {
        log_notice("%s (%04hx) [%02x|%02x] QC=%hu AN=%hu NS=%hu AR=%hu : %r (%r) (%{sockaddrip}) size=%hu",
                   opcode_name,
                   ntohs(dns_message_get_id(mesg)),
                   dns_message_get_flags_hi(mesg),
                   dns_message_get_flags_lo(mesg),
                   dns_message_get_query_count(mesg),      // QC
                   dns_message_get_answer_count(mesg),     // AC
                   dns_message_get_authority_count(mesg),  // NS
                   dns_message_get_additional_count(mesg), // AR
                   RCODE_ERROR_CODE(dns_message_get_status(mesg)),
                   ret,
                   dns_message_get_sender_sa(mesg),
                   dns_message_get_size_u16(mesg));
    }

    if((ret == UNPROCESSABLE_MESSAGE) && (g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE))
    {
        log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, dns_message_get_buffer(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_BUFFER);
    }
}

void server_process_message_query_log_error(dns_message_t *mesg, ya_result ret) { server_process_message_opcode_log_error(mesg, ret, "query"); }

void server_process_message_notify_log_error(dns_message_t *mesg, ya_result ret) { server_process_message_opcode_log_error(mesg, ret, "notify"); }

void server_process_message_update_log_error(dns_message_t *mesg, ya_result ret) { server_process_message_opcode_log_error(mesg, ret, "update"); }

/**
 * @}
 */

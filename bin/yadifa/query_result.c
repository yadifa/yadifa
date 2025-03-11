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

#include "client_config.h"

#include <dnscore/dns_message_writer.h>
#include <dnscore/dns_packet_reader.h>
#include <dnscore/logger.h>

#include <dnslg/config_resolver.h>

#include "common_config.h"

#include "query_result.h"

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

extern logger_handle_t *g_client_logger;
#define MODULE_MSG_HANDLE g_client_logger

extern resolv_t config_resolver_settings;

/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS

/** @brief query_result_check
 *
 *  @param id_sent uint16_t
 *  @param protocol uint16_t
 *  @param question_mode uint16_t
 *  @param mesg message_data
 *  @param go_tcp uint8_t *
 *  @return ya_result
 */
ya_result query_result_check(uint16_t id_sent, uint16_t protocol, uint16_t question_mode, dns_message_t *mesg, uint8_t *go_tcp)
{
    ya_result ret;
    uint16_t  id_returned;
    uint16_t  flags;

    /*    ------------------------------------------------------------    */

    if(dns_message_is_answer(mesg))
    {
        if(FAIL(ret = dns_message_process_lenient(mesg)))
        {
            return ret;
        }
    }
    else
    {
        return ERROR;
    }

    /* initialize flag */
    *go_tcp = NOK;

    /* read first 4 bytes and check some stuff */

    dns_packet_reader_t pr;

    dns_packet_reader_init_from_message(&pr, mesg);

    /* 1. check ID */
    id_returned = dns_message_get_id(mesg);

    if(id_sent != id_returned)
    {
        return NOK; /** @todo 2014xxxx gve --  still needs to add a nice error code */
    }

    /* 2. check for QR bit */
    flags = dns_message_get_flags(mesg);

    if(((ntohs(flags) >> 8) & QR_BITS) == 0)
    {
        log_info(" NOANSWER: %x", ntohs(flags));

        return NOK; /** @todo 2014xxxx gve -- still needs to add a nice error code */
    }

    /* 3. check if TCP query is needed */
    if(!(question_mode & QM_FLAGS_INGORE_TC))
    {
        if(protocol & QM_PROTOCOL_TCP)
        {
            if((ntohs(flags) >> 8) & TC_BITS)
            {
                log_debug("truncated go tcp");

                *go_tcp = OK;
            }
        }
    }

    return OK;
}

ya_result query_result_dns_message_write(output_stream_t *os, dns_message_t *mesg, uint32_t view_model, uint16_t view_mode_with, int32_t time_duration_ms)
{
    if(view_mode_with == 0)
    {
        view_mode_with = DNS_MESSAGE_WRITER_SIMPLE_QUERY;
    }

    dns_message_writer_method *writer_method;

    switch(view_model)
    {
        case VM_DEFAULT:
        {
            writer_method = dns_message_writer_dig;
            break;
        }
        case VM_DIG:
        {
            writer_method = dns_message_writer_dig;
            break;
        }
        case VM_JSON:
        {
            writer_method = dns_message_writer_json;
            break;
        }
        case VM_EASYPARSE:
        {
            writer_method = dns_message_writer_easyparse;
            break;
        }

        default: // you can only have one 1 bit set of the first 16 bits
        {
            osformatln(os, "you can set one view mode at the time (e.g. --json)");
            return INVALID_ARGUMENT_ERROR;
        }
    }

    dns_message_writer_t dmw;
    dns_message_writer_init(&dmw, os, writer_method, view_mode_with);
    dns_message_writer_message_t msg;
    msg.buffer = dns_message_get_buffer_const(mesg);
    msg.length = dns_message_get_size(mesg);
    msg.time_duration_ms = time_duration_ms;
    msg.when = time(NULL);
    msg.server = NULL;
    msg.protocol = 0;
    ya_result ret = dns_message_writer_write(&dmw, &msg);
    return ret;
}

ya_result query_result_view(const dns_message_writer_t *dmw, const dns_message_writer_message_t *msg, ya_result query_return_code)
{
    ya_result return_value;

    return_value = dns_message_writer_write(dmw, msg);

    if(FAIL(query_return_code))
    {
        switch(query_return_code)
        {
            case MAKE_ERRNO_ERROR(ETIMEDOUT):
#if EAGAIN != ETIMEDOUT
            case MAKE_ERRNO_ERROR(EAGAIN):
#endif
            case MAKE_ERRNO_ERROR(ECONNREFUSED):
                /// @todo 20240924 edf -- this should be formatted using the different view models
                formatln(";; connection timed out; no servers could be reached");
                flushout();
                break;
            default:
                if(msg->server == NULL)
                {
                    formatln(";; query to server failed with: %r", query_return_code);
                }
                else
                {
                    formatln(";; query to %{hostaddr} failed with: %r", msg->server, query_return_code);
                }
                flushout();
                break;
        }
    }

    println("");

    /// @todo 20150716 gve -- return_value is not really used
    if(return_value < 0)
    {
        log_err("answer print: %r", return_value);
    }
    flushout();
    return return_value;
}

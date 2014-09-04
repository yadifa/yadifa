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
#include "common-config.h"
#include <dnscore/logger.h>
#include <dnscore/host_address.h>
#include <dnslg/config-resolver.h>
#include <dnslg/dns.h>
#include <dnslg/resolv.h>
#include "query-result.h"

extern logger_handle *g_client_logger;
#define MODULE_MSG_HANDLE g_client_logger

extern resolv_s                   config_resolver_settings;

ya_result
check_query_result(u16 id_sent, u16 protocol, u16 question_mode, message_data *mesg, u8 *go_tcp)
{
    ya_result                                                           ret;
    u16                                                         id_returned;
    u16                                                               flags;

    /*    ------------------------------------------------------------    */ 
    
    if(message_isanswer(mesg))
    {    
        if(FAIL(ret = message_process_lenient(mesg)))
        {
            return ret;
        }
    }
    else
    {
        return ERROR;
    }

    /* Initialize flag */
    *go_tcp = NOK;


    /* Read first 4 bytes and check some stuff */

    packet_unpack_reader_data  pr;

    packet_reader_init(&pr, mesg->buffer, mesg->received);

    /* 1. Check ID */
    packet_reader_read_u16(&pr, &id_returned);

    if (FAIL(id_sent == id_returned))
    {
        return NOK;     /** todo: still needs to add a nice error code */
    }

    /* 2. Check for QR bit */
    packet_reader_read_u16(&pr, &flags);

    if FAIL(((ntohs(flags) >> 8 ) & QR_BITS))
    {
        log_info(" NOANSWER: %x", ntohs(flags));

        return NOK;      /** todo: still needs to add a nice error code */
    }

    /* 3. Check if TCP query is needed */
    if  (!(question_mode & QM_FLAGS_INGORE_TC))
    {
        if (protocol & QM_PROTOCOL_TCP)
        {
            if ((ntohs(flags) >> 8 ) & TC_BITS)
            {
                log_debug("truncated go tcp");

                *go_tcp = OK;
            }
        }
    }


    return OK;
}


ya_result
view_query_result(message_data *mesg, long duration, u16 view_mode_with)
{
    ya_result                                                  return_value;

    if(view_mode_with == 0)
    {
        view_mode_with = VM_WITH_ADDITIONAL|VM_WITH_ANSWER|VM_WITH_AUTHORITY|VM_WITH_QUESTION;
    }

    //u16 view_mode_with             = g_yadig_main_settings.view_mode_with;

    /*    ------------------------------------------------------------    */ 

//    log_debug("VIEW QUERY RESULT: %x", config->view_mode);

//    formatln("result view_mode: %d", view_mode_with);

#undef VM_MULTILINE
#define VM_MULTILINE 0
    if (view_mode_with & VM_MULTILINE)
    {
        formatln("MULTI");
    }

    else
    {
#ifdef DEBUG
            formatln("DIG");
            osprint_dump(termout, mesg->buffer, mesg->received, 16, OSPRINT_DUMP_LAYOUT_GERY | OSPRINT_DUMP_HEXTEXT);
            formatln("");

            flushout();
#endif

        return_value = message_print_format_dig(termout, mesg->buffer, mesg->received, view_mode_with, duration);
    }

    if (return_value < 0)
    {
        log_err("answer print: %r", return_value);
    }
    flushout();

    return return_value;
}



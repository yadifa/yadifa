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

#include "client-config.h"

#include <dnscore/host_address.h>
//#include <dnscore/logger.h>
#include <dnscore/message-viewer.h>
#include <dnscore/message-buffer.h>
#include <dnscore/packet_reader.h>
#include <dnscore/logger.h>

#include <dnslg/config-resolver.h>

#include "common-config.h"

#include "message-viewer-dig.h"

#include "query-result.h"
#include "message-viewer-parse.h"
#include "message-viewer-json.h"
#include "message-viewer-xml.h"
#include "message-viewer-wire.h"



/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

extern logger_handle *g_client_logger;
#define MODULE_MSG_HANDLE g_client_logger

extern resolv_s config_resolver_settings;


/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS 

/** @brief query_result_check
 *
 *  @param id_sent u16
 *  @param protocol u16
 *  @param question_mode u16
 *  @param mesg message_data
 *  @param go_tcp u8 *
 *  @return ya_result
 */
ya_result
query_result_check(u16 id_sent, u16 protocol, u16 question_mode, message_data *mesg, u8 *go_tcp)
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

    /* initialize flag */
    *go_tcp = NOK;


    /* read first 4 bytes and check some stuff */

    packet_unpack_reader_data  pr;

    packet_reader_init_from_message(&pr, mesg);

    /* 1. check ID */
    id_returned = message_get_id(mesg);

    if(id_sent != id_returned)
    {
        return NOK;     /** @todo 2014xxxx gve --  still needs to add a nice error code */
    }

    /* 2. check for QR bit */
    flags = message_get_flags(mesg);

    if FAIL(((ntohs(flags) >> 8 ) & QR_BITS))
    {
        log_info(" NOANSWER: %x", ntohs(flags));

        return NOK;      /** @todo 2014xxxx gve -- still needs to add a nice error code */
    }

    /* 3. check if TCP query is needed */
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

/*    ------------------------------------------------------------    */

#if 1

ya_result
query_result_message_viewer_init(message_viewer *mv, output_stream *os, u32 view_mode, u16 view_mode_with)
{
    if(view_mode_with == 0)
    {
        view_mode_with = MESSAGE_VIEWER_SIMPLE_QUERY;
    }

    switch(view_mode)
    {
        case VM_DEFAULT:
        {
            message_viewer_dig_init(mv, os, view_mode_with);

            break;
        }
        case VM_PARSE_FRIENDLY:
        {
            message_viewer_parse_init(mv, os, view_mode_with);

            break;
        }
        case VM_DIG:
        {
            message_viewer_dig_init(mv, os, view_mode_with);

            break;
        }
        case VM_JSON:
        {
            message_viewer_json_init(mv, os, view_mode_with);

            break;
        }
        case VM_XML:
        {
            message_viewer_xml_init(mv, os, view_mode_with);

            break;
        }
        case VM_WIRE:
        {
            message_viewer_wire_init(mv, os, view_mode_with);

            break;
        }

        default: // you can only have one 1 bit set of the first 16 bits
        {
            osformatln(os, "you can set one view mode at the time (e.g. --json)");

            return NOK;
        }
    }

    return OK;
}
#endif

ya_result
query_result_view(message_viewer *mv, message_data *mesg, s64 duration, ya_result query_return_code)
{
    ya_result                                              return_value = 0;
    /*    ------------------------------------------------------------    */



    u16 old_view_mode_with = mv->view_mode_with; // save

    if(FAIL(query_return_code))
    {
        mv->view_mode_with = 0; // errors don't need to print all that
    }

    message_viewer_start(mv);
    message_buffer_processor(mv, message_get_buffer(mesg), message_get_size(mesg));
    if(ISOK(query_return_code))
    {
        message_viewer_bytes_and_message_update(mv, message_get_size(mesg), 1);
        message_viewer_end(mv, duration);
    }

    if(FAIL(query_return_code))
    {
        mv->view_mode_with = old_view_mode_with; // restore

        switch(query_return_code)
        {
            case MAKE_ERRNO_ERROR(ETIMEDOUT):
#if EAGAIN != ETIMEDOUT
            case MAKE_ERRNO_ERROR(EAGAIN):
#endif
            case MAKE_ERRNO_ERROR(ECONNREFUSED):
                formatln(";; connection timed out; no servers could be reached");
                flushout();
                break;
            default:
                if(mv->host == NULL)
                {
                    formatln(";; query to server failed with: %r", query_return_code);
                }
                else
                {
                    formatln(";; query to %{hostaddr} failed with: %r", mv->host, query_return_code);
                }
                flushout();
                break;
        }
    }

    /// @todo 20150716 gve -- return_value is not really used
    if(return_value < 0)
    {
        log_err("answer print: %r", return_value);
    }
    flushout();
    return return_value;
}


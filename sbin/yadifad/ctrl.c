/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2023, EURid vzw. All rights reserved.
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

/** @defgroup server
 *  @ingroup yadifad
 *  @brief server
 *
 *  Handles queries made in the CH class (ie: version.*)
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#include "server-config.h"

#include <dnscore/file_output_stream.h>
#include <dnscore/logger.h>
#include <dnscore/rfc.h>
#include <dnscore/ctrl-rfc.h>
#include <dnscore/threaded_queue.h>

#include <dnsdb/zdb_zone.h>
#include <dnscore/format.h>
#include <dnscore/packet_writer.h>

#include <dnscore/error_state.h>

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "server-config.h"
#include "confs.h"
#include "signals.h"
#include <dnscore/acl.h>
#include <dnscore/tcp_io_stream.h>
#include "notify.h"


#if DNSCORE_HAS_CTRL



#include "ctrl_query.h"
#include "ctrl.h"

#include "database-service.h"


extern logger_handle* g_server_logger;

/* Zone file variables */
extern zone_data_set database_zone_desc;

static config_control g_ctrl_config =
{

    NULL,
    TRUE
};

static error_state_t ctrl_tcp_reply_error_state = ERROR_STATE_INITIALIZER;

static inline ya_result
ctrl_tcp_reply(message_data *mesg, int sockfd)
{
    ssize_t ret;

    if(ISOK(ret = message_update_length_send_tcp_with_default_minimum_throughput(mesg, sockfd)))
    {
        error_state_clear_locked(&ctrl_tcp_reply_error_state, NULL, 0, NULL);
    }
    else
    {
        if(error_state_log_locked(&ctrl_tcp_reply_error_state, ret))
        {
            log_err("ctrl: tcp: could not answer: %r", (ya_result)ret);
        }
    }

    return (ya_result)ret;
}

static inline ya_result
ctrl_tcp_reply_error(message_data *mesg, int sockfd, u16 error_code)
{
    ssize_t ret;
    if(ISOK(ret = message_make_error_and_reply_tcp_with_default_minimum_throughput(mesg, error_code, sockfd)))
    {
        error_state_clear_locked(&ctrl_tcp_reply_error_state, NULL, 0, NULL);
    }
    else
    {
        if(error_state_log_locked(&ctrl_tcp_reply_error_state, ret))
        {
            log_err("ctrl: tcp: could not answer: %r", (ya_result)ret);
        }
    }

    return (ya_result)ret;
}

void
ctrl_set_listen(host_address* hosts)
{
    if(g_ctrl_config.listen != NULL)
    {
        host_address_delete_list(g_ctrl_config.listen);
    }

    g_ctrl_config.listen = hosts;
}

host_address*
ctrl_get_listen()
{
    return g_ctrl_config.listen;
}

void
ctrl_set_enabled(bool b)
{
    g_ctrl_config.enabled = b;
}

bool
ctrl_get_enabled()
{
    return g_ctrl_config.enabled;
}



ya_result
ctrl_message_process(message_data *mesg)
{
    ya_result ret;

    bool received_query = message_isquery(mesg);

    if(ISOK(ret = message_process(mesg)))
    {
        switch(message_get_query_class(mesg))
        {
            case CLASS_CTRL:
            {
                ctrl_query_process(mesg);
                break;
            } // ctrl class CTRL

            default:
            {
                log_warn("ctrl [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : unsupported class",
                         ntohs(message_get_id(mesg)),
                         message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg),
                         message_get_sender_sa(mesg));

                message_set_status(mesg, FP_CLASS_NOTFOUND);
                message_transform_to_signed_error(mesg);

                break;
            }
        } // switch(class)
    }
    else // an error occurred : no query to be done at all
    {
        log_warn("ctrl [%04hx] from %{sockaddr} error %i : %r", ntohs(message_get_id(mesg)), message_get_sender_sa(mesg), message_get_status(mesg), ret);

        if((ret == INVALID_MESSAGE) && (g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE))
        {
            log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, message_get_buffer(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_BUFFER);
        }

        if((ret != INVALID_MESSAGE) && (((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0) || message_get_status(mesg) != RCODE_FORMERR) && received_query )
        {
            if(!message_has_tsig(mesg) && (message_get_status(mesg) != FP_RCODE_NOTAUTH))
            {
                message_transform_to_error(mesg);
            }

            ret = SUCCESS;
        }
        else
        {
            ret = SUCCESS_DROPPED;
        }
    }

    return ret;
}

#endif // HAS_CTRL

/** @} */

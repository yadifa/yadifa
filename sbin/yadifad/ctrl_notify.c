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

/**-----------------------------------------------------------------------------
 * @defgroup server
 * @ingroup yadifad
 * @brief server
 *
 *  Handles queries made in the CH class (ie: version.*)
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "server_config.h"

#include <dnscore/file_output_stream.h>
#include <dnscore/logger.h>
#include <dnscore/rfc.h>
#include <dnscore/ctrl_rfc.h>
#include <dnscore/threaded_queue.h>

#include <dnsdb/zdb_zone.h>
#include <dnscore/format.h>
#include <dnscore/dns_packet_writer.h>

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "confs.h"
#include "signals.h"
#include <dnscore/acl.h>

#include "ctrl_query_message.h"
#include "ctrl_query_axfr.h"
#include "ctrl.h"

#include "database_service.h"

extern logger_handle_t *g_server_logger;

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING

ya_result ctrl_notify_process(dns_message_t *mesg)
{
    ya_result return_value = SUCCESS;

    log_info("CTRL NOTIFY (%04hx) %{dnsname} %{dnstype}", ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg));

    message_set_answer(mesg);

#if ZDB_HAS_ACL_SUPPORT
    if(ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac.allow_notify)))
    {
        log_info("control: notify: not authorised");

        message_set_status(mesg, FP_NOTIFY_REJECTED);

        return ACL_NOTIFY_REJECTED;
    }
#endif

    if(message_get_query_class(mesg) == CLASS_CTRL)
    {
        if(message_get_query_type(mesg) == TYPE_SOA)
        {
            /*
             * This is a notification that the primary has a new zone configuration
             * (new zone or zone update)
             *
             * Ask for an AXFR CTRL for the zone.
             */

            ctrl_query_axfr_enqueue_from_message(mesg);
        }
#if 0
        else if(message_get_query_type(mesg) == TYPE_AXFR)
        {
            /*
             * This is a notification from a secondary that wants an update on all the dynamic zone
             * it is supposed to know:
             * 
             * look for all dynamic zones
             * send a notify
             */
        }
#endif
    }
    else
    {
        return_value = MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    return return_value;
}

#endif // HAS_CTRL_DYNAMIC_PROVISIONING

/** @} */

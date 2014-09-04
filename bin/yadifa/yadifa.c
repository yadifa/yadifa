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
#define SERVER_C_
#define MODULE_MSG_HANDLE g_client_logger

#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <ctype.h>

#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/message.h>
#include <dnscore/sys_types.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/ctrl-rfc.h>
#include <dnscore/packet_writer.h>

#include <dnslg/dns.h>

#include "yadifa-config.h"
#include "yadifa.h"
#include "query-result.h"

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

logger_handle *g_client_logger;

extern config_main_settings_s       g_yadifa_main_settings;

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** @brief Function ...
 *
 *  ...
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */
static long
time_diff_in_msec(const struct timeval *tv1, const struct timeval *tv2)
{
//    if (tv1 == NULL || tv2 == NULL)
//        error_quit("One or both timeval are NULL");

    return( (tv1->tv_sec * 1000 + tv1->tv_usec / 1000) - (tv2->tv_sec * 1000 + tv2->tv_usec / 1000));
}


static int
time_now(struct timeval *tv)
{
    if (tv == NULL)
    {
        return NOK;
    }

    if (-1 == gettimeofday(tv, NULL))
    {
        //        error_msg("time now: %s\n", strerror(errno));
        return NOK;
    }

    return OK;
}


/// @todo 20140521 gve -- still needs  export DNSCORE_TCP_FLAGS=nodelay,nocork
ya_result
yadifa_run()
{
//    uint16_t                                                          i = 0;
    ya_result                                              return_code = OK;

    /*    ------------------------------------------------------------    */

#ifdef DEBUG
    /// @TODO must be removed in production -- gery
    log_memdump_set_layout(LOG_MEMDUMP_LAYOUT_GERY);
    config_print(termout);
    log_debug("YADIFA RUN");

    formatln("YADIFA --END");
    flushout();
#endif

    message_data                                                       mesg;
    struct timeval                                          query_time_send;
    struct timeval                                      query_time_received;

    u8                                                          go_tcp = OK;


     /*    ------------------------------------------------------------    */


    /* Give ID from config or randomized */
    u16 id                = dns_new_id();
    u16 qtype             = htons(g_yadifa_main_settings.qtype);
//    u16 qclass            = htons(g_yadifa_main_settings.qclass);
    u8 *qname             = g_yadifa_main_settings.qname;


//    u16 question_mode     = g_yadifa_main_settings.question_mode;
    u16 question_mode     = 0;


    // prepare root tld
    char *root = ".";
    u8 root_fqdn[MAX_DOMAIN_LENGTH];
    cstr_to_dnsname(root_fqdn, root);

#if DEBUG
    memset(&mesg, 0xff, sizeof(message_data));
    
    formatln("CTRL START");
    formatln("QTYPE: %{dnstype}", &qtype);
#endif // DEBUG

    switch(qtype)
    {
        case TYPE_CTRL_ZONEFREEZE:
        case TYPE_CTRL_ZONEUNFREEZE:
        case TYPE_CTRL_ZONERELOAD:
        case TYPE_CTRL_ZONECFGRELOAD:
        {
            message_make_query(&mesg, id, root_fqdn, qtype, CLASS_CTRL);

            packet_writer pw;
            packet_writer_init(&pw, mesg.buffer, mesg.send_length, sizeof(mesg.buffer));

            packet_writer_add_record(&pw, root_fqdn, qtype, CLASS_CTRL, 0, qname, dnsname_len(qname));
            MESSAGE_SET_AN(mesg.buffer, htons(1));

            mesg.send_length = pw.packet_offset;

            break;
        }
        /* the same as zone freeze, but without extra information */
        case TYPE_CTRL_ZONEFREEZEALL:
        {
            message_make_query(&mesg, id, root_fqdn, TYPE_CTRL_ZONEFREEZE, CLASS_CTRL);

            break;
        }
        /* the same as zone freeze, but without extra information */
        case TYPE_CTRL_ZONEUNFREEZEALL:
        {
            message_make_query(&mesg, id, root_fqdn, TYPE_CTRL_ZONEUNFREEZE, CLASS_CTRL);

            break;
        }
        /* the same as zone unfreeze, but without extra information */
        case TYPE_CTRL_ZONECFGRELOADALL:
        {
            message_make_query(&mesg, id, root_fqdn, TYPE_CTRL_ZONECFGRELOAD, CLASS_CTRL);

            break;
        }
        case TYPE_CTRL_ZONESYNC:
        {
//            char buffer[256];
//            bool clean = g_yadifa_main_settings.clean; // @todo 20140829 gve -- still needs to be implemented
//            formatln("CLEAN: %d\n", clean);


            break;
        }
        case TYPE_CTRL_SRVQUERYLOG:
        {

            break;
        }
        // case TYPE_CTRL_LOGREOPEN:
        // case TYPE_CTRL_SHUTDOWN
        default:
        {
            message_make_query(&mesg, id, root_fqdn, qtype, CLASS_CTRL);

            break;
        }
    }


    flushout();

    MESSAGE_SET_OP(mesg.buffer, OPCODE_CTRL);
     
    // TSIG ...
    
    return_code = message_sign_query_by_name(&mesg, g_yadifa_main_settings.tsig_key_name);
    
    message_update_tcp_length(&mesg);

    /* Set timer before send */
    time_now(&query_time_send);
    /* fix the tcp length */

    u8 connect_timeout = 3;
    if (FAIL(return_code = message_query_tcp_with_timeout(&mesg, g_yadifa_main_settings.server, connect_timeout)))
    {
        formatln("wrong %{hostaddr} : ret %r", g_yadifa_main_settings.server, return_code); /// @todo 20140630 gve -- better logging
        return return_code;
    }

    /* Stop timer after received */
    time_now(&query_time_received);


//    u16 protocol         = g_yadifa_main_settings.protocol;
    u16 protocol         = 0;
    if (FAIL(return_code = check_query_result(id, protocol, question_mode, &mesg, &go_tcp)))
    {
        return return_code;
    }
//    formatln("CTRL STOP");
    flushout();


    // 3. SHOW THE RESULT
    if (FAIL(return_code = view_query_result(&mesg, time_diff_in_msec(&query_time_received, &query_time_send), 0)))
    {
        return return_code;
    }

    return return_code;
}


    /*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/


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
/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include <dnscore/rfc.h>
#include <dnscore/logger.h>
#include <dnscore/packet_reader.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/random.h>
#include <dnscore/format.h>
#include <dnscore/xfr_copy.h>
#include <dnscore/host_address.h>
#include <dnscore/fdtools.h>
#include <dnscore/message.h>
#include <dnscore/chroot.h>

#include <dnsdb/zdb_zone.h>
#include <dnsdb/journal.h>
#include <dnsdb/zdb-zone-answer-axfr.h>

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "axfr.h"
#include "confs.h"
#include "server.h"


/**
 * 
 * Handle an AXFR query from a slave.
 *
 * @TODO: Add a limit between two AXFR snapshots (?)
 *
 * If we don't do this many slaves could call with a small interval asking a just-dynupdated snapshot.
 * If we do it the slaves will be only a few steps behind and the next notification/ixfr will bring them up to date.
 *
 * @TODO: Set the AXFR storage path
 */
ya_result
axfr_process(message_data *mesg)
{
    /*
     * Start an AXFR "writer" thread
     * Give it the tcp fd
     * It will store the AXFR for the current database snapshot on the disk if it does not exist yet (writers blocked)
     * It will then open the stored file and stream it to the tcp fd (writers freed)
     * ACL/TSIG is not taken in account yet.
     */

    zdb_zone *zone;

    u8 *fqdn = mesg->qname;

    dnsname_vector fqdn_vector;

    dnsname_to_dnsname_vector(fqdn, &fqdn_vector);

    fqdn += dnsname_len(fqdn) + 2; /* ( 2 because of the type ) */

    u16 qclass = GET_U16_AT(*fqdn);
    u16 rcode;

    if( ((zone = zdb_zone_find(g_config->database, &fqdn_vector, qclass)) != NULL) &&
            ZDB_ZONE_VALID(zone) )
    {
#if HAS_ACL_SUPPORT
        access_control *ac = (access_control*)zone->extension;

        if(!ACL_REJECTED(acl_check_access_filter(mesg, &ac->allow_transfer)))
        {
#endif
            log_info("axfr: %{dnsname}: scheduling axfr", mesg->qname);
            
            /*
             * Get the zone AXFR
             *   If not exist create it and start sending back while writing (implies two threads)
             *   else simply send back
             */
            
            // xfr_path is known, dnssec_set_xfr_path set it
            // zone is obviously needed
            // mesg is needed to match query, TSIG, ...
            // zdb_zone_answer_axfr(zone, mesg, thread_pool, g_config->axfr_max_packet_size, g_config->axfr_max_record_by_packet, g_config->axfr_compress_packets);
            // this is mostly background, so 

            zdb_zone_answer_axfr(zone, mesg, NULL, NULL, g_config->xfr_path, g_config->axfr_max_packet_size, g_config->axfr_max_record_by_packet, g_config->axfr_compress_packets);
            
            return SUCCESS;
#if HAS_ACL_SUPPORT
        }
        else
        {
            /* notauth */

            log_info("axfr: %{dnsname}: not authorised", mesg->qname);

            rcode = FP_XFR_REFUSED;
        }
#endif
    }
    else
    {
        /* zone not found */

        log_err("axfr: %{dnsname}: zone not found", mesg->qname);

        if(zone == NULL)
        {
            rcode = FP_NOZONE_FOUND;
        }
        else
        {
            rcode = FP_INVALID_ZONE;
        }
    }

    message_make_error(mesg, rcode);

    tcp_send_message_data(mesg);

    yassert((mesg->sockfd < 0)||(mesg->sockfd >2));

    close_ex(mesg->sockfd);

    return SUCCESS;
}

/**
 *
 * Send an AXFR query to a master and handle the answer (loads the zone).
 *
 * @TODO: Set the AXFR storage path
 */
ya_result
axfr_query(const host_address *servers, const u8 *origin, u32* out_loaded_serial)
{
    /*
     * Background:
     *
     * Build an axfr query message
     * Send it to the master
     * Wait for the answer
     * Copy the answer in a file
     * Load the zone from the file
     *
     * Foreground:
     *
     * Attach the zone to the database.
     */

    /*
     * AXFR query
     */

    ya_result return_value;

    char data_path[PATH_MAX];

    if(FAIL(return_value = xfr_copy_mkdir_data_path(data_path, sizeof(data_path), g_config->xfr_path, origin)))
    {
        log_err("axfr: unable to create directory '%s' for %{dnsname}: %r", data_path, origin, return_value);
        
        return return_value;
    }

    random_ctx rndctx = thread_pool_get_random_ctx();

    /**
     * Create the AXFR query packet
     */

    message_data axfr_query;
    message_make_query(&axfr_query, (u16)random_next(rndctx), origin, TYPE_AXFR, CLASS_IN);
#if HAS_TSIG_SUPPORT
    if(servers->tsig != NULL)
    {
        log_info("axfr: %{dnsname}: transfer will be signed with key '%{dnsname}'", origin, servers->tsig->name);

        message_sign_query(&axfr_query, servers->tsig);
    }
#endif
    message_update_tcp_length(&axfr_query);
    axfr_query.received = axfr_query.send_length;

    /*
     * connect & send
     */

    input_stream is;
    output_stream os;

    // connect
    
    if(ISOK(return_value = tcp_input_output_stream_connect_host_address(servers, &is, &os, g_config->xfr_connect_timeout)))
    {
        // send
        
        if(ISOK(return_value = output_stream_write(&os, &axfr_query.buffer_tcp_len[0], axfr_query.send_length + 2)))
        {
            output_stream_flush(&os);

            int fd = fd_input_stream_get_filedescriptor(&is);

            tcp_set_sendtimeout(fd, 30, 0);
            tcp_set_recvtimeout(fd, 30, 0);

            /** @todo: disables updates/ixfr for the zone */

            /* delete ix files */

            journal_truncate(origin, g_config->xfr_path);
            
            xfr_copy_args xfr;
            xfr.is = &is;
            xfr.origin = origin;
            xfr.message = &axfr_query;
            xfr.current_serial = 0;
            xfr.flags = XFR_ALLOW_AXFR;
            
            input_stream xfris;
            if(ISOK(return_value = xfr_input_stream_init(&xfr, &xfris)))
            {
                if(ISOK(return_value = xfr_copy(&xfris, g_config->xfr_path)))
                {
                    if(out_loaded_serial != NULL)
                    {
                        *out_loaded_serial = xfr_input_stream_get_serial(&xfris);
                    }
                }
                else
                {
                    log_debug("axfr: %{dnsname}: AXFR stream copy failed: %r", origin, return_value);
                }
            }
            else
            {
                log_debug("axfr: %{dnsname}: AXFR stream copy init failed: %r", origin, return_value);
            }

            output_stream_close(&os);
            output_stream_close(&is);
        }
    }

    return return_value;
}

/** @} */

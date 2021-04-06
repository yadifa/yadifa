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

/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

#include "server-config.h"

#include <stdio.h>
#include <stdlib.h>

#include <dnscore/rfc.h>
#include <dnscore/logger.h>
#include <dnscore/packet_reader.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/random.h>
#include <dnscore/host_address.h>
#include <dnscore/fdtools.h>
#include <dnscore/message.h>
#include <dnscore/chroot.h>
#include <dnscore/xfr_input_stream.h>

#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb-zone-answer-axfr.h>
#include <dnsdb/xfr_copy.h>
#include <dnsdb/zdb-zone-path-provider.h>

#define ZDB_JOURNAL_CODE 1
#include <dnsdb/journal.h>

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "axfr.h"
#include "confs.h"
#include "server.h"

extern struct thread_pool_s *server_disk_thread_pool;

/**
 * 
 * Handle an AXFR query from a slave.
 *
 * If we don't do this many slaves could call with a small interval asking a just-dynupdated snapshot.
 * If we do it the slaves will be only a few steps behind and the next notification/ixfr will bring them up to date.
*/
#if DNSCORE_HAS_TCP_MANAGER
ya_result
axfr_process(message_data *mesg, tcp_manager_socket_context_t *sctx)
#else
ya_result
axfr_process(message_data *mesg, int sockfd)
#endif
{
    /*
     * Start an AXFR "writer" thread
     * Give it the tcp fd
     * It will store the AXFR for the current database snapshot on the disk if it does not exist yet (writers blocked)
     * It will then open the stored file and stream it to the tcp fd (writers freed)
     * ACL/TSIG is not taken in account yet.
     */

    zdb_zone *zone;

    const u8 *fqdn = message_get_canonised_fqdn(mesg);
    u32 fqdn_len = dnsname_len(fqdn);

    if(fqdn_len > MAX_DOMAIN_LENGTH)
    {
#if DNSCORE_HAS_TCP_MANAGER
        tcp_manager_context_release(sctx);
        tcp_manager_close(sctx);
#endif
        return DOMAIN_TOO_LONG;
    }

    u16 rcode;

    if((zone = zdb_acquire_zone_read_from_fqdn(g_config->database, fqdn)) != NULL)
    {
        if(zdb_zone_valid(zone))
        {
#if ZDB_HAS_ACL_SUPPORT
            access_control *ac = zone->acl;

            if(!ACL_REJECTED(acl_check_access_filter(mesg, &ac->allow_transfer)))
            {
#endif
                log_info("axfr: %{dnsname}: scheduling axfr answer to %{sockaddr}", message_get_canonised_fqdn(mesg), message_get_sender(mesg));

                /*
                 * This is an asynchronous call
                 * 
                 * Get the zone AXFR
                 *   If not exist create it and start sending back while writing (implies two threads)
                 *   else simply send back
                 */

#if DNSCORE_HAS_TCP_MANAGER
                zdb_zone_answer_axfr(zone, mesg, sctx, NULL, server_disk_thread_pool, g_config->axfr_max_packet_size, g_config->axfr_max_record_by_packet, g_config->axfr_compress_packets);
                tcp_manager_context_release(sctx); // sctx has been acquired by the xfr call
#else
                zdb_zone_answer_axfr(zone, mesg, sockfd, NULL, server_disk_thread_pool, g_config->axfr_max_packet_size, g_config->axfr_max_record_by_packet, g_config->axfr_compress_packets);
#endif
                zdb_zone_release(zone);

                return SUCCESS;
#if HAS_ACL_SUPPORT
            }
            else
            {
                /* notauth */

                if(message_has_tsig(mesg))
                {
                    log_notice("axfr: %{dnsname}: not authorised (%{sockaddr} key %{dnsname})", message_get_canonised_fqdn(mesg), message_get_sender(mesg), message_tsig_get_name(mesg));
                }
                else
                {
                    log_notice("axfr: %{dnsname}: not authorised (%{sockaddr})", message_get_canonised_fqdn(mesg), message_get_sender(mesg));
                }

                rcode = FP_XFR_REFUSED;
            }
#endif
        }
        else
        {
            rcode = FP_INVALID_ZONE;
        }
        
        zdb_zone_release(zone);
    }
    else
    {
        /* zone not found */

        zone_desc_s *zone_desc;
        if((zone_desc = zone_acquirebydnsname(message_get_canonised_fqdn(mesg))) != NULL)
        {
            zone_release(zone_desc);
            log_warn("axfr: %{dnsname}: zone not loaded (%{sockaddr})", message_get_canonised_fqdn(mesg), message_get_sender(mesg));

            rcode = FP_RCODE_SERVFAIL;
        }
        else
        {
            log_notice("axfr: %{dnsname}: no such zone (%{sockaddr})", message_get_canonised_fqdn(mesg), message_get_sender(mesg));

            rcode = FP_NOZONE_FOUND;
        }
    }

    message_make_error(mesg, rcode);

#if DNSCORE_HAS_TCP_MANAGER
    int sockfd = tcp_manager_socket(sctx);
#endif

    ya_result send_ret;

#if DNSCORE_HAS_TCP_MANAGER
    send_ret = message_send_tcp(mesg, sockfd);
#else
    send_ret = message_update_length_send_tcp_with_default_minimum_throughput(mesg, sockfd);
#endif

    if(ISOK(send_ret))
    {
#if DNSCORE_HAS_TCP_MANAGER
        tcp_manager_write_update(sctx, send_ret);
#endif
    }
    else
    {
        log_err("axfr: %{dnsname}: could not send error message: %r (%{sockaddr})", send_ret, message_get_sender(mesg));
    }

    yassert((sockfd < 0)||(sockfd >2));

#if DNSCORE_HAS_TCP_MANAGER
    tcp_manager_context_release(sctx);
#else
    shutdown(sockfd, SHUT_RDWR);
    close_ex(sockfd);
#endif

    return SUCCESS;
}

/**
 *
 * Send an AXFR query to a master and handle the answer (downloads the zone).
 */
ya_result
axfr_query_ex(const host_address *servers, const u8 *origin, u32* out_loaded_serial, u32* out_loaded_refresh)
{
    /*
     * AXFR query
     */

    ya_result return_value;

    char data_path[PATH_MAX];
    
    log_info("axfr: %{dnsname}: querying servers", origin);
    
    if(FAIL(return_value = zdb_zone_path_get_provider()(origin, data_path, sizeof(data_path), ZDB_ZONE_PATH_PROVIDER_AXFR_PATH|ZDB_ZONE_PATH_PROVIDER_MKDIR)))
    {
        log_err("axfr: %{dnsname}: unable to create directory '%s' : %r", origin, data_path, return_value);
        return return_value;
    }

    random_ctx rndctx = thread_pool_get_random_ctx();

    /**
     * Create the AXFR query packet
     */

    message_data_with_buffer axfr_query_buff;
    message_data_with_buffer_init(&axfr_query_buff);
    message_data *axfr_query = message_data_with_buffer_init(&axfr_query_buff);
    message_make_query(axfr_query, (u16)random_next(rndctx), origin, TYPE_AXFR, CLASS_IN);
#if DNSCORE_HAS_TSIG_SUPPORT
    if(servers->tsig != NULL)
    {
        log_info("axfr: %{dnsname}: transfer will be signed with key '%{dnsname}'", origin, servers->tsig->name);

        message_sign_query(axfr_query, servers->tsig);
    }
#endif

    /*
     * connect & send
     */

    input_stream is;
    output_stream os;

    // connect
    
    if(ISOK(return_value = tcp_input_output_stream_connect_host_address(servers, &is, &os, g_config->xfr_connect_timeout)))
    {
        // send

        if(ISOK(return_value = message_write_tcp(axfr_query, &os)))
        {
            output_stream_flush(&os);

            int fd = fd_input_stream_get_filedescriptor(&is);

            tcp_set_sendtimeout(fd, 30, 0);
            tcp_set_recvtimeout(fd, 30, 0);
            
            log_info("axfr: %{dnsname}: truncating journal", origin, data_path, return_value);

            /* delete ix files */

            journal_truncate(origin);
            
            zdb_zone *zone = zdb_acquire_zone_write_lock_from_fqdn(g_config->database, origin, ZDB_ZONE_MUTEX_XFR);
            if(zone != NULL)
            {
                if(!zdb_zone_isinvalid(zone))
                {
#if ZDB_ZONE_HAS_JNL_REFERENCE
                    if(zone->journal != NULL)
                    {
                        journal_close(zone->journal);
                    }
#endif
                    bool have_writing_rights = !zdb_zone_get_set_dumping_axfr(zone);

                    if(!have_writing_rights)
                    {
                        // zone is already being dumped
                        log_err("axfr: %{dnsname}: zone already marked as being dumped", origin);
                    }
                }
                
                zdb_zone_release_unlock(zone, ZDB_ZONE_MUTEX_XFR);
            }

            xfr_copy_flags xfr_flags = XFR_ALLOW_AXFR | ((g_config->axfr_strict_authority)? 0: XFR_LOOSE_AUTHORITY);

            input_stream xfris;
            if(ISOK(return_value = xfr_input_stream_init(&xfris,
                                                         origin,
                                                         &is,
                                                         axfr_query,
                                                         0,
                                                         xfr_flags)))
            {
                if(ISOK(return_value = xfr_copy(&xfris, g_config->xfr_path, FALSE)))
                {
                    return_value = xfr_input_stream_get_type(&xfris);

                    if(out_loaded_serial != NULL)
                    {
                        *out_loaded_serial = xfr_input_stream_get_serial(&xfris);
                    }
                    if(out_loaded_refresh != NULL)
                    {
                        *out_loaded_refresh = xfr_input_stream_get_refresh(&xfris);
                    }
                }
                else
                {
                    log_warn("axfr: %{dnsname}: AXFR stream copy in '%s' failed: %r", origin, data_path, return_value);
                }
                
                input_stream_close(&xfris);
            }
            else
            {
                log_warn("axfr: %{dnsname}: AXFR stream copy init failed: %r", origin, return_value);
            }

            output_stream_close(&os);
            output_stream_close(&is);
            
            zone = zdb_acquire_zone_write_lock_from_fqdn(g_config->database, origin, ZDB_ZONE_MUTEX_XFR);
            if(zone != NULL)
            {
                if(!zdb_zone_isinvalid(zone))
                {
                    zdb_zone_clear_dumping_axfr(zone);
                }
                
                zdb_zone_release_unlock(zone, ZDB_ZONE_MUTEX_XFR);
            }
        }
        else
        {
            log_warn("axfr: %{dnsname}: AXFR query to %{hostaddr} failed: %r", origin, servers, return_value);
        }
    }
    else
    {
        log_warn("axfr: %{dnsname}: AXFR stream connection to %{hostaddr} failed: %r", origin, servers, return_value);
    }

    return return_value;
}

/**
 *
 * Send an AXFR query to a master and handle the answer (downloads the zone).
 */
ya_result
axfr_query(const host_address *servers, const u8 *origin, u32* out_loaded_serial)
{
    ya_result ret = axfr_query_ex(servers, origin, out_loaded_serial, NULL);
    return ret;
}

/** @} */

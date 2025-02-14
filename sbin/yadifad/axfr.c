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
 * @defgroup ### #######
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "server_config.h"

#include <stdio.h>
#include <stdlib.h>

#include <dnscore/rfc.h>
#include <dnscore/logger.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/random.h>
#include <dnscore/host_address.h>
#include <dnscore/fdtools.h>
#include <dnscore/dns_message.h>
#include <dnscore/xfr_input_stream.h>
#include <dnscore/tcp_manager2.h>

#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_answer_axfr.h>
#include <dnsdb/xfr_copy.h>
#include <dnsdb/zdb_zone_path_provider.h>

#define ZDB_JOURNAL_CODE 1
#include <dnsdb/journal.h>

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "axfr.h"
#include "confs.h"
#include "server.h"

static struct thread_pool_s *server_disk_thread_pool = NULL;
static struct thread_pool_s *server_network_thread_pool = NULL;

ya_result                    axfr_process_init()
{
    if(server_disk_thread_pool == NULL)
    {
        server_disk_thread_pool = thread_pool_init_ex(4, 64, "diskio");

        if(server_disk_thread_pool == NULL)
        {
            log_warn("disk thread pool init failed");

            return THREAD_CREATION_ERROR;
        }
    }

    if(server_network_thread_pool == NULL)
    {
        server_network_thread_pool = thread_pool_init_ex(4, 64, "netio");

        if(server_network_thread_pool == NULL)
        {
            log_warn("network thread pool init failed");

            return THREAD_CREATION_ERROR;
        }
    }

    return SUCCESS;
}

ya_result axfr_process_finalise()
{
    ya_result ret0 = SUCCESS;
    ya_result ret1 = SUCCESS;
    if(server_disk_thread_pool != NULL)
    {
        struct thread_pool_s *old_server_disk_thread_pool = server_disk_thread_pool;
        server_disk_thread_pool = NULL;
        thread_pool_stop(old_server_disk_thread_pool);
        ret0 = thread_pool_destroy(old_server_disk_thread_pool);
    }

    if(server_network_thread_pool != NULL)
    {
        struct thread_pool_s *old_server_network_thread_pool = server_network_thread_pool;
        server_network_thread_pool = NULL;
        thread_pool_stop(old_server_network_thread_pool);
        ret1 = thread_pool_destroy(old_server_network_thread_pool);
    }

    if(FAIL(ret0))
    {
        return ret0;
    }
    else
    {
        return ret1;
    }
}

/**
 *
 * Handle an AXFR query from a secondary.
 *
 * If we don't do this many secondaries could call with a small interval asking a just-dynupdated snapshot.
 * If we do it the secondaries will be only a few steps behind and the next notification/ixfr will bring them up to
 * date.
 */

ya_result axfr_process(dns_message_t *mesg, tcp_manager_channel_t *tmc)
{
    /*
     * Start an AXFR "writer" thread
     * Give it the tcp fd
     * It will store the AXFR for the current database snapshot on the disk if it does not exist yet (writers blocked)
     * It will then open the stored file and stream it to the tcp fd (writers freed)
     * ACL/TSIG is not taken in account yet.
     */

    zdb_zone_t    *zone;

    const uint8_t *fqdn = dns_message_get_canonised_fqdn(mesg);
    uint32_t       fqdn_len = dnsname_len(fqdn);

    if(fqdn_len > DOMAIN_LENGTH_MAX)
    {
        return DOMAIN_TOO_LONG;
    }

    uint16_t rcode;

    if((zone = zdb_acquire_zone_read_from_fqdn(g_config->database, fqdn)) != NULL)
    {
        if(zdb_zone_valid(zone))
        {
#if ZDB_HAS_ACL_SUPPORT
            access_control_t *ac = zone->acl;

            if(!ACL_REJECTED(acl_check_access_filter(mesg, &ac->allow_transfer)))
            {
#endif
                log_info("axfr: %{dnsname}: scheduling axfr answer to %{sockaddr}", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender(mesg));

                /*
                 * This is an asynchronous call
                 *
                 * Get the zone AXFR
                 *   If not exist create it and start sending back while writing (implies two threads)
                 *   else simply send back
                 */

                // zdb_zone_answer_axfr(zone, mesg, tmc, server_network_thread_pool, server_disk_thread_pool,
                // g_config->axfr_max_packet_size, g_config->axfr_max_record_by_packet,
                // g_config->axfr_compress_packets);
                zdb_zone_answer_axfr(zone, mesg, tmc, NULL, server_disk_thread_pool, g_config->axfr_max_packet_size, g_config->axfr_max_record_by_packet, g_config->axfr_compress_packets);

                zdb_zone_release(zone);

                return SUCCESS;
#if DNSCORE_HAS_ACL_SUPPORT
            }
            else
            {
                /* notauth */

                if(dns_message_has_tsig(mesg))
                {
                    log_notice("axfr: %{dnsname}: not authorised (%{sockaddr} key %{dnsname})", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender(mesg), dns_message_tsig_get_name(mesg));
                }
                else
                {
                    log_notice("axfr: %{dnsname}: not authorised (%{sockaddr})", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender(mesg));
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

        zone_desc_t *zone_desc;
        if((zone_desc = zone_acquirebydnsname(dns_message_get_canonised_fqdn(mesg))) != NULL)
        {
            zone_release(zone_desc);
            log_warn("axfr: %{dnsname}: zone not loaded (%{sockaddr})", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender(mesg));

            rcode = FP_RCODE_SERVFAIL;
        }
        else
        {
            log_notice("axfr: %{dnsname}: no such zone (%{sockaddr})", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender(mesg));

            rcode = FP_NOZONE_FOUND;
        }
    }

    dns_message_make_error(mesg, rcode);

    ya_result send_ret;

    send_ret = tcp_manager_channel_send(tmc, mesg);

    if(FAIL(send_ret))
    {
        log_err("axfr: %{dnsname}: could not send error message: %r (%{sockaddr})", dns_message_get_canonised_fqdn(mesg), send_ret, dns_message_get_sender(mesg));
    }

    return SUCCESS;
}

/**
 * Sends an AXFR query to a primary and handle the answer (downloads the zone).
 */

ya_result axfr_query_ex(const host_address_t *servers, const uint8_t *origin, uint32_t *out_loaded_serial, uint32_t *out_loaded_refresh)
{
    /*
     * AXFR query
     */

    ya_result ret;
    char      data_path[PATH_MAX];

    if(host_address_is_any(servers))
    {
        return INVALID_ARGUMENT_ERROR;
    }

    log_info("axfr: %{dnsname}: querying servers", origin);

    if(FAIL(ret = zdb_zone_path_get_provider()(origin, data_path, sizeof(data_path), ZDB_ZONE_PATH_PROVIDER_AXFR_PATH | ZDB_ZONE_PATH_PROVIDER_MKDIR)))
    {
        log_err("axfr: %{dnsname}: unable to create directory '%s' : %r", origin, data_path, ret);
        return ret;
    }

    random_ctx_t rndctx = thread_pool_get_random_ctx();

    /**
     * Create the AXFR query packet
     */

    dns_message_with_buffer_t axfr_query_buff;
    dns_message_data_with_buffer_init(&axfr_query_buff);
    dns_message_t *axfr_query = dns_message_data_with_buffer_init(&axfr_query_buff);
    dns_message_make_query(axfr_query, (uint16_t)random_next(rndctx), origin, TYPE_AXFR, CLASS_IN);
#if DNSCORE_HAS_TSIG_SUPPORT
    if(servers->tsig != NULL)
    {
        log_info("axfr: %{dnsname}: transfer will be signed with key '%{dnsname}'", origin, servers->tsig->name);
        dns_message_sign_query(axfr_query, servers->tsig);
    }
#endif

    /*
     * connect & send
     */

    input_stream_t  is;
    output_stream_t os;

    // connect

    host_address_t *transfer_source = zone_transfer_source_copy(origin);
    host_address_t *current_transfer_source;
    current_transfer_source = transfer_source;

    /// @note 20230612 edf -- TLS should be set here
    /// @note 20230612 edf -- we need a pool for outgoing connections

    ret = zone_transfer_source_tcp_connect(servers, &current_transfer_source, &is, &os, g_config->xfr_connect_timeout);

    if(ISOK(ret))
    {
        // send

        if(ISOK(ret = dns_message_write_tcp(axfr_query, &os)))
        {
            output_stream_flush(&os);

            if(is_fd_input_stream(&is))
            {
                int fd = fd_input_stream_get_filedescriptor(&is);
                tcp_set_sendtimeout(fd, 30, 0);
                tcp_set_recvtimeout(fd, 30, 0);
            }

            log_info("axfr: %{dnsname}: truncating journal", origin);

            /* delete ix files */

            journal_truncate(origin);

            zdb_zone_t *zone = zdb_acquire_zone_write_lock_from_fqdn(g_config->database, origin, ZDB_ZONE_MUTEX_XFR);
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

            xfr_copy_flags xfr_flags = XFR_ALLOW_AXFR | ((g_config->axfr_strict_authority) ? 0 : XFR_LOOSE_AUTHORITY);

            input_stream_t xfris;
            if(ISOK(ret = xfr_input_stream_init(&xfris, origin, &is, axfr_query, 0, xfr_flags)))
            {
                if(ISOK(ret = xfr_copy(&xfris, g_config->xfr_path, false)))
                {
                    ret = xfr_input_stream_get_type(&xfris);

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
                    log_warn("axfr: %{dnsname}: AXFR stream copy in '%s' failed: %r", origin, data_path, ret);
                }

                input_stream_close(&xfris);
            }
            else
            {
                log_warn("axfr: %{dnsname}: AXFR stream copy init failed: %r", origin, ret);
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
            log_warn("axfr: %{dnsname}: AXFR query to %{hostaddr} failed: %r", origin, servers, ret);

            output_stream_close(&os);
            output_stream_close(&is);
        }
    }
    else
    {
        if((transfer_source != NULL) && (current_transfer_source == NULL))
        {
            log_warn("axfr: %{dnsname}: %{hostaddr}: could not find a valid bind point to query a transfer from", origin, servers);
        }
        else
        {
            log_info("axfr: %{dnsname}: %{hostaddr}: stream connection failed: %r", origin, servers, ret);
        }
    }

    if(transfer_source != NULL)
    {
        host_address_delete_list(transfer_source);
    }

    return ret;
}

/**
 *
 * Send an AXFR query to a primary and handle the answer (downloads the zone).
 */
ya_result axfr_query(const host_address_t *servers, const uint8_t *origin, uint32_t *out_loaded_serial)
{
    ya_result ret = axfr_query_ex(servers, origin, out_loaded_serial, NULL);
    return ret;
}

/** @} */

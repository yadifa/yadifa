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

#include <dnsdb/zdb_zone.h>
#include <dnscore/rfc.h>
#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/random.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/xfr_input_stream.h>
#include <dnscore/serial.h>
#include <dnscore/fdtools.h>
#include <dnscore/thread_pool.h>
#include <dnscore/packet_writer.h>
#if DNSCORE_HAS_TCP_MANAGER
#include <dnscore/tcp_manager.h>
#endif

#include <dnsdb/zdb-zone-journal.h>
#include <dnsdb/zdb-zone-answer-ixfr.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/zdb_utils.h>
#include <dnsdb/zdb-zone-path-provider.h>
#include <dnsdb/xfr_copy.h>

#include "server.h"
#include "ixfr.h"
#include "confs.h"
#include "notify.h"
#include "dnssec-policy.h"
#include "database-service-zone-download.h"

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

/**
 * 
 * Handle an IXFR query from a slave.
 */
#if DNSCORE_HAS_TCP_MANAGER
ya_result
ixfr_process(message_data *mesg, tcp_manager_socket_context_t *sctx)
#else
ya_result
ixfr_process(message_data *mesg, int sockfd)
#endif
{
    /*
     * Start an IXFR "writer" thread
     * Give it the tcp fd
     * It will store the IXFR for the current database snapshot on the disk if it does not exist yet (writers blocked)
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
    
    ya_result return_value = SUCCESS;

    if((zone = zdb_acquire_zone_read_from_fqdn(g_config->database, fqdn)) != NULL)
    {
        if(zdb_zone_valid(zone))
        {
#if ZDB_HAS_ACL_SUPPORT
            access_control *ac = zone->acl;

            if(!ACL_REJECTED(acl_check_access_filter(mesg, &ac->allow_transfer)))
            {
#endif
                /*
                 * Before doing more work, check the serials.
                 */

                u32 query_serial;

                if(ISOK(return_value = message_ixfr_query_get_serial(mesg, &query_serial)))
                {
                    u32 zone_serial;

                    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                    return_value = zdb_zone_getserial(zone, &zone_serial); // zone is locked
                    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

                    if(ISOK(return_value))
                    {                
                        if(serial_lt(query_serial, zone_serial))
                        {
                            // reply with the relevant XFR stream

#if DNSCORE_HAS_TCP_MANAGER
                            zdb_zone_answer_ixfr(zone, mesg, sctx, NULL, NULL, g_config->axfr_max_packet_size, g_config->axfr_max_record_by_packet, g_config->axfr_compress_packets);
                            tcp_manager_context_release(sctx); // sctx has been acquired by the xfr call
#else
                            zdb_zone_answer_ixfr(zone, mesg, sockfd, NULL, NULL, g_config->axfr_max_packet_size, g_config->axfr_max_record_by_packet, g_config->axfr_compress_packets);
#endif
                            
                            zdb_zone_release(zone);

                            return SUCCESS;
                        }
                        else
                        {
                            /* already up-to-date */

                            log_info("ixfr: %{dnsname}: already up-to-date at serial %u", message_get_canonised_fqdn(mesg), zone_serial);

                            // answer with the SOA

                            packet_writer pc;
                            packet_writer_init(&pc, message_get_buffer(mesg), DNS_HEADER_LENGTH + fqdn_len + 2 + 2, message_get_buffer_size(mesg)); // valid use of message_get_buffer_size()

                            const u8 *soa_rdata;
                            u32 soa_ttl;
                            u16 soa_rdata_size;

                            zdb_zone_lock(zone, ZDB_ZONE_MUTEX_XFR);
                            zdb_zone_getsoa_ttl_rdata(zone, &soa_ttl, &soa_rdata_size, &soa_rdata); // zone is locked
                            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_XFR);

                            packet_writer_add_fqdn(&pc, &(message_get_buffer_const(mesg)[DNS_HEADER_LENGTH]));
                            packet_writer_add_u16(&pc, TYPE_SOA);
                            packet_writer_add_u16(&pc, CLASS_IN);
                            packet_writer_add_u32(&pc, ntohl(soa_ttl));
                            packet_writer_add_rdata(&pc, TYPE_SOA, soa_rdata, soa_rdata_size);
                            message_set_authoritative_answer(mesg);
                            message_set_query_answer_authority_additional_counts_ne(mesg, NETWORK_ONE_16, NETWORK_ONE_16, 0, 0);                        
                            message_set_size(mesg, packet_writer_get_offset(&pc));
                            message_set_status(mesg, FP_XFR_UP_TO_DATE);
                        }
                    }
                    else
                    {
                        /* broken zone */

                        log_info("ixfr: %{dnsname}: broken zone", message_get_canonised_fqdn(mesg));

                        message_set_status(mesg, FP_XFR_BROKENZONE);
                    }
                }
                else
                {                
                    log_info("ixfr: %{dnsname}: unable to fetch serial from message: %r", message_get_canonised_fqdn(mesg), return_value);

                    message_set_status(mesg, FP_XFR_QUERYERROR);
                }

#if ZDB_HAS_ACL_SUPPORT
            }
            else
            {
                /* notauth */

                log_info("ixfr: %{dnsname}: not authorised", message_get_canonised_fqdn(mesg));

                message_set_status(mesg, FP_XFR_REFUSED);
            }
#endif
        } // else !ZDB_ZONE_VALID(zone)
        else
        {
            log_debug("ixfr: %{dnsname}: the acquired zone is not valid", message_get_canonised_fqdn(mesg));
            
            message_set_status(mesg, FP_INVALID_ZONE);
        }
        
        zdb_zone_release(zone);
    }
    else
    {
        /* zone not found */

        log_info("ixfr: %{dnsname}: zone not found", message_get_canonised_fqdn(mesg));

        message_set_status(mesg, FP_XFR_REFUSED);
    }
    
    if(message_get_status(mesg) != FP_XFR_UP_TO_DATE)
    {
        message_make_error(mesg, message_get_status(mesg));
    }
    
#if DNSCORE_HAS_TSIG_SUPPORT
    if(message_has_tsig(mesg))
    {
        message_sign_answer(mesg, message_tsig_get_key(mesg));
    }
#endif

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
        log_err("ixfr: %{dnsname}: could not send error message: %r (%{sockaddr})", send_ret, message_get_sender(mesg));
    }
    
    yassert((sockfd < 0)||(sockfd >2));

#if DNSCORE_HAS_TCP_MANAGER
    tcp_manager_context_release(sctx);
#else
    shutdown(sockfd, SHUT_RDWR);
    close_ex(sockfd);
#endif

    return return_value;
}

/**
 * Connects to the server and sends an IXFR query with the given parameters.
 * In case of success the input and output streams are tcp streams to the server, ready to read the answer
 * In case of error the streams are undefined
 * 
 * @param servers
 * @param origin
 * @param ttl
 * @param rdata
 * @param rdata_size
 * @param is
 * @param os
 * @return 
 */

ya_result
ixfr_start_query(const host_address *servers, const u8 *origin, u32 ttl, const u8 *soa_rdata, u16 soa_rdata_size, input_stream *is, output_stream *os, message_data *ixfr_queryp)
{
    /**
     * Create the IXFR query packet
     */

    ya_result return_value;
    u32 serial;
    
    if(FAIL(return_value = rr_soa_get_serial(soa_rdata, soa_rdata_size, &serial)))
    {
        log_err("ixfr: %{dnsname}: error with the SOA: %r", origin, return_value);
        return return_value;
    }
    
    random_ctx rndctx = thread_pool_get_random_ctx();
    u16 id = (u16)random_next(rndctx);
    log_info("ixfr: %{dnsname}: %{hostaddr}: sending query from serial %i", origin, servers, serial);
             
    message_make_ixfr_query(ixfr_queryp, id, origin, ttl, soa_rdata_size, soa_rdata);
    
#if DNSCORE_HAS_TSIG_SUPPORT
    if(servers->tsig != NULL)
    {
        log_info("ixfr: %{dnsname}: %{hostaddr}: transfer will be signed with key '%{dnsname}'", origin, servers, servers->tsig->name);
        
        message_sign_query(ixfr_queryp, servers->tsig);
    }
#endif

    /**
     * Send UDP, read UDP (or timeout)
     * if error, AXFR will be needed
     * if truncated, TCP will be needed
     */

    /*
     * connect & send
     */

    while(FAIL(return_value = tcp_input_output_stream_connect_host_address(servers, is, os, g_config->xfr_connect_timeout)))
    {
        int err = errno;
        
        if(err != EINTR)
        {
            log_info("ixfr: %{dnsname}: %{hostaddr}: failed to send the query: %r", origin, servers, return_value);
            return return_value;
        }
    }
    
#if DEBUG
    log_debug("ixfr_start_query: write: sending %d bytes to %{hostaddr}", message_get_size(ixfr_queryp) + 2, servers);
    log_memdump_ex(g_server_logger, LOG_DEBUG, message_get_buffer_const(ixfr_queryp), message_get_size(ixfr_queryp), 16, OSPRINT_DUMP_HEXTEXT);
#endif

    if(ISOK(return_value = message_write_tcp(ixfr_queryp, os)))
    {
        output_stream_flush(os);

        int fd = fd_input_stream_get_filedescriptor(is);

        tcp_set_sendtimeout(fd, 30, 0);
        tcp_set_recvtimeout(fd, 30, 0);

        return SUCCESS;
    }
        
    input_stream_close(is);
    output_stream_close(os);
    
    return return_value;
}

/**
 *
 * Send an IXFR query to a master and handle the answer (loads the zone).
 */

ya_result
ixfr_query(const host_address *servers, zdb_zone *zone, u32 *out_loaded_serial)
{
    /*
     * Background:
     *
     * Build an ixfr query message
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
     * IXFR query
     */

    ya_result return_value;
    
    u32 current_serial;
    u32 ttl;
    u16 rdata_size;
    const u8 *rdata;

    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_XFR);
    
    if(FAIL(return_value = zdb_zone_getserial(zone, &current_serial))) // zone is locked
    {
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_XFR);
        return return_value; // will return ZDB_ERROR_NOSOAATAPEX if the zone is invalid
    }

    if(FAIL(return_value = zdb_zone_getsoa_ttl_rdata(zone, &ttl, &rdata_size, &rdata))) // zone is locked
    {
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_XFR);
        return return_value;
    }
    
    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_XFR);

    if(dnscore_shuttingdown())
    {
        return STOPPED_BY_APPLICATION_SHUTDOWN;
    }

    input_stream is;
    output_stream os;
    message_data_with_buffer mesg_buff;
    message_data *mesg = message_data_with_buffer_init(&mesg_buff);

    /**
     * start the IXFR query
     */
    
    if(ISOK(return_value = ixfr_start_query(servers, zone->origin, ttl, rdata, rdata_size, &is, &os, mesg)))
    {
        xfr_copy_flags xfr_flags = XFR_ALLOW_BOTH | XFR_CURRENT_SERIAL_SET | ((g_config->axfr_strict_authority)? 0: XFR_LOOSE_AUTHORITY);

        input_stream xfris;
        if(ISOK(return_value = xfr_input_stream_init(&xfris,
                                                     zone->origin,
                                                     &is,
                                                     mesg,
                                                     current_serial,
                                                     xfr_flags)))
        {
            switch(xfr_input_stream_get_type(&xfris))
            {
                case TYPE_AXFR:
                    log_info("ixfr: %{dnsname}: %{hostaddr}: server answered with AXFR", zone->origin, servers);
                    FALLTHROUGH // fall through
                case TYPE_ANY: // this is an AXFR
                {
                    char data_path[PATH_MAX];

                    if(FAIL(return_value = zdb_zone_path_get_provider()(zone->origin, data_path, sizeof(data_path), ZDB_ZONE_PATH_PROVIDER_AXFR_PATH|ZDB_ZONE_PATH_PROVIDER_MKDIR)))
                    {
                        log_err("ixfr: %{dnsname}: unable to create directory '%s' : %r", zone->origin, data_path, return_value);
                        return return_value;
                    }

                    /* delete axfr files */

                    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_XFR);
                    bool have_writing_rights = !zdb_zone_get_set_dumping_axfr(zone);
                    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_XFR);

                    if(have_writing_rights)
                    {
                        xfr_delete_axfr(zone->origin);
                    
                        /* delete journal file */
                        
                        log_info("ixfr: %{dnsname}: %{hostaddr}: deleting journal", zone->origin, servers);

                        zdb_zone_journal_delete(zone);

                        log_info("ixfr: %{dnsname}: %{hostaddr}: loading AXFR stream from server", zone->origin, servers);

                        if(ISOK(return_value = xfr_copy(&xfris, g_config->xfr_path, FALSE)))
                        {
                            if(out_loaded_serial != NULL)
                            {
                                *out_loaded_serial = xfr_input_stream_get_serial(&xfris);
                            }
                        }
                        else
                        {
                            log_warn("ixfr: %{dnsname}: %{hostaddr}: AXFR stream copy in '%s' failed: %r", zone->origin, servers, g_config->xfr_path, return_value);
                        }
                        
                        zdb_zone_lock(zone, ZDB_ZONE_MUTEX_XFR);
                        zdb_zone_clear_dumping_axfr(zone);
                        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_XFR);
                    }
                    else
                    {
                        // zone is already being dumped
                        log_debug("ixfr: %{dnsname}: cannot AXFR: zone already marked as being dumped", zone->origin);
                    }
                    break;
                }
                case TYPE_IXFR:
                {
                    log_info("ixfr: %{dnsname}: %{hostaddr}: writing stream into the journal", zone->origin, servers);

                    while(!dnscore_shuttingdown())
                    {
                        return_value = zdb_zone_journal_append_ixfr_stream(zone, &xfris);

                        if(ISOK(return_value) || (return_value == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY))
                        {
                            u32 ixfr_from_serial;
                            ya_result ret;

                            if(return_value == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                            {
                                if(dnscore_shuttingdown())
                                {
                                    return_value = STOPPED_BY_APPLICATION_SHUTDOWN;
                                    break;
                                }

#if DEBUG
                                log_info("ixfr: %{dnsname}: the zone needs to be stored on disk. Another IXFR query will be scheduled. (shutdown == %i)", zone->origin, dnscore_shuttingdown());
#else
                                log_info("ixfr: %{dnsname}: the zone needs to be stored on disk. Another IXFR query will be scheduled.", zone->origin);
#endif


                                // if we got some journal
                                if(ISOK(ret = zdb_zone_journal_get_serial_range(zone, &ixfr_from_serial, out_loaded_serial)))
                                {
                                    // if the journal doesn't contain new updates, give up for now

                                    if(serial_ge(current_serial, *out_loaded_serial))
                                    {
                                        log_debug("ixfr: %{dnsname}: did not download a single new update in the journal", zone->origin);
                                        zdb_zone_set_status(zone, ZDB_ZONE_STATUS_NEED_REFRESH);
                                        break;
                                    }
                                }
                            }

                            if(dnscore_shuttingdown())
                            {
                                return_value = STOPPED_BY_APPLICATION_SHUTDOWN;
                                break;
                            }

                            if(ISOK(ret = zdb_zone_journal_get_serial_range(zone, &ixfr_from_serial, out_loaded_serial)))
                            {
                                u32 expected_serial = xfr_input_stream_get_serial(&xfris);
#if DEBUG
                                log_debug("ixfr: %{dnsname}: journal_append_ixfr_stream returned %r", zone->origin, return_value);
#endif
                                log_info("ixfr: %{dnsname}: replaying journal (%u;%u)", zone->origin, ixfr_from_serial, *out_loaded_serial);

#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
                                u8 prev_zone_dnssec_type = zone_policy_guess_dnssec_type(zone);
#endif
                                if(ISOK(ret = zdb_icmtl_replay(zone))) // no signature maintenance here
                                {
                                    log_info("ixfr: %{dnsname}: journal replayed %i pages", zone->origin, ret);

                                    // zone_set_status(zone_desc);
                                
#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_MASTER_SUPPORT
                                    u8 zone_dnssec_type = zone_policy_guess_dnssec_type(zone);

                                    if(prev_zone_dnssec_type != zone_dnssec_type)
                                    {
                                        switch(zone_dnssec_type)
                                        {
                                            case ZONE_DNSSEC_FL_NOSEC:
                                                log_debug("ixfr: %{dnsname}: slave zone is not DNSSEC", zone->origin);
                                                break;
                                            case ZONE_DNSSEC_FL_NSEC:
                                                log_debug("ixfr: %{dnsname}: slave zone is NSEC", zone->origin);
                                                break;
                                            case ZONE_DNSSEC_FL_NSEC3:
                                                log_debug("ixfr: %{dnsname}: slave zone is NSEC3", zone->origin);
                                                break;
                                            case ZONE_DNSSEC_FL_NSEC3_OPTOUT:
                                                log_debug("ixfr: %{dnsname}: slave zone is NSEC3 OPT-OUT", zone->origin);
                                                break;
                                        }

                                        zone_dnssec_status_update(zone);
                                    }
#endif
                                }
                                else
                                {
                                    return_value = ret;
                                    log_err("ixfr: %{dnsname}: journal replay returned %r", zone->origin, return_value);
                                }

                                if(return_value != ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                                {
                                    if(ISOK(ret) && serial_lt(*out_loaded_serial, expected_serial))
                                    {
                                        // should redo an IXFR asap

                                        if(!dnscore_shuttingdown())
                                        {
                                            log_info("ixfr: %{dnsname}: loaded serial %u below expected serial (%u): querying IXFR again", zone->origin, *out_loaded_serial, expected_serial);
                                            database_service_zone_ixfr_query(zone->origin);
                                        }
                                    }
                                    else
                                    {
                                        zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_NEED_REFRESH);
                                    }
                                }
                                else
                                {
                                    zdb_zone_set_status(zone, ZDB_ZONE_STATUS_NEED_REFRESH);
                                }
                            }
                            else
                            {
                                log_warn("ixfr: %{dnsname}: could not get the serial range of the journal: %r", zone->origin, return_value);
                            }
                        }
                        else
                        {
                            if(return_value == ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE)
                            {
                                /// @note 20161018 edf -- we are slave, so it's OK
                                log_warn("ixfr: %{dnsname}: %{hostaddr}: no continuity with the journal, resetting", zone->origin, servers);
                                // hole in the journal : reset
                                zdb_zone_journal_delete(zone);
                            }
                            else
                            {
                                log_err("ixfr: %{dnsname}: %{hostaddr}: failed to write the stream into the journal: %r", zone->origin, servers, return_value);
                            }
                        }
                        
                        break; // for
                    }
                    
                    break;
                }
                default:
                {
                    return_value = RCODE_ERROR_CODE(RCODE_FORMERR);
                    break;
                }
            }

            log_debug("ixfr: %{dnsname}: closing stream", zone->origin);

            input_stream_close(&xfris);
            
            if(ISOK(return_value))
            {
                log_debug("ixfr: %{dnsname}: notifying implicit and explicit slaves", zone->origin);
                notify_slaves(zone->origin);
            }
        }
        else
        {
            if(return_value == ZONE_ALREADY_UP_TO_DATE)
            {
                return_value = SUCCESS;
            }
            else
            {
                log_info("ixfr: %{dnsname}: transfer from master failed: %r", zone->origin, return_value);
            }
        }

        input_stream_close(&is);
        output_stream_close(&os);
    }

    return return_value;
}

/** @} */

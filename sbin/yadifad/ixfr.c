/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2017, EURid. All rights reserved.
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
#include "config.h"

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

#include <dnsdb/zdb-zone-journal.h>
#include <dnsdb/zdb-zone-answer-ixfr.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/zdb_utils.h>
#include <dnsdb/xfr_copy.h>

#include "server.h"
#include "ixfr.h"
#include "confs.h"
#include "notify.h"
#include "database-service-zone-download.h"

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

/**
 * 
 * Handle an IXFR query from a slave.
 *
 * @todo 20101125 edf -- Set the IXFR storage path
 */
ya_result
ixfr_process(message_data *mesg)
{
    /*
     * Start an IXFR "writer" thread
     * Give it the tcp fd
     * It will store the IXFR for the current database snapshot on the disk if it does not exist yet (writers blocked)
     * It will then open the stored file and stream it to the tcp fd (writers freed)
     * ACL/TSIG is not taken in account yet.
     */
    
    zdb_zone *zone;

    u8 *fqdn = mesg->qname;
    u32 fqdn_len = dnsname_len(fqdn);
    
    if(fqdn_len > MAX_DOMAIN_LENGTH)
    {
        return DOMAIN_TOO_LONG;
    }
    
    ya_result return_value = SUCCESS;

    /// @todo 20141006 edf -- verify qclass
    //u16 qclass = GET_U16_AT(mesg->buffer[DNS_HEADER_LENGTH + fqdn_len + 2]);
    
    if(((zone = zdb_acquire_zone_read_from_fqdn(g_config->database, fqdn)) != NULL) && ZDB_ZONE_VALID(zone))
    {
#if ZDB_HAS_ACL_SUPPORT
        access_control *ac = (access_control*)zone->extension;
        
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
                return_value = zdb_zone_getserial(zone, &zone_serial);
                zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                
                if(ISOK(return_value))
                {                
                    if(serial_lt(query_serial, zone_serial))
                    {
                        // reply with the relevant XFR stream
                        
                        zdb_zone_answer_ixfr(zone, mesg, NULL, NULL, g_config->axfr_max_packet_size, g_config->axfr_max_record_by_packet, g_config->axfr_compress_packets);
                        
                        return SUCCESS;
                    }
                    else
                    {
                        /* already up-to-date */
                        
                        log_info("ixfr: %{dnsname}: already up-to-date at serial %u", mesg->qname, zone_serial);
                 
                        // answer with the SOA
                        
                        packet_writer pc;
                        packet_writer_init(&pc, mesg->buffer, DNS_HEADER_LENGTH + fqdn_len + 2 + 2, MAX_U16);

                        const u8 *soa_rdata;
                        u32 soa_ttl;
                        u16 soa_rdata_size;
                        
                        zdb_zone_lock(zone, ZDB_ZONE_MUTEX_XFR);
                        zdb_zone_getsoa_ttl_rdata(zone, &soa_ttl, &soa_rdata_size, &soa_rdata);
                        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_XFR);
                        
                        packet_writer_add_fqdn(&pc, &mesg->buffer[12]);
                        packet_writer_add_u16(&pc, TYPE_SOA);
                        packet_writer_add_u16(&pc, CLASS_IN);
                        packet_writer_add_u32(&pc, ntohl(soa_ttl));
                        packet_writer_add_rdata(&pc, TYPE_SOA, soa_rdata, soa_rdata_size);
                        MESSAGE_FLAGS_OR(mesg->buffer, QR_BITS|AA_BITS, 0);
                        MESSAGE_SET_QD(mesg->buffer, NETWORK_ONE_16);
                        MESSAGE_SET_AN(mesg->buffer, NETWORK_ONE_16);
                        MESSAGE_SET_NSAR(mesg->buffer, 0);
                        
                        mesg->send_length = packet_writer_get_offset(&pc);
                        mesg->status = FP_XFR_UP_TO_DATE;
                    }
                }
                else
                {
                    /* broken zone */
                    
                    log_info("ixfr: %{dnsname}: broken zone", mesg->qname);
                    
                    mesg->status = FP_XFR_BROKENZONE;
                }
            }
            else
            {                
                log_info("ixfr: %{dnsname}: unable to fetch serial from message: %r", mesg->qname, return_value);
                
                mesg->status = FP_XFR_QUERYERROR;
            }
            
#if ZDB_HAS_ACL_SUPPORT
        }
        else
        {
            /* notauth */

            log_info("ixfr: %{dnsname}: not authorised", mesg->qname);
            
            mesg->status = FP_XFR_REFUSED;
        }
#endif
    }
    else
    {
        /* zone not found */

        log_info("ixfr: %{dnsname}: zone not found", mesg->qname);

        if(zone == NULL)
        {
            mesg->status = FP_XFR_REFUSED;
        }
        else
        {
            mesg->status = FP_INVALID_ZONE;
        }
    }
    
    if(mesg->status != FP_XFR_UP_TO_DATE)
    {
        message_make_error(mesg, mesg->status);
    }
    
#if HAS_TSIG_SUPPORT
    if(MESSAGE_HAS_TSIG(*mesg))
    {
        message_sign_answer(mesg,mesg->tsig.tsig);
    }
#endif

    tcp_send_message_data(mesg);
    
    yassert((mesg->sockfd < 0)||(mesg->sockfd >2));
    
    close_ex(mesg->sockfd);

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

    random_ctx rndctx = thread_pool_get_random_ctx();
    ya_result return_value;
    u32 serial;
    u16 id = (u16)random_next(rndctx);
    
    if(FAIL(return_value = rr_soa_get_serial(soa_rdata, soa_rdata_size, &serial)))
    {
        log_err("ixfr: %{dnsname}: error with the SOA: %r", origin, return_value);
        return return_value;
    }
    
    log_info("ixfr: %{dnsname}: %{hostaddr}: sending query from serial %i", origin, servers, serial);
             
    message_make_ixfr_query(ixfr_queryp, id, origin, ttl, soa_rdata_size, soa_rdata);
    
#if HAS_TSIG_SUPPORT
    if(servers->tsig != NULL)
    {
        log_info("ixfr: %{dnsname}: %{hostaddr}: transfer will be signed with key '%{dnsname}'", origin, servers, servers->tsig->name);
        
        message_sign_query(ixfr_queryp, servers->tsig);
    }
#endif

    /**
     * @todo 20120523 edf -- start by doing it UDP (1.0.1)
     * Send UDP, read UDP (or timeout)
     * if error, AXFR will be needed
     * if truncated, TCP will be needed
     */

    message_update_tcp_length(ixfr_queryp);

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
    
#ifdef DEBUG
    log_debug("ixfr_start_query: write: sending %d bytes to %{hostaddr}", ixfr_queryp->send_length + 2, servers);
    log_memdump_ex(g_server_logger, LOG_DEBUG, &ixfr_queryp->buffer_tcp_len[0], ixfr_queryp->send_length + 2, 16, OSPRINT_DUMP_HEXTEXT);
#endif
    
    if(ISOK(return_value = output_stream_write(os, &ixfr_queryp->buffer_tcp_len[0], ixfr_queryp->send_length + 2)))
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
 *
 * @todo 20110620 edf -- Set the IXFR storage path
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
    
    if(FAIL(return_value = zdb_zone_getserial(zone, &current_serial)))
    {
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_XFR);
        return return_value; // will return ZDB_ERROR_NOSOAATAPEX if the zone is invalid
    }

    if(FAIL(return_value = zdb_zone_getsoa_ttl_rdata(zone, &ttl, &rdata_size, &rdata)))
    {
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_XFR);
        return return_value;
    }
    
    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_XFR);

    input_stream is;
    output_stream os;
    message_data mesg;

    /**
     * start the IXFR query
     */
    
    if(ISOK(return_value = ixfr_start_query(servers, zone->origin, ttl, rdata, rdata_size, &is, &os, &mesg)))
    {
        input_stream xfris;
        if(ISOK(return_value = xfr_input_stream_init(&xfris,
                                                     zone->origin,
                                                     &is,
                                                     &mesg,
                                                     current_serial,
                                                     XFR_ALLOW_BOTH|XFR_CURRENT_SERIAL_SET)))
        {
            switch(xfr_input_stream_get_type(&xfris))
            {
                case TYPE_AXFR:
                    log_info("ixfr: %{dnsname}: %{hostaddr}: server answered with AXFR", zone->origin, servers);
                    
                case TYPE_ANY:
                {
                    /* delete axfr files */
                    
                    xfr_delete_axfr(zone->origin);
                    
                    /* delete ix files */

                    zdb_zone_journal_delete(zone);
                    
                    log_info("ixfr: %{dnsname}: %{hostaddr}: loading AXFR stream from server", zone->origin, servers);
                    
                    if(ISOK(return_value = xfr_copy(&xfris, g_config->xfr_path)))
                    {
                        if(out_loaded_serial != NULL)
                        {
                            *out_loaded_serial = xfr_input_stream_get_serial(&xfris);
                        }
                    }
                    else
                    {
                        log_debug("ixfr: %{dnsname}: %{hostaddr}: AXFR stream copy failed: %r", zone->origin, servers, return_value);
                    }
                    
                    break;
                }
                case TYPE_IXFR:
                {
                    log_info("ixfr: %{dnsname}: %{hostaddr}: writing stream into the journal", zone->origin, servers);
                    
                    return_value = zdb_zone_journal_append_ixfr_stream(zone, &xfris);
                    
                    u32 ixfr_from_serial;
                    
                    zdb_zone_journal_get_serial_range(zone, &ixfr_from_serial, out_loaded_serial);
                    
                    u32 expected_serial = xfr_input_stream_get_serial(&xfris);
                    
#ifdef DEBUG
                    log_debug("ixfr: %{dnsname}: journal_append_ixfr_stream returned %r", zone->origin, return_value);
#endif
                    if(ISOK(return_value))
                    {
                        ya_result ret;
                        
                        log_info("ixfr: %{dnsname}: replaying journal (%u;%u)", zone->origin, ixfr_from_serial, *out_loaded_serial);
                        if(ISOK(ret = zdb_icmtl_replay(zone)))
                        {
                            log_info("ixfr: %{dnsname}: journal replayed", zone->origin);
                        }
                        else
                        {
                            return_value = ret;
                            log_err("ixfr: %{dnsname}: journal replay returned %r", zone->origin, return_value);
                        }
                        
                        if(ISOK(ret) && serial_lt(*out_loaded_serial, expected_serial))
                        {
                            // should redo an IXFR asap
                            
                            log_info("ixfr: %{dnsname}: loaded serial %u below expected serial: querying IXFR again", zone->origin, *out_loaded_serial, expected_serial);
                            database_service_zone_ixfr_query(zone->origin);
                        }
                    }
                    else
                    {
                        log_err("ixfr: %{dnsname}: %{hostaddr}: failed to write the stream into the journal: %r", zone->origin, servers, return_value);
                    }
                    
                    break;
                }
                default:
                {
                    return_value = ERROR;
                    break;
                }
            }
            
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

        /**
         * @todo 20121023 edf -- Here is a good place to check the journal size.
         *
         * If it worked, it may be nice to know the current total size of the journaling file
         * If it's beyond a given size, then an zone file/AXFR could be written on the disk and the older files deleted
         */
    }

    return return_value;
}

/** @} */

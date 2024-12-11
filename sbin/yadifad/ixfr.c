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
#include <dnscore/dns_packet_writer.h>

#include <dnsdb/zdb_zone_journal.h>
#include <dnsdb/zdb_zone_answer_ixfr.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/zdb_zone_path_provider.h>
#include <dnsdb/xfr_copy.h>

#include "server.h"
#include "ixfr.h"
#include "confs.h"
#include "notify.h"
#include "dnssec_policy.h"
#include "database_service_zone_download.h"

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

/**
 *
 * Handle an IXFR query from a secondary.
 */

ya_result ixfr_process(dns_message_t *mesg, tcp_manager_channel_t *tmc)
{
    /*
     * Start an IXFR "writer" thread
     * Give it the tcp fd
     * It will store the IXFR for the current database snapshot on the disk if it does not exist yet (writers blocked)
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

    ya_result return_value = SUCCESS;

    if((zone = zdb_acquire_zone_read_from_fqdn(g_config->database, fqdn)) != NULL)
    {
        if(zdb_zone_valid(zone))
        {
#if ZDB_HAS_ACL_SUPPORT
            access_control_t *ac = zone->acl;

            if(!ACL_REJECTED(acl_check_access_filter(mesg, &ac->allow_transfer)))
            {
#endif
                /*
                 * Before doing more work, check the serials.
                 */

                uint32_t query_serial;

                if(ISOK(return_value = dns_message_ixfr_query_get_serial(mesg, &query_serial)))
                {
                    uint32_t zone_serial;

                    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                    return_value = zdb_zone_getserial(zone, &zone_serial); // zone is locked
                    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

                    if(ISOK(return_value))
                    {
                        if(serial_lt(query_serial, zone_serial))
                        {
                            // reply with the relevant XFR stream

                            zdb_zone_answer_ixfr(zone, mesg, tmc, NULL, NULL, g_config->axfr_max_packet_size, g_config->axfr_max_record_by_packet, g_config->axfr_compress_packets);

                            zdb_zone_release(zone);

                            return SUCCESS;
                        }
                        else
                        {
                            /* already up-to-date */

                            log_info("ixfr: %{dnsname}: already up-to-date at serial %u", dns_message_get_canonised_fqdn(mesg), zone_serial);

                            // answer with the SOA

                            dns_packet_writer_t pc;
                            dns_packet_writer_init(&pc, dns_message_get_buffer(mesg), DNS_HEADER_LENGTH + fqdn_len + 2 + 2,
                                                   dns_message_get_buffer_size(mesg)); // valid use of message_get_buffer_size()

                            const uint8_t *soa_rdata;
                            uint32_t       soa_ttl;
                            uint16_t       soa_rdata_size;

                            zdb_zone_lock(zone, ZDB_ZONE_MUTEX_XFR);
                            zdb_zone_getsoa_ttl_rdata(zone, &soa_ttl, &soa_rdata_size, &soa_rdata); // zone is locked
                            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_XFR);

                            dns_packet_writer_add_fqdn(&pc, &(dns_message_get_buffer_const(mesg)[DNS_HEADER_LENGTH]));
                            dns_packet_writer_add_u16(&pc, TYPE_SOA);
                            dns_packet_writer_add_u16(&pc, CLASS_IN);
                            dns_packet_writer_add_u32(&pc, ntohl(soa_ttl));
                            dns_packet_writer_add_rdata(&pc, TYPE_SOA, soa_rdata, soa_rdata_size);
                            dns_message_set_authoritative_answer(mesg);
                            dns_message_set_query_answer_authority_additional_counts_ne(mesg, NETWORK_ONE_16, NETWORK_ONE_16, 0, 0);
                            dns_message_set_size(mesg, dns_packet_writer_get_offset(&pc));
                            dns_message_set_status(mesg, FP_XFR_UP_TO_DATE);
                        }
                    }
                    else
                    {
                        /* broken zone */

                        log_info("ixfr: %{dnsname}: broken zone", dns_message_get_canonised_fqdn(mesg));

                        dns_message_set_status(mesg, FP_XFR_BROKENZONE);
                    }
                }
                else
                {
                    log_info("ixfr: %{dnsname}: unable to fetch serial from message: %r", dns_message_get_canonised_fqdn(mesg), return_value);

                    dns_message_set_status(mesg, FP_XFR_QUERYERROR);
                }

#if ZDB_HAS_ACL_SUPPORT
            }
            else
            {
                /* notauth */

                log_info("ixfr: %{dnsname}: not authorised", dns_message_get_canonised_fqdn(mesg));

                dns_message_set_status(mesg, FP_XFR_REFUSED);
            }
#endif
        } // else !ZDB_ZONE_VALID(zone)
        else
        {
            log_debug("ixfr: %{dnsname}: the acquired zone is not valid", dns_message_get_canonised_fqdn(mesg));

            dns_message_set_status(mesg, FP_INVALID_ZONE);
        }

        zdb_zone_release(zone);
    }
    else
    {
        /* zone not found */

        log_info("ixfr: %{dnsname}: zone not found", dns_message_get_canonised_fqdn(mesg));

        dns_message_set_status(mesg, FP_XFR_REFUSED);
    }

    if(dns_message_get_status(mesg) != FP_XFR_UP_TO_DATE)
    {
        dns_message_make_error(mesg, dns_message_get_status(mesg));
    }

#if DNSCORE_HAS_TSIG_SUPPORT
    if(dns_message_has_tsig(mesg))
    {
        log_debug("ixfr: %{dnsname}: signing answer", dns_message_get_canonised_fqdn(mesg));
        dns_message_sign_answer(mesg);
    }
#endif

    ya_result send_ret;

    send_ret = tcp_manager_channel_send(tmc, mesg);

    if(FAIL(send_ret))
    {
        log_err("ixfr: %{dnsname}: could not send error message: %r (%{sockaddr})", dns_message_get_canonised_fqdn(mesg), send_ret, dns_message_get_sender(mesg));
    }

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

ya_result ixfr_start_query(const host_address_t *servers, const uint8_t *origin, int32_t ttl, const uint8_t *soa_rdata, uint16_t soa_rdata_size, input_stream_t *is, output_stream_t *os, dns_message_t *ixfr_queryp)
{
    /**
     * Create the IXFR query packet
     */

    ya_result return_value;
    uint32_t  serial;

    if(FAIL(return_value = rr_soa_get_serial(soa_rdata, soa_rdata_size, &serial)))
    {
        log_err("ixfr: %{dnsname}: error with the SOA: %r", origin, return_value);
        return return_value;
    }

    random_ctx_t rndctx = thread_pool_get_random_ctx();
    uint16_t     id = (uint16_t)random_next(rndctx);
    log_info("ixfr: %{dnsname}: %{hostaddr}: sending query from serial %i", origin, servers, serial);

    dns_message_make_ixfr_query(ixfr_queryp, id, origin, ttl, soa_rdata_size, soa_rdata);

#if DNSCORE_HAS_TSIG_SUPPORT
    if(servers->tsig != NULL)
    {
        log_info("ixfr: %{dnsname}: %{hostaddr}: transfer will be signed with key '%{dnsname}'", origin, servers, servers->tsig->name);

        dns_message_sign_query(ixfr_queryp, servers->tsig);
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

    host_address_t *transfer_source = zone_transfer_source_copy(origin);
    host_address_t *current_transfer_source;
    current_transfer_source = transfer_source;

    return_value = zone_transfer_source_tcp_connect(servers, &current_transfer_source, is, os, g_config->xfr_connect_timeout);

    if(ISOK(return_value))
    {
#if DEBUG
        log_debug("ixfr_start_query: write: sending %d bytes to %{hostaddr}", dns_message_get_size(ixfr_queryp) + 2, servers);
        log_memdump_ex(g_server_logger, LOG_DEBUG, dns_message_get_buffer_const(ixfr_queryp), dns_message_get_size(ixfr_queryp), 16, OSPRINT_DUMP_HEXTEXT);
#endif
        if(ISOK(return_value = dns_message_write_tcp(ixfr_queryp, os)))
        {
            output_stream_flush(os);

            if(is_fd_input_stream(is))
            {
                int fd = fd_input_stream_get_filedescriptor(is);
                tcp_set_sendtimeout(fd, 30, 0);
                tcp_set_recvtimeout(fd, 30, 0);
            }

            return SUCCESS;
        }

        input_stream_close(is);
        output_stream_close(os);
    }
    else
    {
        if((transfer_source != NULL) && (current_transfer_source == NULL))
        {
            log_warn("ixfr: %{dnsname}: %{hostaddr}: could not find a valid bind point to query a transfer from", origin, servers);
        }
        else
        {
            log_info("ixfr: %{dnsname}: %{hostaddr}: stream connection failed: %r", origin, servers, return_value);
        }
    }

    return return_value;
}

/**
 *
 * Send an IXFR query to a primary and handle the answer (loads the zone).
 */

ya_result ixfr_query(const host_address_t *servers, zdb_zone_t *zone, uint32_t *out_loaded_serial)
{
    /*
     * Background:
     *
     * Build an IXFR query message
     * Send it to the primary
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

    ya_result      return_value;

    uint32_t       current_serial;
    uint32_t       ttl;
    uint16_t       rdata_size;
    uint16_t       transfer_type = 0;
    const uint8_t *rdata;

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

    input_stream_t            is;
    output_stream_t           os;
    dns_message_with_buffer_t mesg_buff;
    dns_message_t            *mesg = dns_message_data_with_buffer_init(&mesg_buff);

    /**
     * start the IXFR query
     */

    if(ISOK(return_value = ixfr_start_query(servers, zone->origin, ttl, rdata, rdata_size, &is, &os, mesg)))
    {
        xfr_copy_flags xfr_flags = XFR_ALLOW_BOTH | XFR_CURRENT_SERIAL_SET | ((g_config->axfr_strict_authority) ? 0 : XFR_LOOSE_AUTHORITY);

        input_stream_t xfris;
        if(ISOK(return_value = xfr_input_stream_init(&xfris, zone->origin, &is, mesg, current_serial, xfr_flags)))
        {
            switch(transfer_type = xfr_input_stream_get_type(&xfris))
            {
                case TYPE_AXFR:
                    log_info("ixfr: %{dnsname}: %{hostaddr}: server answered with AXFR", zone->origin, servers);
                FALLTHROUGH        // fall through
                    case TYPE_ANY: // this is an AXFR
                {
                    char data_path[PATH_MAX];

                    if(FAIL(return_value = zdb_zone_path_get_provider()(zone->origin, data_path, sizeof(data_path), ZDB_ZONE_PATH_PROVIDER_AXFR_PATH | ZDB_ZONE_PATH_PROVIDER_MKDIR)))
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

                        if(ISOK(return_value = xfr_copy(&xfris, g_config->xfr_path, false)))
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
                            uint32_t  ixfr_from_serial;
                            ya_result ret;

                            if(return_value == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                            {
                                if(dnscore_shuttingdown())
                                {
                                    return_value = STOPPED_BY_APPLICATION_SHUTDOWN;
                                    break;
                                }

#if DEBUG
                                log_info(
                                    "ixfr: %{dnsname}: the zone needs to be stored on disk. Another IXFR query will be "
                                    "scheduled. (shutdown == %i)",
                                    zone->origin,
                                    dnscore_shuttingdown());
#else
                                log_info(
                                    "ixfr: %{dnsname}: the zone needs to be stored on disk. Another IXFR query will be "
                                    "scheduled.",
                                    zone->origin);
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
                                uint32_t expected_serial = xfr_input_stream_get_serial(&xfris);
#if DEBUG
                                log_debug("ixfr: %{dnsname}: journal_append_ixfr_stream returned %r", zone->origin, return_value);
#endif
                                log_info("ixfr: %{dnsname}: replaying journal (%u;%u)", zone->origin, ixfr_from_serial, *out_loaded_serial);

#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_PRIMARY_SUPPORT
                                uint8_t prev_zone_dnssec_type = zone_policy_guess_dnssec_type(zone);
#endif
                                if(ISOK(ret = zdb_icmtl_replay(zone))) // no signature maintenance here
                                {
                                    log_info("ixfr: %{dnsname}: journal replayed %i pages", zone->origin, ret);

                                    // zone_set_status(zone_desc);

#if ZDB_HAS_DNSSEC_SUPPORT && HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_PRIMARY_SUPPORT
                                    uint8_t zone_dnssec_type = zone_policy_guess_dnssec_type(zone);

                                    if(prev_zone_dnssec_type != zone_dnssec_type)
                                    {
                                        switch(zone_dnssec_type)
                                        {
                                            case ZONE_DNSSEC_FL_NOSEC:
                                                log_debug("ixfr: %{dnsname}: secondary zone is not DNSSEC", zone->origin);
                                                break;
                                            case ZONE_DNSSEC_FL_NSEC:
                                                log_debug("ixfr: %{dnsname}: secondary zone is NSEC", zone->origin);
                                                break;
                                            case ZONE_DNSSEC_FL_NSEC3:
                                                log_debug("ixfr: %{dnsname}: secondary zone is NSEC3", zone->origin);
                                                break;
                                            case ZONE_DNSSEC_FL_NSEC3_OPTOUT:
                                                log_debug("ixfr: %{dnsname}: secondary zone is NSEC3 OPT-OUT", zone->origin);
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
                                            log_info(
                                                "ixfr: %{dnsname}: loaded serial %u below expected serial (%u): "
                                                "querying IXFR again",
                                                zone->origin,
                                                *out_loaded_serial,
                                                expected_serial);
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
                                /// @note 20161018 edf -- we are secondary, so it's OK
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
                log_debug("ixfr: %{dnsname}: notifying implicit and explicit secondaries", zone->origin);
                notify_secondaries(zone->origin);
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
                log_info("ixfr: %{dnsname}: transfer from primary failed: %r", zone->origin, return_value);
            }
        }

        input_stream_close(&is);
        output_stream_close(&os);
    }

    if(ISOK(return_value))
    {
        return_value = transfer_type;
    }

    return return_value;
}

/** @} */

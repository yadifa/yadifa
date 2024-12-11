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
 * @defgroup dnsdbixfr IXFR answers
 * @ingroup dnsdb
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>

#include "dnsdb/zdb_config_features.h"

#include <dnscore/logger.h>
#include <dnscore/thread_pool.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/format.h>
#include <dnscore/dns_packet_writer.h>
#include <dnscore/dns_packet_reader.h>
#include <dnscore/rfc.h>
#include <dnscore/serial.h>

#if DEBUG
#include <dnscore/logger_output_stream.h>
#endif

#include "dnsdb/zdb_zone_journal.h"
#include "dnsdb/zdb_icmtl.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_types.h"

#include "dnsdb/zdb_zone_answer_axfr.h"

#define TCP_BUFFER_SIZE    4096
#define FILE_BUFFER_SIZE   4096

#define RECORD_MODE_DELETE 0
#define RECORD_MODE_ADD    1

#define ZAIXFRRB_TAG       0x425252465849415a
/*
 * Typically it goes 4 3 [2,1]+ 0
 */

#define MODULE_MSG_HANDLE  g_database_logger
extern logger_handle_t *g_database_logger;

#define TCP_BUFFER_SIZE           4096
#define FILE_BUFFER_SIZE          4096

#define IXFR_RECORD_SENDING_DEBUG 0

#define RECORD_MODE_DELETE        0
#define RECORD_MODE_ADD           1

/*
 * Typically it goes 4 3 [2,1]+ 0
 */

extern logger_handle_t *g_database_logger;

#ifndef PATH_MAX
#error "PATH_MAX not defined"
#endif

typedef struct zdb_zone_answer_ixfr_args zdb_zone_answer_ixfr_args;

#define ZAIXFRA_TAG 0x4152465849415a

struct zdb_zone_answer_ixfr_args
{
    zdb_zone_t            *zone;
    dns_message_t         *mesg;
    struct thread_pool_s  *disk_tp;
    tcp_manager_channel_t *tmc;
    ya_result              return_code;
    uint32_t               packet_size_limit;
    uint32_t               packet_records_limit;
    uint32_t               from_serial;
    bool                   compress_dname_rdata;
    bool                   threaded;
};

static void zdb_zone_answer_ixfr_thread_finalize(zdb_zone_answer_ixfr_args *data)
{
    log_debug("zone write ixfr: ended with: %r", data->return_code);

    zdb_zone_release(data->zone);

    if(data->tmc != NULL)
    {
        if(data->threaded)
        {
            tcp_manager_channel_release(data->tmc);
        }

        data->tmc = NULL;
    }

    if(data->mesg != NULL)
    {
        dns_message_delete(data->mesg);
    }
    // free(data->directory);
    free(data);
}

static ya_result zdb_zone_answer_ixfr_read_record(input_stream_t *is, uint8_t *qname, uint32_t *qname_sizep, struct type_class_ttl_rdlen_s *tctrlp, uint8_t *rdata_buffer, uint32_t *rdata_sizep)
{
    ya_result return_code;

    /* Read the next DNAME from the stored INCREMENTAL */

    if((return_code = input_stream_read_dnsname(is, qname)) <= 0)
    {
        if(return_code < 0)
        {
            log_err("zone write ixfr: error reading IXFR qname: %r", return_code);
        }
        else
        {
            log_debug("zone write ixfr: eof reading IXFR qname: %r", return_code);
        }

        return return_code;
    }

    *qname_sizep = return_code;

    if(return_code > 0)
    {
        /* read the next type+class+ttl+rdatalen from the stored IXFR */

        tctrlp->rtype = 0;
        tctrlp->rdlen = 0;

        if(FAIL(return_code = input_stream_read_fully(is, tctrlp, 10)))
        {
            log_err("zone write ixfr: error reading IXFR record: %r", return_code);

            return return_code;
        }

        if(FAIL(return_code = input_stream_read_fully(is, rdata_buffer, ntohs(tctrlp->rdlen))))
        {
            log_err("zone write ixfr: error reading IXFR record rdata: %r", return_code);

            return return_code;
        }

        *rdata_sizep = return_code;

        return_code = *qname_sizep + 10 + *rdata_sizep;
    }
    else
    {
        *rdata_sizep = 0;
    }

    return return_code;
}

/*
 * mesg is needed for TSIG
 */

extern uint16_t edns0_maxsize;

#if ZDB_HAS_TSIG_SUPPORT
static ya_result zdb_zone_answer_ixfr_send_message(tcp_manager_channel_t *tmc, dns_packet_writer_t *pw, dns_message_t *mesg, tsig_tcp_message_position pos)
#else
static ya_result zdb_zone_answer_ixfr_send_message(tcp_manager_channel_t *tmc, dns_packet_writer_t *pw, dns_message_t *mesg)
#endif
{
    ya_result return_code;

    /*
     * Flush and stop
     */

#if DEBUG
    log_debug("zone write ixfr: %{dnsname}: sending message for %{dnsname} to %{sockaddr}", dns_message_get_canonised_fqdn(mesg), dns_message_get_canonised_fqdn(mesg), dns_message_get_sender(mesg));
#endif

    if(dns_message_has_edns0(mesg)) // Dig does a TCP query with EDNS0
    {
        /* 00 00 29 SS SS rr vv 80 00 00 00 */

        memset(dns_packet_writer_get_next_u8_ptr(pw), 0, EDNS0_RECORD_SIZE);
        dns_packet_writer_forward(pw, 2);
        dns_packet_writer_add_u8(pw, 0x29);
        dns_packet_writer_add_u16(pw, htons(edns0_maxsize));
        dns_packet_writer_add_u32(pw, dns_message_get_edns0_opt_ttl(mesg));
        dns_packet_writer_forward(pw, 2);
        dns_message_set_additional_count_ne(mesg, NETWORK_ONE_16);
    }
    else
    {
        dns_message_set_additional_count_ne(mesg, 0);
    }

    dns_message_set_size(mesg, dns_packet_writer_get_offset(pw));

#if ZDB_HAS_TSIG_SUPPORT
    if(dns_message_has_tsig(mesg))
    {
        dns_message_set_additional_section_ptr(mesg, dns_packet_writer_get_next_u8_ptr(pw));

        if(FAIL(return_code = tsig_sign_tcp_message(mesg, pos)))
        {
            log_err("zone write ixfr: failed to sign the answer: %r", return_code);

            return return_code;
        }
    }
#endif

    return_code = tcp_manager_channel_send(tmc, mesg);

    return return_code;
}

static void zdb_zone_answer_ixfr_thread_close_finalize(zdb_zone_answer_ixfr_args *data, ya_result ret)
{
    data->return_code = ret;
    zdb_zone_answer_ixfr_thread_finalize(data);
}

static ya_result zdb_zone_answer_ixfr_thread_read_SOA_serial(zdb_zone_answer_ixfr_args *data, dns_packet_reader_t *purd, uint32_t *serialp)
{
    struct type_class_ttl_rdlen_s tctr;
    uint8_t                       fqdn[DOMAIN_LENGTH_MAX];

    if((data == NULL) || (purd == NULL) || (serialp == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(FAIL(dns_packet_reader_read_fqdn(purd, fqdn, sizeof(fqdn))))
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    if(!dnsname_equals_ignorecase(fqdn, data->zone->origin))
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    if(FAIL(dns_packet_reader_read(purd, &tctr, 10)))
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    if(tctr.rtype != TYPE_SOA)
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    if(FAIL(dns_packet_reader_skip_fqdn(purd)))
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    if(FAIL(dns_packet_reader_skip_fqdn(purd)))
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    if(dns_packet_reader_available(purd) != 20)
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    if(FAIL(dns_packet_reader_read(purd, (uint8_t *)serialp, 4)))
    {
        return MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    return SUCCESS;
}

/*
 * writes the filtered stream to a file, then adds it to the journal
 * the journal needs to give fast access to the last SOA in it ...
 *
 */

static void zdb_zone_answer_ixfr_thread(void *data_)
{
    zdb_zone_answer_ixfr_args *data = (zdb_zone_answer_ixfr_args *)data_;
    dns_message_t             *mesg = data->mesg;

    /* The TCP output stream */

    /* The incremental file input stream */

    input_stream_t fis;

    /* The packet writer */

    /* Current SOA */

    uint32_t current_soa_rdata_size;
    // u16 target_soa_rdata_size = SOA_RDATA_LENGTH_MAX;

    struct type_class_ttl_rdlen_s current_soa_tctrl;

    /*
     */

    uint8_t                      *rdata_buffer = NULL;
    struct type_class_ttl_rdlen_s tctrl;
    uint32_t                      qname_size;
    uint32_t                      rdata_size = 0;

    /*
     */

    ya_result return_value;

    uint32_t  serial = 0;
    uint16_t  an_count = 0;
    int32_t   pages_sent = 0;
    uint32_t  current_to_serial = 0;
    uint32_t  stream_serial = 0;

    uint32_t  packet_size_limit;
    uint32_t  packet_size_trigger;
    int32_t   packet_records_limit;
    int32_t   packet_records_countdown;

#if ZDB_HAS_TSIG_SUPPORT
    tsig_tcp_message_position pos = TSIG_START;
#endif

    // bool call_is_threaded = data->threaded;

    /*
     * relevant data for when data is not usable anymore
     */

    uint8_t             origin[DOMAIN_LENGTH_MAX];
    uint8_t             current_soa_rdata_buffer[SOA_RDATA_LENGTH_MAX];
    uint8_t             target_soa_rdata_buffer[SOA_RDATA_LENGTH_MAX];
    uint8_t             fqdn[DOMAIN_LENGTH_MAX];

    dns_packet_writer_t pw;

    log_info("zone write ixfr: %{dnsname}: sending journal file", data->zone->origin);

    zdb_zone_lock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

    /* Keep a snapshot of the current SOA */

    int32_t                     soa_ttl;
    zdb_resource_record_data_t *soa = zdb_resource_record_sets_find_soa_and_ttl(&data->zone->apex->resource_record_set, &soa_ttl); // zone is locked

    if(soa == NULL)
    {
        zdb_zone_unlock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

        tcp_manager_channel_make_error_and_send(data->tmc, mesg, RCODE_SERVFAIL);

        /**
         * @note This does an exit with error.
         */

        data->return_code = ZDB_ERROR_NOSOAATAPEX;

        log_crit("zone write ixfr: %{dnsname}: no SOA in zone", data->zone->origin); /* will ultimately lead to the end of the program */

        zdb_zone_answer_ixfr_thread_finalize(data);

        return;
    }

    current_soa_rdata_size = zdb_resource_record_data_rdata_size(soa);
    memcpy(current_soa_rdata_buffer, zdb_resource_record_data_rdata(soa), current_soa_rdata_size);

    current_soa_tctrl.rtype = TYPE_SOA;
    current_soa_tctrl.rclass = CLASS_IN;
    current_soa_tctrl.ttl = htonl(soa_ttl);
    current_soa_tctrl.rdlen = htons((uint16_t)current_soa_rdata_size);

    zdb_zone_unlock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

    /***********************************************************************/

    /*
     * Adjust the message received size
     * get the queried serial number
     * Set the answer bit and clean the NS count
     */

    dns_packet_reader_t purd;
    dns_packet_reader_init_from_message(&purd, mesg);

    /* Keep only the query */

    if(FAIL(dns_packet_reader_skip_fqdn(&purd)))
    {
        log_crit("zone write ixfr: %{dnsname}: format error", data->zone->origin); /* will ultimately lead to the end of the program */
        zdb_zone_answer_ixfr_thread_close_finalize(data, MAKE_RCODE_ERROR(RCODE_FORMERR));
        return;
    }

    if(dns_packet_reader_available(&purd) < 4 + 10)
    {
        log_crit("zone write ixfr: %{dnsname}: format error", data->zone->origin); /* will ultimately lead to the end of the program */
        zdb_zone_answer_ixfr_thread_close_finalize(data, MAKE_RCODE_ERROR(RCODE_FORMERR));
        return;
    }

    purd.packet_offset += 4; // type & class

    dns_message_set_size(mesg, purd.packet_offset); // the part after this will be overwritten later

    /* Get the queried serial from the expected SOA record */

    if(FAIL(zdb_zone_answer_ixfr_thread_read_SOA_serial(data, &purd, &serial)))
    {
        log_crit("zone write ixfr: %{dnsname}: format error", data->zone->origin); /* will ultimately lead to the end of the program */
        zdb_zone_answer_ixfr_thread_close_finalize(data, MAKE_RCODE_ERROR(RCODE_FORMERR));
        return;
    }

    serial = ntohl(serial);

    log_debug("zone write ixfr: %{dnsname}: %{sockaddr}: client requested changes from serial %08x (%d)", data->zone->origin, dns_message_get_sender_sa(mesg), serial, serial);

    dns_message_set_authoritative_answer(mesg);
    dns_message_set_authority_count(mesg, 0);

    uint32_t journal_serial_from, journal_serial_to;
    return_value = zdb_zone_journal_get_serial_range(data->zone, &journal_serial_from, &journal_serial_to);

    dns_resource_record_t rr;
    dns_resource_record_init(&rr);

    if(ISOK(return_value))
    {
        if(serial_ge(serial, journal_serial_from) && serial_le(serial, journal_serial_to))
        {
            // good
            log_info("zone write ixfr: %{dnsname}: %{sockaddr}: host asked for serial %d which is in [%d; %d]", data->zone->origin, dns_message_get_sender_sa(mesg), serial, journal_serial_from, journal_serial_to);
            return_value = zdb_zone_journal_get_ixfr_stream_at_serial(data->zone, serial, &fis, &rr);
        }
        else
        {
            log_notice("zone write ixfr: %{dnsname}: %{sockaddr}: host asked for serial %d which is out of [%d; %d]", data->zone->origin, dns_message_get_sender_sa(mesg), serial, journal_serial_from, journal_serial_to);
            return_value = ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
        }
    }
    else
    {
        if(return_value == ZDB_ERROR_ICMTL_NOTFOUND)
        {
            log_notice(
                "zone write ixfr: %{dnsname}: %{sockaddr}: host asked for serial %d but there is no journal to be "
                "found",
                data->zone->origin,
                dns_message_get_sender_sa(mesg),
                serial);
        }
        else
        {
            if(return_value == ERROR)
            {
                return_value = ZDB_JOURNAL_IS_BUSY;
            }

            if(return_value == ZDB_JOURNAL_IS_BUSY)
            {
                log_notice(
                    "zone write ixfr: %{dnsname}: %{sockaddr}: host asked for serial %d but the journal is being "
                    "maintained",
                    data->zone->origin,
                    dns_message_get_sender_sa(mesg),
                    serial);
            }
        }
    }

#if 0
    if((rand() & 3) == 3)
    {
        if(ISOK(return_value))
        {
            dns_resource_record_clear(&rr);
            input_stream_close(&fis);
            return_value = ZDB_JOURNAL_IS_BUSY;
        }
    }
#endif

    if(FAIL(return_value))
    {
        dns_resource_record_clear(&rr);

        if(return_value != ZDB_JOURNAL_IS_BUSY)
        {
            zdb_zone_answer_axfr(data->zone, mesg, data->tmc, NULL, data->disk_tp, data->packet_size_limit, data->packet_records_limit, data->compress_dname_rdata);
        }
        else
        {
            dns_message_set_status(mesg, RCODE_SERVFAIL);
            dns_message_transform_to_signed_error(mesg);

            tcp_manager_channel_send(data->tmc, mesg);
        }

        data->return_code = return_value;
        zdb_zone_answer_ixfr_thread_finalize(data);

        return;
    }

    yassert(ISOK(return_value));
    // if the rdata is bigger than the maximum possible size, then something is wrong
    if(sizeof(target_soa_rdata_buffer) < rr.rdata_size) // scan-build (7) incoherence
    {
        uint32_t  from, to;
        ya_result range_ret = zdb_zone_journal_get_serial_range(data->zone, &from, &to);
        if(ISOK(range_ret))
        {
            log_warn("zone write ixfr: %{dnsname}: %{sockaddr}: unable to read journal from serial %d [%d; %d]", data->zone->origin, dns_message_get_sender_sa(mesg), serial, from, to);
        }
        else
        {
            log_err(
                "zone write ixfr: %{dnsname}: %{sockaddr}: unable to read journal from serial %d, cannot get its "
                "range: %r",
                data->zone->origin,
                dns_message_get_sender_sa(mesg),
                serial,
                range_ret);
        }

        dns_resource_record_clear(&rr);

        zdb_zone_answer_axfr(data->zone, mesg, data->tmc, NULL, data->disk_tp, data->packet_size_limit, data->packet_records_limit, data->compress_dname_rdata);

        data->return_code = BUFFER_WOULD_OVERFLOW;

        zdb_zone_answer_ixfr_thread_finalize(data);

        return;
    }
    // else we can proceed
    MEMCOPY(target_soa_rdata_buffer, rr.rdata, rr.rdata_size);
    // note: target_soa_rdata_size = rr.rdata_size;

    dns_resource_record_clear(&rr);

    /* fis points to the IX stream */

    MALLOC_OR_DIE(uint8_t *, rdata_buffer, RDATA_LENGTH_MAX, ZAIXFRRB_TAG); /* rdata max size */

    /***********************************************************************/

    /*
     * We will need to output the current SOA
     * But first, we have some setup to do.
     */

    /* It's TCP, my limit is 16 bits */
    // except if the buffer we are using is too small ...
    packet_size_limit = dns_message_get_buffer_size_max(mesg);

    packet_size_trigger = packet_size_limit / 2; // so, ~32KB, also : guarantees that there will be room for SOA & TSIG
    packet_records_limit = data->packet_records_limit;
    if(packet_records_limit <= 0)
    {
        packet_records_limit = INT32_MAX;
    }
    packet_records_countdown = packet_records_limit;

    dns_message_reset_buffer_size(mesg);

    dnsname_copy(origin, data->zone->origin);

    /* Sends the "Write unlocked" notification */

    log_info("zone write ixfr: %{dnsname}: %{sockaddr}: releasing implicit write lock", origin, dns_message_get_sender(mesg));

    tcp_manager_channel_t *tmc = data->tmc;

    data->mesg = NULL; // still need the message.  do not destroy it
    data->return_code = SUCCESS;

    zdb_zone_answer_ixfr_thread_finalize(data);

    /* WARNING: From this point forward, 'data' cannot be used anymore */

    data = NULL; /* WITH THIS I ENSURE A CRASH IF THE ABOVE COMMENT IS NOT FOLLOWED */

    /***********************************************************************/

    log_info("zone write ixfr: %{dnsname}: %{sockaddr}: sending journal from serial %d", origin, dns_message_get_sender_sa(mesg), serial);

    /* attach the tcp descriptor and put a buffer filter in front of the input and the output*/

    buffer_input_stream_init(&fis, &fis, FILE_BUFFER_SIZE);

    size_t query_size = dns_message_get_size(mesg);

    dns_packet_writer_init(&pw, dns_message_get_buffer(mesg), query_size, packet_size_limit - 780);

    /*
     * Init
     *
     * Write the final SOA (start of the IXFR stream)
     */

    dns_packet_writer_add_fqdn(&pw, (const uint8_t *)origin);
    dns_packet_writer_add_bytes(&pw, (const uint8_t *)&current_soa_tctrl, 8); /* not 10 ? */
    dns_packet_writer_add_rdata(&pw, TYPE_SOA, current_soa_rdata_buffer, current_soa_rdata_size);

    uint32_t last_serial;
    rr_soa_get_serial(current_soa_rdata_buffer, current_soa_rdata_size, &last_serial);

    an_count = 1 /*2*/;

    bool end_of_stream = false;

    int  soa_count = 0;

    for(;;)
    { // scan-build false positive: herein scan-build makes an assumption where return_value < 0
        if(FAIL(return_value = zdb_zone_answer_ixfr_read_record(&fis, fqdn, &qname_size, &tctrl, rdata_buffer, &rdata_size)))
        {
            // critical error.

            log_err("zone write ixfr: %{dnsname}: %{sockaddr}: read record #%d failed: %r", origin, dns_message_get_sender_sa(mesg), an_count, return_value);
            break;
        }

        // at this point, record_length >= 0
        // if record_length > 0 then tctrl has been set

        uint32_t record_length = return_value;
        // scan-build false positive: assumed record_length < 0 but takes the true branch
        if(record_length != 0) // a.k.a > 0
        {
            if(tctrl.rtype == TYPE_SOA) // scan-build (7) false positive: the path allegedly leading here lies on an incoherence
                                        // (assuming record_length < 0 followed by assuming record_length <= 0)
            {
                ++soa_count;

                // ensure we didn't go too far
                uint32_t soa_serial;
                rr_soa_get_serial(rdata_buffer, rdata_size, &soa_serial);
                if(serial_gt(soa_serial, last_serial))
                {
                    log_info("zone write ixfr: %{dnsname}: %{sockaddr}: cutting at serial %u", origin, dns_message_get_sender_sa(mesg), soa_serial);

                    record_length = 0; // will be seen as an EOF
                }

                if((soa_count & 1) != 0) // do not cut mid-page
                {
                    current_to_serial = soa_serial;

                    if(dnscore_shuttingdown())
                    {
                        log_info("zone write ixfr: %{dnsname}: %{sockaddr}: shutting down: cutting at serial %u", origin, dns_message_get_sender_sa(mesg), soa_serial);

                        record_length = 0; // will be seen as an EOF
                    }
                }
            }
        }

#if 0
        // DEBUG
        {
            rdata_desc_t rr_desc = {tctrl.qtype, rdata_size, rdata_buffer};
            log_debug("zone write ixfr: %{dnsname}: peek: (%3i) %{dnsname} %{typerdatadesc}", origin, record_length, fqdn, &rr_desc);
        }
#endif

        if(record_length == 0)
        {
#if DEBUG
            log_debug("zone write ixfr: %{dnsname}: %{sockaddr}: end of stream", origin, dns_message_get_sender(mesg));
#endif

#if ZDB_HAS_TSIG_SUPPORT
            if(pos != TSIG_START)
            {
                pos = TSIG_END;
            }
            else
            {
                pos = TSIG_WHOLE;
            }
#endif
            // Last SOA
            // There is no need to check for remaining space as packet_size_trigger guarantees there is still room

#if DEBUG
            {
                rdata_desc_t rr_desc = {TYPE_SOA, current_soa_rdata_size, current_soa_rdata_buffer};
                log_debug("zone write ixfr: %{dnsname}: closing: %{dnsname} %{typerdatadesc}", origin, origin, &rr_desc);
            }
#endif

            dns_packet_writer_add_fqdn(&pw, (const uint8_t *)origin);
            dns_packet_writer_add_bytes(&pw, (const uint8_t *)&current_soa_tctrl, 8); /* not 10 ? */
            dns_packet_writer_add_rdata(&pw, TYPE_SOA, current_soa_rdata_buffer, current_soa_rdata_size);

            ++an_count;

            end_of_stream = true;
        }
        else if(record_length > U16_MAX) // technically possible: a record too big to fit in an update (not likely)
        {
            // this is technically possible with an RDATA of 64K
            log_err("zone write ixfr: %{dnsname}: %{sockaddr}: ignoring record of size %u", origin, dns_message_get_sender_sa(mesg), record_length);
            rdata_desc_t rr_desc = {tctrl.rtype, rdata_size, rdata_buffer};
            log_err("zone write ixfr: %{dnsname}: %{sockaddr}: record is: %{dnsname} %{typerdatadesc}", origin, dns_message_get_sender_sa(mesg), fqdn, &rr_desc);
            continue;
        }

        // if the record puts us above the trigger, or if there is no more record to read, send the message

        if(pw.packet_offset + record_length >= packet_size_trigger || (packet_records_countdown-- <= 0) || end_of_stream)
        {
            // flush

            dns_message_set_answer_count(mesg, an_count);
            // message_set_size(mesg, dns_packet_writer_get_offset(&pw));

            if(ISOK(return_value = zdb_zone_answer_ixfr_send_message(tmc, &pw, mesg, pos)))
            {
                ++pages_sent;
                stream_serial = current_to_serial;
            }
            else
            {
                if(return_value == MAKE_ERRNO_ERROR(EPIPE))
                {
                    log_notice("zone write ixfr: %{dnsname}: %{sockaddr}: send message failed: client closed connection", origin, dns_message_get_sender_sa(mesg));
                }
                else
                {
                    log_notice("zone write ixfr: %{dnsname}: %{sockaddr}: send message failed: %r", origin, dns_message_get_sender_sa(mesg), return_value);
                }

                break;
            }

#if ZDB_HAS_TSIG_SUPPORT
            pos = TSIG_MIDDLE;
#endif
            dns_packet_writer_init(&pw, dns_message_get_buffer(mesg), query_size, packet_size_limit - 780);

            an_count = 0;

            if(end_of_stream)
            {
                break;
            }

            packet_records_countdown = packet_records_limit;
        }

#if IXFR_RECORD_SENDING_DEBUG
        {
            rdata_desc_t rr_desc = {tctrl.qtype, rdata_size, rdata_buffer};
            log_debug("zone write ixfr: %{dnsname}: sending: %{dnsname} %{typerdatadesc}", origin, fqdn, &rr_desc);
        }
#endif

        dns_packet_writer_add_fqdn(&pw, (const uint8_t *)fqdn);
        dns_packet_writer_add_bytes(&pw, (const uint8_t *)&tctrl, 8);
        dns_packet_writer_add_rdata(&pw, tctrl.rtype, rdata_buffer, rdata_size);

        ++an_count;
    }

    if(ISOK(return_value))
    {
        log_info("zone write ixfr: %{dnsname}: %{sockaddr}: incremental stream sent (serial %u)", origin, dns_message_get_sender(mesg), stream_serial);
    }
    else
    {
        if(pages_sent == 0)
        {
            log_warn("zone write ixfr: %{dnsname}: %{sockaddr}: incremental stream not sent", origin, dns_message_get_sender(mesg));
        }
        else
        {
            log_notice("zone write ixfr: %{dnsname}: %{sockaddr}: incremental stream partially sent (serial %u instead of %u)", origin, dns_message_get_sender(mesg), stream_serial, last_serial);
        }
    }

    if(input_stream_valid(&fis))
    {
        input_stream_close(&fis);
    }

    free(rdata_buffer);
    dns_message_delete(mesg);
}

/**
 *
 * Replies an (I)XFR stream to a secondary.
 *
 * @param zone The zone
 * @param mesg The original query
 * @param network_tp The network thread pool to use
 * @param disk_tp The disk thread pool to use
 * @param packet_size_limit the maximum size of a packet/message in the stream
 * @param packet_records_limit The maximum number of records in a single message (1 for very old servers)
 * @param compress_dname_rdata Allow fqdn compression
 *
 */

// zdb_zone_answer_ixfr_parm

void zdb_zone_answer_ixfr(zdb_zone_t *zone, dns_message_t *mesg, tcp_manager_channel_t *tmc, struct thread_pool_s *network_tp, struct thread_pool_s *disk_tp, uint32_t packet_size_limit, uint32_t packet_records_limit,
                          bool compress_dname_rdata)
{
    zdb_zone_answer_ixfr_args *args;

    dns_message_t             *clone = dns_message_dup(mesg);
    if(clone == NULL)
    {
        log_warn("zone write axfr: %{dnsname}: %{sockaddr}: cannot answer, message cannot be processed", zone->origin, dns_message_get_sender_sa(mesg));
        return; // BUFFER_WOULD_OVERFLOW;
    }

    log_info("zone write ixfr: %{dnsname}: %{sockaddr}: queueing answer", zone->origin, dns_message_get_sender_sa(mesg));

    MALLOC_OBJECT_OR_DIE(args, zdb_zone_answer_ixfr_args, ZAIXFRA_TAG);
    zdb_zone_acquire(zone);
    args->zone = zone;

    args->mesg = clone;
    args->disk_tp = disk_tp;
    args->tmc = tmc;
    args->packet_size_limit = packet_size_limit;
    args->packet_records_limit = packet_records_limit;
    args->compress_dname_rdata = compress_dname_rdata;

    if(network_tp != NULL)
    {
        /// note: never reached in practice
        args->threaded = true;
        tcp_manager_channel_acquire(tmc);
        thread_pool_enqueue_call(network_tp, zdb_zone_answer_ixfr_thread, args, NULL, "zone-answer-ixfr");
    }
    else
    {
        args->threaded = false;
        zdb_zone_answer_ixfr_thread(args);
    }
}

/** @} */

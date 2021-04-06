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

/** @defgroup dnsdbixfr IXFR answers
 *  @ingroup dnsdb
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>

#include "dnsdb/zdb-config-features.h"

#include <dnscore/logger.h>
#include <dnscore/thread_pool.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/format.h>
#include <dnscore/packet_writer.h>
#include <dnscore/packet_reader.h>
#include <dnscore/rfc.h>
#include <dnscore/serial.h>
#if DNSCORE_HAS_TCP_MANAGER
#include <dnscore/tcp_manager.h>
#endif

#if DEBUG
#include <dnscore/logger-output-stream.h>
#endif

#include "dnsdb/zdb-zone-journal.h"
#include "dnsdb/zdb_icmtl.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_utils.h"

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_types.h"

#include "dnsdb/zdb-zone-answer-axfr.h"

#define TCP_BUFFER_SIZE     4096
#define FILE_BUFFER_SIZE    4096

#define RECORD_MODE_DELETE  0
#define RECORD_MODE_ADD     1

#define ZAIXFRRB_TAG 0x425252465849415a
/*
 * Typically it goes 4 3 [2,1]+ 0
 */

#define MODULE_MSG_HANDLE g_database_logger
extern logger_handle* g_database_logger;

#define TCP_BUFFER_SIZE     4096
#define FILE_BUFFER_SIZE    4096

#define RECORD_MODE_DELETE  0
#define RECORD_MODE_ADD     1


/*
 * Typically it goes 4 3 [2,1]+ 0
 */

extern logger_handle* g_database_logger;

#ifndef PATH_MAX
#error "PATH_MAX not defined"
#endif

typedef struct zdb_zone_answer_ixfr_args zdb_zone_answer_ixfr_args;

#define ZAIXFRA_TAG 0x4152465849415a

struct zdb_zone_answer_ixfr_args
{
    zdb_zone *zone;
    message_data *mesg;
    struct thread_pool_s *disk_tp;
#if DNSCORE_HAS_TCP_MANAGER
    tcp_manager_socket_context_t *sctx;
#else
    int sockfd;
#endif
    ya_result return_code;
    u32 packet_size_limit;
    u32 packet_records_limit;
    u32 from_serial;
    bool compress_dname_rdata;
};

static void
zdb_zone_answer_ixfr_thread_exit(zdb_zone_answer_ixfr_args* data)
{
    log_debug("zone write ixfr: ended with: %r", data->return_code);

    zdb_zone_release(data->zone);

#if DNSCORE_HAS_TCP_MANAGER
    if(data->sctx != NULL)
    {
        tcp_manager_context_release(data->sctx);
        data->sctx = NULL;
    }
#endif
    
    if(data->mesg != NULL)
    {
        message_free(data->mesg);
    }
    //free(data->directory);
    free(data);
}

static ya_result
zdb_zone_answer_ixfr_read_record(input_stream *is, u8 *qname, u32 *qname_sizep, struct type_class_ttl_rdlen *tctrlp, u8 *rdata_buffer, u32 *rdata_sizep)
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

        tctrlp->qtype = 0;
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

extern u16 edns0_maxsize;

#if ZDB_HAS_TSIG_SUPPORT
static ya_result
zdb_zone_answer_ixfr_send_message(output_stream *tcpos, packet_writer *pw, message_data *mesg, tsig_tcp_message_position pos)
#else
static ya_result
zdb_zone_answer_ixfr_send_message(output_stream *tcpos, packet_writer *pw, message_data *mesg)
#endif
{
    ya_result return_code;
    
    /*
     * Flush and stop
     */

#if DEBUG
    log_debug("zone write ixfr: %{dnsname}: sending message for %{dnsname} to %{sockaddr}", message_get_canonised_fqdn(mesg), message_get_canonised_fqdn(mesg), message_get_sender(mesg));
#endif
    
    if(message_is_edns0(mesg)) // Dig does a TCP query with EDNS0
    {
        /* 00 00 29 SS SS rr vv 80 00 00 00 */

        memset(packet_writer_get_next_u8_ptr(pw), 0, EDNS0_RECORD_SIZE);
        packet_writer_forward(pw, 2);
        packet_writer_add_u8(pw, 0x29);
        packet_writer_add_u16(pw, htons(edns0_maxsize));
        packet_writer_add_u32(pw, message_get_rcode_ext(mesg));
        packet_writer_forward(pw, 2);
        message_set_additional_count_ne(mesg, NETWORK_ONE_16);
    }
    else
    {
        message_set_additional_count_ne(mesg, 0);
    }

    message_set_size(mesg, packet_writer_get_offset(pw));
        
#if ZDB_HAS_TSIG_SUPPORT
    if(message_has_tsig(mesg))
    {
        message_set_additional_section_ptr(mesg, packet_writer_get_next_u8_ptr(pw));

        if(FAIL(return_code = tsig_sign_tcp_message(mesg, pos)))
        {
            log_err("zone write ixfr: failed to sign the answer: %r", return_code);

            return return_code;
        }
    }
#endif
    
    packet_writer_set_offset(pw, message_get_size(mesg));
    

    
    if(FAIL(return_code = write_tcp_packet(pw, tcpos)))
    {
        if(return_code == MAKE_ERRNO_ERROR(EPIPE))
        {
            log_notice("zone write ixfr: %{dnsname}: %{sockaddr}: error sending IXFR message: client closed connection", message_get_canonised_fqdn(mesg), message_get_sender_sa(mesg));
        }
        else
        {
            log_notice("zone write ixfr: %{dnsname}: %{sockaddr}: error sending IXFR message: %r", message_get_canonised_fqdn(mesg), message_get_sender_sa(mesg), return_code);
        }
    }

    return return_code;
}

/*
 * writes the filtered stream to a file, then adds it to the journal
 * the journal needs to give fast access to the last SOA in it ...
 * 
 */

static void*
zdb_zone_answer_ixfr_thread(void* data_)
{
    zdb_zone_answer_ixfr_args* data = (zdb_zone_answer_ixfr_args*)data_;
    message_data *mesg = data->mesg;

    /* The TCP output stream */

    output_stream tcpos;

    /* The incremental file input stream */

    input_stream fis;
    
    /* The packet writer */

    /* Current SOA */

    u32 current_soa_rdata_size;
    //u16 target_soa_rdata_size = MAX_SOA_RDATA_LENGTH;
    
    struct type_class_ttl_rdlen current_soa_tctrl;    

    /*
     */

    u8 *rdata_buffer = NULL;
    struct type_class_ttl_rdlen tctrl;
    u32 qname_size;
    u32 rdata_size = 0;
    
    packet_writer pw;
    
    u8 current_soa_rdata_buffer[MAX_SOA_RDATA_LENGTH];    
    u8 target_soa_rdata_buffer[MAX_SOA_RDATA_LENGTH];
    u8 fqdn[MAX_DOMAIN_LENGTH];

    /*
     */

    ya_result return_value;
    
    u32 serial = 0;
    u16 an_count = 0;
    s32 pages_sent = 0;
    u32 current_to_serial = 0;
    u32 stream_serial = 0;

    u32 packet_size_limit;
    u32 packet_size_trigger;
    s32 packet_records_limit;
    s32 packet_records_countdown;

#if ZDB_HAS_TSIG_SUPPORT
    tsig_tcp_message_position pos = TSIG_START;
#endif

    /*
     * relevant data for when data is not usable anymore
     */

    u8 origin[MAX_DOMAIN_LENGTH];
    
    /*
     */

    log_info("zone write ixfr: %{dnsname}: sending journal file", data->zone->origin);
    
    /***********************************************************************/

#if DNSCORE_HAS_TCP_MANAGER
    if(!tcp_manager_is_valid(data->sctx))
    {
        log_err("zone write ixfr: %{dnsname}: no connection", data->zone->origin);

        data->return_code = MAKE_ERRNO_ERROR(ENOTSOCK);

        zdb_zone_answer_ixfr_thread_exit(data);

        return NULL;
    }
#else
    if(data->sockfd < 0)
    {
        log_err("zone write ixfr: %{dnsname}: no TCP socket set for operation", data->zone->origin);

        data->return_code = MAKE_ERRNO_ERROR(ENOTSOCK);

        zdb_zone_answer_ixfr_thread_exit(data);
        
        return NULL;
    }
#endif
    /***********************************************************************/

    zdb_zone_lock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    /* Keep a snapshot of the current SOA */

    zdb_packed_ttlrdata* soa = zdb_record_find(&data->zone->apex->resource_record_set, TYPE_SOA); // zone is locked
    
    if(soa == NULL)
    {
        zdb_zone_unlock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

#if DNSCORE_HAS_TCP_MANAGER
        if(ISOK(message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcp_manager_socket(data->sctx))))
        {
            tcp_manager_write_update(data->sctx, message_get_size(mesg));
        }
#else
        message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, data->sockfd);
#endif

        /**
         * @note This does an exit with error.
         */

#if DNSCORE_HAS_TCP_MANAGER
        tcp_manager_close(data->sctx);
#else
        shutdown(data->sockfd, SHUT_RDWR);
        close_ex(data->sockfd);
        data->sockfd = -1;
#endif

        
        data->return_code = ZDB_ERROR_NOSOAATAPEX;

        log_crit("zone write ixfr: %{dnsname}: no SOA in zone", data->zone->origin); /* will ultimately lead to the end of the program */
        
        zdb_zone_answer_ixfr_thread_exit(data);
                
        return NULL;        
    }

    current_soa_rdata_size = soa->rdata_size;
    memcpy(current_soa_rdata_buffer, ZDB_PACKEDRECORD_PTR_RDATAPTR(soa), current_soa_rdata_size);

    current_soa_tctrl.qtype  = TYPE_SOA;
    current_soa_tctrl.qclass = CLASS_IN;
    current_soa_tctrl.ttl    = htonl(soa->ttl);
    current_soa_tctrl.rdlen  = htons(soa->rdata_size);
    
    zdb_zone_unlock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

    /***********************************************************************/

    /*
     * Adjust the message received size
     * get the queried serial number
     * Set the answer bit and clean the NS count
     */

    packet_unpack_reader_data purd;    
    packet_reader_init_from_message(&purd, mesg);

    /* Keep only the query */

    packet_reader_skip_fqdn(&purd);
    purd.offset += 4;

    message_set_size(mesg, purd.offset);

    /* Get the queried serial */

    packet_reader_skip_fqdn(&purd);
    
    purd.offset += 2 + 2 + 4 + 2;

    packet_reader_skip_fqdn(&purd);
    packet_reader_skip_fqdn(&purd);
    packet_reader_read(&purd, (u8*)&serial, 4);
    serial = ntohl(serial);
    
    log_debug("zone write ixfr: %{dnsname}: %{sockaddr}: client requested changes from serial %08x (%d)", data->zone->origin, message_get_sender_sa(mesg), serial, serial);

    message_set_authoritative_answer(mesg);
    message_set_authority_count(mesg, 0);
    
    dns_resource_record rr;
    dns_resource_record_init(&rr);
    
    if(FAIL(return_value = zdb_zone_journal_get_ixfr_stream_at_serial(data->zone, serial, &fis, &rr)))
    {
        if(return_value == ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE)
        {
            u32 from, to;
            
            ya_result range_ret = zdb_zone_journal_get_serial_range(data->zone, &from, &to);
            
            if(ISOK(range_ret))
            {
                log_info("zone write ixfr: %{dnsname}: %{sockaddr}: host asked for serial %d out of the journal range [%d; %d]", data->zone->origin, message_get_sender_sa(mesg), serial, from, to);
            }
            else
            {
                log_err("zone write ixfr: %{dnsname}: %{sockaddr}: host asked for serial %d, but the journal range cannot be retrieved: %r", data->zone->origin, message_get_sender_sa(mesg), serial, range_ret);
            }
        }
        else
        {
            if(return_value != ZDB_ERROR_ICMTL_NOTFOUND)
            {
                if(return_value != /**/ ERROR)
                {
                    log_err("zone write ixfr: %{dnsname}: %{sockaddr}: unable to open journal: %r", data->zone->origin, message_get_sender_sa(mesg), return_value);
                }
                else // a generic error occurs when the journal is being maintained
                {
                    log_info("zone write ixfr: %{dnsname}: %{sockaddr}: journal is busy", data->zone->origin, message_get_sender_sa(mesg));
                    return_value = ZDB_JOURNAL_IS_BUSY;
                }
            }
            else
            {
                log_debug("zone write ixfr: %{dnsname}: %{sockaddr}: there is no journal", data->zone->origin, message_get_sender_sa(mesg));
            }
        }
        
        dns_resource_record_clear(&rr);

#if DNSCORE_HAS_TCP_MANAGER
        zdb_zone_answer_axfr(data->zone, mesg, data->sctx, NULL, data->disk_tp, data->packet_size_limit, data->packet_records_limit, data->compress_dname_rdata);
#else
        zdb_zone_answer_axfr(data->zone, mesg, data->sockfd, NULL, data->disk_tp, data->packet_size_limit, data->packet_records_limit, data->compress_dname_rdata);
        data->sockfd = -1;
#endif
        data->return_code = return_value;

        zdb_zone_answer_ixfr_thread_exit(data);
        
        return NULL;
    }

    yassert(ISOK(return_value));

    if(sizeof(target_soa_rdata_buffer) < rr.rdata_size) // scan-build (7) incoherence
    {
        u32 from, to;
        ya_result range_ret = zdb_zone_journal_get_serial_range(data->zone, &from, &to);
        if(ISOK(range_ret))
        {
            log_warn("zone write ixfr: %{dnsname}: %{sockaddr}: unable to read journal from serial %d [%d; %d]", data->zone->origin, message_get_sender_sa(mesg), serial, from, to);
        }
        else
        {
            log_err("zone write ixfr: %{dnsname}: %{sockaddr}: unable to read journal from serial %d, cannot get its range: %r", data->zone->origin, message_get_sender_sa(mesg), serial, range_ret);
        }
        
        dns_resource_record_clear(&rr);

#if DNSCORE_HAS_TCP_MANAGER
        zdb_zone_answer_axfr(data->zone, mesg, data->sctx, NULL, data->disk_tp, data->packet_size_limit, data->packet_records_limit, data->compress_dname_rdata);
#else
        zdb_zone_answer_axfr(data->zone, mesg, data->sockfd, NULL, data->disk_tp, data->packet_size_limit, data->packet_records_limit, data->compress_dname_rdata);
        data->sockfd = -1;
#endif

        data->return_code = BUFFER_WOULD_OVERFLOW;
        
        zdb_zone_answer_ixfr_thread_exit(data);
        
        return NULL;
    }
    
    MEMCOPY(target_soa_rdata_buffer, rr.rdata, rr.rdata_size);
    // note: target_soa_rdata_size = rr.rdata_size;
    
    dns_resource_record_clear(&rr);
    
    /* fis points to the IX stream */
    
    MALLOC_OR_DIE(u8*, rdata_buffer, RDATA_MAX_LENGTH, ZAIXFRRB_TAG);    /* rdata max size */

    /***********************************************************************/
    
    /*
     * We will need to output the current SOA
     * But first, we have some setup to do.
     */

    /* It's TCP, my limit is 16 bits */
    // except if the buffer we are using is too small ...
    packet_size_limit = message_get_buffer_size_max(mesg);
    
    packet_size_trigger = packet_size_limit / 2; // so, ~32KB, also : guarantees that there will be room for SOA & TSIG
    packet_records_limit = data->packet_records_limit;
    if(packet_records_limit <= 0)
    {
        packet_records_limit = MAX_S32;
    }
    packet_records_countdown = packet_records_limit;

    message_reset_buffer_size(mesg);

#if DNSCORE_HAS_TCP_MANAGER
    tcp_manager_socket_context_t *sctx = tcp_manager_context_acquire(data->sctx);
#else
    int tcpfd = data->sockfd;
    data->sockfd = -1;
#endif
    
    dnsname_copy(origin, data->zone->origin);

    /* Sends the "Write unlocked" notification */

    log_info("zone write ixfr: %{dnsname}: %{sockaddr}: releasing implicit write lock", origin, message_get_sender(mesg));

    data->mesg = NULL; // still need the message.  do not destroy it
    data->return_code = SUCCESS;
    
    zdb_zone_answer_ixfr_thread_exit(data);

    /* WARNING: From this point forward, 'data' cannot be used anymore */

    data = NULL; /* WITH THIS I ENSURE A CRASH IF THE ABOVE COMMENT IS NOT FOLLOWED */
    
    /***********************************************************************/

    log_info("zone write ixfr: %{dnsname}: %{sockaddr}: sending journal from serial %d", origin, message_get_sender_sa(mesg), serial);

    /* attach the tcp descriptor and put a buffer filter in front of the input and the output*/

#if DNSCORE_HAS_TCP_MANAGER
    fd_output_stream_attach(&tcpos, tcp_manager_socket(sctx));
#else
    fd_output_stream_attach(&tcpos, tcpfd);
#endif

    buffer_input_stream_init(&fis, &fis, FILE_BUFFER_SIZE);
    buffer_output_stream_init(&tcpos, &tcpos, TCP_BUFFER_SIZE);
    
    size_t query_size = message_get_size(mesg);

    packet_writer_init(&pw, message_get_buffer(mesg), query_size, packet_size_limit - 780);

    /*
     * Init
     * 
     * Write the final SOA (start of the IXFR stream)
     */
   
    packet_writer_add_fqdn(&pw, (const u8*)origin);
    packet_writer_add_bytes(&pw, (const u8*)&current_soa_tctrl, 8); /* not 10 ? */
    packet_writer_add_rdata(&pw, TYPE_SOA, current_soa_rdata_buffer, current_soa_rdata_size);
    
    u32 last_serial;
    rr_soa_get_serial(current_soa_rdata_buffer, current_soa_rdata_size, &last_serial);

    an_count = 1 /*2*/;

    bool end_of_stream = FALSE;

    int soa_count = 0;
    
    for(;;)
    {
        if(FAIL(return_value = zdb_zone_answer_ixfr_read_record(&fis, fqdn, &qname_size, &tctrl, rdata_buffer, &rdata_size)))
        {
            // critical error.

            log_err("zone write ixfr: %{dnsname}: %{sockaddr}: read record #%d failed: %r", origin, message_get_sender_sa(mesg), an_count, return_value);
            break;
        }

#if DNSCORE_HAS_TCP_MANAGER
        tcp_manager_read_update(sctx, return_value);
#endif

        // at this point, record_length >= 0
        // if record_length > 0 then tctrl has been set
        
        u32 record_length = return_value;
        
        if(record_length > 0)
        {
            if(tctrl.qtype == TYPE_SOA) // scan-build (7) false positive: the path allegedly leading here lies on an incoherence (record_length <= 0)
            {
                ++soa_count;

                // ensure we didn't go too far
                u32 soa_serial;
                rr_soa_get_serial(rdata_buffer, rdata_size, &soa_serial);
                if(serial_gt(soa_serial, last_serial))
                {
                    log_info("zone write ixfr: %{dnsname}: %{sockaddr}: cutting at serial %u", origin, message_get_sender_sa(mesg), soa_serial);

                    record_length = 0; // will be seen as an EOF
                }

                if((soa_count & 1) != 0) // do not cut mid-page
                {
                    current_to_serial = soa_serial;

                    if(dnscore_shuttingdown())
                    {
                        log_info("zone write ixfr: %{dnsname}: %{sockaddr}: shutting down: cutting at serial %u", origin, message_get_sender_sa(mesg), soa_serial);

                        record_length = 0; // will be seen as an EOF
                    }
                }
            }
        }

        if(record_length == 0)
        {
#if DEBUG
            log_debug("zone write ixfr: %{dnsname}: %{sockaddr}: end of stream", origin, message_get_sender(mesg));
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
            
#if  DEBUG
            {
                rdata_desc rr_desc = {TYPE_SOA, current_soa_rdata_size, current_soa_rdata_buffer};                            
                log_debug("zone write ixfr: %{dnsname}: closing: %{dnsname} %{typerdatadesc}", origin, origin, &rr_desc);
            }
#endif

            packet_writer_add_fqdn(&pw, (const u8*)origin);
            packet_writer_add_bytes(&pw, (const u8*)&current_soa_tctrl, 8); /* not 10 ? */
            packet_writer_add_rdata(&pw, TYPE_SOA, current_soa_rdata_buffer, current_soa_rdata_size);

            ++an_count;
            
            end_of_stream = TRUE;
        }
        else if(record_length > MAX_U16) // technically possible: a record too big to fit in an update (not likely)
        {
            // this is technically possible with an RDATA of 64K
            log_err("zone write ixfr: %{dnsname}: %{sockaddr}: ignoring record of size %u", origin, message_get_sender_sa(mesg), record_length);
            rdata_desc rr_desc = {tctrl.qtype, rdata_size, rdata_buffer};                            
            log_err("zone write ixfr: %{dnsname}: %{sockaddr}: record is: %{dnsname} %{typerdatadesc}", origin, message_get_sender_sa(mesg), return_value, fqdn, &rr_desc);
            continue;
        }
        
        // if the record puts us above the trigger, or if there is no more record to read, send the message
        
        if(pw.packet_offset + record_length >= packet_size_trigger || (packet_records_countdown-- <= 0) || end_of_stream)
        {
            // flush

            message_set_answer_count(mesg, an_count);
            //message_set_size(mesg, packet_writer_get_offset(&pw));

#if ZDB_HAS_TSIG_SUPPORT
            if(ISOK(return_value = zdb_zone_answer_ixfr_send_message(&tcpos, &pw, mesg, pos)))
#else
            if(ISOK(return_value = zdb_zone_answer_ixfr_send_message(&tcpos, &pw, mesg)))
#endif
            {
#if DNSCORE_HAS_TCP_MANAGER
                tcp_manager_write_update(sctx, return_value);
#endif
                ++pages_sent;
                stream_serial = current_to_serial;
            }
            else
            {
                if(return_value == MAKE_ERRNO_ERROR(EPIPE))
                {
                    log_notice("zone write ixfr: %{dnsname}: %{sockaddr}: send message failed: client closed connection", origin, message_get_sender_sa(mesg));
                }
                else
                {
                    log_notice("zone write ixfr: %{dnsname}: %{sockaddr}: send message failed: %r", origin, message_get_sender_sa(mesg), return_value);
                }

                break;
            }

#if ZDB_HAS_TSIG_SUPPORT
            pos = TSIG_MIDDLE;
#endif
            packet_writer_init(&pw, message_get_buffer(mesg), query_size, packet_size_limit - 780);

            an_count = 0;
            
            if(end_of_stream)
            {
                break;
            }
            
            packet_records_countdown = packet_records_limit;
        }
        
#if  DEBUG
        {
            rdata_desc rr_desc = {tctrl.qtype, rdata_size, rdata_buffer};                            
            log_debug("zone write ixfr: %{dnsname}: sending: %{dnsname} %{typerdatadesc}", origin, fqdn, &rr_desc);
        }
#endif

        packet_writer_add_fqdn(&pw, (const u8*)fqdn);
        packet_writer_add_bytes(&pw, (const u8*)&tctrl, 8);
        packet_writer_add_rdata(&pw, tctrl.qtype, rdata_buffer, rdata_size);
        
        ++an_count;
    }

    if(ISOK(return_value))
    {
        log_info("zone write ixfr: %{dnsname}: %{sockaddr}: incremental stream sent (serial %u)", origin, message_get_sender(mesg), stream_serial);
    }
    else
    {
        if(pages_sent == 0)
        {
            log_warn("zone write ixfr: %{dnsname}: %{sockaddr}: incremental stream not sent", origin, message_get_sender(mesg));
        }
        else
        {
            log_notice("zone write ixfr: %{dnsname}: %{sockaddr}: incremental stream partially sent (serial %u instead of %u)", origin, message_get_sender(mesg), stream_serial, last_serial);
        }
    }


#if DNSCORE_HAS_TCP_MANAGER
    output_stream_flush(&tcpos);
    output_stream *tcpos_filtered = buffer_output_stream_get_filtered(&tcpos);
    fd_output_stream_detach(tcpos_filtered);
#endif
    output_stream_close(&tcpos);
    if(input_stream_valid(&fis))
    {
        input_stream_close(&fis);
    }

    free(rdata_buffer);
    message_free(mesg);

    return NULL;
}

/**
 * 
 * Replies an (I)XFR stream to a slave.
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

//zdb_zone_answer_ixfr_parm

void
zdb_zone_answer_ixfr(
    zdb_zone* zone,
    message_data *mesg,
#if DNSCORE_HAS_TCP_MANAGER
    tcp_manager_socket_context_t *sctx,
#else
    int sockfd,
#endif
    struct thread_pool_s *network_tp,
    struct thread_pool_s *disk_tp,
    u32 packet_size_limit,
    u32 packet_records_limit,
    bool compress_dname_rdata)
{
    zdb_zone_answer_ixfr_args* args;
        
    log_info("zone write ixfr: %{dnsname}: %{sockaddr}: queueing answer", zone->origin, message_get_sender_sa(mesg));
    
    MALLOC_OBJECT_OR_DIE(args, zdb_zone_answer_ixfr_args, ZAIXFRA_TAG);
    zdb_zone_acquire(zone);
    args->zone = zone;

    args->mesg = message_dup(mesg);
    args->disk_tp = disk_tp;
#if DNSCORE_HAS_TCP_MANAGER
    args->sctx = sctx;
#else
    args->sockfd = sockfd;
#endif
    args->packet_size_limit = packet_size_limit;
    args->packet_records_limit = packet_records_limit;
    args->compress_dname_rdata = compress_dname_rdata;

    if(network_tp != NULL)
    {
        thread_pool_enqueue_call(network_tp, zdb_zone_answer_ixfr_thread, args, NULL, "zone-answer-ixfr");
    }
    else
    {
        zdb_zone_answer_ixfr_thread(args);
    }
}

/** @} */


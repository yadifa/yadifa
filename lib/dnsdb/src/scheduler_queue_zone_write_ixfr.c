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
* DOCUMENTATION */
/** @defgroup dnsdbscheduler Scheduled tasks of the database
 *  @ingroup dnsdb
 *  @brief
 *
 *
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>

#include <dnscore/logger.h>
#include <dnscore/thread_pool.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/scheduler.h>
#include <dnscore/format.h>
#include <dnscore/packet_writer.h>
#include <dnscore/rfc.h>
#include <dnscore/serial.h>
#include <dnscore/xfr_copy.h>

#include "dnsdb/zdb_icmtl.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_utils.h"

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_types.h"

/* dnssec_scheduler.h */

void      scheduler_queue_zone_send_axfr(zdb_zone *zone, const char *directory, u32 packet_size_limit, u32 packet_records_limit, bool compress_dname_rdata, message_data *mesg);

#define MODULE_MSG_HANDLE g_database_logger

#define TCP_BUFFER_SIZE     4096
#define FILE_BUFFER_SIZE    4096

#define RECORD_MODE_DELETE  0
#define RECORD_MODE_ADD     1

/*
 * Typically it goes 4 3 [2,1]+ 0
 */

extern logger_handle* g_database_logger;

#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

typedef struct scheduler_queue_zone_write_ixfr_args scheduler_queue_zone_write_ixfr_args;

struct scheduler_queue_zone_write_ixfr_args
{
    zdb_zone *zone;
    char *directory;
    message_data *mesg;
    ya_result return_code;
    u32 packet_size_limit;
    u32 packet_records_limit;
    u32 from_serial;
    bool compress_dname_rdata;
};

static ya_result
scheduler_queue_zone_write_ixfr_callback(void* data_)
{
    scheduler_queue_zone_write_ixfr_args* data = (scheduler_queue_zone_write_ixfr_args*)data_;

    log_debug("zone write ixfr: ended with: %r", data->return_code);

    /*free(data->mesg);*/
    free(data->directory);
    free(data);

    return SCHEDULER_TASK_FINISHED; /* Notify the end of the writer job */
}

static ya_result
scheduler_queue_zone_write_ixfr_read_record(input_stream *is, u8 *qname, u32 *qname_sizep, struct type_class_ttl_rdlen *tctrlp, u8 *rdata_buffer, u32 *rdata_sizep)
{
    ya_result return_code;

    /* Read the next DNAME from the stored INCREMENTAL */

    if(FAIL(return_code = input_stream_read_dnsname(is, qname)))
    {
        log_err("zone write ixfr: error reading IXFR qname: %r", return_code);
        return return_code;
    }

    *qname_sizep = return_code;

    if(return_code > 0)
    {
        /* read the next type+class+ttl+rdatalen from the stored IXFR */

        tctrlp->qtype = 0;
        tctrlp->rdlen = 0;

        if(FAIL(return_code = input_stream_read_fully(is, (u8*) tctrlp, 10)))
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

    return return_code;
}

/*
 * mesg is needed for TSIG
 */

static ya_result
scheduler_queue_zone_write_ixfr_send_message(output_stream *tcpos, packet_writer *pw, message_data *mesg, tsig_tcp_message_position pos)
{
    ya_result return_code;
    
    /*
     * Flush and stop
     */

#ifndef NDEBUG
    log_debug("zone write ixfr: sending message for %{dnsname}", mesg->qname);
#endif

    mesg->send_length = pw->packet_offset; /** @todo: I need to put this in a packet_writer function */

    if(TSIG_ENABLED(mesg))
    {
        mesg->ar_start = &pw->packet[pw->packet_offset];

        if(FAIL(return_code = tsig_sign_tcp_message(mesg, pos)))
        {
            log_err("zone write ixfr: failed to sign the answer: %r", return_code);

            return return_code;
        }
    }

    pw->packet_offset = mesg->send_length; /** @todo: I need to put this in a packet_writer function */
    if(FAIL(return_code = write_tcp_packet(pw, tcpos)))
    {
        log_err("zone write ixfr: error sending IXFR packet: %r", return_code);
    }

    return return_code;
}

/*
 * IXFR is much more complicated than AXFR
 * 
 * There are many annoying cases.
 * 
 * We need to handle multiple incremental files (in sequence)
 * 
 * What about an update close to the limit of the file size ?
 * 
 * There is an easy way but it's far from optimal.
 * 
 */

static void*
scheduler_queue_zone_write_ixfr_thread(void* data_)
{
    scheduler_queue_zone_write_ixfr_args* data = (scheduler_queue_zone_write_ixfr_args*)data_;
    message_data *mesg = data->mesg;

    /* The TCP output stream */

    output_stream tcpos;

    /* The incremental file input stream */

    input_stream fis;
    
    /* The packet writer */

    packet_writer pw;

    /* Current SOA */

    struct type_class_ttl_rdlen current_soa_tctrl;
    u32 current_soa_rdata_size;
    u8 current_soa_rdata_buffer[780];

    /*
     */

    u8 *rdata_buffer = NULL;
    struct type_class_ttl_rdlen tctrl;
    u32 qname_size;
    u32 rdata_size;
    u8 fqdn[MAX_DOMAIN_LENGTH];

    /*
     */

    ya_result return_code;

    u32 serial = 0;
    u16 an_record_count = 0;
    u8  record_mode;
    
    u32 packet_size_limit;
    u32 packet_size_trigger;

    tsig_tcp_message_position pos = TSIG_START;

    /*
     */

    u32 last_valid_serial;
    u32 last_valid_offset = DNS_HEADER_LENGTH;
    u16 last_valid_count = 0;

    /*
     * relevant data for when data is not usable anymore
     */

    u8 origin[MAX_DOMAIN_LENGTH];
    char directory[MAX_PATH];

    /*
     */

    log_info("zone write ixfr: writing %{dnsname} %d journal file", data->zone->origin, serial);
    
    /***********************************************************************/

    if(data->mesg->sockfd < 0)
    {
        log_err("zone write ixfr: no tcp: %{dnsname} %d", data->zone->origin, serial);

        data->return_code = ERROR;

        free(mesg);
        return NULL;
    }

    /***********************************************************************/

    /* Keep a snapshot of the current SOA */

    zdb_packed_ttlrdata* soa = zdb_record_find(&data->zone->apex->resource_record_set, TYPE_SOA);
    
    if(soa == NULL)
    {
        /** @todo error other than "does not exists" : SERVFAIL */

        /**
         * @note This does an exit with error.
         */
        
        free(mesg);
        data->mesg = NULL;
        data->return_code = ZDB_ERROR_NOSOAATAPEX;

        scheduler_schedule_task(scheduler_queue_zone_write_ixfr_callback, data);

        log_crit("zone write ixfr: startup: no SOA"); /* will ultimately lead to the end of the program */
        
        return NULL;        
    }

    current_soa_rdata_size = soa->rdata_size;
    memcpy(current_soa_rdata_buffer, ZDB_PACKEDRECORD_PTR_RDATAPTR(soa), current_soa_rdata_size);

    current_soa_tctrl.qtype  = TYPE_SOA;
    current_soa_tctrl.qclass = CLASS_IN;
    current_soa_tctrl.ttl    = htonl(soa->ttl);
    current_soa_tctrl.rdlen  = htons(soa->rdata_size);

    /***********************************************************************/

    /*
     * Adjust the message received size
     * get the queried serial number
     * Set the answer bit and clean the NS count
     */

    packet_unpack_reader_data purd;
    purd.packet = mesg->buffer;
    purd.packet_size = mesg->received;
    purd.offset = 12;

    /* Keep only the query */

    packet_reader_skip_fqdn(&purd);
    purd.offset += 4;

    mesg->received = purd.offset;

    /* Get the queried serial */

    packet_reader_skip_fqdn(&purd);
    
    purd.offset += 2 + 2 + 4 + 2;

    packet_reader_skip_fqdn(&purd);
    packet_reader_skip_fqdn(&purd);
    packet_reader_read(&purd, (u8*)&serial, 4);
    serial=ntohl(serial);

    MESSAGE_HIFLAGS(mesg->buffer) |= AA_BITS|QR_BITS;
    MESSAGE_NS(mesg->buffer) = 0;

    MALLOC_OR_DIE(u8*, rdata_buffer, RDATA_MAX_LENGTH, GENERIC_TAG);    /* rdata max size */

    /***********************************************************************/
    
    char data_path[1024];
        
    if(FAIL(return_code = xfr_copy_make_data_path(data->directory, data->zone->origin, data_path, sizeof(data_path))))
    {
        log_err("zone write ixfr: unable to make folder for %{dnsname}: %r", data->zone->origin, return_code);
        
        free(rdata_buffer);
        
        scheduler_queue_zone_send_axfr(data->zone, data->directory, data->packet_size_limit, data->packet_records_limit, data->compress_dname_rdata, mesg);
        scheduler_schedule_task(scheduler_queue_zone_write_ixfr_callback, data);
        
        return NULL;
    }

    /* Try to read the first queried SOA */

    log_info("zone write ixfr: fetching first SOA %{dnsname} %d", data->zone->origin, serial);

    if(FAIL(return_code = zdb_icmtl_open_ix_get_soa(data->zone->origin, data_path, serial, &fis,  &tctrl, rdata_buffer, &rdata_size)))
    {
        log_err("zone write ixfr: path '" ICMTL_WIRE_FILE_FORMAT "': %r", data_path, data->zone->origin, return_code);

        /*
        close(data->mesg->sockfd);
        // TODO: Check I must release the lock
        scheduler_schedule_task(scheduler_queue_zone_write_ixfr_callback, data);
        */

        free(rdata_buffer);

        /*
        free(mesg);
        */

        /*
         * @TODO DO NOT DESTROY ANYTHING, INSTEAD HOOK-UP TO AN AXFR ANSWER
         * @TODO ENSURE THAT IS IS THE RIGHT WAY
         */
        scheduler_queue_zone_send_axfr(data->zone, data->directory, data->packet_size_limit, data->packet_records_limit, data->compress_dname_rdata, mesg);
        scheduler_schedule_task(scheduler_queue_zone_write_ixfr_callback, data);
        
        return NULL;
    }

    /*
     * We will need to output the current SOA
     * But first, we have some setup to do.
     */

    data->return_code = SCHEDULER_TASK_FINISHED;

    /* It's TCP, my limit is 16 bits */

    packet_size_limit = DNSPACKET_MAX_LENGTH;
    
    packet_size_trigger = packet_size_limit / 2;

    mesg->size_limit = packet_size_limit;

    int tcpfd = data->mesg->sockfd;
    data->mesg->sockfd = -1;
    
    dnsname_copy(origin, data->zone->origin);

    strcpy(directory, data->directory);

    /* Sends the "Write unlocked" notification */

    log_info("zone write ixfr: releasing implicit write lock %{dnsname} %d", data->zone->origin, serial);

    scheduler_schedule_task(scheduler_queue_zone_write_ixfr_callback, data);

    /* WARNING: From this point forward, 'data' cannot be used anymore */

    data = NULL; /* WITH THIS I ENSURE A CRASH IF I DO NOT RESPECT THE ABOVE COMMENT */

    /***********************************************************************/

    log_info("zone write ixfr: sending journal %{dnsname} %d", origin, serial);

    /* attach the tcp descriptor and put a buffer filter in front of the input and the output*/

    fd_output_stream_attach(tcpfd, &tcpos);

    buffer_input_stream_init(&fis, &fis, FILE_BUFFER_SIZE);
    buffer_output_stream_init(&tcpos, &tcpos, TCP_BUFFER_SIZE);

    packet_writer_init(&pw, mesg->buffer, mesg->received, packet_size_limit - 780);

    /*
     * Init
     */

    packet_writer_add_fqdn(&pw, (const u8*)origin);
    packet_writer_add_bytes(&pw, (const u8*)&current_soa_tctrl, 8);
    packet_writer_add_rdata(&pw, TYPE_SOA, current_soa_rdata_buffer, current_soa_rdata_size);
    
    /*
     * Begin
     */

    packet_writer_add_fqdn(&pw, (const u8*)origin);
    packet_writer_add_bytes(&pw, (const u8*)&tctrl, 8);
    packet_writer_add_rdata(&pw, tctrl.qtype, rdata_buffer, rdata_size);

    an_record_count = 2;

    record_mode = RECORD_MODE_DELETE;

    for(;;)
    {
        if(FAIL(return_code = scheduler_queue_zone_write_ixfr_read_record(&fis, fqdn, &qname_size, &tctrl, rdata_buffer, &rdata_size)))
        {
            /*
             * Critical error.
             */

            log_info("zone write ixfr: read record failed %{dnsname} %d: %r", origin, serial, return_code);

            break;
        }

        if(return_code > 0)
        {
            if(pw.packet_offset + return_code <= pw.packet_limit)
            {
                if(tctrl.qtype == TYPE_SOA)
                {
                    if(record_mode != RECORD_MODE_DELETE)
                    {
                        record_mode = RECORD_MODE_DELETE;

                        rr_soa_get_serial(rdata_buffer, rdata_size, &last_valid_serial);
                        last_valid_offset = pw.packet_offset;
                        last_valid_count  = an_record_count;

                        /*
                         * Check if we already got (beyond) the "being nice" limit
                         */

                        if(pw.packet_offset >= packet_size_trigger)
                        {
                            /*
                             * Yes : flush
                             */

                            /*
                             * End
                             */

                            packet_writer_add_fqdn(&pw, (const u8*)origin);
                            packet_writer_add_bytes(&pw, (const u8*)&current_soa_tctrl, 8);
                            packet_writer_add_rdata(&pw, TYPE_SOA, current_soa_rdata_buffer, current_soa_rdata_size);

                            an_record_count++;

                            MESSAGE_AN(mesg->buffer) = htons(an_record_count);
                            mesg->send_length = pw.packet_offset;

                            if(FAIL(return_code = scheduler_queue_zone_write_ixfr_send_message(&tcpos, &pw, mesg, pos)))
                            {
                                log_err("zone write ixfr: send message failed %{dnsname}: %r", origin, return_code);

                                break;
                            }

                            pos = TSIG_MIDDLE;

                            packet_writer_init(&pw, mesg->buffer, mesg->received, packet_size_limit - 780);

                            /*
                             * Init
                             */

                            packet_writer_add_fqdn(&pw, (const u8*)origin);
                            packet_writer_add_bytes(&pw, (const u8*)&current_soa_tctrl, 8);
                            packet_writer_add_rdata(&pw, TYPE_SOA, current_soa_rdata_buffer, current_soa_rdata_size);

                            an_record_count = 1;
                        }
                    }
                    else
                    {
                        record_mode = RECORD_MODE_ADD;
                    }
                }

                /* Add the record */

                packet_writer_add_fqdn(&pw, (const u8*)fqdn);
                packet_writer_add_bytes(&pw, (const u8*)&tctrl, 8);
                packet_writer_add_rdata(&pw, tctrl.qtype, rdata_buffer, rdata_size);

                an_record_count++;
            }
            else
            {
                /*
                 * packet would overflow
                 *
                 * This is a case I want to avoid.  So I will always try to properly
                 * flush at half the packet_limit, but an update of almost 64K will
                 * still trigger this.
                 *
                 * We have to cut at the last good serial, then add the end soa and
                 * send the paquet.
                 *
                 * Then we have to rewind to the cut.
                 */

                serial = last_valid_serial;
                pw.packet_offset = last_valid_offset;
                an_record_count = last_valid_count;

                /*
                 * End
                 */

                packet_writer_add_fqdn(&pw, (const u8*)origin);
                packet_writer_add_bytes(&pw, (const u8*)&current_soa_tctrl, 8);
                packet_writer_add_rdata(&pw, TYPE_SOA, current_soa_rdata_buffer, current_soa_rdata_size);

                an_record_count++;

                MESSAGE_AN(mesg->buffer) = htons(an_record_count);
                mesg->send_length = pw.packet_offset;

                if(FAIL(return_code = scheduler_queue_zone_write_ixfr_send_message(&tcpos, &pw, mesg, pos)))
                {
                    log_err("zone write ixfr: send message failed %{dnsname}: %r", origin, return_code);

                    break;
                }

                pos = TSIG_MIDDLE;

                input_stream_close(&fis);

                if(FAIL(return_code = zdb_icmtl_open_ix_get_soa(origin, directory, serial, &fis,  &tctrl, rdata_buffer, &rdata_size)))
                {
                    log_err("zone write ixfr: path '" ICMTL_WIRE_FILE_FORMAT "': %r", directory, origin, return_code);

                    break;
                }

                buffer_input_stream_init(&fis, &fis, FILE_BUFFER_SIZE);

                packet_writer_init(&pw, mesg->buffer, mesg->received, packet_size_limit - 780);

                /*
                 * Init
                 */

                packet_writer_add_fqdn(&pw, (const u8*)origin);
                packet_writer_add_bytes(&pw, (const u8*)&current_soa_tctrl, 8);
                packet_writer_add_rdata(&pw, TYPE_SOA, current_soa_rdata_buffer, current_soa_rdata_size);

                /*
                 * Begin
                 */

                packet_writer_add_fqdn(&pw, (const u8*)origin);
                packet_writer_add_bytes(&pw, (const u8*)&tctrl, 8);
                packet_writer_add_rdata(&pw, tctrl.qtype, rdata_buffer, rdata_size);

                an_record_count = 2;

                /*
                 * Loop up and redo the job from where we did cut
                 */
            }
        }
        else
        {
            /*
             * EOF
             *
             * We have to add the end soa and send the paquet.
             * Then we are done.
             */

            /*
             * End
             */

            packet_writer_add_fqdn(&pw, (const u8*)origin);
            packet_writer_add_bytes(&pw, (const u8*)&current_soa_tctrl, 8);
            packet_writer_add_rdata(&pw, TYPE_SOA, current_soa_rdata_buffer, current_soa_rdata_size);

            an_record_count++;

            MESSAGE_AN(mesg->buffer) = htons(an_record_count);
            mesg->send_length = pw.packet_offset;

            if(pos != TSIG_START)
            {
                pos = TSIG_END;
            }
            else
            {
                pos = TSIG_WHOLE;
            }

            if(FAIL(return_code = scheduler_queue_zone_write_ixfr_send_message(&tcpos, &pw, mesg, pos)))
            {
                log_err("zone write ixfr: send message failed %{dnsname}: %r", origin, return_code);
            }

            break;
        }
    }
    
    if(ISOK(return_code))
    {
        log_info("zone write ixfr: %{dnsname} ixfr stream sent", origin);
    }
    else
    {
        log_err("zone write ixfr: %{dnsname} ixfr stream not sent", origin);
    }

    output_stream_close(&tcpos);

    if(input_stream_valid(&fis))
    {
        input_stream_close(&fis);
    }

    free(rdata_buffer);
    free(mesg);

    return NULL;
}

/*
 * This requires that the scheduler calls the IXFR write zone file
 */

void
scheduler_queue_zone_write_ixfr(zdb_zone* zone, const char* directory, u32 packet_size_limit, u32 packet_records_limit, bool compress_dname_rdata)
{
    scheduler_queue_zone_write_ixfr_args* args;
    
    log_info("zone write ixfr: queueing %{dnsname}", zone->origin);
    
    MALLOC_OR_DIE(scheduler_queue_zone_write_ixfr_args*, args, sizeof (scheduler_queue_zone_write_ixfr_args), GENERIC_TAG);
    args->zone = zone;
    args->directory = strdup(directory);
    args->mesg = NULL;
    args->packet_size_limit = packet_size_limit;
    args->packet_records_limit = packet_records_limit;
    args->compress_dname_rdata = compress_dname_rdata;
    
    scheduler_schedule_thread(NULL, scheduler_queue_zone_write_ixfr_thread, args, "scheduler_queue_zone_write_ixfr");
}

/*
 * This requires that the scheduler answers to an IXFR query
 */

void
scheduler_queue_zone_send_ixfr(zdb_zone* zone, const char* directory, u32 packet_size_limit, u32 packet_records_limit, bool compress_dname_rdata, message_data *mesg)
{
    scheduler_queue_zone_write_ixfr_args* args;
        
    log_info("zone write ixfr: queueing %{dnsname}", zone->origin);
    
    MALLOC_OR_DIE(scheduler_queue_zone_write_ixfr_args*, args, sizeof(scheduler_queue_zone_write_ixfr_args), GENERIC_TAG);
    args->zone = zone;
    args->directory = strdup(directory);

    message_data *mesg_clone;

    MALLOC_OR_DIE(message_data*, mesg_clone, sizeof(message_data), GENERIC_TAG);
    memcpy(mesg_clone, mesg, sizeof(message_data));

    args->mesg = mesg_clone;
    args->packet_size_limit = packet_size_limit;
    args->packet_records_limit = packet_records_limit;
    args->compress_dname_rdata = compress_dname_rdata;
    
    scheduler_schedule_thread(NULL, scheduler_queue_zone_write_ixfr_thread, args, "scheduler_queue_zone_send_ixfr");
}

/** @} */


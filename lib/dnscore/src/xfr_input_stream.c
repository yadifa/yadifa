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
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "dnscore/packet_reader.h"
#include "dnscore/format.h"
#include "dnscore/xfr_copy.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/buffer_input_stream.h"
#include "dnscore/buffer_output_stream.h"
#include "dnscore/fdtools.h"
#include "dnscore/pipe_stream.h"

/* it depends if host is DARWIN or LINUX */
#ifdef HAVE_SYS_SYSLIMITS_H
#ifndef __FreeBSD__
#include <sys/syslimits.h>
#endif
#elif HAVE_LINUX_LIMITS_H
#include <linux/limits.h>
#endif /* HAVE_SYS_SYSLIMITS_H */

#define MODULE_MSG_HANDLE g_system_logger

#define DEBUG_XFR_INPUT_STREAM 0

typedef struct xfr_input_stream_data xfr_input_stream_data;

struct xfr_input_stream_data
{
    xfr_copy_args *args;
    output_stream pipe_stream_output;
    input_stream pipe_stream_input;
    input_stream source_stream;
    packet_unpack_reader_data reader;
    u8 *first_soa_record;
    u32 first_soa_record_size;
    
    u16 ancount;
    u16 xfr_mode;
    u32 record_index;                   // index of the record in the stream
    u32 last_serial;
    ya_result last_error;
    bool eos;
    bool ixfr_mark;
#if DNSCORE_HAS_TSIG_SUPPORT
    bool last_message_had_tsig;
    bool need_cleanup_tsig;
#endif
};

/**
 * Reads from the (tcp) input stream for an xfr
 * Detects the xfr type
 * Copies into the right file
 *
 * @return error code
 */

#if HAS_NON_AA_AXFR_SUPPORT

/*
 * Non-RFC-compliant masks (allows AA bit not set)
 * 
 * It seems (some?) Microsoft DNS answers to an AXFR query without setting the AA bit
 * 
 * The RFC 5936 states that in the case of an AXFR answer with no error (RCODE set to 0),
 * the AA bit MUST be set.
 * 
 */

#ifdef WORDS_BIGENDIAN
#define AXFR_MESSAGE_HEADER_MASK    (( (u64) 0 )                                    | \
                                     (((u64) (QR_BITS  | TC_BITS )) << 40 )| \
                                     (((u64) ( RA_BITS | RCODE_BITS )) << 32 )      | \
                                     ( (u64) 1LL << 16 ))

#define AXFR_MESSAGE_HEADER_RESULT  (( (u64) (QR_BITS ) << 40 )            | \
                                     ( ((u64) 1LL) << 16 ))

#define AXFR_NEXT_MESSAGE_HEADER_MASK (( (u64) 0LL )                                   | \
                                      (((u64) ( QR_BITS  | TC_BITS )) << 40 )| \
                                      (((u64) ( RCODE_BITS )) << 32 ))


#define AXFR_NEXT_MESSAGE_HEADER_RESULT   (((u64) ( QR_BITS  )) << 40 )

#else
#define AXFR_MESSAGE_HEADER_MASK     (( (u64) 0LL )                                   | \
                                      (((u64) ( QR_BITS  | TC_BITS )) << 16 )| \
                                      (((u64) ( RCODE_BITS )) << 24 )       | \
                                      (((u64) 1LL) << 40 ))

#define AXFR_MESSAGE_HEADER_RESULT   ((((u64) ( QR_BITS  )) << 16 )| \
                                      (((u64) 1LL) << 40 ))

#define AXFR_NEXT_MESSAGE_HEADER_MASK     (( (u64) 0LL )                                   | \
                                      (((u64) ( QR_BITS  | TC_BITS )) << 16 )| \
                                      (((u64) ( RCODE_BITS )) << 24 ))


#define AXFR_NEXT_MESSAGE_HEADER_RESULT   (((u64) ( QR_BITS  )) << 16 )

#endif

#else

/*
 * RFC compliant masks (AA bit must be set) 
 */

#ifdef WORDS_BIGENDIAN
#define AXFR_MESSAGE_HEADER_MASK    (( (u64) 0 )                                    | \
                                     (((u64) (QR_BITS | AA_BITS | TC_BITS )) << 40 )| \
                                     (((u64) ( RA_BITS | RCODE_BITS )) << 32 )      | \
                                     ( (u64) 1LL << 16 ))

#define AXFR_MESSAGE_HEADER_RESULT  (( (u64) (QR_BITS | AA_BITS) << 40 )            | \
                                     ( ((u64) 1LL) << 16 ))

#define AXFR_NEXT_MESSAGE_HEADER_MASK (( (u64) 0LL )                                   | \
                                      (((u64) ( QR_BITS | AA_BITS | TC_BITS )) << 40 )| \
                                      (((u64) ( RCODE_BITS )) << 32 ))


#define AXFR_NEXT_MESSAGE_HEADER_RESULT   (((u64) ( QR_BITS | AA_BITS )) << 40 )

#else
#define AXFR_MESSAGE_HEADER_MASK     (( (u64) 0LL )                                   | \
                                      (((u64) ( QR_BITS | AA_BITS | TC_BITS )) << 16 )| \
                                      (((u64) ( RCODE_BITS )) << 24 )       | \
                                      (((u64) 1LL) << 40 ))

#define AXFR_MESSAGE_HEADER_RESULT   ((((u64) ( QR_BITS | AA_BITS )) << 16 )| \
                                      (((u64) 1LL) << 40 ))

#define AXFR_NEXT_MESSAGE_HEADER_MASK     (( (u64) 0LL )                                   | \
                                      (((u64) ( QR_BITS | AA_BITS | TC_BITS )) << 16 )| \
                                      (((u64) ( RCODE_BITS )) << 24 ))


#define AXFR_NEXT_MESSAGE_HEADER_RESULT   (((u64) ( QR_BITS | AA_BITS )) << 16 )

#endif

#endif

/*
 * Reads the content of a message from the reader field in data (packet reader)
 * The ancount field in data contains the number of records to read
 * Every record read is written to the output pipe
 */

static ya_result
xfr_input_stream_read_packet(xfr_input_stream_data *data)
{
    message_data *message = data->args->message;
    packet_unpack_reader_data *reader = &data->reader;
    u8 *record = &message->pool_buffer[0];
    u32 record_len;
    ya_result return_value = SUCCESS;
        
#if DEBUG_XFR_INPUT_STREAM
    log_debug("xfr_input_stream_read_packet(%p) ancount=%hd record_index=%u", data, data->ancount, data->record_index);
#endif
    
    while((data->ancount > 0) && (pipe_stream_write_available(&data->pipe_stream_output) > 2048 ))
    {
        --data->ancount;
        
        if(FAIL(record_len = packet_reader_read_record(reader, record, RDATA_MAX_LENGTH + 1)))
        {
            if(record_len != UNSUPPORTED_TYPE)
            {
                data->eos = TRUE;

                return_value = record_len;

                break;
            }

            log_err("xfr_input_stream: skipped unsupported record #%d %{recordwire}", data->record_index, record);

            data->record_index++;
            continue;
        }

#if DEBUG_XFR_INPUT_STREAM
        log_debug("xfr_input_stream: #%u %{recordwire}", data->record_index, record);
#endif
        
        u8 *ptr = record + dnsname_len(record);

        u16 rtype = GET_U16_AT(*ptr);

        switch(rtype)
        {
            case TYPE_SOA:
            {
                /* handle SOA case */

                if(!dnsname_equals(record, data->args->origin))
                {
                    data->eos = TRUE;

                    return_value = ERROR; // OWNER OF SOA RECORD SHOULD BE ORIGIN (protocol error)

                    return return_value;
                }

                ptr += 10;                  /* type class ttl rdata_size */
                ptr += dnsname_len(ptr);
                ptr += dnsname_len(ptr);
                u32 soa_serial = ntohl(GET_U32_AT(*ptr));

                if(data->xfr_mode == TYPE_ANY)
                {
                    if(data->record_index == 1)
                    {
                        /*
                         * This is an IXFR, the first record is not sent up
                         */

                        data->xfr_mode = TYPE_IXFR;
                    }
                    else
                    {
                        output_stream_write(&data->pipe_stream_output, data->first_soa_record, data->first_soa_record_size);
                        data->xfr_mode = TYPE_AXFR;
                    }
                }

                if(soa_serial == data->last_serial)
                {
                    if(data->xfr_mode == TYPE_AXFR || ((data->xfr_mode == TYPE_IXFR) && data->ixfr_mark))
                    {
                        return_value = SUCCESS;

                        /*
                            * The last record of an AXFR must be written,
                            * the last record of an IXFR must not.
                            */

                        if(data->xfr_mode == TYPE_AXFR)
                        {
                            return_value = output_stream_write(&data->pipe_stream_output, record, record_len);
                        }

                        /* done */
                        data->eos = TRUE;                       

                        return return_value; // reached the end
                    }

                    /* IXFR needs to find the mark twice */

                    data->ixfr_mark = TRUE;
                }
                
                break;
            }

            case TYPE_IXFR:
            case TYPE_AXFR:
            case TYPE_OPT:
            case TYPE_ANY:
                return INVALID_PROTOCOL;
            default:
                if(data->record_index == 1)
                {
                    // special case to detect an AXFR returned by an IXFR query
                    
                    if(data->xfr_mode == TYPE_ANY)
                    {
                        data->xfr_mode = TYPE_AXFR;
                        
                        if(FAIL(return_value = output_stream_write(&data->pipe_stream_output, data->first_soa_record, data->first_soa_record_size)))
                        {
                            return return_value;
                        }
                    }
                    else
                    {
                        return_value = ERROR;
                        return return_value;    // invalid status
                    }
                }
                break;
        }

        if(FAIL(return_value = output_stream_write(&data->pipe_stream_output, record, record_len)))
        {
            data->eos = TRUE;

            break;
        }
        
        if(return_value != record_len)
        {
            return UNEXPECTED_EOF;
        }

        data->record_index++;
    }
    
    return return_value;
}

static ya_result
xfr_input_stream_read(input_stream *is, u8 *buffer, u32 len)
{
    xfr_input_stream_data *data = (xfr_input_stream_data*)is->data;
    input_stream *source_stream = &data->source_stream;
    message_data *message = data->args->message;
#if DNSCORE_HAS_TSIG_SUPPORT
    const tsig_item *tsig = message->tsig.tsig;
#endif
    packet_unpack_reader_data *reader = &data->reader;
    
    if(FAIL(data->last_error))
    {
        return data->last_error;
    }
    
    ya_result return_value = SUCCESS;
    
    /* while there is not enough bytes on the input */
    
    while(pipe_stream_read_available(&data->pipe_stream_input) < len)
    {
        /* read the packet and write on the output (so it can be read back on the input) */
        
        if(FAIL(return_value = xfr_input_stream_read_packet(data)))
        {
            break;
        }

        if(data->eos)
        {
            break;
        }
        
        if(data->ancount > 0)
        {
            break;
        }

        /* next TCP chunk */
        
#ifdef DEBUG
        memset(&message->buffer[0], 0xee, sizeof(message->buffer));
#endif
        
        u16 tcplen;
        
        return_value = input_stream_read_nu16(source_stream, &tcplen); /* this is wrong ... */

        if(return_value != 2)
        {
#ifdef DEBUG
            log_debug("xfr_input_stream_read: next message is %ld bytes long", return_value);
#endif
            break;
        }

        if(tcplen == 0)
        {
            return_value = UNEXPECTED_EOF;
            break;
        }

        if(FAIL(return_value = input_stream_read_fully(source_stream, message->buffer, tcplen)))
        {
            break;
        }
        
#if DEBUG_XFR_INPUT_STREAM
        log_memdump(g_system_logger, MSG_DEBUG1, &message->buffer[0], tcplen, 32);
#endif
        
        message->received = return_value;


#ifdef DEBUG
        memset(&message->buffer[tcplen], 0xdd, DNSPACKET_MAX_LENGTH + 1 - tcplen);
#endif
        /*
         * Check the headers
         */

        const u64 *h64 = (u64*)message->buffer;
        const u64 m64 = AXFR_NEXT_MESSAGE_HEADER_MASK;
        const u64 r64 = AXFR_NEXT_MESSAGE_HEADER_RESULT;

        if(((*h64&m64) != r64) || (MESSAGE_NS(message->buffer) != 0))
        {
            u8 code = MESSAGE_RCODE(message->buffer);

            if(code != 0)
            {
                return_value = MAKE_DNSMSG_ERROR(code);
            }
            else
            {
                return_value = UNPROCESSABLE_MESSAGE;
            }
            
            break;
        }
#if DNSCORE_HAS_TSIG_SUPPORT
        if((data->last_message_had_tsig = (tsig != NULL)))
        {
            /* verify the TSIG
             *
             * AR > 0
             * skip ALL the records until the last AR
             * it MUST be a TSIG
             * It's the first TSIG answering to our query
             * verify it
             *
             */

            message->tsig.tsig = NULL;

            if(FAIL(return_value = tsig_message_extract(message)))
            {
                break;
            }
            
            if((return_value == 1) && (message->tsig.tsig != tsig))
            {
                /* This is not the one we started with */

                log_debug("xfr_input_stream: signature key does not match");

                return_value = TSIG_BADSIG;
                break;
            }

            if(FAIL(return_value = tsig_verify_tcp_next_message(message)))
            {
                break;
            }
        }
#endif
        message_header *header = (message_header*)message->buffer;
        
        data->ancount = ntohs(header->ancount);

        packet_reader_init(reader, message->buffer, message->received);
        reader->offset = DNS_HEADER_LENGTH;

        u16 n = ntohs(header->qdcount);
        
        while(n > 0)
        {
            if(FAIL(return_value = packet_reader_skip_fqdn(reader)))
            {
                break;
            }

            packet_reader_skip(reader, 4);

            n--;
        }
    } // for(;;) /* process all TCP chunks */
    
    if(ISOK(return_value))
    {
        if((return_value = pipe_stream_read_available(&data->pipe_stream_input)) > 0) // never fails
        {
            if(FAIL(return_value = input_stream_read(&data->pipe_stream_input, buffer, len)))
            {
                if(data->need_cleanup_tsig)
                {
                    tsig_verify_tcp_last_message(message);
                    data->need_cleanup_tsig = FALSE;
                }
            }
        }
        else
        {
            // here, return_value == 0
            
            if(tsig != NULL)
            {
                tsig_verify_tcp_last_message(message);
                data->need_cleanup_tsig = FALSE;

                if(!data->last_message_had_tsig)
                {
                    /*
                     * The stream didn't end with a TSIG
                     * It's bad.
                     *
                     */

                    log_err("xfr_input_stream: TSIG enabled answer didn't ended with a signed packet");

                    return_value = TSIG_BADSIG;
                }
            }
        }
    }
    else
    {
        // cleanup
        tsig_verify_tcp_last_message(message);
        data->need_cleanup_tsig = FALSE;
    }
    
    data->last_error = return_value;

    return return_value;
}

static ya_result
xfr_input_stream_skip(input_stream *is, u32 len)
{
    /*
     * The reader is too complicated to implement a skip, so skip is a wrapped read
     */
    
    u32 remaining = len;
    ya_result return_value = SUCCESS;
    
    u8 buffer[512];
    
    while(remaining > 0)
    {
        u32 n = MIN(remaining, sizeof(buffer));
        
        return_value = xfr_input_stream_read(is, buffer, n);
        
        if(return_value <= 0) /* FAIL or EOF */
        {
            break;
        }
        
        remaining -= return_value;
    }
    
    if(len != remaining)
    {
        return_value = len - remaining;
    }
    
    return return_value;
}

static void
xfr_input_stream_close(input_stream *is)
{
    xfr_input_stream_data *data = (xfr_input_stream_data*)is->data;
    
    if(data->need_cleanup_tsig)
    {
        log_err("TSIG has not been cleared");
        data->need_cleanup_tsig = FALSE;
    }
    
    data->args = NULL;
    output_stream_close(&data->pipe_stream_output);
    input_stream_close(&data->pipe_stream_input);
    free(data->first_soa_record);
    
#ifdef DEBUG
    memset(data, 0xfe, sizeof(xfr_input_stream_data));
#endif
   
    free(data); 
    
    input_stream_set_void(is);
}

static const input_stream_vtbl xfr_input_stream_vtbl =
{
    xfr_input_stream_read,
    xfr_input_stream_skip,
    xfr_input_stream_close,
    "xfr_input_stream",
};

/**
 * 
 * @param is the input stream with the AXFR or IXFR, wire format
 * @param flags mostly XFR_ALLOW_AXFR or XFR_ALLOW_IXFR
 * @param origin the domain of the zone
 * @param base_data_path the folder where to put the journal (or journal hash directories and journal)
 * @param current_serial the serial currently available
 * @param loaded_serial a pointer to get the serial available after loading
 * @param message the message that led to this download
 * 
 * @return an error code, TYPE_AXFR, TYPE_IXFR, TYPE_NONE
 */

ya_result
xfr_input_stream_init(xfr_copy_args *args, input_stream* filtering_stream)
{
    input_stream *is = args->is;
    const u8 *origin = args->origin;
    message_data *message = args->message;
    
    packet_unpack_reader_data reader;
    u8 *buffer;
    u8 *record;
    u8 *ptr;
#if DNSCORE_HAS_TSIG_SUPPORT
    const tsig_item *tsig;
#endif
    ya_result record_len;
    ya_result return_value;
    u32 origin_len;
    u32 last_serial = 0;

    u16 tcplen;
    u16 qtype;
    u16 qclass;

    u16 old_mac_size;
    
    bool last_message_had_tsig;
    bool need_cleanup_tsig = FALSE;

    u8 old_mac[64];
    
    /*
     * ensure the stream will be unusable if the initialisation fails
     */
    
    input_stream_set_void(filtering_stream);
    
    /*
     * Start by reading the first packet, and determine if it's an AXFR or an IXFR (for the name)
     * note: it's read and converted to the host endianness
     */
    
    if(!is_fd_input_stream(is))
    {
        // expected file input stream
        return INVALID_ARGUMENT_ERROR;
    }
    
    //buffer_input_stream_init(is, is, 4096);
    
    /* TCP length */

    if(FAIL(return_value = input_stream_read_nu16(is, &tcplen)))
    {
        return return_value;
    }
    
    if(return_value != 2)
    {
        return UNEXPECTED_EOF;
    }
    
    /* if the length is not enough, return the most appropriate error code */

    origin_len = dnsname_len(origin);

    if(tcplen < DNS_HEADER_LENGTH + origin_len + 4)
    {
        return_value = UNEXPECTED_EOF;
        
        if(tcplen >= DNS_HEADER_LENGTH)
        {
            if(ISOK(return_value = input_stream_read_fully(is, message->pool_buffer, DNS_HEADER_LENGTH)))
            {
                return_value = MAKE_DNSMSG_ERROR(MESSAGE_RCODE(message->pool_buffer));
            }
        }
        
        /* TODO: retry ? */
        return return_value;
    }
    
    /* read the whole message */

    buffer = &message->buffer[0];
    record = &message->pool_buffer[0];
    
    assert(sizeof(message->pool_buffer) >= 255 + 10 + 65535);

    if(FAIL(return_value = input_stream_read_fully(is, buffer, tcplen)))
    {
        return return_value;
    }
    
#if DEBUG_XFR_INPUT_STREAM
    log_memdump(g_system_logger, MSG_DEBUG1, &message->buffer[0], tcplen, 32);
#endif
    
    message->received = return_value;
    
    /* check the message makes sense */

    const u64 *h64 = (u64*)buffer;
    u64 m64 = AXFR_MESSAGE_HEADER_MASK;
    u64 r64 = AXFR_MESSAGE_HEADER_RESULT;

    if(((*h64&m64) != r64) || (MESSAGE_NS(message->buffer) != 0))
    {
        u8 code = MESSAGE_RCODE(message->buffer);

        if(code != 0)
        {
            return_value = MAKE_DNSMSG_ERROR(code);
        }
        else
        {
            return_value = UNPROCESSABLE_MESSAGE;
        }

         return return_value;
    }

    //m64 = AXFR_NEXT_MESSAGE_HEADER_MASK;
    //r64 = AXFR_NEXT_MESSAGE_HEADER_RESULT;

    packet_reader_init(&reader, buffer, tcplen);
    reader.offset = DNS_HEADER_LENGTH;

    packet_reader_read_fqdn(&reader, record, RDATA_MAX_LENGTH + 1);

    if(!dnsname_equals(record, origin))
    {
        return INVALID_PROTOCOL;
    }

    if(FAIL(return_value = packet_reader_read_u16(&reader, &qtype)))
    {
        return return_value;
    }
    
    if(return_value != 2)
    {
        return UNEXPECTED_EOF;
    }

    /* 
     * check that we are allowed to process this particular kind of transfer
     * note : this does not determine what is REALLY begin transferred
     */
    
    switch(qtype)
    {
        case TYPE_AXFR:
        {
            if((args->flags & XFR_ALLOW_AXFR) == 0)
            {
                return INVALID_PROTOCOL;
            }
            break;
        }
        case TYPE_IXFR:
        {
            if((args->flags & XFR_ALLOW_IXFR) == 0)
            {
                return INVALID_PROTOCOL;
            }
            break;
        }
        default:
        {
            return INVALID_PROTOCOL;
        }
    }

    if(FAIL(return_value = packet_reader_read_u16(&reader, &qclass)))
    {
        return return_value;
    }

    if(qclass != CLASS_IN)
    {
        /** wrong answer */
        return INVALID_PROTOCOL;
    }
    
    /* check for TSIG and verify */

    u16 ancount = ntohs(MESSAGE_AN(buffer));
    
#if DNSCORE_HAS_TSIG_SUPPORT
    if((last_message_had_tsig = ((tsig = message->tsig.tsig) != NULL)))
    {
        /* verify the TSIG
         *
         * AR > 0
         * skip ALL the records until the last AR
         * it MUST be a TSIG
         * It's the first TSIG answering to our query
         * verify it
         *
         */
        
        message->tsig.tsig = NULL;

        old_mac_size = message->tsig.mac_size;
        memcpy(old_mac, message->tsig.mac, old_mac_size);

        if(FAIL(return_value = tsig_message_extract(message)))
        {
            log_debug("xfr_input_stream: error extracting the signature");

            return return_value;
        }

        if(return_value == 0)
        {
            log_debug("xfr_input_stream: no signature when one was requested");

            return TSIG_BADSIG; /* no signature, when one was requested, is a bad signature */
        }

        if(message->tsig.tsig != tsig)
        {
            /* This is not the one we started with */

            log_debug("xfr_input_stream: signature key does not match");

            return TSIG_BADSIG;
        }

        /// check that the tsig in the message matches the one that was sent

        if(FAIL(return_value = tsig_verify_tcp_first_message(message, old_mac, old_mac_size)))
        {
            return return_value;
        }

        reader.packet_size = message->received;
        
        need_cleanup_tsig = TRUE;
    }
#endif
    
    log_debug("xfr_input_stream: expecting %5d answer records", ancount);    

    /*
     * read the SOA (it MUST be an SOA)
     */

    if(FAIL(record_len = packet_reader_read_record(&reader, record, RDATA_MAX_LENGTH + 1)))
    {
        return record_len;
    }

    if(!dnsname_equals(record, origin))
    {
        return INVALID_PROTOCOL;
    }

    ptr = &record[origin_len];

    if(GET_U16_AT(*ptr) != TYPE_SOA)
    {
        return INVALID_PROTOCOL;
    }

    ptr += 8; /* type class ttl */
    
    u16 rdata_size = ntohs(GET_U16_AT(*ptr));
    
    if(rdata_size < 22)
    {
        return INVALID_PROTOCOL;
    }

    rdata_size -= 16;

    ptr += 2; /* rdata size */

    s32 len = dnsname_len(ptr);

    if(len >= rdata_size)
    {
        return INVALID_PROTOCOL;
    }
    rdata_size -= len;
    ptr += len;

    len = dnsname_len(ptr);
    if(len >= rdata_size)
    {
        return INVALID_PROTOCOL;
    }
    rdata_size -= len;

    if(rdata_size != 4)
    {
        return INVALID_PROTOCOL;
    }

    ptr += len;

    // if the serial of the SOA is the same one as we know, then there is no
    // need to download the zone
    
    last_serial = ntohl(GET_U32_AT(*ptr));
    
    if(last_serial == args->current_serial)
    {
        args->out_loaded_serial = args->current_serial;
                        
        return ZONE_ALREADY_UP_TO_DATE;
    }

    xfr_input_stream_data *data;    
    MALLOC_OR_DIE(xfr_input_stream_data*, data, sizeof(xfr_input_stream_data), GENERIC_TAG);
    ZEROMEMORY(data, sizeof(xfr_input_stream_data));
    data->args = args;
    
    /*
     * We have got the first SOA
     * Next time we find this SOA (second next time for IXFR) the stream, it will be the end of the stream
     */

    /*
     * The stream can be AXFR or IXFR.
     * The only way to know this is to look at the records, maybe on many packets.
     * If there are two SOA (different serial numbers) for the start, then it's an IXFR, else it's an AXFR.
     * 
     * OPEN A PIPE STREAM "XFRs"
     *
     * Save the first SOA
     */

    MALLOC_OR_DIE(u8*, data->first_soa_record, record_len, GENERIC_TAG);
    MEMCOPY(data->first_soa_record, record, record_len);
    data->first_soa_record_size = record_len;         

    filtering_stream->vtbl = &xfr_input_stream_vtbl;
    filtering_stream->data = data;
    
    pipe_stream_init(&data->pipe_stream_output, &data->pipe_stream_input, 65536);
    MEMCOPY(&data->reader, &reader, sizeof(packet_unpack_reader_data));
    data->ancount = ancount - 1;
    data->record_index++;
    data->last_serial = last_serial;
    data->xfr_mode = TYPE_ANY;
    data->ixfr_mark = FALSE;
    data->last_message_had_tsig = last_message_had_tsig;
    data->source_stream = *is;
    data->need_cleanup_tsig = need_cleanup_tsig;
    
    /*
     * Then we read all records for all packets
     * If we find an SOA ...
     *      AXFR: it has to be the last serial and it is the end of the stream.
     *      IXFR: if it's not the last serial it has to go from step to step
     *            AND once we have reached the "last serial" once, the next hit is the end of the stream.
     */

    data->eos = FALSE;
    
    /*
     * In order to know what the type is, read the first packet.
     */
    
    return_value = xfr_input_stream_read_packet(data);  /** @TODO CHECK CRASH HERE */
    
    if(FAIL(return_value))
    {
        xfr_input_stream_close(filtering_stream);
    }
    
    return return_value;
}

ya_result
xfr_input_stream_get_type(input_stream *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data*)in_xfr_input_stream->data;
    return data->xfr_mode;
}


const u8*
xfr_input_stream_get_origin(input_stream *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data*)in_xfr_input_stream->data;
    return data->args->origin;
}

ya_result
xfr_input_stream_get_serial(input_stream *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data*)in_xfr_input_stream->data;
    return data->last_serial;
}

/** @} */

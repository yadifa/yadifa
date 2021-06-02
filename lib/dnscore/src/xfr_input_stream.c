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
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include "dnscore/dnscore-config.h"
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "dnscore/xfr_input_stream.h"

#include "dnscore/zalloc.h"
#include "dnscore/packet_reader.h"
#include "dnscore/format.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/buffer_input_stream.h"
#include "dnscore/buffer_output_stream.h"
#include "dnscore/fdtools.h"
#include "dnscore/pipe_stream.h"
#include "dnscore/message.h"
#include "dnscore/pool.h"
#include "dnscore/random.h"
#include "dnscore/thread_pool.h"
#include "dnscore/tcp_io_stream.h"

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

#define XFRISDTA_TAG 0x4154445349524658
#define XFRISSOA_TAG 0x414f535349524658
#define XFRPOOL_TAG 0x4c4f4f50524658

struct xfr_input_stream_data
{
    output_stream pipe_stream_output;
    input_stream pipe_stream_input;
    input_stream source_stream;
    output_stream source_output_stream;
    packet_unpack_reader_data reader;
    
    message_data *message;
    const u8 *origin;
    u8 *pool;   // 64KB
        
    u8 *first_soa_record;
    u32 first_soa_record_size;
    
    u16 ancount;
    u16 xfr_mode;
    u32 record_index;                   // index of the record in the stream

    u32 last_serial;
    u32 last_refresh;
    u32 last_retry;
    u32 last_expire;
    u32 last_nttl;

    u64 mesg_hdr_mask;
    u64 mesg_hdr_result;
    u64 next_hdr_mask;
    u64 next_hdr_result;

    ya_result last_error;
    bool eos;
    bool ixfr_mark;
    bool owns_message;
    bool owns_input_stream;
#if DNSCORE_HAS_TSIG_SUPPORT
    bool last_message_had_tsig;
    bool need_cleanup_tsig;
#endif
};

static pool_s xfr_pool;
static mutex_t xfr_pool_init_mtx = MUTEX_INITIALIZER;
static bool xfr_pool_initialised = FALSE;

static void *xfr_pool_alloc(void *args)
{
    (void)args;
    void *p;
    MALLOC_OBJECT_ARRAY(p, u8, 0x1010a, XFRPOOL_TAG);
    // void *p = malloc(0x1010a);
    return p;
}

static void xfr_pool_free(void *ptr, void* args)
{
    (void)args;
    free(ptr);
}

/**
 * Reads from the (tcp) input stream for an xfr
 * Detects the xfr type
 * Copies into the right file
 *
 * @return error code
 */

//#if HAS_NON_AA_AXFR_SUPPORT

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
#define AXFR_MESSAGE_LENIENT_HEADER_MASK    (( (u64) 0 )                                    | \
                                     (((u64) (QR_BITS  | TC_BITS )) << 40 )| \
                                     (((u64) ( RA_BITS | RCODE_BITS )) << 32 )      | \
                                     ( (u64) 1LL << 16 ))

#define AXFR_MESSAGE_LENIENT_HEADER_RESULT  (( (u64) (QR_BITS ) << 40 )            | \
                                     ( ((u64) 1LL) << 16 ))

#define AXFR_NEXT_MESSAGE_LENIENT_HEADER_MASK (( (u64) 0LL )                                   | \
                                      (((u64) ( QR_BITS  | TC_BITS )) << 40 )| \
                                      (((u64) ( RCODE_BITS )) << 32 ))


#define AXFR_NEXT_MESSAGE_LENIENT_HEADER_RESULT   (((u64) ( QR_BITS  )) << 40 )

#else
#define AXFR_MESSAGE_LENIENT_HEADER_MASK     (( (u64) 0LL )                                   | \
                                      (((u64) ( QR_BITS  | TC_BITS )) << 16 )| \
                                      (((u64) ( RCODE_BITS )) << 24 )       | \
                                      (((u64) 1LL) << 40 ))

#define AXFR_MESSAGE_LENIENT_HEADER_RESULT   ((((u64) ( QR_BITS  )) << 16 )| \
                                      (((u64) 1LL) << 40 ))

#define AXFR_NEXT_MESSAGE_LENIENT_HEADER_MASK     (( (u64) 0LL )                                   | \
                                      (((u64) ( QR_BITS  | TC_BITS )) << 16 )| \
                                      (((u64) ( RCODE_BITS )) << 24 ))


#define AXFR_NEXT_MESSAGE_LENIENT_HEADER_RESULT   (((u64) ( QR_BITS  )) << 16 )

#endif

//#else

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

//#endif

/*
 * Reads the content of a message from the reader field in data (packet reader)
 * The ancount field in data contains the number of records to read
 * Every record read is written to the output pipe
 */

static ya_result
xfr_input_stream_read_packet(xfr_input_stream_data *data)
{
    //message_data *message = data->message;
    packet_unpack_reader_data *reader = &data->reader;
    u8 *record = data->pool; // no persistence of content needed
    s32 record_len;
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
        log_debug("xfr_input_stream: <%u %{recordwire}", data->record_index, record);
#endif
        
        const u8 *ptr = record + dnsname_len(record);

        u16 rtype = GET_U16_AT(*ptr);

        switch(rtype)
        {
            case TYPE_SOA:
            {
                /* handle SOA case */

                if(!dnsname_equals(record, data->origin))
                {
                    data->eos = TRUE;

                    return_value = MAKE_DNSMSG_ERROR(FP_XFR_QUERYERROR); // OWNER OF SOA RECORD SHOULD BE ORIGIN (protocol error)

                    return return_value;
                }

                ptr += 10;                  /* type class ttl rdata_size */
                ptr += dnsname_len(ptr);
                ptr += dnsname_len(ptr);
                u32 soa_serial = ntohl(GET_U32_AT(*ptr));

                if(data->xfr_mode == TYPE_ANY) // the type of stream has not been decided yet
                {
                    if(data->record_index == 1)
                    {
                        // second record is an SOA: this is an IXFR, the first record is not sent up
                        
#if DEBUG_XFR_INPUT_STREAM
                        log_debug("xfr_input_stream: #%u %{recordwire} ; (IXFR START)", data->record_index, data->first_soa_record);
#endif
                         
                        data->xfr_mode = TYPE_IXFR;
                    }
                    else
                    {
                        // second record is not an SOA: this is an AXFR, the first record is sent up
                        
#if DEBUG_XFR_INPUT_STREAM
                        log_debug("xfr_input_stream: #%u %{recordwire} ; (AXFR START)", data->record_index, record);
#endif
                        
                        output_stream_write(&data->pipe_stream_output, data->first_soa_record, data->first_soa_record_size);
                        data->xfr_mode = TYPE_AXFR;
                    }
                }

                if(soa_serial == data->last_serial)
                {
                    // the SOA serial has the same value as the last record we expect
                    // if it's an AXFR or this is the second time it happens on an IXFR, then it's then end of the stream
                    
                    if(data->xfr_mode == TYPE_AXFR || ((data->xfr_mode == TYPE_IXFR) && data->ixfr_mark))
                    {
                        return_value = SUCCESS;

                        /*
                         * The last record of an AXFR must be written,
                         * the last record of an IXFR must not.
                         */

                        if(data->xfr_mode == TYPE_AXFR)
                        {
#if DEBUG_XFR_INPUT_STREAM
                            log_debug("xfr_input_stream: #%u %{recordwire} ; (AXFR END)", data->record_index, record);
#endif
                            
                            return_value = output_stream_write(&data->pipe_stream_output, record, record_len);
                        }
#if DEBUG_XFR_INPUT_STREAM
                        else
                        {
                            log_debug("xfr_input_stream: #%u %{recordwire} ; (IXFR END)", data->record_index, record);
                        }
#endif

                        // done
                        data->eos = TRUE;                       

                        return return_value; // reached the end
                    }

                    // IXFR needs to find the mark twice
                    
#if DEBUG_XFR_INPUT_STREAM
                    log_debug("xfr_input_stream: #%u %{recordwire} ; (IXFR LAST)", data->record_index, record);
#endif

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
            {
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
                        return_value = INVALID_STATE_ERROR; // XFR mode should be "ANY"
                        return return_value;    // invalid status
                    }
                }

                break;
            }
        }
        
#if DEBUG_XFR_INPUT_STREAM
        log_debug("xfr_input_stream: >%u %{recordwire}", data->record_index, record);
#endif

        if(FAIL(return_value = output_stream_write(&data->pipe_stream_output, record, record_len)))
        {
            data->eos = TRUE;

            break;
        }
        
        if(return_value != (s32)record_len)
        {
            return UNEXPECTED_EOF;
        }

        data->record_index++;
    }
    
    return return_value;
}

static ya_result
xfr_input_stream_fill(input_stream *is, u32 len)
{
    xfr_input_stream_data *data = (xfr_input_stream_data*)is->data;
    input_stream *source_stream = &data->source_stream;
    message_data *mesg = data->message;
#if DNSCORE_HAS_TSIG_SUPPORT
    const tsig_item *tsig = message_tsig_get_key(mesg);
#endif
    packet_unpack_reader_data *pr = &data->reader;
    
    if(FAIL(data->last_error))
    {
        return data->last_error;
    }
    
    ya_result ret = SUCCESS;
    
    while(pipe_stream_read_available(&data->pipe_stream_input) < (s32)len)
    {
        /* read the packet and write on the output (so it can be read back on the input) */
        
        if(FAIL(ret = xfr_input_stream_read_packet(data)))
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
        
#if DEBUG
        message_debug_trash_buffer(mesg);
#endif
        
        u16 tcplen;
        
        ret = input_stream_read_nu16(source_stream, &tcplen); /* this is wrong ... */

        if(ret != 2)
        {
#if DEBUG
            log_debug("xfr_input_stream_read: next message is %ld bytes long", ret);
#endif
            break;
        }

        if(tcplen == 0)
        {
            ret = UNEXPECTED_EOF;
            break;
        }

        if(FAIL(ret = input_stream_read_fully(source_stream, message_get_buffer(mesg), tcplen)))
        {
            break;
        }
               
        message_set_size(mesg, ret);

#if DEBUG_XFR_INPUT_STREAM
        LOGGER_EARLY_CULL_PREFIX(MSG_INFO) message_log(MODULE_MSG_HANDLE, MSG_INFO, mesg);
#endif


#if DEBUG
        memset(&message_get_buffer(mesg)[tcplen], 0xdd, DNSPACKET_MAX_LENGTH + 1 - tcplen);
#endif
        /*
         * Check the headers
         */

        const u64 *h64 = (u64*)message_get_buffer(mesg);
        const u64 m64 = data->next_hdr_mask; // AXFR_NEXT_MESSAGE_HEADER_MASK;
        const u64 r64 = data->next_hdr_result; // AXFR_NEXT_MESSAGE_HEADER_RESULT;

        if(((*h64&m64) != r64) || (message_get_authority_count_ne(mesg) != 0))
        {
            u8 code = message_get_rcode(mesg);

            if(code != 0)
            {
                ret = MAKE_DNSMSG_ERROR(code);
            }
            else
            {
                ret = UNPROCESSABLE_MESSAGE;
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

            message_tsig_clear_key(mesg);

            if(FAIL(ret = tsig_message_extract(mesg)))
            {
                break;
            }
            
            if((ret == 1) && (message_tsig_get_key(mesg) != tsig))
            {
                /* This is not the one we started with */

                log_debug("xfr_input_stream: signature key does not match");

                ret = TSIG_BADSIG;
                break;
            }

            if(FAIL(ret = tsig_verify_tcp_next_message(mesg)))
            {
                break;
            }
        }
#endif
        message_header *header = message_get_header(mesg);
        
        data->ancount = ntohs(header->ancount);

        packet_reader_init_from_message_at(pr, mesg, DNS_HEADER_LENGTH);

        u16 n = ntohs(header->qdcount);
        
        while(n > 0)
        {
            if(FAIL(ret = packet_reader_skip_fqdn(pr))) // this is the domain already used for this query
            {
                break;
            }

            packet_reader_skip(pr, 4);

            n--;
        }
    } // for(;;) /* process all TCP chunks */
    
    return ret;
}

static ya_result
xfr_input_stream_read(input_stream *is, void *buffer_, u32 len)
{
    xfr_input_stream_data *data = (xfr_input_stream_data*)is->data;
    message_data *mesg = data->message;
#if DNSCORE_HAS_TSIG_SUPPORT
    const tsig_item *tsig = message_tsig_get_key(mesg);
#endif

    if(FAIL(data->last_error))
    {
        return data->last_error;
    }
    
    u8 *buffer = (u8*)buffer_;
    
    ya_result return_value = xfr_input_stream_fill(is, len);
    
    /* while there is not enough bytes on the input */
    
    if(ISOK(return_value))
    {
        if((return_value = pipe_stream_read_available(&data->pipe_stream_input)) > 0) // never fails
        {
            if(FAIL(return_value = input_stream_read(&data->pipe_stream_input, buffer, len)))
            {
#if DNSCORE_HAS_TSIG_SUPPORT
                if(data->need_cleanup_tsig)
                {
                    tsig_verify_tcp_last_message(mesg);
                    data->need_cleanup_tsig = FALSE;
                }
#endif
            }
        }
        else
        {
            // here, return_value == 0
#if DNSCORE_HAS_TSIG_SUPPORT
            if(tsig != NULL)
            {
                tsig_verify_tcp_last_message(mesg);
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
#endif
        }
    }
    else
    {
#if DNSCORE_HAS_TSIG_SUPPORT
        // cleanup
        tsig_verify_tcp_last_message(mesg);
        data->need_cleanup_tsig = FALSE;
#endif
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

#if DNSCORE_HAS_TSIG_SUPPORT
    if(data->need_cleanup_tsig)
    {
        message_clear_hmac(data->message);

        if(ISOK(data->last_error))
        {
#if DEBUG
            log_warn("xfr: %{dnsname}: TSIG has not been cleared (DEBUG)", data->origin);
#else
            log_debug("xfr: %{dnsname}: TSIG has not been cleared (%r)", data->origin, data->last_error);
#endif
        }
        data->need_cleanup_tsig = FALSE;
    }
#endif
    
#if DEBUG_XFR_INPUT_STREAM
    log_debug("xfr_input_stream: %{dnsname}: close, last serial is %i //////////////////////////////", data->origin, data->last_serial);
#endif
    
    pool_release(&xfr_pool, data->pool);
    
    output_stream_close(&data->pipe_stream_output);
    input_stream_close(&data->pipe_stream_input);
    free(data->first_soa_record);
    
    if(data->owns_message)
    {
        message_free(data->message);
    }
    
    if(data->owns_input_stream)
    {
        input_stream_close(&data->source_stream);
        output_stream_close(&data->source_output_stream);
    }
        
#if DEBUG
    memset(data, 0xfe, sizeof(xfr_input_stream_data));
#endif
    
    ZFREE(data, xfr_input_stream_data); // used to be leaked ?
    
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
xfr_input_stream_init(input_stream* filtering_stream, const u8 *origin, input_stream *xfr_source_stream, message_data *mesg, u32 current_serial, xfr_copy_flags flags)
{
    yassert(filtering_stream != NULL && origin != NULL && xfr_source_stream != NULL && mesg != NULL);
    
    mutex_lock(&xfr_pool_init_mtx);
    if(!xfr_pool_initialised)
    {
        xfr_pool_initialised = TRUE;
        pool_init(&xfr_pool, xfr_pool_alloc, xfr_pool_free, NULL, "xfr stream data pool");
    }
    mutex_unlock(&xfr_pool_init_mtx);
    
    input_stream *is = xfr_source_stream;
    
    packet_unpack_reader_data pr;
    u8 *buffer;
    u8 *record;
    u8 *ptr;
    u8 *pool = NULL;   // 128KB
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

#if DNSCORE_HAS_TSIG_SUPPORT
    u8 old_mac[64];
#endif
    
#if DEBUG_XFR_INPUT_STREAM
    log_debug("xfr_input_stream: %{dnsname}: init, current serial is %i //////////////////////////////", origin, current_serial);
#endif
    
    /*
     * ensure the stream will be unusable if the initialisation fails
     */
    
    input_stream_set_sink(filtering_stream);
    
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
            u8 tmp_hdr[DNS_HEADER_LENGTH];
            
            if(ISOK(return_value = input_stream_read_fully(is, tmp_hdr, DNS_HEADER_LENGTH)))
            {
                return_value = MAKE_DNSMSG_ERROR(MESSAGE_RCODE(tmp_hdr));
            }
        }

        return return_value;
    }
    
    pool = pool_alloc(&xfr_pool);
    
    /* read the whole message */

    buffer = message_get_buffer(mesg);
    record = pool; // no persistence required

    if(FAIL(return_value = input_stream_read_fully(is, buffer, tcplen)))
    {
        pool_release(&xfr_pool, pool);
        
        return return_value;
    }

    message_set_size(mesg, return_value);
    
#if DEBUG_XFR_INPUT_STREAM
    LOGGER_EARLY_CULL_PREFIX(MSG_INFO) message_log(MODULE_MSG_HANDLE, MSG_INFO, mesg);
#endif
    
    /* check the message makes sense */

    bool axfr_strict_authority = (flags & XFR_LOOSE_AUTHORITY) == 0;

    const u64 *h64 = (u64*)buffer;
    u64 m64 = axfr_strict_authority ? AXFR_MESSAGE_HEADER_MASK : AXFR_MESSAGE_LENIENT_HEADER_MASK;
    u64 r64 = axfr_strict_authority ? AXFR_MESSAGE_HEADER_RESULT : AXFR_MESSAGE_LENIENT_HEADER_RESULT;

    if(((*h64&m64) != r64) || (message_get_authority_count_ne(mesg) != 0))
    {
        u8 code = message_get_rcode(mesg);

        if(code != 0)
        {
            return_value = MAKE_DNSMSG_ERROR(code);
        }
        else
        {
            return_value = UNPROCESSABLE_MESSAGE;
        }

        pool_release(&xfr_pool, pool);
        
        return return_value;
    }

    packet_reader_init_from_message(&pr, mesg);
    packet_reader_read_fqdn(&pr, record, RDATA_MAX_LENGTH + 1);

    if(!dnsname_equals(record, origin))
    {
        pool_release(&xfr_pool, pool);
        
        return INVALID_PROTOCOL;
    }

    if(FAIL(return_value = packet_reader_read_u16(&pr, &qtype)))
    {
        pool_release(&xfr_pool, pool);
        
        return return_value;
    }
    
    if(return_value != 2)
    {
        pool_release(&xfr_pool, pool);
        
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
            if((flags & XFR_ALLOW_AXFR) == 0)
            {
                pool_release(&xfr_pool, pool);
                
                return INVALID_PROTOCOL;
            }
            break;
        }
        case TYPE_IXFR:
        {
            if((flags & XFR_ALLOW_IXFR) == 0)
            {
                pool_release(&xfr_pool, pool);
                
                return INVALID_PROTOCOL;
            }
            break;
        }
        default:
        {
            pool_release(&xfr_pool, pool);
            
            return INVALID_PROTOCOL;
        }
    }

    if(FAIL(return_value = packet_reader_read_u16(&pr, &qclass)))
    {
        pool_release(&xfr_pool, pool);
        
        return return_value;
    }

    if(qclass != CLASS_IN)
    {
        // wrong answer
        
        pool_release(&xfr_pool, pool);
        
        return INVALID_PROTOCOL;
    }
    
    /* check for TSIG and verify */

    u16 ancount = ntohs(MESSAGE_AN(buffer));
    
#if DNSCORE_HAS_TSIG_SUPPORT
    if((last_message_had_tsig = ((tsig = message_tsig_get_key(mesg)) != NULL)))
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
        
        message_tsig_clear_key(mesg);

        old_mac_size = message_tsig_mac_get_size(mesg);
        message_tsig_mac_copy(mesg, old_mac);

        if(FAIL(return_value = tsig_message_extract(mesg)))
        {
            log_debug("xfr_input_stream: error extracting the signature");

            pool_release(&xfr_pool, pool);
            
            return return_value;
        }

        if(return_value == 0)
        {
            log_debug("xfr_input_stream: no signature when one was requested");

            pool_release(&xfr_pool, pool);
            
            return TSIG_BADSIG; /* no signature, when one was requested, is a bad signature */
        }

        if(tsig != message_tsig_get_key(mesg))
        {
            /* This is not the one we started with */

            log_debug("xfr_input_stream: signature key does not match");

            pool_release(&xfr_pool, pool);
            
            return TSIG_BADSIG;
        }

        /// check that the tsig in the message matches theh one that was sent

        if(FAIL(return_value = tsig_verify_tcp_first_message(mesg, old_mac, old_mac_size)))
        {
            pool_release(&xfr_pool, pool);
            
            return return_value;
        }

        pr.packet_size = message_get_size(mesg);
        
        need_cleanup_tsig = TRUE;
    }
#endif
    
    log_debug("xfr_input_stream: expecting %5d answer records", ancount);    

    /*
     * read the SOA (it MUST be an SOA)
     */

    if(FAIL(record_len = packet_reader_read_record(&pr, record, RDATA_MAX_LENGTH + 1)))
    {
        pool_release(&xfr_pool, pool);
        
        return record_len;
    }

    if(!dnsname_equals(record, origin))
    {
        pool_release(&xfr_pool, pool);
        
        return INVALID_PROTOCOL;
    }

    ptr = &record[origin_len];

    if(GET_U16_AT(*ptr) != TYPE_SOA)
    {
        pool_release(&xfr_pool, pool);
        
        return INVALID_PROTOCOL;
    }

    ptr += 8; /* type class ttl */
    
    u16 rdata_size = ntohs(GET_U16_AT(*ptr));
    
    if(rdata_size < 22)
    {
        pool_release(&xfr_pool, pool);
        
        return INVALID_PROTOCOL;
    }

    rdata_size -= 16;

    ptr += 2; /* rdata size */

    s32 len = dnsname_len(ptr);

    if(len >= rdata_size)
    {
        pool_release(&xfr_pool, pool);
        
        return INVALID_PROTOCOL;
    }
    rdata_size -= len;
    ptr += len;

    len = dnsname_len(ptr);
    if(len >= rdata_size)
    {
        pool_release(&xfr_pool, pool);
        
        return INVALID_PROTOCOL;
    }
    rdata_size -= len;

    if(rdata_size != 4)
    {
        pool_release(&xfr_pool, pool);
        
        return INVALID_PROTOCOL;
    }

    ptr += len;

    // if the serial of the SOA is the same one as we know, then there is no
    // need to download the zone
    
    last_serial = ntohl(GET_U32_AT(ptr[0]));
    
    if(last_serial == current_serial)
    {
        pool_release(&xfr_pool, pool);
        
        return ZONE_ALREADY_UP_TO_DATE;
    }

    u32 last_refresh = ntohl(GET_U32_AT(ptr[4]));
    u32 last_retry = ntohl(GET_U32_AT(ptr[8]));
    u32 last_expire = ntohl(GET_U32_AT(ptr[12]));
    u32 last_nttl = ntohl(GET_U32_AT(ptr[16]));

    xfr_input_stream_data *data;    
    ZALLOC_OBJECT_OR_DIE( data, xfr_input_stream_data, XFRISDTA_TAG);
    ZEROMEMORY(data, sizeof(xfr_input_stream_data));
    
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

    MALLOC_OR_DIE(u8*, data->first_soa_record, record_len, XFRISSOA_TAG);
    MEMCOPY(data->first_soa_record, record, record_len);
    data->first_soa_record_size = record_len;         

    filtering_stream->vtbl = &xfr_input_stream_vtbl;
    filtering_stream->data = data;
    
    u32 pipe_buffer_size = 0x10000;
    
    pipe_stream_init(&data->pipe_stream_output, &data->pipe_stream_input, pipe_buffer_size);
    MEMCOPY(&data->reader, &pr, sizeof(packet_unpack_reader_data));
    
    data->origin = origin;
    data->message = mesg;
    
    data->pool = pool;
    
    data->ancount = ancount - 1;
    data->record_index++;
    data->last_serial = last_serial;
    data->last_refresh = last_refresh;
    data->last_retry = last_retry;
    data->last_expire = last_expire;
    data->last_nttl = last_nttl;

    if(axfr_strict_authority)
    {
        data->mesg_hdr_mask = AXFR_MESSAGE_HEADER_MASK;
        data->mesg_hdr_result = AXFR_MESSAGE_HEADER_RESULT;
        data->next_hdr_mask = AXFR_NEXT_MESSAGE_HEADER_MASK;
        data->next_hdr_result = AXFR_NEXT_MESSAGE_HEADER_RESULT;
    }
    else
    {
        data->mesg_hdr_mask = AXFR_MESSAGE_LENIENT_HEADER_MASK;
        data->mesg_hdr_result = AXFR_MESSAGE_LENIENT_HEADER_RESULT;
        data->next_hdr_mask = AXFR_NEXT_MESSAGE_LENIENT_HEADER_MASK;
        data->next_hdr_result = AXFR_NEXT_MESSAGE_LENIENT_HEADER_RESULT;
    }

    data->xfr_mode = TYPE_ANY;
    data->ixfr_mark = FALSE;
    data->last_message_had_tsig = last_message_had_tsig;
    data->source_stream = *is;
    data->need_cleanup_tsig = need_cleanup_tsig;
    data->owns_message = FALSE;
    data->owns_input_stream = FALSE;
    
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
    
    if(ISOK(return_value = xfr_input_stream_fill(filtering_stream, pipe_buffer_size / 2)))
    {
        if(ISOK(return_value = xfr_input_stream_read_packet(data)))
        {
            return return_value;
        }
    }
    
    xfr_input_stream_close(filtering_stream);
    
    return return_value;
}

ya_result
xfr_input_stream_init_with_query(input_stream* filtering_stream, const host_address *server, const u8 *origin, s32 ttl, const u8 *soa_rdata, int soa_rdata_size, xfr_copy_flags flags)
{
    input_stream is;
    output_stream os;
    random_ctx rndctx = thread_pool_get_random_ctx();
    message_data *mesg = message_new_instance();
    ya_result ret;
    u32 serial;
    u16 id;
    
    if(FAIL(ret = rr_soa_get_serial(soa_rdata, soa_rdata_size, &serial)))
    {
        return ret;
    }
    
     id = (u16)random_next(rndctx);
             
    message_make_ixfr_query(mesg, id, origin, ttl, soa_rdata_size, soa_rdata);
    
#if DNSCORE_HAS_TSIG_SUPPORT
    if(server->tsig != NULL)
    {
        if(FAIL(ret = message_sign_query(mesg, server->tsig)))
        {
            message_free(mesg);
            return ret;
        }
    }
#endif

    /*
     * connect & send
     */

    while(FAIL(ret = tcp_input_output_stream_connect_host_address(server, &is, &os, 3)))
    {
        if(ret != MAKE_ERRNO_ERROR(EINTR))
        {
            message_free(mesg);
            return ret;
        }
    }
    
    if(FAIL(ret = message_write_tcp(mesg, &os)))
    {
        input_stream_close(&is);
        output_stream_close(&os);

        message_free(mesg);

        return ret;
    }
    
    output_stream_flush(&os);

    int fd = fd_input_stream_get_filedescriptor(&is);

    tcp_set_sendtimeout(fd, 10, 0);
    tcp_set_recvtimeout(fd, 10, 0);
    
    if(FAIL(xfr_input_stream_init(filtering_stream, origin, &is, mesg, serial, flags)))
    {
        input_stream_close(&is);
        output_stream_close(&os);

        message_free(mesg);

        return ret;
    }
    
    xfr_input_stream_data *data = (xfr_input_stream_data*)filtering_stream->data;
    data->owns_message = TRUE;
    data->owns_input_stream = TRUE;
    data->source_output_stream = os;

    return SUCCESS;
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
    return data->origin;
}

u32
xfr_input_stream_get_serial(input_stream *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data*)in_xfr_input_stream->data;
    return data->last_serial;
}

u32
xfr_input_stream_get_refresh(input_stream *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data*)in_xfr_input_stream->data;
    return data->last_refresh;
}

void
xfr_input_stream_finalize()
{
    mutex_lock(&xfr_pool_init_mtx);
    if(xfr_pool_initialised)
    {
        pool_finalize(&xfr_pool);
        xfr_pool_initialised = FALSE;
    }
    mutex_unlock(&xfr_pool_init_mtx);
}

/** @} */

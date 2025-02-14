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
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "dnscore/xfr_input_stream.h"

#include "dnscore/zalloc.h"
#include <dnscore/dns_packet_reader.h>
#include "dnscore/format.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/buffer_input_stream.h"
#include "dnscore/buffer_output_stream.h"
#include "dnscore/fdtools.h"
#include "dnscore/pipe_stream.h"
#include "dnscore/dns_message.h"
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

#define MODULE_MSG_HANDLE      g_system_logger

#define DEBUG_XFR_INPUT_STREAM 0

#define XFRISDTA_TAG           0x4154445349524658
#define XFRISSOA_TAG           0x414f535349524658
#define XFRPOOL_TAG            0x4c4f4f50524658

struct xfr_input_stream_data
{
    output_stream_t     pipe_stream_output;
    input_stream_t      pipe_stream_input;
    input_stream_t      source_stream;
    output_stream_t     source_output_stream;
    dns_packet_reader_t reader;

    dns_message_t      *message;
    const uint8_t      *origin;
    uint8_t            *pool; // 64KB

    uint8_t            *first_soa_record;
    uint32_t            first_soa_record_size;

    uint16_t            ancount;
    uint16_t            xfr_mode;
    uint32_t            record_index; // index of the record in the stream

    uint32_t            last_serial;
    uint32_t            last_refresh;
    uint32_t            last_retry;
    uint32_t            last_expire;
    uint32_t            last_nttl;

    uint64_t            mesg_hdr_mask;
    uint64_t            mesg_hdr_result;
    uint64_t            next_hdr_mask;
    uint64_t            next_hdr_result;

    uint64_t            size_total;
    uint32_t            mesg_count;

    ya_result           last_error;
    bool                eos;
    bool                ixfr_mark;
    bool                owns_message;
    bool                owns_input_stream;
#if DNSCORE_HAS_TSIG_SUPPORT
    bool last_message_had_tsig;
    bool need_cleanup_tsig;
#endif
};

typedef struct xfr_input_stream_data xfr_input_stream_data;

static pool_t                        g_xfr_pool;
static initialiser_state_t           xfr_pool_init_state = INITIALISE_STATE_INIT;

static void                         *xfr_pool_alloc(void *args)
{
    (void)args;
    void *p;
    MALLOC_OBJECT_ARRAY(p, uint8_t, 0x1010a, XFRPOOL_TAG);
    // void *p = malloc(0x1010a);
    return p;
}

static void xfr_pool_free(void *ptr, void *args)
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

// #if HAS_NON_AA_AXFR_SUPPORT

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
#define AXFR_MESSAGE_LENIENT_HEADER_MASK        (((uint64_t)0) | (((uint64_t)(QR_BITS | TC_BITS)) << 40) | (((uint64_t)(RA_BITS | RCODE_BITS)) << 32) | ((uint64_t)1LL << 16))

#define AXFR_MESSAGE_LENIENT_HEADER_RESULT      (((uint64_t)(QR_BITS) << 40) | (((uint64_t)1LL) << 16))

#define AXFR_NEXT_MESSAGE_LENIENT_HEADER_MASK   (((uint64_t)0LL) | (((uint64_t)(QR_BITS | TC_BITS)) << 40) | (((uint64_t)(RCODE_BITS)) << 32))

#define AXFR_NEXT_MESSAGE_LENIENT_HEADER_RESULT (((uint64_t)(QR_BITS)) << 40)

#else
#define AXFR_MESSAGE_LENIENT_HEADER_MASK        (((uint64_t)0LL) | (((uint64_t)(QR_BITS | TC_BITS)) << 16) | (((uint64_t)(RCODE_BITS)) << 24) | (((uint64_t)1LL) << 40))

#define AXFR_MESSAGE_LENIENT_HEADER_RESULT      ((((uint64_t)(QR_BITS)) << 16) | (((uint64_t)1LL) << 40))

#define AXFR_NEXT_MESSAGE_LENIENT_HEADER_MASK   (((uint64_t)0LL) | (((uint64_t)(QR_BITS | TC_BITS)) << 16) | (((uint64_t)(RCODE_BITS)) << 24))

#define AXFR_NEXT_MESSAGE_LENIENT_HEADER_RESULT (((uint64_t)(QR_BITS)) << 16)

#endif

// #else

/*
 * RFC compliant masks (AA bit must be set)
 */

#ifdef WORDS_BIGENDIAN
#define AXFR_MESSAGE_HEADER_MASK        (((uint64_t)0) | (((uint64_t)(QR_BITS | AA_BITS | TC_BITS)) << 40) | (((uint64_t)(RA_BITS | RCODE_BITS)) << 32) | ((uint64_t)1LL << 16))

#define AXFR_MESSAGE_HEADER_RESULT      (((uint64_t)(QR_BITS | AA_BITS) << 40) | (((uint64_t)1LL) << 16))

#define AXFR_NEXT_MESSAGE_HEADER_MASK   (((uint64_t)0LL) | (((uint64_t)(QR_BITS | AA_BITS | TC_BITS)) << 40) | (((uint64_t)(RCODE_BITS)) << 32))

#define AXFR_NEXT_MESSAGE_HEADER_RESULT (((uint64_t)(QR_BITS | AA_BITS)) << 40)

#else
#define AXFR_MESSAGE_HEADER_MASK        (((uint64_t)0LL) | (((uint64_t)(QR_BITS | AA_BITS | TC_BITS)) << 16) | (((uint64_t)(RCODE_BITS)) << 24) | (((uint64_t)1LL) << 40))

#define AXFR_MESSAGE_HEADER_RESULT      ((((uint64_t)(QR_BITS | AA_BITS)) << 16) | (((uint64_t)1LL) << 40))

#define AXFR_NEXT_MESSAGE_HEADER_MASK   (((uint64_t)0LL) | (((uint64_t)(QR_BITS | AA_BITS | TC_BITS)) << 16) | (((uint64_t)(RCODE_BITS)) << 24))

#define AXFR_NEXT_MESSAGE_HEADER_RESULT (((uint64_t)(QR_BITS | AA_BITS)) << 16)

#endif

// #endif

/*
 * Reads the content of a message from the reader field in data (packet reader)
 * The ancount field in data contains the number of records to read
 * Every record read is written to the output pipe
 */

static ya_result xfr_input_stream_read_packet(xfr_input_stream_data *data)
{
    dns_packet_reader_t *reader = &data->reader;
    uint8_t             *record = data->pool; // no persistence of content needed
    int32_t              record_len;
    ya_result            return_value = SUCCESS;

#if DEBUG_XFR_INPUT_STREAM
    log_debug("xfr_input_stream_read_packet(%p) ancount=%hd record_index=%u", data, data->ancount, data->record_index);
#endif

    while((data->ancount > 0) && (pipe_stream_write_available(&data->pipe_stream_output) > 2048))
    {
        --data->ancount;

        if(FAIL(record_len = dns_packet_reader_read_record(reader, record, RDATA_LENGTH_MAX + 1)))
        {
            if(record_len != UNSUPPORTED_TYPE)
            {
                data->eos = true;

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

        const uint8_t *ptr = record + dnsname_len(record);

        uint16_t       rtype = GET_U16_AT(*ptr);

        switch(rtype)
        {
            case TYPE_SOA:
            {
                /* handle SOA case */

                if(!dnsname_equals(record, data->origin))
                {
                    data->eos = true;

                    return_value = MAKE_RCODE_ERROR(FP_XFR_QUERYERROR); // OWNER OF SOA RECORD SHOULD BE ORIGIN (protocol error)

                    return return_value;
                }

                ptr += 10; /* type class ttl rdata_size */
                ptr += dnsname_len(ptr);
                ptr += dnsname_len(ptr);
                uint32_t soa_serial = ntohl(GET_U32_AT(*ptr));

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
                    // if it's an AXFR or this is the second time it happens on an IXFR, then it's then end of the
                    // stream

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
                        data->eos = true;

                        return return_value; // reached the end
                    }

                    // IXFR needs to find the mark twice

#if DEBUG_XFR_INPUT_STREAM
                    log_debug("xfr_input_stream: #%u %{recordwire} ; (IXFR LAST)", data->record_index, record);
#endif

                    data->ixfr_mark = true;
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
                        return return_value;                // invalid status
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
            data->eos = true;

            break;
        }

        if(return_value != (int32_t)record_len)
        {
            return UNEXPECTED_EOF;
        }

        data->record_index++;
    }

    return return_value;
}

static ya_result xfr_input_stream_fill(input_stream_t *is, uint32_t len)
{
    xfr_input_stream_data *data = (xfr_input_stream_data *)is->data;
    input_stream_t        *source_stream = &data->source_stream;
    dns_message_t         *mesg = data->message;
#if DNSCORE_HAS_TSIG_SUPPORT
    const tsig_key_t *tsig = dns_message_tsig_get_key(mesg);
#endif
    dns_packet_reader_t *pr = &data->reader;

    if(FAIL(data->last_error))
    {
        return data->last_error;
    }

    ya_result ret = SUCCESS;

    while(pipe_stream_read_available(&data->pipe_stream_input) < (int32_t)len)
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
        dns_message_debug_trash_buffer(mesg);
#endif

        uint16_t tcplen;

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

        if(FAIL(ret = input_stream_read_fully(source_stream, dns_message_get_buffer(mesg), tcplen)))
        {
            break;
        }

        dns_message_set_size(mesg, ret);

        data->mesg_count++;
        data->size_total += ret;

#if DEBUG_XFR_INPUT_STREAM
        LOGGER_EARLY_CULL_PREFIX(MSG_INFO) message_log(MODULE_MSG_HANDLE, MSG_INFO, mesg);
#endif

#if DEBUG
        memset(&dns_message_get_buffer(mesg)[tcplen], 0xdd, DNSPACKET_LENGTH_MAX + 1 - tcplen);
#endif
        /*
         * Check the headers
         */

        const uint64_t *h64 = (uint64_t *)dns_message_get_buffer(mesg);
        const uint64_t  m64 = data->next_hdr_mask;   // AXFR_NEXT_MESSAGE_HEADER_MASK;
        const uint64_t  r64 = data->next_hdr_result; // AXFR_NEXT_MESSAGE_HEADER_RESULT;

        if(((*h64 & m64) != r64) || (dns_message_get_authority_count_ne(mesg) != 0))
        {
            uint8_t code = dns_message_get_rcode(mesg);

            if(code != 0)
            {
                ret = MAKE_RCODE_ERROR(code);
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

            dns_message_tsig_clear_key(mesg);

            if(FAIL(ret = tsig_message_extract(mesg)))
            {
                break;
            }

            if((ret == 1) && (dns_message_tsig_get_key(mesg) != tsig))
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
        dns_message_header_t *header = dns_message_get_header(mesg);

        data->ancount = ntohs(header->ancount);

        dns_packet_reader_init_from_message_at(pr, mesg, DNS_HEADER_LENGTH);

        uint16_t n = ntohs(header->qdcount);

        while(n > 0)
        {
            if(FAIL(ret = dns_packet_reader_skip_fqdn(pr))) // this is the domain already used for this query
            {
                break;
            }

            if(FAIL(ret = dns_packet_reader_skip(pr, 4)))
            {
                break;
            }

            n--;
        }
    } // for(;;) /* process all TCP chunks */

    return ret;
}

static ya_result xfr_input_stream_read(input_stream_t *is, void *buffer_, uint32_t len)
{
    xfr_input_stream_data *data = (xfr_input_stream_data *)is->data;
    dns_message_t         *mesg = data->message;
#if DNSCORE_HAS_TSIG_SUPPORT
    const tsig_key_t *tsig = dns_message_tsig_get_key(mesg);
#endif

    if(FAIL(data->last_error))
    {
        return data->last_error;
    }

    uint8_t  *buffer = (uint8_t *)buffer_;

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
                    data->need_cleanup_tsig = false;
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
                data->need_cleanup_tsig = false;

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
        data->need_cleanup_tsig = false;
#endif
    }

    data->last_error = return_value;

    return return_value;
}

static ya_result xfr_input_stream_skip(input_stream_t *is, uint32_t len)
{
    /*
     * The reader is too complicated to implement a skip, so skip is a wrapped read
     */

    uint32_t  remaining = len;
    ya_result return_value = SUCCESS;

    uint8_t   buffer[512];

    while(remaining > 0)
    {
        uint32_t n = MIN(remaining, sizeof(buffer));

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

static void xfr_input_stream_close(input_stream_t *is)
{
    xfr_input_stream_data *data = (xfr_input_stream_data *)is->data;

#if DNSCORE_HAS_TSIG_SUPPORT
    if(data->need_cleanup_tsig)
    {
        dns_message_clear_hmac(data->message);

        if(ISOK(data->last_error))
        {
#if DEBUG
            log_warn("xfr: %{dnsname}: TSIG has not been cleared (DEBUG)", data->origin);
#else
            log_debug("xfr: %{dnsname}: TSIG has not been cleared (%r)", data->origin, data->last_error);
#endif
        }
        data->need_cleanup_tsig = false;
    }
#endif

#if DEBUG_XFR_INPUT_STREAM
    log_debug("xfr_input_stream: %{dnsname}: close, last serial is %i //////////////////////////////", data->origin, data->last_serial);
#endif

    pool_release(&g_xfr_pool, data->pool);

    output_stream_close(&data->pipe_stream_output);
    input_stream_close(&data->pipe_stream_input);
    free(data->first_soa_record);

    if(data->owns_message)
    {
        dns_message_delete(data->message);
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

static const input_stream_vtbl xfr_input_stream_vtbl = {
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

ya_result xfr_input_stream_init(input_stream_t *filtering_stream, const uint8_t *origin, input_stream_t *xfr_source_stream, dns_message_t *mesg, uint32_t current_serial, xfr_copy_flags flags)
{
    yassert(filtering_stream != NULL && origin != NULL && xfr_source_stream != NULL && mesg != NULL);

    if(initialise_state_begin(&xfr_pool_init_state))
    {
        pool_init(&g_xfr_pool, xfr_pool_alloc, xfr_pool_free, NULL, "xfr stream data pool");
        initialise_state_ready(&xfr_pool_init_state);
    }

    input_stream_t     *is = xfr_source_stream;

    dns_packet_reader_t pr;
    uint8_t            *buffer;
    uint8_t            *record;
    uint8_t            *ptr;
    uint8_t            *pooled_65802_bytes_buffer = NULL; // 128KB
#if DNSCORE_HAS_TSIG_SUPPORT
    const tsig_key_t *tsig;
#endif
    ya_result record_len;
    ya_result return_value;
    uint32_t  origin_len;
    uint32_t  last_serial = 0;

    uint16_t  tcplen;
    uint16_t  qtype;
    uint16_t  qclass;

    uint16_t  old_mac_size;

    bool      last_message_had_tsig;
    bool      need_cleanup_tsig = false;

#if DNSCORE_HAS_TSIG_SUPPORT
    uint8_t old_mac[HMAC_BUFFER_SIZE];
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

    /* TCP length */

    if(FAIL(return_value = input_stream_read_nu16(is, &tcplen)))
    {
        return return_value;
    }

    if(return_value != 2)
    {
        return UNEXPECTED_EOF;
    }

    // if the length is not enough, return the most appropriate error code

    origin_len = dnsname_len(origin);

    // this ensures both the rtype and rclass are present

    if(tcplen < DNS_HEADER_LENGTH + origin_len + 4)
    {
        return_value = UNEXPECTED_EOF;

        if(tcplen >= DNS_HEADER_LENGTH)
        {
            uint8_t tmp_hdr[DNS_HEADER_LENGTH];

            // see if there is an error code in the header

            if(ISOK(return_value = input_stream_read_fully(is, tmp_hdr, DNS_HEADER_LENGTH)))
            {
                int32_t message_error_code = MAKE_RCODE_ERROR(MESSAGE_RCODE(tmp_hdr));
                if(message_error_code == MAKE_RCODE_ERROR(0))
                {
                    // no error, it's clearly an EOF
                    return_value = UNEXPECTED_EOF;
                }
                else
                {
                    return_value = message_error_code;
                }
            }
        }

        return return_value;
    }

    pooled_65802_bytes_buffer = pool_alloc(&g_xfr_pool); // the allocator will either return an item or abort

    /* read the whole message */

    buffer = dns_message_get_buffer(mesg);
    record = pooled_65802_bytes_buffer; // no persistence required

    if(FAIL(return_value = input_stream_read_fully(is, buffer, tcplen)))
    {
        pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

        return return_value;
    }

    dns_message_set_size(mesg, return_value);

    uint32_t data_mesg_count = 1;
    uint64_t data_size_total = return_value;

#if DEBUG_XFR_INPUT_STREAM
    LOGGER_EARLY_CULL_PREFIX(MSG_INFO) message_log(MODULE_MSG_HANDLE, MSG_INFO, mesg);
#endif

    /* check the message makes sense */

    bool            axfr_strict_authority = (flags & XFR_LOOSE_AUTHORITY) == 0;

    const uint64_t *h64 = (uint64_t *)buffer;
    uint64_t        m64 = axfr_strict_authority ? AXFR_MESSAGE_HEADER_MASK : AXFR_MESSAGE_LENIENT_HEADER_MASK;
    uint64_t        r64 = axfr_strict_authority ? AXFR_MESSAGE_HEADER_RESULT : AXFR_MESSAGE_LENIENT_HEADER_RESULT;

    if(((*h64 & m64) != r64) || (dns_message_get_authority_count_ne(mesg) != 0))
    {
        uint8_t code = dns_message_get_rcode(mesg);

        if(code != 0)
        {
            return_value = MAKE_RCODE_ERROR(code);
        }
        else
        {
            return_value = UNPROCESSABLE_MESSAGE;
        }

        pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

        return return_value;
    }

    /*
     * @note 20240320 edf -- in the above if, the mask in m64 masks for RCODE and the expected value is always 0
     *                       this means that if we reach here, RCODE is always RCODE_NOERROR
     */

    dns_packet_reader_init_from_message(&pr, mesg);

    if(FAIL(dns_packet_reader_read_fqdn(&pr, record, RDATA_LENGTH_MAX + 1)))
    {
        pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);
        return INVALID_PROTOCOL;
    }

    if(!dnsname_equals(record, origin))
    {
        pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

        return INVALID_PROTOCOL;
    }

    dns_packet_reader_read_u16(&pr, &qtype); // cannot fail because an ealier test ensures the rtype is present

    /*
     * @note 20240320 edf -- dns_packet_reader_read_u16 can only return 2 or UNEXPECTED_EOF
     */

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
                pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

                return INVALID_PROTOCOL;
            }
            break;
        }
        case TYPE_IXFR:
        {
            if((flags & XFR_ALLOW_IXFR) == 0)
            {
                pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

                return INVALID_PROTOCOL;
            }
            break;
        }
        default:
        {
            pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

            return INVALID_PROTOCOL;
        }
    }

    dns_packet_reader_read_u16(&pr, &qclass); // cannot fail because an earlier test ensures the rclass is present

    if(qclass != CLASS_IN)
    {
        // wrong answer

        pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

        return INVALID_PROTOCOL;
    }

    /* check for TSIG and verify */

    uint16_t ancount = ntohs(MESSAGE_AN(buffer));

#if DNSCORE_HAS_TSIG_SUPPORT
    if((last_message_had_tsig = ((tsig = dns_message_tsig_get_key(mesg)) != NULL)))
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

        dns_message_tsig_clear_key(mesg);
        old_mac_size = dns_message_tsig_mac_get_size(mesg);
        dns_message_tsig_mac_copy(mesg, old_mac);

        if(FAIL(return_value = tsig_message_extract(mesg)))
        {
            log_debug("xfr_input_stream: error extracting the signature");

            pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

            return return_value;
        }

        if(return_value == 0)
        {
            log_debug("xfr_input_stream: no signature when one was requested");

            pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

            return TSIG_BADSIG; /* no signature, when one was requested, is a bad signature */
        }

        if(tsig != dns_message_tsig_get_key(mesg))
        {
            /* This is not the one we started with */

            log_debug("xfr_input_stream: signature key does not match");

            pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

            return TSIG_BADSIG;
        }

        /// check that the tsig in the message matches the one that was sent

        if(FAIL(return_value = tsig_verify_tcp_first_message(mesg, old_mac, old_mac_size)))
        {
            pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

            return return_value;
        }

        pr.packet_size = dns_message_get_size(mesg);

        need_cleanup_tsig = true;
    }
#endif

    log_debug("xfr_input_stream: expecting %5d answer records", ancount);

    /*
     * read the SOA (it MUST be an SOA)
     */

    if(FAIL(record_len = dns_packet_reader_read_record(&pr, record, RDATA_LENGTH_MAX + 1)))
    {
        pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

        return record_len;
    }

    if(!dnsname_equals(record, origin))
    {
        pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

        return INVALID_PROTOCOL;
    }

    ptr = &record[origin_len]; // points to the rtype

    if(GET_U16_AT(*ptr) != TYPE_SOA)
    {
        pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

        return INVALID_PROTOCOL;
    }

    ptr += 8; // skips rtype rclass rttl

#ifndef NDEBUG
    uint16_t rdata_size = ntohs(GET_U16_AT(*ptr));
#endif

    /// @note 20240320 edf -- as the SOA record has been read with dns_packet_reader_read_record,
    ///                       it's guaranteed to be at least 22 bytes long

    ptr += 2; // rdata size

    int32_t mname_len = dnsname_len(ptr);

    /// @note 20240320 edf -- as the SOA record has been read with dns_packet_reader_read_record,
    ///                       it's guaranteed that the rdata_size has been updated and is correct
    ///                       for the content of the rdata
    ///                       the two fqdn in the SOA rdata plus 20 is the total length of the rdata

    ptr += mname_len;

    int32_t rname_len = dnsname_len(ptr);

    ptr += rname_len;

    assert(mname_len + rname_len + 20 == rdata_size);

    // if the serial of the SOA is the same one as we know, then there is no
    // need to download the zone

    last_serial = ntohl(GET_U32_AT(ptr[0]));

    if(last_serial == current_serial)
    {
        pool_release(&g_xfr_pool, pooled_65802_bytes_buffer);

        return ZONE_ALREADY_UP_TO_DATE;
    }

    uint32_t               last_refresh = ntohl(GET_U32_AT(ptr[4]));
    uint32_t               last_retry = ntohl(GET_U32_AT(ptr[8]));
    uint32_t               last_expire = ntohl(GET_U32_AT(ptr[12]));
    uint32_t               last_nttl = ntohl(GET_U32_AT(ptr[16]));

    xfr_input_stream_data *data;
    ZALLOC_OBJECT_OR_DIE(data, xfr_input_stream_data, XFRISDTA_TAG);
    ZEROMEMORY(data, sizeof(xfr_input_stream_data));

    data->mesg_count = data_mesg_count;
    data->size_total = data_size_total;

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

    MALLOC_OR_DIE(uint8_t *, data->first_soa_record, record_len, XFRISSOA_TAG);
    MEMCOPY(data->first_soa_record, record, record_len);
    data->first_soa_record_size = record_len;

    filtering_stream->vtbl = &xfr_input_stream_vtbl;
    filtering_stream->data = data;

    uint32_t pipe_buffer_size = 0x10000;

    pipe_stream_init(&data->pipe_stream_output, &data->pipe_stream_input, pipe_buffer_size);
    MEMCOPY(&data->reader, &pr, sizeof(dns_packet_reader_t));

    data->origin = origin;
    data->message = mesg;

    data->pool = pooled_65802_bytes_buffer;

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
    data->ixfr_mark = false;
    data->source_stream = *is;
    data->owns_message = false;
    data->owns_input_stream = false;
#if DNSCORE_HAS_TSIG_SUPPORT
    data->last_message_had_tsig = last_message_had_tsig;
    data->need_cleanup_tsig = need_cleanup_tsig;
#endif

    /*
     * Then we read all records for all packets
     * If we find an SOA ...
     *      AXFR: it has to be the last serial and it is the end of the stream.
     *      IXFR: if it's not the last serial it has to go from step to step
     *            AND once we have reached the "last serial" once, the next hit is the end of the stream.
     */

    data->eos = false;

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

ya_result xfr_input_stream_init_with_query_and_timeout(input_stream_t *filtering_stream, const host_address_t *server, const uint8_t *origin, int32_t ttl, const uint8_t *soa_rdata, int soa_rdata_size, xfr_copy_flags flags, int32_t timeout)
{
    input_stream_t  is;
    output_stream_t os;
    random_ctx_t    rndctx = thread_pool_get_random_ctx();
    dns_message_t  *mesg = dns_message_new_instance();
    ya_result       ret;
    uint32_t        serial;
    uint16_t        id;

    if(FAIL(ret = rr_soa_get_serial(soa_rdata, soa_rdata_size, &serial)))
    {
        return ret;
    }

    id = (uint16_t)random_next(rndctx);

    dns_message_make_ixfr_query(mesg, id, origin, ttl, soa_rdata_size, soa_rdata);

#if DNSCORE_HAS_TSIG_SUPPORT
    if(server->tsig != NULL)
    {
        if(FAIL(ret = dns_message_sign_query(mesg, server->tsig)))
        {
            dns_message_delete(mesg);
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
            dns_message_delete(mesg);
            return ret;
        }
    }

    if(FAIL(ret = dns_message_write_tcp(mesg, &os)))
    {
        input_stream_close(&is);
        output_stream_close(&os);
        dns_message_delete(mesg);
        return ret;
    }

    output_stream_flush(&os);

    int fd = fd_input_stream_get_filedescriptor(&is);

    tcp_set_sendtimeout(fd, timeout, 0);
    tcp_set_recvtimeout(fd, timeout, 0);

    if(FAIL(ret = xfr_input_stream_init(filtering_stream, origin, &is, mesg, serial, flags)))
    {
        input_stream_close(&is);
        output_stream_close(&os);
        dns_message_delete(mesg);
        return ret;
    }

    xfr_input_stream_data *data = (xfr_input_stream_data *)filtering_stream->data;
    data->owns_message = true;
    data->owns_input_stream = true;
    data->source_output_stream = os;

    return SUCCESS;
}

ya_result xfr_input_stream_init_with_query(input_stream_t *filtering_stream, const host_address_t *server, const uint8_t *origin, int32_t ttl, const uint8_t *soa_rdata, int soa_rdata_size, xfr_copy_flags flags)
{
    ya_result ret = xfr_input_stream_init_with_query_and_timeout(filtering_stream, server, origin, ttl, soa_rdata, soa_rdata_size, flags, 10);
    return ret;
}

ya_result xfr_input_stream_get_type(input_stream_t *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data *)in_xfr_input_stream->data;
    return data->xfr_mode;
}

const uint8_t *xfr_input_stream_get_origin(input_stream_t *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data *)in_xfr_input_stream->data;
    return data->origin;
}

uint32_t xfr_input_stream_get_serial(input_stream_t *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data *)in_xfr_input_stream->data;
    return data->last_serial;
}

uint32_t xfr_input_stream_get_refresh(input_stream_t *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data *)in_xfr_input_stream->data;
    return data->last_refresh;
}

uint32_t xfr_input_stream_get_message_count(input_stream_t *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data *)in_xfr_input_stream->data;
    return data->mesg_count;
}

uint32_t xfr_input_stream_get_record_count(input_stream_t *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data *)in_xfr_input_stream->data;
    return data->record_index;
}

uint64_t xfr_input_stream_get_size_total(input_stream_t *in_xfr_input_stream)
{
    xfr_input_stream_data *data = (xfr_input_stream_data *)in_xfr_input_stream->data;
    return data->size_total;
}

void xfr_input_stream_finalize()
{
    /*
    if(initialise_state_unready(&xfr_pool_init_state))
    {
        pool_finalize(&g_xfr_pool);
        initialise_state_end(&xfr_pool_init_state);
    }
    */
}

/** @} */

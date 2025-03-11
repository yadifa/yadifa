/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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

#ifndef XFR_INPUT_STREAM_H_
#define XFR_INPUT_STREAM_H_

#include <dirent.h>

#include <dnscore/input_stream.h>
#include <dnscore/dns_message.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    XFR_ALLOW_AXFR = 1,
    XFR_ALLOW_IXFR = 2,
    XFR_ALLOW_BOTH = 3,
    XFR_CURRENT_SERIAL_SET = 4, // tells the serial parameter is valid
    XFR_LOOSE_AUTHORITY = 8     // ignores missing AA flag
} xfr_copy_flags;

/**
 *
 * The XFR input stream is meant to give record by record the payload of an XFR
 * transfer. It verifies the TSIGs.  It knows its type after two read records.
 *
 * @param args                  see xfr_copy_args
 * @param filtering_stream
 * @return
 */

ya_result xfr_input_stream_init(input_stream_t *filtering_stream, const uint8_t *origin, input_stream_t *xfr_source_stream, dns_message_t *message, uint32_t current_serial, xfr_copy_flags flags);

/**
 *
 * Queries the server with origin IXFR with the given SOA and timeout.
 *
 * @param xfris
 * @param server
 * @param origin
 * @param ttl
 * @param soa_rdata
 * @param soa_rdata_size
 * @param flags
 * @param timeout in seconds
 * @return
 */

ya_result xfr_input_stream_init_with_query_and_timeout(input_stream_t *filtering_stream, const host_address_t *server, const uint8_t *origin, int32_t ttl, const uint8_t *soa_rdata, int soa_rdata_size, xfr_copy_flags flags, int32_t timeout);

/**
 *
 * Queries the server with origin IXFR with the given SOA and a timeout of 10 seconds.
 *
 * @param xfris
 * @param server
 * @param origin
 * @param ttl
 * @param soa_rdata
 * @param soa_rdata_size
 * @param flags
 * @return
 */

ya_result      xfr_input_stream_init_with_query(input_stream_t *xfris, const host_address_t *server, const uint8_t *origin, int32_t ttl, const uint8_t *soa_rdata, int soa_rdata_size, xfr_copy_flags flags);

ya_result      xfr_input_stream_get_type(input_stream_t *in_xfr_input_stream);

const uint8_t *xfr_input_stream_get_origin(input_stream_t *in_xfr_input_stream);

/**
 * Returns the serial of the SOA at the end of the stream.
 *
 * @param in_xfr_input_stream_t
 * @return the last SOA serial number
 */

uint32_t xfr_input_stream_get_serial(input_stream_t *in_xfr_input_stream);

uint32_t xfr_input_stream_get_refresh(input_stream_t *in_xfr_input_stream);

uint32_t xfr_input_stream_get_message_count(input_stream_t *in_xfr_input_stream);

uint32_t xfr_input_stream_get_record_count(input_stream_t *in_xfr_input_stream);

uint64_t xfr_input_stream_get_size_total(input_stream_t *in_xfr_input_stream);

void     xfr_input_stream_finalize();

#ifdef __cplusplus
}
#endif

#endif /* XFR_INPUT_STREAM_H_ */

/** @} */

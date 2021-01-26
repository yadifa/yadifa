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

#ifndef XFR_INPUT_STREAM_H_
#define	XFR_INPUT_STREAM_H_

#include <dirent.h>

#include <dnscore/input_stream.h>
#include <dnscore/message.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum
{
    XFR_ALLOW_AXFR=1,
    XFR_ALLOW_IXFR=2,
    XFR_ALLOW_BOTH=3,
    XFR_CURRENT_SERIAL_SET=4,   // tells the serial parameter is valid
    XFR_LOOSE_AUTHORITY=8       // ignores missing AA flag
} xfr_copy_flags;

/*
typedef struct xfr_copy_args xfr_copy_args;

struct xfr_copy_args
{
    input_stream            *is;                        // TCP stream
    const u8                *origin;                    // origin of the zone
    message_data            *message;                   // message (first set to the head XFR message by the init)
    
    u32                     current_serial;             // the current serial for the zone (if XFR_CURRENT_SERIAL_SET in flags)
    u32                     out_loaded_serial;          // the target serial of the stream
     
    xfr_copy_flags          flags;                      // what is allowed in the stream    
};
*/

/**
 * 
 * The XFR input stream is meant to give record by record the payload of an XFR
 * transfer. It verifies the TSIGs.  It knows its type after two read records.
 * 
 * @param args                  see xfr_copy_args
 * @param filtering_stream
 * @return 
 */

ya_result xfr_input_stream_init(input_stream* filtering_stream, const u8 *origin, input_stream *xfr_source_stream, message_data *message, u32 current_serial, xfr_copy_flags flags);

/**
 * 
 * Queries the server with origin IXFR with the given SOA.
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

ya_result xfr_input_stream_init_with_query(input_stream* xfris, const host_address *server, const u8 *origin, s32 ttl, const u8 *soa_rdata, int soa_rdata_size, xfr_copy_flags flags);

ya_result xfr_input_stream_get_type(input_stream* in_xfr_input_stream);

const u8* xfr_input_stream_get_origin(input_stream* in_xfr_input_stream);

/**
 * Returns the serial of the SOA at the end of the stream.
 * 
 * @param in_xfr_input_stream
 * @return the last SOA serial number
 */

u32 xfr_input_stream_get_serial(input_stream* in_xfr_input_stream);

u32 xfr_input_stream_get_refresh(input_stream *in_xfr_input_stream);

void xfr_input_stream_finalize();

#ifdef	__cplusplus
}
#endif

#endif	/* XFR_INPUT_STREAM_H_ */


/** @} */

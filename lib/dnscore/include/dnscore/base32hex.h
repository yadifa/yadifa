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

/**
 *  @defgroup base Base conversion functions
 *  @ingroup dnscore
 *  @brief Base 32 hex codec
 *
 * Base 32-hex codec functions
 * 
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _BASE32HEX_H
#define	_BASE32HEX_H

#include <dnscore/sys_types.h>
#include <dnscore/output_stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define BASE32HEX_DECODED_CHUNK 5
#define BASE32HEX_ENCODED_CHUNK 8

#define BASE32HEX_ENCODED_LEN(bin_size_) ((((bin_size_)+(BASE32HEX_DECODED_CHUNK-1))/BASE32HEX_DECODED_CHUNK)*BASE32HEX_ENCODED_CHUNK)
#define BASE32HEX_DECODED_LEN(b32_size_) ((((b32_size_)/BASE32HEX_ENCODED_CHUNK))*BASE32HEX_DECODED_CHUNK)

/**
 * Encodes bytes into base32hex
 * The output size must be at least size_in * 8/5
 * 
 * @param buffer_in     bytes to convert
 * @param size_in       number of bytes
 * @param buffer_out    output buffer of a size >= size_in * 8/5
 * 
 * @return output size
 */
    
u32 base32hex_encode(const u8* buffer_in,u32 size_in,char* buffer_out);

/**
 * encodes the buffer into base32hex to the output stream
 * 
 * @param os        output stream
 * @param buffer_in buffer to encode
 * @param size_in   size of the buffer
 * 
 * @return bytes written
 */

ya_result output_stream_write_base32hex(output_stream *os, const u8 *buffer_in, u32 size_in);

/**
 * Decodes base32hex into bytes
 * The output size must be at least size_in * 5/8
 * 
 * @param buffer_in     base32hex text
 * @param size_in       number of chars
 * @param buffer_out    output buffer of a size >= size_in * 5/8
 * 
 * @return output size
 */

ya_result base32hex_decode(const char *buffer_in, u32 size_in, u8 *buffer_out);

#ifdef	__cplusplus
}
#endif

#endif	/* _BASE32_H */

/** @} */

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

/** @defgroup streaming Streams
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _BYTEARRAY_INPUT_STREAM_H
#define	_BYTEARRAY_INPUT_STREAM_H

#include <dnscore/input_stream.h>

#ifdef	__cplusplus
extern "C" {
#endif
    
void bytearray_input_stream_init_const(input_stream* out_stream, const void* array, u32 size);

void bytearray_input_stream_init(input_stream* out_stream, void* array, u32 size, bool owned);

void bytearray_input_stream_reset(input_stream* stream);

void bytearray_input_stream_update(input_stream* stream, void* array, u32 size, bool owned);

u32 bytearray_input_stream_offset(const input_stream* stream);
u32 bytearray_input_stream_set_offset(input_stream* stream, u32 offset);

u32 bytearray_input_stream_size(const input_stream* stream);
u32 bytearray_input_stream_remaining(const input_stream* stream);
const u8* bytearray_input_stream_buffer(const input_stream* stream);
u8* bytearray_input_stream_detach(input_stream* stream);

bool bytearray_input_stream_is_instance_of(const input_stream* stream);

/**
 * Z-allocate a byte array input stream matching the one passed as a parameter.
 * Offset is matched.
 * Buffer is owned.
 */

input_stream *bytearray_input_stream_clone(const input_stream* stream);

#ifdef	__cplusplus
}
#endif

#endif	/* _BYTEARRAY_INPUT_STREAM_H */
/** @} */


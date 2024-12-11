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
 * @defgroup streaming Streams
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _BYTEARRAY_INPUT_STREAM_H
#define _BYTEARRAY_INPUT_STREAM_H

#include <dnscore/input_stream.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Initialises a bytearray_input_stream with a constant buffer in memory. Doesn't own it, obviously.
 *
 * @param out_stream    the stream to initialise
 * @param array         the constant array
 * @param size          the size of the constant array
 */

void bytearray_input_stream_init_const(input_stream_t *out_stream, const void *array, uint32_t size);

/**
 * Initialises a bytearray_input_stream with a buffer.
 *
 * @param out_stream    the stream to initialise
 * @param array         the constant array
 * @param size          the size of the constant array
 * @param owned         if true, the buffer will be freed using free() when the stream is closed.
 */

void bytearray_input_stream_init(input_stream_t *out_stream, const void *array, uint32_t size, bool owned);

/**
 * Rewinds the read offset of the input stream
 *
 * @param out_stream    the stream to initialise
 */

void bytearray_input_stream_reset(input_stream_t *stream);

/**
 * Replaces the current buffer with another one.
 * It's essentially an init but the current buffer is freed if owned.
 *
 * @param stream        the stream
 * @param array         the constant array
 * @param size          the size of the constant array
 * @param owned         if true, the buffer will be freed using free() when the stream is closed.
 *
 * Note: offset is truncated to size.
 */

void bytearray_input_stream_update(input_stream_t *stream, void *array, uint32_t size, bool owned);

/**
 * Returns the offset in the stream.
 *
 * @param stream        the stream
 * @return the offset in the stream
 */

uint32_t bytearray_input_stream_offset(const input_stream_t *stream);

/**
 * Sets the offset in the stream.
 *
 * @param stream        the stream
 * @return the offset in the stream.
 */

uint32_t bytearray_input_stream_set_offset(input_stream_t *stream, uint32_t offset);

/**
 * Returns the size of the stream.
 *
 * @param stream        the stream
 * @return the size of the stream
 */

uint32_t bytearray_input_stream_size(const input_stream_t *stream);

/**
 * Returns the number of available bytes in the stream.
 *
 * @param stream the stream
 * @return the number of available bytes in the stream
 */

uint32_t bytearray_input_stream_remaining(const input_stream_t *stream);

/**
 * Returns the buffer of the stream.
 *
 * @param stream the stream
 * @return the buffer of the stream
 */

const uint8_t *bytearray_input_stream_buffer(const input_stream_t *stream);

/**
 * Detaches the buffer from the stream.
 *
 * @param stream the stream
 * @return the buffer of the stream
 */

uint8_t *bytearray_input_stream_detach(input_stream_t *stream);

/**
 * Returns true iff the stream is a bytearray_input_stream.
 *
 * @param stream the stream
 * @return true iff the stream is a bytearray_input_stream
 */

bool bytearray_input_stream_is_instance_of(const input_stream_t *stream);

/**
 * Z-allocate a byte array input stream matching the one passed as a parameter.
 * Offset is matched.
 * Buffer is owned.
 *
 * @param stream the stream
 * @return a clone of the stream, Z-allocated
 */

input_stream_t *bytearray_input_stream_clone(const input_stream_t *stream);

#ifdef __cplusplus
}
#endif

#endif /* _BYTEARRAY_INPUT_STREAM_H */
/** @} */

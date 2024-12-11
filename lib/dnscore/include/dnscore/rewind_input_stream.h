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
#pragma once

#include <dnscore/input_stream.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define BUFFER_INPUT_STREAM_DEFAULT_BUFFER_SIZE 4096

void rewind_input_stream_init(input_stream_t *filtered_in, input_stream_t *stream_out, int rewind_size);

/**
 * Marks the stream as the new earliest beginning for a rewind.
 *
 * @param stream
 */

void            rewind_input_stream_mark(input_stream_t *stream);

input_stream_t *rewind_input_stream_get_filtered(input_stream_t *bis);

/**
 * Rewinds the input stream back of a given number of bytes
 *
 * @param bos
 * @param bytes_back
 *
 * @return bytes_back  : the operation was successful
 *         <bytes_back : the maximum number of bytes available for rewind at the time of the call
 *                       that amount has been rewound and no more
 */

int32_t rewind_input_stream_rewind(input_stream_t *stream, int32_t bytes_back);

/**
 * Activate the buffer and put the byte passed as a parameter into it
 *
 * @param stream
 * @param byte_value
 * @return true if the buffer isn't full
 */

bool rewind_input_stream_push_back(input_stream_t *stream, uint8_t byte_value);

void rewind_input_stream_rewind_to_mark(input_stream_t *stream);

/**
 * Returns true iff the input stream is a rewind input stream
 *
 * @param bos
 * @return
 */

bool is_rewind_input_stream(input_stream_t *bos);

#ifdef __cplusplus
}
#endif

/** @} */

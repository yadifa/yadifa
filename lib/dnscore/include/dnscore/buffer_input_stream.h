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
 * @defgroup streaming Streams
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _BUFFER_INPUT_STREAM_H
#define _BUFFER_INPUT_STREAM_H

#include <dnscore/input_stream.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define BUFFER_INPUT_STREAM_DEFAULT_BUFFER_SIZE 4096

/**
 * Initialises a buffer input stream.
 *
 * @param stream the stream to initialise
 * @param filtered_in the stream to filter
 * @param buffer_size the size of the buffer
 */

void buffer_input_stream_init(input_stream_t *stream, input_stream_t *filtered_in, int buffer_size);

/**
 * Function specific to the buffer_input_stream_t to read a line up to the '\n'
 */

ya_result       buffer_input_stream_read_line(input_stream_t *stream, char *buffer, uint32_t len);

/**
 * Returns a pointer to the filtered stream inside the buffer input stream.
 *
 * @param bos
 * @return
 */

input_stream_t *buffer_input_stream_get_filtered(input_stream_t *bis);

/**
 * Detaches the filtered input stream, sends a copy back.
 *
 * @param bos
 * @return
 */

input_stream_t buffer_input_stream_detach(input_stream_t *bos);

/**
 * Rewinds the input stream back of a given number of bytes
 *
 * @param bos
 * @param bytes_back
 *
 * @return bytes_back : the operation was successful
 *         > 0        : the maximum number of bytes available for rewind at the time of the call
 */

ya_result buffer_input_stream_rewind(input_stream_t *bos, uint32_t bytes_back);

/**
 * Returns true iff the input stream is a buffer input stream
 *
 * @param bos
 * @return
 */

bool is_buffer_input_stream(input_stream_t *bos);

#ifdef __cplusplus
}
#endif

#endif /* _BUFFER_INPUT_STREAM_H */
/** @} */

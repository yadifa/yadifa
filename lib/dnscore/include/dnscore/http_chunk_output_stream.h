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
#pragma once

#include <dnscore/output_stream.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 *
 * Bufferise the in_filtered output stream wrapping it in out_stream
 * Then writes the output in the HTTP chunk format
 *
 * Can only fail if in_filtered has not been set properly
 *
 * @param in_filtered the stream to bufferise
 * @param out_stream the resulting stream
 * @param in_buffer_size the size of the buffer
 *
 * @return SUCCESS except if in_filtered has not been opened
 */

ya_result http_chunk_output_stream_init(output_stream_t *out_stream, output_stream_t *in_filtered, int in_buffer_size);

/***/

output_stream_t *http_chunk_output_stream_get_filtered(output_stream_t *bos);

void             http_chunk_output_stream_detach(output_stream_t *bos);

bool             http_chunk_output_stream_instance(output_stream_t *os);

#ifdef __cplusplus
}
#endif
/** @} */

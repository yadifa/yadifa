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

/*
 * The buffer will be freed (free) on close.
 */

#define BYTEARRAY_OWNED          1

/*
 * The buffer's size can be changed.
 */

#define BYTEARRAY_DYNAMIC        2

/*
 * The internal context has been allocated by a malloc (the default except if the _static variant is used)
 * YOU MOSTLY WILL NOT USE THAT FLAG
 */

#define BYTEARRAY_ZALLOC_CONTEXT 4

typedef char bytezarray_output_stream_context[sizeof(void *) + 9];

void         bytezarray_output_stream_init(output_stream_t *out_stream, uint8_t *array, uint32_t size);
void         bytezarray_output_stream_init_ex(output_stream_t *out_stream, uint8_t *array, uint32_t size, uint8_t flags);

/*
 * most of bytezarray_output_stream_t usages function-enclosed : init, work on, close
 * this variant of initialisation avoids an malloc
 */

void     bytezarray_output_stream_init_ex_static(output_stream_t *out_stream, uint8_t *array, uint32_t size, uint8_t flags, bytezarray_output_stream_context *ctx);

void     bytezarray_output_stream_reset(output_stream_t *out_stream);
uint32_t bytezarray_output_stream_size(output_stream_t *out_stream);
uint8_t *bytezarray_output_stream_buffer(output_stream_t *out_stream);
uint32_t bytezarray_output_stream_buffer_size(output_stream_t *stream);
uint32_t bytezarray_output_stream_buffer_offset(output_stream_t *stream);
uint8_t *bytezarray_output_stream_detach(output_stream_t *out_stream);

void     bytezarray_output_stream_set(output_stream_t *out_stream, uint8_t *buffer, uint32_t buffer_size, bool owned);

/**
 * If the buffer is owned, grows it to ensure it has at least the specified size.
 * If the buffer is not owned: fails.
 *
 * @param out_stream the stream
 * @param size the minimum required size
 * @return an error code
 */

ya_result bytezarray_output_stream_ensure(output_stream_t *out_stream, uint32_t size);

/**
 * Rewinds the position in the stream to by that amount of bytes
 *
 * @param steam
 * @param rewind_count
 * @return the actual rewind_count
 */

uint32_t bytezarray_output_stream_rewind(output_stream_t *out_stream, uint32_t rewind_count);

/**
 * Sets the position in the stream.
 * If the buffer is dynamic, may grow the buffer.
 * If the buffer is static, may be limited to the size of the buffer.
 *
 * @param steam
 * @param position
 * @return the new position
 */

uint32_t bytezarray_output_stream_setposition(output_stream_t *out_stream, uint32_t position);

/**
 * Makes a zallocated copy of the buffer up to the current position.
 *
 * @param stream
 * @return a pointer to the zallocated copy
 */

uint8_t *bytezarray_output_stream_zdup(output_stream_t *stream);

/**
 * Makes a mallocated copy of the buffer up to the current position.
 *
 * @param stream
 * @return a pointer to the mallocated copy
 */

uint8_t *bytezarray_output_stream_dup(output_stream_t *stream);

#ifdef __cplusplus
}
#endif

/** @} */

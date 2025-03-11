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
#include "dnscore/dnscore_config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/bytearray_input_stream.h"
#include "dnscore/zalloc.h"

#define BYTE_ARRAY_INPUT_STREAM_TAG      0x53494142         // BAIS
#define BYTE_ARRAY_INPUT_STREAM_DATA_TAG 0x4154414453494142 // BAISDATA
#define BYTE_ARRAY_INPUT_STREAM_BUFF_TAG 0x4646554253494142 // BAISBUFF

typedef struct bytearray_input_stream_data bytearray_input_stream_data;

/* flags */

struct bytearray_input_stream_data
{
    const uint8_t *buffer;
    uint32_t       offset;
    uint32_t       size;
    bool           own_buffer;
};

static ya_result bytearray_input_stream_read(input_stream_t *stream, void *buffer, uint32_t len)
{
    if(len == 0)
    {
        return 0;
    }

    bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;

    uint32_t                     remaining = data->size - data->offset;

    if(len > remaining)
    {
        if(remaining == 0)
        {
            return 0; /* EOF */
        }

        len = remaining;
    }

    const uint8_t *src = &data->buffer[data->offset];

    MEMCOPY(buffer, src, len);

    data->offset += len;

    return len;
}

static ya_result bytearray_input_stream_skip(input_stream_t *stream, uint32_t len)
{
    if(len == 0)
    {
        return 0;
    }

    bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;

    uint32_t                     remaining = data->size - data->offset;

    if(len > remaining)
    {
        if(remaining == 0)
        {
            return 0; /* EOF */
        }

        len = remaining;
    }

    data->offset += len;

    return len;
}

static void bytearray_input_stream_close(input_stream_t *stream)
{
    bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;

    if(data->own_buffer)
    {
        free((void *)data->buffer);
    }

    ZFREE_OBJECT(data);

    input_stream_set_void(stream);
}

static const input_stream_vtbl bytearray_input_stream_vtbl = {
    bytearray_input_stream_read,
    bytearray_input_stream_skip,
    bytearray_input_stream_close,
    "bytearray_input_stream",
};

/**
 * Initialises a bytearray_input_stream with a constant buffer in memory. Doesn't own it, obviously.
 *
 * @param out_stream    the stream to initialise
 * @param array         the constant array
 * @param size          the size of the constant array
 */

void bytearray_input_stream_init_const(input_stream_t *out_stream, const void *array, uint32_t size)
{
    bytearray_input_stream_data *data;

    ZALLOC_OBJECT_OR_DIE(data, bytearray_input_stream_data, BYTE_ARRAY_INPUT_STREAM_DATA_TAG);

    data->buffer = array;
    data->offset = 0;
    data->size = size;
    data->own_buffer = false;

    out_stream->data = data;
    out_stream->vtbl = &bytearray_input_stream_vtbl;
}

/**
 * Initialises a bytearray_input_stream with a buffer.
 *
 * @param out_stream    the stream to initialise
 * @param array         the constant array
 * @param size          the size of the constant array
 * @param owned         if true, the buffer will be freed using free() when the stream is closed.
 */

void bytearray_input_stream_init(input_stream_t *out_stream, const void *array, uint32_t size, bool owned)
{
    bytearray_input_stream_data *data;

    ZALLOC_OBJECT_OR_DIE(data, bytearray_input_stream_data, BYTE_ARRAY_INPUT_STREAM_DATA_TAG);

    data->buffer = array;
    data->offset = 0;
    data->size = size;
    data->own_buffer = owned;

    out_stream->data = data;
    out_stream->vtbl = &bytearray_input_stream_vtbl;
}

/**
 * Rewinds the read offset of the input stream
 *
 * @param out_stream    the stream to initialise
 */

void bytearray_input_stream_reset(input_stream_t *stream)
{
    bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;
    data->offset = 0;
}

/**
 * Replaces the current buffer with another one.
 * It's essentially an init but the current buffer is freed if owned.
 *
 * @param stream    the stream to initialise
 * @param array         the constant array
 * @param size          the size of the constant array
 * @param owned         if true, the buffer will be freed using free() when the stream is closed.
 *
 * Note: offset is truncated to size.
 */

void bytearray_input_stream_update(input_stream_t *stream, void *array, uint32_t size, bool owned)
{
    bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;

    if(data->own_buffer && (data->buffer != array))
    {
        free((uint8_t *)data->buffer);
    }
    data->buffer = array;
    data->size = size;
    if(data->offset > data->size)
    {
        data->offset = data->size;
    }
    data->own_buffer = owned;
}

/**
 * Returns the offset in the stream.
 *
 * @param stream the strea
 * @return the offset in the stream
 */

uint32_t bytearray_input_stream_offset(const input_stream_t *stream)
{
    bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;
    return data->offset;
}

/**
 * Sets the offset in the stream.
 *
 * @param stream the strea
 * @return the offset in the stream.
 */

uint32_t bytearray_input_stream_set_offset(input_stream_t *stream, uint32_t offset)
{
    bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;
    if(data->size <= offset)
    {
        offset = data->size; // EOF
    }
    data->offset = offset;
    return offset;
}

/**
 * Returns the size of the stream.
 *
 * @param stream the stream
 * @return the size of the stream
 */

uint32_t bytearray_input_stream_size(const input_stream_t *stream)
{
    bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;
    return data->size;
}

/**
 * Returns the number of available bytes in the stream.
 *
 * @param stream the stream
 * @return the number of available bytes in the stream
 */

uint32_t bytearray_input_stream_remaining(const input_stream_t *stream)
{
    bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;
    uint32_t                     remaining = data->size - data->offset;
    return remaining;
}

/**
 * Returns the buffer of the stream.
 *
 * @param stream the stream
 * @return the buffer of the stream
 */

const uint8_t *bytearray_input_stream_buffer(const input_stream_t *stream)
{
    bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;

    return data->buffer;
}

/**
 * Detaches the buffer from the stream.
 *
 * @param stream the stream
 * @return the buffer of the stream
 */

uint8_t *bytearray_input_stream_detach(input_stream_t *stream)
{
    bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;

    data->own_buffer = false;

    return (uint8_t *)data->buffer;
}

/**
 * Returns true iff the stream is a bytearray_input_stream.
 *
 * @param stream the stream
 * @return true iff the stream is a bytearray_input_stream
 */

bool bytearray_input_stream_is_instance_of(const input_stream_t *stream) { return (stream != NULL) && (stream->vtbl == &bytearray_input_stream_vtbl); }

/**
 * Z-allocate a byte array input stream matching the one passed as a parameter.
 * Offset is matched.
 * Buffer is owned.
 *
 * @param stream the stream
 * @return a clone of the stream, Z-allocated
 */

input_stream_t *bytearray_input_stream_clone(const input_stream_t *stream)
{
    if(bytearray_input_stream_is_instance_of(stream))
    {
        bytearray_input_stream_data *data = (bytearray_input_stream_data *)stream->data;

        input_stream_t              *is;
        ZALLOC_OBJECT_OR_DIE(is, input_stream_t, BYTE_ARRAY_INPUT_STREAM_TAG);

        bytearray_input_stream_data *is_data;

        ZALLOC_OBJECT_OR_DIE(is_data, bytearray_input_stream_data, BYTE_ARRAY_INPUT_STREAM_DATA_TAG);

        // is_data->buffer <= data->array;
        MALLOC_OBJECT_ARRAY_OR_DIE(is_data->buffer, uint8_t, data->size, BYTE_ARRAY_INPUT_STREAM_BUFF_TAG)
        memcpy((char *)is_data->buffer, data->buffer, data->size);

        is_data->offset = data->offset;
        is_data->size = data->size;
        is_data->own_buffer = true;

        is->data = is_data;
        is->vtbl = &bytearray_input_stream_vtbl;

        return is;
    }
    else
    {
        return NULL;
    }
}

/** @} */

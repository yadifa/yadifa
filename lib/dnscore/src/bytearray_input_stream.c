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
#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/bytearray_input_stream.h"
#include "dnscore/zalloc.h"

#define BYTE_ARRAY_INPUT_STREAM_TAG         0x53494142          // BAIS
#define BYTE_ARRAY_INPUT_STREAM_DATA_TAG    0x4154414453494142  // BAISDATA
#define BYTE_ARRAY_INPUT_STREAM_BUFF_TAG    0x4646554253494142  // BAISBUFF

typedef struct bytearray_input_stream_data bytearray_input_stream_data;

/* flags */

struct bytearray_input_stream_data
{
    const u8* buffer;
    u32 offset;
    u32 size;
    bool own_buffer;
};

static ya_result
bytearray_input_stream_read(input_stream* stream, void *buffer, u32 len)
{
    if(len == 0)
    {
        return 0;
    }

    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;
    
    u32 remaining = data->size - data->offset;
    
    if(len > remaining)
    {
        if(remaining == 0)
        {
            return 0; /* EOF */
        }
        
        len = remaining;
    }
    
    const u8* src = &data->buffer[data->offset];
    
    MEMCOPY(buffer, src, len);
    
    data->offset += len;

    return len;
}

static ya_result
bytearray_input_stream_skip(input_stream* stream, u32 len)
{
    if(len == 0)
    {
        return 0;
    }

    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;
    
    u32 remaining = data->size - data->offset;
    
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

static void
bytearray_input_stream_close(input_stream* stream)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;

    if(data->own_buffer)
    {
        free((void*)data->buffer);
    }
        
    ZFREE_OBJECT(data);

    input_stream_set_void(stream);
}

static const input_stream_vtbl bytearray_input_stream_vtbl =
{
    bytearray_input_stream_read,
    bytearray_input_stream_skip,
    bytearray_input_stream_close,
    "bytearray_input_stream",
};

void
bytearray_input_stream_init_const(input_stream* out_stream, const void* array, u32 size)
{
    bytearray_input_stream_data* data;

    ZALLOC_OBJECT_OR_DIE( data, bytearray_input_stream_data, BYTE_ARRAY_INPUT_STREAM_DATA_TAG);

    data->buffer = array;
    data->offset = 0;
    data->size = size;
    data->own_buffer = FALSE;
    
    out_stream->data = data;
    out_stream->vtbl = &bytearray_input_stream_vtbl;
}

void
bytearray_input_stream_init(input_stream* out_stream, void* array, u32 size, bool owned)
{
    bytearray_input_stream_data* data;

    ZALLOC_OBJECT_OR_DIE( data, bytearray_input_stream_data, BYTE_ARRAY_INPUT_STREAM_DATA_TAG);

    data->buffer = array;
    data->offset = 0;
    data->size = size;
    data->own_buffer = owned;
    
    out_stream->data = data;
    out_stream->vtbl = &bytearray_input_stream_vtbl;
}

void
bytearray_input_stream_reset(input_stream* stream)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;
    data->offset = 0;
}

void
bytearray_input_stream_update(input_stream* stream, void* array, u32 size, bool owned)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;
    
    if(data->own_buffer && (data->buffer != array))
    {
        free((u8*)data->buffer);
    }
    data->buffer = array;
    data->size = size;
    data->own_buffer = owned;
}

u32
bytearray_input_stream_offset(const input_stream* stream)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;
    return data->offset;
}

u32
bytearray_input_stream_set_offset(input_stream* stream, u32 offset)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;
    if(data->size <= offset)
    {
        offset = data->size - 1;
    }
    data->offset = offset;
    return offset;
}

u32
bytearray_input_stream_size(const input_stream* stream)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;
    return data->size;
}

u32
bytearray_input_stream_remaining(const input_stream* stream)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;
    u32 remaining = data->size - data->offset;
    return remaining;
}

const u8*
bytearray_input_stream_buffer(const input_stream* stream)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;

    return data->buffer;
}

u8*
bytearray_input_stream_detach(input_stream* stream)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;

    data->own_buffer = FALSE;

    return (u8*)data->buffer;
}

bool
bytearray_input_stream_is_instance_of(const input_stream* stream)
{
    return (stream != NULL) && (stream->vtbl == &bytearray_input_stream_vtbl);
}

/**
 * Z-allocate a byte array input stream matching the one passed as a parameter.
 * Offset is matched.
 * Buffer is owned.
 */

input_stream *bytearray_input_stream_clone(const input_stream* stream)
{
    if(bytearray_input_stream_is_instance_of(stream))
    {
        bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;

        input_stream *is;
        ZALLOC_OBJECT_OR_DIE(is, input_stream, BYTE_ARRAY_INPUT_STREAM_TAG);

        bytearray_input_stream_data* is_data;

        ZALLOC_OBJECT_OR_DIE( is_data, bytearray_input_stream_data, BYTE_ARRAY_INPUT_STREAM_DATA_TAG);

        //is_data->buffer <= data->array;
        MALLOC_OBJECT_ARRAY_OR_DIE(is_data->buffer, u8, data->size, BYTE_ARRAY_INPUT_STREAM_BUFF_TAG)
        memcpy((char*)is_data->buffer, data->buffer, data->size);

        is_data->offset = data->offset;
        is_data->size = data->size;
        is_data->own_buffer = TRUE;

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


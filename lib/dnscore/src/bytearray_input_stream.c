/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/bytearray_input_stream.h"

#define BYTE_ARRAY_INPUT_STREAM_TAG         0x53494142          // BAIS
#define BYTE_ARRAY_INPUT_STREAM_DATA_TAG    0x4154414453494142  // BAISDATA

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
bytearray_read(input_stream* stream, u8 *buffer, u32 len)
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
bytearray_skip(input_stream* stream, u32 len)
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
bytearray_close(input_stream* stream)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;

    free(data);

    input_stream_set_void(stream);
}

static const input_stream_vtbl bytearray_input_stream_vtbl = {
    bytearray_read,
    bytearray_skip,
    bytearray_close,
    "bytearray_input_stream",
};

void
bytearray_input_stream_init(const u8* array, u32 size, input_stream* out_stream, bool owned)
{
    bytearray_input_stream_data* data;

    MALLOC_OR_DIE(bytearray_input_stream_data*, data, sizeof (bytearray_input_stream_data), BYTE_ARRAY_INPUT_STREAM_DATA_TAG);

    data->buffer = array;
    data->offset = 0;
    data->size = size;

    out_stream->data = data;
    out_stream->vtbl = &bytearray_input_stream_vtbl;
}

void
bytearray_input_stream_reset(input_stream* stream)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;
    data->offset = 0;
}

u32
bytearray_input_stream_offset(input_stream* stream)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;
    return data->offset;
}

u32
bytearray_input_stream_size(input_stream* stream)
{
    bytearray_input_stream_data* data = (bytearray_input_stream_data*)stream->data;
    return data->size;
}

const u8*
bytearray_input_stream_buffer(input_stream* stream)
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

/** @} */

/*----------------------------------------------------------------------------*/


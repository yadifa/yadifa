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

#include "dnscore/buffer_output_stream.h"

#define BUFFER_OUTPUT_STREAM_TAG 0x534F5246465542 /* BUFFROS */

typedef struct buffer_output_stream_data buffer_output_stream_data;

struct buffer_output_stream_data
{
    output_stream filtered;
    u32 buffer_maxsize;

    u32 buffer_offset;

    u8 buffer[1];
};

static ya_result
buffer_write(output_stream* stream, const u8* buffer, u32 len)
{
    buffer_output_stream_data* data = (buffer_output_stream_data*)stream->data;
    u8* src = data->buffer;

    ya_result ret;

    u32 remaining = data->buffer_maxsize - data->buffer_offset;

    if(len < remaining)
    {
        MEMCOPY(&src[data->buffer_offset], buffer, len);
        data->buffer_offset += len;

        /* There are still some bytes available */

        return len;
    }

    /* len >= remaining : fill the buffer */

    MEMCOPY(&src[data->buffer_offset], buffer, remaining);
    len -= remaining;
    buffer += remaining;

    /* NOTE: at this point the internal buffer is full : write it  */

    if(FAIL(ret = output_stream_write(&data->filtered, src, data->buffer_maxsize)))
    {
        return ret;
    }

    if(len > data->buffer_maxsize)
    {
        /* It would be pointless to buffer a write bigger than the buffer */

        data->buffer_offset = 0; /* mark the buffer as "empty" */

        if(FAIL(ret = output_stream_write(&data->filtered, buffer, len)))
        {
            return ret;
        }

        return remaining + len; /* the chunk we've write from the buffer +
				   the chunk we've write from the stream */
    }

    /* What remains to write is smaller than the buffer max size */

    MEMCOPY(src, buffer, len);
    data->buffer_offset = len;

    return remaining + len;
}

static ya_result
buffer_flush(output_stream* stream)
{
    buffer_output_stream_data* data = (buffer_output_stream_data*)stream->data;

    if(data->buffer_offset > 0)
    {
        ya_result ret;

        if(FAIL(ret = output_stream_write(&data->filtered, data->buffer, data->buffer_offset)))
        {
            return ret;
        }

        data->buffer_offset = 0;
    }

    return output_stream_flush(&data->filtered);
}

static void
buffer_close(output_stream* stream)
{
    buffer_flush(stream);

    buffer_output_stream_data* data = (buffer_output_stream_data*)stream->data;
    output_stream_close(&data->filtered);
    free(data);
    
    output_stream_set_void(stream);
}

static const output_stream_vtbl buffer_output_stream_vtbl ={
    buffer_write,
    buffer_flush,
    buffer_close,
    "buffer_output_stream",
};

ya_result
buffer_output_stream_init(output_stream* filtered, output_stream* stream, int buffer_size)
{
    buffer_output_stream_data* data;

    if(filtered->vtbl == NULL)
    {
        return OBJECT_NOT_INITIALIZED;
    }

    MALLOC_OR_DIE(buffer_output_stream_data*, data, sizeof (buffer_output_stream_data) + buffer_size - 1, BUFFER_OUTPUT_STREAM_TAG);

    data->filtered.data = filtered->data;
    data->filtered.vtbl = filtered->vtbl;

    data->buffer_maxsize = buffer_size;
    data->buffer_offset = 0;

    filtered->data = NULL; /* Clean the filtered BEFORE setting up the stream */
    filtered->vtbl = NULL;

    stream->data = data;
    stream->vtbl = &buffer_output_stream_vtbl;

    return SUCCESS;
}

output_stream*
buffer_output_stream_get_filtered(output_stream* bos)
{
    buffer_output_stream_data* data = (buffer_output_stream_data*)bos->data;

    return &data->filtered;
}

bool
is_buffer_output_stream(output_stream* os)
{
    return os->vtbl == &buffer_output_stream_vtbl;
}

/** @} */

/*----------------------------------------------------------------------------*/


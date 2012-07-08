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
* DOCUMENTATION */
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

#include "dnscore/bytearray_output_stream.h"

#define BYTE_ARRAY_OUTPUT_STREAM_TAG 0x534f4142 /* BAOS */
#define BYTE_ARRAY_OUTPUT_STREAM_DATA_TAG 0x41544144534f4142 /* BAOSDATA */
#define BYTE_ARRAY_OUTPUT_STREAM_BUFF_TAG 0x46465542534f4142 /* BAOSBUFF */

typedef struct bytearray_output_stream_data bytearray_output_stream_data;


#define BYTEARRAY_STARTSIZE 1024

/* flags */

struct bytearray_output_stream_data
{
    u8* buffer;
    u32 buffer_size;
    u32 buffer_offset;
    u8 flags;
};

static ya_result
bytearray_write(output_stream* stream, const u8* buffer, u32 len)
{
    if(len == 0)
    {
        return 0;
    }

    bytearray_output_stream_data* data = (bytearray_output_stream_data*)stream->data;
    u8* src = data->buffer;

    ya_result ret;

    u32 remaining = data->buffer_size - data->buffer_offset;

    if(len > remaining)
    {
        /* Either we can resize, either we have to trunk */

        if((data->flags & BYTEARRAY_DYNAMIC) != 0)
        {
            u8* newbuffer;
            u32 newsize = data->buffer_size;

            do
            {
                newsize = newsize * 2;
            }
            while(newsize < data->buffer_size + len);

            MALLOC_OR_DIE(u8*, newbuffer, newsize, BYTE_ARRAY_OUTPUT_STREAM_TAG);

            MEMCOPY(newbuffer, data->buffer, data->buffer_offset);

            if((data->flags & BYTEARRAY_OWNED) != 0)
            {
                free(data->buffer);
            }

            data->buffer = newbuffer;
            data->buffer_size = newsize;

            data->flags |= BYTEARRAY_OWNED;
        }
        else
        {
            len = remaining;
        }
    }

    MEMCOPY(&data->buffer[data->buffer_offset], buffer, len);
    data->buffer_offset += len;

    return len;
}

static ya_result
bytearray_flush(output_stream* stream)
{
    return SUCCESS;
}

static void
bytearray_close(output_stream* stream)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)stream->data;

    if((data->flags & BYTEARRAY_OWNED) != 0)
    {
        free(data->buffer);
    }

    free(data);

    output_stream_set_void(stream);
}

static output_stream_vtbl bytearray_output_stream_vtbl = {
    bytearray_write,
    bytearray_flush,
    bytearray_close,
    "bytearray_output_stream",
};

void
bytearray_output_stream_init_ex(u8* array, u32 size, output_stream* out_stream, u8 flags)
{
    bytearray_output_stream_data* data;

    MALLOC_OR_DIE(bytearray_output_stream_data*, data, sizeof (bytearray_output_stream_data), BYTE_ARRAY_OUTPUT_STREAM_DATA_TAG);

    if(array == NULL)
    {
        flags |= BYTEARRAY_OWNED;

        if(size == 0)
        {
            flags |= BYTEARRAY_DYNAMIC;

            size = BYTEARRAY_STARTSIZE;
        }

        MALLOC_OR_DIE(u8*, array, size, BYTE_ARRAY_OUTPUT_STREAM_BUFF_TAG);
    }

    data->buffer = array;
    data->buffer_size = size;
    data->buffer_offset = 0;
    data->flags = flags;

    out_stream->data = data;
    out_stream->vtbl = &bytearray_output_stream_vtbl;
}

void
bytearray_output_stream_init(u8* array, u32 size, output_stream* out_stream)
{
    bytearray_output_stream_init_ex(array, size, out_stream, 0);
}

void
bytearray_output_stream_reset(output_stream* stream)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)stream->data;
    data->buffer_offset = 0;
}

u32
bytearray_output_stream_size(output_stream* stream)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)stream->data;
    return data->buffer_offset;
}

u8*
bytearray_output_stream_buffer(output_stream* stream)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)stream->data;

    return data->buffer;
}

u8*
bytearray_output_stream_detach(output_stream* stream)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)stream->data;

    data->flags &= ~BYTEARRAY_OWNED;

    return data->buffer;
}

/** @} */

/*----------------------------------------------------------------------------*/


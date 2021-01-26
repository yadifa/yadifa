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

#include "dnscore/bytearray_output_stream.h"
#include "dnscore/zalloc.h"

#define BYTE_ARRAY_OUTPUT_STREAM_TAG 0x534f4142 /* BAOS */
#define BYTE_ARRAY_OUTPUT_STREAM_DATA_TAG 0x41544144534f4142 /* BAOSDATA */
#define BYTE_ARRAY_OUTPUT_STREAM_BUFF_TAG 0x46465542534f4142 /* BAOSBUFF */

#define BYTEARRAY_STARTSIZE 1024

#define BAOSZDUP_TAG 0x5055445a534f4142
#define BAOSDUP_TAG 0x505544534f4142

typedef struct bytearray_output_stream_data bytearray_output_stream_data;

/**
 * @NOTE: if this changes, take care that bytearray_output_stream_context in the header file has at least the SAME SIZE
 */

struct bytearray_output_stream_data
{
    u8* buffer;
    u32 buffer_size;
    u32 buffer_offset;
    u8 flags;
};

static ya_result
bytearray_output_stream_write(output_stream* stream, const u8* buffer, u32 len)
{
    if(len == 0)
    {
        return 0;
    }

    bytearray_output_stream_data* data = (bytearray_output_stream_data*)stream->data;

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

            MALLOC_OR_DIE(u8*, newbuffer, newsize, BYTE_ARRAY_OUTPUT_STREAM_BUFF_TAG);
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
bytearray_output_stream_flush(output_stream* stream)
{
    (void)stream;

    return SUCCESS;
}

static void
bytearray_output_stream_close(output_stream* stream)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)stream->data;

    if((data->flags & BYTEARRAY_OWNED) != 0)
    {
#if DEBUG
        memset(data->buffer, 0xe5, data->buffer_size);
#endif        
        free(data->buffer);
    }

    if((data->flags & BYTEARRAY_ZALLOC_CONTEXT) != 0)
    {
        ZFREE(data,bytearray_output_stream_data);
    }

    output_stream_set_void(stream);
}

static const output_stream_vtbl bytearray_output_stream_vtbl =
{
    bytearray_output_stream_write,
    bytearray_output_stream_flush,
    bytearray_output_stream_close,
    "bytearray_output_stream",
};

void
bytearray_output_stream_init_ex_static(output_stream* out_stream, u8* array,u32 size, u8 flags, bytearray_output_stream_context *ctx)
{
    bytearray_output_stream_data *data = (bytearray_output_stream_data*)ctx;
 
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
bytearray_output_stream_init_ex(output_stream* out_stream, u8* array, u32 size, u8 flags)
{
    bytearray_output_stream_data* data;

    ZALLOC_OBJECT_OR_DIE( data, bytearray_output_stream_data, BYTE_ARRAY_OUTPUT_STREAM_DATA_TAG);

    flags |= BYTEARRAY_ZALLOC_CONTEXT;
    
    bytearray_output_stream_init_ex_static(out_stream, array, size, flags, (bytearray_output_stream_context*)data);
}

void
bytearray_output_stream_init(output_stream* out_stream, u8* array, u32 size)
{
    bytearray_output_stream_init_ex(out_stream, array, size, 0);
}

void
bytearray_output_stream_reset(output_stream* stream)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)stream->data;
    data->buffer_offset = 0;
}

ya_result
bytearray_output_stream_ensure(output_stream* stream, u32 size)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)stream->data;
    
    if(data->buffer_size < size)
    {
        /* Either we can resize, either we have to trunk */
        
        size = (size + 7) & ~7;

        if((data->flags & BYTEARRAY_DYNAMIC) != 0)
        {
            u8* newbuffer;

            MALLOC_OR_DIE(u8*, newbuffer, size, BYTE_ARRAY_OUTPUT_STREAM_BUFF_TAG);
            MEMCOPY(newbuffer, data->buffer, data->buffer_offset);

            if((data->flags & BYTEARRAY_OWNED) != 0)
            {
                free(data->buffer);
            }

            data->buffer = newbuffer;
            data->buffer_size = size;

            data->flags |= BYTEARRAY_OWNED;
        }
        else
        {
            return ERROR; // not dynamic
        }
    }
    
    return SUCCESS;
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

void
bytearray_output_stream_set(output_stream* stream, u8 *buffer, u32 buffer_size, bool owned)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)stream->data;
    if((data->buffer != buffer) && ((data->flags & BYTEARRAY_OWNED) != 0))
    {
        free(data->buffer);
    }
    data->buffer = buffer;
    data->buffer_offset = buffer_size;
    data->buffer_size = buffer_size;
    data->flags = (data->flags & BYTEARRAY_ZALLOC_CONTEXT) | ((owned)?BYTEARRAY_OWNED:0);
}

    /**
     
     * @param out_stream
     * @param by
     * @return the actual rewind_count
     */
    
u32
bytearray_output_stream_rewind(output_stream* out_stream, u32 rewind_count)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)out_stream->data;
    if(rewind_count < data->buffer_offset)
    {
        data->buffer_offset -= rewind_count;
    }
    else
    {
        rewind_count = data->buffer_offset;
        data->buffer_offset = 0;
    }
    
    return rewind_count;
}

u8*
bytearray_output_stream_zdup(output_stream* out_stream)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)out_stream->data;
    u8 *ret;
    u32 n = MAX(data->buffer_offset, 1); // because allocating 0 bytes can be an hassle
    ZALLOC_OBJECT_ARRAY_OR_DIE(ret, u8, n, BAOSZDUP_TAG);
    memcpy(ret, data->buffer, n);
    
    return ret;
}

u8*
bytearray_output_stream_dup(output_stream* out_stream)
{
    bytearray_output_stream_data* data = (bytearray_output_stream_data*)out_stream->data;
    u8 *ret;
    u32 n = MAX(data->buffer_offset, 1); // because allocating 0 bytes can be an hassle
    MALLOC_OR_DIE(u8*, ret, n, BAOSDUP_TAG);
    memcpy(ret, data->buffer, n);
    
    return ret;
}

/** @} */

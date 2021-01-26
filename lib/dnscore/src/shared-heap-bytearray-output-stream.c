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

#include "dnscore/shared-heap.h"
#include "dnscore/shared-heap-bytearray-output-stream.h"

#include "dnscore/zalloc.h"

#define BYTE_ARRAY_OUTPUT_STREAM_DATA_TAG 0x41544144534f4853 /* SHOSDATA */

#define SHARED_HEAP_STARTSIZE 48

typedef struct shared_heap_output_stream_data shared_heap_output_stream_data;

/**
 * @NOTE: if this changes, take care that shared_heap_output_stream_context in the header file has at least the SAME SIZE
 */

struct shared_heap_output_stream_data
{
    u8* buffer;
    u32 buffer_size;
    u32 buffer_offset;
    u8 flags;
    u8 id;
};

static ya_result
shared_heap_output_stream_write(output_stream* stream, const u8* buffer, u32 len)
{
    if(len == 0)
    {
        return 0;
    }

    shared_heap_output_stream_data* data = (shared_heap_output_stream_data*)stream->data;

    u32 remaining = data->buffer_size - data->buffer_offset;
    /*
    1;48    -> 48
    49;112  -> 112
    */      
    if(len > remaining)
    {
        /* Either we can resize, either we have to trunk */

        if((data->flags & SHARED_HEAP_DYNAMIC) != 0)
        {
            u8* newbuffer;
            u32 newsize = (((data->buffer_offset + len) + 16 + 63) & ~63) - 16;

            newbuffer = (u8*)shared_heap_wait_alloc(data->id, newsize);
            MEMCOPY(newbuffer, data->buffer, data->buffer_offset);

            if((data->flags & SHARED_HEAP_OWNED) != 0)
            {
                shared_heap_free(data->buffer);
            }

            data->buffer = newbuffer;
            data->buffer_size = newsize;

            data->flags |= SHARED_HEAP_OWNED;
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
shared_heap_output_stream_flush(output_stream* stream)
{
    (void)stream;
    return SUCCESS;
}

static void
shared_heap_output_stream_close(output_stream* stream)
{
    shared_heap_output_stream_data* data = (shared_heap_output_stream_data*)stream->data;

    if((data->flags & SHARED_HEAP_OWNED) != 0)
    {
#if DEBUG
        memset(data->buffer, 0xe5, data->buffer_size);
#endif
        shared_heap_free(data->buffer);
    }

    if((data->flags & SHARED_HEAP_ZALLOC_CONTEXT) != 0)
    {
        ZFREE_OBJECT(data);
    }

    output_stream_set_void(stream);
}

static const output_stream_vtbl shared_heap_output_stream_vtbl =
{
    shared_heap_output_stream_write,
    shared_heap_output_stream_flush,
    shared_heap_output_stream_close,
    "shared_heap_output_stream",
};

void
shared_heap_output_stream_init_ex_static(output_stream* out_stream, u8 id, u8* array,u32 size, u8 flags, shared_heap_output_stream_context *ctx)
{
    shared_heap_output_stream_data *data = (shared_heap_output_stream_data*)ctx;
 
    if(array == NULL)
    {
        flags |= SHARED_HEAP_OWNED;

        if(size == 0)
        {
            flags |= SHARED_HEAP_DYNAMIC;

            size = SHARED_HEAP_STARTSIZE;
        }
        else
        {
            // size = ((size + 63) & ~63) - 16;
        }

        array = (u8*)shared_heap_wait_alloc(id, size);
    }

    data->buffer = array;
    data->buffer_size = size;
    data->buffer_offset = 0;
    data->flags = flags;
    data->id = id;

    out_stream->data = data;
    out_stream->vtbl = &shared_heap_output_stream_vtbl;
}

void
shared_heap_output_stream_try_init_ex_static(output_stream* out_stream, u8 id, u8* array,u32 size, u8 flags, shared_heap_output_stream_context *ctx)
{
    shared_heap_output_stream_data *data = (shared_heap_output_stream_data*)ctx;

    if(array == NULL)
    {
        flags |= SHARED_HEAP_OWNED;

        if(size == 0)
        {
            flags |= SHARED_HEAP_DYNAMIC;

            size = SHARED_HEAP_STARTSIZE;
        }
        else
        {
            // size = ((size + 63) & ~63) - 16;
        }

        array = (u8*)shared_heap_try_alloc(id, size);
    }

    data->buffer = array;
    data->buffer_size = size;
    data->buffer_offset = 0;
    data->flags = flags;
    data->id = id;

    out_stream->data = data;
    out_stream->vtbl = &shared_heap_output_stream_vtbl;
}

void
shared_heap_output_stream_init_ex(output_stream* out_stream, u8 id, u8* array, u32 size, u8 flags)
{
    shared_heap_output_stream_data* data;

    ZALLOC_OBJECT_OR_DIE( data, shared_heap_output_stream_data, BYTE_ARRAY_OUTPUT_STREAM_DATA_TAG);
    
    array = (u8*)shared_heap_wait_alloc(id, size);
    flags |= SHARED_HEAP_ZALLOC_CONTEXT;
    
    shared_heap_output_stream_init_ex_static(out_stream, id, array, size, flags, (shared_heap_output_stream_context*)data);
}

void
shared_heap_output_stream_init(output_stream* out_stream, u8 id, u8* array, u32 size)
{
    shared_heap_output_stream_init_ex(out_stream, id, array, size, 0);
}

void
shared_heap_output_stream_reset(output_stream* stream)
{
    shared_heap_output_stream_data* data = (shared_heap_output_stream_data*)stream->data;
    data->buffer_offset = 0;
}

u32
shared_heap_output_stream_size(output_stream* stream)
{
    shared_heap_output_stream_data* data = (shared_heap_output_stream_data*)stream->data;
    return data->buffer_offset;
}

u32
shared_heap_output_stream_buffer_size(output_stream* stream)
{
    shared_heap_output_stream_data* data = (shared_heap_output_stream_data*)stream->data;
    return data->buffer_size;
}

u8*
shared_heap_output_stream_buffer(output_stream* stream)
{
    shared_heap_output_stream_data* data = (shared_heap_output_stream_data*)stream->data;

    return data->buffer;
}

u8*
shared_heap_output_stream_detach(output_stream* stream)
{
    shared_heap_output_stream_data* data = (shared_heap_output_stream_data*)stream->data;

    data->flags &= ~SHARED_HEAP_OWNED;

    return data->buffer;
}



/** @} */

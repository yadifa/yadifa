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

#include "dnscore/bytezarray_output_stream.h"
#include "dnscore/zalloc.h"

#define BYTE_ARRAY_OUTPUT_STREAM_TAG      0x534f4142         /* BAOS */
#define BYTE_ARRAY_OUTPUT_STREAM_DATA_TAG 0x41544144534f4142 /* BAOSDATA */
#define BYTE_ARRAY_OUTPUT_STREAM_BUFF_TAG 0x46465542534f4142 /* BAOSBUFF */

#define BYTEARRAY_STARTSIZE               1024

#define BAOSZDUP_TAG                      0x5055445a534f4142
#define BAOSDUP_TAG                       0x505544534f4142

typedef struct bytezarray_output_stream_data bytezarray_output_stream_data;

/**
 * @NOTE: if this changes, take care that bytezarray_output_stream_context in the header file has at least the SAME SIZE
 */

struct bytezarray_output_stream_data
{
    uint8_t *buffer;
    uint32_t buffer_size;
    uint32_t buffer_offset;
    uint8_t  flags;
};

static ya_result bytezarray_output_stream_write(output_stream_t *stream, const uint8_t *buffer, uint32_t len)
{
    if(len == 0)
    {
        return 0;
    }

    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)stream->data;

    uint32_t                       remaining = data->buffer_size - data->buffer_offset;

    if(len > remaining)
    {
        /* Either we can resize, either we have to trunk */

        if((data->flags & BYTEARRAY_DYNAMIC) != 0)
        {
            uint8_t *newbuffer;
            uint32_t newsize = data->buffer_size;

            do
            {
                newsize = newsize * 2;
            } while(newsize < data->buffer_size + len);

            ZALLOC_OBJECT_ARRAY_OR_DIE(newbuffer, uint8_t, newsize, BYTE_ARRAY_OUTPUT_STREAM_TAG);

            MEMCOPY(newbuffer, data->buffer, data->buffer_offset);

            if((data->flags & BYTEARRAY_OWNED) != 0)
            {
                ZFREE_ARRAY(data->buffer, data->buffer_size);
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

static ya_result bytezarray_output_stream_flush(output_stream_t *stream)
{
    (void)stream;

    return SUCCESS;
}

static void bytezarray_output_stream_close(output_stream_t *stream)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)stream->data;

    if((data->flags & BYTEARRAY_OWNED) != 0)
    {
#if DEBUG
        memset(data->buffer, 0xe5, data->buffer_size);
#endif
        ZFREE_ARRAY(data->buffer, data->buffer_size);
    }

    if((data->flags & BYTEARRAY_ZALLOC_CONTEXT) != 0)
    {
        ZFREE(data, bytezarray_output_stream_data);
    }

    output_stream_set_void(stream);
}

static const output_stream_vtbl bytezarray_output_stream_vtbl = {
    bytezarray_output_stream_write,
    bytezarray_output_stream_flush,
    bytezarray_output_stream_close,
    "bytezarray_output_stream",
};

void bytezarray_output_stream_init_ex_static(output_stream_t *out_stream, uint8_t *array, uint32_t size, uint8_t flags, bytezarray_output_stream_context *ctx)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)ctx;

    if(array == NULL)
    {
        flags |= BYTEARRAY_OWNED;

        if(size == 0)
        {
            flags |= BYTEARRAY_DYNAMIC;

            size = BYTEARRAY_STARTSIZE;
        }

        ZALLOC_OBJECT_ARRAY_OR_DIE(array, uint8_t, size, BYTE_ARRAY_OUTPUT_STREAM_BUFF_TAG);
    }

    data->buffer = array;
    data->buffer_size = size;
    data->buffer_offset = 0;
    data->flags = flags;

    out_stream->data = data;
    out_stream->vtbl = &bytezarray_output_stream_vtbl;
}

void bytezarray_output_stream_init_ex(output_stream_t *out_stream, uint8_t *array, uint32_t size, uint8_t flags)
{
    bytezarray_output_stream_data *data;

    ZALLOC_OBJECT_OR_DIE(data, bytezarray_output_stream_data, BYTE_ARRAY_OUTPUT_STREAM_DATA_TAG);

    flags |= BYTEARRAY_ZALLOC_CONTEXT;

    bytezarray_output_stream_init_ex_static(out_stream, array, size, flags, (bytezarray_output_stream_context *)data);
}

void bytezarray_output_stream_init(output_stream_t *out_stream, uint8_t *array, uint32_t size) { bytezarray_output_stream_init_ex(out_stream, array, size, 0); }

void bytezarray_output_stream_reset(output_stream_t *stream)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)stream->data;
    data->buffer_offset = 0;
}

uint32_t bytezarray_output_stream_size(output_stream_t *stream)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)stream->data;
    return data->buffer_offset;
}

uint32_t bytezarray_output_stream_buffer_size(output_stream_t *stream)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)stream->data;
    return data->buffer_size;
}

uint32_t bytezarray_output_stream_buffer_offset(output_stream_t *stream)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)stream->data;
    return data->buffer_offset;
}

uint8_t *bytezarray_output_stream_buffer(output_stream_t *stream)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)stream->data;

    return data->buffer;
}

uint8_t *bytezarray_output_stream_detach(output_stream_t *stream)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)stream->data;

    data->flags &= ~BYTEARRAY_OWNED;

    return data->buffer;
}

void bytezarray_output_stream_set(output_stream_t *stream, uint8_t *buffer, uint32_t buffer_size, bool owned)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)stream->data;
    if((data->buffer != buffer) && ((data->flags & BYTEARRAY_OWNED) != 0))
    {
        ZFREE_ARRAY(data->buffer, data->buffer_size);
    }
    data->buffer = buffer;
    data->buffer_offset = buffer_size;
    data->buffer_size = buffer_size;
    data->flags = (data->flags & BYTEARRAY_ZALLOC_CONTEXT) | ((owned) ? BYTEARRAY_OWNED : 0);
}

/**
 * If the buffer is owned, grows it to ensure it has at least the specified size.
 * If the buffer is not owned: fails.
 *
 * @param out_stream the stream
 * @param size the minimum required size
 * @return an error code
 */

ya_result bytezarray_output_stream_ensure(output_stream_t *stream, uint32_t size)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)stream->data;

    if(data->buffer_size < size)
    {
        /* Either we can resize, either we have to trunk */

        size = (size + 7) & ~7;

        if((data->flags & BYTEARRAY_DYNAMIC) != 0)
        {
            uint8_t *newbuffer;

            ZALLOC_OBJECT_ARRAY_OR_DIE(newbuffer, uint8_t, size, BYTE_ARRAY_OUTPUT_STREAM_BUFF_TAG);
            MEMCOPY(newbuffer, data->buffer, data->buffer_offset);

            if((data->flags & BYTEARRAY_OWNED) != 0)
            {
                ZFREE(data->buffer, data->buffer_size);
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

/**
 * Rewinds the position in the stream to by that amount of bytes
 *
 * @param steam
 * @param rewind_count
 * @return the actual rewind_count
 */

uint32_t bytezarray_output_stream_rewind(output_stream_t *out_stream, uint32_t rewind_count)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)out_stream->data;
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

/**
 * Sets the position in the stream.
 * If the buffer is dynamic, may grow the buffer.
 * If the buffer is static, may be limited to the size of the buffer.
 *
 * @param steam
 * @param position
 * @return the new position
 */

uint32_t bytezarray_output_stream_setposition(output_stream_t *out_stream, uint32_t position)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)out_stream->data;

    if(position <= data->buffer_size)
    {
        data->buffer_offset = position;
    }
    else
    {
        ya_result ret = bytezarray_output_stream_ensure(out_stream, position);

        if(ISOK(ret))
        {
            data->buffer_offset = position;
        }
        else
        {
            data->buffer_offset = data->buffer_size;
            position = data->buffer_offset;
        }
    }

    return position;
}

/**
 * Makes a zallocated copy of the buffer up to the current position.
 *
 * @param stream
 * @return a pointer to the zallocated copy
 */

uint8_t *bytezarray_output_stream_zdup(output_stream_t *out_stream)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)out_stream->data;
    uint8_t                       *ret;
    uint32_t                       n = MAX(data->buffer_offset, 1); // because allocating 0 bytes can be an hassle
    ZALLOC_OBJECT_ARRAY_OR_DIE(ret, uint8_t, n, BAOSZDUP_TAG);
    memcpy(ret, data->buffer, n);

    return ret;
}

/**
 * Makes a mallocated copy of the buffer up to the current position.
 *
 * @param stream
 * @return a pointer to the mallocated copy
 */

uint8_t *bytezarray_output_stream_dup(output_stream_t *out_stream)
{
    bytezarray_output_stream_data *data = (bytezarray_output_stream_data *)out_stream->data;
    uint8_t                       *ret;
    uint32_t                       n = MAX(data->buffer_offset, 1); // because allocating 0 bytes can be an hassle
    MALLOC_OR_DIE(uint8_t *, ret, n, BAOSDUP_TAG);
    memcpy(ret, data->buffer, n);

    return ret;
}

/** @} */

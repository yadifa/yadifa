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

#include "dnscore/buffer_output_stream.h"

#define BUFFER_OUTPUT_STREAM_TAG 0x534F5246465542 /* BUFFROS */

typedef struct buffer_output_stream_data buffer_output_stream_data;

struct buffer_output_stream_data
{
    output_stream_t filtered;
    uint32_t        buffer_maxsize;

    uint32_t        buffer_offset;

    uint8_t         buffer[1];
};

static inline ya_result buffer_output_stream_data_write_buffer(buffer_output_stream_data *data)
{
    ya_result                   ret;
    uint8_t                    *base = data->buffer;
    uint8_t                    *buffer = base;
    uint32_t                    len = data->buffer_offset;
    output_stream_write_method *writefunc = data->filtered.vtbl->write;

    for(;;)
    {
        ret = writefunc(&data->filtered, buffer, len);

        if(ISOK(ret))
        {
            if((uint32_t)ret == len)
            {
                return data->buffer_offset;
            }

            len -= ret;
            buffer += ret;
        }
        else
        {
            int32_t d = buffer - base;

            if(d > 0)
            {
                memmove(base, buffer, len);
                data->buffer_offset = len;
                return d;
            }
            else
            {
                return ret;
            }
        }
    }
}

static ya_result buffer_output_stream_write(output_stream_t *stream, const uint8_t *buffer, uint32_t len)
{
    buffer_output_stream_data *data = (buffer_output_stream_data *)stream->data;
    uint8_t                   *src = data->buffer;

    ya_result                  ret;

    if(data->buffer_offset == 0) // empty buffer
    {
        if(len < data->buffer_maxsize) // few bytes
        {
            MEMCOPY(src, buffer, len); // accumulate
            data->buffer_offset = len;

            return len;
        }
        else // write
        {
            ret = output_stream_write(&data->filtered, buffer, len);
            return ret;
        }
    }
    else // buffer not empty
    {
        uint32_t remaining = data->buffer_maxsize - data->buffer_offset;

        if(len < data->buffer_maxsize) // will not immediately require two writes
        {
            if(len < remaining)
            {
                MEMCOPY(&src[data->buffer_offset], buffer, len);
                data->buffer_offset += len;

                return len;
            }
            else // len >= remaining
            {
                // fill the buffer

                MEMCOPY(&src[data->buffer_offset], buffer, remaining);
                data->buffer_offset += remaining;

                // write the content

                if(ISOK(ret = buffer_output_stream_data_write_buffer(data)))
                {
                    len -= remaining;
                    buffer += remaining;

                    // still have len to write

                    // this is always true: len < data->buffer_maxsize
                    MEMCOPY(src, buffer, len);
                    data->buffer_offset = len;
                    return remaining + len;
                }
                else
                {
                    return (remaining > 0) ? (int32_t)remaining : ret;
                }
            }
        }
        else // the write will not go through the buffer: write the buffer then write the data
        {
            if(ISOK(ret = buffer_output_stream_data_write_buffer(data)))
            {
                data->buffer_offset = 0;

                ret = output_stream_write(&data->filtered, buffer, len);
            }

            return ret;
        }
    }
}

static ya_result buffer_output_stream_flush(output_stream_t *stream)
{
    buffer_output_stream_data *data = (buffer_output_stream_data *)stream->data;

    if(data->buffer_offset > 0)
    {
        ya_result ret;

        if(ISOK(ret = buffer_output_stream_data_write_buffer(data)))
        {
            data->buffer_offset = 0;
            return output_stream_flush(&data->filtered);
        }
        else
        {
            return ret;
        }
    }
    else
    {
        return output_stream_flush(&data->filtered);
    }
}

static void buffer_output_stream_close(output_stream_t *stream)
{
    buffer_output_stream_flush(stream);

    buffer_output_stream_data *data = (buffer_output_stream_data *)stream->data;
    output_stream_close(&data->filtered);
    free(data);

    output_stream_set_void(stream);
}

static const output_stream_vtbl buffer_output_stream_vtbl = {
    buffer_output_stream_write,
    buffer_output_stream_flush,
    buffer_output_stream_close,
    "buffer_output_stream",
};

ya_result buffer_output_stream_init(output_stream_t *stream, output_stream_t *filtered, int buffer_size)
{
    buffer_output_stream_data *data;
    assert((filtered != NULL) && (filtered->vtbl != NULL));

    if(buffer_size <= 0)
    {
        buffer_size = 512;
    }

    MALLOC_OR_DIE(buffer_output_stream_data *, data, sizeof(buffer_output_stream_data) + buffer_size - 1, BUFFER_OUTPUT_STREAM_TAG);

    data->filtered.data = filtered->data;
    data->filtered.vtbl = filtered->vtbl;

    data->buffer_maxsize = buffer_size;
    data->buffer_offset = 0;

    output_stream_set_void(filtered);

    stream->data = data;
    stream->vtbl = &buffer_output_stream_vtbl;

    return SUCCESS;
}

output_stream_t *buffer_output_stream_get_filtered(output_stream_t *bos)
{
    buffer_output_stream_data *data = (buffer_output_stream_data *)bos->data;
    yassert(bos->vtbl == &buffer_output_stream_vtbl);
    return &data->filtered;
}

bool is_buffer_output_stream(output_stream_t *os) { return (os != NULL) && (os->vtbl == &buffer_output_stream_vtbl); }

/** @} */

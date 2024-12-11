/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#include "dnscore/dnscore_config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/pushback_input_stream.h"

#define REWIND_INPUT_STREAM_TAG 0x53495246465542 /* BUFFERIS */

typedef struct pushback_input_stream_data pushback_input_stream_data;

struct pushback_input_stream_data
{
    input_stream_t filtered;
    int32_t        buffer_size;   // size of the pushback buffer
    int32_t        buffer_offset; // amount of the pushback that's filled
    bool           marked;        // true if we are in a pushback;
    uint8_t        buffer[];      // the pushback buffer
};

static ya_result               pushback_input_stream_read(input_stream_t *stream, void *buffer, uint32_t len);
static void                    pushback_input_stream_close(input_stream_t *stream);
static ya_result               pushback_input_stream_skip(input_stream_t *stream, uint32_t len);

static const input_stream_vtbl pushback_input_stream_vtbl = {pushback_input_stream_read, pushback_input_stream_skip, pushback_input_stream_close, "pushback_input_stream"};

input_stream_t                 pushback_input_stream_detach(input_stream_t *stream)
{
    pushback_input_stream_data *data = (pushback_input_stream_data *)stream->data;
    input_stream_t              filtered = data->filtered;
    input_stream_set_sink(&data->filtered);
    return filtered;
}

bool pushback_input_stream_push_back(input_stream_t *stream, uint8_t byte_value)
{
    pushback_input_stream_data *data = (pushback_input_stream_data *)stream->data;
    yassert(stream->vtbl == &pushback_input_stream_vtbl);

    if(data->buffer_offset > 0)
    {
        data->buffer[--data->buffer_offset] = byte_value;
        return true;
    }
    else
    {
        return false;
    }
}

static ya_result pushback_input_stream_read(input_stream_t *stream, void *buffer_, uint32_t len)
{
    pushback_input_stream_data *data = (pushback_input_stream_data *)stream->data;
    ya_result                   ret;

    uint8_t                    *buffer = (uint8_t *)buffer_;

    int32_t                     bytes_in_buffer = data->buffer_size - data->buffer_offset;
    if(bytes_in_buffer > 0)
    {
        if(bytes_in_buffer >= (int32_t)len)
        {
            memcpy(buffer, &data->buffer[data->buffer_offset], len);
            data->buffer_offset += len;
            return len;
        }

        memcpy(buffer, &data->buffer[data->buffer_offset], bytes_in_buffer);
        data->buffer_offset = data->buffer_size;
    }
    // no mark? pass-through

    ret = data->filtered.vtbl->read(&data->filtered, buffer + bytes_in_buffer, len);
    if(ISOK(ret))
    {
        return ret + bytes_in_buffer;
    }
    else
    {
        return ret;
    }
}

static void pushback_input_stream_close(input_stream_t *stream)
{
    pushback_input_stream_data *data = (pushback_input_stream_data *)stream->data;
    input_stream_close(&data->filtered);
    free(data);

    input_stream_set_void(stream);
}

static ya_result pushback_input_stream_skip(input_stream_t *stream, uint32_t len)
{
    pushback_input_stream_data *data = (pushback_input_stream_data *)stream->data;
    ya_result                   ret;

    int32_t                     bytes_in_buffer = data->buffer_size - data->buffer_offset;
    if(bytes_in_buffer > 0)
    {
        if(bytes_in_buffer >= (int32_t)len)
        {
            data->buffer_offset += len;
            return len;
        }
        len -= bytes_in_buffer;
        data->buffer_offset = data->buffer_size;
    }

    ret = data->filtered.vtbl->skip(&data->filtered, len);

    if(ISOK(ret))
    {
        return ret + bytes_in_buffer;
    }
    else
    {
        return ret;
    }
}

void pushback_input_stream_init(input_stream_t *stream, input_stream_t *filtered, int pushback_size)
{
    pushback_input_stream_data *data;

    yassert(pushback_size > 0);

    yassert(filtered->vtbl != NULL);

    MALLOC_OR_DIE(pushback_input_stream_data *, data, sizeof(pushback_input_stream_data) + pushback_size, REWIND_INPUT_STREAM_TAG);

    data->filtered.data = filtered->data;
    data->filtered.vtbl = filtered->vtbl;

    filtered->data = NULL;
    filtered->vtbl = NULL;

    data->buffer_size = pushback_size;
    data->buffer_offset = pushback_size;
    memset(data->buffer, '-', pushback_size);

    stream->data = data;
    stream->vtbl = &pushback_input_stream_vtbl;
}

input_stream_t *pushback_input_stream_get_filtered(input_stream_t *bos)
{
    pushback_input_stream_data *data = (pushback_input_stream_data *)bos->data;

    return &data->filtered;
}

/**
 *Returns true iff the input stream is a pushback input stream
 *
 *@param bos
 *@return
 */

bool is_pushback_input_stream(input_stream_t *bos) { return bos->vtbl == &pushback_input_stream_vtbl; }

/* *@} */

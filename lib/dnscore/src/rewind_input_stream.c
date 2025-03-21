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

#include "dnscore/dnscore_config.h"
#include <stdio.h>
#include <stdlib.h>

#if DEBUG
#include "dnscore/logger.h"
#define MODULE_MSG_HANDLE g_system_logger
extern logger_handle_t *g_system_logger;
#endif

#include "dnscore/rewind_input_stream.h"

#define REWIND_INPUT_STREAM_TAG 0x53495246465542 /* BUFFERIS */

/*
 *buffer                                     buffer size
 *|                                          |
 *v                                          v
 *[0123456...                                ]
 *                 ^   ^
 *                 |<->|
 *                 |   buffer offset
 *                 |
 *                 read position
 *
 *                  <-> is rewind relative
 *
 */

typedef struct rewind_input_stream_data rewind_input_stream_data;

struct rewind_input_stream_data
{
    input_stream_t filtered;
#if DEBUG
    uint64_t offset;
#endif
    int32_t buffer_size;     // size of the rewind buffer
    int32_t buffer_offset;   // amount of the rewind that's filled
    int32_t rewind_relative; // position in the rewind
    bool    marked;          // true if we are in a rewind;
    uint8_t buffer[];        // the rewind buffer
};

static ya_result               rewind_input_stream_read(input_stream_t *stream, void *buffer, uint32_t len);
static void                    rewind_input_stream_close(input_stream_t *stream);
static ya_result               rewind_input_stream_skip(input_stream_t *stream, uint32_t len);

static const input_stream_vtbl rewind_input_stream_vtbl = {rewind_input_stream_read, rewind_input_stream_skip, rewind_input_stream_close, "rewind_input_stream"};

/**
 * Marks the stream as the new earliest beginning for a rewind.
 *
 * @param stream
 */

void    rewind_input_stream_mark(input_stream_t *stream);

int32_t rewind_input_stream_rewind(input_stream_t *stream, int32_t how_much)
{
    rewind_input_stream_data *data = (rewind_input_stream_data *)stream->data;
    yassert(stream->vtbl == &rewind_input_stream_vtbl);

    if(data->marked)
    {
        int32_t relative = data->rewind_relative + how_much;

        if(relative <= data->buffer_offset)
        {
            data->rewind_relative = relative;
            return how_much;
        }
        else
        {
            how_much = data->buffer_offset - data->rewind_relative;
            data->rewind_relative = data->buffer_offset;
            return how_much;
        }
    }
    else
    {
        return 0;
    }
}

bool rewind_input_stream_push_back(input_stream_t *stream, uint8_t byte_value)
{
    rewind_input_stream_data *data = (rewind_input_stream_data *)stream->data;
    yassert(stream->vtbl == &rewind_input_stream_vtbl);

    if(!data->marked)
    {
        data->buffer_offset = 0;
        data->rewind_relative = 0;
        data->marked = true;
    }
    if(data->buffer_offset < data->buffer_size)
    {
        data->buffer[data->buffer_offset++] = byte_value;
        data->rewind_relative++;
        return true;
    }
    else
    {
        return false;
    }
}

void rewind_input_stream_rewind_to_mark(input_stream_t *stream)
{
    rewind_input_stream_data *data = (rewind_input_stream_data *)stream->data;
    yassert(stream->vtbl == &rewind_input_stream_vtbl);
#if DEBUG
    log_debug1("rewind_input_stream_rewind_to_mark(%p) (%llu, %u, %u, %u)", stream, data->offset, data->buffer_offset, data->rewind_relative, data->buffer_offset - data->rewind_relative);
#endif
    data->rewind_relative = data->buffer_offset;
}

static ya_result rewind_input_stream_read(input_stream_t *stream, void *buffer_, uint32_t len)
{
    rewind_input_stream_data *data = (rewind_input_stream_data *)stream->data;
    ya_result                 ret;

    uint8_t                  *buffer = (uint8_t *)buffer_;

#if DEBUG
    log_debug1("rewind_input_stream_read(%p, %p, %u) (%llu, %u, %u, %u)", stream, buffer, len, data->offset, data->buffer_offset, data->rewind_relative, data->buffer_offset - data->rewind_relative);
#endif

    // no mark? pass-through

    if(!data->marked)
    {
        ret = data->filtered.vtbl->read(&data->filtered, buffer, len);
#if DEBUG
        if(ISOK(ret))
        {
            data->offset += len;
        }
#endif
        return ret;
    }

    int32_t rewind_len = 0;

    // if rewind_relative > 0, then we have rewinded and are reading from the buffer

    if(data->rewind_relative > 0)
    {
        rewind_len = MIN(data->rewind_relative, (int32_t)len);
        memcpy(buffer, &data->buffer[data->buffer_offset - data->rewind_relative], rewind_len);

        data->rewind_relative -= rewind_len;
        len -= rewind_len;

        if(len == 0)
        {
            return rewind_len;
        }

        // still some bytes to read

        buffer += rewind_len;
    }

    // marked ... add to the rewind buffer

    int32_t remaining_space_in_buffer = data->buffer_size - data->buffer_offset;

    if(remaining_space_in_buffer >= (int32_t)len)
    {
        if(ISOK(ret = data->filtered.vtbl->read(&data->filtered, &data->buffer[data->buffer_offset], len)))
        {
            memcpy(buffer, &data->buffer[data->buffer_offset], ret);
            data->buffer_offset += ret;
#if DEBUG
            data->offset += ret;
#endif
            return ret + rewind_len;
        }
        return ret;
    }
    else
    {
        // we are about to overflow the buffer
        // two implementation choices:
        // _ remove the mark and continue
        // _ cut the read to fill the buffer and return the short read

        data->marked = false;

        if(ISOK(ret = data->filtered.vtbl->read(&data->filtered, buffer, len)))
        {
#if DEBUG
            data->offset += ret;
#endif
            return ret + rewind_len;
        }

        return ret;
    }
}

static void rewind_input_stream_close(input_stream_t *stream)
{
    rewind_input_stream_data *data = (rewind_input_stream_data *)stream->data;
    input_stream_close(&data->filtered);
    free(data);

    input_stream_set_void(stream);
}

static ya_result rewind_input_stream_skip(input_stream_t *stream, uint32_t len)
{
    rewind_input_stream_data *data = (rewind_input_stream_data *)stream->data;
    ya_result                 ret;

#if DEBUG
    log_debug1("rewind_input_stream_skip(%p, %u) (%llu, %u, %u, %u)", stream, len, data->offset, data->buffer_offset, data->rewind_relative, data->buffer_offset - data->rewind_relative);
#endif

    if(!data->marked)
    {
        ret = data->filtered.vtbl->skip(&data->filtered, len);

#if DEBUG
        if(ISOK(ret))
        {
            data->offset += ret;
        }
#endif

        return ret;
    }

    // marked ... add to the rewind buffer

    int32_t rewind_len = 0;

    if(data->rewind_relative > 0)
    {
        rewind_len = MIN(data->rewind_relative, (int32_t)len);

        data->rewind_relative -= rewind_len;
        len -= rewind_len;

        if(len == 0)
        {
            return rewind_len;
        }

        // still some bytes to read
    }

    int32_t remaining_space_in_buffer = data->buffer_size - data->buffer_offset;

    if(remaining_space_in_buffer >= (int32_t)len)
    {
        if(ISOK(ret = data->filtered.vtbl->read(&data->filtered, &data->buffer[data->buffer_offset], len)))
        {
            data->buffer_offset += ret;
#if DEBUG
            data->offset += ret;
#endif
            return ret + rewind_len;
        }

        return ret;
    }
    else
    {
        // we are about to overflow the buffer
        // two implementation choices:
        // _ remove the mark and continue
        // _ cut the read to fill the buffer and return the short read

        data->marked = false;

        if(ISOK(ret = data->filtered.vtbl->skip(&data->filtered, len)))
        {
#if DEBUG
            data->offset += ret;
#endif
            return ret + rewind_len;
        }

        return ret;
    }
}

void rewind_input_stream_mark(input_stream_t *stream)
{
    rewind_input_stream_data *data = (rewind_input_stream_data *)stream->data;
    yassert(stream->vtbl == &rewind_input_stream_vtbl);

#if DEBUG
    log_debug1("rewind_input_stream_mark(%p) (%llu, %u, %u, %u)", stream, data->offset, data->buffer_offset, data->rewind_relative, data->buffer_offset - data->rewind_relative);
#endif

    if(!data->marked) // not marked yet: sets the offset and relative to right here
    {
        data->buffer_offset = 0;
        data->rewind_relative = 0;
        data->marked = true;

#if DEBUG
        memset(data->buffer, 0xff, data->buffer_size);
#endif
    }
    else
    {
        // If rewind relative is not 0, then memory will have to be moved
        // else it means that we are at the buffer_offset and thus we don't care
        //      about the past.

        int32_t src_len = data->rewind_relative;

        if(src_len != 0 && data->buffer_offset != src_len)
        {
            memmove(&data->buffer[0], &data->buffer[data->buffer_offset - src_len], src_len);
        }

        data->buffer_offset = src_len;
        data->rewind_relative = src_len;

#if DEBUG
        memset(&data->buffer[data->buffer_offset], 0xff, data->buffer_size - data->buffer_offset);
#endif
    }
}

void rewind_input_stream_init(input_stream_t *stream, input_stream_t *filtered, int rewind_size)
{
    rewind_input_stream_data *data;

    yassert(rewind_size > 0);

    yassert(filtered->vtbl != NULL);

    MALLOC_OR_DIE(rewind_input_stream_data *, data, sizeof(rewind_input_stream_data) + rewind_size, REWIND_INPUT_STREAM_TAG);

    data->filtered.data = filtered->data;
    data->filtered.vtbl = filtered->vtbl;
#if DEBUG
    data->offset = 0;
    memset(data->buffer, 0xff, rewind_size);
#endif

    filtered->data = NULL;
    filtered->vtbl = NULL;

    data->buffer_size = rewind_size;
    data->marked = false;

    stream->data = data;
    stream->vtbl = &rewind_input_stream_vtbl;
}

input_stream_t *rewind_input_stream_get_filtered(input_stream_t *bos)
{
    rewind_input_stream_data *data = (rewind_input_stream_data *)bos->data;

    return &data->filtered;
}

/**
 *Returns true iff the input stream is a rewind input stream
 *
 *@param bos
 *@return
 */

bool is_rewind_input_stream(input_stream_t *bos) { return bos->vtbl == &rewind_input_stream_vtbl; }

/* *@} */

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

#include "dnscore/buffer_input_stream.h"

#define BUFFER_INPUT_STREAM_TAG 0x53495246465542 /* BUFFERIS */

typedef struct buffer_input_stream_data buffer_input_stream_data;

struct buffer_input_stream_data
{
    input_stream_t filtered;
    uint32_t       buffer_maxsize; // physical size of the buffer

    uint32_t       buffer_size;   // amount of the buffer that's filled
    uint32_t       buffer_offset; // position in the buffer

    uint8_t        buffer[1];
};

static ya_result buffer_input_stream_read(input_stream_t *stream, void *buffer_, uint32_t len)
{
    buffer_input_stream_data *data = (buffer_input_stream_data *)stream->data;
    uint8_t                  *buffer = (uint8_t *)buffer_;
    uint8_t                  *src = data->buffer;

    ya_result                 ret;

    uint32_t                  remaining = data->buffer_size - data->buffer_offset;

    if(len <= remaining)
    {
        MEMCOPY(buffer, &src[data->buffer_offset], len);
        data->buffer_offset += len;

        /* There are still some bytes available */

        return len;
    }

    /* len >= remaining : copy what remains in the buffer */

    MEMCOPY(buffer, &src[data->buffer_offset], remaining);
    len -= remaining;
    buffer += remaining;

    /* NOTE: at this point the internal buffer is empty */

    if(len >= data->buffer_maxsize)
    {
        /* It would be pointless to buffer a read bigger than the buffer */

        data->buffer_offset = data->buffer_size; /* mark the buffer as "empty" */

        if(ISOK(ret = input_stream_read(&data->filtered, buffer, len)))
        {
            return remaining + ret; /* the chunk we've read from the buffer +
                                   the chunk we've read from the stream */
        }
        else // 'remaining' bytes may have been copied already, if so, return that before the error
        {
            return (remaining > 0) ? (int32_t)remaining : ret;
        }
    }

#if DEBUG
    memset(data->buffer, 0xbe, data->buffer_maxsize);
#endif

    // What remains to read is smaller than the buffer max size:
    // read a full buffer

    if((ret = input_stream_read(&data->filtered, data->buffer, data->buffer_maxsize)) <= 0)
    {
        data->buffer_size = 0;
        data->buffer_offset = 0;

        // 'remaining' bytes may have been copied already, if so, return that before the error

        return (remaining > 0) ? (int32_t)remaining : ERROR /* eof */;
    }

    if(len > (uint32_t)ret) // ret > 0
    {
        len = (uint32_t)ret;
    }

    MEMCOPY(buffer, data->buffer, len); /* starts at offset 0 */

    data->buffer_size = (uint32_t)ret;
    data->buffer_offset = len;

    return remaining + len;
}

static void buffer_input_stream_close(input_stream_t *stream)
{
    buffer_input_stream_data *data = (buffer_input_stream_data *)stream->data;
    input_stream_close(&data->filtered);
    free(data);

    input_stream_set_void(stream);
}

static ya_result buffer_input_stream_skip(input_stream_t *stream, uint32_t len)
{
    ya_result                 ret;

    buffer_input_stream_data *data = (buffer_input_stream_data *)stream->data;
    uint32_t                  remaining = data->buffer_size - data->buffer_offset;

    if(len <= remaining)
    {
        data->buffer_offset += len;
        return len;
    }

    len -= remaining;

    data->buffer_offset = data->buffer_size;

    if(FAIL(ret = input_stream_skip(&data->filtered, len)))
    {
        // 'remaining' bytes may have been skipped already, if so, return that before the error

        return (remaining > 0) ? (int32_t)remaining : ret;
    }

    return remaining + ret;
}

static const input_stream_vtbl buffer_input_stream_vtbl = {buffer_input_stream_read, buffer_input_stream_skip, buffer_input_stream_close, "buffer_input_stream"};

/**
 * Initialises a buffer input stream.
 *
 * @param stream the stream to initialise
 * @param filtered_in the stream to filter
 * @param buffer_size the size of the buffer
 */

void buffer_input_stream_init(input_stream_t *stream, input_stream_t *filtered, int buffer_size)
{
    buffer_input_stream_data *data;

    if(buffer_size == 0)
    {
        buffer_size = BUFFER_INPUT_STREAM_DEFAULT_BUFFER_SIZE;
    }

    yassert(filtered->vtbl != NULL);

    MALLOC_OR_DIE(buffer_input_stream_data *, data, sizeof(buffer_input_stream_data) + buffer_size - 1, BUFFER_INPUT_STREAM_TAG);

    data->filtered.data = filtered->data;
    data->filtered.vtbl = filtered->vtbl;

    filtered->data = NULL;
    filtered->vtbl = NULL;

    data->buffer_maxsize = (uint32_t)buffer_size;
    data->buffer_size = 0;
    data->buffer_offset = 0;

    stream->data = data;
    stream->vtbl = &buffer_input_stream_vtbl;
}

/**
 * Function specific to the buffer_input_stream_t to read a line up to the '\n'
 */

ya_result buffer_input_stream_read_line(input_stream_t *stream, char *buffer, uint32_t len)
{
    assert(stream->vtbl == &buffer_input_stream_vtbl);

    buffer_input_stream_data *data = (buffer_input_stream_data *)stream->data;

    assert(data->buffer_offset <= data->buffer_size);

    char *src = (char *)data->buffer;

    if(len == 0)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    len--;

    uint32_t total = 0;

    /*
     * look for '\n' in the remaining bytes
     */

    char   *b = &src[data->buffer_offset];
    int32_t n = data->buffer_size - data->buffer_offset;

    if(n == 0)
    {
        if((n = input_stream_read(&data->filtered, (uint8_t *)src, data->buffer_maxsize)) <= 0)
        {
            data->buffer_offset = 0;
            data->buffer_size = 0;

            return n /* eof */;
        }

        data->buffer_offset = 0;
        data->buffer_size = (uint32_t)n;
        b = src;
    }

    for(;;)
    {

        n = MIN((int32_t)len, n);

        //
        char *eol = (char *)memchr(b, '\n', (size_t)n);
        if(eol != NULL)
        {
            ++eol;
            uint32_t len_to_the_end = eol - b;
            data->buffer_offset = eol - src;
            memcpy(buffer, b, len_to_the_end);
            buffer[len_to_the_end] = '\0';
            return total + len_to_the_end;
        }
        memcpy(buffer, b, (size_t)n);
        buffer += n;
        //
        total += n;
        len -= (int32_t)n;

        if(len == 0)
        {
            data->buffer_offset += len;

            *buffer = '\0';

            return total;
        }

        /* What remains to read is smaller than the buffer max size */

        data->buffer_offset = 0;

        if((n = input_stream_read(&data->filtered, (uint8_t *)src, data->buffer_maxsize)) <= 0)
        {
            data->buffer_size = 0;

            *buffer = '\0';

            return (total > 0) ? (int32_t)total : ERROR /* eof */;
        }

        data->buffer_size = (uint32_t)n;

        b = src;
    }
}

/**
 * Returns a pointer to the filtered stream inside the buffer input stream.
 *
 * @param bos
 * @return
 */

input_stream_t *buffer_input_stream_get_filtered(input_stream_t *bos)
{
    buffer_input_stream_data *data = (buffer_input_stream_data *)bos->data;

    return &data->filtered;
}

/**
 * Detaches the filtered input stream, sends a copy back.
 *
 * @param bos
 * @return
 */

input_stream_t buffer_input_stream_detach(input_stream_t *bos)
{
    buffer_input_stream_data *data = (buffer_input_stream_data *)bos->data;
    input_stream_t filtered = data->filtered;
    input_stream_set_sink(&filtered);
    return filtered;
}

/**
 * Rewinds the input stream back of a given number of bytes
 *
 * @param bos
 * @param bytes_back
 *
 * @return bytes_back : the operation was successful
 *         > 0        : the maximum number of bytes available for rewind at the time of the call
 */

ya_result buffer_input_stream_rewind(input_stream_t *bos, uint32_t bytes_back)
{
    buffer_input_stream_data *data = (buffer_input_stream_data *)bos->data;

    if(bytes_back <= data->buffer_offset)
    {
        data->buffer_offset -= bytes_back;
        return bytes_back;
    }
    else
    {
        return data->buffer_offset;
    }
}

/**
 * Returns true iff the input stream is a buffer input stream
 *
 * @param bos
 * @return
 */

bool is_buffer_input_stream(input_stream_t *bos) { return bos->vtbl == &buffer_input_stream_vtbl; }

/** @} */

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

#include "dnscore/buffer_input_stream.h"

#define BUFFER_INPUT_STREAM_TAG 0x53495246465542    /* BUFFERIS */

typedef struct buffer_input_stream_data buffer_input_stream_data;

struct buffer_input_stream_data
{
    input_stream filtered;
    u32 buffer_maxsize; // physical size of the buffer

    u32 buffer_size;    // amount of the buffer that's filled
    u32 buffer_offset;  // position in the buffer

    u8 buffer[1];
};

static ya_result
buffer_read(input_stream* stream, u8* buffer, u32 len)
{
    buffer_input_stream_data* data = (buffer_input_stream_data*)stream->data;
    u8* src = data->buffer;

    ya_result ret;

    u32 remaining = data->buffer_size - data->buffer_offset;

    if(len < remaining)
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

    if(len > data->buffer_maxsize)
    {
        /* It would be pointless to buffer a read bigger than the buffer */

        data->buffer_offset = data->buffer_size; /* mark the buffer as "empty" */

        if(ISOK(ret = input_stream_read(&data->filtered, buffer, len)))
        {
            return remaining + len; /* the chunk we've read from the buffer +
				   the chunk we've read from the stream */
        }

        return ret;
    }

#ifdef DEBUG
    memset(data->buffer, 0xee, data->buffer_maxsize);
#endif

    /* What remains to read is smaller than the buffer max size */

    if((ret = input_stream_read(&data->filtered, data->buffer, data->buffer_maxsize)) <= 0)
    {
        data->buffer_size = 0;
        data->buffer_offset = 0;

        return (remaining > 0) ? remaining : ERROR /* eof */; // TODO: this should be 0, not ERROR ... what are the side effects if fixed ?
    }

    MEMCOPY(buffer, data->buffer, len); /* starts at offset 0 */

    data->buffer_size = ret;
    data->buffer_offset = len;

    return remaining + len;
}

static void
buffer_close(input_stream* stream)
{
    buffer_input_stream_data* data = (buffer_input_stream_data*)stream->data;
    input_stream_close(&data->filtered);
    free(data);

    input_stream_set_void(stream);
}

static ya_result
buffer_skip(input_stream* stream, u32 len)
{
    ya_result return_code;
    u32 total_len = len;
    
    buffer_input_stream_data* data = (buffer_input_stream_data*)stream->data;
    u32 remaining = data->buffer_size - data->buffer_offset;

    if(remaining > len)
    {
        data->buffer_offset += len;
        return len;
    }

    len -= remaining;

    data->buffer_offset = data->buffer_size;

    if(FAIL(return_code = input_stream_skip(&data->filtered, len)))
    {
        return return_code;
    }

    return total_len;
}

static const input_stream_vtbl buffer_input_stream_vtbl =
{
    buffer_read,
    buffer_skip,
    buffer_close,
    "buffer_input_stream"
};

void
buffer_input_stream_init(input_stream* filtered, input_stream* stream, int buffer_size)
{
    buffer_input_stream_data* data;
    
    if(buffer_size == 0)
    {
        buffer_size = BUFFER_INPUT_STREAM_DEFAULT_BUFFER_SIZE;
    }

    yassert(filtered->vtbl != NULL);

    MALLOC_OR_DIE(buffer_input_stream_data*, data, sizeof (buffer_input_stream_data) + buffer_size - 1, BUFFER_INPUT_STREAM_TAG);

    data->filtered.data = filtered->data;
    data->filtered.vtbl = filtered->vtbl;

    filtered->data = NULL;
    filtered->vtbl = NULL;

    data->buffer_maxsize = buffer_size;
    data->buffer_size = 0;
    data->buffer_offset = 0;

    stream->data = data;
    stream->vtbl = &buffer_input_stream_vtbl;
}

ya_result
buffer_input_stream_read_line(input_stream* stream, char* buffer, u32 len)
{
    assert(stream->vtbl == &buffer_input_stream_vtbl);
    
    buffer_input_stream_data* data = (buffer_input_stream_data*)stream->data;
    
    assert(data->buffer_offset <= data->buffer_size); 
    
    char *src = (char*)data->buffer;
    
    if(len == 0)
    {
        return BUFFER_WOULD_OVERFLOW;
    }
    
    len--;

    u32 total = 0;
    
    /*
     * look for '\n' in the remaining bytes
     */

    char *b = &src[data->buffer_offset];
    s32 n = data->buffer_size - data->buffer_offset;
    
    if(n == 0)
    {
        if((n = input_stream_read(&data->filtered, (u8*)src, data->buffer_maxsize)) <= 0)
        {
            data->buffer_offset = 0;
            data->buffer_size = 0;
            
            return n /* eof */;
        }
        
        data->buffer_offset = 0;
        data->buffer_size = n;
        b = src;
    }
    
    for(;;)
    { 
        
        n = MIN((s32)len, n);
        
#if 0 /* fix */
#else
        //
        char *eol = (char*)memchr(b, '\n', n);
        if(eol != NULL)
        {
            ++eol;
            u32 len = eol - b;
            data->buffer_offset = eol - src;
            memcpy(buffer, b, len);
            buffer[len] = '\0';
            return total + len;
        }
        memcpy(buffer, b, n);
        buffer += n;
#endif
        //
        total += n;
        len -= (s32)n;
        
        if(len == 0)
        {
            data->buffer_offset += len;
            
            *buffer = '\0';
            
            return total;
        }

       /* What remains to read is smaller than the buffer max size */

        data->buffer_offset = 0;

        if((n = input_stream_read(&data->filtered, (u8*)src, data->buffer_maxsize)) <= 0)
        {
            data->buffer_size = 0;
            
            *buffer = '\0';

            return (total > 0) ? total : ERROR /* eof */;
        }
        
        data->buffer_size = n;

        b = src;
    }
}

input_stream*
buffer_input_stream_get_filtered(input_stream *bos)
{
    buffer_input_stream_data* data = (buffer_input_stream_data*)bos->data;

    return &data->filtered;
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

ya_result
buffer_input_stream_rewind(input_stream *bos, u32 bytes_back)
{
    buffer_input_stream_data* data = (buffer_input_stream_data*)bos->data;
    
    if(bytes_back < data->buffer_offset)
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

bool
is_buffer_input_stream(input_stream *bos)
{
    return bos->vtbl == &buffer_input_stream_vtbl;
}

/** @} */

/*----------------------------------------------------------------------------*/


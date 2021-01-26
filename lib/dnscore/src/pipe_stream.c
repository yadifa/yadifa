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

#include "dnscore/dnscore-config.h"
#include <unistd.h>
#include "dnscore/pipe_stream.h"

#include "dnscore/logger.h"

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#define MODULE_MSG_HANDLE		g_system_logger

#define DEBUG_PIPE_OUTPUT_STREAM 0

#define OUTPUT_OPENED 1
#define INPUT_OPENED 2

typedef struct pipe_stream_data pipe_stream_data;

#define PIPESDTA_TAG 0x4154445345504950
#define PIPESBFR_TAG 0x5246425345504950

struct pipe_stream_data
{
    u8* buffer;
    u32 buffer_size;
    u32 write_offset;
    u32 write_avail;
    u32 read_offset;
    u32 read_avail;
    u8  flags;
};

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */


static ya_result
pipe_stream_output_write(output_stream* stream, const u8* buffer, u32 len)
{
    if(len == 0)
    {
        return 0;
    }

    pipe_stream_data *data = (pipe_stream_data*)stream->data;
    
    u32 remaining = len;
    
    while((remaining > 0) && (data->write_avail > 0))
    {
        u32 chunk_len = MIN(data->buffer_size - data->write_offset, data->write_avail);
        chunk_len = MIN(remaining, chunk_len);
        
#if DEBUG_PIPE_OUTPUT_STREAM
        log_debug("pipe: w: %d bytes", len);
        log_memdump_ex(g_system_logger, LOG_DEBUG, buffer, chunk_len, 16, OSPRINT_DUMP_ALL);
#endif
        
        MEMCOPY(&data->buffer[data->write_offset], buffer, chunk_len);
        buffer += chunk_len;
        data->write_offset += chunk_len;
        data->write_avail -= chunk_len;
        data->read_avail += chunk_len;
        if(data->write_offset == data->buffer_size)
        {
            data->write_offset = 0;
        }
        remaining -= chunk_len;
        
        //usleep(1000);
    }
    
    len -= remaining;
    
    if((len == 0) && ( (data->flags & (INPUT_OPENED|OUTPUT_OPENED))  != (INPUT_OPENED|OUTPUT_OPENED)))
    {
        return UNEXPECTED_EOF; // if one of the sides is closed ...
    }

    return len;
}

static ya_result
pipe_stream_output_flush(output_stream* stream)
{
    (void)stream;
    return SUCCESS;
}

static void
pipe_stream_output_close(output_stream* stream)
{
    pipe_stream_data* data = (pipe_stream_data*)stream->data;

    data->flags &= ~OUTPUT_OPENED;
    
    if((data->flags & INPUT_OPENED) == 0)
    {
        free(data->buffer);
        free(data);
    }

    output_stream_set_void(stream);
}

static const output_stream_vtbl pipe_stream_output_vtbl = {
    pipe_stream_output_write,
    pipe_stream_output_flush,
    pipe_stream_output_close,
    "pipe_stream_output",
};


static ya_result
pipe_stream_input_read(input_stream* stream, void *buffer_, u32 len)
{
    if(len == 0)
    {
        return 0;
    }
    
    u8 *buffer = (u8*)buffer_;
    
#if DEBUG
    memset(buffer, 0xff, len);
#endif

    pipe_stream_data* data = (pipe_stream_data*)stream->data;
    
    u32 remaining = len;
    
    while((remaining > 0) && (data->read_avail > 0))
    {
        u32 chunk_len = MIN(data->buffer_size - data->read_offset, data->read_avail);
        chunk_len = MIN(remaining, chunk_len);
        MEMCOPY(buffer, &data->buffer[data->read_offset], chunk_len);
        buffer += chunk_len;
        data->read_offset += chunk_len;
        data->read_avail -= chunk_len;
        data->write_avail += chunk_len;

        if(data->read_offset == data->buffer_size)
        {
            data->read_offset = 0;
        }
        remaining -= chunk_len;
    }

    return len - remaining;
}

static ya_result
pipe_stream_input_skip(input_stream* stream, u32 len)
{
    if(len == 0)
    {
        return 0;
    }

    pipe_stream_data* data = (pipe_stream_data*)stream->data;
    
    u32 remaining = len;
    
    for(;;)
    {
        while((remaining > 0) && (data->read_avail > 0))
        {
            u32 chunk_len = MIN(data->buffer_size - data->read_offset, data->read_avail);
            chunk_len = MIN(remaining, chunk_len);
            
            data->read_offset += chunk_len;
            data->read_avail -= chunk_len;
            data->write_avail += chunk_len;

            if(data->read_offset == data->buffer_size)
            {
                data->read_offset = 0;
            }
            remaining -= chunk_len;
        }
        
        if((len != remaining) || ((data->flags & OUTPUT_OPENED) == 0))
        {
            break;
        }
        
        usleep(1000);
    }
    
    return len - remaining;
}

static void
pipe_stream_input_close(input_stream* stream)
{
    pipe_stream_data* data = (pipe_stream_data*)stream->data;

    data->flags &= ~INPUT_OPENED;
    
    if((data->flags & OUTPUT_OPENED) == 0)
    {
        free(data->buffer);
        free(data);
    }

    input_stream_set_void(stream);
}

static const input_stream_vtbl pipe_stream_input_vtbl =
{
    pipe_stream_input_read,
    pipe_stream_input_skip,
    pipe_stream_input_close,
    "pipe_stream_input_stream",
};

/**
 * Creates both output and input stream
 * Writing in the output stream makes it available for the input stream
 * This is not currently threadable.
 * 
 * @param output
 * @param input
 */

void
pipe_stream_init(output_stream *output, input_stream *input, u32 buffer_size)
{
    pipe_stream_data *data;
    MALLOC_OBJECT_OR_DIE(data, pipe_stream_data, PIPESDTA_TAG);   
    ZEROMEMORY(data, sizeof(pipe_stream_data));
    MALLOC_OR_DIE(u8*, data->buffer, buffer_size, PIPESBFR_TAG);
    
#if DEBUG
    memset(data->buffer, 0xff, buffer_size);
#endif
    
    data->buffer_size = buffer_size;
    data->write_avail = buffer_size;
    data->flags       = OUTPUT_OPENED|INPUT_OPENED;
    output->data = data;
    output->vtbl = &pipe_stream_output_vtbl;
    input->data = data;
    input->vtbl = &pipe_stream_input_vtbl;
}

/**
 * 
 * Number of available bytes in the input stream
 * 
 * @param input
 * @return 
 */

ya_result
pipe_stream_read_available(input_stream *input)
{
    pipe_stream_data *data = (pipe_stream_data*)input->data;
    return data->read_avail;
}

/**
 * 
 * Room for bytes in the output stream
 * 
 * @param input
 * @return 
 */

ya_result
pipe_stream_write_available(output_stream *input)
{
    pipe_stream_data *data = (pipe_stream_data*)input->data;
    return data->write_avail;
}

/** @} */

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
#include <stdlib.h>
#include <string.h>

#include "dnscore/logger_handle.h"
#include "dnscore/zalloc.h"

/*
 * This structure is supposed to match the output_stream one
 * It helps using the void* data as an int without a INT_AT(x) kind of macro
 */

typedef struct logger_output_stream_data logger_output_stream_data;

#define LGOSDATA_TAG 0x41544144534f474c
#define LGOSLINE_TAG 0x454e494c534f474c

struct logger_output_stream_data
{
    logger_handle *handle;
    char *line;
    u32 line_offset;
    u32 line_size;
    u32 level;
};

typedef struct logger_output_stream logger_output_stream;

struct logger_output_stream
{
    logger_output_stream_data *data;
    const output_stream_vtbl *vtbl;
};

static ya_result
logger_output_stream_write(output_stream* stream_, const u8* buffer, u32 len_)
{
    logger_output_stream* stream = (logger_output_stream*)stream_;

    u32 len = len_;
    
    for(;;)
    {
        const u8 *eol = (const u8*)memchr(buffer, '\n', len);
        
        if(eol == NULL)
        {
            break;
        }
        
        u32 line_len = eol - buffer;
        
        // merge with the buffer if it exists
        
        if(stream->data->line_offset == 0)
        {
            logger_handle_msg_text(stream->data->handle, stream->data->level, (const char*)buffer, line_len);
            ++line_len;
            buffer += line_len;
            len -= line_len;
        }
        else
        {
            // merge with the buffer
            
            int remaining = stream->data->line_size - stream->data->line_offset;
            
            if(remaining >= (int)line_len)
            {
                memcpy(&stream->data->line[stream->data->line_offset], buffer, line_len);
                stream->data->line_offset += line_len;
                logger_handle_msg_text(stream->data->handle, stream->data->level, stream->data->line, stream->data->line_offset);
            }
            else
            {
                memcpy(&stream->data->line[stream->data->line_offset], buffer, remaining);
                stream->data->line_offset += remaining;
                logger_handle_msg_text(stream->data->handle, stream->data->level, stream->data->line, stream->data->line_offset);
                line_len -= remaining;
                logger_handle_msg_text(stream->data->handle, stream->data->level, (const char*)buffer, line_len);
            }
            
            ++line_len;
            buffer += line_len;
            len -= line_len;
            stream->data->line_offset = 0;
        }
    }
    
    // no EOL, try to flush what remains
    
    while(len > 0)
    {
        int remaining = stream->data->line_size - stream->data->line_offset;
        
        if(remaining >= (int)len)
        {
            memcpy(&stream->data->line[stream->data->line_offset], buffer, len);
            stream->data->line_offset += len;
            break;
        }
        else
        {
            memcpy(&stream->data->line[stream->data->line_offset], buffer, remaining);            
            logger_handle_msg_text(stream->data->handle, stream->data->level, stream->data->line, stream->data->line_size);
            stream->data->line_offset = 0;
            len -= remaining;
        }
    }

    return len_;
}

static ya_result
logger_output_stream_flush(output_stream* stream_)
{
    (void)stream_;
    //logger_flush();

    return SUCCESS;
}

static void
logger_output_stream_close(output_stream* stream_)
{
    logger_output_stream* stream = (logger_output_stream*)stream_;
    
    free(stream->data->line);
    ZFREE_OBJECT(stream->data);

    output_stream_set_void(stream_);
}

static const output_stream_vtbl logger_output_stream_vtbl =
{
    logger_output_stream_write,
    logger_output_stream_flush,
    logger_output_stream_close,
    "logger_output_stream",
};

ya_result
logger_output_stream_open(output_stream* stream, logger_handle *handle, u16 level, u32 max_line_len)
{
    if(stream == NULL || handle == NULL || level == 0 || max_line_len < 64 || max_line_len > 65536)
    {
        return INVALID_ARGUMENT_ERROR;
    }
    
    logger_output_stream_data *data;
    ZALLOC_OBJECT_OR_DIE( data, logger_output_stream_data, LGOSDATA_TAG);
    data->handle = handle;
    data->level = level;
    MALLOC_OR_DIE(char*, data->line, max_line_len, LGOSLINE_TAG);
    data->line_offset = 0;
    data->line_size = max_line_len;
    stream->data = data;
    stream->vtbl = &logger_output_stream_vtbl;
    
    return SUCCESS;
}

/** @} */


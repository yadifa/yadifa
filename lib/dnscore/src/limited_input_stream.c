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

#include "dnscore/limited_input_stream.h"
#include "dnscore/zalloc.h"

#define LIMITED_INPUT_STREAM_TAG 0x53494454494d494c    /* LIMITDIS */

#define MODULE_MSG_HANDLE g_database_logger

typedef struct limited_input_stream_data limited_input_stream_data;

struct limited_input_stream_data
{
    input_stream filtered;
    u64 remaining;
};

static ya_result
limited_read(input_stream* stream, void* buffer, u32 len)
{
    limited_input_stream_data* data = (limited_input_stream_data*)stream->data;
    
    if(data->remaining > 0)
    { 
        len = MIN(len, data->remaining);

        ya_result return_value = input_stream_read(&data->filtered, buffer, len);

        if(ISOK(return_value))
        {
            data->remaining -= len;
        }

        return return_value;
    }
    else
    {
       return -1;   /* EOF */ 
    }
}

static void
limited_close(input_stream* stream)
{
    limited_input_stream_data* data = (limited_input_stream_data*)stream->data;
    input_stream_close(&data->filtered);
    ZFREE_OBJECT(data);

    input_stream_set_void(stream);
}

static ya_result
limited_skip(input_stream* stream, u32 len)
{
    limited_input_stream_data* data = (limited_input_stream_data*)stream->data;
 
    len = MIN(len, data->remaining);

    ya_result return_value = input_stream_skip(&data->filtered, len);
    
    if(ISOK(return_value))
    {
        data->remaining -= len;
    }

    return return_value;
}

static const input_stream_vtbl limited_input_stream_vtbl =
{
    limited_read,
    limited_skip,
    limited_close,
    "limited_input_stream"
};

void
limited_input_stream_init(input_stream* filtered, input_stream *stream, u64 stream_size)
{
    limited_input_stream_data* data;

    yassert(filtered->vtbl != NULL);

    ZALLOC_OBJECT_OR_DIE( data, limited_input_stream_data, LIMITED_INPUT_STREAM_TAG);

    data->filtered.data = filtered->data;
    data->filtered.vtbl = filtered->vtbl;

    filtered->data = NULL;
    filtered->vtbl = NULL;

    data->remaining = stream_size;

    stream->data = data;
    stream->vtbl = &limited_input_stream_vtbl;
}

/** @} */

/*----------------------------------------------------------------------------*/


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

#include "dnscore/clone_input_output_stream.h"
#include "dnscore/zalloc.h"

#define CLONE_INPUT_OUTPUT_STREAM_TAG 0x534f49454e4f4c43 /* CLONEIOS */

typedef struct clone_input_output_stream_data clone_input_output_stream_data;

struct clone_input_output_stream_data
{
    input_stream cloned;
    output_stream copy;
};

static ya_result
clone_input_output_stream_read(input_stream* stream, void* buffer, u32 len)
{
    clone_input_output_stream_data* data = (clone_input_output_stream_data*)stream->data;
    
    ya_result return_value;
    
    if(ISOK(return_value = input_stream_read(&data->cloned, buffer, len)))
    {
        output_stream_write(&data->copy, buffer, (u32)return_value);
    }    

    return return_value;
}

static void
clone_input_output_stream_close(input_stream* stream)
{
    clone_input_output_stream_data* data = (clone_input_output_stream_data*)stream->data;
    input_stream_close(&data->cloned);
    output_stream_close(&data->copy);
    ZFREE(data, clone_input_output_stream_data);

    input_stream_set_void(stream);
}

static u8 skip[4] = {'S', 'K', 'I', 'P'};

static ya_result
clone_input_output_stream_skip(input_stream* stream, u32 len)
{
    clone_input_output_stream_data* data = (clone_input_output_stream_data*)stream->data;
    
    ya_result return_code;
    
    if(ISOK(return_code = input_stream_skip(&data->cloned, len)))
    {
        int n = return_code;
        while(n > 4)
        {
            output_stream_write(&data->copy, skip, 4);
            n -= 4;
        }
        
        output_stream_write(&data->copy, skip, (u32)n);
    }

    return return_code;
}

static const input_stream_vtbl clone_input_output_stream_vtbl ={
    clone_input_output_stream_read,
    clone_input_output_stream_skip,
    clone_input_output_stream_close,
    "clone_input_output_stream"
};

ya_result
clone_input_output_stream_init(input_stream *cis, input_stream *in_cloned, output_stream *out_stream)
{
    clone_input_output_stream_data* data;

    if((in_cloned->vtbl == NULL) || (out_stream == NULL))
    {
        return OBJECT_NOT_INITIALIZED;
    }

    ZALLOC_OBJECT_OR_DIE( data, clone_input_output_stream_data, CLONE_INPUT_OUTPUT_STREAM_TAG);

    data->cloned.data = in_cloned->data;
    data->cloned.vtbl = in_cloned->vtbl;
    
    data->copy.data = out_stream->data;
    data->copy.vtbl = out_stream->vtbl;


    in_cloned->data = NULL;
    in_cloned->vtbl = NULL;
    
    out_stream->data = NULL;
    out_stream->vtbl = NULL;

    cis->data = data;
    cis->vtbl = &clone_input_output_stream_vtbl;

    return SUCCESS;
}

input_stream *
clone_input_output_stream_get_cloned(input_stream *cis)
{
    clone_input_output_stream_data *data = (clone_input_output_stream_data*)cis->data;
    
    return &data->cloned;
}

output_stream *
clone_input_output_stream_get_copy(input_stream *cis)
{
    clone_input_output_stream_data *data = (clone_input_output_stream_data*)cis->data;
    
    return &data->copy;
}

/** @} */

/*----------------------------------------------------------------------------*/


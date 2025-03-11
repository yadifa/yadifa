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

#include "dnscore/counter_output_stream.h"

static ya_result counter_output_stream_write(output_stream_t *stream, const uint8_t *buffer, uint32_t len)
{
    counter_output_stream_context_t *data = (counter_output_stream_context_t *)stream->data;

    data->write_count += len;

    if(ISOK(data->result))
    {
        data->result = output_stream_write(data->filtered, buffer, len);

        if(ISOK(data->result))
        {
            data->written_count += data->result;
        }
    }

    return data->result;
}

static ya_result counter_output_stream_flush(output_stream_t *stream)
{
    counter_output_stream_context_t *data = (counter_output_stream_context_t *)stream->data;

    if(ISOK(data->result))
    {
        data->result = output_stream_flush(data->filtered);
    }

    return data->result;
}

static void counter_output_stream_close(output_stream_t *stream)
{
    // counter_output_stream_data* data = (counter_output_stream_data*)stream->data;

    output_stream_set_void(stream);
}

static const output_stream_vtbl counter_output_stream_vtbl = {
    counter_output_stream_write,
    counter_output_stream_flush,
    counter_output_stream_close,
    "counter_output_stream",
};

void counter_output_stream_init(output_stream_t *stream, output_stream_t *filtered, counter_output_stream_context_t *counter_data)
{
    yassert(filtered != stream);

    counter_output_stream_context_t *data = counter_data;

    data->filtered = filtered;
    data->write_count = 0;
    data->written_count = 0;
    data->result = SUCCESS;

    stream->data = data;
    stream->vtbl = &counter_output_stream_vtbl;
}

/**
 * Returns the counter context
 *
 * @param os the stream
 */

counter_output_stream_context_t *counter_output_stream_context_get(output_stream_t *os)
{
    if((os != NULL) && (os->vtbl == &counter_output_stream_vtbl))
    {
        return (counter_output_stream_context_t *)os->data;
    }
    else
    {
        return NULL;
    }
}

/**
 * Returns the filtered stream
 *
 * @param os the stream
 */

output_stream_t *counter_output_stream_get_filtered(output_stream_t *os)
{
    if((os != NULL) && (os->vtbl == &counter_output_stream_vtbl))
    {
        return ((counter_output_stream_context_t *)os->data)->filtered;
    }
    else
    {
        return NULL;
    }
}

/** @} */

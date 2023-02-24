/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2023, EURid vzw. All rights reserved.
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
#include "dnscore/checked_output_stream.h"

static void checked_data_update_from_error(checked_output_stream_data_t* data, ya_result ret)
{
    switch(ret)
    {
        case MAKE_ERRNO_ERROR(ENOSPC):
            data->state |= CHECKED_OUTPUT_STREAM_NOSPC;
            break;
        case MAKE_ERRNO_ERROR(EPERM):
            data->state |= CHECKED_OUTPUT_STREAM_PERM;
            break;
        case MAKE_ERRNO_ERROR(EIO):
            data->state |= CHECKED_OUTPUT_STREAM_IO;
            break;
        case MAKE_ERRNO_ERROR(EFBIG):
            data->state |= CHECKED_OUTPUT_STREAM_FBIG;
            break;
        case MAKE_ERRNO_ERROR(EDQUOT):
            data->state |= CHECKED_OUTPUT_STREAM_DQUOT;
            break;
        case MAKE_ERRNO_ERROR(EBADF):
            data->state |= CHECKED_OUTPUT_STREAM_BADF;
            break;
    }
}

static ya_result
checked_write(output_stream* stream, const u8* buffer, u32 len)
{
    checked_output_stream_data_t* data = (checked_output_stream_data_t*)stream->data;
    ya_result ret = output_stream_write(data->filtered, buffer, len);
    if(FAIL(ret))
    {
        checked_data_update_from_error(data, ret);
    }

    return ret;
}

static ya_result
checked_flush(output_stream* stream)
{
    checked_output_stream_data_t* data = (checked_output_stream_data_t*)stream->data;
    ya_result ret = output_stream_flush(data->filtered);
    if(FAIL(ret))
    {
        checked_data_update_from_error(data, ret);
    }
    return ret;
}

static void
checked_close(output_stream* stream)
{
    // checked_output_stream_data_t* data = (checked_output_stream_data_t*)stream->data;
    
    output_stream_set_void(stream);
}

static const output_stream_vtbl checked_output_stream_vtbl ={
    checked_write,
    checked_flush,
    checked_close,
    "checked_output_stream",
};

static int checked_output_stream_errnos[CHECKED_OUTPUT_STREAM_STATES_COUNT] =
{
    MAKE_ERRNO_ERROR(ENOSPC),
    MAKE_ERRNO_ERROR(EPERM),
    MAKE_ERRNO_ERROR(EIO),
    MAKE_ERRNO_ERROR(EFBIG),
    MAKE_ERRNO_ERROR(EDQUOT),
    MAKE_ERRNO_ERROR(EBADF)
};

ya_result
checked_output_stream_error(output_stream* os)
{
    assert(checked_output_stream_instance(os));

    output_stream_flush(os); // else a buffering will make all this checking pointless

    checked_output_stream_data_t* data = (checked_output_stream_data_t*)os->data;

    u32 state = data->state;
    if(state == 0)
    {
        return SUCCESS;
    }
    else
    {
        s32 index = 0;
        while((state & 1) == 0)
        {
            ++index;
            state >>= 1;
        }

        if(index < CHECKED_OUTPUT_STREAM_STATES_COUNT)
        {
            return checked_output_stream_errnos[index];
        }
        else
        {
            return INVALID_STATE_ERROR;
        }
    }
}

void
checked_output_stream_init(output_stream* stream, output_stream* filtered, checked_output_stream_data_t* checked_data)
{
    yassert(filtered != stream);
    
    checked_output_stream_data_t* data = checked_data;

    data->filtered = filtered;
    data->state = 0;

    stream->data = data;
    stream->vtbl = &checked_output_stream_vtbl;
}

bool
checked_output_stream_instance(output_stream *stream)
{
    return (stream != NULL) && (stream->vtbl == &checked_output_stream_vtbl);
}

/** @} */


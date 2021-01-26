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
#include "dnscore/empty-input-stream.h"

#define EIS_CLOSED      2
#define EIS_READONCE    1
#define EIS_CANREADMASK (EIS_CLOSED|EIS_READONCE)
#define EIS_CANREAD     0

struct empty_input_stream_overload
{
    union
    {
        void* _voidp;
        u32 flags;
    } data;

    const input_stream_vtbl *vtbl;
};

typedef struct empty_input_stream_overload empty_input_stream_overload;

static ya_result
empty_input_stream_read(input_stream *stream_, void* buffer, u32 len)
{
    yassert(stream_ != NULL);
    empty_input_stream_overload *eis = (empty_input_stream_overload*)stream_; // mutant stream
    (void)buffer;
    (void)len;
    if((eis->data.flags & EIS_CANREADMASK) == EIS_CANREAD)    // closed read-once
    {
        if(len > 0)
        {
            eis->data.flags |= EIS_READONCE;   // read-once
        }
        return 0;
    }
    else
    {
        return -1;
    }
}

static void
empty_input_stream_close(input_stream *stream_)
{
    yassert(stream_ != NULL);
    empty_input_stream_overload *eis = (empty_input_stream_overload*)stream_; // mutant stream
    eis->data.flags |= EIS_CLOSED;
}

static ya_result
empty_input_stream_skip(input_stream *stream_, u32 len)
{
    yassert(stream_ != NULL);
    empty_input_stream_overload *eis = (empty_input_stream_overload*)stream_; // mutant stream
    if((eis->data.flags & EIS_CANREADMASK) == EIS_CANREAD)    // closed read-once
    {
        if(len > 0)
        {
            eis->data.flags |= EIS_READONCE;   // read-once
        }
        return 0;
    }
    else
    {
        return -1;
    }
}

static const input_stream_vtbl empty_input_stream_vtbl ={
    empty_input_stream_read,
    empty_input_stream_skip,
    empty_input_stream_close,
    "empty_input_stream"
};

void
empty_input_stream_init(input_stream *stream)
{
    stream->data = NULL;
    stream->vtbl = &empty_input_stream_vtbl;
}

/** @} */

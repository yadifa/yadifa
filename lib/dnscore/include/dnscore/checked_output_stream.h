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
#pragma once

#include <dnscore/output_stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define CHECKED_OUTPUT_STREAM_STATES_COUNT 6

#define CHECKED_OUTPUT_STREAM_NOSPC 0x00000001
#define CHECKED_OUTPUT_STREAM_PERM  0x00000002
#define CHECKED_OUTPUT_STREAM_IO    0x00000004
#define CHECKED_OUTPUT_STREAM_FBIG  0x00000008
#define CHECKED_OUTPUT_STREAM_DQUOT 0x00000010
#define CHECKED_OUTPUT_STREAM_BADF  0x00000020

struct checked_output_stream_data_s
{
    output_stream* filtered;
    u32 state;
};

typedef struct checked_output_stream_data_s checked_output_stream_data_t;

void checked_output_stream_init(output_stream* os, output_stream* filtered, checked_output_stream_data_t* checked_data);

bool checked_output_stream_instance(output_stream *stream);

ya_result checked_output_stream_error(output_stream* os);

/**
 * Every single of the kept states are show-breakers.
 */

static inline bool checked_output_stream_failed(output_stream* os)
{
    assert(checked_output_stream_instance(os));
    checked_output_stream_data_t* data = (checked_output_stream_data_t*)os->data;
    return data->state != 0;
}

static inline void checked_output_stream_state_clear(output_stream* os)
{
    assert(checked_output_stream_instance(os));
    checked_output_stream_data_t* data = (checked_output_stream_data_t*)os->data;
    data->state = 0;
}

#ifdef	__cplusplus
}
#endif

/** @} */


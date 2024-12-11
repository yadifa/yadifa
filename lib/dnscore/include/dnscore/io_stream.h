/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @{
 *----------------------------------------------------------------------------*/

#ifndef _IO_STREAM_H
#define _IO_STREAM_H

#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct io_stream_s
{
    input_stream_t  in;
    output_stream_t out;
};

typedef struct io_stream_s io_stream_t;

static inline void         io_stream_link(io_stream_t *ios, input_stream_t *is, output_stream_t *os)
{
    ios->in.data = is->data; // scan-build false-positive (it assumes an error is returned, but still goes through 'ISOK')
    ios->in.vtbl = is->vtbl;

    ios->out.data = os->data;
    ios->out.vtbl = os->vtbl;
}

static inline ya_result io_stream_read(io_stream_t *ios, uint8_t *buffer, uint32_t len) { return ios->in.vtbl->read(&ios->in, buffer, len); }

static inline ya_result io_stream_skip(io_stream_t *ios, uint32_t len) { return ios->in.vtbl->skip(&ios->in, len); }

static inline ya_result io_stream_write(io_stream_t *ios, uint8_t *buffer, uint32_t len) { return ios->out.vtbl->write(&ios->out, buffer, len); }

static inline ya_result io_stream_flush(io_stream_t *ios) { return ios->out.vtbl->flush(&ios->out); }

static inline void      io_stream_close(io_stream_t *ios)
{
    ios->in.vtbl->close(&ios->in);
    ios->out.vtbl->close(&ios->out);
}

#ifdef __cplusplus
}
#endif

#endif /* _IO_STREAM_H */

/** @} */

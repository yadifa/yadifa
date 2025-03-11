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

#include "yatest.h"
#include "yatest_stream.h"

#include <dnscore/dnscore.h>
#include <dnscore/counter_output_stream.h>
#include <dnscore/bytearray_output_stream.h>

static int counter_output_stream_factory(output_stream_t *os, uint32_t *in_out_size)
{
    output_stream_t                 *baos = output_stream_new_instance();
    counter_output_stream_context_t *counter_data = (counter_output_stream_context_t *)malloc(sizeof(counter_output_stream_context_t));
    bytearray_output_stream_init(baos, NULL, *in_out_size);
    counter_output_stream_init(os, baos, counter_data);
    return 0;
}

static int counter_output_stream_close_readback(output_stream_t *os, void **bufferp, size_t *buffer_sizep)
{
    output_stream_flush(os);
    *buffer_sizep = bytearray_output_stream_size(counter_output_stream_get_filtered(os));
    *bufferp = (void *)bytearray_output_stream_detach(counter_output_stream_get_filtered(os));

    counter_output_stream_context_t *context = counter_output_stream_context_get(os);

    if(*buffer_sizep != context->written_count)
    {
        yatest_err("written_count (%i) doesn't match expectations (%i)", context->written_count, *buffer_sizep);
        exit(1);
    }

    output_stream_close(counter_output_stream_get_filtered(os));
    output_stream_close(os);
    return 0;
}

static int write_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(counter_output_stream_factory, counter_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "counter_output_stream");
    return ret;
}

static int features_test()
{
    output_stream_t os;
    uint8_t        *buffer;
    size_t          buffer_size;
    uint32_t        stream_size = 4096;
    dnscore_init();
    counter_output_stream_factory(&os, &stream_size);
    if(counter_output_stream_get_filtered(NULL) != NULL)
    {
        yatest_err("counter_output_stream_get_filtered didn't return NULL for NULL");
        return 1;
    }
    if(counter_output_stream_get_filtered(counter_output_stream_get_filtered(&os)) != NULL)
    {
        yatest_err("counter_output_stream_get_filtered didn't return NULL for not counter");
        return 1;
    }
    if(counter_output_stream_context_get(NULL) != NULL)
    {
        yatest_err("counter_output_stream_context_get didn't return NULL for NULL");
        return 1;
    }
    if(counter_output_stream_context_get(counter_output_stream_get_filtered(&os)) != NULL)
    {
        yatest_err("counter_output_stream_context_get didn't return NULL for not counter");
        return 1;
    }
    counter_output_stream_close_readback(&os, (void **)&buffer, &buffer_size);
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(write_consistency_test)
YATEST(features_test)
YATEST_TABLE_END

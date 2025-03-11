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
#include <dnscore/zalloc.h>
#include <dnscore/bytearray_input_stream.h>

static int bytearray_input_stream_factory(input_stream_t *is, uint32_t *in_out_size)
{
    input_stream_t ris;
    yatest_random_input_stream_init(&ris, *in_out_size);
    char *buffer = (char *)malloc(*in_out_size);
    input_stream_read(&ris, buffer, *in_out_size);
    bytearray_input_stream_init(is, buffer, *in_out_size, true);
    return 0;
}

static int bytearray_input_stream_factoryconst(input_stream_t *is, uint32_t *in_out_size)
{
    *in_out_size = sizeof(yatest_lorem_ipsum);
    bytearray_input_stream_init_const(is, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum));
    return 0;
}

static int bytearray_input_stream_factoryempty(input_stream_t *is, uint32_t *in_out_size)
{
    *in_out_size = 0;
    input_stream_t ris;
    yatest_random_input_stream_init(&ris, *in_out_size);
    char *buffer = (char *)malloc(*in_out_size);
    input_stream_read(&ris, buffer, *in_out_size);
    bytearray_input_stream_init(is, buffer, *in_out_size, true);
    return 0;
}

static int read_consistencyempty_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(bytearray_input_stream_factoryempty, 4096, 1, 4097 + 1, 1, "bytearray_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistencyempty_test failed");
        return ret;
    }
    return 0;
}

static int read_consistencyconst_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(bytearray_input_stream_factoryconst, 4096, 1, 4097 + 1, 1, "bytearray_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistencyconst_test failed");
        return ret;
    }
    return 0;
}

static int read_consistency4096_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(bytearray_input_stream_factory, 4096, 1, 4097 + 1, 1, "bytearray_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistency4096_test failed");
        return ret;
    }
    return 0;
}

static int read_consistency1_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(bytearray_input_stream_factory, 1, 1, 7, 1, "bytearray_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistency1_test failed");
        return ret;
    }
    return 0;
}

static int skip_consistency4096_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_skip_consistency_test(bytearray_input_stream_factory, 4096, 1, 4097 + 1, 1, "bytearray_input_stream");
    if(ret != 0)
    {
        yatest_err("skip_consistency4096_test failed");
        return ret;
    }
    return 0;
}

static int skip_consistency1_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_skip_consistency_test(bytearray_input_stream_factory, 1, 1, 7, 1, "bytearray_input_stream");
    if(ret != 0)
    {
        yatest_err("skip_consistency1_test failed");
        return ret;
    }
    return 0;
}

static int features_test()
{
    int ret;
    dnscore_init();

    input_stream_t ris;
    yatest_random_input_stream_init(&ris, 4096);

    input_stream_t  bis;
    input_stream_t *bis_clone;
    const size_t    buffer_size = 4096;
    uint32_t        bis_size = buffer_size;
    uint8_t         buffer[buffer_size];
    ret = bytearray_input_stream_factory(&bis, &bis_size);
    if((ret != 0) || (bis_size != buffer_size))
    {
        yatest_err("skip_features_test: failed to initialise: %i, %u", ret, bis_size);
        return 1;
    }

    if(!bytearray_input_stream_is_instance_of(&bis))
    {
        yatest_err("skip_features_test: bytearray_input_stream_is_instance_of wrongly said false");
        return 1;
    }

    if(bytearray_input_stream_is_instance_of(&ris))
    {
        yatest_err("skip_features_test: bytearray_input_stream_is_instance_of wrongly said true");
        return 1;
    }

    if(bytearray_input_stream_clone(&ris) != NULL)
    {
        yatest_err("skip_features_test: clone of the wrong stream didn't return NULL");
        return 1;
    }

    bis_clone = bytearray_input_stream_clone(&bis);
    if(bis_clone == NULL)
    {
        yatest_err("skip_features_test: clone returned NULL");
        return 1;
    }

    if(bytearray_input_stream_size(&bis) != buffer_size)
    {
        yatest_err("skip_features_test: buffer size differs from expectations: %u, %u", bytearray_input_stream_size(&bis), buffer_size);
        return 1;
    }

    if(bytearray_input_stream_size(&bis) != bytearray_input_stream_size(bis_clone))
    {
        yatest_err("skip_features_test: clone size differs from original");
        return 1;
    }

    ret = input_stream_read_fully(&bis, buffer, buffer_size / 2);
    if(ret != (int)buffer_size / 2)
    {
        yatest_err("skip_features_test: failed to read: expected %u, got %i (init)", buffer_size / 2, ret);
        return 1;
    }

    if(bytearray_input_stream_remaining(&bis) != buffer_size / 2)
    {
        yatest_err("skip_features_test: expected remaining bytes to be %u, got %i)", buffer_size / 2, bytearray_input_stream_remaining(&bis));
        return 1;
    }

    // try reset

    bytearray_input_stream_reset(&bis);
    ret = input_stream_read_fully(&bis, &buffer[buffer_size / 2], buffer_size / 2);
    if(ret != (int)buffer_size / 2)
    {
        yatest_err("skip_features_test: failed to read: expected %u, got %i (reset)", buffer_size / 2, ret);
        return 1;
    }

    ret = memcmp(buffer, &buffer[buffer_size / 2], buffer_size / 2);
    if(ret != 0)
    {
        yatest_err("skip_features_test: halves of the buffer don't match (reset)");
        return 1;
    }

    // try set offset

    memset(&buffer[buffer_size / 2], 0xff, buffer_size / 2);

    if((ret = bytearray_input_stream_offset(&bis)) != ((int)buffer_size / 2))
    {
        yatest_err("skip_features_test: bytearray_input_stream_offset returned %i instead of %u", ret, buffer_size / 2);
        return 1;
    }

    bytearray_input_stream_set_offset(&bis, 0);

    if((ret = bytearray_input_stream_offset(&bis)) != 0)
    {
        yatest_err("skip_features_test: bytearray_input_stream_offset returned %i instead of zero", ret);
        return 1;
    }

    ret = input_stream_read_fully(&bis, &buffer[buffer_size / 2], buffer_size / 2);
    if(ret != (int)buffer_size / 2)
    {
        yatest_err("skip_features_test: failed to read: expected %u, got %i (offset)", buffer_size / 2, ret);
        return 1;
    }

    ret = memcmp(buffer, &buffer[buffer_size / 2], buffer_size / 2);
    if(ret != 0)
    {
        yatest_err("skip_features_test: halves of the buffer don't match (offset)");
        return 1;
    }

    // try the clone

    const uint8_t *clone_buffer = bytearray_input_stream_buffer(bis_clone);
    uint8_t       *detached_clone_buffer = bytearray_input_stream_detach(bis_clone);

    if(clone_buffer != detached_clone_buffer)
    {
        yatest_err("skip_features_test: buffer and detached buffer differs");
        return 1;
    }

    ret = memcmp(buffer, clone_buffer, buffer_size / 2);
    if(ret != 0)
    {
        yatest_err("skip_features_test: buffer didn't match what was read");
        return 1;
    }

    uint8_t *double_buffer = (uint8_t *)malloc(buffer_size * 2);
    ZEROMEMORY(double_buffer, buffer_size * 2);
    bytearray_input_stream_update(bis_clone, double_buffer, buffer_size * 2, true);
    bytearray_input_stream_set_offset(bis_clone, buffer_size * 2 + 1);
    if(bytearray_input_stream_offset(bis_clone) != buffer_size * 2)
    {
        yatest_err("skip_features_test: bytearray_input_stream_offset outside of bounds didn't properly truncate");
        return 1;
    }

    bytearray_input_stream_update(bis_clone, detached_clone_buffer, buffer_size, true);
    bytearray_input_stream_update(bis_clone, detached_clone_buffer, buffer_size, true);
    if(bytearray_input_stream_offset(bis_clone) != buffer_size)
    {
        yatest_err("skip_features_test: bytearray_input_stream_update outside of bounds didn't properly truncate");
        return 1;
    }
    bytearray_input_stream_reset(bis_clone);

    memset(&buffer[buffer_size / 2], 0xff, buffer_size / 2);

    ret = input_stream_read_fully(bis_clone, &buffer[buffer_size / 2], buffer_size / 2);
    if(ret != (int)buffer_size / 2)
    {
        yatest_err("skip_features_test: failed to read: expected %u, got %i (clone)", buffer_size / 2, ret);
        return 1;
    }

    ret = memcmp(buffer, &buffer[buffer_size / 2], buffer_size / 2);
    if(ret != 0)
    {
        yatest_err("skip_features_test: halves of the buffer don't match (clone)");
        return 1;
    }

    input_stream_close(bis_clone);
    ZFREE_OBJECT(bis_clone);
    input_stream_close(&bis);

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(read_consistencyempty_test)
YATEST(read_consistencyconst_test)
YATEST(read_consistency4096_test)
YATEST(read_consistency1_test)
YATEST(skip_consistency4096_test)
YATEST(skip_consistency1_test)
YATEST(features_test)
YATEST_TABLE_END

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
#include <dnscore/bytezarray_output_stream.h>
#include <dnscore/zalloc.h>

static int bytezarray_output_stream_static_factory(output_stream_t *os, uint32_t *in_out_size)
{
    bytezarray_output_stream_init(os, NULL, *in_out_size);
    return 0;
}

static int bytezarray_output_stream_dynamic_factory(output_stream_t *os, uint32_t *in_out_size)
{
    bytezarray_output_stream_init_ex(os, NULL, *in_out_size, BYTEARRAY_DYNAMIC);
    return 0;
}

static int bytezarray_output_stream_dynamic_grows_factory(output_stream_t *os, uint32_t *in_out_size)
{
    (void)in_out_size;
    bytezarray_output_stream_init_ex(os, NULL, 0, BYTEARRAY_DYNAMIC);
    return 0;
}

static int bytezarray_output_stream_dynamic_ensure_factory(output_stream_t *os, uint32_t *in_out_size)
{
    bytezarray_output_stream_init_ex(os, NULL, 1, BYTEARRAY_DYNAMIC);
    bytezarray_output_stream_ensure(os, *in_out_size);
    return 0;
}

static int bytezarray_output_stream_close_readback(output_stream_t *os, void **bufferp, size_t *buffer_sizep)
{
    *buffer_sizep = bytezarray_output_stream_size(os);
    void *buffer = (void *)malloc(*buffer_sizep);
    memcpy(buffer, bytezarray_output_stream_buffer(os), *buffer_sizep);
    *bufferp = buffer;
    output_stream_close(os);
    return 0;
}

static int write_static_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(bytezarray_output_stream_static_factory, bytezarray_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "bytezarray_output_stream");
    return ret;
}

static int write_dynamic_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(bytezarray_output_stream_dynamic_factory, bytezarray_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "bytezarray_output_stream");
    return ret;
}

static int write_dynamic_grows_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(bytezarray_output_stream_dynamic_grows_factory, bytezarray_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "bytezarray_output_stream");
    return ret;
}

static int write_dynamic_grows_threshold_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(bytezarray_output_stream_dynamic_grows_factory, bytezarray_output_stream_close_readback, 0x200000, 65536, 0x100001 + 1, 65536, "bytezarray_output_stream");
    return ret;
}

static int write_dynamic_ensure_consistency_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(bytezarray_output_stream_dynamic_ensure_factory, bytezarray_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "bytezarray_output_stream");
    return ret;
}

static int features()
{
    int             ret;
    uint32_t        size = 4096;
    input_stream_t  ris;
    output_stream_t os;
    uint8_t         dummy[4] = {1, 2, 3, 4};
    dnscore_init();
    yatest_random_input_stream_init(&ris, size);
    bytezarray_output_stream_dynamic_factory(&os, &size);
    for(int i = 0; i < 4096; ++i)
    {
        uint8_t b;
        input_stream_read_u8(&ris, &b);
        output_stream_write_u8(&os, b);
    }

    uint8_t *original_buffer = bytezarray_output_stream_detach(&os);
    output_stream_close(&os);
    bytezarray_output_stream_dynamic_factory(&os, &size);
    bytezarray_output_stream_set(&os, original_buffer, size, true);
    bytezarray_output_stream_setposition(&os, size);
    if((ret = bytezarray_output_stream_rewind(&os, 1)) != 1)
    {
        yatest_err("bytezarray_output_stream_rewind didn't return 1 (%i)", ret);
        return 1;
    }

    ret = output_stream_write_u8(&os, size - 1);
    if(FAIL(ret))
    {
        yatest_err("output_stream_write_u8 failed to write the last byte");
        return 1;
    }

    for(int32_t i = (int32_t)size - 2; i >= 0; --i)
    {
        if((ret = bytezarray_output_stream_rewind(&os, 2)) != 2)
        {
            yatest_err("bytezarray_output_stream_rewind didn't return 2 (%i)", ret);
            return 1;
        }
        ret = output_stream_write_u8(&os, i);
        if(FAIL(ret))
        {
            yatest_err("output_stream_write_u8 failed to write byte at position %i", i);
            return 1;
        }
    }
    for(uint32_t i = 0; i < size; ++i)
    {
        if(bytezarray_output_stream_buffer(&os)[i] != (uint8_t)i)
        {
            yatest_err("byte at position %i (%02x) differs from expectations (%02x)", i, bytezarray_output_stream_buffer(&os)[i], (uint8_t)i);
            return 1;
        }
    }

    uint32_t end_position = bytezarray_output_stream_setposition(&os, size);

    if(end_position != size)
    {
        yatest_err("bytezarray_output_stream_setposition at size didn't extend the buffer");
        return 1;
    }

    uint8_t *mbuffer = bytezarray_output_stream_dup(&os);
    uint8_t *zbuffer = bytezarray_output_stream_zdup(&os);

    if(memcmp(mbuffer, bytezarray_output_stream_buffer(&os), size) != 0)
    {
        yatest_err("mbuffer & stream buffer differs");
        return 1;
    }

    if(memcmp(mbuffer, zbuffer, size) != 0)
    {
        yatest_err("mbuffer & zbuffer differs");
        return 1;
    }

    free(mbuffer);
    ZFREE(zbuffer, size);

    output_stream_close(&os);

    bytezarray_output_stream_dynamic_factory(&os, &size);

    uint32_t new_position = bytezarray_output_stream_setposition(&os, size * 2);

    if(new_position != size * 2)
    {
        yatest_err("bytezarray_output_stream_setposition at size*2 didn't extend the dynamic buffer");
        return 1;
    }

    output_stream_close(&os);

    bytezarray_output_stream_static_factory(&os, &size);

    new_position = bytezarray_output_stream_setposition(&os, size * 2);

    if(new_position != size)
    {
        yatest_err("bytezarray_output_stream_setposition at size*2 should not have extended the static buffer");
        return 1;
    }

    ret = bytezarray_output_stream_ensure(&os, size * 4);
    if(ISOK(ret))
    {
        yatest_err("bytezarray_output_stream_ensure at size*4 should not have extended the static buffer");
        return 1;
    }

    new_position = bytezarray_output_stream_setposition(&os, size - 1);

    ret = output_stream_write(&os, dummy, sizeof(dummy));

    if(ret != 1)
    {
        yatest_err(
            "output_stream_write of %i bytes at one byte from the end of the static buffer should only have written 1 "
            "byte (%i)",
            sizeof(dummy),
            ret);
        return 1;
    }

    uint32_t current_position = bytezarray_output_stream_buffer_offset(&os);
    if(current_position != size)
    {
        yatest_err("bytezarray_output_stream_buffer_offset returned %u instead of %u", current_position, size);
        return 1;
    }

    uint32_t current_size = bytezarray_output_stream_buffer_size(&os);
    if(current_size < size)
    {
        yatest_err("bytezarray_output_stream_buffer_size returned %u which is < %u", current_size, size);
        return 1;
    }

    bytezarray_output_stream_reset(&os);
    current_position = bytezarray_output_stream_buffer_offset(&os);
    if(current_position != 0)
    {
        yatest_err("bytezarray_output_stream_buffer_offset returned %u instead of %u (after reset)", current_position, 0);
        return 1;
    }

    output_stream_close(&os);

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(write_static_consistency_test)
YATEST(write_dynamic_consistency_test)
YATEST(write_dynamic_grows_consistency_test)
YATEST(write_dynamic_grows_threshold_consistency_test)
YATEST(write_dynamic_ensure_consistency_test)
YATEST(features)
YATEST_TABLE_END

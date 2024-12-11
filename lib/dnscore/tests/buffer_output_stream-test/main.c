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

#include "yatest.h"
#include "yatest_stream.h"

#include <dnscore/dnscore.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/zalloc.h>

static int buffer_output_stream_factory_size(output_stream_t *os, uint32_t *in_out_size, int buffer_size)
{
    int             ret;
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, *in_out_size);
    ret = buffer_output_stream_init(os, &baos, buffer_size);

    if(FAIL(ret))
    {
        yatest_err("buffer_output_stream_init %i failed with %s", buffer_size, error_gettext(ret));
        exit(1);
    }

    if(!is_buffer_output_stream(os))
    {
        yatest_err("is_buffer_output_stream returned false");
        exit(1);
    }
    if(is_buffer_output_stream(&baos))
    {
        yatest_err("is_buffer_output_stream returned true");
        exit(1);
    }
    return 0;
}

static int buffer_output_stream_factoryfull(output_stream_t *os, uint32_t *in_out_size) { return buffer_output_stream_factory_size(os, in_out_size, *in_out_size); }

static int buffer_output_stream_factory32(output_stream_t *os, uint32_t *in_out_size) { return buffer_output_stream_factory_size(os, in_out_size, 32); }

static int buffer_output_stream_factory7(output_stream_t *os, uint32_t *in_out_size) { return buffer_output_stream_factory_size(os, in_out_size, 7); }

static int buffer_output_stream_factory1(output_stream_t *os, uint32_t *in_out_size) { return buffer_output_stream_factory_size(os, in_out_size, 1); }

static int buffer_output_stream_factory0(output_stream_t *os, uint32_t *in_out_size) { return buffer_output_stream_factory_size(os, in_out_size, 0); }

static int buffer_output_stream_close_readback(output_stream_t *os, void **bufferp, size_t *buffer_sizep)
{
    output_stream_flush(os);
    *buffer_sizep = bytearray_output_stream_size(buffer_output_stream_get_filtered(os));
    *bufferp = (void *)bytearray_output_stream_detach(buffer_output_stream_get_filtered(os));
    output_stream_close(os);
    return 0;
}

static int write_consistencyfull_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(buffer_output_stream_factoryfull, buffer_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "buffer_output_stream");
    return ret;
}

static int write_consistency32_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(buffer_output_stream_factory32, buffer_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "buffer_output_stream");
    return ret;
}

static int write_consistency7_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(buffer_output_stream_factory7, buffer_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "buffer_output_stream");
    return ret;
}

static int write_consistency1_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(buffer_output_stream_factory1, buffer_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "buffer_output_stream");
    return ret;
}

static int write_consistency0_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(buffer_output_stream_factory0, buffer_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "buffer_output_stream");
    return ret;
}

static int features()
{
    int ret;
    int buffer_size = 4;
    dnscore_init();
    output_stream_t baos;
    output_stream_t os;
    /*
        ret = buffer_output_stream_init(&os, NULL, buffer_size);

        if(ret != OBJECT_NOT_INITIALIZED)
        {
            yatest_err("buffer_output_stream_init didn't return OBJECT_NOT_INITIALIZED (%s instead)",
       error_gettext(ret)); exit(1);
        }
    */
    bytearray_output_stream_init(&baos, NULL, 15);
    ret = buffer_output_stream_init(&os, &baos, buffer_size);

    if(FAIL(ret))
    {
        yatest_err("buffer_output_stream_init %i failed with %s", buffer_size, error_gettext(ret));
        return 1;
    }

    char *buffer = (char *)malloc(buffer_size);
    memset(buffer, 0, buffer_size);

    int total = 0;

    while(true)
    {
        ret = output_stream_write(&os, buffer, buffer_size);
        if(FAIL(ret))
        {
            yatest_err("output_stream_write %i failed with %s", buffer_size, error_gettext(ret));
            return 1;
        }
        total += ret;
        output_stream_flush(&os);
        if(ret < buffer_size)
        {
            break;
        }
    }

    int baos_size = bytearray_output_stream_size(buffer_output_stream_get_filtered(&os));

    if(total != baos_size)
    {
        yatest_err("output_stream_write didn't write all the bytes: %i != %i", buffer_size, error_gettext(ret), total, baos_size);
        return 1;
    }

    return 0;
}

static int error_passthrough()
{
    int ret;
    int buffer_size = 4;
    int error_code = MAKE_ERRNO_ERROR(EPERM);
    dnscore_init();
    output_stream_t eos;
    output_stream_t os;

    yatest_error_output_stream_init(&eos, buffer_size + 1, error_code);
    ret = buffer_output_stream_init(&os, &eos, buffer_size);

    char *buffer = (char *)malloc(buffer_size);
    memset(buffer, 0, buffer_size);

    ret = output_stream_write(&os, buffer, buffer_size);
    if(ret != buffer_size)
    {
        yatest_err("output_stream_write %i didn't write everything (%i)", buffer_size, ret);
        return 1;
    }

    ret = output_stream_write(&os, buffer, buffer_size);
    if(ret != 1)
    {
        yatest_err("output_stream_write %i didn't write everything (%i)", buffer_size, ret);
        return 1;
    }

    ret = output_stream_write(&os, buffer, buffer_size);
    if(ret != error_code)
    {
        yatest_err("output_stream_write %i didn't return an error", buffer_size, ret);
        return 1;
    }

    return 0;
}

static int error_delayed()
{
    int ret;
    int buffer_size = 4;
    int error_code = MAKE_ERRNO_ERROR(EPERM);
    dnscore_init();
    output_stream_t eos;
    output_stream_t os;

    yatest_error_output_stream_init(&eos, buffer_size + 1, error_code);
    ret = buffer_output_stream_init(&os, &eos, buffer_size);

    char *buffer = (char *)malloc(buffer_size);
    memset(buffer, 0, buffer_size);

    for(int i = 0; i <= buffer_size + 1; ++i)
    {
        ret = output_stream_write(&os, &buffer[i], 1);
        if(ret != 1)
        {
            yatest_err("output_stream_write %i didn't write everything (%i)", 1, ret);
            return 1;
        }
    }

    ret = output_stream_flush(&os);
    if(ret != error_code)
    {
        yatest_err("output_stream_write %i didn't return an error", buffer_size, ret);
        return 1;
    }

    return 0;
}

static int write_pattern_0()
{
    int ret;
    int buffer_size = 4;
    dnscore_init();
    output_stream_t baos;
    output_stream_t os;

    bytearray_output_stream_init(&baos, NULL, buffer_size);
    buffer_output_stream_init(&os, &baos, buffer_size);

    char *buffer = (char *)malloc(buffer_size * 2);
    memset(buffer, 0, buffer_size * 2);

    // make the buffer not empty

    ret = output_stream_write(&os, buffer, buffer_size - 1);
    if(ret != buffer_size - 1)
    {
        yatest_err("output_stream_write %i didn't write everything (%i)", buffer_size - 1, ret);
        return 1;
    }

    ret = output_stream_write(&os, buffer, buffer_size * 2);
    if(ret != 1)
    {
        yatest_err("output_stream_write %i didn't write everything (%i)", 1, ret);
        return 1;
    }

    output_stream_close(&os);

    return 0;
}

static int write_pattern_1()
{
    int ret;
    int buffer_size = 4;
    dnscore_init();
    output_stream_t baos;
    output_stream_t os;

    bytearray_output_stream_init(&baos, NULL, buffer_size * 3);
    buffer_output_stream_init(&os, &baos, buffer_size);

    char *buffer = (char *)malloc(buffer_size * 2);
    memset(buffer, 0, buffer_size * 2);

    // make the buffer not empty

    ret = output_stream_write(&os, buffer, buffer_size - 1);
    if(ret != buffer_size - 1)
    {
        yatest_err("output_stream_write %i didn't write everything (%i)", buffer_size - 1, ret);
        return 1;
    }

    // write size must be bigger than remaining space in buffer ( > 1) but also smaller than the buffer (buffer_size -
    // 1) the buffer will be filled (1) then writen then the remaining (n - 1) need to be bigger than the buffer size

    ret = output_stream_write(&os, buffer, buffer_size - 1);
    if(ret != buffer_size - 1)
    {
        yatest_err("output_stream_write %i didn't write everything (%i)", buffer_size - 1, ret);
        return 1;
    }

    output_stream_close(&os);

    return 0;
}

static int write_pattern_1e()
{
    int ret;
    int buffer_size = 4;
    dnscore_init();
    output_stream_t eos;
    output_stream_t os;

    yatest_error_output_stream_init(&eos, 0, ERROR);
    buffer_output_stream_init(&os, &eos, buffer_size);

    char *buffer = (char *)malloc(buffer_size * 2);
    memset(buffer, 0, buffer_size * 2);

    // make the buffer not empty

    ret = output_stream_write(&os, buffer, buffer_size - 1);
    if(ret != buffer_size - 1)
    {
        yatest_err("output_stream_write %i didn't write everything (%i)", buffer_size - 1, ret);
        return 1;
    }

    // write size must be bigger than remaining space in buffer ( > 1) but also smaller than the buffer (buffer_size -
    // 1) the buffer will be filled (1) then writen then the remaining (n - 1) need to be bigger than the buffer size

    ret = output_stream_write(&os, buffer, buffer_size - 1);
    if(ret != 1) // 1 because that's the last byte that entered the buffer before the undelying stream returned an error
    {
        yatest_err("output_stream_write %i didn't write everything (%i)", buffer_size - 1, ret);
        return 1;
    }

    output_stream_close(&os);

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(write_consistencyfull_test)
YATEST(write_consistency32_test)
YATEST(write_consistency7_test)
YATEST(write_consistency1_test)
YATEST(write_consistency0_test)
YATEST(features)
YATEST(error_passthrough)
YATEST(error_delayed)
YATEST(write_pattern_0)
YATEST(write_pattern_1)
YATEST(write_pattern_1e)
YATEST_TABLE_END

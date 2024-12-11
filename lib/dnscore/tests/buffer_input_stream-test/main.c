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
#include <dnscore/buffer_input_stream.h>
#include <dnscore/bytearray_output_stream.h>

static int buffer_input_stream_factory0(input_stream_t *is, uint32_t *in_out_size)
{
    input_stream_t ris;
    yatest_random_input_stream_init(&ris, *in_out_size);
    buffer_input_stream_init(is, &ris, 0);
    return 0;
}

static int buffer_input_stream_factoryempty(input_stream_t *is, uint32_t *in_out_size)
{
    input_stream_t ris;
    *in_out_size = 0;
    yatest_random_input_stream_init(&ris, 0);
    buffer_input_stream_init(is, &ris, 0);
    return 0;
}

static int buffer_input_stream_factory4096(input_stream_t *is, uint32_t *in_out_size)
{
    input_stream_t ris;
    yatest_random_input_stream_init(&ris, *in_out_size);
    buffer_input_stream_init(is, &ris, 4096);
    return 0;
}

static int buffer_input_stream_factory1(input_stream_t *is, uint32_t *in_out_size)
{
    input_stream_t ris;
    yatest_random_input_stream_init(&ris, *in_out_size);
    buffer_input_stream_init(is, &ris, 1);
    return 0;
}

static int read_consistencydefault_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(buffer_input_stream_factory0, BUFFER_INPUT_STREAM_DEFAULT_BUFFER_SIZE * 3 + 97, 1, BUFFER_INPUT_STREAM_DEFAULT_BUFFER_SIZE + 1, 1, "buffer_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistencydefault_test failed");
        return ret;
    }
    return 0;
}

static int read_consistencyempty_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(buffer_input_stream_factoryempty, BUFFER_INPUT_STREAM_DEFAULT_BUFFER_SIZE * 3 + 97, 1, BUFFER_INPUT_STREAM_DEFAULT_BUFFER_SIZE + 1, 1, "buffer_input_stream");
    if(ret != 0)
    {
        yatest_err("read_consistencyempty_test failed");
        return ret;
    }
    return 0;
}

static int read_consistency4096_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(buffer_input_stream_factory4096, 4097 * 3 + 97, 1, 4097, 1, "buffer_input_stream");
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

    ret = yatest_input_stream_read_consistency_test(buffer_input_stream_factory1, 1 * 3 + 97, 1, 7, 1, "buffer_input_stream");
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

    ret = yatest_input_stream_skip_consistency_test(buffer_input_stream_factory4096, 4097 * 3 + 97, 1, 4097, 1, "buffer_input_stream");
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

    ret = yatest_input_stream_skip_consistency_test(buffer_input_stream_factory1, 1 * 3 + 97, 1, 7, 1, "buffer_input_stream");
    if(ret != 0)
    {
        yatest_err("skip_consistency1_test failed");
        return ret;
    }
    return 0;
}

static int read_line4096_test()
{
    int ret;
    dnscore_init();

    input_stream_t  liis;
    input_stream_t  bis;
    output_stream_t baos;
    char            line[4096];
    yatest_loremipsum_input_stream_init(&liis);
    buffer_input_stream_init(&bis, &liis, 4096);
    bytearray_output_stream_init(&baos, NULL, 0);

    ret = buffer_input_stream_read_line(&bis, line, 0);

    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("read_line4096_test: expected a BUFFER_WOULD_OVERFLOW error");
        return 1;
    }

    if(!is_buffer_input_stream(&bis))
    {
        yatest_err("read_line4096_test: is_buffer_input_stream didn't recognise the stream");
        return 1;
    }

    if(is_buffer_input_stream(&liis))
    {
        yatest_err("read_line4096_test: is_buffer_input_stream wrongly recognised the stream");
        return 1;
    }

    for(;;)
    {
        ret = buffer_input_stream_read_line(&bis, line, sizeof(line));
        if(ret <= 0)
        {
            if(ret < 0)
            {
                yatest_err("read_line4096_test: failed reading a line: %x", ret);
                return 1;
            }
            break;
        }

        if(line[ret - 1] != '\n')
        {
            yatest_err("read_line4096_test: expected the last character to be an LF: got a chr(%i) instead", line[ret - 1]);
            return 1;
        }

        if(ret < 2)
        {
            yatest_err("read_line4096_test: expected to read at least 2 characters but got only %i", ret);
            return 1;
        }

        if(line[ret - 2] != '.')
        {
            yatest_err("read_line4096_test: expected the penultimate character to be an '.': got a chr(%i) instead", line[ret - 2]);
            return 1;
        }

        output_stream_write(&baos, line, ret);
    }

    output_stream_write_u8(&baos, 0); // adds a NUL terminator

    if(strcmp((char *)bytearray_output_stream_buffer(&baos), yatest_lorem_ipsum) != 0)
    {
        yatest_err("read_line4096_test: reconstituted text didn't match the original");
        return 1;
    }

    return 0;
}

static int read_line1_test()
{
    int ret;
    dnscore_init();

    input_stream_t  liis;
    input_stream_t  liis_copy;
    input_stream_t  bis;
    output_stream_t baos;
    char            line[4096];
    yatest_loremipsum_input_stream_init(&liis);
    liis_copy = liis;
    buffer_input_stream_init(&bis, &liis, 1); // destroys the values in liis, hence the copy

    ret = buffer_input_stream_read_line(&bis, line, 0);

    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("read_line1_test: expected a BUFFER_WOULD_OVERFLOW error");
        return 1;
    }

    if(!is_buffer_input_stream(&bis))
    {
        yatest_err("read_line1_test: is_buffer_input_stream didn't recognise the stream");
        return 1;
    }

    if(is_buffer_input_stream(&liis))
    {
        yatest_err("read_line1_test: is_buffer_input_stream wrongly recognised the stream");
        return 1;
    }

    input_stream_t *fis = buffer_input_stream_get_filtered(&bis);

    if((fis->data != liis_copy.data) || (fis->vtbl != liis_copy.vtbl))
    {
        yatest_err("read_line1_test: buffer_input_stream_get_filtered returned an unexpected value");
        return 1;
    }

    bytearray_output_stream_init(&baos, NULL, 0);

    for(;;)
    {
        ret = buffer_input_stream_read_line(&bis, line, sizeof(line));
        if(ret <= 0)
        {
            if(ret < 0)
            {
                yatest_err("read_line1_test: failed reading a line: %x", ret);
                return 1;
            }
            break;
        }

        if(line[ret - 1] != '\n')
        {
            yatest_err("read_line1_test: expected the last character to be an LF: got a chr(%i) instead", line[ret - 1]);
            return 1;
        }

        if(ret < 2)
        {
            yatest_err("read_line1_test: expected to read at least 2 characters but got only %i", ret);
            return 1;
        }

        if(line[ret - 2] != '.')
        {
            yatest_err("read_line1_test: expected the penultimate character to be an '.': got a chr(%i) instead", line[ret - 2]);
            return 1;
        }

        output_stream_write(&baos, line, ret);
    }

    output_stream_write_u8(&baos, 0); // adds a NUL terminator

    if(strcmp((char *)bytearray_output_stream_buffer(&baos), yatest_lorem_ipsum) != 0)
    {
        yatest_err("read_line1_test: reconstituted text didn't match the original");
        return 1;
    }

    return 0;
}

static int read_rewind_test()
{
    dnscore_init();

    input_stream_t liis;
    input_stream_t bis;
    char           line0[4096];
    char           line1[4096];
    yatest_loremipsum_input_stream_init(&liis);
    buffer_input_stream_init(&bis, &liis, 4096);
    int ret0 = buffer_input_stream_read_line(&bis, line0, sizeof(line0));
    int max_rewind = buffer_input_stream_rewind(&bis, UINT32_MAX);
    if(ret0 != max_rewind)
    {
        yatest_err("read_rewind_test: expected max rewind (%i) to be equal to first read (%i)", max_rewind, ret0);
        return 1;
    }
    int max_rewind2 = buffer_input_stream_rewind(&bis, max_rewind);
    if(max_rewind2 != max_rewind)
    {
        yatest_err("read_rewind_test: expected max rewind (%i) to be equal to anounced max rewind (%i)", max_rewind2, max_rewind);
        return 1;
    }
    int ret1 = buffer_input_stream_read_line(&bis, line1, sizeof(line1));
    if(max_rewind2 != max_rewind)
    {
        yatest_err("read_rewind_test: expected second line size (%i) to be the same one as the first line size (%i)", ret1, ret0);
        return 1;
    }
    if(memcmp(line0, line1, ret0) != 0)
    {
        yatest_err("read_rewind_test: expected both lines to be identical");
        return 1;
    }
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(read_consistencydefault_test)
YATEST(read_consistencyempty_test)
YATEST(read_consistency4096_test)
YATEST(read_consistency1_test)
YATEST(skip_consistency4096_test)
YATEST(skip_consistency1_test)
YATEST(read_line4096_test)
YATEST(read_line1_test)
YATEST(read_rewind_test)
YATEST_TABLE_END

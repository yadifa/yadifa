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
#include <dnscore/limited_input_stream.h>
#include <dnscore/bytearray_output_stream.h>

static int limited_input_stream_factory0(input_stream_t *is, uint32_t *in_out_size)
{
    *in_out_size = 0;
    input_stream_t ris;
    yatest_random_input_stream_init(&ris, *in_out_size * 2);
    limited_input_stream_init(is, &ris, *in_out_size);
    return 0;
}

static int limited_input_stream_factoryempty(input_stream_t *is, uint32_t *in_out_size)
{
    input_stream_t ris;
    *in_out_size = 0;
    yatest_random_input_stream_init(&ris, 4096);
    limited_input_stream_init(is, &ris, *in_out_size);
    return 0;
}

static int limited_input_stream_factory4096(input_stream_t *is, uint32_t *in_out_size)
{
    input_stream_t ris;
    yatest_random_input_stream_init(&ris, *in_out_size * 2);
    limited_input_stream_init(is, &ris, *in_out_size);
    return 0;
}

static int limited_input_stream_factory1(input_stream_t *is, uint32_t *in_out_size)
{
    input_stream_t ris;
    yatest_random_input_stream_init(&ris, *in_out_size * 2);
    limited_input_stream_init(is, &ris, *in_out_size);
    return 0;
}

static int read_consistencydefault_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(limited_input_stream_factory0, 4096 * 3 + 97, 1, 4096 + 1, 1, "limited_input_stream");
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

    ret = yatest_input_stream_read_consistency_test(limited_input_stream_factoryempty, 4096 * 3 + 97, 1, 4096 + 1, 1, "limited_input_stream");
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

    ret = yatest_input_stream_read_consistency_test(limited_input_stream_factory4096, 4097 * 3 + 97, 1, 4097, 1, "limited_input_stream");
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

    ret = yatest_input_stream_read_consistency_test(limited_input_stream_factory1, 1 * 3 + 97, 1, 7, 1, "limited_input_stream");
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

    ret = yatest_input_stream_skip_consistency_test(limited_input_stream_factory4096, 4097 * 3 + 97, 1, 4097, 1, "limited_input_stream");
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

    ret = yatest_input_stream_skip_consistency_test(limited_input_stream_factory1, 1 * 3 + 97, 1, 7, 1, "limited_input_stream");
    if(ret != 0)
    {
        yatest_err("skip_consistency1_test failed");
        return ret;
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
YATEST_TABLE_END

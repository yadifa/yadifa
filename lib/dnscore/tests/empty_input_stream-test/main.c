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

#include <dnscore/dnscore.h>
#include <dnscore/empty_input_stream.h>

static int read_simple_test()
{
    int            ret;
    input_stream_t is;
    char           dummy[8];
    dnscore_init();

    empty_input_stream_init(&is);
    ret = input_stream_read(&is, dummy, sizeof(dummy));
    if(ret != 0)
    {
        yatest_err("read_simple_test expected 0, got %i", ret);
        return 1;
    }
    ret = input_stream_read(&is, dummy, sizeof(dummy));
    if(ret >= 0)
    {
        yatest_err("read_simple_test expected <0, got %i", ret);
        return 1;
    }
    input_stream_close(&is);
    return 0;
}

static int skip_simple_test()
{
    int            ret;
    input_stream_t is;
    char           dummy[8];
    dnscore_init();

    empty_input_stream_init(&is);
    ret = input_stream_skip(&is, sizeof(dummy));
    if(ret != 0)
    {
        yatest_err("read_simple_test expected 0, got %i", ret);
        return 1;
    }
    ret = input_stream_skip(&is, sizeof(dummy));
    if(ret >= 0)
    {
        yatest_err("read_simple_test expected <0, got %i", ret);
        return 1;
    }
    input_stream_close(&is);
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(read_simple_test)
YATEST(skip_simple_test)
YATEST_TABLE_END

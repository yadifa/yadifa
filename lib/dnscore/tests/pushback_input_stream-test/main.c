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
#include <dnscore/pushback_input_stream.h>
#include <dnscore/bytearray_input_stream.h>

static input_stream_t bais;
static input_stream_t pbis;

static const char     hello_world[] = "Hello World!";

static const size_t   buffer_size = 65536;
static char          *buffer = NULL;

static void           init(int pbs)
{
    dnscore_init();
    bytearray_input_stream_init_const(&bais, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum));
    pushback_input_stream_init(&pbis, &bais, pbs);
    buffer = (char *)yatest_malloc(buffer_size);
}

static void finalise()
{
    dnscore_finalize();
    input_stream_close(&pbis);
}

static int pushback_test()
{
    int ret;
    init(sizeof(hello_world) - 1);

    for(int i = sizeof(hello_world) - 2; i >= 0; --i)
    {
        if(!pushback_input_stream_push_back(&pbis, hello_world[i]))
        {
            yatest_err("pushback_input_stream_push_back rejected char %i", i);
            return 1;
        }
    }

    if(pushback_input_stream_push_back(&pbis, 'x'))
    {
        yatest_err("pushback_input_stream_push_back accepted oveflowing char");
        return 1;
    }

    ret = input_stream_read(&pbis, buffer, sizeof(hello_world) - 1);
    if(ret != sizeof(hello_world) - 1)
    {
        yatest_err("input_stream_read should have returned %i, returned %i instead", sizeof(hello_world) - 1, ret);
        return 1;
    }

    if(memcmp(buffer, hello_world, sizeof(hello_world) - 1) != 0)
    {
        yatest_err("got:");
        yatest_hexdump_err(buffer, buffer + sizeof(hello_world) - 1);
        yatest_err("expected:");
        yatest_hexdump_err(hello_world, hello_world + sizeof(hello_world) - 1);
        return 1;
    }

    for(int i = sizeof(hello_world) - 2; i >= 0; --i)
    {
        if(!pushback_input_stream_push_back(&pbis, hello_world[i]))
        {
            yatest_err("pushback_input_stream_push_back rejected char %i", i);
            return 1;
        }
    }

    if(pushback_input_stream_push_back(&pbis, 'x'))
    {
        yatest_err("pushback_input_stream_push_back accepted oveflowing char");
        return 1;
    }

    ret = input_stream_read(&pbis, buffer, sizeof(yatest_lorem_ipsum) + sizeof(hello_world) - 2);

    if(memcmp(buffer, hello_world, sizeof(hello_world) - 1) != 0)
    {
        yatest_err("got:");
        yatest_hexdump_err(buffer, buffer + sizeof(hello_world) - 1);
        yatest_err("expected:");
        yatest_hexdump_err(hello_world, hello_world + sizeof(hello_world) - 1);
        return 1;
    }

    if(memcmp(buffer + sizeof(hello_world) - 1, yatest_lorem_ipsum, sizeof(yatest_lorem_ipsum) - 1) != 0)
    {
        yatest_err("got:");
        yatest_hexdump_err(buffer + sizeof(hello_world), buffer + sizeof(hello_world) + sizeof(yatest_lorem_ipsum) - 1);
        yatest_err("expected:");
        yatest_hexdump_err(yatest_lorem_ipsum, yatest_lorem_ipsum + sizeof(yatest_lorem_ipsum) - 1);
        return 1;
    }

    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(pushback_test)
YATEST_TABLE_END

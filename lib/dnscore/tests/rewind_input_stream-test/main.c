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
#include <dnscore/rewind_input_stream.h>

#define REWIND_BUFFER_SIZE 16

static int rewind_input_stream_factory4096(input_stream_t *is, uint32_t *in_out_size)
{
    input_stream_t ris;
    yatest_random_input_stream_init(&ris, *in_out_size);
    rewind_input_stream_init(is, &ris, 4096);
    return 0;
}

static int read_consistency4096_test()
{
    int ret;
    dnscore_init();

    ret = yatest_input_stream_read_consistency_test(rewind_input_stream_factory4096, 4097 * 3 + 97, 1, 4097, 1, "rewind_input_stream");
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

    ret = yatest_input_stream_read_consistency_test(rewind_input_stream_factory4096, 1 * 3 + 97, 1, 7, 1, "rewind_input_stream");
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

    ret = yatest_input_stream_skip_consistency_test(rewind_input_stream_factory4096, 4097 * 3 + 97, 1, 4097, 1, "rewind_input_stream");
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

    ret = yatest_input_stream_skip_consistency_test(rewind_input_stream_factory4096, 1 * 3 + 97, 1, 7, 1, "rewind_input_stream");
    if(ret != 0)
    {
        yatest_err("skip_consistency1_test failed");
        return ret;
    }
    return 0;
}

static int rewind_test()
{
    int ret;
    dnscore_init();

    input_stream_t ris;
    input_stream_t ris_copy;
    input_stream_t is;
    char           model[65536];
    char           buffer[REWIND_BUFFER_SIZE];
    char           buffer2[REWIND_BUFFER_SIZE];

    yatest_random_input_stream_init(&ris, INT32_MAX);
    ris_copy = ris;
    input_stream_read(&ris, model, sizeof(model));
    input_stream_close(&ris);

    yatest_random_input_stream_init(&ris, INT32_MAX);
    rewind_input_stream_init(&is, &ris, REWIND_BUFFER_SIZE);

    input_stream_t *ris_ptr = rewind_input_stream_get_filtered(&is);
    if(memcmp(&ris_copy, ris_ptr, sizeof(input_stream_t)) != 0)
    {
        yatest_err("rewind_test: rewind_input_stream_get_filtered failed");
        return 1;
    }

    if(!is_rewind_input_stream(&is))
    {
        yatest_err("rewind_test: is_rewind_input_stream wrongly returned false");
        return 1;
    }

    if(is_rewind_input_stream(&ris))
    {
        yatest_err("rewind_test: is_rewind_input_stream wrongly returned true");
        return 1;
    }

    rewind_input_stream_mark(&is);
    input_stream_skip(&is, REWIND_BUFFER_SIZE / 2);
    rewind_input_stream_mark(&is);
    input_stream_skip(&is, REWIND_BUFFER_SIZE);
    rewind_input_stream_mark(&is);
    input_stream_skip(&is, REWIND_BUFFER_SIZE);

    ret = rewind_input_stream_rewind(&is, 1);
    if(ret != 1)
    {
        yatest_err("rewind_test: rewind_input_stream_rewind failed at %i: %i instead of 1", REWIND_BUFFER_SIZE, ret);
        return 1;
    }
    ret = input_stream_read(&is, &buffer[REWIND_BUFFER_SIZE - 1], 1);
    for(int i = REWIND_BUFFER_SIZE - 2; i >= 0; --i)
    {
        ret = rewind_input_stream_rewind(&is, 2);
        if(ret != 2)
        {
            yatest_err("rewind_test: rewind_input_stream_rewind failed at %i: %i instead of 2", i, ret);
            return 1;
        }
        ret = input_stream_read(&is, &buffer[i], 1);
        if(ret != 1)
        {
            yatest_err("rewind_test: failed at %i: %i instead of 1", i, ret);
            return 1;
        }
    }

    const uint8_t *displaced = (uint8_t *)model + REWIND_BUFFER_SIZE / 2 + REWIND_BUFFER_SIZE;

    if(memcmp(displaced, buffer, REWIND_BUFFER_SIZE) != 0)
    {
        yatest_log("displaced:");
        yatest_hexdump(displaced, displaced + REWIND_BUFFER_SIZE);
        yatest_log("buffer:");
        yatest_hexdump(buffer, buffer + REWIND_BUFFER_SIZE);
        yatest_err("rewind_test: displaced vs buffer difference");
        return 1;
    }

    rewind_input_stream_mark(&is);
    input_stream_skip(&is, REWIND_BUFFER_SIZE);
    ret = rewind_input_stream_rewind(&is, REWIND_BUFFER_SIZE + 1);
    if(ret != REWIND_BUFFER_SIZE)
    {
        yatest_err("rewind_test: rewind_input_stream_rewind has rewound %i bytes instead of %i", ret, REWIND_BUFFER_SIZE);
        return 1;
    }

    input_stream_skip(&is, REWIND_BUFFER_SIZE);
    rewind_input_stream_rewind_to_mark(&is);
    ret = input_stream_read(&is, buffer, REWIND_BUFFER_SIZE);
    if(ret != REWIND_BUFFER_SIZE)
    {
        yatest_err("rewind_test: input_stream_read read %i bytes instead of %i (rewind_input_stream_rewind_to_mark)", ret, REWIND_BUFFER_SIZE);
        return 1;
    }
    ret = rewind_input_stream_rewind(&is, REWIND_BUFFER_SIZE + 1);
    if(ret != REWIND_BUFFER_SIZE)
    {
        yatest_err("rewind_test: rewind_input_stream_rewind has rewound %i bytes instead of %i (bis)", ret, REWIND_BUFFER_SIZE);
        return 1;
    }
    ret = input_stream_read(&is, buffer2, REWIND_BUFFER_SIZE);
    if(ret != REWIND_BUFFER_SIZE)
    {
        yatest_err("rewind_test: input_stream_read read %i bytes instead of %i (rewind_input_stream_rewind)", ret, REWIND_BUFFER_SIZE);
        return 1;
    }

    if(memcmp(buffer, buffer2, REWIND_BUFFER_SIZE) != 0)
    {
        yatest_log("buffer:");
        yatest_hexdump(buffer, buffer + REWIND_BUFFER_SIZE);
        yatest_log("buffer2:");
        yatest_hexdump(buffer2, buffer2 + REWIND_BUFFER_SIZE);
        yatest_err("rewind_test: buffer vs buffer2 difference");
        return 1;
    }
    input_stream_close(&is);

    return 0;
}

static int rewind_overflow_test()
{
    int ret;
    dnscore_init();

    input_stream_t ris;
    input_stream_t is;
    char           model[65536];
    char           buffer[REWIND_BUFFER_SIZE];
    char           buffer2[REWIND_BUFFER_SIZE];

    yatest_random_input_stream_init(&ris, INT32_MAX);
    input_stream_read(&ris, model, sizeof(model));
    input_stream_close(&ris);

    yatest_random_input_stream_init(&ris, INT32_MAX);
    rewind_input_stream_init(&is, &ris, REWIND_BUFFER_SIZE);
    rewind_input_stream_mark(&is);

    for(int i = 0; i < REWIND_BUFFER_SIZE; ++i)
    {
        ret = input_stream_read(&is, &buffer[i], 1);
        if(ret != 1)
        {
            yatest_err("rewind_overflow_test: failed to read 1 byte (first)");
            return 1;
        }
    }

    for(int i = 0; i < REWIND_BUFFER_SIZE; ++i)
    {
        ret = input_stream_read(&is, &buffer2[i], 1);
        if(ret != 1)
        {
            yatest_err("rewind_overflow_test: failed to read 1 byte (second)");
            return 1;
        }
    }

    if(memcmp(&model[0], buffer, REWIND_BUFFER_SIZE) != 0)
    {
        yatest_log("model[0]:");
        yatest_hexdump(model, model + REWIND_BUFFER_SIZE);
        yatest_log("buffer:");
        yatest_hexdump(buffer, buffer + REWIND_BUFFER_SIZE);
        yatest_err("rewind_overflow_test: model[0] & buffer differs");
        return 1;
    }

    if(memcmp(&model[REWIND_BUFFER_SIZE], buffer2, REWIND_BUFFER_SIZE) != 0)
    {
        yatest_log("model[REWIND_BUFFER_SIZE]:");
        yatest_hexdump(model + REWIND_BUFFER_SIZE, model + REWIND_BUFFER_SIZE * 2);
        yatest_log("buffer:");
        yatest_hexdump(buffer2, buffer2 + REWIND_BUFFER_SIZE);
        yatest_err("rewind_overflow_test: model[REWIND_BUFFER_SIZE] & buffer2 differs");
        return 1;
    }

    ret = rewind_input_stream_rewind(&is, REWIND_BUFFER_SIZE + 1);

    if(ret != 0)
    {
        yatest_err("rewind_overflow_test: rewind should not have moved at all, instead moved of %i", ret);
        return 1;
    }

    rewind_input_stream_mark(&is);

    for(int i = 0; i < REWIND_BUFFER_SIZE + 1; ++i)
    {
        ret = input_stream_skip(&is, 1);
        if(ret != 1)
        {
            yatest_err("rewind_overflow_test: failed to skip 1 byte (first)");
            return 1;
        }
    }

    ret = rewind_input_stream_rewind(&is, REWIND_BUFFER_SIZE + 1);

    if(ret != 0)
    {
        yatest_err("rewind_overflow_test: rewind should not have moved at all, instead moved of %i (bis)", ret);
        return 1;
    }

    return 0;
}

static int pushback_test()
{
    int ret;
    dnscore_init();

    input_stream_t    ris;
    input_stream_t    is;

    static const char text[] = "Hello World!";
    char              buffer[sizeof(text)];

    yatest_random_input_stream_init(&ris, INT32_MAX);
    rewind_input_stream_init(&is, &ris, sizeof(text) - 1);

    for(int i = 0; text[i] != '\0'; ++i)
    {
        yatest_log("pushing back '%c'", text[i]);
        if(!rewind_input_stream_push_back(&is, text[i]))
        {
            yatest_err("pushback_test: push back failed at offset %i", i);
            return 1;
        }
    }

    if(rewind_input_stream_push_back(&is, '?'))
    {
        yatest_err("pushback_test: push back unexpectedly succeeded at offset %i", sizeof(text));
        return 1;
    }

    ret = input_stream_read(&is, buffer, sizeof(text) - 1);
    if(ret != sizeof(text) - 1)
    {
        yatest_err("pushback_test: input_stream_read returned %i instead of %i", ret, sizeof(text) - 1);
        return 1;
    }

    if(memcmp(text, buffer, sizeof(text) - 1) != 0)
    {
        yatest_log("text:");
        yatest_hexdump(text, text + sizeof(text) - 1);
        yatest_log("buffer:");
        yatest_hexdump(buffer, buffer + sizeof(text) - 1);
        yatest_err("pushback_test: buffer differs");
        return 1;
    }

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(read_consistency4096_test)
YATEST(read_consistency1_test)
YATEST(skip_consistency4096_test)
YATEST(skip_consistency1_test)
YATEST(rewind_test)
YATEST(rewind_overflow_test)
YATEST(pushback_test)
YATEST_TABLE_END

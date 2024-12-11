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
#include <dnscore/pipe_stream.h>

static int pipe_stream_test()
{
    dnscore_init();

    output_stream_t os;
    input_stream_t  is;
    char            buffer[sizeof(yatest_lorem_ipsum) * 2];
    pipe_stream_init(&os, &is, sizeof(buffer));

    for(size_t i = 0; i < sizeof(yatest_lorem_ipsum);)
    {
        int32_t wavail = pipe_stream_write_available(&os);
        int     wn = MIN(((int)i & 7) + 1, wavail);
        output_stream_write(&os, &yatest_lorem_ipsum[i], wn);
        i += wn;
    }

    output_stream_flush(&os);

    for(size_t i = 0; i < sizeof(yatest_lorem_ipsum);)
    {
        int32_t ravail = pipe_stream_read_available(&is);
        input_stream_read(&is, buffer, ravail);
        i += ravail;
    }

    if(strcmp(buffer, yatest_lorem_ipsum) != 0)
    {
        yatest_err("unexpected result");
        return 1;
    }

    for(size_t i = 0; i < sizeof(yatest_lorem_ipsum);)
    {
        int32_t wavail = pipe_stream_write_available(&os);
        int     wn = MIN(((int)i & 7) + 1, wavail);
        output_stream_write(&os, &yatest_lorem_ipsum[i], wn);
        i += wn;
    }

    output_stream_flush(&os);

    for(size_t i = 0; i < sizeof(yatest_lorem_ipsum);)
    {
        int32_t ravail = pipe_stream_read_available(&is);
        input_stream_skip(&is, ravail);
        i += ravail;
    }

    output_stream_close(&os);
    input_stream_close(&is);

    dnscore_finalize();

    return 0;
}

YATEST_TABLE_BEGIN
YATEST(pipe_stream_test)
YATEST_TABLE_END

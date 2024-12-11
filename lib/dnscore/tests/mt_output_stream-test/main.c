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
#include <dnscore/mt_output_stream.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/format.h>

static int mt_output_stream_test()
{
    output_stream_t baos;
    output_stream_t baos2;
    output_stream_t os;
    dnscore_init();
    bytearray_output_stream_init(&baos, NULL, 65536);
    bytearray_output_stream_init(&baos2, NULL, 65536);
    mt_output_stream_init(&os, &baos);
    mt_output_stream_set_filtered(&os, &baos2, true);
    static const char expected[] = "Hello World!";
    osformat(&os, expected);
    output_stream_flush(&os);
    output_stream_write_u8(mt_output_stream_get_filtered(&os), 0);
    if(strcmp((const char *)bytearray_output_stream_buffer(mt_output_stream_get_filtered(&os)), expected) != 0)
    {
        yatest_err("got '%s', expected '%s'", bytearray_output_stream_buffer(mt_output_stream_get_filtered(&os)), expected);
        return 1;
    }
    output_stream_close(&os);
    dnscore_finalize();
    return 0;
}

static int mt_output_stream_full_test()
{
    output_stream_t baos;
    output_stream_t os;
    dnscore_init();
    static const uint32_t size = 1;
    bytearray_output_stream_init(&baos, NULL, size);
    mt_output_stream_init(&os, &baos);
    static const char expected[] = "Hello World!";
    osformat(&os, expected);
    output_stream_flush(&os);
    if(bytearray_output_stream_size(mt_output_stream_get_filtered(&os)) != size)
    {
        yatest_err("unexpected size");
        return 1;
    }
    output_stream_close(&os);
    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(mt_output_stream_test)
YATEST(mt_output_stream_full_test)
YATEST_TABLE_END

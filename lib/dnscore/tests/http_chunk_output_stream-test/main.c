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
#include <dnscore/http_chunk_output_stream.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/zalloc.h>

static void http_chunk_decode(uint8_t *buffer, uint32_t buffer_size, uint8_t **out_buffer, uint32_t *out_buffer_size)
{
    uint8_t *limit = buffer + buffer_size;
    uint64_t total_size = 0;
    uint8_t *o = NULL;
    for(int pass = 0; pass <= 1; ++pass)
    {
        uint8_t *p = buffer;

        while(p < limit)
        {
            uint64_t size = 0;

            while(p < limit)
            {
                char c = (char)*p++;
                if(c == '\r')
                {
                    c = (char)*p++;
                    if(c != '\n')
                    {
                        yatest_err("Expected LF");
                        exit(1);
                    }
                    break;
                }
                if(c >= '0' && c <= '9')
                {
                    size <<= 4;
                    size |= (c - '0');
                    continue;
                }
                c |= 32;
                if(c >= 'a' && c <= 'f')
                {
                    size <<= 4;
                    size |= (c - 'a' + 10);
                    continue;
                }

                yatest_err("Unexpected character %02x", c);
                exit(1);
            }

            // size is the size of the chunk

            if(pass == 0)
            {
                total_size += size;
            }
            else
            {
                memcpy(o, p, size);
                o += size;
            }
            p += size;

            char c = (char)*p++;
            if(c == '\r')
            {
                c = (char)*p++;
                if(c != '\n')
                {
                    yatest_err("Expected LF");
                    exit(1);
                }
            }
            else
            {
                yatest_err("Expected CR");
                exit(1);
            }
        }

        // total_size

        if(pass == 0)
        {
            *out_buffer_size = total_size;
            o = (uint8_t *)malloc(total_size);
            *out_buffer = o;
        }
    }
}

static int http_chunk_output_stream_factory_size(output_stream_t *os, uint32_t *in_out_size, int buffer_size)
{
    int             ret;
    output_stream_t baos;
    bytearray_output_stream_init_ex(&baos, NULL, *in_out_size * 4, BYTEARRAY_DYNAMIC);
    ret = http_chunk_output_stream_init(os, &baos, buffer_size);

    if(FAIL(ret))
    {
        yatest_err("http_chunk_output_stream_init %i failed with %s", buffer_size, error_gettext(ret));
        exit(1);
    }

    if(!http_chunk_output_stream_instance(os))
    {
        yatest_err("http_chunk_output_stream_instance returned false");
        exit(1);
    }
    if(http_chunk_output_stream_instance(&baos))
    {
        yatest_err("http_chunk_output_stream_instance returned true");
        exit(1);
    }
    return 0;
}

static int http_chunk_output_stream_factoryfull(output_stream_t *os, uint32_t *in_out_size) { return http_chunk_output_stream_factory_size(os, in_out_size, *in_out_size); }

static int http_chunk_output_stream_factory32(output_stream_t *os, uint32_t *in_out_size) { return http_chunk_output_stream_factory_size(os, in_out_size, 32); }

static int http_chunk_output_stream_factory7(output_stream_t *os, uint32_t *in_out_size) { return http_chunk_output_stream_factory_size(os, in_out_size, 7); }

static int http_chunk_output_stream_factory1(output_stream_t *os, uint32_t *in_out_size) { return http_chunk_output_stream_factory_size(os, in_out_size, 1); }

static int http_chunk_output_stream_factory0(output_stream_t *os, uint32_t *in_out_size) { return http_chunk_output_stream_factory_size(os, in_out_size, 0); }

static int http_chunk_output_stream_close_readback(output_stream_t *os, void **bufferp, size_t *buffer_sizep)
{
    output_stream_flush(os);
    uint32_t encode_size = bytearray_output_stream_size(http_chunk_output_stream_get_filtered(os));
    uint8_t *encoded = (uint8_t *)bytearray_output_stream_buffer(http_chunk_output_stream_get_filtered(os));

    // decode
    uint32_t decoded_size;
    uint8_t *decoded;
    http_chunk_decode(encoded, encode_size, &decoded, &decoded_size);
    *buffer_sizep = decoded_size;
    *bufferp = (void *)decoded;

    output_stream_close(os);
    return 0;
}

static int write_consistencyfull_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(http_chunk_output_stream_factoryfull, http_chunk_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "http_chunk_output_stream");
    return ret;
}

static int write_consistency32_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(http_chunk_output_stream_factory32, http_chunk_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "http_chunk_output_stream");
    return ret;
}

static int write_consistency7_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(http_chunk_output_stream_factory7, http_chunk_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "http_chunk_output_stream");
    return ret;
}

static int write_consistency1_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(http_chunk_output_stream_factory1, http_chunk_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "http_chunk_output_stream");
    return ret;
}

static int write_consistency0_test()
{
    int ret;
    dnscore_init();
    ret = yatest_output_stream_write_consistency_test(http_chunk_output_stream_factory0, http_chunk_output_stream_close_readback, 4096, 1, 4097 + 1, 1, "http_chunk_output_stream");
    return ret;
}

static int write_pattern_0()
{
    int ret;
    int buffer_size = 4;
    dnscore_init();
    output_stream_t baos;
    output_stream_t os;

    bytearray_output_stream_init_ex(&baos, NULL, buffer_size, BYTEARRAY_DYNAMIC);
    http_chunk_output_stream_init(&os, &baos, buffer_size);

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
    if(ret != buffer_size * 2)
    {
        yatest_err("output_stream_write %i didn't write everything (%i)", buffer_size * 2, ret);
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
    http_chunk_output_stream_init(&os, &baos, buffer_size);

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
    http_chunk_output_stream_init(&os, &eos, buffer_size);

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
YATEST(write_pattern_0)
YATEST(write_pattern_1)
YATEST(write_pattern_1e)
YATEST_TABLE_END

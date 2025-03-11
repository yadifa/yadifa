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
#include <dnscore/dnscore.h>
#include <stdlib.h>
#include <dnscore/base16.h>
#include <dnscore/base32.h>
#include <dnscore/base32hex.h>
#include <dnscore/base64.h>

#include <dnscore/bytearray_output_stream.h>

#define PATTERN_SIZE (256 * 257)

static char *yatest_source_message_base16 = "Many hands make light work.";
static char *yatest_source_encoded_base16 = "4D616E792068616E6473206D616B65206C6967687420776F726B2E";

static char *yatest_source_message_base16lc = "Many hands make light work.";
static char *yatest_source_encoded_base16lc = "4d616e792068616e6473206d616b65206c6967687420776f726b2e";

static char *yatest_source_message_base32 = "Many hands make light work.";
static char *yatest_source_encoded_base32 = "JVQW46JANBQW4ZDTEBWWC23FEBWGSZ3IOQQHO33SNMXA====";

static char *yatest_source_message_base32hex = "Many hands make light work.";
static char *yatest_source_encoded_base32hex = "9LGMSU90D1GMSP3J41MM2QR541M6IPR8EGG7ERRIDCN0====";

static char *yatest_source_message_base32hexlc = "Many hands make light work.";
static char *yatest_source_encoded_base32hexlc = "9lgmsu90d1gmsp3j41mm2qr541m6ipr8egg7erridcn0====";

static char *yatest_source_message_base64 = "Many hands make light work.";
static char *yatest_source_encoded_base64 = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu";

static char *allocate_pattern()
{
    char *p = (char *)malloc(PATTERN_SIZE);
    if(p == NULL)
    {
        yatest_err("allocate_pattern alloc error");
        exit(1);
    }
    for(int i = 0; i < 256; ++i)
    {
        for(int j = 0; j < 256; ++j)
        {
            p[256 * i + j] = i;
        }
        p[256 * 256 + i] = i;
    }
    return p;
}

static char *allocate_buffer()
{
    char *p = (char *)malloc(PATTERN_SIZE * 2);
    if(p == NULL)
    {
        yatest_err("allocate_buffer alloc error");
        exit(1);
    }
    return p;
}

static int base16_test()
{
    dnscore_init();

    char *p = allocate_pattern();
    char *a = allocate_buffer();
    char *b = allocate_buffer();
    int   d;

    // error check 0

    if(base16_decode(yatest_source_message_base16, 1, (uint8_t *)b) != PARSEB16_ERROR)
    {
        yatest_err("accepted invalid size input");
        return 16;
    }

    // error check 1

    a[0] = (char)0xff;
    a[1] = (char)0xff;

    if(base16_decode(a, 2, (uint8_t *)b) != PARSEB16_ERROR)
    {
        yatest_err("accepted invalid data input");
        return 16;
    }

    // nibble function

    for(int i = 0; i <= 9; i++)
    {
        if(base16_decode_nibble('0' + i) != i)
        {
            yatest_err("nibble for %c appear to be incorrect", '0' + i);
            return 17;
        }
    }

    for(int i = 10; i <= 15; i++)
    {
        if(base16_decode_nibble('A' - 10 + i) != i)
        {
            yatest_err("nibble for %c appear to be incorrect", 'A' - 10 + i);
            return 18;
        }
    }

    for(int i = 10; i <= 15; i++)
    {
        if(base16_decode_nibble('a' - 10 + i) != i)
        {
            yatest_err("nibble for %c appear to be incorrect", 'a' - 10 + i);
            return 17;
        }
    }

    // validation tests

    uint32_t yatest_source_message_base16_encoded_size = base16_encode((uint8_t *)yatest_source_message_base16, strlen(yatest_source_message_base16), a);
    a[yatest_source_message_base16_encoded_size] = '\0';
    d = strcmp(a, yatest_source_encoded_base16);
    if(d != 0)
    {
        yatest_err("encoded '%s' to '%s' instead of to '%s", yatest_source_message_base16, a, yatest_source_encoded_base16);
        return 1;
    }

    uint32_t encoded_message_base16_decoded_size = base16_decode(a, yatest_source_message_base16_encoded_size, (uint8_t *)b);
    b[encoded_message_base16_decoded_size] = '\0';
    d = strcmp(b, yatest_source_message_base16);
    if(d != 0)
    {
        yatest_err("decoded '%s' to '%s' instead of to '%s", a, b, yatest_source_message_base16);
        return 2;
    }

    uint32_t  a_size = base16_encode((uint8_t *)p, PATTERN_SIZE, a);
    ya_result b_size = base16_decode(a, a_size, (uint8_t *)b);

    if(FAIL(b_size))
    {
        yatest_err("decoding failed");
        return 3;
    }

    if(b_size != PATTERN_SIZE)
    {
        yatest_err("decoded size is wrong: %i instead of %i", b_size, PATTERN_SIZE);
        return 4;
    }

    d = memcmp(p, b, PATTERN_SIZE);

    if(d != 0)
    {
        yatest_err("original and decoded patterns differ");
        return 5;
    }

    free(b);
    free(a);
    free(p);
    return 0;
}

static int base16lc_test()
{
    dnscore_init();
    char    *p = allocate_pattern();
    char    *a = allocate_buffer();
    char    *b = allocate_buffer();
    int      d;

    uint32_t yatest_source_message_base16_encoded_size = base16_encode_lc((uint8_t *)yatest_source_message_base16lc, strlen(yatest_source_message_base16lc), a);
    a[yatest_source_message_base16_encoded_size] = '\0';
    d = strcmp(a, yatest_source_encoded_base16lc);
    if(d != 0)
    {
        yatest_err("encoded '%s' to '%s' instead of to '%s", yatest_source_message_base16lc, a, yatest_source_encoded_base16lc);
        return 1;
    }

    uint32_t encoded_message_base16_decoded_size = base16_decode(a, yatest_source_message_base16_encoded_size, (uint8_t *)b);
    b[encoded_message_base16_decoded_size] = '\0';
    d = strcmp(b, yatest_source_message_base16lc);
    if(d != 0)
    {
        yatest_err("decoded '%s' to '%s' instead of to '%s", a, b, yatest_source_message_base16lc);
        return 2;
    }

    uint32_t  a_size = base16_encode((uint8_t *)p, PATTERN_SIZE, a);
    ya_result b_size = base16_decode(a, a_size, (uint8_t *)b);

    if(FAIL(b_size))
    {
        yatest_err("decoding failed");
        return 3;
    }

    if(b_size != PATTERN_SIZE)
    {
        yatest_err("decoded size is wrong: %i instead of %i", b_size, PATTERN_SIZE);
        return 4;
    }

    d = memcmp(p, b, PATTERN_SIZE);

    if(d != 0)
    {
        yatest_err("original and decoded patterns differ");
        return 5;
    }

    free(b);
    free(a);
    free(p);
    return 0;
}

static int base32_test()
{
    dnscore_init();
    char *p = allocate_pattern();
    char *a = allocate_buffer();
    char *b = allocate_buffer();
    int   d;

    // error check 0

    for(int wrong_size = 1; wrong_size <= 7; ++wrong_size)
    {
        if(base32_decode(yatest_source_message_base32, wrong_size, (uint8_t *)b) != PARSEB32_ERROR)
        {
            yatest_err("accepted invalid size input");
            return 16;
        }
    }

    // error check 1

    for(int i = 0; i < 16; ++i)
    {
        a[i] = (char)0xff;
    }

    if(base32_decode(a, 8, (uint8_t *)b) != PARSEB32_ERROR)
    {
        yatest_err("accepted invalid data input");
        return 17;
    }

    if(base32_decode(a, 16, (uint8_t *)b) != PARSEB32_ERROR)
    {
        yatest_err("accepted invalid data input");
        return 17;
    }

    // error check 2

    for(int size = 2; size <= 16; ++size)
    {
        for(int i = 0; i < size; ++i)
        {
            a[i] = i;
        }
        uint32_t b_size = base32_encode((uint8_t *)a, size, b);
        for(uint32_t j = 0; (j < b_size) && (b[j] != '='); ++j)
        {
            char old = b[j];
            b[j] = (char)0xff;
            if(base32_decode(b, b_size, (uint8_t *)a) != PARSEB32_ERROR)
            {
                yatest_err("accepted invalid data input: size=%i, j=%i", size, j);
                return 17;
            }
            b[j] = old;
        }
    }

    //

    uint32_t yatest_source_message_base32_encoded_size = base32_encode((uint8_t *)yatest_source_message_base32, strlen(yatest_source_message_base32), a);
    a[yatest_source_message_base32_encoded_size] = '\0';
    d = strcmp(a, yatest_source_encoded_base32);
    if(d != 0)
    {
        yatest_err("encoded '%s' to '%s' instead of to '%s", yatest_source_message_base32, a, yatest_source_encoded_base32);
        return 1;
    }

    uint32_t encoded_message_base32_decoded_size = base32_decode(a, yatest_source_message_base32_encoded_size, (uint8_t *)b);
    b[encoded_message_base32_decoded_size] = '\0';
    d = strcmp(b, yatest_source_message_base32);
    if(d != 0)
    {
        yatest_err("decoded '%s' to '%s' instead of to '%s", a, b, yatest_source_message_base32);
        return 2;
    }

    for(uint32_t pattern_size = PATTERN_SIZE - 16; pattern_size <= PATTERN_SIZE; ++pattern_size)
    {
        uint32_t  a_size = base32_encode((uint8_t *)p, pattern_size, a);
        ya_result b_size = base32_decode(a, a_size, (uint8_t *)b);

        if(FAIL(b_size))
        {
            yatest_err("decoding failed, pattern_size=%u", pattern_size);
            return 3;
        }

        if((uint32_t)b_size != pattern_size)
        {
            yatest_err("decoded size is wrong: %i instead of %u", b_size, pattern_size);
            return 4;
        }

        d = memcmp(p, b, pattern_size);

        if(d != 0)
        {
            yatest_err("original and decoded patterns differ, pattern_size=%u", pattern_size);
            return 5;
        }
    }

    free(b);
    free(a);
    free(p);
    return 0;
}

static int base32hex_test()
{
    dnscore_init();
    char *p = allocate_pattern();
    char *a = allocate_buffer();
    char *b = allocate_buffer();
    int   d;

    // error check 0

    for(int wrong_size = 1; wrong_size <= 7; ++wrong_size)
    {
        if(base32hex_decode(yatest_source_message_base32, wrong_size, (uint8_t *)b) != PARSEB32H_ERROR)
        {
            yatest_err("accepted invalid size input");
            return 16;
        }
    }

    // error check 1

    for(int i = 0; i < 16; ++i)
    {
        a[i] = (char)0xff;
    }

    if(base32hex_decode(a, 8, (uint8_t *)b) != PARSEB32H_ERROR)
    {
        yatest_err("accepted invalid data input");
        return 17;
    }

    if(base32hex_decode(a, 16, (uint8_t *)b) != PARSEB32H_ERROR)
    {
        yatest_err("accepted invalid data input");
        return 17;
    }

    // error check 2

    for(int size = 2; size <= 16; ++size)
    {
        for(int i = 0; i < size; ++i)
        {
            a[i] = i;
        }
        uint32_t b_size = base32hex_encode((uint8_t *)a, size, b);
        for(uint32_t j = 0; (j < b_size) && (b[j] != '='); ++j)
        {
            char old = b[j];
            b[j] = (char)0xff;
            if(base32hex_decode(b, b_size, (uint8_t *)a) != PARSEB32H_ERROR)
            {
                yatest_err("accepted invalid data input: size=%i, j=%i", size, j);
                return 17;
            }
            b[j] = old;
        }
    }

    //

    uint32_t yatest_source_message_base32hex_encoded_size = base32hex_encode((uint8_t *)yatest_source_message_base32hex, strlen(yatest_source_message_base32hex), a);
    a[yatest_source_message_base32hex_encoded_size] = '\0';
    d = strcmp(a, yatest_source_encoded_base32hex);
    if(d != 0)
    {
        yatest_err("encoded '%s' to '%s' instead of to '%s", yatest_source_message_base32hex, a, yatest_source_encoded_base32hex);
        return 1;
    }

    uint32_t encoded_message_base32hex_decoded_size = base32hex_decode(a, yatest_source_message_base32hex_encoded_size, (uint8_t *)b);
    b[encoded_message_base32hex_decoded_size] = '\0';
    d = strcmp(b, yatest_source_message_base32hex);
    if(d != 0)
    {
        yatest_err("decoded '%s' to '%s' instead of to '%s", a, b, yatest_source_message_base32hex);
        return 2;
    }

    for(uint32_t pattern_size = PATTERN_SIZE - 16; pattern_size <= PATTERN_SIZE; ++pattern_size)
    {
        uint32_t  a_size = base32hex_encode((uint8_t *)p, pattern_size, a);
        ya_result b_size = base32hex_decode(a, a_size, (uint8_t *)b);

        if(FAIL(b_size))
        {
            yatest_err("decoding failed, pattern_size=%u", pattern_size);
            return 3;
        }

        if((uint32_t)b_size != pattern_size)
        {
            yatest_err("decoded size is wrong: %i instead of %u", b_size, pattern_size);
            return 4;
        }

        d = memcmp(p, b, pattern_size);

        if(d != 0)
        {
            yatest_err("original and decoded patterns differ, pattern_size=%u", pattern_size);
            return 5;
        }

        // test the output_stream_write_base32hex function

        output_stream_t os;
        bytearray_output_stream_init(&os, NULL, 0);
        output_stream_write_base32hex(&os, p, pattern_size);
        uint8_t *encoded_stream_buffer = bytearray_output_stream_buffer(&os);
        uint32_t encoded_stream_size = bytearray_output_stream_size(&os);
        if(encoded_stream_size != a_size)
        {
            yatest_err("output_stream_write_base32hex encoded size is wrong: %u instead of %u", encoded_stream_size, a_size);
            output_stream_close(&os);
            return 6;
        }
        if(memcmp(encoded_stream_buffer, a, a_size) != 0)
        {
            yatest_err("output_stream_write_base32hex encoded stream is wrong");
            output_stream_close(&os);
            return 7;
        }
        output_stream_close(&os);
    }

    free(b);
    free(a);
    free(p);
    return 0;
}

static int base32hexlc_test()
{
    dnscore_init();
    char *p = allocate_pattern();
    char *a = allocate_buffer();
    char *b = allocate_buffer();
    int   d;

    // error check 0

    for(int wrong_size = 1; wrong_size <= 7; ++wrong_size)
    {
        if(base32hex_decode(yatest_source_message_base32, wrong_size, (uint8_t *)b) != PARSEB32H_ERROR)
        {
            yatest_err("accepted invalid size input");
            return 16;
        }
    }

    // error check 1

    for(int i = 0; i < 16; ++i)
    {
        a[i] = (char)0xff;
    }

    if(base32hex_decode(a, 8, (uint8_t *)b) != PARSEB32H_ERROR)
    {
        yatest_err("accepted invalid data input");
        return 17;
    }

    if(base32hex_decode(a, 16, (uint8_t *)b) != PARSEB32H_ERROR)
    {
        yatest_err("accepted invalid data input");
        return 17;
    }

    // error check 2

    for(int size = 2; size <= 16; ++size)
    {
        for(int i = 0; i < size; ++i)
        {
            a[i] = i;
        }
        uint32_t b_size = base32hex_encode_lc((uint8_t *)a, size, b);
        for(uint32_t j = 0; (j < b_size) && (b[j] != '='); ++j)
        {
            char old = b[j];
            b[j] = (char)0xff;
            if(base32hex_decode(b, b_size, (uint8_t *)a) != PARSEB32H_ERROR)
            {
                yatest_err("accepted invalid data input: size=%i, j=%i", size, j);
                return 17;
            }
            b[j] = old;
        }
    }

    //

    uint32_t yatest_source_message_base32hex_encoded_size = base32hex_encode_lc((uint8_t *)yatest_source_message_base32hexlc, strlen(yatest_source_message_base32hexlc), a);
    a[yatest_source_message_base32hex_encoded_size] = '\0';
    d = strcmp(a, yatest_source_encoded_base32hexlc);
    if(d != 0)
    {
        yatest_err("encoded '%s' to '%s' instead of to '%s", yatest_source_message_base32hexlc, a, yatest_source_encoded_base32hexlc);
        return 1;
    }

    uint32_t encoded_message_base32hex_decoded_size = base32hex_decode(a, yatest_source_message_base32hex_encoded_size, (uint8_t *)b);
    b[encoded_message_base32hex_decoded_size] = '\0';
    d = strcmp(b, yatest_source_message_base32hexlc);
    if(d != 0)
    {
        yatest_err("decoded '%s' to '%s' instead of to '%s", a, b, yatest_source_message_base32hexlc);
        return 2;
    }

    for(uint32_t pattern_size = PATTERN_SIZE - 16; pattern_size <= PATTERN_SIZE; ++pattern_size)
    {
        uint32_t  a_size = base32hex_encode_lc((uint8_t *)p, pattern_size, a);
        ya_result b_size = base32hex_decode(a, a_size, (uint8_t *)b);

        if(FAIL(b_size))
        {
            yatest_err("decoding failed, pattern_size=%u", pattern_size);
            return 3;
        }

        if((uint32_t)b_size != pattern_size)
        {
            yatest_err("decoded size is wrong: %i instead of %u", b_size, pattern_size);
            return 4;
        }

        d = memcmp(p, b, pattern_size);

        if(d != 0)
        {
            yatest_err("original and decoded patterns differ, pattern_size=%u", pattern_size);
            return 5;
        }
    }

    free(b);
    free(a);
    free(p);
    return 0;
}

static int base64_test()
{
    dnscore_init();
    char *p = allocate_pattern();
    char *a = allocate_buffer();
    char *b = allocate_buffer();
    int   d;

    // error check 0

    for(int wrong_size = 1; wrong_size <= 3; ++wrong_size)
    {
        if(base64_decode(yatest_source_message_base64, wrong_size, (uint8_t *)b) != PARSEB64_ERROR)
        {
            yatest_err("accepted invalid size input");
            return 16;
        }

        if(base64_equals_binary(yatest_source_message_base64, wrong_size, (uint8_t *)b) != PARSEB64_ERROR)
        {
            yatest_err("accepted invalid size input");
            return 16;
        }
    }

    // error check 1

    for(int i = 0; i < 16; ++i)
    {
        a[i] = (char)0xff;
    }

    if(base64_decode(a, 8, (uint8_t *)b) != PARSEB64_ERROR)
    {
        yatest_err("accepted invalid data input");
        return 17;
    }

    // error check 2

    for(int size = 2; size <= 32; ++size)
    {
        for(int i = 0; i < size; ++i)
        {
            a[i] = i;
        }
        uint32_t b_size = base64_encode((uint8_t *)a, size, b);

        if((base64_equals_binary(b, b_size, (uint8_t *)a)) != 0)
        {
            yatest_err("data should have matched: size=%i", size);
            return 18;
        }

        for(uint32_t j = 0; (j < b_size) && (b[j] != '='); ++j)
        {
            char old = b[j];
            b[j] = (char)0xff;
            if(base64_decode(b, b_size, (uint8_t *)a) != PARSEB64_ERROR)
            {
                yatest_err("accepted invalid data input: size=%i, j=%i", size, j);
                return 19;
            }

            if(base64_equals_binary(b, b_size, (uint8_t *)a) != PARSEB64_ERROR)
            {
                yatest_err("data should not have been accepted: size=%i, j=%i", size, j);
                return 20;
            }

            b[j] = old;

            if(base64_equals_binary(b, b_size, (uint8_t *)a) != 0)
            {
                yatest_err("data did not match: size=%i, j=%i", size, j);
                return 21;
            }

            if(b_size >= 8)
            {
                for(uint32_t k = 0; k < j; ++k)
                {
                    b[k] ^= 1; // note that modifying the first few characters is the only safe option

                    ya_result ret;
                    if((ret = base64_equals_binary(b, b_size, (uint8_t *)a)) == 0)
                    {
                        yatest_err("data should not have matched: size=%i, j=%i (%x)", size, j, ret);
                        return 22;
                    }

                    b[k] ^= 1;
                }
            }

            output_stream_t os;
            bytearray_output_stream_init(&os, NULL, 0);
            base64_print(b, b_size, &os);
            output_stream_close(&os);
        }
    }

    //

    static const char *b64charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    bool               table[256];
    for(int i = 0; i < 256; ++i)
    {
        table[i] = 0;
    }
    for(int i = 0; b64charset[i] != 0; ++i)
    {
        table[(uint32_t)b64charset[i]] = 1;
    }
    for(int i = 0; i < 256; ++i)
    {
        if(base64_character_set_contains(i) != table[i])
        {
            yatest_err("base64_character_set_contains(%i)=%i appears to be incorrect (%i)", i, base64_character_set_contains(i), table[i]);
            return 23;
        }
    }

    //

    uint32_t yatest_source_message_base64_encoded_size = base64_encode((uint8_t *)yatest_source_message_base64, strlen(yatest_source_message_base64), a);
    a[yatest_source_message_base64_encoded_size] = '\0';
    d = strcmp(a, yatest_source_encoded_base64);
    if(d != 0)
    {
        yatest_err("encoded '%s' to '%s' instead of to '%s", yatest_source_message_base64, a, yatest_source_encoded_base64);
        return 1;
    }

    uint32_t encoded_message_base64_decoded_size = base64_decode(a, yatest_source_message_base64_encoded_size, (uint8_t *)b);
    b[encoded_message_base64_decoded_size] = '\0';
    d = strcmp(b, yatest_source_message_base64);
    if(d != 0)
    {
        yatest_err("decoded '%s' to '%s' instead of to '%s", a, b, yatest_source_message_base64);
        return 2;
    }

    for(uint32_t pattern_size = PATTERN_SIZE - 16; pattern_size <= PATTERN_SIZE; ++pattern_size)
    {
        uint32_t  a_size = base64_encode((uint8_t *)p, pattern_size, a);
        ya_result b_size = base64_decode(a, a_size, (uint8_t *)b);

        if(FAIL(b_size))
        {
            yatest_err("decoding failed, pattern_size=%u", pattern_size);
            return 3;
        }

        if((uint32_t)b_size != pattern_size)
        {
            yatest_err("decoded size is wrong: %i instead of %u", b_size, pattern_size);
            return 4;
        }

        d = memcmp(p, b, pattern_size);

        if(d != 0)
        {
            yatest_err("original and decoded patterns differ, pattern_size=%u", pattern_size);
            return 5;
        }
    }

    free(b);
    free(a);
    free(p);
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(base16_test)
YATEST(base16lc_test)
YATEST(base32_test)
YATEST(base32hex_test)
YATEST(base32hexlc_test)
YATEST(base64_test)
YATEST_TABLE_END

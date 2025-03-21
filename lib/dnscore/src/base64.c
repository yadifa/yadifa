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

/**-----------------------------------------------------------------------------
 * @defgroup base Base conversion functions
 * @ingroup dnscore
 * @brief Base 64 codec
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * Base 64 codec functions
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"

#include <stdio.h>
#include <dnscore/output_stream.h>

#include "dnscore/base64.h"

/*
 *
 */

#define BASE64_PADDING '='

static const char __BASE64__[256] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',

                                     'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',

                                     'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',

                                     'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

/**
 * Encodes bytes into base64
 * The output size must be at least size_in * 8/5
 *
 * @param buffer_in     bytes to convert
 * @param size_in       number of bytes
 * @param buffer_out    output buffer of a size >= size_in * 4/3
 *
 * @return output size
 */

uint32_t base64_encode(const void *buffer_in_, uint32_t size_in, char *buffer_out)
{
    const uint8_t *buffer_in = (const uint8_t *)buffer_in_;
    char          *ptr = buffer_out;

    while(size_in >= 3)
    {
        uint8_t b0 = *buffer_in++;
        uint8_t b1 = *buffer_in++;
        uint8_t b2 = *buffer_in++;

        *ptr++ = __BASE64__[b0 >> 2];
        *ptr++ = __BASE64__[(uint8_t)((b0 << 4) | (b1 >> 4))];
        *ptr++ = __BASE64__[(uint8_t)((b1 << 2) | (b2 >> 6))];
        *ptr++ = __BASE64__[b2];

        size_in -= 3;
    }

    switch(size_in)
    {
        case 2:
        {
            uint8_t b0 = *buffer_in++;
            uint8_t b1 = *buffer_in;
            *ptr++ = __BASE64__[b0 >> 2];
            *ptr++ = __BASE64__[(uint8_t)((b0 << 4) | (b1 >> 4))];
            *ptr++ = __BASE64__[(uint8_t)(b1 << 2)];
            *ptr++ = BASE64_PADDING;
            break;
        }
        case 1:
        {
            uint8_t b0 = *buffer_in;
            *ptr++ = __BASE64__[b0 >> 2];
            *ptr++ = __BASE64__[(uint8_t)(b0 << 4)];
            *ptr++ = BASE64_PADDING;
            *ptr++ = BASE64_PADDING;
            break;
        }
    }

    return (uint32_t)(ptr - buffer_out);
}

/**
 * Encodes bytes into base64 and writes them to the output stream
 *
 * @param buffer_in     bytes to convert
 * @param size_in       number of bytes
 * @param os            the output stream
 *
 * @return output size
 */

uint32_t base64_print(const void *buffer_in_, uint32_t size_in, output_stream_t *os)
{
    const uint8_t *buffer_in = (const uint8_t *)buffer_in_;
    uint32_t       count = BASE64_ENCODED_SIZE(size_in);
    char           buffer[4];

    while(size_in >= 3)
    {
        uint8_t b0 = *buffer_in++;
        uint8_t b1 = *buffer_in++;
        uint8_t b2 = *buffer_in++;

        buffer[0] = __BASE64__[b0 >> 2];
        buffer[1] = __BASE64__[(uint8_t)((b0 << 4) | (b1 >> 4))];
        buffer[2] = __BASE64__[(uint8_t)((b1 << 2) | (b2 >> 6))];
        buffer[3] = __BASE64__[b2];
        output_stream_write(os, buffer, sizeof(buffer));

        size_in -= 3;
    }

    switch(size_in)
    {
        case 2:
        {
            uint8_t b0 = *buffer_in++;
            uint8_t b1 = *buffer_in;
            buffer[0] = __BASE64__[b0 >> 2];
            buffer[1] = __BASE64__[(uint8_t)((b0 << 4) | (b1 >> 4))];
            buffer[2] = __BASE64__[(uint8_t)(b1 << 2)];
            buffer[3] = BASE64_PADDING;
            output_stream_write(os, buffer, sizeof(buffer));
            break;
        }
        case 1:
        {
            uint8_t b0 = *buffer_in;
            buffer[0] = __BASE64__[b0 >> 2];
            buffer[1] = __BASE64__[(uint8_t)(b0 << 4)];
            buffer[2] = BASE64_PADDING;
            buffer[3] = BASE64_PADDING;
            output_stream_write(os, buffer, sizeof(buffer));
            break;
        }
    }

    return count;
}

#define __DEBASE64__STOP__ 0x80

static const uint8_t __DEBASE64__[256] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /*  0 -  7 */
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /*  8 - 15 */
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 16 - 23 */
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 24 - 31 */
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 32 - 39 */
                                          0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f, /* 40 - 47 ...+.../ */
                                          0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, /* 01234567 */
                                          0x3c, 0x3d, 0xff, 0xff, 0xff, 0x80, 0xff, 0xff, /* 89...=.. */

                                          0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, /* .ABCDEFG */
                                          0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, /* HIJKLMNO */
                                          0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, /* PQRSTUVW */
                                          0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff, /* XYZ..... */
                                          0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, /* .abcdefg */
                                          0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, /* hijklmno */
                                          0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, /* pqrstuvw */
                                          0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff, /* xyz..... */

                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,

                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

bool                 base64_character_set_contains(char c) { return __DEBASE64__[(uint8_t)c] != (uint8_t)0xff; }

/**
 * Decodes base64 into bytes
 * The output size must be at least size_in * 3/4
 *
 * @param buffer_in     base64 text
 * @param size_in       number of chars
 * @param buffer_out    output buffer of a size >= size_in * 3/4
 *
 * @return output size
 */

ya_result base64_decode(const char *buffer_in, uint32_t size_in, uint8_t *buffer_out)
{
    if((size_in & 3) != 0)
    {
        return PARSEB64_ERROR; // wrong number of bytes
    }

    uint8_t *in = (uint8_t *)buffer_in;
    uint8_t *out = buffer_out;

    while(size_in > 4)
    {
        uint8_t a = __DEBASE64__[*in++];
        uint8_t b = __DEBASE64__[*in++];
        uint8_t c = __DEBASE64__[*in++];
        uint8_t d = __DEBASE64__[*in++];

        if(((a | b | c | d) & 0x80) != 0x00)
        {
            /* PARSE ERROR */

            return PARSEB64_ERROR;
        }

        *out++ = (a << 2) | (b >> 4);
        *out++ = (b << 4) | (c >> 2);
        *out++ = (c << 6) | d;

        size_in -= 4;
    }

    if(size_in != 0) /* It's either 0 or 4 */
    {
        uint8_t a = __DEBASE64__[*in++];
        uint8_t b = __DEBASE64__[*in++];

        if(((a | b) & 0xc0) != 0x00)
        {
            /* PARSE ERROR */

            return PARSEB64_ERROR;
        }

        *out++ = (a << 2) | (b >> 4);

        uint8_t c = __DEBASE64__[*in++];
        if(c != __DEBASE64__STOP__)
        {
            if((c & 0xc0) != 0)
            {
                return PARSEB64_ERROR;
            }

            *out++ = (b << 4) | (c >> 2);

            uint8_t d = __DEBASE64__[*in++];

            if(d != __DEBASE64__STOP__)
            {
                if((d & 0xc0) != 0)
                {
                    return PARSEB64_ERROR;
                }

                *out++ = (c << 6) | d;
            }
        }
    }

    return out - buffer_out;
}

/**
 * Compares base64 with a binary image
 * The output size must be at least size_in * 3/4
 *
 * @param buffer_in     base64 text
 * @param size_in       number of chars
 * @param compared_to   buffer of size == size_in * 3/4
 *
 * @return 0 if it's a match, 1 if it isn't, or an error code
 *
 */

ya_result base64_equals_binary(const char *buffer_in, uint32_t size_in, const uint8_t *compared_to)
{
    if((size_in & 3) != 0)
    {
        return PARSEB64_ERROR; // wrong number of bytes
    }

    const uint8_t *in = (const uint8_t *)buffer_in;
    const uint8_t *ptr = compared_to;
    uint8_t        exp_ptr;

    while(size_in > 4)
    {
        uint8_t a = __DEBASE64__[*in++];
        uint8_t b = __DEBASE64__[*in++];
        uint8_t c = __DEBASE64__[*in++];
        uint8_t d = __DEBASE64__[*in++];

        if(((a | b | c | d) & 0x80) != 0x00)
        {
            /* PARSE ERROR */

            return PARSEB64_ERROR;
        }

        exp_ptr = ((a << 2) | (b >> 4));
        if((exp_ptr - *ptr) != 0)
        {
            return 1;
        }
        ++ptr;

        exp_ptr = ((b << 4) | (c >> 2));
        if((exp_ptr - *ptr) != 0)
        {
            return 1;
        }
        ++ptr;

        exp_ptr = ((c << 6) | d);
        if((exp_ptr - *ptr) != 0)
        {
            return 1;
        }
        ++ptr;

        size_in -= 4;
    }

    if(size_in != 0) /* It's either 0 or 4 */
    {
        uint8_t a = __DEBASE64__[*in++];
        uint8_t b = __DEBASE64__[*in++];

        if(((a | b) & 0xc0) != 0x00)
        {
            /* PARSE ERROR */

            return PARSEB64_ERROR;
        }

        exp_ptr = ((a << 2) | (b >> 4));
        if((exp_ptr - *ptr) != 0)
        {
            return 1;
        }
        ++ptr;

        uint8_t c = __DEBASE64__[*in++];
        if(c != __DEBASE64__STOP__)
        {
            if((c & 0xc0) != 0)
            {
                return PARSEB64_ERROR;
            }

            exp_ptr = ((b << 4) | (c >> 2));
            if((exp_ptr - *ptr) != 0)
            {
                return 1;
            }
            ++ptr;

            uint8_t d = __DEBASE64__[*in++];

            if(d != __DEBASE64__STOP__)
            {
                if((d & 0xc0) != 0)
                {
                    return PARSEB64_ERROR;
                }

                exp_ptr = ((c << 6) | d);
                if((exp_ptr - *ptr) != 0)
                {
                    return 1;
                }
                ++ptr;
            }
        }
    }

    return 0; // equals
}

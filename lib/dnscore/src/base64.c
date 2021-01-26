/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
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
 *------------------------------------------------------------------------------
 *
 */

/**
 *  @defgroup base Base conversion functions
 *  @ingroup dnscore
 *  @brief Base 64 codec
 *
 * Base 64 codec functions
 * 
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"

#include <stdio.h>

#include "dnscore/base64.h"

/*
 *
 */

#define BASE64_PADDING '='

static const char __BASE64__[256] ={
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/',

    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/',

    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/',

    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

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

u32
base64_encode(const u8* buffer_in, u32 size_in, char* buffer_out)
{
    char* ptr = buffer_out;

    while(size_in >= 3)
    {
        u8 b0 = *buffer_in++;
        u8 b1 = *buffer_in++;
        u8 b2 = *buffer_in++;

        *ptr++ = __BASE64__[ b0 >> 2 ];
        *ptr++ = __BASE64__[(u8)((b0 << 4) | (b1 >> 4))];
        *ptr++ = __BASE64__[(u8)((b1 << 2) | (b2 >> 6))];
        *ptr++ = __BASE64__[ b2 ];

        size_in -= 3;
    }

    switch(size_in)
    {
        case 2:
        {
            u8 b0 = *buffer_in++;
            u8 b1 = *buffer_in;
            *ptr++ = __BASE64__[ b0 >> 2 ];
            *ptr++ = __BASE64__[(u8)((b0 << 4) | (b1 >> 4))];
            *ptr++ = __BASE64__[(u8)(b1 << 2) ];
            *ptr++ = BASE64_PADDING;
            break;
        }
        case 1:
        {
            u8 b0 = *buffer_in;
            *ptr++ = __BASE64__[ b0 >> 2 ];
            *ptr++ = __BASE64__[ (u8)(b0 << 4) ];
            *ptr++ = BASE64_PADDING;
            *ptr++ = BASE64_PADDING;
            break;
        }
    }

    return (u32)(ptr - buffer_out);
}

#define __DEBASE64__STOP__ 0x80

static const u8 __DEBASE64__[256] ={
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /*  0 -  7 */
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

    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,

    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

bool
base64_character_set_contains(char c)
{
    return __DEBASE64__[(u8)c] != (u8)0xff;
}

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

ya_result
base64_decode(const char* buffer_in, u32 size_in, u8* buffer_out)
{
    if((size_in & 3) != 0)
    {
        return PARSEB64_ERROR; // wrong number of bytes
    }

    u8* in = (u8*)buffer_in;
    u8* out = buffer_out;

    while(size_in > 4)
    {
        u8 a = __DEBASE64__[*in++];
        u8 b = __DEBASE64__[*in++];
        u8 c = __DEBASE64__[*in++];
        u8 d = __DEBASE64__[*in++];

        if(((a | b | c | d)&0x80) != 0x00)
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
        u8 a = __DEBASE64__[*in++];
        u8 b = __DEBASE64__[*in++];

        if(((a | b)&0xc0) != 0x00)
        {
            /* PARSE ERROR */

            return PARSEB64_ERROR;
        }

        *out++ = (a << 2) | (b >> 4);

        u8 c = __DEBASE64__[*in++];
        if(c != __DEBASE64__STOP__)
        {
            if((c & 0xc0) != 0)
            {
                return PARSEB64_ERROR;
            }

            *out++ = (b << 4) | (c >> 2);

            u8 d = __DEBASE64__[*in++];

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

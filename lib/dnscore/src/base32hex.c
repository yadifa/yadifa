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
 * @brief Base 32 hex codec
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * Base 32-hex codec functions
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include <stdio.h>

#include "dnscore/base32hex.h"

/*
 *
 */

#define BASE32_HEX_PADDING '='

static const char __BASE32_HEX__[256] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
};

static const char __BASE32_HEX_LC__[256] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',

    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
};

/**
 * Encodes bytes into base32hex
 * The output size must be at least size_in * 8/5
 *
 * @param buffer_in     bytes to convert
 * @param size_in       number of bytes
 * @param buffer_out    output buffer of a size >= size_in * 8/5
 *
 * @return output size
 */

uint32_t base32hex_encode(const void *buffer_in_, uint32_t size_in, char *buffer_out)
{
    const uint8_t *buffer_in = (const uint8_t *)buffer_in_;
    char          *ptr = buffer_out;

    while(size_in >= 5)
    {
        uint8_t b0 = *buffer_in++;
        uint8_t b1 = *buffer_in++;
        uint8_t b2 = *buffer_in++;
        uint8_t b3 = *buffer_in++;
        uint8_t b4 = *buffer_in++;

        *ptr++ = __BASE32_HEX__[b0 >> 3];
        *ptr++ = __BASE32_HEX__[(uint8_t)((b0 << 2) | (b1 >> 6))];
        *ptr++ = __BASE32_HEX__[b1 >> 1];
        *ptr++ = __BASE32_HEX__[(uint8_t)((b1 << 4) | (b2 >> 4))];
        *ptr++ = __BASE32_HEX__[(uint8_t)((b2 << 1) | (b3 >> 7))];
        *ptr++ = __BASE32_HEX__[b3 >> 2];
        *ptr++ = __BASE32_HEX__[(uint8_t)((b3 << 3) | (b4 >> 5))];
        *ptr++ = __BASE32_HEX__[b4];

        size_in -= 5;
    }

    switch(size_in)
    {
        case 4:
        {
            uint8_t b0 = *buffer_in++;
            uint8_t b1 = *buffer_in++;
            uint8_t b2 = *buffer_in++;
            uint8_t b3 = *buffer_in++;

            *ptr++ = __BASE32_HEX__[b0 >> 3];
            *ptr++ = __BASE32_HEX__[(uint8_t)((b0 << 2) | (b1 >> 6))];
            *ptr++ = __BASE32_HEX__[b1 >> 1];
            *ptr++ = __BASE32_HEX__[(uint8_t)((b1 << 4) | (b2 >> 4))];
            *ptr++ = __BASE32_HEX__[(uint8_t)((b2 << 1) | (b3 >> 7))];
            *ptr++ = __BASE32_HEX__[b3 >> 2];

            *ptr++ = __BASE32_HEX__[(uint8_t)(b3 << 3)];
            *ptr++ = BASE32_HEX_PADDING;
            break;
        }
        case 3:
        {
            uint8_t b0 = *buffer_in++;
            uint8_t b1 = *buffer_in++;
            uint8_t b2 = *buffer_in++;

            *ptr++ = __BASE32_HEX__[b0 >> 3];
            *ptr++ = __BASE32_HEX__[(uint8_t)((b0 << 2) | (b1 >> 6))];
            *ptr++ = __BASE32_HEX__[b1 >> 1];
            *ptr++ = __BASE32_HEX__[(uint8_t)((b1 << 4) | (b2 >> 4))];

            *ptr++ = __BASE32_HEX__[(uint8_t)(b2 << 1)];
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            break;
        }
        case 2:
        {
            uint8_t b0 = *buffer_in++;
            uint8_t b1 = *buffer_in++;

            *ptr++ = __BASE32_HEX__[b0 >> 3];
            *ptr++ = __BASE32_HEX__[(uint8_t)((b0 << 2) | (b1 >> 6))];
            *ptr++ = __BASE32_HEX__[b1 >> 1];

            *ptr++ = __BASE32_HEX__[(uint8_t)(b1 << 4)];
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            break;
        }
        case 1:
        {
            uint8_t b0 = *buffer_in++;

            *ptr++ = __BASE32_HEX__[b0 >> 3];
            *ptr++ = __BASE32_HEX__[(uint8_t)(b0 << 2)];

            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            break;
        }
    }

    return (uint32_t)(ptr - buffer_out);
}

uint32_t base32hex_encode_lc(const void *buffer_in_, uint32_t size_in, char *buffer_out)
{
    const uint8_t *buffer_in = (const uint8_t *)buffer_in_;
    char          *ptr = buffer_out;

    while(size_in >= 5)
    {
        uint8_t b0 = *buffer_in++;
        uint8_t b1 = *buffer_in++;
        uint8_t b2 = *buffer_in++;
        uint8_t b3 = *buffer_in++;
        uint8_t b4 = *buffer_in++;

        *ptr++ = __BASE32_HEX_LC__[b0 >> 3];
        *ptr++ = __BASE32_HEX_LC__[(uint8_t)((b0 << 2) | (b1 >> 6))];
        *ptr++ = __BASE32_HEX_LC__[b1 >> 1];
        *ptr++ = __BASE32_HEX_LC__[(uint8_t)((b1 << 4) | (b2 >> 4))];
        *ptr++ = __BASE32_HEX_LC__[(uint8_t)((b2 << 1) | (b3 >> 7))];
        *ptr++ = __BASE32_HEX_LC__[b3 >> 2];
        *ptr++ = __BASE32_HEX_LC__[(uint8_t)((b3 << 3) | (b4 >> 5))];
        *ptr++ = __BASE32_HEX_LC__[b4];

        size_in -= 5;
    }

    switch(size_in)
    {
        case 4:
        {
            uint8_t b0 = *buffer_in++;
            uint8_t b1 = *buffer_in++;
            uint8_t b2 = *buffer_in++;
            uint8_t b3 = *buffer_in++;

            *ptr++ = __BASE32_HEX_LC__[b0 >> 3];
            *ptr++ = __BASE32_HEX_LC__[(uint8_t)((b0 << 2) | (b1 >> 6))];
            *ptr++ = __BASE32_HEX_LC__[b1 >> 1];
            *ptr++ = __BASE32_HEX_LC__[(uint8_t)((b1 << 4) | (b2 >> 4))];
            *ptr++ = __BASE32_HEX_LC__[(uint8_t)((b2 << 1) | (b3 >> 7))];
            *ptr++ = __BASE32_HEX_LC__[b3 >> 2];

            *ptr++ = __BASE32_HEX_LC__[(uint8_t)(b3 << 3)];
            *ptr++ = BASE32_HEX_PADDING;
            break;
        }
        case 3:
        {
            uint8_t b0 = *buffer_in++;
            uint8_t b1 = *buffer_in++;
            uint8_t b2 = *buffer_in++;

            *ptr++ = __BASE32_HEX_LC__[b0 >> 3];
            *ptr++ = __BASE32_HEX_LC__[(uint8_t)((b0 << 2) | (b1 >> 6))];
            *ptr++ = __BASE32_HEX_LC__[b1 >> 1];
            *ptr++ = __BASE32_HEX_LC__[(uint8_t)((b1 << 4) | (b2 >> 4))];

            *ptr++ = __BASE32_HEX_LC__[(uint8_t)(b2 << 1)];
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            break;
        }
        case 2:
        {
            uint8_t b0 = *buffer_in++;
            uint8_t b1 = *buffer_in++;

            *ptr++ = __BASE32_HEX_LC__[b0 >> 3];
            *ptr++ = __BASE32_HEX_LC__[(uint8_t)((b0 << 2) | (b1 >> 6))];
            *ptr++ = __BASE32_HEX_LC__[b1 >> 1];

            *ptr++ = __BASE32_HEX_LC__[(uint8_t)(b1 << 4)];
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            break;
        }
        case 1:
        {
            uint8_t b0 = *buffer_in++;

            *ptr++ = __BASE32_HEX_LC__[b0 >> 3];
            *ptr++ = __BASE32_HEX_LC__[(uint8_t)(b0 << 2)];

            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            *ptr++ = BASE32_HEX_PADDING;
            break;
        }
    }

    return (uint32_t)(ptr - buffer_out);
}

#define __DEBASE32_HEX__STOP__ 0x80

static const uint8_t __DEBASE32_HEX__[256] = {0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff, /*  0 -  7 */
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff, /*  8 - 15 */
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff, /* 16 - 23 */
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff, /* 24 - 31 */
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff, /* 32 - 39 */
                                              0xff,
                                              0xff,
                                              0xff,
                                              0x3e,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0x3f, /* 40 - 47 ...+.../ */
                                              0x00,
                                              0x01,
                                              0x02,
                                              0x03,
                                              0x04,
                                              0x05,
                                              0x06,
                                              0x07, /* 01234567 */
                                              0x08,
                                              0x09,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0x80,
                                              0xff,
                                              0xff, /* 89...=.. */

                                              0xff,
                                              0x0a,
                                              0x0b,
                                              0x0c,
                                              0x0d,
                                              0x0e,
                                              0x0f,
                                              0x10, /* .ABCDEFG */
                                              0x11,
                                              0x12,
                                              0x13,
                                              0x14,
                                              0x15,
                                              0x16,
                                              0x17,
                                              0x18, /* HIJKLMNO */
                                              0x19,
                                              0x1a,
                                              0x1b,
                                              0x1c,
                                              0x1d,
                                              0x1e,
                                              0x1f,
                                              0xff, /* PQRSTUVW */
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff, /* XYZ..... */
                                              0xff,
                                              0x0a,
                                              0x0b,
                                              0x0c,
                                              0x0d,
                                              0x0e,
                                              0x0f,
                                              0x10,
                                              /* .abcdefg */ /* Added to support NSD */
                                              0x11,
                                              0x12,
                                              0x13,
                                              0x14,
                                              0x15,
                                              0x16,
                                              0x17,
                                              0x18, /* hijklmno */
                                              0x19,
                                              0x1a,
                                              0x1b,
                                              0x1c,
                                              0x1d,
                                              0x1e,
                                              0x1f,
                                              0xff, /* pqrstuvw */
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff, /* xyz..... */

                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,

                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff,
                                              0xff};

/**
 * Decodes base32hex into bytes
 * The output size must be at least size_in * 5/8
 *
 * @param buffer_in     base32hex text
 * @param size_in       number of chars
 * @param buffer_out    output buffer of a size >= size_in * 5/8
 *
 * @return output size
 */

ya_result base32hex_decode(const char *buffer_in, uint32_t size_in, uint8_t *buffer_out)
{
    if((size_in & 7) != 0)
    {
        return PARSEB32H_ERROR; // wrong number of bytes
    }

    uint8_t *in = (uint8_t *)buffer_in;
    uint8_t *out = buffer_out;

    while(size_in > 8)
    {
        uint8_t a = __DEBASE32_HEX__[*in++];
        uint8_t b = __DEBASE32_HEX__[*in++];
        uint8_t c = __DEBASE32_HEX__[*in++];
        uint8_t d = __DEBASE32_HEX__[*in++];
        uint8_t e = __DEBASE32_HEX__[*in++];
        uint8_t f = __DEBASE32_HEX__[*in++];
        uint8_t g = __DEBASE32_HEX__[*in++];
        uint8_t h = __DEBASE32_HEX__[*in++];

        if(((a | b | c | d | e | f | g | h) & 0x40) != 0x00)
        {
            /* PARSE ERROR */

            return PARSEB32H_ERROR;
        }

        *out++ = (a << 3) | (b >> 2);
        *out++ = (b << 6) | (c << 1) | (d >> 4);
        *out++ = (d << 4) | (e >> 1);
        *out++ = (e << 7) | (f << 2) | (g >> 3);
        *out++ = (g << 5) | h;

        size_in -= 8;
    }

    if(size_in != 0) /* It's either 0 or 4 */
    {
        uint8_t a = __DEBASE32_HEX__[*in++];
        uint8_t b = __DEBASE32_HEX__[*in++];

        if(((a | b) & 0xc0) != 0x00)
        {
            /* PARSE ERROR */

            return PARSEB32H_ERROR;
        }

        *out++ = (a << 3) | (b >> 2);

        uint8_t c = __DEBASE32_HEX__[*in++];
        uint8_t d = __DEBASE32_HEX__[*in++];

        if((c != __DEBASE32_HEX__STOP__) && (d != __DEBASE32_HEX__STOP__))
        {
            if(((c | d) & 0x40) != 0)
            {
                return PARSEB32H_ERROR;
            }

            *out++ = (b << 6) | (c << 1) | (d >> 4);

            uint8_t e = __DEBASE32_HEX__[*in++];

            if(e != __DEBASE32_HEX__STOP__)
            {
                if((e & 0x40) != 0)
                {
                    return PARSEB32H_ERROR;
                }

                *out++ = (d << 4) | (e >> 1);

                uint8_t f = __DEBASE32_HEX__[*in++];
                uint8_t g = __DEBASE32_HEX__[*in++];

                if((f != __DEBASE32_HEX__STOP__) && (g != __DEBASE32_HEX__STOP__))
                {
                    if(((f | g) & 0x40) != 0)
                    {
                        return PARSEB32H_ERROR;
                    }

                    *out++ = (e << 7) | (f << 2) | (g >> 3);

                    uint8_t h = __DEBASE32_HEX__[*in++];

                    if(h != __DEBASE32_HEX__STOP__)
                    {
                        if((h & 0x40) != 0)
                        {
                            return PARSEB32H_ERROR;
                        }

                        *out++ = (g << 5) | h;
                    }
                }
            }
        }
    }

    return out - buffer_out;
}

/**
 * encodes the buffer into base32hex to the output stream
 *
 * @param os        output stream
 * @param buffer_in buffer to encode
 * @param size_in   size of the buffer
 *
 * @return bytes written
 */

ya_result output_stream_write_base32hex(output_stream_t *os, const void *buffer_in_, uint32_t size_in)
{
    const uint8_t *buffer_in = (const uint8_t *)buffer_in_;
    ya_result      total = ((size_in + (BASE32HEX_DECODED_CHUNK - 1)) / BASE32HEX_DECODED_CHUNK) * BASE32HEX_ENCODED_CHUNK;

    char           tmp[8];

    while(size_in >= BASE32HEX_DECODED_CHUNK)
    {
        /* this cannot fail */
        base32hex_encode(buffer_in, BASE32HEX_DECODED_CHUNK, tmp);

        output_stream_write(os, (uint8_t *)tmp, BASE32HEX_ENCODED_CHUNK);
        buffer_in += BASE32HEX_DECODED_CHUNK;
        size_in -= BASE32HEX_DECODED_CHUNK;
    }

    ya_result return_code;

    /* doing the general case in the if block results into faster code */

    if(ISOK(return_code = output_stream_write(os, (uint8_t *)tmp, base32hex_encode(buffer_in, size_in, tmp))))
    {
        return total;
    }

    return return_code;
}

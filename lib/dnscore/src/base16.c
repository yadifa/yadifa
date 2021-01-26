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

/** @defgroup base Base conversion functions
 *  @ingroup dnscore
 *  @brief Base 16 codec
 * 
 * Base 16 codec functions
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"
#include <stdio.h>

#include "dnscore/sys_types.h"

static const u8 __BASE16__[16] ={
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

/**
 * Encodes bytes into base16
 * The output size must be at least size_in * 2
 * 
 * @param buffer_in     bytes to convert
 * @param size_in       number of bytes
 * @param buffer_out    output buffer of a size >= size_in * 2
 * 
 * @return output size
 */

u32
base16_encode(const u8* buffer_in, u32 size_in, char* buffer_out)
{
    u32 ret = size_in << 1;

    while(size_in > 0)
    {
        u8 c = *buffer_in++;

        *buffer_out++ = __BASE16__[c >> 4];
        *buffer_out++ = __BASE16__[c & 0x0f];

        size_in--;
    }

    return ret;
}

static const u8 __DEBASE16__[256] ={
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /*  0 -  7 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /*  8 - 15 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 16 - 23 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 24 - 31 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 32 - 39 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 40 - 47 ...+.../ */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* 01234567 */
    0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 89...=.. */

    0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, /* .ABCDEFG */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* HIJKLMNO */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* PQRSTUVW */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* XYZ..... */
    0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, /* .abcdefg */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* hijklmno */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* pqrstuvw */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* xyz..... */

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

/**
 * Decodes base16 into bytes
 * The output size must be at least size_in / 2
 * 
 * @param buffer_in     base16 text
 * @param size_in       number of chars
 * @param buffer_out    output buffer of a size >= size_in / 2
 * 
 * @return output size
 */

ya_result
base16_decode(const char *buffer_in, u32 size_in, u8 *buffer_out)
{
    if((size_in & 1) != 0)
    {
        return PARSEB16_ERROR; // wrong number of bytes
    }
    
    u8* in = (u8*)buffer_in;
    u8* out = buffer_out;

    while(size_in > 0)
    {
        u8 h = __DEBASE16__[*in++];
        u8 l = __DEBASE16__[*in++];

        if(((h | l) & 0x80) != 0)
        {
            return PARSEB16_ERROR;
        }

        *out++ = (h << 4) | l;
        size_in -= 2;
    }

    return (out - buffer_out);
}

u8 base16_decode_nibble(char nibble)
{
    return __DEBASE16__[(ssize_t)nibble];
}

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

#include "dnscore/utf8.h"

/**
 * @fn static inline int utf8_encode_char32()
 * @brief
 *
 * @details
 * Encodes a character to the output
 * Returns the number of bytes written
 * Can only write values from 0 to 0x10ffff, incuded.
 *
 * @param[in] character the character to encode
 * @param[out] out_text the text to write the encoded character to
 * @return the number of bytes written, 0 if the character is out of range
 */

int utf8_encode_char32(uint32_t character, uint8_t *out_text)
{
    if(character < 0x80)
    {
        *out_text = (uint8_t)character;
        return 1;
    }
    if(character < 0x800)
    {
        out_text[0] = (0xc0 | (character >> 6));
        out_text[1] = (0x80 | (character & 0x3f));
        return 2;
    }
    if(character < 0x10000)
    {
        out_text[0] = (0xe0 | (character >> 12));
        out_text[1] = (0x80 | ((character >> 6) & 0x3f));
        out_text[2] = (0x80 | (character & 0x3f));
        return 3;
    }
    if(character < 0x110000)
    {
        out_text[0] = (0xf0 | (character >> 18));
        out_text[1] = (0x80 | ((character >> 12) & 0x3f));
        out_text[2] = (0x80 | ((character >> 6) & 0x3f));
        out_text[3] = (0x80 | (character & 0x3f));
        return 4;
    }

    return 0; // not encoded (out of the covered UTF-8 space)
}

/**
 * @fn static inline int utf8_next_char32()
 * @brief
 *
 * @details
 * Decodes the next character from the UTF-8 text
 * Returns the number of decoded chars
 * Checks the integrity of input
 * In case of error, returns 0
 *
 * @param text the UTF-8 text
 * @param out_char a pointer to receive the next character read from input
 *
 * @return the number of bytes read from the text, 0 if it failed
 */

int utf8_next_char32(const uint8_t *text, uint32_t *out_char)
{
    uint8_t c = *text;

    if((c & 0x80) == 0)
    {
        *out_char = c;
        return 1;
    }

    if((c & 0xe0) == 0xc0)
    {
        uint32_t tmp = c & 0x1f;
        c = *++text;
        if((c & 0xc0) == 0x80)
        {
            tmp <<= 6;
            tmp |= c & 0x3f;

            *out_char = tmp;

            return 2;
        }

        return 0;
    }

    if((c & 0xf0) == 0xe0)
    {
        uint32_t tmp = c & 0xf;
        c = *++text;
        if((c & 0xc0) == 0x80)
        {
            tmp <<= 6;
            tmp |= c & 0x3f;
            c = *++text;
            if((c & 0xc0) == 0x80)
            {
                tmp <<= 6;
                tmp |= c & 0x3f;

                *out_char = tmp;

                return 3;
            }
        }

        return 0;
    }

    if((c & 0xf8) == 0xf0)
    {
        uint32_t tmp = c & 0xf;
        c = *++text;
        if((c & 0xc0) == 0x80)
        {
            tmp <<= 6;
            tmp |= c & 0x3f;
            c = *++text;
            if((c & 0xc0) == 0x80)
            {
                tmp <<= 6;
                tmp |= c & 0x3f;

                c = *++text;
                if((c & 0xc0) == 0x80)
                {
                    tmp <<= 6;
                    tmp |= c & 0x3f;

                    *out_char = tmp;

                    return 4;
                }
            }
        }
    }

    return 0;
}

/**
 * @fn static inline ya_result utf8_next_char32_from_stream()
 * @brief
 *
 * @details
 * Decodes the next character from the UTF-8 text
 * Returns the number of decoded chars
 * Checks the integrity of input
 * In case of error, returns 0
 *
 * @param text the UTF-8 text
 * @param out_char a pointer to receive the next character read from input
 *
 * @return the number of bytes read from the text, 0 if it failed
 */

ya_result utf8_next_char32_from_stream(input_stream_t *is, uint32_t *out_char)
{
    ya_result ret;
    uint8_t   c;

    if(FAIL(ret = input_stream_read_u8(is, &c)))
    {
        return ret;
    }

    if((c & 0x80) == 0)
    {
        *out_char = c;
        return 1;
    }

    if((c & 0xe0) == 0xc0)
    {
        uint32_t tmp = c & 0x1f;
        if(FAIL(ret = input_stream_read_u8(is, &c)))
        {
            return ret;
        }

        if((c & 0xc0) == 0x80)
        {
            tmp <<= 6;
            tmp |= c & 0x3f;

            *out_char = tmp;

            return 2;
        }

        return 0;
    }

    if((c & 0xf0) == 0xe0)
    {
        uint32_t tmp = c & 0xf;
        if(FAIL(ret = input_stream_read_u8(is, &c)))
        {
            return ret;
        }
        if((c & 0xc0) == 0x80)
        {
            tmp <<= 6;
            tmp |= c & 0x3f;
            if(FAIL(ret = input_stream_read_u8(is, &c)))
            {
                return ret;
            }
            if((c & 0xc0) == 0x80)
            {
                tmp <<= 6;
                tmp |= c & 0x3f;

                *out_char = tmp;

                return 3;
            }
        }

        return 0;
    }

    if((c & 0xf8) == 0xf0)
    {
        uint32_t tmp = c & 0xf;
        if(FAIL(ret = input_stream_read_u8(is, &c)))
        {
            return ret;
        }
        if((c & 0xc0) == 0x80)
        {
            tmp <<= 6;
            tmp |= c & 0x3f;
            if(FAIL(ret = input_stream_read_u8(is, &c)))
            {
                return ret;
            }
            if((c & 0xc0) == 0x80)
            {
                tmp <<= 6;
                tmp |= c & 0x3f;

                if(FAIL(ret = input_stream_read_u8(is, &c)))
                {
                    return ret;
                }
                if((c & 0xc0) == 0x80)
                {
                    tmp <<= 6;
                    tmp |= c & 0x3f;

                    *out_char = tmp;

                    return 4;
                }
            }
        }
    }

    return 0;
}

ya_result utf8_read_line(input_stream_t *is, uchar_t *buffer, uint32_t len)
{
    uchar_t             *p = buffer;
    const uchar_t *const limit = &buffer[len];
    uint32_t             chr;

    while(p < limit)
    {
        if(utf8_next_char32_from_stream(is, &chr) <= 0) // do not replace by the uchar
        {
            return p - buffer;
        }

        if(chr == '\r') // scan-build false positive : the only way this is not initialised is if the call to
                        // utf8_next_char32_from_stream returned < 0
        {               // however, if <= 0 is already handled right above ( <= 0 )
            continue;
        }

        *p++ = (uchar_t)chr;

        // output_stream_write_u8(termout, chr);

        if(chr == '\n')
        {
            return p - buffer;
        }
    }

    return BUFFER_WOULD_OVERFLOW;
}

ya_result utf8_write_unicode(output_stream_t *os, uchar_t *buffer, uint32_t len)
{
    uchar_t             *p = buffer;
    const uchar_t *const limit = &buffer[len];
    int                  total = 0;
    int                  text_len;
    uint8_t              text[4];

    while(p < limit)
    {
        uint32_t  chr = *p++;
        ya_result ret;
        text_len = utf8_encode_char32(chr, text);
        if(ISOK(ret = output_stream_write(os, text, text_len)))
        {
            total += ret;
        }
        else
        {
            return ret;
        }
    }

    return total;
}

/**
 * @fn static inline int utf8_next_char16()
 * @brief
 *
 * @details
 * Decodes the next character from the UTF-8 text
 * Returns the number of decoded chars
 * Checks the integrity of input
 * In case of error, returns 0
 *
 * @param text the UTF-8 text
 * @param out_char a pointer to receive the next character read from input
 *
 * @return the number of bytes read from the text, 0 if it failed
 */

int utf8_next_char16(const uint8_t *text, uint16_t *out_char)
{
    uint8_t c = *text;

    if((c & 0x80) == 0)
    {
        *out_char = c;
        return 1;
    }

    if((c & 0xe0) == 0xc0)
    {
        uint32_t tmp = c & 0x1f;
        c = *++text;
        if((c & 0xc0) == 0x80)
        {
            tmp <<= 6;
            tmp |= c & 0x3f;

            *out_char = (uint16_t)tmp;

            return 2;
        }

        return 0;
    }

    if((c & 0xf0) == 0xe0)
    {
        uint32_t tmp = c & 0xf;
        c = *++text;
        if((c & 0xc0) == 0x80)
        {
            tmp <<= 6;
            tmp |= c & 0x3f;
            c = *++text;
            if((c & 0xc0) == 0x80)
            {
                tmp <<= 6;
                tmp |= c & 0x3f;

                *out_char = tmp;

                return 3;
            }
        }
    }

    return 0;
}

/**
 * @fn static inline int utf8_next_char32_nocheck()
 * @brief
 *
 * @details
 * Decodes the next character from the UTF-8 text
 * Returns the number of decoded chars
 * Assumes the input is perfect.
 *
 * @param text the UTF-8 text
 * @param out_char a pointer to receive the next character read from input
 * @return the number of bytes read from the text
 */

int utf8_next_char32_nocheck(const uint8_t *text, uchar_t *out_char)
{
    uint8_t c = *text;

    if((c & 0x80) == 0)
    {
        *out_char = c;
        return 1;
    }

    if((c & 0xe0) == 0xc0)
    {
        uint32_t tmp = c & 0x1f;

        c = *++text;
        tmp <<= 6;
        tmp |= c & 0x3f;

        *out_char = tmp;

        return 2;
    }

    if((c & 0xf0) == 0xe0)
    {
        uint32_t tmp = c & 0xf;

        c = *++text;
        tmp <<= 6;
        tmp |= c & 0x3f;

        c = *++text;
        tmp <<= 6;
        tmp |= c & 0x3f;

        *out_char = tmp;

        return 3;
    }

    // ((c & 0xf8) == 0xf0)

    uint32_t tmp = c & 0xf;

    c = *++text;
    tmp <<= 6;
    tmp |= c & 0x3f;

    c = *++text;
    tmp <<= 6;
    tmp |= c & 0x3f;

    c = *++text;
    tmp <<= 6;
    tmp |= c & 0x3f;

    *out_char = tmp;

    return 4;
}

/**
 * @fn static inline int utf8_next_char16_nocheck()
 * @brief
 *
 * @details
 * Decodes the next character from the UTF-8 text
 * Returns the number of decoded chars
 * Assumes the input is perfect and in the 0 to 0xffff range
 *
 * @param text the UTF-8 text
 * @param out_char a pointer to receive the next character read from input
 * @return the number of bytes read from the text
 */

int utf8_next_char16_nocheck(const uint8_t *text, uint16_t *out_char)
{
    uint8_t c = *text;

    if((c & 0x80) == 0)
    {
        *out_char = c;
        return 1;
    }

    if((c & 0xe0) == 0xc0)
    {
        uint16_t tmp = c & 0x1f;

        c = *++text;
        tmp <<= 6;
        tmp |= c & 0x3f;

        *out_char = tmp;

        return 2;
    }

    // (c & 0xf0) == 0xe0)

    uint16_t tmp = c & 0xf;

    c = *++text;
    tmp <<= 6;
    tmp |= c & 0x3f;

    c = *++text;
    tmp <<= 6;
    tmp |= c & 0x3f;

    *out_char = tmp;

    return 3;
}

const uint8_t *utf8_strchr(const uint8_t *line, uchar_t seek_char)
{
    for(;;)
    {
        uint32_t next_char;

        int      n = utf8_next_char32(line, &next_char);
        if(n < 1)
        {
            line = NULL;
            break;
        }

        if(next_char == seek_char)
        {
            break;
        }

        if(next_char == 0)
        {
            break;
        }

        line += n;
    }

    return line;
}

int utf8_strcmp(const uint8_t *a, const uint8_t *b)
{
    uint32_t a_char;
    uint32_t b_char;

    for(;;)
    {
        a_char = 0;
        b_char = 0;

        int a_char_len = utf8_next_char32(a, &a_char);
        utf8_next_char32(b, &b_char);

        int d = (int)a_char - (int)b_char;

        if(d != 0)
        {
            return d;
        }

        if(a_char == 0)
        {
            return 0;
        }
        a += a_char_len;
        b += a_char_len;
    }
}

int utf8_memcmp(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len)
{
    uint32_t a_char;
    uint32_t b_char;

    size_t   len = MIN(a_len, b_len);

    for(size_t i = 0; i < len;)
    {
        a_char = 0;
        int a_char_len = utf8_next_char32(a, &a_char);
        b_char = 0;
        utf8_next_char32(b, &b_char);

        int d = (int)a_char - (int)b_char;

        if(d != 0)
        {
            return d;
        }

        if(a_char == 0)
        {
            break;
        }

        a += a_char_len;
        b += a_char_len;

        i += a_char_len;
    }

    return (int)a_len - (int)b_len;
}

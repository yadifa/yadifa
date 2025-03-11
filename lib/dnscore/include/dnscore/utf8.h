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

#ifndef UTF8_H
#define UTF8_H

// #include <dnscore/unicode.h>

#ifdef __cplusplus
extern "C"
{
#endif

#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>

#define UCHAR_SIZE 32 // bits

#if UCHAR_SIZE == 32
typedef uint32_t uchar_t;
#define UCHAR_MAX U32_MAX
#elif UCHAR_SIZE == 16
typedef uint16_t uchar_t;
#define UCHAR_MAX U16_MAX
#else
#error "only UCHAR_SIZE of 16 and 32 bits are supported"
#endif

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

int               utf8_encode_char32(uint32_t character, uint8_t *out_text);

static inline int utf8_encode_char32_len(uint32_t character)
{
    if(character < 0x80)
    {
        return 1;
    }
    if(character < 0x800)
    {
        return 2;
    }
    if(character < 0x10000)
    {
        return 3;
    }
    if(character < 0x110000)
    {
        return 4;
    }

    return 0; // not encoded (out of the covered UTF-8 space)
}

/**
 * @fn static inline int utf8_encode_char16()
 * @brief
 *
 * @details
 * Encodes a character to the output
 * Returns the number of bytes written
 * Can only write values from 0 to 0xffff, incuded.
 *
 * @param character the character to encode
 * @param out_text the text to write the encoded character to
 * @return the number of bytes written
 */

static inline int utf8_encode_char16(uint16_t character, uint8_t *out_text)
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

    out_text[0] = (0xe0 | (character >> 12));
    out_text[1] = (0x80 | ((character >> 6) & 0x3f));
    out_text[2] = (0x80 | (character & 0x3f));

    return 3;
}

static inline int utf8_encode_char16_len(uint16_t character)
{
    if(character < 0x80)
    {
        return 1;
    }
    if(character < 0x800)
    {
        return 2;
    }
    return 3;
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

int utf8_next_char32(const uint8_t *text, uint32_t *out_char);

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

ya_result utf8_next_char32_from_stream(input_stream_t *is, uint32_t *out_char);

ya_result utf8_read_line(input_stream_t *is, uchar_t *buffer, uint32_t len);

ya_result utf8_write_unicode(output_stream_t *os, uchar_t *buffer, uint32_t len);

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

int utf8_next_char16(const uint8_t *text, uint16_t *out_char);

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

int utf8_next_char32_nocheck(const uint8_t *text, uchar_t *out_char);

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

int utf8_next_char16_nocheck(const uint8_t *text, uint16_t *out_char);

#if UCHAR_SIZE == 32

static inline int utf8_encode_uchar(uchar_t character, uint8_t *out_text) { return utf8_encode_char32(character, out_text); }

/**
 * @fn static inline int utf8_encode_uchar_len()
 * @brief
 *
 * @details

 * @param[in] uchar_t character
 *
 */
static inline int    utf8_encode_uchar_len(uchar_t character) { return utf8_encode_char32_len(character); }

static inline size_t utf8_encoded_text_len(const uchar_t *text, size_t len)
{
    size_t ret = 0;
    for(size_t i = 0; i < len; ++i)
    {
        ret += utf8_encode_char32_len(text[i]);
    }
    return ret;
}

static inline void utf8_encode_text(const uchar_t *text, size_t len, uint8_t *dest)
{
    for(size_t i = 0; i < len; ++i)
    {
        int n = utf8_encode_uchar(text[i], dest);
        dest += n;
    }
    *dest = 0;
}

/**
 * @fn static inline ya_result utf8_next_uchar_from_stream()
 * @brief
 *
 * @details

 * @param[out] input_stream *is
 * @param[in] uchar_t *out_char
 *
 */

static inline ya_result utf8_next_uchar_from_stream(input_stream_t *is, uchar_t *out_char) { return utf8_next_char32_from_stream(is, out_char); }

/**
 * @fn static inline int utf8_next_uchar()
 * @brief
 *
 * @details

 * @param[out] const uint8_t *text
 * @param[in] uchar_t *out_char
 *
 */
static inline int utf8_next_uchar(const uint8_t *text, uchar_t *out_char) { return utf8_next_char32(text, out_char); }

#elif UCHAR_SIZE == 16

static inline int       utf8_encode_uchar(uchar_t character, uint8_t *out_text) { return utf8_encode_char16(character, out_text); }

static inline int       utf8_encode_uchar_len(uchar_t character) { return utf8_encode_char16_len(character); }

static inline ya_result utf8_next_uchar_from_stream(input_stream *is, uchar_t *out_char) { return utf8_next_char16_from_stream(is, out_char) }

static inline int       utf8_next_uchar(const uint8_t *text, uchar_t *out_char) { return utf8_next_char16(text, out_char); }

#else
#error "your UCHAR_SIZE is wrong"
#endif

/**
 * @fn static inline int utf8_print_uchar()
 * @brief Append unicode characters to the output stream
 *
 * @details

 * @param[out] output_stream *os
 * @param[in] const uchar_t character
 *
 */
static inline int utf8_print_uchar(output_stream_t *os, uchar_t character)
{
    uint8_t tmp_utf8[4];
    int     len = utf8_encode_uchar(character, tmp_utf8);
    if(len > 0)
    {
        output_stream_write(os, tmp_utf8, len);
    }
    return len;
}

/**
 * @fn static inline void utf8_output_stream_write()
 * @brief Append unicode text to the output stream
 *
 * @details

 * @param[out] output_stream *os
 * @param[in] const uchar_t *text
 * @param[in] size_t size
 *
 */

static inline void utf8_output_stream_write(output_stream_t *os, const uchar_t *text, size_t size)
{
    const uchar_t *limit = &text[size];
    while(text < limit)
    {
        utf8_print_uchar(os, *text++);
    }
}

const uint8_t *utf8_strchr(const uint8_t *line, uchar_t seek_char);

/**
 * Silly function decoding utf-8 for comparison.
 * Use strcmp instead.
 */

int utf8_strcmp(const uint8_t *a, const uint8_t *b);

/**
 * Silly function decoding utf-8 for comparison.
 * Use memcmp instead.
 */

int utf8_memcmp(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len);

#ifdef __cplusplus
}
#endif

#endif /* UTF8_H */

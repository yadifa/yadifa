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

/**-----------------------------------------------------------------------------
 * @defgroup dnscoretools Generic Tools
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#ifndef _PARSING_H
#define _PARSING_H

#include <ctype.h>
#include <dnscore/sys_types.h>

#define BASE_10 10

struct host_address_s;

#ifdef __cplusplus
extern "C"
{
#endif

/** \brief A string will be checked
 *
 *  The number will be extracted from the string if present. This number can
 *  be 10-based, or hex-based, or...\n
 *  The base must be between 2 and 36 and the number must be be between the min
 *  values and max value
 *
 *  @param[in]  src  string with number part in it
 *  @param[out] dst  number found
 *  @param[in]  min
 *  @param[in]  max
 *  @param[in]  base
 *
 *  @retval OK
 *  @retval NOK, if no digits found, or number not in the range
 */
ya_result parse_u32_check_range(const char *src, uint32_t *dst, uint32_t min, uint32_t max, uint8_t base);

ya_result parse_u32_check_range_len_base10(const char *src, uint32_t src_len, uint32_t *dst, uint32_t min, uint32_t max);

ya_result parse_s32_check_range_len_base10(const char *src, uint32_t src_len, int32_t *dst, int32_t min, int32_t max);

/** \brief A string will be extracted and checked
 *
 *  The number will be extracted from the string if present.
 *
 *  @param[in]  src  string with number part in it
 *  @param[in]  src_len string length
 *  @param[out] dst  number found
 *  @param[in]  min
 *  @param[in]  max
 *
 *  @retval OK
 *  @retval PARSEINT_ERROR, if no digits found, or number not in the range
 */
ya_result parse_u64_check_range_len_base10(const char *src, uint32_t src_len, uint64_t *dst, uint64_t min, uint64_t max);

/** \brief A string will be extracted and checked
 *
 *  The number will be extracted from the string if present.
 *
 *  @param[in]  src  string with number part in it
 *  @param[in]  src_len string length
 *  @param[out] dst  number found
 *  @param[in]  min
 *  @param[in]  max
 *
 *  @retval OK
 *  @retval PARSEINT_ERROR, if no digits found, or number not in the range
 */

ya_result parse_u64_check_range_len_base16(const char *src, uint32_t src_len, uint64_t *dst, uint64_t min, uint64_t max);

/**
 *  Reads a ("-quoted) string from the source.
 *  Makes it into a pascal string on the destination.
 *  After the call, the source pointer is updated to after the parsed string.
 *
 *  @param src  a pointer to input text
 *  @param src_len size of the input buffer
 *  @param dst  output buffer
 *  @param dst_len size of the output buffer
 *
 *  @retval an error code
 */

ya_result parse_pstring(char **srcp_in_out, size_t src_len, uint8_t *dst, size_t dst_len);

/** \brief Converts a string to an epoch
 *
 *  Converts a string to an epoch
 *
 *  @param[in]  src  string in the form YYYYMMDDhhmmss
 *  @param[out] dst  value of the source converted into GMT epoch
 *
 *  @retval OK
 *  @retval NOK, if no digits found, or number not in the range
 */

ya_result parse_yyyymmddhhmmss_check_range_len(const char *src, uint32_t src_len, time_t *dst);

ya_result parse_yyyymmddhhmmss_check_range(const char *src, time_t *dst);

/** \brief Copies and trim a string
 *
 *  Copies a string while remove head & tail spaces and reducing any blank run to a single space
 *  The source does not need to be asciiz
 *  The destination will be asciiz
 *
 *  @param[in] src      string
 *  @param[in] src_len  size of the string (the zero sentinel is not checked)
 *  @param[in] dst      buffer that will receive the output string
 *  @param[in] dst_len  size of the buffer
 *
 *  @retval >= 0, the length of the dst string
 *  @retval ERROR, dst_len was too small
 */

ya_result parse_copy_trim_spaces(const char *src, uint32_t src_len, char *dst, uint32_t dst_len);

/**
 * Removes all space charactesr from the string.
 *
 * @param the string to modify.
 *
 * @return the length of the modified string.
 */

ya_result parse_remove_spaces(char *inout_txt);

/**
 * Remove end CR/LF
 */

int32_t parse_trim_end(char *text, int32_t text_len);

/** \brief Skips a specific keyword from a string, case insensitive
 *
 *  Skips a specific keyword from a string,  case insensitive, skips white spaces before and after the match
 *
 *  @param[in] src          string
 *  @param[in] src_len      size of the string (the zero sentinel is not checked)
 *  @param[in] words        array of strings that will be looked for
 *  @param[in] word_count   the size of the array
 *  @param[in] matched_word a pointer to an integer that will hold the matched word index or -1 (can be NULL)
 *
 *  @retval >= 0, the number of bytes until the next word
 *  @retval ERROR, dst_len was too small
 */

ya_result parse_skip_word_specific(const char *src, uint32_t src_len, const char *const *words, uint32_t word_count, int32_t *matched_word);

/**
 * Skip characters from input until a char from a set is found.
 *
 * @param src the input
 * @param chars an array of characters to match
 * @param chars_len the number of characters in chars
 *
 * @return an pointer to the first matching character or the asciiz sentinel.
 */

const char *parse_skip_until_chars(const char *src, const char *chars, uint32_t chars_len);

/** \brief Skips a specific keyword from a string, case insensitive
 *
 *  Skips a specific keyword from a string,  case insensitive, skips white spaces before and after the match
 *
 *  @param[in] src          string
 *  @param[in] src_len      size of the string (the zero sentinel is not checked)
 *  @param[in] dst          buffer that will receive the binary version of the ip
 *  @param[in] dst_len      the size of the buffer, minimum 4 for ipv4 and minimum 16 for ipv6
 *
 *  @retval >= 0, the number of bytes written (4 for ipv4 and 16 for ipv6)
 *  @retval ERROR, dst_len was too small or the src was not a valid ip
 */

ya_result parse_ip_address(const char *src, uint32_t src_len, uint8_t *dst, uint32_t dst_len);

/**
 * Returns a pointer to the first non-blank character on an ASCIIZ string
 * blank = space-char & tab
 * space = space-char & tab & form feed & cr & lf
 *
 * @param txt
 * @return
 */

static inline const char *parse_skip_spaces(const char *txt)
{
    while(isspace(*txt) && (*txt != '\0'))
    {
        txt++;
    }

    return txt;
}

static inline const char *parse_skip_spaces_ex(const char *txt, const char *txt_limit)
{
    for(;;)
    {
        if(txt >= txt_limit)
        {
            return NULL;
        }

        if(!isspace(*txt) || (*txt == '\0'))
        {
            return txt;
        }

        txt++;
    }
}

/**
 * Returns a pointer to the first non-digit character on an ASCIIZ string
 *
 * @param txt
 * @return
 */

static inline const char *parse_skip_digits(const char *txt)
{
    while(isdigit(*txt) && (*txt != '\0'))
    {
        txt++;
    }

    return txt;
}

/**
 * Returns a pointer to the first digit character on an ASCIIZ string
 *
 * @param txt
 * @return
 */

static inline const char *parse_skip_nondigits(const char *txt)
{
    while(!isdigit(*txt) && (*txt != '\0'))
    {
        txt++;
    }

    return txt;
}

/**
 * Returns a pointer to the first blank character on an ASCIIZ string
 * blank = space-char & tab
 * space = space-char & tab & form feed & cr & lf
 *
 * @param txt
 * @return
 */

static inline const char *parse_next_blank(const char *txt)
{
    while(!isblank(*txt) && (*txt != '\0'))
    {
        txt++;
    }

    return txt;
}

/**
 * Returns a pointer to the first blank character on an ASCIIZ string
 * blank = space-char & tab
 * space = space-char & tab & form feed & cr & lf
 *
 * @param txt
 * @return
 */

static inline const char *parse_next_blank_ex(const char *txt, const char *txt_limit)
{
    for(;;)
    {
        if(txt >= txt_limit)
        {
            return NULL;
        }

        if(isblank(*txt) || (*txt == '\0'))
        {
            return txt;
        }

        txt++;
    }
}

/**
 * Returns a pointer to the first space character on an ASCIIZ string
 * blank = space-char & tab
 * space = space-char & tab & form feed & cr & lf
 *
 * @param txt
 * @return
 */

static inline const char *parse_next_space(const char *txt)
{
    while(!isspace(*txt) && (*txt != '\0'))
    {
        txt++;
    }

    return txt;
}

/**
 * Returns a pointer to the first space character on an ASCIIZ string
 * blank = space-char & tab
 * space = space-char & tab & form feed & cr & lf
 *
 * @param txt
 * @return
 */

static inline const char *parse_next_char_equals(const char *txt, char c)
{
    while((*txt != c) && (*txt != '\0'))
    {
        txt++;
    }

    return txt;
}

/**
 * Copies the next word into dst
 * Expects to start from the first letter of the word.
 *
 * @param txt
 * @return strlen(dst)
 */

static inline int32_t parse_copy_word(char *dst, size_t dst_size, const char *txt)
{
    char             *base = dst;

    const char *const limit = &txt[MIN(strlen(txt), dst_size)];

    while(!isspace(*txt) && (txt < limit))
    {
        *dst++ = *txt++;
    }

    *dst = '\0';

    return (int32_t)(dst - base);
}

/**
 * Copies the next word into dst
 * Will skip blanks to reach the next word
 *
 * @param txt
 * @return number of letters read from txt
 */

static inline int32_t parse_copy_next_word(char *dst, size_t dst_size, const char *txt)
{
    const char *non_blank_txt = parse_skip_spaces(txt);
    int32_t     n = parse_copy_word(dst, dst_size, non_blank_txt);

    if(n >= 0)
    {
        n += (int32_t)(non_blank_txt - txt);
    }

    return n;
}

/**
 * Cuts a token from a text at the first occurence of a delimiter.
 *
 * @param dest the destination where the token will be copied.
 * @param dest_size the size of the destination
 * @param from the text
 * @param delim a string containing all the characters that are delimiters
 * @return the number of characters taken from the text
 */

int32_t parse_next_token(char *dest, size_t dest_size, const char *from, const char *delim);

/**
 *
 * now
 * tomorrow
 * yesterday
 * +1y +1year +1years (months,weeks,days,seconds)
 * -1y -1year -1years (months,weeks,days,seconds)
 * 2019-04-16
 * 2019-04-16_12:00:00.123456
 * 20190416
 * 20190416120000123456
 *
 */

int64_t parse_timeus_from_smarttime(const char *text);

/**
 * Parses an IP or a host name + port + key
 *
 * port and key are optional
 *
 * The function uses getaddrinfo for name resolution and IP parsing.
 *
 * e.g.
 *  127.0.0.1 port 53 key mykey
 *  ns1.eurid.eu. key thatkey
 */

ya_result          parse_hostaddr(const char *ipname_port_key, struct host_address_s **hap);

static inline bool parse_word_match(const char *text, uint32_t text_len, const char *match, uint32_t match_len)
{
    if(text_len == match_len)
    {
        bool ret = (memcmp(text, match, text_len) == 0);

        return ret;
    }

    return false;
}

static inline bool parse_word_case_match(const char *text, uint32_t text_len, const char *match, uint32_t match_len)
{
    if(text_len == match_len)
    {
        for(uint_fast32_t i = 0; i < text_len; ++i)
        {
            if(tolower(text[i]) != tolower(match[i]))
            {
                return false;
            }
        }

        return true;
    }

    return false;
}

static inline ya_result parser_get_u8(const char *text, uint32_t text_len, uint8_t *out_value)
{
    uint32_t  tmp_u32;
    ya_result return_code = parse_u32_check_range_len_base10(text, text_len, &tmp_u32, 0, U8_MAX);
    *out_value = (uint8_t)tmp_u32;

    return return_code;
}

static inline ya_result parser_get_s8(const char *text, uint32_t text_len, int8_t *out_value)
{
    int32_t   tmp_s32;
    ya_result return_code = parse_s32_check_range_len_base10(text, text_len, &tmp_s32, (int32_t)S8_MIN, (int32_t)S8_MAX);
    *out_value = (int8_t)tmp_s32;

    return return_code;
}

static inline ya_result parser_get_u16(const char *text, uint32_t text_len, uint16_t *out_value)
{
    uint32_t  tmp_u32;
    ya_result return_code = parse_u32_check_range_len_base10(text, text_len, &tmp_u32, 0, U16_MAX);
    *out_value = (uint16_t)tmp_u32;

    return return_code;
}

static inline ya_result parser_get_s16(const char *text, uint32_t text_len, int16_t *out_value)
{
    int32_t   tmp_s32;
    ya_result return_code = parse_s32_check_range_len_base10(text, text_len, &tmp_s32, S16_MIN, S16_MAX);
    *out_value = (int16_t)tmp_s32;

    return return_code;
}

static inline ya_result parser_get_u32(const char *text, uint32_t text_len, uint32_t *out_value)
{
    ya_result return_code = parse_u32_check_range_len_base10(text, text_len, out_value, 0, U32_MAX);

    return return_code;
}

static inline ya_result parser_get_s32(const char *text, uint32_t text_len, int32_t *out_value)
{
    ya_result return_code = parse_s32_check_range_len_base10(text, text_len, out_value, S32_MIN, INT32_MAX);

    return return_code;
}

static inline ya_result parser_get_u64(const char *text, uint32_t text_len, uint64_t *out_value)
{
    ya_result return_code = parse_u64_check_range_len_base10(text, text_len, out_value, 0, U64_MAX);

    return return_code;
}

#ifdef __cplusplus
}
#endif

#endif /* _PARSING_H */

/** @} */

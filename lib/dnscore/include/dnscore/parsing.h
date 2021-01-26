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

/** @defgroup dnscoretools Generic Tools
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#ifndef _PARSING_H
#define	_PARSING_H

#include <ctype.h>
#include <dnscore/sys_types.h>

#define BASE_10 10

#ifdef	__cplusplus
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
ya_result
parse_u32_check_range(const char *src, u32 *dst, u32 min, u32 max, u8 base);

ya_result parse_u32_check_range_len_base10(const char *src, u32 src_len, u32 *dst, u32 min, u32 max);

ya_result parse_s32_check_range_len_base10(const char *src, u32 src_len, s32 *dst, s32 min, s32 max);

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
ya_result parse_u64_check_range_len_base10(const char *src, u32 src_len, u64 *dst, u64 min, u64 max);

/** \brief Converts a chain of pascal strings to a string
 *
 *  Converts a chain of pascal strings to a string
 *
 *  @param[in]  src  string in the form [len+chars]*
 *  @param[out] dst  string
 *
 *  @retval OK
 *  @retval NOK, if something is broken
 */
ya_result
parse_pstring(char **srcp_in_out, size_t src_len, u8 *dst, size_t dst_len);

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

ya_result parse_yyyymmddhhmmss_check_range_len(const char *src, u32 src_len, time_t *dst);

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

ya_result parse_copy_trim_spaces(const char *src, u32 src_len, char *dst, u32 dst_len);
ya_result parse_remove_spaces(char *inout_txt);

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

ya_result parse_skip_word_specific(const char *src, u32 src_len, const char **words, u32 word_count, s32 *matched_word);

const char * parse_skip_until_chars(const char *src, const char *chars, u32 chars_len);


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

ya_result
parse_ip_address(const char *src, u32 src_len, u8 *dst, u32 dst_len);

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
 * Copies the next word into dst
 * 
 * @param txt
 * @return strlen(dst)
 */

static inline s32 parse_copy_word(char *dst, size_t dst_size, const char *txt)
{
    char *base = dst;
    
    const char * const limit = &txt[MIN(strlen(txt), dst_size)];
    
    while(!isspace(*txt) && (txt < limit))
    {
    	*dst++ = *txt++;
    }
    
    *dst = '\0';
    
    return dst - base;
}

static inline s32 parse_copy_next_word(char *dst, size_t dst_size, const char *txt)
{
    const char *non_blank_txt = parse_skip_spaces(txt);
    s32 n = parse_copy_word(dst, dst_size, non_blank_txt);
    
    if(n >= 0)
    {
        n += non_blank_txt - txt;
    }
    
    return n;
}

s32 parse_next_token(char *dest, size_t dest_size, const char *from, const char *delim);

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

s64 parse_timeus_from_smarttime(const char *text);

#ifdef	__cplusplus
}
#endif

#endif	/* _PARSING_H */

/** @} */

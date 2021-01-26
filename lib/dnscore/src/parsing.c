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

#include "dnscore/dnscore-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <dnscore/timems.h>
#include <dnscore/config_settings.h>

#include "dnscore/parsing.h"

#if !HAVE_TIMEGM && !HAS_TIMEGM
static inline time_t timegm(struct tm *tv)
{
    return timegm_internal(tv);
}
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
parse_u32_check_range(const char *src, u32 *dst, u32 min, u32 max, u8 base)
{
    long long int val;
    char *endptr;
    int err;

    /** @note sizeof(long long int) > sizeof(u32) */

    /*    ------------------------------------------------------------    */

    errno = 0;

    /** @note strtol returns a 64 bits integer on 64 bits architectures
     *        strtoll should be 64 bits on both 32 and 64 bits architectures
     *	      so for portability 64 bits has to be handled
     */

    val = strtoll(src, &endptr, base); /* stroll = 64 bits : dst is 32 */

    err = errno; /* in case errno is a macro */

    if((endptr == src) || (err == EINVAL) || (err == ERANGE) || (val < (long long int)min) || (val > (long long int)max))
    {
        return PARSEINT_ERROR;
    }

    *dst = (u32)val;

    return OK;
}



ya_result
parse_u32_check_range_len_base10(const char *src, u32 src_len, u32 *dst, u32 min, u32 max)
{
    // 0......N
    // 67612321
    
    if(src_len > 10)
    {
        return PARSEINT_ERROR; // out of range
    }
    
    --src_len;
        
    u64 output_value = ((u64)src[src_len]) - '0';
    
    if((u64)output_value > 9)
    {
        return PARSEINT_ERROR;
    }
    
    u32 base_multiplier = 10;
    
    while(src_len > 0)
    {
        --src_len;
        
        u64 value = ((u64)src[src_len]) - '0';
        
        if(value > 9)
        {
            return PARSEINT_ERROR;
        }
        
        value *= base_multiplier;
        
        output_value += value;
        
        base_multiplier *= 10;
    }
    
    if((output_value < min) || (output_value > max))
    {
        return PARSEINT_ERROR;
    }
    
    *dst = (u32)output_value;

    return SUCCESS;
}

ya_result
parse_s32_check_range_len_base10(const char *src, u32 src_len, s32 *dst, s32 min, s32 max)
{
    // 0......N
    // 67612321
    
    --src_len;
    
    if(src_len > 10)
    {
        return PARSEINT_ERROR; // out of range
    }
    
    bool minus;
    
    if((minus = (src[0] == '-')))
    {
        src++;
        --src_len;
    }
    
    u32 base_multiplier = 10;
        
    s64 output_value = ((s64)src[src_len]) - '0';
    
    if((u64)output_value > 9)
    {
        return PARSEINT_ERROR;
    }
    
    while(src_len > 0)
    {
        --src_len;
        
        s64 value = ((s64)src[src_len]) - '0';
        
        if((u64)value > 9)
        {
            return PARSEINT_ERROR;
        }
        
        value *= base_multiplier;
        
        output_value += value;
        
        base_multiplier *= 10;
    }
    
    if(minus)
    {
        output_value = -output_value;
    }
    
    if((output_value < min) || (output_value > max))
    {
        return PARSEINT_ERROR;
    }
    
    *dst = (s32)output_value;

    return SUCCESS;
}

ya_result
parse_u64_check_range_len_base10(const char *src, u32 src_len, u64 *dst, u64 min, u64 max)
{
    // 0......N
    // 18446744073709551615
    
    if(src_len > 20)
    {
        return PARSEINT_ERROR; // out of range
    }
    
    --src_len; // 19
        
    u64 output_value = ((u64)src[src_len]) - '0';
    
    if((u64)output_value > 9)
    {
        return PARSEINT_ERROR;
    }
    
    if(src_len < 19) // if no risk of overflow
    {
        u64 base_multiplier = 10;

        while(src_len > 0)
        {
            --src_len;

            u64 value = ((u64)src[src_len]) - '0';

            if(value > 9)
            {
                return PARSEINT_ERROR;
            }

            output_value += value * base_multiplier;

            base_multiplier *= 10;
        }
    }
    else // the only case with possible overflow at the last iteration of the loop
    {
        u64 base_multiplier = 10;
        
        while(src_len-- > 1)
        {
            u64 value = ((u64)src[src_len]) - '0';

            if(value > 9)
            {
                return PARSEINT_ERROR;
            }

            output_value += value * base_multiplier;

            base_multiplier *= 10;
        }
        
        if(src_len == 0)
        {
            u64 max_div_10 = max / 10;
            
            if(output_value > max_div_10)   // check before multiplication there will be no 64 bits overflow
            {                               // this only should be tested for the last iteration of the loop
                return PARSEINT_ERROR;      // => the last pass should happen out of this loop
            }

            u64 value = ((u64)src[0]) - '0';

            if(value > 9)
            {
                return PARSEINT_ERROR;
            }

            value *= base_multiplier;

            if(output_value > max - value)  // check before addition there will be no 64 bits overflow
            {
                return PARSEINT_ERROR;
            }

            output_value += value;
        }
    }
    
    if((output_value < min) || (output_value > max)) // the second half of the test could probably get rid of, with a slight modification
    {
        return PARSEINT_ERROR;
    }
    
    *dst = output_value;

    return SUCCESS;
}



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
ya_result
parse_yyyymmddhhmmss_check_range_len(const char *src, u32 src_len, time_t *dst)
{
    struct tm thetime;
    
    if(src_len != 14)
    {
        return PARSEDATE_ERROR;
    }

#if DEBUG
    memset(&thetime, 0xff, sizeof(thetime));
#endif
    
    u32 tmp_u32;
    
    if(FAIL(parse_u32_check_range_len_base10(src, 4, &tmp_u32, 1970, 2106/*2038*/)))
    {
        return PARSEDATE_ERROR;
    }
    thetime.tm_year = tmp_u32;
    src += 4;
    
    if(FAIL(parse_u32_check_range_len_base10(src, 2, &tmp_u32, 1, 12)))
    {
        return PARSEDATE_ERROR;
    }
    thetime.tm_mon = tmp_u32;
    src += 2;
    
    if(FAIL(parse_u32_check_range_len_base10(src, 2, &tmp_u32, 1, 31)))
    {
        return PARSEDATE_ERROR;
    }
    thetime.tm_mday = tmp_u32;
    src += 2;
    
    if(FAIL(parse_u32_check_range_len_base10(src, 2, &tmp_u32, 0, 23)))
    {
        return PARSEDATE_ERROR;
    }
    thetime.tm_hour = tmp_u32;
    src += 2;
    
    if(FAIL(parse_u32_check_range_len_base10(src, 2, &tmp_u32, 0, 59)))
    {
        return PARSEDATE_ERROR;
    }
    thetime.tm_min = tmp_u32;
    src += 2;
    
    if(FAIL(parse_u32_check_range_len_base10(src, 2, &tmp_u32, 0, 61)))
    {
        return PARSEDATE_ERROR;
    }
    thetime.tm_sec = tmp_u32;

    thetime.tm_year -= 1900;
    thetime.tm_mon--;

    time_t t = timegm(&thetime);

    if(t < 0)
    {
        return PARSEDATE_ERROR;
    }

    *dst = (u32)t;

    return OK;
}

ya_result
parse_yyyymmddhhmmss_check_range(const char *src, time_t *dst)
{
    ya_result return_code;
    
    return_code = parse_yyyymmddhhmmss_check_range_len(src, strlen(src), dst);
    
    return return_code;
}

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
parse_pstring(char **srcp, size_t src_len, u8 *dst, size_t dst_len)
{
    char *s = *srcp;
    const char * const limit = &s[src_len];
    u8 *p;
    const u8 *dst_limit;
    bool quoted;
    
    if(src_len == 0 || dst_len < 256)
    {
        return PARSESTRING_ERROR;
    }
    
    p = &dst[1];
    dst_limit = &dst[dst_len];
    
    quoted = FALSE;
    if(s[0] == '"')
    {
        quoted = TRUE;
        s++;
    }

    for(; s < limit; s++)
    {
        char c = *s;
        
        if((c < 32))
        {
            return PARSE_INVALID_CHARACTER;
        }
        
        // If unescaped '\' go on otherwise set escape = 1
        if(c == '\\')
        {
            // grab next char IF there is one
            
            s++;
            
            if(s < limit)
            {                    
                if((c < 32))
                {
                    return PARSE_INVALID_CHARACTER;
                }

                if(p == dst_limit)
                {
                    return PARSE_BUFFER_TOO_SMALL_ERROR;
                }
                
                *p++ = *s;
            }
            else
            {
                return PARSESTRING_ERROR;
            }
            
            continue;
        }

        // only "
        
        if(c == '"')
        {
            if(!quoted)
            {
                return PARSESTRING_ERROR;
            }
            
            quoted = FALSE;
                        
            break;
        }
        
        if(!quoted)
        {
            if(isspace(c))
            {
                break;
            }
        }

        if(p == dst_limit)
        {
            return PARSE_BUFFER_TOO_SMALL_ERROR;
        }

        /* add character to temporary variable */
        
        *p++    = c;
    }

    /* if unbalanaced qoutes --> stop */
    if(quoted)
    {
        return PARSESTRING_ERROR;
    }

    ya_result len    = p - dst;

    dst[0] = len - 1;

    /* Now it is really done the parsing */
    
    *srcp = s + 1;

    return len;
}

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

ya_result
parse_copy_trim_spaces(const char *src, u32 src_len, char *dst, u32 dst_len)
{
    yassert(src != NULL && dst != NULL && dst_len > 0);

    const char *src_limit = src + src_len;
    const char *dst_limit = dst + dst_len - 1;
    const char *dst_org = dst;

    bool has_space = FALSE;
    
    *dst = '\0';
    
    while(src < src_limit && isspace(*src))
    {
        src++;
    }

    while(src < src_limit)
    {
        char c = *src++;

        if(isspace(c))
        {
            has_space = TRUE;
            continue;
        }

        if(has_space)
        {
            *dst++ = ' ';

            if(dst == dst_limit)
            {
                return PARSE_BUFFER_TOO_SMALL_ERROR;       /* buffer too small */
            }
        }

        has_space = FALSE;

        *dst++ = c;

        if(dst == dst_limit)
        {
            return PARSE_BUFFER_TOO_SMALL_ERROR;       /* buffer too small */
        }
    }

    *dst++ = '\0';

    return dst - dst_org;
}

ya_result
parse_remove_spaces(char *inout_txt)
{
    char *p = inout_txt;
    char c;
    
    while((c = *inout_txt++) != '\0')
    {
        if(isspace(c))
        {
            continue;
        }
        
        *p++ = c;
    }
    
    *p = '\0';
    
    return p - inout_txt;
}

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

ya_result
parse_skip_word_specific(const char *src, u32 src_len, const char **words, u32 word_count, s32 *matched_word)
{
    const char *src_org = src;
    const char *src_limit = src + src_len;
    
    // skip spaces
    
    src = parse_skip_spaces(src);
        
    // get the non-space
    
    const char *p = src;
    while(p < src_limit && !isspace(*p))
    {
        p++;
    }
    // p == src_limit OR p is at the first blank after the word
    
    src_limit = p;
    
    src_len = src_limit - src;

    for(u32 i = 0; i < word_count; i++)
    {
        const char *ptr = src;
        const char *word = words[i];
        
        u32 word_len = strlen(word);
        
        if(word_len != src_len)
        {
            continue;
        }
        
        const char *word_limit = word + word_len;
        
        // lengths are the same
        
        while(word < word_limit)
        {
            if(tolower(*ptr++) != tolower(*word++))
            {
                break;
            }
        }
        
        if(word == word_limit)
        {
            /* match */
            if(matched_word != NULL)
            {
                *matched_word = i;
            }
            
            return src_limit - src_org;
        }
    }

    if(matched_word != NULL)
    {
        *matched_word = -1;
    }

    return PARSEWORD_NOMATCH_ERROR; /* no match */
}

const char *
parse_skip_until_chars(const char *src, const char *chars, u32 chars_len)
{
    
    for(;;)
    {
        char c = *src;
        
        if(c == '\0')
        {
            return src;
        }
        
        for(u32 i = 0; i < chars_len; i++)
        {
            if(c == chars[i])
            {
                return src;
            }
        }
        
        src++;
    }
}

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
parse_ip_address(const char *src, u32 src_len_, u8 *dst, u32 dst_len)
{
    const char *new_src = parse_skip_spaces(src);
    s32 src_len = (s32)src_len_;
    src_len -= new_src - src;
    bool expect_v6_or_more = FALSE;
    
    if(src_len <= 0)
    {
        return PARSEIP_ERROR;
    }

    if(*new_src == '[') /// @note handle RFC 3986, section 3.2.2
    {
        expect_v6_or_more = TRUE;
        
        new_src++;
        // IPv6+ delimiter
        char *end = strchr(new_src, ']');
        if(end == NULL)
        {
            return PARSEIP_ERROR;
        }
        src_len = end - new_src;
    }
    
    char tmp[64];
    src_len = MIN((size_t)src_len, sizeof(tmp)-1);
    memcpy(tmp, src, src_len);
    tmp[src_len] = '\0';

    if(dst_len < 4)
    {
        return PARSE_BUFFER_TOO_SMALL_ERROR;   /* dst too small */
    }

    if(inet_pton(AF_INET, tmp, dst) == 1)
    {
        if(expect_v6_or_more)
        {
            return PARSEIP_ERROR;
        }
        
        return 4;
    }

    if(dst_len < 16)
    {
        return PARSE_BUFFER_TOO_SMALL_ERROR;   /* dst too small */
    }

    if(inet_pton(AF_INET6, tmp, dst) == 1)
    {
        return 16;
    }

    return PARSEIP_ERROR;
}

s32
parse_next_token(char *dest, size_t dest_size, const char *from, const char *delim)
{
    const char *to = from;
    for(;;)
    {
        char c = *to;
        
        if(c == '\0')
        {
            size_t len = to - from;
                
            if(len > dest_size)
            {
                return PARSE_BUFFER_TOO_SMALL_ERROR;
            }

            memcpy(dest, from, len);
            dest[len] = '\0';
            return len;
        }
        
        // for every delimiter, test if c if such a delimiter
        // if it is, then
        
        for(const char *d = delim; *d != 0; d++)
        {
            if(*d == c)
            {
                // end of word
                size_t len = to - from;
                
                if(len > dest_size)
                {
                    return PARSE_BUFFER_TOO_SMALL_ERROR;
                }
                
                memcpy(dest, from, len);
                dest[len] = '\0';
                return len;
            }
        }
        ++to;
    }
}

/** @} */

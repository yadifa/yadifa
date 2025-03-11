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
 * @defgroup dnscoretools Generic Tools
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <dnscore/timems.h>
#include <dnscore/config_settings.h>
#include <dnscore/host_address.h>
#include <dnscore/tsig.h>

#include "dnscore/parsing.h"

#if !HAVE_TIMEGM && !HAS_TIMEGM
static inline time_t timegm(struct tm *tv) { return timegm_internal(tv); }
#endif

extern const uint8_t __DEBASE16__[256];

static const value_name_table_t true_false_enum[] = {{1, "yes"}, {1, "1"}, {1, "enable"}, {1, "enabled"}, {1, "on"}, {1, "true"}, {0, "no"}, {0, "0"}, {0, "disable"}, {0, "disabled"}, {0, "off"}, {0, "false"}, {0, NULL}};

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
ya_result parse_u32_check_range(const char *src, uint32_t *dst, uint32_t min, uint32_t max, uint8_t base)
{
    long long int val;
    char         *endptr;
    int           err;

    /** @note sizeof(long long int) > sizeof(uint32_t) */

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

    *dst = (uint32_t)val;

    return OK;
}

ya_result parse_u32_check_range_len_base10(const char *src, uint32_t src_len, uint32_t *dst, uint32_t min, uint32_t max)
{
    // 0......N
    // 67612321

    if(src_len > 10)
    {
        return PARSEINT_ERROR; // out of range
    }

    --src_len;

    uint64_t output_value = ((uint64_t)src[src_len]) - '0';

    if((uint64_t)output_value > 9)
    {
        return PARSEINT_ERROR;
    }

    uint32_t base_multiplier = 10;

    while(src_len > 0)
    {
        --src_len;

        uint64_t value = ((uint64_t)src[src_len]) - '0';

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

    *dst = (uint32_t)output_value;

    return SUCCESS;
}

ya_result parse_s32_check_range_len_base10(const char *src, uint32_t src_len, int32_t *dst, int32_t min, int32_t max)
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

    uint32_t base_multiplier = 10;

    int64_t  output_value = ((int64_t)src[src_len]) - '0';

    if((uint64_t)output_value > 9)
    {
        return PARSEINT_ERROR;
    }

    while(src_len > 0)
    {
        --src_len;

        int64_t value = ((int64_t)src[src_len]) - '0';

        if((uint64_t)value > 9)
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

    *dst = (int32_t)output_value;

    return SUCCESS;
}

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

ya_result parse_u64_check_range_len_base10(const char *src, uint32_t src_len, uint64_t *dst, uint64_t min, uint64_t max)
{
    // 0......N
    // 18446744073709551615

    if(src_len > 20)
    {
        return PARSEINT_ERROR; // out of range
    }

    --src_len; // 19

    uint64_t output_value = ((uint64_t)src[src_len]) - '0';

    if((uint64_t)output_value > 9)
    {
        return PARSEINT_ERROR;
    }

    if(src_len < 19) // if no risk of overflow
    {
        uint64_t base_multiplier = 10;

        while(src_len > 0)
        {
            --src_len;

            uint64_t value = ((uint64_t)src[src_len]) - '0';

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
        uint64_t base_multiplier = 10;

        while(src_len-- > 1)
        {
            uint64_t value = ((uint64_t)src[src_len]) - '0';

            if(value > 9)
            {
                return PARSEINT_ERROR;
            }

            output_value += value * base_multiplier;

            base_multiplier *= 10;
        }

        if(src_len == 0)
        {
            uint64_t max_div_10 = max / 10;

            if(output_value > max_div_10) // check before multiplication there will be no 64 bits overflow
            {                             // this only should be tested for the last iteration of the loop
                return PARSEINT_ERROR;    // => the last pass should happen out of this loop
            }

            uint64_t value = ((uint64_t)src[0]) - '0';

            if(value > 9)
            {
                return PARSEINT_ERROR;
            }

            value *= base_multiplier;

            if(output_value > max - value) // check before addition there will be no 64 bits overflow
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

ya_result parse_u64_check_range_len_base16(const char *src, uint32_t src_len, uint64_t *dst, uint64_t min, uint64_t max)
{
    // 0......N
    // 18446744073709551615

    if((src_len == 0) || (src_len > 16))
    {
        return PARSEINT_ERROR; // out of range
    }

    uint64_t value = 0;
    uint8_t  shift = 0;

    for(const char *p = src + src_len - 1; p >= src; --p)
    {
        uint64_t digit = __DEBASE16__[(uint8_t)*p];
        if(digit > 15)
        {
            return PARSEINT_ERROR;
        }
        value |= digit << shift;
        shift += 4;
    }

    if((value < min) || (value > max)) // the second half of the test could probably get rid of, with a slight modification
    {
        return PARSEINT_ERROR;
    }

    *dst = value;

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
ya_result parse_yyyymmddhhmmss_check_range_len(const char *src, uint32_t src_len, time_t *dst)
{
    struct tm thetime;

    if(src_len != 14)
    {
        return PARSEDATE_ERROR;
    }

#if DEBUG
    memset(&thetime, 0xff, sizeof(thetime));
#endif

    uint32_t tmp_u32;

    if(FAIL(parse_u32_check_range_len_base10(src, 4, &tmp_u32, 1970, 2106 /*2038*/)))
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

    *dst = (uint32_t)t;

    return OK;
}

/**
 * Parse a boolean value.
 *
 * TRUE: yes, 1, enable, enabled, on, true
 * FALSE: no, 0, disable, disabled, off, false
 *
 * @param src the asciiz text to parse
 * @param dest a pointer that'll get the boolean value
 *
 * @return an error code
 */

ya_result parse_bool(const char *src, bool *dest)
{
    ya_result ret;
    uint32_t integer_value;
    if(ISOK(ret = value_name_table_get_value_from_casename(true_false_enum, src, &integer_value)))
    {
        bool yes_or_no = (integer_value != 0);
        *dest = yes_or_no;
    }
    return ret;
}

ya_result parse_yyyymmddhhmmss_check_range(const char *src, time_t *dst)
{
    ya_result return_code;

    return_code = parse_yyyymmddhhmmss_check_range_len(src, strlen(src), dst);

    return return_code;
}

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

ya_result parse_pstring(char **srcp, size_t src_len, uint8_t *dst, size_t dst_len)
{
    char             *s = *srcp;
    const char *const limit = &s[src_len];
    uint8_t          *p;
    const uint8_t    *dst_limit;
    bool              quoted;

    if(src_len == 0 || dst_len < 256)
    {
        return PARSESTRING_ERROR;
    }

    p = &dst[1];
    dst_limit = &dst[dst_len];

    quoted = false;
    if(s[0] == '"')
    {
        quoted = true;
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

            quoted = false;

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

        *p++ = c;
    }

    /* if unbalanaced qoutes --> stop */
    if(quoted)
    {
        return PARSESTRING_ERROR;
    }

    ya_result len = p - dst;

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

ya_result parse_copy_trim_spaces(const char *src, uint32_t src_len, char *dst, uint32_t dst_len)
{
    yassert(src != NULL && dst != NULL && dst_len > 0);

    const char *src_limit = src + src_len;
    const char *dst_limit = dst + dst_len - 1;
    const char *dst_org = dst;

    bool        has_space = false;

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
            has_space = true;
            continue;
        }

        if(c == '\0')
        {
            break;
        }

        if(has_space)
        {
            *dst++ = ' ';

            if(dst == dst_limit)
            {
                return PARSE_BUFFER_TOO_SMALL_ERROR; /* buffer too small */
            }
        }

        has_space = false;

        *dst++ = c;

        if(dst == dst_limit)
        {
            return PARSE_BUFFER_TOO_SMALL_ERROR; /* buffer too small */
        }
    }

    *dst = '\0';

    return dst - dst_org;
}

/**
 * Removes all space charactesr from the string.
 *
 * @param the string to modify.
 *
 * @return the length of the modified string.
 */

ya_result parse_remove_spaces(char *inout_txt)
{
    const char *base = inout_txt;
    char       *p = inout_txt;
    char        c;

    while((c = *inout_txt++) != '\0')
    {
        if(isspace(c))
        {
            continue;
        }

        *p++ = c;
    }

    *p = '\0';

    return p - base;
}

int32_t parse_trim_end(char *text, int32_t text_len)
{
    while(--text_len > 0)
    {
        char c = text[text_len];
        if((c != '\n') && (c != '\r'))
        {
            return text_len + 1;
        }
        text[text_len] = '\0';
    }
    return 0;
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

ya_result parse_skip_word_specific(const char *src, uint32_t src_len, const char *const *words, uint32_t word_count, int32_t *matched_word)
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

    for(uint_fast32_t i = 0; i < word_count; i++)
    {
        const char *ptr = src;
        const char *word = words[i];

        uint32_t    word_len = strlen(word);

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

/**
 * Skip characters from input until a char from a set is found.
 *
 * @param src the input
 * @param chars an array of characters to match
 * @param chars_len the number of characters in chars
 *
 * @return an pointer to the first matching character or the asciiz sentinel.
 */

const char *parse_skip_until_chars(const char *src, const char *chars, uint32_t chars_len)
{
    for(;;)
    {
        char c = *src;

        if(c == '\0')
        {
            return src;
        }

        for(uint_fast32_t i = 0; i < chars_len; i++)
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

ya_result parse_ip_address(const char *src, uint32_t src_len_, uint8_t *dst, uint32_t dst_len)
{
    const char *new_src = parse_skip_spaces(src);
    int32_t     src_len = (int32_t)src_len_;
    src_len -= new_src - src;
    bool expect_v6_or_more = false;

    if(src_len <= 0)
    {
        return PARSEIP_ERROR;
    }

    if(*new_src == '[') /// @note handle RFC 3986, section 3.2.2
    {
        expect_v6_or_more = true;

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
    src_len = MIN((size_t)src_len, sizeof(tmp) - 1);
    memcpy(tmp, src, src_len);
    tmp[src_len] = '\0';

    if(dst_len < 4)
    {
        return PARSE_BUFFER_TOO_SMALL_ERROR; /* dst too small */
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
        return PARSE_BUFFER_TOO_SMALL_ERROR; /* dst too small */
    }

    if(inet_pton(AF_INET6, tmp, dst) == 1)
    {
        return 16;
    }

    return PARSEIP_ERROR;
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

int32_t parse_next_token(char *dest, size_t dest_size, const char *from, const char *delim)
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

int64_t parse_timeus_from_smarttime(const char *text)
{
    int64_t ret = timeus_from_smarttime(text);
    return ret;
}

static const char *const parse_hostaddr_keywords[4] = {
    "port",
    "key",
    "notls",
    "tls",
};

ya_result parse_hostaddr(const char *ipname_port_key, host_address_t **hap)
{
    ya_result ret;
    // split spaces
    uint8_t     tls = HOST_ADDRESS_TLS_NOT_SET;
    char        host_name[256];
    char        service[256] = "53";
    char        keyname_ascii[256] = "";
    const char *host = parse_skip_spaces(ipname_port_key);
    const char *word = parse_next_blank(host);
    const char *word_end;
    const char *limit = &ipname_port_key[strlen(ipname_port_key)];
    memcpy(host_name, host, word - host);
    host_name[word - host] = '\0';

    for(;;)
    {
        word = parse_skip_spaces(word);

        if(word >= limit)
        {
            break;
        }

        // check for the work "port"
        int32_t matched = -1;
        int32_t word_len = parse_skip_word_specific(word, strlen(word), parse_hostaddr_keywords, 4, &matched);
        word += word_len;
        word = parse_skip_spaces(word);
        char *p;
        switch(matched)
        {
            case 0: // port
            {
                p = service;
                break;
            }
            case 1: // key
            {
                p = keyname_ascii;
                break;
            }
            case 2: // notls
            {
                p = NULL;
                tls = HOST_ADDRESS_TLS_DISABLE;
                break;
            }
            case 3: // tls
            {
                p = NULL;
                tls = HOST_ADDRESS_TLS_ENFORCE;
                break;
            }
            default:
            {
                // oops
                return ERROR;
            }
        }

        word_end = parse_next_blank(word);
        if(p != NULL)
        {
            memcpy(p, word, word_end - word);
            p[word_end - word] = '\0';
        }
        word = word_end;
    }

    struct addrinfo *addrinfo = NULL;
    if(getaddrinfo(host_name, service, NULL, &addrinfo) >= 0)
    {
        host_address_t  *ha = host_address_new_instance();
        socketaddressp_t sa;
        sa.sa = addrinfo->ai_addr;
        if(FAIL(ret = host_address_set_with_socketaddress(ha, sa.sat)))
        {
            host_address_delete(ha);
            return ret;
        }
        if(keyname_ascii[0] != '\0')
        {
            ha->tsig = tsig_get_with_ascii_name(keyname_ascii);
        }
        ha->tls = tls;
        *hap = ha;
        free(addrinfo);

        return SUCCESS;
    }
    else
    {
        return ERRNO_ERROR;
    }
}

/** @} */

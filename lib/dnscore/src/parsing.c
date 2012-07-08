/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
* DOCUMENTATION */
/** @defgroup dnscoretools Generic Tools
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "dnscore/parsing.h"

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
parse_yyyymmddhhmmss_check_range(const char *src, u32 *dst)
{
    struct tm thetime;
    /*
        time_t epoch0 = 0;
        gmtime_r(&epoch0,&thetime);

        time_t t0 = mktime(&thetime);
     */

#ifndef NDEBUG
    memset(&thetime, 0xff, sizeof (thetime));
#endif

    thetime.tm_gmtoff = 0;
    thetime.tm_isdst = 0;
    thetime.tm_zone = "GMT";

    if(sscanf(src, "%04d%02d%02d%02d%02d%02d",
              &thetime.tm_year,
              &thetime.tm_mon,
              &thetime.tm_mday,
              &thetime.tm_hour,
              &thetime.tm_min,
              &thetime.tm_sec) != 6)
    {
        return PARSEDATE_ERROR;
    }

    thetime.tm_year -= 1900;
    thetime.tm_mon--;

#ifndef __FreeBSD__
    time_t t = mktime(&thetime) - timezone;
#else
    time_t t = mktime(&thetime) - 3600;
#endif

    if(t < 0)
    {
        return PARSEDATE_ERROR;
    }

    *dst = (u32)t;

    return OK;
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
    const char *limit = &s[src_len];
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
            if(isblank(c))
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
    zassert(src != NULL && dst != NULL && dst_len > 0);

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
        char c = *src;

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
    
    while(src < src_limit && isspace(*src))
    {
        src++;
    }

    for(u32 i = 0; i < word_count; i++)
    {
        const char *ptr = src;
        const char *word = words[i];
        const char *word_limit = word + strlen(word);

        while(word < word_limit && ptr < src_limit)
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
            
            while(ptr < src_limit && isspace(*ptr))
            {
                ptr++;
            }

            return ptr - src_org;
        }
    }

    if(matched_word != NULL)
    {
        *matched_word = -1;
    }

    return PARSEWORD_NOMATCH_ERROR; /* no match */
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
parse_ip_address(const char *src, u32 src_len, u8 *dst, u32 dst_len)
{
    char tmp[64];

    src_len = MIN(src_len, sizeof(tmp)-1);

    memcpy(tmp, src, src_len);
    tmp[src_len] = '\0';

    if(dst_len < 4)
    {
        return PARSE_BUFFER_TOO_SMALL_ERROR;   /* dst too small */
    }

    if(inet_pton(AF_INET, tmp, dst) == 1)
    {
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

/** @} */

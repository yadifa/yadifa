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
/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/
#ifndef PARSER_H
#define PARSER_H

#include    "config.h"

#include    <arpa/inet.h>
#include    <ctype.h>
#include    <errno.h>
#include    <limits.h>
#include    <stdint.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>
#include    <sys/types.h>
#include    <time.h>

#include <dnscore/sys_types.h>
#include    "wrappers.h"

#define     BASE_10		10
#define     BASE_16		16
#define     CONTAINER	(60 * 1)	/* 1 minute */

/* Skip white-spaces
 *  White-space character are:  In the "C" and "POSIX" locales:
 *  space,
 *  form-feed ('\f'),
 *  newline ('\n'),
 *  carriage return ('\r',
 *  horizontal tab ('\t', and
 *  vertical tab ('\v').
 */
#define SKIP_WHSPACE(ptr)                                        \
    while(isspace((char)*ptr))                                   \
    {                                                            \
        ptr++;                                                   \
    }

#define SKIP_WORD(ptr)                                           \
    while(!isspace((char)*ptr))                                  \
    {                                                            \
        ptr++;                                                   \
    }                                                            \
    ++ptr;

#define SKIP_JUST_WORD(ptr)                                      \
    while(*ptr!= '\0' && !isspace((char)*ptr))                   \
    {                                                            \
        ptr++;                                                   \
    }

#define SKIP_UNTIL(ptr,chars)                                   \
{                                                               \
    int n = strlen(chars);                                      \
                                                                \
    for(;;)                                                     \
    {                                                           \
        char c = *ptr;                                          \
                                                                \
        for(int i=0; i<=n; i++)                                 \
        {                                                       \
            if(c == (chars)[i])                                 \
            {                                                   \
                goto skipped;                                   \
            }                                                   \
        }                                                       \
                                                                \
        ptr++;                                                  \
    }                                                           \
                                                                \
    skipped:;                                                   \
}

#define CUT_STRING(start, next)     				\
	if(*(start) == '"')                             \
	{                                               \
	    (start)++;                                  \
	    (next) = (start);                           \
                                                    \
	    while(*(next) != '\0' && *(next) != '"')    \
	    {                                           \
            (next)++;                               \
	    }                                           \
                                                    \
	    if(*(next) == '"')                          \
	    {                                           \
            *(next) = '\0';                         \
            (next)++;                               \
	    }                                           \
	}                                               \
	else                                            \
	{                                               \
	    (next) = (start);                           \
	    if(*(next) != '\0')                         \
	    {                                           \
            SKIP_JUST_WORD(next);                   \
	    }                                           \
	}



/** \brief Convert values between host and network byte order (16-bit)
 *
 *  For avoiding problems with big edian and little endian we use
 *  converters for convert values between host and network
 *
 *  @param[out] dst
 *  @param[in] data
 *
 *  @return NONE
 */

static inline void
copy_data_to_net_uint16(void *dst, const u16 data)
{
    SET_U16_AT(*(u16*)dst, htons(data));
}

/** \brief Convert values between host and network byte order (32-bit)
 *
 *  For avoiding problems with big edian and little endian we use
 *  converters for convert values between host and network
 *
 *  @param[out] dst
 *  @param[in] data
 *
 *  @return NONE
 */
static inline void
copy_data_to_net_uint32(void *dst, const u32 data)
{
    SET_U32_AT(*(u32*)dst, htonl(data));
}

/** \brief Convert values between network and host byte order (16-bit)
 *
 *  For avoiding problems with big edian and little endian we use
 *  converters for convert values between host and network
 *
 *  @param[out] dst
 *  @param[in] data
 *
 *  @return NONE
 */
static inline void
copy_data_from_net_uint16(void *dst, const u16 data)
{
    SET_U16_AT(*(u16*)dst, ntohs(data));
}

/** \brief Convert values between network and host byte order (32-bit)
 *
 *  For avoiding problems with big edian and little endian we use
 *  converters for convert values between host and network
 *
 *  @param[out] dst
 *  @param[in] data
 *
 *  @return NONE
 */
static inline void
copy_data_from_net_uint32(void *dst, const u32 data)
{
    SET_U32_AT(*(u32*)dst, ntohl(data));
}

/* Cuts the string the remove everything from the first occurence of the char */
void remove_comment(char *, const char);
/* Not used */
size_t remove_whitespace(char *, char *);
/** Cuts the string to remove space chars at the end */
void remove_whitespace_from_right(char *);
/** Moves the beginning of the string to skip the space chars */
void remove_whitespace_from_left(char **);      /* return value not used by thecaller*/


/*    ------------------------------------------------------------    */

#endif /* PARSER_H */

/*    ------------------------------------------------------------    */

/** @} */

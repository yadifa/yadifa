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
#ifndef CHECK_H_
#define CHECK_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "config.h"

#include <stdint.h>
#include <dnscore/parsing.h>

#include <dnszone/resourcerecord.h>


/** \def BRACKET_CLOSED
 *       no dox */
#define         BRACKET_CLOSED          0x00U
/** \def BRACKET_OPEN
 *       no dox */
#define         BRACKET_OPEN            0x01U

/*    ------------------------------------------------------------
 *
 *      MACROS
 */
/** \def CHECK_TTL(ptr, ttl)
 * 	 \ptr ptr is the needle in the string
 * 	 \ttl ttl is time to live found
 *
 *	 Returns a ttl or a NOK if no number is found or if the ttl is not
 *	 between the range 0 <= ttl <= 2^32 -1
 */
#define CHECK_TTL(ptr, ttl)                      \
    parse_u32_check_range(ptr, (u32 *)&ttl, 0, MAX_U32, BASE_10)

/** \def CHECK_BRACKET(ptr, status)
 * 	 \ptr ptr is the needle in the string
 * 	 \status status can be @b BRACKET_OPEN or @b BRACKET_CLOSED
 *
 *       Check for open and closed bracket, if a open bracket is found and
 *       there's already an open bracket an error will return.
 *       The same for closed brackets found if there's no open bracket status
 */
#define CHECK_BRACKET(ptr, status)                \
    if (*ptr == '(')                              \
    {                                             \
        if (status == BRACKET_OPEN)               \
        return SOA_PARSING_ERR;                   \
        status = BRACKET_OPEN;                    \
        ++ptr;                                    \
    }                                             \
    else if (*ptr == ')')                         \
    {                                             \
        OSDEBUG(termout, "CLOSING CHECK\n");      \
        if (status == BRACKET_CLOSED)             \
        {                                         \
            OSDEBUG(termout, "CLOSING BRACKET TO MUCH\n"); \
            return SOA_PARSING_ERR;               \
        }                                         \
        status = BRACKET_CLOSED;                  \
        ++ptr;                                    \
    }

/* Functions to check the correct values for the resource record data */
int parse_u32_range(const char *text, u32 *value, u32 min, u32 max, u8 base);
int check_origin(const char *, char **);
int check_rdata(const char *, char **, u32);
ya_result check_ttl(const char *, u32 *);

/*    ------------------------------------------------------------    */

#ifdef __cplusplus
}
#endif

#endif /* CHECK_H_ */

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/

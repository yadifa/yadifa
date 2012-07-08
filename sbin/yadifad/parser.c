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
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <dnscore/dnscore.h>
#include <dnscore/format.h>

#include "parser.h"

/** \brief Remove comments at the end of the line
 *
 *  @param[in,out] p string to be trimmed of the comments
 *  @param[in] token is charackter that gives the start of the comment
 */
void
remove_comment(char *p, const char token)
{
    char *end_p;

    /*    ------------------------------------------------------------    */

    end_p = p;

    while((*end_p != token) && (*end_p != '\0'))
    {
        end_p++;
    }
    *end_p = '\0';
}

/** \brief  Remove white space at the end of the line before the comments
 *
 *  @param[in,out] p string to be trimmed of the white-space at the right
 */
void
remove_whitespace_from_right(char *p)
{
    char *end_p;

    /*    ------------------------------------------------------------    */

    end_p = p + strlen(p) - 1;	/* if |p|==0 the -1 offset will be dodged by the while test */

    while((end_p >= p) && isspace(*end_p))
    {
        --end_p;
    }
    *(++end_p) = '\0';
}

/** \brief Remove whitespaces at the beginning of the line
 *
 *  @param[in,out] p string to be trimmed of the white-space at the left
 *
 */
void
remove_whitespace_from_left(char **p)
{
    while(isspace(**p) && (**p!='\0'))
    {
        ++(*p);
    }
}

size_t
remove_whitespace(char *dst, char *src)
{
    size_t len = 0;

    /*    ------------------------------------------------------------    */

    OSDEBUG(termout, "START: %s (%d char.)\n", src, strlen(src));
    while(*src)
    {
        if(isspace(*src))
        {
            src++;
            continue;
        }
        len++;
        *dst++ = *src++;
        OSDEBUG(termout, "LEN: %d C: %c\n", len, dst[-1]);
    }
    *dst = '\0';

    return len;
}

/** @} */

/*----------------------------------------------------------------------------*/


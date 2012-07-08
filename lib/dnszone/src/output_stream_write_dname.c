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
/** @defgroup zonefile Zone file loader module
 *  @ingroup dnszone
 *  @brief 
 *
 *  Implementation of routines for ...
 *   - ...
 *   - ...
 *   - ...
 *    -# ...
 *    -# ...
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/rfc.h>
#include <dnscore/dnsname.h>
#include <dnscore/output_stream.h>

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** @brief Function ...
 *
 *  Writes a txt domain name in dns format to the output stream
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */
ya_result
output_stream_write_dname(output_stream *os, const char *src, const u8* origin)
{
    u_char                                             dname[MAX_DOMAIN_LENGTH];

    ya_result return_code;
    
    if(*src == '\0' )
    {
        return NO_LABEL_FOUND;
    }

    if( (src[0] =='.') && (src[1] =='\0') )
    {
        return output_stream_write_u8(os, 0);
    }

    if(ISOK(return_code = cstr_to_dnsname_with_check(dname, src)))
    {
	/*
	 * Note: Since we check for src=="" && src=="." we just KNOW that the result is 2 or more.
	 */

        if(src[return_code - 2] != '.')
        {
            if(origin == NULL)
            {
                return NO_ORIGIN_FOUND;
            }

            u32 origin_len = dnsname_len(origin);

            u32 full_len = return_code + origin_len - 1;    /* -1 because the last byte of the src is erased */

            if(full_len > MAX_DOMAIN_TEXT_LENGTH)
            {
                return DOMAIN_TOO_LONG;
            }

	    /**
	     * @note It could be interesting to see if doing two writes is faster than building the dname first
	     *       If the output stream is buffered there is a good chance that two writes are faster.
	     */

            MEMCOPY(&dname[return_code - 1], origin, origin_len);

            return_code = full_len;
        }
        
        dnsname_locase_verify_extended_charspace(dname); /** @TODO: optimize: half of this has already been done in cstr_to_dnsname_with_check */

        return_code = output_stream_write(os, dname, return_code);
    }

    return return_code;
}

/** @brief Function ...
 *
 *  Writes a txt domain name in dns format to the output stream
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */
ya_result
output_stream_write_dname_with_escape(output_stream *os, const char *src, const u8* origin)
{
    u_char                                             dname[MAX_DOMAIN_LENGTH];

    ya_result return_code;
    
    if(*src == '\0' )
    {
        return NO_LABEL_FOUND;
    }

    if( (src[0] =='.') && (src[1] =='\0') )
    {
        return output_stream_write_u8(os, 0);
    }

    if(ISOK(return_code = cstr_to_dnsrname_with_check(dname, src)))
    {
	/*
	 * Note: Since we check for src=="" && src=="." we just KNOW that the result is 2 or more.
     * 01 'a' 00 <=> a  (3)
     * 01 '.' 00 <=> \. (3)
     * Note: escaping can have given "\." which will wrongly look like the end of a full name.
	 */

        /* return_code is ALWAYS >= 3 */
        
        bool escaped = FALSE;
        bool dotted = FALSE;
        
        src += return_code - 3;
        
        while(*src != '\0')
        {
            if(!escaped)
            {
                switch(*src)
                {
                    case '.':
                        dotted = TRUE;
                        break;
                    case '\\':
                        escaped = TRUE;
                    default:
                        dotted = FALSE;
                        break;
                }
            }
            else
            {
                escaped = FALSE;
            }
            
            src++;
        }
        
        if(!dotted)
        {
            if(origin == NULL)
            {
                return NO_ORIGIN_FOUND;
            }

            u32 origin_len = dnsname_len(origin);

            u32 full_len = return_code + origin_len - 1;    /* -1 because the last byte of the src is erased */

            if(full_len > MAX_DOMAIN_TEXT_LENGTH)
            {
                return DOMAIN_TOO_LONG;
            }

	    /**
	     * @note It could be interesting to see if doing two writes is faster than building the dname first
	     *       If the output stream is buffered there is a good chance that two writes are faster.
	     */

            MEMCOPY(&dname[return_code - 1], origin, origin_len);

            return_code = full_len;
        }
        
        dnsname_locase_verify_extended_charspace(dname); /** @TODO: optimize: half of this has already been done in cstr_to_dnsname_with_check */

        return_code = output_stream_write(os, dname, return_code);
    }

    return return_code;
}

/** @} */

/*----------------------------------------------------------------------------*/


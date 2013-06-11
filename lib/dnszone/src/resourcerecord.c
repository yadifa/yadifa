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
 *  @brief resource record functions
 *
 *  Implementation of routines for the resource_record struct
 *   - init
 *   - parse
 *   - print
 *   - remove
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/rfc.h>
#include <dnscore/parsing.h>

#include "dnszone/output_stream_write_rdata.h"
#include "dnszone/resourcerecord.h"

#define RSRCRCRD_TAG 0x4452435243525352
#define RRORIGIN_TAG 0x4e494749524f5252

/*
#include "server_error.h"
#include "config_error.h"
*/

#define MODULE_MSG_HANDLE g_zone_logger
extern logger_handle* g_zone_logger;

#define DEBUG_LEVEL 1

#define CUT_WORD(ptr)                                            \
    while(!isspace(*ptr) && (*ptr != '\0'))                      \
++ptr;                                                           \
*ptr++ = '\0';

/**
 * @TODO: put this in a centralized tool.
 */

#define SKIP_WHSPACE(ptr)                                        \
    while(isspace((char)*ptr))                                   \
    {                                                            \
        ptr++;                                                   \
    }

/*------------------------------------------------------------------------------
 *
 * FUNCTIONS */

/**
 * src is changed by the function, hence the **
 * dst is the result
 * label is overwrited
 */

static ya_result
rr_check_qname(char **src, u8 *dst, const u8 *origin, u8 *label)
{
    char                                                             *start;
    char                                                            *needle;

    ya_result                                              return_code = OK;
    
    size_t							  start_len;
    size_t							 origin_len;
    bool				              append_origin = FALSE;

    zassert(*src != NULL);

    if(*src == NULL)
    {
        return ZRE_NO_VALUE_FOUND;
    }

    needle = *src;

    if(isspace(*needle))		    /* re-use */
    {
        SKIP_WHSPACE(needle);
        *src = needle;

        if(*label == '\0')		    /* label !empty: only the label will be used */
        {
            if(origin == NULL)
            {
                return NO_ORIGIN_FOUND;
            }

            dnsname_copy(label, origin);    /* label empty: the origin will be added (effectively only the origin will be used) */
        }

        return dnsname_copy(dst, label);    /** @note most of the time dst already have the same content as label */
    }

    /* parse/get (and cut) the first word (the whole string if there is no spaces) */
    start = needle;
    while(!isspace(*needle) && (*needle != '\0'))
    {
        needle++;
    }
    *needle = '\0';

    start_len = needle - start;	/* start_len > 0 because we know the first char was not a space ... */

    /* If it does not ends with '.' we need to append the origin */
    append_origin = (needle[-1] != '.');

    /* cut */
    needle++;
    SKIP_WHSPACE(needle);
    *src = needle;

    if(FAIL(return_code = cstr_to_dnsname_with_check(dst, start)))
    {
        return return_code;
    }

    if(append_origin)
    {
        u8* origin_dst = dst + (return_code - 1);

        if( (origin == NULL) || ((origin_len = dnsname_len(origin)) == 0) )
        {
            return NO_ORIGIN_FOUND;
        }

        if(start_len + origin_len > MAX_DOMAIN_TEXT_LENGTH)
        {
            return ZRE_INCORRECT_DOMAIN_LEN;
        }
        return_code = dnsname_copy(origin_dst, origin);
    }

    dnsname_copy(label, dst);

    return return_code;
}

static ya_result
rr_check_rdata(char *src, resource_record *rr, const u16 qtype, const u8 *origin, int *bracket_status)
{
    ya_result                                              return_code = OK;
    char                                                      *needle;

    /*    ------------------------------------------------------------    */

    SKIP_WHSPACE(src);
    needle = src;

    if (strlen(needle) == 0)
    {
        return ZRE_NO_RDATA_FOUND;
    }

    while(*needle)
    {
        while((*needle != '(') && (*needle != ')') && (*needle != '\0'))
        {
            ++needle;
        }

        if(*needle == '\0')
        {
            if(strlen(rr->rdata)  == 0)
            {
                /* src cannot be null, no need for a wrapper */
                strcpy(rr->rdata, src);
            }
            else
            {
                strcat(rr->rdata, " ");
                strcat(rr->rdata, src);
            }

            if(*bracket_status == BRACKET_CLOSED)
            {
                return_code = output_stream_write_rdata(&rr->os_rdata, rr->rdata, qtype, origin);
            }

            return return_code;
        }

        if(*needle == '(')
        {
            if(*bracket_status == BRACKET_OPEN)
            {
                return ZRE_DUPLICATED_OPEN_BRACKET;
            }
            else
            {
                *bracket_status = BRACKET_OPEN;
            }
        }

        if(*needle == ')')
        {
            if(*bracket_status == BRACKET_CLOSED)
            {
                return ZRE_DUPLICATED_CLOSED_BRACKET;
            }
            else
            {
                *bracket_status = BRACKET_CLOSED;
            }
        }
        *needle = ' ';
    }

    return OK;
}

/** @brief Parse the resource record in its components
 *
 *  For not found values, default values will be used.
 *  Default values are "origin" and "label". "Origin" always exists, but if
 *  "label" does not exist, "origin" will be the "label"
 *
 *  @param[in] rr_line
 *  @param[in,out] label
 *  @param[in,out] origin
 *  @param[in] default_ttl
 *  @param[in] default qclass
 *  @param[out] rr
 *
 *  @retval OK
 *  @retval NOK
 */
ya_result
rr_parse_line(char *src, const u8 *origin, u8 *label, u32 ttl, resource_record *rr, int *bracket_status)
{
    ya_result                                              return_code = OK;
    char                                                   *needle = NULL;

    /*    ------------------------------------------------------------    */

    if(*bracket_status == BRACKET_CLOSED)
    {
        bool no_ttl = TRUE;

        if(FAIL(return_code = rr_check_qname(&src, rr->name, origin, label)))
        {
            return return_code;
        }

        while(*src)
        {
            if(rr->type != 0 )
            {
                break;
            }

            needle = src;
            /* Search for word and cut */
            CUT_WORD(needle);

            if(FAIL(return_code =  parse_u32_check_range(src, &rr->ttl, 0, MAX_S32, /*BASE_*/10))) /* rfc 2181 */
            {
                if(FAIL(return_code = get_class_from_case_name(src, &rr->class)))
                {
                    if(FAIL(return_code = get_type_from_case_name(src, &rr->type)))
                    {
                        return ZRE_NO_TYPE_FOUND;
                    }
                }
            }
            else
            {
                no_ttl = FALSE;
            }

            src = needle;
            SKIP_WHSPACE(src);
        }

        if(no_ttl) /* if no TTL has been found, then use the default one (rfc 2308) */
        {
            rr->ttl = ttl;
        }
    }

    return_code = rr_check_rdata(src, rr, rr->type, origin, bracket_status);

    OSLDEBUG(termerr, 2, "TYPE: %d: %r \n", rr->type, return_code);

    return return_code;
}

/** @brief Print resource records
 *
 *  @param[in] src resource record
 *  @param[in] text to be printed
 *
 *  @retval OK
 */
void
rr_print_all(output_stream* os, resource_record *src, const char *text, u8 flag)
{
    while(src != NULL)
    {
        rr_print(os, src, text, flag);
        src = src->next;
    }
}

/** @brief Print resource records
 *
 *  @param[in] src resource record
 *  @param[in] text to be printed
 *
 *  @retval OK
 */
void
rr_print(output_stream* os, resource_record *src, const char *text, u8 flag)
{
    char                                      tmp_name[MAX_DOMAIN_TEXT_LENGTH];

    /*    ------------------------------------------------------------    */

    if(src == NULL)
    {
        osformat(os, "%s empty\n", text);
        return;
    }

    osformat(os, "%s", text);

    if(flag & RR_NAME)
    {
        if(src->name != NULL)	/** @todo remove : name is never NULL */
        {
            dnsname_to_cstr(tmp_name, src->name);
            osformat(os, "\tNAME    \t: %s\n", tmp_name);

            if(flag & RR_PRINT_PAYLOAD)
            {
                print_payload(os, src->name, dnsname_len(src->name)); /** @todo CHECK: I'm pretty sure it's broken. It looks like the
		  						         *	         old mechanism
									 */
            }
        }
    }

    if(flag & RR_TTL)
    {
        osformat(os, "\tTTL      \t: %u\n", src->ttl);
    }

    if(flag & RR_CLASS)
    {
        osformat(os, "\tCLASS    \t: %d\n", src->class);
    }

    if(flag & RR_TYPE)
    {
        osformat(os, "\tTYPE     \t: %d\n", src->type);
    }

    if(flag & RR_RDATA)
    {
        switch(src->type)
        {
            case TYPE_CNAME:
                dnsname_to_cstr(tmp_name, (u_char*)src->rdata); /** @todo CHECK: I'm pretty sure it's broken. It looks like the old
								 *               mechanism
								 */
                osformat(os, "\tRDATA (#)\t: %s\n", tmp_name);
                break;
            case TYPE_A:
                break;
            default:
                osformat(os, "\tRDATA (#)\t: %s\n", src->rdata);
                break;
        }

        osformat(os, "\n");

        if(flag & RR_PRINT_PAYLOAD)
        {
            //print_payload(os, src->rdata, src->rdata_len);
        }
    }
}


ya_result
rr_get_origin(const char *src, u8 **dst)
{
    size_t                                                           length;

    /*    ------------------------------------------------------------    */

    if(src == NULL)
    {
        return NO_ORIGIN_FOUND;
    }

    length = strlen(src);
    /* Check if the dname ends on a '.' */
    if(src[length - 1] == '.')
    {
        /* It does end on a '.' */
        REALLOC_OR_DIE(u8*, *dst, length + 1, RRORIGIN_TAG);

        return cstr_to_dnsname_with_check(*dst, src);
    }
    else
    {
        return ZRE_INCORRECT_ORIGIN;
    }
}

ya_result
rr_get_ttl(const char *src, u32 *dst)
{
    u32                                                                 ttl;

    /*    ------------------------------------------------------------    */

    if(OK == parse_u32_check_range(src, (u32 *)&ttl, 0, MAX_U32, /*BASE_*/10))
    {
        while(isspace(*src))
        {
            src++;
        }

        while(isdigit(*src))
        {
            src++;
        }

        if(!isspace(*src))
        {
            u64 ttl64 = ttl;
            
            switch(*src)
            {
                case 'w':
                    ttl64 *= 60 * 60 * 24 * 7;
                    break;
                case 'd':
                    ttl64 *= 60 * 60 * 24;
                    break;
                case 'h':
                    ttl64 *= 60 * 60;
                    break;
                case 'm':
                    ttl64 *= 60;
                    break;
                case 's':
                    break;
            }

            if(ttl64 > MAX_S32)
            {
                ttl64 = MAX_S32;
            }

            ttl = (u32)ttl64;
        }

        *dst = ttl;

        return OK;
    }
    else
    {
        return ZRE_INCORRECT_TTL;
    }
}

/** @} */

/*----------------------------------------------------------------------------*/

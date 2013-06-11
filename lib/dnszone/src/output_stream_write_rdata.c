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
#include <ctype.h>

/* Added this for FreeBSD */
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif
/**/

#include <netinet/in.h>
#include <arpa/inet.h>

#if 1 // TODO why oh why ?
#undef DEBUG
#ifndef NDEBUG
#define NDEBUG
#endif
#endif

#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/rfc.h>
#include <dnscore/ctrl-rfc.h>
#include <dnscore/typebitmap.h>
#include <dnscore/output_stream.h>
#include <dnscore/parsing.h>
#include <dnscore/sys_error.h>
#include <dnscore/string_set.h>

#include "dnszone/output_stream_write_rdata.h"

static string_node* zone_types_set;
static string_node* zone_dnssec_set;
static bool output_stream_write_rdata_init_done = FALSE;

void
output_stream_write_rdata_init()
{
    if(output_stream_write_rdata_init_done)
    {
        return;
    }
    
    output_stream_write_rdata_init_done = TRUE;
    
    string_set_avl_init(&zone_types_set);
    string_set_avl_init(&zone_dnssec_set);

    string_node* node;
    
    node = string_set_avl_insert(&zone_types_set, "NONE");
    node->value       = ZT_HINT;
    node = string_set_avl_insert(&zone_types_set, "MASTER");
    node->value       = ZT_MASTER;
    node = string_set_avl_insert(&zone_types_set, "SLAVE");
    node->value       = ZT_SLAVE;
    node = string_set_avl_insert(&zone_types_set, "STUB");
    node->value       = ZT_STUB;
        
    node = string_set_avl_insert(&zone_dnssec_set, "NONE");
    node->value       = ZD_DNSSEC_NONE;
    node = string_set_avl_insert(&zone_dnssec_set, "UNSECURE");
    node->value       = ZD_DNSSEC_NONE;
    node = string_set_avl_insert(&zone_dnssec_set, "NSEC");
    node->value       = ZD_DNSSEC_NSEC;
    node = string_set_avl_insert(&zone_dnssec_set, "NSEC3");
    node->value       = ZD_DNSSEC_NSEC3;
    node = string_set_avl_insert(&zone_dnssec_set, "NSEC3OPTOUT");
    node->value       = ZD_DNSSEC_NSEC3_OPTOUT;
    node = string_set_avl_insert(&zone_dnssec_set, "NSEC3-OPTOUT");
    node->value       = ZD_DNSSEC_NSEC3_OPTOUT;
}

/*------------------------------------------------------------------------------
 * MACROS */

/* Skip numbers */
#define SKIP_DIGIT(ptr)								\
    while(isdigit((char)*ptr) && (*ptr != '\0'))				\
    {										\
            ptr++;								\
    }
     
#define SKIP_WHSPACE(ptr)							\
    while(isspace((char)*ptr) && (*ptr != '\0'))				\
    {										\
	ptr++;									\
    }

#define CUT_WORD(ptr)								\
    while(!isspace(*ptr) && (*ptr != '\0'))	\
    {										\
    	++ptr;								\
    }										\
    *ptr++ = '\0';

/* BASE_10 */
#define GET_VALUE(dst, src, range)						\
    SKIP_WHSPACE(src);								\
    needle = src;							        \
    CUT_WORD(needle);							        \
    if(FAIL(return_code=parse_u32_check_range(src, &dst, 0, range, 10)))        \
    {										\
	return return_code;							\
    }										\
    src  = needle;

#define GET_YYYYMMDDHHMMSS(dst, src)            				\
    SKIP_WHSPACE(src);								\
    needle = src;							        \
    CUT_WORD(needle);							        \
    if(FAIL(return_code=parse_yyyymmddhhmmss_check_range(src, &dst)))           \
    {										\
	return return_code;							\
    }										\
    src  = needle;


#define EXTRACT_WORD(ptr, value)						\
    SKIP_WHSPACE(ptr);								\
    value  = ptr;								\
    while(!isspace(*ptr) && (*ptr != '\0'))					\
    {										\
	ptr++;									\
    }										\
    if(*ptr != '\0')                                                            \
    {                                                                           \
        *ptr++ = '\0';                                                          \
    }

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */
/*
static u32            type_bit_maps_initialize(type_bit_maps_context *, char *);
static ya_result                              parse_soa_values(u_char *, u32 *);
static ya_result           add_origin(u_char *, const u_char *, const u_char *);
*/
/*------------------------------------------------------------------------------
 * FUNCTIONS */

static u32
type_bit_maps_initialize(type_bit_maps_context* context, char *src)
{
    u16                                                                type;

    u8                      *type_bitmap_field = context->type_bitmap_field;
    u8                                  *window_size = context->window_size;

    u32                                              type_bit_maps_size = 0;
    u8                                                                   ws;

    char                                                          *tmp_char;

    /*    ------------------------------------------------------------    */

    ZEROMEMORY(window_size, sizeof(context->window_size));
    context->last_type_window = -1;

    //    SKIP_WHITESPACE(src);
    if(*src == '\0')
    {
        return 1;
    }

    ZEROMEMORY(type_bitmap_field, sizeof(context->type_bitmap_field));

    do
    {
        EXTRACT_WORD(src, tmp_char);

        DEBUGF("BM: %s\n", tmp_char);

        if(FAIL(get_type_from_case_name(tmp_char, &type)))
        {
            return 0;
        }

        type = ntohs(type); /* types are now stored in NETWORK order */

        /* Network bit order */
        type_bitmap_field[type >> 3] |= 1 << (7 - (type & 7));
        window_size[type >> 8] = ((type & 0xf8) >> 3) + 1;

        context->last_type_window = MAX(type >> 8, context->last_type_window);
    }
    while(*src != '\0');

    for(s32 i = 0; i <= context->last_type_window; i++)
    {
        ws = window_size[i];

        if(ws > 0)
        {
            type_bit_maps_size += 1 + 1 + ws;
        }
    }

    context->type_bit_maps_size = type_bit_maps_size;

    return type_bit_maps_size;
}

static ya_result
parse_soa_values(char *src, u32 *soa_values)
{
    u8                                                            count = 0;

    /*    ------------------------------------------------------------    */

    /* If digit, put it in the array and check of total amount values in the array */
    SKIP_WHSPACE(src);

    if(OK == parse_u32_check_range(src, (u32 *)&soa_values[count], 0, MAX_U32, /*BASE_*/10))
    {
        ++count;
        SKIP_DIGIT(src);
        SKIP_WHSPACE(src);

        while(isdigit(*src) && (count < 5))
        {
            /*
             * This one handles the overflow too
             */

            if(ISOK(rr_get_ttl(src, &soa_values[count])))
            {
                while(!isspace(*src) && *src != '\0')
                {
                    src++;
                }
            }

            ++count;
            SKIP_WHSPACE(src);
        }
    }

    /* Check if we did not succeeded the correct amount of values */
    if((count != 5) || (*src != '\0'))
    {
        return INCORRECT_RDATA;
    }

    return OK;
}

static size_t strlenskipspaces(const char* str)
{
    size_t n = 0;
    
    while(*str != '\0')
    {
        if(!isspace(*str))
        {
            n++;
        }
        str++;
    }

    return n;
}

/** @brief Function ...
 *
 *  ...
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */
ya_result
output_stream_write_rdata(output_stream *os, char *src, const u16 src_type, const u8 *origin_fqdn)
{
    char                                                            *needle;
    char                                                             *limit;
    
    u32                                                       soa_values[5];

    u32                                                          tmp_uint32;
    u16                                                          tmp_uint16;

    u8                                                                    i;

    type_bit_maps_context                                           context;

    ya_result                                                   return_code;

    /*    ------------------------------------------------------------    */

    OSDEBUG(termout, "SOURCE LINE    : %s", src);
    SKIP_WHSPACE(src);

    /* At the end of the parsing of the line, after skipping the remaining
     * spaces, the pointer must be >= to limit, else it means we have crap
     * at the end of the line.
     */

    limit = src + strlen(src);
    
    while((limit > src) && (isspace(limit[-1])))
    {
        --limit;
        *limit = '\0';
    }

    OSDEBUG(termout, "SOURCE LEN     : %d", strlen(src));

    /*
     * rfc 3597
     *
     * \# length_10 HE XA DE CIMA LCODES
     */

    if(!(src[0] == '\\' && src[1] == '#'))  /* check we are not on the special rfc 3597 case */
    {
        return_code = SUCCESS;
        
        switch(src_type)
        {
            case TYPE_A:
            {
                in_addr_t                                                          addr;

                /* Create a network address structure
                 * from the the dotted-quad format ddd.ddd.ddd.ddd into a in_addr_t
                 */

                needle = src;
                CUT_WORD(needle);

                if(inet_pton(AF_INET, (char *) src, &addr))
                {
                    return_code = output_stream_write(os, (u8*)&addr, 4);

                    OSDEBUG(termout, "needle A: %s", needle);
                    src = needle;
                }
                else
                {
                    return_code = INCORRECT_IPADDRESS;
                }
                break;
            }
            case TYPE_DNAME:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_NS:
            case TYPE_CNAME:
            case TYPE_PTR:
            case TYPE_MD:   /** @NOTE: obsolete */
            case TYPE_MF:   /** NOTE: obsolete */
            case TYPE_MB:   /** NOTE: obsolete */
            case TYPE_MG:   /** NOTE: obsolete */
            case TYPE_MR:   /** NOTE: obsolete */
            case TYPE_WKS:   
            {
                needle = src;
                CUT_WORD(needle);

#ifdef DEBUG    // limit can be outside memory and needle should be equal to limit
               if(needle < limit) OSDEBUG(termout, "needle NS: %s", needle);
               OSDEBUG(termout, "src    NS: %s", src);
               flushout();
#endif
               
                return_code = output_stream_write_dname(os, src, origin_fqdn);

                src = needle;
               
#ifdef DEBUG    // limit can be outside memory and needle should be equal to limit
               if(src < limit) OSDEBUG(termout, "src2   NS: %s", src);
#endif

                /* else this is in fact an error code */
                /* will return the return_code at the end of the function */

    // OSDEBUG(termout, "SOURCE LEN DUF: %d", src); this prints a pointer as an integer ?
                   
                break;
            }
            case TYPE_SOA:
            {
                /* 1: Do MNAME */
                needle   = src;
                CUT_WORD(needle);

                return_code = output_stream_write_dname(os, src, origin_fqdn);

                /* 2: Do RNAME */
                SKIP_WHSPACE(needle);

                if(*needle == '\0') /* a.k.a strlen((const char *)needle) == 0 */
                {
                    return_code = INCORRECT_RDATA;
                    break;
                }

                src = needle;
                CUT_WORD(needle);

                /** @todo still needs to add a check of '\' in the rname */
                if(FAIL(return_code = output_stream_write_dname_with_escape(os, src, origin_fqdn)))
                {
                    break;
                }

                /* 3: Do SOA VALUES */
                SKIP_WHSPACE(needle);

                if(*needle == '\0') /* a.k.a strlen((const char *)needle) == 0 */
                {
                    return_code = INCORRECT_RDATA;
                    break;
                }

                /* Parse the number values of a SOA record */
                if(FAIL(return_code = parse_soa_values(needle, soa_values)))
                {
                    break;	/* will return the return_code at the end of the function */
                }

                for(i = 0; i < 5; i++)
                {
                    output_stream_write_nu32(os, soa_values[i]);
                }

                src = limit; /* parse_soa_values already handles the crap */

                /* will return the return_code of parse_soa_values at the end of the function */

                break;
            }
            case TYPE_HINFO:
            {
                u8 tmp[256];
                
                /* p-string () */
                
                SKIP_WHSPACE(src);
                
                if(FAIL(return_code = parse_pstring(&src, limit-src, tmp, sizeof(tmp))))
                {
                    break;
                }                
                output_stream_write(os, tmp, return_code);
                
                /* p-string () */
                
                SKIP_WHSPACE(src);
                
                if(FAIL(return_code = parse_pstring(&src, limit-src, tmp, sizeof(tmp))))
                {
                    break;
                }                
                output_stream_write(os, tmp, return_code);
                
                /* "domain name" (repl) */
                
                SKIP_WHSPACE(src);

                break;
            }
            case TYPE_MINFO:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_RP:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_ASFDB:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_X25:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_ISDN:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_RT:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_NSAP:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_NSAP_PTR:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_SIG:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_KEY:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_PX:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_GPOS:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_LOC:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_NXT:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_EID:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_NIMLOC:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_SRV:
            {                   
                /* 16 bits () */
                
                GET_VALUE(tmp_uint32, src, MAX_U16);
                output_stream_write_nu16(os, tmp_uint32);
                
                /* 16 bits () */
                
                GET_VALUE(tmp_uint32, src, MAX_U16);
                output_stream_write_nu16(os, tmp_uint32);
                
                /* 16 bits () */
                
                GET_VALUE(tmp_uint32, src, MAX_U16);
                output_stream_write_nu16(os, tmp_uint32);
                
                SKIP_WHSPACE(src);
                
                needle = src;
                CUT_WORD(needle);

                if(FAIL(return_code = output_stream_write_dname(os, src, origin_fqdn)))
                {
                    break;
                }
                
                src = needle;
                
                SKIP_WHSPACE(src);
                
                break;
            }
            case TYPE_ATMA:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_NAPTR:
            {                
                u8 tmp[256];
                
                /* 16 bits (order) */
                
                GET_VALUE(tmp_uint32, src, MAX_U16);
                output_stream_write_nu16(os, tmp_uint32);
                
                /* 16 bits (preference) */
                
                GET_VALUE(tmp_uint32, src, MAX_U16);
                output_stream_write_nu16(os, tmp_uint32);
                
                /* p-string (flags) */
                
                SKIP_WHSPACE(src);
                
                if(FAIL(return_code = parse_pstring(&src, limit-src, tmp, sizeof(tmp))))
                {
                    break;
                }                
                output_stream_write(os, tmp, return_code);
                
                /* p-string (service) */
                
                SKIP_WHSPACE(src);
                
                if(FAIL(return_code = parse_pstring(&src, limit-src, tmp, sizeof(tmp))))
                {
                    break;
                }                
                output_stream_write(os, tmp, return_code);
                
                /* p-string (regexp) */
                
                SKIP_WHSPACE(src);
                
                if(FAIL(return_code = parse_pstring(&src, limit-src, tmp, sizeof(tmp))))
                {
                    break;
                }                
                output_stream_write(os, tmp, return_code);
                
                /* "domain name" (repl) */
                
                SKIP_WHSPACE(src);
                
                needle = src;
                CUT_WORD(needle);

                if(FAIL(return_code = output_stream_write_dname(os, src, origin_fqdn)))
                {
                    break;
                }
                
                src = needle;
                
                SKIP_WHSPACE(src);
                
                break;
            }
            case TYPE_KX:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_CERT:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_A6:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_SINK:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_OPT:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_APL:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_IPSECKEY:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_DHCID:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_HIP:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_NINFO:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_RKEY:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_TALINK:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_SPF:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_UINFO:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_UID:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_GID:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_UNSPEC:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_TKEY:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_TSIG:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_MAILB:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_MAILA:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_URI:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_CAA:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_DLV:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_TA:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
            case TYPE_MX:
            {
                /* 1: Do PREFERENCE */

                /* Get the "keytag" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U16);
                output_stream_write_nu16(os, tmp_uint32);

                /* 2: Do DNAME */
                SKIP_WHSPACE(src);
                needle = src;
                CUT_WORD(needle);

                return_code = output_stream_write_dname(os, src, origin_fqdn);

                src = needle;

                break;
            }
            case TYPE_AAAA:
            {
                struct in6_addr                                             addr;

                needle = src;
                CUT_WORD(needle);

                /* Create a network address structure
                 * from the the dotted-quad format ddd.ddd.ddd.ddd into a in_addr_t
                 */
                if(inet_pton(AF_INET6, (char *) src, &addr))
                {
                    return_code = output_stream_write(os, (u8*)&addr, 16);

                    src = needle;
                }
                else
                {
                    return_code = INCORRECT_IPADDRESS;
                }
                
                break;
            }
            case TYPE_DS:
            {
                /* Get the "keytag" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U16);
                output_stream_write_nu16(os, tmp_uint32);

                /* Get the "algorithm" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);

                /* Get the "digest type" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);

                return_code = output_stream_decode_base16(os, (char*)src, strlen((const char *)src));

                /* will return the return_code at the end of the function */

                /* note that the crap is handled by the base16 decoder */

                src = limit;

                break;
            }

            case TYPE_RRSIG:
            {
                needle = src;
                CUT_WORD(needle);

                get_type_from_case_name(src, &tmp_uint16);	    /* returns the type in network order */
                output_stream_write_u16(os, tmp_uint16);	    /** @note NATIVETYPE */

                src = needle;

                /* Get the "algorithm" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);

                /* Get the "labels" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                /** @todo still needs to check the amount of labels */
                output_stream_write_u8(os, tmp_uint32);

                /* Get the "ttl" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U32);
                output_stream_write_nu32(os, tmp_uint32);

                /* Get the "Signature Expiration" part of the string and put it in a stream */
                GET_YYYYMMDDHHMMSS(tmp_uint32,src);
                /** @todo needs to check the data */
                output_stream_write_nu32(os, tmp_uint32);

                /* Get the "Signature Inception" part of the string and put it in a stream */
                GET_YYYYMMDDHHMMSS(tmp_uint32,src);
                /** @todo needs to check the data */
                output_stream_write_nu32(os, tmp_uint32);

                /* Get the "Key Tag" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U16);
                output_stream_write_nu16(os, tmp_uint32);

                /* Get the "Signer's Name" part of the string and put it in a stream */
                SKIP_WHSPACE(src);
                needle = src;
                CUT_WORD(needle);

                if(FAIL(return_code = output_stream_write_dname(os, src, origin_fqdn)))
                {
                    break;
                }

                /* Get the "Signature" part of the string and put it in a stream */
                src = needle;
                return_code = output_stream_decode_base64(os, (char*)src, strlen((const char *)src));

                /* note that the crap is handled by the base64 decoder */

                src = limit;


                break;
            }
            case TYPE_NSEC:
            {
                DEBUGF("NSEC0: %s\n", src);

                needle = src;
                SKIP_WHSPACE(needle);
                CUT_WORD(needle);
                SKIP_WHSPACE(needle);

                return_code = output_stream_write_dname(os, src, origin_fqdn);

                /* Get "Type Bit Maps" */
                src = needle;
                DEBUGF("TBM: %s\n", src);
                
                if(src < limit) /* if there are types in the types bitmap */
                {
                    if(type_bit_maps_initialize(&context, (char*)src) > 0)
                    {
                        output_stream_write_type_bit_maps(os, &context);

                        /* note that the crap is handled by type_bit_maps_initialize */

                        src = limit;
                    }
                    else
                    {
                        return_code = ZRE_CRAP_AT_END_OF_RECORD;
                    }
                }

                /* will return the return_code of output_stream_decode_base32hex */

                break;
            }
            case TYPE_DNSKEY:
            {
                /* Get the flags part of the string */
                GET_VALUE(tmp_uint32, src, MAX_U16);
                output_stream_write_nu16(os, tmp_uint32);

                /* Get Protocol part of the string */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);

                /* Get Algorithm part of the string */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);

                /* Get Public Key part of the string */
                return_code = output_stream_decode_base64(os, (char*)src, strlen((const char *)src));

                /* note that the crap is handled by the base64 decoder */

                src = limit;

                break;
            }

            case TYPE_NSEC3:
            {
                DEBUGF("NSEC3P0: %s\n", src);

                /* Get the "hash alg." part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);

                /* Get the "flags" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);

                /* Get the "iterations" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U16);
                output_stream_write_nu16(os, tmp_uint32);

                /* Get SALT */
                SKIP_WHSPACE(needle);
                src = needle;
                CUT_WORD(needle);

                /* Take not decoded string length */
                tmp_uint32 = strlen((const char *)src);

                /*
                 *  Check if "salt" not bigger than 255 characters
                 * 510 because it's 255 * 2 hex chars that have to be converted to a 255 bytes hash
                 *
                 */

                if(tmp_uint32 > 510)
                {
                    return SALT_TO_BIG;
                }

                /* Check if no "salt" */
                if((tmp_uint32 == 1) && (*src == '-'))
                {
                    tmp_uint32 = 0;
                }

                if(tmp_uint32 % 2 != 0)
                {
                    return SALT_NOT_EVEN_LENGTH;
                }

                /* Get the "salt length */
                output_stream_write_u8(os, tmp_uint32 / 2);

                /* Put "salt" in buffer */
                if(tmp_uint32 != 0)
                {
                    if(FAIL(return_code = output_stream_decode_base16(os, (char*)src, tmp_uint32)))
                    {
                        break;
                    }
                }

                SKIP_WHSPACE(needle);
                src = needle;
                CUT_WORD(needle);

                /* Take not decoded string length */
                tmp_uint32 = strlen((const char *)src);

                /* Check if "hash" not bigger than 255 characters */
                if(tmp_uint32 > 510)
                {
                    return HASH_TOO_BIG;
                }

                if(tmp_uint32 < 8 )
                {
                    return HASH_TOO_SMALL;
                }

                if((tmp_uint32 & 7) != 0)
                {
                    return HASH_NOT_X8_LENGTH;	/* Actually it's not "multiple of 8" length */
                }

                /* Get the "hash length */

                output_stream_write_u8(os, (tmp_uint32/8) * 5);
                DEBUGF("HASH: %s\n", src);

                /* Put "hash" in buffer */

                if(FAIL(return_code = output_stream_decode_base32hex(os, (char*)src, tmp_uint32)))
                {
                    return HASH_BASE32DECODE_FAILED;
                }

                if(return_code != (tmp_uint32/8) * 5)
                {
                    return HASH_BASE32DECODE_WRONGSIZE;
                }

                /* Get "Type Bit Maps" */
                src = needle;
                DEBUGF("TBM: %s\n", src);
                
                if(src < limit) /* if there are types in the types bitmap ... */
                {
                    if(type_bit_maps_initialize(&context, (char*)src) > 0)
                    {
                        output_stream_write_type_bit_maps(os, &context);

                        /* note that the crap is handled by type_bit_maps_initialize */

                        src = limit;
                    }
                    else
                    {
                        return_code = ZRE_CRAP_AT_END_OF_RECORD;
                    }
                }

                /* will return the return_code of output_stream_decode_base32hex */

                break;
            }
            case TYPE_NSEC3PARAM:
            {
                /* Get the "hash alg." part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);

                /* Get the "flags" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);

                /* Get the "iterations" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U16);
                output_stream_write_nu16(os, tmp_uint32);

                /* Get SALT */
                SKIP_WHSPACE(src);
                CUT_WORD(needle);

                tmp_uint32 = strlen((const char *)src); /* needle - src ? */

                /* Check if "salt" not bigger than 255 characters */
                if(tmp_uint32 > 510)
                {
                    return SALT_TO_BIG;
                }

                /* Check if no "salt" */
                if((tmp_uint32 == 1) && (*src == '-'))
                {
                    tmp_uint32 = 0;
                    output_stream_write_u8(os, 0);

                    return_code = OK;
                    src = needle;

                    break;
                }
                else if((tmp_uint32 & 1) != 0)
                {
                    return SALT_NOT_EVEN_LENGTH;
                }

                /* Get the "salt length */
                output_stream_write_u8(os, tmp_uint32 >> 1);

                return_code = output_stream_decode_base16(os, (char*)src, tmp_uint32);
        
                /* will return the return_code of output_stream_decode_base16 */

                /* note that the crap is handled by the base16 decoder */

                src = limit;

                break;
            }
            case TYPE_SSHFP:
            {
                /* Get the "algorithm" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);

                /* Get the "fp type" part of the string and put it in a stream */
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);

                /* Get the fingerprint */
                SKIP_WHSPACE(src);
                CUT_WORD(needle);
                
                tmp_uint32 = strlen((const char *)src);

                return_code = output_stream_decode_base16(os, (char*)src, tmp_uint32);

                /* note that the crap is handled by the base16 decoder */

                src = limit;

                break;
            }
            case TYPE_TLSA:
            {
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);
                                
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);
                
                GET_VALUE(tmp_uint32, src, MAX_U8);
                output_stream_write_u8(os, tmp_uint32);
                
                tmp_uint32 = strlen((const char *)src);

                return_code = output_stream_decode_base16(os, (char*)src, tmp_uint32);
                
                /* note that the crap is handled by the base16 decoder */
                
                src = limit;
                
                break;
            }
            case TYPE_TXT:
            {
                u8 tmp[256];
                
                OSDEBUG(termout, "[%s]", src);
                
                SKIP_WHSPACE(src);
                
                OSDEBUG(termout, "(%s)", src);
                
                while(src < limit)
                {                   
                    if(FAIL(return_code = parse_pstring(&src, limit-src, tmp, sizeof(tmp))))
                    {
                        break;
                    }
                    
                    /* write everything to RDATA to stream */
                    
                    output_stream_write(os, tmp, return_code);
                    SKIP_WHSPACE(src);
                }

                break;
            }
            
            
            default:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** @todo unsupported type ? TYPE## ? */
                break;
            }
        }

        if(ISOK(return_code) && (src < limit))
        {
            return_code = ZRE_CRAP_AT_END_OF_RECORD;
        }        
    }
    else    /* rfc 3597 support */
    {
        CUT_WORD(src);   /* skips the \# */
        SKIP_WHSPACE(src);

        needle = src;
        CUT_WORD(needle);   /* gets the length integer */

        GET_VALUE(tmp_uint32, src, MAX_U16);

        src = needle;	    /* the supposed length */

        if(strlenskipspaces(src) != (tmp_uint32<<1))
        {
            return INCORRECT_RDATA;
        }

        return_code = output_stream_decode_base16(os, src, strlen(src));
    }

   return return_code;
}                                    

/** @} */

/*----------------------------------------------------------------------------*/

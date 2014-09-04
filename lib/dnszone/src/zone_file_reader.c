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
*/

#include <fcntl.h>
#include <stddef.h>

#include <dnscore/parser.h>

#include <dnscore/logger.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/buffer_input_stream.h>

#include <dnscore/typebitmap.h>
#include <dnscore/base16.h>
#include <dnscore/base32hex.h>
#include <dnscore/base64.h>

#include "dnszone/dnszone.h"
#include "dnszone/zone_file_reader.h"

#define ZONE_FILE_READER_INCLUDE_DEPTH_MAX 16

extern logger_handle *g_zone_logger;
#define MODULE_MSG_HANDLE g_zone_logger

#define DEBUG_BENCH_TEXT_ZONE_PARSE 1
#ifndef DEBUG
#undef  DEBUG_BENCH_TEXT_ZONE_PARSE
#define DEBUG_BENCH_TEXT_ZONE_PARSE 0
#endif

static bool zone_file_reader_init_error_codes_done = FALSE;

static const char * const zfr_string_delimiters = "\"\"''";
static const char * const zfr_multiline_delimiters = "()";
static const char * const zrf_comment_markers = ";#";
static const char * const zrf_blank_makers = "\040\t\r";
static const char * const zfr_escape_characters = "\\";

typedef struct zone_file_reader zone_file_reader;
struct zone_file_reader
{
    parser_s parser;
    resource_record* unread_next;
    s32 zttl;
    s32 rttl;
    u32 dot_origin_size; // with the CHR0 sentinel
    u16 zclass;
    u16 rclass;
    u16 rdata_size;
    bool soa_found;
    bool template_source;
    
    u8   domain[MAX_DOMAIN_LENGTH];
    u8   origin[MAX_DOMAIN_LENGTH];
    char dot_origin[MAX_DOMAIN_LENGTH + 1];
    char text_buffer[512];
    u8 rdata[RDATA_MAX_LENGTH];    
    
    input_stream includes[ZONE_FILE_READER_INCLUDE_DEPTH_MAX];
    u8 includes_count;
};

static inline ya_result
zone_file_reader_copy_rdata_inline(parser_s *p, u16 rtype, u8 *rdata, u32 rdata_size, const u8 *origin)
{
    const char *text;
    u32 text_len;
    ya_result return_code;
    char text_buffer[1024];
    type_bit_maps_context tbmctx;
    
    if(FAIL(return_code = parser_copy_next_word(p, text_buffer, sizeof(text_buffer))))
    {
        return return_code;
    }

    text = text_buffer;    
    text_len = return_code;
    
    if(!((text_len >= 1) && (text[0] == '#')))
    {
        switch(rtype)
        {
            case TYPE_A:
            {
                if(inet_pton(AF_INET, text, rdata))
                {
                    return_code = 4;
                }
                else
                {
                    return_code = INCORRECT_IPADDRESS;
                }
                
                break;
            }
            case TYPE_AAAA:
            {
                if(inet_pton(AF_INET6, text, rdata))
                {
                    return_code = 16;
                }
                else
                {
                    return_code = INCORRECT_IPADDRESS;
                }
                break;
            }
            case TYPE_SOA:
            {
                s32 total_size;
                
                if(FAIL(return_code = cstr_to_locase_dnsname_with_check_len_with_origin(rdata, text, text_len, origin)))
                {
                    break;
                }
                
                total_size = return_code;
                
                rdata += return_code;
                rdata_size -= return_code;
                    
                if(FAIL(return_code = parser_copy_next_fqdn_locase_with_origin(p, rdata, origin)))
                {
                    break;
                }
                
                total_size += return_code + 20;
                
                rdata += return_code;
                rdata_size -= return_code;
                return_code = total_size;
                
                for(u8 i = 5; i > 0; i--)
                {
                    s32 tmp_int32;
                    ya_result err;
                    if(FAIL(err = parser_copy_next_ttl(p, &tmp_int32)))
                    {
                        return_code = err;
                        break;
                    }
                    tmp_int32 = htonl(tmp_int32);
                    SET_U32_AT_P(rdata, tmp_int32);
                    rdata += 4;
                }
                                
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
                return_code = cstr_to_locase_dnsname_with_check_len_with_origin(rdata, text, text_len, origin);
                
                break;
            }
            case TYPE_MX:
            {
                u16 preference;
                
                if(FAIL(return_code = parser_get_u16(text, text_len, &preference)))
                {
                    break;
                }
                preference = htons(preference);
                SET_U16_AT_P(rdata, preference);
                rdata += 2;
                
                if(FAIL(return_code = parser_copy_next_fqdn_locase_with_origin(p, rdata, origin)))
                {
                    break;
                }
                
                return_code += 2;
                
                break;
            }
            case TYPE_RRSIG:
            {
                u16 rtype;
                
                if(FAIL(return_code = get_type_from_case_name_len(text, text_len, &rtype)))
                {
                    break;
                }
                SET_U16_AT_P(rdata, rtype);
                rdata += 2;
                
                // algorithm (8 bits integer)
                
                if(FAIL(return_code = parser_copy_next_u8(p, rdata)))
                {
                    break;
                }
                
                rdata++;

                // labels (8 bits integer)
                
                if(FAIL(return_code = parser_copy_next_u8(p, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // original TTL (32 bits integer)
                
                s32 ttl;
                
                if(FAIL(return_code = parser_copy_next_ttl(p, &ttl)))
                {
                    break;
                }
                
                ttl = htonl(ttl);
                SET_U32_AT_P(rdata, ttl);
                rdata += 4;
                
                // signature expiration (YYYYMMDDHHMMSS epoch -> 32 bits)
                
                u32 epoch;
                
                if(FAIL(return_code = parser_copy_next_yyyymmddhhmmss(p, &epoch)))
                {
                    break;
                }
                
                epoch = htonl(epoch);
                SET_U32_AT_P(rdata, epoch);
                rdata += 4;
                
                // signature inception (YYYYMMDDHHMMSS epoch -> 32 bits)
                
                if(FAIL(return_code = parser_copy_next_yyyymmddhhmmss(p, &epoch)))
                {
                    break;
                }
                
                epoch = htonl(epoch);
                SET_U32_AT_P(rdata, epoch);
                rdata += 4;
                
                // key tag (16 bits integer)
                
                u16 tag;
                
                if(FAIL(return_code = parser_copy_next_u16(p, &tag)))
                {
                    break;
                }
                
                tag = htons(tag);
                SET_U16_AT_P(rdata, tag);
                rdata += 2;
                
                // signer's name (fqdn)
                
                if(FAIL(return_code = parser_copy_next_fqdn_with_origin(p, rdata, origin)))
                {
                    break;
                }
                
                rdata += return_code;
                
                u32 signer_len = return_code;
                
                // signature (base64)
                
                if(FAIL(return_code = parser_concat_next_tokens_nospace(p)))
                {
                    break;
                }
                
                if(FAIL(return_code = base64_decode(parser_text(p), parser_text_length(p), rdata)))
                {
                    break;
                }
                
                return_code += 18 + signer_len;
                
                break;
            }
            case TYPE_DNSKEY:
            {
                // flags
                
                u16 flags;
                
                if(FAIL(return_code = parser_get_u16(text, text_len, &flags)))
                {
                    break;
                }
                flags = htons(flags);
                SET_U16_AT_P(rdata, flags);
                rdata += 2;
                
                // protocol (8 bits integer)
                
                if(FAIL(return_code = parser_copy_next_u8(p, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // algorithm (8 bits integer)
                
                if(FAIL(return_code = parser_copy_next_u8(p, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // key (base64)
                
                if(FAIL(return_code = parser_concat_next_tokens_nospace(p)))
                {
                    break;
                }
                
                if(FAIL(return_code = base64_decode(parser_text(p), parser_text_length(p), rdata)))
                {
                    break;
                }
                
                return_code += 4;
                
                break;
            }
            case TYPE_NSEC3PARAM:
            {
                // hash algorithm
                
                if(FAIL(return_code = parser_get_u8(text, text_len, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // flags
                
                if(FAIL(return_code = parser_copy_next_u8(p, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // iterations
                
                u16 iterations;
                
                if(FAIL(return_code = parser_copy_next_u16(p, &iterations)))
                {
                    break;
                }
                
                iterations = htons(iterations);
                SET_U16_AT_P(rdata, iterations);
                rdata += 2;
                
                // salt
                
                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }
                
                if(FAIL(return_code = base16_decode(parser_text(p), parser_text_length(p), rdata + 1)))
                {
                    break;
                }
                
                if(return_code > 255)
                {
                    return_code = ZONEFILE_SALT_TOO_BIG; // parse error ...
                    break;
                }
                
                rdata[0] = (u8)return_code;
                
                return_code += 5;
                
                break;
            }
            case TYPE_NSEC3:
            {
                u8 *rdata_start = rdata;
                // hash algorithm
                
                if(FAIL(return_code = parser_get_u8(text, text_len, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // flags
                
                if(FAIL(return_code = parser_copy_next_u8(p, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // iterations
                
                u16 iterations;
                
                if(FAIL(return_code = parser_copy_next_u16(p, &iterations)))
                {
                    break;
                }
                
                iterations = htons(iterations);
                SET_U16_AT_P(rdata, iterations);
                rdata += 2;
                
                // salt
                
                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }
                
                if(FAIL(return_code = base16_decode(parser_text(p), parser_text_length(p), rdata + 1)))
                {
                    break;
                }
                
                if(return_code > 255)
                {
                    return_code = ZONEFILE_SALT_TOO_BIG; // parse error ...
                    break;
                }
                
                rdata[0] = (u8)return_code;
                
                rdata += return_code + 1;
                
                // digest
                
                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }
                
                if(FAIL(return_code = base32hex_decode(parser_text(p), parser_text_length(p), rdata + 1)))
                {
                    break;
                }
                
                rdata[0] = (u8)return_code;
                rdata += return_code + 1;
                
                // type bitmap
                
                if(FAIL(return_code = parser_type_bit_maps_initialize(p, &tbmctx)))
                {
                    break;
                }
                
                if(return_code > 0)
                {
                    type_bit_maps_write(rdata, &tbmctx);
                    rdata += return_code;
                }
                
                return_code = rdata - rdata_start;
                
                parser_set_eol(p);
                
                break;
            }
            case TYPE_NSEC:
            {
                u8 *rdata_start = rdata;
                
                if(FAIL(return_code = cstr_to_locase_dnsname_with_check_len_with_origin(rdata, text, text_len, origin)))
                {
                    break;
                }
                
                rdata += return_code;
                
                // type bitmap
                                
                if(FAIL(return_code = parser_type_bit_maps_initialize(p, &tbmctx)))
                {
                    break;
                }
                
                type_bit_maps_write(rdata, &tbmctx);
                
                rdata += return_code;
                
                return_code = rdata - rdata_start;
                
                parser_set_eol(p);
                
                break;
            }
            case TYPE_DS:
            {
                // keytag
                
                u16 keytag;
                
                if(FAIL(return_code = parser_get_u16(text, text_len, &keytag)))
                {
                    break;
                }
                keytag = htons(keytag);
                SET_U16_AT_P(rdata, keytag);
                rdata += 2;
                
                // algorithm
                
                if(FAIL(return_code = parser_copy_next_u8(p, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // digest type
                
                if(FAIL(return_code = parser_copy_next_u8(p, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // digest
                
                if(FAIL(return_code = parser_concat_next_tokens_nospace(p)))
                {
                    break;
                }
                
                if(FAIL(return_code = base16_decode(parser_text(p), parser_text_length(p), rdata)))
                {
                    break;
                }
                
                return_code += 4;
                
                break;
            }
            case TYPE_TXT:
            {
                u8 *rdata_start = rdata;
                
                for(;;)
                {
                    if(text_len > 255)
                    {
                        return_code = ZONEFILE_TEXT_TOO_BIG;
                        break;
                    }

                    *rdata++ = (u8)text_len;
                    memcpy(rdata, text, text_len);
                    rdata += text_len;

                    if(FAIL(return_code = parser_next_token(p)))
                    {
                        break;
                    }

                    if((return_code & (PARSER_COMMENT|PARSER_EOL|PARSER_EOF)) != 0)
                    {
                        // stop

                        break;
                    }
                    text = parser_text(p);
                    text_len = parser_text_length(p);
                }
                
                return_code = rdata - rdata_start;
                
                parser_set_eol(p);
                        
                break;
            }
            case TYPE_SSHFP:
            {
                // algorithm
                
                if(FAIL(return_code = parser_get_u8(text, text_len, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // fp type
                
                if(FAIL(return_code = parser_copy_next_u8(p, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // fingerprint
                
                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }
                
                if(FAIL(return_code = base16_decode(parser_text(p), parser_text_length(p), rdata)))
                {
                    break;
                }
                
                return_code += 2;
                
                break;
            }
            case TYPE_TLSA:
            {
                // ?
                
                if(FAIL(return_code = parser_get_u8(text, text_len, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // ?
                
                if(FAIL(return_code = parser_copy_next_u8(p, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // ?
                
                if(FAIL(return_code = parser_copy_next_u8(p, rdata)))
                {
                    break;
                }
                
                rdata++;
                
                // ?
                
                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }
                
                if(FAIL(return_code = base16_decode(parser_text(p), parser_text_length(p), rdata)))
                {
                    break;
                }
                
                return_code += 2;
                
                break;
            }
            case TYPE_SRV:
            {
                u16 tmp16;
                
                // ?                
                
                if(FAIL(return_code = parser_get_u16(text, text_len, &tmp16)))
                {
                    break;
                }
                tmp16 = htons(tmp16);
                SET_U16_AT_P(rdata, tmp16);
                rdata += 2;
                
                // ?
                
                if(FAIL(return_code = parser_copy_next_u16(p, &tmp16)))
                {
                    break;
                }
                tmp16 = htons(tmp16);
                SET_U16_AT_P(rdata, tmp16);
                rdata += 2;
                
                // ?
                
                if(FAIL(return_code = parser_copy_next_u16(p, &tmp16)))
                {
                    break;
                }
                tmp16 = htons(tmp16);
                SET_U16_AT_P(rdata, tmp16);
                rdata += 2;
                
                if(FAIL(return_code = parser_copy_next_fqdn_with_origin(p, rdata, origin)))
                {
                    break;
                }
                
                return_code += 6;
                break;
            }
            case TYPE_NAPTR:
            {
                u8 *rdata_start = rdata;
                u16 tmp16;
                
                // order
                
                if(FAIL(return_code = parser_get_u16(text, text_len, &tmp16)))
                {
                    break;
                }
                tmp16 = htons(tmp16);
                SET_U16_AT_P(rdata, tmp16);
                rdata += 2;
                
                // preference
                
                if(FAIL(return_code = parser_copy_next_u16(p, &tmp16)))
                {
                    break;
                }
                tmp16 = htons(tmp16);
                SET_U16_AT_P(rdata, tmp16);
                rdata += 2;
                
                // flags
                
                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }
                
                if((return_code & (PARSER_COMMENT|PARSER_EOL|PARSER_EOF)) != 0)
                {
                    // stop

                    break;
                }
                text = parser_text(p);
                text_len = parser_text_length(p);
                
                if(text_len > 255)
                {
                    return_code = ZONEFILE_FLAGS_TOO_BIG;
                    break;
                }
                
                *rdata++ = (u8)text_len;
                memcpy(rdata, text, text_len);
                rdata += text_len;
                
                // service
                
                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }
                
                if((return_code & (PARSER_COMMENT|PARSER_EOL|PARSER_EOF)) != 0)
                {
                    // stop

                    break;
                }
                text = parser_text(p);
                text_len = parser_text_length(p);
                
                if(text_len > 255)
                {
                    return_code = ZONEFILE_SERVICE_TOO_BIG;
                    break;
                }
                
                *rdata++ = (u8)text_len;
                memcpy(rdata, text, text_len);
                rdata += text_len;
                
                // regex
                
                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }
                
                if((return_code & (PARSER_COMMENT|PARSER_EOL|PARSER_EOF)) != 0)
                {
                    // stop

                    break;
                }
                text = parser_text(p);
                text_len = parser_text_length(p);
                
                if(text_len > 255)
                {
                    return_code = ZONEFILE_REGEX_TOO_BIG;
                    break;
                }
                
                *rdata++ = (u8)text_len;
                memcpy(rdata, text, text_len);
                rdata += text_len;
                
                if(FAIL(return_code = parser_copy_next_fqdn_with_origin(p, rdata, origin)))
                {
                    break;
                }
                
                return_code += rdata - rdata_start;
                break;
            }
            case TYPE_HINFO:
            {
                u8 *rdata_start = rdata;
                
                if(text_len > 255)
                {
                    return_code = ZONEFILE_TEXT_TOO_BIG;
                    break;
                }

                *rdata++ = (u8)text_len;
                memcpy(rdata, text, text_len);
                rdata += text_len;

                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }

                if((return_code & (PARSER_COMMENT|PARSER_EOL|PARSER_EOF)) != 0)
                {
                    // stop

                    break;
                }
                text = parser_text(p);
                text_len = parser_text_length(p);
                
                if(text_len > 255)
                {
                    return_code = ZONEFILE_TEXT_TOO_BIG;
                    break;
                }
                
                *rdata++ = (u8)text_len;
                memcpy(rdata, text, text_len);
                rdata += text_len;
                
                if(FAIL(return_code = parser_copy_next_fqdn_with_origin(p, rdata, origin)))
                {
                    break;
                }
                
                return_code += rdata - rdata_start;
                
                break;
            }
            case TYPE_OPT:
            case TYPE_TSIG:
            case TYPE_IXFR:
            case TYPE_AXFR:
            case TYPE_ANY:
            {
                return_code = ZONEFILE_INVALID_TYPE;
                break;
            }
            case TYPE_DNAME:
            case TYPE_NULL:
            case TYPE_MINFO:
            case TYPE_RP:
            case TYPE_ASFDB:
            case TYPE_X25:
            case TYPE_ISDN:
            case TYPE_RT:
            case TYPE_NSAP:
            case TYPE_NSAP_PTR:
            case TYPE_SIG:
            case TYPE_KEY:
            case TYPE_PX:
            case TYPE_GPOS:
            case TYPE_LOC:
            case TYPE_NXT:
            case TYPE_EID:
            case TYPE_NIMLOC:
            case TYPE_ATMA:
            case TYPE_KX:
            case TYPE_CERT:
            case TYPE_A6:
            case TYPE_SINK:
            case TYPE_APL:
            case TYPE_IPSECKEY:
            case TYPE_DHCID:
            case TYPE_HIP:
            case TYPE_NINFO:
            case TYPE_RKEY:
            case TYPE_TALINK:
            case TYPE_CDS:
            case TYPE_SPF:
            case TYPE_UINFO:
            case TYPE_UID:
            case TYPE_GID:
            case TYPE_UNSPEC:
            case TYPE_NID:
            case TYPE_L32:
            case TYPE_L64:
            case TYPE_LP:
            case TYPE_EUI48:
            case TYPE_EUI64:
            case TYPE_TKEY:
            case TYPE_MAILB:
            case TYPE_MAILA:
            case TYPE_URI:
            case TYPE_CAA:
            case TYPE_DLV:
            case TYPE_TA:
            {
                return_code = ZONEFILE_UNSUPPORTED_TYPE;    /** unsupported type, TYPE## */
                break;
            }
            default:
            {
                return_code = UNSUPPORTED_RECORD;
                log_err("parser_copy_rdata: %{dnstype}: %r", &rtype, return_code);
                break;
            }
        } // end switch
    }
    else
    {
        // hex
        
        return_code = ZONEFILE_RDATA_PARSE_ERROR; /// parse error
        
        if((text_len == 1) && (text[0] == '#'))
        {
            u16 unknown_rdata_len;
            
            if(ISOK(return_code = parser_copy_next_u16(p, &unknown_rdata_len)))
            {
                return_code = ZONEFILE_RDATA_BUFFER_TOO_SMALL; /// buffer too small
                
                if(unknown_rdata_len <= rdata_size)
                {
                    if(ISOK(return_code = parser_concat_next_tokens_nospace(p)))
                    {
                        if((return_code << 1) <= rdata_size)
                        {
                            if(ISOK(return_code = base16_decode(parser_text(p), parser_text_length(p), rdata)))
                            {
                                if(return_code != unknown_rdata_len)
                                {
                                    return_code = ZONEFILE_RDATA_SIZE_MISMATCH; /// unexpected size
                                }
                            }
                        }
                        else
                        {
                            return_code = ZONEFILE_RDATA_BUFFER_TOO_SMALL; /// buffer too small
                        }
                    }
                }
            }
        }
    }
    
    if(ISOK(return_code))
    {
        // expect to find EOL
        ya_result got_eol = parser_expect_eol(p);
        
        if(FAIL(got_eol))
        {
            return_code = got_eol;
            
            log_err("parser_copy_rdata: EXPECTED EOL: %{dnstype}: %r", &rtype, return_code);
        }
    }
    
    return return_code;
}

static ya_result
zone_file_reader_unread_record(zone_reader *zr, resource_record *entry)
{
    zone_file_reader *zfr = (zone_file_reader*)zr->data;
    resource_record *rr;
    u32 required = offsetof(resource_record,rdata) + entry->rdata_size;
    MALLOC_OR_DIE(resource_record*, rr, required, GENERIC_TAG);
    memcpy(rr, entry, required);
    rr->next = zfr->unread_next;
    zfr->unread_next = rr;
    
    return SUCCESS;
}

static ya_result
zone_file_reader_read_record(zone_reader *zr, resource_record *entry)
{
    yassert((zr != NULL) && (entry != NULL));

    zone_file_reader *zfr = (zone_file_reader*)zr->data;
    
    if(zfr->unread_next != NULL)
    {
        resource_record *top = zfr->unread_next;
        u32 required = offsetof(resource_record,rdata) + top->rdata_size;
        memcpy(entry, top, required);
        zfr->unread_next = top->next;
        free(top);
        
        return 0;
    }
    
    parser_s *p = &zfr->parser;
    ya_result return_code;
    
    for(;;)
    {
        if(ISOK(return_code = parser_next_token(p)))
        {
            if(!(return_code & PARSER_WORD))
            {
                if(return_code & PARSER_COMMENT)
                {
#if DO_PRINT
                    print("[COMMENT]");
#endif
                    continue;
                }

                if(return_code & PARSER_EOL)
                {
#if DO_PRINT
                    println("[EOL]");
#endif
                    continue;
                }

                if(return_code & PARSER_EOF)
                {
#if DO_PRINT
                    println("[EOF]");
#endif
                    input_stream *completed_stream = parser_pop_stream(p);
                    
#if (DNSDB_USE_POSIX_ADVISE != 0) && (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L)

                    input_stream *file_stream = buffer_input_stream_get_filtered(completed_stream);
                    
                    int fd = fd_input_stream_get_filedescriptor(file_stream);
                    fdatasync(fd);
                    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif              
                    input_stream_close(completed_stream);

                    if(parser_stream_count(p) > 0)
                    {
                        continue;
                    }
                    else
                    {
                        break;
                    }
                }
                
                continue;
            }

            p->needle_mark = p->text;
            
            // keywords or new domain

            u32 text_len = parser_text_length(p);
            const char *text = parser_text(p);

            if(text_len > 0)
            {
                if(text[0] == '$')
                {
                    // keyword match

                    if(parse_word_match(text, text_len, "$ORIGIN", 7))
                    {
                        if(FAIL(return_code = parser_next_word(p)))
                        {
                            return return_code;
                        }

                        text_len = parser_text_length(p);
                        text = parser_text(p);

                        memcpy(&zfr->dot_origin[1], text, text_len);
                        zfr->dot_origin_size = text_len + 1; // +1 for the dot
                        
                        if(FAIL(return_code = cstr_to_locase_dnsname_with_check_len(zfr->origin, &zfr->dot_origin[1], zfr->dot_origin_size - 1)))
                        {
                            return return_code;
                        }
                    }
                    else if(parse_word_match(text, text_len, "$TTL", 4))
                    {
                        if(FAIL(return_code = parser_copy_next_s32(p, &zfr->zttl)))
                        {
                            return return_code;
                        }
                    }
                    else if(parse_word_match(text, text_len, "$INCLUDE", 8))
                    {
                         char file_name[PATH_MAX];
    
                        if(FAIL(return_code = parser_copy_next_word(p, file_name, sizeof(file_name))))
                        {
                            return return_code;
                        }
                        
                        if((return_code & PARSER_WORD) != 0)
                        {
                            ya_result err;
                            
                            if(ISOK(err = file_input_stream_open(file_name, &zfr->includes[zfr->includes_count])))
                            {
                                parser_push_stream(&zfr->parser, &zfr->includes[zfr->includes_count]);
/*
#if (DNSDB_USE_POSIX_ADVISE != 0) && (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L)
                                int fd = fd_input_stream_get_filedescriptor(&zfr->includes[zfr->includes_count]);
                                fdatasync(fd);
                                posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
*/
                                zfr->includes_count++;
                            }
                            else
                            {
                                return err;
                            }
                        }
                        else
                        {
                            return_code = ZONEFILE_EXPECTED_FILE_PATH;
                            return return_code;
                        }
                    }
                    else if(parse_word_match(text, text_len, "$GENERATE", 9))
                    {
                        return ZONEFILE_FEATURE_NOT_SUPPORTED;
                    }
                    else if(parse_word_match(text, text_len, "$CLASS", 6))
                    {
                    }
                    else if(parse_word_match(text, text_len, "$RETURN", 7))
                    {
                        input_stream *completed_stream = parser_pop_stream(p);
                        input_stream_close(completed_stream);

                        if(parser_stream_count(p) > 0)
                        {
                            continue;
                        }
                        else
                        {
                            break;
                        }
                    }
                    else if(parse_word_match(text, text_len, "$END", 4))
                    {
                        break;
                    }
                }
                else
                {
                    // domain
                    if((return_code & PARSER_BLANK_START) == 0)
                    {
                        // new domain
                        
                        u8 *domain = entry->name;
                        
                        if(!((text_len == 1) && (text[0] == '@')))
                        {
                            if(text[text_len - 1] != '.')
                            {
                                /*
                                memcpy(zfr->text_buffer, text, text_len);
                                memcpy(&zfr->text_buffer[text_len], zfr->dot_origin, zfr->dot_origin_size);
                                text_len += zfr->dot_origin_size;
                                text = zfr->text_buffer;
                                */
                                if(FAIL(return_code = charp_to_locase_dnsname_with_check(domain, text, text_len)))
                                {
                                    return return_code;
                                }
                                
                                if(FAIL(return_code = dnsname_copy(&domain[return_code - 1], zfr->origin)))
                                {
                                    return return_code;
                                }
                            }
                            else
                            {
                                if(FAIL(return_code = charp_to_locase_dnsname(domain, text, text_len)))
                                {
                                    return return_code;
                                }
                            }
                        }
                        else
                        {
                            /*
                            if(FAIL(return_code = charp_to_dnsname(domain, &zfr->dot_origin[1], zfr->dot_origin_size - 1)))
                            {
                                return return_code;
                            }
                            */
                            if(FAIL(return_code = dnsname_copy(domain, zfr->origin)))
                            {
                                return return_code;
                            }

                            if(FAIL(return_code = dnsname_to_cstr(&zfr->dot_origin[1], zfr->origin)))
                            {
                                return return_code;
                            }
                            
                            zfr->dot_origin_size = return_code + 1;
                            zfr->template_source = TRUE;
                        }
                    }
                    else
                    {
                        parser_rewind(p);
                    }
                    // TTL CLASS TYPE ... RDATA

                    parser_mark(p);
                    if(FAIL(parser_copy_next_ttl(p, &zfr->rttl)))
                    {
                        parser_rewind(p);
                    }
                    entry->ttl = zfr->rttl;
                    
                    u16 rclass = CLASS_NONE;
                    
                    parser_mark(p);
                    if(FAIL(parser_copy_next_class(p, &rclass)))
                    {
                        parser_rewind(p);
                    }

                    entry->class = zfr->zclass;
                    
                    u16 rtype;
                    
                    if(FAIL(return_code = parser_copy_next_type(p, &rtype)))
                    {
                        return return_code;
                    }
                    
                    entry->type = rtype;

                    if(rtype == TYPE_SOA)
                    {
                        if(rclass == CLASS_NONE)
                        {
                            return ZONEFILE_SOA_WITHOUT_CLASS;
                        }

                        entry->class = rclass;
                    }
#ifdef RR_OS_RDATA
                    if(FAIL(return_code = zone_file_reader_copy_rdata_inline(p, rtype, zfr->rdata, sizeof(zfr->rdata), zfr->origin)))
                    {
                        return return_code;
                    }

                    // assigns the content of the rdata to the record ...

                    bytearray_output_stream_set(&entry->os_rdata, zfr->rdata, return_code, FALSE);
#else
                    if(FAIL(return_code = zone_file_reader_copy_rdata_inline(p, rtype, entry->rdata, sizeof(entry->rdata), zfr->origin)))
                    {
                        return return_code;
                    }

                    entry->rdata_size = return_code;
#endif                    
                    // FULL RECORD READY
                    
                    return SUCCESS;
                }
            }

            
#if DO_PRINT
            flushout();
#endif
        }
        else
        {
            formatln("[ERROR %r]", return_code);
            break;
        }
    }
    
    if(ISOK(return_code))
    {
        return_code = 1;
    }
    
    return return_code;
}


static ya_result
zone_file_reader_free_record(zone_reader *zone, resource_record *entry)
{
    return OK;
}

/** @brief Closes a zone file entry
 *
 *  Closes a zone file entry.  The function will do nothing if the zonefile has already been closed
 *
 *  @param[in] zonefile a pointer to a valid (zone_file_open'ed) zone-file structure
 *
 */
static void
zone_file_reader_close(zone_reader *zr)
{
    yassert(zr != NULL);

    zone_file_reader *zfr = (zone_file_reader*)zr->data;
    
    parser_finalize(&zfr->parser);
/*
#if (DNSDB_USE_POSIX_ADVISE != 0) && (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L)
    int fd = fd_input_stream_get_filedescriptor(&zfr->includes[0]);
    fdatasync(fd);
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
*/    
    resource_record *rr = zfr->unread_next;
    while(rr != NULL)
    {
        resource_record *tmp = rr;
        rr = rr->next;
        free(tmp);
    }
    
    free(zfr);
    
    zr->data = NULL;
    zr->vtbl = NULL;
}

static bool
zone_file_reader_canwriteback(zone_reader *zr)
{
    yassert(zr != NULL);

    zone_file_reader *zfr = (zone_file_reader*)zr->data;
    return !zfr->template_source;
}

static void
zone_file_reader_handle_error(zone_reader *zr, ya_result error_code)
{
    /* nop */
}


static zone_reader_vtbl zone_file_reader_vtbl =
{
    zone_file_reader_read_record,
    zone_file_reader_unread_record,
    zone_file_reader_free_record,
    zone_file_reader_close,
    zone_file_reader_handle_error,
    zone_file_reader_canwriteback,
    "zone_file_reader_v2"
};


void
zone_file_reader_init_error_codes()
{
    if(zone_file_reader_init_error_codes_done)
    {
        return;
    }
    
    zone_file_reader_init_error_codes_done = TRUE;
    
    error_register(ZONEFILE_FEATURE_NOT_SUPPORTED, "ZONEFILE_FEATURE_NOT_SUPPORTED");
    error_register(ZONEFILE_EXPECTED_FILE_PATH, "ZONEFILE_EXPECTED_FILE_PATH");
    error_register(ZONEFILE_SOA_WITHOUT_CLASS, "ZONEFILE_SOA_WITHOUT_CLASS");
    error_register(ZONEFILE_SALT_TOO_BIG, "ZONEFILE_SALT_TOO_BIG");
    error_register(ZONEFILE_TEXT_TOO_BIG, "ZONEFILE_TEXT_TOO_BIG");
    error_register(ZONEFILE_FLAGS_TOO_BIG, "ZONEFILE_FLAGS_TOO_BIG");
    error_register(ZONEFILE_SERVICE_TOO_BIG, "ZONEFILE_SERVICE_TOO_BIG");
    error_register(ZONEFILE_REGEX_TOO_BIG, "ZONEFILE_REGEX_TOO_BIG");
    error_register(ZONEFILE_RDATA_PARSE_ERROR, "ZONEFILE_RDATA_PARSE_ERROR");
    error_register(ZONEFILE_RDATA_BUFFER_TOO_SMALL, "ZONEFILE_RDATA_BUFFER_TOO_SMALL");
    error_register(ZONEFILE_RDATA_SIZE_MISMATCH, "ZONEFILE_RDATA_SIZE_MISMATCH");
}

static ya_result
zone_file_reader_init(zone_reader *zr)
{
    ya_result error_code;
    zone_file_reader *zfr;
    
    /*    ------------------------------------------------------------    */
    
    MALLOC_OR_DIE(zone_file_reader*, zfr, sizeof (zone_file_reader), ZFREADER_TAG);

    ZEROMEMORY(zfr, sizeof (zone_file_reader));

    if(ISOK(error_code = parser_init(&zfr->parser,
        zfr_string_delimiters,      // by 2
        zfr_multiline_delimiters,   // by 2
        zrf_comment_markers,        // by 1
        zrf_blank_makers,           // by 1
        zfr_escape_characters)))    // by 1
    {     
        zfr->zttl = 86400;
        zfr->rttl = 86400;
        zfr->dot_origin_size = 2; // with the CHR0 sentinel
        zfr->zclass = CLASS_IN;
        zfr->rclass = CLASS_IN;
        zfr->rdata_size = 0;
        zfr->soa_found = FALSE;
        zfr->domain[0] = (u8)'\0';
        zfr->dot_origin[0] = '.';
        zfr->dot_origin[1] = '\0';
    }
    
    zr->data = zfr;
    zr->vtbl = &zone_file_reader_vtbl;
    
    return error_code;
}

ya_result
zone_file_reader_parse_stream(input_stream *ins, zone_reader *zr)
{
    if(ISOK(zone_file_reader_init(zr)))
    {    
        zone_file_reader *zfr = (zone_file_reader*)zr->data;
        
        // push the stream
        
        parser_push_stream(&zfr->parser, ins);
    }

    return OK;
}

#if DEBUG_BENCH_TEXT_ZONE_PARSE

static debug_bench_s zone_file_reader_parse;
static bool zone_file_reader_parse_done = FALSE;

static inline void zone_file_reader_bench_register()
{
    if(!zone_file_reader_parse_done)
    {
        zone_file_reader_parse_done = TRUE;
        debug_bench_register(&zone_file_reader_parse, "text parse");
    }
}

#endif

/** @brief Opens a zone file
 *
 *  Opens a zone file
 *
 *  @param[in]  fullpath the path and name of the file to open
 *  @param[out] zone a pointer to a structure that will be used by the function
 *              to hold the zone-file information
 *
 *  @return     A result code
 *  @retval     OK   : the file has been opened successfully
 *  @retval     else : an error occurred
 */
ya_result
zone_file_reader_open(const char* fullpath, zone_reader *zr)
{
    ya_result return_value;
    
#if DEBUG_BENCH_TEXT_ZONE_PARSE
    zone_file_reader_bench_register();
    u64 bench = debug_bench_start(&zone_file_reader_parse);
#endif
    
    if(ISOK(return_value = zone_file_reader_init(zr)))
    {
        // push the stream
        
        zone_file_reader *zfr = (zone_file_reader*)zr->data;
        
        if(ISOK(return_value = file_input_stream_open(fullpath, &zfr->includes[0])))
        {
/*
#if (DNSDB_USE_POSIX_ADVISE != 0) && (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L)
            int fd = fd_input_stream_get_filedescriptor(&zfr->includes[0]);
            fdatasync(fd);
            posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
*/
            parser_push_stream(&zfr->parser, &zfr->includes[zfr->includes_count++]);
        }
        else
        {
            log_debug("zone file: cannot open: '%s': %r", fullpath, return_value);
            
            zone_file_reader_close(zr);
            
            return return_value;
        }
        
#if DEBUG_BENCH_TEXT_ZONE_PARSE
        zone_file_reader_bench_register();
        debug_bench_stop(&zone_file_reader_parse, bench);
#endif
    }
    
    return return_value;
}

void
zone_file_reader_ignore_missing_soa(zone_reader *zr)
{
    zone_file_reader *zfr = (zone_file_reader*)zr->data;
    zfr->soa_found = TRUE;
}


ya_result
zone_file_reader_set_origin(zone_reader *zr, const u8* origin)
{
    zone_file_reader *zfr = (zone_file_reader*)zr->data;
    ya_result return_code = dnsname_copy(zfr->origin, origin);
    return return_code;
}

ya_result
zone_file_reader_copy_rdata(const char *text, u16 rtype, u8 *rdata, u32 rdata_size, const u8 *origin)
{
    parser_s parser;
    
    ya_result return_code;
    
    char buffer[4096];
    
    int n = strlen(text);
    
    if(n > sizeof(buffer) - 2)
    {
        return -1;
    }
    
    if(text[n - 1] != '\n')
    {
        memcpy(buffer, text, n);
        buffer[n] = '\n';
        buffer[n + 1] = '\0';
        n++;
        text = buffer;
    }

    if(ISOK(return_code = parser_init(&parser,
        zfr_string_delimiters,      // by 2
        zfr_multiline_delimiters,   // by 2
        zrf_comment_markers,        // by 1
        zrf_blank_makers,           // by 1
        zfr_escape_characters)))    // by 1
    {
        input_stream text_is;

        bytearray_input_stream_init((const u8*)text, n, &text_is, FALSE);
        
        if(ISOK(return_code = parser_push_stream(&parser, &text_is)))
        {        
            return_code = zone_file_reader_copy_rdata_inline(&parser, rtype, rdata, rdata_size, origin);
        }
        
        // will be closed by the parser
        // input_stream_close(&text_is);
        
        parser_finalize(&parser);
    }
    
    return return_code;
}

/** @} */


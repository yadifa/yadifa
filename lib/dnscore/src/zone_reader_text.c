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

#include "dnscore/dnscore-config.h"

#include <fcntl.h>
#include <stddef.h>
#include <arpa/inet.h>

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
#include <dnscore/fdtools.h>

#include "dnscore/zone_reader_text.h"

#define ZFREADER_TAG 0x524544414552465a
#define ZFERRMSG_TAG 0x47534d525245465a
#define ZONE_FILE_READER_INCLUDE_DEPTH_MAX 16

#define DOT_SYMBOL '.'

#if !DNSCORE_HAS_FULL_ASCII7
#define AT_SYMBOL '@'
#define VAR_SYMBOL '$'
#else
#define AT_SYMBOL ((char)0xff)
#define VAR_SYMBOL ((char)0xfe)
//#define DOT_SYMBOL ((char)0xfd)
#endif

logger_handle *g_zone_logger = LOGGER_HANDLE_SINK;
#define MODULE_MSG_HANDLE g_zone_logger

#define DEBUG_BENCH_TEXT_ZONE_PARSE 1
#if !DEBUG
#undef  DEBUG_BENCH_TEXT_ZONE_PARSE
#define DEBUG_BENCH_TEXT_ZONE_PARSE 0
#endif

static bool zone_reader_text_init_error_codes_done = FALSE;

static const char * const zfr_string_delimiters = "\"\"";
static const char * const zfr_multiline_delimiters = "()";
static const char * const zrf_comment_markers = ";";
static const char * const zrf_blank_makers = "\040\t\r";
static const char * const zfr_escape_characters = "\\";

#define ZONE_FILE_READER_MESSAGE_STATIC     0
#define ZONE_FILE_READER_MESSAGE_ALLOCATED  1

typedef struct zone_reader_text zone_reader_text;
struct zone_reader_text
{
    parser_s parser;
    resource_record* unread_next;
    s32 rttl_default;   // $TTL
    s32 rttl_current;
    u32 dot_origin_size; // with the CHR0 sentinel
    s32 origin_stack_size;
    u16 rclass_current;
    u16 rdata_size;
    bool soa_found;
    bool template_source;
    bool rttl_default_defined;
    bool rttl_current_defined;

    u8   domain[MAX_DOMAIN_LENGTH + 1];
    u8   origin[MAX_DOMAIN_LENGTH + 1];
    char dot_origin[MAX_DOMAIN_LENGTH + 1];
    u8 *origin_stack[PARSER_INCLUDE_DEPTH_MAX];

    u8 rdata[RDATA_MAX_LENGTH];

    input_stream includes[ZONE_FILE_READER_INCLUDE_DEPTH_MAX];
    char *file_name[ZONE_FILE_READER_INCLUDE_DEPTH_MAX];

    u8 includes_count;
    //
    ya_result error_message_code;
    u8 error_message_allocated; // 0: static 1: malloc
    char *error_message_buffer; // It's not aligned but this is an exception :
                                // _ This is a rarely used structure (don't care too much about a hole)
                                // _ This is an hopefully rarely used field (best case: "never" (besides setting it up to NULL))
                                // _ Putting it among the more popular fields will likely increase misses
};

static void
zone_reader_text_free_error_message(zone_reader_text *zfr)
{
    if(zfr->error_message_allocated == ZONE_FILE_READER_MESSAGE_ALLOCATED)
    {
        free(zfr->error_message_buffer);
    }
}
/*
static void
zone_reader_text_clear_error_message(zone_reader_text *zfr)
{
    zone_reader_text_free_error_message(zfr);
    zfr->error_message_buffer = NULL;
}
*/

static ya_result
zone_reader_text_cstr_to_locase_dnsname_with_check_len_with_origin(u8* name_parm, const char* text, u32 text_len, const u8 *origin, parser_s *p)
{
    ya_result ret;
    if(FAIL(ret = cstr_to_locase_dnsname_with_check_len_with_origin(name_parm, text, text_len, origin)))
    {
        bool retry = FALSE;
        char retry_text[MAX_DOMAIN_LENGTH];

        if(text_len <= MAX_DOMAIN_LENGTH)
        {
            for(u32 i = 0; i < text_len; ++i)
            {
                char c = text[i];
                switch(c)
                {
                    case VAR_SYMBOL:
                    {
                        retry_text[i] = '$';
                        retry = TRUE;
                        break;
                    }
                    case AT_SYMBOL:
                    {
                        retry_text[i] = '@';
                        retry = TRUE;
                        break;
                    }
                    default:
                    {
                        retry_text[i] = c;
                        break;
                    }
                }
            }
        }

        if(retry)
        {
            if(ISOK(ret = cstr_to_locase_dnsname_with_check_len_with_origin(name_parm, retry_text, text_len, origin)))
            {
                // an escape is probably missing
                /*
                char *file_name = "?";
                if((p->includes_count > 0) && (p->includes_count < ZONE_FILE_READER_INCLUDE_DEPTH_MAX))
                {
                    if(p->file_name[p->includes_count - 1] != NULL)
                    {
                        file_name = p->file_name[p->includes_count - 1];
                    }
                }

                log_warn("zone parse: there is probably an escape missing in front of a '$' or a '@' in file '%s' at line %u for %{dnsname}",  file_name, p->line_number, domain);
                */
                log_warn("zone parse: there is probably an escape missing in front of a '$' or a '@' at line %u for %{dnsname}", p->line_number, name_parm);
            }
        }
    }

    return ret;
}

static inline ya_result
zone_reader_text_copy_rdata_inline(parser_s *p, u16 rtype, u8 *rdata, u32 rdata_size, const u8 *origin)
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

                if(FAIL(return_code = zone_reader_text_cstr_to_locase_dnsname_with_check_len_with_origin(rdata, text, text_len, origin, p)))
                {
                    break;
                }

                total_size = return_code;

                rdata += return_code;

                if(FAIL(return_code = parser_copy_next_fqdn_locase_with_origin(p, rdata, origin)))
                {
                    break;
                }

                total_size += return_code + 20;

                rdata += return_code;
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
#if !HAS_NOOBSOLETETYPES
            case TYPE_MD:   /** @NOTE: obsolete */
            case TYPE_MF:   /** NOTE: obsolete */
            case TYPE_MB:   /** NOTE: obsolete */
            case TYPE_MG:   /** NOTE: obsolete */
            case TYPE_MR:   /** NOTE: obsolete */
#endif
            {
                return_code = zone_reader_text_cstr_to_locase_dnsname_with_check_len_with_origin(rdata, text, text_len, origin, p);

                break;
            }
#if !HAS_NOOBSOLETETYPES
            case TYPE_WKS:
            {
                // ip address
                if(!inet_pton(AF_INET, text, rdata))
                {
                    return_code = INCORRECT_IPADDRESS;
                    break;
                }
                rdata += 4;

                int protocol;
                if(FAIL(return_code = parser_get_network_protocol_from_next_word(p, &protocol)))
                {
                    break;
                }

                rdata[0] = (u8) protocol;
                rdata++;
                
                ZEROMEMORY(rdata, rdata_size - 1);
                int port_limit = (rdata_size - 5) << 3;
                int max_index = -1;
                
                for(;;)
                {
                    int service_port;
                    if(FAIL(return_code = parser_get_network_service_port_from_next_word(p, &service_port)))
                    {
                        break;
                    }
                    
                    if(service_port > port_limit)
                    {
                        return_code = MAKE_ERRNO_ERROR(ERANGE); /// @todo 20181018 edf -- consider having a value/parameter "out of range" error code
                        break;
                    }
                    
                    int index = service_port >> 3;
                    
                    rdata[index] |= 0x80 >> (service_port & 7);

                    if(index > max_index)
                    {
                        max_index = index;
                    }
                }
                
                if(FAIL(return_code))
                {
                    break;
                }
                
                if(max_index < 0) // @todo 20150608 timh -- is this the right way to do it?
                {
                    return_code = INVALID_RECORD;
                    break;
                }

                return_code = max_index + 6; // ipv4 + proto + index=>+1

                parser_set_eol(p);  // @todo 20150608 timh -- is this necessary?
                break;
            }
#endif
            case TYPE_MX:
            case TYPE_KX:
            case TYPE_LP:
            case TYPE_AFSDB:
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

                if(FAIL(return_code = dns_type_from_case_name_length(text, text_len, &rtype)))
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
            case TYPE_CDNSKEY:
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
                    if(ISOK(return_code = parser_copy_word(p, text_buffer, sizeof(text_buffer))))
                    {
                        if(FAIL(return_code = dns_encryption_algorithm_from_name(text_buffer, rdata)))
                        {
                            break;
                        }
                    }
                    else
                    {
                        break;
                    }
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
            
            case TYPE_OPENPGPKEY:
            {
                if(FAIL(return_code = parser_concat_current_and_next_tokens_nospace(p)))
                {
                    break;
                }

                return_code = base64_decode(parser_text(p), parser_text_length(p), rdata);
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
                
                if(! ((parser_text_length(p) == 1) && (parser_text(p)[0] == '-')) )
                {
                    if(FAIL(return_code = base16_decode(parser_text(p), parser_text_length(p), rdata + 1)))
                    {
                        break;
                    }

                    if(return_code > 255)
                    {
                        return_code = ZONEFILE_SALT_TOO_BIG; // parse error ...
                        break;
                    }
                }
                else
                {
                    // no salt
                    return_code = 0;
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
                
                if(! ((parser_text_length(p) == 1) && (parser_text(p)[0] == '-')) )
                {
                    if(FAIL(return_code = base16_decode(parser_text(p), parser_text_length(p), rdata + 1)))
                    {
                        break;
                    }

                    if(return_code > 255)
                    {
                        return_code = ZONEFILE_SALT_TOO_BIG; // parse error ...
                        break;
                    }
                }
                else
                {
                    return_code = 0;
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

                if(FAIL(return_code = parser_type_bit_maps_initialise(p, &tbmctx)))
                {
                    break;
                }

                if(return_code > 0)
                {
                    type_bit_maps_write(&tbmctx, rdata);
                    rdata += return_code;
                }

                return_code = rdata - rdata_start;

                parser_set_eol(p);

                break;
            }
            
            case TYPE_NSEC:
            {
                u8 *rdata_start = rdata;

                if(FAIL(return_code = zone_reader_text_cstr_to_locase_dnsname_with_check_len_with_origin(rdata, text, text_len, origin, p)))
                {
                    break;
                }

                rdata += return_code;

                // type bitmap

                if(FAIL(return_code = parser_type_bit_maps_initialise(p, &tbmctx)))
                {
                    break;
                }

                type_bit_maps_write(&tbmctx, rdata);

                rdata += return_code;

                return_code = rdata - rdata_start;

                parser_set_eol(p);

                break;
            }
            
            case TYPE_DS:
            case TYPE_CDS:
            case TYPE_DLV:
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
            case TYPE_SPF:  // discontinued
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

                if(ISOK(return_code))
                {
                    return_code = rdata - rdata_start;
                    parser_set_eol(p);
                }

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

                if(FAIL(return_code = parser_concat_next_tokens_nospace(p)))
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

                if(FAIL(return_code = parser_concat_next_tokens_nospace(p)))
                {
                    break;
                }

                if(FAIL(return_code = base16_decode(parser_text(p), parser_text_length(p), rdata)))
                {
                    break;
                }

                return_code += 3;

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

            // exist out of two parts
            // 1. mbox-dname
            // 2. txt-dname
            case TYPE_RP:
            {
                u8 *rdata_start = rdata;

                // 1.mbox-name1
                //s32 total_size;

                // return_code = "length" or "error code"
                if(FAIL(return_code = zone_reader_text_cstr_to_locase_dnsname_with_check_len_with_origin(rdata, text, text_len, origin, p)))
                {
                    break;
                }

                // set rdata to the next chunk
                rdata += return_code;

                if(FAIL(return_code = parser_copy_next_fqdn_locase_with_origin(p, rdata, origin)))
                {
                    break;
                }

                return_code = rdata - rdata_start + return_code;
                break;
            }

            case TYPE_HINFO: // should not be supported anymore
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
            
            case TYPE_NID:
            case TYPE_L64:
            {
                u16 preference;

                if(FAIL(return_code = parser_get_u16(text, text_len, &preference)))
                {
                    break;
                }
                preference = htons(preference);
                SET_U16_AT_P(rdata, preference);
                
                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }
                
                memcpy(text_buffer, parser_text(p), parser_text_length(p));
                text_buffer[parser_text_length(p)] = '\0';
                
                // hex:hex:hex:hex
                
                unsigned int a,b,c,d;
                if(sscanf(text_buffer, "%x:%x:%x:%x", &a,&b,&c,&d) != 4)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }
                
                if((a|b|c|d) > 65535)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }
                                
                SET_U16_AT(rdata[2], htons((u16)a));
                SET_U16_AT(rdata[4], htons((u16)b));
                SET_U16_AT(rdata[6], htons((u16)c));
                SET_U16_AT(rdata[8], htons((u16)d));
                
                return_code = 10;
                
                break;
            }
            case TYPE_L32:
            {
                u16 preference;

                if(FAIL(return_code = parser_get_u16(text, text_len, &preference)))
                {
                    break;
                }
                preference = htons(preference);
                SET_U16_AT_P(rdata, preference);
                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }
                
                memcpy(text_buffer, parser_text(p), parser_text_length(p));
                text_buffer[parser_text_length(p)] = '\0';
                
                // hex:hex:hex:hex
                
                unsigned int a,b,c,d;
                if(sscanf(text_buffer, "%u.%u.%u.%u", &a,&b,&c,&d) != 4)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }
                
                if((a|b|c|d) > 255)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }
                
                rdata[2] = (u8)a;
                rdata[3] = (u8)b;
                rdata[4] = (u8)c;
                rdata[5] = (u8)d;
                
                return_code = 6;
                
                break;
            }
            
            case TYPE_EUI48:
            {
                text_buffer[parser_text_length(p)] = '\0';
                
                unsigned int a,b,c,d,e,f;
                if(sscanf(text_buffer, "%x-%x-%x-%x-%x-%x", &a,&b,&c,&d,&e,&f) != 6)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }
                
                if((a|b|c|d|e|f) > 255)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }
                
                rdata[0] = (u8)a;
                rdata[1] = (u8)b;
                rdata[2] = (u8)c;
                rdata[3] = (u8)d;
                rdata[4] = (u8)e;
                rdata[5] = (u8)f;
                
                return_code = 6;
                break;
            }
            
            case TYPE_EUI64:
            {
                text_buffer[parser_text_length(p)] = '\0';
                
                unsigned int a,b,c,d,e,f,g,h;
                if(sscanf(text_buffer, "%x-%x-%x-%x-%x-%x-%x-%x", &a,&b,&c,&d,&e,&f,&g,&h) != 8)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }
                
                if((a|b|c|d|e|f|g|h) > 255)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }
                
                rdata[0] = (u8)a;
                rdata[1] = (u8)b;
                rdata[2] = (u8)c;
                rdata[3] = (u8)d;
                rdata[4] = (u8)e;
                rdata[5] = (u8)f;
                rdata[6] = (u8)g;
                rdata[7] = (u8)h;
                
                return_code = 8;
                break;
            }
            case TYPE_TSIG:
                for(;;)
                {
                    return_code = parser_next_token(p);
                    if((return_code == PARSER_CHAR_TYPE_EOL) || (return_code == PARSER_EOL) || (return_code == PARSER_EOF))
                    {
                        break;
                    }
                }
            case TYPE_OPT:
            case TYPE_IXFR:
            case TYPE_AXFR:
            case TYPE_ANY:
            {
                return_code = ZONEFILE_INVALID_TYPE;
                break;
            }
            default:
            {
                return_code = UNSUPPORTED_RECORD;
                log_err("zone file: %{dnsname}: %{dnstype}: %r", origin, &rtype, return_code);
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
                        if(((u32)return_code << 1) <= rdata_size)
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
    } // if(!((text_len >= 1) && (text[0] == '#')))

    if(ISOK(return_code))
    {
        // expect to find EOL
        ya_result got_eol = parser_expect_eol(p);

        if(FAIL(got_eol))
        {
            return_code = got_eol;

            log_err("zone file: %{dnsname}: %{dnstype}: expected end of line: %r", origin,  &rtype, return_code);
        }
    }

    return return_code;
}

static ya_result
zone_reader_text_unread_record(zone_reader *zr, resource_record *entry)
{
    zone_reader_text *zfr = (zone_reader_text*)zr->data;
    resource_record *rr;
    u32 required = offsetof(resource_record,rdata) + entry->rdata_size;
    MALLOC_OR_DIE(resource_record*, rr, required, DNSRR_TAG);
    memcpy(rr, entry, required);
    rr->next = zfr->unread_next;
    zfr->unread_next = rr;

    return SUCCESS;
}

static void
zone_reader_text_escaped_string_format(const void *value, output_stream *os, s32 padding, char pad_char,
                                          bool left_justified, void *reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;

#if !DNSCORE_HAS_FULL_ASCII7
    output_stream_write(os, value, strlen((const char*)value));
#else
    const char *text = (const char*)value;

    for(;;)
    {
        char c = *text;

        switch(c)
        {
            case '\0':
            {
                return;
            }
            case VAR_SYMBOL:
            {
                output_stream_write_u8(os, '$');
                break;
            }
            case AT_SYMBOL:
            {
                output_stream_write_u8(os, '@');
                break;
            }
            case '$':
            {
                output_stream_write_u8(os, '\\');
                output_stream_write_u8(os, '$');
                break;
            }
            case '@':
            {
                output_stream_write_u8(os, '\\');
                output_stream_write_u8(os, '@');
                break;
            }
            default:
            {
                output_stream_write_u8(os, c);
                break;
            }
        }

        ++text;
    }
#endif
}

static ya_result
zone_reader_text_read_record(zone_reader *zr, resource_record *entry)
{
    yassert((zr != NULL) && (entry != NULL));

    zone_reader_text *zfr = (zone_reader_text*)zr->data;

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
                    if(zfr->origin_stack[--zfr->origin_stack_size] != NULL)
                    {
                        dnsname_copy(zfr->origin, zfr->origin_stack[zfr->origin_stack_size]);
                        zfr->dot_origin_size = dnsname_to_cstr(&zfr->dot_origin[1], zfr->origin) + 1;

                        dnsname_zfree(zfr->origin_stack[zfr->origin_stack_size]);
                    }

                    input_stream *completed_stream = parser_pop_stream(p);
#if DEBUG
                    if(zfr->includes_count <= 0)
                    {
                        abort();
                    }
#endif
                    --zfr->includes_count;
#if DEBUG
                    if(zfr->file_name[zfr->includes_count] == NULL)
                    {
                        abort();
                    }
#endif

                    free(zfr->file_name[zfr->includes_count]);

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
                if(text[0] == VAR_SYMBOL)
                {
                    // keyword match

                    if(parse_word_case_match(&text[1], text_len - 1, "ORIGIN", 6))
                    {
                        if(FAIL(return_code = parser_next_word(p)))
                        {
                            entry->name[0] = '\0';
                            entry->type = TYPE_NONE;
                            entry->class = CLASS_NONE;
                            entry->rdata_size = 0;
                            //
                            zone_reader_text_free_error_message(zfr);
                            zfr->error_message_code = return_code;


                            format_writer escaped_text = {zone_reader_text_escaped_string_format, text};
                            if(ISOK(asformat(&zfr->error_message_buffer, "failed to parse $ORIGIN from line \"%w\"", &escaped_text)))
                            {
                                zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                            }
                            return return_code;
                        }

                        text_len = parser_text_length(p);
                        text = parser_text(p);

                        memcpy(&zfr->dot_origin[1], text, text_len);
                        zfr->dot_origin_size = text_len + 1; // +1 for the dot

                        if(FAIL(return_code = cstr_to_locase_dnsname_with_check_len(zfr->origin, &zfr->dot_origin[1], zfr->dot_origin_size - 1)))
                        {
                            entry->name[0] = '\0';
                            entry->type = TYPE_NONE;
                            entry->class = CLASS_NONE;
                            entry->rdata_size = 0;
                            //
                            zone_reader_text_free_error_message(zfr);
                            zfr->error_message_code = return_code;

                            format_writer escaped_text = {zone_reader_text_escaped_string_format, text};
                            if(ISOK(asformat(&zfr->error_message_buffer, "failed to parse $ORIGIN from line \"%w\"", &escaped_text)))
                            {
                                zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                            }
                            return return_code;
                        }
                    }
                    else if(parse_word_case_match(&text[1], text_len - 1, "TTL", 3))
                    {
                        if(FAIL(return_code = parser_copy_next_ttl(p, &zfr->rttl_default)))
                        {
                            entry->name[0] = '\0';
                            entry->type = TYPE_NONE;
                            entry->class = CLASS_NONE;
                            entry->rdata_size = 0;
                            //
                            zone_reader_text_free_error_message(zfr);
                            zfr->error_message_code = return_code;

                            format_writer escaped_text = {zone_reader_text_escaped_string_format, text};
                            if(ISOK(asformat(&zfr->error_message_buffer, "failed to parse $TTL from line \"%w\"", &escaped_text)))
                            {
                                zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                            }
                            return return_code;
                        }

                        zfr->rttl_current = zfr->rttl_default;
                        zfr->rttl_default_defined = TRUE;
                    }
                    else if(parse_word_case_match(&text[1], text_len - 1, "INCLUDE", 7))
                    {
                        char file_name[PATH_MAX];

                        if(FAIL(return_code = parser_copy_next_word(p, file_name, sizeof(file_name))))
                        {
                            entry->name[0] = '\0';
                            entry->type = TYPE_NONE;
                            entry->class = CLASS_NONE;
                            entry->rdata_size = 0;
                            //
                            zone_reader_text_free_error_message(zfr);
                            zfr->error_message_code = ZONEFILE_EXPECTED_FILE_PATH;

                            format_writer escaped_text = {zone_reader_text_escaped_string_format, text};
                            if(ISOK(asformat(&zfr->error_message_buffer, "failed to parse $INCLUDE from line \"%w\"", &escaped_text)))
                            {
                                zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                            }
                            return return_code;
                        }

                        if(file_name[0] != '/')
                        {
                            // prepend the path of current file
                            // path + current = zfr->file_name[zfr->includes_count - 1];
                            char *current = zfr->file_name[zfr->includes_count - 1];
                            char *path_end = strrchr(current, '/');

                            if(path_end != NULL)
                            {
                                size_t path_len = path_end - current + 1;
                                size_t file_name_len = strlen(file_name) + 1;
                                if(path_len + file_name_len < sizeof(file_name))
                                {
                                    memmove(&file_name[path_len], file_name, file_name_len);
                                    memcpy(file_name, current, path_len);
                                }
                                else
                                {
                                    entry->name[0] = '\0';
                                    entry->type = TYPE_NONE;
                                    entry->class = CLASS_NONE;
                                    entry->rdata_size = 0;
                                    //
                                    zone_reader_text_free_error_message(zfr);
                                    zfr->error_message_code = BUFFER_WOULD_OVERFLOW;

                                    format_writer escaped_text = {zone_reader_text_escaped_string_format, text};
                                    if(ISOK(asformat(&zfr->error_message_buffer, "$INCLUDE absolute path of file is too big, from line \"%w\"", &escaped_text)))
                                    {
                                        zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                                    }

                                    return BUFFER_WOULD_OVERFLOW;
                                }
                            }
                        }

                        u8 new_origin[MAX_DOMAIN_LENGTH];

                        if(ISOK(return_code = parser_copy_next_fqdn(p, new_origin)))
                        {
                            if((return_code & PARSER_WORD) != 0)
                            {
                                // push current origin and replace

                                zfr->origin_stack[zfr->origin_stack_size++] = dnsname_zdup(zfr->origin);
                                dnsname_copy(zfr->origin, new_origin);
                                zfr->dot_origin_size = dnsname_to_cstr(&zfr->dot_origin[1], new_origin) + 1;
                            }
                            else
                            {
                                zfr->origin_stack[zfr->origin_stack_size++] = NULL;
                            }
                        }
                        else
                        {
                            zfr->origin_stack[zfr->origin_stack_size++] = NULL;
                        }


                        ya_result err;

                        if(ISOK(err = file_input_stream_open(&zfr->includes[zfr->includes_count], file_name)))
                        {
                            zfr->file_name[zfr->includes_count] = strdup(file_name);
                            parser_push_stream(&zfr->parser, &zfr->includes[zfr->includes_count++]);
                        }
                        else
                        {
                            entry->name[0] = '\0';
                            entry->type = TYPE_NONE;
                            entry->class = CLASS_NONE;
                            entry->rdata_size = 0;
                            //
                            zone_reader_text_free_error_message(zfr);
                            zfr->error_message_code = err;

                            if(ISOK(asformat(&zfr->error_message_buffer, "failed to open file %s", file_name)))
                            {
                                zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                            }

                            return err;
                        }
                    }
                    else if(parse_word_match(&text[1], text_len - 1, "GENERATE", 8))
                    {
                        entry->name[0] = '\0';
                        entry->type = TYPE_NONE;
                        entry->class = CLASS_NONE;
                        entry->rdata_size = 0;
                        //
                        zone_reader_text_free_error_message(zfr);
                        zfr->error_message_code = ZONEFILE_FEATURE_NOT_SUPPORTED;
                        zfr->error_message_buffer = "$GENERATE not supported";
                        return ZONEFILE_FEATURE_NOT_SUPPORTED;
                    }
                    else if(parse_word_match(&text[1], text_len - 1, "CLASS", 5))
                    {
                    }
                    else if(parse_word_match(&text[1], text_len - 1, "RETURN", 6))
                    {
                        if(zfr->origin_stack[--zfr->origin_stack_size] != NULL)
                        {
                            dnsname_copy(zfr->origin, zfr->origin_stack[zfr->origin_stack_size]);
                            zfr->dot_origin_size = dnsname_to_cstr(&zfr->dot_origin[1], zfr->origin) + 1;

                            dnsname_zfree(zfr->origin_stack[zfr->origin_stack_size]);
                        }

                        input_stream *completed_stream = parser_pop_stream(p);
                        free(zfr->file_name[zfr->includes_count]);

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
                    else if(parse_word_match(&text[1], text_len - 1, "END", 3))
                    {
                        break;
                    }
                }
                else // parse record
                {
                    // domain
                    if((return_code & PARSER_BLANK_START) == 0)
                    {
                        // new domain

                        u8 *domain = entry->name;

                        if(!((text_len == 1) && (text[0] == AT_SYMBOL)))
                        {
                            if(text[text_len - 1] != DOT_SYMBOL)
                            {
                                if(FAIL(return_code = charp_to_locase_dnsname_with_check(domain, text, text_len)))
                                {
                                    bool retry = FALSE;
                                    char retry_text[MAX_DOMAIN_LENGTH];

                                    if(text_len <= MAX_DOMAIN_LENGTH)
                                    {
                                        for(u32 i = 0; i < text_len; ++i)
                                        {
                                            char c = text[i];
                                            switch(c)
                                            {
                                                case VAR_SYMBOL:
                                                {
                                                    retry_text[i] = '$';
                                                    retry = TRUE;
                                                    break;
                                                }
                                                case AT_SYMBOL:
                                                {
                                                    retry_text[i] = '@';
                                                    retry = TRUE;
                                                    break;
                                                }
                                                default:
                                                {
                                                    retry_text[i] = c;
                                                    break;
                                                }
                                            }
                                        }
                                    }

                                    if(retry)
                                    {
                                        if(ISOK(return_code = charp_to_locase_dnsname_with_check(domain, retry_text, text_len)))
                                        {
                                            // an escape is probably missing
                                            char *file_name = "?";
                                            if((zfr->includes_count > 0) && (zfr->includes_count < ZONE_FILE_READER_INCLUDE_DEPTH_MAX))
                                            {
                                                if(zfr->file_name[zfr->includes_count - 1] != NULL)
                                                {
                                                    file_name = zfr->file_name[zfr->includes_count - 1];
                                                }
                                            }

                                            log_warn("zone parse: there is probably an escape missing in front of a '$' or a '@' in file '%s' at line %u for %{dnsname}",  file_name, p->line_number, domain);
                                        }
                                    }

                                    if(FAIL(return_code))
                                    {
                                        entry->type = TYPE_NONE;
                                        entry->class = CLASS_NONE;
                                        entry->rdata_size = 0;
                                        //
                                        zone_reader_text_free_error_message(zfr);
                                        zfr->error_message_code = return_code;
                                        MALLOC_OR_DIE(char*, zfr->error_message_buffer, text_len + 1, ZFERRMSG_TAG);
                                        memcpy(zfr->error_message_buffer, text, text_len);
                                        zfr->error_message_buffer[text_len] = '\0';
                                        zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;


                                        return return_code;
                                    }
                                }

                                /*return_code =*/ dnsname_copy(&domain[return_code - 1], zfr->origin); /// @note: cannot fail
                            }
                            else
                            {
                                if(FAIL(return_code = charp_to_locase_dnsname(domain, text, text_len)))
                                {
                                    entry->type = TYPE_NONE;
                                    entry->class = CLASS_NONE;
                                    entry->rdata_size = 0;
                                    //
                                    zone_reader_text_free_error_message(zfr);
                                    zfr->error_message_code = return_code;
                                    MALLOC_OR_DIE(char*, zfr->error_message_buffer, text_len + 1, ZFERRMSG_TAG);
                                    memcpy(zfr->error_message_buffer, text, text_len);
                                    zfr->error_message_buffer[text_len] = '\0';
                                    zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;

                                    return return_code;
                                }
                            }
                        }
                        else // label is @
                        {
                            dnsname_copy(domain, zfr->origin); /// @note: cannot fail
                            dnsname_to_cstr(&zfr->dot_origin[1], zfr->origin); /// @note: cannot fail

                            zfr->dot_origin_size = return_code + 1;
                            zfr->template_source = TRUE;
                        }
                    }
                    else
                    {
                        parser_rewind(p);
                    }

                    // TTL CLASS TYPE RDATA
                    // CLASS TTL TYPE RDATA

                    parser_mark(p);

                    if(ISOK(parser_copy_next_ttl(p, &zfr->rttl_current))) // parses as an int ?
                    {
                        entry->ttl = zfr->rttl_current;
                        zfr->rttl_current_defined = TRUE;

                        parser_mark(p);

                        if(FAIL(parser_copy_next_class(p, &zfr->rclass_current))) // TTL no CLASS
                        {
                            parser_rewind(p);
                        }
                        // else TTL + CLASS
                    }
                    else
                    {
                        parser_rewind(p);

                        if(ISOK(parser_copy_next_class(p, &zfr->rclass_current)))
                        {
                            parser_mark(p);

                            if(ISOK(parser_copy_next_ttl(p, &zfr->rttl_current))) // parses as an int ? // CLASS + TTL
                            {
                                entry->ttl = zfr->rttl_current;
                                zfr->rttl_current_defined = TRUE;
                            }
                            else
                            {
                                if(!zfr->rttl_default_defined)      // CLASS no TTL, no $TTL
                                {
                                    if(zfr->rttl_current_defined)
                                    {
                                        entry->ttl = zfr->rttl_current;
                                    }
                                    else
                                    {
                                        // this will be handled with the SOA case
                                    }
                                }

                                parser_rewind(p); // CLASS no TTL, + $TTL

                                entry->ttl = zfr->rttl_default;
                            }
                        }
                        else // no CLASS, no TTL, $TTL ?
                        {
                            parser_rewind(p);

                            if(zfr->rttl_default_defined)
                            {
                                entry->ttl = zfr->rttl_default;
                            }
                            else
                            {
                                entry->ttl = zfr->rttl_current;
                            }
                        }
                    }

                    entry->class = zfr->rclass_current;

                    u16 rtype;

                    if(FAIL(return_code = parser_copy_next_type(p, &rtype)))
                    {
                        entry->type = TYPE_NONE;
                        entry->class = CLASS_NONE;
                        entry->rdata_size = 0;
                        //
                        zone_reader_text_free_error_message(zfr);
                        zfr->error_message_code = return_code;

                        format_writer escaped_text = {zone_reader_text_escaped_string_format, text};

                        if(ISOK(asformat(&zfr->error_message_buffer, "could not parse type for %{dnsname} from line %i: \"%w\"", entry->name, parser_get_line_number(p), &escaped_text)))
                        {
                            zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                        }
                        return return_code;
                    }

                    entry->type = rtype;

#if DNSCORE_HAS_FULL_ASCII7
                    parser_del_translation(&zfr->parser, '@');
                    parser_del_translation(&zfr->parser, '$');
#endif
                    if(rtype != TYPE_SOA)
                    {
                        if(FAIL(return_code = zone_reader_text_copy_rdata_inline(p, rtype, entry->rdata, sizeof(entry->rdata), zfr->origin)))
                        {
                            entry->rdata_size = 0;
                            //
                            zone_reader_text_free_error_message(zfr);
                            zfr->error_message_code = return_code;

                            format_writer escaped_text = {zone_reader_text_escaped_string_format, text};
                            if(ISOK(asformat(&zfr->error_message_buffer, "could not parse rdata for %{dnsname} %{dnsclass} %{dnstype} from line \"%w\"", entry->name, &entry->class, &entry->type, &escaped_text)))
                            {
                                zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                            }
                            return return_code;
                        }

                        entry->rdata_size = return_code;
                    }
                    else // SOA
                    {
                        if(entry->class == CLASS_NONE)
                        {
                            entry->rdata_size = 0;
                            //
                            zone_reader_text_free_error_message(zfr);
                            zfr->error_message_code = ZONEFILE_SOA_WITHOUT_CLASS;
                            zfr->error_message_buffer = "no class set on the SOA record";
                            return ZONEFILE_SOA_WITHOUT_CLASS;
                        }

                        if(FAIL(return_code = zone_reader_text_copy_rdata_inline(p, rtype, entry->rdata, sizeof(entry->rdata), zfr->origin)))
                        {
                            entry->rdata_size = 0;
                            //
                            zone_reader_text_free_error_message(zfr);
                            zfr->error_message_code = return_code;

                            format_writer escaped_text = {zone_reader_text_escaped_string_format, text};
                            if(ISOK(asformat(&zfr->error_message_buffer, "could not parse rdata for %{dnsname} %{dnsclass} %{dnstype} from line \"%w\"", entry->name, &entry->class, &entry->type, &escaped_text)))
                            {
                                zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                            }
                            return return_code;
                        }

                        entry->rdata_size = return_code;

                        // FULL RECORD READY

                        if(!(zfr->rttl_default_defined || zfr->rttl_current_defined))
                        {
                            u8 *p = entry->rdata;
                            p += entry->rdata_size - 4;

                            zfr->rttl_default = zfr->rttl_current = ntohl(GET_U32_AT_P(p));
                            zfr->rttl_default_defined = zfr->rttl_current_defined = TRUE;
                            entry->ttl = zfr->rttl_default;
                        }
                    }

#if DNSCORE_HAS_FULL_ASCII7
                    parser_add_translation(&zfr->parser, '@', AT_SYMBOL);
                    parser_add_translation(&zfr->parser, '$', VAR_SYMBOL);
#endif

                    return SUCCESS;
                }
            }

#if DO_PRINT
            flushout();
#endif
        }
        else
        {
#if DO_PRINT
            formatln("[ERROR %r]", return_code);
#endif
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
zone_reader_text_free_record(zone_reader *zr, resource_record *entry)
{
    (void)zr;
    (void)entry;
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
zone_reader_text_close(zone_reader *zr)
{
    yassert(zr != NULL);

    zone_reader_text *zfr = (zone_reader_text*)zr->data;

    parser_finalize(&zfr->parser);

    u8 n = zfr->includes_count;
    while(n-- > 0)
    {
        free(zfr->file_name[n]);
        /*
                Warning	C6001	Using uninitialized memory '**zr[BYTE:268944]'.	yadifa
                zone_reader_text.c	2411
        */
    }

    resource_record *rr = zfr->unread_next;
    while(rr != NULL)
    {
        resource_record *tmp = rr;
        rr = rr->next;
        free(tmp);
    }

    zone_reader_text_free_error_message(zfr);

    free(zfr);

    zr->data = NULL;
    zr->vtbl = NULL;
}

static bool
zone_reader_text_canwriteback(zone_reader *zr)
{
    yassert(zr != NULL);

    zone_reader_text *zfr = (zone_reader_text*)zr->data;
    return !zfr->template_source;
}

static void
zone_reader_text_handle_error(zone_reader *zr, ya_result error_code)
{
    /* nop */
    (void)zr;
    (void)error_code;
}

static const char*
zone_reader_text_get_last_error_message(zone_reader *zr)
{
    zone_reader_text *zfr = (zone_reader_text*)zr->data;
    return zfr->error_message_buffer;
}

static const zone_reader_vtbl zone_reader_text_vtbl =
{
    zone_reader_text_read_record,
    zone_reader_text_unread_record,
    zone_reader_text_free_record,
    zone_reader_text_close,
    zone_reader_text_handle_error,
    zone_reader_text_canwriteback,
    zone_reader_text_get_last_error_message,
    "zone_reader_text_v2"
};


void
zone_reader_text_init_error_codes()
{
    if(zone_reader_text_init_error_codes_done)
    {
        return;
    }

    zone_reader_text_init_error_codes_done = TRUE;

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
zone_reader_text_init(zone_reader *zr)
{
    ya_result error_code;
    zone_reader_text *zfr;

    /*    ------------------------------------------------------------    */

    MALLOC_OBJECT_OR_DIE(zfr, zone_reader_text, ZFREADER_TAG);

    ZEROMEMORY(zfr, sizeof(zone_reader_text));

    if(ISOK(error_code = parser_init(&zfr->parser,
        zfr_string_delimiters,      // by 2
        zfr_multiline_delimiters,   // by 2
        zrf_comment_markers,        // by 1
        zrf_blank_makers,           // by 1
        zfr_escape_characters)))    // by 1
    {
        zfr->rttl_default = 86400;
        zfr->rttl_current = 86400;
        zfr->dot_origin_size = 2; // with the CHR0 sentinel
        zfr->rclass_current = CLASS_IN;
        zfr->rdata_size = 0;
        zfr->soa_found = FALSE;
        zfr->domain[0] = (u8)'\0';
        zfr->dot_origin[0] = '.';
        zfr->dot_origin[1] = '\0';
    }

#if DNSCORE_HAS_FULL_ASCII7
    parser_add_translation(&zfr->parser, '@', AT_SYMBOL);
    parser_add_translation(&zfr->parser, '$', VAR_SYMBOL);
    //parser_add_translation(&zfr->parser, '.', DOT_SYMBOL);
#endif

    zr->data = zfr;
    zr->vtbl = &zone_reader_text_vtbl;

    return error_code;
}

#if DEBUG_BENCH_TEXT_ZONE_PARSE

static debug_bench_s zone_reader_text_parse;
static bool zone_reader_text_parse_done = FALSE;

static inline void zone_reader_text_bench_register()
{
    if(!zone_reader_text_parse_done)
    {
        zone_reader_text_parse_done = TRUE;
        debug_bench_register(&zone_reader_text_parse, "text parse");
    }
}

#endif

ya_result
zone_reader_text_parse_stream(input_stream *ins, zone_reader *zr)
{
#if DEBUG_BENCH_TEXT_ZONE_PARSE
    zone_reader_text_bench_register();
    u64 bench = debug_bench_start(&zone_reader_text_parse);
#endif

    ya_result ret;

    if(ISOK(ret = zone_reader_text_init(zr)))
    {
        zone_reader_text *zfr = (zone_reader_text*)zr->data;

        // push the stream

        parser_push_stream(&zfr->parser, ins);
    }
    else
    {
        zone_reader_text_close(zr);
    }

#if DEBUG_BENCH_TEXT_ZONE_PARSE
    zone_reader_text_bench_register();
    debug_bench_stop(&zone_reader_text_parse, bench);
#endif

    return ret;
}

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
zone_reader_text_open(const char* fullpath, zone_reader *zr)
{
    ya_result return_value;

#if DEBUG_BENCH_TEXT_ZONE_PARSE
    zone_reader_text_bench_register();
    u64 bench = debug_bench_start(&zone_reader_text_parse);
#endif

    if(ISOK(return_value = zone_reader_text_init(zr)))
    {
        // push the stream

        zone_reader_text *zfr = (zone_reader_text*)zr->data;

        if(ISOK(return_value = file_input_stream_open(&zfr->includes[0], fullpath)))
        {
/*
#if (DNSDB_USE_POSIX_ADVISE != 0) && (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L)
            int fd = fd_input_stream_get_filedescriptor(&zfr->includes[0]);
            fdatasync_ex(fd);
            posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
*/
            zfr->file_name[zfr->includes_count] = strdup(fullpath);
            parser_push_stream(&zfr->parser, &zfr->includes[zfr->includes_count++]);
        }
        else
        {
            log_debug("zone file: cannot open: '%s': %r", fullpath, return_value);

            zone_reader_text_close(zr);

            return return_value;
        }

#if DEBUG_BENCH_TEXT_ZONE_PARSE
        zone_reader_text_bench_register();
        debug_bench_stop(&zone_reader_text_parse, bench);
#endif
    }

    return return_value;
}

void
zone_reader_text_ignore_missing_soa(zone_reader *zr)
{
    zone_reader_text *zfr = (zone_reader_text*)zr->data;
    zfr->soa_found = TRUE;
}

ya_result
zone_reader_text_set_origin(zone_reader *zr, const u8* origin)
{
    zone_reader_text *zfr = (zone_reader_text*)zr->data;
    ya_result return_code = dnsname_copy(zfr->origin, origin);
    return return_code;
}

ya_result
zone_reader_text_copy_rdata(const char *text, u16 rtype, u8 *rdata, u32 rdata_size, const u8 *origin)
{
    parser_s parser;

    ya_result return_code;

    char buffer[4096];

    int n = strlen(text);

    if(n > (int)(sizeof(buffer) - 2))
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

        bytearray_input_stream_init_const(&text_is, (const u8*)text, n);

        if(ISOK(return_code = parser_push_stream(&parser, &text_is)))
        {
            return_code = zone_reader_text_copy_rdata_inline(&parser, rtype, rdata, rdata_size, origin);
        }

        // will be closed by the parser
        // input_stream_close(&text_is);

        parser_finalize(&parser);
    }

    return return_code;
}

ya_result
zone_reader_text_len_copy_rdata(const char *text, u32 n, u16 rtype, u8 *rdata, u32 rdata_size, const u8 *origin)
{
    parser_s parser;

    ya_result return_code;

    if(ISOK(return_code = parser_init(&parser,
                                      zfr_string_delimiters,      // by 2
                                      zfr_multiline_delimiters,   // by 2
                                      zrf_comment_markers,        // by 1
                                      zrf_blank_makers,           // by 1
                                      zfr_escape_characters)))    // by 1
    {
        input_stream text_is;

        bytearray_input_stream_init_const(&text_is, (const u8*)text, n);

        if(ISOK(return_code = parser_push_stream(&parser, &text_is)))
        {
            return_code = zone_reader_text_copy_rdata_inline(&parser, rtype, rdata, rdata_size, origin);
        }

        // will be closed by the parser
        // input_stream_close(&text_is);

        parser_finalize(&parser);
    }

    return return_code;
}


/** @} */

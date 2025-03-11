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

#include "dnscore/dnscore_config.h"

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
#include "dnscore/mutex.h"
#include "dnscore/dnscore_extension.h"

#define ZFREADER_TAG                       0x524544414552465a
#define ZFERRMSG_TAG                       0x47534d525245465a
#define ZONE_FILE_READER_INCLUDE_DEPTH_MAX 16

#define DOT_SYMBOL                         '.'

#if !DNSCORE_HAS_FULL_ASCII7
#define AT_SYMBOL  '@'
#define VAR_SYMBOL '$'
#else
#define AT_SYMBOL  ((char)0xff)
#define VAR_SYMBOL ((char)0xfe)
// #define DOT_SYMBOL ((char)0xfd)
#endif

#define ZONE_READER_TTL_DEFAULT 86400

logger_handle_t *g_zone_logger = LOGGER_HANDLE_SINK;
#define MODULE_MSG_HANDLE           g_zone_logger

#define DEBUG_BENCH_TEXT_ZONE_PARSE 1
#if !DEBUG
#undef DEBUG_BENCH_TEXT_ZONE_PARSE
#define DEBUG_BENCH_TEXT_ZONE_PARSE 0
#endif

static initialiser_state_t zone_reader_text_error_codes_init_state = INITIALISE_STATE_INIT;

static const char *const   zfr_string_delimiters = "\"\"";
static const char *const   zfr_multiline_delimiters = "()";
static const char *const   zrf_comment_markers = ";";
static const char *const   zrf_blank_makers = "\040\t\r";
static const char *const   zfr_escape_characters = "\\";

#define ZONE_FILE_READER_MESSAGE_STATIC    0
#define ZONE_FILE_READER_MESSAGE_ALLOCATED 1

struct zone_reader_text_s
{
    parser_t           parser;
    resource_record_t *unread_next;
    int32_t            rttl_default; // $TTL
    int32_t            rttl_current;
    uint32_t           dot_origin_size; // with the CHR0 sentinel
    int32_t            origin_stack_size;
    uint16_t           rclass_current;
    uint16_t           rdata_size;
    bool               soa_found;
    bool               template_source;
    bool               rttl_default_defined;
    bool               rttl_current_defined;

    uint8_t            domain[DOMAIN_LENGTH_MAX + 1];
    uint8_t            origin[DOMAIN_LENGTH_MAX + 1];
    char               dot_origin[DOMAIN_LENGTH_MAX + 1];
    uint8_t           *origin_stack[PARSER_INCLUDE_DEPTH_MAX];

    uint8_t            rdata[RDATA_LENGTH_MAX];

    input_stream_t     includes[ZONE_FILE_READER_INCLUDE_DEPTH_MAX];
    char              *file_name[ZONE_FILE_READER_INCLUDE_DEPTH_MAX];

    int                includes_count;
    //
    ya_result error_message_code;
    uint8_t   error_message_allocated; // 0: static 1: malloc
    char     *error_message_buffer;    // It's not aligned but this is an exception :
                                       // _ This is a rarely used structure (don't care too much about a hole)
    // _ This is an hopefully rarely used field (best case: "never" (besides setting it up
    // to NULL)) _ Putting it among the more popular fields will likely increase misses
};

typedef struct zone_reader_text_s zone_reader_text_t;

static void                       zone_reader_text_free_error_message(zone_reader_text_t *zfr)
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

static ya_result zone_reader_text_cstr_to_locase_dnsname_with_check_len_with_origin(uint8_t *name_parm, const char *text, uint32_t text_len, const uint8_t *origin, parser_t *p)
{
    ya_result ret;
    if(FAIL(ret = dnsname_init_check_star_with_charp_and_origin_locase(name_parm, text, text_len, origin)))
    {
        bool retry = false;
        char retry_text[DOMAIN_LENGTH_MAX];

        if(text_len <= DOMAIN_LENGTH_MAX)
        {
            for(uint_fast32_t i = 0; i < text_len; ++i)
            {
                char c = text[i];
                switch(c)
                {
                    case VAR_SYMBOL:
                    {
                        retry_text[i] = '$';
                        retry = true;
                        break;
                    }
                    case AT_SYMBOL:
                    {
                        retry_text[i] = '@';
                        retry = true;
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
            if(ISOK(ret = dnsname_init_check_star_with_charp_and_origin_locase(name_parm, retry_text, text_len, origin)))
            {
                // an escape is probably missing
                log_warn(
                    "zone parse: there is probably an escape missing in front of a '$' or a '@' at line %u for "
                    "%{dnsname}",
                    p->line_number,
                    name_parm);
            }
        }
    }

    return ret;
}

static inline ya_result zone_reader_text_copy_rdata_inline(parser_t *p, uint16_t rtype, uint8_t *rdata, uint32_t rdata_size, const uint8_t *origin)
{
    const char             *text;
    uint32_t                text_len;
    ya_result               return_code;
    char                    text_buffer[1024];
    type_bit_maps_context_t tbmctx;
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
                int32_t total_size;

                if(FAIL(return_code = zone_reader_text_cstr_to_locase_dnsname_with_check_len_with_origin(rdata, text, text_len, origin, p)))
                {
                    break;
                }

                if(ISOK(return_code) && dnsname_is_wildcard(rdata))
                {
                    return_code = INVALID_RECORD;
                    break;
                }

                total_size = return_code;

                rdata += return_code;

                if(FAIL(return_code = parser_copy_next_fqdn_locase_with_origin(p, rdata, origin)))
                {
                    break;
                }

                if(ISOK(return_code) && dnsname_is_wildcard(rdata))
                {
                    return_code = INVALID_RECORD;
                    break;
                }

                total_size += return_code + 20;

                rdata += return_code;
                return_code = total_size;

                for(uint_fast8_t i = 5; i > 0; i--)
                {
                    int32_t   tmp_int32;
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
            case TYPE_MD: /** @NOTE: obsolete */
            case TYPE_MF: /** NOTE: obsolete */
            case TYPE_MB: /** NOTE: obsolete */
            case TYPE_MG: /** NOTE: obsolete */
            case TYPE_MR: /** NOTE: obsolete */
#endif
            {
                return_code = zone_reader_text_cstr_to_locase_dnsname_with_check_len_with_origin(rdata, text, text_len, origin, p);

                if(ISOK(return_code) && dnsname_is_wildcard(rdata))
                {
                    return_code = INVALID_RECORD;
                }

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

                rdata[0] = (uint8_t)protocol;
                rdata++;
                rdata_size -= 5;

                uint32_t rdata_size_available = MIN(rdata_size, 8192);
                ZEROMEMORY(rdata, rdata_size_available);

                int port_limit = MIN(rdata_size_available << 3, UINT16_MAX);
                int max_index = -1;

                for(;;)
                {
                    int service_port;
                    if(FAIL(return_code = parser_get_network_service_port_from_next_word(p, &service_port)))
                    {
                        if((return_code == PARSER_REACHED_END_OF_LINE) || (return_code == PARSER_REACHED_END_OF_FILE))
                        {
                            if(max_index >= 0)
                            {
                                return_code = SUCCESS;
                            }
                        }
                        break;
                    }

                    if(service_port > port_limit)
                    {
                        return_code = MAKE_ERRNO_ERROR(ERANGE);
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
                {                 // @note 20220805 edf -- this seems pointless. It seems max_index is only < 0 if there has been an
                                  // error.
                    return_code = INVALID_RECORD;
                    break;
                }

                return_code = 4 + 1 + 1 + max_index; // ipv4 + proto + index=>+1

                parser_set_eol(p);
                break;
            }
#endif
            case TYPE_MX:
            case TYPE_KX:
            case TYPE_LP:
            case TYPE_AFSDB:
            {
                uint16_t preference;

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

                if(ISOK(return_code) && dnsname_is_wildcard(rdata))
                {
                    return_code = INVALID_RECORD;
                    break;
                }

                return_code += 2;

                break;
            }

            case TYPE_RRSIG:
            {
                uint16_t rtype;

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

                int32_t ttl;

                if(FAIL(return_code = parser_copy_next_ttl(p, &ttl)))
                {
                    break;
                }

                ttl = htonl(ttl);
                SET_U32_AT_P(rdata, ttl);
                rdata += 4;

                // signature expiration (YYYYMMDDHHMMSS epoch -> 32 bits)

                uint32_t epoch;

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

                uint16_t tag;

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

                uint32_t signer_len = return_code;

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

                uint16_t flags;

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

                uint16_t iterations;

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

                if(!((parser_text_length(p) == 1) && (parser_text(p)[0] == '-')))
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

                rdata[0] = (uint8_t)return_code;
                return_code += 5;

                break;
            }

            case TYPE_NSEC3:
            {
                const uint8_t *rdata_start = rdata;
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

                uint16_t iterations;

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

                if(!((parser_text_length(p) == 1) && (parser_text(p)[0] == '-')))
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

                rdata[0] = (uint8_t)return_code;
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

                rdata[0] = (uint8_t)return_code;
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
                const uint8_t *rdata_start = rdata;

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

                uint16_t keytag;

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
            case TYPE_SPF: // discontinued
            {
                const uint8_t *rdata_start = rdata;

                for(;;)
                {
                    if(text_len > 255)
                    {
                        return_code = ZONEFILE_TEXT_TOO_BIG;
                        break;
                    }

                    *rdata++ = (uint8_t)text_len;
                    memcpy(rdata, text, text_len);
                    rdata += text_len;

                    if(FAIL(return_code = parser_next_token(p)))
                    {
                        break;
                    }

                    if((return_code & (PARSER_COMMENT | PARSER_EOL | PARSER_EOF)) != 0)
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
                uint16_t tmp16;

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
                uint8_t *rdata_start = rdata;
                uint16_t tmp16;

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

                if((return_code & (PARSER_COMMENT | PARSER_EOL | PARSER_EOF)) != 0)
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

                *rdata++ = (uint8_t)text_len;
                memcpy(rdata, text, text_len);
                rdata += text_len;

                // service

                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }

                if((return_code & (PARSER_COMMENT | PARSER_EOL | PARSER_EOF)) != 0)
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

                *rdata++ = (uint8_t)text_len;
                memcpy(rdata, text, text_len);
                rdata += text_len;

                // regex

                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }

                if((return_code & (PARSER_COMMENT | PARSER_EOL | PARSER_EOF)) != 0)
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

                *rdata++ = (uint8_t)text_len;
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
                const uint8_t *rdata_start = rdata;

                // 1.mbox-name1
                // int32_t total_size;

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
                const uint8_t *rdata_start = rdata;

                if(text_len > 255)
                {
                    return_code = ZONEFILE_TEXT_TOO_BIG;
                    break;
                }

                *rdata++ = (uint8_t)text_len;
                memcpy(rdata, text, text_len);
                rdata += text_len;

                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }

                if((return_code & (PARSER_COMMENT | PARSER_EOL | PARSER_EOF)) != 0)
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

                *rdata++ = (uint8_t)text_len;
                memcpy(rdata, text, text_len);
                rdata += text_len;

                return_code = rdata - rdata_start;

                break;
            }

            case TYPE_NID:
            case TYPE_L64:
            {
                uint16_t preference;

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

                unsigned int a, b, c, d;
                if(sscanf(text_buffer, "%x:%x:%x:%x", &a, &b, &c, &d) != 4)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }

                if((a | b | c | d) > 65535)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }

                SET_U16_AT(rdata[2], htons((uint16_t)a));
                SET_U16_AT(rdata[4], htons((uint16_t)b));
                SET_U16_AT(rdata[6], htons((uint16_t)c));
                SET_U16_AT(rdata[8], htons((uint16_t)d));

                return_code = 10;

                break;
            }
            case TYPE_L32:
            {
                uint16_t preference;

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

                unsigned int a, b, c, d;
                if(sscanf(text_buffer, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }

                if((a | b | c | d) > 255)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }

                rdata[2] = (uint8_t)a;
                rdata[3] = (uint8_t)b;
                rdata[4] = (uint8_t)c;
                rdata[5] = (uint8_t)d;

                return_code = 6;

                break;
            }

            case TYPE_EUI48:
            {
                text_buffer[parser_text_length(p)] = '\0';

                unsigned int a, b, c, d, e, f;
                if(sscanf(text_buffer, "%x-%x-%x-%x-%x-%x", &a, &b, &c, &d, &e, &f) != 6)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }

                if((a | b | c | d | e | f) > 255)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }

                rdata[0] = (uint8_t)a;
                rdata[1] = (uint8_t)b;
                rdata[2] = (uint8_t)c;
                rdata[3] = (uint8_t)d;
                rdata[4] = (uint8_t)e;
                rdata[5] = (uint8_t)f;

                return_code = 6;
                break;
            }

            case TYPE_EUI64:
            {
                text_buffer[parser_text_length(p)] = '\0';

                unsigned int a, b, c, d, e, f, g, h;
                if(sscanf(text_buffer, "%x-%x-%x-%x-%x-%x-%x-%x", &a, &b, &c, &d, &e, &f, &g, &h) != 8)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }

                if((a | b | c | d | e | f | g | h) > 255)
                {
                    return_code = PARSEB16_ERROR;
                    break;
                }

                rdata[0] = (uint8_t)a;
                rdata[1] = (uint8_t)b;
                rdata[2] = (uint8_t)c;
                rdata[3] = (uint8_t)d;
                rdata[4] = (uint8_t)e;
                rdata[5] = (uint8_t)f;
                rdata[6] = (uint8_t)g;
                rdata[7] = (uint8_t)h;

                return_code = 8;
                break;
            }
            case TYPE_CAA:
            {
                const uint8_t *rdata_start = rdata;

                uint8_t        flags;

                if(FAIL(return_code = parser_get_u8(text, text_len, &flags)))
                {
                    break;
                }

                *rdata = flags;
                ++rdata;

                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }

                if((return_code & (PARSER_COMMENT | PARSER_EOL | PARSER_EOF)) != 0)
                {
                    // stop

                    break;
                }
                text = parser_text(p);
                text_len = parser_text_length(p);

                if((text_len < 1) || (text_len > 255))
                {
                    return_code = ZONEFILE_RDATA_PARSE_ERROR;
                    break;
                }

                *rdata = text_len;
                ++rdata;

                for(uint32_t i = 0; i < text_len; ++i)
                {
                    char c = text[i];
                    if(((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) || ((c >= '0') && (c <= '9')))
                    {
                        rdata[i] = c;
                    }
                    else
                    {
                        return_code = ZONEFILE_RDATA_PARSE_ERROR;
                        break;
                    }
                }

                rdata += text_len;

                if(ISOK(return_code))
                {
                    if(FAIL(return_code = parser_next_token(p)))
                    {
                        break;
                    }

                    if((return_code & (PARSER_COMMENT | PARSER_EOL | PARSER_EOF)) != 0)
                    {
                        // stop

                        break;
                    }

                    text = parser_text(p);
                    text_len = parser_text_length(p);

                    memcpy(rdata, text, text_len);
                    rdata += text_len;

                    return_code = rdata - rdata_start;
                }

                break;
            }
            case TYPE_CERT:
            {
                const uint8_t *rdata_start = rdata;

                uint16_t       cert_type;

                char           mnemonic[16];

                if(text_len > sizeof(mnemonic))
                {
                    return_code = INVALID_RECORD;
                    break;
                }

                memcpy(mnemonic, text, text_len);
                mnemonic[text_len] = '\0';

                if(FAIL(dns_cert_type_value_from_name(mnemonic, &cert_type)))
                {
                    if(FAIL(return_code = parser_get_u16(text, text_len, &cert_type)))
                    {
                        break;
                    }
                }

                SET_U16_AT_P(rdata, htons(cert_type));
                rdata += 2;

                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }

                if((return_code & (PARSER_COMMENT | PARSER_EOL | PARSER_EOF)) != 0)
                {
                    // stop

                    break;
                }
                text = parser_text(p);
                text_len = parser_text_length(p);

                uint16_t key_tag;

                if(FAIL(return_code = parser_get_u16(text, text_len, &key_tag)))
                {
                    break;
                }

                SET_U16_AT_P(rdata, htons(key_tag));
                rdata += 2;

                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }

                if((return_code & (PARSER_COMMENT | PARSER_EOL | PARSER_EOF)) != 0)
                {
                    // stop

                    break;
                }

                text = parser_text(p);
                text_len = parser_text_length(p);

                uint8_t algorithm;

                if(FAIL(return_code = parser_get_u8(text, text_len, &algorithm)))
                {
                    // maybe it's a mnemonic

                    if(text_len >= sizeof(mnemonic))
                    {
                        break;
                    }

                    memcpy(mnemonic, text, text_len);
                    mnemonic[text_len] = '\0';

                    if(FAIL(return_code = dns_encryption_algorithm_from_name(mnemonic, &algorithm)))
                    {
                        break;
                    }
                }

                *rdata = algorithm;
                ++rdata;

                if(FAIL(return_code = parser_concat_next_tokens_nospace(p)))
                {
                    break;
                }

                if(FAIL(return_code = base64_decode(parser_text(p), parser_text_length(p), rdata)))
                {
                    break;
                }

                rdata += return_code;

                return_code = rdata - rdata_start;

                break;
            }
            case TYPE_CSYNC:
            {
                const uint8_t *rdata_start = rdata;

                uint32_t       serial;

                if(FAIL(return_code = parser_get_u32(text, text_len, &serial)))
                {
                    break;
                }

                SET_U32_AT_P(rdata, htonl(serial));
                rdata += 4;

                if(FAIL(return_code = parser_next_token(p)))
                {
                    break;
                }

                if((return_code & (PARSER_COMMENT | PARSER_EOL | PARSER_EOF)) != 0)
                {
                    // stop

                    break;
                }
                text = parser_text(p);
                text_len = parser_text_length(p);

                uint16_t flags;

                if(FAIL(return_code = parser_get_u16(text, text_len, &flags)))
                {
                    break;
                }

                SET_U16_AT_P(rdata, htons(flags));
                rdata += 2;

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
            case TYPE_DHCID:
            {
                if(FAIL(return_code = parser_concat_current_and_next_tokens_nospace(p)))
                {
                    break;
                }

                if(FAIL(return_code = base64_decode(parser_text(p), parser_text_length(p), rdata)))
                {
                    break;
                }

                break;
            }
            case TYPE_TSIG:
            {
                for(;;)
                {
                    return_code = parser_next_token(p);
                    if((return_code == PARSER_CHAR_TYPE_EOL) || (return_code == PARSER_EOL) || (return_code == PARSER_EOF))
                    {
                        break;
                    }
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
                if((return_code = dnscore_dns_extension_zone_reader_text_copy_rdata(p, rtype, rdata, rdata_size, origin, &text, &text_len)) != UNSUPPORTED_RECORD)
                {
                    break;
                }

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
            uint16_t unknown_rdata_len;

            if(ISOK(return_code = parser_copy_next_u16(p, &unknown_rdata_len)))
            {
                return_code = ZONEFILE_RDATA_BUFFER_TOO_SMALL; /// buffer too small

                if(unknown_rdata_len <= rdata_size)
                {
                    if(ISOK(return_code = parser_concat_next_tokens_nospace(p)))
                    {
                        if(((uint32_t)return_code << 1) <= rdata_size)
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

            log_err("zone file: %{dnsname}: %{dnstype}: expected end of line: %r", origin, &rtype, return_code);
        }
    }

    return return_code;
}

static ya_result zone_reader_text_unread_record(zone_reader_t *zr, resource_record_t *entry)
{
    zone_reader_text_t *zfr = (zone_reader_text_t *)zr->data;
    resource_record_t  *rr;
    uint32_t            required = offsetof(resource_record_t, rdata) + entry->rdata_size;
    MALLOC_OR_DIE(resource_record_t *, rr, required, DNSRR_TAG);
    memcpy(rr, entry, required);
    rr->next = zfr->unread_next;
    zfr->unread_next = rr;

    return SUCCESS;
}

static void zone_reader_text_escaped_string_format(const void *value, output_stream_t *os, int32_t padding, char pad_char, bool left_justified, void *reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;

#if !DNSCORE_HAS_FULL_ASCII7
    output_stream_write(os, value, strlen((const char *)value));
#else
    const char *text = (const char *)value;

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

static ya_result zone_reader_text_read_record(zone_reader_t *zr, resource_record_t *entry)
{
    yassert((zr != NULL) && (entry != NULL));

    zone_reader_text_t *zfr = (zone_reader_text_t *)zr->data;

    if(zfr->unread_next != NULL)
    {
        resource_record_t *top = zfr->unread_next;
        uint32_t           required = offsetof(resource_record_t, rdata) + top->rdata_size;
        memcpy(entry, top, required);
        zfr->unread_next = top->next;
        free(top);

        return 1;
    }

    parser_t *p = &zfr->parser;
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
                        zfr->dot_origin_size = cstr_init_with_dnsname(&zfr->dot_origin[1], zfr->origin) + 1;

                        dnsname_zfree(zfr->origin_stack[zfr->origin_stack_size]);
                    }

                    input_stream_t *completed_stream = parser_pop_stream(p);
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
                        return 0; // EOF
                    }
                }

                continue;
            }

            p->needle_mark = p->text;

            // keywords or new domain

            uint32_t    text_len = parser_text_length(p);
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

                            format_writer_t escaped_text = {zone_reader_text_escaped_string_format, text};
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

                        if(FAIL(return_code = dnsname_init_check_nostar_with_charp_locase(zfr->origin, &zfr->dot_origin[1], zfr->dot_origin_size - 1)))
                        {
                            entry->name[0] = '\0';
                            entry->type = TYPE_NONE;
                            entry->class = CLASS_NONE;
                            entry->rdata_size = 0;
                            //
                            zone_reader_text_free_error_message(zfr);
                            zfr->error_message_code = return_code;

                            format_writer_t escaped_text = {zone_reader_text_escaped_string_format, text};
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

                            format_writer_t escaped_text = {zone_reader_text_escaped_string_format, text};
                            if(ISOK(asformat(&zfr->error_message_buffer, "failed to parse $TTL from line \"%w\"", &escaped_text)))
                            {
                                zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                            }
                            return return_code;
                        }

                        zfr->rttl_current = zfr->rttl_default;
                        zfr->rttl_default_defined = true;
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

                            format_writer_t escaped_text = {zone_reader_text_escaped_string_format, text};
                            if(ISOK(asformat(&zfr->error_message_buffer, "failed to parse $INCLUDE from line \"%w\"", &escaped_text)))
                            {
                                zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                            }
                            return return_code;
                        }

                        if(!filepath_is_absolute(file_name))
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

                                    format_writer_t escaped_text = {zone_reader_text_escaped_string_format, text};
                                    if(ISOK(asformat(&zfr->error_message_buffer, "$INCLUDE absolute path of file is too big, from line \"%w\"", &escaped_text)))
                                    {
                                        zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;
                                    }

                                    return BUFFER_WOULD_OVERFLOW;
                                }
                            }
                        }

                        zfr->origin_stack[zfr->origin_stack_size++] = dnsname_zdup(zfr->origin);

                        uint8_t new_origin[DOMAIN_LENGTH_MAX];

                        if(ISOK(return_code = parser_copy_next_fqdn_with_origin(p, new_origin, zfr->origin)))
                        {
                            if(return_code > 0)
                            {
                                // push current origin and replace

                                dnsname_copy(zfr->origin, new_origin);
                                zfr->dot_origin_size = cstr_init_with_dnsname(&zfr->dot_origin[1], new_origin) + 1;
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
                            zfr->dot_origin_size = cstr_init_with_dnsname(&zfr->dot_origin[1], zfr->origin) + 1;

                            dnsname_zfree(zfr->origin_stack[zfr->origin_stack_size]);
                        }

                        input_stream_t *completed_stream = parser_pop_stream(p);
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

                        uint8_t *domain = entry->name;

                        if(!((text_len == 1) && (text[0] == AT_SYMBOL)))
                        {
                            if(text[text_len - 1] != DOT_SYMBOL)
                            {
                                if(FAIL(return_code = dnsname_init_check_with_charp_locase(domain, text, text_len)))
                                {
                                    bool retry = false;
                                    char retry_text[DOMAIN_LENGTH_MAX];

                                    if(text_len <= DOMAIN_LENGTH_MAX)
                                    {
                                        for(uint_fast32_t i = 0; i < text_len; ++i)
                                        {
                                            char c = text[i];
                                            switch(c)
                                            {
                                                case VAR_SYMBOL:
                                                {
                                                    retry_text[i] = '$';
                                                    retry = true;
                                                    break;
                                                }
                                                case AT_SYMBOL:
                                                {
                                                    retry_text[i] = '@';
                                                    retry = true;
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
                                        if(ISOK(return_code = dnsname_init_check_with_charp_locase(domain, retry_text, text_len)))
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

                                            log_warn(
                                                "zone parse: there is probably an escape missing in front of a '$' or "
                                                "a '@' in file '%s' at line %u for %{dnsname}",
                                                file_name,
                                                p->line_number,
                                                domain);
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
                                        MALLOC_OR_DIE(char *, zfr->error_message_buffer, text_len + 1, ZFERRMSG_TAG);
                                        memcpy(zfr->error_message_buffer, text, text_len);
                                        zfr->error_message_buffer[text_len] = '\0';
                                        zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;

                                        return return_code;
                                    }
                                }

                                /*return_code =*/dnsname_copy(&domain[return_code - 1],
                                                              zfr->origin); /// @note: cannot fail
                            }
                            else
                            {
                                if(FAIL(return_code = dnsname_init_with_charp_locase(domain, text, text_len)))
                                {
                                    entry->type = TYPE_NONE;
                                    entry->class = CLASS_NONE;
                                    entry->rdata_size = 0;
                                    //
                                    zone_reader_text_free_error_message(zfr);
                                    zfr->error_message_code = return_code;
                                    MALLOC_OR_DIE(char *, zfr->error_message_buffer, text_len + 1, ZFERRMSG_TAG);
                                    memcpy(zfr->error_message_buffer, text, text_len);
                                    zfr->error_message_buffer[text_len] = '\0';
                                    zfr->error_message_allocated = ZONE_FILE_READER_MESSAGE_ALLOCATED;

                                    return return_code;
                                }
                            }
                        }
                        else // label is @
                        {
                            dnsname_copy(domain, zfr->origin);                        /// @note: cannot fail
                            cstr_init_with_dnsname(&zfr->dot_origin[1], zfr->origin); /// @note: cannot fail

                            zfr->dot_origin_size = return_code + 1;
                            zfr->template_source = true;
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
                        zfr->rttl_current_defined = true;

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
                                zfr->rttl_current_defined = true;
                            }
                            else
                            {
                                if(!zfr->rttl_default_defined) // CLASS no TTL, no $TTL
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

                    uint16_t rtype;

                    if(FAIL(return_code = parser_copy_next_type(p, &rtype)))
                    {
                        entry->type = TYPE_NONE;
                        entry->class = CLASS_NONE;
                        entry->rdata_size = 0;
                        //
                        zone_reader_text_free_error_message(zfr);
                        zfr->error_message_code = return_code;

                        format_writer_t escaped_text = {zone_reader_text_escaped_string_format, text};

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

                            format_writer_t escaped_text = {zone_reader_text_escaped_string_format, text};
                            if(ISOK(asformat(
                                   &zfr->error_message_buffer, "could not parse rdata for %{dnsname} %{dnsclass} %{dnstype} from line %i: \"%w\"", entry->name, &entry->class, &entry->type, parser_get_line_number(p), &escaped_text)))
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

                            format_writer_t escaped_text = {zone_reader_text_escaped_string_format, text};
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
                            uint8_t *p = entry->rdata;
                            p += entry->rdata_size - 4;

                            zfr->rttl_default = zfr->rttl_current = ntohl(GET_U32_AT_P(p));
                            zfr->rttl_default_defined = zfr->rttl_current_defined = true;
                            entry->ttl = zfr->rttl_default;
                        }
                    }

#if DNSCORE_HAS_FULL_ASCII7
                    parser_add_translation(&zfr->parser, '@', AT_SYMBOL);
                    parser_add_translation(&zfr->parser, '$', VAR_SYMBOL);
#endif

                    return 1;
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
            if(return_code == PARSER_NO_INPUT)
            {
                return 0;
            }
            break;
        }
    }
    /*
        if(ISOK(return_code))
        {
            return_code = 1;
        }
    */
    return return_code;
}

static ya_result zone_reader_text_free_record(zone_reader_t *zr, resource_record_t *entry)
{
    (void)zr;
    (void)entry;
    return SUCCESS;
}

/** @brief Closes a zone file entry
 *
 *  Closes a zone file entry.  The function will do nothing if the zonefile has already been closed
 *
 *  @param[in] zonefile a pointer to a valid (zone_file_open'ed) zone-file structure
 *
 */
static void zone_reader_text_close(zone_reader_t *zr)
{
    yassert(zr != NULL);

    zone_reader_text_t *zfr = (zone_reader_text_t *)zr->data;

    parser_finalize(&zfr->parser);

    int n = zfr->includes_count;
    while(n-- > 0)
    {
        free(zfr->file_name[n]);
        /*
                Warning	C6001	Using uninitialized memory '**zr[BYTE:268944]'.	yadifa
                zone_reader_text.c	2411
        */
    }

    resource_record_t *rr = zfr->unread_next;
    while(rr != NULL)
    {
        resource_record_t *tmp = rr;
        rr = rr->next;
        free(tmp);
    }

    zone_reader_text_free_error_message(zfr);

    free(zfr);

    zr->data = NULL;
    zr->vtbl = NULL;
}

static bool zone_reader_text_canwriteback(zone_reader_t *zr)
{
    yassert(zr != NULL);

    zone_reader_text_t *zfr = (zone_reader_text_t *)zr->data;
    return !zfr->template_source;
}

static void zone_reader_text_handle_error(zone_reader_t *zr, ya_result error_code)
{
    /* nop */
    (void)zr;
    (void)error_code;
}

static const char *zone_reader_text_get_last_error_message(zone_reader_t *zr)
{
    zone_reader_text_t *zfr = (zone_reader_text_t *)zr->data;
    return zfr->error_message_buffer;
}

static const zone_reader_vtbl zone_reader_text_vtbl = {zone_reader_text_read_record,
                                                       zone_reader_text_unread_record,
                                                       zone_reader_text_free_record,
                                                       zone_reader_text_close,
                                                       zone_reader_text_handle_error,
                                                       zone_reader_text_canwriteback,
                                                       zone_reader_text_get_last_error_message,
                                                       "zone_reader_text_v2"};

void                          zone_reader_text_init_error_codes()
{
    if(initialise_state_begin(&zone_reader_text_error_codes_init_state))
    {
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

        initialise_state_ready(&zone_reader_text_error_codes_init_state);
    }
}

static ya_result zone_reader_text_init(zone_reader_t *zr)
{
    ya_result           error_code;
    zone_reader_text_t *zfr;

    MALLOC_OBJECT_OR_DIE(zfr, zone_reader_text_t, ZFREADER_TAG);
    ZEROMEMORY(zfr, sizeof(zone_reader_text_t));

    if(ISOK(error_code = parser_init(&zfr->parser,
                                     zfr_string_delimiters,    // by 2
                                     zfr_multiline_delimiters, // by 2
                                     zrf_comment_markers,      // by 1
                                     zrf_blank_makers,         // by 1
                                     zfr_escape_characters)))  // by 1
    {
        zfr->rttl_default = ZONE_READER_TTL_DEFAULT;
        zfr->rttl_current = ZONE_READER_TTL_DEFAULT;
        zfr->dot_origin_size = 2; // with the CHR0 sentinel
        zfr->rclass_current = CLASS_IN;
        zfr->rdata_size = 0;
        zfr->soa_found = false;
        zfr->domain[0] = (uint8_t)'\0';
        zfr->dot_origin[0] = '.';
        zfr->dot_origin[1] = '\0';
    }

#if DNSCORE_HAS_FULL_ASCII7
    parser_add_translation(&zfr->parser, '@', AT_SYMBOL);
    parser_add_translation(&zfr->parser, '$', VAR_SYMBOL);
    // parser_add_translation(&zfr->parser, '.', DOT_SYMBOL);
#endif

    zr->data = zfr;
    zr->vtbl = &zone_reader_text_vtbl;

    return error_code;
}

#if DEBUG_BENCH_TEXT_ZONE_PARSE

static debug_bench_t zone_reader_text_parse;
static bool          zone_reader_text_parse_done = false;

static inline void   zone_reader_text_bench_register()
{
    if(!zone_reader_text_parse_done)
    {
        zone_reader_text_parse_done = true;
        debug_bench_register(&zone_reader_text_parse, "text parse");
    }
}

#endif

ya_result zone_reader_text_parse_stream(zone_reader_t *zr, input_stream_t *ins)
{
#if DEBUG_BENCH_TEXT_ZONE_PARSE
    zone_reader_text_bench_register();
    uint64_t bench = debug_bench_start(&zone_reader_text_parse);
#endif

    ya_result ret;

    if(ISOK(ret = zone_reader_text_init(zr)))
    {
        zone_reader_text_t *zfr = (zone_reader_text_t *)zr->data;

        // push the stream

        zfr->file_name[zfr->includes_count] = NULL;
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
ya_result zone_reader_text_open(zone_reader_t *zr, const char *fullpath)
{
    ya_result return_value;

#if DEBUG_BENCH_TEXT_ZONE_PARSE
    zone_reader_text_bench_register();
    uint64_t bench = debug_bench_start(&zone_reader_text_parse);
#endif

    if(ISOK(return_value = zone_reader_text_init(zr)))
    {
        // push the stream

        zone_reader_text_t *zfr = (zone_reader_text_t *)zr->data;

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

void zone_reader_text_ignore_missing_soa(zone_reader_t *zr)
{
    zone_reader_text_t *zfr = (zone_reader_text_t *)zr->data;
    zfr->soa_found = true;
}

ya_result zone_reader_text_set_origin(zone_reader_t *zr, const uint8_t *origin)
{
    zone_reader_text_t *zfr = (zone_reader_text_t *)zr->data;
    ya_result           return_code = dnsname_copy(zfr->origin, origin);
    return return_code;
}

ya_result zone_reader_text_copy_rdata(const char *text, uint16_t rtype, uint8_t *rdata, uint32_t rdata_size, const uint8_t *origin)
{
    parser_t  parser;

    ya_result return_code;

    char      buffer[4096];

    int       n = strlen(text);

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
                                      zfr_string_delimiters,    // by 2
                                      zfr_multiline_delimiters, // by 2
                                      zrf_comment_markers,      // by 1
                                      zrf_blank_makers,         // by 1
                                      zfr_escape_characters)))  // by 1
    {
        input_stream_t text_is;

        bytearray_input_stream_init_const(&text_is, (const uint8_t *)text, n);

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

ya_result zone_reader_text_len_copy_rdata(const char *text, uint32_t n, uint16_t rtype, uint8_t *rdata, uint32_t rdata_size, const uint8_t *origin)
{
    parser_t  parser;

    ya_result return_code;

    if(ISOK(return_code = parser_init(&parser,
                                      zfr_string_delimiters,    // by 2
                                      zfr_multiline_delimiters, // by 2
                                      zrf_comment_markers,      // by 1
                                      zrf_blank_makers,         // by 1
                                      zfr_escape_characters)))  // by 1
    {
        input_stream_t text_is;

        bytearray_input_stream_init_const(&text_is, (const uint8_t *)text, n);

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

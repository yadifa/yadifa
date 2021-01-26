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

#ifndef PARSER_H
#define	PARSER_H

#include <dnscore/sys_types.h>
#include <dnscore/parsing.h>
#include <dnscore/typebitmap.h>
#include <dnscore/input_stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct parser_delimiter_s
{
    char begin; // " ' <
    char end;   // " ' >
    u8 id;
    u8 reserved;
};

typedef struct parser_delimiter_s parser_delimiter_s;

#define PARSER_INCLUDE_DEPTH_MAX 256
#define PARSER_LINE_LENGTH_MAX 65535

#define PARSER_CHAR_TYPE_NORMAL                  0
#define PARSER_CHAR_TYPE_ESCAPE_CHARACTER        1
#define PARSER_CHAR_TYPE_COMMENT_MARKER          2
#define PARSER_CHAR_TYPE_STRING_DELIMITER        3
#define PARSER_CHAR_TYPE_MULTILINE_DELIMITER     4
#define PARSER_CHAR_TYPE_MULTILINE_DELIMITER_END 5
#define PARSER_CHAR_TYPE_BLANK_MARKER            6
#define PARSER_CHAR_TYPE_EOL                     7
#if DNSCORE_HAS_FULL_ASCII7
#define PARSER_CHAR_TYPE_TO_TRANSLATE            8
#endif

#define PARSER_CHAR_TYPE_IGNORE                255

#define PARSER_STATUS_NORMAL                 0
#define PARSER_STATUS_STRING                 1
#define PARSER_STATUS_MULTILINE              2

#define PARSER_EOF          1
#define PARSER_EOL          2
#define PARSER_COMMENT      4
#define PARSER_WORD         8
#define PARSER_BLANK_START 16

#define PARSER_ERROR_BASE                       0x800D0000
#define PARSER_ERROR_CODE(code_)                ((s32)(PARSER_ERROR_BASE+(code_)))

#define PARSER_SYNTAX_ERROR_MULTILINE           PARSER_ERROR_CODE(0x0001)
#define PARSER_SYNTAX_ERROR_EXPECTED_EOL        PARSER_ERROR_CODE(0x0002)
#define PARSER_SYNTAX_ERROR_LINE_TOO_BIG        PARSER_ERROR_CODE(0x0003)
#define PARSER_BUFFER_TOO_SMALL                 PARSER_ERROR_CODE(0x0004)
#define PARSER_NO_INPUT                         PARSER_ERROR_CODE(0x0005)
#define PARSER_ODD_CHAR_NUMBER                  PARSER_ERROR_CODE(0x0006)
#define PARSER_LINE_ENDED_WITH_ESCAPE           PARSER_ERROR_CODE(0x0007)
#define PARSER_UNEXPECTED_STRING_DELIMITER      PARSER_ERROR_CODE(0x0008)
#define PARSER_EXPECTED_STRING_END_DELIMITER    PARSER_ERROR_CODE(0x0009)
#define PARSER_INCLUDE_DEPTH_TOO_BIG            PARSER_ERROR_CODE(0x000A)
#define PARSER_UNKNOWN_TIME_UNIT                PARSER_ERROR_CODE(0x000B)
#define PARSER_NO_MARK_SET                      PARSER_ERROR_CODE(0x000C)
#define PARSER_REACHED_END_OF_LINE              PARSER_ERROR_CODE(0x000D)
#define PARSER_FOUND_WORD                       PARSER_ERROR_CODE(0x000E)
#define PARSER_REACHED_END_OF_FILE              PARSER_ERROR_CODE(0x000F)
#define PARSER_INVALID_ESCAPED_FORMAT           PARSER_ERROR_CODE(0x0010)

struct parser_token_s
{
    const char *word;
    u32 word_len;
};

typedef struct parser_token_s parser_token_s;

struct parser_s
{
    // SETTINGS
    
    // ie: "" '' <> []
    parser_delimiter_s *string_delimiters;
    
    
    // ie: ()
    parser_delimiter_s *multiline_delimiters;
        
    // ie: # ;
    const char *comment_marker;
        
    // ie: SPACE TAB
    const char *blank_marker;
        
    // ie: BACKSLASH
    const char *escape_characters;
        
    // STATE MACHINE
    
    char *needle;
    char *needle_mark;
    char *limit;
    char *text;
    u32 text_length;
    u32 string_delimiters_count;
    
    u32 multiline_delimiters_count;
    u32 comment_marker_count;
    
    u32 blank_marker_count;
    u32 escape_characters_count;

    u32 line_number;
    u32 input_stream_stack_size;
    
    char multiline;     // TODO: stack of multilines
    char cutchar;       // 
    bool tokenize_on_string;
    bool close_last_stream;
    
    input_stream *input_stream_stack[PARSER_INCLUDE_DEPTH_MAX];
    u32 line_number_stack[PARSER_INCLUDE_DEPTH_MAX];
    
    char char_type[256];
    char delimiter_close[256];
#if DNSCORE_HAS_FULL_ASCII7
    char translation_table[256];
#endif
        
    char line_buffer[PARSER_LINE_LENGTH_MAX];
    char line_buffer_zero;
    char extra_buffer[PARSER_LINE_LENGTH_MAX];
    char extra_buffer_zero;
    char additional_buffer[PARSER_LINE_LENGTH_MAX];
    char additional_buffer_zero;
};

typedef struct parser_s parser_s;

void parser_init_error_codes();

ya_result parser_init(parser_s *parser,
            const char *string_delimiters,      // by 2
            const char *multiline_delimiters,   // by 2
            const char *comment_markers,        // by 1
            const char *blank_makers,           // by 1
            const char *escape_characters       // by 1            
        );

ya_result parser_finalize(parser_s *parser);

ya_result parser_next_token(parser_s *parser);

ya_result parser_next_characters(parser_s *parser);
ya_result parser_next_characters_nospace(parser_s *parser);

ya_result parser_concat_next_tokens(parser_s *parser);
ya_result parser_concat_next_tokens_nospace(parser_s *parser);

ya_result parser_concat_current_and_next_tokens_nospace(parser_s *parser);

void parser_set_eol(parser_s *parser);

#if DNSCORE_HAS_FULL_ASCII7
void parser_add_translation(parser_s *parser, u8 character, u8 translates_into);
void parser_del_translation(parser_s *parser, u8 character);
#endif

static inline u32
parser_text_length(const parser_s *parser)
{
    return parser->text_length;
}

static inline const char *
parser_text(const parser_s *parser)
{
    return parser->text;
}

/**
 * 
 * sets a terminating zero at the end of the current text returned by parser_text(parser)
 * can only work once
 * parser_text_unasciiz(parser) MUST be called before parsing the remaining of the input
 * 
 * @param parser
 * @return 
 */

static inline bool
parser_text_asciiz(parser_s *parser)
{
    if(parser->cutchar == '\0')
    {
        parser->cutchar = parser->text[parser->text_length];
        parser->text[parser->text_length] = '\0';
        
        return TRUE;
    }
    
    return FALSE;
}

/**
 * 
 * see parser_text_unasciiz
 * 
 * @param parser
 * @return 
 */

static inline bool
parser_text_unasciiz(parser_s *parser)
{
    if(parser->cutchar != '\0')
    {
        parser->text[parser->text_length] = parser->cutchar;
        parser->cutchar = '\0';
        
        return TRUE;
    }
    
    return FALSE;
}

static inline u8
parser_text_delimiter(const parser_s *parser)
{
    (void)parser;
    return 0; // not implemented
}

ya_result parser_push_stream(parser_s *p, input_stream *is);
        
input_stream *parser_pop_stream(parser_s *p);

static inline u32
parser_stream_count(const parser_s *p)
{
    return p->input_stream_stack_size;
}

/**
 * 
 * Set the rewind position in the parser
 * 
 * @param p
 */

static inline void
parser_mark(parser_s *p)
{
    p->needle_mark = p->needle;
}

static inline ya_result
parser_rewind(parser_s *p)
{
    if(p->needle_mark != NULL)
    {
        p->needle = p->needle_mark;
        return SUCCESS;
    }
    else
    {
        return PARSER_NO_MARK_SET;
    }
}

static inline u32
parser_get_line_number(const parser_s *p)
{
    return p->line_number;
}

///////////////////////////////////////////////////////////////////////////////

static inline ya_result
parser_next_word(parser_s *p)
{
    ya_result ret;
    
    for(;;)
    {
        if(FAIL(ret = parser_next_token(p)))
        {
            return ret;
        }
        
        if(ret & PARSER_WORD)
        {
            return 1;
        }

        if(ret & (PARSER_EOL|PARSER_EOF))
        {
            if(ret & PARSER_EOL)
            {
                return PARSER_REACHED_END_OF_LINE;
            }
            else
            {
                return PARSER_REACHED_END_OF_FILE;
            }
        }
    }
}

static inline ya_result
parser_get_u16(const char *text, u32 text_len, u16 *out_value)
{
    u32 tmp_u32;
    ya_result return_code = parse_u32_check_range_len_base10(text, text_len, &tmp_u32, 0, MAX_U16);
    *out_value = (u16)tmp_u32;

    return return_code;
}

static inline ya_result
parser_copy_next_u16(parser_s *p, u16 *out_value)
{
    ya_result return_code = parser_next_word(p);
    
    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        u32 text_len = parser_text_length(p);
        u32 tmp_u32;
        return_code = parse_u32_check_range_len_base10(text, text_len, &tmp_u32, 0, MAX_U16);
        *out_value = (u16)tmp_u32;
    }
    
    return return_code;
}

static inline ya_result
parser_copy_next_u8(parser_s *p, u8 *out_value)
{
    ya_result return_code = parser_next_word(p);
    
    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        u32 text_len = parser_text_length(p);
        u32 tmp_u32;
        return_code = parse_u32_check_range_len_base10(text, text_len, &tmp_u32, 0, MAX_U8);
        *out_value = (u8)tmp_u32;
    }
    
    return return_code;
}

static inline ya_result
parser_get_u8(const char *text, u32 text_len, u8 *out_value)
{
    u32 tmp_u32;
    ya_result return_code = parse_u32_check_range_len_base10(text, text_len, &tmp_u32, 0, MAX_U8);
    *out_value = (u8)tmp_u32;

    return return_code;
}

static inline ya_result
parser_get_s8(const char *text, u32 text_len, s8 *out_value)
{
    s32 tmp_s32;
    ya_result return_code = parse_s32_check_range_len_base10(text, text_len, &tmp_s32, (s32)MIN_S8, (s32)MAX_S8);
    *out_value = (s8)tmp_s32;

    return return_code;
}

static inline ya_result
parser_expect_eol(parser_s *p)
{
    ya_result return_code;
    
    for(;;)
    {
        return_code = parser_next_token(p);
        
        if(return_code & PARSER_WORD)
        {
            return PARSER_FOUND_WORD;
        }
        
        if(return_code & (PARSER_EOL|PARSER_EOF))
        {
            return SUCCESS;
        }
    }
}

static inline bool
parse_word_match(const char *text, u32 text_len, const char *match, u32 match_len)
{
    if(text_len == match_len)
    {
        bool ret = (memcmp(text, match, text_len) == 0);
        
        return ret;
    }
    
    return FALSE;
}

static inline bool
parse_word_case_match(const char *text, u32 text_len, const char *match, u32 match_len)
{
    if(text_len == match_len)
    {
        for(u32 i = 0; i < text_len; ++i)
        {
            if(tolower(text[i]) != tolower(match[i]))
            {
                return FALSE;
            }
        }

        return TRUE;
    }

    return FALSE;
}

static inline ya_result
parser_copy_word(parser_s *p, char *out_text, u32 out_text_len)
{
    u32 len = parser_text_length(p);
    if(len < out_text_len)
    {
        memcpy(out_text, parser_text(p), len);
        out_text[len] = '\0';

        return len;
    }
    else
    {
        return PARSER_BUFFER_TOO_SMALL;
    }
}

static inline ya_result
parser_copy_next_word(parser_s *p, char *out_text, u32 out_text_len)
{
    ya_result return_code = parser_next_word(p);
    
    if(ISOK(return_code))
    {
        u32 len = parser_text_length(p);
        if(len < out_text_len)
        {
            memcpy(out_text, parser_text(p), len);
            out_text[len] = '\0';
            
            return_code = len;
        }
        else
        {
            return_code = PARSER_BUFFER_TOO_SMALL;
        }
    }
    
    return return_code;
}

static inline ya_result
parser_copy_next_class(parser_s *p, u16 *out_value)
{
    ya_result return_code;
    
    char text[32];
    
    if(ISOK(return_code = parser_copy_next_word(p, text, sizeof(text))))
    {
        return_code = dns_class_from_name(text, out_value);
    }
    
    return return_code;
}

static inline ya_result
parser_copy_next_type(parser_s *p, u16 *out_value)
{
    ya_result return_code;
    
    char text[32];
    
    if(ISOK(return_code = parser_copy_next_word(p, text, sizeof(text))))
    {
        return_code = dns_type_from_name(text, out_value);
    }
    
    return return_code;
}

ya_result parser_copy_next_ttl(parser_s *p, s32 *out_value);

static inline ya_result
parser_copy_next_fqdn(parser_s *p, u8 *out_value)
{
    ya_result return_code = parser_next_word(p);
    
    if(ISOK(return_code))
    {    
        const char *text = parser_text(p);
        u32 text_len = parser_text_length(p);

        return_code = cstr_to_dnsname_with_check_len(out_value, text, text_len);
    }
    
    return return_code;
}

static inline ya_result
parser_copy_next_fqdn_with_origin(parser_s *p, u8 *out_value, const u8 *origin)
{
    ya_result return_code = parser_next_word(p);
    
    if(ISOK(return_code))
    {    
        const char *text = parser_text(p);
        u32 text_len = parser_text_length(p);

        return_code = cstr_to_dnsname_with_check_len_with_origin(out_value, text, text_len, origin);
    }
    
    return return_code;
}

static inline ya_result
parser_copy_next_fqdn_locase_with_origin(parser_s *p, u8 *out_value, const u8 *origin)
{
    ya_result return_code = parser_next_word(p);
    
    if(ISOK(return_code))
    {    
        const char *text = parser_text(p);
        u32 text_len = parser_text_length(p);

        return_code = cstr_to_locase_dnsname_with_check_len_with_origin(out_value, text, text_len, origin);
    }
    
    return return_code;
}

static inline ya_result
parser_copy_next_yyyymmddhhmmss(parser_s *p, u32 *out_value)
{
    ya_result return_code = parser_next_word(p);
    
    if(ISOK(return_code))
    {    
        const char *text = parser_text(p);
        u32 text_len = parser_text_length(p);
        time_t t;
        return_code = parse_yyyymmddhhmmss_check_range_len(text, text_len, &t);
        *out_value = (u32)t;
    }
    
    return return_code;
}

static inline ya_result
parser_get_s16(const char *text, u32 text_len, s16 *out_value)
{
    s32 tmp_s32;
    ya_result return_code = parse_s32_check_range_len_base10(text, text_len, &tmp_s32, MIN_S16, MAX_S16);
    *out_value = (s16)tmp_s32;

    return return_code;
}

static inline ya_result
parser_copy_next_s16(parser_s *p, s16 *out_value)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        u32 text_len = parser_text_length(p);

        s32 tmp_s32;
        return_code = parse_s32_check_range_len_base10(text, text_len, &tmp_s32, MIN_S16, MAX_S16);
        *out_value = (s16)tmp_s32;
    }

    return return_code;
}

static inline ya_result
parser_get_u32(const char *text, u32 text_len, u32 *out_value)
{
    ya_result return_code = parse_u32_check_range_len_base10(text, text_len, out_value, 0, MAX_U32);

    return return_code;
}

static inline ya_result
parser_get_s32(const char *text, u32 text_len, s32 *out_value)
{
    ya_result return_code = parse_s32_check_range_len_base10(text, text_len, out_value, MIN_S32, MAX_S32);

    return return_code;
}

static inline ya_result
parser_copy_next_s32(parser_s *p, s32 *out_value)
{
    ya_result return_code = parser_next_word(p);
    
    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        u32 text_len = parser_text_length(p);

        return_code = parse_s32_check_range_len_base10(text, text_len, out_value, MIN_S32, MAX_S32);
    }
    
    return return_code;
}

static inline ya_result
parser_copy_next_u32(parser_s *p, u32 *out_value)
{
    ya_result return_code = parser_next_word(p);
    
    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        u32 text_len = parser_text_length(p);

        return_code = parse_u32_check_range_len_base10(text, text_len, out_value, 0, MAX_U32);
    }
    
    return return_code;
}

static inline ya_result
parser_get_u64(const char *text, u32 text_len, u64 *out_value)
{
    ya_result return_code = parse_u64_check_range_len_base10(text, text_len, out_value, 0, MAX_U64);

    return return_code;
}

static inline ya_result
parser_copy_next_u64(parser_s *p, u64 *out_value)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        u32 text_len = parser_text_length(p);

        return_code = parse_u64_check_range_len_base10(text, text_len, out_value, 0, MAX_U64);
    }

    return return_code;
}

ya_result parser_get_network_protocol_from_next_word(parser_s *p, int *out_value);

ya_result parser_get_network_service_port_from_next_word(parser_s *p, int *out_value);

ya_result parser_type_bit_maps_initialise(parser_s *p, type_bit_maps_context* context);

#ifdef	__cplusplus
}
#endif

#endif	/* PARSER_H */

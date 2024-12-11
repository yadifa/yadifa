/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#ifndef PARSER_H
#define PARSER_H

#include <dnscore/sys_types.h>
#include <dnscore/parsing.h>
#include <dnscore/typebitmap.h>
#include <dnscore/input_stream.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct parser_delimiter_s
{
    char    begin; // " ' <
    char    end;   // " ' >
    uint8_t id;
    uint8_t reserved;
};

typedef struct parser_delimiter_s parser_delimiter_s;

#define PARSER_INCLUDE_DEPTH_MAX 256

#if DNSCORE_HAS_OQS_SUPPORT
#define PARSER_LINE_LENGTH_MAX 0x20000 // because SPHINCS 256F has
#else
#define PARSER_LINE_LENGTH_MAX 0x10000
#endif

#define PARSER_CHAR_TYPE_NORMAL                  0
#define PARSER_CHAR_TYPE_ESCAPE_CHARACTER        1
#define PARSER_CHAR_TYPE_COMMENT_MARKER          2
#define PARSER_CHAR_TYPE_STRING_DELIMITER        3
#define PARSER_CHAR_TYPE_MULTILINE_DELIMITER     4
#define PARSER_CHAR_TYPE_MULTILINE_DELIMITER_END 5
#define PARSER_CHAR_TYPE_BLANK_MARKER            6
#define PARSER_CHAR_TYPE_EOL                     7
#if DNSCORE_HAS_FULL_ASCII7
#define PARSER_CHAR_TYPE_TO_TRANSLATE 8
#endif

#define PARSER_CHAR_TYPE_IGNORE              255

#define PARSER_STATUS_NORMAL                 0
#define PARSER_STATUS_STRING                 1
#define PARSER_STATUS_MULTILINE              2

#define PARSER_EOF                           1
#define PARSER_EOL                           2
#define PARSER_COMMENT                       4
#define PARSER_WORD                          8
#define PARSER_BLANK_START                   16

#define PARSER_ERROR_BASE                    0x800D0000
#define PARSER_ERROR_CODE(code_)             ((int32_t)(PARSER_ERROR_BASE + (code_)))

#define PARSER_SYNTAX_ERROR_MULTILINE        PARSER_ERROR_CODE(0x0001)
#define PARSER_SYNTAX_ERROR_EXPECTED_EOL     PARSER_ERROR_CODE(0x0002)
#define PARSER_SYNTAX_ERROR_LINE_TOO_BIG     PARSER_ERROR_CODE(0x0003)
#define PARSER_BUFFER_TOO_SMALL              PARSER_ERROR_CODE(0x0004)
#define PARSER_NO_INPUT                      PARSER_ERROR_CODE(0x0005)
#define PARSER_ODD_CHAR_NUMBER               PARSER_ERROR_CODE(0x0006)
#define PARSER_LINE_ENDED_WITH_ESCAPE        PARSER_ERROR_CODE(0x0007)
#define PARSER_UNEXPECTED_STRING_DELIMITER   PARSER_ERROR_CODE(0x0008)
#define PARSER_EXPECTED_STRING_END_DELIMITER PARSER_ERROR_CODE(0x0009)
#define PARSER_INCLUDE_DEPTH_TOO_BIG         PARSER_ERROR_CODE(0x000A)
#define PARSER_UNKNOWN_TIME_UNIT             PARSER_ERROR_CODE(0x000B)
#define PARSER_NO_MARK_SET                   PARSER_ERROR_CODE(0x000C)
#define PARSER_REACHED_END_OF_LINE           PARSER_ERROR_CODE(0x000D)
#define PARSER_FOUND_WORD                    PARSER_ERROR_CODE(0x000E)
#define PARSER_REACHED_END_OF_FILE           PARSER_ERROR_CODE(0x000F)
#define PARSER_INVALID_ESCAPED_FORMAT        PARSER_ERROR_CODE(0x0010)

struct parser_soken_s
{
    const char *word;
    uint32_t    word_len;
};

typedef struct parser_soken_s parser_token_t;

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

    char           *needle;
    char           *needle_mark;
    char           *limit;
    char           *text;
    uint32_t        text_length;
    uint32_t        string_delimiters_count;

    uint32_t        multiline_delimiters_count;
    uint32_t        comment_marker_count;

    uint32_t        blank_marker_count;
    uint32_t        escape_characters_count;

    uint32_t        line_number;
    uint32_t        input_stream_stack_size;

    char            multiline; // TODO: stack of multilines
    char            cutchar;   //
    bool            tokenize_on_string;
    bool            close_last_stream;

    input_stream_t *input_stream_stack[PARSER_INCLUDE_DEPTH_MAX];
    uint32_t        line_number_stack[PARSER_INCLUDE_DEPTH_MAX];

    char            char_type[256];
    char            delimiter_close[256];
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

typedef struct parser_s parser_t;

void                    parser_init_error_codes();

/**
 * Initialises a parser.
 *
 * @param string_delimiters characters used to delimit a string, e.g. "\"\"''"
 * @param multiline_delimiters characters used to delimit a multiline, e.g. "()"
 * @param comment_markers characters used to start a comment, e.g. ";"
 * @param blank_makers characters considered as a blank, e.g. "\040\t\r"
 * @param escape_characters characters used for an escape, e.g. "\\"
 *
 * @return an error code
 */

ya_result parser_init(parser_t   *parser,
                      const char *string_delimiters,    // by 2
                      const char *multiline_delimiters, // by 2
                      const char *comment_markers,      // by 1
                      const char *blank_makers,         // by 1
                      const char *escape_characters     // by 1
);

/**
 * Finalises the parser.
 * Releases internal structures.
 *
 * @param parser the parser
 * @return an error code
 */

ya_result parser_finalize(parser_t *parser);

/**
 * Obtains the next token from the parser.
 *
 * Returns an error code or a bit field
 *
 * The bits are:
 *  PARSER_EOL
 *  PARSER_EOF
 *
 * @param parser the parser
 * @return a bit field or an error code
 *
 */

ya_result parser_next_token(parser_t *parser);

#if UNUSED
ya_result parser_next_characters(parser_t *parser);
ya_result parser_next_characters_nospace(parser_t *parser);
#endif

ya_result parser_concat_next_tokens(parser_t *parser);
ya_result parser_concat_next_tokens_nospace(parser_t *parser);

ya_result parser_concat_current_and_next_tokens_nospace(parser_t *parser);

void      parser_set_eol(parser_t *parser);

#if DNSCORE_HAS_FULL_ASCII7
void parser_add_translation(parser_t *parser, uint8_t character, uint8_t translates_into);
void parser_del_translation(parser_t *parser, uint8_t character);
#endif

/**
 * Returns the length of the current token.
 *
 * @param parser the parser
 * @return the length of the current token
 */

static inline uint32_t parser_text_length(const parser_t *parser) { return parser->text_length; }

/**
 * Returns the current token.
 *
 * @param parser the parser
 * @return the current token
 */

static inline const char *parser_text(const parser_t *parser) { return parser->text; }

/**
 * Sets a terminating zero at the end of the current text returned by parser_text(parser)
 * Can only be called once for a given token.
 *
 * parser_text_unasciiz(parser) MUST be called before parsing the remaining of the input
 *
 * @param parser
 * @return true iff the operation succeeded.
 */

static inline bool parser_text_asciiz(parser_t *parser)
{
    if(parser->cutchar == '\0')
    {
        parser->cutchar = parser->text[parser->text_length];
        parser->text[parser->text_length] = '\0';

        return true;
    }

    return false;
}

/**
 * Undo the operation done by parser_text_asciiz.
 * see parser_text_asciiz
 *
 * @param parser
 * @return true iff the operation succeeded.
 */

static inline bool parser_text_unasciiz(parser_t *parser)
{
    if(parser->cutchar != '\0')
    {
        parser->text[parser->text_length] = parser->cutchar;
        parser->cutchar = '\0';

        return true;
    }

    return false;
}

/**
 * Pushes an input stream as the next input for the parser.
 * Used for an "include" feature.
 *
 * @param p the parser
 * @param is the input stream
 * @return an error code
 */

ya_result parser_push_stream(parser_t *p, input_stream_t *is);

/**
 * Pops the current input stream from the parser.
 *
 * @return a pointer to the input stream
 */

input_stream_t *parser_pop_stream(parser_t *p);

/**
 * Returns the size of the stack of input streams
 *
 * @return the size of the stack of input streams
 */

static inline uint32_t parser_stream_count(const parser_t *p) { return p->input_stream_stack_size; }

/**
 *
 * Sets the rewind position in the parser
 *
 * @param p the parser
 */

static inline void parser_mark(parser_t *p) { p->needle_mark = p->needle; }

/**
 * Rewinds to the last set rewind position of the parser
 *
 * @param p the parser
 * @return an error code
 */

static inline ya_result parser_rewind(parser_t *p)
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

/**
 * Returns the current line number in the current file/input stream
 *
 * @returns the current line number in the current file/input stream
 */

static inline uint32_t parser_get_line_number(const parser_t *p) { return p->line_number; }

///////////////////////////////////////////////////////////////////////////////

/**
 * Go to the next word from the input
 *
 * @return an error code
 */

static inline ya_result parser_next_word(parser_t *p)
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

        if(ret & (PARSER_EOL | PARSER_EOF))
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

/**
 * Go to the next word from the input and converts it to an uint8_t
 *
 * @param p the parser
 * @param out_value a pointer to store the parsed uint8_t
 *
 * @return an error code
 */

static inline ya_result parser_copy_next_u8(parser_t *p, uint8_t *out_value)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        uint32_t    text_len = parser_text_length(p);
        uint32_t    tmp_u32;
        return_code = parse_u32_check_range_len_base10(text, text_len, &tmp_u32, 0, U8_MAX);
        *out_value = (uint8_t)tmp_u32;
    }

    return return_code;
}

/**
 * Go to the next word from the input and converts it to an uint16_t
 *
 * @param p the parser
 * @param out_value a pointer to store the parsed uint16_t
 *
 * @return an error code
 */

static inline ya_result parser_copy_next_u16(parser_t *p, uint16_t *out_value)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        uint32_t    text_len = parser_text_length(p);
        uint32_t    tmp_u32;
        return_code = parse_u32_check_range_len_base10(text, text_len, &tmp_u32, 0, U16_MAX);
        *out_value = (uint16_t)tmp_u32;
    }

    return return_code;
}

/**
 * Go to the next word from the input and converts it to an int16_t
 *
 * @param p the parser
 * @param out_value a pointer to store the parsed int16_t
 *
 * @return an error code
 */

static inline ya_result parser_copy_next_s16(parser_t *p, int16_t *out_value)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        uint32_t    text_len = parser_text_length(p);

        int32_t     tmp_s32;
        return_code = parse_s32_check_range_len_base10(text, text_len, &tmp_s32, S16_MIN, S16_MAX);
        *out_value = (int16_t)tmp_s32;
    }

    return return_code;
}

/**
 * Go to the next word from the input and converts it to an int32_t
 *
 * @param p the parser
 * @param out_value a pointer to store the parsed int32_t
 *
 * @return an error code
 */

static inline ya_result parser_copy_next_s32(parser_t *p, int32_t *out_value)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        uint32_t    text_len = parser_text_length(p);

        return_code = parse_s32_check_range_len_base10(text, text_len, out_value, S32_MIN, INT32_MAX);
    }

    return return_code;
}

/**
 * Go to the next word from the input and converts it to an uint32_t
 *
 * @param p the parser
 * @param out_value a pointer to store the parsed uint32_t
 *
 * @return an error code
 */

static inline ya_result parser_copy_next_u32(parser_t *p, uint32_t *out_value)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        uint32_t    text_len = parser_text_length(p);

        return_code = parse_u32_check_range_len_base10(text, text_len, out_value, 0, U32_MAX);
    }

    return return_code;
}

/**
 * Go to the next word from the input and converts it to an uint64_t
 *
 * @param p the parser
 * @param out_value a pointer to store the parsed uint64_t
 *
 * @return an error code
 */

static inline ya_result parser_copy_next_u64(parser_t *p, uint64_t *out_value)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        uint32_t    text_len = parser_text_length(p);

        return_code = parse_u64_check_range_len_base10(text, text_len, out_value, 0, U64_MAX);
    }

    return return_code;
}

static inline ya_result parser_expect_eol(parser_t *p)
{
    ya_result return_code;

    for(;;)
    {
        return_code = parser_next_token(p);

        if(return_code & PARSER_WORD)
        {
            return PARSER_FOUND_WORD;
        }

        if(return_code & (PARSER_EOL | PARSER_EOF))
        {
            return SUCCESS;
        }
    }
}

static inline ya_result parser_copy_word(parser_t *p, char *out_text, uint32_t out_text_len)
{
    uint32_t len = parser_text_length(p);
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

static inline ya_result parser_copy_next_word(parser_t *p, char *out_text, uint32_t out_text_len)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        uint32_t len = parser_text_length(p);
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

static inline ya_result parser_copy_next_class(parser_t *p, uint16_t *out_value)
{
    ya_result return_code;

    char      text[32];

    if(ISOK(return_code = parser_copy_next_word(p, text, sizeof(text))))
    {
        return_code = dns_class_from_name(text, out_value);
    }

    return return_code;
}

static inline ya_result parser_copy_next_type(parser_t *p, uint16_t *out_value)
{
    ya_result return_code;

    char      text[32];

    if(ISOK(return_code = parser_copy_next_word(p, text, sizeof(text))))
    {
        return_code = dns_type_from_name(text, out_value);
    }

    return return_code;
}

ya_result               parser_copy_next_ttl(parser_t *p, int32_t *out_value);

static inline ya_result parser_copy_next_fqdn(parser_t *p, uint8_t *out_value)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        uint32_t    text_len = parser_text_length(p);

        return_code = dnsname_init_check_nostar_with_charp(out_value, text, text_len);
    }

    return return_code;
}

static inline ya_result parser_copy_next_fqdn_with_origin(parser_t *p, uint8_t *out_value, const uint8_t *origin)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        uint32_t    text_len = parser_text_length(p);

        return_code = dnsname_init_check_star_with_charp_and_origin(out_value, text, text_len, origin);
    }

    return return_code;
}

static inline ya_result parser_copy_next_fqdn_locase_with_origin(parser_t *p, uint8_t *out_value, const uint8_t *origin)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        uint32_t    text_len = parser_text_length(p);

        return_code = dnsname_init_check_star_with_charp_and_origin_locase(out_value, text, text_len, origin);
    }

    return return_code;
}

static inline ya_result parser_copy_next_yyyymmddhhmmss(parser_t *p, uint32_t *out_value)
{
    ya_result return_code = parser_next_word(p);

    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        uint32_t    text_len = parser_text_length(p);
        time_t      t;
        return_code = parse_yyyymmddhhmmss_check_range_len(text, text_len, &t);
        *out_value = (uint32_t)t;
    }

    return return_code;
}

ya_result parser_get_network_protocol_from_next_word(parser_t *p, int *out_value);

ya_result parser_get_network_service_port_from_next_word(parser_t *p, int *out_value);

ya_result parser_type_bit_maps_initialise(parser_t *p, type_bit_maps_context_t *context);

#ifdef __cplusplus
}
#endif

#endif /* PARSER_H */

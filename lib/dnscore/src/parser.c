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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
//#include <sys/resource.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "dnscore/timems.h"
#include "dnscore/logger.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/logger_channel_stream.h"
#include "dnscore/buffer_input_stream.h"

#include "dnscore/base16.h"
#include "dnscore/base32hex.h"
#include "dnscore/base64.h"

#include "dnscore/parser.h"
#include "dnscore/ptr_set.h"
#include "dnscore/mutex.h"


#define DO_PRINT 0
#define DO_BUFFERIZE 1

#define PARSER_STREAM_BUFFER_SIZE 4096

static const char eol_park_needle[2] = {' ', '\0'};
static bool parser_init_error_codes_done = FALSE;

static inline ya_result
parser_set_couples(parser_s *parser, const char* input, u8 kind, u8 closer_kind)
{
    u32 n = strlen(input);
    
    if((n & 1) != 0)
    {
        return PARSER_ODD_CHAR_NUMBER;
    }
    
    for(u32 i = 0; i < n; i+= 2)
    {
        parser->char_type[(u8)input[i]] = kind;
        if(closer_kind != PARSER_CHAR_TYPE_IGNORE)
        {
            parser->char_type[(u8)input[i + 1]] = closer_kind;
        }
        parser->delimiter_close[(u8)input[i]] = input[i + 1];
    }
    
    return n>>1;
}

static inline u32
parser_set_singleton(parser_s *parser, const char* input, u8 kind)
{
    u32 n = strlen(input);

    for(u32 i = 0; i < n; i++)
    {
        parser->char_type[(u8)input[i]] = kind;
    }
    
    return n;
}

void
parser_init_error_codes()
{
    if(parser_init_error_codes_done)
    {
        return;
    }
    
    parser_init_error_codes_done = TRUE;
    
    error_register(PARSER_SYNTAX_ERROR_MULTILINE,"PARSER_SYNTAX_ERROR_MULTILINE");
    error_register(PARSER_SYNTAX_ERROR_EXPECTED_EOL,"PARSER_SYNTAX_ERROR_EXPECTED_EOL");
    error_register(PARSER_SYNTAX_ERROR_LINE_TOO_BIG,"PARSER_SYNTAX_ERROR_LINE_TOO_BIG");
    error_register(PARSER_BUFFER_TOO_SMALL,"PARSER_BUFFER_TOO_SMALL");
    error_register(PARSER_NO_INPUT,"PARSER_NO_INPUT");
    error_register(PARSER_ODD_CHAR_NUMBER,"PARSER_ODD_CHAR_NUMBER");
    error_register(PARSER_LINE_ENDED_WITH_ESCAPE,"PARSER_LINE_ENDED_WITH_ESCAPE");
    error_register(PARSER_UNEXPECTED_STRING_DELIMITER,"PARSER_UNEXPECTED_STRING_DELIMITER");
    error_register(PARSER_EXPECTED_STRING_END_DELIMITER,"PARSER_EXPECTED_STRING_END_DELIMITER");
    error_register(PARSER_INCLUDE_DEPTH_TOO_BIG,"PARSER_INCLUDE_DEPTH_TOO_BIG");
    error_register(PARSER_UNKNOWN_TIME_UNIT,"PARSER_UNKNOWN_TIME_UNIT");
    error_register(PARSER_NO_MARK_SET,"PARSER_NO_MARK_SET");
    error_register(PARSER_REACHED_END_OF_LINE,"PARSER_REACHED_END_OF_LINE");
    error_register(PARSER_FOUND_WORD,"PARSER_FOUND_WORD");
    error_register(PARSER_REACHED_END_OF_FILE, "PARSER_REACHED_END_OF_FILE");
    error_register(PARSER_INVALID_ESCAPED_FORMAT, "PARSER_INVALID_ESCAPED_FORMAT");
}

ya_result
parser_init(parser_s *parser,
            const char *string_delimiters,      // by 2
            const char *multiline_delimiters,   // by 2
            const char *comment_markers,        // by 1
            const char *blank_makers,           // by 1
            const char *escape_characters       // by 1            
        )
{
    ya_result return_code = SUCCESS;
    
    /// @note may be improved if we spawn parser a lot
    
    ZEROMEMORY(parser, sizeof(parser_s));
    
    //

    if(ISOK(return_code = parser_set_couples(parser, string_delimiters, PARSER_CHAR_TYPE_STRING_DELIMITER, PARSER_CHAR_TYPE_IGNORE)))
    {
        parser->string_delimiters_count = return_code;
        
        if(ISOK(return_code = parser_set_couples(parser, multiline_delimiters, PARSER_CHAR_TYPE_MULTILINE_DELIMITER, PARSER_CHAR_TYPE_MULTILINE_DELIMITER_END)))
        {
            parser->multiline_delimiters_count = return_code;
            
            parser->comment_marker_count = parser_set_singleton(parser, comment_markers, PARSER_CHAR_TYPE_COMMENT_MARKER);
            parser->comment_marker = comment_markers;
            parser->blank_marker_count = parser_set_singleton(parser, blank_makers, PARSER_CHAR_TYPE_BLANK_MARKER);
            parser->blank_marker = blank_makers;
            parser->escape_characters_count =parser_set_singleton(parser, escape_characters, PARSER_CHAR_TYPE_ESCAPE_CHARACTER);
            parser->escape_characters = escape_characters;
            parser->close_last_stream = TRUE;
            parser_set_singleton(parser, "\n", PARSER_CHAR_TYPE_EOL);
        }
    }
        
    return return_code;
}

ya_result
parser_finalize(parser_s *parser)
{
    for(;;)
    {
        input_stream *is = parser_pop_stream(parser);
        if(is == NULL)
        {
            break;
        }
        if((parser->input_stream_stack_size == 0) && !parser->close_last_stream)
        {
            break;
        }
        input_stream_close(is);
        input_stream_set_void(is);
    }
    
    return SUCCESS;
}

static inline u32
parser_line_size(parser_s *parser)
{
    return (u32)(parser->limit - parser->needle);
}

static inline ya_result
parser_clear_escape_codes(char **startp, int *lenp, char escape_char, char *new_start)
{
    char *start = *startp;
    char *escape_char_ptr;
    int len = *lenp;
   
    if((escape_char_ptr = memchr(start, escape_char, len)) != NULL)
    {
        char *op = new_start;
        
        for(;;)
        {
            size_t n = escape_char_ptr - start;

            // is the escape code is at the last position ?
            
            if(n + 1 == (size_t)len)
            {
                // oops
                return PARSER_LINE_ENDED_WITH_ESCAPE;
            }

            memcpy(op, start, n);

            char c = escape_char_ptr[1];

            if((c >= '0') && (c <= '2'))
            {
                if(n + 3 < (size_t)len)
                {
                    u32 decimal_char = (c - '0') * 100;
                    c = escape_char_ptr[2];
                    if((c >= '0') && (c <= '9'))
                    {
                        decimal_char += (c - '0') * 10;
                        c = escape_char_ptr[3];
                        if((c >= '0') && (c <= '9'))
                        {
                            decimal_char += (c - '0');
                            if(decimal_char <= 255)
                            {
                                op[n] = (u8)decimal_char;
                                op += n + 1;
                                start = escape_char_ptr + 4;
                                len -= n + 4;
                            }
                            else
                            {
                                return PARSER_INVALID_ESCAPED_FORMAT;
                            }
                        }
                        else
                        {
                            return PARSER_INVALID_ESCAPED_FORMAT;
                        }
                    }
                    else
                    {
                        return PARSER_INVALID_ESCAPED_FORMAT;
                    }
                }
                else
                {
                    return PARSER_INVALID_ESCAPED_FORMAT;
                }
            }
            else
            {
                op[n] = c;
                op += n + 1;
                start = escape_char_ptr + 2;
                len -= n + 2;
            }

            yassert(len >= 0);
            
            if(len == 0)
            {
                break;
            }

            if((escape_char_ptr = memchr(start, escape_char, len)) == NULL)
            {
                // copy the remaining bytes
                
                memcpy(op, start, len);
                op += len;
                break;
            }
        }
        
        *startp = new_start;
        *lenp = op - new_start;
    }
    // else we have nothing more to do
    
    return len;
}

/**
 * 
 * returns the token type
 * 
 * @param parser
 * @return 
 */

static inline ya_result
parser_read_line(parser_s *parser)
{
    ya_result return_code;
        
    if(parser_line_size(parser) == 0)
    {
        // read next line
        
        if(parser->input_stream_stack_size == 0)
        {
            return_code = PARSER_NO_INPUT; // no input file/stream
            return return_code;
        }
        
        char *buffer = parser->line_buffer;
        char *limit = &parser->line_buffer[sizeof(parser->line_buffer)];
        
        for(;;)
        {
            if(limit - buffer == 0)
            {
                return PARSER_SYNTAX_ERROR_LINE_TOO_BIG;
            }
            
#if DO_BUFFERIZE
            return_code = buffer_input_stream_read_line(parser->input_stream_stack[parser->input_stream_stack_size - 1],
                                                            buffer,
                                                            limit - buffer);
#else
            return_code = input_stream_read_line(parser->input_stream_stack[parser->input_stream_stack_size - 1],
                                                    buffer,
                                                    limit - buffer);
#endif
        
            if(return_code > 0)
            {
                // one line has been read (maybe)

                buffer += return_code;

                if(return_code > 1)
                {
                    if(buffer[-2] == parser->escape_characters[0])
                    {
                        // the EOL was escaped, concat the next line ...
                        // do NOT remove the escape code now

                        continue;
                    }
                }

                parser->limit = buffer;
                parser->needle = parser->line_buffer;
                parser->line_number++;
            }
            else
            {
                // error or end of stream

                parser->limit = parser->line_buffer;
                parser->needle = parser->line_buffer;

                if(return_code == 0)
                {
                    if(parser->multiline != 0)
                    {
                        return_code = PARSER_SYNTAX_ERROR_MULTILINE;
                    }
                }
            }
            
            return return_code;
        }
    }
    
    return PARSER_EOF;
}

ya_result
parser_next_token(parser_s *parser)
{
    ya_result return_code;
    
    for(;;)
    {        
        if((return_code = parser_read_line(parser)) <= 0)
        {

            if(return_code == 0)
            {


                return PARSER_EOF;
            }

            return return_code;
        }

        // there are bytes
        
        return_code = 0;

        for(char *needle = parser->needle; needle < parser->limit; needle++)
        {
            u8 b = (u8)*needle;

            // test for multiline close

            bool has_escapes = FALSE;

            switch(parser->char_type[b])
            {
#if DNSCORE_HAS_FULL_ASCII7
                case PARSER_CHAR_TYPE_TO_TRANSLATE:
                    *needle = parser->translation_table[b];
                    --needle;
#endif
                FALLTHROUGH // fall through
                case PARSER_CHAR_TYPE_ESCAPE_CHARACTER:
                    // the text starts after the next char, whatever it is
                    if(++needle < parser->limit)
                    {
                        if((*needle >= '0') && (*needle <= '2'))
                        {
                            // octal byte
                            if(needle + 2 < parser->limit)
                            {
                                //u8 octal_char = ((*needle) - '0') * 100;
                                ++needle;
                                if((*needle >= '0') && (*needle <= '9'))
                                {
                                    //octal_char |= ((*needle) - '0') * 10;
                                    ++needle;
                                    if((*needle >= '0') && (*needle <= '9'))
                                    {
                                        //octal_char |= ((*needle) - '0');
                                        needle -= 3;
                                        has_escapes = TRUE;
                                        // the buffer needs to be copied
                                    }
                                    else
                                    {
                                        // octal parse error

                                        return PARSER_INVALID_ESCAPED_FORMAT;
                                    }
                                }
                                else
                                {
                                    // octal parse error

                                    return PARSER_INVALID_ESCAPED_FORMAT;
                                }
                            }
                            else
                            {
                                // octal parse error

                                return PARSER_INVALID_ESCAPED_FORMAT;
                            }
                        }
                    }

                    FALLTHROUGH // fall through

                case PARSER_CHAR_TYPE_NORMAL:
                {
                    // BLANK or MULTI => done
                    // STRING => error
                    // COMMENT => CUT

                    parser->text = needle++;

                    for(; needle < parser->limit; needle++)
                    {
                        b = (u8)*needle;

                        switch(parser->char_type[b])
                        {
                            case PARSER_CHAR_TYPE_MULTILINE_DELIMITER_END:
                            {
                                if((parser->multiline) != 0 && (b == parser->multiline))
                                {
                                    b = ' ';
                                    *needle = b;
                                    parser->multiline = 0;
                                }
                                else
                                {
                                    return PARSER_SYNTAX_ERROR_MULTILINE;
                                }

                                // we got the whole word

                                parser->text_length = needle - parser->text;
                                parser->needle = needle + 1;
                                goto parser_next_token_end_of_token_found; /********* GOTO G O T O GOTO **********/
                            }

                            case PARSER_CHAR_TYPE_MULTILINE_DELIMITER:
                            {
                                if(parser->multiline == 0)
                                {
                                    parser->multiline = parser->delimiter_close[b];
                                }
                                else
                                {
                                    return PARSER_SYNTAX_ERROR_MULTILINE;
                                }

                                *needle = ' ';

                                // we got the whole word

                                parser->text_length = needle - parser->text;
                                parser->needle = needle + 1;
                                goto parser_next_token_end_of_token_found; /********* GOTO G O T O GOTO **********/
                            }

                            case PARSER_CHAR_TYPE_EOL:
                            {
                                // only tell we got an EOL if we are not on "multiline"

                                if(parser->multiline != 0)
                                {
                                    *needle = ' ';
                                }

                                // we got the whole word

                                parser->text_length = needle - parser->text;
                                parser->needle = needle;
                                goto parser_next_token_end_of_token_found; /********* GOTO G O T O GOTO **********/
                            }

                            case PARSER_CHAR_TYPE_BLANK_MARKER:
                            {
                                // we got the whole word

                                parser->text_length = needle - parser->text;
                                parser->needle = needle + 1;
                                goto parser_next_token_end_of_token_found; /********* GOTO G O T O GOTO **********/
                            }

                            case PARSER_CHAR_TYPE_ESCAPE_CHARACTER:
                            {
                                needle++;

                                has_escapes = TRUE;

                                break;
                            }

                            case PARSER_CHAR_TYPE_COMMENT_MARKER:
                            {
                                // we got the whole word

                                parser->text_length = needle - parser->text;
                                parser->needle = needle;
                                goto parser_next_token_end_of_token_found; /********* GOTO G O T O GOTO **********/
                            }

                            case PARSER_CHAR_TYPE_STRING_DELIMITER:
                            {
                                // parse error
                                if(!parser->tokenize_on_string)
                                {
                                    return PARSER_UNEXPECTED_STRING_DELIMITER;
                                }
                                
                                parser->text_length = needle - parser->text;
                                parser->needle = needle;
                                goto parser_next_token_end_of_token_found; /********* GOTO G O T O GOTO **********/
                            }
#if DNSCORE_HAS_FULL_ASCII7
                            case PARSER_CHAR_TYPE_TO_TRANSLATE:
                            {
                                *needle = parser->translation_table[b];
                                break;
                            }
#endif

                            //case PARSER_CHAR_TYPE_NORMAL:
                            default:
                            {
                                break;
                            }
                        } // end switch char type
                    } // end for needle

                    parser_next_token_end_of_token_found: ;

                    // at this point we have a full token (maybe still escaped)

                    int token_len = needle - parser->text;

                    if(has_escapes)
                    {
                        yassert(parser->escape_characters_count <= 1);
                        
                        if(parser->escape_characters_count == 1)
                        {
                            ya_result err;
                            
                            char escape_char = parser->escape_characters[0];

                            if(FAIL(err = parser_clear_escape_codes(&parser->text, &token_len, escape_char, parser->extra_buffer)))
                            {
                                return err;
                            }
                        }
                    }

                    parser->text_length = token_len;
                    parser->needle = needle;

                    return return_code | PARSER_WORD;
                }
                case PARSER_CHAR_TYPE_COMMENT_MARKER:
                {
                    // cut line

                    parser->text = needle;
                    parser->text_length = parser->limit - needle;

                    parser->needle = parser->limit;

                    if(parser->multiline == 0)
                    {
                        parser->needle_mark = NULL;
                        return return_code | PARSER_COMMENT | PARSER_EOL;
                    }
                    else
                    {
                        return return_code | PARSER_COMMENT;
                    }
                }
                case PARSER_CHAR_TYPE_MULTILINE_DELIMITER_END:
                {
                    if((parser->multiline) != 0 && (b == parser->multiline))
                    {
                        /*b = ' ';
                        *needle = b;*/
                        parser->multiline = 0;
                    }
                    else
                    {
                        return PARSER_SYNTAX_ERROR_MULTILINE;
                    }

                    break;
                }            
                case PARSER_CHAR_TYPE_STRING_DELIMITER:
                {
                    // find the end char ...
                    // note: see strpbrk

                    char end_char = parser->delimiter_close[b];

                    char *string_start = ++needle;
                    char *string_end;
                    for(;;)
                    {
                        string_end = memchr(needle, end_char, parser->limit - needle);

                        if(string_end != NULL)
                        {
                            // this one may have been escaped

                            /// @note 20190917 edf -- Patch submitted trough github by JZerf
                            ///                       This fixes the case of escaped escapes as well as an incorrect limit test
                            ///                       The patch has been slightly adapted in 2.4.x but may be kept as it is in 2.3.x

                            /* Check if the string delimiter that was found was escaped. Keep in
                             * mind that if there was an escape character in front of the string
                             * delimiter, the escape character itself could have also been escaped
                             * (and the one before that and the one before that...). What we can do
                             * is check to see how many consecutive preceding escape characters
                             * there are (by finding the first preceding nonescape character or the
                             * opening string delimiter if there isn't one) and if it's an even
                             * number then the string delimiter we found is unescaped but if it's an
                             * odd number then it is escaped. Note that this will need to be revised
                             * if YADIDA later adds support for using \DDD type escape sequences
                             * between string delimiters.
                             */

                            /// @note 20190917 edf -- while => do-while : I've kept the first if out of the loop to avoid needlessly
                            ///                       testing for the needle. (Which should be the most common case)

                            const char *prior_nonescape_character = string_end - 1;

                            do
                            {
                                if(parser->char_type[(u8)*prior_nonescape_character] != PARSER_CHAR_TYPE_ESCAPE_CHARACTER)
                                {
                                    break;
                                }
                            }
                            while(--prior_nonescape_character >= needle);
                            
                            // this one was escaped ...
                            if(((string_end - prior_nonescape_character) & 1) == 1)
                            {
                                break; /* String delimiter was not escaped if we got here. */
                            }

                            string_end++;
                            
                            // needle = string_end + 1 and try again ?
                            
                            if(string_end >= parser->limit)
                            {
                                return PARSER_EXPECTED_STRING_END_DELIMITER;
                            }
                            
                            needle = string_end;
                        }
                        else
                        {
                            // syntax error

                            return PARSER_EXPECTED_STRING_END_DELIMITER;
                        }
                    }

                    int token_len = string_end - string_start;

                    yassert(parser->escape_characters_count <= 1);
                    
                    for(u32 escape_index = 0; escape_index < parser->escape_characters_count; escape_index++)
                    {
                        ya_result err;
                        char escape_char = parser->escape_characters[escape_index];

                        if(FAIL(err = parser_clear_escape_codes(&string_start, &token_len, escape_char, parser->extra_buffer)))
                        {
                            return err;
                        }
                    }

                    parser->text = string_start;
                    parser->text_length = token_len;

                    parser->needle = string_end + 1;

                    // end of token ... return ?

                    return return_code | PARSER_WORD;
                }
                case PARSER_CHAR_TYPE_MULTILINE_DELIMITER:
                {
                    if(parser->multiline == 0)
                    {
                        parser->multiline = parser->delimiter_close[b];
                    }
                    else
                    {
                        return PARSER_SYNTAX_ERROR_MULTILINE;
                    }
                    *needle = ' ';
                    break;
                }
                case PARSER_CHAR_TYPE_EOL:
                {
                    // only tell we got an EOL if we are not on "multiline"

                    if(parser->multiline == 0)
                    {
                        parser->needle = parser->limit;
                        parser->text_length = 0;
                        parser->needle_mark = NULL;
                        return PARSER_EOL;
                    }

                    *needle = ' ';
                }
                FALLTHROUGH // fall through

                case PARSER_CHAR_TYPE_BLANK_MARKER:
                {
                    return_code |= PARSER_BLANK_START;
                    break;
                }
            }
        }

        // reached the end of line without a token : EOL
        // if we are not on a multiline: return EOL

        parser->needle = parser->limit;
        parser->text_length = 0;

        if(parser->multiline == 0)
        {

            return PARSER_EOL;
        }

        // else read the next line (loop)
    }
    
    // never reached
    
    // return 0;
}

void
parser_set_eol(parser_s *parser)
{
    parser->needle = (char*)&eol_park_needle[0];
    parser->limit = (char*)&eol_park_needle[1];
}

#if DNSCORE_HAS_FULL_ASCII7
void
parser_add_translation(parser_s *parser, u8 character, u8 translates_into)
{
    parser->translation_table[character] = translates_into;
    parser->char_type[character] = PARSER_CHAR_TYPE_TO_TRANSLATE;
}

void
parser_del_translation(parser_s *parser, u8 character)
{
    parser->char_type[character] = PARSER_CHAR_TYPE_NORMAL;
}
#endif

ya_result
parser_next_characters(parser_s *parser)
{
    parser->text = parser->needle;
    parser->text_length = parser->limit - parser->needle;

    if(parser->multiline != 0)
    {    
        u32 offset = parser->text_length;
        
        memcpy(parser->additional_buffer, parser->text, offset);
        parser->additional_buffer[offset++] = ' ';
        
        ya_result ret;
        do
        {
            ret = parser_next_token(parser);
            
            const char *text = parser_text(parser);
            size_t text_length = parser_text_length(parser);
            
            size_t new_length = offset + text_length + 1;
            if(new_length > sizeof(parser->additional_buffer))
            {
                return PARSER_SYNTAX_ERROR_LINE_TOO_BIG;
            }
            
            memcpy(&parser->additional_buffer[offset], text, text_length);
            offset = new_length;
            parser->additional_buffer[offset - 1] = ' ';
        }
        while((ret & (PARSER_EOF|PARSER_EOL)) == 0);
        
        parser->text = parser->additional_buffer;
        parser->text_length = offset - 1;
    }
    
    parser->needle = (char*)&eol_park_needle[0];
    parser->limit = (char*)&eol_park_needle[1];
        
    return parser->text_length;
}

ya_result
parser_next_characters_nospace(parser_s *parser)
{
    parser->text = parser->needle;
    parser->text_length = parser->limit - parser->needle;

    if(parser->multiline != 0)
    {    
        u32 offset = parser->text_length;
        
        memcpy(parser->additional_buffer, parser->text, offset);
        
        ya_result ret;
        do
        {
            ret = parser_next_token(parser);
            
            const char *text = parser_text(parser);
            size_t text_length = parser_text_length(parser);
            size_t new_length = offset + text_length;
            if(new_length > sizeof(parser->additional_buffer))
            {
                return PARSER_SYNTAX_ERROR_LINE_TOO_BIG;
            }
            
            memcpy(&parser->additional_buffer[offset], text, text_length);
            offset = new_length;
        }
        while((ret & (PARSER_EOF|PARSER_EOL)) == 0);
        
        parser->text = parser->additional_buffer;
        parser->text_length = offset;
    }
    
    char* text = parser->text;
    while(parser->char_type[(u8)*text] == PARSER_CHAR_TYPE_BLANK_MARKER)
    {
        text++;
    }
    parser->text_length -= text - parser->text;
    parser->text = text;
    
    parser->needle = (char*)&eol_park_needle[0];
    parser->limit = (char*)&eol_park_needle[1];
    
    return parser->text_length;
}


ya_result
parser_concat_next_tokens(parser_s *parser)
{
    ya_result ret;
    size_t offset = 0;

//    char space = parser->blank_marker[0];
    char space = ' ';
    do
    {
        ret = parser_next_token(parser);

        if(ret & PARSER_WORD)
        {
            //   if((ret & PARSER_COMMENT) != 0)
            //  {
            //     continue;
            //  }

            const char *text = parser_text(parser);
            size_t text_length = parser_text_length(parser);
            size_t new_length = offset + text_length;
            if(new_length > sizeof(parser->additional_buffer))
            {
                return PARSER_SYNTAX_ERROR_LINE_TOO_BIG;
            }

            memcpy(&parser->additional_buffer[offset], text, text_length); // VS false positive: overflow is chercked right before
            offset = new_length;

            parser->additional_buffer[offset] = space;
            offset++;
        }
    }
    while((ret & (PARSER_EOF|PARSER_EOL)) == 0);


    // remove the last space, because we always add a space
    offset--;

    
    char *text = parser->additional_buffer;

    parser->text_length = offset - (text - parser->additional_buffer);
    parser->text = text;
    parser->needle = (char*)&eol_park_needle[0];
    parser->limit = (char*)&eol_park_needle[1];
    
    return parser->text_length;
}

ya_result
parser_concat_current_and_next_tokens_nospace(parser_s *parser)
{
    ya_result ret;
    size_t offset;
    
    if(parser->text_length > sizeof(parser->additional_buffer))
    {
        return PARSER_SYNTAX_ERROR_LINE_TOO_BIG;
    }
    
    memcpy(&parser->additional_buffer[0], parser->text, parser->text_length);
    offset = parser->text_length;
    
    do
    {
        ret = parser_next_token(parser);
        
        if((ret & PARSER_COMMENT) != 0)
        {
            continue;
        }

        const char *text = parser_text(parser);
        size_t text_length = parser_text_length(parser);
        size_t new_length = offset + text_length;
        if(new_length > sizeof(parser->additional_buffer))
        {
            return PARSER_SYNTAX_ERROR_LINE_TOO_BIG;
        }

        memcpy(&parser->additional_buffer[offset], text, text_length);
        offset = new_length;
    }
    while((ret & (PARSER_EOF|PARSER_EOL)) == 0);
    
    char* text = parser->additional_buffer;
    while(parser->char_type[(u8)*text] == PARSER_CHAR_TYPE_BLANK_MARKER)
    {
        text++;
    }
    parser->text_length = offset - (text - parser->additional_buffer);
    parser->text = text;
    parser->needle = (char*)&eol_park_needle[0];
    parser->limit = (char*)&eol_park_needle[1];
    
    return parser->text_length;
}

ya_result
parser_concat_next_tokens_nospace(parser_s *parser)
{
    ya_result ret;
    size_t offset = 0;
    do
    {
        ret = parser_next_token(parser);
        
        if((ret & PARSER_COMMENT) != 0)
        {
            continue;
        }

        if((ret & PARSER_WORD) != 0)
        {
            const char *text = parser_text(parser);
            size_t text_length = parser_text_length(parser);
            size_t new_length = offset + text_length;
            if(new_length > sizeof(parser->additional_buffer))
            {
                return PARSER_SYNTAX_ERROR_LINE_TOO_BIG;
            }

            memcpy(&parser->additional_buffer[offset], text, text_length);
            offset = new_length;
        }
    }
    while((ret & (PARSER_EOF|PARSER_EOL)) == 0);
    
    char* text = parser->additional_buffer;
    while(parser->char_type[(u8)*text] == PARSER_CHAR_TYPE_BLANK_MARKER)
    {
        text++;
    }
    parser->text_length = offset - (text - parser->additional_buffer);
    parser->text = text;
    parser->needle = (char*)&eol_park_needle[0];
    parser->limit = (char*)&eol_park_needle[1];
    
    return parser->text_length;
}

ya_result
parser_push_stream(parser_s *p, input_stream *is)
{
    if(p->input_stream_stack_size < PARSER_INCLUDE_DEPTH_MAX )
    {
#if DO_BUFFERIZE
        buffer_input_stream_init(is, is, PARSER_STREAM_BUFFER_SIZE);
#endif  
        p->input_stream_stack[p->input_stream_stack_size] = is;
        p->line_number_stack[p->input_stream_stack_size] = p->line_number;
        
        ++p->input_stream_stack_size;
        
        return p->input_stream_stack_size;
    }
    
    return PARSER_INCLUDE_DEPTH_TOO_BIG;
}

/**
 * @param p
 * @return the popped stream or NULL if the stack is empty
 */

input_stream *
parser_pop_stream(parser_s *p)
{
    input_stream *is = NULL;
    
    if(p->input_stream_stack_size > 0)
    {
         is = p->input_stream_stack[--p->input_stream_stack_size];
#if DEBUG
         p->input_stream_stack[p->input_stream_stack_size] = NULL;
#endif
         p->line_number = p->line_number_stack[p->input_stream_stack_size];
    }
    
    return is;
}

///////////////////////////////////////////////////////////////////////////////

ya_result
parser_copy_next_ttl(parser_s *p, s32 *out_value)
{
    ya_result return_code = parser_next_word(p);
    
    if(ISOK(return_code))
    {
        const char *text = parser_text(p);
        u32 text_len = parser_text_length(p);
        
        char lc = text[text_len - 1];
        
        if(isdigit(lc))
        {
            return_code = parse_s32_check_range_len_base10(text, text_len, out_value, 0, MAX_S32);
        }
        else
        {
            s64 mult = 1;
            text_len--;
            
            switch(lc)
            {
                case 'w':
                case 'W':
                    mult = 60 * 60 * 24 * 7;
                    break;
                case 'd':
                case 'D':
                    mult = 60 * 60 * 24;
                    break;
                case 'h':
                case 'H':
                    mult = 60 * 60;
                    break;
                case 'm':
                case 'M':
                    mult = 60;
                    break;
                case 's':
                case 'S':
                    break;
                default:
                {
                    return PARSER_UNKNOWN_TIME_UNIT;
                }
            }
            
            s32 ttl32;
            
            if(ISOK(return_code = parse_s32_check_range_len_base10(text, text_len, &ttl32, 0, MAX_S32)))
            {
                mult *= ttl32;
                
                if(mult <= MAX_S32)
                {
                    *out_value = (s32)mult;
                }
                else
                {
                    return_code = PARSEINT_ERROR;
                }
            }
        }
    }
    
    return return_code;
}

ya_result
parser_type_bit_maps_initialise(parser_s *p, type_bit_maps_context* context)
{
    u16                                                                type;

    u8                      *type_bitmap_field = context->type_bitmap_field;
    u8                                  *window_size = context->window_size;

    u32                                              type_bit_maps_size = 0;
    u8                                                                   ws;

    /*    ------------------------------------------------------------    */

    ZEROMEMORY(window_size, sizeof(context->window_size));
    context->last_type_window = -1;
    ZEROMEMORY(type_bitmap_field, sizeof(context->type_bitmap_field));

    ya_result return_code;
    
    do
    {
        if(FAIL(return_code = parser_next_token(p)))
        {
            return return_code;
        }
        
        if((return_code & PARSER_WORD) != 0)
        {
            const char *text = parser_text(p);
            u32 text_len = parser_text_length(p);
            
            ya_result ret; // MUST use another return variable than return_code
            if(FAIL(ret = dns_type_from_case_name_length(text, text_len, &type)))
            {
                return ret;
            }

            type = ntohs(type); /* types are now stored in NETWORK order */

            /* Network bit order */
            type_bitmap_field[type >> 3] |= 1 << (7 - (type & 7));
            window_size[type >> 8] = ((type & 0xf8) >> 3) + 1;

            context->last_type_window = MAX(type >> 8, context->last_type_window);
        }
        
    }
    while((return_code & (PARSER_EOF|PARSER_EOL)) == 0);

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

ya_result
parser_get_network_protocol_from_next_word(parser_s *p, int *out_value)
{
    char protocol_token[64];
    
    ya_result ret = parser_copy_next_word(p, protocol_token, sizeof(protocol_token));
    
    if(ISOK(ret))
    {
        ret = protocol_name_to_id(protocol_token, out_value);
    }
    
    return ret;
}

ya_result
parser_get_network_service_port_from_next_word(parser_s *p, int *out_value)
{
    char service_token[64];
    
    ya_result ret = parser_copy_next_word(p, service_token, sizeof(service_token));
    
    if(ISOK(ret))
    {
        ret = server_name_to_port(service_token, out_value);
    }
    
    return ret;
}

/** @} */


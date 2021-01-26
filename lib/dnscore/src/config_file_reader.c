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

#define DO_PRINT 0

#include "dnscore/fdtools.h"
#include "dnscore/dnscore-config.h"
#include "dnscore/config_file_reader.h"
#include "dnscore/parser.h"
#include "dnscore/logger.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/typebitmap.h"
#include "dnscore/config_settings.h"
#include "dnscore/fdtools.h"

#define CONFIG_FILE_READER_INCLUDE_DEPTH_MAX 4

#define CFREADER_TAG 0x5245444145524641

extern logger_handle *g_zone_logger;
#define MODULE_MSG_HANDLE g_zone_logger

typedef struct config_file_reader config_file_reader;
struct config_file_reader
{
    parser_s parser;
    config_section_descriptor_s *section_descriptor;
    config_error_s *error_context;
    struct file_mtime_set_s *file_mtime_set;

    const char *container_name;
    size_t container_name_length;

    size_t key_length;
    size_t current_container_name_length;
    
    //u8 container_type;
    u8 includes_count;
    
    bool in_container;
    bool expected_container;

   /// char text_buffer[512];

    char key[256];
    char current_container_name[256];

    input_stream includes[CONFIG_FILE_READER_INCLUDE_DEPTH_MAX];
    char* file_name[CONFIG_FILE_READER_INCLUDE_DEPTH_MAX];
};

/**
 * Prepends the path of the base file to the file path
 * file_path should be in a buffer of at least PATH_MAX chars
 * 
 * @param file_path
 * @param base_file_path
 * @return 
 */

static ya_result
config_file_reader_prepend_path_from_file(char *file_path, const char *base_file_path)
{
    size_t n = 0;
    
    const char *file_name_last_slash = strrchr(base_file_path, '/');

    if(file_name_last_slash == NULL)
    {
        size_t m = strlen(file_path);
        return m;
    }
    else
    {
        ++file_name_last_slash;
    }

    n = file_name_last_slash - base_file_path;

    if(n >= PATH_MAX)
    {
        return CONFIG_FILE_PATH_TOO_BIG;
    }
    
    size_t m = strlen(file_path);
    
    if(n + m + 1 >= PATH_MAX)
    {
        return CONFIG_FILE_PATH_TOO_BIG;
    }

    memmove(&file_path[n], file_path, m + 1);
    memcpy(file_path, base_file_path, n);
    
    return n + m;
}


/**
 * 
 * Parses a configuration
 * 
 * @param cfr
 * @return 
 */

static ya_result
config_file_reader_read(config_file_reader *cfr, config_error_s *cfgerr) /// config_reader
{
    parser_s *p = &cfr->parser;
    ya_result return_code;
    int token_count = 0;
    for(;;)
    {
        // get the next token
        
        if(ISOK(return_code = parser_next_token(p)))
        {
            if((token_count & 255) == 0) // force early stop for cases with huge configurations/includes
            {
                if(dnscore_shuttingdown())
                {
                    return_code = PARSER_EOF;
                }
            }
            
            ++token_count;
            
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
                    // EOF: close the stream and pop the next one if available
                    // else just finish parsing
                    
                    --cfr->includes_count;

                    free(cfr->file_name[cfr->includes_count]);
                    
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

                continue;
            }

            p->needle_mark = p->text;

            // keywords

            u32 text_len = parser_text_length(p);
            const char *text = parser_text(p);

#if DO_PRINT
            formatln("[%i]'%s'", text_len, text);
#endif
            
            if(text_len > 0)
            {
                /// test of container
                
                if(text[0] == '<')
                {
                    if(text[text_len - 1] != '>')
                    {
                        return_code = CONFIG_PARSE_SECTION_TAG_NOT_CLOSED;

                        return return_code;
                    }

                    /// if there are enough characters
                    if(text_len > 3)
                    {
                        // if it's beginning of a container 
                        if(text[1] != '/')
                        {
                            // if already in a container
                            if(cfr->in_container)
                            {
                                // this is bad
                                return_code = CONFIG_PARSE_UNEXPECTED_SECTION_OPEN;

                                return return_code;
                            }

                            // if tag is the correct one
                            if((cfr->container_name_length == text_len - 2) && (memcmp(&text[1], cfr->container_name, cfr->container_name_length) == 0))
                            {
#if DO_PRINT
                                print("(EXPECTED)");
                                output_stream_write(termout, (const u8*)cfr->container_name, cfr->container_name_length);
#endif
                                // the container is the one we expected
                                // use the callback telling the container is starting
                                
                                cfr->section_descriptor->vtbl->start(cfr->section_descriptor);
                                
                                cfr->expected_container = TRUE;
                            }

                            memcpy(cfr->current_container_name, &text[1], text_len - 2); // copy between < > 
                            cfr->current_container_name_length = text_len - 2;
#if DO_PRINT
                            print("(CONTAINER)");
                            output_stream_write(termout, (const u8*)cfr->current_container_name, cfr->current_container_name_length);
#endif
                            // mark the container as OPEN
                            cfr->in_container = TRUE;

                            continue;
                        }
                        else // if it's end of a container 
                        {
                            // if not in container
                            if(!cfr->in_container)
                            {
                                // this is bad
                                return_code = CONFIG_PARSE_UNEXPECTED_SECTION_CLOSE;

                                return return_code;
                            }

                            // 
                            if((cfr->current_container_name_length == text_len - 3) && (memcmp(&text[2], cfr->current_container_name, cfr->current_container_name_length) == 0))
                            {
                                if(cfr->expected_container)
                                {
                                    // we are closing the container
                                    // if the current source level is below the set autodefault
                                    
                                    if(config_get_autodefault_after_source() <= config_get_source())
                                    {
                                        // save the current source
                                        
                                        u8 level = config_get_source();
                                        
                                        // set the source level to default
                                            
                                        config_set_source(config_get_default_source());

                                        // apply the default values
                                        
                                        if(FAIL(return_code = config_set_section_default(cfr->section_descriptor, cfr->error_context)))
                                        {
                                            return return_code;
                                        }
                                        
                                        // restore the source level
                                        
                                        config_set_source(level);
                                    }
                                    
                                    // use the callback telling the section/container is closed
                                    
                                    if(FAIL(return_code = cfr->section_descriptor->vtbl->stop(cfr->section_descriptor)))
                                    {
                                        return return_code;
                                    }
                                }
#if DO_PRINT
                                print("(container)");
                                if(cfr->expected_container)
                                {
                                    print("(expected)");
                                }
#endif
                                cfr->in_container = FALSE;
                                cfr->expected_container = FALSE;

                                continue;
                            }
                            else
                            {
                                // this is bad
                                return_code = CONFIG_PARSE_CLOSED_WRONG_SECTION;

                                return return_code;
                            }

                        }

                    }
                    else
                    {
                        // this is bad
                        return_code = CONFIG_PARSE_SECTION_TAG_TOO_SMALL;

                        return return_code;

                    }
                }
                else // the first char is not '<' : it's not a container tag
                {
                    // if we are not in a container
                    
                    if(!cfr->in_container)
                    {
                        // keyword match : include file ?
                        
                        if(parse_word_match(text, text_len, "include", 7))
                        {
                            char file_name[PATH_MAX];
                            
                            if(FAIL(return_code = parser_copy_next_word(p, file_name, sizeof(file_name))))
                            {
                                if(return_code != PARSER_BUFFER_TOO_SMALL)
                                {
                                    return_code = CONFIG_PARSE_INCLUDE_EXPECTED_FILE_PATH;
                                }
                                else
                                {
                                    return_code = CONFIG_FILE_PATH_TOO_BIG;
                                }
                                
                                return return_code;
                            }
                            
                            // return_code is the length of the path
                            
                            if(file_name[0] != '/')
                            {
                                // relative path
                                
                                if(FAIL(return_code = config_file_reader_prepend_path_from_file(file_name, cfr->file_name[cfr->includes_count - 1])))
                                {
                                    return return_code;
                                }
                            }

                            if(return_code > 0)
                            {
                                ya_result err;

                                if(ISOK(err = file_input_stream_open(&cfr->includes[cfr->includes_count], file_name)))
                                {
                                    // add the file and its mtime to the context

                                    if(cfr->file_mtime_set != NULL)
                                    {
                                        file_mtime_set_add_file(cfr->file_mtime_set, file_name);
                                    }

                                    parser_push_stream(&cfr->parser, &cfr->includes[cfr->includes_count]);
                                    cfr->file_name[cfr->includes_count] = strdup(file_name);

                                    ++cfr->includes_count;
                                    
                                    token_count = 0;
                                }
                                else
                                {
                                    if((err == MAKE_ERRNO_ERROR(ENOENT)) || (err == MAKE_ERRNO_ERROR(EACCES)))
                                    {
                                        err = CANNOT_OPEN_FILE;
                                    }
                                    return err;
                                }
                            }
                            else
                            {
                                return_code = CONFIG_PARSE_INCLUDE_EXPECTED_FILE_PATH;
                                return return_code;
                            }
                        }
                        else // incorrect keyword
                        {
                            return_code = CONFIG_PARSE_UNKNOWN_KEYWORD;

                            return return_code;
                        }
                    }
                    else // in container
                    if(cfr->expected_container)
                    {
                        // we are in a container : the current token is the key
                        
                        memcpy(cfr->key, text, text_len);

                        cfr->key_length = text_len;
                        cfr->key[text_len] = '\0';
                        
                        // concat the remainder of the line for the value

                        if(FAIL(return_code = parser_concat_next_tokens(p)))
                        {
                            return_code = CONFIG_PARSE_EXPECTED_VALUE;

                            return return_code;
                        }
                        
                        // get the concatenated text

                        text = parser_text(p);
#if DO_PRINT
                        text_len = parser_text_length(p);
#else
                        parser_text_length(p);
#endif
                        // cut the text as asciiz (state can be restored)
                        parser_text_asciiz(p);
#if DO_PRINT
                        print("[KEY]");
                        output_stream_write(termout, (const u8*)cfr->key, cfr->key_length);
                        print("[VALUE]");
                        output_stream_write(termout, (const u8*)text, text_len);
                        println("[EOL]");
#endif
                        // using the descriptor table : set the value in the target struct
                        
                        return_code = config_value_set(cfr->section_descriptor, cfr->key, text, cfgerr);

                        // restore the character cut of
                        
                        parser_text_unasciiz(p);
                        
                        if(FAIL(return_code))
                        {
                            return return_code;
                        }
                    }
                }
            }
            else
            {
                // empty line
            }


#if DO_PRINT
            flushout();
#endif
        }
        else
        {
            formatln("[ERROR %r]", return_code);
            flushout();
            break;
        } 
    } // for(;;)

    return return_code;
}

/**
 * 
 * Parses an input stream for a section/container defined by its config sectiondescriptor.
 * 
 * @param stream_name a name to identify the stream in case of error
 * @param ins the input stream to parse
 * @param csd the descriptor of the section to parse
 * @param cfgerr if not NULL, the error reporting structure to fill in case of error
 * 
 * @return an error code
 */

ya_result
config_file_reader_parse_stream(const char* stream_name, input_stream *ins, config_section_descriptor_s *csd, config_error_s *cfgerr)
{
    config_file_reader *cfr; /// remove
    ya_result return_code;

    file_mtime_set_t *file_mtime_set = file_mtime_set_get_for_file(stream_name);

    // allocates and initialises a config file reader structure
    
    MALLOC_OBJECT_OR_DIE(cfr, config_file_reader, CFREADER_TAG);
    ZEROMEMORY(cfr, sizeof(config_file_reader));

    config_error_reset(cfgerr);
    cfr->error_context = cfgerr;
    cfr->file_mtime_set = file_mtime_set;

    // initalises a parser

    const char *string_delimiters = "\"\"''";
    const char *multiline_delimiters = "()";
    const char *comment_markers = "#";
    const char *blank_makers = "\040\t\r";
    const char *escape_characters = "";

    if(ISOK(return_code = parser_init(&cfr->parser,
        string_delimiters,      // by 2
        multiline_delimiters,   // by 2
        comment_markers,        // by 1
        blank_makers,           // by 1
        escape_characters)))    // by 1
    {
        // the parser is initalised : push the stream to parse to it
        
        parser_push_stream(&cfr->parser, ins);
        
        if(stream_name == NULL)
        {
            // if the stream is anonymous, give it a name.
            
            stream_name = "?";
        }
        
        cfr->file_name[cfr->includes_count] = strdup(stream_name);
        ++cfr->includes_count;

        cfr->container_name = csd->vtbl->name;
        cfr->container_name_length = strlen(cfr->container_name);
        
        // the csd describes the section we want to parse
        
        cfr->section_descriptor = csd;
       
        // the config file reader structure is now ready : parse the stream
        // parsing will setup fields described by the config section descriptor
        
        if(FAIL(return_code = config_file_reader_read(cfr, cfgerr)))
        {
            // failure: if the error reporting is set then use it
#if 1
            if((cfgerr != NULL) && (cfr->includes_count > 0) && !cfgerr->has_content)
            {
                const char *file_name = cfr->file_name[cfr->includes_count - 1];

                if(file_name == NULL)
                {
                    file_name = "?";
                }
                
                strcpy_ex(cfgerr->file, file_name, sizeof(cfgerr->file));
                
                size_t len = MIN(strlen(cfr->parser.line_buffer), sizeof(cfgerr->line) - 1);
                memcpy(cfgerr->line, cfr->parser.line_buffer, len);
                if(cfgerr->line[len - 1] == '\n')
                {
                    cfgerr->line[len - 1] = '\0';
                }
                
                cfgerr->line_number = parser_get_line_number(&cfr->parser);
                cfgerr->has_content = TRUE;
            }
#endif
        }
       
       // ends parsing, this also closes the input stream pushed to the parser
               
        parser_finalize(&cfr->parser);
    }

#if DEBUG
    memset(cfr, 0xfe, sizeof(config_file_reader));
#endif
    
    free(cfr);

    return return_code;
}

/**
 * 
 * Parses a file for a section/container defined by its config sectiondescriptor.
 * 
 * @param fullpath the file path
 * @param csd the descriptor of the section to parse
 * @param cfgerr if not NULL, the error reporting structure to fill in case of error
 * 
 * @return an error code
 */

ya_result
config_file_reader_open(const char* fullpath, config_section_descriptor_s *csd, config_error_s *cfgerr)
{
    input_stream ins;
    ya_result return_value;
    
    if(FAIL(return_value = file_input_stream_open(&ins, fullpath)))
    {
        return return_value;
    }

    // add the file and its mtime to the context

#if (DNSDB_USE_POSIX_ADVISE != 0) && (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L) && !defined(__gnu__hurd__)
    int fd = fd_input_stream_get_filedescriptor(&ins);
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
    
    return_value = config_file_reader_parse_stream(fullpath, &ins, csd, cfgerr);
    
    return return_value;
}

/** @} */


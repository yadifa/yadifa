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

#include <dnscore/cmdline.h>
#include "dnscore/dnscore-config.h"
#include "dnscore/bytearray_input_stream.h"
#include "dnscore/bytearray_output_stream.h"
#include "dnscore/ptr_set.h"
#include "dnscore/format.h"

#include "dnscore/cmdline.h"

#define CMDLOSAP_TAG 0x5041534f4c444d43

static ptr_set g_cmdline_sections = PTR_SET_ASCIIZ_EMPTY;
static bool cmdline_init_error_codes_done = FALSE;

/*
#if 0
v = value;
t = translate;

ya_result
cmdline_tsigkey_translate(output_stream *os, const char *text, const char *section_name)
{


}
CMDLINE(0, "main");
    v, 'd', "daemon",     "on" ,  "daemon"   /// (on/off)
CMDLINE(0, "zone");
    v,  0,  "nodaemon",   "off" , "daemon" /// (on/off)
CMDLINE(0, "main");
    v, 't', "thread-count, NULL , "thread-count"
{0, "key"}
{t, "key", 'y', cmdline_tsigkey_translate}


daemon || d    ===  on /off;
i
thread-count || t , "10"
#endif
*/

ya_result
cmdline_process_argument(const cmdline_desc_s *desc, const char *section_name, const char *arg)
{
    ya_result return_code; 

    if((desc->flags & CMDLINE_FLAG_ARGUMENTS) && (arg == NULL))
    {
        return CMDLINE_OPT_EXPECTS_ARGUMENT;
    }

    ptr_node *node;

    node = ptr_set_insert(&g_cmdline_sections, (char*)section_name);

    output_stream *os; 

    if(node->value == NULL)
    {
        MALLOC_OBJECT_OR_DIE(os, output_stream, CMDLOSAP_TAG);
        bytearray_output_stream_init(os, NULL, 0);

        osformatln(os, "<%s>", section_name);

        node->value = os;
    }

    os = (output_stream *)node->value;

    switch(desc->flags)
    {
        case CMDLINE_FLAG_SECTION:    

            return_code = CMDLINE_PROCESSING_SECTION_AS_ARGUMENT;

            break;
        case CMDLINE_FLAG_ALIAS:
            osformatln(os, "%s \"%s\"", desc->target.alias, desc->value);

            return_code = 0;

            break;
        case CMDLINE_FLAG_TRANSLATOR:
            return_code = desc->target.translator(desc, os, section_name, desc->value);

            if(return_code >= 0)
            {
                return_code = 0;
            }

            break;
        case CMDLINE_FLAG_ALIAS | CMDLINE_FLAG_ARGUMENTS:
            osformatln(os, "%s \"%s\"", desc->target.alias, arg);

            return_code = 1;

            break;
        case CMDLINE_FLAG_TRANSLATOR | CMDLINE_FLAG_ARGUMENTS:
            return_code = desc->target.translator(desc, os, section_name, arg);

            break;
        default:
            // ignore
            return_code = 0;
            break;
    }

    return return_code;
}


ya_result 
cmdline_get_opt_long(const cmdline_desc_s *table, const char *name, const char *arg)
{
    ya_result return_code = CMDLINE_LONG_OPT_UNDEFINED;
    int i;
    bool internal_arg = FALSE;
    
    char clean_name[128];
    
    for(i = 0; name[i] != '\0'; i++)
    {
        if(name[i] != '=')
        {
            clean_name[i] = name[i];
        }
        else
        {
            arg = &name[i + 1];

            internal_arg = TRUE;
            
            break;
        }
    }
    clean_name[i] = '\0';

    const char *section_name = "";

    for(const cmdline_desc_s *desc = table; cmdline_desc_not_end(desc); desc++)
    {
        if(desc->flags == CMDLINE_FLAG_SECTION)
        {
            section_name = desc->name;

            continue;
        }

        if((desc->name != NULL) && (strcmp(clean_name, desc->name) == 0))
        {
            if(ISOK(return_code = cmdline_process_argument(desc, section_name, arg)))
            {
                if(internal_arg)
                {
                    return_code = 0;
                }
            }

            if((desc->flags & CMDLINE_FLAG_OBFUSCATE) != 0)
            {
                if(arg != NULL)
                {
                    for(char *p = (char*)arg; *p != '\0'; ++p)
                    {
                        *p = '\t';
                    }
                }
            }

            break;
        }
    }

   return return_code;
}

ya_result
cmdline_get_opt_short(const cmdline_desc_s *table, const char *name, const char *arg)
{
    ya_result return_code = CMDLINE_SHORT_OPT_UNDEFINED;
    const char *section_name = "";

    while(*name != '\0')
    {
        for(const cmdline_desc_s *desc = table; cmdline_desc_not_end(desc); desc++)
        {
            if(desc->flags == CMDLINE_FLAG_SECTION)
            {
                section_name = desc->name;

                continue;
            }

            if(*name == desc->letter)
            {
                if(desc->flags & CMDLINE_FLAG_ARGUMENTS)
                {
                    if(name[1] != '\0')
                    {
                        arg = &name[1];
                    }

                    return_code = cmdline_process_argument(desc, section_name, arg);

                    if(arg != NULL)
                    {
                        if((desc->flags & CMDLINE_FLAG_OBFUSCATE) != 0)
                        {
                            for(char *p = (char*)arg; *p != '\0'; ++p)
                            {
                                *p = '\t';
                            }
                        }
                    }

                    return return_code;
                }
                else
                {
                    return_code = cmdline_process_argument(desc, section_name, arg);

                    if(arg != NULL)
                    {
                        if((desc->flags & CMDLINE_FLAG_OBFUSCATE) != 0)
                        {
                            for(char *p = (char*)arg; *p != '\0'; ++p)
                            {
                                *p = '\t';
                            }
                        }
                    }

                    break;
                }
            }
        }
        name++;
    }

   return return_code;

}

ya_result
cmdline_parse(const cmdline_desc_s *table, int argc, char **argv, cmdline_filter_callback *filter, void *filter_arg, input_stream *is, int *argc_errorp)
{
    if((table == NULL) || (argv == NULL) || (is == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(argc_errorp != NULL)
    {
        *argc_errorp = -1;
    }

    // ensures the IS is unusable if something goes wrong here
    input_stream_set_void(is);

    // check if the first line after "CMDLINE_BEGIN" sets the filter

    if((table->flags & CMDLINE_FLAG_FILTER_SET) != 0)
    {
        // override the filter
        filter = table->target.filter;
        filter_arg = CMDLINE_CALLBACK_ARG_GET(table);
    }
            
    for(int i = 1; i < argc; i++)
    {
        char *arg = argv[i];
        int arg_len = strlen(arg);
        ya_result return_code;
        
        if((arg[0] == '-') && (arg_len > 1))
        {
            // fetch next val
            
            const char *val = NULL;
            
            if(i < argc - 1)
            {
                val = argv[i + 1];
                
                if(val[0] == '-')
                {
                    val = NULL;
                }
            }
            
            // check opt(long/short) or add

            if(arg[1] != '-')
            {
                // short argument
                
                if(FAIL(return_code = cmdline_get_opt_short(table, &arg[1], val)))
                {
                    if(argc_errorp != NULL)
                    {
                        *argc_errorp = i;
                    }
                    return return_code;
                }
                
                i += return_code;
                
                continue;
            }
            else
            {
                // long argument
                
                if(arg_len > 2)
                {
                    if(FAIL(return_code = cmdline_get_opt_long(table, &arg[2], val)))
                    {
                        if(argc_errorp != NULL)
                        {
                            *argc_errorp = i;
                        }
                        return return_code;
                    }
                    
                    i += return_code;
                    
                    continue;
                }
                else // == 2
                {
                    // case of "--"
                    
                    // fall outside of the if
                }
            }
        }
        
        if(filter != NULL)
        {
            return_code = filter(table, arg, filter_arg);

            switch(return_code)
            {
                case CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS:
                {
                    for(++i;i < argc;i++)
                    {
                        char *arg_i = argv[i];

                        if(FAIL(return_code = filter(table, arg_i, filter_arg)))
                        {
                            break;
                        }
                    }
                    break;
                }
                default:
                    break;
            }

            if(FAIL(return_code))
            {
                if(argc_errorp != NULL)
                {
                    *argc_errorp = i;
                }
                return return_code;
            }
        }
    } // for

    /// 
    output_stream complete_config_os;
    bytearray_output_stream_init(&complete_config_os, NULL, 0);

    ptr_set_iterator iter;
    ptr_set_iterator_init(&g_cmdline_sections, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        output_stream *os = (output_stream *)node->value;
        const char *section_name = (const char *)node->key;

        osformatln(os, "</%s>", section_name);

        u32 buffer_size = bytearray_output_stream_size(os);
        const u8 *buffer = bytearray_output_stream_buffer(os);

        output_stream_write(&complete_config_os, buffer, buffer_size);
        output_stream_close(os); // VS false positive: 'os' cannot be NULL or the node would not exist
        free(node->value);
        node->value = NULL;
    }

    ptr_set_destroy(&g_cmdline_sections);

    u32 buffer_size = bytearray_output_stream_size(&complete_config_os);
    u8 *buffer      = bytearray_output_stream_detach(&complete_config_os);
    
    output_stream_close(&complete_config_os);

    bytearray_input_stream_init(is, buffer, buffer_size, TRUE);

    return buffer_size;
}

void
cmdline_init_error_codes()
{
    if(cmdline_init_error_codes_done)
    {
        return;
    }
    
    cmdline_init_error_codes_done = TRUE;
    
    error_register(CMDLINE_PROCESSING_SECTION_AS_ARGUMENT, "CMDLINE_PROCESSING_SECTION_AS_ARGUMENT");
    error_register(CMDLINE_PROCESSING_INVALID_DESCRIPTOR, "CMDLINE_PROCESSING_INVALID_DESCRIPTOR");
    error_register(CMDLINE_LONG_OPT_UNDEFINED, "CMDLINE_LONG_OPT_UNDEFINED");
    error_register(CMDLINE_SHORT_OPT_UNDEFINED, "CMDLINE_SHORT_OPT_UNDEFINED");
    error_register(CMDLINE_OPT_EXPECTS_ARGUMENT, "CMDLINE_OPT_EXPECTS_ARGUMENT");
}

ya_result
cmdline_print_help(const cmdline_desc_s *table, int arg_column_prefix, int arg_width, const char *column_separator, int text_width, output_stream *os)
{
    const cmdline_desc_s *p = NULL;
    const cmdline_desc_s *t = table;
    while(cmdline_desc_not_end(t))
    {
        if((t->flags & CMDLINE_FLAG_HELP_LINE) && (p != NULL))
        {
            osprint_char_times(os, ' ', arg_column_prefix);

            int width = 0;

            if(p->letter != '\0')
            {
                width += output_stream_write_u8(os, '-');
                width += output_stream_write_u8(os, (u8)p->letter);
                if(p->name != NULL)
                {
                    width += output_stream_write(os, ", ", 2);
                }
            }
            if(p->name != NULL)
            {
                width += output_stream_write(os, "--", 2);
                width += osprint(os, p->name);

                if((t->name != NULL) && (t->name[0] != '\0'))
                {
                    width += output_stream_write_u8(os, ' ');
                    width += osprint(os, t->name);
                }
            }

            osprint_char_times(os, ' ', arg_width - width);

            osprint(os, column_separator);

            int help_len = (int)strlen(t->value);

            if(help_len < text_width)
            {
                osprint(os, t->value);
            }
            else
            {
#if DEBUG
#pragma message("TODO: (COSMETIC) cut the t->value text word by word and wrap to the next line when needed")
#endif
                osprint(os, t->value);
            }

            output_stream_write_u8(os, '\n');
        }
        else if(t->flags & CMDLINE_FLAG_HELP_MESSAGE)
        {
            if(t->flags & CMDLINE_FLAG_INDENTED)
            {
                osprint_char_times(os, ' ', arg_column_prefix);
            }
            int width = osprint(os, t->name);
            osprint_char_times(os, ' ', arg_width - width);
            if(t->letter != 0)
            {
                output_stream_write_u8(os, t->letter);
            }
            if(t->flags & CMDLINE_FLAG_SEPARATOR)
            {
                osprint(os, column_separator);
            }
            osprint(os, t->value);
            output_stream_write_u8(os, '\n');
        }
        else if(t->flags & CMDLINE_FLAG_HELP_CALLBACK)
        {
            t->target.printer(t, os);
            output_stream_write_u8(os, '\n');
        }
        else if(t->flags == CMDLINE_FLAG_INDENTED)
        {
            arg_column_prefix = MAX(arg_column_prefix + t->target.integer_value, 0);
        }
        p = t;
        ++t;
    }

    return SUCCESS;
}

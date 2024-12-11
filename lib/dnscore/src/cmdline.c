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

#include <sys/ioctl.h>
#include <stdio.h>

#include "dnscore/cmdline.h"
#include "dnscore/dnscore_config.h"
#include "dnscore/bytearray_input_stream.h"
#include "dnscore/bytearray_output_stream.h"
#include "dnscore/ptr_treemap.h"
#include "dnscore/format.h"

#include "dnscore/cmdline.h"
#include "dnscore/mutex.h"

#define CMDLOSAP_TAG         0x5041534f4c444d43

#define TEXT_COLUMNS_DEFAULT 80

static ptr_treemap_t       g_cmdline_sections = PTR_TREEMAP_ASCIIZ_EMPTY;
static initialiser_state_t cmdline_error_codes_init_state = INITIALISE_STATE_INIT;

/*
#if 0
v = value;
t = translate;

ya_result
cmdline_tsigkey_translate(output_stream_t *os, const char *text, const char *section_name)
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

ya_result cmdline_process_argument(const cmdline_desc_t *desc, const char *section_name, const char *arg)
{
    ya_result return_code;

    if((desc->flags & CMDLINE_FLAG_ARGUMENTS) && (arg == NULL))
    {
        return CMDLINE_OPT_EXPECTS_ARGUMENT;
    }

    ptr_treemap_node_t *node;

    node = ptr_treemap_insert(&g_cmdline_sections, (char *)section_name);

    output_stream_t *os;

    if(node->value == NULL)
    {
        MALLOC_OBJECT_OR_DIE(os, output_stream_t, CMDLOSAP_TAG);
        bytearray_output_stream_init(os, NULL, 0);

        osformatln(os, "<%s>", section_name);

        node->value = os;
    }

    os = (output_stream_t *)node->value;

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

ya_result cmdline_get_opt_long(const cmdline_desc_t *table, const char *name, const char *arg)
{
    ya_result return_code = CMDLINE_LONG_OPT_UNDEFINED;
    int       i;
    bool      internal_arg = false;

    char      clean_name[128];

    for(i = 0; name[i] != '\0'; i++)
    {
        if(name[i] != '=')
        {
            clean_name[i] = name[i];
        }
        else
        {
            arg = &name[i + 1];

            internal_arg = true;

            break;
        }
    }
    clean_name[i] = '\0';

    const char *section_name = "";

    for(const cmdline_desc_t *desc = table; cmdline_desc_not_end(desc); desc++)
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
                    for(char *p = (char *)arg; *p != '\0'; ++p)
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

/**
 * Returns 1 if the argument has been eaten, 0 if not.
 */

ya_result cmdline_get_opt_short(const cmdline_desc_t *table, const char *name, const char *arg)
{
    ya_result   return_code = CMDLINE_SHORT_OPT_UNDEFINED;
    const char *section_name = "";

    while(*name != '\0')
    {
        for(const cmdline_desc_t *desc = table; cmdline_desc_not_end(desc); desc++)
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
                            for(char *p = (char *)arg; *p != '\0'; ++p)
                            {
                                *p = '\t';
                            }
                        }
                    }
                    /*
                    if(ISOK(return_code))
                    {
                        return_code = desc->flags & CMDLINE_FLAG_ARGUMENTS;
                    }
                    */
                    return return_code;
                }
                else
                {
                    return_code = cmdline_process_argument(desc, section_name, arg);

                    if(arg != NULL)
                    {
                        if((desc->flags & CMDLINE_FLAG_OBFUSCATE) != 0)
                        {
                            for(char *p = (char *)arg; *p != '\0'; ++p)
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

/**
 * Parses a command line and returns an input stream ready to be parsed by a configuration reader.
 *
 * The function works by generating a configuration file in a stream using the command line table as a map.
 * The table is used to check for the existence of the options
 *
 * @param table the name of a table defined using CMDLINE_BEGIN
 * @param argc the argc of main()
 * @param argv the argv of main()
 * @param filter a callback function that will be called for unhandled command line parameters (file names, "--", ...)
 * @param filter_arg a pointer given to the filter callback
 * @param is the input stream to initialise with the command line
 * @return an error code
 */

ya_result cmdline_parse(const cmdline_desc_t *table, int argc, char **argv, cmdline_filter_callback *filter, void *filter_arg, input_stream_t *is, int *argc_errorp)
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

    for(int_fast32_t i = 1; i < argc; i++)
    {
        char     *arg = argv[i];
        int       arg_len = strlen(arg);
        ya_result return_code;

        if((arg[0] == '-') && (arg_len > 1))
        {
            // fetch next val

            const char *val = NULL;

            if(i < argc - 1)
            {
                val = argv[i + 1];
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
                    for(++i; i < argc; i++)
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
    output_stream_t complete_config_os;
    bytearray_output_stream_init(&complete_config_os, NULL, 0);

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&g_cmdline_sections, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
        output_stream_t    *os = (output_stream_t *)node->value;
        const char         *section_name = (const char *)node->key;

        osformatln(os, "</%s>", section_name);

        uint32_t       buffer_size = bytearray_output_stream_size(os);
        const uint8_t *buffer = bytearray_output_stream_buffer(os);

        output_stream_write(&complete_config_os, buffer, buffer_size);
        output_stream_close(os); // VS false positive: 'os' cannot be NULL or the node would not exist
        free(node->value);
        node->value = NULL;
    }

    ptr_treemap_finalise(&g_cmdline_sections);

    uint32_t buffer_size = bytearray_output_stream_size(&complete_config_os);
    uint8_t *buffer = bytearray_output_stream_detach(&complete_config_os);

    output_stream_close(&complete_config_os);

    bytearray_input_stream_init(is, buffer, buffer_size, true);

    return buffer_size;
}

void cmdline_init_error_codes()
{
    if(initialise_state_begin(&cmdline_error_codes_init_state))
    {
        error_register(CMDLINE_PROCESSING_SECTION_AS_ARGUMENT, "CMDLINE_PROCESSING_SECTION_AS_ARGUMENT");
        error_register(CMDLINE_PROCESSING_INVALID_DESCRIPTOR, "CMDLINE_PROCESSING_INVALID_DESCRIPTOR");
        error_register(CMDLINE_LONG_OPT_UNDEFINED, "CMDLINE_LONG_OPT_UNDEFINED");
        error_register(CMDLINE_SHORT_OPT_UNDEFINED, "CMDLINE_SHORT_OPT_UNDEFINED");
        error_register(CMDLINE_OPT_EXPECTS_ARGUMENT, "CMDLINE_OPT_EXPECTS_ARGUMENT");

        initialise_state_ready(&cmdline_error_codes_init_state);
    }
}

/**
 * Prints the embedded help in the cmdline table.
 *
 * @param table the cmdline table
 * @param arg_column_prefix the number of spaces to put before printing the first '-' of a parameter
 * @param arg_width the space to reserve for parameters (width that column). A negative value = automatic fit.
 * @param column_separator what to print between the parameters and the explanation
 * @param text_width to wrap text (0 means detect columns)
 * @param os the stream where to print the table (e.g. termout)
 *
 */

ya_result cmdline_print_help_ex(const cmdline_desc_t *table, int arg_column_prefix, int arg_width, const char *column_separator, int text_width, output_stream_t *os)
{
    if(text_width == 0)
    {
#ifdef TIOCGWINSZ
        struct winsize w;
        ioctl(0, TIOCGWINSZ, &w);
        text_width = w.ws_col;
        if(text_width <= 0)
        {
            text_width = TEXT_COLUMNS_DEFAULT;
        }
#else
        text_width = TEXT_COLUMNS_DEFAULT;
#endif
    }

    if(arg_width < 0)
    {
        int                   computed_width_max = 0;
        const cmdline_desc_t *p = NULL;
        const cmdline_desc_t *t = table;
        while(cmdline_desc_not_end(t))
        {
            int computed_width = 0;
            if((t->flags & CMDLINE_FLAG_HELP_LINE) && (p != NULL))
            {
                if(p->letter != '\0')
                {
                    computed_width += 2;
                    if(p->name != NULL)
                    {
                        computed_width++;
                    }
                }
                if(p->name != NULL)
                {
                    computed_width += 2 + strlen(p->name);

                    if((t->name != NULL) && (t->name[0] != '\0'))
                    {
                        computed_width += 1 + strlen(t->name);
                    }
                }
                if(computed_width > computed_width_max)
                {
                    computed_width_max = computed_width;
                }
            }
            p = t;
            ++t;
        }
        arg_width = computed_width_max + 1;
    }

    const cmdline_desc_t *p = NULL;
    const cmdline_desc_t *t = table;
    size_t                column_separator_len = strlen(column_separator);
    size_t                text_first_column = arg_column_prefix + arg_width + column_separator_len;
    size_t                text_space = text_width - text_first_column; // if the text_width is too low, the unsigned arithmetic will
                                                                       // fix it automatically by not wrapping at all
    while(cmdline_desc_not_end(t))
    {
        if((t->flags & CMDLINE_FLAG_HELP_LINE) && (p != NULL))
        {
            osprint_char_times(os, ' ', arg_column_prefix);

            int width = 0;

            if(p->letter != '\0')
            {
                width += output_stream_write_u8(os, '-');
                width += output_stream_write_u8(os, (uint8_t)p->letter);
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

            size_t help_len = strlen(t->value);

            if(help_len <= text_space)
            {
                osprint(os, t->value);
            }
            else
            {
                osprint_wrapped(os, t->value, text_first_column, text_width, text_first_column);
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
            text_first_column = arg_column_prefix + arg_width + column_separator_len;
            text_space = text_width - text_first_column; // if the text_width is too
        }
        p = t;
        ++t;
    }

    return SUCCESS;
}

/**
 * Prints the embedded help in the cmdline table.
 *
 * = cmdline_print_help_ex(table, 4, -1, " :  ", text_width, os);
 *
 */

ya_result cmdline_print_help(const cmdline_desc_t *table, output_stream_t *os)
{
    ya_result ret = cmdline_print_help_ex(table, 4, -1, " :  ", 0, os);
    return ret;
}

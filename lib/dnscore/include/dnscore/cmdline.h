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

#pragma once

#include <dnscore/input_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/output_stream.h>

#define CMDLINE_FLAG_SECTION      0
#define CMDLINE_FLAG_ALIAS        1
#define CMDLINE_FLAG_TRANSLATOR   2
#define CMDLINE_FLAG_TERMINATOR   4
#define CMDLINE_FLAG_FILTER_SET   8
#define CMDLINE_FLAG_HELP_CALLBACK 16
#define CMDLINE_FLAG_HELP_MESSAGE  32
#define CMDLINE_FLAG_HELP_LINE     64
#define CMDLINE_FLAG_ARGUMENTS  128
#define CMDLINE_FLAG_OBFUSCATE  256
#define CMDLINE_FLAG_INDENTED  512
#define CMDLINE_FLAG_SEPARATOR 1024

#define CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS 1

#define CMDLINE_ERROR_BASE                       0x800E0000
#define CMDLINE_ERROR_CODE(code_)                ((s32)(CMDLINE_ERROR_BASE+(code_)))

#define CMDLINE_PROCESSING_SECTION_AS_ARGUMENT   CMDLINE_ERROR_CODE(0xff01)
#define CMDLINE_PROCESSING_INVALID_DESCRIPTOR    CMDLINE_ERROR_CODE(0xff02)
#define CMDLINE_LONG_OPT_UNDEFINED               CMDLINE_ERROR_CODE(0x0001)
#define CMDLINE_SHORT_OPT_UNDEFINED              CMDLINE_ERROR_CODE(0x0002)
#define CMDLINE_OPT_EXPECTS_ARGUMENT             CMDLINE_ERROR_CODE(0x0003)

struct cmdline_desc_s;

typedef ya_result cmdline_translator_callback(const struct cmdline_desc_s *desc, output_stream *os, const char *section_name, const char *arg_name);
typedef ya_result cmdline_filter_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned);

// desc->name is used to store the args
typedef ya_result cmdline_printer_callback(const struct cmdline_desc_s *desc, output_stream *os);

struct cmdline_desc_s
{
    u16 flags;
    char letter;

    const char *name;
    const char *value;

    union 
    { 
        const char *alias;
        cmdline_translator_callback *translator;
        cmdline_printer_callback *printer;
        cmdline_filter_callback *filter;
        int integer_value;
    } target;
};

typedef struct cmdline_desc_s cmdline_desc_s;

/**
 * Definition of a command-line
 * The command line is handled as a table of aliases to configuration settings.
 * It means that each entry has to be linked to a section/container as well as a variable.
 * 
 * The table must be put between CMDLINE_BEGIN and CMDLINE_END
 * 
 * The parameter of CMDLINE_BEGIN and CMDLINE_END is the name of the table (a variable name)
 * 
 * The section is set using CMDLINE_SECTION(section name). Each configuration alias refers
 * to the section named by the last CMDLINE_SECTION entry above it.
 * 
 * CMDLINE_BOOL CMDLINE_BOOL_NOT CMDLINE_OPT are taking 3 parameters
 * The first one is the name of the parameter on the command line. (long option)
 * The second one is the letter of the parameter on the command line. (short option)
 * The third one is the name of the variable in the configuration section.
 *
 * NOTE: there is no "underscore" filtering for the argument name.
 *   "long_opt" only matches "--long_opt" and
 *   "long-opt" only matches "--long-opt"
 *
 * "underscore" filtering is enabled for the alias argument
 * 
 */


#define CMDLINE_BEGIN(name_)                    static const cmdline_desc_s name_[] = {
/**
 * The filter gets all words not taken by the rest of the CMDLINE struct
 *
 * Only active is placed right after CMDLINE_BEGIN
 */
#define CMDLINE_FILTER(function_, arg_)         {CMDLINE_FLAG_FILTER_SET                  ,      '\0', (arg_), NULL, {.filter = (function_)} },
#define CMDLINE_SECTION(name_)                  {                                        0,      '\0', (name_),  NULL, {.alias = NULL}},
#define CMDLINE_BOOL(name_,letter_,alias_)      {CMDLINE_FLAG_ALIAS                       , (letter_), (name_),  "on", {.alias = (alias_)}},
#define CMDLINE_BOOL_NOT(name_,letter_,alias_)  {CMDLINE_FLAG_ALIAS                       , (letter_), (name_), "off", {.alias = (alias_)}},
#define CMDLINE_OPT(name_,letter_,alias_)       {CMDLINE_FLAG_ALIAS|CMDLINE_FLAG_ARGUMENTS, (letter_), (name_),  NULL, {.alias = (alias_)}},
#define CMDLINE_OPT_OBFUSCATE(name_,letter_,alias_) {CMDLINE_FLAG_ALIAS|CMDLINE_FLAG_ARGUMENTS|CMDLINE_FLAG_OBFUSCATE, (letter_), (name_),  NULL, {.alias = (alias_)}},
#define CMDLINE_HELP(argparm_, helptext_)       {CMDLINE_FLAG_HELP_LINE                   ,      '\0', (argparm_),(helptext_), {.alias = NULL} },
#define CMDLINE_MSG(argparm_, helptext_)        {CMDLINE_FLAG_HELP_MESSAGE                ,      '\0', (argparm_),(helptext_), {.alias = NULL} },
#define CMDLINE_IMSG(argparm_, helptext_)       {CMDLINE_FLAG_HELP_MESSAGE|CMDLINE_FLAG_INDENTED,      '\0', (argparm_),(helptext_), {.alias = NULL} },
#define CMDLINE_IMSGS(argparm_, helptext_)       {CMDLINE_FLAG_HELP_MESSAGE|CMDLINE_FLAG_INDENTED|CMDLINE_FLAG_SEPARATOR,      '\0', (argparm_),(helptext_), {.alias = NULL} },
#define CMDLINE_CALLBACK(function_, arg_)       {CMDLINE_FLAG_HELP_CALLBACK               ,      '\0', (arg_), NULL, {.printer = (function_)} },
#define CMDLINE_INDENT(value_)                  {CMDLINE_FLAG_INDENTED                    ,      '\0', NULL,   NULL, {.integer_value = (value_)} },
#define CMDLINE_BLANK()        {CMDLINE_FLAG_HELP_MESSAGE                ,      '\0', "", "", {.alias = NULL} },
#define CMDLINE_END(name_)                      {CMDLINE_FLAG_TERMINATOR                  ,      '\0', NULL,   NULL, {.alias = NULL}} };

#define CMDLINE_CALLBACK_ARG_GET(_desc_) ((void*)((_desc_)->name))

static inline bool cmdline_desc_not_end(const cmdline_desc_s *table)
{
    return (table->flags & CMDLINE_FLAG_TERMINATOR) == 0;
}

/**
 * Parses a command line and returns an input stream ready to be parsed by a configuration reader.
 * 
 * The function works by generating a configuration file in a stream using the command line table as a map.
 * 
 * @param table the name of a table defined using CMDLINE_BEGIN
 * @param argc the argc of main()
 * @param argv the argv of main()
 * @param filter a callback function that will be called for unhandled command line parameters (file names, "--", ...)
 * @param filter_arg a pointer given to the filter callback
 * @param is the input stream to initialise with the command line
 * @return 
 */

ya_result cmdline_parse(const cmdline_desc_s *table, int argc, char **argv, cmdline_filter_callback *filter, void *filter_arg, input_stream *is, int *argc_errorp);

/**
 * Registers command line error codes.
 */

void cmdline_init_error_codes();

ya_result cmdline_get_opt_long(const cmdline_desc_s *table, const char *name, const char *arg);

ya_result cmdline_get_opt_short(const cmdline_desc_s *table, const char *name, const char *arg);

ya_result cmdline_print_help(const cmdline_desc_s *table, int arg_column_prefix, int arg_width, const char *column_separator, int text_width, output_stream *os);

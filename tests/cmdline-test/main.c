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

#include <sys/ioctl.h>
#include <stdio.h>

#include <dnscore/dnscore.h>
#include <dnscore/cmdline.h>
#include <dnscore/config_cmdline.h>
#include <dnscore/config_settings.h>
#include <dnscore/format.h>

#define MAIN_SETTINGS_NAME "main"

#define VERSION            "1.0.0 (test value, don't change it)"

struct main_settings_s
{
    char   *password;
    int32_t value_s32;
    bool    value_bool;
};

typedef struct main_settings_s main_settings_s;

static main_settings_s         g_main_settings;

#define CONFIG_TYPE main_settings_s
CONFIG_BEGIN(main_settings_desc)
CONFIG_S32(value_s32, 0)
CONFIG_BOOL(value_bool, "off")
CONFIG_STRING(password, "")
CONFIG_END(main_settings_desc)
#undef CONFIG_TYPE

/**
 * Example of code called by printing the CMDLINE struct
 */

static ya_result main_cmdline_help_callback(const struct cmdline_desc_s *desc, output_stream_t *os)
{
    int64_t now = timeus();
    void   *arg = CMDLINE_CALLBACK_ARG_GET(desc);
    osformatln(os, "\nCurrent time: %llT (arg = %p)", now, arg);
    return SUCCESS;
}

/**
 * The filter gets all words not taken by the rest of the CMDLINE struct
 */

static ya_result main_cmdline_filter_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
{
    void *arg = CMDLINE_CALLBACK_ARG_GET(desc);

    // note: arg == callback_owned

    format("filtered argument: '%s' (%p == %p)\n", arg_name, arg, callback_owned);
    return SUCCESS;
}

CMDLINE_BEGIN(main_settings_cmdline)
CMDLINE_FILTER(main_cmdline_filter_callback, NULL) // NULL is passed to the callback as a parameter (callback_owned)
// main
CMDLINE_SECTION(MAIN_SETTINGS_NAME)
CMDLINE_OPT("value-s32", 'i', "value_s32")
CMDLINE_HELP("<32 bits signed integer>", "sets that int32_t value")
CMDLINE_BOOL("value-bool-yes", 'y', "value_bool")
CMDLINE_HELP("(no parameters)", "sets that bool value to true")
CMDLINE_BOOL_NOT("value-bool-no", 'n', "value_bool")
CMDLINE_HELP("(no parameters)", "sets that bool value to false")
CMDLINE_OPT_OBFUSCATE("password", 'p', "password")
CMDLINE_HELP("<password>", "sets a password, value should not be visible on process list after it has been parsed")
CMDLINE_MSG("", "")
CMDLINE_VERSION_HELP(main_settings_cmdline)
CMDLINE_CALLBACK(main_cmdline_help_callback,
                 NULL) // NULL is passed to the callback, use CMDLINE_CALLBACK_ARG_GET(desc) to get it
CMDLINE_END(main_settings_cmdline)

static void help(const char *name)
{
    formatln("%s [args]\n\n", name);

    cmdline_print_help(main_settings_cmdline, termout);
}

static ya_result main_config(int argc, char *argv[])
{
    config_error_t cfgerr;
    ya_result      ret;

    config_init();

    int priority = 0;

    config_register_struct(MAIN_SETTINGS_NAME, main_settings_desc, &g_main_settings, priority++);

    config_register_cmdline(priority++); // without this line, the help will not work

    struct config_source_s sources[1];

    if(FAIL(ret = config_source_set_commandline(&sources[0], main_settings_cmdline, argc, argv)))
    {
        formatln("command line definition: %r", ret);
        return ret;
    }

    config_error_init(&cfgerr);

    if(FAIL(ret = config_read_from_sources(sources, 1, &cfgerr)))
    {
        formatln("settings: (%s:%i) %s: %r", cfgerr.file, cfgerr.line_number, cfgerr.line, ret);
        flushout();
        config_error_finalise(&cfgerr);
        return ret;
    }

    config_error_finalise(&cfgerr);

    if(cmdline_help_get())
    {
        help(argv[0]);
        return SUCCESS;
    }

#ifdef TIOCGWINSZ
    struct winsize w;
    ioctl(0, TIOCGWINSZ, &w);
    int cols = w.ws_col;
    formatln("COLUMNS: %i detected", cols);
    if(cols <= 0)
    {
        cols = 80;
    }
    else if(cols > 99)
    {
        cols = 99;
    }
#else
    int cols = 80;
#endif

    formatln("COLUMNS: %i will be used", cols);

    for(int_fast32_t help_cols = 0; help_cols < cols; help_cols += 8)
    {
        println("===========================================================");
        formatln("COLUMNS: %i", help_cols);
        println("===========================================================");
        for(int_fast32_t i = 0; i < cols; ++i)
        {
            format("%i", i / 10);
        }
        println("");
        for(int_fast32_t i = 0; i < cols; ++i)
        {
            format("%i", i % 10);
        }
        println("\n===========================================================");

        cmdline_print_help_ex(main_settings_cmdline, 4, -1, " :  ", help_cols, termout);
    }

    return 1;
}

int main(int argc, char *argv[])
{
    /* initializes the core library */
    dnscore_init();

    ya_result ret = main_config(argc, argv);

    if(ISOK(ret))
    {
        if(ret == 1)
        {
            config_print(termout);
        }
        else
        {
            // help was printed.
        }
    }
    else
    {
        formatln("main_config returned: %r", ret);
    }

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}

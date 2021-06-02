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

/** @defgroup test
 *  @ingroup test
 *  @brief skeleton file
 * 
 * skeleton test program, will not be installed with a "make install"
 * 
 * To create a new test based on the skeleton:
 * 
 * _ copy the folder
 * _ replace "skeleton" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 * _ add the test to the CMakeLists.txt from the tests directory
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/logger.h>
#include <dnscore/logger_channel_stream.h>
#include <dnscore/fdtools.h>
#include <dnscore/host_address.h>
#include <dnscore/config-cmdline.h>
#include <dnscore/config_settings.h>
#include <dnscore/signals.h>

#include "server.h"

logger_handle *g_main_logger = LOGGER_HANDLE_SINK;
#define MODULE_MSG_HANDLE g_main_logger

#define CONFIG_LISTEN_DEFAULT "172.0.80.70 port 5353"
#define CONFIG_CLIENT_DEFAULT "172.0.80.71 port 5353"

struct main_args
{
    host_address *listen;
    host_address *client;
};

typedef struct main_args main_args;

#define CONFIG_TYPE main_args
CONFIG_BEGIN(main_args_desc)
CONFIG_HOST_LIST_EX(listen, CONFIG_LISTEN_DEFAULT, CONFIG_HOST_LIST_FLAGS_DEFAULT,1)
CONFIG_HOST_LIST_EX(client, CONFIG_CLIENT_DEFAULT, CONFIG_HOST_LIST_FLAGS_DEFAULT,1)
CONFIG_END(main_args_desc)
#undef CONFIG_TYPE

CMDLINE_BEGIN(main_cmdline)
CMDLINE_SECTION("main")
CMDLINE_OPT("listen",'l',"listen")
CMDLINE_HELP("address [port number]", "the address to listen to (default: " CONFIG_LISTEN_DEFAULT ")")
CMDLINE_OPT("client",'s',"client")
CMDLINE_HELP("address [port number]", "the address of the client (default: " CONFIG_CLIENT_DEFAULT ")")
CMDLINE_VERSION_HELP(main_cmdline)
CMDLINE_END(main_cmdline)

static main_args g_config = {NULL, NULL};

static void
help(const char *name)
{
    formatln("%s [options]\n\n", name);
    cmdline_print_help(main_cmdline, 4, 0, " :  ", 0, termout);
}

static ya_result
main_config(int argc, char *argv[])
{
    config_error_s cfg_error;
    ya_result ret;

    config_init();

    int priority = 0;

    config_register_struct("main", main_args_desc, &g_config, priority++);

    config_register_cmdline(priority++); // without this line, the help will not work

    struct config_source_s sources[1];

    if(FAIL(ret = config_source_set_commandline(&sources[0], main_cmdline, argc, argv)))
    {
        formatln("command line definition: %r", ret);
        return ret;
    }

    if(FAIL(ret = config_read_from_sources(sources, 1, &cfg_error)))
    {
        formatln("settings: (%s:%i) %s: %r", cfg_error.file, cfg_error.line_number, cfg_error.line, ret);
        flushout();
        return ret;
    }

    if(cmdline_help_get())
    {
        help(argv[0]);
        return SUCCESS;
    }

    return ret;
}

static void
main_logger_setup()
{
    output_stream stdout_os;
    fd_output_stream_attach(&stdout_os, dup_ex(1));
    buffer_output_stream_init(&stdout_os, &stdout_os, 65536);

    logger_channel *stdout_channel = logger_channel_alloc();
    logger_channel_stream_open(&stdout_os, FALSE, stdout_channel);
    logger_channel_register("stdout", stdout_channel);

    logger_handle_create("system", &g_system_logger);
    logger_handle_add_channel("system", MSG_PROD_MASK, "stdout");

    logger_handle_create("main", &g_main_logger);
    logger_handle_add_channel("main", MSG_PROD_MASK, "stdout");
}

static void
signal_int(u8 signum)
{
    (void)signum;

    log_notice("SIGINT");

    if(!dnscore_shuttingdown())
    {
        dnscore_shutdown();
    }

    signal_handler_stop();
}

int
main(int argc, char *argv[])
{
    ya_result ret;

    (void)argc;
    (void)argv;
    /* initializes the core library */
    dnscore_init();

    if(FAIL(ret = main_config(argc, argv)))
    {
        (void)ret;
        return EXIT_FAILURE;
    }

    signal_handler_init();
    signal_handler_set(SIGINT, signal_int);

    logger_start();
    main_logger_setup();

    ret = server_tcp(g_config.listen, g_config.client);

    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}

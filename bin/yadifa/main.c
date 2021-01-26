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

/** @defgroup yadifa
 *  @ingroup ###
 *  @brief
 */

//#include <sys/resource.h>

#include "client-config.h"

#include <dnscore/dnscore.h>
#include <dnscore/config_settings.h>
#include <dnscore/parser.h>
#include <dnscore/cmdline.h>
#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/signals.h>
#include <dnslg/config-load.h>

#include "main.h"
#include "module.h"
#include "buildinfo.h"

//#define DEBUG_FAKE_PROGRAM_NAME "./ykeygen"

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

logger_handle *g_client_logger = LOGGER_HANDLE_SINK;
#define MODULE_MSG_HANDLE g_client_logger

/*----------------------------------------------------------------------------*/
#pragma mark STATIC PROTOTYPES

void config_logger_setdefault();
void config_logger_cleardefault();

/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS

typedef struct my_additional_stuff_s my_additional_stuff_s;
struct my_additional_stuff_s
{
    struct config_main                                            *next;

    u16                                                           qtype;
    u16                                                          qclass;

    u8                                                        fqdn[256];
};

/*    ------------------------------------------------------------    */

/** @brief main function of yadifa
 *
 *  @param[in] argc number of arguments on the command line
 *  @param[in] argv array of arguments on the command line
 *
 *  @return EXIT_SUCCESS
 *  @return EXIT_FAILURE
 *  @return exit codes
 */
int
main(int argc, char **argv)
{
#if defined(DEBUG_FAKE_PROGRAM_NAME)
    argv[0] = DEBUG_FAKE_PROGRAM_NAME;
#endif

    /* initializes the core library */
    dnscore_init();

    // automatic handling of basic signals so the program doesn't die with, say, SIGPIPE

    signal_handler_init();

    ya_result                                                           ret;
    ret = module_run_from_args(&argc, argv);

    signal_handler_finalize();

    return ISOK(ret)?EXIT_SUCCESS:EXIT_FAILURE;
}

void
yadifa_print_authors()
{
    print("\n"
          "\t\tYADIFAD authors:\n"
          "\t\t---------------\n"
          "\t\t\n"
          "\t\tGery Van Emelen\n"
          "\t\tEric Diaz Fernandez\n"
          "\n"
          "\t\tContact: " PACKAGE_BUGREPORT "\n"
         );
    flushout();
}

/**
 *  @fn static void distance_print_version()
 *  @brief  distance_print_version prints the authors who wrote distance
 *
 *  @param level int
 *  @return -- nothing --
 */
void
yadifa_show_version(u8 level)
{
    switch(level)
    {
        case 0:
            break;
        case 1:
            osformatln(termout, "%s %s (%s)\n", PROGRAM_NAME, PROGRAM_VERSION, RELEASE_DATE);
            break;
        case 2:
#if HAS_BUILD_TIMESTAMP && defined(__DATE__)
            osformatln(termout, "%s %s (released %s, compiled %s)\n\nbuild settings: %s\n", PROGRAM_NAME, PROGRAM_VERSION, RELEASE_DATE, __DATE__, BUILD_OPTIONS);
#else
            osformatln(termout, "%s %s (released %s)\n\nbuild settings: %s\n", PROGRAM_NAME, PROGRAM_VERSION, RELEASE_DATE, BUILD_OPTIONS);
#endif
            break;
        case 3:
#if HAS_BUILD_TIMESTAMP && defined(__DATE__)
            osformatln(termout, "%s %s (released %s, compiled %s)\n", PROGRAM_NAME, PROGRAM_VERSION, RELEASE_DATE, __DATE__);
#else
            osformatln(termout, "%s %s (released %s)\n", PROGRAM_NAME, PROGRAM_VERSION, RELEASE_DATE);
#endif
            yadifa_print_authors();
            break;
        default:
            osformat(termout, "\nYou want to know too much!\n\n");
            break;
    }

    flushout();
}

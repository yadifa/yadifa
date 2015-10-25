/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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

#include <sys/resource.h>
#include <sys/time.h>

#include "client-config.h"

#include <dnscore/dnscore.h>
#include <dnscore/config_settings.h>
#include <dnscore/parser.h>
#include <dnscore/cmdline.h>
#include <dnslg/config-load.h>

#include "yadifa.h"
#include "yadifa-config.h"

#undef HAS_TCL

/*----------------------------------------------------------------------------*/

logger_handle *g_client_logger;
#define MODULE_MSG_HANDLE g_client_logger


//extern config_resolver_settings_s yadifa_resolver_settings;
//volatile int program_mode = SA_CONT; /** @note must be volatile */

//static bool server_do_clean_exit = FALSE;

/*----------------------------------------------------------------------------*/

void config_logger_setdefault();
void config_logger_cleardefault();

/*----------------------------------------------------------------------------*/

ya_result (*generic_config_init)(void);
ya_result (*generic_config_cmdline)(int , char **);
ya_result (*generic_config_finalise)(void);
char *    (*generic_config_file_get)(void);

int (*generic_run)(void);

#define GENERIC_COMMAND_BEGIN(name__,command__)  if(! strcmp(program_name, name__)){\
                                 generic_config_init=&command__ ## _config_init;\
                                 generic_config_cmdline=&command__ ## _config_cmdline;\
                                 generic_config_finalise=&command__ ## _config_finalise;\
                                 generic_config_file_get=&command__ ## _config_file_get;\
                                 generic_run=&command__ ## _run;}

#define GENERIC_COMMAND(name__,command__) else GENERIC_COMMAND_BEGIN(name__,command__)

#define GENERIC_COMMAND_END(command__)  else{generic_config_init=&command__ ## _config_init;\
                                        generic_config_cmdline=&command__ ## _config_cmdline;\
                                        generic_config_finalise=&command__ ## _config_finalise;\
                                        generic_config_file_get=&command__ ## _config_file_get;\
                                        generic_run=&command__ ## _run;}


/*----------------------------------------------------------------------------*/

/** @brief base_of_path
 *
 *  @param s char *
 *  @return char * 
 */
static char *
base_of_path (char *s)
{
    char *ptr;

    if (s[0] == '/' && s[1] == 0)
    {
        return (s);
    }

    ptr = strrchr (s, '/');

    return (ptr ? ++ptr : s);
}


/** @brief get_rc_file
 *
 *  @param program_name const char *
 *  @return char * 
 */
static char *
get_rc_file(const char *program_name)
{
    const char *home_env = getenv ("HOME");
    char *rc_file = NULL;

    if (home_env != NULL)
    {
        ssize_t home_env_length = strlen(home_env);
        ssize_t program_name_length = strlen(program_name);

        /* allocate memory and create the config */
        MALLOC_OR_DIE(char*, rc_file, 1 + home_env_length + 2 + program_name_length + 3, GENERIC_TAG);

        rc_file[0] = '\0';

        strcat(rc_file, home_env);
        strcat(rc_file, "/.");
        strcat(rc_file, program_name);
        strcat(rc_file, ".rc");
        
        log_debug("rc file: '%s'", rc_file);
    }

    return rc_file;
}




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
main(int argc, char *argv[])
{
    ya_result                                                   return_code;

    char                              *program_name = base_of_path(argv[0]);
    char                               *rc_file = get_rc_file(program_name);


    /*    ------------------------------------------------------------    */


    /* 1. INIT EVERYTHING */

    /* initializes the core library */
    dnscore_init();

    log_memdump_set_layout(LOG_MEMDUMP_LAYOUT_GERY);

    parser_init_error_codes();
    config_init_error_codes();

    logger_start();

    GENERIC_COMMAND_BEGIN("yadifa",yadifa)



    GENERIC_COMMAND_END(yadifa)

    if(FAIL(return_code = generic_config_init()))
    {
        formatln("config_init failed: %r", return_code);
        flushout();
        dnscore_finalize();

        return EXIT_FAILURE;
    }

    if(FAIL(return_code = generic_config_cmdline(argc, argv)))
    {
        formatln("cmdline_parse failed: %r", return_code);
        flushout();
        dnscore_finalize();

        return EXIT_FAILURE;
    }

    /* if command line option is 'help' or 'version' --> exit */
    if (return_code > 0)
    {
        return EXIT_SUCCESS;

    }

    /* if there's a config file, use that one otherwise use the 'rc' file */
    char *config_file;
    if (NULL == (config_file = generic_config_file_get()))
    {
        /* load the config of rc file */
        if (FAIL(return_code = config_load_rc(rc_file)))
        {
            dnscore_finalize();

            return EXIT_FAILURE;
        }
    }
    else
    {
        /* load the config of rc file */
        if (FAIL(return_code = config_load_rc(config_file)))
        {
            dnscore_finalize();

            return EXIT_FAILURE;
        }
    }


    if(FAIL(return_code = generic_config_finalise()))
    {
        osformatln(termerr, "error: %r", return_code);
        flusherr();

        return EXIT_FAILURE;
    }

    /* finally run "the command" */


    return_code = generic_run();









    return EXIT_SUCCESS;
}

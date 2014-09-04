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
/** @defgroup ### #######
 *  @ingroup ###
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#define _POSIX_SOURCES
#define __USE_POSIX

#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/config_settings.h>
#include <dnscore/parser.h>
#include <dnscore/cmdline.h>

#include <dnslg/config-load.h>

#include "yadifa.h"
#include "yadifa-config.h"


logger_handle *g_client_logger;

#define MODULE_MSG_HANDLE g_client_logger


//extern config_resolver_settings_s yadifa_resolver_settings;



//volatile int program_mode = SA_CONT; /** @note must be volatile */

/*------------------------------------------------------------------------------
 * GO */

//static bool server_do_clean_exit = FALSE;

void config_logger_setdefault();
void config_logger_cleardefault();

static char *
base_of_path (char *s)
{
    char *ptr;

    if (s[0] == '/' && s[1] == 0)
    {
        return (s);
    }

    ptr = (char *)strrchr (s, '/');

    return (ptr ? ++ptr : s);
}


static char *
get_rc_file(const char *program_name)
{
    const char *home_env = getenv ("HOME");
    char *rc_file = NULL;

    if (home_env != NULL)
    {
        ssize_t home_env_length = strlen(home_env);
        ssize_t program_name_length = strlen(program_name);

        // allocate memory and create the config
        MALLOC_OR_DIE(char*, rc_file, 1 + home_env_length + 1 + program_name_length + 3, GENERIC_TAG);

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
    struct config_main *next;

    u16 qtype;
    u16 qclass;

    u8 fqdn[256];
};

//#define CONFIG_TYPE config_data
//CONFIG_BEGIN(config_main_desc)
//    CONFIG_U32(cpu_count, "2")
//    CONFIG_U32_RANGE(thread_count, "2", 0, 16)
//CONFIG_BOOL(daemon, "on")
//CONFIG_END(config_main_desc)
//#undef CONFIG_TYPE
//
//CMDLINE_BEGIN(my_cmdline)
//    CMDLINE_SECTION("brol")
//    CMDLINE_OPT("server",'s',"server")
//    CMDLINE_OPT("cpu_count",'C',"cpu_count")
//    CMDLINE_BOOL("daemon", 'd', "daemon")
//    CMDLINE_BOOL_NOT("nodaemon", 0, "daemon")
//    CMDLINE_SECTION("truc")
//    CMDLINE_BOOL("nasty", 'd', "daemon")
//CMDLINE_BOOL_NOT("nonasty", 0, "daemon")
//CMDLINE_END(my_cmdline)



    //    my_additional_stuff_s my_additional_stuff;
    //    ZEROMEMORY(&my_additional_stuff, sizeof(my_additional_stuff_s));

static ya_result
cmdline_filter_callback_function(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
{
    ya_result return_code = SUCCESS;

    formatln("cmdline_filter_callback_function: '%s'", arg_name);

    if(strcmp(arg_name, "--") == 0)
    {
        return CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS;
    }

    my_additional_stuff_s *add = (my_additional_stuff_s*)callback_owned;

    if(arg_name[0] == '@')
    {
        formatln("FOUND @@");
        //
        config_section_descriptor_s *desc = config_section_get_descriptor("yadifa");

        if(desc != NULL)
        {
            formatln("ARG %s\n", arg_name[1]);
            if(ISOK(return_code = config_value_set(desc, "servers", &arg_name[1])))
            {
                // values >= MUST be 0 or CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS
                return_code = 0;
            }

        }
        else
        {
            return_code = ERROR; // bug
        }
    }
    else
    {
        s32 qtype = get_type_from_case_name(arg_name, &add->qtype);
        if(FAIL(qtype))
        {
            s32 qclass = get_type_from_case_name(arg_name, &add->qclass);
            if(FAIL(qclass))
            {
                if(ISOK(return_code = cstr_to_dnsname_with_check(add->fqdn, arg_name)))
                {
                    // values >= MUST be 0 or CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS
                    return_code = 0;
                }
                else
                {
                    printf("NOT FOUND\n");
                }
            }
        }
    }

#if DEBUG
    if(FAIL(return_code))
    {
        println("oops");
    }
#endif

    return return_code;
}

#if DOG
int pcapInteractive();
#endif

/** \brief Main function of yadifa
 *
 *  @param[in] argc number of arguments on the command line
 *  @param[in] argv array of arguments on the command line
 *
 *  @return EXIT_SUCCESS
 *  @return EXIT_FAILURE
 *  @return exit codes
 *
 */
int
main(int argc, char *argv[])
{
    ya_result                                                   return_code;

    char                              *program_name = base_of_path(argv[0]);
    char                               *rc_file = get_rc_file(program_name);


    /*    ------------------------------------------------------------    */


    // 1. INIT EVERYTHING
    //

    /* initializes the core library */
    dnscore_init();



    log_memdump_set_layout(LOG_MEMDUMP_LAYOUT_GERY);

    parser_init_error_codes();
    config_init_error_codes();

    logger_start();


    {
        // nothing else found then use the default one
        //    u64 started_at = timeus();
        //    ya_result err;

        if(FAIL(return_code = yadifa_config_init()))
        {
            formatln("config_init failed: %r", return_code);
            flushout();
            dnscore_finalize();

            return EXIT_FAILURE;
        }

        if(FAIL(return_code = yadifa_config_cmdline(argc, argv)))
        {
            formatln("cmdline_parse failed: %r", return_code);
            flushout();
            dnscore_finalize();

            return EXIT_FAILURE; 
        }

        // if return was '--help' or '--version' quit gracefully
        if (return_code > 0)
        {
            return EXIT_SUCCESS;
        }



        // 3. load the config of rc file
        if(FAIL(return_code = config_load_rc(rc_file)))
        {
            dnscore_finalize();

            return EXIT_FAILURE; 
        }


        // if command line option is 'help' or 'version' --> exit
        if (return_code > 0)
        {
            return EXIT_SUCCESS;

        }

        // 5. set the default options
        if(FAIL(return_code = yadifa_config_finalise()))
        {
            osformatln(termerr, "error: %r", return_code);
            flusherr();

            return EXIT_FAILURE;
        }


        // 6. finally run "yadig"
        return_code = yadifa_run();
    }
    
    if(FAIL(return_code))
    {
        osformatln(termerr, "error: %r", return_code);
        flusherr();
    }











    return EXIT_SUCCESS;
}

/** @} */

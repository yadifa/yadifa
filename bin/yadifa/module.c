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

#include <strings.h>

#include "client-config.h"

#include "module.h"
#include "common.h"
#include "ya-conf.h"
#include "main.h"

#if HAS_CTRL
#include "module/ctrl.h"
#endif

#if HAS_KEYGEN
#include "module/keygen.h"
#endif

#if HAS_ZONESIGN
#include "module/zonesign.h"
#endif

#include <dnscore/logger_handle.h>
#include <dnscore/config-cmdline.h>
#include <dnscore/config_settings.h>

logger_handle *g_yadifa_logger = LOGGER_HANDLE_SINK;

extern logger_handle *g_generate_logger;

static int verbosity_level = 0;

int module_verbosity_level()
{
    return verbosity_level;
}


// each module has a structure --> virtual table
// only those that are compiled in the program are taken in
static const module_s *module_list[] =
{
#if HAS_CTRL
    &ctrl_program,
#endif

#if HAS_KEYGEN
    &keygen_program,
#endif

#if HAS_ZONESIGN
    &zonesign_program,
#endif

    NULL
};

void
module_print_help(const module_s *module, const char* program_name, int is_executable)
{
    // formatln("is_executable=%i", is_executable);

    if(is_executable == 0) // if it's not a a module, give the program help (covers 'unspecified')
    {
        osformatln(termout, "Usage:\n\n%s %s [command] [options []]\n", program_name, module->parametername);
    }
    else
    {
        osformatln(termout, "Usage:\n\n%s command [options []]\n", program_name);
    }
    module->help_print(module, termout);
}

static void
module_program_print_help(const char *program_name, int help_count, int version_count)
{
    yadifa_show_version(version_count); // level 0 prints nothing

    if(help_count > 0 || version_count == 0)
    {
        // give help

        formatln("%s command [parameters]\n", program_name);
        println("\tCommands:");

        for(int i = 0; module_list[i] != NULL; ++i) // VS false positive: the last item of the array is guaranteed to be NULL
        {
            formatln("\t\t%12s : %s", module_list[i]->parametername, module_list[i]->name);
        }

        formatln("\nTry '%s help command' for more information about a command.\n", program_name);
    }
}

const module_s *
module_get_from_args(int *argcp, char **argv, int *is_executable_ptr)
{
    const char *executable_name = filename_from_path(argv[0]);

    *is_executable_ptr = -1;

    // no <commandname> found, check for <parametername>

    int argc = *argcp;

    // if <parametername> is used there must be at least 3 parameters.
    // if not we print an help page
    
    if(argc >= 2) // if there is at least one parameter after the name
    {
        // compares the parameter name with each module "parametername"

        for(int i = 0; module_list[i] != NULL; ++i) // VS false positive: the last item of the array is guaranted to be NULL
        {
            if(strcmp(argv[1], module_list[i]->parametername) == 0)
            {
                // module has been matched

                *is_executable_ptr = 0;

                // patch the command parameters (shifts out the first parameter)
                
                for(int i = 2; i < argc; ++i)
                {
                    argv[i - 1] = argv[i];
                }
                
                --argc;
                *argcp = argc;

                return module_list[i];
            }
        }

        // no module has been matched, look if help was requested one way or another

        if(strcasecmp(argv[1], "help") == 0)
        {
            // no match.
            // is it "help" ?

            if(argc >= 3) // if there is a parameter after help ..;
            {
                // putting in place the whole settings just to answer help or version would be pointless

                // find the module whose help was requested and print it

                for(int i = 0; module_list[i] != NULL; ++i)
                {
                    if(strcmp(argv[2], module_list[i]->parametername) == 0)
                    {
                        *is_executable_ptr = 0;

                        module_print_help(module_list[i], argv[0], *is_executable_ptr);
                        return NULL;
                    }
                }
            }
            else
            {
                println("help command requires a parameter.\n");

                module_program_print_help(argv[0], 1, 0);
                return NULL;
            }
        }
        else if((strcasecmp(argv[1], "--help") == 0) || (strcasecmp(argv[1], "-h") == 0))
        {
            // help was asked in a standard way: print the general help listing the modules
            // used as flag to know, that even if its not a module, the exit can be clean, 'help' of the module
            // has been asked
            *is_executable_ptr = 0;
        }
        else
        {
            // whatever was asked to yadifa is unknown: complain about it then print the general help listing the modules
        }
    }
    else
    {
        // nothing was asked to yadifa: print the general help listing the modules
    }
    
    int help_count = 0;
    int version_count = 0;
    int verbose_level = 0;

    for(int i = 1; i < argc; ++i)
    {        
        if((strcmp(argv[1], "--help") == 0) || (strcmp(argv[1], "-h") == 0) )
        {
            ++help_count;
        }
        else if((strcmp(argv[1], "--version") == 0) || (strcmp(argv[1], "-V") == 0))
        {
            ++version_count;
        }
        else if((strcmp(argv[1], "--verbose") == 0) || (strcmp(argv[1], "-v") == 0))
        {
            ++verbose_level;
        }
        else
        {
            flushout();
            osformatln(termerr, "%s: invalid option: %s", argv[0], argv[i]);
            flusherr();
        }
    }
    
    verbosity_level = verbose_level;

    module_program_print_help(argv[0], help_count, version_count);
    
    return NULL;
}

ya_result
module_run_from_args(int *argcp, char *argv[])
{
    ya_result ret = ERROR;
    
    int argc = *argcp;
    int is_executable = -2;
    
    const module_s *module = module_get_from_args(&argc, argv, &is_executable);
    
    *argcp = argc;
    
    // at this point, the program to execute is known
    
    if(module != NULL)
    {
        if(FAIL(ret = module->init()))
        {
            formatln("module %s initialisation failed: %r", module->name, ret);
            return ret;
        }
    
        // if the logger is running (not a guarantee), register the system logger

        if(logger_is_running())
        {
            logger_handle_create("yadifa", &g_yadifa_logger);
        }

        // @TODO 20180611 gve -- this must be uncomment
        if(ISOK(ret = ya_conf_init()))
        {
            int priority = ret;

            if(ISOK(ret = module->config_register(priority)))
            {
                ret = ya_conf_read(module->cmdline_table, argc, argv, module->filter, module->filter_arg, module->rcname);

                ya_conf_finalize();

                if(cmdline_help_get() + cmdline_version_get() > 0)
                {
                    module_print_help(module, argv[0], is_executable);
                }
                else
                {
                    if(ret  == 0)
                    {
                        if(ISOK(ret = module->setup()))
                        {
                            ret = module->run();
                        }
                        else // something is wrong with the setup
                        {
                            module_print_help(module, argv[0], is_executable);
                        }

                        // THERE IS NO GUARANTEE TO REACH THIS LINE (TCL)
                    }

                    if(FAIL(ret))
                    {
                        if((ret == CONFIG_PARSE_UNKNOWN_KEYWORD) || (ret == COMMAND_ARGUMENT_EXPECTED) || (ret == YADIFA_MODULE_HELP_REQUESTED))
                        {
                            module_print_help(module, argv[0], is_executable);
                        }
                        else
                        {
                            /// @todo 20220511 edf -- print the error if it's not YADIFA_MODULE_HELP_REQUESTED ?
                            flushout();
                            flusherr();
                            osformatln(termerr, "error: %r", ret);
                        }
                    }
                }
            }
            else
            {
                formatln("module %s configuration registration failed: %r", module->name, ret);
            }
        }
        else
        {
            formatln("module %s configuration initialisation failed: %r", module->name, ret);
        }
    }
    else
    {
        // no module matched but maybe 'help' was asked instead
        if (is_executable == 0)
        {
            // 'help' was asked instead
            ret = 0;
        }
    }
    
    *argcp = argc;
    
    return ret;
}

/*----------------------------------------------------------------------------*/
#pragma mark MODULES DEFAULT FUNCTIONS

// ********************************************************************************
// ***** module initializer
// ********************************************************************************

ya_result
module_default_init(const struct module_s* m)
{
    (void)m;
    return SUCCESS;
}

// ********************************************************************************
// ***** module finalizer
// ********************************************************************************

ya_result
module_default_finalize()
{
    return SUCCESS;
}

// ********************************************************************************
// ***** module register
// ********************************************************************************

int
module_default_config_register(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return 0;
}



// ********************************************************************************
// ***** module setup
// ********************************************************************************

int
module_default_setup()
{
    return SUCCESS; // returns anything else than 0 => program will exit
}

// ********************************************************************************
// ***** module run
// ********************************************************************************

ya_result
module_default_run()
{
    return SUCCESS;
}

ya_result
module_default_help_print(const struct module_s* m, output_stream *os)
{
    if(m->help_text != NULL)
    {
        osformatln(os, m->help_text, m->name);
    }
    else
    {
        osformatln(os, "help callback for module '%s' is not set properly", m->name);
    }
    return SUCCESS;
}

ya_result
module_default_cmdline_help_print(const struct module_s* m, output_stream *os)
{
    cmdline_print_help(m->cmdline_table, 16, 28, " :  ", 48, os);
    return SUCCESS;
}

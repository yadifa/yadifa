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



/** @defgroup yadifa
 *  @ingroup ###
 *  @brief
 */


#include <dnscore/sys_types.h>
#include <dnscore/output_stream.h>
#include <dnscore/cmdline.h>

struct module_s
{
    ya_result (*init)();        //
    ya_result (*finalise)();    //
    int (*config_register)(int priority);
    int (*setup)();
    ya_result (*run)();
    ya_result (*help_print)(const struct module_s*,output_stream* os);

    const cmdline_desc_s *cmdline_table;
    cmdline_filter_callback *filter;
    void *filter_arg;
    
    const char *name;           // public name
    const char *commandname;    // name as an executable
    const char *parametername;  // name as a parameter (yadifa command name)
    const char *help_text;      // a text to be printed upon help request
    const char *rcname;         // ie: ".modulerc"
};

typedef struct module_s module_s;

// is_executable: -1 none, 0: module 1: executable
void module_print_help(const module_s *module, const char *program_name, int is_executable);

// is_executable: -1 none, 0: module 1: executable
const module_s *module_get_from_args(int *argcp, char **argv, int *is_executable_ptr);

/**
 * Finds the module from the command line.
 * Prints help.
 * Runs the module.
 * 
 * @param argcp
 * @param argv
 * @return 
 */

ya_result module_run_from_args(int *argcp, char **argv);

int module_verbosity_level();

/*----------------------------------------------------------------------------*/
#pragma mark MODULES DEFAULT FUNCTIONS

ya_result module_default_init(const struct module_s*);
ya_result module_default_finalize();
int module_default_config_register(int argc, char **argv);
int module_default_setup();
ya_result module_default_run();
ya_result  module_default_help_print(const struct module_s*, output_stream *os);
ya_result module_default_cmdline_help_print(const struct module_s* m, output_stream *os);

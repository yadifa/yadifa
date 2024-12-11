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

/**-----------------------------------------------------------------------------
 * @defgroup yadifa
 * @ingroup ###
 * @brief
 *----------------------------------------------------------------------------*/

#define DUMMY_C_

// ********************************************************************************
#pragma mark includes

#include "client_config.h"

#include "module/dummy.h"
#include "common_config.h"
#include "module.h"
#include "common.h"

#include <dnscore/cmdline.h>
#include <dnscore/config_cmdline.h>
#include <dnscore/config_settings.h>

#include <dnscore/logger_handle.h>

// ********************************************************************************
#pragma mark--
#pragma mark defines

// ********************************************************************************
#pragma mark--
#pragma mark logger

/** @note: here we define the variable that is holding the default logger handle for the current source file
 *         Such a handle should NEVER been set in an include file.
 */

logger_handle *g_dummy_logger = LOGGER_HANDLE_SINK;
#define MODULE_MSG_HANDLE g_dummy_logger

// ********************************************************************************
#pragma mark--
#pragma mark module common functions

// ********************************************************************************
// ***** module settings
// ********************************************************************************

static ya_result dummy_cmdline_filter_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
{
    void *arg = CMDLINE_CALLBACK_ARG_GET(desc);

    return SUCCESS;
}

/** @struct: g_dummy_settings_s
 *  @brief dummy_g_dummy_settings
 */
static dummy_settings_s g_dummy_settings;

#define CONFIG_TYPE dummy_settings_s
CONFIG_BEGIN(dummy_settings_desc)
CONFIG_U32(value, DUMMY_CONFIG_VALUE_DEFAULT)
CONFIG_END(dummy_settings_desc)

// ********************************************************************************
// ***** module command line struct
// ********************************************************************************

/** @struct: dummy_cmdline
 *  @brief dummy_cmdline
 */
CMDLINE_BEGIN(dummy_cmdline)

// main hooks
CMDLINE_SECTION(MAIN_SECTION_NAME)
CMDLINE_FILTER(dummy_cmdline_filter_callback, NULL) // NULL is passed to the callback as a parameter (callback_owned)
CMDLINE_OPT("config", 'c', "config_file")
CMDLINE_HELP("<file>", "sets the configuration file")
CMDLINE_BOOL("verbose", 'v', "verbose")

// server hooks

CMDLINE_SECTION("dummy")
CMDLINE_OPT("value", 'V', "value")

CMDLINE_VERSION_HELP(dummy_cmdline)

CMDLINE_END(dummy_cmdline)

// ********************************************************************************
// ***** command help usage
// ********************************************************************************

static const char dummy_cmdline_help[] =
    "command:\n\n"
    "\toptions:\n"
    "\t\t--config/-c <config-file>   : use <config_file> as configuration\n"
    "\t\t--verbose/-v                : be verbose\n"
    "\n"
    "\t\t--value/-V <value>          : this is a dummy parameter\n";

// ********************************************************************************
// ***** module initializer
// ********************************************************************************

/** @fn dummy_init
 *  @brief dummy_init
 *
 *  @return ya_result
 */
static ya_result dummy_init()
{
    /*
    logger_start();
    logger_handle_create("dummy", &g_dummy_logger);
    */
    return SUCCESS;
}

// ********************************************************************************
// ***** module config register
// ********************************************************************************

/** @fn dummy_config_register
 *  @brief dummy_config_register
 *
 *  @param priority
 *
 *  @return int
 */
static int dummy_config_register(int priority)
{
    // register all config blocs required by the server

    ZEROMEMORY(&g_dummy_settings, sizeof(g_dummy_settings));
    ya_result ret = config_register_struct("dummy", dummy_settings_desc, &g_dummy_settings, priority++);

    return ret;
}

// ********************************************************************************
// ***** module setup
// ********************************************************************************

/** @fn dummy_setup
 *  @brief dummy_setup
 *
 *  @param priority
 *
 *  @return int: SUCCESS
 */
static int dummy_setup()
{
    return SUCCESS; // returns anything else than 0 => program will exit
}

// ********************************************************************************
// ***** module finalizer
// ********************************************************************************

/** @fn dummy_finalize
 *  @brief dummy_finalize
 *
 *  @return int: SUCCESS
 */
static ya_result dummy_finalize() { return SUCCESS; }

// ********************************************************************************
// ***** module command line callback
// ********************************************************************************

/** @fn dummy_cmdline_callback
 *  @brief dummy_cmdline_callback
 *
 *  @param desc:
 *  @param arg_name:
 *  @param callback_owned
 *
 *  @return ya_result: SUCCESS
 */
static ya_result dummy_cmdline_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
{
    if(strcmp(arg_name, "--") == 0)
    {
        return CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS;
    }

    return SUCCESS;
}

// ********************************************************************************
#pragma mark--
#pragma mark module run

// ********************************************************************************
// ***** module run
// ********************************************************************************

/** @fn dummy_run
 *  @brief dummy_run
 *
 *  @return ya_result: SUCCESS
 */
static ya_result dummy_run() { return SUCCESS; }

// ********************************************************************************
#pragma mark--
#pragma mark module virtual table

// ********************************************************************************
// ***** module virtual table
// ********************************************************************************

/** @var: dummy_program
 *  @brief dummy_program
 */
const module_s dummy_program = {
    dummy_init,            // module initializer
    dummy_finalize,        // module finalizer
    dummy_config_register, // module config register
    dummy_setup,           // module setup
    dummy_run,             // module run

    dummy_cmdline,          // module command line struct
    dummy_cmdline_callback, // module command line callback
    NULL,                   // module filter arguments

    "module blueprint", // module public name
    "dummy",            // module command (name as executable match)
    "dummy",            // module parameter (name as first parameter)
    dummy_cmdline_help, // module text to be printed upon help request
    NULL                // no RC for dummies (see module.h)
};

// ********************************************************************************
#pragma mark--
#pragma mark functions

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

#define CONFIG_CMDLINE_C

#include "dnscore/dnscore-config.h"
#include "dnscore/config_settings.h"


const char CMDLINE_CONTAINER[] = "\001cmdline";


/// command line container 
//  only for the general settings:
//      version
//      help
typedef struct cmdline_general_settings_s cmdline_general_settings_s;
struct cmdline_general_settings_s
{
    u8 version;
    bool help;
};

#define CONFIG_TYPE cmdline_general_settings_s
CONFIG_BEGIN(cmdline_settings_desc)

CONFIG_U8_INC(version)
CONFIG_BOOL(help, "0")

CONFIG_END(cmdline_settings_desc)
#undef CONFIG_TYPE

// declare and init global variable
static cmdline_general_settings_s cmdline_general_settings = {0, FALSE};

ya_result
config_register_cmdline(u8 priority)
{
    ya_result return_code;

    // init and register general command line settings container
    if(FAIL(return_code = config_register_struct(CMDLINE_CONTAINER, cmdline_settings_desc, &cmdline_general_settings, priority)))
    {
        return return_code;
    }

    return SUCCESS;
}

/**
 * Returns if the CMDLINE_VERSION_HELP(main_cmdline) command line help hook detected a --help
 * Needs to have config_register_cmdline(priority++) called in the configuration registration code.
 */

bool
cmdline_help_get()
{
    return cmdline_general_settings.help;
}

/**
 * Returns if the CMDLINE_VERSION_HELP(main_cmdline) command line help hook detected a --version
 * Needs to have config_register_cmdline(priority++) called in the configuration registration code.
 */

u8
cmdline_version_get()
{
    return cmdline_general_settings.version;
}


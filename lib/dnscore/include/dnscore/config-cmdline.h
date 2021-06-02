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

/** @defgroup 
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#pragma once

#include "dnscore/sys_types.h"

#ifndef CONFIG_CMDLINE_C
extern const char CMDLINE_CONTAINER[];
#endif

/**
 * This define has to be put in a CMDLINE table so the help can be handled
 * automatically.
 * 
 * Requires registration of the command line using config_register_cmdline
 */

#define CMDLINE_VERSION_HELP(cmdline)\
    CMDLINE_SECTION(  CMDLINE_CONTAINER)\
    CMDLINE_BOOL(     "help",      'h', "help")\
    CMDLINE_HELP("","shows this help")\
    CMDLINE_BOOL(     "help",      '?', "help") /* not adding CMDLINE_HELP here is not an oversight */ \
    CMDLINE_BOOL(     "version",   'V', "version")\
    CMDLINE_HELP("","prints the version of the software")

/**
 * 
 * Registers the command line section/container with the configuration mechanism.
 * Allows handling of help and version command line parameters.
 * 
 * @param priority
 * @return 
 */

ya_result config_register_cmdline(u8 priority);

/**
 * Returns if the CMDLINE_VERSION_HELP(main_cmdline) command line help hook detected a --help
 * Needs to have config_register_cmdline(priority++) called in the configuration registration code.
 *
 * @return TRUE iff a help parameter was found in the command line
 */

bool cmdline_help_get();

/**
 * Returns if the CMDLINE_VERSION_HELP(main_cmdline) command line help hook detected a --version
 * Needs to have config_register_cmdline(priority++) called in the configuration registration code.
 * 
 * @return the number of times a version parameter was found on the command line
 */

u8 cmdline_version_get();

 /** @} */

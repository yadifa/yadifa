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
 *  @brief yadifa
 */


// header files should not contain the generated client-config.h file
// #include "client-config.h"

#include <dnscore/cmdline.h>
#include <dnscore/host_address.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/sys_types.h>

#include "module.h"
#include "ya-conf.h"

/*----------------------------------------------------------------------------*/
#pragma mark DEFINES

#define MAIN_SECTION_NAME           "yadifa"

// server flags
#define SERVER_FL_CHROOT            0x01
#if HAS_DAEMON_SUPPORT
#define SERVER_FL_DAEMON            0x02
#endif


#define     SERVER_FL_ANSWER_FORMERR    0x08
#define     SERVER_FL_LOG_UNPROCESSABLE 0x10

#define SERVER_CTRL_PORT    53

/*----------------------------------------------------------------------------*/
#pragma mark STRUCTS



typedef struct yadifa_main_settings_s yadifa_main_settings_s;
struct yadifa_main_settings_s
{
//    host_address                                                    *server;
    char                                                       *config_file;

    u8                                                            log_level;

    /*    ------------------------------------------------------------    */

    /** @todo 20150219 gve -- #if HAS_TCL must be set, before release */
//#if HAS_TCL
    bool                                                        interactive;
//#endif // HAS_TCL
    bool                                                            verbose;
//    bool                                                             enable;
};



/*----------------------------------------------------------------------------*/
#pragma mark PROTOTYPES 


/**
 * 
 * 
 * @return 
 */

ya_result ya_conf_init();

/**
 * Reads the configuration
 * Prints the help
 * 
 * 
 * @param cmdline_table
 * @param filter
 * @param argc
 * @param argv
 * @return 0 : continue, >0 : help given, <0 : an error code
 */

ya_result ya_conf_read(const cmdline_desc_s *cmdline_table, int argc, char **argv, cmdline_filter_callback *filter,
                           void *filter_arg, const char *rcfilename);

ya_result ya_conf_finalize();                     // not called, should be called even if it does nothing, for structure


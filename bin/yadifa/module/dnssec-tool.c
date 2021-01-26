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

#include "client-config.h"

#define DNSSEC_TOOL_C_

#include <dnscore/logger_handle.h>
#include <dnscore/cmdline.h>
#include <dnscore/config-cmdline.h>
#include <dnscore/config_settings.h>
#include <dnscore/message-viewer.h>

#include <dnslg/config-resolver.h>

#include "module/dnssec-tool.h"

#include "common-config.h"

/*------------------------------------------------------------------------------
 * DEFINES */

#define     DEF_VAL_CLASS                           "CTRL"
#define     DEF_VAL_TYPE                            "A"


/*------------------------------------------------------------------------------
 * LOGGER */

extern logger_handle *g_client_logger;

#define MODULE_MSG_HANDLE g_client_logger


struct logger_name_handle_s
{
    const char *name;
    logger_handle **handlep;
};

static const struct logger_name_handle_s logger_name_handles[] =
{
    { "client", &g_client_logger },
    { NULL, NULL                 }
};



// ********************************************************************************
// ***** module settings
// ********************************************************************************

static dnssec_tool_settings_s g_dnssec_tool_settings;

#define CONFIG_TYPE dnssec_tool_settings_s
CONFIG_BEGIN(dnssec_tool_desc)

CONFIG_DNS_CLASS( qclass,           DEF_VAL_CLASS                                                  )
CONFIG_DNS_TYPE(  qtype,            DEF_VAL_TYPE                                                   )
CONFIG_FQDN(      qname,            "."                                                            )

CONFIG_FLAG16(    dnssec,           CONFIG_FLAG_OFF,      question_mode,  QM_FLAGS_DNSSEC          )
CONFIG_FLAG16(    ignore_tc,        CONFIG_FLAG_OFF,      question_mode,  QM_FLAGS_INGORE_TC       )
CONFIG_FLAG16(    recursive,        CONFIG_FLAG_ON,       question_mode,  QM_FLAGS_RECURSIVE       )
CONFIG_FLAG16(    trace,            CONFIG_FLAG_OFF,      question_mode,  QM_FLAGS_TRACE           )

CONFIG_FLAG16(    aaonly,           CONFIG_FLAG_OFF,      question_mode,  QM_FLAGS_AAONLY          )
CONFIG_FLAG16(    adflag,           CONFIG_FLAG_OFF,      question_mode,  QM_FLAGS_AD              )
CONFIG_FLAG16(    cdflag,           CONFIG_FLAG_OFF,      question_mode,  QM_FLAGS_CD              )

CONFIG_FLAG16(    additional,       CONFIG_FLAG_ON,       view_mode_with, MESSAGE_VIEWER_WITH_ADDITIONAL       )
CONFIG_FLAG16(    answer,           CONFIG_FLAG_ON,       view_mode_with, MESSAGE_VIEWER_WITH_ANSWER           )
CONFIG_FLAG16(    authority,        CONFIG_FLAG_ON,       view_mode_with, MESSAGE_VIEWER_WITH_AUTHORITY        )
CONFIG_FLAG16(    question,         CONFIG_FLAG_ON,       view_mode_with, MESSAGE_VIEWER_WITH_QUESTION         )

CONFIG_FLAG16(    json,             CONFIG_FLAG_OFF,      view_mode,      VM_JSON                  )
CONFIG_FLAG16(    multiline,        CONFIG_FLAG_OFF,      view_mode,      VM_MULTILINE             )
CONFIG_FLAG16(    parse,            CONFIG_FLAG_OFF,      view_mode,      VM_PARSE_FRIENDLY        )
CONFIG_FLAG16(    short,            CONFIG_FLAG_OFF,      view_mode,      VM_SHORT                 )
CONFIG_FLAG16(    xml,              CONFIG_FLAG_OFF,      view_mode,      VM_XML                   )
CONFIG_FLAG16(    wire,             CONFIG_FLAG_OFF,      view_mode,      VM_WIRE                  )

CONFIG_FLAG16(    udp,              CONFIG_FLAG_ON,       protocol,       QM_PROTOCOL_UDP          )
CONFIG_FLAG16(    tcp,              CONFIG_FLAG_ON,       protocol,       QM_PROTOCOL_TCP          )

CONFIG_FLAG16(    ipv6,             CONFIG_FLAG_OFF,      protocol,       QM_PROTOCOL_IPV6         )
CONFIG_FLAG16(    ipv4,             CONFIG_FLAG_ON,       protocol,       QM_PROTOCOL_IPV4         )

CONFIG_END(dnssec_tool_desc)
#undef CONFIG_TYPE






// ********************************************************************************
// ***** module command line struct
// ********************************************************************************

CMDLINE_BEGIN(dnssec_tool_cmdline)

// main
CMDLINE_SECTION(  "main")
CMDLINE_OPT(      "config",          'C',  "config_file"               )

CMDLINE_OPT(      "qname",           'q', "qname"                      )

CMDLINE_OPT(      "type",            't', "qtype"                      )
CMDLINE_OPT(      "class",           'c', "qclass"                     )

CMDLINE_BOOL(     "aaonly",           0,  "aaonly"                     )
CMDLINE_BOOL(     "adflag",           0,  "adflag"                     )
CMDLINE_BOOL(     "cdflag",           0,  "cdflag"                     )
CMDLINE_BOOL_NOT( "noaaonly",         0,  "aaonly"                     )
CMDLINE_BOOL_NOT( "noadflag",         0,  "adflag"                     )
CMDLINE_BOOL_NOT( "nocdflag",         0,  "cdflag"                     )

CMDLINE_BOOL(     "dnssec",           0,  "dnssec"                     )
CMDLINE_BOOL(     "ignore_tc",        0,  "ignore_tc"                  )
CMDLINE_BOOL(     "recursive",        0,  "recursive"                  )
CMDLINE_BOOL(     "trace",            0,  "trace"                      )
CMDLINE_BOOL_NOT( "notrace",          0,  "trace"                      )
CMDLINE_BOOL_NOT( "norecursive",      0,  "recursive"                  )

CMDLINE_BOOL(     "additional",       0,  "additional"                 )
CMDLINE_BOOL(     "answer",           0,  "answer"                     )
CMDLINE_BOOL(     "authority",        0,  "authority"                  )
CMDLINE_BOOL(     "question",         0,  "question"                   )
CMDLINE_BOOL_NOT( "noadditional",     0,  "additional"                 )
CMDLINE_BOOL_NOT( "noanswer",         0,  "answer"                     )
CMDLINE_BOOL_NOT( "noauthority",      0,  "authority"                  )
CMDLINE_BOOL_NOT( "noquestion",       0,  "question"                   )

CMDLINE_BOOL(     "json",             0,  "json"                       )
CMDLINE_BOOL(     "multiline",        0,  "multiline"                  )
CMDLINE_BOOL(     "parse",            0,  "parse"                      )
CMDLINE_BOOL(     "short",            0,  "short"                      )
CMDLINE_BOOL(     "xml",              0,  "xml"                        )
CMDLINE_BOOL(     "wire",             0,  "wire"                       )

CMDLINE_BOOL(     "udp",              0,  "udp"                        )
CMDLINE_BOOL(     "tcp",              0,  "tcp"                        )
CMDLINE_BOOL(     "ipv4",            '4', "ipv4"                       )
CMDLINE_BOOL(     "ipv6",            '6', "ipv6"                       )

CMDLINE_OPT(      "port",            'p', "server_port"                )

// resolver section
CMDLINE_RESOLVER(dnssec_tool_cmdline)

// command line
CMDLINE_VERSION_HELP(dnssec_tool_cmdline)


CMDLINE_END(dnssec_tool_cmdline)



// ********************************************************************************
// ***** command help usage
// ********************************************************************************

static const char dnssec_tool_cmdline_help[] =
        "command: yadifa [-c config] [-s server] [-v] command\n\n"
        "\toptions:\n"
        "\t\t--config/-c <config_file>   : use <config_file> as configuration\n"

        

        "\n"
        "\t\t--version/-V                : view version\n"
        "\t\t--help/-h                   : show this help text\n";



// ********************************************************************************
// ***** module initializer
// ********************************************************************************

static ya_result
dnssec_tool_init()
{
    ya_result return_code;


    for(const struct logger_name_handle_s *name_handle = logger_name_handles; name_handle->name != NULL; name_handle++)
    {
        logger_handle_create(name_handle->name, name_handle->handlep);
    }

    if(FAIL(return_code = config_init()))
    {
        return return_code;
    }

    return return_code;
}



// ********************************************************************************
// ***** module finalizer
// ********************************************************************************

static ya_result
dnssec_tool_finalize()
{
    config_error_s cfgerr;
    ya_result return_code;

    config_set_source(CONFIG_SOURCE_DEFAULT);

    if(ISOK(return_code = config_set_default(&cfgerr)))
    {
        config_postprocess();
    }
    else
    {
        formatln("defaults: internal error: %s:%u: '%s': %r", cfgerr.file, cfgerr.line_number, cfgerr.line, return_code);
    }

    return return_code;
}



// ********************************************************************************
// ***** module register
// ********************************************************************************

static int
dnssec_tool_register(int priority)
{
    (void)priority;
    ya_result ret;

    /*    ------------------------------------------------------------    */

    // to handle version & help
    // to handle version & help

    config_set_source(CONFIG_SOURCE_CMDLINE);

    if (FAIL(ret = config_register_cmdline(6))) {
        return ret;
    }

    // init and register main settings container
    ZEROMEMORY(&g_dnssec_tool_settings, sizeof(g_dnssec_tool_settings));
    if (FAIL(
        ret = config_register_struct("main", dnssec_tool_desc, &g_dnssec_tool_settings, 5))) {
        return ret;
    }

#if 1
    if (FAIL(ret = config_register_resolver(4))) {
        return ret;
    }
#endif
    return ret;
}



// ********************************************************************************
// ***** module setup
// ********************************************************************************

static int
dnssec_tool_setup()
{
    return SUCCESS; // returns anything else than 0 => program will exit
}



// ********************************************************************************
// ***** module command line callback
// ********************************************************************************

static ya_result
dnssec_tool_cmdline_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
{
    (void)desc;
    (void)callback_owned;
    if(strcmp(arg_name, "--") == 0)
    {
        return CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS;
    }

    return SUCCESS;
}



// ********************************************************************************
// ***** module run
// ********************************************************************************

static ya_result
dnssec_tool_run()
{
//    uint16_t                                                          i = 0;
    ya_result                                              return_code = OK;

    /*    ------------------------------------------------------------    */

    log_debug("DNSSEC TOOL RUN");


    return return_code;
}



// ********************************************************************************
// ***** module virtual table
// ********************************************************************************

const module_s dnssec_tool_program =
{
    dnssec_tool_init,                   // module initialiser
    dnssec_tool_finalize,               // module finaliser
    dnssec_tool_register,               // module register
    dnssec_tool_setup,                  // module setup
    dnssec_tool_run,                    // module run

    module_default_cmdline_help_print,  //

    dnssec_tool_cmdline,                // module command line struct
    dnssec_tool_cmdline_callback,       // module command line callback
    NULL,                               // module filter arguments

    "yadifa dns checker config",        // module public name
    "dnssec_tool",                      // module command (name as executable match)
    "dcc",                              // module parameter (name as first parameter)
    dnssec_tool_cmdline_help,           // module text to be printed upon help request
    ".dnssec_tool.rc"                   // module rc file (ie: ".modulerc"
};



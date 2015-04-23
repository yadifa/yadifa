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
*  @brief yadifa
*/

//#include <dnscore/logger_handle.h>
//#include <dnscore/cmdline.h>
//#include <dnscore/config-cmdline.h>
//#include <dnscore/config_settings.h>

#include <dnscore/input_stream.h>
#include <dnslg/config-resolver.h>

#include <dnscore/cmdline.h>
#include <dnscore/config-cmdline.h>

#include <dnscore/config_settings.h>

// automatic created include file
#include "client-config.h"

#include "common-config.h"
#include "yazu-config.h"

/*----------------------------------------------------------------------------*/

#define DEF_VAL_CLASS                                              "CTRL"
#define DEF_VAL_TYPE                                                  "A"


/*----------------------------------------------------------------------------*/

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


/*----------------------------------------------------------------------------*/

#define CONFIG_TYPE config_yazu_settings_s
CONFIG_BEGIN(config_yazu_desc)

CONFIG_HOST_LIST_EX( server,        DEF_VAL_SERVER,       CONFIG_HOST_LIST_FLAGS_DEFAULT, 1        )
CONFIG_DNS_CLASS(    qclass,        DEF_VAL_CLASS                                                  )
CONFIG_DNS_TYPE(     qtype,         DEF_VAL_TYPE                                                   )
CONFIG_FQDN(         qname,         "."                                                            )
CONFIG_FQDN(         qzone,         "."                                                            )
CONFIG_U32(          qttl,          "3600"                                                         )
CONFIG_FILE(         file,          '\0'                                                           )
CONFIG_STRING(       update,        '\0'                                                           )






CONFIG_FLAG16(  json,             CONFIG_FLAG_OFF,      view_mode,      VM_JSON                  )
CONFIG_FLAG16(  multiline,        CONFIG_FLAG_OFF,      view_mode,      VM_MULTILINE             )
CONFIG_FLAG16(  parse,            CONFIG_FLAG_OFF,      view_mode,      VM_PARSE_FRIENDLY        )
CONFIG_FLAG16(  short,            CONFIG_FLAG_OFF,      view_mode,      VM_SHORT                 )
CONFIG_FLAG16(  xml,              CONFIG_FLAG_OFF,      view_mode,      VM_XML                   )
CONFIG_FLAG16(  wire,             CONFIG_FLAG_OFF,      view_mode,      VM_WIRE                  )

CONFIG_FLAG16(  udp,              CONFIG_FLAG_ON,       protocol,       QM_PROTOCOL_UDP          )
CONFIG_FLAG16(  tcp,              CONFIG_FLAG_ON,       protocol,       QM_PROTOCOL_TCP          )

CONFIG_FLAG16(  ipv6,             CONFIG_FLAG_OFF,      protocol,       QM_PROTOCOL_IPV6         )
CONFIG_FLAG16(  ipv4,             CONFIG_FLAG_ON,       protocol,       QM_PROTOCOL_IPV4         )

CONFIG_END(config_yazu_desc)
#undef CONFIG_TYPE


config_yazu_settings_s g_yazu_main_settings;

/// use global resolver and general command line settings
//extern config_resolver_settings_s g_resolver_settings;


/*----------------------------------------------------------------------------*/

// configuration specific to the command line

CMDLINE_BEGIN(yazu_cmdline)

// main
CMDLINE_SECTION(  "yazu")
CMDLINE_OPT(      "qclass",            0, "qclass"                     )
CMDLINE_OPT(      "config",          'c', "config_file"                )
CMDLINE_OPT(      "qname",           'q', "qname"                      )
CMDLINE_OPT(      "qzone",           'z', "qzone"                      )
CMDLINE_OPT(      "qttl",              0, "qttl"                       )
CMDLINE_OPT(      "server",          's', "server"                     )
CMDLINE_OPT(      "type",            't', "qtype"                      )
CMDLINE_OPT(      "file",            'f', "file"                       )
CMDLINE_OPT(      "update",          'u', "update"                     )

//CMDLINE_BOOL(     "aaonly",           0,  "aaonly"                     )
//CMDLINE_BOOL(     "adflag",           0,  "adflag"                     )
//CMDLINE_BOOL(     "cdflag",           0,  "cdflag"                     )

//CMDLINE_BOOL(     "dnssec",           0,  "dnssec"                     )
//CMDLINE_BOOL(     "ignore_tc",        0,  "ignore_tc"                  )
//CMDLINE_BOOL(     "recursive",        0,  "recursive"                  )
//CMDLINE_BOOL(     "trace",            0,  "trace"                      )

//CMDLINE_BOOL(     "additional",       0,  "additional"                 )
//CMDLINE_BOOL(     "answer",           0,  "answer"                     )
//CMDLINE_BOOL(     "authority",        0,  "authority"                  )
//CMDLINE_BOOL(     "question",         0,  "question"                   )
//CMDLINE_BOOL_NOT( "noadditional",     0,  "additional"                 )
//CMDLINE_BOOL_NOT( "noanswer",         0,  "answer"                     )
//CMDLINE_BOOL_NOT( "noauthority",      0,  "authority"                  )
//CMDLINE_BOOL_NOT( "noquestion",       0,  "question"                   )

CMDLINE_BOOL(     "json",             0,  "json"                       )
CMDLINE_BOOL(     "multiline",        0,  "multiline"                  )
CMDLINE_BOOL(     "parse",            0,  "parse"                      )
CMDLINE_BOOL(     "short",            0,  "short"                      )
CMDLINE_BOOL(     "xml",              0,  "xml"                        )
CMDLINE_BOOL(     "wire",             0,  "wire"                       )

//CMDLINE_BOOL(     "udp",              0,  "udp"                        )
//CMDLINE_BOOL(     "tcp",              0,  "tcp"                        )
//CMDLINE_BOOL(     "ipv4",            '4', "ipv4"                       )
//CMDLINE_BOOL(     "ipv6",            '6', "ipv6"                       )


CMDLINE_OPT(      "port",            'p', "server_port"                )

#if 0 /* fix */
#else

// resolver section
CMDLINE_RESOLVER(yazu_cmdline)
#endif

// command line
CMDLINE_VERSION_HELP(yazu_cmdline)


CMDLINE_END(yazu_cmdline)


/*----------------------------------------------------------------------------*/

/** \brief  Prints the help page when asked with -h or -V or a incorrect command
 *          line
 *
 *  @param NONE
 *
 *  @return NONE
 */
static void
yazu_print_usage(void)
{
    puts("\n"
            "\t\toptions:\n"
            "\t\t--config/-C <config_file>                 : use <config_file> as configuration\n"


            "Update options:\n"
            "\t\t--class/-c <class>                        : which 'class' to be queried\n"
            "\t\t--type/-t <type>                          : which type to be queried(default:a and aaaa)\n"
            "\t\t--server/-s <string [port <port number>]> : connect to <fqdn> on port <portnumber>\n"
            "\t\t--ttl <number>                            : time to live in seconds\n"
            "\t\t--zone/-z <domain name>                   : domain name is a FQDN\n"
            "\t\t                                            <string> can be a name or an IP address\n"
            "\t\t--zone/-z <domain name>                   : domain name is a FQDN\n"

            "\t\t---y <hmac:name:key>                      : base64 tsig key\n"
            "\t\t--k  <FILENAME>                           : filename with base64 tsig key in\n"

            "\t\t---prereq_nxdomain  <string>              : string\n"
            "\t\t---prereq_yxdomain  <string>              : string\n"
            "\t\t---prereq_nxrrset  <string>               : string\n"
            "\t\t---prereq_nyrrset  <string>               : string\n"
            "\t\t---update  <command>                      : <command> can be \"add\" or \"delete\"\n"


            "IP Protocol options:\n"
            "\t\t--udp-tries <number>                      : number of udp attempts (default: 3)\n"
            "\t\t--udp-retry <number>                      : number of udp retries (default: 3)\n"
            "\t\t--udp-time  <number>                      : query timeout\n"
            );

    puts("\n"

            "\n"
            "\t\t--version/-V                              : view version\n"
            "\t\t--help/-h                                 : show this help text\n"

        );
}


/** @brief  yadifa_print_authors prints the authors who wrote yadifa
 *
 *  @param -- nothing --
 *  @return -- nothing --
 */
static void
yazu_print_authors()
{
    print("\n"
            "\t\tDNSUPDATE authors:\n"
            "\t\t------------------\n"
            "\t\t\n"
            "\t\tGery Van Emelen\n"
            "\t\tEric Diaz Fernandez\n"
            "\n"
            "\t\tContact: " PACKAGE_BUGREPORT "\n"
        );
    flushout();
}


static void
yazu_print_version(int level)
{
    switch(level)
    {
        case 1:
            osformatln(termout, "%s %s (%s)", PROGRAM_NAME, PROGRAM_VERSION, RELEASEDATE);
            break;
        case 2:
            osformatln(termout, "%s %s (released %s, compiled %s)", PROGRAM_NAME, PROGRAM_VERSION, RELEASEDATE, COMPILEDATE);
            break;
        case 3:
            osformatln(termout, "%s %s (released %s, compiled %s)", PROGRAM_NAME, PROGRAM_VERSION, RELEASEDATE, COMPILEDATE);
            yazu_print_authors();
            break;
        default:
            osformat(termout, "\nYou want to know too much!\n\n");
            break;
    }
}


/*----------------------------------------------------------------------------*/

ya_result
yazu_config_finalise()
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
        formatln("defaults: internal error: %s:%u : '%s': %r", cfgerr.file, cfgerr.line_number, cfgerr.line, return_code);
    }


    /// @todo 20150311 gve -- set all the server ports to the default value if they are 0

    return return_code;
}


static ya_result
yazu_config_cmdline_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
{
    if(strcmp(arg_name, "--") == 0)
    {
        return CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS;
    }

    return SUCCESS;
}


ya_result
yazu_config_cmdline(int argc, char **argv)
{
    input_stream                                                  config_is;
    config_error_s                                                   cfgerr;
    ya_result                                                   return_code;

    /*    ------------------------------------------------------------    */

    config_set_source(CONFIG_SOURCE_HIGHEST);

    if(FAIL(return_code = cmdline_parse(yazu_cmdline, argc, argv, yazu_config_cmdline_callback, NULL, &config_is)))
    {
#ifdef DEBUG
        formatln("cmdline_parse failed: %r", return_code);
        flushout();
#endif // DEBUG
        return return_code;
    }


    config_set_source(CONFIG_SOURCE_CMDLINE);

    if(FAIL(return_code = config_read_from_buffer((const char*)bytearray_input_stream_buffer(&config_is),
                    bytearray_input_stream_size(&config_is),  "command-line",
                    &cfgerr)))
    {
        formatln("%s: parsing error: %s:%u : '%s': %r", "cmdline", cfgerr.file, cfgerr.line_number, cfgerr.line, return_code);
        flushout();

        input_stream_close(&config_is);

        return return_code;
    }

    input_stream_close(&config_is);
    flushout();

    return_code = 0;

    /* check if cmd '--version' */
    if(cmdline_version_get() > 0)
    {
        yazu_print_version(cmdline_version_get());

        return_code++;
    }

    /* check if cmd '--help' */
    if(cmdline_help_get())
    {
        yazu_print_usage();
        return_code++;
    }

    //     return_code = config_value_set_to_default("main", "config", &cfgerr);
    //
    //
   
    /// @todo 20150311 gve -- this part should be moved somewhere else
    ya_result err;

    config_set_source(CONFIG_SOURCE_DEFAULT);
    if(ISOK(err = config_set_default(&cfgerr)))
    {
        formatln("config default values set");
    }
    else
    {
        formatln("defaults: internal error: %s:%u : '%s': %r", cfgerr.file, cfgerr.line_number, cfgerr.line, err);
    }


    return return_code;
}


ya_result
yazu_config_init()
{
    ya_result                                                   return_code;

    /*    ------------------------------------------------------------    */

    /** @todo 20150211 gve -- revisiting mabye this can be removed or put in some kind of option */
    /* 1. log handling. Is this really needed? */
    for(const struct logger_name_handle_s *name_handle = logger_name_handles; name_handle->name != NULL; name_handle++)
    {
        logger_handle_create(name_handle->name, name_handle->handlep);
    }

    /** @todo 20150311 gve -- does nothing at the moment, maybe it will be used later */
    if(FAIL(return_code = config_init()))
    {
        return return_code;
    }

    // to handle version & help

    /* 3. register commadn line optoins: version and help */
    config_set_source(CONFIG_SOURCE_CMDLINE);

    if(FAIL(return_code = config_register_cmdline(6)))
    {
        return return_code;
    }


    /* 4. register main options: ....
     *
     * init and register main settings container */
    ZEROMEMORY(&g_yazu_main_settings, sizeof(g_yazu_main_settings));
    if(FAIL(return_code = config_register_struct("yazu", config_yazu_desc, &g_yazu_main_settings, 5)))
    {
        return return_code;
    }


    if(FAIL(return_code = config_register_resolver(4)))
    {
        return return_code;
    }

    /** @todo 20150311 gve -- still need todo something about TSIG for yazu */


    return return_code;
}


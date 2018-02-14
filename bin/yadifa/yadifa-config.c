/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2018, EURid vzw. All rights reserved.
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

#include <ctype.h>
#include <sys/stat.h>

#include <dnscore/logger_handle.h>
#include <dnscore/cmdline.h>
#include <dnscore/config-cmdline.h>
#include <dnscore/config_settings.h>
//#include <dnscore/rfc.h>
#include <dnscore/ctrl-rfc.h>
#include <dnscore/string_set.h>

#include <dnslg/config-resolver.h>
#include <sys/stat.h>

// automatic created include file
#include "client-config.h"


#include "yadifa-config.h"
#include "common-config.h"

#include "buildinfo.h"

/*----------------------------------------------------------------------------*/
#pragma mark DEFINES 

#define DEF_VAL_CLASS                                              "CTRL"
#define DEF_VAL_TYPE                                              "TYPE0"
#define DEF_YADIFA_CONF                         SYSCONFDIR "/yadifa.conf"

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

extern logger_handle *g_client_logger;
#define MODULE_MSG_HANDLE g_client_logger


struct logger_name_handle_s
{
    const char                                                    *name;
    logger_handle                                             **handlep;
};

static const struct logger_name_handle_s logger_name_handles[] =
{
    { "client", &g_client_logger },
    { NULL, NULL                 }
};


/*----------------------------------------------------------------------------*/
#pragma mark CONFIG


/// main container
#define CONFIG_TYPE config_main_settings_s
CONFIG_BEGIN(config_main_desc)

CONFIG_HOST_LIST_EX( server,        DEF_VAL_SERVER,       CONFIG_HOST_LIST_FLAGS_DEFAULT, 1        )
CONFIG_DNS_CLASS(    qclass,        DEF_VAL_CLASS                                                  )
CONFIG_DNS_TYPE(     qtype,         DEF_VAL_TYPE                                                   )
CONFIG_FQDN(         qname,         "."                                                            )
CONFIG_FQDN(         tsig_key_name, "ctrl-key"                                                     )
CONFIG_BOOL(         enable,        "on"                                                           )
CONFIG_BOOL(         clean,         "off"                                                          )
CONFIG_STRING(       config_file,   DEF_YADIFA_CONF                                                )



CONFIG_BOOL(         verbose,       "off"                                                          )

    /** @todo 20150219 gve -- must be removed before release */
CONFIG_U8(           log_level,     "6"                                                            ) // 6 is MSG_INFO


CONFIG_END(config_main_desc)
#undef CONFIG_TYPE

config_main_settings_s g_yadifa_main_settings;

/// use global resolver and general command line settings
//extern config_resolver_settings_s g_resolver_settings;


/*----------------------------------------------------------------------------*/
#pragma mark COMMAND LINE

// configuration specific to the command line

CMDLINE_BEGIN(yadifa_cmdline)

// main
CMDLINE_SECTION(  "yadifa")
CMDLINE_OPT(      "config",          'c', "config_file"                )

CMDLINE_BOOL(     "clean",             0,  "clean"                      )
CMDLINE_BOOL_NOT( "noclean",           0,  "clean"                      )
CMDLINE_OPT(      "level",           'l', "log_level"                  )
CMDLINE_OPT(      "qname",           'q', "qname"                      )
CMDLINE_OPT(      "server",          's', "server"                     )
CMDLINE_OPT(      "type",            't', "qtype"                      )
CMDLINE_OPT(      "key-name",        'K', "tsig_key_name"              )



CMDLINE_BOOL(     "enable",            0,  "enable"                     )
CMDLINE_BOOL_NOT( "disable",           0,  "enable"                     )
CMDLINE_BOOL(     "verbose",         'v',  "verbose"                    )

CMDLINE_BOOL(     "json",              0,  "json"                       )
CMDLINE_BOOL(     "multiline",         0,  "multiline"                  )
CMDLINE_BOOL(     "parse",             0,  "parse"                      )
CMDLINE_BOOL(     "short",             0,  "short"                      )
CMDLINE_BOOL(     "xml",               0,  "xml"                        )
CMDLINE_BOOL(     "wire",              0,  "wire"                       )

// resolver section
CMDLINE_RESOLVER(yadifa_cmdline)

// command line
CMDLINE_VERSION_HELP(yadifa_cmdline)

CMDLINE_END(yadifa_cmdline)

typedef value_name_table ctrl_type_table;
static string_node *ctrl_type_set = NULL;

/** @todo 20150219 gve -- check for HAS_CTRL instead of 1 as if statement */
const ctrl_type_table ctrl_type[] = {
#if 1
    { TYPE_CTRL_SRVCFGRELOAD,     TYPE_CTRL_SRVCFGRELOAD_NAME     },
    { TYPE_CTRL_SRVLOGREOPEN,     TYPE_CTRL_SRVLOGREOPEN_NAME     },
    { TYPE_CTRL_SRVLOGLEVEL,      TYPE_CTRL_SRVLOGLEVEL_NAME      },
    { TYPE_CTRL_SRVSHUTDOWN,      TYPE_CTRL_SHUTDOWN_NAME         },
    { TYPE_CTRL_SRVSHUTDOWN,      "HALT"                          },
    { TYPE_CTRL_SRVSHUTDOWN,      "STOP"                          },
    { TYPE_CTRL_ZONECFGRELOAD,    TYPE_CTRL_ZONECFGRELOAD_NAME    },
    { TYPE_CTRL_ZONECFGRELOADALL, TYPE_CTRL_ZONECFGRELOADALL_NAME },
    { TYPE_CTRL_ZONEFREEZE,       TYPE_CTRL_ZONEFREEZE_NAME       },

    { TYPE_CTRL_ZONERELOAD,       TYPE_CTRL_ZONERELOAD_NAME       },
    { TYPE_CTRL_ZONEUNFREEZE,     TYPE_CTRL_ZONEUNFREEZE_NAME     },

#endif
    { 0,                          NULL                            }
};

typedef struct command_translation_table command_translation_table;

struct command_translation_table
{
    const char *name;                       // name of the command
    const char *field_name;                 // what field to set
    const char *field_value;                // what value to put in the set
    const char *field_value_with_parameter; // what value to put in the set in case of parameter
    const char *parameter_field_name;       // what field to put the parameter in
};

static command_translation_table yadifa_commands_translation_table[] =
{
    { "reload",        "qtype", NULL,                             TYPE_CTRL_ZONERELOAD_NAME,    "qname"  },
    { "cfgreload",     "qtype", TYPE_CTRL_SRVCFGRELOAD_NAME,      NULL,                         NULL     },
    { "sync",          "qtype", NULL,                             TYPE_CTRL_ZONESYNC_NAME,      "qname"  },
    { "querylog",      "qtype", NULL,                             TYPE_CTRL_SRVQUERYLOG_NAME,   "enable" },
    { "loglevel",      "qtype", NULL,                             TYPE_CTRL_SRVLOGLEVEL_NAME,   "log_level"  },
    { "logreopen",     "qtype", TYPE_CTRL_SRVLOGREOPEN_NAME,      NULL,                         NULL     },
    { "zonecfgreload", "qtype", TYPE_CTRL_ZONECFGRELOADALL_NAME , TYPE_CTRL_ZONECFGRELOAD_NAME, "qname"  },

    { "freeze",        "qtype", NULL,                             TYPE_CTRL_ZONEFREEZE_NAME,    "qname"  },
    { "unfreeze",      "qtype", NULL,                             TYPE_CTRL_ZONEUNFREEZE_NAME,  "qname"  },
    { "shutdown",      "qtype", TYPE_CTRL_SHUTDOWN_NAME,          NULL,                         NULL     },

    {NULL, NULL, NULL, NULL, NULL}
};


/*----------------------------------------------------------------------------*/
#pragma mark GENERAL FUNCTIONS

/** @brief ctrl_rfc_init
 *  
 *  @param -- nothing --
 *  @return -- nothing --
 */     
void
ctrl_rfc_init()
{
    int i;

    string_set_avl_init(&ctrl_type_set);
    for(i = 0; qtype[i].id != 0; i++)
    {
        string_node* node = string_set_avl_insert(&ctrl_type_set, ctrl_type[i].data);
#if 1
        node->value       = ctrl_type[i].id;
#endif
    }
}


/** @brief get_ctrl_type_from_name
 *  
 *  @param src const char *
 *  @param dst u16 *
 *  @retval dst ctrl type
 *  @return ctrl type
 *  @return UNKNOWN_DNS_TYPE
 */     
int
get_ctrl_type_from_name(const char *src, u16 *dst)
{
    string_node *node = string_set_avl_find(&ctrl_type_set, (const char *)src);

    if(node != NULL)
    {
        u16 t = node->value;
        *dst = t;
        return t;
    }
    else
    {
        return UNKNOWN_DNS_TYPE;
    }
}


/** @brief get_ctrl_type_from_case_name
 *  @discussion this is the same function as get_ctrl_type_from_name
 *  except that the src will be uppercase checked
 *  
 *  @param src const char *
 *  @param dst u16 *
 *  @retval dst ctrl type
 *  @return ctrl type
 *  @return UNKNOWN_DNS_TYPE
 */     
int
get_ctrl_type_from_case_name(const char *src, u16 *dst)
{
    char txt[16];
    s32 n = strlen(src);
    if(n > sizeof(txt))
    {
        return UNKNOWN_DNS_TYPE;
    }

    for(s32 i = 0; i < n; i++)
    {
        txt[i] = toupper(src[i]);
    }

    txt[n] = '\0';

    return get_ctrl_type_from_name(txt, dst);
}



/** @brief  yadifa_print_usage prints the help page when asked with -h or -V or a incorrect command
 *          line
 *
 *  @param -- nothing --
 *  @return -- nothing --
 */
void
yadifa_print_usage(void)
{
    println("\n"
            "Usage: yadifa [-c config] [-s server] [-v] command\n\n"
            "\toptions:\n"
            "\t\t--config/-c <config_file>   : use <config_file> as configuration\n"
            "\t\t--server/-s <host>          : <host> can be an ip address or\n"
            "\t\t                            : an ip address with portnumber\n"
            "\t\t                            : e.g. \"192.0.2.1 port 53\"\n"
            "\t\t                            : note: the quotes are needed\n"
            "\t\t@<host>                     : <host> is the same as for [-s <host>]\n"



        );
    println("\n"
            "\t\t--verbose/-v                : verbose output\n"
            "\n"
            "\t\t--version/-V                : view version\n"
            "\t\t--help/-h                   : show this help text\n"

            "\n"
            "\tcommands:\n"
            "\t\tfreeze <zone>               : suspends updates to a zone\n"

            "\t\tunfreeze <zone>             : enable updates to a zone\n"

            "\t\treload <zone>               : reloads a zone from disk\n"
            "\t\tcfgreload                   : reloads settings from disk\n"
            "\t\tzonecfgreload [<zone>]      : reloads all (or specified) zone settings from disk\n"
            "\t\tsync <zone> [clean]         : writes the zone file on disk, optionally cleans up the journal\n"
            "\t\tquerylog <enable>           : enables or disables the query logging\n"
            "\t\tloglevel <level>            : sets up the maximum level of log [0;15], 6 = INFO, 15 = NULL\n"
            "\t\tlogreopen                   : closes and reopens all log files\n"
            "\t\tshutdown                    : shuts down the server\n"

            "\n"
            "\tnote:\n"
            "\t\twith ambiguity:\n"
            "\t\t-q <zone>                   : for a zone\n"
            "\t\t-t <command>                : for the command\n"
            "\t\t-K <keyname>                : for the controller\n"
            "\t\t--level/-l <number>         : for the \"loglevel\" command, [0;15], 6 = INFO, 15 = FULL\n"
            "\t\t--clean                     : for the \"sync\" command, requests to clean up the journal\n"

            "\n"
        );
}


/** @brief  yadifa_print_authors prints the authors who wrote yadifa
 *
 *  @param -- nothing --
 *  @return -- nothing --
 */
static void
yadifa_print_authors()
{
    println("\n"
            "\t\tYADIFAD authors:\n"
            "\t\t---------------\n"
            "\t\t\n"
            "\t\tGery Van Emelen\n"
            "\t\tEric Diaz Fernandez\n"
            "\n"
            "\t\tContact: " PACKAGE_BUGREPORT
         );
    flushout();
}


/** @brief  yadifa_print_version prints the authors who wrote yadifa
 *
 *  @param level int
 *  @return -- nothing --
 */
void
yadifa_print_version(int level)
{
    switch(level)
    {
	case 1:
	    osformatln(termout, "%s %s (%s)\n", PROGRAM_NAME, PROGRAM_VERSION, RELEASEDATE);
	    break;
	case 2:
#if HAS_BUILD_TIMESTAMP && defined(__DATE__)
	    osformatln(termout, "%s %s (released %s, compiled %s)\n\nbuild settings: %s\n", PROGRAM_NAME, PROGRAM_VERSION, RELEASEDATE, __DATE__, BUILD_OPTIONS);
#else
            osformatln(termout, "%s %s (released %s)\n\nbuild settings: %s\n", PROGRAM_NAME, PROGRAM_VERSION, RELEASEDATE, BUILD_OPTIONS);
#endif
	    break;
        case 3:
#if HAS_BUILD_TIMESTAMP && defined(__DATE__)
	    osformatln(termout, "%s %s (released %s, compiled %s)\n", PROGRAM_NAME, PROGRAM_VERSION, RELEASEDATE, __DATE__);
#else
            osformatln(termout, "%s %s (released %s)\n", PROGRAM_NAME, PROGRAM_VERSION, RELEASEDATE);
#endif
            yadifa_print_authors();
            break;
	default:
	    osformat(termout, "\nYou want to know too much!\n\n");
	    break;
    }
}


/*----------------------------------------------------------------------------*/
#pragma mark FUNCTIONS

/** @brief  yadifa_config_finalise
 *
 *  @param -- nothing --
 *  @return ya_result
 */
ya_result
yadifa_config_finalise()
{
    config_error_s                                                   cfgerr;
    ya_result                                                   return_code;

    /*    ------------------------------------------------------------    */

    config_set_source(CONFIG_SOURCE_DEFAULT);

    if(ISOK(return_code = config_set_default(&cfgerr)))
    {
        config_postprocess();
    }
    else
    {
        formatln("defaults: internal error: %s:%u : '%s': %r", cfgerr.file, cfgerr.line_number, cfgerr.line, return_code);
    }


    /* set all the server ports to the default value if they are 0 */
    host_set_default_port_value(g_yadifa_main_settings.server, htons(DEF_VAL_SERVER_PORT)); /** @todo 20140701 gve -- put a nice define */


    return return_code;
}

/** @brief  yadifa_config_cmdline_callback
*
*  @param desc const struct cmdline_desc_s *
*  @param arg_name const char *
*  @param callback_owned void *
*  @return ya_result
*/
static ya_result
yadifa_config_cmdline_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
{
    ya_result return_code = SUCCESS;
    
    if(strcmp(arg_name, "--") == 0)
    {
        return CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS;
    }

    if(arg_name[0] == '@')
    {

        //
        config_section_descriptor_s *desc = config_section_get_descriptor("yadifa");

        if(desc != NULL)
        {
            if(ISOK(return_code = config_value_set(desc, "server", &arg_name[1])))
            {
                /* values >= MUST be 0 or CMDLINE_ARG_STOP_PROCESSING_FLAG_OPTIONS */
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
        ptr_vector *yadifa_extras = (ptr_vector*)callback_owned;
        ptr_vector_append(yadifa_extras, strdup(arg_name));
        return_code = 0;
    }


    return return_code;
}


/** @brief  yadifa_config_cmdline
 *
 *  @param argc int
 *  @param argv char **
 *  @return ya_result
 */
ya_result
yadifa_config_cmdline(int argc, char **argv)
{
    input_stream                                                  config_is;
    config_error_s                                                   cfgerr;
    ya_result                                                   return_code;

    /*    ------------------------------------------------------------    */

    config_set_source(CONFIG_SOURCE_HIGHEST);
    
    ptr_vector yadifa_extras = EMPTY_PTR_VECTOR;

    if(FAIL(return_code = cmdline_parse(yadifa_cmdline, argc, argv, yadifa_config_cmdline_callback, &yadifa_extras, &config_is)))
    {
#ifdef DEBUG
        formatln("cmdline_parse failed: %r", return_code);
        flushout();
#endif // DEBUG
        return return_code;
    }
    
    if(ptr_vector_size(&yadifa_extras) > 0)
    {
        config_section_descriptor_s *yadifa_desc = config_section_get_descriptor("yadifa");
        
        assert(yadifa_desc != NULL);

        {
            int i = 0;
            
            char *name = (char*)ptr_vector_get(&yadifa_extras, i);
            bool has_parameter = i < ptr_vector_last_index(&yadifa_extras);
            
            bool match = FALSE;
            
            for(const command_translation_table *item = yadifa_commands_translation_table; item->name != NULL; ++item)
            {
                if(strcasecmp(name, item->name) == 0)
                {
                    // if there is a parameter AND the command supports a parameter
                    
                    if(has_parameter && (item->field_value_with_parameter != NULL && item->parameter_field_name != NULL))
                    {
                        // one
                        char *parm = (char*)ptr_vector_get(&yadifa_extras, ++i);
                        config_value_set(yadifa_desc, item->field_name, item->field_value_with_parameter);
                        config_value_set(yadifa_desc, item->parameter_field_name, parm);
                        free(parm);
                    }
                    else
                    {
                        // all
                        if(item->field_value != NULL)
                        {
                            config_value_set(yadifa_desc, item->field_name, item->field_value);
                        }
                        else
                        {
                            // requires parameter
                            osformatln(termerr,"command %s requires a parameter", name);
                            return_code = ERROR;
                        }
                    }
                    
                    match = TRUE;
                    
                    break;
                }
            }
            
            if(!match)
            {
                osformatln(termerr,"unknown command %s", name);
            }
            
            free(name);
            
            if(i < ptr_vector_last_index(&yadifa_extras))
            {
                osformat(termerr, "extranneous parameters: ");
                for(int j = i; j <= ptr_vector_last_index(&yadifa_extras); ++j)
                {
                    osprint(termerr, ptr_vector_get(&yadifa_extras, j));
                }
                osprintln(termerr, "");
            }
        }
        ptr_vector_destroy(&yadifa_extras);
    }

    if(FAIL(return_code))
    {
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

    /* check if cmd '--verion' */
    if(cmdline_version_get() > 0)
    {
        yadifa_print_version(cmdline_version_get());

        return_code++;
    }

    /* check if cmd '--help' */
    if(cmdline_help_get())
    {
        yadifa_print_usage();
        return_code++;
    }


    return return_code;
}


/** @brief yadifa_config_init
 *
 *  @param -- nothing --
 *  @return ya_result
 */
ya_result
yadifa_config_init()
{
    ya_result                                                   return_code;

    /*    ------------------------------------------------------------    */

    /** @todo 20140701 gve -- revisiting maybe this can be removed or put in some kind of option */
    /* 1. log handling. Is this really needed? */ 
    for(const struct logger_name_handle_s *name_handle = logger_name_handles; name_handle->name != NULL; name_handle++)
    {
        logger_handle_create(name_handle->name, name_handle->handlep);
    }





    /** 2. @todo 20140701 gve -- does nothing at the moment, maybe it will be used later */
    if(FAIL(return_code = config_init()))
    {
        return return_code;
    }


    /* 3. register command line options: version and help */
    config_set_source(CONFIG_SOURCE_CMDLINE);

    if(FAIL(return_code = config_register_cmdline(6)))
    {
        return return_code;
    }


    /* 4. register main options: qname, qclass, qtype, ...
     *
     * init and register main settings container */
    ZEROMEMORY(&g_yadifa_main_settings, sizeof(g_yadifa_main_settings));
    if(FAIL(return_code = config_register_struct("yadifa", config_main_desc, &g_yadifa_main_settings, 5)))
    {
        return return_code;
    }
    
    if(FAIL(return_code = config_register_key("key", 7)))
    {
        return return_code;
    }


    return return_code;
}


char *
yadifa_config_file_get()
{
    struct stat fileinfo;

    if(g_yadifa_main_settings.config_file != NULL)
    {
        if(strlen(g_yadifa_main_settings.config_file) > 0)
        {
            if(stat(g_yadifa_main_settings.config_file, &fileinfo) < 0)
            {
                formatln("error: %s has error: %lu", g_yadifa_main_settings.config_file, ERRNO_ERROR);

                return NULL; // ERRNO_ERROR
            }

            /* Is it a regular file */
            if(!S_ISREG(fileinfo.st_mode))
            {
                formatln("error: %s is not a regular file", g_yadifa_main_settings.config_file);

                return NULL; // CONFIG_NOT_A_REGULAR_FILE;
            }

            return g_yadifa_main_settings.config_file;
        }
    }

    return NULL;
}




/*    ------------------------------------------------------------    */


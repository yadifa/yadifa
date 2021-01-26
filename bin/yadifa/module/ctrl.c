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

#define CTRL_C_ 1

/** @note: here we define the variable that is holding the default logger handle for the current source file
 *         Such a handle should NEVER been set in an include file.
 */

#include "client-config.h"

#include <sys/time.h>
#include <unistd.h>
#include <strings.h>

#include "common-config.h"
#include "common.h"
#include "module.h"
#include "ya-conf.h"
#include "module/ctrl.h"
#include "query-result.h"
#include "message-viewer-dig.h"

#include <dnscore/cmdline.h>
#include <dnscore/config-cmdline.h>
#include <dnscore/config_settings.h>
#include <dnscore/ctrl-rfc.h>
#include <dnscore/logger.h>
#include <dnscore/logger_handle.h>
#include <dnscore/message.h>
#include <dnscore/output_stream.h>  // needed because of an issue in cmdline
#include <dnscore/packet_writer.h>
#include <dnscore/tcp_io_stream.h>
#include <dnslg/dns.h>
#include <dnscore/message-buffer.h>

/*----------------------------------------------------------------------------*/
#pragma mark DEFINES

#define DEF_VAL_CLASS                                              "CTRL"
#define DEF_VAL_TYPE                                              "TYPE0"
#define DEF_YADIFA_CONF                         SYSCONFDIR "/yadifa.conf"

#define CTRL_SECTION_NAME "yadifa-ctrl"

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

extern logger_handle *g_yadifa_logger;
#define MODULE_MSG_HANDLE g_yadifa_logger

// ********************************************************************************
// ***** module settings
// ********************************************************************************

static yadifa_ctrl_settings_s g_yadifa_ctrl_settings;

#define CONFIG_TYPE yadifa_ctrl_settings_s
CONFIG_BEGIN(yadifa_ctrl_settings_desc)
CONFIG_HOST_LIST_EX( server,        DEF_VAL_SERVER,       CONFIG_HOST_LIST_FLAGS_DEFAULT, 1        )
CONFIG_DNS_CLASS(    qclass,        DEF_VAL_CLASS                                                  )
CONFIG_DNS_TYPE(     qtype,         DEF_VAL_TYPE                                                   )
CONFIG_U16(          port,          DEF_VAL_SERVERPORT                                             )
CONFIG_FQDN(         qname,         NULL                                                           )
CONFIG_FQDN(         tsig_key_name, "ctrl-key"                                                     )
CONFIG_BOOL(         enable,        "on"                                                           )
CONFIG_BOOL(         clean,         "off"                                                          )
CONFIG_STRING(       config_file,   DEF_YADIFA_CONF                                                )
CONFIG_TSIG_ITEM(    tsig_key_item, NULL)
CONFIG_ALIAS(key, tsig_key_name)

CONFIG_BOOL(         verbose,       "off"                                                          )
    /** @todo 20150219 gve -- must be removed before release */
CONFIG_U8(           log_level,     "6"                                                            ) // 6 is MSG_INFO

CONFIG_END(yadifa_ctrl_settings_desc)

// ********************************************************************************
// ***** module command line struct
// ********************************************************************************

/**
 * The filter gets all words not taken by the rest of the CMDLINE struct
 */

static ya_result
ctrl_cmdline_filter_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
{
    void *arg = CMDLINE_CALLBACK_ARG_GET(desc);
    (void)arg;
    (void)callback_owned;

    ya_result ret;

    if(arg_name[0] == '@')
    {
        // @ip

        ret = cmdline_get_opt_short(desc, "s", &arg_name[1]);

        // do NOT return "ret" here (see why after the else block)
    }
    else
    {
        // states of the friendly command begin -> x -> y -> end

        enum CTRL_CMD_STATE
        {
            CTRL_CMD_STATE_BEGIN = 0,
            CTRL_CMD_STATE_ZONERELOAD,
            CTRL_CMD_STATE_ZONECFGRELOAD,
            CTRL_CMD_STATE_ZONESYNC,
            CTRL_CMD_STATE_ZONESYNC_FQDN,
            CTRL_CMD_STATE_SRVQUERYLOG,
            CTRL_CMD_STATE_SRVLOGLEVEL,
            CTRL_CMD_STATE_SRVCFGRELOAD,
            CTRL_CMD_STATE_SRVLOGREOPEN,
            CTRL_CMD_STATE_SRVSHUTDOWN,
            CTRL_CMD_STATE_FREEZE,
            CTRL_CMD_STATE_UNFREEZE,
            CTRL_CMD_STATE_FREEZEALL,
            CTRL_CMD_STATE_UNFREEZEALL,
            CTRL_CMD_STATE_ZONENOTIFY,
            CTRL_CMD_STATE_END
        };

        static const u16 CTRL_CMD_STATE_TO_TYPE_CTRL[] =
        {
            0,
            TYPE_CTRL_ZONERELOAD,
            TYPE_CTRL_ZONECFGRELOAD,
            TYPE_CTRL_ZONESYNC,
            0,
            TYPE_CTRL_SRVQUERYLOG,
            TYPE_CTRL_SRVLOGLEVEL,
            TYPE_CTRL_SRVCFGRELOAD,
            TYPE_CTRL_SRVLOGREOPEN,
            TYPE_CTRL_SRVSHUTDOWN,
            TYPE_CTRL_ZONEFREEZE,
            TYPE_CTRL_ZONEUNFREEZE,
            TYPE_CTRL_ZONEFREEZEALL,
            TYPE_CTRL_ZONEUNFREEZEALL,
            TYPE_CTRL_ZONENOTIFY,
            0
        };

        // key words: the right column is used as key here

        static const value_name_table keywords[] =
        {
            {CTRL_CMD_STATE_ZONERELOAD, "reload"},
            {CTRL_CMD_STATE_ZONECFGRELOAD, "zonecfgreload"},
            {CTRL_CMD_STATE_ZONESYNC, "sync"},
            {CTRL_CMD_STATE_SRVQUERYLOG, "querylog"},
            {CTRL_CMD_STATE_SRVLOGLEVEL, "loglevel"},
            {CTRL_CMD_STATE_SRVCFGRELOAD, "cfgreload"},
            {CTRL_CMD_STATE_SRVLOGREOPEN, "logreopen"},
            {CTRL_CMD_STATE_SRVSHUTDOWN, "shutdown"},
            {CTRL_CMD_STATE_FREEZE, "freeze"},
            {CTRL_CMD_STATE_UNFREEZE, "unfreeze"},
            {CTRL_CMD_STATE_UNFREEZE, "thaw"},
            {CTRL_CMD_STATE_FREEZEALL, "freezeall"},
            {CTRL_CMD_STATE_UNFREEZEALL, "unfreezeall"},
            {CTRL_CMD_STATE_UNFREEZE, "thawall"},
            {CTRL_CMD_STATE_ZONENOTIFY, "notify"},

            {0, NULL}
        };

        static enum CTRL_CMD_STATE cmdline_state = CTRL_CMD_STATE_BEGIN;

        switch(cmdline_state)
        {
            case CTRL_CMD_STATE_BEGIN:
            {
                u32 keyword_value;
                ret = value_name_table_get_value_from_casename(keywords, arg_name, &keyword_value);

                if(ISOK(ret))
                {
                    cmdline_state = keyword_value;
                    u16 qtype = CTRL_CMD_STATE_TO_TYPE_CTRL[keyword_value];
                    const char * qtype_name = dns_type_get_name(qtype);

                    if(qtype_name != NULL)
                    {
                        ret = cmdline_get_opt_short(desc, "t", qtype_name);
                    }
                    else
                    {
                        ret = CONFIG_PARSE_UNKNOWN_KEYWORD; // check in dns_type_get_name if the type exists
                    }
                }
                else
                {
                    if(strcmp(arg_name, "help") == 0)
                    {
                        ret = cmdline_get_opt_short(desc, "h", NULL);
                    }
                    else
                    {
                        ret = CONFIG_PARSE_UNKNOWN_KEYWORD;
                    }
                }

                break;
            }
            case CTRL_CMD_STATE_FREEZE:
            case CTRL_CMD_STATE_UNFREEZE:
            case CTRL_CMD_STATE_ZONERELOAD:
            case CTRL_CMD_STATE_ZONECFGRELOAD:
            case CTRL_CMD_STATE_ZONENOTIFY:
            {
                ret = cmdline_get_opt_short(desc, "q", arg_name);
                cmdline_state = CTRL_CMD_STATE_END;
                break;
            }
            case CTRL_CMD_STATE_ZONESYNC:
            {
                // solve an ambiguity: if the fqdn is "clean.", then we assume it's the option "clean" and there is no fqdn.
                // if the users really means "clean.", then he must explicitly use "-q clean." or "-q clean --clean"

                if(strcasecmp(arg_name, "clean") == 0)
                {
                    g_yadifa_ctrl_settings.clean = TRUE;
                    ret = cmdline_get_opt_long(desc, "clean", NULL);
                    cmdline_state = CTRL_CMD_STATE_END;
                }
                else
                {
                    ret = cmdline_get_opt_short(desc, "q", arg_name);
                }
                cmdline_state = CTRL_CMD_STATE_ZONESYNC_FQDN;
                break;
            }
            case CTRL_CMD_STATE_ZONESYNC_FQDN:
            {
                if(strcasecmp(arg_name, "clean") == 0)
                {
                    g_yadifa_ctrl_settings.clean = TRUE;
                    ret = cmdline_get_opt_long(desc, "clean", NULL);
                    cmdline_state = CTRL_CMD_STATE_END;
                }
                else
                {
                    ret = PARSE_INVALID_ARGUMENT;
                }
                break;
            }
            case CTRL_CMD_STATE_SRVQUERYLOG:
            {
                if(strcmp(arg_name, "enable") == 0)
                {
                    g_yadifa_ctrl_settings.enable = TRUE;
                    /*ret = */ cmdline_get_opt_long(desc, "enable", NULL);
                    ret = SUCCESS;
                }
                else if(strcmp(arg_name, "disable") == 0)
                {
                    g_yadifa_ctrl_settings.enable = FALSE;
                    /*ret = */ cmdline_get_opt_long(desc, "disable", NULL);
                    ret = SUCCESS;
                }
                else
                {
                    ret = PARSE_INVALID_ARGUMENT;
                }

                cmdline_state = CTRL_CMD_STATE_END;
                break;
            }
            case CTRL_CMD_STATE_SRVLOGLEVEL:
            {
                ret = cmdline_get_opt_short(desc, "l", arg_name);
                cmdline_state = CTRL_CMD_STATE_END;
                break;
            }
            case CTRL_CMD_STATE_SRVCFGRELOAD:
            case CTRL_CMD_STATE_SRVLOGREOPEN:
            case CTRL_CMD_STATE_SRVSHUTDOWN:
            case CTRL_CMD_STATE_END:
            {
                ret = PARSE_INVALID_ARGUMENT;
                break;
            }
            default:
            {
                ret = INVALID_PROTOCOL;
            }
        }
    }

    if(ISOK(ret))
    {
        ret = SUCCESS; // some success values are stopping command line processing, we do not want that to happen.
    }

    return ret;
}

CMDLINE_BEGIN(yadifa_cmdline)
CMDLINE_FILTER(ctrl_cmdline_filter_callback, NULL) // NULL is passed to the callback as a parameter (callback_owned)
// main hooks
CMDLINE_INDENT(4)
CMDLINE_IMSG("options:", "")
CMDLINE_INDENT(4)
CMDLINE_SECTION(MAIN_SECTION_NAME)
CMDLINE_OPT("config",'c', "config_file"               )
CMDLINE_HELP("<config-file>", "use <config_file> as configuration (default: " DEF_YADIFA_CONF ")")
CMDLINE_SECTION(CTRL_SECTION_NAME)
CMDLINE_OPT("server", 's', "server"                    )
CMDLINE_HELP("<host>", "sets the name server to connect to")
CMDLINE_IMSGS("", "can be an ip address or an ip address with a port number")
CMDLINE_IMSGS("", "e.g. \"192.0.2.1 port 53\"")
CMDLINE_IMSGS("", "note: the quotes are needed")
CMDLINE_IMSGS("@<host>", "equivalent to --server <host>")
CMDLINE_OPT("port", 'p', "port")
CMDLINE_HELP("<port>", "sets the DNS server port (default: 53)")
CMDLINE_OPT("key-name",        'K', "tsig_key_name"             )
CMDLINE_HELP("<keyname>", "name of the TSIG key to use for authentication (requires configuration file)")
CMDLINE_OPT("key", 'y', "tsig_key_item")
CMDLINE_HELP("[hmac:]name:key", "TSIG key to use for authentication (default hmac: hmac-md5)")

// command line
CMDLINE_VERSION_HELP(yadifa_cmdline)
CMDLINE_SECTION(CTRL_SECTION_NAME)  // CMDLINE_VERSION_HELP changes the section

CMDLINE_BOOL("enable",            0, "enable")
CMDLINE_BOOL_NOT("disable",           0, "enable")
CMDLINE_BOOL("verbose",         'v', "verbose")

CMDLINE_INDENT(-4)
CMDLINE_BLANK()
CMDLINE_IMSG("commands:", "")
CMDLINE_INDENT(4)
CMDLINE_IMSGS("cfgreload", "reloads settings from disk")
CMDLINE_IMSGS("freeze [<zone>]", "prevents dynamic updates to one or every zones")
CMDLINE_IMSGS("freezeall", "prevents dynamic updates to every zone currently loaded")
CMDLINE_IMSGS("loglevel <level>", "sets up the maximum level of log [0;15], 6 = INFO, 15 = ALL")
CMDLINE_IMSGS("logreopen", "closes and reopens all the log files")
CMDLINE_IMSGS("notify [<zone>]", "send notifies to slaves of these zones")
CMDLINE_IMSGS("querylog [enable|disable]", "enables or disables the query logging (default: enable)")
CMDLINE_IMSGS("reload <zone>", "reloads a zone from disk")
CMDLINE_IMSGS("shutdown", "shuts the server down")
CMDLINE_IMSGS("sync [<zone>] [clean]", "writes the zone file on disk, optionally cleans up the journal")
CMDLINE_IMSGS("thaw [<zone>]", "allows dynamic updates to one or every zones again")
CMDLINE_IMSGS("thawall", "allows dynamic updates to every zone again")
CMDLINE_IMSGS("unfreeze [<zone>]", "allows dynamic updates to one or every zones again")
CMDLINE_IMSGS("unfreezeall", "allows dynamic updates to every zone again")
CMDLINE_IMSGS("zonecfgreload [<zone>]", "reloads all (or specified) zone settings from disk")

CMDLINE_INDENT(-4)
CMDLINE_BLANK()
CMDLINE_IMSG("alternative:", "")
CMDLINE_INDENT(4)
CMDLINE_BOOL(        "clean",             0, "clean"                     )
CMDLINE_HELP("", "sets the \"clean\" flag of the \"sync\" command")
CMDLINE_OPT(         "level",           'l', "log_level"                 )
CMDLINE_HELP("<number>", "sets the \"level\" of the \"loglevel\" command")
CMDLINE_OPT(         "qname",           'q', "qname"                     )
CMDLINE_HELP("<zone>", "sets the zone parameter of a command")
CMDLINE_OPT(         "type",            't', "qtype"                     )
CMDLINE_HELP("<command>", "sets the command, can be:")
CMDLINE_IMSGS("",  "  SHUTDOWN, RELOAD, LOGREOPEN, QUERYLOG, LOGLEVEL,")
CMDLINE_IMSGS("",  "  FREEZE, UNFREEZE, FREEZEALL, UNFREEZEALL, SYNC,")
CMDLINE_IMSGS("",  "  ZONENOTIFY, CFGRELOAD, CFGLOAD, ZONECFGRELOAD,")
CMDLINE_IMSGS("",  "  ZONECFGRELOADALL")
//CMDLINE_BOOL_NOT(    "noclean",0, "clean"                     )
//CMDLINE_HELP("","clears the \"clean\" flag of the \"sync\" command")

// resolver section
//CMDLINE_RESOLVER(yadifa_cmdline)

CMDLINE_END(yadifa_cmdline)



// ********************************************************************************
// ***** module register
// ********************************************************************************

static int
ctrl_config_register(int priority)
{
    // register all config blocs required by the server

    ZEROMEMORY(&g_yadifa_ctrl_settings, sizeof(g_yadifa_ctrl_settings));

    ya_result ret;

    if(FAIL(ret = config_register_struct(CTRL_SECTION_NAME, yadifa_ctrl_settings_desc, &g_yadifa_ctrl_settings, priority)))
    {
        return ret; // internal error
    }

    return ret;
}

// ********************************************************************************
// ***** module run
// ********************************************************************************

static ya_result
ctrl_run()
{
    ya_result                                              return_code = OK;

    for(host_address *ha = g_yadifa_ctrl_settings.server; ha != NULL; ha = ha->next)
    {
        if(ha->port == 0)
        {
            ha->port = htons(g_yadifa_ctrl_settings.port);
        }
#if DEBUG
        osformatln(termout, ";; DEBUG: server address: %{hostaddr}", ha);
#endif
    }

    /*    ------------------------------------------------------------    */

    message_data_with_buffer mesg_buff;
    message_data *mesg;
    s64 query_time_send;
    s64 query_time_received;

    u8                                                          go_tcp = OK;

    /*    ------------------------------------------------------------    */

    /* give ID from config or randomized */
    u16 id                = dns_new_id();
    u16 qtype             = htons(g_yadifa_ctrl_settings.qtype);
    u8 *qname             = g_yadifa_ctrl_settings.qname;

#if 0 /* fix */
#else
    u16 question_mode     = 0;
#endif // if 0

    /* prepare root tld */
    char *root = ".";
    u8 root_fqdn[MAX_DOMAIN_LENGTH];
    cstr_to_dnsname(root_fqdn, root);



    mesg = message_data_with_buffer_init(&mesg_buff);

    switch(qtype)
    {
        case TYPE_NONE:
            /// @note this should have been caught in the module->setup() call so the help would be printed
            return_code = COMMAND_ARGUMENT_EXPECTED;
            formatln("control command required");
            return return_code;

        case TYPE_CTRL_ZONEFREEZE:
        case TYPE_CTRL_ZONEUNFREEZE:
        case TYPE_CTRL_ZONERELOAD:
        case TYPE_CTRL_ZONECFGRELOAD:
        case TYPE_CTRL_ZONENOTIFY:
        {
            message_make_query(mesg, id, root_fqdn, qtype, CLASS_CTRL);

            packet_writer pw;
            packet_writer_init_append_to_message(&pw, mesg);

            if(qname != NULL)
            {
                packet_writer_add_record(&pw, root_fqdn, qtype, CLASS_CTRL, 0, qname, (u16)dnsname_len(qname));
                message_set_answer_count_ne(mesg, NETWORK_ONE_16); // fqdn parameter is expected in the "answer" section
            }

            message_set_size(mesg, packet_writer_get_offset(&pw));
            break;
        }
            /* the same as zone freeze, but without extra information */
        case TYPE_CTRL_ZONEFREEZEALL:
        {
            message_make_query(mesg, id, root_fqdn, TYPE_CTRL_ZONEFREEZE, CLASS_CTRL);

            break;
        }
            /* the same as zone freeze, but without extra information */
        case TYPE_CTRL_ZONEUNFREEZEALL:
        {
            message_make_query(mesg, id, root_fqdn, TYPE_CTRL_ZONEUNFREEZE, CLASS_CTRL);

            break;
        }
            /* the same as zone unfreeze, but without extra information */
        case TYPE_CTRL_ZONECFGRELOADALL:
        {
            message_make_query(mesg, id, root_fqdn, TYPE_CTRL_ZONECFGRELOAD, CLASS_CTRL);

            break;
        }

        case TYPE_CTRL_SRVLOGLEVEL:
        {
            /* 1. create rdata part for the 'added record'
                  - 1 byte (0 or 1) from --clean command line parameter
                  - qname
            */
            u8 buffer[256]; // max domain name length + 1 byte for clean value

            buffer[0]      = MIN(g_yadifa_ctrl_settings.log_level, MSG_ALL);
            u16 buffer_len = 1;

            /* 2. make message */
            message_make_query(mesg, id, root_fqdn, qtype, CLASS_CTRL);

            /* 3. modify message, add an extra resource record */
            packet_writer pw;
            packet_writer_init_append_to_message(&pw, mesg);

            packet_writer_add_record(&pw, root_fqdn, qtype, CLASS_CTRL, 0, buffer, buffer_len);

            message_set_answer_count_ne(mesg, NETWORK_ONE_16);

            message_set_size(mesg, packet_writer_get_offset(&pw));

            break;
        }

            /** @todo 20150219 gve -- still needs to check this on yadifad side */
        case TYPE_CTRL_ZONESYNC:
        {
            /* 1. create rdata part for the 'added record'
                  - 1 byte (0 or 1) from --clean command line parameter
                  - qname
            */
            u8 buffer[256]; // max domain name length + 1 byte for clean value

            buffer[0]      = (u8)g_yadifa_ctrl_settings.clean;
            u16 buffer_len = 1;

            /* 2. make message */
            message_make_query(mesg, id, root_fqdn, qtype, CLASS_CTRL);

            /* 3. modify message, add an extra resource record */
            packet_writer pw;
            packet_writer_init_append_to_message(&pw, mesg);

            if(qname != NULL)
            {
                dnsname_copy(&buffer[1], qname);
                buffer_len += (u16)dnsname_len(qname);
                packet_writer_add_record(&pw, root_fqdn, qtype, CLASS_CTRL, 0, buffer, buffer_len);
                message_set_answer_count_ne(mesg, NETWORK_ONE_16);
            }
            else if(g_yadifa_ctrl_settings.clean) // if the clean flag is set then the parameter is required
            {
                packet_writer_add_record(&pw, root_fqdn, qtype, CLASS_CTRL, 0, buffer, buffer_len);
                message_set_answer_count_ne(mesg, NETWORK_ONE_16);
            }

            message_set_size(mesg, packet_writer_get_offset(&pw));

            break;
        }
        case TYPE_CTRL_SRVQUERYLOG:
        {
            /* 1. make message */
            message_make_query(mesg, id, root_fqdn, qtype, CLASS_CTRL);

            /* 2. modify message, add an extra resource record */
            packet_writer pw;
            packet_writer_init_append_to_message(&pw, mesg);
            u8 flags = (g_yadifa_ctrl_settings.enable)?1:0;
            packet_writer_add_record(&pw, root_fqdn, qtype, CLASS_CTRL, 0, &flags, 1);
            message_set_answer_count_ne(mesg, NETWORK_ONE_16);

            message_set_size(mesg, packet_writer_get_offset(&pw));

            break;
        }
        // case TYPE_CTRL_LOGREOPEN:
        // case TYPE_CTRL_SHUTDOWN
        // case TYPE_CTRL_SRVCFGRELOAD  (-t cfgreload)
        default:
        {
            message_make_query(mesg, id, root_fqdn, qtype, CLASS_CTRL);

            break;
        }
    }

    message_set_opcode(mesg, OPCODE_CTRL);

    const u8 *tsig_key_name = (g_yadifa_ctrl_settings.tsig_key_item != NULL)?g_yadifa_ctrl_settings.tsig_key_item->name:g_yadifa_ctrl_settings.tsig_key_name;

    /**  TSIG check and returns if not good
     *  @note TSIG is always needed for the controller
     */
    if(FAIL(return_code = message_sign_query_by_name(mesg, tsig_key_name)))
    {
        /** @todo 20150217 gve -- needs to send back a good return value */
        if(return_code == TSIG_BADKEY)
        {
            osformatln(termerr,
            "The key used for signing the control queries isn't correct.\n"
            "Please verify that the controller key on the server is named '%{dnsname}.\n"
            "Please verify that a <key> section for a key named '%{dnsname}' matching the one on the server is defined.\n"
            "\n"
            "e.g.:\n"
            "\n"
            "<yadifa-ctrl>\n"
            "  key %{dnsname}\n"
            "  ...\n"
            "</yadifa-ctrl>\n"
            "\n"
            "<key>\n"
            "  name %{dnsname}\n"
            "  algorithm hmac-XXX\n"
            "  secret XXXXXXXXXXXXXXXXX\n"
            "</key>\n"
            "\n"
            "Please refer to man 8 yadifa.conf for more information.\n",
                g_yadifa_ctrl_settings.tsig_key_name, // BE SURE TO MATCH THE %{dnsname} IN THE ABOVE TEXT
                g_yadifa_ctrl_settings.tsig_key_name,
                g_yadifa_ctrl_settings.tsig_key_name,
                g_yadifa_ctrl_settings.tsig_key_name
            );

            flusherr();
        }
        else if(return_code == TSIG_SIZE_LIMIT_ERROR)
        {
            osformatln(termerr, "The size of the key %{dnsname} is not supported.\n", g_yadifa_ctrl_settings.tsig_key_name);
            flusherr();
        }

        return return_code;
    }

#if DEBUG
    osformatln(termout, ";;; DEBUG INFORMATION");
    message_print_format_dig(termout, message_get_buffer(mesg), message_get_size(mesg), MESSAGE_VIEWER_SIMPLE_QUERY, -1);
    osformatln(termout, ";;; DEBUG INFORMATION (END)");
#endif

    /* set timer before send */
    query_time_send = timems();
    u8 connect_timeout = 6;
    ya_result query_return_code = message_query_tcp_with_timeout(mesg, g_yadifa_ctrl_settings.server, connect_timeout);
    query_time_received = timems();

    if(FAIL(query_return_code))
    {
        if(g_yadifa_ctrl_settings.verbose)
        {
            message_viewer mv;
            message_viewer_dig_init(&mv, termout, 0); // do not print any section
            mv.host = g_yadifa_ctrl_settings.server;    // so the server(s) can be printed if needed
            query_result_view(&mv, mesg, MAX(query_time_received - query_time_send, 0), query_return_code);
        }
        else
        {
            osformatln(termerr, "command to %{hostaddr} failed: %r", g_yadifa_ctrl_settings.server, query_return_code);
        }

        return query_return_code;
    }

    /* stop timer after received */

#if 0 /* fix */
#else
    u16 protocol         = 0;
#endif // if 0

    return_code = query_result_check(id, protocol, question_mode, mesg, &go_tcp);

    /* show the result if verbose */
    if(g_yadifa_ctrl_settings.verbose)
    {
        /// @todo 20150715 gve -- needs to be modified for view_with_mode
        message_viewer mv;
        message_viewer_dig_init(&mv, termout, MESSAGE_VIEWER_SIMPLE_QUERY);
        mv.host = g_yadifa_ctrl_settings.server;    // so the server(s) can be printed if needed

        return_code = query_result_view(&mv, mesg, MAX(query_time_received - query_time_send, 0), query_return_code);

        println("");

        if(FAIL(return_code))
        {
            return return_code;
        }
    }

    if(ISOK(return_code))
    {
        // osformatln(termout, "%s", dns_message_rcode_get_name(message_get_rcode(mesg)));
    }
    else
    {
        osformatln(termerr, "error: %r", return_code);
    }

    return return_code;
}

// ********************************************************************************
// ***** module virtual table
// ********************************************************************************

const module_s ctrl_program =
{
    module_default_init,            // module initializer
    module_default_finalize,        // module finalizer
    ctrl_config_register,         // module register
    module_default_setup,           // module setup
    ctrl_run,                     // module run
    module_default_cmdline_help_print,      //

    yadifa_cmdline,                 // module command line struct
    NULL,                           // module command line callback
    NULL,                           // module filter arguments
    
    "yadifad controller",           // module public name
    "yctrl",                        // module command (name as executable match)
    "ctrl",                         // module parameter (name as first parameter)
    /*ctrl_cmdline_help*/ NULL,          // module text to be printed upon help request
    ".yadifa.rc"                    // module rc file (ie: ".module.rc"
};


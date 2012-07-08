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
* DOCUMENTATION */
/** @defgroup config Configuration handling
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

/*
 * DYNAMIC SECTION
 */

#include <stdio.h>
#include <stdlib.h>

#include <dnscore/format.h>

#include <dnscore/logger_channel_stream.h>
#include <dnscore/logger_channel_file.h>
#include <dnscore/logger_channel_syslog.h>

#include <dnscore/file_output_stream.h>

#include "confs.h"

#include "config_error.h"
#include "server_error.h"

#define MODULE_MSG_HANDLE g_server_logger

/*
 *
 */

/*
 * 2011/10/18 : EDF: disabling the debug because it makes the legitimate error output unreadable.
 */

#undef DEBUGLNF
#undef DEBUGF
#undef OSDEBUG
#undef LDEBUG
#undef OSLDEBUG
#define DEBUGLNF(...)
#define DEBUGF(...)
#define OSDEBUG(...)
#define LDEBUG(...)
#define OSLDEBUG(...)

/**
 * Syslog levels
 */

#define SYSLOG_LEVEL_TOKEN_DELIMITER ",;:+"

/**
 * Syslog channels
 */

#define SYSLOG_CHANNEL_TOKEN_DELIMITER "\t ,;:+"

enum channel_type
{
	CT_STDOUT,
	CT_STDERR,
	CT_SYSLOG,
	CT_FILE
};
typedef enum channel_type channel_type;

typedef struct syslog_channel_data syslog_channel_data;
struct syslog_channel_data
{
	int                                                          option;
	int                                                        facility;
};

typedef struct file_channel_data file_channel_data;
struct file_channel_data
{
	char                                                          *path;
	unsigned int                                                 access;
};

typedef struct channel_data channel_data;
struct channel_data
{
	struct channel_data                                           *next;
	char                                                          *name;
	logger_channel                                             *channel;
	union
	{
	    file_channel_data                                          file;
	    syslog_channel_data                                      syslog;
	} arguments;
	channel_type                                                   type;
	bool                                                      activated;
};

typedef struct channel_data_list channel_data_list;
struct channel_data_list
{
	struct channel_data_list                                      *next;
	struct channel_data                                        *channel;
};


/*
 *  CHANNELS is a dynamic section so there is no config_table
 */

#define FILE_CHANNEL_DEFAULT_ACCESS_RIGHTS 0644

static channel_data                                       *tmp_channels = NULL;
static bool has_channels_section = FALSE;

static value_name_table syslog_channel_arguments_options[] =
{
#ifdef LOG_CONS
    {LOG_CONS, "cons"},
#endif

#ifdef LOG_NDELAY
    {LOG_NDELAY, "ndelay"},
#endif

#ifdef LOG_NOWAIT
    {LOG_NOWAIT, "nowait"},
#endif

#ifdef LOG_ODELAY
    {LOG_ODELAY, "odelay"},
#endif

#ifdef LOG_PERROR
    {LOG_PERROR, "perror"},
#endif

#ifdef LOG_PID
    {LOG_PID, "pid"},
#endif

    {0, NULL}
};

static value_name_table syslog_channel_arguments_facility[] =
{
#ifdef LOG_AUTH
    {LOG_AUTH, "auth"},
#endif

#ifdef LOG_AUTHPRIV
    {LOG_AUTHPRIV, "authpriv"},
#endif

#ifdef LOG_CRON
    {LOG_CRON, "cron"},
#endif

#ifdef LOG_DAEMON
    {LOG_DAEMON, "daemon"},
#endif

#ifdef LOG_FTP
    {LOG_FTP, "ftp"},
#endif

/*
 This is forbidden for anybody but the kernel.
#ifdef LOG_KERN
    {LOG_KERN, "kern"},
#endif
*/

#ifdef LOG_LOCAL0
    {LOG_LOCAL0, "local0"},
#endif

#ifdef LOG_LOCAL1
    {LOG_LOCAL1, "local1"},
#endif

#ifdef LOG_LOCAL2
    {LOG_LOCAL2, "local2"},
#endif

#ifdef LOG_LOCAL3
    {LOG_LOCAL3, "local3"},
#endif

#ifdef LOG_LOCAL4
    {LOG_LOCAL4, "local4"},
#endif

#ifdef LOG_LOCAL5
    {LOG_LOCAL5, "local5"},
#endif

#ifdef LOG_LOCAL6
    {LOG_LOCAL6, "local6"},
#endif

#ifdef LOG_LOCAL7
    {LOG_LOCAL7, "local7"},
#endif

#ifdef LOG_LPR
    {LOG_LPR, "lpr"},
#endif

#ifdef LOG_MAIL
    {LOG_MAIL, "mail"},
#endif

#ifdef LOG_NEWS
    {LOG_NEWS, "news"},
#endif

#ifdef LOG_SYSLOG
    {LOG_SYSLOG, "syslog"},
#endif

#ifdef LOG_USER
    {LOG_USER, "user"},
#endif

#ifdef LOG_UUCP
    {LOG_UUCP, "uucp"},
#endif

    {0, NULL}
};

static bool loggers_assigned = FALSE;
static bool channels_assigned = FALSE;

extern logger_handle                                       *g_statistics_logger;
extern logger_handle                                           *g_server_logger;
extern logger_handle                                         *g_database_logger;
extern logger_handle                                             *g_zone_logger;
#if HAS_DNSSEC_SUPPORT != 0
extern logger_handle                                           *g_dnssec_logger;
#endif
extern logger_handle                                          *g_queries_logger;

static const char *logger_names[]=
{
    "system",
    "database",
#if HAS_DNSSEC_SUPPORT != 0
    "dnssec",
#endif
    "zone",
    "server",
    "stats",
    "queries",
    NULL
};

typedef logger_handle* logger_handlep;

static logger_handlep* logger_handles[]=
{
    &g_system_logger,
    &g_database_logger,
#if HAS_DNSSEC_SUPPORT != 0
    &g_dnssec_logger,
#endif
    &g_zone_logger,
    &g_server_logger,
    &g_statistics_logger,
    &g_queries_logger,
    NULL
};

/**/

static ya_result
set_variable_channels(char *variable, char *value, char *argument);

static ya_result
set_variable_loggers(char *variable, char *value, char *argument);

static logger_channel *stdout_channel = NULL;

void
config_logger_setdefault()
{
    if(stdout_channel == NULL)
    {
        output_stream stdout_os;
        fd_output_stream_attach(dup(1), &stdout_os);
        stdout_channel = logger_channel_alloc();
        logger_channel_stream_open(&stdout_os, FALSE, stdout_channel);
    }
        
    for(int i = 0; logger_names[i] != NULL; i++)
    {
        if(logger_handle_get(logger_names[i]) == NULL)
        {
            logger_handle* log = logger_handle_add(logger_names[i]);
            *(logger_handles[i]) = log;
            logger_handle_add_channel(log, 0xffff, stdout_channel);
        }
    }
    
#ifndef NDEBUG
    log_debug("logging to stdout");
#endif
}

void
config_logger_cleardefault()
{
    logger_finalize();
    
    stdout_channel = NULL;
    
    g_system_logger = NULL;
    g_database_logger = NULL;
#if HAS_DNSSEC_SUPPORT != 0
    g_dnssec_logger = NULL;
#endif
    g_zone_logger = NULL;
    g_server_logger = NULL;
    g_statistics_logger = NULL;
    g_queries_logger = NULL;
    
    logger_start();
}

static void
config_update_handles()
{
    if(loggers_assigned && channels_assigned)
    {
        /* Logging for threads, scheduler, dnscore stuff ... */
        g_system_logger         = logger_handle_get("system");
        g_database_logger       = logger_handle_get("database");
#if HAS_DNSSEC_SUPPORT != 0
        g_dnssec_logger         = logger_handle_get("dnssec");
#endif
        g_zone_logger           = logger_handle_get("zone");
        
        /* Logging for server */
        g_server_logger         = logger_handle_get("server");
        
        g_statistics_logger     = logger_handle_get("stats");
        g_queries_logger        = logger_handle_get("queries");
    }
}

/******************** Channels *************************/

static ya_result
config_channel_section_init(config_data *config)
{
    has_channels_section = TRUE;
    
    return SUCCESS;
}

static void
config_channel_section_activate(config_data *config, channel_data* channel)
{
    /* NOTE: the output_stream is taken by the channel
     *       at the exit of logger_channel_stream_open errlog_channel is
     *	     "cloned", then the source is "destroyed".
     */

    if(channel->activated)
    {
        return;
    }

    char *chroot_base;

    if((config->server_flags & SERVER_FL_CHROOT) != 0)
    {
        chroot_base = config->chroot_path;
    }
    else
    {
        chroot_base = "/";
    }

    switch(channel->type)
    {
        case CT_STDOUT:
	    {
            output_stream stdout_os;
            fd_output_stream_attach(dup(1), &stdout_os);
            logger_channel *stdout_channel = logger_channel_alloc();
            logger_channel_stream_open(&stdout_os, FALSE, stdout_channel);
            channel->channel = stdout_channel;
            break;
	    }
        case CT_STDERR:
	    {
            output_stream stderr_os;
            fd_output_stream_attach(dup(2), &stderr_os);
            logger_channel *stderr_channel = logger_channel_alloc();
            logger_channel_stream_open(&stderr_os, FALSE, stderr_channel);
            channel->channel = stderr_channel;
            break;
	    }
    	case CT_SYSLOG:
	    {
            logger_channel* syslog_channel = logger_channel_alloc();
            logger_channel_syslog_open(PACKAGE_NAME "d",                /* yadifad */
                channel->arguments.syslog.option,
                channel->arguments.syslog.facility,
                syslog_channel);
            channel->channel = syslog_channel;
            break;
	    }
        case CT_FILE:
	    {
            ya_result return_code;
            
            char fullpath[PATH_MAX];

            if(channel->arguments.file.path[0] != '/')
            {
                snformat(fullpath, sizeof(fullpath), "%s/%s%s", chroot_base, config->log_path, channel->arguments.file.path);
            }
            else
            {
                snformat(fullpath, sizeof(fullpath), "%s/%s", chroot_base, channel->arguments.file.path);
            }

            logger_channel* file_channel = logger_channel_alloc();

            if(FAIL(return_code = logger_channel_file_open(fullpath, g_config->uid, g_config->gid, channel->arguments.file.access, FALSE, file_channel)))
            {
                osformatln(termerr, "config: unable to open file channel '%s' (%d:%d %o) : %r", fullpath, g_config->uid, g_config->gid, channel->arguments.file.access, return_code);
                flusherr();
                exit(EXIT_CONFIG_ERROR);
            }
            
            if((config->server_flags & SERVER_FL_CHROOT) != 0)
            {
                if(channel->arguments.file.path[0] != '/')
                {
                    snformat(fullpath, sizeof(fullpath), "/%s%s", config->log_path, channel->arguments.file.path);
                }
                else
                {
                    snformat(fullpath, sizeof(fullpath), "/%s", channel->arguments.file.path);
                }
                
                logger_channel_file_rename(file_channel, fullpath);
            }
                        
            channel->channel = file_channel;
            break;
	    }
        default:
	    {
            osformatln(termerr, "config: unknown channel type (#%i)", channel->type);
            flusherr();
            exit(EXIT_CONFIG_ERROR);
            break;
	    }
    }

    channel->activated = TRUE;
}

static ya_result
config_channel_section_assign(config_data *config)
{
    /** Channel fill-up */
    
    config_logger_cleardefault();

    if(!has_channels_section)
    {
        set_variable_channels("default", "stderr", "");
    }
    
    channels_assigned = TRUE;

    config_update_handles();

    return SUCCESS;
}

static ya_result
config_channel_section_free(config_data *config)
{
    channel_data *channel;
    
    channel = tmp_channels;
    
    while(channel != NULL)
    {
        channel_data *tmp = channel;
        channel = channel->next;

        if(tmp->type == CT_FILE)
        {
            free(tmp->arguments.file.path);
        }

        free(tmp->name);
#ifndef NDEBUG
        memset(tmp,0xff,sizeof(channel_data));
#endif
        free(tmp);
    }

    tmp_channels = NULL;

    return SUCCESS;
}

static ya_result
set_variable_channels(char *variable, char *value, char *argument)
{
    OSDEBUG(termout, "Set channel variable : %s (%s: %s)\n", variable, value, argument);

    channel_data* item = tmp_channels;

    while(item != NULL)
    {
        if(strcasecmp(item->name, variable) == 0)
        {
            osformatln(termerr, "Variable already defined %s = (%i, %s)",
                   item->name,
                   item->type,
                   (item->arguments.file.path != NULL) ? item->arguments.file.path : "");

            return CONFIG_CHANNEL_DUPLICATE;
        }

        item = item->next;
    }

    MALLOC_OR_DIE(channel_data*, item, sizeof (channel_data), GENERIC_TAG);
    item->name = strdup(variable);
    item->next = tmp_channels;
    item->activated = FALSE;
    tmp_channels = item;

    if(strcasecmp("stdout", value) == 0)
    {
        item->type = CT_STDOUT;
    }
    else if(strcasecmp("stderr", value) == 0)
    {
        item->type = CT_STDERR;
    }
    else if(strcasecmp("syslog", value) == 0)
    {
        char* token;

        item->type = CT_SYSLOG;

        /*
         * Tokenize
         */

        item->arguments.syslog.option = 0;
        item->arguments.syslog.facility = 0;

        /* WARNING: NEVER EVER USE A CONST STRING AS ARGUMENT OR strtok WILL SIGSEGV */

        for(token =  strtok(argument, SYSLOG_CHANNEL_TOKEN_DELIMITER);
            token != NULL;
            token =  strtok(NULL, SYSLOG_CHANNEL_TOKEN_DELIMITER))
        {
            u32 token_value;

            if(ISOK(get_value_from_casename(syslog_channel_arguments_options, token, &token_value)))
            {
                item->arguments.syslog.option |= token_value;
            }
            else if(ISOK(get_value_from_casename(syslog_channel_arguments_facility, token, &token_value)))
            {
                item->arguments.syslog.facility = token_value; /* Facility is NOT a bit mask */
            }
            else
            {
                /* Note: empty statement is taken care of here */
                OSDEBUG(termout, "unknown syslog argument '%s'\n", token);

                osformat(termerr, "wrong syslog argument for '%s'.  Valid names are: ", variable);

                print_value_name_table_names(syslog_channel_arguments_options);
                print(",");
                print_value_name_table_names(syslog_channel_arguments_facility);
                println("");
            }
        }
    }
    else
    {
        item->type = CT_FILE;

        item->arguments.file.path = strdup(value);
        unsigned int access_rights;
        
        if(sscanf(argument, "%o", &access_rights) != 1)
        {
            access_rights = FILE_CHANNEL_DEFAULT_ACCESS_RIGHTS;
        }

        item->arguments.file.access = access_rights;
    }

    return OK;
}

static ya_result config_channels_section_print(config_data *config)
{
    return SUCCESS;
}

static config_section_descriptor section_channels =
{
    "channels",
    set_variable_channels,
    config_channel_section_init,
    config_channel_section_assign,
    config_channel_section_free,
    config_channels_section_print,
    TRUE
};

const config_section_descriptor *
confs_channels_get_descriptor()
{
    return &section_channels;
}

/* *******************************************************************************************************/
/* *******************************************************************************************************/
/* *******************************************************************************************************/
/* *******************************************************************************************************/
/* *******************************************************************************************************/

/******************** Loggers*************************/


typedef struct logger_data logger_data;
struct logger_data
{
    struct logger_data                                            *next;
    struct channel_data_list                                  *channels;
    char                                                          *name;
    u32                                                      debuglevel;
};

static logger_data *tmp_loggers = NULL;
static bool has_logger_section = FALSE;

/*
 *  LOGGERS is a dynamic section so there is no config_table
 */

static ya_result config_loggers_section_init(config_data *config)
{
    has_logger_section = TRUE;
    return SUCCESS;
}

static ya_result config_loggers_section_assign(config_data *config)
{
    logger_data* logger;
    
    if(!has_logger_section)
    {
        /*
         * strtok & cie have an issue with text defined in the "const" (read-only) data section(s).
         * To avoid a segmentation fault a copy into rw memory must be used.
         */
                
        char all[2] = { '*', '\0' };
        char txt_default[8];
        memcpy(txt_default, "default", 8);
        
        set_variable_loggers("database", all, txt_default);
        set_variable_loggers("dnssec", all, txt_default);
        set_variable_loggers("server", all, txt_default);
        set_variable_loggers("stats", all, txt_default);
        set_variable_loggers("system", all, txt_default);
        set_variable_loggers("zone", all, txt_default);
        set_variable_loggers("queries", all, txt_default);
    }

    logger = tmp_loggers;

    while(logger != NULL)
    {
        OSDEBUG(termout, "logger '%s':\n", logger->name);

	/* Creates an handle with a given name */

        logger_handle* log = logger_handle_add(logger->name);

        channel_data_list* channel = logger->channels;

        while(channel != NULL)
        {
            OSDEBUG(termout, "\tAdd channel '%s'\n", channel->channel->name);

            if(!channel->channel->activated)
            {
                /*
                 * Activate the channel : no more files created and not used.
                 *
                 */

                config_channel_section_activate(config, channel->channel);
            }

            logger_handle_add_channel(log, logger->debuglevel, channel->channel->channel);

            channel = channel->next;
        }

        logger = logger->next;
    }

    loggers_assigned = TRUE;
    
    config_update_handles();
    
    return SUCCESS;
}

static ya_result
config_loggers_section_free(config_data *config)
{
    /** Loggers init */

    logger_data* logger;

    logger = tmp_loggers;
    while(logger != NULL)
    {
        logger_data* tmp = logger;
        logger = logger->next;

        channel_data_list* channel = tmp->channels;
        while(channel != NULL)
        {
            channel_data_list* tmp_channel = channel;
            channel = channel->next;

#ifndef NDEBUG
            memset(tmp_channel,0xff,sizeof(channel_data_list));
#endif

            free(tmp_channel);
        }

        free(tmp->name);

# ifndef NDEBUG
        memset(tmp,0xff,sizeof(logger_data));
#endif

        free(tmp);
    }

    return SUCCESS;
}

static value_name_table logger_debuglevels[] ={
    {1 << MSG_EMERG, "emerg"},
    {1 << MSG_ALERT, "alert"},
    {1 << MSG_CRIT, "crit"},
    {1 << MSG_ERR, "err"},
    {1 << MSG_WARNING, "warning"},
    {1 << MSG_NOTICE, "notice"},
    {1 << MSG_INFO, "info"},
    {1 << MSG_DEBUG, "debug"},
    {1 << MSG_DEBUG1, "debug1"},
    {1 << MSG_DEBUG2, "debug2"},
    {1 << MSG_DEBUG3, "debug3"},
    {1 << MSG_DEBUG4, "debug4"},
    {1 << MSG_DEBUG5, "debug5"},
    {1 << MSG_DEBUG6, "debug6"},
    {1 << MSG_DEBUG7, "debug7"},
    {(1 << (MSG_ALL + 1)) - 1, "all"},
    {(1 << (MSG_ALL + 1)) - 1, "*"},
    {0, NULL}
};

static ya_result
set_variable_loggers(char *variable, char *value, char *argument)
{
    OSDEBUG(termout, "Set logger variable  : %s (%s: %s)\n", variable, value, argument);
    
    bool valid_name = FALSE;
    
    for(int i = 0; logger_names[i] != NULL ; i++)
    {
        if(strcmp(variable, logger_names[i]) == 0)
        {
            valid_name = TRUE;
            break;
        }
    }
    
    if(!valid_name)
    {
        log_warn("config: loggers: invalid logger name '%s'", variable);

        if(strcmp(variable,"statistics") == 0)
        {
            log_warn("config: loggers: did you mean 'stats' ?");
        }
        
        return SUCCESS; /*CONFIG_LOGGER_UNDEFINED : do not give an error, only print the warning */;
    }

    char* token;
    u32 debuglevel = 0;

    for(token = strtok(value, SYSLOG_LEVEL_TOKEN_DELIMITER); token != NULL; token = strtok(NULL, SYSLOG_LEVEL_TOKEN_DELIMITER))
    {
        u32 debuglevel_value;
        
        if(FAIL(get_value_from_casename(logger_debuglevels, token, &debuglevel_value)))
        {
            osformat(termerr, "config: loggers: wrong level name for '%s'.  Valid names are: ", variable);
            print_value_name_table_names(logger_debuglevels);
            println("");

            return CONFIG_INVALID_DEBUGLEVEL;
        }

        debuglevel |= debuglevel_value;
    }

    logger_data** loggers = &tmp_loggers;
    logger_data* item = *loggers;

    /* No dups */

    for(token = strtok(argument, SYSLOG_CHANNEL_TOKEN_DELIMITER); token != NULL; token = strtok(NULL, SYSLOG_CHANNEL_TOKEN_DELIMITER))
    {
        if(*token == '\0')
        {
            continue;
        }

        /* Look for the channel -> */

        channel_data* channel = tmp_channels;

        while(channel != NULL)
        {
            if(strcasecmp(channel->name, token) == 0)
            {
                OSDEBUG(termout, "Add logger channel  : '%s'\n", channel->name);

                MALLOC_OR_DIE(logger_data*, item, sizeof (logger_data), GENERIC_TAG);

                item->next = *loggers;
                *loggers = item;

                item->name = strdup(variable);
                item->debuglevel = debuglevel;
                item->channels = NULL;

                channel_data_list* channel_item;
                MALLOC_OR_DIE(channel_data_list*, channel_item, sizeof (channel_data_list), GENERIC_TAG);
                channel_item->channel = channel;
                channel_item->next = item->channels;
                item->channels = channel_item;

                break;
            }

            channel = channel->next;
        }

        if(channel == NULL)
        {
            OSDEBUG(termout, "Channel '%s' not found\n", token);

            return CONFIG_CHANNEL_UNDEFINED;
        }

	/* <- Look for the channel */
    }

    return OK;
}

static ya_result config_loggers_section_print(config_data *config)
{
    return SUCCESS;
}

static config_section_descriptor section_loggers =
{
    "loggers",
    set_variable_loggers,
    config_loggers_section_init,
    config_loggers_section_assign,
    config_loggers_section_free,
    config_loggers_section_print,
    TRUE
};

const config_section_descriptor *
confs_loggers_get_descriptor()
{
    return &section_loggers;
}

/** @} */

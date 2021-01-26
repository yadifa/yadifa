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

#include "dnscore/dnscore-config.h"
#include <syslog.h>
#include <unistd.h>
#include <strings.h>

#include "dnscore/logger.h"
#include "dnscore/file_output_stream.h"
#include "dnscore/logger_channel_stream.h"
#include "dnscore/logger_channel_syslog.h"
#include "dnscore/logger_channel_file.h"
#include "dnscore/logger_channel_pipe.h"
#include "dnscore/parsing.h"
#include "dnscore/chroot.h"
#include "dnscore/fdtools.h"

#include "dnscore/config_settings.h"

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

/*
 *  CHANNELS is a dynamic section so there is no config_table
 */

#define FILE_CHANNEL_DEFAULT_ACCESS_RIGHTS 0644

static const value_name_table syslog_channel_arguments_options[] =
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

static const value_name_table syslog_channel_arguments_facility[] =
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

static const value_name_table logger_debuglevels[] =
{
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
    {(1 << MSG_EMERG)|(1 << MSG_ALERT)|(1 << MSG_CRIT)|(1 << MSG_ERR)|(1 << MSG_WARNING)|(1 << MSG_NOTICE)|(1 << MSG_INFO), "prod"},
    {0, NULL}
};

static const char DEFAULT_PATH[] = "";

static const char *log_path = DEFAULT_PATH;

static bool logger_section_found = FALSE;

void
config_set_log_base_path(const char *path)
{   
    if(path != NULL)
    {
        if(strcmp(path, log_path) == 0)
        {
            return;
        }
        
        log_path = strdup(path);
    }
    else
    {
        if(log_path != DEFAULT_PATH)
        {
            free((char*)log_path);
        }
        
        log_path = DEFAULT_PATH;
    }
}

static ya_result
config_section_handles_init(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
config_section_handles_start(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    
    logger_section_found = TRUE;
    
    //logger_channel_close_all();
    
    return SUCCESS;
}

static ya_result
config_section_handles_stop(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
config_section_handles_postprocess(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
config_section_handles_finalize(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
config_section_handles_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    if(logger_channel_get_usage_count(key) >= 0)
    {
        return CONFIG_LOGGER_HANDLE_ALREADY_DEFINED; // already defined
    }
    
    char value_target[PATH_MAX];
    parse_copy_word(value_target, sizeof(value_target), value);
    
    if(strcasecmp("stdout", value_target) == 0)
    {
        output_stream stdout_os;
        fd_output_stream_attach(&stdout_os, dup_ex(1));
        logger_channel *stdout_channel = logger_channel_alloc();
        logger_channel_stream_open(&stdout_os, FALSE, stdout_channel);
        logger_channel_register(key, stdout_channel);
    }
    else if(strcasecmp("stderr", value_target) == 0)
    {
        output_stream stderr_os;
        fd_output_stream_attach(&stderr_os, dup_ex(2));
        logger_channel *stderr_channel = logger_channel_alloc();
        logger_channel_stream_open(&stderr_os, FALSE, stderr_channel);
        logger_channel_register(key, stderr_channel);
    }
    else if(strcasecmp("syslog", value_target) == 0)
    {
        char* token;

        /*
         * Tokenize
         */

        u32 options = 0;
        u32 facility = 0;

        /* WARNING: NEVER EVER USE A CONST STRING AS ARGUMENT OR strtok WILL SIGSEGV */

        char *tmp_value = strdup(value); // value, not value_target
        
        for(token =  strtok(tmp_value, SYSLOG_CHANNEL_TOKEN_DELIMITER);
            token != NULL;
            token =  strtok(NULL, SYSLOG_CHANNEL_TOKEN_DELIMITER))
        {
            u32 token_value;
            
            if(ISOK(value_name_table_get_value_from_casename(syslog_channel_arguments_options, token, &token_value)))
            {
                options |= token_value;
            }
            else if(ISOK(value_name_table_get_value_from_casename(syslog_channel_arguments_facility, token, &token_value)))
            {
                facility = token_value; // Facility is NOT a bit mask
            }
            else
            {
                /* Note: empty statement is taken care of here */
                osformatln(termerr, "wrong syslog argument '%s' : ", csd->vtbl->name);
                
                free(tmp_value);
                return PARSE_INVALID_ARGUMENT;
            }
        }
        
        free(tmp_value);
        
        logger_channel *syslog_channel = logger_channel_alloc();
        logger_channel_syslog_open(key, options, facility, syslog_channel);
        logger_channel_register(key, syslog_channel);
    }
    else
    {
#ifndef WIN32
        const char *chroot_base = chroot_get_path();
        
        uid_t uid = logger_get_uid();
        gid_t gid = logger_get_gid();

        ya_result return_code;
        unsigned int access_rights;
        char fullpath[PATH_MAX];
        
        // find the end of the word
        // cut it
        
        const char *path_limit = parse_next_blank(value);
        size_t path_len = path_limit - value;
        size_t pathbase_len;
        
        if(value[0] != '|')
        {        
            if(value[0] != '/')
            {
                pathbase_len = snformat(fullpath, sizeof(fullpath), "%s%s", chroot_base, log_path);
            }
            else
            {
                pathbase_len = snformat(fullpath, sizeof(fullpath), "%s", chroot_base);
            }

            if(pathbase_len + path_len + 1 >= sizeof(fullpath))
            {
                return CONFIG_FILE_PATH_TOO_BIG;
            }

            memcpy(&fullpath[pathbase_len], value, path_len);
            path_len += pathbase_len;
            fullpath[path_len] = '\0';

            // parse the next word, it is supposed to be an octal number
#if 1
            errno = 0;

            access_rights = strtol(path_limit, NULL, 8);
            if(errno != 0)
            {
                access_rights = FILE_CHANNEL_DEFAULT_ACCESS_RIGHTS;
            }
#else
            if(sscanf(path_limit, "%o", &access_rights) != 1)
            {
                access_rights = FILE_CHANNEL_DEFAULT_ACCESS_RIGHTS;
            }
#endif
            
            bool sync = FALSE;

            // if the path starts with a slash, it's absolute, else it's relative
            // to the log directory

            logger_channel* file_channel = logger_channel_alloc();
            if(FAIL(return_code = logger_channel_file_open(fullpath, uid, gid, access_rights, sync, file_channel)))
            {
                osformatln(termerr, "config: unable to open file channel '%s' (%d:%d %o) : %r", fullpath, uid, gid, access_rights, return_code);
                flusherr();

                return return_code;
            }

            logger_channel_register(key, file_channel);
        }
        else
        {
            ++value;

            logger_channel* file_channel = logger_channel_alloc();
            if(FAIL(return_code = logger_channel_pipe_open(value, FALSE, file_channel)))
            {
                osformatln(termerr, "config: unable to open pipe channel '%s' : %r", fullpath, return_code);
                flusherr();

                return return_code;
            }

            logger_channel_register(key, file_channel);
        }
#else
    osformatln(termerr, "config: pipes not supported");
    return ERROR;
#endif
    }
    
    return SUCCESS;
}

static ya_result
config_section_handles_print_wild(const struct config_section_descriptor_s *csd, output_stream *os, const char *key)
{
    (void)csd;
    (void)os;
    (void)key;

    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

static ya_result
config_section_loggers_init(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    
    return SUCCESS;
}

static ya_result
config_section_loggers_start(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    
    logger_section_found = TRUE;
    
    // clear all loggers
    
    return SUCCESS;
}

static ya_result
config_section_loggers_stop(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
config_section_loggers_postprocess(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}


static ya_result
config_section_loggers_finalize(struct config_section_descriptor_s *csd)
{
    // NOP
    (void)csd;
    return SUCCESS;
}

static ya_result
config_section_loggers_set_wild(struct config_section_descriptor_s *csd, const char *key, const char *value)
{
    (void)csd;

    u32 debuglevel = 0;
    ya_result return_code;
    
    // next word(base,delimiter)
    // 

    bool end_of_level = FALSE;
    
    do
    {
        char level[16];
        
        value = parse_skip_spaces(value);
        
        if(*value == '\0')
        {
            break;
        }
        
        if(FAIL(return_code = parse_next_token(level, sizeof(level), value, SYSLOG_LEVEL_TOKEN_DELIMITER)))
        {
            return return_code;
        }
        
        // if the token has spaces between two chars, then we need to cut
        
        char *end_of_first_word = (char*)parse_next_blank(level); // level is not const
        if(*end_of_first_word != '\0')
        {
            char *start_of_next_word = (char*)parse_skip_spaces(end_of_first_word); // end_of_first_word is not const

            if(start_of_next_word != end_of_first_word)
            {
                // last loop iteration
                
                end_of_level = TRUE;
            }
            
            *end_of_first_word = '\0';
            
            // adjust next word search start
            
            value += end_of_first_word - level + 1;
        }
        else
        {
            value += (size_t)return_code + 1; // note: false positive from cppcheck
        }
        
        //
        
        u32 debuglevel_value;
        
        if(FAIL(value_name_table_get_value_from_casename(logger_debuglevels, level, &debuglevel_value)))
        {
            return CONFIG_LOGGER_INVALID_DEBUGLEVEL;
        }

        debuglevel |= debuglevel_value;
    }
    while(!end_of_level);
    
    for(;;)
    {
        char channel_name[64];
        
        value = parse_skip_spaces(value);
        
        if(*value == '\0')
        {
            break;
        }
        
        if(FAIL(return_code = parse_next_token(channel_name, sizeof(channel_name), value, SYSLOG_CHANNEL_TOKEN_DELIMITER)))
        {
            return return_code;
        }
                
        if(*channel_name == '\0')
        {
            continue;
        }

        logger_handle_add_channel(key, (int)debuglevel, channel_name);
        
        value += return_code;
        
        if(*value == '\0')
        {
            break;
        }
        
        value++;
    }
    
    return SUCCESS;
}

static ya_result
config_section_loggers_print_wild(const struct config_section_descriptor_s *csd, output_stream *os, const char *key)
{
    (void)csd;
    (void)os;
    (void)key;

    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

static const config_section_descriptor_vtbl_s config_section_handles_descriptor_vtbl =
{
    "channels",                         // no table
    NULL,
    config_section_handles_set_wild,
    config_section_handles_print_wild,
    config_section_handles_init,
    config_section_handles_start,
    config_section_handles_stop,
    config_section_handles_postprocess,
    config_section_handles_finalize
};

static const config_section_descriptor_s config_section_handles_descriptor =
{
    NULL,
    &config_section_handles_descriptor_vtbl
};

static const config_section_descriptor_vtbl_s config_section_loggers_descriptor_vtbl =
{
    "loggers",
    NULL,                               // no table
    config_section_loggers_set_wild,
    config_section_loggers_print_wild,
    config_section_loggers_init,
    config_section_loggers_start,
    config_section_loggers_stop,
    config_section_loggers_postprocess,
    config_section_loggers_finalize
};

static const config_section_descriptor_s config_section_loggers_descriptor =
{
    NULL,
    &config_section_loggers_descriptor_vtbl
};

/// register the logging configuration
/// note that for this to work, logger_handle_create("handle-name",logger_handle_for_handle_name_ptr_ptr)
/// must be called before the config_read is done
ya_result
config_register_logger(const char *null_or_channels_name, const char *null_or_loggers_name, s32 priority)
{
    //null_or_channels_name = "channels";
    //null_or_loggers_name = "loggers";
    (void)null_or_channels_name;
    (void)null_or_loggers_name;

    if(priority < 0)
    {
        priority = 0;
    }
    
    ya_result return_code;
    
    if(ISOK(return_code = config_register_const(&config_section_handles_descriptor, priority + 0)))
    {
        return_code = config_register_const(&config_section_loggers_descriptor, priority + 1);
    }
    
    return return_code;
}

bool config_logger_isconfigured()
{
    return logger_section_found;
}

void config_logger_clearconfigured()
{
    logger_section_found = FALSE;
}

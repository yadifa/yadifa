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
 *  @brief yadifa
 */

#include "client-config.h"

#include <ctype.h>

#include <dnscore/logger_handle.h>
#include <dnscore/cmdline.h>
#include <dnscore/config-cmdline.h>
#include <dnscore/config_settings.h>
#include <dnscore/string_set.h>

#include <dnscore/sys_types.h>
#include <dnscore/host_address.h>
#include <dnscore/fdtools.h>

#include <sys/stat.h>

#include "ya-conf.h"
#include "common-config.h"


#include "module.h"

#define DISTANCE_CONF_C_

/*----------------------------------------------------------------------------*/
#pragma mark DEFINES 

#define DEF_DISTANCE_CONF                     SYSCONFDIR "/DISTANCE.conf"


/*----------------------------------------------------------------------------*/
#pragma mark DEFINES


#define DEF_VAL_CLASS                                              "CTRL"
#define DEF_VAL_TYPE                                              "TYPE0"
#define DEF_YADIFA_CONF                         SYSCONFDIR "/yadifa.conf"

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

/*----------------------------------------------------------------------------*/
#pragma mark CONFIG


// ********************************************************************************
// ***** module settings
// ********************************************************************************

#define CONFIG_TYPE yadifa_main_settings_s
CONFIG_BEGIN(yadifa_main_settings_desc)
//CONFIG_HOST_LIST_EX( server,        DEF_VAL_SERVER,       CONFIG_HOST_LIST_FLAGS_DEFAULT, 1        )
//CONFIG_DNS_CLASS(    qclass,        DEF_VAL_CLASS                                                  )
//CONFIG_DNS_TYPE(     qtype,         DEF_VAL_TYPE                                                   )
//CONFIG_FQDN(         qname,         "."                                                            )
//CONFIG_FQDN(         tsig_key_name, "ctrl-key"                                                     )
//CONFIG_BOOL(         enable,        "on"                                                           )
//CONFIG_BOOL(         clean,         "off"                                                          )
CONFIG_STRING(       config_file,   DEF_YADIFA_CONF                                                )
CONFIG_END(yadifa_main_settings_desc)
#undef CONFIG_TYPE

yadifa_main_settings_s                                          g_yadifa_main_settings;

/*----------------------------------------------------------------------------*/
//#pragma mark FUNCTIONS

/**
 *  @fn ya_result distance_config_init()
 *  @brief distance_config_init
 *
 *  @param nothing --
 *  @return ya_result
 */

ya_result
ya_conf_init()
{
    ya_result                                                               ret;

    if(FAIL(ret = config_init()))
    {
        return ret;
    }

    // ? config_set_source(CONFIG_SOURCE_CMDLINE);
    
    int priority = 1;

    if(FAIL(ret = config_register_cmdline(priority++)))
    {
        return ret;
    }

    /* 4. register main options: qname, qclass, qtype, ...
     *
     * init and register main settings container */
    ZEROMEMORY(&g_yadifa_main_settings, sizeof(g_yadifa_main_settings));
    if(FAIL(ret = config_register_struct(MAIN_SECTION_NAME, yadifa_main_settings_desc, &g_yadifa_main_settings, priority++)))
    {
        return ret;
    }

    if(FAIL(ret = config_register_key("key", 7)))
    {
        return ret;
    }
    
    if(logger_is_running())
    {
        if(FAIL(ret = config_register_logger(NULL, NULL, priority))) // 5 & 6
        {
            return ret;
        }

        priority += 2;
    }
    
    return priority;
}

ya_result
ya_conf_read(const cmdline_desc_s *cmdline_table, int argc, char **argv, cmdline_filter_callback *filter, void *filter_arg, const char *rcfilename)
{
    input_stream config_is;
    config_error_s cfgerr;
    ya_result return_code;
    
    config_set_source(CONFIG_SOURCE_HIGHEST);

    int argc_error;

    if(FAIL(return_code = cmdline_parse(cmdline_table, argc, argv, filter, filter_arg, &config_is, &argc_error)))
    {
        if(argc_error > 0)
        {
            formatln("command line: %r at %s", return_code, argv[argc_error]);
        }
        else
        {
            formatln("command line: %r", return_code);
        }
        flushout();

        return return_code;
    }
    
    config_set_source(CONFIG_SOURCE_CMDLINE);
        
    u32 cmdline_buffer_size = bytearray_input_stream_size(&config_is);
    u8* cmdline_buffer = bytearray_input_stream_detach(&config_is);
    
    input_stream_close(&config_is);

    if(FAIL(return_code = config_read_from_buffer((const char*)cmdline_buffer, cmdline_buffer_size, "command-line", &cfgerr)))
    {
        if(cfgerr.file[0] != '\0')
        {
            formatln("command line: '%s': %r", cfgerr.line, return_code);
            flushout();
        }
        
        free(cmdline_buffer);
        
        return return_code;
    }
    
    free(cmdline_buffer);
    
    return_code  = cmdline_help_get()?1:0;
    return_code |= cmdline_version_get() << 1;
    
    // if return_code != 0, then specific help has been asked
    
    if(return_code != 0)
    {
        return return_code;
    }
    
    config_set_source(CONFIG_SOURCE_DEFAULT);
    
    if(FAIL(return_code = config_value_set_to_default(MAIN_SECTION_NAME, "config_file", &cfgerr)))
    {
        if(cfgerr.file[0] != '\0')
        {
            osformatln(termerr, "%s: %r",  cfgerr.file, return_code);
            flusherr();
        }
        else
        {
            // should never happen

            osformatln(termerr, "error: %r",  cfgerr.file, return_code);
            flusherr();
        }

        return return_code;
    }
    
    /**
     *  The RC file should be set here as a source.
     *  Multiples sources can be read in parallel.
     *  Then again, is an rc file needed for this tool ?
     */
   
    int sources_count = 0;
    struct config_source_s sources[2];
    char rcfullpath[PATH_MAX];
    
    if(rcfilename != NULL)
    {
#if _GNU_SOURCE
        const char *home = secure_getenv("HOME");
#else
        const char *home = getenv("HOME");
#endif
        if(home != NULL)
        {
            if(ISOK(snformat(rcfullpath, sizeof(rcfullpath), "%s/%s", home, rcfilename)))
            {
                if(file_exists(rcfullpath))
                {
                    config_source_set_file(&sources[sources_count], rcfullpath, CONFIG_SOURCE_FILE);    // + 1 => higher priority
                    sources_count++;
                }
            }
        }        
    }
    
    config_source_set_file(&sources[sources_count], g_yadifa_main_settings.config_file, CONFIG_SOURCE_FILE - 1);
    sources_count++;

    return_code =  config_read_from_sources(sources, sources_count, &cfgerr);

    if(FAIL(return_code))
    {
        if(return_code == MAKE_ERRNO_ERROR(ENOENT))
        {
            return_code = SUCCESS;  // config file shouldn't always be mandatory
        }
        else
        {
            osformatln(termerr, "error: failed to read the configuration '%s': %r", cfgerr.file, return_code);
            flusherr();
        }
    }

    return return_code;
}

/**
 *  @fn ya_result distance_config_finalize()
 *  @brief  yadifa_config_finalize
 *
 *  @param -- nothing --
 *  @return ya_result
 */
ya_result
ya_conf_finalize()
{
    return SUCCESS;
}

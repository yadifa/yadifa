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

#define CONFIG_RESOLVER_C

#include <dnscore/config_settings.h>
#include "dnslg/resolv-conf.h"


const char RESOLVER_CONTAINER[] = "resolver";

// resolver defines

#define     DEF_VAL_CONF_OPTION_NAMESERVERS         "172.19.110.8 port 53"
#define     DEF_VAL_CONF_OPTION_ATTEMPTS            "3"
#define     DEF_VAL_CONF_OPTION_TIMEOUT             "1"
#define     DEF_VAL_CONF_OPTION_UDP_TRIES           "1"
#define     DEF_VAL_CONF_OPTION_NDOTS               "1"
#define     DEF_VAL_CONF_OPTION_RES_DEBUG           "0"
#define     DEF_VAL_CONF_OPTION_NO_TLD_QUERY        "0"

/// resolver container
#define CONFIG_TYPE resolv_s
CONFIG_BEGIN(config_resolver_desc)

CONFIG_HOST_LIST_EX( nameserver,   DEF_VAL_CONF_OPTION_NAMESERVERS, CONFIG_HOST_LIST_FLAGS_DEFAULT /*| CONFIG_HOST_LIST_FLAGS_APPEND*/, 3 )
CONFIG_U16(          timeout,      DEF_VAL_CONF_OPTION_TIMEOUT      )
CONFIG_U8(           attempts,     DEF_VAL_CONF_OPTION_ATTEMPTS     )
CONFIG_U8(           ndots,        DEF_VAL_CONF_OPTION_NDOTS        )
CONFIG_BOOL(         no_tld_query, DEF_VAL_CONF_OPTION_NO_TLD_QUERY )
CONFIG_BOOL(         debug,        DEF_VAL_CONF_OPTION_RES_DEBUG    )
// tricky struct, so go raw on it
CONFIG_SEARCH_OR_DOMAIN(search_or_domain)

CONFIG_END(config_resolver_desc)
#undef CONFIG_TYPE





// declare global variable 
resolv_s config_resolver_settings;


ya_result
config_register_resolver(u8 priority)
{
    ya_result return_code;

    // init and register resolver settings container
    ZEROMEMORY(&config_resolver_settings, sizeof(config_resolver_settings));
//    ptr_vector_init(&config_resolver_settings.servers);
    if(FAIL(return_code = config_register_struct(RESOLVER_CONTAINER, config_resolver_desc, &config_resolver_settings, priority)))
    {
        return return_code;
    }


    return 0;
}

u8
resolver_time_get()
{
//    return config_resolver_settings.udp_time;
    return 0;
}


u8
resolver_tries_get()
{
    return config_resolver_settings.attempts;
}


u8
resolver_retry_get()
{
 //   return config_resolver_settings.udp_retry;
    return 0;
}


u8
resolver_ndots_get()
{
    return config_resolver_settings.ndots;
}


bool
resolver_res_debug_get()
{
    return config_resolver_settings.debug;
}


bool
resolver_no_tld_query()
{
    return config_resolver_settings.no_tld_query;
}

host_address *
resolver_nameservers_get()
{
    return config_resolver_settings.nameserver;
}


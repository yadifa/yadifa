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

#include <dnscore/sys_types.h>
#include <dnscore/host_address.h>
//#include <dnscore/ptr_vector.h>

#ifndef CONFIG_RESOLVER_C
extern const char RESOLVER_CONTAINER[];
#endif

#define RO_NO_DOMAIN_OR_SEARCH     0
#define RO_DOMAIN                  1
#define RO_SEARCH                  2

#define CONFIG_SEARCH_OR_DOMAIN(fieldname) \
{"search", offsetof(CONFIG_TYPE, fieldname), (config_set_field_function*)config_set_search_or_domain, NULL,{._u8=RO_SEARCH}, 0, 0, CONFIG_TABLE_SOURCE_NONE, 0}, \
{"domain", offsetof(CONFIG_TYPE, fieldname), (config_set_field_function*)config_set_search_or_domain, NULL,{._u8=RO_DOMAIN}, 0, 0, CONFIG_TABLE_SOURCE_NONE, 0},


struct search_or_domain_s
{
    union
    {
        host_address            *search;
        host_address            *domain;
        host_address            *list;
    } address;
    u8 search_or_domain;
};

typedef struct search_or_domain_s search_or_domain_s;


/*    ------------------------------------------------------------    */


struct resolv_s
{
    search_or_domain_s  search_or_domain;
    host_address             *nameserver;

    u16                          timeout;
    u8                          attempts;
    u8                             ndots;
    bool                    no_tld_query;
    bool                           debug;
};

typedef struct resolv_s resolv_s;



// resolver section

#define CMDLINE_RESOLVER(resolver)                                       \
CMDLINE_SECTION(  RESOLVER_CONTAINER)                                    \
CMDLINE_BOOL(     "no_tld_query",     'Z',  "no_tld_query"               ) \
CMDLINE_BOOL(     "res_debug",        'Y',  "debug"                      ) \
CMDLINE_OPT(      "attempts",         0,  "attempts"                   ) \
CMDLINE_OPT(      "ndots",            0,  "ndots"                      ) \
CMDLINE_OPT(      "timeout",          0,  "timeout"                    )

//CMDLINE_OPT(      "retry",            0,  "udp_retry"                  ) 
//CMDLINE_OPT(      "nameserver",      's', "nameservers"                ) 

ya_result config_register_resolver(u8 priority);

bool resolver_no_tld_query();
bool resolver_res_debug_get();

u8 resolver_ndots_get();
u8 resolver_retry_get();
u8 resolver_time_get();
u8 resolver_tries_get();

host_address* resolver_nameservers_get();



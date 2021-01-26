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

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef RESOLV_H_
#define RESOLV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <dnscore/host_address.h>

/* defaults, minimum and maximum values for the resolver_s struct */

#define RES_PATH_RESOLV_CONF        "/etc/resolv.conf"

#define RES_NAME_SERVERS_MAX        3              /* MAXNS */
    
#define RES_OPTION_ATTEMPTS_DEFAULT 2
#define RES_OPTION_ATTEMPTS_MAX     5

#define RES_OPTION_NDOTS_DEFAULT    1
#define RES_OPTION_NDOTS_MAX        15

#define RES_TIMEOUT_DEFAULT         5
#define RES_TIMEOUT_MAX             30

struct resolver_s 
{
    host_address  *nameserver;

    u8           *sortlist[6];

    union 
    {
        u8            *domain;
        u8         *search[6];
    } name_ascii;
    u8        name_ascii_type;

    u8              resolv_ns;

    u8                  ndots;
    u8               attempts;
    u8                timeout;
    u8            timeout_max;
};

typedef struct resolver_s resolver_s;

void resolv_without_forward(void);
void resolv_print_version(void);


int resolv_normal(void);

ya_result resolv_lookup_name_server(host_address **dest);

ya_result resolv_init(resolver_s *resolv);
ya_result resolv_add_hostaddress(resolver_s *resolv, host_address *address);
ya_result resolv_add_domain(resolver_s *resolv, char *domain);
ya_result resolv_add_search(resolver_s *resolv, char *search);
ya_result resolv_add_ndots(resolver_s *resolv, u8 ndots);
ya_result resolv_add_attemps(resolver_s *resolv, u8 attemps);
ya_result resolv_add_timeout(resolver_s *resolv, u8 timeout);

#define IP_LIST_MAX 16  

#define HAS_IPV4    0x01
#define HAS_IPV6    0x02


ya_result resolv_address(host_address *src, host_address *dst, int ip_flags);
ya_result resolv_host_address_list(host_address *src, host_address *dst);





#ifdef __cplusplus
}
#endif

#endif /* RESOLV_H_ */

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/


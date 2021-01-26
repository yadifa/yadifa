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

#include <stdlib.h>
#include <stdio.h>

#include <dnscore/host_address.h>
#include <dnscore/format.h>
#include <dnscore/parsing.h>

#include "dnslg/resolv.h"

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** @brief Function ...
 *
 *  ...
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */

#define RESOLVER_TAG 0x7A457E72757B457A



void
resolv_without_forward(void)
{
    //
}

void
resolv_print_version(void)
{
    printf("1.0.1");

    return;
}


ya_result
resolv_lookup_name_server(host_address **dest)
{
    ya_result                                                   return_code;
    host_address                                                   *address;

    u8                                         dname[MAX_DOMAIN_LENGTH + 1];
///    tsig_item                                                  *tsig = NULL;

    u16                                                        ip_port = 53;
    u8                                                        ip_buffer[16];
    u8                                                              ip_size;

    u32                                                     port_value = 53; /// @todo 20130618 gve -- needs to be more generic

    char                                            *value = "172.19.110.8";

    /*    ------------------------------------------------------------    */



    // 1. GET THE IP ADDRESS(ES) FROM "/etc/resolv.conf"


    if(FAIL(return_code = parse_ip_address(value, strlen(value), ip_buffer, sizeof(ip_buffer))))
    {

        return_code = 255;
    }

    ip_size = (u8)return_code;
    ip_port = (u16)port_value;


    // 2. STORE THE IP ADDRESS(ES) IN "dest"
    
    MALLOC_OBJECT_OR_DIE(address, host_address, HOSTADDR_TAG);

    address->next = NULL;

#if DNSCORE_HAS_TSIG_SUPPORT
    address->tsig = NULL;
#endif

    switch(ip_size)
    {
        case 4:
            {
                host_address_set_ipv4(address, ip_buffer, htons(ip_port));
                break;
            }
        case 16:
            {
                host_address_set_ipv6(address, ip_buffer, htons(ip_port));
                break;
            }
        case 255:
            {
                host_address_set_dname(address, dname, htons(ip_port));
                break;
            }
    }

    *dest = address;

    return SUCCESS;
}




ya_result
resolv_init(resolver_s *resolv)
{
    ZEROMEMORY(resolv, sizeof(struct resolver_s));
/*** @todo 20130823 gve -- implement
    resolv->option_attempts =  RES_OPTION_ATTEMPTS_DEFAULT;
    resolv->option_ndots    = RES_OPTION_NDOTS_DEFAULT;
    resolv->option_timeout  =  RES_TIMEOUT_DEFAULT;
*/

    return OK;
}


ya_result
resolv_add_hostaddress(resolver_s *resolv, host_address *address)
{

//    host_address **nameserver;

    return 0;
}




// 172.19.110.8
// 172.31.110.8
// search be.eurid.eu vt.eurid.eu tc.eurid.eu eurid.eu int.eurid.eu


    /*    ------------------------------------------------------------    */


/**
 *
 *  Resolving
 *
 *  - 
 *
 *
 *
 *
 *
 */

// remove addrinfo structure
static void
free_addrinfo(struct addrinfo *ai)
{
    struct addrinfo                                                *temp_ai;

    /*    ------------------------------------------------------------    */

    while (ai != NULL)
    {
        temp_ai = ai->ai_next;

        if (ai->ai_addr != NULL)
        {
            free(ai->ai_addr);
        }
        if (ai->ai_canonname)
        {
            free(ai->ai_canonname);
        }
        free(ai);

        ai = temp_ai;
    }
}


ya_result
resolv_address(host_address *src, host_address *dst, int ip_flags)
{
    struct addrinfo                                                  hints;
    struct addrinfo                                               *ai_list;
    struct addrinfo                                                    *ai;

    struct sockaddr_in                                                *sin;

/// @todo 20160308 gve -- needs to be checked for linux


    int                                                         error_code;

    ya_result                                            return_code = TRUE;

    char                                   fqdn[MAX_DOMAIN_TEXT_LENGTH + 1];

    /*    ------------------------------------------------------------    */


    // 1. PREPARE THE HINTS
    //
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags     |= AI_CANONNAME;

    // no need to search for IPv6, IPv4 only
    if (! (ip_flags & HAS_IPV6))
    {
        hints.ai_family     = PF_INET;
    }
    // no need to search for IPv4, IPv6 only
    if (! (ip_flags & HAS_IPV4))
    {
        hints.ai_family     = PF_INET6;
    }
    // go search for IPv4 and IPv6
    else
    {
        hints.ai_family     = PF_UNSPEC;
    }

    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_addr       = NULL;
    hints.ai_next       = NULL;


    // 2. GET THE IP ADDRESS 
    //
    dnsname_to_cstr(fqdn, src->ip.dname.dname);
#if DEBUG
    formatln("dname: %{hostaddr}", src);
#endif

//    size_t len = strlen(fqdn);
//    fqdn[len -1] = '\0';
//    formatln("dname: %s", fqdn);

    error_code = getaddrinfo(fqdn, NULL, &hints, &ai_list);

    if (error_code != 0)
    {
        perror ("getaddrinfo");

        return -1; // @todo 20140509 gve -- nicer error code ---
    }


    // 3. WRITE THE RESULT INTO HOST_ADDRESS LIST
    //
    int i;
    for (ai = ai_list, i = 0; ai != NULL && i < IP_LIST_MAX; ai = ai->ai_next)
    {
        switch (ai->ai_family)
        {
            case AF_INET:
                    sin = (struct sockaddr_in *)ai->ai_addr;

                    if (dst->version == 0)
                    {
                        host_address_set_ipv4(dst, (const u8 *)&sin->sin_addr.s_addr, dst->port); /// @note use host_address_set_with_sockaddr (translates v4 & v6)
                    }
                    else
                    {
                        host_address_append_ipv4(dst, (const u8 *)&sin->sin_addr.s_addr, dst->port);
                    }

                break;

        }
        i++;
    }
    free_addrinfo(ai);


    return return_code;
}


ya_result
resolv_host_address_list(host_address *src, host_address *dst)
{
    ya_result                                            return_code = TRUE;
//    char                                   fqdn[MAX_DOMAIN_TEXT_LENGTH + 1];
//    s32                                                            fqdn_len;

    /*    ------------------------------------------------------------    */

    // init destination host address list
    host_address_clear(dst);
    dst->next = NULL;


    // go thru the list and all fqdn will be resolved into a new list (dst)
    while(src != NULL)
    {
        if (src->version == HOST_ADDRESS_DNAME)
        {
//            fqdn_len = dnsname_to_cstr(fqdn, src->ip.dname.dname);

            if(FAIL(return_code = resolv_address(src, dst, HAS_IPV4 | HAS_IPV6)))
            {
#if DEBUG
                formatln("RESOLV ADDRESS FAULT");
#endif
                return return_code;
            }
        }

        src = src->next;
    }


    return return_code;
}


/** @} */

/*----------------------------------------------------------------------------*/

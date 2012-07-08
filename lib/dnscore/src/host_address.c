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
/** @defgroup dnscoretools Generic Tools
 *  @ingroup dnscore
 *  @brief host address (list) functions
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#if  0 /* BSD */
#include <sys/types.>
#endif
#include <sys/socket.h>
#include <netinet/in.h>

#include "dnscore/host_address.h"


/*------------------------------------------------------------------------------
 * FUNCTIONS */

/**
 * Deletes a host addresse
 * 
 * @param the host address
 */

void
host_address_delete(host_address *address)
{
    if(address->version == HOST_ADDRESS_DNAME)
    {
        free(address->ip.dname.dname);
    }

    free(address);
}

/**
 * Deletes a list of host addresses
 *
 * @todo: move to a better place
 * 
 * @param the first host address in the list
 */

void
host_address_delete_list(host_address *address)
{
    while(address != NULL)
    {
        host_address *next = address->next;

        host_address_delete(address);

        address = next;
    }
}

host_address *
host_address_copy_list(host_address *address)
{
    host_address clone_head;
    clone_head.next = NULL;
    
    host_address *clone = &clone_head;
    
    while(address != NULL)
    {
        host_address_append_host_address(clone, address);
                
        clone = clone->next;

        address = address->next;
    }
    
    return clone_head.next;
}

u32
host_address_count(host_address *address)
{
    u32 n = 0;

    while(address != NULL)
    {
        n++;
        address = address->next;
    }

    return n;
}

ya_result
host_address2allocated_sockaddr(struct sockaddr **sap, host_address *address)
{
    switch(address->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            struct sockaddr_in *sa_in;

#if HAS_SOCKADDR_SA_LEN != 0
            sa_in->sa_len = sizeof(struct sockaddr_in);
#endif
            MALLOC_OR_DIE(struct sockaddr_in*, sa_in, sizeof(struct sockaddr_in), SOCKADD4_TAG);
            ZEROMEMORY(sa_in, sizeof(struct sockaddr_in));
            memcpy(&sa_in->sin_addr.s_addr, address->ip.v4.bytes, 4);
            //sa_in->sin_addr.s_addr = htonl(sa_in->sin_addr.s_addr);
            sa_in->sin_port = address->port;
            sa_in->sin_family = AF_INET;
            *sap = (struct sockaddr*)sa_in;
            return sizeof(struct sockaddr_in);
        }
        case HOST_ADDRESS_IPV6:
        {
            struct sockaddr_in6 *sa_in6;

#if HAS_SOCKADDR_SA_LEN != 0
            sa_in6->sa_len = sizeof(struct sockaddr_in6);
#endif
            MALLOC_OR_DIE(struct sockaddr_in6*, sa_in6, sizeof(struct sockaddr_in6), SOCKADD6_TAG);
            ZEROMEMORY(sa_in6, sizeof(struct sockaddr_in6));
            memcpy(&sa_in6->sin6_addr, address->ip.v6.bytes, 16);
            sa_in6->sin6_port = address->port;
            sa_in6->sin6_family = AF_INET6;
            /*
               sa_in6->sin6_flowinfo = 0;
               sa_in6->sin6_scope_id = 0;
               */
            *sap = (struct sockaddr*)sa_in6;
            return sizeof(struct sockaddr_in6);
        }
        default:
        {
            return ERROR;   /* unsupported ip version */
        }
    }
}

ya_result
host_address2sockaddr(socketaddress *sap, host_address *address)
{
    switch(address->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            struct sockaddr_in *sa_in = (struct sockaddr_in*)sap;

#if HAS_SOCKADDR_SA_LEN != 0
            sa_in->sa_len = sizeof(struct sockaddr_in);
#endif
            ZEROMEMORY(sa_in, sizeof(struct sockaddr_in));
            memcpy(&sa_in->sin_addr.s_addr, address->ip.v4.bytes, 4);

            sa_in->sin_port = address->port;
            sa_in->sin_family = AF_INET;

            return sizeof(struct sockaddr_in);
        }
        case HOST_ADDRESS_IPV6:
        {
            struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6*)sap;

#if HAS_SOCKADDR_SA_LEN != 0
            sa_in6->sa_len = sizeof(struct sockaddr_in6);
#endif

            ZEROMEMORY(sa_in6, sizeof(struct sockaddr_in6));
            memcpy(&sa_in6->sin6_addr, address->ip.v6.bytes, 16);
            sa_in6->sin6_port = address->port;
            sa_in6->sin6_family = AF_INET6;

            return sizeof(struct sockaddr_in6);
        }
        default:
        {
            return ERROR;   /* unsupported ip version */
        }
    }
}

void
host_set_default_port_value(host_address *address, u16 port)
{
    /* set the default port on any unset port */

    while(address != NULL)
    {
        if(address->port == 0)
        {
            address->port = port;
        }

        address = address->next;
    }
}

ya_result
host_address2addrinfo(struct addrinfo **addrp, host_address *address)
{
    struct addrinfo *addr;
    ya_result return_value;

    MALLOC_OR_DIE(struct addrinfo*, addr, sizeof(struct addrinfo), GENERIC_TAG);

    addr->ai_flags = AI_PASSIVE;

    addr->ai_protocol = 0; /* IPPROTO_UDP | IPPROTO_TCP */
    addr->ai_socktype = 0; /* SOCK_DGRAM SOCK_STREAM */
    addr->ai_canonname = NULL;
    addr->ai_next = NULL;

    switch(address->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            addr->ai_family = AF_INET;
            break;
        }
        case HOST_ADDRESS_IPV6:
        {
            addr->ai_family = AF_INET6;
            break;
        }
        default:
        {
            free(addr);
            return ERROR;
        }
    }

    if(ISOK(return_value = host_address2allocated_sockaddr(&addr->ai_addr, address)))
    {
        addr->ai_addrlen = return_value;
        *addrp = addr;
    }
    else
    {
        free(addr);
    }

    return return_value;
}

ya_result
host_address_set_with_sockaddr(host_address *address, const socketaddress *sa)
{
    switch(sa->sa.sa_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in *sain = (const struct sockaddr_in*)sa;

            address->version = HOST_ADDRESS_IPV4;
            address->port = sain->sin_port;
            address->ip.v4.value = sain->sin_addr.s_addr;
                        
            return SUCCESS;
        }
        case AF_INET6:
        {
            const struct sockaddr_in6 *sain6 = (const struct sockaddr_in6*)sa;

            address->version = HOST_ADDRESS_IPV6;
            address->port = sain6->sin6_port;
            memcpy(address->ip.v6.bytes, &sain6->sin6_addr, 16);
            
            return SUCCESS;
        }
        default:
        {
            return ERROR;
        }
    }
}

bool
host_address_list_contains_ip(host_address *address_list, const socketaddress *sa)
{
    host_address address;
    
    if(ISOK(host_address_set_with_sockaddr(&address, sa)))
    {
        switch(address.version)
        {
            case HOST_ADDRESS_IPV4:
            {
                while(address_list != NULL)
                {
                    if(address_list->version == HOST_ADDRESS_IPV4)
                    {
                        if(address_list->ip.v4.value == address.ip.v4.value)
                        {
                            return TRUE;
                        }
                    }

                    address_list = address_list->next;
                }
                
                break;
            }
            case HOST_ADDRESS_IPV6:
            {
                while(address_list != NULL)
                {
                    if(address_list->version == HOST_ADDRESS_IPV6)
                    {
                        if((address_list->ip.v6.lohi[0] == address.ip.v6.lohi[0]) && (address_list->ip.v6.lohi[1] == address.ip.v6.lohi[1]))
                        {
                            return TRUE;
                        }
                    }

                    address_list = address_list->next;
                }
                
                break;
            }
            default:
            {
                break;
            }
        }
    }
    
    return FALSE;
}

bool
host_address_list_contains_host(host_address *address_list, const host_address *address)
{
    switch(address->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            while(address_list != NULL)
            {
                if(address_list->version == HOST_ADDRESS_IPV4)
                {
                    if(address_list->ip.v4.value == address->ip.v4.value)
                    {
                        return TRUE;
                    }
                }

                address_list = address_list->next;
            }

            break;
        }
        case HOST_ADDRESS_IPV6:
        {
            while(address_list != NULL)
            {
                if(address_list->version == HOST_ADDRESS_IPV6)
                {
                    if((address_list->ip.v6.lohi[0] == address->ip.v6.lohi[0]) && (address_list->ip.v6.lohi[1] == address->ip.v6.lohi[1]))
                    {
                        return TRUE;
                    }
                }

                address_list = address_list->next;
            }

            break;
        }
        default:
        {
            break;
        }
    }
    
    return FALSE;
}

void
host_address_set_ipv4(host_address *address, u8 *ipv4, u16 port)
{
    memcpy(address->ip.v4.bytes, ipv4, 4);
    address->port = port;
    address->version = HOST_ADDRESS_IPV4;
}

void
host_address_set_ipv6(host_address *address, u8 *ipv6, u16 port)
{
    memcpy(address->ip.v6.bytes, ipv6, 16);
    address->port = port;
    address->version = HOST_ADDRESS_IPV6;
}

void
host_address_set_dname(host_address *address, u8 *dname, u16 port)
{
    address->ip.dname.dname = dnsname_dup(dname);
    address->port = port;
    address->version = HOST_ADDRESS_DNAME;
}

ya_result
host_address_append_ipv4(host_address *address, u8 *ipv4, u16 port)
{
    for(;;)
    {
        if(address->version == HOST_ADDRESS_IPV4)
        {
            if(memcmp(address->ip.v4.bytes, ipv4, 4) == 0)
            {
                /* dup */
                return ERROR;
            }
        }
        
        if(address->next == NULL)
        {
            break;
        }

        address = address->next;
    }

    host_address *new_address;

    MALLOC_OR_DIE(host_address*, new_address, sizeof(host_address), HOSTADDR_TAG);
    new_address->next = NULL;
    new_address->tsig = NULL;
    host_address_set_ipv4(new_address, ipv4, port);
    address->next = new_address;

    return SUCCESS;
}

ya_result
host_address_append_ipv6(host_address *address, u8 *ipv6, u16 port)
{
    for(;;)
    {
        if(address->version == HOST_ADDRESS_IPV6)
        {
            if(memcmp(address->ip.v6.bytes, ipv6, 16) == 0)
            {
                /* dup */
                return ERROR;
            }
        }

        if(address->next == NULL)
        {
            break;
        }

        address = address->next;
    }

    host_address *new_address;

    MALLOC_OR_DIE(host_address*, new_address, sizeof(host_address), HOSTADDR_TAG);
    new_address->next = NULL;
    new_address->tsig = NULL;
    host_address_set_ipv6(new_address, ipv6, port);
    address->next = new_address;

    return SUCCESS;
}

ya_result
host_address_append_dname(host_address *address, u8 *dname, u16 port)
{
    int dname_len = dnsname_len(dname);
    
    for(;;)
    {
        if(address->version == HOST_ADDRESS_DNAME)
        {
            if(memcmp(address->ip.dname.dname, dname, dname_len) == 0)
            {
                /* dup */
                return ERROR;
            }
        }

        if(address->next == NULL)
        {
            break;
        }

        address = address->next;
    }

    host_address *new_address;

    MALLOC_OR_DIE(host_address*, new_address, sizeof(host_address), HOSTADDR_TAG);
    new_address->next = NULL;
    new_address->tsig = NULL;
    host_address_set_dname(new_address, dname, port);
    address->next = new_address;

    return SUCCESS;
}

ya_result
host_address_append_host_address(host_address *address, host_address *ha)
{
    switch(ha->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            for(;;)
            {
                if(address->version == ha->version)
                {
                    if(address->ip.v4.value == ha->ip.v4.value)
                    {
                        /* dup */
                        return ERROR;
                    }
                }
                if(address->next == NULL)
                {
                    break;
                }

                address = address->next;
            }

            host_address *new_address;

            MALLOC_OR_DIE(host_address*, new_address, sizeof(host_address), HOSTADDR_TAG);
            new_address->next = NULL;
            new_address->tsig = ha->tsig;
            host_address_set_ipv4(new_address, ha->ip.v4.bytes, ha->port);
            address->next = new_address;

            break;
        }
        case HOST_ADDRESS_IPV6:
        {
            for(;;)
            {
                if(address->version == ha->version)
                {
                    if((address->ip.v6.lohi[0] == ha->ip.v6.lohi[0]) && (address->ip.v6.lohi[1] == ha->ip.v6.lohi[1]))
                    {
                        /* dup */
                        return ERROR;
                    }
                }
                if(address->next == NULL)
                {
                    break;
                }

                address = address->next;
            }

            host_address *new_address;

            MALLOC_OR_DIE(host_address*, new_address, sizeof(host_address), HOSTADDR_TAG);
            new_address->next = NULL;
            new_address->tsig = ha->tsig;
            host_address_set_ipv6(new_address, ha->ip.v6.bytes, ha->port);
            address->next = new_address;

            break;
        }
        case HOST_ADDRESS_DNAME:
        {
            int dname_len = dnsname_len(ha->ip.dname.dname);

            for(;;)
            {
                if(address->version == ha->version)
                {
                    if(memcmp(address->ip.v4.bytes, ha->ip.dname.dname, dname_len) == 0)
                    {
                        /* dup */
                        return ERROR;
                    }
                }
                if(address->next == NULL)
                {
                    break;
                }

                address = address->next;
            }

            host_address *new_address;

            MALLOC_OR_DIE(host_address*, new_address, sizeof(host_address), HOSTADDR_TAG);
            new_address->next = NULL;
            new_address->tsig = ha->tsig;
            host_address_set_ipv6(new_address, ha->ip.v6.bytes, ha->port);
            address->next = new_address;
        }
        default:
        {
            return ERROR;
        }
    }
    
    return SUCCESS;
}

ya_result
host_address_append_hostent(host_address *address, struct hostent *he, u16 port)
{
    if(he != NULL)
    {
        switch(he->h_addrtype)
        {
            case AF_INET:
            {
                char **addr = he->h_addr_list;

                while(*addr != NULL)
                {
                    host_address_append_ipv4(address, (u8*)addr, port);

                    addr++;
                }

                return SUCCESS;
            }
            case AF_INET6:
            {
                char **addr = he->h_addr_list;

                while(*addr != NULL)
                {
                    host_address_append_ipv6(address, (u8*)addr, port);

                    addr++;
                }

                return SUCCESS;
            }
            default:
            {
                break;
            }
        }
    }

    return ERROR;
}

bool
host_address_equals(host_address *a, host_address *b)
{
    if(a->version == b->version && a->port == b->port)
    {
        switch(a->version)
        {
            case HOST_ADDRESS_IPV4:
            {
                return a->ip.v4.value == b->ip.v4.value;
            }
            case HOST_ADDRESS_IPV6:
            {
                return a->ip.v6.lohi[0] == b->ip.v6.lohi[0] && a->ip.v6.lohi[1] == b->ip.v6.lohi[1];
            }
            case HOST_ADDRESS_DNAME:
            {
                return dnsname_equals(a->ip.dname.dname, b->ip.dname.dname);
            }
        }
    }

    return FALSE;
}

bool
host_address_match(host_address *a, host_address *b)
{
    if(a->version == b->version && ((a->port == b->port) || (b->port == 0) || (a->port == 0)) )
    {
        switch(a->version)
        {
            case HOST_ADDRESS_IPV4:
            {
                return a->ip.v4.value == b->ip.v4.value;
            }
            case HOST_ADDRESS_IPV6:
            {
                return a->ip.v6.lohi[0] == b->ip.v6.lohi[0] && a->ip.v6.lohi[1] == b->ip.v6.lohi[1];
            }
            case HOST_ADDRESS_DNAME:
            {
                return dnsname_equals(a->ip.dname.dname, b->ip.dname.dname);
            }
        }
    }

    return FALSE;
}

/**
 * Removes the matching host_address from the list
 * 
 * @param address
 * @param ha
 * @return 
 */

host_address *
host_address_remove_host_address(host_address **address, host_address *ha_match)
{
    host_address **ha_prev = address;
    host_address *ha = *ha_prev;
    
    while(ha != NULL)
    {
        if(host_address_equals(ha, ha_match))
        {
            *ha_prev = ha->next;
            ha->next = NULL;
            return ha;
        }

        ha_prev = &ha->next;
        ha = *ha_prev;
    }

    return NULL;
}

/** @} */

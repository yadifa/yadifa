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

/** @defgroup dnscoretools Generic Tools
 *  @ingroup dnscore
 *  @brief host address (list) functions
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "dnscore/dnscore-config.h"

#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "dnscore/host_address.h"
#include "dnscore/tsig.h"
#include "dnscore/zalloc.h"
#include "dnscore/format.h"

/*------------------------------------------------------------------------------
 * FUNCTIONS */

host_address
*host_address_alloc()
{
    host_address *new_address;
    ZALLOC_OBJECT_OR_DIE( new_address, host_address, HOSTADDR_TAG);
    new_address->version = 0;
    new_address->next = NULL;
    
#if DNSCORE_HAS_TSIG_SUPPORT
    new_address->tsig = NULL;
#endif
    return new_address;
}

/**
 * Clears the content of a host_address (mostly : deletes the dname if it's
 * what it contains.
 * 
 * @param the host address
 */

void
host_address_clear(host_address *address)
{
    if(address->version == HOST_ADDRESS_DNAME)
    {
        free(address->ip.dname.dname);
    }
    
    address->version = 0;
}


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
#if DEBUG
        memset(address->ip.dname.dname, 0xff, dnsname_len(address->ip.dname.dname));
#endif
        free(address->ip.dname.dname);
    }
    
#if DEBUG
    memset(address, 0xff, sizeof(host_address));
#endif
    ZFREE_OBJECT(address);
}

/**
 * Deletes a list of host addresses
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
host_address_copy(const host_address *address)
{
    host_address clone_head;
#if DEBUG
    memset(&clone_head, 0xff, sizeof(clone_head));
#endif
    /* no need to set TSIG */
    clone_head.next = NULL;
    clone_head.version = HOST_ADDRESS_NONE;
    
    if(address != NULL)
    {
        host_address_append_host_address(&clone_head, address); // copy made, or may fail if address is not supported
    }
    
    return clone_head.next;
}

host_address *
host_address_copy_list(const host_address *address)
{
    host_address clone_head;
#if DEBUG
    memset(&clone_head, 0xff, sizeof(clone_head));
#endif
    /* no need to set TSIG */
    clone_head.next = NULL;
    clone_head.version = HOST_ADDRESS_NONE;
    
    host_address *clone = &clone_head;
    
    while(address != NULL)
    {
        if(ISOK(host_address_append_host_address(clone, address))) // copy made, or may fail is address is not supported
        {
            clone = clone->next;
        }

        address = address->next;
    }
    
    return clone_head.next;
}

u32
host_address_count(const host_address *address)
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
host_address2allocated_sockaddr(const host_address *address, struct sockaddr **sap)
{
    switch(address->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            struct sockaddr_in *sa_in;

            MALLOC_OBJECT_OR_DIE(sa_in, struct sockaddr_in, SOCKADD4_TAG); // no ZALLOC
            ZEROMEMORY(sa_in, sizeof(struct sockaddr_in));
            memcpy(&sa_in->sin_addr.s_addr, address->ip.v4.bytes, 4);
            //sa_in->sin_addr.s_addr = htonl(sa_in->sin_addr.s_addr);
            sa_in->sin_port = address->port;
            sa_in->sin_family = AF_INET;
#if HAS_SOCKADDR_IN_SIN_LEN
            sa_in->sin_len = sizeof(struct sockaddr_in);
#endif
            *sap = (struct sockaddr*)sa_in;
            return sizeof(struct sockaddr_in);
        }
        case HOST_ADDRESS_IPV6:
        {
            struct sockaddr_in6 *sa_in6;

            MALLOC_OBJECT_OR_DIE(sa_in6, struct sockaddr_in6, SOCKADD6_TAG); // no ZALLOC
            ZEROMEMORY(sa_in6, sizeof(struct sockaddr_in6));
            memcpy(&sa_in6->sin6_addr, address->ip.v6.bytes, 16);
            sa_in6->sin6_port = address->port;
            sa_in6->sin6_family = AF_INET6;
#if HAS_SOCKADDR_IN6_SIN6_LEN
            sa_in6->sin6_len = sizeof(struct sockaddr_in6);
#endif
            /*
               sa_in6->sin6_flowinfo = 0;
               sa_in6->sin6_scope_id = 0;
               */
            *sap = (struct sockaddr*)sa_in6;
            return sizeof(struct sockaddr_in6);
        }
        default:
        {
            return IP_VERSION_NOT_SUPPORTED;   /* unsupported ip version */
        }
    }
}

ya_result
host_address2sockaddr(const host_address *address, socketaddress *sap)
{
    switch(address->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            struct sockaddr_in *sa_in = (struct sockaddr_in*)sap;

            ZEROMEMORY(sa_in, sizeof(struct sockaddr_in));
            memcpy(&sa_in->sin_addr.s_addr, address->ip.v4.bytes, 4);

            sa_in->sin_port = address->port;
            sa_in->sin_family = AF_INET;
#if HAS_SOCKADDR_IN_SIN_LEN
            sa_in->sin_len = sizeof(struct sockaddr_in);
#endif
            return sizeof(struct sockaddr_in);
        }
        case HOST_ADDRESS_IPV6:
        {
            struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6*)sap;

            ZEROMEMORY(sa_in6, sizeof(struct sockaddr_in6));
            memcpy(&sa_in6->sin6_addr, address->ip.v6.bytes, 16);
            sa_in6->sin6_port = address->port;
            sa_in6->sin6_family = AF_INET6;
#if HAS_SOCKADDR_IN6_SIN6_LEN
            sa_in6->sin6_len = sizeof(struct sockaddr_in6);
#endif
            return sizeof(struct sockaddr_in6);
        }
        default:
        {
            return IP_VERSION_NOT_SUPPORTED;   /* unsupported ip version */
        }
    }
}

void
host_address_set_default_port_value(host_address *address, u16 port)
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
host_address2addrinfo(const host_address *address, struct addrinfo **addrp)
{
    struct addrinfo *addr;
    ya_result ret;

    MALLOC_OBJECT_OR_DIE(addr, struct addrinfo, ADDRINFO_TAG); // no ZALLOC (yet)

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
            return IP_VERSION_NOT_SUPPORTED;
        }
    }

    if(ISOK(ret = host_address2allocated_sockaddr(address, &addr->ai_addr)))
    {
        addr->ai_addrlen = ret;
        *addrp = addr;
    }
    else
    {
        free(addr);
    }

    return ret;
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
            return IP_VERSION_NOT_SUPPORTED;
        }
    }
}

bool
host_address_list_contains_ip(const host_address *address_list, const socketaddress *sa)
{
    host_address address;
#if DEBUG
    memset(&address, 0xff, sizeof(address));
#endif
    /* no need to set NEXT nor TSIG */
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

#if DNSCORE_HAS_TSIG_SUPPORT

bool
host_address_list_contains_ip_tsig(const host_address *address_list, const socketaddress *sa, const tsig_item *tsig)
{
    host_address address;
#if DEBUG
    memset(&address, 0xff, sizeof(address));
#endif
    /* no need to set NEXT nor TSIG */
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
                            if(address_list->tsig == tsig)
                            {
                                return TRUE;
                            }
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
                            if(address_list->tsig == tsig)
                            {
                                return TRUE;
                            }
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

#endif

bool
host_address_list_contains_host(const host_address *address_list, const host_address *address)
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
#if DNSCORE_HAS_TSIG_SUPPORT
                        if(address_list->tsig == address->tsig)
                        {
                            return TRUE;
                        }
#else
                        return TRUE;
#endif
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
#if DNSCORE_HAS_TSIG_SUPPORT
                        if(address_list->tsig == address->tsig)
                        {
                            return TRUE;
                        }
#else
                        return TRUE;
#endif
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
host_address_set_ipv4(host_address *address, const u8 *ipv4, u16 port)
{
    memcpy(address->ip.v4.bytes, ipv4, 4);
    address->port = port;
    address->version = HOST_ADDRESS_IPV4;
}

void
host_address_set_ipv6(host_address *address, const u8 *ipv6, u16 port)
{
    memcpy(address->ip.v6.bytes, ipv6, 16);
    address->port = port;
    address->version = HOST_ADDRESS_IPV6;
}

void
host_address_set_dname(host_address *address, const u8 *dname, u16 port)
{
    address->ip.dname.dname = dnsname_dup(dname);
    address->port = port;
    address->version = HOST_ADDRESS_DNAME;
}

ya_result
host_address_append_ipv4(host_address *address, const u8 *ipv4, u16 port)
{
    for(;;)
    {
        if((address->version == HOST_ADDRESS_IPV4) && (address->port == port))
        {
            if(memcmp(address->ip.v4.bytes, ipv4, 4) == 0)
            {
                /* dup */
                return COLLECTION_DUPLICATE_ENTRY;
            }
        }
        
        if(address->next == NULL)
        {
            break;
        }

        address = address->next;
    }

    host_address *new_address;

    ZALLOC_OBJECT_OR_DIE( new_address, host_address, HOSTADDR_TAG);
    new_address->next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
    new_address->tsig = NULL;
#endif
    host_address_set_ipv4(new_address, ipv4, port);
    address->next = new_address;

    return SUCCESS;
}

ya_result
host_address_append_ipv6(host_address *address, const u8 *ipv6, u16 port)
{
    for(;;)
    {
        if((address->version == HOST_ADDRESS_IPV6) && (address->port == port))
        {
            if(memcmp(address->ip.v6.bytes, ipv6, 16) == 0)
            {
                /* dup */
                return COLLECTION_DUPLICATE_ENTRY;
            }
        }

        if(address->next == NULL)
        {
            break;
        }

        address = address->next;
    }

    host_address *new_address;

    ZALLOC_OBJECT_OR_DIE( new_address, host_address, HOSTADDR_TAG);
    new_address->next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
    new_address->tsig = NULL;
#endif
    host_address_set_ipv6(new_address, ipv6, port);
    address->next = new_address;

    return SUCCESS;
}

ya_result
host_address_append_dname(host_address *address, const u8 *dname, u16 port)
{
    int dname_len = dnsname_len(dname);
    
    for(;;)
    {
        if((address->version == HOST_ADDRESS_DNAME) && (address->port == port))
        {
            if(memcmp(address->ip.dname.dname, dname, dname_len) == 0)
            {
                /* dup */
                return COLLECTION_DUPLICATE_ENTRY;
            }
        }

        if(address->next == NULL)
        {
            break;
        }

        address = address->next;
    }

    host_address *new_address;

    ZALLOC_OBJECT_OR_DIE( new_address, host_address, HOSTADDR_TAG);
    new_address->next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
    new_address->tsig = NULL;
#endif
    host_address_set_dname(new_address, dname, port);
    address->next = new_address;

    return SUCCESS;
}

/**
 * Makes a copy of the host_address* ha.
 */

ya_result
host_address_append_host_address(host_address *address, const host_address *ha)
{
    switch(ha->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            for(;;)
            {
                if((address->version == ha->version) && (address->port == ha->port))
                {
                    if(address->ip.v4.value == ha->ip.v4.value)
                    {
                        /* dup */
                        return COLLECTION_DUPLICATE_ENTRY;
                    }
                }
                if(address->next == NULL)
                {
                    break;
                }

                address = address->next;
            }

            host_address *new_address;

            ZALLOC_OBJECT_OR_DIE( new_address, host_address, HOSTADDR_TAG);
            new_address->next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
            new_address->tsig = ha->tsig;
#endif            
            host_address_set_ipv4(new_address, ha->ip.v4.bytes, ha->port);
            address->next = new_address;

            break;
        }
        case HOST_ADDRESS_IPV6:
        {
            for(;;)
            {
                if((address->version == ha->version) && (address->port == ha->port))
                {
                    if((address->ip.v6.lohi[0] == ha->ip.v6.lohi[0]) && (address->ip.v6.lohi[1] == ha->ip.v6.lohi[1]))
                    {
                        /* dup */
                        return COLLECTION_DUPLICATE_ENTRY;
                    }
                }
                if(address->next == NULL)
                {
                    break;
                }

                address = address->next;
            }

            host_address *new_address;

            ZALLOC_OBJECT_OR_DIE( new_address, host_address, HOSTADDR_TAG);
            new_address->next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
            new_address->tsig = ha->tsig;
#endif            
            host_address_set_ipv6(new_address, ha->ip.v6.bytes, ha->port);
            address->next = new_address;

            break;
        }
        case HOST_ADDRESS_DNAME:
        {
            int dname_len = dnsname_len(ha->ip.dname.dname);

            for(;;)
            {
                if((address->version == ha->version) && (address->port == ha->port))
                {
                    if(memcmp(address->ip.dname.dname, ha->ip.dname.dname, dname_len) == 0)
                    {
                        /* dup */
                        return COLLECTION_DUPLICATE_ENTRY;
                    }
                }
                if(address->next == NULL)
                {
                    break;
                }

                address = address->next;
            }

            host_address *new_address;

            ZALLOC_OBJECT_OR_DIE( new_address, host_address, HOSTADDR_TAG);
            new_address->next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
            new_address->tsig = ha->tsig;
#endif
            host_address_set_dname(new_address, ha->ip.dname.dname, ha->port);
            address->next = new_address;
            
            break;
        }
        default:
        {
            return IP_VERSION_NOT_SUPPORTED;
        }
    }
    
    return SUCCESS;
}

ya_result
host_address_append_sockaddr(host_address *address, const socketaddress *sa)
{
    if(sa != NULL)
    {
        ya_result ret;
        host_address new_address;
        new_address.next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
        new_address.tsig = NULL;
#endif
        if(ISOK(ret = host_address_set_with_sockaddr(&new_address, sa)))
        {
            if(ISOK(ret = host_address_append_host_address(address, &new_address)))
            {
                return ret;
            }
        }

        return ret;
    }
    return UNEXPECTED_NULL_ARGUMENT_ERROR;
}

ya_result
host_address_append_sockaddr_with_port(host_address *address, const socketaddress *sa, u16 port)
{
    if(sa != NULL)
    {
        ya_result ret;
        host_address new_address;
        new_address.next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
        new_address.tsig = NULL;
#endif
        if(ISOK(ret = host_address_set_with_sockaddr(&new_address, sa)))
        {
            new_address.port = port;

            if(ISOK(ret = host_address_append_host_address(address, &new_address)))
            {
                return ret;
            }
            else
            {
                if(ret == COLLECTION_DUPLICATE_ENTRY)
                {
                    ret = SUCCESS;
                }
            }
        }

        return ret;
    }
    return UNEXPECTED_NULL_ARGUMENT_ERROR;
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

    return UNEXPECTED_NULL_ARGUMENT_ERROR;
}

bool
host_address_equals(const host_address *a, const host_address *b)
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
host_address_list_equals(const host_address *a, const host_address *b)
{
    while((a != NULL) && (b != NULL))
    {
        if(a == b)
        {
            return TRUE;
        }
        
        if(!host_address_equals(a, b))
        {
            return FALSE;
        }
        
        a = a->next;
        b = b->next;
    }
    
    return (a == b);
}

/**
 * Moves the first item at the end of the list.
 * 
 * @param firstp pointer to pointer to the first item of the list
 */

void
host_address_list_roll(host_address **firstp)
{
    host_address *first = *firstp;
    host_address *next = first->next;
    if(next != NULL)
    {
        *firstp = next;
        first->next = NULL;
        while(next->next != NULL)
        {
            next = next->next;
        }
        next->next = first;
    }
}

s32
host_address_compare(const host_address *a, const host_address *b)
{
    s32 v = (s32)a->version - (s32)b->version;
    if(v == 0)
    {
        switch(a->version)
        {
            case HOST_ADDRESS_IPV4:
            {
                s32 d = memcmp(a->ip.v4.bytes, b->ip.v4.bytes, 4);
                
                if(d != 0)
                {
                    return d;
                }
                
                break;
            }
            case HOST_ADDRESS_IPV6:
            {
                s32 d = memcmp(a->ip.v6.bytes, b->ip.v6.bytes, 16);

                if(d != 0)
                {
                    return d;
                }
                
                break;
            }
            case HOST_ADDRESS_DNAME:
            {
                s32 d = dnsname_compare(a->ip.dname.dname, b->ip.dname.dname);
                
                if(d != 0)
                {
                    return d;
                }
                break;
            }
        }
        
        return (s32)a->port - (s32)b->port;
    }
    else
    {
        return v;
    }
}


bool
host_address_match(const host_address *a, const host_address *b)
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

bool
host_address_update_host_address_list(host_address **dp, const host_address *s)
{    
    host_address* d = *dp;
    bool changed = FALSE;
    
    // if the first list is empty (NULL)
    //      and the second one is not null
    //          put a copy of the second one in the first one
    //      else
    //          do nothing and it's an error
    //  else
    //       ...

    if(d == NULL)
    {
        if(s != NULL)
        {
            d = host_address_copy_list(s);
            *dp = d;
            return TRUE; // d has changed
        }
        else
        {
            return FALSE; // d hasn't changed
        }
    }

    if(s == NULL)
    {
        return FALSE; // d hasn't changed
    }
    
    // *dp is not NULL
    
    // ...
    //
    // for each ha in d
    //     not in s -> remove from d
    //
    // now d is smaller, test what it still contains
    //
    // for each ha in s
    //     not in d -> add to d
    //
    for(host_address *ha = d; ha != NULL; ha = ha->next)
    {
        if(!host_address_list_contains_host(s, ha))
        {
            // remove from d
            host_address *removed = host_address_remove_host_address(&d, ha); // cannot return NULL in this case (only returns NULL if ha is not found in d)
            // release it
            host_address_delete(removed);
            
            // if d was ha (a list with only element, it being ha), then d is now empty

            if(d == NULL)
            {
                d = host_address_copy_list(s);
                *dp = d;
                return TRUE;
            }

            ha = d;
            changed = TRUE;
        }
    }
    
    /// @note host_address_append_host_address checks for duplicate before putting a copy
    
    for(const host_address *ha = s; ha != NULL; ha = ha->next)
    {
        if(ISOK(host_address_append_host_address(d, ha))) // copy made
        {
            changed = TRUE;
        }
    }
    
    // this is not a leak, the head of the list may have changed so this fixes it
    
    if(changed)
    {
        *dp = d;
    }
    
    return changed;
}

ya_result
host_address_to_str(const host_address *ha, char *str, int len, u8 flags)
{
    char *limit = &str[len];
    char *p = str;
    char port_separator;
    
    switch(ha->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            port_separator = ':';
            if(inet_ntop(AF_INET, ha->ip.v4.bytes, p, limit - p) == NULL)
            {
                *p = '\0';
                return ERRNO_ERROR;
            }
            p += strlen(p);
            break;
        }
        case HOST_ADDRESS_IPV6:
        {
            port_separator = '#';
            if(inet_ntop(AF_INET6, ha->ip.v6.bytes, p, limit - p) == NULL)
            {
                *p = '\0';
                return ERRNO_ERROR;
            }
            p += strlen(p);

            break;
        }
        case HOST_ADDRESS_DNAME:
        {
            s32 n;
            port_separator = ':';
            *p = '\0';
            if(FAIL(n = snformat(p, len, "%{dnsname}", ha->ip.dname.dname)))
            {
                // it failed, and n is the error code
                return n;
            }
            p += n;
            break;
        }
        default:
        {
            port_separator = ':';
            *p = '\0';
            break;
        }
    }

    if((ha->port != 0) && (flags & HOST_ADDRESS_TO_STR_SHOW_PORT_ZERO))
    {
        if(flags & (HOST_ADDRESS_TO_STR_FULLPORT|HOST_ADDRESS_TO_STR_PORT))
        {
            s32 n;
            
            if(flags & HOST_ADDRESS_TO_STR_FULLPORT)
            {                    
                n = snformat(p, limit - p, " port %i", ntohs(ha->port));
            }
            else
            {
                n = snformat(p, limit - p, "%c%i", port_separator, ntohs(ha->port));
            }
            
            if(FAIL(n))
            {
                // it failed, and n is the error code
                return n;
            }

            p += n;
        }
    }
    
#if DNSCORE_HAS_TSIG_SUPPORT
    if((ha->tsig != NULL) && (ha->tsig->name != NULL))
    {
        s32 n = 0;
        if(flags & HOST_ADDRESS_TO_STR_TSIG)
        {
            n = snformat(p, limit - p, "*%{dnsname}", ha->tsig->name);
        }
        else if(flags & HOST_ADDRESS_TO_STR_FULLTSIG)
        {
            n = snformat(p, limit - p, "key %{dnsname}", ha->tsig->name);
        }
        
        if(FAIL(n))
        {
            // it failed, and n is the error code
            return n;
        }

        p += n;
    }
#endif
    
    return p - str;
}

bool
host_address_is_any(const host_address *ha)
{
    //bool is_any;
    if(ha->version == HOST_ADDRESS_IPV4)
    {
        return ha->ip.v4.value == INADDR_ANY;
    }
    else if(ha->version == HOST_ADDRESS_IPV6)
    {
        return (ha->ip.v6.lohi[0]|ha->ip.v6.lohi[1]) == 0;
    }
    else
    {
        // no supported, so no
        return FALSE;
    }
}

/** @} */

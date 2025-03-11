/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup dnscoretools Generic Tools
 * @ingroup dnscore
 * @brief host address (list) functions
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"

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
#include "dnscore/parsing.h"

/*------------------------------------------------------------------------------
 * FUNCTIONS */

host_address_t *host_address_new_instance()
{
    host_address_t *new_address;
    ZALLOC_OBJECT_OR_DIE(new_address, host_address_t, HOSTADDR_TAG);
    new_address->next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
    new_address->tsig = NULL;
#endif
    new_address->version = HOST_ADDRESS_NONE;
    new_address->tls = HOST_ADDRESS_TLS_NOT_SET;

    return new_address;
}

/**
 * Allocates a new instance of host_address with a 4 bytes array and a network-endian port.
 *
 * @param ipv4 4 bytes containing a network-endian IPv4
 * @param port network-endian port
 */

host_address_t *host_address_new_instance_ipv4(const uint8_t *ipv4, uint16_t port)
{
    host_address_t *ha = host_address_new_instance();
    host_address_set_ipv4(ha, ipv4, port);
    return ha;
}

/**
 * Allocates a new instance of host_address with a 16 bytes array and a network-endian port.
 *
 * @param ipv6 16 bytes containing a network-endian IPv6
 * @param port network-endian port
 */

host_address_t *host_address_new_instance_ipv6(const uint8_t *ipv6, uint16_t port)
{
    host_address_t *ha = host_address_new_instance();
    host_address_set_ipv6(ha, ipv6, port);
    return ha;
}

/**
 * Allocates a new instance of host_address with an fqdn and a network-endian port.
 *
 * @param dname an fqdn
 * @param port network-endian port
 */

host_address_t *host_address_new_instance_dname(const uint8_t *dname, uint16_t port)
{
    host_address_t *ha = host_address_new_instance();
    host_address_set_dname(ha, dname, port);
    return ha;
}

host_address_t *host_address_new_instance_socketaddress(const socketaddress_t *sa)
{
    host_address_t *ha = host_address_new_instance();
    host_address_set_with_socketaddress(ha, sa);
    return ha;
}

/**
 * Allocates a new instance of host_address with a 4 bytes array, a network-endian port and a TSIG key.
 *
 * @param ipv4 4 bytes containing a network-endian IPv4
 * @param port network-endian port
 * @param tsig the tsig key
 */

host_address_t *host_address_new_instance_ipv4_tsig(const uint8_t *ipv4, uint16_t port, const struct tsig_key_s *tsig)
{
    host_address_t *ha = host_address_new_instance();
#if DNSCORE_HAS_TSIG_SUPPORT
    ha->tsig = tsig;
#endif
    host_address_set_ipv4(ha, ipv4, port);
    return ha;
}

/**
 * Allocates a new instance of host_address with a 16 bytes array, a network-endian port and a TSIG key.
 *
 * @param ipv6 16 bytes containing a network-endian IPv6
 * @param port network-endian port
 * @param tsig the tsig key
 */

host_address_t *host_address_new_instance_ipv6_tsig(const uint8_t *ipv6, uint16_t port, const struct tsig_key_s *tsig)
{
    host_address_t *ha = host_address_new_instance();
#if DNSCORE_HAS_TSIG_SUPPORT
    ha->tsig = tsig;
#endif
    host_address_set_ipv6(ha, ipv6, port);
    return ha;
}

/**
 * Allocates a new instance of host_address with an fqdn, a network-endian port and a TSIG key.
 *
 * @param dname an fqdn
 * @param port network-endian port
 * @param tsig the tsig key
 */

host_address_t *host_address_new_instance_dname_tsig(const uint8_t *dname, uint16_t port, const struct tsig_key_s *tsig)
{
    host_address_t *ha = host_address_new_instance();
#if DNSCORE_HAS_TSIG_SUPPORT
    ha->tsig = tsig;
#endif
    host_address_set_dname(ha, dname, port);
    return ha;
}

/**
 * Allocates a new instance of host_address from the text-representation of an IP address.
 *
 * @param ip_to_parse the text representation of an IP address
 */

host_address_t *host_address_new_instance_parse(const char *ip_to_parse)
{
    host_address_t *ha = host_address_new_instance();
    ha->port = 0;
    ya_result ret;
    ret = parse_ip_address(ip_to_parse, strlen(ip_to_parse), &ha->ip.v6.bytes[0], sizeof(ha->ip.v6.bytes));
    if(ISOK(ret))
    {
        switch(ret)
        {
            case 4:
            {
                ha->version = HOST_ADDRESS_IPV4;
                return ha;
            }
            case 16:
            {
                ha->version = HOST_ADDRESS_IPV6;
                return ha;
            }
            default:
            {
                break;
            }
        }
    }
    else
    {
        uint8_t dname[FQDN_LENGTH_MAX];
        if(ISOK(ret = dnsname_init_with_cstr(dname, ip_to_parse)))
        {
            host_address_set_dname(ha, dname, 0);
            return ha;
        }
    }

    host_address_delete(ha);
    return NULL;
}

/**
 * Allocates a new instance of host_address from the text-representation of an IP address, as well as a port
 *
 * @param ip_to_parse the text representation of an IP address
 * @param port the native representation of a port (e.g. not Network Endian specifically)
 */

host_address_t *host_address_new_instance_parse_port(const char *ip_to_parse, int port)
{
    host_address_t *ha = host_address_new_instance_parse(ip_to_parse);
    if(ha != NULL)
    {
        ha->port = htons(port);
    }
    return ha;
}

/**
 * Clears the content of a host_address (mostly : deletes the dname if it's
 * what it contains.
 *
 * @param the host address
 */

void host_address_finalise(host_address_t *address)
{
    if(address->version == HOST_ADDRESS_DNAME)
    {
#if DEBUG
        memset(address->ip.dname.dname, 0xff, dnsname_len(address->ip.dname.dname));
#endif
        free(address->ip.dname.dname);
        address->ip.dname.dname = NULL;
    }

    address->version = HOST_ADDRESS_NONE;
    address->tls = HOST_ADDRESS_TLS_NOT_SET;
}

/**
 * Deletes a host addresse
 *
 * @param the host address
 */

void host_address_delete(host_address_t *address)
{
    if(address != NULL)
    {
        if(address->version == HOST_ADDRESS_DNAME)
        {
#if DEBUG
            memset(address->ip.dname.dname, 0xff, dnsname_len(address->ip.dname.dname));
#endif
            free(address->ip.dname.dname);
        }

#if DEBUG
        memset(address, 0xff, sizeof(host_address_t));
#endif
        ZFREE_OBJECT(address);
    }
}

/**
 * Deletes a list of host addresses
 *
 * @param the first host address in the list
 */

void host_address_delete_list(host_address_t *address)
{
    while(address != NULL)
    {
        host_address_t *next = address->next;

        host_address_delete(address);

        address = next;
    }
}

host_address_t *host_address_copy(const host_address_t *address)
{
    host_address_t clone_head;
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

host_address_t *host_address_copy_list(const host_address_t *address)
{
    host_address_t clone_head;
#if DEBUG
    memset(&clone_head, 0xff, sizeof(clone_head));
#endif
    /* no need to set TSIG */
    clone_head.next = NULL;
    clone_head.version = HOST_ADDRESS_NONE;

    host_address_t *clone = &clone_head;

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

uint32_t host_address_count(const host_address_t *address)
{
    uint32_t n = 0;

    while(address != NULL)
    {
        n++;
        address = address->next;
    }

    return n;
}

ya_result host_address2allocated_sockaddr(const host_address_t *address, struct sockaddr **sap)
{
    switch(address->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            socketaddress_t *sa;

            MALLOC_OBJECT_OR_DIE(sa, socketaddress_t, SOCKADD4_TAG); // no ZALLOC
            memcpy(&sa->sa4.sin_addr.s_addr, address->ip.v4.bytes, 4);
            sa->sa4.sin_port = address->port;
            sa->sa4.sin_family = AF_INET;
#if HAS_SOCKADDR_IN_SIN_LEN
            sa->sa4.sin_len = sizeof(struct sockaddr_in);
#endif
            *sap = &sa->sa;
            return sizeof(struct sockaddr_in);
        }
        case HOST_ADDRESS_IPV6:
        {
            socketaddress_t *sa;

            MALLOC_OBJECT_OR_DIE(sa, socketaddress_t, SOCKADD6_TAG); // no ZALLOC
            sa->sa6.sin6_family = AF_INET6;
            sa->sa6.sin6_port = address->port;
            sa->sa6.sin6_flowinfo = 0;
            memcpy(&sa->sa6.sin6_addr, address->ip.v6.bytes, 16);
            sa->sa6.sin6_scope_id = 0;
#if HAS_SOCKADDR_IN6_SIN6_LEN
            sa->sa6.sin6_len = sizeof(struct sockaddr_in6);
#endif
            *sap = &sa->sa;
            return sizeof(struct sockaddr_in6);
        }
        default:
        {
            return IP_VERSION_NOT_SUPPORTED; /* unsupported ip version */
        }
    }
}

ya_result host_address2sockaddr(const host_address_t *address, socketaddress_t *sap)
{
    switch(address->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            struct sockaddr_in *sa_in = &sap->sa4;

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
            struct sockaddr_in6 *sa_in6 = &sap->sa6;

            ZEROMEMORY(sa_in6, sizeof(struct sockaddr_in6));
            sa_in6->sin6_family = AF_INET6;
            sa_in6->sin6_port = address->port;
            sa_in6->sin6_flowinfo = 0;
            memcpy(&sa_in6->sin6_addr, address->ip.v6.bytes, 16);
            sa_in6->sin6_scope_id = 0;

#if HAS_SOCKADDR_IN6_SIN6_LEN
            sa_in6->sin6_len = sizeof(struct sockaddr_in6);
#endif
            return sizeof(struct sockaddr_in6);
        }
        default:
        {
            return IP_VERSION_NOT_SUPPORTED; /* unsupported ip version */
        }
    }
}

void host_address_set_default_port_value(host_address_t *address, uint16_t port)
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

void host_address_set_port_value(host_address_t *address, uint16_t port)
{
    /* set the default port on any unset port */

    while(address != NULL)
    {
        address->port = port;
        address = address->next;
    }
}

/**
 * Converts an host_address to a addrinfo
 * Must can be freed by "free"
 */

ya_result host_address2addrinfo(const host_address_t *address, struct addrinfo **addrp)
{
    struct addrinfo *addr;
    ya_result        ret;

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

ya_result host_address_set_with_socketaddress(host_address_t *address, const socketaddress_t *sa)
{
    address->next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
    address->tsig = NULL;
#endif

    switch(sa->sa.sa_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in *sain = &sa->sa4;
            address->ip.v4.value = sain->sin_addr.s_addr;
            address->port = sain->sin_port;
            address->version = HOST_ADDRESS_IPV4;
            address->tls = HOST_ADDRESS_TLS_NOT_SET;
            return SUCCESS;
        }
        case AF_INET6:
        {
            const struct sockaddr_in6 *sain6 = &sa->sa6;
            memcpy(address->ip.v6.bytes, &sain6->sin6_addr, 16);
            address->port = sain6->sin6_port;
            address->version = HOST_ADDRESS_IPV6;
            address->tls = HOST_ADDRESS_TLS_NOT_SET;
            return SUCCESS;
        }
        default:
        {
            return IP_VERSION_NOT_SUPPORTED;
        }
    }
}

bool host_address_list_contains_ip(const host_address_t *address_list, const socketaddress_t *sa)
{
    host_address_t address;
#if DEBUG
    memset(&address, 0xff, sizeof(address));
#endif
    /* no need to set NEXT nor TSIG */
    if(ISOK(host_address_set_with_socketaddress(&address, sa)))
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
                            return true;
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
                            return true;
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

    return false;
}

#if DNSCORE_HAS_TSIG_SUPPORT

bool host_address_list_contains_ip_tsig(const host_address_t *address_list, const socketaddress_t *sa, const tsig_key_t *tsig)
{
    host_address_t address;
#if DEBUG
    memset(&address, 0xff, sizeof(address));
#endif
    /* no need to set NEXT nor TSIG */
    if(ISOK(host_address_set_with_socketaddress(&address, sa)))
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
                                return true;
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
                                return true;
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

    return false;
}

#endif

bool host_address_list_contains_host(const host_address_t *address_list, const host_address_t *address)
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
                            return true;
                        }
#else
                        return true;
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
                            return true;
                        }
#else
                        return true;
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

    return false;
}

void host_address_set_ipv4(host_address_t *address, const uint8_t *ipv4, uint16_t port)
{
    memcpy(address->ip.v4.bytes, ipv4, 4);
    address->port = port;
    address->version = HOST_ADDRESS_IPV4;
}

void host_address_set_ipv6(host_address_t *address, const uint8_t *ipv6, uint16_t port)
{
    memcpy(address->ip.v6.bytes, ipv6, 16);
    address->port = port;
    address->version = HOST_ADDRESS_IPV6;
}

void host_address_set_dname(host_address_t *address, const uint8_t *dname, uint16_t port)
{
    address->ip.dname.dname = dnsname_dup(dname);
    address->port = port;
    address->version = HOST_ADDRESS_DNAME;
}

ya_result host_address_append_ipv4(host_address_t *address, const uint8_t *ipv4, uint16_t port)
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

    host_address_t *new_address = host_address_new_instance_ipv4(ipv4, port);
    address->next = new_address;

    return SUCCESS;
}

ya_result host_address_append_ipv6(host_address_t *address, const uint8_t *ipv6, uint16_t port)
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

    host_address_t *new_address = host_address_new_instance_ipv6(ipv6, port);
    address->next = new_address;

    return SUCCESS;
}

ya_result host_address_append_dname(host_address_t *address, const uint8_t *dname, uint16_t port)
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

    host_address_t *new_address = host_address_new_instance_dname(dname, port);
    address->next = new_address;

    return SUCCESS;
}

/**
 * Makes a copy of the host_address* ha.
 */

ya_result host_address_append_host_address(host_address_t *address, const host_address_t *ha)
{
    switch(ha->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            for(;;)
            {
                if((address->version == ha->version) && (address->port == ha->port) && (address->tls == ha->tls))
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

            host_address_t *new_address = host_address_new_instance_ipv4_tsig(ha->ip.v4.bytes, ha->port, ha->tsig);
            new_address->tls = ha->tls;
            address->next = new_address;

            break;
        }
        case HOST_ADDRESS_IPV6:
        {
            for(;;)
            {
                if((address->version == ha->version) && (address->port == ha->port) && (address->tls == ha->tls))
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

            host_address_t *new_address = host_address_new_instance_ipv6_tsig(ha->ip.v6.bytes, ha->port, ha->tsig);
            new_address->tls = ha->tls;
            address->next = new_address;

            break;
        }
        case HOST_ADDRESS_DNAME:
        {
            int dname_len = dnsname_len(ha->ip.dname.dname);

            for(;;)
            {
                if((address->version == ha->version) && (address->port == ha->port) && (address->tls == ha->tls))
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

            host_address_t *new_address = host_address_new_instance_dname_tsig(ha->ip.dname.dname, ha->port, ha->tsig);
            new_address->tls = ha->tls;
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

ya_result host_address_append_sockaddr(host_address_t *address, const socketaddress_t *sa)
{
    if(sa != NULL)
    {
        ya_result      ret;
        host_address_t new_address;
        new_address.next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
        new_address.tsig = NULL;
#endif
        if(ISOK(ret = host_address_set_with_socketaddress(&new_address, sa)))
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

ya_result host_address_append_sockaddr_with_port(host_address_t *address, const socketaddress_t *sa, uint16_t port)
{
    if(sa != NULL)
    {
        ya_result      ret;
        host_address_t new_address;
        new_address.next = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
        new_address.tsig = NULL;
#endif
        if(ISOK(ret = host_address_set_with_socketaddress(&new_address, sa)))
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

#if DEPRECATED
ya_result host_address_append_hostent(host_address_t *address, struct hostent *he, uint16_t port)
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
                    host_address_append_ipv4(address, (uint8_t *)addr, port);

                    addr++;
                }

                return SUCCESS;
            }
            case AF_INET6:
            {
                char **addr = he->h_addr_list;

                while(*addr != NULL)
                {
                    host_address_append_ipv6(address, (uint8_t *)addr, port);

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
#endif

/**
 * Compares the host address
 * The port is not part of the comparison.
 *
 * @param a host_address_t
 * @param b host_address_t
 * @return true if a & b are the same type and have the same ip/domain (port being ignored)
 */

bool host_address_equals(const host_address_t *a, const host_address_t *b)
{
    if((a->version == b->version) && (a->port == b->port) && (a->tls == b->tls))
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
            default:
            {
                return true; // both are essentially garbage
            }
        }
    }

    return false;
}

bool host_address_list_equals(const host_address_t *a, const host_address_t *b)
{
    while((a != NULL) && (b != NULL))
    {
        if(a == b)
        {
            return true;
        }

        if(!host_address_equals(a, b))
        {
            return false;
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

void host_address_list_roll(host_address_t **firstp)
{
    host_address_t *first = *firstp;
    host_address_t *next = first->next;
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

/**
 * Compares the host address
 *
 * Compares, in order, version/ip/port/tls
 *
 * @param a host_address_t
 * @param b host_address_t
 * @return <0 if a < b, 0 if a == b, >0 if a > b
 */

int32_t host_address_compare(const host_address_t *a, const host_address_t *b)
{
    int32_t v = (int32_t)a->version - (int32_t)b->version;

    if(v == 0)
    {
        switch(a->version)
        {
            case HOST_ADDRESS_IPV4:
            {
                int32_t d = memcmp(a->ip.v4.bytes, b->ip.v4.bytes, 4);

                if(d != 0)
                {
                    return d;
                }

                break;
            }
            case HOST_ADDRESS_IPV6:
            {
                int32_t d = memcmp(a->ip.v6.bytes, b->ip.v6.bytes, 16);

                if(d != 0)
                {
                    return d;
                }

                break;
            }
            case HOST_ADDRESS_DNAME:
            {
                int32_t d = dnsname_compare(a->ip.dname.dname, b->ip.dname.dname);

                if(d != 0)
                {
                    return d;
                }
                break;
            }
        }

        v = (int32_t)a->port - (int32_t)b->port;

        if(v == 0)
        {
            v = (int32_t)a->tls - (int32_t)b->tls;
        }

        return v;
    }
    else
    {
        return v;
    }
}

bool host_address_match(const host_address_t *a, const host_address_t *b)
{
    if(a->version == b->version && ((a->port == b->port) || (b->port == 0) || (a->port == 0)))
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

    return false;
}

/**
 * Removes the matching host_address from the list
 *
 * @param address
 * @param ha
 * @return
 */

host_address_t *host_address_remove_host_address(host_address_t **address, host_address_t *ha_match)
{
    host_address_t **ha_prev = address;
    host_address_t  *ha = *ha_prev;

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

/**
 * Replaces host_address_t from the first list with the ones from the second list.
 * Avoids reallocations: items already present are kept.
 *
 * @param dp the first list
 * @param s the second list
 *
 * @return true iff the first list has been changed.
 */

bool host_address_update_host_address_list(host_address_t **dp, const host_address_t *s)
{
    host_address_t *d = *dp;
    bool            changed = false;

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
            return true; // d has changed
        }
        else
        {
            return false; // d hasn't changed
        }
    }

    if(s == NULL)
    {
        return false; // d hasn't changed
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
    for(host_address_t *ha = d; ha != NULL; ha = ha->next)
    {
        if(!host_address_list_contains_host(s, ha))
        {
            // remove from d
            host_address_t *removed = host_address_remove_host_address(&d, ha); // cannot return NULL in this case (only returns NULL if ha is not found in d)
            // release it
            host_address_delete(removed);

            // if d was ha (a list with only element, it being ha), then d is now empty

            if(d == NULL)
            {
                d = host_address_copy_list(s);
                *dp = d;
                return true;
            }

            ha = d;
            changed = true;
        }
    }

    /// @note host_address_append_host_address checks for duplicate before putting a copy

    for(const host_address_t *ha = s; ha != NULL; ha = ha->next)
    {
        if(ISOK(host_address_append_host_address(d, ha))) // copy made
        {
            changed = true;
        }
    }

    // this is not a leak, the head of the list may have changed so this fixes it

    if(changed)
    {
        *dp = d;
    }

    return changed;
}

ya_result host_address_to_str(const host_address_t *ha, char *str, int len, uint8_t flags)
{
    char *limit = &str[len];
    char *p = str;
    char  port_separator;

    if(ha != NULL)
    {
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
                int32_t n;
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

        if((ha->port != 0) || (flags & HOST_ADDRESS_TO_STR_SHOW_PORT_ZERO))
        {
            if(flags & (HOST_ADDRESS_TO_STR_FULLPORT | HOST_ADDRESS_TO_STR_PORT))
            {
                int32_t n;

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
            int32_t n = 0;
            if(flags & HOST_ADDRESS_TO_STR_TSIG)
            {
                n = snformat(p, limit - p, "*%{dnsname}", ha->tsig->name);
            }
            else if(flags & HOST_ADDRESS_TO_STR_FULLTSIG)
            {
                n = snformat(p, limit - p, " key %{dnsname}", ha->tsig->name);
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
    else
    {
        memcpy(str, "NULL", MIN(len, 5));
        return 4;
    }
}

bool host_address_is_any(const host_address_t *ha)
{
    // bool is_any;
    if(ha->version == HOST_ADDRESS_IPV4)
    {
        return ha->ip.v4.value == INADDR_ANY;
    }
    else if(ha->version == HOST_ADDRESS_IPV6)
    {
        return (ha->ip.v6.lohi[0] | ha->ip.v6.lohi[1]) == 0;
    }
    else
    {
        // no supported, so no
        return false;
    }
}

/** @} */

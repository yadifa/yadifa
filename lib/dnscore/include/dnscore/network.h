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

/** @defgroup network Network functions
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef NETWORK_H
#define NETWORK_H

#include <sys/types.h>	/* Required for BSD */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <dnscore/sys_types.h>

#define SOCKADD4_TAG 0x344444414b434f53
#define SOCKADD6_TAG 0x364444414b434f53

/*
 * In order to avoid casting, this is the type that should be used to store sockaddr
 */

typedef union socketaddress socketaddress;

union socketaddress
{
    /// @note 20200629 edf -- In order to avoid a potential issue with the sockaddr structure in FreeBSD and possibly other OSes, I've removed the ss_* fields.
    //                        Every access must be done through "sa".

    struct sockaddr         sa;
    struct sockaddr_in      sa4;
    struct sockaddr_in6     sa6;
    struct sockaddr_storage ss;
};

// minimal storage for IPv4 & IPv6

union socketaddress_46
{
    struct sockaddr         sa;
    struct sockaddr_in      sa4;
    struct sockaddr_in6     sa6;
};

static inline bool sockaddr_equals(const struct sockaddr *a, const struct sockaddr *b)
{
    if(a->sa_family == b->sa_family)
    {
        switch (a->sa_family)
        {
            case AF_INET:
            {
                const struct sockaddr_in *sa4 = (const struct sockaddr_in *)a;
                const struct sockaddr_in *sb4 = (const struct sockaddr_in *)b;

                return memcmp(&sa4->sin_addr.s_addr, &sb4->sin_addr.s_addr, 4) == 0;
            }
            case  AF_INET6:
            {

                const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)a;
                const struct sockaddr_in6 *sb6 = (const struct sockaddr_in6 *)b;

                return memcmp(&sa6->sin6_addr, &sb6->sin6_addr, 16) == 0;
            }
        }
    }

    return FALSE;
}

int sockaddr_compare_addr_port(const struct sockaddr *a, const struct sockaddr *b);

int socketaddress_compare_ip(const void *a, const void *b);

static inline u16 sockaddr_port_ne(socketaddress *sa)
{
    switch(sa->sa.sa_family)
    {
        case AF_INET:
        {
            return sa->sa4.sin_port;
        }
        case AF_INET6:
        {
            return sa->sa6.sin6_port;
        }
        default:
        {
            return 0;
        }
    }
}

static inline u16 sockaddr_port(socketaddress *sa)
{
    return ntohs(sockaddr_port_ne(sa));
}

static inline s32 sockaddr_inet_port(const struct sockaddr* sa)
{
    switch(sa->sa_family)
    {
        case AF_INET:
        {
            struct sockaddr_in *ipv4 = (struct sockaddr_in*)sa;
            return (u32)ipv4->sin_port;
        }
        case AF_INET6:
        {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)sa;
            return (u32)ipv6->sin6_port;
        }
        default:
        {
            return ERROR;
        }
    }
}

/**
 * Tool function to tell if a (listening) address is ANY
 */

bool addr_info_is_any(struct addrinfo* addr);

/**
 * Enumerates all network interfaces.
 */

typedef ya_result (network_interfaces_forall_callback)(const char* itf_name, const socketaddress* ss, void* data);

ya_result network_interfaces_forall(network_interfaces_forall_callback *cb, void *data);

#endif /* HOST_ADDRESS_H */

/** @} */


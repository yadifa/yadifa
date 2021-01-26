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

/** @defgroup network
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */


#pragma once

#if __APPLE__
#if !defined(__APPLE_USE_RFC_3542)
#error "__APPLE_USE_RFC_3542 must be defined globally for this to work on OSX"
#endif
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

#include <dnscore/network.h>

#define SERVER_CONTEXT_API_BUFFER_SIZE 256

/*
 * from: http://www.mombu.com/programming/c/t-how-to-get-udp-destination-address-on-incoming-packets-7784569.html
 */

#if defined IP_RECVDSTADDR
# define DSTADDR_SOCKOPT IP_RECVDSTADDR
# define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_addr)))
# define dstaddr(x) (CMSG_DATA(x))
#elif defined IP_PKTINFO
# define DSTADDR_SOCKOPT IP_PKTINFO
# define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_pktinfo)))
# define dstaddr(x) (&(((struct in_pktinfo *)(CMSG_DATA(x)))->ipi_addr))
#else
# error "can't determine socket option"
#endif

#if defined IPV6_PKTINFO
# define DSTADDR6_SOCKOPT IPV6_PKTINFO
# define DSTADDR6_DATASIZE (CMSG_SPACE(sizeof(struct in6_pktinfo)))
# define dstaddr6(x) (&(((struct in6_pktinfo *)(CMSG_DATA(x)))->ipi_addr))
#else
#error "can't determine socket v6 option"
#endif

struct socket_server_opensocket_noserver_s
{
    int sockfd;
    ya_result error;
    int family;
    struct addrinfo addr;
    socketaddress ss;
};

struct socket_server_opensocket_s
{
    u8 *p;
    u8 buffer_out[SERVER_CONTEXT_API_BUFFER_SIZE];
};

typedef struct socket_server_opensocket_s socket_server_opensocket_s;

/**
 * 
 * 
 * @param ctx the struct to initialise
 * @param addr the address
 * @param sock_type e.g.: SOCK_STREAM, SOCK_DGRAM, ...
 */

ya_result socket_server_opensocket_init(socket_server_opensocket_s *ctx, struct addrinfo *addr, int sock_type);
void socket_server_opensocket_setopt(socket_server_opensocket_s *ctx, int level, int optname, const void* opt, socklen_t optlen);
void socket_server_opensocket_setopt_ignore_result(socket_server_opensocket_s *ctx, int level, int optname, const void* opt, socklen_t optlen);
void socket_server_opensocket_setopt_ignore_error(socket_server_opensocket_s *ctx, int level, int optname, const void* opt, socklen_t optlen);

/**
 * Opens the socket and returns its file descriptor or an error code.
 * 
 * @param ctx
 * 
 * @return the file descriptor or an error code
 */

int socket_server_opensocket_open(socket_server_opensocket_s *ctx);

ya_result socket_server_init(int argc, char **argv);
ya_result socket_server_finalize();

/**
 * Returns the user id of the socket server (the user ID it had when it was started)
 */

uid_t socket_server_uid();

/** @} */

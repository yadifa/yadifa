/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2017, EURid. All rights reserved.
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
/** @defgroup server Server
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#pragma once

#include "config.h"

#include <dnscore/message.h>
#include "database.h"

#include "confs.h"

#if HAS_MESSAGES_SUPPORT
#define UDP_USE_MESSAGES 1
#else
#define UDP_USE_MESSAGES 0
#endif

#ifdef	__cplusplus
extern "C"
{
#endif
    
#if UDP_USE_MESSAGES

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

/*
union cmsghdr_dstaddr {
struct cmsghdr cmsg;
u_char data[DSTADDR_DATASIZE];
};
*/
#endif
    
typedef struct server_context_s server_context_s;

/**
 * This structure describes every single piece of information required
 * for setting up the server workers.
 */

struct server_context_s
{
    host_address **listen;
    int listen_count;
    //
    struct addrinfo **udp_interface;
    int udp_interface_count;
    
    struct addrinfo **tcp_interface;
    int tcp_interface_count;
    //
    int *udp_socket; // sorted by interface
    int udp_socket_count;
    //
    int *tcp_socket;
    int tcp_socket_count;
    
    // the fields below have to be set by the network model setup in server-mt.c or server-rw.c
    
    int udp_unit_per_interface; // = udp_socket_count / listen_count
    int tcp_unit_per_interface; // = tcp_socket_count / listen_count
    int thread_per_udp_worker_count;// = mt: 1, rw: 2
    int thread_per_tcp_worker_count;// = mt: 1, rw: 1

    unsigned int reuse:1,ready:1;
};

#define SERVER_CONTEXT_INITIALISER {NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0,  0, 0, 1, 1, 0, 0}

#ifndef SERVER_CONTEXT_C
extern server_context_s server_context;
#endif

typedef struct server_vtbl_s server_vtbl_s;
    
/** \brief  Initialize sockets and copy the config parameters into server_context_t
 *
 *  @param[in] config
 *  @param[out] server_context
 *
 *  @retval OK
 *  @return otherwise log_quit will stop the program
 */

int server_context_start(host_address *interfaces);


/**
 * Appends the name of the socket s to the buffer.
 * The buffer has to be big enough, no size test is performed.
 * 
 * @param buffer
 * @param s
 * 
 * @return the length of the name
 */
    
u32 server_context_append_socket_name(char *buffer, u16 s);

/** \brief Closes all sockets and remove pid file
 *
 *  @param[in] config
 *  @param[in] server_context
 *
 *  @retval OK
 *  @return otherwise log_quit will stop the program
 */

void server_context_stop();

#ifdef	__cplusplus
}
#endif


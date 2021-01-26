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

/** @defgroup server Server
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

#pragma once

#include "server-config.h"
#include <dnscore/message.h>
#include "database.h"



#include "confs.h"

#ifdef	__cplusplus
extern "C"
{
#endif

    
typedef struct server_context_s server_context_s;

/**
 * This structure describes every single piece of information required
 * for setting up the server workers.
 */

struct server_context_s
{
    host_address **listen;
    u32 listen_count;
    //
    struct addrinfo **udp_interface;
    u32 udp_interface_count;
    
    struct addrinfo **tcp_interface;
    u32 tcp_interface_count;
    //
    int *udp_socket; // sorted by interface
    u32 udp_socket_count;
    //
    int *tcp_socket;
    u32 tcp_socket_count;
    
    // the fields below have to be set by the network model setup in server-rw.c

    u32 udp_unit_per_interface; // = udp_socket_count / listen_count
    u32 tcp_unit_per_interface; // = tcp_socket_count / listen_count
    u32 thread_per_udp_worker_count;// = mt: 1, rw: 2
    u32 thread_per_tcp_worker_count;// = mt: 1, rw: 1

    u32 worker_backlog_queue_size;  // this value indicates the backlog entries for the workers for the models that support it
                                    // if the server is overloaded, that's how many messages will be kept for later processing until
                                    // new queries are dropped. (Also messages are to be pushed out of the queue after a small amount
                                    // of time e.g.: 1 to 3 seconds)
                                    // on server-mt, the memory usage in bytes is this value * 64 (2^20 => 64MB)
                                    // at this time, by default, 2^19 but should be changed to something much lower
                                    
    unsigned int reuse:1,ready:1;
};

#define SERVER_CONTEXT_INITIALISER {NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0,  0, 0, 1, 1, 65536, 0, 0}

#ifndef SERVER_CONTEXT_C
extern server_context_s g_server_context;
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

int server_context_create();

bool server_context_matches_config();

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


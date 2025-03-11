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
 * @defgroup server Server
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#include "server_config.h"
#include <dnscore/dns_message.h>
#include "database.h"

#include "confs.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct server_context_s server_context_s;

/**
 * This structure describes every single piece of information required
 * for setting up the server workers.
 *
 * It exists for two reasons.
 * _ it centralises information about the network interfaces
 * _ it allows to open privileged sockets before the user/group is changed
 *
 * The second feature is only required because the socket-server feature (allowing reopening of privileged sockets
 * anytime) is not available on every OS.
 *
 * In practice, the server context will open and bind all relevant sockets just before yadifad switches to a
 * non-privileged user.
 */

struct server_context_s
{
    host_address_t **listen;
    uint32_t         listen_count;
    // detected by server_context
    struct addrinfo **udp_interface;
    uint32_t          udp_interface_count;
    // detected by server_context
    struct addrinfo **tcp_interface;
    uint32_t          tcp_interface_count;
};

#define SERVER_CONTEXT_INITIALISER {NULL, 0, NULL, 0, NULL, 0} //, NULL, 0, NULL, 0,  0, 0, 1, 1, 65536, 0, 0}

struct network_server_vtbl_s;

/**
 * Multiple server-type support (multiple DNS-UDP, DNS-TCP, DNS-TLS, ... REST? ...) means a having a different class
 * per type is desirable.
 *
 * UDP will get his (multiple ones actually)
 * TCP will get his
 * TLS will get his
 * ...
 */

struct network_server_s
{
    void                               *data;
    const struct network_server_vtbl_s *vtbl;
};

typedef struct network_server_s network_server_t;

typedef ya_result (*server_init_instance_callback)(network_server_t *);

/*
 * A reconfiguration typically does a join/stop/deconfigure/configure/start
 */

struct network_server_vtbl_s
{
    ya_result (*configure)(network_server_t *server);   // the network & everything
    ya_result (*start)(network_server_t *server);       // starts the threads
    ya_result (*join)(network_server_t *server);        // wait for the threads to stop
    ya_result (*stop)(network_server_t *server);        // could return instantly, only waits in deconfigure, finalise & start
    ya_result (*deconfigure)(network_server_t *server); // the reverse operation of configure
    ya_result (*finalise)(network_server_t *server);    // frees whatever resources were allocated when the structure was made
    ya_result (*state)(network_server_t *server);       // gives the state of the server
    const char *(*long_name)();                         // gives the name of this server (e.g. its class)
};

extern struct network_server_vtbl_s network_server_dummy_vtbl;

#define NETWORK_SERVICE_UNINITIALISED {NULL, &network_server_dummy_vtbl}

// extern server_context_s g_server_context;

/** \brief  Initialize sockets and copy the config parameters into server_context_t
 *
 *  @param[in] config
 *
 *  @param[out] server_context
 *
 *  @retval OK
 *  @return otherwise log_quit will stop the program
 */

int  server_context_create();

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

uint32_t server_context_append_socket_name(char *buffer, uint16_t s);

/** \brief Closes all sockets and remove pid file
 *
 *  @param[in] config
 *  @param[in] server_context
 *
 *  @retval OK
 *  @return otherwise log_quit will stop the program
 */

void             server_context_stop();

uint32_t         server_context_tcp_interface_count();
struct addrinfo *server_context_tcp_interface(uint32_t index);
int32_t          server_context_tcp_reserve(uint16_t n);
int              server_context_tcp_socket(uint16_t n);

uint32_t         server_context_udp_interface_count();
struct addrinfo *server_context_udp_interface(uint32_t index);
int32_t          server_context_udp_reserve(uint16_t n);
int              server_context_udp_socket(uint16_t n);

ya_result        server_context_socket_open_bind(struct addrinfo *addr, int sock_type, bool reuse_port);
ya_result        server_context_socket_open_bind_multiple(struct addrinfo *addr, int sock_type, bool reuse_port, int *sockets, int socket_count);
ya_result        server_context_socket_close(int socket);
ya_result        server_context_socket_close_multiple(int *sockets, int socket_count);

void             server_context_init();
void             server_context_finalise();

#ifdef __cplusplus
}
#endif

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

#pragma once

#include <dnscore/sys_types.h>

#ifndef DNSCORE_HAS_TCP_MANAGER
#define DNSCORE_HAS_TCP_MANAGER 0
#endif

#ifndef __TCP_MANAGER_C__
#if !DNSCORE_HAS_TCP_MANAGER
#error "dnscore/tcp_manager.h should not be included if the TCP manager is disabled"
#endif
typedef void* tcp_manager_socket_context_t;
#endif

#define TCP_MANAGER_HOST_CONTEXT_CONNECTION_COUNT_MAX 16
#define TCP_MANAGER_REGISTERED_HOST_CONTEXT_CONNECTION_COUNT_MAX 16

void tcp_manager_init();

void tcp_manager_finalise();

/**
 * Registers a hosts with its separate allowed connections.
 */
ya_result tcp_manager_host_register(const socketaddress *sa, socklen_t sa_len, s32 allowed_connections_max);

/**
 * Sets the allowed connections total for all unregistered connections.
 */
ya_result tcp_manager_connection_max(s32 allowed_connections_max);

/**
 * Accepts a TCP connection and manages it.
 */
ya_result tcp_manager_accept(int servfd, tcp_manager_socket_context_t **sctxp);

/**
 * Acquires a TCP connection, ensuring exclusive access to the stream.
 */
tcp_manager_socket_context_t* tcp_manager_context_acquire_from_socket(int sockfd);

tcp_manager_socket_context_t* tcp_manager_context_acquire(tcp_manager_socket_context_t *sctx);

/**
 * Releases a TCP connection.
 */
void tcp_manager_context_release(tcp_manager_socket_context_t *sctx);

/**
 * Closes then releases a TCP connection. (When the last read returned 0 bytes)
 */
void tcp_manager_context_close_and_release(tcp_manager_socket_context_t *sctx);

/**
 * Updates the amount of bytes sent over an acquired connection.
 */
void tcp_manager_write_update(tcp_manager_socket_context_t *sctx, size_t buffer_size);

/**
 * Updates the amount of bytes received from an acquired connection.
 */
void tcp_manager_read_update(tcp_manager_socket_context_t *sctx, size_t buffer_size);

/**
 * Reports an error that occurred using the connection.
 */
void tcp_manager_error_report(tcp_manager_socket_context_t *sctx, size_t buffer_size);

/**
 * Sends over an acquired connection, calls tcp_manager_write_update.
 */
ya_result tcp_manager_write(tcp_manager_socket_context_t *sctx, const u8 *buffer, size_t buffer_size);

/**
 * Receives from an acquired connection, calls tcp_manager_write_update.
 */
ya_result tcp_manager_read(tcp_manager_socket_context_t *sctx, u8 *buffer, size_t buffer_size);

/**
 * Receives from an acquired connection, calls tcp_manager_write_update.
 */
ya_result tcp_manager_read_fully(tcp_manager_socket_context_t *sctx, u8 *buffer, size_t buffer_size);

/**
 * Marks the TCP stream as being closed.
 * When the last reference to the TCP stream is lost, then it will be closed and removed from the states collections.
 */
ya_result tcp_manager_close(tcp_manager_socket_context_t *sctx);

/**
 * Retrieves the address of an acquired connection.
 */
socketaddress *tcp_manager_socketaddress(tcp_manager_socket_context_t *sctx);

/**
 * Retrieves the address length of an acquired connection.
 */
socklen_t tcp_manager_socklen(tcp_manager_socket_context_t *sctx);

/**
 * Gets the socket file descriptor of an acquired connection.
 */
int tcp_manager_socket(tcp_manager_socket_context_t *sctx);

void tcp_manager_set_recvtimeout(tcp_manager_socket_context_t *sctx, int seconds, int useconds);
void tcp_manager_set_sendtimeout(tcp_manager_socket_context_t *sctx, int seconds, int useconds);
void tcp_manager_set_nodelay(tcp_manager_socket_context_t *sctx, bool enable);
void tcp_manager_set_cork(tcp_manager_socket_context_t *sctx, bool enable);

/**
 * Not sure it make sense anymore.
 */
bool tcp_manager_is_valid(tcp_manager_socket_context_t *sctx);

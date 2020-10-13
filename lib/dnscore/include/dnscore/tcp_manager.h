/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2020, EURid vzw. All rights reserved.
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
typedef void* tcp_manager_socket_context_t;
#endif

ya_result tcp_manager_accept(int servfd);
tcp_manager_socket_context_t* tcp_manager_context_acquire(int sockfd);
bool tcp_manager_context_release(tcp_manager_socket_context_t *sctx);
ya_result tcp_manager_write(tcp_manager_socket_context_t *sctx, const u8 *buffer, size_t buffer_size);
ya_result tcp_manager_read(tcp_manager_socket_context_t *sctx, u8 *buffer, size_t buffer_size);
ya_result tcp_manager_close(tcp_manager_socket_context_t *sctx);

void tcp_manager_write_update(tcp_manager_socket_context_t *sctx, size_t buffer_size);
void tcp_manager_read_update(tcp_manager_socket_context_t *sctx, size_t buffer_size);

socketaddress *tcp_manager_socketaddress(tcp_manager_socket_context_t *sctx);
socklen_t tcp_manager_socklen(tcp_manager_socket_context_t *sctx);
int tcp_manager_socket(tcp_manager_socket_context_t *sctx);

bool tcp_manager_is_valid(tcp_manager_socket_context_t *sctx);

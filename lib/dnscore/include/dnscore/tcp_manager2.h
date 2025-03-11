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

#pragma once

#include <dnscore/host_address.h>
#include <dnscore/mutex.h>
#include <dnscore/dns_message.h>

#ifndef DNSCORE_HAS_TCP_MANAGER
#define DNSCORE_HAS_TCP_MANAGER 1
#endif

struct tcp_manager_channel_s;

typedef ya_result tcp_manager_channel_message_read_method(struct tcp_manager_channel_s *tmc, dns_message_t *mesg);
typedef ya_result tcp_manager_channel_message_write_method(struct tcp_manager_channel_s *tmc, dns_message_t *mesg);
typedef ya_result tcp_manager_channel_message_close_method(struct tcp_manager_channel_s *tmc);

struct tcp_manager_channel_message_vtbl
{
    tcp_manager_channel_message_read_method  *read;
    tcp_manager_channel_message_write_method *write;
    tcp_manager_channel_message_close_method *close;
};

#define TCPM2CHN_TAG 0x4e4843324d504354

struct tcp_manager_channel_s
{
    mutex_t                                  rd_mtx;
    mutex_t                                  wr_mtx;
    socketaddress_t                          ss;
    int64_t                                  accept_ts;
    int64_t                                  read_ts;
    int64_t                                  write_ts;
    SSL                                     *ssl_socket;
    struct tcp_manager_channel_message_vtbl *vtbl;
    atomic_int                               rc;
    socklen_t                                ss_len;
    int                                      sock;
    int                                      index;
};

typedef struct tcp_manager_channel_s tcp_manager_channel_t;

#if !__TCP_MANAGER2_C__
extern struct tcp_manager_channel_message_vtbl tcp_manager_channel_message_tcp;
#endif

/**
 * Checks the quotas.
 *  _ IP quotas
 *  _ total quotas
 * Creates a channel.
 * Creates the R&W threads for the channel. (Pool?)
 */

ya_result tcp_manager_channel_accept(int sockfd, tcp_manager_channel_t **tmcp);

/*
 * The R thread reads each message into a dns_message and sends it for processing.
 * The dns_message contains a reference (output stream?) to write back to the channel (?).
 * There is one counter and it's the number of processing threads.
 */

void                    tcp_manager_channel_acquire(tcp_manager_channel_t *tmc);

void                    tcp_manager_channel_release(tcp_manager_channel_t *tmc);

static inline int       tcp_manager_channel_socket(tcp_manager_channel_t *tmc) { return tmc->sock; }

static inline ya_result tcp_manager_channel_send(tcp_manager_channel_t *tmc, dns_message_t *mesg) { return tmc->vtbl->write(tmc, mesg); }

static inline ya_result tcp_manager_channel_make_error_and_send(tcp_manager_channel_t *tmc, dns_message_t *mesg, uint16_t error_code)
{
    ya_result ret;
    dns_message_make_signed_error(mesg, error_code);
    ret = tcp_manager_channel_send(tmc, mesg);
    return ret;
}

SSL_CTX  *tcp_manager_channel_ssl_context_new(const char *cert_pem, const char *key_pem);

void      tcp_manager_channel_ssl_context_delete(SSL_CTX *ssl_ctx);

int       tcp_manager_channel_ssl_handshake(tcp_manager_channel_t *tmc, SSL_CTX *ssl_ctx);

void      server_process_channel_thread(void *parm);

ya_result tcp_manager_host_register(const socketaddress_t *sa, socklen_t sa_len, int32_t allowed_connections_max);

ya_result tcp_manager_connection_max(int32_t allowed_connections_max);

ya_result tcp_manager_init();

void      tcp_manager_finalise();

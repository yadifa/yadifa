/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
#include <dnscore/ptr_treemap.h>
#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>

#define DNSCORE_REST_HAS_HTTPS 0

struct rest_server_network_setup_args_s
{
    host_address_t *listen;
    char           *pid_file;
#if DNSCORE_REST_HAS_HTTPS
    char *ca;
    char *cert;
    char *key;
#endif
    pid_t    pid;
    uid_t    uid;
    gid_t    gid;
    uint32_t worker_count;
    uint32_t queue_size;
    uint16_t default_port;
#if DNSCORE_REST_HAS_HTTPS
    bool https;
#endif
    bool setup_signals;
};

typedef struct rest_server_network_setup_args_s rest_server_network_setup_args_t;

struct rest_server_service_client_s
{
    socketaddress_t sa;
    socklen_t       sa_len;
    int             sockfd;
    int             query_line_size;
    char            query_line[1];
};

typedef struct rest_server_service_client_s rest_server_service_client_t;

static inline rest_server_service_client_t *rest_server_service_client_new_instance(int line_size)
{
    rest_server_service_client_t *client = (rest_server_service_client_t *)malloc(sizeof(rest_server_service_client_t) - 1 + line_size);
    ZEROMEMORY(client, sizeof(rest_server_service_client_t) - 1);
    client->query_line_size = line_size;
    return client;
}

static inline void rest_server_service_client_free(rest_server_service_client_t *client) { free(client); }

struct rest_server_context_s
{
    rest_server_service_client_t *client;
    input_stream_t                is;
    output_stream_t               fos;
    output_stream_t               os; // the buffered output
    char                         *access_control_allow_origin;
    char                         *page_name;
    ptr_treemap_t                 page_args;
    ptr_treemap_t                 path_args;
    int64_t                       answer_start;
#if DNSCORE_REST_HAS_HTTPS
    SSL_CTX *sslctx;
    SSL     *sslsock;
#endif
};

typedef struct rest_server_context_s rest_server_context_t;

typedef void(rest_server_page_t)(rest_server_context_t *);

int       rest_server_setup(rest_server_network_setup_args_t *args);

ya_result rest_server_start(rest_server_network_setup_args_t *args);

void      rest_server_wait(rest_server_network_setup_args_t *args);

void      rest_server_stop(rest_server_network_setup_args_t *args);

ya_result rest_server_page_register(const char *name, rest_server_page_t *page);

bool      rest_server_context_arg_get(rest_server_context_t *ctx, char **text, const char *name_, ...);

bool      rest_server_context_arg_get_double(rest_server_context_t *ctx, double *valuep, const char *name_, ...);

bool      rest_server_context_arg_get_int(rest_server_context_t *ctx, int *value, const char *name_, ...);

bool      rest_server_context_arg_get_int64(rest_server_context_t *ctx, int64_t *value, const char *name_, ...);

bool      rest_server_context_arg_get_u8(rest_server_context_t *ctx, uint8_t *valuep, const char *name_, ...);

bool      rest_server_context_arg_get_bool(rest_server_context_t *ctx, bool *value, const char *name_, ...);

bool      rest_server_context_path_arg_get(rest_server_context_t *ctx, char **text, const char *name);

bool      rest_server_context_path_arg_get_double(rest_server_context_t *ctx, double *valuep, const char *name);

bool      rest_server_context_path_arg_get_int(rest_server_context_t *ctx, int *valuep, const char *name);

bool      rest_server_context_path_arg_get_int64(rest_server_context_t *ctx, int64_t *valuep, const char *name);

bool      rest_server_context_path_arg_get_u8(rest_server_context_t *ctx, uint8_t *valuep, const char *name);

bool      rest_server_context_path_arg_get_bool(rest_server_context_t *ctx, bool *valuep, const char *name);

ya_result rest_server_write_http_header_and_body(rest_server_context_t *ctx, int code, const char *code_text, int buffer_size, const void *buffer);

ya_result rest_server_write_http_header_and_print(rest_server_context_t *ctx, int code, const char *code_text, const char *fmt, ...);

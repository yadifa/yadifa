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
 * @defgroup dnspacket DNS Messages
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/dnscore_config_features.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <dnscore/ptr_treemap.h>
#include <dnscore/service.h>
#include <dnscore/thread_pool.h>
#include <dnscore/mutex.h>

/**
 * Sets the minimum time between two queries from a given IP to any rate-limited page.
 */

void    ip_rate_limit_set(int64_t microseconds);

int64_t ip_rate_limit_get();

/**
 * Sets the time a nonce is valid after returning a 401.
 */

void    ip_nonce_validity_time_set(int64_t microseconds);

int64_t ip_nonce_limit_get();

/**
 * Sends the "HTTP/1.1 [code]" header.
 * Where [code] is
 *   200 -- success
 *   or anything else from https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
 * @param os
 * @param code the
 * @return
 */

ya_result http_header_code(output_stream_t *os, int code);

/**
 * Sends a header field.
 *
 * name: value\r\n
 *
 * @param os
 * @param name
 * @param name_len
 * @param value
 * @param value_len
 * @return
 */

ya_result http_header_field(output_stream_t *os, const char *name, size_t name_len, const char *value, size_t value_len);

/**
 * Sends the host header field.
 *
 * @param os
 * @param host
 * @param host_len
 * @return
 */

ya_result http_header_host(output_stream_t *os, const char *host, size_t host_len);

/**
 * Sends the Content-Type header field.
 *
 * @param os
 * @param content_type
 * @param content_type_len
 * @return
 */

ya_result http_header_content_type(output_stream_t *os, const char *content_type, size_t content_type_len);

/**
 * Sends the application/octet-stream Content-Type header field.
 *
 * @param os
 * @return
 */

ya_result http_header_content_type_application_octet_stream(output_stream_t *os);

/**
 * Sends the application/json Content-Type header field.
 *
 * @param os
 * @return
 */

ya_result http_header_content_type_application_json(output_stream_t *os);

/**
 * Sends the Transfer-Encoding header field.
 *
 * @param os
 * @param transfer_encoding
 * @param transfer_encoding_len
 * @return
 */

ya_result http_header_transfer_encoding(output_stream_t *os, const char *transfer_encoding, size_t transfer_encoding_len);

/**
 * Sends Transfer-Encoding as "chunked".
 *
 * @param os
 * @return
 */

ya_result http_header_transfer_encoding_chunked(output_stream_t *os);

/**
 * Sends the Content-Length field.
 *
 * @param os
 * @param length
 * @return
 */

ya_result http_header_content_length(output_stream_t *os, size_t length);

/**
 * Sends a date in RFC5322 format.
 *
 * @param os
 * @param date
 * @param date_len
 * @return
 */

ya_result http_header_date(output_stream_t *os, const char *date, size_t date_len);

/**
 * Sends the current date in RFC5322 format.
 *
 * @param os
 * @return
 */

ya_result http_header_date_now(output_stream_t *os);

/**
 * Closes the header.
 *
 * @param os
 * @return
 */

ya_result http_header_close(output_stream_t *os);

/**
 * Sends a chunk lenght (Transfer-Encoding: chunked)
 *
 * MUST be followed by the announced amount of bytes, then
 * http_write_chunk_end(os) must be called
 *
 * @param os
 * @param data
 * @param size
 * @return
 */

ya_result http_write_chunk_begin(output_stream_t *os, size_t size);

/**
 * Sends a chunk (Transfer-Encoding: chunked)
 *
 * Ends a block started with the http_write_chunk_begin() call
 * Note that the last chunk is sent using http_write_chunk_close(os)
 *
 * @param os
 * @param data
 * @param size
 * @return
 */

ya_result http_write_chunk_end(output_stream_t *os);

/**
 * Sends a whole chunk (Transfer-Encoding: chunked)
 * Begin, content and end of chunk are handled.
 *
 * Note that the last chunk must be a NULL, 0-sized chunk.
 *
 * @param os
 * @param data
 * @param size
 * @return
 */

ya_result http_write_chunk(output_stream_t *os, const void *data, size_t size);

/**
 * Sends a chunk terminator
 *
 * @param os
 * @return
 */

ya_result http_write_chunk_close(output_stream_t *os);

/**
 * Sends content.
 *
 * The size must match Content-Length
 *
 * @param os
 * @param data
 * @param size
 * @return
 */

ya_result http_write_content(output_stream_t *os, const void *data, size_t size);

struct simple_rest_server_page_writer_args
{
    ptr_treemap_t uri_name_value_set;    // uri arguments
    ptr_treemap_t header_name_value_set; // header name-value set

    char         *path; // uri path
};

typedef struct simple_rest_server_page_writer_args simple_rest_server_page_writer_args;

struct simple_rest_server_page;
struct simple_rest_server;

typedef ya_result simple_rest_server_page_writer(const struct simple_rest_server_page *, output_stream_t *, const simple_rest_server_page_writer_args *);

struct simple_rest_server_page
{
    char                           *path;
    simple_rest_server_page_writer *writer; // this is a callback
    void *private;
    atomic_int rc;
    bool       rate_limited;
    bool       access_protected;
};

typedef struct simple_rest_server_page simple_rest_server_page;

struct simple_rest_server_s
{
    mutex_t               mtx;
    cond_t                cond;
    ptr_treemap_t         path_page_set;
    struct service_s      service;
    struct thread_pool_s *thread_pool;
    int                   client_current_count;
    int                   sockfd;
};

typedef struct simple_rest_server_s simple_rest_server_t;
typedef simple_rest_server_t        simple_rest_server; // to avoid compatibility issues (OBSOLETE)

#define SIMPLE_REST_SERVER_UNINITIALISED {MUTEX_INITIALIZER, COND_INITIALIZER, {NULL, ptr_treemap_asciizp_node_compare}, UNINITIALIZED_SERVICE, NULL, 0, -1}
#define SIMPLE_REST_SERVER_UNINITIALiSED SIMPLE_REST_SERVER_UNINITIALISED // to avoid compatibility issues with programs using that typo

ya_result simple_rest_server_init(simple_rest_server_t *srs, struct addrinfo *addr);

ya_result simple_rest_server_page_register_ex(simple_rest_server_t *srs, const char *path, simple_rest_server_page_writer *page_writer, void *page_private, bool access_protected, bool rate_limited);

ya_result simple_rest_server_page_register(simple_rest_server_t *srs, const char *path, simple_rest_server_page_writer *page_writer, void *page_private);

/**
 * Unregistering pages while the server is started has undefined behaviour
 *
 * @param srs
 * @param path
 * @return
 */

ya_result             simple_rest_server_page_unregister(simple_rest_server_t *srs, const char *path);

void                  simple_rest_server_finalize(simple_rest_server_t *srs);

void                  simple_rest_server_threadpool_set(simple_rest_server_t *srs, struct thread_pool_s *tp);

struct thread_pool_s *simple_rest_server_threadpool_get(simple_rest_server_t *srs);

ya_result             simple_rest_server_start(simple_rest_server_t *srs);

ya_result             simple_rest_server_stop(simple_rest_server_t *srs);

/**
 * Gets the HTTP header field of the query
 *
 * @param args
 * @param key
 *
 * @return the value for the key
 */

const char *simple_rest_server_page_writer_args_get_header_field(const simple_rest_server_page_writer_args *args, const char *key);

/**
 * Gets the HTTP URI field of the query
 *
 * @param args
 * @param key
 *
 * @return the value for the key
 */

const char *simple_rest_server_page_writer_args_get_uri_arg(const simple_rest_server_page_writer_args *args, const char *key);

/**
 * Gets the HTTP URI field of the query
 *
 * @param args
 * @param key
 * @param default_value
 *
 * @return the value for the key or default if there was no value
 */

const char *simple_rest_server_page_writer_args_get_uri_arg_with_default(const simple_rest_server_page_writer_args *args, const char *key, const char *default_value);

/**
 * Gets the HTTP URI field of the query and convert it to an integer
 *
 * @param args
 * @param key
 * @param valuep a pointer to an int64_t that will contain the value
 *
 * @return SUCCESS if the value has been properly parsed, otherwise an error code
 */

ya_result simple_rest_server_page_writer_args_get_uri_int_arg(const simple_rest_server_page_writer_args *args, const char *key, int64_t *valuep);

/**
 * Gets the HTTP URI field of the query and convert it to an integer
 *
 * @param args
 * @param key
 * @param valuep a pointer to an int64_t that will contain the value
 *
 */

void simple_rest_server_page_writer_args_get_uri_int_arg_with_default(const simple_rest_server_page_writer_args *args, const char *key, int64_t *valuep, int64_t default_value);

/*
 * The realm is a part of the authentication token.
 * Users can only be authenticated if the realm is the same than for the token creation.
 *

#!/bin/sh

USER="$1"
REALM="$2"
PASSWORD="$3"

if [ -z $PASSWORD ]; then
  echo "$* user realm password"
  exit 1
fi

echo -n "$USER:$REALM:$PASSWORD" | md5sum
exit 0

 */

void        http_user_account_realm_set(const char *realm);
const char *http_user_account_realm_get();

ya_result   http_user_authentication_token_compute(const char *name, const char *realm, const char *password, char *digest_text, size_t digest_text_size);
void        http_user_account_add_ex(const char *name, const char *md5_name_realm_password);
void        http_user_account_add(const char *name, const char *realm, const char *password);
void        http_user_account_del(const char *name);
const char *http_user_account_authentication_get(const char *name);
const char *http_user_account_nonce_get(const char *name, int64_t *nonce_token_epochp);
bool        http_user_account_nonce_set(const char *name, const char *nonce_token);

/** @} */

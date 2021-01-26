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

/** @defgroup dnspacket DNS Messages
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#pragma once

#include "dnscore/dnscore-config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "dnscore/ptr_set.h"
#include "dnscore/service.h"
#include "dnscore/thread_pool.h"

/**
 * Callback for uri_decode.
 * 
 * name value are the arguments of the uri
 * args is the last parameter passed through uri_decode.
 * 
 * The path part of the uri is a value with its name set to NULL.
 */

typedef void uri_decode_callback(const char *name, const char *value, void *args);

/**
 * Unescapes and parse an URI
 * 
 * @param text_
 * @param text_limit_
 * @param uri_callback
 * @param args
 * @return 
 */

ya_result uri_decode(const char *text_, const char *text_limit_, uri_decode_callback *uri_callback, void *args);


/**
 * Sends the "HTTP/1.1 [code]" header.
 * Where [code] is
 *   200 -- success
 *   or anything else from https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
 * @param os
 * @param code the 
 * @return 
 */

ya_result http_header_code(output_stream *os, int code);

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

ya_result http_header_field(output_stream *os, const char *name, size_t name_len, const char *value, size_t value_len);

/**
 * Sends the host header field.
 * 
 * @param os
 * @param host
 * @param host_len
 * @return 
 */

ya_result http_header_host(output_stream *os, const char *host, size_t host_len);

/**
 * Sends the Content-Type header field.
 * 
 * @param os
 * @param content_type
 * @param content_type_len
 * @return 
 */

ya_result http_header_content_type(output_stream *os, const char *content_type, size_t content_type_len);

/**
 * Sends the application/octet-stream Content-Type header field.
 * 
 * @param os
 * @return 
 */

ya_result http_header_content_type_application_octet_stream(output_stream *os);

/**
 * Sends the application/json Content-Type header field.
 * 
 * @param os
 * @return 
 */

ya_result http_header_content_type_application_json(output_stream *os);

/**
 * Sends the Transfer-Encoding header field.
 * 
 * @param os
 * @param transfer_encoding
 * @param transfer_encoding_len
 * @return 
 */

ya_result http_header_transfer_encoding(output_stream *os, const char *transfer_encoding, size_t transfer_encoding_len);

/**
 * Sends Transfer-Encoding as "chunked".
 * 
 * @param os
 * @return 
 */

ya_result http_header_transfer_encoding_chunked(output_stream *os);

/**
 * Sends the Content-Length field.
 * 
 * @param os
 * @param length
 * @return 
 */

ya_result http_header_content_length(output_stream *os, size_t length);

/**
 * Sends a date in RFC5322 format.
 * 
 * @param os
 * @param date
 * @param date_len
 * @return 
 */

ya_result http_header_date(output_stream *os, const char *date, size_t date_len);

/**
 * Sends the current date in RFC5322 format.
 * 
 * @param os
 * @return 
 */

ya_result http_header_date_now(output_stream *os);

/**
 * Closes the header.
 * 
 * @param os
 * @return 
 */

ya_result http_header_close(output_stream *os);

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

ya_result http_write_chunk_begin(output_stream *os, size_t size);

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

ya_result http_write_chunk_end(output_stream *os);

/**
 * Sends a while chunk (Transfer-Encoding: chunked)
 * Begin, content and end of chunk are handled.
 * 
 * Note that the last chunk must be a NULL, 0-sized chunk.
 * 
 * @param os
 * @param data
 * @param size
 * @return 
 */

ya_result http_write_chunk(output_stream *os, const void *data, size_t size);

/**
 * Sends a chunk terminator
 * 
 * @param os
 * @return 
 */

ya_result http_write_chunk_close(output_stream *os);

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

ya_result http_write_content(output_stream *os, const void *data, size_t size);

struct simple_rest_server_page_writer_args
{
    ptr_set uri_name_value_set;     // uri arguments
    ptr_set query_name_value_set;   // query arguments
    
    char *path;                     // uri path
};

typedef struct simple_rest_server_page_writer_args simple_rest_server_page_writer_args;

struct simple_rest_server_page;
struct simple_rest_server;

typedef ya_result simple_rest_server_page_writer(const struct simple_rest_server_page *, output_stream *, const simple_rest_server_page_writer_args *);

struct simple_rest_server_page
{
    char *path;
    simple_rest_server_page_writer *writer;
    void *private;
    int rc;
};

typedef struct simple_rest_server_page simple_rest_server_page;

struct simple_rest_server
{
    mutex_t mtx;
    cond_t cond;
    ptr_set path_page_set;
    struct service_s service;
    struct thread_pool_s *thread_pool;
    int client_current_count;
    int sockfd;
};

typedef struct simple_rest_server simple_rest_server;

ya_result simple_rest_server_init(simple_rest_server *srs, struct addrinfo *addr);

ya_result simple_rest_server_page_register(simple_rest_server *srs, const char *path, simple_rest_server_page_writer *page_writer, void *page_private);

/**
 * Unregistering pages while the server is started has undefined behaviour
 * 
 * @param srs
 * @param path
 * @return 
 */

ya_result simple_rest_server_page_unregister(simple_rest_server *srs, const char *path);

void simple_rest_server_finalize(simple_rest_server *srs);

void simple_rest_server_threadpool_set(simple_rest_server *srs, struct thread_pool_s* tp);

struct thread_pool_s *simple_rest_server_threadpool_get(simple_rest_server *srs);

ya_result simple_rest_server_start(simple_rest_server *srs);

ya_result simple_rest_server_stop(simple_rest_server *srs);

/**
 * 
 * Gets the HTTP header field of the query
 * 
 * @param args
 * @param host
 * @return 
 */

const char *simple_rest_server_page_writer_args_get_header_field(const simple_rest_server_page_writer_args *args, const char *host);

/**
 * 
 * Gets the HTTP header field of the query
 * 
 * @param args
 * @param host
 * @return 
 */

const char *simple_rest_server_page_writer_args_get_uri_arg(const simple_rest_server_page_writer_args *args, const char *host);

/** @} */

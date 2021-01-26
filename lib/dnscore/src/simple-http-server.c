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
#include "dnscore/dnscore-config.h"

#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>

#if HAS_HTTPS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#endif

#include "dnscore/fdtools.h"
#include "dnscore/ptr_vector.h"
#include "dnscore/logger.h"
#include "dnscore/config-cmdline.h"
#include "dnscore/config_settings.h"
#include "dnscore/pid.h"
#include "dnscore/service.h"
#include "dnscore/thread_pool.h"
#include "dnscore/cmdline.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/ptr_set.h"
#include "dnscore/socket-server.h"
#include "dnscore/zalloc.h"
#include "dnscore/network.h"
#include "dnscore/bytearray_output_stream.h"
#include "dnscore/parsing.h"

#include "dnscore/simple-http-server.h"

#define SIMPLE_REST_SERVER_CLIENT_LINE_SIZE 4096
#define SIMPLE_REST_SERVER_CLIENT_LISTEN_BACKLOG 30

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger



ya_result
uri_decode(const char *text_, const char *text_limit_, uri_decode_callback *uri_callback, void *args)
{
    // un-escape
    
    output_stream baos;
    bytearray_output_stream_init_ex(&baos, NULL, text_limit_ - text_, BYTEARRAY_DYNAMIC);
    while(text_ < text_limit_)
    {
        if(*text_ != '%')
        {
            output_stream_write_u8(&baos, *text_);
            ++text_;
        }
        else
        {
            u32 v;
            ++text_; // for the percent
            if(sscanf(text_, "%2x", &v) == 1)
            {
                output_stream_write_u8(&baos, v);
                text_ += 2; // for the two ASCII chars
            }
            else
            {
                // log_err("uri decoding of '%s' failed", text_);
                output_stream_close(&baos);
                return ERROR;
            }
        }
    }
    output_stream_write_u8(&baos, 0);
    
    // parse
    
    char *text = (char*)bytearray_output_stream_buffer(&baos);
    //const char *text_limit = &text_[bytearray_output_stream_size(&baos) - 1];

    char *param0;
    param0 = strchr(text, '?');
    
    if(param0 == NULL)
    {
        // no parameters
        
        uri_callback(NULL, text, args);
        
        output_stream_close(&baos);
        return SUCCESS;
    }
    
    *param0++ = '\0';
    
    uri_callback(NULL, text, args);
    
    char *name = param0;
    
    for(;;)
    {
        char *value = strchr(name, '=');
        
        if(value == NULL)
        {
            break;
        }
        
        size_t name_len = value - name;
        
        ++value;
        
        size_t value_len;
        
        char *name_next = strchr(value, '&');
        
        if(name_next == NULL)
        {
            value_len = text_limit_ - value;
        }
        else
        {
            value_len = name_next - value;
        }
        
        name[name_len] = '\0';
        value[value_len] = '\0';

        // log_info("'%s' = '%s'", name, value);
        
        uri_callback(name, value, args);

        if(name_next == NULL)
        {
            break;
        }
        
        name = name_next + 1;
    }
    
    output_stream_close(&baos);
    
    return SUCCESS;
}

/**
 * Sends the "HTTP/1.1 [code]" header.
 * Where [code] is
 *   200 -- success
 *   or anything else from https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
 * @param os
 * @param code the 
 * @return 
 */

ya_result
http_header_code(output_stream *os, int code)
{
    ya_result ret;
    
    if(ISOK(ret = output_stream_write_fully(os, "HTTP/1.1 ", 9)))
    {
        if(ISOK(ret = osformat(os, "%i", code)))
        {
            ret = output_stream_write_fully(os, "\r\n", 2);
        }
    }
    
    return ret;
}

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

ya_result
http_header_field(output_stream *os, const char *name, size_t name_len, const char *value, size_t value_len)
{
    ya_result ret;
    
    if(ISOK(ret = output_stream_write_fully(os, name, name_len)))
    {
        if(ISOK(ret = output_stream_write_fully(os, ": ", 2)))
        {
            if(ISOK(ret = output_stream_write_fully(os, value, value_len)))
            {
                ret = output_stream_write_fully(os, "\r\n", 2);
            }
        }
    }
    
    return ret;
}

/**
 * Sends the host header field.
 * 
 * @param os
 * @param host
 * @param host_len
 * @return 
 */

ya_result
http_header_host(output_stream *os, const char *host, size_t host_len)
{
    ya_result ret = http_header_field(os, "Host", 4, host, host_len);
    
    return ret;
}

/**
 * Sends the Content-Type header field.
 * 
 * @param os
 * @param content_type
 * @param content_type_len
 * @return 
 */

ya_result
http_header_content_type(output_stream *os, const char *content_type, size_t content_type_len)
{
    ya_result ret = http_header_field(os, "Content-Type", 12, content_type, content_type_len);
    
    return ret;
}

/**
 * Sends the application/octet-stream Content-Type header field.
 * 
 * @param os
 * @return 
 */

ya_result
http_header_content_type_application_octet_stream(output_stream *os)
{
    ya_result ret = http_header_content_type(os, "application/octet-stream", 24);
    
    return ret;
}

/**
 * Sends the application/json Content-Type header field.
 * 
 * @param os
 * @return 
 */

ya_result
http_header_content_type_application_json(output_stream *os)
{
    ya_result ret = http_header_content_type(os, "application/json", 16);
    
    return ret;
}

/**
 * Sends the text/html;charset=UTF-8 Content-Type header field.
 * 
 * @param os
 * @return 
 */

ya_result
http_header_content_type_text_html_utf8(output_stream *os)
{
    ya_result ret = http_header_content_type(os, "text/html;charset=UTF-8", 23);
    
    return ret;
}

/**
 * Sends the Transfer-Encoding header field.
 * 
 * @param os
 * @param transfer_encoding
 * @param transfer_encoding_len
 * @return 
 */

ya_result
http_header_transfer_encoding(output_stream *os, const char *transfer_encoding, size_t transfer_encoding_len)
{
    ya_result ret = http_header_field(os, "Transfer-Encoding", 17, transfer_encoding, transfer_encoding_len);
    
    return ret;
}

/**
 * Sends Transfer-Encoding as "chunked".
 * 
 * @param os
 * @return 
 */

ya_result
http_header_transfer_encoding_chunked(output_stream *os)
{
    ya_result ret = http_header_transfer_encoding(os, "chunked", 7);
    
    return ret;
}

/**
 * Sends the Content-Length field.
 * 
 * @param os
 * @param length
 * @return 
 */

ya_result
http_header_content_length(output_stream *os, size_t length)
{
    char length_as_text[16];
    ya_result n = snformat(length_as_text, sizeof(length_as_text), "%llu", length);
    ya_result ret = http_header_field(os, "Content-Length", 14, length_as_text, n);
    
    return ret;
}

/**
 * Sends the Date header field.
 * 
 * @param os
 * @param date
 * @param date_len
 * @return 
 */

ya_result
http_header_date(output_stream *os, const char *date, size_t date_len)
{
    ya_result ret = http_header_field(os, "Date", 4, date, date_len);
    
    return ret;
}

/**
 * Sends the current date in RFC5322 format.
 * 
 * @param os
 * @return 
 */

ya_result
http_header_date_now(output_stream *os)
{
    char date_buffer[32];
    
    ya_result date_buffer_len = time_epoch_as_rfc5322(time(NULL), date_buffer, sizeof(date_buffer)); // only fails if the buffer is < 29 bytes long
    
    ya_result ret = http_header_date(os, date_buffer, date_buffer_len);
    
    return ret;
}

/**
 * Closes the header.
 * 
 * @param os
 * @return 
 */

ya_result
http_header_close(output_stream *os)
{
    ya_result ret = output_stream_write_fully(os, "\r\n", 2);
    
    return ret;
}

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

ya_result
http_write_chunk_begin(output_stream *os, size_t size)
{
    ya_result ret;
    
    ret = osformat(os, "%llx\r\n", size);
    
    return ret;
}

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

ya_result
http_write_chunk_end(output_stream *os)
{
    ya_result ret;
    
    ret = output_stream_write_fully(os, "\r\n", 2);
    
    return ret;
}


/**
 * Sends a chunk (Transfer-Encoding: chunked)
 * 
 * Note that the last chunk is sent using http_write_chunk_close(os)
 * 
 * @param os
 * @param data
 * @param size
 * @return 
 */

ya_result
http_write_chunk(output_stream *os, const void *data, size_t size)
{
    ya_result ret;
    
    if(ISOK(ret = osformat(os, "%llx\r\n", size)))
    {
        if(size > 0)
        {
            if(ISOK(ret = output_stream_write_fully(os, data, size)))
            {
                ret = output_stream_write_fully(os, "\r\n", 2);
            }
        }
    }
    
    return ret;
}

/**
 * Sends a chunk terminator
 * 
 * @param os
 * @return 
 */

ya_result
http_write_chunk_close(output_stream *os)
{
    ya_result ret = output_stream_write_fully(os, "0\r\n\r\n", 5);
    
    return ret;
}

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

ya_result
http_write_content(output_stream *os, const void *data, size_t size)
{
    ya_result ret = output_stream_write_fully(os, data, size);
    
    return ret;
}

struct simple_rest_server_client
{
    simple_rest_server *srs;
    socketaddress sa;
    socklen_t sa_len;
    int sockfd;
};

typedef struct simple_rest_server_client simple_rest_server_client;

static simple_rest_server_client*
simple_rest_server_client_new_instance(simple_rest_server *srs)
{
    simple_rest_server_client *client;
    
    ZALLOC_OBJECT_OR_DIE(client, simple_rest_server_client, GENERIC_TAG);
    client->srs = srs;
    client->sa_len = sizeof(client->sa);
    client->sockfd = -1;
    
    mutex_lock(&srs->mtx);
    ++srs->client_current_count;
    mutex_unlock(&srs->mtx);
    
    return client;
}

static void
simple_rest_server_client_reset(simple_rest_server_client* client)
{
    client->sa_len = sizeof(client->sa);
    client->sockfd = -1;
}

static void
simple_rest_server_client_delete(simple_rest_server_client *client)
{
    if(client != NULL)
    {
        mutex_lock(&client->srs->mtx);
        --client->srs->client_current_count;
        cond_notify(&client->srs->cond);
        mutex_unlock(&client->srs->mtx);
        
        close_ex(client->sockfd);
        ZFREE_OBJECT(client);
    }
}

static int simple_rest_server_main(struct service_worker_s *worker);

ya_result
simple_rest_server_init(simple_rest_server *srs, struct addrinfo *addr)
{
    static const int on = 1;
    
    socket_server_opensocket_s socket;
    ya_result ret;
    
    if(FAIL(ret = socket_server_opensocket_init(&socket, addr, SOCK_STREAM)))
    {
        return ret;
    }

    socket_server_opensocket_setopt(&socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#if defined(SO_REUSEPORT)
    socket_server_opensocket_setopt(&socket, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
    
    int sockfd = socket_server_opensocket_open(&socket);
    
    if(FAIL(sockfd))
    {
        return sockfd;
    }
    
    mutex_init(&srs->mtx);
    cond_init(&srs->cond);
    
    ptr_set_init(&srs->path_page_set);
    srs->path_page_set.compare = ptr_set_asciizp_node_compare;
    
    srs->thread_pool = NULL;
    
    service_init(&srs->service, simple_rest_server_main, "rest");
    service_args_set(&srs->service, srs);
    
    srs->client_current_count = 0;
    
    srs->sockfd = sockfd;
    
    return SUCCESS;
}

static simple_rest_server_page*
simple_rest_server_page_new_instance(const char *path, simple_rest_server_page_writer *page_writer, void *page_private)
{
    simple_rest_server_page *page;
    
    ZALLOC_OBJECT_OR_DIE(page, simple_rest_server_page, GENERIC_TAG);
    page->path = strdup(path);
    page->writer = page_writer;
    page->private = page_private;
    page->rc = 1;
    return page;
}

static void
simple_rest_server_page_delete(simple_rest_server_page *page)
{
    if(page != NULL)
    {
        free(page->path);
        ZFREE_OBJECT(page);
    }
}
static void
simple_rest_server_page_acquire_nolock(simple_rest_server *srs, simple_rest_server_page *page)
{
    (void)srs;
    ++page->rc;
}
#if UNUSED_DONT_REMOVE_YET
static void
simple_rest_server_page_acquire(simple_rest_server *srs, simple_rest_server_page *page)
{
    mutex_lock(&srs->mtx);
    simple_rest_server_page_acquire_nolock(srs, page);
    mutex_unlock(&srs->mtx);
}
#endif
static void
simple_rest_server_page_release(simple_rest_server *srs, simple_rest_server_page *page)
{
    mutex_lock(&srs->mtx);

    if(--page->rc == 0)
    {
        ptr_set_delete(&srs->path_page_set, page->path);
        
        mutex_unlock(&srs->mtx);

        simple_rest_server_page_delete(page);
    }
    else
    {
        mutex_unlock(&srs->mtx);
    }
}

static ya_result
simple_rest_server_page_release_with_path(simple_rest_server *srs, const char *path)
{
    simple_rest_server_page *page;
    
    mutex_lock(&srs->mtx);
    
    ptr_node *node = ptr_set_find(&srs->path_page_set, path);
    
    if((node != NULL) && (node->value != NULL))
    {
        page = (simple_rest_server_page*)node->value;
        
        if(--page->rc == 0)
        {
            ptr_set_delete(&srs->path_page_set, path);

            mutex_unlock(&srs->mtx);

            simple_rest_server_page_delete(page);
        }
        else
        {
            mutex_unlock(&srs->mtx);
        }
        
        return SUCCESS;
    }
    else
    {
        return ERROR;
    }
}

ya_result
simple_rest_server_page_register(simple_rest_server *srs, const char *path, simple_rest_server_page_writer *page_writer, void *page_private)
{
    simple_rest_server_page *page = simple_rest_server_page_new_instance(path, page_writer, page_private);
    
    bool inserted = FALSE;
    
    mutex_lock(&srs->mtx);
    ptr_node *node = ptr_set_insert(&srs->path_page_set, page->path);
    if(node->value == NULL)
    {
        node->value = page;
        inserted = TRUE;
    }
    mutex_unlock(&srs->mtx);
    
    if(inserted)
    {
        return SUCCESS;
    }
    else
    {
        simple_rest_server_page_delete(page);
        
        return ERROR;
    }
}

ya_result
simple_rest_server_page_unregister(simple_rest_server *srs, const char *path)
{
    ya_result ret = simple_rest_server_page_release_with_path(srs, path);
    
    return ret;
}

static void
simple_rest_server_destroy_callback(ptr_node *node)
{
    if(node->value != NULL)
    {
        simple_rest_server_page *page = (simple_rest_server_page*)node->value;
        simple_rest_server_page_delete(page);
    }
}

void
simple_rest_server_finalize(simple_rest_server *srs)
{
    mutex_lock(&srs->mtx);
    ptr_set_callback_and_destroy(&srs->path_page_set, simple_rest_server_destroy_callback);
    mutex_unlock(&srs->mtx);
    
    cond_finalize(&srs->cond);
    mutex_destroy(&srs->mtx);
    
    close_ex(srs->sockfd);
    
    srs->sockfd = -1;
}

void
simple_rest_server_threadpool_set(simple_rest_server *srs, struct thread_pool_s* tp)
{
    mutex_lock(&srs->mtx);
    srs->thread_pool = tp;
    mutex_unlock(&srs->mtx);
}

struct thread_pool_s*
simple_rest_server_threadpool_get(simple_rest_server *srs)
{
    mutex_lock(&srs->mtx);
    struct thread_pool_s* tp = srs->thread_pool;
    mutex_unlock(&srs->mtx);
    
    return tp;
}

ya_result
simple_rest_server_start(simple_rest_server *srs)
{
    ya_result ret = service_start(&srs->service);
    return ret;
}

ya_result
simple_rest_server_stop(simple_rest_server *srs)
{
    ya_result ret = service_stop(&srs->service);
    return ret;
}

/**
 * 
 * Gets the HTTP header field of the query
 * 
 * @param args
 * @param host
 * @return 
 */

const char *
simple_rest_server_page_writer_args_get_header_field(const simple_rest_server_page_writer_args *args, const char *host)
{
    ptr_node *node = ptr_set_find(&args->query_name_value_set, host);
    if(node != NULL && node->value != NULL)
    {
        return (const char*)node->value;
    }
    else
    {
        return NULL;
    }
}

/**
 * 
 * Gets the HTTP header field of the query
 * 
 * @param args
 * @param host
 * @return 
 */

const char *
simple_rest_server_page_writer_args_get_uri_arg(const simple_rest_server_page_writer_args *args, const char *host)
{
    ptr_node *node = ptr_set_find(&args->uri_name_value_set, host);
    if(node != NULL && node->value != NULL)
    {
        return (const char*)node->value;
    }
    else
    {
        return NULL;
    }
}


static void
simple_rest_server_client_answer_uri(const char *name, const char *value, void *args)
{
    simple_rest_server_page_writer_args *srspwa = (simple_rest_server_page_writer_args*)args;
    
    if(name != NULL)
    {
        ptr_set *uri_parameters_set = (ptr_set*)&srspwa->uri_name_value_set;
        ptr_node *node = ptr_set_insert(uri_parameters_set, (void*)name);
        if(node->value == NULL)
        {
            node->key = strdup(name);
            node->value = strdup(value);
        }
    }
    else
    {
        srspwa->path = strdup(value);
    }
}

static void
simple_rest_server_client_answer_destroy_callback(ptr_node *node)
{
    if(node->value != NULL)
    {
        free(node->key);
        free(node->value);
    }
}

static void
simple_rest_server_client_answer(simple_rest_server_client *client)
{
    input_stream is;
    output_stream os;
    simple_rest_server_page *page = NULL;
    simple_rest_server_page_writer_args args;

    ya_result ret;
    int line_index;
    
    char line[SIMPLE_REST_SERVER_CLIENT_LINE_SIZE];

    // read the input
    
    fd_input_stream_attach(&is, client->sockfd);
    fd_output_stream_attach_noclose(&os, client->sockfd); // we don't want to close the file descriptor twice
    
    ptr_set_init(&args.uri_name_value_set);
    args.uri_name_value_set.compare = ptr_set_asciizp_node_compare;
    ptr_set_init(&args.query_name_value_set);
    args.query_name_value_set.compare = ptr_set_asciizp_node_compare;
        
    for(line_index = 0; ; ++line_index)
    {
        if((ret = input_stream_read_line(&is, line, sizeof(line))) <= 0)
        {
            // unexpected eof
            log_err("http: unexpected eof");
            break;
        }                
                
        --ret;
        
        while((ret >= 0) && (line[ret] <= ' '))
        {
            --ret;
        }
        
        ++ret;
        
        if(ret == 0)
        {
            // details have been gathered, now answer

            if(page != NULL)
            {
                page->writer(page, &os, &args);
                break;
            }
        }
        
        line[ret] = '\0';
        
        log_debug("http: parsing [%i] '%s'", line_index, line);
        
        // begins with 'GET ' ?
        // ends with ' HTTP/1.1' ?
        
        if(line_index == 0)
        {
            if((ret >= 9) && (memcmp(line, "GET ", 4) == 0) && (memcmp(&line[ret - 9], " HTTP/1.1", 9) == 0))
            {
                ya_result uri_err = uri_decode(&line[4], &line[ret - 9], simple_rest_server_client_answer_uri, &args);
                
                if(FAIL(uri_err))
                {
                    line[ret - 9] = '\0';
                    
                    log_err("http: could not parse uri '%s'", &line[4]);
                    
                    break;
                }
                
                // early cut: check if the page is registered
                
                mutex_lock(&client->srs->mtx);
                const char *path = args.path;
                
                while(*path == '/') ++path;

                // get the page
                
                ptr_node *node = ptr_set_find(&client->srs->path_page_set, path);

                if((node != NULL) && (node->value != NULL))
                {
                    page = (simple_rest_server_page*)node->value;
                    simple_rest_server_page_acquire_nolock(client->srs, page);
                    mutex_unlock(&client->srs->mtx);
                }
                else
                {
                    static const char error_404[] = "<html><body><h0>404 not found.</h0></body></html>";
                    
                    mutex_unlock(&client->srs->mtx);
                                        
                    http_header_code(&os, 404);
                    http_header_host(&os, "localhost", 9);
                    http_header_date_now(&os);
                    http_header_content_length(&os, sizeof(error_404) - 1);
                    http_header_close(&os);
                    http_write_content(&os, error_404, sizeof(error_404) - 1);
                    
                    log_err("http: '%s': path not found", args.path);
                    
                    break;
                }
            }
            else
            {
                log_err("http: query '%s' not supported", line);
                break;
            }
        }
        else
        {
            char *name_end = strchr(line, ':');
            
            if(name_end == NULL)
            {
                log_err("http: cannot parse '%s'", line);
                break;
            }
            
            *name_end++ = '\0';
            
            const char *name = line;
            const char *value = parse_skip_spaces(name_end);
            
            ptr_node *node = ptr_set_insert(&args.query_name_value_set, (void*)name);
            if(node->value != NULL)
            {
                node->key = strdup(name);
                node->value = strdup(value);
            }
        }
    }
    
    ptr_set_callback_and_destroy(&args.uri_name_value_set, simple_rest_server_client_answer_destroy_callback);
    ptr_set_callback_and_destroy(&args.query_name_value_set, simple_rest_server_client_answer_destroy_callback);
    
    if(page != NULL)
    {
        simple_rest_server_page_release(client->srs, page);
    }
    
    output_stream_close(&os);
    input_stream_close(&is);
}

static void*
simple_rest_server_client_answer_thread(void *client_parm)
{
    simple_rest_server_client *client = (simple_rest_server_client*)client_parm;
    simple_rest_server_client_answer(client);
    simple_rest_server_client_delete(client);

    return NULL;
}

static int
simple_rest_server_main(struct service_worker_s *worker)
{
    simple_rest_server *srs = (simple_rest_server*)service_args_get(worker->service);
    
    if(FAIL(listen(srs->sockfd, SIMPLE_REST_SERVER_CLIENT_LISTEN_BACKLOG)))
    {
        return ERRNO_ERROR;
    }
    
    simple_rest_server_client *client = simple_rest_server_client_new_instance(srs);
    
    service_set_servicing(worker);
    
    while(service_should_run(worker))
    {
        int client_sockfd = accept(srs->sockfd, &client->sa.sa, &client->sa_len);
        
        if(client_sockfd < 0)
        {
            int err = errno;

#if EAGAIN != EWOULDBLOCK
            if(!((err == EINTR) || (err == EAGAIN) || (err == EWOULDBLOCK)))
            {
                log_err("failure to accept: %r", MAKE_ERRNO_ERROR(err));
            }
#else
            if(!((err == EINTR) || (err == EAGAIN)))
            {
                log_err("failure to accept: %r", MAKE_ERRNO_ERROR(err));
            }
#endif
            
            continue;
        }
        
        client->sockfd = client_sockfd;
        
        if(srs->thread_pool != NULL)
        {
            if(ISOK(thread_pool_try_enqueue_call(srs->thread_pool, simple_rest_server_client_answer_thread, client, NULL, "rest-client")))
            {
                client = simple_rest_server_client_new_instance(srs);
            }
            else
            {
                simple_rest_server_client_answer(client);
                
                simple_rest_server_client_reset(client);
            }
        }
        else
        {
            simple_rest_server_client_answer(client);
            
            simple_rest_server_client_reset(client);
        }
    }
    
    service_set_stopping(worker);
    
    simple_rest_server_client_delete(client); // do this first
    
    mutex_lock(&srs->mtx);
    while(srs->client_current_count > 0)
    {
        cond_timedwait(&srs->cond, &srs->mtx, ONE_SECOND_US); // 1 sec
    }
    mutex_unlock(&srs->mtx);
    
    return SUCCESS;
}

/** @} */

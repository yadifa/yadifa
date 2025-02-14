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

#include "dnscore/host_address.h"
#include "dnscore/tools.h"
#include "dnscore/logger.h"
#include "dnscore/input_stream.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/parsing.h"
#include "dnscore/bytearray_output_stream.h"
#include "dnscore/json.h"
#include "dnscore/rest_client.h"
#include "dnscore/timems.h"

logger_handle_t *g_rest_logger = LOGGER_HANDLE_SINK;
#define MODULE_MSG_HANDLE            g_rest_logger

#define REST_CLIENT_USER_AGENT       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
#define REST_CLIENT_CONNECTION_TRIES 3

static int g_rest_query_tries_count = REST_CLIENT_CONNECTION_TRIES;
static int g_rest_query_sleep_seconds = 1;

/**
 * Connects to the REST server using the scheme.
 * Queries it with the given command, path and arguments.
 * Returns the JSON answer.
 *
 * @param scheme the connection scheme (only URI_SCHEME_HTTP supported at the moment)
 * @param host the server address and port
 * @param command the command to use
 * @param encoded_path_and_args the path and arguments, percent-encoded
 * @param jsonp a pointer to a json that will be instantiated and initialised
 *
 * @return an error code
 *
 */

ya_result rest_query(uri_scheme_t scheme, host_address_t *host, http_query_command_t command, const char *encoded_path_and_args, json_t *jsonp)
{
    (void)scheme;
    input_stream_t  http_is;
    output_stream_t http_os;
    size_t          query_size;
    ya_result       ret;
    size_t          text_buffer_size = 4096;
    char           *text_buffer;
    char            key[64];
    char            value[256];
    char            server_and_port[256];

    if(FAIL(ret = host_address_to_str(host, server_and_port, sizeof(server_and_port), 0)))
    {
        return ret;
    }

    text_buffer = malloc(text_buffer_size);
    if(text_buffer == NULL)
    {
        return MAKE_ERRNO_ERROR(ENOMEM);
    }

    static const char *command_array[2] = {"GET", "POST"};

    snprintf(text_buffer,
             text_buffer_size,
             "%s %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: " REST_CLIENT_USER_AGENT
             "\r\n"
             "\r\n",
             command_array[command],
             encoded_path_and_args,
             server_and_port);
    query_size = strlen(text_buffer);
    // open a connection to the server address
    // send the stream
    // read the answer

    for(int i = g_rest_query_tries_count; i >= 0; --i)
    {
        ret = tcp_input_output_stream_connect_host_address_ex(host, &http_is, &http_os, NULL, 3);

        if(ISOK(ret))
        {
            break;
        }

        if(i == 0)
        {
            free(text_buffer);
            return ret;
        }

        usleep_ex(ONE_SECOND_US * g_rest_query_sleep_seconds);
    }

    output_stream_write_fully(&http_os, text_buffer, query_size);
    output_stream_flush(&http_os);

    // first line

    ret = input_stream_read_line(&http_is, text_buffer, text_buffer_size);
    if(ret <= 0)
    {
        free(text_buffer);
        input_stream_close(&http_is);
        return ret;
    }

    int  content_length = 0;
    bool transfer_encoding_chunked = false;

    // header begin

    for(;;)
    {
        ret = input_stream_read_line(&http_is, text_buffer, text_buffer_size);
        if(ret <= 0)
        {
            break;
        }

        if(ret <= 2)
        {
            break;
        }

        --ret;
        text_buffer[--ret] = '\0';

        char *p = text_buffer;
        key[0] = '\0';
        value[0] = '\0';

        int32_t key_len = parse_copy_next_word(key, sizeof(key), p);
        p += key_len;
        key[key_len - 1] = '\0';
        /*p += */ parse_copy_next_word(value, sizeof(value), p);

        // header = key: value

        if(strcmp(key, "Content-Length") == 0)
        {
            content_length = atoi(value);
        }
        else if(strcmp(key, "Transfer-Encoding") == 0)
        {
            if(strcmp(value, "chunked") == 0)
            {
                transfer_encoding_chunked = true;
            }
            else
            {
                log_err("rest_client: Transfer-Encoding '%s' not implemented", value);
            }
        }
    }

    // header end

    output_stream_t baos;
    bytearray_output_stream_init_ex(&baos, NULL, content_length, BYTEARRAY_DYNAMIC);

    // message begin

    if(transfer_encoding_chunked)
    {
        // hex\r\n
        // content\r\n
        // 0\r\n\r\n
        for(;;)
        {
            uint64_t chunk_len;

            if(ISOK(ret = input_stream_read_line(&http_is, text_buffer, text_buffer_size)))
            {
                ret = MAX(ret - 2, 0);
                if(ISOK(ret = parse_u64_check_range_len_base16(text_buffer, ret, &chunk_len, 0, 0x1000000))) // 16GB
                {
                    if(ISOK(ret = input_stream_to_output_stream_copy(&http_is, &baos, chunk_len)))
                    {
                        // read the CRLF
                        if(ISOK(ret = input_stream_read_line(&http_is, text_buffer, text_buffer_size)))
                        {
                            if(ret == 2)
                            {
                                if(chunk_len > 0)
                                {
                                    continue;
                                }
                                else
                                {
                                    break;
                                }
                            }
                            else
                            {
                                ret = PARSE_ERROR;
                            }
                        }
                    }
                }
            }

            // ret < 0

            free(text_buffer);
            input_stream_close(&http_is);
            output_stream_close(&baos);
            return ret;
        }
    }
    else
    {
        while(content_length > 0)
        {
            int n = MIN((int)text_buffer_size, content_length);
            ret = input_stream_read_fully(&http_is, text_buffer, n);
            if(FAIL(ret))
            {
                free(text_buffer);
                input_stream_close(&http_is);
                output_stream_close(&baos);
                return ret;
            }
            output_stream_write_fully(&baos, text_buffer, ret);
            flushout();
            content_length -= ret;
        }
    }

    // message end

    // the bytearray output stream contains the json message

    free(text_buffer);

    const char *json_message_text = (const char *)bytearray_output_stream_buffer(&baos);
    int         json_message_text_size = bytearray_output_stream_size(&baos);
    json_t      json = json_new_instance_from_buffer(json_message_text, json_message_text_size);

    if(json != NULL)
    {
        if(jsonp != NULL)
        {
            *jsonp = json;
        }
        else
        {
            json_delete(json);
        }

        return SUCCESS;
    }
    else
    {
        return INVALID_STATE_ERROR;
    }
}

/**
 * Connects to the REST server using the scheme.
 * Queries it with GET, path and arguments.
 * Returns the JSON answer.
 *
 * @param uri_text the full, unencoded, query
 * @param jsonp a pointer to a json that will be instantiated and initialised
 *
 * @return an error code
 *
 */

ya_result rest_query_uri(const char *uri_text, json_t *jsonp)
{
    uri_t     uri;
    ya_result ret;
    uint32_t  port = 80;
    if(FAIL(ret = uri_init_from_text(&uri, uri_text)))
    {
        return ret;
    }

    uri_scheme_t scheme = uri_scheme_get(&uri);

    if(scheme != URI_SCHEME_UNKNOWN)
    {
        host_address_t *ha;
        if((uri.port_text != NULL) && (strlen(uri.port_text) > 0))
        {
            if(FAIL(ret = parse_u32_check_range_len_base10(uri.port_text, strlen(uri.port_text), &port, 1, 65535)))
            {
                uri_finalise(&uri);
                return ret;
            }
        }
        if((ha = host_address_new_instance_parse_port(uri.host_text, port)) != NULL)
        {
            output_stream_t baos;
            bytearray_output_stream_init(&baos, NULL, 0);

            // encode the path
            output_stream_write_u8(&baos, '/');
            if(ISOK(ret = uri_encode_buffer(&baos, (const uint8_t *)uri.path_text, strlen(uri.path_text))))
            {
                if(!ptr_treemap_isempty(&uri.args))
                {
                    char arg_separator = '?';

                    ptr_treemap_iterator_t iter;
                    ptr_treemap_iterator_init(&uri.args, &iter);
                    while(ptr_treemap_iterator_hasnext(&iter))
                    {
                        output_stream_write_u8(&baos, arg_separator);
                        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
                        if(FAIL(ret = uri_encode_buffer(&baos, node->key, strlen(node->key))))
                        {
                            break;
                        }
                        output_stream_write_u8(&baos, '=');
                        if(FAIL(ret = uri_encode_buffer(&baos, node->value, strlen(node->value))))
                        {
                            break;
                        }
                        arg_separator = '&';
                    }
                }
                if(ISOK(ret))
                {
                    output_stream_write_u8(&baos, 0);
                    const char *path = (const char *)bytearray_output_stream_buffer(&baos);
                    ret = rest_query(scheme, ha, HTTP_QUERY_COMMAND_GET, path, jsonp);
                }
            }

            host_address_delete(ha);
        }
    }
    uri_finalise(&uri);
    return ret;
}

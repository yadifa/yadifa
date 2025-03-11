/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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

#include <dnscore/bytearray_output_stream.h>
#include <dnscore/parsing.h>
#include "dnscore/ptr_vector.h"
#include "dnscore/tools.h"
#include "dnscore/ptr_treemap.h"
#include "dnscore/uri.h"
#include "dnscore/utf8.h"
#include "dnscore/format.h"

static int uri_decode_hex_digit_to_int(char c)
{
    if(c >= '0' && c <= '9')
    {
        return c - '0';
    }
    c &= ~32; // [a-f] => [A-F] (and we don't care about any other value)
    if((c >= 'A') && (c <= 'F'))
    {
        return c - 'A' + 10;
    }
    return -1;
}

static ya_result uri_decode_encoding(const char *src, size_t src_size, output_stream_t *bytearray_os)
{
    int         index = bytearray_output_stream_size(bytearray_os);

    const char *src_limit = &src[src_size];

    for(; src < src_limit; ++src)
    {
        char c = *src;
        if(c == '%')
        {
            if(src_limit - src < 2)
            {
                break; // broken, skip the rest
            }

            int h = uri_decode_hex_digit_to_int(*++src);
            if(h < 0)
            {
                return DATA_FORMAT_ERROR; // broken, skip the rest
            }

            int l = uri_decode_hex_digit_to_int(*++src);
            if(l < 0)
            {
                return DATA_FORMAT_ERROR; // broken, skip the rest
            }

            c = (h << 4) | l;
        }

        output_stream_write_u8(bytearray_os, c);
    }

    output_stream_write_u8(bytearray_os, 0);

    return index;
}

/**
 * Decode a string in the form:
 *
 * WORD<spaces>/path/to/page?arg=val&arg=val
 *
 * Used by simple_http & rest_server
 *
 * For each arg=val, calls a callback with caller-defined args, the name and the value.
 *
 * @param text the string
 * @param text_limit a pointer right after the string
 * @param uri_callback the callback
 * @param args the caller-defined args
 *
 * @return an error code
 */

ya_result uri_path_decode(const char *text, const char *text_limit, ya_result (*uri_callback)(void *, const char *, const char *), void *args)
{
    output_stream_t baos;
    bytearray_output_stream_init_ex(&baos, NULL, text_limit - text, BYTEARRAY_DYNAMIC);

    // parse the URI page

    // find the start of the URI page

    const char *p = text;

    if(*p != '/') // skip the word if any
    {
        p = parse_next_blank(p);
        p = parse_skip_spaces(p);
    }

    while(*p == '/') // skip the first slash(es)
    {
        ++p;
    }

    // find the end of the URI page

    const char *param0;
    param0 = strchr(text, '?');

    // if no parameter mark was found, set the param0 to the end of the string

    if(param0 == NULL)
    {
        param0 = text_limit;
    }

    // get the current position in the buffer (0) and write the page
    int page_index = uri_decode_encoding(p, param0 - p, &baos);

    if(FAIL(page_index))
    {
        output_stream_close(&baos);
        return page_index;
    }

    const char *buffer = (const char *)bytearray_output_stream_buffer(&baos);
    const char *page = &buffer[page_index];

    uri_callback(args, page, NULL); // page already ends with '\0'

    // if there is no parameter to parse, return

    if(param0 == text_limit)
    {
        output_stream_close(&baos);
        return SUCCESS;
    }

    // the page isn't required anymore

    page = NULL; // ensure the program will crash if page is used

    ya_result ret;

    ++param0;

    // decode all the '&'-separated name=value

    const char *name = param0;

    for(;;)
    {
        bytearray_output_stream_reset(&baos);

        // find the end of the parameter name

        const char *value = strchr(name, '=');
        if(value == NULL)
        {
            output_stream_close(&baos);
            return DATA_FORMAT_ERROR;
        }

        size_t name_len = value - name;

        ++value;

        int name_index = uri_decode_encoding(name, name_len, &baos);

        if(FAIL(name_index))
        {
            output_stream_close(&baos);
            return name_index;
        }

        size_t      value_len;

        const char *name_next = strchr(value, '&');

        if(name_next == NULL)
        {
            value_len = text_limit - value;
        }
        else
        {
            value_len = name_next - value;
        }

        int value_index = uri_decode_encoding(value, value_len, &baos);

        if(FAIL(value_index))
        {
            output_stream_close(&baos);
            return value_index;
        }

        buffer = (const char *)bytearray_output_stream_buffer(&baos);

        const char *decoded_name = &buffer[name_index];
        const char *decoded_value = &buffer[value_index];

        if(FAIL(ret = uri_callback(args, decoded_name, decoded_value)))
        {
            output_stream_close(&baos);
            return ret;
        }

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
 * Decomposes a string in the form:
 *
 * "http://login@host:port/path?arg0=val0&arg1=val1&&arg2=val2"
 *
 * into an uri_t.
 *
 * @param uri an uninitialised uri_t
 * @param uri_text a string in the correct form
 *
 * @return an error code
 */

ya_result uri_init_from_text(uri_t *uri, const char *uri_text)
{
    memset(uri, 0, sizeof(uri_t));
    ptr_treemap_init(&uri->args);
    uri->args.compare = ptr_treemap_asciizp_node_compare;

    const char *p = uri_text;
    p = parse_skip_spaces(p);
    const char *scheme_begin = p;
    p = parse_skip_until_chars(p, ":", 1);
    if(*p == '\0')
    {
        return PARSE_ERROR;
    }
    const char *scheme_end = p;

    if(memcmp(p, "://", 3) != 0)
    {
        return PARSE_ERROR;
    }

    p += 3;

    const char *userinfo_or_host_start = p;
    p = parse_skip_until_chars(p, "@:/?", 4);

    const char *user_begin = NULL;
    const char *user_end = NULL;
    const char *host_begin = NULL;
    const char *host_end = NULL;
    const char *port_begin = NULL;
    const char *port_end = NULL;
    const char *path_begin = NULL;
    const char *path_end = NULL;

    if(*p != '@') // ':' or '/' (or '\0')
    {
        host_begin = userinfo_or_host_start;
    }
    else
    {
        user_begin = userinfo_or_host_start;
        user_end = p;
        ++p;
        host_begin = p;
    }
    p = parse_skip_until_chars(p, ":/?", 3);
    host_end = p;
    if(*p == ':')
    {
        ++p;
        port_begin = p;
        p = parse_skip_until_chars(p, "/?", 2);
        port_end = p;
    }
    if(*p == '/')
    {
        // there is a path to parse
        ++p;
        path_begin = p;
        p = parse_skip_until_chars(p, "?", 1);
        path_end = p;
    }
    if(*p == '?')
    {
        // there are args to parse
        do
        {
            ++p;
            const char *key_begin = p;
            p = parse_skip_until_chars(p, "=&", 2);
            const char *key_end = p;
            const char *val_begin = NULL;
            const char *val_end = NULL;
            if(*p == '=')
            {
                ++p;
                val_begin = p;
                p = parse_skip_until_chars(p, "&", 1);
                val_end = p;
            }
            char *key_text = memdup(key_begin, key_end - key_begin + 1);
            key_text[key_end - key_begin] = '\0';
            char *val_text = memdup(val_begin, val_end - val_begin + 1);
            val_text[val_end - val_begin] = '\0';
            ptr_treemap_node_t *node = ptr_treemap_insert(&uri->args, key_text);
            if(node->key == key_text)
            {
                node->value = val_text;
            }
            else // duplicate
            {
                free(key_text);
                free(val_text);
            }
        } while(*p == '&');
    }

    uri->scheme_text = memdup(scheme_begin, scheme_end - scheme_begin + 1);
    uri->scheme_text[scheme_end - scheme_begin] = '\0';
    uri->user_text = memdup(user_begin, user_end - user_begin + 1);
    uri->user_text[user_end - user_begin] = '\0';
    uri->host_text = memdup(host_begin, host_end - host_begin + 1);
    uri->host_text[host_end - host_begin] = '\0';
    uri->port_text = memdup(port_begin, port_end - port_begin + 1);
    uri->port_text[port_end - port_begin] = '\0';
    uri->path_text = memdup(path_begin, path_end - path_begin + 1);
    uri->path_text[path_end - path_begin] = '\0';
    return 0;
}

static void uri_finalise_callback(ptr_treemap_node_t *node)
{
    free(node->key);
    free(node->value);
}

/**
 * Releases the memory allocated in an initialised uri.
 *
 * @param uri an initialised uri_t
 */

void uri_finalise(uri_t *uri)
{
    free(uri->scheme_text);
    uri->scheme_text = NULL;
    free(uri->user_text);
    uri->user_text = NULL;
    free(uri->host_text);
    uri->host_text = NULL;
    free(uri->port_text);
    uri->port_text = NULL;
    free(uri->path_text);
    uri->path_text = NULL;
    ptr_treemap_callback_and_finalise(&uri->args, uri_finalise_callback);
}

/**
 * Returns the scheme of an URI
 *
 * @param uri an initialised uri_t
 *
 * @return a scheme
 */

uri_scheme_t uri_scheme_get(const uri_t *uri)
{
    if(strcasecmp(uri->scheme_text, "http") == 0)
    {
        return URI_SCHEME_HTTP;
    }
    if(strcasecmp(uri->scheme_text, "https") == 0)
    {
        return URI_SCHEME_HTTPS;
    }
    return URI_SCHEME_UNKNOWN;
}

/**
 * Percent-encode the given UTF-8 buffer to the output_stream_t
 *
 * @param os the output_stream_t
 * @param buffer the UTF-8 encoded text
 * @param buffer_size the size of the text
 *
 * @return an error code
 */

ya_result uri_encode_buffer(output_stream_t *os, const uint8_t *buffer, size_t buffer_size)
{
    const uint8_t *buffer_limit = buffer + buffer_size;
    ya_result      ret = SUCCESS;
    while(buffer < buffer_limit)
    {
        uint32_t char_value;
        int      char_len = utf8_next_char32(buffer, &char_value);
        if(char_len > 0)
        {
            if(!((char_value >= 0x21) && (char_value <= 0x5d)))
            {
                if(FAIL(ret = output_stream_write(os, buffer, char_len)))
                {
                    return ret;
                }
            }
            else
            {
                uint64_t bit = 1ULL << (char_value - 0x20);
                // https://en.wikipedia.org/wiki/Percent-encoding
                //    5    5    5    5    4    4    4    4    3    3    3    3    2    2    2    2
                //    c    8    4    0    c    8    4    0    c    8    4    0    c    8    4    0
                // 0010 1000 0000 0000 0000 0000 0000 0001 1010 1100 0000 0000 1001 1111 1101 1010

                const uint64_t reserved_bit_mask = 0x28000001ac009fdaULL;

                if((bit & reserved_bit_mask) == 0)
                {
                    if(FAIL(ret = output_stream_write(os, buffer, char_len)))
                    {
                        return ret;
                    }
                }
                else
                {
                    // percent-encode
                    if(FAIL(ret = output_stream_write_u8(os, '%')))
                    {
                        return ret;
                    }
                    format_hex_u64_hi(char_value, os, 2, '0', false);
                }
            }
            buffer += char_len;
        }
    }
    return ret;
}

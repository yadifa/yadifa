/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
#include <dnscore/sys_types.h>
#include <dnscore/ptr_treemap.h>

/**
 * Decode a string in the form:
 *
 * WORD<spaces>/path/to/page?arg=val&arg=val
 *
 * Used by simple_http & rest_server
 *
 * Calls a callback with caller-defined-args, the path/to/page and NULL
 *
 * Then, for each arg=val, calls a callback with caller-defined args, the name and the value.
 *
 * @param text the string
 * @param text_limit a pointer right after the string
 * @param uri_callback the callback
 * @param args the caller-defined args
 *
 * @return an error code
 */

ya_result uri_path_decode(const char *text, const char *text_limit, ya_result (*uri_callback)(void *, const char *, const char *), void *args);

struct uri_s
{
    char         *scheme_text;
    char         *user_text;
    char         *host_text;
    char         *port_text;
    char         *path_text;
    ptr_treemap_t args; // nodes are name->value
};

typedef struct uri_s uri_t;

enum uri_scheme_e
{
    URI_SCHEME_HTTP = 0,
    URI_SCHEME_HTTPS = 1,
    URI_SCHEME_UNKNOWN = 2
};

typedef enum uri_scheme_e uri_scheme_t;

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

ya_result uri_init_from_text(uri_t *uri, const char *uri_text);

/**
 * Releases the memory allocated in an initialised uri.
 *
 * @param uri an initialised uri_t
 */

void uri_finalise(uri_t *uri);

/**
 * Returns the scheme of an URI
 *
 * @param uri an initialised uri_t
 *
 * @return a scheme
 */

uri_scheme_t uri_scheme_get(const uri_t *uri);

/**
 * Percent-encode the given UTF-8 buffer to the output_stream_t
 *
 * @param os the output_stream_t
 * @param buffer the UTF-8 encoded text
 * @param buffer_size the size of the text
 *
 * @return an error code
 */

ya_result uri_encode_buffer(output_stream_t *os, const uint8_t *buffer, size_t buffer_size);

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
#include <dnscore/uri.h>
#include <dnscore/json.h>

#define DNSCORE_REST_HAS_HTTPS 0

enum http_query_command_e
{
    HTTP_QUERY_COMMAND_GET = 0,
    HTTP_QUERY_COMMAND_POST = 1
};

typedef enum http_query_command_e http_query_command_t;

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

ya_result rest_query(uri_scheme_t scheme, host_address_t *host, http_query_command_t command, const char *encoded_path_and_args, json_t *jsonp);

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

ya_result rest_query_uri(const char *uri_text, json_t *jsonp);

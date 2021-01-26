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

#include <dnscore/sys_types.h>
#include <dnscore/output_stream.h>

#if !JSON_C_
union json {intptr type;};
#endif

typedef union json* json;

enum json_type
{
    JSON_ARRAY = 0,
    JSON_OBJECT,
    JSON_STRING,
    JSON_NUMBER,
    JSON_BOOLEAN
};

json json_object_new_instance();

json json_array_new_instance();

json json_string_new_instance();

json json_number_new_instance();

json json_boolean_new_instance();

enum json_type json_type_get(const json j);

bool json_boolean_get(const json j);

void json_boolean_set(json j, bool value);

double json_number_get(const json j);

void json_number_set(json j, double value);

const char * json_string_get(const json j);

size_t json_string_size_get(const json j);

void json_string_set(json j, const char *text);

json json_array_get(json j, size_t index);

void json_array_add(const json j, json item);

static inline void json_array_add_boolean(const json j, bool value)
{
    json boolean = json_boolean_new_instance();
    json_boolean_set(boolean, value);
    json_array_add(j, boolean);
}

static inline void json_array_add_number(const json j, double value)
{
    json number = json_number_new_instance();
    json_number_set(number, value);
    json_array_add(j, number);
}

static inline void json_array_add_string(const json j, const char *text)
{
    json string = json_string_new_instance();
    json_string_set(string, text);
    json_array_add(j, string);
}

json json_object_get(json j, const char *name);

bool json_object_add(const json j, const char *key, json item);

static inline void json_object_add_boolean(const json j, const char* key, bool value)
{
    json boolean = json_boolean_new_instance();
    json_boolean_set(boolean, value);
    json_object_add(j, key, boolean);
}

static inline void json_object_add_number(const json j, const char* key, double value)
{
    json number = json_number_new_instance();
    json_number_set(number, value);
    json_object_add(j, key, number);
}

static inline void json_object_add_string(const json j, const char* key, const char *text)
{
    json string = json_string_new_instance();
    json_string_set(string, text);
    json_object_add(j, key, string);
}

ya_result json_write_to(json j, output_stream *os);

ya_result json_size(json j);

void json_delete(json j);

/** @} */

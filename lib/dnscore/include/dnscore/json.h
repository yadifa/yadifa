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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <dnscore/sys_types.h>
#include <dnscore/output_stream.h>
#include <dnscore/input_stream.h>

#if !JSON_C_
union json_u
{
    intptr_t type;
};
typedef union json_u *json_t;
#endif

#define JSON_KEY_LENGTH_MAX 256

#include <dnscore/json_type.h>
#include "bytearray_input_stream.h"
#include "ptr_vector.h"

json_t             json_object_new_instance();

json_t             json_array_new_instance_ex(uint32_t capacity);

json_t             json_array_new_instance();

json_t             json_string_new_instance();

json_t             json_number_new_instance();

json_t             json_boolean_new_instance();

enum json_type     json_type_get(const json_t j);

bool               json_boolean_get(const json_t j);

ya_result          json_boolean_get_bool(const json_t j, bool *value);

void               json_boolean_set(json_t j, bool value);

double             json_number_as_double(const json_t j);

int64_t            json_number_as_s64(const json_t j);

ya_result          json_number_get_double(const json_t j, double *value);

ya_result          json_number_get_s64(const json_t j, int64_t *value);

ya_result          json_number_get_s32(const json_t j, int32_t *value);

ya_result          json_number_get_double_array(const json_t j, double *array, size_t length);

void               json_number_set_double(json_t j, double value);

void               json_number_set_s64(json_t j, int64_t value);

const char        *json_string_get(const json_t j);

size_t             json_string_size_get(const json_t j);

void               json_string_set(json_t j, const uint8_t *text);

json_t             json_array_get(const json_t j, size_t index);

int32_t            json_array_size(json_t j);

void               json_array_add(json_t j, json_t item);

static inline void json_array_add_boolean(json_t j, bool value)
{
    json_t boolean = json_boolean_new_instance();
    json_boolean_set(boolean, value);
    json_array_add(j, boolean);
}

static inline void json_array_add_number(json_t j, double value)
{
    json_t number = json_number_new_instance();
    json_number_set_double(number, value);
    json_array_add(j, number);
}

static inline void json_array_add_string(json_t j, const uint8_t *text)
{
    json_t string = json_string_new_instance();
    json_string_set(string, text);
    json_array_add(j, string);
}

json_t             json_object_get(const json_t j, const char *name);

void               json_object_add(json_t j, const uint8_t *key, json_t item);

static inline void json_object_add_boolean(const json_t j, const uint8_t *key, bool value)
{
    json_t boolean = json_boolean_new_instance();
    json_boolean_set(boolean, value);
    json_object_add(j, key, boolean);
}

static inline void json_object_add_number_double(const json_t j, const uint8_t *key, double value)
{
    json_t number = json_number_new_instance();
    json_number_set_double(number, value);
    json_object_add(j, key, number);
}

static inline void json_object_add_number_s64(const json_t j, const uint8_t *key, int64_t value)
{
    json_t number = json_number_new_instance();
    json_number_set_s64(number, value);
    json_object_add(j, key, number);
}

static inline void json_object_add_string(const json_t j, const uint8_t *key, const uint8_t *text)
{
    json_t string = json_string_new_instance();
    json_string_set(string, text);
    json_object_add(j, key, string);
}

static inline void json_object_add_ascii_string(const json_t j, const char *key, const char *text)
{
    json_t string = json_string_new_instance();
    json_string_set(string, (const uint8_t *)text);
    json_object_add(j, (const uint8_t *)key, string);
}

ya_result json_write_to(json_t j, output_stream_t *os);

ya_result input_stream_read_json(input_stream_t *is, json_t *jp);

/**
 * Avoid using this function directly.
 *
 * Note: this function is used in the distance project.
 */

static inline ya_result json_read_from(input_stream_t *is, json_t *jp) { return input_stream_read_json(is, jp); }

static inline json_t    json_new_instance_from_stream(input_stream_t *is)
{
    json_t json = NULL;
    input_stream_read_json(is, &json);
    return json;
}

static inline json_t json_new_instance_from_buffer(const char *text, size_t text_size)
{
    input_stream_t bais;
    bytearray_input_stream_init(&bais, text, text_size, false);
    json_t json = NULL;
    input_stream_read_json(&bais, &json);
    input_stream_close(&bais);
    return json;
}

ya_result json_size(json_t j);

/**
 * Recursively delete all the json.
 */

void json_delete(json_t j);

/**
 * Serialises the json into an allocated buffer.
 */

char *json_to_string(json_t j);

/**
 * Creates a deep clone from a json_t
 *
 * @param json the json to deep clone
 *
 * @return a cloned json or NULL if an error occurred.
 */

json_t json_clone(json_t json);

/**
 * Gets the json_t at the relative path position from the json.
 *
 * Path are a concatenation of keys and indexes separated by '/'
 *
 * e.g. key_of_array_in_object/1234/key_of_object_at_position_1234_in_array
 *
 * @param json the object to start from
 * @param path the path string
 * @param path_size the path string length
 * @param json_itemp at pointer that will receive the found json item if any
 *
 * @return an error code
 */

ya_result json_get_from_path_buffer(json_t json, const char *path, int path_size, json_t *json_itemp);

/**
 * Iterates through all items in the json.
 * Calls the callback with the json item and a ptr_vector_t stack of all the parent items.
 *
 * If the callback returns an error, the iteration stops.
 *
 * @param json the json to iterate trough
 * @param json_for_all_callback the callback
 *
 * @return an error code.
 */

ya_result json_for_all(json_t json, ya_result (*json_for_all_callback)(json_t json, void *args, ptr_vector_t *json_stack), void *args);

/**
 * Gets the json_t at the relative path position from the json.
 *
 * Path are a concatenation of keys and indexes separated by '/'
 *
 * e.g. key_of_array_in_object/1234/key_of_object_at_position_1234_in_array
 *
 * @param json the object to start from
 * @param path the path string
 * @param json_itemp at pointer that will receive the found json item if any
 *
 * @return an error code
 */

ya_result json_get_from_path(json_t json, const char *path, json_t *json_itemp);

/**
 * Exchange two JSON values,
 * keeping parents intact as only internals of the objects are updated.
 *
 * @param json exchange with
 * @param what_with exchanged with
 */

void json_exchange(json_t json, json_t what_with);

/** @} */

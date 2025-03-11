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
#include "dnscore/dnscore_config.h"

#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>

#define JSON_C_ 1

#include "dnscore/sys_types.h"
#include "dnscore/ptr_treemap.h"
#include "dnscore/ptr_vector.h"
#include "dnscore/zalloc.h"
#include "dnscore/format.h"
#include "dnscore/json_type.h"

#define JSON_TAG 0x4e4f534a

struct json_value_array_s
{
    intptr_t     type;
    ptr_vector_t array;
};

struct json_value_object_s
{
    intptr_t      type;
    ptr_treemap_t map;
};

struct json_value_string_s
{
    intptr_t type;
    uint8_t *utf8_text;
    size_t   utf8_text_size;
};

struct json_value_number_s
{
    intptr_t type;
    char    *value_text;
    bool     floating;
};

struct json_value_bool_s
{
    intptr_t type;
    bool     value;
};

union json_u
{
    enum json_type             type;
    struct json_value_bool_s   boolean;
    struct json_value_number_s number;
    struct json_value_string_s string;
    struct json_value_array_s  array;
    struct json_value_object_s map;
};

typedef union json_u *json_t;

#include "dnscore/json.h"
#include "dnscore/utf8.h"
#include "dnscore/pushback_input_stream.h"
#include "dnscore/bytearray_output_stream.h"
#include "dnscore/parsing.h"

static json_t json_type_new_intance(enum json_type type)
{
    json_t ret;
    ZALLOC_OBJECT_OR_DIE(ret, union json_u, JSON_TAG);
    ret->type = type;
    return ret;
}

json_t json_object_new_instance()
{
    json_t ret = json_type_new_intance(JSON_OBJECT);
    ptr_treemap_init(&ret->map.map);
    ret->map.map.compare = ptr_treemap_asciizp_node_compare;
    return ret;
}

json_t json_array_new_instance_ex(uint32_t capacity)
{
    json_t ret = json_type_new_intance(JSON_ARRAY);
    ptr_vector_init_ex(&ret->array.array, capacity);
    return ret;
}

json_t json_array_new_instance()
{
    json_t ret = json_type_new_intance(JSON_ARRAY);
    ptr_vector_init(&ret->array.array);
    return ret;
}

json_t json_string_new_instance()
{
    json_t ret = json_type_new_intance(JSON_STRING);
    ret->string.utf8_text = NULL;
    ret->string.utf8_text_size = 0;
    return ret;
}

json_t json_number_new_instance()
{
    json_t ret = json_type_new_intance(JSON_NUMBER);
    ret->number.value_text = NULL;
    ret->number.floating = false;
    return ret;
}

json_t json_boolean_new_instance()
{
    json_t ret = json_type_new_intance(JSON_BOOLEAN);
    ret->boolean.value = false;
    return ret;
}

enum json_type json_type_get(const json_t j) { return j->type; }

bool json_boolean_get(const json_t j)
{
    yassert(j->type == JSON_BOOLEAN);
    return j->boolean.value;
}

ya_result json_boolean_get_bool(const json_t j, bool *value)
{
    if(j->type == JSON_BOOLEAN)
    {
        *value = j->boolean.value;
        return SUCCESS;
    }
    else
    {
        return INVALID_ARGUMENT_ERROR;
    }
}

void json_boolean_set(json_t j, bool value)
{
    yassert(j->type == JSON_BOOLEAN);
    j->boolean.value = value;
}

double json_number_as_double(const json_t j)
{
    yassert(j->type == JSON_NUMBER);
    double ret;
    ret = strtod(j->number.value_text, NULL);
    return ret;
}

int64_t json_number_as_s64(const json_t j)
{
    yassert(j->type == JSON_NUMBER);
    long long ret;
    ret = strtoll(j->number.value_text, NULL, 10);
    return ret;
}

ya_result json_number_get_double(const json_t j, double *value)
{
    if(j->type == JSON_NUMBER)
    {
        double parsed_value;
        errno = 0;
        parsed_value = strtod(j->number.value_text, NULL);
        int err = errno;
        if(err == 0)
        {
            *value = parsed_value;
            return SUCCESS;
        }
        else
        {
            return MAKE_ERRNO_ERROR(err);
        }
    }
    else
    {
        return INVALID_ARGUMENT_ERROR;
    }
}

ya_result json_number_get_s64(const json_t j, int64_t *value)
{
    if(j->type == JSON_NUMBER)
    {
        long long parsed_value;
        parsed_value = strtoll(j->number.value_text, NULL, 10);
        int err = errno;
        if(err == 0)
        {
            *value = parsed_value;
            return SUCCESS;
        }
        else
        {
            return MAKE_ERRNO_ERROR(err);
        }
    }
    else
    {
        return INVALID_ARGUMENT_ERROR;
    }
}

ya_result json_number_get_s32(const json_t j, int32_t *value)
{
    if(j->type == JSON_NUMBER)
    {
        long parsed_value;
        parsed_value = strtol(j->number.value_text, NULL, 10);
        int err = errno;
        if(err == 0)
        {
            *value = parsed_value;
            return SUCCESS;
        }
        else
        {
            return MAKE_ERRNO_ERROR(err);
        }
    }
    else
    {
        return INVALID_ARGUMENT_ERROR;
    }
}

ya_result json_number_get_double_array(const json_t j, double *array, size_t length)
{
    if((j != NULL) && (json_type_get(j) == JSON_ARRAY))
    {
        for(size_t i = 0; i < length; ++i)
        {
            json_t value = json_array_get(j, i);

            if(value == NULL)
            {
                return INVALID_STATE_ERROR;
            }

            ya_result ret = json_number_get_double(value, &array[i]);
            if(FAIL(ret))
            {
                break;
            }
        }
        return 0;
    }
    return INVALID_ARGUMENT_ERROR;
}


void json_number_set_double(json_t j, double value)
{
    yassert(j->type == JSON_NUMBER);
    char *tmp;
    asformat(&tmp, "%lf", value);
    j->number.value_text = tmp;
    j->number.floating = true;
}

void json_number_set_s64(json_t j, int64_t value)
{
    yassert(j->type == JSON_NUMBER);
    char *tmp;
    asformat(&tmp, "%lli", value);
    j->number.value_text = tmp;
    j->number.floating = true;
}

static void json_number_set_text(json_t j, char *text, int text_len)
{
    yassert(j->type == JSON_NUMBER);
    char *tmp = (char *)malloc(text_len + 1);
    if(tmp == NULL)
    {
        abort();
    }
    memcpy(tmp, text, text_len);
    tmp[text_len] = '\0';
    j->number.value_text = tmp;
    j->number.floating = true;
}

size_t json_string_size_get(const json_t j)
{
    yassert(j->type == JSON_STRING);
    return j->string.utf8_text_size;
}

const char *json_string_get(const json_t j)
{
    yassert(j->type == JSON_STRING);
    return (const char *)j->string.utf8_text;
}

void json_string_set(json_t j, const uint8_t *text)
{
    yassert(j->type == JSON_STRING);
    j->string.utf8_text = (uint8_t *)strdup((const char *)text);
    j->string.utf8_text_size = strlen((const char *)text);
}

void json_string_set_uchar_array(json_t j, uchar_t *text, size_t text_len)
{
    yassert(j->type == JSON_STRING);
    size_t   size = utf8_encoded_text_len(text, text_len);
    uint8_t *encoded_text = (uint8_t *)malloc(size + 1); // + 1 for the NUL terminator
    if(encoded_text == NULL)
    {
        abort();
    }
    utf8_encode_text(text, text_len, encoded_text);
    j->string.utf8_text = encoded_text;
    j->string.utf8_text_size = text_len;
}

json_t json_array_get(const json_t j, size_t index)
{
    yassert(j->type == JSON_ARRAY);
    if((int)index <= ptr_vector_last_index(&j->array.array))
    {
        json_t json_item = (json_t)ptr_vector_get(&j->array.array, (uint32_t)index);
        return json_item;
    }
    else
    {
        return NULL;
    }
}

int32_t json_array_size(json_t j)
{
    yassert(j->type == JSON_ARRAY);
    return ptr_vector_size(&j->array.array);
}

void json_array_add(json_t j, json_t item)
{
    yassert(j->type == JSON_ARRAY);
    ptr_vector_append(&j->array.array, item);
}

json_t json_object_get(const json_t j, const char *name)
{
    yassert(j->type == JSON_OBJECT);
    ptr_treemap_node_t *node = ptr_treemap_find(&j->map.map, name);
    if(node != NULL && node->value != NULL)
    {
        return (json_t)node->value;
    }
    else
    {
        return NULL;
    }
}

void json_object_add(json_t j, const uint8_t *key, json_t item)
{
    yassert(j->type == JSON_OBJECT);
    ptr_treemap_node_t *node = ptr_treemap_insert(&j->map.map, (void *)key);
    if(node->value != NULL)
    {
        json_t old_item = (json_t)node->value;
        json_delete(old_item);
    }
    node->key = strdup((const char *)key);
    node->value = item;
}

ya_result json_write_to(json_t j, output_stream_t *os);

struct json_write_forall_callback_args
{
    output_stream_t *os;
    ya_result        ret;
    bool             comma;
};

#define ESCAPE_MASK_LO ((1ULL << 9) | (1ULL << 10) | (1ULL << 13) | (1ULL << 0x22))

static char json_escape_char_table[0x60] = {
    // 0    1    2    3    4    5    6    7    8    9    a    b    c    d    e    f
    0, 0, 0,   0, 0, 0, 0, 0, 0, 't', 'n', 0, 0,    'r', 0, 0, // 0
    0, 0, 0,   0, 0, 0, 0, 0, 0, 0,   0,   0, 0,    0,   0, 0, // 1
    0, 0, '"', 0, 0, 0, 0, 0, 0, 0,   0,   0, 0,    0,   0, 0, // 2
    0, 0, 0,   0, 0, 0, 0, 0, 0, 0,   0,   0, 0,    0,   0, 0, // 3
    0, 0, 0,   0, 0, 0, 0, 0, 0, 0,   0,   0, 0,    0,   0, 0, // 4
    0, 0, 0,   0, 0, 0, 0, 0, 0, 0,   0,   0, '\\', 0,   0, 0, // 5
};

ya_result json_write_escaped_string(output_stream_t *os, const uint8_t *text, int text_size)
{
    ya_result ret;
    int       escape_count = 0;

    if((ret = output_stream_write(os, "\"", 1)) == 1)
    {
        const uint8_t *limit = text + text_size;
        for(const uint8_t *p = text; p < limit;)
        {
            uchar_t c;
            int     char_len = utf8_next_uchar(p, &c);

            char    escape_char;
            if(!(c <= 0x5c && ((escape_char = json_escape_char_table[c]) != 0)))
            {
                if(FAIL(ret = output_stream_write(os, p, char_len)))
                {
                    break;
                }
                p += char_len;
            }
            else
            {
                if(FAIL(ret = output_stream_write_u8(os, '\\')))
                {
                    break;
                }
                ++escape_count;
                if(FAIL(ret = output_stream_write_u8(os, escape_char)))
                {
                    break;
                }
                ++p;
            }
        }

        if(ISOK(ret))
        {
            ret = output_stream_write(os, "\"", 1);

            if(ISOK(ret))
            {
                ret = text_size + escape_count + 2;
            }
        }
    }
    return ret;
}

static int json_write_forall_callback(ptr_treemap_node_t *node, void *args_)
{
    struct json_write_forall_callback_args *args = (struct json_write_forall_callback_args *)args_;
    output_stream_t                        *os = args->os;
    ya_result                               ret = 0;
    int                                     total = 0;

    if(args->comma)
    {
        if(FAIL(ret = output_stream_write(os, ",", 1)))
        {
            args->ret = ret;
            return ret;
        }
        total = 1;
    }

    ret = json_write_escaped_string(os, node->key, strlen(node->key));

    if(ISOK(ret))
    {
        total += ret;

        static const char json_object_kv_separator[] = {':', ' '};

        ret = output_stream_write(os, json_object_kv_separator, sizeof(json_object_kv_separator));

        if(ISOK(ret))
        {
            total += ret;

            if(ISOK(ret = json_write_to((json_t)node->value, os)))
            {
                ret = total + ret + args->ret;
                args->comma = true;
            }
        }
    }

    args->ret = ret;

    return ret;
}

ya_result json_write_to(json_t j, output_stream_t *os)
{
    ya_result ret;
    if(j != NULL)
    {
        switch(j->type)
        {
            case JSON_BOOLEAN:
            {
                if(j->boolean.value)
                {
                    ret = output_stream_write(os, "true", 4);
                }
                else
                {
                    ret = output_stream_write(os, "false", 5);
                }
                break;
            }
            case JSON_NUMBER:
            {
                ret = output_stream_write(os, j->number.value_text, strlen(j->number.value_text));
                break;
            }
            case JSON_STRING:
            {
                ret = json_write_escaped_string(os, j->string.utf8_text, j->string.utf8_text_size);
                break;
            }
            case JSON_ARRAY:
            {
                ya_result t = 1;
                ret = output_stream_write_u8(os, '[');

                if(ISOK(ret))
                {
                    int last_index = ptr_vector_last_index(&j->array.array);

                    if(last_index >= 0)
                    {
                        if(ISOK(ret = json_write_to((json_t)ptr_vector_get(&j->array.array, 0), os)))
                        {
                            t += ret;

                            for(int_fast32_t i = 1; i <= last_index; ++i)
                            {
                                if(FAIL(ret = output_stream_write_u8(os, ',')))
                                {
                                    break;
                                }

                                if(FAIL(ret = json_write_to((json_t)ptr_vector_get(&j->array.array, i), os)))
                                {
                                    break;
                                }

                                t += ret;
                            }

                            t += last_index; // for the commas

                            if(ISOK(ret))
                            {
                                if(ISOK(ret = output_stream_write_u8(os, ']')))
                                {
                                    ret += t;
                                }
                            }
                        }
                    }
                    else
                    {
                        if(ISOK(ret = output_stream_write_u8(os, ']')))
                        {
                            ret += t;
                        }
                    }
                }

                break;
            }
            case JSON_OBJECT:
            {
                ret = output_stream_write_u8(os, '{');

                if(ISOK(ret))
                {
                    struct json_write_forall_callback_args args = {os, 2, false};

                    ptr_treemap_forall(&j->map.map, json_write_forall_callback, &args);

                    if(ISOK(args.ret))
                    {
                        if(ISOK(ret = output_stream_write_u8(os, '}')))
                        {
                            ret = args.ret;
                        }
                    }
                }

                break;
            }
            default:
            {
                ret = INVALID_STATE_ERROR;
                break;
            }
        } // switch(j->type)
    }
    else
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    return ret;
}

#if UNUSED
static ya_result json_read_next_char_skip_blanks(input_stream_t *is, uchar_t *cp)
{
    ya_result ret;
    for(;;)
    {
        ret = utf8_next_uchar_from_stream(is, cp);
        if(ret <= 0)
        {
            return ret;
        }
        uchar_t c = *cp;
        if((c == '\t') || (c == '\n') || (c == '\r') || (c == ' '))
        {
            continue;
        }
        return ret;
    }
}
#endif

static ya_result json_expect_next_char_skip_blanks(input_stream_t *is, uchar_t *cp)
{
    ya_result ret;
    for(;;)
    {
        ret = utf8_next_uchar_from_stream(is, cp);
        if(ret <= 0)
        {
            if(ret == 0)
            {
                ret = UNEXPECTED_EOF;
            }
            return ret;
        }
        uchar_t c = *cp;
        if((c == '\t') || (c == '\n') || (c == '\r') || (c == ' '))
        {
            continue;
        }
        return ret;
    }
}

static ya_result json_expect_next_char_equals_skip_blanks(input_stream_t *is, uchar_t expected_c)
{
    ya_result ret;
    uchar_t   c;
    for(;;)
    {
        ret = utf8_next_uchar_from_stream(is, &c);
        if(ret <= 0)
        {
            if(ret == 0)
            {
                ret = UNEXPECTED_EOF;
            }
            return ret;
        }
        if((c == '\t') || (c == '\n') || (c == '\r') || (c == ' '))
        {
            continue;
        }
        if(c == expected_c)
        {
            return ret;
        }
        else
        {
            return PARSE_ERROR;
        }
    }
}

static ya_result json_expect_next_char(input_stream_t *is, uchar_t *cp)
{
    ya_result ret;

    ret = utf8_next_uchar_from_stream(is, cp);
    if(ret <= 0)
    {
        if(ret == 0)
        {
            ret = UNEXPECTED_EOF;
        }
        return ret;
    }

    return ret;
}

static ya_result json_expect_next_char_equals(input_stream_t *is, uchar_t expected_c)
{
    ya_result ret;
    uchar_t   c;

    ret = utf8_next_uchar_from_stream(is, &c);
    if(ret <= 0)
    {
        if(ret == 0)
        {
            ret = UNEXPECTED_EOF;
        }
        return ret;
    }

    if(c == expected_c)
    {
        return ret;
    }
    else
    {
        return PARSE_ERROR;
    }
}

static ya_result json_item_read_from(input_stream_t *is, json_t *jp);

static ya_result json_boolean_read_from(input_stream_t *is, json_t *jp)
{
    ya_result ret;
    uchar_t   c;
    bool      value;

    ret = json_expect_next_char(is, &c);

    if(FAIL(ret))
    {
        return ret;
    }

    if(c == 't')
    {
        ret = json_expect_next_char_equals(is, 'r');
        if(FAIL(ret))
        {
            return ret;
        }
        ret = json_expect_next_char_equals(is, 'u');
        if(FAIL(ret))
        {
            return ret;
        }
        ret = json_expect_next_char_equals(is, 'e');
        if(FAIL(ret))
        {
            return ret;
        }
        value = true;
    }
    else if(c == 'f')
    {
        ret = json_expect_next_char_equals(is, 'a');
        if(FAIL(ret))
        {
            return ret;
        }
        ret = json_expect_next_char_equals(is, 'l');
        if(FAIL(ret))
        {
            return ret;
        }
        ret = json_expect_next_char_equals(is, 's');
        if(FAIL(ret))
        {
            return ret;
        }
        ret = json_expect_next_char_equals(is, 'e');
        if(FAIL(ret))
        {
            return ret;
        }
        value = false;
    }
    else
    {
        return PARSE_ERROR;
    }

    json_t j = json_boolean_new_instance();
    json_boolean_set(j, value);
    *jp = j;

    return SUCCESS;
}

static ya_result json_number_read_from(input_stream_t *is, json_t *jp)
{
    ya_result ret;
    char     *buffer;
    uchar_t   c;
    int       buffer_size = JSON_KEY_LENGTH_MAX;
    int       number_size = 0;
    bool      floating_point = false;
    char      _tmp[JSON_KEY_LENGTH_MAX];
    *jp = NULL;
    buffer = &_tmp[0];

    for(;;)
    {
        ret = json_expect_next_char(is, &c);
        if(FAIL(ret))
        {
            return ret;
        }
        if(((c < '0') && (c != '.')) || (c > '9'))
        {
            if(!pushback_input_stream_push_back(is, c))
            {
                return INVALID_STATE_ERROR;
            }
            break;
        }

        if(c == '.')
        {
            if(floating_point)
            {
                return PARSE_ERROR;
            }
            floating_point = true;
        }

        if(number_size == buffer_size - 1)
        {
            int   new_size = buffer_size * 2;
            char *tmp = (char *)malloc(new_size * sizeof(char));
            if(tmp == NULL)
            {
                if(buffer_size > JSON_KEY_LENGTH_MAX)
                {
                    free(buffer);
                }
                return MAKE_ERRNO_ERROR(ENOMEM);
            }
            memcpy(tmp, buffer, buffer_size * sizeof(char));
            if(buffer_size > JSON_KEY_LENGTH_MAX)
            {
                free(buffer);
            }

            buffer = tmp;
            buffer_size = new_size;
        }
        buffer[number_size++] = c;
    }

    json_t j = json_number_new_instance();
    json_number_set_text(j, buffer, number_size);
    *jp = j;
    return SUCCESS;
}

static ya_result json_string_read_from(input_stream_t *is, json_t *jp)
{
    ya_result ret;
    uchar_t   c;
    uchar_t  *buffer;
    int       buffer_size = JSON_KEY_LENGTH_MAX;
    int       string_size = 0;
    uchar_t   _tmp[JSON_KEY_LENGTH_MAX];

    *jp = NULL;
    buffer = &_tmp[0];

    for(;;)
    {
        ret = json_expect_next_char(is, &c);
        if(FAIL(ret))
        {
            return ret;
        }

        bool escaped = (c == '\\');

        if(escaped)
        {
            ret = json_expect_next_char(is, &c);
            if(FAIL(ret))
            {
                return ret;
            }
            // optional translation
            switch(c)
            {
                case 't':
                {
                    c = '\t';
                    break;
                }
                case 'n':
                {
                    c = '\n';
                    break;
                }
                case 'r':
                {
                    c = '\r';
                    break;
                }
                default:
                {
                    break;
                }
            }
        }

        if(!escaped && (c == '"'))
        {
            break;
        }

        if(string_size == buffer_size)
        {
            int      new_size = buffer_size * 2;
            uchar_t *tmp = (uchar_t *)malloc(new_size * sizeof(uchar_t));
            if(tmp == NULL)
            {
                if(buffer_size > JSON_KEY_LENGTH_MAX)
                {
                    free(buffer);
                }
                return MAKE_ERRNO_ERROR(ENOMEM);
            }
            memcpy(tmp, buffer, buffer_size * sizeof(uchar_t));
            if(buffer_size > JSON_KEY_LENGTH_MAX)
            {
                free(buffer);
            }

            buffer = tmp;
            buffer_size = new_size;
        }
        buffer[string_size++] = c;
    }

    json_t j = json_string_new_instance();
    json_string_set_uchar_array(j, buffer, string_size);
    *jp = j;
    return SUCCESS;
}

static ya_result json_array_read_from(input_stream_t *is, json_t *jp)
{
    ya_result ret;
    uchar_t   c;

    *jp = NULL;

    json_t item;

    ret = json_expect_next_char_skip_blanks(is, &c);
    if(FAIL(ret))
    {
        return ret;
    }

    if(c == ']')
    {
        json_t j = json_array_new_instance();
        *jp = j;
        return SUCCESS;
    }

    if(!pushback_input_stream_push_back(is, c))
    {
        return INVALID_STATE_ERROR;
    }

    ret = json_item_read_from(is, &item);

    if(FAIL(ret))
    {
        return ret;
    }

    json_t j = json_array_new_instance();

    json_array_add(j, item);

    for(;;)
    {
        ret = json_expect_next_char_skip_blanks(is, &c);
        if(FAIL(ret))
        {
            json_delete(j);
            return ret;
        }
        if(c == ']')
        {
            *jp = j;
            return SUCCESS;
        }
        if(c != ',')
        {
            json_delete(j);
            return PARSE_ERROR;
        }
        ret = json_item_read_from(is, &item);
        if(FAIL(ret))
        {
            json_delete(j);
            return ret;
        }

        json_array_add(j, item);
    }
}

static ya_result json_object_read_from(input_stream_t *is, json_t *jp)
{
    ya_result ret;
    bool      expect_item = false;

    *jp = NULL;

    json_t j = json_object_new_instance();

    for(;;)
    {
        uchar_t c;
        ret = json_expect_next_char_skip_blanks(is, &c);
        if(FAIL(ret))
        {
            json_delete(j);
            return ret;
        }
        switch(c)
        {
            case '"':
            {
                int     key_length = 0;
                uint8_t key[JSON_KEY_LENGTH_MAX + 4];

                // read until the end "
                for(;;)
                {
                    ret = json_expect_next_char(is, &c);

                    if(FAIL(ret))
                    {
                        json_delete(j);
                        return ret;
                    }

                    bool escaped = (c == '\\');

                    if(escaped)
                    {
                        ret = json_expect_next_char(is, &c);

                        if(FAIL(ret))
                        {
                            json_delete(j);
                            return ret;
                        }
                    }

                    if(key_length > JSON_KEY_LENGTH_MAX)
                    {
                        json_delete(j);
                        return BUFFER_WOULD_OVERFLOW;
                    }

                    if(escaped || (c != '"'))
                    {
                        key_length += utf8_encode_uchar(c, &key[key_length]);
                    }
                    else // not escaped and c == '"'
                    {
                        // got the key, now seek the ':'
                        key[key_length] = 0;

                        ret = json_expect_next_char_equals_skip_blanks(is, ':');
                        if(FAIL(ret))
                        {
                            json_delete(j);
                            return ret;
                        }
                        // got the ':', now parse any JSON item

                        json_t item;

                        ret = json_item_read_from(is, &item);

                        if(ISOK(ret))
                        {
                            json_object_add(j, key, item);

                            ret = json_expect_next_char(is, &c);

                            if(FAIL(ret))
                            {
                                json_delete(j);
                                return ret;
                            }

                            if(c == '}')
                            {
                                *jp = j;
                                return SUCCESS;
                            }
                            if(c == ',')
                            {
                                expect_item = true;
                                break;
                            }

                            json_delete(j);

                            return PARSE_ERROR;
                        }
                        else
                        {
                            json_delete(j);
                            return ret;
                        }
                    }
                }

                break;
            }
            case '}':
            {
                if(!expect_item)
                {
                    *jp = j;
                    return SUCCESS;
                }
                else
                {
                    json_delete(j);
                    return PARSE_ERROR;
                }
            }
            default:
            {
                json_delete(j);
                return PARSE_ERROR;
            }
        }
    }
}

static ya_result json_item_read_from(input_stream_t *is, json_t *jp)
{
    ya_result ret;

    uchar_t   c;
    ret = json_expect_next_char_skip_blanks(is, &c);
    if(FAIL(ret))
    {
        return ret;
    }
    switch(c)
    {
        case '{':
        {
            ret = json_object_read_from(is, jp);
            break;
        }
        case '[':
        {
            ret = json_array_read_from(is, jp);
            break;
        }
        case '"':
        {
            ret = json_string_read_from(is, jp);
            break;
        }
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
        case '.':
        {
            if(!pushback_input_stream_push_back(is, c))
            {
                return INVALID_STATE_ERROR;
            }
            ret = json_number_read_from(is, jp);
            break;
        }
        case 't':
        case 'f':
        {
            if(!pushback_input_stream_push_back(is, c))
            {
                return INVALID_STATE_ERROR;
            }
            ret = json_boolean_read_from(is, jp);
            break;
        }
        default:
        {
            ret = PARSE_INVALID_CHARACTER;
            break;
        }
    }

    return ret;
}

ya_result input_stream_read_json(input_stream_t *is, json_t *jp)
{
    input_stream_t pbis;
    pushback_input_stream_init(&pbis, is, 1);
    ya_result ret;

    uint8_t   c;
    ret = input_stream_read_u8(&pbis, &c);
    if(ret > 0)
    {
        switch(c)
        {
            case '{':
            {
                ret = json_object_read_from(&pbis, jp);
                break;
            }
            case '[':
            {
                ret = json_array_read_from(&pbis, jp);
                break;
            }
            default:
            {
                ret = PARSE_INVALID_CHARACTER;
            }
        }
    }
    *is = pushback_input_stream_detach(&pbis);
    input_stream_close(&pbis);

    return ret;
}

void        json_delete(json_t j);

static void json_delete_forall_callback(ptr_treemap_node_t *node)
{
    free(node->key);
    json_delete((json_t)node->value);
}

/**
 * Recursively delete all the json.
 */

void json_delete(json_t j)
{
    switch(j->type)
    {
        case JSON_STRING:
            free(j->string.utf8_text);
            ZFREE_OBJECT(j);
            break;
        case JSON_BOOLEAN:
            ZFREE_OBJECT(j);
            break;
        case JSON_NUMBER:
        {
            free(j->number.value_text);
            ZFREE_OBJECT(j);
            break;
        }
        case JSON_ARRAY:
        {
            int last_index = ptr_vector_last_index(&j->array.array);
            for(int_fast32_t i = 0; i <= last_index; ++i)
            {
                json_delete((json_t)ptr_vector_get(&j->array.array, i));
            }
            break;
        }
        case JSON_OBJECT:
        {
            ptr_treemap_callback_and_finalise(&j->map.map, json_delete_forall_callback);
            break;
        }
        default:
        {
            // ERROR;
            break;
        }
    } // switch(j->type)
}

ya_result json_size(json_t j)
{
    output_stream_t os;
    output_stream_set_sink(&os);
    ya_result ret = json_write_to(j, &os);
    return ret;
}

/**
 * Serialises the json into an allocated buffer.
 */

char *json_to_string(json_t j)
{
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 0);
    json_write_to(j, &baos);
    output_stream_write_u8(&baos, 0);
    char *ret = (char *)bytearray_output_stream_detach(&baos);
    output_stream_close(&baos);
    return ret;
}

/**
 * Creates a deep clone from a json_t
 *
 * @param json the json to deep clone
 *
 * @return a cloned json or NULL if an error occurred.
 */

json_t json_clone(json_t json)
{
    json_t cloned_json;

    if(json != NULL)
    {
        switch(json->type)
        {
            case JSON_BOOLEAN:
            {
                cloned_json = json_boolean_new_instance();
                cloned_json->boolean.value = json->boolean.value;
                break;
            }
            case JSON_NUMBER:
            {
                cloned_json = json_number_new_instance();
                cloned_json->number.value_text = strdup(json->number.value_text);
                cloned_json->number.floating = json->number.floating;
                break;
            }
            case JSON_STRING:
            {
                cloned_json = json_string_new_instance();
                cloned_json->string.utf8_text = malloc(json->string.utf8_text_size + 1);
                memcpy(cloned_json->string.utf8_text, json->string.utf8_text, json->string.utf8_text_size + 1);
                cloned_json->string.utf8_text_size = json->string.utf8_text_size;
                break;
            }
            case JSON_ARRAY:
            {
                cloned_json = json_array_new_instance_ex(ptr_vector_size(&json->array.array));
                for(int i = 0; i <= ptr_vector_last_index(&json->array.array); ++i)
                {
                    json_t json_item = ptr_vector_get(&json->array.array, i);
                    json_t cloned_json_item = json_clone(json_item);
                    json_array_add(cloned_json, cloned_json_item);
                }
                break;
            }
            case JSON_OBJECT:
            {
                cloned_json = json_object_new_instance();
                ptr_treemap_iterator_t iter;
                ptr_treemap_iterator_init(&json->map.map, &iter);
                while(ptr_treemap_iterator_hasnext(&iter))
                {
                    ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
                    json_t              json_item = node->value;
                    json_t              cloned_json_item = json_clone(json_item);
                    json_object_add(cloned_json, (const uint8_t *)node->key, cloned_json_item);
                }
                break;
            }
            default:
            {
                cloned_json = json_boolean_new_instance();
                break;
            }
        } // switch(j->type)
    }
    else
    {
        cloned_json = NULL;
    }

    return cloned_json;
}

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

ya_result json_get_from_path_buffer(json_t json, const char *path, int path_size, json_t *json_itemp)
{
    ya_result ret;

    for(int i = 0; i < path_size; ++i)
    {
        if(path[i] != '/')
        {
            break;
        }
        ++path;
        --path_size;
    }

    if(json != NULL)
    {
        if((path_size > 0) && (path != NULL))
        {
            switch(json->type)
            {
                case JSON_BOOLEAN:
                case JSON_NUMBER:
                case JSON_STRING:
                {
                    if((path == NULL) || (path_size == 0))
                    {
                        *json_itemp = json;
                        return SUCCESS;
                    }
                    else
                    {
                        return INVALID_ARGUMENT_ERROR;
                    }
                }
                case JSON_ARRAY:
                {
                    // get the word until the '/' or the EOL
                    // it's supposed to be an integer

                    const char *limit = path + path_size;
                    const char *p = strchr(path, '/');
                    if(p == NULL)
                    {
                        p = path + strlen(path);
                    }
                    int num_len = p - path;

                    // parse int at p and of len p_len

                    int32_t index;
                    if(ISOK(ret = parse_s32_check_range_len_base10(path, num_len, &index, INT32_MIN, INT32_MAX)))
                    {
                        if(index >= 0)
                        {
                            index %= ptr_vector_size(&json->array.array);
                        }
                        else
                        {
                            index = -((-index) % ptr_vector_size(&json->array.array));
                        }

                        ++p;
                        json = json_array_get(json, index);
                        ret = json_get_from_path_buffer(json, p, limit - p, json_itemp);
                    }
                    return ret;
                }
                case JSON_OBJECT:
                {
                    const char *limit = path + path_size;
                    const char *p = strchr(path, '/');
                    int         text_len;
                    char       *key;
                    char        key_[64];

                    if(p == NULL)
                    {
                        p = path + strlen(path);
                    }
                    text_len = p - path;
                    if(text_len < (int)sizeof(key_))
                    {
                        key = key_;
                    }
                    else
                    {
                        key = malloc(text_len + 1);
                        if(key == NULL)
                        {
                            return MAKE_ERRNO_ERROR(ENOMEM);
                        }
                    }
                    memcpy(key, path, text_len);
                    key[text_len] = '\0';

                    ptr_treemap_node_t *node = ptr_treemap_find(&json->map.map, key);
                    if(text_len >= (int)sizeof(key_))
                    {
                        free(key);
                    }
                    if(node != NULL)
                    {
                        json = node->value;
                        ++p;
                        ret = json_get_from_path_buffer(json, p, limit - p, json_itemp);
                    }
                    else
                    {
                        ret = INVALID_ARGUMENT_ERROR;
                    }
                    return ret;
                }
                default:
                {
                    return INVALID_STATE_ERROR;
                }
            }
        }
        else
        {
            *json_itemp = json;
            return SUCCESS;
        }
    }
    else
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
}

ya_result json_for_all_internal(json_t json, ya_result (*json_for_all_callback)(json_t json, void *args, ptr_vector_t *json_stack), void *args, ptr_vector_t *json_stack)
{
    ptr_vector_append(json_stack, json);
    ya_result ret = json_for_all_callback(json, args, json_stack);
    if(ISOK(ret))
    {
        if(json->type == JSON_ARRAY)
        {
            for(int i = 0; i <= ptr_vector_last_index(&json->array.array); ++i)
            {
                json_t json_item = ptr_vector_get(&json->array.array, i);
                if(FAIL(ret = json_for_all_internal(json_item, json_for_all_callback, args, json_stack)))
                {
                    break;
                }
            }
        }
        else if(json->type == JSON_OBJECT)
        {
            ptr_treemap_iterator_t iter;
            ptr_treemap_iterator_init(&json->map.map, &iter);
            while(ptr_treemap_iterator_hasnext(&iter))
            {
                ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
                json_t              json_item = node->value;
                if(FAIL(ret = json_for_all_internal(json_item, json_for_all_callback, args, json_stack)))
                {
                    break;
                }
            }
        }
    }
    ptr_vector_pop(json_stack);
    return ret;
}

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

ya_result json_for_all(json_t json, ya_result (*json_for_all_callback)(json_t json, void *args, ptr_vector_t *json_stack), void *args)
{
    if(json != NULL)
    {
        ptr_vector_t json_stack;
        ptr_vector_init(&json_stack);
        ya_result ret = json_for_all_internal(json, json_for_all_callback, args, &json_stack);
        ptr_vector_finalise(&json_stack);
        return ret;
    }
    else
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
}

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

ya_result json_get_from_path(json_t json, const char *path, json_t *json_itemp) { return json_get_from_path_buffer(json, path, (path != NULL) ? strlen(path) : 0, json_itemp); }

/**
 * Exchange two JSON values,
 * keeping parents intact as only internals of the objects are updated.
 *
 * @param json exchange with
 * @param what_with exchanged with
 */

void json_exchange(json_t json, json_t what_with)
{
    // exchange both values;
    union json_u tmp;
    tmp = *json;
    *json = *what_with;
    *what_with = tmp;
}

/** @} */

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

#define JSON_C_ 1

#include "dnscore/sys_types.h"
#include "dnscore/ptr_set.h"
#include "dnscore/ptr_vector.h"
#include "dnscore/zalloc.h"
#include "dnscore/format.h"

struct json_value_array
{
    intptr type;
    ptr_vector array;
};

struct json_value_object
{
    intptr type;
    ptr_set map;
};

struct json_value_string
{
    intptr type;
    char *text;
    size_t text_size;
};

struct json_value_number
{
    intptr type;
    double value;
};

struct json_value_bool
{
    intptr type;
    bool value;
};

#include "dnscore/json.h"

union json
{
    enum json_type type;
    struct json_value_bool boolean;
    struct json_value_number number;
    struct json_value_string string;
    struct json_value_array array;
    struct json_value_object map;
};

static json
json_type_new_intance(enum json_type type)
{
    json ret;
    ZALLOC_OBJECT_OR_DIE(ret, union json, GENERIC_TAG);
    ret->type = type;
    return ret;
}

json
json_object_new_instance()
{
    json ret = json_type_new_intance(JSON_OBJECT);
    ptr_set_init(&ret->map.map);
    ret->map.map.compare = ptr_set_asciizp_node_compare;
    return ret;
}

json
json_array_new_instance()
{
    json ret = json_type_new_intance(JSON_ARRAY);
    ptr_vector_init(&ret->array.array);
    return ret;
}

json
json_string_new_instance()
{
    json ret = json_type_new_intance(JSON_STRING);
    ret->string.text = NULL;
    ret->string.text_size = 0;
    return ret;
}

json
json_number_new_instance()
{
    json ret = json_type_new_intance(JSON_NUMBER);
    ret->number.value = 0;
    return ret;
}

json
json_boolean_new_instance()
{
    json ret = json_type_new_intance(JSON_BOOLEAN);
    ret->boolean.value = FALSE;
    return ret;
}

enum json_type
json_type_get(const json j)
{
    return j->type;
}

bool
json_boolean_get(const json j)
{
    yassert(j->type == JSON_BOOLEAN);
    return j->boolean.value; 
}

void
json_boolean_set(json j, bool value)
{
    yassert(j->type == JSON_BOOLEAN);
    j->boolean.value = value;    
}

double
json_number_get(const json j)
{
    yassert(j->type == JSON_NUMBER);
    return j->number.value; 
}

void
json_number_set(json j, double value)
{
    yassert(j->type == JSON_NUMBER);
    j->number.value = value;    
}

const char *
json_string_get(const json j)
{
    yassert(j->type == JSON_STRING);
    return j->string.text;
}

size_t
json_string_size_get(const json j)
{
    yassert(j->type == JSON_STRING);
    return j->string.text_size;
}

void
json_string_set(json j, const char* text)
{
    yassert(j->type == JSON_STRING);
    j->string.text = strdup(text);
    j->string.text_size = strlen(text);
}

json
json_array_get(json j, size_t index)
{
    yassert(j->type == JSON_ARRAY);
    json ret = (json)ptr_vector_get(&j->array.array, index);
    return ret;
}

void
json_array_add(const json j, json item)
{
    yassert(j->type == JSON_ARRAY);
    ptr_vector_append(&j->array.array, item);
}

json
json_object_get(json j, const char *name)
{
    yassert(j->type == JSON_OBJECT);
    ptr_node *node = ptr_set_find(&j->map.map, name);
    if(node != NULL && node->value != NULL)
    {
        return (json)node->value;
    }
    else
    {
        return NULL;
    }
}

bool
json_object_add(const json j, const char *key, json item)
{
    yassert(j->type == JSON_OBJECT);
    ptr_node *node = ptr_set_insert(&j->map.map, (void*)key);
    if(node->value == NULL)
    {
        node->key = strdup(key);
        node->value = item;
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

ya_result json_write_to(json j, output_stream *os);

struct json_write_forall_callback_args
{
    output_stream *os;
    ya_result ret;
    bool comma;
};

static int
json_write_forall_callback(ptr_node *node, void *args_)
{
    struct json_write_forall_callback_args *args = (struct json_write_forall_callback_args*)args_;
    output_stream *os = args->os;    
    ya_result ret = 0;
    
    if(!args->comma || ((ret = output_stream_write(os, ",", 1)) == 1))
    {    
        ya_result ret0;
        
        ret0 = osformat(os, "\"%s\": ", node->key);
        if(ISOK(ret0))
        {
            ya_result ret1;
            if(ISOK(ret1 = json_write_to((json)node->value, os)))
            {
                ret += ret0 + ret1;
                args->ret += ret;
                args->comma = TRUE;
            }
            else
            {
                ret = ret1;;
            }
        }
        else
        {
            ret = ret0;
        }
    }
    
    return ret;
}

ya_result
json_write_to(json j, output_stream *os)
{
    ya_result ret;
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
            ret = osformat(os, "%f", j->number.value);
            break;
        }
        case JSON_STRING:
        {
            ya_result ret_tmp;
            if((ret_tmp = output_stream_write(os, "\"", 1)) == 1)
            {
                if(ISOK(ret = output_stream_write(os, j->string.text, j->string.text_size)))
                {
                    if((ret_tmp = output_stream_write(os, "\"", 1)) == 1)
                    {
                        ret += 2;
                    }
                    else
                    {
                        ret = ret_tmp;
                    }
                }
            }
            else
            {
                ret = ret_tmp;
            }
            break;
        }
        case JSON_ARRAY:
        {
            ya_result t = 2;
            ret = output_stream_write_u8(os, '[');
            
            if(ISOK(ret))
            {
                int last_index = ptr_vector_last_index(&j->array.array);
                
                if(last_index >= 0)
                {
                    if(ISOK(ret = json_write_to((json)ptr_vector_get(&j->array.array, 0), os)))
                    {
                        t += ret;
                        
                        for(int i = 1; i <= last_index; ++i)
                        {
                            if(FAIL(ret = output_stream_write_u8(os, ',')))
                            {
                                break;
                            }
                            
                            if(FAIL(ret = json_write_to((json)ptr_vector_get(&j->array.array, i), os)))
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
            }
            
            break;
        }
        case JSON_OBJECT:
        {
            ret = output_stream_write_u8(os, '{');
            
            if(ISOK(ret))
            {
                struct json_write_forall_callback_args args = { os, 2, FALSE};
                
                ptr_set_forall(&j->map.map, json_write_forall_callback, &args);

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
    
    return ret;
}

void json_delete(json j);

static void
json_delete_forall_callback(ptr_node *node)
{
    free(node->key);
    json_delete((json)node->value);
}

void
json_delete(json j)
{
    switch(j->type)
    {
        case JSON_STRING:
            free(j->string.text);
            FALLTHROUGH // fall through
        case JSON_BOOLEAN:
            FALLTHROUGH // fall through
        case JSON_NUMBER:
        {
            ZFREE_OBJECT(j);
            break;
        }  
        case JSON_ARRAY:
        {
            int last_index = ptr_vector_last_index(&j->array.array);
            for(int i = 0; i <= last_index; ++i)
            {
                json_delete((json)ptr_vector_get(&j->array.array, i));
            }
            break;
        }
        case JSON_OBJECT:
        {
            ptr_set_callback_and_destroy(&j->map.map, json_delete_forall_callback);
            break;
        }
        default:
        {
            // ERROR;
            break;
        }
    } // switch(j->type)
}

ya_result json_size(json j)
{
    output_stream os;
    output_stream_set_sink(&os);
    ya_result ret = json_write_to(j, &os);
    return ret;
}

/** @} */

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

#include "yatest.h"
#include <dnscore/dnscore.h>

#include <dnscore/dnscore.h>
#include <dnscore/json.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/bytearray_output_stream.h>
#include <math.h>

static const char *const json_0 = "{}";

static const char *const json_1 = "[]";

static const char *const json_2 = "{\"key\": \"text\"}";

static const char *const json_3 = "{\"key\": 123456789}";

static const char *const json_4 = "{\"key\": 123456789.87654321}";

static const char *const json_5 = "{\"key\": true}";

static const char *const json_6 = "{\"key\": false}";

static const char *const json_7 = "[\"text\"]";

static const char *const json_8 = "[123456789]";

static const char *const json_9 = "[123456789.87654321]";

static const char *const json_10 = "[true]";

static const char *const json_11 = "[false]";

static const char *const json_12 =
    "{"
    "\"False\": false,"
    "\"True\": true,"
    "\"arr\": [{\"subobj1\": \"subval1\"},\"A "
    "text\",123456789,123456789.87654321,true,false,[\"array\",\"of\",\"three\"]],"
    "\"double\": 123456789.87654321,"
    "\"int\": 123456789,"
    "\"obj\": {\"subobj0\": \"subval0\"},"
    "\"str\": \"Another text\""
    "}";

static const char *const json_13 = "[{\"one\": true},[1,2,3]]";

static const char *const json_14 =
    "{\""
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 256
    "\": false}";

static const char *const json_15 =
    "{\"key\": "
    "1234567890123456789012345678901234567890123456789012345678901234"
    "1234567890123456789012345678901234567890123456789012345678901234"
    "1234567890123456789012345678901234567890123456789012345678901234"
    "1234567890123456789012345678901234567890123456789012345678901234"
    "1234567890123456789012345678901234567890123456789012345678901234"
    "}";

static const char *const json_16 =
    "{\"key\": \""
    "1234567890123456789012345678901234567890123456789012345678901234"
    "1234567890123456789012345678901234567890123456789012345678901234"
    "1234567890123456789012345678901234567890123456789012345678901234"
    "1234567890123456789012345678901234567890123456789012345678901234"
    "1234567890123456789012345678901234567890123456789012345678901234"
    "\"}";

static const char *const json_key_too_big =
    "{\""
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 256
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // BUFFER_WOULD_OVERFLOW
    "\": false}";

static const char *const json_escaped_quotes = "{\"\\\"key\\\"\": \"\\\"value\\t\\r\\n\\\\\\\"\"}";

static const char       *json_list[] = {json_0, json_1, json_2, json_3, json_4, json_5, json_6, json_7, json_8, json_9, json_10, json_11, json_12, json_13, json_14, json_15, json_16, NULL};

// for several json streams, parses the json then prints it and compares the input and the output

static ya_result json_test_n(const char *json_text)
{
    json_t         j;
    input_stream_t is;
    ya_result      ret;
    yatest_log("JSON: -->%s<--", json_text);
    bytearray_input_stream_init(&is, (void *)json_text, strlen(json_text), false);
    ret = input_stream_read_json(&is, &j);
    input_stream_close(&is);
    if(ISOK(ret))
    {
        yatest_log("SUCCESS: %08x (parsing) BEGIN", ret);
        json_write_to(j, termout);
        flushout();
        yatest_log("END");
        output_stream_t baos;
        bytearray_output_stream_init(&baos, NULL, 0);
        int n = json_write_to(j, &baos);
        output_stream_write_u8(&baos, 0);
        const char *json_back = (const char *)bytearray_output_stream_buffer(&baos);
        uint32_t    json_back_len = bytearray_output_stream_size(&baos) - 1;
        if(strlen(json_text) == json_back_len)
        {
            if(memcmp(json_text, json_back, json_back_len) == 0)
            {
                ret = SUCCESS;
                yatest_log("SUCCESS: %08x (comparing)", ret);
            }
            else
            {
                ret = INVALID_STATE_ERROR;
                yatest_err("ERROR: %08x (comparing)", ret);
            }
        }
        else
        {
            ret = INVALID_STATE_ERROR;
            yatest_err("ERROR: %08x (length: strlen(json_text) == json_back_len: %i != %i)", ret, strlen(json_text), json_back_len);
            yatest_err("'%s'", json_text);
            yatest_err("'%s'", json_back);
        }
        if(n != (int)json_back_len)
        {
            yatest_err("json_write_to returned %i instead of %i", n, json_back_len);
            return 1;
        }

        json_t cloned_j = json_clone(j);

        bytearray_output_stream_reset(&baos);
        n = json_write_to(cloned_j, &baos);
        output_stream_write_u8(&baos, 0);
        const char *cloned_json_back = (const char *)bytearray_output_stream_buffer(&baos);
        uint32_t    cloned_json_back_len = bytearray_output_stream_size(&baos) - 1;

        if(strlen(json_text) == cloned_json_back_len)
        {
            if(memcmp(json_text, cloned_json_back, cloned_json_back_len) == 0)
            {
                ret = SUCCESS;
                yatest_log("SUCCESS: %08x (comparing)", ret);
            }
            else
            {
                ret = INVALID_STATE_ERROR;
                yatest_err("ERROR: %08x (comparing)", ret);
            }
        }
        else
        {
            ret = INVALID_STATE_ERROR;
            yatest_err("ERROR: %08x (length: strlen(json_text) == cloned_json_back_len: %i != %i)", ret, strlen(json_text), cloned_json_back_len);
            yatest_err("'%s'", json_text);
            yatest_err("'%s'", json_back);
        }

        output_stream_close(&baos);
        json_delete(cloned_j);
        json_delete(j);
    }
    else
    {
        yatest_err("FAILURE: %08x = %s", ret, error_gettext(ret));
    }

    return ret;
}

static int json_set_get_test()
{
    dnscore_init();

    json_t json = json_object_new_instance();
    json_t b0 = json_boolean_new_instance();
    json_boolean_set(b0, false);
    if(json_boolean_get(b0))
    {
        yatest_err("b0 is true");
        return 1;
    }
    json_t b1 = json_boolean_new_instance();
    json_boolean_set(b1, true);
    if(!json_boolean_get(b1))
    {
        yatest_err("b1 is false");
        return 1;
    }
    json_t nd = json_number_new_instance();
    json_number_set_double(nd, 3.14159);
    if(fabs(json_number_as_double(nd) - 3.14159) > 0.00001)
    {
        yatest_err("nd = %f, which is not close enough to 3.14159", json_number_as_double(nd));
        return 1;
    }
    json_t ni = json_number_new_instance();
    json_number_set_s64(ni, INT64_MAX);
    if(json_number_as_s64(ni) != INT64_MAX)
    {
        yatest_err("ni = %lli != %lli", json_number_as_s64(ni), INT64_MAX);
        return 1;
    }
    json_t      s = json_string_new_instance();
    static char hello_world[] = "Hello World!";
    json_string_set(s, (const uint8_t *)hello_world);
    if(json_string_size_get(s) != sizeof(hello_world) - 1)
    {
        yatest_err("s len = %i != %i", json_string_size_get(s), sizeof(hello_world) - 1);
        return 1;
    }
    if(strcmp(json_string_get(s), hello_world) != 0)
    {
        yatest_err("s '%s' != '%s'", json_string_get(s), hello_world);
        return 1;
    }
    json_t a = json_array_new_instance();
    json_array_add_boolean(a, true);
    json_array_add_number(a, 1);
    json_array_add_string(a, (const uint8_t *)"one");
    if(!json_boolean_get(json_array_get(a, 0)))
    {
        yatest_err("a[0] is not true");
        return 1;
    }

    ya_result ret;
    bool bool_value = false;

    if(FAIL(ret = json_boolean_get_bool(json_array_get(a, 0), &bool_value)))
    {
        yatest_err("a[0] could not be read as a bool: %08x", ret);
        return 1;
    }

    if(!bool_value)
    {
        yatest_err("a[0] could not be read as true");
        return 1;
    }

    if(json_number_as_s64(json_array_get(a, 1)) != 1)
    {
        yatest_err("a[1] is not 1");
        return 1;
    }

    double double_value = 0.0;

    if(FAIL(ret = json_number_get_double(json_array_get(a, 1), &double_value)))
    {
        yatest_err("a[1] could not be read as a double: %08x", ret);
        return 1;
    }

    if(double_value != 1.0)
    {
        yatest_err("a[1] could not be read as 1.0");
        return 1;
    }

    int64_t s64_value = 0;

    if(FAIL(ret = json_number_get_s64(json_array_get(a, 1), &s64_value)))
    {
        yatest_err("a[1] could not be read as an int64_t: %08x", ret);
        return 1;
    }

    if(s64_value != 1)
    {
        yatest_err("a[1] could not be read as 1 (64 bits)");
        return 1;
    }

    int32_t s32_value = 0;

    if(FAIL(ret = json_number_get_s32(json_array_get(a, 1), &s32_value)))
    {
        yatest_err("a[1] could not be read as an int32_t: %08x", ret);
        return 1;
    }

    if(s32_value != 1)
    {
        yatest_err("a[1] could not be read as 1 (32 bits)");
        return 1;
    }

    json_t da = json_array_new_instance();
    for(int i = 0; i <= 4; ++i)
    {
        json_array_add_number(da, (double)i);
    }

    double double_array[8] = {7, 7, 7, 7, 7, 7, 7, 7};

    int double_array_size = json_array_size(da);

    if(double_array_size > (int)(sizeof(double_array)/sizeof(double_array[0])))
    {
        yatest_err("double_array size is too small for this test (test bug)");
        return 1;
    }

    ret = json_number_get_double_array(da, double_array, double_array_size);

    if(FAIL(ret))
    {
        yatest_err("da could not be read as an array of double: %08x", ret);
        return 1;
    }

    for(int i = 0; i <= 4; ++i)
    {
        if(double_array[i] != (double)i)
        {
            yatest_err("da[%i] value differs from expectations: %f != %f", double_array[i], (double)i);
            return 1;
        }
    }

    if(strcmp(json_string_get(json_array_get(a, 2)), "one") != 0)
    {
        yatest_err("a[2] is not \"one\"");
        return 1;
    }
    json_object_add(json, (const uint8_t *)"b0", b0);
    json_object_add(json, (const uint8_t *)"b1", b1);
    json_object_add(json, (const uint8_t *)"nd", nd);
    json_object_add(json, (const uint8_t *)"ni", ni);
    json_object_add(json, (const uint8_t *)"s", s);
    json_object_add(json, (const uint8_t *)"a", a);
    json_object_add_boolean(json, (const uint8_t *)"inline-bool", false);
    json_object_add_number_double(json, (const uint8_t *)"inline-double", 1.618);
    json_object_add_number_s64(json, (const uint8_t *)"inline-int", 97);
    json_object_add_string(json, (const uint8_t *)"inline-string", (const uint8_t *)"word");

    if(json_boolean_get(json_object_get(json, "b0")))
    {
        yatest_err("json[\"b0\"] is true");
        return 1;
    }

    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 65536);
    json_write_to(json, &baos);
    output_stream_write_u8(&baos, 0);
    yatest_log("'%s'", bytearray_output_stream_buffer(&baos));
    char *text = json_to_string(json);
    yatest_log("'%s'", text);
    int text_size = json_size(json);
    if(text_size != (int)strlen(text))
    {
        yatest_err("json_size(json) != strlen(json_to_string(json)) %i != %i", text_size, strlen(text));
        return 1;
    }
    free(text);

    if(json_type_get(json) != JSON_OBJECT)
    {
        yatest_err("json expected to be a JSON_OBJECT = %i, got %i", JSON_OBJECT, json_type_get(json));
        return 1;
    }

    json_delete(json);
    output_stream_close(&baos);

    dnscore_finalize();
    return 0;
}

static int json_test()
{
    dnscore_init();

    int ret;
    for(int_fast32_t i = 0; json_list[i] != NULL; ++i)
    {
        yatest_log("==============================================");
        yatest_log("JSON %i", i);
        yatest_log("==============================================");
        if((ret = json_test_n(json_list[i])) < 0)
        {
            return 1;
        }
        yatest_log("==============================================");
        yatest_log("JSON %i: %08x", i, ret);
        yatest_log("==============================================");
    }

    dnscore_finalize();
    return 0;
}

static int json_parse_key_too_big_test()
{
    dnscore_init();
    int ret = json_test_n(json_key_too_big);
    if(ret != BUFFER_WOULD_OVERFLOW)
    {
        yatest_err("parsing key too big expected BUFFER_WOULD_OVERFLOW=%08x, got %08x", BUFFER_WOULD_OVERFLOW, ret);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int json_parse_escaped_quotes_test()
{
    dnscore_init();
    int ret = json_test_n(json_escaped_quotes);
    if(FAIL(ret))
    {
        yatest_err("expeced to parse the object, got %08x", ret);
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static int json_path_test()
{
    dnscore_init();
    json_t         j;
    input_stream_t is;
    ya_result      ret;
    const char    *json_text = json_12;
    yatest_log("JSON: -->%s<--", json_text);
    bytearray_input_stream_init(&is, (void *)json_text, strlen(json_text), false);
    ret = input_stream_read_json(&is, &j);
    input_stream_close(&is);
    if(ISOK(ret))
    {
        json_t item;
        if(FAIL(ret = json_get_from_path(j, "", &item)))
        {
            yatest_err("json_get_from_path '' returned %08x", ret);
            return 1;
        }
        if(item != j)
        {
            yatest_err("expected empty path to return root item");
            return 1;
        }
        if(FAIL(ret = json_get_from_path(j, "False", &item)))
        {
            yatest_err("json_get_from_path 'False' returned %08x", ret);
            return 1;
        }
        if((item->type != JSON_BOOLEAN) || json_boolean_get(item))
        {
            yatest_err("json_get_from_path 'False' returned the wrong item");
        }
        if(FAIL(ret = json_get_from_path(j, "True", &item)))
        {
            yatest_err("json_get_from_path 'True' returned %08x", ret);
            return 1;
        }
        if((item->type != JSON_BOOLEAN) || !json_boolean_get(item))
        {
            yatest_err("json_get_from_path 'True' returned the wrong item");
        }
        if(FAIL(ret = json_get_from_path(j, "arr/6/1", &item)))
        {
            yatest_err("json_get_from_path 'arr/6/1' returned %08x", ret);
            return 1;
        }

        if((item->type != JSON_STRING) || (strcmp(json_string_get(item), "of") != 0))
        {
            yatest_err("json_get_from_path 'arr/6/1' returned the wrong item");
            return 1;
        }
        if(FAIL(ret = json_get_from_path(j, "obj/subobj0", &item)))
        {
            yatest_err("json_get_from_path 'obj/subobj0' returned %08x", ret);
            return 1;
        }
        if((item->type != JSON_STRING) || (strcmp(json_string_get(item), "subval0") != 0))
        {
            yatest_err("json_get_from_path 'obj/subobj0' returned the wrong item");
            return 1;
        }
    }
    else
    {
        yatest_err("failed to parse json");
        return 1;
    }
    dnscore_finalize();
    return 0;
}

static ya_result json_for_all_test_callback(json_t json, void *args, ptr_vector_t *json_stack)
{
    (void)json;
    (void)json_stack;
    int *counterp = args;
    ++(*counterp);
    return SUCCESS;
}

static int json_for_all_test()
{
    dnscore_init();
    json_t         j;
    input_stream_t is;
    ya_result      ret;
    const char    *json_text = json_12;
    yatest_log("JSON: -->%s<--", json_text);
    bytearray_input_stream_init(&is, (void *)json_text, strlen(json_text), false);
    ret = input_stream_read_json(&is, &j);
    input_stream_close(&is);
    if(ISOK(ret))
    {
        int       counter = 0;
        const int counter_expected = 20;
        ret = json_for_all(j, json_for_all_test_callback, &counter);
        if(FAIL(ret))
        {
            yatest_err("json_for_all failed with %08x", ret);
            return 1;
        }
        if(counter != counter_expected)
        {
            yatest_err("json_for_all: expected counter value to be %i, got %i", counter_expected, counter);
            return 1;
        }
    }
    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(json_test)
YATEST(json_set_get_test)
YATEST(json_parse_key_too_big_test)
YATEST(json_parse_escaped_quotes_test)
YATEST(json_path_test)
YATEST(json_for_all_test)
YATEST_TABLE_END

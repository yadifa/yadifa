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
#include <dnscore/host_address.h>
#include <dnscore/ptr_treemap_debug.h>

static char  tmp_text_buffer[256];

static void *ptr_key_generator(int64_t value) { return (void *)(intptr_t)value; }

static char *ptr_key_to_text(void *key)
{
    snprintf(tmp_text_buffer, sizeof(tmp_text_buffer), "%p", key);
    return tmp_text_buffer;
}

static void *asciizp_key_generator(int64_t value)
{
    char tmp[24];
    snprintf(tmp, sizeof(tmp), "K%019li", value);
    return yatest_strdup(tmp);
}

static char *asciizp_key_to_text(void *key)
{
    if(key != NULL)
    {
        return key;
    }
    else
    {
        strcpy(tmp_text_buffer, "NULL");
        return tmp_text_buffer;
    }
}

static void *dnsname_key_generator(int64_t value)
{
    char tmp[24];
    int  n = snprintf(tmp + 1, sizeof(tmp) - 1, "K%019li", value);
    tmp[0] = n;
    return dnsname_dup((uint8_t *)tmp);
}

static char *dnsname_key_to_text(void *key)
{
    if(key != NULL)
    {
        cstr_init_with_dnsname(tmp_text_buffer, key);
    }
    else
    {
        strcpy(tmp_text_buffer, "NULL");
    }
    return tmp_text_buffer;
}

static void *host_address_key_generator(int64_t value)
{
    host_address_t *ha = host_address_new_instance();
    ha->ip.v6.lohi[0] = 0;
    ha->ip.v6.lohi[1] = bswap_64(value);
    ha->ip.v6.bytes[0] = 0x20;
    ha->ip.v6.bytes[1] = 0x02;
    ha->version = 6;
    ha->port = 0;
    return ha;
}

static char *host_address_key_to_text(void *key)
{
    host_address_t *ha = key;
    host_address_to_str(ha, tmp_text_buffer, sizeof(tmp_text_buffer), 0);
    return tmp_text_buffer;
}

#define FIBONACCI_INT64_MAX 92

static int64_t fibonacci(int64_t value)
{
    if(value < 2)
    {
        return value;
    }
    static int64_t *fibonacci_memorised = NULL;
    if(fibonacci_memorised == NULL)
    {
        fibonacci_memorised = yatest_malloc((FIBONACCI_INT64_MAX + 1) * sizeof(int64_t));
        fibonacci_memorised[0] = 0;
        fibonacci_memorised[1] = 1;
        for(int64_t i = 2; i <= FIBONACCI_INT64_MAX; ++i)
        {
            fibonacci_memorised[i] = fibonacci_memorised[i - 1] + fibonacci_memorised[i - 2];
        }
    }
    if(value < FIBONACCI_INT64_MAX)
    {
        return fibonacci_memorised[value];
    }
    else // beyond 64 bits anyway ...
    {
        return INT64_MAX;
    }
}

static int add_del_test_common(ptr_treemap_node_debug_compare_t *comparator, void *(*key_generator)(int64_t), char *(*key_to_text)(void *), bool is_nullable)
{
    dnscore_init();

    ptr_treemap_debug_t tree;
    tree.root = NULL;
    tree.compare = comparator;

    for(int64_t i = 2; i <= FIBONACCI_INT64_MAX; ++i)
    {
        char *key = key_generator(fibonacci(i));
        yatest_log("inserting key: %s (%lli)", key_to_text(key), i);
        /*ptr_treemap_node_debug_t *node = */ ptr_treemap_debug_insert(&tree, key);
    }

    if(is_nullable)
    {
        /*ptr_treemap_node_debug_t *node = */ ptr_treemap_debug_insert(&tree, NULL);
    }

    ptr_treemap_debug_iterator_t iter;
    ptr_treemap_debug_iterator_init(&tree, &iter);
    while(ptr_treemap_debug_iterator_hasnext(&iter))
    {
        ptr_treemap_node_debug_t *node = ptr_treemap_debug_iterator_next_node(&iter);
        yatest_log("iterated: %s", key_to_text(node->key));
    }

    for(int64_t i = 2; i <= FIBONACCI_INT64_MAX; ++i)
    {
        char *key = key_generator(fibonacci(i));
        yatest_log("finding key: %s", key_to_text(key));
        ptr_treemap_node_debug_t *node = ptr_treemap_debug_find(&tree, key);
        if(node == NULL)
        {
            yatest_err("expected to find node for key %s", key_to_text(key));

            ptr_treemap_debug_iterator_init(&tree, &iter);
            while(ptr_treemap_debug_iterator_hasnext(&iter))
            {
                ptr_treemap_node_debug_t *node = ptr_treemap_debug_iterator_next_node(&iter);
                yatest_err("iterated: %s", key_to_text(node->key));
            }
            return 1;
        }
        yatest_log("deleting key: %s", key_to_text(key));
        ptr_treemap_debug_delete(&tree, key);
    }

    if(is_nullable)
    {
        ptr_treemap_debug_delete(&tree, NULL);
    }

    if(!ptr_treemap_debug_isempty(&tree))
    {
        yatest_err("expected the treemap to be empty");
        return 1;
    }

    dnscore_finalize();
    return 0;
}

static int add_del_ptr_test() { return add_del_test_common(ptr_treemap_debug_ptr_node_compare, ptr_key_generator, ptr_key_to_text, false); }

static int add_del_asciizp_test() { return add_del_test_common(ptr_treemap_debug_asciizp_node_compare, asciizp_key_generator, asciizp_key_to_text, false); }

static int add_del_nullable_asciizcasep_test() { return add_del_test_common(ptr_treemap_debug_nullable_asciizp_node_compare, asciizp_key_generator, asciizp_key_to_text, true); }

static int add_del_dnsname_test() { return add_del_test_common(ptr_treemap_debug_dnsname_node_compare, dnsname_key_generator, dnsname_key_to_text, false); }

static int add_del_dnslabel_test() { return add_del_test_common(ptr_treemap_debug_dnslabel_node_compare, dnsname_key_generator, dnsname_key_to_text, false); }

static int add_del_nullable_dnsname_test() { return add_del_test_common(ptr_treemap_debug_nullable_dnsname_node_compare, dnsname_key_generator, dnsname_key_to_text, true); }

static int add_del_host_address_test() { return add_del_test_common(ptr_treemap_debug_host_address_node_compare, host_address_key_generator, host_address_key_to_text, true); }

YATEST_TABLE_BEGIN
YATEST(add_del_ptr_test)
YATEST(add_del_asciizp_test)
YATEST(add_del_nullable_asciizcasep_test)
YATEST(add_del_dnsname_test)
YATEST(add_del_nullable_dnsname_test)
YATEST(add_del_dnslabel_test)
YATEST(add_del_host_address_test)
YATEST_TABLE_END

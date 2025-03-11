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

#include "yatest.h"
#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnscore/host_address.h>
#include <dnscore/u64_treemap.h>

#define FIBONACCI_INT64_MAX 92
#define FIBONACCI_INT32_MAX 46
#if __SIZEOF_POINTER__ == 8
#define FIBONACCI_PTR_MAX FIBONACCI_INT64_MAX
#else
#define FIBONACCI_PTR_MAX FIBONACCI_INT32_MAX
#endif

static int64_t fibonacci(int64_t value)
{
    if(value < 2)
    {
        return value;
    }
    static int64_t *fibonacci_memorised = NULL;
    if(fibonacci_memorised == NULL)
    {
        fibonacci_memorised = yatest_malloc((FIBONACCI_PTR_MAX + 1) * sizeof(int64_t));
        fibonacci_memorised[0] = 0;
        fibonacci_memorised[1] = 1;
        for(int64_t i = 2; i <= FIBONACCI_PTR_MAX; ++i)
        {
            fibonacci_memorised[i] = fibonacci_memorised[i - 1] + fibonacci_memorised[i - 2];
        }
    }
    if(value < FIBONACCI_PTR_MAX)
    {
        return fibonacci_memorised[value];
    }
    else // beyond 64 bits anyway ...
    {
        return INT64_MAX;
    }
}

static int add_del_test()
{
    dnscore_init();

    u64_treemap_t tree = U64_TREEMAP_EMPTY;

    for(int64_t i = 2; i <= FIBONACCI_PTR_MAX; ++i)
    {
        uint64_t key = fibonacci(i);
        yatest_log("inserting key: %lli", key);
        u64_treemap_node_t *node = u64_treemap_insert(&tree, key);
        node->value_u64 = key;
    }

    u64_treemap_iterator_t iter;
    u64_treemap_iterator_init(&tree, &iter);
    while(u64_treemap_iterator_hasnext(&iter))
    {
        u64_treemap_node_t *node = u64_treemap_iterator_next_node(&iter);
        yatest_log("iterated: %llu = %llu", node->key, node->value_u64);
    }

    u64_treemap_iterator_init(&tree, &iter);
    for(;;)
    {
        void *value = u64_treemap_iterator_hasnext_next_value(&iter);
        if(value != NULL)
        {
            yatest_log("iterated (bis): %p", value);
            continue;
        }
        break;
    }

    for(int64_t i = 2; i <= FIBONACCI_PTR_MAX; ++i)
    {
        uint64_t key = fibonacci(i);
        yatest_log("finding key: %llu", key);
        u64_treemap_node_t *node = u64_treemap_find(&tree, key);
        if(node == NULL)
        {
            yatest_err("expected to find node for key %llu", key);

            u64_treemap_iterator_init(&tree, &iter);
            while(u64_treemap_iterator_hasnext(&iter))
            {
                u64_treemap_node_t *node = u64_treemap_iterator_next_node(&iter);
                yatest_err("iterated: %llu", node->key);
            }
            return 1;
        }
        yatest_log("deleting key: %llu", key);
        u64_treemap_delete(&tree, key);
    }

    if(!u64_treemap_isempty(&tree))
    {
        yatest_err("expected the treemap to be empty");
        return 1;
    }

    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(add_del_test)
YATEST_TABLE_END

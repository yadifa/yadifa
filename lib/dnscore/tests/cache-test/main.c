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
#include <dnscore/cache.h>

static int  cache_item_expected_count = 0;

static void cache_test_item_delete(void *data)
{
    uint8_t *sizep = data;
    printf("cache_test_item_delete(%p): freeing %i bytes\n", data, 1 << *sizep);
    fflush(stdout);
    free(data);
    --cache_item_expected_count;
}

static int cache_test()
{
    dnscore_init();
    cache_t *cache = cache_new_instance(65536);

    for(int64_t i = 0; i < 16; ++i)
    {
        cache_item_key_t key;
        cache_item_key_init(&key, sizeof(int64_t));
        memcpy(key.key, &i, sizeof(i));
        cache_item_t *item = cache_acquire_item(cache, key);
        ++cache_item_expected_count;
        char *data = malloc(1 << i);
        memset(data, i, 1 << i);
        cache_update_item(cache, item, data, cache_test_item_delete, 1 << i);
        cache_release_item(cache, item);
    }

    if(cache_item_expected_count != 16)
    {
        yatest_err("expected 16 items, got %i (acquire)", cache_item_expected_count);
        return 1;
    }

    for(int64_t i = 0; i < 16; ++i)
    {
        cache_item_key_t key;
        cache_item_key_init(&key, sizeof(int64_t));
        memcpy(key.key, &i, sizeof(i));
        cache_item_t *item = cache_acquire_item(cache, key);
        if(item->data == NULL)
        {
            yatest_err("cache cleared for no good reason");
            return 1;
        }
        cache_release_item(cache, item);
    }

    if(cache_item_expected_count != 16)
    {
        yatest_err("expected 16 items, got %i (release)", cache_item_expected_count);
        return 1;
    }

    cache_delete(cache);
    dnscore_finalize();
    return 0;
}

static int cache_maintenance_test()
{
    dnscore_init();
    cache_t *cache = cache_new_instance(32768);

    for(int64_t i = 0; i < 17; ++i)
    {
        cache_item_key_t key;
        cache_item_key_init(&key, sizeof(int64_t));
        memcpy(key.key, &i, sizeof(i));
        yatest_log("item size %i: cache %i/%i", 1 << i, cache->weight_current, cache->weight_max);
        cache_item_t *item = cache_acquire_item(cache, key);
        yatest_log("item size %i: cache %i/%i (acquire)", 1 << i, cache->weight_current, cache->weight_max);
        ++cache_item_expected_count;
        char *data = malloc(1 << i);
        memset(data, i, 1 << i);
        cache_update_item(cache, item, data, cache_test_item_delete, 1 << i);
        yatest_log("item size %i: cache %i/%i (updated)", 1 << i, cache->weight_current, cache->weight_max);
        cache_release_item(cache, item);
    }

    for(int64_t i = 0; i < 17; ++i)
    {
        cache_item_key_t key;
        cache_item_key_init(&key, sizeof(int64_t));
        memcpy(key.key, &i, sizeof(i));
        yatest_log("item size %i: cache %i/%i", 1 << i, cache->weight_current, cache->weight_max);
        cache_item_t *item = cache_acquire_item(cache, key);
        yatest_log("item size %i: cache %i/%i (acquire)", 1 << i, cache->weight_current, cache->weight_max);
        cache_release_item(cache, item);
    }

    if(cache_item_expected_count != 1)
    {
        yatest_err("expected 1 items, got %i", cache_item_expected_count);
        return 1;
    }

    cache_delete(cache);

    if(cache_item_expected_count != 0)
    {
        yatest_err("expected 0 items, got %i", cache_item_expected_count);
        return 1;
    }

    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(cache_test)
YATEST(cache_maintenance_test)
YATEST_TABLE_END

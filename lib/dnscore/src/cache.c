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

/**-----------------------------------------------------------------------------
 * @defgroup streaming Streams
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/cache.h"

static int cache_ptr_treemap_node_compare(const void *key_a, const void *key_b)
{
    const cache_item_key_t *ka = key_a;
    const cache_item_key_t *kb = key_b;
    int64_t                 d = ka->key_size - kb->key_size;
    if(d == 0)
    {
        return memcmp(ka->key, kb->key, ka->key_size);
    }
    else
    {
        return (int)d; // assuming the key isn't bigger than 2GB ...
    }
}

static void cache_item_dummy_delete(void *data)
{
    // nop
    (void)data;
}

/**
 * Creates a new instance of a cache_t with the given weight_max
 */

cache_t *cache_new_instance(int32_t weight_max)
{
    if(weight_max > 0)
    {
        cache_t *cache;
        ZALLOC_OBJECT_OR_DIE(cache, cache_t, GENERIC_TAG);
        ptr_treemap_init(&cache->items);
        cache->items.compare = cache_ptr_treemap_node_compare;
        list_dl_nodata_init(&cache->mru);
        cache->weight_current = 0;
        cache->weight_max = weight_max;
        mutex_init_recursive(&cache->items_mtx);
        return cache;
    }
    else
    {
        return NULL;
    }
}

/**
 * Removes items at the end of the MRU until the current weight is below or equal the max weight
 */

void cache_maintain(cache_t *cache)
{
    mutex_lock(&cache->items_mtx); // memory wall
    if(cache->weight_current > cache->weight_max)
    {
        assert(list_dl_nodata_size(&cache->mru) > 0);
        // from the back to the front of the MRU
        list_dl_nodata_node_t *first_node = list_dl_nodata_first_node(&cache->mru);
        list_dl_nodata_node_t *mru_node = list_dl_nodata_last_node(&cache->mru);
        while(mru_node != first_node)
        {
            cache_item_t          *item = (cache_item_t *)(((uint8_t *)mru_node) - offsetof(cache_item_t, mru_node));
            list_dl_nodata_node_t *prev_mru_node = mru_node->prev;
            if(item->rc == 1)
            {
                // delete
                cache->weight_current -= item->weight;
                list_dl_nodata_remove_node(&cache->mru, mru_node);
                ptr_treemap_delete(&cache->items, &item->key);
                cache_release_item(cache, item);
                if(cache->weight_current < cache->weight_max)
                {
                    break;
                }
            }
            mru_node = prev_mru_node;
        }
    }
    mutex_unlock(&cache->items_mtx);
}

/**
 * Removes every item from the cache
 */

void cache_clear(cache_t *cache)
{
    mutex_lock(&cache->items_mtx);
    assert(list_dl_nodata_size(&cache->mru) > 0);
    // from the back to the front of the MRU

    while(list_dl_nodata_size(&cache->mru) > 0)
    {
        list_dl_nodata_node_t *mru_node = list_dl_nodata_remove_first_node(&cache->mru);
        cache_item_t          *item = (cache_item_t *)(((uint8_t *)mru_node) - offsetof(cache_item_t, mru_node));
        // delete
        ptr_treemap_delete(&cache->items, &item->key);
        cache_release_item(cache, item);
    }

    cache->weight_current = 0;

    mutex_unlock(&cache->items_mtx);
}

/**
 * Deletes the cache
 */

void cache_delete(cache_t *cache)
{
    cache_clear(cache);
    mutex_finalize(&cache->items_mtx);
}

/**
 * Create a new item with the given key or return the existing one.
 * Updates the timestamp.
 * Moves the item to the head of the MRU.
 *
 * If the item is created, it's the responsibility of the caller to set
 * the data, clear and weight fields.
 *
 * Increases the RC
 */

cache_item_t *cache_acquire_item(cache_t *cache, cache_item_key_t key)
{
    mutex_lock(&cache->items_mtx);
    ptr_treemap_node_t *node = ptr_treemap_find(&cache->items, &key);
    if(node != NULL)
    {
        cache_item_t *item = node->value;
        list_dl_nodata_remove_node(&cache->mru, &item->mru_node);
        list_dl_nodata_insert_node(&cache->mru, &item->mru_node);
        ++item->rc;
        mutex_unlock(&cache->items_mtx);
        return item;
    }
    else
    {
        cache_item_t *item;
        ZALLOC_OBJECT_OR_DIE(item, cache_item_t, GENERIC_TAG);
        item->key = key;
        item->data = NULL;
        item->clear = cache_item_dummy_delete;
        item->timestamp = timeus();
        item->rc = 2;
        item->weight = 0;
        node = ptr_treemap_insert(&cache->items, &item->key);
        node->value = item;
        list_dl_nodata_insert_node(&cache->mru, &item->mru_node);
        mutex_unlock(&cache->items_mtx);
        return item;
    }
}

void cache_update_item(cache_t *cache, cache_item_t *item, void *data, cache_item_delete_method *clear, int32_t weight)
{
    int32_t dw = weight - item->weight;
    item->clear(data);
    item->data = data;
    item->clear = clear;
    item->weight = weight;
    cache->weight_current += dw;
    cache_maintain(cache);
}

/**
 * Decreases the RC
 *
 * The RC is used to know if a cache is in use, avoiding its destruction.
 */

void cache_release_item(cache_t *cache, cache_item_t *item)
{
    if(--item->rc == 0) // not even in the cache ...
    {
        mutex_lock(&cache->items_mtx);

        item->clear(item->data);
        cache_item_key_finalise(&item->key);
        ZFREE_OBJECT(item);

        mutex_unlock(&cache->items_mtx);
    }
}

/** @} */

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
 * @defgroup base Base conversion functions
 * @ingroup dnscore
 * @brief Base 64 codec
 *
 * Base 64 codec functions
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/ptr_treemap.h>
#include <dnscore/list_dl_nodata.h>
#include <dnscore/mutex.h>

typedef void cache_item_delete_method(void *data);

struct cache_item_key_s
{
    void   *key; // zallocated
    int64_t key_size;
};

typedef struct cache_item_key_s cache_item_key_t;

static inline void              cache_item_key_init(cache_item_key_t *item_key, int64_t key_size)
{
    ZALLOC_ARRAY_OR_DIE(uint8_t *, item_key->key, key_size, GENERIC_TAG);
    item_key->key_size = key_size;
}

static inline void cache_item_key_finalise(cache_item_key_t *item_key) { ZFREE_ARRAY(item_key->key, item_key->key_size); }

struct cache_item_s
{
    cache_item_key_t          key;
    void                     *data;
    cache_item_delete_method *clear;
    list_dl_nodata_node_t     mru_node;
    int64_t                   timestamp;
    atomic_int                rc;
    int32_t                   weight;
};

typedef struct cache_item_s cache_item_t;

struct cache_s
{
    ptr_treemap_t    items;
    list_dl_nodata_t mru;
    atomic_int       weight_current;
    int              weight_max;
    pthread_mutex_t  items_mtx;
};

typedef struct cache_s cache_t;

/**
 * Creates a new instance of a cache_t with the given weight_max
 */

cache_t *cache_new_instance(int32_t weight_max);

/**
 * Removes items at the end of the MRU until the current weight is below or equal the max weight
 */

void cache_maintain(cache_t *cache);

/**
 * Removes every item from the cache
 */

void cache_clear(cache_t *cache);

/**
 * Deletes the cache
 */

void cache_delete(cache_t *cache);

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

cache_item_t *cache_acquire_item(cache_t *cache, cache_item_key_t key);

/**
 * Updates the cache entry
 */

void cache_update_item(cache_t *cache, cache_item_t *item, void *data, cache_item_delete_method *clear, int32_t weight);

/**
 * Decreases the RC
 *
 * The RC is used to know if a cache is in use, avoiding its destruction.
 */

void cache_release_item(cache_t *cache, cache_item_t *item);

/** @} */

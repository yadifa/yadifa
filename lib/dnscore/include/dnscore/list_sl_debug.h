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
 * @defgroup collections Generic collections functions
 * @ingroup dnscore
 * @brief A node-based single linked list
 *
 * A node-based single linked list
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

/*    ------------------------------------------------------------
 *
 *      INCLUDES
 */

#include <dnscore/sys_types.h>
#include <dnscore/zalloc.h>

/*    ------------------------------------------------------------
 *
 *      STRUCTS
 */

/**
 * Linked list for interface data
 *
 * (looks like a no-header no-sentinel single-linked list of strings)
 *
 * head : the base structure of the list
 * item : the concept of what is being stored in the list
 * node : holds the item
 * data : the reference to the item (which can be called data because it's type-less)
 *
 */

#define LISTSLND_TAG 0x444e4c535453494c

struct list_sl_debug_node_s
{
    struct list_sl_debug_node_s *next;
    void                        *data;
};

typedef struct list_sl_debug_node_s list_sl_debug_node_t;

/// The sentiel is a butchered node, meant to avoid the (useless) data field.

struct list_sl_debug_node_sentiel_s
{
    struct list_sl_debug_node_s *next;
};

typedef struct list_sl_debug_node_sentiel_s list_sl_debug_node_sentiel_t;

struct list_sl_debug_s
{
    list_sl_debug_node_t        *first;
    list_sl_debug_node_sentiel_t sentinel;
    uint32_t                     size;
};

typedef struct list_sl_debug_s list_sl_debug_t;

/*    ------------------------------------------------------------
 *
 *      PROTOTYPES
 */

/**
 * Initialises a list.
 *
 * @param list
 */

static inline void list_sl_debug_init(list_sl_debug_t *list)
{
    void *dummy = &list->sentinel;
    list->first = (list_sl_debug_node_t *)dummy;
    list->sentinel.next = NULL;
    list->size = 0;
}

static inline list_sl_debug_t *list_sl_debug_new_instance()
{
    list_sl_debug_t *list = (list_sl_debug_t *)debug_malloc_unmonitored(sizeof(list_sl_debug_t));
    list_sl_debug_init(list);
    return list;
}

/**
 * Adds an item at the head of the list.
 *
 * @param list
 * @param data
 */

void list_sl_debug_insert(list_sl_debug_t *list, void *data);

/**
 *
 * Adds an item to the list.
 * Effectively inserts the item.
 *
 * @param list
 * @param data
 */

static inline void list_sl_debug_add(list_sl_debug_t *list, void *data) { list_sl_debug_insert(list, data); }
/*
static inline void
list_sl_debug_add_list(list_sl_debug_s *list, list_sl_debug_s *list_to_append)
{

}
*/

/**
 * Remove the first item from the list.
 * Deletes the node but not the data.
 * The data is returned.
 *
 * @param list
 * @return the data or NULL if the list is empty
 */

void *list_sl_debug_remove_first(list_sl_debug_t *list);

/**
 *
 * Adds an item to the list, seen as a stack.
 * Effectively inserts the item.
 *
 * @param list
 * @param data
 */

static inline void list_sl_debug_push(list_sl_debug_t *list, void *data) { list_sl_debug_insert(list, data); }

/**
 *
 * Adds an item to the list, seen as a stack.
 * Effectively inserts the item.
 *
 * @param list
 * @param data
 */

static inline void *list_sl_debug_pop(list_sl_debug_t *list)
{
    void *data = list_sl_debug_remove_first(list);
    return data;
}

/**
 * Remove the first item that points to data;
 *
 * @param list
 * @param data
 * @return true if an item has been deleted
 */

bool list_sl_debug_remove(list_sl_debug_t *list, void *data);

/**
 * Remove all items from the list.
 * Deletes the nodes but not the data.
 *
 * @param list
 */

void               list_sl_debug_clear(list_sl_debug_t *list);

static inline void list_sl_debug_delete(list_sl_debug_t *list)
{
    list_sl_debug_clear(list);
    debug_free_unmonitored(list);
}
/**
 * Iterates through the items of the function, calling the comparator.
 *
 * The comparator must return:
 *
 * COLLECTION_ITEM_SKIP                 : go to next item
 * COLLECTION_ITEM_STOP                 : stop processing, return NULL
 * COLLECTION_ITEM_PROCESS_THEN_STOP    : stop processing, return node data
 *
 * @param list
 * @param comparator
 *
 * @return a matching node or NULL
 */

void *list_sl_debug_search(list_sl_debug_t *list, result_callback_function_t *comparator, void *parm);

/**
 * Iterates through the items of the function, calling the comparator.
 *
 * The comparator must return:
 *
 * COLLECTION_ITEM_SKIP                 : go to next item
 * COLLECTION_ITEM_PROCESS              : delete, then go to next item
 * COLLECTION_ITEM_STOP                 : stop processing
 * COLLECTION_ITEM_PROCESS_THEN_STOP    : delete, then stop processing
 *
 * @param list
 * @param comparator
 *
 * @return true if at least one item has been deleted, false otherwise.
 */

bool list_sl_debug_remove_match(list_sl_debug_t *list, result_callback_function_t *comparator, void *parm);

/**
 *
 * Returns the size of the list
 *
 * @param list
 * @return the size of the list
 */

static inline uint32_t list_sl_debug_size(const list_sl_debug_t *list) { return list->size; }

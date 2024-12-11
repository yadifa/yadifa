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

/**
 * Linked list helper, meant to be used in more complex data (e.g. tcp_manager_socket_context_t ...)
 */

// 16 bytes

struct list_dl_nodata_node_s
{
    struct list_dl_nodata_node_s *next;
    struct list_dl_nodata_node_s *prev;
};

typedef struct list_dl_nodata_node_s list_dl_nodata_node_t;

// 24 bytes

struct list_dl_nodata_s
{
    list_dl_nodata_node_t sentinel;
    uint32_t              size;
};

typedef struct list_dl_nodata_s list_dl_nodata_t;

/**
 * Removes the node from the list, the node is not freed
 *
 * @param list
 * @param node
 */

void list_nodata_dl_remove_node(list_dl_nodata_t *list, list_dl_nodata_node_t *node);

/**
 * Initialises a list.
 *
 * @param list
 */

static inline void list_dl_nodata_init(list_dl_nodata_t *list)
{
    ZEROMEMORY(list, sizeof(list_dl_nodata_t));
    list->sentinel.next = &list->sentinel;
    list->sentinel.prev = &list->sentinel;
}

static inline list_dl_nodata_t *list_dl_nodata_new_instance()
{
    list_dl_nodata_t *list;
    ZALLOC_OBJECT_OR_DIE(list, list_dl_nodata_t, GENERIC_TAG);
    list_dl_nodata_init(list);
    return list;
}

static inline void list_dl_nodata_insert_node(list_dl_nodata_t *list, list_dl_nodata_node_t *node)
{
    node->next = list->sentinel.next;
    node->prev = &list->sentinel;
    list->sentinel.next->prev = node;
    list->sentinel.next = node;

#if DEBUG
    assert(node->next != NULL);
    assert(node->prev != NULL);
    assert(node->next->next != NULL);
    assert(node->next->prev != NULL);
    assert(node->prev->next != NULL);
    assert(node->prev->prev != NULL);
    assert(list->sentinel.next->prev == &list->sentinel);
    assert(list->sentinel.next != NULL);
    assert(list->sentinel.prev != NULL);
#endif

    list->size++;
}

static inline void list_dl_nodata_append_node(list_dl_nodata_t *list, list_dl_nodata_node_t *node)
{
    node->next = &list->sentinel;
    node->prev = list->sentinel.prev;
    list->sentinel.prev->next = node;
    list->sentinel.prev = node;

#if DEBUG
    assert(node->next != NULL);
    assert(node->prev != NULL);
    assert(node->next->next != NULL);
    assert(node->next->prev != NULL);
    assert(node->prev->next != NULL);
    assert(node->prev->prev != NULL);
    assert(list->sentinel.prev->next == &list->sentinel);
    assert(list->sentinel.next != NULL);
    assert(list->sentinel.prev != NULL);
#endif
    list->size++;
}

static inline list_dl_nodata_node_t *list_dl_nodata_first_node(list_dl_nodata_t *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->sentinel.next != &list->sentinel);
        assert(list->sentinel.prev != &list->sentinel);
        assert(list->sentinel.next != NULL);
        assert(list->sentinel.prev != NULL);
#endif

        return list->sentinel.next;
    }
    else
    {
        return NULL;
    }
}

static inline list_dl_nodata_node_t *list_dl_nodata_remove_first_node(list_dl_nodata_t *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->sentinel.next != &list->sentinel);
        assert(list->sentinel.prev != &list->sentinel);
        assert(list->sentinel.next != NULL);
        assert(list->sentinel.prev != NULL);
#endif
        list_dl_nodata_node_t *node = list->sentinel.next;
        assert(node->next != NULL);
        assert(node->prev != NULL);
        list->sentinel.next = node->next;
        node->next->prev = &list->sentinel;
        list->size--;
        assert(node->next->next != NULL);
        assert(node->next->prev != NULL);
        assert(node->prev->next != NULL);
        assert(node->prev->prev != NULL);
        node->next = NULL;
        node->prev = NULL;
#if DEBUG
        assert(list->sentinel.next->prev == &list->sentinel);
        assert(list->sentinel.next != NULL);
        assert(list->sentinel.prev != NULL);
#endif
        return node;
    }
    else
    {
        return NULL;
    }
}

static inline list_dl_nodata_node_t *list_dl_nodata_last_node(list_dl_nodata_t *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->sentinel.next != &list->sentinel);
        assert(list->sentinel.prev != &list->sentinel);
        assert(list->sentinel.next != NULL);
        assert(list->sentinel.prev != NULL);
#endif

        return list->sentinel.prev;
    }
    else
    {
        return NULL;
    }
}

static inline list_dl_nodata_node_t *list_dl_nodata_remove_last_node(list_dl_nodata_t *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->sentinel.next != &list->sentinel);
        assert(list->sentinel.prev != &list->sentinel);
        assert(list->sentinel.next != NULL);
        assert(list->sentinel.prev != NULL);
#endif

        list_dl_nodata_node_t *node = list->sentinel.prev;

#if DEBUG
        assert(node->next != NULL);
        assert(node->prev != NULL);
#endif
        list->sentinel.prev = node->prev;
        node->prev->next = &list->sentinel;

        list->size--;

#if DEBUG
        assert(node->next->next != NULL);
        assert(node->next->prev != NULL);
        assert(node->prev->next != NULL);
        assert(node->prev->prev != NULL);

        assert(list->sentinel.prev->next == &list->sentinel);
        assert(list->sentinel.next != NULL);
        assert(list->sentinel.prev != NULL);
#endif
        node->next = NULL;
        node->prev = NULL;

        return node;
    }
    else
    {
        return NULL;
    }
}

void list_dl_nodata_remove_node(list_dl_nodata_t *list, list_dl_nodata_node_t *node);

void list_dl_nodata_move_node_to_first_position(list_dl_nodata_t *list, list_dl_nodata_node_t *node);

/**
 *
 * Returns the size of the list
 *
 * @param list
 * @return the size of the list
 */

static inline uint32_t list_dl_nodata_size(const list_dl_nodata_t *list)
{
#if DEBUG
    assert(list->sentinel.next != NULL);
    assert(list->sentinel.prev != NULL);
#endif
    return list->size;
}

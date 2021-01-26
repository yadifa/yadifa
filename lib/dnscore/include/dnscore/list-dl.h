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

/** @defgroup collections Generic collections functions
 *  @ingroup dnscore
 *  @brief A node-based single linked list
 *
 * A node-based single linked list
 *
 * @{
 */
/*----------------------------------------------------------------------------*/
#ifndef LIST_DL_H_
#define LIST_DL_H_

/*    ------------------------------------------------------------
 *
 *      INCLUDES
 */

#include <dnscore/sys_types.h>
#include <dnscore/zalloc.h>

/**
 * Linked list for interface data
 * 
 * (looks like a no-header no-sentinel single-linked list of strings)
 * 
 * 
 * head : the base structure of the list
 * item : the concept of what is being stored in the list
 * node : holds the item
 * data : the reference to the item (which can be called data because it's type-less)
 * 
 */

#define LISTDL_TAG 0x4c445453494c
#define LISTDLND_TAG 0x444e4c445453494c

typedef struct list_dl_node_s list_dl_node_s;

// 24 bytes

struct list_dl_node_s
{
    struct list_dl_node_s *next;
    struct list_dl_node_s *prev;
    void *data;
};

typedef struct list_dl_node_sentiel_s list_dl_node_sentiel_s;

// 16 bytes

struct list_dl_node_sentiel_s
{
    struct list_dl_node_s *next;
    struct list_dl_node_s *prev;
};

typedef struct list_dl_s list_dl_s;

// 36 bytes

struct list_dl_s
{
    list_dl_node_sentiel_s head_sentinel;
    list_dl_node_sentiel_s tail_sentinel;
    u32 size;
};

typedef struct list_dl_iterator_s list_dl_iterator_s;

struct list_dl_iterator_s
{
    list_dl_s *list;
    list_dl_node_s *current_node;
};

/*    ------------------------------------------------------------
 *
 *      PROTOTYPES
 */

static inline void
list_dl_iterator_init(list_dl_iterator_s *iter, list_dl_s *list)
{
    iter->list = list;
    iter->current_node = (list_dl_node_s*)&list->head_sentinel;
}

static inline bool
list_dl_iterator_has_next(list_dl_iterator_s *iter)
{
    return iter->current_node->next != (list_dl_node_s*)&iter->list->tail_sentinel;
}

static inline void*
list_dl_iterator_next(list_dl_iterator_s *iter)
{
    iter->current_node = iter->current_node->next;
    return iter->current_node->data;
}

/**
 * Removes the node from the list, the node is not freed
 * 
 * @param list
 * @param node
 */

void list_dl_remove_node(list_dl_s *list, list_dl_node_s *node);

static inline void*
list_dl_iterator_remove(list_dl_iterator_s *iter)
{
    list_dl_node_s *current =  iter->current_node;
    iter->current_node = current->prev;
    void *data = current->data;
    list_dl_remove_node(iter->list, current);
    return data;
}

/**
 * Inserts data BEFORE the current node
 * 
 * @param iter
 * @param data
 * @return 
 */

bool list_dl_iterator_insert(list_dl_iterator_s *iter, void *data);

/**
 * Inserts data BEFORE the current node
 * 
 * @param iter
 * @param data
 * @return 
 */

bool list_dl_iterator_append(list_dl_iterator_s *iter, void *data);

static inline list_dl_node_s *
list_dl_node_alloc()
{
    list_dl_node_s *node;
    ZALLOC_OBJECT_OR_DIE( node, list_dl_node_s, LISTDLND_TAG);
    return node;
}

static inline void
list_dl_node_free(list_dl_node_s *node)
{
    ZFREE_OBJECT(node);
}

/**
 * Initialises a list.
 * 
 * @param list
 */

static inline void
list_dl_init(list_dl_s *list)
{
    ZEROMEMORY(list, sizeof(list_dl_s));
    list->head_sentinel.next = (list_dl_node_s*)&list->tail_sentinel;
    list->tail_sentinel.prev = (list_dl_node_s*)&list->head_sentinel;
}

static inline list_dl_s*
list_dl_new_instance()
{
    list_dl_s *list;
    ZALLOC_OBJECT_OR_DIE(list, list_dl_s, LISTDL_TAG);
    list_dl_init(list);
    return list;
}

/**
 * Adds an item at the head of the list.
 * 
 * @param list
 * @param data
 */

static inline void
list_dl_insert(list_dl_s *list, void *data)
{
    list_dl_node_s *node;
    ZALLOC_OBJECT_OR_DIE( node, list_dl_node_s, LISTDLND_TAG);
    node->next = list->head_sentinel.next;
    node->prev = (list_dl_node_s*)&list->head_sentinel;
    list->head_sentinel.next->prev = node;
    list->head_sentinel.next = node;
    
#if DEBUG
    assert(list->head_sentinel.next->prev == (list_dl_node_s*)&list->head_sentinel);
#endif
    
    node->data = data;
    list->size++;
}

void list_dl_move_to_first_position(list_dl_s *list, void *data);

static inline void
list_dl_insert_node(list_dl_s *list, list_dl_node_s *node)
{
    node->next = list->head_sentinel.next;
    node->prev = (list_dl_node_s*)&list->head_sentinel;
    list->head_sentinel.next->prev = node;
    list->head_sentinel.next = node;
    
#if DEBUG
    assert(list->head_sentinel.next->prev == (list_dl_node_s*)&list->head_sentinel);
#endif
    
    list->size++;
}

/**
 * Adds an item at the tail of the list.
 * 
 * @param list
 * @param data
 */

static inline void
list_dl_append(list_dl_s *list, void *data)
{
    list_dl_node_s *node;
    ZALLOC_OBJECT_OR_DIE( node, list_dl_node_s, LISTDLND_TAG);
    node->next = (list_dl_node_s*)&list->tail_sentinel;
    node->prev = list->tail_sentinel.prev;
    list->tail_sentinel.prev->next = node;
    list->tail_sentinel.prev = node;
    
#if DEBUG
    assert(list->tail_sentinel.prev->next == (list_dl_node_s*)&list->tail_sentinel);
#endif
    
    node->data = data;
    list->size++;
}

static inline void
list_dl_append_node(list_dl_s *list, list_dl_node_s *node)
{
    node->next = (list_dl_node_s*)&list->tail_sentinel;
    node->prev = list->tail_sentinel.prev;
    list->tail_sentinel.prev->next = node;
    list->tail_sentinel.prev = node;
    
#if DEBUG
    assert(list->tail_sentinel.prev->next == (list_dl_node_s*)&list->tail_sentinel);
#endif
    list->size++;
}

static inline void
list_dl_append_list(list_dl_s *list, list_dl_s *list_to_add)
{
    if(list_to_add->size > 0)
    {
        list_dl_node_s *node;
        
        node = list_to_add->head_sentinel.next;
        node->prev = list->tail_sentinel.prev;
        list->tail_sentinel.prev->next = node;
        
        node = list_to_add->tail_sentinel.prev;
        node->next = (list_dl_node_s*)&list->tail_sentinel;
        list->tail_sentinel.prev = node;
        
        list->size += list_to_add->size;
        
        list_to_add->head_sentinel.next = (list_dl_node_s*)&list_to_add->tail_sentinel;
        list_to_add->tail_sentinel.prev = (list_dl_node_s*)&list_to_add->head_sentinel;
        list_to_add->size = 0;
    }
}

/**
 * 
 * Adds an item to the list.
 * Effectively inserts the item.
 * 
 * @param list
 * @param data
 */

static inline void
list_dl_add(list_dl_s *list, void *data)
{
    list_dl_append(list, data);
}

/**
 * Remove the first item from the list.
 * Deletes the node but not the data.
 * The data is returned.
 * 
 * @param list
 * @return the data or NULL if the list is empty
 */

static inline void*
list_dl_remove_first(list_dl_s *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->head_sentinel.next != (list_dl_node_s*)&list->tail_sentinel);
        assert(list->tail_sentinel.prev != (list_dl_node_s*)&list->head_sentinel);
        assert(list->head_sentinel.next != NULL);
        assert(list->tail_sentinel.prev != NULL);
#endif
        list_dl_node_s *node = list->head_sentinel.next;
        list->head_sentinel.next = node->next;
        node->next->prev = (list_dl_node_s*)&list->head_sentinel;
        list->size--;
        void *data = node->data;
        ZFREE_OBJECT(node);
#if DEBUG
        assert(list->head_sentinel.next->prev == (list_dl_node_s*)&list->head_sentinel);
#endif
        return data;
    }
    else
    {
        return NULL;
    }
}

/**
 * Returns the data of the first item on the list
 * 
 * @param list
 * @return the data or NULL if the list is empty
 */

static inline void*
list_dl_peek_first(list_dl_s *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->head_sentinel.next != (list_dl_node_s*)&list->tail_sentinel);
        assert(list->tail_sentinel.prev != (list_dl_node_s*)&list->head_sentinel);
        assert(list->head_sentinel.next != NULL);
        assert(list->tail_sentinel.prev != NULL);
#endif
        
        list_dl_node_s *node = list->head_sentinel.next;
        void *data = node->data;
        
        return data;
    }
    else
    {
        return NULL;
    }
}

static inline list_dl_node_s*
list_dl_first_node(list_dl_s *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->head_sentinel.next != (list_dl_node_s*)&list->tail_sentinel);
        assert(list->tail_sentinel.prev != (list_dl_node_s*)&list->head_sentinel);
        assert(list->head_sentinel.next != NULL);
        assert(list->tail_sentinel.prev != NULL);
#endif
        
        return list->head_sentinel.next;
    }
    else
    {
        return NULL;
    }
}

static inline list_dl_node_s*
list_dl_remove_first_node(list_dl_s *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->head_sentinel.next != (list_dl_node_s*)&list->tail_sentinel);
        assert(list->tail_sentinel.prev != (list_dl_node_s*)&list->head_sentinel);
        assert(list->head_sentinel.next != NULL);
        assert(list->tail_sentinel.prev != NULL);
#endif   
        list_dl_node_s *node = list->head_sentinel.next;
        list->head_sentinel.next = node->next;
        node->next->prev = (list_dl_node_s*)&list->head_sentinel;
        list->size--;
        
#if DEBUG
        assert(list->head_sentinel.next->prev == (list_dl_node_s*)&list->head_sentinel);
#endif
        return node;
    }
    else
    {
        return NULL;
    }
}

/**
 * Remove the last item from the list.
 * Deletes the node but not the data.
 * The data is returned.
 * 
 * @param list
 * @return the data or NULL if the list is empty
 */

static inline void*
list_dl_remove_last(list_dl_s *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->head_sentinel.next != (list_dl_node_s*)&list->tail_sentinel);
        assert(list->tail_sentinel.prev != (list_dl_node_s*)&list->head_sentinel);
        assert(list->head_sentinel.next != NULL);
        assert(list->tail_sentinel.prev != NULL);
#endif
        
        list_dl_node_s *node = list->tail_sentinel.prev;
        list->tail_sentinel.prev = node->prev;
        node->prev->next = (list_dl_node_s*)&list->tail_sentinel;
        list->size--;
        void *data = node->data;
        ZFREE_OBJECT(node);
        
#if DEBUG
        assert(list->tail_sentinel.prev->next == (list_dl_node_s*)&list->tail_sentinel);
#endif
        return data;
    }
    else
    {
        return NULL;
    }
}

static inline void
list_dl_move_last_to_first(list_dl_s *list)
{
    if(list->size > 1)
    {
#if DEBUG
        assert(list->head_sentinel.next != (list_dl_node_s*)&list->tail_sentinel);
        assert(list->tail_sentinel.prev != (list_dl_node_s*)&list->head_sentinel);
        assert(list->head_sentinel.next != NULL);
        assert(list->tail_sentinel.prev != NULL);
#endif
        // remove last node
        
        list_dl_node_s *node = list->tail_sentinel.prev;
        list->tail_sentinel.prev = node->prev;
        node->prev->next = (list_dl_node_s*)&list->tail_sentinel;
        
        // insert node
        
        node->next = list->head_sentinel.next;
        node->prev = (list_dl_node_s*)&list->head_sentinel;
        list->head_sentinel.next->prev = node;
        list->head_sentinel.next = node;
        
#if DEBUG
        assert(list->tail_sentinel.prev->next == (list_dl_node_s*)&list->tail_sentinel);
#endif
    }
}

/**
 * Returns the data of the last item on the list
 * 
 * @param list
 * @return the data or NULL if the list is empty
 */

static inline void*
list_dl_peek_last(list_dl_s *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->head_sentinel.next != (list_dl_node_s*)&list->tail_sentinel);
        assert(list->tail_sentinel.prev != (list_dl_node_s*)&list->head_sentinel);
        assert(list->head_sentinel.next != NULL);
        assert(list->tail_sentinel.prev != NULL);
#endif
        
        list_dl_node_s *node = list->tail_sentinel.prev;
        void *data = node->data;
        
        return data;
    }
    else
    {
        return NULL;
    }
}

static inline list_dl_node_s*
list_dl_last_node(list_dl_s *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->head_sentinel.next != (list_dl_node_s*)&list->tail_sentinel);
        assert(list->tail_sentinel.prev != (list_dl_node_s*)&list->head_sentinel);
        assert(list->head_sentinel.next != NULL);
        assert(list->tail_sentinel.prev != NULL);
#endif
        
        return list->tail_sentinel.prev;
    }
    else
    {
        return NULL;
    }
}

static inline list_dl_node_s *
list_dl_remove_last_node(list_dl_s *list)
{
    if(list->size > 0)
    {
#if DEBUG
        assert(list->head_sentinel.next != (list_dl_node_s*)&list->tail_sentinel);
        assert(list->tail_sentinel.prev != (list_dl_node_s*)&list->head_sentinel);
        assert(list->head_sentinel.next != NULL);
        assert(list->tail_sentinel.prev != NULL);
#endif
        
        list_dl_node_s *node = list->tail_sentinel.prev;
        list->tail_sentinel.prev = node->prev;
        node->prev->next = (list_dl_node_s*)&list->tail_sentinel;
        list->size--;
        
#if DEBUG
        assert(list->tail_sentinel.prev->next == (list_dl_node_s*)&list->tail_sentinel);
#endif
        return node;
    }
    else
    {
        return NULL;
    }
}


/**
 * Enqueues the item in the list, seen as a queue.
 * 
 * @param list
 * @param data
 */

static inline void
list_dl_enqueue(list_dl_s *list, void *data)
{
    list_dl_insert(list, data);
}

/**
 * Dequeues the item from the list, seen as a queue.
 * 
 * @param list
 * @return an item or NULL if the list/queue is empty
 */

static inline void*
list_dl_dequeue(list_dl_s *list)
{
    void *data = list_dl_remove_last(list);
    return data;
}

/**
 * Remove the first item that points to data;
 * 
 * @param list
 * @param data
 * @return TRUE if an item has been deleted
 */

bool list_dl_remove(list_dl_s *list, const void *data);

/**
 * Removes the node from the list, the node is not freed
 * 
 * @param list
 * @param node
 */

void list_dl_remove_node(list_dl_s *list, list_dl_node_s *node);

/**
 * Remove the first item for which the match does not returns 0.
 * 
 * @param list
 * @param match a callback function called with the data and args
 * @param args
 * @return 
 */

bool list_dl_remove_matching(list_dl_s *list, result_callback_function *match, void *args);

/**
 * Remove all the items for which the match does not returns 0.
 * 
 * @param list
 * @param match a callback function called with the data and args
 * @param args
 * @return 
 */

bool list_dl_remove_all_matching(list_dl_s *list, result_callback_function *match, void *args);

/**
 * Remove all items from the list.
 * Deletes the nodes but not the data.
 * 
 * @param list
 */

void list_dl_clear(list_dl_s *list);

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

void *list_dl_search(list_dl_s *list, result_callback_function *comparator, void *parm);

/**
 * 
 * Returns the index of that specific pointer into the list
 * Linear search (slow)
 * 
 * @param list
 * @param comparator
 * @return 
 */

ya_result list_dl_indexof(list_dl_s *list, void *data);

void *list_dl_get(list_dl_s *list, int index);

ya_result list_dl_foreach(list_dl_s *list, result_callback_function *callback, void *caller_data);

bool list_dl_remove_matching_ptr(list_dl_s *list, void *ptr);

/**
 * 
 * Returns the size of the list
 * 
 * @param list
 * @return the size of the list
 */

static inline u32
list_dl_size(const list_dl_s *list)
{

    return list->size;
}

#endif /* LIST_DL_H_ */

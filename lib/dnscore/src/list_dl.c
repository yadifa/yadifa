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
 * @defgroup collections Generic collections functions
 * @ingroup dnscore
 * @brief A node-based single linked list
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * A node-based single linked list

 ------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include "dnscore/list_dl.h"

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/**
 * Remove the first item that points to data;
 *
 * @param list
 * @param data
 * @return true if an item has been deleted
 */

bool list_dl_remove(list_dl_t *list, const void *data)
{
    list_dl_node_t *node = list->head_sentinel.next;

    while(node->next != NULL)
    {
        if(data == node->data)
        {
            node->prev->next = node->next;
            node->next->prev = node->prev;
            list->size--;
#if DEBUG
            node->next = (struct list_dl_node_s *)~0;
            node->prev = (struct list_dl_node_s *)~0;
            node->data = (struct list_dl_node_s *)~0;
#endif
            ZFREE_OBJECT(node);
            return true;
        }

        node = node->next;
    }

    return false;
}

void list_dl_move_to_first_position(list_dl_t *list, void *data)
{
    list_dl_node_t *node = list->head_sentinel.next;

    // seek for the data

    while(node->next != NULL)
    {
        if(data == node->data)
        {
            // ensure it's not already at the first position

            if(node->prev != (list_dl_node_t *)&list->head_sentinel)
            {
                // remove part

                assert(list->size > 1);

                struct list_dl_node_s *next = node->next;
                struct list_dl_node_s *prev = node->prev;

                prev->next = next;
                next->prev = prev;

                // end of the remove part

                // insert part

                node->next = list->head_sentinel.next;
                node->next->prev = node;
                node->prev = (list_dl_node_t *)&list->head_sentinel;
                list->head_sentinel.next = node;

                // end of the insert part
            }

            return;
        }

        node = node->next;
    }

    list_dl_insert(list, data);
}

/**
 * Removes the node from the list, the node is not freed
 *
 * @param list
 * @param node
 */

void list_dl_remove_node(list_dl_t *list, list_dl_node_t *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = NULL;
    node->prev = NULL;

    list->size--;
}

bool list_dl_remove_matching_ptr(list_dl_t *list, void *ptr)
{
    list_dl_node_t *node = list->head_sentinel.next;

    while(node->next != NULL)
    {
        if(node->data == ptr)
        {
            node->prev->next = node->next;
            node->next->prev = node->prev;
            list->size--;
            ZFREE_OBJECT(node);
            return true;
        }

        node = node->next;
    }

    return false;
}

bool list_dl_remove_matching(list_dl_t *list, result_callback_function_t *match, void *args)
{
    list_dl_node_t *node = list->head_sentinel.next;

    while(node->next != NULL)
    {
        ya_result ret = match(node->data, args);
        if(ret != 0)
        {
            node->prev->next = node->next;
            node->next->prev = node->prev;
            list->size--;
            ZFREE_OBJECT(node);
            return true;
        }

        node = node->next;
    }

    return false;
}

bool list_dl_remove_all_matching(list_dl_t *list, result_callback_function_t *match, void *args)
{
    bool            ret = false;
    list_dl_node_t *node = list->head_sentinel.next;
    list_dl_node_t *node_next;
    while((node_next = node->next) != NULL)
    {
        if(match(node->data, args) != 0)
        {
            node->prev->next = node->next;
            node->next->prev = node->prev;
            list->size--;
            ZFREE_OBJECT(node);
            ret = true;
        }

        node = node_next;
    }

    return ret;
}

/**
 * Remove all items from the list.
 * Deletes the nodes but not the data.
 *
 * @param list
 */

void list_dl_clear(list_dl_t *list)
{
    list_dl_node_t *node = list->head_sentinel.next;

    while(node->next != NULL)
    {
        list_dl_node_t *tmp = node;

        node = node->next;

        ZFREE_OBJECT(tmp);
    }

    list->head_sentinel.next = (list_dl_node_t *)&list->tail_sentinel;
    list->size = 0;
}

/**
 * Iterates through the nodes of the function, calling the comparator.
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

void *list_dl_search(list_dl_t *list, result_callback_function_t *comparator, void *parm)
{
    list_dl_node_t *node = list->head_sentinel.next;

    while(node->next != NULL)
    {
        void *data = node->data;
        node = node->next;

        ya_result ret = comparator(data, parm);

        if((ret & COLLECTION_ITEM_STOP) != 0)
        {
            if((ret & COLLECTION_ITEM_PROCESS) != 0)
            {
                return data;
            }
            else
            {
                return NULL;
            }
        }
    }

    return NULL;
}

/**
 *
 * Returns the index of that specific pointer into the list
 * Linear search (slow)
 *
 * @param list
 * @param comparator
 * @return the index in the list or -1 if the item is wasn't found
 */

ya_result list_dl_indexof(list_dl_t *list, void *data)
{
    list_dl_node_t *node = list->head_sentinel.next;

    ya_result       index = 0;

    while(node->next != NULL)
    {
        if(node->data == data)
        {
            return index;
        }

        ++index;

        node = node->next;
    }

    return -1;
}

void *list_dl_get(list_dl_t *list, int32_t index)
{
    list_dl_node_t *node = list->head_sentinel.next;

    if((uint32_t)index < list->size)
    {
        while(index != 0)
        {
            node = node->next;
            index--;
        }

        return node->data;
    }
    else
    {
        return NULL;
    }
}

ya_result list_dl_foreach(list_dl_t *list, result_callback_function_t *callback, void *caller_data)
{
    list_dl_node_t *node = list->head_sentinel.next;

    while(node->next != NULL)
    {
        void *data = node->data;
        node = node->next;

        ya_result ret = callback(data, caller_data);

        if(FAIL(ret))
        {
            return ret;
        }

        if(ret == COLLECTION_ITEM_STOP)
        {
            break;
        }
    }

    return SUCCESS;
}

/**
 * Inserts data BEFORE the current node
 *
 * @param iter
 * @return
 */

bool list_dl_iterator_insert(list_dl_iterator_t *iter, void *data)
{
    if(iter->current_node != (list_dl_node_t *)&iter->list->head_sentinel)
    {
        list_dl_node_t *node;
        ZALLOC_OBJECT_OR_DIE(node, list_dl_node_t, LISTDLND_TAG);
        node->data = data;
        node->next = iter->current_node;
        node->prev = iter->current_node->prev;
        iter->current_node->prev = node;
        node->prev->next = node;
        ++iter->list->size;
        return true;
    }
    return false;
}

/**
 * Inserts data BEFORE the current node
 *
 * @param iter
 * @return
 */

bool list_dl_iterator_append(list_dl_iterator_t *iter, void *data)
{
    if(iter->current_node != (list_dl_node_t *)&iter->list->tail_sentinel)
    {
        list_dl_node_t *node;
        ZALLOC_OBJECT_OR_DIE(node, list_dl_node_t, LISTDLND_TAG);
        node->data = data;
        node->next = iter->current_node->next;
        node->prev = iter->current_node;
        iter->current_node->next = node;
        node->next->prev = node;
        ++iter->list->size;
        return true;
    }
    return false;
}

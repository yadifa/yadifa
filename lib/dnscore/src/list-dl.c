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
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "dnscore/dnscore-config.h"
#include "dnscore/list-dl.h"

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/**
 * Remove the first item that points to data;
 * 
 * @param list
 * @param data
 * @return TRUE if an item has been deleted
 */

bool
list_dl_remove(list_dl_s *list, const void *data)
{
    list_dl_node_s *node = list->head_sentinel.next;

    while(node->next != NULL)
    {
        if(data == node->data)
        {
            node->prev->next = node->next;
            node->next->prev = node->prev;
            list->size--;
            ZFREE_OBJECT(node);
            return TRUE;
        }

        node = node->next;
    }
    
    return FALSE;
}

void
list_dl_move_to_first_position(list_dl_s *list, void *data)
{
    list_dl_node_s *node = list->head_sentinel.next;
    
    // seek for the data

    while(node->next != NULL)
    {
        if(data == node->data)
        {
            // ensure it's not already at the first position

            if(node->prev != (list_dl_node_s*)&list->head_sentinel)
            {
                // remove part

                node->prev->next = node->next;
                node->next->prev = node->prev;

                // end of the remove part

                // insert part

                node->next = list->head_sentinel.next;
                node->prev = (list_dl_node_s*)&list->head_sentinel;
                list->head_sentinel.next->prev = node;
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

void
list_dl_remove_node(list_dl_s *list, list_dl_node_s *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = NULL;
    node->prev = NULL;
    
    list->size--;
}

bool
list_dl_remove_matching_ptr(list_dl_s *list, void *ptr)
{
    list_dl_node_s *node = list->head_sentinel.next;

    while(node->next != NULL)
    {
        if(node->data == ptr)
        {
            node->prev->next = node->next;
            node->next->prev = node->prev;
            list->size--;
            ZFREE_OBJECT(node);
            return TRUE;
        }

        node = node->next;
    }

    return FALSE;
}


bool
list_dl_remove_matching(list_dl_s *list, result_callback_function *match, void *args)
{
    list_dl_node_s *node = list->head_sentinel.next;

    while(node->next != NULL)
    {
        ya_result ret = match(node->data, args);
        if(ret != 0)
        {
            node->prev->next = node->next;
            node->next->prev = node->prev;
            list->size--;
            ZFREE_OBJECT(node);
            return TRUE;
        }

        node = node->next;
    }
    
    return FALSE;
}

bool
list_dl_remove_all_matching(list_dl_s *list, result_callback_function *match, void *args)
{
    list_dl_node_s *node = list->head_sentinel.next;
    list_dl_node_s *node_next;
    while((node_next = node->next) != NULL)
    {

        ya_result ret = match(node->data, args);
        if(ret != 0)
        {
            node->prev->next = node->next;
            node->next->prev = node->prev;
            list->size--;
            ZFREE_OBJECT(node);
        }

        node = node_next;
    }
    
    return FALSE;
}

/**
 * Remove all items from the list.
 * Deletes the nodes but not the data.
 * 
 * @param list
 */

void
list_dl_clear(list_dl_s *list)
{
    list_dl_node_s *node = list->head_sentinel.next;

    while(node->next != NULL)
    {
        list_dl_node_s *tmp = node;
        
        node = node->next;
        
        ZFREE_OBJECT(tmp);
    }
    
    list->head_sentinel.next = (list_dl_node_s*)&list->tail_sentinel;
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

void *list_dl_search(list_dl_s *list, result_callback_function *comparator, void *parm)
{
    list_dl_node_s *node = list->head_sentinel.next;

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

ya_result
list_dl_indexof(list_dl_s *list, void *data)
{
    list_dl_node_s *node = list->head_sentinel.next;
    
    ya_result index = 0;
    
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

void *
list_dl_get(list_dl_s *list, s32 index)
{
    list_dl_node_s *node = list->head_sentinel.next;
    
    if((u32)index < list->size)
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

ya_result list_dl_foreach(list_dl_s *list, result_callback_function *callback, void *caller_data)
{
    list_dl_node_s *node = list->head_sentinel.next;

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

bool
list_dl_iterator_insert(list_dl_iterator_s *iter, void *data)
{
    if(iter->current_node != (list_dl_node_s*)&iter->list->head_sentinel)
    {
        list_dl_node_s *node;
        ZALLOC_OBJECT_OR_DIE( node, list_dl_node_s, LISTDLND_TAG);
        node->data = data;
        node->next = iter->current_node;
        node->prev = iter->current_node->prev;
        iter->current_node->prev = node;
        node->prev->next = node;
        ++iter->list->size;
        return TRUE;
    }
    return FALSE;
}

/**
 * Inserts data BEFORE the current node
 * 
 * @param iter
 * @return 
 */

bool
list_dl_iterator_append(list_dl_iterator_s *iter, void *data)
{
    if(iter->current_node != (list_dl_node_s*)&iter->list->tail_sentinel)
    {
        list_dl_node_s *node;
        ZALLOC_OBJECT_OR_DIE( node, list_dl_node_s, LISTDLND_TAG);
        node->data = data;
        node->next = iter->current_node->next;
        node->prev = iter->current_node;
        iter->current_node->next = node;
        node->next->prev = node;
        ++iter->list->size;
        return TRUE;
    }
    return FALSE;
}

/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

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
            free(node);
            return TRUE;
        }

        node = node->next;
    }
    
    return NULL;
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
        
        free(tmp);
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

void *list_dl_search(list_dl_s *list, result_callback_function *comparator)
{
    list_dl_node_s *node = list->head_sentinel.next;

    while(node->next != NULL)
    {
        void *data = node->data;
        node = node->next;
        
        ya_result ret = comparator(data);
        
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
 * @return 
 */

ya_result
list_dl_indexof(list_dl_s *list, void *data)
{
    list_dl_node_s *node = list->head_sentinel.next;
    
    ya_result index = -1;

    while(node->next != NULL)
    {
        index++;
        
        if(node->data == data)
        {
            break;
        }
                
        node = node->next;
    }
    
    return index;
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

ya_result list_dl_foreach(list_dl_s *list, item_process_callback_function *callback, void *caller_data)
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
 * Iterates through the nodes of the function, calling the comparator.
 * 
 * The comparator must return:
 * 
 * < 0 : stop processing, return NULL
 * = 0 : no match
 * > 0 : stop processing, return node data
 * 
 * @param list
 * @param comparator
 * 
 * @return a matching node or NULL
 */

bool
list_dl_remove_match(list_dl_s *list, result_callback_function *comparator)
{
    list_dl_node_s *node = list->head_sentinel.next;
    list_dl_node_s *node_next;
    bool matched = FALSE;
    
    while((node_next = node->next) != NULL)
    {
        ya_result ret = comparator(node->data);
        
        if((ret & COLLECTION_ITEM_PROCESS) != 0)
        {
            node->prev->next = node->next;
            node->next->prev = node->prev;
            list->size--;
            free(node);
            matched = true;
        }
        
        if((ret & COLLECTION_ITEM_STOP) != 0)
        {
            break;
        }
        
        node = node_next;
    }
    
    return matched;
}


/** @} */

/*----------------------------------------------------------------------------*/

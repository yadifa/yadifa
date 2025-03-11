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
 *
 * A node-based single linked list
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include "dnscore/list_sl.h"

#define LISTDATA_TAG 0x415441445453494c

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/**
 * Remove the first item that points to data;
 *
 * @param list
 * @param data
 * @return true if an item has been deleted
 */

bool list_sl_remove(list_sl_t *list, void *data)
{
    list_sl_node_t **nodep = &list->first;
    list_sl_node_t  *node = list->first;

    while(node != (list_sl_node_t *)&list->sentinel)
    {
        if(data == node->data)
        {
            *nodep = node->next;
            list->size--;
            ZFREE_OBJECT(node);
            return true;
        }

        nodep = &node->next;
        node = node->next;
    }

    return false;
}

/**
 * Remove all items from the list.
 * Deletes the nodes but not the data.
 *
 * @param list
 */

void list_sl_clear(list_sl_t *list)
{
    list_sl_node_t *node = list->first;

    while(node != (list_sl_node_t *)&list->sentinel)
    {
        list_sl_node_t *tmp = node;
        node = node->next;
        ZFREE_OBJECT(tmp);
    }

    list->first = (list_sl_node_t *)&list->sentinel;
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

void *list_sl_search(list_sl_t *list, result_callback_function_t *comparator, void *parm)
{
    list_sl_node_t *node = list->first;

    while(node != (list_sl_node_t *)&list->sentinel)
    {
        ya_result ret = comparator(node->data, parm);

        if((ret & COLLECTION_ITEM_STOP) != 0)
        {
            if((ret & COLLECTION_ITEM_PROCESS) != 0)
            {
                return node->data;
            }
            else
            {
                return NULL;
            }
        }

        node = node->next;
    }

    return NULL;
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

bool list_sl_remove_match(list_sl_t *list, result_callback_function_t *comparator, void *parm)
{
    list_sl_node_t **nodep = &list->first;
    list_sl_node_t  *node = list->first;
    bool             matched = false;

    while(node != (list_sl_node_t *)&list->sentinel)
    {
        ya_result ret = comparator(node->data, parm);

        if((ret & COLLECTION_ITEM_PROCESS) != 0)
        {
            list_sl_node_t *next = node->next;
            *nodep = node->next;
            list->size--;
            ZFREE_OBJECT(node);
            matched = true;

            if((ret & COLLECTION_ITEM_STOP) != 0)
            {
                break;
            }

            node = next; // node is assigned its next value (stored in *nodep), it's not using freed memory with this.
            continue;
        }

        if((ret & COLLECTION_ITEM_STOP) != 0)
        {
            break;
        }

        nodep = &node->next;
        node = node->next; // node is assigned its next value (stored in *nodep), it's not using freed memory with this.
    }

    return matched;
}

/** @} */

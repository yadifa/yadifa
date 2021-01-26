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
 *  @brief A node-based single linked list where insertions are always sorted
 *
 * A node-based single linked list where insertions are always sorted by priority.
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "dnscore/dnscore-config.h"
#include "dnscore/basic-priority-queue.h"

#define LISTDATA_TAG 0x415441445453494c

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/**
 * Initialises a list.
 * 
 * @param list
 */

void
bpqueue_init(bpqueue_s *list)
{
    list->first = NULL;
    list->last = NULL;
    list->size = 0;
}

/**
 * Adds an item at the head of the list.
 * 
 * @param list
 * @param data
 */

void
bpqueue_enqueue(bpqueue_s *list, void *data, u32 priority)
{
    bpqueue_node_s *node;
    MALLOC_OBJECT_OR_DIE(node, bpqueue_node_s, BPQNODE_TAG);
    node->data = data;
    node->priority = priority;
    if(list->size > 0)
    {
        if(list->last->priority <= priority)
        {
            // append
            node->next = NULL;
            list->last->next = node;
            list->last = node;
        }
        else if(list->first->priority > priority)
        {
            node->next = list->first;
            list->first = node;
        }
        else
        {
            // seek and insert
            // there are at least two items in the list
            // the item WILL be added before the last one
            
            bpqueue_node_s *prev = list->first;
            
            while(prev->next->priority <= priority)
            {
                prev = prev->next;
            }
            
            node->next = prev->next;
            prev->next = node;
        }
        
        list->size++;
    }
    else
    {
        node->next = NULL;
        
        list->first = node;
        list->last = node;

        list->size = 1;
    }
}

/**
 * Remove the first item from the list.
 * Deletes the node but not the data.
 * The data is returned.
 * 
 * @param list
 * @return the data or NULL if the list is empty
 */

void*
bpqueue_dequeue(bpqueue_s *list)
{
    if(list->size > 0)
    {
        bpqueue_node_s *node = list->first;
        void *data = node->data;
        list->first = node->next;
        list->size--;
        if(list->size == 0)
        {
            list->last = NULL;
        }
        free(node);
        return data;
    }
    else
    {
        return NULL;
    }
}

/**
 * Remove all items from the list.
 * Deletes the nodes but not the data.
 * 
 * @param list
 */

void
bpqueue_clear(bpqueue_s *list)
{
    bpqueue_node_s *node = list->first;

    while(node->next != NULL)
    {
        bpqueue_node_s *tmp = node;
        
        node = node->next;
        
        free(tmp);
    }
    
    list->first = NULL;
    list->last = NULL;
    list->size = 0;
}

/** @} */

/*----------------------------------------------------------------------------*/

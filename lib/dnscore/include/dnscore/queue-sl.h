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
 *  @brief A queue based on single-linked nodes.
 *
 * A queue based on single-linked nodes.
 *
 * @{
 */
/*----------------------------------------------------------------------------*/
#ifndef QUEUE_SL_H_
#define QUEUE_SL_H_

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
 * queue implemented as a linked list
 * 
 * (looks like a no-header no-sentinel single-linked list of strings)
 * 
 * head : the base structure of the list
 * item : the concept of what is being stored in the list
 * node : holds the item
 * data : the reference to the item (which can be called data because it's type-less)
 * 
 */

#define QUSLNODE_TAG 0x45444f4e4c535551

struct queue_sl_node_s
{
    struct queue_sl_node_s *next;
    void *data;
};

typedef struct queue_sl_node_s queue_sl_node_s;

/// The sentiel is a butchered node, meant to avoid the (useless) data field.
/*
typedef struct queue_sl_node_sentiel_s queue_sl_node_sentiel_s;

struct queue_sl_node_sentiel_s
{
    struct queue_sl_node_s *next;
};
*/

struct queue_sl_s
{
    queue_sl_node_s *first;
    queue_sl_node_s *last;
    u32 size;
};

typedef struct queue_sl_s queue_sl_s;

/*    ------------------------------------------------------------
 *
 *      PROTOTYPES
 */

/**
 * Initialises a list.
 * 
 * @param list
 */

static inline void
queue_sl_init(queue_sl_s *list)
{
    ZEROMEMORY(list, sizeof(queue_sl_s));
}

/**
 * Adds an item at the head of the list.
 * 
 * @param list
 * @param data
 */

static inline void
queue_sl_enqueue(queue_sl_s *list, void *data)
{
    queue_sl_node_s *node;
    ZALLOC_OBJECT_OR_DIE( node, queue_sl_node_s, QUSLNODE_TAG);
    node->data = data;
        
    if(list->size > 0)
    {
        list->last->next = node;
        list->last = node;
        list->size++;
    }
    else
    {
        list->first = node;
        list->last = node;
        list->size = 1;
    }  
}

static inline void*
queue_sl_dequeue(queue_sl_s *list)
{
    if(list->size > 0)
    {
        queue_sl_node_s *node = list->first;
        list->first = list->first->next;
        list->size--;
        void *data = node->data;
        ZFREE_OBJECT(node);
        return data;
    }
    else
    {
        return NULL;
    }  
}

static inline void
queue_sl_enqueue_node(queue_sl_s *list, queue_sl_node_s *node)
{
    if(list->size > 0)
    {
        list->last->next = node;
        list->last = node;
        list->size++;
    }
    else
    {
        list->first = node;
        list->last = node;
        list->size = 1;
    }  
}

static inline queue_sl_node_s*
queue_sl_dequeue_node(queue_sl_s *list)
{
    if(list->size > 0)
    {
        queue_sl_node_s *node = list->first;
        list->first = list->first->next;
        list->size--;
        return node;
    }
    else
    {
        return NULL;
    }  
}

/**
 * 
 * Returns the size of the list
 * 
 * @param list
 * @return the size of the list
 */

static inline u32
queue_sl_size(const queue_sl_s *list)
{
    return list->size;
}

static inline queue_sl_node_s *
queue_sl_node_alloc()
{
    queue_sl_node_s *node;
    ZALLOC_OBJECT_OR_DIE( node, queue_sl_node_s, QUSLNODE_TAG);
    return node;
}

static inline void
queue_sl_node_free(queue_sl_node_s *node)
{
    ZFREE_OBJECT(node);
}

#endif /* LIST_SL_H_ */

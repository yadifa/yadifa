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

/** @defgroup streaming Streams
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"
#include "dnscore/hsdllist.h"

static void
hsdllist_free_nothing(void *data)
{
    (void)data;
}

void
hsdllist_init(hsdllist_s *lst)
{
    lst->first.next = &lst->last;
    lst->first.prev = NULL;
    lst->first.data = NULL;
    lst->last.prev = &lst->first;
    lst->last.next = NULL;
    lst->last.data = NULL;
    lst->size = 0;
    lst->node_allocator = &libc_allocator;
    lst->data_free_callback = hsdllist_free_nothing;
}

void
hsdllist_destroy(hsdllist_s *lst)
{
    hsdllist_node_s *node = lst->first.next;
    
    for(u32 n = lst->size; n > 0; n--)
    {
        hsdllist_node_s *next_node = node->next;
        void *data = node->data;
        afree(lst->node_allocator, node);
        lst->data_free_callback(data);
        node = next_node;
    }
    lst->first.next = &lst->last;
    lst->last.prev = &lst->first;
    lst->size = 0;
}

void
hsdllist_append(hsdllist_s *lst, void *data)
{
    hsdllist_node_s *new_node = aalloc(lst->node_allocator,sizeof(hsdllist_node_s));
    new_node->next = &lst->last;
    new_node->prev = lst->last.prev;
    new_node->data = data;
    lst->last.prev = new_node;
    lst->size++;
}

void
hsdllist_insert(hsdllist_s *lst, void *data)
{
    hsdllist_node_s *new_node = aalloc(lst->node_allocator,sizeof(hsdllist_node_s));
    new_node->next = lst->first.next;
    new_node->prev = &lst->first;
    new_node->data = data;
    lst->first.next = new_node;
    lst->size++;
}

u32
hsdllist_size(hsdllist_s *lst)
{
    return lst->size;
}

void*
hsdllist_remove_last(hsdllist_s *lst)
{
    if(lst->size > 0)
    {
        lst->size--;
        
        hsdllist_node_s *node = lst->last.prev;
        lst->last.prev = node->prev;
        node->prev->next = &lst->last;
        
        void *data = node->data;        
        afree(lst->node_allocator, node);
        return data;
    }
    
    return NULL;
}

void*
hsdllist_remove_first(hsdllist_s *lst)
{
    if(lst->size > 0)
    {
        lst->size--;
        
        hsdllist_node_s *node = lst->first.next;
        lst->first.next = node->next;
        node->next->prev = &lst->first;
        
        void *data = node->data;        
        afree(lst->node_allocator, node);
        return data;
    }
    
    return NULL;
}

/**
 * @}
 */

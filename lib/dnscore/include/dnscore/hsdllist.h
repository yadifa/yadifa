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
 *  @brief 
 *
 *  A header/sentiel/double-linked list
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#ifndef __HSDLLIST_H__
#define __HSDLLIST_H__

#include <dnscore/sys_types.h>
#include <dnscore/allocator.h>

struct hsdllist_node_s
{
    struct hsdllist_node_s *next;
    struct hsdllist_node_s *prev;
    void *data;
};

typedef struct hsdllist_node_s hsdllist_node_s;

struct hsdllist_s
{
    struct hsdllist_node_s first;          // first node
    struct hsdllist_node_s last;           // last node
    
    allocator_s *node_allocator;            // what to use to allocate/delete nodes (default: malloc/free a.k.a &libc_allocator)
    callback_function *data_free_callback;  // what to use to free data (can be NULL)
    u32 size;
};

typedef struct hsdllist_s hsdllist_s;

void hsdllist_init(hsdllist_s *lst);
void hsdllist_destroy(hsdllist_s *lst);
void hsdllist_append(hsdllist_s *lst, void *data);
void hsdllist_insert(hsdllist_s *lst, void *data);
u32 hsdllist_size(hsdllist_s *lst);
void* hsdllist_remove_last(hsdllist_s *lst);
void* hsdllist_remove_first(hsdllist_s *lst);

#endif // __HSDLLIST_H__

/**
 * @}
 */

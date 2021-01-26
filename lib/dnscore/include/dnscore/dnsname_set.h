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

/** @defgroup 
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _DNSNAME_SET_H
#define	_DNSNAME_SET_H

#include <dnscore/sys_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#define DNSNAME_SET_MEMORY_POOL_SIZE 512

/*
 * A structure to hold both children with direct access
 */

typedef struct dnsname_node dnsname_node;

struct dnsname_children
{
    struct dnsname_node* left;
    struct dnsname_node* right;
};

/*
 * An union to have access to the children with direct or indexed access
 */

typedef union dnsname_children_union dnsname_children_union;

union dnsname_children_union
{
    struct dnsname_children lr;
    struct dnsname_node * child[2];
};

/*
 * The node structure CANNOT have a varying size on a given collection
 * This means that the digest size is a constant in the whole tree
 */

struct dnsname_node
{
    union dnsname_children_union children;
    const u8* key;
};

typedef struct dnsname_set dnsname_set;

struct dnsname_set
{
    dnsname_node pool[DNSNAME_SET_MEMORY_POOL_SIZE];
    dnsname_node *next_free;
    dnsname_node *head;
};

typedef struct dnsname_set_iterator dnsname_set_iterator;

struct dnsname_set_iterator
{
    dnsname_node* next;
    dnsname_node* limit;
};

static inline void dnsname_set_init(dnsname_set* set)
{
    set->next_free = set->pool;
    set->head = NULL;
}

static inline bool dnsname_set_insert(dnsname_set* set, const u8 *name)
{
    if(set->next_free >= &set->pool[DNSNAME_SET_MEMORY_POOL_SIZE])
    {
        return FALSE;
    }
    
    dnsname_node** nodep;
    dnsname_node* node;

    nodep = &set->head;
    node = *nodep;
    
    while(node != NULL)
    {
        int cmp = dnsname_compare(name, node->key);
        
        if(cmp == 0)
        {
            return TRUE;
        }

        nodep = &node->children.child[(cmp > 0) & 1];
        node = *nodep;
    }

    *nodep = set->next_free++;
    node = *nodep;

    node->children.lr.left = NULL;
    node->children.lr.right = NULL;
    node->key = (u8*)name;
    
    return TRUE;
}

static inline void dnsname_set_iterator_init(dnsname_set* set, dnsname_set_iterator* iter)
{
    iter->next = set->pool;
    iter->limit = set->next_free;
}

static inline bool dnsname_set_iterator_hasnext(dnsname_set_iterator* iter)
{
    return iter->next < iter->limit;
}

static inline dnsname_node* dnsname_set_iterator_next_node(dnsname_set_iterator* iter)
{
    return iter->next++;
}

#ifdef	__cplusplus
}
#endif

#endif	/* _DNSNAME_SET_H */

/** @} */

/*----------------------------------------------------------------------------*/



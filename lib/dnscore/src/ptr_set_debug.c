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

/** @defgroup dnsdbcollection Collections used by the database
 *  @ingroup dnsdb
 *  @brief
 *
 *
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>

#define _PTR_SET_COLLECTION_C

#define DEBUG_LEVEL 0

#include "dnscore/ptr_set_debug.h"
#include "dnscore/zalloc.h"

#undef malloc
#undef free
#undef realloc
#undef calloc
#undef debug_mtest
#undef debug_stat
#undef debug_mallocated

#define AVL_NODE_TAG 0x0045444F4E4c5641 /* "AVLNODE" */

/*
 * The following macros are defining relevant fields in the node
 */

/*
 * Access to the field that points to the left child
 */
#define AVL_LEFT_CHILD(node) ((node)->children.lr.left)
/*
 * Access to the field that points to the right child
 */
#define AVL_RIGHT_CHILD(node) ((node)->children.lr.right)
/*
 * Access to the field that points to one of the children (0: left, 1: right)
 */
#define AVL_CHILD(node,id) ((node)->children.child[(id)])
/*
 * OPTIONAL : Access to the field that points the parent of the node.
 *
 * This field is optional but is mandatory if AVL_HAS_PARENT_POINTER is not 0
 */
#define AVL_PARENT(node) ((node)->parent)
/*
 * Access to the field that keeps the balance (a signed byte)
 */
#define AVL_BALANCE(node) ((node)->balance)
/*
 * The type used for comparing the nodes.
 */
#define AVL_REFERENCE_TYPE void*
/*
 *
 */

#define AVL_REFERENCE_FORMAT_STRING "%p"
#define AVL_REFERENCE_FORMAT(reference) ((void*)reference)

/*
 * A macro to initialize a node and setting the reference
 */
#define AVL_INIT_NODE(node,reference) node->key = reference


/*
 * A macro to allocate a new node
 */

#define AVL_ALLOC_NODE(node,reference) node=((AVL_NODE_TYPE*)debug_malloc_unmonitored(sizeof(AVL_NODE_TYPE)));memset(node, 0, sizeof(AVL_NODE_TYPE))
/*
 * A macro to free a node
 */

#define AVL_FREE_NODE(node) debug_free_unmonitored(node)

/*
 * A macro to print the node
 */
#define AVL_DUMP_NODE(node) format("node@%p",(node));
/*
 * A macro that returns the reference field of the node.
 * It must be of type REFERENCE_TYPE
 */
#define AVL_REFERENCE(node) (node)->key
#define AVL_REFERENCE_IS_POINTER TRUE
#define AVL_REFERENCE_IS_CONST FALSE

#define AVL_TERNARYCMP 1

#if !AVL_TERNARYCMP
/*
 * A macro to compare two references
 * Returns TRUE if and only if the references are equal.
 */
#define AVL_ISEQUAL(reference_a,reference_b) (tree->compare((reference_a),(reference_b)) == 0)
/*
 * A macro to compare two references
 * Returns TRUE if and only if the first one is bigger than the second one.
 */
#define AVL_ISBIGGER(reference_a,reference_b) (tree->compare((reference_a),(reference_b)) > 0)
#else
#define AVL_COMPARE(reference_a,reference_b) (tree->compare((reference_a),(reference_b)))
#endif

/*
 * Copies the payload of a node
 * It MUST NOT copy the "proprietary" node fields : children, parent, balance
 */
//#define AVL_COPY_PAYLOAD(node_trg,node_src) {(node_trg)->data = (node_src)->data;(node_trg)->key = (node_src)->key;}
#define AVL_COPY_PAYLOAD(node_trg,node_src) {(node_trg)->data = (node_src)->data;(node_trg)->key = (node_src)->key;}
/*
 * A macro to preprocess a node before it is preprocessed for a delete (detach)
 * If there was anything to do BEFORE deleting a node, we would do it here
 * After this macro is exectuted, the node
 * _ is detached, then deleted with FREE_NODE
 * _ has got its content overwritten by the one of another node, then the other
 *   node is deleted with FREE_NODE
 */
#define AVL_NODE_DELETE_CALLBACK(node)

#include "dnscore/avl.c.inc"

int
ptr_set_debug_ptr_node_compare(const void *node_a, const void *node_b)
{
    ssize_t a = (ssize_t)node_a;
    ssize_t b = (ssize_t)node_b;
    ssize_t d = b - a;
    if((d & 0xffffffffULL) == 0)
    {
        d >>= 32;
    }
    return (int)d;
}

int
ptr_set_debug_asciizp_node_compare(const void *node_a, const void *node_b)
{
    return strcmp((const char*)node_a, (const char*)node_b);
}

int
ptr_set_debug_dnsname_node_compare(const void *node_a, const void *node_b)
{
    return dnsname_compare((const u8*)node_a, (const u8*)node_b);
}

// key = fqdn (cannot be NULL)

int
ptr_set_debug_dnslabel_node_compare(const void *node_a, const void *node_b)
{
    
    const u8 *a = (const u8*)node_a;
    const u8 *b = (const u8*)node_b;
    int n = MIN(*a, *b) + 1;
    return memcmp(a, b, n);
}

int
ptr_set_debug_nullable_asciizp_node_compare(const void *node_a, const void *node_b)
{
    if(node_a != NULL)
    {
        if(node_b != NULL)
        {
            return strcmp((const char*)node_a, (const char*)node_b);
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return (node_b == NULL)?0:1;
    }
}

int
ptr_set_debug_nullable_dnsname_node_compare(const void *node_a, const void *node_b)
{
    if(node_a != NULL)
    {
        if(node_b != NULL)
        {
            return dnsname_compare((const u8*)node_a, (const u8*)node_b);
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return (node_b == NULL)?0:1;
    }
}

int
ptr_set_debug_host_address_node_compare(const void *node_a, const void *node_b)
{
    if(node_a != NULL)
    {
        if(node_b != NULL)
        {
            return host_address_compare((const host_address*)node_a, (const host_address*)node_b);
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return (node_b == NULL)?0:1;
    }
}

void*
ptr_set_debug_iterator_hasnext_next_value(ptr_set_debug_iterator *iterp)
{
    if(ptr_set_debug_iterator_hasnext(iterp))
    {
        ptr_node_debug *node = ptr_set_debug_iterator_next_node(iterp);
        void *ptr = node->value;
        return ptr;
    }
    else
    {
        return NULL;
    }
}

/** @} */

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

/** @defgroup nsec NSEC functions
 *  @ingroup dnsdbdnssec
 *  @brief
 *
 *
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#define _NSEC_COLLECTION_C

#define DEBUG_LEVEL 0

#include <dnscore/dnscore.h>
#include "dnsdb/nsec_collection.h"

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
#define AVL_REFERENCE_TYPE u8*
/*
 *
 */

#define AVL_REFERENCE_FORMAT_STRING "%{dnsname}"
#define AVL_REFERENCE_FORMAT(reference) reference

/*
 * A macro to initialize a node and setting the reference
 */
#define AVL_INIT_NODE(node,reference) (node)->inverse_relative_name=dnsname_zdup(reference)
/*
 * A macro to allocate a new node
 */
#define AVL_ALLOC_NODE(node,reference)                                                      \
	ZALLOC_ARRAY_OR_DIE(AVL_NODE_TYPE*, node, (sizeof(AVL_NODE_TYPE)), AVL_NODE_TAG);   \
	ZEROMEMORY(node,sizeof(AVL_NODE_TYPE))

/*
 * A macro to free a node allocated by ALLOC_NODE
 */

static void
nsec_free_node(AVL_NODE_TYPE* node)
{
    ZFREE_ARRAY(node, sizeof(AVL_NODE_TYPE));
}

#define AVL_FREE_NODE(node) nsec_free_node(node)
/*
 * A macro to print the node
 */
#define AVL_DUMP_NODE(node) format("node@%p",(node));
/*
 * A macro that returns the reference field of the node.
 * It must be of type REFERENCE_TYPE
 */
#define AVL_REFERENCE(node) (node)->inverse_relative_name

#define AVL_TERNARYCMP 1

#if !AVL_TERNARYCMP
/*
 * A macro to compare two references
 * Returns TRUE if and only if the references are equal.
 */
#define AVL_ISEQUAL(reference_a,reference_b) dnsname_equals((reference_a),(reference_b))
/*
 * A macro to compare two references
 * Returns TRUE if and only if the first one is bigger than the second one.
 */
#define AVL_ISBIGGER(reference_a,reference_b) (dnsname_compare((reference_a),(reference_b))>0)
#else
#define AVL_COMPARE(reference_a,reference_b) (dnsname_compare((reference_a),(reference_b)))
#endif
/*
 * Copies the payload of a node
 * It MUST NOT copy the "proprietary" node fields : children, parent, balance
 */
#define AVL_COPY_PAYLOAD(node_trg,node_src) (node_trg)->inverse_relative_name=(node_src)->inverse_relative_name
/*
 * A macro to preprocess a node before it is preprocessed for a delete (detach)
 * If there was anything to do BEFORE deleting a node, we would do it here
 * After this macro is exectuted, the node
 * _ is detached, then deleted with FREE_NODE
 * _ has got its content overwritten by the one of another node, then the other
 *   node is deleted with FREE_NODE
 */
#define AVL_NODE_DELETE_CALLBACK(node) dnsname_zfree((node)->inverse_relative_name);

#include <dnscore/avl.c.inc>

AVL_NODE_TYPE*
AVL_PREFIXED(find_interval_start)(AVL_CONST_TREE_TYPE* root, AVL_REFERENCE_TYPE obj_hash)
{
    const AVL_NODE_TYPE* node = *root;
    const AVL_NODE_TYPE* lower_bound = NULL;
    AVL_REFERENCE_TYPE h;
    
    yassert(node != NULL);

    /* This is one of the parts I could try to optimize
     * I've checked the assembly, and it sucks ...
     */

    /* Both the double-test while/ternary and the current one
     * are producing the same assembly code.
     */

    while(node != NULL)
    {
        h = AVL_REFERENCE(node);

        /*
         * [0] is the length of the obj_hash
         *
         * The obj_hashs starts at [1]
         *
         */

        int cmp = dnsname_compare(obj_hash, h);

        /* equals */
        if(cmp == 0)
        {
            return (AVL_NODE_TYPE*)node;
        }

        /* bigger */
        if(cmp > 0)
        {
            lower_bound = node;
            node = AVL_CHILD(node, DIR_RIGHT);
        }
        else
        {
            node = AVL_CHILD(node, DIR_LEFT);
        }
    }

        
    if(lower_bound == NULL)
    {
        lower_bound = *root;
        
        yassert(lower_bound != NULL);
        
        while((node = AVL_CHILD(lower_bound, DIR_RIGHT)) != NULL) // VS false positive: an assert says this can't happen
        {
            lower_bound = node;
        }
    }
    
    return (AVL_NODE_TYPE*)lower_bound;
}

AVL_NODE_TYPE*
AVL_PREFIXED(find_interval_prev_mod)(AVL_CONST_TREE_TYPE* root, const AVL_REFERENCE_TYPE obj_hash)
{
    AVL_NODE_TYPE* node = *root;
    AVL_NODE_TYPE* lower_bound = NULL;
    AVL_REFERENCE_TYPE h;
    
    yassert(node != NULL);

    /* Both the double-test while/ternary and the current one
     * are producing the same assembly code.
     */
    
    /**
     * Get a key that 
     */

    while(node != NULL)
    {
        h = AVL_REFERENCE(node);

        /*
         * [0] is the length of the obj_hash
         *
         * The obj_hashs starts at [1]
         *
         */

        int cmp = dnsname_compare(obj_hash, h);

        /* equals */
        if(cmp == 0)
        {
            return nsec_node_mod_prev(node);
        }

        /* bigger */
        if(cmp > 0)
        {
            lower_bound = node;
            node = AVL_CHILD(node, DIR_RIGHT);            
        }
        else
        {
            node = AVL_CHILD(node, DIR_LEFT);
        }
    }
    
    if(lower_bound == NULL)
    {
        lower_bound = *root;
        
        yassert(lower_bound != NULL);
        
        while((node = AVL_CHILD(lower_bound, DIR_RIGHT)) != NULL) // VS false positive: an assert says this can't happen
        {
            lower_bound = node;
        }
    }
    
    return lower_bound;
}

/** @} */

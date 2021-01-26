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

#ifndef _NSEC_COLLECTION_H
#define	_NSEC_COLLECTION_H

#include <dnsdb/zdb_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif

/*
 * A digest is stored prefixed with its length ([1;255])
 */

/*
 * A structure to hold both children with direct access
 */

typedef struct nsec_node nsec_node;


struct nsec_children
{
    struct nsec_node* left;
    struct nsec_node* right;
};

/*
 * An union to have access to the children with direct or indexed access
 */

typedef union nsec_children_union nsec_children_union;

union nsec_children_union
{
    struct nsec_children lr;
    struct nsec_node * child[2];
};

typedef union nsec_label_pointer_array nsec_label_pointer_array;

union nsec_label_pointer_array
{
    zdb_rr_label* owner;
    zdb_rr_label** owners;
};

/*
 * The node structure CANNOT have a varying size on a given collection
 * This means that the digest size is a constant in the whole tree
 */

struct nsec_node
{
    union nsec_children_union children;
    /**/
    struct nsec_node *parent;
    /**/
    s8 balance;
  
    /*
     * The order is defined by the canonisation : I need the full dname (minus the origin)
     *
     * The name is stored inverse (ie: eu.eurid.www) beause its tested in that order
     *
     * I cannot use a nested name in this structure because the length is not a constant.
     * Allocating a constant size for every nsec would cost too much (memory, cache miss & cpu)
     */

    zdb_rr_label *label;
    
    u8 *inverse_relative_name;

    /*
     * I'm tempted to add a pointer to the NSEC record here, but it would only help for
     * dynupdating and would cost 24MB for the TLD, all this for a few cycles: not worth it
     */
};

typedef struct nsec_node nsec_zone_item;

/*
 * AVL definition part begins here
 */

/*
 * The maximum depth of a tree.
 * 40 is enough for storing 433494436 items (worst case)
 *
 * Depth 0 is one node.
 *
 * Worst case : N is enough for sum[n = 0,N](Fn) where Fn is Fibonacci(n+1)
 * Best case : N is enough for (2^(N+1))-1
 */
#define AVL_MAX_DEPTH 52 // 139*10^9 items max (worst case)64

/*
 * The previx that will be put in front of each function name
 */
#define AVL_PREFIX	nsec_

/*
 * The type that hold the node
 */
#define AVL_NODE_TYPE   nsec_node

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_TREE_TYPE   AVL_NODE_TYPE*

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_CONST_TREE_TYPE AVL_NODE_TYPE* const

/*
 * How to find the root in the tree
 */
#define AVL_TREE_ROOT(__tree__) (*(__tree__))

/*
 * The type used for comparing the nodes.
 */
#define AVL_REFERENCE_TYPE u8*
#define AVL_REFERENCE_IS_CONST FALSE
#define AVL_REFERENCE_IS_POINTER TRUE

/*
 * The node has got a pointer to its parent
 *
 * 0   : disable
 * !=0 : enable
 */
#define AVL_HAS_PARENT_POINTER 1

#ifdef	__cplusplus
}
#endif

#include <dnscore/avl.h.inc>

#ifdef	__cplusplus
extern "C"
{
#endif

AVL_NODE_TYPE* AVL_PREFIXED(find_interval_start)(AVL_CONST_TREE_TYPE* tree, AVL_REFERENCE_TYPE obj_hash);

AVL_NODE_TYPE* AVL_PREFIXED(find_interval_prev_mod)(AVL_CONST_TREE_TYPE* root, const AVL_REFERENCE_TYPE obj_hash);

/*
 * I recommend setting a define to identify the C part of the template
 * So it can be used to undefine what is not required anymore for every
 * C file but that one.
 *
 */

#ifndef _NSEC_COLLECTION_C

#undef AVL_MAX_DEPTH
#undef AVL_PREFIX
#undef AVL_NODE_TYPE
#undef AVL_TREE_TYPE
#undef AVL_CONST_TREE_TYPE
#undef AVL_TREE_ROOT
#undef AVL_REFERENCE_TYPE
#undef AVL_HAS_PARENT_POINTER
#undef AVL_REFERENCE_IS_CONST
#undef AVL_REFERENCE_IS_POINTER

#undef _AVL_H_INC

#endif	/* _NSEC_COLLECTION_C */

#ifdef	__cplusplus
}
#endif

/*
 * AVL definition part ends here
 */

#endif	/* _NSEC_COLLECTION_H */

/** @} */

/*----------------------------------------------------------------------------*/


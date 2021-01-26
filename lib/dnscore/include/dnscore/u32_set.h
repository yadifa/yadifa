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
 *  @brief A dictionary u32 => ptr based on the AVL code.
 *
 * A dictionary u32 => ptr based on the AVL code.
 * Mostly used for accessing hash => value
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#ifndef _U32_SET_H
#define	_U32_SET_H

#include <dnscore/sys_types.h>

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

typedef struct u32_node u32_node;


struct u32_children
{
    struct u32_node* left;
    struct u32_node* right;
};

/*
 * An union to have access to the children with direct or indexed access
 */

typedef union u32_children_union u32_children_union;

union u32_children_union
{
    struct u32_children lr;
    struct u32_node * child[2];
};


/*
 * The node structure CANNOT have a varying size on a given collection
 * This means that the digest size is a constant in the whole tree
 */

struct u32_node
{
    union u32_children_union children;      /* 2 ptrs */
    void* value;                            /* 1 ptr */
    u32 key;                                /* 4 b */
    s8 balance;                             /* 1 b */
};                                          /* 29 OR 17 bytes (64/32) */

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
#define AVL_PREFIX	    u32_set_

/*
 * The type that hold the node
 */
#define AVL_NODE_TYPE   u32_node

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_TREE_TYPE   AVL_NODE_TYPE*

typedef AVL_TREE_TYPE u32_set;

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_CONST_TREE_TYPE AVL_NODE_TYPE * const

/*
 * How to find the root in the tree
 */
#define AVL_TREE_ROOT(__tree__) (*(__tree__))

/*
 * The type used for comparing the nodes.
 */

#define AVL_REFERENCE_TYPE u32
#define AVL_REFERENCE_IS_POINTER FALSE
#define AVL_REFERENCE_IS_CONST FALSE

/*
 * The node has got a pointer to its parent
 *
 * 0   : disable
 * !=0 : enable
 */
#define AVL_HAS_PARENT_POINTER 0

#ifdef	__cplusplus
}
#endif

#include <dnscore/avl.h.inc>

#ifdef	__cplusplus
extern "C"
{
#endif
    
/*
 * I recommend setting a define to identify the C part of the template
 * So it can be used to undefine what is not required anymore for every
 * C file but that one.
 *
 */

#ifndef _U32_SET_C

#undef AVL_MAX_DEPTH
#undef AVL_PREFIX
#undef AVL_NODE_TYPE
#undef AVL_TREE_TYPE
#undef AVL_CONST_TREE_TYPE
#undef AVL_TREE_ROOT
#undef AVL_REFERENCE_TYPE
#undef AVL_HAS_PARENT_POINTER
#undef AVL_REFERENCE_IS_POINTER
#undef AVL_REFERENCE_IS_CONST

#undef _AVL_H_INC

#endif	/* _U32_SET_C */
    
    
#define U32_SET_EMPTY NULL

#ifdef	__cplusplus
}
#endif

#endif	/* _U32_SET_H */
/** @} */


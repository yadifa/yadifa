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
 * @defgroup nsec3 NSEC3 functions
 * @ingroup dnsdbdnssec
 * @brief
 *
 *  This is the collection that holds the NSEC3 chain for one NSEC3PARAM
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnsdb/nsec3_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * A digest is stored prefixed with its length ([1;255])
 */

/*
 * A structure to hold both children with direct access
 */

typedef struct nsec3_node_s nsec3_node_t;

struct nsec3_children
{
    struct nsec3_node_s *left;
    struct nsec3_node_s *right;
};

/*
 * A union to have access to the children with direct or indexed access
 */

union nsec3_children_union
{
    struct nsec3_children lr;
    struct nsec3_node_s  *child[2];
};

typedef union nsec3_children_union nsec3_children_union_t;

union nsec3_item_label_owner_array
{
    zdb_rr_label_t  *owner;
    zdb_rr_label_t **owners;
};

typedef union nsec3_item_label_owner_array nsec3_item_label_owner_array;

/*
 * The node structure CANNOT have a varying size on a given collection
 * This means that the digest size is a constant in the whole tree
 */

#define N3NODE_TAG 0x45444f4e334e

typedef struct nsec3_node_s nsec3_node_t;

struct nsec3_node_s
{
    nsec3_children_union_t children;
    /**/
    struct nsec3_node_s *parent;
    /**/

    /* 64 bits aligned */
    int8_t balance;

    /* PAYLOAD BEYOND THIS POINT */

    uint8_t  flags; /* opt-out */
    uint16_t type_bit_maps_size;

    int32_t  rc; /* label RC */
    int32_t  sc; /* *.label RC */

    /* 64 bits aligned */

    zdb_resource_record_set_t *rrsig_rrset;
    /**/

    nsec3_item_label_owner_array label;
    nsec3_item_label_owner_array star_label;

    uint8_t                     *type_bit_maps; /* MUST be a ptr */

    uint8_t                      digest[1];
    /* 7*4	7*8
     * 3*2      3*2
     * 1*1      1*1
     *
     * 35       63
     *
     * +21
     *
     *56 (56)   84 (88)
     *
     * For the 3M records of EU:
     *
     * 168MB    240MB
     *
     * To this, 2+1 ptrs must be added
     * by record
     *
     * The remaining overhead happens
     * if there are many references
     * for the same label, this should
     * be fairly negligible.
     *
     * 36MB    72MB
     *
     * =>
     *
     * 204MB   312MB
     *
     */
};

static inline void nsec3_item_type_bitmap_free(nsec3_node_t *item) { ZFREE_ARRAY(item->type_bit_maps, item->type_bit_maps_size); }

#define NSEC3_NODE_SIZE_FOR_DIGEST(node, digest) ((sizeof(nsec3_node) - 1) + digest[0])

#define NSEC3_NODE_DIGEST_SIZE(node)             (node->digest[0])
#define NSEC3_NODE_DIGEST_PTR(node)              (&node->digest[1])

#define NSEC3_NODE_SIZE(node)                    ((sizeof(nsec3_node_t) - 1) + NSEC3_NODE_DIGEST_SIZE(node))

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
#define AVL_DEPTH_MAX                            52 // 139*10^9 items max (worst case)64

/*
 * The previx that will be put in front of each function name
 */
#define AVL_PREFIX                               nsec3_

/*
 * The type that hold the node
 */
#define AVL_NODE_TYPE                            nsec3_node_t

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_TREE_TYPE                            AVL_NODE_TYPE *

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_CONST_TREE_TYPE                      AVL_NODE_TYPE *const

/*
 * How to find the root in the tree
 */
#define AVL_TREE_ROOT(__tree__)                  (*(__tree__))

/*
 * The type used for comparing the nodes.
 */
#define AVL_REFERENCE_TYPE                       uint8_t *
#define AVL_REFERENCE_IS_CONST                   false
#define AVL_REFERENCE_IS_POINTER                 true

/*
 * The node has got a pointer to its parent
 *
 * 0   : disable
 * !=0 : enable
 */
#define AVL_HAS_PARENT_POINTER                   1

#ifdef __cplusplus
}
#endif

#include <dnscore/avl.h.inc>

#ifdef __cplusplus
extern "C"
{
#endif

AVL_NODE_TYPE *AVL_PREFIXED(find_interval_start)(AVL_CONST_TREE_TYPE *tree, const AVL_REFERENCE_TYPE obj_hash);
AVL_NODE_TYPE *AVL_PREFIXED(find_interval_prev_mod)(AVL_CONST_TREE_TYPE *root, const AVL_REFERENCE_TYPE obj_hash);

/*
 * I recommend setting a define to identify the C part of the template
 * So it can be used to undefine what is not required anymore for every
 * C file but that one.
 *
 */

#ifndef _NSEC3_COLLECTION_C

#undef AVL_DEPTH_MAX
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

#endif /* _NSEC3_COLLECTION_C */

#ifdef __cplusplus
}
#endif

/*
 * AVL definition part ends here
 */

/** @} */

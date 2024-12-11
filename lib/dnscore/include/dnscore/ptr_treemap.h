/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @defgroup collections Generic collections functions
 * @ingroup dnscore
 * @brief A dictionary (map, hash, ...) ptr->ptr implemented as an AVL balanced tree
 *
 * A dictionary (map, hash, ...) implemented as an AVL balanced tree
 * The key is a pointer and is compated with other keys using a used-defined,
 * per-collection comparison function.
 *
 * Pre-defined comparators include:
 *
 * PTR_TREEMAP_EMPTY  (ptr_treemap_default_node_compare) pointer addresses
 * PTR_TREEMAP_ASCIIZ_EMPTY (ptr_treemap_asciizp_node_compare) C-strings
 * PTR_TREEMAP_DNSNAME_EMPTY (ptr_treemap_dnsname_node_compare) FQDNs
 * PTR_TREEMAP_NULLABLE_ASCIIZ_EMPTY (ptr_treemap_nullable_asciizp_node_compare) C-strings AND NULL
 * PTR_TREEMAP_NULLABLE_DNSNAME_EMPTY (ptr_treemap_nullable_dnsname_node_compare) FQDNs AND NULL
 * PTR_TREEMAP_PTR_EMPTY (ptr_treemap_ptr_node_compare) pointer addresses
 * PTR_TREEMAP_HOST_ADDRESS_EMPTY (ptr_treemap_host_address_node_compare) host_address
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <dnscore/sys_types.h>

/*
 * A digest is stored prefixed with its length ([1;255])
 */

/*
 * A structure to hold both children with direct access
 */

typedef int ptr_treemap_node_compare_t(const void *key_a, const void *key_b);

struct ptr_treemap_s;

typedef struct ptr_treemap_s      ptr_treemap_t;
typedef struct ptr_treemap_node_s ptr_treemap_node_t;

struct ptr_treemap_s
{
    struct ptr_treemap_node_s  *root;
    ptr_treemap_node_compare_t *compare; // compares nodes by passing pointers to the keys (and not the full node)
};

struct ptr_treemap_children_s
{
    ptr_treemap_node_t *left;
    ptr_treemap_node_t *right;
};

/*
 * A union to have access to the children with direct or indexed access
 */

union ptr_treemap_children_u
{
    struct ptr_treemap_children_s lr;
    ptr_treemap_node_t           *child[2];
};

/*
 * The node structure CANNOT have a varying size on a given collection
 * This means that the digest size is a constant in the whole tree
 */

struct ptr_treemap_node_s
{
    union ptr_treemap_children_u children; // 16
    /**/
    ptr_treemap_node_t *parent; //  8
    /**/
    void *key; /* ie: nsec3 item */
    union
    {
        void    *value; /* ie: label linked to the nsec3 item */
        intptr_t value_intptr;
        void (*void_function_void)();
#if __SIZEOF_POINTER__ == 8
        int64_t  value_s64;
        uint64_t value_u64;
#endif
        int32_t  value_s32;
        uint32_t value_u32;
    };

    int8_t balance;
};

#define PTR_TREEMAP_NODE_SIZE(node) sizeof(ptr_node)

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
#define AVL_DEPTH_MAX               52 // 139*10^9 items max (worst case)

/*
 * The previx that will be put in front of each function name
 */
#define AVL_PREFIX                  ptr_treemap_

/*
 * The type that hold the node
 */
#define AVL_NODE_TYPE               ptr_treemap_node_t

/*
 * The tag for the node
 */

#define PTR_NODE_TAG                0x45444f4e525450 // PTRNODE

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_TREE_TYPE               ptr_treemap_t

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_CONST_TREE_TYPE         const ptr_treemap_t

/*
 *
 */
#define AVL_TREE_ROOT(__tree__)     (__tree__)->root
/*
 * The type used for comparing the nodes.
 */
#define AVL_REFERENCE_TYPE          void *
#define AVL_REFERENCE_IS_POINTER    true
#define AVL_REFERENCE_IS_CONST      false

/*
 * The node has got a pointer to its parent
 *
 * 0   : disable
 * !=0 : enable
 */
#define AVL_HAS_PARENT_POINTER      1

#ifdef __cplusplus
}
#endif

#include <dnscore/avl.h.inc>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * I recommend setting a define to identify the C part of the template
 * So it can be used to undefine what is not required anymore for every
 * C file but that one.
 *
 */

#ifndef _PTR_TREEMAP_C

#undef AVL_DEPTH_MAX
#undef AVL_PREFIX
#undef AVL_NODE_TYPE
#undef AVL_NODE_TAG
#undef AVL_TREE_TYPE
#undef AVL_CONST_TREE_TYPE
#undef AVL_TREE_ROOT
#undef AVL_REFERENCE_TYPE
#undef AVL_HAS_PARENT_POINTER
#undef AVL_REFERENCE_IS_POINTER
#undef AVL_REFERENCE_IS_CONST
#undef _AVL_H_INC

#endif /* _PTR_TREEMAP_C */

#ifdef __cplusplus
}
#endif

#define ptr_treemap_default_node_compare ptr_treemap_ptr_node_compare

/**
 * ptr_treemap_t comparator function.
 * Compares pointer values.
 *
 * @param key_a
 * @param key_b
 * @return
 */

int ptr_treemap_ptr_node_compare(const void *key_a, const void *key_b);

/**
 * ptr_treemap_t comparator function.
 * Compares C-string values.
 *
 * @param key_a
 * @param key_b
 * @return
 */

int ptr_treemap_asciizp_node_compare(const void *key_a, const void *key_b);

/**
 * ptr_treemap_t comparator function.
 * Compares C-string values, case-insensitive
 *
 * @param key_a
 * @param key_b
 * @return
 */

int ptr_treemap_asciizcasep_node_compare(const void *key_a, const void *key_b);

/**
 * ptr_treemap_t comparator function.
 * Compares dnsname values, taking depth into account.
 *
 * @param key_a
 * @param key_b
 * @return
 */

int ptr_treemap_fqdn_node_compare(const void *key_a, const void *key_b);

/**
 * ptr_treemap_t comparator function.
 * Compares dnsname values.
 *
 * @param key_a
 * @param key_b
 * @return
 */

int ptr_treemap_dnsname_node_compare(const void *key_a, const void *key_b);

/**
 * ptr_treemap_t comparator function.
 * Compares dnslabel values.
 *
 * @param key_a
 * @param key_b
 * @return
 */

int ptr_treemap_dnslabel_node_compare(const void *key_a, const void *key_b);

// key = asciiz (can be NULL)

/**
 * ptr_treemap_t comparator function.
 * Compares C-strings values, NULL is allowed.
 *
 * @param key_a
 * @param key_b
 * @return
 */

int ptr_treemap_nullable_asciizp_node_compare(const void *key_a, const void *key_b);

/**
 * ptr_treemap_t comparator function.
 * Compares dnsname values, NULL is allowed.
 *
 * @param key_a
 * @param key_b
 * @return
 */

int ptr_treemap_nullable_dnsname_node_compare(const void *key_a, const void *key_b);

/**
 * ptr_treemap_t comparator function.
 * Compares host_address values.
 *
 * @param key_a
 * @param key_b
 * @return
 */

int ptr_treemap_host_address_node_compare(const void *key_a, const void *key_b);
int ptr_treemap_socketaddress_node_compare(const void *key_a, const void *key_b);

#define PTR_TREEMAP_EMPTY                              {NULL, ptr_treemap_default_node_compare}
#define PTR_TREEMAP_ASCIIZ_EMPTY                       {NULL, ptr_treemap_asciizp_node_compare}
#define PTR_TREEMAP_ASCIIZCASE_EMPTY                   {NULL, ptr_treemap_asciizcasep_node_compare}
#define PTR_TREEMAP_DNSNAME_EMPTY                      {NULL, ptr_treemap_dnsname_node_compare}
#define PTR_TREEMAP_NULLABLE_ASCIIZ_EMPTY              {NULL, ptr_treemap_nullable_asciizp_node_compare}
#define PTR_TREEMAP_NULLABLE_DNSNAME_EMPTY             {NULL, ptr_treemap_nullable_dnsname_node_compare}
#define PTR_TREEMAP_PTR_EMPTY                          {NULL, ptr_treemap_ptr_node_compare}
#define PTR_TREEMAP_CUSTOM(comparator___)              {NULL, (comparator___)}
#define PTR_TREEMAP_HOST_ADDRESS_EMPTY                 {NULL, ptr_treemap_host_address_node_compare}
#define PTR_TREEMAP_SOCKETADDRESS_EMPTY                {NULL, ptr_treemap_socketaddress_node_compare}
#define PTR_TREEMAP_EMPTY_WITH_COMPARATOR(cmp_func___) {NULL, (cmp_func___)}

void *ptr_treemap_iterator_hasnext_next_value(ptr_treemap_iterator_t *iterp);

#define FOREACH_PTR_TREEMAP(cast__, var__, ptr_treemap__)                                                                                                                                                                                      \
    ptr_treemap_iterator_t PREPROCESSOR_CONCAT_EVAL(foreach_ptr_treemap_iter, __LINE__);                                                                                                                                                       \
    ptr_treemap_iterator_init((ptr_treemap__), &PREPROCESSOR_CONCAT_EVAL(foreach_ptr_treemap_iter, __LINE__));                                                                                                                                 \
    for(cast__ var__; ((var__) = (cast__)ptr_treemap_iterator_hasnext_next_value(&PREPROCESSOR_CONCAT_EVAL(foreach_ptr_treemap_iter, __LINE__))) != NULL;)
// #define FOREACH_PTR_TREEMAP_KEY_VALUE(castk__,vark__,castv__,varv__,ptr_treemap__) ptr_treemap_iterator_t
// PREPROCESSOR_CONCAT_EVAL(foreach_ptr_treemap_iter,__LINE__); ptr_treemap_iterator_init((ptr_treemap__),
// &PREPROCESSOR_CONCAT_EVAL(foreach_ptr_treemap_iter,__LINE__)); for(varv__ varv__;((varc__) =
// (cast__)ptr_treemap_iterator_hasnext_next_key_value(&PREPROCESSOR_CONCAT_EVAL(foreach_ptr_treemap_iter,__LINE__))) !=
// NULL;)

struct const_ptr_treemap_of_one
{
    ptr_treemap_t      set;
    ptr_treemap_node_t one;
};

typedef struct const_ptr_treemap_of_one const_ptr_treemap_of_one;

/**
 *
 * For these cases you need a set of a single element that is to be used a simple, constant, input,
 * this is an efficient way to do so.
 *
 * Can only be used for reading (find, iterate)
 * The above implies : cannot be destroyed (as it is supposed to be on the stack and die winding up)
 *
 * Any other usage WILL crash the program.
 *
 * @param cpsoo
 * @param key
 * @param value
 * @param cmp
 *
 * example usage:
 *
 * const_ptr_treemap_of_one fqdn_set;
 * const_ptr_treemap_of_one_init(&fqdn_set, fqdn, fqdn, ptr_treemap_dnsname_node_compare);
 * my_function_expecting_a_read_only_fqdn_set(&fqdn_set.set);
 *
 * // do whatever I want with the fqdn and forget the fqdn_set
 */

static inline void const_ptr_treemap_of_one_init(const_ptr_treemap_of_one *cpsoo, void *key, void *value, ptr_treemap_node_compare_t *cmp)
{
    cpsoo->set.root = &cpsoo->one;
    cpsoo->set.compare = cmp;
    ZEROMEMORY(&cpsoo->one, sizeof(ptr_treemap_node_t));
    cpsoo->one.key = key;
    cpsoo->one.value = value;
}

/*
 * AVL definition part ends here
 */

/** @} */

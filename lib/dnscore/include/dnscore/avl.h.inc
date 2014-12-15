/* 
 *
 * Copyright (c) 2011, EURid. All rights reserved.
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
 */

#ifndef _AVL_H_INC
#define	_AVL_H_INC

#include <stdlib.h>
#include <stdbool.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#ifndef AVL_PREFIX
    #error Expected define: AVL_PREFIX name
#endif

#ifndef AVL_NODE_TYPE
    #error Expected define: AVL_NODE_TYPE type
#endif

#ifndef AVL_TREE_TYPE
    #error Expected define: AVL_TREE_TYPE type
#endif

#ifndef AVL_CONST_TREE_TYPE
    #error Expected define: AVL_CONST_TREE_TYPE type
#endif

/*
 * Self explanatory but not mandatory, defaulted to TRUE
 */

// #define AVL_REFERENCE_ISPOINTER TRUE

#ifndef AVL_REFERENCE_TYPE
    #error Expected define: AVL_REFERENCE_TYPE type
#endif

#ifndef AVL_HAS_PARENT_POINTER
    #error Expected define: AVL_HAS_PARENT_POINTER boolean.
#endif

#ifndef AVL_TREE_ROOT
    #error Expected define: AVL_TREE_ROOT(__tree__).
    // #define AVL_TREE_ROOT(x) (*x)
#endif

#ifdef AVL_REFERENCE_IS_CONST
#undef AVL_REFERENCE_MODIFIER
#undef AVL_REFERENCE_CONST
#define AVL_REFERENCE_MODIFIER
#define AVL_REFERENCE_CONST
#else
#define AVL_REFERENCE_CONST const
#endif
/*
 * Macros to set the prefix to the function name
 * And no : AFAIK there are no other way to do this using only one parameter in
 * the first call ... (ie: less than 3 lines)
 */

#define __AVL_PREFIXED(name_a,name_b) name_a ## name_b		/* Concat */
#define _AVL_PREFIXED(name_a,name_b) __AVL_PREFIXED(name_a,name_b)	/* Do the expansion */
#define AVL_PREFIXED(name) _AVL_PREFIXED( AVL_PREFIX , name)		/* Call with macro */

typedef struct AVL_PREFIXED(avl_iterator) AVL_PREFIXED(avl_iterator);

struct AVL_PREFIXED(avl_iterator)
{
    s32 stack_pointer;
    AVL_NODE_TYPE* stack[AVL_MAX_DEPTH];    /* An AVL depth of 64 is HUGE */
};


/** @brief Initializes the tree
 *
 *  Initializes the tree.
 *  Basically : *tree=NULL;
 *
 *  @param[in]  tree the tree to initialize
 *
 */

void AVL_PREFIXED(avl_init)(AVL_TREE_TYPE* tree);

/** @brief Find a node in the tree
 *
 *  Find a node in the tree matching a hash value.
 *
 *  @param[in]  tree the tree to search in
 *  @param[in]  obj_hash the hash to find
 *
 *  @return A pointer to the node or NULL if there is no such node.
 */

AVL_NODE_TYPE* AVL_PREFIXED(avl_find)(AVL_CONST_TREE_TYPE* tree, AVL_REFERENCE_CONST AVL_REFERENCE_TYPE obj_hash);

/** @brief Insert a node into the tree.
 *
 *  Insert data into the tree.
 *  Since hash can have collisions, the data will most likely be a collection
 *  (another tree, a list, ...)
 *
 *  NOTE:
 *  If the node associated to the hazdb_icmtl_replaysh already exists, it is returned unaltered,
 *  the caller will be responsible to manipulate the node's data.
 *  Else a new node is created, pointing to the data.
 *
 *  @param[in]  tree the tree where the insertion should be made
 *  @param[in]  obj_hash the hash associated to the data
 *
 *  @return The node associated to the hash
 */

AVL_NODE_TYPE* AVL_PREFIXED(avl_insert)(AVL_TREE_TYPE *tree,AVL_REFERENCE_TYPE obj_hash);

/** @brief Deletes a node from the tree.
 *
 *  Deletes a node from the tree.
 *
 *  @param[in]  tree the tree from which the delete will be made
 *  @param[in]  obj_hash the hash associated to the node to remove
 *
 *  @return The node associated to the hash, NULL if it did not exist.
 */

void AVL_PREFIXED(avl_delete)(AVL_TREE_TYPE *tree,AVL_REFERENCE_CONST AVL_REFERENCE_TYPE obj_hash);

/** @brief Releases all the nodes of a tree
 *
 *  Releases all the nodes of a tree.  Data is not destroyed.
 *  Only the right and left childs are used.  Everything else
 *  is of no importance. (Useful for destroying data & keys,
 *  then only calling this to free the container structure)
 *
 *  @param[in] tree the tree to empty
 */

void AVL_PREFIXED(avl_destroy)(AVL_TREE_TYPE *tree);

static inline bool AVL_PREFIXED(avl_isempty)(AVL_CONST_TREE_TYPE *tree)
{
    return AVL_TREE_ROOT(tree) == NULL;
}

/**
 * 
 * @brief Returns the last node of the tree
 *
 */

AVL_NODE_TYPE* AVL_PREFIXED(avl_node_last)(AVL_NODE_TYPE *node);

void AVL_PREFIXED(avl_iterator_init)(AVL_CONST_TREE_TYPE* tree,AVL_PREFIXED(avl_iterator*) iter);
bool AVL_PREFIXED(avl_iterator_hasnext)(AVL_PREFIXED(avl_iterator*) iter);
AVL_NODE_TYPE* AVL_PREFIXED(avl_iterator_next_node)(AVL_PREFIXED(avl_iterator*) iter);

/** @brief Releases all the nodes of a tree
 *
 *  Releases all the nodes of a tree.
 *  Calls a function passed in parameter before destroying the data.
 *  It's the responsibility of the callback to process (destroy) the data
 *  in the tree.
 *
 *  @param[in] tree the tree to empty
 */

void AVL_PREFIXED(avl_callback_and_destroy)(AVL_TREE_TYPE *tree,callback_function callback);

AVL_NODE_TYPE *AVL_PREFIXED(avl_get_first)(AVL_CONST_TREE_TYPE* tree);

#if AVL_HAS_PARENT_POINTER != 0

AVL_NODE_TYPE* AVL_PREFIXED(avl_node_next)(const AVL_NODE_TYPE* node);

AVL_NODE_TYPE* AVL_PREFIXED(avl_node_prev)(const AVL_NODE_TYPE* node);

AVL_NODE_TYPE* AVL_PREFIXED(avl_node_mod_next)(const AVL_NODE_TYPE* node);

AVL_NODE_TYPE* AVL_PREFIXED(avl_node_mod_prev)(const AVL_NODE_TYPE* node);

#endif

int AVL_PREFIXED(avl_check)(AVL_TREE_TYPE *tree);
void AVL_PREFIXED(avl_dump)(AVL_TREE_TYPE *tree);

#ifdef	__cplusplus
}
#endif

#else

#error AVL.H.INC SHOULD NOT BE INCLUDED TWICE

#endif	/* _AVL_H_INC */

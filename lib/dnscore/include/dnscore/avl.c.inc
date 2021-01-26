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
 *  @brief AVL structure and functions
 *
 *  AVL structure and functions
 *
 * @{
 */

/* Optimization that have an effect on some avl depths */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "dnscore/sys_types.h"
#include "dnscore/format.h"

void logger_flush();

#ifndef DUMPER_FUNCTION
#define DUMPER_FUNCTION(...) formatln(__VA_ARGS__);flushout()
#endif

#if defined(DEBUG_DUMP)
#define DUMP(...) DUMPER_FUNCTION(__VA_ARGS__)
#define DUMP_NODE(...) AVL_DUMP_NODE(__VA_ARGS__)
#else
#define DUMP(...)
#define DUMP_NODE(...)
#endif

/*
 *
 */

#if AVL_HAS_PARENT_POINTER
#ifndef AVL_PARENT
#error AVL_HAS_PARENT_POINTER enabled but parent not defined
#endif
#else
#ifdef AVL_PARENT
#error AVL_HAS_PARENT_POINTER disabled but parent defined
#endif
#endif

#ifndef AVL_REFERENCE_IS_POINTER
#define AVL_REFERENCE_IS_POINTER TRUE
#endif

#ifndef AVL_REFERENCE_IS_CONST
#define AVL_REFERENCE_IS_CONST FALSE
#endif

#if AVL_REFERENCE_IS_POINTER
#undef AVL_REFERENCE_MODIFIER
#define AVL_REFERENCE_MODIFIER const
#else
#undef AVL_REFERENCE_MODIFIER
#define AVL_REFERENCE_MODIFIER
#endif

#if AVL_REFERENCE_IS_CONST
#undef AVL_REFERENCE_MODIFIER
#define AVL_REFERENCE_MODIFIER
#undef AVL_REFERENCE_CONST
#define AVL_REFERENCE_CONST
#else
#undef AVL_REFERENCE_CONST
#define AVL_REFERENCE_CONST const
#endif

#define TOOLEFT    (-2)
#define LEFT       (-1)
#define MIDDLE      0
#define RIGHT       1
#define TOORIGHT    2

#define DIR_LEFT    0
#define DIR_RIGHT   1
#define DIR_CRASH   127

static s8 DIR_TO_AVL_BALANCE_[2] = {LEFT, RIGHT};
#define DIR_TO_AVL_BALANCE(dir) DIR_TO_AVL_BALANCE_[(dir)]

static s8 AVL_BALANCE_TO_DIR_[5] = {DIR_LEFT, DIR_LEFT, DIR_CRASH, DIR_RIGHT, DIR_RIGHT};
#define AVL_BALANCE_TO_DIR(bal) AVL_BALANCE_TO_DIR_[(bal)-TOOLEFT]

#define NODE_AVL_BALANCED(node) (AVL_BALANCE(node)==MIDDLE)

#define MUST_REAVL_BALANCE(node) ((AVL_BALANCE(node)<LEFT)||(AVL_BALANCE(node)>RIGHT))

#if (defined(AVL_PARENT) && DEBUG)

#define ASSERT_CHECK_CHILD_PARENT_LINK(node)                    \
    if(node!=NULL)                                              \
    {                                                           \
        AVL_NODE_TYPE *parent__ = AVL_PARENT(node);             \
        if(parent__ != NULL)                                    \
        {                                                       \
            AVL_NODE_TYPE *l__ = AVL_LEFT_CHILD(parent__);      \
            AVL_NODE_TYPE *r__ = AVL_RIGHT_CHILD(parent__);     \
            if(!(l__==(node) ||                                 \
                 r__==(node))	)                               \
                {                                               \
                    DUMP("parent->node link broken");           \
                    DUMP("\tparent=(%p, " AVL_REFERENCE_FORMAT_STRING")",parent__, AVL_REFERENCE_FORMAT(AVL_REFERENCE(parent__))); \
                    if(l__ != NULL)                                                                                                 \
                    {                                                                                                               \
                        DUMP("\t\tparent.lt=(%p, " AVL_REFERENCE_FORMAT_STRING")",l__, AVL_REFERENCE_FORMAT(AVL_REFERENCE(l__)));   \
                    }                                                                                                               \
                    if(r__ != NULL)                                                                                                 \
                    {                                                                                                               \
                        DUMP("\t\tparent.rt=(%p, " AVL_REFERENCE_FORMAT_STRING")",r__, AVL_REFERENCE_FORMAT(AVL_REFERENCE(r__)));   \
                    }                                                                                                               \
                    DUMP("\tnode=(%p, " AVL_REFERENCE_FORMAT_STRING")",node, AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)));            \
                    DUMP_NODE(parent__);                        \
                    DUMP_NODE(node);                            \
                    logger_flush();                             \
                    flushout();                                 \
                    flusherr();                                 \
                    puts("assertion failed on a " TOSTRING(AVL_NODE_TYPE));fflush(NULL);      \
                    abort();                                    \
                }                                               \
        }                                                       \
    }
#else

#define ASSERT_CHECK_CHILD_PARENT_LINK(node)

#endif

static AVL_NODE_TYPE*
avl_node_single_rotation2(AVL_NODE_TYPE *node)
{
    AVL_NODE_TYPE* save;

    assert(node != NULL);

    ASSERT_CHECK_CHILD_PARENT_LINK(node);

    if(AVL_BALANCE(node) < 0) /* balance = LEFT -> dir = RIGHT other = LEFT */
    {
        save = AVL_LEFT_CHILD(node);

        assert(save != NULL);

        ASSERT_CHECK_CHILD_PARENT_LINK(save);

#ifdef AVL_PARENT
        if(AVL_RIGHT_CHILD(save) != NULL)
        {
            AVL_PARENT(AVL_RIGHT_CHILD(save)) = node;
        }
        AVL_PARENT(save) = AVL_PARENT(node);
        AVL_PARENT(node) = save;
#endif

        AVL_LEFT_CHILD(node) = AVL_RIGHT_CHILD(save);
        AVL_RIGHT_CHILD(save) = node;
    }
    else
    {
        save = AVL_RIGHT_CHILD(node);

        assert(save != NULL);

        ASSERT_CHECK_CHILD_PARENT_LINK(save);

#ifdef AVL_PARENT
        if(AVL_LEFT_CHILD(save) != NULL)
        {
            AVL_PARENT(AVL_LEFT_CHILD(save)) = node;
        }
        AVL_PARENT(save) = AVL_PARENT(node);
        AVL_PARENT(node) = save;
#endif

        AVL_RIGHT_CHILD(node) = AVL_LEFT_CHILD(save);
        AVL_LEFT_CHILD(save) = node;
    }

    AVL_BALANCE(node) = MIDDLE;
    AVL_BALANCE(save) = MIDDLE;

    ASSERT_CHECK_CHILD_PARENT_LINK(node);

    return save;
}

static AVL_NODE_TYPE*
avl_node_double_rotation2(AVL_NODE_TYPE *node)
{
    AVL_NODE_TYPE* save;

    assert(node != NULL);

    if(AVL_BALANCE(node) < 0) /* balance = LEFT -> dir = RIGHT other = LEFT */
    {
        save = AVL_RIGHT_CHILD(AVL_LEFT_CHILD(node));

        if(AVL_BALANCE(save) == MIDDLE)
        {
            AVL_BALANCE(AVL_LEFT_CHILD(node)) = MIDDLE;
            AVL_BALANCE(node) = MIDDLE;
        }
        else if(AVL_BALANCE(save) > 0) /* dir right & balance right */
        {
            AVL_BALANCE(AVL_LEFT_CHILD(node)) = LEFT;
            AVL_BALANCE(node) = MIDDLE;
        }
        else /* AVL_BALANCE(save)<0 */
        {
            AVL_BALANCE(AVL_LEFT_CHILD(node)) = MIDDLE;
            AVL_BALANCE(node) = RIGHT;
        }

        AVL_BALANCE(save) = MIDDLE;

#ifdef AVL_PARENT
        if(AVL_LEFT_CHILD(node) != NULL)
        {
            AVL_PARENT(AVL_LEFT_CHILD(node)) = save;
        }

        if(AVL_LEFT_CHILD(save) != NULL)
        {
            AVL_PARENT(AVL_LEFT_CHILD(save)) = AVL_LEFT_CHILD(node);
        }

        if(AVL_RIGHT_CHILD(save) != NULL)
        {
            AVL_PARENT(AVL_RIGHT_CHILD(save)) = node;
        }

        AVL_PARENT(save) = AVL_PARENT(node);
        AVL_PARENT(node) = save;
#endif

        AVL_RIGHT_CHILD(AVL_LEFT_CHILD(node)) = AVL_LEFT_CHILD(save);
        AVL_LEFT_CHILD(save) = AVL_LEFT_CHILD(node);
        AVL_LEFT_CHILD(node) = AVL_RIGHT_CHILD(save);
        AVL_RIGHT_CHILD(save) = node;
    }
    else /* balance = RIGHT -> dir = LEFT other = RIGHT */
    {
        save = AVL_LEFT_CHILD(AVL_RIGHT_CHILD(node));

        assert(save != NULL);

        if(AVL_BALANCE(save) == MIDDLE)
        {

            AVL_BALANCE(AVL_RIGHT_CHILD(node)) = MIDDLE;
            AVL_BALANCE(node) = MIDDLE;
        }
        else if(AVL_BALANCE(save) < 0) /* dir left & balance left */
        {
            AVL_BALANCE(AVL_RIGHT_CHILD(node)) = RIGHT;
            AVL_BALANCE(node) = MIDDLE;
        }
        else /* AVL_BALANCE(save)>0 */
        {
            AVL_BALANCE(AVL_RIGHT_CHILD(node)) = MIDDLE;
            AVL_BALANCE(node) = LEFT;
        }

        AVL_BALANCE(save) = MIDDLE;

#ifdef AVL_PARENT
        if(AVL_RIGHT_CHILD(node) != NULL)
        {
            AVL_PARENT(AVL_RIGHT_CHILD(node)) = save;
        }

        if(AVL_RIGHT_CHILD(save) != NULL)
        {
            AVL_PARENT(AVL_RIGHT_CHILD(save)) = AVL_RIGHT_CHILD(node);
        }

        if(AVL_LEFT_CHILD(save) != NULL)
        {
            AVL_PARENT(AVL_LEFT_CHILD(save)) = node;
        }

        AVL_PARENT(save) = AVL_PARENT(node);
        AVL_PARENT(node) = save;
#endif

        AVL_LEFT_CHILD(AVL_RIGHT_CHILD(node)) = AVL_RIGHT_CHILD(save);
        AVL_RIGHT_CHILD(save) = AVL_RIGHT_CHILD(node);
        AVL_RIGHT_CHILD(node) = AVL_LEFT_CHILD(save);
        AVL_LEFT_CHILD(save) = node;
    }

    ASSERT_CHECK_CHILD_PARENT_LINK(node);

    return save;
}

static AVL_NODE_TYPE*
avl_create_node(AVL_REFERENCE_TYPE hash)
{
    AVL_NODE_TYPE *node;

    AVL_ALLOC_NODE(node, hash);

    AVL_LEFT_CHILD(node) = NULL;
    AVL_RIGHT_CHILD(node) = NULL;

    AVL_INIT_NODE(node, hash);

    AVL_BALANCE(node) = MIDDLE;

    return node;
}

/** @brief Initializes the tree
 *
 *  Initializes the tree.
 *  Basically : *tree=NULL;
 *
 *  @param[in]  tree the tree to initialize
 *
 */

void
AVL_PREFIXED(init)(AVL_TREE_TYPE* tree)
{
    AVL_TREE_ROOT(tree) = NULL;
}

/** @brief Find a node in the tree
 *
 *  Find a node in the tree matching a hash value.
 *
 *  @param[in]  root the tree to search in
 *  @param[in]  obj_hash the hash to find
 *
 *  @return A pointer to the node or NULL if there is no such node.
 */

AVL_NODE_TYPE*
AVL_PREFIXED(find)(AVL_CONST_TREE_TYPE* tree, AVL_REFERENCE_CONST AVL_REFERENCE_TYPE obj_hash)
{
    assert(tree != NULL);

    const AVL_NODE_TYPE *node = AVL_TREE_ROOT(tree);
    AVL_REFERENCE_MODIFIER AVL_REFERENCE_TYPE h;

    /* This is one of the parts I could try to optimize
     * I've checked the assembly, and it sucks ...
     */

    /* Both the double-test while/ternary and the current one
     * are producing the same assembly code.
     */

    while(node != NULL)
    {
        h = AVL_REFERENCE(node);

#if !AVL_TERNARYCMP
        if(AVL_ISEQUAL(h, obj_hash))
        {
            return (AVL_NODE_TYPE*)node;
        }

        node = AVL_CHILD(node, AVL_ISBIGGER(obj_hash, h)&1);
#else
        int cmp = AVL_COMPARE(h, obj_hash);

        if(cmp == 0)
        {
            return (AVL_NODE_TYPE*)node;
        }

        node = AVL_CHILD(node, (cmp<0)&1);
#endif
    }

    return NULL;
}

/** @brief Find a node in the tree or if such node does into exist, find the one after it (by key order)
 *
 *  Find a node in the tree or if such node does into exist, find the one after it (by key order)
 *
 *  @param[in]  root the tree to search in
 *  @param[in]  obj_hash the hash to find
 *
 *  @return A pointer to the node, or if it does not exists the node after it, or NULL if there is no such node.
 *
 *        L
 *       / \
 *      A   *
 *    /   \
 *    E     B
 *  /  \   / \
 * F   G  C   D
 *           /
 *          H
 *         /
 *        I
 *       / \
 *      J  K
 *
 */

AVL_NODE_TYPE*
AVL_PREFIXED(find_key_or_next)(AVL_CONST_TREE_TYPE* tree, AVL_REFERENCE_CONST AVL_REFERENCE_TYPE obj_hash)
{
    assert(tree != NULL);

    AVL_NODE_TYPE *node = AVL_TREE_ROOT(tree);
    AVL_REFERENCE_MODIFIER AVL_REFERENCE_TYPE h;

    // the stack is used to find parents

#if !AVL_HAS_PARENT_POINTER
    int stack_size = 0;
    AVL_NODE_TYPE *stack[48];
    stack[0] = NULL;
#else
    AVL_NODE_TYPE *prev = NULL;
#endif

    if(node != NULL)
    {
        do
        {
#if !AVL_HAS_PARENT_POINTER
            stack[stack_size++] = node;
#endif

            h = AVL_REFERENCE(node);

#if AVL_HAS_PARENT_POINTER
            prev = node;
#endif

#if !AVL_TERNARYCMP
            if(AVL_ISEQUAL(h, obj_hash))
            {
                return (AVL_NODE_TYPE*)node;
            }

            node = AVL_CHILD(node, AVL_ISBIGGER(obj_hash, h)&1);
#else
            int cmp = AVL_COMPARE(h, obj_hash);

            if(cmp == 0)
            {
                return (AVL_NODE_TYPE*)node;
            }

            node = AVL_CHILD(node, (cmp < 0)&1);
#endif
        }
        while(node != NULL);

        // the node was not found, now, using the stack, find the next node from the key

#if !AVL_HAS_PARENT_POINTER
        node = stack[--stack_size];

        if(node == NULL)
        {
            return node;
        }
#else
        if(prev == NULL)
        {
            return prev;
        }

        node = prev;
#endif

        // back on the last node on the path

#if !AVL_TERNARYCMP
        h = AVL_REFERENCE(node);
        if(AVL_ISBIGGER(h, obj_hash))
        {
            return node;
        }
#else
        int cmp = AVL_COMPARE(h, obj_hash);

        if(cmp >= 0)
        {
            return (AVL_NODE_TYPE*)node;
        }
#endif

        const AVL_NODE_TYPE *right_node = AVL_CHILD(node, DIR_RIGHT);
        if(right_node != NULL)
        {
            // the next node is below (the left-most node from the right child)
            // right_node is already a valid answer

            for(;;)
            {
                const AVL_NODE_TYPE *left_node = AVL_CHILD(right_node, DIR_LEFT);

                if(left_node != NULL)
                {
                    right_node = left_node;
                }
                else
                {
                    return (AVL_NODE_TYPE*)right_node;
                }
            }
        }
        else
        {
            // the next node is either the first "right" parent
            // either nothing

            for(;;)
            {
#if !AVL_HAS_PARENT_POINTER
                if(stack_size == 0)
                {
                    return (AVL_NODE_TYPE*)NULL;
                }

                const AVL_NODE_TYPE *parent_node = stack[--stack_size];
#else
                const AVL_NODE_TYPE *parent_node = AVL_PARENT(node);
                if(parent_node == NULL)
                {
                    return (AVL_NODE_TYPE*)NULL;
                }
#endif
                // if the node is the left child of the parent, then return the parent

                if(node == AVL_CHILD(parent_node, DIR_LEFT))
                {
                    return (AVL_NODE_TYPE*)parent_node;
                }

                node = (AVL_NODE_TYPE*)parent_node;
            }
        }
    }
    else
    {
        return NULL;
    }
}

/** @brief Find a node in the tree or if such node does into exist, find the one after it (by key order)
 *
 *  Find a node in the tree or if such node does into exist, find the one after it (by key order)
 *
 *  @param[in]  root the tree to search in
 *  @param[in]  obj_hash the hash to find
 *
 *  @return A pointer to the node, or if it does not exists the node after it, or NULL if there is no such node.
 */

AVL_NODE_TYPE*
AVL_PREFIXED(find_key_or_prev)(AVL_CONST_TREE_TYPE* tree, AVL_REFERENCE_CONST AVL_REFERENCE_TYPE obj_hash)
{
    assert(tree != NULL);

    AVL_NODE_TYPE *node = AVL_TREE_ROOT(tree);
    AVL_REFERENCE_MODIFIER AVL_REFERENCE_TYPE h;

    // the stack is used to find parents

#if !AVL_HAS_PARENT_POINTER
    int stack_size = 0;
    AVL_NODE_TYPE *stack[48];
    stack[0] = NULL;
#else
    AVL_NODE_TYPE *prev = NULL;
#endif

    if(node != NULL)
    {
        do
        {
#if !AVL_HAS_PARENT_POINTER
            stack[stack_size++] = node;
#endif

            h = AVL_REFERENCE(node);

#if AVL_HAS_PARENT_POINTER
            prev = node;
#endif

#if !AVL_TERNARYCMP
            if(AVL_ISEQUAL(h, obj_hash))
            {
                return (AVL_NODE_TYPE*)node;
            }

            node = AVL_CHILD(node, AVL_ISBIGGER(obj_hash, h)&1);
#else
            int cmp = AVL_COMPARE(h, obj_hash);

            if(cmp == 0)
            {
                return (AVL_NODE_TYPE*)node;
            }

            node = AVL_CHILD(node, (cmp < 0)&1);
#endif
        }
        while(node != NULL);

        // the node was not found, now, using the stack, find the next node from the key

#if !AVL_HAS_PARENT_POINTER
        node = stack[--stack_size];

        if(node == NULL)
        {
            return node;
        }
#else
        if(prev == NULL)
        {
            return prev;
        }

        node = prev;
#endif

        // back on the last node on the path

#if !AVL_TERNARYCMP
        h = AVL_REFERENCE(node);
        if(AVL_ISBIGGER(obj_hash, h))
        {
            return node;
        }
#else
        int cmp = AVL_COMPARE(obj_hash, h);

        if(cmp >= 0)
        {
            return (AVL_NODE_TYPE*)node;
        }
#endif

        const AVL_NODE_TYPE *left_node = AVL_CHILD(node, DIR_LEFT);
        if(left_node != NULL)
        {
            // the prev node is below (the right-most node from the left child)
            // left_node is already a valid answer

            for(;;)
            {
                const AVL_NODE_TYPE *right_node = AVL_CHILD(left_node, DIR_RIGHT);

                if(right_node != NULL)
                {
                    left_node = right_node;
                }
                else
                {
                    return (AVL_NODE_TYPE*)left_node;
                }
            }
        }
        else
        {
            // the next node is either the first "right" parent
            // either nothing

            for(;;)
            {
#if !AVL_HAS_PARENT_POINTER
                if(stack_size == 0)
                {
                    return (AVL_NODE_TYPE*)NULL;
                }

                const AVL_NODE_TYPE *parent_node = stack[--stack_size];
#else
                const AVL_NODE_TYPE *parent_node = AVL_PARENT(node);
                if(parent_node == NULL)
                {
                    return (AVL_NODE_TYPE*)NULL;
                }
#endif
                // if the node is the right child of the parent, then return the parent

                if(node == AVL_CHILD(parent_node, DIR_RIGHT))
                {
                    return (AVL_NODE_TYPE*)parent_node;
                }

                node = (AVL_NODE_TYPE*)parent_node;
            }
        }
    }
    else
    {
        return NULL;
    }
}

/** @brief Insert a node into the tree.
 *
 *  Insert data into the tree.
 *  Since hash can have collisions, the data will most likely be a collection
 *  (another tree, a list, ...)
 *
 *  NOTE:
 *  If the node associated to the hash already exists, it is returned unaltered,
 *  the caller will be responsible to manipulate the node's data.
 *  Else a new node is created, pointing to the data.
 *
 *  @param[in]  root the tree where the insertion should be made
 *  @param[in]  obj_hash the hash associated to the data
 *  @param[out] obj the data to insert
 *
 *  @return The node associated to the hash
 */

AVL_NODE_TYPE*
AVL_PREFIXED(insert)(AVL_TREE_TYPE* tree, AVL_REFERENCE_TYPE obj_hash)
{
    assert(tree != NULL);

    DUMP("avl_insert(%p, " AVL_REFERENCE_FORMAT_STRING
         ") ------------------------------",
         tree, AVL_REFERENCE_FORMAT(obj_hash));

    if(AVL_TREE_ROOT(tree) == NULL)
    {
        AVL_TREE_ROOT(tree) = avl_create_node(obj_hash);

        DUMP("First node (root) (" AVL_REFERENCE_FORMAT_STRING ")", AVL_REFERENCE_FORMAT(AVL_REFERENCE(AVL_TREE_ROOT(tree))));

        assert(AVL_TREE_ROOT(tree) != NULL);

        return AVL_TREE_ROOT(tree);
    }

    AVL_NODE_TYPE * nodes[AVL_MAX_DEPTH];
    s8 balances[AVL_MAX_DEPTH];
    s8 dirs[AVL_MAX_DEPTH];

    AVL_NODE_TYPE *node = AVL_TREE_ROOT(tree);
    AVL_REFERENCE_TYPE node_hash;
    int level = 0;
    s8 dir = MIDDLE;

#if !AVL_TERNARYCMP
    while((node != NULL) && !AVL_ISEQUAL(obj_hash, (node_hash = AVL_REFERENCE(node))))
    {
        nodes[level] = node;
        balances[level] = AVL_BALANCE(node);

        /* DIR_LEFT = 0, DIR_RIGHT = 1 */
        dir = AVL_ISBIGGER(obj_hash, node_hash)&1;

        ASSERT_CHECK_CHILD_PARENT_LINK(node);

        node = AVL_CHILD(node, dir);

        dirs[level++] = dir;
    }
#else

    while(node != NULL)
    {
        node_hash = AVL_REFERENCE(node);
        int cmp = AVL_COMPARE(obj_hash, node_hash);

        if(cmp == 0)
        {
            break;
        }

        nodes[level] = node;
        balances[level] = AVL_BALANCE(node);

        /* DIR_LEFT = 0, DIR_RIGHT = 1 */

        dir = (cmp > 0)&1;

        ASSERT_CHECK_CHILD_PARENT_LINK(node);

        node = AVL_CHILD(node, dir);

        dirs[level++] = dir;
    }
#endif

    DUMP("Level = %i", level);

    if(node != NULL)
    {
        /* match */

        DUMP("Got a match");

        ASSERT_CHECK_CHILD_PARENT_LINK(node);

        return node;
    }

    /* Add a new node to the last one (the AVL_PARENT) */

    node = nodes[--level];

    /* the parent is node */

    AVL_NODE_TYPE* ret = avl_create_node(obj_hash);
    AVL_CHILD(node, dir) = ret;

#ifdef AVL_PARENT
    AVL_PARENT(ret) = node;
#endif

    ASSERT_CHECK_CHILD_PARENT_LINK(ret);
    ASSERT_CHECK_CHILD_PARENT_LINK(node);

    DUMP("Created a new node from " AVL_REFERENCE_FORMAT_STRING ", going %i (%p)", AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)), dir, ret);

    if(AVL_BALANCE(node) == MIDDLE)
    {
        /* There were no AVL_CHILD, now there is one */
        /* not  balanced anymore */
        AVL_BALANCE(node) = DIR_TO_AVL_BALANCE(dir); /* 0 or 1 => -1 or +1 */

        DUMP("Parent was  balanced, now it is not anymore : %i (%i)", dir, AVL_BALANCE(node));
    }
    else
    {
        /* There was a AVL_CHILD, now there is two */
        /* balance */
        AVL_BALANCE(node) = MIDDLE;

        DUMP("Parent was not  balanced, now it is");
    }

    AVL_NODE_TYPE* parent;

    /* Now I have to update the balance up to the root (if needed ...)
     * node is m_nodes[level]
     * we need the parent at m_nodes[level-1]
     * parent -> node -> (new node/processed node)
     */

    while(level > 0) /* level points to the parent */
    {
        DUMP("\tUpdating balance at %i", level);

        if(AVL_BALANCE(node) == balances[level]) /* balance of the node */
        { /* this branch will exit */
            /* The node's balance has not been changed */

            ASSERT_CHECK_CHILD_PARENT_LINK(ret);

            return ret;
        }

        /* The node's balance has been changed */

        DUMP("\t\tBalance of " AVL_REFERENCE_FORMAT_STRING " was %i, now it is %i",
             AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)), balances[level], AVL_BALANCE(node));

        if(AVL_BALANCE(node) == MIDDLE) /* this branch will exit */
        {
            /* AVL_BALANCE(node)==MIDDLE and we are  balanced
             *  balanced -> done
             */

            ASSERT_CHECK_CHILD_PARENT_LINK(ret);

            DUMP("Done (E)");

            return ret;
        }

        parent = nodes[level - 1];

        /* not  balanced (anymore) */
        /* Now dir AVL_CHILD it is un balanced ... */
        /* Let's update the imbalance */

        dir = dirs[level - 1];

        DUMP("\t\t\timbalance: dir=%i old parent balance=%i patch=%i", dir, AVL_BALANCE(parent), DIR_TO_AVL_BALANCE(dir));

        AVL_BALANCE(parent) += DIR_TO_AVL_BALANCE(dir);

        if(MUST_REAVL_BALANCE(parent)) /* this branch will exit */
        {
            /* parent is the "root" */
            /* node is the pivot */

            DUMP("\t\t\t\tREBALANCING of " AVL_REFERENCE_FORMAT_STRING "", AVL_REFERENCE_FORMAT(AVL_REFERENCE(parent)));

            AVL_BALANCE(parent) >>= 1; /* reset the balance to -1;1 ... */

            DUMP("\t\t\t\tbalance fix -> %i", AVL_BALANCE(parent));

            /* HERE THE AVL_BALANCES ARE LOST/CORRUPTED !!! */

            if(AVL_BALANCE(node) == AVL_BALANCE(parent)) /* if the sign is the same ... */
            {
                /* AVL_BALANCE(node)=0; */
                node = avl_node_single_rotation2(parent);

                /* the parent's parent has to be updated (to node) */

                DUMP("\t\t\t\tSingle rotation, new parent is " AVL_REFERENCE_FORMAT_STRING "", AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)));
            }
            else
            {
                /* AVL_BALANCE(node)=0; */
                node = avl_node_double_rotation2(parent);

                /* the parent's parent has to be updated (to node) */

                DUMP("\t\t\t\tDouble rotation, new parent is " AVL_REFERENCE_FORMAT_STRING "", AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)));
            }

            /* typically ...
             * level--;
             * node=parent;
             * parent=m_nodes[level-1];
             * here I have to reset the new parent
             * -> I have to get the parent on level-2 (oops if level is < 2 :
             *      it means that the parent is the root, thus that we have to fix the root)
             * -> I have to get the dir used on level-2 and set it to node
             */

            if(level > 1) /* 2 or more ... */
            {
                AVL_CHILD(nodes[level - 2], dirs[level - 2]) = node;
            }
            else /* root */
            {
                DUMP("Root changing from " AVL_REFERENCE_FORMAT_STRING
                     " to " AVL_REFERENCE_FORMAT_STRING "",
                     AVL_REFERENCE_FORMAT(AVL_REFERENCE(AVL_TREE_ROOT(tree))),
                     AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)));

                AVL_TREE_ROOT(tree) = node;
            }

            ASSERT_CHECK_CHILD_PARENT_LINK(node);

            /* rebalancing -> done */

            DUMP("Done (I)");

            ASSERT_CHECK_CHILD_PARENT_LINK(ret);

            return ret;
        }

        node = parent;

        ASSERT_CHECK_CHILD_PARENT_LINK(node);
        ASSERT_CHECK_CHILD_PARENT_LINK(parent);

        level--;
    }

    ASSERT_CHECK_CHILD_PARENT_LINK(ret);

    return ret;
}

/** @brief Deletes a node from the tree.
 *
 *  Deletes a node from the tree.
 *
 *  @param[in]  root the tree from which the delete will be made
 *  @param[in]  obj_hash the hash associated to the node to remove
 *
 *  @return The node associated to the hash, NULL if it did not exist.
 */

void
AVL_PREFIXED(delete)(AVL_TREE_TYPE* tree, AVL_REFERENCE_CONST AVL_REFERENCE_TYPE obj_hash)
{
    DUMP("avl_delete(%p, " AVL_REFERENCE_FORMAT_STRING ") ------------------------------", tree, AVL_REFERENCE_FORMAT(obj_hash));

    assert(tree != NULL);

    if(AVL_TREE_ROOT(tree) == NULL)
    {
        /* Already empty */

        return;
    }

    AVL_NODE_TYPE *nodes[AVL_MAX_DEPTH];
    s8 balances[AVL_MAX_DEPTH];
    s8 dirs[AVL_MAX_DEPTH];

#if DEBUG
    memset(&nodes, 0xf0, sizeof(AVL_NODE_TYPE*) * AVL_MAX_DEPTH);
    memset(&balances, 0xfb, AVL_MAX_DEPTH);
    memset(&dirs, 0xfd, AVL_MAX_DEPTH);
#endif

    AVL_NODE_TYPE *node = AVL_TREE_ROOT(tree);
    AVL_REFERENCE_TYPE node_hash;
    int level = 0;
    s8 dir = MIDDLE;

    /* look for the node to delete, keep the path */

#if !AVL_TERNARYCMP
    while((node != NULL) && !AVL_ISEQUAL(obj_hash, (node_hash = AVL_REFERENCE(node))))
    {
        nodes[level] = node;
        balances[level] = AVL_BALANCE(node);

        /* DIR_LEFT = 0, DIR_RIGHT = 1 */
        dir = AVL_ISBIGGER(obj_hash, node_hash)&1;
        node = AVL_CHILD(node, dir);

        dirs[level++] = dir;
    }
#else
    while(node != NULL)
    {
        node_hash = AVL_REFERENCE(node);

        int cmp = AVL_COMPARE(obj_hash, node_hash);

        if(cmp == 0)
        {
            break;
        }

        nodes[level] = node;
        balances[level] = AVL_BALANCE(node);

        /* DIR_LEFT = 0, DIR_RIGHT = 1 */

        dir = (cmp > 0)&1;
        node = AVL_CHILD(node, dir);

        dirs[level++] = dir;
    }
#endif

    DUMP("Level = %i", level);

    assert(level < AVL_MAX_DEPTH);

    if(node == NULL)
    {
        /* no match : nothing to delete */

        DUMP("No match");

        return;
    }

    DUMP("[%2i] Victim is "AVL_REFERENCE_FORMAT_STRING, level, AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)));

    /* keep a pointer to the parent->child pointer */

    AVL_NODE_TYPE **victim_parent_link = &AVL_TREE_ROOT(tree);

    if(level > 0)
    {
        victim_parent_link = &(AVL_CHILD(nodes[level - 1],dirs[level - 1]));
    }

    nodes[level] = node;
    balances[level] = AVL_BALANCE(node);
    dirs[level++] = dir; /* THIS IS WRONG (?) */

    /* Remove "node" from the parent */
    /* Keep the pointer for the find & destroy operation */

    AVL_NODE_TYPE* victim = node;

#ifdef AVL_NODE_DELETE_CALLBACK
    AVL_NODE_DELETE_CALLBACK(victim);
#endif

    AVL_NODE_TYPE* victim_left = AVL_LEFT_CHILD(node);
    AVL_NODE_TYPE* victim_right = AVL_RIGHT_CHILD(node);

    /** We have found the victim node.  From here 3 cases can be found
     *
     *  #1 : the victim has no AVL_CHILD.  We just have to remove it. (and change parent balance)
     *
     *  #2 : the victim has only got one AVL_CHILD.  We just have to remove it and
     *  put its children in its place.
     *
     *  #3 : the victim has got two children.
     *
     *       Method '1': Theoretical way:
     *
     *       We move the successor of the victim instead of B, then delete using
     *       #1 or #2.
     *
     *       Actually this requires a lot of work. (5 to 10 times more than ...)
     *
     *       Method '2': Fastest way: (and forbidden with the NSEC3 because I keep pointer into the nodes)
     *
     *       We have to find his "successor" (left or right).
     *       We overwrite the data of the successor into the victim.
     *       We link the parent of the successor
     *       We then rebalance from the node right before where successor was.
     *
     *  #3 is dependent on #1 and #2 so let's handle #3 first.
     */

    if(victim_left != NULL && victim_right != NULL)
    {
        /** Case #3:
         *
         *  @note: It is recommended to switch left/right successors
         *  between each delete for a better balancing.
         *
         *  NOTE: The path has to be completed.
         *
         */

        DUMP("#3");

        /* Arbitraty: "<" successor */
        /****************************/

        /*
         * Look for the node that will replace this one.
         * Given that we are in a (L-R) case, it's the last one in the chain L->R*
         */

        s32 victim_level = level - 1;

        dirs[victim_level] = DIR_LEFT;

        DUMP("[%2i] From "AVL_REFERENCE_FORMAT_STRING ", going LEFT", level-1, AVL_REFERENCE_FORMAT(AVL_REFERENCE(victim)));
        DUMP("\tUpdating balance at %i", level-1);
        DUMP("\t\tBalance of " AVL_REFERENCE_FORMAT_STRING " was %i, now it is %i",
             AVL_REFERENCE_FORMAT(AVL_REFERENCE(victim)), balances[level-1], AVL_BALANCE(victim));

        AVL_NODE_TYPE* beforesuccessor = victim; /* actually it's "victim" here */
        AVL_NODE_TYPE* successor = victim_left;
        AVL_NODE_TYPE* tmp_node;

        nodes[level] = successor;
        balances[level] = AVL_BALANCE(successor);
        dirs[level++] = DIR_RIGHT;

        while((tmp_node = AVL_RIGHT_CHILD(successor)) != NULL)
        {
            beforesuccessor = successor;

            DUMP("[%2i] From " AVL_REFERENCE_FORMAT_STRING ", going RIGHT", level-1, AVL_REFERENCE_FORMAT(AVL_REFERENCE(successor)));
            
            successor = tmp_node;
            nodes[level] = successor;

            DUMP("\tUpdating balance at %i", level);
            DUMP("\t\tBalance of " AVL_REFERENCE_FORMAT_STRING " was %i, now it is %i",
                AVL_REFERENCE_FORMAT(AVL_REFERENCE(successor)), balances[level], AVL_BALANCE(successor));

            balances[level] = AVL_BALANCE(successor);
            dirs[level++] = DIR_RIGHT;
        }

        assert(level < AVL_MAX_DEPTH);

        /* successor has at most one left AVL_CHILD */

        DUMP("[%2i] Replacement "AVL_REFERENCE_FORMAT_STRING, level-1, AVL_REFERENCE_FORMAT(AVL_REFERENCE(successor)));

        /* Method 2 uses 3 moves, method 1 uses 10 */

#if 1
        /* 
         * Move the parent of victim must point to successor
         * The parent of successor must point to nothing.
         */

        *victim_parent_link = successor;

        nodes[victim_level] = successor;

        AVL_RIGHT_CHILD(successor) = victim_right;
        AVL_BALANCE(successor) = AVL_BALANCE(victim);

#ifdef AVL_PARENT
        AVL_PARENT(successor) = AVL_PARENT(victim);
        AVL_PARENT(victim_right) = successor;
#endif

        if(beforesuccessor != victim)
        {
            AVL_RIGHT_CHILD(beforesuccessor) = AVL_LEFT_CHILD(successor);
#ifdef AVL_PARENT
            if(AVL_LEFT_CHILD(successor) != NULL)
            {
                AVL_PARENT(AVL_LEFT_CHILD(successor)) = beforesuccessor;
            }
#endif
            
            AVL_LEFT_CHILD(successor) = victim_left;
#ifdef AVL_PARENT
            AVL_PARENT(victim_left) = successor;
#endif
            AVL_BALANCE(beforesuccessor)--;

            level -= 2;
        }
        else
        {
            AVL_BALANCE(successor)++;

            level -= 2;
        }

        AVL_FREE_NODE(victim);

        
#else
        /*
         *  Overwrite node successor into victim,
         *  then delete successor, since its content is safe
         *
         *  This special case does not work if the node is linked by a third party
         *  so I disabled it to avoid misuses.
         */

        AVL_COPY_PAYLOAD(victim, successor);

        if(beforesuccessor != victim)
        {
            AVL_RIGHT_CHILD(beforesuccessor) = AVL_LEFT_CHILD(successor);
            AVL_BALANCE(beforesuccessor)--;
        }
        else
        {
            AVL_LEFT_CHILD(beforesuccessor) = AVL_LEFT_CHILD(successor);
            AVL_BALANCE(beforesuccessor)++;
        }

        AVL_FREE_NODE(successor);

        level -= 2;
#endif

        /*nodes[level] = successor;*/

    } /* Case #3 done */
    else
    {
        /* Only 2 cases could occur right now : #1 and #2 */

        AVL_FREE_NODE(victim);

        if(level > 1)
        {
            AVL_NODE_TYPE* victim_parent = nodes[level - 2];

            /* ONE or BOTH are NULL, this is the best alternative to an if/elseif/else */

            AVL_CHILD(victim_parent, dir) = (AVL_NODE_TYPE*)((intptr)victim_left | (intptr)victim_right);

#ifdef AVL_PARENT
            if(victim_left != NULL)
            {
                AVL_PARENT(victim_left) = victim_parent;
            }
            if(victim_right != NULL)
            {
                AVL_PARENT(victim_right) = victim_parent;
            }
#endif

            AVL_BALANCE(victim_parent) -= DIR_TO_AVL_BALANCE(dir); /* The balance has changed */

            /* At this point the victim is detached from the tree */
            /* I can delete it */

            level -= 2;
        }
        else /* Else we have no AVL_PARENT, so we change the root */
        {

            /* ONE or BOTH are NULL, this is the best alternative to the if/elseif/else above */
            AVL_TREE_ROOT(tree) = (AVL_NODE_TYPE*)((intptr)victim_left | (intptr)victim_right);
#ifdef AVL_PARENT
            if(victim_left != NULL)
            {
                AVL_PARENT(victim_left) = NULL;
            }
            if(victim_right != NULL)
            {
                AVL_PARENT(victim_right) = NULL;
            }
#endif

            return;
        }
    }

    /* Rebalance will occur either from the replacement's parent, either from
     * the victim's parent.
     */
    /* NOTE: A delete-rebalance can occur many times, up to the root. */
    node = nodes[level];

    /* Now I have to update the balance up to the root (if needed ...)
     * node is m_nodes[level]
     * we need the parent at m_nodes[level-1]
     * parent -> node -> (new node/processed node)
     */

    while(level >= 0) /* level points to the parent */
    {
        if(AVL_BALANCE(node) == balances[level]) /* balance of the node, scan-build false positive */
        {
            /* this branch will exit */
            /* The node's balance has not been changed */

            return;
        }

        /* The node's balance has been changed */

        /*
         * balance became 0 : It was -1 or +1 : the tree's height decreased.
         * It is  balanced but a propagation is required.
         *
         * balance became -1 or +1 : It was 0 : the tree's height didn't changed.
         * (One of its branch is shorter but the other one's size didn't changed.)
         * It is a valid AVL and the propagation can stop.
         *
         * balance became -2 or +2 : it was -1 or +1 : the tree is un balanced.
         * It needs to be re balanced and then a propagation is required.
         */

        if(AVL_BALANCE(node) == MIDDLE)
        {
            /* Height decreased, tell it to the parent */

            level--;

            if(level >= 0)
            {
                DUMP("\t[%2i] " AVL_REFERENCE_FORMAT_STRING " balance changed for MIDDLE (%i) Fixing [%i] parent balance of %i (%i)",
                     level + 1, AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)), balances[level + 1], level, DIR_TO_AVL_BALANCE(dirs[level]), dirs[level]);

                node = nodes[level];
                AVL_BALANCE(node) -= DIR_TO_AVL_BALANCE(dirs[level]);
            }

            continue;
        }

        if(AVL_BALANCE(node) == LEFT || AVL_BALANCE(node) == RIGHT) /* this branch will exit */
        {
            DUMP("\t[%2i] " AVL_REFERENCE_FORMAT_STRING " balance changed for LEFT or RIGHT (%i)", level, AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)), balances[level]);

            return;
        }

        DUMP("\t[%2i] " AVL_REFERENCE_FORMAT_STRING " balance changed for imbalance (%i)", level, AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)), balances[level]);

        /*
         * We need to rotate in order to be AVL again.
         *
         * + cases:
         *
         * R(+) P(-) => R(0) P(0) (double rotation)
         * R(+) P(0) => R(+) P(-) (single rotation, delete special case)
         * R(+) P(+) => R(0) P(0) (single roration)
         *
         * => if node&save balance are equal => MIDDLE for both
         *
         */

        AVL_BALANCE(node) >>= 1;

        AVL_NODE_TYPE* child = AVL_CHILD(node, AVL_BALANCE_TO_DIR(AVL_BALANCE(node)));
        s8 parent_balance = AVL_BALANCE(node);
        s8 child_balance = AVL_BALANCE(child);

        if(child_balance == MIDDLE) /* patched single rotation */
        {
            DUMP("Single Rotation (delete)");

            AVL_NODE_TYPE* newroot;

            newroot = avl_node_single_rotation2(node);

            assert(newroot == child);

            AVL_BALANCE(child) = -parent_balance;
            AVL_BALANCE(node) = parent_balance;

            node = newroot;
        }
        else if(parent_balance == child_balance) /* single rotation case */
        {
            DUMP("Single Rotation");

            node = avl_node_single_rotation2(node);

            assert(node == child);
        }
        else
        {
            DUMP("Double Rotation");

            node = avl_node_double_rotation2(node);
        }

        if(level == 0) /* 2 or more ... */
        {
            /* root */

            DUMP("Root changing from " AVL_REFERENCE_FORMAT_STRING " to "
                 AVL_REFERENCE_FORMAT_STRING "",
                 AVL_REFERENCE_FORMAT(AVL_REFERENCE(AVL_TREE_ROOT(tree))),
                 AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)));

            AVL_TREE_ROOT(tree) = node;
            break;
        }

        /* link the parent to its new child  */

        /*
        level--;

        AVL_CHILD(nodes[level],dirs[level])=node;

        node=nodes[level];
         */

        /* The rotations could have changed something */
        /* I'll process the same level again */

        AVL_CHILD(nodes[level - 1], dirs[level - 1]) = node;
        //AVL_CHILD(nodes[level], dirs[level]) = node;

        ASSERT_CHECK_CHILD_PARENT_LINK(node);

        /* node=nodes[level]; */
    }

    DUMP("avl_delete done level=%i", level);
}

static void
avl_destroy_(AVL_NODE_TYPE *node)
{
#ifdef AVL_NODE_DELETE_CALLBACK
    AVL_NODE_DELETE_CALLBACK(node);
#endif

    AVL_NODE_TYPE* AVL_CHILD = AVL_LEFT_CHILD(node);
    if(AVL_CHILD != NULL)
    {
        avl_destroy_(AVL_CHILD);
    }
    AVL_CHILD = AVL_RIGHT_CHILD(node);
    if(AVL_CHILD != NULL)
    {
        avl_destroy_(AVL_CHILD);
    }

    AVL_FREE_NODE(node);
}

/** @brief Releases all the nodes of a tree
 *
 *  Releases all the nodes of a tree.  Data is not destroyed.
 *
 *  @param[in] tree the tree to empty
 */

void
AVL_PREFIXED(destroy)(AVL_TREE_TYPE* tree)
{
    if(AVL_TREE_ROOT(tree) != NULL)
    {

        avl_destroy_(AVL_TREE_ROOT(tree));
        AVL_TREE_ROOT(tree) = NULL;
    }
}

AVL_NODE_TYPE*
AVL_PREFIXED(node_last)(AVL_NODE_TYPE *node)
{
    if(node == NULL)
    {
        return NULL;
    }

    for(;;)
    {
        AVL_NODE_TYPE *next = AVL_RIGHT_CHILD(node);

        if(next == NULL)
        {
            return node;
        }

        node = next;
    }
}

/* Iterators -> */

void
AVL_PREFIXED(iterator_init)(AVL_CONST_TREE_TYPE *tree, AVL_PREFIXED(iterator*) iter)
{
    /* Do we have a tree to iterate ? */

    iter->stack_pointer = -1;

    const AVL_NODE_TYPE *node = AVL_TREE_ROOT(tree);

    while(node != NULL)
    {
        iter->stack[++iter->stack_pointer] = (AVL_NODE_TYPE*)node;
        node = AVL_LEFT_CHILD(node);
    }
}

void
AVL_PREFIXED(iterator_init_from)(AVL_CONST_TREE_TYPE *tree, AVL_PREFIXED(iterator*) iter, AVL_REFERENCE_CONST AVL_REFERENCE_TYPE obj_hash)
{
    // Do we have a tree to iterate ?

    iter->stack_pointer = -1;

    if(tree != NULL)
    {
        // Let's stack the path left path

        AVL_NODE_TYPE *node = AVL_TREE_ROOT(tree);
        AVL_REFERENCE_MODIFIER AVL_REFERENCE_TYPE h;

        while(node != NULL)
        {
            h = AVL_REFERENCE(node);

#if !AVL_TERNARYCMP
            if(AVL_ISBIGGER(h, obj_hash))
            {
                iter->stack[++iter->stack_pointer] = node;
                node = AVL_LEFT_CHILD(node);
            }
            else if(AVL_ISBIGGER(obj_hash, h))
            {
                node = AVL_RIGHT_CHILD(node);
            }
            else
            {
                iter->stack[++iter->stack_pointer] = node;

                return;
            }
#else
            int cmp = AVL_COMPARE(h, obj_hash);

            if(cmp > 0)
            {
                iter->stack[++iter->stack_pointer] = node;
                node = AVL_LEFT_CHILD(node);
            }
            else if(cmp < 0)
            {
                node = AVL_RIGHT_CHILD(node);
            }
            else
            {
                iter->stack[++iter->stack_pointer] = node;

                return;
            }
#endif
        }
    }
}

bool
AVL_PREFIXED(iterator_hasnext)(AVL_PREFIXED(iterator*) iter)
{
    return iter->stack_pointer >= 0;
}

AVL_NODE_TYPE*
AVL_PREFIXED(iterator_next_node)(AVL_PREFIXED(iterator*) iter)
{
    assert(iter->stack_pointer >= 0);

    AVL_NODE_TYPE *node = iter->stack[iter->stack_pointer];
    AVL_NODE_TYPE* current = node;

    /* we got the data, now let's ready the next node */

    AVL_NODE_TYPE* tmp;

    /* let's branch right if possible */

    if((tmp = AVL_RIGHT_CHILD(node)) != NULL)
    {
        iter->stack[iter->stack_pointer] = tmp; /* replace TOP */

        node = tmp;
        while((tmp = AVL_LEFT_CHILD(node)) != NULL)
        {
            iter->stack[++iter->stack_pointer] = tmp; /* PUSH @note edf 20180102 -- overflow is unlikely: the depth of the stack allows iteration on collections of tens of billions of items */
            node = tmp;
        }

        return current;
    }

    iter->stack_pointer--;

    return current;
}

/* <- Iterators */

static void
avl_callback_and_destroy_(AVL_NODE_TYPE *node, void (*callback)(AVL_NODE_TYPE *))
{
    AVL_NODE_TYPE* AVL_CHILD = AVL_LEFT_CHILD(node);
    if(AVL_CHILD != NULL)
    {
        avl_callback_and_destroy_(AVL_CHILD, callback);
    }
    AVL_CHILD = AVL_RIGHT_CHILD(node);
    if(AVL_CHILD != NULL)
    {
        avl_callback_and_destroy_(AVL_CHILD, callback);
    }

    callback(node);

    AVL_FREE_NODE(node);
}

/** @brief Releases all the nodes of a tree
 *
 *  Releases all the nodes of a tree.
 *  Calls a function passed in parameter before destroying the data.
 *  It's the responsibility of the callback to process (destroy) the data
 *  in the tree.
 *
 *  @param[in] tree the tree to empty
 */

void
AVL_PREFIXED(callback_and_destroy)(AVL_TREE_TYPE *tree, void (*callback)(AVL_NODE_TYPE *))
{
    if(AVL_TREE_ROOT(tree) != NULL)
    {
        avl_callback_and_destroy_(AVL_TREE_ROOT(tree), callback);
        AVL_TREE_ROOT(tree) = NULL;
    }
}

AVL_NODE_TYPE*
AVL_PREFIXED(get_first)(AVL_CONST_TREE_TYPE* tree)
{
    assert(tree != NULL);

    AVL_NODE_TYPE *node = AVL_TREE_ROOT(tree);
    
    if(node != NULL)
    {
        while(node->children.lr.left != NULL)
        {
            node = node->children.lr.left;
        }
    }
    
    return node;
}

#ifdef AVL_PARENT

AVL_NODE_TYPE*
AVL_PREFIXED(node_next)(const AVL_NODE_TYPE *node)
{
    AVL_NODE_TYPE* next;

    next = AVL_RIGHT_CHILD(node);

    if(next != NULL)
    {
        /* Not a leaf */

        /*
         * From the (current) right, go all the way down to the left.
         */

        while(AVL_LEFT_CHILD(next) != NULL)
        {
            next = AVL_LEFT_CHILD(next);
        }
    }
    else
    {
        /* Leaf */

        /*
         * Go up until we are the left child
         */

        next = AVL_PARENT(node);

        while(next != NULL)
        {
            if(AVL_LEFT_CHILD(next) == node)
            {
                break;
            }

            node = next;

            next = AVL_PARENT(node);
        }
    }

    return next;
}

AVL_NODE_TYPE*
AVL_PREFIXED(node_prev)(const AVL_NODE_TYPE *node)
{
    AVL_NODE_TYPE* prev;

    prev = AVL_LEFT_CHILD(node);

    if(prev != NULL)
    {
        /* Not a leaf */

        /*
         * From the (current) left, go all the way down to the right.
         * If there is nothing, then the current node (prev) is the one I'm looking for.
         */

        while(AVL_RIGHT_CHILD(prev) != NULL)
        {
            prev = AVL_RIGHT_CHILD(prev);
        }
    }
    else
    {
        /* Leaf */


        for(;;)
        {
            prev = AVL_PARENT(node);

            if(prev == NULL)
            {
                break; /* no pred */
            }

            if(AVL_RIGHT_CHILD(prev) == node)
            {
                break;
            }

            node = prev;
        }

    }

    return prev;
}

AVL_NODE_TYPE*
AVL_PREFIXED(node_mod_next)(const AVL_NODE_TYPE *node)
{
    AVL_NODE_TYPE* next;
    
    next = AVL_RIGHT_CHILD(node);

    if(next != NULL)
    {
        /* Not a leaf */

        /*
         * From the (current) right, go all the way down to the left.
         */

        while(AVL_LEFT_CHILD(next) != NULL)
        {
            next = AVL_LEFT_CHILD(next);
        }
    }
    else
    {
        /* Leaf */

        /*
         * Go up until we are the left child
         */

        next = AVL_PARENT(node);

        while(next != NULL)
        {
            if(AVL_LEFT_CHILD(next) == node)
            {
                break;
            }

            node = next;

            next = AVL_PARENT(node);
        }

        if(next == NULL)
        {
            /* Modulo */

            /* We are at the root, the next one is the one most on the left
             * or ourself.
             */

            next = (AVL_NODE_TYPE*)node; // node is not the starting point anymore, so casting to not-const is ok

            while(AVL_LEFT_CHILD(next) != NULL)
            {
                next = AVL_LEFT_CHILD(next);
            }
        }
    }

    return next;
}

AVL_NODE_TYPE*
AVL_PREFIXED(node_mod_prev)(const AVL_NODE_TYPE *node)
{
    AVL_NODE_TYPE* prev;
    
    prev = AVL_LEFT_CHILD(node);

    if(prev != NULL)
    {
        /* Not a leaf */

        /*
         * From the (current) left, go all the way down to the right.
         */

        while(AVL_RIGHT_CHILD(prev) != NULL)
        {
            prev = AVL_RIGHT_CHILD(prev);
        }
    }
    else
    {
        /* Leaf */

        /*
         * Go up until we are the right child
         */

        prev = AVL_PARENT(node);

        while(prev != NULL)
        {
            if(AVL_RIGHT_CHILD(prev) == node)
            {
                break;
            }

            node = prev;

            prev = AVL_PARENT(node);
        }

        if(prev == NULL)
        {
            /* Modulo */

            /* We are at the root, the prev one is the one most on the right
             * or ourself.
             */

            prev = (AVL_NODE_TYPE*)node; // node is not the starting point anymore, so casting to not-const is ok

            while(AVL_RIGHT_CHILD(prev) != NULL)
            {
                prev = AVL_RIGHT_CHILD(prev);
            }
        }
    }

    return prev;
}

#endif // AVL_PARENT

static int
AVL_PREFIXED(check_common)(AVL_NODE_TYPE *node, int depth);

static int
AVL_PREFIXED(check_node)(AVL_NODE_TYPE *node, int depth)
{
#if AVL_HAS_PARENT_POINTER == 1
    if(AVL_PARENT(node) == NULL)
    {
        /* oops */
        DUMP("avl_check_node: expected a parent");
        logger_flush();
        DUMP("avl_check_node:\tnode=(%p, " AVL_REFERENCE_FORMAT_STRING")",node, AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)));
        logger_flush();
        return -depth;
    }

    if(AVL_PARENT(node))
    {
        AVL_NODE_TYPE *parent__ = AVL_PARENT(node);
        if(parent__ != NULL)
        {

            AVL_NODE_TYPE *l__ = AVL_LEFT_CHILD(parent__);


            AVL_NODE_TYPE *r__ = AVL_RIGHT_CHILD(parent__);



            if(!(l__==(node) ||
                 r__==(node))	)
                {
                    DUMP("avl_check_node: parent->node link broken");
                    DUMP("avl_check_node:\tparent=(%p, " AVL_REFERENCE_FORMAT_STRING")",parent__, AVL_REFERENCE_FORMAT(AVL_REFERENCE(parent__)));
                    if(l__ != NULL)
                    {
                        DUMP("avl_check_node:\t\tparent.lt=(%p, " AVL_REFERENCE_FORMAT_STRING")",l__, AVL_REFERENCE_FORMAT(AVL_REFERENCE(l__)));
                    }
                    if(r__ != NULL)
                    {
                        DUMP("avl_check_node:\t\tparent.rt=(%p, " AVL_REFERENCE_FORMAT_STRING")",r__, AVL_REFERENCE_FORMAT(AVL_REFERENCE(r__)));
                    }
                    DUMP("avl_check_node:\tnode=(%p, " AVL_REFERENCE_FORMAT_STRING")",node, AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)));
                    DUMP_NODE(parent__);
                    DUMP_NODE(node);
                    logger_flush();
                    flushout();
                    flusherr();
                    return -depth;
                }
        }
    }
#endif

    return AVL_PREFIXED(check_common)(node, depth);
}

static int
AVL_PREFIXED(check_common)(AVL_NODE_TYPE *node, int depth)
{
    int ld = depth;
    int rd = depth;

    AVL_NODE_TYPE *lc = AVL_LEFT_CHILD(node);
    AVL_NODE_TYPE *rc = AVL_RIGHT_CHILD(node);

    if(lc != NULL)
    {
        if((ld = AVL_PREFIXED(check_node)(lc, depth + 1)) < 0)
        {
            return ld;
        }
    }
    if(rc != NULL)
    {
        if((rd = AVL_PREFIXED(check_node)(rc, depth + 1)) < 0)
        {
            return rd;
        }
    }

    s8 b = AVL_BALANCE(node);

    if( ((ld == rd) && (b != MIDDLE)) ||
        ((ld >  rd) && (b != LEFT))   ||
        ((ld <  rd) && (b != RIGHT))  ||
        (abs(ld - rd) > 1)            )
    {
        /* oops */

        DUMP("avl_check_common: invalid balancing |%d - %d| = %i (b = %i)", ld, rd, rd - ld, b);
        logger_flush();
        DUMP("avl_check_node:\tnode=(%p, " AVL_REFERENCE_FORMAT_STRING")",node, AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)));
        logger_flush();

        return -depth;
    }

    return MAX(ld, rd);
}

void AVL_PREFIXED(forall)(AVL_CONST_TREE_TYPE* tree, AVL_PREFIXED(forall_callback) *callback, void *callback_args)
{
#if AVL_HAS_PARENT_POINTER
    
    AVL_NODE_TYPE *node = AVL_PREFIXED(get_first)(tree);
    while(node != NULL)
    {
        if(callback(node, callback_args) <= 0)
        {
            return;
        }
        
        node = AVL_PREFIXED(node_next)(node);
    }
#else
    AVL_PREFIXED(iterator) iter;
    AVL_PREFIXED(iterator_init)(tree, &iter);
    while(AVL_PREFIXED(iterator_hasnext)(&iter))
    {
        AVL_NODE_TYPE *node = AVL_PREFIXED(iterator_next_node)(&iter);
        if(callback(node, callback_args) <= 0)
        {
            break;
        }
    }
#endif
}

int
AVL_PREFIXED(check_tree)(AVL_TREE_TYPE* tree)
{
    if(AVL_TREE_ROOT(tree) == NULL)
    {
        return 0;
    }
    
#if AVL_HAS_PARENT_POINTER == 1
    if(AVL_PARENT(AVL_TREE_ROOT(tree)) != NULL)
    {
        /* oops */
        DUMP("avl_check: didn't expected a parent");
        logger_flush();
        DUMP("avl_check:\troot=(%p, " AVL_REFERENCE_FORMAT_STRING")",AVL_TREE_ROOT(tree), AVL_REFERENCE_FORMAT(AVL_REFERENCE(AVL_TREE_ROOT(tree))));
        logger_flush();
        return -1;
    }
#endif
    
    int depth = AVL_PREFIXED(check_common)(AVL_TREE_ROOT(tree), 0);

    return depth;
}

static void
AVL_PREFIXED(dump_node)(AVL_NODE_TYPE *node, int level, char c)
{
#if defined(DEBUG_DUMP)
    char b;

    switch(AVL_BALANCE(node))
    {
        case TOOLEFT:
            b = 'l';
            break;
        case LEFT:
            b = 'L';
            break;
        case MIDDLE:
            b = 'M';
            break;
        case RIGHT:
            b = 'R';
            break;
        case TOORIGHT:
            b = 'r';
            break;
        default:
            b = '?';
            break;
    }

#if AVL_HAS_PARENT_POINTER == 1
    DUMP("[%2i]%S %c@%p='" AVL_REFERENCE_FORMAT_STRING"' %c (%p,%p) <- %p", level, level, c, node, AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)), b, AVL_LEFT_CHILD(node), AVL_RIGHT_CHILD(node), AVL_PARENT(node));
#else
    DUMP("[%2i]%S %c@%p='" AVL_REFERENCE_FORMAT_STRING"' %c (%p,%p)", level, level, c, node, AVL_REFERENCE_FORMAT(AVL_REFERENCE(node)), b, AVL_LEFT_CHILD(node), AVL_RIGHT_CHILD(node));
#endif
    
    if(AVL_LEFT_CHILD(node) != NULL)
    {
        AVL_PREFIXED(dump_node)(AVL_LEFT_CHILD(node), level +1, 'l');
    }
    if(AVL_RIGHT_CHILD(node) != NULL)
    {
        AVL_PREFIXED(dump_node)(AVL_RIGHT_CHILD(node), level +1, 'r');
    }
#else
    (void)node;
    (void)level;
    (void)c;
#endif
}

void
AVL_PREFIXED(dump)(AVL_TREE_TYPE *tree)
{
    AVL_PREFIXED(dump_node)(AVL_TREE_ROOT(tree), 0, 'r');
}


/** @} */

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
 *  @brief AVL structure and functions
 *
 *  AVL structure and functions
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#define DEBUG_LEVEL 0

#include "dnsdb/dnsdb-config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <dnscore/sys_types.h>
#include <dnscore/zalloc.h>
#include "dnsdb/zdb_error.h"

#include <dnscore/format.h>

#if 0 /* fix */
#else
#define DUMP_NODE(...)
#endif

#include "dnsdb/avl.h"

#ifdef LDEBUG
#undef LDEBUG
#define LDEBUG(...)
#endif

/* This should be closer to 40 */

#define MAX_DEPTH   40 /* 64 */

/*
 * The following macros are defining relevant fields in the node
 */

#define LEFT_CHILD(node) ((node)->children.lr.left)
#define RIGHT_CHILD(node) ((node)->children.lr.right)
#define CHILD(node,id) ((node)->children.child[(id)])

#define BALANCE(node) ((node)->balance)

/*
 * The following macros are defining relevant operations in the node
 */

/* What is used to compare the nodes */
#define REFERENCE_TYPE hashcode
#define INIT_NODE(node,reference) (node)->hash=(reference);(node)->data=NULL
#define REFERENCE(node) (node)->hash
/* Compare two references */
#define BIGGER(reference_a,reference_b) (reference_a)>(reference_b)

/* What is returned when a node is created/found */
#define DATA(node) (node)->data
#define DATAPTR(node) &(node)->data

/* Copies the payload of a node (not the balance + pointers) */
#define COPY_PAYLOAD(node_trg,node_src) (node_trg)->data = (node_src)->data; (node_trg)->hash = (node_src)->hash

/*
 *
 */

#define TOOLEFT    (-2)
#define LEFT       (-1)
#define MIDDLE      0
#define RIGHT       1
#define TOORIGHT    2

#define DIR_LEFT    0
#define DIR_RIGHT   1
#define DIR_CRASH   127

#define avl_destroy_node(node) LDEBUG(9, "avl_destroy_node(%p)\n",node);ZFREE_OBJECT(node);

/* #define DIR_TO_BALANCE(dir) (((dir)==0)?LEFT:RIGHT) */
static s8 DIR_TO_BALANCE_[2] = {LEFT, RIGHT};
#define DIR_TO_BALANCE(dir) DIR_TO_BALANCE_[(dir)]

/* #define BALANCE_TO_DIR(bal) (((bal)<MIDDLE)?DIR_LEFT:DIR_RIGHT) */
static s8 BALANCE_TO_DIR_[5] = {DIR_LEFT, DIR_LEFT, DIR_CRASH, DIR_RIGHT, DIR_RIGHT};
#define BALANCE_TO_DIR(bal) BALANCE_TO_DIR_[(bal)-TOOLEFT]

#define NODE_BALANCED(node) (BALANCE(node)==MIDDLE)

#define MUST_REBALANCE(node) ((BALANCE(node)<LEFT)||(BALANCE(node)>RIGHT))

static inline avl_node*
avl_node_single_rotation2(avl_node* node)
{
    avl_node* save;

    if(BALANCE(node) < 0) /* balance = LEFT -> dir = RIGHT other = LEFT */
    {
        save = LEFT_CHILD(node);
        LEFT_CHILD(node) = RIGHT_CHILD(save);
        RIGHT_CHILD(save) = node;
    }
    else
    {
        save = RIGHT_CHILD(node);
        RIGHT_CHILD(node) = LEFT_CHILD(save);
        LEFT_CHILD(save) = node;
    }

    BALANCE(node) = MIDDLE;
    BALANCE(save) = MIDDLE;

    return save;
}

static inline avl_node*
avl_node_double_rotation2(avl_node* node)
{
    avl_node* save;

    if(BALANCE(node) < 0) /* balance = LEFT -> dir = RIGHT other = LEFT */
    {
        save = RIGHT_CHILD(LEFT_CHILD(node));

        if(BALANCE(save) == MIDDLE)
        {

            BALANCE(LEFT_CHILD(node)) = MIDDLE;
            BALANCE(node) = MIDDLE;
        }
        else if(BALANCE(save) > 0) /* dir right & balance right */
        {
            BALANCE(LEFT_CHILD(node)) = LEFT;
            BALANCE(node) = MIDDLE;
        }
        else /* BALANCE(save)<0 */
        {
            BALANCE(LEFT_CHILD(node)) = MIDDLE;
            BALANCE(node) = RIGHT;
        }

        BALANCE(save) = MIDDLE;
        RIGHT_CHILD(LEFT_CHILD(node)) = LEFT_CHILD(save);
        LEFT_CHILD(save) = LEFT_CHILD(node);
        LEFT_CHILD(node) = RIGHT_CHILD(save);
        RIGHT_CHILD(save) = node;
    }
    else /* balance = RIGHT -> dir = LEFT other = RIGHT */
    {
        save = LEFT_CHILD(RIGHT_CHILD(node));

        if(BALANCE(save) == MIDDLE)
        {

            BALANCE(RIGHT_CHILD(node)) = MIDDLE;
            BALANCE(node) = MIDDLE;
        }
        else if(BALANCE(save) < 0) /* dir left & balance left */
        {
            BALANCE(RIGHT_CHILD(node)) = RIGHT;
            BALANCE(node) = MIDDLE;
        }
        else /* BALANCE(save)>0 */
        {
            BALANCE(RIGHT_CHILD(node)) = MIDDLE;
            BALANCE(node) = LEFT;
        }

        BALANCE(save) = MIDDLE;
        LEFT_CHILD(RIGHT_CHILD(node)) = RIGHT_CHILD(save);
        RIGHT_CHILD(save) = RIGHT_CHILD(node);
        RIGHT_CHILD(node) = LEFT_CHILD(save);
        LEFT_CHILD(save) = node;
    }

    return save;
}

static avl_node*
avl_create_node(hashcode hash)
{
    avl_node* node;

    ZALLOC_OBJECT_OR_DIE( node, avl_node, AVL_NODE_TAG);

    LEFT_CHILD(node) = NULL;
    RIGHT_CHILD(node) = NULL;
    node->data = NULL;
    node->hash = hash;
    BALANCE(node) = MIDDLE;

    return node;
}

/*
   static void avl_destroy_node(avl_node* node)
   {
   avl_destroy_node(node);
   }
 */

/** @brief Initializes the tree
 *
 *  Initializes the tree.
 *  Basically : *tree=NULL;
 *
 *  @param[in]  tree the tree to initialize
 *
 */

void
avl_init(avl_tree* tree)
{
    *tree = NULL;
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

#if !ZDB_INLINES_AVL_FIND

void*
avl_find(avl_tree* root, hashcode obj_hash)
{
#if 1 /* NOTE: If I do this in assembly code.  I could probably win a few cycles
       *       This is by far the most common call of the DB
       * NOTE: The compiler's job is very good.
       */
    avl_node* node = *root;
    hashcode h;

    /* This is one of the parts I could try to optimize
     * I've checked the assembly, and it sucks ...
     */

    /* Both the double-test while/ternary and the current one
     * are producing the same assembly code.
     */

    while(node != NULL)
    {
        if((h = node->hash) == obj_hash)
        {
            return node->data;
        }

        node = CHILD(node, (obj_hash > h)&1);
    }

    /*return (node!=NULL)?node->data:NULL;*/
    return NULL;
#else

    /*
     * I would ...
     *
     *   mov eax,node
     *   test eax,eax                       ; node==NULL ?
     *   jz exit_null                       ; YES -> JUMP
     *   mov edx,obj_hash
     * loop:
     *   cmp edx,[eax+hash_offs]            ; node->hash==obj_hash ?
     *   sbb ebx,ebx                        ; below=>ebx=~0
     *   jz exit_data                       ; EQUAL -> JUMP
     *   and ebx,4                          ; ebx=0 | 1 (left | right)
     *   mov eax,[eax+child_offs+ebx]       ; node=node->child[left|right]
     *   test eax,eax                       ; node==NULL ?
     *   jnz loop                           ; NO -> JUMP
     * exit_null:
     *   ret                                ; return NULL
     * exit_data:
     *   mov eax,[eax+data_offs]            ; return node->data
     *   ret
     */
    /* NOT DONE YET !!! */
    /* x86_64 :  RDI = root, ESI = obj_hash */
    __asm__
            (
             "movq (%rdi),%rax\n\t"
             "testq %rax,%rax\n\t"
             "jz avl_find_return_null\n\t"
             "\navl_find_loop:\n\t"
             "cmpl 16(%rax),%esi\n\t"
             "jz avl_find_return_data\n\t"
             "sbbq %rcx,%rcx\n\t"
             "andq 8,%rcx\n\t"
             "movq (%rcx,%rax),%rax\n\t"
             "testq %rax,%rax\n\t"
             "jnz avl_find_loop\n\t"
             "\navl_find_return_null:\n\t"
#if DEBUG
            "leave\n\t"
#endif
            "ret\n\t"
             "\navl_find_return_data:\n\t"
             "mov 16(%rax),%rax\n\t"
#if DEBUG
            "leave\n\t"
#endif
            "ret\n\t"
             );
#endif
}

#endif

/** @brief Find a node in the tree
 *
 *  Find a node in the tree matching a hash value.
 *  This is required for search that could lead to a change to the data.
 *
 *  @param[in]  root the tree to search in
 *  @param[in]  obj_hash the hash to find
 *
 *  @return A pointer to the node or NULL if there is no such node.
 */

#if !ZDB_INLINES_AVL_FIND

void**
avl_findp(avl_tree* root, hashcode obj_hash)
{
    avl_node* node = *root;
    hashcode h;

    while(node != NULL /* &&((h=node->hash)!=obj_hash) */)
    {
        if((h = node->hash) == obj_hash)
        {
            return &node->data;
        }

        node = CHILD(node, (obj_hash > h)&1);
    }

    /* return (node!=NULL)?&node->data:NULL; */

    return NULL;
}

#endif

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

void**
avl_insert(avl_tree* root, hashcode obj_hash)
{
    LDEBUG(9, "avl_insert(%p,%08x) ------------------------------\n", root, obj_hash);

    if(*root == NULL)
    {
        *root = avl_create_node(obj_hash);

        LDEBUG(9, "First node (root) (%p)\n", *root);

        return &(*root)->data;
    }

    avl_node * nodes[MAX_DEPTH];
    s8 balances[MAX_DEPTH];
    s8 dirs[MAX_DEPTH];

    avl_node* node = *root;
    hashcode node_hash;
    int level = 0;
    s8 dir = MIDDLE;

    while((node != NULL) && (obj_hash != (node_hash = node->hash)))
    {
        nodes[level] = node;
        balances[level] = BALANCE(node);

        /* DIR_LEFT = 0, DIR_RIGHT = 1 */
        dir = (obj_hash > node_hash)&1;
        node = CHILD(node, dir);

        dirs[level++] = dir;
    }

    LDEBUG(9, "Level = %i\n", level);

    if(node != NULL)
    {
        /* match */

        LDEBUG(9, "Got a match\n");

        return &node->data;
    }

    /* Add a new node to the last one (the parent) */

    node = nodes[--level];

    /* the parent is node */

    avl_node* ret = avl_create_node(obj_hash);
    CHILD(node, dir) = ret;

    LDEBUG(9, "Created a new node from %08x, going %i (%p)\n", node->hash, dir, ret);

    if(BALANCE(node) == MIDDLE)
    {
        /* There were no child, now there is one */
        /* not balanced anymore */
        BALANCE(node) = DIR_TO_BALANCE(dir); /* 0 or 1 => -1 or +1 */

        LDEBUG(9, "parent was balanced, now it is not anymore : %i (%i)\n", dir, BALANCE(node));
    }
    else
    {
        /* There was a child, now there is two */
        /* balance */
        BALANCE(node) = MIDDLE;

        LDEBUG(9, "parent was not balanced, now it is\n");
    }

    avl_node* parent;

    /* Now I have to update the balance up to the root (if needed ...)
     * node is m_nodes[level]
     * we need the parent at m_nodes[level-1]
     * parent -> node -> (new node/processed node)
     */

    while(level > 0) /* level points to the parent */
    {
        LDEBUG(9, "\tUpdating balance at %i\n", level);

        if(BALANCE(node) == balances[level]) /* balance of the node */
        { /* this branch will exit */
            /* The node's balance has not been changed */

            return &ret->data;
        }

        parent = nodes[level - 1];

        /* The node's balance has been changed */

        LDEBUG(9, "\t\tBalance of %08x was %i, now it is %i\n", node->hash, balances[level], BALANCE(node));

        if(BALANCE(node) == MIDDLE) /* this branch will exit */
        {
            /* BALANCE(node)==MIDDLE and we are balanced
             * balanced -> done
             */

            LDEBUG(9, "Done (E)\n");

            return &ret->data;
        }

        /* not balanced (anymore) */
        /* Now dir child it is unbalanced ... */
        /* Let's update the imbalance */

        dir = dirs[level - 1];

        LDEBUG(9, "\t\t\tIMBALANCE: dir=%i old parent balance=%i patch=%i\n", dir, BALANCE(parent), DIR_TO_BALANCE(dir));

        BALANCE(parent) += DIR_TO_BALANCE(dir);

        if(MUST_REBALANCE(parent)) /* this branch will exit */
        {
            /* parent is the "root" */
            /* node is the pivot */

            LDEBUG(9, "\t\t\t\tREBALANCING of %08x\n", parent->hash);

            BALANCE(parent) >>= 1; /* reset the balance to -1;1 ... */

            LDEBUG(9, "\t\t\t\tBalance fix -> %i\n", BALANCE(parent));

            /* HERE THE BALANCES ARE LOST/CORRUPTED !!! */

            if(BALANCE(node) == BALANCE(parent)) /* if the sign is the same ... */
            {
                /* BALANCE(node)=0; */
                node = avl_node_single_rotation2(parent);

                /* the parent's parent has to be updated (to node) */

                LDEBUG(9, "\t\t\t\tSingle rotation, new parent is %08x\n", node->hash);
            }
            else
            {
                /* BALANCE(node)=0; */
                node = avl_node_double_rotation2(parent);

                /* the parent's parent has to be updated (to node) */

                LDEBUG(9, "\t\t\t\tDouble rotation, new parent is %08x\n", node->hash);
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
                CHILD(nodes[level - 2], dirs[level - 2]) = node;
            }
            else /* root */
            {
                LDEBUG(9, "Root changing from %08x to %08x\n", (*root)->hash, node->hash);

                *root = node;
            }

            /* rebalancing -> done */

            LDEBUG(9, "Done (I)\n");

            return &ret->data;
        }

        node = parent;
        level--;
    }

    return &ret->data;
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

void*
avl_delete(avl_tree* root, hashcode obj_hash)
{
    LDEBUG(9, "avl_delete(%p,%08x) ------------------------------\n", root, obj_hash);

    if(*root == NULL)
    {
        /* Already empty */

        return NULL;
    }

    avl_node * nodes[MAX_DEPTH];
    s8 balances[MAX_DEPTH];
    s8 dirs[MAX_DEPTH];

#if DEBUG
    memset(&nodes, 0xff, sizeof(avl_node*) * MAX_DEPTH);
    memset(&balances, 0xff, MAX_DEPTH);
    memset(&dirs, 0xff, MAX_DEPTH);
#endif

    avl_node* node = *root;
    hashcode node_hash;
    int level = 0;
    s8 dir = MIDDLE;

    while((node != NULL) && (obj_hash != (node_hash = node->hash)))
    {
        nodes[level] = node;
        balances[level] = BALANCE(node);

        /* DIR_LEFT = 0, DIR_RIGHT = 1 */
        dir = (obj_hash > node_hash)&1;
        node = CHILD(node, dir);

        dirs[level++] = dir;
    }

    LDEBUG(9, "Level = %i\n", level);

    yassert(level < MAX_DEPTH);

    if(node == NULL)
    {
        /* no match : nothing to delete */

        LDEBUG(9, "No match\n");

        return NULL;
    }

    LDEBUG(9, "[%i] VICTIM IS ", level);
    DUMP_NODE(node);
    LDEBUG(9, "\n");

    nodes[level] = node;
    balances[level] = BALANCE(node);
    dirs[level++] = dir; /* THIS IS WRONG */

    /* Remove "node" from the parent */
    /* Keep the pointer for the find & destroy operation */

    void* data = node->data;

    avl_node* victim = node;
    avl_node* victim_left = LEFT_CHILD(node);
    avl_node* victim_right = RIGHT_CHILD(node);

    /** We have found the victim node.  From here 3 cases can be found
     *
     *  #1 : the victim has no child.  We just have to remove it.
     *
     *  #2 : the victim has only got one child.  We just have to remove it and
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
     *       Method '2': Fastest way:
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
         *  NOTE: It is recommended to switch left/right successors
         *	  between each delete for a better balancing.
         *
         *  NOTE: The path has to be completed.
         *
         */

        LDEBUG(9, "#3\n");

        /* Arbitraty: "<" successor */
        /****************************/

        dirs[level - 1] = DIR_LEFT;

        LDEBUG(9, "[%i] FROM ", level - 1);
        DUMP_NODE(victim);
        LDEBUG(9, ", GOING LEFT (VICTIM)\n");

        avl_node* beforesuccessor = victim; /* actually it's "victim" here */
        avl_node* successor = victim_left;
        avl_node* tmp_node;

        LDEBUG(9, "[%i] From ", level);
        DUMP_NODE(successor);
        LDEBUG(9, ", going RIGHT\n");

        nodes[level] = successor;
        balances[level] = BALANCE(successor);
        dirs[level++] = DIR_RIGHT;

        while((tmp_node = RIGHT_CHILD(successor)) != NULL)
        {
            beforesuccessor = successor;

            LDEBUG(9, "[%i] From ", level);
            DUMP_NODE(successor);
            LDEBUG(9, ", going RIGHT\n");

            successor = tmp_node;

            nodes[level] = successor;
            balances[level] = BALANCE(successor);
            dirs[level++] = DIR_RIGHT;
        }

        yassert(level < MAX_DEPTH);
        
        /* successor has at most one left child */

        LDEBUG(9, "[%i] Replacement is ", level);
        DUMP_NODE(successor);
        LDEBUG(9, "\n");

        /* Method 2 uses 3 moves, method 1 uses 10 */
        victim->data = successor->data;
        victim->hash = successor->hash;

        if(beforesuccessor != victim)
        {
            RIGHT_CHILD(beforesuccessor) = LEFT_CHILD(successor);
            BALANCE(beforesuccessor)--;
        }
        else
        {
            LEFT_CHILD(beforesuccessor) = LEFT_CHILD(successor);
            BALANCE(beforesuccessor)++;
        }


        DUMP_NODE(successor);
        LDEBUG(9, " : avl_destroy_node(%p)\n", successor);
        avl_destroy_node(successor); /* avl_destroy_node(successor); */

        level -= 2;

    } /* Case #3 done */
    else
    {
        /* Only 2 cases could occur right now : #1 and #2 */

        DUMP_NODE(victim);
        LDEBUG(9, " : avl_destroy_node(%p)\n", victim);

        avl_destroy_node(victim); /* avl_destroy_node(victim); */

        if(level > 1)
        {
            avl_node* victim_parent = nodes[level - 2];

            /* ONE or BOTH are NULL, this is the best alternative to the if/elseif/else above */

            CHILD(victim_parent, dir) = (avl_node*)((intptr)victim_left | (intptr)victim_right);

            BALANCE(victim_parent) -= DIR_TO_BALANCE(dir); /* The balance has changed */

            /* At this point the victim is detached from the tree */
            /* I can delete it */

            level -= 2;
        }
        else /* Else we have no parent, so we change the root */
        {
            /* ONE or BOTH are NULL, this is the best alternative to the if/elseif/else above */
            *root = (avl_node*)((intptr)victim_left | (intptr)victim_right);
            return data;
        }
    }

    /* Rebalance from the victim_parent */
    /* NOTE: A delete-rebalance can occur many times, up to the root. */

    node = nodes[level]; /* start at the parent of the deleted node */

    /* Now I have to update the balance up to the root (if needed ...)
     * node is m_nodes[level]
     * we need the parent at m_nodes[level-1]
     * parent -> node -> (new node/processed node)
     */

    while(level >= 0) /* level points to the parent */
    {
        LDEBUG(9, "Updating balance at %i : ", level);
        DUMP_NODE(node);
        LDEBUG(9, "\n");

        if(BALANCE(node) == balances[level]) /* balance of the node */
        { /* this branch will exit */
            /* The node's balance has not been changed */

            LDEBUG(9, "Balance is the same\n");

            return data;
        }

        /* The node's balance has been changed */

        /*
         * Balance became 0 : It was -1 or +1 : the tree's height decreased.
         * It is balanced but a propagation is required.
         *
         * Balance became -1 or +1 : It was 0 : the tree's height didn't changed.
         * It is a valid AVL and the propagation can stop.
         *
         * Balance became -2 or +2 : it was -1 or +1 : the tree is unbalanced.
         * It needs to be rebalanced and then a propagation is required.
         */

        if(BALANCE(node) == MIDDLE)
        {
            /* Height decreased, tell it to the parent */

            level--;

            if(level >= 0)
            {
                LDEBUG(9, "\tBalance [%i] changed for MIDDLE (%i) Fixing [%i] parent balance of %i (%i)\n",
                       level + 1, balances[level + 1], level, DIR_TO_BALANCE(dirs[level]), dirs[level]);

                node = nodes[level];
                BALANCE(node) -= DIR_TO_BALANCE(dirs[level]);
            }

            continue;
        }

        if(BALANCE(node) == LEFT || BALANCE(node) == RIGHT) /* this branch will exit */
        {
            LDEBUG(9, "\tBalance changed for LEFT or RIGHT (%i)\n", balances[level]);

            return data;
        }

        LDEBUG(9, "\tBalance changed for imbalance (%i)\n", balances[level]);

        /*
         * We need to rotate in order to be AVL again.
         *
         * + cases:
         *
         * R(+) P(-) => R(0) P(0) (double rotation)
         * R(+) P(0) => R(+) P(-) (single rotation, delete special case)
         * R(+) P(+) => R(0) P(0) (single roration
         *
         * => if node&save balance are equal => MIDDLE for both
         *
         */

        BALANCE(node) >>= 1;

        avl_node* child = CHILD(node, BALANCE_TO_DIR(BALANCE(node)));
        s8 parent_balance = BALANCE(node);
        s8 child_balance = BALANCE(child);

        if(child_balance == MIDDLE) /* patched single rotation */
        {
            LDEBUG(9, "Single Rotation (delete)\n");

            avl_node* root;

            root = avl_node_single_rotation2(node);

            yassert(root == child);

            BALANCE(child) = -parent_balance;
            BALANCE(node) = parent_balance;

            node = root;
        }
        else if(parent_balance == child_balance) /* single rotation case */
        {
            LDEBUG(9, "Single Rotation\n");

            node = avl_node_single_rotation2(node);

            yassert(node == child);
        }
        else
        {
            LDEBUG(9, "Double Rotation\n");

            node = avl_node_double_rotation2(node);
        }

        if(level == 0) /* 2 or more ... */
        {
            /* root */

            LDEBUG(9, "Root changing from %08x to %08x\n", (*root)->hash, node->hash);

            *root = node;
            break;
        }

        /* link the parent to its new child */

        /*
           level--;

           CHILD(nodes[level],dirs[level])=node;

           node=nodes[level];
         */

        /* The rotations could have changed something */
        /* I'll process the same level again */

        CHILD(nodes[level - 1], dirs[level - 1]) = node;

        /* node=nodes[level]; */
    }

    LDEBUG(9, "avl_delete done (%p) level=%i\n", data, level);

    return data;
}

static void
avl_destroy_(avl_node* node)
{
    avl_node* child = LEFT_CHILD(node);
    if(child != NULL)
    {
        avl_destroy_(child);
    }
    child = RIGHT_CHILD(node);
    if(child != NULL)
    {
        avl_destroy_(child);
    }

    avl_destroy_node(node); /* avl_destroy_node(node); */
}

/** @brief Releases all the nodes of a tree
 *
 *  Releases all the nodes of a tree.  Data is not destroyed.
 *
 *  @param[in] tree the tree to empty
 */

void
avl_destroy(avl_tree* tree)
{
    if(*tree != NULL)
    {
        avl_destroy_(*tree);
        *tree = NULL;
    }
}

/* Iterators -> */

void
avl_iterator_init(avl_tree tree, avl_iterator* iter)
{
    /* Do we have a tree to iterate ? */

    iter->stack_pointer = -1;

    if(tree != NULL)
    {
        /* Let's stack the whole left path */

        register avl_node* node = tree;

        while(node != NULL)
        {
            iter->stack[++iter->stack_pointer] = node;
            node = LEFT_CHILD(node);
        }
    }
}

avl_node*
avl_iterator_init_from_after(avl_tree tree, avl_iterator *iter, hashcode obj_hash)
{
    /* Do we have a tree to iterate ? */

    iter->stack_pointer = -1;

    if(tree != NULL)
    {
        /* Let's stack the path left path */

        register avl_node* node = tree;

        while(node != NULL)
        {
            register hashcode h = node->hash;
            
            if(obj_hash < h)
            {                
                iter->stack[++iter->stack_pointer] = node;
                node = LEFT_CHILD(node);
            }
            else if(obj_hash > h)
            {
                node = RIGHT_CHILD(node);
            }
            else
            {
                if(RIGHT_CHILD(node) != NULL)
                {
                    // one right, full left
                    register avl_node* next_node = RIGHT_CHILD(node);
                    
                    do
                    {
                        iter->stack[++iter->stack_pointer] = next_node;
                        next_node = LEFT_CHILD(next_node);
                    }
                    while(next_node != NULL);
                    
                    return node;
                }
                
                return node;
            }
        }
    }
    
    return NULL;
}

#if !ZDB_INLINES_AVL_FIND
bool
avl_iterator_hasnext(avl_iterator* iter)
{
    return iter->stack_pointer >= 0;
}
#endif

void**
avl_iterator_next(avl_iterator* iter)
{
    yassert(iter->stack_pointer >= 0);
    
    register avl_node* node = iter->stack[iter->stack_pointer];
    void** datapp = &node->data;

    /* we got the data, now let's ready the next node */

    register avl_node* tmp;

    /* let's branch right if possible */

    if((tmp = RIGHT_CHILD(node)) != NULL)
    {
        iter->stack[iter->stack_pointer] = tmp; /* replace TOP */
        node = tmp;
        
        while((tmp = LEFT_CHILD(node)) != NULL)
        {
            iter->stack[++iter->stack_pointer] = tmp; /* PUSH @note edf 20180102 -- overflow is unlikely: the depth of the stack allows iteration on collections of tens of billions of items*/
            node = tmp;
        }

        return datapp;
    }
    
#if DEBUG
    iter->stack[iter->stack_pointer] = (avl_node*)(intptr)0xfefefefefefefefeLL;
#endif

    iter->stack_pointer--;

    return datapp;
}

avl_node*
avl_iterator_next_node(avl_iterator* iter)
{
    yassert(iter->stack_pointer >= 0);
    
    avl_node* node = iter->stack[iter->stack_pointer];
    avl_node* current = node;

    /* we got the data, now let's ready the next node */

    register avl_node* tmp;

    /* let's branch right if possible */

    if((tmp = RIGHT_CHILD(node)) != NULL)
    {
        iter->stack[iter->stack_pointer] = tmp; /* replace TOP */

        node = tmp;
        while((tmp = LEFT_CHILD(node)) != NULL)
        {
            iter->stack[++iter->stack_pointer] = tmp; /* PUSH @note edf 20180102 -- overflow is unlikely: the depth of the stack allows iteration on collections of tens of billions of items */
            node = tmp;
        }

        return current;
    }
    
#if DEBUG
    iter->stack[iter->stack_pointer] = (avl_node*)(intptr)0xfefefefefefefefeLL;
#endif

    iter->stack_pointer--;

    return current;
}

/* <- Iterators */

static void
avl_callback_and_destroy_(avl_node* node, void (*callback)(void*))
{
    avl_node* child = LEFT_CHILD(node);
    if(child != NULL)
    {
        avl_callback_and_destroy_(child, callback);
    }
    child = RIGHT_CHILD(node);
    if(child != NULL)
    {
        avl_callback_and_destroy_(child, callback);
    }

    callback(node->data);

    avl_destroy_node(node); /* avl_destroy_node(node); */
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
avl_callback_and_destroy(avl_tree tree, void (*callback)(void*))
{
    if(tree != NULL)
    {
        avl_callback_and_destroy_(tree, callback);
    }
}

#if DEBUG

/** @brief DEBUG: check that a tree fits the AVL definition.
 *
 *  DEBUG: check that a tree fits the AVL definition.
 *
 *  @param[in] tree the tree to check
 *
 *  @return A positive integer if the AVL is right (the depth actually) else
 *          a negative integer.
 *
 */

ya_result
avl_check(avl_tree tree)
{
    int err = avl_checkdepth(tree);
    if(err < 0)
    {
        DIE(ERROR);
    }
    return err;
}

/** @brief DEBUG: check that a node fits the AVL definition.
 *
 *  DEBUG: check that a node fits the AVL definition.
 *
 *  @param[in] node the node to check
 *
 *  @return A positive integer if the AVL is right (the depth actually) else
 *          a negative integer.
 *
 */

s32
avl_checkdepth(avl_node* node)
{
    if(node == NULL)
    {
        return 0;
    }

    int left_d = avl_checkdepth(LEFT_CHILD(node));

    if(left_d < 0)
    {
        format("Child L of %08x\n", node->hash);
        return -1;
    }

    int right_d = avl_checkdepth(RIGHT_CHILD(node));

    if(right_d < 0)
    {
        format("Child R of %08x\n", node->hash);

        return -1;
    }

    int max;
    int min;

    if(left_d > right_d)
    {
        max = left_d;
        min = right_d;
    }
    else
    {
        max = right_d;
        min = left_d;
    }

    if(max - min > 1)
    {
        format("AVL %08x is not balanced !!! %i %i\n", node->hash, left_d, right_d);

        return -1;
    }

    switch(BALANCE(node))
    {
        case MIDDLE:
            if(left_d != right_d)
            {
                format("AVL %08x balance is broken (MIDDLE) %i %i\n", node->hash, left_d, right_d);
                return -1;
            }
            break;
        case LEFT:
            if(left_d <= right_d)
            {
                format("AVL %08x balance is broken (LEFT) %i %i\n", node->hash, left_d, right_d);
                return -1;
            }
            break;
        case RIGHT:
            if(left_d >= right_d)
            {
                format("AVL %08x balance is broken (RIGHT) %i %i\n", node->hash, left_d, right_d);
                return -1;
            }
            break;
        default:
            format("AVL balance is broken (%i) %i %i\n", BALANCE(node), left_d, right_d);
            return -1;
    }

    return max + 1;
}

static void
avl_print_(avl_node* node)
{
    if(LEFT_CHILD(node) != NULL)
    {
        avl_print_(LEFT_CHILD(node));
    }

    format("[%08x]", node->hash);

    if(RIGHT_CHILD(node) != NULL)
    {
        avl_print_(RIGHT_CHILD(node));
    }
}

/** @brief DEBUG: Prints the (sorted) content of the AVL
 *
 *  DEBUG: Prints the (sorted) content of the AVL
 *
 *  @param[in] tree the tree to print
 *
 */

void
avl_print(avl_tree tree)
{
    if(tree != NULL)
    {
        avl_print_(tree);
    }
    else
    {
        format("(empty)");
    }
}

/** @brief DEBUG: Prints the content of the AVL node
 *
 *  DEBUG: Prints the (sorted) content of the AVL node
 *
 *  @param[in] node the node to print
 *
 */

#define HASH(x) (((x)!=NULL)?(x)->hash:0)

/*#define MAX(x,y) (((x)>(y))?(x):(y))*/

int
avl_getnodedepth(avl_node* node)
{
    if(node == NULL)
    {
        return 0;
    }
    return MAX(avl_getnodedepth(LEFT_CHILD(node)), avl_getnodedepth(RIGHT_CHILD(node))) + 1;
}

void
avl_printnode(avl_node* node)
{
    if(node != NULL)
    {
        format("%08x@{%08x,%08x,%3i}", node->hash, HASH(LEFT_CHILD(node)), HASH(RIGHT_CHILD(node)), BALANCE(node));
    }
    else
    {
        format("(empty)");
    }
}

#endif

/** @} */

/*----------------------------------------------------------------------------*/

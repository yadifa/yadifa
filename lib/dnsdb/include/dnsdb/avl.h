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
#ifndef _AVL_H
#define	_AVL_H

#include <dnsdb/zdb_config.h>
#include <dnscore/hash.h>

#ifndef ZDB_INLINES_AVL_FIND
#error "ZDB_INLINES_AVL_FIND not defined"
#endif

#ifdef	__cplusplus
extern "C"
{
#endif

#define AVL_NODE_TAG 0x0045444F4E4c5641 /* "AVLNODE" */

/*
 * In the worst case, AVL is Fibonacci-balanced.
 */
/* Python script to compute fibo nodes for each depth:
import sys
import math

def fibonacci(n):
  a,b,c = 1,1,0
  for i in range(0,n):
    c   = c+a
    print "F#",i," Value=",a," Items=",c, " Log2=",math.log(c,2);
    a,b = b,a+b

if __name__ == "__main__":
    fibonacci(64);
 */
/*

 And here are the first values:

F# 0  Value= 1  Items= 1  Log2= 0.0
F# 1  Value= 1  Items= 2  Log2= 1.0
F# 2  Value= 2  Items= 4  Log2= 2.0
F# 3  Value= 3  Items= 7  Log2= 2.80735492206
F# 4  Value= 5  Items= 12  Log2= 3.58496250072
F# 5  Value= 8  Items= 20  Log2= 4.32192809489
F# 6  Value= 13  Items= 33  Log2= 5.04439411936
F# 7  Value= 21  Items= 54  Log2= 5.75488750216
F# 8  Value= 34  Items= 88  Log2= 6.45943161864
F# 9  Value= 55  Items= 143  Log2= 7.15987133678
F# 10  Value= 89  Items= 232  Log2= 7.85798099513
F# 11  Value= 144  Items= 376  Log2= 8.55458885168
F# 12  Value= 233  Items= 609  Log2= 9.25029841791
F# 13  Value= 377  Items= 986  Log2= 9.94544383638
F# 14  Value= 610  Items= 1596  Log2= 10.6402449362
F# 15  Value= 987  Items= 2583  Log2= 11.3348319281
F# 16  Value= 1597  Items= 4180  Log2= 12.029287227
F# 17  Value= 2584  Items= 6764  Log2= 12.7236609444
F# 18  Value= 4181  Items= 10945  Log2= 13.4179843341
F# 19  Value= 6765  Items= 17710  Log2= 14.1122765916
F# 20  Value= 10946  Items= 28656  Log2= 14.806549622
F# 21  Value= 17711  Items= 46367  Log2= 15.5008107652
F# 22  Value= 28657  Items= 75024  Log2= 16.1950645637
F# 23  Value= 46368  Items= 121392  Log2= 16.8893138224
F# 24  Value= 75025  Items= 196417  Log2= 17.5835602755
F# 25  Value= 121393  Items= 317810  Log2= 18.2778049947
F# 26  Value= 196418  Items= 514228  Log2= 18.9720486423
F# 27  Value= 317811  Items= 832039  Log2= 19.6662916275
F# 28  Value= 514229  Items= 1346268  Log2= 20.3605342035
F# 29  Value= 832040  Items= 2178308  Log2= 21.0547765264
F# 30  Value= 1346269  Items= 3524577  Log2= 21.749018693
F# 31  Value= 2178309  Items= 5702886  Log2= 22.443260763
F# 32  Value= 3524578  Items= 9227464  Log2= 23.1375027733
F# 33  Value= 5702887  Items= 14930351  Log2= 23.8317447466
F# 34  Value= 9227465  Items= 24157816  Log2= 24.5259866972
F# 35  Value= 14930352  Items= 39088168  Log2= 25.2202286336
F# 36  Value= 24157817  Items= 63245985  Log2= 25.9144705613
F# 37  Value= 39088169  Items= 102334154  Log2= 26.6087124837
F# 38  Value= 63245986  Items= 165580140  Log2= 27.3029544027
F# 39  Value= 102334155  Items= 267914295  Log2= 27.9971963197
F# 40  Value= 165580141  Items= 433494436  Log2= 28.6914382353
F# 41  Value= 267914296  Items= 701408732  Log2= 29.3856801502
F# 42  Value= 433494437  Items= 1134903169  Log2= 30.0799220647
F# 43  Value= 701408733  Items= 1836311902  Log2= 30.7741639788
F# 44  Value= 1134903170  Items= 2971215072  Log2= 31.4684058927
F# 45  Value= 1836311903  Items= 4807526975  Log2= 32.1626478065
F# 46  Value= 2971215073  Items= 7778742048  Log2= 32.8568897203
F# 47  Value= 4807526976  Items= 12586269024  Log2= 33.551131634
F# 48  Value= 7778742049  Items= 20365011073  Log2= 34.2453735476
F# 49  Value= 12586269025  Items= 32951280098  Log2= 34.9396154613
F# 50  Value= 20365011074  Items= 53316291172  Log2= 35.633857375
F# 51  Value= 32951280099  Items= 86267571271  Log2= 36.3280992886
F# 52  Value= 53316291173  Items= 139583862444  Log2= 37.0223412022
F# 53  Value= 86267571272  Items= 225851433716  Log2= 37.7165831159
F# 54  Value= 139583862445  Items= 365435296161  Log2= 38.4108250295
F# 55  Value= 225851433717  Items= 591286729878  Log2= 39.1050669431
F# 56  Value= 365435296162  Items= 956722026040  Log2= 39.7993088568
F# 57  Value= 591286729879  Items= 1548008755919  Log2= 40.4935507704
F# 58  Value= 956722026041  Items= 2504730781960  Log2= 41.187792684
F# 59  Value= 1548008755920  Items= 4052739537880  Log2= 41.8820345977
F# 60  Value= 2504730781961  Items= 6557470319841  Log2= 42.5762765113
F# 61  Value= 4052739537881  Items= 10610209857722  Log2= 43.2705184249
F# 62  Value= 6557470319842  Items= 17167680177564  Log2= 43.9647603385
F# 63  Value= 10610209857723  Items= 27777890035287  Log2= 44.6590022522
*/

#define AVL_MAX_DEPTH 52 // 139*10^9 items max (worst case)*/

struct avl_leftrightchildren
{
    struct avl_node_* left;
    struct avl_node_* right;
};

struct avl_node_
{

    union
    {
	struct avl_node_ * child[2]; /* 2 ptr    */
	struct avl_leftrightchildren lr;
    } children;

    void* data; /* 1 ptr    */
    hashcode hash; /* hashcode of the data (32 bits) */

    s8 balance; /* used for balance check */
    // 3 unused bytes
}; /* 17 29 => 24 32 */

typedef struct avl_node_ avl_node;

typedef avl_node* avl_tree;

typedef struct
{
    s32 stack_pointer;
    avl_node *stack[AVL_MAX_DEPTH]; /* An AVL depth of 64 is HUGE */
} avl_iterator;

#undef AVL_MAX_DEPTH

/** @brief Initializes the tree
 *
 *  Initializes the tree.
 *  Basically : *tree=NULL;
 *
 *  @param[in]  tree the tree to initialize
 *
 */

void avl_init(avl_tree* tree);

/** @brief Find a node in the tree
 *
 *  Find a node in the tree matching a hash value.
 *
 *  @param[in]  tree the tree to search in
 *  @param[in]  obj_hash the hash to find
 *
 *  @return A pointer to the node or NULL if there is no such node.
 */
#if !ZDB_INLINES_AVL_FIND
void* avl_find(avl_tree* tree, hashcode obj_hash);
#else

#define CHILD(node,id) ((node)->children.child[(id)])

static inline void*
avl_find(const avl_tree* root, hashcode obj_hash)
{
    assert(root != NULL);

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
}
#endif

/** @brief Find a node in the tree
 *
 *  Find a node in the tree matching a hash value.
 *  This is required for search that could lead to a change to the data.
 *
 *  @param[in]  tree the tree to search in
 *  @param[in]  obj_hash the hash to find
 *
 *  @return A pointer to a pointer to the node or NULL if there is no such node.
 */

#if !ZDB_INLINES_AVL_FIND
void** avl_findp(avl_tree* tree, hashcode obj_hash);
#else
static inline void**
avl_findp(const avl_tree* root, hashcode obj_hash)
{
    assert(root != NULL);

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

#undef CHILD

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
 *  @param[in]  tree the tree where the insertion should be made
 *  @param[in]  obj_hash the hash associated to the data
 *
 *  @return The node associated to the hash
 */

void** avl_insert(avl_tree* tree, hashcode obj_hash);

/** @brief Deletes a node from the tree.
 *
 *  Deletes a node from the tree.
 *
 *  @param[in]  tree the tree from which the delete will be made
 *  @param[in]  obj_hash the hash associated to the node to remove
 *
 *  @return The node associated to the hash, NULL if it did not exist.
 */

void* avl_delete(avl_tree* tree, hashcode obj_hash);

/** @brief Releases all the nodes of a tree
 *
 *  Releases all the nodes of a tree.  Data is not destroyed.
 *
 *  @param[in] tree the tree to empty
 */

void avl_destroy(avl_tree* tree);

void avl_iterator_init(avl_tree tree, avl_iterator* iter);

/**
 * Initialises an iterator from right after a given key.
 * Returns the node, or NULL if the node does not exist.
 * The next call to avl_iterator_next* will return the next node (provided the first one exists)
 * 
 * @param tree the avl_tree collection
 * @param iter an iterator that will be initialised to the node following the returned one (if not NULL)
 * @param obj_hash the key of the node to look for
 * @return the sought node
 */

avl_node* avl_iterator_init_from_after(avl_tree tree, avl_iterator *iter, hashcode obj_hash);

#if !ZDB_INLINES_AVL_FIND
bool avl_iterator_hasnext(avl_iterator* iter);
#else
static inline bool
avl_iterator_hasnext(avl_iterator* iter)
{
    return iter->stack_pointer >= 0;
}
#endif

void** avl_iterator_next(avl_iterator* iter);
avl_node* avl_iterator_next_node(avl_iterator* iter);

/** @brief Releases all the nodes of a tree
 *
 *  Releases all the nodes of a tree.
 *  Calls a function passed in parameter before destroying the data.
 *  It's the responsibility of the callback to process (destroy) the data
 *  in the tree.
 *
 *  @param[in] tree the tree to empty
 */

void avl_callback_and_destroy(avl_tree tree, void (*callback)(void*));

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

ya_result avl_check(avl_tree tree);

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

s32 avl_checkdepth(avl_node* node);

/** @brief DEBUG: Prints the (sorted) content of the AVL
 *
 *  DEBUG: Prints the (sorted) content of the AVL
 *
 *  @param[in] tree the tree to print
 *
 */

void avl_print(avl_tree tree);


/** @brief DEBUG: Prints the content of the AVL node
 *
 *  DEBUG: Prints the (sorted) content of the AVL node
 *
 *  @param[in] node the node to print
 *
 */

void avl_printnode(avl_node* node);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _AVL_H */

/** @} */

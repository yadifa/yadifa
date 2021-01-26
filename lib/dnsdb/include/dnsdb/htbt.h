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
 *  @brief Hash-Table of Balanced trees structure and functions.
 *
 *  Implementation of the Hash-Table of Balanced trees structure and functions.
 *  An hashtable holding htbt collections.
 *
 *  The idea behind this structure is that, although balanced trees are FAST,
 *  the deeper, the slower they are.
 *
 *  Another important thing is that btrees are accessed by a hash and thus, can collide.
 *
 *  This structure is thus used for the top-level balanced tree in order to
 *
 *  _ divide the top-level domains into smaller, faster trees.
 *  _ reduce the number of potential collisions in said trees.
 *
 * @{
 */
#ifndef _HHTBT_H
#define	_HHTBT_H
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <dnscore/hash.h>
#include <dnsdb/htable.h>
#include <dnsdb/btree.h>

#ifdef	__cplusplus
extern "C"
{
#endif

    /**
     * This macro is the transformation on the hash to distribute the collided hashes
     * on different btree.
     * 
     * To work as intended (potentially split collisions) it has to be generated with
     * another formula than the one used for the BT.
     * 
     * The idea is:
     * 
     * H(x)  = H(y) => collision
     * h(x) != h(y) => no collision anymore
     * 
     * h(x) must not be a function of H(x)
     *
     *
     */

#define HTBT_HASH_TRANSFORM(x) (x)

typedef htable_entry* htbt;

typedef btree_node htbt_node;

/** @brief Initializes the collection
 *
 *  Initializes the collection.
 *  Basically : *collection=NULL;
 *
 *  @param[in]  collection the collection to initialize
 *
 */

htbt htbt_create();
void htbt_init(htbt* collection);

#if !ZDB_INLINES_HTBT_FIND

/** @brief Finds a node in the collection.
 *
 *  Finds a node in the collection.
 *
 *  THIS CALL IS NOT THREAD SAFE.
 *
 *  @param[in]  collection the collection to search in
 *  @param[in]  obj_hash the hash to find
 *
 *  @return A pointer to the node or NULL if there is no such node.
 */

void* htbt_find(htbt collection, hashcode obj_hash);

/** @brief Finds a node in the collection.
 *
 *  Finds a node in the collection.
 *
 *  THIS CALL IS NOT THREAD SAFE.
 *
 *  @param[in]  collection the collection to search in
 *  @param[in]  obj_hash the hash to find
 *
 *  @return A pointer to a pointer to the node or NULL if there is no such node.
 */

void** htbt_findp(htbt collection, hashcode obj_hash);

/** @brief Inserts data into the collection.
 *
 *  Insert datat into the collection.
 *  The caller will then have to use the returned void** to set his data.
 *
 *  THIS CALL IS NOT THREAD SAFE
 *
 *  @param[in]  collection the collection where the insertion should be made
 *  @param[in]  obj_hash the hash associated to the node
 *
 *  @return A pointer to the data field associated to the hash, or NULL (out of memory)
 */

void** htbt_insert(htbt collection, hashcode obj_hash);

/** @brief Deletes a node from the collection.
 *
 *  Deletes a node from the collection.
 *
 *  THIS CALL IS NOT THREAD SAFE
 *
 *  @param[in]  collection the collection from which the delete will be made
 *  @param[in]  obj_hash the hash associated to the node to remove
 *
 *  @return The node associated to the hash
 */

void* htbt_delete(htbt collection, hashcode obj_hash);

#endif

/** @brief Destroys the collection.
 *
 *  Destroys the collection.
 *  No other thread should access it, obiviously.
 *
 *  @param[in] collection the collection to destroy
 */

void htbt_destroy(htbt* collection);

typedef struct htbt_iterator
{
    htbt table;
    s32 count;
    btree_iterator iter;
} htbt_iterator;

void htbt_iterator_init(htbt tree, htbt_iterator* iter);
//void htbt_iterator_init_from(htbt collection, htbt_iterator* iter, hashcode obj_hash);
btree_node *htbt_iterator_init_from(htbt collection, htbt_iterator* iter, hashcode obj_hash);
//avl_node *htbt_iterator_init_from(htbt collection, htbt_iterator* iter, const u8 *label);

#if !ZDB_INLINES_HTBT_FIND
bool htbt_iterator_hasnext(htbt_iterator* iter);
#endif

void** htbt_iterator_next(htbt_iterator* iter);
htbt_node* htbt_iterator_next_node(htbt_iterator* iter);

#if ZDB_INLINES_HTBT_FIND

/** @brief Finds a node in the collection.
 *
 *  Finds a node in the collection.
 *
 *  THIS CALL IS NOT THREAD SAFE.
 *
 *  @param[in]  collection the collection to search in
 *  @param[in]  obj_hash the hash to find
 *
 *  @return A pointer to the node or NULL if there is no such node.
 */

static inline void* htbt_find(htbt collection, hashcode obj_hash)
{
    /* compute the table hash from the object hash */
    hashcode table_hash = HTBT_HASH_TRANSFORM(obj_hash);

    /* grab the entry for the given hash */
    htable_entry* entry = &htable_get(collection, table_hash);

    /* search the tree of the entry */

    return btree_find((btree*) & entry->data, obj_hash);
}

/** @brief Finds a node in the collection.
 *
 *  Finds a node in the collection.
 *
 *  THIS CALL IS NOT THREAD SAFE.
 *
 *  @param[in]  collection the collection to search in
 *  @param[in]  obj_hash the hash to find
 *
 *  @return A pointer to a pointer to the node or NULL if there is no such node.
 */

static inline void** htbt_findp(htbt collection, hashcode obj_hash)
{
    /* compute the table hash from the object hash */
    hashcode table_hash = HTBT_HASH_TRANSFORM(obj_hash);

    /* grab the entry for the given hash */
    htable_entry* entry = &htable_get(collection, table_hash);

    /* search the tree of the entry */

    return btree_findp((btree*) & entry->data, obj_hash);
}

/** @brief Inserts data into the collection.
 *
 *  Insert datat into the collection.
 *  The caller will then have to use the returned void** to set his data.
 *
 *  THIS CALL IS NOT THREAD SAFE
 *
 *  @param[in]  collection the collection where the insertion should be made
 *  @param[in]  obj_hash the hash associated to the node
 *
 *  @return A pointer to the data field associated to the hash, or NULL (out of memory)
 */

static inline void** htbt_insert(htbt collection, hashcode obj_hash)
{
    /* compute the table hash from the object hash */
    hashcode table_hash = HTBT_HASH_TRANSFORM(obj_hash);

    /* grab the entry for the given hash */
    htable_entry* entry = &htable_get(collection, table_hash);

    /* search the tree of the entry */

    void** pdata = btree_insert((btree*) & entry->data, obj_hash);

    return pdata;
}

/** @brief Deletes a node from the collection.
 *
 *  Deletes a node from the collection.
 *
 *  THIS CALL IS NOT THREAD SAFE
 *
 *  @param[in]  collection the collection from which the delete will be made
 *  @param[in]  obj_hash the hash associated to the node to remove
 *
 *  @return The node associated to the hash
 */

static inline void* htbt_delete(htbt collection, hashcode obj_hash)
{
    /* compute the table hash from the object hash */
    hashcode table_hash = HTBT_HASH_TRANSFORM(obj_hash);

    /* grab the entry for the given hash */
    htable_entry* entry = &htable_get(collection, table_hash);

    /* search the tree of the entry */

    void** pdata = btree_delete((btree*) & entry->data, obj_hash);

    return pdata;
}

static inline bool htbt_iterator_hasnext(htbt_iterator* iter)
{
    if(btree_iterator_hasnext(&iter->iter))
    {
        return TRUE;
    }
    else
    {
        if(iter->count > 0)
        {
            for(; (iter->count > 0) && (iter->table->data == NULL); iter->count--, iter->table++);

            if(iter->count > 0)
            {
                btree_iterator_init((btree)iter->table->data, &iter->iter);

                iter->table++;
                iter->count--;
                
                return TRUE;
            }
        }
        
        return FALSE;
    }
}

#endif


#ifdef	__cplusplus
}
#endif

#endif	/* _Hhtbt_H */

/** @} */

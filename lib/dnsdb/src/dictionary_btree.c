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
 *  @brief Dictionary module based on a btree
 *
 *  Dictionary module based on a btree
 *
 * @{
 */
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/sys_types.h>
#include "dnsdb/zdb_error.h"
#include "dnsdb/dictionary.h"
#include "dnsdb/dictionary-node.h"

/*
 *
 */

void dictionary_btree_init(dictionary* dico);
void dictionary_btree_destroy(dictionary* dico, dictionary_destroy_record_function destroy);
void dictionary_btree_destroy_ex(dictionary* dico, dictionary_destroy_ex_record_function destroyex, void* arg);
dictionary_node* dictionary_btree_add(dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare, dictionary_data_record_create_function create);
dictionary_node* dictionary_btree_find(const dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare);
dictionary_node** dictionary_btree_findp(const dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare);
dictionary_node* dictionary_btree_remove(dictionary* dico, hashcode key, void* record_match_data, dictionary_data_record_compare_function compare);
ya_result dictionary_btree_process(dictionary* dico, hashcode key, void* record_match_data, dictionary_process_record_function compare);
void dictionary_btree_iterator_init(const dictionary* dico, dictionary_iterator* iter);
bool dictionary_btree_iterator_hasnext(dictionary_iterator* dico);
void** dictionary_btree_iterator_next(dictionary_iterator* dico);
void dictionary_btree_iterator_init_from(const dictionary* dico, dictionary_iterator* iter, const u8 *name);

void dictionary_btree_empties(dictionary* dico, void* bucket, dictionary_bucket_record_function destroy);
void
dictionary_btree_fills(dictionary* dico, hashcode key, dictionary_node* node);


static const struct dictionary_vtbl dictionary_btree_vtbl = {
    dictionary_btree_destroy,
    dictionary_btree_add,
    dictionary_btree_find,
    dictionary_btree_findp,
    dictionary_btree_remove,
    dictionary_btree_process,
    dictionary_btree_destroy_ex,
    dictionary_btree_iterator_init,
    dictionary_btree_iterator_init_from,
    dictionary_btree_empties,
    dictionary_btree_fills,
    "BTREE"
};

static const struct dictionary_iterator_vtbl dictionary_iterator_btree_vtbl = {
    dictionary_btree_iterator_hasnext,
    dictionary_btree_iterator_next
};

void
dictionary_btree_init(dictionary* dico)
{
    btree_init(&dico->ct.btree_collection);
    dico->vtbl = &dictionary_btree_vtbl;
    dico->count = 0;
    dico->threshold = MAX_U32;
}

void
dictionary_btree_destroy(dictionary* dico, dictionary_destroy_record_function destroy)
{
    yassert(dico != NULL);

    if(dico->ct.btree_collection != NULL)
    {
        btree_iterator iter;

        btree_iterator_init(dico->ct.btree_collection, &iter);

        while(btree_iterator_hasnext(&iter))
        {
            dictionary_node** node_sll_p = (dictionary_node**)btree_iterator_next(&iter);
            dictionary_node* node = *node_sll_p;
            *node_sll_p = NULL;

            while(node != NULL)
            {
                dictionary_node* tmp = node;
                node = node->next;
                tmp->next = NULL;

                destroy(tmp); /* free, if any, is made here */
            }
        }

        btree_destroy(&dico->ct.btree_collection);
        dico->count = 0;
    }
}

void
dictionary_btree_destroy_ex(dictionary* dico, dictionary_destroy_ex_record_function destroyex, void* arg)
{
    yassert(dico != NULL);

    if(dico->ct.btree_collection != NULL)
    {
        btree_iterator iter;

        btree_iterator_init(dico->ct.btree_collection, &iter);

        while(btree_iterator_hasnext(&iter))
        {
            dictionary_node** node_sll_p = (dictionary_node**)btree_iterator_next(&iter);
            dictionary_node* node = *node_sll_p;
            *node_sll_p = NULL;

            while(node != NULL)
            {
                dictionary_node* tmp = node;
                node = node->next;
                tmp->next = NULL;

                destroyex(tmp, arg); /* free, if any, is made here */
            }
        }

        btree_destroy(&dico->ct.btree_collection);
        dico->count = 0;
    }
}

dictionary_node*
dictionary_btree_add(dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare,
                     dictionary_data_record_create_function create)
{
    dictionary_node** node_sll_p = (dictionary_node**)btree_insert(&dico->ct.btree_collection, key);
    dictionary_node* node = *node_sll_p;

    while(node != NULL)
    {
        if(compare(record_match_data, node))
        {
            return node;
        }

        node = node->next;
    }

    node = create(record_match_data);
    node->next = (*node_sll_p);
    (*node_sll_p) = node;

    dico->count++;

    if(dictionary_should_mutate(dico))
    {
        dictionary_mutate(dico);
    }

    return node;
}

dictionary_node*
dictionary_btree_find(const dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare)
{
    dictionary_node* node = (dictionary_node*)btree_find(&dico->ct.btree_collection, key);

    while(node != NULL)
    {
        if(compare(record_match_data, node))
        {
            return node;
        }

        node = node->next;
    }

    return NULL;
}

dictionary_node**
dictionary_btree_findp(const dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare)
{
    dictionary_node** node_sll_p = (dictionary_node**)btree_findp(&dico->ct.btree_collection, key);

    if(node_sll_p != NULL)
    {
        while(*node_sll_p != NULL)
        {
            if(compare(record_match_data, *node_sll_p))
            {
                return node_sll_p;
            }

            node_sll_p = &(*node_sll_p)->next;
        }
    }

    return NULL;
}

dictionary_node*
dictionary_btree_remove(dictionary* dico, hashcode key, void* record_match_data, dictionary_data_record_compare_function compare)
{
    dictionary_node** node_sll_p = (dictionary_node**)btree_findp(&dico->ct.btree_collection, key);
    dictionary_node* node = *node_sll_p;

    while(node != NULL)
    {
        if(compare(record_match_data, node))
        {
            /* remove sll node
             *
             * I could have to remove the tree node too
             */

            dico->count--;

            /* detach */
            if(node->next == NULL)
            {
                /* remove tree node for the (now empty) sll */
                btree_delete(&dico->ct.btree_collection, key);
            }
            else
            {
                *node_sll_p = node->next;
                node->next = NULL;
            }

            return node;
        }

        node_sll_p = &(node->next);
        node = node->next;
    }

    return NULL;
}

ya_result
dictionary_btree_process(dictionary* dico, hashcode key, void* record_match_data, dictionary_process_record_function process)
{
    dictionary_node** node_sll_p = (dictionary_node**)btree_findp(&dico->ct.btree_collection, key);

    if(node_sll_p == NULL)
    {
        return ZDB_ERROR_KEY_NOTFOUND; /* NOT FOUND */
    }

    const dictionary_node** node_sll_head_p = (const dictionary_node**)node_sll_p;

    dictionary_node* node = *node_sll_p;

    while(node != NULL)
    {
        dictionary_node* node_next = node->next;
        int op = process(record_match_data, node);

        switch(op)
        {
            case COLLECTION_PROCESS_NEXT:
            {
                node_sll_p = &(node->next);

                node = node_next;
                continue;
            }

            case COLLECTION_PROCESS_DELETENODE:
            {
                /* remove sll node
                 *
                 * I could have to remove the tree node too
                 */

                dico->count--;

                *node_sll_p = node_next;

                /* detach */
                if(*node_sll_head_p == NULL)
                {
                    /* remove tree node for the (now empty) sll */
                    btree_delete(&dico->ct.btree_collection, key);
                }

                /* fall trough ... return op */
            }
            FALLTHROUGH //fallthrough

            default:
            {
                return op;
            }
        }
    }

    return COLLECTION_PROCESS_NEXT;
}

void
dictionary_btree_iterator_init(const dictionary *dico, dictionary_iterator *iter)
{
    iter->vtbl = &dictionary_iterator_btree_vtbl;
    iter->sll = NULL;
    btree_iterator_init(dico->ct.btree_collection, &iter->ct.as_btree);
}

void
dictionary_btree_iterator_init_from(const dictionary *dico, dictionary_iterator *iter, const u8 *name)
{
    iter->vtbl = &dictionary_iterator_btree_vtbl;
    iter->sll = NULL;
    
    hashcode key = hash_dnslabel(name);
    btree_node *node = btree_iterator_init_from(dico->ct.btree_collection, &iter->ct.as_btree, key);
    
    zdb_rr_label *label = (zdb_rr_label*)node->data;
    
    while(label != NULL)
    {
        if(dnslabel_equals(label->name, name))
        {
            iter->sll = (dictionary_node*)label;
            break;
        }

        label = label->next;
    }
}

bool
dictionary_btree_iterator_hasnext(dictionary_iterator *iter)
{
    /* If the Single Linked List is empty, fallback on the balanced tree,
     * else there is something next ...
     */
    return (iter->sll != NULL && iter->sll->next != NULL) ?
            TRUE
            :
            btree_iterator_hasnext(&iter->ct.as_btree)
            ;
}

void**
dictionary_btree_iterator_next(dictionary_iterator *iter)
{
    void* vpp;

    if(iter->sll != NULL && iter->sll->next != NULL)
    {
        /* pointer is into a sll node */

        vpp = &iter->sll->next;

        iter->sll = iter->sll->next;
        return vpp;
    }

    /* pointer is into a tree node */
    vpp = btree_iterator_next(&iter->ct.as_btree);
    iter->sll = ((dictionary_node*)vpp)->next;
    return vpp;
}

void
dictionary_btree_empties(dictionary* dico, void* bucket_data, dictionary_bucket_record_function bucket)
{
    yassert(dico != NULL);

    if(dico->ct.btree_collection != NULL)
    {
        btree_iterator iter;

        btree_iterator_init(dico->ct.btree_collection, &iter);

        while(btree_iterator_hasnext(&iter))
        {
            btree_node* bnode = (btree_node*)btree_iterator_next_node(&iter);

            hashcode key = bnode->hash;

            dictionary_node* node = (dictionary_node*)bnode->data;

            while(node != NULL)
            {
                dictionary_node* tmp = node;
                node = node->next;
                tmp->next = NULL;

                bucket(bucket_data, key, tmp); /* free, if any, is made here */
            }
        }

        btree_destroy(&dico->ct.btree_collection);
        dico->count = 0;
    }
}

void
dictionary_btree_fills(dictionary* dico, hashcode key, dictionary_node* node)
{
    dictionary_node** node_sll_p = (dictionary_node**)btree_insert(&dico->ct.btree_collection, key);
    node->next = (*node_sll_p);
    *node_sll_p = node;

    dico->count++;
}

/** @} */

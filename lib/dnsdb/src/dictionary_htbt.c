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
 *  @brief Dictionary module based on an hash table of binary trees
 *
 *  Dictionary module based on an hash table of binary trees
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

void dictionary_htbt_init(dictionary* dico);
void dictionary_htbt_destroy(dictionary* dico, dictionary_destroy_record_function destroy);
void dictionary_htbt_destroy_ex(dictionary* dico, dictionary_destroy_ex_record_function destroy, void* arg);
dictionary_node* dictionary_htbt_add(dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare, dictionary_data_record_create_function create);
dictionary_node* dictionary_htbt_find(const dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare);
dictionary_node** dictionary_htbt_findp(const dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare);
dictionary_node* dictionary_htbt_remove(dictionary* dico, hashcode key, void* record_match_data, dictionary_data_record_compare_function compare);
ya_result dictionary_htbt_process(dictionary* dico, hashcode key, void* record_match_data, dictionary_process_record_function compare);
void dictionary_htbt_iterator_init(const dictionary* dico, dictionary_iterator* iter);
bool dictionary_htbt_iterator_hasnext(dictionary_iterator* dico);
void** dictionary_htbt_iterator_next(dictionary_iterator* dico);
void dictionary_htbt_iterator_init_from(const dictionary* dico, dictionary_iterator* iter, const u8 *name);

void dictionary_htbt_empties(dictionary* dico, void* bucket, dictionary_bucket_record_function destroy);
void
dictionary_htbt_fills(dictionary* dico, hashcode key, dictionary_node* node);


static const struct dictionary_vtbl dictionary_htbt_vtbl =
{
    /*dictionary_htbt_init,*/
    dictionary_htbt_destroy,
    dictionary_htbt_add,
    dictionary_htbt_find,
    dictionary_htbt_findp,
    dictionary_htbt_remove,
    dictionary_htbt_process,
    dictionary_htbt_destroy_ex,
    dictionary_htbt_iterator_init,
    dictionary_htbt_iterator_init_from,
    dictionary_htbt_empties,
    dictionary_htbt_fills,
    "HTBT"
};

static const struct dictionary_iterator_vtbl dictionary_iterator_htbt_vtbl =
{
    dictionary_htbt_iterator_hasnext,
    dictionary_htbt_iterator_next
};

void
dictionary_htbt_init(dictionary* dico)
{
    htbt_init(&(dico->ct.htbt_collection));
    dico->vtbl = &dictionary_htbt_vtbl;
    dico->count = 0;
    dico->threshold = ~0;
}

void
dictionary_htbt_destroy(dictionary* dico, dictionary_destroy_record_function destroy)
{
    yassert(dico != NULL);

    if(dico->ct.htbt_collection != NULL)
    {
        htbt_iterator iter;

        htbt_iterator_init(dico->ct.htbt_collection, &iter);

        while(htbt_iterator_hasnext(&iter))
        {
            dictionary_node** node_sll_p = (dictionary_node**)htbt_iterator_next(&iter);
            dictionary_node* node = *node_sll_p;
            *node_sll_p = NULL;

            while(node != NULL)
            {
                dictionary_node* tmp = node;
                node = node->next;
                tmp->next = NULL;

                destroy(tmp);
            }


        }

        htbt_destroy(&dico->ct.htbt_collection);

        dico->count = 0;
    }
}

void
dictionary_htbt_destroy_ex(dictionary* dico, dictionary_destroy_ex_record_function destroyex, void* arg)
{
    yassert(dico != NULL);

    if(dico->ct.htbt_collection != NULL)
    {
        htbt_iterator iter;

        htbt_iterator_init(dico->ct.htbt_collection, &iter);

        while(htbt_iterator_hasnext(&iter))
        {
            dictionary_node** node_sll_p = (dictionary_node**)htbt_iterator_next(&iter);
            dictionary_node* node = *node_sll_p;
            *node_sll_p = NULL;

            while(node != NULL)
            {
                dictionary_node* tmp = node;
                node = node->next;
                tmp->next = NULL;

                destroyex(tmp, arg);
            }
        }

        htbt_destroy(&dico->ct.htbt_collection);

        dico->count = 0;
    }
}

dictionary_node*
dictionary_htbt_add(dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare,
                    dictionary_data_record_create_function create)
{
    dictionary_node** node_sll_p = (dictionary_node**)htbt_insert(dico->ct.htbt_collection, key);
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

    return node;
}

dictionary_node*
dictionary_htbt_find(const dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare)
{
    dictionary_node* node = (dictionary_node*)htbt_find(dico->ct.htbt_collection, key);

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
dictionary_htbt_findp(const dictionary* dico, hashcode key, const void* record_match_data, dictionary_data_record_compare_function compare)
{
    dictionary_node** node_sll_p = (dictionary_node**)htbt_findp(dico->ct.htbt_collection, key);

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
dictionary_htbt_remove(dictionary* dico, hashcode key, void* record_match_data, dictionary_data_record_compare_function compare)
{
    dictionary_node** node_sll_p = (dictionary_node**)htbt_findp(dico->ct.htbt_collection, key);
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
                htbt_delete(dico->ct.htbt_collection, key);
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
dictionary_htbt_process(dictionary* dico, hashcode key, void* record_match_data, dictionary_process_record_function process)
{
    dictionary_node** node_sll_p = (dictionary_node**)htbt_findp(dico->ct.htbt_collection, key);

    if(node_sll_p == NULL)
    {
        return ZDB_ERROR_KEY_NOTFOUND; /* NOT FOUND */
    }

    const dictionary_node** node_sll_head_p = (const dictionary_node**)node_sll_p;

    dictionary_node* node = *node_sll_p;

    while(node != NULL)
    {
        /* To allow to destroy the node inside, I should ...
         * dictionary_node* node_next=node->next; */

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
                    htbt_delete(dico->ct.htbt_collection, key);
                }

                /* return op */
            }
            FALLTHROUGH // fall through

            default:
            {
                return op;
            }
        }
    }

    return COLLECTION_PROCESS_NEXT;
}

void
dictionary_htbt_iterator_init(const dictionary* dico, dictionary_iterator* iter)
{
    iter->vtbl = &dictionary_iterator_htbt_vtbl;
    iter->sll = NULL;
    htbt_iterator_init(dico->ct.htbt_collection, &(iter->ct.as_htbt));
}

void
dictionary_htbt_iterator_init_from(const dictionary* dico, dictionary_iterator* iter, const u8 *name)
{
    iter->vtbl = &dictionary_iterator_htbt_vtbl;
    iter->sll = NULL;
    //avl_node *node = htbt_iterator_init_from(dico->ct.htbt_collection, &(iter->ct.as_htbt), key);
    hashcode key = hash_dnslabel(name);
    avl_node *node = htbt_iterator_init_from(dico->ct.htbt_collection, &(iter->ct.as_htbt), key);
    
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
dictionary_htbt_iterator_hasnext(dictionary_iterator* iter)
{
    return (iter->sll != NULL && iter->sll->next != NULL) ?
            TRUE
            :
            htbt_iterator_hasnext(&iter->ct.as_htbt)
            ;
}

void**
dictionary_htbt_iterator_next(dictionary_iterator* iter)
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
    vpp = htbt_iterator_next(&iter->ct.as_htbt);
    iter->sll = ((dictionary_node*)vpp)->next;
    return vpp;
}

void
dictionary_htbt_empties(dictionary* dico, void* bucket_data, dictionary_bucket_record_function bucket)
{
    yassert(dico != NULL);

    if(dico->ct.htbt_collection != NULL)
    {
        htbt_iterator iter;

        htbt_iterator_init(dico->ct.htbt_collection, &iter);

        while(htbt_iterator_hasnext(&iter))
        {
            htbt_node* hnode = htbt_iterator_next_node(&iter);

            hashcode key = hnode->hash;

            dictionary_node* node = (dictionary_node*)hnode->data;

            while(node != NULL)
            {
                dictionary_node* tmp = node;
                node = node->next;
                tmp->next = NULL;

                bucket(bucket_data, key, tmp); /* free, if any, is made here */
            }
        }

        htbt_destroy(&dico->ct.htbt_collection);

        dico->count = 0;
    }
}

void
dictionary_htbt_fills(dictionary* dico, hashcode key, dictionary_node* node)
{
    dictionary_node** node_sll_p = (dictionary_node**)htbt_insert(dico->ct.htbt_collection, key);
    node->next = (*node_sll_p);
    *node_sll_p = node;
    dico->count++;
}

/** @} */

/*----------------------------------------------------------------------------*/


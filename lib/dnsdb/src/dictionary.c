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
 *  @brief Hash-based collection designed to change it's structure to improve speed.
 *
 *  Hash-based collection designed to change it's structure to improve speed.
 *
 * @{
 */
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnsdb/zdb_config.h"
#include "dnsdb/dictionary.h"

#define ZDB_HASHTABLE_THRESHOLD_DISABLE (~0)

void dictionary_btree_init(dictionary* dico);

void dictionary_htbt_init(dictionary* dico);

struct dictionary_mutation_table_entry
{
    u32 threshold; /* Up to that number of items in the collection */
    dictionary_init_method* init;
};

static struct dictionary_mutation_table_entry dictionary_mutation_table[2] = {
    { ZDB_HASHTABLE_THRESHOLD, dictionary_btree_init},
    { MAX_U32, dictionary_htbt_init},
};


static struct dictionary_mutation_table_entry*
dictionary_get_mutation_entry(dictionary* dico)
{
    struct dictionary_mutation_table_entry* entry = dictionary_mutation_table;

    for(; dico->count > entry->threshold; entry++);

    return entry;
}

/*
 * I could avoid this hook, the signature is almost the same
 *
 */
static void
dictionary_bucket_record_callback(void* bucket_data, hashcode key, dictionary_node* node)
{
    dictionary_fills((dictionary*)bucket_data, key, node);
}

static void
dictionary_destroy_record_callback(dictionary_node* node)
{
    (void)node;
    /* This should NEVER be called */
    assert(FALSE); /* NOT zassert ! */
}

void
dictionary_init(dictionary* dico)
{
    dictionary_mutation_table[0].init(dico);
    dico->threshold = dictionary_mutation_table[0].threshold;
}

void
dictionary_mutate(dictionary* dico)
{
    struct dictionary_mutation_table_entry* entry = dictionary_get_mutation_entry(dico);

    /* Check the mutation condition */

    if(dico->threshold == entry->threshold)
    {
        return;
    }

    /* Mutate */

    dictionary new_dico;
    entry->init(&new_dico);

    /* Update the default (MAX_UNSIGNED_INT) threshold */

    new_dico.threshold = entry->threshold;

    dictionary_empties(dico, &new_dico, dictionary_bucket_record_callback);
    dictionary_destroy(dico, dictionary_destroy_record_callback);

    MEMCOPY(dico, &new_dico, sizeof(dictionary));
}

static bool
dictionary_empty_iterator_hasnext(dictionary_iterator* dico)
{
    (void)dico;
    return FALSE;
}

static void**
dictionary_empty_iterator_next(dictionary_iterator* dico)
{
    (void)dico;
    return NULL;
}

static const struct dictionary_iterator_vtbl no_element_iterator = 
{
    dictionary_empty_iterator_hasnext,
    dictionary_empty_iterator_next
};

void
dictionary_empty_iterator_init(dictionary_iterator *iter)
{
    iter->vtbl = &no_element_iterator;
}

/** @} */

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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Internal functions for the database: zoned resource records label.
 *
 *  Internal functions for the database: zoned resource records label.
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <dnscore/format.h>

#include "dnsdb/zdb.h"

#include "dnsdb/dictionary.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_error.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

/**
 * @brief INTERNAL callback, tests for a match between a label and a node.
 */

static int
zdb_zone_label_zlabel_match(const void *label, const dictionary_node * node)
{
    const zdb_zone_label* zone_label = (const zdb_zone_label*)node;
    return dnslabel_equals(zone_label->name, label);
}

/**
 * @brief INTERNAL callback, creates a new node instance
 */

static dictionary_node *
zdb_zone_label_create(const void *data)
{
    zdb_zone_label* zone_label;

    ZALLOC_OBJECT_OR_DIE(zone_label, zdb_zone_label, ZDB_ZONELABEL_TAG);

    zone_label->next = NULL;
    dictionary_init(&zone_label->sub);
    zone_label->name = dnslabel_zdup(data);

    zone_label->zone = NULL;

    return (dictionary_node *)zone_label;
}

/**
 * @brief INTERNAL callback, destroys a node instance and its collections.
 */

static void
zdb_zone_label_destroy_callback(dictionary_node * zone_label_node)
{
    if(zone_label_node == NULL)
    {
        return;
    }

    zdb_zone_label *zone_label = (zdb_zone_label*)zone_label_node;

    /* detach is made by destroy */

    dictionary_destroy(&zone_label->sub, zdb_zone_label_destroy_callback);

    dnslabel_zfree(zone_label->name);

    if(zone_label->zone != NULL)
    {
        zdb_zone_release(zone_label->zone);
        zone_label->zone = NULL;
    }

    ZFREE_OBJECT(zone_label);
}

/**
 * @brief Search for the label of a zone in the database
 *
 * Search for the label of a zone in the database
 *
 * @param[in] db the database to explore
 * @param[in] origin the dnsname_vector mapping the label
 *
 * @return a pointer to the label or NULL if it does not exists in the database.
 *
 */

zdb_zone_label*
zdb_zone_label_find(zdb * db, const dnsname_vector* origin) // mutex checked
{
    zdb_zone_label* zone_label;
    
    yassert(group_mutex_islocked(&db->mutex));
        
    zone_label = db->root; /* the "." zone */

    const_dnslabel_stack_reference sections = origin->labels;
    s32 index = origin->size;

    /* look into the sub level */

    while(zone_label != NULL && index >= 0)
    {
        const u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);

        zone_label =
                (zdb_zone_label*)dictionary_find(&zone_label->sub, hash, label,
                                                 zdb_zone_label_zlabel_match);

        index--;
    }

    return zone_label;
}

/**
 * @brief Search for the label of a zone in the database
 *
 * Search for the label of a zone in the database
 *
 * @param[in] db the database to explore
 * @param[in] origin the dnsname_vector mapping the label
 *
 * @return a pointer to the label or NULL if it does not exists in the database.
 *
 */

zdb_zone_label*
zdb_zone_label_find_nolock(zdb * db, const dnsname_vector* origin)
{
    zdb_zone_label* zone_label;
    
    zone_label = db->root; /* the "." zone */

    const_dnslabel_stack_reference sections = origin->labels;
    s32 index = origin->size;

    /* look into the sub level */

    while(zone_label != NULL && index >= 0)
    {
        const u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);

        zone_label =
                (zdb_zone_label*)dictionary_find(&zone_label->sub, hash, label,
                                                 zdb_zone_label_zlabel_match);

        index--;
    }
    
    return zone_label;
}

zdb_zone_label*
zdb_zone_label_find_from_name(zdb* db, const char* name) // mutex checked
{
    dnsname_vector origin;

    u8 dns_name[MAX_DOMAIN_LENGTH];

    if(ISOK(cstr_to_dnsname(dns_name, name)))
    {
        dnsname_to_dnsname_vector(dns_name, &origin);

        zdb_zone_label *label = zdb_zone_label_find(db, &origin); // in zdb_zone_label_find_from_name
        
        return label;
    }

    return NULL;
}

zdb_zone_label*
zdb_zone_label_find_from_dnsname(zdb* db, const u8* dns_name) // mutex checked
{
    dnsname_vector origin;

    dnsname_to_dnsname_vector(dns_name, &origin);

    zdb_zone_label *label = zdb_zone_label_find(db, &origin); // in zdb_zone_label_find_from_dnsname
    
    return label;
}

zdb_zone_label*
zdb_zone_label_find_from_dnsname_nolock(zdb* db, const u8* dns_name)
{
    dnsname_vector origin;

    dnsname_to_dnsname_vector(dns_name, &origin);

    zdb_zone_label *label = zdb_zone_label_find_nolock(db, &origin); // in zdb_zone_label_find_from_dnsname_nolock
    
    return label;
}

/**
 * @brief Destroys a label and its collections.
 *
 * Destroys a label and its collections.
 *
 * @param[in] zone_labelp a pointer to a pointer to the label to destroy.
 *
 */

void
zdb_zone_label_destroy(zdb_zone_label **zone_labelp)
{
    yassert(zone_labelp != NULL);
    
    zdb_zone_label* zone_label = *zone_labelp;

    if(zone_label != NULL)
    {
#if DEBUG
        log_debug5("zdb_zone_label_destroy: %{dnslabel}", zone_label->name);
#endif
        
        dictionary_destroy(&zone_label->sub, zdb_zone_label_destroy_callback);

        
        zdb_zone *zone = zone_label->zone;
        
        if(zone != NULL)
        {
#if DEBUG
            log_debug5("zdb_zone_label_destroy: %{dnsname}", zone->origin);
#endif
            mutex_lock(&zone->lock_mutex);
            alarm_close(zone->alarm_handle);
            zone->alarm_handle = ALARM_HANDLE_INVALID;
            mutex_unlock(&zone->lock_mutex);
            
            zdb_zone_release(zone);
            zone_label->zone = NULL;
        }
        
        //zdb_zone_destroy(zone_label->zone);
        
        dnslabel_zfree(zone_label->name);
        ZFREE_OBJECT(zone_label);
        *zone_labelp = NULL;
    }
}

/**
 * @brief Gets pointers to all the zone labels along the path of a name.
 *
 * Gets pointers to all the zone labels along the path of a name.
 *
 * @param[in] db a pointer to the database
 * @param[in] name a pointer to the dns name
 * @param[in] zone_label_stack a pointer to the stack that will hold the labels pointers
 *
 * @return the top of the stack (-1 = empty)
 */

s32
zdb_zone_label_match(zdb * db, const dnsname_vector* origin,  // mutex checked
                     zdb_zone_label_pointer_array zone_label_stack)
{
    zdb_zone_label* zone_label;
    
    yassert(zdb_islocked_by(db, ZDB_MUTEX_READER));
    
    zone_label = db->root; /* the "." zone */

    const_dnslabel_stack_reference sections = origin->labels;
    s32 index = origin->size;

    s32 sp = 0;

    zone_label_stack[0] = zone_label;

    /* look into the sub level */

    while(index >= 0)
    {
        const u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);

        zone_label = (zdb_zone_label*)dictionary_find(&zone_label->sub, hash, label, zdb_zone_label_zlabel_match);

        if(zone_label == NULL)
        {
            break;
        }

        zone_label_stack[++sp] = zone_label;

        index--;
    }
    
    return sp;
}

zdb_zone_label*
zdb_zone_label_add_nolock(zdb * db, const dnsname_vector* origin) // mutex checked
{
    zdb_zone_label* zone_label;
    
    yassert(zdb_islocked(db));

    zone_label = db->root; /* the "." zone */

    const_dnslabel_stack_reference sections = origin->labels;
    s32 index = origin->size;

    /* look into the sub level */

    while(index >= 0)
    {
        const u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);
        zone_label = (zdb_zone_label*)dictionary_add(&zone_label->sub, hash, label, zdb_zone_label_zlabel_match, zdb_zone_label_create);

        index--;
    }

    return zone_label;
}

typedef struct zdb_zone_label_delete_process_callback_args
zdb_zone_label_delete_process_callback_args;

struct zdb_zone_label_delete_process_callback_args
{
    dnslabel_stack_reference sections;
    s32 top;
};

/**
 * @brief INTERNAL callback
 */

static ya_result
zdb_zone_label_delete_process_callback(void *a, dictionary_node * node)
{
    yassert(node != NULL);

    zdb_zone_label* zone_label = (zdb_zone_label*)node;

    zdb_zone_label_delete_process_callback_args *args = (zdb_zone_label_delete_process_callback_args *)a;

    /*
     * a points to a kind of dnsname and we are going in
     *
     * we go down and down each time calling the dictionnary process for the next level
     *
     * at the last level we return the "delete" code
     *
     * from there, the dictionnary processor will remove the entry
     *
     * at that point the calling dictionnary will know if he has to delete his node or not
     *
     * and so on and so forth ...
     *
     */

    s32 top = args->top;
    const u8* label = (u8*)args->sections[top];

    if(!dnslabel_equals(zone_label->name, label))
    {
        return COLLECTION_PROCESS_NEXT;
    }

    /* match */

    if(top > 0)
    {
        /* go to the next level */

        label = args->sections[--args->top];
        hashcode hash = hash_dnslabel(label);

        ya_result err;
        if((err =
                dictionary_process(&zone_label->sub, hash, args,
                                   zdb_zone_label_delete_process_callback)) ==
                COLLECTION_PROCESS_DELETENODE)
        {
            /* check the node for relevance, return "delete" if irrelevant */

            if(ZONE_LABEL_IRRELEVANT(zone_label))
            {
                /* Irrelevant means that only the name remains */

                dictionary_destroy(&zone_label->sub,
                                   zdb_zone_label_destroy_callback);

                if(zone_label->zone != NULL)
                {
                    zdb_zone_release(zone_label->zone);
                    zone_label->zone = NULL;
                }
                
                dnslabel_zfree(zone_label->name);
                ZFREE_OBJECT(zone_label);

                return COLLECTION_PROCESS_DELETENODE;
            }

            return COLLECTION_PROCESS_STOP;
        }

        /* or ... stop */

        return err;
    }

    /* NOTE: the 'detach' is made by destroy : do not touch to the "next" field */
    /* NOTE: the freee of the node is made by destroy : do not do it */

    /* dictionary destroy will take every item in the dictionary and
     * iterate through it calling the passed function.
     */

    dictionary_destroy(&zone_label->sub, zdb_zone_label_destroy_callback);

    
    if(zone_label->zone != NULL)
    {
        zdb_zone_release(zone_label->zone);
        zone_label->zone = NULL;
    }
    
    dnslabel_zfree(zone_label->name);
    ZFREE_OBJECT(zone_label);

    return COLLECTION_PROCESS_DELETENODE;
}

/**
 * @brief Destroys a zone label and all its collections
 *
 * Destroys a zone label and all its collections
 *
 * @parm[in] db a pointer to the database
 * @parm[in] name a pointer to the name
 *
 * @return an error code
 */

ya_result
zdb_zone_label_delete(zdb * db, dnsname_vector* name) // mutex checked
{
    yassert(db != NULL && name != NULL && name->size >= 0);
    yassert(zdb_islocked(db));
    
    zdb_zone_label* root_label;
    root_label = db->root; /* the "." zone */

    if(root_label == NULL)
    {
        /* has already been destroyed */

        return ZDB_ERROR_NOSUCHCLASS;
    }

    zdb_zone_label_delete_process_callback_args args;
    args.sections = name->labels;
    args.top = name->size;

    hashcode hash = hash_dnslabel(args.sections[args.top]);

    ya_result err = dictionary_process(&root_label->sub, hash, &args, zdb_zone_label_delete_process_callback);
    
    if(err == COLLECTION_PROCESS_DELETENODE)
    {
        err = COLLECTION_PROCESS_STOP;
    }

    return err;
}

#if DEBUG

/**
 * DEBUG
 */

void
zdb_zone_label_print_indented(zdb_zone_label* zone_label, output_stream *os, int indented)
{
    if(zone_label == NULL)
    {
        osformatln(os, "%tg: NULL", indented);
        return;
    }

    if(zone_label->zone != NULL)
    {
        zdb_zone_print_indented(zone_label->zone, os, indented + 1);
    }

    if(zone_label->name != NULL)
    {
        osformatln(os, "%tg: '%{dnslabel}'", indented, zone_label->name);
    }
    else
    {
        osformatln(os, "%tg: WRONG", indented);
    }



    dictionary_iterator iter;
    dictionary_iterator_init(&zone_label->sub, &iter);

    while(dictionary_iterator_hasnext(&iter))
    {
        zdb_zone_label* *sub_labelp = (zdb_zone_label**)dictionary_iterator_next(&iter);

        zdb_zone_label_print_indented(*sub_labelp, os, indented + 1);
    }
}

void
zdb_zone_label_print(zdb_zone_label* zone_label, output_stream *os)
{
    zdb_zone_label_print_indented(zone_label, os, 0);
}

#endif

/** @} */

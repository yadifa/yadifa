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
 * @defgroup dnsdbzone Zone related functions
 * @ingroup dnsdb
 * @brief Internal functions for the database: zoned resource records label.
 *
 *  Internal functions for the database: zoned resource records label.
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnsdb/dnsdb_config.h"
#include <dnscore/format.h>

#include "dnsdb/dictionary.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/zdb_error.h"

#if ZDB_HAS_RRCACHE_ENABLED

/**
 * @brief Sets all records of a given type for a zone label (cache)
 *
 * Destroys all records of a given type for a zone label (cache)
 *
 * @parm[in] db a pointer to the database
 * @parm[in] name a pointer to the name
 * @parm[in] zclass the class of the zone of the label
 * @parm[in] type the type of the records to delete
 *
 * @return an error code
 */

ya_result zdb_zone_label_set_record_set(zdb *db, dnsname_vector *origin, uint16_t type, zdb_resource_record_data *ttl_rdata)
{
    if(ttl_rdata != NULL)
    {
        zdb_zone_label            *label = zdb_zone_label_add(db, origin); // cache

        zdb_resource_record_data **rrsetp = zdb_resource_record_sets_find_insert(&label->global_resource_record_set, type);

        zdb_resource_record_data  *replaced_rrset = *rrsetp;

        *rrsetp = ttl_rdata;

        while(replaced_rrset != NULL)
        {
            zdb_resource_record_data *tmp = replaced_rrset;
            replaced_rrset = replaced_rrset->next;
            zdb_resource_record_data_delete(tmp);
        }

        return SUCCESS;
    }
    else
    {
        return zdb_zone_label_delete_record(db, origin, type);
    }
}

struct zdb_zone_label_delete_record_process_callback_args
{
    dnslabel_stack_reference sections;
    int32_t                  top;
    uint16_t                 type;
};

typedef struct zdb_zone_label_delete_record_process_callback_args zdb_zone_label_delete_record_process_callback_args;

/**
 * @brief INTERNAL callback
 */

static ya_result zdb_zone_label_delete_record_process_callback(void *a, dictionary_node *node)
{
    yassert(node != NULL);

    zdb_zone_label                                     *zone_label = (zdb_zone_label *)node;

    zdb_zone_label_delete_record_process_callback_args *args = (zdb_zone_label_delete_record_process_callback_args *)a;

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

    int32_t  top = args->top;
    uint8_t *label = (uint8_t *)args->sections[top];

    if(!dnslabel_equals(zone_label->name, label))
    {
        return COLLECTION_PROCESS_NEXT;
    }

    /* match */

    if(top > 0)
    {
        /* go to the next level */

        label = args->sections[--args->top];
        hashcode  hash = hash_dnslabel(label);

        ya_result err;
        if((err = dictionary_process(&zone_label->sub, hash, args, zdb_zone_label_delete_record_process_callback)) == COLLECTION_PROCESS_DELETENODE)
        {
            /* check the node for relevance, return "delete" if irrelevant */

            if(ZONE_LABEL_IRRELEVANT(zone_label))
            {
                /* Irrelevant means that only the name remains */

                dictionary_destroy(&zone_label->sub, zdb_zone_label_destroy_callback);
#if ZDB_HAS_RRCACHE_ENABLED
                zdb_resource_record_sets_destroy(&zone_label->global_resource_record_set);
#endif
                zdb_zone_destroy(zone_label->zone);
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
    /* NOTE: the free of the node is made by destroy : do not do it */

    /* We are at the right place for the record */

    if(FAIL(zdb_resource_record_delete(&zone_label->global_resource_record_set, args->type))) /* CACHE: No FeedBack  */
    {
        return COLLECTION_PROCESS_RETURNERROR;
    }

    if(ZONE_LABEL_RELEVANT(zone_label))
    {
        return COLLECTION_PROCESS_STOP;
    }

    /* dictionary destroy will take every item in the dictionary and
     * iterate through it calling the passed function.
     */

    dictionary_destroy(&zone_label->sub, zdb_zone_label_destroy_callback);
#if ZDB_HAS_RRCACHE_ENABLED
    zdb_resource_record_sets_destroy(&zone_label->global_resource_record_set);
#endif
    zdb_zone_destroy(zone_label->zone);
    dnslabel_zfree(zone_label->name);
    ZFREE_OBJECT(zone_label);

    return COLLECTION_PROCESS_DELETENODE;
}

/**
 * @brief Destroys all records of a given type for a zone label (cache)
 *
 * Destroys all records of a given type for a zone label (cache)
 *
 * @parm[in] db a pointer to the database
 * @parm[in] name a pointer to the name
 * @parm[in] zclass the class of the zone of the label
 * @parm[in] type the type of the records to delete
 *
 * @return an error code
 */

ya_result zdb_zone_label_delete_record(zdb *db, dnsname_vector *name, uint16_t zclass, uint16_t type) // mutex checked
{
    yassert(db != NULL && name != NULL && name->size >= 0 && zclass > 0);

    zdb_zone_label *root_label;

#ifdef HAS_DYNAMIC_PROVISIONING
    zdb_lock(db, ZDB_MUTEX_WRITER);
#endif

#if ZDB_RECORDS_CLASS_MAX == 1
    root_label = db->root[0]; /* the "." zone */
#else
    root_label = db->root[ntohs(zclass) - 1]; /* the "." zone */
#endif

    if(root_label == NULL)
    {
        /* has already been destroyed */

#ifdef HAS_DYNAMIC_PROVISIONING
        zdb_unlock(db, ZDB_MUTEX_WRITER);
#endif

        return ZDB_ERROR_NOSUCHCLASS;
    }

    zdb_zone_label_delete_record_process_callback_args args;
    args.sections = name->labels;
    args.top = name->size;
    args.type = type;

    hashcode  hash = hash_dnslabel(args.sections[args.top]);

    ya_result err = dictionary_process(&root_label->sub, hash, &args, zdb_zone_label_delete_record_process_callback);

#ifdef HAS_DYNAMIC_PROVISIONING
    zdb_unlock(db, ZDB_MUTEX_WRITER);
#endif

    if(err == COLLECTION_PROCESS_DELETENODE)
    {
        err = COLLECTION_PROCESS_STOP;
    }

    return err;
}

struct zdb_zone_label_delete_record_exact_process_callback_args
{
    dnslabel_stack_reference sections;
    const zdb_ttlrdata      *ttlrdata;
    int32_t                  top;
    uint16_t                 type;
};

typedef struct zdb_zone_label_delete_record_exact_process_callback_args zdb_zone_label_delete_record_exact_process_callback_args;

/**
 * @brief INTERNAL callback
 */

static ya_result zdb_zone_label_delete_record_exact_process_callback(void *a, dictionary_node *node)
{
    yassert(node != NULL);

    zdb_zone_label                                           *zone_label = (zdb_zone_label *)node;

    zdb_zone_label_delete_record_exact_process_callback_args *args = (zdb_zone_label_delete_record_exact_process_callback_args *)a;

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

    int32_t  top = args->top;
    uint8_t *label = (uint8_t *)args->sections[top];

    if(!dnslabel_equals(zone_label->name, label))
    {
        return COLLECTION_PROCESS_NEXT;
    }

    /* match */

    if(top > 0)
    {
        /* go to the next level */

        label = args->sections[--args->top];
        hashcode  hash = hash_dnslabel(label);

        ya_result err;
        if((err = dictionary_process(&zone_label->sub, hash, args, zdb_zone_label_delete_record_exact_process_callback)) == COLLECTION_PROCESS_DELETENODE)
        {
            /* check the node for relevance, return "delete" if irrelevant */

            if(ZONE_LABEL_IRRELEVANT(zone_label))
            {
                /* Irrelevant means that only the name remains */

                dictionary_destroy(&zone_label->sub, zdb_zone_label_destroy_callback);
#if ZDB_HAS_RRCACHE_ENABLED
                zdb_resource_record_sets_destroy(&zone_label->global_resource_record_set);
#endif
                zdb_zone_destroy(zone_label->zone);
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
    /* NOTE: the free of the node is made by destroy : do not do it */

    /* We are at the right place for the record */

    if(FAIL(zdb_resource_record_delete_exact(&zone_label->global_resource_record_set, args->type, args->ttlrdata))) /* CACHE: No FeedBack */
    {
        return COLLECTION_PROCESS_RETURNERROR;
    }

    if(ZONE_LABEL_RELEVANT(zone_label))
    {
        return COLLECTION_PROCESS_STOP;
    }

    /* dictionary destroy will take every item in the dictionary and
     * iterate through it calling the passed function.
     */

    dictionary_destroy(&zone_label->sub, zdb_zone_label_destroy_callback);
#if ZDB_HAS_RRCACHE_ENABLED
    zdb_resource_record_sets_destroy(&zone_label->global_resource_record_set);
#endif
    zdb_zone_destroy(zone_label->zone);
    dnslabel_zfree(zone_label->name);
    ZFREE_OBJECT(zone_label);

    return COLLECTION_PROCESS_DELETENODE;
}

/**
 * @brief Destroys a record matching of a given type, ttl and rdata for a zone label (cache)
 *
 * Destroys a record matching of a given type, ttl and rdata for a zone label (cache)
 *
 * @parm[in] db a pointer to the database
 * @parm[in] name a pointer to the name
 * @parm[in] zclass the class of the zone of the label
 * @parm[in] type the type of the records to delete
 * @parm[in] ttlrdata the ttl and rdata to match
 *
 * @return an error code
 */

ya_result zdb_zone_label_delete_record_exact(zdb *db, dnsname_vector *name, uint16_t zclass, uint16_t type,
                                             const zdb_ttlrdata *ttlrdata) // mutex checked
{
    yassert(db != NULL && name != NULL && name->size >= 0 && zclass > 0);

    zdb_zone_label *root_label;

#ifdef HAS_DYNAMIC_PROVISIONING
    zdb_lock(db, ZDB_MUTEX_WRITER);
#endif

#if ZDB_RECORDS_CLASS_MAX == 1
    root_label = db->root[0]; /* the "." zone */
#else
    root_label = db->root[ntohs(zclass) - 1]; /* the "." zone */
#endif

    if(root_label == NULL)
    {
        /* has already been destroyed */

#ifdef HAS_DYNAMIC_PROVISIONING
        zdb_unlock(db, ZDB_MUTEX_WRITER);
#endif

        return ZDB_ERROR_NOSUCHCLASS;
    }

    zdb_zone_label_delete_record_process_callback_args args;
    args.sections = name->labels;
    args.top = name->size;
    args.type = type;

    hashcode  hash = hash_dnslabel(args.sections[args.top]);

    ya_result err = dictionary_process(&root_label->sub, hash, &args, zdb_zone_label_delete_record_exact_process_callback);

#ifdef HAS_DYNAMIC_PROVISIONING
    zdb_unlock(db, ZDB_MUTEX_WRITER);
#endif

    if(err == COLLECTION_PROCESS_DELETENODE)
    {
        err = COLLECTION_PROCESS_STOP;
    }

    return err;
}

/** @brief Search for a match in global/cache part of the database
 *
 *  Search for a match in global/cache part of the database
 *
 *  @param[in]  db the database
 *  @param[in]  dnsname_name the name dnsname to search for
 *  @param[in]  type the type to match
 *  @param[out] ttl_rdara_out a pointer to a pointer set of results (single linked list)
 *
 *  @return SUCCESS in case of success.
 */

ya_result zdb_query_global(zdb *db, uint8_t *name_, uint16_t type, zdb_resource_record_data **ttlrdata_out)
{
    yassert(ttlrdata_out != NULL);
    yassert(group_mutex_islocked(db));

    dnsname_vector name;

    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(name_, &name);

    zdb_zone_label           *zone_label = zdb_zone_label_find(db, &name); // cache mechanism ...

    zdb_resource_record_data *ttlrdata = zdb_resource_record_sets_find(&zone_label->global_resource_record_set, type);

    *ttlrdata_out = ttlrdata;

    return (ttlrdata != NULL) ? SUCCESS : ZDB_ERROR_KEY_NOTFOUND;
}

/** @brief Deletes an entry from the database
 *
 *  Matches and deletes an entry from the database
 *
 *  @param[in]  db the database
 *  @param[in]  name_ the name of the record
 *  @param[in]  type the type of the record
 *  @param[in]  ttl the ttl of the record
 *  @param[in]  rdata_size the size of the rdata of the record
 *  @param[in]  rdata a pointer to the rdata of the record
 *
 *  @return SUCCESS in case of success.
 */

ya_result zdb_delete_global(zdb *db, const uint8_t *name_, uint16_t type, uint32_t ttl, uint16_t rdata_size, void *rdata) /* 5 match, delete 1 */
{
    yassert(db != NULL && name_ != NULL && (rdata_size == 0 || rdata != NULL));

    dnsname_vector name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(name_, &name);

    zdb_ttlrdata ttlrdata;

    ZDB_RECORD_TTLRDATA_SET(ttlrdata, ttl, rdata_size, rdata);

    /* I do not really require a record set here ... */
    return zdb_zone_label_delete_record_exact(db, &name, type, &ttlrdata);
}

#ifdef CUTBEGIN

/** @brief Adds an entry in the database
 *
 *  Adds an entry in the database
 *
 *  @param[in]  db the database
 *  @param[in]  name_ the full name of the record (dns form)
 *  @param[in]  type the type of the record
 *  @param[in]  ttl the ttl of the record
 *  @param[in]  rdata_size the size of the rdata of the record
 *  @param[in]  rdata a pointer to the rdata of the record
 *
 *  @return SUCCESS in case of success.
 */

ya_result zdb_add_global(zdb *db, uint8_t *name_, uint16_t type, uint32_t ttl, uint16_t rdata_size, void *rdata) /* 4 match, add    1 */
{
    yassert(db != NULL && name_ != NULL && (rdata_size == 0 || rdata != NULL));

    dnsname_vector name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(name_, &name);

    zdb_zone_label *zone_label = zdb_zone_label_add(db, &name); // CUT OUT

    // This record will be put as it is in the DB

    zdb_resource_record_data *ttlrdata = zdb_resource_record_data_new_instance_copy(ttl, rdata_size, rdata);

    zdb_record_insert(&zone_label->global_resource_record_set, type, ttlrdata);
    /* CACHE: NO DELEGATION FLAGS */ /* #if 0 : NOT USED */

    return SUCCESS;
}

#endif // CUTEND

#endif

/** @} */

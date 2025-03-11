/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 * @defgroup records Internal functions for the database: resource records.
 * @ingroup dnsdb
 * @brief Internal functions for the database: resource records.
 *
 *  Internal functions for the database: resource records.
 *
 *  Handling of the class->type->ttl+rdata list.
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <dnscore/format.h>
#include <dnscore/dnscore.h>

#include <arpa/inet.h>

#include "dnsdb/zdb_zone_resource_record_sets.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/btree.h"

#if HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3_types.h"
#endif

#define TTLRDATA_TAG 0x41544144524c5454
#define ZDBRDATA_TAG 0x415441445242445a
#define TMPRDATA_TAG 0x4154414452504d54

/** @brief Inserts a resource record into the resource collection, assume no dups
 *
 *  Assume there are no dups.
 *  Inserts a ttl-rdata record into the rtl-rdata collection
 *  The caller loses the property of the record.
 *
 *  @param[in]  collection the collection
 *  @param[in]  class_ the class of the resource record
 *  @param[in]  type the type of the resource record
 *  @param[in]  ttl the ttl of the resource record
 *  @param[in]  rdata_size the size of the rdata of the resource record
 *  @param[in]  rdata a pointer to the rdata of the resource record
 *
 *  @return OK in case of success.
 */

void zdb_resource_record_sets_insert_record(zdb_resource_record_sets_set_t *collection, uint16_t type, int32_t ttl, zdb_resource_record_data_t *record)
{
    zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_insert(collection, type);
    zdb_resource_record_set_insert_record_with_ttl(&rrset_node->value, record, ttl);
}

zdb_resource_record_sets_node_t *zdb_resource_record_sets_insert_empty_set(zdb_resource_record_sets_set_t *collection, uint16_t type)
{
    zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_insert(collection, type);
    return rrset_node;
}

/** @brief Inserts a resource record into the resource collection, checks for dups
 *
 *  Do not assume anything.
 *  Inserts a ttl-rdata record into the rtl-rdata collection
 *  The caller loses the property of the record.
 *  If the record is a dup, it is destroyed.
 *
 *  @param[in]  collection the collection
 *  @param[in]  class_ the class of the resource record
 *  @param[in]  type the type of the resource record
 *  @param[in]  ttl the ttl of the resource record
 *  @param[in]  rdata_size the size of the rdata of the resource record
 *  @param[in]  rdata a pointer to the rdata of the resource record
 *
 *  @return true in case of success.
 */

bool zdb_resource_record_sets_insert_record_checked(zdb_resource_record_sets_set_t *collection, uint16_t type, int32_t ttl, zdb_resource_record_data_t *record)
{
    zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_insert(collection, type);
    if(!zdb_resource_record_set_insert_record_with_ttl_checked(&rrset_node->value, record, ttl))
    {
        zdb_resource_record_data_delete(record);
    }
    return true; // TODO: check this
}

bool zdb_resource_record_sets_insert_record_checked_with_mp(zdb_resource_record_sets_set_t *collection, uint16_t type, int32_t ttl, zdb_resource_record_data_t *record, memory_pool_t *mp)
{
    zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_insert(collection, type);
    if(!zdb_resource_record_set_insert_record_with_ttl_checked_with_mp(&rrset_node->value, record, ttl, mp))
    {
        zdb_resource_record_data_delete(record);
    }
    return true; // TODO: check this
}

/** @brief Inserts a resource record into the resource collection, checks for dups
 *
 * THIS ONLY MAKES SENSE FOR RRSIG, AND THIS IS TROUBLE FOR NOW
 * IT WILL NEED TO BE FIXED AT THE QUERY LEVEL AS THIS IS NOT POSSIBLE ANYMORE
 *
 *  Do not assume anything.
 *  Inserts a ttl-rdata record into the rtl-rdata collection
 *  The caller loses the property of the record.
 *  If the record is a dup, it is destroyed.
 *  TTL value is not propagated through the resource record set
 *
 *  @param[in]  collection the collection
 *  @param[in]  class_ the class of the resource record
 *  @param[in]  type the type of the resource record
 *  @param[in]  ttl the ttl of the resource record
 *  @param[in]  rdata_size the size of the rdata of the resource record
 *  @param[in]  rdata a pointer to the rdata of the resource record
 *
 *  @return true in case of success.
 */

bool zdb_resource_record_sets_insert_record_checked_keep_ttl(zdb_resource_record_sets_set_t *collection, uint16_t type, int32_t ttl, zdb_resource_record_data_t *record)
{
    zdb_resource_record_sets_insert_record_checked(collection, type, ttl, record);
    return true;
}

bool zdb_resource_record_sets_insert_record_checked_keep_ttl_with_mp(zdb_resource_record_sets_set_t *collection, uint16_t type, int32_t ttl, zdb_resource_record_data_t *record, memory_pool_t *mp)
{
    zdb_resource_record_sets_insert_record_checked_with_mp(collection, type, ttl, record, mp);
    return true;
}

#if !ZDB_RECORD_USES_INLINE

/** @brief Finds and return all the a resource record matching the class and type
 *
 *  Finds and returns all the a resource record matching the class and type
 *
 *  @param[in]  collection the collection
 *  @param[in]  class_ the class of the resource record to match
 *  @param[in]  type the type of the resource record to match
 *
 *  @return the first record, or NULL of none has been found.
 */

zdb_resource_record_data_t *zdb_resource_record_sets_find(const zdb_resource_record_sets_set *collection, uint16_t type)
{
    zdb_resource_record_data_t *record_list = (zdb_resource_record_data_t *)btree_find(collection, type);

    return record_list;
}

/** @brief Finds and return a pointer to the list of all the a resource record matching the class and type
 *
 *  Finds and returns a pointer to the list of all the a resource record matching the class and type
 *
 *  @param[in]  collection the collection
 *  @param[in]  class_ the class of the resource record to match
 *  @param[in]  type the type of the resource record to match
 *
 *  @return the first record, or NULL of none has been found.
 */

zdb_resource_record_data_t **zdb_resource_record_sets_findp(const zdb_resource_record_sets_set *collection, uint16_t type)
{
    zdb_resource_record_data_t **record_list = (zdb_resource_record_data_t **)btree_findp(collection, type);

    return record_list;
}

/** @brief Finds and return all the a resource record matching the class and type
 *  Create the node if no such resource exists
 *
 *  Finds and returl all the a resource record matching the class and type
 *  Create the node if no such resource exists
 *
 *  @param[in]  collection the collection
 *  @param[in]  class_ the class of the resource record to match
 *  @param[in]  type the type of the resource record to match
 *
 *  @return the first record, or NULL of none has been found.
 */

zdb_resource_record_data_t **zdb_resource_record_sets_find_insert(zdb_resource_record_sets_set *collection, uint16_t type)
{
    yassert(collection != NULL);

    zdb_resource_record_data_t **record_list = (zdb_resource_record_data_t **)btree_insert(collection, type);

    return record_list;
}

#endif

/** @brief Deletes all the a resource record matching the class and type
 *
 *  Deletes and return all the a resource record matching the class and type
 *
 *  @param[in]  collection the collection
 *  @param[in]  class_ the class of the resource record to match
 *  @param[in]  type the type of the resource record to match
 *
 *  @return OK in case of success.  ERROR if no record were deleted.
 */

ya_result zdb_resource_record_sets_delete_type(zdb_resource_record_sets_set_t *collection, uint16_t type)
{
    yassert(collection != NULL);

    if(type != TYPE_ANY)
    {
        zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_find(collection, type);

        if(rrset_node != NULL)
        {
            zdb_resource_record_sets_set_delete(collection, type);

            return SUCCESS;
        }
        else
        {
            return ZDB_ERROR_KEY_NOTFOUND;
        }
    }
    else
    {
        zdb_resource_record_sets_destroy(collection); /* FB: This should be handled by the caller */

        return SUCCESS;
    }
}

/** @brief Deletes the a resource record matching the class, type, ttl, rdata
 *
 *  Deletes the a resource record matching the class, type, ttl, rdata
 *
 *  @param[in]  collection the collection
 *  @param[in]  type the type of the resource record to match
 *  @param[in]  ttl the ttl of the resource record to match
 *  @param[in]  rdata_size the size of the rdata of the resource record to match
 *  @param[in]  rdata a pointer to the rdata of the resource record to match
 *
 *  @return SUCCESS  if we removed the last record of this type.
 *	    >SUCCESS if we removed the record but other of this type are still available.
 *          ERROR    if no record were deleted.
 */

ya_result zdb_resource_record_sets_delete_exact_record(zdb_resource_record_sets_set_t *collection, uint16_t type, const zdb_ttlrdata *ttlrdata)
{
    yassert((collection != NULL) && (type != TYPE_ANY));

    zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_find(collection, type);

    if(rrset_node != NULL)
    {
        zdb_resource_record_set_t *rrset = &rrset_node->value;

        if(zdb_resource_record_set_delete_matching(rrset, (bool (*)(const zdb_resource_record_data_t *, const void *))zdb_record_equals_unpacked, ttlrdata))
        {
            if(rrset->_record_count > 0)
            {
                return SUCCESS_STILL_RECORDS;
            }
            else
            {
                zdb_resource_record_sets_set_delete(collection, type);
                return SUCCESS_LAST_RECORD;
            }
        }
    }

    return ZDB_ERROR_KEY_NOTFOUND;
}

/** @brief Deletes the a resource record matching the class, type, ttl, rdata
 *
 *  Wraps zdb_resource_record_sets_delete_exact_record by having a local copy of the record.
 *  Vitally important if the parameter is made using the content of the set itself.
 *  Deletes the a resource record matching the class, type, ttl, rdata
 *
 *  @param[in]  collection the collection
 *  @param[in]  type the type of the resource record to match
 *  @param[in]  ttl the ttl of the resource record to match
 *  @param[in]  rdata_size the size of the rdata of the resource record to match
 *  @param[in]  rdata a pointer to the rdata of the resource record to match
 *
 *  @return SUCCESS  if we removed the last record of this type.
 *	    >SUCCESS if we removed the record but other of this type are still available.
 *          ERROR    if no record were deleted.
 */

ya_result zdb_resource_record_sets_delete_exact_record_self(zdb_resource_record_sets_set_t *collection, uint16_t type, const zdb_ttlrdata *ttlrdata_)
{
    ya_result    ret;
    uint8_t     *tmp;
    zdb_ttlrdata ttlrdata;
    ttlrdata.next = NULL;
    ttlrdata.rdata_size = ttlrdata_->rdata_size;
    uint8_t tmp_[512];

    if(ttlrdata.rdata_size <= sizeof(tmp_))
    {
        memcpy(tmp_, ttlrdata_->rdata_pointer, ttlrdata.rdata_size);
        ttlrdata.rdata_pointer = tmp_;
        ttlrdata.ttl = ttlrdata_->ttl;

        ret = zdb_resource_record_sets_delete_exact_record(collection, type, &ttlrdata); // safe
    }
    else
    {
        MALLOC_OR_DIE(uint8_t *, tmp, ttlrdata.rdata_size, TMPRDATA_TAG);
        memcpy(tmp, ttlrdata_->rdata_pointer, ttlrdata.rdata_size);
        ttlrdata.rdata_pointer = tmp;
        ttlrdata.ttl = ttlrdata_->ttl;

        ret = zdb_resource_record_sets_delete_exact_record(collection, type, &ttlrdata); // safe

        free(tmp);
    }

    return ret;
}

static void zdb_resource_record_sets_destroy_node_callback(zdb_resource_record_sets_node_t *rrset_node)
{
    zdb_resource_record_set_clear(&rrset_node->value); // nodes contain the zdb_resource_record_set_t and are freed after this
}

/** @brief Destroys all the a resource record of the collection
 *
 *  Destroys all the a resource record of the collection
 *
 *  @param[in]  collection the collection to destroy
 */

void zdb_resource_record_sets_destroy(zdb_resource_record_sets_set_t *collection)
{
    yassert(collection != NULL);

    zdb_resource_record_sets_set_callback_and_finalise(collection, zdb_resource_record_sets_destroy_node_callback);
}

/** @brief Checks if a collection is empty
 *
 *  Checks if a collection is empty
 *
 *  @return true if the collection is empty, false otherwise.
 */

bool zdb_resource_record_sets_isempty(const zdb_resource_record_sets_set_t *collection)
{
    yassert(collection != NULL);

    return zdb_resource_record_sets_set_isempty(collection);
}

/**
 * DEBUG
 */

void zdb_resource_record_sets_print_indented(const zdb_resource_record_sets_set_t *collection, output_stream_t *os, int indent)
{
    zdb_resource_record_sets_set_iterator_t iter;
    zdb_resource_record_sets_set_iterator_init(collection, &iter);
    while(zdb_resource_record_sets_set_iterator_hasnext(&iter))
    {
        zdb_resource_record_sets_node_t *node = zdb_resource_record_sets_set_iterator_next_node(&iter);
        zdb_resource_record_set_t       *rrset = (zdb_resource_record_set_t *)&node->value;

        uint16_t                         rtype = zdb_resource_record_set_type(rrset);

        for(int_fast32_t i = 0; i < rrset->_record_count; ++i)
        {
            zdb_resource_record_data_t *rr = zdb_resource_record_set_record_get(rrset, i);
            osformat(os, "%t[%{dnstype} %9d] ", indent, &rtype, rrset->_ttl);
            osprint_rdata(os, rtype, zdb_resource_record_data_rdata(rr), zdb_resource_record_data_rdata_size(rr));
            osprintln(os, "");
        }
    }
}

void     zdb_resource_record_sets_print(const zdb_resource_record_sets_set_t *collection, output_stream_t *os) { zdb_resource_record_sets_print_indented(collection, os, 0); }

uint16_t zdb_resource_record_sets_bitmap_type_init(const zdb_resource_record_sets_set_t *collection, type_bit_maps_context_t *bitmap)
{
    type_bit_maps_init(bitmap);

    zdb_resource_record_sets_set_iterator_t iter;
    zdb_resource_record_sets_set_iterator_init(collection, &iter);
    while(zdb_resource_record_sets_set_iterator_hasnext(&iter))
    {
        zdb_resource_record_sets_node_t *node = zdb_resource_record_sets_set_iterator_next_node(&iter);
        zdb_resource_record_set_t       *rrset = (zdb_resource_record_set_t *)&node->value;

        uint16_t                         rtype = zdb_resource_record_set_type(rrset);

        if((rtype != TYPE_A) && (rtype != TYPE_AAAA))
        {
            type_bit_maps_set_type(bitmap, rtype);
        }
    }

    uint16_t bitmap_size = type_bit_maps_update_size(bitmap);

    return bitmap_size;
}

/** @} */

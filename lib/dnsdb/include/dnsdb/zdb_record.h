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

#ifndef _ZDB_RECORD_H
#define _ZDB_RECORD_H

#include <dnscore/typebitmap.h>
#include <dnsdb/zdb_types.h>

#define ZDB_RECORD_USES_INLINE 1

#if ZDB_RECORD_USES_INLINE
#include <dnsdb/btree.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#define SUCCESS_STILL_RECORDS      SUCCESS
#define SUCCESS_LAST_RECORD        SUCCESS + 1

/**
 *
 * Internal functions for the ZDB structure.
 */

#define ZDB_RECORDS_COLLECTION_TAG 0x4343455242445a /** "ZDBRECC" */
#define ZDB_RECORD_RDATA_TAG       0x5243455242445a /** "ZDBRECR" */

#define COULD_BE_GLUE(type)        (((type) == TYPE_A) || ((type) == TYPE_AAAA) || ((type) == TYPE_A6))

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

/* 2 USES */
ya_result zdb_resource_record_sets_delete_type(zdb_resource_record_sets_set_t *collection, uint16_t type);

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
 *
 */

/* 4 USES */
ya_result zdb_resource_record_sets_delete_exact_record(zdb_resource_record_sets_set_t *collection, uint16_t type, const zdb_ttlrdata *ttlrdata);

/** @brief Deletes the a resource record matching the class, type, ttl, rdata (safer)
 *
 *  Makes a copy of the data to delete first.  This allow using the record from the DB as a base for removal.
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
 *
 */

ya_result zdb_resource_record_sets_delete_exact_record_self(zdb_resource_record_sets_set_t *collection, uint16_t type, const zdb_ttlrdata *ttlrdata_);

/** @brief Destroys all the a resource record of the collection
 *
 *  Destroys all the a resource record of the collection
 *
 *  @param[in]  collection the collection to destroy
 */

/* 23 USES */
void zdb_resource_record_sets_destroy(zdb_resource_record_sets_set_t *collection);

/** @brief Checks if a collection is empty
 *
 *  Checks if a collection is empty
 *
 *  @return true if the collection is empty, false otherwise.
 */

/* 1 USE */
bool zdb_resource_record_sets_isempty(const zdb_resource_record_sets_set_t *collection);

/** @brief Checks if two records are equal.
 *
 *  Checks if two records are equal.
 *
 *  @return true if the records are equal, false otherwise.
 */

/* 1 USE */
bool zdb_record_equals_unpacked(const zdb_resource_record_data_t *a, const zdb_ttlrdata *b);

/** @brief Checks if two records are equal.
 *
 *  Checks if two records are equal.
 *
 *  @return true if the records are equal, false otherwise.
 */

/* 1 USE */
bool zdb_record_equals(const zdb_resource_record_data_t *a, const zdb_resource_record_data_t *b);

/**
 * @brief Copies the soa rdata to an soa_rdata native structure.
 *
 * Copies the soa of a zone to an soa_rdata structure.
 * No memory is allocated for the soa_rdata.  If the zone is destroyed,
 * the soa_rdata becomes invalid.
 *
 * @param[in] zone a pointer to the zone
 * @param[out] soa_out a pointer to an soa_rdata structure
 */

ya_result zdb_record_getsoa(const zdb_resource_record_data_t *soa, zdb_soa_rdata_t *soa_out);

/**
 * @brief Allocated and duplicates the content of the source
 */

zdb_ttlrdata *zdb_ttlrdata_clone(const zdb_ttlrdata *source);

/**
 * @brief Allocated and duplicates the first bytes of content of the source
 * This is mostly used to clone an NSEC3 record into an NSEC3PARAM
 */

zdb_ttlrdata *zdb_ttlrdata_clone_resized(const zdb_ttlrdata *source, uint32_t rdata_newsize);

/**
 * @brief Frees the content of the source
 */
void zdb_ttlrdata_delete(zdb_ttlrdata *record);

/**
 * DEBUG
 */

void     zdb_resource_record_sets_print_indented(const zdb_resource_record_sets_set_t *collection, output_stream_t *os, int indent);
void     zdb_resource_record_sets_print(const zdb_resource_record_sets_set_t *collection, output_stream_t *os);

uint16_t zdb_resource_record_sets_bitmap_type_init(const zdb_resource_record_sets_set_t *collection, type_bit_maps_context_t *bitmap);

#ifdef __cplusplus
}
#endif

#endif /* _ZDB_RECORD_H */

/** @} */

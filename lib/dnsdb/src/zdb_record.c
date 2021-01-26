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

/** @defgroup records Internal functions for the database: resource records.
 *  @ingroup dnsdb
 *  @brief Internal functions for the database: resource records.
 *
 *  Internal functions for the database: resource records.
 *
 *  Handling of the class->type->ttl+rdata list.
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <dnscore/format.h>
#include <dnscore/dnscore.h>

#include <arpa/inet.h>

#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_error.h"

#include "dnsdb/btree.h"

#if HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3_types.h"
#endif

#define TTLRDATA_TAG 0x41544144524c5454
#define ZDBRDATA_TAG 0x415441445242445a
#define TMPRDATA_TAG 0x4154414452504d54

/** @brief Frees a resource record
 *
 *  Inserts a ttl-rdata record into the rtl-rdata collection
 *
 *  @param[in]  record the ttl-rdata to free
 */

static void
zdb_record_free(zdb_packed_ttlrdata* record)
{
    /** MEMORY CANNOT BE TRASHED WHEN USING ZALLOC BECAUSE rdata_size IS USED TO FREE THE MEMORY ! */
    /** DO NOT DO THIS : memset(record,0x8f,sizeof(zdb_packed_ttlrdata)+record->rdata_size-1); */

#if DEBUG
    //yassert((u32)(intptr)(record->next) != 0xfefefefeUL);
    u16 tmp = record->rdata_size;
    memset(record, 0xfe, sizeof(zdb_packed_ttlrdata) + tmp - 1);
    record->rdata_size = tmp;
#endif
    
    ZDB_RECORD_ZFREE(record);
}

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

void
zdb_record_insert(zdb_rr_collection* collection, u16 type, zdb_packed_ttlrdata* record)
{
    zdb_packed_ttlrdata** record_sll = (zdb_packed_ttlrdata**)btree_insert(collection, type);

#if DEBUG
    switch(type)
    {
        case TYPE_A:
            if(record->rdata_size != 4) abort();
            break;
        case TYPE_AAAA:
            if(record->rdata_size != 16) abort();
            break;
#if ZDB_HAS_NSEC3_SUPPORT
        case TYPE_NSEC3PARAM:
            if(record->rdata_size != NSEC3PARAM_RDATA_SIZE_FROM_RDATA(record->rdata_start)) abort();
            break;
#endif
        default:
            break;
    }
#endif
    
    record->next = *record_sll;
    *record_sll = record;
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
 *  @return TRUE in case of success.
 */

bool
zdb_record_insert_checked(zdb_rr_collection* collection, u16 type, zdb_packed_ttlrdata* record)
{
    zdb_packed_ttlrdata** record_sll = (zdb_packed_ttlrdata**)btree_insert(collection, type);
    
    if(type != TYPE_CNAME)
    {
        u32 ttl = record->ttl;
        
        zdb_packed_ttlrdata* next = *record_sll;
        
        while(next != NULL)
        {
            next->ttl = ttl;
            
            if(next->rdata_size == record->rdata_size)
            {
                if(memcmp(next->rdata_start, record->rdata_start, record->rdata_size) == 0) /* dup */
                {
#if DEBUG
                    switch(type)
                    {
                        case TYPE_A:
                            if(record->rdata_size != 4) abort();
                            break;
                        case TYPE_AAAA:
                            if(record->rdata_size != 16) abort();
                            break;
#if ZDB_HAS_NSEC3_SUPPORT
                        case TYPE_NSEC3PARAM:
                            if(record->rdata_size != NSEC3PARAM_RDATA_SIZE_FROM_RDATA(record->rdata_start)) abort();
                            break;
#endif
                        default:
                            break;
                    }
#endif
                    
                    next = next->next;
                    
                    while(next != NULL)
                    {
                        next->ttl = ttl;
                        
                        next = next->next;
                    }
                        
                    return FALSE;
                }
            }

            next = next->next;
        }

        record->next = *record_sll;
        *record_sll = record;
    }
    else
    {
        ZDB_RECORD_SAFE_ZFREE(*record_sll);
        record->next = NULL;
        *record_sll = record;
    }

    return TRUE;
}

/** @brief Inserts a resource record into the resource collection, checks for dups
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
 *  @return TRUE in case of success.
 */

bool
zdb_record_insert_checked_keep_ttl(zdb_rr_collection* collection, u16 type, zdb_packed_ttlrdata* record)
{
    zdb_packed_ttlrdata** record_sll = (zdb_packed_ttlrdata**)btree_insert(collection, type);
    
    if(type != TYPE_CNAME)
    {
        zdb_packed_ttlrdata* next = *record_sll;
        
        while(next != NULL)
        {
            if(next->rdata_size == record->rdata_size)
            {
                if(memcmp(next->rdata_start, record->rdata_start, record->rdata_size) == 0) /* dup */
                {
#if DEBUG
                    switch(type)
                    {
                        case TYPE_A:
                            if(record->rdata_size != 4) abort();
                            break;
                        case TYPE_AAAA:
                            if(record->rdata_size != 16) abort();
                            break;
#if ZDB_HAS_NSEC3_SUPPORT
                        case TYPE_NSEC3PARAM:
                            if(record->rdata_size != NSEC3PARAM_RDATA_SIZE_FROM_RDATA(record->rdata_start)) abort();
                            break;
#endif
                        default:
                            break;
                    }
#endif
                    
                    return FALSE;
                }
            }

            next = next->next;
        }

        record->next = *record_sll;
        *record_sll = record;
    }
    else
    {
        ZDB_RECORD_SAFE_ZFREE(*record_sll);
        record->next = NULL;
        *record_sll = record;
    }

    return TRUE;
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

zdb_packed_ttlrdata*
zdb_record_find(const zdb_rr_collection* collection, u16 type)
{
    zdb_packed_ttlrdata* record_list = (zdb_packed_ttlrdata*)btree_find(collection, type);

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

zdb_packed_ttlrdata**
zdb_record_findp(const zdb_rr_collection* collection, u16 type)
{
    zdb_packed_ttlrdata** record_list = (zdb_packed_ttlrdata**)btree_findp(collection, type);

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

zdb_packed_ttlrdata**
zdb_record_find_insert(zdb_rr_collection* collection, u16 type)
{
    yassert(collection != NULL);

    zdb_packed_ttlrdata** record_list = (zdb_packed_ttlrdata**)btree_insert(collection, type);

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

ya_result
zdb_record_delete(zdb_rr_collection* collection, u16 type)
{
    yassert(collection != NULL);

    if(type != TYPE_ANY)
    {
        zdb_packed_ttlrdata* record_list = (zdb_packed_ttlrdata*)btree_delete(collection, type);

        if(record_list != NULL)
        {
            /* We have the data of the node that has just been deleted */

            do
            {
                zdb_packed_ttlrdata* tmp = record_list;
                record_list = record_list->next;
                zdb_record_free(tmp);
            }
            while(record_list != NULL);

            return SUCCESS;
        }

        return ZDB_ERROR_KEY_NOTFOUND;
    }
    else
    {
        zdb_record_destroy(collection); /* FB: This should be handled by the caller */

        return SUCCESS;
    }
}

/** @brief Checks if two records are equal.
 *
 *  Checks if two records are equal.
 *
 *  @return TRUE if the records are equal, FALSE otherwise.
 */

bool
zdb_record_equals_unpacked(const zdb_packed_ttlrdata* a, const zdb_ttlrdata* b)
{
    int len;
    bool ret = FALSE;

    /* The TTL is irrelevant for matches */

    if((len = ZDB_PACKEDRECORD_PTR_RDATASIZE(a)) == ZDB_RECORD_PTR_RDATASIZE(b))
    {
        if(memcmp(ZDB_PACKEDRECORD_PTR_RDATAPTR(a), ZDB_RECORD_PTR_RDATAPTR(b), len) == 0)
        {
            ret = TRUE;
        }
    }

    return ret;
}

/** @brief Checks if two records are equal.
 *
 *  Checks if two records are equal.
 *
 *  @return TRUE if the records are equal, FALSE otherwise.
 */

bool
zdb_record_equals(const zdb_packed_ttlrdata *a, const zdb_packed_ttlrdata *b)
{
    int len;
    bool ret = FALSE;

    /* The TTL is irrelevant for matches */

    if((len = ZDB_PACKEDRECORD_PTR_RDATASIZE(a)) == ZDB_PACKEDRECORD_PTR_RDATASIZE(b))
    {
        if(memcmp(ZDB_PACKEDRECORD_PTR_RDATAPTR(a), ZDB_PACKEDRECORD_PTR_RDATAPTR(b), len) == 0)
        {
            ret = TRUE;
        }
    }

    return ret;
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

ya_result
zdb_record_delete_exact(zdb_rr_collection* collection, u16 type, const zdb_ttlrdata *ttlrdata)
{
    yassert((collection != NULL) && (type != TYPE_ANY));

    zdb_packed_ttlrdata** record_listp = (zdb_packed_ttlrdata**)btree_findp(collection, type);

    if(record_listp != NULL)
    {
        /* We got all the records of the same type */

        zdb_packed_ttlrdata* prev = NULL;
        zdb_packed_ttlrdata* record_list = *record_listp;

        while(record_list != NULL)
        {
            if(zdb_record_equals_unpacked(record_list, ttlrdata))
            {
                /* got it */

                /* first one of the list ? */

                if(prev == NULL) /* head */
                {
                    /* assign NEXT then check for emptyness */

                    ya_result ret = SUCCESS_STILL_RECORDS;    /* We destroyed the last record of this type */

                    if((*record_listp = record_list->next) == NULL)
                    {
                        /* delete the tree entry */

                        btree_delete(collection, type);

                        ret = SUCCESS_LAST_RECORD;                  /* There is still at least one record of this type available */
                    }
                    
                    yassert(record_list->rdata_start != ttlrdata->rdata_pointer);

                    zdb_record_free(record_list);

                    return ret;
                }

                prev->next = record_list->next;

                yassert(record_list->rdata_start != ttlrdata->rdata_pointer);
                
                zdb_record_free(record_list);

                return SUCCESS_STILL_RECORDS; /* There is still at least one record of this type available */
            }

            prev = record_list;

            record_list = record_list->next;

        }
    }

    return ZDB_ERROR_KEY_NOTFOUND;
}

ya_result
zdb_record_delete_self_exact(zdb_rr_collection* collection, u16 type, const zdb_ttlrdata *ttlrdata_)
{
    u8 *tmp;
    ya_result ret;
    u8 tmp_[512];
    zdb_ttlrdata ttlrdata;
    ttlrdata.next = NULL;
    ttlrdata.rdata_size = ttlrdata_->rdata_size;
    if(ttlrdata.rdata_size <= sizeof(tmp_))
    {
        tmp = &tmp_[0];
    }
    else   
    {
        MALLOC_OR_DIE(u8*, tmp, ttlrdata.rdata_size, TMPRDATA_TAG);
    }
    memcpy(tmp, ttlrdata_->rdata_pointer, ttlrdata.rdata_size);
    ttlrdata.rdata_pointer = tmp;
    ttlrdata.ttl = ttlrdata_->ttl;

    ret = zdb_record_delete_exact(collection, type, &ttlrdata); // safe
    
    if(ttlrdata.rdata_size <= sizeof(tmp_))
    {
    }
    else
    {
        free(tmp);
    }
    
    return ret;
}

static void
zdb_record_destroy_callback(void* record_list_)
{
    zdb_packed_ttlrdata* record_list = (zdb_packed_ttlrdata*)record_list_;

    while(record_list != NULL)
    {
        zdb_packed_ttlrdata* tmp = record_list;
        record_list = record_list->next;
        zdb_record_free(tmp);
    }
}

/** @brief Destroys all the a resource record of the collection
 *
 *  Destroys all the a resource record of the collection
 *
 *  @param[in]  collection the collection to destroy
 */

void
zdb_record_destroy(zdb_rr_collection* collection)
{
    yassert(collection != NULL);
    
    btree_callback_and_destroy(*collection, zdb_record_destroy_callback);
    *collection = NULL;
}

/** @brief Checks if a collection is empty
 *
 *  Checks if a collection is empty
 *
 *  @return TRUE if the collection is empty, FALSE otherwise.
 */

bool
zdb_record_isempty(const zdb_rr_collection* collection)
{
    yassert(collection != NULL);
    
    return *collection == NULL;
}

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

ya_result
zdb_record_getsoa(const zdb_packed_ttlrdata* soa, soa_rdata* soa_out)
{
    s32 soa_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(soa);

    const u8* soa_start = soa->rdata_start;
    soa_out->mname = soa_start;

    u32 len = dnsname_len(soa_start);

    soa_size -= len;

    if(soa_size <= 0)
    {
        return ZDB_ERROR_CORRUPTEDSOA;
    }

    soa_start += len;
    soa_out->rname = soa_start;

    len = dnsname_len(soa_start);

    soa_size -= len;
    if(soa_size != 5 * 4) /* Only the 5 32 bits (should) remain */
    {
        return ZDB_ERROR_CORRUPTEDSOA;
    }

    soa_start += len;

    soa_out->serial = ntohl(GET_U32_AT(*soa_start));
    soa_start += 4;
    soa_out->refresh = ntohl(GET_U32_AT(*soa_start));
    soa_start += 4;
    soa_out->retry  = ntohl(GET_U32_AT(*soa_start));
    soa_start += 4;
    soa_out->expire = ntohl(GET_U32_AT(*soa_start));
    soa_start += 4;
    soa_out->minimum = ntohl(GET_U32_AT(*soa_start));
    //soa_start += 4;

    return SUCCESS;
}

/**
 * @brief Allocated and duplicates the content of the source
 */

zdb_ttlrdata*
zdb_ttlrdata_clone(const zdb_ttlrdata* source)
{
    zdb_ttlrdata *rec;
    int size = ((sizeof(zdb_ttlrdata) + 7) & ~7) + source->rdata_size;
    ZALLOC_ARRAY_OR_DIE(zdb_ttlrdata*, rec, size, TTLRDATA_TAG);
    rec->next = NULL;
    rec->ttl = source->ttl;
    rec->rdata_size = source->rdata_size;
    rec->rdata_pointer = &((u8*)rec)[(sizeof(zdb_ttlrdata) + 7) & ~7];
    memcpy(rec->rdata_pointer, source->rdata_pointer, rec->rdata_size);
    
    return rec;
}

/**
 * @brief Allocated and duplicates the first bytes of content of the source
 * This is mostly used to clone an NSEC3 record into an NSEC3PARAM
 */

zdb_ttlrdata*
zdb_ttlrdata_clone_resized(const zdb_ttlrdata* source, u32 rdata_newsize)
{
    zdb_ttlrdata *rec;
    int size = ((sizeof(zdb_ttlrdata) + 7) & ~7) + rdata_newsize;
    ZALLOC_ARRAY_OR_DIE(zdb_ttlrdata*, rec, size, TTLRDATA_TAG);
    rec->next = NULL;
    rec->ttl = source->ttl;
    rec->rdata_size = rdata_newsize;
    rec->rdata_pointer = &((u8*)rec)[(sizeof(zdb_ttlrdata) + 7) & ~7];
    memcpy(rec->rdata_pointer, source->rdata_pointer, rec->rdata_size);
    
    return rec;
}

/**
 * @brief Frees the content of the source
 */
void zdb_ttlrdata_delete(zdb_ttlrdata* record)
{
    int size = ((sizeof(zdb_ttlrdata) + 7) & ~7) + record->rdata_size;
    ZFREE_ARRAY(record, size);
    (void)size; // silences warning in some builds setups
}

/**
 * DEBUG
 */

void
zdb_record_print_indented(zdb_rr_collection collection, output_stream *os, int indent)
{
    btree_iterator iter;
    btree_iterator_init(collection, &iter);

    while(btree_iterator_hasnext(&iter))
    {
        btree_node* node = btree_iterator_next_node(&iter);
        u16 type = node->hash;

        zdb_packed_ttlrdata* ttlrdata_sll = (zdb_packed_ttlrdata*)node->data;

        if(ttlrdata_sll == NULL)
        {
            osformatln(os, "%t[%{dnstype}] EMPTY TYPE", indent, &type);
            continue;
        }

        do
        {
            osformat(os, "%t[%{dnstype} %9d] ", indent, &type, ttlrdata_sll->ttl);
            osprint_rdata(os, type, ZDB_PACKEDRECORD_PTR_RDATAPTR(ttlrdata_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(ttlrdata_sll));
            osprintln(os, "");

            ttlrdata_sll = ttlrdata_sll->next;
        }
        while(ttlrdata_sll != NULL);
    }
}

void
zdb_record_print(zdb_rr_collection collection, output_stream *os)
{
    zdb_record_print_indented(collection, os, 0);
}

u16
zdb_record_bitmap_type_init(const zdb_rr_collection collection, type_bit_maps_context *bitmap)
{
    type_bit_maps_init(bitmap);

    btree_iterator iter;
    btree_iterator_init(collection, &iter);

    while(btree_iterator_hasnext(&iter))
    {
        btree_node* node = btree_iterator_next_node(&iter);
        u16 type = node->hash;
        if((type != TYPE_A) && (type != TYPE_AAAA))
        {
            type_bit_maps_set_type(bitmap, type);
        }
    }

    u16 bitmap_size = type_bit_maps_update_size(bitmap);

    return bitmap_size;
}

/** @} */

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
 * @defgroup types The types used in the database
 * @ingroup dnsdb
 * @brief The types used in the database
 *
 * The types used in the database
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnsdb/zdb_config_features.h>

#include <dnscore/typebitmap.h>
#include <dnsdb/zdb_zone_resource_record_set.h>
#include <dnsdb/zdb_ttlrdata.h>

#include <dnsdb/btree.h>

#ifdef __cplusplus
extern "C"
{
#endif

#include <dnscore/sys_types.h>

/*
 * A digest is stored prefixed with its length ([1;255])
 */

/*
 * A structure to hold both children with direct access
 */

struct zdb_resource_record_sets_set_s;
struct zdb_resource_record_sets_node_s;
typedef struct zdb_resource_record_sets_set_s  zdb_resource_record_sets_set_t;
typedef struct zdb_resource_record_sets_node_s zdb_resource_record_sets_node_t;

struct zdb_resource_record_sets_set_s
{
    struct zdb_resource_record_sets_node_s *root;
};

struct zdb_resource_record_sets_set_children
{
    struct zdb_resource_record_sets_node_s *left;
    struct zdb_resource_record_sets_node_s *right;
};

/*
 * A union to have access to the children with direct or indexed access
 */

typedef union zdb_resource_record_sets_set_children_union zdb_resource_record_sets_set_children_union;

union zdb_resource_record_sets_set_children_union
{
    struct zdb_resource_record_sets_set_children lr;
    struct zdb_resource_record_sets_node_s      *child[2];
};

/*
 * The node structure CANNOT have a varying size on a given collection
 * This means that the digest size is a constant in the whole tree
 */

struct zdb_resource_record_sets_node_s
{
    zdb_resource_record_set_t                         value;    // MUST be the first entry
    union zdb_resource_record_sets_set_children_union children; // 16
    int8_t                                            balance;
};

/*
 * AVL definition part begins here
 */

/*
 * The maximum depth of a tree.
 * 40 is enough for storing 433494436 items (worst case)
 *
 * Depth 0 is one node.
 *
 * Worst case : N is enough for sum[n = 0,N](Fn) where Fn is Fibonacci(n+1)
 * Best case : N is enough for (2^(N+1))-1
 */
#define AVL_DEPTH_MAX            22 // 75024 items max (worst case)

/*
 * The previx that will be put in front of each function name
 */
#define AVL_PREFIX               zdb_resource_record_sets_set_

/*
 * The type that hold the node
 */
#define AVL_NODE_TYPE            zdb_resource_record_sets_node_t

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_TREE_TYPE            zdb_resource_record_sets_set_t

/*
 * The type that hold the tree (should be AVL_NODE_TYPE*)
 */
#define AVL_CONST_TREE_TYPE      const zdb_resource_record_sets_set_t

/*
 *
 */
#define AVL_TREE_ROOT(__tree__)  (__tree__)->root
/*
 * The type used for comparing the nodes.
 */
#define AVL_REFERENCE_TYPE       uint16_t
#define AVL_REFERENCE_IS_POINTER false
#define AVL_REFERENCE_IS_CONST   false

/*
 * The node has got a pointer to its parent
 *
 * 0   : disable
 * !=0 : enable
 */
#define AVL_HAS_PARENT_POINTER   0

#ifdef __cplusplus
}
#endif

#include <dnscore/avl.h.inc>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * I recommend setting a #define to identify the C part of the template
 * So it can be used to undefine what is not required anymore for every
 * C file but that one.
 *
 */

#ifndef __ZDB_ZONE_RESOURCE_RECORD_SETS_C__

#undef AVL_DEPTH_MAX
#undef AVL_PREFIX
#undef AVL_NODE_TYPE
#undef AVL_TREE_TYPE
#undef AVL_CONST_TREE_TYPE
#undef AVL_TREE_ROOT
#undef AVL_REFERENCE_TYPE
#undef AVL_HAS_PARENT_POINTER
#undef AVL_REFERENCE_IS_POINTER
#undef AVL_REFERENCE_IS_CONST
#undef _AVL_H_INC

#endif /* __ZDB_ZONE_RESOURCE_RECORD_SETS_C__ */

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct zdb_resource_record_sets_set_s zdb_resource_record_sets_set_t;

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

void                             zdb_resource_record_sets_insert_record(zdb_resource_record_sets_set_t *collection, uint16_t type, int32_t ttl, zdb_resource_record_data_t *record);

zdb_resource_record_sets_node_t *zdb_resource_record_sets_insert_empty_set(zdb_resource_record_sets_set_t *collection, uint16_t type);

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

bool zdb_resource_record_sets_insert_record_checked(zdb_resource_record_sets_set_t *collection, uint16_t type, int32_t ttl, zdb_resource_record_data_t *record);

bool zdb_resource_record_sets_insert_record_checked_with_mp(zdb_resource_record_sets_set_t *collection, uint16_t type, int32_t ttl, zdb_resource_record_data_t *record, memory_pool_t *mp);

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
 *  @return true in case of success.
 */

bool zdb_resource_record_sets_insert_record_checked_keep_ttl(zdb_resource_record_sets_set_t *collection, uint16_t type, int32_t ttl, zdb_resource_record_data_t *record);

bool zdb_resource_record_sets_insert_record_checked_keep_ttl_with_mp(zdb_resource_record_sets_set_t *collection, uint16_t type, int32_t ttl, zdb_resource_record_data_t *record, memory_pool_t *mp);

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

static inline const zdb_resource_record_set_t *zdb_resource_record_sets_find_set_const(const zdb_resource_record_sets_set_t *rrsets, uint16_t type)
{
    void                            *item = zdb_resource_record_sets_set_find(rrsets, type);
    const zdb_resource_record_set_t *rrset = (const zdb_resource_record_set_t *)item;
    return rrset;
}

static inline bool zdb_resource_record_sets_has_type(const zdb_resource_record_sets_set_t *rrsets, uint16_t type)
{
    struct zdb_resource_record_sets_node_s *rrset_node = zdb_resource_record_sets_set_find(rrsets, type);
    return rrset_node != NULL;
}

static inline zdb_resource_record_set_t *zdb_resource_record_sets_find(const zdb_resource_record_sets_set_t *rrsets, uint16_t type)
{
    zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_find(rrsets, type);

    return &rrset_node->value;
}

static inline zdb_resource_record_data_t *zdb_resource_record_sets_find_soa(const zdb_resource_record_sets_set_t *rrsets)
{
    zdb_resource_record_sets_node_t *soa_rrset_node = zdb_resource_record_sets_set_find(rrsets, TYPE_SOA);
    if(soa_rrset_node != NULL)
    {
        if(zdb_resource_record_set_of_one(&soa_rrset_node->value))
        {
            return soa_rrset_node->value._record;
        }
    }
    return NULL;
}

static inline zdb_resource_record_data_t *zdb_resource_record_sets_find_soa_and_ttl(const zdb_resource_record_sets_set_t *rrsets, int32_t *soa_ttl)
{
    struct zdb_resource_record_sets_node_s *soa_rrset_node = zdb_resource_record_sets_set_find(rrsets, TYPE_SOA);
    if(soa_rrset_node != NULL)
    {
        if(zdb_resource_record_set_of_one(&soa_rrset_node->value))
        {
            *soa_ttl = soa_rrset_node->value._ttl;
            return soa_rrset_node->value._record;
        }
    }
    return NULL;
}

static inline zdb_resource_record_data_t *zdb_resource_record_sets_find_nsec(const zdb_resource_record_sets_set_t *rrsets)
{
    struct zdb_resource_record_sets_node_s *nsec_rrset_node = zdb_resource_record_sets_set_find(rrsets, TYPE_NSEC);
    if(nsec_rrset_node != NULL)
    {
        if(zdb_resource_record_set_of_one(&nsec_rrset_node->value))
        {
            return nsec_rrset_node->value._record;
        }
    }
    return NULL;
}

static inline zdb_resource_record_data_t *zdb_resource_record_sets_find_nsec_and_ttl(const zdb_resource_record_sets_set_t *rrsets, int32_t *nsec_ttl)
{
    struct zdb_resource_record_sets_node_s *nsec_rrset_node = zdb_resource_record_sets_set_find(rrsets, TYPE_NSEC);
    if(nsec_rrset_node != NULL)
    {
        if(zdb_resource_record_set_of_one(&nsec_rrset_node->value))
        {
            *nsec_ttl = nsec_rrset_node->value._ttl;
            return nsec_rrset_node->value._record;
        }
    }
    return NULL;
}

static inline zdb_resource_record_data_t *zdb_resource_record_sets_find_cname(const zdb_resource_record_sets_set_t *rrsets)
{
    struct zdb_resource_record_sets_node_s *cname_rrset_node = zdb_resource_record_sets_set_find(rrsets, TYPE_CNAME);
    if(cname_rrset_node != NULL)
    {
        if(zdb_resource_record_set_of_one(&cname_rrset_node->value))
        {
            return cname_rrset_node->value._record;
        }
    }
    return NULL;
}

static inline zdb_resource_record_data_t *zdb_resource_record_sets_find_cname_and_ttl(const zdb_resource_record_sets_set_t *rrsets, int32_t *cname_ttl)
{
    struct zdb_resource_record_sets_node_s *cname_rrset_node = zdb_resource_record_sets_set_find(rrsets, TYPE_CNAME);
    if(cname_rrset_node != NULL)
    {
        if(zdb_resource_record_set_of_one(&cname_rrset_node->value))
        {
            *cname_ttl = cname_rrset_node->value._ttl;
            return cname_rrset_node->value._record;
        }
    }
    return NULL;
}

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
 */

ya_result zdb_resource_record_sets_delete_exact_record(zdb_resource_record_sets_set_t *collection, uint16_t type, const zdb_ttlrdata *ttlrdata);

ya_result zdb_resource_record_sets_delete_exact_record_self(zdb_resource_record_sets_set_t *collection, uint16_t type, const zdb_ttlrdata *ttlrdata_);

/** @brief Destroys all the a resource record of the collection
 *
 *  Destroys all the a resource record of the collection
 *
 *  @param[in]  collection the collection to destroy
 */

void zdb_resource_record_sets_destroy(zdb_resource_record_sets_set_t *collection);

/** @brief Checks if a collection is empty
 *
 *  Checks if a collection is empty
 *
 *  @return true if the collection is empty, false otherwise.
 */

bool zdb_resource_record_sets_isempty(const zdb_resource_record_sets_set_t *collection);

/**
 * DEBUG
 */

void     zdb_resource_record_sets_print_indented(const zdb_resource_record_sets_set_t *collection, output_stream_t *os, int indent);

void     zdb_resource_record_sets_print(const zdb_resource_record_sets_set_t *collection, output_stream_t *os);

uint16_t zdb_resource_record_sets_bitmap_type_init(const zdb_resource_record_sets_set_t *collection, type_bit_maps_context_t *bitmap);

#ifdef __cplusplus
}
#endif

/** @} */

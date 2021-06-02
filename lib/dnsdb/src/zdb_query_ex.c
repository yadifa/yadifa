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

/** @defgroup query_ex Database top-level query function
 *  @ingroup dnsdb
 *  @brief Database top-level query function
 *
 *  Database top-level query function
 *
 * @{
 */
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>
#define DEBUG_LEVEL 0
#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnscore/random.h>
#include <dnscore/dnsname_set.h>
#include <dnscore/message.h>
#include <dnscore/thread_pool.h>

#include "dnsdb/zdb.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/dictionary.h"
#if ZDB_HAS_NSEC_SUPPORT
#include "dnsdb/nsec.h"
#endif
#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif
#if ZDB_HAS_DNSSEC_SUPPORT
#include "dnsdb/rrsig.h"
#endif
#if ZDB_EXPLICIT_READER_ZONE_LOCK
#define LOCK(a_)    zdb_zone_lock((a_), ZDB_ZONE_MUTEX_SIMPLEREADER)
#define UNLOCK(a_)  zdb_zone_unlock((a_), ZDB_ZONE_MUTEX_SIMPLEREADER)
#else
#define LOCK(a_)   
#define UNLOCK(a_) 
#endif

#define ENFORCE_MINTTL 1

/**
 * In order to optimise-out the class parameter that is not required if ZDB_RECORDS_MAX_CLASS == 1 ...
 */
#if ZDB_RECORDS_MAX_CLASS != 1
#define DECLARE_ZCLASS_PARAMETER    u16 zclass,
#define PASS_ZCLASS_PARAMETER       zclass,
#define PASS_ZONE_ZCLASS_PARAMETER  zone->zclass,
#else
#define DECLARE_ZCLASS_PARAMETER
#define PASS_ZCLASS_PARAMETER
#define PASS_ZONE_ZCLASS_PARAMETER
#endif     

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger
#ifndef HAS_DYNAMIC_PROVISIONING
#error "MISSING HAS_DYNAMIC_PROVISIONING"
#endif

#define DEBUG_LOG_POOL_USAGE 0

#if DEBUG_LOG_POOL_USAGE
static inline void log_pool_usage(message_data *mesg, u8 * restrict *pool)
{
    u8 *pool_position = *((u8**)pool);
    log_debug("pool usage: %llu", pool_position - (u8*)message_get_pool_buffer(mesg));
}
#else
#define log_pool_usage(...)
#endif

process_flags_t zdb_query_process_flags = ~0;

/** @brief Creates a answer node from a database record
 *
 * @param source a pointer to the ttlrdata to put into the node
 * @param name the owner of the record
 * @param zclass (if more than one class is supported in the database)
 * @param rtype the type of the record
 * @param pool the memory pool
 * 
 * @return a resource record suitable for network serialisation
 *
 * 5 uses
 * 
 */

static inline zdb_resourcerecord*
zdb_query_ex_answer_make(const zdb_packed_ttlrdata* source, const u8* name,
                         DECLARE_ZCLASS_PARAMETER
                         u16 rtype, u8 * restrict * pool)
{
    yassert(source != NULL && name != NULL);

    zdb_resourcerecord* node = (zdb_resourcerecord*) * pool;
#if DEBUG
    memset(node, 0xff, ALIGN16(sizeof(zdb_resourcerecord)));
#endif

    *pool += ALIGN16(sizeof(zdb_resourcerecord));

    node->next = NULL;
    node->ttl_rdata = (zdb_packed_ttlrdata*)source;
    /** @note I should not need to clone the name
     *  It comes either from the query, either from an rdata in the database.
     */
    node->name = name;
#if ZDB_RECORDS_MAX_CLASS != 1
    node->zclass = zclass;
#else
    node->zclass = CLASS_IN;
#endif
    
    node->rtype = rtype;
    node->ttl = source->ttl;

    return node;
}

/** @brief Creates a answer node from a database record with a specific TTL
 *
 * @param source a pointer to the ttlrdata to put into the node
 * @param name the owner of the record
 * @param zclass (if more than one class is supported in the database)
 * @param rtype the type of the record
 * @param ttl the TTL that replaces the one in the record
 * @param pool the memory pool
 *
 * @return a resource record suitable for network serialisation
 * 
 * 5 uses
 */

static inline zdb_resourcerecord*
zdb_query_ex_answer_make_ttl(const zdb_packed_ttlrdata* source, const u8* name,
                             DECLARE_ZCLASS_PARAMETER
                             u16 rtype, u32 ttl, u8 * restrict * pool)
{
    yassert(source != NULL && name != NULL);

    zdb_resourcerecord* node = (zdb_resourcerecord*) * pool;
#if DEBUG
    memset(node, 0xff, ALIGN16(sizeof(zdb_resourcerecord)));
#endif

    *pool += ALIGN16(sizeof(zdb_resourcerecord));

    node->next = NULL;
    node->ttl_rdata = (zdb_packed_ttlrdata*)source;
    /** @note I should not need to clone the name
     *  It comes either from the query, either from an rdata in the database.
     */
    
    node->name = name;
#if ZDB_RECORDS_MAX_CLASS != 1
    node->zclass = zclass;
#else
    node->zclass = CLASS_IN;
#endif
    
    node->rtype = rtype;

    node->ttl = ttl;

    return node;
}

/** @brief Appends a list of database records to a list of nodes at a random position
 *
 * @param source a pointer to the ttlrdata to put into the node
 * @param name the owner of the record
 * @param zclass (if more than one class is supported in the database)
 * @param rtype the type of the record
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 6 uses
 */
static void
zdb_query_ex_answer_appendrndlist(const zdb_packed_ttlrdata* source, const u8* label,
                                  DECLARE_ZCLASS_PARAMETER
                                  u16 type, zdb_resourcerecord** headp, u8 * restrict * pool)
{
    yassert(source != NULL && label != NULL);

    zdb_resourcerecord* head = zdb_query_ex_answer_make(source, label,
                                                        PASS_ZCLASS_PARAMETER
                                                        type, pool);
    head->next = *headp;
    source = source->next;

    if(source != NULL)
    {
        random_ctx rndctx = thread_pool_get_random_ctx();

        int rnd = random_next(rndctx);

        do
        {
            zdb_resourcerecord* node = zdb_query_ex_answer_make(source, label,
                                            PASS_ZCLASS_PARAMETER
                                            type, pool);

            if(rnd & 1)
            {
                /* put the new node in front of the head,
                 * and assign the head to node
                 */

                node->next = head;
                head = node;
            }
            else
            {
                /* put the new node next to the head */
                node->next = head->next;
                head->next = node;
            }

            rnd >>= 1;

            /**
             *  @note: After 32 entries it will not be so randomized at all ...
             */

            source = source->next;
        }
        while(source != NULL);
    }

    *headp = head;
}

/** @brief Appends a list of database records to a list of nodes
 *
 * @param source a pointer to the ttlrdata to put into the node
 * @param name the owner of the record
 * @param zclass (if more than one class is supported in the database)
 * @param rtype the type of the record
 * @param headp a pointer to the section list
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 10 uses
 */
static void
zdb_query_ex_answer_appendlist(const zdb_packed_ttlrdata* source, const u8* label,
                               DECLARE_ZCLASS_PARAMETER
                               u16 rtype, zdb_resourcerecord** headp, u8 * restrict * pool)
{
    yassert(source != NULL && label != NULL);

    zdb_resourcerecord* head = *headp;
    while(source != NULL)
    {
        zdb_resourcerecord* node = zdb_query_ex_answer_make(source, label, PASS_ZCLASS_PARAMETER rtype, pool);
        
        node->next = head;
        head = node;
        source = source->next;
    }
    *headp = head;
}

#if ZDB_HAS_DNSSEC_SUPPORT

/** @brief Appends a list of database records to a list of nodes with a specific TTL
 *
 * @param source a pointer to the ttlrdata to put into the node
 * @param name the owner of the record
 * @param zclass (if more than one class is supported in the database)
 * @param rtype the type of the record
 * @param ttl the ttl of the record set
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 12 uses, NSEC3 only
 */
static void
zdb_query_ex_answer_appendlist_ttl(const zdb_packed_ttlrdata* source, const u8* label,
                                   DECLARE_ZCLASS_PARAMETER
                                   u16 rtype, u32 ttl, zdb_resourcerecord** headp, u8 * restrict * pool)
{
    yassert(source != NULL && label != NULL);

    zdb_resourcerecord* next = *headp;
    int countdown = 32;
    while(source != NULL)
    {
        zdb_resourcerecord* node = zdb_query_ex_answer_make_ttl(source, label, 
                                                                PASS_ZCLASS_PARAMETER                                                                
                                                                rtype, ttl, pool);
        node->next = next;
        next = node;
        source = source->next;
        
        if(--countdown == 0)
        {
            break;
        }
    }
    *headp = next;
}

#endif

/** @brief Appends a list of database records to a list of nodes
 *
 * At the end
 * 
 * @param source a pointer to the ttlrdata to put into the node
 * @param name the owner of the record
 * @param zclass (if more than one class is supported in the database)
 * @param rtype the type of the record
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 5 uses
 */
static void
zdb_query_ex_answer_append(const zdb_packed_ttlrdata* source, const u8* label,
                           DECLARE_ZCLASS_PARAMETER
                           u16 type, zdb_resourcerecord** headp, u8 * restrict * pool)
{
    yassert(source != NULL);
    yassert(label != NULL);

    zdb_resourcerecord* next = *headp;
    zdb_resourcerecord* head = zdb_query_ex_answer_make(source, label,
                                                        PASS_ZCLASS_PARAMETER
                                                        type, pool);
    if(next != NULL)
    {
        while(next->next != NULL)
        {
            next = next->next;
        }
        next->next = head;
    }
    else
    {
        *headp = head;
    }
}

/** @brief Appends a list of database records to a list of nodes with a specific TTL
 *
 * At the end
 * 
 * @param source a pointer to the ttlrdata to put into the node
 * @param name the owner of the record
 * @param zclass (if more than one class is supported in the database)
 * @param rtype the type of the record
 * @param ttl the ttl of the record
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 16 uses
 */
static void
zdb_query_ex_answer_append_ttl(const zdb_packed_ttlrdata* source, const u8* label,
                               DECLARE_ZCLASS_PARAMETER
                               u16 rtype, u32 ttl, zdb_resourcerecord** headp, u8 * restrict * pool)
{
    yassert(source != NULL);
    yassert(label != NULL);

    zdb_resourcerecord* next = *headp;
    zdb_resourcerecord* head = zdb_query_ex_answer_make_ttl(source, label, 
                                                            PASS_ZCLASS_PARAMETER
                                                            rtype, ttl, pool);
    if(next != NULL)
    {
        while(next->next != NULL)       /* look for the last node */
        {
            next = next->next;
        }
        next->next = head;              /* set the value */
    }
    else
    {
        *headp = head;                  /* set the head */
    }
}

/** @brief Appends an RRSIG record set to a list of nodes with a specific TTL
 *
 * At the end
 * 
 * @param source a pointer to the ttlrdata to put into the node
 * @param name the owner of the record
 * @param zclass (if more than one class is supported in the database)
 * @param ttl the ttl of the record
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * @return a resource record suitable for network serialisation
 * 
 * 2 uses
 */
static inline void
zdb_query_ex_answer_append_rrsig(const zdb_packed_ttlrdata *source, const u8 *label,
                                 DECLARE_ZCLASS_PARAMETER
                                 u32 ttl, zdb_resourcerecord **headp, u8 * restrict * pool)
{
    zdb_query_ex_answer_append_ttl(source, label,
                                   PASS_ZCLASS_PARAMETER
                                   TYPE_RRSIG, ttl, headp, pool);
}
#if ZDB_HAS_DNSSEC_SUPPORT
/** @brief Appends the RRSIG rrset that covers the given type
 *
 * At the end
 * 
 * @param label the database label that owns the rrset
 * @param label_fqdn the owner of the records
 * @param zclass (if more than one class is supported in the database)
 * @param ttl the ttl of the record
 * @param headp a pointer to the section list
 * @param pool the memory pool
 * 
 * 20 uses
 */
static void
zdb_query_ex_answer_append_type_rrsigs(const zdb_rr_label *label, const u8 *label_fqdn, u16 rtype,
                                       DECLARE_ZCLASS_PARAMETER
                                       u32 ttl, zdb_resourcerecord **headp, u8 * restrict * pool)
{
    const zdb_packed_ttlrdata *type_rrsig = rrsig_find_first(label, rtype); // zone is locked

    while(type_rrsig != NULL)
    {
        zdb_query_ex_answer_append_rrsig(type_rrsig, label_fqdn, 
                                         PASS_ZCLASS_PARAMETER
                                         ttl, headp, pool);

        type_rrsig = rrsig_find_next(type_rrsig, rtype);
    }
}

/** @brief Appends the RRSIG rrset that covers the given type
 *
 * At the end
 * 
 * @param rrsig_list an RRSIG rrset to take the signatures from
 * @param label_fqdn the owner of the records
 * @param zclass (if more than one class is supported in the database)
 * @param ttl the ttl of the record
 * @param headp a pointer to the section list
 * @param pool the memory pool
 * 
 * 2 uses
 */
static void
zdb_query_ex_answer_append_type_rrsigs_from(const zdb_packed_ttlrdata *rrsig_list, const u8 *label_fqdn, u16 rtype,
                                            DECLARE_ZCLASS_PARAMETER
                                            u32 ttl, zdb_resourcerecord **headp, u8 * restrict * pool)
{
    const zdb_packed_ttlrdata *rrsig = rrsig_list;

    do
    {
        if(RRSIG_TYPE_COVERED(rrsig) == rtype)
        {
            zdb_query_ex_answer_append_rrsig(rrsig, label_fqdn, 
                                             PASS_ZCLASS_PARAMETER
                                             ttl, headp, pool);
        }

        rrsig = rrsig->next;
    } 
    while(rrsig != NULL);
}

#if ZDB_HAS_NSEC_SUPPORT

/** @brief Appends the NSEC interval for the given name
 *
 * At the end
 * 
 * @param zone the zone
 * @param name the name path
 * @param dups the label that cannot be added (used for wildcards)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 * 
 * 3 uses
 */
static void
zdb_query_ex_add_nsec_interval(const zdb_zone *zone, const dnsname_vector* name,
                               zdb_rr_label* dups, zdb_resourcerecord** headp,
                               u8 * restrict * pool)
{
    zdb_rr_label *nsec_interval_label;

    u8* nsec_dnsname = NULL;
    
    s32 min_ttl;

    if(zone->nsec.nsec == NULL)
    {
        return;
    }
    
    zdb_zone_getminttl(zone, &min_ttl);

    nsec_interval_label = nsec_find_interval(zone, name, &nsec_dnsname, pool);
    
    yassert(nsec_interval_label != NULL);

    if(/*(nsec_interval_label != NULL) && */(nsec_interval_label != dups))
    {
        zdb_packed_ttlrdata *nsec_interval_label_nsec = zdb_record_find(&nsec_interval_label->resource_record_set, TYPE_NSEC);

        if(nsec_interval_label_nsec != NULL)
        {
            zdb_packed_ttlrdata *nsec_interval_label_nsec_rrsig = rrsig_find_first(nsec_interval_label, TYPE_NSEC); // zone is locked
            
            if(nsec_interval_label_nsec_rrsig != NULL)
            {
                zdb_query_ex_answer_append_ttl(nsec_interval_label_nsec, nsec_dnsname,
                                            PASS_ZONE_ZCLASS_PARAMETER
                                            TYPE_NSEC, min_ttl, headp, pool);
                do
                {
                    zdb_query_ex_answer_append_ttl(nsec_interval_label_nsec_rrsig, nsec_dnsname,
                                                PASS_ZONE_ZCLASS_PARAMETER
                                                TYPE_RRSIG, min_ttl, headp, pool);

                    nsec_interval_label_nsec_rrsig = rrsig_find_next(nsec_interval_label_nsec_rrsig, TYPE_NSEC);
                }
                while(nsec_interval_label_nsec_rrsig != NULL);
            }
        }
    }
}
#endif // ZDB_HAS_NSEC_SUPPORT

#endif // ZDB_HAS_DNSSEC_SUPPORT

/** @brief Appends the SOA negative ttl record
 *
 * At the end
 *
 * @param zone the zone
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 3 uses
 */
static void
zdb_query_ex_answer_append_soa(const zdb_zone *zone, zdb_resourcerecord **headp,u8 * restrict * pool)
{
    yassert(zone != NULL);

    const u8* label_fqdn = zone->origin;
#if ZDB_RECORDS_MAX_CLASS != 1
    u16 zclass = zone->zclass;
#endif
    zdb_rr_collection* apex_records = &zone->apex->resource_record_set;
    zdb_packed_ttlrdata* zone_soa = zdb_record_find(apex_records, TYPE_SOA);

    if(zone_soa != NULL)
    {
        zdb_resourcerecord* next = *headp;

        s32 min_ttl;
        zdb_zone_getminttl(zone, &min_ttl);

        zdb_resourcerecord* node = zdb_query_ex_answer_make(zone_soa, label_fqdn,
                                                            PASS_ZCLASS_PARAMETER
                                                            TYPE_SOA, pool);

        if(next != NULL)
        {
            while(next->next != NULL)
            {
                next = next->next;
            }
            next->next = node;
        }
        else
        {
            *headp = node;
        }
    }
}

/** @brief Appends the SOA negative ttl record and its signature
 *
 * At the end
 *
 * @param zone the zone
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * @returns the negative ttl (minimum TTL is obsolete)
 *
 * 3 uses
 */

static void
zdb_query_ex_answer_append_soa_rrsig(const zdb_zone *zone, zdb_resourcerecord **headp, u8 * restrict * pool)
{
    yassert(zone != NULL);

    const u8 *label_fqdn = zone->origin;
#if ZDB_RECORDS_MAX_CLASS != 1
    u16 zclass = zone->zclass;
#endif
    zdb_rr_collection *apex_records = &zone->apex->resource_record_set;
    zdb_packed_ttlrdata *zone_soa = zdb_record_find(apex_records, TYPE_SOA);
    if(zone_soa != NULL)
    {
        zdb_resourcerecord* next = *headp;

        s32 min_ttl;
        zdb_zone_getminttl(zone, &min_ttl);

        zdb_resourcerecord* node = zdb_query_ex_answer_make(zone_soa, label_fqdn,
                                                            PASS_ZCLASS_PARAMETER
                                                            TYPE_SOA, pool);

        if(next != NULL)
        {
            while(next->next != NULL)
            {
                next = next->next;
            }
            next->next = node;
        }
        else
        {
            *headp = node;
        }

#if ZDB_HAS_DNSSEC_SUPPORT
#if ENFORCE_MINTTL
        zdb_query_ex_answer_append_type_rrsigs(zone->apex, label_fqdn, TYPE_SOA,
                                           PASS_ZCLASS_PARAMETER
                                           min_ttl, headp, pool);
#else
        zdb_query_ex_answer_append_type_rrsigs(zone->apex, label_fqdn, TYPE_SOA,
                                               PASS_ZCLASS_PARAMETER
                                               zone_soa->ttl, headp, pool);
#endif
#endif
    }
}

/** @brief Appends the SOA negative ttl record
 *
 * At the end
 * 
 * @param zone the zone
 * @param headp a pointer to the section list
 * @param pool the memory pool
 * 
 * 3 uses
 */
static void
zdb_query_ex_answer_append_soa_nttl(const zdb_zone *zone, zdb_resourcerecord **headp,u8 * restrict * pool)
{
    yassert(zone != NULL);
    
    const u8* label_fqdn = zone->origin;
#if ZDB_RECORDS_MAX_CLASS != 1
    u16 zclass = zone->zclass;
#endif
    zdb_rr_collection* apex_records = &zone->apex->resource_record_set;
    zdb_packed_ttlrdata* zone_soa = zdb_record_find(apex_records, TYPE_SOA);

    if(zone_soa != NULL)
    {
        zdb_resourcerecord* next = *headp;

        s32 min_ttl;
        zdb_zone_getminttl(zone, &min_ttl);

#if ENFORCE_MINTTL
        zdb_resourcerecord* node = zdb_query_ex_answer_make_ttl(zone_soa, label_fqdn,
                                                                PASS_ZCLASS_PARAMETER
                                                                TYPE_SOA, min_ttl, pool);
#else
        zdb_resourcerecord* node = zdb_query_ex_answer_make(zone_soa, label_fqdn,
                                                            PASS_ZCLASS_PARAMETER
                                                            TYPE_SOA, pool);
#endif
        if(next != NULL)
        {
            while(next->next != NULL)
            {
                next = next->next;
            }
            next->next = node;
        }
        else
        {
            *headp = node;
        }
    }
}

/** @brief Appends the SOA negative ttl record and its signature
 *
 * At the end
 * 
 * @param zone the zone
 * @param headp a pointer to the section list
 * @param pool the memory pool
 * 
 * @returns the negative ttl (minimum TTL is obsolete)
 * 
 * 3 uses
 */

static void
zdb_query_ex_answer_append_soa_rrsig_nttl(const zdb_zone *zone, zdb_resourcerecord **headp, u8 * restrict * pool)
{
    yassert(zone != NULL);

    const u8 *label_fqdn = zone->origin;
#if ZDB_RECORDS_MAX_CLASS != 1
    u16 zclass = zone->zclass;
#endif
    zdb_rr_collection *apex_records = &zone->apex->resource_record_set;
    zdb_packed_ttlrdata *zone_soa = zdb_record_find(apex_records, TYPE_SOA);
    if(zone_soa != NULL)
    {
        zdb_resourcerecord* next = *headp;

        s32 min_ttl;
        zdb_zone_getminttl(zone, &min_ttl);

#if ENFORCE_MINTTL
        zdb_resourcerecord* node = zdb_query_ex_answer_make_ttl(zone_soa, label_fqdn,
                                                                PASS_ZCLASS_PARAMETER
                                                                TYPE_SOA, min_ttl, pool);
#else
        zdb_resourcerecord* node = zdb_query_ex_answer_make(zone_soa, label_fqdn,
                                                            PASS_ZCLASS_PARAMETER
                                                            TYPE_SOA, pool);
#endif

        if(next != NULL)
        {
            while(next->next != NULL)
            {
                next = next->next;
            }
            next->next = node;
        }
        else
        {
            *headp = node;
        }

#if ZDB_HAS_DNSSEC_SUPPORT
#if ENFORCE_MINTTL
    zdb_query_ex_answer_append_type_rrsigs(zone->apex, label_fqdn, TYPE_SOA, 
                                           PASS_ZCLASS_PARAMETER
                                           min_ttl, headp, pool);
#else
    zdb_query_ex_answer_append_type_rrsigs(zone->apex, label_fqdn, TYPE_SOA,
                                           PASS_ZCLASS_PARAMETER
                                           zone_soa->ttl, headp, pool);
#endif
#endif
    }
}

#if 0
/** @brief Appends the SOA negative ttl record and its signature
 *
 * At the end
 *
 * @param zone the zone
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * @returns the negative ttl (minimum TTL is obsolete)
 *
 * 3 uses
 */

static void
zdb_query_ex_answer_append_soa_rrsig_ttl0(const zdb_zone *zone, zdb_resourcerecord **headp, u8 * restrict * pool)
{
    yassert(zone != NULL);

    const u8 *label_fqdn = zone->origin;
#if ZDB_RECORDS_MAX_CLASS != 1
    u16 zclass = zone->zclass;
#endif
    zdb_rr_collection *apex_records = &zone->apex->resource_record_set;
    zdb_packed_ttlrdata *zone_soa = zdb_record_find(apex_records, TYPE_SOA);
    if(zone_soa != NULL)
    {
        zdb_resourcerecord* next = *headp;

        s32 min_ttl;
        zdb_zone_getminttl(zone, &min_ttl);

        zdb_resourcerecord* node = zdb_query_ex_answer_make_ttl(zone_soa, label_fqdn,
                                                                PASS_ZCLASS_PARAMETER
                                                                TYPE_SOA, 0, pool);

        if(next != NULL)
        {
            while(next->next != NULL)
            {
                next = next->next;
            }
            next->next = node;
        }
        else
        {
            *headp = node;
        }

#if ZDB_HAS_DNSSEC_SUPPORT
        zdb_query_ex_answer_append_type_rrsigs(zone->apex, label_fqdn, TYPE_SOA,
                                               PASS_ZCLASS_PARAMETER
                                               0, headp, pool);
#endif
    }
}
#endif
/**
 * @brief Returns the label for the dns_name, relative to the apex of the zone
 * 
 * @param zone the zone
 * @param dns_name the name of the label to find
 * 
 * @return a pointer the label
 * 
 * 2 uses
 */

static zdb_rr_label*
zdb_query_rr_label_find_relative(const zdb_zone* zone, const u8* dns_name)
{
    /*
     * Get the relative path
     */

    const dnslabel_vector_reference origin = (const dnslabel_vector_reference)zone->origin_vector.labels;
    s32 origin_top = zone->origin_vector.size;

    dnslabel_vector name;
    s32 name_top = dnsname_to_dnslabel_vector(dns_name, name);
    if(name_top >= origin_top)
    {
        s32 i;

        for(i = 0; i <= origin_top; i++)
        {
            if(!dnslabel_equals(origin[origin_top - i], name[name_top - i]))
            {
                return NULL;
            }
        }

        /*
         * At this point we got the relative path, get the label
         *
         */

        zdb_rr_label* rr_label = zdb_rr_label_find(zone->apex, name, (name_top - origin_top) - 1);

        return rr_label;
    }
    else
    {
        return NULL;
    }
}

/**
 * @brief Appends all the IPs (A & AAAA) under a name on the given zone
 * 
 * @param zone the zone
 * @param dns_name the name of the label to find
 * @param zclass (if more than one class is supported in the database)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 * @param dnssec dnssec enabled or not
 * 
 * 1 use
 */

static inline void
zdb_query_ex_answer_append_ips(const zdb_zone* zone, const u8* dns_name,
                               DECLARE_ZCLASS_PARAMETER
                               zdb_resourcerecord** headp, u8 * restrict * pool, bool dnssec)
{
    /* Find relatively from the zone */
    yassert(dns_name != NULL);

    zdb_rr_label* rr_label = zdb_query_rr_label_find_relative(zone, dns_name);

    if(rr_label != NULL)
    {
        /* Get the label, instead of the type in the label */
        zdb_packed_ttlrdata* a = zdb_record_find(&rr_label->resource_record_set, TYPE_A);

        if(a != NULL)
        {
            zdb_query_ex_answer_appendlist(a, dns_name, 
                                           PASS_ZCLASS_PARAMETER
                                           TYPE_A, headp, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
            if(dnssec)
            {
                zdb_query_ex_answer_append_type_rrsigs(rr_label, dns_name, TYPE_A, 
                                                       PASS_ZCLASS_PARAMETER
                                                       a->ttl, headp, pool);
            }
#endif
        }

        zdb_packed_ttlrdata* aaaa = zdb_record_find(&rr_label->resource_record_set, TYPE_AAAA);

        if(aaaa != NULL)
        {
            zdb_query_ex_answer_appendlist(aaaa, dns_name, 
                                           PASS_ZCLASS_PARAMETER
                                           TYPE_AAAA, headp, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
            if(dnssec)
            {
                zdb_query_ex_answer_append_type_rrsigs(rr_label, dns_name, TYPE_AAAA, 
                                                       PASS_ZCLASS_PARAMETER
                                                       aaaa->ttl, headp, pool);
            }
#endif
        }
    }
}

/**
 * @brief Update a name set with the name found in an RDATA
 * 
 * @param source the record rdata containing the name to add
 * @param headp a pointer to the section list
 * @param rtype the type of the record
 * @param set collection where to add the name
 * 
 * 10 use
 */
static void
update_additionals_dname_set(const zdb_packed_ttlrdata* source,
                             DECLARE_ZCLASS_PARAMETER
                             u16 rtype, dnsname_set* set)
{
    if(source == NULL)
    {
        return;
    }

    u32 offset = 0;

    switch(rtype)
    {
        case TYPE_MX:
        {
            offset = 2;
        }
        FALLTHROUGH // fall through
        case TYPE_NS:
        {
            do
            {
                /* ADD NS "A/AAAA" TO ADDITIONAL  */

                const u8 *dns_name = ZDB_PACKEDRECORD_PTR_RDATAPTR(source);
                dns_name += offset;

                if(!dnsname_set_insert(set, dns_name))
                {
                    break;
                }

                source = source->next;
            }
            while(source != NULL);

            break;
        }
    }
}

/**
 * @brief Update a name set with the name found in an RDATA
 * 
 * @param zone
 * @param zclass (if more than one class is supported in the database)
 * @param set collection where to add the name
 * @param headp a pointer to the section list
 * @param pool the memory pool
 * @param dnssec dnssec enabled or not
 * 
 * 10 use
 */
static void
append_additionals_dname_set(const zdb_zone* zone,
                             DECLARE_ZCLASS_PARAMETER
                             dnsname_set* set, zdb_resourcerecord** headp, u8 * restrict * pool, bool dnssec)
{
    dnsname_set_iterator iter;

    dnsname_set_iterator_init(set, &iter);

    while(dnsname_set_iterator_hasnext(&iter))
    {
        /* ADD NS "A/AAAA" TO ADDITIONAL  */

        const u8* dns_name = dnsname_set_iterator_next_node(&iter)->key;

        zdb_query_ex_answer_append_ips(zone, dns_name,
                                       PASS_ZCLASS_PARAMETER
                                       headp, pool, dnssec);
    }
}

/**
 * @brief Appends NS records to a section
 * 
 * Appends NS records from the label to the referenced section
 * Also appends RRSIG for these NS
 * 
 * @param qname
 * @param rr_label_info
 * @param headp a pointer to the section list
 * @param pool the memory pool
 * @param dnssec dnssec enabled or not
 * 
 * 3 uses
 */
static zdb_packed_ttlrdata*
append_authority(const u8 * qname,
                 DECLARE_ZCLASS_PARAMETER
                 const zdb_rr_label_find_ext_data* rr_label_info, zdb_resourcerecord** headp, u8 * restrict * pool, bool dnssec)
{
    zdb_packed_ttlrdata* authority = zdb_record_find(&rr_label_info->authority->resource_record_set, TYPE_NS);

    if(authority != NULL)
    {
        s32 i = rr_label_info->authority_index;
        
        while(i > 0)
        {
            qname += qname[0] + 1;
            i--;
        }

        zdb_query_ex_answer_appendrndlist(authority, qname, 
                                       PASS_ZCLASS_PARAMETER
                                       TYPE_NS, headp, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
        if(dnssec)
        {
            zdb_query_ex_answer_append_type_rrsigs(rr_label_info->authority, qname, TYPE_NS, 
                                                   PASS_ZCLASS_PARAMETER
                                                   authority->ttl, headp, pool);
            
            zdb_packed_ttlrdata* dsset = zdb_record_find(&rr_label_info->authority->resource_record_set, TYPE_DS);
            
            if(dsset != NULL)
            {
                zdb_query_ex_answer_appendlist(dsset, qname, 
                                               PASS_ZCLASS_PARAMETER
                                               TYPE_DS, headp, pool);                
                zdb_query_ex_answer_append_type_rrsigs(rr_label_info->authority, qname, TYPE_DS, 
                                                       PASS_ZCLASS_PARAMETER
                                                       dsset->ttl, headp, pool);
            }
            
        }
#endif
    }

    return authority;
}
#if ZDB_HAS_NSEC3_SUPPORT

/**
 * @brief Appends the NSEC3 - NODATA answer to the section
 * 
 * @param zone the zone
 * @param rr_label the covered label
 * @param name the owner name
 * @param apex_index the index of the apex in the name
 * @param type the type of record required
 * @param zclass (if more than one class is supported in the database)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 * 
 * 2 uses
 */
static inline void
zdb_query_ex_append_nsec3_nodata(const zdb_zone *zone, const zdb_rr_label *rr_label,
                                 const dnsname_vector *name, s32 apex_index, u16 rtype,
                                 DECLARE_ZCLASS_PARAMETER
                                 zdb_resourcerecord** headp, u8 * restrict * pool)
{
    //nsec3_zone *n3 = zone->nsec.nsec3;

    u8 *nsec3_owner = NULL;
    u8 *closest_nsec3_owner = NULL;

    s32 min_ttl;
    zdb_zone_getminttl(zone, &min_ttl);

    zdb_packed_ttlrdata* nsec3 = NULL;
    const zdb_packed_ttlrdata* nsec3_rrsig;
    zdb_packed_ttlrdata* closest_nsec3;
    const zdb_packed_ttlrdata* closest_nsec3_rrsig;

    if(!IS_WILD_LABEL(rr_label->name))
    {
        if(rtype != TYPE_DS) // type is DS (7.2.3)
        {
            nsec3_nodata_error(zone, rr_label, name, apex_index,
                               pool,

                               &nsec3_owner,
                               &nsec3,
                               &nsec3_rrsig,

                               &closest_nsec3_owner,
                               &closest_nsec3,
                               &closest_nsec3_rrsig);
        }
        else // type is DS (7.2.4)
        {
            closest_nsec3 = NULL;
            closest_nsec3_rrsig = NULL;

            if((rr_label->nsec.dnssec != NULL)) // (7.2.3 a)
            {
                nsec3_zone_item *owner_nsec3 = nsec3_label_extension_self(rr_label->nsec.nsec3);
                nsec3_zone *n3 = zone->nsec.nsec3;

                if(owner_nsec3 != NULL)
                {
                    nsec3_zone_item_to_new_zdb_packed_ttlrdata_parm nsec3_parms =
                    {
                        n3,
                        owner_nsec3,
                        zone->origin,
                        pool,
                        min_ttl
                    };

                    nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                            &nsec3_parms,
                            &nsec3_owner,
                            &nsec3,
                            &nsec3_rrsig);
                }
            }
            else // (7.2.4 b)
            {
                //u8 *wild_closest_nsec3_owner = NULL;
                //zdb_packed_ttlrdata* wild_closest_nsec3 = NULL;
                //const zdb_packed_ttlrdata* wild_closest_nsec3_rrsig = NULL;

                /* closest encloser proof */
                nsec3_nodata_error(zone, rr_label, name, apex_index, pool,

                                        &nsec3_owner,
                                        &nsec3,
                                        &nsec3_rrsig,

                                        &closest_nsec3_owner,
                                        &closest_nsec3,
                                        &closest_nsec3_rrsig);

                if((nsec3 != NULL) && (nsec3_rrsig != NULL))
                {
#if DEBUG
                    log_debug("zdb-query: nsec3_nodata_error: nsec3_owner: %{dnsname}", nsec3_owner);
#endif
                    zdb_query_ex_answer_append_ttl(nsec3, nsec3_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, headp, pool);

                    zdb_query_ex_answer_appendlist_ttl(nsec3_rrsig, nsec3_owner,
                                                       PASS_ZCLASS_PARAMETER
                                                       TYPE_RRSIG, min_ttl, headp, pool);
                }
#if 0
                if((wild_closest_nsec3 != NULL) && (wild_closest_nsec3_rrsig != NULL))
                {
#if DEBUG
                    log_debug("zdb-query: nsec3_nodata_error: wild_closest_nsec3_owner: %{dnsname}", wild_closest_nsec3_owner);
#endif
                    zdb_query_ex_answer_append_ttl(wild_closest_nsec3, wild_closest_nsec3_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, headp, pool);

                    zdb_query_ex_answer_appendlist_ttl(wild_closest_nsec3_rrsig, wild_closest_nsec3_owner,
                                                       PASS_ZCLASS_PARAMETER
                                                       TYPE_RRSIG, min_ttl, headp, pool);
                }
#endif
                if((closest_nsec3 != NULL) && (closest_nsec3_owner != nsec3_owner) && (closest_nsec3_rrsig != NULL))
                {
#if DEBUG
                    log_debug("zdb-query: nsec3_nodata_error: closest_nsec3_owner: %{dnsname}", closest_nsec3_owner);
#endif
                    zdb_query_ex_answer_append_ttl(closest_nsec3, closest_nsec3_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, headp, pool);

                    zdb_query_ex_answer_appendlist_ttl(closest_nsec3_rrsig, closest_nsec3_owner,
                                                       PASS_ZCLASS_PARAMETER
                                                       TYPE_RRSIG, min_ttl, headp, pool);
                }

                return;
            }
        }
    }
    else
    {
        u8 *wild_closest_nsec3_owner = NULL;
        zdb_packed_ttlrdata* wild_closest_nsec3 = NULL;
        const zdb_packed_ttlrdata* wild_closest_nsec3_rrsig = NULL;

        nsec3_wild_nodata_error(zone, rr_label, name, apex_index, pool,

                                &nsec3_owner,
                                &nsec3,
                                &nsec3_rrsig,

                                &closest_nsec3_owner,
                                &closest_nsec3,
                                &closest_nsec3_rrsig,

                                &wild_closest_nsec3_owner,
                                &wild_closest_nsec3,
                                &wild_closest_nsec3_rrsig);

        if((wild_closest_nsec3 != NULL) && (wild_closest_nsec3_rrsig != NULL))
        {
#if DEBUG
            log_debug("zdb-query: nsec3_nodata_error: wild_closest_nsec3_owner: %{dnsname}", wild_closest_nsec3_owner);
#endif
            zdb_query_ex_answer_append_ttl(wild_closest_nsec3, wild_closest_nsec3_owner,
                                           PASS_ZCLASS_PARAMETER
                                           TYPE_NSEC3, min_ttl, headp, pool);
            zdb_query_ex_answer_appendlist_ttl(wild_closest_nsec3_rrsig, wild_closest_nsec3_owner,
                                               PASS_ZCLASS_PARAMETER
                                               TYPE_RRSIG, min_ttl, headp, pool);
        }
    }

    if((nsec3 != NULL) && (nsec3_rrsig != NULL))
    {
#if DEBUG
        log_debug("zdb-query: nsec3_nodata_error: nsec3_owner: %{dnsname}", nsec3_owner);
#endif

        /// @note part of the fix for https://github.com/yadifa/yadifa/issues/12

        bool delegation = zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_UNDERDELEGATION);
        bool allowed_under_delegation = (rtype == TYPE_ANY) || (rtype == TYPE_A) || (rtype == TYPE_AAAA);
        if(NSEC3_RDATA_IS_OPTOUT(ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3)) || (!delegation || (delegation && allowed_under_delegation)))
        {
            zdb_query_ex_answer_append_ttl(nsec3, nsec3_owner,
                                           PASS_ZCLASS_PARAMETER
                                           TYPE_NSEC3, min_ttl, headp, pool);

            zdb_query_ex_answer_appendlist_ttl(nsec3_rrsig, nsec3_owner,
                                               PASS_ZCLASS_PARAMETER
                                               TYPE_RRSIG, min_ttl, headp, pool);
        }
    }

    if((closest_nsec3 != NULL) && (closest_nsec3_rrsig != NULL))
    {
#if DEBUG
        log_debug("zdb-query: nsec3_nodata_error: closest_nsec3_owner: %{dnsname}", closest_nsec3_owner);
#endif
        zdb_query_ex_answer_append_ttl(closest_nsec3, closest_nsec3_owner,
                                       PASS_ZCLASS_PARAMETER
                                       TYPE_NSEC3, min_ttl, headp, pool);
        zdb_query_ex_answer_appendlist_ttl(closest_nsec3_rrsig, closest_nsec3_owner,
                                           PASS_ZCLASS_PARAMETER
                                           TYPE_RRSIG, min_ttl, headp, pool);
    }


}

/**
 * @brief Appends the wildcard NSEC3 - DATA answer to the section
 *
 * @param zone the zone
 * @param rr_label the covered label
 * @param name the owner name
 * @param apex_index the index of the apex in the name
 * @param zclass (if more than one class is supported in the database)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 2 uses
 */
static inline void
zdb_query_ex_append_wild_nsec3_data(const zdb_zone *zone, const zdb_rr_label *rr_label,
                                    const dnsname_vector *name, s32 apex_index,
                                    DECLARE_ZCLASS_PARAMETER
                                    zdb_resourcerecord** headp, u8 * restrict * pool)
{
    yassert(IS_WILD_LABEL(rr_label->name));

    //nsec3_zone *n3 = zone->nsec.nsec3;

    u8 *nsec3_owner = NULL;

    u8 *closest_nsec3_owner = NULL;

    u8 *qname_nsec3_owner = NULL;

    s32 min_ttl;
    zdb_zone_getminttl(zone, &min_ttl);

    zdb_packed_ttlrdata* nsec3 = NULL;
    const zdb_packed_ttlrdata* nsec3_rrsig;

    zdb_packed_ttlrdata* closest_nsec3 = NULL;
    const zdb_packed_ttlrdata* closest_nsec3_rrsig;

    zdb_packed_ttlrdata* qname_nsec3 = NULL;
    const zdb_packed_ttlrdata* qname_nsec3_rrsig;

    nsec3_wild_nodata_error(zone, rr_label, name, apex_index, pool,

                            &nsec3_owner,
                            &nsec3,
                            &nsec3_rrsig,

                            &closest_nsec3_owner,
                            &closest_nsec3,
                            &closest_nsec3_rrsig,

                            &qname_nsec3_owner,
                            &qname_nsec3,
                            &qname_nsec3_rrsig
                            );


#if 1
    if((qname_nsec3 != NULL) && (qname_nsec3_rrsig != NULL))
    {
#if DEBUG
        log_debug("zdb-query: nsec3_nodata_error: qname_nsec3_owner: %{dnsname}", qname_nsec3_owner);
#endif
        zdb_query_ex_answer_append_ttl(qname_nsec3, qname_nsec3_owner,
                                       PASS_ZCLASS_PARAMETER
                                       TYPE_NSEC3, min_ttl, headp, pool);
        zdb_query_ex_answer_appendlist_ttl(qname_nsec3_rrsig, qname_nsec3_owner,
                                           PASS_ZCLASS_PARAMETER
                                           TYPE_RRSIG, min_ttl, headp, pool);
    }
#endif
}

/**
 * @brief Appends the NSEC3 delegation answer to the section
 *
 * @param zone the zone
 * @param rr_label the covered label
 * @param name the owner name
 * @param apex_index the index of the apex in the name
 * @param zclass (if more than one class is supported in the database)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 3 uses
 */
static inline void
zdb_query_ex_append_nsec3_delegation(const zdb_zone *zone, const zdb_rr_label_find_ext_data *rr_label_info,
                                     const dnsname_vector *name, s32 apex_index,
                                     DECLARE_ZCLASS_PARAMETER
                                     zdb_resourcerecord **headp, u8 * restrict * pool)
{
    zdb_rr_label *authority = rr_label_info->authority;

    s32 min_ttl;
    zdb_zone_getminttl(zone, &min_ttl);

    if((authority->nsec.nsec3 != NULL) && (nsec3_label_extension_self(authority->nsec.nsec3) != NULL))
    {
        /* add it */

        u8 *authority_nsec3_owner = NULL;

        nsec3_zone *n3 = zone->nsec.nsec3;
        zdb_packed_ttlrdata *authority_nsec3;
        const zdb_packed_ttlrdata *authority_nsec3_rrsig;

        nsec3_zone_item_to_new_zdb_packed_ttlrdata_parm nsec3_parms =
        {
            n3,
            nsec3_label_extension_self(authority->nsec.nsec3),
            zone->origin,
            pool,
            min_ttl
        };

        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                &nsec3_parms,
                &authority_nsec3_owner,
                &authority_nsec3,
                &authority_nsec3_rrsig);

        zdb_query_ex_answer_append_ttl(authority_nsec3, authority_nsec3_owner,
                                       PASS_ZCLASS_PARAMETER
                                       TYPE_NSEC3, min_ttl, headp, pool);

        if(authority_nsec3_rrsig != NULL)
        {
            zdb_query_ex_answer_appendlist_ttl(authority_nsec3_rrsig, authority_nsec3_owner,
                                               PASS_ZCLASS_PARAMETER
                                               TYPE_RRSIG, min_ttl, headp, pool);
        }
    }
    else
    {
        // add closest provable encloser proof

        zdb_query_ex_append_nsec3_nodata(zone, authority, name, apex_index, 0,
                                         PASS_ZCLASS_PARAMETER
                                         headp, pool);
    }
}
#endif
#if ZDB_HAS_NSEC_SUPPORT

/**
 * @brief Appends the NSEC records of a label to the section
 *
 * @param rr_label the covered label
 * @param qname the owner name
 * @param min_ttl the minimum ttl (OBSOLETE)
 * @param zclass (if more than one class is supported in the database)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 2 uses
 */
static inline void
zdb_query_ex_append_nsec_records(const zdb_rr_label *rr_label, const u8 * restrict qname, u32 min_ttl,
                                 DECLARE_ZCLASS_PARAMETER
                                 zdb_resourcerecord **headp, u8 * restrict * pool)
{
    (void)min_ttl;

    zdb_packed_ttlrdata *rr_label_nsec_record = zdb_record_find(&rr_label->resource_record_set, TYPE_NSEC);

    if(rr_label_nsec_record != NULL)
    {
        zdb_query_ex_answer_append(rr_label_nsec_record, qname,
                                   PASS_ZCLASS_PARAMETER
                                   TYPE_NSEC, headp, pool);
        zdb_query_ex_answer_append_type_rrsigs(rr_label, qname, TYPE_NSEC,
                                               PASS_ZCLASS_PARAMETER
                                               rr_label_nsec_record->ttl, headp, pool);
    }
}
#endif

/** @brief Destroys a zdb_resourcerecord* single linked list.
 *
 *  Destroys a zdb_resourcerecord* single linked list created by a zdb_query*
 *
 *  @param[in]  rr the head of the sll.
 *
 * 3 uses
 */

void
zdb_destroy_resourcerecord_list(zdb_resourcerecord *rr)
{
    (void)rr;
}

/**
 * @brief Handles what to do when a record has not been found (NXRRSET)
 *
 * @param zone the zone
 * @param rr_label_info details about the labels on the path of the query
 * @param qname name of the query
 * @param name name of the query (vector)
 * @param sp index of the label in the name (vector)
 * @param top
 * @param type
 * @param zclass (if more than one class is supported in the database)
 * @param ans_auth_add a pointer to the section list
 * @param pool the memory pool
 * @param additionals_dname_set
 *
 * 3 uses
 */
static inline ya_result
zdb_query_ex_record_not_found(const zdb_zone *zone,
                              const zdb_rr_label_find_ext_data *rr_label_info,
                              const u8* qname,
                              const dnsname_vector *name,
                              s32 sp_label_index,
                              s32 top,
                              u16 type,
                              DECLARE_ZCLASS_PARAMETER
                              u8 * restrict * pool,
                              bool dnssec,
                              zdb_query_ex_answer *ans_auth_add,
                              dnsname_set *additionals_dname_set)
{
    zdb_rr_label *rr_label = rr_label_info->answer;

    // NXRRSET

#if ZDB_HAS_NSEC3_SUPPORT
    if(dnssec && ZONE_NSEC3_AVAILABLE(zone))
    {
        zdb_packed_ttlrdata *zone_soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);

        s32 min_ttl;
        zdb_zone_getminttl(zone, &min_ttl);

        if( ((type == TYPE_DS) && (zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_UNDERDELEGATION)))    ||
            ((type != TYPE_DS) && (zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION))) )
        {
            /*
             * Add all the NS and their signature
             */
            zdb_rr_label *authority = rr_label_info->authority;
            zdb_packed_ttlrdata* rr_label_ns = zdb_record_find(&authority->resource_record_set, TYPE_NS);

            if(rr_label_ns != NULL)
            {
                const u8* auth_name = name->labels[rr_label_info->authority_index];

                zdb_query_ex_answer_appendlist(rr_label_ns, auth_name,
                                               PASS_ZCLASS_PARAMETER
                                               TYPE_NS, &ans_auth_add->authority, pool);
                zdb_query_ex_answer_append_type_rrsigs(rr_label, auth_name,
                                                       PASS_ZCLASS_PARAMETER
                                                       TYPE_NS, rr_label_ns->ttl, &ans_auth_add->authority, pool);

                update_additionals_dname_set(rr_label_ns,
                                             PASS_ZCLASS_PARAMETER
                                             TYPE_NS, additionals_dname_set);

                append_additionals_dname_set(zone,
                                             PASS_ZCLASS_PARAMETER
                                             additionals_dname_set, &ans_auth_add->additional, pool, FALSE);

                zdb_packed_ttlrdata* label_ds = zdb_record_find(&authority->resource_record_set, TYPE_DS);

                if(label_ds != NULL)
                {
                    zdb_query_ex_answer_appendlist(label_ds, auth_name,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_DS, &ans_auth_add->authority, pool);
                    zdb_query_ex_answer_append_type_rrsigs(authority, auth_name, TYPE_DS,
                                                           PASS_ZCLASS_PARAMETER
                                                           label_ds->ttl, &ans_auth_add->authority, pool);

                    /* ans_auth_add->is_delegation = TRUE; later */

                    return FP_BASIC_RECORD_NOTFOUND;
                }
            }
        }
        else
        {
            zdb_query_ex_answer_append_ttl(zone_soa, zone->origin,
                                           PASS_ZCLASS_PARAMETER
                                           TYPE_SOA, min_ttl, &ans_auth_add->authority, pool);
            zdb_query_ex_answer_append_type_rrsigs(zone->apex, zone->origin, TYPE_SOA,
                                                   PASS_ZCLASS_PARAMETER
                                                   min_ttl, &ans_auth_add->authority, pool);
        }

        if(type != 0)
        {
            zdb_query_ex_append_nsec3_nodata(zone, rr_label, name, top, type,
                                             PASS_ZCLASS_PARAMETER
                                             &ans_auth_add->authority, pool);
        }
        else
        {
            /*
                * If there is an NSEC3 RR that matches the delegation name, then that
                * NSEC3 RR MUST be included in the response.  The DS bit in the type
                * bit maps of the NSEC3 RR MUST NOT be set.
                *
                * If the zone is Opt-Out, then there may not be an NSEC3 RR
                * corresponding to the delegation.  In this case, the closest provable
                * encloser proof MUST be included in the response.  The included NSEC3
                * RR that covers the "next closer" name for the delegation MUST have
                * the Opt-Out flag set to one.  (Note that this will be the case unless
                * something has gone wrong).
                */

            zdb_query_ex_append_nsec3_delegation(zone, rr_label_info, name, top,
                                                 PASS_ZCLASS_PARAMETER
                                                 &ans_auth_add->authority, pool);
        }
#if DEBUG
        log_debug("zdb-query: FP_NSEC3_RECORD_NOTFOUND (NSEC3)");
#endif
        return FP_NSEC3_RECORD_NOTFOUND;
    }
    else    /* We had the label, not the record, it's not NSEC3 : */
#endif
    {
        /** Got label but no record : show the authority
         *  AA
         */

        if(zdb_rr_label_is_not_apex(rr_label_info->authority))
        {
            zdb_packed_ttlrdata* authority;

            if( (
                    ((type == TYPE_DS) && zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_UNDERDELEGATION)) ||
                    ((type != TYPE_DS) && zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION))
                )
                &&
                (
                    ((authority = zdb_record_find(&rr_label_info->authority->resource_record_set, TYPE_NS)) != NULL)
                ) )
            {
                const u8* auth_name = name->labels[rr_label_info->authority_index];

                zdb_query_ex_answer_appendrndlist(authority, auth_name,
                                                  PASS_ZCLASS_PARAMETER
                                                  TYPE_NS, &ans_auth_add->authority, pool);

                update_additionals_dname_set(authority,
                                             PASS_ZCLASS_PARAMETER
                                             TYPE_NS, additionals_dname_set);
                append_additionals_dname_set(zone,
                                             PASS_ZCLASS_PARAMETER
                                             additionals_dname_set, &ans_auth_add->additional, pool, FALSE);

                /* ans_auth_add->is_delegation = TRUE; later */
            }
            else
            {
                /* append the SOA */

                if(!dnssec)
                {
                    zdb_query_ex_answer_append_soa(zone, &ans_auth_add->authority, pool);
                }
                else
                {
                    zdb_query_ex_answer_append_soa_rrsig(zone, &ans_auth_add->authority, pool);
                }
            }
        }
        else // apex
        {
            /* append the SOA */

            if(!dnssec)
            {
                zdb_query_ex_answer_append_soa(zone, &ans_auth_add->authority, pool);
            }
            else
            {
                zdb_query_ex_answer_append_soa_rrsig(zone, &ans_auth_add->authority, pool);
            }
        }
#if ZDB_HAS_NSEC_SUPPORT
        if(dnssec && ZONE_NSEC_AVAILABLE(zone))
        {
            zdb_rr_label* rr_label_authority = rr_label_info->authority;
            zdb_packed_ttlrdata *delegation_signer = zdb_record_find(&rr_label_authority->resource_record_set, TYPE_DS);

            if(delegation_signer != NULL)
            {
                const u8 * authority_qname = zdb_rr_label_info_get_authority_qname(qname, rr_label_info);

                zdb_query_ex_answer_appendlist(delegation_signer , authority_qname,
                                               PASS_ZCLASS_PARAMETER
                                               TYPE_DS, &ans_auth_add->authority, pool);
                zdb_query_ex_answer_append_type_rrsigs(rr_label_authority, authority_qname, TYPE_DS,
                                                       PASS_ZCLASS_PARAMETER
                                                       delegation_signer->ttl, &ans_auth_add->authority, pool);
            }
            else
            {
                u8 *wild_name = (u8*)qname;

                if(IS_WILD_LABEL(rr_label->name))
                {
                    wild_name = *pool;
                    *pool += ALIGN16(MAX_DOMAIN_LENGTH + 2);
                    wild_name[0] = 1;
                    wild_name[1] = (u8)'*';
                    dnslabel_vector_to_dnsname(&name->labels[name->size - sp_label_index], sp_label_index, &wild_name[2]);
                }

                zdb_packed_ttlrdata *rr_label_nsec_record = zdb_record_find(&rr_label->resource_record_set, TYPE_NSEC);

                if(rr_label_nsec_record != NULL)
                {
                    zdb_query_ex_answer_append(rr_label_nsec_record, wild_name,
                                               PASS_ZCLASS_PARAMETER
                                               TYPE_NSEC, &ans_auth_add->authority, pool);
                    zdb_query_ex_answer_append_type_rrsigs(rr_label, wild_name, TYPE_NSEC,
                                                           PASS_ZCLASS_PARAMETER
                                                           rr_label_nsec_record->ttl, &ans_auth_add->authority, pool);
                }

                zdb_query_ex_add_nsec_interval(zone, name, rr_label, &ans_auth_add->authority, pool);
            }

        }
#endif
    }

    return FP_BASIC_RECORD_NOTFOUND;
}

/**
 * @brief Handles what to do when a record has not been found (NXRRSET)
 *
 * @param zone the zone
 * @param rr_label_info details about the labels on the path of the query
 * @param qname name of the query
 * @param name name of the query (vector)
 * @param sp index of the label in the name (vector)
 * @param top
 * @param type
 * @param zclass (if more than one class is supported in the database)
 * @param ans_auth_add a pointer to the section list
 * @param pool the memory pool
 * @param additionals_dname_set
 *
 * 3 uses
 */
static inline ya_result
zdb_query_ex_record_not_found_nttl(const zdb_zone *zone,
                              const zdb_rr_label_find_ext_data *rr_label_info,
                              const u8* qname,
                              const dnsname_vector *name,
                              s32 sp_label_index,
                              s32 top,
                              u16 type,
                              DECLARE_ZCLASS_PARAMETER
                              u8 * restrict * pool,
                              bool dnssec,
                              zdb_query_ex_answer *ans_auth_add,
                              dnsname_set *additionals_dname_set)
{
    zdb_rr_label *rr_label = rr_label_info->answer;

    // NXRRSET
#if ZDB_HAS_NSEC3_SUPPORT
    if(dnssec && ZONE_NSEC3_AVAILABLE(zone))
    {
        zdb_packed_ttlrdata *zone_soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);

        s32 min_ttl;
        zdb_zone_getminttl(zone, &min_ttl);

        if( ((type == TYPE_DS) && (zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_UNDERDELEGATION)))    ||
            ((type != TYPE_DS) && (zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION))) )
        {
            /*
                * Add all the NS and their signature
                */
            zdb_rr_label *authority = rr_label_info->authority;
            zdb_packed_ttlrdata* rr_label_ns = zdb_record_find(&authority->resource_record_set, TYPE_NS);

            if(rr_label_ns != NULL)
            {
                const u8* auth_name = name->labels[rr_label_info->authority_index];

                zdb_query_ex_answer_appendlist(rr_label_ns, auth_name,
                                               PASS_ZCLASS_PARAMETER
                                               TYPE_NS, &ans_auth_add->authority, pool);
                zdb_query_ex_answer_append_type_rrsigs(rr_label, auth_name,
                                                       PASS_ZCLASS_PARAMETER
                                                       TYPE_NS, rr_label_ns->ttl, &ans_auth_add->authority, pool);

                update_additionals_dname_set(rr_label_ns,
                                             PASS_ZCLASS_PARAMETER
                                             TYPE_NS, additionals_dname_set);

                append_additionals_dname_set(zone,
                                             PASS_ZCLASS_PARAMETER
                                             additionals_dname_set, &ans_auth_add->additional, pool, FALSE);

                zdb_packed_ttlrdata* label_ds = zdb_record_find(&authority->resource_record_set, TYPE_DS);

                if(label_ds != NULL)
                {
                    zdb_query_ex_answer_appendlist(label_ds, auth_name,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_DS, &ans_auth_add->authority, pool);
                    zdb_query_ex_answer_append_type_rrsigs(authority, auth_name, TYPE_DS,
                                                           PASS_ZCLASS_PARAMETER
                                                           label_ds->ttl, &ans_auth_add->authority, pool);

                    /* ans_auth_add->is_delegation = TRUE; later */

                    return FP_BASIC_RECORD_NOTFOUND;
                }
            }
        }
        else
        {
            zdb_query_ex_answer_append_ttl(zone_soa, zone->origin,
                                           PASS_ZCLASS_PARAMETER
                                           TYPE_SOA, min_ttl, &ans_auth_add->authority, pool);
            zdb_query_ex_answer_append_type_rrsigs(zone->apex, zone->origin, TYPE_SOA,
                                                   PASS_ZCLASS_PARAMETER
                                                   min_ttl, &ans_auth_add->authority, pool);
        }

        if(type != 0)
        {
            zdb_query_ex_append_nsec3_nodata(zone, rr_label, name, top, type,
                                             PASS_ZCLASS_PARAMETER
                                             &ans_auth_add->authority, pool);
        }
        else
        {
            /*
                * If there is an NSEC3 RR that matches the delegation name, then that
                * NSEC3 RR MUST be included in the response.  The DS bit in the type
                * bit maps of the NSEC3 RR MUST NOT be set.
                *
                * If the zone is Opt-Out, then there may not be an NSEC3 RR
                * corresponding to the delegation.  In this case, the closest provable
                * encloser proof MUST be included in the response.  The included NSEC3
                * RR that covers the "next closer" name for the delegation MUST have
                * the Opt-Out flag set to one.  (Note that this will be the case unless
                * something has gone wrong).
                */

            zdb_query_ex_append_nsec3_delegation(zone, rr_label_info, name, top,
                                                 PASS_ZCLASS_PARAMETER
                                                 &ans_auth_add->authority, pool);
        }
#if DEBUG
        log_debug("zdb-query: FP_NSEC3_RECORD_NOTFOUND (NSEC3)");
#endif
        return FP_NSEC3_RECORD_NOTFOUND;
    }
    else    /* We had the label, not the record, it's not NSEC3 : */
#endif
    {
        /** Got label but no record : show the authority
         *  AA
         */

        if(zdb_rr_label_is_not_apex(rr_label_info->authority))
        {
            zdb_packed_ttlrdata* authority;

            if( (
                    ((type == TYPE_DS) && zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_UNDERDELEGATION)) ||
                    ((type != TYPE_DS) && zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION))
                )
                &&
                (
                    ((authority = zdb_record_find(&rr_label_info->authority->resource_record_set, TYPE_NS)) != NULL)
                ) )
            {
                const u8* auth_name = name->labels[rr_label_info->authority_index];

                zdb_query_ex_answer_appendrndlist(authority, auth_name,
                                                  PASS_ZCLASS_PARAMETER
                                                  TYPE_NS, &ans_auth_add->authority, pool);

                update_additionals_dname_set(authority,
                                             PASS_ZCLASS_PARAMETER
                                             TYPE_NS, additionals_dname_set);
                append_additionals_dname_set(zone,
                                             PASS_ZCLASS_PARAMETER
                                             additionals_dname_set, &ans_auth_add->additional, pool, FALSE);

                /* ans_auth_add->is_delegation = TRUE; later */
            }
            else
            {
                /* append the SOA */

                if(!dnssec)
                {
                    zdb_query_ex_answer_append_soa_nttl(zone, &ans_auth_add->authority, pool);
                }
                else
                {
                    zdb_query_ex_answer_append_soa_rrsig_nttl(zone, &ans_auth_add->authority, pool);
                }
            }
        }
        else // apex
        {
            /* append the SOA */

            if(!dnssec)
            {
                zdb_query_ex_answer_append_soa_nttl(zone, &ans_auth_add->authority, pool);
            }
            else
            {
                zdb_query_ex_answer_append_soa_rrsig_nttl(zone, &ans_auth_add->authority, pool);
            }
        }
#if ZDB_HAS_NSEC_SUPPORT
        if(dnssec && ZONE_NSEC_AVAILABLE(zone))
        {
            zdb_rr_label* rr_label_authority = rr_label_info->authority;
            zdb_packed_ttlrdata *delegation_signer = zdb_record_find(&rr_label_authority->resource_record_set, TYPE_DS);

            if(delegation_signer != NULL)
            {
                const u8 * authority_qname = zdb_rr_label_info_get_authority_qname(qname, rr_label_info);

                zdb_query_ex_answer_appendlist(delegation_signer , authority_qname,
                                               PASS_ZCLASS_PARAMETER
                                               TYPE_DS, &ans_auth_add->authority, pool);
                zdb_query_ex_answer_append_type_rrsigs(rr_label_authority, authority_qname, TYPE_DS,
                                                       PASS_ZCLASS_PARAMETER
                                                       delegation_signer->ttl, &ans_auth_add->authority, pool);
            }
            else
            {
                u8 *wild_name = (u8*)qname;

                if(IS_WILD_LABEL(rr_label->name))
                {
                    wild_name = *pool;
                    *pool += ALIGN16(MAX_DOMAIN_LENGTH + 2);
                    wild_name[0] = 1;
                    wild_name[1] = (u8)'*';
                    dnslabel_vector_to_dnsname(&name->labels[name->size - sp_label_index], sp_label_index, &wild_name[2]);
                }

                zdb_packed_ttlrdata *rr_label_nsec_record = zdb_record_find(&rr_label->resource_record_set, TYPE_NSEC);

                if(rr_label_nsec_record != NULL)
                {
                    zdb_query_ex_answer_append(rr_label_nsec_record, wild_name,
                                               PASS_ZCLASS_PARAMETER
                                               TYPE_NSEC, &ans_auth_add->authority, pool);
                    zdb_query_ex_answer_append_type_rrsigs(rr_label, wild_name, TYPE_NSEC,
                                                           PASS_ZCLASS_PARAMETER
                                                           rr_label_nsec_record->ttl, &ans_auth_add->authority, pool);
                }

                zdb_query_ex_add_nsec_interval(zone, name, rr_label, &ans_auth_add->authority, pool);
            }

        }
#endif
    }

    return FP_BASIC_RECORD_NOTFOUND;
}

/**
 * @brief destroys an answer made by zdb_query*
 *
 * @param ans_auth_add a pointer to the answer structure
 *
 */
#ifndef zdb_query_ex_answer_destroy

void
zdb_query_ex_answer_destroy(zdb_query_ex_answer* ans_auth_add)
{
    zdb_destroy_resourcerecord_list(ans_auth_add->answer);
    ans_auth_add->answer = NULL;
    zdb_destroy_resourcerecord_list(ans_auth_add->authority);
    ans_auth_add->authority = NULL;
    zdb_destroy_resourcerecord_list(ans_auth_add->additional);
    ans_auth_add->additional = NULL;
}
#endif


/**
 * @brief Queries the database given a message
 *
 * @param db the database
 * @param mesg the message
 * @param ans_auth_add the structure that will contain the sections of the answer
 * @param pool_buffer a big enough buffer used for the memory pool
 *
 * @return the status of the message (probably useless)
 */

static finger_print
zdb_query_from_cname(zdb *db, message_data *mesg, zdb_query_ex_answer *ans_auth_add, zdb_zone *in_zone, u8 * restrict pool_buffer)
{
    yassert(ans_auth_add != NULL);

    //const u8 * restrict qname = message_get_canonised_fqdn(mesg);
    const u8 *qname = message_get_canonised_fqdn(mesg);
#if ZDB_RECORDS_MAX_CLASS != 1
    const u16 zclass = message_get_query_class(mesg);
#endif

    zdb_rr_label_find_ext_data rr_label_info;

    u16 type = message_get_query_type(mesg);
    const process_flags_t flags = zdb_query_process_flags;

    /** Check that we are even allowed to handle that class */
#if ZDB_RECORDS_MAX_CLASS == 1
    if(message_get_query_class(mesg) != CLASS_IN)
    {
#if DEBUG
        log_debug("zdb-query-cname: FP_CLASS_NOTFOUND");
#endif
        return FP_CLASS_NOTFOUND;
    }
#endif
#if HAS_DYNAMIC_PROVISIONING
    zdb_lock(db, ZDB_MUTEX_READER);
#endif
#if ZDB_RECORDS_MAX_CLASS != 1
    u16 host_zclass = ntohs(zclass); /* no choice */
    if(host_zclass > ZDB_RECORDS_MAX_CLASS)
    {
        return; // FP_CLASS_NOTFOUND;
    }
#endif

    bool dnssec = message_has_rcode_ext_dnssec(mesg);

    /**
     *  MANDATORY, INITIALISES A LOCAL MEMORY POOL
     *
     *  This is actually a macro found in dnsname_set.h
     */

    dnsname_vector name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(qname, &name);

    u8 * restrict * pool = &pool_buffer;

    /*
     * Find closest matching label
     * Should return a stack of zones
     */

    zdb_zone_label_pointer_array zone_label_stack;

    s32 top = zdb_zone_label_match(db, &name, zone_label_stack); // value returned >= 0

    s32 sp = top; // top >=0 => sp >= 0

    zdb_packed_ttlrdata* answer;

    /* This flag means that there HAS to be an authority section */

    bool authority_required = flags & PROCESS_FL_AUTHORITY_AUTH;

    /* This flag means the names in the authority must be (internally) resolved if possible */

    bool additionals_required = flags & PROCESS_FL_ADDITIONAL_AUTH;

    switch(type)
    {
        case TYPE_A:
        case TYPE_AAAA:
        case TYPE_DNSKEY:
        {
            authority_required = FALSE;
            additionals_required = FALSE;
            break;
        }
    }

    /* Got a stack of zone labels with and without zone cuts */
    /* Search the label on the zone files */

    /* While we have labels along the path */

    if(type == TYPE_DS)         // This is the only type that can only be found outside of the zone
    {                           // In order to avoid to hit said zone, I skip the last label.
        if(name.size == sp - 1) // we have a perfect match (DS for an APEX), try to get outside ...
        {
            s32 parent_sp = sp;

            while(--parent_sp >= 0)
            {
                /* Get the "bottom" label (top being ".") */

                zdb_zone_label* zone_label = zone_label_stack[parent_sp];

                /* Is there a zone file at this level ? If yes, search into it. */

                if(zone_label->zone != NULL)
                {
                    // got it.
                    sp = parent_sp;
                    message_set_authoritative(mesg);
                    break;
                }
            }

            authority_required = FALSE;
        }
    }

    bool outside_of_zone = TRUE;

    while(sp >= 0)
    {
        /* Get the "bottom" label (top being ".") */

        zdb_zone_label* zone_label = zone_label_stack[sp];

        /* Is there a zone file at this level ? If yes, search into it. */

        if(zone_label->zone == in_zone)
        {
            outside_of_zone = FALSE;

            zdb_zone *zone = zone_label->zone;

            /*
             * lock
             */

            LOCK(zone);

#if DEBUG
            log_debug("zdb-query-cname: zone %{dnsname}, flags=%x", zone->origin, zdb_rr_label_flag_get(zone->apex));
#endif

            /*
             * We know the zone, and its extension here ...
             */

            {
                /*
                 * Filter handling (ACL)
                 * NOTE: the return code has to be fingerprint-based
                 */

                if(FAIL(zone->query_access_filter(mesg, zone->acl)))
                {
#if DEBUG
                    log_debug("zdb-query-cname: FP_ACCESS_REJECTED");
#endif
                    UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                    zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                    return FP_ACCESS_REJECTED;
                }
            }

            /**
             * The ACL have been passed so ... now check that the zone is valid
             */

            if(zdb_zone_invalid(zone))
            {
                /**
                 * @note the blocks could be reversed and jump if the zone is invalid (help the branch prediction)
                 */
#if DEBUG
                log_debug("zdb-query-cname: FP_ZONE_EXPIRED");
#endif

                UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                return FP_INVALID_ZONE;
            }

            //message_set_authoritative(mesg);

            dnsname_set additionals_dname_set;
            dnsname_set_init(&additionals_dname_set);

            /*
             * In one query, get the authority and the closest (longest) path to the domain we are looking for.
             */

            zdb_rr_label *rr_label = zdb_rr_label_find_ext(zone->apex, name.labels, name.size - sp, &rr_label_info);

            /* Has a label been found ? */

            if(rr_label != NULL)
            {
                /*
                 * Got the label.  I will not find anything relevant by going
                 * up to another zone file.
                 *
                 * We set the AA bit iff we are not at or under a delegation.
                 *
                 * The ZDB_RR_LABEL_DELEGATION flag means the label is a delegation.
                 * This means that it only contains NS & DNSSEC records + may have sub-labels for glues
                 *
                 * ZDB_RR_LABEL_UNDERDELEGATION means we are below a ZDB_RR_LABEL_DELEGATION label
                 *
                 */

                /*
                 * CNAME alias handling
                 */

                // if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_HASCNAME) && (type != TYPE_CNAME) && (type != TYPE_ANY))
                if(((zdb_rr_label_flag_get(rr_label) & (ZDB_RR_LABEL_HASCNAME|ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION)) == ZDB_RR_LABEL_HASCNAME) &&
                    (type != TYPE_CNAME) && (type != TYPE_ANY) && (type != TYPE_RRSIG))
                {
                    /*
                    * The label is an alias:
                    *
                    * Add the CNAME and restart the query from the alias
                    */

                    if(ans_auth_add->depth >= ZDB_CNAME_LOOP_MAX)
                    {
                        log_warn("CNAME depth at %{dnsname} is bigger than allowed %d>=%d", qname, ans_auth_add->depth, ZDB_CNAME_LOOP_MAX);

                        message_set_authoritative(mesg);

                        UNLOCK(zone);

                        // stop there
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return FP_CNAME_MAXIMUM_DEPTH;
                    }

                    ans_auth_add->depth++;

                    if((answer = zdb_record_find(&rr_label->resource_record_set, TYPE_CNAME)) != NULL)
                    {
                        /* The RDATA in answer is the fqdn to a label with an A record (list) */
                        /* There can only be one cname for a given owner */
                        /* Append all A/AAAA records associated to the CNAME AFTER the CNAME record */

                        zdb_resourcerecord *rr = ans_auth_add->answer;

                        u32 cname_depth_count = 0; /* I don't want to allocate that globally for now */

                        while(rr != NULL)
                        {
                            if((rr->rtype == TYPE_CNAME) && (ZDB_PACKEDRECORD_PTR_RDATAPTR(rr->ttl_rdata) == ZDB_PACKEDRECORD_PTR_RDATAPTR(answer)))
                            {
                                /* LOOP */

                                log_warn("CNAME loop at %{dnsname}", qname);

                                message_set_authoritative(mesg);
#if HAS_DYNAMIC_PROVISIONING
                                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                                return FP_CNAME_LOOP;
                            }

                            cname_depth_count++;

                            rr = rr->next;
                        }

                        u8* cname_owner = *pool;

                        *pool += ALIGN16(dnsname_copy(*pool, qname));

                        /* ONE record */
                        zdb_query_ex_answer_append(answer, cname_owner,
                                                    PASS_ZCLASS_PARAMETER
                                                    TYPE_CNAME, &ans_auth_add->answer, pool);

#if ZDB_HAS_DNSSEC_SUPPORT
                        if(dnssec)
                        {
                            zdb_query_ex_answer_append_type_rrsigs(rr_label, cname_owner, TYPE_CNAME,
                                                                    PASS_ZCLASS_PARAMETER
                                                                    answer->ttl, &ans_auth_add->answer, pool);
                        }
#endif

                        message_set_canonised_fqdn(mesg, ZDB_PACKEDRECORD_PTR_RDATAPTR(answer));

                        zdb_query_from_cname(db, mesg, ans_auth_add, in_zone, pool_buffer);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return FP_RCODE_NOERROR;
                    }
                    else
                    {
                        /*
                        * We expected a CNAME record but found none.
                        * This is NOT supposed to happen.
                        *
                        */

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return FP_CNAME_BROKEN;
                    }
                }

                if(zdb_rr_label_flag_isclear(rr_label, ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION))
                {
                    message_set_authoritative(mesg);
                }
                else
                {
                    /*
                     * we are AT or UNDER a delegation
                     * We can only find (show) NS, DS, RRSIG, NSEC records from the query
                     *
                     * The answer WILL be a referral ...
                     */

                    switch(type)
                    {
                        /* for these ones : give the rrset for the type and clear AA */
                        case TYPE_DS:
                        {
                            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                            {
                                message_set_authoritative(mesg);
                            }
                            else if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_UNDERDELEGATION))
                            {
                                message_disable_authoritative(mesg);
                            }
                            authority_required = FALSE;
                            break;
                        }
                        case TYPE_NSEC:
                        {
                            ans_auth_add->delegation = 1; // no answer, and we will answer with NS (as at or under delegation)

                            if(zdb_rr_label_flag_isclear(rr_label, ZDB_RR_LABEL_UNDERDELEGATION))
                            {
                                message_set_authoritative(mesg);
                            }
                            break;
                        }
                        /* for these ones : give the rrset for the type */
                        case TYPE_NS:
                            ans_auth_add->delegation = 1; // no answer, and we will answer with NS (as at or under delegation)
                            break;
                        /* for this one : present the delegation */
                        case TYPE_ANY:
                            ans_auth_add->delegation = 1; // no answer, and we will answer with NS (as at or under delegation)
                            authority_required = FALSE;
                            break;
                        /* for the rest : NSEC ? */
                        default:

                            /*
                             * do not try to look for it
                             *
                             * faster: go to label but no record, but let's avoid gotos ...
                             */
                            type = 0;
                            break;
                    }
                }

                /*
                 * First let's handle "simple" cases.  ANY will be handled in another part of the code.
                 */

                if(type != TYPE_ANY)
                {
                    /*
                     * From the label that has been found, get the RRSET for the required type (zdb_packed_ttlrdata*)
                     */

                    if((answer = zdb_record_find(&rr_label->resource_record_set, type)) != NULL)
                    {
                        /* A match has been found */

                        /* NS case */

                        if(type == TYPE_NS)
                        {
                            zdb_resourcerecord **section;

                            /*
                             * If the label is a delegation, the NS have to be added into authority,
                             * else they have to be added into answer.
                             *
                             */

                            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                            {
                                section = &ans_auth_add->authority;
                                /* ans_auth_add->is_delegation = TRUE; later */
                            }
                            else
                            {
                                section = &ans_auth_add->answer;
                            }

                            /*
                             * Add the NS records in random order in the right section
                             *
                             */

                            zdb_query_ex_answer_appendrndlist(answer, qname,
                                                              PASS_ZCLASS_PARAMETER
                                                              type, section, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
                            /*
                             * Append all the RRSIG of NS from the label
                             */

                            if(dnssec)
                            {
                                zdb_query_ex_answer_append_type_rrsigs(rr_label, qname, TYPE_NS,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       answer->ttl, section, pool);

                                if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                                {
                                    zdb_packed_ttlrdata* label_ds = zdb_record_find(&rr_label->resource_record_set, TYPE_DS);

                                    if(label_ds != NULL)
                                    {
                                        zdb_query_ex_answer_appendlist(label_ds, qname,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       TYPE_DS, &ans_auth_add->authority, pool);
                                        zdb_query_ex_answer_append_type_rrsigs(rr_label, qname, TYPE_DS,
                                                                               PASS_ZCLASS_PARAMETER
                                                                               label_ds->ttl, &ans_auth_add->authority, pool);
                                    }
#if ZDB_HAS_NSEC3_SUPPORT
                                    else
                                    if(ZONE_NSEC3_AVAILABLE(zone))
                                    {
                                        /**
                                         * If there is an NSEC3 RR that matches the delegation name, then that
                                         * NSEC3 RR MUST be included in the response.  The DS bit in the type
                                         * bit maps of the NSEC3 RR MUST NOT be set.
                                         *
                                         * If the zone is Opt-Out, then there may not be an NSEC3 RR
                                         * corresponding to the delegation.  In this case, the closest provable
                                         * encloser proof MUST be included in the response.  The included NSEC3
                                         * RR that covers the "next closer" name for the delegation MUST have
                                         * the Opt-Out flag set to one.  (Note that this will be the case unless
                                         * something has gone wrong).
                                         *
                                         */

                                        zdb_query_ex_append_nsec3_delegation(zone, &rr_label_info, &name, top,
                                                                             PASS_ZCLASS_PARAMETER
                                                                             &ans_auth_add->authority, pool);
                                    }
#endif
#if ZDB_HAS_NSEC_SUPPORT
                                    else
                                    if(ZONE_NSEC_AVAILABLE(zone))
                                    {
                                        /*
                                         * Append the NSEC of rr_label and all its signatures
                                         */

                                        s32 min_ttl;

                                        zdb_zone_getminttl(zone, &min_ttl);

                                        zdb_query_ex_append_nsec_records(rr_label, qname, min_ttl,
                                                                         PASS_ZCLASS_PARAMETER
                                                                         &ans_auth_add->authority, pool);
                                    }
#endif
                                }
                            }
#endif
                            /*
                             * authority is never required since we have it already
                             *
                             */

                            /*
                             * fetch all the additional records for the required type (NS and MX types)
                             * add them to the additional section
                             */

                            if(additionals_required)
                            {
                                update_additionals_dname_set(answer,
                                                             PASS_ZCLASS_PARAMETER
                                                             type, &additionals_dname_set);
                                append_additionals_dname_set(zone,
                                                             PASS_ZCLASS_PARAMETER
                                                             &additionals_dname_set, &ans_auth_add->additional, pool, dnssec);
                            }
                        }
                        else /* general case */
                        {
                            /*
                             * Add the records from the answer in random order to the answer section
                             */

                            zdb_query_ex_answer_appendrndlist(answer, qname,
                                                              PASS_ZCLASS_PARAMETER
                                                              type, &ans_auth_add->answer, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
                            /*
                             * Append all the RRSIG of NS from the label
                             */

                            if(dnssec)
                            {
                                zdb_query_ex_answer_append_type_rrsigs(rr_label, qname, type,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       answer->ttl, &ans_auth_add->answer, pool);

                                if(IS_WILD_LABEL(rr_label->name))
                                {
                                    /**
                                     * If there is a wildcard match for QNAME and QTYPE, then, in addition
                                     * to the expanded wildcard RRSet returned in the answer section of the
                                     * response, proof that the wildcard match was valid must be returned.
                                     *
                                     * This proof is accomplished by proving that both QNAME does not exist
                                     * and that the closest encloser of the QNAME and the immediate ancestor
                                     * of the wildcard are the same (i.e., the correct wildcard matched).
                                     *
                                     * To this end, the NSEC3 RR that covers the "next closer" name of the
                                     * immediate ancestor of the wildcard MUST be returned.
                                     * It is not necessary to return an NSEC3 RR that matches the closest
                                     * encloser, as the existence of this closest encloser is proven by
                                     * the presence of the expanded wildcard in the response.
                                     */
#if ZDB_HAS_NSEC3_SUPPORT
                                    if(ZONE_NSEC3_AVAILABLE(zone))
                                    {
                                        /*
                                        zdb_query_ex_append_wild_nsec3_data(zone, rr_label, &name, top,
                                                                            PASS_ZCLASS_PARAMETER
                                                                            &ans_auth_add->authority, pool);
                                        */
                                    }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                    else
#endif
                                    if(ZONE_NSEC_AVAILABLE(zone))
                                    {
                                        /* add the NSEC of the wildcard and its signature(s) */

                                        zdb_query_ex_add_nsec_interval(zone, &name, NULL, &ans_auth_add->authority, pool);
                                    }
#endif
                                }
                            }
#endif
                            /*
                             * if authority required
                             */

                            if(authority_required)
                            {
                                if((type == TYPE_NSEC || type == TYPE_DS) && (rr_label_info.authority != zone->apex))
                                {
                                    rr_label_info.authority = zone->apex;
                                    rr_label_info.authority_index = sp - 1;
                                }

                                zdb_packed_ttlrdata* authority = append_authority(qname,
                                                                                  PASS_ZCLASS_PARAMETER
                                                                                  &rr_label_info, &ans_auth_add->authority, pool, dnssec);

                                if(additionals_required)
                                {
                                    update_additionals_dname_set(authority,
                                                                 PASS_ZCLASS_PARAMETER
                                                                 TYPE_NS, &additionals_dname_set);
                                }
                            }

                            /*
                             * fetch all the additional records for the required type (NS and MX types)
                             * add them to the additional section
                             */

                            if(additionals_required)
                            {
                                update_additionals_dname_set(answer,
                                                             PASS_ZCLASS_PARAMETER
                                                             type, &additionals_dname_set);
                                append_additionals_dname_set(zone,
                                                             PASS_ZCLASS_PARAMETER
                                                             &additionals_dname_set, &ans_auth_add->additional, pool, dnssec);
                            } /* resolve authority */
                        }
#if DEBUG
                        log_debug("zdb-query-cname: FP_BASIC_RECORD_FOUND");
#endif
                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return FP_BASIC_RECORD_FOUND;
                    } /* if found the record of the requested type */
                    else
                    {
                        /* label but no record */

                        /**
                        * Got the label, but not the record.
                        * This should branch to NSEC3 if it is supported.
                        */

                        ya_result ret = zdb_query_ex_record_not_found(zone,
                                &rr_label_info,
                                qname,
                                &name,
                                sp,
                                top,
                                type,
                                PASS_ZCLASS_PARAMETER
                                pool,
                                dnssec,
                                ans_auth_add,
                                &additionals_dname_set);
#if DEBUG
                        log_debug("zdb-query-cname: FP_BASIC_RECORD_NOTFOUND (done)");
#endif

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return (finger_print)ret;
                    }
                }
                else /* We got the label BUT type == TYPE_ANY */
                {
                    if(zdb_rr_label_flag_isclear(rr_label, ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION))
                    {
                        zdb_packed_ttlrdata *soa = NULL;

#if ZDB_HAS_DNSSEC_SUPPORT
                        zdb_packed_ttlrdata *rrsig_list = zdb_record_find(&rr_label->resource_record_set, TYPE_RRSIG);
#endif

                        bool answers = FALSE;

                        /* We do iterate on ALL the types of the label */

                        btree_iterator iter;
                        btree_iterator_init(rr_label->resource_record_set, &iter);

                        while(btree_iterator_hasnext(&iter))
                        {
                            btree_node* nodep = btree_iterator_next_node(&iter);

                            u16 type = nodep->hash;

                            answers = TRUE;

                            zdb_packed_ttlrdata* ttlrdata = (zdb_packed_ttlrdata*)nodep->data;

                            /**
                             * @note: doing the list once may be faster ...
                             *        And YES maybe, because of the jump and because the list is supposed to
                             *        be VERY small (like 1-3)
                             */

                            switch(type)
                            {
                                case TYPE_SOA:
                                {
                                    soa = ttlrdata;
                                    continue;
                                }
                                case TYPE_NS:
                                {
                                    /* NO NEED FOR AUTHORITY */
                                    authority_required = FALSE;
                                }
                                FALLTHROUGH // fall through
                                case TYPE_MX:
                                case TYPE_CNAME:
                                {
                                    /* ADD MX "A/AAAA/GLUE" TO ADDITIONAL */

                                    if(additionals_required)
                                    {
                                        update_additionals_dname_set(ttlrdata,
                                                                     PASS_ZCLASS_PARAMETER
                                                                     type, &additionals_dname_set);
                                    }
                                    break;
                                }
                                case TYPE_RRSIG:
                                {
                                    // signatures will be added by type
                                    continue;
                                }
                                default:
                                {
                                    break;
                                }
                            }

                            zdb_query_ex_answer_appendrndlist(ttlrdata, qname,
                                                              PASS_ZCLASS_PARAMETER
                                                              type, &ans_auth_add->answer, pool);

#if ZDB_HAS_DNSSEC_SUPPORT
                            if(rrsig_list != NULL)
                            {
                                zdb_query_ex_answer_append_type_rrsigs_from(rrsig_list, qname, type,
                                                                            PASS_ZCLASS_PARAMETER
                                                                            ttlrdata->ttl, &ans_auth_add->answer, pool);
                            }
#endif
                        }

                        /* now we can insert the soa, if any has been found, at the head of the list */

                        if(soa != NULL)
                        {
                            zdb_resourcerecord* soa_rr = zdb_query_ex_answer_make(soa, qname,
                                                                                  PASS_ZCLASS_PARAMETER
                                                                                  TYPE_SOA, pool);
                            soa_rr->next = ans_auth_add->answer;
                            ans_auth_add->answer = soa_rr;
#if ZDB_HAS_DNSSEC_SUPPORT
                            if(rrsig_list != NULL)
                            {
                                zdb_query_ex_answer_append_type_rrsigs_from(rrsig_list, qname, TYPE_SOA,
                                                                            PASS_ZCLASS_PARAMETER
                                                                            soa_rr->ttl, &ans_auth_add->answer, pool);
                            }
#endif
                        }

                        if(answers)
                        {
                            if(authority_required)
                            {   // not at or under a delegation
                                zdb_packed_ttlrdata* authority = append_authority(qname,
                                                                                  PASS_ZCLASS_PARAMETER
                                                                                  &rr_label_info, &ans_auth_add->authority, pool, dnssec);

                                if(additionals_required)
                                {
                                    update_additionals_dname_set(authority,
                                                                 PASS_ZCLASS_PARAMETER
                                                                 TYPE_NS, &additionals_dname_set);
                                }

                            } /* if authority required */

                            if(additionals_required)
                            {
                                append_additionals_dname_set(zone,
                                                             PASS_ZCLASS_PARAMETER
                                                             &additionals_dname_set, &ans_auth_add->additional, pool, dnssec);
                            }

#if ZDB_HAS_DNSSEC_SUPPORT
                            if(dnssec && IS_WILD_LABEL(rr_label->name))
                            {
                                /**
                                 * If there is a wildcard match for QNAME and QTYPE, then, in addition
                                 * to the expanded wildcard RRSet returned in the answer section of the
                                 * response, proof that the wildcard match was valid must be returned.
                                 *
                                 * This proof is accomplished by proving that both QNAME does not exist
                                 * and that the closest encloser of the QNAME and the immediate ancestor
                                 * of the wildcard are the same (i.e., the correct wildcard matched).
                                 *
                                 * To this end, the NSEC3 RR that covers the "next closer" name of the
                                 * immediate ancestor of the wildcard MUST be returned.
                                 * It is not necessary to return an NSEC3 RR that matches the closest
                                 * encloser, as the existence of this closest encloser is proven by
                                 * the presence of the expanded wildcard in the response.
                                 */

#if ZDB_HAS_NSEC3_SUPPORT
                                if(ZONE_NSEC3_AVAILABLE(zone))
                                {
                                    zdb_query_ex_append_wild_nsec3_data(zone, rr_label, &name, top,
                                                                        PASS_ZCLASS_PARAMETER
                                                                        &ans_auth_add->authority, pool);
                                }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                else
#endif
                                if(ZONE_NSEC_AVAILABLE(zone))
                                {
                                    /* add the NSEC of the wildcard and its signature(s) */

                                    zdb_query_ex_add_nsec_interval(zone, &name, NULL, &ans_auth_add->authority, pool);
                                }
#endif
                            }
#endif // ZDB_HAS_DNSSEC_SUPPORT

#if DEBUG
                            log_debug("zdb-query-cname: FP_BASIC_RECORD_FOUND (any)");
#endif
                            UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                            zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                            return FP_BASIC_RECORD_FOUND;
                        }
                        else
                        {
                            /* no records found ... */

                            ya_result ret = zdb_query_ex_record_not_found(zone,
                                    &rr_label_info,
                                    qname,
                                    &name,
                                    sp,
                                    top,
                                    TYPE_ANY,
                                    PASS_ZCLASS_PARAMETER
                                    pool,
                                    dnssec,
                                    ans_auth_add,
                                    &additionals_dname_set);

                            UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                            zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                            return (finger_print)ret;
                        }
                    }
                    else
                    {   /* ANY, at or under a delegation */

                        zdb_query_ex_record_not_found(zone,
                              &rr_label_info,
                              qname,
                              &name,
                              sp,
                              top,
                              0,
                              PASS_ZCLASS_PARAMETER
                              pool,
                              dnssec,
                              ans_auth_add,
                              &additionals_dname_set);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return FP_BASIC_RECORD_FOUND;
                    }
                }
            }       /* end of if rr_label != NULL => */
            else    /* rr_label == NULL */
            {
                zdb_rr_label* rr_label_authority = rr_label_info.authority;

                if(rr_label_authority != zone->apex)
                {
                    message_disable_authoritative(mesg);

                    zdb_packed_ttlrdata *authority = zdb_record_find(&rr_label_authority->resource_record_set, TYPE_NS);

                    if(authority != NULL)
                    {

                        const u8 * authority_qname = zdb_rr_label_info_get_authority_qname(qname, &rr_label_info);

                        zdb_query_ex_answer_appendrndlist(authority, authority_qname,
                                                          PASS_ZCLASS_PARAMETER
                                                          TYPE_NS, &ans_auth_add->authority, pool);
                        update_additionals_dname_set(authority,
                                                     PASS_ZCLASS_PARAMETER
                                                     TYPE_NS, &additionals_dname_set);
                        append_additionals_dname_set(zone,
                                                     PASS_ZCLASS_PARAMETER
                                                     &additionals_dname_set, &ans_auth_add->additional, pool, FALSE);

                        if(dnssec)
                        {
#if ZDB_HAS_DNSSEC_SUPPORT
                            zdb_query_ex_answer_append_type_rrsigs(rr_label_authority, authority_qname, TYPE_NS,
                                                                   PASS_ZCLASS_PARAMETER
                                                                   authority->ttl, &ans_auth_add->authority, pool);
#endif

                            zdb_packed_ttlrdata *delegation_signer = zdb_record_find(&rr_label_authority->resource_record_set, TYPE_DS);

                            if(delegation_signer != NULL)
                            {
                                zdb_query_ex_answer_appendlist(delegation_signer , authority_qname,
                                                               PASS_ZCLASS_PARAMETER
                                                               TYPE_DS, &ans_auth_add->authority, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
                                zdb_query_ex_answer_append_type_rrsigs(rr_label_authority, authority_qname, TYPE_DS,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       delegation_signer->ttl, &ans_auth_add->authority, pool);
#endif
                            }
                            else
                            {
#if ZDB_HAS_NSEC3_SUPPORT
                                if(ZONE_NSEC3_AVAILABLE(zone))
                                {
                                    // add ... ? it looks like the record that covers the path that has been found in the zone
                                    // is used for the digest, then the interval is shown
                                    // add apex NSEC3 (wildcard)

                                    zdb_query_ex_append_nsec3_delegation(zone, &rr_label_info, &name, top,
                                                                         PASS_ZCLASS_PARAMETER
                                                                         &ans_auth_add->authority, pool);
                                }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                else
#endif
                                if(ZONE_NSEC_AVAILABLE(zone))
                                {
                                    /*
                                     * Append the NSEC of rr_label and all its signatures
                                     */

                                    s32 min_ttl;

                                    zdb_zone_getminttl(zone, &min_ttl);
                                    zdb_query_ex_append_nsec_records(rr_label_authority, authority_qname, min_ttl,
                                                                     PASS_ZCLASS_PARAMETER
                                                                     &ans_auth_add->authority, pool);

                                }
#endif
                            }
                        }

                        ans_auth_add->delegation = 1; // no answer, NS records in authority : referral
#if DEBUG
                        log_debug("zdb-query-cname: FP_BASIC_LABEL_NOTFOUND (done)");
#endif
                        /* ans_auth_add->is_delegation = TRUE; later */

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return FP_BASIC_LABEL_DELEGATION;
                    }
                }
                else
                {
                    message_set_authoritative(mesg);
                }
            }

            /* LABEL NOT FOUND: We stop the processing and fall through NSEC(3) or the basic case. */

            UNLOCK(zone);

            /* Stop looking, skip cache */
            break;

        } /* if(zone!=NULL) */

        sp--;
    } /* while ... */

    if(outside_of_zone)
    {
        return FP_RCODE_NOERROR;
    }

#if 1
    /*************************************************
     *                                               *
     * At this point we are not an authority anymore. *
     *                                               *
     *************************************************/


    /*if(authority_required) { */
    /*
     * Get the most relevant label (lowest zone).
     * Try to do NSEC3 or NSEC with it.
     */

    zdb_zone* zone;

#if DEBUG
    zone = (zdb_zone*)~0;
#endif

    sp = top;           // top >= 0, so we can enter here and zone is assigned

    yassert(sp >= 0);

    while(sp >= 0)      // scan-build false positive: we ALWAYS get into this loop at least once
    {
        zdb_zone_label* zone_label = zone_label_stack[sp--];

        if((zone = zone_label->zone) != NULL) // scan-build false positive: one alleged error relies on this being both NULL and not NULL at the same time (with zone_label_stack[sp=0]).
        {
            /* if type == DS && zone->origin = qname then the return value is NOERROR instead of NXDOMAIN */
            break;
        }
    }

    if(zone == NULL)    // zone is ALWAYS assigned because top is >= 0 (several false-positive)
    {
#if DEBUG
        log_debug("zdb-query-cname: FP_NOZONE_FOUND (2)");
#endif

        // ??? zone_pointer_out->apex->flags |= ZDB_RR_LABEL_MASTER_OF;
#if HAS_DYNAMIC_PROVISIONING
        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
        return FP_NOZONE_FOUND;
    }

    LOCK(zone);

    if(!zdb_zone_invalid(zone))
    {

        // zone is the most relevant zone
#if ZDB_HAS_DNSSEC_SUPPORT
        if(dnssec)
        {
#if ZDB_HAS_NSEC3_SUPPORT
            if(ZONE_NSEC3_AVAILABLE(zone))
            {
                //nsec3_zone *n3 = zone->nsec.nsec3;

                u8 *next_closer_owner = NULL;
                zdb_packed_ttlrdata* next_closer;
                const zdb_packed_ttlrdata* next_closer_rrsig;

                u8 *closer_encloser_owner = NULL;
                zdb_packed_ttlrdata* closer_encloser;
                const zdb_packed_ttlrdata* closer_encloser_rrsig;

                u8 *wild_closer_encloser_owner = NULL;
                zdb_packed_ttlrdata* wild_closer_encloser;
                const zdb_packed_ttlrdata* wild_closer_encloser_rrsig;
#if DEBUG
                log_debug("nsec3_name_error");
#endif
                nsec3_name_error(
                        zone, &name, top, pool,

                        &next_closer_owner,
                        &next_closer,
                        &next_closer_rrsig,

                        &closer_encloser_owner,
                        &closer_encloser,
                        &closer_encloser_rrsig,

                        &wild_closer_encloser_owner,
                        &wild_closer_encloser,
                        &wild_closer_encloser_rrsig);

                s32 min_ttl;
                zdb_zone_getminttl(zone, &min_ttl);
                zdb_query_ex_answer_append_soa_rrsig_nttl(zone, &ans_auth_add->authority, pool);
#if DEBUG
                log_debug("zdb-query-cname: nsec3_name_error: next_closer_owner: %{dnsname}", next_closer_owner);
#endif

                if(next_closer != NULL /*&& next_closer_rrsig != NULL*/)
                {
                    zdb_query_ex_answer_append_ttl(next_closer, next_closer_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, &ans_auth_add->authority, pool);

                    if(next_closer_rrsig != NULL)
                    {
                        zdb_query_ex_answer_appendlist_ttl(next_closer_rrsig, next_closer_owner,
                                                           PASS_ZCLASS_PARAMETER
                                                           TYPE_RRSIG, min_ttl, &ans_auth_add->authority, pool);
                    }
                }

                if(closer_encloser != NULL/* && closer_encloser_rrsig != NULL*/)
                {
#if DEBUG
                    log_debug("zdb-query-cname: nsec3_name_error: closer_encloser_owner: %{dnsname}", closer_encloser_owner);
#endif
                    zdb_query_ex_answer_append_ttl(closer_encloser, closer_encloser_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, &ans_auth_add->authority, pool);

                    if(closer_encloser_rrsig != NULL)
                    {
                        zdb_query_ex_answer_appendlist_ttl(closer_encloser_rrsig, closer_encloser_owner,
                                                           PASS_ZCLASS_PARAMETER
                                                           TYPE_RRSIG, min_ttl, &ans_auth_add->authority, pool);
                    }
                }

                if(wild_closer_encloser != NULL)
                {
#if DEBUG
                    log_debug("zdb-query-cname: nsec3_name_error: wild_closer_encloser_owner: %{dnsname}", wild_closer_encloser_owner);
#endif
                    zdb_query_ex_answer_append_ttl(wild_closer_encloser, wild_closer_encloser_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, &ans_auth_add->authority, pool);

                    if(wild_closer_encloser_rrsig != NULL)
                    {
                        zdb_query_ex_answer_appendlist_ttl(wild_closer_encloser_rrsig, wild_closer_encloser_owner,
                                                           PASS_ZCLASS_PARAMETER
                                                           TYPE_RRSIG, min_ttl, &ans_auth_add->authority, pool);
                    }
                }
#if DEBUG
                log_debug("zdb-query-cname: FP_NSEC3_LABEL_NOTFOUND (done)");
#endif
                UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                return FP_NSEC3_LABEL_NOTFOUND;
            }

#endif /* ZDB_HAS_NSEC3_SUPPORT != 0 */

                /* NSEC, if possible */
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
            else /* Following will be either the NSEC answer or just the SOA added in the authority */
#endif
            if(ZONE_NSEC_AVAILABLE(zone))
            {
                /*
                 * Unknown and not in the cache : NSEC
                 *
                 */

                /*
                 * zone label stack
                 *
                 * #0 : top
                 * #1 : com, org, ...
                 * #2 : example, ...
                 *
                 * Which is the inverse of the dnslabel stack
                 *
                 * dnslabel stack
                 *
                 * #0 : example
                 * #1 : com
                 * #2 : NOTHING ("." is not stored)
                 *
                 *
                 */

                /*
                 * Get the SOA + NSEC + RRIGs for the zone
                 */


                //zdb_rr_label *apex_label = zone->apex;
                zdb_query_ex_answer_append_soa_rrsig_nttl(zone, &ans_auth_add->authority, pool);

                u8 *encloser_nsec_name = NULL;
                u8 *wild_encloser_nsec_name = NULL;
                zdb_rr_label *encloser_nsec_label;
                zdb_rr_label *wildencloser_nsec_label;

                nsec_name_error(zone, &name, rr_label_info.closest_index, // scan-build (7) false positive: the path allegedly leading here lies on an incoherence (VS false positive too)
                                pool,
                                &encloser_nsec_name, &encloser_nsec_label,
                                &wild_encloser_nsec_name, &wildencloser_nsec_label);

                if(encloser_nsec_label != NULL)
                {
                    zdb_packed_ttlrdata *encloser_nsec_rr = zdb_record_find(&encloser_nsec_label->resource_record_set, TYPE_NSEC);

                    if(encloser_nsec_rr != NULL)
                    {
                        zdb_query_ex_answer_append(encloser_nsec_rr, encloser_nsec_name,
                                                   DECLARE_ZCLASS_PARAMETER
                                                   TYPE_NSEC, &ans_auth_add->authority, pool);

                        zdb_query_ex_answer_append_type_rrsigs(encloser_nsec_label, encloser_nsec_name, TYPE_NSEC,
                                                               DECLARE_ZCLASS_PARAMETER
                                                               encloser_nsec_rr->ttl, &ans_auth_add->authority, pool);

                        if(wildencloser_nsec_label != encloser_nsec_label)
                        {
                            zdb_packed_ttlrdata *wildencloser_nsec_rr = zdb_record_find(&wildencloser_nsec_label->resource_record_set, TYPE_NSEC);

                            if(wildencloser_nsec_rr != NULL)
                            {
                                zdb_query_ex_answer_append(wildencloser_nsec_rr, wild_encloser_nsec_name,
                                                           DECLARE_ZCLASS_PARAMETER
                                                           TYPE_NSEC, &ans_auth_add->authority, pool);

                                zdb_query_ex_answer_append_type_rrsigs(wildencloser_nsec_label, wild_encloser_nsec_name, TYPE_NSEC,
                                                                       DECLARE_ZCLASS_PARAMETER
                                                                       wildencloser_nsec_rr->ttl, &ans_auth_add->authority, pool);
                            }
                        }
                    }
                }
#if DEBUG
                log_debug("zdb-query-cname: FP_NSEC_LABEL_NOTFOUND (done)");
#endif
                UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                return FP_NSEC_LABEL_NOTFOUND;
            }
#endif // ZDB_HAS_NSEC_SUPPORT
        }
#endif // ZDB_HAS_DNSSEC_SUPPORT

        zdb_query_ex_answer_append_soa_nttl(zone, &ans_auth_add->authority, pool);
#if DEBUG
        log_debug("zdb-query-cname: FP_BASIC_LABEL_NOTFOUND (done)");
#endif

        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
        return FP_BASIC_LABEL_NOTFOUND;
    }
    else // if(!zdb_zone_invalid(zone))
    {
#if DEBUG
        log_debug("zdb-query-cname: FP_ZONE_EXPIRED (2)");
#endif

        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
        return FP_INVALID_ZONE;
    }
#endif
    return FP_RCODE_NOERROR;
}

/**
 * @brief Queries the database given a message
 *
 * @param db the database
 * @param mesg the message
 * @param pool_buffer a big enough buffer used for the memory pool
 *
 * @return the status of the message (probably useless)
 */

void
zdb_query_and_update(zdb *db, message_data *mesg, u8 * restrict pool_buffer)
{
    zdb_query_ex_answer ans_auth_add;

    const u8 *qname = message_get_canonised_fqdn(mesg);
#if ZDB_RECORDS_MAX_CLASS != 1
    const u16 zclass = message_get_query_class(mesg);
#endif

    zdb_rr_label_find_ext_data rr_label_info;

    u16 type = message_get_query_type(mesg);
    const process_flags_t flags = zdb_query_process_flags;

    /** Check that we are even allowed to handle that class */
#if ZDB_RECORDS_MAX_CLASS == 1
    if(message_get_query_class(mesg) != CLASS_IN)
    {
#if DEBUG
        log_debug("zdb_query_and_update: FP_CLASS_NOTFOUND");
#endif
        return; // FP_CLASS_NOTFOUND;
    }

    zdb_query_ex_answer_create(&ans_auth_add);

#endif
#if HAS_DYNAMIC_PROVISIONING
    zdb_lock(db, ZDB_MUTEX_READER);
#endif
#if ZDB_RECORDS_MAX_CLASS != 1
    u16 host_zclass = ntohs(zclass); /* no choice */
    if(host_zclass > ZDB_RECORDS_MAX_CLASS)
    {
        return; // FP_CLASS_NOTFOUND;
    }
#endif

    bool dnssec = message_has_rcode_ext_dnssec(mesg);

    /**
     *  MANDATORY, INITIALISES A LOCAL MEMORY POOL
     *
     *  This is actually a macro found in dnsname_set.h
     */

    dnsname_vector name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(qname, &name);

    u8 * restrict * pool = &pool_buffer;

    /*
     * Find closest matching label
     * Should return a stack of zones
     */

    zdb_zone_label_pointer_array zone_label_stack;

    s32 top = zdb_zone_label_match(db, &name, zone_label_stack);

    s32 sp = top;

    zdb_packed_ttlrdata* answer;

    /* This flag means that there HAS to be an authority section */

    bool authority_required = flags & PROCESS_FL_AUTHORITY_AUTH;

    /* This flag means the names in the authority must be (internally) resolved if possible */

    bool additionals_required = flags & PROCESS_FL_ADDITIONAL_AUTH;

    switch(type)
    {
        case TYPE_DNSKEY:
        {
            authority_required = FALSE;
            additionals_required = FALSE;
            break;
        }
    }

    /* Got a stack of zone labels with and without zone cuts */
    /* Search the label on the zone files */

    /* While we have labels along the path */

    if(type == TYPE_DS)         // This is the only type that can only be found outside of the zone
    {                           // In order to avoid to hit said zone, I skip the last label.
        if(name.size == sp - 1) // we have a perfect match (DS for an APEX), try to get outside ...
        {
            s32 parent_sp = sp;

            while(--parent_sp >= 0)
            {
                /* Get the "bottom" label (top being ".") */

                zdb_zone_label* zone_label = zone_label_stack[parent_sp];

                /* Is there a zone file at this level ? If yes, search into it. */

                if(zone_label->zone != NULL)
                {
                    // got it.
                    sp = parent_sp;
                    message_set_authoritative_answer(mesg);
                    break;
                }
            }

            authority_required = FALSE;
        }
    }

    while(sp >= 0)
    {
        /* Get the "bottom" label (top being ".") */

        zdb_zone_label* zone_label = zone_label_stack[sp];

        /* Is there a zone file at this level ? If yes, search into it. */

        if(zone_label->zone != NULL)
        {

            zdb_zone *zone = zone_label->zone;

            /*
             * lock
             */

            LOCK(zone);

#if DEBUG
            log_debug("zdb_query_and_update: zone %{dnsname}, flags=%x", zone->origin, zdb_rr_label_flag_get(zone->apex));
#endif

            /*
             * We know the zone, and its extension here ...
             */

            {
                /*
                 * Filter handling (ACL)
                 * NOTE: the return code has to be fingerprint-based
                 */

                if(FAIL(zone->query_access_filter(mesg, zone->acl)))
                {
#if DEBUG
                    log_debug("zdb_query_and_update: FP_ACCESS_REJECTED");
#endif
                    message_set_status(mesg, FP_ACCESS_REJECTED);
                    zdb_query_message_update(mesg, &ans_auth_add);
                    zdb_query_ex_answer_destroy(&ans_auth_add);

                    UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                    zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                    return; // FP_ACCESS_REJECTED;
                }
            }

            /**
             * The ACL have been passed so ... now check that the zone is valid
             */

            if(zdb_zone_invalid(zone))
            {
                /**
                 * @note the blocks could be reversed and jump if the zone is invalid (help the branch prediction)
                 */
#if DEBUG
                log_debug("zdb_query_and_update: FP_INVALID_ZONE");
#endif
                message_set_status(mesg, FP_INVALID_ZONE);
                zdb_query_message_update(mesg, &ans_auth_add);
                zdb_query_ex_answer_destroy(&ans_auth_add);

                UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                return; // FP_INVALID_ZONE;
            }

            //message_set_authoritative(mesg);

            dnsname_set additionals_dname_set;
            dnsname_set_init(&additionals_dname_set);

            /*
             * In one query, get the authority and the closest (longest) path to the domain we are looking for.
             */

            zdb_rr_label *rr_label = zdb_rr_label_find_ext(zone->apex, name.labels, name.size - sp, &rr_label_info);

            /* Has a label been found ? */

            if(rr_label != NULL)
            {
                /*
                 * Got the label.  I will not find anything relevant by going
                 * up to another zone file.
                 *
                 * We set the AA bit iff we are not at or under a delegation.
                 *
                 * The ZDB_RR_LABEL_DELEGATION flag means the label is a delegation.
                 * This means that it only contains NS & DNSSEC records + may have sub-labels for glues
                 *
                 * ZDB_RR_LABEL_UNDERDELEGATION means we are below a ZDB_RR_LABEL_DELEGATION label
                 *
                 */

                /*
                 * CNAME alias handling
                 */

                if(((zdb_rr_label_flag_get(rr_label) & (ZDB_RR_LABEL_HASCNAME|ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION)) == ZDB_RR_LABEL_HASCNAME) &&
                   (type != TYPE_CNAME) && (type != TYPE_ANY) && (type != TYPE_RRSIG))
                {
                    /*
                    * The label is an alias:
                    *
                    * Add the CNAME and restart the query from the alias
                    */

                    if(ans_auth_add.depth >= ZDB_CNAME_LOOP_MAX)
                    {
                        log_warn("CNAME depth at %{dnsname} is bigger than allowed %d>=%d", qname, ans_auth_add.depth, ZDB_CNAME_LOOP_MAX);

                        message_set_authoritative(mesg);

                        message_set_status(mesg, FP_CNAME_MAXIMUM_DEPTH);
                        zdb_query_message_update(mesg, &ans_auth_add);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);

                        // stop there
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return; // FP_CNAME_MAXIMUM_DEPTH;
                    }

                    ans_auth_add.depth++;

                    if((answer = zdb_record_find(&rr_label->resource_record_set, TYPE_CNAME)) != NULL)
                    {
                        /* The RDATA in answer is the fqdn to a label with an A record (list) */
                        /* There can only be one cname for a given owner */
                        /* Append all A/AAAA records associated to the CNAME AFTER the CNAME record */

                        zdb_resourcerecord *rr = ans_auth_add.answer;

                        u32 cname_depth_count = 0; /* I don't want to allocate that globally for now */

                        while(rr != NULL)
                        {
                            if((rr->rtype == TYPE_CNAME) && (ZDB_PACKEDRECORD_PTR_RDATAPTR(rr->ttl_rdata) == ZDB_PACKEDRECORD_PTR_RDATAPTR(answer)))
                            {
                                /* LOOP */

                                log_warn("CNAME loop at %{dnsname}", qname);

                                message_set_authoritative(mesg);

                                message_set_status(mesg, FP_CNAME_LOOP);
                                zdb_query_message_update(mesg, &ans_auth_add);
                                zdb_query_ex_answer_destroy(&ans_auth_add);

                                UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                                return; // FP_CNAME_LOOP;
                            }

                            cname_depth_count++;

                            rr = rr->next;
                        }

                        u8* cname_owner = *pool;

                        *pool += ALIGN16(dnsname_copy(*pool, qname));

                        /* ONE record */
                        zdb_query_ex_answer_append(answer, cname_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_CNAME, &ans_auth_add.answer, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
                        if(dnssec)
                        {
                            zdb_query_ex_answer_append_type_rrsigs(rr_label, cname_owner, TYPE_CNAME,
                                                                   PASS_ZCLASS_PARAMETER
                                                                   answer->ttl, &ans_auth_add.answer, pool);
                        }
#endif
                        message_set_canonised_fqdn(mesg, ZDB_PACKEDRECORD_PTR_RDATAPTR(answer));

                        finger_print fp = zdb_query_from_cname(db, mesg, &ans_auth_add, zone, pool_buffer);

                        message_set_authoritative(mesg); /// @note 20200520 EDF -- flag missing in the test
                        message_set_status(mesg, fp);
                        zdb_query_message_update(mesg, &ans_auth_add);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return; // fp;
                    }
                    else
                    {
                        /*
                        * We expected a CNAME record but found none.
                        * This is NOT supposed to happen.
                        *
                        */

                        message_set_status(mesg, FP_CNAME_BROKEN);
                        zdb_query_message_update(mesg, &ans_auth_add);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return; // FP_CNAME_BROKEN;
                    }
                }

                if(zdb_rr_label_flag_isclear(rr_label, (ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION) ))
                {
                    message_set_authoritative(mesg);
                    authority_required = FALSE;
                }
                else
                {
                    /*
                     * we are AT or UNDER a delegation
                     * We can only find (show) NS, DS, RRSIG, NSEC records from the query
                     *
                     * The answer WILL be a referral ...
                     */

                    switch(type)
                    {
                        /* for these ones : give the rrset for the type and clear AA */
                        case TYPE_DS:
                        {
                            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                            {
                                message_set_authoritative(mesg);
                            }
                            else if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_UNDERDELEGATION))
                            {
                                message_disable_authoritative(mesg);
                            }
                            authority_required = FALSE;
                            break;
                        }
                        case TYPE_NSEC:
                        {
                            if(zdb_rr_label_flag_isclear(rr_label, ZDB_RR_LABEL_UNDERDELEGATION))
                            {
                                message_set_authoritative(mesg);
                            }
                            break;
                        }
                            /* for these ones : give the rrset for the type */
                        case TYPE_NS:
                            ans_auth_add.delegation = 1;
                            break;
                            /* for this one : present the delegation */
                        case TYPE_ANY:
                            ans_auth_add.delegation = 1;
                            authority_required = FALSE;
                            break;
                            /* for the rest : NSEC ? */
                        default:
                            ans_auth_add.delegation = 1;
                            /*
                             * do not try to look for it
                             *
                             * faster: go to label but no record, but let's avoid gotos ...
                             */
                            type = 0;
                            break;
                    }
                }

                /*
                 * First let's handle "simple" cases.  ANY will be handled in another part of the code.
                 */

                if(type != TYPE_ANY)
                {
                    /*
                     * From the label that has been found, get the RRSET for the required type (zdb_packed_ttlrdata*)
                     */

                    if((answer = zdb_record_find(&rr_label->resource_record_set, type)) != NULL)
                    {
                        /* A match has been found */

                        /* NS case */

                        if(type == TYPE_NS)
                        {
                            zdb_resourcerecord **section;

                            /*
                             * If the label is a delegation, the NS have to be added into authority,
                             * else they have to be added into answer.
                             *
                             */

                            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                            {
                                section = &ans_auth_add.authority;
                                /* ans_auth_add.is_delegation = TRUE; later */
                            }
                            else
                            {
                                section = &ans_auth_add.answer;
                            }

                            /*
                             * Add the NS records in random order in the right section
                             *
                             */

                            zdb_query_ex_answer_appendrndlist(answer, qname,
                                                              PASS_ZCLASS_PARAMETER
                                                              type, section, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
                            /*
                             * Append all the RRSIG of NS from the label
                             */

                            if(dnssec)
                            {
                                zdb_query_ex_answer_append_type_rrsigs(rr_label, qname, TYPE_NS,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       answer->ttl, section, pool);

                                if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                                {
                                    zdb_packed_ttlrdata* label_ds = zdb_record_find(&rr_label->resource_record_set, TYPE_DS);

                                    if(label_ds != NULL)
                                    {
                                        zdb_query_ex_answer_appendlist(label_ds, qname,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       TYPE_DS, &ans_auth_add.authority, pool);
                                        zdb_query_ex_answer_append_type_rrsigs(rr_label, qname, TYPE_DS,
                                                                               PASS_ZCLASS_PARAMETER
                                                                               label_ds->ttl, &ans_auth_add.authority, pool);
                                    }
#if ZDB_HAS_NSEC3_SUPPORT
                                    else if(ZONE_NSEC3_AVAILABLE(zone))
                                    {
                                        /**
                                         * If there is an NSEC3 RR that matches the delegation name, then that
                                         * NSEC3 RR MUST be included in the response.  The DS bit in the type
                                         * bit maps of the NSEC3 RR MUST NOT be set.
                                         *
                                         * If the zone is Opt-Out, then there may not be an NSEC3 RR
                                         * corresponding to the delegation.  In this case, the closest provable
                                         * encloser proof MUST be included in the response.  The included NSEC3
                                         * RR that covers the "next closer" name for the delegation MUST have
                                         * the Opt-Out flag set to one.  (Note that this will be the case unless
                                         * something has gone wrong).
                                         *
                                         */

                                        zdb_query_ex_append_nsec3_delegation(zone, &rr_label_info, &name, top,
                                                                             PASS_ZCLASS_PARAMETER
                                                                             &ans_auth_add.authority, pool);
                                    }
#endif
#if ZDB_HAS_NSEC_SUPPORT
                                    else
                                    if(ZONE_NSEC_AVAILABLE(zone))
                                    {
                                        /*
                                         * Append the NSEC of rr_label and all its signatures
                                         */

                                        s32 min_ttl;
                                        zdb_zone_getminttl(zone, &min_ttl);

                                        zdb_query_ex_append_nsec_records(rr_label, qname, min_ttl,
                                                                         PASS_ZCLASS_PARAMETER
                                                                         &ans_auth_add.authority, pool);
                                    }
#endif
                                }
                            }
#endif
                            /*
                             * authority is never required since we have it already
                             *
                             */

                            /*
                             * fetch all the additional records for the required type (NS and MX types)
                             * add them to the additional section
                             */

                            if(additionals_required)
                            {
                                update_additionals_dname_set(answer,
                                                             PASS_ZCLASS_PARAMETER
                                                             type, &additionals_dname_set);
                                append_additionals_dname_set(zone,
                                                             PASS_ZCLASS_PARAMETER
                                                             &additionals_dname_set, &ans_auth_add.additional, pool, dnssec);
                            }
                        }
                        else /* general case */
                        {
                            /*
                             * Add the records from the answer in random order to the answer section
                             */

                            zdb_query_ex_answer_appendrndlist(answer, qname,
                                                              PASS_ZCLASS_PARAMETER
                                                              type, &ans_auth_add.answer, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
                            /*
                             * Append all the RRSIG of NS from the label
                             */

                            if(dnssec)
                            {
                                zdb_query_ex_answer_append_type_rrsigs(rr_label, qname, type,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       answer->ttl, &ans_auth_add.answer, pool);

                                if(IS_WILD_LABEL(rr_label->name))
                                {
                                    /**
                                     * If there is a wildcard match for QNAME and QTYPE, then, in addition
                                     * to the expanded wildcard RRSet returned in the answer section of the
                                     * response, proof that the wildcard match was valid must be returned.
                                     *
                                     * This proof is accomplished by proving that both QNAME does not exist
                                     * and that the closest encloser of the QNAME and the immediate ancestor
                                     * of the wildcard are the same (i.e., the correct wildcard matched).
                                     *
                                     * To this end, the NSEC3 RR that covers the "next closer" name of the
                                     * immediate ancestor of the wildcard MUST be returned.
                                     * It is not necessary to return an NSEC3 RR that matches the closest
                                     * encloser, as the existence of this closest encloser is proven by
                                     * the presence of the expanded wildcard in the response.
                                     */
#if ZDB_HAS_NSEC3_SUPPORT
                                    if(ZONE_NSEC3_AVAILABLE(zone))
                                    {
                                        zdb_query_ex_append_wild_nsec3_data(zone, rr_label, &name, top,
                                                                            PASS_ZCLASS_PARAMETER
                                                                            &ans_auth_add.authority, pool);
                                    }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                    else
#endif
                                    if(ZONE_NSEC_AVAILABLE(zone))
                                    {
                                        /* add the NSEC of the wildcard and its signature(s) */

                                        zdb_query_ex_add_nsec_interval(zone, &name, NULL, &ans_auth_add.authority, pool);
                                    }
#endif
                                }
                            }
#endif
                            /*
                             * if authority required
                             */

                            if(authority_required)
                            {
                                if((type == TYPE_NSEC || type == TYPE_DS) && (rr_label_info.authority != zone->apex))
                                {
                                    rr_label_info.authority = zone->apex;
                                    rr_label_info.authority_index = sp - 1;
                                }

                                zdb_packed_ttlrdata* authority = append_authority(qname,
                                                                                  PASS_ZCLASS_PARAMETER
                                                                                  &rr_label_info, &ans_auth_add.authority, pool, dnssec);

                                if(additionals_required)
                                {
                                    update_additionals_dname_set(authority,
                                                                 PASS_ZCLASS_PARAMETER
                                                                 TYPE_NS, &additionals_dname_set);
                                }
                            }

                            /*
                             * fetch all the additional records for the required type (NS and MX types)
                             * add them to the additional section
                             */

                            if(additionals_required)
                            {
                                update_additionals_dname_set(answer,
                                                             PASS_ZCLASS_PARAMETER
                                                             type, &additionals_dname_set);
                                append_additionals_dname_set(zone,
                                                             PASS_ZCLASS_PARAMETER
                                                             &additionals_dname_set, &ans_auth_add.additional, pool, dnssec);
                            } /* resolve authority */
                        }
#if DEBUG
                        log_debug("zdb_query_and_update: FP_BASIC_RECORD_FOUND");
#endif
                        message_set_status(mesg, FP_BASIC_RECORD_FOUND);
                        zdb_query_message_update(mesg, &ans_auth_add);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return; // FP_BASIC_RECORD_FOUND;
                    } /* if found the record of the requested type */
                    else
                    {
                        /* label but no record */

                        /**
                        * Got the label, but not the record.
                        * This should branch to NSEC3 if it is supported.
                        */

                        finger_print fp;

                        if(ZONE_NSEC_AVAILABLE(zone) || ZONE_NSEC3_AVAILABLE(zone))
                        {
                            fp = (finger_print)zdb_query_ex_record_not_found_nttl(zone,
                                                                                  &rr_label_info,
                                                                                  qname,
                                                                                  &name,
                                                                                  sp,
                                                                                  top,
                                                                                  type,
                                                                                  PASS_ZCLASS_PARAMETER
                                                                                  pool,
                                                                                  dnssec,
                                                                                  &ans_auth_add,
                                                                                  &additionals_dname_set);
                        }
                        else
                        {
                            fp = (finger_print)zdb_query_ex_record_not_found(zone,
                                                                             &rr_label_info,
                                                                             qname,
                                                                             &name,
                                                                             sp,
                                                                             top,
                                                                             type,
                                                                             PASS_ZCLASS_PARAMETER
                                                                             pool,
                                                                             dnssec,
                                                                             &ans_auth_add,
                                                                             &additionals_dname_set);
                        }
#if DEBUG
                        log_debug("zdb_query_and_update: FP_BASIC_RECORD_NOTFOUND (done)");
#endif
                        message_set_status(mesg, fp);
                        zdb_query_message_update(mesg, &ans_auth_add);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return; // (finger_print)return_value;
                    }
                }
                else /* We got the label BUT type == TYPE_ANY */
                {
                    if(zdb_rr_label_flag_isclear(rr_label, (ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION) ))
                    {
                        zdb_packed_ttlrdata *soa = NULL;

#if ZDB_HAS_DNSSEC_SUPPORT
                        zdb_packed_ttlrdata *rrsig_list = zdb_record_find(&rr_label->resource_record_set, TYPE_RRSIG);
#endif

                        bool answers = FALSE;

                        /* We do iterate on ALL the types of the label */

                        btree_iterator iter;
                        btree_iterator_init(rr_label->resource_record_set, &iter);

                        while(btree_iterator_hasnext(&iter))
                        {
                            btree_node* nodep = btree_iterator_next_node(&iter);

                            u16 type = nodep->hash;

                            answers = TRUE;

                            zdb_packed_ttlrdata* ttlrdata = (zdb_packed_ttlrdata*)nodep->data;

                            /**
                             * @note: doing the list once may be faster ...
                             *        And YES maybe, because of the jump and because the list is supposed to
                             *        be VERY small (like 1-3)
                             */

                            switch(type)
                            {
                                case TYPE_SOA:
                                {
                                    soa = ttlrdata;
                                    continue;
                                }
                                case TYPE_NS:
                                {
                                    /* NO NEED FOR AUTHORITY */
                                    authority_required = FALSE;
                                }
                                    FALLTHROUGH // fall through
                                case TYPE_MX:
                                case TYPE_CNAME:
                                {
                                    /* ADD MX "A/AAAA/GLUE" TO ADDITIONAL */

                                    if(additionals_required)
                                    {
                                        update_additionals_dname_set(ttlrdata,
                                                                     PASS_ZCLASS_PARAMETER
                                                                     type, &additionals_dname_set);
                                    }
                                    break;
                                }
                                case TYPE_RRSIG:
                                {
                                    // signatures will be added by type
                                    continue;
                                }
                                default:
                                {
                                    break;
                                }
                            }

                            zdb_query_ex_answer_appendrndlist(ttlrdata, qname,
                                                              PASS_ZCLASS_PARAMETER
                                                              type, &ans_auth_add.answer, pool);

#if ZDB_HAS_DNSSEC_SUPPORT
                            if(rrsig_list != NULL)
                            {
                                zdb_query_ex_answer_append_type_rrsigs_from(rrsig_list, qname, type,
                                                                            PASS_ZCLASS_PARAMETER
                                                                            ttlrdata->ttl, &ans_auth_add.answer, pool);
                            }
#endif
                        }

                        /* now we can insert the soa, if any has been found, at the head of the list */

                        if(soa != NULL)
                        {
                            zdb_resourcerecord* soa_rr = zdb_query_ex_answer_make(soa, qname,
                                                                                  PASS_ZCLASS_PARAMETER
                                                                                  TYPE_SOA, pool);
                            soa_rr->next = ans_auth_add.answer;
                            ans_auth_add.answer = soa_rr;
#if ZDB_HAS_DNSSEC_SUPPORT
                            if(rrsig_list != NULL)
                            {
                                zdb_query_ex_answer_append_type_rrsigs_from(rrsig_list, qname, TYPE_SOA,
                                                                            PASS_ZCLASS_PARAMETER
                                                                            soa_rr->ttl, &ans_auth_add.answer, pool);
                            }
#endif
                        }

                        if(answers)
                        {
                            if(authority_required)
                            {   // not at or under a delegation
                                zdb_packed_ttlrdata* authority = append_authority(qname,
                                                                                  PASS_ZCLASS_PARAMETER
                                                                                  &rr_label_info, &ans_auth_add.authority, pool, dnssec);

                                if(additionals_required)
                                {
                                    update_additionals_dname_set(authority,
                                                                 PASS_ZCLASS_PARAMETER
                                                                 TYPE_NS, &additionals_dname_set);
                                }

                            } /* if authority required */

                            if(additionals_required)
                            {
                                append_additionals_dname_set(zone,
                                                             PASS_ZCLASS_PARAMETER
                                                             &additionals_dname_set, &ans_auth_add.additional, pool, dnssec);
                            }

#if ZDB_HAS_DNSSEC_SUPPORT
                            if(dnssec && IS_WILD_LABEL(rr_label->name))
                            {
                                /**
                                 * If there is a wildcard match for QNAME and QTYPE, then, in addition
                                 * to the expanded wildcard RRSet returned in the answer section of the
                                 * response, proof that the wildcard match was valid must be returned.
                                 *
                                 * This proof is accomplished by proving that both QNAME does not exist
                                 * and that the closest encloser of the QNAME and the immediate ancestor
                                 * of the wildcard are the same (i.e., the correct wildcard matched).
                                 *
                                 * To this end, the NSEC3 RR that covers the "next closer" name of the
                                 * immediate ancestor of the wildcard MUST be returned.
                                 * It is not necessary to return an NSEC3 RR that matches the closest
                                 * encloser, as the existence of this closest encloser is proven by
                                 * the presence of the expanded wildcard in the response.
                                 */

#if ZDB_HAS_NSEC3_SUPPORT
                                if(ZONE_NSEC3_AVAILABLE(zone))
                                {
                                    zdb_query_ex_append_wild_nsec3_data(zone, rr_label, &name, top,
                                                                        PASS_ZCLASS_PARAMETER
                                                                        &ans_auth_add.authority, pool);
                                }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                else
#endif
                                if(ZONE_NSEC_AVAILABLE(zone))
                                {
                                    /* add the NSEC of the wildcard and its signature(s) */

                                    zdb_query_ex_add_nsec_interval(zone, &name, NULL, &ans_auth_add.authority, pool);
                                }
#endif
                            }
#endif // ZDB_HAS_DNSSEC_SUPPORT

#if DEBUG
                            log_debug("zdb_query_and_update: FP_BASIC_RECORD_FOUND (any)");
#endif
                            message_set_status(mesg, FP_BASIC_RECORD_FOUND);
                            zdb_query_message_update(mesg, &ans_auth_add);
                            zdb_query_ex_answer_destroy(&ans_auth_add);

                            UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                            zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                            return; // FP_BASIC_RECORD_FOUND;
                        }
                        else
                        {
                            /* no records found ... */

                            finger_print fp;

                            if(ZONE_NSEC_AVAILABLE(zone) || ZONE_NSEC3_AVAILABLE(zone))
                            {
                                fp = (finger_print)zdb_query_ex_record_not_found_nttl(zone,
                                                                                      &rr_label_info,
                                                                                      qname,
                                                                                      &name,
                                                                                      sp,
                                                                                      top,
                                                                                      TYPE_ANY,
                                                                                      PASS_ZCLASS_PARAMETER
                                                                                      pool,
                                                                                      dnssec,
                                                                                      &ans_auth_add,
                                                                                      &additionals_dname_set);
                            }
                            else
                            {
                                fp = (finger_print)zdb_query_ex_record_not_found(zone,
                                                                                 &rr_label_info,
                                                                                 qname,
                                                                                 &name,
                                                                                 sp,
                                                                                 top,
                                                                                 TYPE_ANY,
                                                                                 PASS_ZCLASS_PARAMETER
                                                                                 pool,
                                                                                 dnssec,
                                                                                 &ans_auth_add,
                                                                                 &additionals_dname_set);
                            }

                            message_set_status(mesg, fp);
                            zdb_query_message_update(mesg, &ans_auth_add);
                            zdb_query_ex_answer_destroy(&ans_auth_add);

                            UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                            zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                            return; // fp;
                        }
                    }
                    else
                    {   /* ANY, at or under a delegation */

                        zdb_query_ex_record_not_found(zone,
                                                      &rr_label_info,
                                                      qname,
                                                      &name,
                                                      sp,
                                                      top,
                                                      0,
                                                      PASS_ZCLASS_PARAMETER
                                                      pool,
                                                      dnssec,
                                                      &ans_auth_add,
                                                      &additionals_dname_set);

                        message_set_status(mesg, FP_BASIC_RECORD_FOUND);
                        zdb_query_message_update(mesg, &ans_auth_add);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        log_pool_usage(mesg, pool);
                        return; // FP_BASIC_RECORD_FOUND;
                    }
                }
            }       /* end of if rr_label!=NULL => */
            else    /* rr_label == NULL */
            {
                zdb_rr_label* rr_label_authority = rr_label_info.authority;

                if(rr_label_authority != zone->apex)
                {
                    message_disable_authoritative(mesg);

                    zdb_packed_ttlrdata *authority = zdb_record_find(&rr_label_authority->resource_record_set, TYPE_NS);

                    if(authority != NULL)
                    {

                        const u8 * authority_qname = zdb_rr_label_info_get_authority_qname(qname, &rr_label_info);

                        zdb_query_ex_answer_appendrndlist(authority, authority_qname,
                                                          PASS_ZCLASS_PARAMETER
                                                          TYPE_NS, &ans_auth_add.authority, pool);
                        update_additionals_dname_set(authority,
                                                     PASS_ZCLASS_PARAMETER
                                                     TYPE_NS, &additionals_dname_set);
                        append_additionals_dname_set(zone,
                                                     PASS_ZCLASS_PARAMETER
                                                     &additionals_dname_set, &ans_auth_add.additional, pool, FALSE);

                        if(dnssec)
                        {
#if ZDB_HAS_DNSSEC_SUPPORT
                            zdb_query_ex_answer_append_type_rrsigs(rr_label_authority, authority_qname, TYPE_NS,
                                                                   PASS_ZCLASS_PARAMETER
                                                                   authority->ttl, &ans_auth_add.authority, pool);
#endif

                            zdb_packed_ttlrdata *delegation_signer = zdb_record_find(&rr_label_authority->resource_record_set, TYPE_DS);

                            if(delegation_signer != NULL)
                            {
                                zdb_query_ex_answer_appendlist(delegation_signer , authority_qname,
                                                               PASS_ZCLASS_PARAMETER
                                                               TYPE_DS, &ans_auth_add.authority, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
                                zdb_query_ex_answer_append_type_rrsigs(rr_label_authority, authority_qname, TYPE_DS,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       delegation_signer->ttl, &ans_auth_add.authority, pool);
#endif
                            }
                            else
                            {
#if ZDB_HAS_NSEC3_SUPPORT
                                if(ZONE_NSEC3_AVAILABLE(zone))
                                {
                                    // add ... ? it looks like the record that covers the path that has been found in the zone
                                    // is used for the digest, then the interval is shown
                                    // add apex NSEC3 (wildcard)

                                    zdb_query_ex_append_nsec3_delegation(zone, &rr_label_info, &name, top,
                                                                         PASS_ZCLASS_PARAMETER
                                                                         &ans_auth_add.authority, pool);
                                }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                else
#endif
                                if(ZONE_NSEC_AVAILABLE(zone))
                                {
                                    /*
                                     * Append the NSEC of rr_label and all its signatures
                                     */

                                    s32 min_ttl;
                                    zdb_zone_getminttl(zone, &min_ttl);
                                    zdb_query_ex_append_nsec_records(rr_label_authority, authority_qname, min_ttl,
                                                                     PASS_ZCLASS_PARAMETER
                                                                     &ans_auth_add.authority, pool);

                                }
#endif
                            }
                        }

                        ans_auth_add.delegation = 1; // no answer, NS records in authority : referral
#if DEBUG
                        log_debug("zdb_query_and_update: FP_BASIC_LABEL_NOTFOUND (done)");
#endif
                        /* ans_auth_add.is_delegation = TRUE; later */

                        message_set_status(mesg, FP_BASIC_LABEL_DELEGATION);
                        zdb_query_message_update(mesg, &ans_auth_add);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        log_pool_usage(mesg, pool);
                        return; // FP_BASIC_LABEL_DELEGATION;
                    }
                }
                else
                {
                    message_set_authoritative(mesg);
                }
            }

            /* LABEL NOT FOUND: We stop the processing and fall through NSEC(3) or the basic case. */

            UNLOCK(zone);

            /* Stop looking, skip cache */
            break;

        } /* if(zone!=NULL) */

        sp--;
    } /* while ... */

    /*************************************************
     *                                               *
     * At this point we are not an authority anymore. *
     *                                               *
     *************************************************/


    /*if(authority_required) { */
    /*
     * Get the most relevant label (lowest zone).
     * Try to do NSEC3 or NSEC with it.
     */

    zdb_zone* zone;

#if DEBUG
    zone = (zdb_zone*)~0;
#endif

    sp = top;           // top >= 0, so we can enter here and zone is assigned

    yassert(sp >= 0);

    while(sp >= 0)      // scan-build false positive: we ALWAYS get into this loop at least once
    {
        zdb_zone_label* zone_label = zone_label_stack[sp--];

        if((zone = zone_label->zone) != NULL)
        {
            /* if type == DS && zone->origin = qname then the return value is NOERROR instead of NXDOMAIN */
            break;
        }
    }

    if(zone == NULL)    // zone is ALWAYS assigned because top is >= 0
    {
#if DEBUG
        log_debug("zdb_query_and_update: FP_NOZONE_FOUND (2)");
#endif

        message_set_status(mesg, FP_NOZONE_FOUND);
        zdb_query_message_update(mesg, &ans_auth_add);
        zdb_query_ex_answer_destroy(&ans_auth_add);

        // ??? zone_pointer_out->apex->flags |= ZDB_RR_LABEL_MASTER_OF;
#if HAS_DYNAMIC_PROVISIONING
        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
        log_pool_usage(mesg, pool);
        return; // FP_NOZONE_FOUND;
    }

    LOCK(zone);

    if(!zdb_zone_invalid(zone))
    {
        // zone is the most relevant zone
#if ZDB_HAS_DNSSEC_SUPPORT
        if(dnssec)
        {
#if ZDB_HAS_NSEC3_SUPPORT
            if(ZONE_NSEC3_AVAILABLE(zone))
            {
                //nsec3_zone *n3 = zone->nsec.nsec3;

                u8 *next_closer_owner = NULL;
                zdb_packed_ttlrdata* next_closer;
                const zdb_packed_ttlrdata* next_closer_rrsig;

                u8 *closer_encloser_owner = NULL;
                zdb_packed_ttlrdata* closer_encloser;
                const zdb_packed_ttlrdata* closer_encloser_rrsig;

                u8 *wild_closer_encloser_owner = NULL;
                zdb_packed_ttlrdata* wild_closer_encloser;
                const zdb_packed_ttlrdata* wild_closer_encloser_rrsig;
#if DEBUG
                log_debug("nsec3_name_error");
#endif
                nsec3_name_error(
                    zone, &name, top, pool,

                    &next_closer_owner,
                    &next_closer,
                    &next_closer_rrsig,

                    &closer_encloser_owner,
                    &closer_encloser,
                    &closer_encloser_rrsig,

                    &wild_closer_encloser_owner,
                    &wild_closer_encloser,
                    &wild_closer_encloser_rrsig);

                s32 min_ttl;
                zdb_zone_getminttl(zone, &min_ttl);
                zdb_query_ex_answer_append_soa_rrsig_nttl(zone, &ans_auth_add.authority, pool);
                //zdb_query_ex_answer_append_soa_rrsig_ttl0(zone, &ans_auth_add.authority, pool);
#if DEBUG
                log_debug("zdb_query_and_update: nsec3_name_error: next_closer_owner: %{dnsname}", next_closer_owner);
#endif
                if(next_closer != NULL /*&& next_closer_rrsig != NULL*/)
                {
                    zdb_query_ex_answer_append_ttl(next_closer, next_closer_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, &ans_auth_add.authority, pool);

                    if(next_closer_rrsig != NULL)
                    {
                        zdb_query_ex_answer_appendlist_ttl(next_closer_rrsig, next_closer_owner,
                                                           PASS_ZCLASS_PARAMETER
                                                           TYPE_RRSIG, min_ttl, &ans_auth_add.authority, pool);
                    }
                }

                if(closer_encloser != NULL/* && closer_encloser_rrsig != NULL*/)
                {
#if DEBUG
                    log_debug("zdb_query_and_update: nsec3_name_error: closer_encloser_owner: %{dnsname}", closer_encloser_owner);
#endif
                    zdb_query_ex_answer_append_ttl(closer_encloser, closer_encloser_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, &ans_auth_add.authority, pool);

                    if(closer_encloser_rrsig != NULL)
                    {
                        zdb_query_ex_answer_appendlist_ttl(closer_encloser_rrsig, closer_encloser_owner,
                                                           PASS_ZCLASS_PARAMETER
                                                           TYPE_RRSIG, min_ttl, &ans_auth_add.authority, pool);
                    }
                }

                if(wild_closer_encloser != NULL)
                {
#if DEBUG
                    log_debug("zdb_query_and_update: nsec3_name_error: wild_closer_encloser_owner: %{dnsname}", wild_closer_encloser_owner);
#endif
                    zdb_query_ex_answer_append_ttl(wild_closer_encloser, wild_closer_encloser_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, &ans_auth_add.authority, pool);

                    if(wild_closer_encloser_rrsig != NULL)
                    {
                        zdb_query_ex_answer_appendlist_ttl(wild_closer_encloser_rrsig, wild_closer_encloser_owner,
                                                           PASS_ZCLASS_PARAMETER
                                                           TYPE_RRSIG, min_ttl, &ans_auth_add.authority, pool);
                    }
                }
#if DEBUG
                log_debug("zdb_query_and_update: FP_NSEC3_LABEL_NOTFOUND (done)");
#endif
                message_set_status(mesg, FP_NSEC3_LABEL_NOTFOUND);
                zdb_query_message_update(mesg, &ans_auth_add);
                zdb_query_ex_answer_destroy(&ans_auth_add);

                UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                log_pool_usage(mesg, pool);
                return; // FP_NSEC3_LABEL_NOTFOUND;
            }
#endif /* ZDB_HAS_NSEC3_SUPPORT != 0 */

                /* NSEC, if possible */
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
            else /* Following will be either the NSEC answer or just the SOA added in the authority */
#endif
            if(ZONE_NSEC_AVAILABLE(zone))
            {
                /*
                 * Unknown and not in the cache : NSEC
                 *
                 */

                /*
                 * zone label stack
                 *
                 * #0 : top
                 * #1 : com, org, ...
                 * #2 : example, ...
                 *
                 * Which is the inverse of the dnslabel stack
                 *
                 * dnslabel stack
                 *
                 * #0 : example
                 * #1 : com
                 * #2 : NOTHING ("." is not stored)
                 *
                 *
                 */

                /*
                 * Get the SOA + NSEC + RRIGs for the zone
                 */

                //zdb_rr_label *apex_label = zone->apex;
                zdb_query_ex_answer_append_soa_rrsig_nttl(zone, &ans_auth_add.authority, pool);

                u8 *encloser_nsec_name = NULL;
                u8 *wild_encloser_nsec_name = NULL;
                zdb_rr_label *encloser_nsec_label;
                zdb_rr_label *wildencloser_nsec_label;

                nsec_name_error(zone, &name, rr_label_info.closest_index, // VS false positive: reaching this point, rr_label_info is initialized
                                pool,
                                &encloser_nsec_name, &encloser_nsec_label,
                                &wild_encloser_nsec_name, &wildencloser_nsec_label);

                if(encloser_nsec_label != NULL)
                {
                    zdb_packed_ttlrdata *encloser_nsec_rr = zdb_record_find(&encloser_nsec_label->resource_record_set, TYPE_NSEC);

                    if(encloser_nsec_rr != NULL)
                    {
                        zdb_query_ex_answer_append(encloser_nsec_rr, encloser_nsec_name,
                                                   DECLARE_ZCLASS_PARAMETER
                                                   TYPE_NSEC, &ans_auth_add.authority, pool);

                        zdb_query_ex_answer_append_type_rrsigs(encloser_nsec_label, encloser_nsec_name, TYPE_NSEC,
                                                               DECLARE_ZCLASS_PARAMETER
                                                               encloser_nsec_rr->ttl, &ans_auth_add.authority, pool);

                        if(wildencloser_nsec_label != encloser_nsec_label)
                        {
                            zdb_packed_ttlrdata *wildencloser_nsec_rr = zdb_record_find(&wildencloser_nsec_label->resource_record_set, TYPE_NSEC);

                            if(wildencloser_nsec_rr != NULL)
                            {
                                zdb_query_ex_answer_append(wildencloser_nsec_rr, wild_encloser_nsec_name,
                                                           DECLARE_ZCLASS_PARAMETER
                                                           TYPE_NSEC, &ans_auth_add.authority, pool);

                                zdb_query_ex_answer_append_type_rrsigs(wildencloser_nsec_label, wild_encloser_nsec_name, TYPE_NSEC,
                                                                       DECLARE_ZCLASS_PARAMETER
                                                                       wildencloser_nsec_rr->ttl, &ans_auth_add.authority, pool);
                            }
                        }
                    }
                }
#if DEBUG
                log_debug("zdb_query_and_update: FP_NSEC_LABEL_NOTFOUND (done)");
#endif
                message_set_status(mesg, FP_NSEC_LABEL_NOTFOUND);
                zdb_query_message_update(mesg, &ans_auth_add);
                zdb_query_ex_answer_destroy(&ans_auth_add);

                UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                log_pool_usage(mesg, pool);
                return; // FP_NSEC_LABEL_NOTFOUND;
            }
#endif // ZDB_HAS_NSEC_SUPPORT
        }
#endif // ZDB_HAS_DNSSEC_SUPPORT

        zdb_query_ex_answer_append_soa_nttl(zone, &ans_auth_add.authority, pool);
#if DEBUG
        log_debug("zdb_query_and_update: FP_BASIC_LABEL_NOTFOUND (done)");
#endif

        message_set_status(mesg, FP_BASIC_LABEL_NOTFOUND);
        zdb_query_message_update(mesg, &ans_auth_add);
        zdb_query_ex_answer_destroy(&ans_auth_add);

        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
        log_pool_usage(mesg, pool);
        return; // FP_BASIC_LABEL_NOTFOUND;
    }
    else // if(!zdb_zone_invalid(zone))
    {
#if DEBUG
        log_debug("zdb_query_and_update: FP_ZONE_EXPIRED (2)");
#endif

        message_set_status(mesg, FP_INVALID_ZONE);
        zdb_query_message_update(mesg, &ans_auth_add);
        zdb_query_ex_answer_destroy(&ans_auth_add);

        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
        log_pool_usage(mesg, pool);
        return; // FP_INVALID_ZONE;
    }
}

/**
 * @brief Queries the database given a message
 *
 * @param db the database
 * @param mesg the message
 * @param pool_buffer a big enough buffer used for the memory pool
 *
 * @return the status of the message (probably useless)
 */

ya_result
zdb_query_and_update_with_rrl(zdb *db, message_data *mesg, u8 * restrict pool_buffer, rrl_process_callback *rrl_process)
{
    zdb_query_ex_answer ans_auth_add;

    const u8 *qname = message_get_canonised_fqdn(mesg);
#if ZDB_RECORDS_MAX_CLASS != 1
    const u16 zclass = message_get_query_class(mesg);
#endif

    zdb_rr_label_find_ext_data rr_label_info;

    u16 type = message_get_query_type(mesg);
    const process_flags_t flags = zdb_query_process_flags;

    /** Check that we are even allowed to handle that class */
#if ZDB_RECORDS_MAX_CLASS == 1
    if(message_get_query_class(mesg) != CLASS_IN)
    {
#if DEBUG
        log_debug("zdb_query_and_update_with_rrl: FP_CLASS_NOTFOUND");
#endif
        return FP_CLASS_NOTFOUND;
    }

    zdb_query_ex_answer_create(&ans_auth_add);

#endif
#if HAS_DYNAMIC_PROVISIONING
    zdb_lock(db, ZDB_MUTEX_READER);
#endif
#if ZDB_RECORDS_MAX_CLASS != 1
    u16 host_zclass = ntohs(zclass); /* no choice */
    if(host_zclass > ZDB_RECORDS_MAX_CLASS)
    {
        return FP_CLASS_NOTFOUND;
    }
#endif

    bool dnssec = message_has_rcode_ext_dnssec(mesg);

    /**
     *  MANDATORY, INITIALISES A LOCAL MEMORY POOL
     *
     *  This is actually a macro found in dnsname_set.h
     */

    dnsname_vector name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(qname, &name);

    u8 * restrict * pool = &pool_buffer;

    /*
     * Find closest matching label
     * Should return a stack of zones
     */

    zdb_zone_label_pointer_array zone_label_stack;

    s32 top = zdb_zone_label_match(db, &name, zone_label_stack);

    s32 sp = top;

    zdb_packed_ttlrdata* answer;

    /* This flag means that there HAS to be an authority section */

    bool authority_required = flags & PROCESS_FL_AUTHORITY_AUTH;

    /* This flag means the names in the authority must be (internally) resolved if possible */

    bool additionals_required = flags & PROCESS_FL_ADDITIONAL_AUTH;

    switch(type)
    {
        case TYPE_DNSKEY:
        {
            authority_required = FALSE;
            additionals_required = FALSE;
            break;
        }
    }

    /* Got a stack of zone labels with and without zone cuts */
    /* Search the label on the zone files */

    /* While we have labels along the path */

    if(type == TYPE_DS)         // This is the only type that can only be found outside of the zone
    {                           // In order to avoid to hit said zone, I skip the last label.
        if(name.size == sp - 1) // we have a perfect match (DS for an APEX), try to get outside ...
        {
            s32 parent_sp = sp;

            while(--parent_sp >= 0)
            {
                /* Get the "bottom" label (top being ".") */

                zdb_zone_label* zone_label = zone_label_stack[parent_sp];

                /* Is there a zone file at this level ? If yes, search into it. */

                if(zone_label->zone != NULL)
                {
                    // got it.
                    sp = parent_sp;
                    message_set_authoritative_answer(mesg);
                    break;
                }
            }

            authority_required = FALSE;
        }
    }

    while(sp >= 0)
    {
        /* Get the "bottom" label (top being ".") */

        zdb_zone_label* zone_label = zone_label_stack[sp];

        /* Is there a zone file at this level ? If yes, search into it. */

        if(zone_label->zone != NULL)
        {

            zdb_zone *zone = zone_label->zone;

            /*
             * lock
             */

            LOCK(zone);

#if DEBUG
            log_debug("zdb_query_and_update_with_rrl: zone %{dnsname}, flags=%x", zone->origin, zdb_rr_label_flag_get(zone->apex));
#endif

            /*
             * We know the zone, and its extension here ...
             */

            {
                /*
                 * Filter handling (ACL)
                 * NOTE: the return code has to be fingerprint-based
                 */

                if(FAIL(zone->query_access_filter(mesg, zone->acl)))
                {
#if DEBUG
                    log_debug("zdb_query_and_update_with_rrl: FP_ACCESS_REJECTED");
#endif
                    message_set_status(mesg, FP_INVALID_ZONE);
                    ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                    zdb_query_ex_answer_destroy(&ans_auth_add);

                    UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                    zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                    return rrl;
                }
            }

            /**
             * The ACL have been passed so ... now check that the zone is valid
             */

            if(zdb_zone_invalid(zone))
            {
                /**
                 * @note the blocks could be reversed and jump if the zone is invalid (help the branch prediction)
                 */
#if DEBUG
                log_debug("zdb_query_and_update_with_rrl: FP_ZONE_EXPIRED");
#endif
                message_set_status(mesg, FP_INVALID_ZONE);
                ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                zdb_query_ex_answer_destroy(&ans_auth_add);

                UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                return rrl;
            }

            //message_set_authoritative(mesg);

            dnsname_set additionals_dname_set;
            dnsname_set_init(&additionals_dname_set);

            /*
             * In one query, get the authority and the closest (longest) path to the domain we are looking for.
             */

            zdb_rr_label *rr_label = zdb_rr_label_find_ext(zone->apex, name.labels, name.size - sp, &rr_label_info);

            /* Has a label been found ? */

            if(rr_label != NULL)
            {
                /*
                 * Got the label.  I will not find anything relevant by going
                 * up to another zone file.
                 *
                 * We set the AA bit iff we are not at or under a delegation.
                 *
                 * The ZDB_RR_LABEL_DELEGATION flag means the label is a delegation.
                 * This means that it only contains NS & DNSSEC records + may have sub-labels for glues
                 *
                 * ZDB_RR_LABEL_UNDERDELEGATION means we are below a ZDB_RR_LABEL_DELEGATION label
                 *
                 */

                /*
                 * CNAME alias handling
                 */

                if(((zdb_rr_label_flag_get(rr_label) & (ZDB_RR_LABEL_HASCNAME|ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION)) == ZDB_RR_LABEL_HASCNAME) &&
                   (type != TYPE_CNAME) && (type != TYPE_ANY) && (type != TYPE_RRSIG))
                {
                    /*
                    * The label is an alias:
                    *
                    * Add the CNAME and restart the query from the alias
                    */

                    if(ans_auth_add.depth >= ZDB_CNAME_LOOP_MAX)
                    {
                        log_warn("CNAME depth at %{dnsname} is bigger than allowed %d>=%d", qname, ans_auth_add.depth, ZDB_CNAME_LOOP_MAX);

                        message_set_authoritative(mesg);

                        message_set_status(mesg, FP_CNAME_MAXIMUM_DEPTH);
                        ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);

                        // stop there
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return rrl;
                    }

                    ans_auth_add.depth++;

                    if((answer = zdb_record_find(&rr_label->resource_record_set, TYPE_CNAME)) != NULL)
                    {
                        /* The RDATA in answer is the fqdn to a label with an A record (list) */
                        /* There can only be one cname for a given owner */
                        /* Append all A/AAAA records associated to the CNAME AFTER the CNAME record */

                        zdb_resourcerecord *rr = ans_auth_add.answer;

                        u32 cname_depth_count = 0; /* I don't want to allocate that globally for now */

                        while(rr != NULL)
                        {
                            if((rr->rtype == TYPE_CNAME) && (ZDB_PACKEDRECORD_PTR_RDATAPTR(rr->ttl_rdata) == ZDB_PACKEDRECORD_PTR_RDATAPTR(answer)))
                            {
                                /* LOOP */

                                log_warn("CNAME loop at %{dnsname}", qname);

                                message_set_authoritative(mesg);

                                message_set_status(mesg, FP_CNAME_LOOP);
                                ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                                zdb_query_ex_answer_destroy(&ans_auth_add);

                                UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                                return rrl;
                            }

                            cname_depth_count++;

                            rr = rr->next;
                        }

                        u8* cname_owner = *pool;

                        *pool += ALIGN16(dnsname_copy(*pool, qname));

                        /* ONE record */
                        zdb_query_ex_answer_append(answer, cname_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_CNAME, &ans_auth_add.answer, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
                        if(dnssec)
                        {
                            zdb_query_ex_answer_append_type_rrsigs(rr_label, cname_owner, TYPE_CNAME,
                                                                   PASS_ZCLASS_PARAMETER
                                                                   answer->ttl, &ans_auth_add.answer, pool);

                            // take the STAR of the label, add it to authority

                        }
#endif
                        message_set_canonised_fqdn(mesg, ZDB_PACKEDRECORD_PTR_RDATAPTR(answer));

                        finger_print fp = zdb_query_from_cname(db, mesg, &ans_auth_add, zone, pool_buffer);

                        message_set_authoritative(mesg); /// @note 20200520 EDF -- flag missing in the test
                        message_set_status(mesg, fp);
                        ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return rrl;
                    }
                    else
                    {
                        /*
                        * We expected a CNAME record but found none.
                        * This is NOT supposed to happen.
                        *
                        */

                        message_set_status(mesg, FP_CNAME_BROKEN);
                        ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return rrl;
                    }
                }

                if(zdb_rr_label_flag_isclear(rr_label, (ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION) ))
                {
                    message_set_authoritative(mesg);
                    authority_required = FALSE;
                }
                else
                {
                    /*
                     * we are AT or UNDER a delegation
                     * We can only find (show) NS, DS, RRSIG, NSEC records from the query
                     *
                     * The answer WILL be a referral ...
                     */

                    switch(type)
                    {
                        /* for these ones : give the rrset for the type and clear AA */
                        case TYPE_DS:
                        {
                            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                            {
                                message_set_authoritative(mesg);
                            }
                            else if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_UNDERDELEGATION))
                            {
                                message_disable_authoritative(mesg);
                            }
                            authority_required = FALSE;
                            break;
                        }
                        case TYPE_NSEC:
                        {
                            if(zdb_rr_label_flag_isclear(rr_label, ZDB_RR_LABEL_UNDERDELEGATION))
                            {
                                message_set_authoritative(mesg);
                            }
                            break;
                        }
                            /* for these ones : give the rrset for the type */
                        case TYPE_NS:
                            ans_auth_add.delegation = 1; // that may be stupid
                            break;
                            /* for this one : present the delegation */
                        case TYPE_ANY:
                            ans_auth_add.delegation = 1;
                            authority_required = FALSE;
                            break;
                            /* for the rest : NSEC ? */
                        default:
                            ans_auth_add.delegation = 1;
                            /*
                             * do not try to look for it
                             *
                             * faster: go to label but no record, but let's avoid gotos ...
                             */
                            type = 0;
                            break;
                    }
                }

                /*
                 * First let's handle "simple" cases.  ANY will be handled in another part of the code.
                 */

                if(type != TYPE_ANY)
                {
                    /*
                     * From the label that has been found, get the RRSET for the required type (zdb_packed_ttlrdata*)
                     */

                    if((answer = zdb_record_find(&rr_label->resource_record_set, type)) != NULL)
                    {
                        /* A match has been found */

                        /* NS case */

                        if(type == TYPE_NS)
                        {
                            zdb_resourcerecord **section;

                            /*
                             * If the label is a delegation, the NS have to be added into authority,
                             * else they have to be added into answer.
                             *
                             */

                            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                            {
                                section = &ans_auth_add.authority;
                                /* ans_auth_add.is_delegation = TRUE; later */
                            }
                            else
                            {
                                section = &ans_auth_add.answer;
                            }

                            /*
                             * Add the NS records in random order in the right section
                             *
                             */

                            zdb_query_ex_answer_appendrndlist(answer, qname,
                                                              PASS_ZCLASS_PARAMETER
                                                              type, section, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
                            /*
                             * Append all the RRSIG of NS from the label
                             */

                            if(dnssec)
                            {
                                zdb_query_ex_answer_append_type_rrsigs(rr_label, qname, TYPE_NS,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       answer->ttl, section, pool);

                                if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                                {
                                    zdb_packed_ttlrdata* label_ds = zdb_record_find(&rr_label->resource_record_set, TYPE_DS);

                                    if(label_ds != NULL)
                                    {
                                        zdb_query_ex_answer_appendlist(label_ds, qname,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       TYPE_DS, &ans_auth_add.authority, pool);
                                        zdb_query_ex_answer_append_type_rrsigs(rr_label, qname, TYPE_DS,
                                                                               PASS_ZCLASS_PARAMETER
                                                                               label_ds->ttl, &ans_auth_add.authority, pool);
                                    }
#if ZDB_HAS_NSEC3_SUPPORT
                                    else if(ZONE_NSEC3_AVAILABLE(zone))
                                    {
                                        /**
                                         * If there is an NSEC3 RR that matches the delegation name, then that
                                         * NSEC3 RR MUST be included in the response.  The DS bit in the type
                                         * bit maps of the NSEC3 RR MUST NOT be set.
                                         *
                                         * If the zone is Opt-Out, then there may not be an NSEC3 RR
                                         * corresponding to the delegation.  In this case, the closest provable
                                         * encloser proof MUST be included in the response.  The included NSEC3
                                         * RR that covers the "next closer" name for the delegation MUST have
                                         * the Opt-Out flag set to one.  (Note that this will be the case unless
                                         * something has gone wrong).
                                         *
                                         */

                                        zdb_query_ex_append_nsec3_delegation(zone, &rr_label_info, &name, top,
                                                                             PASS_ZCLASS_PARAMETER
                                                                             &ans_auth_add.authority, pool);
                                    }
#endif
#if ZDB_HAS_NSEC_SUPPORT
                                    else
                                    if(ZONE_NSEC_AVAILABLE(zone))
                                    {
                                        /*
                                         * Append the NSEC of rr_label and all its signatures
                                         */

                                        s32 min_ttl;
                                        zdb_zone_getminttl(zone, &min_ttl);

                                        zdb_query_ex_append_nsec_records(rr_label, qname, min_ttl,
                                                                         PASS_ZCLASS_PARAMETER
                                                                         &ans_auth_add.authority, pool);
                                    }
#endif
                                }
                            }
#endif
                            /*
                             * authority is never required since we have it already
                             *
                             */

                            /*
                             * fetch all the additional records for the required type (NS and MX types)
                             * add them to the additional section
                             */

                            if(additionals_required)
                            {
                                update_additionals_dname_set(answer,
                                                             PASS_ZCLASS_PARAMETER
                                                             type, &additionals_dname_set);
                                append_additionals_dname_set(zone,
                                                             PASS_ZCLASS_PARAMETER
                                                             &additionals_dname_set, &ans_auth_add.additional, pool, dnssec);
                            }
                        }
                        else /* general case */
                        {
                            /*
                             * Add the records from the answer in random order to the answer section
                             */

                            zdb_query_ex_answer_appendrndlist(answer, qname,
                                                              PASS_ZCLASS_PARAMETER
                                                              type, &ans_auth_add.answer, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
                            /*
                             * Append all the RRSIG of NS from the label
                             */

                            if(dnssec)
                            {
                                zdb_query_ex_answer_append_type_rrsigs(rr_label, qname, type,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       answer->ttl, &ans_auth_add.answer, pool);

                                if(IS_WILD_LABEL(rr_label->name))
                                {
                                    /**
                                     * If there is a wildcard match for QNAME and QTYPE, then, in addition
                                     * to the expanded wildcard RRSet returned in the answer section of the
                                     * response, proof that the wildcard match was valid must be returned.
                                     *
                                     * This proof is accomplished by proving that both QNAME does not exist
                                     * and that the closest encloser of the QNAME and the immediate ancestor
                                     * of the wildcard are the same (i.e., the correct wildcard matched).
                                     *
                                     * To this end, the NSEC3 RR that covers the "next closer" name of the
                                     * immediate ancestor of the wildcard MUST be returned.
                                     * It is not necessary to return an NSEC3 RR that matches the closest
                                     * encloser, as the existence of this closest encloser is proven by
                                     * the presence of the expanded wildcard in the response.
                                     */
#if ZDB_HAS_NSEC3_SUPPORT
                                    if(ZONE_NSEC3_AVAILABLE(zone))
                                    {
                                        zdb_query_ex_append_wild_nsec3_data(zone, rr_label, &name, top,
                                                                            PASS_ZCLASS_PARAMETER
                                                                            &ans_auth_add.authority, pool);
                                    }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                    else
#endif
                                    if(ZONE_NSEC_AVAILABLE(zone))
                                    {
                                        /* add the NSEC of the wildcard and its signature(s) */

                                        zdb_query_ex_add_nsec_interval(zone, &name, NULL, &ans_auth_add.authority, pool);
                                    }
#endif
                                }
                            }
#endif
                            /*
                             * if authority required
                             */

                            if(authority_required)
                            {
                                if((type == TYPE_NSEC || type == TYPE_DS) && (rr_label_info.authority != zone->apex))
                                {
                                    rr_label_info.authority = zone->apex;
                                    rr_label_info.authority_index = sp - 1;
                                }

                                zdb_packed_ttlrdata* authority = append_authority(qname,
                                                                                  PASS_ZCLASS_PARAMETER
                                                                                  &rr_label_info, &ans_auth_add.authority, pool, dnssec);

                                if(additionals_required)
                                {
                                    update_additionals_dname_set(authority,
                                                                 PASS_ZCLASS_PARAMETER
                                                                 TYPE_NS, &additionals_dname_set);
                                }
                            }

                            /*
                             * fetch all the additional records for the required type (NS and MX types)
                             * add them to the additional section
                             */

                            if(additionals_required)
                            {
                                update_additionals_dname_set(answer,
                                                             PASS_ZCLASS_PARAMETER
                                                             type, &additionals_dname_set);
                                append_additionals_dname_set(zone,
                                                             PASS_ZCLASS_PARAMETER
                                                             &additionals_dname_set, &ans_auth_add.additional, pool, dnssec);
                            } /* resolve authority */
                        }
#if DEBUG
                        log_debug("zdb_query_and_update_with_rrl: FP_BASIC_RECORD_FOUND");
#endif
                        message_set_status(mesg, FP_BASIC_RECORD_FOUND);
                        ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        log_pool_usage(mesg, pool);
                        return rrl;
                    } /* if found the record of the requested type */
                    else
                    {
                        /* label but no record */

                        /**
                        * Got the label, but not the record.
                        * This should branch to NSEC3 if it is supported.
                        */

                        finger_print fp;

                        if(ZONE_NSEC_AVAILABLE(zone) || ZONE_NSEC3_AVAILABLE(zone))
                        {
                            fp = (finger_print)zdb_query_ex_record_not_found_nttl(zone,
                                                                                  &rr_label_info,
                                                                                  qname,
                                                                                  &name,
                                                                                  sp,
                                                                                  top,
                                                                                  type,
                                                                                  PASS_ZCLASS_PARAMETER
                                                                                  pool,
                                                                                  dnssec,
                                                                                  &ans_auth_add,
                                                                                  &additionals_dname_set);
                        }
                        else
                        {
                            fp = (finger_print)zdb_query_ex_record_not_found(zone,
                                                                             &rr_label_info,
                                                                             qname,
                                                                             &name,
                                                                             sp,
                                                                             top,
                                                                             type,
                                                                             PASS_ZCLASS_PARAMETER
                                                                             pool,
                                                                             dnssec,
                                                                             &ans_auth_add,
                                                                             &additionals_dname_set);
                        }
#if DEBUG
                        log_debug("zdb_query_and_update_with_rrl: FP_BASIC_RECORD_NOTFOUND (done)");
#endif
                        message_set_status(mesg, fp);
                        ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        return rrl;
                    }
                }
                else /* We got the label BUT type == TYPE_ANY */
                {
                    if(zdb_rr_label_flag_isclear(rr_label, (ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION) ))
                    {
                        zdb_packed_ttlrdata *soa = NULL;

#if ZDB_HAS_DNSSEC_SUPPORT
                        zdb_packed_ttlrdata *rrsig_list = zdb_record_find(&rr_label->resource_record_set, TYPE_RRSIG);
#endif

                        bool answers = FALSE;

                        /* We do iterate on ALL the types of the label */

                        btree_iterator iter;
                        btree_iterator_init(rr_label->resource_record_set, &iter);

                        while(btree_iterator_hasnext(&iter))
                        {
                            btree_node* nodep = btree_iterator_next_node(&iter);

                            u16 type = nodep->hash;

                            answers = TRUE;

                            zdb_packed_ttlrdata* ttlrdata = (zdb_packed_ttlrdata*)nodep->data;

                            /**
                             * @note: doing the list once may be faster ...
                             *        And YES maybe, because of the jump and because the list is supposed to
                             *        be VERY small (like 1-3)
                             */

                            switch(type)
                            {
                                case TYPE_SOA:
                                {
                                    soa = ttlrdata;
                                    continue;
                                }
                                case TYPE_NS:
                                {
                                    /* NO NEED FOR AUTHORITY */
                                    authority_required = FALSE;
                                }
                                    FALLTHROUGH // fall through
                                case TYPE_MX:
                                case TYPE_CNAME:
                                {
                                    /* ADD MX "A/AAAA/GLUE" TO ADDITIONAL */

                                    if(additionals_required)
                                    {
                                        update_additionals_dname_set(ttlrdata,
                                                                     PASS_ZCLASS_PARAMETER
                                                                     type, &additionals_dname_set);
                                    }
                                    break;
                                }
                                case TYPE_RRSIG:
                                {
                                    // signatures will be added by type
                                    continue;
                                }
                                default:
                                {
                                    break;
                                }
                            }

                            zdb_query_ex_answer_appendrndlist(ttlrdata, qname,
                                                              PASS_ZCLASS_PARAMETER
                                                              type, &ans_auth_add.answer, pool);

#if ZDB_HAS_DNSSEC_SUPPORT
                            if(rrsig_list != NULL)
                            {
                                zdb_query_ex_answer_append_type_rrsigs_from(rrsig_list, qname, type,
                                                                            PASS_ZCLASS_PARAMETER
                                                                            ttlrdata->ttl, &ans_auth_add.answer, pool);
                            }
#endif
                        }

                        /* now we can insert the soa, if any has been found, at the head of the list */

                        if(soa != NULL)
                        {
                            zdb_resourcerecord* soa_rr = zdb_query_ex_answer_make(soa, qname,
                                                                                  PASS_ZCLASS_PARAMETER
                                                                                  TYPE_SOA, pool);
                            soa_rr->next = ans_auth_add.answer;
                            ans_auth_add.answer = soa_rr;
#if ZDB_HAS_DNSSEC_SUPPORT
                            if(rrsig_list != NULL)
                            {
                                zdb_query_ex_answer_append_type_rrsigs_from(rrsig_list, qname, TYPE_SOA,
                                                                            PASS_ZCLASS_PARAMETER
                                                                            soa_rr->ttl, &ans_auth_add.answer, pool);
                            }
#endif
                        }

                        if(answers)
                        {
                            if(authority_required)
                            {   // not at or under a delegation
                                zdb_packed_ttlrdata* authority = append_authority(qname,
                                                                                  PASS_ZCLASS_PARAMETER
                                                                                  &rr_label_info, &ans_auth_add.authority, pool, dnssec);

                                if(additionals_required)
                                {
                                    update_additionals_dname_set(authority,
                                                                 PASS_ZCLASS_PARAMETER
                                                                 TYPE_NS, &additionals_dname_set);
                                }

                            } /* if authority required */

                            if(additionals_required)
                            {
                                append_additionals_dname_set(zone,
                                                             PASS_ZCLASS_PARAMETER
                                                             &additionals_dname_set, &ans_auth_add.additional, pool, dnssec);
                            }

#if ZDB_HAS_DNSSEC_SUPPORT
                            if(dnssec && IS_WILD_LABEL(rr_label->name))
                            {
                                /**
                                 * If there is a wildcard match for QNAME and QTYPE, then, in addition
                                 * to the expanded wildcard RRSet returned in the answer section of the
                                 * response, proof that the wildcard match was valid must be returned.
                                 *
                                 * This proof is accomplished by proving that both QNAME does not exist
                                 * and that the closest encloser of the QNAME and the immediate ancestor
                                 * of the wildcard are the same (i.e., the correct wildcard matched).
                                 *
                                 * To this end, the NSEC3 RR that covers the "next closer" name of the
                                 * immediate ancestor of the wildcard MUST be returned.
                                 * It is not necessary to return an NSEC3 RR that matches the closest
                                 * encloser, as the existence of this closest encloser is proven by
                                 * the presence of the expanded wildcard in the response.
                                 */

#if ZDB_HAS_NSEC3_SUPPORT
                                if(ZONE_NSEC3_AVAILABLE(zone))
                                {
                                    zdb_query_ex_append_wild_nsec3_data(zone, rr_label, &name, top,
                                                                        PASS_ZCLASS_PARAMETER
                                                                        &ans_auth_add.authority, pool);
                                }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                else
#endif
                                if(ZONE_NSEC_AVAILABLE(zone))
                                {
                                    /* add the NSEC of the wildcard and its signature(s) */

                                    zdb_query_ex_add_nsec_interval(zone, &name, NULL, &ans_auth_add.authority, pool);
                                }
#endif
                            }
#endif // ZDB_HAS_DNSSEC_SUPPORT

#if DEBUG
                            log_debug("zdb_query_and_update_with_rrl: FP_BASIC_RECORD_FOUND (any)");
#endif
                            message_set_status(mesg, FP_BASIC_RECORD_FOUND);
                            ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                            zdb_query_ex_answer_destroy(&ans_auth_add);

                            UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                            zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                            log_pool_usage(mesg, pool);
                            return rrl;
                        }
                        else
                        {
                            /* no records found ... */

                            finger_print fp;
                            if(ZONE_NSEC_AVAILABLE(zone) || ZONE_NSEC3_AVAILABLE(zone))
                            {
                                fp = (finger_print)zdb_query_ex_record_not_found_nttl(zone,
                                                                                      &rr_label_info,
                                                                                      qname,
                                                                                      &name,
                                                                                      sp,
                                                                                      top,
                                                                                      TYPE_ANY,
                                                                                      PASS_ZCLASS_PARAMETER
                                                                                      pool,
                                                                                      dnssec,
                                                                                      &ans_auth_add,
                                                                                      &additionals_dname_set);
                            }
                            else
                            {
                                fp = (finger_print)zdb_query_ex_record_not_found(zone,
                                                                                 &rr_label_info,
                                                                                 qname,
                                                                                 &name,
                                                                                 sp,
                                                                                 top,
                                                                                 TYPE_ANY,
                                                                                 PASS_ZCLASS_PARAMETER
                                                                                 pool,
                                                                                 dnssec,
                                                                                 &ans_auth_add,
                                                                                 &additionals_dname_set);
                            }

                            message_set_status(mesg, fp);
                            ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                            zdb_query_ex_answer_destroy(&ans_auth_add);

                            UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                            zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                            log_pool_usage(mesg, pool);
                            return rrl;
                        }
                    }
                    else
                    {   /* ANY, at or under a delegation */

                        zdb_query_ex_record_not_found(zone,
                                                      &rr_label_info,
                                                      qname,
                                                      &name,
                                                      sp,
                                                      top,
                                                      0,
                                                      PASS_ZCLASS_PARAMETER
                                                      pool,
                                                      dnssec,
                                                      &ans_auth_add,
                                                      &additionals_dname_set);

                        message_set_status(mesg, FP_BASIC_RECORD_FOUND);
                        ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        log_pool_usage(mesg, pool);
                        return rrl;
                    }
                }
            }       /* end of if rr_label!=NULL => */
            else    /* rr_label == NULL */
            {
                zdb_rr_label* rr_label_authority = rr_label_info.authority;

                if(rr_label_authority != zone->apex)
                {
                    message_disable_authoritative(mesg);

                    zdb_packed_ttlrdata *authority = zdb_record_find(&rr_label_authority->resource_record_set, TYPE_NS);

                    if(authority != NULL)
                    {

                        const u8 * authority_qname = zdb_rr_label_info_get_authority_qname(qname, &rr_label_info);

                        zdb_query_ex_answer_appendrndlist(authority, authority_qname,
                                                          PASS_ZCLASS_PARAMETER
                                                          TYPE_NS, &ans_auth_add.authority, pool);
                        update_additionals_dname_set(authority,
                                                     PASS_ZCLASS_PARAMETER
                                                     TYPE_NS, &additionals_dname_set);
                        append_additionals_dname_set(zone,
                                                     PASS_ZCLASS_PARAMETER
                                                     &additionals_dname_set, &ans_auth_add.additional, pool, FALSE);

                        if(dnssec)
                        {
#if ZDB_HAS_DNSSEC_SUPPORT
                            zdb_query_ex_answer_append_type_rrsigs(rr_label_authority, authority_qname, TYPE_NS,
                                                                   PASS_ZCLASS_PARAMETER
                                                                   authority->ttl, &ans_auth_add.authority, pool);
#endif

                            zdb_packed_ttlrdata *delegation_signer = zdb_record_find(&rr_label_authority->resource_record_set, TYPE_DS);

                            if(delegation_signer != NULL)
                            {
                                zdb_query_ex_answer_appendlist(delegation_signer , authority_qname,
                                                               PASS_ZCLASS_PARAMETER
                                                               TYPE_DS, &ans_auth_add.authority, pool);
#if ZDB_HAS_DNSSEC_SUPPORT
                                zdb_query_ex_answer_append_type_rrsigs(rr_label_authority, authority_qname, TYPE_DS,
                                                                       PASS_ZCLASS_PARAMETER
                                                                       delegation_signer->ttl, &ans_auth_add.authority, pool);
#endif
                            }
                            else
                            {
#if ZDB_HAS_NSEC3_SUPPORT
                                if(ZONE_NSEC3_AVAILABLE(zone))
                                {
                                    // add ... ? it looks like the record that covers the path that has been found in the zone
                                    // is used for the digest, then the interval is shown
                                    // add apex NSEC3 (wildcard)

                                    zdb_query_ex_append_nsec3_delegation(zone, &rr_label_info, &name, top,
                                                                         PASS_ZCLASS_PARAMETER
                                                                         &ans_auth_add.authority, pool);
                                }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                else
#endif
                                if(ZONE_NSEC_AVAILABLE(zone))
                                {
                                    /*
                                     * Append the NSEC of rr_label and all its signatures
                                     */

                                    s32 min_ttl;
                                    zdb_zone_getminttl(zone, &min_ttl);
                                    zdb_query_ex_append_nsec_records(rr_label_authority, authority_qname, min_ttl,
                                                                     PASS_ZCLASS_PARAMETER
                                                                     &ans_auth_add.authority, pool);

                                }
#endif
                            }
                        }

                        ans_auth_add.delegation = 1; // no answer, NS records in authority : referral
#if DEBUG
                        log_debug("zdb_query_and_update_with_rrl: FP_BASIC_LABEL_NOTFOUND (done)");
#endif
                        /* ans_auth_add.is_delegation = TRUE; later */

                        message_set_status(mesg, FP_BASIC_LABEL_DELEGATION);
                        ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                        zdb_query_ex_answer_destroy(&ans_auth_add);

                        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                        log_pool_usage(mesg, pool);
                        return rrl;
                    }
                }
                else
                {
                    message_set_authoritative(mesg);
                }
            }

            /* LABEL NOT FOUND: We stop the processing and fall through NSEC(3) or the basic case. */

            UNLOCK(zone);

            /* Stop looking, skip cache */
            break;

        } /* if(zone!=NULL) */

        sp--;
    } /* while ... */

    /*************************************************
     *                                               *
     * At this point we are not an authority anymore. *
     *                                               *
     *************************************************/


    /*if(authority_required) { */
    /*
     * Get the most relevant label (lowest zone).
     * Try to do NSEC3 or NSEC with it.
     */

    zdb_zone* zone;

#if DEBUG
    zone = (zdb_zone*)~0;
#endif

    sp = top;           // top >= 0, so we can enter here and zone is assigned

    yassert(sp >= 0);

    while(sp >= 0)      // scan-build false positive: we ALWAYS get into this loop at least once
    {
        zdb_zone_label* zone_label = zone_label_stack[sp--];

        if((zone = zone_label->zone) != NULL)
        {
            /* if type == DS && zone->origin = qname then the return value is NOERROR instead of NXDOMAIN */
            break;
        }
    }

    if(zone == NULL)    // zone is ALWAYS assigned because top is >= 0
    {
#if DEBUG
        log_debug("zdb_query_and_update_with_rrl: FP_NOZONE_FOUND (2)");
#endif

        message_set_status(mesg, FP_NOZONE_FOUND);
        ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
        zdb_query_ex_answer_destroy(&ans_auth_add);

        // ??? zone_pointer_out->apex->flags |= ZDB_RR_LABEL_MASTER_OF;
#if HAS_DYNAMIC_PROVISIONING
        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
        log_pool_usage(mesg, pool);
        return rrl;
    }

    LOCK(zone);

    if(!zdb_zone_invalid(zone))
    {
        // zone is the most relevant zone
#if ZDB_HAS_DNSSEC_SUPPORT
        if(dnssec)
        {
#if ZDB_HAS_NSEC3_SUPPORT
            if(ZONE_NSEC3_AVAILABLE(zone))
            {
                //nsec3_zone *n3 = zone->nsec.nsec3;

                u8 *next_closer_owner = NULL;
                zdb_packed_ttlrdata* next_closer;
                const zdb_packed_ttlrdata* next_closer_rrsig;

                u8 *closer_encloser_owner = NULL;
                zdb_packed_ttlrdata* closer_encloser;
                const zdb_packed_ttlrdata* closer_encloser_rrsig;

                u8 *wild_closer_encloser_owner = NULL;
                zdb_packed_ttlrdata* wild_closer_encloser;
                const zdb_packed_ttlrdata* wild_closer_encloser_rrsig;
#if DEBUG
                log_debug("nsec3_name_error");
#endif
                nsec3_name_error(
                    zone, &name, top, pool,

                    &next_closer_owner,
                    &next_closer,
                    &next_closer_rrsig,

                    &closer_encloser_owner,
                    &closer_encloser,
                    &closer_encloser_rrsig,

                    &wild_closer_encloser_owner,
                    &wild_closer_encloser,
                    &wild_closer_encloser_rrsig);

                s32 min_ttl;
                zdb_zone_getminttl(zone, &min_ttl);
                zdb_query_ex_answer_append_soa_rrsig_nttl(zone, &ans_auth_add.authority, pool);
                //zdb_query_ex_answer_append_soa_rrsig_ttl0(zone, &ans_auth_add.authority, pool);
#if DEBUG
                log_debug("zdb_query_and_update_with_rrl: nsec3_name_error: next_closer_owner: %{dnsname}", next_closer_owner);
#endif
                if(next_closer != NULL /*&& next_closer_rrsig != NULL*/)
                {
                    zdb_query_ex_answer_append_ttl(next_closer, next_closer_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, &ans_auth_add.authority, pool);

                    if(next_closer_rrsig != NULL)
                    {
                        zdb_query_ex_answer_appendlist_ttl(next_closer_rrsig, next_closer_owner,
                                                           PASS_ZCLASS_PARAMETER
                                                           TYPE_RRSIG, min_ttl, &ans_auth_add.authority, pool);
                    }
                }

                if(closer_encloser != NULL/* && closer_encloser_rrsig != NULL*/)
                {
#if DEBUG
                    log_debug("zdb_query_and_update_with_rrl: nsec3_name_error: closer_encloser_owner: %{dnsname}", closer_encloser_owner);
#endif
                    zdb_query_ex_answer_append_ttl(closer_encloser, closer_encloser_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, &ans_auth_add.authority, pool);

                    if(closer_encloser_rrsig != NULL)
                    {
                        zdb_query_ex_answer_appendlist_ttl(closer_encloser_rrsig, closer_encloser_owner,
                                                           PASS_ZCLASS_PARAMETER
                                                           TYPE_RRSIG, min_ttl, &ans_auth_add.authority, pool);
                    }
                }

                if(wild_closer_encloser != NULL)
                {
#if DEBUG
                    log_debug("zdb_query_and_update_with_rrl: nsec3_name_error: wild_closer_encloser_owner: %{dnsname}", wild_closer_encloser_owner);
#endif
                    zdb_query_ex_answer_append_ttl(wild_closer_encloser, wild_closer_encloser_owner,
                                                   PASS_ZCLASS_PARAMETER
                                                   TYPE_NSEC3, min_ttl, &ans_auth_add.authority, pool);

                    if(wild_closer_encloser_rrsig != NULL)
                    {
                        zdb_query_ex_answer_appendlist_ttl(wild_closer_encloser_rrsig, wild_closer_encloser_owner,
                                                           PASS_ZCLASS_PARAMETER
                                                           TYPE_RRSIG, min_ttl, &ans_auth_add.authority, pool);
                    }
                }
#if DEBUG
                log_debug("zdb_query_and_update_with_rrl: FP_NSEC3_LABEL_NOTFOUND (done)");
#endif
                message_set_status(mesg, FP_NSEC3_LABEL_NOTFOUND);
                ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                zdb_query_ex_answer_destroy(&ans_auth_add);

                UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                log_pool_usage(mesg, pool);
                return rrl;
            }
#endif /* ZDB_HAS_NSEC3_SUPPORT != 0 */

                /* NSEC, if possible */
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
            else /* Following will be either the NSEC answer or just the SOA added in the authority */
#endif
            if(ZONE_NSEC_AVAILABLE(zone))
            {
                /*
                 * Unknown and not in the cache : NSEC
                 *
                 */

                /*
                 * zone label stack
                 *
                 * #0 : top
                 * #1 : com, org, ...
                 * #2 : example, ...
                 *
                 * Which is the inverse of the dnslabel stack
                 *
                 * dnslabel stack
                 *
                 * #0 : example
                 * #1 : com
                 * #2 : NOTHING ("." is not stored)
                 *
                 *
                 */

                /*
                 * Get the SOA + NSEC + RRIGs for the zone
                 */

                //zdb_rr_label *apex_label = zone->apex;
                zdb_query_ex_answer_append_soa_rrsig_nttl(zone, &ans_auth_add.authority, pool);

                u8 *encloser_nsec_name = NULL;
                u8 *wild_encloser_nsec_name = NULL;
                zdb_rr_label *encloser_nsec_label;
                zdb_rr_label *wildencloser_nsec_label;

                nsec_name_error(zone, &name, rr_label_info.closest_index, // VS false positive: reaching this point, rr_label_info is initialized
                                pool,
                                &encloser_nsec_name, &encloser_nsec_label,
                                &wild_encloser_nsec_name, &wildencloser_nsec_label);

                if(encloser_nsec_label != NULL)
                {
                    zdb_packed_ttlrdata *encloser_nsec_rr = zdb_record_find(&encloser_nsec_label->resource_record_set, TYPE_NSEC);

                    if(encloser_nsec_rr != NULL)
                    {
                        zdb_query_ex_answer_append(encloser_nsec_rr, encloser_nsec_name,
                                                   DECLARE_ZCLASS_PARAMETER
                                                   TYPE_NSEC, &ans_auth_add.authority, pool);

                        zdb_query_ex_answer_append_type_rrsigs(encloser_nsec_label, encloser_nsec_name, TYPE_NSEC,
                                                               DECLARE_ZCLASS_PARAMETER
                                                               encloser_nsec_rr->ttl, &ans_auth_add.authority, pool);

                        if(wildencloser_nsec_label != encloser_nsec_label)
                        {
                            zdb_packed_ttlrdata *wildencloser_nsec_rr = zdb_record_find(&wildencloser_nsec_label->resource_record_set, TYPE_NSEC);

                            if(wildencloser_nsec_rr != NULL)
                            {
                                zdb_query_ex_answer_append(wildencloser_nsec_rr, wild_encloser_nsec_name,
                                                           DECLARE_ZCLASS_PARAMETER
                                                           TYPE_NSEC, &ans_auth_add.authority, pool);

                                zdb_query_ex_answer_append_type_rrsigs(wildencloser_nsec_label, wild_encloser_nsec_name, TYPE_NSEC,
                                                                       DECLARE_ZCLASS_PARAMETER
                                                                       wildencloser_nsec_rr->ttl, &ans_auth_add.authority, pool);
                            }
                        }
                    }
                }
#if DEBUG
                log_debug("zdb_query_and_update_with_rrl: FP_NSEC_LABEL_NOTFOUND (done)");
#endif
                message_set_status(mesg, FP_NSEC_LABEL_NOTFOUND);
                ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
                zdb_query_ex_answer_destroy(&ans_auth_add);

                UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
                zdb_unlock(db, ZDB_MUTEX_READER);
#endif
                log_pool_usage(mesg, pool);
                return rrl;
            }
#endif // ZDB_HAS_NSEC_SUPPORT
        }
#endif // ZDB_HAS_DNSSEC_SUPPORT

        zdb_query_ex_answer_append_soa_nttl(zone, &ans_auth_add.authority, pool);
#if DEBUG
        log_debug("zdb_query_and_update_with_rrl: FP_BASIC_LABEL_NOTFOUND (done)");
#endif

        message_set_status(mesg, FP_BASIC_LABEL_NOTFOUND);
        ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
        zdb_query_ex_answer_destroy(&ans_auth_add);

        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
        log_pool_usage(mesg, pool);
        return rrl;
    }
    else // if(!zdb_zone_invalid(zone))
    {
#if DEBUG
        log_debug("zdb_query_and_update_with_rrl: FP_ZONE_EXPIRED (2)");
#endif

        message_set_status(mesg, FP_INVALID_ZONE);
        ya_result rrl = zdb_query_message_update_with_rrl(mesg, &ans_auth_add, rrl_process);
        zdb_query_ex_answer_destroy(&ans_auth_add);

        UNLOCK(zone);
#if HAS_DYNAMIC_PROVISIONING
        zdb_unlock(db, ZDB_MUTEX_READER);
#endif
        log_pool_usage(mesg, pool);
        return rrl;
    }
}

/** @} */

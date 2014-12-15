/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#include <unistd.h>
#include <arpa/inet.h>

#ifdef DEBUG
#include <dnscore/format.h>
#endif

#include <dnscore/mutex.h>

#include <dnscore/dnscore.h>

#include <dnscore/logger.h>

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_error.h"

#include "dnsdb/zdb_dnsname.h"
#include "dnsdb/dnsrdata.h"

#include "dnsdb/zdb_listener.h"

#include "dnsdb/journal.h"

#if ZDB_HAS_NSEC_SUPPORT != 0
#include "dnsdb/nsec.h"
#endif
#if ZDB_HAS_NSEC3_SUPPORT != 0
#include "dnsdb/nsec3.h"
#endif

#ifdef DEBUG
#define ZONE_MUTEX_LOG 0    // set this to 0 to disable in DEBUG
#else
#define ZONE_MUTEX_LOG 0
#endif

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

/**
 * @brief Unloads and destroys a zone.
 *
 * Unloads and destroys a zone.
 *
 * @param[in] db a pointer to the database
 * @param[in] exact_match_origin the name of the zone
 * @param[in] zclass the class of the zone
 *
 * @return an error code.
 *
 */

ya_result
zdb_zone_unload(zdb* db, dnsname_vector* name, u16 zclass) // mutex checked
{
    /* Find an existing label */

    zdb_zone_label* zone_label = zdb_zone_label_find(db, name, zclass);

    if(zone_label == NULL)
    {
        return ZDB_READER_ZONENOTLOADED;
    }

    /* destroy zone */

    zdb_zone *zone = zone_label->zone;
    zone_label->zone = NULL;

    if(zone != NULL)
    {
        zdb_zone_destroy(zone);
    }

    /* do we require this label for anything else ? */

    if(dictionary_isempty(&zone_label->sub)

            )
    {
        /**
         * we can destroy the label
         * 
         * @note : right usage of zdb_zone_label_delete
         * 
         */

        zdb_zone_label_delete(db, name, zclass);
    }

    return SUCCESS;
}

/**
 * @brief Get the zone with the given name
 *
 * Get the zone with the given name
 *
 * @param[in] db a pointer to the database
 * @param[in] exact_match_origin the name of the zone
 * @param[in] zclass the class of the zone
 *
 * @return a pointer to zone or NULL if the zone is not in the database
 *
 */

zdb_zone*
zdb_zone_find(zdb* db, dnsname_vector* exact_match_origin, u16 zclass) // mutex checked
{
    /* Find label */

    zdb_zone_label* zone_label = zdb_zone_label_find(db, exact_match_origin, zclass);

    return (zone_label != NULL) ? zone_label->zone : NULL;
}

/**
 * @brief Get the zone with the given name
 *
 * Get the zone with the given name
 *
 * @param[in] db a pointer to the database
 * @param[in] name the name of the zone (dotted c-string)
 * @param[in] zclass the class of the zone
 *
 * @return a pointer to zone or NULL if the zone is not in the database
 *
 */

zdb_zone*
zdb_zone_find_from_name(zdb* db, const char* name, u16 qclass) // mutex checked
{
    dnsname_vector origin;

    u8 dns_name[MAX_DOMAIN_LENGTH];

    if(ISOK(cstr_to_dnsname(dns_name, name)))
    {
        dnsname_to_dnsname_vector(dns_name, &origin);

        return zdb_zone_find(db, &origin, qclass);
    }

    return NULL;
}

/**
 * @brief Get the zone with the given dns name
 *
 * Get the zone with the given dns name
 *
 * @param[in] db a pointer to the database
 * @param[in] name the name of the zone (dns name)
 * @param[in] zclass the class of the zone
 *
 * @return a pointer to zone or NULL if the zone is not in the database
 *
 */

zdb_zone*
zdb_zone_find_from_dnsname(zdb* db, const u8 *dns_name, u16 qclass) // mutex checked
{
    dnsname_vector origin;

    dnsname_to_dnsname_vector(dns_name, &origin);

    return zdb_zone_find(db, &origin, qclass);
}

/**
 * @brief Adds a record to a zone
 *
 * Adds a record to a zone.
 *
 * @param[in] zone the zone
 * @param[in] labels the stack of labels of the dns name
 * @param[in] labels_top the index of the top of the stack (the level)
 * @param[in] type the type of the record
 * @param[in] ttlrdata the ttl and rdata of the record.  NOTE: the zone becomes its new owner !!!
 */

void
zdb_zone_record_add(zdb_zone *zone, dnslabel_vector_reference labels, s32 labels_top, u16 type, zdb_packed_ttlrdata* ttlrdata)
{
    zdb_rr_label* rr_label = zdb_rr_label_add(zone, labels, labels_top);
    /* This record will be put as it is in the DB */

#if ZDB_HAS_NSEC_SUPPORT != 0
    /*
     * At this point I could add empty nsec3 records, or schedule the nsec3 signature
     */
#endif

    u16 flag_mask = 0;

    switch(type)
    {
        case TYPE_CNAME:
        {
            if((rr_label->flags & ZDB_RR_LABEL_DROPCNAME) != 0)
            {
                log_err("zone %{dnsname}: ignoring CNAME add on non-CNAME", zone->origin);
                ZDB_RECORD_ZFREE(ttlrdata);
                return;
            }
            flag_mask = ZDB_RR_LABEL_HASCNAME;
            break;
        }
        case TYPE_RRSIG:
        case TYPE_NSEC:
            break;
        case TYPE_NS:
        {
            if( (rr_label->flags & ZDB_RR_LABEL_HASCNAME) != 0)
            {
                log_err("zone %{dnsname}: ignoring NS add on CNAME", zone->origin);
                ZDB_RECORD_ZFREE(ttlrdata);
                return;
            }

            if( (rr_label->flags & ZDB_RR_LABEL_APEX) == 0)
            {
                flag_mask = ZDB_RR_LABEL_DELEGATION;

                /* all labels under are "under delegation" */

                dictionary_iterator iter;
                dictionary_iterator_init(&rr_label->sub, &iter);
                while(dictionary_iterator_hasnext(&iter))
                {
                    zdb_rr_label** sub_labelp = (zdb_rr_label**)dictionary_iterator_next(&iter);

                    (*sub_labelp)->flags |= ZDB_RR_LABEL_UNDERDELEGATION;
                }
            }
            
            flag_mask |= ZDB_RR_LABEL_DROPCNAME;

            break;
        }
        default:
        {
            if( (rr_label->flags & ZDB_RR_LABEL_HASCNAME) != 0)
            {
                log_err("zone %{dnsname}: ignoring non-CNAME add on CNAME", zone->origin);
                ZDB_RECORD_ZFREE(ttlrdata);
                return;
            }
            flag_mask = ZDB_RR_LABEL_DROPCNAME;
            break;
        }
    }

    if(!zdb_record_insert_checked(&rr_label->resource_record_set, type, ttlrdata)) /* FB done */
    {
        ZDB_RECORD_ZFREE(ttlrdata);
        return;
    }

    rr_label->flags |= flag_mask;

#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0

    /*
     * Update ICMTL.
     *
     * NOTE: the zdb_rr_label set of functions are zdb_listener-aware but the zdb_record ones are not.
     * That's why this one needs a call to the listener.
     *
     */

    zdb_ttlrdata unpacked_ttlrdata;
    unpacked_ttlrdata.rdata_pointer = &ttlrdata->rdata_start[0];
    unpacked_ttlrdata.rdata_size = ttlrdata->rdata_size;
    unpacked_ttlrdata.ttl = ttlrdata->ttl;
    zdb_listener_notify_add_record(labels, labels_top, type, &unpacked_ttlrdata);

#endif

}

/**
 * @brief Removes a record from a zone
 *
 * Removes a record from a zone
 *
 * @param[in] zone the zone
 * @param[in] labels the stack of labels of the dns name
 * @param[in] labels_top the index of the top of the stack (the level)
 * @param[in] type the type of the record
 * @param[in] ttlrdata the ttl and rdata of the record.  NOTE: the caller stays the owner
 */


ya_result
zdb_zone_record_delete(zdb_zone *zone, dnslabel_vector_reference labels, s32 labels_top, u16 type, zdb_packed_ttlrdata* packed_ttlrdata)
{
    zdb_ttlrdata ttlrdata;

    ttlrdata.next = NULL;
    ttlrdata.rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(packed_ttlrdata);
    ttlrdata.rdata_pointer = ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata);
    ttlrdata.ttl = packed_ttlrdata->ttl;

    return zdb_rr_label_delete_record_exact(zone, labels, labels_top, type, &ttlrdata);
}

/**
 * @brief Search for a record in a zone
 *
 * Search for a record in a zone
 *
 * @param[in] zone the zone
 * @param[in] labels the stack of labels of the dns name
 * @param[in] labels_top the index of the top of the stack (the level)
 * @param[in] type the type of the record
 */

zdb_packed_ttlrdata*
zdb_zone_record_find(zdb_zone *zone, dnslabel_vector_reference labels, s32 labels_top, u16 type)
{
    zdb_rr_label* rr_label = zdb_rr_label_find_exact(zone->apex, labels, labels_top);

    if(rr_label != NULL)
    {
        return zdb_record_find(&rr_label->resource_record_set, type);
    }

    return NULL;
}

static ya_result
zdb_default_query_access_filter(const message_data *mesg, const void *extension)
{
    return SUCCESS;
}

static
u32 zdb_zone_get_struct_size(const u8 *origin)
{
    u32 zone_footprint = sizeof(zdb_zone) - sizeof(dnsname_vector) + sizeof(u8*) * (dnsname_getdepth(origin) + 1);
    
    return zone_footprint;
}

zdb_zone*
zdb_zone_create(const u8* origin, u16 zclass)
{
#if ZDB_RECORDS_MAX_CLASS == 1
    if(zclass != CLASS_IN)
    {
        return NULL; // ZDB_ERROR_NOSUCHCLASS
    }
#endif
    
    zdb_zone *zone;
    u32 zone_footprint = zdb_zone_get_struct_size(origin);
    ZALLOC_ARRAY_OR_DIE(zdb_zone*, zone, zone_footprint, ZDB_ZONETAG);
   
    log_debug7("zdb_zone_create %{dnsname}@%p", origin, zone);
            
    zone->origin = dnsname_zdup(origin);

    dnsname_to_dnsname_vector(zone->origin, &zone->origin_vector);

#if ZDB_RECORDS_MAX_CLASS != 1
    zone->zclass = zclass;
#endif
    
    zone->axfr_timestamp = 1;
    /* zone->axfr_serial = 0; implicit */

#if ZDB_HAS_DNSSEC_SUPPORT != 0
    ZEROMEMORY(&zone->nsec, sizeof (nsec_zone_union));
    zone->sig_validity_interval_seconds = 30*24*3600;       /* 1 month */
    zone->sig_validity_regeneration_seconds = 7*24*3600;    /* 1 week */
    zone->sig_validity_jitter_seconds = 86400;              /* 1 day */
    zone->sig_quota = 100;
#endif

    zone->alarm_handle = alarm_open(zone->origin);

    zone->apex = zdb_rr_label_new_instance(ROOT_LABEL);
    zone->apex->flags = ZDB_RR_LABEL_APEX;

    zone->query_access_filter = zdb_default_query_access_filter;
    zone->extension = NULL;
    mutex_init(&zone->mutex);
    zone->mutex_owner = ZDB_ZONE_MUTEX_NOBODY;
    zone->mutex_count = 0;
    zone->mutex_reserved_owner = ZDB_ZONE_MUTEX_NOBODY;
    zone->journal = NULL;
    zone->sig_last_processed_node = NULL;
    
    return zone;
}

/**
 * @brief Destroys a zone and all its content
 *
 * Destroys a zone and all its content
 *
 * @param[in] zone a pointer to the zone
 */

void
zdb_zone_truncate_invalidate(zdb_zone *zone)
{
    if(zone != NULL)
    {
        // remove all alarms linked to the zone
        alarm_close(zone->alarm_handle);
        
        zone->alarm_handle = ALARM_HANDLE_INVALID;
        
        // empty the zone records
        if(zone->apex != NULL)
        {
#if ZDB_HAS_NSEC_SUPPORT != 0
            if(zdb_zone_is_nsec(zone))
            {
                nsec_destroy_zone(zone);
            }
#endif

#if ZDB_HAS_NSEC3_SUPPORT != 0
            if(zdb_zone_is_nsec3(zone))
            {
                nsec3_destroy_zone(zone);
            }
#endif
            
            // zdb_rr_label_destroy(zone, &zone->apex);
            
            /*
             * Destroy ALL the content of the apex but not the apex itself.
             */
            
            zdb_rr_label_truncate(zone, zone->apex);
            
            zone->apex->flags |= ZDB_RR_LABEL_INVALID_ZONE;
        }
    }
}

/**
 * @brief Destroys a zone and all its content
 *
 * Destroys a zone and all its content
 *
 * @param[in] zone a pointer to the zone
 */

void
zdb_zone_destroy(zdb_zone *zone)
{     
    if(zone != NULL)
    {
        log_debug5("zdb_zone_destroy zone@%p", zone);
        
        /* zdb_rr_label_set apex;                          SOA, NS, ... */
        /* ya_result	zdb_rr_label_delete(
         *		    zdb_rr_label** apex,
         *		    dnslabel_vector_reference path,s32 path_index);
         */

        u32 lock_count = 0;
        while(!zdb_zone_trylock(zone, ZDB_ZONE_MUTEX_DESTROY))
        {
            if((lock_count++ & 0x3ff) != 0)
            {
                log_debug6("zone: waiting to destroy zone locked by #%i (wait)", zone->mutex_owner);
            }
            usleep(1000);
        }
        
        if(zone->alarm_handle != ALARM_HANDLE_INVALID)
        {
            alarm_close(zone->alarm_handle);
            zone->alarm_handle = ALARM_HANDLE_INVALID;
        }
        
        if(zone->journal != NULL)
        {
            journal_close(zone->journal);
        }
                
#ifndef DEBUG
        // do not bother clearing the memory if it's for a shutdown (faster)
        if(!dnscore_shuttingdown())
#endif
        {
            if(zone->apex != NULL)
            {

#if ZDB_HAS_NSEC_SUPPORT != 0
                if(zdb_zone_is_nsec(zone))
                {
                    nsec_destroy_zone(zone);
                }
#endif

#if ZDB_HAS_NSEC3_SUPPORT != 0
                if(zdb_zone_is_nsec3(zone))
                {
                    nsec3_destroy_zone(zone);
                }

#endif
                zdb_rr_label_destroy(zone, &zone->apex);
                zone->apex = NULL;
            }
        }
        
        u32 zone_footprint = zdb_zone_get_struct_size(zone->origin);
        
        ZFREE_STRING(zone->origin);

#ifdef DEBUG
        zone->origin = NULL;
        zone->min_ttl= 0xbadbad01;
        zone->extension = NULL;
        zone->axfr_serial = 0xbadbad00;
#endif

        mutex_destroy(&zone->mutex);
                
        ZFREE_ARRAY(zone, zone_footprint);
    }
}

/**
 * @brief Copies the soa of a zone to an soa_rdata structure.
 *
 * Copies the soa of a zone to an soa_rdata structure.
 * No memory is allocated for the soa_rdata.  If the zone is destroyed,
 * the soa_rdata becomes invalid.
 *
 * @param[in] zone a pointer to the zone
 * @param[out] soa_out a pointer to an soa_rdata structure
 */

ya_result
zdb_zone_getsoa(const zdb_zone *zone, soa_rdata* soa_out)
{
#ifdef DEBUG
    if(zone->mutex_owner == ZDB_ZONE_MUTEX_NOBODY)
    {
        log_err("zdb_zone_getsoa called on an unlocked zone: %{dnsname}", zone->origin);
        debug_log_stacktrace(MODULE_MSG_HANDLE, LOG_ERR, "zdb_zone_getsoa");
        logger_flush();
    }
    else
    {
        log_debug("zdb_zone_getsoa called on a zone locked by %02hhx (%{dnsname})", zone->mutex_owner, zone->origin);
    }
#endif
    
    const zdb_rr_label *apex = zone->apex;
    const zdb_packed_ttlrdata *soa = zdb_record_find(&apex->resource_record_set, TYPE_SOA);
    ya_result return_code;

    if(soa != NULL)
    {
        return_code = zdb_record_getsoa(soa, soa_out);
    }
    else
    {
        return_code = ZDB_ERROR_NOSOAATAPEX;
    }
    
    return return_code;
}

ya_result
zdb_zone_getsoa_ttl_rdata(const zdb_zone *zone, u32 *ttl, u16 *rdata_size, const u8 **rdata)
{
#ifdef DEBUG
    if(zone->mutex_owner == ZDB_ZONE_MUTEX_NOBODY)
    {
        log_err("zdb_zone_getsoa_ttl_rdata called on an unlocked zone: %{dnsname}", zone->origin);
        debug_log_stacktrace(MODULE_MSG_HANDLE, LOG_ERR, "zdb_zone_getsoa_ttl_rdata");
        logger_flush();
    }
    else
    {
        log_debug("zdb_zone_getsoa_ttl_rdata called on a zone locked by %02hhx (%{dnsname})", zone->mutex_owner, zone->origin);
    }
#endif
    
    const zdb_rr_label *apex = zone->apex;
    const zdb_packed_ttlrdata *soa = zdb_record_find(&apex->resource_record_set, TYPE_SOA);

    if(soa == NULL)
    {
        return ZDB_ERROR_NOSOAATAPEX;
    }

    if(ttl != NULL)
    {
        *ttl = soa->ttl;
    }

    if(rdata_size != NULL && rdata != NULL)
    {
        *rdata_size = soa->rdata_size;
        *rdata = &soa->rdata_start[0];
    }

    return SUCCESS;
}

/**
 * @brief Retrieve the serial of a zone
 *
 * Retrieve the serial of a zone
 *
 * @param[in] zone a pointer to the zone
 * @param[out] soa_out a pointer to an soa_rdata structure
 */

ya_result
zdb_zone_getserial(const zdb_zone *zone, u32 *serial)
{
#ifdef DEBUG
    if(zone->mutex_owner == ZDB_ZONE_MUTEX_NOBODY)
    {
        log_err("zdb_zone_getserial called on an unlocked zone (%{dnsname})", zone->origin);
        debug_log_stacktrace(MODULE_MSG_HANDLE, LOG_ERR, "zdb_zone_getserial");
        logger_flush();
    }
    else
    {
        log_debug("zdb_zone_getserial called on a zone locked by %02hhx (%{dnsname})", zone->mutex_owner, zone->origin);
    }
#endif
    
    yassert(serial != NULL);

    zdb_rr_label *apex = zone->apex;
    zdb_packed_ttlrdata *soa = zdb_record_find(&apex->resource_record_set, TYPE_SOA);

    if(soa != NULL)
    {
        return rr_soa_get_serial(soa->rdata_start, soa->rdata_size, serial);
    }

    return ZDB_ERROR_NOSOAATAPEX;
}

const zdb_packed_ttlrdata*
zdb_zone_get_dnskey_rrset(zdb_zone *zone)
{
    return zdb_record_find(&zone->apex->resource_record_set, TYPE_DNSKEY);
}

/*
 * Zone lock
 */

void
zdb_zone_lock(zdb_zone *zone, u8 owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("acquiring lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

    for(;;)
    {
        mutex_lock(&zone->mutex);

        /*
         * An simple way to ensure that a lock can be shared
         * by similar entities or not.
         * Sharable entities have their msb off.
         */

        u8 co = zone->mutex_owner & 0x7f;
        
        if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
        {
            yassert(zone->mutex_count != 255);

            zone->mutex_owner = owner & 0x7f;
            zone->mutex_count++;
            
#if ZONE_MUTEX_LOG
            log_debug7("acquired lock for zone %{dnsname}@%p for %x (#%i)", zone->origin, zone, owner, zone->mutex_count);
#endif
                        
            mutex_unlock(&zone->mutex);
            
            break;
        }

        mutex_unlock(&zone->mutex);

        /**
         * Don't set this too low.
         * A lock basically slows down a task to 100000Hz
         * Waiting close to 0.00001 seconds is counterproductive.
         * Given that we are using locks for slow tasks, waiting 1ms seems reasonable.
         * 
         * @todo: use broadcasts
         */

        usleep(10);
    }
}

bool
zdb_zone_trylock(zdb_zone *zone, u8 owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("trying to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

    mutex_lock(&zone->mutex);

    u8 co = zone->mutex_owner & 0x7f;
    
    if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
    {
        yassert(zone->mutex_count != 255);

        zone->mutex_owner = owner & 0x7f;
        zone->mutex_count++;

#if ZONE_MUTEX_LOG
        log_debug7("acquired lock for zone %{dnsname}@%p for %x (#%i)", zone->origin, zone, owner, zone->mutex_count);
#endif

        mutex_unlock(&zone->mutex);

        return TRUE;
    }

    mutex_unlock(&zone->mutex);

#if ZONE_MUTEX_LOG
    log_debug7("failed to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

    return FALSE;
}

void
zdb_zone_unlock(zdb_zone *zone, u8 owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("releasing lock for zone %{dnsname}@%p by %x (owned by %x)", zone->origin, zone, owner, zone->mutex_owner);
#endif

    mutex_lock(&zone->mutex);

#ifdef DEBUG
    if((zone->mutex_owner != (owner & 0x7f)) || (zone->mutex_count == 0))
    {
        logger_flush();
        mutex_unlock(&zone->mutex);
        yassert(zone->mutex_owner == (owner & 0x7f));
        yassert(zone->mutex_count != 0);
    }
#endif

    zone->mutex_count--;

#if ZONE_MUTEX_LOG
    log_debug7("released lock for zone %{dnsname}@%p by %x (#%i)", zone->origin, zone, owner, zone->mutex_count);
#endif
    
    if(zone->mutex_count == 0)
    {
        zone->mutex_owner = ZDB_ZONE_MUTEX_NOBODY;
    }
    
    mutex_unlock(&zone->mutex);
}

void
zdb_zone_double_lock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("acquiring lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

    for(;;)
    {
        mutex_lock(&zone->mutex);

        /*
         * An simple way to ensure that a lock can be shared
         * by similar entities or not.
         * Sharable entities have their msb off.
         */
        
        u8 so = zone->mutex_reserved_owner & 0x7f;
        
        if(so == ZDB_ZONE_MUTEX_NOBODY || so == secondary_owner)
        {
            u8 co = zone->mutex_owner & 0x7f;

            if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
            {
                yassert(zone->mutex_count != 255);

                zone->mutex_owner = owner & 0x7f;
                zone->mutex_count++;
                zone->mutex_reserved_owner = secondary_owner & 0x7f;
            
#if ZONE_MUTEX_LOG
                log_debug7("acquired lock for zone %{dnsname}@%p for %x (#%i)", zone->origin, zone, owner, zone->mutex_count);
#endif
                
                mutex_unlock(&zone->mutex);

                break;
            }
        }
        else
        {
            // the secondary owner is already taken
        }

        mutex_unlock(&zone->mutex);

        /*
         * Don't set this too low.
         * A lock basically slows down a task to 100000Hz
         * Waiting close to 0.00001 seconds is counterproductive.
         * Given that we are using locks for slow tasks, waiting 1ms seems reasonable.
         * 
         * todo: use broadcasts
         */

        usleep(10);
    }
}

bool
zdb_zone_try_double_lock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("trying to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

    mutex_lock(&zone->mutex);

    u8 so = zone->mutex_reserved_owner & 0x7f;
        
    if(so == ZDB_ZONE_MUTEX_NOBODY || so == secondary_owner)
    {
        u8 co = zone->mutex_owner & 0x7f;
    
        if(co == ZDB_ZONE_MUTEX_NOBODY || co == owner)
        {
            yassert(zone->mutex_count != 255);

            zone->mutex_owner = owner & 0x7f;
            zone->mutex_count++;
            zone->mutex_reserved_owner = secondary_owner & 0x7f;

#if ZONE_MUTEX_LOG
            log_debug7("acquired lock for zone %{dnsname}@%p for %x (#%i)", zone->origin, zone, owner, zone->mutex_count);
#endif

            mutex_unlock(&zone->mutex);

            return TRUE;
        }

        mutex_unlock(&zone->mutex);
    }
    else
    {
        // already double-owned
    }

#if ZONE_MUTEX_LOG
    log_debug7("failed to acquire lock for zone %{dnsname}@%p for %x", zone->origin, zone, owner);
#endif

    return FALSE;
}

void
zdb_zone_double_unlock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("releasing lock for zone %{dnsname}@%p by %x (owned by %x)", zone->origin, zone, owner, zone->mutex_owner);
#endif

    mutex_lock(&zone->mutex);

#ifdef DEBUG
    if((zone->mutex_owner != (owner & 0x7f)) || (zone->mutex_count == 0))
    {
        logger_flush();
        mutex_unlock(&zone->mutex);
        yassert(zone->mutex_owner == (owner & 0x7f));
        yassert(zone->mutex_count != 0);
    }
    
    if(zone->mutex_reserved_owner != (secondary_owner & 0x7f))
    {
        logger_flush();
        mutex_unlock(&zone->mutex);
        yassert(zone->mutex_reserved_owner != (secondary_owner & 0x7f));
    }
#endif
    
    zone->mutex_count--;
    zone->mutex_reserved_owner = ZDB_ZONE_MUTEX_NOBODY;

#if ZONE_MUTEX_LOG
    log_debug7("released lock for zone %{dnsname}@%p by %x (#%i)", zone->origin, zone, owner, zone->mutex_count);
#endif
    
    if(zone->mutex_count == 0)
    {
        zone->mutex_owner = ZDB_ZONE_MUTEX_NOBODY;
    }
    
    mutex_unlock(&zone->mutex);
}

void
zdb_zone_transfer_lock(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("transferring lock for zone %{dnsname}@%p from %x to %x (owned by %x:%x)", zone->origin, zone, owner, secondary_owner, zone->mutex_owner, zone->mutex_reserved_owner);
#endif

    mutex_lock(&zone->mutex);

#ifdef DEBUG
    if((zone->mutex_owner != (owner & 0x7f)) || (zone->mutex_count == 0))
    {
        logger_flush();
        mutex_unlock(&zone->mutex);
        yassert(zone->mutex_owner == (owner & 0x7f));
        yassert(zone->mutex_count != 0);
    }
    
    if(zone->mutex_reserved_owner != (secondary_owner & 0x7f))
    {
        logger_flush();
        mutex_unlock(&zone->mutex);
        yassert(zone->mutex_reserved_owner != (secondary_owner & 0x7f));
    }
#endif
    
    // wait to be the last one
    
    while(zone->mutex_count != 1)
    {
        mutex_unlock(&zone->mutex);
        usleep(10); /// @todo use group wait
        mutex_lock(&zone->mutex);
    }
    
    zone->mutex_owner = secondary_owner & 0x7f;
    zone->mutex_reserved_owner = ZDB_ZONE_MUTEX_NOBODY;
    

#if ZONE_MUTEX_LOG
    log_debug7("transferred lock for zone %{dnsname}@%p from %x to %x (#%i)", zone->origin, zone, owner, secondary_owner, zone->mutex_count);
#endif

    mutex_unlock(&zone->mutex);
}

void
zdb_zone_exchange_locks(zdb_zone *zone, u8 owner, u8 secondary_owner)
{
#if ZONE_MUTEX_LOG
    log_debug7("exchanging locks for zone %{dnsname}@%p from %x to %x (owned by %x:%x)", zone->origin, zone, owner, secondary_owner, zone->mutex_owner, zone->mutex_reserved_owner);
#endif

    mutex_lock(&zone->mutex);

#ifdef DEBUG
    if((zone->mutex_owner != (owner & 0x7f)) || (zone->mutex_count == 0))
    {
        logger_flush();
        mutex_unlock(&zone->mutex);
        yassert(zone->mutex_owner == (owner & 0x7f));
        yassert(zone->mutex_count != 0);
    }
    
    if(zone->mutex_reserved_owner != (secondary_owner & 0x7f))
    {
        logger_flush();
        mutex_unlock(&zone->mutex);
        yassert(zone->mutex_reserved_owner != (secondary_owner & 0x7f));
    }
#endif
    
    // wait to be the last one
    
    while(zone->mutex_count != 1)
    {
        mutex_unlock(&zone->mutex);
        usleep(10); /// @todo use group wait
        mutex_lock(&zone->mutex);
    }
    
    zone->mutex_owner = secondary_owner & 0x7f;
    zone->mutex_reserved_owner = owner & 0x7f;
    

#if ZONE_MUTEX_LOG
    log_debug7("exchanged locks for zone %{dnsname}@%p from %x to %x (#%i)", zone->origin, zone, owner, secondary_owner, zone->mutex_count);
#endif

    mutex_unlock(&zone->mutex);
}

zdb_zone*
zdb_zone_xchg_with_invalid(zdb *db, const u8 *origin, u16 zclass, u16 or_flags) // lock checked
{
    dnsname_vector name;    
    dnsname_to_dnsname_vector(origin, &name);
        
    zdb_zone_label *zone_label = zdb_zone_label_add(db, &name, zclass);
    
    zdb_zone *old = zone_label->zone;
    
    /*
     * If the zone exists and is invalid already : skip
     */
    
    if(old != NULL)
    {
        zdb_zone_lock(old, ZDB_ZONE_MUTEX_INVALIDATE);
        
        alarm_close(old->alarm_handle);
        old->alarm_handle = ALARM_HANDLE_INVALID;
        
        if((old->apex->flags & ZDB_RR_LABEL_INVALID_ZONE) == 0)
        {
            // create a dummy invalid zone
            zdb_zone *zone = zdb_zone_create(origin, zclass);

            if(zone != NULL)
            {
                // mark the dummy zone as invalid
                zone->apex->flags |= ZDB_RR_LABEL_INVALID_ZONE;

                // locks so that only readers can access it
                zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER); // see scheduler_database_replace_zone_init
                
                // so here is a rule : an invalid zone is always locked, and is only unlocked to be destroyed
            }

            log_debug("zdb_zone_xchg_with_invalid: replacing %p with %p", zone_label->zone, zone);

            zone_label->zone = zone;
        }
        
        zdb_zone_unlock(old, ZDB_ZONE_MUTEX_INVALIDATE);
    }
    else
    {
        if(old == NULL)
        {
            log_err("zdb_zone_xchg_with_invalid: no zone %{dnsname} found", origin);
        }
        else
        {
            log_err("zdb_zone_xchg_with_invalid: zone %{dnsname}@%p is invalid already", old->origin, old);
            old = NULL;
        }
    }
    
    return old;
}

bool
zdb_zone_isinvalid(zdb_zone *zone)
{
    bool invalid = TRUE;
    
    if((zone != NULL) && (zone->apex != NULL))
    {
        invalid = (zone->apex->flags & ZDB_RR_LABEL_INVALID_ZONE) != 0;
    }
    
    return invalid;
}

#ifdef DEBUG

/**
 * DEBUG
 */

void
zdb_zone_print_indented(zdb_zone *zone, output_stream *os, int indent)
{
    if(zone == NULL)
    {
        osformatln(os, "%tz: NULL", indent);
        return;
    }
    
    u16 zclass = zdb_zone_getclass(zone);

    osformatln(os, "%tzone@%p(CLASS=%{dnsclass},ORIGIN='%{dnsname}'", indent, (void*)zone, &zclass, zone->origin);
    zdb_rr_label_print_indented(zone->apex, os, indent + 1);
    osformatln(os, "%t+:", indent);
}

void
zdb_zone_print(zdb_zone *zone, output_stream *os)
{
    zdb_zone_print_indented(zone, os, 0);
}

#endif

/** @} */

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
 * @defgroup dnsdbzone Zone related functions
 * @ingroup dnsdb
 * @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 *----------------------------------------------------------------------------*/

#define DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS 0
#if DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS
#pragma message("WARNING: DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS enabled !")
#endif

#define ZDB_JOURNAL_CODE 1

#include "dnsdb/dnsdb_config.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>

#if DEBUG
#include <dnscore/format.h>
#endif

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/threaded_dll_cw.h>

#include "dnsdb/dnsdb_config.h"
#include "dnsdb/dnssec_keystore.h"
#include "dnsdb/zdb_icmtl.h"
#include "dnsdb/zdb.h"

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/zdb_error.h"

#include "dnsdb/journal.h"
#include "dnsdb/dynupdate_diff.h"
#include "dnsdb/dynupdate_message.h"
#include "dnsdb/zdb_zone_path_provider.h"

#if DNSCORE_HAS_DNSSEC_SUPPORT
#include "dnsdb/rrsig.h"
#if ZDB_HAS_NSEC_SUPPORT
#include "dnsdb/nsec.h"
#endif
#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif
#endif

#ifndef HAS_DYNUPDATE_DIFF_ENABLED
#error "HAS_DYNUPDATE_DIFF_ENABLED not defined"
#endif

#if DEBUG
#define ZONE_MUTEX_LOG 0 // set this to 0 to disable in DEBUG
#else
#define ZONE_MUTEX_LOG 0
#endif

extern logger_handle_t *g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define TMPRDATA_TAG      0x4154414452504d54

#if HAS_TRACK_ZONES_DEBUG_SUPPORT
smp_int       g_zone_instanciated_count = SMP_INT_INITIALIZER;
ptr_treemap_t g_zone_instanciated_set = PTR_TREEMAP_PTR_EMPTY;
mutex_t       g_zone_instanciated_set_mtx = MUTEX_INITIALIZER;
#endif

static void zdb_zone_record_or_and_flags_to_subdomains(zdb_rr_label_t *rr_label, uint16_t orflags, uint16_t andflags)
{
    dictionary_iterator_t iter;
    dictionary_iterator_init(&rr_label->sub, &iter);
    while(dictionary_iterator_hasnext(&iter))
    {
        zdb_rr_label_t **sub_labelp = (zdb_rr_label_t **)dictionary_iterator_next(&iter);

        zdb_rr_label_flag_or_and(*sub_labelp, orflags, andflags),

            zdb_zone_record_or_and_flags_to_subdomains(*sub_labelp, orflags, andflags);
    }
}

/**
 * @brief Adds a record to a zone
 *
 * Adds a record to a zone.
 *
 * @note Expects the full fqdn in the labels parameter. "." has a labels_top at -1
 *
 *
 * @param[in] zone the zone
 * @param[in] labels the stack of labels of the dns name
 * @param[in] labels_top the index of the top of the stack (the level)
 * @param[in] type the type of the record
 * @param[in] ttlrdata the ttl and rdata of the record.  NOTE: the zone becomes its new owner !!!
 */

void zdb_zone_record_add(zdb_zone_t *zone, dnslabel_vector_reference_t labels, int32_t labels_top, uint16_t type, int32_t ttl, zdb_resource_record_data_t *ttlrdata)
{
    zdb_rr_label_t *rr_label = zdb_rr_label_add(zone, labels, labels_top - zone->origin_vector.size - 1); // flow verified
    /* This record will be put as it is in the DB */

#if ZDB_HAS_NSEC_SUPPORT
    /*
     * At this point I could add empty nsec3 records, or schedule the nsec3 signature
     */
#endif

    uint16_t flag_mask = 0;

    switch(type)
    {
        case TYPE_CNAME:
        {
            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DROPCNAME))
            {
                log_err("zone %{dnsname}: ignoring CNAME add on non-CNAME", zone->origin);
                zdb_resource_record_data_delete(ttlrdata);
                return;
            }
            flag_mask = ZDB_RR_LABEL_HASCNAME;
            break;
        }
        case TYPE_RRSIG:
        {
            if(!zdb_resource_record_sets_insert_record_checked_keep_ttl(&rr_label->resource_record_set, type, ttl, ttlrdata)) /* FB done */
            {
                zdb_resource_record_data_delete(ttlrdata);
                return;
            }

            zdb_rr_label_flag_or(rr_label, flag_mask);

            return;
        }
        case TYPE_NSEC:
            break;
        case TYPE_NS:
        {
            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_HASCNAME))
            {
                log_err("zone %{dnsname}: ignoring NS add on CNAME", zone->origin);
                zdb_resource_record_data_delete(ttlrdata);
                return;
            }

            if(zdb_rr_label_is_not_apex(rr_label))
            {
                // handle the sub-delegation case

                if(zdb_rr_label_flag_isclear(rr_label, ZDB_RR_LABEL_UNDERDELEGATION))
                {
                    flag_mask = ZDB_RR_LABEL_DELEGATION;

                    // if(!ZDB_LABEL_UNDERDELEGATION(flag_mask & ZDB_RR_LABEL_UNDERDELEGATION))
                    {
                        /* all labels under are "under delegation" */

                        // zdb_zone_record_or_flags_to_subdomains(rr_label, ZDB_RR_LABEL_UNDERDELEGATION);
                        zdb_zone_record_or_and_flags_to_subdomains(rr_label, ZDB_RR_LABEL_UNDERDELEGATION, ~ZDB_RR_LABEL_DELEGATION);
                    }
                }
            }

            flag_mask |= ZDB_RR_LABEL_DROPCNAME /*| ZDB_RR_LABEL_HAS_NS*/;

            break;
        }
        case TYPE_DS:
        {
            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_HASCNAME))
            {
                log_err("zone %{dnsname}: ignoring non-CNAME add on CNAME", zone->origin);
                zdb_resource_record_data_delete(ttlrdata);
                return;
            }

            flag_mask |= ZDB_RR_LABEL_DROPCNAME /*| ZDB_RR_LABEL_HAS_DS*/;
            break;
        }
        default:
        {
            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_HASCNAME))
            {
                log_err("zone %{dnsname}: ignoring non-CNAME add on CNAME", zone->origin);
                zdb_resource_record_data_delete(ttlrdata);
                return;
            }
            flag_mask = ZDB_RR_LABEL_DROPCNAME;
            break;
        }
    }

    if(!zdb_resource_record_sets_insert_record_checked(&rr_label->resource_record_set, type, ttl, ttlrdata)) /* FB done */
    {
        zdb_resource_record_data_delete(ttlrdata);
        return;
    }

    zdb_rr_label_flag_or(rr_label, flag_mask);
}

void zdb_zone_record_add_with_mp(zdb_zone_t *zone, dnslabel_vector_reference_t labels, int32_t labels_top, uint16_t type, int32_t ttl, zdb_resource_record_data_t *ttlrdata, memory_pool_t *mp)
{
    zdb_rr_label_t *rr_label = zdb_rr_label_add(zone, labels, labels_top - zone->origin_vector.size - 1); // flow verified
    /* This record will be put as it is in the DB */

#if ZDB_HAS_NSEC_SUPPORT
    /*
     * At this point I could add empty nsec3 records, or schedule the nsec3 signature
     */
#endif

    uint16_t flag_mask = 0;

    switch(type)
    {
        case TYPE_CNAME:
        {
            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DROPCNAME))
            {
                log_err("zone %{dnsname}: ignoring CNAME add on non-CNAME", zone->origin);
                zdb_resource_record_data_delete(ttlrdata);
                return;
            }
            flag_mask = ZDB_RR_LABEL_HASCNAME;
            break;
        }
        case TYPE_RRSIG:
        {
#define ZDB_ZONE_RECORD_ADD_RRSIG_WITH_MP 0 // appears to be counter-productive
#if !ZDB_ZONE_RECORD_ADD_RRSIG_WITH_MP
            if(!zdb_resource_record_sets_insert_record_checked_keep_ttl(&rr_label->resource_record_set, type, ttl,
                                                                        ttlrdata)) // FB done
            {
                zdb_resource_record_data_delete(ttlrdata);
                return;
            }
#else
            if(!zdb_resource_record_sets_insert_record_checked_keep_ttl_with_mp(&rr_label->resource_record_set, type, ttl, ttlrdata, mp)) // FB done
            {
                zdb_resource_record_data_delete(ttlrdata);
                return;
            }
#endif
            zdb_rr_label_flag_or(rr_label, flag_mask);

            return;
        }
        case TYPE_NSEC:
            break;
        case TYPE_NS:
        {
            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_HASCNAME))
            {
                log_err("zone %{dnsname}: ignoring NS add on CNAME", zone->origin);
                zdb_resource_record_data_delete(ttlrdata);
                return;
            }

            if(zdb_rr_label_is_not_apex(rr_label))
            {
                // handle the sub-delegation case

                if(zdb_rr_label_flag_isclear(rr_label, ZDB_RR_LABEL_UNDERDELEGATION))
                {
                    flag_mask = ZDB_RR_LABEL_DELEGATION;

                    // if(!ZDB_LABEL_UNDERDELEGATION(flag_mask & ZDB_RR_LABEL_UNDERDELEGATION))
                    {
                        /* all labels under are "under delegation" */

                        // zdb_zone_record_or_flags_to_subdomains(rr_label, ZDB_RR_LABEL_UNDERDELEGATION);
                        zdb_zone_record_or_and_flags_to_subdomains(rr_label, ZDB_RR_LABEL_UNDERDELEGATION, ~ZDB_RR_LABEL_DELEGATION);
                    }
                }
            }

            flag_mask |= ZDB_RR_LABEL_DROPCNAME /*| ZDB_RR_LABEL_HAS_NS*/;

            break;
        }
        case TYPE_DS:
        {
            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_HASCNAME))
            {
                log_err("zone %{dnsname}: ignoring non-CNAME add on CNAME", zone->origin);
                zdb_resource_record_data_delete(ttlrdata);
                return;
            }

            flag_mask |= ZDB_RR_LABEL_DROPCNAME /*| ZDB_RR_LABEL_HAS_DS*/;
            break;
        }
        default:
        {
            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_HASCNAME))
            {
                log_err("zone %{dnsname}: ignoring non-CNAME add on CNAME", zone->origin);
                zdb_resource_record_data_delete(ttlrdata);
                return;
            }
            flag_mask = ZDB_RR_LABEL_DROPCNAME;
            break;
        }
    }

    if(!zdb_resource_record_sets_insert_record_checked_with_mp(&rr_label->resource_record_set, type, ttl, ttlrdata, mp)) /* FB done */
    {
        zdb_resource_record_data_delete(ttlrdata);
        return;
    }

    zdb_rr_label_flag_or(rr_label, flag_mask);
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
 *
 * @return a pointer to the RRSET or NULL if it was not found
 */

zdb_resource_record_set_t *zdb_zone_find_resource_record_set(zdb_zone_t *zone, dnslabel_vector_reference_t labels, int32_t labels_top, uint16_t type)
{
    zdb_rr_label_t *rr_label = zdb_rr_label_find_exact(zone->apex, labels, labels_top);

    if(rr_label != NULL)
    {
        zdb_resource_record_set_t *ret;
        ret = zdb_resource_record_sets_find(&rr_label->resource_record_set, type);
        return ret;
    }

    return NULL;
}

/**
 * Searches the zone for the zdb_rr_label of an fqdn if it exists.
 *
 * @param[in] zone the zone
 * @parma[in] fqdn the fqdn of the the label
 *
 * @return a pointer the label, or NULL if it was not found.
 */

zdb_rr_label_t *zdb_zone_find_label_from_fqdn(zdb_zone_t *zone, const uint8_t *fqdn)
{
    dnslabel_vector_t labels;
    int32_t           labels_top = dnsname_to_dnslabel_vector(fqdn, labels);
    zdb_rr_label_t   *label = zdb_rr_label_find_exact(zone->apex, labels, labels_top - zone->origin_vector.size - 1);
    return label;
}

static ya_result zdb_default_query_access_filter(const dns_message_t *mesg, const void *extension)
{
    (void)mesg;
    (void)extension;

    return SUCCESS;
}

static uint32_t zdb_zone_get_struct_size(const uint8_t *origin)
{
    uint32_t zone_footprint = sizeof(zdb_zone_t) - sizeof(dnsname_vector_t) + sizeof(uint8_t *) * (dnsname_getdepth(origin) + 1);

    return zone_footprint;
}

zdb_zone_t *zdb_zone_create(const uint8_t *origin)
{
    zdb_zone_t *zone;
    uint32_t    zone_footprint = zdb_zone_get_struct_size(origin);
    ZALLOC_ARRAY_OR_DIE(zdb_zone_t *, zone, zone_footprint, ZDB_ZONETAG);

#if DEBUG
    memset(zone, 0xac, zone_footprint);
#endif

#if HAS_TRACK_ZONES_DEBUG_SUPPORT
    smp_int_inc(&g_zone_instanciated_count);
    mutex_lock(&g_zone_instanciated_set_mtx);
    ptr_treemap_node_t *node = ptr_treemap_insert(&g_zone_instanciated_set, zone);
    mutex_unlock(&g_zone_instanciated_set_mtx);
    node->value = NULL;
#endif

    log_debug7("zdb_zone_create %{dnsname}@%p", origin, zone);

    zone->origin = dnsname_zdup(origin);

    dnsname_to_dnsname_vector(zone->origin, &zone->origin_vector);

#if ZDB_RECORDS_CLASS_MAX > 1
    zone->zclass = CLASS_IN;
#elif ZDB_RECORDS_CLASS_MAX <= 0
#error "ZDB_RECORDS_CLASS_MAX must be > 0"
#endif

    zone->axfr_timestamp = 1;
    /* zone->axfr_serial = 0; implicit */

#if ZDB_HAS_DNSSEC_SUPPORT
    ZEROMEMORY(&zone->nsec, sizeof(dnssec_zone_extension_t));
    zone->sig_validity_interval_seconds = 30 * 24 * 3600;    /* 1 month */
    zone->sig_validity_regeneration_seconds = 7 * 24 * 3600; /* 1 week */
    zone->sig_validity_jitter_seconds = 86400;               /* 1 day */
    zone->sig_quota = 100;

#if DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS
    zone->sig_validity_regeneration_seconds = 90;
    zone->sig_validity_interval_seconds = 180;
    zone->sig_validity_jitter_seconds = 5;
#endif

#endif

    zone->alarm_handle = alarm_open(zone->origin);

    zone->apex = zdb_rr_label_new_instance(ROOT_LABEL);
    zone->apex->_flags = ZDB_RR_LABEL_APEX;

    zone->query_access_filter = zdb_default_query_access_filter;
    zone->acl = NULL;
#if ZDB_HAS_DNSSEC_SUPPORT
    zone->progressive_signature_update.current_fqdn = NULL;
    zone->progressive_signature_update.earliest_signature_expiration = INT32_MAX;
    zone->progressive_signature_update.labels_at_once = ZDB_ZONE_MAINTENANCE_LABELS_AT_ONCE_DEFAULT;
#endif
    mutex_init(&zone->lock_mutex);
    cond_init(&zone->lock_cond);
    zone->rc = 1;
    zone->lock_owner = ZDB_ZONE_MUTEX_NOBODY;
    zone->lock_count = 0;
    zone->lock_reserved_owner = ZDB_ZONE_MUTEX_NOBODY;
    atomic_store(&zone->_status, 0);
    zone->_flags = 0;
#if ZDB_HAS_OLD_MUTEX_DEBUG_SUPPORT
    zone->lock_trace = NULL;
    zone->lock_id = 0;
    zone->lock_timestamp = 0;
#endif
#if ZDB_ZONE_HAS_JNL_REFERENCE
    zone->journal = NULL;
#endif

    return zone;
}

void zdb_zone_invalidate(zdb_zone_t *zone)
{
    yassert(zone != NULL);

    zdb_zone_set_invalid(zone);
}

/**
 * @brief Destroys a zone and all its content
 *
 * Destroys a zone and all its content
 *
 * @param[in] zone a pointer to the zone
 */

void zdb_zone_truncate_invalidate(zdb_zone_t *zone)
{
    if(zone != NULL)
    {
        // remove all alarms linked to the zone
        alarm_close(zone->alarm_handle);
        zone->alarm_handle = ALARM_HANDLE_INVALID;

        // empty the zone records
        if(zone->apex != NULL)
        {
#if ZDB_HAS_NSEC_SUPPORT
            nsec_destroy_zone(zone);
#endif

#if ZDB_HAS_NSEC3_SUPPORT
            nsec3_destroy_zone(zone);
#endif

            // zdb_rr_label_destroy(zone, &zone->apex);

            /*
             * Destroy ALL the content of the apex but not the apex itself.
             */

            zdb_rr_label_truncate(zone, zone->apex);

            zdb_zone_set_invalid(zone);
        }
    }
}

void zdb_zone_destroy_nolock(zdb_zone_t *zone)
{
    if(zone != NULL)
    {
        assert(zone->rc == 0);

        log_debug("zone: %{dnsname}: releasing memory (nolock)", zone->origin);

        int rc = zone->rc;

        if(rc != 0)
        {
            log_debug("zone: %{dnsname}: rc=%i != 0 (nolock)", zone->origin, rc);
        }

#if HAS_TRACK_ZONES_DEBUG_SUPPORT
        mutex_lock(&g_zone_instanciated_set_mtx);
        bool known_zone = (ptr_treemap_find(&g_zone_instanciated_set, zone) != NULL);
        yassert(known_zone);
        ptr_treemap_delete(&g_zone_instanciated_set, zone);

        mutex_unlock(&g_zone_instanciated_set_mtx);
        smp_int_dec(&g_zone_instanciated_count);
        yassert(smp_int_get(&g_zone_instanciated_count) >= 0);
#endif

        if(zone->alarm_handle != ALARM_HANDLE_INVALID)
        {
            log_debug("zone: %{dnsname}: removing alarm events (%p) (nolock)", zone->origin, zone->alarm_handle);

            alarm_close(zone->alarm_handle);
            zone->alarm_handle = ALARM_HANDLE_INVALID;
        }

#if ZDB_ZONE_HAS_JNL_REFERENCE
        if(zone->journal != NULL)
        {
            journal *jh = zone->journal; // pointed for closing/releasing
            journal_close(jh);           // only authorised usage of this call
            zone->journal = NULL;
        }
#endif

#if !DEBUG
        // do not bother clearing the memory if it's for a shutdown (faster)
        if(!dnscore_shuttingdown())
#endif
        {
            if(zone->apex != NULL)
            {

#if ZDB_HAS_NSEC_SUPPORT
                log_debug("zone: %{dnsname}: deleting NSEC chain (if any) (nolock)", zone->origin);

                nsec_destroy_zone(zone);
#endif

#if ZDB_HAS_NSEC3_SUPPORT
                log_debug("zone: %{dnsname}: deleting NSEC3 chain (if any) (nolock)", zone->origin);

                nsec3_destroy_zone(zone);
#endif
                log_debug("zone: %{dnsname}: deleting records (nolock)", zone->origin);

                zdb_rr_label_destroy(zone, &zone->apex);
                zone->apex = NULL;
            }
            else
            {
                log_debug("zone: %{dnsname}: apex is empty (nolock)", zone->origin);
            }
        }
#if !DEBUG
        else
        {
            log_debug(
                "zone: %{dnsname}: will not spend time carefully releasing the memory used by the records and the "
                "chains (shutting down) (nolock)",
                zone->origin);
        }
#endif

        uint32_t zone_footprint = zdb_zone_get_struct_size(zone->origin);

#if DNSCORE_HAS_DNSSEC_SUPPORT
        if(zone->progressive_signature_update.current_fqdn != NULL)
        {
            log_debug("zone: %{dnsname}: releasing progressive signature update (nolock)", zone->origin);

            dnsname_zfree(zone->progressive_signature_update.current_fqdn);
            zone->progressive_signature_update.current_fqdn = NULL;
        }
#endif

#if DEBUG
        zone->min_ttl = 0xbadbad01;
        zone->acl = NULL;
        zone->axfr_serial = 0xbadbad00;
#endif

        log_debug("zone: %{dnsname}: releasing name and structure (nolock)", zone->origin);

        dnsname_zfree(zone->origin);

#if DEBUG
        zone->origin = NULL;
#endif

        ZFREE_ARRAY(zone, zone_footprint);
    }
#if DEBUG
    else
    {
        log_debug("zone: NULL: zdb_zone_destroy_nolock called on NULL (nolock)");
    }
#endif
}

/**
 * @brief Destroys a zone and all its content
 *
 * Destroys a zone and all its content
 *
 * @param[in] zone a pointer to the zone
 */

void zdb_zone_destroy(zdb_zone_t *zone)
{
    if(zone != NULL)
    {
        log_debug("zone: %{dnsname}: releasing memory", zone->origin);

        zdb_zone_lock(zone, ZDB_ZONE_MUTEX_DESTROY);
        int rc = zone->rc;
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_DESTROY);

        if(rc != 0)
        {
            log_debug("zone: %{dnsname}: rc=%i != 0", zone->origin, rc);

            logger_flush();
            abort();
        }

#if HAS_TRACK_ZONES_DEBUG_SUPPORT
        mutex_lock(&g_zone_instanciated_set_mtx);
        bool known_zone = (ptr_treemap_find(&g_zone_instanciated_set, zone) != NULL);
        yassert(known_zone);
        ptr_treemap_delete(&g_zone_instanciated_set, zone);

        mutex_unlock(&g_zone_instanciated_set_mtx);
        smp_int_dec(&g_zone_instanciated_count);
        yassert(smp_int_get(&g_zone_instanciated_count) >= 0);
#endif

        zdb_zone_lock(zone, ZDB_ZONE_MUTEX_DESTROY);
        if(zone->alarm_handle != ALARM_HANDLE_INVALID)
        {
            log_debug("zone: %{dnsname}: removing alarm events (%p)", zone->origin, zone->alarm_handle);

            alarm_close(zone->alarm_handle);
            zone->alarm_handle = ALARM_HANDLE_INVALID;
        }
#if ZDB_ZONE_HAS_JNL_REFERENCE
        if(zone->journal != NULL)
        {
            journal *jh = zone->journal; // pointed for closing/releasing
            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_DESTROY);
            journal_close(jh); // only authorised usage of this call
            zone->journal = NULL;
        }
        else
#endif
        {
            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_DESTROY);
        }

#if !DEBUG
        // do not bother clearing the memory if it's for a shutdown (faster)
        if(!dnscore_shuttingdown())
#endif
        {
            if(zone->apex != NULL)
            {
#if ZDB_HAS_NSEC_SUPPORT
                log_debug("zone: %{dnsname}: deleting NSEC chain (if any)", zone->origin);

                nsec_destroy_zone(zone);
#endif

#if ZDB_HAS_NSEC3_SUPPORT
                log_debug("zone: %{dnsname}: deleting NSEC3 chain (if any)", zone->origin);

                nsec3_destroy_zone(zone);
#endif
                log_debug("zone: %{dnsname}: deleting records", zone->origin);

                zdb_rr_label_destroy(zone, &zone->apex);
                zone->apex = NULL;
            }
            else
            {
                log_debug("zone: %{dnsname}: apex is empty", zone->origin);
            }
        }
#if !DEBUG
        else
        {
            log_debug(
                "zone: %{dnsname}: will not spend time carefully releasing the memory used by the records and the "
                "chains (shutting down)",
                zone->origin);
        }
#endif

        uint32_t zone_footprint = zdb_zone_get_struct_size(zone->origin);

#if DNSCORE_HAS_DNSSEC_SUPPORT
        if(zone->progressive_signature_update.current_fqdn != NULL)
        {
            log_debug("zone: %{dnsname}: releasing progressive signature update", zone->origin);

            dnsname_zfree(zone->progressive_signature_update.current_fqdn);
            zone->progressive_signature_update.current_fqdn = NULL;
        }
#endif

#if DEBUG
        zone->min_ttl = 0xbadbad01;
        zone->acl = NULL;
        zone->axfr_serial = 0xbadbad00;
#endif
        cond_finalize(&zone->lock_cond);
        mutex_destroy(&zone->lock_mutex);

        log_debug("zone: %{dnsname}: releasing name and structure", zone->origin);

        dnsname_zfree(zone->origin);

#if DEBUG
        zone->origin = NULL;
#endif

        ZFREE_ARRAY(zone, zone_footprint);
    }
#if DEBUG
    else
    {
        log_debug("zone: NULL: zdb_zone_destroy called on NULL");
    }
#endif
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

ya_result zdb_zone_getsoa(const zdb_zone_t *zone, zdb_soa_rdata_t *soa_out)
{
#if DEBUG
    if(zone->lock_owner == ZDB_ZONE_MUTEX_NOBODY)
    {
        log_err("zdb_zone_getsoa called on an unlocked zone: %{dnsname}", zone->origin);
        debug_log_stacktrace(MODULE_MSG_HANDLE, LOG_ERR, "zdb_zone_getsoa");
        // logger_flush();
    }
    else
    {
        log_debug("zdb_zone_getsoa called on a zone locked by %02hhx (%{dnsname})", zone->lock_owner, zone->origin);
    }
#endif

    const zdb_rr_label_t             *apex = zone->apex;
    const zdb_resource_record_data_t *soa = zdb_resource_record_sets_find_soa(&apex->resource_record_set); // zone is locked
    ya_result                         return_code;

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

ya_result zdb_zone_getsoa_ttl_rdata(const zdb_zone_t *zone, uint32_t *ttl, uint16_t *rdata_size, const uint8_t **rdata)
{
#if DEBUG
    if(zone->lock_owner == ZDB_ZONE_MUTEX_NOBODY)
    {
        log_err("zdb_zone_getsoa_ttl_rdata called on an unlocked zone: %{dnsname}", zone->origin);
        debug_log_stacktrace(MODULE_MSG_HANDLE, LOG_ERR, "zdb_zone_getsoa_ttl_rdata");
        logger_flush();
    }
    else
    {
        log_debug("zdb_zone_getsoa_ttl_rdata called on a zone locked by %02hhx (%{dnsname})", zone->lock_owner, zone->origin);
    }
#endif

    const zdb_rr_label_t             *apex = zone->apex;
    int32_t                           soa_ttl;
    const zdb_resource_record_data_t *soa_rr = zdb_resource_record_sets_find_soa_and_ttl(&apex->resource_record_set, &soa_ttl); // zone is locked

    if(soa_rr == NULL)
    {
        return ZDB_ERROR_NOSOAATAPEX;
    }

    if(ttl != NULL)
    {
        *ttl = soa_ttl;
    }

    if(rdata_size != NULL && rdata != NULL)
    {
        *rdata_size = zdb_resource_record_data_rdata_size(soa_rr);
        *rdata = zdb_resource_record_data_rdata_const(soa_rr);
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

ya_result zdb_zone_getserial(const zdb_zone_t *zone, uint32_t *serial)
{
#if DEBUG
    if(zone->lock_owner == ZDB_ZONE_MUTEX_NOBODY)
    {
        log_err("zdb_zone_getserial called on an unlocked zone (%{dnsname})", zone->origin);
        debug_log_stacktrace(MODULE_MSG_HANDLE, LOG_ERR, "zdb_zone_getserial");
        logger_flush();
    }
    else
    {
        log_debug1("zdb_zone_getserial called on a zone locked by %02hhx (%{dnsname})", zone->lock_owner, zone->origin);
    }
#endif

    yassert(serial != NULL);

    zdb_rr_label_t             *apex = zone->apex;
    zdb_resource_record_data_t *soa = zdb_resource_record_sets_find_soa(&apex->resource_record_set); // zone is locked

    if(soa != NULL)
    {
        return rr_soa_get_serial(zdb_resource_record_data_rdata_const(soa), zdb_resource_record_data_rdata_size(soa), serial);
    }

    return ZDB_ERROR_NOSOAATAPEX;
}

const zdb_resource_record_set_t *zdb_zone_get_dnskey_rrset(zdb_zone_t *zone)
{
    return zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_DNSKEY); // zone is locked
}

bool zdb_zone_isinvalid(zdb_zone_t *zone)
{
    bool invalid = true;

    if((zone != NULL) && (zone->apex != NULL))
    {
        invalid = zdb_zone_is_invalid(zone);
    }

    return invalid;
}

#if DNSCORE_HAS_DNSSEC_SUPPORT

/**
 *
 * Returns true iff the key is present as a record in the zone
 *
 * @param zone
 * @param key
 * @return
 */

bool zdb_zone_contains_dnskey_record_for_key(zdb_zone_t *zone, const dnskey_t *key)
{
    yassert(zdb_zone_islocked(zone));

    const zdb_resource_record_set_t *dnskey_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_DNSKEY); // zone is locked

    if(dnskey_rrset != NULL)
    {
        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(dnskey_rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *dnskey_record = zdb_resource_record_set_const_iterator_next(&iter);

            if(dnskey_matches_rdata(key, zdb_resource_record_data_rdata_const(dnskey_record), zdb_resource_record_data_rdata_size(dnskey_record)))
            {
                return true;
            }
        }
    }

    return false;
}

/**
 * Returns true iff there is at least one RRSIG record with the tag and algorithm of the key
 *
 * @param zone
 * @param key
 * @return
 */

bool zdb_zone_apex_contains_rrsig_record_by_key(zdb_zone_t *zone, const dnskey_t *key)
{
    yassert(zdb_zone_islocked(zone));

    const zdb_resource_record_set_t *rrsig_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_RRSIG); // zone is locked

    if(rrsig_rrset != NULL)
    {
        uint16_t                               tag = dnskey_get_tag_const(key);
        uint8_t                                algorithm = dnskey_get_algorithm(key);

        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(rrsig_rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *rrsig_record = zdb_resource_record_set_const_iterator_next(&iter);

            if((RRSIG_ALGORITHM(rrsig_record) == algorithm) && (RRSIG_KEY_TAG(rrsig_record) == tag))
            {
                return true;
            }
        }
    }

    return false;
}

#if HAS_PRIMARY_SUPPORT

/**
 * Adds a DNSKEY record in a zone from the dnskey_t object.
 *
 * @param key
 * @return true iff the record has been added
 */

bool zdb_zone_add_dnskey_from_key(zdb_zone_t *zone, const dnskey_t *key)
{
    yassert(zdb_zone_islocked(zone));

    zdb_resource_record_data_t *dnskey_record;
    uint32_t                    rdata_size = key->vtbl->dnskey_rdatasize(key);
    dnskey_record = zdb_resource_record_data_new_instance(rdata_size);
    key->vtbl->dnskey_writerdata(key, zdb_resource_record_data_rdata(dnskey_record), rdata_size);

    // store the record

    if(zdb_resource_record_sets_insert_record_checked(&zone->apex->resource_record_set, TYPE_DNSKEY, 86400, dnskey_record)) /* FB done */
    {
        return true;
    }
    else
    {
        zdb_resource_record_data_delete(dnskey_record);

        return false;
    }
}

/**
 * Removes a DNSKEY record in a zone from the dnskey_t object.
 *
 * @param key
 * @return true iff the record has been found and removed
 */

bool zdb_zone_remove_dnskey_from_key(zdb_zone_t *zone, const dnskey_t *key)
{
    yassert(zdb_zone_islocked(zone));

    zdb_resource_record_data_t *dnskey_record;
    uint32_t                    rdata_size = key->vtbl->dnskey_rdatasize(key);
    dnskey_record = zdb_resource_record_data_new_instance(rdata_size);
    key->vtbl->dnskey_writerdata(key, zdb_resource_record_data_rdata(dnskey_record), rdata_size);

    zdb_ttlrdata unpacked_dnskey_record;
    unpacked_dnskey_record.rdata_pointer = zdb_resource_record_data_rdata(dnskey_record);
    unpacked_dnskey_record.rdata_size = zdb_resource_record_data_rdata_size(dnskey_record);
    unpacked_dnskey_record.ttl = 86400;

    // remove the record

    if(zdb_resource_record_sets_delete_exact_record_self(&zone->apex->resource_record_set, TYPE_DNSKEY, &unpacked_dnskey_record) >= 0)
    {
        // remove all RRSIG on DNSKEY
        rrsig_delete(zone, zone->origin, zone->apex, TYPE_DNSKEY);

        rrsig_delete_by_tag(zone, dnskey_get_tag_const(key));

        // zdb_listener_notify_remove_type(zone, zone->origin, &zone->apex->resource_record_set, TYPE_RRSIG);

        zdb_resource_record_data_delete(dnskey_record);

        return true;
    }
    else
    {
        zdb_resource_record_data_delete(dnskey_record);
        return false;
    }
}

static ya_result zdb_zone_update_zone_remove_add_dnskeys(zdb_zone_t *zone, ptr_vector_t *removed_keys, ptr_vector_t *added_keys, uint8_t secondary_lock)
{
    dynupdate_message   dmsg;
    dns_packet_reader_t reader;
    const uint8_t      *fqdn = NULL;

    if(!ptr_vector_isempty(removed_keys))
    {
        dnskey_t *key = (dnskey_t *)ptr_vector_get(removed_keys, 0);
        yassert(key != NULL);
        fqdn = dnskey_get_domain(key);
    }
    else if(!ptr_vector_isempty(added_keys))
    {
        dnskey_t *key = (dnskey_t *)ptr_vector_get(added_keys, 0);
        yassert(key != NULL);
        fqdn = dnskey_get_domain(key);
    }
    else
    {
        return 0; // EMPTY
    }

    ya_result ret = SUCCESS;
    int       add_index = 0;
    int       del_index = 0;
    bool      work_to_do = false;

    do
    {
        dynupdate_message_init(&dmsg, fqdn, CLASS_IN);

        for(; add_index <= ptr_vector_last_index(added_keys); ++add_index)
        {
            dnskey_t *key = (dnskey_t *)ptr_vector_get(added_keys, add_index);

            if(FAIL(ret = dynupdate_message_add_dnskey(&dmsg, zone->min_ttl, key)))
            {
                log_debug("dnskey: %{dnsname}: +%03d+%05d/%d key cannot be sent with this update, postponing", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));
                work_to_do = true;
                break;
            }

            log_info("dnskey: %{dnsname}: +%03d+%05d/%d key will be added", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));
        }

        if(!work_to_do)
        {
            for(; del_index <= ptr_vector_last_index(removed_keys); ++del_index)
            {
                dnskey_t *key = (dnskey_t *)ptr_vector_get(removed_keys, del_index);
                if(FAIL(ret = dynupdate_message_del_dnskey(&dmsg, key)))
                {
                    log_debug("dnskey: %{dnsname}: +%03d+%05d/%d key cannot be sent with this update, postponing", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));
                    work_to_do = true;
                    break;
                }

                log_info("dnskey: %{dnsname}: +%03d+%05d/%d key will be removed", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));
            }
        }

        dynupdate_message_set_reader(&dmsg, &reader);
        uint16_t count = dynupdate_message_get_count(&dmsg);

        dns_packet_reader_skip(&reader, DNS_HEADER_LENGTH); // checked below
        dns_packet_reader_skip_fqdn(&reader);               // checked below
        dns_packet_reader_skip(&reader, 4);                 // checked below

        if(!dns_packet_reader_eof(&reader))
        {
            // the update is ready : push it

            if(ISOK(ret = dynupdate_diff(zone, &reader, count, secondary_lock, DYNUPDATE_DIFF_RUN)))
            {
                // done
                log_info("dnskey: %{dnsname}: keys update successful", fqdn);
            }

            if(FAIL(ret))
            {
                if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                {
                    // trigger a background store of the zone

                    zdb_zone_info_background_store_zone(fqdn);
                }

                dynupdate_message_finalize(&dmsg);
                /// @todo 20220803 edf -- check this is restarted after the zone has ben stored
                log_err("dnskey: %{dnsname}: keys update failed", fqdn);
                break;
            }
        }
        else
        {
            log_err("dnskey: %{dnsname}: keys update failed: FORMERR", fqdn);
        }

        dynupdate_message_finalize(&dmsg);
    } while(work_to_do);

    return ret;
}

/**
 * From the keystore (files/pkcs12) for that zone
 *
 * Remove the keys that should not be in the zone anymore.
 * Add the keys that should be in the zone.
 *
 * @param zone
 */

void zdb_zone_update_keystore_keys_from_zone(zdb_zone_t *zone, uint8_t secondary_lock)
{
    // keystore keys with a publish time that did not expire yet have to be added
    // keystore keys with an unpublish time that passed have to be removed
    //
    // after (and only after) the signature is done, set alarms at all the (relevant) timings of the keys (publish,
    // activate, inactivate, unpublish)

    yassert(zdb_zone_islocked(zone));

    ptr_vector_t dnskey_add = PTR_VECTOR_EMPTY;
    ptr_vector_t dnskey_del = PTR_VECTOR_EMPTY;

    bool         rrsig_push_allowed = zdb_zone_get_rrsig_push_allowed(zone);

    for(int_fast32_t i = 0;; ++i)
    {
        dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_at_index(zone->origin, i);

        if(key == NULL)
        {
            break;
        }

        if(dnskey_is_private(key))
        {
            time_t now = time(NULL);

            if(dnskey_is_published(key, now) || !dnskey_has_explicit_publish(key)) // if published or no publication set
            {
                if(!dnskey_is_expired(key, now)) // if the key hasn't expired (includes a test for activation)
                {
                    if(!zdb_zone_contains_dnskey_record_for_key(zone, key)) // if the key is not in the zone
                    {
                        if(!rrsig_push_allowed)
                        {
                            dnskey_acquire(key); // then add the key in the zone
                            ptr_vector_append(&dnskey_add, key);
                        }
                    }
                } // else there is no point publishing it if it was not already
            }
        }

        dnskey_release(key);
    }

    zdb_resource_record_set_t *dnskey_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_DNSKEY); // zone is locked

    if(dnskey_rrset != NULL)
    {
        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(dnskey_rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *dnskey_record = zdb_resource_record_set_const_iterator_next(&iter);

            dnskey_t                         *key;

            ya_result                         ret;

            if(ISOK(ret = dnssec_keystore_load_private_key_from_rdata(zdb_resource_record_data_rdata_const(dnskey_record), zdb_resource_record_data_rdata_size(dnskey_record), zone->origin,
                                                                      &key))) // key properly released
            {
                if(dnskey_has_explicit_delete(key) && dnskey_is_unpublished(key, time(NULL)))
                {
                    if(!rrsig_push_allowed)
                    {
                        // need to unpublish
                        dnskey_acquire(key);
                        ptr_vector_append(&dnskey_del, key);
                    }
                }
                // note: the key alarms are not set

                dnskey_release(key);
            }
        }
    }

    if(ptr_vector_size(&dnskey_add) + ptr_vector_size(&dnskey_del) > 0)
    {
        if(ISOK(zdb_zone_update_zone_remove_add_dnskeys(zone, &dnskey_del, &dnskey_add, secondary_lock)))
        {
            log_info("zone: %{dnsname}: keys added: %i, keys deleted: %i", zone->origin, ptr_vector_size(&dnskey_add), ptr_vector_size(&dnskey_del));
        }
        else
        {
            log_warn("zone: %{dnsname}: failed to update keys (keys meant to be added: %i, keys meant to be deleted: %i)", zone->origin, ptr_vector_size(&dnskey_add), ptr_vector_size(&dnskey_del));
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&dnskey_add); ++i)
        {
            dnskey_release(ptr_vector_get(&dnskey_add, i));
        }
        ptr_vector_finalise(&dnskey_add);

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&dnskey_del); ++i)
        {
            dnskey_release(ptr_vector_get(&dnskey_del, i));
        }
        ptr_vector_finalise(&dnskey_del);
    }
}

#endif // HAS_PRIMARY_SUPPORT

#endif

#if DEBUG

/**
 * DEBUG
 */

void zdb_zone_print_indented(zdb_zone_t *zone, output_stream_t *os, int indent)
{
    if(zone == NULL)
    {
        osformatln(os, "%tz: NULL", indent);
        return;
    }

    uint16_t zclass = zdb_zone_getclass(zone);

    osformatln(os, "%tzone@%p(CLASS=%{dnsclass},ORIGIN='%{dnsname}'", indent, (void *)zone, &zclass, zone->origin);
    zdb_rr_label_print_indented(zone->apex, os, indent + 1);
    osformatln(os, "%t+:", indent);
}

void zdb_zone_print(zdb_zone_t *zone, output_stream_t *os) { zdb_zone_print_indented(zone, os, 0); }

#endif

uint32_t zdb_zone_get_status(zdb_zone_t *zone)
{
    uint32_t ret = atomic_load(&zone->_status);
    return ret;
}

uint32_t zdb_zone_set_status(zdb_zone_t *zone, uint32_t status)
{
#if DEBUG
    log_debug4("zdb_zone_set_status(%{dnsname},%08x)", zone->origin, status);
#endif

    for(;;)
    {
        uint_fast32_t expected = atomic_load(&zone->_status);
        if((expected & status) != status)
        {
            uint_fast32_t desired = expected | status;
            if(atomic_compare_exchange_strong(&zone->_status, &expected, desired))
            {
                return expected; // old value
            }

            // the update failed, try a gain
        }
        else
        {
            return expected; // no work to do
        }
    }
}

uint32_t zdb_zone_clear_status(zdb_zone_t *zone, uint32_t status)
{
#if DEBUG
    log_debug4("zdb_zone_clear_status(%{dnsname},%08x)", zone->origin, status);
#endif

    uint_fast32_t not_status = ~status;

    for(;;)
    {
        uint_fast32_t expected = atomic_load(&zone->_status);
        if((expected & status) != 0)
        {
            uint_fast32_t desired = expected & not_status;
            if(atomic_compare_exchange_strong(&zone->_status, &expected, desired))
            {
                return expected; // old value
            }

            // the update failed, try a gain
        }
        else
        {
            return expected; // no work to do
        }
    }
}

bool zdb_zone_error_status_getnot_set(zdb_zone_t *zone, uint8_t error_status)
{
    bool ret = (zone->_error_status & error_status) == 0;
    zone->_error_status &= ~error_status;
    return ret;
}

void zdb_zone_error_status_clear(zdb_zone_t *zone, uint8_t error_status) { zone->_error_status &= ~error_status; }

/** @} */

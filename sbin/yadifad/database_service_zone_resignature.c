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
 * @defgroup database Routines for database manipulations
 * @ingroup yadifad
 * @brief database functions
 *
 *  Implementation of routines for the database
 *   - add zone file(s)
 *   - clear zone file(s)
 *   - print zone files(s)
 *   - load db
 *   - unload db
 *   - lookup database result of a message
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/

#include "server_config.h"

#include <dnscore/logger.h>
#include <dnscore/timeformat.h>
#include <dnscore/dnskey_keyring.h>
#include <dnscore/thread_pool.h>
#include <dnsdb/dnssec.h>
#include <dnsdb/rrsig.h>
#include <dnsdb/zdb_rr_label.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_process.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/dynupdate_diff.h>
#include <dnsdb/dynupdate_message.h>
#include <dnsdb/zdb_zone_maintenance.h>
#include <dnsdb/zdb_zone_path_provider.h>
#include <dnsdb/dnssec_keystore.h>

#include "database_service.h"
#if HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_DNSSEC_SUPPORT
#include "database_service_zone_resignature.h"
#endif

#include "notify.h"
#include "zone_signature_policy.h"

#if HAS_EVENT_DYNAMIC_MODULE
#include "dynamic_module_handler.h"
#endif

#ifndef HAS_DYNUPDATE_DIFF_ENABLED
#error "HAS_DYNUPDATE_DIFF_ENABLED not defined"
#endif

#if !HAS_RRSIG_MANAGEMENT_SUPPORT
#error "RRSIG management support disabled : this file should not be compiled"
#endif

#define MODULE_MSG_HANDLE g_server_logger

#define DBUPSIGP_TAG      0x5047495350554244
#define RESIGALR_TAG      0x524c414749534552

#if DNSCORE_HAS_PRIMARY_SUPPORT && DNSCORE_HAS_DNSSEC_SUPPORT

ya_result                    zone_policy_process(zone_desc_t *zone_desc);

static struct thread_pool_s *database_service_zone_resignature_publish_dnskey_tp = NULL;
static mutex_t               database_service_zone_resignature_publish_dnskey_mtx = MUTEX_INITIALIZER;

extern logger_handle_t      *g_server_logger;
extern zone_data_set         database_zone_desc;

struct database_service_zone_resignature_init_callback_s
{
    zone_desc_t     *zone_desc;
    dnskey_keyring_t keyring;
    uint64_t         total_signature_valitity_time; // to compute the mean validity period
    uint32_t         signature_count;
    uint32_t         missing_signatures_count;
    uint32_t         unverifiable_signatures_count;
    uint32_t         earliest_expiration_epoch;
    uint32_t         smallest_validity_period;
    uint32_t         biggest_validity_period;
};

struct database_service_zone_resignature_alarm_s
{
    zone_desc_t *zone_desc;
    zdb_zone_t  *zone;
};

typedef struct database_service_zone_resignature_alarm_s database_service_zone_resignature_alarm_s;

#define DSZZRPRM_TAG 0x4d5250525a5a5344

struct database_service_zone_resignature_dnskey_alarm_args
{
    uint8_t *domain;
    uint16_t flags;
    uint16_t tag;
    uint8_t  algorithm;
};

typedef struct database_service_zone_resignature_dnskey_alarm_args database_service_zone_resignature_dnskey_alarm_args;

struct database_service_zone_resignature_parms_s
{
    zone_desc_t *zone_desc;
};

typedef struct database_service_zone_resignature_parms_s database_service_zone_resignature_parms_s;

static uint32_t                                          database_service_zone_resignature_dnskey_alarm_unique_key(const dnskey_t *key, uint32_t operation)
{
    uint32_t tag = dnskey_get_tag_const(key);
    uint32_t alg = dnskey_get_algorithm(key);

    return operation | (tag << 8) | (alg << 24);
}

database_service_zone_resignature_dnskey_alarm_args *database_service_zone_resignature_dnskey_alarm_args_new(const dnskey_t *key)
{
    database_service_zone_resignature_dnskey_alarm_args *ret;
    ZALLOC_OBJECT_OR_DIE(ret, database_service_zone_resignature_dnskey_alarm_args, RESIGALR_TAG);
    ret->domain = dnsname_zdup(dnskey_get_domain(key));
    ret->tag = dnskey_get_tag_const(key);
    ret->algorithm = dnskey_get_algorithm(key);
    ret->flags = key->flags;
    return ret;
}

void database_service_zone_resignature_dnskey_alarm_args_free(database_service_zone_resignature_dnskey_alarm_args *args)
{
    dnsname_zfree(args->domain);
    ZFREE(args, database_service_zone_resignature_dnskey_alarm_args);
}

static ya_result database_service_zone_add_dnskey(dnskey_t *key)
{
    // make a dynupdate query update that adds the record

    dynupdate_message   dmsg;
    dns_packet_reader_t reader;
    dynupdate_message_init(&dmsg, dnskey_get_domain(key), CLASS_IN);
    ya_result ret;

    if(ISOK(ret = dynupdate_message_add_dnskey(&dmsg, 86400, key)))
    {
        dynupdate_message_set_reader(&dmsg, &reader);
        uint16_t count = dynupdate_message_get_count(&dmsg);

        dns_packet_reader_skip(&reader, DNS_HEADER_LENGTH); // eof checked below
        dns_packet_reader_skip_fqdn(&reader);               // eof checked below
        dns_packet_reader_skip(&reader, 4);                 // eof checked below

        if(!dns_packet_reader_eof(&reader))
        {
            // the update is ready : push it

            zdb_zone_t *zone = zdb_acquire_zone_read_double_lock_from_fqdn(g_config->database, dnskey_get_domain(key), ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
            if(zone != NULL)
            {
                for(;;)
                {
                    uint32_t reader_offset = reader.packet_offset;

                    ret = dynupdate_diff(zone, &reader, count, ZDB_ZONE_MUTEX_DYNUPDATE, DYNUPDATE_DIFF_RUN);

                    if(ISOK(ret))
                    {
                        // done
                        log_info("dnskey: %{dnsname}: +%03d+%05d/%d key added", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));
                        // args->domain, args->algorithm, args->tag, ntohs(args->flags));
#if HAS_EVENT_DYNAMIC_MODULE
                        if(dynamic_module_dnskey_interface_chain_available())
                        {
                            dynamic_module_on_dnskey_publish(key); // we know this key has been pushed as we have crafted the update message
                        }
#endif
                        notify_secondaries(zone->origin);

                        zdb_zone_set_maintained(zone, true);
                    }
                    else if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                    {
                        log_warn("dnskey: %{dnsname}: +%03d+%05d/%d could not add key as the journal is full", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));

                        // trigger a background store of the zone

                        // zdb_zone_info_background_store_zone(dnskey_get_domain(key));
                        if(ISOK(ret = zdb_zone_info_store_locked_zone(dnskey_get_domain(key))))
                        {
                            reader.packet_offset = reader_offset;
                            continue;
                        }
                        else
                        {
                            log_err("dnskey: %{dnsname}: failed to store the zone on disk: %r", dnskey_get_domain(key), ret);
                        }
                    }

                    break;
                }

                zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

                zdb_zone_release(zone);
            }
        }
        else
        {
            ret = MAKE_RCODE_ERROR(RCODE_FORMERR);
        }
    }

    if(FAIL(ret))
    {
        log_err("dnskey: %{dnsname}: +%03d+%05d/%d could not add key: %r", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)), ret);
    }

    dynupdate_message_finalize(&dmsg);

    return ret;
}

/**
 * Applies the dynamic update to that zone.
 * Note that the zone may be flushed on disk as a result (e.g. if the journal is full.)
 */

static ya_result database_service_zone_update_published_keys_flush(const uint8_t *fqdn, dynupdate_message *dmsg)
{
    ya_result           ret;
    dns_packet_reader_t reader;

    dynupdate_message_set_reader(dmsg, &reader);
    uint16_t count = dynupdate_message_get_count(dmsg);

    dns_packet_reader_skip(&reader, DNS_HEADER_LENGTH); // eof checked below
    dns_packet_reader_skip_fqdn(&reader);               // eof checked below
    dns_packet_reader_skip(&reader, 4);                 // eof checked below

    if(!dns_packet_reader_eof(&reader))
    {
        // the update is ready : push it

        zdb_zone_t *zone = zdb_acquire_zone_read_double_lock_from_fqdn(g_config->database, fqdn, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
        if(zone != NULL)
        {
            for(;;)
            {
                uint32_t reader_offset = reader.packet_offset;

                ret = dynupdate_diff(zone, &reader, count, ZDB_ZONE_MUTEX_DYNUPDATE, DYNUPDATE_DIFF_RUN);

                if(ISOK(ret))
                {
                    // done
                }
                else if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                {
                    log_warn("dnskey: %{dnsname}: the journal is full", fqdn);

                    // trigger a background store of the zone

                    if(ISOK(ret = zdb_zone_info_store_locked_zone(fqdn)))
                    {
                        reader.packet_offset = reader_offset;
                        continue; // try again
                    }
                    else
                    {
                        log_err("dnskey: %{dnsname}: failed to store the zone on disk: %r", fqdn, ret);
                    }
                }

                break;
            }

            zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

            zdb_zone_release(zone);
        }
        else
        {
            ret = ZDB_ERROR_ZONE_NOT_IN_DATABASE;
        }
    }
    else
    {
        ret = MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    return ret;
}
/*
static void
database_service_zone_maintain_presignatures_for_key(const uint8_t *fqdn, time_t now, dnskey_t *key)
{
    zone_desc_s *zone_desc = zone_acquirebydnsname(fqdn);
    if(zone_desc != NULL)
    {
        zone_lock(zone_desc, ZONE_LOCK_READONLY);
        zdb_zone *zone = zone_get_loaded_zone(zone_desc);
        if(zone != NULL)
        {
            if(dnskey_is_activated_lenient(fqdn, now, zone->sig_validity_regeneration_seconds))
            {
                // maintenance

                database_service_zone_dnssec_maintenance(zone_desc);
            }
            zdb_zone_release(zone);
        }
        zone_unlock(zone_desc, ZONE_LOCK_READONLY);
        zone_release(zone_desc);
    }
}
*/

static ya_result database_service_zone_update_published_keys(const uint8_t *fqdn)
{
    // make a dynupdate query update that adds the record

    zone_desc_t *zone_desc = zone_acquirebydnsname(fqdn);

    if(zone_desc == NULL)
    {
        return INVALID_STATE_ERROR;
    }

    ptr_vector_t publish_keys = EMPTY_PTR_VECTOR;
    ptr_vector_t delete_keys = EMPTY_PTR_VECTOR;

    if(dnssec_keystore_acquire_publish_delete_keys_from_fqdn_to_vectors(fqdn, &publish_keys, &delete_keys) == 0)
    {
        zone_release(zone_desc);
        return SUCCESS; // nothing to do
    }

    dynupdate_message dmsg;

    dynupdate_message_init(&dmsg, fqdn, CLASS_IN);
    ya_result      ret = SUCCESS;
    int            record_count = 0;
    bool           should_star_maintenance = false;
    bool           some_work_done = false;

    dnssec_policy *dp;
    bool           is_dnssec_policy_managed = ((dp = zone_desc->dnssec_policy) != NULL);

    if(is_dnssec_policy_managed)
    {
        dnssec_policy_acquire(dp);
    }

    zone_release(zone_desc);

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(&publish_keys); ++i)
    {
        dnskey_t *key = (dnskey_t *)ptr_vector_get(&publish_keys, i);

        if(is_dnssec_policy_managed)
        {
            if(!dnssec_policy_is_key_matching(dp, key))
            {
                continue;
            }
        }

        if(ISOK(ret = dynupdate_message_add_dnskey(&dmsg, 86400, key)))
        {
            bool key_should_start_maintenance = false;
            zone_lock(zone_desc, ZONE_LOCK_READONLY);
            zdb_zone_t *zone = zone_get_loaded_zone(zone_desc);
            if(zone != NULL)
            {
                key_should_start_maintenance = dnskey_is_activated_lenient(key, time(NULL), zone->sig_validity_regeneration_seconds);
                should_star_maintenance |= key_should_start_maintenance;
                zdb_zone_release(zone);
            }
            zone_unlock(zone_desc, ZONE_LOCK_READONLY);

            log_info("dnskey: %{dnsname}: +%03d+%05d/%d key will be published %T => %T => %T => %T (%i)",
                     dnskey_get_domain(key),
                     dnskey_get_algorithm(key),
                     dnskey_get_tag_const(key),
                     ntohs(dnskey_get_flags(key)),
                     dnskey_get_publish_epoch(key),
                     dnskey_get_activate_epoch(key),
                     dnskey_get_inactive_epoch(key),
                     dnskey_get_delete_epoch(key),
                     key_should_start_maintenance);
            ++record_count;
        }
        else
        {
            // full ?
            if(record_count > 0)
            {
                // flush
                if(FAIL(ret = database_service_zone_update_published_keys_flush(fqdn, &dmsg)))
                {
                    log_err("dnskey: %{dnsname}: key publication failed: %r", fqdn, ret);
                    break;
                }

                some_work_done = true;
                --i;
                record_count = 0;
                dynupdate_message_reset(&dmsg, fqdn, CLASS_IN);
            }
            else
            {
                log_err("dnskey: %{dnsname}: key publication message creation failed: %r", fqdn, ret);
                break;
            }
        }
    }

    if(is_dnssec_policy_managed)
    {
        dnssec_policy_release(dp);
        dp = NULL;
    }

    if(ISOK(ret))
    {
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&delete_keys); ++i)
        {
            dnskey_t *key = (dnskey_t *)ptr_vector_get(&delete_keys, i);
            if(ISOK(ret = dynupdate_message_del_dnskey(&dmsg, key)))
            {
                log_info("dnskey: %{dnsname}: +%03d+%05d/%d key will be unpublished %T => %T => %T => %T",
                         dnskey_get_domain(key),
                         dnskey_get_algorithm(key),
                         dnskey_get_tag_const(key),
                         ntohs(dnskey_get_flags(key)),
                         dnskey_get_publish_epoch(key),
                         dnskey_get_activate_epoch(key),
                         dnskey_get_inactive_epoch(key),
                         dnskey_get_delete_epoch(key));
                ++record_count;
            }
            else
            {
                // full ?
                if(record_count > 0)
                {
                    // flush
                    if(FAIL(ret = database_service_zone_update_published_keys_flush(fqdn, &dmsg)))
                    {
                        log_err("dnskey: %{dnsname}: key deletion failed: %r", fqdn, ret);
                        break;
                    }

                    some_work_done = true;
                    --i;
                    record_count = 0;
                    dynupdate_message_reset(&dmsg, fqdn, CLASS_IN);
                }
                else
                {
                    log_err("dnskey: %{dnsname}: key deletion message creation failed: %r", fqdn, ret);
                    break;
                }
            }
        }
    }

    if(ISOK(ret))
    {
        if(record_count > 0)
        {
            if(ISOK(ret = database_service_zone_update_published_keys_flush(fqdn, &dmsg)))
            {
                some_work_done = true;
            }
            else
            {
                log_err("dnskey: %{dnsname}: key publication failed: %r (last stage)", fqdn, ret);
            }
        }
    }

    // does the zone needs to have its chain(s) processed ?

    zone_desc = zone_acquirebydnsname(fqdn);

    if(zone_desc != NULL)
    {
        zone_lock(zone_desc, ZONE_LOCK_READONLY);
        zone_policy_process_dnssec_chain(zone_desc);
        zone_unlock(zone_desc, ZONE_LOCK_READONLY);
        zone_release(zone_desc);
    }

    dynupdate_message_finalize(&dmsg);

    dnssec_keystore_release_keys_from_vector(&delete_keys);
    dnssec_keystore_release_keys_from_vector(&publish_keys);
    ptr_vector_finalise(&delete_keys);
    ptr_vector_finalise(&publish_keys);

    if(some_work_done)
    {
        notify_secondaries(fqdn);

        zdb_zone_t *zone = zdb_acquire_zone_read_double_lock_from_fqdn(g_config->database, fqdn, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
        if(zone != NULL)
        {
            zdb_zone_set_maintained(zone, true);
            zdb_zone_set_maintenance_paused(zone, false);
            zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
            zdb_zone_release(zone);
        }

        if(should_star_maintenance)
        {
            zone_desc = zone_acquirebydnsname(fqdn);
            if(zone_desc != NULL)
            {
                log_debug("dnskey: %{dnsname}: starting maintenance", fqdn);
                database_service_zone_dnssec_maintenance(zone_desc);
                zone_release(zone_desc);
            }
            else
            {
                log_err("dnskey: %{dnsname}: cannot start maintenance", fqdn); // which should never happen
            }
        }
        else
        {
            log_debug("dnskey: %{dnsname}: no maintenance needed", fqdn);
        }
    }

    return ret;
}

static ya_result database_service_zone_remove_dnskey(dnskey_t *key)
{
    // make a dynupdate query update that removes the record

    dynupdate_message   dmsg;
    dns_packet_reader_t reader;
    dynupdate_message_init(&dmsg, dnskey_get_domain(key), CLASS_IN);
    ya_result ret;

    if(ISOK(ret = dynupdate_message_del_dnskey(&dmsg, key)))
    {
        dynupdate_message_set_reader(&dmsg, &reader);
        uint16_t count = dynupdate_message_get_count(&dmsg);

        dns_packet_reader_skip(&reader, DNS_HEADER_LENGTH); // eof checked below
        dns_packet_reader_skip_fqdn(&reader);               // eof checked below
        dns_packet_reader_skip(&reader, 4);                 // eof checked below

        // the update is ready : push it

        if(!dns_packet_reader_eof(&reader))
        {
            zdb_zone_t *zone = zdb_acquire_zone_read_double_lock_from_fqdn(g_config->database, dnskey_get_domain(key), ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
            if(zone != NULL)
            {
                for(;;)
                {
                    uint32_t reader_offset = reader.packet_offset;
                    ret = dynupdate_diff(zone, &reader, count, ZDB_ZONE_MUTEX_DYNUPDATE, DYNUPDATE_DIFF_RUN);

                    if(ISOK(ret))
                    {
                        // done
                        log_info("dnskey: %{dnsname}: +%03d+%05d/%d key removed", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));
#if HAS_EVENT_DYNAMIC_MODULE
                        if(dynamic_module_dnskey_interface_chain_available())
                        {
                            dynamic_module_on_dnskey_delete(key);
                        }
#endif
                        notify_secondaries(zone->origin);
                    }
                    else if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                    {
                        log_warn("dnskey: %{dnsname}: +%03d+%05d/%d could not remove key as the journal is full", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));

                        // trigger a background store of the zone

                        // zdb_zone_info_background_store_zone(dnskey_get_domain(key));

                        if(ISOK(ret = zdb_zone_info_store_locked_zone(dnskey_get_domain(key))))
                        {
                            reader.packet_offset = reader_offset;
                            continue;
                        }
                        else
                        {
                            log_err("dnskey: %{dnsname}: failed to store the zone on disk: %r", dnskey_get_domain(key), ret);
                        }
                    }

                    break;
                }

                zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

                zdb_zone_release(zone);
            }
        }
        else
        {
            ret = MAKE_RCODE_ERROR(RCODE_FORMERR);
        }
    }

    if(FAIL(ret))
    {
        log_err("dnskey: %{dnsname}: +%03d+%05d/%d could not remove key: %r", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)), ret);
    }

    dynupdate_message_finalize(&dmsg);

    return ret;
}

static void database_service_zone_resignature_publish_dnskey_thread(void *args_)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args *)args_;

    if(ISOK(database_service_zone_update_published_keys(args->domain)))
    {
        log_info("dnskey: %{dnsname}: DNSKEY rrset updated", args->domain);
    }
    else // failed, try to do the one
    {
        log_info("dnskey: %{dnsname}: +%03d+%05d/%d publish", args->domain, args->algorithm, args->tag, ntohs(args->flags));

        // grab the key, ensure it should still be published, publish it

        dnskey_t *key;
        ya_result ret;

        if(ISOK(ret = dnssec_keystore_load_private_key_from_parameters(args->algorithm, args->tag, args->flags, args->domain, &key))) // key properly released
        {
            assert(key != NULL);

            time_t now = time(NULL);

            if(dnskey_is_published(key, now) && !dnskey_is_expired_now(key)) // do not smart-add an expired key (even if it's never unpublished)
            {
                log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: publish: in its publish time window", args->domain, args->algorithm, args->tag, ntohs(args->flags));

                // has private KSK keys available now ?

                if(dnssec_keystore_has_usable_ksk(dnskey_get_domain(key), now))
                {
                    if(ISOK(ret = database_service_zone_update_published_keys(dnskey_get_domain(key))))
                    {
                        // database_service_zone_maintain_presignatures_for_key(dnskey_get_domain(key), now, key);
                    }
                    else
                    {
                        if(FAIL(ret = database_service_zone_add_dnskey(key)))
                        {
                            log_warn("dnskey: %{dnsname}: +%03d+%05d/%d: publish: key not published: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
                        }
                    }
                }
                else
                {
                    log_err(
                        "dnskey: %{dnsname}: +%03d+%05d/%d: publish: key not published as there is no usable KSK at "
                        "this time",
                        args->domain,
                        args->algorithm,
                        args->tag,
                        ntohs(args->flags));

                    ret = DNSSEC_ERROR_RRSIG_NOUSABLEKEYS;
                }
            }
            else if(dnskey_is_unpublished(key, now))
            {
                log_warn("dnskey: %{dnsname}: +%03d+%05d/%d: publish: key should not be published anymore", args->domain, args->algorithm, args->tag, ntohs(args->flags));

                // delete the key if it's in the zone

                if(ISOK(ret = database_service_zone_remove_dnskey(key)))
                {
                    // remove the key from the store and rename the files

                    dnssec_keystore_delete_key(key);
                }
                else
                {
                    // the key was not removed

                    // if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                    // try again later (zone_policy_process will be called)

                    log_warn("dnskey: %{dnsname}: +%03d+%05d/%d: publish: unpublish failed: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
                }
            }
            else
            {
                log_warn("dnskey: %{dnsname}: +%03d+%05d/%d: publish: key should not be published yet", args->domain, args->algorithm, args->tag, ntohs(args->flags));
            }

            dnskey_release(key);

            zone_desc_t *zone_desc = zone_acquirebydnsname(args->domain);
            if(zone_desc != NULL)
            {
                if(ISOK(ret = zone_policy_process(zone_desc)))
                {
                    log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: publish: post-publish policy process done", args->domain, args->algorithm, args->tag, ntohs(args->flags));
                }
                else
                {
                    log_err("dnskey: %{dnsname}: +%03d+%05d/%d: publish: post-publish policy process failed: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
                }
                zone_release(zone_desc);
            }
        }
        else
        {
            assert(key == NULL);

            log_err("dnskey: %{dnsname}: +%03d+%05d/%d:publish: cancelled: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
        }

        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: publish: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);

        database_service_zone_resignature_dnskey_alarm_args_free(args);
    }
}

static ya_result database_service_zone_resignature_publish_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args *)args_;
    ya_result                                            ret = SUCCESS;

    if(!cancel)
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: publish ...", args->domain, args->algorithm, args->tag, ntohs(args->flags));

        if(thread_pool_try_enqueue_call(database_service_zone_resignature_publish_dnskey_tp, database_service_zone_resignature_publish_dnskey_thread, args, NULL, "dnskey-publish alarm") == LOCK_TIMEOUT)
        {
            ret = ALARM_REARM;
        }
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: publish alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        database_service_zone_resignature_dnskey_alarm_args_free(args);
    }

    return ret;
}

static void database_service_zone_resignature_unpublish_dnskey_thread(void *args_)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args *)args_;

    if(ISOK(database_service_zone_update_published_keys(args->domain))) // fails -> works
    {
        log_info("dnskey: %{dnsname}: DNSKEY rrset updated (unpublish)", args->domain);
    }
    else // failed, try to do the one
    {
        ya_result ret;

        log_info("dnskey: %{dnsname}: +%03d+%05d/%d: unpublish", args->domain, args->algorithm, args->tag, ntohs(args->flags));

        // grab the key, ensure it should still be published, publish it

        dnskey_t *key = NULL;
        if(ISOK(ret = dnssec_keystore_load_private_key_from_parameters(args->algorithm, args->tag, args->flags, args->domain, &key))) // key properly released
        {
            assert(key != NULL);

            if(dnskey_is_unpublished(key, time(NULL)))
            {
                log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: unpublish: out of its publish time window", args->domain, args->algorithm, args->tag, ntohs(args->flags));

                if(ISOK(ret = database_service_zone_remove_dnskey(key)))
                {
                    // remove the key from the store and rename the files

                    dnssec_keystore_delete_key(key);
                }
                else
                {
                    // the key was not removed

                    // if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                    // try again later (zone_policy_process will be called)

                    log_warn("dnskey: %{dnsname}: +%03d+%05d/%d: unpublish: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
                }
            }
            else
            {
                if(dnskey_has_explicit_delete(key))
                {
                    log_warn("dnskey: %{dnsname}: +%03d+%05d/%d: unpublish: key should not be unpublished (not until %T)", args->domain, args->algorithm, args->tag, ntohs(args->flags), key->epoch_delete);
                }
                else
                {
                    log_warn("dnskey: %{dnsname}: +%03d+%05d/%d: unpublish: key should not be unpublished (ever)", args->domain, args->algorithm, args->tag, ntohs(args->flags));
                }
            }

            dnskey_release(key);

            zone_desc_t *zone_desc = zone_acquirebydnsname(args->domain);

            if(zone_desc != NULL)
            {
                if(ISOK(ret = zone_policy_process(zone_desc)))
                {
                    log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: unpublish: post-unpublish policy process done", args->domain, args->algorithm, args->tag, ntohs(args->flags));
                }
                else
                {
                    log_err("dnskey: %{dnsname}: +%03d+%05d/%d: unpublish: post-unpublish policy process failed: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
                }
                zone_release(zone_desc);
            }
        }
        else
        {
            assert(key == NULL);
            log_err("dnskey: %{dnsname}: +%03d+%05d/%d: unpublish cancelled: private key not available: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
        }

        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: unpublish: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
    }

    database_service_zone_resignature_dnskey_alarm_args_free(args);
}

static ya_result database_service_zone_resignature_unpublish_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args *)args_;
    ya_result                                            ret = SUCCESS;

    if(!cancel)
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: removal ...", args->domain, args->algorithm, args->tag, ntohs(args->flags));

        if(thread_pool_try_enqueue_call(database_service_zone_resignature_publish_dnskey_tp, database_service_zone_resignature_unpublish_dnskey_thread, args, NULL, "dnskey-unpublish alarm") == LOCK_TIMEOUT)
        {
            ret = ALARM_REARM;
        }
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: removal alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));

        database_service_zone_resignature_dnskey_alarm_args_free(args);
    }

    return ret;
}

static void database_service_zone_resignature_activate_dnskey_thread(void *args_)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args *)args_;

    dnskey_t                                            *key = NULL;
    ya_result                                            ret = dnssec_keystore_load_private_key_from_parameters(args->algorithm, args->tag, args->flags, args->domain, &key);
    if(ISOK(ret))
    {
        uint32_t state = dnskey_state_get(key);

        if((state & DNSKEY_KEY_IS_ACTIVE) == 0) // not active yet ?
        {
            time_t now = time(NULL);

            if((state & DNSKEY_KEY_IS_IN_ZONE) == 0) // not in zone yet ?
            {
                // will be automatically added, except if there is no signing key for this

                /*
                 * YADIFA-168 key point
                 *
                 * current: KSK or nothing
                 *
                 * should be: ((policy without a KSK) || (!policy but zone without a KSK)) => ZSK allowed, else KSK only
                 */

                bool         can_edit_dnskey_rrsig = false;

                zone_desc_t *zone_desc = zone_acquirebydnsname(args->domain);
                if(zone_desc != NULL)
                {
                    dnssec_policy *dp = zone_desc->dnssec_policy;
                    if(dp != NULL)
                    {
                        if(dnssec_policy_defines_ksk(dp))
                        {
                            // ksk only
                            can_edit_dnskey_rrsig = dnssec_keystore_has_usable_ksk(dnskey_get_domain(key), now);
                        }
                        else
                        {
                            can_edit_dnskey_rrsig = true; // (args->flags == DNSKEY_FLAGS_KSK) || (args->flags == DNSKEY_FLAGS_ZSK);
                        }
                    }
                    else
                    {
                        if(dnssec_keystore_has_any_ksk(dnskey_get_domain(key)))
                        {
                            can_edit_dnskey_rrsig = dnssec_keystore_has_usable_ksk(dnskey_get_domain(key), now);
                        }
                        else
                        {
                            can_edit_dnskey_rrsig = dnssec_keystore_has_usable_zsk(dnskey_get_domain(key), now);
                        }
                    }
                    zone_release(zone_desc);
                }

                if(!can_edit_dnskey_rrsig)
                {
                    log_info(
                        "dnskey: %{dnsname}: +%03d+%05d/%d: is not in the zone and cannot be added (no KSK can be "
                        "used)",
                        args->domain,
                        args->algorithm,
                        args->tag,
                        ntohs(args->flags));
                    dnskey_release(key);
                    database_service_zone_resignature_dnskey_alarm_args_free(args);
                    return;
                }

                if(ISOK(ret = database_service_zone_update_published_keys(args->domain)))
                {
                    log_info("dnskey: %{dnsname}: DNSKEY rrset updated, triggered by key activation", args->domain);
                }
                else
                {
                    log_err("dnskey: %{dnsname}: +%03d+%05d/%d: is not in the zone and cannot be added: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);

                    dnskey_release(key);
                    database_service_zone_resignature_dnskey_alarm_args_free(args);
                    return;
                }
            }

            zone_desc_t *zone_desc = zone_acquirebydnsname(args->domain);

            if(zone_desc != NULL)
            {
                dnskey_state_enable(key, DNSKEY_KEY_IS_ACTIVE);

                database_service_zone_dnssec_maintenance(zone_desc);

#if HAS_EVENT_DYNAMIC_MODULE
                if(dynamic_module_dnskey_interface_chain_available())
                {
                    dynamic_module_on_dnskey_activate(key);
                }
#endif
                zone_release(zone_desc);
            }
        }

        dnskey_release(key);

        log_info("dnskey: %{dnsname}: +%03d+%05d/%d: activation", args->domain, args->algorithm, args->tag, ntohs(args->flags));
    }
    else
    {
        zone_desc_t *zone_desc = zone_acquirebydnsname(args->domain);

        if(zone_desc != NULL)
        {
            if(zone_rrsig_nsupdate_allowed(zone_desc))
            {
                if(args->flags == DNSKEY_FLAGS_ZSK)
                {
                    log_notice("dnskey: %{dnsname}: +%03d+%05d/%d: activation failed: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
                }
                else if(args->flags == DNSKEY_FLAGS_KSK)
                {
                    log_info("dnskey: %{dnsname}: +%03d+%05d/%d: activation failed, which is probably expected: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
                }
                else
                {
                    log_warn("dnskey: %{dnsname}: could not activate +%03d+%05d/%d: %r, and flags aren't ZSK nor KSK", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
                }
            }
            else
            {
                log_err("dnskey: %{dnsname}: +%03d+%05d/%d: activation failed: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
            }
            zone_release(zone_desc);
        }
        else
        {
            log_err("dnskey: %{dnsname}: +%03d+%05d/%d: activation failed: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
        }
    }

    database_service_zone_resignature_dnskey_alarm_args_free(args);
}

static ya_result database_service_zone_resignature_activate_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args *)args_;
    ya_result                                            ret = SUCCESS;

    if(!cancel)
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: activation ...", args->domain, args->algorithm, args->tag, ntohs(args->flags));

        if(thread_pool_try_enqueue_call(database_service_zone_resignature_publish_dnskey_tp, database_service_zone_resignature_activate_dnskey_thread, args, NULL, "dnskey-activate alarm") == LOCK_TIMEOUT)
        {
            ret = ALARM_REARM;
        }
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: activation alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        database_service_zone_resignature_dnskey_alarm_args_free(args);
    }

    return ret;
}

static void database_service_zone_resignature_deactivate_dnskey_thread(void *args_)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args *)args_;

    log_info("dnskey: %{dnsname}: +%03d+%05d/%d: deactivation", args->domain, args->algorithm, args->tag, ntohs(args->flags));

    zone_desc_t *zone_desc = zone_acquirebydnsname(args->domain);
    if(zone_desc != NULL)
    {
        database_service_zone_dnssec_maintenance(zone_desc);

#if HAS_EVENT_DYNAMIC_MODULE
        if(dynamic_module_dnskey_interface_chain_available())
        {
            dnskey_t *key = NULL;
            ya_result ret = dnssec_keystore_load_private_key_from_parameters(args->algorithm, args->tag, args->flags, args->domain, &key);
            if(ISOK(ret))
            {
                dynamic_module_on_dnskey_inactive(key);
                dnskey_release(key);
            }
            else
            {
                log_warn("dnskey: %{dnsname}: +%03d+%05d/%d: could not load key to notify deactivation to module", args->domain, args->algorithm, args->tag, ntohs(args->flags));
            }
        }
#endif

        zone_release(zone_desc);
    }

    database_service_zone_resignature_dnskey_alarm_args_free(args);
}

static ya_result database_service_zone_resignature_deactivate_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args *)args_;
    ya_result                                            ret = SUCCESS;

    if(!cancel)
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: deactivation ...", args->domain, args->algorithm, args->tag, ntohs(args->flags));

        if(thread_pool_try_enqueue_call(database_service_zone_resignature_publish_dnskey_tp, database_service_zone_resignature_deactivate_dnskey_thread, args, NULL, "dnskey-deactivate alarm") == LOCK_TIMEOUT)
        {
            ret = ALARM_REARM;
        }
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: deactivation alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        database_service_zone_resignature_dnskey_alarm_args_free(args);
    }

    return ret;
}

void database_service_zone_dnskey_set_alarms_for_key(zdb_zone_t *zone, dnskey_t *key)
{
    log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: setting alarms", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)));

    time_t now = time(NULL);

    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    bool in_zone = zdb_zone_contains_dnskey_record_for_key(zone, key);
    // bool signs = zdb_zone_apex_contains_rrsig_record_by_key(zone, key);
    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

    uint32_t state = dnskey_state_get(key);

    int32_t  publish_epoch = dnskey_get_publish_epoch(key);
    int32_t  active_epoch = dnskey_get_activate_epoch(key);
    int32_t  inactive_epoch = dnskey_get_inactive_epoch(key);
    int32_t  delete_epoch = dnskey_get_delete_epoch(key);

    bool     give_up = false;

    if(publish_epoch > active_epoch)
    {
        log_warn(
            "dnskey: %{dnsname}: +%03d+%05d/%d: publication after activation %T > %T, setting publication to "
            "activation",
            dnskey_get_domain(key),
            dnskey_get_algorithm(key),
            dnskey_get_tag(key),
            ntohs(dnskey_get_flags(key)),
            publish_epoch,
            active_epoch);
        publish_epoch = active_epoch;
    }

    if(inactive_epoch > delete_epoch)
    {
        log_warn("dnskey: %{dnsname}: +%03d+%05d/%d: deactivation after delete %T > %T, setting delete to deactivation",
                 dnskey_get_domain(key),
                 dnskey_get_algorithm(key),
                 dnskey_get_tag(key),
                 ntohs(dnskey_get_flags(key)),
                 inactive_epoch,
                 delete_epoch);
        delete_epoch = inactive_epoch;
    }

    if((give_up |= (publish_epoch >= delete_epoch)))
    {
        log_err("dnskey: %{dnsname}: +%03d+%05d/%d: publication at or after deletion %T >= %T", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)), publish_epoch, delete_epoch);
    }

    if((give_up |= (active_epoch >= inactive_epoch)))
    {
        log_err("dnskey: %{dnsname}: +%03d+%05d/%d: activation at or after deactivation %T >= %T", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)), publish_epoch, delete_epoch);
    }

    if(give_up)
    {
        log_notice("dnskey: %{dnsname}: +%03d+%05d/%d: gave up setting alarms", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)));
        return;
    }

    int32_t when;

    // if the key will need to be published

    if(now < delete_epoch)
    {
        // and the key hasn't been published already

        bool publish_queued = false;

        if(!in_zone)
        {
            // follow the rule, if the key is not in the zone and should be, arm its publication even if it's never
            // activated

            if((state & DNSKEY_KEY_PUBLISH_ARMED) == 0)
            {
                // mark the key as timed for publication and arm said publication
                // once the key is added, activation will occur too if needed

                when = publish_epoch;

                dnskey_state_enable(key, DNSKEY_KEY_PUBLISH_ARMED);

                log_info("dnskey: %{dnsname}: +%03d+%05d/%d: will be published at %T", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)), when);

                alarm_event_node_t *event = alarm_event_new( // dnskey publish (resignature)
                    when,
                    database_service_zone_resignature_dnskey_alarm_unique_key(key, ALARM_KEY_ZONE_DNSKEY_PUBLISH),
                    database_service_zone_resignature_publish_dnskey_alarm,
                    database_service_zone_resignature_dnskey_alarm_args_new(key),
                    ALARM_DUP_REMOVE_LATEST,
                    "dnskey publish to zone");

                alarm_set(zone->alarm_handle, event);

                publish_queued = true;
            }
            else
            {
                log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: already marked to be published", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)));
            }
        }

        // if the key needs to be activated ...

        if(now < inactive_epoch)
        {
            if((state & DNSKEY_KEY_ACTIVATE_ARMED) == 0)
            {
                // mark the key as timed for activation and arm said activation

                // sig_validity_regeneration
                when = MIN(MAX(active_epoch - zone->sig_validity_regeneration_seconds, now - zone->sig_validity_regeneration_seconds - 5), publish_epoch);
#if DEBUG
                log_info(
                    "dnskey: %{dnsname}: +%03d+%05d/%d: activation alarm set to %T but activation is really at %T "
                    "(regeneration is: %i)",
                    dnskey_get_domain(key),
                    dnskey_get_algorithm(key),
                    dnskey_get_tag(key),
                    ntohs(dnskey_get_flags(key)),
                    when,
                    active_epoch,
                    zone->sig_validity_regeneration_seconds);
#endif

                if(!(publish_queued && (when <= publish_epoch)))
                {
                    dnskey_state_enable(key, DNSKEY_KEY_ACTIVATE_ARMED);
                    log_info("dnskey: %{dnsname}: +%03d+%05d/%d: will be activated at %T", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)), when);

                    // set alarm

                    alarm_event_node_t *event = alarm_event_new( // dnskey activate (resignature)
                        when,
                        database_service_zone_resignature_dnskey_alarm_unique_key(key, ALARM_KEY_ZONE_DNSKEY_ACTIVATE),
                        database_service_zone_resignature_activate_dnskey_alarm,
                        database_service_zone_resignature_dnskey_alarm_args_new(key),
                        ALARM_DUP_REMOVE_LATEST,
                        "dnskey activate from zone");

                    alarm_set(zone->alarm_handle, event);
                }
                else
                {
                    log_info(
                        "dnskey: %{dnsname}: +%03d+%05d/%d: will be activated along with publication at %T", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)), MAX(publish_epoch, now));
                }
            }
            else
            {
                log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: already marked to be activated", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)));
            }
        }
    } // if now < delete epoch

    // the actions to take if the key was not in the zone or needed to be activated are made.

    // deactivate, remove ...

    if(in_zone)
    {
        if(now <= inactive_epoch)
        {
            if((state & DNSKEY_KEY_DEACTIVATE_ARMED) != 0)
            {
                // mark the key as timed for activation and arm said activation

                dnskey_state_enable(key, DNSKEY_KEY_DEACTIVATE_ARMED);

                when = inactive_epoch;

                log_info("dnskey: %{dnsname}: +%03d+%05d/%d: will be deactivated at %T", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)), when);

                // set alarm
                // @note 20220715 edf -- maybe this should be called earlier too ... (?)
                alarm_event_node_t *event = alarm_event_new( // dnskey deactivate (resignature)
                    when,
                    database_service_zone_resignature_dnskey_alarm_unique_key(key, ALARM_KEY_ZONE_DNSKEY_DEACTIVATE),
                    database_service_zone_resignature_deactivate_dnskey_alarm,
                    database_service_zone_resignature_dnskey_alarm_args_new(key),
                    ALARM_DUP_REMOVE_LATEST,
                    "dnskey deactivate from zone");

                alarm_set(zone->alarm_handle, event);
            }
            else
            {
                log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: already marked to be deactivated", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)));
            }
        }

        if((state & DNSKEY_KEY_DELETE_ARMED) == 0)
        {
            dnskey_state_enable(key, DNSKEY_KEY_DELETE_ARMED);

            when = delete_epoch;

            log_info("dnskey: %{dnsname}: +%03d+%05d/%d: will be unpublished at %T", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)), when);

            alarm_event_node_t *event = alarm_event_new( // dnskey unpublish (resignature)
                when,
                database_service_zone_resignature_dnskey_alarm_unique_key(key, ALARM_KEY_ZONE_DNSKEY_UNPUBLISH),
                database_service_zone_resignature_unpublish_dnskey_alarm,
                database_service_zone_resignature_dnskey_alarm_args_new(key),
                ALARM_DUP_REMOVE_LATEST,
                "dnskey unpublish from zone");

            alarm_set(zone->alarm_handle, event);
        }
        else
        {
            log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: already marked to be unpublished", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)));
        }
    } // in zone

    log_debug("dnskey: %{dnsname}: +%03d+%05d/%d: alarms have been set", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key), ntohs(dnskey_get_flags(key)));
}

/**
 *
 * Fetches all (smart signing) events of all the keys of a zone and arms them.
 *
 * @param zone
 */

void database_service_zone_dnskey_set_alarms(zdb_zone_t *zone)
{
    // set alarms for the timings of the keys
    // (publish, activate, inactivate, unpublish)
    // this should probably only be done after the zone is mounted (else race could occur)

    log_info("database-service: %{dnsname}: set DNSKEY alarms", zone->origin);

    time_t now = time(NULL);

    for(int_fast32_t i = 0;; ++i)
    {
        dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_at_index(zone->origin, i);

        if(key == NULL)
        {
            break;
        }

        if(dnskey_get_flags(key) != (DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY))
        {
            if(!dnskey_is_activated(key, now))
            {
                continue;
            }

            if(!dnskey_is_private(key))
            {
                continue;
            }

            break;
        }

        database_service_zone_dnskey_set_alarms_for_key(zone, key);

        dnskey_release(key);
    }

    for(int_fast32_t i = 0;; ++i)
    {
        dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_at_index(zone->origin, i);

        if(key == NULL)
        {
            break;
        }

        database_service_zone_dnskey_set_alarms_for_key(zone, key);

        dnskey_release(key);
    }

    log_debug("database-service: %{dnsname}: DNSKEY alarms have been set", zone->origin);
}

static ya_result database_service_zone_dnskey_set_alarms_on_all_zones_callback(zone_desc_t *zone_desc, void *args)
{
    (void)args;
    bool is_primary;

    zone_lock(zone_desc, ZONE_LOCK_READONLY);
    is_primary = (zone_desc->type == ZT_PRIMARY);
    zdb_zone_t *zone = zone_get_loaded_zone(zone_desc);
    zone_unlock(zone_desc, ZONE_LOCK_READONLY);

    if(!is_primary)
    {
        if(zone != NULL)
        {
            zdb_zone_release(zone);
        }

        log_debug("%{dnsname}: not primary, skipping setting of the DNSKEY alarm (part of a batch)", zone_origin(zone_desc));

        return SUCCESS;
    }

    if(zone != NULL)
    {
        if(zdb_zone_is_maintained(zone))
        {
            log_debug("%{dnsname}: setting DNSKEY alarm (part of a batch)", zone->origin);
            database_service_zone_dnskey_set_alarms(zone);
        }
        else
        {
            log_debug("%{dnsname}: not maintained, skipping setting of the DNSKEY alarm (part of a batch)", zone->origin);
        }

        zdb_zone_release(zone);
    }
    return SUCCESS;
}

void                                              database_service_zone_dnskey_set_alarms_on_all_zones() { zone_desc_for_all(database_service_zone_dnskey_set_alarms_on_all_zones_callback, NULL); }

static database_service_zone_resignature_parms_s *database_service_zone_resignature_parms_alloc(zone_desc_t *zone_desc)
{
    database_service_zone_resignature_parms_s *parm;

    ZALLOC_OBJECT_OR_DIE(parm, database_service_zone_resignature_parms_s, DSZZRPRM_TAG);
    parm->zone_desc = zone_desc;

    return parm;
}

void database_service_zone_resignature_parms_free(database_service_zone_resignature_parms_s *parm)
{
#if DEBUG
    memset(parm, 0xff, sizeof(database_service_zone_resignature_parms_s));
#endif
    ZFREE_OBJECT(parm);
}

#endif

#if ZDB_HAS_PRIMARY_SUPPORT && ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT

static void database_service_zone_dnssec_maintenance_thread(void *parms_)
{
    database_service_zone_resignature_parms_s *parms = (database_service_zone_resignature_parms_s *)parms_;
    zone_desc_t                               *zone_desc = parms->zone_desc;
    ya_result                                  return_code;

    if(zone_desc == NULL)
    {
        // this happening probably means a buffer overrun has occurred, likely a corruption of the memory heap

        log_err("zone sign: database_service_zone_dnssec_maintenance_thread called with a NULL descriptor");
        logger_flush(); // yes, it's important to flush for this
        database_service_zone_resignature_parms_free(parms);
        return;
    }

    yassert(zone_desc != NULL);

    if(!zone_maintains_dnssec(zone_desc))
    {
        log_warn(
            "zone sign: %{dnsname}: resignature triggered although the feature was explicitly disabled : ignoring "
            "request.",
            zone_origin(zone_desc));

        database_service_zone_resignature_parms_free(parms);

        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        return;
    }

    if(dnscore_shuttingdown())
    {
        log_warn("zone sign: %{dnsname}: resignature called while shutting down : ignoring request.", zone_origin(zone_desc));

        database_service_zone_resignature_parms_free(parms);

        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        return;
    }

    zone_lock(zone_desc, ZONE_LOCK_SIGNATURE);

    const uint32_t must_be_off = ZONE_STATUS_LOAD | ZONE_STATUS_LOADING | ZONE_STATUS_DROP | ZONE_STATUS_DROPPING | ZONE_STATUS_SAVING_ZONE_FILE | ZONE_STATUS_SAVING_AXFR_FILE | ZONE_STATUS_SIGNATURES_UPDATING | ZONE_STATUS_DYNAMIC_UPDATE |
                                 ZONE_STATUS_DYNAMIC_UPDATING;

#if DEBUG
    log_debug("database_service_zone_dnssec_maintenance(%{dnsname}@%p=%i)", zone_origin(zone_desc), zone_desc, zone_desc->rc);
#endif

    if((zone_get_status(zone_desc) & must_be_off) != 0)
    {
        log_err("zone sign: %{dnsname}: conflicting status: %08x instead of 0", zone_origin(zone_desc), (zone_get_status(zone_desc) & must_be_off));

        zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);

        database_service_zone_resignature_parms_free(parms);

        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        return;
    }

    zone_set_status(zone_desc, ZONE_STATUS_SIGNATURES_UPDATING);

    // do a bunch of signatures

    zdb_zone_t *zone = zone_get_loaded_zone(zone_desc);

    if(zone != NULL)
    {
        // should have a starting point, cylcing trough the nodes
        // that way there will be no increasingly long scans

        if(zdb_zone_is_maintained(zone))
        {
            log_debug("zone sign: %{dnsname}: signatures update", zone_origin(zone_desc));

            if(FAIL(return_code = zdb_zone_maintenance(zone)))
            {
#if DEBUG
                log_info("zone sign: %{dnsname}: failed with %r and earliest signature expiration happens at %T", zone_origin(zone_desc), return_code, zone->progressive_signature_update.earliest_signature_expiration);
#endif
                switch(return_code)
                {
                    case ZDB_ERROR_ZONE_IS_NOT_DNSSEC:
                        log_warn(
                            "zone sign: %{dnsname}: unable to sign, it has not been configured as DNSSEC (disabling "
                            "maintenance)",
                            zone_origin(zone_desc));
                        zdb_zone_set_maintained(zone, false);
                        break;
                    case ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED:
                        log_info("zone sign: %{dnsname}: could not refresh signatures, it is already being signed", zone_origin(zone_desc));
                        break;
                    case ZDB_ERROR_ZONE_NO_ZSK_PRIVATE_KEY_FILE:
                        log_warn(
                            "zone sign: %{dnsname}: unable to try to refresh signatures because there are no private "
                            "keys available (pausing maintenance)",
                            zone_origin(zone_desc));
                        // zdb_zone_set_maintained(zone, false);
                        zdb_zone_set_maintenance_paused(zone, true);
#if YADIFA_257
                        /*
                         * if zone is policed
                         *   wait for a minute then enable maintenance again and retry
                         *   do that using an alarm
                         */
                        if(zone_desc->dnssec_policy != NULL)
                        {
                            time_t ts = time(NULL) + 60;
                            log_info("zone sign: %{dnsname}: will try to enable maintenance and update signatures at %T", zone_origin(zone_desc), ts);
                            database_zone_enable_maintenance_and_update_signatures_at(zone, ts);
                        }
#endif
                        break;
                    case DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM:
                        log_warn(
                            "zone sign: %{dnsname}: unable to refresh signatures because there is a key with an "
                            "unsupported algorithm (disabling maintenance)",
                            zone_origin(zone_desc));
                        zdb_zone_set_maintained(zone, false);
                        break;
                    case ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY:
                        log_info("zone sign: %{dnsname}: unable to sign, the journal is full (pausing maintenance)", zone_origin(zone_desc));
                        zdb_zone_set_maintenance_paused(zone, true);
                        zone_clear_status(zone_desc, ZONE_STATUS_SIGNATURES_UPDATING);
                        zdb_zone_info_background_store_zone(zone_origin(zone_desc));
                        break;
                    default:
                        log_err("zone sign: %{dnsname}: signature failed: %r", zone_origin(zone_desc), return_code);
                        break;
                }
            }
            else if(return_code == 0) // no signature have been done, let's scan the current status
            {
                log_debug("zone sign: %{dnsname}: earliest signature expiration at %T", zone_origin(zone_desc), zone->progressive_signature_update.earliest_signature_expiration);

                time_t soon = time(NULL) + 1;
                if(zone->progressive_signature_update.earliest_signature_expiration < soon)
                {
                    // queue
                    database_zone_update_signatures(zone->origin, zone_desc, zone);
                }
                else
                {
                    // the signature should happen before of course ...
                    // alarm queue
                    database_zone_update_signatures_at(zone, zone->progressive_signature_update.earliest_signature_expiration);
                }
            }
            else // let's just restart this asap
            {
                log_debug("zone sign: %{dnsname}: quota reached, signature will resume as soon as possible", zone_origin(zone_desc));

                database_zone_update_signatures_resume(zone->origin, zone_desc, zone);

                if((zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_MODIFIED) != 0)
                {
                    notify_secondaries(zone_origin(zone_desc));
                }
            }
        }
        else
        {
            log_info("zone sign: %{dnsname}: maintenance disabled", zone_origin(zone_desc));
            database_zone_update_signatures_allow_queue(zone->origin, zone_desc, zone);
        }

        zdb_zone_release(zone);
    }
    else
    {
        log_err("zone sign: %{dnsname}: zone has not been loaded yet", zone_origin(zone_desc));
    }

    // release

    zone_clear_status(zone_desc, ZONE_STATUS_PROCESSING | ZONE_STATUS_SIGNATURES_UPDATE | ZONE_STATUS_SIGNATURES_UPDATING | ZONE_STATUS_PROCESSING);

    log_debug("zone sign: %{dnsname}: signatures update end", zone_origin(zone_desc));

    database_service_zone_resignature_parms_free(parms);

    zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);

    database_fire_zone_processed(zone_desc);
    zone_release(zone_desc);
}

ya_result database_service_zone_dnssec_maintenance_lock_for(zone_desc_t *zone_desc,
                                                            uint8_t      zone_desc_owner) // one thread for all the program
{
    yassert(zone_desc != NULL);

    if(!zone_is_primary(zone_desc))
    {
        return INVALID_STATE_ERROR;
    }

    const uint8_t *origin = zone_origin(zone_desc);

    log_debug1("database_service_zone_dnssec_maintenance(%{dnsname}@%p=%i)", origin, zone_desc, zone_desc->rc);

    if(!zone_maintains_dnssec(zone_desc))
    {
        log_debug1("database_service_zone_dnssec_maintenance: %{dnsname} has signature maintenance disabled", origin);
        return FEATURE_NOT_SUPPORTED;
    }

    log_debug1("zone sign: %{dnsname}: locking zone for signature update", origin);

    if(zone_desc_owner == 0)
    {
        if(FAIL(zone_lock(zone_desc, ZONE_LOCK_SIGNATURE)))
        {
            log_err("zone sign: %{dnsname}: failed to lock zone settings", origin);

            return INVALID_STATE_ERROR;
        }
    }

    log_debug("zone sign: %{dnsname}", origin);

    if(zone_get_status(zone_desc) & (ZONE_STATUS_SIGNATURES_UPDATE | ZONE_STATUS_SIGNATURES_UPDATING))
    {
        // already loading
#if DEBUG
        zone_desc_log(MODULE_MSG_HANDLE, MSG_DEBUG1, zone_desc, "database_service_zone_resignature");
#endif
        log_debug("zone sign: %{dnsname}: already having its signatures updated", origin);

        ya_result ret;

        if(zone_desc->loaded_zone != NULL)
        {
            database_zone_update_signatures_at(zone_desc->loaded_zone, time(NULL) + 5);
            ret = SERVICE_ALREADY_RUNNING;
        }
        else
        {
            log_err("zone sign: %{dnsname}: zone not bound", origin);
            ret = ZDB_READER_ZONENOTLOADED;
        }

        if(zone_desc_owner == 0)
        {
            zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE); // locked in this call
        }

        return ret;
    }

    log_debug("zone sign: %{dnsname}: zone signatures update begin", origin);

    zone_clear_status(zone_desc, ZONE_STATUS_STARTING_UP);
    zone_set_status(zone_desc, ZONE_STATUS_SIGNATURES_UPDATE);

    database_service_zone_resignature_parms_s *database_zone_resignature_parms = database_service_zone_resignature_parms_alloc(zone_desc);
    zone_acquire(zone_desc);
    database_service_zone_resignature_queue_thread(database_service_zone_dnssec_maintenance_thread, database_zone_resignature_parms, NULL, "database_zone_resignature_thread");

    log_debug1("zone sign: %{dnsname}: unlocking zone for signature update", origin);

    if(zone_desc_owner == 0)
    {
        zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE); // locked in this call
    }

    return SUCCESS;
}

ya_result database_service_zone_dnssec_maintenance(zone_desc_t *zone_desc) // one thread for all the program
{
    ya_result ret = database_service_zone_dnssec_maintenance_lock_for(zone_desc, ZONE_LOCK_SIGNATURE);
    return ret;
}

ya_result database_service_zone_resignature_init()
{
    mutex_lock(&database_service_zone_resignature_publish_dnskey_mtx);

    if(database_service_zone_resignature_publish_dnskey_tp == NULL)
    {
        if(!g_config->hidden_primary)
        {
            database_service_zone_resignature_publish_dnskey_tp = thread_pool_init_ex(1, 1024, "keypub");
        }
        else
        {
            database_service_zone_resignature_publish_dnskey_tp = thread_pool_init_ex(8, 0x100000, "keypub");
        }
    }
    mutex_unlock(&database_service_zone_resignature_publish_dnskey_mtx);

    return (database_service_zone_resignature_publish_dnskey_tp != NULL) ? SUCCESS : THREAD_CREATION_ERROR;
}

ya_result database_service_zone_resignature_finalize()
{
    mutex_lock(&database_service_zone_resignature_publish_dnskey_mtx);

    if(database_service_zone_resignature_publish_dnskey_tp != NULL)
    {
        thread_pool_destroy(database_service_zone_resignature_publish_dnskey_tp);
        database_service_zone_resignature_publish_dnskey_tp = NULL;
    }
    mutex_unlock(&database_service_zone_resignature_publish_dnskey_mtx);

    return (database_service_zone_resignature_publish_dnskey_tp != NULL) ? SUCCESS : ERROR;
}

#endif

/**
 * @}
 */

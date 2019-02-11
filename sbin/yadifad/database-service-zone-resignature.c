/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2019, EURid vzw. All rights reserved.
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
/** @defgroup database Routines for database manipulations
 *  @ingroup yadifad
 *  @brief database functions
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
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "server-config.h"

#include <dnscore/logger.h>
#include <dnscore/timeformat.h>
#include <dnscore/dnskey-keyring.h>
#include <dnscore/thread_pool.h>

#include <dnsdb/dnssec.h>
#include <dnsdb/rrsig.h>
#include <dnsdb/zdb_rr_label.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_process.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/dynupdate-diff.h>
#include <dnsdb/zdb-zone-maintenance.h>

#include "database-service.h"
#include "database-service-zone-resignature.h"

#include "notify.h"

#ifndef HAS_DYNUPDATE_DIFF_ENABLED
#error "HAS_DYNUPDATE_DIFF_ENABLED not defined"
#endif

#if !HAS_RRSIG_MANAGEMENT_SUPPORT
#error "RRSIG management support disabled : this file should not be compiled"
#endif

#define MODULE_MSG_HANDLE g_server_logger

#define DBUPSIGP_TAG 0x5047495350554244
#define RESIGALR_TAG 0x524c414749534552

ya_result zone_policy_process(zone_desc_s *zone_desc);

static struct thread_pool_s *database_service_zone_resignature_publish_dnskey_tp = NULL;
static mutex_t database_service_zone_resignature_publish_dnskey_mtx = MUTEX_INITIALIZER;

extern logger_handle *g_server_logger;
extern zone_data_set database_zone_desc;

struct database_service_zone_resignature_init_callback_s
{
    zone_desc_s *zone_desc;
    dnskey_keyring keyring;
    u64 total_signature_valitity_time; // to compute the mean validity period
    u32 signature_count;
    u32 missing_signatures_count;
    u32 unverifiable_signatures_count;
    u32 earliest_expiration_epoch;
    u32 smallest_validity_period;
    u32 biggest_validity_period;
};

struct database_service_zone_resignature_alarm_s
{
    zone_desc_s *zone_desc;
    zdb_zone *zone;
};

typedef struct database_service_zone_resignature_alarm_s database_service_zone_resignature_alarm_s;

#define DSZZRPRM_TAG 0x4d5250525a5a5344

struct database_service_zone_resignature_dnskey_alarm_args
{
    u8 *domain;
    u16 flags;
    u16 tag;
    u8 algorithm;
};

typedef struct database_service_zone_resignature_dnskey_alarm_args database_service_zone_resignature_dnskey_alarm_args;

struct database_service_zone_resignature_parms_s
{
    zone_desc_s *zone_desc;
};

typedef struct database_service_zone_resignature_parms_s database_service_zone_resignature_parms_s;

static u32
database_service_zone_resignature_dnskey_alarm_unique_key(const dnssec_key *key, u32 operation)
{
    u32 tag = dnssec_key_get_tag_const(key);
    u32 alg = dnssec_key_get_algorithm(key);
    
    return operation | (tag << 8) | (alg << 24);
}

database_service_zone_resignature_dnskey_alarm_args*
database_service_zone_resignature_dnskey_alarm_args_new(const dnssec_key *key)
{
    database_service_zone_resignature_dnskey_alarm_args *ret;
    ZALLOC_OR_DIE(database_service_zone_resignature_dnskey_alarm_args*,ret,database_service_zone_resignature_dnskey_alarm_args, RESIGALR_TAG);
    ret->domain = dnsname_zdup(dnssec_key_get_domain(key));
    ret->tag = dnssec_key_get_tag_const(key);
    ret->algorithm = dnssec_key_get_algorithm(key);
    ret->flags = key->flags;
    return ret;
}

void
database_service_zone_resignature_dnskey_alarm_args_free(database_service_zone_resignature_dnskey_alarm_args *args)
{
    dnsname_zfree(args->domain);
    ZFREE(args,database_service_zone_resignature_dnskey_alarm_args);
}

static ya_result
database_service_zone_add_dnskey(dnssec_key *key)
{
    // make a dynupdate query update that adds the record
    
    dynupdate_message dmsg;
    packet_unpack_reader_data reader;
    dynupdate_message_init(&dmsg, dnssec_key_get_domain(key), CLASS_IN);
    ya_result ret;

    if(ISOK(ret = dynupdate_message_add_dnskey(&dmsg, 86400, key)))
    {
        dynupdate_message_set_reader(&dmsg, &reader);
        u16 count = dynupdate_message_get_count(&dmsg);

        packet_reader_skip(&reader, DNS_HEADER_LENGTH);
        packet_reader_skip_fqdn(&reader);
        packet_reader_skip(&reader, 4);

        // the update is ready : push it

        zdb_zone *zone = zdb_acquire_zone_read_double_lock_from_fqdn(g_config->database, dnssec_key_get_domain(key), ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
        if(zone != NULL)
        {
            if(ISOK(ret = dynupdate_diff(zone, &reader, count, ZDB_ZONE_MUTEX_DYNUPDATE, DYNUPDATE_UPDATE_RUN)))
            {
                // done
                log_info("dnskey: %{dnsname}: +%03d+%05d/%d key added",
                        dnssec_key_get_domain(key), dnssec_key_get_algorithm(key), dnssec_key_get_tag_const(key), ntohs(dnssec_key_get_flags(key)));
                        //args->domain, args->algorithm, args->tag, ntohs(args->flags));
                
                notify_slaves(zone->origin);

                zdb_zone_set_maintained(zone, TRUE);
            }

            zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

            zdb_zone_release(zone);
        }
    }
    
    if(FAIL(ret))
    {
        log_err("dnskey: %{dnsname}: +%03d+%05d/%d could not add key: %r",
                dnssec_key_get_domain(key), dnssec_key_get_algorithm(key), dnssec_key_get_tag_const(key), dnssec_key_get_flags(key), ret);
                //args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
    }

    dynupdate_message_finalise(&dmsg);
    
    return ret;
}

static ya_result
database_service_zone_remove_dnskey(dnssec_key *key)
{
    // make a dynupdate query update that removes the record

    dynupdate_message dmsg;
    packet_unpack_reader_data reader;
    dynupdate_message_init(&dmsg, dnssec_key_get_domain(key), CLASS_IN);
    ya_result ret;

    if(ISOK(ret = dynupdate_message_del_dnskey(&dmsg, key)))
    {
        dynupdate_message_set_reader(&dmsg, &reader);
        u16 count = dynupdate_message_get_count(&dmsg);

        packet_reader_skip(&reader, DNS_HEADER_LENGTH);
        packet_reader_skip_fqdn(&reader);
        packet_reader_skip(&reader, 4);

        // the update is ready : push it

        zdb_zone *zone = zdb_acquire_zone_read_double_lock_from_fqdn(g_config->database, dnssec_key_get_domain(key), ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
        if(zone != NULL)
        {
            if(ISOK(ret = dynupdate_diff(zone, &reader, count, ZDB_ZONE_MUTEX_DYNUPDATE, DYNUPDATE_UPDATE_RUN)))
            {
                // done
                log_info("dnskey: %{dnsname}: +%03d+%05d/%d key removed",
                        dnssec_key_get_domain(key), dnssec_key_get_algorithm(key), dnssec_key_get_tag_const(key), dnssec_key_get_flags(key));
                        //args->domain, args->algorithm, args->tag, ntohs(args->flags));
                
                notify_slaves(zone->origin);
            }

            zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

            zdb_zone_release(zone);
        }
    }

    if(FAIL(ret))
    {
        log_err("dnskey: %{dnsname}: +%03d+%05d/%d could not add key: %r",
                dnssec_key_get_domain(key), dnssec_key_get_algorithm(key), dnssec_key_get_tag_const(key), dnssec_key_get_flags(key), ret);
                //args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
    }

    dynupdate_message_finalise(&dmsg);
    
    return ret;
}


static void*
database_service_zone_resignature_publish_dnskey_thread(void *args_)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    
    log_info("dnskey: %{dnsname}: +%03d+%05d/%d publish", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        
    // grab the key, ensure it should still be published, publish it

    dnssec_key *key;
    ya_result ret;
    
    if(ISOK(ret = dnssec_keystore_load_private_key_from_parameters(args->algorithm, args->tag, args->flags, args->domain, &key)) && (key != NULL))
    {
        if(dnskey_is_published(key, time(NULL)))
        {
            database_service_zone_add_dnskey(key);
        }
        else if(dnskey_is_unpublished(key, time(NULL)))
        {
            log_warn("dnskey: %{dnsname}: +%03d+%05d/%d publish cancelled: key should not be published anymore", args->domain, args->algorithm, args->tag, ntohs(args->flags));

            // delete the key if it's in the zone

            ret = database_service_zone_remove_dnskey(key);

            // remove the key from the store and rename the files

            dnssec_keystore_delete_key(key);
        }
        else
        {
            log_warn("dnskey: %{dnsname}: +%03d+%05d/%d publish cancelled: key should not be published yet", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        }

        dnskey_release(key);

        zone_desc_s *zone_desc = zone_acquirebydnsname(args->domain);
        if(zone_desc != NULL)
        {
            zone_policy_process(zone_desc);
            zone_release(zone_desc);
        }
    }
    else
    {
        log_err("dnskey: %{dnsname}: +%03d+%05d/%d publish cancelled: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
    }

    database_service_zone_resignature_dnskey_alarm_args_free(args);
    
    return NULL;
}

static ya_result
database_service_zone_resignature_publish_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    ya_result ret = SUCCESS;
    
    if(!cancel)
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d publish ...", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        
        if(thread_pool_try_enqueue_call(database_service_zone_resignature_publish_dnskey_tp,
                database_service_zone_resignature_publish_dnskey_thread,
                args,
                NULL,
                "dnskey-publish alarm") == LOCK_TIMEOUT)
        {
            
            ret = ALARM_REARM;
        }
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d publish alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        database_service_zone_resignature_dnskey_alarm_args_free(args);
    }
    
    return ret;
}

static void*
database_service_zone_resignature_unpublish_dnskey_thread(void *args_)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    log_info("dnskey: %{dnsname}: +%03d+%05d/%d removal", args->domain, args->algorithm, args->tag, ntohs(args->flags));
    
    ya_result ret;
        
    // grab the key, ensure it should still be published, publish it

    dnssec_key *key = NULL;
    if(ISOK(ret = dnssec_keystore_load_private_key_from_parameters(args->algorithm, args->tag, args->flags, args->domain, &key)) && (key != NULL))
    {
        if(dnskey_is_unpublished(key, time(NULL)))
        {
            ret = database_service_zone_remove_dnskey(key);

            // remove the key from the store and rename the files

            dnssec_keystore_delete_key(key);
        }
        else
        {
            if(key->epoch_delete != 0)
            {
                log_warn("dnskey: %{dnsname}: +%03d+%05d/%d removal cancelled: key should not be unpublished (not until %T)", args->domain, args->algorithm, args->tag, ntohs(args->flags), key->epoch_delete);
            }
            else
            {
                log_warn("dnskey: %{dnsname}: +%03d+%05d/%d removal cancelled: key should not be unpublished (ever)", args->domain, args->algorithm, args->tag, ntohs(args->flags), key->epoch_delete);
            }
        }

        dnskey_release(key);
    }
    else
    {
        log_err("dnskey: %{dnsname}: +%03d+%05d/%d removal cancelled: private key not available: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
    }
    
    database_service_zone_resignature_dnskey_alarm_args_free(args);
    
    return NULL;
}

static ya_result
database_service_zone_resignature_unpublish_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    ya_result ret = SUCCESS;
    
    if(!cancel)
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d removal ...", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        
        if(thread_pool_try_enqueue_call(database_service_zone_resignature_publish_dnskey_tp,
                database_service_zone_resignature_unpublish_dnskey_thread,
                args,
                NULL,
                "dnskey-unpublish alarm") == LOCK_TIMEOUT)
        {   
            ret = ALARM_REARM;
        }
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d removal alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        
        database_service_zone_resignature_dnskey_alarm_args_free(args);
    }
    
    return ret;
}

static void*
database_service_zone_resignature_activate_dnskey_thread(void *args_)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    
    log_info("dnskey: %{dnsname}: +%03d+%05d/%d activation", args->domain, args->algorithm, args->tag, ntohs(args->flags));
    
    zone_desc_s *zone_desc = zone_acquirebydnsname(args->domain);
    if(zone_desc != NULL)
    {
        database_service_zone_dnssec_maintenance(zone_desc);
        zone_release(zone_desc);
    }
    
    database_service_zone_resignature_dnskey_alarm_args_free(args);
    
    return NULL;
}

static ya_result
database_service_zone_resignature_activate_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    ya_result ret = SUCCESS;
    
    if(!cancel)
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d activation ...", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        
        if(thread_pool_try_enqueue_call(database_service_zone_resignature_publish_dnskey_tp,
                database_service_zone_resignature_activate_dnskey_thread,
                args,
                NULL,
                "dnskey-activate alarm") == LOCK_TIMEOUT)
        {   
            ret = ALARM_REARM;
        }
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d activation alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        database_service_zone_resignature_dnskey_alarm_args_free(args);
    }
    
    return ret;
}

static void*
database_service_zone_resignature_deactivate_dnskey_thread(void *args_)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    
    log_info("dnskey: %{dnsname}: +%03d+%05d/%d deactivation", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        
    zone_desc_s *zone_desc = zone_acquirebydnsname(args->domain);
    if(zone_desc != NULL)
    {
        database_service_zone_dnssec_maintenance(zone_desc);
        zone_release(zone_desc);
    }
    
    database_service_zone_resignature_dnskey_alarm_args_free(args);
    
    return NULL;
}

static ya_result
database_service_zone_resignature_deactivate_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    ya_result ret = SUCCESS;
    
    if(!cancel)
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d deactivation ...", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        
        if(thread_pool_try_enqueue_call(database_service_zone_resignature_publish_dnskey_tp,
                database_service_zone_resignature_deactivate_dnskey_thread,
                args,
                NULL,
                "dnskey-deactivate alarm") == LOCK_TIMEOUT)
        {   
            ret = ALARM_REARM;
        }
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d deactivation alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        database_service_zone_resignature_dnskey_alarm_args_free(args);
    }
    
    return ret;
}

void
database_service_zone_dnskey_set_alarms_for_key(zdb_zone *zone, dnssec_key *key)
{
    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    bool in_zone = zdb_zone_contains_dnskey_record_for_key(zone, key);
    bool signs = zdb_zone_apex_contains_rrsig_record_by_key(zone, key);
    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

    // if not published, when ?
    // see if any of the key matches
    if(!in_zone)
    {
        u32 when = dnskey_get_publish_epoch(key);
        if(when != 0)
        {
            // set an alarm at 'when' to add the key

            log_debug("dnskey: %{dnsname}: +%03d+%05d/%d will be published at %T", dnssec_key_get_domain(key), key->algorithm, key->tag, ntohs(key->flags), when);

            alarm_event_node *event = alarm_event_new(
                    when,
                    database_service_zone_resignature_dnskey_alarm_unique_key(key, ALARM_KEY_ZONE_DNSKEY_PUBLISH),
                    database_service_zone_resignature_publish_dnskey_alarm,
                    database_service_zone_resignature_dnskey_alarm_args_new(key),
                    ALARM_DUP_REMOVE_LATEST,
                    "dnskey publish to zone");

            alarm_set(zone->alarm_handle, event);
        }
    }

    // if not activated, when ?
    // see if any signature is by this key ? (KSK/ZSK) (SOA + DNSKEY)
    if(!signs)
    {
        u32 when = dnskey_get_activate_epoch(key);

        if(when != 0)
        {
            log_debug("dnskey: %{dnsname} +%03d+%05d/%d will be activated at %T", dnssec_key_get_domain(key), key->algorithm, key->tag, ntohs(key->flags), when);

            // set alarm

            alarm_event_node *event = alarm_event_new(
                    when,
                    database_service_zone_resignature_dnskey_alarm_unique_key(key, ALARM_KEY_ZONE_DNSKEY_ACTIVATE),
                    database_service_zone_resignature_activate_dnskey_alarm,
                    database_service_zone_resignature_dnskey_alarm_args_new(key),
                    ALARM_DUP_REMOVE_LATEST,
                    "dnskey activate from zone");

            alarm_set(zone->alarm_handle, event);
        }
    }

    // if not deactivated, when ?
    // see if any signature is by this key ? (KSK/ZSK) (SOA + DNSKEY)
    else
    {
        u32 when = dnskey_get_inactive_epoch(key);
        if(when != 0)
        {
            log_debug("dnskey: %{dnsname} +%03d+%05d/%d will be deactivated at %T", dnssec_key_get_domain(key), key->algorithm, key->tag, ntohs(key->flags), when);

            // set alarm

            alarm_event_node *event = alarm_event_new(
                    when,
                    database_service_zone_resignature_dnskey_alarm_unique_key(key, ALARM_KEY_ZONE_DNSKEY_DEACTIVATE),
                    database_service_zone_resignature_deactivate_dnskey_alarm,
                    database_service_zone_resignature_dnskey_alarm_args_new(key),
                    ALARM_DUP_REMOVE_LATEST,
                    "dnskey deactivate from zone");

            alarm_set(zone->alarm_handle, event);
        }
    }

    // if not unpublished, when ?
    // see if any of the key matches
    if(in_zone)
    {
        u32 when = dnskey_get_delete_epoch(key);
        if(when != 0)
        {
            log_debug("dnskey: %{dnsname} +%03d+%05d/%d will be unpublished at %T", dnssec_key_get_domain(key), key->algorithm, key->tag, ntohs(key->flags), when);

            alarm_event_node *event = alarm_event_new(
                    when,
                    database_service_zone_resignature_dnskey_alarm_unique_key(key, ALARM_KEY_ZONE_DNSKEY_UNPUBLISH),
                    database_service_zone_resignature_unpublish_dnskey_alarm,
                    database_service_zone_resignature_dnskey_alarm_args_new(key),
                    ALARM_DUP_REMOVE_LATEST,
                    "dnskey unpublish from zone");

            alarm_set(zone->alarm_handle, event);
        }
    }
}

/**
 * 
 * Fetches all (smart signing) events of all the keys of a zone and arms them.
 * 
 * @param zone
 */

void
database_service_zone_dnskey_set_alarms(zdb_zone *zone)
{
    // set alarms for the timings of the keys
    // (publish, activate, inactivate, unpublish)
    // this should probably only be done after the zone is mounted (else race could occur)
    
    for(int i = 0; ; ++i)
    {
        dnssec_key *key = dnssec_keystore_acquire_key(zone->origin, i);

        if(key == NULL)
        {
            break;
        }

        database_service_zone_dnskey_set_alarms_for_key(zone, key);

        dnskey_release(key);
    }
}

static ya_result
database_service_zone_dnskey_set_alarms_on_all_zones_callback(zone_desc_s *zone_desc, void *args)
{
    (void)args;
    bool is_master;
    
    zone_lock(zone_desc, ZONE_LOCK_READONLY);
    is_master = (zone_desc->type == ZT_MASTER);
    zdb_zone *zone = zone_get_loaded_zone(zone_desc);
    zone_unlock(zone_desc, ZONE_LOCK_READONLY);
    
    if(!is_master)
    {
        log_debug("%{dnsname}: not master, skipping setting of the DNSKEY alarm (part of a batch)", zone->origin);
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
    }
    return SUCCESS;
}

void
database_service_zone_dnskey_set_alarms_on_all_zones()
{
    zone_desc_for_all(database_service_zone_dnskey_set_alarms_on_all_zones_callback, NULL);
}


static database_service_zone_resignature_parms_s*
database_service_zone_resignature_parms_alloc(zone_desc_s *zone_desc)
{
    database_service_zone_resignature_parms_s *parm;
    
    ZALLOC_OR_DIE(database_service_zone_resignature_parms_s*, parm, database_service_zone_resignature_parms_s, DSZZRPRM_TAG);
    parm->zone_desc = zone_desc;

    
    return parm;
}

void
database_service_zone_resignature_parms_free(database_service_zone_resignature_parms_s *parm)
{
#ifdef DEBUG
    memset(parm, 0xff, sizeof(database_service_zone_resignature_parms_s));
#endif
    ZFREE(parm, database_service_zone_resignature_parms_s);
}


static void*
database_service_zone_dnssec_maintenance_thread(void *parms_)
{
    database_service_zone_resignature_parms_s *parms = (database_service_zone_resignature_parms_s*)parms_;
    zone_desc_s *zone_desc = parms->zone_desc;
    ya_result return_code;
    
    yassert(zone_desc != NULL);
    
    if(!zone_maintains_dnssec(zone_desc))
    {
        log_warn("zone sign: %{dnsname}: resignature triggered although the feature was explicitly disabled : ignoring request.", zone_desc->origin);
        
        zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
        
        database_service_zone_resignature_parms_free(parms);

        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        return NULL;
    }
    
    zone_lock(zone_desc, ZONE_LOCK_SIGNATURE);
    
    const u32 must_be_off = ZONE_STATUS_LOAD | ZONE_STATUS_LOADING | \
                            ZONE_STATUS_DROP | ZONE_STATUS_DROPPING | \
                            ZONE_STATUS_SAVING_ZONE_FILE | ZONE_STATUS_SAVING_AXFR_FILE   | \
                            ZONE_STATUS_SIGNATURES_UPDATING | ZONE_STATUS_DYNAMIC_UPDATE  | \
                            ZONE_STATUS_DYNAMIC_UPDATING;
    
#ifdef DEBUG
    log_debug("database_service_zone_dnssec_maintenance(%{dnsname}@%p=%i)", zone_desc->origin, zone_desc, zone_desc->rc);
#endif
    
    if((zone_get_status(zone_desc) & must_be_off) != 0)
    {
        log_err("zone sign: %{dnsname}: conflicting status: %08x instead of 0", zone_desc->origin, (zone_get_status(zone_desc) & must_be_off));
    
        zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
        
        database_service_zone_resignature_parms_free(parms);
        
        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        return NULL;
    }
        
    zone_set_status(zone_desc, ZONE_STATUS_SIGNATURES_UPDATING);
        
    // do a bunch of signatures

    zdb_zone *zone = zone_get_loaded_zone(zone_desc);
    
    if(zone != NULL)
    {    
        // should have a starting point, cylcing trough the nodes
        // that way there will be no increasingly long scans
        
        if(zdb_zone_is_maintained(zone))
        {
            log_debug("zone sign: %{dnsname}: signatures update", zone_desc->origin);

            if(FAIL(return_code = zdb_zone_maintenance(zone)))
            {
                switch(return_code)
                {
                    case ZDB_ERROR_ZONE_IS_NOT_DNSSEC:
                        log_warn("zone sign: %{dnsname}: unable to sign, it has not been configured as DNSSEC (disabling maintenance)", zone_desc->origin);
                        zdb_zone_set_maintained(zone, FALSE);
                        break;
                    case ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED:
                        log_info("zone sign: %{dnsname}: could not refresh signatures, it is already being signed", zone_desc->origin);
                        break;
                    case ZDB_ERROR_ZONE_NO_ZSK_PRIVATE_KEY_FILE:
                        log_warn("zone sign: %{dnsname}: unable to try to refresh signatures because there are no private keys available (disabling maintenance)", zone_desc->origin);
                        zdb_zone_set_maintained(zone, FALSE);
                        break;
                    case DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM:
                        log_warn("zone sign: %{dnsname}: unable to refresh signatures because there is a key with an unsupported algorithm (disabling maintenance)", zone_desc->origin);
                        zdb_zone_set_maintained(zone, FALSE);
                        break;
                    default:
                       log_err("zone sign: %{dnsname}: signature failed: %r", zone_desc->origin, return_code);
                       break;
                }
            }
            else if(return_code == 0)   // no signature have been done, let's scan the current status
            {
                log_debug("zone sign: %{dnsname}: earliest signature expiration at %T", zone_desc->origin, zone->progressive_signature_update.earliest_signature_expiration);

                time_t soon = time(NULL) + 1;
                if(zone->progressive_signature_update.earliest_signature_expiration < soon)
                {
                    // queue
                    database_zone_update_signatures(zone->origin, zone_desc, zone);
                }
                else
                {
                    // alarm queue
                    database_zone_update_signatures_at(zone, zone->progressive_signature_update.earliest_signature_expiration);
                }
            }
            else                        // let's just restart this asap
            {
                zone_set_status(zone_desc, ZONE_STATUS_MODIFIED);

                log_debug("zone sign: %{dnsname}: quota reached, signature will resume as soon as possible", zone_desc->origin);

                database_zone_update_signatures(zone->origin, zone_desc, zone);

                notify_slaves(zone_desc->origin);
            }
        }
        else
        {
            log_debug("zone sign: %{dnsname}: maintenance disabled", zone_desc->origin);
        }

        zdb_zone_release(zone);
    }
    else
    {
        log_err("zone sign: %{dnsname}: zone has not been loaded yet", zone_desc->origin);
    }
    
    // release
    
    zone_clear_status(zone_desc, ZONE_STATUS_PROCESSING|ZONE_STATUS_SIGNATURES_UPDATE|ZONE_STATUS_SIGNATURES_UPDATING|ZONE_STATUS_PROCESSING);
    
    log_debug("zone sign: %{dnsname}: signatures update end", zone_desc->origin);
    
    database_service_zone_resignature_parms_free(parms);
    
    zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
    
    database_fire_zone_processed(zone_desc);
    zone_release(zone_desc);
    
    return NULL;
}

ya_result
database_service_zone_dnssec_maintenance(zone_desc_s *zone_desc) // one thread for all the program
{
    yassert(zone_desc != NULL);
    
    log_debug1("database_service_zone_dnssec_maintenance(%{dnsname}@%p=%i)", zone_desc->origin, zone_desc, zone_desc->rc);
    
    if(!zone_maintains_dnssec(zone_desc))
    {
        log_debug1("database_service_zone_dnssec_maintenance: %{dnsname} has signature maintenance disabled", zone_desc->origin);
        return ERROR;
    }
    
    log_debug1("zone sign: %{dnsname}: locking zone for signature update", zone_desc->origin);
    
    if(FAIL(zone_lock(zone_desc, ZONE_LOCK_SIGNATURE)))
    {
        log_err("zone sign: %{dnsname}: failed to lock zone settings", zone_desc->origin);
        
        return ERROR;
    }
    
    const u8 *origin = zone_desc->origin;
    
    log_info("zone sign: %{dnsname}", origin);
    
    if(zone_get_status(zone_desc) & (ZONE_STATUS_SIGNATURES_UPDATE|ZONE_STATUS_SIGNATURES_UPDATING))
    {
        // already loading
        
        zone_desc_log(MODULE_MSG_HANDLE, MSG_DEBUG1, zone_desc, "database_service_zone_resignature");
        
        log_info("zone sign: %{dnsname}: already having its signatures updated", origin);
        
        if(zone_desc->loaded_zone != NULL)
        {
            database_zone_update_signatures_at(zone_desc->loaded_zone, time(NULL) + 5);
        }
        else
        {
            log_err("zone sign: %{dnsname}: zone not bound", origin);
        }
        
        zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
                                
        return ERROR;
    }
    
    log_debug("zone sign: %{dnsname}: zone signatures update begin", origin);

    zone_clear_status(zone_desc, ZONE_STATUS_STARTING_UP);
    zone_set_status(zone_desc, ZONE_STATUS_SIGNATURES_UPDATE);
    
    database_service_zone_resignature_parms_s *database_zone_resignature_parms = database_service_zone_resignature_parms_alloc(zone_desc);
    zone_acquire(zone_desc);
    database_service_zone_resignature_queue_thread(database_service_zone_dnssec_maintenance_thread, database_zone_resignature_parms, NULL, "database_zone_resignature_thread");
    
    log_debug1("zone sign: %{dnsname}: unlocking zone for signature update", origin);
    
    zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
    
    return SUCCESS;
}

ya_result
database_service_zone_resignature_init()
{
    mutex_lock(&database_service_zone_resignature_publish_dnskey_mtx);
        
    if(database_service_zone_resignature_publish_dnskey_tp == NULL)
    {
        database_service_zone_resignature_publish_dnskey_tp = thread_pool_init_ex(1, 1024, "dnskey-publish");
    }
    mutex_unlock(&database_service_zone_resignature_publish_dnskey_mtx);
    
    return (database_service_zone_resignature_publish_dnskey_tp != NULL)?SUCCESS:ERROR;
}

ya_result
database_service_zone_resignature_finalize()
{
    mutex_lock(&database_service_zone_resignature_publish_dnskey_mtx);
        
    if(database_service_zone_resignature_publish_dnskey_tp != NULL)
    {
        thread_pool_destroy(database_service_zone_resignature_publish_dnskey_tp);
        database_service_zone_resignature_publish_dnskey_tp = NULL;
    }
    mutex_unlock(&database_service_zone_resignature_publish_dnskey_mtx);
    
    return (database_service_zone_resignature_publish_dnskey_tp != NULL)?SUCCESS:ERROR;
}

/**
 * @}
 */

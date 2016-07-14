/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2016, EURid. All rights reserved.
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
#include "config.h"

#include <dnscore/logger.h>
#include <dnscore/timeformat.h>
#include <dnscore/dnskey-keyring.h>

#include <dnsdb/dnssec.h>
#include <dnsdb/rrsig.h>
#include <dnsdb/zdb_rr_label.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_process.h>
#include <dnsdb/zdb_icmtl.h>

#include "database-service.h"
#include "database-service-zone-resignature.h"

#if !HAS_RRSIG_MANAGEMENT_SUPPORT
#error "RRSIG management support disabled : this file should not be compiled"
#endif

#define MODULE_MSG_HANDLE g_server_logger

#define DBUPSIGP_TAG 0x5047495350554244

ya_result zone_policy_process(zone_desc_s *zone_desc);

extern logger_handle *g_server_logger;
extern zone_data_set database_zone_desc;

struct database_service_zone_resignature_init_callback_s
{
    zone_desc_s *zone_desc;
    dnskey_keyring keyring;
    u64 total_signature_valitity_time; // to compute the mean validity period
    u32 signature_count;
    u32 missing_signatures_count;
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
    ZALLOC_OR_DIE(database_service_zone_resignature_dnskey_alarm_args*,ret,database_service_zone_resignature_dnskey_alarm_args,GENERIC_TAG);
    ret->domain = dnsname_zdup(key->owner_name);
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
database_service_zone_resignature_publish_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    ya_result ret = ERROR;
    
    if(!cancel)
    {
        log_info("dnskey: %{dnsname}: +%03d+%05d/%d publish", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        
        // grab the key, ensure it should still be published, publish it
        
        dnssec_key *key;
        if(ISOK(ret = dnssec_keystore_load_private_key_from_parameters(args->algorithm, args->tag, args->flags, args->domain, &key)) && (key != NULL))
        {
            if(dnskey_is_published(key, time(NULL)))
            {
                zdb *db = g_config->database;
                zdb_zone *zone;
                if((zone = zdb_acquire_zone_read_double_lock_from_fqdn(db, args->domain, ZDB_ZONE_MUTEX_RRSIG_UPDATER, ZDB_ZONE_MUTEX_SIMPLEREADER)) != NULL)
                {
                    yassert(zdb_zone_islocked(zone));
                    
                    zdb_icmtl icmtl;
                    dnsname_vector apex_name;
                    DEBUG_RESET_dnsname(apex_name);
                    dnsname_to_dnsname_vector(zone->origin, &apex_name);
                    ya_result ret;
            
                    if(ISOK(ret = zdb_icmtl_begin(&icmtl, zone)))
                    {
                        zdb_zone_add_dnskey_from_key(zone, key);
                        
                        zdb_icmtl_end(&icmtl);
                    }
                    
                    zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER, ZDB_ZONE_MUTEX_SIMPLEREADER);
                }
            }
            else if(dnskey_is_unpublished(key, time(NULL)))
            {
                log_warn("dnskey: %{dnsname}: +%03d+%05d/%d publish cancelled: key should not be published anymore", args->domain, args->algorithm, args->tag, ntohs(args->flags));
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
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d publish alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));
    }
    
    database_service_zone_resignature_dnskey_alarm_args_free(args);
    
    return ret;
}

static ya_result
database_service_zone_resignature_unpublish_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    ya_result ret = ERROR;
    
    if(!cancel)
    {
        log_info("dnskey: %{dnsname}: +%03d+%05d/%d removal", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        
        // grab the key, ensure it should still be published, publish it
        
        dnssec_key *key;
        if(ISOK(ret = dnssec_keystore_load_private_key_from_parameters(args->algorithm, args->tag, args->flags, args->domain, &key)) && (key != NULL))
        {
            if(dnskey_is_unpublished(key, time(NULL)))
            {
                zdb *db = g_config->database;
                zdb_zone *zone;
                if((zone = zdb_acquire_zone_read_double_lock_from_fqdn(db, args->domain, ZDB_ZONE_MUTEX_RRSIG_UPDATER, ZDB_ZONE_MUTEX_SIMPLEREADER)) != NULL)
                {
                    zdb_icmtl icmtl;
                    dnsname_vector apex_name;
                    DEBUG_RESET_dnsname(apex_name);
                    dnsname_to_dnsname_vector(zone->origin, &apex_name);
                    ya_result ret;
            
                    if(ISOK(ret = zdb_icmtl_begin(&icmtl, zone)))
                    {
                        zdb_zone_remove_dnskey_from_key(zone, key);
                        zdb_icmtl_end(&icmtl);
                        zdb_zone_release_double_unlock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER, ZDB_ZONE_MUTEX_SIMPLEREADER);
                    }
                }
                
                // remove the key from the store and rename the files
                
                dnssec_keystore_delete_key(key);
            }
            else
            {
                log_warn("dnskey: %{dnsname}: +%03d+%05d/%d removal cancelled: key should not be unpublished", args->domain, args->algorithm, args->tag, ntohs(args->flags));
            }
            
            dnskey_release(key);
        }
        else
        {
            log_err("dnskey: %{dnsname}: +%03d+%05d/%d removal cancelled: private key not available: %r", args->domain, args->algorithm, args->tag, ntohs(args->flags), ret);
        }
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d removal alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));
    }
    
    database_service_zone_resignature_dnskey_alarm_args_free(args);
    
    return ret;
}

static ya_result
database_service_zone_resignature_activate_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    ya_result ret = ERROR;
    
    if(!cancel)
    {
        log_info("dnskey: %{dnsname}: +%03d+%05d/%d activation", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        
        zone_desc_s *zone_desc = zone_acquirebydnsname(args->domain);
        if(zone_desc != NULL)
        {
            database_service_zone_resignature(zone_desc);
            zone_release(zone_desc);
        }
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d activation alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));
    }
    
    database_service_zone_resignature_dnskey_alarm_args_free(args);
    
    return ret;
}

static ya_result
database_service_zone_resignature_deactivate_dnskey_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_dnskey_alarm_args *args = (database_service_zone_resignature_dnskey_alarm_args*)args_;
    ya_result ret = ERROR;
    
    if(!cancel)
    {
        log_info("dnskey: %{dnsname}: +%03d+%05d/%d deactivation", args->domain, args->algorithm, args->tag, ntohs(args->flags));
        
        zone_desc_s *zone_desc = zone_acquirebydnsname(args->domain);
        if(zone_desc != NULL)
        {
            database_service_zone_resignature(zone_desc);
            zone_release(zone_desc);
        }
    }
    else
    {
        log_debug("dnskey: %{dnsname}: +%03d+%05d/%d deactivation alarm cancelled", args->domain, args->algorithm, args->tag, ntohs(args->flags));
    }
    
    database_service_zone_resignature_dnskey_alarm_args_free(args);
    
    return ret;
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
                
                log_debug("dnskey: %{dnsname}: +%03d+%05d/%d will be published at %T", key->owner_name, key->algorithm, key->tag, ntohs(key->flags), when);
                
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
                log_debug("dnskey: %{dnsname} +%03d+%05d/%d will be activated at %T", key->owner_name, key->algorithm, key->tag, ntohs(key->flags), when);
                
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
                log_debug("dnskey: %{dnsname} +%03d+%05d/%d will be deactivated at %T", key->owner_name, key->algorithm, key->tag, ntohs(key->flags), when);
                
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
                log_debug("dnskey: %{dnsname} +%03d+%05d/%d will be unpublished at %T", key->owner_name, key->algorithm, key->tag, ntohs(key->flags), when);
                
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

        dnskey_release(key);
    }
}

static ya_result
database_service_zone_dnskey_set_alarms_on_all_zones_callback(zone_desc_s *zone_desc, void *args)
{
    (void)args;
    zone_lock(zone_desc, ZONE_LOCK_READONLY);
    zdb_zone *zone = zone_get_loaded_zone(zone_desc);
    zone_unlock(zone_desc, ZONE_LOCK_READONLY);
    if(zone != NULL)
    {
        database_service_zone_dnskey_set_alarms(zone);
    }
    return SUCCESS;
}

void
database_service_zone_dnskey_set_alarms_on_all_zones()
{
    zone_desc_for_all(database_service_zone_dnskey_set_alarms_on_all_zones_callback, NULL);
}

struct database_service_zone_resignature_parms_s
{
    zone_desc_s *zone_desc;
};

typedef struct database_service_zone_resignature_parms_s database_service_zone_resignature_parms_s;

static ya_result
database_service_zone_resignature_alarm(void *args_, bool cancel)
{
    database_service_zone_resignature_alarm_s *args = (database_service_zone_resignature_alarm_s*)args_;
    
    // verify that the keys are valid
    // generate keys if needs to be
    // sign the zone, not using the scheduler:
    //   lock for read
    //   (re)compute relevant signatures
    //   unlock for read
    //   lock for write
    //   store signatures
    //   loop until a quota has been reached
    
    if(!cancel)
    {
        database_zone_update_signatures(args->zone_desc->origin, args->zone_desc, args->zone);
    }
    
    zdb_zone_release(args->zone);
    zone_release(args->zone_desc);
#ifdef DEBUG
    memset(args, 0xff, sizeof(database_service_zone_resignature_alarm_s));
#endif
    free(args);
    
    return SUCCESS; // could return anything but ALARM_REARM
}

/**
 * Arms the trigger for the next resignature of the zone.
 * 
 * @param zone_desc
 * @param zone
 * @return 
 */

static ya_result
database_service_zone_resignature_arm(zone_desc_s *zone_desc, zdb_zone *zone)
{   
    if(zone_desc->signature.scheduled_sig_invalid_first >= zone_desc->signature.sig_invalid_first)
    {
        u32 now = time(NULL);
        
        u32 regeneration_before_invalid = 0;
        if(zone_desc->signature.scheduled_sig_invalid_first != ZONE_SIGNATURE_INVALID_FIRST_ASSUME_BROKEN)
        {
            if(zone_desc->signature.sig_validity_regeneration < zone_desc->signature.sig_invalid_first)
            {
                regeneration_before_invalid = zone_desc->signature.sig_invalid_first - zone_desc->signature.sig_validity_regeneration;
            }
            else
            {
                regeneration_before_invalid = now;
            }       
        }
        
        u32 alarm_epoch = MAX(regeneration_before_invalid, now);

        log_info("database: %{dnsname}: scheduling a signature update at %T", zone_desc->origin, alarm_epoch);

        database_service_zone_resignature_alarm_s *args;
        MALLOC_OR_DIE(database_service_zone_resignature_alarm_s*, args, sizeof(database_service_zone_resignature_alarm_s), DBUPSIGP_TAG);
        zone_acquire(zone_desc);
        args->zone_desc = zone_desc;
        zdb_zone_acquire(zone);
        args->zone = zone;

        /*
         * Sets the alarm to be called at the time the first signature will be invalidated
         * The first time the alarm will be called for the zone is reset to the new, earlier, value
         */

        alarm_event_node *event = alarm_event_new(
                        MAX(zone_desc->signature.sig_invalid_first, time(NULL) - 5),
                        ALARM_KEY_ZONE_SIGNATURE_UPDATE,
                        database_service_zone_resignature_alarm,
                        args,
                        ALARM_DUP_REMOVE_LATEST,
                        "database-service-zone-resignature");

        alarm_set(zone->alarm_handle, event);

        zone_desc->signature.scheduled_sig_invalid_first = zone_desc->signature.sig_invalid_first;
        
        return 1;
    }
    else
    {
        return 0;
    }
}

static ya_result
database_service_zone_resignature_init_callback(zdb_zone_process_label_callback_parms *parms)
{
    struct database_service_zone_resignature_init_callback_s *args = (struct database_service_zone_resignature_init_callback_s*)parms->args;
    
    if(!zdb_rr_label_has_records(parms->rr_label)) // no records on this label
    {
        if(!zdb_rr_label_has_records(parms->rr_label))
        {
            log_debug("database: %{dnsname}: %{dnsnamestack}: no records in label", parms->zone->origin, parms->fqdn_stack, parms->rr_label->resource_record_set);
        }
        
        return ZDB_ZONE_PROCESS_CONTINUE;
    }
    

    zdb_packed_ttlrdata*  rrsig_rrset = zdb_rr_label_get_rrset(parms->rr_label, TYPE_RRSIG);
    
    if(rrsig_rrset != NULL) // there are RRSIGs on the label
    {
        // for all types, check there is a valid signature for it
        
        // iterate through types
        // look in the signatures which one are covering them
        // proceed
        
        bool has_DS = zdb_rr_label_has_rrset(parms->rr_label, TYPE_DS);
        
        btree_iterator types_iter;
        btree_iterator_init(parms->rr_label->resource_record_set, &types_iter);
        while(btree_iterator_hasnext(&types_iter))
        {
            btree_node *node = btree_iterator_next_node(&types_iter);

            u16 type = node->hash; /** @note : NATIVETYPE */
            
            if(type == TYPE_RRSIG)
            {
                continue;
            }
    
            // is there a signature covering this ?
         
            bool type_is_covered = FALSE;
            
            for(zdb_packed_ttlrdata *rrsig_rr = rrsig_rrset; rrsig_rr != NULL; rrsig_rr = rrsig_rr->next)
            {
                u16 type_covered = RRSIG_TYPE_COVERED(rrsig_rr);
                
                if(type_covered != type)
                {
                    continue;
                }
                
                // key is signed by a valid key (exists, properly signed)
                // the keyring has been filled by keys that are valid at the time of the call


                u16 tag = RRSIG_KEY_TAG(rrsig_rrset);
                u8 algorithm = RRSIG_ALGORITHM(rrsig_rrset);

                if(dnskey_keyring_has_key(&args->keyring, algorithm, tag, parms->zone->origin))
                {
                    type_is_covered = TRUE;

                    u32 expires_on = RRSIG_VALID_UNTIL(rrsig_rr);
                    u32 valid_from = RRSIG_VALID_SINCE(rrsig_rr);

                    u32 validity_period = 0;

                    if(valid_from <= expires_on)
                    {
                        validity_period = expires_on - valid_from;
                    }

                    args->total_signature_valitity_time += validity_period;
                    args->signature_count++;
                    args->earliest_expiration_epoch = MIN(args->earliest_expiration_epoch, expires_on);
                    args->smallest_validity_period = MIN(args->smallest_validity_period, validity_period);
                    args->biggest_validity_period = MAX(args->biggest_validity_period, validity_period);
                }
            }
            
            if(!type_is_covered) // no signature is covering the current type
            {
                if(!ZDB_LABEL_ATORUNDERDELEGATION(parms->rr_label)) // we are not at or under a delegation
                {
                    // a signature is expected on this RRSET
#ifdef DEBUG
                    log_debug2("database_service_zone_resignature: missing signature above delegation: %{dnsnamestack} %{dnstype}", &parms->fqdn_stack, &type);
#endif
                    args->missing_signatures_count++;
                }
                else // we are at or under a delegation ...
                {
                    if(ZDB_LABEL_ATDELEGATION(parms->rr_label))
                    {
                        // the presence of a DS calls for a signature (of the DS)
                        if(zdb_zone_is_nsec3_optin(parms->zone) || !(type == TYPE_NS && has_DS)) // if the type is NS and there is a DS (signed or not, not the current problem) the signature is not needed
                        {
#ifdef DEBUG
                            log_debug2("database_service_zone_resignature: missing signature at delegation: %{dnsnamestack} %{dnstype}", &parms->fqdn_stack, &type);
#endif
                            args->missing_signatures_count++;
                        }
                    } // under a delegation, there should be no signature
                }
            }
            // else it does not matter
        } // for all types in the label
    }
    else // there are no signatures on the label
    {
        if(!ZDB_LABEL_ATORUNDERDELEGATION(parms->rr_label)) // we are not at or under a delegation
        {
            // a signature is expected
            
#ifdef DEBUG
            log_debug2("database_service_zone_resignature: no signature at delegation: %{dnsnamestack}", &parms->fqdn_stack);
#endif
            
            args->missing_signatures_count++;
        }
        else // we are at or under a delegation
        {
            if(ZDB_LABEL_ATDELEGATION(parms->rr_label))
            {
                // opt-in or the presence of a DS calls for a signature
                if(zdb_zone_is_nsec3_optin(parms->zone) || zdb_rr_label_has_rrset(parms->rr_label, TYPE_DS))
                {
#ifdef DEBUG
                    log_debug2("database_service_zone_resignature: no signature at delegation: %{dnsnamestack}", &parms->fqdn_stack);
#endif
                    args->missing_signatures_count++;
                }
            }
        }
    }

    return ZDB_ZONE_PROCESS_CONTINUE;
}

#if ZDB_HAS_NSEC3_SUPPORT
static ya_result
database_service_nsec3_zone_resignature_init_callback(zdb_zone_process_label_callback_parms *parms)
{
    struct database_service_zone_resignature_init_callback_s *args = (struct database_service_zone_resignature_init_callback_s*)parms->args;
    
    database_service_zone_resignature_init_callback(parms);

    if(parms->rr_label != NULL && parms->rr_label->nsec.dnssec != NULL)
    {
        nsec3_node *item =  parms->rr_label->nsec.nsec3->self;
        
        if(item != NULL)
        {
            zdb_packed_ttlrdata *rrsig_rrset = item->rrsig;

            if(rrsig_rrset != NULL)
            {
                do
                {
                    // key is signed by a valid key (exists, properly signed)
                    // the keyring has been filled by keys that are valid at the time of the call

                    
                    u16 tag = RRSIG_KEY_TAG(rrsig_rrset);
                    u8 algorithm = RRSIG_ALGORITHM(rrsig_rrset);
                    
                    if(dnskey_keyring_has_key(&args->keyring, algorithm, tag, parms->zone->origin))
                    {
                        // signature did not expire ...

                        u32 expires_on = RRSIG_VALID_UNTIL(rrsig_rrset);
                        u32 valid_from = RRSIG_VALID_SINCE(rrsig_rrset);

                        u32 validity_period = 0;

                        if(valid_from <= expires_on)
                        {
                            validity_period = expires_on - valid_from;
                        }


                        args->total_signature_valitity_time += validity_period;
                        args->signature_count++;
                        args->earliest_expiration_epoch = MIN(args->earliest_expiration_epoch, expires_on);
                        args->smallest_validity_period = MIN(args->smallest_validity_period, validity_period);
                        args->biggest_validity_period = MAX(args->biggest_validity_period, validity_period);
                    }

                    rrsig_rrset = rrsig_rrset->next;
                }
                while(rrsig_rrset != NULL);
            }
            else
            {
#ifdef DEBUG
                log_debug2("database_service_zone_resignature: no signature at NSEC3: %{digest32h}.%{dnsname}", item->digest, parms->zone->origin);
#endif
                
                args->missing_signatures_count++;
            }
        }
    }

    return ZDB_ZONE_PROCESS_CONTINUE;
}
#endif

ya_result
database_service_zone_resignature_init(zone_desc_s *zone_desc, zdb_zone *zone)
{
    // both are already locked
    
    log_debug("database: %{dnsname}: initialising signature maintenance", zone_desc->origin);
    
    u64 elapsed = timeus();
    
    struct database_service_zone_resignature_init_callback_s args;
        
    dnskey_keyring_init(&args.keyring);
    dnssec_keystore_add_valid_keys_from_fqdn(zone_desc->origin, elapsed / 1000000LL, &args.keyring);
    
    /// @todo 20160606 edf -- if no keys have been added to the keyring, stop processing ?
    
    args.zone_desc = zone_desc;
    args.total_signature_valitity_time = 0;
    args.signature_count = 0;
    args.missing_signatures_count = 0;
    args.earliest_expiration_epoch = MAX_U32;
    args.smallest_validity_period = MAX_U32;
    args.biggest_validity_period = 0;
    
    ya_result return_code;
    
#if ZDB_HAS_NSEC3_SUPPORT
    if(zdb_zone_is_nsec3(zone))
    {
        // if there is a (first) NSEC3PARAMADD record, then generate its chain
        
        return_code = zdb_zone_process_all_labels_from_zone(zone, database_service_nsec3_zone_resignature_init_callback, &args);
    }
    else
#endif
    {

        return_code = zdb_zone_process_all_labels_from_zone(zone, database_service_zone_resignature_init_callback, &args);
    }
    
    u64 now = timeus();
    
    elapsed = now - elapsed;
    
    log_debug("zone sign: %{dnsname}: took %.3fs", zone_desc->origin, elapsed / 1000000.0);
    
    now /= 1000000;
    
    u32 mean_validity_period = 0;
        
    if(args.signature_count > 0)
    {
        mean_validity_period = (u32)(args.total_signature_valitity_time / args.signature_count);
    }
    else
    {
        // no signatures were made during this pass
    }
    
    log_debug("zone sign: %{dnsname}: found: %u, missing: %u", zone_desc->origin, args.signature_count, args.missing_signatures_count);
    log_debug("zone sign: %{dnsname}: validity from %.3f days to %.3f days (mean of %.3f days)", zone_desc->origin,
                args.smallest_validity_period / 86400.0, args.biggest_validity_period / 86400.0, mean_validity_period / 86400.0);
    
    u32 next_resignature_epoch = MAX((s32)(args.earliest_expiration_epoch - g_config->sig_validity_regeneration), 0);
    
    if((now < next_resignature_epoch) && (args.missing_signatures_count == 0))
    {
        log_debug("zone sign: %{dnsname}: next one will be made before the next %.3f days", zone_desc->origin, (next_resignature_epoch - now) / 86400.0);
        zone_desc->signature.sig_invalid_first = next_resignature_epoch;
    }
    else
    {
        log_debug("zone sign: %{dnsname}: next one will be made as soon as possible", zone_desc->origin);
        if(args.missing_signatures_count == 0)
        {
            zone_desc->signature.sig_invalid_first = now - 1; // do it already (assumes we are not at 1970-01-01 00:00:01 and we'll see for 2^32)
        }
        else
        {
            zone_desc->signature.sig_invalid_first = ZONE_SIGNATURE_INVALID_FIRST_ASSUME_BROKEN; // missing signatures means we absolutely
        }                                                                                        // cannot trust the current signatures values
    }
    
    dnskey_keyring_destroy(&args.keyring);
    
    if(ISOK(return_code))
    {
        zone_desc->signature.scheduled_sig_invalid_first = MAX_S32;
        
        if(zone_maintains_dnssec(zone_desc))
        {
            return_code = database_service_zone_resignature_arm(zone_desc, zone);
        }
        else
        {
            log_debug("zone sign: %{dnsname}: DNSSEC maintenance is disabled on zone, no signature will be made", zone_desc->origin);
        }
    }
    
    return return_code;
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
database_service_zone_resignature_thread(void *parms_)
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
    log_debug("database_service_zone_resignature_thread(%{dnsname}@%p=%i)", zone_desc->origin, zone_desc, zone_desc->rc);
#endif
    
    if((zone_desc->status_flags & must_be_off) != 0)
    {
        log_err("zone sign: %{dnsname}: conflicting status: %08x instead of 0", zone_desc->origin, (zone_desc->status_flags & must_be_off));
    
        zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
        
        database_service_zone_resignature_parms_free(parms);
        zone_release(zone_desc);
        return NULL;
    }
        
    zone_desc->status_flags |= ZONE_STATUS_SIGNATURES_UPDATING;
        
    // do a bunch of signatures

    zdb_zone *zone = zone_get_loaded_zone(zone_desc);
    
    if(zone != NULL)
    {    
        // should have a starting point, cylcing trough the nodes
        // that way there will be no increasingly long scans

        log_debug("zone sign: %{dnsname}: signatures update", zone_desc->origin);

        if(FAIL(return_code = zdb_update_zone_signatures(zone, zone->sig_quota, zone_desc->signature.sig_invalid_first != ZONE_SIGNATURE_INVALID_FIRST_ASSUME_BROKEN)))
        {
            switch(return_code)
            {
                case ZDB_ERROR_ZONE_IS_NOT_DNSSEC:
                    log_warn("zone sign: %{dnsname}: unable to sign, it has not been configured as DNSSEC", zone_desc->origin);
                    break;
                case ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED:
                    log_info("zone sign: %{dnsname}: could not refresh signatures, it is already being signed", zone_desc->origin);
                    break;
                case ZDB_ERROR_ZONE_NO_ZSK_PRIVATE_KEY_FILE:
                    log_warn("zone sign: %{dnsname}: unable to try to refresh signatures because there are no private keys available", zone_desc->origin);
                    break;
                case DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM:
                    log_warn("zone sign: %{dnsname}: unable to refresh signatures because there is a key with an unsupported algorithm", zone_desc->origin);
                    break;
                default:
                   log_err("zone sign: %{dnsname}: signature failed: %r", zone_desc->origin, return_code);
                   break;
            }
        }
        else if(return_code == 0)   // no signature have been done, let's scan the current status
        {
            log_debug("zone sign: %{dnsname}: no signatures updated: scanning again", zone_desc->origin);

            database_service_zone_resignature_init(zone_desc, zone);
        }
        else                        // let's just restart this asap
        {
            time_t soon = time(NULL) + 1;
            log_debug("zone sign: %{dnsname}: arming signatures, moving scheduled time from %T to %T", zone_desc->origin, zone_desc->signature.scheduled_sig_invalid_first, soon);

            zone_desc->status_flags |= ZONE_STATUS_MODIFIED;
            zone_desc->signature.scheduled_sig_invalid_first = soon + 1;
            zone_desc->signature.sig_invalid_first = soon;
            return_code = database_service_zone_resignature_arm(zone_desc, zone);
        }

        zdb_zone_release(zone);
    }
    else
    {
        log_err("zone sign: %{dnsname}: zone has not been loaded yet", zone_desc->origin);
    }
    
    // release
    
    zone_desc->status_flags &= ~(ZONE_STATUS_PROCESSING|ZONE_STATUS_SIGNATURES_UPDATE|ZONE_STATUS_SIGNATURES_UPDATING|ZONE_STATUS_PROCESSING);
    
    log_debug("zone sign: %{dnsname}: signatures update end", zone_desc->origin);
    
    database_service_zone_resignature_parms_free(parms);
    
    zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
    zone_release(zone_desc);
    
    return NULL;
}

ya_result
database_service_zone_resignature(zone_desc_s *zone_desc) // one thread for all the program
{
    yassert(zone_desc != NULL);
    
    log_debug1("database_service_zone_resignature(%{dnsname}@%p=%i)", zone_desc->origin, zone_desc, zone_desc->rc);
    
    if(!zone_maintains_dnssec(zone_desc))
    {
        log_debug1("database_service_zone_resignature: %{dnsname} has signature maintenance disabled", zone_desc->origin);
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
    
    if(zone_desc->status_flags & (ZONE_STATUS_SIGNATURES_UPDATE|ZONE_STATUS_SIGNATURES_UPDATING))
    {
        // already loading
        
        zone_desc_log(MODULE_MSG_HANDLE, MSG_DEBUG1, zone_desc, "database_service_zone_resignature");
        
        log_info("zone sign: %{dnsname}: already having its signatures updated", origin);
        
        zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
                        
        return ERROR;
    }
    
    log_debug("zone sign: %{dnsname}: zone signatures update begin", origin);

    zone_desc->status_flags &= ~ZONE_STATUS_STARTING_UP;
    zone_desc->status_flags |= ZONE_STATUS_SIGNATURES_UPDATE;
    
    database_service_zone_resignature_parms_s *database_zone_resignature_parms = database_service_zone_resignature_parms_alloc(zone_desc);
    zone_acquire(zone_desc);
    database_service_zone_resignature_queue_thread(database_service_zone_resignature_thread, database_zone_resignature_parms, NULL, "database_zone_resignature_thread");
    
    log_debug1("zone sign: %{dnsname}: unlocking zone for signature update", origin);
    
    zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
    
    return SUCCESS;
}

/**
 * @}
 */

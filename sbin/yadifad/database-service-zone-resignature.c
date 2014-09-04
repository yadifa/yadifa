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

#include "config.h"

#include <dnscore/logger.h>
#include <dnscore/timeformat.h>

#include <dnsdb/dnssec.h>
#include <dnsdb/rrsig.h>
#include <dnsdb/zdb_rr_label.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_process.h>

#include "database-service.h"

#if !HAS_RRSIG_MANAGEMENT_SUPPORT
#error "RRSIG management support disabled : this file should not be compiled"
#endif

#define MODULE_MSG_HANDLE g_server_logger

extern logger_handle *g_server_logger;
extern zone_data_set database_zone_desc;

struct database_service_zone_resignature_init_callback_s
{
    zone_desc_s *zone_desc;
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

struct database_service_zone_resignature_parms_s
{
    zone_desc_s *zone_desc;
};

typedef struct database_service_zone_resignature_parms_s database_service_zone_resignature_parms_s;

static ya_result
database_service_zone_resignature_alarm(void *args_)
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
    
    database_zone_update_signatures(args->zone_desc->origin, args->zone_desc, args->zone);
    
    free(args);
    
    return SUCCESS; // could return anything but ALARM_REARM
}

static ya_result
database_service_zone_resignature_arm(zone_desc_s *zone_desc, zdb_zone *zone)
{
    if(zone_desc->signature.scheduled_sig_invalid_first >= zone_desc->signature.sig_invalid_first)
    {
        u32 now = time(NULL);
        
        u32 alarm_epoch = MAX(zone_desc->signature.sig_invalid_first - zone_desc->signature.sig_validity_regeneration, now);

        EPOCH_DEF(alarm_epoch);
        
        log_info("database: scheduling a signature update for '%{dnsname}' at %w", zone_desc->origin, EPOCH_REF(alarm_epoch));

        database_service_zone_resignature_alarm_s *args;
        MALLOC_OR_DIE(database_service_zone_resignature_alarm_s*, args, sizeof(database_service_zone_resignature_alarm_s), DBUPSIGP_TAG);
        args->zone_desc = zone_desc;
        args->zone = zone;

        /*
         * Sets the alarm to be called at the time the first signature will be invalidated
         * The first time the alarm will be called for the zone is reset to the new, earlier, value
         */

        alarm_event_node *event = alarm_event_alloc();
        event->epoch = zone_desc->signature.sig_invalid_first;
        event->function = database_service_zone_resignature_alarm;
        event->args = args;
        event->key = ALARM_KEY_ZONE_SIGNATURE_UPDATE;
        event->flags = ALARM_DUP_REMOVE_LATEST;
        event->text = "database-service-zone-resignature";

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
    

    zdb_packed_ttlrdata*  rrsig_rrset = zdb_rr_label_get_rrset(parms->rr_label, TYPE_RRSIG);
    
    if(rrsig_rrset != NULL)
    {
        do
        {
            u32 expires_on = RRSIG_VALID_UNTIL(rrsig_rrset);
            u32 valid_from = RRSIG_VALID_SINCE(rrsig_rrset);
            u16 type_covered = RRSIG_TYPE_COVERED(rrsig_rrset);

            u32 validity_period = 0;
            
            if(valid_from <= expires_on)
            {
                validity_period = expires_on - valid_from;
            }

            if(type_covered != TYPE_DNSKEY)
            {
                args->total_signature_valitity_time += validity_period;
                args->signature_count++;
                args->earliest_expiration_epoch = MIN(args->earliest_expiration_epoch, expires_on);
                args->smallest_validity_period = MIN(args->smallest_validity_period, validity_period);
                args->biggest_validity_period = MAX(args->biggest_validity_period, validity_period);
            }
            else
            {
                
            }

            rrsig_rrset = rrsig_rrset->next;
        }
        while(rrsig_rrset != NULL);
    }
    else
    {
        if(!ZDB_LABEL_ATORUNDERDELEGATION(parms->rr_label))
        {
            // a signature is expected
            
            if(RR_LABEL_HASRECORDS(parms->rr_label))
            {
                args->missing_signatures_count++;
            }
        }
        else // we are at or under a delegation
        {
            if(ZDB_LABEL_ATDELEGATION(parms->rr_label))
            {
                // the presence of a DS calls for a signature
                if(zdb_rr_label_get_rrset(parms->rr_label, TYPE_DS) != NULL)
                {
                    args->missing_signatures_count++;
                }
            }
        }
    }

    return ZDB_ZONE_PROCESS_CONTINUE;
}

ya_result
database_service_zone_resignature_init(zone_desc_s *zone_desc, zdb_zone *zone)
{
    // both are already locked
    
    log_debug("%{dnsname}: initialising signature maintenance", zone_desc->origin);
    
    u64 elapsed = timeus();
    
    struct database_service_zone_resignature_init_callback_s args;
    args.zone_desc = zone_desc;
    args.total_signature_valitity_time = 0;
    args.signature_count = 0;
    args.missing_signatures_count = 0;
    args.earliest_expiration_epoch = MAX_U32;
    args.smallest_validity_period = MAX_U32;
    args.biggest_validity_period = 0;
    
    ya_result return_code = zdb_zone_process_all_labels_from_zone(zone, database_service_zone_resignature_init_callback, &args);
   
    u64 now = timeus();
    
    elapsed = now - elapsed;
    
    log_debug1("%{dnsname}: signatures: took %.3fs", zone_desc->origin, elapsed / 1000000.0);
    
    now /= 1000000;
    
    u32 mean_validity_period = 0;
        
    if(args.signature_count > 0)
    {
        mean_validity_period = (u32)(args.total_signature_valitity_time / args.signature_count);
    }
    
    log_debug("%{dnsname}: signatures: found: %u, missing: %u", zone_desc->origin, args.signature_count, args.missing_signatures_count);
    log_debug("%{dnsname}: signatures: validity from %.3f days to %.3f days (mean of %.3f days)", zone_desc->origin,
                args.smallest_validity_period / 86400.0, args.biggest_validity_period / 86400.0, mean_validity_period / 86400.0);
    
    u32 next_resignature_epoch = MAX((s32)(args.earliest_expiration_epoch - g_config->sig_validity_regeneration), 0);
    
    if((now < next_resignature_epoch) && (args.missing_signatures_count == 0))
    {
        log_debug("%{dnsname}: signatures: next one will be made before the next %.3f days", zone_desc->origin, (next_resignature_epoch - now) / 86400.0);
        zone_desc->signature.sig_invalid_first = next_resignature_epoch;
    }
    else
    {
        log_debug("%{dnsname}: signatures: next one will be made as soon as possible", zone_desc->origin);
        zone_desc->signature.sig_invalid_first = now - 1; // do it already (0 would work too, of course)
    }
    
    if(ISOK(return_code))
    {
        zone_desc->signature.scheduled_sig_invalid_first = MAX_S32;
        
        return_code = database_service_zone_resignature_arm(zone_desc, zone);
    }
    
    return return_code;
}



static database_service_zone_resignature_parms_s*
database_service_zone_resignature_parms_alloc(zone_desc_s *zone_desc)
{
    database_service_zone_resignature_parms_s *parm;
    
    ZALLOC_OR_DIE(database_service_zone_resignature_parms_s*, parm, database_service_zone_resignature_parms_s, GENERIC_TAG);
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
        log_err("zone sign: conflicting status: %08x instead of 0", (zone_desc->status_flags & must_be_off));
    
        zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
        
        database_service_zone_resignature_parms_free(parms);
        zone_release(zone_desc);
        return NULL;
    }
        
    zone_desc->status_flags |= ZONE_STATUS_SIGNATURES_UPDATING;
        
    // do a bunch of signatures

    zdb_zone *zone = zone_desc->loaded_zone;
    
    // should have a starting point, cylcing trough the nodes
    // that way there will be no increasingly long scans
    
    if(FAIL(return_code = zdb_update_zone_signatures(zone, zone->sig_quota)))
    {
        log_err("zone signature failed: %r", return_code);
    }
    else if(return_code == 0)   // no signature have been done, let's scan the current status
    {
        database_service_zone_resignature_init(zone_desc, zone);
    }
    else                        // let's just restart this asap
    {
        return_code = database_service_zone_resignature_arm(zone_desc, zone);
    }
    
    // release
    
    zone_desc->status_flags &= ~(ZONE_STATUS_SIGNATURES_UPDATE|ZONE_STATUS_SIGNATURES_UPDATING|ZONE_STATUS_PROCESSING);
    
    database_service_zone_resignature_parms_free(parms);
    
    zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
    zone_acquire(zone_desc);
    
    return NULL;
}

ya_result
database_service_zone_resignature(zone_desc_s *zone_desc) // one thread for all the program
{
    yassert(zone_desc != NULL);
    
    log_debug1("database_serviec_zone_resignature(%{dnsname}@%p=%i)", zone_desc->origin, zone_desc, zone_desc->rc);
    
    log_debug1("database_service_zone_resignature: locking zone '%{dnsname}' for signing", zone_desc->origin);
    
    if(FAIL(zone_lock(zone_desc, ZONE_LOCK_SIGNATURE)))
    {
        log_err("zone sign: failed to lock zone settings for '%{dnsname}'", zone_desc->origin);
        return ERROR;
    }
    
    const u8 *origin = zone_desc->origin;
    
    log_info("zone sign: %{dnsname}", origin);
    
    if(zone_desc->status_flags & (ZONE_STATUS_SIGNATURES_UPDATE|ZONE_STATUS_SIGNATURES_UPDATING))
    {
        // already loading
        
        zone_desc_log(MODULE_MSG_HANDLE, MSG_DEBUG1, zone_desc, "database_service_zone_resignature");
        
        log_err("zone sign: '%{dnsname}' already having its signatures updated", origin);
        
        zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
                        
        return ERROR;
    }

    zone_desc->status_flags &= ~ZONE_STATUS_STARTING_UP;
    zone_desc->status_flags |= ZONE_STATUS_SIGNATURES_UPDATE;
    
    database_service_zone_resignature_parms_s *database_zone_resignature_parms = database_service_zone_resignature_parms_alloc(zone_desc);
    zone_acquire(zone_desc);
    database_service_zone_resignature_queue_thread(database_service_zone_resignature_thread, database_zone_resignature_parms, NULL, "database_zone_resignature_thread");
    
    log_debug1("database_service_zone_resignature: unlocking zone '%{dnsname}' for signing", origin);
    
    zone_unlock(zone_desc, ZONE_LOCK_SIGNATURE);
    
    return SUCCESS;
}

/**
 * @}
 */


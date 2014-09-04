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
/** @defgroup
 *  @ingroup dnsdb
 *  @brief
 *
 *
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/timems.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_icmtl.h"

#include "dnsdb/dnssec.h"
#include "dnsdb/dnssec_task.h"
#include "dnsdb/rrsig_updater.h"
#include "dnsdb/nsec3_rrsig_updater.h"
#include "dnsdb/zdb_record.h"

#define UZSARGS_TAG 0x53475241535a55

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

typedef struct zdb_update_zone_signatures_thread_args zdb_update_zone_signatures_thread_args;

struct zdb_update_zone_signatures_thread_args
{
    zdb_zone* zone;
};

static const char *dnssec_xfr_path = NULL;

void
dnssec_set_xfr_path(const char* xfr_path)
{
    dnssec_xfr_path = xfr_path;
}

ya_result
zdb_update_zone_signatures(zdb_zone* zone, u32 signature_count_loose_limit)
{
    log_debug("zdb_update_zone_signatures(%p) %{dnsname} [lock=%x]", zone, zone->origin, zone->mutex_owner);

    if(dnssec_xfr_path == NULL)
    {
        log_err("zdb_update_zone_signatures: dnssec_xfr_path not set");
        return ERROR;
    }
    
    if(!zdb_zone_is_dnssec(zone))
    {
        log_debug("zdb_update_zone_signatures(%p) %{dnsname} [lock=%x]: not dnssec", zone, zone->origin, zone->mutex_owner);
        return ZDB_ERROR_ZONE_IS_NOT_DNSSEC; /* @TODO set a new code for "zone is neither NSEC nor NSEC3" */
    }
    
    /**
     * Locks the zone, prevents from being locked twice by this mechanism.
     * 
     */

    if(!zdb_zone_try_double_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER))
    {
        log_debug("zdb_update_zone_signatures(%p) %{dnsname} [lock=%x]: already locked", zone, zone->origin, zone->mutex_owner);
        
        return ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED;
    }
        
    u64 start_time = timeus();

    rrsig_updater_parms parms;
    ZEROMEMORY(&parms, sizeof(rrsig_updater_parms));
    parms.quota = signature_count_loose_limit;
    parms.signatures_are_verified = TRUE; // no need to verify again
    rrsig_updater_init(&parms, zone);
    
    // ensure that at least one ZDK DNSKEY private key is present, else no point
    // going further
    
    /// @todo 20140526 edf -- these checks must be replaced to their "smart signing" homologue mechanism
    
    bool has_zsk = FALSE;
    
    zdb_packed_ttlrdata *dnskey_rrset = zdb_record_find(&zone->apex->resource_record_set, TYPE_DNSKEY);
    
    ya_result return_code = ZDB_ERROR_ZONE_NO_ZSK_PRIVATE_KEY_FILE;
    zdb_icmtl icmtl;
    
    char origin_ascii[MAX_DOMAIN_LENGTH];
    
    dnsname_to_cstr(origin_ascii, zone->origin);
    
    while(dnskey_rrset != NULL)
    {
        const u8 *rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(dnskey_rrset);
        const u16 rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(dnskey_rrset);
        
        u16 tag = dnskey_getkeytag(rdata, rdata_size);
        u16 key_flags = GET_U16_AT(rdata[0]);
        u8 algorithm = rdata[3];
        
        switch(algorithm)
        {
            case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
            case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            case DNSKEY_ALGORITHM_DSASHA1:
            case DNSKEY_ALGORITHM_RSASHA1:
            {
                if(key_flags == DNSKEY_FLAGS_ZSK)
                {
                    dnssec_key *key;
                    if(ISOK(dnssec_key_load_private(algorithm, tag, key_flags, origin_ascii, &key)))
                    {
                        // good to go
                        
                        has_zsk = TRUE;
                    }
                }
                break;
            }
            default:
            {
                return_code = DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
                break;
            }
        }
        
        dnskey_rrset = dnskey_rrset->next;
    }
    
    if(has_zsk && ISOK(return_code = zdb_icmtl_begin(zone, &icmtl, dnssec_xfr_path)))
    {
        // zone should be locked for readers
        
        if(ISOK(return_code = rrsig_updater_process_zone(&parms)))
        {
            u32 sig_count = return_code;
            
            if(sig_count > 0)
            {
                
                zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
                
                log_debug("zdb_update_zone_signatures(%p) %{dnsname} [lock=%x] done", zone, zone->origin, zone->mutex_owner);

                rrsig_updater_commit(&parms);
                
                zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER, ZDB_ZONE_MUTEX_SIMPLEREADER);
            }
            else
            {
                if(zdb_zone_is_nsec3(zone))
                {
                    // no normal signatures anymore, do the nsec3 signatures

                    nsec3_rrsig_updater_parms parms;
                    ZEROMEMORY(&parms, sizeof(nsec3_rrsig_updater_parms));
                    parms.quota = signature_count_loose_limit;
                    parms.signatures_are_verified = TRUE; // no need to verify again
                    
                    nsec3_rrsig_updater_init(&parms, zone);

                    if(ISOK(sig_count = nsec3_rrsig_updater_process_zone(&parms)))
                    {
                        zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER);

                        nsec3_rrsig_updater_commit(&parms);

                        zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER, ZDB_ZONE_MUTEX_SIMPLEREADER);
                    }

                    nsec3_rrsig_updater_finalize(&parms);
                }
            }
            
            zdb_icmtl_end(&icmtl, dnssec_xfr_path);
            
            zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
            
            /* release */

            u64 time_frame = 1000000;   // 1 secs worth of job
            
            u64 stop_time = timeus();

            u64 duration = stop_time - start_time;
            
            // 1000000 = 1s
            
            u64 new_quota = sig_count;
            
            // if signatures have been made, update the quota
            
            if(sig_count != 0)
            {
                new_quota *= time_frame;
                new_quota /= MAX(duration, 1);      // if it lasted less than 1us, say it did
                                                    // (and still-impossible div0 are avoided)
                new_quota = BOUND(512, new_quota, 8192);
                
                zone->sig_quota = (s32)new_quota;
            }
            
            //zone->sig_quota = 4096;

            double dt = duration;
            dt /= 1000000.0;

            log_debug("zdb_update_zone_signatures(%p) %{dnsname} ~%u signatures in %.6fs, new quota is %u", zone, zone->origin, sig_count, dt, zone->sig_quota);
            
            return_code = sig_count;
        }
        else
        {
            zdb_icmtl_cancel(&icmtl);
            zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
                        
            log_err("zdb_update_zone_signatures(%p) %{dnsname} [lock=%x] failed at signing: %r", zone, zone->origin, zone->mutex_owner, return_code);
        }
    }
    else
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
        
        log_debug("zdb_update_zone_signatures(%p) %{dnsname} [lock=%x] failed at journaling: %r", zone, zone->origin, zone->mutex_owner, return_code);
    }
    
    rrsig_updater_finalize(&parms);
    
    return return_code;
}

/** @} */

/*----------------------------------------------------------------------------*/


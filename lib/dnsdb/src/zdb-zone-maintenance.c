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
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/timems.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_icmtl.h"

#include "dnsdb/zdb-packed-ttlrdata.h"

#include "dnsdb/dnssec.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/dnssec-keystore.h"
#include <dnscore/dnskey-signature.h>

#include "dnsdb/zdb_zone_label_iterator.h"

#include "dnsdb/zdb-zone-maintenance.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define ZDB_ZONE_MAINTENANCE_DETAILED_LOG 1

static void
zdb_zone_maintenance_validate_sign_chain_store(zdb_zone_maintenance_ctx *mctx, zone_diff *diff, zdb_zone *zone, ptr_vector *rrset_to_sign, ptr_vector *remove, ptr_vector *add)
{
    ya_result ret;
    
    log_debug("maintenance: validate-sign-chain-store: %{dnsname}", zone->origin);
    
#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
    for(int i = 0; i <= ptr_vector_last_index(remove); ++i)
    {
        zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(remove, i);
        rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

        log_debug("before-validate: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
    }

    for(int i = 0; i <= ptr_vector_last_index(add); ++i)
    {
        zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add, i);
        rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

        log_debug("before-validate: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
    }

    logger_flush();
#endif
    
    if(ISOK(ret = zone_diff_validate(diff)))
    {
#ifdef DEBUG
        log_debug("maintenance: %{dnsname}: diff validated", diff->origin);
#endif
        // store changes in vectors and get the RR sets to sign
        
#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
        for(int i = 0; i <= ptr_vector_last_index(remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(remove, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-get-changes: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int i = 0; i <= ptr_vector_last_index(add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-get-changes: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        logger_flush();
#endif

        bool dnskey_set_update = zone_diff_get_changes(diff, NULL, rrset_to_sign, remove, add);

        ptr_vector ksks = EMPTY_PTR_VECTOR;
        ptr_vector zsks = EMPTY_PTR_VECTOR;

        // no need to populate the KSKs if we are not working on an DNSKEY anywhere

        dnssec_keystore_acquire_activated_keys_from_fqdn_to_vectors(diff->origin, (dnskey_set_update)?&ksks:NULL, &zsks);
        
        // the above function returns keys that are supposed to be active
        // we must also ensure that these keys are/will be in the zone so we can sign using them
        zone_diff_filter_out_keys(diff, &ksks);
        zone_diff_filter_out_keys(diff, &zsks);

        // sign the records, store the changes in vectors
        
#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
        for(int i = 0; i <= ptr_vector_last_index(remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(remove, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-diff-sign: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int i = 0; i <= ptr_vector_last_index(add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-diff-sign: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }
        
        logger_flush();
#endif

        zone_diff_sign(diff, zone, rrset_to_sign, &ksks, &zsks, remove, add);

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
        for(int i = 0; i <= ptr_vector_last_index(remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(remove, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-nsec-chain-store-diff: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int i = 0; i <= ptr_vector_last_index(add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-nsec-chain-store-diff: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }
#endif
        
        dnssec_chain_store_diff(&mctx->nsec_chain_updater, diff, &mctx->zsks, remove, add);
        
#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
        for(int i = 0; i <= ptr_vector_last_index(remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(remove, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-nsec3-chain-store-diff: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int i = 0; i <= ptr_vector_last_index(add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-nsec3-chain-store-diff: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }
#endif
        
        dnssec_chain_store_diff(&mctx->nsec3_chains_updater, diff, &mctx->zsks, remove, add);

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
        for(int i = 0; i <= ptr_vector_last_index(remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(remove, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("when-all-is-said-and-done: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int i = 0; i <= ptr_vector_last_index(add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(add, i);
            rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("when-all-is-said-and-done: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }
#endif
        
        dnssec_keystore_release_keys_from_vector(&zsks);
        dnssec_keystore_release_keys_from_vector(&ksks);

        ptr_vector_destroy(&zsks);
        ptr_vector_destroy(&ksks);
    }
    else
    {
        log_debug("maintenance: %{dnsname}: could not validate the diff", diff->origin);
    }
}

/**
 * Updates the signatures of a zone incrementally.
 * Each call goes a bit further.
 * 
 * @param zone
 * @param signature_count_loose_limit
 * @param present_signatures_are_verified
 * @return 
 */

static ya_result
zdb_zone_maintenance_from(zdb_zone* zone, u8 *from_fqdn, size_t from_fqdn_size, s64 maxus)
{
    log_debug("maintenance: %{dnsname}: starting from %{dnsname}", zone->origin, from_fqdn);
    
    s64 start_time = timeus();
    
    zdb_zone_maintenance_ctx mctx;
    ZEROMEMORY(&mctx, sizeof(zdb_zone_maintenance_ctx));
    mctx.zone = zone;
    
    u8 maintain_mode = zone_get_maintain_mode(zone);
    
    zone_diff diff;
    zone_diff_init(&diff, zone->origin, zone->min_ttl, TRUE); // of course RRSIG can be changed
    
    dnssec_chain_init(&mctx.nsec_chain_updater, dynupdate_nsec_chain_get_vtbl(), &diff);
    if((maintain_mode & ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT) != ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT)
    {
        dnssec_chain_init(&mctx.nsec3_chains_updater, dynupdate_nsec3_chain_get_vtbl(), &diff);
    }
    else
    {
        dnssec_chain_init(&mctx.nsec3_chains_updater, dynupdate_nsec3_optout_chain_get_vtbl(), &diff);
    }
    
    ptr_vector_init(&mctx.ksks);
    ptr_vector_init(&mctx.zsks);
    dnssec_keystore_acquire_activated_keys_from_fqdn_to_vectors(zone->origin, &mctx.ksks, &mctx.zsks);
    
    ptr_vector remove = EMPTY_PTR_VECTOR;
    ptr_vector add = EMPTY_PTR_VECTOR;

    int loop_iterations = 0;
    
    bool diff_has_changes = FALSE;
    bool the_end = FALSE;
    
    if(!zdb_zone_is_maintained(zone))
    {
        zone_diff_finalise(&diff);
        
        log_debug("maintenance: %{dnsname}: not maintained", zone->origin);
        return ZDB_ERROR_ZONE_NOT_MAINTAINED;
    }
    
    if(!zdb_zone_try_double_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER))
    {
        zone_diff_finalise(&diff);
        
        log_debug("maintenance: %{dnsname}: cannot double-lock", zone->origin);
        
        return ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED;
    }
    
    log_debug("maintenance: %{dnsname}: fetching keys", zone->origin);
    
    zdb_zone_get_active_keys(zone, &mctx.keys, &mctx.ksk_count, &mctx.zsk_count);
    
    ya_result ret;
    
    if(mctx.zsk_count > 0)
    {
        log_debug("maintenance: %{dnsname}: has %i KSKs and %i ZSKs", zone->origin, mctx.ksk_count, mctx.zsk_count);
        
#ifdef DEBUG
        {
            dnssec_key_sll* key = mctx.keys;
            while(key != NULL)
            {
                log_debug("maintenance: DNSKEY: %{dnsname}-%i-%i/%i", key->key->owner_name, key->key->algorithm, key->key->tag, key->key->flags);
                key = key->next;
            }
        }
#endif
        
        ptr_vector rrset_to_sign = EMPTY_PTR_VECTOR;
        
        zone_diff_fqdn *apex = zone_diff_add_static_fqdn(&diff, diff.origin, zone->apex);
        

        zdb_zone_label_iterator iter;
        
        // initialises the "start-from" iterator

        if(*from_fqdn == 0)
        {
            zdb_zone_label_iterator_init(&iter, zone);
            // also reset the earliest resignature
            mctx.zone->progressive_signature_update.earliest_signature_expiration = MAX_U32;
            mctx.zone->progressive_signature_update.labels_at_once = 1;
        }
        else
        {
            zdb_zone_label_iterator_init_from(&iter, zone, from_fqdn);
        }
        
        // get the nsec status
                
        nsec_zone_get_status(zone, &mctx.nsec_chain_status);
        dnssec_chain_add_chain(&mctx.nsec_chain_updater, (dnssec_chain_head_t)zone->nsec.nsec, (mctx.nsec_chain_status & NSEC_ZONE_REMOVING) != 0);
        
        // get all nsec3 statuses
        
        mctx.nsec3_chain_count = MIN(nsec3_zone_get_chain_count(zone), ZDB_ZONE_MAINTENANCE_NSEC3CHAIN_MAX);
        nsec3_zone_get_chains(zone, mctx.nsec3_chain, mctx.nsec3_chain_count);
        for(u8 nsec3_chain_index = 0; nsec3_chain_index < mctx.nsec3_chain_count; ++nsec3_chain_index)
        {
            const u8 *nsec3param_rdata = mctx.nsec3_chain[nsec3_chain_index]->rdata;
            nsec3_zone_get_status_from_rdata(zone, nsec3param_rdata, NSEC3_ZONE_RDATA_SIZE(mctx.nsec3_chain[nsec3_chain_index]), &mctx.nsec3_chain_status[nsec3_chain_index]);
            dnssec_chain_add_chain(&mctx.nsec3_chains_updater, (dnssec_chain_head_t)mctx.nsec3_chain[nsec3_chain_index], (mctx.nsec3_chain_status[nsec3_chain_index] & NSEC3_ZONE_REMOVING) != 0);
        }

        mctx.now = time(NULL);
        /*
        zdb_packed_ttlrdata_record_view_data rrv_data;
        resource_record_view rrv = {&rrv_data, zdb_packed_ttlrdata_record_view_get_vtbl()};
        */
        ptr_vector rrset_vector = EMPTY_PTR_VECTOR;
        ptr_vector candidates = EMPTY_PTR_VECTOR;
        ptr_vector chain_candidates = EMPTY_PTR_VECTOR;
                
        int max_labels = mctx.zone->progressive_signature_update.labels_at_once;
        
        for(;;)
        {
            if(zdb_zone_label_iterator_hasnext(&iter))
            {    
                memcpy(&mctx.fqdn_stack.labels[0], &iter.dnslabels[0], (iter.top + 1) * sizeof(u8*));
                mctx.fqdn_stack.size = iter.top;

                dnsname_stack_to_dnsname(&mctx.fqdn_stack, mctx.fqdn);
                
                // if too many iterations : break
                
                if(--max_labels < 0)
                {
#ifdef DEBUG
                    log_debug("maintenance: %{dnsname}: quota spent, next one will be %{dnsnamestack}", zone->origin, &mctx.fqdn_stack);
#endif
                    break;
                }
                
                s64 now = timeus();
                
                if((loop_iterations > 0) && (now - start_time >= maxus))
                {
                    // too much time taken already
#ifdef DEBUG
                    double dt = now - start_time;
                    dt /= 1000000.;
                    log_debug("maintenance: %{dnsname}: time elapsed (%fs), next one will be %{dnsnamestack}", zone->origin, dt, &mctx.fqdn_stack);
#endif
                    break;
                }
                
                ++loop_iterations;
                
#ifdef DEBUG
                log_debug("maintenance: %{dnsname}: at %{dnsnamestack}", zone->origin, &mctx.fqdn_stack);
#endif
                zdb_rr_label *rr_label = zdb_zone_label_iterator_next(&iter);
                mctx.label = rr_label;

                zone_diff_fqdn *diff_fqdn = zone_diff_add_static_fqdn(&diff, mctx.fqdn, rr_label);
                
                int action_count;

                action_count = zdb_zone_maintenance_rrsig(&mctx, diff_fqdn, &rrset_to_sign);
                action_count += zdb_zone_maintenance_nsec(&mctx, diff_fqdn, &rrset_to_sign);
                action_count += zdb_zone_maintenance_nsec3(&mctx, diff_fqdn);
                
                if(action_count > 0)
                {
                    ++max_labels;
                }
            }
            else
            {
                the_end = TRUE;
                break;
            }
        } // while has labels ..
        
        if(the_end && (loop_iterations == 0))
        {
            // maintenance finished its pass(es)
#ifdef DEBUG
            log_debug("maintenance: %{dnsname}: no more labels to process", zone->origin, &mctx.fqdn_stack);
#endif
            // disable the NSEC/NSEC3 state(s)
            
            if(zone_diff_will_have_rrset_type(apex, TYPE_NSEC3CHAINSTATE))
            {
                zone_diff_fqdn_rr_set *nsec3chainstate_rrset = zone_diff_fqdn_rr_get(apex, TYPE_NSEC3CHAINSTATE);
                yassert(nsec3chainstate_rrset != NULL);
                zone_diff_fqdn_rr_set_set_state(nsec3chainstate_rrset, ZONE_DIFF_REMOVE);
            }
        }
        
        diff_has_changes = zone_diff_has_changes(&diff, &rrset_to_sign);
        
        if(diff_has_changes)
        {
            zdb_packed_ttlrdata* soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);
            if(soa != NULL)
            {
                zone_diff_record_remove(&diff, zone->apex, zone->origin, TYPE_SOA, soa->ttl, ZDB_PACKEDRECORD_PTR_RDATASIZE(soa), ZDB_PACKEDRECORD_PTR_RDATAPTR(soa));
            }

            if(ISOK(zone_diff_set_soa(&diff, zone->apex)))
            {
                yassert(apex != NULL);
                zone_diff_fqdn_rr_set *soa_rrset = zone_diff_fqdn_rr_get(apex, TYPE_SOA);
                yassert(soa_rrset != NULL);
                ptr_vector_append(&rrset_to_sign, soa_rrset);
            }
            
#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
            for(int i = 0; i <= ptr_vector_last_index(&remove); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&remove, i);
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                log_debug("before-validate-sign: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
            }

            for(int i = 0; i <= ptr_vector_last_index(&add); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&add, i);
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                log_debug("before-validate-sign: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
            }
#endif
            
            zdb_zone_maintenance_validate_sign_chain_store(&mctx, &diff, zone, &rrset_to_sign, &remove, &add);
            
#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
            for(int i = 0; i <= ptr_vector_last_index(&remove); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&remove, i);
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                log_debug("after-validate-sign: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
            }

            for(int i = 0; i <= ptr_vector_last_index(&add); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&add, i);
                rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                log_debug("after-validate-sign: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
            }
#endif
        }
        else
        {
            log_debug("maintenance: %{dnsname}: no changes", zone->origin);
         
            if(the_end)
            {
                log_debug("maintenance: %{dnsname}: closing edited chains", zone->origin);
                
                // add missing NSEC3PARAM
                // remove TYPE65282
                // update NSEC3
                // update signatures
                
                bool updated = FALSE;
                                
                if(zone_diff_will_have_rrset_type(apex, TYPE_NSEC3CHAINSTATE))
                {
                    //zone_diff_fqdn_rr_set *nsec3chainstate_rrset = zone_diff_fqdn_rr_get(apex, TYPE_NSEC3CHAINSTATE);
                    //yassert(nsec3chainstate_rrset != NULL);
                    //zone_diff_fqdn_rr_set_set_state(nsec3chainstate_rrset, ZONE_DIFF_REMOVE);
                    
                    // NSEC3PARAM
                    
                    zdb_packed_ttlrdata* nsec3chainstate = zdb_record_find(&zone->apex->resource_record_set, TYPE_NSEC3CHAINSTATE);
                    if(nsec3chainstate != NULL)
                    {
                        do
                        {
                            // find the nsec3param matching nsec3chainstate in nsec3param_rrset
                            // if no match has been found, add a new nsec3param
                            
                            zone_diff_label_rr *rr = zone_diff_record_add(&diff, zone->apex, zone->origin, TYPE_NSEC3PARAM, 0,
                                    ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec3chainstate) - 1,
                                    ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3chainstate)
                                    );
                            
                            // clears the opt-out flag that exists in the NSEC3CHAINSTATE record
                            
                            u8* flagsp = &((u8*)rr->rdata)[1];
                            *flagsp = 0;
                            
                            nsec3chainstate = nsec3chainstate->next;
                        }
                        while(nsec3chainstate != NULL);
                        
                        yassert(apex != NULL);
                        zone_diff_fqdn_rr_set *nsec3chainstate_rrset = zone_diff_fqdn_rr_get(apex, TYPE_NSEC3CHAINSTATE);
                        yassert(nsec3chainstate_rrset != NULL);
                        zone_diff_fqdn_rr_set_set_state(nsec3chainstate_rrset, ZONE_DIFF_REMOVE);
                        
                        zone_diff_fqdn_rr_set *nsec3param_rrset = zone_diff_fqdn_rr_get(apex, TYPE_NSEC3PARAM);
                        yassert(nsec3param_rrset != NULL);
                        ptr_vector_append(&rrset_to_sign, nsec3param_rrset);
                        
                        updated = TRUE;
                    }
                }
                
                if(zone_diff_will_have_rrset_type(apex, TYPE_NSECCHAINSTATE))
                {
                    yassert(apex != NULL);
                    zone_diff_fqdn_rr_set *nsecchainstate_rrset = zone_diff_fqdn_rr_get(apex, TYPE_NSECCHAINSTATE);
                    yassert(nsecchainstate_rrset != NULL);
                    zone_diff_fqdn_rr_set_set_state(nsecchainstate_rrset, ZONE_DIFF_REMOVE);
                    
                    updated = TRUE;
                }
                    
                if(updated)
                {
                    diff_has_changes = TRUE;
                    
                    zdb_zone_maintenance_nsec(&mctx, apex, NULL);
                    zdb_zone_maintenance_nsec3(&mctx, apex);
                    
                    // SOA
                        
                    zdb_packed_ttlrdata* soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);
                    if(soa != NULL)
                    {
                        zone_diff_record_remove(&diff, zone->apex, zone->origin, TYPE_SOA, soa->ttl, ZDB_PACKEDRECORD_PTR_RDATASIZE(soa), ZDB_PACKEDRECORD_PTR_RDATAPTR(soa));
                    }

                    if(ISOK(zone_diff_set_soa(&diff, zone->apex)))
                    {
                        yassert(apex != NULL);
                        zone_diff_fqdn_rr_set *soa_rrset = zone_diff_fqdn_rr_get(apex, TYPE_SOA);
                        yassert(soa_rrset != NULL);
                        ptr_vector_append(&rrset_to_sign, soa_rrset);
                    }
                    
#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
                    for(int i = 0; i <= ptr_vector_last_index(&remove); ++i)
                    {
                        zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&remove, i);
                        rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                        log_debug("before-validate-sign: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
                    }

                    for(int i = 0; i <= ptr_vector_last_index(&add); ++i)
                    {
                        zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&add, i);
                        rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                        log_debug("before-validate-sign: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
                    }
#endif
                    
                    zdb_zone_maintenance_validate_sign_chain_store(&mctx, &diff, zone, &rrset_to_sign, &remove, &add);
                    
#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
                    for(int i = 0; i <= ptr_vector_last_index(&remove); ++i)
                    {
                        zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&remove, i);
                        rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                        log_debug("after-validate-sign: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
                    }

                    for(int i = 0; i <= ptr_vector_last_index(&add); ++i)
                    {
                        zone_diff_label_rr *rr = (zone_diff_label_rr*)ptr_vector_get(&add, i);
                        rdata_desc rd = {rr->rtype, rr->rdata_size, rr->rdata};

                        log_debug("after-validate-sign: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
                    }
#endif
                }
            }
        }
        
        ptr_vector_destroy(&rrset_to_sign);
        
        ptr_vector_destroy(&chain_candidates);
        ptr_vector_destroy(&candidates);
        ptr_vector_destroy(&rrset_vector);
        
        if(diff_has_changes)
        {
            log_debug("maintenance: %{dnsname}: writing and playing transaction", zone->origin);

            ret = dynupdate_diff_write_to_journal_and_replay(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER, &remove, &add);
        }
        else
        {
            ret = 0;
        }
    }
    else
    {
        log_info("maintenance: %{dnsname}: has no active zone signing keys: disabling maintenance", zone->origin);
        //from_fqdn[0] = 0;
        //zdb_zone_set_maintained(zone, FALSE);
        
        ret = ZDB_ERROR_ZONE_NO_ZSK_PRIVATE_KEY_FILE;
    }
        
    if(ISOK(ret))
    {
        if(ret < 32768)
        {
            if(ret > 0)
            {
                double r = 32768.0;
                r /= ret;
                r *= mctx.zone->progressive_signature_update.labels_at_once;
                if(r > 65535.0)
                {
                    r = 65535;
                }
                mctx.zone->progressive_signature_update.labels_at_once = (u16)r;
            }
            else
            {
                mctx.zone->progressive_signature_update.labels_at_once = 65535;
            }
            
            log_debug("maintenance: %{dnsname}: adjusting up batch size to %i", zone->origin, mctx.zone->progressive_signature_update.labels_at_once);
        }
        else
        {
            if(mctx.zone->progressive_signature_update.labels_at_once > 1)
            {
                mctx.zone->progressive_signature_update.labels_at_once /= 2;
                log_debug("maintenance: %{dnsname}: adjusting down batch size to %i", zone->origin, mctx.zone->progressive_signature_update.labels_at_once);
            }
        }
    }
    
    log_debug("maintenance: %{dnsname}: releasing resources", zone->origin);
    
    zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
    
    dnssec_keystore_release_keys_from_vector(&mctx.ksks);
    dnssec_keystore_release_keys_from_vector(&mctx.zsks);
        
    ptr_vector_destroy(&mctx.ksks);
    ptr_vector_destroy(&mctx.zsks);
    
    dnssec_chain_finalise(&mctx.nsec_chain_updater);
    dnssec_chain_finalise(&mctx.nsec3_chains_updater);
    
    zdb_zone_release_active_keys(mctx.keys);
    
    zone_diff_finalise(&diff);
    
    if(the_end)
    {
        if(ISOK(ret))
        {
            ret = 0; // so the caller do not try to call again right away.
            mctx.fqdn[0] = '\0';
        }
    }
    else
    {
        if(ret == 0)
        {
            ret = 1;    // else the remaining will be postponed for a while
        }
    }
    
    size_t fqdn_len = dnsname_len(mctx.fqdn);
    
    if(fqdn_len <= from_fqdn_size)
    {
        memcpy(from_fqdn, mctx.fqdn, fqdn_len);
    }
    
    s64 stop_time = timeus();
    
    double dt = stop_time - start_time;
    if(dt < 0) dt = 0;
    dt /= 1000000.0;
        
    log_debug("rrsig: %{dnsname}: done (%.3fs)", zone->origin, dt);
    
    return ret;
}

/**
 * Will double-lock for reader & rrsig-updater
 * 
 * @param zone
 * @param signature_count_loose_limit
 * @param present_signatures_are_verified
 * @return 0 : all done, >0 : some done (some could be 0), <0 error
 */

ya_result
zdb_zone_maintenance(zdb_zone* zone)
{
    ya_result ret;
    u8 in_out_fqdn[MAX_DOMAIN_LENGTH];
    
    if(zone->progressive_signature_update.current_fqdn != NULL)
    {
        log_debug("maintenance: %{dnsname}: resuming from %{dnsname}", zone->origin, zone->progressive_signature_update.current_fqdn);
        
        dnsname_copy(in_out_fqdn, zone->progressive_signature_update.current_fqdn);
        dnsname_zfree(zone->progressive_signature_update.current_fqdn);
        zone->progressive_signature_update.current_fqdn = NULL;
    }
    else
    {
        log_debug("maintenance: %{dnsname}: starting", zone->origin);
        in_out_fqdn[0] = 0;
    }
    
    ret = zdb_zone_maintenance_from(zone, in_out_fqdn, sizeof(in_out_fqdn), 1000);  // 0.0001 max spent on iterating
    
    if(in_out_fqdn[0] != 0)
    {
        zone->progressive_signature_update.current_fqdn = dnsname_zdup(in_out_fqdn);
        log_debug("maintenance: %{dnsname}: pausing at %{dnsname}", zone->origin, zone->progressive_signature_update.current_fqdn);
    }
    else
    {
        log_debug("maintenance: %{dnsname}: done (%r)", zone->origin, ret);
    }
    
    return ret;
}

/** @} */

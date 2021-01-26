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
#include <dnscore/u32_set.h>
#include <dnscore/logger.h>
#include "dnsdb/zdb-zone-maintenance.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/zdb_zone.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define DEBUG_RRSIG_PASS_STATES 0

#if DEBUG_RRSIG_PASS_STATES
#pragma message("WARNING: DEBUG_RRSIG_PASS_STATES IS NOT SET TO 0.  SET IT BACK TO 0 IT IF YOU DON'T NEED IT!")
#endif

/**
 * Adds a node (type,0) in a u32_set for each rrset in the label pointed out by mctx.
 * 
 * @param mctx
 * @param type_coverage
 */

static void
zdb_zone_maintenance_rrsig_coverage_init(zdb_zone_maintenance_ctx* mctx, u32_set *type_coverage)
{
    btree_iterator iter;
    btree_iterator_init(mctx->label->resource_record_set, &iter);

    while(btree_iterator_hasnext(&iter))
    {
        btree_node *rr_node = btree_iterator_next_node(&iter);
        u16 type = (u16)rr_node->hash;
        if(/*(type != TYPE_NSEC) && */(type != TYPE_RRSIG))
        {
            u32_set_insert(type_coverage, type);
        }
    }
}

static int
zdb_zone_maintenance_rrsig_coverage_finalize(zdb_zone_maintenance_ctx* mctx, zone_diff_fqdn *diff_fqdn, ptr_vector *rrset_to_sign, u32_set *type_coverage)
{
    int signatures_to_generate = 0;

    intptr ksk_mask = mctx->ksk_mask;
    intptr zsk_mask = mctx->zsk_mask;

    bool at_or_underdelegation = ZDB_LABEL_ATORUNDERDELEGATION(mctx->label);
    //u8 maintain_mode = zone_get_maintain_mode(mctx->zone);
    
    if(!at_or_underdelegation)
    {
        u32_set_iterator iter;
        u32_set_iterator_init(type_coverage, &iter);
        while(u32_set_iterator_hasnext(&iter))
        {
            u32_node *node = u32_set_iterator_next_node(&iter);
            intptr mask = (intptr)node->value;                              // what is really covering
            intptr key_mask = (node->key != TYPE_DNSKEY)?zsk_mask:ksk_mask; // what it should be covered by

            if((key_mask & mask) != key_mask)
            {
                // there are holes : set has to be updated

                // give the rrset from the diff

                zone_diff_fqdn_rr_set *rrset = zone_diff_fqdn_rr_set_get(diff_fqdn, node->key);
                rrset->key_mask = (key_mask & mask) ^ key_mask;             // get the needed coverage into rrset->key_mask
#if DEBUG
                u16 rtype = (u16)node->key;
                log_debug1("maintenance: %{dnsname}: %{dnsname} %{dnstype} will have its RRSIGs updated",
                        mctx->zone->origin,
                        diff_fqdn->fqdn,
                        &rtype);
#endif
                ptr_vector_append(rrset_to_sign, rrset);
                ++signatures_to_generate;
            }
        }
    }
    else
    {
        if(zone_diff_will_have_rrset_type(diff_fqdn, TYPE_DS))
        {
            zone_diff_fqdn_rr_set *ds_rrset = zone_diff_fqdn_rr_set_get(diff_fqdn, TYPE_DS);

            if(ds_rrset != NULL)
            {
                u32_node *node = u32_set_find(type_coverage, TYPE_DS);
                intptr mask = (node != NULL)?(intptr)node->value:0;
                intptr key_mask = zsk_mask;

                if((key_mask & mask) != key_mask)
                {
                    ds_rrset->key_mask = (key_mask & mask) ^ key_mask;
#if DEBUG
                    log_debug1("maintenance: %{dnsname}: %{dnsname} DS will have its RRSIGs updated",
                            mctx->zone->origin,
                            diff_fqdn->fqdn);
#endif
                    ptr_vector_append(rrset_to_sign, ds_rrset);
                    ++signatures_to_generate;
                }
                else
                {
#if DEBUG
                    log_debug1("maintenance: %{dnsname}: %{dnsname} properly signed already",
                            mctx->zone->origin,
                            diff_fqdn->fqdn);
#endif
                }
            }
        }
        /*
        if(maintain_mode == ZDB_ZONE_MAINTAIN_NSEC)
        {
        }
        */
    }
    
    zone_diff_fqdn_rr_clear(diff_fqdn, TYPE_RRSIG); // only deletes the set if it is empty
    
    u32_set_destroy(type_coverage);
    
    return signatures_to_generate;
}

/**
 * Updates the signatures of a zone incrementally.
 * Each call goes a bit further.
 * 
 * @param zone
 * @param signature_count_loose_limit
 * @param present_signatures_are_verified
 * @return the number of actions made by the call
 */

int
zdb_zone_maintenance_rrsig(zdb_zone_maintenance_ctx* mctx, zone_diff_fqdn *diff_fqdn, ptr_vector *rrset_to_sign)
{
    ya_result signatures_to_add_or_remove = 0;
    
#if DEBUG_RRSIG_PASS_STATES
    log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}", mctx->zone->origin, diff_fqdn->fqdn);
#endif
    
    // for all RRSIG: remove expired ones
    
    if(rrsig_should_label_be_signed(mctx->zone, mctx->fqdn, mctx->label))
    {
#if DEBUG
        log_debug2("zdb_zone_maintenance_rrsig: %{dnsname}", diff_fqdn->fqdn);
        zone_diff_fqdn_log(diff_fqdn, mctx->zone->origin, MODULE_MSG_HANDLE, MSG_DEBUG1);
#endif
        // generate a set of all the (relevant) types in the label, and list a node by key
        // they are meant to be signed with
        
        // first, remove the expired or unknown signatures
        
        bool create_signatures = TRUE;
        bool at_delegation = ZDB_LABEL_ATDELEGATION(mctx->label);
        bool above_delegation = !ZDB_LABEL_ATORUNDERDELEGATION(mctx->label);
        bool will_have_ds = zone_diff_will_have_rrset_type(diff_fqdn, TYPE_DS);
        bool will_have_nsec = zone_diff_will_have_rrset_type(diff_fqdn, TYPE_NSEC);

        switch(zone_get_maintain_mode(mctx->zone))
        {
            case ZDB_ZONE_MAINTAIN_NSEC:
                create_signatures = above_delegation || (at_delegation && (will_have_nsec || will_have_ds));
                break;
            case ZDB_ZONE_MAINTAIN_NSEC3:
                create_signatures = above_delegation || (at_delegation && will_have_ds);
                break;
            case ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:
                create_signatures = above_delegation || (at_delegation && will_have_ds);
                break;
        }
        
        u32_set type_coverage = U32_SET_EMPTY;
        zdb_zone_maintenance_rrsig_coverage_init(mctx, &type_coverage);
        
        // look if there are expired signatures (time, key, ...)
        // mark them for removal, mark the covered rrset for signature
        
        zone_diff_fqdn_rr_set *rrsig_set = zone_diff_fqdn_rr_set_get(diff_fqdn, TYPE_RRSIG);
        if(rrsig_set != NULL)
        {
#if DEBUG_RRSIG_PASS_STATES
            log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: contains signatures", mctx->zone->origin, diff_fqdn->fqdn);
#endif
            zone_diff_fqdn_rr_set* rrsig_covered_rrset_cached = NULL;
            u16 rrsig_ctype_cached = MAX_U16;
            s32 rrsig_ctype_ttl = -1;
            
            // for all RRSIG records ...
            
            ptr_set_iterator rr_iter;
            ptr_set_iterator_init(&rrsig_set->rr, &rr_iter);
            while(ptr_set_iterator_hasnext(&rr_iter))
            {
                ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rrsig_rr = (zone_diff_label_rr *)node->key;
#if DEBUG_RRSIG_PASS_STATES
                u16 tmp_type = rrsig_get_type_covered_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);
                rdata_desc rrsig_rr_rd = {rrsig_rr->rtype, rrsig_rr->rdata_size, rrsig_rr->rdata};
                format_writer temp_fw_0 = {zone_diff_record_state_format, &rrsig_rr->state};
                log_debug("maintenance: rrsig: %{dnsname}: has %w %{dnsname} %9i %{typerdatadesc}",
                        mctx->zone->origin, &temp_fw_0, rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_rd);
#endif
                if((rrsig_rr->state & ZONE_DIFF_RR_REMOVE) != 0)
                {
#if DEBUG_RRSIG_PASS_STATES
                    log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: RRSIG %02x %{dnstype} %T %T (already being removed)", mctx->zone->origin, diff_fqdn->fqdn,
                              rrsig_rr->state, &tmp_type,
                        rrsig_get_valid_until_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size), rrsig_get_valid_from_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size));
#endif
                    continue; // signature is being removed already: ignore
                }

                s32 valid_until = rrsig_get_valid_until_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);
                s32 valid_from = rrsig_get_valid_from_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);
                u16 type_covered = rrsig_get_type_covered_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);

                if(valid_from > valid_until)
                {
                    log_warn("maintenance: rrsig: %{dnsname}: %{dnsname}: %{dnstype}: bad timings (%T > %T)", mctx->zone->origin,
                        diff_fqdn->fqdn, &type_covered, valid_from, valid_until);

                    rrsig_rr->state |= ZONE_DIFF_RR_REMOVE;

                    ++signatures_to_add_or_remove;
                    continue;
                }

                ptr_vector *keys = (type_covered!= TYPE_DNSKEY)?&mctx->zsks:&mctx->ksks;

                s32 key_index = -2;
                if(rrsig_should_remove_signature_from_rdata(
                    rrsig_rr->rdata, rrsig_rr->rdata_size,
                    keys, mctx->now, mctx->zone->sig_validity_regeneration_seconds, &key_index) || (key_index == -1))
                {
#if DEBUG_RRSIG_PASS_STATES
                    log_debug("maintenance: rrsig: %{dnsname}: will replace %{dnsname} %9i %{typerdatadesc}",
                              mctx->zone->origin, /*valid_until, mctx->zone->sig_validity_regeneration_seconds, mctx->now,*/
                              rrsig_rr->fqdn, rrsig_rr->ttl, &rrsig_rr_rd);
#endif
                    rrsig_rr->state |= ZONE_DIFF_RR_REMOVE;
                    ++signatures_to_add_or_remove;
                    continue;
                }

                // if valid_until is earlier than the current earliest for the zone, update the latter
                
                if(mctx->zone->progressive_signature_update.earliest_signature_expiration > valid_until)
                {
                    mctx->zone->progressive_signature_update.earliest_signature_expiration = valid_until;
                }

                if(type_covered != rrsig_ctype_cached)
                {
                    rrsig_ctype_cached = type_covered;
                    rrsig_covered_rrset_cached = zone_diff_fqdn_rr_set_get(diff_fqdn, type_covered);
                    if(rrsig_covered_rrset_cached != NULL)
                    {
                        rrsig_ctype_ttl = zone_diff_fqdn_rr_set_get_ttl(rrsig_covered_rrset_cached);
                    }
                    else
                    {
                        rrsig_ctype_ttl = -1;
                    }
                }

                if(rrsig_ctype_ttl >= 0)
                {
                    yassert(key_index >= 0);

                    dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, key_index);

                    // only fix the TTL if the key is able to sign

                    if(dnskey_is_private(key))
                    {
                        s32 rrsig_original_ttl = rrsig_get_original_ttl_from_rdata(rrsig_rr->rdata, rrsig_rr->rdata_size);
                        if(rrsig_original_ttl != rrsig_ctype_ttl)
                        {
                            // TTL does not match: redo

                            rrsig_rr->state |= ZONE_DIFF_RR_REMOVE;
                            ++signatures_to_add_or_remove;
                            continue;
                        }
                    }
                }
                else
                {
                    // no such type: remove

                    rrsig_rr->state |= ZONE_DIFF_RR_REMOVE;
                    ++signatures_to_add_or_remove;
                    continue;
                }

                rrsig_covered_rrset_cached->key_mask |= 1ULL << key_index;

                u32_node *type_node = u32_set_find(&type_coverage, type_covered);

                if(type_node != NULL)
                {
                    // update the key coverage mask

                    intptr mask = (intptr)type_node->value;
                    mask |= 1ULL << key_index;
                    type_node->value = (void*)mask;
                }
            } // while RR in RRSET
        }
        else
        {
#if DEBUG
            log_debug2("maintenance: rrsig: %{dnsname}: %{dnsname}: contains no signatures", mctx->zone->origin, diff_fqdn->fqdn);
#endif
        }
        
#if DEBUG_RRSIG_PASS_STATES
        log_debug2("zdb_zone_maintenance_rrsig: %{dnsname} after RRSIG pass", diff_fqdn->fqdn);
        zone_diff_fqdn_log(diff_fqdn, mctx->zone->origin, MODULE_MSG_HANDLE, MSG_DEBUG1);
#endif
        // masks have been set
        
        if(create_signatures)
        {
#if DEBUG
            log_debug2("maintenance: rrsig: %{dnsname}: %{dnsname}: will create signatures", mctx->zone->origin, diff_fqdn->fqdn);
#endif
            int modified_rrset = zdb_zone_maintenance_rrsig_coverage_finalize(mctx, diff_fqdn, rrset_to_sign, &type_coverage);

            signatures_to_add_or_remove += modified_rrset;
        }
        else // opt-out zone and not apex nor delegation with a DS record
        {
#if DEBUG
            log_debug2("maintenance: rrsig: %{dnsname}: %{dnsname}: removing emtpy signatures rrset", mctx->zone->origin, diff_fqdn->fqdn);
#endif
            zone_diff_fqdn_rr_clear(diff_fqdn, TYPE_RRSIG); // removes the empty RRSIG rrset (or do nothing)
            u32_set_destroy(&type_coverage);
        }
#if DEBUG_RRSIG_PASS_STATES
        log_debug2("zdb_zone_maintenance_rrsig: %{dnsname} after create pass", diff_fqdn->fqdn);
        zone_diff_fqdn_log(diff_fqdn, mctx->zone->origin, MODULE_MSG_HANDLE, MSG_DEBUG1);
#endif
    }
#if DEBUG
    else
    {
        log_debug("zdb_zone_maintenance_rrsig: %{dnsname} should not be signed (REMOVE EXISTING)", diff_fqdn->fqdn);
    }
#endif
    
    return signatures_to_add_or_remove;
}

/** @} */

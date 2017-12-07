/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2017, EURid. All rights reserved.
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
#include "dnsdb/zdb-zone-maintenance.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/zdb_zone.h"

#include <dnscore/u32_set.h>

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

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
        if((type != TYPE_NSEC) && (type != TYPE_RRSIG))
        {
            u32_set_avl_insert(type_coverage, type);
        }
    }
}

static int
zdb_zone_maintenance_rrsig_coverage_finalize(zdb_zone_maintenance_ctx* mctx, zone_diff_fqdn *diff_fqdn, ptr_vector *rrset_to_sign, u32_set *type_coverage)
{
    int ret = 0;
    
    intptr zsk_mask = UINTPTR_MAX >> ((__SIZEOF_POINTER__<<3) - mctx->zsk_count);
    intptr ksk_mask = UINTPTR_MAX >> ((__SIZEOF_POINTER__<<3) - mctx->ksk_count);
    
    bool opt_out_coverage;
    
    switch(zone_get_maintain_mode(mctx->zone))
    {
        case ZDB_ZONE_MAINTAIN_NSEC:
        case ZDB_ZONE_MAINTAIN_NSEC3:
        default:
            opt_out_coverage = FALSE;
            break;
        case ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:
            opt_out_coverage = ZDB_LABEL_ATORUNDERDELEGATION(mctx->label);
            break;
    }
    
    if(!opt_out_coverage)
    {
        u32_set_avl_iterator iter;
        u32_set_avl_iterator_init(type_coverage, &iter);
        while(u32_set_avl_iterator_hasnext(&iter))
        {
            u32_node *node = u32_set_avl_iterator_next_node(&iter);
            intptr mask = (intptr)node->value;
            intptr key_mask = (node->key != TYPE_DNSKEY)?zsk_mask:ksk_mask;

            if((key_mask & mask) != key_mask)
            {
                // there are holes : set has to be updated

                // give the rrset from the diff

                zone_diff_fqdn_rr_set *rrset = zone_diff_fqdn_rr_get(diff_fqdn, node->key);

#ifdef DEBUG
                u16 rtype = (u16)node->key;
                log_debug1("maintenance: %{dnsname}: %{dnsname} %{dnstype} will have its RRSIGs updated",
                        mctx->zone->origin,
                        diff_fqdn->fqdn,
                        &rtype);
#endif
            
                ptr_vector_append(rrset_to_sign, rrset);
                ++ret;
            }
        }
    }
    else
    {
        if(zone_diff_will_have_rrset_type(diff_fqdn, TYPE_DS))
        {
            zone_diff_fqdn_rr_set *ds_rrset = zone_diff_fqdn_rr_get(diff_fqdn, TYPE_DS);

            if(ds_rrset != NULL)
            {
                u32_node *node = u32_set_avl_find(type_coverage, TYPE_DS);
                intptr mask = (node != NULL)?(intptr)node->value:0;
                intptr key_mask = zsk_mask;

                if((key_mask & mask) != key_mask)
                {
#ifdef DEBUG
                    log_debug1("maintenance: %{dnsname}: %{dnsname} DS will have its RRSIGs updated (optout)",
                            mctx->zone->origin,
                            diff_fqdn->fqdn);
#endif
                    ptr_vector_append(rrset_to_sign, ds_rrset);
                    ++ret;
                }
                else
                {
#ifdef DEBUG
                    log_debug1("maintenance: %{dnsname}: %{dnsname} properly signed already",
                            mctx->zone->origin,
                            diff_fqdn->fqdn);
#endif
                }
            }
        }
    }
    
    zone_diff_fqdn_rr_clear(diff_fqdn, TYPE_RRSIG);
    
    u32_set_avl_destroy(type_coverage);
    
    return ret;
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
    ya_result ret = 0;
    
#ifdef DEBUG
    log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}", mctx->zone->origin, diff_fqdn->fqdn);
#endif
    
    // for all RRSIG: remove expired ones
    
    if(rrsig_should_label_be_signed(mctx->zone, mctx->fqdn, mctx->label))
    {
        // generate a set of all the (relevant) types in the label, and list a node by key
        // they are meant to be signed with
        
        // first, remove the expired or unknown signatures
        
        bool create_signatures = TRUE;

        switch(zone_get_maintain_mode(mctx->zone))
        {
            case ZDB_ZONE_MAINTAIN_NSEC:
            case ZDB_ZONE_MAINTAIN_NSEC3:
                create_signatures = TRUE;
                break;
            case ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:
                create_signatures = !ZDB_LABEL_ATORUNDERDELEGATION(mctx->label) || (ZDB_LABEL_ATDELEGATION(mctx->label) && zone_diff_will_have_rrset_type(diff_fqdn, TYPE_DS));
                break;
        }
        
        u32_set type_coverage = U32_SET_EMPTY;
        zdb_zone_maintenance_rrsig_coverage_init(mctx, &type_coverage);
        
        // look if there are expired signatures (time, key, ...)
        // mark them for removal, mark the covered rrset for signature
        
        zone_diff_fqdn_rr_set *rrsig_set = zone_diff_fqdn_rr_get(diff_fqdn, TYPE_RRSIG);
        if(rrsig_set != NULL)
        {
#ifdef DEBUG
            log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: contains signatures", mctx->zone->origin, diff_fqdn->fqdn);
#endif
            
            // for all RRSIG records ...
            
            ptr_set_avl_iterator rr_iter;
            ptr_set_avl_iterator_init(&rrsig_set->rr, &rr_iter);
            while(ptr_set_avl_iterator_hasnext(&rr_iter))
            {
                ptr_node *node = ptr_set_avl_iterator_next_node(&rr_iter);
                zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;
                
#ifdef DEBUG
                u16 tmp_type = rrsig_get_type_covered_from_rdata(rr->rdata, rr->rdata_size);
                log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: RRSIG %02x %{dnstype} %T %T", mctx->zone->origin, diff_fqdn->fqdn,
                        rr->state, &tmp_type,
                        rrsig_get_valid_until_from_rdata(rr->rdata, rr->rdata_size), rrsig_get_valid_from_from_rdata(rr->rdata, rr->rdata_size));
#endif

                if((rr->state & ZONE_DIFF_REMOVE) != 0)
                {
#ifdef DEBUG
                    log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: RRSIG %02x %{dnstype} %T %T (already being removed)", mctx->zone->origin, diff_fqdn->fqdn,
                        rr->state, &tmp_type,
                        rrsig_get_valid_until_from_rdata(rr->rdata, rr->rdata_size), rrsig_get_valid_from_from_rdata(rr->rdata, rr->rdata_size));
#endif
                    continue; // signature is being removed already: ignore
                }

                u32 valid_until = rrsig_get_valid_until_from_rdata(rr->rdata, rr->rdata_size);
                u32 valid_from = rrsig_get_valid_from_from_rdata(rr->rdata, rr->rdata_size);
                (void)valid_from;
                if(mctx->now >= valid_until) // signature has expired, mark for removal then ignore
                {
#ifdef DEBUG
                    log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: RRSIG %02x %{dnstype} %T %T (expired, will be removed)", mctx->zone->origin, diff_fqdn->fqdn,
                        rr->state, &tmp_type,
                        rrsig_get_valid_until_from_rdata(rr->rdata, rr->rdata_size), rrsig_get_valid_from_from_rdata(rr->rdata, rr->rdata_size));
#endif
                    rr->state |= ZONE_DIFF_REMOVE;
                    ++ret;
                    continue;
                }
                
                // if valid_until is earlier than the current earliest for the zone, update the latter
                
                if(mctx->zone->progressive_signature_update.earliest_signature_expiration > valid_until)
                {
                    mctx->zone->progressive_signature_update.earliest_signature_expiration = valid_until;
                }

                u16 rrsig_ctype = rrsig_get_type_covered_from_rdata(rr->rdata, rr->rdata_size);

                if(rrsig_ctype == TYPE_NSEC)
                {
                    continue;
                }
                
                u16 rrsig_keytag = rrsig_get_key_tag_from_rdata(rr->rdata, rr->rdata_size);

                // get the collection for the right type of key and find if the key is known
                
                ptr_vector *keys = (rrsig_ctype != TYPE_DNSKEY)?&mctx->zsks:&mctx->ksks;

                int key_index = -1;
                for(int i = 0; i <= ptr_vector_last_index(keys); ++i)
                {
                    const dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, i);
                    u16 keytag = dnssec_key_get_tag_const(key);
                    if(keytag == rrsig_keytag)
                    {
                        key_index = i;
                        break;
                    }
                }

                if(key_index >= 0)
                {
                    u32_node *type_node = u32_set_avl_find(&type_coverage, rrsig_ctype);
                    
                    if(type_node != NULL)
                    {
                        // update the key coverage mask
                        
                        intptr mask = (intptr)type_node->value;
                        mask |= 1 << key_index;
                        type_node->value = (void*)mask;
                    }
                    else
                    {
#ifdef DEBUG
                        log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: RRSIG %02x %{dnstype} %T %T (no such covered record, will be removed)", mctx->zone->origin, diff_fqdn->fqdn,
                            rr->state, &tmp_type,
                            rrsig_get_valid_until_from_rdata(rr->rdata, rr->rdata_size), rrsig_get_valid_from_from_rdata(rr->rdata, rr->rdata_size));
#endif
                        // covered record set does not exist
                        // delete the rrsig
                        rr->state |= ZONE_DIFF_REMOVE;
                        ++ret;
                    }
                }
                else
                {
#ifdef DEBUG
                    log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: RRSIG %02x %{dnstype} %T %T (no such dnskey, will be removed)", mctx->zone->origin, diff_fqdn->fqdn,
                        rr->state, &tmp_type,
                        rrsig_get_valid_until_from_rdata(rr->rdata, rr->rdata_size), rrsig_get_valid_from_from_rdata(rr->rdata, rr->rdata_size));
#endif
                    // unknown key
                    // delete the rrsig
                    rr->state |= ZONE_DIFF_REMOVE;
                    ++ret;
                }
            } // while RR in RRSET
        }
        else
        {
#ifdef DEBUG
            log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: contains no signatures", mctx->zone->origin, diff_fqdn->fqdn);
#endif
        }
        
        // masks have been set
        
        if(create_signatures)
        {
#ifdef DEBUG
            log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: will create signatures", mctx->zone->origin, diff_fqdn->fqdn);
#endif
            ret += zdb_zone_maintenance_rrsig_coverage_finalize(mctx, diff_fqdn, rrset_to_sign, &type_coverage);
        }
        else // opt-out zone and not apex nor delegation with a DS record
        {
#ifdef DEBUG
            log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: removing signatures", mctx->zone->origin, diff_fqdn->fqdn);
#endif
            zone_diff_fqdn_rr_clear(diff_fqdn, TYPE_RRSIG);
        }
    }
    
#ifdef DEBUG
    log_debug("maintenance: rrsig: %{dnsname}: %{dnsname}: done", mctx->zone->origin, diff_fqdn->fqdn);
#endif
    
    return ret;
}

/** @} */

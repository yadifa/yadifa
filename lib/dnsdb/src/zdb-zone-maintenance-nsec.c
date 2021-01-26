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

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

/**
 * Updates the signatures of a zone incrementally.
 * Each call goes a bit further.
 * 
 * @param zone
 * @param signature_count_loose_limit
 * @param present_signatures_are_verified
 * @return the number of actions counted
 */

int
zdb_zone_maintenance_nsec(zdb_zone_maintenance_ctx* mctx, const zone_diff_fqdn *diff_fqdn, ptr_vector *rrset_to_sign)
{
    //   if NSEC created :
    //   _ add the NSEC record & signature if missing
    //   _ update the NSEC RRSIG
    //   _ add the NSEC node to the collection

    //   if NSEC removal :
    //   _ remove the NSEC record & signature
    //   _ remove the NSEC node from the collection
    
    // NSEC signatures should be handled with the general signatures
    
    int ret = 0;

    if((mctx->nsec_chain_status & (NSEC_ZONE_GENERATING|NSEC_ZONE_REMOVING)) == NSEC_ZONE_GENERATING)
    {
        // add
        zdb_packed_ttlrdata *nsec_rrset = zdb_record_find(&mctx->label->resource_record_set, TYPE_NSEC);
        if(nsec_rrset == NULL)
        {
            // need to add the NSEC record and its signature
            // difficult as the next record has to be known
            
            ret = dnssec_chain_add_from_diff_fqdn(&mctx->nsec_chain_updater, diff_fqdn, 0);
        }
    }
    else if((mctx->nsec_chain_status & (NSEC_ZONE_GENERATING|NSEC_ZONE_REMOVING)) == NSEC_ZONE_REMOVING)
    {
        // del
        zdb_packed_ttlrdata *nsec_rrset = zdb_record_find(&mctx->label->resource_record_set, TYPE_NSEC);
        if(nsec_rrset != NULL)
        {
            // need to remove the NSEC record(s) and its signature(s)
            // simple to do
            ret = dnssec_chain_del_from_diff_fqdn(&mctx->nsec_chain_updater, diff_fqdn, 0);
        }
    }
    else
    {
        if(rrset_to_sign != NULL)
        {
#if DEBUG
            log_debug1("maintenance: %{dnsname}: looking at NSEC RRSIG coverage", mctx->zone->origin);
#endif
            if(zone_diff_will_have_rrset_type(diff_fqdn, TYPE_NSEC))
            {
                zone_diff_fqdn_rr_set *nsec_rrset = zone_diff_fqdn_rr_set_get((zone_diff_fqdn *) diff_fqdn, TYPE_NSEC);

                if(nsec_rrset != NULL)
                {
#if DEBUG
                    log_debug1("maintenance: %{dnsname}: NSEC RRSET exists", mctx->zone->origin);
#endif
#if 0
                    zone_diff_fqdn_rr_set *rrsig_rrset = zone_diff_fqdn_rr_set_get((zone_diff_fqdn *) diff_fqdn, TYPE_RRSIG);
#endif
                    bool sign_nsec_rrset = TRUE;
#if 0
                    if(rrsig_rrset != NULL)
                    {
                        bool has_one_valid_signature = FALSE;
                        sign_nsec_rrset = FALSE;
                        
                        ptr_set_iterator rr_iter;
                        ptr_set_iterator_init(&rrsig_rrset->rr, &rr_iter);
                        while(ptr_set_iterator_hasnext(&rr_iter))
                        {
                            ptr_node *node = ptr_set_iterator_next_node(&rr_iter);
                            zone_diff_label_rr *rr = (zone_diff_label_rr *)node->key;                            
                            
                            if((rr->state & ZONE_DIFF_RR_REMOVE) != 0)
                            {
                                continue; // signature is being removed already: ignore
                            }
                            
                            u16 covered_type = rrsig_get_type_covered_from_rdata(rr->rdata, rr->rdata_size);

                            if(covered_type == TYPE_NSEC)
                            {
                                s32 key_index = -2;
                                if(rrsig_should_remove_signature_from_rdata(
                                    rr->rdata, rr->rdata_size,
                                    &mctx->zsks, mctx->now, mctx->zone->sig_validity_regeneration_seconds, &key_index) && (key_index != -1))
                                {
#if DEBUG
                                    log_debug1("maintenance: %{dnsname}: NSEC RRSET signature should be removed", mctx->zone->origin);
#endif
                                    sign_nsec_rrset = TRUE;
                                    break;
                                }
                                else
                                {
#if DEBUG
                                    log_debug1("maintenance: %{dnsname}: NSEC RRSET is covered by at least one signature", mctx->zone->origin);
#endif
                                    has_one_valid_signature = TRUE;
                                }
                            }
                        }

                        sign_nsec_rrset |= has_one_valid_signature;
                    }
                    else
                    {
#if DEBUG
                        log_debug1("maintenance: %{dnsname}: NSEC RRSET and there are no signatures at all on the label", mctx->zone->origin);
#endif
                        sign_nsec_rrset = TRUE;
                    }
#endif
                    if(sign_nsec_rrset) // always true ...
                    {
                        for(int i = 0; i <= ptr_vector_last_index(rrset_to_sign); ++i)
                        {
                            if(ptr_vector_get(rrset_to_sign, i) == nsec_rrset)
                            {
                                sign_nsec_rrset = FALSE;
                                break;
                            }
                        }
                        
                        if(sign_nsec_rrset)
                        {
#if DEBUG
                            u16 rtype = TYPE_NSEC;
                            log_debug1("maintenance: %{dnsname}: %{dnsname} %{dnstype} will have its RRSIGs updated",
                                    mctx->zone->origin,
                                    diff_fqdn->fqdn,
                                    &rtype);
#endif
                            ptr_vector_append(rrset_to_sign, nsec_rrset);
                            ++ret;
                        }
                        else
                        {
                            log_debug1("maintenance: %{dnsname}: NSEC RRSET is already marked for signature", mctx->zone->origin);
                        }
                    }
                    else
                    {
#if DEBUG
                        log_debug1("maintenance: %{dnsname}: NSEC RRSET does not need to be signed again", mctx->zone->origin);
#endif
                    }
                }
            }
        }
    }
    return ret;
}

/** @} */

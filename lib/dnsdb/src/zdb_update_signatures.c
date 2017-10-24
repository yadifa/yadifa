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
#include <dnscore/dnskey-signature.h>

#include "dnsdb/zdb_zone_label_iterator.h"

#ifndef HAS_DYNUPDATE_DIFF_ENABLED
#error "HAS_DYNUPDATE_DIFF_ENABLED not defined"
#endif

#define UZSARGS_TAG 0x53475241535a55

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

typedef struct zdb_zone_update_signatures_thread_args zdb_zone_update_signatures_thread_args;

struct zdb_zone_update_signatures_thread_args
{
    zdb_zone* zone;
};

static const char *dnssec_xfr_path = NULL;

void
dnssec_set_xfr_path(const char* xfr_path)
{
    dnssec_xfr_path = xfr_path;
}

#if OBSOLETE

/**
 * Look at this for a base of offline zone signing
 * 
 * Updates the signatures of a zone incrementally.
 * Each call goes a bit further.
 * 
 * @param zone
 * @param signature_count_loose_limit
 * @param present_signatures_are_verified
 * @return 
 */

static ya_result
zdb_zone_update_signatures_from(zdb_zone* zone, u8 *from_fqdn, size_t from_fqdn_size, s32 signature_count_loose_limit)
{
    zdb_packed_ttlrdata *rrsig_to_remove = NULL;
    zdb_packed_ttlrdata *rrsig_to_add = NULL;
    dnssec_key_sll *keys = NULL;
    ya_result ret;
    int ksk_count = 0;
    int zsk_count = 0;
    int rrsig_removed = 0;
    int rrsig_added = 0;
    
    dnsname_stack fqdn_stack;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    
    log_debug("rrsig: %{dnsname}: begin update with a loose limit of %i signatures", zone->origin, signature_count_loose_limit);
    
    log_debug("zdb_zone_update_signatures(%p) %{dnsname} [lock=%x]", zone, zone->origin, zone->lock_owner);
    
    if(signature_count_loose_limit < 0)
    {
        log_warn("zdb_zone_update_signatures called with a negative number (%i): assuming sign error and setting to max instead", signature_count_loose_limit);
        signature_count_loose_limit = MAX_S32;
    }
    
    if(!zdb_zone_is_maintained(zone))
    {
        log_debug("zdb_zone_update_signatures(%p) %{dnsname} [lock=%x]: not dnssec", zone, zone->origin, zone->lock_owner);
        return ZDB_ERROR_ZONE_IS_NOT_DNSSEC;
    }
    
    if(!zdb_zone_try_double_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER))
    {
        log_debug("zdb_zone_update_signatures(%p) %{dnsname} [lock=%x]: already locked", zone, zone->origin, zone->lock_owner);
        
        return ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED;
    }
    
    zdb_zone_get_active_keys(zone, &keys, &ksk_count, &zsk_count);
    
    if(zsk_count > 0)
    {
        zdb_zone_label_iterator iter;
        
        // initialises the "start-from" iterator

        if(*from_fqdn == 0)
        {
            zdb_zone_label_iterator_init(&iter, zone);
        }
        else
        {
            zdb_zone_label_iterator_init_from(&iter, zone, from_fqdn);
        }

        time_t now = time(NULL);
        
        zdb_packed_ttlrdata_record_view_data rrv_data;
        resource_record_view rrv = {&rrv_data, zdb_packed_ttlrdata_record_view_get_vtbl()};
        
        ptr_vector rrset_vector = EMPTY_PTR_VECTOR;
        ptr_vector candidates = EMPTY_PTR_VECTOR;
        ptr_vector chain_candidates = EMPTY_PTR_VECTOR;
        //ptr_vector toremove = EMPTY_PTR_VECTOR;
        u32_set tosign = U32_SET_EMPTY;
        
        while(zdb_zone_label_iterator_hasnext(&iter))
        {
            memcpy(&fqdn_stack.labels[0], &iter.dnslabels[0], (iter.top + 1) * sizeof(u8*));
            fqdn_stack.size = iter.top;

            dnsname_stack_to_dnsname(&fqdn_stack, fqdn);

#ifdef DEBUG
            log_debug2("rrsig: %{dnsname}: check %{dnsnamestack}", zone->origin, &fqdn_stack);
#endif

            zdb_rr_label *rr_label = zdb_zone_label_iterator_next(&iter);

            if(rrsig_should_label_be_signed(zone, fqdn, rr_label)) /// @TODO filter
            {
                // the label should be signed

                // get all signatures in a "candidates" list

                // for all types of the rrset
                //   for all keys                    
                //     for all candidates
                //       if the signature covers the rrset for the key
                //         remove if from the candidates
                //       if the signature is invalid
                //         put it in the "toremove" list
                //         continue
                //       (else) if the signature is valid
                //         look for duplicates and put them in the remove list
                //     if there is no valid signature, generate one
                // remove all remaining signatures in "candidates" as they are not linked to any key/type
                // remove all the "toremove" signatures

                // so

                // get all signatures in a "candidates" list

                ptr_vector_empties(&candidates);

                {
                    zdb_packed_ttlrdata *rrsig_sll = zdb_record_find(&rr_label->resource_record_set, TYPE_RRSIG);
                    while(rrsig_sll != NULL)
                    {
                        rdata_desc rr = {TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig_sll), ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig_sll)};

                        log_debug2("rrsig: %{dnsname}: has %{dnsname} %{typerdatadesc} (%p)", zone->origin, fqdn, &rr, rrsig_sll);

                        ptr_vector_append(&candidates, rrsig_sll);
                        rrsig_sll = rrsig_sll->next;
                    }
                }

                yassert(rrsig_to_remove == NULL);
                yassert(rrsig_to_add == NULL);

                // for all types of the rrset ...

                btree_iterator iter;
                btree_iterator_init(rr_label->resource_record_set, &iter);

                while(btree_iterator_hasnext(&iter))
                {
                    btree_node *node = btree_iterator_next_node(&iter);
                    u16 rtype = (u16)node->hash;

                    if(rtype == TYPE_RRSIG)
                    {
                        continue;
                    }

                    //zdb_packed_ttlrdata *rrset_sll = (zdb_packed_ttlrdata*)node->data;

                    // for all (active) keys ...

                    for(dnssec_key_sll *key_sll = keys; key_sll != NULL; key_sll = key_sll->next)
                    {
                        dnssec_key *key = key_sll->key;

                        if((dnssec_key_get_flags(key) == DNSKEY_FLAGS_KSK) && (rtype != TYPE_DNSKEY))
                        {
                            continue;
                        }

                        if((dnssec_key_get_flags(key) == DNSKEY_FLAGS_ZSK) && (rtype == TYPE_DNSKEY))
                        {
                            continue;
                        }

                        log_debug2("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: signature with key tagged %i expected",
                                        zone->origin, fqdn, &rtype, dnssec_key_get_tag_const(key_sll->key));

                        bool type_signed_by_key = FALSE;

                        // for all candidates ...

                        for(int sigidx = 0; sigidx <= ptr_vector_last_index(&candidates); ++sigidx)
                        {
                            zdb_packed_ttlrdata *rrsig = (zdb_packed_ttlrdata*)ptr_vector_get(&candidates, sigidx);

                            u16 type_covered = RRSIG_TYPE_COVERED(rrsig);
#ifdef DEBUG
                            log_debug3("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: looking at signature covering %{dnstype} (%p)",
                                        zone->origin, fqdn, &rtype, &type_covered, rrsig);
#endif
                            if(type_covered == rtype)
                            {
                                u16 key_alg = RRSIG_ALGORITHM(rrsig);
                                u16 key_tag = RRSIG_KEY_TAG(rrsig);

                                // if the signature covers the rrset for the key ...

#ifdef DEBUG
                                log_debug3("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: looking at signature covering %{dnstype} signed by %03i %05i (%p)",
                                        zone->origin, fqdn, &rtype, &type_covered, key_alg, key_tag, rrsig);
#endif

                                if((key_alg != dnssec_key_get_algorithm(key)) || (key_tag != dnssec_key_get_tag_const(key)))
                                {
                                    continue;
                                }

                                // remove if from the candidates ...
#ifdef DEBUG
                                log_debug3("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: swapping signature at %i with last signature", 
                                        zone->origin, fqdn, &rtype, sigidx);
#endif
                                ptr_vector_end_swap(&candidates, sigidx);

                                --candidates.offset;
                                --sigidx;
#ifdef DEBUG
                                log_debug3("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: shrank the size to %i", 
                                        zone->origin, fqdn, &rtype, ptr_vector_size(&candidates));
#endif
                                // if the signature is invalid (time only) ...

                                u32 until = RRSIG_VALID_UNTIL(rrsig);

                                if(until < now)
                                {
                                    log_debug2("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: signature with key tagged %i expired on %T",
                                        zone->origin, fqdn, &rtype, dnssec_key_get_tag_const(key_sll->key), until);

                                    // put it in the "toremove" list ...
                                    // ptr_vector_append(&toremove, rrsig);
                                    zdb_packed_ttlrdata_insert_clone(&rrsig_to_remove, rrsig);
                                    // continue ...
                                }
                                else
                                {
                                    // the signature is valid ...
                                    // look for duplicates and put them in the remove list

                                    for(int dupidx = sigidx + 1; dupidx < ptr_vector_last_index(&candidates); ++dupidx)
                                    {
                                        zdb_packed_ttlrdata *dup_rrsig = (zdb_packed_ttlrdata*)ptr_vector_get(&candidates, dupidx);

                                        u16 dup_type_covered = RRSIG_TYPE_COVERED(dup_rrsig);

                                        if(dup_type_covered == rtype)
                                        {
                                            u16 dup_key_alg = RRSIG_ALGORITHM(dup_rrsig);
                                            if(dup_key_alg == key_alg)
                                            {
                                                u16 dup_key_tag = RRSIG_KEY_NATIVETAG(dup_rrsig);

                                                if(dup_key_tag == key_tag)
                                                {
                                                    log_debug2("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: signature with key tagged %i has duplicates",
                                                            zone->origin, fqdn, &rtype, dnssec_key_get_tag_const(key_sll->key));

                                                    ptr_vector_end_swap(&candidates, dupidx);
                                                    --candidates.offset;
                                                    //ptr_vector_append(&toremove, dup);
                                                    zdb_packed_ttlrdata_insert_clone(&rrsig_to_remove, dup_rrsig);
                                                }
                                            }
                                        }
                                    }

                                    log_debug2("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: signature with key tagged %i is valid (%p)",
                                            zone->origin, fqdn, &rtype, dnssec_key_get_tag_const(key_sll->key), rrsig);

                                    type_signed_by_key = TRUE;
                                }
                            }
                        } // for all candidates

                        // if there is no valid signature, generate one

                        if(!type_signed_by_key)
                        {
                            log_debug2("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: signature required for key tagged %i",
                                                            zone->origin, fqdn, &rtype, dnssec_key_get_tag_const(key_sll->key));

                            u32_node *node = u32_set_avl_insert(&tosign, rtype);
                            dnssec_key_sll *key_sll;
                            ZALLOC_OR_DIE(dnssec_key_sll*, key_sll, dnssec_key_sll, DNSSEC_KEY_SLL_TAG);
                            key_sll->key = key;
                            key_sll->next = node->value;
                            node->value = key_sll;
                        }
                    }
                }
                
                /***************************************************************
                 * 
                 * Parallel chain handling (NSEC3)
                 * 
                 **************************************************************/
                
                if(zdb_zone_is_nsec3(zone))
                {
                    // look at the NSEC3 records
                    
                    // follow the chains
                    
                    nsec3_zone *n3 = zone->nsec.nsec3;
                    nsec3_label_extension *n3le = rr_label->nsec.nsec3;
                    while(n3le != NULL && n3 != NULL)
                    {
                        zdb_packed_ttlrdata *chain_rrsig_to_remove = NULL;
                        zdb_packed_ttlrdata *chain_rrsig_to_add = NULL;
                    
                        const u16 rtype = TYPE_NSEC3;
                        
                        if(n3le->self != NULL)
                        {
                            for(dnssec_key_sll *key_sll = keys; key_sll != NULL; key_sll = key_sll->next)
                            {
                                dnssec_key *key = key_sll->key;

                                if(dnssec_key_get_flags(key) == DNSKEY_FLAGS_ZSK)
                                {
                                    continue;
                                }
                                
                                ptr_vector_empties(&chain_candidates);
                                
                                zdb_packed_ttlrdata *rrsig_sll = n3le->self->rrsig;
                                while(rrsig_sll != NULL)
                                {
                                    rdata_desc rr = {TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig_sll), ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig_sll)};
                                    log_debug2("rrsig: %{dnsname}: has %{dnsname} %{typerdatadesc} (%p)", zone->origin, fqdn, &rr, rrsig_sll);
                                    
                                    ptr_vector_append(&chain_candidates, rrsig_sll);
                                    
                                    rrsig_sll = rrsig_sll->next;
                                }
                                
                                bool signed_with_key = FALSE;
                                
                                for(int sigidx = 0; sigidx <= ptr_vector_last_index(&chain_candidates); ++sigidx)
                                {
                                    zdb_packed_ttlrdata *rrsig = (zdb_packed_ttlrdata*)ptr_vector_get(&chain_candidates, sigidx);
                                    
                                    u16 key_alg = RRSIG_ALGORITHM(rrsig);
                                    u16 key_tag = RRSIG_KEY_TAG(rrsig);

                                    // if the signature covers the rrset for the key ...

                                    if((key_alg != dnssec_key_get_algorithm(key)) || (key_tag != dnssec_key_get_tag_const(key)))
                                    {
                                        continue;
                                    }
                                    
                                    ptr_vector_end_swap(&chain_candidates, sigidx);
                                    --chain_candidates.offset;
                                    --sigidx;
                                    
                                    u32 until = RRSIG_VALID_UNTIL(rrsig);

                                    if(until < now)
                                    {
                                        log_debug2("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: signature with key tagged %i expired on %T",
                                            zone->origin, fqdn, &rtype, dnssec_key_get_tag_const(key_sll->key), until);

                                        // put it in the "toremove" list ...
                                        // ptr_vector_append(&toremove, rrsig);
                                        zdb_packed_ttlrdata_insert_clone(&chain_rrsig_to_remove, rrsig);
                                        // continue ...
                                    }
                                    else
                                    {
                                        // the signature is valid ...
                                        // look for duplicates and put them in the remove list
                                        
                                        signed_with_key = TRUE;
                                    }
                                }
                                
                                if(!signed_with_key)
                                {
                                    log_debug2("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: signature required for key tagged %i",
                                                            zone->origin, fqdn, &rtype, dnssec_key_get_tag_const(key_sll->key));
                                    
                                    // generate signature
                                    
                                    dnskey_signature ds;
                                    dnskey_signature_init(&ds);
                                    zdb_packed_ttlrdata *rrsig = NULL;
                                    zdb_packed_ttlrdata *nsec3_packed_ttl_rdata;
                                    
                                    u8 chain_fqdn[MAX_DOMAIN_LENGTH];
                                    u8 nsec3_packed_ttl_rdata_buffer[sizeof(zdb_packed_ttlrdata) - 1 + TMP_NSEC3_TTLRDATA_SIZE];
                                    
                                    nsec3_packed_ttl_rdata = (zdb_packed_ttlrdata*)nsec3_packed_ttl_rdata_buffer;
                                    
                                    nsec3_zone_item_to_zdb_packed_ttlrdata(
                                            n3,
                                            n3le->self,
                                            zone->origin,
                                            chain_fqdn,                 // out
                                            zone->min_ttl,              // in
                                            nsec3_packed_ttl_rdata,     // tmp
                                            TMP_NSEC3_TTLRDATA_SIZE);

                                    log_debug("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: generating signature with key tagged %i",
                                                zone->origin, fqdn, &rtype, dnssec_key_get_tag_const(key_sll->key));

                                    rrv_data.fqdn = chain_fqdn;
                                    rrv_data.rtype = TYPE_NSEC3;
                                    rrv_data.rclass = CLASS_IN;
                                    rrv_data.rttl = zone->min_ttl;
                                    
                                    if(FAIL(ret = dnskey_signature_rrset_sign_with_key(key_sll->key, &rrset_vector, FALSE, &rrv, (void**)&rrsig)))
                                    {
                                        log_err("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: key tagged  %i could not generate signature: %r",
                                                zone->origin, fqdn, &rtype, dnssec_key_get_tag_const(key_sll->key), ret);
                                    }
                                    else
                                    {
                                        rrsig->next = chain_rrsig_to_add;
                                        chain_rrsig_to_add = rrsig;
                                    }

                                    dnskey_signature_finalise(&ds);
                                }
                            } // for keys
                            
                            // apply the changes
                            
                            zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER);

                            //n3le->self->rrsig;
                            //chain_rrsig_to_remove;
                            //chain_rrsig_to_add
                            
                            zdb_packed_ttlrdata *rrsig_to_remove_sll = chain_rrsig_to_remove;
                            while(rrsig_to_remove_sll != NULL)
                            {
                                zdb_packed_ttlrdata *tmp = NULL;
                                zdb_packed_ttlrdata **prrsig_sll = &n3le->self->rrsig;
                                while(*prrsig_sll != NULL)
                                {
                                    if(zdb_record_equals(*prrsig_sll, rrsig_to_remove_sll))
                                    {
                                        // detach
                                        *prrsig_sll = rrsig_to_remove_sll->next;
                                        break;
                                    }
                                    prrsig_sll = &(*prrsig_sll)->next;
                                }
                                
                                tmp = rrsig_to_remove_sll;
                                rrsig_to_remove_sll = rrsig_to_remove_sll->next;
                                ZDB_RECORD_ZFREE(tmp);
                            }
                            
                            zdb_packed_ttlrdata **prrsig_sll = &n3le->self->rrsig;
                            while(*prrsig_sll != NULL)
                            {
                                prrsig_sll = &(*prrsig_sll)->next;
                            }
                            
                            *prrsig_sll = chain_rrsig_to_add;

                            zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER, ZDB_ZONE_MUTEX_SIMPLEREADER);
                            
                        } // in self
                        
                        n3le = n3le->next;
                        n3 = n3->next;
                    } // for chains
                }
                
                /***************************************************************
                 * 
                 * Parallel chain handling done (NSEC3)
                 * 
                 **************************************************************/

                // at this point all the work is known

                for(int sigidx = 0; sigidx < ptr_vector_last_index(&candidates); ++sigidx)
                {
                    zdb_packed_ttlrdata *rrsig = (zdb_packed_ttlrdata*)ptr_vector_get(&candidates, sigidx);

                    u16 type_covered = RRSIG_TYPE_COVERED(rrsig);
                    u16 key_tag = RRSIG_KEY_TAG(rrsig);

                    //rrsig_context_append_delete_signature(&ctx, rrsig);
                    zdb_packed_ttlrdata_insert_clone(&rrsig_to_remove, rrsig);

                    log_debug2("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: signature for key tagged %i will be removed (%p)",
                            zone->origin, fqdn, &type_covered, key_tag, rrsig);
                }
                /*
                for(int sigidx = 0; sigidx < ptr_vector_last_index(&toremove); ++sigidx)
                {
                    zdb_packed_ttlrdata *rrsig = (zdb_packed_ttlrdata*)ptr_vector_get(&toremove, sigidx);
                    rrsig_context_append_delete_signature(&ctx, rrsig);
                }
                */
                if(!u32_set_avl_isempty(&tosign))
                {
                    // here ...

                    rrv_data.fqdn = fqdn;
                    rrv_data.rclass = CLASS_IN;

                    u32_set_avl_iterator iter;
                    u32_set_avl_iterator_init(&tosign, &iter);
                    while(u32_set_avl_iterator_hasnext(&iter))
                    {
                        u32_node *node = u32_set_avl_iterator_next_node(&iter);
                        u16 rtype = (u16)node->key;

                        rrv_data.rtype = rtype;

                        zdb_packed_ttlrdata *rrset_sll = zdb_record_find(&rr_label->resource_record_set, rtype);

                        if(rrset_sll != NULL)
                        {
                            rrv_data.rttl = rrset_sll->ttl;

                            log_debug2("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: rrset TTL is %i",
                                    zone->origin, fqdn, &rtype, rrv_data.rttl);
                        }

                        ptr_vector_empties(&rrset_vector);

                        while(rrset_sll != NULL)
                        {
                            ptr_vector_append(&rrset_vector, rrset_sll);
                            rrset_sll = rrset_sll->next;
                        }

                        dnssec_key_sll *key_sll = (dnssec_key_sll*)node->value;

                        bool canonize = TRUE;

                        while(key_sll != NULL)
                        {
                            // sign the type with the key
                            // (as optimisation, the canonisation may be done once)

                            //ret = rrsig_update_rrset_with_key(&ctx, rr_label, rtype, key_sll->key, TRUE);

                            dnskey_signature ds;
                            dnskey_signature_init(&ds);
                            zdb_packed_ttlrdata *rrsig = NULL;

                            log_debug("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: generating signature with key tagged %i",
                                        zone->origin, fqdn, &rtype, dnssec_key_get_tag_const(key_sll->key));

                            if(FAIL(ret = dnskey_signature_rrset_sign_with_key(key_sll->key, &rrset_vector, canonize, &rrv, (void**)&rrsig)))
                            {
                                log_err("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: key tagged  %i could not generate signature: %r",
                                        zone->origin, fqdn, &rtype, dnssec_key_get_tag_const(key_sll->key), ret);
                            }

                            dnskey_signature_finalise(&ds);

                            if(rrsig != NULL)
                            {
                                rdata_desc rr = {TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig), ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig)};
                                log_debug3("rrsig: %{dnsname}: generated %{dnsname} %{typerdatadesc} (%p)", zone->origin, fqdn, &rr, rrsig);

                                zdb_packed_ttlrdata_insert(&rrsig_to_add, rrsig);

                                canonize = FALSE;
                            }

                            dnssec_key_sll *tmp = key_sll;
                            key_sll = key_sll->next;
                            ZFREE(tmp, dnssec_key_sll);

                            --signature_count_loose_limit;
                        }
                    }

                    u32_set_avl_destroy(&tosign);
                }
            }
            else
            {
                // the label should not be signed

                log_debug2("rrsig: %{dnsname}: %{dnsname}: should not be signed", zone->origin, fqdn);

                // delete all signatures

                zdb_packed_ttlrdata *rrsig_sll = zdb_record_find(&rr_label->resource_record_set, TYPE_RRSIG);
                while(rrsig_sll != NULL)
                {
                    u16 type_covered = RRSIG_TYPE_COVERED(rrsig_sll);
                    u16 key_tag = RRSIG_KEY_NATIVETAG(rrsig_sll);

                    log_debug2("rrsig: %{dnsname}: %{dnsname}: %{dnstype}: signature for key tagged %i is not required and will be removed",
                            zone->origin, fqdn, &type_covered, key_tag);

                    //rrsig_context_append_delete_signature(&ctx, rrsig_sll);
                    zdb_packed_ttlrdata_insert_clone(&rrsig_to_remove, rrsig_sll);
                    rrsig_sll = rrsig_sll->next;
                }
            }

            zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER);

            while(rrsig_to_remove != NULL)
            {
                zdb_ttlrdata rrsig_record =
                {
                    NULL,
                    rrsig_to_remove->ttl,
                    ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig_to_remove),
                    0,
                    ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig_to_remove)
                };

                rdata_desc rr = {TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig_to_remove), ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig_to_remove)};

                log_debug("rrsig: %{dnsname}: - %{dnsname} %{typerdatadesc}",
                        zone->origin, fqdn, &rr);

#if HAS_DYNUPDATE_DIFF_ENABLED
#pra gma message "TODO: 20161215 edf -- HAS_DYNUPDATE_DIFF_ENABLED use the diff mechanism (zdb_record_delete_exact)"
                log_err("TODO: 20161215 edf -- HAS_DYNUPDATE_DIFF_ENABLED use the diff mechanism (zdb_record_delete_exact)");
#endif
                zdb_record_delete_exact(&rr_label->resource_record_set, TYPE_RRSIG, &rrsig_record);
                
#if ZDB_CHANGE_FEEDBACK_SUPPORT
                if(zdb_listener_notify_enabled())
                {
                    zdb_listener_notify_remove_record(zone, fqdn, TYPE_RRSIG, &rrsig_record);
                }
#endif
                ++rrsig_removed;
                zdb_packed_ttlrdata *tmp = rrsig_to_remove;
                rrsig_to_remove = rrsig_to_remove->next;
                ZDB_RECORD_ZFREE(tmp);
            }

            while(rrsig_to_add != NULL)
            {
                zdb_packed_ttlrdata *next = rrsig_to_add->next;

                rdata_desc rr = {TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig_to_add), ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig_to_add)};

                log_debug("rrsig: %{dnsname}: + %{dnsname} %{typerdatadesc}",
                        zone->origin, fqdn, &rr);
                
#if HAS_DYNUPDATE_DIFF_ENABLED
#pra gma message "TODO: 20161215 edf -- HAS_DYNUPDATE_DIFF_ENABLED use the diff mechanism (zdb_record_insert) (not triggered in any test yet ?)"
                log_err("TODO: 20161215 edf -- HAS_DYNUPDATE_DIFF_ENABLED use the diff mechanism (zdb_record_insert)");
#endif
                zdb_record_insert(&rr_label->resource_record_set, TYPE_RRSIG, rrsig_to_add);
                
#if ZDB_CHANGE_FEEDBACK_SUPPORT
                if(zdb_listener_notify_enabled())
                {
                    dnsname_vector name_path;

                    zdb_ttlrdata unpacked_ttlrdata;

                    unpacked_ttlrdata.ttl = rrsig_to_add->ttl;
                    unpacked_ttlrdata.rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig_to_add);
                    unpacked_ttlrdata.rdata_pointer = ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig_to_add);

                    dnsname_to_dnsname_vector(fqdn, &name_path);

                    zdb_listener_notify_add_record(zone, name_path.labels, name_path.size, TYPE_RRSIG, &unpacked_ttlrdata);
                }
#endif
                
                ++rrsig_added;
                rrsig_to_add = next;
            }

            zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER, ZDB_ZONE_MUTEX_SIMPLEREADER);

            if(signature_count_loose_limit <= 0)
            {
                /// TODO save current location

                break;
            }

        } // while has labels ..
        
        /// TODO commit the signatures ...
        
        ptr_vector_destroy(&chain_candidates);
        ptr_vector_destroy(&candidates);
        ptr_vector_destroy(&rrset_vector);
    }
    
    if(signature_count_loose_limit > 0)
    {
        if(zdb_zone_is_nsec3(zone))
        {
            // proceed on the NSEC3 chain
            
            // one NSEC3 record per label, so canonisation is easy
        }
    }
    
    zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
    
    zdb_zone_release_active_keys(keys);
    
    size_t fqdn_len = dnsname_len(fqdn);
    
    if(fqdn_len <= from_fqdn_size)
    {
        memcpy(from_fqdn, fqdn, fqdn_len);
    }
        
    log_debug("rrsig: %{dnsname}: done", zone->origin);
    
    return rrsig_removed + rrsig_added;
}

/**
 * Will double-lock for reader & rrsig-updater
 * 
 * @param zone
 * @param signature_count_loose_limit
 * @param present_signatures_are_verified
 * @return 
 */

ya_result zdb_zone_update_signatures(zdb_zone* zone, s32 signature_count_loose_limit, bool present_signatures_are_verified)
{
    ya_result ret;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    
    if(zone->progressive_signature_update.current_fqdn != NULL)
    {
        dnsname_copy(fqdn, zone->progressive_signature_update.current_fqdn);
    }
    else
    {
        fqdn[0] = 0;
    }
        
    ret = zdb_zone_update_signatures_from(zone, fqdn, sizeof(fqdn), signature_count_loose_limit);
    
    return ret;
}

#endif

/** @} */

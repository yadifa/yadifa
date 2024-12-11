/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @defgroup
 * @ingroup dnsdb
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/timems.h>
#include <dnscore/rfc.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_icmtl.h"

#include "dnsdb/zdb_packed_ttlrdata.h"

#include "dnsdb/dnssec.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/dnssec_keystore.h"
#include <dnscore/dnskey_signature.h>
#include <dnscore/base32hex.h>

#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb_zone_maintenance.h"

extern logger_handle_t *g_database_logger;
#define MODULE_MSG_HANDLE                      g_database_logger

#define ZDB_ZONE_MAINTENANCE_DETAILED_LOG      0 /// @note 20180615 edf -- heavy, use with care
#define ZDB_ZONE_MAINTENANCE_IGNORE_TIME_QUOTA 0
#define DEBUG_SIGNATURE_REFRESH                0

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
#pragma message("WARNING: ZDB_ZONE_MAINTENANCE_DETAILED_LOG is not set to 0")
#endif

#if ZDB_ZONE_MAINTENANCE_IGNORE_TIME_QUOTA
#pragma message("WARNING: ZDB_ZONE_MAINTENANCE_IGNORE_TIME_QUOTA is not set to 0")
#endif

#define ZDB_ZONE_MAINTENANCE_SAME_PASS_CLOSE       1
#define ZDB_ZONE_MAINTENANCE_RRSIG_COUNT_THRESHOLD 256   // after that many signatures, stop processing labels
#define ZDB_MAINTENANCE_BATCH_TIME_US_MAX          20000 // 10ms

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
#pragma message("WARNING: ZDB_ZONE_MAINTENANCE_DETAILED_LOG IS NOT SET TO 0.  SET IT BACK TO 0 IT IF YOU DON'T NEED IT!")
#pragma message("WARNING: ZDB_ZONE_MAINTENANCE_DETAILED_LOG IS NOT SET TO 0.  SET IT BACK TO 0 IT IF YOU DON'T NEED IT!")
#pragma message("WARNING: ZDB_ZONE_MAINTENANCE_DETAILED_LOG IS NOT SET TO 0.  SET IT BACK TO 0 IT IF YOU DON'T NEED IT!")
#endif

static bool zdb_zone_maintenance_validate_sign_chain_store(zdb_zone_maintenance_ctx *mctx, zone_diff *diff, zdb_zone_t *zone, ptr_vector_t *rrset_to_sign, ptr_vector_t *remove, ptr_vector_t *add)
{
    ya_result ret;

    log_debug("maintenance: validate-sign-chain-store: %{dnsname}", zone->origin);

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
    for(int_fast32_t i = 0; i <= ptr_vector_last_index(remove); ++i)
    {
        zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(remove, i);
        rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

        log_debug("before-validate: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
    }

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(add); ++i)
    {
        zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(add, i);
        rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

        log_debug("before-validate: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
    }
#endif

    if(ISOK(ret = zone_diff_validate(diff)))
    {
#if DEBUG
        log_debug("maintenance: %{dnsname}: diff validated", diff->origin);
#endif
        // store changes in vectors and get the RR sets to sign

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(remove, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-get-changes: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(add, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-get-changes: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }
#endif
        ptr_vector_t ksks = PTR_VECTOR_EMPTY;
        ptr_vector_t zsks = PTR_VECTOR_EMPTY;

        int32_t      mandatory_changes = zone_diff_get_changes(diff, rrset_to_sign, &ksks, &zsks, remove, add, zone->sig_validity_regeneration_seconds);

        // sign the records, store the changes in vectors

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(remove, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-diff-sign: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(add, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-diff-sign: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        log_debug("maintenance: mandatory-changes: %i", mandatory_changes);
#endif

        bool relevant_update = (mandatory_changes > 0);

        if(relevant_update)
        {
            /*
             * Signs the RRSETs using the ksk & zsk, applies the changes in remove and add vectors
             */

            dnssec_chain_store_diff(&mctx->nsec_chain_updater, diff, &zsks, remove, add);

            zone_diff_sign(diff, zone, rrset_to_sign, &ksks, &zsks, remove, add);

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
            for(int_fast32_t i = 0; i <= ptr_vector_last_index(remove); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(remove, i);
                rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

                log_debug("before-nsec3-chain-store-diff: %{dnsname}: - [%02x] %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->state, rr->fqdn, rr->ttl, &rd);
            }

            for(int_fast32_t i = 0; i <= ptr_vector_last_index(add); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(add, i);
                rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

                log_debug("before-nsec3-chain-store-diff: %{dnsname}: + [%02x] %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->state, rr->fqdn, rr->ttl, &rd);
            }
#endif
            // zone_diff_get_chain_changes(diff, &dc);

            dnssec_chain_store_diff(&mctx->nsec3_chains_updater, diff, &zsks, remove, add);

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
            for(int_fast32_t i = 0; i <= ptr_vector_last_index(remove); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(remove, i);
                rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

                log_debug("when-all-is-said-and-done: %{dnsname}: - [%02x] %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->state, rr->fqdn, rr->ttl, &rd);
            }

            for(int_fast32_t i = 0; i <= ptr_vector_last_index(add); ++i)
            {
                zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(add, i);
                rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

                log_debug("when-all-is-said-and-done: %{dnsname}: + [%02x] %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->state, rr->fqdn, rr->ttl, &rd);
            }
#endif
        }

        dnssec_keystore_release_keys_from_vector(&zsks);
        dnssec_keystore_release_keys_from_vector(&ksks);

        ptr_vector_finalise(&zsks);
        ptr_vector_finalise(&ksks);

        return relevant_update;
    }
    else
    {
        log_err("maintenance: %{dnsname}: could not validate the diff", diff->origin);

        return false;
    }
}

static void zdb_zone_maintenance_ctx_init(zdb_zone_maintenance_ctx *mctx, zdb_zone_t *zone)
{
    log_debug("maintenance: %{dnsname}: context init", zone->origin);
    ZEROMEMORY(mctx, sizeof(zdb_zone_maintenance_ctx));
    mctx->zone = zone;
}

static void zdb_zone_maintenance_ctx_finalize(zdb_zone_maintenance_ctx *mctx)
{
    log_debug("maintenance: %{dnsname}: context finalize", mctx->zone->origin);

    log_debug("maintenance: %{dnsname}: context finalize: clearing KSK", mctx->zone->origin);

    dnssec_keystore_release_keys_from_vector(&mctx->ksks);

    log_debug("maintenance: %{dnsname}: context finalize: clearing ZSK", mctx->zone->origin);

    dnssec_keystore_release_keys_from_vector(&mctx->zsks);

    ptr_vector_finalise(&mctx->ksks);
    ptr_vector_finalise(&mctx->zsks);

    log_debug("maintenance: %{dnsname}: context finalize: finalising NSEC chain", mctx->zone->origin);

    dnssec_chain_finalize(&mctx->nsec_chain_updater);

    log_debug("maintenance: %{dnsname}: context finalize: finalising NSEC3 chain", mctx->zone->origin);

    dnssec_chain_finalize(&mctx->nsec3_chains_updater);

    log_debug("maintenance: %{dnsname}: context finalize: releasing active keys", mctx->zone->origin);

    zdb_zone_release_active_keys(mctx->keys);

    mctx->keys = NULL;

    log_debug("maintenance: %{dnsname}: context finalize done", mctx->zone->origin);
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

static ya_result zdb_zone_maintenance_from(zdb_zone_t *zone, uint8_t *from_fqdn, size_t from_fqdn_size, int64_t maxus, int32_t rrsigcountmax)
{
    yassert(((from_fqdn != NULL) && (from_fqdn_size > 0)) || ((from_fqdn == NULL) && (from_fqdn_size == 0)));
    // bool from_fqdn_is_binary_digest = false;

    if(!zdb_zone_is_maintained(zone))
    {
        log_debug("maintenance: %{dnsname}: not maintained", zone->origin);
        return ZDB_ERROR_ZONE_NOT_MAINTAINED;
    }

    uint8_t current_owner;
    uint8_t current_reserved_owner;

    while(!zdb_zone_try_double_lock_ex(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER, &current_owner, &current_reserved_owner))
    {
        log_debug("maintenance: %{dnsname}: cannot double-lock the zone for maintenance (%02x, %04x, %02x, %02x)", zone->origin, zone->_flags, zone->_status, current_owner, current_reserved_owner);

        if((current_owner == ZDB_ZONE_MUTEX_RRSIG_UPDATER) || (current_reserved_owner == ZDB_ZONE_MUTEX_RRSIG_UPDATER))
        {
            // the zone is already being signed
            return ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED;
        }
        else
        {
            // wait for the condition
            mutex_lock(&zone->lock_mutex);
            cond_timedwait(&zone->lock_cond, &zone->lock_mutex, 1000);
            mutex_unlock(&zone->lock_mutex);
        }
    }

    if((from_fqdn != NULL) && (from_fqdn[0] != 0))
    {
        log_debug("maintenance: %{dnsname}: starting from %{dnsname}", zone->origin, from_fqdn);
    }
    else
    {
        log_debug("maintenance: %{dnsname}: starting from the apex", zone->origin);
        zdb_zone_clear_maintenance_queued(zone);
    }

    int64_t                  start_time = timeus();

    int                      maintenance_rrsig_count = 0;
    int                      maintenance_nsec_count = 0;
    int                      maintenance_nsec3_count = 0;
    int                      maintenance_generate_nsec3_rrsig_count = 0;
    int                      maintenance_generate_nsec3param_rrsig_count = 0;
    bool                     nsecchainstate_changed = false;

    zdb_zone_maintenance_ctx mctx;
    zdb_zone_maintenance_ctx_init(&mctx, zone);

    uint8_t   maintain_mode = zone_get_maintain_mode(zone);

    zone_diff diff;
    zone_diff_init(&diff, zone, true);

    switch(maintain_mode)
    {
        case ZDB_ZONE_MAINTAIN_NSEC3:
        case ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:
        {
            diff.maintain_nsec3 = true;
            break;
        }
        case ZDB_ZONE_MAINTAIN_NSEC:
        {
            diff.maintain_nsec = true;
            break;
        }
        default:
        {
            break;
        }
    }

    dnssec_chain_init(&mctx.nsec_chain_updater, dynupdate_nsec_chain_get_vtbl(), &diff);
    if((maintain_mode & ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT) != ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT)
    {
        dnssec_chain_init(&mctx.nsec3_chains_updater, dynupdate_nsec3_chain_get_vtbl(), &diff);
    }
    else
    {
        dnssec_chain_init(&mctx.nsec3_chains_updater, dynupdate_nsec3_optout_chain_get_vtbl(), &diff);
    }

    // load all the active keys from the keyring of the zone
    // compute a mask for all the keys that are private (usable)

    log_debug("maintenance: %{dnsname}: fetching keys", zone->origin);

    ptr_vector_init(&mctx.ksks);
    ptr_vector_init(&mctx.zsks);
    zone_diff_store_diff_dnskey_get_keys(&diff, &mctx.ksks, &mctx.zsks, zone->sig_validity_regeneration_seconds);

    uint64_t ksk_mask = 0;
    uint64_t zsk_mask = 0;

    mctx.now = time(NULL);

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(&mctx.ksks); ++i)
    {
        const dnskey_t *key = (const dnskey_t *)ptr_vector_get(&mctx.ksks, i);

        if(dnskey_is_private(key))
        {
            log_debug("maintenance: DNSKEY: %{dnsname}+%03d+%05d/%d is not a private KSK", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));
            continue;
        }

        if(dnskey_is_activated_lenient(key, mctx.now, zone->sig_validity_regeneration_seconds))
        {
            ksk_mask |= 1ULL << i;
            log_debug("maintenance: DNSKEY: %{dnsname}+%03d+%05d/%d will be used for KSK signatures", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));
        }
    }

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(&mctx.zsks); ++i)
    {
        const dnskey_t *key = (const dnskey_t *)ptr_vector_get(&mctx.zsks, i);

        if(!dnskey_is_private(key))
        {
            log_debug("maintenance: DNSKEY: %{dnsname}+%03d+%05d/%d is not a private ZSK", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));
            continue;
        }

        if(dnskey_is_activated_lenient(key, mctx.now, zone->sig_validity_regeneration_seconds))
        {
            zsk_mask |= 1ULL << i;
            log_debug("maintenance: DNSKEY: %{dnsname}+%03d+%05d/%d will be used for ZSK signatures", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag_const(key), ntohs(dnskey_get_flags(key)));
        }
    }

    mctx.ksk_mask = ksk_mask;
    mctx.zsk_mask = zsk_mask;
    mctx.ksk_count = ptr_vector_size(&mctx.ksks);
    mctx.zsk_count = ptr_vector_size(&mctx.zsks);

    log_debug("maintenance: DNSKEY: %{dnsname}: ksk mask=%p, count=%llx, zsk mask=%p, count = %i", mctx.zone->origin, mctx.ksk_mask, mctx.ksk_count, mctx.zsk_mask, mctx.zsk_count);

    if(mctx.zsk_mask == 0)
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_RRSIG_UPDATER);

        zone_diff_finalize(&diff);
        zdb_zone_maintenance_ctx_finalize(&mctx);

        return ZDB_ERROR_ZONE_NO_ZSK_PRIVATE_KEY_FILE;
    }

    ptr_vector_t remove = PTR_VECTOR_EMPTY;
    ptr_vector_t add = PTR_VECTOR_EMPTY;

    int          loop_iterations = 0; // prevents loops to break in first iteration when the system is too slow (forever retrying)

    bool         diff_has_changes = false;
    bool         actions_happened = false;
    bool         last_label_of_zone_reached = false;
    // bool soa_updated = false;

    diff.has_active_ksk = ksk_mask != 0;
    diff.has_active_zsk = zsk_mask != 0;

    // the maximum number of labels we are allowed to process in one pass

    int       labels_at_once = mctx.zone->progressive_signature_update.labels_at_once;

    ya_result ret;

    log_debug("maintenance: %{dnsname}: has %i KSKs and %i ZSKs" /* (%i and %i)"*/, zone->origin, mctx.ksk_count, mctx.zsk_count /*, mctx_ksk_count, mctx_zsk_count*/);

    // no rrset to sign, for now

    ptr_vector_t rrset_to_sign = PTR_VECTOR_EMPTY;

    // get a copy of the APEX

    zone_diff_fqdn           *apex = zone_diff_add_static_fqdn(&diff, diff.origin, zone->apex);

    zdb_zone_label_iterator_t iter;

    // initialises the "start-from" iterator

    if(zone->progressive_signature_update.chain_index < 0)
    {
        if((from_fqdn == NULL) || (*from_fqdn == 0))
        {
            zdb_zone_label_iterator_init(zone, &iter);
            // also reset the earliest resignature
            mctx.zone->progressive_signature_update.earliest_signature_expiration = INT32_MAX;
            mctx.zone->progressive_signature_update.labels_at_once = ZDB_ZONE_MAINTENANCE_LABELS_AT_ONCE_DEFAULT;
        }
        else
        {
            zdb_zone_label_iterator_init_from(&iter, zone, from_fqdn);
        }
    }

    // get the nsec status

    nsec_zone_get_status(zone, &mctx.nsec_chain_status);
    dnssec_chain_add_chain(&mctx.nsec_chain_updater, (dnssec_chain_head_t)zone->nsec.nsec, (mctx.nsec_chain_status & NSEC_ZONE_REMOVING) != 0);

    // get all nsec3 statuses
    mctx.nsec3_chain_count = MIN(nsec3_zone_get_chain_count(zone), ZDB_ZONE_MAINTENANCE_NSEC3CHAIN_MAX);
    nsec3_zone_get_chains(zone, mctx.nsec3_chain, mctx.nsec3_chain_count);
    for(uint_fast8_t nsec3_chain_index = 0; nsec3_chain_index < mctx.nsec3_chain_count; ++nsec3_chain_index)
    {
        const uint8_t *nsec3param_rdata = mctx.nsec3_chain[nsec3_chain_index]->rdata;
        nsec3_zone_get_status_from_rdata(zone, nsec3param_rdata, NSEC3PARAM_RDATA_SIZE_FROM_CHAIN(mctx.nsec3_chain[nsec3_chain_index]), &mctx.nsec3_chain_status[nsec3_chain_index]);
        dnssec_chain_add_chain(&mctx.nsec3_chains_updater, (dnssec_chain_head_t)mctx.nsec3_chain[nsec3_chain_index], (mctx.nsec3_chain_status[nsec3_chain_index] & NSEC3_ZONE_REMOVING) != 0);
    }

    /**************************************************************************************************************
     *
     * "Normal" database (chain_index < 0)
     *
     **************************************************************************************************************/

    ptr_vector_t rrset_vector = PTR_VECTOR_EMPTY;
    ptr_vector_t candidates = PTR_VECTOR_EMPTY;
    ptr_vector_t chain_candidates = PTR_VECTOR_EMPTY;

    int64_t      labels_to_process_count = labels_at_once;
    if(labels_to_process_count == 0)
    {
        labels_to_process_count = INT64_MAX;
    }

    uint8_t from_digest[256];

    if(zone->progressive_signature_update.chain_index < 0)
    {
        for(;;)
        {
            if(zdb_zone_label_iterator_hasnext(&iter))
            {
                memcpy(&mctx.fqdn_stack.labels[0], &iter.dnslabels[0], sizeof(uint8_t *) * (iter.top + 1));

                mctx.fqdn_stack.size = iter.top; // MUST be called before zdb_zone_label_iterator_next(&iter)

                zdb_rr_label_t *rr_label = zdb_zone_label_iterator_next(&iter);

                // if we are under delegation : don't stop (resuming from under a delegation would require to fetch more
                // data

                bool under_delegation = ZDB_LABEL_UNDERDELEGATION(rr_label);

                dnsname_stack_to_dnsname(&mctx.fqdn_stack, mctx.fqdn);

                // if too many iterations : break

                int64_t now = timeus();

                --labels_to_process_count;

                if(!under_delegation)
                {
                    if(labels_to_process_count < 0)
                    {
#if DEBUG
                        double dt = now - start_time;
                        dt /= ONE_SECOND_US_F;
                        log_debug(
                            "maintenance: %{dnsname}: time elapsed (%fs): fqdn quota spent: next one will be "
                            "%{dnsnamestack}",
                            zone->origin,
                            dt,
                            &mctx.fqdn_stack);
#endif
                        break;
                    }

#if !ZDB_ZONE_MAINTENANCE_IGNORE_TIME_QUOTA
                    if((loop_iterations > 0) && (now - start_time >= maxus))
                    {
                        // too much time taken already
#if DEBUG
                        double dt = now - start_time;
                        dt /= ONE_SECOND_US_F;
                        log_debug("maintenance: %{dnsname}: time elapsed (%fs): time spent: next one will be %{dnsnamestack}", zone->origin, dt, &mctx.fqdn_stack);
#endif
                        break;
                    }
#endif
                }

                ++loop_iterations;
#if DEBUG
                log_debug2("maintenance: %{dnsname}: at %{dnsnamestack}", zone->origin, &mctx.fqdn_stack);
#endif
                mctx.label = rr_label;

                zone_diff_fqdn *diff_fqdn = zone_diff_add_static_fqdn(&diff, mctx.fqdn, rr_label);

                maintenance_rrsig_count += zdb_zone_maintenance_rrsig(&mctx, diff_fqdn, &rrset_to_sign);
                maintenance_nsec_count += zdb_zone_maintenance_nsec(&mctx, diff_fqdn, &rrset_to_sign);
                maintenance_nsec3_count += zdb_zone_maintenance_nsec3(&mctx, diff_fqdn); // only affects the chain structure, hence the lack of "rrset_to_sign"

#if DEBUG
                log_debug2("maintenance: %{dnsname}: at %{dnsnamestack} %i + %i + %i = %i",
                           zone->origin,
                           &mctx.fqdn_stack,
                           maintenance_rrsig_count,
                           maintenance_nsec_count,
                           maintenance_nsec3_count,
                           maintenance_rrsig_count + maintenance_nsec_count + maintenance_nsec3_count);
#endif

                if(maintenance_rrsig_count + maintenance_nsec_count + maintenance_nsec3_count > 0)
                {
                    // ++labels_to_process_count;
                    actions_happened = true;

                    // if too many signatures are already to be generated, don't process more labels

                    if(maintenance_rrsig_count > rrsigcountmax)
                    {
                        labels_at_once = loop_iterations; // update the amount of labels projected in this update
                        labels_to_process_count = 0;      // prevents doing more labels
                    }
                }
            }
            else
            {
#if DEBUG
                log_debug("maintenance: %{dnsname}: reached the last label", zone->origin);
#endif
                if(mctx.nsec3_chain_count > 0)
                {
                    // if the chain is not empty in the zone

                    if(mctx.zone->nsec.nsec3->items != NULL)
                    {
                        log_debug("maintenance: %{dnsname}: will process NSEC3 chain(s)", zone->origin);
                        zone->progressive_signature_update.chain_index = 0;
                        nsec3_zone_item_t *first = nsec3_get_first(&mctx.zone->nsec.nsec3->items);

                        memcpy(from_digest, first->digest, first->digest[0] + 1);
                        from_digest[first->digest[0] + 1] = 0;
                        // from_fqdn_is_binary_digest = true;

                        log_debug("maintenance: %{dnsname}: starting work on NSEC3 chain %i", zone->origin, zone->progressive_signature_update.chain_index);
                    }
                    else
                    {
#if DEBUG
                        log_debug("maintenance: %{dnsname}: no chain to process after the last label", zone->origin);
#endif
                        last_label_of_zone_reached = true;
                    }
                }
                else
                {
#if DEBUG
                    log_debug("maintenance: %{dnsname}: no chain in the zone to be processed after the last label", zone->origin);
#endif
                    last_label_of_zone_reached = true;
                }

                break;
            }
        } // while has labels ..
    }
    else
    {
        // if we are working in the NSEC3 chains, the index is >= 0
        // then we also want to decode the base32hex encoding to work on the binary digest

        from_digest[0] = base32hex_decode((const char *)&from_fqdn[1], from_fqdn[0], &from_digest[1]);
        // from_fqdn_is_binary_digest = true;

        log_debug("maintenance: %{dnsname}: starting work on NSEC3 chain %i", zone->origin, zone->progressive_signature_update.chain_index);
    }

    // while no more normal labels are to be processed but NSEC3 chains are remaining

    /**************************************************************************************************************
     *
     * "NSEC3" database
     *
     **************************************************************************************************************/

    while(zone->progressive_signature_update.chain_index >= 0)
    {
        loop_iterations = 0;

        // yassert(from_fqdn_is_binary_digest);

        nsec3_zone_t *n3e = zdb_zone_get_nsec3chain(mctx.zone, zone->progressive_signature_update.chain_index);

        if(n3e == NULL)
        {
            break;
        }

        nsec3_iterator_t iter;
        nsec3_iterator_init_from(&n3e->items, &iter, from_digest); // binary form

        for(;;)
        {
            if(nsec3_iterator_hasnext(&iter))
            {
                nsec3_zone_item_t *item = nsec3_iterator_next_node(&iter);
                // uint8_t digest_len = NSEC3_NODE_DIGEST_SIZE(item);

                // check signature
                //   mark signature for update
                //     actions_happened = true;

                int64_t now = timeus();

                if(item->rc <= 0)
                {
                    double dt = now - start_time;
                    dt /= ONE_SECOND_US_F;
                    log_debug(
                        "maintenance: %{dnsname}: time elapsed (%fs): %{digest32h}.%{dnsname} has no owner (rc=%i, "
                        "sc=%i)",
                        zone->origin,
                        dt,
                        item->digest,
                        zone->origin,
                        item->rc,
                        item->sc);
                }

                --labels_to_process_count;

                if(labels_to_process_count < 0)
                {
#if DEBUG
                    double dt = now - start_time;
                    dt /= ONE_SECOND_US_F;
                    log_debug(
                        "maintenance: %{dnsname}: time elapsed (%fs): fqdn quota spent: next one will be "
                        "%{digest32h}.%{dnsname}",
                        zone->origin,
                        dt,
                        item->digest,
                        zone->origin);
#endif
                    uint8_t digest_len = NSEC3_NODE_DIGEST_SIZE(item);
                    mctx.fqdn[0] = base32hex_encode_lc(NSEC3_NODE_DIGEST_PTR(item), digest_len, (char *)&mctx.fqdn[1]);
                    dnsname_copy(&mctx.fqdn[mctx.fqdn[0] + 1], zone->origin);

                    /************************************
                     * GOTO, breaking two loops at once.*
                     ************************************/

                    goto zdb_zone_maintenance_from_chain_iteration_loop_break;
                }

#if !ZDB_ZONE_MAINTENANCE_IGNORE_TIME_QUOTA
                if((loop_iterations > 0) && (now - start_time >= maxus))
                {
                    // too much time taken already
#if DEBUG
                    double dt = now - start_time;
                    dt /= ONE_SECOND_US_F;
                    log_debug(
                        "maintenance: %{dnsname}: time elapsed (%fs): time spent: next one will be "
                        "%{digest32h}.%{dnsname}",
                        zone->origin,
                        dt,
                        item->digest,
                        zone->origin);
#endif
                    uint8_t digest_len = NSEC3_NODE_DIGEST_SIZE(item);
                    mctx.fqdn[0] = base32hex_encode_lc(NSEC3_NODE_DIGEST_PTR(item), digest_len, (char *)&mctx.fqdn[1]);
                    dnsname_copy(&mctx.fqdn[mctx.fqdn[0] + 1], zone->origin);

                    /************************************
                     * GOTO, breaking two loops at once.*
                     ************************************/

                    goto zdb_zone_maintenance_from_chain_iteration_loop_break;
                }
#endif
                intptr_t nsec3_key_mask;

                bool     delete_nsec3_rrsig = false;

                if(item->rrsig_rrset != NULL)
                {
                    nsec3_key_mask = 0;
                    uint32_t                               key_matched = 0;

                    zdb_resource_record_set_const_iterator rrsig_rrset_iter;
                    zdb_resource_record_set_const_iterator_init(item->rrsig_rrset, &rrsig_rrset_iter);
                    while(zdb_resource_record_set_const_iterator_has_next(&rrsig_rrset_iter))
                    {
                        const zdb_resource_record_data_t *rrsig_record = zdb_resource_record_set_const_iterator_next(&rrsig_rrset_iter);

                        int32_t                           key_index = -2;

                        // returns true iff the signature needs to be removed, that covers "key not found"

                        bool rrsig_should_remove_signature_from_rdata_result = rrsig_should_remove_signature_from_rdata(
                            zdb_resource_record_data_rdata_const(rrsig_record), zdb_resource_record_data_rdata_size(rrsig_record), &mctx.zsks, mctx.now, zone->sig_validity_regeneration_seconds, &key_index);
#if DEBUG_SIGNATURE_REFRESH
                        rdata_desc_t nsec3_rrsig_desc = {TYPE_RRSIG, zdb_resource_record_data_rdata_size(rrsig_record), zdb_resource_record_data_rdata_const(rrsig_record)};
                        log_debug("maintenance: %{dnsname}: should-remove: %{digest32h}.%{dnsname} %{typerdatadesc}: %s (%i)",
                                  zone->origin,
                                  item->digest,
                                  zone->origin,
                                  &nsec3_rrsig_desc,
                                  (rrsig_should_remove_signature_from_rdata_result ? "yes" : "no"),
                                  key_index);
#endif
                        if(rrsig_should_remove_signature_from_rdata_result)
                        {
                            if(key_index >= 0)
                            {
                                // RRSIG will be removed, use the key_index to update the mask
                                nsec3_key_mask |= 1LL << key_index;
                            }
                            else
                            {
                                // the key was not found: remove the RRSIG
                                delete_nsec3_rrsig = true; // this enables a "filter out"
                            }
                        }
                        else
                        {
                            key_matched |= 1LL << key_index;
                        }
                    }

                    // keys whose signatures have not been found are added now

                    nsec3_key_mask |= key_matched ^ mctx.zsk_mask;
                }
                else
                {
                    nsec3_key_mask = mctx.zsk_mask;
                }
#if DEBUG || DEBUG_SIGNATURE_REFRESH
                log_debug(
                    "maintenance: %{dnsname}: at %{digest32h}.%{dnsname} NSEC3: mask=%p/%p (has signature: %i, "
                    "key-not-found: %i)",
                    zone->origin,
                    item->digest,
                    zone->origin,
                    nsec3_key_mask,
                    mctx.zsk_mask,
                    (item->rrsig_rrset != NULL),
                    delete_nsec3_rrsig);

                if(item->rrsig_rrset != NULL)
                {
                    zdb_resource_record_set_const_iterator rrsig_rrset_iter;
                    zdb_resource_record_set_const_iterator_init(item->rrsig_rrset, &rrsig_rrset_iter);
                    while(zdb_resource_record_set_const_iterator_has_next(&rrsig_rrset_iter))
                    {
                        const zdb_resource_record_data_t *rrsig_record = zdb_resource_record_set_const_iterator_next(&rrsig_rrset_iter);

                        const void                       *rdata = zdb_resource_record_data_rdata_const(rrsig_record);
                        uint16_t                          rdata_size = zdb_resource_record_data_rdata_size(rrsig_record);

                        log_debug("maintenance: %{dnsname}: at %{digest32h}.%{dnsname} RRSIG: %5i %T -> %T",
                                  zone->origin,
                                  item->digest,
                                  zone->origin,
                                  rrsig_get_key_tag_from_rdata(rdata, rdata_size),
                                  rrsig_get_valid_from_from_rdata(rdata, rdata_size),
                                  rrsig_get_valid_until_from_rdata(rdata, rdata_size));
                    }
                }
#endif
                if((nsec3_key_mask != 0) || delete_nsec3_rrsig)
                {
                    // generate signature or delete signatures

                    zone_diff_fqdn_rr_set *nsec3_diff_rrset = NULL;

#if NSEC3_MIN_TTL_ERRATA
                    int32_t ttl = mctx.zone->min_ttl_soa;
#else
                    int32_t ttl = mctx.zone->min_ttl;
#endif

#if DEBUG
                    zone_diff_fqdn *nsec3_diff_fqdn =
#endif
                        zone_diff_add_nsec3_ex(&diff, &mctx.zsks, mctx.zone->nsec.nsec3, item, ttl, &nsec3_diff_rrset, mctx.now, zone->sig_validity_regeneration_seconds);

                    if(nsec3_diff_rrset != NULL)
                    {
#if DEBUG
                        log_debug("maintenance: %{dnsname}: %{dnsname}: NSEC3 should be signed", zone->origin, nsec3_diff_fqdn->fqdn);
#endif
                        nsec3_diff_rrset->key_mask = nsec3_key_mask;

                        ptr_vector_append(&rrset_to_sign, nsec3_diff_rrset);
                        ++maintenance_generate_nsec3_rrsig_count;
                        actions_happened = true;
                    }
                }

                ++loop_iterations;
            }
            else // end of iteration
            {
                // if there is another chain, take its first digest (binary form)

                if(++zone->progressive_signature_update.chain_index < mctx.nsec3_chain_count)
                {
                    n3e = n3e->next;

                    if(n3e != NULL)
                    {
                        log_debug("maintenance: %{dnsname}: starting work on NSEC3 chain %i", zone->origin, zone->progressive_signature_update.chain_index);

                        nsec3_zone_item_t *first = nsec3_get_first(&mctx.zone->nsec.nsec3->items);
                        memcpy(from_digest, first->digest, first->digest[0] + 1);
                        from_digest[first->digest[0] + 1] = 0;
                        // from_fqdn_is_binary_digest = true;

                        break;
                    }
                    else
                    {
                        log_err("maintenance: %{dnsname}: NSEC3 chain smaller than expected", zone->origin);
#if DEBUG
                        log_debug("maintenance: %{dnsname}: no more chain after last label", zone->origin);
#endif
                        zone->progressive_signature_update.chain_index = -1;
                        last_label_of_zone_reached = true;
                        mctx.fqdn[0] = 0;

                        /************************************
                         * GOTO, breaking two loops at once.*
                         ************************************/

                        goto zdb_zone_maintenance_from_chain_iteration_loop_break; // nothing else
                    }
                }
                else
                {
                    zone->progressive_signature_update.chain_index = -1;
#if DEBUG
                    log_debug("maintenance: %{dnsname}: nothing to do after last label (NSEC3 rrsig to do: %i)", zone->origin, maintenance_generate_nsec3_rrsig_count);
#endif
                    last_label_of_zone_reached = true;
                    mctx.fqdn[0] = 0;

                    /************************************
                     * GOTO, breaking two loops at once.*
                     ************************************/

                    goto zdb_zone_maintenance_from_chain_iteration_loop_break; // nothing else
                }
            }
        } // for
    } // while

zdb_zone_maintenance_from_chain_iteration_loop_break:

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
    log_debug("maintenance: %{dnsname}: last_label_of_zone_reached: %i, rrset_to_sign contains %i items", zone->origin, last_label_of_zone_reached, ptr_vector_size(&rrset_to_sign));
#endif

    diff.nsec_change_count = maintenance_nsec_count;
    diff.nsec3_change_count = maintenance_nsec3_count;

    diff_has_changes |= maintenance_nsec_count > 0;
    diff_has_changes |= zone_diff_has_changes(&diff, &rrset_to_sign);

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
    log_debug(
        "maintenance: %{dnsname}: diff_has_changes: %i, last_label_of_zone_reached: %i, rrset_to_sign contains %i "
        "items",
        zone->origin,
        diff_has_changes,
        last_label_of_zone_reached,
        ptr_vector_size(&rrset_to_sign));
#endif

    if(diff_has_changes && !last_label_of_zone_reached)
    {
#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&remove, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-validate-sign: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&add, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};

            log_debug("before-validate-sign: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }
#endif
    }
    else // not diff_has_changes
    {
        log_debug("maintenance: %{dnsname}: no changes", zone->origin);
    }

    if(last_label_of_zone_reached)
    {
        log_debug("maintenance: %{dnsname}: closing edited chains", zone->origin);

        // add missing NSEC3PARAM
        // remove TYPE65282
        // update NSEC3
        // update signatures

        bool updated = false;

        if(zone_diff_will_have_rrset_type(apex, TYPE_NSEC3CHAINSTATE))
        {
#if DEBUG
            log_debug("maintenance: %{dnsname}: NSEC3CHAINSTATE will be present", zone->origin);
#endif
            // NSEC3PARAM

            zdb_resource_record_set_t *nsec3chainstate = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_NSEC3CHAINSTATE);

            if(nsec3chainstate != NULL)
            {
                zdb_resource_record_set_const_iterator iter;
                zdb_resource_record_set_const_iterator_init((zdb_resource_record_set_const_t *)nsec3chainstate, &iter);
                while(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    const zdb_resource_record_data_t *nsec3chainstate_record = zdb_resource_record_set_const_iterator_next(&iter);

                    // find the nsec3param matching nsec3chainstate in nsec3param_rrset
                    // if no match has been found, add a new nsec3param

                    zone_diff_label_rr *rr =
                        zone_diff_record_add(&diff, zone->apex, zone->origin, TYPE_NSEC3PARAM, 0, zdb_resource_record_data_rdata_size(nsec3chainstate_record) - 1, (void *)zdb_resource_record_data_rdata_const(nsec3chainstate_record));

                    // clears the opt-out flag that exists in the NSEC3CHAINSTATE record

                    uint8_t *flagsp = &((uint8_t *)rr->rdata)[1];
                    *flagsp = 0;
                }

                yassert(apex != NULL);
                zone_diff_fqdn_rr_set *nsec3chainstate_rrset = zone_diff_fqdn_rr_set_get(apex, TYPE_NSEC3CHAINSTATE);
                yassert(nsec3chainstate_rrset != NULL);
                zone_diff_fqdn_rr_set_set_state(nsec3chainstate_rrset, ZONE_DIFF_RR_REMOVE);
                ptr_vector_append(&rrset_to_sign, nsec3chainstate_rrset);

                zone_diff_fqdn_rr_set *nsec3paramqueued_rrset = zone_diff_fqdn_rr_set_get(apex, TYPE_NSEC3PARAMQUEUED);
                if(nsec3paramqueued_rrset != NULL)
                {
                    yassert(nsec3paramqueued_rrset != NULL);
                    zone_diff_fqdn_rr_set_set_state(nsec3paramqueued_rrset, ZONE_DIFF_RR_REMOVE);
                    ptr_vector_append(&rrset_to_sign, nsec3paramqueued_rrset);
                }

                zone_diff_fqdn_rr_set *nsec3param_rrset = zone_diff_fqdn_rr_set_get(apex, TYPE_NSEC3PARAM);
                if(nsec3param_rrset != NULL)
                {
                    yassert(nsec3param_rrset != NULL);
                    nsec3param_rrset->key_mask = zsk_mask;
                    ptr_vector_append(&rrset_to_sign, nsec3param_rrset);
                }

                ++maintenance_generate_nsec3param_rrsig_count;
                updated = true;
                actions_happened = true;
            }
        }

        if(zone_diff_will_have_rrset_type(apex, TYPE_NSECCHAINSTATE))
        {
            yassert(apex != NULL);
            zone_diff_fqdn_rr_set *nsecchainstate_rrset = zone_diff_fqdn_rr_set_get(apex, TYPE_NSECCHAINSTATE);
            yassert(nsecchainstate_rrset != NULL);
            zone_diff_fqdn_rr_set_set_state(nsecchainstate_rrset, ZONE_DIFF_RR_REMOVE);

            updated = true;
            nsecchainstate_changed = true;
            actions_happened = true;
        }

        if(updated)
        {
            diff_has_changes = true;

            zdb_zone_maintenance_nsec(&mctx, apex, NULL);
            zdb_zone_maintenance_nsec3(&mctx, apex);
        }
    }

    // if remove contains more than +- SOA and +- SOA RRSIG ...

    if(actions_happened)
    {
        uint32_t                    soa_serial = 0;
        int32_t                     soa_ttl;
        zdb_resource_record_data_t *soa_rr = zdb_resource_record_sets_find_soa_and_ttl(&zone->apex->resource_record_set, &soa_ttl);
        if(soa_rr != NULL)
        {
            // zone_diff_record_remove(&diff, zone->apex, zone->origin, TYPE_SOA, soa->ttl,
            // zdb_resource_record_data_rdata_size(soa), zdb_resource_record_data_rdata(soa));
            zone_diff_record_remove_automated(&diff, zone->apex, zone->origin, TYPE_SOA, soa_ttl, zdb_resource_record_data_rdata_size(soa_rr), zdb_resource_record_data_rdata(soa_rr));
            rr_soa_get_serial(zdb_resource_record_data_rdata(soa_rr), zdb_resource_record_data_rdata_size(soa_rr), &soa_serial);
        }

        log_debug(
            "maintenance: %{dnsname}: serial=%u actions: rrsig=%i nsec=%i nsec3=%i nsec3-rrsig=%i nsec3param=%i "
            "chain-state=%i",
            zone->origin,
            soa_serial,
            maintenance_rrsig_count,
            maintenance_nsec_count,
            maintenance_nsec3_count,
            maintenance_generate_nsec3_rrsig_count,
            maintenance_generate_nsec3param_rrsig_count,
            nsecchainstate_changed);

        if(ISOK(zone_diff_set_soa(&diff, zone->apex)))
        {
#if DEBUG
            log_debug1("maintenance: %{dnsname}: SOA should be signed", zone->origin);
#endif
            yassert(apex != NULL);
            zone_diff_fqdn_rr_set *soa_rrset = zone_diff_fqdn_rr_set_get(apex, TYPE_SOA);
            soa_rrset->key_mask = zsk_mask;
            yassert(soa_rrset != NULL);
            ptr_vector_append(&rrset_to_sign, soa_rrset);
        }

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&remove, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};
            log_debug("before-validate-sign: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&add, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};
            log_debug("before-validate-sign: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }
#endif
        /*
         * Does validation checks on the update.
         * Generates signatures for the specified RRSETs.
         */

        diff_has_changes = zdb_zone_maintenance_validate_sign_chain_store(&mctx, &diff, zone, &rrset_to_sign, &remove, &add);

        if(!diff_has_changes)
        {
            log_debug("maintenance: %{dnsname}: update contains nothing", zone->origin);
        }

#if ZDB_ZONE_MAINTENANCE_DETAILED_LOG
        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&remove); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&remove, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};
            log_debug("after-validate-sign: %{dnsname}: - %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&add); ++i)
        {
            zone_diff_label_rr *rr = (zone_diff_label_rr *)ptr_vector_get(&add, i);
            rdata_desc_t        rd = {rr->rtype, rr->rdata_size, rr->rdata};
            log_debug("after-validate-sign: %{dnsname}: + %{dnsname} %9i %{typerdatadesc} ; (W+R)", zone->origin, rr->fqdn, rr->ttl, &rd);
        }
#endif
    }

    ptr_vector_finalise(&rrset_to_sign);

    ptr_vector_finalise(&chain_candidates);
    ptr_vector_finalise(&candidates);
    ptr_vector_finalise(&rrset_vector);

    if(diff_has_changes)
    {
        log_debug("maintenance: %{dnsname}: writing and playing transaction", zone->origin);

        ret = dynupdate_diff_write_to_journal_and_replay(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER, &remove, &add);
    }
    else
    {
        ret = 0;
    }

    ptr_vector_finalise(&remove);
    ptr_vector_finalise(&add);

    if(ISOK(ret))
    {
        if(ret < 32768)
        {
            if(ret > 0)
            {
                double r = 32768.0;
                r /= ret;
                r *= labels_at_once;
                if(r > 65535.0)
                {
                    r = 65535;
                }
                mctx.zone->progressive_signature_update.labels_at_once = (uint16_t)r;
            }
            else
            {
                mctx.zone->progressive_signature_update.labels_at_once = U16_MAX;
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

    zdb_zone_maintenance_ctx_finalize(&mctx);

    zone_diff_finalize(&diff);

    if(last_label_of_zone_reached)
    {
        if(ISOK(ret))
        {
#if ZDB_ZONE_MAINTENANCE_SAME_PASS_CLOSE
            log_info("maintenance: %{dnsname}: done", zone->origin);

            ret = 0; // so the caller do not try to call again right away.
            mctx.fqdn[0] = '\0';
#else
            if(!diff_has_changes) // the end and no changes : closure must have happened
            {
                log_debug("maintenance: %{dnsname}: done, for now", zone->origin);

                ret = 0; // so the caller do not try to call again right away.
                mctx.fqdn[0] = '\0';
            }
            else
            {
                log_debug("maintenance: %{dnsname}: done, but will allow for one last pass", zone->origin);

                ret = 1; // else the potential closing of the chain will not happen
            }
#endif
        }
        else
        {
            if(ret != ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
            {
                log_warn("maintenance: %{dnsname}: reached the end, but with an error code: %r", zone->origin, ret);
            }
            else
            {
                log_debug("maintenance: %{dnsname}: reached the end, but zone must be stored", zone->origin);
            }
        }
    }
    else
    {
        if(ret == 0)
        {
            log_debug("maintenance: %{dnsname}: another pass will follow from %{dnsname}", zone->origin, mctx.fqdn);

            ret = 1; // else the remaining will be postponed for a while
        }
    }

    if(ISOK(ret))
    {
        size_t fqdn_len = dnsname_len(mctx.fqdn);

        if((fqdn_len <= from_fqdn_size) && (from_fqdn != NULL))
        {
            log_debug("maintenance: %{dnsname}: saving the next node (%{dnsname})", zone->origin, mctx.fqdn);
            memcpy(from_fqdn, mctx.fqdn, fqdn_len); // if from_fqdn == 0, fqdl_len == 0
            // from_fqdn_is_binary_digest = false;
        }
        else
        {
            log_debug(
                "maintenance: %{dnsname}: cannot save the next node (%{dnsname}) as buffer size is too small (%llu < "
                "%llu)",
                zone->origin,
                mctx.fqdn,
                from_fqdn_size,
                fqdn_len);
        }
    }
    else
    {
        log_debug(
            "maintenance: %{dnsname}: an error state occurred (%r), keeping previous state (%{dnsname}), ignoring next "
            "state (%{dnsname})",
            zone->origin,
            ret,
            from_fqdn,
            mctx.fqdn);
    }

    int64_t stop_time = timeus();

    double  dt = stop_time - start_time;
    if(dt < 0)
    {
        dt = 0;
    }
    dt /= ONE_SECOND_US_F;

    log_debug("rrsig: %{dnsname}: %r (%.3fs)", zone->origin, ret, dt);

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

ya_result zdb_zone_maintenance(zdb_zone_t *zone)
{
    ya_result ret;
    uint8_t  *prev_fqdn;
    int8_t    prev_chain_index;
    uint8_t   in_out_fqdn[DOMAIN_LENGTH_MAX];

    if(zone->progressive_signature_update.current_fqdn != NULL)
    {
        log_debug("maintenance: %{dnsname}: resuming from %{dnsname}", zone->origin, zone->progressive_signature_update.current_fqdn);

        dnsname_copy(in_out_fqdn, zone->progressive_signature_update.current_fqdn);
        prev_fqdn = zone->progressive_signature_update.current_fqdn;
        prev_chain_index = zone->progressive_signature_update.chain_index;
        // dnsname_zfree(zone->progressive_signature_update.current_fqdn);
        zone->progressive_signature_update.current_fqdn = NULL;
    }
    else
    {
        prev_fqdn = NULL;
        prev_chain_index = -1;
        log_info("maintenance: %{dnsname}: zone maintenance started", zone->origin);
        in_out_fqdn[0] = 0;
#if DEBUG
        memset(in_out_fqdn, 0, sizeof(in_out_fqdn));
#endif
        zone->progressive_signature_update.current_fqdn = NULL;
        zone->progressive_signature_update.chain_index = -1;
#if DEBUG
        log_debug("maintenance: %{dnsname}: interval=%is jitter=%is regeneration=%is (DEBUG)", zone->origin, zone->sig_validity_interval_seconds, zone->sig_validity_jitter_seconds, zone->sig_validity_regeneration_seconds);
#endif
    }

    ret = zdb_zone_maintenance_from(zone, in_out_fqdn, sizeof(in_out_fqdn), ZDB_MAINTENANCE_BATCH_TIME_US_MAX, ZDB_ZONE_MAINTENANCE_RRSIG_COUNT_THRESHOLD);

    if(in_out_fqdn[0] != 0)
    {
        if(ISOK(ret))
        {
            zone->progressive_signature_update.current_fqdn = dnsname_zdup(in_out_fqdn);
            if(prev_fqdn != NULL)
            {
                dnsname_zfree(prev_fqdn);
                prev_fqdn = NULL;
            }

            log_debug("maintenance: %{dnsname}: pausing at %{dnsname} (%r)", zone->origin, zone->progressive_signature_update.current_fqdn, ret);
        }
        else
        {
            if(prev_fqdn != NULL)
            {
                zone->progressive_signature_update.current_fqdn = prev_fqdn;
                zone->progressive_signature_update.chain_index = prev_chain_index;
                prev_fqdn = NULL;
                // prev_chain_index = -1;
                log_debug("maintenance: %{dnsname}: pausing at %{dnsname} (%r) (may try again)", zone->origin, zone->progressive_signature_update.current_fqdn, ret);
            }
            else
            {
                log_debug("maintenance: %{dnsname}: pausing (%r) (may try again)", zone->origin, ret);
            }
        }
    }
    else
    {
        if(prev_fqdn != NULL)
        {
            dnsname_zfree(prev_fqdn);
            prev_fqdn = NULL;
        }

        log_debug("maintenance: %{dnsname}: done (%r)", zone->origin, ret);
    }

    if(ret == 0)
    {
        log_info("maintenance: %{dnsname}: zone maintenance finished", zone->origin);
    }

    return ret;
}

ya_result zdb_zone_sign(zdb_zone_t *zone)
{
    zone->progressive_signature_update.current_fqdn = NULL;
    zone->progressive_signature_update.labels_at_once = 0;
    zone->progressive_signature_update.chain_index = -1;
    ya_result ret = zdb_zone_maintenance_from(zone, NULL, 0, INT64_MAX, INT32_MAX);
    return ret;
}

/** @} */

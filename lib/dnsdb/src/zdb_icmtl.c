/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 * ICMTL is actually INCREMENTAL.
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
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include <dnscore/format.h>

#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/ptr_treemap.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/serial.h>

#include "dnsdb/zdb_icmtl.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_journal.h"
#include "dnsdb/nsec3.h"
#include "dnsdb/nsec.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/dnssec.h"

#include "dnsdb/nsec_chain_replay.h"
#include "dnsdb/nsec3_chain_replay.h"

#ifndef HAS_DYNUPDATE_DIFF_ENABLED
#error "HAS_DYNUPDATE_DIFF_ENABLED not defined"
#endif

extern logger_handle_t *g_database_logger;
#define MODULE_MSG_HANDLE          g_database_logger

#define ICMTL_DUMP_JOURNAL_RECORDS 0

#if ICMTL_DUMP_JOURNAL_RECORDS
#pragma message("WARNING: ICMTL_DUMP_JOURNAL_RECORDS enabled !")
#endif

#define ZDB_ICMTL_REPLAY_GATHER               0
#define ZDB_ICMTL_REPLAY_COMMIT               1
#define ZDB_ICMTL_REPLAY_COMMIT_AND_STOP      3
#define ZDB_ICMTL_REPLAY_STOP                 4
#define ZDB_ICMTL_REPLAY_SHUTDOWN_POLL_PERIOD 64
#define ZDB_ICMTL_REPLAY_BUFFER_SIZE          4096

static ya_result zdb_icmtl_replay_commit_label_forall_nsec3_del_cb(zdb_rr_label_t *rr_label, const uint8_t *rr_label_fqdn, void *data)
{
    (void)rr_label;
    chain_replay_t *nsec3replayp = (chain_replay_t *)data;
    ya_result       ret = nsec3replayp->vtbl->record_del(nsec3replayp, rr_label_fqdn, TYPE_NONE, NULL);
    return ret;
}

static ya_result zdb_icmtl_replay_commit_label_forall_nsec3_add_cb(zdb_rr_label_t *rr_label, const uint8_t *rr_label_fqdn, void *data)
{
    (void)rr_label;
    chain_replay_t *nsec3replayp = (chain_replay_t *)data;
    ya_result       ret = nsec3replayp->vtbl->record_add(nsec3replayp, rr_label_fqdn, TYPE_NONE, NULL);
    return ret;
}

static void zdb_icmtl_replay_remove_keep_flag(ptr_treemap_t *marked_labels, const uint8_t *origin)
{
    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(marked_labels, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
        if(node->value != (void *)(intptr_t)-1)
        {
            zdb_rr_label_t *rr_label = (zdb_rr_label_t *)node->value;

            zdb_rr_label_flag_and(rr_label, ~ZDB_RR_LABEL_KEEP);

            log_debug1("journal: %{dnsname}: un-keep @%p", origin, rr_label);
        }
        dnsname_zfree(node->key);
    }
}

void zdb_icmtl_replay_commit_state_init(zdb_icmtl_replay_commit_state *state)
{
    state->dnskey_added = 0;
    state->dnskey_removed = 0;
#if DNSCORE_HAS_EVENT_DYNAMIC_MODULE
    ptr_vector_init_empty(&state->dnskey_added_list);
    ptr_vector_init_empty(&state->dnskey_removed_list);
#endif
}

void zdb_icmtl_replay_commit_state_finalize(zdb_icmtl_replay_commit_state *state)
{
#if DNSCORE_HAS_EVENT_DYNAMIC_MODULE
    ptr_vector_finalise(&state->dnskey_added_list);
    ptr_vector_finalise(&state->dnskey_removed_list);
#else
    (void)state;
#endif
}

ya_result zdb_icmtl_replay_commit_ex(zdb_zone_t *zone, input_stream_t *is, zdb_icmtl_replay_commit_state *out_state)
{
    ya_result ret;
    /*
     * 0: DELETE, 1: ADD
     * The mode is switched every time an SOA is found.
     */

    yassert(zdb_zone_islocked(zone) && (out_state != NULL));

    yassert(bytearray_input_stream_is_instance_of(is));

#if ZDB_HAS_NSEC3_SUPPORT
    bool has_nsec3 = zdb_zone_is_nsec3(zone);
#endif

#if ZDB_HAS_NSEC_SUPPORT
    bool has_nsec = zdb_zone_is_nsec(zone);
#endif

#if ZDB_HAS_NSEC3_SUPPORT && ZDB_HAS_NSEC_SUPPORT
    if(has_nsec3 && has_nsec)
    {
        log_err("journal: %{dnsname}: zone has both NSEC and NSEC3 status, which is not supported by YADIFA", zone->origin);
        return ERROR; /// @note this is not entirely true anymore
    }
#endif

    uint8_t               mode = 1; // the first SOA will switch the mode to delete
    int32_t               changes = 0;

    zdb_ttlrdata          ttlrdata;
    dns_resource_record_t rr;
    dns_resource_record_init(&rr);
    const uint8_t    *fqdn = rr.name;
    dnslabel_vector_t labels;

    ttlrdata.next = NULL;

    /*
     * The plan for NSEC3 :
     * Store the fqdn + type class ttl rdata in collections
     * => the delete collection
     * => the add collection
     * Then there is the NSEC3 covered labels: keep a reference to them for later
     *
     * When a pass of SOA-/SOA+ has finished:
     * _ replace the NSEC3 in both collections (reading from delete)
     * _ delete NSEC3 to delete
     * _ add NSEC3 to add
     *
     * _ and finally update the NSEC3 for the labels kept above
     */

#if ZDB_HAS_NSEC3_SUPPORT
    chain_replay_t nsec3replay;
    nsec3_chain_replay_init(&nsec3replay, zone);
#endif

#if ZDB_HAS_NSEC_SUPPORT
    chain_replay_t nsecreplay;
    nsec_chain_replay_init(&nsecreplay, zone);
#endif

    zdb_icmtl_replay_commit_state_init(out_state);

    /*
     * At this point : the next record, if it exists AND is not an SOA , has to be deleted
     *
     */

    // mark the labels to keep no matter what

    uint32_t      is_offset = bytearray_input_stream_offset(is);
    ptr_treemap_t marked_labels = PTR_TREEMAP_DNSNAME_EMPTY;

    for(;;)
    {
        /*
         * read the full record
         *
         * == 0 : no record (EOF)
         *  < 0 : failed
         */

        if((ret = dns_resource_record_read(&rr, is)) <= 0)
        {
            if(ISOK(ret))
            {
                log_debug("journal: %{dnsname}: reached the end of the journal page", zone->origin);
            }
            else
            {
                log_err("journal: %{dnsname}: broken journal: %r", zone->origin, ret);
                logger_flush(); // broken journal (bad, keep me)
            }

            break;
        }

        if(rr.tctr.rtype == TYPE_SOA)
        {
            mode ^= 1;
            continue;
        }

        if(mode != 0)
        {
            // add
            // grab the fqdn
            // find the label, if it exists mark it and keep the mark

            if(rr.tctr.rtype != TYPE_NSEC3)
            {
                if((rr.tctr.rtype != TYPE_RRSIG) || ((rr.tctr.rtype == TYPE_RRSIG) && (rrsig_get_type_covered_from_rdata(rr.rdata, rr.rdata_size) != TYPE_NSEC3)))
                {
                    ptr_treemap_node_t *node = ptr_treemap_insert(&marked_labels, rr.name);

                    if(node->value == NULL)
                    {
                        int32_t         top = dnsname_to_dnslabel_vector(rr.name, labels);

                        zdb_rr_label_t *rr_label = zdb_rr_label_find_exact(zone->apex, labels, (top - zone->origin_vector.size) - 1);

                        if(rr_label != NULL)
                        {
#if DEBUG
                            log_debug1("journal: %{dnsname}: keep %{dnsname} (@%p)", zone->origin, fqdn, rr_label);
#endif
                            node->value = rr_label;
                            zdb_rr_label_flag_or(rr_label, ZDB_RR_LABEL_KEEP);
                        }
                        else
                        {
#if DEBUG
                            log_debug1("journal: %{dnsname}: no-keep %{dnsname} because it's new", zone->origin, fqdn);
#endif
                            node->value = (void *)(intptr_t)-1;
                        }

                        node->key = dnsname_zdup(rr.name);
                    }
                }
#if DEBUG
                else
                {
                    log_debug1("journal: %{dnsname}: cannot-keep %{dnsname} RRSIG on NSEC3", zone->origin, fqdn);
                }
#endif
            }
#if DEBUG
            else
            {
                log_debug1("journal: %{dnsname}: cannot-keep %{dnsname} NSEC3", zone->origin, fqdn);
            }
#endif
        }
        else
        {
            // del
            // ignore
        }
    }

    // relevant labels have been marked

    bytearray_input_stream_set_offset(is, is_offset);

    bool did_remove_soa = false;

    mode = 1;

    // something has to be committed

    for(;;)
    {
        /*
         * read the full record
         *
         * == 0 : no record (EOF)
         *  < 0 : failed
         */

        if(dns_resource_record_read(&rr, is) <= 0)
        {
            log_debug("journal: %{dnsname}: reached the end of the journal page", zone->origin);
            break;
        }

        ttlrdata.ttl = ntohl(rr.tctr.ttl);
        ttlrdata.rdata_pointer = rr.rdata;
        ttlrdata.rdata_size = rr.rdata_size;

        /*
         * Stop at the SOA
         */

        if(rr.tctr.rtype == TYPE_SOA)
        {
            mode ^= 1;
        }

        if(!did_remove_soa)
        {
#if DEBUG
            log_debug("journal: %{dnsname}: removing obsolete SOA", zone->origin);
#endif

            if(FAIL(ret = zdb_resource_record_sets_delete_type(&zone->apex->resource_record_set, TYPE_SOA)))
            {
                /**
                 * complain
                 */

                log_err("journal: %{dnsname}: removing current SOA gave an error: %r", zone->origin, ret);

                /* That's VERY bad ... */

                changes = ret;

                break;
            }

            did_remove_soa = true;
        }

        int32_t top = dnsname_to_dnslabel_vector(fqdn, labels);

        if(mode == 0)
        {
            /*
             * "TO DEL" record
             */

#if ICMTL_DUMP_JOURNAL_RECORDS
            rdata_desc_t type_len_rdata = {rr.tctr.qtype, rr.rdata_size, rr.rdata};
            log_debug("journal: del %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
            logger_flush();
#endif
            bool handled_by_chain = false;

#if ZDB_HAS_NSEC3_SUPPORT

            // 0 : proceed
            // 1 : ignore
            // ? : error

            handled_by_chain = (nsec3replay.vtbl->record_del(&nsec3replay, fqdn, rr.tctr.rtype, &ttlrdata) != 0);

#if DEBUG
            log_debug3("journal: %{dnsname}: DEL: %{dnsname} %{dntype} handled_by_chain=%i", zone->origin, fqdn, &rr.tctr.rtype, handled_by_chain);
#endif

            if(handled_by_chain)
            {
                ++changes;
            }
            else
            {
                if(top > zone->origin_vector.size)
                {
                    const uint8_t *above_fqdn = fqdn;
                    for(int_fast32_t i = 1; i < top - zone->origin_vector.size; ++i)
                    {
                        zdb_rr_label_t *above = zdb_rr_label_find_exact(zone->apex, &labels[i], top - zone->origin_vector.size - 1 - i);
                        if(above != NULL)
                        {
                            if(zdb_resource_record_sets_isempty(&above->resource_record_set))
                            {
                                break;
                            }
                        }

                        above_fqdn += above_fqdn[0] + 1;
                        nsec3replay.vtbl->record_del(&nsec3replay, above_fqdn, TYPE_NONE, NULL);
                    }

                    zdb_rr_label_t *rr_label = zdb_rr_label_find_exact(zone->apex, labels, (top - zone->origin_vector.size) - 1);

                    if(rr_label != NULL)
                    {
                        zdb_rr_label_forall_children_of_fqdn(rr_label, fqdn, zdb_icmtl_replay_commit_label_forall_nsec3_del_cb, &nsec3replay);
                    }
                }
            }
#endif
#if ZDB_HAS_NSEC_SUPPORT

            // 0 : proceed
            // 1 : ignore
            // ? : error

            if(!handled_by_chain && (handled_by_chain = nsecreplay.vtbl->record_del(&nsecreplay, fqdn, rr.tctr.rtype, &ttlrdata) != 0))
            {
                ++changes;
            }
            // else
#endif
            if(!handled_by_chain)
            {
                switch(rr.tctr.rtype)
                {
                    case TYPE_SOA:
                    {
                        rdata_desc_t rdata = {TYPE_SOA, ttlrdata.rdata_size, ttlrdata.rdata_pointer};
                        log_debug("journal: %{dnsname}: SOA: del %{dnsname} %{typerdatadesc}", zone->origin, fqdn, &rdata);

                        int32_t m1 = (top - zone->origin_vector.size) - 1;

                        if(m1 == -1)
                        {
                            if(FAIL(ret = zdb_resource_record_sets_delete_exact_record(&zone->apex->resource_record_set, TYPE_SOA, &ttlrdata))) /* FB done, APEX : no delegation, source is the journal */
                            {
                                if(!did_remove_soa)
                                {
                                    log_err("journal: %{dnsname}: SOA: %r", zone->origin, ret);
                                }
                            }
                        }
                        else
                        {
                            if(FAIL(ret = zdb_rr_label_delete_record_exact(zone, labels, (top - zone->origin_vector.size) - 1, rr.tctr.rtype,
                                                                           &ttlrdata))) // source is journal
                            {
                                if(!did_remove_soa)
                                {
                                    log_err("journal: %{dnsname}: SOA: (2) %r", zone->origin, ret);
                                }
                            }
                        }
                        break;
                    }

                    case TYPE_NSEC3:
                    {
                        break;
                    }

                    case TYPE_DNSKEY:
                    {
                        ++out_state->dnskey_removed;

                        dnskey_t *key = NULL;

                        // add the public key to the keystore

                        ya_result ret = dnskey_new_from_rdata(rr.rdata, rr.rdata_size, zone->origin, &key);

                        if(ISOK(ret))
                        {
                            /*
#if HAS_EVENT_DYNAMIC_MODULE
                            if(dynamic_module_dnskey_interface_chain_available())
                            {
                                dynamic_module_on_dnskey_publish(key);
                            }
#endif
                             */
                            dnskey_state_disable(key, DNSKEY_KEY_IS_IN_ZONE);

#if HAS_EDF
#pragma message("TODO: keys should probably not be removed from the keyring.  Instead they should be marked as removed")
#endif

                            if(dnssec_keystore_remove_key(key))
                            {
#if DEBUG
                                log_debug(
                                    "journal: %{dnsname}: deleted key from record: K%{dnsname}+%03d+%05d/%d P=%T A=%T "
                                    "I=%T D=%T",
                                    zone->origin,
                                    dnskey_get_domain(key),
                                    dnskey_get_algorithm(key),
                                    dnskey_get_tag_const(key),
                                    ntohs(dnskey_get_flags(key)),
                                    dnskey_get_publish_epoch(key),
                                    dnskey_get_activate_epoch(key),
                                    dnskey_get_inactive_epoch(key),
                                    dnskey_get_delete_epoch(key));
#endif
                            }
                            else
                            {
#if DEBUG
                                log_debug(
                                    "journal: %{dnsname}: deleted key from record: K%{dnsname}+%03d+%05d/%d P=%T A=%T "
                                    "I=%T D=%T (not in keyring)",
                                    zone->origin,
                                    dnskey_get_domain(key),
                                    dnskey_get_algorithm(key),
                                    dnskey_get_tag_const(key),
                                    ntohs(dnskey_get_flags(key)),
                                    dnskey_get_publish_epoch(key),
                                    dnskey_get_activate_epoch(key),
                                    dnskey_get_inactive_epoch(key),
                                    dnskey_get_delete_epoch(key));
#endif
                                dnskey_release(key);
                            }
                        }
                        else
                        {
                            // could not generate key
                            log_err("journal: %{dnsname}: could not make key from DNSKEY record: %r", zone->origin, ret);
                        }
                    }
                        FALLTHROUGH // fallthrough

                            default:
                        {
#if 0
                        /**
                         * @note 20180704 edf -- This is certainly not the place to check for an NSEC3 record.  Besides ...
                         *                       This assumes that if a NSEC3 record is not optout, then the zone is not optout.
                         *                       But I think it should be: if there is an optout, it's optout.  Optin should be broken.
                         *                       And none of this matters.  Optout/optin should be configured or guessed when loading the zone.
                         */

                        // NSEC3
                        if(rr.tctr.qtype == TYPE_NSEC3)
                        {
                            if(!NSEC3_RDATA_IS_OPTOUT(rr.rdata))
                            {
                                zone->_flags &= ~ZDB_ZONE_HAS_OPTOUT_COVERAGE;
                            }
                        }
#endif
                            if(FAIL(ret = zdb_rr_label_delete_record_exact(zone, labels, (top - zone->origin_vector.size) - 1, rr.tctr.rtype,
                                                                           &ttlrdata))) // source is journal
                            {
                                // signatures can be removed automatically by maintenance

                                if((rr.tctr.rtype != TYPE_RRSIG) && (ret != ZDB_ERROR_KEY_NOTFOUND))
                                {
                                    log_err("journal: %{dnsname}: del %{dnsrr}", zone->origin, &rr);
                                    log_err("journal: %{dnsname}: %{dnstype}: %r", zone->origin, &rr.tctr.rtype, ret);
                                }
                                else
                                {
                                    log_debug("journal: %{dnsname}: del %{dnsrr}", zone->origin, &rr);
                                    log_debug("journal: %{dnsname}: %{dnstype}: %r", zone->origin, &rr.tctr.rtype, ret);
                                }
                            }
                        }
                }
            }
        }
        else
        {
            /*
             * "TO ADD" record
             */

            bool handled_by_chain = false;

            if(rr.tctr.rtype == TYPE_SOA)
            {
                rr_soa_get_minimumttl(rr.rdata, rr.rdata_size, &zone->min_ttl);
#if NSEC3_MIN_TTL_ERRATA
                zone->min_ttl_soa = MIN((int32_t)ntohl(rr.tctr.ttl), zone->min_ttl);
#else
                zone->min_ttl_soa = zone->min_ttl;
#endif
            }

#if DNSCORE_HAS_DNSSEC_SUPPORT
            if(rr.tctr.rtype == TYPE_RRSIG)
            {
                // get expiration, update resignature alarm if needed

                int32_t rrsig_expiration = rrsig_get_valid_until_from_rdata(rr.rdata, rr.rdata_size);

                if(zone->progressive_signature_update.earliest_signature_expiration > rrsig_expiration)
                {
                    zone->progressive_signature_update.earliest_signature_expiration = rrsig_expiration;
                }
            }
#endif

#if ZDB_HAS_NSEC3_SUPPORT

            // returns the number of changes taken into account (0 or 1)
            // 0 : proceed
            // 1 : ignore
            // ? : error

            handled_by_chain = (nsec3replay.vtbl->record_add(&nsec3replay, fqdn, rr.tctr.rtype, &ttlrdata) != 0);

#if DEBUG
            log_debug3("journal: %{dnsname}: ADD: %{dnsname} %{dnstype} handled_by_chain=%i", zone->origin, fqdn, &rr.tctr.rtype, handled_by_chain);
#endif

            if(handled_by_chain)
            {
                ++changes;
            }
            else
            {
                if((top > zone->origin_vector.size) && (rr.tctr.rtype != TYPE_NSEC3) && ((rr.tctr.rtype != TYPE_RRSIG) || ((rr.tctr.rtype == TYPE_RRSIG) && (GET_U16_AT_P(ZDB_RECORD_PTR_RDATAPTR(&ttlrdata)) != TYPE_NSEC3))))
                {
                    const uint8_t *above_fqdn = fqdn;
                    for(int_fast32_t i = 1; i < top - zone->origin_vector.size; ++i)
                    {
                        zdb_rr_label_t *above = zdb_rr_label_find_exact(zone->apex, &labels[i], top - zone->origin_vector.size - 1 - i);
                        if(above != NULL)
                        {
                            if(!zdb_resource_record_sets_set_isempty(&above->resource_record_set))
                            {
                                break;
                            }
                        }

                        above_fqdn += above_fqdn[0] + 1;
                        nsec3replay.vtbl->record_add(&nsec3replay, above_fqdn, TYPE_NONE, NULL);
                    }

                    zdb_rr_label_t *rr_label = zdb_rr_label_find_exact(zone->apex, labels, (top - zone->origin_vector.size) - 1);
                    if(rr_label != NULL)
                    {
                        zdb_rr_label_forall_children_of_fqdn(rr_label, fqdn, zdb_icmtl_replay_commit_label_forall_nsec3_add_cb, &nsec3replay);
                    }
                }
            }
#endif
#if ZDB_HAS_NSEC_SUPPORT

            // returns the number of changes taken into account (0 or 1)
            // 0 : proceed
            // 1 : ignore
            // ? : error

            if(!handled_by_chain && (handled_by_chain = (nsecreplay.vtbl->record_add(&nsecreplay, fqdn, rr.tctr.rtype, &ttlrdata) != 0)))
            {
                ++changes;
            }
            // else
#endif
#if 0
#pragma message("TODO: WHY IS IT UNDER THAT CONDITION ? (when is it not true?)")
#endif
            if(!handled_by_chain)
            {
                switch(rr.tctr.rtype)
                {
#if ZDB_HAS_NSEC3_SUPPORT
                    case TYPE_NSEC3CHAINSTATE:
                    {
                        // create chain if missing ...

                        nsec3_zone_add_from_rdata(zone, rr.rdata_size, rr.rdata);

                        // add the record

                        zdb_resource_record_data_t *packed_ttlrdata = zdb_resource_record_data_new_instance(rr.rdata_size);

                        MEMCOPY(zdb_resource_record_data_rdata(packed_ttlrdata), rr.rdata, rr.rdata_size);
                        zdb_zone_record_add(zone, labels, top, rr.tctr.rtype, ttlrdata.ttl,
                                            packed_ttlrdata); // class is implicit, flow verified

                        break;
                    }
#endif // ZDB_HAS_NSEC3_SUPPORT

                    case TYPE_DNSKEY:
                    {
                        ++out_state->dnskey_added;

                        dnskey_t *key = NULL;

                        // add the public key to the keystore

                        ya_result ret = dnskey_new_from_rdata(rr.rdata, rr.rdata_size, zone->origin, &key);

                        if(ISOK(ret))
                        {
                            if(dnssec_keystore_add_key(key))
                            {
#if DEBUG
                                log_debug(
                                    "journal: %{dnsname}: added key from record: K%{dnsname}+%03d+%05d/%d P=%T A=%T "
                                    "I=%T D=%T",
                                    zone->origin,
                                    dnskey_get_domain(key),
                                    dnskey_get_algorithm(key),
                                    dnskey_get_tag_const(key),
                                    ntohs(dnskey_get_flags(key)),
                                    dnskey_get_publish_epoch(key),
                                    dnskey_get_activate_epoch(key),
                                    dnskey_get_inactive_epoch(key),
                                    dnskey_get_delete_epoch(key));
#endif
                                dnskey_state_enable(key, DNSKEY_KEY_IS_IN_ZONE);
                            }
                            else
                            {
#if DEBUG
                                log_debug(
                                    "journal: %{dnsname}: added key from record: K%{dnsname}+%03d+%05d/%d P=%T A=%T "
                                    "I=%T D=%T (in keyring already)",
                                    zone->origin,
                                    dnskey_get_domain(key),
                                    dnskey_get_algorithm(key),
                                    dnskey_get_tag_const(key),
                                    ntohs(dnskey_get_flags(key)),
                                    dnskey_get_publish_epoch(key),
                                    dnskey_get_activate_epoch(key),
                                    dnskey_get_inactive_epoch(key),
                                    dnskey_get_delete_epoch(key));
#endif
                                dnskey_release(key);
                            }
                        }
                        else
                        {
                            // could not generate key
                            log_err("journal: %{dnsname}: could not make key from DNSKEY record: %r", zone->origin, ret);
                        }
                    }
                        FALLTHROUGH // fall through

                            default:
                        {
                            zdb_resource_record_data_t *packed_ttlrdata = zdb_resource_record_data_new_instance(rr.rdata_size);

                            MEMCOPY(zdb_resource_record_data_rdata(packed_ttlrdata), rr.rdata, rr.rdata_size);

#if ICMTL_DUMP_JOURNAL_RECORDS
                            rdata_desc_t type_len_rdata = {rr.tctr.qtype, rr.rdata_size, zdb_resource_record_data_rdata(packed_ttlrdata)};
                            log_debug("journal: add %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
                            logger_flush();
#endif
                            if(rr.tctr.rtype == TYPE_SOA)
                            {
                                rr_soa_get_serial(zdb_resource_record_data_rdata(packed_ttlrdata), zdb_resource_record_data_rdata_size(packed_ttlrdata), &out_state->end_serial);
                                rdata_desc_t rdata = {TYPE_SOA, zdb_resource_record_data_rdata_size(packed_ttlrdata), zdb_resource_record_data_rdata(packed_ttlrdata)};
                                log_debug("journal: %{dnsname}: SOA: add %{dnsname} %{typerdatadesc}", zone->origin, fqdn, &rdata);
                            }

                            zdb_zone_record_add(zone, labels, top, rr.tctr.rtype, ttlrdata.ttl,
                                                packed_ttlrdata); // class is implicit, flow verified
                        }
                }
            }
        } // end if ADD

        changes++;
    }

    /*
     * Yes, I know.  If 2^32 changes (add batch + del batch) occurs then it will be seen as an error ...
     */

    if(ISOK(changes))
    {
#if ZDB_HAS_NSEC3_SUPPORT && ZDB_HAS_NSEC_SUPPORT

        if(has_nsec3 && has_nsec)
        {
            log_warn(
                "journal: %{dnsname}: both NSEC3 and NSEC operations happened, which is not supported by YADIFA. "
                "Keeping the original one.",
                zone->origin);

            has_nsec3 = zdb_zone_is_nsec3(zone);
            has_nsec = zdb_zone_is_nsec(zone);

            log_debug("journal: %{dnsname}: has NSEC3: %i, has NSEC: %i", zone->origin, has_nsec3, has_nsec);
        }
#endif

#if ZDB_HAS_NSEC3_SUPPORT
        nsec3replay.vtbl->execute(&nsec3replay);
#endif

#if ZDB_HAS_NSEC_SUPPORT
        nsecreplay.vtbl->execute(&nsecreplay);
#endif
        zdb_zone_set_status(zone, ZDB_ZONE_STATUS_MODIFIED);
    }

#if ZDB_HAS_NSEC3_SUPPORT
    // has_nsec3 = zdb_zone_is_nsec3(zone);
    nsec3replay.vtbl->finalise(&nsec3replay);
#endif
#if ZDB_HAS_NSEC_SUPPORT
    // has_nsec = zdb_zone_is_nsec(zone);
    nsecreplay.vtbl->finalise(&nsecreplay);
#endif

    zdb_icmtl_replay_remove_keep_flag(&marked_labels, zone->origin);

    ptr_treemap_finalise(&marked_labels);

    dns_resource_record_clear(&rr);

    return changes;
}

ya_result zdb_icmtl_replay_commit(zdb_zone_t *zone, input_stream_t *is, uint32_t *out_serial_after_replayp)
{
    ya_result                     ret;
    zdb_icmtl_replay_commit_state state;
    ret = zdb_icmtl_replay_commit_ex(zone, is, &state);
    if(ISOK(ret) && (out_serial_after_replayp != NULL))
    {
        *out_serial_after_replayp = state.end_serial;
    }
    zdb_icmtl_replay_commit_state_finalize(&state);
    return ret;
}

/*
 * Replay the incremental stream
 */

ya_result zdb_icmtl_replay(zdb_zone_t *zone)
{
    ya_result return_value;
    uint32_t  serial;

    zdb_zone_double_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);

    return_value = zdb_zone_getserial(zone, &serial); // zone is locked

    if(FAIL(return_value))
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);

        log_err("journal: %{dnsname}: error reading serial for zone: %r", zone->origin, return_value);

        return return_value;
    }

    input_stream_t is;

#if ICMTL_DUMP_JOURNAL_RECORDS
    log_debug("journal: zdb_icmtl_replay(%{dnsname})", zone->origin);
    logger_flush();
#endif

    uint32_t first_serial;
    uint32_t last_serial;

    if(FAIL(return_value = zdb_zone_journal_get_serial_range(zone, &first_serial, &last_serial)))
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);

        if(return_value == ZDB_ERROR_ICMTL_NOTFOUND)
        {
            return_value = SUCCESS;
        }
        else
        {
            log_err("journal: %{dnsname}: error opening journal for zone: %r", zone->origin, return_value);
        }

        return return_value;
    }

    log_debug("journal: %{dnsname}: zone serial is %i, journal covers serials from %i to %i", zone->origin, serial, first_serial, last_serial);

    if(last_serial == serial)
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);

        log_debug("journal: %{dnsname}: nothing to read from the journal", zone->origin);
        return 0;
    }

    if(serial_lt(serial, first_serial))
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);

        log_warn("journal: %{dnsname}: first serial from the journal is after the zone (deleting journal)", zone->origin);
        // should invalidate the journal
        zdb_zone_journal_delete(zone);
        return 0;
    }

    if(serial_gt(serial, last_serial))
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);

        log_warn("journal: %{dnsname}: last serial from the journal is before the zone (deleting journal)", zone->origin);
        // should invalidate the journal
        zdb_zone_journal_delete(zone);
        return 0;
    }

    if(FAIL(return_value = zdb_zone_journal_get_ixfr_stream_at_serial(zone, serial, &is, NULL)))
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);

        log_err("journal: %{dnsname}: error reading journal from serial %d: %r", zone->origin, serial, return_value);

        return return_value;
    }

    log_debug("journal: %{dnsname}: replaying from serial %u", zone->origin, serial);

    buffer_input_stream_init(&is, &is, ZDB_ICMTL_REPLAY_BUFFER_SIZE);

    uint16_t shutdown_test_countdown = ZDB_ICMTL_REPLAY_SHUTDOWN_POLL_PERIOD;

    uint32_t current_serial = serial;

    /*
     * Read all records from [ SOA ... SOA ... [ SOA in memory
     */

    output_stream_t       baos;
    input_stream_t        bais;
    dns_resource_record_t rr;

    int                   baos_rr_count = 0;
    int                   baos_soa_count = 0;

    bool                  was_nsec3 = zdb_zone_is_nsec3(zone);

    bytearray_output_stream_init_ex(&baos, NULL, ZDB_ICMTL_REPLAY_BUFFER_SIZE, BYTEARRAY_DYNAMIC);
    dns_resource_record_init(&rr);

    // 0: gather, 1: commit, 2: commit & stop

    for(int_fast32_t replay_state = ZDB_ICMTL_REPLAY_GATHER; replay_state != ZDB_ICMTL_REPLAY_COMMIT_AND_STOP;)
    {
        // ensure it's not supposed to shut down (every few iterations)

        if(--shutdown_test_countdown <= 0)
        {
            if(dnscore_shuttingdown())
            {
                return_value = STOPPED_BY_APPLICATION_SHUTDOWN;
                break;
            }

            shutdown_test_countdown = ZDB_ICMTL_REPLAY_SHUTDOWN_POLL_PERIOD;
        }

        // read the next record

        if((return_value = dns_resource_record_read(&rr, &is)) <= 0)
        {
            if(ISOK(return_value))
            {
                log_debug("journal: %{dnsname}: reached the end of the journal file", zone->origin);
                replay_state = ZDB_ICMTL_REPLAY_COMMIT_AND_STOP;
            }
            else
            {
                log_err("journal: broken journal: %r", return_value);
                logger_flush(); // broken journal (flush is slow, but this is bad, so : keep it)
                // replay_state = ZDB_ICMTL_REPLAY_STOP; // never read
                break;
            }
        }
        else                       // first record must be an SOA (or it's wrong)
            if(baos_rr_count == 0) // first record ?
            {
                if(rr.tctr.rtype != TYPE_SOA) // must be SOA
                {
                    // expected an SOA
                    return_value = ZDB_JOURNAL_SOA_RECORD_EXPECTED;
                    break;
                }

                ++baos_soa_count; // 0 -> 1 // this is not mandatory but clearer to read
            }
            else // the page ends with an SOA or end of stream
                if(rr.tctr.rtype == TYPE_SOA)
                {
                    if(baos_soa_count == 2)
                    {
                        // this record is the start of the next stream, keep it for the next iteration
                        replay_state = ZDB_ICMTL_REPLAY_COMMIT;
                    }

                    ++baos_soa_count;
                }

        ++baos_rr_count;

        if((replay_state & ZDB_ICMTL_REPLAY_COMMIT) != 0)
        {
            log_debug("journal: %{dnsname}: applying changes", zone->origin);
            uint64_t ts_start = timeus();
            zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);
            bytearray_input_stream_init_const(&bais, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos));

            return_value = zdb_icmtl_replay_commit(zone, &bais, &current_serial);

            zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_LOAD, ZDB_ZONE_MUTEX_SIMPLEREADER);
            input_stream_close(&bais);
            uint64_t ts_stop = timeus();
            if(ts_stop < ts_start) // time change
            {
                ts_stop = ts_start;
            }

            uint64_t ts_delta = ts_stop - ts_start;

            if(ISOK(return_value))
            {
                if(ts_delta < 1000)
                {
                    log_debug("journal: %{dnsname}: applied changes (%lluus)", zone->origin, ts_delta);
                }
                else if(ts_delta < ONE_SECOND_US)
                {
                    double ts_delta_s = ts_delta;
                    ts_delta_s /= 1000.0;
                    log_debug("journal: %{dnsname}: applied changes (%5.2fms)", zone->origin, ts_delta_s);
                }
                else
                {
                    double ts_delta_s = ts_delta;
                    ts_delta_s /= 1000000.0;
                    log_debug("journal: %{dnsname}: applied changes (%5.2fs)", zone->origin, ts_delta_s);
                }
            }
            else
            {
                log_err("journal: %{dnsname}: failed to committed changes", zone->origin);
                break;
            }

            // the current page has been processed

            if(replay_state == ZDB_ICMTL_REPLAY_COMMIT_AND_STOP)
            {
                // no more page to read
                break;
            }

            // reset the state for the next page
            // note: the next written record will be the last read SOA

            baos_rr_count = 1;
            baos_soa_count = 1;
            replay_state = ZDB_ICMTL_REPLAY_GATHER;
            bytearray_output_stream_reset(&baos);

        } // end if replay_state is ZDB_ICMTL_REPLAY_COMMIT (mask)

        dns_resource_record_write(&rr, &baos);
    }

    input_stream_close(&is);
    output_stream_close(&baos);
    dns_resource_record_clear(&rr);

    // cleanup destroyed nsec3 chains

    if(ISOK(return_value))
    {
        bool is_nsec3 = zdb_zone_is_nsec3(zone);

        if(is_nsec3 && !was_nsec3)
        {
            // the chain has just been created, but is probably missing internal links
            log_debug("journal: %{dnsname}: zone switched to NSEC3 by reading the journal: updating links", zone->origin);

            zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);
            nsec3_zone_update_chain0_links(zone);
            zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_LOAD, ZDB_ZONE_MUTEX_SIMPLEREADER);

            log_debug("journal: %{dnsname}: zone switched to NSEC3 by reading the journal: links updated", zone->origin);
        }

        if(FAIL(return_value = zdb_zone_getserial(zone, &serial))) // zone is locked
        {
            zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);

            log_err("journal: %{dnsname}: error reading confirmation serial for zone: %r", zone->origin, return_value);

            return return_value;
        }

        if(serial != last_serial)
        {
            log_warn("journal: %{dnsname}: expected serial to be %i but it is %i instead", zone->origin, last_serial, serial);
        }

#if 0 // ICMTL_DUMP_JOURNAL_RECORDS
        if(is_nsec)
        {
            nsec_logdump_tree(zone);
            logger_flush();
        }
#endif
    }

    zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);

    if(ISOK(return_value))
    {
        log_info("journal: %{dnsname}: replayed until serial %u", zone->origin, current_serial);

        return_value = last_serial - first_serial;
        zdb_zone_set_status(zone, ZDB_ZONE_STATUS_MODIFIED);
    }

    return return_value;
}

/** @} */

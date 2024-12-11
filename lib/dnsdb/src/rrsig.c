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
 * @defgroup rrsig RRSIG functions
 * @ingroup dnsdbdnssec
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

#include <arpa/inet.h>

#include <dnscore/sys_types.h>
#include <dnscore/logger.h>
#include <dnscore/dnsname.h>
#include <dnscore/random.h>
#include <dnscore/dnskey.h>
#include <dnscore/thread_pool.h>
#include <dnscore/dnskey_signature.h>

#include "dnsdb/dnssec.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_zone_dnssec.h"
#include "dnsdb/zdb_packed_ttlrdata.h"

#include "dnsdb/nsec.h"

#define MODULE_MSG_HANDLE             g_dnssec_logger

/*
 * 0 : no dump
 * 1 : dump
 * 2 : more dump ...
 */

#define RRSIG_DUMP                    0 // 5

#define RRSIG_AUTOMATIC_ALARM_REFRESH 0

#define DEBUG_SIGNATURE_REMOVAL_TEST  0

/**
 * Deletes all RRSIG covering the given type.
 */

static inline bool rrsig_record_covers_type(const zdb_resource_record_data_t *rrsig, const void *typep) { return RRSIG_TYPE_COVERED(rrsig) == GET_U16_AT_P(typep); }

void               rrsig_delete_covering(zdb_rr_label_t *label, uint16_t type)
{
    zdb_resource_record_set_t *rrsig_rrset = zdb_resource_record_sets_find(&label->resource_record_set, TYPE_RRSIG); // pointer to a pointer to the record
    if(rrsig_rrset != NULL)
    {
        zdb_resource_record_set_delete_matching(rrsig_rrset, rrsig_record_covers_type, &type);
    }
}

/**
 *
 * Removes all the RRSIG covering the type
 *
 * @param dname         the fqdn of the label
 * @param label         the label
 * @param covered_type  the type covered by the RRSIG
 */

void rrsig_delete(const zdb_zone_t *zone, const uint8_t *dname, zdb_rr_label_t *label, uint16_t type)
{
    /*
     * zdb_resource_record_data_t** prev = zdb_resource_record_sets_findp(&label->resource_record_set, TYPE_RRSIG);
     *
     * =>
     *
     */

    (void)zone;
    (void)dname;

    rrsig_delete_covering(label, type);
}

static inline bool rrsig_record_signed_with_tag(const zdb_resource_record_data_t *record, const void *tagp) { return RRSIG_KEY_TAG(record) == GET_U16_AT_P(tagp); }

void               rrsig_delete_by_tag(const zdb_zone_t *zone, uint16_t tag)
{
    zdb_resource_record_sets_node_t *rrsig_rrset_node = zdb_resource_record_sets_set_find(&zone->apex->resource_record_set, TYPE_RRSIG);
    if(rrsig_rrset_node != NULL)
    {
        zdb_resource_record_set_t *rrsig_rrset = &rrsig_rrset_node->value;
        if(rrsig_rrset != NULL)
        {
            zdb_resource_record_set_delete_matching(rrsig_rrset, rrsig_record_signed_with_tag, &tag);
        }
    }
}

/**
 * Use label position state (apex, at delegation, under delegation, ...) to decide if a label should be signed.
 * Optout is not taken into account.
 */

bool rrsig_should_label_be_signed(zdb_zone_t *zone, const uint8_t *fqdn, zdb_rr_label_t *rr_label)
{
    (void)zone;
    (void)fqdn;
    if(LABEL_HAS_RECORDS(rr_label))
    {
        if(zdb_rr_label_is_apex(rr_label))
        {
            return true;
        }
        else
        {
            if(ZDB_LABEL_ATDELEGATION(rr_label))
            {
                return true;
            }
            else
            {
                // not under a delegation: sign

                if(!ZDB_LABEL_UNDERDELEGATION(rr_label))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }
    }
    else
    {
        return false;
    }
}

/**
 * regeneration is the time before expiration of the signature to regenerate it
 * but it should not be taken into account if the key will expire in that amount of time
 *
 */

bool rrsig_should_remove_signature_from_rdata(const void *rdata, uint16_t rdata_size, const ptr_vector_t *zsks, int32_t now, int32_t regeneration, int32_t *key_indexp)
{
    int64_t inception = rrsig_get_valid_from_from_rdata(rdata, rdata_size);
    int64_t expiration = rrsig_get_valid_until_from_rdata(rdata, rdata_size);

#if DEBUG_SIGNATURE_REMOVAL_TEST
    rdata_desc_t rrsig_rr_rd = {TYPE_RRSIG, rdata_size, rdata};
#endif

    if(inception > expiration)
    {
        expiration += U32_MAX;
    }

    // signature date mismatched (time will be handled as 64 bits integers at a later date)

    if(expiration < inception)
    {
#if DEBUG_SIGNATURE_REMOVAL_TEST
        log_info("rrsig_should_remove_signature_from_rdata: mismatched times %T < %T (DEBUG_SIGNATURE_REMOVAL_TEST)", expiration, inception);
#endif
        return true;
    }

    // signature expired

    if(now >= expiration)
    {
#if DEBUG_SIGNATURE_REMOVAL_TEST
        log_info(
            "rrsig_should_remove_signature_from_rdata: now >= expiration %T >= %T (DEBUG_SIGNATURE_REMOVAL_TEST) "
            "%{rdatadesc}",
            now,
            expiration,
            &rrsig_rr_rd);
#endif
        return true;
    }

    // find the key

    uint16_t key_tag = rrsig_get_key_tag_from_rdata(rdata, rdata_size);

#if DEBUG_SIGNATURE_REMOVAL_TEST
    log_info("rrsig_should_remove_signature_from_rdata: tag=%hd", key_tag);
#endif

    dnskey_t *key = NULL;
    for(int_fast32_t i = 0; i <= ptr_vector_last_index(zsks); ++i)
    {
        key = (dnskey_t *)ptr_vector_get(zsks, i);

        if(key == NULL) // invalid key
        {
            log_err("rrsig_should_remove_signature_from_rdata: tag=%hd: got NULL key", key_tag);
            break;
        }

        if(dnskey_get_tag(key) == key_tag)
        {
            *key_indexp = i;

            // key found

            if(!dnskey_is_deactivated(key, expiration))
            {
                // key will not be deactivated at expiration of this signature (else there is no point regenerating it)

                // if the key is not private, regeneration is impossible

                if(dnskey_is_private(key))
                {
                    if(now >= (expiration - regeneration)) // signature needs to be regenerated (maybe)
                    {
                        if(now < expiration)
                        {
                            if(expiration < dnskey_get_inactive_epoch(key))
                            {
#if DEBUG_SIGNATURE_REMOVAL_TEST
                                log_info(
                                    "rrsig_should_remove_signature_from_rdata: tag=%hd: expiration < "
                                    "inactive_epoch(key) times %T < %T (DEBUG_SIGNATURE_REMOVAL_TEST) %{rdatadesc}",
                                    key_tag,
                                    now,
                                    expiration,
                                    &rrsig_rr_rd);
#endif
                                return true; // remove it for replacement
                            }
                            else
                            {
                                return false; // no point re-doing it, it would only move the goal post
                            }
                        }
                        else
                        {
#if DEBUG_SIGNATURE_REMOVAL_TEST
                            log_info(
                                "rrsig_should_remove_signature_from_rdata: tag=%hd: now >= expiration %T >= %T "
                                "(DEBUG_SIGNATURE_REMOVAL_TEST) %{rdatadesc}",
                                key_tag,
                                now,
                                expiration,
                                &rrsig_rr_rd);
#endif
                            return true; // remove it for replacement
                        }
                    }
                    else
                    {
                        return false;
                    }

                    // return  now >= (expiration - regeneration); // signature needs to be regenerated
                }
                else
                {
#if DEBUG_SIGNATURE_REMOVAL_TEST
                    if(now >= expiration)
                    {
                        log_info(
                            "rrsig_should_remove_signature_from_rdata: tag=%hd: now >= expiration %T >= %T "
                            "(DEBUG_SIGNATURE_REMOVAL_TEST 2) %{rdatadesc}",
                            key_tag,
                            now,
                            expiration,
                            &rrsig_rr_rd);
                    }
#endif
                    return now >= expiration;
                }
            }
            else // key is deactivated with its signature
            {
#if DEBUG_SIGNATURE_REMOVAL_TEST
                if(now >= dnskey_get_inactive_epoch(key))
                {
                    log_info(
                        "rrsig_should_remove_signature_from_rdata: tag=%hd: now >= inactive_epoch(key) %T >= %T "
                        "(DEBUG_SIGNATURE_REMOVAL_TEST 2) %{rdatadesc}",
                        key_tag,
                        now,
                        dnskey_get_inactive_epoch(key),
                        &rrsig_rr_rd);
                }
#endif
                return (now >= dnskey_get_inactive_epoch(key));
            }
        }
    }

#if DEBUG_SIGNATURE_REMOVAL_TEST
    if(key != NULL)
    {
        if(now >= dnskey_get_inactive_epoch(key))
        {
            log_info(
                "rrsig_should_remove_signature_from_rdata: tag=%hd: key is inactive (DEBUG_SIGNATURE_REMOVAL_TEST) "
                "%{rdatadesc}",
                key_tag,
                now,
                dnskey_get_inactive_epoch(key),
                &rrsig_rr_rd);
        }
    }
    else
    {
        log_info(
            "rrsig_should_remove_signature_from_rdata: tag=%hd : no such key (DEBUG_SIGNATURE_REMOVAL_TEST) "
            "%{rdatadesc}",
            key_tag,
            &rrsig_rr_rd);
    }
#endif

    *key_indexp = -1; // key is unknown

    return true;
}

/** @} */

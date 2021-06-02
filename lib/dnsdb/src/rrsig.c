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

/** @defgroup rrsig RRSIG functions
 *  @ingroup dnsdbdnssec
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

#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#include <dnscore/sys_types.h>
#include <dnscore/logger.h>
#include <dnscore/dnsname.h>
#include <dnscore/random.h>
#include <dnscore/dnskey.h>
#include <dnscore/thread_pool.h>
#include <dnscore/dnskey-signature.h>

#include "dnsdb/dnsrdata.h"
#include "dnsdb/dnssec.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb-zone-dnssec.h"
#include "dnsdb/zdb-packed-ttlrdata.h"

#include "dnsdb/nsec.h"


#define MODULE_MSG_HANDLE g_dnssec_logger

/*
 * 0 : no dump
 * 1 : dump
 * 2 : more dump ...
 */

#define RRSIG_DUMP 0 // 5

#define RRSIG_AUTOMATIC_ALARM_REFRESH 0

#define DEBUG_SIGNATURE_REMOVAL_TEST 0

/**
 * 
 * Returns the first RRSIG record that applies to the give type.
 * 
 * @param label        the label where to do the search
 * @param covered_type the type covered by the RRSIG
 * 
 * @return the first RRSIG covering the type or NULL
 */

zdb_packed_ttlrdata*
rrsig_find_first(const zdb_rr_label* label, u16 type)
{
    zdb_packed_ttlrdata* rrsig = zdb_record_find(&label->resource_record_set, TYPE_RRSIG);

    while(rrsig != NULL)
    {
        if(RRSIG_TYPE_COVERED(rrsig) == type)
        {
            return rrsig;
        }

        rrsig = rrsig->next;
    }

    return NULL;
}

/**
 * 
 * Returns the next RRSIG record that applies to the give type.
 * 
 * @param rrsig        the previous RRSIG covering the type
 * @param covered_type the type covered by the RRSIG
 * 
 * @return  covered_type the next RRSIG covering the type or NULL
 */
 
zdb_packed_ttlrdata*
rrsig_find_next(const zdb_packed_ttlrdata* rrsig, u16 type)
{
    rrsig = rrsig->next;
    
    while(rrsig != NULL)
    {
        if(RRSIG_TYPE_COVERED(rrsig) == type)
        {
            return (zdb_packed_ttlrdata*)rrsig;
        }

        rrsig = rrsig->next;
    }

    return NULL;
}

/**
 * Deletes all RRSIG covering the given type.
 */

void
rrsig_delete_covering(const zdb_rr_label* label, u16 type)
{
    zdb_packed_ttlrdata** rrsigp = zdb_record_findp(&label->resource_record_set, TYPE_RRSIG); // pointer to a pointer to the record

    if(rrsigp != NULL)
    {
        zdb_packed_ttlrdata *rrsig; // will point to the record

        while((rrsig = *rrsigp) != NULL)
        {
            if(RRSIG_TYPE_COVERED(rrsig) != type)
            {
                rrsigp = &(*rrsigp)->next;
            }
            else
            {
                *rrsigp = (*rrsigp)->next;
                ZDB_RECORD_ZFREE(rrsig);
            }
        }
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

void
rrsig_delete(const zdb_zone *zone, const u8 *dname, zdb_rr_label* label, u16 type)
{
    /*
     * zdb_packed_ttlrdata** prev = zdb_record_findp(&label->resource_record_set, TYPE_RRSIG);
     *
     * =>
     *
     */

    (void)zone;
    (void)dname;

    zdb_packed_ttlrdata** first = (zdb_packed_ttlrdata**)btree_findp(&label->resource_record_set, TYPE_RRSIG);

    if(first == NULL)
    {
        return;
    }

    zdb_packed_ttlrdata** prev = first;

    zdb_packed_ttlrdata* rrsig = *prev;

    while(rrsig != NULL)
    {
        if(RRSIG_TYPE_COVERED(rrsig) == type)
        {
            if(prev == first && rrsig->next == NULL) /* Only one RRSIG: proper removal and delete */
            {
                zdb_record_delete(&label->resource_record_set, TYPE_RRSIG);
                break;
            }
            else
            {
                *prev = rrsig->next; /* More than one RRSIG: unchain and delete */

                ZDB_RECORD_ZFREE(rrsig);                
                rrsig = *prev;
                
                if(rrsig == NULL)
                {
                    break;
                }
            }
        }

        prev = &(*prev)->next;
        rrsig = rrsig->next;
    }
}

void
rrsig_delete_by_tag(const zdb_zone *zone, u16 tag)
{
    /*
     * zdb_packed_ttlrdata** prev = zdb_record_findp(&label->resource_record_set, TYPE_RRSIG);
     *
     * =>
     *
     */

    zdb_packed_ttlrdata** first = (zdb_packed_ttlrdata**)btree_findp(&zone->apex->resource_record_set, TYPE_RRSIG);

    if(first == NULL)
    {
        return;
    }

    zdb_packed_ttlrdata** prev = first;

    zdb_packed_ttlrdata* rrsig = *prev;

    while(rrsig != NULL)
    {
        if(RRSIG_KEY_TAG(rrsig) == tag)
        {
            if(prev == first && rrsig->next == NULL) /* Only one RRSIG: proper removal and delete */
            {
                zdb_record_delete(&zone->apex->resource_record_set, TYPE_RRSIG);
                break;
            }
            else
            {
                *prev = rrsig->next; /* More than one RRSIG: unchain and delete */

                ZDB_RECORD_ZFREE(rrsig);                
                rrsig = *prev;
                
                if(rrsig == NULL)
                {
                    break;
                }
            }
        }

        prev = &(*prev)->next;
        rrsig = rrsig->next;
    }
}

/**
 * Use label position state (apex, at delegation, under delegation, ...) to decide if a label should be signed.
 * Optout is not taken into account.
 */

bool
rrsig_should_label_be_signed(zdb_zone *zone, const u8 *fqdn, zdb_rr_label *rr_label)
{
    (void)zone;
    (void)fqdn;
    if(LABEL_HAS_RECORDS(rr_label))
    {
        if(zdb_rr_label_is_apex(rr_label))
        {
            return TRUE;
        }
        else
        {
            if(ZDB_LABEL_ATDELEGATION(rr_label))
            {
                return TRUE;
            }
            else
            {
                // not under a delegation: sign

                if(!ZDB_LABEL_UNDERDELEGATION(rr_label))
                {
                    return TRUE;
                }
                else
                {
                    return FALSE;
                }
            }
        }
    }
    else
    {
        return FALSE;
    }
}

/**
 * regeneration is the time before expiration of the signature to regenerate it
 * but it should not be taken into account if the key will expire in that amount of time
 *
 */

bool
rrsig_should_remove_signature_from_rdata(const void *rdata, u16 rdata_size, const ptr_vector *zsks, s32 now, s32 regeneration, s32 *key_indexp)
{
    s64 inception = rrsig_get_valid_from_from_rdata(rdata, rdata_size);
    s64 expiration = rrsig_get_valid_until_from_rdata(rdata, rdata_size);

#if DEBUG_SIGNATURE_REMOVAL_TEST
    rdata_desc rrsig_rr_rd = {TYPE_RRSIG, rdata_size, rdata};
#endif

    if(inception > expiration)
    {
        expiration += MAX_U32;
    }

    // signature date mismatched (time will be handled as 64 bits integers at a later date)

    if(expiration < inception)
    {
#if DEBUG_SIGNATURE_REMOVAL_TEST
        log_info("rrsig_should_remove_signature_from_rdata: mismatched times %T < %T (DEBUG_SIGNATURE_REMOVAL_TEST)", expiration, inception);
#endif
        return TRUE;
    }

    // signature expired

    if(now >= expiration)
    {
#if DEBUG_SIGNATURE_REMOVAL_TEST
        log_info("rrsig_should_remove_signature_from_rdata: now >= expiration %T >= %T (DEBUG_SIGNATURE_REMOVAL_TEST) %{rdatadesc}", now, expiration, &rrsig_rr_rd);
#endif
        return TRUE;
    }

    // find the key

    u16 key_tag = rrsig_get_key_tag_from_rdata(rdata, rdata_size);

#if DEBUG_SIGNATURE_REMOVAL_TEST
    log_info("rrsig_should_remove_signature_from_rdata: tag=%hd",  key_tag);
#endif

    dnssec_key *key = NULL;
    for(int i = 0; i <= ptr_vector_last_index(zsks); ++i)
    {
        key = (dnssec_key*)ptr_vector_get(zsks, i);

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
                                log_info("rrsig_should_remove_signature_from_rdata: tag=%hd: expiration < inactive_epoch(key) times %T < %T (DEBUG_SIGNATURE_REMOVAL_TEST) %{rdatadesc}", key_tag, now, expiration, &rrsig_rr_rd);
#endif
                                return TRUE; // remove it for replacement
                            }
                            else
                            {
                                return FALSE; // no point re-doing it, it would only move the goal post
                            }
                        }
                        else
                        {
#if DEBUG_SIGNATURE_REMOVAL_TEST
                            log_info("rrsig_should_remove_signature_from_rdata: tag=%hd: now >= expiration %T >= %T (DEBUG_SIGNATURE_REMOVAL_TEST) %{rdatadesc}", key_tag, now, expiration, &rrsig_rr_rd);
#endif
                            return TRUE; // remove it for replacement
                        }
                    }
                    else
                    {
                        return FALSE;
                    }

                    // return  now >= (expiration - regeneration); // signature needs to be regenerated
                }
                else
                {
#if DEBUG_SIGNATURE_REMOVAL_TEST
                    if(now >= expiration)
                    {
                        log_info("rrsig_should_remove_signature_from_rdata: tag=%hd: now >= expiration %T >= %T (DEBUG_SIGNATURE_REMOVAL_TEST 2) %{rdatadesc}", key_tag, now, expiration, &rrsig_rr_rd);
                    }
#endif
                    return  now >= expiration;
                }
            }
            else // key is deactivated with its signature
            {
#if DEBUG_SIGNATURE_REMOVAL_TEST
                if(now >= dnskey_get_inactive_epoch(key))
                {
                    log_info("rrsig_should_remove_signature_from_rdata: tag=%hd: now >= inactive_epoch(key) %T >= %T (DEBUG_SIGNATURE_REMOVAL_TEST 2) %{rdatadesc}", key_tag, now, dnskey_get_inactive_epoch(key), &rrsig_rr_rd);
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
            log_info("rrsig_should_remove_signature_from_rdata: tag=%hd: key is inactive (DEBUG_SIGNATURE_REMOVAL_TEST) %{rdatadesc}", key_tag, now, dnskey_get_inactive_epoch(key), &rrsig_rr_rd);
        }
    }
    else
    {
        log_info("rrsig_should_remove_signature_from_rdata: tag=%hd : no such key (DEBUG_SIGNATURE_REMOVAL_TEST) %{rdatadesc}", key_tag, &rrsig_rr_rd);
    }
#endif

    *key_indexp = -1; // key is unknown

    return TRUE;
}

/** @} */

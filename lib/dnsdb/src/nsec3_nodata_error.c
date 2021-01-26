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

/** @defgroup nsec3 NSEC3 functions
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
#include <dnscore/logger.h>

#include "dnsdb/zdb_zone.h"
#include "dnsdb/nsec3_types.h"
#include "dnsdb/nsec3_item.h"
#include "dnsdb/nsec3_name_error.h"

#include "dnsdb/rrsig.h"

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

/*
 * It is assumed that zone is NSEC3.
 * The caller must ensure this is the case.
 */

/**
 * @note No Data Responses, QTYPE is not DS
 * 
 * The server MUST include the NSEC3 RR that matches QNAME.  This NSEC3
 * RR MUST NOT have the bits corresponding to either the QTYPE or CNAME
 * set in its Type Bit Maps field.
 */

void
nsec3_nodata_error(const zdb_zone *zone, const zdb_rr_label* owner,
                   const dnsname_vector *qname, s32 apex_index,
                   u8 * restrict * pool,
                   
                   u8 **out_owner_nsec3_owner,
                   zdb_packed_ttlrdata** out_owner_nsec3,
                   const zdb_packed_ttlrdata** out_owner_nsec3_rrsig,
                   
                   u8 **out_closest_encloser_nsec3_owner,
                   zdb_packed_ttlrdata** out_closest_encloser_nsec3,
                   const zdb_packed_ttlrdata** out_closest_encloser_nsec3_rrsig)
{
    yassert(out_owner_nsec3_owner != NULL && out_owner_nsec3 != NULL && out_owner_nsec3_rrsig != NULL);
    yassert(out_closest_encloser_nsec3_owner != NULL && out_closest_encloser_nsec3 != NULL && out_closest_encloser_nsec3_rrsig != NULL);
    
    const nsec3_zone_item *owner_nsec3;

    nsec3_zone* n3 = zone->nsec.nsec3;
    
    s32 min_ttl;
    zdb_zone_getminttl(zone, &min_ttl);
    
    nsec3_zone_item_to_new_zdb_packed_ttlrdata_parm nsec3_parms =
    {
        n3,
        NULL,
        zone->origin,
        pool,
        min_ttl
    };

    if((owner->nsec.dnssec == NULL) || (nsec3_label_extension_self(owner->nsec.nsec3) == NULL)) // scan-build false positive: owner->nsec.dnssec == owner->nsec.nsec3 => owner->nsec.nsec3 can't ben NULL for nsec3_label_extension_self
    {
        nsec3_closest_encloser_proof(zone, qname, apex_index,
                                    &owner_nsec3,
                                    &nsec3_parms.item, // closest_provable_encloser_nsec3
                                    NULL
                                    );

        if(nsec3_parms.item != NULL)
        {
            nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                    &nsec3_parms,
                    out_closest_encloser_nsec3_owner,
                    out_closest_encloser_nsec3,
                    out_closest_encloser_nsec3_rrsig);
        }
        else
        {
            *out_closest_encloser_nsec3_owner = NULL;
            *out_closest_encloser_nsec3 = NULL;
            *out_closest_encloser_nsec3_rrsig = NULL;
#if DEBUG
            log_debug("nsec3_nodata_error: no closest encloser proof");
#endif
        }
    }
    else
    {
        owner_nsec3 = nsec3_label_extension_self(owner->nsec.nsec3);
        *out_closest_encloser_nsec3 = NULL;
        *out_closest_encloser_nsec3_rrsig = NULL;
    }

    /* Append all items + sig to the authority
     * Don't do dups
     */

    if(owner_nsec3 != NULL)
    {
        nsec3_parms.item = owner_nsec3;
        
        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                &nsec3_parms,
                out_owner_nsec3_owner,
                out_owner_nsec3,
                out_owner_nsec3_rrsig);
    }
    else
    {
        log_err("%{dnsnamevector} has no NSEC3 owner, has DNSSEC mode been changed?", qname);
        
        //
        /*
        ((zone->_flags & ZDB_ZONE_HAS_OPTOUT_COVERAGE) != 0)
        
        digestname(closest_provable_encloser, dnsname_len(closest_provable_encloser), salt, salt_len, iterations, &digest[1], FALSE);
        closest_provable_encloser_nsec3 = nsec3_find(&n3->items, digest);
        */
    }
}

/**
 * 
 * @note Wildcard No Data Responses
 *
 * If there is a wildcard match for QNAME, but QTYPE is not present at
 * that name, the response MUST include a closest encloser proof for
 * QNAME and MUST include the NSEC3 RR that matches the wildcard.  This
 * combination proves both that QNAME itself does not exist and that a
 * wildcard that matches QNAME does exist.  Note that the closest
 * encloser to QNAME MUST be the immediate ancestor of the wildcard RR
 * (if this is not the case, then something has gone wrong).
 */

void nsec3_wild_nodata_error(const zdb_zone *zone, const zdb_rr_label *owner,
                             const dnsname_vector *qname, u32 apex_index,
                             u8 * restrict * pool,
                             
                             u8 **out_next_closer_nsec3_owner_p,
                             zdb_packed_ttlrdata** out_encloser_nsec3,
                             const zdb_packed_ttlrdata** out_encloser_nsec3_rrsig,
                             
                             u8 **out_closest_encloser_nsec3_owner_p,
                             zdb_packed_ttlrdata** out_closest_encloser_nsec3,
                             const zdb_packed_ttlrdata** out_closest_encloser_nsec3_rrsig,

                             u8 **out_qname_encloser_nsec3_owner_p,
                             zdb_packed_ttlrdata** out_qname_encloser_nsec3,
                             const zdb_packed_ttlrdata** out_qname_encloser_nsec3_rrsig)
{   
    yassert(out_next_closer_nsec3_owner_p != NULL && out_encloser_nsec3 != NULL && out_encloser_nsec3_rrsig != NULL);
    yassert(out_closest_encloser_nsec3_owner_p != NULL && out_closest_encloser_nsec3 != NULL && out_closest_encloser_nsec3_rrsig != NULL);

    (void)owner;

    // find the *.fqdn
    // add the name error above it

    const nsec3_zone_item *wild_encloser_nsec3 = NULL;
    const nsec3_zone_item *closest_provable_encloser_nsec3 = NULL;
    const nsec3_zone_item *qname_encloser_nsec3 = NULL;
    nsec3_wild_closest_encloser_proof(zone, qname, apex_index, &wild_encloser_nsec3, &closest_provable_encloser_nsec3, &qname_encloser_nsec3);

    nsec3_zone* n3 = zone->nsec.nsec3;

    s32 min_ttl;
    zdb_zone_getminttl(zone, &min_ttl);

    nsec3_zone_item_to_new_zdb_packed_ttlrdata_parm nsec3_parms =
        {
            n3,
            wild_encloser_nsec3,
            zone->origin,
            pool,
            min_ttl
        };

    *out_encloser_nsec3 = NULL;

    if(wild_encloser_nsec3 != NULL)
    {
        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
            &nsec3_parms,
            out_next_closer_nsec3_owner_p,
            out_encloser_nsec3,
            out_encloser_nsec3_rrsig);
    }

    *out_closest_encloser_nsec3 = NULL;

    if((closest_provable_encloser_nsec3 != wild_encloser_nsec3) && (closest_provable_encloser_nsec3 != NULL))
    {
        nsec3_parms.item = closest_provable_encloser_nsec3;
        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
            &nsec3_parms,
            out_closest_encloser_nsec3_owner_p,
            out_closest_encloser_nsec3,
            out_closest_encloser_nsec3_rrsig);
    }

    if((qname_encloser_nsec3 != wild_encloser_nsec3) && (qname_encloser_nsec3 != closest_provable_encloser_nsec3) && (qname_encloser_nsec3 != NULL))
    {
        nsec3_parms.item = qname_encloser_nsec3;
        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
            &nsec3_parms,
            out_qname_encloser_nsec3_owner_p,
            out_qname_encloser_nsec3,
            out_qname_encloser_nsec3_rrsig);
    }
}

/** @} */

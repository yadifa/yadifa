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

#include "dnsdb/nsec3_types.h"
#include "dnsdb/nsec3_item.h"
#include "dnsdb/nsec3_name_error.h"
#include "dnsdb/zdb_zone.h"

#include "dnsdb/rrsig.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

extern logger_handle *g_dnssec_logger;

/**
 */

void
nsec3_closest_encloser_from_fqdn(const zdb_zone* zone, const dnsname_vector *qname, u32 apex_index,
                 u8 * restrict * pool,
                 u8 **out_next_closer_nsec3_owner_p,
                 zdb_packed_ttlrdata** out_encloser_nsec3,
                 const zdb_packed_ttlrdata** out_encloser_nsec3_rrsig)
{
    const struct nsec3_node *encloser_nsec3;
    nsec3_closest_encloser_proof(zone, qname, apex_index, &encloser_nsec3,NULL,NULL);

    if(encloser_nsec3 != NULL)
    {
        nsec3_zone* n3 = zone->nsec.nsec3;

        s32 min_ttl;
        zdb_zone_getminttl(zone, &min_ttl);

        nsec3_zone_item_to_new_zdb_packed_ttlrdata_parm nsec3_parms =
            {
                n3,
                encloser_nsec3,
                zone->origin,
                pool,
                min_ttl
            };

        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
            &nsec3_parms,
            out_next_closer_nsec3_owner_p,
            out_encloser_nsec3,
            out_encloser_nsec3_rrsig);
    }
}

void nsec3_wild_closest_encloser(const zdb_zone* zone, const dnsname_vector *qname, u32 apex_index,
                                 u8 * restrict * pool,

                                 u8 **out_wild_encloser_nsec3_owner_p,
                                 zdb_packed_ttlrdata** out_wild_encloser_nsec3,
                                 const zdb_packed_ttlrdata** out_wild_encloser_nsec3_rrsig,

                                 u8 **out_wild_closest_encloser_nsec3_owner_p,
                                 zdb_packed_ttlrdata** out_wild_closest_encloser_nsec3,
                                 const zdb_packed_ttlrdata** out_wild_closest_encloser_nsec3_rrsig,

                                 u8 **out_qname_encloser_nsec3_owner_p,
                                 zdb_packed_ttlrdata** out_qname_encloser_nsec3,
                                 const zdb_packed_ttlrdata** out_qname_encloser_nsec3_rrsig

                                 )
{
    const nsec3_zone_item *wild_encloser_nsec3;
    const nsec3_zone_item *closest_provable_encloser_nsec3;
    const nsec3_zone_item *qname_encloser_nsec3;

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

    if(wild_encloser_nsec3 != NULL)
    {
        nsec3_parms.item = wild_encloser_nsec3;
        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
            &nsec3_parms,
            out_wild_encloser_nsec3_owner_p,
            out_wild_encloser_nsec3,
            out_wild_encloser_nsec3_rrsig);
    }

    if((closest_provable_encloser_nsec3 != wild_encloser_nsec3) && (closest_provable_encloser_nsec3 != NULL))
    {
        nsec3_parms.item = closest_provable_encloser_nsec3;
        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
            &nsec3_parms,
            out_wild_closest_encloser_nsec3_owner_p,
            out_wild_closest_encloser_nsec3,
            out_wild_closest_encloser_nsec3_rrsig);
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

/**
 * @note Name Error Responses
 * 
 * Retrieve NSEC3 name error records
 *
 * To prove the nonexistence of QNAME, a closest encloser proof and an
 * NSEC3 RR covering the (nonexistent) wildcard RR at the closest
 * encloser MUST be included in the response.  This collection of (up
 * to) three NSEC3 RRs proves both that QNAME does not exist and that a
 * wildcard that could have matched QNAME also does not exist.
 *
 * For example, if "gamma.example." is the closest provable encloser to
 * QNAME, then an NSEC3 RR covering "*.gamma.example." is included in
 * the authority section of the response.
 *
 *
 * 
 * Z-Allocates and creates an NSEC3 record from an nsec3_zone_item
 *
 * This record is temporary.
 *
 * The function is supposed to be called by nsec3_name_error & nsec3_nodata_error
 * Said functions are called by the query function
 *
 * The record is supposed to be destroyed after usage (ie: at destroy query answer)
 * 
 * @param zone
 * @param qname
 * @param apex_index
 * @param pool
 * @param out_next_closer_nsec3_owner_p
 * @param out_encloser_nsec3
 * @param out_encloser_nsec3_rrsig
 * @param out_closest_encloser_nsec3_owner_p
 * @param out_closest_encloser_nsec3
 * @param out_closest_encloser_nsec3_rrsig
 * @param out_wild_closest_encloser_nsec3_owner_p
 * @param out_wild_closest_encloser_nsec3
 * @param out_wild_closest_encloser_nsec3_rrsig
 */

void
nsec3_name_error(const zdb_zone* zone, const dnsname_vector *qname, u32 apex_index,
                 u8 * restrict * pool,
                 
                 u8 **out_next_closer_nsec3_owner_p,
                 zdb_packed_ttlrdata** out_encloser_nsec3,
                 const zdb_packed_ttlrdata** out_encloser_nsec3_rrsig,
                 
                 u8 **out_closest_encloser_nsec3_owner_p,
                 zdb_packed_ttlrdata** out_closest_encloser_nsec3,
                 const zdb_packed_ttlrdata** out_closest_encloser_nsec3_rrsig,
                 
                 u8 **out_wild_closest_encloser_nsec3_owner_p,
                 zdb_packed_ttlrdata** out_wild_closest_encloser_nsec3,
                 const zdb_packed_ttlrdata** out_wild_closest_encloser_nsec3_rrsig
                 )
{   
    const nsec3_zone_item *encloser_nsec3;
    const nsec3_zone_item *closest_provable_encloser_nsec3;
    const nsec3_zone_item *wild_closest_provable_encloser_nsec3;
    
    yassert(out_next_closer_nsec3_owner_p != NULL && out_encloser_nsec3 != NULL && out_encloser_nsec3_rrsig != NULL);
    yassert(out_closest_encloser_nsec3_owner_p != NULL && out_closest_encloser_nsec3 != NULL && out_closest_encloser_nsec3_rrsig != NULL);
    yassert(out_wild_closest_encloser_nsec3_owner_p != NULL && out_wild_closest_encloser_nsec3 != NULL && out_wild_closest_encloser_nsec3_rrsig != NULL);

    *out_next_closer_nsec3_owner_p = NULL;
    *out_encloser_nsec3 = NULL;
    *out_encloser_nsec3_rrsig = NULL;
    
    *out_closest_encloser_nsec3_owner_p = NULL;
    *out_closest_encloser_nsec3 = NULL;
    *out_closest_encloser_nsec3_rrsig = NULL;
    
    *out_wild_closest_encloser_nsec3_owner_p = NULL;
    *out_wild_closest_encloser_nsec3 = NULL;
    *out_wild_closest_encloser_nsec3_rrsig = NULL;

    nsec3_closest_encloser_proof(zone, qname, apex_index,
                                 &encloser_nsec3,
                                 &closest_provable_encloser_nsec3,
                                 &wild_closest_provable_encloser_nsec3
                                 );

    /* Append all items + sig to the authority
     * Don't do dups
     */

    nsec3_zone* n3 = zone->nsec.nsec3;
    
    s32 min_ttl;
    zdb_zone_getminttl(zone, &min_ttl);
    
    nsec3_zone_item_to_new_zdb_packed_ttlrdata_parm nsec3_parms =
    {
        n3,
        encloser_nsec3,
        zone->origin,
        pool,
        min_ttl
    };

    if(encloser_nsec3 != NULL)
    {
        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                &nsec3_parms,
                out_next_closer_nsec3_owner_p,
                out_encloser_nsec3,
                out_encloser_nsec3_rrsig);
    }
    
    *out_closest_encloser_nsec3 = NULL;
    
    if((closest_provable_encloser_nsec3 != encloser_nsec3) && (closest_provable_encloser_nsec3 != NULL))
    {
        nsec3_parms.item = closest_provable_encloser_nsec3;
        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                &nsec3_parms,
                out_closest_encloser_nsec3_owner_p,
                out_closest_encloser_nsec3,
                out_closest_encloser_nsec3_rrsig);
    }

    *out_wild_closest_encloser_nsec3 = NULL;
    
    if((wild_closest_provable_encloser_nsec3 != encloser_nsec3) && (wild_closest_provable_encloser_nsec3 != closest_provable_encloser_nsec3) && (wild_closest_provable_encloser_nsec3 != NULL))
    {
        nsec3_parms.item = wild_closest_provable_encloser_nsec3;
        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                &nsec3_parms,
                out_wild_closest_encloser_nsec3_owner_p,
                out_wild_closest_encloser_nsec3,
                out_wild_closest_encloser_nsec3_rrsig);
    }
}

/** @} */

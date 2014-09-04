/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
#include <stdio.h>
#include <stdlib.h>

#include "dnsdb/nsec3_types.h"
#include "dnsdb/nsec3_item.h"

#include "dnsdb/rrsig.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

extern logger_handle *g_dnssec_logger;

/*
 * Retrieve NSEC3 name error records
 */

/**
 * @note Name Error Responses
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

    nsec3_closest_encloser_proof(zone, qname, apex_index,
                                 &encloser_nsec3,
                                 &closest_provable_encloser_nsec3,
                                 &wild_closest_provable_encloser_nsec3
                                 );

    /* Append all items + sig to the authority
     * Don't do dups
     */

    nsec3_zone* n3 = zone->nsec.nsec3;
    
    u32 min_ttl = 900;
    
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

    *out_closest_encloser_nsec3 = NULL;
    
    if(closest_provable_encloser_nsec3 != encloser_nsec3)
    {
        nsec3_parms.item = closest_provable_encloser_nsec3;
        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                &nsec3_parms,
                out_closest_encloser_nsec3_owner_p,
                out_closest_encloser_nsec3,
                out_closest_encloser_nsec3_rrsig);
    }

    *out_wild_closest_encloser_nsec3 = NULL;
    
    if((wild_closest_provable_encloser_nsec3 != encloser_nsec3) && (wild_closest_provable_encloser_nsec3 != closest_provable_encloser_nsec3))
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

/*----------------------------------------------------------------------------*/


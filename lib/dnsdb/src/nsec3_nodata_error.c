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
    const nsec3_zone_item *owner_nsec3;

    nsec3_zone* n3 = zone->nsec.nsec3;
    
    u32 min_ttl = 900;
    
    zdb_zone_getminttl(zone, &min_ttl);
    
    nsec3_zone_item_to_new_zdb_packed_ttlrdata_parm nsec3_parms =
    {
        n3,
        NULL,
        zone->origin,
        pool,
        min_ttl
    };

    if((owner->nsec.dnssec) == NULL)
    {
        nsec3_closest_encloser_proof(zone, qname, apex_index,
                                    &owner_nsec3,
                                    &nsec3_parms.item, // closest_provable_encloser_nsec3
                                    NULL
                                    );

        nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                &nsec3_parms,
                out_closest_encloser_nsec3_owner,
                out_closest_encloser_nsec3,
                out_closest_encloser_nsec3_rrsig);
    }
    else
    {
        owner_nsec3 = owner->nsec.nsec3->self;
        *out_closest_encloser_nsec3 = NULL;
        *out_closest_encloser_nsec3_rrsig = NULL;
    }

    /* Append all items + sig to the authority
     * Don't do dups
     */

    nsec3_parms.item = owner_nsec3;
    nsec3_zone_item_to_new_zdb_packed_ttlrdata(
            &nsec3_parms,
            out_owner_nsec3_owner,
            out_owner_nsec3,
            out_owner_nsec3_rrsig);
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
                             u8 **out_wild_closest_encloser_nsec3_owner_p,
                             zdb_packed_ttlrdata** out_wild_closest_encloser_nsec3,
                             const zdb_packed_ttlrdata** out_wild_closest_encloser_nsec3_rrsig
                             )
{    
    nsec3_name_error(zone, qname, apex_index, pool,
                     out_next_closer_nsec3_owner_p,
                     out_encloser_nsec3, out_encloser_nsec3_rrsig,
                     out_closest_encloser_nsec3_owner_p,
                     out_closest_encloser_nsec3,
                     out_closest_encloser_nsec3_rrsig,
                     out_wild_closest_encloser_nsec3_owner_p,
                     out_wild_closest_encloser_nsec3,
                     out_wild_closest_encloser_nsec3_rrsig);
}



/** @} */

/*----------------------------------------------------------------------------*/


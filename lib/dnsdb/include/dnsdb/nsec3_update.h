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
 *
 *----------------------------------------------------------------------------*/
#ifndef _NSEC3_UPDATE_H
#define	_NSEC3_UPDATE_H

#include <dnsdb/nsec3_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif

/* Builds the NSEC3 records in a zone,
 * after this call all the signatures of each NSEC3 from the zone should be updated */
    
ya_result nsec3_update_zone(zdb_zone* zone);

bool nsec3_is_label_covered(zdb_rr_label *label, bool opt_out);

/**
 * 
 * Commits the changes
 * There is NO lock made on the zone
 * 
 * @param removed_rrsig_sll
 * @param added_rrsig_sll
 * @param item
 * @param zone
 */

void nsec3_update_rrsig_commit(zdb_packed_ttlrdata *removed_rrsig_sll, zdb_packed_ttlrdata *added_rrsig_sll, nsec3_zone_item *item, zdb_zone *zone);


#ifdef	__cplusplus
}
#endif

#endif	/* _NSEC3_UPDATE_H */
/** @} */

/*----------------------------------------------------------------------------*/


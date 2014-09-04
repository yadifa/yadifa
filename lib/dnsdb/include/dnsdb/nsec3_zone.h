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
#ifndef _NSEC3_ZONE_H
#define	_NSEC3_ZONE_H

#include <dnsdb/nsec3_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif

int  nsec3_zone_rdata_compare(const u8* a_rdata, const u8* b_rdata);
int  nsec3_zone_compare(nsec3_zone* a, nsec3_zone* b);
void nsec3_zone_destroy(zdb_zone* zone, nsec3_zone* n3);
nsec3_zone* nsec3_zone_from_item(zdb_zone* zone, nsec3_zone_item* item);
nsec3_zone* nsec3_zone_add_from_rdata(zdb_zone* zone, u16 nsec3param_rdata_size, const u8* nsec3param_rdata);
nsec3_zone* nsec3_zone_get_from_rdata(zdb_zone* zone, u16 nsec3param_rdata_size, const u8* nsec3param_rdata);

#ifdef	__cplusplus
}
#endif

#endif	/* _NSEC3_ZONE_H */
/** @} */

/*----------------------------------------------------------------------------*/


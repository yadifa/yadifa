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
 *
 *----------------------------------------------------------------------------*/
#ifndef _NSEC3_ZONE_H
#define	_NSEC3_ZONE_H

#include <dnsdb/nsec3_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif

int  nsec3param_compare_by_rdata(const u8* a_rdata, const u8* b_rdata);
int  nsec3_zone_compare(nsec3_zone* a, nsec3_zone* b);
void nsec3_zone_destroy(zdb_zone* zone, nsec3_zone* n3);

nsec3_zone* nsec3_zone_new(const u8 *nsec3param_rdata, u16 nsec3param_rdata_size);

/**
 * Frees the memory allocated by the nsec3_zone struct.
 * Must not be called for a nsec3_zone that's being linked into a zdb_zone or
 * that still contains items.
 * 
 * @param n3
 */

void nsec3_zone_free(nsec3_zone *n3);

nsec3_zone* nsec3_zone_from_item(const zdb_zone* zone, const nsec3_zone_item* item);
nsec3_zone* nsec3_zone_add_from_rdata(zdb_zone* zone, u16 nsec3param_rdata_size, const u8* nsec3param_rdata);
nsec3_zone* nsec3_zone_get_from_rdata(const zdb_zone* zone, u16 nsec3param_rdata_size, const u8* nsec3param_rdata);

bool nsec3_zone_detach(zdb_zone *zone, nsec3_zone *n3);

ya_result nsec3_zone_chain_count(zdb_zone* zone);

/**
 * 
 * Adds the nsec3_zone (NSEC3PARAM "alter-ego") to the zone.
 *
 * Updates labels flags + nsec3 item references placeholders
 * using nsec3_insert_empty_nsec3
 *
 * Uses nsec3zone_compare
 *
 * Used by nsec3_add_nsec3param and nsec3_load_add_nsec3param
 *
 * @note Does not add the record.
 * 
 * @param zone
 * @param nsec3param_rdata
 * @param nsec3param_rdata_size
 * 
 * @return an error code
 */

ya_result nsec3_zone_chain_add_with_rdata(zdb_zone* zone, const u8* nsec3param_rdata, u16 nsec3param_rdata_size);

/**
 * Returns the index of an NSEC3PARAM in the zone, or an error code
 * 
 * @param zone
 * @param nsec3param_rdata
 * @param nsec3param_rdata_size
 * @return 
 */

ya_result nsec3_zone_chain_get_index_from_rdata(zdb_zone* zone, const u8* nsec3param_rdata, u16 nsec3param_rdata_size);

ya_result nsec3_zone_chain_get_index_from_rdata(zdb_zone* zone, const u8* nsec3param_rdata, u16 nsec3param_rdata_size);

#ifdef	__cplusplus
}
#endif

#endif	/* _NSEC3_ZONE_H */
/** @} */

/*----------------------------------------------------------------------------*/


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
 * @defgroup query_ex Database top-level query function
 * @ingroup dnsdb
 * @brief Database top-level query function
 *
 *  Database top-level query function
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnsdb/zdb_query_to_wire_context.h>

/** @brief Appends the SOA record of the zone
 *
 * @param context the query context
 * @param zone the zone
 *
 * @returns 1 (the number of records added)
 */

uint16_t zdb_query_to_wire_append_soa(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone);

/** @brief Appends the SOA record of the zone and its signature
 *
 * @param context the query context
 * @param zone the zone
 *
 * @returns the number of records added
 */

uint16_t zdb_query_to_wire_append_soa_rrsig(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone);

/** @brief Appends the SOA record of the zone
 *
 * if the TTL is bigger than min TTL, then use min TTL
 *
 * @param context the query context
 * @param zone the zone
 *
 * @return 1 (the number of records added)
 */


uint16_t zdb_query_to_wire_append_soa_nttl(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone);

/** @brief Appends the SOA record of the zone and its signature
 *
 * if the TTL is bigger than min TTL, then use min TTL
 *
 * @param context the query context
 * @param zone the zone
 *
 * @return the number of records added
 */


uint16_t     zdb_query_to_wire_append_soa_rrsig_nttl(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone);

/** @brief Appends the SOA for an NXDOMAIN answer
 *
 * if the query record type is SOA, TTL = 0
 * if the SOA record TTL > min TTL, uses min TTL
 *
 * @param context the query context
 * @param zone the zone
 *
 * @return 1 (the number of records added)
 */

uint16_t     zdb_query_to_wire_append_soa_nodata_nxdomain(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone);

/** @brief Appends the SOA and its signature for an NXDOMAIN answer
 *
 * if the query record type is SOA, TTL = 0
 * if the SOA record TTL > min TTL, uses min TTL
 *
 * @param context the query context
 * @param zone the zone
 *
 * @return 1 (the number of records added)
 */

uint16_t zdb_query_to_wire_append_soa_rrsig_nodata_nxdomain(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone);

typedef void zdb_query_to_wire_append_soa_authority_method(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, bool dnssec);

void         zdb_query_to_wire_append_soa_authority_nttl(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, bool dnssec);

void         zdb_query_to_wire_append_soa_authority(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, bool dnssec);

/** @} */

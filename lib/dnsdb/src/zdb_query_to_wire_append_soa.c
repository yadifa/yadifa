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

#include "dnsdb/zdb_query_to_wire.h"
#include "dnsdb/zdb_query_to_wire_append_type_rrsigs.h"
#include "dnsdb/zdb_zone.h"

/** @brief Appends the SOA record of the zone
 *
 * @param context the query context
 * @param zone the zone
 *
 * @returns 1 (the number of records added)
 */

uint16_t zdb_query_to_wire_append_soa(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone)
{
    yassert(zone != NULL);

    zdb_resource_record_set_t        *soa_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_SOA);
    const zdb_resource_record_data_t *soa_rr = zdb_resource_record_set_record_get_const(soa_rrset, 0);

    int32_t                           ttl = zdb_resource_record_set_ttl(soa_rrset);

    dns_packet_writer_add_fqdn(&context->pw, zone->origin);
    dns_packet_writer_add_u16(&context->pw, TYPE_SOA);
    dns_packet_writer_add_u16(&context->pw, CLASS_IN);
    dns_packet_writer_add_u32(&context->pw, htonl(ttl));
    uint16_t offset = context->pw.packet_offset;
    context->pw.packet_offset += 2;
    const uint8_t *rname = zdb_resource_record_data_rdata_const(soa_rr);
    const uint8_t *mname = rname + dnsname_len(rname);
    const uint8_t *data = mname + dnsname_len(mname);
    dns_packet_writer_add_fqdn(&context->pw, rname);
    dns_packet_writer_add_fqdn(&context->pw, mname);
    dns_packet_writer_add_bytes(&context->pw, data, 20);
    dns_packet_writer_set_u16(&context->pw, htons(context->pw.packet_offset - offset - 2), offset);

    return 1;
}

/** @brief Appends the SOA record of the zone and its signature
 *
 * @param context the query context
 * @param zone the zone
 *
 * @returns the number of records added
 */

uint16_t zdb_query_to_wire_append_soa_rrsig(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone)
{
    yassert(zone != NULL);

    zdb_resource_record_set_t        *soa_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_SOA);
    const zdb_resource_record_data_t *soa_rr = zdb_resource_record_set_record_get_const(soa_rrset, 0);

    int32_t                           ttl = zdb_resource_record_set_ttl(soa_rrset);

    dns_packet_writer_add_fqdn(&context->pw, zone->origin);
    dns_packet_writer_add_u16(&context->pw, TYPE_SOA);
    dns_packet_writer_add_u16(&context->pw, CLASS_IN);
    dns_packet_writer_add_u32(&context->pw, htonl(ttl));
    uint16_t offset = context->pw.packet_offset;
    context->pw.packet_offset += 2;
    const uint8_t *rname = zdb_resource_record_data_rdata_const(soa_rr);
    const uint8_t *mname = rname + dnsname_len(rname);
    const uint8_t *data = mname + dnsname_len(mname);
    dns_packet_writer_add_fqdn(&context->pw, rname);
    dns_packet_writer_add_fqdn(&context->pw, mname);
    dns_packet_writer_add_bytes(&context->pw, data, 20);
    dns_packet_writer_set_u16(&context->pw, htons(context->pw.packet_offset - offset - 2), offset);

    uint16_t count = zdb_query_to_wire_append_type_rrsigs(context, zone->apex, zone->origin, TYPE_SOA, ttl) + 1;
    return count;
}

/** @brief Appends the SOA record of the zone
 *
 * if the TTL is bigger than min TTL, then use min TTL
 *
 * @param context the query context
 * @param zone the zone
 *
 * @return 1 (the number of records added)
 */

uint16_t zdb_query_to_wire_append_soa_nttl(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone)
{
    yassert(zone != NULL);

    zdb_resource_record_set_t        *soa_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_SOA);
    const zdb_resource_record_data_t *soa_rr = zdb_resource_record_set_record_get_const(soa_rrset, 0);

    int32_t                           soa_ttl;
    soa_ttl = zdb_resource_record_set_ttl(soa_rrset);
    int32_t min_ttl;
    zdb_zone_getminttl(zone, &min_ttl);
    if(soa_ttl > min_ttl)
    {
        soa_ttl = min_ttl;
    }

    dns_packet_writer_add_fqdn(&context->pw, zone->origin);
    dns_packet_writer_add_u16(&context->pw, TYPE_SOA);
    dns_packet_writer_add_u16(&context->pw, CLASS_IN);
    dns_packet_writer_add_u32(&context->pw, htonl(soa_ttl));
    uint16_t offset = context->pw.packet_offset;
    context->pw.packet_offset += 2;
    const uint8_t *rname = zdb_resource_record_data_rdata_const(soa_rr);
    const uint8_t *mname = rname + dnsname_len(rname);
    const uint8_t *data = mname + dnsname_len(mname);
    dns_packet_writer_add_fqdn(&context->pw, rname);
    dns_packet_writer_add_fqdn(&context->pw, mname);
    dns_packet_writer_add_bytes(&context->pw, data, 20);
    dns_packet_writer_set_u16(&context->pw, htons(context->pw.packet_offset - offset - 2), offset);

    return 1;
}

/** @brief Appends the SOA record of the zone and its signature
 *
 * if the TTL is bigger than min TTL, then use min TTL
 *
 * @param context the query context
 * @param zone the zone
 *
 * @return the number of records added
 */

uint16_t zdb_query_to_wire_append_soa_rrsig_nttl(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone)
{
    yassert(zone != NULL);

    zdb_resource_record_set_t        *soa_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_SOA);
    const zdb_resource_record_data_t *soa_rr = zdb_resource_record_set_record_get_const(soa_rrset, 0);
    int32_t                           soa_ttl = zdb_resource_record_set_ttl(soa_rrset);
    int32_t min_ttl;
    zdb_zone_getminttl(zone, &min_ttl);
    if(soa_ttl > min_ttl)
    {
        soa_ttl = min_ttl;
    }

    dns_packet_writer_t *pw = &context->pw;

    uint16_t             last_good_offset = pw->packet_offset;

    if(FAIL(dns_packet_writer_add_fqdn(pw, zone->origin)))
    {
        dns_packet_writer_set_truncated(pw);
        return 0;
    }

    if(dns_packet_writer_get_remaining_capacity(pw) < 10 + zdb_resource_record_data_rdata_size(soa_rr))
    {
        dns_packet_writer_set_truncated(pw);
        pw->packet_offset = last_good_offset;
        return 0;
    }

    dns_packet_writer_add_u16(pw, TYPE_SOA);
    dns_packet_writer_add_u16(pw, CLASS_IN);
    dns_packet_writer_add_u32(pw, htonl(soa_ttl));
    uint16_t offset = context->pw.packet_offset;
    context->pw.packet_offset += 2;
    const uint8_t *rname = zdb_resource_record_data_rdata_const(soa_rr);
    const uint8_t *mname = rname + dnsname_len(rname);
    const uint8_t *data = mname + dnsname_len(mname);
    if(FAIL(dns_packet_writer_add_fqdn(pw, rname)))
    {
        dns_packet_writer_set_truncated(pw);
        pw->packet_offset = last_good_offset;
        return 0;
    }
    if(FAIL(dns_packet_writer_add_fqdn(pw, mname)))
    {
        dns_packet_writer_set_truncated(pw);
        pw->packet_offset = last_good_offset;
        return 0;
    }
    if(dns_packet_writer_get_remaining_capacity(pw) < 20)
    {
        dns_packet_writer_set_truncated(pw);
        pw->packet_offset = last_good_offset;
        return 0;
    }

    dns_packet_writer_add_bytes(pw, data, 20);
    dns_packet_writer_set_u16(pw, htons(context->pw.packet_offset - offset - 2), offset);

    uint16_t count = zdb_query_to_wire_append_type_rrsigs(context, zone->apex, zone->origin, TYPE_SOA, soa_ttl) + 1;

    return count;
}

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

uint16_t zdb_query_to_wire_append_soa_nodata_nxdomain(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone)
{
    yassert(zone != NULL);

    zdb_resource_record_set_t        *soa_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_SOA);
    const zdb_resource_record_data_t *soa_rr = zdb_resource_record_set_record_get_const(soa_rrset, 0);

    int32_t soa_ttl;
    int32_t min_ttl;
    zdb_zone_getminttl(zone, &min_ttl);
    soa_ttl = zdb_resource_record_set_ttl(soa_rrset);

    if(context->record_type != TYPE_SOA)
    {
        if(soa_ttl > min_ttl)
        {
            soa_ttl = min_ttl;
        }
    }
    else
    {
        soa_ttl = 0;
    }

    dns_packet_writer_add_fqdn(&context->pw, zone->origin);
    dns_packet_writer_add_u16(&context->pw, TYPE_SOA);
    dns_packet_writer_add_u16(&context->pw, CLASS_IN);
    dns_packet_writer_add_u32(&context->pw, htonl(soa_ttl));
    uint16_t offset = context->pw.packet_offset;
    context->pw.packet_offset += 2;
    const uint8_t *rname = zdb_resource_record_data_rdata_const(soa_rr);
    const uint8_t *mname = rname + dnsname_len(rname);
    const uint8_t *data = mname + dnsname_len(mname);
    dns_packet_writer_add_fqdn(&context->pw, rname);
    dns_packet_writer_add_fqdn(&context->pw, mname);
    dns_packet_writer_add_bytes(&context->pw, data, 20);
    dns_packet_writer_set_u16(&context->pw, htons(context->pw.packet_offset - offset - 2), offset);

    return 1;
}

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

uint16_t zdb_query_to_wire_append_soa_rrsig_nodata_nxdomain(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone)
{
    yassert(zone != NULL);

    zdb_resource_record_set_t        *soa_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_SOA);
    const zdb_resource_record_data_t *soa_rr = zdb_resource_record_set_record_get_const(soa_rrset, 0);

    int32_t soa_ttl;
    int32_t min_ttl;
    zdb_zone_getminttl(zone, &min_ttl);
    soa_ttl = zdb_resource_record_set_ttl(soa_rrset);

    if(context->record_type != TYPE_SOA)
    {
        if(soa_ttl > min_ttl)
        {
            soa_ttl = min_ttl;
        }
    }
    else
    {
        soa_ttl = 0;
    }

    dns_packet_writer_add_fqdn(&context->pw, zone->origin);
    dns_packet_writer_add_u16(&context->pw, TYPE_SOA);
    dns_packet_writer_add_u16(&context->pw, CLASS_IN);
    dns_packet_writer_add_u32(&context->pw, htonl(soa_ttl));
    uint16_t offset = context->pw.packet_offset;
    context->pw.packet_offset += 2;
    const uint8_t *rname = zdb_resource_record_data_rdata_const(soa_rr);
    const uint8_t *mname = rname + dnsname_len(rname);
    const uint8_t *data = mname + dnsname_len(mname);
    dns_packet_writer_add_fqdn(&context->pw, rname);
    dns_packet_writer_add_fqdn(&context->pw, mname);
    dns_packet_writer_add_bytes(&context->pw, data, 20);
    dns_packet_writer_set_u16(&context->pw, htons(context->pw.packet_offset - offset - 2), offset);

    uint16_t count = zdb_query_to_wire_append_type_rrsigs(context, zone->apex, zone->origin, TYPE_SOA, soa_ttl) + 1;

    return count;
}


void zdb_query_to_wire_append_soa_authority_nttl(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, bool dnssec)
{
    if(!dnssec)
    {
        context->authority_count += zdb_query_to_wire_append_soa_nttl(context, zone);
    }
    else
    {
        context->authority_count += zdb_query_to_wire_append_soa_rrsig_nttl(context, zone);
    }
}

void zdb_query_to_wire_append_soa_authority(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, bool dnssec)
{
    if(!dnssec)
    {
        context->authority_count += zdb_query_to_wire_append_soa(context, zone);
    }
    else
    {
        context->authority_count += zdb_query_to_wire_append_soa_rrsig(context, zone);
    }
}

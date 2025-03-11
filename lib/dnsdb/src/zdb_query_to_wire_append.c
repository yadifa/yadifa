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

#include <dnsdb/zdb_rr_label.h>
#include <dnsdb/zdb_query_to_wire_append_soa.h>
#include <dnsdb/zdb_query_to_wire_append_type_rrsigs.h>
#include "dnsdb/zdb_query_to_wire_append.h"

/**
 * @brief Returns the label for the dns_name, relative to the apex of the zone
 *
 * @param zone the zone
 * @param dns_name the name of the label to find
 *
 * @return a pointer the label
 *
 * 2 uses
 */

static zdb_rr_label_t *zdb_query_to_wire_rr_label_find_relative(const zdb_zone_t *zone, const uint8_t *dns_name)
{
    /*
     * Get the relative path
     */

    const dnslabel_vector_reference_t origin = (const dnslabel_vector_reference_t)zone->origin_vector.labels;
    int32_t                           origin_top = zone->origin_vector.size;

    dnslabel_vector_t                 name;
    int32_t                           name_top = dnsname_to_dnslabel_vector(dns_name, name);
    if(name_top >= origin_top)
    {
        int32_t i;

        for(i = 0; i <= origin_top; i++)
        {
            if(!dnslabel_equals(origin[origin_top - i], name[name_top - i]))
            {
                return NULL;
            }
        }

        /*
         * At this point we got the relative path, get the label
         *
         */

        zdb_rr_label_t *rr_label = zdb_rr_label_find(zone->apex, name, (name_top - origin_top) - 1);

        return rr_label;
    }
    else
    {
        return NULL;
    }
}

uint16_t zdb_query_to_wire_append_ns_from_rrset(zdb_query_to_wire_context_t *context, const uint8_t *label_fqdn, zdb_resource_record_set_t *ns_rrset)
{
#if ZDB_QUERY_TO_WIRE_USE_PACKET_RRSET_OPTIMISATION
    dns_packet_writer_add_rrset(&context->pw, label_fqdn, ns_rrset);
#else
    int32_t                                ne_ttl = htonl(zdb_resource_record_set_ttl(ns_rrset));

    zdb_resource_record_set_const_iterator iter;
    zdb_resource_record_set_const_iterator_init(ns_rrset, &iter);
    while(zdb_resource_record_set_const_iterator_has_next(&iter))
    {
        const zdb_resource_record_data_t *ns_rr = zdb_resource_record_set_const_iterator_next(&iter);

        dns_packet_writer_add_fqdn(&context->pw, label_fqdn);
        dns_packet_writer_add_u16(&context->pw, TYPE_NS);
        dns_packet_writer_add_u16(&context->pw, CLASS_IN);
        dns_packet_writer_add_u32(&context->pw, ne_ttl);
        uint16_t offset = context->pw.packet_offset;
        context->pw.packet_offset += 2;
        dns_packet_writer_add_fqdn(&context->pw, zdb_resource_record_data_rdata_const(ns_rr));
        dns_packet_writer_set_u16(&context->pw, htons(context->pw.packet_offset - offset - 2), offset);
    }
#endif
    return zdb_resource_record_set_size(ns_rrset);
}

/**
 * @brief Appends NS records to a section
 *
 * Appends NS records from the label to the referenced section
 * Also appends RRSIG for these NS
 *
 * @param qname
 * @param rr_label_info
 * @param headp a pointer to the section list
 * @param pool the memory pool
 * @param dnssec dnssec enabled or not
 *
 * 3 uses
 */

uint16_t zdb_query_to_wire_append_authority(zdb_query_to_wire_context_t *context, const uint8_t *qname, const zdb_rr_label_find_ext_data *rr_label_info, bool dnssec)
{
    zdb_resource_record_set_t *authority_rrset = zdb_resource_record_sets_find(&rr_label_info->authority->resource_record_set, TYPE_NS);

    if(authority_rrset != NULL)
    {
        int32_t i = rr_label_info->authority_index;

        while(i > 0)
        {
            qname += qname[0] + 1;
            i--;
        }

        assert(context->ns_rrset_count < ZDB_QUERY_TO_WIRE_CONTEXT_NS_RRSET_COUNT_MAX);
        context->ns_rrsets[context->ns_rrset_count++] = authority_rrset;
        uint16_t count = zdb_query_to_wire_append_ns_from_rrset(context, qname, authority_rrset);

#if ZDB_HAS_DNSSEC_SUPPORT
        if(dnssec)
        {
            count += zdb_query_to_wire_append_type_rrsigs(context, rr_label_info->authority, qname, TYPE_NS, zdb_resource_record_set_ttl(authority_rrset));
            zdb_resource_record_set_t *ds_rrset = zdb_resource_record_sets_find(&rr_label_info->authority->resource_record_set, TYPE_DS);

            if(ds_rrset != NULL)
            {
                count = zdb_query_to_wire_append_from_rrset(context, qname, ds_rrset);
                count += zdb_query_to_wire_append_type_rrsigs(context, rr_label_info->authority, qname, TYPE_DS, zdb_resource_record_set_ttl(ds_rrset));
            }
        }
#endif

        return count;
    }
    else
    {
        return 0;
    }
}

/**
 * @brief Appends all the IPs (A & AAAA) under a name on the given zone
 *
 * @param zone the zone
 * @param dns_name the name of the label to find
 * @param zclass (if more than one class is supported in the database)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 * @param dnssec dnssec enabled or not
 *
 * 1 use
 */

uint16_t zdb_query_to_wire_append_ips(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const uint8_t *dns_name, bool dnssec)
{
    /* Find relatively from the zone */
    yassert(dns_name != NULL);

    uint16_t        count = 0;

    zdb_rr_label_t *rr_label = zdb_query_to_wire_rr_label_find_relative(zone, dns_name);

    if(rr_label != NULL)
    {
        /* Get the label, instead of the type in the label */
        zdb_resource_record_set_t *a_rrset = zdb_resource_record_sets_find(&rr_label->resource_record_set, TYPE_A);

        if(a_rrset != NULL)
        {
            count += zdb_query_to_wire_append_from_rrset(context, dns_name, a_rrset);

#if ZDB_HAS_DNSSEC_SUPPORT
            if(dnssec)
            {
                count += zdb_query_to_wire_append_type_rrsigs(context, rr_label, dns_name, TYPE_A, zdb_resource_record_set_ttl(a_rrset));
            }
#endif
        }

        zdb_resource_record_set_t *aaaa_rrset = zdb_resource_record_sets_find(&rr_label->resource_record_set, TYPE_AAAA);

        if(aaaa_rrset != NULL)
        {
            count += zdb_query_to_wire_append_from_rrset(context, dns_name, aaaa_rrset);
#if ZDB_HAS_DNSSEC_SUPPORT
            if(dnssec)
            {
                count += zdb_query_to_wire_append_type_rrsigs(context, rr_label, dns_name, TYPE_AAAA, zdb_resource_record_set_ttl(aaaa_rrset));
            }
#endif
        }
    }

    return count;
}

uint16_t zdb_query_to_wire_append_glues_from_ns(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const zdb_resource_record_set_t *ns_rrset, bool dnssec)
{
    uint16_t count = 0;

    if(ns_rrset != NULL)
    {
        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(ns_rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *ns_record = zdb_resource_record_set_const_iterator_next(&iter);

            count += zdb_query_to_wire_append_ips(context, zone, zdb_resource_record_data_rdata_const(ns_record), dnssec);
        }
    }

    return count;
}

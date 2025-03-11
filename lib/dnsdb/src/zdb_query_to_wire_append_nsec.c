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

#include "dnsdb/zdb_query_to_wire_append_nsec.h"
#include "dnsdb/zdb_query_to_wire_append_type_rrsigs.h"
#include "dnsdb/nsec.h"

/** @brief Appends the NSEC interval for the given name
 *
 * At the end
 *
 * @param zone the zone
 * @param name the name path
 * @param dups the label that cannot be added (used for wildcards)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 3 uses
 */
uint16_t zdb_query_to_wire_append_nsec_interval(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const dnsname_vector_t *name, const zdb_rr_label_t *rr_label)
{
    zdb_rr_label_t *nsec_interval_label;

    uint8_t         nsec_dnsname[DOMAIN_LENGTH_MAX];

    if(zone->nsec.nsec != NULL)
    {
        nsec_interval_label = nsec_find_interval_and_name(zone, name, nsec_dnsname);

        yassert(nsec_interval_label != NULL);

        if(nsec_interval_label != rr_label)
        {
            int32_t                     nsec_ttl;
            zdb_resource_record_data_t *nsec_interval_label_nsec = zdb_resource_record_sets_find_nsec_and_ttl(&nsec_interval_label->resource_record_set, &nsec_ttl);

            if(nsec_interval_label_nsec != NULL)
            {
                int32_t min_ttl;
                zdb_zone_getminttl(zone, &min_ttl);
                if(nsec_ttl > min_ttl)
                {
                    nsec_ttl = min_ttl;
                }
                dns_packet_writer_add_fqdn(&context->pw, nsec_dnsname);
                dns_packet_writer_add_u16(&context->pw, TYPE_NSEC);
                dns_packet_writer_add_u16(&context->pw, CLASS_IN);
                dns_packet_writer_add_u32(&context->pw, htonl(nsec_ttl));
                dns_packet_writer_add_u16(&context->pw, htons(zdb_resource_record_data_rdata_size(nsec_interval_label_nsec)));
                dns_packet_writer_add_bytes(&context->pw, zdb_resource_record_data_rdata_const(nsec_interval_label_nsec), zdb_resource_record_data_rdata_size(nsec_interval_label_nsec));

                return zdb_query_to_wire_append_type_rrsigs(context, nsec_interval_label, nsec_dnsname, TYPE_NSEC, nsec_ttl) + 1;
            }
        }
    }

    return 0;
}

/**
 * @brief Appends the NSEC records of a label to the section
 *
 * @param rr_label the covered label
 * @param qname the owner name
 * @param min_ttl the minimum ttl (OBSOLETE)
 * @param zclass (if more than one class is supported in the database)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 2 uses
 */
uint16_t zdb_query_to_wire_append_nsec_records(zdb_query_to_wire_context_t *context, const zdb_rr_label_t *rr_label, const uint8_t *restrict qname)
{
    zdb_resource_record_set_t *nsec_rrset = zdb_resource_record_sets_find(&rr_label->resource_record_set, TYPE_NSEC);

    if(nsec_rrset != NULL)
    {
        uint16_t count = zdb_query_to_wire_append_from_rrset(context, qname, nsec_rrset);
        count += zdb_query_to_wire_append_type_rrsigs(context, rr_label, qname, TYPE_NSEC, zdb_resource_record_set_ttl(nsec_rrset));
        return count;
    }

    return 0;
}

uint16_t zdb_query_to_wire_append_nsec_name_error(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const dnsname_vector_t *name, int32_t closest_index)
{
    /*uint32_t len;*/
    uint8_t encloser_nsec_name[DOMAIN_LENGTH_MAX + 2];
    uint8_t wild_encloser_nsec_name[DOMAIN_LENGTH_MAX + 2];
    uint8_t dname_inverted[DOMAIN_LENGTH_MAX + 2];

    dnslabel_stack_to_dnsname(name->labels, name->size, dname_inverted);
    nsec_node_t *node = nsec_find_interval_start(&zone->nsec.nsec, dname_inverted);

    if(node != NULL)
    {
        /*len = */ nsec_inverse_name(encloser_nsec_name, node->inverse_relative_name);

        zdb_resource_record_sets_node_t *nsec_rrset_node = zdb_resource_record_sets_set_find(&node->label->resource_record_set, TYPE_NSEC);

        uint16_t                         count = zdb_query_to_wire_append_from_rrset(context, encloser_nsec_name, &nsec_rrset_node->value);

        dnslabel_stack_to_dnsname(&name->labels[closest_index], name->size - closest_index, dname_inverted);

        nsec_node_t *wild_node = nsec_find_interval_start(&zone->nsec.nsec, dname_inverted);

        count += zdb_query_to_wire_append_type_rrsigs(context, node->label, encloser_nsec_name, TYPE_NSEC, zdb_resource_record_set_ttl(&nsec_rrset_node->value));

        if(wild_node != node)
        {
            /*len = */ nsec_inverse_name(wild_encloser_nsec_name, wild_node->inverse_relative_name);

            zdb_resource_record_sets_node_t *wild_nsec_rrset_node = zdb_resource_record_sets_set_find(&wild_node->label->resource_record_set, TYPE_NSEC);

            count += zdb_query_to_wire_append_from_rrset(context, wild_encloser_nsec_name, &wild_nsec_rrset_node->value);

            count += zdb_query_to_wire_append_type_rrsigs(context, wild_node->label, wild_encloser_nsec_name, TYPE_NSEC, zdb_resource_record_set_ttl(&wild_nsec_rrset_node->value));
        }

        return count;
    }
    else
    {
        return 0;
    }
}

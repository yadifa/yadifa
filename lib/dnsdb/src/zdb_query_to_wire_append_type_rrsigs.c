/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#include "dnsdb/zdb_query_to_wire_append_type_rrsigs.h"

/**
 * @brief Queries the database given a message
 *
 * @param context the context of the query
 * @param label the label of the RRSET
 * @param label_fqdn the fqdn of the RRSET
 * @param rtype the covered type
 * @param ttl the TTL of the covered RRSET
 *
 * RFC4034:
 *
 * The TTL value of an RRSIG RR MUST match the TTL value of the RRset it
 * covers.  This is an exception to the [RFC2181] rules for TTL values
 * of individual RRs within a RRset: individual RRSIG RRs with the same
 * owner name will have different TTL values if the RRsets they cover
 * have different TTL values.
 *
 * @return the number of records added
 */

uint16_t zdb_query_to_wire_append_type_rrsigs(zdb_query_to_wire_context_t *context, const zdb_rr_label_t *label, const uint8_t *label_fqdn, uint16_t rtype, int32_t ttl)
{
    zdb_resource_record_set_t *rrsig_rrset = zdb_resource_record_sets_find(&label->resource_record_set, TYPE_RRSIG);
    if(rrsig_rrset != NULL)
    {
        int32_t ne_ttl = htonl(ttl);

#if ZDB_QUERY_TO_WIRE_USE_PACKET_RRSET_OPTIMISATION
        ya_result ret = dns_packet_writer_add_rrset_rrsig(&context->pw, label_fqdn, rrsig_rrset, rtype, ne_ttl);
        return ret;
#else
        ya_result                              ret = 0;

        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(rrsig_rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *rrsig_record = zdb_resource_record_set_const_iterator_next(&iter);

            if(rrsig_get_type_covered_from_rdata(zdb_resource_record_data_rdata_const(rrsig_record), zdb_resource_record_data_rdata_size(rrsig_record)) == rtype)
            {
                dns_packet_writer_add_fqdn(&context->pw, label_fqdn);
                dns_packet_writer_add_u16(&context->pw, TYPE_RRSIG);
                dns_packet_writer_add_u16(&context->pw, CLASS_IN);
                dns_packet_writer_add_u32(&context->pw, ne_ttl);
                dns_packet_writer_add_u16(&context->pw, ntohs(zdb_resource_record_data_rdata_size(rrsig_record)));
                dns_packet_writer_add_bytes(&context->pw, zdb_resource_record_data_rdata_const(rrsig_record), zdb_resource_record_data_rdata_size(rrsig_record));
                ++ret;
            }
        }

        return ret;
#endif
    }
    else
    {
        return 0;
    }
}

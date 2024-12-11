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

#include <dnscore/dns_message.h>
#include <dnsdb/zdb_types.h>
#include <dnsdb/zdb_zone_resource_record_set.h>
#include <dnsdb/zdb_zone.h>

#define ZDB_QUERY_TO_WIRE_USE_PACKET_RRSET_OPTIMISATION 1

#define ZDB_QUERY_TO_WIRE_CONTEXT_NS_RRSET_COUNT_MAX    16

struct zdb_query_to_wire_context_s
{
    dns_packet_writer_t pw;
    dns_message_t      *mesg;
    const uint8_t      *fqdn;
#if DNSCORE_HAS_RRL_SUPPORT
    zdb_rr_label_t *fqdn_label;
#endif
    uint16_t                         flags;
    uint16_t                         record_type;
    uint16_t                         answer_count;
    uint16_t                         authority_count;
    uint16_t                         additional_count;
    uint8_t                          cname_count;
    uint8_t                          ns_rrset_count;
    bool                             delegation;
    bool                             additionals_required;
    const zdb_resource_record_set_t *ns_rrsets[ZDB_QUERY_TO_WIRE_CONTEXT_NS_RRSET_COUNT_MAX];
    const uint8_t                   *cname_list[ZDB_CNAME_LOOP_MAX];
};

typedef struct zdb_query_to_wire_context_s zdb_query_to_wire_context_t;

static inline void                         zdb_query_to_wire_context_set_truncated(zdb_query_to_wire_context_t *context) { dns_message_set_truncated_answer(context->mesg); }

static inline uint16_t                     zdb_query_to_wire_append_from_rrset(zdb_query_to_wire_context_t *context, const uint8_t *label_fqdn, zdb_resource_record_set_t *rrset)
{
#if ZDB_QUERY_TO_WIRE_USE_PACKET_RRSET_OPTIMISATION
    dns_packet_writer_add_rrset(&context->pw, label_fqdn, rrset);
#else
    int32_t                                ne_ttl = htonl(zdb_resource_record_set_ttl(rrset));

    zdb_resource_record_set_const_iterator iter;
    zdb_resource_record_set_const_iterator_init(rrset, &iter);
    while(zdb_resource_record_set_const_iterator_has_next(&iter))
    {
        const zdb_resource_record_data_t *rr = zdb_resource_record_set_const_iterator_next(&iter);

        dns_packet_writer_add_fqdn(&context->pw, label_fqdn);
        dns_packet_writer_add_u16(&context->pw, zdb_resource_record_set_type(rrset));
        dns_packet_writer_add_u16(&context->pw, CLASS_IN);
        dns_packet_writer_add_u32(&context->pw, ne_ttl);
        dns_packet_writer_add_u16(&context->pw, htons(zdb_resource_record_data_rdata_size(rr)));
        dns_packet_writer_add_bytes(&context->pw, zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr));
    }
#endif
    return zdb_resource_record_set_size(rrset);
}

/** @} */

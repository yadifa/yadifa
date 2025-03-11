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

#pragma once
#include "dnsdb/zdb_query_to_wire_context.h"
#include "dnsdb/zdb_rr_label.h"

uint16_t zdb_query_to_wire_append_ns_from_rrset(zdb_query_to_wire_context_t *context, const uint8_t *label_fqdn, zdb_resource_record_set_t *ns_rrset);

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

uint16_t zdb_query_to_wire_append_authority(zdb_query_to_wire_context_t *context, const uint8_t *qname, const zdb_rr_label_find_ext_data *rr_label_info, bool dnssec);

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

uint16_t zdb_query_to_wire_append_ips(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const uint8_t *dns_name, bool dnssec);

uint16_t zdb_query_to_wire_append_glues_from_ns(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const zdb_resource_record_set_t *ns_rrset, bool dnssec);

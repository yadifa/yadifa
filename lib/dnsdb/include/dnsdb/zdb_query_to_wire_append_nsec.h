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

uint16_t zdb_query_to_wire_append_nsec_interval(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const dnsname_vector_t *name, const zdb_rr_label_t *rr_label);

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

uint16_t zdb_query_to_wire_append_nsec_records(zdb_query_to_wire_context_t *context, const zdb_rr_label_t *rr_label, const uint8_t *restrict qname);

uint16_t zdb_query_to_wire_append_nsec_name_error(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const dnsname_vector_t *name, int32_t closest_index);

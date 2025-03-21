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
 * @defgroup nsec3 NSEC3 functions
 * @ingroup dnsdbdnssec
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnsdb/nsec3_types.h>
#include <dnscore/ptr_treemap.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * This struct and the five functions are handling the loading of the nsec3
 * records of a zone file.
 */

struct nsec3_load_context
{
    // based on the first bytes of the NSEC3(PARAM) record
    // contains an array of record
    ptr_vector_t  nsec3chain;
    ptr_treemap_t postponed_rrsig;
    void         *last_inserted_nsec3;
    zdb_zone_t   *zone;

    uint32_t      rrsig_added;
    uint32_t      rrsig_ignored;
    uint32_t      rrsig_discarded;

    uint32_t      nsec3_accepted;
    uint32_t      nsec3_rejected;
    uint32_t      nsec3_discarded;

    bool          opt_out;
    bool          can_fix;
    bool          fix_applied;
};

typedef struct nsec3_load_context nsec3_load_context;

typedef bool(nsec3_load_is_label_covered_function)(zdb_rr_label_t *);

bool               nsec3_load_is_label_covered(zdb_rr_label_t *label);
bool               nsec3_load_is_label_covered_optout(zdb_rr_label_t *label);

ya_result          nsec3_load_init(nsec3_load_context *context, zdb_zone_t *zone);

static inline void nsec3_load_allowed_to_fix(nsec3_load_context *context, bool can_fix) { context->can_fix = can_fix; }

void               nsec3_load_destroy(nsec3_load_context *context);

ya_result          nsec3_load_add_nsec3param(nsec3_load_context *context, const uint8_t *entry_rdata, uint16_t entry_rdata_size);
ya_result          nsec3_load_add_nsec3(nsec3_load_context *context, const uint8_t *base32hex_digest, int32_t entry_ttl, const uint8_t *entry_rdata, uint16_t entry_rdata_size);
ya_result          nsec3_load_add_rrsig(nsec3_load_context *context, const uint8_t *entry_name, int32_t entry_ttl, const uint8_t *entry_rdata, uint16_t entry_rdata_size);

ya_result          nsec3_load_add_nsec3chainstate(nsec3_load_context *context, const uint8_t *rdata, uint16_t rdata_size);

ya_result          nsec3_load_generate(nsec3_load_context *context);

bool               nsec3_load_is_context_empty(nsec3_load_context *context);

#ifdef __cplusplus
}
#endif

/** @} */

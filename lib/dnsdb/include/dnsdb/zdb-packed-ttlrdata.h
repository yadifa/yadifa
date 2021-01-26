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

/**
 * @brief database internal record type
 *
 * @{ */
#pragma once

#include <dnscore/dnskey-signature.h>
#include <dnsdb/zdb_types.h>

#define ZDBPTRVD_TAG 0x445652545042445a

struct zdb_packed_ttlrdata_record_view_data
{
    const u8 *fqdn;
    u16 rtype;
    u16 rclass;
    s32 rttl;
};

typedef struct zdb_packed_ttlrdata_record_view_data zdb_packed_ttlrdata_record_view_data;

void zdb_packed_ttlrdata_resource_record_view_init(struct resource_record_view *rrv);
void zdb_packed_ttlrdata_resource_record_view_set_fqdn(struct resource_record_view *rrv, const u8 *fqdn);
void zdb_packed_ttlrdata_resource_record_view_set_type(struct resource_record_view *rrv, u16 rtype);
void zdb_packed_ttlrdata_resource_record_view_set_class(struct resource_record_view *rrv, u16 rclass);
void zdb_packed_ttlrdata_resource_record_view_set_ttl(struct resource_record_view *rrv, s32 rttl);
void zdb_packed_ttlrdata_resource_record_view_finalize(struct resource_record_view *rrv);

zdb_packed_ttlrdata *zdb_packed_ttlrdata_clone(zdb_packed_ttlrdata *record);
void zdb_packed_ttlrdata_insert_clone(zdb_packed_ttlrdata **list_head, zdb_packed_ttlrdata *record);
void zdb_packed_ttlrdata_insert(zdb_packed_ttlrdata **list_head, zdb_packed_ttlrdata *new_head);

/** @} */

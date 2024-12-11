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

/*------------------------------------------------------------------------------
 * @brief database internal record type
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnscore/dnskey_signature.h>
#include <dnsdb/zdb_types.h>

#define ZDBPTRVD_TAG 0x445652545042445a

struct zdb_resource_record_data_record_view_data_s
{
    const uint8_t *fqdn;
    uint16_t       rtype;
    uint16_t       rclass;
    int32_t        rttl;
};

typedef struct zdb_resource_record_data_record_view_data_s zdb_resource_record_data_record_view_data_t;

void                                                       zdb_resource_record_data_resource_record_view_init(struct resource_record_view_s *rrv);
void                                                       zdb_resource_record_data_resource_record_view_set_fqdn(struct resource_record_view_s *rrv, const uint8_t *fqdn);
void                                                       zdb_resource_record_data_resource_record_view_set_type(struct resource_record_view_s *rrv, uint16_t rtype);
void                                                       zdb_resource_record_data_resource_record_view_set_class(struct resource_record_view_s *rrv, uint16_t rclass);
void                                                       zdb_resource_record_data_resource_record_view_set_ttl(struct resource_record_view_s *rrv, int32_t rttl);
void                                                       zdb_resource_record_data_resource_record_view_finalize(struct resource_record_view_s *rrv);

zdb_resource_record_data_t                                *zdb_resource_record_data_clone(zdb_resource_record_data_t *record);
void                                                       zdb_resource_record_data_insert_clone(zdb_resource_record_data_t **list_head, zdb_resource_record_data_t *record);
void                                                       zdb_resource_record_data_insert(zdb_resource_record_data_t **list_head, zdb_resource_record_data_t *new_head);

/** @} */

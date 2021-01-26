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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#pragma once

#include <dnsdb/zdb_types.h>

#define ZDB_ZONE_PROCESS_CONTINUE       0
#define ZDB_ZONE_PROCESS_SKIP_LABEL     1
#define ZDB_ZONE_PROCESS_STOP           2

struct zdb_zone_process_rrset_callback_parms;

typedef ya_result zdb_zone_process_rrset_callback(struct zdb_zone_process_rrset_callback_parms *parms);

struct zdb_zone_process_rrset_callback_parms
{
    zdb_zone_process_rrset_callback *cb;
    const zdb_zone *zone;
    void *args;
    const zdb_rr_label *rr_label;
    const zdb_packed_ttlrdata *rrset;
    u16 record_type;
    dnsname_stack fqdn_stack;
};

typedef struct zdb_zone_process_rrset_callback_parms zdb_zone_process_rrset_callback_parms;

struct zdb_zone_process_label_callback_parms;

typedef ya_result zdb_zone_process_label_callback(struct zdb_zone_process_label_callback_parms *parms);

struct zdb_zone_process_label_callback_parms
{
    zdb_zone_process_label_callback *cb;
    zdb_zone *zone;
    void *args;
    zdb_rr_label *rr_label;
    dnsname_stack fqdn_stack;
};

typedef struct zdb_zone_process_label_callback_parms zdb_zone_process_label_callback_parms;

/**
 * 
 * All zdb_rr_label of the zone will be passed to the callback
 * through a zdb_zone_process_label_callback_parms structure
 * 
 * @param zone
 * @param cb
 * @param args
 * @return 
 */

ya_result zdb_zone_process_all_labels_from_zone(zdb_zone *zone, zdb_zone_process_label_callback *cb, void *args);

/**
 * 
 * All zdb_packed_ttlrdata of all labels of the zone will be passed to the callback
 * through a zdb_zone_process_rrset_callback_parms
 * 
 * If the zone is NSEC3, the NSEC3 records and their signature will also be passed
 * with a virtual/fake (most likely on stack) zdb_rr_label and zdb_packed_ttlrdata
 * These are meant to be read-only
 * 
 * @param zone
 * @param cb
 * @param args
 * @return 
 */

ya_result zdb_zone_process_all_rrsets_from_all_labels_from_zone(zdb_zone *zone, zdb_zone_process_rrset_callback *cb, void *args);


/**
  @}
 */

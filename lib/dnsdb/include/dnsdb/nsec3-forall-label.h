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

#pragma once
#include <dnsdb/nsec3.h>

struct nsec3_forall_label_s;

typedef ya_result nsec3_forall_label_callback(struct nsec3_forall_label_s*);

struct nsec3_forall_label_s
{
    zdb_zone* zone;
    nsec3_forall_label_callback *callback;
    void *callback_args;    // 4 callback
    s32 label_stack_level;
    s32 name_len;
    s32 origin_len;
    unsigned int callback_need_fqdn:1,nsec3_covered:1,optout:1,can_ignore_signatures:1;
    s8 chain_index;
    u8 zone_lock_owner;     // typically: read
    u8 zone_reserved_owner; // typically: write
    bool last_call;
    zdb_rr_label *label_stack[128];
    u8 name[2 + MAX_DOMAIN_LENGTH];
};

typedef struct nsec3_forall_label_s nsec3_forall_label_s;

static inline zdb_rr_label* nsec3_forall_label_get_label(nsec3_forall_label_s *ctx)
{
    return ctx->label_stack[ctx->label_stack_level];
}

/**
 * This function goes through all the nsec3 database, ie: for updating/creating an nsec3param chain.
 * This is meant to be used in a background thread.
 */

void nsec3_forall_label(zdb_zone *zone, s8 chain_index, bool callback_need_fqdn, bool opt_out, bool can_ignore_signatures, u8 lock_owner, u8 reserved_owner, nsec3_forall_label_callback *callback, void *callback_args);

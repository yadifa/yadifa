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
 *  @defgroup dnskey DNSSEC keys functions
 *  @ingroup dnscorednssec
 *  @addtogroup dnskey DNSKEY functions
 *  @brief
 *
 *
 * @{
 */
#pragma once

#include <dnscore/dnskey.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/digest.h>

struct resource_record_view_vtbl
{
    const u8* (*get_fqdn)(void*, const void*);
    u16 (*get_type)(void*, const void*);
    u16 (*get_class)(void*, const void*);
    s32 (*get_ttl)(void*, const void*);
    u16 (*get_rdata_size)(void*, const void*);
    const u8* (*get_rdata)(void*, const void*);
    
    void *(*new_instance)(void*, const u8 *fqdn, u16 rtype, u16 rclass, s32 ttl, u16 rdata_size, const u8 *rdata);
};

typedef struct resource_record_view_vtbl resource_record_view_vtbl;

struct resource_record_view
{
    void *data; // passed as first parameter of the vtbl methods
    const struct resource_record_view_vtbl *vtbl;
};

typedef struct resource_record_view resource_record_view;

struct dnskey_signature
{
    ptr_vector *rrset_reference;
    resource_record_view *rr_view;
    u32 inception;
    u32 expiration;
    unsigned int is_canonised:1, has_digest:1, inception_set:1, expiration_set:1, reserved:4,
                key_algorithm:8,
                digest_size:8;
    //u8 digest_buffer[DIGEST_BUFFER_SIZE];
    digest_s digest_ctx;
};

typedef struct dnskey_signature dnskey_signature;

void dnskey_signature_init(dnskey_signature *ds);
void dnskey_signature_set_validity(dnskey_signature *ds, time_t from, time_t to);

/**
 * Sets the view that translates the content of the rrset ptr_vector.
 * The view is also responsible for generating rrsig records.
 */

void dnskey_signature_set_view(dnskey_signature *ds, resource_record_view *view);
void dnskey_signature_set_rrset_reference(dnskey_signature *ds, ptr_vector *rrset);
void dnskey_signature_set_canonised(dnskey_signature *ds, bool canonised);
ya_result dnskey_signature_sign(dnskey_signature *ds, const dnssec_key *key, void **out_rrsig_rr);
ya_result dnskey_signature_verify(dnskey_signature *ds, const dnssec_key *key, void *in_rrsig_rr);
void dnskey_signature_finalize(dnskey_signature *ds);

ya_result dnskey_sign_rrset_with_maxinterval(const dnssec_key *key, ptr_vector *rrset, bool canonize,
                                             resource_record_view *view, s32 maxinterval, void **out_rrsig);
//ya_result dnskey_signature_rrset_verify(dnskey_signature *ds, const dnssec_key *key, ptr_vector *rrset, resource_record_view *view);

/**
 * @}
 */

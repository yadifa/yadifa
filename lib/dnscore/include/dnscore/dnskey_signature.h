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
 * @defgroup dnskey DNSSEC keys functions
 * @ingroup dnscorednssec
 *  @addtogroup dnskey DNSKEY functions
 * @brief
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnscore/dnskey.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/digest.h>

struct resource_record_view_vtbl
{
    const uint8_t *(*get_fqdn)(void *, const void *);
    uint16_t (*get_type)(void *, const void *);
    uint16_t (*get_class)(void *, const void *);
    int32_t (*get_ttl)(void *, const void *);
    uint16_t (*get_rdata_size)(void *, const void *);
    const uint8_t *(*get_rdata)(void *, const void *);

    void *(*new_instance)(void *, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, uint16_t rdata_size, const uint8_t *rdata);
};

typedef struct resource_record_view_vtbl resource_record_view_vtbl;

struct resource_record_view_s
{
    void                                   *data; // passed as first parameter of the vtbl methods
    const struct resource_record_view_vtbl *vtbl;
};

typedef struct resource_record_view_s resource_record_view_t;

struct dnskey_signature_s
{
    ptr_vector_t           *rrset_reference;
    resource_record_view_t *rr_view;
    uint32_t                inception;
    uint32_t                expiration;
    unsigned int            is_canonised : 1, inception_set : 1, expiration_set : 1, reserved : 4, key_algorithm : 8;
    // note removed: uint32_t digest_size; /// @note 20211202 edf -- MUST be 32 bits to accomodate EDDSA
    // note removed: has_digest:1
    // note removed: digest_t digest_ctx;
};

typedef struct dnskey_signature_s dnskey_signature_t;

void                              dnskey_signature_init(dnskey_signature_t *ds);
void                              dnskey_signature_set_validity(dnskey_signature_t *ds, time_t from, time_t to);

/**
 * Sets the view that translates the content of the rrset ptr_vector.
 * The view is also responsible for generating rrsig records.
 */

void      dnskey_signature_set_view(dnskey_signature_t *ds, resource_record_view_t *view);
void      dnskey_signature_set_rrset_reference(dnskey_signature_t *ds, ptr_vector_t *rrset);
void      dnskey_signature_set_canonised(dnskey_signature_t *ds, bool canonised);
ya_result dnskey_signature_sign(dnskey_signature_t *ds, dnskey_t *key, void **out_rrsig_rr);
ya_result dnskey_signature_verify(dnskey_signature_t *ds, dnskey_t *key, void *in_rrsig_rr);
void      dnskey_signature_finalize(dnskey_signature_t *ds);

ya_result dnskey_sign_rrset_with_maxinterval(dnskey_t *key, ptr_vector_t *rrset, bool canonize, resource_record_view_t *view, int32_t maxinterval, void **out_rrsig);
// ya_result dnskey_signature_rrset_verify(dnskey_signature *ds, const dnskey_t *key, ptr_vector_t *rrset,
// resource_record_view *view);

/**
 * @}
 */

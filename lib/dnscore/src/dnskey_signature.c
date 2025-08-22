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
 * @defgroup dnskey DNSSEC keys functions
 * @ingroup dnscorednssec
 *  @addtogroup dnskey DNSKEY functions
 * @brief
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnskey_signature.h"
#include "dnscore/dnskey.h"
#include "dnscore/logger.h"
#include <openssl/err.h>

#define MODULE_MSG_HANDLE      g_system_logger

#define DEBUG_CRYPTO_INTERNALS 0

#if DEBUG_CRYPTO_INTERNALS
#pragma message("WARNING: DEBUG_CRYPTO_INTERNALS is not set to 0")
#endif

#if DEBUG_CRYPTO_INTERNALS
#define DNSKEY_SIGN_TIME_LENIENCY 0
#else
#define DNSKEY_SIGN_TIME_LENIENCY 86400
#endif

struct dnskey_signature_header
{
    // this part MUST match the 18 bytes of wire image of an RRSIG

    uint16_t type_covered;
    uint8_t  algorithm;
    uint8_t  labels;
    int32_t  original_ttl;

    uint32_t expiration;
    uint32_t inception; // 16 bytes
    uint16_t tag;       // 18
    uint8_t  fqdn_signature[];
};

union dnskey_signature_header_storage
{
#if DNSCORE_HAS_OQS_SUPPORT
    uint8_t rdata[65535];
#else
    uint8_t rdata[RRSIG_RDATA_HEADER_LEN + 256 + 2048];
#endif
    struct dnskey_signature_header header;
};

struct dnskey_signature_tctr
{
    uint16_t rtype;
    uint16_t rclass;
    int32_t  ttl;
    uint16_t rdata_size;
};

static int dnskey_signature_canonize_sort_record_view_rdata_compare(const void *a, const void *b, void *c)
{
    const uint8_t          *ptr_a = (const uint8_t *)a;
    const uint8_t          *ptr_b = (const uint8_t *)b;
    resource_record_view_t *view = (resource_record_view_t *)c;

    uint16_t                rr_a_size = view->vtbl->get_rdata_size(view->data, ptr_a);
    uint16_t                rr_b_size = view->vtbl->get_rdata_size(view->data, ptr_b);

    int                     ret;

    int                     diff_len = rr_a_size;
    diff_len -= rr_b_size;

    const uint8_t *rr_a_rdata = view->vtbl->get_rdata(view->data, ptr_a);
    const uint8_t *rr_b_rdata = view->vtbl->get_rdata(view->data, ptr_b);

    if(diff_len != 0)
    {
        uint16_t len = MIN(rr_a_size, rr_b_size);

        ret = memcmp(rr_a_rdata, rr_b_rdata, len);

        if(ret == 0)
        {
            ret = diff_len;
        }
    }
    else
    {
        ret = memcmp(rr_a_rdata, rr_b_rdata, rr_a_size);
    }

    return ret;
}

void dnskey_signature_init(dnskey_signature_t *ds) { ZEROMEMORY(ds, sizeof(*ds)); }

void dnskey_signature_set_validity(dnskey_signature_t *ds, time_t from, time_t to)
{
    if(from != ds->inception)
    {
        ds->inception = (uint32_t)from;
        ds->inception_set = 1;
    }
    if(to != ds->expiration)
    {
        ds->expiration = (uint32_t)to;
        ds->expiration_set = 1;
    }
}

void dnskey_signature_set_view(dnskey_signature_t *ds, resource_record_view_t *view)
{
    ds->rr_view = view;
    ds->is_canonised = 0;
}

void dnskey_signature_set_rrset_reference(dnskey_signature_t *ds, ptr_vector_t *rrset)
{
    ds->rrset_reference = rrset;
    ds->is_canonised = 0;
}

void dnskey_signature_set_canonised(dnskey_signature_t *ds, bool canonised) { ds->is_canonised = canonised ? 1 : 0; }

/**
 * out_rrsig_rr points to a mallocated dns_resource_record
 */

ya_result dnskey_signature_sign(dnskey_signature_t *ds, dnskey_t *key, void **out_rrsig_rr)
{
    uint8_t                              *signature;
    const void                           *rr0;
    const uint8_t                        *fqdn;
    size_t                                fqdn_len;
    const uint8_t                        *owner_fqdn;
    size_t                                owner_fqdn_len;

    struct dnskey_signature_tctr          tctr;
    bytes_signer_t                        bytes_signer;
    uint8_t                               fqdn_buffer[256];

    union dnskey_signature_header_storage hdr;

    if(key == NULL)
    {
        return INVALID_ARGUMENT_ERROR; // no key
    }

    if(!dnskey_is_private(key))
    {
        return DNSSEC_ERROR_KEYRING_KEY_IS_NOT_PRIVATE; // not private
    }

    if((ds->rrset_reference == NULL) || (ptr_vector_size(ds->rrset_reference) == 0))
    {
        return INVALID_ARGUMENT_ERROR; // empty set
    }

#if DEBUG || DEBUG_CRYPTO_INTERNALS
    memset(&hdr, 0xf5, sizeof(hdr));
#endif

    key->vtbl->signer_init(key, &bytes_signer);

    time_t                           inception = ds->inception;
    time_t                           expiration = ds->expiration /*dnskey_get_inactive_epoch(key)*/;

    ptr_vector_t                    *rrset = ds->rrset_reference;
    const resource_record_view_vtbl *view_vtbl = ds->rr_view->vtbl;
    void                            *data = ds->rr_view->data;

    rr0 = ptr_vector_get(rrset, 0);

    fqdn_len = dnsname_canonize(view_vtbl->get_fqdn(data, rr0), fqdn_buffer);
    fqdn = fqdn_buffer;

    hdr.header.labels = 0;

    if((fqdn[0] == 1) && (fqdn[1] == (uint8_t)'*'))
    {
        fqdn += *fqdn + 1;
    }

    while(fqdn[0] != 0)
    {
        ++hdr.header.labels;
        fqdn += *fqdn + 1;
    }

    fqdn = fqdn_buffer;

    owner_fqdn = dnskey_get_domain(key);
    owner_fqdn_len = dnsname_len(owner_fqdn);

    if(!ds->is_canonised && (ptr_vector_last_index(rrset) > 0))
    {

        ptr_vector_qsort_r(rrset, dnskey_signature_canonize_sort_record_view_rdata_compare, ds->rr_view);
        ds->is_canonised = 1;
    }

    hdr.header.type_covered = view_vtbl->get_type(data, rr0);
    hdr.header.algorithm = dnskey_get_algorithm(key);
    // hdr.header.labels has already been set
    hdr.header.original_ttl = htonl(view_vtbl->get_ttl(data, rr0));
    hdr.header.expiration = ntohl(expiration);
    hdr.header.inception = ntohl(inception);
    hdr.header.tag = htons(dnskey_get_tag_const(key));
    memcpy(&hdr.header.fqdn_signature[0], owner_fqdn,
           owner_fqdn_len); // VS false positive: more than enough room has been allocated on the stack
    signature = &hdr.header.fqdn_signature[owner_fqdn_len];

    tctr.rtype = hdr.header.type_covered;
    tctr.rclass = view_vtbl->get_class(data, rr0);
    tctr.ttl = hdr.header.original_ttl;

    size_t hdr_size = signature - (uint8_t *)&hdr;

#if DEBUG_CRYPTO_INTERNALS
    log_debug("dnskey_signature_sign: digest for %{dnsname} %{dnstype} and key tag %i", owner_fqdn, &hdr.header.type_covered, dnskey_get_tag_const(key));
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, &hdr, hdr_size, 32);
#endif

    bytes_signer.vtbl->update(&bytes_signer, &hdr, hdr_size);

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(rrset); ++i)
    {
        const void *rr = ptr_vector_get(rrset, i);

        bytes_signer.vtbl->update(&bytes_signer, fqdn, fqdn_len);

        uint16_t rdata_size = view_vtbl->get_rdata_size(data, rr);
        tctr.rdata_size = htons(rdata_size);

        const void *rdata = view_vtbl->get_rdata(data, rr);

#if DEBUG_CRYPTO_INTERNALS
        rdata_desc_t rdd = {tctr.rtype, rdata_size, rdata};
        log_debug("dnskey_signature_sign: #%i: %{dnsname} %i %{dnsclass} %{typerdatadesc}", i, fqdn, ntohl(tctr.ttl), &tctr.rclass, &rdd);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, fqdn, fqdn_len, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, &tctr, 2 + 2 + 4 + 2, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, rdata, rdata_size, 32);
#endif
        bytes_signer.vtbl->update(&bytes_signer, &tctr, 2 + 2 + 4 + 2);
        bytes_signer.vtbl->update(&bytes_signer, rdata, rdata_size);
    }

    uint8_t *signature_limit = (uint8_t *)&hdr;
    signature_limit += sizeof(hdr);

    uint32_t signature_size = signature_limit - signature;
    int32_t  signature_generated = bytes_signer.vtbl->sign(&bytes_signer, signature, &signature_size);
    bytes_signer.vtbl->finalise(&bytes_signer);

    if(ISOK(signature_generated))
    {
#if DEBUG_CRYPTO_INTERNALS
        log_debug("dnskey_signature_sign: signature value");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, signature, signature_size, 32);
#endif
        uint16_t rrsig_rdata_size = RRSIG_RDATA_HEADER_LEN + owner_fqdn_len + signature_size;
        void    *rrsig_rr = view_vtbl->new_instance(data, fqdn, TYPE_RRSIG, tctr.rclass, view_vtbl->get_ttl(data, rr0), rrsig_rdata_size, hdr.rdata);
        *out_rrsig_rr = rrsig_rr;
        return rrsig_rdata_size;
    }
    else
    {
        char buffer[1024];
        ERR_error_string_n(signature_size, buffer, sizeof(buffer));
        println(buffer);
        return ERROR;
    }
}

ya_result dnskey_signature_verify(dnskey_signature_t *ds, dnskey_t *key, void *in_rrsig_rr) // not tested
{
    const void                           *rr0;
    const uint8_t                        *fqdn;
    size_t                                fqdn_len;
    const uint8_t                        *owner_fqdn;
    size_t                                owner_fqdn_len;

    struct dnskey_signature_tctr          tctr;
    bytes_verifier_t                      bytes_verifier;
    uint8_t                               fqdn_buffer[256];

    union dnskey_signature_header_storage hdr;

    if(key == NULL)
    {
        return INVALID_ARGUMENT_ERROR; // no key
    }

    if((ds->rrset_reference == NULL) || (ptr_vector_size(ds->rrset_reference) == 0))
    {
        return INVALID_ARGUMENT_ERROR; // empty set
    }

    key->vtbl->verifier_init(key, &bytes_verifier);

    ptr_vector_t                    *rrset = ds->rrset_reference;
    const resource_record_view_vtbl *view_vtbl = ds->rr_view->vtbl;
    void                            *data = ds->rr_view->data;

    rr0 = ptr_vector_get(rrset, 0);

    fqdn_len = dnsname_canonize(view_vtbl->get_fqdn(data, rr0), fqdn_buffer);
    fqdn = fqdn_buffer;
    hdr.header.labels = 0;

    if((fqdn[0] == 1) && (fqdn[1] == (uint8_t)'*'))
    {
        fqdn += *fqdn + 1;
    }

    while(fqdn[0] != 0)
    {
        ++hdr.header.labels;
        fqdn += *fqdn + 1;
    }

    fqdn = fqdn_buffer;

    owner_fqdn = dnskey_get_domain(key);
    owner_fqdn_len = dnsname_len(owner_fqdn);

    if(!ds->is_canonised && (ptr_vector_last_index(rrset) > 0))
    {
        ptr_vector_qsort_r(rrset, dnskey_signature_canonize_sort_record_view_rdata_compare, ds->rr_view);
        ds->is_canonised = 1;
    }

    const uint8_t *rrsig_rdata = view_vtbl->get_rdata(data, in_rrsig_rr);
    /*u16 rrsig_rdata_size = */ view_vtbl->get_rdata_size(data, in_rrsig_rr);
    size_t hdr_size = &hdr.header.fqdn_signature[owner_fqdn_len] - (uint8_t *)&hdr;

    memcpy(hdr.rdata, rrsig_rdata, hdr_size);

    tctr.rtype = hdr.header.type_covered;
    tctr.rclass = view_vtbl->get_class(data, rr0);
    tctr.ttl = hdr.header.original_ttl;

#if DEBUG_CRYPTO_INTERNALS
    log_debug("dnskey_signature_verify: digest for %{dnsname} %{dnstype} and key tag %i", owner_fqdn, &hdr.header.type_covered, dnskey_get_tag_const(key));
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, &hdr, hdr_size, 32);
#endif

    bytes_verifier.vtbl->update(&bytes_verifier, &hdr, hdr_size);

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(rrset); ++i)
    {
        const void *rr = ptr_vector_get(rrset, i);
        bytes_verifier.vtbl->update(&bytes_verifier, fqdn, fqdn_len);

        uint16_t rdata_size = view_vtbl->get_rdata_size(data, rr);
        tctr.rdata_size = htons(rdata_size);

        const void *rdata = view_vtbl->get_rdata(data, rr);

#if DEBUG_CRYPTO_INTERNALS
        rdata_desc_t rdd = {tctr.rtype, rdata_size, rdata};
        log_debug("dnskey_signature_verify: #%i: %{dnsname} %i %{dnsclass} %{typerdatadesc}", i, fqdn, ntohl(tctr.ttl), &tctr.rclass, &rdd);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, fqdn, fqdn_len, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, &tctr, 2 + 2 + 4 + 2, 32);
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, rdata, rdata_size, 32);
#endif
        bytes_verifier.vtbl->update(&bytes_verifier, &tctr, 2 + 2 + 4 + 2);
        bytes_verifier.vtbl->update(&bytes_verifier, rdata, rdata_size);
    }

    const uint8_t *signature_rdata = view_vtbl->get_rdata(ds->rr_view->data, in_rrsig_rr);
    uint16_t       signature_rdata_size = view_vtbl->get_rdata_size(ds->rr_view->data, in_rrsig_rr);

    uint32_t       rrsig_signer_name_len = dnsname_len(rrsig_get_signer_name_from_rdata(signature_rdata, signature_rdata_size));
    uint32_t       rrsig_header_len = RRSIG_RDATA_HEADER_LEN + rrsig_signer_name_len;
    uint16_t       signature_size = signature_rdata_size - rrsig_header_len;

    const uint8_t *signature = &signature_rdata[rrsig_header_len];

#if DEBUG_CRYPTO_INTERNALS
    log_debug("dnskey_signature_verify: signature value");
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, signature, signature_size, 32);
#endif

    bool verified = bytes_verifier.vtbl->verify(&bytes_verifier, signature, signature_size);
    bytes_verifier.vtbl->finalise(&bytes_verifier);

#if DEBUG_CRYPTO_INTERNALS
    log_debug("dnskey_signature_verify: %s", (verified) ? "verified" : "wrong");
#endif

    return (verified) ? SUCCESS : ERROR;
}

void      dnskey_signature_finalize(dnskey_signature_t *ds) { (void)ds; }

ya_result dnskey_sign_rrset_with_maxinterval(dnskey_t *key, ptr_vector_t *rrset, bool canonize, resource_record_view_t *view, int32_t maxinterval, void **out_rrsig_rr)
{
    if(dnskey_is_private(key))
    {
        dnskey_signature_t ds;
        dnskey_signature_init(&ds);

        int32_t from_epoch = MAX(((int64_t)time(NULL)) - DNSKEY_SIGN_TIME_LENIENCY, 0);
        if(dnskey_has_explicit_activate(key))
        {
            from_epoch = MAX(from_epoch, dnskey_get_activate_epoch(key));
        }

        int32_t to_epoch = dnskey_get_inactive_epoch(key);

        // if the key will be inactive well after the maxinterval, use maxinterval to the life-time of the signature

        if(to_epoch - from_epoch > maxinterval + DNSKEY_SIGN_TIME_LENIENCY) // + 86400 : don't limit down for a small period of overhead
        {
            if(((int64_t)from_epoch + (int64_t)maxinterval) <= INT32_MAX) // check for doomsday
            {
                to_epoch = from_epoch + maxinterval;
            }
            else
            {
                log_warn("dnskey_sign_rrset_with_maxinterval(%{dnsname}, ..., %i, %p)", dnskey_get_domain(key), maxinterval, out_rrsig_rr);
                to_epoch = INT32_MAX;
            }
        }
        // else limit to the expiration time of the signature

        dnskey_signature_set_validity(&ds, from_epoch, to_epoch);
        dnskey_signature_set_view(&ds, view);
        dnskey_signature_set_rrset_reference(&ds, rrset);
        dnskey_signature_set_canonised(&ds, canonize);
        ya_result ret = dnskey_signature_sign(&ds, key, out_rrsig_rr);
        dnskey_signature_finalize(&ds);

        return ret;
    }
    else
    {
        return DNSSEC_ERROR_KEYRING_KEY_IS_NOT_PRIVATE;
    }
}

/*
ya_result
dnskey_signature_rrset_verify(dnskey_signature *ds, const dnskey_t *key, ptr_vector_t *rrset, resource_record_view
*view)
{
}
*/
/**
 * @}
 */

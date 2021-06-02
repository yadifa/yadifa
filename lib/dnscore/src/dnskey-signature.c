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

#include "dnscore/dnskey-signature.h"
#include "dnscore/dnskey.h"
#include "dnscore/logger.h"

#define MODULE_MSG_HANDLE g_system_logger

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
    
    u16 type_covered;
    u8 algorithm;
    u8 labels;
    s32 original_ttl;
    
    u32 expiration;
    u32 inception;          // 16 bytes
    u16 tag;                // 18
    u8 fqdn_signature[];
};

union dnskey_signature_header_storage
{
    u8 rdata[RRSIG_RDATA_HEADER_LEN + 256 + 2048];
    struct dnskey_signature_header header;
};

struct dnskey_signature_tctr
{
    u16 rtype;
    u16 rclass;
    s32 ttl;
    u16 rdata_size;
};

static int
dnskey_signature_canonize_sort_record_view_rdata_compare(const void *a, const void *b, void *c)
{
    const u8* ptr_a = (const u8*)a;
    const u8* ptr_b = (const u8*)b;
    resource_record_view *view = (resource_record_view*)c;
    
    u16 rr_a_size = view->vtbl->get_rdata_size(view->data, ptr_a);
    u16 rr_b_size = view->vtbl->get_rdata_size(view->data, ptr_b);

    int ret;

    int diff_len = rr_a_size;
    diff_len -= rr_b_size;
    
    const u8 *rr_a_rdata = view->vtbl->get_rdata(view->data, ptr_a);
    const u8 *rr_b_rdata = view->vtbl->get_rdata(view->data, ptr_b);

    if(diff_len != 0)
    {
        u16 len = MIN(rr_a_size, rr_b_size);
        
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

void
dnskey_signature_init(dnskey_signature *ds)
{
    ZEROMEMORY(ds, sizeof(*ds));
}

void dnskey_signature_set_validity(dnskey_signature *ds, time_t from, time_t to)
{
    if(from != ds->inception)
    {
        ds->inception = (u32)from;
        ds->has_digest = 0;
        ds->inception_set = 1;
    }
    if(to != ds->expiration)
    {
        ds->expiration = (u32)to;
        ds->has_digest = 0;
        ds->expiration_set = 1;
    }
}

void
dnskey_signature_set_view(dnskey_signature *ds, resource_record_view *view)
{
    ds->rr_view = view;
    ds->is_canonised = 0;
    ds->has_digest = 0;
}

void
dnskey_signature_set_rrset_reference(dnskey_signature *ds, ptr_vector *rrset)
{
    ds->rrset_reference = rrset;
    ds->is_canonised = 0;
    ds->has_digest = 0;
}

void
dnskey_signature_set_canonised(dnskey_signature *ds, bool canonised)
{
    ds->is_canonised = canonised?1:0;
}

/**
 * out_rrsig_rr points to a mallocated dns_resource_record
 */

ya_result
dnskey_signature_sign(dnskey_signature *ds, const dnssec_key *key, void **out_rrsig_rr)
{
    u8 *signature;
    const void *rr0;
    const u8 *fqdn;
    size_t fqdn_len;
    const u8* owner_fqdn;
    size_t owner_fqdn_len;
    digest_s *ctx_ptr = &ds->digest_ctx;
    ya_result ret;
    struct dnskey_signature_tctr tctr;
    u8 fqdn_buffer[256];
    
    union dnskey_signature_header_storage hdr;

    if(key == NULL)
    {
        return INVALID_ARGUMENT_ERROR;   // no key
    }
    
    if(!dnskey_is_private(key))
    {
        return DNSSEC_ERROR_KEYRING_KEY_IS_NOT_PRIVATE; // not private
    }
        
    if((ds->rrset_reference == NULL) || (ptr_vector_size(ds->rrset_reference) == 0))
    {
        return INVALID_ARGUMENT_ERROR;   // empty set
    }

#if DEBUG || DEBUG_CRYPTO_INTERNALS
    memset(&hdr, 0xf5, sizeof(hdr));
#endif

    time_t inception = ds->inception;
    time_t expiration = ds->expiration/*dnskey_get_inactive_epoch(key)*/;
    
    u8 key_algorithm = dnskey_get_algorithm(key);
    
    if(key_algorithm != ds->key_algorithm)
    {
        ds->has_digest = 0;
    }
    
    ptr_vector *rrset = ds->rrset_reference;
    const resource_record_view_vtbl *view_vtbl = ds->rr_view->vtbl;
    void *data = ds->rr_view->data;
    
    if(!ds->has_digest)
    {
        if(FAIL(ret = dnskey_digest_init(ctx_ptr, key_algorithm)))
        {
            return ret;
        }

        rr0 = ptr_vector_get(rrset, 0);
        
        fqdn_len = dnsname_canonize(view_vtbl->get_fqdn(data, rr0), fqdn_buffer);
        fqdn = fqdn_buffer;
        //dnsname_len(fqdn);
        hdr.header.labels = 0;

        if((fqdn[0] == 1) && (fqdn[1] == (u8)'*'))
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

        if(!ds->is_canonised)
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
        memcpy(&hdr.header.fqdn_signature[0], owner_fqdn, owner_fqdn_len); // VS false positive: more than enough room has been allocated on the stack
        signature = &hdr.header.fqdn_signature[owner_fqdn_len];

        tctr.rtype = hdr.header.type_covered;
        tctr.rclass = view_vtbl->get_class(data, rr0);
        tctr.ttl = hdr.header.original_ttl;
        
        size_t hdr_size = signature - (u8*)&hdr;

#if DEBUG_CRYPTO_INTERNALS
        log_debug("dnskey_signature_sign: digest for %{dnsname} %{dnstype} and key tag %i", owner_fqdn, &hdr.header.type_covered, dnskey_get_tag_const(key));
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, &hdr, hdr_size, 32);
#endif

        digest_update(ctx_ptr, &hdr, hdr_size);

        for(int i = 0; i <= ptr_vector_last_index(rrset); ++i)
        {
            const void *rr = ptr_vector_get(rrset, i);
            digest_update(ctx_ptr, fqdn, fqdn_len);

            u16 rdata_size = view_vtbl->get_rdata_size(data, rr);
            tctr.rdata_size = htons(rdata_size);
            
            const void *rdata = view_vtbl->get_rdata(data, rr);

#if DEBUG_CRYPTO_INTERNALS
            rdata_desc rdd = {tctr.rtype, rdata_size, rdata};
            log_debug("dnskey_signature_sign: #%i: %{dnsname} %i %{dnsclass} %{typerdatadesc}",
                    i, fqdn, ntohl(tctr.ttl), &tctr.rclass, &rdd);
            log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, fqdn, fqdn_len, 32);
            log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, &tctr, 2 + 2 + 4 + 2, 32);
            log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, rdata, rdata_size, 32);
#endif
            digest_update(ctx_ptr, &tctr, 2 + 2 + 4 + 2);
            digest_update(ctx_ptr, rdata, rdata_size);
        }

        s32 digest_size = digest_get_size(ctx_ptr);

        //digest_final_copy_bytes(ctx_ptr, ds->digest_buffer, sizeof(ds->digest_buffer));
        digest_final(ctx_ptr);
        
#if DEBUG_CRYPTO_INTERNALS
        log_debug("dnskey_signature_sign: digest value");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, digest_get_digest_ptr(ctx_ptr), digest_size, 32);
#endif
        
        ds->digest_size = digest_size;
        ds->has_digest = 1;
    }
    else
    {
        // digest has already been computed, only need to ready the signature,
        // the rr0 and the fqdn
        
#if DEBUG_CRYPTO_INTERNALS
        log_debug("dnskey_signature_sign: digest already computed");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, digest_get_digest_ptr(ctx_ptr), ds->digest_size, 32);
#endif
        
        owner_fqdn = dnskey_get_domain(key);
        owner_fqdn_len = dnsname_len(owner_fqdn);
        signature = &hdr.header.fqdn_signature[owner_fqdn_len];
        rr0 = ptr_vector_get(rrset, 0);
        fqdn = view_vtbl->get_fqdn(data, rr0);

        tctr.rtype = view_vtbl->get_type(data, rr0);
        tctr.rclass = view_vtbl->get_class(data, rr0);
        tctr.ttl = htonl(view_vtbl->get_ttl(data, rr0));
    }

    void *digest_ptr;
    digest_get_digest(ctx_ptr, &digest_ptr);
    s32 signature_size = key->vtbl->dnssec_key_sign_digest(key, digest_ptr, ds->digest_size, signature);

    if(ISOK(signature_size))
    {
#if DEBUG_CRYPTO_INTERNALS
        log_debug("dnskey_signature_sign: signature value");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, signature, signature_size, 32);
#endif
    
        u16 rrsig_rdata_size = RRSIG_RDATA_HEADER_LEN + owner_fqdn_len + signature_size;

        void *rrsig_rr = view_vtbl->new_instance(data, fqdn, TYPE_RRSIG, tctr.rclass, view_vtbl->get_ttl(data, rr0), rrsig_rdata_size, hdr.rdata);

        *out_rrsig_rr = rrsig_rr;

        return rrsig_rdata_size;
    }
    else
    {
        return signature_size;
    }
}


ya_result
dnskey_signature_verify(dnskey_signature *ds, const dnssec_key *key, void *in_rrsig_rr) // not tested
{
    const void *rr0;
    const u8 *fqdn;
    size_t fqdn_len;
    const u8* owner_fqdn;
    size_t owner_fqdn_len;
    digest_s *ctx_ptr = &ds->digest_ctx;
    ya_result ret;
    struct dnskey_signature_tctr tctr;
    u8 fqdn_buffer[256];

    union dnskey_signature_header_storage hdr;

    if(key == NULL)
    {
        return INVALID_ARGUMENT_ERROR;   // no key
    }

    if((ds->rrset_reference == NULL) || (ptr_vector_size(ds->rrset_reference) == 0))
    {
        return INVALID_ARGUMENT_ERROR;   // empty set
    }

    u8 key_algorithm = dnskey_get_algorithm(key);

    if(key_algorithm != ds->key_algorithm)
    {
        ds->has_digest = 0;
    }

    ptr_vector *rrset = ds->rrset_reference;
    const resource_record_view_vtbl *view_vtbl = ds->rr_view->vtbl;
    void *data = ds->rr_view->data;

    if(!ds->has_digest)
    {
        if(FAIL(ret = dnskey_digest_init(ctx_ptr, key_algorithm)))
        {
            return ret;
        }

        rr0 = ptr_vector_get(rrset, 0);

        fqdn_len = dnsname_canonize(view_vtbl->get_fqdn(data, rr0), fqdn_buffer);
        fqdn = fqdn_buffer;
        //dnsname_len(fqdn);
        hdr.header.labels = 0;

        if((fqdn[0] == 1) && (fqdn[1] == (u8)'*'))
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

        if(!ds->is_canonised)
        {
            ptr_vector_qsort_r(rrset, dnskey_signature_canonize_sort_record_view_rdata_compare, ds->rr_view);
            ds->is_canonised = 1;
        }

        const u8 *rrsig_rdata = view_vtbl->get_rdata(data, in_rrsig_rr);
        /*u16 rrsig_rdata_size = */ view_vtbl->get_rdata_size(data, in_rrsig_rr);
        size_t hdr_size = &hdr.header.fqdn_signature[owner_fqdn_len] - (u8*)&hdr;

        memcpy(hdr.rdata, rrsig_rdata, hdr_size);
        /*
        hdr.header.type_covered = htons(rrsig_get_type_covered_from_rdata(rrsig_rdata, rrsig_rdata_size));
        hdr.header.algorithm = rrsig_get_algorithm_from_rdata(rrsig_rdata, rrsig_rdata_size);
        // hdr.header.labels has already been set
        hdr.header.original_ttl = htonl(rrsig_get_original_ttl_from_rdata(rrsig_rdata, rrsig_rdata_size));
        hdr.header.expiration = ntohl(rrsig_get_valid_until_from_rdata(rrsig_rdata, rrsig_rdata_size));
        hdr.header.inception = ntohl(rrsig_get_valid_from_from_rdata(rrsig_rdata, rrsig_rdata_size));
        hdr.header.tag = htons(rrsig_get_key_tag_from_rdata(rrsig_rdata, rrsig_rdata_size));
        memcpy(&hdr.header.fqdn_signature[0], owner_fqdn, owner_fqdn_len);
        */
        tctr.rtype = hdr.header.type_covered;
        tctr.rclass = view_vtbl->get_class(data, rr0);
        tctr.ttl = hdr.header.original_ttl;

#if DEBUG_CRYPTO_INTERNALS
        log_debug("dnskey_signature_verify: digest for %{dnsname} %{dnstype} and key tag %i", owner_fqdn, &hdr.header.type_covered, dnskey_get_tag_const(key));
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, &hdr, hdr_size, 32);
#endif

        digest_update(ctx_ptr, &hdr, hdr_size);

        for(int i = 0; i <= ptr_vector_last_index(rrset); ++i)
        {
            const void *rr = ptr_vector_get(rrset, i);
            digest_update(ctx_ptr, fqdn, fqdn_len);

            u16 rdata_size = view_vtbl->get_rdata_size(data, rr);
            tctr.rdata_size = htons(rdata_size);

            const void *rdata = view_vtbl->get_rdata(data, rr);

#if DEBUG_CRYPTO_INTERNALS
            rdata_desc rdd = {tctr.rtype, rdata_size, rdata};
            log_debug("dnskey_signature_verify: #%i: %{dnsname} %i %{dnsclass} %{typerdatadesc}",
                      i, fqdn, ntohl(tctr.ttl), &tctr.rclass, &rdd);
            log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, fqdn, fqdn_len, 32);
            log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, &tctr, 2 + 2 + 4 + 2, 32);
            log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, rdata, rdata_size, 32);
#endif
            digest_update(ctx_ptr, &tctr, 2 + 2 + 4 + 2);
            digest_update(ctx_ptr, rdata, rdata_size);
        }

        s32 digest_size = digest_get_size(ctx_ptr);

        //digest_final_copy_bytes(ctx_ptr, ds->digest_buffer, sizeof(ds->digest_buffer));
        digest_final(ctx_ptr);

#if DEBUG_CRYPTO_INTERNALS
        log_debug("dnskey_signature_verify: digest value");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, digest_get_digest_ptr(ctx_ptr), digest_size, 32);
#endif

        ds->digest_size = digest_size;
        ds->has_digest = 1;
    }
    else
    {
        // digest has already been computed, only need to ready the signature,
        // the rr0 and the fqdn

#if DEBUG_CRYPTO_INTERNALS
        log_debug("dnskey_signature_verify: digest already computed");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, digest_get_digest_ptr(ctx_ptr), ds->digest_size, 32);
#endif
        /// @TODO 20210218 edf -- add optional signature verification")
        // owner_fqdn = dnskey_get_domain(key); // never read
        // owner_fqdn_len = dnsname_len(owner_fqdn); // never read
        //signature = &hdr.header.fqdn_signature[owner_fqdn_len];
        // rr0 = ptr_vector_get(rrset, 0); // never read
        // fqdn = view_vtbl->get_fqdn(data, rr0); // never read
    }

    const u8 *signature_rdata = view_vtbl->get_rdata(ds->rr_view->data, in_rrsig_rr);
    u16 signature_rdata_size = view_vtbl->get_rdata_size(ds->rr_view->data, in_rrsig_rr);

    u32 rrsig_signer_name_len = dnsname_len(rrsig_get_signer_name_from_rdata(signature_rdata, signature_rdata_size));
    u32 rrsig_header_len = RRSIG_RDATA_HEADER_LEN + rrsig_signer_name_len;
    u16 signature_size = signature_rdata_size - rrsig_header_len;

    const u8 *signature = &signature_rdata[rrsig_header_len];

#if DEBUG_CRYPTO_INTERNALS
    log_debug("dnskey_signature_verify: signature value");
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, signature, signature_size, 32);
#endif

    void *digest_ptr;
    digest_get_digest(ctx_ptr, &digest_ptr);
    bool verified = key->vtbl->dnssec_key_verify_digest(key, digest_ptr, ds->digest_size, signature, signature_size);

#if DEBUG_CRYPTO_INTERNALS
    log_debug("dnskey_signature_verify: %s", (verified)?"verified":"wrong");
#endif

    return (verified)?SUCCESS:ERROR;
}

void
dnskey_signature_finalize(dnskey_signature *ds)
{
    (void)ds;
}

ya_result
dnskey_sign_rrset_with_maxinterval(const dnssec_key *key, ptr_vector *rrset, bool canonize, resource_record_view *view,
                                   s32 maxinterval, void **out_rrsig_rr)
{
    if(dnskey_is_private(key))
    {
        dnskey_signature ds;
        dnskey_signature_init(&ds);

        s32 from_epoch = MAX(time(NULL) - 86400, 0);
        s32 to_epoch = dnskey_get_inactive_epoch(key);

        // if the key will be inactive well after the maxinterval, use maxinterval to the life-time of the signature

        if(to_epoch - from_epoch > maxinterval + DNSKEY_SIGN_TIME_LENIENCY) // + 86400 : don't limit down for a small period of overhead
        {
            if(((s64)from_epoch + (s64)maxinterval) <= MAX_S32)
            {
                to_epoch = from_epoch + maxinterval;
            }
            else
            {
                log_warn("dnskey_sign_rrset_with_maxinterval(%{dnsname}, ..., %i, %p)", dnskey_get_domain(key), maxinterval, out_rrsig_rr);
                to_epoch = MAX_S32;
            }
        }
        // else limit to the expiration time of the signature

        from_epoch -= DNSKEY_SIGN_TIME_LENIENCY;    // give some leniency for the validity start

        dnskey_signature_set_validity(&ds, from_epoch, to_epoch);
        dnskey_signature_set_view(&ds, view);
        dnskey_signature_set_rrset_reference(&ds, rrset);
        dnskey_signature_set_canonised(&ds, !canonize);
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
dnskey_signature_rrset_verify(dnskey_signature *ds, const dnssec_key *key, ptr_vector *rrset, resource_record_view *view)
{
}
*/
/**
 * @}
 */

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
 * @ingroup dnsdbdnssec
 * @brief
 *
 *  NOT DONE
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"
#include "dnscore/dnscore_config_features.h"

#if DNSCORE_HAS_ECDSA_SUPPORT

#include <stdio.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "dnscore/openssl.h"

#include "dnscore/dnscore_config.h"

#include "dnscore/sys_types.h"
#include "dnscore/base64.h"

#include "dnscore/dnskey.h"
#include "dnscore/dnskey_ecdsa.h"
#include "dnscore/dnssec_errors.h"

#include "dnscore/zalloc.h"
#include "dnscore/tools.h"
#include "dnscore/format.h"

#define MODULE_MSG_HANDLE g_system_logger

#define KEYECDSA_TAG      0x415344434559454b

#ifndef SSL_API
#error "SSL_API not defined"
#endif

#define DNSKEY_ALGORITHM_ECDSAP256SHA256_NID NID_X9_62_prime256v1
#define DNSKEY_ALGORITHM_ECDSAP384SHA384_NID NID_secp384r1

/*
 * Intermediary key
 */

struct dnskey_ecdsa_s
{
    dnskey_raw_field_t private_key;
};

struct dnskey_ecdsa_const_s
{
    const dnskey_raw_field_t private_key;
};

static void dnskey_ecdsa_init(struct dnskey_ecdsa_s *yecdsa) { memset(yecdsa, 0, sizeof(struct dnskey_ecdsa_s)); }

static void dnskey_ecdsa_finalize(struct dnskey_ecdsa_s *yecdsa)
{
    dnskey_raw_field_clean_finalize(&yecdsa->private_key);
    dnskey_ecdsa_init(yecdsa);
}

static const struct dnskey_field_access_s ECDSA_field_access_read[] = {{"PrivateKey", offsetof(struct dnskey_ecdsa_s, private_key), STRUCTDESCRIPTOR_RAW}, {"", 0, 0}};

static const struct dnskey_field_access_s ECDSA_field_access_write[] = {{"PrivateKey", offsetof(struct dnskey_ecdsa_s, private_key), STRUCTDESCRIPTOR_RAW}, {"", 0, 0}};

static int                                dnskey_ecdsa_getnid(uint8_t algorithm)
{
    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
        {
            return DNSKEY_ALGORITHM_ECDSAP256SHA256_NID;
        }
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
        {
            return DNSKEY_ALGORITHM_ECDSAP384SHA384_NID;
        }
        default:
        {
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        }
    }
}

static const char *dnskey_ecdsa_getgroup(uint8_t algorithm)
{
    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
        {
            // return "prime256v1";
            return "P-256";
        }
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
        {
            // return "secp384r1";
            return "P-384";
        }
        default:
        {
            return "ECDSA_ALGORITHM_NOT_SUPPORTED";
        }
    }
}

static int dnskey_ecdsa_nid_to_signature_bn_size(int nid)
{
    switch(nid)
    {
        case DNSKEY_ALGORITHM_ECDSAP256SHA256_NID:
        {
            return 32; // 64
        }
        case DNSKEY_ALGORITHM_ECDSAP384SHA384_NID:
        {
            return 48; // 96
        }
        default:
        {
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        }
    }
}

static int dnskey_ecdsa_algorithm_to_signature_bn_size(int nid)
{
    switch(nid)
    {
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
        {
            return 32; // 64
        }
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
        {
            return 48; // 96
        }
        default:
        {
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        }
    }
}

static EVP_PKEY *dnskey_ecdsa_genkey_by_nid(int nid)
{
    const int     id = EVP_PKEY_EC;

    EVP_PKEY     *evp_key = NULL;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(id, NULL);
    if(pctx != NULL)
    {
        if(EVP_PKEY_paramgen_init(pctx) > 0)
        {
            if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) > 0)
            {
                EVP_PKEY *params = NULL;

                if(EVP_PKEY_paramgen(pctx, &params) > 0)
                {
                    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
                    if(kctx != NULL)
                    {
                        if(EVP_PKEY_keygen_init(kctx) > 0)
                        {
                            if(EVP_PKEY_keygen(kctx, &evp_key) > 0)
                            {
                                // yay
                                // EVP_PKEY_dump_params(evp_key);
                            }
                        }

                        EVP_PKEY_CTX_free(kctx);
                    }

                    EVP_PKEY_free(params);
                }
            }
        }
        EVP_PKEY_CTX_free(pctx);
    }

    return evp_key;
}

static EVP_PKEY *dnskey_ecdsa_public_load(uint8_t algorithm, const uint8_t *rdata_key_bytes, uint16_t rdata_key_bytes_size)
{
    const int      id = EVP_PKEY_EC;
    const int      nid = dnskey_ecdsa_getnid(algorithm);
    const uint32_t x_y_len = dnskey_ecdsa_nid_to_signature_bn_size(nid);

    if((rdata_key_bytes == NULL) || (rdata_key_bytes_size != (x_y_len << 1)))
    {
        return NULL;
    }

    uint8_t x_y_ptr[128];
    /*
    bytes_copy_swap(x_y_ptr + 1, rdata + 4, x_y_len);
    bytes_copy_swap(x_y_ptr + 1 + x_y_len, rdata + 4 + x_y_len, x_y_len);
    */

    x_y_ptr[0] = POINT_CONVERSION_UNCOMPRESSED;
    memcpy(&x_y_ptr[1], rdata_key_bytes, x_y_len << 1);

    EVP_PKEY     *evp_key = NULL;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(id, NULL);
    if(pctx != NULL)
    {
        if(EVP_PKEY_paramgen_init(pctx) > 0)
        {
            if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) > 0)
            {
                EVP_PKEY *params = NULL;

                if(EVP_PKEY_paramgen(pctx, &params) > 0)
                {
                    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
                    if(kctx != NULL)
                    {
                        if(EVP_PKEY_fromdata_init(kctx) > 0)
                        {
                            OSSL_PARAM params[3] = {
                                OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)dnskey_ecdsa_getgroup(algorithm), 0), OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, x_y_ptr, (x_y_len << 1) + 1), OSSL_PARAM_END};

                            if(EVP_PKEY_fromdata(kctx, &evp_key, EVP_PKEY_PUBLIC_KEY, params) > 0)
                            {
                                // yay
                                // EVP_PKEY_dump_params(evp_key);
                            }
                            else
                            {
                                crypto_openssl_error();
                            }
                        }
                        else
                        {
                            crypto_openssl_error();
                        }

                        EVP_PKEY_CTX_free(kctx);
                    }

                    EVP_PKEY_free(params);
                }
            }
        }
        EVP_PKEY_CTX_free(pctx);
    }

    return evp_key;
}

static uint32_t ecdsa_public_store(const EVP_PKEY *ecdsa, uint8_t *output_buffer, uint32_t output_buffer_size)
{
    size_t  tmp_size = 0;
    uint8_t tmp[128];
    if(EVP_PKEY_get_octet_string_param(ecdsa, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, tmp, sizeof(tmp), &tmp_size) > 0)
    {
        --tmp_size;
        if(tmp_size <= output_buffer_size)
        {
            memcpy(output_buffer, &tmp[1], tmp_size);
            return tmp_size;
        }
    }
    return 0;
}

static uint32_t dnskey_ecdsa_dnskey_public_store(const dnskey_t *key, uint8_t *rdata, size_t rdata_size)
{
    uint32_t len;

    SET_U16_AT(rdata[0], key->flags);
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = key->algorithm;

    len = ecdsa_public_store(key->key.evp_key, &rdata[4], rdata_size - 4) + 4;

    return len;
}

static uint32_t dnskey_ecdsa_size(const dnskey_t *key)
{
    uint32_t half = dnskey_ecdsa_nid_to_signature_bn_size(dnskey_ecdsa_getnid(dnskey_get_algorithm(key)));
    return half << 3; // don't add 1 because there are two halves : it gives the double of the expected value, and 3
                      // because the answer is in bits
}

/**
 * Returns the size in byte of the public key.
 *
 * @param ecdsa
 * @return
 */

static uint32_t dnskey_ecdsa_public_size(const EVP_PKEY *ecdsa)
{
    BIGNUM *qxy = NULL;
    if(EVP_PKEY_get_bn_param(ecdsa, OSSL_PKEY_PARAM_EC_PUB_X, &qxy) > 0)
    {
        uint32_t qx_size = BN_num_bytes(qxy);
        qx_size = (qx_size + 3) & ~3;
        if(EVP_PKEY_get_bn_param(ecdsa, OSSL_PKEY_PARAM_EC_PUB_Y, &qxy) > 0)
        {
            uint32_t qy_size = BN_num_bytes(qxy);
            qy_size = (qy_size + 3) & ~3;
            BN_clear_free(qxy);
            return qx_size + qy_size;
        }
    }
    crypto_openssl_error();
    BN_clear_free(qxy);
    return 0;
}

static uint32_t dnskey_ecdsa_dnskey_rdatasize(const dnskey_t *key)
{
    int nid = dnskey_ecdsa_getnid(dnskey_get_algorithm(key));
    if(nid >= 0)
    {
        int bn_size = dnskey_ecdsa_nid_to_signature_bn_size(nid);
        if(bn_size > 0)
        {
            uint32_t size = 4 + (bn_size << 1);
            return size;
        }
    }
    return 0;
}

static bool dnskey_ecdsa_equals(const dnskey_t *key_a, const dnskey_t *key_b)
{
    if(key_a == key_b)
    {
        return true;
    }

    if(dnskey_tag_field_set(key_a) && dnskey_tag_field_set(key_b))
    {
        if(key_a->tag != key_b->tag)
        {
            return false;
        }
    }

    if((key_a->flags == key_b->flags) && (key_a->algorithm == key_b->algorithm))
    {
        if(strcmp(key_a->origin, key_b->origin) == 0)
        {
            bool ret = EVP_PKEY_eq(key_a->key.evp_key, key_b->key.evp_key);
            return ret;
        }
    }

    return false;
}

static ya_result dnskey_ecdsa_print_fields(dnskey_t *key, output_stream_t *os)
{
    struct dnskey_ecdsa_s yecdsa;
    ya_result             ret = INVALID_STATE_ERROR;
    uint8_t               private_key[128];

    BIGNUM               *priv = NULL;
    if(EVP_PKEY_get_bn_param(key->key.evp_key, OSSL_PKEY_PARAM_PRIV_KEY, &priv) > 0)
    {
        int private_key_size = BN_bn2bin(priv, private_key);
        if(private_key_size > 0)
        {
#if SWAP_BYTES
            bytes_swap(private_key, private_key_size);
#endif
            yecdsa.private_key.buffer = private_key;
            yecdsa.private_key.size = private_key_size;
            ret = dnskey_field_access_print(ECDSA_field_access_write, &yecdsa, os);
        }
        BN_clear_free(priv);
    }
    else
    {
        crypto_openssl_error();
    }

    return ret;
}

//////////////////////////////////////////////////////////////////////////////

static const EVP_MD *ecdsa_md_from_algorithm(dnskey_t *key)
{
    const EVP_MD *md;
    switch(key->algorithm)
    {
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
        {
            md = EVP_sha256();
            break;
        }
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
        {
            md = EVP_sha384();
            break;
        }
        default:
        {
            md = NULL;
        }
    }
    return md;
}

static int32_t dnskey_ecdsa_signer_update(struct bytes_signer_s *signer, const void *buffer, uint32_t buffer_size)
{
    EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)signer->dctx;
    return EVP_DigestUpdate(md_ctx, buffer, buffer_size) - 1;
}

static int32_t dnskey_ecdsa_signer_sign(struct bytes_signer_s *signer, void *signature_, uint32_t *signature_size)
{
    uint8_t      *signature = (uint8_t *)signature_;
    EVP_MD_CTX   *md_ctx = (EVP_MD_CTX *)signer->dctx;
    dnskey_t     *key = (dnskey_t *)signer->kctx;
    ECDSA_SIG    *sig = NULL;
    const BIGNUM *r, *s;
    uint8_t       encoded_signature[128];

    int           bn_size = dnskey_ecdsa_algorithm_to_signature_bn_size(key->algorithm);

    size_t        encoded_signature_size = sizeof(encoded_signature);
    int           status = EVP_DigestSignFinal(md_ctx, encoded_signature, &encoded_signature_size);

    if(status == 1)
    {
        const uint8_t *encoded_signature_ = encoded_signature;
        d2i_ECDSA_SIG(&sig, &encoded_signature_, encoded_signature_size);
        ECDSA_SIG_get0(sig, &r, &s);

        int r_size = BN_num_bytes(r);
        memset(signature, 0, bn_size - r_size);
        signature += bn_size - r_size;
        BN_bn2bin(r, signature);
        signature += r_size;
        int s_size = BN_num_bytes(s);
        memset(signature, 0, bn_size - s_size);
        signature += bn_size - s_size;
        BN_bn2bin(s, signature);

        ECDSA_SIG_free(sig);
        *signature_size = bn_size * 2;
        return bn_size * 2;
    }
    else
    {
        return ERROR;
    }
}

static int32_t dnskey_ecdsa_signer_finalise(struct bytes_signer_s *signer)
{
    EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)signer->dctx;
    dnskey_t   *key = (dnskey_t *)signer->kctx;
    dnskey_release(key);
    EVP_MD_CTX_free(md_ctx);
    signer->dctx = NULL;
    signer->kctx = NULL;
    signer->vtbl = NULL;
    return SUCCESS;
}

static int32_t dnskey_ecdsa_verifier_update(struct bytes_verifier_s *verifier, const void *buffer, uint32_t buffer_size)
{
    EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)verifier->dctx;
    return EVP_DigestUpdate(md_ctx, buffer, buffer_size) - 1;
}

static bool dnskey_ecdsa_verifier_verify(struct bytes_verifier_s *verifier, const void *signature_, uint32_t signature_size)
{
    const uint8_t *signature = signature_;
    EVP_MD_CTX    *md_ctx = (EVP_MD_CTX *)verifier->dctx;
    dnskey_t      *key = (dnskey_t *)verifier->kctx;
    ECDSA_SIG     *sig = ECDSA_SIG_new();
    BIGNUM        *r, *s;
    uint8_t        encoded_signature[128];

    int            bn_size = dnskey_ecdsa_algorithm_to_signature_bn_size(key->algorithm);

    if(bn_size * 2 != (int)signature_size)
    {
        return false;
    }

    r = BN_bin2bn(signature, bn_size, NULL);
    signature += bn_size;
    s = BN_bin2bn(signature, bn_size, NULL);
    // signature += bn_size;
    ECDSA_SIG_set0(sig, r, s);

    uint8_t *encoded_signature_ = encoded_signature;
    int      encoded_signature_size = i2d_ECDSA_SIG(sig, &encoded_signature_);
    ECDSA_SIG_free(sig);

    int status = EVP_DigestVerifyFinal(md_ctx, encoded_signature, encoded_signature_size);

    return status == 1;
}

static int32_t dnskey_ecdsa_verifier_finalise(struct bytes_verifier_s *verifier)
{
    EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)verifier->dctx;
    dnskey_t   *key = (dnskey_t *)verifier->kctx;
    dnskey_release(key);
    EVP_MD_CTX_free(md_ctx);
    verifier->dctx = NULL;
    verifier->kctx = NULL;
    verifier->vtbl = NULL;
    return SUCCESS;
}

static const struct bytes_signer_vtbl bytes_signer_vtbl = {dnskey_ecdsa_signer_update, dnskey_ecdsa_signer_sign, dnskey_ecdsa_signer_finalise};

static ya_result                      dnskey_ecdsa_signer_init(dnskey_t *key, bytes_signer_t *signer)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        const EVP_MD *md = ecdsa_md_from_algorithm(key);
        if(md != NULL)
        {
            if(EVP_DigestSignInit(ctx, NULL, md, NULL, key->key.evp_key) == 1)
            {
                dnskey_acquire(key);
                signer->dctx = ctx;
                signer->kctx = key;
                signer->vtbl = &bytes_signer_vtbl;
                return SUCCESS;
            }
        }

        EVP_MD_CTX_free(ctx);
    }

    return ERROR;
}

static const struct bytes_verifier_vtbl bytes_verifier_vtbl = {dnskey_ecdsa_verifier_update, dnskey_ecdsa_verifier_verify, dnskey_ecdsa_verifier_finalise};

static ya_result                        dnskey_ecdsa_verifier_init(dnskey_t *key, bytes_verifier_t *verifier)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        const EVP_MD *md = ecdsa_md_from_algorithm(key);
        if(md != NULL)
        {
            if(EVP_DigestVerifyInit(ctx, NULL, md, NULL, key->key.evp_key) == 1)
            {
                dnskey_acquire(key);
                verifier->dctx = ctx;
                verifier->kctx = key;
                verifier->vtbl = &bytes_verifier_vtbl;
                return SUCCESS;
            }
        }

        EVP_MD_CTX_free(ctx);
    }
    return ERROR;
}

//////////////////////////////////////////////////////////////////////////////

void                     dnskey_evp_free(dnskey_t *key);

static const dnskey_vtbl ecdsa_vtbl = {
    dnskey_ecdsa_signer_init, dnskey_ecdsa_verifier_init, dnskey_ecdsa_dnskey_rdatasize, dnskey_ecdsa_dnskey_public_store, dnskey_evp_free, dnskey_ecdsa_equals, dnskey_ecdsa_print_fields, dnskey_ecdsa_size, "ECDSA"};

static ya_result dnskey_ecdsa_initinstance(EVP_PKEY *ecdsa, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key)
{
    int     nid;

    uint8_t rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES]; /* 4096 bits -> 1KB */

    *out_key = NULL;

    if(FAIL(nid = dnskey_ecdsa_getnid(algorithm)))
    {
        return nid;
    }

#if DEBUG
    memset(rdata, 0xff, sizeof(rdata));
#endif

    uint32_t public_key_size = dnskey_ecdsa_public_size(ecdsa);

    if(public_key_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    SET_U16_AT(rdata[0], flags); // NATIVEFLAGS
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = algorithm;

    if(ecdsa_public_store(ecdsa, &rdata[4], sizeof(rdata) - 4) != public_key_size)
    {
        return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
    }

    /* Note : + 4 because of the flags,protocol & algorithm bytes
     *        are not taken in account
     */

    uint16_t  tag = dnskey_get_tag_from_rdata(rdata, public_key_size + 4);

    dnskey_t *key = dnskey_newemptyinstance(algorithm, flags, origin); // RC

    if(key == NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    key->key.evp_key = ecdsa;
    key->vtbl = &ecdsa_vtbl;
    key->tag = tag;
    key->nid = nid;

    BIGNUM *priv_field = NULL;
    if(EVP_PKEY_get_bn_param(ecdsa, OSSL_PKEY_PARAM_PRIV_KEY, &priv_field) > 0)
    {
        BN_clear_free(priv_field);
        key->status |= DNSKEY_KEY_IS_PRIVATE;
    }

    *out_key = key;

    return SUCCESS;
}

static ya_result dnskey_ecdsa_parse_field(struct dnskey_field_parser *parser, parser_t *p)
{
    struct dnskey_ecdsa_s *yecdsa = (struct dnskey_ecdsa_s *)parser->data;

    ya_result              ret = dnskey_field_access_parse(ECDSA_field_access_read, yecdsa, p);

    return ret;
}

static ya_result dnskey_ecdsa_parse_set_key(struct dnskey_field_parser *parser, dnskey_t *key)
{
    struct dnskey_ecdsa_s *yecdsa = (struct dnskey_ecdsa_s *)parser->data;

    if(key == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    switch(key->algorithm)
    {
        case DNSKEY_ALGORITHM_ECDSAP256SHA256:
        case DNSKEY_ALGORITHM_ECDSAP384SHA384:
            break;
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    if(dnskey_raw_field_empty(&yecdsa->private_key))
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }

    const int id = EVP_PKEY_EC;
    const int nid = dnskey_ecdsa_getnid(dnskey_get_algorithm(key));
    ya_result ret = DNSSEC_ERROR_INCOMPLETEKEY;
    EVP_PKEY *evp_key = NULL;
    size_t    pubkey_size = 0;
    uint8_t   pubkey[128];
    EVP_PKEY_get_octet_string_param(key->key.evp_key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pubkey, sizeof(pubkey), &pubkey_size);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(id, NULL);
    if(pctx != NULL)
    {
        if(EVP_PKEY_paramgen_init(pctx) > 0)
        {
            if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) > 0)
            {
                EVP_PKEY *params = NULL;

                if(EVP_PKEY_paramgen(pctx, &params) > 0)
                {
                    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
                    if(kctx != NULL)
                    {
                        if(EVP_PKEY_fromdata_init(kctx) > 0)
                        {
                            OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
                            OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, (char *)dnskey_ecdsa_getgroup(key->algorithm), 0);
                            OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, pubkey, pubkey_size);
                            BIGNUM *priv = BN_bin2bn(yecdsa->private_key.buffer, yecdsa->private_key.size, NULL);
                            OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, priv);
                            OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);

                            if(EVP_PKEY_fromdata(kctx, &evp_key, EVP_PKEY_KEYPAIR, params) > 0)
                            {
                                // yay
                                // EVP_PKEY_dump_params(evp_key);
                                ret = SUCCESS;
                                key->status |= DNSKEY_KEY_IS_PRIVATE;
                                if(key->key.evp_key != NULL)
                                {
                                    EVP_PKEY_free(key->key.evp_key);
                                }
                                key->key.evp_key = evp_key;
                            }

                            OSSL_PARAM_free(params);
                            OSSL_PARAM_BLD_free(param_bld);
                            BN_clear_free(priv);
                        }

                        EVP_PKEY_CTX_free(kctx);
                    }

                    EVP_PKEY_free(params);
                }
            }
        }
        EVP_PKEY_CTX_free(pctx);
    }

    return ret;
}

static void dnskey_ecdsa_parse_finalize(struct dnskey_field_parser *parser)
{
    struct dnskey_ecdsa_s *ydsa = (struct dnskey_ecdsa_s *)parser->data;

    if(ydsa != NULL)
    {
        dnskey_ecdsa_finalize(ydsa);
        ZFREE(ydsa, struct dnskey_ecdsa_s);
    }
}

static const struct dnskey_field_parser_vtbl ecdsa_field_parser_vtbl = {dnskey_ecdsa_parse_field, dnskey_ecdsa_parse_set_key, dnskey_ecdsa_parse_finalize, "ECDSA"};

void                                         dnskey_ecdsa_parse_init(dnskey_field_parser *fp)
{
    struct dnskey_ecdsa_s *yecdsa;
    ZALLOC_OBJECT_OR_DIE(yecdsa, struct dnskey_ecdsa_s, KEYECDSA_TAG);
    ZEROMEMORY(yecdsa, sizeof(struct dnskey_ecdsa_s));
    fp->data = yecdsa;
    fp->vtbl = &ecdsa_field_parser_vtbl;
}

ya_result dnskey_ecdsa_loadpublic(const uint8_t *rdata, uint16_t rdata_size, const char *origin, dnskey_t **out_key)
{
    *out_key = NULL;

    if(rdata == NULL || rdata_size <= 6 || origin == NULL)
    {
        /* bad */

        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    uint16_t flags = GET_U16_AT(rdata[0]);
    uint8_t  algorithm = rdata[3];

    if((algorithm != DNSKEY_ALGORITHM_ECDSAP256SHA256) && (algorithm != DNSKEY_ALGORITHM_ECDSAP384SHA384) && (algorithm != DNSKEY_ALGORITHM_ED25519) && (algorithm != DNSKEY_ALGORITHM_ED448))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    rdata += 4;
    rdata_size -= 4;

    ya_result return_value = DNSSEC_ERROR_CANNOT_READ_KEY_FROM_RDATA;

    EVP_PKEY *ecdsa = dnskey_ecdsa_public_load(algorithm, rdata, rdata_size);

    if(ecdsa != NULL)
    {
        dnskey_t *key;

        if(ISOK(return_value = dnskey_ecdsa_initinstance(ecdsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }

        EVP_PKEY_free(ecdsa);
    }

    return return_value;
}

ya_result dnskey_ecdsa_newinstance(uint32_t size, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key)
{
    *out_key = NULL;

    if(size > DNSSEC_MAXIMUM_KEY_SIZE)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    if((algorithm != DNSKEY_ALGORITHM_ECDSAP256SHA256) && (algorithm != DNSKEY_ALGORITHM_ECDSAP384SHA384) && (algorithm != DNSKEY_ALGORITHM_ED25519) && (algorithm != DNSKEY_ALGORITHM_ED448))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    ya_result return_value = DNSSEC_ERROR_KEY_GENERATION_FAILED;

    EVP_PKEY *ecdsa = dnskey_ecdsa_genkey_by_nid(dnskey_ecdsa_getnid(algorithm));

    if(ecdsa != NULL)
    {
        dnskey_t *key;

        if(ISOK(return_value = dnskey_ecdsa_initinstance(ecdsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }

        EVP_PKEY_free(ecdsa);
    }

    return return_value;
}

#else

void dnskey_ecdsa_not_supported() {}

#endif // HAS_ECDSA_SUPPORT

/** @} */

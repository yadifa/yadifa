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
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "dnscore/openssl.h"

#include "dnscore/sys_types.h"
#include "dnscore/base64.h"

#include "dnscore/logger.h"
#include "dnscore/dnskey_rsa.h"
#include "dnscore/dnssec_errors.h"
#include "dnscore/parser.h"
#include "dnscore/tools.h"
#include "dnscore/zalloc.h"

#define MODULE_MSG_HANDLE g_system_logger

#define KEYRSA_TAG        0x41535259454b

#ifndef SSL_API
#error "SSL_API not defined"
#endif

struct dnskey_rsa_s
{
    dnskey_raw_field_t n, e, d, p, q, dmp1, dmq1, iqmp;
};

struct dnskey_rsa_const_s
{
    const dnskey_raw_field_t n, e, d, p, q, dmp1, dmq1, iqmp;
};

static void dnskey_rsa_init(struct dnskey_rsa_s *yrsa) { memset(yrsa, 0, sizeof(struct dnskey_rsa_s)); }

static void dnskey_rsa_finalize(struct dnskey_rsa_s *yrsa)
{
    dnskey_raw_field_clean_finalize(&yrsa->n);
    dnskey_raw_field_clean_finalize(&yrsa->e);
    dnskey_raw_field_clean_finalize(&yrsa->d);
    dnskey_raw_field_clean_finalize(&yrsa->p);
    dnskey_raw_field_clean_finalize(&yrsa->q);
    dnskey_raw_field_clean_finalize(&yrsa->dmp1);
    dnskey_raw_field_clean_finalize(&yrsa->dmq1);
    dnskey_raw_field_clean_finalize(&yrsa->iqmp);

    dnskey_rsa_init(yrsa);
}

static const struct dnskey_field_access_s RSA_field_access[] = {{"Modulus", offsetof(struct dnskey_rsa_s, n), STRUCTDESCRIPTOR_RAW},
                                                                {"PublicExponent", offsetof(struct dnskey_rsa_s, e), STRUCTDESCRIPTOR_RAW},
                                                                {"PrivateExponent", offsetof(struct dnskey_rsa_s, d), STRUCTDESCRIPTOR_RAW},
                                                                {"Prime1", offsetof(struct dnskey_rsa_s, p), STRUCTDESCRIPTOR_RAW},
                                                                {"Prime2", offsetof(struct dnskey_rsa_s, q), STRUCTDESCRIPTOR_RAW},
                                                                {"Exponent1", offsetof(struct dnskey_rsa_s, dmp1), STRUCTDESCRIPTOR_RAW},
                                                                {"Exponent2", offsetof(struct dnskey_rsa_s, dmq1), STRUCTDESCRIPTOR_RAW},
                                                                {"Coefficient", offsetof(struct dnskey_rsa_s, iqmp), STRUCTDESCRIPTOR_RAW},
                                                                {"", 0, 0}};

static int                                dnskey_rsa_getnid(uint8_t algorithm)
{
    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA1:
        {
            return NID_sha1;
        }
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        {
            return NID_sha256;
        }
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
        {
            return NID_sha512;
        }
        default:
        {
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        }
    }
}

static EVP_PKEY *dnskey_rsa_genkey(uint32_t size)
{
    yassert(size >= DNSSEC_MINIMUM_KEY_SIZE && size <= DNSSEC_MAXIMUM_KEY_SIZE);

    const int     id = EVP_PKEY_RSA;

    EVP_PKEY     *evp_key = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(id, NULL);
    if(kctx != NULL)
    {
        if(EVP_PKEY_keygen_init(kctx) > 0)
        {
            if(EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, size) > 0)
            {
                if(EVP_PKEY_keygen(kctx, &evp_key) > 0)
                {
                    // yay
                }
            }
        }
        EVP_PKEY_CTX_free(kctx);
    }

    return evp_key;
}

static EVP_PKEY *dnskey_rsa_public_load(const uint8_t *rdata, uint16_t rdata_size)
{
    // rdata_size < 4 is harsher than needed but anyway such a small key would
    // and this avoids another test later be worthless

    if(rdata == NULL || rdata_size < 4)
    {
        return NULL;
    }

    const uint8_t *inptr = rdata;
    uint32_t       n;
    n = *inptr++;
    rdata_size--; // rdata_size is at least 1, so it is OK
    if(n == 0)
    {
        n = *inptr++;
        n <<= 8;
        n |= *inptr++;
        rdata_size -= 2;
    }

    if(rdata_size < n + 1)
    {
        return NULL;
    }

    uint8_t *exponent_ptr = (uint8_t *)inptr;
    int      exponent_len = n;

    inptr += n;
    n = rdata_size - n;

    uint8_t      *modulus_ptr = (uint8_t *)inptr;
    int           modulus_len = n;

    const int     id = EVP_PKEY_RSA;

    EVP_PKEY     *evp_key = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(id, NULL);
    if(kctx != NULL)
    {
        if(EVP_PKEY_keygen_init(kctx) > 0)
        {
            if(EVP_PKEY_fromdata_init(kctx) > 0)
            {
                // for some reasons, the byte order is different with that interface???
                OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
                BIGNUM         *e = BN_bin2bn(exponent_ptr, exponent_len, NULL);
                OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e);
                BIGNUM *n = BN_bin2bn(modulus_ptr, modulus_len, NULL);
                OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n);
                OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);

                if(EVP_PKEY_fromdata(kctx, &evp_key, EVP_PKEY_PUBLIC_KEY, params) > 0)
                {
                    // yay (evp_key is not NULL)
                    yassert(evp_key != NULL);
                }
                else
                {
                    formatln("dnskey_rsa_public_load: %r", crypto_openssl_error());
                }

                OSSL_PARAM_free(params);
                OSSL_PARAM_BLD_free(param_bld);
                BN_clear_free(n);
                BN_clear_free(e);
            }
        }
        EVP_PKEY_CTX_free(kctx);
    }

    return evp_key;
}

static uint32_t dnskey_rsa_public_store(EVP_PKEY *evp_key, uint8_t *output_buffer, uint32_t output_buffer_size)
{
    unsigned char *outptr = output_buffer;

    BIGNUM        *exponent = NULL;
    BIGNUM        *modulus = NULL;

    if(EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_RSA_E, &exponent) > 0)
    {
        if(EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_RSA_N, &modulus) > 0)
        {
            uint32_t n = BN_num_bytes(exponent);
            uint32_t m = BN_num_bytes(modulus);

            if(n > 1 && n < 256)
            {
                if(1 + n + m <= output_buffer_size)
                {
                    *outptr++ = n;
                }
                else
                {
                    // error
                    BN_clear_free(modulus);
                    BN_clear_free(exponent);
                    return 0;
                }
            }
            else
            {
                if(3 + n + m <= output_buffer_size)
                {
                    *outptr++ = 0;
                    *outptr++ = n >> 8;
                    *outptr++ = n;
                }
                else
                {
                    // error
                    BN_clear_free(modulus);
                    BN_clear_free(exponent);
                    return 0;
                }
            }

            n = BN_bn2bin(exponent, outptr);
            outptr += n;
            n = BN_bn2bin(modulus, outptr);
            outptr += n;

            BN_clear_free(modulus);
            BN_clear_free(exponent);

            return outptr - output_buffer;
        }

        BN_clear_free(exponent);
    }

    return 0;
}

static uint32_t dnskey_rsa_dnskey_public_store(const dnskey_t *key, uint8_t *rdata, size_t rdata_size)
{
    uint32_t len;

    SET_U16_AT(rdata[0], key->flags);
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = key->algorithm;

    len = dnskey_rsa_public_store(key->key.evp_key, &rdata[4], rdata_size - 4) + 4;

    return len;
}

static uint32_t dnskey_rsa_size(const dnskey_t *key)
{
    BIGNUM *modulus = NULL;
    if(EVP_PKEY_get_bn_param(key->key.evp_key, OSSL_PKEY_PARAM_RSA_N, &modulus) > 0)
    {
        uint32_t m_size = BN_num_bytes(modulus);
        BN_clear_free(modulus);
        return m_size << 3;
    }
    return 0;
}

/// Returns the number of bytes required to store the key part of the DNSKEY rdata

static uint32_t dnskey_rsa_public_size(const EVP_PKEY *evp_key)
{
    BIGNUM  *rsa_e = NULL;
    BIGNUM  *rsa_n = NULL;
    uint32_t size = 0;

    if(EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_RSA_E, &rsa_e) > 0)
    {
        if(EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_RSA_N, &rsa_n) > 0)
        {
            uint32_t e_size = BN_num_bytes(rsa_e);
            uint32_t m_size = BN_num_bytes(rsa_n);

            size = m_size + e_size + ((e_size < 256) ? 1 : 3);

            BN_clear_free(rsa_n);
        }
        BN_clear_free(rsa_e);
    }
    else
    {
        formatln("dnskey_rsa_public_size: %r", crypto_openssl_error());
        flushout();
    }

    return size;
}

static uint32_t dnskey_rsa_dnskey_rdatasize(const dnskey_t *key)
{
    uint32_t size = dnskey_rsa_public_size(key->key.evp_key) + 4;
    return size;
}

static bool dnskey_rsa_equals(const dnskey_t *key_a, const dnskey_t *key_b)
{
    /* RSA, compare modulus and exponent, exponent first (it's the smallest) */

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
            EVP_PKEY *a_rsa = key_a->key.evp_key;
            EVP_PKEY *b_rsa = key_b->key.evp_key;

            BIGNUM   *a_bn = NULL;
            BIGNUM   *b_bn = NULL;

            if(EVP_PKEY_get_bn_param(a_rsa, OSSL_PKEY_PARAM_RSA_E, &a_bn) > 0)
            {
                if(EVP_PKEY_get_bn_param(b_rsa, OSSL_PKEY_PARAM_RSA_E, &b_bn) > 0)
                {
                    if(BN_cmp(a_bn, b_bn) == 0)
                    {
                        BN_clear_free(b_bn);
                        a_bn = NULL;
                        BN_clear_free(a_bn);
                        b_bn = NULL;
                        if(EVP_PKEY_get_bn_param(a_rsa, OSSL_PKEY_PARAM_RSA_N, &a_bn) > 0)
                        {
                            if(EVP_PKEY_get_bn_param(b_rsa, OSSL_PKEY_PARAM_RSA_N, &b_bn) > 0)
                            {
                                if(BN_cmp(a_bn, b_bn) == 0)
                                {
                                    BN_clear_free(b_bn);
                                    BN_clear_free(a_bn);

                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            BN_clear_free(b_bn);
            BN_clear_free(a_bn);
        }
    }

    return false;
}

static ya_result dnskey_rsa_private_print_fields(dnskey_t *key, output_stream_t *os)
{
    struct dnskey_rsa_s yrsa;
    ZEROMEMORY(&yrsa, sizeof(struct dnskey_rsa_s));

    BIGNUM *e = NULL;
    BIGNUM *n = NULL;
    BIGNUM *d = NULL;
    BIGNUM *dmp1 = NULL;
    BIGNUM *dmq1 = NULL;
    BIGNUM *iqmp = NULL;
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;

    EVP_PKEY_get_bn_param(key->key.evp_key, OSSL_PKEY_PARAM_RSA_E, &e);
    EVP_PKEY_get_bn_param(key->key.evp_key, OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(key->key.evp_key, OSSL_PKEY_PARAM_RSA_D, &d);
    EVP_PKEY_get_bn_param(key->key.evp_key, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1);
    EVP_PKEY_get_bn_param(key->key.evp_key, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1);
    EVP_PKEY_get_bn_param(key->key.evp_key, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);
    EVP_PKEY_get_bn_param(key->key.evp_key, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
    EVP_PKEY_get_bn_param(key->key.evp_key, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);

    uint8_t *buffer;
    int      buffer_size = BN_num_bytes(e);
    buffer_size += BN_num_bytes(n);
    buffer_size += BN_num_bytes(d);
    buffer_size += BN_num_bytes(dmp1);
    buffer_size += BN_num_bytes(dmq1);
    buffer_size += BN_num_bytes(iqmp);
    buffer_size += BN_num_bytes(p);
    buffer_size += BN_num_bytes(q);

    MALLOC_OBJECT_ARRAY(buffer, uint8_t, buffer_size, GENERIC_TAG); // generic is fine
    uint8_t *buffer_ptr = buffer;

    BN_bn2bin(e, buffer_ptr);
    yrsa.e.buffer = buffer_ptr;
    yrsa.e.size = BN_num_bytes(e);
    buffer_ptr += yrsa.e.size;

    BN_bn2bin(n, buffer_ptr);
    yrsa.n.buffer = buffer_ptr;
    yrsa.n.size = BN_num_bytes(n);
    buffer_ptr += yrsa.n.size;

    BN_bn2bin(d, buffer_ptr);
    yrsa.d.buffer = buffer_ptr;
    yrsa.d.size = BN_num_bytes(d);
    buffer_ptr += yrsa.d.size;

    BN_bn2bin(dmp1, buffer_ptr);
    yrsa.dmp1.buffer = buffer_ptr;
    yrsa.dmp1.size = BN_num_bytes(dmp1);
    buffer_ptr += yrsa.dmp1.size;

    BN_bn2bin(dmq1, buffer_ptr);
    yrsa.dmq1.buffer = buffer_ptr;
    yrsa.dmq1.size = BN_num_bytes(dmq1);
    buffer_ptr += yrsa.dmq1.size;

    BN_bn2bin(iqmp, buffer_ptr);
    yrsa.iqmp.buffer = buffer_ptr;
    yrsa.iqmp.size = BN_num_bytes(iqmp);
    buffer_ptr += yrsa.iqmp.size;

    BN_bn2bin(p, buffer_ptr);
    yrsa.p.buffer = buffer_ptr;
    yrsa.p.size = BN_num_bytes(p);
    buffer_ptr += yrsa.p.size;

    BN_bn2bin(q, buffer_ptr);
    yrsa.q.buffer = buffer_ptr;
    yrsa.q.size = BN_num_bytes(q);
    // buffer_ptr += yrsa.q.size;

    ya_result ret = dnskey_field_access_print(RSA_field_access, &yrsa, os);

    free(buffer);
    BN_clear_free(q);
    BN_clear_free(p);
    BN_clear_free(iqmp);
    BN_clear_free(dmq1);
    BN_clear_free(dmp1);
    BN_clear_free(d);
    BN_clear_free(n);
    BN_clear_free(e);

    return ret;
}

#if OBSOLETE
static ya_result dnskey_rsa_sign(const dnskey_t *key, const uint8_t *digest, uint32_t digest_len, uint8_t *output)
{
    ya_result     ret;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key->key.evp_key, NULL);
    if(ctx != NULL)
    {
        if(EVP_PKEY_sign_init(ctx) == 1)
        {
            if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1)
            {
                size_t output_size = U32_MAX;
                if(EVP_PKEY_sign(ctx, output, &output_size, digest, digest_len) == 1)
                {
                    ret = (ya_result)output_size;
                }
                else
                {
                    ret = ya_ssl_error();
                }
            }
            else
            {
                ret = ya_ssl_error();
            }
        }
        else
        {
            ret = ya_ssl_error();
        }
        EVP_PKEY_CTX_free(ctx);
    }
    else
    {
        ret = ya_ssl_error();
    }

    return ret;
}
#endif

#if OBSOLETE
static bool dnskey_rsa_verify(const dnskey_t *key, const uint8_t *digest, uint32_t digest_len, const uint8_t *signature, uint32_t signature_len)
{
    bool          ret = false;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key->key.evp_key, NULL);
    if(ctx != NULL)
    {
        if(EVP_PKEY_verify_init(ctx) == 1)
        {
            if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1)
            {
                if(EVP_PKEY_verify(ctx, signature, signature_len, digest, digest_len) == 1)
                {
                    ret = true;
                }
                else
                {
                    ya_ssl_error();
                }
            }
            else
            {
                ya_ssl_error();
            }
        }
        else
        {
            ya_ssl_error();
        }
        EVP_PKEY_CTX_free(ctx);
    }
    else
    {
        ret = ya_ssl_error();
    }

    return ret;
}
#endif

//////////////////////////////////////////////////////////////////////////////

static const EVP_MD *rsa_md_from_algorithm(dnskey_t *key)
{
    const EVP_MD *md;
    switch(key->algorithm)
    {
        case DNSKEY_ALGORITHM_RSASHA1:
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        {
            md = EVP_sha1();
            break;
        }
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        {
            md = EVP_sha256();
            break;
        }
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
        {
            md = EVP_sha512();
            break;
        }
        default:
        {
            md = NULL;
        }
    }
    return md;
}

static int32_t dnskey_rsa_signer_update(struct bytes_signer_s *signer, const void *buffer, uint32_t buffer_size)
{
    EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)signer->dctx;
    return EVP_SignUpdate(md_ctx, buffer, buffer_size) - 1;
}

static int32_t dnskey_rsa_signer_sign(struct bytes_signer_s *signer, void *signature, uint32_t *signature_size)
{
    EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)signer->dctx;
    dnskey_t   *key = (dnskey_t *)signer->kctx;
    *signature_size = 1024;
    int status = EVP_SignFinal(md_ctx, signature, signature_size, key->key.evp_key);

    if(status == 1)
    {
        return SUCCESS;
    }
    else
    {
        crypto_openssl_error();
        *signature_size = 0;
        return ERROR;
    }
}

static int32_t dnskey_rsa_signer_finalise(struct bytes_signer_s *signer)
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

static int32_t dnskey_rsa_verifier_update(struct bytes_verifier_s *verifier, const void *buffer, uint32_t buffer_size)
{
    EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)verifier->dctx;
    return EVP_VerifyUpdate(md_ctx, buffer, buffer_size) - 1;
}

static bool dnskey_rsa_verifier_verify(struct bytes_verifier_s *verifier, const void *signature, uint32_t signature_size)
{
    EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)verifier->dctx;
    dnskey_t   *key = (dnskey_t *)verifier->kctx;

    int         status = EVP_VerifyFinal(md_ctx, signature, signature_size, key->key.evp_key);
    return status == 1;
}

static int32_t dnskey_rsa_verifier_finalise(struct bytes_verifier_s *verifier)
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

static const struct bytes_signer_vtbl dnskey_rsa_bytes_signer_vtbl = {dnskey_rsa_signer_update, dnskey_rsa_signer_sign, dnskey_rsa_signer_finalise};

static ya_result                      dnskey_rsa_signer_init(dnskey_t *key, bytes_signer_t *signer)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        const EVP_MD *md = rsa_md_from_algorithm(key);
        if(md != NULL)
        {
            if(EVP_DigestInit(ctx, md) == 1)
            {
                dnskey_acquire(key);
                signer->dctx = ctx;
                signer->kctx = key;
                signer->vtbl = &dnskey_rsa_bytes_signer_vtbl;
                return SUCCESS;
            }
        }

        EVP_MD_CTX_free(ctx);
    }
    return ERROR;
}

static const struct bytes_verifier_vtbl dnskey_rsa_bytes_verifier_vtbl = {dnskey_rsa_verifier_update, dnskey_rsa_verifier_verify, dnskey_rsa_verifier_finalise};

static ya_result                        dnskey_rsa_verifier_init(dnskey_t *key, bytes_verifier_t *verifier)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        const EVP_MD *md = rsa_md_from_algorithm(key);
        if(md != NULL)
        {
            if(EVP_VerifyInit(ctx, md) == 1)
            {
                dnskey_acquire(key);
                verifier->dctx = ctx;
                verifier->kctx = key;
                verifier->vtbl = &dnskey_rsa_bytes_verifier_vtbl;
                return SUCCESS;
            }
        }

        EVP_MD_CTX_free(ctx);
    }
    return ERROR;
}

//////////////////////////////////////////////////////////////////////////////

void                     dnskey_evp_free(dnskey_t *key);

static const dnskey_vtbl rsa_vtbl = {
    dnskey_rsa_signer_init, dnskey_rsa_verifier_init, dnskey_rsa_dnskey_rdatasize, dnskey_rsa_dnskey_public_store, dnskey_evp_free, dnskey_rsa_equals, dnskey_rsa_private_print_fields, dnskey_rsa_size, "RSA"};

static ya_result dnskey_rsa_initinstance(EVP_PKEY *evp_key, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key)
{
    int     nid;

    uint8_t rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES]; /* 4096 bits -> 1KB */

    if(evp_key == NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    *out_key = NULL;

    if(FAIL(nid = dnskey_rsa_getnid(algorithm)))
    {
        return nid;
    }

#if DEBUG
    memset(rdata, 0xff, sizeof(rdata));
#endif

    uint32_t rdata_size = dnskey_rsa_public_size(evp_key);

    if(rdata_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    SET_U16_AT(rdata[0], flags); // NATIVEFLAGS
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = algorithm;

    if(dnskey_rsa_public_store(evp_key, &rdata[4], sizeof(rdata) - 4) != rdata_size)
    {
        return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
    }

    /* Note : + 4 because of the flags,protocol & algorithm bytes
     *        are not taken in account
     */

    uint16_t  tag = dnskey_get_tag_from_rdata(rdata, rdata_size + 4);

    dnskey_t *key = dnskey_newemptyinstance(algorithm, flags, origin); // RC

    if(key == NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    key->key.evp_key = evp_key;
    key->vtbl = &rsa_vtbl;
    key->tag = tag;
    key->nid = nid;

    BIGNUM *secret_exponent = NULL;

    if(EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_RSA_D, &secret_exponent) > 0)
    {
        key->status |= DNSKEY_KEY_IS_PRIVATE;
        BN_clear_free(secret_exponent);
    }

    *out_key = key;

    return SUCCESS;
}

static ya_result dnskey_rsa_parse_field(struct dnskey_field_parser *parser, parser_t *p)
{
    struct dnskey_rsa_s *yrsa = (struct dnskey_rsa_s *)parser->data;

    ya_result            ret = dnskey_field_access_parse(RSA_field_access, yrsa, p);

    return ret;
}

static ya_result dnskey_rsa_parse_set_key(struct dnskey_field_parser *parser, dnskey_t *key)
{
    if(key == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    // yassert(key->nid == 0);

    switch(key->algorithm)
    {
        case DNSKEY_ALGORITHM_RSASHA1:
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            break;
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    struct dnskey_rsa_s *yrsa = (struct dnskey_rsa_s *)parser->data;

    if(dnskey_raw_field_empty(&yrsa->n) || dnskey_raw_field_empty(&yrsa->e) || dnskey_raw_field_empty(&yrsa->d) || dnskey_raw_field_empty(&yrsa->dmp1) || dnskey_raw_field_empty(&yrsa->dmq1) || dnskey_raw_field_empty(&yrsa->iqmp))
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }

    if(dnskey_raw_field_empty(&yrsa->p) != dnskey_raw_field_empty(&yrsa->q))
    {
        // half a private key is wrong
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }

    int nid;

    if(FAIL(nid = dnskey_rsa_getnid(key->algorithm)))
    {
        return nid;
    }

    if((key->nid != 0) && (key->nid != nid))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    ya_result ret = DNSSEC_ERROR_INCOMPLETEKEY;

    bool      has_private = !(dnskey_raw_field_empty(&yrsa->p) || dnskey_raw_field_empty(&yrsa->q));
    bool      loaded = false;

    if(key->key.evp_key != NULL)
    {
        EVP_PKEY_free(key->key.evp_key); /// @TODO 20221014 edf -- I hate this but I've not found a way to transform a
                                         /// key with the EVP interface.
        key->key.evp_key = NULL;
    }

    if(key->key.evp_key == NULL)
    {
        key->vtbl = &rsa_vtbl;

        const int     id = EVP_PKEY_RSA;
        EVP_PKEY     *evp_key = NULL;
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(id, NULL);
        if(kctx != NULL)
        {
            if(EVP_PKEY_keygen_init(kctx) > 0)
            {
                if(EVP_PKEY_fromdata_init(kctx) > 0)
                {
                    OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
                    BIGNUM         *e = BN_bin2bn(yrsa->e.buffer, yrsa->e.size, NULL);
                    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e);
                    BIGNUM *n = BN_bin2bn(yrsa->n.buffer, yrsa->n.size, NULL);
                    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n);
                    BIGNUM *d = BN_bin2bn(yrsa->d.buffer, yrsa->d.size, NULL);
                    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_D, d);
                    BIGNUM *dmp1 = BN_bin2bn(yrsa->dmp1.buffer, yrsa->dmp1.size, NULL);
                    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1);
                    BIGNUM *dmq1 = BN_bin2bn(yrsa->dmq1.buffer, yrsa->dmq1.size, NULL);
                    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1);
                    BIGNUM *iqmp = BN_bin2bn(yrsa->iqmp.buffer, yrsa->iqmp.size, NULL);
                    OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp);
                    BIGNUM *p = NULL;
                    BIGNUM *q = NULL;
                    if(has_private)
                    {
                        p = BN_bin2bn(yrsa->p.buffer, yrsa->p.size, NULL);
                        OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
                        q = BN_bin2bn(yrsa->q.buffer, yrsa->q.size, NULL);
                        OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
                    }

                    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);

                    if(EVP_PKEY_fromdata(kctx, &evp_key, EVP_PKEY_KEYPAIR, params) > 0)
                    {
                        // yay
                        key->key.evp_key = evp_key;
                        loaded = true;
                    }

                    OSSL_PARAM_free(params);
                    OSSL_PARAM_BLD_free(param_bld);
                    if(has_private)
                    {
                        BN_clear_free(q);
                        BN_clear_free(p);
                    }
                    BN_clear_free(iqmp);
                    BN_clear_free(dmq1);
                    BN_clear_free(dmp1);
                    BN_clear_free(d);
                    BN_clear_free(n);
                    BN_clear_free(e);
                }
            }

            EVP_PKEY_CTX_free(kctx);
        }
    }
    else
    {
        /*
        OSSL_PARAM params[9] =
        {
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_RSA_E, &yrsa->e),
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_RSA_N, &yrsa->n),
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_RSA_D, &yrsa->d),
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_RSA_EXPONENT1, &yrsa->dmp1),
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_RSA_EXPONENT2, &yrsa->dmq1),
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &yrsa->iqmp),
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_RSA_FACTOR1, &yrsa->p),
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_RSA_FACTOR2, &yrsa->q),
            OSSL_PARAM_END
        };
        */
    }

    if(loaded)
    {
        // at this point, yrsa has been emptied
        uint32_t rdata_size = dnskey_rsa_public_size(key->key.evp_key);

        uint16_t tag;

        uint8_t  rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];

        if(rdata_size <= DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
        {
            SET_U16_AT(rdata[0], key->flags);
            rdata[2] = DNSKEY_PROTOCOL_FIELD;
            rdata[3] = key->algorithm;

            if(dnskey_rsa_public_store(key->key.evp_key, &rdata[4], sizeof(rdata) - 4) == rdata_size)
            {
                /* Note : + 4 because of the flags,protocol & algorithm bytes
                 *        are not taken in account
                 */

                tag = dnskey_get_tag_from_rdata(rdata, rdata_size + 4);

                key->tag = tag;
                key->nid = nid;

                key->status |= DNSKEY_KEY_IS_VALID;

                if(has_private)
                {
                    key->status |= DNSKEY_KEY_IS_PRIVATE;
                }

                ret = SUCCESS;
            }
            else
            {
                ret = DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
            }
        }
        else
        {
            ret = DNSSEC_ERROR_KEYISTOOBIG;
        }
    }

    return ret;
}

static void dnskey_rsa_parse_finalize(struct dnskey_field_parser *parser)
{
    struct dnskey_rsa_s *yrsa = (struct dnskey_rsa_s *)parser->data;

    if(yrsa != NULL)
    {
        dnskey_rsa_finalize(yrsa);
        ZFREE(yrsa, struct dnskey_rsa_s);
    }
}

static const struct dnskey_field_parser_vtbl rsa_field_parser_vtbl = {dnskey_rsa_parse_field, dnskey_rsa_parse_set_key, dnskey_rsa_parse_finalize, "RSA"};

void                                         dnskey_rsa_parse_init(dnskey_field_parser *fp)
{
    struct dnskey_rsa_s *yrsa;
    ZALLOC_OBJECT_OR_DIE(yrsa, struct dnskey_rsa_s, KEYRSA_TAG);
    ZEROMEMORY(yrsa, sizeof(struct dnskey_rsa_s));
    fp->data = yrsa;
    fp->vtbl = &rsa_field_parser_vtbl;
}

ya_result dnskey_rsa_loadpublic(const uint8_t *rdata, uint16_t rdata_size, const char *origin, dnskey_t **out_key)
{
    *out_key = NULL;

    if(rdata == NULL || rdata_size <= 6 || origin == NULL)
    {
        /* bad */

        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    uint16_t flags = GET_U16_AT(rdata[0]);
    uint8_t  algorithm = rdata[3];

    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_RSASHA1:
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            break;
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    rdata += 4;
    rdata_size -= 4;

    ya_result return_value = DNSSEC_ERROR_CANNOT_READ_KEY_FROM_RDATA;

    EVP_PKEY *evp_key = dnskey_rsa_public_load(rdata, rdata_size);

    if(evp_key != NULL)
    {
        // EVP_PKEY_print_public_fp(stdout, evp_key, 0, NULL);

        dnskey_t *key;

        if(ISOK(return_value = dnskey_rsa_initinstance(evp_key, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }

        EVP_PKEY_free(evp_key);
    }

    return return_value;
}

ya_result dnskey_rsa_newinstance(uint32_t size, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key)
{
    *out_key = NULL;

    if(size > DNSSEC_MAXIMUM_KEY_SIZE)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_RSASHA1:
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
            break;
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    ya_result return_value = DNSSEC_ERROR_KEY_GENERATION_FAILED;

    EVP_PKEY *evp_key = dnskey_rsa_genkey(size);

    if(evp_key != NULL)
    {
        dnskey_t *key;

        if(ISOK(return_value = dnskey_rsa_initinstance(evp_key, algorithm, flags, origin, &key)))
        {
            // EVP_PKEY_print_public_fp(stdout, key->key.evp_key, 0, NULL);
            *out_key = key;

            return return_value;
        }

        EVP_PKEY_free(evp_key);
    }

    return return_value;
}

/** @} */

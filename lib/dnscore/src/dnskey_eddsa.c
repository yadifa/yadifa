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

// Note: mix of SSL < 3.0 and SSL >= 3.0
// Note: https://www.openssl.org/docs/manmaster/man7/Ed25519.html
//       The PureEdDSA instances do not support the streaming mechanism of other signature algorithms using,
//       for example, EVP_DigestUpdate(). The message to sign or verify must be passed using the one-shot
//       EVP_DigestSign() and EVP_DigestVerify() functions.
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include "dnscore/dnscore_config_features.h"

#if DNSCORE_HAS_EDDSA_SUPPORT

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include "dnscore/openssl.h"

#include "dnscore/dnscore_config.h"

#include "dnscore/dnscore.h"
#include "dnscore/sys_types.h"
// EVP_PKEY_new_raw_public_key
#include "dnscore/logger.h"
#include "dnscore/dnskey.h"
#if DNSCORE_HAS_EDDSA_SUPPORT
#include "dnscore/dnskey_eddsa.h"
#endif

#ifdef LIBRESSL_VERSION
#pragma message("Note: 2022-11-17 It is unlikely libreSSL has EDDSA support")
#endif

#include "dnscore/dnssec_errors.h"
#include "dnscore/zalloc.h"

#define MODULE_MSG_HANDLE g_system_logger

#define KEYECDSA_TAG      0x415344434559454b
#define EDDSABFR_TAG      0x5246424153444445

#ifndef SSL_API
#error "SSL_API not defined"
#endif

#ifdef NID_ED25519
#define DNSKEY_ALGORITHM_ED25519_NID NID_ED25519
#elif defined(NID_Ed25519)
#define DNSKEY_ALGORITHM_ED25519_NID NID_Ed25519
#else
#error "ED25519 not defined"
#endif

#ifdef NID_ED448
#define DNSKEY_ALGORITHM_ED448_NID NID_ED448
#elif defined(NID_Ed448)
#define DNSKEY_ALGORITHM_ED448_NID NID_Ed448
#else
#error "ED448 not defined"
#endif

/*
 * Intermediary key
 */

struct dnskey_eddsa_s
{
    dnskey_raw_field_t private_key;
};

struct dnskey_eddsa_const_s
{
    const dnskey_raw_field_t private_key;
};

static void dnskey_eddsa_init(struct dnskey_eddsa_s *yeddsa) { memset(yeddsa, 0, sizeof(struct dnskey_eddsa_s)); }

static void dnskey_eddsa_from_eddsa(struct dnskey_eddsa_s *yeddsa, const EVP_PKEY *eddsa)
{
    uint8_t *buffer;
    size_t   size;
    if(EVP_PKEY_get_raw_private_key(eddsa, NULL, &size) > 0)
    {
        ZALLOC_OBJECT_ARRAY_OR_DIE(buffer, uint8_t, size, EDDSABFR_TAG);
        EVP_PKEY_get_raw_private_key(eddsa, buffer, &size);
        yeddsa->private_key.buffer = buffer;
        yeddsa->private_key.size = size;
    }
    else
    {
        yeddsa->private_key.buffer = NULL;
        yeddsa->private_key.size = 0;
    }
}

static void dnskey_eddsa_finalize(struct dnskey_eddsa_s *yeddsa)
{
    if(yeddsa->private_key.buffer != NULL)
    {
        dnskey_raw_field_clean_finalize(&yeddsa->private_key);
    }
    dnskey_eddsa_init(yeddsa);
}

static const struct dnskey_field_access_s ECDSA_field_access[] = {{"PrivateKey", offsetof(struct dnskey_eddsa_s, private_key), STRUCTDESCRIPTOR_RAW}, {"", 0, STRUCTDESCRIPTOR_NONE}};

static int                                dnskey_eddsa_getnid(uint8_t algorithm)
{
    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_ED25519:
        {
            return DNSKEY_ALGORITHM_ED25519_NID;
        }
        case DNSKEY_ALGORITHM_ED448:
        {
            return DNSKEY_ALGORITHM_ED448_NID;
        }
        default:
        {
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        }
    }
}

#if SSL_API_LT_300
#if OBSOLETE
static int dnskey_eddsa_nid_to_signature_bn_size(int nid)
{
    switch(nid)
    {
        case DNSKEY_ALGORITHM_ED25519_NID:
        {
            return 32 * 2;
        }
        case DNSKEY_ALGORITHM_ED448_NID:
        {
            return 57 * 2;
        }
        default:
        {
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        }
    }
}
#endif

#if OBSOLETE
static ya_result dnskey_eddsa_signdigest(const dnskey_t *key, const uint8_t *digest, uint32_t digest_len, uint8_t *output)
{
    ya_result   ret;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        if(EVP_DigestSignInit(ctx, NULL, NULL, NULL, key->key.evp_key) == 1)
        {
            size_t output_size = DIGEST_BUFFER_SIZE;
            if(EVP_DigestSign(ctx, output, &output_size, digest, digest_len) == 1)
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
        EVP_MD_CTX_free(ctx);
    }
    else
    {
        ret = ya_ssl_error();
    }

    return ret;
}
#endif

#if OBSOLETE
static bool dnskey_eddsa_verifydigest(const dnskey_t *key, const uint8_t *digest, uint32_t digest_len, const uint8_t *signature, uint32_t signature_len)
{
    yassert(signature_len <= DNSSEC_MAXIMUM_KEY_SIZE_BYTES);

#if DEBUG
    log_debug6("eddsa_verifydigest(K%{dnsname}-%03d-%05d, @%p, @%p)", key->owner_name, key->algorithm, key->tag, digest, signature);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, digest, digest_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, signature, signature_len, 32);
#endif

    int bn_size = dnskey_eddsa_nid_to_signature_bn_size(key->nid);

    if(FAIL(bn_size))
    {
        log_err("EDDSA: getting size for NID returned: %r", bn_size);
        return false;
    }

    if((int)signature_len != bn_size)
    {
        log_err("EDDSA: signature size unexpected");
        return false;
    }

    bool        ret = false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        if(EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key->key.evp_key) == 1)
        {
            if(EVP_DigestVerify(ctx, signature, signature_len, digest, digest_len) == 1)
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
        EVP_MD_CTX_free(ctx);
    }
    else
    {
        ya_ssl_error();
    }

    return ret;
}
#endif

#endif

static EVP_PKEY *dnskey_eddsa_public_load(uint8_t algorithm, const uint8_t *rdata_key, uint16_t rdata_key_size)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(dnskey_eddsa_getnid(algorithm), NULL, rdata_key, rdata_key_size);
    return key;
}

static uint32_t eddsa_public_store(const EVP_PKEY *eddsa, uint8_t *output_buffer, size_t output_buffer_size)
{
    size_t size = output_buffer_size;
    if(EVP_PKEY_get_raw_public_key(eddsa, output_buffer, &size) == 1)
    {
        return size;
    }
    else
    {
        return ERROR;
    }
}

static uint32_t dnskey_eddsa_dnskey_public_store(const dnskey_t *key, uint8_t *rdata, size_t rdata_size)
{
    uint32_t len;

    SET_U16_AT(rdata[0], key->flags);
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = key->algorithm;

    len = eddsa_public_store(key->key.evp_key, &rdata[4], rdata_size) + 4;

    return len;
}

static uint32_t dnskey_eddsa_size(const dnskey_t *key)
{
    size_t size = 0;
    if(EVP_PKEY_get_raw_public_key(key->key.evp_key, NULL, &size) > 0)
    {
        return (uint32_t)size * 8;
    }
    else
    {
        return crypto_openssl_error();
    }
}

/**
 * Returns the size in byte of the public key.
 *
 * @param eddsa
 * @return
 */

static uint32_t dnskey_eddsa_public_size(const EVP_PKEY *eddsa)
{
    size_t size = 0;
    EVP_PKEY_get_raw_public_key(eddsa, NULL, &size);
    return (uint32_t)size;
}

static uint32_t dnskey_eddsa_dnskey_rdatasize(const dnskey_t *key)
{
    uint32_t size = dnskey_eddsa_public_size(key->key.evp_key) + 4;
    return size;
}

static bool dnskey_eddsa_equals(const dnskey_t *key_a, const dnskey_t *key_b)
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
#if SSL_API_GE_300
            return EVP_PKEY_eq(key_a->key.evp_key, key_b->key.evp_key);
#else
            return EVP_PKEY_cmp(key_a->key.evp_key, key_b->key.evp_key) == 1;
#endif
        }
    }

    return false;
}

static ya_result dnskey_eddsa_print_fields(dnskey_t *key, output_stream_t *os)
{
    struct dnskey_eddsa_s yeddsa;
    dnskey_eddsa_from_eddsa(&yeddsa, key->key.evp_key);

    // @note 20220802 edf -- prints the private key on stdout for some test, disabled, obviously
    // PEM_write_PrivateKey(stdout, key->key.ed, NULL, NULL, 0, NULL, NULL);

    size_t  buffer_size;
    uint8_t buffer[256];

    buffer_size = sizeof(buffer);
    EVP_PKEY_get_raw_private_key(key->key.evp_key, buffer, &buffer_size);

    buffer_size = sizeof(buffer);
    EVP_PKEY_get_raw_public_key(key->key.evp_key, buffer, &buffer_size);

    ya_result ret = dnskey_field_access_print(ECDSA_field_access, &yeddsa, os);

    dnskey_eddsa_finalize(&yeddsa);

    return ret;
}

#if SSL_API_LT_300
void dnskey_eddsa_free(dnskey_t *key)
{
    EVP_PKEY *evp_key = key->key.evp_key;
    EVP_PKEY_free(evp_key);
    key->key.evp_key = NULL;
}
#endif

//////////////////////////////////////////////////////////////////////////////

static int32_t dnskey_eddsa_signer_update(struct bytes_signer_s *signer, const void *buffer, uint32_t buffer_size)
{
    digest_t *digest_ctx = (digest_t *)signer->dctx;
    int32_t   ret = digest_update(digest_ctx, buffer, buffer_size);
    return ret;
}

static int32_t dnskey_eddsa_signer_sign(struct bytes_signer_s *signer, void *signature, uint32_t *signature_size)
{
    digest_t   *digest_ctx = (digest_t *)signer->dctx;
    dnskey_t   *key = (dnskey_t *)signer->kctx;
    uint8_t    *digest;
    int32_t     digest_size = digest_get_digest(digest_ctx, (void **)&digest);
    ya_result   ret;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        if(EVP_DigestSignInit(ctx, NULL, NULL, NULL, key->key.evp_key) == 1)
        {
            size_t signature_size_ = *signature_size;
            if(EVP_DigestSign(ctx, signature, &signature_size_, digest, digest_size) == 1)
            {
                *signature_size = (uint32_t)signature_size_;
                ret = SUCCESS;
            }
            else
            {
                ret = crypto_openssl_error();
            }
        }
        else
        {
            ret = crypto_openssl_error();
        }
        EVP_MD_CTX_free(ctx);
    }
    else
    {
        ret = crypto_openssl_error();
    }
    return ret;
}

static int32_t dnskey_eddsa_signer_finalise(struct bytes_signer_s *signer)
{
    digest_t *ctx = (digest_t *)signer->dctx;
    dnskey_t *key = (dnskey_t *)signer->kctx;
    dnskey_release(key);
    digest_finalise(ctx);
    ZFREE_OBJECT(ctx);
    signer->dctx = NULL;
    signer->kctx = NULL;
    signer->vtbl = NULL;

    return SUCCESS;
}

static int32_t dnskey_eddsa_verifier_update(struct bytes_verifier_s *verifier, const void *buffer, uint32_t buffer_size)
{
    digest_t *digest_ctx = (digest_t *)verifier->dctx;
    int32_t   ret = digest_update(digest_ctx, buffer, buffer_size);
    return ret;
}

static bool dnskey_eddsa_verifier_verify(struct bytes_verifier_s *verifier, const void *signature, uint32_t signature_size)
{
    digest_t   *digest_ctx = (digest_t *)verifier->dctx;
    dnskey_t   *key = (dnskey_t *)verifier->kctx;
    uint8_t    *digest;
    int32_t     digest_size = digest_get_digest(digest_ctx, (void **)&digest);
    ya_result   ret = false;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        if(EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key->key.evp_key) == 1)
        {
            if(EVP_DigestVerify(ctx, signature, signature_size, digest, digest_size) == 1)
            {
                ret = true;
            }
        }
        else
        {
            crypto_openssl_error();
        }
        EVP_MD_CTX_free(ctx);
    }
    else
    {
        crypto_openssl_error();
    }

    return ret;
}

static int32_t dnskey_eddsa_verifier_finalise(struct bytes_verifier_s *verifier)
{
    digest_t *ctx = (digest_t *)verifier->dctx;
    dnskey_t *key = (dnskey_t *)verifier->kctx;
    dnskey_release(key);
    digest_finalise(ctx);
    ZFREE_OBJECT(ctx);
    verifier->dctx = NULL;
    verifier->kctx = NULL;
    verifier->vtbl = NULL;

    return SUCCESS;
}

static const struct bytes_signer_vtbl dnskey_eddsa_bytes_signer_vtbl = {dnskey_eddsa_signer_update, dnskey_eddsa_signer_sign, dnskey_eddsa_signer_finalise};

static ya_result                      dnskey_eddsa_signer_init(dnskey_t *key, bytes_signer_t *signer)
{
    digest_t *ctx;
    ZALLOC_OBJECT_OR_DIE(ctx, digest_t, DIGEST_TAG);
    digest_rawdata_init(ctx);

    dnskey_acquire(key);
    signer->dctx = ctx;
    signer->kctx = key;
    signer->vtbl = &dnskey_eddsa_bytes_signer_vtbl;
    return SUCCESS;
}

static const struct bytes_verifier_vtbl dnskey_eddsa_bytes_verifier_vtbl = {dnskey_eddsa_verifier_update, dnskey_eddsa_verifier_verify, dnskey_eddsa_verifier_finalise};

static ya_result                        dnskey_eddsa_verifier_init(dnskey_t *key, bytes_verifier_t *verifier)
{
    digest_t *ctx;
    ZALLOC_OBJECT_OR_DIE(ctx, digest_t, DIGEST_TAG);
    digest_rawdata_init(ctx);

    dnskey_acquire(key);
    verifier->dctx = ctx;
    verifier->kctx = key;
    verifier->vtbl = &dnskey_eddsa_bytes_verifier_vtbl;
    return SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////

void                     dnskey_evp_free(dnskey_t *key);

static const dnskey_vtbl eddsa_vtbl = {

    dnskey_eddsa_signer_init,
    dnskey_eddsa_verifier_init,
    dnskey_eddsa_dnskey_rdatasize,
    dnskey_eddsa_dnskey_public_store,
#if SSL_API_LT_300
    dnskey_eddsa_free,
#else
    dnskey_evp_free,
#endif
    dnskey_eddsa_equals,
    dnskey_eddsa_print_fields,
    dnskey_eddsa_size,
    "ECDSA"};

static ya_result dnskey_eddsa_initinstance(EVP_PKEY *eddsa, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key)
{
    int nid;
    // needed to compute the tag
    uint8_t rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES]; /* 4096 bits -> 1KB */

    *out_key = NULL;

    if(FAIL(nid = dnskey_eddsa_getnid(algorithm)))
    {
        return nid;
    }

#if DEBUG
    memset(rdata, 0xff, sizeof(rdata));
#endif

    uint32_t public_key_size = dnskey_eddsa_public_size(eddsa);

    if(public_key_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    SET_U16_AT(rdata[0], flags); // NATIVEFLAGS
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = algorithm;

    if(eddsa_public_store(eddsa, &rdata[4], sizeof(rdata) - 4) != public_key_size)
    {
        return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
    }

    /* Note : + 4 because of the flags,protocol & algorithm bytes
     *        are not taken in account
     */

    uint16_t  tag = dnskey_get_tag_from_rdata(rdata, public_key_size + 4);

    dnskey_t *key = dnskey_newemptyinstance(algorithm, flags, origin); // RC

    key->key.evp_key = eddsa;
    key->vtbl = &eddsa_vtbl;
    key->tag = tag;
    key->nid = nid;
    key->status |= (i2d_PrivateKey(eddsa, NULL) > 0) ? DNSKEY_KEY_IS_PRIVATE : 0;

    *out_key = key;

    return SUCCESS;
}

static ya_result dnskey_eddsa_parse_field(struct dnskey_field_parser *parser, parser_t *p)
{
    struct dnskey_eddsa_s *yeddsa = (struct dnskey_eddsa_s *)parser->data;

    ya_result              ret = dnskey_field_access_parse(ECDSA_field_access, yeddsa, p);

    return ret;
}

static ya_result dnskey_eddsa_parse_set_key(struct dnskey_field_parser *parser, dnskey_t *key)
{
    if(key == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    switch(key->algorithm)
    {
        case DNSKEY_ALGORITHM_ED25519:
        case DNSKEY_ALGORITHM_ED448:
            break;
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    struct dnskey_eddsa_s *yeddsa = (struct dnskey_eddsa_s *)parser->data;

    if(yeddsa->private_key.buffer == NULL)
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }

    int nid;

    if(FAIL(nid = dnskey_eddsa_getnid(key->algorithm)))
    {
        return nid;
    }

    EVP_PKEY *eddsa = EVP_PKEY_new_raw_private_key(nid, NULL, yeddsa->private_key.buffer, yeddsa->private_key.size);

    if(eddsa != NULL)
    {
        // at this point, yeddsa has been emptied

        uint32_t rdata_size = dnskey_eddsa_public_size(eddsa);

        uint16_t tag;

        uint8_t  rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];

        if(rdata_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
        {
            EVP_PKEY_free(eddsa);
            return DNSSEC_ERROR_KEYISTOOBIG;
        }

        SET_U16_AT(rdata[0], key->flags);
        rdata[2] = DNSKEY_PROTOCOL_FIELD;
        rdata[3] = key->algorithm;

        if(eddsa_public_store(eddsa, &rdata[4], sizeof(rdata) - 4) != rdata_size)
        {
            EVP_PKEY_free(eddsa);
            return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
        }

        /* Note : + 4 because of the flags,protocol & algorithm bytes
         *        are not taken in account
         */

        tag = dnskey_get_tag_from_rdata(rdata, rdata_size + 4);
        if(key->key.evp_key != NULL)
        {
            EVP_PKEY_free(key->key.evp_key);
        }
        key->key.evp_key = eddsa;

        key->tag = tag;
        key->nid = nid;

        key->status |= DNSKEY_KEY_IS_VALID | DNSKEY_KEY_IS_PRIVATE;

        return SUCCESS;
    }

    return DNSSEC_ERROR_INCOMPLETEKEY;
}

static void dnskey_eddsa_parse_finalize(struct dnskey_field_parser *parser)
{
    struct dnskey_eddsa_s *ydsa = (struct dnskey_eddsa_s *)parser->data;

    if(ydsa != NULL)
    {
        dnskey_eddsa_finalize(ydsa);
        ZFREE(ydsa, struct dnskey_eddsa_s);
    }
}

static const struct dnskey_field_parser_vtbl eddsa_field_parser_vtbl = {dnskey_eddsa_parse_field, dnskey_eddsa_parse_set_key, dnskey_eddsa_parse_finalize, "EDDSA"};

void                                         dnskey_eddsa_parse_init(dnskey_field_parser *fp)
{
    struct dnskey_eddsa_s *yeddsa;
    ZALLOC_OBJECT_OR_DIE(yeddsa, struct dnskey_eddsa_s, KEYECDSA_TAG);
    ZEROMEMORY(yeddsa, sizeof(struct dnskey_eddsa_s));
    fp->data = yeddsa;
    fp->vtbl = &eddsa_field_parser_vtbl;
}

ya_result dnskey_eddsa_loadpublic(const uint8_t *rdata, uint16_t rdata_size, const char *origin, dnskey_t **out_key)
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

    EVP_PKEY *eddsa = dnskey_eddsa_public_load(algorithm, rdata, rdata_size);

    if(eddsa != NULL)
    {
        dnskey_t *key = NULL;

        if(ISOK(return_value = dnskey_eddsa_initinstance(eddsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }

        EVP_PKEY_free(eddsa);
    }

    return return_value;
}

ya_result dnskey_eddsa_newinstance(uint32_t size, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key)
{
    *out_key = NULL;

    if(size > DNSSEC_MAXIMUM_KEY_SIZE)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    if((algorithm != DNSKEY_ALGORITHM_ED25519) && (algorithm != DNSKEY_ALGORITHM_ED448))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    ya_result     ret = ERROR;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(dnskey_eddsa_getnid(algorithm), NULL);
    if(ctx != NULL)
    {
        if(EVP_PKEY_keygen_init(ctx) == 1)
        {
            EVP_PKEY *evp_key = NULL;

            if(EVP_PKEY_keygen(ctx, &evp_key) == 1)
            {
                dnskey_t *key = NULL;

                if(ISOK(ret = dnskey_eddsa_initinstance(evp_key, algorithm, flags, origin, &key)))
                {
                    *out_key = key;
                }
            }
        }

        if(FAIL(ret))
        {
            unsigned long ssl_err;

            while((ssl_err = ERR_get_error()) != 0)
            {
                char buffer[256];
                ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
                osformatln(termerr, "digest signature returned an ssl error %08x %s", (unsigned int)ssl_err, buffer);
            }

            ERR_clear_error();
        }

        EVP_PKEY_CTX_free(ctx);
    }

    return ret;
}
#else

void dnskey_eddsa_not_supported() {}

#endif // HAS_EDDSA_SUPPORT

/** @} */

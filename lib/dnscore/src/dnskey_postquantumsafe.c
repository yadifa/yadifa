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

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <oqs/oqs.h>

#include "dnscore/dnscore_config.h"

#include "dnscore/dnscore.h"
#include "dnscore/sys_types.h"
#include "dnscore/base64.h"

#include "dnscore/logger.h"
#include "dnscore/dnskey.h"
#include "dnscore/dnskey_postquantumsafe.h"
#include "dnscore/dnssec_errors.h"

#include "dnscore/zalloc.h"

#define MODULE_MSG_HANDLE                                g_system_logger

#define KEYPOSTQUANTUMSAFE_TAG                           0x415344434559454b

#define DNSKEY_ALGORITHM_DILITHIUM2_OQS_NAME             OQS_SIG_alg_dilithium_2
#define DNSKEY_ALGORITHM_DILITHIUM3_OQS_NAME             OQS_SIG_alg_dilithium_3
#define DNSKEY_ALGORITHM_DILITHIUM5_OQS_NAME             OQS_SIG_alg_dilithium_5
#define DNSKEY_ALGORITHM_FALCON512_OQS_NAME              OQS_SIG_alg_falcon_512
#define DNSKEY_ALGORITHM_FALCON1024_OQS_NAME             OQS_SIG_alg_falcon_1024
#define DNSKEY_ALGORITHM_FALCONPAD512_OQS_NAME           OQS_SIG_alg_falcon_padded_512
#define DNSKEY_ALGORITHM_FALCONPAD1024_OQS_NAME          OQS_SIG_alg_falcon_padded_1024
#define DNSKEY_ALGORITHM_SPHINCSSHA2128F_OQS_NAME        OQS_SIG_alg_sphincs_sha2_128f_simple
#define DNSKEY_ALGORITHM_SPHINCSSHA2128S_OQS_NAME        OQS_SIG_alg_sphincs_sha2_128s_simple
#define DNSKEY_ALGORITHM_SPHINCSSHA2192F_OQS_NAME        OQS_SIG_alg_sphincs_sha2_192f_simple
#define DNSKEY_ALGORITHM_SPHINCSSHA2192S_OQS_NAME        OQS_SIG_alg_sphincs_sha2_192s_simple
#define DNSKEY_ALGORITHM_SPHINCSSHA2256F_OQS_NAME        OQS_SIG_alg_sphincs_sha2_256f_simple
#define DNSKEY_ALGORITHM_SPHINCSSHA2256S_OQS_NAME        OQS_SIG_alg_sphincs_sha2_256s_simple
#define DNSKEY_ALGORITHM_SPHINCSSHAKE128F_OQS_NAME       OQS_SIG_alg_sphincs_shake_128f_simple
#define DNSKEY_ALGORITHM_SPHINCSSHAKE128S_OQS_NAME       OQS_SIG_alg_sphincs_shake_128s_simple
#define DNSKEY_ALGORITHM_SPHINCSSHAKE192F_OQS_NAME       OQS_SIG_alg_sphincs_shake_192f_simple
#define DNSKEY_ALGORITHM_SPHINCSSHAKE192S_OQS_NAME       OQS_SIG_alg_sphincs_shake_192s_simple
#define DNSKEY_ALGORITHM_SPHINCSSHAKE256F_OQS_NAME       OQS_SIG_alg_sphincs_shake_256f_simple
#define DNSKEY_ALGORITHM_SPHINCSSHAKE256S_OQS_NAME       OQS_SIG_alg_sphincs_shake_256s_simple
#define DNSKEY_ALGORITHM_MAYO1_OQS_NAME                  OQS_SIG_alg_mayo_1
#define DNSKEY_ALGORITHM_MAYO2_OQS_NAME                  OQS_SIG_alg_mayo_2
#define DNSKEY_ALGORITHM_MAYO3_OQS_NAME                  OQS_SIG_alg_mayo_3
#define DNSKEY_ALGORITHM_MAYO5_OQS_NAME                  OQS_SIG_alg_mayo_5
#define DNSKEY_ALGORITHM_CROSS_RSDP128BALANCED_OQS_NAME  OQS_SIG_alg_cross_rsdp_128_balanced
#define DNSKEY_ALGORITHM_CROSS_RSDP128FAST_OQS_NAME      OQS_SIG_alg_cross_rsdp_128_fast
#define DNSKEY_ALGORITHM_CROSS_RSDP128SMALL_OQS_NAME     OQS_SIG_alg_cross_rsdp_128_small
#define DNSKEY_ALGORITHM_CROSS_RSDP192BALANCED_OQS_NAME  OQS_SIG_alg_cross_rsdp_192_balanced
#define DNSKEY_ALGORITHM_CROSS_RSDP192FAST_OQS_NAME      OQS_SIG_alg_cross_rsdp_192_fast
#define DNSKEY_ALGORITHM_CROSS_RSDP192SMALL_OQS_NAME     OQS_SIG_alg_cross_rsdp_192_small
#define DNSKEY_ALGORITHM_CROSS_RSDP256BALANCED_OQS_NAME  OQS_SIG_alg_cross_rsdp_256_balanced
// #define DNSKEY_ALGORITHM_CROSS_RSDP256FAST_OQS_NAME      OQS_SIG_alg_cross_rsdp_256_fast
#define DNSKEY_ALGORITHM_CROSS_RSDP256SMALL_OQS_NAME     OQS_SIG_alg_cross_rsdp_256_small
#define DNSKEY_ALGORITHM_CROSS_RSDPG128BALANCED_OQS_NAME OQS_SIG_alg_cross_rsdpg_128_balanced
#define DNSKEY_ALGORITHM_CROSS_RSDPG128FAST_OQS_NAME     OQS_SIG_alg_cross_rsdpg_128_fast
#define DNSKEY_ALGORITHM_CROSS_RSDPG128SMALL_OQS_NAME    OQS_SIG_alg_cross_rsdpg_128_small
#define DNSKEY_ALGORITHM_CROSS_RSDPG192BALANCED_OQS_NAME OQS_SIG_alg_cross_rsdpg_192_balanced
#define DNSKEY_ALGORITHM_CROSS_RSDPG192FAST_OQS_NAME     OQS_SIG_alg_cross_rsdpg_192_fast
#define DNSKEY_ALGORITHM_CROSS_RSDPG192SMALL_OQS_NAME    OQS_SIG_alg_cross_rsdpg_192_small
#define DNSKEY_ALGORITHM_CROSS_RSDPG256BALANCED_OQS_NAME OQS_SIG_alg_cross_rsdpg_256_balanced
#define DNSKEY_ALGORITHM_CROSS_RSDPG256FAST_OQS_NAME     OQS_SIG_alg_cross_rsdpg_256_fast
#define DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL_OQS_NAME    OQS_SIG_alg_cross_rsdpg_256_small

struct postquantumsafe_key_s
{
    uint8_t *public_key;
    size_t   public_key_size;
    uint8_t *private_key;
    size_t   private_key_size;
    OQS_SIG *sig; // internal OQS structure used to generate a key, sign, and verify
    uint8_t  algorithm;
};

typedef struct postquantumsafe_key_s postquantumsafe_key_t;

static void                          postquantumsafe_free(postquantumsafe_key_t *pqs_key)
{
    if(pqs_key != NULL)
    {
        OQS_SIG_free(pqs_key->sig);
    }
    free(pqs_key->public_key);
    OQS_MEM_secure_free(pqs_key->private_key, pqs_key->private_key_size);
    ZFREE_OBJECT(pqs_key);
}

static const char *dnskey_postquantumsafe_algorithm_to_name(uint8_t algorithm)
{
    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_DILITHIUM2:
            return DNSKEY_ALGORITHM_DILITHIUM2_OQS_NAME;
        case DNSKEY_ALGORITHM_DILITHIUM3:
            return DNSKEY_ALGORITHM_DILITHIUM3_OQS_NAME;
        case DNSKEY_ALGORITHM_DILITHIUM5:
            return DNSKEY_ALGORITHM_DILITHIUM5_OQS_NAME;
        case DNSKEY_ALGORITHM_FALCON512:
            return DNSKEY_ALGORITHM_FALCON512_OQS_NAME;
        case DNSKEY_ALGORITHM_FALCON1024:
            return DNSKEY_ALGORITHM_FALCON1024_OQS_NAME;
        case DNSKEY_ALGORITHM_FALCONPAD512:
            return DNSKEY_ALGORITHM_FALCONPAD512_OQS_NAME;
        case DNSKEY_ALGORITHM_FALCONPAD1024:
            return DNSKEY_ALGORITHM_FALCONPAD1024_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2128F:
            return DNSKEY_ALGORITHM_SPHINCSSHA2128F_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2128S:
            return DNSKEY_ALGORITHM_SPHINCSSHA2128S_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2192F:
            return DNSKEY_ALGORITHM_SPHINCSSHA2192F_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2192S:
            return DNSKEY_ALGORITHM_SPHINCSSHA2192S_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2256F:
            return DNSKEY_ALGORITHM_SPHINCSSHA2256F_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHA2256S:
            return DNSKEY_ALGORITHM_SPHINCSSHA2256S_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE128F:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE128F_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE128S:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE128S_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE192F:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE192F_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE192S:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE192S_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE256F:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE256F_OQS_NAME;
        case DNSKEY_ALGORITHM_SPHINCSSHAKE256S:
            return DNSKEY_ALGORITHM_SPHINCSSHAKE256S_OQS_NAME;
        case DNSKEY_ALGORITHM_MAYO1:
            return DNSKEY_ALGORITHM_MAYO1_OQS_NAME;
        case DNSKEY_ALGORITHM_MAYO2:
            return DNSKEY_ALGORITHM_MAYO2_OQS_NAME;
        case DNSKEY_ALGORITHM_MAYO3:
            return DNSKEY_ALGORITHM_MAYO3_OQS_NAME;
        case DNSKEY_ALGORITHM_MAYO5:
            return DNSKEY_ALGORITHM_MAYO5_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP128BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDP128BALANCED_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP128FAST:
            return DNSKEY_ALGORITHM_CROSS_RSDP128FAST_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP128SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDP128SMALL_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP192BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDP192BALANCED_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP192FAST:
            return DNSKEY_ALGORITHM_CROSS_RSDP192FAST_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP192SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDP192SMALL_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP256BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDP256BALANCED_OQS_NAME;
        // case DNSKEY_ALGORITHM_CROSS_RSDP256FAST: return DNSKEY_ALGORITHM_CROSS_RSDP256FAST_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDP256SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDP256SMALL_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG128BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDPG128BALANCED_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG128FAST:
            return DNSKEY_ALGORITHM_CROSS_RSDPG128FAST_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG128SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDPG128SMALL_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG192BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDPG192BALANCED_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG192FAST:
            return DNSKEY_ALGORITHM_CROSS_RSDPG192FAST_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG192SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDPG192SMALL_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG256BALANCED:
            return DNSKEY_ALGORITHM_CROSS_RSDPG256BALANCED_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG256FAST:
            return DNSKEY_ALGORITHM_CROSS_RSDPG256FAST_OQS_NAME;
        case DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL:
            return DNSKEY_ALGORITHM_CROSS_RSDPG256SMALL_OQS_NAME;

        default:
            return NULL;
    }
}

/*
 * Intermediary key
 */

struct dnskey_postquantumsafe_s
{
    dnskey_raw_field_t private_key;
};

struct dnskey_postquantumsafe_const_s
{
    const dnskey_raw_field_t private_key;
};

static void dnskey_postquantumsafe_init(struct dnskey_postquantumsafe_s *ypostquantumsafe) { memset(ypostquantumsafe, 0, sizeof(struct dnskey_postquantumsafe_s)); }

static bool dnskey_postquantumsafe_to_postquantumsafe(struct dnskey_postquantumsafe_s *ypostquantumsafe, postquantumsafe_key_t *pqs_key)
{
    if(ypostquantumsafe->private_key.buffer != NULL)
    {
        pqs_key->private_key = ypostquantumsafe->private_key.buffer;
        pqs_key->private_key_size = ypostquantumsafe->private_key.size;
        ypostquantumsafe->private_key.buffer = NULL;
        ypostquantumsafe->private_key.size = 0;
        return true;
    }
    else
    {
        return false;
    }
}

static void dnskey_postquantumsafe_from_postquantumsafe(struct dnskey_postquantumsafe_s *ypostquantumsafe, const postquantumsafe_key_t *pqs_key)
{
    uint8_t *buffer;
    if(pqs_key->private_key != NULL)
    {
        MALLOC_OBJECT_ARRAY_OR_DIE(buffer, uint8_t, pqs_key->private_key_size, EDDSABFR_TAG);
        memcpy(buffer, pqs_key->private_key, pqs_key->private_key_size);
        ypostquantumsafe->private_key.buffer = buffer;
        ypostquantumsafe->private_key.size = pqs_key->private_key_size;
    }
    else
    {
        ypostquantumsafe->private_key.buffer = NULL;
        ypostquantumsafe->private_key.size = 0;
    }
}

static void dnskey_postquantumsafe_finalize(struct dnskey_postquantumsafe_s *ypostquantumsafe)
{
    if(ypostquantumsafe->private_key.buffer != NULL)
    {
        dnskey_raw_field_clean_finalize(&ypostquantumsafe->private_key);
    }
    dnskey_postquantumsafe_init(ypostquantumsafe);
}

static const struct dnskey_field_access_s POSTQUANTUMSAFE_field_access[] = {{"PrivateKey", offsetof(struct dnskey_postquantumsafe_s, private_key), STRUCTDESCRIPTOR_RAW}, {"", 0, 0}};

static int                                dnskey_postquantumsafe_getnid(uint8_t algorithm) { return 0x40000000 | algorithm; }

static postquantumsafe_key_t             *dnskey_postquantumsafe_public_load(uint8_t algorithm, const uint8_t *rdata, uint16_t rdata_size)
{
    const char *name = dnskey_postquantumsafe_algorithm_to_name(algorithm);

    if(name == NULL)
    {
        return NULL;
    }

    OQS_SIG *sig = OQS_SIG_new(name);

    if(sig != NULL)
    {
        if(sig->length_public_key == rdata_size)
        {
            uint8_t *public_key;
            MALLOC_OBJECT_ARRAY_OR_DIE(public_key, uint8_t, rdata_size, GENERIC_TAG);
            memcpy(public_key, rdata, rdata_size);

            postquantumsafe_key_t *pqs_key;
            ZALLOC_OBJECT_OR_DIE(pqs_key, postquantumsafe_key_t, GENERIC_TAG);
            pqs_key->public_key = public_key;
            pqs_key->public_key_size = sig->length_public_key;
            pqs_key->private_key = NULL;
            pqs_key->private_key_size = 0;
            pqs_key->sig = sig;
            pqs_key->algorithm = algorithm;

            return pqs_key;
        }
        else
        {
            OQS_SIG_free(sig);
        }
    }

    return NULL;
}

static uint32_t dnskey_postquantumsafe_public_store(const postquantumsafe_key_t *pqs_key, uint8_t *output_buffer)
{
    memcpy(output_buffer, pqs_key->public_key, pqs_key->public_key_size);
    return pqs_key->public_key_size;
}

static uint32_t dnskey_postquantumsafe_dnskey_public_store(const dnskey_t *key, uint8_t *rdata, size_t rdata_size)
{
    (void)rdata_size;
    uint32_t len;

    SET_U16_AT(rdata[0], key->flags);
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = key->algorithm;

    len = dnskey_postquantumsafe_public_store(key->key.any, &rdata[4]) + 4;

    return len;
}

static uint32_t dnskey_postquantumsafe_size(const dnskey_t *key)
{
    postquantumsafe_key_t *pqs_key = key->key.any;

    return pqs_key->public_key_size << 3;
}

/**
 * Returns the size in byte of the public key.
 *
 * @param postquantumsafe
 * @return
 */

static uint32_t dnskey_postquantumsafe_public_size(postquantumsafe_key_t *pqs_key) { return pqs_key->public_key_size; }

static uint32_t dnskey_postquantumsafe_dnskey_rdatasize(const dnskey_t *key)
{
    uint32_t size = dnskey_postquantumsafe_public_size(key->key.any) + 4;
    return size;
}

static void dnskey_postquantumsafe_free(dnskey_t *key)
{
    if(key->key.any != NULL)
    {
        postquantumsafe_free(key->key.any);
    }
    key->key.any = NULL;
}

static bool dnskey_postquantumsafe_equals(const dnskey_t *key_a, const dnskey_t *key_b)
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
            postquantumsafe_key_t *pqs_key_a = key_a->key.any;
            postquantumsafe_key_t *pqs_key_b = key_b->key.any;
            if(pqs_key_a->public_key_size == pqs_key_b->public_key_size)
            {
                if(pqs_key_a->private_key_size == pqs_key_b->private_key_size)
                {
                    if(memcmp(pqs_key_a->public_key, pqs_key_b->public_key, pqs_key_a->public_key_size) == 0)
                    {
                        if(memcmp(pqs_key_a->private_key, pqs_key_b->private_key, pqs_key_a->private_key_size) == 0)
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }

    return false;
}

static ya_result dnskey_postquantumsafe_print_fields(dnskey_t *key, output_stream_t *os)
{
    struct dnskey_postquantumsafe_s ypostquantumsafe;
    dnskey_postquantumsafe_from_postquantumsafe(&ypostquantumsafe, key->key.any);

    ya_result ret = dnskey_field_access_print(POSTQUANTUMSAFE_field_access, &ypostquantumsafe, os);

    return ret;
}

//////////////////////////////////////////////////////////////////////////////

static int32_t dnskey_postquantumsafe_signer_update(struct bytes_signer_s *signer, const void *buffer, uint32_t buffer_size)
{
    digest_t *digest_ctx = (digest_t *)signer->dctx;
    int32_t   ret = digest_update(digest_ctx, buffer, buffer_size);
    return ret;
}

static int32_t dnskey_postquantumsafe_signer_sign(struct bytes_signer_s *signer, void *signature, uint32_t *signature_size)
{
    digest_t              *digest_ctx = (digest_t *)signer->dctx;
    dnskey_t              *key = (dnskey_t *)signer->kctx;
    uint8_t               *digest;
    int32_t                digest_size = digest_get_digest(digest_ctx, (void **)&digest);
    ya_result              ret;

    postquantumsafe_key_t *pqs_key = key->key.any;

    size_t                 signature_size_ = *signature_size;

    OQS_STATUS             rc = OQS_SIG_sign(pqs_key->sig, signature, &signature_size_, digest, digest_size, pqs_key->private_key);

    ret = (rc == OQS_SUCCESS) ? SUCCESS : ERROR;

    *signature_size = (uint32_t)signature_size_;

    return ret;
}

static int32_t dnskey_postquantumsafe_signer_finalise(struct bytes_signer_s *signer)
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

static int32_t dnskey_postquantumsafe_verifier_update(struct bytes_verifier_s *verifier, const void *buffer, uint32_t buffer_size)
{
    digest_t *digest_ctx = (digest_t *)verifier->dctx;
    int32_t   ret = digest_update(digest_ctx, buffer, buffer_size);
    return ret;
}

static bool dnskey_postquantumsafe_verifier_verify(struct bytes_verifier_s *verifier, const void *signature, uint32_t signature_size)
{
    digest_t              *digest_ctx = (digest_t *)verifier->dctx;
    dnskey_t              *key = (dnskey_t *)verifier->kctx;
    uint8_t               *digest;
    int32_t                digest_size = digest_get_digest(digest_ctx, (void **)&digest);

    postquantumsafe_key_t *pqs_key = key->key.any;

    OQS_STATUS             rc = OQS_SIG_verify(pqs_key->sig, digest, digest_size, signature, signature_size, pqs_key->public_key);

    return (rc == OQS_SUCCESS) ? true : false;
}

static int32_t dnskey_postquantumsafe_verifier_finalise(struct bytes_verifier_s *verifier)
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

static const struct bytes_signer_vtbl dnskey_postquantumsafe_bytes_signer_vtbl = {dnskey_postquantumsafe_signer_update, dnskey_postquantumsafe_signer_sign, dnskey_postquantumsafe_signer_finalise};

static ya_result                      dnskey_postquantumsafe_signer_init(dnskey_t *key, bytes_signer_t *signer)
{
    digest_t *ctx;
    ZALLOC_OBJECT_OR_DIE(ctx, digest_t, DIGEST_TAG);
    digest_rawdata_init(ctx);

    dnskey_acquire(key);
    signer->dctx = ctx;
    signer->kctx = key;
    signer->vtbl = &dnskey_postquantumsafe_bytes_signer_vtbl;
    return SUCCESS;
}

static const struct bytes_verifier_vtbl dnskey_postquantumsafe_bytes_verifier_vtbl = {dnskey_postquantumsafe_verifier_update, dnskey_postquantumsafe_verifier_verify, dnskey_postquantumsafe_verifier_finalise};

static ya_result                        dnskey_postquantumsafe_verifier_init(dnskey_t *key, bytes_verifier_t *verifier)
{
    digest_t *ctx;
    ZALLOC_OBJECT_OR_DIE(ctx, digest_t, DIGEST_TAG);
    digest_rawdata_init(ctx);

    dnskey_acquire(key);
    verifier->dctx = ctx;
    verifier->kctx = key;
    verifier->vtbl = &dnskey_postquantumsafe_bytes_verifier_vtbl;
    return SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////

static const dnskey_vtbl postquantumsafe_vtbl = {dnskey_postquantumsafe_signer_init,
                                                 dnskey_postquantumsafe_verifier_init,
                                                 dnskey_postquantumsafe_dnskey_rdatasize,
                                                 dnskey_postquantumsafe_dnskey_public_store,
                                                 dnskey_postquantumsafe_free,
                                                 dnskey_postquantumsafe_equals,
                                                 dnskey_postquantumsafe_print_fields,
                                                 dnskey_postquantumsafe_size,
                                                 "POSTQUANTUMSAFE"};

static ya_result         dnskey_postquantumsafe_initinstance(postquantumsafe_key_t *pqs_key, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key)
{
    int     nid = dnskey_postquantumsafe_getnid(algorithm);

    uint8_t rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES]; /* 4096 bits -> 1KB */

    *out_key = NULL;

#if DEBUG
    memset(rdata, 0xff, sizeof(rdata));
#endif

    SET_U16_AT(rdata[0], flags); // NATIVEFLAGS
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = algorithm;

    if(dnskey_postquantumsafe_public_store(pqs_key, &rdata[4]) != pqs_key->public_key_size)
    {
        return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
    }

    /* Note : + 4 because of the flags,protocol & algorithm bytes
     *        are not taken in account
     */

    uint16_t  tag = dnskey_get_tag_from_rdata(rdata, pqs_key->public_key_size + 4);

    dnskey_t *key = dnskey_newemptyinstance(algorithm, flags, origin); // RC

    if(key == NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    key->key.any = pqs_key;
    key->vtbl = &postquantumsafe_vtbl;
    key->tag = tag;
    key->nid = nid;
    key->status |= (pqs_key->private_key != NULL) ? DNSKEY_KEY_IS_PRIVATE : 0;

    *out_key = key;

    return SUCCESS;
}

static ya_result dnskey_postquantumsafe_parse_field(struct dnskey_field_parser *parser, parser_t *p)
{
    struct dnskey_postquantumsafe_s *ypostquantumsafe = (struct dnskey_postquantumsafe_s *)parser->data;

    ya_result                        ret = dnskey_field_access_parse(POSTQUANTUMSAFE_field_access, ypostquantumsafe, p);

    return ret;
}

static ya_result dnskey_postquantumsafe_parse_set_key(struct dnskey_field_parser *parser, dnskey_t *key)
{
    struct dnskey_postquantumsafe_s *ypostquantumsafe = (struct dnskey_postquantumsafe_s *)parser->data;

    if(key == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    const char *name = dnskey_postquantumsafe_algorithm_to_name(key->algorithm);

    if(name == NULL)
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    if(ypostquantumsafe->private_key.size == 0)
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }

    int nid;

    if(FAIL(nid = dnskey_postquantumsafe_getnid(key->algorithm)))
    {
        return nid;
    }

    if(key->key.any == NULL)
    {
        postquantumsafe_key_t *pqs_key;
        ZALLOC_OBJECT_OR_DIE(pqs_key, postquantumsafe_key_t, GENERIC_TAG);
        memset(pqs_key, 0, sizeof(postquantumsafe_key_t));
        pqs_key->algorithm = key->algorithm;

        key->key.any = pqs_key;
        key->vtbl = &postquantumsafe_vtbl;
    }

    postquantumsafe_key_t *pqs_key = key->key.any;

    if(dnskey_postquantumsafe_to_postquantumsafe(ypostquantumsafe, pqs_key) != 0)
    {
        // at this point, ypostquantumsafe has been emptied

        uint32_t rdata_size = dnskey_postquantumsafe_public_size(pqs_key);

        uint16_t tag;

        uint8_t  rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];

        if(rdata_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
        {
            return DNSSEC_ERROR_KEYISTOOBIG;
        }

        SET_U16_AT(rdata[0], key->flags);
        rdata[2] = DNSKEY_PROTOCOL_FIELD;
        rdata[3] = key->algorithm;

        if(dnskey_postquantumsafe_public_store(pqs_key, &rdata[4]) != rdata_size)
        {
            return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
        }

        /* Note : + 4 because of the flags,protocol & algorithm bytes
         *        are not taken in account
         */

        tag = dnskey_get_tag_from_rdata(rdata, rdata_size + 4);

        key->tag = tag;
        key->nid = nid;

        key->status |= DNSKEY_KEY_IS_VALID | DNSKEY_KEY_IS_PRIVATE;

        return SUCCESS;
    }
    else
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }
}

static void dnskey_postquantumsafe_parse_finalize(struct dnskey_field_parser *parser)
{
    struct dnskey_postquantumsafe_s *ydsa = (struct dnskey_postquantumsafe_s *)parser->data;

    if(ydsa != NULL)
    {
        dnskey_postquantumsafe_finalize(ydsa);
        ZFREE(ydsa, struct dnskey_postquantumsafe_s);
    }
}

static const struct dnskey_field_parser_vtbl postquantumsafe_field_parser_vtbl = {dnskey_postquantumsafe_parse_field, dnskey_postquantumsafe_parse_set_key, dnskey_postquantumsafe_parse_finalize, "POSTQUANTUMSAFE"};

void                                         dnskey_postquantumsafe_parse_init(dnskey_field_parser *fp)
{
    struct dnskey_postquantumsafe_s *ypostquantumsafe;
    ZALLOC_OBJECT_OR_DIE(ypostquantumsafe, struct dnskey_postquantumsafe_s, KEYPOSTQUANTUMSAFE_TAG);
    ZEROMEMORY(ypostquantumsafe, sizeof(struct dnskey_postquantumsafe_s));
    fp->data = ypostquantumsafe;
    fp->vtbl = &postquantumsafe_field_parser_vtbl;
}

ya_result dnskey_postquantumsafe_loadpublic(const uint8_t *rdata, uint16_t rdata_size, const char *origin, dnskey_t **out_key)
{
    *out_key = NULL;

    if(rdata == NULL || rdata_size <= 6 || origin == NULL)
    {
        /* bad */

        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    uint16_t    flags = GET_U16_AT(rdata[0]);
    uint8_t     algorithm = rdata[3];

    const char *name = dnskey_postquantumsafe_algorithm_to_name(algorithm);

    if(name == NULL)
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    rdata += 4;
    rdata_size -= 4;

    ya_result              ret = DNSSEC_ERROR_CANNOT_READ_KEY_FROM_RDATA;

    postquantumsafe_key_t *pqs_key = dnskey_postquantumsafe_public_load(algorithm, rdata, rdata_size);

    if(pqs_key != NULL)
    {
        dnskey_t *key;

        if(ISOK(ret = dnskey_postquantumsafe_initinstance(pqs_key, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return ret;
        }
    }

    return ret;
}

ya_result dnskey_postquantumsafe_newinstance(uint32_t size, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key)
{
    (void)size;
    *out_key = NULL;

    const char *name = dnskey_postquantumsafe_algorithm_to_name(algorithm);

    if(name == NULL)
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    ya_result ret = DNSSEC_ERROR_KEY_GENERATION_FAILED;

    OQS_SIG  *sig = OQS_SIG_new(name);

    if(sig != NULL)
    {
        dnskey_t *key;
        uint8_t  *public_key;
        uint8_t  *private_key;
        MALLOC_OBJECT_ARRAY_OR_DIE(public_key, uint8_t, sig->length_public_key, GENERIC_TAG);
        MALLOC_OBJECT_ARRAY_OR_DIE(private_key, uint8_t, sig->length_secret_key, GENERIC_TAG);
        OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, private_key);
        if(rc != OQS_SUCCESS)
        {
            return ret; // something is wrong ...
        }

        postquantumsafe_key_t *pqs_key;
        ZALLOC_OBJECT_OR_DIE(pqs_key, postquantumsafe_key_t, GENERIC_TAG);
        pqs_key->public_key = public_key;
        pqs_key->public_key_size = sig->length_public_key;
        pqs_key->private_key = private_key;
        pqs_key->private_key_size = sig->length_secret_key;
        pqs_key->sig = sig;
        pqs_key->algorithm = algorithm;

        if(ISOK(ret = dnskey_postquantumsafe_initinstance(pqs_key, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return ret;
        }
    }

    return ret;
}

/** @} */

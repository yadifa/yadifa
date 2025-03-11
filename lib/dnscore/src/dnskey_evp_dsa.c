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
#include "dnscore/openssl.h"

#include "dnscore/sys_types.h"
#include "dnscore/base64.h"

#include "dnscore/dnskey_dsa.h"
#include "dnscore/dnssec_errors.h"
#include "dnscore/parser.h"
#include "dnscore/tools.h"
#include "dnscore/zalloc.h"

#define MODULE_MSG_HANDLE g_system_logger

#define KEYDSA_TAG        0x41535259454b

#ifndef SSL_API
#error "SSL_API not defined"
#endif

struct dnskey_dsa_s
{
    dnskey_raw_field_t p, q, g, pub_key, priv_key;
};

struct dnskey_dsa_const_s
{
    const dnskey_raw_field_t p, q, g, pub_key, priv_key;
};

static void dnskey_dsa_init(struct dnskey_dsa_s *ydsa) { memset(ydsa, 0, sizeof(struct dnskey_dsa_s)); }

static void dnskey_dsa_finalize(struct dnskey_dsa_s *ydsa)
{
    dnskey_raw_field_clean_finalize(&ydsa->p);
    dnskey_raw_field_clean_finalize(&ydsa->q);
    dnskey_raw_field_clean_finalize(&ydsa->g);
    dnskey_raw_field_clean_finalize(&ydsa->pub_key);
    dnskey_raw_field_clean_finalize(&ydsa->priv_key);

    dnskey_dsa_init(ydsa);
}

static const struct dnskey_field_access DSA_field_access[] = {{"Base(g)", offsetof(struct dnskey_dsa_s, g), STRUCTDESCRIPTOR_REVRAW},
                                                              {"Prime(p)", offsetof(struct dnskey_dsa_s, p), STRUCTDESCRIPTOR_REVRAW},
                                                              {"Subprime(q)", offsetof(struct dnskey_dsa_s, q), STRUCTDESCRIPTOR_REVRAW},
                                                              {"Public_value(y)", offsetof(struct dnskey_dsa_s, pub_key), STRUCTDESCRIPTOR_REVRAW},
                                                              {"Private_value(x)", offsetof(struct dnskey_dsa_s, priv_key), STRUCTDESCRIPTOR_REVRAW},
                                                              {"", 0, 0}};

static int                              dnskey_dsa_getnid(uint8_t algorithm)
{
    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_DSASHA1:
        {
            return NID_sha1;
        }
        default:
        {
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        }
    }
}

void             EVP_PKEY_dump_params(EVP_PKEY *evp_key);

static EVP_PKEY *dnskey_dsa_genkey(uint32_t size)
{
    yassert(size >= DNSSEC_MINIMUM_KEY_SIZE && size <= DNSSEC_MAXIMUM_KEY_SIZE);

    const int     id = EVP_PKEY_DSA;

    EVP_PKEY     *evp_key = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(id, NULL);
    if(pctx != NULL)
    {
        EVP_PKEY *param_key = NULL;
        if(EVP_PKEY_paramgen_init(pctx) > 0)
        {
            if(EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, size) > 0)
            {
                if(EVP_PKEY_CTX_set_dsa_paramgen_q_bits(pctx, 160) > 0)
                {
                    if(EVP_PKEY_generate(pctx, &param_key) > 0)
                    {
                        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
                        if(kctx != NULL)
                        {
                            if(EVP_PKEY_keygen_init(kctx) > 0)
                            {
                                if(EVP_PKEY_generate(kctx, &evp_key) > 0)
                                {
                                    // yay
                                    // EVP_PKEY_dump_params(evp_key);
                                }
                            }
                            EVP_PKEY_CTX_free(kctx);
                        }
                    }
                }
            }
            EVP_PKEY_free(param_key);
        }

        EVP_PKEY_CTX_free(pctx);
    }

    return evp_key;
}

static EVP_PKEY *dnskey_dsa_public_load(const uint8_t *rdata, uint16_t rdata_size)
{
    // rdata_size < 4 is harsher than needed but anyway such a small key would
    // and this avoids another test later be worthless

    if(rdata == NULL || rdata_size < 4)
    {
        return NULL;
    }

    const uint8_t *inptr = rdata;
    uint32_t       t;
    t = *inptr;

    uint32_t pgy_len = 64 + (t << 3);

    if(rdata_size != 1 + 20 + 3 * pgy_len)
    {
        return NULL;
    }

    ++inptr;

    uint8_t  _buffer[1024];
    uint8_t *buffer;
    if(rdata_size <= sizeof(_buffer))
    {
        buffer = _buffer;
    }
    else
    {
        buffer = malloc(rdata_size);
    }

    uint8_t *swappedptr = buffer;

    bytes_copy_swap(swappedptr, inptr, 20);
    uint8_t *q = swappedptr;
    inptr += 20;
    swappedptr += 20;

    bytes_copy_swap(swappedptr, inptr, pgy_len);
    uint8_t *p = swappedptr;
    inptr += pgy_len;
    swappedptr += pgy_len;

    bytes_copy_swap(swappedptr, inptr, pgy_len);
    uint8_t *g = swappedptr;
    inptr += pgy_len;
    swappedptr += pgy_len;

    bytes_copy_swap(swappedptr, inptr, pgy_len);
    uint8_t      *y = swappedptr;

    const int     id = EVP_PKEY_DSA;

    EVP_PKEY     *evp_key = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(id, NULL);
    if(pctx != NULL)
    {
        if(EVP_PKEY_paramgen_init(pctx) > 0)
        {
            if(EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, (pgy_len) << 3) > 0)
            {
                EVP_PKEY *params = NULL;

                if(EVP_PKEY_paramgen(pctx, &params) > 0)
                {
                    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
                    if(kctx != NULL)
                    {
                        if(EVP_PKEY_fromdata_init(kctx) > 0)
                        {
                            OSSL_PARAM params[5] = {OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, q, 20),
                                                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, p, pgy_len),
                                                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, g, pgy_len),
                                                    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, y, pgy_len),
                                                    OSSL_PARAM_END};

                            if(EVP_PKEY_fromdata(kctx, &evp_key, EVP_PKEY_PUBLIC_KEY, params) > 0)
                            {
                                // yay
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

                        EVP_PKEY_CTX_free(kctx);
                    }

                    EVP_PKEY_free(params);
                }
            }
        }
        EVP_PKEY_CTX_free(pctx);
    }

    if(buffer != _buffer)
    {
        free(buffer);
    }

    return evp_key;
}

static uint32_t dnskey_dsa_public_store(EVP_PKEY *evp_key, uint8_t *output_buffer, uint32_t output_buffer_size)
{
    const uint8_t *outptr = output_buffer;

    BIGNUM        *q = NULL;
    BIGNUM        *p = NULL;
    BIGNUM        *g = NULL;
    BIGNUM        *pub_key = NULL;

    if(EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_FFC_Q, &q) > 0)
    {
        if(EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_FFC_P, &p) > 0)
        {
            if(EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_FFC_G, &g) > 0)
            {
                if(EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_PUB_KEY, &pub_key) > 0)
                {
                    int q_bytes = BN_num_bytes(q);
                    int p_bytes = BN_num_bytes(p);
                    int g_bytes = BN_num_bytes(g);
                    int pub_key_bytes = BN_num_bytes(pub_key);

                    if((q_bytes == 20) && (p_bytes >= 64) && ((p_bytes & 7) == 0) && (p_bytes == g_bytes) && (p_bytes == pub_key_bytes) && ((int)output_buffer_size >= (21 + p_bytes * 3)))
                    {
                        int t = (p_bytes - 64) >> 3;
                        output_buffer[0] = (uint8_t)t;
                        ++output_buffer;
                        BN_bn2bin(q, output_buffer);
                        output_buffer += q_bytes;
                        BN_bn2bin(p, output_buffer);
                        output_buffer += p_bytes;
                        BN_bn2bin(g, output_buffer);
                        output_buffer += g_bytes;
                        BN_bn2bin(pub_key, output_buffer);
                        output_buffer += pub_key_bytes;
                    }

                    BN_clear_free(pub_key);
                }
                BN_clear_free(g);
            }
            BN_clear_free(p);
        }
        BN_clear_free(q);
    }

    return output_buffer - outptr;
}

static uint32_t dnskey_dsa_dnskey_public_store(const dnskey_t *key, uint8_t *rdata, size_t rdata_size)
{
    uint32_t len;

    SET_U16_AT(rdata[0], key->flags);
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = key->algorithm;

    len = dnskey_dsa_public_store(key->key.evp_key, &rdata[4], rdata_size - 4) + 4;

    return len;
}

static uint32_t dnskey_dsa_size(const dnskey_t *key)
{
    BIGNUM *p = NULL;

    if(EVP_PKEY_get_bn_param(key->key.evp_key, OSSL_PKEY_PARAM_FFC_P, &p) > 0)
    {
        uint32_t m_size = BN_num_bytes(p);
        BN_clear_free(p);
        return m_size << 3;
    }
    return 0;
}

/// Returns the number of bytes required to store the key part of the DNSKEY rdata

static uint32_t dnskey_dsa_public_size(const EVP_PKEY *evp_key)
{
    uint32_t size = 0;
    BIGNUM  *p = NULL;

    if(EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_FFC_P, &p) > 0)
    {
        uint32_t psize = BN_num_bytes(p);
        BN_clear_free(p);
        size = 21 + psize * 3;
    }

    return size;
}

static uint32_t dnskey_dsa_dnskey_rdatasize(const dnskey_t *key)
{
    uint32_t size = dnskey_dsa_public_size(key->key.evp_key) + 4;
    return size;
}

static bool dnskey_dsa_equals(const dnskey_t *key_a, const dnskey_t *key_b)
{
    /* DSA, compare modulus and exponent, exponent first (it's the smallest) */

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
        }
    }

    return false;
}

static ya_result dnskey_dsa_private_print_fields(dnskey_t *key, output_stream_t *os)
{
    struct dnskey_dsa_s ydsa;
    ZEROMEMORY(&ydsa, sizeof(struct dnskey_dsa_s));
    ya_result  ret = ERROR;

    OSSL_PARAM params[6] = {OSSL_PARAM_RAW(OSSL_PKEY_PARAM_FFC_Q, &ydsa.q),
                            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_FFC_P, &ydsa.p),
                            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_FFC_G, &ydsa.g),
                            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_PUB_KEY, &ydsa.pub_key),
                            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_PRIV_KEY, &ydsa.priv_key),
                            OSSL_PARAM_END};

    if(EVP_PKEY_get_params(key->key.evp_key, params) > 0)
    {
        int total_size = 0;
        for(OSSL_PARAM *param = params; param->key != NULL; ++param)
        {
            total_size += param->return_size;
        }
        uint8_t *buffer = malloc(total_size);
        if(buffer != NULL)
        {
            uint8_t *p = buffer;
            for(OSSL_PARAM *param = params; param->key != NULL; ++param)
            {
                ssize_t size = (ssize_t)param->return_size;
                if(size < 0)
                {
                    free(buffer);
                    return DNSSEC_ERROR_INCOMPLETEKEY; // not all the private fields are available
                }
                param->data = p;
                param->data_size = size;
                p += size;
            }

            if(EVP_PKEY_get_params(key->key.evp_key, params) > 0)
            {
                int i = 0;

                // note : order is important, obviously

                ydsa.q.buffer = params[i].data;
                ydsa.q.size = params[i++].data_size;

                ydsa.p.buffer = params[i].data;
                ydsa.p.size = params[i++].data_size;

                ydsa.g.buffer = params[i].data;
                ydsa.g.size = params[i++].data_size;

                ydsa.pub_key.buffer = params[i].data;
                ydsa.pub_key.size = params[i++].data_size;

                ydsa.priv_key.buffer = params[i].data;
                ydsa.priv_key.size = params[i++].data_size;

                ret = dnskey_field_access_print(DSA_field_access, &ydsa, os);
            }

            free(buffer);
        }
    }
    else
    {
        ret = ya_ssl_error();
    }

    return ret;
}

static const dnskey_vtbl dsa_vtbl = {dnskey_evp_signdigest, dnskey_evp_verifydigest, dnskey_dsa_dnskey_rdatasize, dnskey_dsa_dnskey_public_store, dnskey_evp_free, dnskey_dsa_equals, dnskey_dsa_private_print_fields, dnskey_dsa_size, "DSA"};

static ya_result         dnskey_dsa_initinstance(EVP_PKEY *evp_key, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key)
{
    int     nid;

    uint8_t rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES]; /* 4096 bits -> 1KB */

    *out_key = NULL;

    if(FAIL(nid = dnskey_dsa_getnid(algorithm)))
    {
        return nid;
    }

#if DEBUG
    memset(rdata, 0xff, sizeof(rdata));
#endif

    uint32_t rdata_size = dnskey_dsa_public_size(evp_key);

    if(rdata_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    SET_U16_AT(rdata[0], flags); // NATIVEFLAGS
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = algorithm;

    if(dnskey_dsa_public_store(evp_key, &rdata[4], sizeof(rdata) - 4) != rdata_size)
    {
        return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
    }

    /* Note : + 4 because of the flags,protocol & algorithm bytes
     *        are not taken in account
     */

    uint16_t  tag = dnskey_get_tag_from_rdata(rdata, rdata_size + 4);

    dnskey_t *key = dnskey_newemptyinstance(algorithm, flags, origin); // RC

    if(evp_key == NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    key->key.evp_key = evp_key;
    key->vtbl = &dsa_vtbl;
    key->tag = tag;
    key->nid = nid;

    BIGNUM *secret_exponent = NULL;

    if(EVP_PKEY_get_bn_param(evp_key, OSSL_PKEY_PARAM_PRIV_KEY, &secret_exponent) > 0)
    {
        key->status |= DNSKEY_KEY_IS_PRIVATE;
        BN_clear_free(secret_exponent);
    }

    *out_key = key;

    return SUCCESS;
}

static ya_result dnskey_dsa_parse_field(struct dnskey_field_parser *parser, parser_s *p)
{
    struct dnskey_dsa_s *ydsa = (struct dnskey_dsa_s *)parser->data;

    ya_result            ret = dnskey_field_access_parse(DSA_field_access, ydsa, p);

    return ret;
}

static ya_result dnskey_dsa_parse_set_key(struct dnskey_field_parser *parser, dnskey_t *key)
{
    if(key == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    // yassert(key->nid == 0);

    switch(key->algorithm)
    {
        case DNSKEY_ALGORITHM_DSASHA1:
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            break;
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    struct dnskey_dsa_s *ydsa = (struct dnskey_dsa_s *)parser->data;

    if(dnskey_raw_field_empty(&ydsa->q) || dnskey_raw_field_empty(&ydsa->p) || dnskey_raw_field_empty(&ydsa->g) || dnskey_raw_field_empty(&ydsa->pub_key))
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }

    int nid;

    if(FAIL(nid = dnskey_dsa_getnid(key->algorithm)))
    {
        return nid;
    }

    if((key->nid != 0) && (key->nid != nid))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    ya_result ret = DNSSEC_ERROR_INCOMPLETEKEY;

    bool      has_private = !dnskey_raw_field_empty(&ydsa->priv_key);
    bool      loaded = false;

    if(key->key.evp_key != NULL)
    {
        EVP_PKEY_free(key->key.evp_key); /// @TODO 20221014 edf -- I hate this but I've not found a way to transform a
                                         /// key with the EVP interface.
        key->key.evp_key = NULL;
    }

    if(key->key.evp_key == NULL)
    {
        key->vtbl = &dsa_vtbl;

        const int     id = EVP_PKEY_DSA;
        EVP_PKEY     *evp_key = NULL;
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(id, NULL);
        if(kctx != NULL)
        {
            if(EVP_PKEY_keygen_init(kctx) > 0)
            {
                if(EVP_PKEY_fromdata_init(kctx) > 0)
                {
                    OSSL_PARAM params[6] = {OSSL_PARAM_RAW(OSSL_PKEY_PARAM_FFC_Q, &ydsa->q),
                                            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_FFC_P, &ydsa->p),
                                            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_FFC_G, &ydsa->g),
                                            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_PUB_KEY, &ydsa->pub_key),
                                            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_PRIV_KEY, &ydsa->priv_key),
                                            OSSL_PARAM_END};

                    if(!has_private)
                    {
                        params[4] = params[5];
                    }

                    if(EVP_PKEY_fromdata(kctx, &evp_key, EVP_PKEY_KEYPAIR, params) > 0)
                    {
                        // yay
                        key->key.evp_key = evp_key;
                        loaded = true;
                    }
                }
            }

            EVP_PKEY_CTX_free(kctx);
        }
    }
    else
    {
        /*
        OSSL_PARAM params[6] =
        {
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_FFC_Q, &ydsa->q),
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_FFC_P, &ydsa->p),
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_FFC_G, &ydsa->g),
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_PUB_KEY, &ydsa->pub_key),
            OSSL_PARAM_RAW(OSSL_PKEY_PARAM_PRIV_KEY, &ydsa->priv_key),
            OSSL_PARAM_END
        };
        */
    }

    if(loaded)
    {
        // at this point, ydsa has been emptied
        uint32_t rdata_size = dnskey_dsa_public_size(key->key.evp_key);

        uint16_t tag;

        uint8_t  rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];

        if(rdata_size <= DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
        {
            SET_U16_AT(rdata[0], key->flags);
            rdata[2] = DNSKEY_PROTOCOL_FIELD;
            rdata[3] = key->algorithm;

            if(dnskey_dsa_public_store(key->key.evp_key, &rdata[4], sizeof(rdata) - 4) == rdata_size)
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

static void dnskey_dsa_parse_finalize(struct dnskey_field_parser *parser)
{
    struct dnskey_dsa_s *ydsa = (struct dnskey_dsa_s *)parser->data;

    if(ydsa != NULL)
    {
        dnskey_dsa_finalize(ydsa);
        ZFREE(ydsa, struct dnskey_dsa_s);
    }
}

static const struct dnskey_field_parser_vtbl rsa_field_parser_vtbl = {dnskey_dsa_parse_field, dnskey_dsa_parse_set_key, dnskey_dsa_parse_finalize, "DSA"};

void                                         dnskey_dsa_parse_init(dnskey_field_parser *fp)
{
    struct dnskey_dsa_s *ydsa;
    ZALLOC_OBJECT_OR_DIE(ydsa, struct dnskey_dsa_s, KEYDSA_TAG);
    ZEROMEMORY(ydsa, sizeof(struct dnskey_dsa_s));
    fp->data = ydsa;
    fp->vtbl = &rsa_field_parser_vtbl;
}

ya_result dnskey_dsa_loadpublic(const uint8_t *rdata, uint16_t rdata_size, const char *origin, dnskey_t **out_key)
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
        case DNSKEY_ALGORITHM_DSASHA1:
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            break;
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    rdata += 4;
    rdata_size -= 4;

    ya_result return_value = DNSSEC_ERROR_CANNOT_READ_KEY_FROM_RDATA;

    EVP_PKEY *evp_key = dnskey_dsa_public_load(rdata, rdata_size);

    if(evp_key != NULL)
    {
        // EVP_PKEY_print_public_fp(stdout, evp_key, 0, NULL);

        dnskey_t *key;

        if(ISOK(return_value = dnskey_dsa_initinstance(evp_key, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }

        EVP_PKEY_free(evp_key);
    }

    return return_value;
}

ya_result dnskey_dsa_newinstance(uint32_t size, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key)
{
    *out_key = NULL;

    if(size > DNSSEC_MAXIMUM_KEY_SIZE)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_DSASHA1:
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
            break;
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    ya_result return_value = DNSSEC_ERROR_KEY_GENERATION_FAILED;

    EVP_PKEY *evp_key = dnskey_dsa_genkey(size);

    if(evp_key != NULL)
    {
        dnskey_t *key;

        if(ISOK(return_value = dnskey_dsa_initinstance(evp_key, algorithm, flags, origin, &key)))
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

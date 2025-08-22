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

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/dsa.h>
#include <openssl/ssl.h>
#include "dnscore/openssl.h"

#include "dnscore/dnscore.h"

#include "dnscore/sys_types.h"
#include "dnscore/base64.h"

#include "dnscore/logger.h"
#include "dnscore/dnskey.h"
#include "dnscore/dnskey_dsa.h"
#include "dnscore/dnssec_errors.h"
#include "dnscore/zalloc.h"

#define MODULE_MSG_HANDLE g_system_logger

#define KEYDSA_TAG        0x5f41534459454b

#ifndef SSL_API
#error "SSL_API not defined"
#endif

#if SSL_API_LT_110

/*
 * Backward-compatible interface for 0.9.x
 */

#define SSL_FIELD_GET(st_, f_)                                                                                                                                                                                                                 \
    if(f_ != NULL)                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                          \
        *f_ = st_->f_;                                                                                                                                                                                                                         \
    }
#define SSL_FIELD_SET(st_, f_)                                                                                                                                                                                                                 \
    if(f_ != NULL)                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                          \
        BN_clear_free(st_->f_);                                                                                                                                                                                                                \
        st_->f_ = f_;                                                                                                                                                                                                                          \
    }
#define SSL_FIELD_SET_FAIL(st_, f_) (st_->f_ == NULL && f_ == NULL)

static void DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    SSL_FIELD_GET(d, p)
    SSL_FIELD_GET(d, q)
    SSL_FIELD_GET(d, g)
}

static int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    if(SSL_FIELD_SET_FAIL(d, p) || SSL_FIELD_SET_FAIL(d, q) || SSL_FIELD_SET_FAIL(d, g))
    {
        return 0;
    }
    SSL_FIELD_SET(d, p)
    SSL_FIELD_SET(d, q)
    SSL_FIELD_SET(d, g)
    return 1;
}

const BIGNUM *DSA_get0_p(const DSA *d) { return d->p; }

void          DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    SSL_FIELD_GET(d, pub_key)
    SSL_FIELD_GET(d, priv_key)
}

int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)
{
    if(SSL_FIELD_SET_FAIL(d, pub_key))
    {
        return 0;
    }
    SSL_FIELD_SET(d, pub_key)
    SSL_FIELD_SET(d, priv_key)
    return 1;
}

void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **r, const BIGNUM **s)
{
    SSL_FIELD_GET(sig, r)
    SSL_FIELD_GET(sig, s)
}

int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if(SSL_FIELD_SET_FAIL(sig, r) || SSL_FIELD_SET_FAIL(sig, s))
    {
        return 0;
    }
    SSL_FIELD_SET(sig, r)
    SSL_FIELD_SET(sig, s)
    return 1;
}
#elif SSL_API_LT_111
const BIGNUM *DSA_get0_p(const DSA *d)
{
    const BIGNUM *p;
    const BIGNUM *q;
    const BIGNUM *g;
    DSA_get0_pqg(d, &p, &q, &g);
    return p;
}
#endif

/*
 * Intermediary key
 */

struct dnskey_dsa_s
{
    BIGNUM *p, *q, *g, *pub_key, *priv_key;
};

struct dnskey_dsa_const_s
{
    const BIGNUM *p, *q, *g, *pub_key, *priv_key;
};

static void dnskey_dsa_init(struct dnskey_dsa_s *ydsa) { memset(ydsa, 0, sizeof(struct dnskey_dsa_s)); }

static bool dnskey_dsa_to_dsa(struct dnskey_dsa_s *ydsa, DSA *dsa)
{
    if(DSA_set0_pqg(dsa, ydsa->p, ydsa->q, ydsa->g) != 0)
    {
        ydsa->p = NULL;
        ydsa->q = NULL;
        ydsa->g = NULL;

        if(DSA_set0_key(dsa, ydsa->pub_key, ydsa->priv_key) != 0)
        {
            ydsa->pub_key = NULL;
            ydsa->priv_key = NULL;
            return true;
        }
    }

    return false;
}

static void dnskey_dsa_from_dsa(struct dnskey_dsa_const_s *ydsa, const DSA *dsa)
{
    DSA_get0_pqg(dsa, &ydsa->p, &ydsa->q, &ydsa->g);
    DSA_get0_key(dsa, &ydsa->pub_key, &ydsa->priv_key);
}

static void dnskey_dsa_finalize(struct dnskey_dsa_s *ydsa)
{
    if(ydsa->g != NULL)
    {
        BN_clear_free(ydsa->g);
    }
    if(ydsa->p != NULL)
    {
        BN_clear_free(ydsa->p);
    }
    if(ydsa->q != NULL)
    {
        BN_clear_free(ydsa->q);
    }
    if(ydsa->pub_key != NULL)
    {
        BN_clear_free(ydsa->pub_key);
    }
    if(ydsa->priv_key != NULL)
    {
        BN_clear_free(ydsa->priv_key);
    }
    dnskey_dsa_init(ydsa);
}

static const struct dnskey_field_access DSA_field_access[] = {{"Prime(p)", offsetof(struct dnskey_dsa_s, p), STRUCTDESCRIPTOR_BN},
                                                              {"Subprime(q)", offsetof(struct dnskey_dsa_s, q), STRUCTDESCRIPTOR_BN},
                                                              {"Base(g)", offsetof(struct dnskey_dsa_s, g), STRUCTDESCRIPTOR_BN},
                                                              {"Private_value(x)", offsetof(struct dnskey_dsa_s, priv_key), STRUCTDESCRIPTOR_BN},
                                                              {"Public_value(y)", offsetof(struct dnskey_dsa_s, pub_key), STRUCTDESCRIPTOR_BN},
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

static DSA *dnskey_dsa_genkey(uint32_t size)
{
    yassert(size >= DNSSEC_MINIMUM_KEY_SIZE && size <= DNSSEC_MAXIMUM_KEY_SIZE);

    int  err;
    DSA *dsa;

#if SSL_API_LT_110
    dsa = DSA_generate_parameters(size, NULL, 0, NULL, NULL, NULL, NULL);
#else
    dsa = DSA_new();
    DSA_generate_parameters_ex(dsa, size, NULL, 0, NULL, NULL, NULL);
#endif

    yassert(dsa != NULL);

    err = DSA_generate_key(dsa); /* no callback */

    if(err == 0)
    {
        // error

        DSA_free(dsa);
        dsa = NULL;
    }

    return dsa;
}

static ya_result dnskey_dsa_signdigest(const dnskey_t *key, const uint8_t *digest, uint32_t digest_len, uint8_t *output_)
{
    uint8_t *output = output_;
    DSA_SIG *sig = DSA_do_sign(digest, digest_len, key->key.dsa);

    if(sig != NULL)
    {
        const BIGNUM *sig_r;
        const BIGNUM *sig_s;

        const BIGNUM *p;
        p = DSA_get0_p(key->key.dsa);
        DSA_SIG_get0(sig, &sig_r, &sig_s);
        uint32_t p_size_bytes = BN_num_bytes(p);
        uint32_t t = (p_size_bytes - 64) >> 3;

        *output++ = t;
        const int bn_size = 20;

        int       r_size = BN_num_bytes(sig_r);
        int       r_pad = bn_size - r_size;
        memset(output, 0, r_pad);
        BN_bn2bin(sig_r, &output[r_pad]);
        output += bn_size;

        int s_size = BN_num_bytes(sig_s);
        int s_pad = bn_size - s_size;
        memset(output, 0, s_pad);
        BN_bn2bin(sig_s, &output[s_pad]);
        // output += bn_size;

        DSA_SIG_free(sig);

        // ya_result output_size = (rn << 1) + 1;
        ya_result output_size = 20 * 2 + 1;

#if DEBUG
        if(!key->vtbl->dnskey_verify_digest(key, digest, digest_len, output_, output_size))
        {
            log_err("CANNOT VERIFY OWN SIGNATURE!");
        }
#endif

        return output_size;
    }
    else
    {
        unsigned long ssl_err;

        while((ssl_err = ERR_get_error()) != 0)
        {
            char buffer[256];
            ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
            log_err("dsa: sign: %{dnsname}/%05d: error %08x %s", key->owner_name, key->tag, ssl_err, buffer);
        }

        ERR_clear_error();

        return DNSSEC_ERROR_DSASIGNATUREFAILED;
    }
}

static bool dnskey_dsa_verifydigest(const dnskey_t *key, const uint8_t *digest, uint32_t digest_len, const uint8_t *signature, uint32_t signature_len)
{
    yassert(signature_len <= DNSSEC_MAXIMUM_KEY_SIZE_BYTES);

#if DEBUG
    log_debug6("dsa_verifydigest(K%{dnsname}-%03d-%05d, @%p, @%p)", key->owner_name, key->algorithm, key->tag, digest, signature);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, digest, digest_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, signature, signature_len, 32);
#endif

    if(signature_len != 41)
    {
        log_warn("DSA signature expected to be 41 bytes long");
    }

    if((signature_len & 1) == 0)
    {
        log_err("DSA signature size expected to be an odd number");

        return false;
    }

    uint8_t t = *signature++;

    if(t != 8)
    {
        log_warn("DSA T!=8 (%i)", t);
    }

    signature_len--;
    signature_len >>= 1;

    DSA_SIG *sig = DSA_SIG_new();

    BIGNUM  *sig_r = BN_bin2bn(signature, signature_len, NULL);
    signature += signature_len;
    BIGNUM *sig_s = BN_bin2bn(signature, signature_len, NULL);
    DSA_SIG_set0(sig, sig_r, sig_s);

    int err = DSA_do_verify(digest, digest_len, sig, key->key.dsa);

    DSA_SIG_free(sig);

    if(err != 1)
    {
        unsigned long ssl_err;

        while((ssl_err = ERR_get_error()) != 0)
        {
            char buffer[256];
            ERR_error_string_n(ssl_err, buffer, sizeof(buffer));

            log_debug("dsa: verify: %{dnsname}/%05d: error %08x %s", key->owner_name, key->tag, ssl_err, buffer);
        }

        ERR_clear_error();

        return false;
    }

    return true;
}

static DSA *dnskey_dsa_public_load(const uint8_t *rdata, uint16_t rdata_size)
{
    if(rdata == NULL)
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

    inptr++;

    BIGNUM *dsa_q;
    BIGNUM *dsa_p;
    BIGNUM *dsa_g;
    BIGNUM *dsa_pub_key;

    dsa_q = BN_bin2bn(inptr, 20, NULL);
    if(dsa_q == NULL)
    {
        log_err("dsa_public_load: NULL q");

        return NULL;
    }
    inptr += 20;
    dsa_p = BN_bin2bn(inptr, pgy_len, NULL);
    if(dsa_p == NULL)
    {
        log_err("dsa_public_load: NULL p");
        BN_clear_free(dsa_q);

        return NULL;
    }
    inptr += pgy_len;
    dsa_g = BN_bin2bn(inptr, pgy_len, NULL);
    if(dsa_g == NULL)
    {
        log_err("dsa_public_load: NULL g");
        BN_clear_free(dsa_q);
        BN_clear_free(dsa_p);

        return NULL;
    }
    inptr += pgy_len;
    dsa_pub_key = BN_bin2bn(inptr, pgy_len, NULL);
    if(dsa_pub_key == NULL)
    {
        log_err("dsa_public_load: NULL y");
        BN_clear_free(dsa_q);
        BN_clear_free(dsa_p);
        BN_clear_free(dsa_g);

        return NULL;
    }

    DSA *dsa;
    dsa = DSA_new();

    yassert(dsa != NULL);

    DSA_set0_pqg(dsa, dsa_p, dsa_q, dsa_g);
    DSA_set0_key(dsa, dsa_pub_key, NULL);

    return dsa;
}

static uint32_t dnskey_dsa_public_store(DSA *dsa, uint8_t *output_buffer, uint32_t output_buffer_size)
{
    unsigned char *outptr = output_buffer;

    const BIGNUM  *q = NULL;
    const BIGNUM  *p = NULL;
    const BIGNUM  *g = NULL;
    const BIGNUM  *y = NULL;

    DSA_get0_pqg(dsa, &p, &q, &g);
    DSA_get0_key(dsa, &y, NULL);

    uint32_t q_n = BN_num_bytes(q);

    if(q_n != 20)
    {
        return 0;
    }

    int32_t p_n = BN_num_bytes(p);
    int32_t g_n = BN_num_bytes(g);
    int32_t y_n = BN_num_bytes(y);

    if((abs(p_n - g_n) > 2) || (abs(p_n - y_n) > 2)) /* sometimes, there is one byte difference in storage */
    {
        log_err("dnskey_dsa_public_store: DSA key size discrepancy");
        return 0;
    }

    int32_t t = p_n;
    t -= 64;

    if(t < 0)
    {
        return 0;
    }

    if((t & 7) != 0)
    {
        return 0;
    }

    t >>= 3;

    if(t + q_n + p_n + g_n + y_n > output_buffer_size)
    {
        return 0; // BUFFER_WOULD_OVERFLOW;
    }

    *outptr++ = t;

    BN_bn2bin(q, outptr);
    outptr += q_n;

    BN_bn2bin(p, outptr);
    outptr += p_n;

    BN_bn2bin(g, outptr);
    outptr += g_n;

    BN_bn2bin(y, outptr);
    outptr += y_n;

    return outptr - output_buffer;
}

static uint32_t dnskey_dsa_dnskey_public_store(const dnskey_t *key, uint8_t *rdata, size_t rdata_size)
{
    uint32_t len;

    SET_U16_AT(rdata[0], key->flags);
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = key->algorithm;

    len = dnskey_dsa_public_store(key->key.dsa, &rdata[4], rdata_size - 4) + 4;

    return len;
}

static uint32_t dnskey_dsa_size(const dnskey_t *key)
{
    const BIGNUM *y;

    DSA_get0_key(key->key.dsa, &y, NULL);

    uint32_t y_n = BN_num_bytes(y);

    return y_n << 3;
}

static uint32_t dnskey_dsa_public_size(const DSA *dsa)
{
    const BIGNUM *p;
    const BIGNUM *q;
    const BIGNUM *g;
    const BIGNUM *y;

    DSA_get0_pqg(dsa, &p, &q, &g);
    DSA_get0_key(dsa, &y, NULL);

    uint32_t p_n = BN_num_bytes(p);
    uint32_t q_n = BN_num_bytes(q);
    uint32_t g_n = BN_num_bytes(g);
    uint32_t y_n = BN_num_bytes(y);

    return 1 + p_n + q_n + g_n + y_n;
}

static uint32_t dnskey_dsa_dnskey_rdatasize(const dnskey_t *key) { return dnskey_dsa_public_size(key->key.dsa) + 4; }

static void     dnskey_dsa_free(dnskey_t *key)
{
    DSA *dsa = key->key.dsa;
    DSA_free(dsa);

    key->key.dsa = NULL;
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
            const DSA    *a_dsa = key_a->key.dsa;
            const DSA    *b_dsa = key_b->key.dsa;

            const BIGNUM *a_dsa_q;
            const BIGNUM *a_dsa_p;
            const BIGNUM *a_dsa_g;
            const BIGNUM *b_dsa_q;
            const BIGNUM *b_dsa_p;
            const BIGNUM *b_dsa_g;

            DSA_get0_pqg(a_dsa, &a_dsa_p, &a_dsa_q, &a_dsa_g);
            DSA_get0_pqg(b_dsa, &b_dsa_p, &b_dsa_q, &b_dsa_g);

            if(BN_cmp(a_dsa_q, b_dsa_q) == 0)
            {
                if(BN_cmp(a_dsa_p, b_dsa_p) == 0)
                {
                    if(BN_cmp(a_dsa_g, b_dsa_g) == 0)
                    {
                        const BIGNUM *a_dsa_pub_key;
                        const BIGNUM *a_dsa_priv_key;
                        const BIGNUM *b_dsa_pub_key;
                        const BIGNUM *b_dsa_priv_key;

                        DSA_get0_key(a_dsa, &a_dsa_pub_key, &a_dsa_priv_key);
                        DSA_get0_key(b_dsa, &b_dsa_pub_key, &b_dsa_priv_key);

                        if(BN_cmp(a_dsa_pub_key, b_dsa_pub_key) == 0)
                        {
                            if(a_dsa_priv_key != NULL)
                            {
                                if(b_dsa_priv_key != NULL)
                                {
                                    return BN_cmp(a_dsa_priv_key, b_dsa_priv_key) == 0;
                                }
                            }
                            else
                            {
                                return b_dsa_priv_key == NULL;
                            }
                        }
                    }
                }
            }
        }
    }

    return false;
}

static ya_result dnskey_dsa_private_print_fields(dnskey_t *key, output_stream_t *os)
{
    struct dnskey_dsa_const_s ydsa;
    dnskey_dsa_from_dsa(&ydsa, key->key.dsa);

    ya_result ret = dnskey_field_access_print(DSA_field_access, &ydsa, os);

    return ret;
}

static const dnskey_vtbl dsa_vtbl = {dnskey_dsa_signdigest, dnskey_dsa_verifydigest, dnskey_dsa_dnskey_rdatasize, dnskey_dsa_dnskey_public_store, dnskey_dsa_free, dnskey_dsa_equals, dnskey_dsa_private_print_fields, dnskey_dsa_size, "DSA"};

static ya_result         dnskey_dsa_initinstance(DSA *dsa, uint8_t algorithm, uint16_t flags, const char *origin, dnskey_t **out_key)
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

    uint32_t rdata_size = dnskey_dsa_public_size(dsa);

    if(rdata_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    SET_U16_AT(rdata[0], flags); // NATIVEFLAGS
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = algorithm;

    uint32_t stored_rdata_size = dnskey_dsa_public_store(dsa, &rdata[4], sizeof(rdata) - 4);

    if(stored_rdata_size != rdata_size)
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

    key->key.dsa = dsa;
    key->vtbl = &dsa_vtbl;
    key->tag = tag;
    key->nid = nid;

    const BIGNUM *dsa_priv_key = NULL;
    DSA_get0_key(dsa, NULL, &dsa_priv_key);

    if(dsa_priv_key != NULL)
    {
        key->status |= DNSKEY_KEY_IS_PRIVATE;
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
    struct dnskey_dsa_s *ydsa = (struct dnskey_dsa_s *)parser->data;

    if(key == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    switch(key->algorithm)
    {
        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_DSASHA1:
            break;
        default:
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    if((ydsa->p == NULL) || (ydsa->q == NULL) || (ydsa->g == NULL) || (ydsa->pub_key == NULL))
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }

    int nid;

    if(FAIL(nid = dnskey_dsa_getnid(key->algorithm)))
    {
        return nid;
    }

    bool has_private = ydsa->priv_key != NULL;

    if(key->key.dsa == NULL)
    {
        key->key.dsa = DSA_new();
        key->vtbl = &dsa_vtbl;
    }

    if(dnskey_dsa_to_dsa(ydsa, key->key.dsa))
    {
        // at this point, ydsa has been emptied

        DSA     *dsa = key->key.dsa;

        uint32_t rdata_size = dnskey_dsa_public_size(dsa);

        uint16_t tag;

        uint8_t  rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];

        if(rdata_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
        {
            return DNSSEC_ERROR_KEYISTOOBIG;
        }

        SET_U16_AT(rdata[0], key->flags);
        rdata[2] = DNSKEY_PROTOCOL_FIELD;
        rdata[3] = key->algorithm;

        if(dnskey_dsa_public_store(dsa, &rdata[4], sizeof(rdata) - 4) != rdata_size)
        {
            return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
        }

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

        return SUCCESS;
    }
    else
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }
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

static const struct dnskey_field_parser_vtbl dsa_field_parser_vtbl = {dnskey_dsa_parse_field, dnskey_dsa_parse_set_key, dnskey_dsa_parse_finalize, "DSA"};

void                                         dnskey_dsa_parse_init(dnskey_field_parser *fp)
{
    struct dnskey_dsa_s *ydsa;
    ZALLOC_OBJECT_OR_DIE(ydsa, struct dnskey_dsa_s, KEYDSA_TAG);
    ZEROMEMORY(ydsa, sizeof(struct dnskey_dsa_s));
    fp->data = ydsa;
    fp->vtbl = &dsa_field_parser_vtbl;
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

    if((algorithm != DNSKEY_ALGORITHM_DSASHA1_NSEC3) && (algorithm != DNSKEY_ALGORITHM_DSASHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    rdata += 4;
    rdata_size -= 4;

    ya_result return_value = DNSSEC_ERROR_CANNOT_READ_KEY_FROM_RDATA;

    DSA      *dsa = dnskey_dsa_public_load(rdata, rdata_size);

    if(dsa != NULL)
    {
        dnskey_t *key;

        if(ISOK(return_value = dnskey_dsa_initinstance(dsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }

        DSA_free(dsa);
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

    if((algorithm != DNSKEY_ALGORITHM_DSASHA1_NSEC3) && (algorithm != DNSKEY_ALGORITHM_DSASHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    ya_result return_value = DNSSEC_ERROR_KEY_GENERATION_FAILED;

    DSA      *dsa = dnskey_dsa_genkey(size);

    if(dsa != NULL)
    {
        dnskey_t *key;

        if(ISOK(return_value = dnskey_dsa_initinstance(dsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }

        DSA_free(dsa);
    }

    return return_value;
}

/** @} */

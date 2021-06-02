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

/** @defgroup dnskey DNSSEC keys functions
 *  @ingroup dnsdbdnssec
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include "dnscore/openssl.h"

#include "dnscore/sys_types.h"
#include "dnscore/base64.h"

#include "dnscore/logger.h"
#include "dnscore/dnskey_rsa.h"
#include "dnscore/dnssec_errors.h"
#include "dnscore/parser.h"

#include "dnscore/zalloc.h"

#define MODULE_MSG_HANDLE g_system_logger

#define KEYRSA_TAG 0x41535259454b

#ifndef SSL_API
#error "SSL_API not defined"
#endif

#if SSL_API_LT_110

#define SSL_FIELD_GET(st_,f_) if(f_ != NULL) { *f_ = st_->f_; }
#define SSL_FIELD_SET(st_,f_) if(f_ != NULL) { BN_free(st_->f_); st_->f_ = f_; }
#define SSL_FIELD_SET_FAIL(st_,f_) (st_->f_ == NULL && f_ == NULL)

static void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    SSL_FIELD_GET(r,n)
    SSL_FIELD_GET(r,e)
    SSL_FIELD_GET(r,d)
}

static int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    if(SSL_FIELD_SET_FAIL(r,n) || SSL_FIELD_SET_FAIL(r,e))
    {
        return 0;
    }
    SSL_FIELD_SET(r,n)
    SSL_FIELD_SET(r,e)
    SSL_FIELD_SET(r,d)
    return 1;
}

static void RSA_get0_factors(const RSA *r,
                  const BIGNUM **p, const BIGNUM **q)
{
    SSL_FIELD_GET(r,p)
    SSL_FIELD_GET(r,q)
}

static int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
    if(SSL_FIELD_SET_FAIL(r,p) || SSL_FIELD_SET_FAIL(r,q))
    {
        return 0;
    }
    SSL_FIELD_SET(r,p)
    SSL_FIELD_SET(r,q)
    return 1;
}

static void RSA_get0_crt_params(const RSA *r,
                  const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp)
{
    SSL_FIELD_GET(r,dmp1)
    SSL_FIELD_GET(r,dmq1)
    SSL_FIELD_GET(r,iqmp)
}

static int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    if(SSL_FIELD_SET_FAIL(r,dmp1) || SSL_FIELD_SET_FAIL(r,dmq1) || SSL_FIELD_SET_FAIL(r,iqmp))
    {
        return 0;
    }
    SSL_FIELD_SET(r,dmp1)
    SSL_FIELD_SET(r,dmq1)
    SSL_FIELD_SET(r,iqmp)
    return 1;
}


#endif

struct dnskey_rsa
{
    BIGNUM *n,*e,*d,*p,*q,*dmp1,*dmq1,*iqmp;
};

struct dnskey_rsa_const
{
    const BIGNUM *n,*e,*d,*p,*q,*dmp1,*dmq1,*iqmp;
};

static void dnskey_rsa_init(struct dnskey_rsa *yrsa)
{
    memset(yrsa, 0, sizeof(struct dnskey_rsa));
}
    
static bool dnskey_rsa_to_rsa(struct dnskey_rsa *yrsa, RSA *rsa)
{
    if(RSA_set0_key(rsa, yrsa->n, yrsa->e, yrsa->d) != 0)
    {
        yrsa->n = NULL;
        yrsa->e = NULL;
        yrsa->d = NULL;
        
        if(RSA_set0_factors(rsa, yrsa->p, yrsa->q) != 0)
        {
            yrsa->p = NULL;
            yrsa->q = NULL;
            
            if(RSA_set0_crt_params(rsa, yrsa->dmp1, yrsa->dmq1, yrsa->iqmp) != 0)
            {
                yrsa->dmp1 = NULL;
                yrsa->dmq1 = NULL;
                yrsa->iqmp = NULL;
                
                return TRUE;
            }
        }
    }
    
    return FALSE;
}

static void dnskey_rsa_from_rsa(struct dnskey_rsa_const *yrsa, const RSA *rsa)
{
    RSA_get0_key(rsa, &yrsa->n, &yrsa->e, &yrsa->d);
    RSA_get0_factors(rsa, &yrsa->p, &yrsa->q);
    RSA_get0_crt_params(rsa, &yrsa->dmp1, &yrsa->dmq1, &yrsa->iqmp);
}

static void dnskey_rsa_finalize(struct dnskey_rsa *yrsa)
{
    if(yrsa->n != NULL) BN_free(yrsa->n);
    if(yrsa->e != NULL) BN_free(yrsa->e);
    if(yrsa->d != NULL) BN_free(yrsa->d);
    if(yrsa->p != NULL) BN_free(yrsa->p);
    if(yrsa->q != NULL) BN_free(yrsa->q);
    if(yrsa->dmp1 != NULL) BN_free(yrsa->dmp1);
    if(yrsa->dmq1 != NULL) BN_free(yrsa->dmq1);
    if(yrsa->iqmp != NULL) BN_free(yrsa->iqmp);
    dnskey_rsa_init(yrsa);
}

static const struct dnskey_field_access RSA_field_access[] ={
    {"Modulus", offsetof(struct dnskey_rsa,n), STRUCTDESCRIPTOR_BN},
    {"PublicExponent", offsetof(struct dnskey_rsa,e), STRUCTDESCRIPTOR_BN},
    {"PrivateExponent", offsetof(struct dnskey_rsa,d), STRUCTDESCRIPTOR_BN},
    {"Prime1", offsetof(struct dnskey_rsa,p), STRUCTDESCRIPTOR_BN},
    {"Prime2", offsetof(struct dnskey_rsa,q), STRUCTDESCRIPTOR_BN},
    {"Exponent1", offsetof(struct dnskey_rsa,dmp1), STRUCTDESCRIPTOR_BN},
    {"Exponent2", offsetof(struct dnskey_rsa,dmq1), STRUCTDESCRIPTOR_BN},
    {"Coefficient", offsetof(struct dnskey_rsa,iqmp), STRUCTDESCRIPTOR_BN},
    {"", 0, 0}
};

static int
dnskey_rsa_getnid(u8 algorithm)
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

static RSA*
dnskey_rsa_genkey(u32 size)
{
    yassert(size >= DNSSEC_MINIMUM_KEY_SIZE && size <= DNSSEC_MAXIMUM_KEY_SIZE);

    int err;
    BN_CTX *ctx;
    BIGNUM *e;
    RSA* rsa;

    ctx = BN_CTX_new();

    yassert(ctx != NULL);

    e = BN_new();
    BN_set_word(e, 0x10001);    // exponent, 65537

    yassert(e != NULL);

    rsa = RSA_new();

    yassert(rsa != NULL);

    err = RSA_generate_key_ex(rsa, size, e, NULL); /* no callback */
    
    if(err == 0)
    {

        RSA_free(rsa);
        rsa = NULL;
    }
    
    BN_free(e);
    BN_CTX_free(ctx);

    return rsa;
}

static ya_result
dnskey_rsa_signdigest(const dnssec_key *key, const u8 *digest, u32 digest_len, u8 *output)
{
    u32 output_size = MAX_U32;

    int err = RSA_sign(key->nid, digest, digest_len, output, &output_size, key->key.rsa);

#if DEBUG
    if(err == 0)
    {
        ERR_print_errors_fp(stderr);

        return DNSSEC_ERROR_RSASIGNATUREFAILED;
    }
#endif

    return (err != 0) ? (s32)output_size : DNSSEC_ERROR_RSASIGNATUREFAILED; // condition is only "always true" if DEBUG is on
}

static bool
dnskey_rsa_verifydigest(const dnssec_key *key, const u8 *digest, u32 digest_len, const u8 *signature, u32 signature_len)
{
    yassert(signature_len <= DNSSEC_MAXIMUM_KEY_SIZE_BYTES);
    
#if DEBUG
    log_debug6("rsa_verifydigest(K%{dnsname}-%03d-%05d, @%p, @%p)", key->owner_name, key->algorithm, key->tag, digest, signature);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, digest, digest_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, signature, signature_len, 32);
#endif
    
#if SSL_API_LT_100
    int err = RSA_verify(key->nid, digest, digest_len, (unsigned char*)signature, signature_len, key->key.rsa);
#else
    int err = RSA_verify(key->nid, digest, digest_len, signature, signature_len, key->key.rsa);
#endif

    if(err != 1)
    {
        unsigned long ssl_err;

        while((ssl_err = ERR_get_error()) != 0)
        {
#if DEBUG
            char buffer[256];
            ERR_error_string_n(ssl_err, buffer, sizeof(buffer));

            log_debug("digest verification returned an ssl error %08x %s", ssl_err, buffer);
#endif
        }

        ERR_clear_error();

        return FALSE;
    }

    return TRUE;
}

static RSA*
dnskey_rsa_public_load(const u8* rdata, u16 rdata_size)
{
    // rdata_size < 4 is harsher than needed but anyway such a small key would
    // and this avoid another test later be worthless
    
    if(rdata == NULL || rdata_size < 4)
    {
        return NULL;
    }
    
    const u8 *inptr = rdata;
    u32 n;
    n = *inptr++;
    rdata_size--;       // rdata_size is at least 1, so it is OK
    if(n == 0)
    {
        n = *inptr++;
        n <<= 8;
        n |= *inptr++;
        rdata_size-=2;
    }
    
    if(rdata_size < n + 1)
    {
        return NULL;
    }

    BIGNUM* exponent;
    BIGNUM* modulus;

    exponent = BN_bin2bn(inptr, n, NULL);
    
    if(exponent == NULL)
    {
        log_err("rsa_public_load: NULL exponent");
        
        return NULL;
    }
    
    inptr += n;
    n = rdata_size - n;
    
    modulus = BN_bin2bn(inptr, n, NULL);
    
    if(modulus == NULL)
    {
        log_err("rsa_public_load: NULL modulus");
        
        BN_free(exponent);
        
        return NULL;
    }

    BN_CTX *ctx;
    RSA* rsa;

    ctx = BN_CTX_new();

    yassert(ctx != NULL);

    rsa = RSA_new();

    yassert(rsa != NULL);

    RSA_set0_key(rsa, modulus, exponent, NULL);

    BN_CTX_free(ctx);

    return rsa;
 }

static u32
dnskey_rsa_public_store(RSA* rsa, u8* output_buffer, u32 output_buffer_size)
{
    unsigned char* outptr = output_buffer;

    u32 n;
    u32 m;

    const BIGNUM* exponent;
    const BIGNUM* modulus;
    RSA_get0_key(rsa, &modulus, &exponent, NULL);

    n = BN_num_bytes(exponent);
    m = BN_num_bytes(modulus);

    if(n > 1 && n < 256)
    {
        if(1 + n + m > output_buffer_size)
        {
            return 0;
        }

        *outptr++ = n;
    }
    else
    {
        if(3 + n + m > output_buffer_size)
        {
            return 0;
        }

        *outptr++ = 0;
        *outptr++ = n >> 8;
        *outptr++ = n;
    }

    n = BN_bn2bin(exponent, outptr);
    outptr += n;

    n = BN_bn2bin(modulus, outptr);
    outptr += n;

    return outptr - output_buffer;
}

static u32
dnskey_rsa_dnskey_public_store(const dnssec_key *key, u8 *rdata, size_t rdata_size)
{
    u32 len;
    
    SET_U16_AT(rdata[0], key->flags);
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = key->algorithm;
    
    len = dnskey_rsa_public_store(key->key.rsa, &rdata[4], rdata_size - 4) + 4;
    
    return len;
}

static u32
dnskey_rsa_size(const dnssec_key* key)
{
    const BIGNUM* rsa_n;
    RSA_get0_key(key->key.rsa, &rsa_n, NULL, NULL);
    
    u32 m_size = BN_num_bytes(rsa_n);

    return m_size << 3;
}

static u32
dnskey_rsa_public_size(const RSA* rsa)
{
    const BIGNUM* rsa_e;
    const BIGNUM* rsa_n;
    RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL);
    
    u32 e_size = BN_num_bytes(rsa_e);
    u32 m_size = BN_num_bytes(rsa_n);

    return m_size + e_size + ((e_size < 256) ? 1 : 3);
}

static u32
dnskey_rsa_dnskey_rdatasize(const dnssec_key* key)
{
    u32 size = dnskey_rsa_public_size(key->key.rsa) + 4;
    return size;
}

static void
dnskey_rsa_free(dnssec_key* key)
{
    RSA* rsa = key->key.rsa;
    RSA_free(rsa);

    key->key.rsa = NULL;
}

static bool
dnskey_rsa_equals(const dnssec_key* key_a, const dnssec_key* key_b)
{
    /* RSA, compare modulus and exponent, exponent first (it's the smallest) */

    if(key_a == key_b)
    {
        return TRUE;
    }
    
    if(dnssec_key_tag_field_set(key_a) && dnssec_key_tag_field_set(key_b))
    {
       if(key_a->tag != key_b->tag)
       {
           return FALSE;
       }
    }
    
    if((key_a->flags == key_b->flags) && (key_a->algorithm == key_b->algorithm))
    {
        if(strcmp(key_a->origin, key_b->origin) == 0)
        {
            RSA* a_rsa = key_a->key.rsa;
            RSA* b_rsa = key_b->key.rsa;
            
            const BIGNUM* a_rsa_e;
            const BIGNUM* a_rsa_n;
            const BIGNUM* b_rsa_e;
            const BIGNUM* b_rsa_n;
            RSA_get0_key(a_rsa, &a_rsa_n, &a_rsa_e, NULL);            
            RSA_get0_key(b_rsa, &b_rsa_n, &b_rsa_e, NULL);

            if(BN_cmp(a_rsa_e, b_rsa_e) == 0)
            {
                if(BN_cmp(a_rsa_n, b_rsa_n) == 0)
                {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

ya_result
dnskey_rsa_private_print_fields(dnssec_key *key, output_stream *os)
{
    struct dnskey_rsa_const yrsa;
    dnskey_rsa_from_rsa(&yrsa, key->key.rsa);
    
    ya_result ret = dnskey_field_access_print(RSA_field_access, &yrsa, os);
        
    return ret;
}

static const dnssec_key_vtbl rsa_vtbl =
{
    dnskey_rsa_signdigest,
    dnskey_rsa_verifydigest,
    dnskey_rsa_dnskey_rdatasize,
    dnskey_rsa_dnskey_public_store,
    dnskey_rsa_free,
    dnskey_rsa_equals,
    dnskey_rsa_private_print_fields,
    dnskey_rsa_size,
    "RSA"
};

static ya_result
dnskey_rsa_initinstance(RSA* rsa, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
{
    int nid;
    
    u8 rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES]; /* 4096 bits -> 1KB */
    
    *out_key = NULL;
    
    if(FAIL(nid = dnskey_rsa_getnid(algorithm)))
    {
        return nid;
    }

#if DEBUG
    memset(rdata, 0xff, sizeof(rdata));
#endif

    u32 rdata_size = dnskey_rsa_public_size(rsa);

    if(rdata_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    SET_U16_AT(rdata[0], flags);                // NATIVEFLAGS
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = algorithm;

    if(dnskey_rsa_public_store(rsa, &rdata[4], sizeof(rdata) - 4) != rdata_size)
    {
        return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
    }

    /* Note : + 4 because of the flags,protocol & algorithm bytes
     *        are not taken in account
     */

    u16 tag = dnskey_get_tag_from_rdata(rdata, rdata_size + 4);

    dnssec_key* key = dnskey_newemptyinstance(algorithm, flags, origin); // RC

    if(key == NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    key->key.rsa = rsa;
    key->vtbl = &rsa_vtbl;
    key->tag = tag;
    key->nid = nid;
 
    const BIGNUM *rsa_p;
    const BIGNUM *rsa_q;
    
    RSA_get0_factors(rsa, &rsa_p, &rsa_q);
    if((rsa_q != NULL) && (rsa_p != NULL))
    {
        key->status |= DNSKEY_KEY_IS_PRIVATE;
    }

    *out_key = key;
    
    return SUCCESS;
}

static ya_result
dnskey_rsa_parse_field(struct dnskey_field_parser *parser, parser_s *p)
{
    struct dnskey_rsa *yrsa = (struct dnskey_rsa*)parser->data;
    
    ya_result ret = dnskey_field_access_parse(RSA_field_access, yrsa, p);
            
    return ret;
}

static ya_result
dnskey_rsa_parse_set_key(struct dnskey_field_parser *parser, dnssec_key *key)
{
    if(key == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    //yassert(key->nid == 0);

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
    
    struct dnskey_rsa *yrsa = (struct dnskey_rsa*)parser->data;
    
    if((yrsa->n == NULL) ||
       (yrsa->e == NULL) ||
       (yrsa->d == NULL) ||
       (yrsa->dmp1 == NULL) ||
       (yrsa->dmq1 == NULL) ||
       (yrsa->iqmp == NULL))
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }
    
    if((yrsa->p == NULL) != (yrsa->q == NULL))
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
    
    bool has_private = (yrsa->p != NULL) && (yrsa->q != NULL);
    
    if(key->key.rsa == NULL)
    {
        key->key.rsa = RSA_new();
        key->vtbl = &rsa_vtbl;
    }
    
    if(dnskey_rsa_to_rsa(yrsa, key->key.rsa))
    {
        // at this point, yrsa has been emptied
        
        RSA *rsa = key->key.rsa;

        u32 rdata_size = dnskey_rsa_public_size(rsa);
        
        u16 tag;
        
        u8 rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];
        
        if(rdata_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
        {
            return DNSSEC_ERROR_KEYISTOOBIG;
        }

        SET_U16_AT(rdata[0], key->flags);
        rdata[2] = DNSKEY_PROTOCOL_FIELD;
        rdata[3] = key->algorithm;

        if(dnskey_rsa_public_store(rsa, &rdata[4], sizeof(rdata) - 4) != rdata_size)
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
        
static void
dnskey_rsa_parse_finalize(struct dnskey_field_parser *parser)
{
    struct dnskey_rsa *yrsa = (struct dnskey_rsa*)parser->data;
   
    if(yrsa != NULL)
    {
        dnskey_rsa_finalize(yrsa);
        ZFREE(yrsa, struct dnskey_rsa);
    }
}

static const struct dnskey_field_parser_vtbl rsa_field_parser_vtbl =
{
    dnskey_rsa_parse_field,
    dnskey_rsa_parse_set_key,
    dnskey_rsa_parse_finalize,
    "RSA"
};

void
dnskey_rsa_parse_init(dnskey_field_parser *fp)
{
    struct dnskey_rsa *yrsa;
    ZALLOC_OBJECT_OR_DIE(yrsa, struct dnskey_rsa, KEYRSA_TAG);
    ZEROMEMORY(yrsa, sizeof(struct dnskey_rsa));
    fp->data = yrsa;
    fp->vtbl = &rsa_field_parser_vtbl;
}

ya_result
dnskey_rsa_loadpublic(const u8 *rdata, u16 rdata_size, const char *origin, dnssec_key **out_key)
{
    *out_key = NULL;
            
    if(rdata == NULL || rdata_size <= 6 || origin == NULL)
    {
        /* bad */
        
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    u16 flags = GET_U16_AT(rdata[0]);
    u8 algorithm = rdata[3];
    
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

    RSA *rsa = dnskey_rsa_public_load(rdata, rdata_size);
    
    if(rsa != NULL)
    {
        dnssec_key *key;
        
        if(ISOK(return_value = dnskey_rsa_initinstance(rsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }
        
        RSA_free(rsa);
    }
    
    return return_value;
}

ya_result
dnskey_rsa_newinstance(u32 size, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
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

    RSA *rsa = dnskey_rsa_genkey(size);
    
    if(rsa != NULL)
    {
        dnssec_key *key;
        
        if(ISOK(return_value = dnskey_rsa_initinstance(rsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;
            
            return return_value;
        }
        
        RSA_free(rsa);
    }

    return return_value;
}

/** @} */

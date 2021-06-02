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
 *  NOT DONE
 * 
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnscore/dnscore-config.h"

#if HAS_ECDSA_SUPPORT

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
//#include <openssl/ec_lcl.h>
#include <openssl/ecdsa.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include "dnscore/openssl.h"

#include "dnscore/dnscore-config.h"

#include "dnscore/dnscore.h"
#include "dnscore/sys_types.h"
#include "dnscore/base64.h"

#include "dnscore/logger.h"
#include "dnscore/dnskey.h"
#include "dnscore/dnskey_ecdsa.h"
#include "dnscore/dnssec_errors.h"

#include "dnscore/zalloc.h"

#define MODULE_MSG_HANDLE g_system_logger

#define KEYECDSA_TAG 0x415344434559454b

#ifndef SSL_API
#error "SSL_API not defined"
#endif

#define DNSKEY_ALGORITHM_ECDSAP256SHA256_NID NID_X9_62_prime256v1
#define DNSKEY_ALGORITHM_ECDSAP384SHA384_NID NID_secp384r1

#if SSL_API_LT_110

#define SSL_FIELD_GET(st_,f_) if(f_ != NULL) { *f_ = st_->f_; }
#define SSL_FIELD_SET(st_,f_) if(f_ != NULL) { BN_free(st_->f_); st_->f_ = f_; }
#define SSL_FIELD_SET_FAIL(st_,f_) (st_->f_ == NULL && f_ == NULL)

void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **r, const BIGNUM **s)
{
    SSL_FIELD_GET(sig,r)
    SSL_FIELD_GET(sig,s)
}

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if(SSL_FIELD_SET_FAIL(sig,r) || SSL_FIELD_SET_FAIL(sig,s))
    {
        return 0;
    }
    SSL_FIELD_SET(sig,r)
    SSL_FIELD_SET(sig,s)
    return 1;
}

#endif

/*
 * Intermediary key
 */

struct dnskey_ecdsa
{
    BIGNUM *private_key;
};

struct dnskey_ecdsa_const
{
    const BIGNUM *private_key;
};

static void dnskey_ecdsa_init(struct dnskey_ecdsa *yecdsa)
{
    memset(yecdsa, 0, sizeof(struct dnskey_ecdsa));
}
    
static bool dnskey_ecdsa_to_ecdsa(struct dnskey_ecdsa *yecdsa, EC_KEY *ecdsa)
{
    if(EC_KEY_set_private_key(ecdsa, yecdsa->private_key) != 0)
    {
        yecdsa->private_key = NULL;
    
        return TRUE;
    }
    
    return FALSE;
}

static void dnskey_ecdsa_from_ecdsa(struct dnskey_ecdsa_const *yecdsa, const EC_KEY *ecdsa)
{
    yecdsa->private_key = EC_KEY_get0_private_key(ecdsa);
}

static void dnskey_ecdsa_finalize(struct dnskey_ecdsa *yecdsa)
{
    if(yecdsa->private_key != NULL) BN_free(yecdsa->private_key);
    dnskey_ecdsa_init(yecdsa);
}

static const struct dnskey_field_access ECDSA_field_access[] =
{
    {"PrivateKey", offsetof(struct dnskey_ecdsa,private_key), STRUCTDESCRIPTOR_BN},
    {"", 0, 0}
};

static int
dnskey_ecdsa_getnid(u8 algorithm)
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



static int
dnskey_ecdsa_nid_to_signature_bn_size(int nid)
{
    switch(nid)
    {
        case DNSKEY_ALGORITHM_ECDSAP256SHA256_NID:
        {
            return 32; //64
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



static EC_KEY*
dnskey_ecdsa_genkey_by_nid(int nid)
{
    //yassert(size == 256 || size == 384);

    int err;
    EC_KEY *ecdsa;
    EC_GROUP *group;

    if((group = EC_GROUP_new_by_curve_name(nid)) == NULL)
    {
        return NULL;
    }

    if((ecdsa = EC_KEY_new()) == NULL)
    {
        return NULL;
    }

    EC_KEY_set_group(ecdsa, group);

    err = EC_KEY_generate_key(ecdsa); /* no callback */

    EC_GROUP_clear_free(group);

    if(err == 0)
    {
        // error

        EC_KEY_free(ecdsa);
        ecdsa = NULL;
    }

    return ecdsa;
}

static ya_result
dnskey_ecdsa_signdigest(const dnssec_key *key, const u8 *digest, u32 digest_len, u8 *output_)
{
    u8 *output;


    output = output_;



    ECDSA_SIG *sig = ECDSA_do_sign(digest, digest_len, key->key.ec);

    if(sig != NULL)
    {
        int bn_size = dnskey_ecdsa_nid_to_signature_bn_size(key->nid);
        ZEROMEMORY(output, bn_size * 2);
        
        const BIGNUM *sig_r;
        const BIGNUM *sig_s;
        ECDSA_SIG_get0(sig, &sig_r, &sig_s);

        int r_size = BN_num_bytes(sig_r);
        int r_pad = bn_size - r_size;
        memset(output, 0, r_pad);
        BN_bn2bin(sig_r, &output[r_pad]);
        output += bn_size;

        int s_size = BN_num_bytes(sig_s);
        int s_pad = bn_size - s_size;
        memset(output, 0, s_pad);
        BN_bn2bin(sig_s, &output[s_pad]);
        //output += bn_size;
        
        ECDSA_SIG_free(sig);
        
        ya_result output_size = bn_size * 2; // r_size + s_size;



        return output_size;
    }
    else
    {
        unsigned long ssl_err;

        while((ssl_err = ERR_get_error()) != 0)
        {
            char buffer[256];
            ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
            log_err("digest signature returned an ssl error %08x %s", ssl_err, buffer);
        }

        ERR_clear_error();
        
        return DNSSEC_ERROR_ECDSASIGNATUREFAILED;
    }
}

static bool
dnskey_ecdsa_verifydigest(const dnssec_key *key, const u8 *digest, u32 digest_len, const u8 *signature, u32 signature_len)
{
    yassert(signature_len <= DNSSEC_MAXIMUM_KEY_SIZE_BYTES);
    
#if DEBUG
    log_debug6("ecdsa_verifydigest(K%{dnsname}-%03d-%05d, @%p, @%p)", key->owner_name, key->algorithm, key->tag, digest, signature);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, digest, digest_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, signature, signature_len, 32);
#endif

    /*
     * For P-256, each integer MUST be encoded as 32 octets;
     * for P-384, each integer MUST be encoded as 48 octets.
     */
    
    int bn_size = dnskey_ecdsa_nid_to_signature_bn_size(key->nid);

    if(FAIL(bn_size))
    {
        log_err("EC_KEY getting size for NID returned: %r", bn_size);
        return FALSE;
    }

    if((int)signature_len != bn_size * 2)
    {
        log_err("EC_KEY signature size unexpected");
        return FALSE;
    }
    
    ECDSA_SIG *sig = ECDSA_SIG_new();
    
    BIGNUM *sig_r = BN_bin2bn(signature, bn_size, NULL);
    signature += bn_size;
    BIGNUM *sig_s = BN_bin2bn(signature, bn_size, NULL);
    ECDSA_SIG_set0(sig, sig_r, sig_s);

    int err = ECDSA_do_verify(digest, digest_len, sig, key->key.ec);
    
    if(err != 1)
    {
        unsigned long ssl_err;

        while((ssl_err = ERR_get_error()) != 0)
        {
            char buffer[256];
            ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
            log_debug("digest verification returned an ssl error %08x %s", ssl_err, buffer);
        }

        ECDSA_SIG_free(sig);
        ERR_clear_error();

        return FALSE;
    }
    
    ECDSA_SIG_free(sig);

    return TRUE;
}

static EC_KEY*
dnskey_ecdsa_public_load(u8 algorithm, const u8* rdata, u16 rdata_size)
{
    EC_KEY *ecdsa;
    if((ecdsa = EC_KEY_new_by_curve_name(dnskey_ecdsa_getnid(algorithm))) != NULL)
    {
        const EC_GROUP *group = EC_KEY_get0_group(ecdsa);
        EC_POINT *point = EC_POINT_new(group);
        u8 tmp[512];
    
        tmp[0] = 4;
        memcpy(&tmp[1], rdata, rdata_size);
    
        if(EC_POINT_oct2point(group, point, tmp, rdata_size + 1, NULL) == 1)
        {
            EC_KEY_set_public_key(ecdsa, point);
            EC_POINT_free(point);
            return ecdsa;
        }
        
        EC_POINT_free(point);
        EC_KEY_free(ecdsa);
    }
    
    return NULL;
 }

static u32
ecdsa_public_store(const EC_KEY* ecdsa, u8* output_buffer)
{
    const EC_GROUP *group = EC_KEY_get0_group(ecdsa);
    const EC_POINT *point = EC_KEY_get0_public_key(ecdsa);
    BN_CTX *ctx = BN_CTX_new();
    u8 tmp[512];
    
    size_t size = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, tmp, sizeof(tmp), ctx);
    
    assert((size > 0) && (tmp[0] == 4));
    
    memcpy(output_buffer, &tmp[1], size - 1);
    
    BN_CTX_free(ctx);
    
    return size - 1;
}

static u32
dnskey_ecdsa_dnskey_public_store(const dnssec_key* key, u8* rdata, size_t rdata_size)
{
    (void)rdata_size;
    u32 len;

    SET_U16_AT(rdata[0], key->flags);
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = key->algorithm;

    len = ecdsa_public_store(key->key.ec, &rdata[4]) + 4;
    
    return len;
}

static u32
dnskey_ecdsa_size(const dnssec_key* key)
{
    const EC_GROUP *group = EC_KEY_get0_group(key->key.ec);
    const EC_POINT *point = EC_KEY_get0_public_key(key->key.ec);    
    BN_CTX *ctx = BN_CTX_new();
    u8 tmp[512];
    
    size_t size = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, tmp, sizeof(tmp), ctx);
    
    assert((size > 0) && (tmp[0] == 4));
        
    BN_CTX_free(ctx);
    
    return (size - 1) << 2;
}

/**
 * Returns the size in byte of the public key.
 * 
 * @param ecdsa
 * @return 
 */

static u32
dnskey_ecdsa_public_size(const EC_KEY* ecdsa)
{
    const EC_GROUP *group = EC_KEY_get0_group(ecdsa);
    const EC_POINT *point = EC_KEY_get0_public_key(ecdsa);    
    BN_CTX *ctx = BN_CTX_new();
    u8 tmp[512];
    
    size_t size = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, tmp, sizeof(tmp), ctx);
    
    assert((size > 0) && (tmp[0] == 4));
        
    BN_CTX_free(ctx);
    
    return size - 1;
}

static u32
dnskey_ecdsa_dnskey_rdatasize(const dnssec_key* key)
{
    u32 size = dnskey_ecdsa_public_size(key->key.ec) + 4;
    return size;
}

static void
dnskey_ecdsa_free(dnssec_key* key)
{
    EC_KEY* ecdsa = key->key.ec;
    EC_KEY_free(ecdsa);

    key->key.ec = NULL;
}

static bool
dnskey_ecdsa_equals(const dnssec_key *key_a, const dnssec_key *key_b)
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
            const EC_GROUP *group_a = EC_KEY_get0_group(key_a->key.ec);
            const EC_GROUP *group_b = EC_KEY_get0_group(key_b->key.ec);
            
            BN_CTX *ctx = BN_CTX_new();
            
            if(EC_GROUP_cmp(group_a, group_b, ctx) == 0)
            {            
                const EC_POINT *point_a = EC_KEY_get0_public_key(key_a->key.ec);
                const EC_POINT *point_b = EC_KEY_get0_public_key(key_b->key.ec);

                
                bool ret = EC_POINT_cmp(group_a, point_a, point_b, ctx);
                BN_CTX_free(ctx);
                
                return ret;
            }
            
            BN_CTX_free(ctx);
        }
    }

    return FALSE;
}

static ya_result
dnskey_ecdsa_print_fields(dnssec_key *key, output_stream *os)
{
    struct dnskey_ecdsa_const yecdsa;
    dnskey_ecdsa_from_ecdsa(&yecdsa, key->key.ec);
    
    ya_result ret = dnskey_field_access_print(ECDSA_field_access, &yecdsa, os);
        
    return ret;
}

static const dnssec_key_vtbl ecdsa_vtbl = {
    dnskey_ecdsa_signdigest,
    dnskey_ecdsa_verifydigest,
    dnskey_ecdsa_dnskey_rdatasize,
    dnskey_ecdsa_dnskey_public_store,
    dnskey_ecdsa_free,
    dnskey_ecdsa_equals,
    dnskey_ecdsa_print_fields,
    dnskey_ecdsa_size,
    "ECDSA"
};

static ya_result
dnskey_ecdsa_initinstance(EC_KEY *ecdsa, u8 algorithm, u16 flags, const char *origin, dnssec_key **out_key)
{
    int nid;
    
    u8 rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES]; /* 4096 bits -> 1KB */
    
    *out_key = NULL;
    
    if(FAIL(nid = dnskey_ecdsa_getnid(algorithm)))
    {
        return nid;
    }

#if DEBUG
    memset(rdata, 0xff, sizeof(rdata));
#endif

    u32 public_key_size = dnskey_ecdsa_public_size(ecdsa);

    if(public_key_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    SET_U16_AT(rdata[0], flags); // NATIVEFLAGS
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = algorithm;

    if(ecdsa_public_store(ecdsa, &rdata[4]) != public_key_size)
    {
        return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
    }

    /* Note : + 4 because of the flags,protocol & algorithm bytes
     *        are not taken in account
     */

    u16 tag = dnskey_get_tag_from_rdata(rdata, public_key_size + 4);

    dnssec_key* key = dnskey_newemptyinstance(algorithm, flags, origin); // RC

    if(key == NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    key->key.ec = ecdsa;
    key->vtbl = &ecdsa_vtbl;
    key->tag = tag;
    key->nid = nid;
    key->status |= (EC_KEY_get0_private_key(ecdsa) != NULL)?DNSKEY_KEY_IS_PRIVATE:0;

    *out_key = key;
    
    return SUCCESS;
}

static ya_result
dnskey_ecdsa_parse_field(struct dnskey_field_parser *parser, parser_s *p)
{
    struct dnskey_ecdsa *yecdsa = (struct dnskey_ecdsa*)parser->data;
    
    ya_result ret = dnskey_field_access_parse(ECDSA_field_access, yecdsa, p);
            
    return ret;
}

static ya_result
dnskey_ecdsa_parse_set_key(struct dnskey_field_parser *parser, dnssec_key *key)
{
    struct dnskey_ecdsa *yecdsa = (struct dnskey_ecdsa*)parser->data;
    
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
    
    if(yecdsa->private_key == NULL)
    {
        return DNSSEC_ERROR_INCOMPLETEKEY;
    }
    
    int nid;
    
    if(FAIL(nid = dnskey_ecdsa_getnid(key->algorithm)))
    {
        return nid;
    }

    const EC_GROUP *group = NULL;
    
    if(key->key.ec == NULL)
    {
        EC_KEY *ecdsa = EC_KEY_new_by_curve_name(nid);
        
        if(ecdsa == NULL)
        {
            return DNSSEC_ERROR_INCOMPLETEKEY;
        }
        
        group = EC_KEY_get0_group(ecdsa);
        
        if(group == NULL)
        {
            return DNSSEC_ERROR_INCOMPLETEKEY;
        }
        
        key->key.ec = ecdsa;
        key->vtbl = &ecdsa_vtbl;
    }
    else
    {
        group = EC_KEY_get0_group(key->key.ec);
        
        if(group == NULL)
        {
            return DNSSEC_ERROR_INCOMPLETEKEY;
        }
    }
        
    EC_KEY *ecdsa = key->key.ec;

    const EC_POINT *point;

    if((point = EC_KEY_get0_public_key(ecdsa)) == NULL)
    {
        EC_POINT *gen_point = EC_POINT_new(group);

        if(EC_POINT_mul(group, gen_point, yecdsa->private_key, NULL, NULL, NULL) == 1)
        {
            EC_KEY_set_public_key(ecdsa, gen_point);
            point = gen_point;
        }

        EC_POINT_free(gen_point);
    }

    if(point != NULL)
    {
        if(dnskey_ecdsa_to_ecdsa(yecdsa, ecdsa) != 0)
        {
            // at this point, yecdsa has been emptied
            
            u32 rdata_size = dnskey_ecdsa_public_size(ecdsa);

            u16 tag;

            u8 rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];

            if(rdata_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
            {
                return DNSSEC_ERROR_KEYISTOOBIG;
            }

            SET_U16_AT(rdata[0], key->flags);
            rdata[2] = DNSKEY_PROTOCOL_FIELD;
            rdata[3] = key->algorithm;

            if(ecdsa_public_store(ecdsa, &rdata[4]) != rdata_size)
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
    }

    return DNSSEC_ERROR_INCOMPLETEKEY;
}

static void
dnskey_ecdsa_parse_finalize(struct dnskey_field_parser *parser)
{
    struct dnskey_ecdsa *ydsa = (struct dnskey_ecdsa*)parser->data;
    
    if(ydsa != NULL)
    {
        dnskey_ecdsa_finalize(ydsa);
        ZFREE(ydsa, struct dnskey_ecdsa);
    }
}

static const struct dnskey_field_parser_vtbl ecdsa_field_parser_vtbl =
{
    dnskey_ecdsa_parse_field,
    dnskey_ecdsa_parse_set_key,
    dnskey_ecdsa_parse_finalize,
    "ECDSA"
};

void
dnskey_ecdsa_parse_init(dnskey_field_parser *fp)
{
    struct dnskey_ecdsa *yecdsa;
    ZALLOC_OBJECT_OR_DIE(yecdsa, struct dnskey_ecdsa, KEYECDSA_TAG);
    ZEROMEMORY(yecdsa, sizeof(struct dnskey_ecdsa));
    fp->data = yecdsa;
    fp->vtbl = &ecdsa_field_parser_vtbl;
}

ya_result
dnskey_ecdsa_loadpublic(const u8 *rdata, u16 rdata_size, const char *origin, dnssec_key** out_key)
{
    *out_key = NULL;
            
    if(rdata == NULL || rdata_size <= 6 || origin == NULL)
    {
        /* bad */
        
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    u16 flags = GET_U16_AT(rdata[0]);
    u8 algorithm = rdata[3];

    if((algorithm != DNSKEY_ALGORITHM_ECDSAP256SHA256) && (algorithm != DNSKEY_ALGORITHM_ECDSAP384SHA384) &&
       (algorithm != DNSKEY_ALGORITHM_ED25519) && (algorithm != DNSKEY_ALGORITHM_ED448))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    rdata += 4;
    rdata_size -= 4;
    
    ya_result return_value = DNSSEC_ERROR_CANNOT_READ_KEY_FROM_RDATA;

    EC_KEY *ecdsa = dnskey_ecdsa_public_load(algorithm, rdata, rdata_size);
    
    if(ecdsa != NULL)
    {
        dnssec_key *key;
        
        if(ISOK(return_value = dnskey_ecdsa_initinstance(ecdsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }
        
        EC_KEY_free(ecdsa);
    }
    
    return return_value;
}

ya_result
dnskey_ecdsa_newinstance(u32 size, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
{
    *out_key = NULL;
    
    if(size > DNSSEC_MAXIMUM_KEY_SIZE)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }
    
    if((algorithm != DNSKEY_ALGORITHM_ECDSAP256SHA256) && (algorithm != DNSKEY_ALGORITHM_ECDSAP384SHA384) &&
       (algorithm != DNSKEY_ALGORITHM_ED25519) && (algorithm != DNSKEY_ALGORITHM_ED448))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }
    
    ya_result return_value = DNSSEC_ERROR_KEY_GENERATION_FAILED;

    //EC_KEY *ecdsa = dnskey_ecdsa_genkey(size);
    EC_KEY *ecdsa = dnskey_ecdsa_genkey_by_nid(dnskey_ecdsa_getnid(algorithm));
    
    if(ecdsa != NULL)
    {
        dnssec_key *key;
        
        if(ISOK(return_value = dnskey_ecdsa_initinstance(ecdsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;
            
            return return_value;
        }
        
        EC_KEY_free(ecdsa);
    }

    return return_value;
}
#else

void dnskey_ecdsa_not_supported() {}

#endif // HAS_ECDSA_SUPPORT

/** @} */


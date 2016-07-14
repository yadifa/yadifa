/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2016, EURid. All rights reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

#include "dnscore/dnscore-config.h"

#include "dnscore/dnscore.h"
#include "dnscore/sys_types.h"
#include "dnscore/base64.h"

#include "dnscore/logger.h"
#include "dnscore/dnskey.h"
#include "dnscore/dnskey_ecdsa.h"
#include "dnscore/dnssec_errors.h"

#include "dnscore/dnskey.h"



#define MODULE_MSG_HANDLE g_system_logger

#define DNSKEY_ALGORITHM_ECDSAP256SHA256_NID NID_X9_62_prime256v1
#define DNSKEY_ALGORITHM_ECDSAP384SHA384_NID NID_secp384r1

static const char* ecdsa_private_key_field = "PrivateKey";

static int
ecdsa_getnid(u8 algorithm)
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
ecdsa_getnid_by_size(u32 size)
{
    switch(size)
    {
        case 256:
        {
            return DNSKEY_ALGORITHM_ECDSAP256SHA256_NID;
        }
        case 384:
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
ecdsa_nid_to_signature_bn_size(int nid)
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
ecdsa_genkey(u32 size)
{
    yassert(size == 256 || size == 384);

    int err;
    EC_KEY *ecdsa;
    EC_GROUP *group;
    
    if((group = EC_GROUP_new_by_curve_name(ecdsa_getnid_by_size(size))) == NULL)
    {
        return NULL;
    }

    if((ecdsa = EC_KEY_new()) == NULL)
    {
        return NULL;
    }
    
    EC_KEY_set_group(ecdsa, group);
    
    err = EC_KEY_generate_key(ecdsa); /* no callback */

    if(err == 0)
    {
        // error
        
        EC_KEY_free(ecdsa);
        ecdsa = NULL;
    }
    
    return ecdsa;
}

static ya_result
ecdsa_signdigest(const dnssec_key *key, const u8 *digest, u32 digest_len, u8 *output)
{
    ECDSA_SIG *sig = ECDSA_do_sign(digest, digest_len, key->key.ec);

    if(sig != NULL)
    {
        int bn_size = ecdsa_nid_to_signature_bn_size(key->nid);
        ZEROMEMORY(output, bn_size * 2);
        int r_size = BN_bn2bin(sig->r, output);
        output += r_size;
        //output += bn_size;
        int s_size = BN_bn2bin(sig->s, output);
        
        ECDSA_SIG_free(sig);
        
        return r_size + s_size;
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
ecdsa_verifydigest(const dnssec_key *key, const u8 *digest, u32 digest_len, const u8 *signature, u32 signature_len)
{
    yassert(signature_len <= DNSSEC_MAXIMUM_KEY_SIZE_BYTES);
    
#ifdef DEBUG
    log_debug6("ecdsa_verifydigest(K%{dnsname}-%03d-%05d, @%p, @%p)", key->owner_name, key->algorithm, key->tag, digest, signature);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, digest, digest_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, signature, signature_len, 32);
#endif

    /*
     * For P-256, each integer MUST be encoded as 32 octets;
     * for P-384, each integer MUST be encoded as 48 octets.
     */
    
    int bn_size = ecdsa_nid_to_signature_bn_size(key->nid);
    
    ECDSA_SIG sig;    
    
    if(signature_len != bn_size * 2)
    {
        log_err("EC_KEY signature expected to be 41 bytes long");
        return FALSE;
    }
    
    sig.r = BN_bin2bn(signature, bn_size, NULL);
    signature += bn_size;
    sig.s = BN_bin2bn(signature, bn_size, NULL);

    int err = ECDSA_do_verify(digest, digest_len, &sig, key->key.ec);
    
    BN_free(sig.r);
    BN_free(sig.s);
    
    if(err != 1)
    {
        unsigned long ssl_err;

        while((ssl_err = ERR_get_error()) != 0)
        {
            char buffer[256];
            ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
            log_err("digest verification returned an ssl error %08x %s", ssl_err, buffer);
        }

        ERR_clear_error();

        return FALSE;
    }

    return TRUE;
}

static EC_KEY*
ecdsa_public_load(u8 algorithm, const u8* rdata, u16 rdata_size)
{
    EC_KEY *ecdsa;
    if((ecdsa = EC_KEY_new_by_curve_name(ecdsa_getnid(algorithm))) != NULL)
    {
        const EC_GROUP *group = EC_KEY_get0_group(ecdsa);
        EC_POINT *point = EC_POINT_new(group);
        u8 tmp[512];
    
        tmp[0] = 4;
        memcpy(&tmp[1], rdata, rdata_size);
    
        if(EC_POINT_oct2point(group, point, tmp, rdata_size + 1, NULL) == 1)
        {
            EC_KEY_set_public_key(ecdsa, point);
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
ecdsa_dnskey_public_store(const dnssec_key* key, u8* rdata)
{
    u32 len;

    SET_U16_AT(rdata[0], key->flags);
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = key->algorithm;

    len = ecdsa_public_store(key->key.ec, &rdata[4]) + 4;
    
    return len;
}

/**
 * Returns the size in byte of the public key.
 * @todo 20160209 edf -- This is very inneficient.  Have to find a better way than writing the key.
 * 
 * @param ecdsa
 * @return 
 */

static u32
ecdsa_public_getsize(const EC_KEY* ecdsa)
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
ecdsa_dnskey_public_getsize(const dnssec_key* key)
{
    u32 size = ecdsa_public_getsize(key->key.ec) + 4;
    return size;
}

static void
ecdsa_free(dnssec_key* key)
{
    EC_KEY* ecdsa = key->key.ec;
    EC_KEY_free(ecdsa);

    key->key.ec = NULL;
}

static bool
ecdsa_equals(const dnssec_key *key_a, const dnssec_key *key_b)
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

const struct structdescriptor *
ecdsa_get_fields_descriptor(dnssec_key* key)
{
    return NULL;
}

ya_result
ecdsa_private_print_fields(dnssec_key *key, output_stream *os)
{
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
            break;
    }
    
    ya_result ret;
    
    EC_KEY* ecdsa = key->key.ec;
   
    osformat(os, "PrivateKey: ");
    
    const BIGNUM *private_key = EC_KEY_get0_private_key(ecdsa);
    
    ret = dnskey_write_bignum_as_base64_to_stream(private_key, os);
    
    osprintln(os, "");
    
    return ret;
}

static const dnssec_key_vtbl ecdsa_vtbl = {
    ecdsa_signdigest,
    ecdsa_verifydigest,
    ecdsa_dnskey_public_getsize,
    ecdsa_dnskey_public_store,
    ecdsa_free,
    ecdsa_equals,
    ecdsa_private_print_fields,
    "ECDSA"
};

static ya_result
ecdsa_initinstance(EC_KEY *ecdsa, u8 algorithm, u16 flags, const char *origin, dnssec_key **out_key)
{
    int nid;
    
    u8 rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES]; /* 4096 bits -> 1KB */
    
    *out_key = NULL;
    
    if(FAIL(nid = ecdsa_getnid(algorithm)))
    {
        return nid;
    }

#ifdef DEBUG
    memset(rdata, 0xff, sizeof(rdata));
#endif

    u32 public_key_size = ecdsa_public_getsize(ecdsa);

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

    u16 tag = dnskey_get_key_tag_from_rdata(rdata, public_key_size + 4);

    dnssec_key* key = dnskey_newemptyinstance(algorithm, flags, origin); // RC

    key->key.ec = ecdsa;
    key->vtbl = &ecdsa_vtbl;
    key->tag = tag;
    key->nid = nid;
    key->status |= (EC_KEY_get0_private_key(ecdsa) != NULL)?DNSKEY_KEY_IS_PRIVATE:0;

    *out_key = key;
    
    return SUCCESS;
}

ya_result
ecdsa_private_parse_field(dnssec_key *key, parser_s *p)
{
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
            break;
    }
    
    ya_result ret = ERROR;
    
    u32 label_len = parser_text_length(p);
    const char *label = parser_text(p);
    u8 tmp_out[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];
    
    if((label_len == 10) && memcmp(label, ecdsa_private_key_field, 10) == 0)
    {
        if(ISOK(ret = parser_next_word(p)))
        {
            u32 word_len = parser_text_length(p);
            const char *word = parser_text(p);

            ya_result n = base64_decode(word, word_len, tmp_out);

            if(ISOK(n))
            {
                BIGNUM *private_key = BN_bin2bn(tmp_out, n, NULL);

                if(private_key != NULL)
                {
                    EC_KEY *ecdsa = key->key.ec;
                    
                    if(ecdsa == NULL)
                    {
                        ecdsa = EC_KEY_new_by_curve_name(ecdsa_getnid(key->algorithm));
                        
                        yassert(ecdsa != NULL);
                    }

                    const EC_GROUP *group = EC_KEY_get0_group(ecdsa);

                    if(group != NULL)
                    {
                        const EC_POINT *point;
                        
                        if((point = EC_KEY_get0_public_key(ecdsa)) == NULL)
                        {
                            EC_POINT *gen_point = EC_POINT_new(group);

                            if(EC_POINT_mul(group, gen_point, private_key, NULL, NULL, NULL) == 1)
                            {
                                EC_KEY_set_public_key(ecdsa, gen_point);
                                point = gen_point;
                            }
                        }
                        
                        if(point != NULL)
                        {
                            EC_KEY_set_private_key(ecdsa, private_key);

                            u32 rdata_size = ecdsa_public_getsize(ecdsa);
                            u8 *rdata = tmp_out;
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

                            u16 tag = dnskey_get_key_tag_from_rdata(rdata, rdata_size + 4);
                            
                            if(key->key.ec == NULL)
                            {
                                key->key.ec = ecdsa;
                                key->vtbl = &ecdsa_vtbl;
                            }

                            key->tag = tag;
                            key->nid = ecdsa_getnid(key->algorithm);

                            key->status |= DNSKEY_KEY_IS_VALID | DNSKEY_KEY_IS_PRIVATE;

                            return SUCCESS;
                        }
                    }
                    
                    if(key->key.ec == NULL)
                    {
                        EC_KEY_free(ecdsa);
                    }
                }
                else
                {
                    log_err("unable to get big number from field %s", ecdsa_private_key_field);
                    ret = DNSSEC_ERROR_BNISNULL;
                }
                
                BN_free(private_key);
            }
            else
            {
                log_err("unable to decode field %s", ecdsa_private_key_field);
                ret = n;
            }
        }
    }
        
    return ret;
}

ya_result
ecdsa_loadpublic(const u8 *rdata, u16 rdata_size, const char *origin, dnssec_key** out_key)
{
    *out_key = NULL;
            
    if(rdata == NULL || rdata_size <= 6 || origin == NULL)
    {
        /* bad */
        
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    u16 flags = GET_U16_AT(rdata[0]);
    u8 algorithm = rdata[3];
    
    if((algorithm != DNSKEY_ALGORITHM_ECDSAP256SHA256) && (algorithm != DNSKEY_ALGORITHM_ECDSAP384SHA384))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    rdata += 4;
    rdata_size -= 4;
    
    ya_result return_value = ERROR;

    EC_KEY *ecdsa = ecdsa_public_load(algorithm, rdata, rdata_size);
    
    if(ecdsa != NULL)
    {
        dnssec_key *key;
        
        if(ISOK(return_value = ecdsa_initinstance(ecdsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }
        
        EC_KEY_free(ecdsa);
    }
    
    return return_value;
}

ya_result
ecdsa_newinstance(u32 size, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
{
    *out_key = NULL;
    
    if(size > DNSSEC_MAXIMUM_KEY_SIZE)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }
    
    if((algorithm != DNSKEY_ALGORITHM_ECDSAP256SHA256) && (algorithm != DNSKEY_ALGORITHM_ECDSAP384SHA384))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }
    
    ya_result return_value = ERROR;

    EC_KEY *ecdsa = ecdsa_genkey(size);
    
    if(ecdsa != NULL)
    {
        dnssec_key *key;
        
        if(ISOK(return_value = ecdsa_initinstance(ecdsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;
            
            return return_value;
        }
        
        EC_KEY_free(ecdsa);
    }

    return return_value;
}

/*    ------------------------------------------------------------    */

/** @} */


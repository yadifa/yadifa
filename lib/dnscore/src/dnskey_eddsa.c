/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2023, EURid vzw. All rights reserved.
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
#include "dnscore/dnscore-config-features.h"

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

#include "dnscore/dnscore-config.h"

#include "dnscore/dnscore.h"
#include "dnscore/sys_types.h"
// EVP_PKEY_new_raw_public_key
#include "dnscore/logger.h"
#include "dnscore/dnskey.h"
#if DNSCORE_HAS_EDDSA_SUPPORT
#include "dnscore/dnskey_eddsa.h"
#endif

#include "dnscore/dnssec_errors.h"
#include "dnscore/zalloc.h"

#define MODULE_MSG_HANDLE g_system_logger

#define KEYECDSA_TAG 0x415344434559454b
#define EDDSABFR_TAG 0x5246424153444445

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

struct dnskey_eddsa
{
    dnskey_raw_field_t private_key;
};

struct dnskey_eddsa_const
{
    const dnskey_raw_field_t private_key;
};

static void dnskey_eddsa_init(struct dnskey_eddsa *yeddsa)
{
    memset(yeddsa, 0, sizeof(struct dnskey_eddsa));
}

static void dnskey_eddsa_from_eddsa(struct dnskey_eddsa *yeddsa, const EVP_PKEY *eddsa)
{
    u8 *buffer;
    size_t size;
    if(EVP_PKEY_get_raw_private_key(eddsa, NULL, &size) == 1)
    {
        ZALLOC_OBJECT_ARRAY_OR_DIE(buffer, u8, size, EDDSABFR_TAG);
        EVP_PKEY_get_raw_private_key(eddsa, buffer, &size);
        yeddsa->private_key.buffer = buffer;
        yeddsa->private_key.size = size;
    }
}

static void dnskey_eddsa_finalize(struct dnskey_eddsa *yeddsa)
{
    if(yeddsa->private_key.buffer != NULL)
    {
        ZEROMEMORY(yeddsa->private_key.buffer, yeddsa->private_key.size);
        ZFREE_ARRAY(yeddsa->private_key.buffer, yeddsa->private_key.size);
    }
    dnskey_eddsa_init(yeddsa);
}

static const struct dnskey_field_access ECDSA_field_access[] =
{
    {"PrivateKey", offsetof(struct dnskey_eddsa,private_key), STRUCTDESCRIPTOR_RAW},
    {"", 0, STRUCTDESCRIPTOR_NONE}
};

static int
dnskey_eddsa_getnid(u8 algorithm)
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
#if 0
static int
dnskey_eddsa_getnid_by_size(u32 size)
{
    switch(size)
    {
        case 256:
        {
            return DNSKEY_ALGORITHM_ED25519_NID;
        }
        case 456:
        {
            return DNSKEY_ALGORITHM_ED448_NID;
        }
        default:
        {
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        }
    }
}
#endif
static int
dnskey_eddsa_nid_to_signature_bn_size(int nid)
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


static ya_result
dnskey_eddsa_signdigest(const dnssec_key *key, const u8 *digest, u32 digest_len, u8 *output)
{
    ya_result ret;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        if(EVP_DigestSignInit(ctx, NULL, NULL, NULL, key->key.ed) == 1)
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

static bool
dnskey_eddsa_verifydigest(const dnssec_key *key, const u8 *digest, u32 digest_len, const u8 *signature, u32 signature_len)
{
    yassert(signature_len <= DNSSEC_MAXIMUM_KEY_SIZE_BYTES);
    
#if DEBUG
    log_debug6("eddsa_verifydigest(K%{dnsname}-%03d-%05d, @%p, @%p)", key->owner_name, key->algorithm, key->tag, digest, signature);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, digest, digest_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, signature, signature_len, 32);
#endif

    /*
     * For P-256, each integer MUST be encoded as 32 octets;
     * for P-384, each integer MUST be encoded as 48 octets.
     */
    
    int bn_size = dnskey_eddsa_nid_to_signature_bn_size(key->nid);

    if(FAIL(bn_size))
    {
        log_err("EDDSA: getting size for NID returned: %r", bn_size);
        return FALSE;
    }

    if((int)signature_len != bn_size)
    {
        log_err("EDDSA: signature size unexpected");
        return FALSE;
    }

    bool ret = FALSE;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        if(EVP_DigestSignInit(ctx, NULL, NULL, NULL, key->key.ed) == 1)
        {
            if(EVP_DigestVerify(ctx, signature, signature_len, digest, digest_len) == 1)
            {
                ret = TRUE;
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

static EVP_PKEY*
dnskey_eddsa_public_load(u8 algorithm, const u8* rdata_key, u16 rdata_key_size)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(dnskey_eddsa_getnid(algorithm), NULL, rdata_key, rdata_key_size);
    return key;
 }

    
static u32
eddsa_public_store(const EVP_PKEY* eddsa, u8* output_buffer, size_t output_buffer_size)
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


static u32
dnskey_eddsa_dnskey_public_store(const dnssec_key* key, u8* rdata, size_t rdata_size)
{
    u32 len;

    SET_U16_AT(rdata[0], key->flags);
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = key->algorithm;

    len = eddsa_public_store(key->key.ed, &rdata[4], rdata_size) + 4;
    
    return len;
}

static u32
dnskey_eddsa_size(const dnssec_key* key)
{
    size_t size = 0;
    EVP_PKEY_get_raw_private_key(key->key.ed, NULL, &size);
    return (u32)size * 8;
}

/**
 * Returns the size in byte of the public key.
 * 
 * @param eddsa
 * @return 
 */

static u32
dnskey_eddsa_public_size(const EVP_PKEY* eddsa)
{
    size_t size = 0;
    EVP_PKEY_get_raw_public_key(eddsa, NULL, &size);
    return (u32)size;
}

static u32
dnskey_eddsa_dnskey_rdatasize(const dnssec_key* key)
{
    u32 size = dnskey_eddsa_public_size(key->key.ed) + 4;
    return size;
}

static void
dnskey_eddsa_free(dnssec_key* key)
{
    EVP_PKEY* eddsa = key->key.ed;
    EVP_PKEY_free(eddsa);

    key->key.ed = NULL;
}

static bool
dnskey_eddsa_equals(const dnssec_key *key_a, const dnssec_key *key_b)
{
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
#if SSL_API_GE_300
            return EVP_PKEY_eq(key_a->key.ed, key_b->key.ed) == 1;
#else
            return EVP_PKEY_cmp(key_a->key.ed, key_b->key.ed) == 1;
#endif
        }
    }

    return FALSE;
}

static ya_result
dnskey_eddsa_print_fields(dnssec_key *key, output_stream *os)
{
    struct dnskey_eddsa yeddsa;
    dnskey_eddsa_from_eddsa(&yeddsa, key->key.ed);

    // @note 20220802 edf -- prints the private key on stdout for some test, disabled, obviously
    // PEM_write_PrivateKey(stdout, key->key.ed, NULL, NULL, 0, NULL, NULL);

    size_t buffer_size;
    u8 buffer[256];

    buffer_size = sizeof(buffer);
    EVP_PKEY_get_raw_private_key(key->key.ed, buffer, &buffer_size);
    /*
    format("private[%llu]=", buffer_size);
    debug_dump_ex(buffer, buffer_size, 32, TRUE, FALSE, FALSE);
    */

    buffer_size = sizeof(buffer);
    EVP_PKEY_get_raw_public_key(key->key.ed, buffer, &buffer_size);
    /*
    format("\npublic[%llu]=", buffer_size);
    debug_dump_ex(buffer, buffer_size, 32, TRUE, FALSE, FALSE);
    println("");
    flushout();
    */

    ya_result ret = dnskey_field_access_print(ECDSA_field_access, &yeddsa, os);
        
    return ret;
}

static const dnssec_key_vtbl eddsa_vtbl = {
    dnskey_eddsa_signdigest,
    dnskey_eddsa_verifydigest,
    dnskey_eddsa_dnskey_rdatasize,
    dnskey_eddsa_dnskey_public_store,
    dnskey_eddsa_free,
    dnskey_eddsa_equals,
    dnskey_eddsa_print_fields,
    dnskey_eddsa_size,
    "ECDSA"
};

static ya_result
dnskey_eddsa_initinstance(EVP_PKEY *eddsa, u8 algorithm, u16 flags, const char *origin, dnssec_key **out_key)
{
    int nid;
    // needed to compute the tag
    u8 rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES]; /* 4096 bits -> 1KB */
    
    *out_key = NULL;
    
    if(FAIL(nid = dnskey_eddsa_getnid(algorithm)))
    {
        return nid;
    }

#if DEBUG
    memset(rdata, 0xff, sizeof(rdata));
#endif

    u32 public_key_size = dnskey_eddsa_public_size(eddsa);

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

    u16 tag = dnskey_get_tag_from_rdata(rdata, public_key_size + 4);

    dnssec_key* key = dnskey_newemptyinstance(algorithm, flags, origin); // RC

    key->key.ed = eddsa;
    key->vtbl = &eddsa_vtbl;
    key->tag = tag;
    key->nid = nid;
    key->status |= (i2d_PrivateKey(eddsa, NULL) > 0)?DNSKEY_KEY_IS_PRIVATE:0;

    *out_key = key;
    
    return SUCCESS;
}

static ya_result
dnskey_eddsa_parse_field(struct dnskey_field_parser *parser, parser_s *p)
{
    struct dnskey_eddsa *yeddsa = (struct dnskey_eddsa*)parser->data;

    ya_result ret = dnskey_field_access_parse(ECDSA_field_access, yeddsa, p);
            
    return ret;
}

static ya_result
dnskey_eddsa_parse_set_key(struct dnskey_field_parser *parser, dnssec_key *key)
{
    struct dnskey_eddsa *yeddsa = (struct dnskey_eddsa*)parser->data;
    
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

        u32 rdata_size = dnskey_eddsa_public_size(eddsa);

        u16 tag;

        u8 rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];

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

        key->key.ed = eddsa;

        key->tag = tag;
        key->nid = nid;

        key->status |= DNSKEY_KEY_IS_VALID | DNSKEY_KEY_IS_PRIVATE;

        return SUCCESS;
    }

    return DNSSEC_ERROR_INCOMPLETEKEY;
}

static void
dnskey_eddsa_parse_finalize(struct dnskey_field_parser *parser)
{
    struct dnskey_eddsa *ydsa = (struct dnskey_eddsa*)parser->data;
    
    if(ydsa != NULL)
    {
        dnskey_eddsa_finalize(ydsa);
        ZFREE(ydsa, struct dnskey_eddsa);
    }
}

static const struct dnskey_field_parser_vtbl eddsa_field_parser_vtbl =
{
    dnskey_eddsa_parse_field,
    dnskey_eddsa_parse_set_key,
    dnskey_eddsa_parse_finalize,
    "EDDSA"
};

void
dnskey_eddsa_parse_init(dnskey_field_parser *fp)
{
    struct dnskey_eddsa *yeddsa;
    ZALLOC_OBJECT_OR_DIE(yeddsa, struct dnskey_eddsa, KEYECDSA_TAG);
    ZEROMEMORY(yeddsa, sizeof(struct dnskey_eddsa));
    fp->data = yeddsa;
    fp->vtbl = &eddsa_field_parser_vtbl;
}

ya_result
dnskey_eddsa_loadpublic(const u8 *rdata, u16 rdata_size, const char *origin, dnssec_key** out_key)
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

    EVP_PKEY *eddsa = dnskey_eddsa_public_load(algorithm, rdata, rdata_size);
    
    if(eddsa != NULL)
    {
        dnssec_key *key;
        
        if(ISOK(return_value = dnskey_eddsa_initinstance(eddsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }
        
        EVP_PKEY_free(eddsa);
    }
    
    return return_value;
}

ya_result
dnskey_eddsa_newinstance(u32 size, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
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

    ya_result ret = ERROR;
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(dnskey_eddsa_getnid(algorithm), NULL);
    if(ctx != NULL)
    {
        if(EVP_PKEY_keygen_init(ctx) == 1)
        {
            EVP_PKEY *evp_key = NULL;

            if(EVP_PKEY_keygen(ctx, &evp_key) == 1)
            {
                dnssec_key *key = NULL;

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


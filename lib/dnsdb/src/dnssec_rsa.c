/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
* DOCUMENTATION */
/** @defgroup dnskey DNSSEC keys functions
 *  @ingroup dnsdbdnssec
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

#include <dnscore/sys_types.h>
#include <dnscore/base64.h>

#include <dnscore/logger.h>

#include "dnsdb/dnsrdata.h"
#include "dnsdb/dnssec.h"
#include "dnsdb/dnssec_keystore.h"
#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_utils.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

#define WRITE_BIGNUM_AS_BASE64(f_,num_,tmp_in_,tmp_out_)    \
{                                                           \
    if(num_==NULL)                                          \
    {                                                       \
        return DNSSEC_ERROR_BNISNULL;                       \
    }                                                       \
                                                            \
    u32 n=BN_num_bytes(num_);                               \
    if(n>sizeof(tmp_in_))                                   \
    {                                                       \
        return DNSSEC_ERROR_BNISBIGGERTHANBUFFER;           \
    }                                                       \
                                                            \
    BN_bn2bin(num_, tmp_in_);                               \
    n=base64_encode(tmp_in_,n,tmp_out_);                    \
    if((n=fwrite(tmp_out_,n,1,f_))!=1)                      \
    {                                                       \
        return DNSSEC_ERROR_KEYWRITEERROR;                  \
    }                                                       \
}

struct structdescriptor
{
    const char* name;
    size_t address;
    int type;
};

#define STRUCTDESCRIPTOR_BN 1

struct structdescriptor struct_RSA[] ={
    {"Modulus", offsetof(RSA, n), STRUCTDESCRIPTOR_BN},
    {"PublicExponent", offsetof(RSA, e), STRUCTDESCRIPTOR_BN},
    {"PrivateExponent", offsetof(RSA, d), STRUCTDESCRIPTOR_BN},
    {"Prime1", offsetof(RSA, p), STRUCTDESCRIPTOR_BN},
    {"Prime2", offsetof(RSA, q), STRUCTDESCRIPTOR_BN},
    {"Exponent1", offsetof(RSA, dmp1), STRUCTDESCRIPTOR_BN},
    {"Exponent2", offsetof(RSA, dmq1), STRUCTDESCRIPTOR_BN},
    {"Coefficient", offsetof(RSA, iqmp), STRUCTDESCRIPTOR_BN},
    {NULL, 0, 0}
};

static RSA*
rsa_dnskey_key_scan(FILE *f)
{
    char tmp_label[1024];
    /*char tmp_in[BASE64_ENCODED_SIZE(DNSSEC_MAXIMUM_KEY_SIZE_BYTES)];*/
    u8 tmp_out[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];

    BN_CTX *ctx = BN_CTX_new();

    zassert(ctx != NULL);

    RSA* rsa = RSA_new();

    while(!feof(f))
    {
        tmp_label[0] = '\0';

        if(fgets(tmp_label, sizeof (tmp_label), f) == (char*)EOF) /* comparison ptr/int ? man fgets */
        {
            break;
        }

        char *tmp_in = strchr(tmp_label, ':');

        if(tmp_in == NULL)
        {
            /* error */

            break;
        }

        *tmp_in = '\0';
        while(*++tmp_in == ' ');
        size_t tmp_in_len = strcspn(tmp_in, " \t\r\n");
        tmp_in[tmp_in_len] = '\0';

        if(strcmp(tmp_label, "Private-key-format") == 0)
        {
            if(memcmp(tmp_in, "v1.", 3) != 0) /* Assume that all 1.x formatted keys will be recognisable */
            {
                break;
            }
        }
        else if(strcmp(tmp_label, "Algorithm") == 0) /* only accept algorithms NSEC3-RSA-SHA1 and NSEC-RSA-SHA1 */
        {
            if((strcmp(tmp_in, "7") != 0) && (strcmp(tmp_in, "5") != 0))
            {
                log_err("unsupported RSA algorithm '%s'", tmp_in);
                
                break;
            }
        }
        else
        {
            for(struct structdescriptor *sd = struct_RSA; sd->name != NULL; sd++)
            {
                if(strcmp(tmp_label, sd->name) == 0)
                {
                    BIGNUM **valuep = (BIGNUM**)&(((u8*)rsa)[sd->address]);

                    if(*valuep != NULL)
                    {
                        log_err("field %s has already been initialized", tmp_label);
                        fseek(f, 0, SEEK_END);
                        break;
                    }

                    ya_result n = base64_decode(tmp_in, tmp_in_len, tmp_out);

                    if(FAIL(n))
                    {
                        log_err("unable to decode field %s (%s)", tmp_label, tmp_in);
                        fseek(f, 0, SEEK_END);
                        break;
                    }

                    *valuep = BN_bin2bn(tmp_out, n, NULL);
                    break;
                }
            } /* for each possible field */
        }
    }

    if((rsa->n == NULL)    ||
       (rsa->e == NULL)    ||
       (rsa->p == NULL)    ||
       (rsa->q == NULL)    ||
       (rsa->dmp1 == NULL) ||
       (rsa->dmq1 == NULL) ||
       (rsa->iqmp == NULL))
    {
        RSA_free(rsa);
        rsa = NULL;
    }

    BN_CTX_free(ctx);

    return rsa;
}

static RSA*
rsa_genkey(u32 size)
{
    zassert(size >= DNSSEC_MINIMUM_KEY_SIZE && size <= DNSSEC_MAXIMUM_KEY_SIZE);

    BN_CTX *ctx;
    BIGNUM *e;
    RSA* rsa;

    ctx = BN_CTX_new();

    zassert(ctx != NULL);

    e = BN_new();
    BN_set_word(e, 0x10001);

    zassert(e != NULL);

    rsa = RSA_new();

    zassert(rsa != NULL);

    int err = RSA_generate_key_ex(rsa, size, e, NULL); /* no callback */

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
rsa_signdigest(dnssec_key *key, u8 *digest, u32 digest_len, u8 *output)
{
    u32 output_size = MAX_U32;

    int err = RSA_sign(key->nid, digest, digest_len, output, &output_size, key->key.rsa);

#ifndef NDEBUG
    if(err == 0)
    {
        ERR_print_errors_fp(stderr);

        return DNSSEC_ERROR_RSASIGNATUREFAILED;
    }
#endif

    return (err != 0) ? output_size : DNSSEC_ERROR_RSASIGNATUREFAILED;
}

static bool
rsa_verifydigest(dnssec_key* key, u8* digest, u32 digest_len, u8* signature, u32 signature_len)
{
    zassert(signature_len <= DNSSEC_MAXIMUM_KEY_SIZE_BYTES);

    int err = RSA_verify(key->nid, digest, digest_len, signature, signature_len, key->key.rsa);

    if(err == 0)
    {
        unsigned long ssl_err;

        while((ssl_err = ERR_get_error()) != 0)
        {
            char buffer[128];
            ERR_error_string_n(ssl_err, buffer, sizeof (buffer));

            log_debug("digest verification returned an ssl error %08x %s", ssl_err, buffer);
        }

        ERR_clear_error();

        return FALSE;
    }

    return TRUE;
}

static RSA*
rsa_public_load(const u8* rdata, u16 rdata_size)
{
    const u8 *inptr = rdata;
    u32 n;
    n = *inptr++;
    rdata_size--;
    if(n == 0)
    {
        n = *inptr++;
        n <<= 8;
        n |= *inptr++;
        rdata_size-=2;
    }

    BIGNUM* exponent;
    BIGNUM* modulus;

    exponent = BN_bin2bn(inptr, n, NULL);
    inptr += n;
    n = rdata_size - n;
    modulus = BN_bin2bn(inptr, n, NULL);

    BN_CTX *ctx;
    RSA* rsa;

    ctx = BN_CTX_new();

    zassert(ctx != NULL);

    rsa = RSA_new();

    zassert(rsa != NULL);

    rsa->e = exponent;
    rsa->n = modulus;

    BN_CTX_free(ctx);

    return rsa;
 }

static u32
rsa_public_store(RSA* rsa, u8* output_buffer)
{
    unsigned char* outptr = output_buffer;

    u32 n;

    BIGNUM* exponent = rsa->e;
    BIGNUM* modulus = rsa->n;

    n = BN_num_bytes(exponent);

    if(n > 1 && n < 256)
    {
        *outptr++ = n;
    }
    else
    {
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
rsa_dnskey_public_store(dnssec_key* key, u8* output_buffer)
{
    return rsa_public_store(key->key.rsa, output_buffer);
}

static u32
rsa_public_getsize(RSA* rsa)
{
    u32 e_size = BN_num_bytes(rsa->e);
    u32 m_size = BN_num_bytes(rsa->n);

    return m_size + e_size + ((e_size < 256) ? 1 : 3);
}

static u32
rsa_dnskey_public_getsize(dnssec_key* key)
{
    return rsa_public_getsize(key->key.rsa);
}

static void
rsa_free(dnssec_key* key)
{
    RSA* rsa = key->key.rsa;
    RSA_free(rsa);

    key->key.rsa = NULL;
}

static dnssec_key_vtbl rsa_vtbl = {
    rsa_signdigest,
    rsa_verifydigest,
    rsa_dnskey_public_getsize,
    rsa_dnskey_public_store,
    rsa_free
};

static int
rsa_getnid(u8 algorithm)
{
    switch(algorithm)
    {
        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
        case DNSKEY_ALGORITHM_RSASHA1:
        {
            return NID_sha1;
        }
        default:
        {
            return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
        }
            
    }
}

ya_result rsa_initinstance(RSA* rsa, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
{
    int nid;
    
    u8 rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES]; /* 4096 bits -> 1KB */
    
    *out_key = NULL;
    
    if(FAIL(nid = rsa_getnid(algorithm)))
    {
        return nid;
    }

#ifndef NDEBUG
    memset(rdata, 0xff, sizeof (rdata));
#endif

    u32 rdata_size = rsa_public_getsize(rsa);

    if(rdata_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    SET_U16_AT(rdata[0], htons(flags)); /** @todo: NATIVEFLAGS */
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = algorithm;

    if(rsa_public_store(rsa, &rdata[4]) != rdata_size)
    {
        return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
    }

    /* Note : + 4 because of the flags,protocol & algorithm bytes
     *        are not taken in account
     */

    u16 tag = dnskey_getkeytag(rdata, rdata_size + 4);

    dnssec_key* key = dnssec_key_newemptyinstance(algorithm, flags, origin);

    key->key.rsa = rsa;
    key->vtbl = &rsa_vtbl;
    key->tag = tag;
    key->nid = nid;
    key->is_private = (rsa->q != NULL) && (rsa->p != NULL);

    *out_key = key;
    
    return SUCCESS;
}


ya_result rsa_loadprivate(FILE* private, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
{
    *out_key = NULL;
    
    if(private == NULL)
    {
        return ERROR;
    }
    
    if((algorithm != DNSKEY_ALGORITHM_RSASHA1_NSEC3) && (algorithm != DNSKEY_ALGORITHM_RSASHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }
    
    ya_result return_value = ERROR;
    
    RSA *rsa = rsa_dnskey_key_scan(private);
    
    if(rsa != NULL)
    {
        dnssec_key *key;
                
        if(ISOK(return_value = rsa_initinstance(rsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;
            
            return return_value;
        }
        
        RSA_free(rsa);
    }
    
    return return_value;
}

ya_result
rsa_loadpublic(const u8 *rdata, u16 rdata_size, const char *origin, dnssec_key** out_key)
{
    *out_key = NULL;
            
    if(rdata == NULL || rdata_size <= 6 || origin == NULL)
    {
        /* bad */
        
        return ERROR;
    }

    u16 flags = ntohs(GET_U16_AT(rdata[0]));
    u8 algorithm = rdata[3];
    
    if((algorithm != DNSKEY_ALGORITHM_RSASHA1_NSEC3) && (algorithm != DNSKEY_ALGORITHM_RSASHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    rdata += 4;
    rdata_size -= 4;
    
    ya_result return_value = ERROR;

    RSA *rsa = rsa_public_load(rdata, rdata_size);
    
    if(rsa != NULL)
    {
        dnssec_key *key;
        
        if(ISOK(return_value = rsa_initinstance(rsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }
        
        RSA_free(rsa);
    }
    
    return return_value;
}

ya_result
rsa_newinstance(u32 size, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
{
    *out_key = NULL;
    
    if(size > DNSSEC_MAXIMUM_KEY_SIZE)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }
    
    if((algorithm != DNSKEY_ALGORITHM_RSASHA1_NSEC3) && (algorithm != DNSKEY_ALGORITHM_RSASHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }
    
    ya_result return_value = ERROR;

    RSA *rsa = rsa_genkey(size);
    
    if(rsa != NULL)
    {
        dnssec_key *key;
        
        if(ISOK(return_value = rsa_initinstance(rsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;
            
            return return_value;
        }
        
        RSA_free(rsa);
    }

    return return_value;
}

ya_result
rsa_storeprivate(FILE* private, dnssec_key* key)
{
    if(private == NULL)
    {
        return ERROR;
    }
    
    if((key->algorithm != DNSKEY_ALGORITHM_RSASHA1_NSEC3) && (key->algorithm != DNSKEY_ALGORITHM_RSASHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    u8 tmp_in[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];
    char tmp_out[BASE64_ENCODED_SIZE(DNSSEC_MAXIMUM_KEY_SIZE_BYTES)];

    RSA* rsa = key->key.rsa;

    /* Modulus */

    fprintf(private, "Private-key-format: v1.2\nAlgorithm: %i (?)", key->algorithm); /* @TODO: think about handling v1.3 */

    for(struct structdescriptor *sd = struct_RSA; sd->name != NULL; sd++)
    {
        fprintf(private, "%s: ", sd->name);
        BIGNUM **valuep = (BIGNUM**)&(((u8*)rsa)[sd->address]);
        WRITE_BIGNUM_AS_BASE64(private, *valuep, tmp_in, tmp_out);
        fputs("\n", private);
    }

    return SUCCESS;
}

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/


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
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/dsa.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

#include "dnscore/dnscore.h"

#include "dnscore/sys_types.h"
#include "dnscore/base64.h"

#include "dnscore/logger.h"
#include "dnscore/dnskey.h"
#include "dnscore/dnskey_dsa.h"
#include "dnscore/dnssec_errors.h"

#include "dnscore/dnskey.h"

#define MODULE_MSG_HANDLE g_system_logger

static const struct structdescriptor struct_DSA[] ={
    {"Prime(p)", offsetof(DSA, p), STRUCTDESCRIPTOR_BN},
    {"Subprime(q)", offsetof(DSA, q), STRUCTDESCRIPTOR_BN},
    {"Base(g)", offsetof(DSA, g), STRUCTDESCRIPTOR_BN},
    {"Private_value(x)", offsetof(DSA, priv_key), STRUCTDESCRIPTOR_BN},
    {"Public_value(y)", offsetof(DSA, pub_key), STRUCTDESCRIPTOR_BN},
    {NULL, 0, 0}
};


static int
dsa_getnid(u8 algorithm)
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

static DSA*
dsa_dnskey_key_scan(FILE *f)
{
    char tmp_label[1024];
    /*char tmp_in[BASE64_ENCODED_SIZE(DNSSEC_MAXIMUM_KEY_SIZE_BYTES)];*/
    u8 tmp_out[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];

    DSA* dsa = DSA_new();

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
        else if(strcmp(tmp_label, "Algorithm") == 0) /* only accept algorithms NSEC3-DSA-SHA1 and NSEC-DSA-SHA1 */
        {
            int alg = atoi(tmp_in);
            
            if(FAIL(dsa_getnid(alg)))
            {
                log_err("unsupported DSA algorithm '%s'", tmp_in);
                    
                break;
            }
        }
        else
        {
            for(const struct structdescriptor *sd = struct_DSA; sd->name != NULL; sd++)
            {
                if(strcmp(tmp_label, sd->name) == 0)
                {
                    BIGNUM **valuep = (BIGNUM**)&(((u8*)dsa)[sd->address]);

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

    if((dsa->p == NULL)    ||
       (dsa->q == NULL)    ||
       (dsa->g == NULL)    ||
       (dsa->priv_key == NULL)    ||
       (dsa->pub_key == NULL))
    {
        DSA_free(dsa);
        dsa = NULL;
    }

    return dsa;
}

static DSA*
dsa_genkey(u32 size)
{
    yassert(size >= DNSSEC_MINIMUM_KEY_SIZE && size <= DNSSEC_MAXIMUM_KEY_SIZE);

    int err;
    DSA* dsa;

    dsa = DSA_generate_parameters(size, NULL,0, NULL, NULL, NULL, NULL);
    
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

static ya_result
dsa_signdigest(dnssec_key *key, u8 *digest, u32 digest_len, u8 *output)
{
    DSA_SIG *sig = DSA_do_sign(digest, digest_len, key->key.dsa);

    if(sig != NULL)
    {
        u32 t = BN_num_bytes(key->key.dsa->pub_key) >> 3;
        u32 rn = BN_num_bytes(sig->r);        
        
        *output++ = t;
        BN_bn2bin(sig->r, output);
        output += rn;
        BN_bn2bin(sig->s, output);
        
        DSA_SIG_free(sig);
        
        return (rn << 1) + 1;
    }
    else
    {
        unsigned long ssl_err;

        while((ssl_err = ERR_get_error()) != 0)
        {
            char buffer[256];
            ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
            log_err("digest verification returned an ssl error %08x %s", ssl_err, buffer);
        }

        ERR_clear_error();
        
        return DNSSEC_ERROR_DSASIGNATUREFAILED;
    }
}

static bool
dsa_verifydigest(dnssec_key* key, u8* digest, u32 digest_len, u8* signature, u32 signature_len)
{
    yassert(signature_len <= DNSSEC_MAXIMUM_KEY_SIZE_BYTES);
    
#ifdef DEBUG
    log_debug6("dsa_verifydigest(K%{dnsname}-%03d-%05d, @%p, @%p)", key->owner_name, key->algorithm, key->tag, digest, signature);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, digest, digest_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, signature, signature_len, 32);
#endif

    DSA_SIG sig;
    
    if(signature_len != 41)
    {
        log_warn("DSA signature expected to be 41 bytes long");
    }
    
    if((signature_len & 1) == 0)
    {
        log_err("DSA signature size expected to be an odd number");
        
        return FALSE;
    }
    
    u8 t = *signature++;
    
    if(t != 8)
    {
        log_warn("DSA T!=8");
    }
    
    signature_len--;        
    signature_len >>= 1;
    
    sig.r = BN_bin2bn(signature, signature_len, NULL);
    signature += signature_len;
    sig.s = BN_bin2bn(signature, signature_len, NULL);

    int err = DSA_do_verify(digest, digest_len, &sig, key->key.dsa);
    
    BN_free(sig.r);
    BN_free(sig.s);
    
    if(err != 1)
    {
        unsigned long ssl_err;

        while((ssl_err = ERR_get_error()) != 0)
        {
            char buffer[256];
            ERR_error_string_n(ssl_err, buffer, sizeof (buffer));
            log_err("digest verification returned an ssl error %08x %s", ssl_err, buffer);
        }

        ERR_clear_error();

        return FALSE;
    }

    return TRUE;
}

static DSA*
dsa_public_load(const u8* rdata, u16 rdata_size)
{
    if(rdata == NULL)
    {
        return NULL;
    }
    
    const u8 *inptr = rdata;
    u32 t;
    t = *inptr;
    
    u32 pgy_len = 64 + (t << 3);
    
    if(rdata_size != 1 + 20 + 3 * pgy_len)
    {
        return NULL;
    }
    
    inptr++;

    BIGNUM* q;
    BIGNUM* p;
    BIGNUM* g;
    BIGNUM* y;

    q = BN_bin2bn(inptr, 20, NULL);
    if(q == NULL)
    {
        log_err("dsa_public_load: NULL q");
        
        return NULL;
    }
    inptr += 20;
    p = BN_bin2bn(inptr, pgy_len, NULL);
    if(p == NULL)
    {
        log_err("dsa_public_load: NULL p");
        BN_free(q);
        
        return NULL;
    }
    inptr += pgy_len;
    g = BN_bin2bn(inptr, pgy_len, NULL);
    if(g == NULL)
    {
        log_err("dsa_public_load: NULL g");
        BN_free(q);
        BN_free(p);
        
        return NULL;
    }
    inptr += pgy_len;
    y = BN_bin2bn(inptr, pgy_len, NULL);
    if(y == NULL)
    {
        log_err("dsa_public_load: NULL y");
        BN_free(q);
        BN_free(p);
        BN_free(g);
        
        return NULL;
    }

    DSA* dsa;
    dsa = DSA_new();

    yassert(dsa != NULL);

    dsa->q = q;
    dsa->p = p;
    dsa->g = g;
    dsa->pub_key = y;

    return dsa;
 }

static u32
dsa_public_store(DSA* dsa, u8* output_buffer)
{
    unsigned char* outptr = output_buffer;

    BIGNUM* q = dsa->q;
    BIGNUM* p = dsa->p;
    BIGNUM* g = dsa->g;
    BIGNUM* y = dsa->pub_key;

    u32 q_n = BN_num_bytes(q);
    
    if(q_n != 20)
    {
        return 0;
    }
    
    u32 p_n = BN_num_bytes(p);
    u32 g_n = BN_num_bytes(g);
    u32 y_n = BN_num_bytes(y);

    if((p_n != g_n) || (p_n != y_n))
    {
        return 0;
    }
    
    s32 t = p_n;
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

static u32
dsa_dnskey_public_store(dnssec_key* key, u8* output_buffer)
{
    return dsa_public_store(key->key.dsa, output_buffer);
}

static u32
dsa_public_getsize(DSA* dsa)
{
    BIGNUM* q = dsa->q;
    BIGNUM* p = dsa->p;
    BIGNUM* g = dsa->g;
    BIGNUM* y = dsa->pub_key;

    u32 q_n = BN_num_bytes(q);
    u32 p_n = BN_num_bytes(p);
    u32 g_n = BN_num_bytes(g);
    u32 y_n = BN_num_bytes(y);

    return 1 + q_n + p_n + g_n + y_n;
}

static u32
dsa_dnskey_public_getsize(dnssec_key* key)
{
    return dsa_public_getsize(key->key.dsa);
}

static void
dsa_free(dnssec_key* key)
{
    DSA* dsa = key->key.dsa;
    DSA_free(dsa);

    key->key.dsa = NULL;
}

static bool
dsa_equals(dnssec_key* key_a,dnssec_key* key_b)
{
    /* RSA, compare modulus and exponent, exponent first (it's the smallest) */

    if(key_a == key_b)
    {
        return TRUE;
    }
    
    if((key_a->tag == key_b->tag) && (key_a->flags == key_b->flags) && (key_a->algorithm == key_b->algorithm))
    {
        if(strcmp(key_a->origin, key_b->origin) == 0)
        {
            DSA* a_dsa = key_a->key.dsa;
            DSA* b_dsa = key_b->key.dsa;

            if(BN_cmp(a_dsa->q, b_dsa->q) == 0)
            {
                if(BN_cmp(a_dsa->p, b_dsa->p) == 0)
                {
                    if(BN_cmp(a_dsa->g, b_dsa->g) == 0)
                    {
                        if(BN_cmp(a_dsa->pub_key, b_dsa->pub_key) == 0)
                        {
                            if(a_dsa->priv_key != NULL)
                            {
                                if(b_dsa->priv_key != NULL)
                                {
                                    return BN_cmp(a_dsa->priv_key, b_dsa->priv_key) == 0;
                                }
                            }
                            else
                            {
                                return b_dsa->priv_key == NULL;
                            }
                        }
                    }
                }
            }
        }
    }

    return FALSE;
}

const struct structdescriptor *
dsa_get_fields_descriptor(dnssec_key* key)
{
    return struct_DSA;
}

static const dnssec_key_vtbl dsa_vtbl = {
    dsa_signdigest,
    dsa_verifydigest,
    dsa_dnskey_public_getsize,
    dsa_dnskey_public_store,
    dsa_free,
    dsa_equals,
    dsa_get_fields_descriptor,
    "DSA"
};

ya_result dsa_initinstance(DSA* dsa, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
{
    int nid;
    
    u8 rdata[DNSSEC_MAXIMUM_KEY_SIZE_BYTES]; /* 4096 bits -> 1KB */
    
    *out_key = NULL;
    
    if(FAIL(nid = dsa_getnid(algorithm)))
    {
        return nid;
    }

#ifdef DEBUG
    memset(rdata, 0xff, sizeof (rdata));
#endif

    u32 rdata_size = dsa_public_getsize(dsa);

    if(rdata_size > DNSSEC_MAXIMUM_KEY_SIZE_BYTES)
    {
        return DNSSEC_ERROR_KEYISTOOBIG;
    }

    SET_U16_AT(rdata[0], htons(flags)); /// @todo 20140523 edf -- DNSKEY NATIVEFLAGS
    rdata[2] = DNSKEY_PROTOCOL_FIELD;
    rdata[3] = algorithm;

    if(dsa_public_store(dsa, &rdata[4]) != rdata_size)
    {
        return DNSSEC_ERROR_UNEXPECTEDKEYSIZE; /* Computed size != real size */
    }

    /* Note : + 4 because of the flags,protocol & algorithm bytes
     *        are not taken in account
     */

    u16 tag = dnskey_getkeytag(rdata, rdata_size + 4);

    dnssec_key* key = dnskey_newemptyinstance(algorithm, flags, origin);

    key->key.dsa = dsa;
    key->vtbl = &dsa_vtbl;
    key->tag = tag;
    key->nid = nid;
    key->is_private = (dsa->priv_key != NULL);

    *out_key = key;
    
    return SUCCESS;
}


ya_result dsa_loadprivate(FILE* private, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
{
    *out_key = NULL;
    
    if(private == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    if((algorithm != DNSKEY_ALGORITHM_DSASHA1_NSEC3) && (algorithm != DNSKEY_ALGORITHM_DSASHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }
    
    ya_result return_value = ERROR;
    
    DSA *dsa = dsa_dnskey_key_scan(private);
    
    if(dsa != NULL)
    {
        dnssec_key *key;
                
        if(ISOK(return_value = dsa_initinstance(dsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;
            
            return return_value;
        }
        
        DSA_free(dsa);
    }
    
    return return_value;
}

ya_result
dsa_loadpublic(const u8 *rdata, u16 rdata_size, const char *origin, dnssec_key** out_key)
{
    *out_key = NULL;
            
    if(rdata == NULL || rdata_size <= 6 || origin == NULL)
    {
        /* bad */
        
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    u16 flags = ntohs(GET_U16_AT(rdata[0]));
    u8 algorithm = rdata[3];
    
    if((algorithm != DNSKEY_ALGORITHM_DSASHA1_NSEC3) && (algorithm != DNSKEY_ALGORITHM_DSASHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    rdata += 4;
    rdata_size -= 4;
    
    ya_result return_value = ERROR;

    DSA *dsa = dsa_public_load(rdata, rdata_size);
    
    if(dsa != NULL)
    {
        dnssec_key *key;
        
        if(ISOK(return_value = dsa_initinstance(dsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;

            return return_value;
        }
        
        DSA_free(dsa);
    }
    
    return return_value;
}

ya_result
dsa_newinstance(u32 size, u8 algorithm, u16 flags, const char* origin, dnssec_key** out_key)
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
    
    ya_result return_value = ERROR;

    DSA *dsa = dsa_genkey(size);
    
    if(dsa != NULL)
    {
        dnssec_key *key;
        
        if(ISOK(return_value = dsa_initinstance(dsa, algorithm, flags, origin, &key)))
        {
            *out_key = key;
            
            return return_value;
        }
        
        DSA_free(dsa);
    }

    return return_value;
}

ya_result
dsa_storeprivate(FILE* private, dnssec_key* key)
{
    if(private == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    if((key->algorithm != DNSKEY_ALGORITHM_DSASHA1_NSEC3) && (key->algorithm != DNSKEY_ALGORITHM_DSASHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDKEYALGORITHM;
    }

    u8 tmp_in[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];
    char tmp_out[BASE64_ENCODED_SIZE(DNSSEC_MAXIMUM_KEY_SIZE_BYTES)];

    DSA* dsa = key->key.dsa;

    /* Modulus */

    fprintf(private, "Private-key-format: v1.2\nAlgorithm: %i (?)", key->algorithm); /// @todo 20140523 edf -- handle v1.3 */

    ya_result return_code = ERROR;
    
    for(const struct structdescriptor *sd = struct_DSA; sd->name != NULL; sd++)
    {
        fprintf(private, "%s: ", sd->name);
        BIGNUM **valuep = (BIGNUM**)&(((u8*)dsa)[sd->address]);
        
        // WRITE_BIGNUM_AS_BASE64(private, *valuep, tmp_in, tmp_out);
        
        if(FAIL(return_code = dnskey_write_bignum_as_base64(private, *valuep, tmp_in, sizeof(tmp_in), tmp_out, sizeof(tmp_out))))
        {
            break;
        }
        
        fputs("\n", private);
    }

    return return_code;
}

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/


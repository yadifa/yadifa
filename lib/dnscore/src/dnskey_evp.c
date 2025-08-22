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
#include <openssl/ssl.h>
#include <openssl/core_names.h>
#include "dnscore/openssl.h"
#include "dnscore/dnskey.h"

#include "dnscore/sys_types.h"
#include "dnscore/base64.h"

#include "dnscore/logger.h"
#include "dnscore/dnssec_errors.h"
#include "dnscore/parser.h"
#include "dnscore/tools.h"
#include "dnscore/zalloc.h"

#define MODULE_MSG_HANDLE g_system_logger

#ifndef SSL_API
#error "SSL_API not defined"
#endif

#define EVP_SIGNDIGEST_IMPLEMENTED   0
#define EVP_SIGN_IMPLEMENTED         0
#define EVP_VERIFYDIGEST_IMPLEMENTED 0

#if DEBUG
void OSSL_PARAM_dump(const OSSL_PARAM *params)
{
    if(params == NULL)
    {
        return;
    }
    while(params->key != NULL)
    {
        if(params->data_size > 0)
        {
            format("field '%s' (%i)", STRNULL(params->key), params->data_type);
            if(params->data != NULL)
            {
                format("@%p=", params->data);
                osprint_dump(termout, params->data, params->data_size, params->data_size, OSPRINT_DUMP_BASE16);
            }
            else
            {
                format(" size=%i", params->data_size);
            }
            println("");
        }
        ++params;
    }
    flushout();
}
#endif

#if EVP_SIGNDIGEST_IMPLEMENTED
ya_result dnskey_evp_signdigest(const dnskey_t *key, const uint8_t *digest, uint32_t digest_len, uint8_t *output)
{
    ya_result   ret;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        if(EVP_DigestSignInit(ctx, NULL, NULL, NULL, key->key.evp_key) == 1)
        {
#if 0
            print("DIGEST: ");
            osprint_dump(termout, digest,digest_len,32,OSPRINT_DUMP_BUFFER);
            println("");
#endif
            size_t output_size = U32_MAX;
            if(EVP_DigestSign(ctx, output, &output_size, digest, digest_len) == 1)
            {
                // bytes_swap(output, output_size);
                ret = (ya_result)output_size;
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
#endif

#if EVP_SIGN_IMPLEMENTED
ya_result dnskey_evp_sign(const dnskey_t *key, const uint8_t *digest, uint32_t digest_len, uint8_t *output)
{
    ya_result   ret;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        if(EVP_SignInit_ex(ctx, EVP_md_null(), NULL) == 1)
        {
            if(EVP_SignUpdate(ctx, digest, digest_len) == 1)
            {
                unsigned int output_size = U32_MAX;
                if(EVP_SignFinal(ctx, output, &output_size, key->key.evp_key) == 1)
                {
                    // bytes_swap(output, output_size);
                    ret = (ya_result)output_size;
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
#endif

#if EVP_VERIFYDIGEST_IMPLEMENTED
bool dnskey_evp_verifydigest(const dnskey_t *key, const uint8_t *digest, uint32_t digest_len, const uint8_t *signature, uint32_t signature_len)
{
    yassert(signature_len <= DNSSEC_MAXIMUM_KEY_SIZE_BYTES);

#if DEBUG
    log_debug6("dnskey_evp_verifydigest(K%{dnsname}-%03d-%05d, @%p, @%p)", key->owner_name, key->algorithm, key->tag, digest, signature);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, digest, digest_len, 32);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG6, signature, signature_len, 32);
#endif

    bool        ret = false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx != NULL)
    {
        if(EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key->key.evp_key) == 1)
        {
#if 0
            print("DIGEST: ");
            osprint_dump(termout, digest,digest_len,32,OSPRINT_DUMP_BUFFER);
            println("");
#endif
            if(EVP_DigestVerify(ctx, signature, signature_len, digest, digest_len) == 1)
            {
                ret = true;
            }
            else
            {
                crypto_openssl_error();
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
#endif

void dnskey_evp_free(dnskey_t *key)
{
    EVP_PKEY *evp_key = key->key.evp_key;
    EVP_PKEY_free(evp_key);
    key->key.evp_key = NULL;
}

#if DEBUG
void EVP_PKEY_dump_params(EVP_PKEY *evp_key)
{
    if(evp_key != NULL)
    {
        const OSSL_PARAM *params = EVP_PKEY_gettable_params(evp_key);
        OSSL_PARAM_dump(params);
    }
}
#endif

/** @} */

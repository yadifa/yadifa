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

/** @defgroup hmac
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include "dnscore/dnscore-config.h"
#include "dnscore/zalloc.h"
#include "dnscore/hmac.h"
#include "dnscore/logger.h"
#include "dnscore/openssl.h"

#include <openssl/hmac.h>

#ifndef SSL_API
#error "SSL_API not defined"
#endif

#define LOG_HMAC_OPENSSL 0 // 1 2 3

#if SSL_API_LT_110 // ie: 0.9.x
struct hmac_openssl_t
{
    const struct hmac_vtbl *vtbl;
    HMAC_CTX hmac;
};
#else
struct hmac_openssl_t
{
    const struct hmac_vtbl *vtbl;
    HMAC_CTX *hmac;
};
#endif

typedef struct hmac_openssl_t* hmac_openssl_t;

static HMAC_CTX* hmac_openssl_hmac(tsig_hmac_t hmac)
{
#if SSL_API_LT_110 // ie: 0.9.x
    return &((hmac_openssl_t)hmac)->hmac;
#else
    return ((hmac_openssl_t)hmac)->hmac;
#endif
}

static const EVP_MD *
hmac_get_EVP_MD(u8 algorithm)
{
    switch(algorithm)
    {
#ifndef OPENSSL_NO_MD5
        case HMAC_MD5:
            return EVP_md5();
#endif
#ifndef OPENSSL_NO_SHA
        case HMAC_SHA1:
            return EVP_sha1();
#endif
#ifndef OPENSSL_NO_SHA256
        case HMAC_SHA224:
            return EVP_sha224();
        case HMAC_SHA256:
            return EVP_sha256();
#endif
#ifndef OPENSSL_NO_SHA512
        case HMAC_SHA384:
            return EVP_sha384();
        case HMAC_SHA512:
            return EVP_sha512();
#endif
        default:
            return EVP_md_null();
    }
}

/**
 * Allocates an HMAC_CTX
 * This layer has been added for openssl-1.1.0 compatibility
 */

#define HMACCTX_TAG 0x58544343414d48

/**
 * Frees an HMAC_CTX
 * This layer has been added for openssl-1.1.0 compatibility
 */

static void
hmac_openssl_free(tsig_hmac_t t)
{
    hmac_openssl_t hmac_openssl = (hmac_openssl_t)t;
#if SSL_API_LT_110
    HMAC_CTX_cleanup(hmac_openssl_hmac(t));
#else
    HMAC_CTX_free(hmac_openssl_hmac(t));
#endif
    ZFREE_OBJECT(hmac_openssl);
}

static void
hmac_openssl_reset(tsig_hmac_t t)
{
    HMAC_CTX *hmac = hmac_openssl_hmac(t);
#if SSL_API_LT_110
    HMAC_CTX_cleanup(hmac);
    HMAC_CTX_init(hmac);
#else
    HMAC_CTX_reset(hmac);
#endif
}

static ya_result
hmac_openssl_init(tsig_hmac_t t, const void *key, int len, u8 algorithm)
{    
#if LOG_HMAC_OPENSSL != 0 // not a boolean
    log_debug("tsig_hmac_init(%p, %p, %i, %i)", t, key, len, algorithm);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, key, len, 32);
#endif
    
    const EVP_MD *evp_md = hmac_get_EVP_MD(algorithm);
    
    if(evp_md != NULL)
    {    
        HMAC_CTX *hmac = hmac_openssl_hmac(t);

        if(hmac != NULL)
        {
            int ret;
#if SSL_API_LT_100
            ret = HMAC_Init(hmac, key, len, evp_md);
#else
            ret = HMAC_Init_ex(hmac, key, len, evp_md, NULL);
#endif
            if(ret == 1)
            {
                return SUCCESS;
            }
        }
    }

    return ERROR;
}

static int
hmac_openssl_update(tsig_hmac_t t, const void *data, size_t len)
{
#if LOG_HMAC_OPENSSL != 0 // not a boolean
    log_debug("tsig_hmac_update(%p, %p, %i)", t, data, len);
#endif
    
#if LOG_HMAC_OPENSSL >= 3
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, key, len, 32);
#elif LOG_HMAC_OPENSSL >= 2
    if(len <= 64)
    {
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, data, len, 32);
    }
    else
    {
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, data, 32, 32);
        log_debug("...");
        const u8 *data_byte = (const u8*)data;
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, &data_byte[len - 32], 32, 32);
    }
#endif
    
#if SSL_API_LT_100
    HMAC_Update(hmac_openssl_hmac(t), (const unsigned char*)data, len);
    return 1;
#else
    int ret = HMAC_Update(hmac_openssl_hmac(t), (const unsigned char*)data, len);
    return ret;
#endif
}

static int
hmac_openssl_final(tsig_hmac_t t, void *out_data, unsigned int *out_len)
{
#if SSL_API_LT_100
    HMAC_Final(hmac_openssl_hmac(t), (unsigned char*)out_data, out_len);
    
#if LOG_HMAC_OPENSSL != 0 // not a boolean
    log_debug("tsig_hmac_final(%p, %p, %i)", t, out_data, *out_len);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, out_data, *out_len, 32);
#endif
    
    return 1;
#else
    int ret = HMAC_Final(hmac_openssl_hmac(t), (unsigned char*)out_data, out_len);
    
#if LOG_HMAC_OPENSSL != 0 // not a boolean
    log_debug("tsig_hmac_final(%p, %p, %i)", t, out_data, *out_len);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, out_data, *out_len, 32);
#endif
    
    return ret;
#endif
}

static const struct hmac_vtbl hmac_openssl_vtbl =
{
    hmac_openssl_update,
    hmac_openssl_final,
    hmac_openssl_reset,
    hmac_openssl_init,
    hmac_openssl_free
};

tsig_hmac_t
tsig_hmac_allocate()
{
    hmac_openssl_t hmac;
    ZALLOC_OBJECT_OR_DIE(hmac, struct hmac_openssl_t, HMACCTX_TAG);
    hmac->vtbl = &hmac_openssl_vtbl;
#if SSL_API_LT_110 // ie: 0.9.x
    HMAC_CTX_init(&hmac->hmac);
#else
    hmac->hmac = HMAC_CTX_new();
#endif
    
    return (tsig_hmac_t)hmac;
}

/** @} */

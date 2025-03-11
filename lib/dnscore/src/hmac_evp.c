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
 * @defgroup hmac
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include "dnscore/zalloc.h"
#include "dnscore/hmac.h"
#include "dnscore/logger.h"
#include "dnscore/openssl.h"

#include <openssl/hmac.h>

#ifndef SSL_API
#error "SSL_API not defined"
#endif

#if SSL_API_LT_300
#error "This file is meant to be built for OpenSSL >= 3.0"
#endif

#define LOG_HMAC_OPENSSL 0 // 1 2 3

struct hmac_evp_t
{
    const struct hmac_vtbl *vtbl;
    EVP_MAC_CTX            *hmac;
};

typedef struct hmac_evp_t *hmac_evp_t;

static EVP_MAC_CTX        *hmac_evp_hmac(tsig_hmac_t hmac) { return ((hmac_evp_t)hmac)->hmac; }

static void                hmac_evp_hmac_set(tsig_hmac_t hmac, EVP_MAC_CTX *evp_mac_ctx) { ((hmac_evp_t)hmac)->hmac = evp_mac_ctx; }

static const char         *hmac_evp_get_algorithm_name(uint8_t algorithm)
{
    switch(algorithm)
    {
#ifndef OPENSSL_NO_MD5
        case HMAC_MD5:
            return "MD5";
#endif
#ifndef OPENSSL_NO_SHA
        case HMAC_SHA1:
            return "SHA1";
#endif
#ifndef OPENSSL_NO_SHA256
        case HMAC_SHA224:
            return "SHA224";
        case HMAC_SHA256:
            return "SHA256";
#endif
#ifndef OPENSSL_NO_SHA512
        case HMAC_SHA384:
            return "SHA384";
        case HMAC_SHA512:
            return "SHA512";
#endif
        default:
            return NULL;
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

static void hmac_evp_free(tsig_hmac_t t)
{
    hmac_evp_t hmac_evp = (hmac_evp_t)t;
    if(hmac_evp->hmac != NULL)
    {
        EVP_MAC_CTX_free(hmac_evp->hmac);
    }
    ZFREE_OBJECT(hmac_evp);
}

static void hmac_evp_reset(tsig_hmac_t t)
{
    EVP_MAC_CTX *hmac = hmac_evp_hmac(t);
    EVP_MAC_CTX_free(hmac);
    hmac_evp_hmac_set(t, NULL);
}

static ya_result hmac_evp_init(tsig_hmac_t t, const void *key, int key_len, uint8_t algorithm)
{
#if LOG_HMAC_OPENSSL != 0 // not a boolean
    log_debug("tsig_hmac_init(%p, %p, %i, %i)", t, key, len, algorithm);
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, key, len, 32);
#endif

    const char *algorithm_name = hmac_evp_get_algorithm_name(algorithm);
    if(algorithm_name == NULL)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    if(hmac_evp_hmac(t) != NULL)
    {
        return INVALID_STATE_ERROR;
    }

    EVP_MAC *evp_mac;
    evp_mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if(evp_mac != NULL)
    {
        EVP_MAC_CTX *evp_mac_ctx = EVP_MAC_CTX_new(evp_mac);
        EVP_MAC_free(evp_mac);
        if(evp_mac_ctx != NULL)
        {
            OSSL_PARAM params[2] = {OSSL_PARAM_utf8_string("digest", (char *)algorithm_name, 0), OSSL_PARAM_END};
            if(EVP_MAC_init(evp_mac_ctx, key, key_len, params) > 0)
            {
                hmac_evp_hmac_set(t, evp_mac_ctx);
                return SUCCESS;
            }
            EVP_MAC_CTX_free(evp_mac_ctx);
        }
    }

    return ERROR;
}

static int hmac_evp_update(tsig_hmac_t t, const void *data, size_t len)
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
        const uint8_t *data_byte = (const uint8_t *)data;
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG, &data_byte[len - 32], 32, 32);
    }
#endif
    if(EVP_MAC_update(hmac_evp_hmac(t), (const unsigned char *)data, len) > 0)
    {
        return SUCCESS;
    }
    else
    {
        return ERROR;
    }
}

static int hmac_evp_final(tsig_hmac_t t, void *out_data, unsigned int *out_len)
{
    size_t outl = 0;
    if(EVP_MAC_final(hmac_evp_hmac(t), out_data, &outl, *out_len) > 0)
    {
        *out_len = outl;
        return outl;
    }
    else
    {
        crypto_openssl_error();
        return ERROR;
    }
}

static const struct hmac_vtbl hmac_evp_vtbl = {hmac_evp_update, hmac_evp_final, hmac_evp_reset, hmac_evp_init, hmac_evp_free};

/**
 * Allocates and initialises a tsig_hmac_t
 */

tsig_hmac_t tsig_hmac_allocate()
{
    hmac_evp_t hmac;
    ZALLOC_OBJECT_OR_DIE(hmac, struct hmac_evp_t, HMACCTX_TAG);
    hmac->vtbl = &hmac_evp_vtbl;
    hmac->hmac = NULL;

    return (tsig_hmac_t)hmac;
}

/** @} */

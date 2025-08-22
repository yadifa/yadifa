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
 * @defgroup debug Debug functions
 * @ingroup dnscore
 * @brief Crypto setup functions.
 *
 *  Defi
 *
 * @{
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"
#include "dnscore/crypto.h"
#include "dnscore/logger.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "dnscore/openssl.h"

#if DNSCORE_HAS_OQS_SUPPORT
#include <oqs/oqs.h>
#endif

extern logger_handle_t *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#ifdef LIBRESSL_VERSION_NUMBER
void ENGINE_load_openssl(void) {}
void ENGINE_cleanup(void) {}
int  SSL_library_init(void) { return 1; }
void SSL_load_error_strings(void) {}
void ERR_free_strings(void) {}
void EVP_cleanup(void) {}
void CRYPTO_cleanup_all_ex_data(void) {}
#endif

/*
#ifndef SSL_API
#error "SSL_API not defined"
#endif
*/

ya_result crypto_init()
{
    /* Init openssl */

#if SSL_API_LT_110
    ENGINE_load_openssl();
#endif

    SSL_library_init();
    SSL_load_error_strings();

#if SSL_API_LT_300
    ENGINE_load_builtin_engines();
#endif

#if SSL_API_LT_110
    SSL_load_error_strings();

    ssl_mutex_count = CRYPTO_num_locks();

    MALLOC_OR_DIE(mutex_t *, ssl_mutex, ssl_mutex_count * sizeof(mutex_t), ZDB_SSLMUTEX_TAG);

    int i;

    for(i = 0; i < ssl_mutex_count; i++)
    {
        mutex_init(&ssl_mutex[i]);
    }

    CRYPTO_set_id_callback(ssl_thread_id);
    CRYPTO_set_locking_callback(ssl_lock);
#endif

#if DNSCORE_HAS_OQS_SUPPORT
    OQS_init();
#endif

    return SUCCESS;
}

void crypto_finalise()
{

#if SSL_API_LT_110
    CONF_modules_free();
    ENGINE_cleanup();
    CONF_modules_unload(1);
#endif
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    // sk_free(SSL_COMP_get_compression_methods());

#if SSL_API_LT_110
    ERR_remove_state(0);

    /* Init openssl */

    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);

    int i;

    for(i = 0; i < ssl_mutex_count; i++)
    {
        mutex_destroy(&ssl_mutex[i]);
    }

    ssl_mutex_count = 0;

    free(ssl_mutex);
#endif

#if SSL_API_LT_110
    ENGINE_cleanup();
#endif
}

// SSL_ERROR_WANT_CLIENT_HELLO_CB
#if SSL_API_LT_300
#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
#define YA_SSL_ERROR_TEXT_LIST_SIZE (SSL_ERROR_WANT_CLIENT_HELLO_CB + 1)
#elif defined(SSL_ERROR_WANT_ACCEPT)
#define YA_SSL_ERROR_TEXT_LIST_SIZE (SSL_ERROR_WANT_ACCEPT + 1)
#endif
#else
#define YA_SSL_ERROR_TEXT_LIST_SIZE (SSL_ERROR_WANT_RETRY_VERIFY + 1)
#endif

#if !DNSCORE_HAS_LOGGING_DISABLED
static const char *ya_ssl_error_text_list[13] = {"SSL_ERROR_NONE",
                                                 "SSL_ERROR_SSL",
                                                 "SSL_ERROR_WANT_READ",
                                                 "SSL_ERROR_WANT_WRITE",
                                                 "SSL_ERROR_WANT_X509_LOOKUP",
                                                 "SSL_ERROR_SYSCALL",
                                                 "SSL_ERROR_ZERO_RETURN",
                                                 "SSL_ERROR_WANT_CONNECT",
                                                 "SSL_ERROR_WANT_ACCEPT",
                                                 "SSL_ERROR_WANT_ASYNC",
                                                 "SSL_ERROR_WANT_ASYNC_JOB",
                                                 "SSL_ERROR_WANT_CLIENT_HELLO_CB",
#if SSL_API_GE_300
                                                 "SSL_ERROR_WANT_RETRY_VERIFY"
#endif
};
#endif

void crypto_ssl_error(void *ssl_, int n)
{
    SSL *ssl = (SSL *)ssl_;
    int  code = SSL_get_error(ssl, n);
    int  err = 0;
    if(code == SSL_ERROR_SYSCALL)
    {
        err = errno;
    }

#if !DNSCORE_HAS_LOGGING_DISABLED
    const char *code_text = "?";
    if((code >= 0) && (code < YA_SSL_ERROR_TEXT_LIST_SIZE))
    {
        code_text = ya_ssl_error_text_list[code];
    }
#endif

    if(err == 0)
    {
        log_err("ssl: SSL_get_error(%p, %x) = %x %s", ssl, n, code, code_text);
    }
    else
    {
        log_err("ssl: SSL_get_error(%p, %x) = %x %s %r", ssl, n, code, code_text, err);
    }

    if(code == SSL_ERROR_SSL)
    {
        crypto_openssl_error();
    }
}

ya_result crypto_openssl_error()
{
    unsigned long ssl_err = ERR_get_error();

    if(ssl_err == 0)
    {
        return SUCCESS;
    }

#if !DNSCORE_HAS_LOGGING_DISABLED
    LOGGER_EARLY_CULL_PREFIX(MSG_ERR)
    {
        char buffer[256];
        ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
        log_err("ssl: %i, %s", ssl_err, buffer);

        unsigned long next_ssl_err;
        while((next_ssl_err = ERR_get_error()) != 0)
        {
            ERR_error_string_n(next_ssl_err, buffer, sizeof(buffer));
            log_err("ssl: %i, %s", next_ssl_err, buffer);
        }

        ERR_clear_error();
    }
#else
    char buffer[256];
    ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
    fprintf(stderr, "ssl: %i, %s", ssl_err, buffer);

    unsigned long next_ssl_err;
    while((next_ssl_err = ERR_get_error()) != 0)
    {
        ERR_error_string_n(next_ssl_err, buffer, sizeof(buffer));
        fprintf(stderr, "ssl: %i, %s", next_ssl_err, buffer);
    }
    fflush(stderr);
    ERR_clear_error();
#endif
#if DEBUG
    else
    {
        char buffer[256];
        ERR_error_string_n(ssl_err, buffer, sizeof(buffer));
        formatln("ssl: %i, %s", ssl_err, buffer);

        unsigned long next_ssl_err;
        while((next_ssl_err = ERR_get_error()) != 0)
        {
            ERR_error_string_n(next_ssl_err, buffer, sizeof(buffer));
            formatln("ssl: %i, %s", next_ssl_err, buffer);
        }

        ERR_clear_error();
    }
#endif

    return SSL_ERROR_CODE(ssl_err);
}

static const char  g_preferred_ciphers_default[] = "DEFAULT";

static const char *g_preferred_ciphers = g_preferred_ciphers_default;

void               crypto_preferred_ciphers_set(const char *preferred_ciphers)
{
    if(g_preferred_ciphers != g_preferred_ciphers_default)
    {
        free((char *)g_preferred_ciphers);
    }
    if(preferred_ciphers != NULL)
    {
        g_preferred_ciphers = strdup(preferred_ciphers);
    }
    else
    {
        g_preferred_ciphers = g_preferred_ciphers_default;
    }
}

const char *crypto_preferred_ciphers() { return g_preferred_ciphers; }

/** @} */

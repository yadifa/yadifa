/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#define __TCP_MANAGER_CHANNEL_CONTEXT_SSL_C__ 1

#include "dnscore/dnscore_config.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "dnscore/logger.h"
#include "dnscore/crypto.h"
#include "dnscore/tcp_manager2.h"

static const char         alpn_dot_protocol[4] = {3, 'd', 'o', 't'}; // ALPN
static const unsigned int alpn_dot_protocol_size = sizeof(alpn_dot_protocol);

// https://www.openssl.org/docs/man1.1.1/man3/BIO_s_mem.html
// https://stackoverflow.com/questions/51632606/why-does-ssl-set-bio-takes-two-pointers-to-bio-as-parameters-openssl-bio-s-me

static ya_result tcp_manager_channel_message_tls_read(struct tcp_manager_channel_s *tmc, dns_message_t *mesg)
{
    SSL     *ssl_socket = tmc->ssl_socket;

    int      n;
    uint16_t len;
    uint32_t len_max = dns_message_get_buffer_size_max(mesg);
    uint8_t *buffer = dns_message_get_buffer(mesg);
    mutex_lock(&tmc->rd_mtx);
    if((n = SSL_read(ssl_socket, &len, 2)) == 2)
    {
        len = ntohs(len);
        if(len <= len_max)
        {
            n = SSL_read(ssl_socket, buffer, len);
            dns_message_set_size(mesg, n);
        }
        else
        {
            int  m;
            char tmp[512];
            n = SSL_read(ssl_socket, buffer, len_max);
            dns_message_set_size(mesg, n);
            int dt = len - n;
            while(dt > (int)sizeof(buffer))
            {
                m = SSL_read(ssl_socket, tmp, sizeof(buffer));
                dt -= m;
            }
            m = readfully(tmc->sock, tmp, dt);
        }
    }
    mutex_unlock(&tmc->rd_mtx);
    return n;
}

static ya_result tcp_manager_channel_message_tls_write(struct tcp_manager_channel_s *tmc, dns_message_t *mesg)
{
    SSL     *ssl_socket = tmc->ssl_socket;

    uint16_t size = dns_message_get_size(mesg);
    uint16_t size_ne = htons(size);

    SSL_write(ssl_socket, &size_ne, 2);
    SSL_write(ssl_socket, dns_message_get_buffer(mesg), size);

    return size;
}

static ya_result tcp_manager_channel_message_tls_close(struct tcp_manager_channel_s *tmc)
{
    SSL_shutdown(tmc->ssl_socket);
    tmc->ssl_socket = NULL;
#if DEBUG
    tmc->ssl_socket = (SSL *)(intptr_t)0xfefefefefefefefeULL;
#endif
    return SUCCESS;
}

struct tcp_manager_channel_message_vtbl tcp_manager_channel_message_tls_vtbl = {tcp_manager_channel_message_tls_read, tcp_manager_channel_message_tls_write, tcp_manager_channel_message_tls_close};

int                                     tcp_manager_socket_context_ssl_close(tcp_manager_channel_t *tmc)
{
    SSL *ssl_socket = tmc->ssl_socket;
    SSL_free(ssl_socket);
    return 0;
}

static int tcp_manager_channel_ssl_context_new_instance_alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl;
    (void)arg;

    if((out != NULL) && (outlen != NULL) && (in != NULL) && (inlen == alpn_dot_protocol_size) && (memcmp(in, alpn_dot_protocol, alpn_dot_protocol_size) == 0))
    {
        *out = (const unsigned char *)&alpn_dot_protocol[1];
        *outlen = (unsigned char)alpn_dot_protocol[0];
        return SSL_TLSEXT_ERR_OK;
    }
    else
    {
        return SSL_TLSEXT_ERR_NOACK;
    }
}

SSL_CTX *tcp_manager_channel_ssl_context_new(const char *cert_pem, const char *key_pem)
{
    /******************************************************************************************************************
     *
     * DNS over TLS
     *
     * https://www.rfc-editor.org/rfc/rfc7858
     *
     * We have accepted a connection : now handshake
     */

    if((cert_pem == NULL) || (key_pem == NULL))
    {
        return NULL;
    }

    const SSL_METHOD *ssl_method = TLS_server_method();
    SSL_CTX          *ssl_ctx = SSL_CTX_new(ssl_method);
    if(ssl_ctx == NULL)
    {
        return NULL;
    }

    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ssl_ctx, flags);

    if(SSL_CTX_use_certificate_file(ssl_ctx, cert_pem, SSL_FILETYPE_PEM) <= 0)
    {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if(SSL_CTX_use_PrivateKey_file(ssl_ctx, key_pem, SSL_FILETYPE_PEM) <= 0)
    {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    // doesn't work
    // SSL_CTX_set_alpn_protos(ssl_ctx, alpn_dot_protocol, alpn_dot_protocol_size);

    SSL_CTX_set_alpn_select_cb(ssl_ctx, tcp_manager_channel_ssl_context_new_instance_alpn_cb, NULL);

    return ssl_ctx;
}

void tcp_manager_channel_ssl_context_delete(SSL_CTX *ssl_ctx) { SSL_CTX_free(ssl_ctx); }

SSL *SSL_new_tcp_manager_channel_ssl(SSL_CTX *ssl_ctx, tcp_manager_channel_t *tmc)
{
    SSL *ssl = SSL_new(ssl_ctx);

    int  ret = SSL_set_cipher_list(ssl, crypto_preferred_ciphers());
    if(ret <= 0)
    {
        SSL_free(ssl);
        return NULL;
    }

    BIO *b = BIO_new_socket(tcp_manager_channel_socket(tmc), 0);
    SSL_set_bio(ssl, b, b);

    return ssl;
}

int tcp_manager_channel_ssl_handshake(tcp_manager_channel_t *tmc, SSL_CTX *ssl_ctx)
{
    int  ssl_err;
    SSL *ssl_socket = SSL_new_tcp_manager_channel_ssl(ssl_ctx, tmc);
    if(ssl_socket != NULL)
    {
        if((ssl_err = SSL_accept(ssl_socket)) > 0)
        {
            // change this socket context to SSL
            tmc->ssl_socket = ssl_socket;
            tmc->vtbl = &tcp_manager_channel_message_tls_vtbl;
            return SUCCESS;
        }
        else
        {
            crypto_openssl_error();
            ya_result ret = SSL_ERROR_CODE(ERR_get_error());
            SSL_free(ssl_socket);
            return ret;
        }
    }
    else
    {
        return INVALID_STATE_ERROR;
    }
}

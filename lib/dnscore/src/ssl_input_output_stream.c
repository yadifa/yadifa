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
 * @defgroup streaming Streams
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"
#include <stdio.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "dnscore/zalloc.h"
#include "dnscore/ssl_input_output_stream.h"
#include "dnscore/file_input_stream.h"
#include "dnscore/crypto.h"

#define SSL_INPUT_STREAM_TAG 0x5254534e494c5353 /* SSLINSTR */

struct ssl_input_output_stream_data
{
    input_stream_t  in_filtered;
    output_stream_t out_filtered;
    SSL_CTX        *ctx;
    SSL            *ssl;
    atomic_int      rc;
};

typedef struct ssl_input_output_stream_data ssl_input_output_stream_data;

static ya_result                            ssl_input_stream_read(input_stream_t *stream, void *buffer, uint32_t len)
{
    ssl_input_output_stream_data *data = (ssl_input_output_stream_data *)stream->data;
    int                           n = SSL_read(data->ssl, buffer, len);
    if(n <= 0)
    {
        crypto_ssl_error(data->ssl, n);
        if(n < 0)
        {
            n = ERROR;
        }
    }
    return n;
}

static ya_result ssl_output_stream_write(output_stream_t *stream, const uint8_t *buffer, uint32_t len)
{
    ssl_input_output_stream_data *data = (ssl_input_output_stream_data *)stream->data;
    int                           n = SSL_write(data->ssl, buffer, len);
    if(n <= 0)
    {
        crypto_ssl_error(data->ssl, n);
        if(n < 0)
        {
            n = ERROR;
        }
    }
    return n;
}

static ya_result ssl_output_stream_flush(output_stream_t *stream)
{
    (void)stream;
    return SUCCESS;
}

static void ssl_input_stream_data_release(ssl_input_output_stream_data *data)
{
    if(--data->rc == 0)
    {
        SSL_free(data->ssl);
        SSL_CTX_free(data->ctx);
        ZFREE_OBJECT(data);
    }
}

static void ssl_input_stream_close(input_stream_t *stream)
{
    ssl_input_output_stream_data *data = (ssl_input_output_stream_data *)stream->data;
    input_stream_close(&data->in_filtered);
    input_stream_set_void(stream);
    ssl_input_stream_data_release(data);
}

static void ssl_output_stream_close(output_stream_t *stream)
{
    ssl_input_output_stream_data *data = (ssl_input_output_stream_data *)stream->data;
    output_stream_close(&data->out_filtered);
    output_stream_set_void(stream);
    ssl_input_stream_data_release(data);
}

static ya_result ssl_input_stream_skip(input_stream_t *stream, uint32_t len)
{
    ssl_input_output_stream_data *data = (ssl_input_output_stream_data *)stream->data;
    uint32_t                      req_len = len;
    int                           n;
    uint8_t                       buffer[1024];

    while(len > sizeof(buffer))
    {
        n = SSL_read(data->ssl, buffer, 1024);
        if(n <= 0)
        {
            if(n == 0)
            {
                return req_len - len;
            }
            return ERROR;
        }

        len -= n;
    }

    n = SSL_read(data->ssl, buffer, len);

    if(n >= 0)
    {
        len -= n;

        return req_len - len;
    }

    return ERROR;
}

static const input_stream_vtbl  ssl_input_stream_vtbl = {ssl_input_stream_read, ssl_input_stream_skip, ssl_input_stream_close, "ssl_input_stream"};

static const output_stream_vtbl ssl_output_stream_vtbl = {ssl_output_stream_write, ssl_output_stream_flush, ssl_output_stream_close, "ssl_output_stream"};

#if UNUSED

static const char         alpn_dot_protocol[4] = {3, 'd', 'o', 't'};
static const unsigned int alpn_dot_protocol_size = sizeof(alpn_dot_protocol);

static int                ssl_input_stream_ssl_context_new_instance_alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
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
#endif

/**
 * Adds the SSL protocol with the 3dot ALPN on an open TCP connection.
 *
 * @param in_stream the SSL input stream
 * @param in_filtered the TCP input stream
 * @param out_stream the SSL output stream
 * @param out_filtered the TCP output stream
 * @param cert_pem the X509 certificate to use
 * @param key_pem the key of the X509 certificate
 *
 */

ya_result ssl_input_output_stream_init(input_stream_t *in_stream, input_stream_t *in_filtered, output_stream_t *out_stream, output_stream_t *out_filtered, const char *cert_pem, const char *key_pem)
{
    ssl_input_output_stream_data *data;
    int                           ret;

    if((in_stream == NULL) || (in_filtered == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(!is_fd_input_stream(in_filtered))
    {
        return INVALID_ARGUMENT_ERROR;
    }

    yassert(in_filtered->vtbl != NULL);

    /*
        if((cert_pem == NULL) || (key_pem == NULL))
        {
            return NULL;
        }
    */
    const SSL_METHOD *ssl_method = TLS_client_method();
    // const SSL_METHOD *ssl_method = SSLv23_method();
    SSL_CTX *ssl_ctx = SSL_CTX_new(ssl_method);
    if(ssl_ctx == NULL)
    {
        crypto_openssl_error();
        return INVALID_STATE_ERROR;
    }

    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ssl_ctx, flags);

    if((cert_pem != NULL) && (key_pem != NULL))
    {
        if(SSL_CTX_use_certificate_file(ssl_ctx, cert_pem, SSL_FILETYPE_PEM) <= 0)
        {
            SSL_CTX_free(ssl_ctx);
            return INVALID_STATE_ERROR;
        }

        if(SSL_CTX_use_PrivateKey_file(ssl_ctx, key_pem, SSL_FILETYPE_PEM) <= 0)
        {
            SSL_CTX_free(ssl_ctx);
            return INVALID_STATE_ERROR;
        }
    }

    static const unsigned char alpn_dot_protocol[4] = {3, 'd', 'o', 't'}; // ALPN
    static const unsigned int  alpn_dot_protocol_size = sizeof(alpn_dot_protocol);

    /*ret = */ SSL_CTX_set_alpn_protos(ssl_ctx, alpn_dot_protocol, alpn_dot_protocol_size);

    int  fd = fd_input_stream_get_filedescriptor(in_filtered);

    SSL *ssl = SSL_new(ssl_ctx); /* create new SSL connection state */

    ret = SSL_set_cipher_list(ssl, crypto_preferred_ciphers());
    if(ret <= 0)
    {
        crypto_openssl_error();
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        return INVALID_STATE_ERROR;
    }

    SSL_set_fd(ssl, fd); /* attach the socket descriptor */
    ret = SSL_connect(ssl);

    if(ret <= 0)
    {
        crypto_openssl_error();
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        return INVALID_STATE_ERROR;
    }

    ret = SSL_do_handshake(ssl);

    if(ret <= 0)
    {
        crypto_openssl_error();
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        return INVALID_STATE_ERROR;
    }

    ZALLOC_OBJECT_OR_DIE(data, ssl_input_output_stream_data, SSL_INPUT_STREAM_TAG);

    // SSL_CTX_set_alpn_select_cb(ssl_ctx, ssl_input_stream_ssl_context_new_instance_alpn_cb, NULL);

    data->in_filtered.data = in_filtered->data;
    data->in_filtered.vtbl = in_filtered->vtbl;

    data->out_filtered.data = out_filtered->data;
    data->out_filtered.vtbl = out_filtered->vtbl;

    data->ctx = ssl_ctx;
    data->ssl = ssl;
    data->rc = 2;

    in_stream->data = data;
    in_stream->vtbl = &ssl_input_stream_vtbl;

    out_stream->data = data;
    out_stream->vtbl = &ssl_output_stream_vtbl;

    return SUCCESS;
}

input_stream_t *ssl_input_stream_get_filtered(input_stream_t *bos)
{
    ssl_input_output_stream_data *data = (ssl_input_output_stream_data *)bos->data;

    return &data->in_filtered;
}

/**
 * Returns true iff the input stream is a buffer input stream
 *
 * @param bos
 * @return
 */

bool is_ssl_input_stream(input_stream_t *bos) { return bos->vtbl == &ssl_input_stream_vtbl; }

/** @} */

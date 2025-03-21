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
 * @defgroup digest Cryptographic digest functions.
 * @ingroup dnscore
 * @brief Cryptographic digest functions.
 *
 * Cryptographic digest functions: SHA0, SHA1, SHA256, SHA384 SHA512
 *
 * They are very simple and self-explanatory wrappers around the cryptographic
 * library (currently : openssl)
 * Hence the small specific C-files are not documented.
 *
 * Adding more would be trivial but these are the only ones needed for DNS at
 * this point.
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <dnscore/sys_types.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/openssl.h>

#define DIGEST_MD5_USE_INTERNAL 1

struct digest_md5_internal_ctx_s
{
    uint32_t h0, h1, h2, h3;
    uint8_t  size;
    uint8_t  finalised;
    uint32_t total_size;
    uint8_t  buffer[64];
};

typedef struct digest_md5_internal_ctx_s digest_md5_internal_ctx_t;

#define DIGEST_BUFFER_SIZE 128 // should probably be EVP_MAX_MD_SIZE

struct digest_s;

typedef int32_t digest_update_method(struct digest_s *, const void *, uint32_t);
typedef int32_t digest_final_method(struct digest_s *); // finishes computing the digest
typedef int32_t digest_final_copy_bytes_method(struct digest_s *, void *, uint32_t);
typedef int32_t digest_get_size_method(struct digest_s *);
typedef int32_t digest_get_digest_method(struct digest_s *, void **);
typedef void    digest_finalise_method(struct digest_s *); // destroys the object, frees resources

struct digest_vtbl
{
    digest_update_method           *update;
    digest_final_method            *final;
    digest_final_copy_bytes_method *final_copy_bytes;
    digest_get_size_method         *get_size;
    digest_get_digest_method       *get_digest;
    digest_finalise_method         *finalise;
    const char                     *__class__;
};

struct digest_rawdata_ctx
{
    bytearray_output_stream_context baos_ctx;
    output_stream_t                 baos; // accumulates bytes (EDDSA)    // total: about 11 pointers
    uint8_t                         data[sizeof(SHA512_CTX) - sizeof(output_stream_t) - sizeof(bytearray_output_stream_context)];
};

#define DIGEST_TAG 0x545345474944

struct digest_s
{
    const struct digest_vtbl *vtbl;
    union
    {
#if SSL_API_LT_300
        MD5_CTX    md5;
        SHA_CTX    sha0;
        SHA_CTX    sha1;
        SHA256_CTX sha256;
        SHA512_CTX sha384; /// @note 20160202 edf -- there is no SHA384_CTX, SHA512_CTX must be used
        SHA512_CTX sha512;
#else
        EVP_MD_CTX *evp_md_ctx;
#endif
        digest_md5_internal_ctx_t md5_internal;
        struct digest_rawdata_ctx rawdata; // to handle eddsa
    } ctx;

    uint8_t digest[DIGEST_BUFFER_SIZE]; // used so the caller does not need to keep a copy of the digest.
};

typedef struct digest_s digest_t;

#define digest_class(is_)                                    ((is_)->vtbl)
#define digest_class_name(is_)                               ((is_)->vtbl->__class__)
#define digest_update(ctx_, buffer_, len_)                   (ctx_)->vtbl->update(ctx_, buffer_, len_)
#define digest_final(ctx_)                                   (ctx_)->vtbl->final(ctx_)
#define digest_final_copy_bytes(ctx_, buffer_, buffer_size_) (ctx_)->vtbl->final_copy_bytes((ctx_), (buffer_), (buffer_size_))
#define digest_get_size(ctx_)                                (ctx_)->vtbl->get_size(ctx_)
#define digest_get_digest(ctx_, ptr_)                        (ctx_)->vtbl->get_digest((ctx_), (ptr_))
#define digest_finalise(ctx_)                                (ctx_)->vtbl->finalise(ctx_)

static inline void digest_copy_bytes(digest_t *ctx, void *buffer)
{
    void   *digest_bytes;
    int32_t size = digest_get_digest(ctx, &digest_bytes);
    memcpy(buffer, digest_bytes, size);
}

static inline void *digest_get_digest_ptr(digest_t *ctx)
{
    void *digest_bytes;
    digest_get_digest(ctx, &digest_bytes);
    return digest_bytes;
}

void digest_md5_init(digest_t *ctx);

#if !DIGEST_MD5_USE_INTERNAL
void digest_md5_init_internal(digest_t *ctx);
#endif

#ifndef OPENSSL_NO_SHA1
void digest_sha1_init(digest_t *ctx);
#endif

#ifndef OPENSSL_NO_SHA256
void digest_sha256_init(digest_t *ctx);
#endif

#ifndef OPENSSL_NO_SHA512
void digest_sha384_init(digest_t *ctx);
void digest_sha512_init(digest_t *ctx);
#endif

void digest_rawdata_init(digest_t *ctx);

#ifndef OPENSSL_NO_SHA0
void digest_sha0_init(digest_t *ctx);
#endif

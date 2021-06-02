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

/** @defgroup digest Cryptographic digest functions.
 *  @ingroup dnscore
 *  @brief Cryptographic digest functions.
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
 */
#ifndef _DIGEST_H
#define	_DIGEST_H

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <dnscore/sys_types.h>
#include <dnscore/bytearray_output_stream.h>

#define DIGEST_BUFFER_SIZE 128

struct digest_s;

typedef s32 digest_update_method(struct digest_s*,const void*, u32);
typedef s32 digest_final_method(struct digest_s*);
typedef s32 digest_sha1_final_copy_bytes_method(struct digest_s*, void*, u32);
typedef s32 digest_get_size_method(struct digest_s*);
typedef s32 digest_get_digest_method(struct digest_s*, void**);

struct digest_vtbl
{
    digest_update_method* update;
    digest_final_method* final;
    digest_sha1_final_copy_bytes_method* final_copy_bytes;
    digest_get_size_method* get_size;
    digest_get_digest_method* get_digest;
    const char * __class__;
};

struct digest_rawdata_ctx
{
    bytearray_output_stream_context baos_ctx;
    output_stream baos; // accumulates bytes (EDDSA)    // total: about 11 pointers
    u8 data[sizeof(SHA512_CTX) - sizeof(output_stream) - sizeof(bytearray_output_stream_context)];
};

struct digest_s
{
    const struct digest_vtbl *vtbl;
    union
    {
        SHA_CTX sha0;
        SHA_CTX sha1;
        SHA256_CTX sha256;
        SHA512_CTX sha384; /// @note 20160202 edf -- there is no SHA384_CTX, SHA512_CTX must be used
        SHA512_CTX sha512;
        struct digest_rawdata_ctx rawdata;
    } ctx;

    u8 digest[DIGEST_BUFFER_SIZE];  // used so the caller does not need to keep a copy of the digest.
};

typedef struct digest_s digest_s;

#define digest_class(is_) ((is_)->vtbl)
#define digest_class_name(is_) ((is_)->vtbl->__class__)
#define digest_update(ctx_,buffer_,len_) (ctx_)->vtbl->update(ctx_,buffer_,len_)
#define digest_final(ctx_) (ctx_)->vtbl->final(ctx_)
#define digest_final_copy_bytes(ctx_,buffer_,buffer_size_) (ctx_)->vtbl->final_copy_bytes((ctx_),(buffer_),(buffer_size_))
#define digest_get_size(ctx_) (ctx_)->vtbl->get_size(ctx_)
#define digest_get_digest(ctx_,ptr_) (ctx_)->vtbl->get_digest((ctx_),(ptr_))

static inline void digest_copy_bytes(digest_s *ctx, void *buffer)
{
    void *digest_bytes;
    s32 size = digest_get_digest(ctx, &digest_bytes);
    memcpy(buffer, digest_bytes, size);
}

static inline void* digest_get_digest_ptr(digest_s *ctx)
{
    void *digest_bytes;
    digest_get_digest(ctx, &digest_bytes);
    return digest_bytes;
}

#ifndef OPENSSL_NO_SHA1
void digest_sha1_init(digest_s *ctx);
#endif

#ifndef OPENSSL_NO_SHA256
void digest_sha256_init(digest_s *ctx);
#endif

#ifndef OPENSSL_NO_SHA512
void digest_sha384_init(digest_s *ctx);
void digest_sha512_init(digest_s *ctx);
#endif

void digest_rawdata_init(digest_s *ctx);

#ifndef OPENSSL_NO_SHA0
void digest_sha0_init(digest_s *ctx);
#endif

#endif // _DIGEST_H

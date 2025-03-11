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

#include "dnscore/dnscore_config.h"
#include "dnscore/digest.h"

static int32_t digest_evp_update(digest_t *ctx, const void *buffer, uint32_t size) { return EVP_DigestUpdate(ctx->ctx.evp_md_ctx, buffer, size) - 1; }

static int32_t digest_evp_final(digest_t *ctx)
{
    unsigned int digest_size = sizeof(ctx->digest);
    // note: the _ex variant doesn't reset the digest
    return EVP_DigestFinal_ex(ctx->ctx.evp_md_ctx, ctx->digest, &digest_size) - 1;
}

static int32_t digest_evp_get_size(digest_t *ctx)
{
    int ret = EVP_MD_CTX_get_size(ctx->ctx.evp_md_ctx);
    return ret;
}

static int32_t digest_evp_final_copy_bytes(digest_t *ctx, void *buffer, uint32_t size)
{
    if((int)size >= EVP_MD_CTX_get_size(ctx->ctx.evp_md_ctx))
    {
        unsigned int sizep = 0;
        // note: the _ex variant doesn't reset the digest
        if(EVP_DigestFinal_ex(ctx->ctx.evp_md_ctx, buffer, &sizep) > 0)
        {
            return sizep;
        }
        else
        {
            return ERROR;
        }
    }

    return BUFFER_WOULD_OVERFLOW;
}

static int32_t digest_evp_get_digest(digest_t *ctx, void **ptr)
{
    *ptr = &ctx->digest[0];
    return digest_evp_get_size(ctx);
}

static void digest_evp_finalise(digest_t *ctx)
{
    EVP_MD_CTX_free(ctx->ctx.evp_md_ctx);
    ctx->ctx.evp_md_ctx = NULL;
}

#if !DIGEST_MD5_USE_INTERNAL
static const struct digest_vtbl digest_md5_evp_vtbl = {digest_evp_update, digest_evp_final, digest_evp_final_copy_bytes, digest_evp_get_size, digest_evp_get_digest, digest_evp_finalise, "MD5"};
#endif

static const struct digest_vtbl digest_sha1_evp_vtbl = {digest_evp_update, digest_evp_final, digest_evp_final_copy_bytes, digest_evp_get_size, digest_evp_get_digest, digest_evp_finalise, "SHA1"};

static const struct digest_vtbl digest_sha256_evp_vtbl = {digest_evp_update, digest_evp_final, digest_evp_final_copy_bytes, digest_evp_get_size, digest_evp_get_digest, digest_evp_finalise, "SHA256"};

static const struct digest_vtbl digest_sha384_evp_vtbl = {digest_evp_update, digest_evp_final, digest_evp_final_copy_bytes, digest_evp_get_size, digest_evp_get_digest, digest_evp_finalise, "SHA384"};

static const struct digest_vtbl digest_sha512_evp_vtbl = {digest_evp_update, digest_evp_final, digest_evp_final_copy_bytes, digest_evp_get_size, digest_evp_get_digest, digest_evp_finalise, "SHA512"};

static void                     digest_evp_init(digest_t *ctx, const struct digest_vtbl *vtbl, int nid)
{
    ctx->vtbl = vtbl;
    const EVP_MD *digest = EVP_get_digestbynid(nid);
    ctx->ctx.evp_md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx->ctx.evp_md_ctx, digest, NULL);
}

#if !DIGEST_MD5_USE_INTERNAL
void digest_md5_init(digest_t *ctx) { digest_evp_init(ctx, &digest_md5_evp_vtbl, NID_md5); }
#endif

void digest_sha1_init(digest_t *ctx) { digest_evp_init(ctx, &digest_sha1_evp_vtbl, NID_sha1); }
void digest_sha256_init(digest_t *ctx) { digest_evp_init(ctx, &digest_sha256_evp_vtbl, NID_sha256); }

void digest_sha384_init(digest_t *ctx) { digest_evp_init(ctx, &digest_sha384_evp_vtbl, NID_sha384); }

void digest_sha512_init(digest_t *ctx) { digest_evp_init(ctx, &digest_sha512_evp_vtbl, NID_sha512); }

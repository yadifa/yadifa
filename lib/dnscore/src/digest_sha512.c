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

#ifndef OPENSSL_NO_SHA512

static int32_t digest_sha512_update(digest_t *ctx, const void *buffer, uint32_t size) { return SHA512_Update(&ctx->ctx.sha512, buffer, size) - 1; }

static int32_t digest_sha512_final(digest_t *ctx) { return SHA512_Final(ctx->digest, &ctx->ctx.sha512) - 1; }

static int32_t digest_sha512_final_copy_bytes(digest_t *ctx, void *buffer, uint32_t size)
{
    if(size >= SHA512_DIGEST_LENGTH)
    {
        if(SHA512_Final(buffer, &ctx->ctx.sha512) != 0)
        {
            return SHA512_DIGEST_LENGTH;
        }
        else
        {
            return ERROR;
        }
    }

    return BUFFER_WOULD_OVERFLOW;
}

static int32_t digest_sha512_get_size(digest_t *ctx)
{
    (void)ctx;

    return SHA512_DIGEST_LENGTH;
}

static int32_t digest_sha512_get_digest(digest_t *ctx, void **ptr)
{
    *ptr = &ctx->digest[0];

    return SHA512_DIGEST_LENGTH;
}

static void                     digest_sha512_finalise(struct digest_s *ctx) { (void)ctx; }

static const struct digest_vtbl sha512_vtbl = {digest_sha512_update, digest_sha512_final, digest_sha512_final_copy_bytes, digest_sha512_get_size, digest_sha512_get_digest, digest_sha512_finalise, "SHA512"};

void                            digest_sha512_init(digest_t *ctx)
{
    ctx->vtbl = &sha512_vtbl;
    SHA512_Init(&ctx->ctx.sha512);
}

#endif

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

static const uint8_t   s[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                                4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static const uint32_t  K[64] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                                0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                                0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

static inline uint32_t leftrotate(uint32_t v, uint8_t shift) { return (v << shift) | (v >> (32 - shift)); }

// M is 64 32 bits words
static void md5_chunk(digest_md5_internal_ctx_t *md5, const void *M_)
{
    const uint32_t *M = M_;

    uint32_t        a = md5->h0;
    uint32_t        b = md5->h1;
    uint32_t        c = md5->h2;
    uint32_t        d = md5->h3;

    uint32_t        i;
    uint32_t        F;
    uint32_t        g;

    for(i = 0; i < 16; ++i)
    {
        g = i;
        uint32_t Mg;
        Mg = M[g];
#if !DNSCORE_HAS_LITTLE_ENDIAN
        Mg = bswap_32(Mg);
#endif
        F = ((b & c) | ((~b) & d)) + a + K[i] + Mg;
        a = d;
        d = c;
        c = b;
        b += leftrotate(F, s[i]);
    }
    for(; i < 32; ++i)
    {
        g = (i * 5 + 1) & 15;
        uint32_t Mg;
        Mg = M[g];
#if !DNSCORE_HAS_LITTLE_ENDIAN
        Mg = bswap_32(Mg);
#endif
        F = ((d & b) | ((~d) & c)) + a + K[i] + Mg;
        a = d;
        d = c;
        c = b;
        b += leftrotate(F, s[i]);
    }
    for(; i < 48; ++i)
    {
        g = (i * 3 + 5) & 15;
        uint32_t Mg;
        Mg = M[g];
#if !DNSCORE_HAS_LITTLE_ENDIAN
        Mg = bswap_32(Mg);
#endif
        F = (b ^ c ^ d) + a + K[i] + Mg;
        a = d;
        d = c;
        c = b;
        b += leftrotate(F, s[i]);
    }
    for(; i < 64; ++i)
    {
        g = (i * 7) & 15;
        uint32_t Mg;
        Mg = M[g];
#if !DNSCORE_HAS_LITTLE_ENDIAN
        Mg = bswap_32(Mg);
#endif
        F = (c ^ (b | (~d))) + a + K[i] + Mg;
        a = d;
        d = c;
        c = b;
        b += leftrotate(F, s[i]);
    }
    md5->h0 += a;
    md5->h1 += b;
    md5->h2 += c;
    md5->h3 += d;
}

static int32_t digest_md5_update(digest_t *ctx, const void *buffer_, uint32_t size)
{
    digest_md5_internal_ctx_t *md5 = &ctx->ctx.md5_internal;
    const uint8_t             *buffer = buffer_;
    ctx->ctx.md5_internal.total_size += size;
    if(md5->size > 0)
    {
        // fill
        // chunk
        uint32_t space = sizeof(md5->buffer) - md5->size;
        uint32_t avail = MIN(space, size);
        memcpy(&md5->buffer[md5->size], buffer, avail);
        md5->size += avail;

        if(md5->size < sizeof(md5->size))
        {
            return SUCCESS;
        }

        // update the chunk
        md5_chunk(md5, md5->buffer);
        buffer += avail;
        size -= avail;
    }
    while(size > sizeof(md5->buffer))
    {
        md5_chunk(md5, md5->buffer);
        buffer += sizeof(md5->buffer);
        size -= sizeof(md5->buffer);
    }
    md5->size = size;
    memcpy(&md5->buffer[0], buffer, size);
    return SUCCESS;
}

static void digest_md5_pad(digest_md5_internal_ctx_t *md5)
{
    if(md5->finalised == 0)
    {
        md5->buffer[md5->size++] = 0x80;
        if(md5->size > sizeof(md5->buffer) - 8)
        {
            memset(&md5->buffer[md5->size], 0, sizeof(md5->buffer) - md5->size);
            md5_chunk(md5, md5->buffer);
            md5->size = 0;
        }
        memset(&md5->buffer[md5->size], 0, sizeof(md5->buffer) - 8 - md5->size);
        uint64_t sizeb = md5->total_size << 3;
#if !DNSCORE_HAS_LITTLE_ENDIAN
        sizeb = bswap_64(sizeb);
#endif
        SET_U64_AT(md5->buffer[sizeof(md5->buffer) - 8], sizeb);
        md5_chunk(md5, md5->buffer);
        md5->finalised = 1;
    }
}

static int32_t digest_md5_final(digest_t *ctx)
{
    // NOTE: md5->size is strictly smaller than sizeof(md5->buffer)
    digest_md5_internal_ctx_t *md5 = &ctx->ctx.md5_internal;
    digest_md5_pad(md5);
#if DNSCORE_HAS_LITTLE_ENDIAN
    SET_U32_AT(ctx->digest[0], md5->h0);
    SET_U32_AT(ctx->digest[4], md5->h1);
    SET_U32_AT(ctx->digest[8], md5->h2);
    SET_U32_AT(ctx->digest[12], md5->h3);
#else
    SET_U32_AT(ctx->digest[0], bswap_32(md5->h0));
    SET_U32_AT(ctx->digest[4], bswap_32(md5->h1));
    SET_U32_AT(ctx->digest[8], bswap_32(md5->h2));
    SET_U32_AT(ctx->digest[12], bswap_32(md5->h3));
#endif
    return SUCCESS;
}

static int32_t digest_md5_final_copy_bytes(digest_t *ctx, void *buffer_, uint32_t size)
{
    if(size >= MD5_DIGEST_LENGTH)
    {
        digest_md5_internal_ctx_t *md5 = &ctx->ctx.md5_internal;
        digest_md5_pad(md5);
        uint8_t *buffer = buffer_;
#if DNSCORE_HAS_LITTLE_ENDIAN
        SET_U32_AT(buffer[0], md5->h0);
        SET_U32_AT(buffer[4], md5->h1);
        SET_U32_AT(buffer[8], md5->h2);
        SET_U32_AT(buffer[12], md5->h3);
#else
        SET_U32_AT(buffer[0], bswap_32(md5->h0));
        SET_U32_AT(buffer[4], bswap_32(md5->h1));
        SET_U32_AT(buffer[8], bswap_32(md5->h2));
        SET_U32_AT(buffer[12], bswap_32(md5->h3));
#endif
        return MD5_DIGEST_LENGTH;
    }

    return BUFFER_WOULD_OVERFLOW;
}

static int32_t digest_md5_get_size(digest_t *ctx)
{
    (void)ctx;

    return MD5_DIGEST_LENGTH;
}

static int32_t digest_md5_get_digest(digest_t *ctx, void **ptr)
{
    *ptr = &ctx->digest[0];

    return MD5_DIGEST_LENGTH;
}

static void                     digest_md5_finalise(struct digest_s *ctx) { (void)ctx; }

static const struct digest_vtbl md5_vtbl = {digest_md5_update, digest_md5_final, digest_md5_final_copy_bytes, digest_md5_get_size, digest_md5_get_digest, digest_md5_finalise, "MD5"};

#if DIGEST_MD5_USE_INTERNAL
void digest_md5_init(digest_t *ctx)
#else
void digest_md5_init_internal(digest_t *ctx)
#endif
{
    ctx->vtbl = &md5_vtbl;

    ctx->ctx.md5_internal.h0 = 0x67452301;
    ctx->ctx.md5_internal.h1 = 0xefcdab89;
    ctx->ctx.md5_internal.h2 = 0x98badcfe;
    ctx->ctx.md5_internal.h3 = 0x10325476;
    ctx->ctx.md5_internal.size = 0;
    ctx->ctx.md5_internal.finalised = 0;
    ctx->ctx.md5_internal.total_size = 0;
}

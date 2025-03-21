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

#include <dnscore/digest.h>
#include "dnscore/dnscore_config.h"
#include "dnscore/digest.h"
#include "dnscore/bytearray_output_stream.h"

static int32_t digest_rawdata_update(digest_t *ctx, const void *buffer, uint32_t size) { return output_stream_write(&ctx->ctx.rawdata.baos, buffer, size) - 1; }

static int32_t digest_rawdata_final(digest_t *ctx)
{
    (void)ctx;
    return SUCCESS;
}

static ya_result digest_rawdata_final_copy_bytes(digest_t *ctx, void *output, uint32_t output_size)
{
    uint32_t size = bytearray_output_stream_size(&ctx->ctx.rawdata.baos);
    if(size <= output_size)
    {
        memcpy(output, bytearray_output_stream_buffer(&ctx->ctx.rawdata.baos), size);
        return size;
    }
    else
    {
        return BUFFER_WOULD_OVERFLOW;
    }
}

static int32_t digest_rawdata_get_size(digest_t *ctx)
{
    int32_t ret = (int32_t)bytearray_output_stream_size(&ctx->ctx.rawdata.baos);
    return ret;
}

static int32_t digest_rawdata_get_digest(digest_t *ctx, void **p)
{
    *p = bytearray_output_stream_buffer(&ctx->ctx.rawdata.baos);
    return bytearray_output_stream_size(&ctx->ctx.rawdata.baos);
}

static void digest_rawdata_finalise(digest_t *ctx)
{
#if DEBUG
    memset(bytearray_output_stream_buffer(&ctx->ctx.rawdata.baos), 0xee, bytearray_output_stream_size(&ctx->ctx.rawdata.baos));
#endif
    output_stream_close(&ctx->ctx.rawdata.baos);
}

static const struct digest_vtbl rawdata_vtbl = {digest_rawdata_update, digest_rawdata_final, digest_rawdata_final_copy_bytes, digest_rawdata_get_size, digest_rawdata_get_digest, digest_rawdata_finalise, "RAWDATA"};

void                            digest_rawdata_init(digest_t *ctx)
{
    ctx->vtbl = &rawdata_vtbl;
    // bytearray_output_stream_init(&ctx->ctx.rawdata, NULL, 0);
    bytearray_output_stream_init_ex_static(&ctx->ctx.rawdata.baos, ctx->ctx.rawdata.data, sizeof(ctx->ctx.rawdata.data), BYTEARRAY_DYNAMIC, &ctx->ctx.rawdata.baos_ctx);
}

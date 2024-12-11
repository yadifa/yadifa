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

#include "yatest.h"
#include "dnscore/bytearray_output_stream.h"
#include <dnscore/dnscore.h>
#include <dnscore/typebitmap.h>

static const uint16_t present_types[] = {TYPE_A, TYPE_NS, TYPE_SOA, TYPE_MX, TYPE_TXT, TYPE_NSEC, TYPE_NSEC3PARAM, TYPE_RRSIG, TYPE_DNSKEY, TYPE_NSEC3, 0};

static const uint16_t present_types2[] = {TYPE_AAAA, TYPE_SSHFP, 0};
#if 0
static void show_ctx_diffs(const type_bit_maps_context_t *a, const type_bit_maps_context_t *b)
{
    uint8_t *p = a->type_bitmap_field;
    uint8_t *q = b->type_bitmap_field;

    int n = MIN((a->last_type_window + 1) * 256, (b->last_type_window + 1) * 256);

    for(int i = 0; i < n; ++i)
    {
        if(p[i] != q[i])
        {
            yatest_err("[%4i]: %02x != %02x", i, p[i], q[i]);
        }
    }
}
#endif
static int typebitmap_test()
{
    dnscore_init();

    // ctx

    type_bit_maps_context_t ctx;
    type_bit_maps_init(&ctx);
    for(int i = 0; present_types[i] != 0; ++i)
    {
        type_bit_maps_set_type(&ctx, present_types[i]);
    }
    type_bit_maps_clear_type(&ctx, TYPE_NSEC3);
    uint16_t ctx_size = type_bit_maps_update_size(&ctx);
    uint8_t *ctx_wire = yatest_malloc(ctx_size);
    type_bit_maps_write(&ctx, ctx_wire);

    yatest_log("ctx:");
    yatest_hexdump(ctx_wire, ctx_wire + ctx_size);

    for(int i = 0; present_types[i] != 0; ++i)
    {
        if(present_types[i] == TYPE_NSEC3) // because it has been manually removed
        {
            continue;
        }

        if(!type_bit_maps_gettypestatus(ctx_wire, ctx_size, present_types[i]))
        {
            yatest_err("type_bit_maps_gettypestatus didn't return true for a type present in the bitmap (%s)", dns_type_get_name(present_types[i]));
            return 1;
        }
    }

    for(int i = 0; present_types2[i] != 0; ++i)
    {
        if(type_bit_maps_gettypestatus(ctx_wire, ctx_size, present_types2[i]))
        {
            yatest_err("type_bit_maps_gettypestatus didn't return false for a type not present in the bitmap (%s)", dns_type_get_name(present_types[i]));
            return 1;
        }
    }

    output_stream_t os;
    bytearray_output_stream_init(&os, NULL, 256);
    type_bit_maps_output_stream_write(&ctx, &os);
    if((bytearray_output_stream_size(&os) != ctx_size) || (memcmp(bytearray_output_stream_buffer(&os), ctx_wire, ctx_size) != 0))
    {
        yatest_err("type_bit_maps_output_stream_write result not matched:");
        yatest_err("got");
        yatest_hexdump_err(bytearray_output_stream_buffer(&os), bytearray_output_stream_buffer(&os) + bytearray_output_stream_size(&os));
        yatest_err("expected");
        yatest_hexdump_err(ctx_wire, ctx_wire + ctx_size);
        return 1;
    }
    output_stream_close(&os);

    // ctx_expanded

    type_bit_maps_context_t ctx_expanded;
    type_bit_maps_init(&ctx_expanded);
    type_bit_maps_expand(&ctx_expanded, ctx_wire, ctx_size);
    type_bit_maps_update_size(&ctx_expanded);

    // ctx2

    type_bit_maps_context_t ctx2;
    type_bit_maps_init(&ctx2);
    for(int i = 0; present_types2[i] != 0; ++i)
    {
        type_bit_maps_set_type(&ctx2, present_types2[i]);
    }
    type_bit_maps_clear_type(&ctx2, TYPE_NSEC3);
    uint16_t ctx2_size = type_bit_maps_update_size(&ctx2);
    uint8_t *ctx2_wire = yatest_malloc(ctx2_size);
    type_bit_maps_update_size(&ctx2);
    type_bit_maps_write(&ctx2, ctx2_wire);

    yatest_log("ctx2:");
    yatest_hexdump(ctx2_wire, ctx2_wire + ctx2_size);

    //

    if(type_bit_maps_compare(&ctx, &ctx2) == 0)
    {
        yatest_err("type_bit_maps_compare ctx ctx2 should have returned != 0");
        return 1;
    }

    if(type_bit_maps_compare(&ctx, &ctx_expanded) != 0)
    {
        yatest_err("type_bit_maps_compare ctx ctx_expanded should have returned == 0");
        return 1;
    }

    type_bit_maps_finalize(&ctx);
    dnscore_finalize();
    return 0;
}

static int type_bit_maps_clear_type_test()
{
    dnscore_init();

    // ctx

    type_bit_maps_context_t ctx;
    type_bit_maps_init(&ctx);
    type_bit_maps_set_type(&ctx, TYPE_NSEC);
    type_bit_maps_clear_type(&ctx, TYPE_NSEC);
    uint16_t ctx_size = type_bit_maps_update_size(&ctx);
    uint8_t *ctx_wire = yatest_malloc(ctx_size);
    type_bit_maps_write(&ctx, ctx_wire);

    yatest_log("ctx: (+NSEC-NSEC)");
    yatest_hexdump(ctx_wire, ctx_wire + ctx_size);

    if(ctx_size > 0)
    {
        yatest_err("(+NSEC-NSEC) should be empty");
        return 1;
    }

    free(ctx_wire);

    type_bit_maps_set_type(&ctx, TYPE_NSEC);
    type_bit_maps_set_type(&ctx, TYPE_NSEC3);
    type_bit_maps_clear_type(&ctx, TYPE_NSEC);
    ctx_size = type_bit_maps_update_size(&ctx);
    ctx_wire = yatest_malloc(ctx_size);
    type_bit_maps_write(&ctx, ctx_wire);

    yatest_log("ctx: (+NSEC+NSEC3-NSEC)");
    yatest_hexdump(ctx_wire, ctx_wire + ctx_size);

    static const uint8_t nsec3_expected[] = {0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20};

    if((ctx_size != sizeof(nsec3_expected)) || (memcmp(ctx_wire, nsec3_expected, ctx_size)) != 0)
    {
        yatest_err("(+NSEC+NSEC3-NSEC) result not matched:");
        yatest_err("got");
        yatest_hexdump_err(ctx_wire, ctx_wire + ctx_size);
        yatest_err("expected");
        yatest_hexdump_err(nsec3_expected, nsec3_expected + sizeof(nsec3_expected));
        return 1;
    }

    free(ctx_wire);

    type_bit_maps_clear_type(&ctx, TYPE_NSEC3);
    ctx_size = type_bit_maps_update_size(&ctx);
    ctx_wire = yatest_malloc(ctx_size);
    type_bit_maps_write(&ctx, ctx_wire);

    yatest_log("ctx: (-NSEC3)");
    yatest_hexdump(ctx_wire, ctx_wire + ctx_size);

    if(ctx_size > 0)
    {
        yatest_err("(+NSEC+NSEC3-NSEC-NSEC3) should be empty");
        return 1;
    }

    dnscore_finalize();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(typebitmap_test)
YATEST(type_bit_maps_clear_type_test)
YATEST_TABLE_END

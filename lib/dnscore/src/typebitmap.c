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

/** @defgroup
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore-config.h"

#include <arpa/inet.h>

#include "dnscore/rfc.h"
#include "dnscore/typebitmap.h"

/*
 * Call this with the context->type_bitmap_field set
 */

void
type_bit_maps_write(const type_bit_maps_context *context, u8 *output)
{
    /* No types at all ? Should NOT have been called */

    //yassert(context->type_bit_maps_size > 2);

    const u8* type_bitmap_field = context->type_bitmap_field;
    const u8* window_size = context->window_size;

    for(s32 i = 0; i <= context->last_type_window; i++)
    {
        u8 bytes = window_size[i];

        if(bytes == 0)
        {
            continue;
        }

        *output++ = i;
        *output++ = bytes;

        u32 wo = i << 5;    /* 256 bits = 32 bytes = 2^5 */
        u32 wo_limit = wo + bytes;

        for(; wo < wo_limit; wo++)
        {
            *output++ = type_bitmap_field[wo];
        }
    }
}

s32
type_bit_maps_expand(type_bit_maps_context* context, u8* type_bitmap, u32 size)
{
    const u8 * const limit = type_bitmap + size;
    s32 last_type = -1;
    while(type_bitmap < limit)
    {
        u8 wn = *type_bitmap++;
        last_type = wn;
        u8 ws = *type_bitmap++;

        if(ws == 0)         /* Blocks with no types present MUST NOT be included */
        {
            continue;
        }

        u8* wp = &context->type_bitmap_field[wn << 8];
        context->window_size[wn] = MAX(context->window_size[wn], ws);

        while(ws-- > 0)
        {
            *wp++ = *type_bitmap++;
        }
    }

    context->last_type_window = MAX(last_type >> 8, context->last_type_window);

    return last_type;
}

bool
type_bit_maps_merge(type_bit_maps_context* context, u8* type_bitmap_a, u32 a_size, u8* type_bitmap_b, u32 b_size)
{
    if(a_size == b_size)
    {
        if(memcmp(type_bitmap_a, type_bitmap_b, a_size) == 0)
        {
            return FALSE; /* Nothing to do.  Both bitmaps are equals */
        }
    }

    u8* type_bitmap_field = context->type_bitmap_field;
    u8* window_size = context->window_size;

    ZEROMEMORY(window_size, sizeof(context->window_size));
    ZEROMEMORY(type_bitmap_field, sizeof(context->type_bitmap_field));

    s32 last_type_a = type_bit_maps_expand(context, type_bitmap_a, a_size);
    s32 last_type_b = type_bit_maps_expand(context, type_bitmap_b, b_size);

    u32 type_bit_maps_size = 0;
    s32 last_type_window = MAX(last_type_a, last_type_b);

    for(s32 i = 0; i <= last_type_window; i++)
    {
        u8 ws = window_size[i];

        if(ws > 0)
        {
            type_bit_maps_size += 1 + 1 + ws;
        }
    }

    return TRUE;
}

void
type_bit_maps_output_stream_write(const type_bit_maps_context* context, output_stream* os)
{
    /* No types at all */

    if(context->type_bit_maps_size == 0)
    {
        return;
    }

    const u8* type_bitmap_field = context->type_bitmap_field;
    const u8* window_size = context->window_size;

    for(s32 i = 0; i <= context->last_type_window; i++)
    {
        u8 bytes = window_size[i];

        if(bytes > 0)
        {
            output_stream_write_u8(os, i);
            output_stream_write_u8(os, bytes);
            output_stream_write(os, &type_bitmap_field[i << 5], bytes);
        }
    }
}

bool
type_bit_maps_gettypestatus(u8* packed_type_bitmap, u32 size, u16 type)
{
    u8 window_index = (type >> 8);

    /* Skip to the right window */

    while(size > 2)
    {
        u8 current_index = *packed_type_bitmap++;
        u8 current_size = *packed_type_bitmap++;

        if(current_index >= window_index)
        {
            if(current_index == window_index)
            {
                u32 byte_offset = (type >> 3);

                if(byte_offset < current_size)
                {
                    return (packed_type_bitmap[byte_offset] & (0x80 >> (type & 7))) != 0;
                }
            }

            break;
        }

        size -= 2;

        size -= current_size;
        packed_type_bitmap += current_size;
    }

    return FALSE;

}

/*
 * Force RRSIG: because the signatures could not be available yet.
 * Force NSEC: because the NSEC record is not available at first init.
 *
 */

void
type_bit_maps_init(type_bit_maps_context *context)
{
    ZEROMEMORY(context, sizeof(type_bit_maps_context));
    context->last_type_window = -1;
}

void type_bit_maps_set_type(type_bit_maps_context *context, u16 rtype)
{
    u8 *type_bitmap_field = context->type_bitmap_field;
    u8 *window_size = context->window_size;

    /* Network bit order */
    rtype = (u16)ntohs(rtype);
    
    const u8 mask = 1 << (7 - (rtype & 7));
    
    if((type_bitmap_field[rtype >> 3] & mask) == 0)
    {
        type_bitmap_field[rtype >> 3] |= mask;
        window_size[rtype >> 8] = MAX(((rtype & 0xf8) >> 3) + 1, window_size[rtype >> 8]);

        context->last_type_window = MAX(rtype >> 8, context->last_type_window);
    }
}

void type_bit_maps_clear_type(type_bit_maps_context *context, u16 rtype)
{
    u8 *type_bitmap_field = context->type_bitmap_field;
    u8 *window_size = context->window_size;

    /* Network bit order */
    rtype = (u16)ntohs(rtype);

    const u8 mask = 1 << (7 - (rtype & 7));

    int rtype_byte_offset = rtype >> 3;
    int rtype_window_offset = rtype >> 8;

    if((type_bitmap_field[rtype_byte_offset] & mask) == 0)
    {
        type_bitmap_field[rtype_byte_offset] &= ~mask;
        s8 ws = window_size[rtype_window_offset];
        u8 *window_base = &type_bitmap_field[rtype_byte_offset & 0xf8];

        while((ws > 0) && (window_base[ws] == 0))
        {
            --ws;
        }

        window_size[rtype_window_offset] = ws;

        if(ws == 0)
        {
            while(rtype_window_offset >= 0)
            {
                if(window_size[rtype_window_offset] > 0)
                {
                    break;
                }
            }
        }

        context->last_type_window = MAX(rtype >> 8, context->last_type_window);
    }
}

u16 type_bit_maps_update_size(type_bit_maps_context *context)
{
    const u8 *window_size = context->window_size;
    u32 type_bit_maps_size = 0;

    for(s32 i = 0; i <= context->last_type_window; i++)
    {
        u8 ws = window_size[i];

        if(ws > 0)
        {
            type_bit_maps_size += 1 + 1 + ws;
        }
    }

    context->type_bit_maps_size = type_bit_maps_size;

    return type_bit_maps_size;
}

/**
 * Compares two types bit maps.
 * 
 * type_bit_maps_update_size(a) must have been called before.
 * type_bit_maps_update_size(b) must have been called before.
 * 
 * @param a
 * @param b
 * @return 
 */

int type_bit_maps_compare(const type_bit_maps_context *a, const type_bit_maps_context *b)
{
    int d = a->last_type_window;
    d -= b->last_type_window;
    if(d == 0)
    {
        d = a->type_bit_maps_size;
        d -= b->type_bit_maps_size;
        if(d == 0)
        {
            if(a->last_type_window > 0)
            {
                d = memcmp(a->type_bitmap_field, b->type_bitmap_field, a->last_type_window << 5); // VS complains: 32 bits is more than enough
            }
        }
    }
    
    return d;
}

/** @} */

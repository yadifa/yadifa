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

/**-----------------------------------------------------------------------------
 * @defgroup
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"

#include <arpa/inet.h>

#include "dnscore/rfc.h"
#include "dnscore/typebitmap.h"

/*
 * Call this with the context->type_bitmap_field set
 */

void type_bit_maps_write(const type_bit_maps_context_t *context, uint8_t *output)
{
    /* No types at all ? Should NOT have been called */

    // yassert(context->type_bit_maps_size > 2);

    const uint8_t *type_bitmap_field = context->type_bitmap_field;
    const uint8_t *window_size = context->window_size;

    for(int_fast32_t i = 0; i <= context->last_type_window; i++)
    {
        uint8_t bytes = window_size[i];

        if(bytes == 0)
        {
            continue;
        }

        *output++ = i;
        *output++ = bytes;

        uint32_t wo = i << 5; /* 256 bits = 32 bytes = 2^5 */
        uint32_t wo_limit = wo + bytes;

        for(; wo < wo_limit; wo++)
        {
            *output++ = type_bitmap_field[wo];
        }
    }
}

int32_t type_bit_maps_expand(type_bit_maps_context_t *context, uint8_t *type_bitmap, uint32_t size)
{
    if(size > 0)
    {
        const uint8_t *const limit = type_bitmap + size;
        int32_t              last_type_window = -1;
        while(type_bitmap < limit)
        {
            // read the window index & size
            uint8_t window_index = *type_bitmap++; // window index
            uint8_t window_size = *type_bitmap++;  // window size

            if(window_size == 0) // Blocks with no types present MUST NOT be included
            {
                context->window_size[window_index] = 0;
                continue;
            }

            // update the last_type_window

            last_type_window = window_index;

            if(window_index > context->last_type_window) // seems pointless
            {
                context->last_type_window = window_index;
            }
            // destination into the 8K bitmap
            uint8_t *wp = &context->type_bitmap_field[window_index << 8];
            // update the window size
            context->window_size[window_index] = MAX(context->window_size[window_index], window_size);

            while(window_size-- > 0)
            {
                uint8_t types = *type_bitmap;
                *wp++ = types;
                type_bitmap++;
            }

            context->window_size[window_index] = wp - context->type_bitmap_field;
        }

        context->last_type_window = MAX(last_type_window >> 8, context->last_type_window);

        return last_type_window;
    }
    else
    {
        return -1;
    }
}

void type_bit_maps_output_stream_write(const type_bit_maps_context_t *context, output_stream_t *os)
{
    /* No types at all */

    if(context->type_bit_maps_size == 0)
    {
        return;
    }

    const uint8_t *type_bitmap_field = context->type_bitmap_field;
    const uint8_t *window_size = context->window_size;

    for(int_fast32_t i = 0; i <= context->last_type_window; i++)
    {
        uint8_t bytes = window_size[i];

        if(bytes > 0)
        {
            output_stream_write_u8(os, i);
            output_stream_write_u8(os, bytes);
            output_stream_write(os, &type_bitmap_field[i << 5], bytes);
        }
    }
}

bool type_bit_maps_gettypestatus(uint8_t *packed_type_bitmap, uint32_t size, uint16_t type)
{
    type = ntohs(type);
    uint8_t window_index = (type >> 8);

    /* Skip to the right window */

    while(size > 2)
    {
        uint8_t current_index = *packed_type_bitmap++;
        uint8_t current_size = *packed_type_bitmap++;

        if(current_index >= window_index)
        {
            if(current_index == window_index)
            {
                uint32_t byte_offset = (type >> 3);

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

    return false;
}

/*
 * Force RRSIG: because the signatures could not be available yet.
 * Force NSEC: because the NSEC record is not available at first init.
 *
 */

void type_bit_maps_init(type_bit_maps_context_t *context)
{
    // context->last_type_window = 0;
    context->type_bit_maps_size = 0;
    // ZEROMEMORY(context, sizeof(type_bit_maps_context));
    context->last_type_window = -1;
}

void type_bit_maps_set_type(type_bit_maps_context_t *context, uint16_t rtype)
{
    uint8_t *type_bitmap_field = context->type_bitmap_field;
    uint8_t *window_size = context->window_size;
    int32_t  last_type_window = context->last_type_window;

    // Network bit order
    rtype = (uint16_t)ntohs(rtype);

    const int32_t type_window = rtype >> 8;

    // clear additional bytes if needed

    if(type_window > last_type_window)
    {
        int32_t length = type_window - last_type_window;
        ZEROMEMORY(&window_size[last_type_window + 1], length);
        ZEROMEMORY(&type_bitmap_field[(last_type_window + 1) << 5], length << 5);
        last_type_window = type_window;
        context->last_type_window = last_type_window;
    }

    const uint8_t mask = 1 << (7 - (rtype & 7));
    type_bitmap_field[rtype >> 3] |= mask;
    uint8_t new_window_size = ((rtype & 0xf8) >> 3) + 1;
    if(new_window_size > window_size[type_window])
    {
        window_size[type_window] = new_window_size;
    }
}

void type_bit_maps_clear_type(type_bit_maps_context_t *context, uint16_t rtype)
{
    uint8_t *type_bitmap_field = context->type_bitmap_field;
    uint8_t *window_size = context->window_size;

    /* Network bit order */
    rtype = (uint16_t)ntohs(rtype);

    const uint8_t mask = 1 << (7 - (rtype & 7));

    int           rtype_byte_offset = rtype >> 3;
    int           rtype_window_offset = rtype >> 8;

    // offset              size = offset - 1
    if(rtype_byte_offset >= window_size[rtype_window_offset]) // bit not set
    {
        return;
    }

    if((type_bitmap_field[rtype_byte_offset] & mask) != 0)
    {
        type_bitmap_field[rtype_byte_offset] &= ~mask;

        if((rtype_byte_offset == window_size[rtype_window_offset] - 1) && (type_bitmap_field[rtype_byte_offset] == 0))
        {
            while(rtype_byte_offset >= 0)
            {
                if(type_bitmap_field[--rtype_byte_offset] != 0)
                {
                    break;
                }
            }

            window_size[rtype_window_offset] = rtype_byte_offset + 1;

            context->last_type_window = MAX(rtype_window_offset, context->last_type_window);
        }
    }
}

uint16_t type_bit_maps_update_size(type_bit_maps_context_t *context)
{
    const uint8_t *window_size = context->window_size;
    uint32_t       type_bit_maps_size = 0;

    for(int_fast32_t i = 0; i <= context->last_type_window; i++)
    {
        uint8_t ws = window_size[i];

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

int type_bit_maps_compare(const type_bit_maps_context_t *a, const type_bit_maps_context_t *b)
{
    int d = a->last_type_window;
    d -= b->last_type_window;
    if(d == 0)
    {
        d = a->type_bit_maps_size;
        d -= b->type_bit_maps_size;
        if(d == 0)
        {
            for(int_fast32_t i = 0; i <= a->last_type_window; ++i)
            {
                d = a->window_size[i] - b->window_size[i];
                if(d == 0)
                {
                    d = memcmp(a->type_bitmap_field, b->type_bitmap_field,
                               a->window_size[i]); // VS complains: 32 bits is more than enough
                    if(d != 0)
                    {
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
        }
    }

    return d;
}

/** @} */

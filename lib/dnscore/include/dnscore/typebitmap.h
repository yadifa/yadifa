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
#ifndef _TYPEBITMAP_H
#define	_TYPEBITMAP_H

#include <dnscore/sys_types.h>

#include <dnscore/output_stream.h>

#ifdef	__cplusplus
extern "C"
{
#endif

typedef struct type_bit_maps_context type_bit_maps_context;


/*
 * Maximum type bitmap size =
 *
 * (1+1+32) * 256 = 8704
 *
 */

#define TYPE_BIT_MAPS_MAX_RDATA_SIZE 8704

struct type_bit_maps_context
{
    u32 type_bit_maps_size;
    s32 last_type_window;
    u8 window_size[256];
    u8 type_bitmap_field[8192];
};

void type_bit_maps_init(type_bit_maps_context *context);

static inline void type_bit_maps_finalize(type_bit_maps_context *context) { (void)context; }

void type_bit_maps_set_type(type_bit_maps_context *context, u16 rtype);

void type_bit_maps_clear_type(type_bit_maps_context *context, u16 rtype);

u16 type_bit_maps_update_size(type_bit_maps_context *context);

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

int type_bit_maps_compare(const type_bit_maps_context *a, const type_bit_maps_context *b);

/*
 *  Once initialized properly, a bitmap context can be written as an (NSEC, NSEC3) bitmap using this function
 */
 
void type_bit_maps_write(const type_bit_maps_context* context, u8* output);

/*
 * Converts a (compressed) bitmap to its bit field (expanded)
 */

s32 type_bit_maps_expand(type_bit_maps_context* context, u8* type_bitmap, u32 size);

/*
 * Takes two (compressed) bitmaps and merge them.
 * Used for DNSSEC
 */

bool type_bit_maps_merge(type_bit_maps_context* context, u8* type_bitmap_a, u32 a_size, u8* type_bitmap_b, u32 b_size);

/*
 * Takes two bitmaps and merge them into a stream
 * Used by the zone reader
 */

void type_bit_maps_output_stream_write(const type_bit_maps_context* context, output_stream* os);

/*
 * Returns TRUE if the type is enabled in the packed_type_bitmap
 * (The buffer format matches the type bitmap in the NSEC/NSEC3 wire format)
 */

bool type_bit_maps_gettypestatus(u8* packed_type_bitmap, u32 size, u16 type);

#ifdef	__cplusplus
}
#endif

#endif	/* _NSEC_COMMON_H */

/** @} */

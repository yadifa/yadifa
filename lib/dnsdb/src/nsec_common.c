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

/** @defgroup nsec NSEC functions
 *  @ingroup dnsdbdnssec
 *  @brief
 *
 *
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnsdb/dnsdb-config.h"
#include <dnscore/sys_types.h>
#include <dnscore/rfc.h>
#include "dnsdb/btree.h"

#include "dnsdb/zdb_record.h"

#include "dnsdb/nsec_common.h"

#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif

/*
 * Force RRSIG: because the signatures could not be available yet.
 * Force NSEC: because the NSEC record is not available at first init.
 *
 */

u32
nsec_type_bit_maps_initialise_from_label(type_bit_maps_context *context, zdb_rr_label *label, bool force_nsec,
                                         bool force_rrsig)
{
    u8 *type_bitmap_field = context->type_bitmap_field;
    u8 *window_size = context->window_size;

    ZEROMEMORY(window_size, sizeof(context->window_size));

    context->last_type_window = -1;

    bool has_records = !zdb_record_isempty(&label->resource_record_set);

    /* If there are no records, nor forced ones ... */
    if(!(force_nsec||force_rrsig||has_records))
    {
        return 0;
    }

    ZEROMEMORY(type_bitmap_field, sizeof(context->type_bitmap_field));

    btree_iterator types_iter;
    btree_iterator_init(label->resource_record_set, &types_iter);
    while(btree_iterator_hasnext(&types_iter))
    {
        btree_node *node = btree_iterator_next_node(&types_iter);

        u16 type = node->hash; /** @note : NATIVETYPE */
        
#if ZDB_HAS_NSEC3_SUPPORT
        if(type == TYPE_NSEC3PARAMADD) type = TYPE_NSEC3PARAM; // we are generating an NSEC3 chain : let's get the real types right
#endif
        /**
         * domain.tld. NS domain.tld.
         *              A domain.tld.
         *              NSEC further.tld. NS RRSIG NSEC
         *              RRSIG ...
         *
         * Because this is possible, I have to filter out (I should maybe filter in instead)
         */

        if(zdb_rr_label_flag_isset(label, (ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION)))
        {
            if(type == TYPE_A || type == TYPE_AAAA)
            {
                continue;
            }
        }

        type = (u16)ntohs(type);

        /* Network bit order */

        type_bitmap_field[type >> 3] |= 1 << (7 - (type & 7));
        window_size[type >> 8] = ((type & 0xf8) >> 3) + 1;

        context->last_type_window = MAX(type >> 8, context->last_type_window);
    }

    /*
     * Add the forced types : NSEC, RRSIG
     * They all are on window 0
     */

    /*
     * HHHHHHHH LLLLLlll
     *
     * TBF[ HHHHHHHH LLLLL ] |= 1 << 7 - (lll)
     *
     * =>
     *
     *
     * LLLLLlll HHHHHHHH
     *
     * TBF[ HHHHHHHH LLLLL ] |= 1 << ((0x700 - (lll00000000)) >> 8)
     *
     * * Given that I can't get rid of the >> 8 in the above statement, a swap will work better
     *
     */


    if(force_rrsig)
    {
        type_bitmap_field[(NU16(TYPE_RRSIG) >> 3)] |= 1 << (7 - (NU16(TYPE_RRSIG) & 7)); /** @note : NATIVETYPE */
        window_size[0] = MAX(((NU16(TYPE_RRSIG) & 0xf8) >> 3) + 1, window_size[0]); /** @note : NATIVETYPE */

        context->last_type_window = MAX(0, context->last_type_window);
    }

    if(force_nsec)
    {
        type_bitmap_field[(NU16(TYPE_NSEC) >> 3)] |= 1 << (7 - (NU16(TYPE_NSEC) & 7)); /** @note : NATIVETYPE */
        window_size[0] = MAX(((NU16(TYPE_NSEC) & 0xf8) >> 3) + 1, window_size[0]); /** @note : NATIVETYPE */

        context->last_type_window = MAX(0, context->last_type_window);
    }

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

/** @} */

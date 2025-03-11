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

/**-----------------------------------------------------------------------------
 * @defgroup dnsdbzone Zone related functions
 * @ingroup dnsdb
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <dnscore/sys_types.h>
#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb_record.h"

#include <dnscore/base32hex.h>

#include <dnscore/dnsname.h>

#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif

#include <dnscore/output_stream.h>

#include <dnscore/rfc.h>

#include <dnscore/dnscore.h>

// With this set to 1, AXFR storage on disk will be extremely slow.
// Meant to debug network faster than disk speeds.
// The value is expressed in ms
//
// Keep this to 0 except if you need it to be slow

#define DEBUG_SLOW_STORAGE_MS 0 // 100

#if !DEBUG
#undef DEBUG_SLOW_STORAGE_MS
#define DEBUG_SLOW_STORAGE_MS 0
#endif

/*
 *
 */

struct type_class_ttl_size
{
    uint16_t rtype;
    uint16_t rclass;
    uint32_t rttl;
    uint16_t rsize;
};

/*
 * MAGIC // F0 C Z F
 * class (2 bytes)
 * Size (5 bytes)
 * domain-size (1 bytes)
 * DOMAIN
 *     0 TTL (compact)
 *     Type (compact) count (compact)
 *       rdata_len (compact) rdata (bytes)
 *     Type-OPT (end)
 *
 * label (go down)
 *     0 TTL (compact)
 *     Type (compact) count (compact)
 *       rdata_len (compact) rdata (bytes)
 *     Type-OPT (end)
 * 0 (byte) go up
 *
 * MAGIC // F1 E N D
 *
 */

struct zone_writer_czf_header_s
{
    uint32_t magic;
    uint16_t zclass;
    uint8_t  size[5];
    uint8_t  origin_size;
};

ya_result zdb_zone_store_czf(zdb_zone_t *zone, output_stream_t *os)
{
    zdb_rr_label_t                 *label;

    uint32_t                        fqdn_len;
    ya_result                       ret = SUCCESS;

    uint8_t                         fqdn[DOMAIN_LENGTH_MAX];

    struct zone_writer_czf_header_s header;
    header.magic = MAGIC4(0xf0, 'C', 'Z', 'F');
    header.zclass = zdb_zone_getclass(zone);
    memset(&header.size, 0, sizeof(header.size));
    header.origin_size = dnsname_len(zone->origin);

    zdb_zone_label_iterator_t label_iter;

    yassert(zdb_zone_islocked(zone));

    header.zclass = zdb_zone_getclass(zone); /** @note: NATIVECLASS */

    output_stream_write_fully(os, &header, sizeof(header));
    output_stream_write_dnsname(os, zone->origin);

    int32_t                     current_ttl;
    zdb_resource_record_data_t *soa_rr = zdb_resource_record_sets_find_soa_and_ttl(&zone->apex->resource_record_set, &current_ttl);

    if(soa_rr == NULL)
    {
        return ZDB_ERROR_GENERAL;
    }

    int32_t minimum_ttl = current_ttl;

    // init the TTL and add the SOA

    output_stream_write_u8(os, 0);             // announce TTL
    output_stream_write_pu32(os, current_ttl); // the SOA TTL
    output_stream_write_pu32(os, NU16(TYPE_SOA));
    output_stream_write_u8(os, 1);
    output_stream_write_pu32(os, zdb_resource_record_data_rdata_size(soa_rr));
    output_stream_write_fully(os, zdb_resource_record_data_rdata_const(soa_rr), zdb_resource_record_data_rdata_size(soa_rr));

    zdb_zone_label_iterator_init(zone, &label_iter);

    zdb_zone_label_iterator_hasnext(&label_iter); // can only be true, but needs to be called

    fqdn_len = zdb_zone_label_iterator_nextname(&label_iter, fqdn); // the origin
    (void)fqdn_len;
    label = zdb_zone_label_iterator_next(&label_iter); // the apex

    zdb_resource_record_sets_set_iterator_t rrsets_iter;
    zdb_resource_record_sets_set_iterator_init(&label->resource_record_set, &rrsets_iter);
    while(zdb_resource_record_sets_set_iterator_hasnext(&rrsets_iter))
    {
        zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_iterator_next_node(&rrsets_iter);
        uint16_t                         rtype = zdb_resource_record_set_type(&rrset_node->value);

        if(rtype == TYPE_SOA)
        {
            continue;
        }

        zdb_resource_record_set_const_t *rrset = (zdb_resource_record_set_const_t *)&rrset_node->value;
        int32_t                          rrset_ttl = zdb_resource_record_set_ttl(rrset);
        if(rrset_ttl != current_ttl)
        {
            current_ttl = rrset_ttl;
            output_stream_write_u8(os, 0);             // announce TTL
            output_stream_write_pu32(os, current_ttl); // the SOA TTL
        }

        int32_t rrset_size = zdb_resource_record_set_size(rrset);
        output_stream_write_pu32(os, NU16(zdb_resource_record_set_type(rrset)));
        output_stream_write_pu32(os, rrset_size);
        for(int_fast32_t i = 0; i < rrset_size; ++i)
        {
            const zdb_resource_record_data_t *rr = zdb_resource_record_set_record_get_const(rrset, i);
            output_stream_write_pu32(os, zdb_resource_record_data_rdata_size(rr));
            output_stream_write_fully(os, zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr));
        }
    }

    output_stream_write_u8(os, NU16(TYPE_OPT)); // end for this leaf

    uint8_t         current_domain[256];
    dnsname_stack_t current_domain_stack;
    dnsname_stack_t next_domain_stack;
    dnsname_copy(current_domain, zone->origin);
    dnsname_to_dnsname_stack(zone->origin, &current_domain_stack);

    int depth = 0;

    while(zdb_zone_label_iterator_hasnext(&label_iter))
    {
        fqdn_len = zdb_zone_label_iterator_nextname(&label_iter, fqdn);
        (void)fqdn_len;
        // determine the label path
        // it's either a number of downs, either a number of ups followed by a number of downs

        dnsname_to_dnsname_stack(fqdn, &next_domain_stack);
        /*
         * a b c
         * a d e
         * =>
         * pop 2, add 2
         *
         * a b c d
         * a e
         * =>
         * pop 3, add 1
         */

        int32_t current_len = dnsname_stack_depth(&current_domain_stack);
        int32_t next_len = dnsname_stack_depth(&next_domain_stack);
        int     stack_index;
        for(stack_index = 0; stack_index < current_len; ++stack_index)
        {
            if(!dnslabel_equals(current_domain_stack.labels[stack_index], next_domain_stack.labels[stack_index]))
            {
                // pop len-stack_index
                for(int_fast32_t i = stack_index; i < current_len; ++i)
                {
                    output_stream_write_u8(os, 0);
                    --depth;
                }
                break;
            }
        }

        // push from stack_index to len-1

        for(int_fast32_t i = stack_index; i < next_len; ++i)
        {
            output_stream_write_fully(os, next_domain_stack.labels[i], next_domain_stack.labels[i][0] + 1);
            ++depth;
        }

        dnsname_copy(current_domain, fqdn);
        dnsname_to_dnsname_stack(current_domain, &current_domain_stack);

        //

        label = zdb_zone_label_iterator_next(&label_iter);

        zdb_resource_record_sets_set_iterator_init(&label->resource_record_set, &rrsets_iter);
        while(zdb_resource_record_sets_set_iterator_hasnext(&rrsets_iter))
        {
            zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_iterator_next_node(&rrsets_iter);

            zdb_resource_record_set_const_t *rrset = (zdb_resource_record_set_const_t *)&rrset_node->value;
            int32_t                          rrset_ttl = zdb_resource_record_set_ttl(rrset);
            if(rrset_ttl != current_ttl)
            {
                current_ttl = rrset_ttl;
                output_stream_write_u8(os, 0);             // announce TTL
                output_stream_write_pu32(os, current_ttl); // the SOA TTL
            }

            output_stream_write_pu32(os, NU16(zdb_resource_record_set_type(rrset)));
            int32_t rrset_size = zdb_resource_record_set_size(rrset);
            output_stream_write_pu32(os, rrset_size);
            for(int_fast32_t i = 0; i < rrset_size; ++i)
            {
                const zdb_resource_record_data_t *rr = zdb_resource_record_set_record_get_const(rrset, i);
                output_stream_write_pu32(os, zdb_resource_record_data_rdata_size(rr));
                output_stream_write_fully(os, zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr));
            }
        }

        output_stream_write_u8(os, NU16(TYPE_OPT)); // end for this leaf
    }

    for(; depth > 0; --depth)
    {
        output_stream_write_u8(os, 0);
    }

    // go up to the apex

#if ZDB_HAS_NSEC3_SUPPORT

    /*
     * NSEC3 part of the DB
     */

    /*
     * For each NSEC3PARAM struct ...
     *
     * Note that from the 'transaction' update, the dnssec zone collections have to be read without checking for the
     * NSEC3 flag
     */

    nsec3_zone_t *n3 = zone->nsec.nsec3;

    while(n3 != NULL)
    {
        /*
         *  Iterate the NSEC3 nodes
         */

        nsec3_iterator_t nsec3_items_iter;
        nsec3_iterator_init(&n3->items, &nsec3_items_iter);

        if(nsec3_iterator_hasnext(&nsec3_items_iter))
        {
            nsec3_zone_item_t *first = nsec3_iterator_next_node(&nsec3_items_iter);
            nsec3_zone_item_t *item = first;
            nsec3_zone_item_t *next_item;

            uint8_t            digest_len = NSEC3_NODE_DIGEST_SIZE(first);
            uint32_t           rdata_hash_offset = NSEC3PARAM_RDATA_SIZE_FROM_CHAIN(n3);
            uint32_t           encoded_digest_len = BASE32HEX_ENCODED_LEN(digest_len);

            do
            {
                if(nsec3_iterator_hasnext(&nsec3_items_iter))
                {
                    next_item = nsec3_iterator_next_node(&nsec3_items_iter);
                }
                else
                {
                    next_item = first;
                }

                /* Writes the nsec3 item, wire format, to an output stream */

                uint32_t rdata_size = rdata_hash_offset + digest_len + 1 + item->type_bit_maps_size;

                if(rdata_size > RDATA_LENGTH_MAX)
                {
                    return ZDB_ERROR_GENERAL;
                }

                /* FQDN */

                fqdn[0] = encoded_digest_len;
                base32hex_encode_lc(NSEC3_NODE_DIGEST_PTR(item), digest_len, (char *)&fqdn[1]);

                // down one level

                if(FAIL(ret = output_stream_write_fully(os, fqdn, encoded_digest_len + 1)))
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_u8(os, NU16(TYPE_NSEC3))))
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_u8(os, 1)))
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_nu32(os, minimum_ttl)))
                {
                    return ret;
                }

                /* Write the data */

                if(FAIL(ret = output_stream_write_pu32(os, rdata_size)))
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_u8(os, n3->rdata[0])))
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_u8(os, item->flags)))
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_fully(os, &n3->rdata[2], rdata_hash_offset - 2)))
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_fully(os, next_item->digest, digest_len + 1)))
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_fully(os, item->type_bit_maps, item->type_bit_maps_size)))
                {
                    return ret;
                }

                zdb_resource_record_set_const_t *rrset = item->rrsig_rrset;

                if(rrset != NULL)
                {
                    int32_t                                ne_ttl = htonl(zdb_resource_record_set_ttl(rrset));

                    zdb_resource_record_set_const_iterator iter;
                    zdb_resource_record_set_const_iterator_init(rrset, &iter);
                    while(zdb_resource_record_set_const_iterator_has_next(&iter))
                    {
                        // const zdb_resource_record_data_t *rrsig_rr =
                        // zdb_resource_record_set_const_iterator_next(&iter);

                        if(FAIL(ret = output_stream_write_u8(os, NU16(TYPE_RRSIG))))
                        {
                            return ret;
                        }

                        if(FAIL(ret = output_stream_write_u32(os, ne_ttl)))
                        {
                            return ret;
                        }

                        int32_t rrset_size = zdb_resource_record_set_size(rrset);
                        output_stream_write_pu32(os, rrset_size);
                        for(int_fast32_t i = 0; i < rrset_size; ++i)
                        {
                            const zdb_resource_record_data_t *rrsig_rr = zdb_resource_record_set_record_get_const(rrset, i);
                            output_stream_write_pu32(os, zdb_resource_record_data_rdata_size(rrsig_rr));
                            output_stream_write_fully(os, zdb_resource_record_data_rdata_const(rrsig_rr), zdb_resource_record_data_rdata_size(rrsig_rr));
                        }
                    }
                }

                output_stream_write_u8(os, NU16(TYPE_OPT)); // end for this leaf
                output_stream_write_u8(os, 0);              // up one level

                /*
                 * nsec3 item written with its signatures
                 *
                 * Wire format
                 *
                 */

                item = next_item;
            } while(next_item != first);

        } /* If there is a first item*/

        n3 = n3->next;
    }

#endif

    output_stream_write_u32(os, MAGIC4(0xf1, 'E', 'N', 'D'));

    return ret;
}

/** @} */

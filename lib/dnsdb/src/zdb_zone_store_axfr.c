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

#define TCTS_SIZE 10

// static const uint8_t wild_wire[2] = {1, '*'};

ya_result zdb_zone_store_axfr(zdb_zone_t *zone, output_stream_t *os)
{
    zdb_rr_label_t            *label;

    uint32_t                   fqdn_len;
    ya_result                  ret = SUCCESS;

    uint8_t                    fqdn[DOMAIN_LENGTH_MAX];

    zdb_zone_label_iterator_t  iter;

    struct type_class_ttl_size rec;

    yassert((((uint8_t *)&rec.rtype - (uint8_t *)&rec) == 0) && (((uint8_t *)&rec.rclass - (uint8_t *)&rec) == 2) && (((uint8_t *)&rec.rttl - (uint8_t *)&rec) == 4) &&
            (((uint8_t *)&rec.rsize - (uint8_t *)&rec) == 8)); /* Else the struct is "aligned" ... and broken */

    yassert(zdb_zone_islocked(zone));

    rec.rclass = zdb_zone_getclass(zone); /** @note: NATIVECLASS */

    int32_t                     soa_ttl;
    zdb_resource_record_data_t *soa_rr = zdb_resource_record_sets_find_soa_and_ttl(&zone->apex->resource_record_set, &soa_ttl);

    if(soa_rr == NULL)
    {
        return ZDB_ERROR_GENERAL;
    }

    int32_t minimum_ttl;
#if NSEC3_MIN_TTL_ERRATA
    zdb_zone_getminttlsoa(zone, &minimum_ttl);
#else
    zdb_zone_getminttl(zone, &minimum_ttl);
#endif
    rec.rtype = (TYPE_SOA); /** @note: NATIVETYPE */
    rec.rttl = htonl(soa_ttl);
    rec.rsize = htons(zdb_resource_record_data_rdata_size(soa_rr));

    if(FAIL(ret = output_stream_write_fully(os, zone->origin, dnsname_len(zone->origin))))
    {
        return ret;
    }
    if(FAIL(ret = output_stream_write_fully(os, (uint8_t *)&rec, TCTS_SIZE)))
    {
        return ret;
    }
    if(FAIL(ret = output_stream_write_fully(os, zdb_resource_record_data_rdata_const(soa_rr), zdb_resource_record_data_rdata_size(soa_rr))))
    {
        return ret;
    }

    zdb_zone_label_iterator_init(zone, &iter);

    while(zdb_zone_label_iterator_hasnext(&iter))
    {
#if DEBUG_SLOW_STORAGE_MS > 0
        usleep(DEBUG_SLOW_STORAGE_MS * 1000);
#endif

        fqdn_len = zdb_zone_label_iterator_nextname(&iter, fqdn);

        label = zdb_zone_label_iterator_next(&iter);

        zdb_resource_record_sets_set_iterator_t iter;
        zdb_resource_record_sets_set_iterator_init(&label->resource_record_set, &iter);
        while(zdb_resource_record_sets_set_iterator_hasnext(&iter))
        {
            zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_iterator_next_node(&iter);
            uint16_t                         rtype = zdb_resource_record_set_type(&rrset_node->value);

            if(rtype == TYPE_SOA)
            {
                continue;
            }

            zdb_resource_record_set_const_t *rrset = (zdb_resource_record_set_const_t *)&rrset_node->value;
            int32_t                          rrset_ttl_n = htonl(rrset->_ttl);

            rec.rtype = rtype; /** @note: NATIVETYPE */

            zdb_resource_record_set_const_iterator iter;
            zdb_resource_record_set_const_iterator_init(rrset, &iter);

            if(rtype != TYPE_RRSIG)
            {
                while(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    const zdb_resource_record_data_t *rr = zdb_resource_record_set_const_iterator_next(&iter);

                    rec.rttl = rrset_ttl_n;
                    rec.rsize = htons(zdb_resource_record_data_rdata_size(rr));

                    if(FAIL(ret = output_stream_write_fully(os, fqdn, fqdn_len)))
                    {
                        return ret;
                    }

                    if(FAIL(ret = output_stream_write_fully(os, (uint8_t *)&rec, TCTS_SIZE)))
                    {
                        return ret;
                    }

                    if(FAIL(ret = output_stream_write_fully(os, zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr))))
                    {
                        return ret;
                    }
                }
            }
            else
            {
                while(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    const zdb_resource_record_data_t *rr = zdb_resource_record_set_const_iterator_next(&iter);
                    uint16_t                          covered_type = rrsig_get_type_covered_from_rdata(zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr));

                    zdb_resource_record_set_t        *covered_rrset = zdb_resource_record_sets_find(&label->resource_record_set, covered_type);
                    if(covered_rrset != NULL)
                    {
                        rec.rttl = htonl(zdb_resource_record_set_ttl(covered_rrset));
                    }
                    else
                    {
                        rec.rttl = rrset_ttl_n;
                    }

                    rec.rsize = htons(zdb_resource_record_data_rdata_size(rr));

                    if(FAIL(ret = output_stream_write_fully(os, fqdn, fqdn_len)))
                    {
                        return ret;
                    }

                    if(FAIL(ret = output_stream_write_fully(os, (uint8_t *)&rec, TCTS_SIZE)))
                    {
                        return ret;
                    }

                    if(FAIL(ret = output_stream_write_fully(os, zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr))))
                    {
                        return ret;
                    }
                }
            }
        }
    }

#if ZDB_HAS_NSEC3_SUPPORT

    /*
     * NSEC3 part of the DB
     */

    uint32_t origin_len = dnsname_len(zone->origin);

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

                if(FAIL(ret = output_stream_write_fully(os, fqdn, encoded_digest_len + 1)))
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_fully(os, zone->origin, origin_len)))
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_u16(os, TYPE_NSEC3))) /** @note NATIVETYPE */
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_u16(os, CLASS_IN))) /** @note NATIVECLASS */
                {
                    return ret;
                }

                if(FAIL(ret = output_stream_write_nu32(os, minimum_ttl)))
                {
                    return ret;
                }

                /* Write the data */

                if(FAIL(ret = output_stream_write_nu16(os, rdata_size)))
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
                        const zdb_resource_record_data_t *rrsig_rr = zdb_resource_record_set_const_iterator_next(&iter);

                        if(FAIL(ret = output_stream_write_fully(os, fqdn, encoded_digest_len + 1)))
                        {
                            return ret;
                        }
                        if(FAIL(ret = output_stream_write_fully(os, zone->origin, origin_len)))
                        {
                            return ret;
                        }

                        if(FAIL(ret = output_stream_write_u16(os, TYPE_RRSIG))) /** @note NATIVETYPE */
                        {
                            return ret;
                        }

                        if(FAIL(ret = output_stream_write_u16(os, CLASS_IN))) /** @note NATIVECLASS */
                        {
                            return ret;
                        }

                        if(FAIL(ret = output_stream_write_u32(os, ne_ttl)))
                        {
                            return ret;
                        }

                        if(FAIL(ret = output_stream_write_nu16(os, zdb_resource_record_data_rdata_size(rrsig_rr))))
                        {
                            return ret;
                        }

                        if(FAIL(ret = output_stream_write_fully(os, zdb_resource_record_data_rdata_const(rrsig_rr), zdb_resource_record_data_rdata_size(rrsig_rr))))
                        {
                            return ret;
                        }
                    }
                }

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

    rec.rtype = (TYPE_SOA); /** @note: NATIVETYPE */
    rec.rttl = htonl(soa_ttl);
    rec.rsize = htons(zdb_resource_record_data_rdata_size(soa_rr));

    if(FAIL(ret = output_stream_write_fully(os, zone->origin, dnsname_len(zone->origin))))
    {
        return ret;
    }

    if(FAIL(ret = output_stream_write_fully(os, (uint8_t *)&rec, TCTS_SIZE)))
    {
        return ret;
    }

    ret = output_stream_write_fully(os, zdb_resource_record_data_rdata_const(soa_rr), zdb_resource_record_data_rdata_size(soa_rr));

    return ret;
}

/** @} */

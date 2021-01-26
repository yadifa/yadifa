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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
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

#include "dnsdb/zdb_utils.h"
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
    u16 rtype;
    u16 rclass;
    u32 rttl;
    u16 rsize;
};

#define TCTS_SIZE 10

//static const u8 wild_wire[2] = {1, '*'};

ya_result
zdb_zone_store_axfr(zdb_zone* zone, output_stream* os)
{
    zdb_rr_label* label;
    
    u32 fqdn_len;
    ya_result err = SUCCESS;

    u8 fqdn[MAX_DOMAIN_LENGTH];

    zdb_zone_label_iterator iter;
    btree_iterator type_iter;

    struct type_class_ttl_size rec;

    yassert((((u8*) & rec.rtype - (u8*) & rec) == 0) &&
           (((u8*) & rec.rclass - (u8*) & rec) == 2) &&
           (((u8*) & rec.rttl - (u8*) & rec) == 4) &&
           (((u8*) & rec.rsize - (u8*) & rec) == 8)
           ); /* Else the struct is "aligned" ... and broken */
    
    yassert(zdb_zone_islocked(zone));

    rec.rclass = zdb_zone_getclass(zone); /** @note: NATIVECLASS */

    zdb_packed_ttlrdata* soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);

    if(soa == NULL)
    {
        return ZDB_ERROR_GENERAL;
    }

    s32 minimum_ttl;

    zdb_zone_getminttl(zone, &minimum_ttl);

    rec.rtype = (TYPE_SOA); /** @note: NATIVETYPE */
    rec.rttl = htonl(soa->ttl);
    rec.rsize = htons(soa->rdata_size);

    output_stream_write(os, zone->origin, dnsname_len(zone->origin));
    output_stream_write(os, (u8*) & rec, TCTS_SIZE);
    output_stream_write(os, soa->rdata_start, soa->rdata_size);

    zdb_zone_label_iterator_init(&iter, zone);

    while(zdb_zone_label_iterator_hasnext(&iter))
    {
#if DEBUG_SLOW_STORAGE_MS > 0
        usleep(DEBUG_SLOW_STORAGE_MS * 1000);
#endif
        
        fqdn_len = zdb_zone_label_iterator_nextname(&iter, fqdn);

        label = zdb_zone_label_iterator_next(&iter);
        btree_iterator_init(label->resource_record_set, &type_iter);
        while(btree_iterator_hasnext(&type_iter))
        {
            btree_node* type_node = btree_iterator_next_node(&type_iter);

            if(type_node->hash == TYPE_SOA)
            {
                continue;
            }

            rec.rtype = ((u16)type_node->hash); /** @note: NATIVETYPE */

            zdb_packed_ttlrdata* rr_sll = (zdb_packed_ttlrdata*)type_node->data;

            do
            {
                rec.rttl = htonl(rr_sll->ttl);
                rec.rsize = htons(rr_sll->rdata_size);

                if(FAIL(err = output_stream_write(os, fqdn, fqdn_len)))
                {
                    return err;
                }

                if(FAIL(err = output_stream_write(os, (u8*) & rec, TCTS_SIZE)))
                {
                    return err;
                }

                if(FAIL(err = output_stream_write(os, rr_sll->rdata_start, rr_sll->rdata_size)))
                {
                    return err;
                }

                rr_sll = rr_sll->next;
            }
            while(rr_sll != NULL);
        }
    }

#if ZDB_HAS_NSEC3_SUPPORT

    /*
     * NSEC3 part of the DB
     */

    u32 origin_len = dnsname_len(zone->origin);

    /*
     * For each NSEC3PARAM struct ...
     * 
     * Note that from the 'transaction' update, the dnssec zone collections have to be read without checking for the NSEC3 flag
     */

    nsec3_zone* n3 = zone->nsec.nsec3;

    while(n3 != NULL)
    {
        /*
         *  Iterate the NSEC3 nodes
         */

        nsec3_iterator nsec3_items_iter;
        nsec3_iterator_init(&n3->items, &nsec3_items_iter);

        if(nsec3_iterator_hasnext(&nsec3_items_iter))
        {
            nsec3_zone_item *first = nsec3_iterator_next_node(&nsec3_items_iter);
            nsec3_zone_item *item = first;
            nsec3_zone_item *next_item;

            u8 digest_len = NSEC3_NODE_DIGEST_SIZE(first);
            u32 rdata_hash_offset = NSEC3_ZONE_RDATA_SIZE(n3);
            u32 encoded_digest_len = BASE32HEX_ENCODED_LEN(digest_len);

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

                u32 rdata_size = rdata_hash_offset + digest_len + 1 + item->type_bit_maps_size;

                if(rdata_size > RDATA_MAX_LENGTH)
                {
                    return ZDB_ERROR_GENERAL;
                }

                /* FQDN */

                fqdn[0] = encoded_digest_len;
                base32hex_encode(NSEC3_NODE_DIGEST_PTR(item), digest_len, (char*)&fqdn[1]);

                if(FAIL(err = output_stream_write(os, fqdn, encoded_digest_len + 1)))
                {
                    return err;
                }

                if(FAIL(err = output_stream_write(os, zone->origin, origin_len)))
                {
                    return err;
                }

                if(FAIL(err = output_stream_write_u16(os, TYPE_NSEC3))) /** @note NATIVETYPE */
                {
                    return err;
                }

                if(FAIL(err = output_stream_write_u16(os, CLASS_IN))) /** @note NATIVECLASS */
                {
                    return err;
                }

                if(FAIL(err = output_stream_write_nu32(os, minimum_ttl)))
                {
                    return err;
                }

                /* Write the data */

                if(FAIL(err = output_stream_write_nu16(os, rdata_size)))
                {
                    return err;
                }

                if(FAIL(err = output_stream_write_u8(os, n3->rdata[0])))
                {
                    return err;
                }

                if(FAIL(err = output_stream_write_u8(os, item->flags)))
                {
                    return err;
                }

                if(FAIL(err = output_stream_write(os, &n3->rdata[2], rdata_hash_offset - 2)))
                {
                    return err;
                }

                if(FAIL(err = output_stream_write(os, next_item->digest, digest_len + 1)))
                {
                    return err;
                }

                if(FAIL(err = output_stream_write(os, item->type_bit_maps, item->type_bit_maps_size)))
                {
                    return err;
                }

                zdb_packed_ttlrdata* rrsig = item->rrsig;

                while(rrsig != NULL)
                {
                    output_stream_write(os, fqdn, encoded_digest_len + 1);
                    output_stream_write(os, zone->origin, origin_len);

                    output_stream_write_u16(os, TYPE_RRSIG); /** @note NATIVETYPE */
                    output_stream_write_u16(os, CLASS_IN); /** @note NATIVECLASS */
                    output_stream_write_nu32(os, rrsig->ttl);
                    output_stream_write_nu16(os, rrsig->rdata_size);
                    output_stream_write(os, rrsig->rdata_start, rrsig->rdata_size);

                    rrsig = rrsig->next;
                }

                /*
                 * nsec3 item written with its signatures
                 *
                 * Wire format
                 *
                 */

                item = next_item;
            }
            while(next_item != first);

        } /* If there is a first item*/

        n3 = n3-> next;
    }

#endif

    rec.rtype = (TYPE_SOA); /** @note: NATIVETYPE */
    rec.rttl = htonl(soa->ttl);
    rec.rsize = htons(soa->rdata_size);

    output_stream_write(os, zone->origin, dnsname_len(zone->origin));
    output_stream_write(os, (u8*) & rec, TCTS_SIZE);
    output_stream_write(os, soa->rdata_start, soa->rdata_size);

    return err;
}

/** @} */

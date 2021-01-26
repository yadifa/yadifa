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
#include <fcntl.h>

#include <dnscore/file_output_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/format.h>
#include <dnscore/typebitmap.h>
#include <dnscore/base32hex.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb_zone_write.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_zone.h"


#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#include "dnsdb/dnsrdata.h"
#endif

/*
 * Without buffering:
 *
 * zdb_write_zone_text: 1245933248000 -> 1245933499739 (251739)
 *
 * With buffering:
 *
 * zdb_write_zone_text: 1245933590000 -> 1245933597877 (7877)
 *
 */

ya_result
zdb_zone_write_unbound(const zdb_zone* zone, const char* output_file)
{
    output_stream bos;
    output_stream fos;
    ya_result ret;

    if(FAIL(ret = file_output_stream_create(&fos, output_file, 0644)))
    {
        return ret;
    }

    if(FAIL(ret = buffer_output_stream_init(&bos, &fos, 4096)))
    {
        return ret;
    }

    char label_cstr[MAX_DOMAIN_LENGTH];

    osformat(&bos, "local-zone: \"%{dnsname}\" static\n", zone->origin);

    zdb_packed_ttlrdata* soa_ttlrdata = NULL;

    zdb_zone_label_iterator iter;
    btree_iterator records_iter;

    zdb_zone_label_iterator_init(&iter, zone);

    /*
     * Save each label, and its records.
     */

    while(zdb_zone_label_iterator_hasnext(&iter))
    {
        zdb_zone_label_iterator_nextname_to_cstr(&iter, label_cstr);

        zdb_rr_label* label = zdb_zone_label_iterator_next(&iter);

        soa_ttlrdata = zdb_record_find(&label->resource_record_set, TYPE_SOA);

        if(soa_ttlrdata != NULL)
        {
            u16 zclass = zdb_zone_getclass(zone);
            
            osformat(&bos, "local-data: \"%s %u %{dnsclass} SOA ", label_cstr, soa_ttlrdata->ttl, &zclass);
            ret = osprint_rdata(&bos, TYPE_SOA, ZDB_PACKEDRECORD_PTR_RDATAPTR(soa_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa_ttlrdata));
            osprintln(&bos, "\"");

            if(FAIL(ret))
            {
                osprintln(&bos, ";; ABOVE RECORD IS CORRUPTED");
            }
        }

        btree_iterator_init(label->resource_record_set, &records_iter);
        while(btree_iterator_hasnext(&records_iter))
        {
            btree_node* node = btree_iterator_next_node(&records_iter);

            u16 type = (u16)node->hash;

            if(type == TYPE_SOA)
            {
                continue;
            }

            zdb_packed_ttlrdata* ttlrdata_sll = (zdb_packed_ttlrdata*)node->data;

            while(ttlrdata_sll != NULL)
            {
                osformat(&bos, "local-data: \"%s %u %{dnstype} ", label_cstr, ttlrdata_sll->ttl, &type);
                ret = osprint_rdata(&bos, type, ZDB_PACKEDRECORD_PTR_RDATAPTR(ttlrdata_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(ttlrdata_sll));
                osprintln(&bos, "\"");

                if(FAIL(ret))
                {
                    osprintln(&bos, ";; ABOVE RECORD IS CORRUPTED");
                }

                ttlrdata_sll = ttlrdata_sll->next;
            }
        }
    }

    if(soa_ttlrdata == NULL)
    {
        return ZDB_ERROR_NOSOAATAPEX;
    }

#if ZDB_HAS_NSEC3_SUPPORT

    /*
     * If the zone is NSEC3, print the nsec3 data
     */

    if(zdb_record_find(&zone->apex->resource_record_set, TYPE_NSEC3PARAM) != NULL)
    {
        soa_rdata soa;

        zdb_record_getsoa(soa_ttlrdata, &soa);

        nsec3_zone* n3 = zone->nsec.nsec3;

        while(n3 != NULL)
        {
            u8 rdata[TYPE_BIT_MAPS_MAX_RDATA_SIZE];

            u32 rdata_hash_offset = NSEC3_ZONE_RDATA_SIZE(n3);

            MEMCOPY(rdata, &n3->rdata[0], NSEC3_ZONE_RDATA_SIZE(n3));

            nsec3_iterator nsec3_items_iter;
            nsec3_iterator_init(&n3->items, &nsec3_items_iter);

            if(nsec3_iterator_hasnext(&nsec3_items_iter))
            {
                nsec3_zone_item* first = nsec3_iterator_next_node(&nsec3_items_iter);
                nsec3_zone_item* item = first;
                nsec3_zone_item* next_item;

                u8 digest_len = NSEC3_NODE_DIGEST_SIZE(first);

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

                    rdata[1] = item->flags;

                    u32 rdata_size = rdata_hash_offset;

                    MEMCOPY(&rdata[rdata_size], next_item->digest, digest_len + 1);
                    rdata_size += digest_len + 1;

                    MEMCOPY(&rdata[rdata_size], item->type_bit_maps, item->type_bit_maps_size);
                    rdata_size += item->type_bit_maps_size;

                    osprint(&bos, "local-data: \"");
                    if(FAIL(ret = output_stream_write_base32hex(&bos, NSEC3_NODE_DIGEST_PTR(item), digest_len)))
                    {
                        return ret;
                    }

                    osformat(&bos, ".%{dnsname} %u NSEC3 ", zone->origin, soa.minimum);
                    osprint_rdata(&bos, TYPE_NSEC3, rdata, rdata_size);
                    osprintln(&bos, "\"");

                    zdb_packed_ttlrdata* rrsig = item->rrsig;

                    while(rrsig != NULL)
                    {
                        /*osformatln(&bos, ";; rrsig@%p", rrsig);*/

                        u16 type = TYPE_RRSIG;

                        osformat(&bos, "local-data: \"%{dnsname} %u %{dnstype} ", zone->origin, rrsig->ttl, &type); /* ${} requires a pointer to the data */

                        osprint_rdata(&bos, type, ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));

                        osprintln(&bos, "\"");

                        rrsig = rrsig->next;
                    }

                    item = next_item;
                }
                while(next_item != first);

            } /* If there is a first item*/

            n3 = n3->next;

        } /* while n3 != NULL */

    }

#endif

    /* The filter closes the filtered */

    output_stream_close(&bos);

    return SUCCESS;
}

/** @} */

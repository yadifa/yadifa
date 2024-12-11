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

#include "dnsdb/zdb_zone.h"

#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
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

ya_result zdb_zone_write_unbound(const zdb_zone_t *zone, const char *output_file)
{
    output_stream_t bos;
    output_stream_t fos;
    ya_result       ret;

    if(FAIL(ret = file_output_stream_create(&fos, output_file, 0644)))
    {
        return ret;
    }

    if(FAIL(ret = buffer_output_stream_init(&bos, &fos, 4096)))
    {
        return ret;
    }

    char label_cstr[DOMAIN_LENGTH_MAX];

    osformat(&bos, "local-zone: \"%{dnsname}\" static\n", zone->origin);

    zdb_resource_record_data_t *soa_rr = NULL;
    int32_t                     soa_ttl;

    zdb_zone_label_iterator_t   iter;

    zdb_zone_label_iterator_init(zone, &iter);

    /*
     * Save each label, and its records.
     */

    while(zdb_zone_label_iterator_hasnext(&iter))
    {
        zdb_zone_label_iterator_nextname_to_cstr(&iter, label_cstr);

        zdb_rr_label_t *label = zdb_zone_label_iterator_next(&iter);

        soa_rr = zdb_resource_record_sets_find_soa_and_ttl(&label->resource_record_set, &soa_ttl);

        if(soa_rr != NULL)
        {
            uint16_t zclass = zdb_zone_getclass(zone);

            osformat(&bos, "local-data: \"%s %u %{dnsclass} SOA ", label_cstr, soa_ttl, &zclass);
            ret = osprint_rdata(&bos, TYPE_SOA, zdb_resource_record_data_rdata(soa_rr), zdb_resource_record_data_rdata_size(soa_rr));
            osprintln(&bos, "\"");

            if(FAIL(ret))
            {
                osprintln(&bos, ";; ABOVE RECORD IS CORRUPTED");
            }
        }
        else
        {
            osprintln(&bos, ";; EXPECTED EXACTLY ONE SOA");
        }

        zdb_resource_record_sets_set_iterator_t records_iter;
        zdb_resource_record_sets_set_iterator_init(&label->resource_record_set, &records_iter);
        while(zdb_resource_record_sets_set_iterator_hasnext(&records_iter))
        {
            zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_iterator_next_node(&records_iter);
            uint16_t                         rtype = zdb_resource_record_set_type(&rrset_node->value);

            if(rtype == TYPE_SOA)
            {
                continue;
            }

            int32_t                                rttl = zdb_resource_record_set_ttl(&rrset_node->value);

            zdb_resource_record_set_const_t       *rrset = (zdb_resource_record_set_const_t *)&rrset_node->value;

            zdb_resource_record_set_const_iterator iter;
            zdb_resource_record_set_const_iterator_init(rrset, &iter);
            while(zdb_resource_record_set_const_iterator_has_next(&iter))
            {
                const zdb_resource_record_data_t *record = zdb_resource_record_set_const_iterator_next(&iter);

                osformat(&bos, "local-data: \"%s %u %{dnstype} ", label_cstr, rttl, &rtype);
                ret = osprint_rdata(&bos, rtype, zdb_resource_record_data_rdata_const(record), zdb_resource_record_data_rdata_size(record));
                osprintln(&bos, "\"");

                if(FAIL(ret))
                {
                    osprintln(&bos, ";; ABOVE RECORD IS CORRUPTED");
                }
            }
        }
    }

    if(soa_rr == NULL)
    {
        return ZDB_ERROR_NOSOAATAPEX;
    }

#if ZDB_HAS_NSEC3_SUPPORT

    /*
     * If the zone is NSEC3, print the nsec3 data
     */

    if(zdb_resource_record_sets_has_type(&zone->apex->resource_record_set, TYPE_NSEC3PARAM))
    {
        zdb_soa_rdata_t soa;

        zdb_record_getsoa(soa_rr, &soa);

        nsec3_zone_t *n3 = zone->nsec.nsec3;

        while(n3 != NULL)
        {
            uint8_t  rdata[TYPE_BIT_MAPS_RDATA_SIZE_MAX];

            uint32_t rdata_hash_offset = NSEC3PARAM_RDATA_SIZE_FROM_CHAIN(n3);

            MEMCOPY(rdata, &n3->rdata[0], NSEC3PARAM_RDATA_SIZE_FROM_CHAIN(n3));

            nsec3_iterator_t nsec3_items_iter;
            nsec3_iterator_init(&n3->items, &nsec3_items_iter);

            if(nsec3_iterator_hasnext(&nsec3_items_iter))
            {
                nsec3_zone_item_t *first = nsec3_iterator_next_node(&nsec3_items_iter);
                nsec3_zone_item_t *item = first;
                nsec3_zone_item_t *next_item;

                uint8_t            digest_len = NSEC3_NODE_DIGEST_SIZE(first);

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

                    uint32_t rdata_size = rdata_hash_offset;

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

                    const zdb_resource_record_set_t *rrset = item->rrsig_rrset;

                    if(rrset != NULL)
                    {
                        zdb_resource_record_set_const_iterator iter;
                        zdb_resource_record_set_const_iterator_init(rrset, &iter);
                        while(zdb_resource_record_set_const_iterator_has_next(&iter))
                        {
                            const zdb_resource_record_data_t *rrsig_record = zdb_resource_record_set_const_iterator_next(&iter);

                            /*osformatln(&bos, ";; rrsig@%p", rrsig);*/

                            uint16_t type = TYPE_RRSIG;

                            osformat(&bos, "local-data: \"%{dnsname} %u %{dnstype} ", zone->origin, zdb_resource_record_set_ttl(rrset), &type); /* ${} requires a pointer to the data */

                            osprint_rdata(&bos, type, zdb_resource_record_data_rdata_const(rrsig_record), zdb_resource_record_data_rdata_size(rrsig_record));

                            osprintln(&bos, "\"");
                        }
                    }

                    item = next_item;
                } while(next_item != first);

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

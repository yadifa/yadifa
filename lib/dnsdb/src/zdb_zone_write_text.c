/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
* DOCUMENTATION */
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
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

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


#if ZDB_NSEC3_SUPPORT!=0
#include "dnsdb/nsec3.h"
#endif

#define OUTPUT_BUFFER_SIZE  4096
#define DEFAULT_TTL	    86400
#define FILE_RIGHTS	    0644
#define INDENT_TABS	    5

static const char __TAB__[1] = {'\t'};
static const char __LF__[1] = {'\n'};

static void
osprint_tab_padded(output_stream* os, char* str, u32 len, u32 tabs)
{
    output_stream_write(os, (u8*)str, len);
    len >>= 3;
    if(tabs > len)
    {
        tabs -= len;
        while(tabs-- > 0)
        {
            output_stream_write(os, (u8*)__TAB__, 1);
        }
    }
}

ya_result
zdb_zone_write_text(const zdb_zone* zone, output_stream* fos, bool force_label)
{
    output_stream bos;

    ya_result ret;
    
    u32 current_ttl = DEFAULT_TTL;

    if(FAIL(ret = buffer_output_stream_init(fos, &bos, OUTPUT_BUFFER_SIZE)))
    {
        return ret;
    }

    char label_cstr[2 + MAX_DOMAIN_LENGTH + 1];

    u32 label_len;
    u32 origin_len = dnsname_len(zone->origin);
    
    {
        zdb_packed_ttlrdata* soa_ttlrdata = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);
        if(soa_ttlrdata != NULL)
        {
            current_ttl = soa_ttlrdata->ttl;
        }
    }
    
    osformat(&bos, "$ORIGIN %{dnsname}\n$TTL %u\n", zone->origin, current_ttl);

    zdb_zone_label_iterator iter;
    btree_iterator records_iter;

    zdb_zone_label_iterator_init(zone, &iter);

    /*
     * Save each label, and its records.
     */

    while(zdb_zone_label_iterator_hasnext(&iter))
    {       
        u32 len = zdb_zone_label_iterator_nextname_to_cstr(&iter, label_cstr);
        
        if(len != origin_len)
        {
            u32 n = len - origin_len;
            label_cstr[n] = '\0';
            label_len = n;

            if((n > 0) && (label_cstr[n - 1] == '.'))
            {
                label_cstr[n - 1] = '\0';
                label_len--;
            }
        }
        else
        {
            label_len = dnsname_to_cstr(label_cstr, zone->origin);
        }

        zdb_rr_label* label = zdb_zone_label_iterator_next(&iter);
        
        bool print_label = TRUE;

        zdb_packed_ttlrdata* soa_ttlrdata = zdb_record_find(&label->resource_record_set, TYPE_SOA);

        if(soa_ttlrdata != NULL)
        {
            if(print_label)
            {
                osprint_tab_padded(&bos, label_cstr, label_len, INDENT_TABS);

                u16 zclass = zdb_zone_getclass(zone);

                osformat(&bos, " %{dnsclass} SOA ", &zclass);

            }
            else
            {
                osprint_tab_padded(&bos, NULL, 0, INDENT_TABS);
            }

            ret = osprint_rdata(&bos, TYPE_SOA, ZDB_PACKEDRECORD_PTR_RDATAPTR(soa_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa_ttlrdata));

#ifndef NDEBUG
            osformatln(&bos, " ; flags=%04x", label->flags);
#else
            output_stream_write(&bos, (const u8*)__LF__, 1);
#endif

            if(FAIL(ret))
            {
                osprintln(&bos, ";; ABOVE RECORD IS CORRUPTED");
            }
            

            print_label = force_label;
        }
        
        if(dnscore_shuttingdown())
        {
            output_stream_close(&bos);

            return STOPPED_BY_APPLICATION_SHUTDOWN;
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
            
            u32 rrset_ttl = current_ttl;

            while(ttlrdata_sll != NULL)
            {
                if(print_label)
                {
                    osprint_tab_padded(&bos, label_cstr, label_len, INDENT_TABS);
                }
                else
                {
                    osprint_tab_padded(&bos, NULL, 0, INDENT_TABS);
                }
                
                if(ttlrdata_sll->ttl != rrset_ttl)
                {
                    rrset_ttl = ttlrdata_sll->ttl;
                    osformat(&bos," %5u", ttlrdata_sll->ttl);
                }

                osformat(&bos, " %{dnstype} ", &type);

                ret = osprint_rdata(&bos, type, ZDB_PACKEDRECORD_PTR_RDATAPTR(ttlrdata_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(ttlrdata_sll));
                
#ifndef NDEBUG
                osformatln(&bos, " ; flags=%04x", label->flags);
#else
                output_stream_write(&bos, (const u8*)__LF__, 1);
#endif

                if(FAIL(ret))
                {
                    osprintln(&bos, ";; ABOVE RECORD IS CORRUPTED");
                }

                print_label = force_label;

                ttlrdata_sll = ttlrdata_sll->next;
            }
        }
    }

#if ZDB_NSEC3_SUPPORT != 0

    /*
     * If the zone is NSEC3, print the nsec3 data
     */

    if(zdb_record_find(&zone->apex->resource_record_set, TYPE_NSEC3PARAM) != NULL)
    {
        const nsec3_zone* n3 = zone->nsec.nsec3;

        while(n3 != NULL)
        {
            u8 rdata[TYPE_BIT_MAPS_MAX_RDATA_SIZE];

            u32 rdata_hash_offset = NSEC3_ZONE_RDATA_SIZE(n3);

            MEMCOPY(rdata, &n3->rdata[0], NSEC3_ZONE_RDATA_SIZE(n3));

            nsec3_avl_iterator nsec3_items_iter;
            nsec3_avl_iterator_init(&n3->items, &nsec3_items_iter);

            if(nsec3_avl_iterator_hasnext(&nsec3_items_iter))
            {
                nsec3_zone_item* first = nsec3_avl_iterator_next_node(&nsec3_items_iter);
                nsec3_zone_item* item = first;
                nsec3_zone_item* next_item;

                u8 digest_len = NSEC3_NODE_DIGEST_SIZE(first);

                do
                {
                    if(dnscore_shuttingdown())
                    {
                        output_stream_close(&bos);

                        return STOPPED_BY_APPLICATION_SHUTDOWN;
                    }
                    
                    if(nsec3_avl_iterator_hasnext(&nsec3_items_iter))
                    {
                        next_item = nsec3_avl_iterator_next_node(&nsec3_items_iter);
                    }
                    else
                    {
                        next_item = first;
                    }

                    rdata[1] = item->flags;

#if 1	/* DEBUG */
                    if(item->rc == 1)
                    {
                        if(item->rc != 0)
                        {
                            if(item->label.owner != NSEC3_ZONE_FAKE_OWNER)
                            {
                                osformatln(&bos, ";; Owner: %{dnslabel}", item->label.owner->name);
                            }
                            else
                            {
                                osprintln(&bos, ";; Owner: FAKE (Owned by the parents of the zone)");
                            }
                        }
                        else
                        {
                            osprintln(&bos, ";; Owner: ERROR : RC=0");
                        }
                    }
                    else
                    {
                        if(item->rc > 0)
                        {
                            u16 i = item->rc - 1;
                            do
                            {
                                if(item->label.owners[i] != NSEC3_ZONE_FAKE_OWNER)
                                {
                                    osformatln(&bos, ";; Owner: %{dnslabel}", item->label.owners[i]->name);
                                }
                                else
                                {
                                    osprintln(&bos, ";; Owner: FAKE (Owned by the parents of the zone)");
                                }
                            }
                            while(i-- > 0);
                        }
                        else
                        {
                            osprintln(&bos, ";; NO OWNER");
                        }
                    }

                    if(item->sc <= 1)
                    {
                        if(item->sc != 0)
                        {
                            osformatln(&bos, ";; Star: %{dnslabel}", item->star_label.owner->name);
                        }
                    }
                    else
                    {
                        u16 i = item->sc - 1;
                        do
                        {
                            osformatln(&bos, ";; Star: %{dnslabel}", item->star_label.owners[i]->name);
                        }
                        while(i-- > 0);
                    }
#endif
                    u32 rdata_size = rdata_hash_offset;

                    MEMCOPY(&rdata[rdata_size], next_item->digest, digest_len + 1);
                    rdata_size += digest_len + 1;

                    MEMCOPY(&rdata[rdata_size], item->type_bit_maps, item->type_bit_maps_size);
                    rdata_size += item->type_bit_maps_size;

                    if(FAIL(output_stream_write_base32hex(&bos, NSEC3_NODE_DIGEST_PTR(item), digest_len)))
                    {
                        return ERROR;
                    }

                    osformat(&bos, ".%{dnsname} NSEC3 ", zone->origin);
                    osprint_rdata(&bos, TYPE_NSEC3, rdata, rdata_size);
                    osprintln(&bos, "");

                    zdb_packed_ttlrdata* rrsig = item->rrsig;

                    while(rrsig != NULL)
                    {
                        /*osformatln(&bos, ";; rrsig@%p", rrsig);*/

                        u16 type = TYPE_RRSIG;

                        osformat(&bos, "%40s %{dnstype} ", "", &type); /* ${} requires a pointer to the data */


                        osprint_rdata(&bos, type, ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));

                        osprintln(&bos, "");

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

/*
 * Without buffering:
 *
 * zdb_zone_write_text: 1245933248000 -> 1245933499739 (251739)
 *
 * With buffering:
 *
 * zdb_zone_write_text: 1245933590000 -> 1245933597877 (7877)
 *
 */

ya_result
zdb_zone_write_text_file(const zdb_zone* zone, const char* output_file, bool force_label)
{
    output_stream fos;
    ya_result ret;

    if(ISOK(ret = file_output_stream_create(output_file, FILE_RIGHTS, &fos)))
    {
        if(FAIL(ret = zdb_zone_write_text(zone, &fos, force_label)))
        {
            unlink(output_file);
        }
    }
    
    return ret;
}

/** @} */

/*----------------------------------------------------------------------------*/


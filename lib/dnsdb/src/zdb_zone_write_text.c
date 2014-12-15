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
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <dnscore/file_output_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/format.h>
#include <dnscore/typebitmap.h>
#include <dnscore/base32hex.h>

#include "dnsdb/zdb_zone_write.h"

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_zone.h"


#if ZDB_HAS_NSEC3_SUPPORT!=0
#include "dnsdb/nsec3.h"
#endif

#define OUTPUT_BUFFER_SIZE  4096
#define DEFAULT_TTL	    86400
#define FILE_RIGHTS	    0644
#define TAB_SIZE            8
#define TTL_SIZE            8
#define INDENT_SPACES       40
#define INDENT_TABS	    (INDENT_SPACES/TAB_SIZE)

/*
 * 0 1
 * 1 1
 * 2 1
 * 3 1
 * 4 2
 */

static const char __TAB__[1] = {'\t'};
static const char __LF__[1] = {'\n'};

static void
osprint_tab_padded(output_stream* os, char* str, u32 len, s32 tabs)
{
    output_stream_write(os, (u8*)str, len);
    
    tabs -= (len / TAB_SIZE) + 1;

    while(tabs-- > 0)
    {
        output_stream_write(os, (u8*)__TAB__, 1);
    }
}

#ifdef DEBUG
static void
zdb_zone_rr_label_flags_format(const void *value, output_stream *os, s32 padding, char pad_char, bool left_justified, void* reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    u32 flags = *((u16*)value);
    
    if((flags & ZDB_RR_LABEL_APEX) != 0)
    {
        output_stream_write(os, "A", 1);
    }
    
    if((flags & ZDB_RR_LABEL_NSEC) != 0)
    {
        output_stream_write(os, "1", 1);
    }
    
    if((flags & ZDB_RR_LABEL_NSEC3) != 0)
    {
        output_stream_write(os, "3", 1);
    }
    
    if((flags & ZDB_RR_LABEL_NSEC3_OPTOUT) != 0)
    {
        output_stream_write(os, "O", 1);
    }
    
    if((flags & ZDB_RR_LABEL_DNSSEC_EDIT) != 0)
    {
        output_stream_write(os, "E", 1);
    }
    
    if((flags & ZDB_RR_APEX_LABEL_FROZEN) != 0)
    {
        output_stream_write(os, "F", 1);
    }
    
    if((flags & ZDB_RR_LABEL_GOT_WILD) != 0)
    {
        output_stream_write(os, "*", 1);
    }
    
    if((flags & ZDB_RR_LABEL_UPDATING) != 0)
    {
        output_stream_write(os, "U", 1);
    }
    
    if((flags & ZDB_RR_LABEL_DELEGATION) != 0)
    {
        output_stream_write(os, "D", 1);
    }
    
    if((flags & ZDB_RR_LABEL_UNDERDELEGATION) != 0)
    {
        output_stream_write(os, "d", 1);
    }
    
    if((flags & ZDB_RR_LABEL_HASCNAME) != 0)
    {
        output_stream_write(os, "C", 1);
    }
    
    if((flags & ZDB_RR_LABEL_DROPCNAME) != 0)
    {
        output_stream_write(os, "c", 1);
    }
    
    if((flags & ZDB_RR_LABEL_INVALID_ZONE) != 0)
    {
        output_stream_write(os, "I", 1);
    }
}
#endif

ya_result
zdb_zone_write_text(const zdb_zone* zone, output_stream* fos, bool force_label)
{
    output_stream bos;

    ya_result ret;
    
    u32 current_ttl = DEFAULT_TTL;
    u32 soa_nttl = zone->min_ttl;
    u32 label_len;
    u32 origin_len;
    u32 dot_origin_len;
        
    if(FAIL(ret = buffer_output_stream_init(fos, &bos, OUTPUT_BUFFER_SIZE)))
    {
        return ret;
    }
    
#ifdef DEBUG
    format_writer status_flags_fw = {zdb_zone_rr_label_flags_format, NULL};
    osprintln(&bos, "; A=apex 1=NSEC 3=NSEC3 O=NSEC3-OPTOUT E=dnssec-edited F=frozen/loading *=wildcard present U=updating D=at-delegation d=under-delegation C=has-CNAME c=no-CNAME-allowed I=invalid-zone");
#endif

    char label_cstr[2 + MAX_DOMAIN_LENGTH + 1];

    origin_len = dnsname_len(zone->origin);
    
    {
        zdb_packed_ttlrdata* soa_ttlrdata = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);
        if(soa_ttlrdata != NULL)
        {
            current_ttl = soa_ttlrdata->ttl;
        }
    }
    
    char dot_origin[1 + MAX_DOMAIN_LENGTH + 1];
    
    dot_origin[0] = '.';
    dot_origin_len = dnsname_to_cstr(&dot_origin[1], zone->origin) + 1;
    
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

                osformat(&bos, "\t%{dnsclass}%tSOA%t", &zclass, (TTL_SIZE/TAB_SIZE) + 1, TTL_SIZE/TAB_SIZE);
            }
            else
            {
                osprint_tab_padded(&bos, NULL, 0, INDENT_TABS);
            }
            
            ret = osprint_rdata(&bos, TYPE_SOA, ZDB_PACKEDRECORD_PTR_RDATAPTR(soa_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa_ttlrdata));

#ifdef DEBUG
            status_flags_fw.value = &label->flags;
            osformatln(&bos, " ; flags=%w", &status_flags_fw);
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
            
            u32 rrset_ttl = ttlrdata_sll->ttl;

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
                
                
                if(current_ttl != rrset_ttl)
                {
                    current_ttl = rrset_ttl;
                    osformat(&bos, "\t%-" TOSTRING(TTL_SIZE) "u\t", current_ttl);
                }
                else
                {
                    osformat(&bos, "%t", 1 + (TTL_SIZE/TAB_SIZE) + 1);
                }

                osformat(&bos, "%{dnstype}%t", &type, (TTL_SIZE/TAB_SIZE));

                ret = osprint_rdata(&bos, type, ZDB_PACKEDRECORD_PTR_RDATAPTR(ttlrdata_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(ttlrdata_sll));
                
#ifdef DEBUG
                status_flags_fw.value = &label->flags;
                osformatln(&bos, " ; flags=%w", &status_flags_fw);
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

#if ZDB_HAS_NSEC3_SUPPORT != 0

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

#if DEBUG
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

                    ya_result hex32_len;
                    
                    if(FAIL(hex32_len = output_stream_write_base32hex(&bos, NSEC3_NODE_DIGEST_PTR(item), digest_len)))
                    {
                        return hex32_len;
                    }
                    
                    output_stream_write(&bos, (const u8*)dot_origin, dot_origin_len);
                    output_stream_write_u8(&bos, (u8)'\t');
                    
                    osformat(&bos, "%-" TOSTRING(TTL_SIZE) "u\tNSEC3\t", soa_nttl);
                    osprint_rdata(&bos, TYPE_NSEC3, rdata, rdata_size);
                    osprintln(&bos, "");

                    zdb_packed_ttlrdata* rrsig = item->rrsig;

                    while(rrsig != NULL)
                    {
                        u32 tabs = ((hex32_len+ dot_origin_len) / TAB_SIZE) + 1 + (TTL_SIZE/TAB_SIZE) + 1;

                        osformat(&bos, "%tRRSIG\t", tabs); /* ${} requires a pointer to the data */

                        osprint_rdata(&bos, TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));

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


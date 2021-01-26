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
#include <unistd.h>

#include <dnscore/file_output_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/format.h>
#include <dnscore/typebitmap.h>
#include <dnscore/base32hex.h>
#include <dnscore/fdtools.h>
#include <dnscore/random.h>
#include <dnscore/thread_pool.h>
#include <dnsdb/rrsig.h>
#include <dnsdb/nsec_collection.h>

#include "dnsdb/zdb_zone_write.h"

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_zone.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define ZDB_ZONE_WRITE_TEXT_USE_TTL_VAR 1

#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif

#define OUTPUT_BUFFER_SIZE  4096
#define DEFAULT_TTL	    86400
#define FILE_RIGHTS	    0644
#define TAB_SIZE            8
#define TTL_SIZE            8
#define INDENT_SPACES       40
#define INDENT_TABS	    (INDENT_SPACES/TAB_SIZE)

// escapes '@' and '$' symbols of fqdn in rdata

#define ZDB_ZONE_WRITE_TEXT_FILE_ESCAPE_RDATA 1

/*
 * 0 1
 * 1 1
 * 2 1
 * 3 1
 * 4 2
 */

static const char __TAB__[1] = {'\t'};
#if !DEBUG
static const char __LF__[1] = {'\n'};
#endif
static const char __ESCAPE__[1] = {'\\'};

static u32
zdb_zone_write_text_output_stream_write_escaped(output_stream *os, const char *str, u32 len)
{
    u32 additional_len = 0;
    for(u32 i = 0; i < len; ++i)
    {
        switch(str[i])
        {
            case '@':
            case '$':
            case '\r':
            case '\n':
            case '\t':
            case '\\':
                ++additional_len;
                output_stream_write(os, __ESCAPE__, 1);
                FALLTHROUGH // fall through
            default:
                output_stream_write(os, &str[i], 1);
        }
    }

    return len + additional_len;
}

static void
zdb_zone_write_text_fqdn_print(output_stream *os, char *str, u32 len, s32 tabs)
{
    if(str != NULL)
    {
#if 1 // handle escapes

#if _GNU_SOURCE
        char *str_limit = &str[len];
        *str_limit = '@';
        char *chrpos = rawmemchr(str, '@');
        if(chrpos == str_limit) // not found
        {
            *str_limit = '$';
            chrpos = rawmemchr(str, '$');

            if(chrpos == str_limit) // not found
            {
                output_stream_write(os, (u8*)str, len);
            }
            else
            {
                // write escaped
                len = zdb_zone_write_text_output_stream_write_escaped(os, str, len);
            }
        }
        else
        {
            // write escaped
            len = zdb_zone_write_text_output_stream_write_escaped(os, str, len);
        }
#else
        char *chrpos = memchr(str, '@', len);
        if(chrpos == NULL) // not found
        {
            chrpos = memchr(str, '$', len);

            if(chrpos == NULL) // not found
            {
                output_stream_write(os, (u8*)str, len);
            }
            else
            {
                // write escaped
                len = zdb_zone_write_text_output_stream_write_escaped(os, str, len);
            }
        }
        else
        {
            // write escaped
            len = zdb_zone_write_text_output_stream_write_escaped(os, str, len);
        }
#endif

#else // do not handle escapes

        output_stream_write(os, (u8*)str, len);
#endif
    }
    
    tabs -= (len / TAB_SIZE) + 1;

    while(tabs-- > 0)
    {
        output_stream_write(os, (u8*)__TAB__, 1);
    }
}

#if DEBUG
static void
zdb_zone_write_text_rr_label_flags_format(const void *value, output_stream *os, s32 padding, char pad_char,
                                          bool left_justified, void *reserved_for_method_parameters)
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
    
#if ZDB_HAS_NSEC_SUPPORT
    if((flags & ZDB_RR_LABEL_NSEC) != 0)
    {
        output_stream_write(os, "1", 1);
    }
#endif
    
#if ZDB_HAS_NSEC3_SUPPORT
    if((flags & ZDB_RR_LABEL_NSEC3) != 0)
    {
        output_stream_write(os, "3", 1);
    }

    if((flags & ZDB_RR_LABEL_NSEC3_OPTOUT) != 0)
    {
        output_stream_write(os, "O", 1);
    }
#endif

    if((flags & ZDB_RR_LABEL_GOT_WILD) != 0)
    {
        output_stream_write(os, "*", 1);
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

    if((flags & ZDB_RR_LABEL_N3COVERED) != 0)
    {
        output_stream_write(os, "S", 1);
    }
    
    if((flags & ZDB_RR_LABEL_N3OCOVERED) != 0)
    {
        output_stream_write(os, "s", 1);
    }
}
#endif

ya_result
zdb_zone_write_text_ex(zdb_zone *zone, output_stream *fos, bool force_label, bool allow_shutdown)
{
    ya_result ret;
    
    s32 current_ttl = DEFAULT_TTL;
#if ZDB_HAS_NSEC3_SUPPORT
    s32 soa_nttl = zone->min_ttl;
#endif
    u32 label_len;
    u32 origin_len;
#if ZDB_HAS_NSEC3_SUPPORT
    u32 dot_origin_len;
#endif
    u32 stored_serial = 0;
    
    yassert(zdb_zone_islocked_weak(zone));

    s64 wire_size = 0;
    
#if DEBUG
    format_writer status_flags_fw = {zdb_zone_write_text_rr_label_flags_format, NULL};
    osprintln(fos, "; A=apex 1=NSEC 3=NSEC3 O=NSEC3-OPTOUT *=wildcard present D=at-delegation d=under-delegation C=has-CNAME c=no-CNAME-allowed S=NSEC3-covered s=NSEC3-optout-covered");
#endif

    char label_cstr[2 + MAX_DOMAIN_LENGTH + 1];

    origin_len = dnsname_len(zone->origin);
    
    {
        zdb_packed_ttlrdata* soa_ttlrdata = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);
        if(soa_ttlrdata != NULL)
        {
            current_ttl = soa_ttlrdata->ttl;
            rr_soa_get_serial(ZDB_PACKEDRECORD_PTR_RDATAPTR(soa_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa_ttlrdata), &stored_serial);
        }
        else
        {
            log_err("%{dnsname}: no SOA record found at apex.");
        }
    }
    
#if ZDB_HAS_NSEC3_SUPPORT
    char dot_origin[1 + MAX_DOMAIN_LENGTH + 1];
    
    dot_origin[0] = '.';
    dot_origin_len = dnsname_to_cstr(&dot_origin[1], zone->origin) + 1;
#endif
    
    osformat(fos, "$ORIGIN %{dnsname}\n", zone->origin);
#if ZDB_ZONE_WRITE_TEXT_USE_TTL_VAR
    osformat(fos, "$TTL %u\n", current_ttl);
#endif

    zdb_zone_label_iterator iter;
    btree_iterator records_iter;

    zdb_zone_label_iterator_init(&iter, zone);

    /*
     * Save each label, and its records.
     */

    while(zdb_zone_label_iterator_hasnext(&iter))
    {       
        u32 len = zdb_zone_label_iterator_nextname_to_cstr(&iter, label_cstr);
        
        if(len != dot_origin_len)
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

#if DEBUG
        if(zdb_rr_label_flag_isset(label, (ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT)))
        {
            nsec3_label_extension *n3e = label->nsec.nsec3;
            while(n3e != NULL)
            {
                osformat(fos, ";; NSEC3:");
                
                if(n3e->_self != NULL)
                {
                    osformat(fos, " SELF: %{digest32h}", n3e->_self->digest);
                }
                else
                {
                    osformat(fos, " SELF: ERROR");
                }

                if(n3e->_star != NULL)
                {
                    osformat(fos, " STAR: %{digest32h}", n3e->_star->digest);
                }
                else
                {
                    osformat(fos, " STAR: ERROR");
                }

                osprintln(fos, "");
                
                n3e = n3e->_next;
            }
        }
        else if(zdb_rr_label_flag_isset(label, ZDB_RR_LABEL_NSEC))
        {
            osformat(fos, ";; NSEC:");

            nsec_node *nsec = label->nsec.nsec.node;

            if(nsec != NULL)
            {
                osformat(fos, " SELF: %{dnsname}", nsec->inverse_relative_name);
            }
            else
            {
                osformat(fos, " SELF: ERROR");
            }

            osprintln(fos, "");
        }
#endif // DEBUG
        
        bool print_label = TRUE;

        zdb_packed_ttlrdata* soa_ttlrdata = zdb_record_find(&label->resource_record_set, TYPE_SOA);

        if(soa_ttlrdata != NULL)
        {
            wire_size += origin_len + label_len + 10 + ZDB_PACKEDRECORD_PTR_RDATASIZE(soa_ttlrdata);

            if(print_label)
            {
                zdb_zone_write_text_fqdn_print(fos, label_cstr, label_len, INDENT_TABS);

                u16 zclass = zdb_zone_getclass(zone);

                osformat(fos, "\t%{dnsclass}%tSOA%t", &zclass, (TTL_SIZE/TAB_SIZE) + 1, TTL_SIZE/TAB_SIZE);
            }
            else
            {
                zdb_zone_write_text_fqdn_print(fos, NULL, 0, INDENT_TABS);
            }

#if !ZDB_ZONE_WRITE_TEXT_FILE_ESCAPE_RDATA
            ret = osprint_rdata(fos, TYPE_SOA, ZDB_PACKEDRECORD_PTR_RDATAPTR(soa_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa_ttlrdata));
#else
            ret = osprint_rdata_escaped(fos, TYPE_SOA, ZDB_PACKEDRECORD_PTR_RDATAPTR(soa_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa_ttlrdata));
#endif

#if DEBUG
            status_flags_fw.value = &label->_flags;
            osformatln(fos, " ; flags=%w (label@%p)", &status_flags_fw, label);
#else
            output_stream_write(fos, (const u8*)__LF__, 1);
#endif
            if(FAIL(ret))
            {
                osprintln(fos, ";; ABOVE RECORD IS CORRUPTED");
            }

            print_label = force_label;
        }
        
        if(allow_shutdown && dnscore_shuttingdown())
        {
            output_stream_close(fos);

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
            
            s32 rrset_ttl;

            while(ttlrdata_sll != NULL)
            {
                wire_size += origin_len + label_len + 10 + ZDB_PACKEDRECORD_PTR_RDATASIZE(ttlrdata_sll);

                if(print_label)
                {
                    zdb_zone_write_text_fqdn_print(fos, label_cstr, label_len, INDENT_TABS);
                }
                else
                {
                    zdb_zone_write_text_fqdn_print(fos, NULL, 0, INDENT_TABS);
                }

                if(type != TYPE_RRSIG)
                {
                    rrset_ttl = ttlrdata_sll->ttl;
                }
                else
                {
                    rrset_ttl = rrsig_get_original_ttl_from_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(ttlrdata_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(ttlrdata_sll));
                }
                
                if(current_ttl != rrset_ttl)
                {
#if !ZDB_ZONE_WRITE_TEXT_FILE_ESCAPE_RDATA
                    current_ttl = rrset_ttl;
#endif
                    osformat(fos, "\t%-" TOSTRING(TTL_SIZE) "u\t", rrset_ttl);
                }
                else
                {
                    osformat(fos, "%t", 1 + (TTL_SIZE/TAB_SIZE) + 1);
                }

                osformat(fos, "%{dnstype}%t", &type, (TTL_SIZE/TAB_SIZE));

#if !ZDB_ZONE_WRITE_TEXT_FILE_ESCAPE_RDATA
                ret = osprint_rdata(fos, type, ZDB_PACKEDRECORD_PTR_RDATAPTR(ttlrdata_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(ttlrdata_sll));
#else
                ret = osprint_rdata_escaped(fos, type, ZDB_PACKEDRECORD_PTR_RDATAPTR(ttlrdata_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(ttlrdata_sll));
#endif

                if(type == TYPE_DNSKEY)
                {
                    u16 tag = dnskey_get_tag_from_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(ttlrdata_sll), ZDB_PACKEDRECORD_PTR_RDATASIZE(ttlrdata_sll));
                    osformat(fos, " ; tag = %05u", tag);
                }
                
#if DEBUG
                status_flags_fw.value = &label->_flags;
                osformatln(fos, " ; flags=%w (label@%p)", &status_flags_fw, label);
#else
                output_stream_write(fos, (const u8*)__LF__, 1);
#endif
                if(FAIL(ret))
                {
                    osprintln(fos, ";; ABOVE RECORD IS CORRUPTED");
                }

                print_label = force_label;

                ttlrdata_sll = ttlrdata_sll->next;
            }
        }
        
#if DEBUG
        if(btree_isempty(label->resource_record_set))
        {
            osprint(fos, ";; ");
            output_stream_write(fos, label_cstr, label_len);
            
            status_flags_fw.value = &label->_flags;
            
            if(label->sub.count == 0)
            {
                osformatln(fos, " is empty terminal ; flags=%w (label@%p)", &status_flags_fw, label);
            }
            else
            {
                osformatln(fos, " is empty non-terminal ; flags=%w (label@%p)", &status_flags_fw, label);
            }
        }
#endif
    }

#if ZDB_HAS_NSEC3_SUPPORT

    /*
     * If the zone is NSEC3, print the nsec3 data
     */

    const nsec3_zone* n3 = zone->nsec.nsec3;

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
                if(allow_shutdown && dnscore_shuttingdown())
                {
                    output_stream_close(fos);

                    return STOPPED_BY_APPLICATION_SHUTDOWN;
                }

                if(nsec3_iterator_hasnext(&nsec3_items_iter))
                {
                    next_item = nsec3_iterator_next_node(&nsec3_items_iter);
                }
                else
                {
                    next_item = first;
                }

                rdata[1] = item->flags;
#if DEBUG
                if(nsec3_owner_count(item) == 1)
                {
                    if(nsec3_owner_count(item) != 0)
                    {
                        if(item->label.owner->name[0] != 0)
                        {
                            osformatln(fos, ";; Owner: %{dnslabel}", item->label.owner->name);
                        }
                        else
                        {
                            osformatln(fos, ";; Owner: %{dnslabel} (the apex)", zone->origin);
                        }
                    }
                    else
                    {
                        osprintln(fos, ";; Owner: ERROR : RC=0");
                    }
                }
                else
                {
                    if(nsec3_owner_count(item) > 0)
                    {
                        s32 i = nsec3_owner_count(item) - 1;
                        do
                        {
                            if(item->label.owners[i]->name[0] != 0)
                            {
                                osformatln(fos, ";; Owner: %{dnslabel}", item->label.owners[i]->name);
                            }
                            else
                            {
                                osformatln(fos, ";; Owner: %{dnslabel} (the apex)", zone->origin);
                            }
                        }
                        while(i-- > 0);
                    }
                    else
                    {
                        osprintln(fos, ";; NO OWNER");
                    }
                }

                if(item->sc <= 1)
                {
                    if(item->sc != 0)
                    {
                        if(item->star_label.owner->name[0] != 0)
                        {
                            osformatln(fos, ";; Star: %{dnslabel}", item->star_label.owner->name);
                        }
                        else
                        {
                            osformatln(fos, ";; Star: %{dnslabel} (the apex)", zone->origin);
                        }
                    }
                }
                else
                {
                    s32 i = item->sc - 1;
                    do
                    {
                        if(item->star_label.owners[i]->name[0] != 0)
                        {
                            osformatln(fos, ";; Star: %{dnslabel}", item->star_label.owners[i]->name);
                        }
                        else
                        {
                            osformatln(fos, ";; Star: %{dnslabel} (the apex)", zone->origin);
                        }
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

                if(FAIL(hex32_len = output_stream_write_base32hex(fos, NSEC3_NODE_DIGEST_PTR(item), digest_len)))
                {
                    return hex32_len;
                }

                wire_size += origin_len + hex32_len + 10 + rdata_size;

                output_stream_write(fos, (const u8*)dot_origin, dot_origin_len);
                output_stream_write_u8(fos, (u8)'\t');

                osformat(fos, "%-" TOSTRING(TTL_SIZE) "u\tNSEC3\t", soa_nttl);
                osprint_rdata(fos, TYPE_NSEC3, rdata, rdata_size);
                osprintln(fos, "");

                zdb_packed_ttlrdata* rrsig = item->rrsig;

                while(rrsig != NULL)
                {
                    u32 tabs = ((hex32_len+ dot_origin_len) / TAB_SIZE) + 1;
                    s32 rrsig_ttl = rrsig_get_original_ttl_from_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));

                    wire_size += origin_len + hex32_len + 10 + ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig);

#if ZDB_ZONE_WRITE_TEXT_FILE_ESCAPE_RDATA
                    if(rrsig_ttl != current_ttl)
                    {
                        osformat(fos, "%t%-" TOSTRING(TTL_SIZE) "u\tRRSIG\t", tabs, rrsig_ttl);
                    }
                    else
                    {
                        tabs += (TTL_SIZE/TAB_SIZE) + 1;
                        osformat(fos, "%tRRSIG\t", tabs); /* ${} requires a pointer to the data */
                    }
#else
                    if(rrsig_ttl != soa_nttl)
                    {
                        osformat(fos, "%t%-" TOSTRING(TTL_SIZE) "u\tRRSIG\t", tabs, rrsig_ttl);
                    }
                    else
                    {
                        tabs += (TTL_SIZE/TAB_SIZE) + 1;
                        osformat(fos, "%tRRSIG\t", tabs); /* ${} requires a pointer to the data */
                    }
#endif

#if !ZDB_ZONE_WRITE_TEXT_FILE_ESCAPE_RDATA
                    osprint_rdata(fos, TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));
#else
                    osprint_rdata_escaped(fos, TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));
#endif
                    osprintln(fos, "");

                    rrsig = rrsig->next;
                }

                item = next_item;
            }
            while(next_item != first);

        } /* If there is a first item*/

        n3 = n3->next;

    } /* while n3 != NULL */

#endif

    zone->text_serial = stored_serial;
    zone->wire_size = wire_size;

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

/**
 * 
 * Zone MUST be locked 
 * Note that the one caller locks the zone.
 * 
 * @param zone
 * @param output_file
 * @param force_label
 * @return 
 */

/**
 * 
 * Zone MUST be locked 
 * Note that the one caller locks the zone.
 * 
 * @param zone
 * @param output_file
 * @param force_label
 * @return 
 */

ya_result
zdb_zone_write_text_file(zdb_zone* zone, const char* output_file, u8 flags)
{
    output_stream fos;
    ya_result ret;
    random_ctx rnd = thread_pool_get_random_ctx();
    if(rnd == NULL)
    {
        thread_pool_setup_random_ctx();
        rnd = thread_pool_get_random_ctx();
    }
    
    bool force_label = flags & ZDB_ZONE_WRITE_TEXT_FILE_FORCE_LABEL;
    bool allow_shutdown = flags & ZDB_ZONE_WRITE_TEXT_FILE_IGNORE_SHUTDOWN;
    char tmp[PATH_MAX];
    
    size_t output_file_len = strlen(output_file);
    
    if(output_file_len >= PATH_MAX)
    {
        return ERROR;
    }
    
    if(PATH_MAX - output_file_len >= 8)
    {   
        do
        {
            u32 rndval = random_next(rnd);
            if(FAIL(ret = snformat(tmp, sizeof(tmp), "%s%08x", output_file, rndval)))
            {
                return ret;
            }
        }
        while(file_exists(tmp) && !dnscore_shuttingdown());
    }
    else if(PATH_MAX - output_file_len >= 4)
    {
        do
        {
            u32 rndval = random_next(rnd);
#if DEBUG
            ret = 
#endif
            snformat(tmp, sizeof(tmp), "%s%04x", output_file, rndval & 0xffffU);
#if DEBUG
            yassert(ISOK(ret));
#endif
        }
        while(file_exists(tmp) && !dnscore_shuttingdown());
    }
    else
    {
        log_warn("%{dnsname}: path '%s' is too long to allow temporary random suffix, shutdown not allowed while saving the file", zone->origin, output_file);
        allow_shutdown = FALSE;
    }
    
    if(ISOK(ret = file_output_stream_create(&fos, tmp, FILE_RIGHTS)))
    {
        if(ISOK(ret = buffer_output_stream_init(&fos, &fos, OUTPUT_BUFFER_SIZE)))
        {
            ret = zdb_zone_write_text_ex(zone, &fos, force_label, allow_shutdown);

            output_stream_close(&fos);

            if(ISOK(ret)) // zone is locked
            {
                if(file_is_link(output_file) > 0)
                {
                    if(unlink(output_file) < 0)
                    {
                        log_warn("%{dnsname}: could not delete symbolic link '%s': %r", zone->origin, output_file, ERRNO_ERROR);
                    }
                }

                if(rename(tmp, output_file) >= 0)
                {
                    log_info("%{dnsname}: saved as '%s'", zone->origin, output_file);

                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_MODIFIED);

                    return SUCCESS;
                }
                else
                {
                    log_err("%{dnsname}: could not move temporary file '%s' to overwrite '%s': %r", zone->origin, output_file, ERRNO_ERROR);
                    return ERROR;
                }
            }
            else
            {
                log_warn("%{dnsname}: could not write '%s', cleaning up: %r", zone->origin, tmp, ret);
                unlink(tmp);
            }
        }
        else
        {
            log_warn("%{dnsname}: could not bufferize '%s', cleaning up: %r", zone->origin, tmp, ret);
            output_stream_close(&fos);
            unlink(tmp);
        }
    }
    else
    {
        log_err("%{dnsname}: could not create '%s': %r", zone->origin, tmp, ret);
    }

    return ret;
}

/** @} */

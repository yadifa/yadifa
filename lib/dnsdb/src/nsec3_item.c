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

/** @defgroup nsec3 NSEC3 functions
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
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/output_stream.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/logger.h>

#include "dnsdb/zdb_record.h"

#include "dnsdb/nsec3_item.h"
#include "dnsdb/nsec3_owner.h"
#include "dnsdb/nsec3_zone.h"

#include "dnsdb/rrsig.h"

#include <dnscore/base32hex.h>

#define MODULE_MSG_HANDLE g_dnssec_logger

extern logger_handle *g_dnssec_logger;

/**
 * Finds the nsec3 record starting the interval based on the binary digest
 * 
 * @param n3
 * @param digest
 * @return 
 */

nsec3_zone_item*
nsec3_zone_item_find_encloser_start(const nsec3_zone* n3, const u8* digest)
{
    return nsec3_find_interval_start(&n3->items, (u8*)digest);
}

nsec3_zone_item*
nsec3_zone_item_find(const nsec3_zone* n3, const u8* digest)
{
    return nsec3_find(&n3->items, (u8*)digest);
}

/**
 * Finds an nsec3 record matching the label
 * 
 * @param n3
 * @param digest
 * @return 
 */


nsec3_zone_item*
nsec3_zone_item_find_by_name(const nsec3_zone* n3, const u8* nsec3_label)
{
    u8 digest[256];
    
    ya_result digest_len = base32hex_decode((char*)&nsec3_label[1], nsec3_label[0], &digest[1]);
    
    if(ISOK(digest_len))
    {
        digest[0] = digest_len;

        return nsec3_find(&n3->items, digest);
    } 
    else
    {
        return NULL;
    }
}

nsec3_zone_item*
nsec3_zone_item_find_by_name_ext(const zdb_zone *zone, const u8 *fqdn, nsec3_zone **out_n3)
{
    nsec3_zone *n3 = zone->nsec.nsec3;
    nsec3_zone_item *n3zi = NULL;

    while(n3 != NULL)
    {
        if((n3zi = nsec3_zone_item_find_by_name(n3, fqdn)) != NULL)
        {
            break;
        }

        n3 = n3->next;
    }

    if(out_n3 != NULL)
    {
        *out_n3 = n3;
    }

    return n3zi;
}

nsec3_zone_item*
nsec3_zone_item_find_by_record(const zdb_zone *zone, const u8 *fqdn, u16 rdata_size, const u8 *rdata)
{
    const nsec3_zone *n3 = nsec3_zone_get_from_rdata(zone, rdata_size, rdata);
    
    nsec3_zone_item *n3zi = NULL;
    
    if(n3 != NULL)
    {
        n3zi = nsec3_zone_item_find_by_name(n3, fqdn);
    }

    return n3zi;
}

bool
nsec3_zone_item_equals_rdata(const nsec3_zone* n3,
                             const nsec3_zone_item *item,
                             u16 rdata_size,
                             const u8* rdata)
{
    u32 param_rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
    u8 hash_len = NSEC3_NODE_DIGEST_SIZE(item);
    u32 type_bit_maps_size = item->type_bit_maps_size;

    u32 item_rdata_size = param_rdata_size + 1 + hash_len + type_bit_maps_size;

    if(item_rdata_size != rdata_size)
    {
        return FALSE;
    }

    /* Do not check the flags */

    if(nsec3param_compare_by_rdata(rdata, n3->rdata) != 0)
    {
        return FALSE;
    }

    const u8 *p = &rdata[param_rdata_size];

    nsec3_zone_item* next = nsec3_node_mod_next(item);

    if(memcmp(p, next->digest, hash_len + 1) != 0)
    {
#if DEBUG_LEVEL >= 9
        //nsec3_find_debug(&n3->items, item->digest);
        //nsec3_find_debug(&n3->items, next->digest);
        //bool exists = nsec3_find_debug(&n3->items, p) != NULL;
        
        log_debug("nsec3_zone_item_equals_rdata: REJECT: %{digest32h} NSEC3 ... %{digest32h} was expected to be followed by %{digest32h}",
                 item->digest, next->digest, p);
#endif
        return FALSE;
    }

    p += hash_len + 1;

    return memcmp(p, item->type_bit_maps, item->type_bit_maps_size) == 0;
}

bool
nsec3_zone_item_equals_rdata_lenient(const nsec3_zone* n3,
                             const nsec3_zone_item *item,
                             u16 rdata_size,
                             const u8* rdata)
{
    u32 param_rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
    u8 hash_len = NSEC3_NODE_DIGEST_SIZE(item);
    //u32 type_bit_maps_size = item->type_bit_maps_size;

    u32 item_rdata_size = param_rdata_size + 1 + hash_len /*+ type_bit_maps_size*/;

    if(item_rdata_size > rdata_size)
    {
        return FALSE;
    }

    /* Do not check the flags */

    if(nsec3param_compare_by_rdata(rdata, n3->rdata) != 0)
    {
        return FALSE;
    }

    const u8 *p = &rdata[param_rdata_size];

    nsec3_zone_item* next = nsec3_node_mod_next(item);

    if(memcmp(p, next->digest, hash_len + 1) != 0)
    {
#if DEBUG_LEVEL >= 9
        //nsec3_find_debug(&n3->items, item->digest);
        //nsec3_find_debug(&n3->items, next->digest);
        //bool exists = nsec3_find_debug(&n3->items, p) != NULL;
        
        log_debug("nsec3_zone_item_equals_rdata: REJECT: %{digest32h} NSEC3 ... %{digest32h} was expected to be followed by %{digest32h}",
                 item->digest, next->digest, p);
#endif
        return FALSE;
    }

    // p += hash_len + 1;    
    // memcmp(p, item->type_bit_maps, item->type_bit_maps_size) == 0

    return TRUE;
}


/**
 *
 * @param n3
 * @param item
 * @param origin
 * @param out_owner
 * @param nsec3            output buffer
 * @param nsec3_max_size   output_buffer rdata size
 * @param out_nsec3_rrsig  return value, if not NULL, it's a reference into the DB
 */

ya_result
nsec3_zone_item_to_zdb_packed_ttlrdata(const nsec3_zone* n3,
                                       const nsec3_zone_item* item,
                                       const u8* origin,
                                       u8* out_owner, /* dnsname */
                                       u32 ttl,
                                       zdb_packed_ttlrdata* nsec3,
                                       u32 nsec3_max_size)
{
    u32 param_rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
    u8 hash_len = NSEC3_NODE_DIGEST_SIZE(item);
    u32 type_bit_maps_size = item->type_bit_maps_size;

    /* Whatever the editor says: rdata_size is used. */
    u32 rdata_size = param_rdata_size + 1 + hash_len + type_bit_maps_size;

    if(nsec3_max_size < rdata_size)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    /*
     * NOTE: ZALLOC SHOULD NEVER BE USED IN MT
     *
     */

    nsec3->ttl = ttl;
    nsec3->rdata_size = rdata_size;

    nsec3->next = NULL;

    u8* p = &nsec3->rdata_start[0];

    MEMCOPY(p, &n3->rdata[0], param_rdata_size);
    p += param_rdata_size;

    nsec3_zone_item* next = nsec3_node_mod_next(item);

    MEMCOPY(p, next->digest, hash_len + 1);
    p += hash_len + 1;

    MEMCOPY(p, item->type_bit_maps, item->type_bit_maps_size);

    u32 b32_len = base32hex_encode(NSEC3_NODE_DIGEST_PTR(item), hash_len, (char*)& out_owner[1]);
    out_owner[0] = b32_len;

    u32 origin_len = dnsname_len(origin);
    MEMCOPY(&out_owner[1 + b32_len], origin, origin_len);

    nsec3->rdata_start[1] = item->flags & 1; /* Opt-Out or Opt-In */
    
    return rdata_size;
}

/**
 *
 * @param n3
 * @param item
 * @param origin
 * @param out_owner
 * @param out_nsec3         return value, if not NULL, it is allocated by a malloc
 * @param out_nsec3_rrsig   return value, if not NULL, it's a reference into the DB
 */

void
nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                                       nsec3_zone_item_to_new_zdb_packed_ttlrdata_parm *nsec3_parms,
                                       u8** out_owner_p, /* dnsname */
                                       zdb_packed_ttlrdata** out_nsec3,
                                       const zdb_packed_ttlrdata** out_nsec3_rrsig)
{
    const nsec3_zone* n3 = nsec3_parms->n3;
#if DEBUG
    if(n3 == NULL)
    {
        log_err("%{dnsname}: missing NSEC3 chain", nsec3_parms->origin);

        if(out_owner_p != NULL)
        {
            *out_owner_p = NULL;
        }
        if(out_nsec3 != NULL)
        {
            *out_nsec3 = NULL;
        }
        if(out_nsec3_rrsig != NULL)
        {
            *out_nsec3_rrsig = NULL;
        }
        return;
    }
#endif
    u32 param_rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
    const nsec3_zone_item* item = nsec3_parms->item;
#if DEBUG
    if(n3 == NULL)
    {
        log_err("%{dnsname}: missing NSEC3 record", nsec3_parms->origin);

        if(out_owner_p != NULL)
        {
            *out_owner_p = NULL;
        }
        if(out_nsec3 != NULL)
        {
            *out_nsec3 = NULL;
        }
        if(out_nsec3_rrsig != NULL)
        {
            *out_nsec3_rrsig = NULL;
        }
        return;
    }
#endif
    u8 hash_len = NSEC3_NODE_DIGEST_SIZE(nsec3_parms->item);
    u32 type_bit_maps_size = item->type_bit_maps_size;

    /* Whatever the editor says: rdata_size is used. */
    u32 rdata_size = param_rdata_size + 1 + hash_len + type_bit_maps_size;

    zdb_packed_ttlrdata* nsec3;

    // ZDB_RECORD_MALLOC_EMPTY(nsec3, nsec3_parms->ttl, rdata_size);
    
    u8 * restrict * pool = nsec3_parms->pool;
    nsec3 = (zdb_packed_ttlrdata*)*pool;
    *pool += ALIGN16(ZDB_RECORD_SIZE_FROM_RDATASIZE(rdata_size));
    nsec3->next = NULL;
    nsec3->ttl = nsec3_parms->ttl;
    nsec3->rdata_size = rdata_size;

    u8* p = &nsec3->rdata_start[0];

    MEMCOPY(p, &n3->rdata[0], param_rdata_size);
    p += param_rdata_size;

    nsec3_zone_item* next = nsec3_node_mod_next(item);

    MEMCOPY(p, next->digest, hash_len + 1);
    p += hash_len + 1;

    MEMCOPY(p, item->type_bit_maps, item->type_bit_maps_size);

    u8 *out_owner = *pool;
    *out_owner_p = out_owner;
    
    u32 b32_len = base32hex_encode(NSEC3_NODE_DIGEST_PTR(item), hash_len, (char*)&out_owner[1]);
    out_owner[0] = b32_len;

    const u8 *origin = nsec3_parms->origin;
    
    u32 origin_len = dnsname_len(origin);
    MEMCOPY(&out_owner[1 + b32_len], origin, origin_len);
    
    *pool += ALIGN16(1 + b32_len + origin_len);

    nsec3->rdata_start[1] = item->flags & 1; /* Opt-Out or Opt-In */

    *out_nsec3 = nsec3;
    *out_nsec3_rrsig = item->rrsig;
}

u32
nsec3_zone_item_rdata_size(const nsec3_zone* n3,
                           const nsec3_zone_item *item)
{
    u32 param_rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
    u8 hash_len = NSEC3_NODE_DIGEST_SIZE(item);
    u32 type_bit_maps_size = item->type_bit_maps_size;

    /* Whatever the editor says: rdata_size is used. */
    u32 rdata_size = param_rdata_size + 1 + hash_len + type_bit_maps_size;
    return rdata_size;
}

u16
nsec3_zone_item_to_rdata(
    const nsec3_zone* n3,
    const nsec3_zone_item *item,
    u8 *out_rdata, u16 out_rdata_size)
{
    u32 param_rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
    u8 hash_len = NSEC3_NODE_DIGEST_SIZE(item);
    u32 type_bit_maps_size = item->type_bit_maps_size;

    /* Whatever the editor says: rdata_size is used. */
    u32 rdata_size = param_rdata_size + 1 + hash_len + type_bit_maps_size;

    yassert(out_rdata_size >= rdata_size);

    if(out_rdata_size < rdata_size)
    {
        log_err("nsec3_zone_item_to_rdata: buffer would overflow");
        return 0;
    }

    u8* p = out_rdata;

    MEMCOPY(p, &n3->rdata[0], param_rdata_size);
    p[1] = item->flags & 1; /* Opt-Out or Opt-In */

    p += param_rdata_size;

    nsec3_zone_item* next = nsec3_node_mod_next(item);

    MEMCOPY(p, next->digest, hash_len + 1);
    p += hash_len + 1;

    MEMCOPY(p, item->type_bit_maps, item->type_bit_maps_size);

    return rdata_size;
}

u32
nsec3_zone_item_get_label(const nsec3_zone_item* item,
                          u8* output_buffer,
                          u32 buffer_size
                          )
{
    yassert(buffer_size >= 128);
    (void)buffer_size;
    u8 hash_len = NSEC3_NODE_DIGEST_SIZE(item);
    u32 b32_len = base32hex_encode(NSEC3_NODE_DIGEST_PTR(item), hash_len, (char*)&output_buffer[1]);
    output_buffer[0] = b32_len;

    return b32_len + 1;
}

void
nsec3_zone_item_write_owner(output_stream* os,
                            const nsec3_zone_item* item,
                            const u8* origin
                            )
{
    u8 tmp[128]; /* enough to get a 64 bit digest printed as base32hex */

    u32 label_len = nsec3_zone_item_get_label(item, tmp, sizeof(tmp));

    output_stream_write(os, tmp, label_len);

    u32 origin_len = dnsname_len(origin);

    output_stream_write(os, origin, origin_len);
}

void
nsec3_item_format_writer_callback(const void *args_, output_stream *os, s32 padding, char pad_char, bool left_justified, void *reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;

    nsec3_item_format_writer_args *args = (nsec3_item_format_writer_args*)args_;
    output_stream nsec3_wire_os;
    bytearray_output_stream_context nsec3_wire_os_context;
    u8 *wire;
    u8 nsec3_wire_tmp[512]; /* enough for most cases */
    
    bytearray_output_stream_init_ex_static(&nsec3_wire_os, (u8*)nsec3_wire_tmp, sizeof(nsec3_wire_tmp), 0, &nsec3_wire_os_context);
    nsec3_zone_item_to_output_stream(&nsec3_wire_os, args->n3, args->item, args->origin, args->ttl);
    
    wire = bytearray_output_stream_buffer(&nsec3_wire_os);
    
    osformat(os, "%{recordwire}", wire);
}

void
nsec3_zone_item_to_output_stream(output_stream* os,
                                 const nsec3_zone* n3,
                                 const nsec3_zone_item* item,
                                 const u8* origin,
                                 u32 ttl)
{
    u32 param_rdata_size;
    u32 type_bit_maps_size;
    u32 rdata_size;
    u32 b32_len;
    u32 origin_len;
    u8 hash_len;
    u8 tmp[128]; /* enough to get a 64 bit digest printed as base32hex */
    
    param_rdata_size = NSEC3_ZONE_RDATA_SIZE(n3);
    hash_len = NSEC3_NODE_DIGEST_SIZE(item);
    type_bit_maps_size = item->type_bit_maps_size;

    /* Whatever the editor says: rdata_size is used. */
    rdata_size = param_rdata_size + 1 + hash_len + type_bit_maps_size;
    
    b32_len = base32hex_encode(NSEC3_NODE_DIGEST_PTR(item), hash_len, (char*)&tmp[1]);
    tmp[0] = b32_len;

    /* NAME */

    output_stream_write(os, tmp, b32_len + 1);

    origin_len = dnsname_len(origin);

    output_stream_write(os, origin, origin_len);

    /* TYPE */

    output_stream_write_u16(os, TYPE_NSEC3); /** @note NATIVETYPE */

    /* CLASS */

    output_stream_write_u16(os, CLASS_IN); /** @note NATIVECLASS */

    /* TTL */

    output_stream_write_nu32(os, ttl);

    /* RDATA SIZE */

    output_stream_write_nu16(os, rdata_size);

    /* RDATA */

    output_stream_write_u8(os, n3->rdata[0]);

    output_stream_write_u8(os, item->flags);

    output_stream_write(os, &n3->rdata[2], param_rdata_size - 2);

    nsec3_zone_item* next = nsec3_node_mod_next(item);

    output_stream_write(os, next->digest, hash_len + 1);

    output_stream_write(os, item->type_bit_maps, item->type_bit_maps_size);
}

void
nsec3_zone_item_rrsig_del_by_keytag(nsec3_zone_item *item, u16 native_key_tag)
{
    if(item->rrsig != NULL)
    {
        zdb_packed_ttlrdata **rrsigp = &item->rrsig;

        do
        {
            zdb_packed_ttlrdata *rrsig = *rrsigp;
            
            if(RRSIG_KEY_NATIVETAG(rrsig) ==  native_key_tag)
            {
                /* Remove from the list */
                *rrsigp = rrsig->next;
                ZDB_RECORD_ZFREE(rrsig);
                break;
            }

            rrsigp = &rrsig->next;
        }
        while(*rrsigp != NULL);
    }
}

void
nsec3_zone_item_rrsig_del(nsec3_zone_item *item, const zdb_ttlrdata *nsec3_rrsig)
{
    if(item->rrsig != NULL)
    {
        while(nsec3_rrsig != NULL)
        {
            zdb_packed_ttlrdata** rrsigp = &item->rrsig;

            // look for a match

            zdb_packed_ttlrdata* rrsig;

            while((rrsig = *rrsigp) != NULL)
            {
                if(zdb_record_equals_unpacked(rrsig, nsec3_rrsig))
                {
                    /* Remove from the list */
                    *rrsigp = rrsig->next;
                    ZDB_RECORD_ZFREE(rrsig);
                    break;
                }

                rrsigp = &rrsig->next;
            }

            nsec3_rrsig = nsec3_rrsig->next;
        }
    }
}

void
nsec3_zone_item_rrsig_add(nsec3_zone_item *item, zdb_packed_ttlrdata *nsec3_rrsig)
{
    if(item->rrsig == NULL)
    {
        item->rrsig = nsec3_rrsig;
    }
    else
    {        
        zdb_packed_ttlrdata *good = NULL;
        zdb_packed_ttlrdata *rrsig;
        
        while(nsec3_rrsig != NULL)
        {
            /* look for the first item on the list */

            rrsig = item->rrsig;
            
            bool add = TRUE;
            
            do
            {
                /* Replaces another signature ? */

                if(zdb_record_equals(rrsig, nsec3_rrsig))
                {               
                    add = FALSE;
                    break;                    
                }
                
                rrsig = rrsig->next;
            }
            while(rrsig != NULL);
            
            zdb_packed_ttlrdata *tmp = nsec3_rrsig->next;
            
            if(add)
            {
                nsec3_rrsig->next = good;
                good = nsec3_rrsig;
            }
            else
            {
                ZDB_RECORD_ZFREE(nsec3_rrsig);
            }
            
            nsec3_rrsig = tmp;
        }
        
        if(good != NULL)
        {
            rrsig = item->rrsig;
            
            while(rrsig->next != NULL)
            {
                rrsig = rrsig->next;
            }
            
            rrsig->next = good;
        }
        
    }
}

void
nsec3_zone_item_rrsig_delete_all(nsec3_zone_item *item)
{
    zdb_packed_ttlrdata *rrsig_sll = item->rrsig;

    item->rrsig = NULL;

    while(rrsig_sll != NULL)
    {
        zdb_packed_ttlrdata *tmp = rrsig_sll;

        rrsig_sll = rrsig_sll->next;

        ZDB_RECORD_ZFREE(tmp);
    }
}

/*
 * Empties an nsec3_zone_item
 *
 * Only frees the payload : owners, stars, bitmap, rrsig
 * Does not change the other nodes of the structure
 *
 * This should be followed by the destruction of the item
 */

void
nsec3_zone_item_empties(nsec3_zone_item *item)
{
    nsec3_item_remove_all_star(item);
    nsec3_item_remove_all_owners(item);

    yassert(item->rc == 0 && item->sc == 0);

    ZFREE_ARRAY(item->type_bit_maps, item->type_bit_maps_size);

    item->type_bit_maps = NULL;
    item->type_bit_maps_size = 0;

    nsec3_zone_item_rrsig_delete_all(item);
    item->flags = NSEC3_FLAGS_MARKED_FOR_ICMTL_DEL;
}

/**
 * Sets the type bitmap of the nsec3 item to match the one in the rdata
 * Does nothing if the bitmap is already ok
 *
 * NOTE: Remember that the item does not contain
 *
 *  _ hash_algorithm
 *  _ iterations
 *  _ salt_length
 *  _ salt
 *  _ hash_length
 *  _ next_hashed_owner_name
 */

ya_result
nsec3_zone_item_update_bitmap(nsec3_zone_item* nsec3_item, const u8 *rdata, u16 rdata_size)
{
    /*
     * Skip the irrelevant bytes
     */

    if(rdata_size < 8)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    const u8 *bitmap = rdata;
    u16 type_bit_maps_size = rdata_size;

    // skip hash + flags + iterations
    
    bitmap += 4;
    type_bit_maps_size -= 4;

    // skip salt length + salt (and checks)
    
    if(type_bit_maps_size < *bitmap + 1)
    {
        return INCORRECT_RDATA;
    }

    type_bit_maps_size -= *bitmap + 1;
    bitmap += *bitmap + 1;
    
    // skip hash length + hash (and checks)

    if(type_bit_maps_size < *bitmap + 1)
    {
        return INCORRECT_RDATA;
    }
    
    type_bit_maps_size -= *bitmap + 1;
    bitmap += *bitmap + 1;

    /*
     * If it does not match, replace.
     */

    if((nsec3_item->type_bit_maps_size != type_bit_maps_size) || (memcmp(nsec3_item->type_bit_maps, bitmap, type_bit_maps_size) != 0))
    {
        /* If the (bloc) size differs : free and alloc */

        if(zalloc_memory_block_size(nsec3_item->type_bit_maps_size) != zalloc_memory_block_size(type_bit_maps_size))
        {
            ZFREE_ARRAY(nsec3_item->type_bit_maps, nsec3_item->type_bit_maps_size);
            ZALLOC_ARRAY_OR_DIE(u8*, nsec3_item->type_bit_maps, type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);
        }

        memcpy(nsec3_item->type_bit_maps, bitmap, type_bit_maps_size);
        nsec3_item->type_bit_maps_size = type_bit_maps_size;
    }

    return SUCCESS;
}

/** @} */

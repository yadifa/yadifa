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
#include <dnscore/file-pool.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_record.h"

#include <dnscore/dnsname.h>

#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif

#include <dnscore/output_stream.h>

#include <dnscore/rfc.h>

#include "dnsdb/zdb_utils.h"
#include "dnscore/zone_reader.h"
#include <dnscore/dnscore.h>

#define ZNIRDATA_TAG 0x4154414452494e5a

// With this set to 1, AXFR storage on disk will be extremely slow.
// Meant to debug network faster than disk speeds.
// The value is expressed in ms
//
// Keep this to 0 except if you need it to be slow

#define ZDB_ZONE_IMAGE_FLAG_FULLY_WRITTEN 1

#define IMAGE_MAGIC0 MAGIC4(0xff,'Z','O','N')
#define IMAGE_MAGIC1 MAGIC4('E',13,10,26)
#define CHAIN_MAGIC MAGIC4('N','S','C',3)
#define END_MAGIC MAGIC4('E','N','D', 0)

/*
 *
 */

struct zdb_zone_image_store_header
{
    u32 magic0;    
    u32 magic1;
    
    u64 epoch;
    
    u64 size;
    
    u64 estimated_wire_size;
    
    u16 version;
    u8 flags;
    u8 chains;
    u32 serial;
    
    u16 zclass;
    u8 reserved;
    u8 origin_size;
};

struct zdb_zone_image_store_record_set
{
    u16 type;
    u16 count;
};

struct zdb_zone_image_store_record
{
    u32 ttl;
    u16 rdata_size;
    u8  rdata[];
};

struct zdb_zone_image_reader_data
{
    file_pool_file_t file;
    input_stream is;
    resource_record *unread_next;
    struct zdb_zone_image_store_header hdr;
    struct zdb_zone_image_store_record_set rrset_hdr;
    s8 depth;
    u8 fqdn_size;
    u8 label_len[128];
    u8 fqdn[MAX_DOMAIN_LENGTH];
};

typedef struct zdb_zone_image_reader_data zdb_zone_image_reader_data;

//  1: down
// -1: up

#define TCTS_SIZE 10

//static const u8 wild_wire[2] = {1, '*'};

static ya_result
zdb_zone_image_store_record_set_innerloop(output_stream *os, zdb_packed_ttlrdata *rrset)
{
    ya_result ret;
    u32 wire_size = 0;
    
    while(rrset != NULL)
    {
        if(FAIL(ret = output_stream_write_u32(os, rrset->ttl)))
        {
            return ret;
        }
        if(FAIL(ret = output_stream_write_u16(os, ZDB_PACKEDRECORD_PTR_RDATASIZE(rrset))))
        {
            return ret;
        }
        if(FAIL(ret = output_stream_write(os, ZDB_PACKEDRECORD_PTR_RDATAPTR(rrset), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrset))))
        {
            return ret;
        }
        
        wire_size += ZDB_PACKEDRECORD_PTR_RDATASIZE(rrset);
        
        rrset = rrset->next;
    }
    
    return wire_size;
}

static ya_result
zdb_zone_image_store_record_set(output_stream *os, u16 rtype, zdb_packed_ttlrdata *rrset)
{
    ya_result ret;
    
    int count = zdb_packed_ttlrdata_count(rrset);
    
    if(count == 0)
    {
        return 0;
    }

    if(count > MAX_U16)
    {
        return ERROR;
    }
    
    struct zdb_zone_image_store_record_set rrset_hdr = { rtype, count };
    
    if(FAIL(ret = output_stream_write(os, &rrset_hdr, sizeof(rrset_hdr))))
    {
        return ret;
    }
    
    if(FAIL(ret = zdb_zone_image_store_record_set_innerloop(os, rrset)))
    {
        return ret;
    }
    
    return ret + count * TCTS_SIZE;
}

static ya_result
zdb_zone_image_store_record_sets(output_stream *os, zdb_rr_collection rrsets)
{
    ya_result ret;
    u32 wire_size = 0;
    btree_iterator iter;
    
    btree_iterator_init(rrsets, &iter);

    while(btree_iterator_hasnext(&iter))
    {
        btree_node *rr_node = btree_iterator_next_node(&iter);
        u16 rtype = (u16)rr_node->hash;
        if(FAIL(ret = zdb_zone_image_store_record_set(os, rtype, rr_node->data)))   
        {
            return ret;
        }
        
        wire_size += ret;
    }
    
    output_stream_write_u16(os, TYPE_ANY);
    
    return wire_size;
}

static ya_result
zdb_zone_image_store_record_sets_but_SOA(output_stream *os, zdb_rr_collection rrsets)
{
    ya_result ret;
    u32 wire_size = 0;
    btree_iterator iter;
    
    btree_iterator_init(rrsets, &iter);

    while(btree_iterator_hasnext(&iter))
    {
        btree_node *rr_node = btree_iterator_next_node(&iter);
        u16 rtype = (u16)rr_node->hash;
        
        if(rtype == TYPE_SOA)
        {
            continue;
        }
        
        if(FAIL(ret = zdb_zone_image_store_record_set(os, rtype, rr_node->data)))   
        {
            return ret;
        }
        
        wire_size += ret;
    }
    
    output_stream_write_u16(os, TYPE_ANY);
    
    return wire_size;
}

static s64
zdb_zone_image_store_label_children_recursively(output_stream *os, zdb_rr_label_set *labels, u32 name_len)
{
    s64 ret;
    s64 wire_size = 0;
    
    if(!dictionary_isempty(labels))
    {
        dictionary_iterator iter;
        dictionary_iterator_init(labels, &iter);

        while(dictionary_iterator_hasnext(&iter))
        {
            zdb_rr_label *sub_label =  *(zdb_rr_label**)dictionary_iterator_next(&iter);
            
            for(;;)
            {
                output_stream_write_u8(os, 1);
                
                output_stream_write(os, sub_label->name, sub_label->name[0] + 1);

                if(FAIL(ret = zdb_zone_image_store_record_sets(os, sub_label->resource_record_set)))
                {
                    return ret;
                }
                
                wire_size += ret + name_len + sub_label->name[0];
                
                if(FAIL(ret = zdb_zone_image_store_label_children_recursively(os, &sub_label->sub, name_len + sub_label->name[0])))
                {
                    return ret;
                }
                
                wire_size += ret;
                
                output_stream_write_u8(os, 255);
                
                if(sub_label->next == NULL)
                {
                    break;
                }
                
                sub_label = sub_label->next;
            }
        }
    }
    
    return wire_size;
}

s64
zdb_zone_image_store(zdb_zone* zone, const char *filename, file_pool_t fp, mode_t mode)
{
    struct zdb_zone_image_store_header hdr;
    output_stream os;
    ya_result ret;
    u32 soa_serial;
    
    u32 origin_len = dnsname_len(zone->origin);
    
    if(origin_len > 255)
    {
        return ERROR;
    }
    
    zdb_packed_ttlrdata* soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);

    if(soa == NULL)
    {
        return ZDB_ERROR_GENERAL;
    }
    
    rr_soa_get_serial(ZDB_PACKEDRECORD_PTR_RDATAPTR(soa), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa), &soa_serial);
    
    file_pool_unlink_from_pool_and_filename(fp, filename);
    
    file_pool_file_t f = file_pool_create_excl(fp, filename, mode);
    
    if(f == NULL)
    {
        return ERROR;
    }
    
    hdr.magic0 = IMAGE_MAGIC0;
    hdr.magic1 = IMAGE_MAGIC1;
    hdr.epoch = 0;
    hdr.size = 0;
    hdr.estimated_wire_size = 0;
    hdr.flags = 0;
    hdr.version = 0;
    hdr.serial = soa_serial;
    hdr.zclass = zdb_zone_getclass(zone);
    hdr.reserved = 0;
    hdr.origin_size = origin_len;
    
    file_pool_file_output_stream_init(&os, f);
    file_pool_file_output_stream_set_full_writes(&os, TRUE);

    if(FAIL(ret = output_stream_write(&os, &hdr, sizeof(hdr))))
    {
        file_pool_unlink(f);
        output_stream_close(&os);
        //file_close(f);
        return ret;
    }
        
    if(FAIL(ret = output_stream_write(&os, zone->origin, origin_len)))
    {
        file_pool_unlink(f);
        output_stream_close(&os);
        //file_close(f);
        return ret;
    }
    
    // now write from the apex
    
    zdb_zone_image_store_record_set(&os, TYPE_SOA, soa);
    zdb_zone_image_store_record_sets_but_SOA(&os, zone->apex->resource_record_set);
    
    s64 wire_size = zdb_zone_image_store_label_children_recursively(&os, &zone->apex->sub, origin_len);

#if ZDB_HAS_NSEC3_SUPPORT

    /*
     * For each NSEC3PARAM struct ...
     * 
     * Note that from the 'transaction' update, the dnssec zone collections have to be read without checking for the NSEC3 flag
     */

    nsec3_zone *n3 = zone->nsec.nsec3;

    while(n3 != NULL)
    {
        ++hdr.chains;
        
        /*
         *  Iterate the NSEC3 nodes
         */
        
        output_stream_write_u32(&os, CHAIN_MAGIC);
        output_stream_write_u8(&os, NSEC3_ZONE_ALGORITHM(n3));
        output_stream_write_u8(&os, NSEC3_ZONE_FLAGS(n3));
        output_stream_write_u16(&os, NSEC3_ZONE_ITERATIONS(n3));
        output_stream_write_u8(&os, NSEC3_ZONE_SALT_LEN(n3));
        output_stream_write(&os, NSEC3_ZONE_SALT(n3), NSEC3_ZONE_SALT_LEN(n3));
        
        u32 common = 5 + NSEC3_ZONE_SALT_LEN(n3);
        
        nsec3_iterator nsec3_items_iter;
        nsec3_iterator_init(&n3->items, &nsec3_items_iter);
        while(nsec3_iterator_hasnext(&nsec3_items_iter))
        {
            nsec3_zone_item *item = nsec3_iterator_next_node(&nsec3_items_iter);
            
            u8 digest_len = NSEC3_NODE_DIGEST_SIZE(item);
            
            if(FAIL(ret = output_stream_write_u8(&os, digest_len)))
            {
                break;
            }
            
            if(FAIL(ret = output_stream_write(&os, NSEC3_NODE_DIGEST_PTR(item), digest_len)))
            {
                break;
            }
            
            if(FAIL(ret = output_stream_write_u8(&os, item->flags)))
            {
                break;
            }
            
            if(FAIL(ret = output_stream_write_u16(&os, item->type_bit_maps_size)))
            {
                break;
            }
            
            if(FAIL(ret = output_stream_write(&os, item->type_bit_maps, item->type_bit_maps_size)))
            {
                break;
            }
            
            wire_size += common + item->type_bit_maps_size;
            
            int rrsig_count = zdb_packed_ttlrdata_count(item->rrsig);
            
            if(FAIL(ret = output_stream_write_u16(&os, rrsig_count)))
            {
                break;
            }
            
            if(rrsig_count > 0)
            {
                if(FAIL(ret = zdb_zone_image_store_record_set_innerloop(&os, item->rrsig)))
                {
                    return ret;
                }
                
                wire_size += ret + TCTS_SIZE * rrsig_count;
            }
        }
        
        if(FAIL(ret))
        {
            file_pool_unlink(f);
            output_stream_close(&os);
            //file_close(f);
            return ret;
        }

        n3 = n3->next;
    }

#endif

    if(FAIL(ret = output_stream_write_u32(&os, END_MAGIC)))
    {
        file_pool_unlink(f);
        output_stream_close(&os);
        //file_close(f);
        return ret;
    }
    
    output_stream_flush(&os);
    file_pool_file_output_stream_detach(&os);
    
    size_t position;
    if(FAIL(ret = file_pool_tell(f, &position)))
    {
        file_pool_unlink(f);
        file_pool_close(f);
        return ret;
    }
    
    hdr.epoch = timeus();
    hdr.size = position;
    hdr.estimated_wire_size = wire_size;
    hdr.flags |= ZDB_ZONE_IMAGE_FLAG_FULLY_WRITTEN;
    
    if(FAIL(ret = file_pool_seek(f, 0, SEEK_SET)))
    {
        file_pool_unlink(f);
        file_pool_close(f);
        return ret;
    }
    
    if(FAIL(ret = file_pool_write(f, &hdr, sizeof(hdr))))
    {
        file_pool_unlink(f);
        file_pool_close(f);
        return ret;
    }

    return SUCCESS;
}

static ya_result
zdb_zone_image_reader_read_record(zone_reader *zr, resource_record *rr)
{
    zdb_zone_image_reader_data *data = (zdb_zone_image_reader_data*)zr->data;
    
    if(data->unread_next != NULL)
    {
        resource_record *tmp = data->unread_next;
        resource_record_copy(rr, tmp);
        data->unread_next = tmp->next;
        free(tmp);
        return SUCCESS;
    }
    
    ya_result ret;
    
    for(;;)
    {
        if(data->rrset_hdr.count == 0)
        {
            // next RRSET

            if(FAIL(ret = input_stream_read_u16(&data->is, &data->rrset_hdr.type)))
            {
                return ret;
            }

            if(data->rrset_hdr.type != TYPE_ANY)
            {
                if(FAIL(ret = input_stream_read_u16(&data->is, &data->rrset_hdr.count)))
                {
                    return ret;
                }
                
                if(data->rrset_hdr.count == 0)
                {
                    return ERROR;
                }

                // fallback on the "read record, decrement count" code
            }
            else
            {
                // done for this label

                data->rrset_hdr.count = 0;

                for(;;)
                {
                    s8 up_down = 0;
                    u8 label_len = 0;
                    if(FAIL(ret = input_stream_read_s8(&data->is, &up_down)))
                    {
                        return ret;
                    }

                    if(up_down == 1)
                    {
                        // read the next label and append it to the fqdn

                        if(FAIL(ret = input_stream_read_u8(&data->is, &label_len)))
                        {
                            return ret;
                        }

                        if(data->fqdn_size + label_len > 255)
                        {
                            return ERROR;
                        }

                        data->fqdn[data->fqdn_size] = label_len;

                        if(FAIL(ret = input_stream_read(&data->is, &data->fqdn[data->fqdn_size + 1], label_len)))
                        {
                            return ret;
                        }

                        data->label_len[data->depth++] = label_len;

                        data->fqdn_size += label_len;

                        // now go back at the beginning of the function

                        break;
                    }
                    else if(up_down == -1)
                    {
                        if(data->depth == 0)
                        {
                            return ERROR;
                        }

                        data->fqdn_size -= data->label_len[data->depth--];

                        // after a -1 you can get either a 1 or a -1
                    }
                    else
                    {
                        return ERROR;
                    }
                } // for up down

                // reached by breaking for a 1

                continue; // will go back trying to read records
            }
        }
        
        // we know what type is being read
        // we know there is at least one to read
        // we know its fqdn
        
        // rr
        
        input_stream_read_s32(&data->is, &rr->ttl);
        rr->type = data->rrset_hdr.type;
        rr->class = data->hdr.zclass;
        memcpy(rr->name, data->fqdn, data->fqdn_size);
        input_stream_read_u16(&data->is, &rr->rdata_size);
        input_stream_read(&data->is, rr->rdata, rr->rdata_size);
        
        return SUCCESS;
    } // for loop
}

static ya_result
zdb_zone_image_reader_unread_record(zone_reader *zr, resource_record *rr)
{
    zdb_zone_image_reader_data *data = (zdb_zone_image_reader_data*)zr->data;
    resource_record *clone;
    MALLOC_OBJECT_OR_DIE(clone, resource_record, DNSRR_TAG);
    clone->next = data->unread_next;
    data->unread_next = clone;
    return SUCCESS;
}

static ya_result
zdb_zone_image_reader_free_record(zone_reader *zr, resource_record *rr)
{
    zdb_zone_image_reader_data *data = (zdb_zone_image_reader_data*)zr->data;
    (void)zr;
    (void)rr;
    (void)data;
    return SUCCESS;
}

static void
zdb_zone_image_reader_close(zone_reader *zr)
{
    zdb_zone_image_reader_data *data = (zdb_zone_image_reader_data*)zr->data;
    resource_record *rr = data->unread_next;
    while(rr != NULL)
    {
        resource_record *tmp = rr;
        rr = rr->next;
        free(tmp);
    }
    data->unread_next = NULL;
    input_stream_close(&data->is);
    data->file = NULL;
    ZFREE_OBJECT(data);
}

static void
zdb_zone_image_reader_handle_error(zone_reader *zr, ya_result error_code) // used for cleaning up after an error (AXFR feedback)
{
    zdb_zone_image_reader_data *data = (zdb_zone_image_reader_data*)zr->data;
    (void)data;
    (void)error_code;
}

static const char*
zdb_zone_image_reader_get_last_error_message(zone_reader *zr)
{
    zdb_zone_image_reader_data *data = (zdb_zone_image_reader_data*)zr->data;
    (void)data;
    return "?";
}

static bool
zdb_zone_image_reader_canwriteback(zone_reader *zr)
{
    (void)zr;
    return FALSE;
}

static const zone_reader_vtbl zdb_zone_image_reader_vtbl =
{
    zdb_zone_image_reader_read_record,
    zdb_zone_image_reader_unread_record,
    zdb_zone_image_reader_free_record,
    zdb_zone_image_reader_close,
    zdb_zone_image_reader_handle_error,
    zdb_zone_image_reader_canwriteback,
    zdb_zone_image_reader_get_last_error_message,
    "zdb_zone_image_reader"
};

ya_result
zdb_zone_image_reader_open(zone_reader *zr, const char *filename, file_pool_t fp)
{
    file_pool_file_t f = file_pool_open(fp, filename);
    ya_result ret;
    
    if(f == NULL)
    {
        return ERROR;
    }
    
    zdb_zone_image_reader_data *data;
    
    ZALLOC_OBJECT_OR_DIE(data, zdb_zone_image_reader_data, ZNIRDATA_TAG);
    data->file = f;
    file_pool_file_input_stream_init(&data->is, f);
    file_pool_file_input_stream_set_full_reads(&data->is, TRUE);
    data->unread_next = NULL;
    
    if(FAIL(ret = input_stream_read(&data->is, &data->hdr, sizeof(data->hdr))))
    {
        file_pool_close(f);
        ZFREE_OBJECT(data);
        return ret;
    }
    
    if((data->hdr.magic0 != IMAGE_MAGIC0) || (data->hdr.magic0 != IMAGE_MAGIC1))
    {
        file_pool_close(f);
        ZFREE_OBJECT(data);
        return ret;
    }
    
    if(FAIL(ret = input_stream_read(&data->is, data->fqdn, data->hdr.origin_size)))
    {
        file_pool_close(f);
        ZFREE_OBJECT(data);
        return ret;
    }
    
    data->fqdn_size = data->hdr.origin_size;
    data->rrset_hdr.type = 0;
    data->rrset_hdr.count = 0;
    
    zr->data = data;
    zr->vtbl = &zdb_zone_image_reader_vtbl;
    
    return SUCCESS;
}

/** @} */

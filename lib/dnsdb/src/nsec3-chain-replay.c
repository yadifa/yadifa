/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2017, EURid. All rights reserved.
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
 */
/* DOCUMENTATION
 * @defgroup nsec3 NSEC3 functions
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
#include <dnscore/logger.h>
#include <dnscore/base32hex.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/ptr_set.h>
#include "dnsdb/zdb_types.h"
#include "dnsdb/nsec3-chain-replay.h"
#include "dnsdb/nsec3_types.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/zdb-zone-arc.h"
#include "dnsdb/zdb_zone.h"

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

#define NSEC3_CHAIN_REPLAY_DEBUG 1

#define NSEC3CNR_TAG 0x524e43334345534e
#define NSEC3RPL_TAG 0x4c5052334345534e

#define NSEC3_CHAIN_REPLAY_STATUS_UPDATED 1

struct nsec3_chain_replay_record
{
    s32 ttl;
    u16 rdata_size;
#if NSEC3_CHAIN_REPLAY_DEBUG
    u16 rtype;
    u16 _padding_;
#endif
    u8 fqdn_len;
    u8 status;
    u8 fqdn_rdata[];
};

typedef struct nsec3_chain_replay_record nsec3_chain_replay_record;

static nsec3_chain_replay_record *
nsec3_chain_replay_record_new(const u8 *fqdn, u16 rtype, s32 ttl, const u8 *rdata, u16 rdata_size)
{
    nsec3_chain_replay_record *record;
    int fqdn_len = dnsname_len(fqdn);
    ZALLOC_ARRAY_OR_DIE(nsec3_chain_replay_record*, record, sizeof(nsec3_chain_replay_record) + fqdn_len + rdata_size, NSEC3CNR_TAG);
    record->ttl = ttl;
    record->rdata_size = rdata_size;
#if NSEC3_CHAIN_REPLAY_DEBUG
    record->rtype = rtype;
#endif
    record->fqdn_len = fqdn_len;
    record->status = 0;
    memcpy(record->fqdn_rdata, fqdn, fqdn_len);
    memcpy(&record->fqdn_rdata[fqdn_len], rdata, rdata_size);
    
#if NSEC3_CHAIN_REPLAY_DEBUG
    rdata_desc nsec3_desc = {rtype, rdata_size, rdata};
    log_debug("nsec3-chain: record new %{dnsname} %i %{typerdatadesc}", fqdn, ttl, &nsec3_desc);
#else
    (void)rtype;
#endif
    
    return record;
}
static const u8 *
nsec3_chain_replay_record_fqdn(nsec3_chain_replay_record *record)
{
    return record->fqdn_rdata;
}

static const u8 *
nsec3_chain_replay_record_rdata(nsec3_chain_replay_record *record)
{
    return &record->fqdn_rdata[record->fqdn_len];
}

static const u8 *
nsec3_chain_replay_record_next_digest(nsec3_chain_replay_record *record)
{
    const u8 *rdata = nsec3_chain_replay_record_rdata(record);
    return &rdata[rdata[4] + 5];
}

static void
nsec3_chain_replay_record_format(const void* r, output_stream* os, s32 a, char b, bool c, void* d)
{
    nsec3_chain_replay_record *rr = (nsec3_chain_replay_record*)r;
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    
    rdata_desc typerdata = {rr->rtype, rr->rdata_size, nsec3_chain_replay_record_rdata(rr)};

    osformat(os, "%{dnsname} %i %{typerdatadesc}", nsec3_chain_replay_record_fqdn(rr), rr->ttl, &typerdata);
}

static void
nsec3_chain_replay_record_delete(nsec3_chain_replay_record *record)
{
#if NSEC3_CHAIN_REPLAY_DEBUG
    rdata_desc nsec3_desc = {record->rtype, record->rdata_size, nsec3_chain_replay_record_rdata(record)};
    log_debug("nsec3-chain: record free %{dnsname} %i %{typerdatadesc}", nsec3_chain_replay_record_fqdn(record), record->ttl, &nsec3_desc);
#endif
    
    ZFREE_ARRAY(record, sizeof(nsec3_chain_replay_record) + record->fqdn_len + record->rdata_size);
}

static void
nsec3_chain_replay_record_delete_cb(void *record)
{
    nsec3_chain_replay_record_delete((nsec3_chain_replay_record*)record);
}

static nsec3_zone *
nsec3_chain_replay_record_find_chain(zdb_zone *zone, nsec3_chain_replay_record *record)
{
    nsec3_zone *n3 = zone->nsec.nsec3;
    while(n3 != NULL)
    {
        const u8 *record_rdata = nsec3_chain_replay_record_rdata(record);
        u16 record_rdata_size = NSEC3PARAM_RDATA_SIZE_FROM_RDATA(record_rdata);
        u16 n3_rdata_size = NSEC3PARAM_RDATA_SIZE_FROM_RDATA(n3->rdata);
        if(n3_rdata_size <= record_rdata_size)
        {
            if(record_rdata[0] == n3->rdata[0])
            {
                if(memcmp(&record_rdata[3], &n3->rdata[3], n3_rdata_size - 3) == 0)
                {
                    break;
                }
            }
        }
        
        n3 = n3->next;
    }
    return n3;
}

static nsec3_zone *
nsec3_chain_replay_record_add_chain(zdb_zone *zone, nsec3_chain_replay_record *record)
{
    nsec3_zone **n3p = &zone->nsec.nsec3;
    while(*n3p != NULL)
    {
        n3p = &(*n3p)->next;
    }
    
    nsec3_zone *n3 = nsec3_zone_new(nsec3_chain_replay_record_rdata(record), record->rdata_size);
    
    *n3p = n3;
    
    return n3;
}

static nsec3_zone_item *
nsec3_chain_replay_record_find_item_by_name(zdb_zone *zone, nsec3_chain_replay_record *record)
{
    nsec3_zone *n3 = zone->nsec.nsec3;
    while(n3 != NULL)
    {
        nsec3_zone_item *item = nsec3_zone_item_find_by_name(n3, nsec3_chain_replay_record_fqdn(record));
        if(item != NULL)
        {
            return item;
        }
        
        n3 = n3->next;
    }
    return NULL;
}

static int
nsec3_chain_replay_record_nsec3_compare(const void *a, const void *b)
{
    nsec3_chain_replay_record *ra = *(nsec3_chain_replay_record**)a;
    nsec3_chain_replay_record *rb = *(nsec3_chain_replay_record**)b;
    const u8 *ra_rdata = nsec3_chain_replay_record_rdata(ra);
    const u8 *rb_rdata = nsec3_chain_replay_record_rdata(rb);
    int ra_chain_size = NSEC3PARAM_RDATA_SIZE_FROM_RDATA(ra_rdata);
    int rb_chain_size = NSEC3PARAM_RDATA_SIZE_FROM_RDATA(rb_rdata);
    int d = ra_chain_size - rb_chain_size;
    if(d == 0)
    {
        d = memcmp(ra_rdata, rb_rdata, ra_chain_size);
        if(d == 0)
        {
            d = dnsname_compare(nsec3_chain_replay_record_fqdn(ra), nsec3_chain_replay_record_fqdn(rb));
        }
    }
    return d;
}

static void
nsec3_chain_replay_fqdn_key_delete(ptr_node *node)
{
    dnsname_zfree((u8*)node->key);
}

struct nsec3_chain_replay_data
{
    zdb_zone *zone;
    ptr_set fqdns;
    ptr_vector del_nsec3_records;
    ptr_vector add_nsec3_records;
    ptr_vector del_nsec3_rrsig_records;
    ptr_vector add_nsec3_rrsig_records;
    ptr_vector del_nsec3param_records;
    ptr_vector add_nsec3param_records;
};

typedef struct nsec3_chain_replay_data nsec3_chain_replay_data;

static void
nsec3_chain_replay_record_add_fqdn(nsec3_chain_replay_data *crd, const u8 *fqdn)
{
    ptr_node *node = ptr_set_avl_insert(&crd->fqdns, (u8*)fqdn);
    if(node->value == NULL)
    {
        node->key = dnsname_zdup(fqdn);
        node->value = node->key;
    }
}

static ya_result
nsec3_chain_replay_record_del(chain_replay *cr, const u8 *fqdn, u16 rtype, const zdb_ttlrdata *ttlrdata)
{
    yassert((ttlrdata != NULL) || ((ttlrdata == NULL) && (rtype == TYPE_NONE)));
    
    nsec3_chain_replay_data *crd = (nsec3_chain_replay_data*)cr->data;
    
#ifdef DEBUG
    if(ttlrdata != NULL)
    {
        rdata_desc type_len_rdata = {rtype, ZDB_RECORD_PTR_RDATASIZE(ttlrdata), ZDB_RECORD_PTR_RDATAPTR(ttlrdata)};
        log_debug("nsec3-chain: del %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
    }
    else
    {
        log_debug("nsec3-chain: del %{dnsname} (fqdn)", fqdn);
    }
#endif
    
    switch(rtype)
    {
        case TYPE_NSEC3:
        {
            ptr_vector_append(&crd->del_nsec3_records, nsec3_chain_replay_record_new(fqdn, TYPE_NSEC3, ttlrdata->ttl, ZDB_RECORD_PTR_RDATAPTR(ttlrdata), ZDB_RECORD_PTR_RDATASIZE(ttlrdata)));
            return 1;
        }
        case TYPE_NSEC3PARAM:
        {
            ptr_vector_append(&crd->del_nsec3param_records, nsec3_chain_replay_record_new(fqdn, TYPE_NSEC3PARAM, ttlrdata->ttl, ZDB_RECORD_PTR_RDATAPTR(ttlrdata), ZDB_RECORD_PTR_RDATASIZE(ttlrdata)));
            nsec3_chain_replay_record_add_fqdn(crd, fqdn);
            return 0;
        }
        case TYPE_RRSIG:
        {
            u16 covered_type = GET_U16_AT_P(ZDB_RECORD_PTR_RDATAPTR(ttlrdata));
            if(covered_type == TYPE_NSEC3)
            {
                ptr_vector_append(&crd->del_nsec3_rrsig_records, nsec3_chain_replay_record_new(fqdn, TYPE_RRSIG, ttlrdata->ttl, ZDB_RECORD_PTR_RDATAPTR(ttlrdata), ZDB_RECORD_PTR_RDATASIZE(ttlrdata)));
                return 1;
            }
            else
            {
                nsec3_chain_replay_record_add_fqdn(crd, fqdn);
                return 0;
            }
        }
        default:
        {
            nsec3_chain_replay_record_add_fqdn(crd, fqdn);
            return 0;
        }
    }
}

static ya_result
nsec3_chain_replay_record_add(chain_replay *cr, const u8 *fqdn, u16 rtype, const zdb_ttlrdata *ttlrdata)
{
    yassert((ttlrdata != NULL) || ((ttlrdata == NULL) && (rtype == TYPE_NONE)));
    
    nsec3_chain_replay_data *crd = (nsec3_chain_replay_data*)cr->data;
    
#ifdef DEBUG
    if(ttlrdata != NULL)
    {
        rdata_desc type_len_rdata = {rtype, ZDB_RECORD_PTR_RDATASIZE(ttlrdata), ZDB_RECORD_PTR_RDATAPTR(ttlrdata)};
        log_debug("nsec3-chain: add %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
    }
    else
    {
        log_debug("nsec3-chain: add %{dnsname} (fqdn)", fqdn);
    }
#endif
    
    switch(rtype)
    {
        case TYPE_NSEC3:
        {
            ptr_vector_append(&crd->add_nsec3_records, nsec3_chain_replay_record_new(fqdn, TYPE_NSEC3, ttlrdata->ttl, ZDB_RECORD_PTR_RDATAPTR(ttlrdata), ZDB_RECORD_PTR_RDATASIZE(ttlrdata)));
            return 1;
        }
        case TYPE_NSEC3PARAM:
        {
            ptr_vector_append(&crd->add_nsec3param_records, nsec3_chain_replay_record_new(fqdn, TYPE_NSEC3PARAM, ttlrdata->ttl, ZDB_RECORD_PTR_RDATAPTR(ttlrdata), ZDB_RECORD_PTR_RDATASIZE(ttlrdata)));
            nsec3_chain_replay_record_add_fqdn(crd, fqdn);
            return 0;
        }
        case TYPE_RRSIG:
        {
            u16 covered_type = GET_U16_AT_P(ZDB_RECORD_PTR_RDATAPTR(ttlrdata));
            if(covered_type == TYPE_NSEC3)
            {
                ptr_vector_append(&crd->add_nsec3_rrsig_records, nsec3_chain_replay_record_new(fqdn, TYPE_RRSIG, ttlrdata->ttl, ZDB_RECORD_PTR_RDATAPTR(ttlrdata), ZDB_RECORD_PTR_RDATASIZE(ttlrdata)));
                return 1;
            }
            else
            {
                nsec3_chain_replay_record_add_fqdn(crd, fqdn);
                return 0;
            }
        }
        default:
        {
            nsec3_chain_replay_record_add_fqdn(crd, fqdn);
            return 0;
        }
    }
}

static ya_result
nsec3_chain_replay_execute(chain_replay *cr)
{
    // sort NSEC3 records by chain,fqdn
    // verify chains are making sense
    // remove signatures from the relevant nsec3_zone
    // remove nodes from the relevant nsec3_zone
    // add nodes to the relevant nsec3_zone
    // add signatures to the relevant nsec3_zone
    // if an nsec3param was removed, choose the new best chain
    // (start) unlink old chain and add new chain
    
    nsec3_chain_replay_data *crd = (nsec3_chain_replay_data*)cr->data;

    ptr_set del_nsec3_set = PTR_SET_DNSNAME_EMPTY;
    ya_result ret = SUCCESS;
    
    int n;
    u8 expected_mode = ZDB_ZONE_MAINTAIN_NSEC3;
    u8 tmp_digest[MAX_DIGEST_LENGTH + 1];
    
    ptr_vector_qsort(&crd->del_nsec3_records, nsec3_chain_replay_record_nsec3_compare);
    ptr_vector_qsort(&crd->add_nsec3_records, nsec3_chain_replay_record_nsec3_compare);
    
#if NSEC3_CHAIN_REPLAY_DEBUG
    {
        log_debug("nsec3-chain: %{dnsname}: replaying:", crd->zone->origin);
        for(int i = 0; i < ptr_vector_size(&crd->add_nsec3param_records); ++i)
        {
            nsec3_chain_replay_record *rr = (nsec3_chain_replay_record*)ptr_vector_get(&crd->add_nsec3param_records, i);
            format_writer temp_fw_0 = {nsec3_chain_replay_record_format, rr};
            log_debug("nsec3-chain: %{dnsname}: NSEC3PARAM-ADD: %w", crd->zone->origin, &temp_fw_0);
        }
        for(int i = 0; i < ptr_vector_size(&crd->del_nsec3param_records); ++i)
        {
            nsec3_chain_replay_record *rr = (nsec3_chain_replay_record*)ptr_vector_get(&crd->del_nsec3param_records, i);
            format_writer temp_fw_0 = {nsec3_chain_replay_record_format, rr};
            log_debug("nsec3-chain: %{dnsname}: NSEC3PARAM-DEL: %w", crd->zone->origin, &temp_fw_0);
        }
        for(int i = 0; i < ptr_vector_size(&crd->del_nsec3_rrsig_records); ++i)
        {
            nsec3_chain_replay_record *rr = (nsec3_chain_replay_record*)ptr_vector_get(&crd->del_nsec3_rrsig_records, i);
            format_writer temp_fw_0 = {nsec3_chain_replay_record_format, rr};
            log_debug("nsec3-chain: %{dnsname}: NSEC3-RRSIG-DEL: %w", crd->zone->origin, &temp_fw_0);
        }
        for(int i = 0; i < ptr_vector_size(&crd->del_nsec3_records); ++i)
        {
            nsec3_chain_replay_record *rr = (nsec3_chain_replay_record*)ptr_vector_get(&crd->del_nsec3_records, i);
            format_writer temp_fw_0 = {nsec3_chain_replay_record_format, rr};
            log_debug("nsec3-chain: %{dnsname}: NSEC3-DEL: %w", crd->zone->origin, &temp_fw_0);
        }
        for(int i = 0; i < ptr_vector_size(&crd->add_nsec3_records); ++i)
        {
            nsec3_chain_replay_record *rr = (nsec3_chain_replay_record*)ptr_vector_get(&crd->add_nsec3_records, i);
            format_writer temp_fw_0 = {nsec3_chain_replay_record_format, rr};
            log_debug("nsec3-chain: %{dnsname}: NSEC3-ADD: %w", crd->zone->origin, &temp_fw_0);
        }
        for(int i = 0; i < ptr_vector_size(&crd->add_nsec3_rrsig_records); ++i)
        {
            nsec3_chain_replay_record *rr = (nsec3_chain_replay_record*)ptr_vector_get(&crd->add_nsec3_rrsig_records, i);
            format_writer temp_fw_0 = {nsec3_chain_replay_record_format, rr};
            log_debug("nsec3-chain: %{dnsname}: NSEC3-RRSIG-ADD: %w", crd->zone->origin, &temp_fw_0);
        }
        
        ptr_set_avl_iterator iter;
        ptr_set_avl_iterator_init(&crd->fqdns, &iter);
        while(ptr_set_avl_iterator_hasnext(&iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
            log_debug("nsec3-chain: %{dnsname}: FQDN: %{dnsname}", crd->zone->origin, node->value);
        }
    }
#endif
    
    n = ptr_vector_size(&crd->del_nsec3_records);
    
    for(int i = 0; i < n; ++i)
    {
        nsec3_chain_replay_record *record = (nsec3_chain_replay_record*)ptr_vector_get(&crd->del_nsec3_records, i);
        
        // check the record exists
        //   find the chain
        //   find the record
        
        // keep a quick access on the record
        
        ptr_node *node = ptr_set_avl_insert(&del_nsec3_set, (u8*)nsec3_chain_replay_record_fqdn(record));
        if(node->value == NULL)
        {
            node->value = record;
            
            format_writer temp_fw_0 = {nsec3_chain_replay_record_format, record};
            
            nsec3_zone_item *item = nsec3_chain_replay_record_find_item_by_name(crd->zone, record);
            
            if(item != NULL)
            {
                nsec3_zone_item *next = nsec3_avl_node_mod_next(item);
                if(memcmp(next->digest, nsec3_chain_replay_record_next_digest(record), next->digest[0] + 1) == 0)
                {
                    // match
                    log_debug("nsec3-chain: %{dnsname}: del %w checks out", crd->zone->origin, &temp_fw_0);
                }
                else
                {
                    // nsec3_zone_item *next = nsec3_chain_replay_record_find_item_by_digest(crd->zone, nsec3_chain_replay_record_next_digest(record));

                    log_err("nsec3-chain: %{dnsname}: %w is not in the zone: current next is %{digest32h} but expected next is %{digest32h}",
                            crd->zone->origin, &temp_fw_0, next->digest, nsec3_chain_replay_record_next_digest(record));
                    
#ifdef DEBUG
                    logger_flush();
#endif
                    
                    ret = ERROR;
                }
            }
            else
            {
                log_err("nsec3-chain: %{dnsname}: %w is not in the zone: no label",
                        crd->zone->origin, &temp_fw_0);
                
                ret = ERROR;
#ifdef DEBUG
                logger_flush();
#endif
            }
        }
        else
        {
            // duplicate : something is wrong
            
            log_err("nsec3-chain: %{dnsname}: replay delete %{dnsname} is a duplicate entry in this run",
                    crd->zone->origin, nsec3_chain_replay_record_fqdn(record));
        }
    }
    
    if(ISOK(ret))
    {
        n = ptr_vector_size(&crd->add_nsec3_records);

        for(int i = 0; i < n; ++i)
        {
            nsec3_chain_replay_record *record = (nsec3_chain_replay_record*)ptr_vector_get(&crd->add_nsec3_records, i);

            // find the start of a sub-chain
            // find the end of the sub-chain
            // if the sub-chain is not looping, the head must exist (and is being removed/added)

            // check for updates

            ptr_node *node = ptr_set_avl_find(&del_nsec3_set, nsec3_chain_replay_record_fqdn(record));
            if(node != NULL)
            {
                // the record is updated
                nsec3_chain_replay_record *old_record = (nsec3_chain_replay_record*)node->value;
                record->status = NSEC3_CHAIN_REPLAY_STATUS_UPDATED;
                old_record->status = NSEC3_CHAIN_REPLAY_STATUS_UPDATED;
            }
        }

        // n = ptr_vector_size(&crd->add_nsec3_records); // already done

        for(int i = 0; i < n; ++i)
        {
            nsec3_chain_replay_record *record = (nsec3_chain_replay_record*)ptr_vector_get(&crd->add_nsec3_records, i);
            nsec3_chain_replay_record *deleted = NULL;
            // check the next record exist
            //   find the chain
            //   find the record

            // it must not be deleted
            ptr_node *node = ptr_set_avl_find(&del_nsec3_set, nsec3_chain_replay_record_fqdn(record));
            if(node != NULL)
            {
                deleted = (nsec3_chain_replay_record*)node->value;
                if(deleted->status != NSEC3_CHAIN_REPLAY_STATUS_UPDATED)
                {
                    // will be deleted
                }
            }
        }

        // everything checks out : lock the zone for writing

        n = ptr_vector_size(&crd->del_nsec3_rrsig_records);

        for(int i = 0; i < n; ++i)
        {
            nsec3_chain_replay_record *record = (nsec3_chain_replay_record*)ptr_vector_get(&crd->del_nsec3_rrsig_records, i);

            nsec3_zone_item *item = nsec3_chain_replay_record_find_item_by_name(crd->zone, record);
            if(item != NULL)
            {
                // remove RRSIG
                const zdb_ttlrdata nsec3_rrsig =
                {
                    NULL,
                    record->ttl,
                    record->rdata_size,
                    0,
                    (u8*)nsec3_chain_replay_record_rdata(record)
                };
                nsec3_zone_item_rrsig_del(item, &nsec3_rrsig);
                continue;
            }

            rdata_desc type_len_rdata = {TYPE_RRSIG, record->rdata_size, nsec3_chain_replay_record_rdata(record)};
            log_warn("nsec3-chain: - %{dnsname} %{typerdatadesc} failed", nsec3_chain_replay_record_fqdn(record), &type_len_rdata);
        }

        n = ptr_vector_size(&crd->del_nsec3_records);

        for(int i = 0; i < n; ++i)
        {
            nsec3_chain_replay_record *record = (nsec3_chain_replay_record*)ptr_vector_get(&crd->del_nsec3_records, i);
            if(record->status == 0)
            {
                // nsec3_zone *n3 = nsec3_chain_replay_record_find_chain(crd->zone, record);
                // remove the record from n3
#ifdef DEBUG
                const rdata_desc type_len_rdata =
                {
                    TYPE_NSEC3,
                    record->rdata_size,
                    nsec3_chain_replay_record_rdata(record)
                };
                log_debug("nsec3-chain: - %{dnsname} %{typerdatadesc}", nsec3_chain_replay_record_fqdn(record), &type_len_rdata);
#endif
                nsec3_zone *n3 = nsec3_chain_replay_record_find_chain(crd->zone, record);
                if(n3 != NULL)
                {
                    const u8 *record_fqdn = nsec3_chain_replay_record_fqdn(record);
                    ya_result digest_len = base32hex_decode(
                            (char*)&record_fqdn[1],
                            (u32)record_fqdn[0], &tmp_digest[1]);

                    yassert((digest_len >= 0) && (digest_len < sizeof(tmp_digest) - 1));

                    tmp_digest[0] = digest_len;

                    nsec3_zone_item *item = nsec3_avl_find(&n3->items, tmp_digest);
#ifdef DEBUG
                    yassert(item != NULL);
#endif
                    // detach all RC and SC

                    nsec3_remove_all_owners(item);

                    // all the removed stars should be moved to the pred
                    nsec3_node *prev = nsec3_avl_node_mod_prev(item);
                    if((prev != NULL) && (prev != item))
                    {
                        nsec3_move_all_star(item, prev);
                    }
                    else
                    {
                        nsec3_remove_all_star(item);
                    }

                    nsec3_avl_delete(&n3->items, tmp_digest);
                }
            }
            // else the record is being updated
        }

        n = ptr_vector_size(&crd->add_nsec3_records);

        for(int i = 0; i < n; ++i)
        {
            nsec3_chain_replay_record *record = (nsec3_chain_replay_record*)ptr_vector_get(&crd->add_nsec3_records, i);
            nsec3_zone *n3 = nsec3_chain_replay_record_find_chain(crd->zone, record);
            if(n3 == NULL)
            {
                // create the new chain
                n3 = nsec3_chain_replay_record_add_chain(crd->zone, record);
            }

            if(record->status == 0)
            {
                // insert the new record

#ifdef DEBUG
                const rdata_desc type_len_rdata =
                {
                    TYPE_NSEC3,
                    record->rdata_size,
                    (u8*)nsec3_chain_replay_record_rdata(record)
                };
                log_debug("nsec3-chain: + %{dnsname} %{typerdatadesc}", nsec3_chain_replay_record_fqdn(record), &type_len_rdata);
#endif

                const u8 *record_fqdn = nsec3_chain_replay_record_fqdn(record);
                ya_result digest_len = base32hex_decode(
                        (char*)&record_fqdn[1],
                        (u32)record_fqdn[0], &tmp_digest[1]);

                yassert((digest_len >= 0) && (digest_len < sizeof(tmp_digest) - 1));

                const u8 *rdata = nsec3_chain_replay_record_rdata(record);
                
                if(rdata[1] != 0)
                {
                    expected_mode |= ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT;
                }

                tmp_digest[0] = digest_len;

                nsec3_zone_item *item = nsec3_avl_insert(&n3->items, tmp_digest);
                //item->
                nsec3_zone_item_update_bitmap(item, nsec3_chain_replay_record_rdata(record), record->rdata_size);
                
                item->flags = rdata[1];

                // for all fqdns, find the one(s) matching this and link its label
                // look for the pred of item, and move relevant *.fqdn to item
                //
                // This is done later (fqdn iteration)
            }
            else
            {
                const u8 *rdata = nsec3_chain_replay_record_rdata(record);
#ifdef DEBUG
                rdata_desc type_len_rdata =
                {
                    TYPE_NSEC3,
                    record->rdata_size,
                    rdata
                };
                log_debug("nsec3-chain: ~ %{dnsname} %{typerdatadesc}", nsec3_chain_replay_record_fqdn(record), &type_len_rdata);
#endif

                // update the old record
                nsec3_zone_item *item = nsec3_zone_item_find_by_name(n3, nsec3_chain_replay_record_fqdn(record));
                nsec3_zone_item_update_bitmap(item, nsec3_chain_replay_record_rdata(record), record->rdata_size);
                
                item->flags = rdata[1];
            }
        }

        n = ptr_vector_size(&crd->add_nsec3_rrsig_records);

        for(int i = 0; i < n; ++i)
        {
            nsec3_chain_replay_record *record = (nsec3_chain_replay_record*)ptr_vector_get(&crd->add_nsec3_rrsig_records, i);
            nsec3_zone_item *item = nsec3_chain_replay_record_find_item_by_name(crd->zone, record);
            if(item != NULL)
            {
                // remove RRSIG
                zdb_packed_ttlrdata* nsec3_rrsig;
                ZDB_RECORD_ZALLOC(nsec3_rrsig,record->ttl,record->rdata_size,nsec3_chain_replay_record_rdata(record));
                nsec3_rrsig->next = NULL;
                nsec3_zone_item_rrsig_add(item, nsec3_rrsig);
                continue;
            }

            const rdata_desc type_len_rdata = {TYPE_RRSIG, record->rdata_size, nsec3_chain_replay_record_rdata(record)};
            log_warn("nsec3-chain: + %{dnsname} %{typerdatadesc} failed", nsec3_chain_replay_record_fqdn(record), &type_len_rdata);
        }

        // if an nsec3param just appeared, generate the chain if it's the first/only one

        if(ptr_vector_last_index(&crd->add_nsec3param_records) >= 0)
        {
            // this triggers addition of the chain
            log_debug("nsec3-chain: %{dnsname}: NSEC3PARAM added", crd->zone->origin);
        }

        // if there is an active chain, and crd->fqdns is not empty : link the chain

        nsec3_zone *n3 = crd->zone->nsec.nsec3;
        
        if(n3 != NULL)
        {        
            ptr_set_avl_iterator iter;
            ptr_set_avl_iterator_init(&crd->fqdns, &iter);
            while(ptr_set_avl_iterator_hasnext(&iter))
            {
                ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
                const u8 *fqdn = (const u8*)node->key;

                // this FQDN link can be updated
                (void)fqdn;
                // get the label
                zdb_rr_label* label = zdb_rr_label_find_from_name(crd->zone, fqdn);



                if(label == NULL)
                {
                    continue;
                }

                // evaluate N3COVERED and N3OCOVERED

                u8 maintain_mode = zone_get_maintain_mode(crd->zone) | expected_mode;

                if(ZDB_LABEL_ATORUNDERDELEGATION(label))
                {
                    if(!ZDB_LABEL_UNDERDELEGATION(label))
                    {
                        label->flags |= ZDB_RR_LABEL_N3COVERED;

                        if(zdb_rr_label_has_rrset(label, TYPE_DS))
                        {
                            label->flags |= ZDB_RR_LABEL_N3OCOVERED; // at opt-out delegation 
                        }
                        else
                        {
                            label->flags &= ~ZDB_RR_LABEL_N3OCOVERED; // not at opt-out delegation (anymore)
                        }
                    }
                    else
                    {
                        label->flags &= ~(ZDB_RR_LABEL_N3COVERED|ZDB_RR_LABEL_N3OCOVERED); // under delegation
                    }
                }
                else
                {
                    label->flags |= ZDB_RR_LABEL_N3COVERED|ZDB_RR_LABEL_N3OCOVERED; // above delegation
                }

                switch(maintain_mode)
                {
                    case ZDB_ZONE_MAINTAIN_NSEC3:
                    {
                        if((label->flags & ZDB_RR_LABEL_N3COVERED) && !nsec3_avl_isempty(&n3->items) /*&& (!zdb_rr_label_nsec3_linked(label))*/)
                        {
                            // bind it
                            nsec3_zone_label_update_chain0_links(n3, label, fqdn);
                        }
                        break;
                    }
                    case ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:
                    {
                        if((label->flags & ZDB_RR_LABEL_N3OCOVERED) && !nsec3_avl_isempty(&n3->items) /*&& (!zdb_rr_label_nsec3optout_linked(label))*/)
                        {
                            // bind it
                            nsec3_zone_label_update_chain0_links(n3, label, fqdn);
                        }
                        break;
                    }
                }
            }
        }
    }
    
    // unlock the zone for writing
    
    ptr_set_avl_destroy(&del_nsec3_set);
    
    ptr_vector_free_empties(&crd->del_nsec3_records, nsec3_chain_replay_record_delete_cb);
    ptr_vector_free_empties(&crd->add_nsec3_records, nsec3_chain_replay_record_delete_cb);
    ptr_vector_free_empties(&crd->del_nsec3_rrsig_records, nsec3_chain_replay_record_delete_cb);
    ptr_vector_free_empties(&crd->add_nsec3_rrsig_records, nsec3_chain_replay_record_delete_cb);
    ptr_vector_free_empties(&crd->del_nsec3param_records, nsec3_chain_replay_record_delete_cb);
    ptr_vector_free_empties(&crd->add_nsec3param_records, nsec3_chain_replay_record_delete_cb);
    ptr_set_avl_callback_and_destroy(&crd->fqdns, nsec3_chain_replay_fqdn_key_delete);
    
    return SUCCESS;
}

static void
nsec3_chain_replay_finalise(chain_replay *cr)
{
    nsec3_chain_replay_data *crd = (nsec3_chain_replay_data*)cr->data;
    
    ptr_vector_free_empties(&crd->del_nsec3_records, nsec3_chain_replay_record_delete_cb);
    ptr_vector_free_empties(&crd->add_nsec3_records, nsec3_chain_replay_record_delete_cb);
    ptr_vector_free_empties(&crd->del_nsec3_rrsig_records, nsec3_chain_replay_record_delete_cb);
    ptr_vector_free_empties(&crd->add_nsec3_rrsig_records, nsec3_chain_replay_record_delete_cb);
    ptr_vector_free_empties(&crd->del_nsec3param_records, nsec3_chain_replay_record_delete_cb);
    ptr_vector_free_empties(&crd->add_nsec3param_records, nsec3_chain_replay_record_delete_cb);
    
    ptr_vector_destroy(&crd->del_nsec3_records);
    ptr_vector_destroy(&crd->add_nsec3_records);
    ptr_vector_destroy(&crd->del_nsec3_rrsig_records);
    ptr_vector_destroy(&crd->add_nsec3_rrsig_records);
    ptr_vector_destroy(&crd->del_nsec3param_records);
    ptr_vector_destroy(&crd->add_nsec3param_records);
    ptr_set_avl_callback_and_destroy(&crd->fqdns, nsec3_chain_replay_fqdn_key_delete);
    
    zdb_zone_release(crd->zone);
    crd->zone = NULL;
    
    // release memory
}

static const struct chain_replay_vtbl nsec3_chain_replay_vtbl =
{
    nsec3_chain_replay_record_add,
    nsec3_chain_replay_record_del,
    nsec3_chain_replay_execute,
    nsec3_chain_replay_finalise,
    "nsec3_chain_replay"
};

ya_result
nsec3_chain_replay_init(chain_replay *cr, zdb_zone *zone)
{
    nsec3_chain_replay_data *data;
    ZALLOC_OR_DIE(nsec3_chain_replay_data*, data, nsec3_chain_replay_data, NSEC3RPL_TAG);
    data->fqdns.root = NULL;
    data->fqdns.compare = ptr_set_dnsname_node_compare;
    ptr_vector_init(&data->del_nsec3_records);
    ptr_vector_init(&data->add_nsec3_records);
    ptr_vector_init(&data->del_nsec3_rrsig_records);
    ptr_vector_init(&data->add_nsec3_rrsig_records);
    ptr_vector_init(&data->del_nsec3param_records);
    ptr_vector_init(&data->add_nsec3param_records);
    
    zdb_zone_acquire(zone);
    data->zone = zone;
    cr->vtbl = &nsec3_chain_replay_vtbl;
    cr->data = data;
    return SUCCESS;
}

/** @} */


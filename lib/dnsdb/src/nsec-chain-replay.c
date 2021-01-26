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

/** @defgroup nsec NSEC functions
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
#include "dnsdb/nsec-chain-replay.h"
#include "dnsdb/nsec.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/zdb-zone-arc.h"

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

#define NSEC_CHAIN_REPLAY_DEBUG 0

#define NSEC3CNR_TAG 0x524e433345534e
#define NSEC3RPL_TAG 0x4c50523345534e

struct nsec_chain_replay_record
{
    u8 status;
    u8 fqdn[];
};

typedef struct nsec_chain_replay_record nsec_chain_replay_record;

static nsec_chain_replay_record *
nsec_chain_replay_record_new(const u8 *fqdn, s32 ttl, const u8 *rdata, u16 rdata_size)
{
    nsec_chain_replay_record *record;
    int fqdn_len = dnsname_len(fqdn);
    ZALLOC_ARRAY_OR_DIE(nsec_chain_replay_record*, record, sizeof(nsec_chain_replay_record) + fqdn_len, NSEC3CNR_TAG);
    (void)ttl;
    (void)rdata;
    (void)rdata_size;
    record->status = 0;
    memcpy(record->fqdn, fqdn, fqdn_len);
    return record;
}

static void
nsec_chain_replay_record_delete(nsec_chain_replay_record *record)
{
    int fqdn_len = dnsname_len(record->fqdn);
    ZFREE_ARRAY(record, sizeof(nsec_chain_replay_record) + fqdn_len);
}

static void
nsec_chain_replay_record_delete_cb(void *record)
{
    nsec_chain_replay_record_delete((nsec_chain_replay_record*)record);
}

static const u8 *
nsec_chain_replay_record_fqdn(nsec_chain_replay_record *record)
{
    return record->fqdn;
}

static int
nsec_chain_replay_record_nsec_compare(const void *a, const void *b)
{
    nsec_chain_replay_record *ra = (nsec_chain_replay_record*)a;
    nsec_chain_replay_record *rb = (nsec_chain_replay_record*)b;
    int d = dnsname_compare(nsec_chain_replay_record_fqdn(ra), nsec_chain_replay_record_fqdn(rb));
    return d;
}

struct nsec_chain_replay_data
{
    zdb_zone *zone;
    ptr_vector del_nsec_records;
    ptr_vector add_nsec_records;
};

typedef struct nsec_chain_replay_data nsec_chain_replay_data;

static ya_result
nsec_chain_replay_record_del(chain_replay *cr, const u8 *fqdn, u16 rtype, const zdb_ttlrdata *ttlrdata)
{
    nsec_chain_replay_data *crd = (nsec_chain_replay_data*)cr->data;
    
#if NSEC_CHAIN_REPLAY_DEBUG
    rdata_desc type_len_rdata = {rtype, ZDB_RECORD_PTR_RDATASIZE(ttlrdata), ZDB_RECORD_PTR_RDATAPTR(ttlrdata)};
    log_debug("nsec-chain: del %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
#endif
    
    switch(rtype)
    {
        case TYPE_NSEC:
        {
            ptr_vector_append(&crd->del_nsec_records, nsec_chain_replay_record_new(fqdn, ttlrdata->ttl, ZDB_RECORD_PTR_RDATAPTR(ttlrdata), ZDB_RECORD_PTR_RDATASIZE(ttlrdata)));
            return 0;
        }
        default:
        {
            return 0;
        }
    }
}

static ya_result
nsec_chain_replay_record_add(chain_replay *cr, const u8 *fqdn, u16 rtype, const zdb_ttlrdata *ttlrdata)
{
    nsec_chain_replay_data *crd = (nsec_chain_replay_data*)cr->data;
    
#if NSEC_CHAIN_REPLAY_DEBUG
    rdata_desc type_len_rdata = {rtype, ZDB_RECORD_PTR_RDATASIZE(ttlrdata), ZDB_RECORD_PTR_RDATAPTR(ttlrdata)};
    log_debug("nsec-chain: add %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
#endif
    
    switch(rtype)
    {
        case TYPE_NSEC:
        {
            ptr_vector_append(&crd->add_nsec_records, nsec_chain_replay_record_new(fqdn, ttlrdata->ttl, ZDB_RECORD_PTR_RDATAPTR(ttlrdata), ZDB_RECORD_PTR_RDATASIZE(ttlrdata)));
            return 0;
        }
        default:
        {
            return 0;
        }
    }
}

static ya_result
nsec_chain_replay_execute(chain_replay *cr)
{
    // sort NSEC records by chain,fqdn
    // verify chains are making sense
    // remove signatures from the relevant nsec_zone
    // remove nodes from the relevant nsec_zone
    // add nodes to the relevant nsec_zone
    // add signatures to the relevant nsec_zone
    // if an nsecparam was removed, choose the new best chain
    // (start) unlink old chain and add new chain
    
    nsec_chain_replay_data *crd = (nsec_chain_replay_data*)cr->data;
    dnslabel_vector labels;
    
    ptr_set del_nsec_set = PTR_SET_DNSNAME_EMPTY;
    
    ptr_vector_qsort(&crd->del_nsec_records, nsec_chain_replay_record_nsec_compare);
    ptr_vector_qsort(&crd->add_nsec_records, nsec_chain_replay_record_nsec_compare);
    
    for(int i = 0; i < ptr_vector_size(&crd->del_nsec_records); ++i)
    {
        nsec_chain_replay_record *record = (nsec_chain_replay_record*)ptr_vector_get(&crd->del_nsec_records, i);
        
        // check the record exists
        //   find the chain
        //   find the record
        
        // keep a quick access on the record
        
        ptr_node *node = ptr_set_insert(&del_nsec_set, (u8*)nsec_chain_replay_record_fqdn(record));
        if(node->value == NULL)
        {
            
            node->value = record;
        }
        else
        {
            // duplicate : something is wrong
        }
    }
    
    for(int i = 0; i < ptr_vector_size(&crd->add_nsec_records); ++i)
    {
        nsec_chain_replay_record *record = (nsec_chain_replay_record*)ptr_vector_get(&crd->add_nsec_records, i);
        
        // find the start of a sub-chain
        // find the end of the sub-chain
        // if the sub-chain is not looping, the head must exist (and is being removed/added)
        
        // check for updates
        
        ptr_node *node = ptr_set_find(&del_nsec_set, nsec_chain_replay_record_fqdn(record));
        if(node != NULL)
        {
            // the record is updated
            nsec_chain_replay_record *old_record = (nsec_chain_replay_record*)node->value;
            record->status = 1;
            old_record->status = 1;
        }
    }
    
    for(int i = ptr_vector_size(&crd->add_nsec_records); i >= 0; --i)
    {
        // check the next record exist or is 
        //   find the chain
        //   find the record
    }
    
    // everything checks out : lock the zone for writing
        
    for(int i = 0; i < ptr_vector_size(&crd->del_nsec_records); ++i)
    {
        nsec_chain_replay_record *record = (nsec_chain_replay_record*)ptr_vector_get(&crd->del_nsec_records, i);
        if(record->status == 0)
        {
#if NSEC_CHAIN_REPLAY_DEBUG
            log_debug("nsec-chain: - %{dnsname}", nsec_chain_replay_record_fqdn(record));
#endif
            s32 labels_top = dnsname_to_dnslabel_vector(record->fqdn, labels);

            nsec_delete_label_node(crd->zone, labels, labels_top);
            
            zdb_rr_label* label = zdb_rr_label_find_exact(crd->zone->apex, labels, labels_top - crd->zone->origin_vector.size - 1);
            if(label != NULL)
            {
                if(RR_LABEL_IRRELEVANT(label))  // irrelevant and RR_LABEL_EMPTY_TERMINAL should be equivalent here
                {
                    ya_result ret;
                    if(FAIL(ret = zdb_rr_label_delete_record(crd->zone, labels, labels_top - crd->zone->origin_vector.size - 1, TYPE_ANY)))
                    {
                        log_err("nsec-chain: - %{dnsname} could not be removed from the zone: %r", nsec_chain_replay_record_fqdn(record), ret);
                    }
                }
            }
        }
        // else the record is being updated
    }
    
    for(int i = 0; i < ptr_vector_size(&crd->add_nsec_records); ++i)
    {
        nsec_chain_replay_record *record = (nsec_chain_replay_record*)ptr_vector_get(&crd->add_nsec_records, i);

        if(record->status == 0)
        {
            // insert the new record
            
#if NSEC_CHAIN_REPLAY_DEBUG
            log_debug("nsec-chain: + %{dnsname}", nsec_chain_replay_record_fqdn(record));
#endif           
            s32 labels_top = dnsname_to_dnslabel_vector(record->fqdn, labels);
            
            zdb_rr_label* label = zdb_rr_label_find_exact(crd->zone->apex, labels, labels_top - crd->zone->origin_vector.size - 1);
            if(label != NULL)
            {
                nsec_update_label_node(crd->zone, label, labels, labels_top);
            }
        }
        else
        {
#if NSEC_CHAIN_REPLAY_DEBUG
            log_debug("nsec-chain: ~ %{dnsname}", nsec_chain_replay_record_fqdn(record));
#endif
        }
    }
        
    // unlock the zone for writing
    
    ptr_set_destroy(&del_nsec_set);
    
    ptr_vector_callback_and_clear(&crd->del_nsec_records, nsec_chain_replay_record_delete_cb);
    ptr_vector_callback_and_clear(&crd->add_nsec_records, nsec_chain_replay_record_delete_cb);
        
    return SUCCESS;
}

static void
nsec_chain_replay_finalize(chain_replay *cr)
{
    nsec_chain_replay_data *crd = (nsec_chain_replay_data*)cr->data;
    
    ptr_vector_callback_and_clear(&crd->del_nsec_records, nsec_chain_replay_record_delete_cb);
    ptr_vector_callback_and_clear(&crd->add_nsec_records, nsec_chain_replay_record_delete_cb);
    ptr_vector_destroy(&crd->del_nsec_records);
    ptr_vector_destroy(&crd->add_nsec_records);
    
    zdb_zone_release(crd->zone);
    crd->zone = NULL;
    
    // release memory
    
    ZFREE_OBJECT(crd);
    cr->data = NULL;
}

static const struct chain_replay_vtbl nsec_chain_replay_vtbl =
{
    nsec_chain_replay_record_add,
    nsec_chain_replay_record_del,
    nsec_chain_replay_execute,
    nsec_chain_replay_finalize,
    "nsec_chain_replay"
};

ya_result
nsec_chain_replay_init(chain_replay *cr, zdb_zone *zone)
{
    nsec_chain_replay_data *data;
    ZALLOC_OBJECT_OR_DIE(data, nsec_chain_replay_data, NSEC3RPL_TAG);
    ptr_vector_init(&data->del_nsec_records);
    ptr_vector_init(&data->add_nsec_records);    
    zdb_zone_acquire(zone);
    data->zone = zone;
    cr->vtbl = &nsec_chain_replay_vtbl;
    cr->data = data;
    return SUCCESS;
}

/** @} */

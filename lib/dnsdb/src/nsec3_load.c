/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2018, EURid vzw. All rights reserved.
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

#define DEBUG_LEVEL 0

#include <dnscore/dnscore.h>
#include <dnscore/ptr_set.h>

#include "dnsdb/dnssec.h"

#include "dnsdb/nsec3_load.h"
#include "dnsdb/nsec3_zone.h"

#include <dnscore/base32hex.h>

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

#define N3CHNCTX_TAG 0x5854434e4843334e
#define N3PRDATA_TAG 0x415441445250334e

#define N3LCTXRR_TAG 0x52525854434c334e
#define N3LCTXCN_TAG 0x434e5854434c334e
#define N3LKEYDG_TAG 0x474459454b4c334e

/******************************************************************************
 *
 * NSEC3 - load (ie: from zone file / axfr / ...)
 *
 *****************************************************************************/

struct nsec3_context_record
{
    zdb_packed_ttlrdata *rrsig;
    u32 ttl;
    u16 rdata_size;
    u8 digest_then_rdata[];
};

typedef struct nsec3_context_record nsec3_context_record;

struct nsec3_load_context_chain
{
    ptr_vector  nsec3_added;         // array of full of records
    u16         nsec3param_rdata_size;
    bool        has_nsec3param;
    u8          nsec3param_rdata[];
};

typedef struct nsec3_load_context_chain nsec3_load_context_chain;

static void
nsec3_load_context_record_delete(nsec3_context_record *r)
{
    zdb_packed_ttlrdata *rrsig = r->rrsig;
    while(rrsig != NULL)
    {
        zdb_packed_ttlrdata *next = rrsig->next;
        ZDB_RECORD_ZFREE(rrsig);
        rrsig = next;
    }
    size_t digest_len = 1 + r->digest_then_rdata[0];
    ZFREE_ARRAY(r, sizeof(nsec3_context_record) + digest_len + r->rdata_size);
}

static nsec3_context_record*
nsec3_load_context_record_new(const u8 *digest, s32 ttl, const u8 *rdata, u16 rdata_size)
{
    u8 digest_len = BASE32HEX_DECODED_LEN(digest[0]);
 
    nsec3_context_record* record;
        
    ZALLOC_ARRAY_OR_DIE(nsec3_context_record*, record, sizeof(nsec3_context_record) + 1 + digest_len + rdata_size, N3LCTXRR_TAG);
    record->rrsig = NULL;
    record->ttl = ttl;
    record->rdata_size = rdata_size;
    
    //memcpy(&record->digest_then_rdata[0], digest, digest_len);
    record->digest_then_rdata[0] = digest_len;
    
    if(ISOK(base32hex_decode((const char*)&digest[1], digest[0], &record->digest_then_rdata[1])))
    {
        memcpy(&record->digest_then_rdata[digest_len + 1], rdata, rdata_size);    
        return record;
    }
    else
    {
        nsec3_load_context_record_delete(record);
        return NULL;
    }
}

static void
nsec3_load_context_record_delete_void(void *r)
{
    nsec3_load_context_record_delete((nsec3_context_record*)r);
}

static const u8*
nsec3_load_context_record_rdata(const nsec3_context_record *r)
{
    size_t digest_len = 1 + r->digest_then_rdata[0];
    return &r->digest_then_rdata[digest_len];
}

static const u8*
nsec3_load_context_record_next_digest(const nsec3_context_record *r)
{
    const u8 *rdata = nsec3_load_context_record_rdata(r);
    size_t nsec3param_size = NSEC3PARAM_RDATA_SIZE_FROM_RDATA(rdata);
    return &rdata[nsec3param_size];
}

static int
nsec3_load_context_record_qsort_callback(const void *a, const void *b)
{
    const nsec3_context_record *ra = *(nsec3_context_record**)a;
    const nsec3_context_record *rb = *(nsec3_context_record**)b;
    int ra_size = ra->digest_then_rdata[0];
    int rb_size = rb->digest_then_rdata[0];
    int d = ra_size - rb_size;
    if(d == 0)
    {
        d = memcmp(ra->digest_then_rdata, rb->digest_then_rdata, ra_size + 1);
    }
    return d;
}

static bool
nsec3_load_context_record_linked(const nsec3_context_record *ra, const nsec3_context_record *rb)
{
    const u8 *next_digest = nsec3_load_context_record_next_digest(ra);
    int next_size = next_digest[0];
    int size = rb->digest_then_rdata[0];
    if(next_size == size)
    {
        return memcmp(&next_digest[1], &rb->digest_then_rdata[1], size) == 0;
    }
    return FALSE;
}

static nsec3_load_context_chain*
nsec3_load_context_chain_new(nsec3_context_record *r)
{
    nsec3_load_context_chain *chain;
    
    const u8 *nsec3param_rdata = nsec3_load_context_record_rdata(r);
    size_t nsec3param_size = NSEC3PARAM_RDATA_SIZE_FROM_RDATA(nsec3param_rdata);
        
    ZALLOC_ARRAY_OR_DIE(nsec3_load_context_chain*, chain, sizeof(nsec3_load_context_chain) + nsec3param_size, N3LCTXCN_TAG);
    ZEROMEMORY(chain, sizeof(nsec3_load_context_chain));
    ptr_vector_init_ex(&chain->nsec3_added, 65536);
    chain->nsec3param_rdata_size = nsec3param_size;
    memcpy(chain->nsec3param_rdata, nsec3param_rdata, nsec3param_size);
    
    return chain;
}

static void
nsec3_load_context_chain_delete(nsec3_load_context_chain *chain)
{
    ptr_vector_free_empties(&chain->nsec3_added, nsec3_load_context_record_delete_void);
    ZFREE_ARRAY(chain, sizeof(nsec3_load_context_chain) + chain->nsec3param_rdata_size);
}

static void
nsec3_load_context_chain_add_nsec3(nsec3_load_context_chain *chain, nsec3_context_record *r)
{
    ptr_vector_append(&chain->nsec3_added, r);
}

static int
nsec3_load_context_chain_qsort_callback(const void *a, const void *b)
{
    const nsec3_load_context_chain *ca = *(nsec3_load_context_chain**)a;
    const nsec3_load_context_chain *cb = *(nsec3_load_context_chain**)b;
    int d = (ca->has_nsec3param?1:0) - (cb->has_nsec3param?1:0);
    if(d == 0)
    {
        d = ca->nsec3param_rdata_size - cb->nsec3param_rdata_size;
        
        if(d == 0)
        {
            d = memcmp(ca->nsec3param_rdata, cb->nsec3param_rdata, ca->nsec3param_rdata_size);
        }
    }
    return d;
}

static bool
nsec3_load_context_chain_matches(nsec3_load_context_chain *chain, const u8 *rdata, u16 rdata_size)
{
    if((chain->nsec3param_rdata_size <= rdata_size) && (chain->nsec3param_rdata[0] == rdata[0]))
    {
        if(memcmp(&chain->nsec3param_rdata[2], &rdata[2], chain->nsec3param_rdata_size - 2) == 0)
        {
            return TRUE;
        }
    }
    
    return FALSE;
}

static nsec3_load_context_chain*
nsec3_load_context_get_chain(nsec3_load_context *context, nsec3_context_record *r)
{
    // ptr_node *r_node = ptr_set_avl_insert(&context->nsec3chain, r);
    for(int i = 0; i <= ptr_vector_last_index(&context->nsec3chain); ++i)
    {
        nsec3_load_context_chain *chain = (nsec3_load_context_chain*)ptr_vector_get(&context->nsec3chain, i);
        if(nsec3_load_context_chain_matches(chain, nsec3_load_context_record_rdata(r), r->rdata_size))
        {
            return chain;
        }
    }
    
    nsec3_load_context_chain *chain = nsec3_load_context_chain_new(r);
    
    ptr_vector_append(&context->nsec3chain, chain);
    
    return chain;
}



static int nsec3_load_postponed_rrsig_node_compare(const void *node_a, const void *node_b)
{
    const u8 *key_a = (const u8*)node_a;
    const u8 *key_b = (const u8*)node_b;
    int d = key_a[0];
    d -= key_b[0];
    if(d == 0)
    {
        d = memcmp(&key_a[1], &key_b[1], key_a[0]);
    }
    return d;
}

ya_result
nsec3_load_init(nsec3_load_context *context, zdb_zone* zone)
{
    ZEROMEMORY(context, sizeof(nsec3_load_context));
    ptr_vector_init_ex(&context->nsec3chain, 2);
    ptr_set_avl_init(&context->postponed_rrsig);
    context->postponed_rrsig.compare = nsec3_load_postponed_rrsig_node_compare;
    context->zone = zone;
    context->opt_out = TRUE;

    return SUCCESS;
}

void
nsec3_load_destroy(nsec3_load_context *context)
{
    for(int i = 0; i <= ptr_vector_last_index(&context->nsec3chain); ++i)
    {
        nsec3_load_context_chain *chain = (nsec3_load_context_chain*)ptr_vector_get(&context->nsec3chain, i);
        nsec3_load_context_chain_delete(chain);
    }
    
    if(!ptr_set_avl_isempty(&context->postponed_rrsig))
    {
        ptr_set_avl_iterator iter;
        ptr_set_avl_iterator_init(&context->postponed_rrsig, &iter);
        while(ptr_set_avl_iterator_hasnext(&iter))
        {
            ptr_node *rrsig_node = ptr_set_avl_iterator_next_node(&iter);
            u8 *key = (u8*)rrsig_node->key;
            if(rrsig_node->key != NULL)
            {
                ZFREE_ARRAY(rrsig_node->key, key[0] + 1);
            }
            rrsig_node->key = NULL;
            rrsig_node->value = NULL;
        }

        ptr_set_avl_destroy(&context->postponed_rrsig);
    }
    
    context->zone = NULL;
}

ya_result
nsec3_load_add_nsec3param(nsec3_load_context *context, const u8 *rdata, u16 rdata_size)
{
    if((rdata_size < 5) || (NSEC3_RDATA_ALGORITHM(rdata) != DNSSEC_DIGEST_TYPE_SHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM;
    }
    
    nsec3_context_record* nsec3param_r = nsec3_load_context_record_new((const u8*)"", 0, rdata, rdata_size);
    nsec3_load_context_chain* chain = nsec3_load_context_get_chain(context, nsec3param_r);
    nsec3_load_context_record_delete(nsec3param_r);
    chain->has_nsec3param = TRUE;
    
    return SUCCESS;
}

ya_result
nsec3_load_add_nsec3(nsec3_load_context *context, const u8 *digest, s32 ttl, const  u8 *rdata, u16 rdata_size)
{
    /*
     * Get the right chain from the rdata
     * Add the record to the chain
     */
    
    if((rdata_size < 5) || (NSEC3_RDATA_ALGORITHM(rdata) != DNSSEC_DIGEST_TYPE_SHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM;
    }
    
    nsec3_context_record* nsec3_r = nsec3_load_context_record_new(digest, ttl, rdata, rdata_size);
    if(nsec3_r != NULL)
    {
        nsec3_load_context_chain* chain = nsec3_load_context_get_chain(context, nsec3_r);
        nsec3_load_context_chain_add_nsec3(chain, nsec3_r);

        context->last_inserted_nsec3 = nsec3_r;
        
        if(!ptr_set_avl_isempty(&context->postponed_rrsig))
        {
            ptr_node *node = ptr_set_avl_find(&context->postponed_rrsig, nsec3_r->digest_then_rdata);
            
            if(node != NULL)
            {
                u8 *key = node->key;
                nsec3_r->rrsig = (zdb_packed_ttlrdata*)node->value;
                ptr_set_avl_delete(&context->postponed_rrsig, nsec3_r->digest_then_rdata);
                ZFREE_ARRAY(key, key[0] + 1);
            }
        }
        
        return SUCCESS;
    }
    else
    {
        context->last_inserted_nsec3 = NULL;
        
        return DNSSEC_ERROR_NSEC3_LABELTODIGESTFAILED;
    }
}

ya_result
nsec3_load_add_rrsig(nsec3_load_context *context, const  u8 *digest_label, s32 ttl, const u8 *rdata, u16 rdata_size)
{
    u8 digest_len = BASE32HEX_DECODED_LEN(digest_label[0]);
    u8 digest[digest_len + 1];
    digest[0] = digest_len;
    if(ISOK(base32hex_decode((const char*)&digest_label[1], digest_label[0], &digest[1])))
    {
        zdb_packed_ttlrdata *rrsig;
        ZDB_RECORD_ZALLOC(rrsig,ttl,rdata_size,rdata);
                
        if(context->last_inserted_nsec3 != NULL)
        {
            nsec3_context_record* nsec3_r = (nsec3_context_record*)context->last_inserted_nsec3;
            if(memcmp(nsec3_r->digest_then_rdata, digest, 1 + digest[0]) == 0)
            {
                rrsig->next = nsec3_r->rrsig;
                nsec3_r->rrsig = rrsig;
                
                return SUCCESS;
            }
        }
        
        // the records are not nicely ordered : need to postpone the insertion of this record.
        
        ptr_node *node = ptr_set_avl_insert(&context->postponed_rrsig, digest);
                
        if(node->value == NULL)
        {
            u8 *key;
            ZALLOC_ARRAY_OR_DIE(u8*, key, digest_len + 1, N3LKEYDG_TAG);
            memcpy(key, digest, digest_len + 1);
            node->key = key;
        }
        rrsig->next = (zdb_packed_ttlrdata*)node->value;
        node->value = rrsig;
        
        return SUCCESS;
    }
    else
    {
        return DNSSEC_ERROR_NSEC3_LABELTODIGESTFAILED;
    }
}

/*
 * Use this to add the NSEC3 information from the context to the zone
 */

ya_result
nsec3_load_generate(nsec3_load_context *context)
{
    // for all chains
    //   sort the records
    //   ensure the records are following (modulo)
    //   create the nsec3 chain collection
    //   add the collection to the zone (enabled or not)
    
    for(int i = 0; i <= ptr_vector_last_index(&context->nsec3chain); ++i)
    {
        nsec3_load_context_chain *chain = (nsec3_load_context_chain*)ptr_vector_get(&context->nsec3chain, i);
        
        if(ptr_vector_last_index(&chain->nsec3_added) > 0)
        {
            ptr_vector_qsort(&chain->nsec3_added, nsec3_load_context_record_qsort_callback);
            nsec3_context_record *p = (nsec3_context_record*)ptr_vector_last(&chain->nsec3_added);
            
            for(int j = 0; j <= ptr_vector_last_index(&chain->nsec3_added); ++j)
            {
                nsec3_context_record *r = (nsec3_context_record*)ptr_vector_get(&chain->nsec3_added, j);
                
                // the digest in the rdata of p has to be the digest of r
                                
                if(!nsec3_load_context_record_linked(p, r))
                {
                    // the chain is broken
                    return ERROR;
                }
                p = r;
            }
            
            if(!nsec3_load_context_record_linked(p, (nsec3_context_record*)ptr_vector_get(&chain->nsec3_added, 0)))
            {
                // the chain is broken
                return ERROR;
            }
        }
    }
    
    nsec3_zone **n3p = &context->zone->nsec.nsec3;

    // the chain are valid : create the collections
    
    // but first sort the collections to put the ones with NSEC3PARAM with smallest digest/iterations
    
    ptr_vector_qsort(&context->nsec3chain, nsec3_load_context_chain_qsort_callback);
    
    for(int i = 0; i <= ptr_vector_last_index(&context->nsec3chain); ++i)
    {
        nsec3_load_context_chain *chain = (nsec3_load_context_chain*)ptr_vector_get(&context->nsec3chain, i);
        
        nsec3_zone *n3 = nsec3_zone_new(chain->nsec3param_rdata, chain->nsec3param_rdata_size);
        
        for(int j = 0; j <= ptr_vector_last_index(&chain->nsec3_added); ++j)
        {
            nsec3_context_record *r = (nsec3_context_record*)ptr_vector_get(&chain->nsec3_added, j);
            const u8 *rdata = nsec3_load_context_record_rdata(r);
            nsec3_node *node = nsec3_avl_insert(&n3->items, r->digest_then_rdata);
            node->flags = rdata[1];
            nsec3_zone_item_update_bitmap(node, rdata, r->rdata_size);
            node->rrsig = r->rrsig;
            r->rrsig = NULL;
        }
        // the chain is complete
        
        *n3p = n3;
        n3p = &n3->next;
        
        // if the first chain has an nsec3param, it is visible
        if(i == 0 && chain->has_nsec3param)
        {
            // link the labels
            nsec3_zone_update_chain0_links(context->zone);
        }
    }
    
    // finally: add the postponed rrsig records
    
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&context->postponed_rrsig, &iter);
    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *rrsig_node = ptr_set_avl_iterator_next_node(&iter);
     
        bool useless = TRUE;
        
        for(nsec3_zone *n3 = context->zone->nsec.nsec3; n3 != NULL; n3 = n3->next)
        {
            nsec3_node *nsec3_node = nsec3_avl_find(&n3->items, rrsig_node->key);
            if(nsec3_node != NULL)
            {
                zdb_packed_ttlrdata *rrsig = (zdb_packed_ttlrdata*)rrsig_node->value;
                
                nsec3_node->rrsig = rrsig;
                u8 *key = (u8*)rrsig_node->key;
                ZFREE_ARRAY(rrsig_node->key, key[0] + 1);
                rrsig_node->key = NULL;
                rrsig_node->value = NULL;
                
                useless = FALSE;
                
                break;
            }
        }
        
        if(useless)
        {
            // complain
            log_warn("nsec3: %{dnsname}: %{digest32h}: RRSIG does not covers any known NSEC3 record",
                    context->zone->origin,
                    rrsig_node->key);
        }
    }
    
    return SUCCESS;
}

bool
nsec3_load_is_context_empty(nsec3_load_context* context)
{
    return (context->zone == NULL) || (ptr_vector_last_index(&context->nsec3chain) < 0);
}

/** @} */

/*----------------------------------------------------------------------------*/


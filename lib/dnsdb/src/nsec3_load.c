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

#define DEBUG_LEVEL 0

#include <dnscore/dnscore.h>
#include <dnscore/ptr_set.h>
#include <dnscore/base32hex.h>

#include "dnsdb/dnssec.h"

#include "dnsdb/nsec3_load.h"
#include "dnsdb/nsec3_zone.h"
#include "dnsdb/zdb_zone_label_iterator.h"

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

#define N3CHNCTX_TAG 0x5854434e4843334e
#define N3PRDATA_TAG 0x415441445250334e

#define N3LCTXRR_TAG 0x52525854434c334e
#define N3LCTXCN_TAG 0x434e5854434c334e
#define N3LKEYDG_TAG 0x474459454b4c334e
/*
;; Owner: mejnertsen
4Q9DAPPUSCM8987DU4UL56CF2O5S0CNO.eu.         600        NSEC3   1 1 1 5ca1ab1e 4Q9DE8JTV8EA3H4IP8KC33F1RJK45SD1
                                                        RRSIG   NSEC3 8 2 600 20181020080859 20180919080849 37080 eu. urzQ7qjZ5L+F0pEykY/IN5XHuwb5+iwqxz
*/
/******************************************************************************
 *
 * NSEC3 - load (ie: from zone file / axfr / ...)
 *
 *****************************************************************************/

struct nsec3_context_record
{
    zdb_packed_ttlrdata *rrsig;
    s32 ttl;
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
nsec3_load_context_record_delete_rrsig(nsec3_context_record *r)
{
    zdb_packed_ttlrdata *rrsig = r->rrsig;
    while(rrsig != NULL)
    {
        zdb_packed_ttlrdata *next = rrsig->next;
        ZDB_RECORD_ZFREE(rrsig);
        rrsig = next;
    }

    r->rrsig = NULL;
}

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

    size_t nsec3_context_record_size = sizeof(nsec3_context_record) + 1 + r->digest_then_rdata[0] + r->rdata_size;

#if DEBUG
    memset(r, 0xfe, nsec3_context_record_size);
#endif

    ZFREE_ARRAY(r, nsec3_context_record_size);
}

static nsec3_context_record*
nsec3_load_context_record_new(const u8 *base32hex_digest, s32 ttl, const u8 *rdata, u16 rdata_size)
{
    u8 digest_len = BASE32HEX_DECODED_LEN(base32hex_digest[0]);
 
    nsec3_context_record *record;
        
    ZALLOC_ARRAY_OR_DIE(nsec3_context_record*, record, sizeof(nsec3_context_record) + 1 + digest_len + rdata_size, N3LCTXRR_TAG);
    record->rrsig = NULL;
    record->ttl = ttl;
    record->rdata_size = rdata_size;
    
    // memcpy(&record->digest_then_rdata[0], digest, digest_len);
    record->digest_then_rdata[0] = digest_len;
    
    if(ISOK(base32hex_decode((const char*)&base32hex_digest[1], base32hex_digest[0], &record->digest_then_rdata[1])))
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

static nsec3_context_record*
nsec3_load_context_record_new_binary(const u8 *binary_digest, s32 ttl, u16 rdata_size)
{
    u8 digest_len = binary_digest[0];

    nsec3_context_record *record;

    ZALLOC_ARRAY_OR_DIE(nsec3_context_record*, record, sizeof(nsec3_context_record) + 1 + digest_len + rdata_size, N3LCTXRR_TAG);
    record->rrsig = NULL;
    record->ttl = ttl;
    record->rdata_size = rdata_size;

    record->digest_then_rdata[0] = digest_len;
    memcpy(record->digest_then_rdata, binary_digest, digest_len + 1);

#if DEBUG
    memset(&record->digest_then_rdata[digest_len + 1], 0xff, rdata_size);
#endif

    return record;
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
    const nsec3_context_record *ra = (nsec3_context_record*)a;
    const nsec3_context_record *rb = (nsec3_context_record*)b;
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
    
#if DEBUG
    log_debug("nsec3_load_context_chain_new(%p) -> (%p, %p)", r, chain, chain->nsec3_added.data);
#endif
    
    return chain;
}

static void
nsec3_load_context_chain_delete(nsec3_load_context_chain *chain)
{
#if DEBUG
    log_debug("nsec3_load_context_chain_delete(%p) -> (%p)", chain, chain->nsec3_added.data);
#endif
    
    ptr_vector_callback_and_destroy(&chain->nsec3_added, nsec3_load_context_record_delete_void);
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
    const nsec3_load_context_chain *ca = (nsec3_load_context_chain*)a;
    const nsec3_load_context_chain *cb = (nsec3_load_context_chain*)b;
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
    // ptr_node *r_node = ptr_set_insert(&context->nsec3chain, r);
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
    ptr_set_init(&context->postponed_rrsig);
    context->postponed_rrsig.compare = nsec3_load_postponed_rrsig_node_compare;
    context->zone = zone;
    context->opt_out = TRUE;

    return SUCCESS;
}

void
nsec3_load_destroy_nsec3chain_cb(void *ptr)
{
    nsec3_load_context_chain *chain = (nsec3_load_context_chain*)ptr;
    nsec3_load_context_chain_delete(chain);
}

void
nsec3_load_destroy(nsec3_load_context *context)
{
    ptr_vector_callback_and_destroy(&context->nsec3chain, nsec3_load_destroy_nsec3chain_cb);
    
    if(!ptr_set_isempty(&context->postponed_rrsig))
    {
        ptr_set_iterator iter;
        ptr_set_iterator_init(&context->postponed_rrsig, &iter);
        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *rrsig_node = ptr_set_iterator_next_node(&iter);
            if(rrsig_node->key != NULL)
            {
                u8 *key = (u8*)rrsig_node->key;
                ZFREE_ARRAY(rrsig_node->key, key[0] + 1);
                (void)key; // silence warning in some build settings
            }
            rrsig_node->key = NULL;
            rrsig_node->value = NULL;
        }

        ptr_set_destroy(&context->postponed_rrsig);
    }
    
    context->zone = NULL;
}

ya_result
nsec3_load_add_nsec3param(nsec3_load_context *context, const u8 *rdata, u16 rdata_size)
{
    if((rdata_size < 5) || (NSEC3_RDATA_ALGORITHM(rdata) != NSEC3_DIGEST_ALGORITHM_SHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM;
    }
    
    nsec3_context_record* nsec3param_r = nsec3_load_context_record_new((const u8*)"", 0, rdata, rdata_size);
    nsec3_load_context_chain* chain = nsec3_load_context_get_chain(context, nsec3param_r);
    nsec3_load_context_record_delete(nsec3param_r);
    chain->has_nsec3param = TRUE;
    
    return SUCCESS;
}

// TYPE_NSEC3CHAINSTATE

ya_result
nsec3_load_add_nsec3chainstate(nsec3_load_context *context, const u8 *rdata, u16 rdata_size)
{
    if((rdata_size < 5) || (NSEC3_RDATA_ALGORITHM(rdata) != NSEC3_DIGEST_ALGORITHM_SHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM;
    }

    nsec3_context_record* nsec3param_r = nsec3_load_context_record_new((const u8*)"", 0, rdata, rdata_size);
    nsec3_load_context_chain* chain = nsec3_load_context_get_chain(context, nsec3param_r);
    nsec3_load_context_record_delete(nsec3param_r);
    chain->has_nsec3param = FALSE;

    return SUCCESS;
}

ya_result
nsec3_load_add_nsec3(nsec3_load_context *context, const u8 *base32hex_digest, s32 ttl, const  u8 *rdata, u16 rdata_size)
{
    /*
     * Get the right chain from the rdata
     * Add the record to the chain
     */
    
    if((rdata_size < 5) || (NSEC3_RDATA_ALGORITHM(rdata) != NSEC3_DIGEST_ALGORITHM_SHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM;
    }
    
    nsec3_context_record* nsec3_r = nsec3_load_context_record_new(base32hex_digest, ttl, rdata, rdata_size);
    if(nsec3_r != NULL)
    {
        nsec3_load_context_chain* chain = nsec3_load_context_get_chain(context, nsec3_r);
        nsec3_load_context_chain_add_nsec3(chain, nsec3_r);

        context->last_inserted_nsec3 = nsec3_r;
        
        if(!ptr_set_isempty(&context->postponed_rrsig))
        {
            ptr_node *node = ptr_set_find(&context->postponed_rrsig, nsec3_r->digest_then_rdata);
            
            if(node != NULL)
            {
                u8 *key = node->key;
                nsec3_r->rrsig = (zdb_packed_ttlrdata*)node->value;
                ptr_set_delete(&context->postponed_rrsig, nsec3_r->digest_then_rdata);
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
#if C11_VLA_AVAILABLE
    u8 digest[digest_len + 1];
#else
    u8 * const digest = (u8*const)stack_alloc(digest_len + 1);
#endif
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
        
        ptr_node *node = ptr_set_insert(&context->postponed_rrsig, digest);
                
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

static int
nsec3_load_fix_chain_search_cb(const void *key, const void *item)
{
    const u8 *digest = (const u8*)key;
    nsec3_context_record *nsec3_record = (nsec3_context_record*)item;
    int ret = memcmp(digest, nsec3_record->digest_then_rdata, digest[0] + 1);
    return ret;
}

bool
nsec3_load_is_label_covered(zdb_rr_label *label)
{
    return !ZDB_LABEL_UNDERDELEGATION(label);
}

bool
nsec3_load_is_label_covered_optout(zdb_rr_label *label)
{
    if(!ZDB_LABEL_ATORUNDERDELEGATION(label)) // includes APEX
    {
        return TRUE;
    }
    if(ZDB_LABEL_ATDELEGATION(label))
    {
        return zdb_rr_label_get_rrset(label, TYPE_DS) != NULL;
    }
    return FALSE;
}

/**
 * Fixes extraneous NSEC3 records in chain.
 *
 * @returns TRUE iff the chain had no extraneous records;
 */

static bool
nsec3_load_find_extranous_records_in_chain(nsec3_load_context *context, nsec3_load_context_chain *chain)
{
    // for all labels
    //   check if the label should be covered by an NSEC3
    //   compute the digest
    //   seek for the digest
    //     if not missing
    //        mark the entry to tell it's covering something
    //
    // for all digests
    //   if the entry is not used, remove it

    nsec3_hash_function *hash_function;
    u8 *salt;
    nsec3_load_is_label_covered_function *is_covered;
    s32 min_ttl = context->zone->min_ttl;
    u32 nsec3_correction_count = 0;
    u16 hash_iterations;
    u16 nsec3param_rdata_size;
    u8 salt_len;
    u8 digest_len;
    bool fix_required;
    zdb_zone_label_iterator iter;
    u8 digest[64];
    u8 fqdn[MAX_DOMAIN_LENGTH + 1];
    u8 optout_byte;

    digest_len = digest[0] = nsec3_hash_len(NSEC3PARAM_RDATA_ALGORITHM(chain->nsec3param_rdata));
    hash_function = nsec3_hash_get_function(NSEC3PARAM_RDATA_ALGORITHM(chain->nsec3param_rdata));
    salt = NSEC3PARAM_RDATA_SALT(chain->nsec3param_rdata);
    salt_len = NSEC3PARAM_RDATA_SALT_LEN(chain->nsec3param_rdata);
    hash_iterations = NSEC3PARAM_RDATA_ITERATIONS(chain->nsec3param_rdata);
    nsec3param_rdata_size = NSEC3PARAM_MINIMUM_LENGTH + salt_len;
    fix_required = FALSE;

    if(context->opt_out)
    {
        is_covered = nsec3_load_is_label_covered_optout;
        optout_byte = 1;
    }
    else
    {
        is_covered = nsec3_load_is_label_covered;
        optout_byte = 0;
    }

    // find and mark all covered labels, the non-marked ones will be removed

    zdb_zone_label_iterator_init(&iter, context->zone);
    while(zdb_zone_label_iterator_hasnext(&iter))
    {
        u32 fqdn_len = zdb_zone_label_iterator_nextname(&iter, fqdn);
        zdb_rr_label* label = zdb_zone_label_iterator_next(&iter);

        if(is_covered(label)) // note: is_covered is a local variable pointing to the relevant function
        {
            // should be covered

             hash_function(
                fqdn,
                fqdn_len,
                salt,
                salt_len,
                hash_iterations,
                &digest[1],
                FALSE);

            // digest exists ?

            // nsec3 missing: generate the type bitmap and make an rdata with an nsec3 digest
            type_bit_maps_context bitmap;

            u16 bitmap_size = zdb_rr_label_bitmap_type_init(label, &bitmap);
            u16 rdata_size_pre_bitmap = nsec3param_rdata_size + 1 + digest_len;
            u16 rdata_size = rdata_size_pre_bitmap + bitmap_size;
            nsec3_context_record* expected_nsec3_record = nsec3_load_context_record_new_binary(digest, min_ttl, rdata_size);
            u8 *rdata = &expected_nsec3_record->digest_then_rdata[digest_len + 1];
            memcpy(rdata, chain->nsec3param_rdata, nsec3param_rdata_size);
            rdata[1] = optout_byte;
            type_bit_maps_write(&bitmap, &rdata[nsec3param_rdata_size + 1 + digest_len]);
            type_bit_maps_finalize(&bitmap);

            s32 match_index = ptr_vector_search_index(&chain->nsec3_added, digest, nsec3_load_fix_chain_search_cb);
            void *match;

            if((match_index >= 0) && ((match = ptr_vector_get(&chain->nsec3_added, match_index)) != NULL))
            {
                // found

                /*nsec3_context_record *nsec3_record = (nsec3_context_record*)match;
                assert(nsec3_record->ttl >= 0);
                nsec3_record->ttl = -nsec3_record->ttl;
*/
                bool nsec3_matches = FALSE;

                nsec3_context_record *nsec3_record = (nsec3_context_record*)match;

                if(nsec3_record->rdata_size == expected_nsec3_record->rdata_size)
                {
                    if(memcmp(&nsec3_record->digest_then_rdata[digest_len + 1 + rdata_size_pre_bitmap], &expected_nsec3_record->digest_then_rdata[digest_len + 1 + rdata_size_pre_bitmap], bitmap_size) == 0)
                    {
                        nsec3_matches = TRUE;
                    }
                }

                if(nsec3_matches)
                {
                    nsec3_load_context_record_delete(expected_nsec3_record);
                    nsec3_record->ttl = - nsec3_record->ttl;
                }
                else
                {
                    ++nsec3_correction_count;
#if !DEBUG
                    log_debug("zone load: %{dnsname}: nsec3: %{digest32h}.%{dnsname} has mismatched bitmap: fixed (%{dnsname})", context->zone->origin, nsec3_record->digest_then_rdata, context->zone->origin, fqdn);
#else
                    log_warn("zone load: %{dnsname}: nsec3: %{digest32h}.%{dnsname} has mismatched bitmap: fixed (%{dnsname})", context->zone->origin, nsec3_record->digest_then_rdata, context->zone->origin, fqdn);
                    log_warn("zone load: %{dnsname}: nsec3: %{digest32h}.%{dnsname} expected: (DEBUG)", context->zone->origin, nsec3_record->digest_then_rdata, context->zone->origin);
                    log_memdump(MODULE_MSG_HANDLE, MSG_WARNING, &expected_nsec3_record->digest_then_rdata[digest_len + 1 + rdata_size_pre_bitmap], bitmap_size, 32);
                    log_warn("zone load: %{dnsname}: nsec3: %{digest32h}.%{dnsname} got: (DEBUG)", context->zone->origin, nsec3_record->digest_then_rdata, context->zone->origin);
                    log_memdump(MODULE_MSG_HANDLE, MSG_WARNING, &nsec3_record->digest_then_rdata[digest_len + 1 + rdata_size_pre_bitmap], bitmap_size, 32);
#endif
                    memcpy(&expected_nsec3_record->digest_then_rdata[digest_len + 1 + nsec3param_rdata_size], &nsec3_record->digest_then_rdata[digest_len + 1 + nsec3param_rdata_size], digest_len + 1);
                    nsec3_load_context_record_delete_rrsig(expected_nsec3_record);
                    ptr_vector_set(&chain->nsec3_added, match_index, expected_nsec3_record);
                    nsec3_load_context_record_delete(nsec3_record);
                    expected_nsec3_record->ttl = - expected_nsec3_record->ttl;

                    fix_required = TRUE;
                }
            }
            else
            {
                // will be trashed

                log_warn("zone load: %{dnsname}: nsec3: %{digest32h}.%{dnsname} covering %{dnsname} not found in chain",
                    context->zone->origin, digest, context->zone->origin, fqdn);
#if DEBUG
                log_warn("zone load: %{dnsname}: nsec3: %{digest32h}.%{dnsname} covering %{dnsname}: label flags=%04x, is_covered=%i at_or_under_delegation=%i, at_delegation=%i (DEBUG)",
                    context->zone->origin, digest, context->zone->origin, fqdn, zdb_rr_label_flag_get(label),
                    (int)is_covered(label), (int)ZDB_LABEL_ATORUNDERDELEGATION(label), (int)ZDB_LABEL_ATDELEGATION(label));
#endif
                nsec3_load_context_record_delete(expected_nsec3_record);
            }
        }
    }

    int warning_quota = 1000;

    // remove unused and replace them by missing (if any)

    int last_good = -1;
    for(int i = 0; i <= ptr_vector_last_index(&chain->nsec3_added); ++i)
    {
        nsec3_context_record *nsec3_record = (nsec3_context_record*)ptr_vector_get(&chain->nsec3_added, i);
        if(nsec3_record->ttl < 0)
        {
            nsec3_record->ttl = -nsec3_record->ttl;

            ++last_good;
            ptr_vector_set(&chain->nsec3_added, last_good, ptr_vector_get(&chain->nsec3_added, i));
        }
        else
        {
            // unused

            if(warning_quota > 0)
            {
                log_warn("zone load: %{dnsname}: nsec3: unused %{digest32h}.%{dnsname} removed", context->zone->origin, nsec3_record->digest_then_rdata, context->zone->origin);
                if(--warning_quota == 0)
                {
                    log_warn("zone load: %{dnsname}: nsec3: too many warnings, silently removing unused links remaining in the chain", context->zone->origin);
                }
            }

            fix_required = TRUE;
        }
    }

    if(nsec3_correction_count > 0)
    {
        log_warn("zone load: %{dnsname}: nsec3: %u bitmap corrections made", context->zone->origin, nsec3_correction_count);
    }

    ptr_vector_remove_after(&chain->nsec3_added, last_good);
    ptr_vector_resize(&chain->nsec3_added, last_good + 1);

    if(fix_required && context->can_fix)
    {
        // fix next digest

        nsec3_context_record *prev_nsec3_record = (nsec3_context_record*)ptr_vector_last(&chain->nsec3_added);
        size_t next_digest_offset = digest_len + 1 + nsec3param_rdata_size;

        if(ptr_vector_last_index(&chain->nsec3_added) > 0)
        {
            for(int i = 0; i <= ptr_vector_last_index(&chain->nsec3_added); )
            {
                nsec3_context_record *nsec3_record = (nsec3_context_record*)ptr_vector_get(&chain->nsec3_added, i);

                if(memcmp(prev_nsec3_record->digest_then_rdata, nsec3_record->digest_then_rdata, digest_len + 1) == 0)
                {
                    // unlikely case of hash collision : delete record, shrink ptr_vector (should also merge bitmap)
                    /// @todo edf 20180905 -- merge type bitmaps (this is a very unlikely case)

                    log_notice("zone load: %{dnsname}: nsec3: multiple %{digest32h}.%{dnsname} coverage. "
                               "This is highly unexpected as it requires an hash collision. You should probably change the salt value.",
                               context->zone->origin, nsec3_record->digest_then_rdata, context->zone->origin);

                    nsec3_load_context_record_delete(nsec3_record);
                    ptr_vector_remove_at(&chain->nsec3_added, i);
                    continue;
                }

                // if next-hash != next hash ...

                if(memcmp(&prev_nsec3_record->digest_then_rdata[next_digest_offset], nsec3_record->digest_then_rdata, digest_len + 1) != 0)
                {
                    // overwrite next-hash value
                    memcpy(&prev_nsec3_record->digest_then_rdata[next_digest_offset], nsec3_record->digest_then_rdata, digest_len + 1);

                    // clear all signatures
                    nsec3_load_context_record_delete_rrsig(prev_nsec3_record);
                }

                // proceed with the next record

                prev_nsec3_record = nsec3_record;

                ++i;
            }
        }
        else
        {
            for(int i = 0; i <= ptr_vector_last_index(&chain->nsec3_added); ++i)
            {
                nsec3_context_record *nsec3_record = (nsec3_context_record*)ptr_vector_get(&chain->nsec3_added, i);

                // if next-hash != next hash ...

                if(memcmp(&prev_nsec3_record->digest_then_rdata[next_digest_offset], nsec3_record->digest_then_rdata, digest_len + 1) != 0)
                {
                    // overwrite next-hash value
                    memcpy(&prev_nsec3_record->digest_then_rdata[next_digest_offset], nsec3_record->digest_then_rdata, digest_len + 1);

                    // clear all signatures
                    nsec3_load_context_record_delete_rrsig(prev_nsec3_record);
                }

                // proceed with the next record

                prev_nsec3_record = nsec3_record;
            }
        }

        // chain is fixed

        zdb_zone_set_status(context->zone, ZDB_ZONE_STATUS_MODIFIED);
    }

    return !fix_required;
}

/**
 * There are two choices for fixing the chain.
 *  Either all digests are computed, associated with their fqdn and then matched with what exists in the context : this way costs (a lot of) memory (say 100 bytes per covered label.)
 *  Either for all fqdn the digest is computed, then sought in the context : this way costs about log2(#labels) seek/compare per covered label.
 *
 * This fix for extreme cases has more chances to succeed if it does not go out of memory so the second, slower, way has been chosen.
 *
 */

static void
nsec3_load_fix_chain(nsec3_load_context *context, nsec3_load_context_chain *chain)
{
    // for all labels
    //   check if the label should be covered by an NSEC3
    //   compute the digest
    //   seek for the digest
    //     if missing
    //        it will need to be added: keep it on the side for the next pass (with an uninitialised next)
    //     else
    //        mark the entry to tell it's covering something
    //
    // for all digests
    //   if the entry is not used, remove it
    //
    // add all new entries
    //
    // for all digests
    //   verify and fix the next fields
    //

    nsec3_hash_function *hash_function;
    u8 *salt;
    nsec3_load_is_label_covered_function *is_covered;
    ptr_vector added_nsec3 = PTR_VECTOR_EMPTY;
    s32 min_ttl = context->zone->min_ttl;
    u16 hash_iterations;
    u16 nsec3param_rdata_size;
    u8 salt_len;
    u8 optout_byte;
    u8 digest_len;
    bool dirty = FALSE;
    zdb_zone_label_iterator iter;
    u8 digest[64];
    u8 fqdn[MAX_DOMAIN_LENGTH + 1];

    digest_len = digest[0] = nsec3_hash_len(NSEC3PARAM_RDATA_ALGORITHM(chain->nsec3param_rdata));
    hash_function = nsec3_hash_get_function(NSEC3PARAM_RDATA_ALGORITHM(chain->nsec3param_rdata));
    salt = NSEC3PARAM_RDATA_SALT(chain->nsec3param_rdata);
    salt_len = NSEC3PARAM_RDATA_SALT_LEN(chain->nsec3param_rdata);
    hash_iterations = NSEC3PARAM_RDATA_ITERATIONS(chain->nsec3param_rdata);
    nsec3param_rdata_size = NSEC3PARAM_MINIMUM_LENGTH + salt_len;

    if(context->opt_out)
    {
        is_covered = nsec3_load_is_label_covered_optout;
        optout_byte = 1;
    }
    else
    {
        is_covered = nsec3_load_is_label_covered;
        optout_byte = 0;
    }

    zdb_zone_label_iterator_init(&iter, context->zone);
    while(zdb_zone_label_iterator_hasnext(&iter))
    {
        u32 fqdn_len = zdb_zone_label_iterator_nextname(&iter, fqdn);
        zdb_rr_label* label = zdb_zone_label_iterator_next(&iter);

        if(is_covered(label))
        {
            // should be covered

            hash_function(
                fqdn,
                fqdn_len,
                salt,
                salt_len,
                hash_iterations,
                &digest[1],
                FALSE);

            // digest exists ?

            // nsec3 missing: generate the type bitmap and make an rdata with an nsec3 digest
            type_bit_maps_context bitmap;

            u16 bitmap_size = zdb_rr_label_bitmap_type_init(label, &bitmap);

            u16 rdata_size_pre_bitmap = nsec3param_rdata_size + 1 + digest_len;
            u16 rdata_size = rdata_size_pre_bitmap + bitmap_size;

            nsec3_context_record *expected_nsec3_record = nsec3_load_context_record_new_binary(digest, min_ttl, rdata_size);
            u8 *rdata = &expected_nsec3_record->digest_then_rdata[digest_len + 1];
            memcpy(rdata, chain->nsec3param_rdata, nsec3param_rdata_size);
            rdata[1] = optout_byte;
            type_bit_maps_write(&bitmap, &rdata[nsec3param_rdata_size + 1 + digest_len]);
            type_bit_maps_finalize(&bitmap);

            s32 match_index = ptr_vector_search_index(&chain->nsec3_added, digest, nsec3_load_fix_chain_search_cb);
            void *match = (match_index >= 0)?ptr_vector_get(&chain->nsec3_added, match_index):NULL;

            if(match == NULL)
            {
#if DEBUG
                rdata[nsec3param_rdata_size] = digest_len;
                rdata_desc nsec3_rdata = {TYPE_NSEC3, rdata_size, rdata};
                log_debug("zone load: %{dnsname}: missing %{digest32h}.%{dnsname} %{typerdatadesc}",
                        context->zone->origin, expected_nsec3_record->digest_then_rdata, context->zone->origin, &nsec3_rdata);
#endif
                ptr_vector_append(&added_nsec3, expected_nsec3_record);

                log_warn("zone load: %{dnsname}: nsec3: missing %{digest32h}.%{dnsname} covering %{dnsname} added", context->zone->origin, digest, context->zone->origin, fqdn);
            }
            else
            {
                // found

                bool nsec3_matches = FALSE;

                nsec3_context_record *nsec3_record = (nsec3_context_record*)match;

                if(nsec3_record->rdata_size == expected_nsec3_record->rdata_size)
                {
                    if(memcmp(&nsec3_record->digest_then_rdata[digest_len + 1 + rdata_size_pre_bitmap], &expected_nsec3_record->digest_then_rdata[digest_len + 1 + rdata_size_pre_bitmap], bitmap_size) == 0)
                    {
                        nsec3_matches = TRUE;
                    }
                }

                if(nsec3_matches)
                {
                    nsec3_load_context_record_delete(expected_nsec3_record);
                    nsec3_record->ttl = - nsec3_record->ttl;
                }
                else
                {
                    log_warn("zone load: %{dnsname}: nsec3: %{digest32h}.%{dnsname} has mismatched bitmap: fixed (%{dnsname})", context->zone->origin, nsec3_record->digest_then_rdata, context->zone->origin, fqdn);

                    ptr_vector_set(&chain->nsec3_added, match_index, expected_nsec3_record);
                    nsec3_load_context_record_delete(nsec3_record);
                    expected_nsec3_record->ttl = - expected_nsec3_record->ttl;
                    dirty = TRUE;
                }
            }
        }
    }

    int j = 0;

    // remove unused and replace them by missing (if any)

    for(int i = 0; i <= ptr_vector_last_index(&chain->nsec3_added); ++i)
    {
        nsec3_context_record *nsec3_record = (nsec3_context_record*)ptr_vector_get(&chain->nsec3_added, i);
        if(nsec3_record->ttl < 0)
        {
            nsec3_record->ttl = - nsec3_record->ttl;
        }
        else
        {
            // unused

            log_warn("zone load: %{dnsname}: nsec3: unused %{digest32h}.%{dnsname} removed", context->zone->origin, nsec3_record->digest_then_rdata, context->zone->origin);

            nsec3_load_context_record_delete(nsec3_record);
            if(j <= ptr_vector_last_index(&added_nsec3))
            {
                ptr_vector_set(&chain->nsec3_added, i, ptr_vector_get(&added_nsec3, j));
                ++j;
            }
            else
            {
                ptr_vector_set(&chain->nsec3_added, i, NULL);
            }

            dirty = TRUE;
        }
    }

    // add missing not added in previous pass

    if(j <= ptr_vector_last_index(&added_nsec3))
    {
        int reserve = ptr_vector_last_index(&added_nsec3) - j + 1;
        ptr_vector_ensures(&chain->nsec3_added, ptr_vector_size(&chain->nsec3_added) + reserve);
        for(; j <= ptr_vector_last_index(&added_nsec3); ++j)
        {
            ptr_vector_append(&chain->nsec3_added, ptr_vector_get(&added_nsec3, j));
        }
    }

    ptr_vector_destroy(&added_nsec3);

    ptr_vector_qsort(&chain->nsec3_added, nsec3_load_context_record_qsort_callback); // sort the records in the chain

    // fix next digest

    nsec3_context_record *prev_nsec3_record = (nsec3_context_record*)ptr_vector_last(&chain->nsec3_added);
    size_t next_digest_offset = digest_len + 1 + nsec3param_rdata_size;

    for(int i = 0; i <= ptr_vector_last_index(&chain->nsec3_added); ++i)
    {
        nsec3_context_record *nsec3_record = (nsec3_context_record*)ptr_vector_get(&chain->nsec3_added, i);

        // check for duplicates (don't change the comparison order)
        //      the first test is mandatory to find an error
        //      the second test is cheap but pointless on all but duplicate cases

        if(memcmp(prev_nsec3_record->digest_then_rdata, nsec3_record->digest_then_rdata, digest_len + 1) == 0)
        {
            if(ptr_vector_last_index(&chain->nsec3_added) > 0)
            {
                // unlikely case of hash collision : delete record, shrink ptr_vector (should also merge bitmap)
                /// @todo edf 20180905 -- merge type bitmaps (this is a very unlikely case)

                log_notice("zone load: %{dnsname}: nsec3: multiple %{digest32h}.%{dnsname} coverage. This is highly unexpected as it requires an hash collision. You should probably change the salt value.", context->zone->origin, nsec3_record->digest_then_rdata, context->zone->origin);

                dirty = TRUE;

                nsec3_load_context_record_delete(nsec3_record);
                ptr_vector_remove_at(&chain->nsec3_added, i);
                --i;

                continue;
            }
        }

        if(memcmp(&prev_nsec3_record->digest_then_rdata[next_digest_offset], nsec3_record->digest_then_rdata, digest_len + 1) != 0)
        {
            if(ptr_vector_last_index(&chain->nsec3_added) > 0)
            {
                memcpy(&prev_nsec3_record->digest_then_rdata[next_digest_offset], nsec3_record->digest_then_rdata, digest_len + 1);
                nsec3_load_context_record_delete_rrsig(prev_nsec3_record);

                dirty = TRUE;
            }
        }

        prev_nsec3_record = nsec3_record;
    }

    // chain is fixed

    if(dirty)
    {
        zdb_zone_set_status(context->zone, ZDB_ZONE_STATUS_MODIFIED);
    }
}

/*
 * Use this to add the NSEC3 information from the context to the zone.
 * yadifad used to be more strict about the NSEC3 chain
 * Now it only requires the chain to loop.
 *
 * If an error is found, and the context allows fixing the zone then:
 *    The function will correct it and mark the context to tell the zone has been modified.
 *    The caller should then increment the serial, destroy the journal, and save the fixed zone.
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
        
        if(ptr_vector_last_index(&chain->nsec3_added) >= 0)
        {
            ptr_vector_qsort(&chain->nsec3_added, nsec3_load_context_record_qsort_callback); // sort the records in the chain


            // slaves cannot fix their content

            if(context->can_fix)
            {
                if(!nsec3_load_find_extranous_records_in_chain(context, chain))
                {
                    context->fix_applied = TRUE;
                    --i;
                    continue;
                }
            }

            const nsec3_context_record *p = (const nsec3_context_record*)ptr_vector_last(&chain->nsec3_added);
            
            for(int j = 0; j <= ptr_vector_last_index(&chain->nsec3_added); ++j)
            {
                const nsec3_context_record *r = (const nsec3_context_record*)ptr_vector_get(&chain->nsec3_added, j);
                
                // the digest in the rdata of p has to be the digest of r
                                
                if(!nsec3_load_context_record_linked(p, r))
                {
                    // the chain is broken

                    log_err("zone load: %{dnsname}: nsec3: %{digest32h}.%{dnsname} should be followed by %{digest32h}.%{dnsname} but was by  %{digest32h}.%{dnsname} instead",
                        context->zone->origin,
                        p->digest_then_rdata, context->zone->origin,
                        nsec3_load_context_record_next_digest(p), context->zone->origin,
                        r->digest_then_rdata, context->zone->origin);

                    if(!context->can_fix)
                    {
                        // even with a more lenient yadifad, a broken chain is just not usable by a slave
                        // the minimum requirement now is coherence

                        return DNSSEC_ERROR_NSEC3_INVALIDZONESTATE;
                    }

                    nsec3_load_fix_chain(context, chain);

                    context->fix_applied = TRUE;
                    // --i;
                    break;
                }

                p = r;
            }

            if(!context->fix_applied)
            {
                const nsec3_context_record *s = (const nsec3_context_record*)ptr_vector_get(&chain->nsec3_added, 0);

                if(!nsec3_load_context_record_linked(p, s))
                {
                    // the chain is broken

                    log_err("zone load: %{dnsname}: nsec3: %{digest32h}.%{dnsname} should be followed by %{digest32h}.%{dnsname} but was by %{digest32h}.%{dnsname} instead (back to front)",
                            context->zone->origin,
                            p->digest_then_rdata, context->zone->origin,
                            nsec3_load_context_record_next_digest(p), context->zone->origin,
                            s->digest_then_rdata, context->zone->origin);

                    if(!context->can_fix)
                    {
                        return DNSSEC_ERROR_NSEC3_INVALIDZONESTATE;
                    }

                    nsec3_load_fix_chain(context, chain);

                    context->fix_applied = TRUE;
                    //--i;
                    break;
                }
            }
        }
        else
        {
            log_err("zone load: %{dnsname}: nsec3: empty chain %i", context->zone->origin, i);

            // slaves cannot fix their content

            if(context->can_fix)
            {
                nsec3_load_fix_chain(context, chain);

                context->fix_applied = TRUE;
            }
        }
    }
    
    nsec3_zone **n3p = &context->zone->nsec.nsec3;

    // the chain are valid : create the collections
    
    // but first sort the collections to put the ones with NSEC3PARAM with smallest digest/iterations
    
    ptr_vector_qsort(&context->nsec3chain, nsec3_load_context_chain_qsort_callback); // sort the chains
    
    for(int i = 0; i <= ptr_vector_last_index(&context->nsec3chain); ++i)
    {
        nsec3_load_context_chain *chain = (nsec3_load_context_chain*)ptr_vector_get(&context->nsec3chain, i);
        
        nsec3_zone *n3 = nsec3_zone_new(chain->nsec3param_rdata, chain->nsec3param_rdata_size);
        
        for(int j = 0; j <= ptr_vector_last_index(&chain->nsec3_added); ++j)
        {
            nsec3_context_record *r = (nsec3_context_record*)ptr_vector_get(&chain->nsec3_added, j);
            const u8 *rdata = nsec3_load_context_record_rdata(r);
            nsec3_node *node = nsec3_insert(&n3->items, r->digest_then_rdata);
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
    
    ptr_set_iterator iter;
    ptr_set_iterator_init(&context->postponed_rrsig, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *rrsig_node = ptr_set_iterator_next_node(&iter);
     
        bool useless = TRUE;
        
        for(nsec3_zone *n3 = context->zone->nsec.nsec3; n3 != NULL; n3 = n3->next)
        {
            nsec3_node *nsec3_node = nsec3_find(&n3->items, rrsig_node->key);
            if(nsec3_node != NULL)
            {
                zdb_packed_ttlrdata *rrsig = (zdb_packed_ttlrdata*)rrsig_node->value;
                
                nsec3_node->rrsig = rrsig;
                u8 *key = (u8*)rrsig_node->key;
                ZFREE_ARRAY(rrsig_node->key, key[0] + 1); // VS false positive: a key cannot be NULL
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


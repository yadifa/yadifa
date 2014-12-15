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
#include <stdio.h>
#include <stdlib.h>

#define DEBUG_LEVEL 0

#include <dnscore/dnscore.h>
#include "dnsdb/dnssec.h"

#include "dnsdb/nsec3_load.h"
#include "dnsdb/nsec3_zone.h"
#include "dnsdb/nsec3_update.h"

#include <dnscore/base32hex.h>

#include <dnscore/format.h>

#define N3CHNCTX_TAG 0x5854434e4843334e
#define N3PRDATA_TAG 0x415441445250334e

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

/******************************************************************************
 *
 * NSEC3 - load (ie: from zone file / axfr / ...)
 *
 *****************************************************************************/

typedef struct nsec3_context_record nsec3_context_record;

struct nsec3_context_record
{
    u8* digest;
    u8* rdata;
    u32 ttl;
    u16 rdata_size;
};


/*
 * Converts the label of an NSEC3 or an RRSIG(NSEC3) record to a digest.
 * returns a mallocated digest
 *
 * Exclusively used by nsec3_load_add_collection
 *
 */

static u8*
nsec3_label_to_digest(nsec3_load_context *context, const u8 *entry_name)
{
    /*
     * The first label is BASE32HEX encoded and MUST be of a size & 3 == 0
     */

    u8 base32hex_len = entry_name[0];

    if((base32hex_len & 3) != 0)
    {
        return NULL;
    }

    dnsname_vector origin;
    dnsname_vector name;

    dnsname_to_dnsname_vector(context->zone->origin, &origin);
    dnsname_to_dnsname_vector(entry_name, &name);

    /*
     * There MUST be exactly one level of depth between the origin and the name
     */

    if(name.size - origin.size != 1)
    {
        return NULL;
    }

    /*
     * Both path MUST match
     */

    u8** origin_labelsp = &origin.labels[0];
    u8** name_labelsp = &name.labels[1];

    while(name.size-- > 0)
    {
        if(!dnslabel_equals(*origin_labelsp++, *name_labelsp++))
        {
            return NULL;
        }
    }

    u8 bin_len = (base32hex_len >> 3) * 5; /* n<<2 + n */

    u8* digest;

    MALLOC_OR_DIE(u8*, digest, bin_len + 1, NSEC3_DIGEST_TAG);

    if(FAIL(base32hex_decode((char*)& name.labels[0][1], base32hex_len, &digest[1])))
    {
        free(digest);

        return NULL;
    }

    digest[0] = bin_len;

    return digest;
}

static ya_result
nsec3_load_add_collection(nsec3_load_context *context, const u8 *entry_name, u32 entry_ttl, const u8 *entry_rdata, u16 entry_rdata_size, ptr_vector *collection)
{
    /*
     * NOTE: I use MALLOC instead of ZALLOC.
     *       ZALLOC is typically for persistent or recurrent memory
     *       I don't know if this bloc size will be highly re-used
     */

    u8 *digest = nsec3_label_to_digest(context, entry_name);

    if(digest == NULL)
    {
        return DNSSEC_ERROR_NSEC3_LABELTODIGESTFAILED;
    }

    nsec3_context_record *cr;
    MALLOC_OR_DIE(nsec3_context_record*, cr, sizeof (nsec3_context_record), NSEC3_CONTEXT_RECORD_TAG);
    cr->digest = digest;
    MALLOC_OR_DIE(u8*, cr->rdata, entry_rdata_size, NSEC3_RDATA_TAG);
    MEMCOPY(cr->rdata, entry_rdata, entry_rdata_size);
    
    cr->ttl = entry_ttl;
    cr->rdata_size = entry_rdata_size;

    ptr_vector_append(collection, cr);

    return SUCCESS;
}

/*
 * Used exclusively by nsec3_load_compile
 */

static nsec3_zone_item*
nsec3_label_search(zdb_zone* zone, u8* digest, nsec3_zone** out_n3)
{
    nsec3_zone* n3 = zone->nsec.nsec3;

    for(;;)
    {
        nsec3_zone_item* items = n3->items;

        nsec3_zone_item* item = nsec3_avl_find(&items, digest);

        if(item != NULL)
        {
            /*
             * We found the NSEC3 label
             */

            if(out_n3 != NULL)
            {
                *out_n3 = n3;
            }

            return item;
        }

        /*
         * This item does not exists in the current chain,
         * try the next NSEC3PARAM chain
         */

        n3 = n3->next;

        if(n3 == NULL)
        {
            /* skip/ignore this signature */

            return NULL;
        }
    }
}

/*
 * Context Chain
 */

static nsec3_chain_context*
nsec3_load_chain_init(const u8 *rdata, u16 rdata_size)
{
    nsec3_chain_context *ctx;
    MALLOC_OR_DIE(nsec3_chain_context*, ctx, sizeof(nsec3_chain_context), N3CHNCTX_TAG);
    ctx->next = NULL;

    MALLOC_OR_DIE(u8*, ctx->nsec3param_rdata, rdata_size, N3PRDATA_TAG);
    memcpy(ctx->nsec3param_rdata, rdata, rdata_size);
    ctx->nsec3param_rdata_size = rdata_size;

    return ctx;
}

static void
nsec3_load_chain_destroy(nsec3_chain_context* ctx)
{
    while(ctx != NULL)
    {
        nsec3_chain_context *ctx_next = ctx->next;

        ctx->next = NULL;

        free(ctx->nsec3param_rdata);
        
        ctx = ctx_next;
    }
}

static bool
nsec3_load_chain_match(nsec3_chain_context *ctx, const u8 *rdata, u16 rdata_size)
{
    if(rdata_size >= NSEC3PARAM_MINIMUM_LENGTH)
    {
        if(ctx->nsec3param_rdata_size == rdata_size)
        {
            if(ctx->nsec3param_rdata[0] == rdata[0])
            {
                return memcmp(&ctx->nsec3param_rdata[2], &rdata[2], rdata_size - 2) == 0;
            }
        }
    }

    return FALSE;
}

ya_result
nsec3_load_init(nsec3_load_context *context, zdb_zone* zone)
{
    if(zone->nsec.nsec3 != NULL)
    {
        /*
         * The zone already contains an nsec record.  This is highly unexpexted.
         */

        return DNSSEC_ERROR_NSEC3_INVALIDZONESTATE;
    }

    ZEROMEMORY(context, sizeof(nsec3_load_context));
    
    ptr_vector_init(&context->nsec3);
    ptr_vector_init(&context->rrsig);
    context->zone = zone;
    context->opt_out = TRUE;

    return SUCCESS;
}

/*
 *
 */

static void
nsec3_load_destroy_free(void* ptr)
{
    free(ptr);
}

void
nsec3_load_destroy(nsec3_load_context *context)
{
    ptr_vector_free_empties(&context->nsec3, nsec3_load_destroy_free);
    ptr_vector_destroy(&context->nsec3);

    ptr_vector_free_empties(&context->rrsig, nsec3_load_destroy_free);
    ptr_vector_destroy(&context->rrsig);

    nsec3_load_chain_destroy(context->chain);    

    context->zone = NULL;
}

ya_result
nsec3_load_add_nsec3param(nsec3_load_context *context, const u8 *entry_rdata, u16 entry_rdata_size)
{
    if((entry_rdata_size < 5) || (NSEC3_RDATA_ALGORITHM(entry_rdata) != DNSSEC_DIGEST_TYPE_SHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM;
    }

    nsec3_chain_context **ctxp = &context->chain;
    while(*ctxp != NULL)
    {
        if(nsec3_load_chain_match(*ctxp, entry_rdata, entry_rdata_size))
        {
            /* ignore */
            return SUCCESS;
        }
        ctxp = &(*ctxp)->next;
    }

    nsec3_zone_add_from_rdata(context->zone, entry_rdata_size, entry_rdata);

    *ctxp = nsec3_load_chain_init(entry_rdata, entry_rdata_size);
    
    return SUCCESS;
}

ya_result
nsec3_load_add_nsec3(nsec3_load_context *context, const  u8 *entry_name, u32 entry_ttl, const  u8 *entry_rdata, u16 entry_rdata_size)
{
    /*
     * Get the right chain from the rdata
     * Add the record to the chain
     */
    
    if((entry_rdata_size < 5) || (NSEC3_RDATA_ALGORITHM(entry_rdata) != DNSSEC_DIGEST_TYPE_SHA1))
    {
        return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM;
    }

    return nsec3_load_add_collection(context, entry_name, entry_ttl, entry_rdata, entry_rdata_size, &context->nsec3);
}

ya_result
nsec3_load_add_rrsig(nsec3_load_context *context, const  u8 *entry_name, u32 entry_ttl, const u8 *entry_rdata, u16 entry_rdata_size)
{
    /*
     * Find a chain that already contains
     */

    return nsec3_load_add_collection(context, entry_name, entry_ttl, entry_rdata, entry_rdata_size, &context->rrsig);
}

/*
 * Use this to add the NSEC3 information from the context to the zone
 */

ya_result
nsec3_load_compile(nsec3_load_context *context)
{
    /*
     * Note: All the nsec3param have already been initialized
     *
     * 1)
     *
     * Compute the nsec3 for all available nsec3param
     *
     * 2)
     *
     * Add all loaded rrsig records in the relevant nsec3 record, ignore the dups.
     *
     * 3)
     *
     * Check that all loaded nsec3 record is a perfect match of the computed nsec3
     * record.  Destroy the signature of the failed NSEC3 records (issue a warning ?)
     *
     * When everything is done, we need to expect an update of the signatures
     *
     */

    zdb_zone* zone = context->zone;
    s32 i;

    /*
     * NOTE: should I enable the NSEC3 flag here already ?
     */
    
    u32 nsec3_read = context->nsec3.offset;
    u32 rrsig_read = context->rrsig.offset;

    if(context->chain == NULL)
    {
        return DNSSEC_ERROR_NSEC3_INVALIDZONESTATE;
    }

    /* 1) */

    if(context->opt_out)
    {
        context->zone->apex->flags |= ZDB_RR_LABEL_NSEC3_OPTOUT;
    }
    else
    {
        context->zone->apex->flags &= ~ZDB_RR_LABEL_NSEC3_OPTOUT;
    }
    
    nsec3_update_zone(context->zone);

    //nsec3_check(context->zone);

    /* 2) */

    u32 rrsig_added = 0;
    u32 rrsig_ignored = 0;
    u32 rrsig_discarded = 0;

    ptr_vector* rrsigs = &context->rrsig;

    s32 rrsig_count = rrsigs->offset + 1;
    
    u16 shutdown_test_countdown = 1000;

    for(i = 0; i < rrsig_count; i++)
    {
        if(--shutdown_test_countdown == 0)
        {
            if(dnscore_shuttingdown())
            {
                /* Yes, it means there will be a "leak" but the app is shutting down anyway ... */
                
                return STOPPED_BY_APPLICATION_SHUTDOWN;
            }
            
            shutdown_test_countdown = 1000;
        }
        
        nsec3_context_record* cr = (nsec3_context_record*)rrsigs->data[i];
        /* NSEC3 Label: cr->digest */

        nsec3_zone_item* item = nsec3_label_search(zone, cr->digest, NULL);

        if(item != NULL)
        {
           /*
            * We found the NSEC3 label
            *
            * Build a copy of the ttl/rdata, ignore dups
            */
            bool dup = FALSE;
            
            zdb_packed_ttlrdata **rrsigp = &item->rrsig;

            while(*rrsigp != NULL)
            {                
                if((*rrsigp)->rdata_size == cr->rdata_size)
                {
                    if(memcmp((*rrsigp)->rdata_start, cr->rdata, cr->rdata_size) == 0)
                    {
                        dup = TRUE;
                        rrsig_ignored++;
                        break;
                    }
                }
                
                rrsigp = &(*rrsigp)->next;
            }
            
            if(!dup)
            {
                ZDB_RECORD_ZALLOC(*rrsigp, cr->ttl, cr->rdata_size, cr->rdata);
                (*rrsigp)->next = NULL;

                rrsig_added++;
            }
        }
        else
        {
            rrsig_discarded++;
        }

        /* Destroy the rrsig */

        free(cr->digest);
        free(cr->rdata);
        free(cr);

        rrsigs->data[i] = NULL;

    }

    log_debug("nsec3: rrsig: add: %u ignore: %u discard: %u (had %u nsec3 and %u rrsigs)", rrsig_added, rrsig_ignored, rrsig_discarded, nsec3_read, rrsig_read);

    /* 3) */

    ptr_vector* nsec3s = &context->nsec3;
    u32 nsec3_accepted = 0;
    u32 nsec3_rejected = 0;
    u32 nsec3_discarded = 0;

    s32 nsec3_count = nsec3s->offset + 1;
    
    u32 min_ttl = 900;
    
    zdb_zone_getminttl(zone, &min_ttl);
    
    shutdown_test_countdown = 1000;
    
    for(i = 0; i < nsec3_count; i++)
    {
        if(--shutdown_test_countdown == 0)
        {
            if(dnscore_shuttingdown())
            {
                /* Yes, it means there will be a "leak" but the app is shutting down anyway ... */
                
                return STOPPED_BY_APPLICATION_SHUTDOWN;
            }
            
            shutdown_test_countdown = 1000;
        }
        
        nsec3_context_record* cr = (nsec3_context_record*)nsec3s->data[i];
        /* NSEC3 Label: cr->digest */


        nsec3_zone* n3;
        nsec3_zone_item* item = nsec3_label_search(zone, cr->digest, &n3);

        if(item != NULL)
        {
            /*
             * We found the NSEC3 label, we have to compare it to the one
             * it was supposed to be
             */

            if(!nsec3_zone_item_equals_rdata(n3, item, cr->rdata_size, cr->rdata))
            {
                /*
                 * Didn't matched: The signature, if any, will be wrong
                 */

#ifdef DEBUG
                rdata_desc nsec3_desc = {TYPE_NSEC3, cr->rdata_size, cr->rdata};
                log_debug("nsec3: %{digest32h} %{typerdatadesc} rejected (do not agree with rdata value).", item->digest, &nsec3_desc);

                zdb_packed_ttlrdata *nsec3_ttlrdata;
                const zdb_packed_ttlrdata *nsec3_ttlrdata_rrsig;

                u8 *owner;
                u8 *pool;
                u8 pool_buffer[NSEC3_ZONE_ITEM_TO_NEW_ZDB_PACKED_TTLRDATA_SIZE];
                pool = pool_buffer;
                
                nsec3_zone_item_to_new_zdb_packed_ttlrdata_parm nsec3_parms =
                {
                    n3,
                    item,
                    zone->origin,
                    &pool,
                    min_ttl
                };

                nsec3_zone_item_to_new_zdb_packed_ttlrdata(&nsec3_parms, &owner, &nsec3_ttlrdata, &nsec3_ttlrdata_rrsig);

                if(nsec3_ttlrdata != NULL)
                {
                    rdata_desc nsec3_desc = {TYPE_NSEC3, nsec3_ttlrdata->rdata_size, &nsec3_ttlrdata->rdata_start[0]};
                    log_debug("nsec3: computed: %{dnsname} %{typerdatadesc}", owner, &nsec3_desc);
                    nsec3_desc.len = cr->rdata_size;
                    nsec3_desc.rdata = cr->rdata;
                    log_debug("nsec3: received: %{dnsname} %{typerdatadesc}", owner, &nsec3_desc);
                }
                
#endif
                nsec3_rejected++;

                nsec3_zone_item_rrsig_delete_all(item);
            }
            else
            {
                nsec3_accepted++;
            }
        }
        else
        {
#ifdef DEBUG
            rdata_desc nsec3_desc = {TYPE_NSEC3, cr->rdata_size, cr->rdata};
            log_debug("nsec3: discarded: %{digest32h} %{typerdatadesc}", cr->digest, &nsec3_desc);
#endif
            
            nsec3_discarded++;
        }


        /* Destroy the rrsig */

        free(cr->digest);
        free(cr->rdata);
        free(cr);

        nsec3s->data[i] = NULL;
    }

    log_debug("nsec3: accept: %u reject: %u discard: %u", nsec3_accepted, nsec3_rejected, nsec3_discarded);

    /*
     * The caller needs to destroy the context
     * A signature update should be called too
     */
    
    context->rrsig_added = rrsig_added;
    context->rrsig_ignored = rrsig_ignored;
    context->rrsig_discarded = rrsig_discarded;
    
    context->nsec3_accepted = nsec3_accepted;
    context->nsec3_rejected = nsec3_rejected;
    context->nsec3_discarded = nsec3_discarded;


    return SUCCESS;
}

/*
 * A slave cannot choose what is right or not
 */

ya_result
nsec3_load_forced(nsec3_load_context *context)
{
    /*
     * Note: All the nsec3param have already been initialized
     *
     * 1)
     *
     * Compute the nsec3 for all available nsec3param
     *
     * 2)
     *
     * Add all loaded rrsig records in the relevant nsec3 record, ignore the dups.
     *
     * 3)
     *
     * Check that all loaded nsec3 record is a perfect match of the computed nsec3
     * record.  Destroy the signature of the failed NSEC3 records (issue a warning ?)
     *
     * When everything is done, we need to expect an update of the signatures
     *
     */

    zdb_zone* zone = context->zone;
    s32 i;

    /*
     * NOTE: should I enable the NSEC3 flag here already ?
     */

    /* 1) */

    nsec3_update_zone(context->zone);

    /* 2) */

    u32 rrsig_added = 0;
    u32 rrsig_ignored = 0;
    u32 rrsig_discarded = 0;

    ptr_vector* rrsigs = &context->rrsig;

    s32 rrsig_count = rrsigs->offset + 1;

    for(i = 0; i < rrsig_count; i++)
    {
        nsec3_context_record* cr = (nsec3_context_record*)rrsigs->data[i];
        /* NSEC3 Label: cr->digest */

        nsec3_zone_item* item = nsec3_label_search(zone, cr->digest, NULL);

        if(item != NULL)
        {
            /*
             * We found the NSEC3 label
             */

            if(item->rrsig == NULL)
            {
                /*
                 * Build a copy of the ttl/rdata, ignore dups
                 * The macro does not sets the next pointer.
                 * This is why I have to set it to NULL.
                 */

                ZDB_RECORD_ZALLOC(item->rrsig, cr->ttl, cr->rdata_size, cr->rdata);
                item->rrsig->next = NULL;

                rrsig_added++;
            }
            else
            {
                rrsig_ignored++;
            }
        }
        else
        {
            rrsig_discarded++;
        }

        /* Destroy the rrsig */

        free(cr->digest);
        free(cr->rdata);
        free(cr);

        rrsigs->data[i] = NULL;

    }

    log_debug("nsec3: rrsig: add: %u ignore: %u discard: %u", rrsig_added, rrsig_ignored, rrsig_discarded);

    /* 3) */

    ptr_vector* nsec3s = &context->nsec3;
    u32 nsec3_accepted = 0;
    u32 nsec3_rejected = 0;
    u32 nsec3_discarded = 0;

    s32 nsec3_count = nsec3s->offset + 1;

    for(i = 0; i < nsec3_count; i++)
    {
        nsec3_context_record* cr = (nsec3_context_record*)nsec3s->data[i];
        /* NSEC3 Label: cr->digest */

        nsec3_zone* n3;
        nsec3_zone_item* item = nsec3_label_search(zone, cr->digest, &n3);

        if(item != NULL)
        {
            /*
             * We found the NSEC3 label, we have to compare it to the one
             * it was supposed to be
             */

            if(!nsec3_zone_item_equals_rdata(n3, item, cr->rdata_size, cr->rdata))
            {
                /*
                 * Didn't matched: The signature, if any, will be wrong
                 */

                log_debug("nsec3: %{digest32h} rejected.", item->digest);

#if 1
                nsec3_zone_item_equals_rdata(n3, item, cr->rdata_size, cr->rdata);
#endif
                nsec3_rejected++;

                nsec3_zone_item_rrsig_delete_all(item);
            }
            else
            {
                nsec3_accepted++;
            }
        }
        else
        {
            nsec3_discarded++;
        }

        /* Destroy the rrsig */

        free(cr->digest);
        free(cr->rdata);
        free(cr);

        nsec3s->data[i] = NULL;
    }

    log_debug("nsec3: nsec3: accept: %u reject: %u discard: %u", nsec3_accepted, nsec3_rejected, nsec3_discarded);

    /*
     * The caller needs to destroy the context
     * A signature update should be called too
     */

    return SUCCESS;
}


bool
nsec3_load_is_context_empty(nsec3_load_context* ctx)
{
    return (ctx->zone == NULL) || ((ctx->nsec3.offset < 0) && (ctx->rrsig.offset < 0));
}

/** @} */

/*----------------------------------------------------------------------------*/


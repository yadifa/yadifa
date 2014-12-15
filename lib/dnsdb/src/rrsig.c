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
/** @defgroup rrsig RRSIG functions
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

#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#include <dnscore/sys_types.h>
#include <dnscore/logger.h>
#include <dnscore/dnsname.h>
#include <dnscore/format.h>
#include <dnscore/random.h>
#include <dnscore/dnskey.h>
#include <dnscore/thread_pool.h>

#include "dnsdb/dnsrdata.h"
#include "dnsdb/dnssec.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/rr_canonize.h"
#include "dnsdb/zdb_listener.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_rr_label.h"


#define MODULE_MSG_HANDLE g_dnssec_logger

/* EDF: Don't ZALLOC */

#define ALLOW_ZALLOC 0

/*
 * 0 : no dump
 * 1 : dump
 * 2 : more dump ...
 */

#define RRSIG_DUMP 0

#define RRSIG_AUTOMATIC_ALARM_REFRESH 0

/*
#ifndef DEBUG
#undef RRSIG_DUMP
#define RRSIG_DUMP  0
#endif
 *//* setup the header except the signature */
/* canonize the rr list */
/* sign the resulting stream (give the order to sign the the signature engine */

/* The result of the signature operation is a node ready to be insterted in the tree.
 * There must be a time when I can change the resource records of a rr_label.  At that time I'll add the rrsig result.
 *
 * Said time is when all the RR in the label have been processed.
 * So what I could do is batch a label instead of processing by record.
 * The result is for the batch so when we get the result, we know we can insert it.
 */

/* self-explanatory */
ya_result
rrsig_context_initialize(rrsig_context_s *context, const zdb_zone *zone, const char *engine_name, u32 sign_from, smp_int *quota)
{
    /* Grab the keys */
    /* Grab the origin */
    /* Verify that all the keys are matching the origin */
    /* Init the engine */

    yassert(zone != NULL && context != NULL);

    /* Ensure the context is harmless */
    ZEROMEMORY(context, sizeof(rrsig_context_s));
    context->rrs.offset = -1;
    /* */

    if(engine_name == NULL)
    {
        /* NOTE : engine_name CANNOT be a constant until I get rid of strtok_r */
        /* engine_name = DEFAULT_ENGINE_NAME; */

        return DNSSEC_ERROR_RRSIG_NOENGINE;
    }

    zdb_packed_ttlrdata* dnskey_rr_sll = zdb_record_find(&zone->apex->resource_record_set, TYPE_DNSKEY);

    if(dnskey_rr_sll == NULL)
    {
        return DNSSEC_ERROR_RRSIG_NOZONEKEYS;
    }

    context->sig_validity_regeneration_seconds = zone->sig_validity_regeneration_seconds;
    context->sig_validity_interval_seconds = zone->sig_validity_interval_seconds;
    context->sig_jitter_seconds = zone->sig_validity_jitter_seconds;
    context->sig_invalid_first = MAX_S32;//zone->sig_invalid_first;

#if RRSIG_DUMP>=1
    log_debug5("rrsig: header: sig_validity_interval_seconds=%d", context->sig_validity_interval_seconds);
    log_debug5("rrsig: header: sig_jitter_seconds=%d", context->sig_jitter_seconds);
    log_debug5("rrsig: header: sig_invalid_first=%d", context->sig_invalid_first);
#endif

    /* We got a list of key records */

    zdb_packed_ttlrdata* key = dnskey_rr_sll;

    char zone_dnsname[MAX_DOMAIN_LENGTH + 1];
    dnsname_to_cstr(zone_dnsname, zone->origin);

    do
    {
        ya_result return_value;
        
        u8 algorithm = DNSKEY_ALGORITHM(*key);
        u16 tag = DNSKEY_TAG(*key);
        u16 flags = DNSKEY_FLAGS(*key);
        
        dnssec_key* priv_key;
        // from disk or from global keyring
        return_value = dnssec_key_load_private(algorithm, tag, flags, zone_dnsname, &priv_key);

        if(priv_key != NULL)
        {
            /* We can sign with this key : chain it
             *
             */

            dnssec_key_sll* node;

            /*
             * This will be used in an MT environment.
             */
#if ALLOW_ZALLOC != 0
            ZALLOC_OR_DIE(dnssec_key_sll*, node, dnssec_key_sll, DNSSEC_KEY_SLL_TAG);
#else
            MALLOC_OR_DIE(dnssec_key_sll*, node, sizeof (dnssec_key_sll), DNSSEC_KEY_SLL_TAG);
#endif

            node->next = context->key_sll;
            node->key = priv_key;
            context->key_sll = node;
        }
        else
        {
            /**
             * We cannot sign with this key
             *
             * Get the public version for signature verification
             */

            log_warn("rrsig: no private key found for DNSKEY '%s' %{dnsname} algorithm %d tag=%05d flags=%3d: %r",
                     zone_dnsname, zone->origin, algorithm, tag, flags, return_value);

            dnssec_key *public_key;
            
            if(ISOK(return_value = dnskey_load_public(&key->rdata_start[0], key->rdata_size, zone_dnsname, &public_key)))
            {            
                dnssec_key_sll* node;

#if ALLOW_ZALLOC != 0
                ZALLOC_OR_DIE(dnssec_key_sll*, node, dnssec_key_sll, DNSSEC_KEY_SLL_TAG);
#else
                MALLOC_OR_DIE(dnssec_key_sll*, node, sizeof (dnssec_key_sll), DNSSEC_KEY_SLL_TAG);
#endif

                node->next = context->key_sll;
                node->key = public_key;
                context->key_sll = node;
            }
            else
            {
                log_err("rrsig: no public key found for DNSKEY '%s' %{dnsname} algorithm %d tag=%05d flags=%3d: %r",
                     zone_dnsname, zone->origin, algorithm, tag, flags, return_value);
            }
        }

        key = key->next;
    }
    while(key != NULL);
    
    if(context->key_sll == NULL)
    {
        /* No key available at all : nothing to do.
         *
         * Later we will still be able to do verification with the public keys
         * we found, and cleanup based on time.  But that's later ...
         */

        return DNSSEC_ERROR_RRSIG_NOUSABLEKEYS;
    }

    soa_rdata soa;

    if(FAIL(zdb_zone_getsoa(zone, &soa)))
    {
        return DNSSEC_ERROR_RRSIG_NOSOA;
    }
    
    context->loose_quota = quota;

    ptr_vector_init(&context->rrs);

    context->zclass = zdb_zone_getclass(zone);
    context->original_ttl = soa.minimum;
    context->valid_from = sign_from;

    context->origin = zone->origin;
    context->origin_len = dnsname_len(zone->origin);

    dnsname_to_dnsname_stack(zone->origin, &context->rr_dnsname);
    context->rr_dnsname_len = dnsname_len(zone->origin);

    context->label_depth = context->rr_dnsname.size + 1;

    U8_AT(context->rrsig_header[ 3]) = context->label_depth;
    SET_U32_AT(context->rrsig_header[ 4], htonl(context->original_ttl));
    SET_U32_AT(context->rrsig_header[ 8], 0);
    SET_U32_AT(context->rrsig_header[12], htonl(context->valid_from));

    context->rrsig_header_length = dnsname_copy(&context->rrsig_header[RRSIG_RDATA_HEADER_LEN], zone->origin) + RRSIG_RDATA_HEADER_LEN;
    
    context->engine = dnssec_loadengine(engine_name);

    if(zdb_zone_is_nsec3(zone))
    {
        if((zone->apex->flags & ZDB_RR_LABEL_NSEC3_OPTOUT) == 0)
        {
            context->nsec_flags = RRSIG_CONTEXT_NSEC3;
        }
        else
        {
            context->nsec_flags = RRSIG_CONTEXT_NSEC3_OPTOUT;
        }        
    }
    else
    {
        context->nsec_flags = RRSIG_CONTEXT_NSEC;
    }
    
    u32 min_ttl = 900;
    
    zdb_zone_getminttl(zone, &min_ttl);
    
    context->min_ttl = min_ttl;

    return SUCCESS;
}

/* self-splainatory */
void
rrsig_context_destroy(rrsig_context_s *context)
{
    dnssec_key_sll* keys = context->key_sll;

    while(keys != NULL)
    {
        dnssec_key_sll* last_node = keys;

        keys = keys->next;

#if ALLOW_ZALLOC != 0
        ZFREE(last_node, dnssec_key_sll);
#else
        free(last_node);
#endif
    }

    rr_canonize_free(&context->rrs);
    context->canonised_rrset = NULL;
    ptr_vector_destroy(&context->rrs);
    dnssec_unloadengine(context->engine);

    context->engine = NULL;
}

/*
 * Appends a label to the context so it will be processed
 */

void
rrsig_context_push_name_rrsigsll(rrsig_context_s *context, u8* name, zdb_packed_ttlrdata* rrsig_sll)
{
    yassert(context != NULL && name != NULL);

    /* CANONIZED RR HEADER PRECALC : */

    u8 label_dnsname[MAX_DOMAIN_LENGTH];

    context->rr_dnsname_processing_apex = (*name == 0);

    if(!context->rr_dnsname_processing_apex)
    {
        dnsname_stack_push_label(&context->rr_dnsname, name);
        context->rr_dnsname_len += name[0];
    }

    dnsname_stack_to_dnsname(&context->rr_dnsname, label_dnsname);

    context->label_depth = context->rr_dnsname.size + 1;

    context->flags = 0;
    context->rrsig_sll = rrsig_sll;

    if(context->rrsig_sll != NULL)
    {
        context->flags |= HAD_SIGNATURES;
    }

    context->added_rrsig_sll = NULL;
    context->removed_rrsig_sll = NULL;

    U8_AT(context->rrsig_header[ 3]) = context->label_depth;

    context->record_header_label_type_class_ttl_length = dnsname_canonize(label_dnsname, context->record_header_label_type_class_ttl);
    context->canonized_rr_type_offset = context->record_header_label_type_class_ttl_length;
    context->record_header_label_type_class_ttl_length += 2;
    SET_U16_AT(context->record_header_label_type_class_ttl[context->record_header_label_type_class_ttl_length], context->zclass); /** @note: NATIVECLASS */
    context->record_header_label_type_class_ttl_length += 2;
}

/*
 * Called by:
 * 
 * rrsig_updater_thread
 * zdb_icmtl_end
 */
void
rrsig_context_push_label(rrsig_context_s *context, zdb_rr_label* label)
{
    yassert(context != NULL && label != NULL);

    /* CANONIZED RR HEADER PRECALC : */

    rrsig_context_push_name_rrsigsll(context, label->name, zdb_record_find(&label->resource_record_set, TYPE_RRSIG));
}

/*
 * Called by:
 *
 * rrsig_updater_thread
 * zdb_icmtl_end
 */

void
rrsig_context_pop_label(rrsig_context_s *context)
{
    if(!context->rr_dnsname_processing_apex)
    {
        context->rr_dnsname_len -= context->rr_dnsname.labels[context->rr_dnsname.size][0];
        dnsname_stack_pop_label(&context->rr_dnsname);
    }

    // yassert(context->rr_dnsname_len >= 0);

    context->rrsig_sll = NULL;
    context->added_rrsig_sll = NULL;
    context->removed_rrsig_sll = NULL;
}

void
rrsig_context_set_key(rrsig_context_s *context, dnssec_key* key)
{
    yassert(key != NULL);

    /* ONLY THE TYPE CHANGES IN THE TWO FOLLOWING CANONIZED HEADERS : */

    /* We already got a canonized rrsig
     * We only need to update the key algorithm and tag
     */
                                  \
    U8_AT(context->rrsig_header[ 2]) = key->algorithm;
    SET_U16_AT(context->rrsig_header[16], htons(key->tag));

    //context->rrsig_header_length = dnsname_copy(&context->rrsig_header[RRSIG_RDATA_HEADER_LEN], key->owner_name) + RRSIG_RDATA_HEADER_LEN;
}

static u32
rrsig_compute_digest(u8 * restrict rrsig_header,
                     u32 rrsig_header_length,
                     u8 * restrict record_header_label_type_class_ttl,
                     u32 record_header_label_type_class_ttl_length,
                     ptr_vector* canonized_rr,
                     u8 * restrict digest_out)
{
    /**
     * Only supported digest is SHA1 because we do RSA-SHA1 or DSA-SHA1
     * @todo: Other digests ... later
     */

    assert( (offsetof(zdb_canonized_packed_ttlrdata, rdata_start) - offsetof(zdb_canonized_packed_ttlrdata, rdata_canonized_size)) == 2  );

    digest_s ctx;

    dnskey_digest_init(&ctx, rrsig_header[2]);

    /*
     * Add the rrsig (except the signature) to the digest.
     *
     * NOTE: This is true only at generation :
     *
     *	    Only the type of the rrsig changes in this loop, so I computed
     *	    the rest of the header just before, once.
     *
     * NOTE: At verification I have to put up with anything that's in the
     *	     signature's field (could be virtually anything)
     *
     */

#if RRSIG_DUMP>=2
    log_debug5("rrsig: header:");
    log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG5, rrsig_header, rrsig_header_length, 32, OSPRINT_DUMP_HEXTEXT);
#endif

    /*
     * Type covered | algorithm | labels | original_ttl | exp | inception | tag | origin
     *
     */
    digest_update(&ctx, rrsig_header, rrsig_header_length);

    /* For EACH rr, canonization-order :
     *
     * digest the label (full dns name, canonized : FIXED)
     * digest the type (16 bits, Big Endian a.k.a network endian : LOOP-DEPENDENT)
     * digest the class (16 bits, BE, : FIXED)
     * digest the ttl (32 bits, BE : FIXED)
     * +
     * digest the rdata length (16 bits, BE : LOOP-DEPENDENT)
     * digest the rdata, with canonized full dns names ( variable : LOOP-DEPENDENT)
     *
     *
     * Since only the type change in the header part of the canonized rr, I've computer
     * the rest of the header just before, once.
     *
     * The rdata_size + rdata are canonized
     * (They are sorted by rdata according to the rules in the rfc4034)
     *
     * I'm using the standard qsort to do this.
     *
     * Compute the digest on the canonized rrs
     */

    /* NOTE : this is a counter : it's not used as an offset in the array.
     *
     * The "offset" field of the ptr_vector is the last used slot, so effectively
     * the size-1 of its payload.
     */

    s32 n = canonized_rr->offset;
    zdb_canonized_packed_ttlrdata** rdatap = (zdb_canonized_packed_ttlrdata**)canonized_rr->data;
    while(n-- >= 0)
    {
        zdb_canonized_packed_ttlrdata* rdata = *rdatap;

        /*
         * owner | type | class
         */

#if RRSIG_DUMP>=2
        log_debug5("rrsig: record header:");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG5, record_header_label_type_class_ttl, record_header_label_type_class_ttl_length, 32, OSPRINT_DUMP_HEXTEXT);
#endif

        digest_update(&ctx, record_header_label_type_class_ttl, record_header_label_type_class_ttl_length);

        /*
         * ttl
         */

#if RRSIG_DUMP>=2
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG5, &rrsig_header[4], 4, 32, OSPRINT_DUMP_HEXTEXT);
#endif

        digest_update(&ctx, &rrsig_header[4], 4);

        /*
         * rdata+ , canonical order
         */

#if RRSIG_DUMP>=2
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG5, &rdata->rdata_canonized_size, rdata->rdata_size + 2, 32, OSPRINT_DUMP_HEXTEXT);
#endif
        digest_update(&ctx, &rdata->rdata_canonized_size, rdata->rdata_size + 2);

        /* I used to free the rdata here.  I cannot do this anymore since
         * the digest could be recomputed with slight variations
         */

        rdatap++;
    }

    /*
     * Retrieve the digest
     */

    u32 digest_len = digest_get_size(&ctx);
    
    digest_final(&ctx, digest_out, digest_get_size(&ctx));

#if RRSIG_DUMP!=0
    log_debug5("rrsig: digest:");
    log_memdump_ex(MODULE_MSG_HANDLE, MSG_DEBUG5, digest_out, digest_len, 32, OSPRINT_DUMP_HEX);
#endif
    
    return digest_len;
}

static void
rrsig_context_append_delete_signature(rrsig_context_s *context, zdb_packed_ttlrdata* rrsig)
{
    zdb_packed_ttlrdata* rrsig_clone;

    MALLOC_OR_DIE(zdb_packed_ttlrdata*, rrsig_clone, ZDB_RECORD_SIZE(rrsig), RRSIG_TTLRDATA_TAG);

    rrsig_clone->ttl = rrsig->ttl;
    rrsig_clone->rdata_size = rrsig->rdata_size;
    MEMCOPY(rrsig_clone->rdata_start, rrsig->rdata_start, rrsig->rdata_size);

    rrsig_clone->next = context->removed_rrsig_sll;
    context->removed_rrsig_sll = rrsig_clone;
}

static void rrsig_context_update_canon(rrsig_context_s *context, u16 rtype, zdb_packed_ttlrdata *rrset)
{
    if(context->canonised_rrset != rrset)
    {
        rr_canonize_free(&context->rrs);
        /* copy, canonize labels & sort the RRs */
        rr_canonize_rrset(rtype, rrset, &context->rrs);
        context->canonised_rrset = rrset;
    }
}

static bool
rrsig_verify_signature(rrsig_context_s *context, dnssec_key* key, zdb_packed_ttlrdata* rrsig, zdb_packed_ttlrdata *rrset)
{
    u8 digest[DIGEST_BUFFER_SIZE];

    u8* rrsig_name = &rrsig->rdata_start[RRSIG_RDATA_HEADER_LEN];

    /*
     * The owner of the signature must match the owner or the RRSIG
     */

#if RRSIG_DUMP != 0
    rdata_desc rdatadesc={TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig), ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig)};
    log_debug("rrsig: verify: %{dnsnamestack} %{typerdatadesc}", &context->rr_dnsname, &rdatadesc);
#endif

    if(dnsname_equals(rrsig_name, context->origin))
    {
        /*
         * The digest for this signature could be different than the one I
         * would compute (ttl, inception, expiration)
         *
         * The type-covered, labels & key-tag should be the same
         */

#if RRSIG_DUMP!=0
        u16 type = RRSIG_TYPE_COVERED(rrsig);
        log_debug5("rrsig: verify: %{dnsnamestack}(%d) %{dnstype} %05d", &context->rr_dnsname, context->label_depth, &type, key->tag);
#endif

        time_t now = time(NULL);

        u32 valid_until = RRSIG_VALID_UNTIL(rrsig);

        if(valid_until < now)
        {
            /*
             * Expired signature
             */

#if RRSIG_DUMP!=0
            u16 type = RRSIG_TYPE_COVERED(rrsig);
            log_debug5("rrsig: verify: -- EXPIRED at %d (%d ago)", valid_until, now - valid_until);
#endif
            return FALSE;
        }
        
        // skip the verification
        
        if(!context->do_verify_signatures)
        {
            context->good_signatures++;
            context->sig_invalid_first = MIN(valid_until, context->sig_invalid_first);
            
            return TRUE;
        }
        
        /*
         * Update canonised
         */
        
        u16 rtype = RRSIG_TYPE_COVERED(rrsig);
        
        rrsig_context_update_canon(context, rtype, rrset);

        /*
         * The length of the header in the RRSIG
         */
                
        u32 rrsig_start_len = RRSIG_RDATA_HEADER_LEN + context->origin_len;
        u32 digest_len = rrsig_compute_digest(rrsig->rdata_start,
                             rrsig_start_len,
                             context->record_header_label_type_class_ttl,
                             context->record_header_label_type_class_ttl_length,
                             &context->rrs,
                             digest);

        u8* signature = &rrsig->rdata_start[rrsig_start_len];
        u32 signature_len = ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig) - rrsig_start_len;

#if RRSIG_DUMP>=2
        log_debug5("rrsig: signature record:");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG5, rrsig->rdata_start, rrsig->rdata_size, 32, OSPRINT_DUMP_HEXTEXT);
        log_debug5("rrsig: signature to verify:");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG5, signature, signature_len, 32, OSPRINT_DUMP_HEXTEXT);
        log_debug5("rrsig: verifying digest:");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG5, digest, digest_len, 32, OSPRINT_DUMP_HEXTEXT);
#endif

        /**
         * @todo: Verifying the digest is useless if it has already been verified once here already
         *        And said digest only needs to be verified if it comes from a zone file or dynupdate
         */

        if(key->vtbl->dnssec_key_verify_digest(key, digest, digest_len, signature, signature_len))
        {
#if RRSIG_DUMP!=0
            log_debug5("rrsig: verify: -- OK");
#endif
            /* GOOD SIGNATURE : Nothing to do here : process the next type */

            context->good_signatures++;

            /* Already signed, and signature is valid */

#if RRSIG_DUMP!=0
            log_debug5("rrsig: verify: -- OK, first invalid at = %d (%d,%d)", MIN(valid_until, context->sig_invalid_first), valid_until, context->sig_invalid_first);
#endif

            context->sig_invalid_first = MIN(valid_until, context->sig_invalid_first);

            return TRUE;
        }

#if RRSIG_DUMP!=0
        log_debug5("rrsig: verify: -- WRONG");
#endif

        context->wrong_signatures++;
    }

#if RRSIG_DUMP!=0
    log_debug5("rrsig: verify: -- ERR");
#endif

    /* WRONG SIGNATURE : The caller will have to remove it */

    return FALSE;
}

/** @todo: Loop through the keys AFTER having computed the digest */
ya_result
rrsig_update_records(rrsig_context_s *context, dnssec_key* key, zdb_packed_ttlrdata* rr_sll, u16 type, bool do_update)
{
    do_update &= key->is_private;

    /*******************************************************************
     * COMPUTE THE DIGEST (Always needed)
     ******************************************************************/

    /* Update the type */
    SET_U16_AT(context->rrsig_header[0], type); /** @note: NATIVETYPE */

    /* Update the type */
    SET_U16_AT(context->record_header_label_type_class_ttl[context->canonized_rr_type_offset], type); /** @note: NATIVETYPE */

    /*******************************************************************
     * Find & Verify the signature (IF ANY)
     ******************************************************************/

    /* Look into rrsig records for one that covers the current type */

    zdb_packed_ttlrdata *rrsig = context->rrsig_sll;
    //zdb_packed_ttlrdata* rrsig_prev = NULL; /* I could need to detach the node from the list */

    /**
     * While I've got signatures records
     *
     * @todo: NOTE: More than one signature can be made with a given key (I presume)
     *        This means I cannot stop at the first match but I have to test them all ...
     *
     */

#if RRSIG_DUMP!=0
    log_debug(">> ------------------------------------------------------------------------");
    log_debug("rrsig: verifying %{dnsnamestack} %{dnstype}", &context->rr_dnsname, &type);
#endif

    u32 now = time(NULL);
    u32 sig_count = 0;
    if(context->sig_invalid_first == 0)
    {
        context->sig_invalid_first = MAX_U32;
    }

    bool type_signed = FALSE;
    bool deleted_already = FALSE;

    u32 until = 0;

    while(rrsig != NULL)
    {
        u16 tag = RRSIG_KEY_TAG(rrsig);

        if(tag == key->tag)
        {
            /* If I've found the rrsig associated to the current type, I break */
            if(RRSIG_TYPE_COVERED(rrsig) == type)
            {
                /* Got a signature:
                 *
                 * The goal is to remove it if it is wrong or expired
                 *
                 */

                bool valid_signature;
                
                valid_signature = rrsig_verify_signature(context, key, rrsig, rr_sll);
                
                type_signed |= valid_signature;

                if(!valid_signature)
                {
#if RRSIG_DUMP!=0
                    log_debug5("rrsig: delete wrong or expired signature");
#endif
                    if(do_update)
                    {
                        rrsig_context_append_delete_signature(context, rrsig);
                        deleted_already = TRUE;
                    }
                }
                else
                {
                    /*
                     * It is not wrong but maybe it is time to make a new one ...
                     *
                     */

                    /* This key is still a candidate on the "next update event" list */

                    until = MAX(until, RRSIG_VALID_UNTIL(rrsig));
                }
            }
        }

        //rrsig_prev = rrsig;
        rrsig = rrsig->next;
    }


    /*
     * "until" is the oldest signature validity for this record set made by this key
     *
     * If this until is too close, then generate a new signature.
     */

    context->sig_invalid_first = MIN(until, context->sig_invalid_first);

    if(do_update && !type_signed)
    {
        if(until < now + context->sig_validity_regeneration_seconds)
        {
            type_signed = FALSE;
            if((rrsig != NULL) && (!deleted_already))
            {
                rrsig_context_append_delete_signature(context, rrsig);
            }
        }

        /*
         * This should only be executed if:
         *
         * _ There are no RRSIG for this type
         * _ The RRSIG are soon to be expired (ie: less than 1 week)
         *
         * _ Type is not SOA: SOA should only be updated at the end of the change
         *
         */

#if RRSIG_DUMP!=0
        log_debug5("rrsig: create: %{dnsnamestack}(%d) %{dnstype} %05d", &context->rr_dnsname, context->label_depth, &type, key->tag);
#endif
        
        u32 valid_until;

        if(context->sig_jitter_seconds > 0)
        {
            random_ctx rndctx = thread_pool_get_random_ctx();
            
            u32 jitter = random_next(rndctx) % context->sig_jitter_seconds;
            valid_until = now + context->sig_validity_interval_seconds + jitter;
            SET_U32_AT(context->rrsig_header[8], htonl(valid_until));

#if RRSIG_DUMP!=0
            log_debug5("rrsig: sig_invalid_first = %d (%d ?) (jitter)", context->sig_invalid_first, valid_until);
#endif
        }
        else
        {
            valid_until = ntohl(GET_U32_AT(context->rrsig_header[8]));
            
#if RRSIG_DUMP!=0
            log_debug5("rrsig: sig_invalid_first = %d (%d ?) (no jitter)", context->sig_invalid_first, valid_until);
#endif
        }

        /**
         * @TODO: context->sig_invalid_first must be updated, and then the zone->sig_invalid_first too, when it's done.
         */

        context->sig_invalid_first = MIN(valid_until, context->sig_invalid_first);

#if RRSIG_DUMP!=0
        log_debug5("rrsig: create: computing digest");
#endif
        
        rrsig_context_update_canon(context, type, rr_sll);

        u32 digest_len;
        u32 signature_len;
        u8 digest[DIGEST_BUFFER_SIZE];
        u8 signature[DNSSEC_MAXIMUM_KEY_SIZE_BYTES];
        
        digest_len = rrsig_compute_digest(context->rrsig_header,
                                context->rrsig_header_length,
                                context->record_header_label_type_class_ttl,
                                context->record_header_label_type_class_ttl_length,
                                &context->rrs,
                                digest);

#if RRSIG_DUMP>2
        log_debug5("rrsig: signing digest:");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG5, digest, digest_len, 32, OSPRINT_DUMP_HEXTEXT);
#endif

        signature_len = key->vtbl->dnssec_key_sign_digest(key, digest, digest_len, signature);

        yassert(signature_len > 0);

        /* We got the signature. */

#if RRSIG_DUMP>=2
        log_debug5("rrsig: signature:");
        log_memdump(MODULE_MSG_HANDLE, MSG_DEBUG5, signature, signature_len, 32, OSPRINT_DUMP_HEXTEXT);
        log_debug5("<< ------------------------------------------------------------------------");
#endif

        ZDB_RECORD_MALLOC_EMPTY(rrsig, context->original_ttl, context->rrsig_header_length + signature_len);

        /* Copy the header */

        MEMCOPY(&rrsig->rdata_start[0], context->rrsig_header, context->rrsig_header_length);

        /* Append the signature */

        MEMCOPY(&rrsig->rdata_start[context->rrsig_header_length], signature, signature_len);

        /* Add to the schedule "to be added" list */

        rrsig->next = context->added_rrsig_sll;
        context->added_rrsig_sll = rrsig;

        context->flags |= UPDATED_SIGNATURES;
        
        sig_count++;
    }
    else
    {
        // NOP
    }

    return sig_count; /* Signed */
}

ya_result
rrsig_update_label_rrset(rrsig_context_s *context, zdb_rr_label* label, u16 rrset_type) /* Maybe It's a dup*/
{
    yassert(context != NULL);

    if(rrset_type == TYPE_ANY)
    {
        ya_result return_code = rrsig_update_label(context, label);
        
        rrsig_context_update_quota(context, return_code);
        
        return return_code;
    }

    ya_result ret = DNSSEC_ERROR_RRSIG_NOSIGNINGKEY; /* No signing key */
    s32 sig_count = 0;

    /* Get the first key (container) */

    dnssec_key_sll* key_sll;

    zdb_packed_ttlrdata* records_sll = zdb_record_find(&label->resource_record_set, rrset_type);

    bool delegation = ZDB_LABEL_ATDELEGATION(label);
    
    /* While we have signing keys ... */

    for(key_sll = context->key_sll; key_sll != NULL; key_sll = key_sll->next)
    {
        /* Take the real key from the key container */

        dnssec_key* key = key_sll->key;

        rrsig_context_set_key(context, key);

        /* Get all the signatures on this label (NULL if there are no signatures) */

        /* Sign every resource record */

        /*
         * If the query has been marked "delegation" we only can sign the
         * DS record
         *
         * ie: avoid glue records, non-auth, ...
         *
         */
        
        if(!delegation)
        {
            if(key->flags == (DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY))
            {
                /* KSK */

                if(rrset_type != TYPE_DNSKEY)
                {
#if RRSIG_DUMP>=3
                    log_debug5("rrsig: skipping : KSK of !DNSKEY (%{dnstype}/%{dnslabel}.%{dnsnamestack})", &rrset_type, label, &context->rr_dnsname);
#endif

                    continue;
                }
            }
            else if(key->flags == DNSKEY_FLAG_ZONEKEY)
            {
                if(rrset_type == TYPE_RRSIG)
                {
#if RRSIG_DUMP>=3
                    log_debug5("rrsig: skipping ; ZSK of RRSIG (%{dnstype}/%{dnslabel}.%{dnsnamestack})", &rrset_type, label, &context->rr_dnsname);
#endif
                    continue;
                }
            }
            else
            {
#if RRSIG_DUMP>=3
                log_debug5("rrsig: skipping : unsupported key type (%{dnstype}/%{dnslabel}.%{dnsnamestack})", &rrset_type, label, &context->rr_dnsname);
#endif
                continue;
            }
        }
        else /* delegation */
        {
            if((rrset_type != TYPE_DS) || (key->flags != DNSKEY_FLAG_ZONEKEY))
            {
#if RRSIG_DUMP>=3
                log_debug5("rrsig: skipping : delegation (%{dnstype}/%{dnslabel}.%{dnsnamestack})", &rrset_type, label, &context->rr_dnsname);
#endif
                continue;
            }
        }

        /*
         * Get the right RRSIG for the type
         */

        if(FAIL(ret = rrsig_update_records(context, key, records_sll, rrset_type, TRUE)))
        {
            break;
        }
        
        sig_count += ret;

    } /* Loop for the next key */

    /* Inject the signatures back
     */
    
    if(ISOK(ret))
    {
        ret = sig_count;
    }
    
    return ret;
}

ya_result
rrsig_update_label(rrsig_context_s *context, zdb_rr_label* label)
{
    yassert(context != NULL);

    if(context->key_sll == NULL)
    {
        /* nothing to do */

        return DNSSEC_ERROR_RRSIG_NOSIGNINGKEY;
    }
    
    u8 nsec_flags = context->nsec_flags;
    //bool at_apex = (label->name[0] == 0);

    /* Get all the signatures on this label (NULL if there are no signatures) */

    /**
     * If there are signatures here:
     *   Verify the expiration time :
     *
     *     If it is expired, then destroy it (mark them for destruction)
     *
     *     If it will expire soon AND we are supposed to work on the type AND we have the private key available,
     *     then remove it
     *
     * Don't forget to set UPDATED_SIGNATURES if any change is made
     */

    /* Sign relevant resource records */
    
    s32 sig_count = 0;

    if(!ZDB_LABEL_UNDERDELEGATION(label))
    {

        btree_iterator iter;
        btree_iterator_init(label->resource_record_set, &iter);

        /* Sign only APEX and DS records at delegation */

        while(btree_iterator_hasnext(&iter))
        {
            btree_node* rr_node = btree_iterator_next_node(&iter);
            u16 type = (u16)rr_node->hash;

            /* cannot sign a signature */

            if(type == TYPE_RRSIG)
            {
                continue;
            }

            for(dnssec_key_sll* key_sll = context->key_sll; key_sll != NULL; key_sll = key_sll->next)
            {
                /* Take the real key from the key container */

                dnssec_key* key = key_sll->key;

                rrsig_context_set_key(context, key);

                /* can the key sign this kind of record */

                if(key->flags == (DNSKEY_FLAG_ZONEKEY | DNSKEY_FLAG_KEYSIGNINGKEY))
                {
                    /* KSK can only sign a DNSKEY */

                    if(type != TYPE_DNSKEY)
                    {
#if RRSIG_DUMP>=3
                        log_debug5("rrsig: skipping : KSK of !DNSKEY (%{dnstype}/%{dnslabel}.%{dnsnamestack})", &type, label->name, &context->rr_dnsname);
#endif

                        continue;
                    }
                }
                else if(key->flags == DNSKEY_FLAG_ZONEKEY)
                {
                    /* ZSK should not sign a DNSKEY */

                    if(type == TYPE_DNSKEY)
                    {
#if RRSIG_DUMP>=3
                        log_debug5("rrsig: skipping ; ZSK of RRSIG (%{dnstype}/%{dnslabel}.%{dnsnamestack})", &type, label->name, &context->rr_dnsname);
#endif
                        continue;
                    }

                    /* if not at apex then only sign the DS */

                    switch(nsec_flags)
                    {
                        case RRSIG_CONTEXT_NSEC3_OPTOUT:
                        {
                            if(ZDB_LABEL_ATDELEGATION(label))
                            {
                                if(type != TYPE_DS)
                                {
                                    continue;   /* only sign DS & NSEC at delegation */
                                }                                
                            }
                            else
                            {
                                /* sign everything else */
                            }

                            break;
                        }
                        case RRSIG_CONTEXT_NSEC3:
                        {
                            /* sign everything not filtered out yet */
                            break;
                        }
                        case RRSIG_CONTEXT_NSEC:
                        {
                            /* sign everything not filtered out yet */

                            if(ZDB_LABEL_ATDELEGATION(label))
                            {
                                if((type != TYPE_DS) && (type != TYPE_NSEC))
                                {
                                    continue;   /* only sign DS & NSEC at delegation */
                                }                                
                            }
                            else
                            {
                                /* sign everything else */
                            }

                            break;
                        }
                    }
                }
                else
                {
                    /* key type is not supported */

                    continue;
                }

                /*
                 * Get the right RRSIG for the type
                 */

                zdb_packed_ttlrdata* rr_sll = (zdb_packed_ttlrdata*)rr_node->data;

                ya_result return_code;

                if(FAIL(return_code = rrsig_update_records(context, key, rr_sll, type, type != TYPE_SOA)))
                {
                    return return_code;
                }
                
                sig_count += return_code;
                
            }   /* for every key */
        }
    }
    else
    {
        /* destroy all signatures */
        
        log_debug("rrsig: destroy: %{dnsnamestack} %04x", &context->rr_dnsname, label->flags);

        zdb_packed_ttlrdata* rrsig_sll = zdb_record_find(&label->resource_record_set, TYPE_RRSIG);

        while(rrsig_sll != NULL)
        {
#if RRSIG_DUMP>=3
            log_debug5("rrsig: destroying illegaly placed signatures (%{dnslabel}.%{dnsnamestack})", &type, label->name, &context->rr_dnsname);
#endif

            rrsig_context_append_delete_signature(context, rrsig_sll);
            
            rrsig_sll = rrsig_sll->next;
        }
    }

    /* All the signatures for this label have been processed. */

    return sig_count;
}

/**
 * Takes the result of an update and commits it to the label
 *
 * @todo Have an alternative function using the scheduler.
 */

void
rrsig_update_commit(zdb_packed_ttlrdata* removed_rrsig_sll, zdb_packed_ttlrdata* added_rrsig_sll, zdb_rr_label* label, zdb_zone* zone, dnsname_stack* name)
{
    /*
     * NOTE: This is the only place where I can access the zone signature invalidation update properly
     *       I have to tell to the alarm: update your signature alarm clock so that the zone for name is updated
     *
     * NOTE: NSEC3 records have not associated label. (Not really)
     *
     * NOTE: There is a listener hook in here.
     *
     */

    /**
     * @todo: fetch the zone from the name, then update the invalidation using the added signatures
     */

#if RRSIG_DUMP>=3
    log_debug("rrsig: updating: %{dnsnamestack}", name);
#endif

    if((removed_rrsig_sll == NULL) && (added_rrsig_sll == NULL))
    {
#if RRSIG_DUMP>=3
        log_debug("rrsig: updating: nothing to do for %{dnsnamestack}", name);
#endif

        return;
    }

#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0
    
    // notify the journal
    
    zdb_listener_notify_update_rrsig(removed_rrsig_sll, added_rrsig_sll, label, name);
#endif

    zdb_packed_ttlrdata* sig;

    zdb_packed_ttlrdata** rrsig_sllp = zdb_record_find_insert(&label->resource_record_set, TYPE_RRSIG); /* FB handled separately */

#ifdef DEBUG
    zdb_packed_ttlrdata** rrsig_sllp_check = rrsig_sllp;
#endif

    /*
     * For each removed signature:
     *
     * Find it in the label's RRSIG list, then remove it:
     * ZFREE + MFREE
     *
     */

    sig = removed_rrsig_sll;

    while(sig != NULL)
    {
        /*
         * Look for the RRSIG
         *
         */

        zdb_packed_ttlrdata** rrsig_recordp = rrsig_sllp;
        zdb_packed_ttlrdata *rrsig_record = *rrsig_recordp;

#ifdef DEBUG
        rdata_desc rdatadesc={TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(sig), ZDB_PACKEDRECORD_PTR_RDATAPTR(sig)};
        log_debug("rrsig: updating: deleting: %{dnsnamestack} %{typerdatadesc}", name, &rdatadesc);
#endif

        /* This is why my "next" pointer is ALWAYS the first field */

        bool warning = TRUE;

        while(rrsig_record != NULL)
        {
            /*
             * Check if the COVERED TYPE + TAG are matching
             */

            if(ZDB_PACKEDRECORD_PTR_RDATASIZE(sig) == ZDB_PACKEDRECORD_PTR_RDATASIZE(sig))
            {
                if(memcmp(ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig_record), ZDB_PACKEDRECORD_PTR_RDATAPTR(sig), RRSIG_RDATA_HEADER_LEN) == 0)
                {
                    /* remove it from the chain */
                    *rrsig_recordp = rrsig_record->next;
#ifdef DEBUG
                    rrsig_record->next = (zdb_packed_ttlrdata*)~0;
#endif
                    ZDB_RECORD_ZFREE(rrsig_record);
                    
                    warning = FALSE;

                    /*
                     * I can stop here.
                     */

                    break;
                }
            }

            rrsig_recordp = &rrsig_record->next;
            rrsig_record = *rrsig_recordp;
        }

        if(warning)
        {
            rdata_desc rdatadesc={TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(sig), ZDB_PACKEDRECORD_PTR_RDATAPTR(sig)};
            log_warn("rrsig: signature scheduled for delete not found: [%d] %{dnsnamestack} %{typerdatadesc}", ZDB_PACKEDRECORD_PTR_RDATASIZE(sig), name, &rdatadesc);
        }

        zdb_packed_ttlrdata* tmp = sig;
        sig = sig->next;
        free(tmp);
    }

    /*
     * For each added signature:
     *
     * Add it:
     *
     * ZFREE + MFREE
     *
     */

    sig = added_rrsig_sll;

    while(sig != NULL)
    {
        zdb_packed_ttlrdata* rrsig_record;

        u8* rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(sig);
        u32 rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(sig);

#ifdef DEBUG
        rdata_desc rdatadesc={TYPE_RRSIG, rdata_size, rdata};
        log_debug5("rrsig: updating: adding: %{dnsnamestack} %{typerdatadesc}", name, &rdatadesc);
#endif
        /* Handle signature invalidation time */
        
#if RRSIG_AUTOMATIC_ALARM_REFRESH
        
        u32 valid_until = MIN(RRSIG_VALID_UNTIL(rrsig_record), zone->sig_invalid_first);
        
        if(zone->sig_invalid_first > valid_until)
        {
            /**
             * @todo Change the resign time for this zone to valid_until
             */

#if RRSIG_DUMP!=0
            log_debug("rrsig: updating: changing signature invalidation from %d to %d", zone->sig_invalid_first, valid_until);
#endif

            zone->sig_invalid_first = valid_until;

            alarm_event_node *event = alarm_event_alloc();
            event->epoch = zone->sig_invalid_first;
            event->function = zdb_update_zone_signatures_alarm;
            event->args = zone;
            event->key = ALARM_KEY_ZONE_SIGNATURE_UPDATE;
            event->flags = ALARM_DUP_REMOVE_LATEST;
            event->text = "zdb_update_zone_signatures_alarm";

            alarm_set(zone->alarm_handle, event);
        }
#endif

        /**/

        ZDB_RECORD_ZALLOC(rrsig_record, sig->ttl, rdata_size, rdata);

        /* Insert */

        rrsig_record->next = *rrsig_sllp;
        *rrsig_sllp = rrsig_record;

        zdb_packed_ttlrdata* tmp = sig;
        sig = sig->next;
        free(tmp);
    }



    /*
     * If the head of the list is NULL
     */

    if(*rrsig_sllp == NULL)
    {
        /*
         * Note : the RRSIG CANNOT be the last type on the label.
         *
         * When deleting a record of a given type from a label,
         * the associated RRSIG MUST be removed first.
         *
         * In order to accommodate an structure error, the caller could check
         * if the label is still relevant, and do a cleanup if required.
         */

#if RRSIG_DUMP!=0
        log_debug5("rrsig: removing obsolete RRSIG node", label);
#endif

#ifdef DEBUG
        yassert(*rrsig_sllp_check == NULL);
#endif

        zdb_record_delete(&label->resource_record_set, TYPE_RRSIG); /* FB handled separately */
    }
}

/**
 * 
 * Returns the first RRSIG record that applies to the give type.
 * 
 * @param label        the label where to do the search
 * @param covered_type the type covered by the RRSIG
 * 
 * @return the first RRSIG covering the type or NULL
 */

zdb_packed_ttlrdata*
rrsig_find_first(const zdb_rr_label* label, u16 type)
{
    zdb_packed_ttlrdata* rrsig = zdb_record_find(&label->resource_record_set, TYPE_RRSIG);

    while(rrsig != NULL)
    {
        if(RRSIG_TYPE_COVERED(rrsig) == type)
        {
            return rrsig;
        }

        rrsig = rrsig->next;
    }

    return NULL;
}

/**
 * 
 * Returns the next RRSIG record that applies to the give type.
 * 
 * @param rrsig        the previous RRSIG covering the type
 * @param covered_type the type covered by the RRSIG
 * 
 * @return  covered_type the next RRSIG covering the type or NULL
 */
 
zdb_packed_ttlrdata*
rrsig_find_next(const zdb_packed_ttlrdata* rrsig, u16 type)
{
    rrsig = rrsig->next;
    
    while(rrsig != NULL)
    {
        if(RRSIG_TYPE_COVERED(rrsig) == type)
        {
            return (zdb_packed_ttlrdata*)rrsig;
        }

        rrsig = rrsig->next;
    }

    return NULL;
}

/**
 * 
 * Removes all the RRSIG covering the type
 * 
 * @param dname         the fqdn of the label
 * @param label         the label
 * @param covered_type  the type covered by the RRSIG
 */

void
rrsig_delete(const u8 *dname, zdb_rr_label* label, u16 type)
{
    /*
     * zdb_packed_ttlrdata** prev = zdb_record_findp(&label->resource_record_set, TYPE_RRSIG);
     *
     * =>
     *
     */

    zdb_packed_ttlrdata** first = (zdb_packed_ttlrdata**)btree_findp(&label->resource_record_set, TYPE_RRSIG);

    if(first == NULL)
    {
        return;
    }

    zdb_packed_ttlrdata** prev = first;

    zdb_packed_ttlrdata* rrsig = *prev;

    while(rrsig != NULL)
    {
        if(RRSIG_TYPE_COVERED(rrsig) == type)
        {
            if(zdb_listener_notify_enabled())
            {
                zdb_ttlrdata unpacked_ttlrdata;

                unpacked_ttlrdata.ttl = rrsig->ttl;
                unpacked_ttlrdata.rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig);
                unpacked_ttlrdata.rdata_pointer = ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig);

                zdb_listener_notify_remove_record(dname, TYPE_RRSIG, &unpacked_ttlrdata);
            }
            
            /* */
                
            if(prev == first && rrsig->next == NULL) /* Only one RRSIG: proper removal and delete */
            {
                zdb_record_delete(&label->resource_record_set, TYPE_RRSIG);
                break;
            }
            else
            {
                *prev = rrsig->next; /* More than one RRSIG: unchain and delete */

                ZDB_RECORD_ZFREE(rrsig);                
                rrsig = *prev;
                
                if(rrsig == NULL)
                {
                    break;
                }
            }
        }

        prev = &(*prev)->next;
        rrsig = rrsig->next;
    }
}

/** @} */

/*----------------------------------------------------------------------------*/


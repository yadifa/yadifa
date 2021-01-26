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

/** @defgroup rrsig RRSIG functions
 *  @ingroup dnsdbdnssec
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _RRSIG_H
#define	_RRSIG_H

#include <dnscore/threaded_queue.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/dnskey.h>

#include <dnsdb/zdb_types.h>

#if ZDB_HAS_NSEC3_SUPPORT

#include <dnsdb/nsec3.h>

#endif

#define RRSIG_TTLRDATA_TAG	0x52544749535252    /* RRSIGTR */
#define DNSSEC_KEY_SLL_TAG	0x59454b43455344    /* DSECKEY */

#define DNSSEC_DEBUGLEVEL       0  // NOT FOR RELEASE (put a 0 here on RELEASE code)
#define DNSSEC_DUMPSIGNCOUNT    0

#if !DEBUG
#define SIGNER_THREAD_COUNT     2
#else
#define SIGNER_THREAD_COUNT     1   /* EASIER FOR DEBUGGING */
#endif

#define SIGNATURES_COUNT        1000
#define QUEUE_MAX_SIZE          65536
#define MAX_ENGINE_PRESET_COUNT 128

/** The label is not signed */
#define RRSIG_VERIFIER_RESULT_LABELNOTSIGNED    4
/** The type is not signed */
#define RRSIG_VERIFIER_RESULT_NOTSIGNED         3
/** The signature has not been verified */
#define RRSIG_VERIFIER_RESULT_BADSIGNATURE      2
/** The parameters of the RRSIG does not match the context */
#define RRSIG_VERIFIER_RESULT_BADRECORD         1
/** The signature has been verified  */
#define RRSIG_VERIFIER_RESULT_OK                0

#define RRSIG_VERIFIER_RESULT_MAXVALUE          4


#define NO_SIGNATURES       0
#define HAD_SIGNATURES      1
#define UPDATED_SIGNATURES  2

#define RRSIG_DEFAULT_VALIDITY_DURATION	    (86400*31)

/*
 * Extract fields from a packed record
 */

#define RRSIG_TYPE_COVERED(x__)	    (GET_U16_AT((x__)->rdata_start[0]))       /** @note : NATIVETYPE */
#define RRSIG_ALGORITHM(x__)	    ((x__)->rdata_start[2])
#define RRSIG_LABELS(x__)           ((x__)->rdata_start[3])
#define RRSIG_ORIGINAL_TTL(x__)	    (ntohl(GET_U32_AT((x__)->rdata_start[4])))
#define RRSIG_VALID_UNTIL(x__)	    (ntohl(GET_U32_AT((x__)->rdata_start[8])))
#define RRSIG_VALID_SINCE(x__)	    (ntohl(GET_U32_AT((x__)->rdata_start[12])))
#define RRSIG_KEY_TAG(x__)          (ntohs(GET_U16_AT((x__)->rdata_start[16]))) /** @note : NATIVETAG (LOOK FOR ALL OF THEM) */
#define RRSIG_KEY_NATIVETAG(x__)    (GET_U16_AT((x__)->rdata_start[16]))
#define RRSIG_SIGNER_NAME(x__)	    (&(x__)->rdata_start[18])

#define RRSIG_RDATA_TO_TYPE_COVERED(x__) GET_U16_AT(x__)

#define RRSIG_CONTEXT_NSEC          1
#define RRSIG_CONTEXT_NSEC3         2
#define RRSIG_CONTEXT_NSEC3_OPTOUT  3

#ifdef	__cplusplus
extern "C" {
#endif


bool rrsig_should_remove_signature_from_rdata(const void *rdata, u16 rdata_size, const ptr_vector *zsks, s32 now, s32 regeneration, s32 *key_indexp);

typedef struct rrsig_context_s rrsig_context_s;

#define RRSIGCTX_TAG 0x5854434749535252

struct rrsig_context_s
{
    ENGINE *engine;

    dnssec_key_sll *key_sll;

    /*
     * Current rrsig_sll (ZALLOC)
     */

    zdb_packed_ttlrdata *rrsig_sll;

    /*
     * New rrsig_ssl (MALLOC)
     */

    zdb_packed_ttlrdata *added_rrsig_sll;

    /*
     * Expired/invalid rrsig_ssl (MALLOC)
     */

    zdb_packed_ttlrdata *removed_rrsig_sll;
    
    const zdb_packed_ttlrdata *canonised_rrset;

    /* Used for RR canonization */
    ptr_vector rrs;

    u8 *origin;	   /* Origin of the zone.  The rrsig has to match
                    * this.
                    */
    
    smp_int *loose_quota;       // each signature will decrease this by 1
                                // since signatures are made by label, this
                                // is a best effort deal and this value will
                                // most likely drop below zero
    /**/

    u32 rr_dnsname_len;

    u32 origin_len;		/* dnsname_len(origin) */

    u32 original_ttl;
    
    u32 min_ttl;

    /**/

    u32 valid_from;	    /* epoch */

    /**/

    u32 sig_validity_regeneration_seconds;
    u32 sig_validity_interval_seconds;
    u32 sig_jitter_seconds;
    u32 sig_invalid_first;
    u32 sig_pre_validate_seconds;   // the amounts of seconds before "now" the signature will be made valid (1h)

    /**/

    u32 expired_signatures;
    u32 soon_expired_signatures;

    /**/

    u32 wrong_signatures;
    u32 good_signatures;

    /**/

    u32 rrsig_header_length;
    u32 record_header_label_type_class_ttl_length;

    /**/

    u32 canonized_rr_type_offset;

    u16 zclass;
    u8  label_depth;
    u8  flags;
    u8  nsec_flags;
    bool must_verify_signatures;    // once the signatures are in, there is no point doing it again
                                    // if we do them, they are right
                                    // if the master do them, he is right
                                    // the only time they should be verified is at load time
    
    bool signatures_are_invalid;    // signatures verification will immediately see them as wrong.
                                    // must_verify_signatures must be set to TRUE for this to be used. 
    bool rr_dnsname_processing_apex;
    /**/

    /*
     * Owner of the RR
     *
     * STACK!
     */

    dnsname_stack rr_dnsname;

    /*
     * Will contain the label + type + class + ttl
     * Common for all the records of the same label/type
     * The type will be edited in order to avoid computing it for
     * other records of the same label
     *
     * Candidate for the context
     */

    u8 record_header_label_type_class_ttl[MAX_DOMAIN_LENGTH + 1 + 2 + 2];

    /*
     * Will contain the type + alg + labels + orgttl + from + to + tag + name
     * Common for all the records of the same label
     * The type will be edited in order to avoid computing it for
     * other records of the same label
     *
     * Candidate for the context
     */

    u8 rrsig_header[2+1+1+4+4+4+2+MAX_DOMAIN_LENGTH];
};

#define ZDB_RRSIGUPQ_TAG                0x5150554749535252	/* RRSIGUPQ */

struct rrsig_update_item_s
{
    /// The zone being updated

    zdb_zone* zone;

    /// The label being processed

    zdb_rr_label* label;

    /// An rrset of records (mallocated) to add in the label

    zdb_packed_ttlrdata* added_rrsig_sll;

    /// An rrset of records (mallocated) to remove (and free) from the label

    zdb_packed_ttlrdata* removed_rrsig_sll;

    // The fqdn of the label 
    
    dnsname_stack path;
};

typedef struct rrsig_update_item_s rrsig_update_item_s;

static inline rrsig_update_item_s* rrsig_update_item_alloc()
{
    rrsig_update_item_s *ret;
    ZALLOC_OBJECT_OR_DIE( ret, rrsig_update_item_s, ZDB_RRSIGUPQ_TAG);
    return ret;
}

static inline void rrsig_update_item_free(rrsig_update_item_s *rui)
{
    ZFREE_OBJECT(rui);
}

#if ZDB_HAS_NSEC3_SUPPORT

struct nsec3_rrsig_update_item_s
{
    zdb_zone* zone;
    nsec3_zone_item* item;
    nsec3_zone_item* next;

    /*
     * New rrsig (MALLOC)
     */

    zdb_packed_ttlrdata* added_rrsig_sll;

    /*
     * Expired/invalid rrsig (MALLOC)
     */

    zdb_packed_ttlrdata* removed_rrsig_sll;
};

typedef struct nsec3_rrsig_update_item_s nsec3_rrsig_update_item_s;

#endif

/**
 * 
 * @param context the signature context to be initialised
 * @param zone the zone that will be signed
 * @param engine_name the engine name (this parameter will be removed soon for a global setup)
 * @param sign_from the time to sign from
 * @param quota for multi-threaded operation, the amount of signature to target (this is not meant to be accurate)
 * 
 * @return an error code if the initialisation failed
 */

ya_result rrsig_context_initialize(rrsig_context_s *context, const zdb_zone *zone, const char *engine_name, u32 sign_from, smp_int *quota);

void rrsig_context_destroy(rrsig_context_s *context);

static inline void rrsig_context_update_quota(rrsig_context_s *context, s32 sig_count)
{
    if((sig_count > 0) && (context->loose_quota != NULL))
    {
        smp_int_sub(context->loose_quota, sig_count);
    }
}

static inline s32 rrsig_context_get_quota(rrsig_context_s *context)
{
    if(context->loose_quota != NULL)
    {
        s32 quota = smp_int_get(context->loose_quota);
        return quota;
    }
    else
    {
        return MAX_S32;
    }
}

/**
 * Updates the current algorithm and tag of a context using the given key
 * Meant to modify the current pre-computed header of the signature
 * 
 * @param context
 * @param key
 */

void rrsig_context_set_current_key(rrsig_context_s *context, const dnssec_key* key);

/*
 * Adds/Removes a label in the path in order to process it
 */

void rrsig_context_push_name_rrsigsll(rrsig_context_s *context, const u8 *name, zdb_packed_ttlrdata* rrsig_sll);

/* Calls rrsig_update_context_push_name_rrsigsll using the label's fields */
void rrsig_context_push_label(rrsig_context_s *context, zdb_rr_label* label);
void rrsig_context_pop_label(rrsig_context_s *context);

/**
 * Adds the signature to the "to-be-deleted" set of the context.
 * 
 * @param context
 * @param rrsig
 */

void rrsig_context_append_delete_signature(rrsig_context_s *context, zdb_packed_ttlrdata *rrsig);

/**
 * Compute (the need for) updates by a DNSKEY over an RR set of a given type.
 * Updates timings of resignature in the context.
 * 
 * If a public key is given instead of a private key, do_update is assumed FALSE
 * 
 * @param context the signature context
 * @param key the signing key (can be public only)
 * @param rr_sll the rrset records
 * @param type the rrset type
 * @param do_update if TRUE, generated and pushes updates in the context, else only update timings
 * 
 * @return the number of signatures computed
 */

ya_result rrsig_update_rrset_with_key(rrsig_context_s *context, const zdb_packed_ttlrdata *rr_sll, u16 type, const dnssec_key* key, bool do_update);

/**
 * Computes the updates of an rrset of a given type (cannot be TYPE_ANY, obviously)
 * Changes are stored into the context and still needs to be committed.
 * 
 * @param context the signature context
 * @param records_sll the rrset records
 * @param rrset_type the rrset type
 * @param delegation the signature is on a delegation (result of ZDB_LABEL_ATDELEGATION(label))
 * 
 * @return an error code or the number of signatures that have been made
 */

ya_result rrsig_update_rrset(rrsig_context_s *context, const zdb_packed_ttlrdata *records_sll, u16 rrset_type, bool delegation);

/*
 * Takes the result of an update and commits it to the label
 */

void rrsig_update_commit(zdb_packed_ttlrdata* removed_rrsig_sll, zdb_packed_ttlrdata* added_rrsig_sll, zdb_rr_label* label, zdb_zone* zone, dnsname_stack* name);

/**
 * 
 * Returns the first RRSIG record that applies to the give type.
 * 
 * @param label        the label where to do the search
 * @param covered_type the type covered by the RRSIG
 * 
 * @return the first RRSIG covering the type or NULL
 */

zdb_packed_ttlrdata* rrsig_find_first(const zdb_rr_label* label, u16 covered_type);

/**
 * 
 * Returns the next RRSIG record that applies to the give type.
 * 
 * @param rrsig        the previous RRSIG covering the type
 * @param covered_type the type covered by the RRSIG
 * 
 * @return  covered_type the next RRSIG covering the type or NULL
 */
 
zdb_packed_ttlrdata* rrsig_find_next(const zdb_packed_ttlrdata* rrsig, u16 covered_type);


/**
 * Deletes all RRSIG covering the given type.
 */

void  rrsig_delete_covering(const zdb_rr_label* label, u16 type);

/**
 * 
 * Removes all the RRSIG covering the type
 * 
 * @param dname         the fqdn of the label
 * @param label         the label
 * @param covered_type  the type covered by the RRSIG
 */

void rrsig_delete(const zdb_zone *zone, const u8 *dname, zdb_rr_label* label, u16 covered_type);

void rrsig_delete_by_tag(const zdb_zone *zone, u16 tag);

/**
 * 
 * Signs an RRSET using a context.  This is done single-threaded.
 * 
 * @param context
 * @param fqdn
 * @param rtype
 * @param rrset
 * @return 
 */

ya_result rrsig_generate_signatures(rrsig_context_s *context, const u8 *fqdn, u16 rtype, const zdb_packed_ttlrdata *rrset, zdb_packed_ttlrdata **out_rrsig_sll);

/**
 * 
 * Does all the steps required to update an rrset in a zone.
 * The zone is expected to be suitably locked.
 * 
 * @param zone
 * @param fqdn
 * @param label
 * @param rtype
 * @return 
 */

ya_result rrsig_rrset_update_helper(zdb_zone *zone, const u8 *fqdn, zdb_rr_label *label, u16 rtype);

bool rrsig_should_label_be_signed(zdb_zone *zone, const u8 *fqdn, zdb_rr_label *rr_label);

#ifdef	__cplusplus
}
#endif

#endif	/* _RRSIGN_H */
/** @} */

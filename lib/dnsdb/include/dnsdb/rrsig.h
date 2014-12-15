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
 *
 *----------------------------------------------------------------------------*/
#ifndef _RRSIG_H
#define	_RRSIG_H

#include <dnscore/threaded_queue.h>
#include <dnscore/ptr_vector.h>

#include <dnsdb/zdb_types.h>
#include <dnsdb/dnssec_task.h>
#include <dnsdb/rr_canonize.h>

#if ZDB_HAS_NSEC3_SUPPORT != 0

#include <dnsdb/nsec3.h>

#endif

#define RRSIG_TTLRDATA_TAG	0x52544749535252    /* RRSIGTR */
#define DNSSEC_KEY_SLL_TAG	0x59454b43455344    /* DSECKEY */

#define DNSSEC_DEBUGLEVEL       0
#define DNSSEC_DUMPSIGNCOUNT    0

#ifndef DEBUG
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

#define RRSIG_TYPE_COVERED(x__)	    (GET_U16_AT((x__)->rdata_start[0]))       /** @todo : NATIVETYPE */
#define RRSIG_ALGORITHM(x__)	    ((x__)->rdata_start[2])
#define RRSIG_LABELS(x__)           ((x__)->rdata_start[3])
#define RRSIG_ORIGINAL_TTL(x__)	    (ntohl(GET_U32_AT((x__)->rdata_start[4])))
#define RRSIG_VALID_UNTIL(x__)	    (ntohl(GET_U32_AT((x__)->rdata_start[8])))
#define RRSIG_VALID_SINCE(x__)	    (ntohl(GET_U32_AT((x__)->rdata_start[12])))
#define RRSIG_KEY_TAG(x__)          (ntohs(GET_U16_AT((x__)->rdata_start[16]))) /** @todo : NATIVETAG (LOOK FOR ALL OF THEM) */
#define RRSIG_KEY_NATIVETAG(x__)    (GET_U16_AT((x__)->rdata_start[16]))
#define RRSIG_SIGNER_NAME(x__)	    (&(x__)->rdata_start[18])

#define RRSIG_RDATA_TO_TYPE_COVERED(x__) GET_U16_AT(x__)

#define RRSIG_CONTEXT_NSEC          1
#define RRSIG_CONTEXT_NSEC3         2
#define RRSIG_CONTEXT_NSEC3_OPTOUT  3

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct rrsig_context_s rrsig_context_s;


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
    
    zdb_packed_ttlrdata *canonised_rrset;
    
    dnssec_task_s *task;

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
    bool do_verify_signatures;  // once the signatures are in, there is no point doing it again
                                // if we do them, they are right
                                // if the master do them, he is right
                                // the only time they should be verified is at load time
    /**/

    /*
     * Owner of the RR
     *
     * STACK!
     */

    dnsname_stack rr_dnsname;

    bool rr_dnsname_processing_apex;

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

#if ZDB_HAS_NSEC3_SUPPORT != 0

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

void rrsig_context_set_key(rrsig_context_s *context, dnssec_key* key);

/*
 * Adds/Removes a label in the path in order to process it
 */

void rrsig_context_push_name_rrsigsll(rrsig_context_s *context, u8* name, zdb_packed_ttlrdata* rrsig_sll);

/* Calls rrsig_update_context_push_name_rrsigsll using the label's fields */
void rrsig_context_push_label(rrsig_context_s *context, zdb_rr_label* label);
void rrsig_context_pop_label(rrsig_context_s *context);

/** @todo: check is it a dup of rrsig_update_records ? */
ya_result rrsig_update_label_rrset(rrsig_context_s *context, zdb_rr_label* label, u16 type);

ya_result rrsig_update_records(rrsig_context_s *context, dnssec_key* key, zdb_packed_ttlrdata* rr_sll, u16 type, bool do_update);
ya_result rrsig_update_label(rrsig_context_s *context, zdb_rr_label* label);

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
 * 
 * Removes all the RRSIG covering the type
 * 
 * @param dname         the fqdn of the label
 * @param label         the label
 * @param covered_type  the type covered by the RRSIG
 */

void rrsig_delete(const u8 *dname, zdb_rr_label* label, u16 covered_type);

#ifdef	__cplusplus
}
#endif

#endif	/* _RRSIGN_H */
/** @} */

/*----------------------------------------------------------------------------*/


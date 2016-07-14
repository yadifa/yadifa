/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2016, EURid. All rights reserved.
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
 *
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnsdb/zdb_types.h>
#include <dnsdb/nsec3_types.h>
#include <dnscore/ptr_set.h>

#ifdef	__cplusplus
extern "C"
{
#endif


/*
 * These functions are used by the ICMTL.
 * They are all removing functions.
 * The typical requirement of an ICMTL is : no ripple-effect.
 *
 * ie: Removing an item will not void it's predecessor's signature because if it
 *     that signature was to be voided, the ICMTL should have something to say
 *     about it.
 *
 */

/**
 * Returns TRUE if the rdata is a match for an NSEC3PARAM record in the collection.
 * Meant to be used with the NSEC3 chains.
 * 
 * @param collection
 * @param nsec3param_rdata
 * @return 
 */    

bool nsec3_has_nsec3param(zdb_rr_collection *collection, const u8 *nsec3param_rdata);
    
/**
 * Removes the matching NSEC3PARAMDEL entry from the collection
 * 
 * @param collection the rrset collection
 * @param nsec3param_rdata the rdata to match
 * 
 * @return TRUE if the record was found and removed, FALSE otherwise
 */
    
bool nsec3_remove_nsec3paramdel(zdb_rr_collection *collection, const u8 *nsec3param_rdata);

/**
 * Finds the nsec3param's alter-ego and removes all the nsec3 records associated to it.
 * (icmtl)
 * 
 * @param zone
 * @param nsec3
 * 
 * 1 use (zdb_zone_update_ixfr)
 */

void nsec3_remove_nsec3param_by_record(zdb_zone* zone, zdb_packed_ttlrdata* nsec3param);

/**
 * Remove an NSEC3 without touching any of its siblings (icmtl)
 * 
 * @param zone
 * @param nsec3
 * 
 * 1 use (zdb_zone_update_ixfr)
 */

void nsec3_remove_nsec3(zdb_zone* zone, zdb_packed_ttlrdata* nsec3);

/**
 * 
 * @param zone
 * @param nsec3_label
 * @param nsec3_rdata
 * @param nsec3_rdata_size
 * 
 * 1 use (nsec3_icmtl_replay_execute)
 */

void nsec3_remove_nsec3_by_name(zdb_zone* zone, const u8 *nsec3_label, const u8 *nsec3_rdata, u16 nsec3_rdata_size); // the size here is needed for debugging

/**
 * 
 * @param zone
 * @param nsec3_digest
 * @param nsec3_rdata
 * @param nsec3_rdata_size
 * 
 * 1 use (nsec3_icmtl_replay_execute)
 */

void nsec3_remove_nsec3_by_digest(zdb_zone* zone, const u8 *nsec3_digest, const u8* nsec3_rdata, u16 nsec3_rdata_size);

#if OBSOLETE

/**
 * 
 * @param zone
 * @param nsec3_label
 * @param nsec3_rdata
 * @param nsec3_rdata_size
 * @return 
 * 
 * not used anymore ? (commented in zdb_icmtl_replay)
 */

nsec3_zone_item *nsec3_get_nsec3_by_name(zdb_zone* zone, const u8 *nsec3_label, const u8* nsec3_rdata, u16 nsec3_rdata_size);
#endif

/**
 * Remove the RRSIG of an NSEC3 (icmtl)
 * 
 * @param zone
 * @param rrsig
 * 
 * 1 use (zdb_zone_update_ixfr)
 */

void nsec3_remove_rrsig(zdb_zone* zone, zdb_packed_ttlrdata* rrsig);

/**
 * 
 * @param zone
 * @param nsec3_label
 * @param nsec3_rdata
 * @param nsec3_rdata_size
 * 
 * 1 use (nsec3_icmtl_replay_execute)
 */

void nsec3_add_nsec3_by_name(zdb_zone* zone, const u8 *nsec3_label, const u8* nsec3_rdata, u16 nsec3_rdata_size);

struct nsec3_icmtl_replay
{
    // keeps track of the NSEC3 status
    ptr_set nsec3_del;
    ptr_set nsec3_add;
    ptr_set nsec3rrsig_del;
    ptr_set nsec3rrsig_add;
    ptr_set nsec3_labels;
    ptr_set nsec3param_del;
    ptr_set nsec3param_add;
    
    // keeps track of the currently-building NSEC3 status
    ptr_set nsec3paramadd_add;  // future NSEC3PARAM
    ptr_set nsec3add_add;       // NSEC3 records for the future NSEC3PARAMs
    ptr_set nsec3add_del;       // NSEC3 records marked for removal but not part of an NSEC3PARAM nor an NSEC3PARAMADD
                                // (meaning we are destroying them)
    zdb_zone *zone;
    bool optout;
};

typedef struct nsec3_icmtl_replay nsec3_icmtl_replay;

/**
 * Initialises the replay structure
 * 
 * @param replay
 * @param zone
 */

void nsec3_icmtl_replay_init(nsec3_icmtl_replay *replay, zdb_zone *zone);

void nsec3_icmtl_replay_destroy(nsec3_icmtl_replay *replay);

/**
 * Appends a NSEC3 del to the replay structure
 * 
 * @param replay
 * @param fqdn
 * @param ttlrdata
 */
void nsec3_icmtl_replay_nsec3_del(nsec3_icmtl_replay *replay, const u8* fqdn, const zdb_ttlrdata *ttlrdata);

/**
 * Appends a NSEC3 add to the replay structure
 *
 * @param replay
 * @param fqdn
 * @param ttlrdata
 */
void nsec3_icmtl_replay_nsec3_add(nsec3_icmtl_replay *replay, const u8* fqdn, const zdb_ttlrdata *ttlrdata);

/**
 * Appends the RRSIG of an NSEC3 del to the replay structure
 * 
 * @param replay
 * @param fqdn
 * @param ttlrdata
 */
void nsec3_icmtl_replay_nsec3_rrsig_del(nsec3_icmtl_replay *replay, const u8* fqdn, const zdb_ttlrdata *ttlrdata);

/**
 * Appends the RRSIG of an NSEC3 add to the replay structure
 *
 * @param replay
 * @param fqdn
 * @param ttlrdata
 */
void nsec3_icmtl_replay_nsec3_rrsig_add(nsec3_icmtl_replay *replay, const u8* fqdn, zdb_packed_ttlrdata *packed_ttlrdata);


/**
 * Appends a label add to the replay structure
 * @param replay
 * @param fqdn
 * @param labels
 * @param label_top
 */
void nsec3_icmtl_replay_label_add(nsec3_icmtl_replay *replay, const u8 *fqdn, dnslabel_vector_reference labels, s32 label_top);

void nsec3_icmtl_replay_nsec3param_del(nsec3_icmtl_replay *replay, const zdb_ttlrdata *ttlrdata);
void nsec3_icmtl_replay_nsec3param_add(nsec3_icmtl_replay *replay, const zdb_ttlrdata *ttlrdata);

void nsec3_icmtl_replay_nsec3paramadd_del(nsec3_icmtl_replay *replay, const zdb_ttlrdata *ttlrdata);
void nsec3_icmtl_replay_nsec3paramadd_add(nsec3_icmtl_replay *replay, const zdb_ttlrdata *ttlrdata);


/**
 * Plays the replay structure, frees its content
 *
 * @param replay
 */
ya_result nsec3_icmtl_replay_execute(nsec3_icmtl_replay *replay);

#ifdef	__cplusplus
}
#endif

/** @} */

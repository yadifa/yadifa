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
 *
 *----------------------------------------------------------------------------*/
#ifndef _NSEC3_ICMTL_H
#define	_NSEC3_ICMTL_H

#include <dnsdb/zdb_types.h>
#include <dnsdb/nsec3_types.h>
#include <dnscore/treeset.h>

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

/*
 * Finds the nsec3param's alter-ego and removes all the nsec3 records associated to it.
 * (icmtl)
 *
 */

void nsec3_remove_nsec3param_by_record(zdb_zone* zone, zdb_packed_ttlrdata* nsec3param);
/*
 * Remove an NSEC3 without touching any of its siblings (icmtl)
 */

void nsec3_remove_nsec3(zdb_zone* zone, zdb_packed_ttlrdata* nsec3);

void nsec3_remove_nsec3_by_name(zdb_zone* zone, const u8 *nsec3_label, const u8 *nsec3_rdata);

void nsec3_remove_nsec3_by_digest(zdb_zone* zone, const u8 *nsec3_digest, const u8* nsec3_rdata);

nsec3_zone_item *nsec3_get_nsec3_by_name(zdb_zone* zone, const u8 *nsec3_label, const u8* nsec3_rdata);

/*
 * Remove the RRSIG of an NSEC3 (icmtl)
 */

void nsec3_remove_rrsig(zdb_zone* zone, zdb_packed_ttlrdata* rrsig);

void nsec3_add_nsec3_by_name(zdb_zone* zone, const u8 *nsec3_label, const u8* nsec3_rdata, u16 nsec3_rdata_size);

struct nsec3_icmtl_replay
{
    treeset_tree nsec3_del;
    treeset_tree nsec3_add;
    treeset_tree nsec3rrsig_del;
    treeset_tree nsec3rrsig_add;
    treeset_tree nsec3_labels;
    treeset_tree nsec3param_del;
    treeset_tree nsec3param_add;
    zdb_zone *zone;
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

/**
 * Plays the replay structure, frees its content
 *
 * @param replay
 */
ya_result nsec3_icmtl_replay_execute(nsec3_icmtl_replay *replay);

#ifdef	__cplusplus
}
#endif

#endif	/* _NSEC3_ICMTL_H */
/** @} */

/*----------------------------------------------------------------------------*/


/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup nsec NSEC functions
 * @ingroup dnsdbdnssec
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _NSEC_H
#define _NSEC_H

#include <dnsdb/zdb_types.h>

#if !ZDB_HAS_NSEC_SUPPORT
#error "Please do not include nsec.h if ZDB_HAS_NSEC_SUPPORT is 0"
#endif

#include <dnsdb/nsec_collection.h>
#include <dnscore/ptr_treemap.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define ZDB_NSECLABEL_TAG          0x4c42414c4345534e

#define NSEC_NEXT_DOMAIN_NAME(x__) (&(x__).rdata_start[0])

/**
 * Reverses the labels of the fqdn
 *
 * @param inverse_name
 * @param name
 * @return
 */

uint32_t nsec_inverse_name(uint8_t *inverse_name, const uint8_t *name);

/**
 *
 * Updates/Verifies the NSEC structures of the zone.
 *
 * @param zone the zone
 * @param read_only a secondary would not change the records.
 *
 * @return an error code (only fails if a secondary got a zone with errors)
 */

ya_result nsec_update_zone(zdb_zone_t *zone, bool read_only); /* read_only a.k.a secondary */

/**
 * Creates the NSEC node, creates or update the NSEC record
 *
 * @param zone
 * @param label
 * @param labels
 * @param labels_top
 */

void nsec_update_label(zdb_zone_t *zone, zdb_rr_label_t *label, dnslabel_vector_reference_t labels, int32_t labels_top);

/**
 * Verifies and, if needed, update the NSEC record.
 * There WILL be an NSEC record in the label at the end of the call.
 * It does NOT create the NSEC node (needs it created already).
 * It does NOT check for the relevancy of the NSEC record.
 *
 * @param label
 * @param node
 * @param next_node
 * @param name
 * @param ttl
 * @return
 */

bool nsec_update_label_record(zdb_zone_t *zone, zdb_rr_label_t *label, nsec_node_t *node, nsec_node_t *next_node, uint8_t *name);

/**
 * Creates the NSEC node, link it to the label.
 *
 * @param zone
 * @param label
 * @param labels
 * @param labels_top
 * @return
 */

nsec_node_t *nsec_update_label_node(zdb_zone_t *zone, zdb_rr_label_t *label, dnslabel_vector_reference_t labels, int32_t labels_top);

/**
 *
 * Unlink the NSEC node from the label, then deletes said node from the chain.
 *
 * @param zone
 * @param labels
 * @param labels_top
 * @return
 */

bool nsec_delete_label_node(zdb_zone_t *zone, dnslabel_vector_reference_t labels, int32_t labels_top);

/**
 *
 * Find the label that has got the right NSEC interval for "nextname"
 *
 * @param zone
 * @param name_vector
 * @param dname_out
 * @return
 */

zdb_rr_label_t *nsec_find_interval(const zdb_zone_t *zone, const dnsname_vector_t *name_vector, uint8_t **out_dname_p, uint8_t *restrict *pool);

zdb_rr_label_t *nsec_find_interval_and_name(const zdb_zone_t *zone, const dnsname_vector_t *name_vector, uint8_t *out_name);

void            nsec_name_error(const zdb_zone_t *zone, const dnsname_vector_t *qname_not_const, int32_t closest_index, uint8_t *restrict *pool, uint8_t **out_encloser_nsec_name_p, zdb_rr_label_t **out_encloser_nsec_label,
                                uint8_t **out_wild_encloser_nsec_name_p, zdb_rr_label_t **out_wildencloser_nsec_label);

void            nsec_destroy_zone(zdb_zone_t *zone);

void            nsec_logdump_tree(zdb_zone_t *zone);

#define NSEC_ZONE_DISABLED   0
#define NSEC_ZONE_ENABLED    1
#define NSEC_ZONE_GENERATING 2
#define NSEC_ZONE_REMOVING   4

#define TYPE_NSECCHAINSTATE  NU16(0xff01)

/**
 * marks the zone with private records
 *
 * @param zone
 * @param status
 *
 * @return an error code
 */

ya_result nsec_zone_set_status(zdb_zone_t *zone, uint8_t secondary_lock, uint8_t status);

/**
 * gets the zone status from private records
 *
 * @param zone
 * @param statusp
 *
 * @return an error code
 */

ya_result nsec_zone_get_status(zdb_zone_t *zone, uint8_t *statusp);

#define ZONE_NSEC_AVAILABLE(zone_) zdb_rr_label_flag_isset((zone_)->apex, ZDB_RR_LABEL_NSEC)

#ifdef __cplusplus
}
#endif

#endif /* _NSEC_H */
/** @} */

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
 * @defgroup nsec3 NSEC3 functions
 * @ingroup dnsdbdnssec
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _NSEC3_ITEM_H
#define _NSEC3_ITEM_H

#include <dnsdb/nsec3_types.h>
#include <dnscore/output_stream.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* NOTE: The first byte of the digest is its length */
nsec3_zone_item_t *nsec3_zone_item_find_encloser_start(const nsec3_zone_t *n3, const uint8_t *digest);

nsec3_zone_item_t *nsec3_zone_item_find(const nsec3_zone_t *n3, const uint8_t *digest);

/**
 *
 * @param n3
 * @param dnsnamedigest
 * @return
 */
nsec3_zone_item_t *nsec3_zone_item_find_by_name(const nsec3_zone_t *n3, const uint8_t *dnsnamedigest);

/**
 *
 * Also returns the nsec3 chain.
 *
 * @param zone
 * @param nsec3_label
 * @param out_n3
 * @return
 */
nsec3_zone_item_t *nsec3_zone_item_find_by_name_ext(const zdb_zone_t *zone, const uint8_t *nsec3_label, nsec3_zone_t **out_n3);

nsec3_zone_item_t *nsec3_zone_item_find_by_record(const zdb_zone_t *zone, const uint8_t *fqdn, uint16_t rdata_size, const uint8_t *rdata);

bool               nsec3_zone_item_equals_rdata(const nsec3_zone_t *n3, const nsec3_zone_item_t *item, uint16_t rdata_size, const uint8_t *rdata);

struct nsec3_zone_item_to_new_zdb_resource_record_data_parm
{
    const nsec3_zone_t      *n3;
    const nsec3_zone_item_t *item;
    const uint8_t           *origin;
    int32_t                  ttl;
};

typedef struct nsec3_zone_item_to_new_zdb_resource_record_data_parm nsec3_zone_item_to_new_zdb_resource_record_data_parm;

#define NSEC3_ZONE_ITEM_TO_NEW_zdb_resource_record_data_SIZE (ALIGN16(DOMAIN_LENGTH_MAX) + ALIGN16(NSEC3_ZONE_STRUCT_SIZE_FROM_SALT(255)))

void     nsec3_zone_item_to_new_zdb_resource_record_data(nsec3_zone_item_to_new_zdb_resource_record_data_parm *nsec3_parms, uint8_t **out_owner_p, /* dnsname */
                                                         zdb_resource_record_set_t *out_nsec3_rrset, zdb_resource_record_set_t *out_nsec3_rrsig_rrset,
                                                         uint8_t *restrict *pool);

uint32_t nsec3_zone_item_rdata_size(const nsec3_zone_t *n3, const nsec3_zone_item_t *item);

uint16_t nsec3_zone_item_to_rdata(const nsec3_zone_t *n3, const nsec3_zone_item_t *item, uint8_t *out_rdata, uint16_t out_rdata_size);

uint32_t nsec3_zone_item_get_label(const nsec3_zone_item_t *item, uint8_t *output_buffer, uint32_t buffer_size);

void     nsec3_zone_item_write_owner(output_stream_t *os, const nsec3_zone_item_t *item, const uint8_t *origin);

void     nsec3_zone_item_to_output_stream(output_stream_t *os, const nsec3_zone_t *n3, const nsec3_zone_item_t *item, const uint8_t *origin, uint32_t ttl);

void     nsec3_zone_item_rrsig_del(nsec3_zone_item_t *item, const zdb_ttlrdata *nsec3_rrsig);

void     nsec3_zone_item_rrsig_add(nsec3_zone_item_t *item, zdb_resource_record_data_t *nsec3_rrsig);

/*
 * Deletes ALL rrsig in the NSEC3 item
 */

void nsec3_zone_item_rrsig_delete_all(nsec3_zone_item_t *item);

/*
 * Empties an nsec3_zone_item
 *
 * Only frees the payload : owners, stars, bitmap, rrsig
 *
 * This should be followed by the destruction of the item itself
 */

void nsec3_zone_item_empties(nsec3_zone_item_t *item);

/*
 * Sets the type bitmap of the nsec3 item to match the one in the rdata
 * Does nothing if the bitmap is already ok
 *
 * NOTE: Remember that the item does not contain
 *
 *  _ hash_algorithm
 *  _ iterations
 *  _ salt_length
 *  _ salt
 *  _ hash_length
 *  _ next_hashed_owner_name
 */

ya_result                                    nsec3_zone_item_update_bitmap(nsec3_zone_item_t *nsec3_item, const uint8_t *rdata, uint16_t rdatasize);

typedef struct nsec3_item_format_writer_args nsec3_item_format_writer_args;

struct nsec3_item_format_writer_args
{
    const uint8_t           *origin;
    const nsec3_zone_t      *n3;
    const nsec3_zone_item_t *item;
    int32_t                  ttl;
};

/**
 * This helper macro declares a format_writer_t variable to be used with %w
 *
 * It has been written for debug builds.
 *
 * usage:
 * DECLARE_NSEC3_ITEM_FORMAT_WRITER(myvar, origin, n3, nsec3_item, 600);
 * format("%w", &myvar);
 *
 * The implementation is not very efficient.  It first writes the record as a wire, then prints the wire using the
 * "normal" call.
 *
 * The callback should NOT be registered as a format class.
 */

#define DECLARE_NSEC3_ITEM_FORMAT_WRITER(variable_name_, origin_, n3_, item_, ttl_)                                                                                                                                                            \
    const nsec3_item_format_writer_args variable_name_##args = {(origin_), (n3_), (item_), (ttl_)};                                                                                                                                            \
    const format_writer_t               variable_name_ = {nsec3_item_format_writer_callback, &variable_name_##args};

void nsec3_item_format_writer_callback(const void *, output_stream_t *, int32_t, char, bool, void *reserved_for_method_parameters);

#ifdef __cplusplus
}
#endif

#endif /* _NSEC3_ITEM_H */

/** @} */

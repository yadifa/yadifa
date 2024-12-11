/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#include "dnsdb/nsec3.h"
#include "dnsdb/zdb_query_to_wire_context.h"
#include "dnsdb/zdb_query_to_wire_append_nsec3.h"

#include <dnscore/logger.h>
#include <dnscore/base32hex.h>

extern logger_handle_t *g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

/**
 * @note Name Error Responses
 *
 * Retrieve NSEC3 name error records
 *
 * RFC 5155 7.2.2
 *
 * To prove the nonexistence of QNAME, a closest encloser proof and an
 * NSEC3 RR covering the (nonexistent) wildcard RR at the closest
 * encloser MUST be included in the response.  This collection of (up
 * to) three NSEC3 RRs proves both that QNAME does not exist and that a
 * wildcard that could have matched QNAME also does not exist.
 *
 * For example, if "gamma.example." is the closest provable encloser to
 * QNAME, then an NSEC3 RR covering "*.gamma.example." is included in
 * the authority section of the response.
 *
 * --------------------------------------------------------------------------------
 *
 * Z-Allocates and creates an NSEC3 record from an nsec3_zone_item
 *
 * This record is temporary.
 *
 * The function is supposed to be called by nsec3_name_error & nsec3_nodata_error
 * Said functions are called by the query function
 *
 * The record is supposed to be destroyed after usage (ie: at destroy query answer)
 *
 * @param zone
 * @param qname
 * @param apex_index
 * @param pool
 * @param out_next_closer_nsec3_owner_p
 * @param out_encloser_nsec3
 * @param out_encloser_nsec3_rrsig
 * @param out_closest_encloser_nsec3_owner_p
 * @param out_closest_encloser_nsec3
 * @param out_closest_encloser_nsec3_rrsig
 * @param out_wild_closest_encloser_nsec3_owner_p
 * @param out_wild_closest_encloser_nsec3
 * @param out_wild_closest_encloser_nsec3_rrsig
 */

uint16_t zdb_query_to_wire_append_nsec3_name_error(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const dnsname_vector_t *qname, int32_t apex_index)
{
    const nsec3_zone_item_t *encloser_nsec3;
    const nsec3_zone_item_t *closest_provable_encloser_nsec3;
    const nsec3_zone_item_t *wild_closest_provable_encloser_nsec3;

    // closest encloser proof

    nsec3_closest_encloser_proof(zone, qname, apex_index, &encloser_nsec3, &closest_provable_encloser_nsec3, &wild_closest_provable_encloser_nsec3);

    /* Append all items + sig to the authority
     * Don't do dups
     */

    nsec3_zone_t *n3 = zone->nsec.nsec3;

    int32_t       min_ttl;
    zdb_zone_getminttlsoa(zone, &min_ttl);

    nsec3_zone_item_to_new_zdb_resource_record_data_parm nsec3_parms = {n3, encloser_nsec3, zone->origin, NULL, min_ttl};

    uint16_t                                             count = 0;

    if(encloser_nsec3 != NULL)
    {
        count += zdb_query_to_wire_append_nsec3_record(context, &nsec3_parms);
    }

    if((closest_provable_encloser_nsec3 != encloser_nsec3) && (closest_provable_encloser_nsec3 != NULL))
    {
        nsec3_parms.item = closest_provable_encloser_nsec3;

        count += zdb_query_to_wire_append_nsec3_record(context, &nsec3_parms);
    }

    if((wild_closest_provable_encloser_nsec3 != encloser_nsec3) && (wild_closest_provable_encloser_nsec3 != closest_provable_encloser_nsec3) && (wild_closest_provable_encloser_nsec3 != NULL))
    {
        nsec3_parms.item = wild_closest_provable_encloser_nsec3;
        count += zdb_query_to_wire_append_nsec3_record(context, &nsec3_parms);
    }

    return count;
}

uint16_t zdb_query_to_wire_append_nsec3_record(zdb_query_to_wire_context_t *context, nsec3_zone_item_to_new_zdb_resource_record_data_parm *nsec3_parms)
{
    const nsec3_zone_t      *n3 = nsec3_parms->n3;
    uint32_t                 param_rdata_size = NSEC3PARAM_RDATA_SIZE_FROM_CHAIN(n3);
    const nsec3_zone_item_t *item = nsec3_parms->item;
    dns_packet_writer_t     *pw = &context->pw;
    int32_t                  ne_ttl = (int32_t)htonl(nsec3_parms->ttl);

    uint16_t                 last_good_offset = pw->packet_offset;
    uint16_t                 code = last_good_offset;

    code = htons(code | 0xc000);

    if(dns_packet_writer_get_remaining_capacity(pw) < (BASE32HEX_ENCODED_LEN(SHA_DIGEST_LENGTH) + 1))
    {
        zdb_query_to_wire_context_set_truncated(context);
        return 0;
    }

    dns_packet_writer_encode_base32hex_digest(&context->pw, &item->digest[1]);
    if(FAIL(dns_packet_writer_add_fqdn(pw, nsec3_parms->origin)))
    {
        pw->packet_offset = last_good_offset;
        zdb_query_to_wire_context_set_truncated(context);
        return 0;
    }

    uint32_t type_bit_maps_size = item->type_bit_maps_size;

    /* Whatever the editor says: rdata_size is used. */
    uint32_t rdata_size = param_rdata_size + 1 + item->digest[0] + type_bit_maps_size;

    if(dns_packet_writer_get_remaining_capacity(pw) < (int32_t)(10 + rdata_size))
    {
        pw->packet_offset = last_good_offset;
        zdb_query_to_wire_context_set_truncated(context);
        return 0;
    }

    dns_packet_writer_add_u16(pw, TYPE_NSEC3);
    dns_packet_writer_add_u16(pw, CLASS_IN);
    dns_packet_writer_add_u32(pw, ne_ttl);
    dns_packet_writer_add_u16(pw, htons(rdata_size));

    dns_packet_writer_add_u8(pw, n3->nsec3_rdata_prefix[0]);
    dns_packet_writer_add_u8(pw, item->flags & 1);
    dns_packet_writer_add_bytes(pw, &n3->nsec3_rdata_prefix[2], param_rdata_size - 2);
    // p[1] =  item->flags & 1; /* Opt-Out or Opt-In */

    const nsec3_zone_item_t *next = nsec3_node_mod_next(item);

    dns_packet_writer_add_bytes(pw, next->digest, SHA_DIGEST_LENGTH + 1);

    dns_packet_writer_add_bytes(pw, item->type_bit_maps, item->type_bit_maps_size);

    if(item->rrsig_rrset != NULL)
    {
#if USE_PACKET_RRSET_OPTIMISATION_
        dns_packet_writer_add_rrset(pw, fqdn, &item->rrsig_rrset);
#else
        last_good_offset = pw->packet_offset;

        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(item->rrsig_rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *rrsig_record = zdb_resource_record_set_const_iterator_next(&iter);

            if(dns_packet_writer_get_remaining_capacity(pw) < 12 + zdb_resource_record_data_rdata_size(rrsig_record))
            {
                pw->packet_offset = last_good_offset;
                zdb_query_to_wire_context_set_truncated(context);
                break;
            }

            dns_packet_writer_add_u16(pw, code);
            dns_packet_writer_add_u16(pw, TYPE_RRSIG);
            dns_packet_writer_add_u16(pw, CLASS_IN);
            dns_packet_writer_add_u32(pw, ne_ttl);
            dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rrsig_record)));
            dns_packet_writer_add_bytes(pw, zdb_resource_record_data_rdata_const(rrsig_record), zdb_resource_record_data_rdata_size(rrsig_record));

            last_good_offset = pw->packet_offset;
        }
#endif
        return zdb_resource_record_set_size(item->rrsig_rrset) + 1;
    }

    return 1;
}

/**
 * @note No Data Responses, QTYPE is not DS
 *
 * RFC 5155 7.2.3
 *
 * The server MUST include the NSEC3 RR that matches QNAME.  This NSEC3
 * RR MUST NOT have the bits corresponding to either the QTYPE or CNAME
 * set in its Type Bit Maps field.
 *
 */

uint16_t zdb_query_to_wire_append_nsec3_nodata_error(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const zdb_rr_label_t *owner, const dnsname_vector_t *qname, int32_t apex_index)
{
    const nsec3_zone_item_t *closest_provable_encloser_nsec3;

    nsec3_zone_t            *n3 = zone->nsec.nsec3;

    int32_t                  min_ttl;
    zdb_zone_getminttlsoa(zone, &min_ttl);

    uint16_t                                             count;

    nsec3_zone_item_to_new_zdb_resource_record_data_parm nsec3_parms = {n3, NULL, zone->origin, NULL, min_ttl};

    nsec3_closest_encloser_proof(zone, qname, apex_index, &nsec3_parms.item, &closest_provable_encloser_nsec3, NULL);

    count = 0;

    if(nsec3_parms.item != NULL)
    {
        bool     delegation = zdb_rr_label_flag_isset(owner, ZDB_RR_LABEL_UNDERDELEGATION);
        uint16_t rtype = context->record_type;
        bool     allowed_under_delegation = (rtype == TYPE_ANY) || (rtype == TYPE_A) || (rtype == TYPE_AAAA);

        if((zdb_zone_get_flags(zone) & ZDB_ZONE_HAS_OPTOUT_COVERAGE) || (!delegation || (delegation && allowed_under_delegation)))
        {
            count = zdb_query_to_wire_append_nsec3_record(context, &nsec3_parms);
        }
    }

    /* Append all items + sig to the authority
     * Don't do dups
     */

    if(closest_provable_encloser_nsec3 != NULL)
    {
        nsec3_parms.item = closest_provable_encloser_nsec3;

        count += zdb_query_to_wire_append_nsec3_record(context, &nsec3_parms);
    }
    else
    {
        log_err("%{dnsnamevector} has no NSEC3 owner, has DNSSEC mode been changed?", qname);
    }

    return count;
}

/**
 * @note No Data Responses, QTYPE is DS
 *
 * RFC 5155 7.2.4
 *
 * If there is an NSEC3 RR that matches QNAME, the server MUST return it
 * in the response.  The bits corresponding with DS and CNAME MUST NOT
 * be set in the Type Bit Maps field of this NSEC3 RR.
 *
 * If no NSEC3 RR matches QNAME, the server MUST return a closest
 * provable encloser proof for QNAME.  The NSEC3 RR that covers the
 * "next closer" name MUST have the Opt-Out bit set (note that this is
 * true by definition -- if the Opt-Out bit is not set, something has
 * gone wrong).
 *
 * If a server is authoritative for both sides of a zone cut at QNAME,
 * the server MUST return the proof from the parent side of the zone
 * cut.
 *
 */

uint16_t zdb_query_to_wire_append_nsec3_ds_nodata_error(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const zdb_rr_label_t *owner, const dnsname_vector_t *qname, int32_t apex_index)
{
    const nsec3_zone_item_t *owner_nsec3;

    nsec3_zone_t            *n3 = zone->nsec.nsec3;

    int32_t                  min_ttl;
    zdb_zone_getminttlsoa(zone, &min_ttl);

    uint16_t                                             count;

    nsec3_zone_item_to_new_zdb_resource_record_data_parm nsec3_parms = {n3, NULL, zone->origin, NULL, min_ttl};

    // If there is no NSEC3 that matches the qname ...

    if((owner->nsec.dnssec == NULL) || (nsec3_label_extension_self(owner->nsec.nsec3) == NULL)) // scan-build false positive: owner->nsec.dnssec == owner->nsec.nsec3 =>
                                                                                                // owner->nsec.nsec3 can't ben NULL for nsec3_label_extension_self
    {
        nsec3_closest_encloser_proof(zone, qname, apex_index, &owner_nsec3, &nsec3_parms.item, NULL);

        if(nsec3_parms.item != NULL)
        {
            count = zdb_query_to_wire_append_nsec3_record(context, &nsec3_parms);
            /*
            nsec3_zone_item_to_new_zdb_resource_record_data(
                &nsec3_parms,
                out_closest_encloser_nsec3_owner,
                out_closest_encloser_nsec3,
                out_closest_encloser_nsec3_rrsig);
            */
        }
        else
        {
            /*
             *out_closest_encloser_nsec3_owner = NULL;
             *out_closest_encloser_nsec3 = NULL;
             *out_closest_encloser_nsec3_rrsig = NULL;
             * */
#if DEBUG
            log_debug("nsec3_nodata_error: no closest encloser proof");
#endif
            count = 0;
        }
    }
    else // return the NSEC3 matching the qname
    {
        owner_nsec3 = nsec3_label_extension_self(owner->nsec.nsec3);
        /*
         *out_closest_encloser_nsec3 = NULL;
         *out_closest_encloser_nsec3_rrsig = NULL;
         */

        count = 0;
    }

    /* Append all items + sig to the authority
     * Don't do dups
     */

    if(owner_nsec3 != NULL)
    {
        nsec3_parms.item = owner_nsec3;

        count += zdb_query_to_wire_append_nsec3_record(context, &nsec3_parms);
        /*
        nsec3_zone_item_to_new_zdb_resource_record_data(
            &nsec3_parms,
            out_owner_nsec3_owner,
            out_owner_nsec3,
            out_owner_nsec3_rrsig);
        */
    }
    else
    {
        log_err("%{dnsnamevector} has no NSEC3 owner, has DNSSEC mode been changed?", qname);

        //
        /*
        ((zone->_flags & ZDB_ZONE_HAS_OPTOUT_COVERAGE) != 0)

        digestname(closest_provable_encloser, dnsname_len(closest_provable_encloser), salt, salt_len, iterations,
        &digest[1], false); closest_provable_encloser_nsec3 = nsec3_find(&n3->items, digest);
        */
    }

    return count;
}

/**
 * @brief Appends the NSEC3 - NODATA answer to the section
 *
 * @param zone the zone
 * @param rr_label the covered label
 * @param name the owner name
 * @param apex_index the index of the apex in the name
 * @param type the type of record required
 * @param zclass (if more than one class is supported in the database)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 2 uses
 */
uint16_t zdb_query_to_wire_append_nsec3_nodata(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const zdb_rr_label_t *rr_label, const dnsname_vector_t *name, int32_t apex_index, uint16_t rtype)
{
    int32_t min_ttl;
    zdb_zone_getminttlsoa(zone, &min_ttl);
    uint16_t count = 0;

    if(!IS_WILD_LABEL(rr_label->name))
    {
        if(rtype != TYPE_DS)
        {
            count = zdb_query_to_wire_append_nsec3_nodata_error(context, zone, rr_label, name, apex_index);
        }
        else // type is DS
        {
            if((rr_label->nsec.dnssec != NULL))
            {
                nsec3_zone_item_t *owner_nsec3 = nsec3_label_extension_self(rr_label->nsec.nsec3);
                nsec3_zone_t      *n3 = zone->nsec.nsec3;

                if(owner_nsec3 != NULL)
                {
                    nsec3_zone_item_to_new_zdb_resource_record_data_parm nsec3_parms = {n3, owner_nsec3, zone->origin, NULL, min_ttl};

                    count = zdb_query_to_wire_append_nsec3_record(context, &nsec3_parms);
                }
            }
            else
            {
                count = zdb_query_to_wire_append_nsec3_ds_nodata_error(context, zone, rr_label, name, apex_index);
            }
        }
    }
    else // wild nodata error
    {
        count = zdb_query_to_wire_append_wild_nsec3_nodata_error(context, zone, name, apex_index);
    }

    return count;
}

/**
 * @brief Appends the NSEC3 delegation answer to the section
 *
 * @param zone the zone
 * @param rr_label the covered label
 * @param name the owner name
 * @param apex_index the index of the apex in the name
 * @param zclass (if more than one class is supported in the database)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 3 uses
 */

uint16_t zdb_query_to_wire_append_nsec3_delegation(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const zdb_rr_label_find_ext_data *rr_label_info, const dnsname_vector_t *name, int32_t apex_index)
{
    zdb_rr_label_t *authority = rr_label_info->authority;

    int32_t         min_ttl;
    zdb_zone_getminttlsoa(zone, &min_ttl);

    if((authority->nsec.nsec3 != NULL) && (nsec3_label_extension_self(authority->nsec.nsec3) != NULL))
    {
        /* add it */

        nsec3_zone_item_to_new_zdb_resource_record_data_parm nsec3_parms = {zone->nsec.nsec3, nsec3_label_extension_self(authority->nsec.nsec3), zone->origin, NULL, min_ttl};

        return zdb_query_to_wire_append_nsec3_record(context, &nsec3_parms);
    }
    else
    {
        // add closest provable encloser proof

        return zdb_query_to_wire_append_nsec3_nodata(context, zone, authority, name, apex_index, TYPE_NONE);
    }
}

/**
 *
 * RFC 5155 7.2.5
 *
 * If there is a wildcard match for QNAME, but QTYPE is not present at
 * that name, the response MUST include a closest encloser proof for
 * QNAME and MUST include the NSEC3 RR that matches the wildcard.  This
 * combination proves both that QNAME itself does not exist and that a
 * wildcard that matches QNAME does exist.  Note that the closest
 * encloser to QNAME MUST be the immediate ancestor of the wildcard RR
 * (if this is not the case, then something has gone wrong).
 */

uint16_t zdb_query_to_wire_append_wild_nsec3_nodata_error(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const dnsname_vector_t *name, int32_t apex_index)
{
    int32_t min_ttl;
    zdb_zone_getminttlsoa(zone, &min_ttl);

    const nsec3_zone_item_t *wild_encloser_nsec3 = NULL;
    const nsec3_zone_item_t *closest_provable_encloser_nsec3 = NULL;
    const nsec3_zone_item_t *qname_encloser_nsec3 = NULL;

    nsec3_wild_closest_encloser_proof(zone, name, apex_index, &wild_encloser_nsec3, &closest_provable_encloser_nsec3, &qname_encloser_nsec3);

    uint16_t count = 0;

    if(wild_encloser_nsec3 != NULL)
    {
        nsec3_zone_item_to_new_zdb_resource_record_data_parm wild_encloser_nsec3_parms = {zone->nsec.nsec3, wild_encloser_nsec3, zone->origin, NULL, min_ttl};

        count += zdb_query_to_wire_append_nsec3_record(context, &wild_encloser_nsec3_parms);
    }

    if((closest_provable_encloser_nsec3 != wild_encloser_nsec3) && (closest_provable_encloser_nsec3 != NULL))
    {
        nsec3_zone_item_to_new_zdb_resource_record_data_parm closest_provable_encloser_nsec3_parms = {zone->nsec.nsec3, closest_provable_encloser_nsec3, zone->origin, NULL, min_ttl};

        count += zdb_query_to_wire_append_nsec3_record(context, &closest_provable_encloser_nsec3_parms);
    }

    if((qname_encloser_nsec3 != wild_encloser_nsec3) && (qname_encloser_nsec3 != closest_provable_encloser_nsec3) && (qname_encloser_nsec3 != NULL))
    {
        nsec3_zone_item_to_new_zdb_resource_record_data_parm qname_encloser_nsec3_parms = {zone->nsec.nsec3, qname_encloser_nsec3, zone->origin, NULL, min_ttl};

        count += zdb_query_to_wire_append_nsec3_record(context, &qname_encloser_nsec3_parms);
    }

    return count;
}

/**
 * @brief Appends the wildcard NSEC3 - DATA answer to the section
 *
 * RFC 5155 7.2.6
 *
 * If there is a wildcard match for QNAME and QTYPE, then, in addition
 * to the expanded wildcard RRSet returned in the answer section of the
 * response, proof that the wildcard match was valid must be returned.
 *
 * This proof is accomplished by proving that both QNAME does not exist
 * and that the closest encloser of the QNAME and the immediate ancestor
 * of the wildcard are the same (i.e., the correct wildcard matched).
 *
 * To this end, the NSEC3 RR that covers the "next closer" name of the
 * immediate ancestor of the wildcard MUST be returned.  It is not
 * necessary to return an NSEC3 RR that matches the closest encloser, as
 * the existence of this closest encloser is proven by the presence of
 * the expanded wildcard in the response.
 *
 * @param zone the zone
 * @param rr_label the covered label
 * @param name the owner name
 * @param apex_index the index of the apex in the name
 * @param zclass (if more than one class is supported in the database)
 * @param headp a pointer to the section list
 * @param pool the memory pool
 *
 * 2 uses
 */
uint16_t zdb_query_to_wire_append_wild_nsec3_data(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const dnsname_vector_t *name, int32_t apex_index)
{
    int32_t min_ttl;
    zdb_zone_getminttlsoa(zone, &min_ttl);

    const nsec3_zone_item_t *wild_encloser_nsec3 = NULL;
    const nsec3_zone_item_t *closest_provable_encloser_nsec3 = NULL;
    const nsec3_zone_item_t *qname_encloser_nsec3 = NULL;

    nsec3_wild_closest_encloser_proof(zone, name, apex_index, &wild_encloser_nsec3, &closest_provable_encloser_nsec3, &qname_encloser_nsec3);

    // nsec3_wild_next_closer_proof(zone, name, apex_index, &qname_encloser_nsec3);

    if(qname_encloser_nsec3 != NULL)
    {
        nsec3_zone_item_to_new_zdb_resource_record_data_parm qname_encloser_nsec3_parms = {zone->nsec.nsec3, qname_encloser_nsec3, zone->origin, NULL, min_ttl};

        return zdb_query_to_wire_append_nsec3_record(context, &qname_encloser_nsec3_parms);
    }
    else
    {
        return 0;
    }
}

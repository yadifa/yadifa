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

/**-----------------------------------------------------------------------------
 * @defgroup nsec NSEC functions
 * @ingroup dnsdbdnssec
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/dnscore.h>
#include <dnscore/dnsname.h>
#include <dnscore/logger.h>

#include "dnscore/ptr_treemap.h"

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_lock.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/rrsig.h"

#include "dnsdb/nsec.h"
#include "dnsdb/nsec_common.h"

#include "dnsdb/dynupdate_diff.h"
#include "dnsdb/dynupdate_message.h"
#include "dnsdb/zdb_zone_path_provider.h"

/*
   Note : (rfc 4034)

   Because every authoritative name in a zone must be part of the NSEC
   chain, NSEC RRs must be present for names containing a CNAME RR.
   This is a change to the traditional DNS specification [RFC1034],
   which stated that if a CNAME is present for a name, it is the only
   type allowed at that name.  An RRSIG (see Section 3) and NSEC MUST
   exist for the same name as does a CNAME resource record in a signed
   zone.

   ...

   A sender MUST NOT use DNS name compression on the Next Domain Name
   field when transmitting an NSEC RR.

   ...

   Owner names of RRsets for which the given zone is not authoritative
   (such as glue records) MUST NOT be listed in the Next Domain Name
   unless at least one authoritative RRset exists at the same owner
   name.


 */

/*
 * The NSEC processing must be done AFTER the RRSIG one
 *
 * Assuming there are no NSEC:
 *
 * _ Explore the zone
 * _ Canonize names
 * _ Build NSEC records
 * _ NSEC records have to be found quicky
 * _ The NSEC records are either in an array, either double-linked-listed
 *
 * Label => find the nsec record
 * Label => NSEC HASH => find the nsec record
 *
 * If there are NSEC records ...
 *
 * (dyn-)adding a record means adding/changing a/the NSEC record
 * (dyn-)removing a record means removing/changing a/the NSEC record
 *
 * What's the most efficient way to do all this ?
 *
 * First issue : canonization.
 * ---------------------------
 *
 * The ordering of the name is by label depth.
 * So the best way I can think of is to sort the actual labels in the database.
 * But this is not possible.  Records are ordered by an hash.  This is one of
 * most important parts of the architecture.
 *
 * Still I have to have order, so it means that for each label I have to have
 * a sorted (canization-wise) array for the sub-labels.
 *
 * This means a new pointer for each label in a NSEC(3) zone (ARGH)
 * (zdb_rr_label)
 *
 * For the eu-zone and its 3M names, we are speaking of an overhead of 24MB
 * (64 bits)
 *
 * Ok, I can still live with that ...
 *
 * Could I also make it so that this pointer only exists in nsec-zones ?
 * No.  Because it means that an operation on the zone would basically require
 * a dup and complex size checks.  I don't think it's reasonable.
 *
 *
 * The NSEC record is stored with other records.
 * The NSEC3 is not stored with other records.
 *
 */

/* NSEC:
 *
 * At zone apex ...
 *
 * For each label
 *     If there are sub-labels
 *	     Get the sub-labels.
 *	     Canonize them.
 *	     Chain them, keep the chain.
 *	     Create the NSEC record.
 *	     Insert/Update the NSEC record in the label.
 *	     Sign the NSEC record.
 *
 *           The chain contains a link to the NSEC and the RRSIG
 *
 *           Recurse on sub-sub-label
 *
 */

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle_t *g_dnssec_logger;

/*
 * New version of the NSEC handling
 *
 * Take all records
 * Prepare an NSEC record for them (using AVL)
 * For each entry in the AVL
 *  if the entry matches keep its signature and go to the next entry
 *  if the entry does not matches remove the old one and its signature and schedule for a new signature
 *
 */

static int nsec_update_zone_count = 0;

void       nsec_zone_label_detach(zdb_rr_label_t *rr_label)
{
    yassert((rr_label != NULL) && zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_NSEC));

    if((rr_label->nsec.dnssec != NULL) && (rr_label->nsec.nsec.node != NULL))
    {
        rr_label->nsec.nsec.node->label = NULL;
        rr_label->nsec.nsec.node = NULL;
    }
    else
    {
        yassert((rr_label->nsec.dnssec == NULL) && (rr_label->nsec.nsec.node == NULL));
    }

    zdb_rr_label_flag_and(rr_label, ~ZDB_RR_LABEL_NSEC);
}

ya_result nsec_update_zone(zdb_zone_t *zone, bool read_only) // read_only a.k.a secondary
{
    nsec_node_t    *nsec_tree = NULL;
    nsec_node_t    *first_node;
    nsec_node_t    *node;
    uint8_t        *prev_name;
    uint8_t        *name;
    zdb_soa_rdata_t soa;
    uint32_t        missing_nsec_records = 0;
    uint32_t        sibling_count = 0;
    uint32_t        nsec_under_delegation = 0;
    ya_result       return_code;
    uint8_t         name_buffer[2][DOMAIN_LENGTH_MAX];
    uint8_t         inverse_name[DOMAIN_LENGTH_MAX];
    uint8_t         tmp_bitmap[256 * (1 + 1 + 32)]; /* 'max window count' * 'max window length' */

    yassert(zdb_zone_islocked_weak(zone));

    if(FAIL(return_code = zdb_zone_getsoa(zone, &soa))) // zone is locked (weak)
    {
        return return_code;
    }

#if DEBUG
    memset(name_buffer, 0xde, sizeof(name_buffer));
#endif

    name = &name_buffer[0][0];
    prev_name = &name_buffer[1][0];

    zdb_zone_label_iterator_t label_iterator;
    zdb_zone_label_iterator_init(zone, &label_iterator);

    while(zdb_zone_label_iterator_hasnext(&label_iterator))
    {
        zdb_zone_label_iterator_nextname(&label_iterator, name);
        zdb_rr_label_t *label = zdb_zone_label_iterator_next(&label_iterator);

        if(zdb_rr_label_is_glue(label) || zdb_resource_record_sets_set_isempty(&label->resource_record_set))
        {
            // we are under a delegation or on an empty (non-terminal)
            // there should not be an NSEC record here

            if(zdb_resource_record_sets_has_type(&label->resource_record_set, TYPE_NSEC)) // zone is locked
            {
                nsec_under_delegation++;

                log_err("nsec: %{dnsname}: unexpected NSEC record under a delegation", name);
            }

            continue;
        }

        nsec_inverse_name(inverse_name, name);

        nsec_node_t *node = nsec_insert(&nsec_tree, inverse_name);
        node->label = label;
        label->nsec.nsec.node = node;
    }

    /*
     * Now that we have the NSEC chain
     */

    type_bit_maps_context_t tbmctx;

    nsec_iterator_t         nsec_iter;
    nsec_iterator_init(&nsec_tree, &nsec_iter);

    if(nsec_iterator_hasnext(&nsec_iter))
    {
        first_node = nsec_iterator_next_node(&nsec_iter);

        node = first_node;

        do
        {
            nsec_node_t *next_node;

            nsec_update_zone_count++;

            if(nsec_iterator_hasnext(&nsec_iter))
            {
                next_node = nsec_iterator_next_node(&nsec_iter);
            }
            else
            {
                next_node = first_node;
            }

            /*
             * Compute the type bitmap
             */

            zdb_rr_label_t *label = node->label;

            if(label == NULL)
            {
                node = next_node;
                continue;
            }

            uint32_t tbm_size = nsec_type_bit_maps_initialise_from_label(&tbmctx, label, true, true);
            type_bit_maps_write(&tbmctx, tmp_bitmap);

            uint8_t *tmp_name = prev_name;
            prev_name = name;
            name = tmp_name;

            nsec_inverse_name(name, next_node->inverse_relative_name);

            /*
             * Get the NSEC record
             */

            zdb_resource_record_data_t *nsec_record;
            int32_t                     nsec_ttl;

            if((nsec_record = zdb_resource_record_sets_find_nsec_and_ttl(&label->resource_record_set, &nsec_ttl)) != NULL) // zone is locked
            {
                /*
                 * has record -> compare the type and the nsec next
                 * if something does not match remove the record and its signature (no record)
                 *
                 */

                {
                    const uint8_t *rdata = zdb_resource_record_data_rdata(nsec_record);
                    const uint16_t size = zdb_resource_record_data_rdata_size(nsec_record);
                    const uint16_t dname_len = dnsname_len(rdata);

                    if(dname_len < size)
                    {
                        const uint8_t *type_bitmap = &rdata[dname_len];

                        /*
                         * check the type bitmap
                         */

                        if(memcmp(tmp_bitmap, type_bitmap, size - dname_len) == 0)
                        {
                            /*
                             * check the nsec next
                             */

                            if(dnsname_equals(rdata, name))
                            {
                                /* All good */

                                zdb_rr_label_flag_or(label, ZDB_RR_LABEL_NSEC);
                                zdb_rr_label_flag_and(label, ~(ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT));

                                node = next_node;
                                continue;
                            }
                            else // else the "next fqdn" do not match (this is irrecoverable for a secondary)
                            {
                                rdata_desc_t nsec_desc = {TYPE_NSEC, size, rdata};
                                log_debug(
                                    "nsec: %{dnsname}: src: %{dnsname} %{typerdatadesc} next field do not match "
                                    "expected value (%{dnsname})",
                                    zone->origin,
                                    prev_name,
                                    &nsec_desc,
                                    name);
                            }
                        }
                        else // else the type bitmap do not match (this is wrong)
                        {
                            rdata_desc_t nsec_desc = {TYPE_NSEC, size, rdata};
                            log_debug(
                                "nsec: %{dnsname}: src: %{dnsname} %{typerdatadesc} types map do not match expected "
                                "value",
                                zone->origin,
                                prev_name,
                                &nsec_desc);
                        }
                    }
                    else // else the "next fqdn" do not match (early test, this is irrecoverable for a secondary)
                    {
                        rdata_desc_t nsec_desc = {TYPE_NSEC, size, rdata};
                        log_debug(
                            "nsec: %{dnsname}: src: %{dnsname} %{typerdatadesc} next field do not match expected value "
                            "(%{dnsname})",
                            zone->origin,
                            prev_name,
                            &nsec_desc,
                            name);
                    }
                }

#if DEBUG
                /*
                else
                {
                    sibling_count++;

                    log_warn("nsec: %{dnsname}: %{dnsname}: multiple NSEC records where only one is expected",
                zone->origin, prev_name);
                }
                */

                // wrong NSEC RRSET

                /*

                zdb_resource_record_set_const_iterator iter;
                zdb_resource_record_set_const_iterator_init(nsec_record, &iter);
                while(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    const zdb_resource_record_data_t *nsec_rec = zdb_resource_record_set_const_iterator_next(&iter);

                    const zdb_ttlrdata unpacked_ttlrdata =
                    {
                        NULL,
                        nsec_ttl,
                        zdb_resource_record_data_rdata_size(nsec_rec),
                        0,
                        (zdb_resource_record_data_t*)zdb_resource_record_data_rdata_const(nsec_rec)
                    };

                    const rdata_desc_t nsec_desc = {TYPE_NSEC, unpacked_ttlrdata.rdata_size,
                unpacked_ttlrdata.rdata_pointer};

                    if(!read_only)
                    {
                        log_warn("nsec: %{dnsname}: del: %{dnsname} %{typerdatadesc}", zone->origin, prev_name,
                &nsec_desc);
                    }
                    else
                    {
                        log_err("nsec: %{dnsname}: got: %{dnsname} %{typerdatadesc}", zone->origin, prev_name,
                &nsec_desc);
                    }
                }
                */
#endif

                if(!read_only)
                {
                    zdb_resource_record_sets_delete_type(&label->resource_record_set, TYPE_NSEC);
                    rrsig_delete(zone, name, label, TYPE_NSEC);
                    nsec_record = NULL;
                }
            }

            /*
             * no record -> create one and schedule a signature (PRIMARY ONLY)
             */

            if(nsec_record == NULL)
            {
                missing_nsec_records++;

                zdb_resource_record_data_t *nsec_record;

                uint16_t                    dname_len = nsec_inverse_name(name, next_node->inverse_relative_name);
                uint16_t                    rdata_size = dname_len + tbm_size;

                nsec_record = zdb_resource_record_data_new_instance(rdata_size);
                // soa.minimum;    /* TTL / NTTL */
                uint8_t *rdata = zdb_resource_record_data_rdata(nsec_record);
                memcpy(rdata, name, dname_len);
                rdata += dname_len;
                memcpy(rdata, tmp_bitmap, tbm_size);

                rdata_desc_t nsec_desc = {TYPE_NSEC, zdb_resource_record_data_rdata_size(nsec_record), zdb_resource_record_data_rdata(nsec_record)};

                if(!read_only)
                {
                    zdb_resource_record_sets_insert_record(&label->resource_record_set, TYPE_NSEC, soa.minimum, nsec_record);

#if DEBUG
                    log_debug("nsec: %{dnsname}: add: %{dnsname} %{typerdatadesc}", zone->origin, prev_name, &nsec_desc);
#endif
                    /*
                     * Schedule a signature
                     */
                }
                else
                {
                    log_warn("nsec: %{dnsname}: need: %{dnsname} %{typerdatadesc}", zone->origin, prev_name, &nsec_desc);
                    zdb_resource_record_data_delete(nsec_record);
                }
            }

            zdb_rr_label_flag_or(label, ZDB_RR_LABEL_NSEC);
            zdb_rr_label_flag_and(label, ~(ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT));

            node = next_node;
        } while(node != first_node);
    }

    zone->nsec.nsec = nsec_tree;

    if(read_only)
    {
        if(missing_nsec_records + sibling_count + nsec_under_delegation)
        {
            log_err("nsec: missing records: %u, nsec with siblings: %u, nsec under delegation: %u", missing_nsec_records, sibling_count, nsec_under_delegation);

            // return DNSSEC_ERROR_NSEC_INVALIDZONESTATE;
        }
    }
    else
    {
        if(missing_nsec_records + sibling_count + nsec_under_delegation)
        {
            log_warn("nsec: missing records: %u, nsec with siblings: %u, nsec under delegation: %u", missing_nsec_records, sibling_count, nsec_under_delegation);
        }
    }

    return SUCCESS;
}

/**
 * Reverses the labels of the fqdn
 *
 * @param inverse_name
 * @param name
 * @return
 *
 * 3 www 5 eurid 2 eu 0
 *
 * 3 5 2 0
 */

uint32_t nsec_inverse_name(uint8_t *inverse_name, const uint8_t *name)
{
    dnslabel_vector_t labels;

    int32_t           vtop = dnsname_to_dnslabel_vector(name, labels);
    uint32_t          ret = dnslabel_stack_to_dnsname(labels, vtop, inverse_name);
    return ret;
}

/**
 * Creates the NSEC node, link it to the label.
 *
 * @param zone
 * @param label
 * @param labels
 * @param labels_top
 * @return
 */

nsec_node_t *nsec_update_label_node(zdb_zone_t *zone, zdb_rr_label_t *label, dnslabel_vector_reference_t labels, int32_t labels_top)
{
    uint8_t inverse_name[DOMAIN_LENGTH_MAX];

    dnslabel_stack_to_dnsname(labels, labels_top, inverse_name);

    nsec_node_t *node = nsec_insert(&zone->nsec.nsec, inverse_name);
    node->label = label;
    label->nsec.nsec.node = node;
    zdb_rr_label_flag_or(label, ZDB_RR_LABEL_NSEC);
    zdb_rr_label_flag_and(label, ~(ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT));

#if DEBUG
    memset(inverse_name, 0xff, sizeof(inverse_name));
    log_debug("nsec_update_label_node: %{dnsname}", node->inverse_relative_name);
#endif

    return node;
}

/**
 *
 * Unlink the NSEC node from the label, then deletes said node from the chain.
 *
 * @param zone
 * @param label
 * @param labels
 * @param labels_top
 * @return
 */

bool nsec_delete_label_node(zdb_zone_t *zone, dnslabel_vector_reference_t labels, int32_t labels_top)
{
    uint8_t inverse_name[DOMAIN_LENGTH_MAX];

    dnslabel_stack_to_dnsname(labels, labels_top, inverse_name);

    nsec_node_t *node = nsec_find(&zone->nsec.nsec, inverse_name);

    if(node != NULL)
    {
        if(node->label != NULL)
        {
            zdb_rr_label_flag_and(node->label, ~ZDB_RR_LABEL_NSEC);
            node->label->nsec.nsec.node = NULL;
            node->label = NULL;
        }

        nsec_delete(&zone->nsec.nsec, inverse_name);
#if DEBUG
        log_debug("nsec_delete_label_node: %{dnsname}", inverse_name);
#endif
        return true;
    }
    else
    {
#if DEBUG
        log_debug("nsec_delete_label_node: %{dnsname} has not been found", inverse_name);
#endif
        return false;
    }
}

#if 0
/**
 * Creates the NSEC node, creates or update the NSEC record
 * 
 * @param zone
 * @param label
 * @param labels
 * @param labels_top
 */

void
nsec_update_label(zdb_zone* zone, zdb_rr_label* label, dnslabel_vector_reference labels, int32_t labels_top)
{
    uint8_t name[DOMAIN_LENGTH_MAX];

    /* Create or get the node */

    nsec_node_t *node = nsec_update_label_node(zone, label, labels, labels_top);

    /* Get the next node */

    nsec_node_t *next_node = nsec_node_mod_next(node);

    dnslabel_vector_to_dnsname(labels, labels_top, name);

    nsec_update_label_record(zone, label, node, next_node, name);
}

#endif

void nsec_destroy_zone(zdb_zone_t *zone)
{
    if(!nsec_isempty(&zone->nsec.nsec))
    {
        nsec_iterator_t iter;
        nsec_iterator_init(&zone->nsec.nsec, &iter);

        while(nsec_iterator_hasnext(&iter))
        {
            nsec_node_t *node = nsec_iterator_next_node(&iter);
            if(node->label != NULL)
            {
                node->label->nsec.nsec.node = NULL;
                zdb_rr_label_flag_and(node->label, ~ZDB_RR_LABEL_NSEC);
            }
        }

        nsec_destroy(&zone->nsec.nsec);
    }
}

/**
 *
 * Find the label that has got the right NSEC interval for "nextname"
 *
 * @param zone
 * @param name_vector
 * @param dname_out
 * @return
 */

zdb_rr_label_t *nsec_find_interval(const zdb_zone_t *zone, const dnsname_vector_t *name_vector, uint8_t **out_dname_p, uint8_t *restrict *pool)
{
    uint8_t dname_inverted[DOMAIN_LENGTH_MAX];

    dnslabel_stack_to_dnsname(name_vector->labels, name_vector->size, dname_inverted);

    nsec_node_t *node = nsec_find_interval_start(&zone->nsec.nsec, dname_inverted);

    uint8_t     *out_dname = *pool;
    *out_dname_p = out_dname;
    uint32_t out_dname_len = nsec_inverse_name(out_dname, node->inverse_relative_name);
    *pool += ALIGN16(out_dname_len);

    return node->label;
}

zdb_rr_label_t *nsec_find_interval_and_name(const zdb_zone_t *zone, const dnsname_vector_t *name_vector, uint8_t *out_name)
{
    uint8_t dname_inverted[DOMAIN_LENGTH_MAX];

    dnslabel_stack_to_dnsname(name_vector->labels, name_vector->size, dname_inverted);

    nsec_node_t *node = nsec_find_interval_start(&zone->nsec.nsec, dname_inverted);
    /* uint32_t out_dname_len = */ nsec_inverse_name(out_name, node->inverse_relative_name);

    return node->label;
}

void nsec_name_error(const zdb_zone_t *zone, const dnsname_vector_t *name, int32_t closest_index, uint8_t *restrict *pool, uint8_t **out_encloser_nsec_name_p, zdb_rr_label_t **out_encloser_nsec_label,
                     uint8_t **out_wild_encloser_nsec_name_p, zdb_rr_label_t **out_wildencloser_nsec_label)
{
    uint32_t len;
    uint8_t  dname_inverted[DOMAIN_LENGTH_MAX + 2];

    dnslabel_stack_to_dnsname(name->labels, name->size, dname_inverted);

    nsec_node_t *node = nsec_find_interval_start(&zone->nsec.nsec, dname_inverted);

    uint8_t     *out_encloser_nsec_name = *pool;
    *out_encloser_nsec_name_p = out_encloser_nsec_name;
    len = nsec_inverse_name(out_encloser_nsec_name, node->inverse_relative_name);
    *pool += ALIGN16(len);

    dnslabel_stack_to_dnsname(&name->labels[closest_index], name->size - closest_index, dname_inverted);

    nsec_node_t *wild_node = nsec_find_interval_start(&zone->nsec.nsec, dname_inverted);

    if(wild_node != node)
    {
        uint8_t *out_wild_encloser_nsec_name = *pool;
        *out_wild_encloser_nsec_name_p = out_wild_encloser_nsec_name;
        len = nsec_inverse_name(out_wild_encloser_nsec_name, wild_node->inverse_relative_name);
        *pool += ALIGN16(len);
    }

    *out_encloser_nsec_label = node->label;
    *out_wildencloser_nsec_label = wild_node->label;
}

void nsec_logdump_tree(zdb_zone_t *zone)
{
    log_debug("dumping zone %{dnsname} nsec tree", zone->origin);

    nsec_iterator_t iter;
    nsec_iterator_init(&zone->nsec.nsec, &iter);
    while(nsec_iterator_hasnext(&iter))
    {
        nsec_node_t *node = nsec_iterator_next_node(&iter);

        log_debug("%{dnsname}", node->inverse_relative_name);
    }
    log_debug("done dumping zone %{dnsname} nsec tree", zone->origin);
}

#if HAS_PRIMARY_SUPPORT

/**
 * marks the zone with private records
 *
 * @param zone
 * @param status
 *
 * @return an error code
 */

ya_result nsec_zone_set_status(zdb_zone_t *zone, uint8_t secondary_lock, uint8_t status)
{
    dynupdate_message   dmsg;
    dns_packet_reader_t reader;
    dynupdate_message_init(&dmsg, zone->origin, CLASS_IN);

    uint8_t prev_status = 0;
    uint8_t nsecparamadd_rdata[1];

    nsecparamadd_rdata[0] = status;

    // look for the matching record
    if(nsec_zone_get_status(zone, &prev_status) == 1)
    {
        // if the record exists, remove it and add it
        dynupdate_message_del_record_set(&dmsg, zone->origin, TYPE_NSECCHAINSTATE);
    }
    dynupdate_message_add_record(&dmsg, zone->origin, TYPE_NSECCHAINSTATE, 0, 1, nsecparamadd_rdata);
    dynupdate_message_set_reader(&dmsg, &reader);
    uint16_t count = dynupdate_message_get_count(&dmsg);

    dns_packet_reader_skip(&reader, DNS_HEADER_LENGTH); // checked below
    dns_packet_reader_skip_fqdn(&reader);               // checked below
    dns_packet_reader_skip(&reader, 4);                 // checked below

    ya_result ret;

    if(!dns_packet_reader_eof(&reader))
    {
        ret = dynupdate_diff(zone, &reader, count, secondary_lock, DYNUPDATE_DIFF_RUN);

        if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
        {
            // trigger a background store of the zone

            zdb_zone_info_background_store_zone(zone->origin);
        }
    }
    else
    {
        ret = MAKE_RCODE_ERROR(RCODE_FORMERR);
    }

    dynupdate_message_finalize(&dmsg);

    return ret;
}

#endif

/**
 * gets the zone status from private records
 *
 * @param zone
 * @param statusp
 *
 * @return an error code
 */

ya_result nsec_zone_get_status(zdb_zone_t *zone, uint8_t *statusp)
{
    // get the TYPE_NSEC3PARAMADD record set
    // search for a record matching the chain

    zdb_resource_record_set_t *nsec_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_NSECCHAINSTATE); // zone is locked
    if(nsec_rrset != NULL)
    {
        if(zdb_resource_record_set_of_one(nsec_rrset))
        {
            *statusp = zdb_resource_record_data_rdata_const(nsec_rrset->_record)[0];
            return 1;
        }
    }

    return 0;
}

/** @} */

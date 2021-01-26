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

/** @defgroup nsec NSEC functions
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
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/dnscore.h>
#include <dnscore/dnsname.h>
#include <dnscore/logger.h>

#include "dnscore/ptr_set.h"

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb-zone-lock.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/rrsig.h"

#include "dnsdb/nsec.h"
#include "dnsdb/nsec_common.h"

#include "dnsdb/dynupdate-diff.h"
#include "dnsdb/dynupdate-message.h"
#include "dnsdb/zdb-zone-path-provider.h"

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
extern logger_handle *g_dnssec_logger;

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


void
nsec_zone_label_detach(zdb_rr_label *rr_label)
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

ya_result
nsec_update_zone(zdb_zone *zone, bool read_only) // read_only a.k.a slave
{
    nsec_node *nsec_tree = NULL;
    nsec_node *first_node;
    nsec_node *node;
    u8 *prev_name;
    u8 *name;
    soa_rdata soa;
    u32 missing_nsec_records = 0;
    u32 sibling_count = 0;
    u32 nsec_under_delegation = 0;
    ya_result return_code;
    u8 name_buffer[2][MAX_DOMAIN_LENGTH];
    u8 inverse_name[MAX_DOMAIN_LENGTH];
    u8 tmp_bitmap[256 * (1 + 1 + 32)]; /* 'max window count' * 'max window length' */

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
    
    zdb_zone_label_iterator label_iterator;
    zdb_zone_label_iterator_init(&label_iterator, zone);

    while(zdb_zone_label_iterator_hasnext(&label_iterator))
    {
        zdb_zone_label_iterator_nextname(&label_iterator, name);
        zdb_rr_label* label = zdb_zone_label_iterator_next(&label_iterator);

        if(zdb_rr_label_is_glue(label) || (label->resource_record_set == NULL))
        {
            // we are under a delegation or on an empty (non-terminal) 
            // there should not be an NSEC record here
            
            if(zdb_record_find(&label->resource_record_set, TYPE_NSEC) != NULL) // zone is locked
            {
                nsec_under_delegation++;
                
                log_err("nsec: %{dnsname}: unexpected NSEC record under a delegation", name);
            }
            
            continue;
        }

        nsec_inverse_name(inverse_name, name);

        nsec_node *node = nsec_insert(&nsec_tree, inverse_name);
        node->label = label;
        label->nsec.nsec.node = node;
    }

    /*
     * Now that we have the NSEC chain
     */

    type_bit_maps_context tbmctx;
    
    nsec_iterator nsec_iter;
    nsec_iterator_init(&nsec_tree, &nsec_iter);

    if(nsec_iterator_hasnext(&nsec_iter))
    {
        first_node = nsec_iterator_next_node(&nsec_iter);

        node = first_node;

        do
        {
            nsec_node *next_node;

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

            zdb_rr_label *label = node->label;
            
            if(label == NULL)
            {
                node = next_node;
                continue;
            }

            u32 tbm_size = nsec_type_bit_maps_initialise_from_label(&tbmctx, label, TRUE, TRUE);
            type_bit_maps_write(&tbmctx, tmp_bitmap);
            
            u8 *tmp_name = prev_name;
            prev_name = name;
            name = tmp_name;

            nsec_inverse_name(name, next_node->inverse_relative_name);

            /*
             * Get the NSEC record
             */

            zdb_packed_ttlrdata *nsec_record;

            if((nsec_record = zdb_record_find(&label->resource_record_set, TYPE_NSEC)) != NULL) // zone is locked
            {
                /*
                 * has record -> compare the type and the nsec next
                 * if something does not match remove the record and its signature (no record)
                 *
                 */

                if(nsec_record->next == NULL) // should only be one record => delete all if not the case (the rrsig is lost anyway)
                {
                    const u8 *rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec_record);
                    const u16 size = ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec_record);
                    const u16 dname_len = dnsname_len(rdata);

                    if(dname_len < size)
                    {
                        const u8 *type_bitmap = &rdata[dname_len];

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
                                zdb_rr_label_flag_and(label, ~(ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT));

                                node = next_node;
                                continue;
                            }
                            else // else the "next fqdn" do not match (this is irrecoverable for a slave)
                            {
                                rdata_desc nsec_desc = {TYPE_NSEC, size, rdata};
                                log_debug("nsec: %{dnsname}: src: %{dnsname} %{typerdatadesc} next field do not match expected value (%{dnsname})", zone->origin, prev_name, &nsec_desc, name);
                            }
                        }
                        else // else the type bitmap do not match (this is wrong)
                        {
                            rdata_desc nsec_desc = {TYPE_NSEC, size, rdata};
                            log_debug("nsec: %{dnsname}: src: %{dnsname} %{typerdatadesc} types map do not match expected value", zone->origin, prev_name, &nsec_desc);
                        }
                    }
                    else // else the "next fqdn" do not match (early test, this is irrecoverable for a slave)
                    {
                        rdata_desc nsec_desc = {TYPE_NSEC, size, rdata};
                        log_debug("nsec: %{dnsname}: src: %{dnsname} %{typerdatadesc} next field do not match expected value (%{dnsname})", zone->origin, prev_name, &nsec_desc, name);
                    }
                }
                else
                {
                    sibling_count++;
                    
                    log_warn("nsec: %{dnsname}: %{dnsname}: multiple NSEC records where only one is expected", zone->origin, prev_name);
                }
                
                // wrong NSEC RRSET
                
                zdb_packed_ttlrdata *nsec_rec = nsec_record;

                do
                {
                    zdb_ttlrdata unpacked_ttlrdata;

                    unpacked_ttlrdata.ttl = nsec_rec->ttl;
                    unpacked_ttlrdata.rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec_rec);
                    unpacked_ttlrdata.rdata_pointer = ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec_rec);

                    rdata_desc nsec_desc = {TYPE_NSEC, unpacked_ttlrdata.rdata_size, unpacked_ttlrdata.rdata_pointer};

                    if(!read_only)
                    {
                        log_warn("nsec: %{dnsname}: del: %{dnsname} %{typerdatadesc}", zone->origin, prev_name, &nsec_desc);
                    }
                    else
                    {
                        log_err("nsec: %{dnsname}: got: %{dnsname} %{typerdatadesc}", zone->origin, prev_name, &nsec_desc);
                    }

                    nsec_rec = nsec_rec->next;
                }
                while(nsec_rec != NULL);
                
                if(!read_only)
                {
                    zdb_record_delete(&label->resource_record_set, TYPE_NSEC);
                    rrsig_delete(zone, name, label, TYPE_NSEC);
                    nsec_record = NULL;
                }
            }

            /*
             * no record -> create one and schedule a signature (MASTER ONLY)
             */

            if(nsec_record == NULL)
            {
                missing_nsec_records++;
                
                zdb_packed_ttlrdata *nsec_record;

                u16 dname_len = nsec_inverse_name(name, next_node->inverse_relative_name);
                u16 rdata_size = dname_len + tbm_size;

                ZDB_RECORD_ZALLOC_EMPTY(nsec_record, soa.minimum, rdata_size);
                u8* rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec_record);
                memcpy(rdata, name, dname_len);
                rdata += dname_len;
                memcpy(rdata, tmp_bitmap, tbm_size);
                
                rdata_desc nsec_desc = {TYPE_NSEC, ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec_record), ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec_record)};
                
                if(!read_only)
                {                    
                    zdb_record_insert(&label->resource_record_set, TYPE_NSEC, nsec_record);

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
                    ZDB_RECORD_ZFREE(nsec_record);
                }
            }

            zdb_rr_label_flag_or(label, ZDB_RR_LABEL_NSEC);
            zdb_rr_label_flag_and(label, ~(ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT));

            node = next_node;
        }
        while(node != first_node);
    }

    zone->nsec.nsec = nsec_tree;
    
    if(read_only)
    {
        if(missing_nsec_records + sibling_count + nsec_under_delegation)
        {
            log_err("nsec: missing records: %u, nsec with siblings: %u, nsec under delegation: %u", missing_nsec_records, sibling_count, nsec_under_delegation);
            
            //return DNSSEC_ERROR_NSEC_INVALIDZONESTATE;
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

u32
nsec_inverse_name(u8 *inverse_name, const u8 *name)
{
    dnslabel_vector labels;

    s32 vtop = dnsname_to_dnslabel_vector(name, labels);
    u32 ret = dnslabel_stack_to_dnsname(labels, vtop, inverse_name);
    return ret;
}

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

bool
nsec_update_label_record(zdb_zone *zone, zdb_rr_label *label, nsec_node *item, nsec_node *next_item, u8 *name)
{
    yassert(zdb_zone_islocked(zone));
    
    type_bit_maps_context tbmctx;
    u8 tmp_bitmap[256 * (1 + 1 + 32)]; /* 'max window count' * 'max window length' */

    u32 tbm_size = nsec_type_bit_maps_initialise_from_label(&tbmctx, label, TRUE, TRUE);

    u32 ttl = zone->min_ttl;
    type_bit_maps_write(&tbmctx, tmp_bitmap);

    /*
     * Get the NSEC record
     */

    zdb_packed_ttlrdata *nsec_record;

    if((nsec_record = zdb_record_find(&label->resource_record_set, TYPE_NSEC)) != NULL) // zone is locked
    {
        /*
         * has record -> compare the type and the nsec next
         * if something does not match remove the record and its signature (no record)
         *
         */

        log_debug("nsec_update_label_record: [%{dnsname}] %{dnsname} (=> %{dnsname}) updating record.", name, item->inverse_relative_name, next_item->inverse_relative_name);

        /*
         * If there is more than one record, clean-up
         */


        if(nsec_record->next == NULL)
        {
            u8* rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec_record);
            u16 size = ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec_record);

            u16 dname_len = dnsname_len(rdata);

            if(dname_len < size)
            {
                u8* type_bitmap = &rdata[dname_len];

                /*
                 * check the type bitmap
                 */

                if(memcmp(tmp_bitmap, type_bitmap, size - dname_len) == 0)
                {
                    /*
                     * check the nsec next
                     */
                    
                    u8 tmp_name[MAX_DOMAIN_LENGTH];
                    nsec_inverse_name(tmp_name, next_item->inverse_relative_name);

                    if(dnsname_equals(rdata, tmp_name))
                    {
                        /* All good */

                        return FALSE;
                    }
                }
            }    
        }

        zdb_record_delete(&label->resource_record_set, TYPE_NSEC);

        rrsig_delete(zone, name, label, TYPE_NSEC);

        nsec_record = NULL;
    }

    /*
     * no record -> create one and schedule a signature
     */

    if(nsec_record == NULL)
    {
        zdb_packed_ttlrdata *nsec_record;
        u8 next_name[256];

        log_debug("nsec_update_label_record: [%{dnsname}] %{dnsname} (=> %{dnsname}) building new record.", name, item->inverse_relative_name, next_item->inverse_relative_name);

        u16 dname_len = nsec_inverse_name(next_name, next_item->inverse_relative_name);
        u16 rdata_size = dname_len + tbm_size;

        ZDB_RECORD_ZALLOC_EMPTY(nsec_record, ttl, rdata_size);

        u8* rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec_record);

        memcpy(rdata, next_name, dname_len);
        rdata += dname_len;

        memcpy(rdata, tmp_bitmap, tbm_size);

        zdb_record_insert(&label->resource_record_set, TYPE_NSEC, nsec_record);

        /*
         * Schedule a signature
         */
    }

    zdb_rr_label_flag_or(label, ZDB_RR_LABEL_NSEC);
    zdb_rr_label_flag_and(label, ~(ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT));

    return TRUE;
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

nsec_node *
nsec_update_label_node(zdb_zone* zone, zdb_rr_label* label, dnslabel_vector_reference labels, s32 labels_top)
{
    u8 inverse_name[MAX_DOMAIN_LENGTH];

    dnslabel_stack_to_dnsname(labels, labels_top, inverse_name);

    nsec_node *node = nsec_insert(&zone->nsec.nsec, inverse_name);
    node->label = label;
    label->nsec.nsec.node = node;
    zdb_rr_label_flag_or(label, ZDB_RR_LABEL_NSEC);
    zdb_rr_label_flag_and(label, ~(ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT));

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

bool
nsec_delete_label_node(zdb_zone *zone, dnslabel_vector_reference labels, s32 labels_top)
{
    u8 inverse_name[MAX_DOMAIN_LENGTH];

    dnslabel_stack_to_dnsname(labels, labels_top, inverse_name);

    nsec_node *node = nsec_find(&zone->nsec.nsec, inverse_name);
    
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
        return TRUE;
    }
    else
    {
#if DEBUG
        log_debug("nsec_delete_label_node: %{dnsname} has not been found", inverse_name);
#endif
        return FALSE;
    }
}

/**
 * Creates the NSEC node, creates or update the NSEC record
 * 
 * @param zone
 * @param label
 * @param labels
 * @param labels_top
 */

void
nsec_update_label(zdb_zone* zone, zdb_rr_label* label, dnslabel_vector_reference labels, s32 labels_top)
{
    u8 name[MAX_DOMAIN_LENGTH];

    /* Create or get the node */

    nsec_node *node = nsec_update_label_node(zone, label, labels, labels_top);

    /* Get the next node */

    nsec_node *next_node = nsec_node_mod_next(node);

    dnslabel_vector_to_dnsname(labels, labels_top, name);

    nsec_update_label_record(zone, label, node, next_node, name);
}

void
nsec_destroy_zone(zdb_zone *zone)
{
    if(!nsec_isempty(&zone->nsec.nsec))
    {
        nsec_iterator iter;
        nsec_iterator_init(&zone->nsec.nsec,&iter);

        while(nsec_iterator_hasnext(&iter))
        {
            nsec_node *node = nsec_iterator_next_node(&iter);
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

zdb_rr_label *
nsec_find_interval(const zdb_zone *zone, const dnsname_vector *name_vector, u8 **out_dname_p, u8 * restrict * pool)
{
    u8 dname_inverted[MAX_DOMAIN_LENGTH];
    
    dnslabel_stack_to_dnsname(name_vector->labels, name_vector->size, dname_inverted);
    
    nsec_node *node = nsec_find_interval_start(&zone->nsec.nsec, dname_inverted);

    u8 *out_dname = *pool;
    *out_dname_p = out_dname;
    u32 out_dname_len = nsec_inverse_name(out_dname, node->inverse_relative_name);
    *pool += ALIGN16(out_dname_len);

    return node->label;
}

void
nsec_name_error(const zdb_zone* zone, const dnsname_vector *name, s32 closest_index,
                u8 * restrict * pool,
                u8 **out_encloser_nsec_name_p,
                zdb_rr_label **out_encloser_nsec_label,
                u8 **out_wild_encloser_nsec_name_p,
                zdb_rr_label **out_wildencloser_nsec_label
                 )
{
    u32 len;
    u8 dname_inverted[MAX_DOMAIN_LENGTH + 2];
    
    dnslabel_stack_to_dnsname(name->labels, name->size, dname_inverted);
    
    nsec_node *node = nsec_find_interval_start(&zone->nsec.nsec, dname_inverted);
    
    u8 *out_encloser_nsec_name = *pool;
    *out_encloser_nsec_name_p = out_encloser_nsec_name;
    len = nsec_inverse_name(out_encloser_nsec_name, node->inverse_relative_name);
    *pool += ALIGN16(len);
    
    dnslabel_stack_to_dnsname(&name->labels[closest_index], name->size - closest_index, dname_inverted);
    
    nsec_node *wild_node = nsec_find_interval_start(&zone->nsec.nsec, dname_inverted);
    
    if(wild_node != node)
    {
        u8 *out_wild_encloser_nsec_name = *pool;
        *out_wild_encloser_nsec_name_p = out_wild_encloser_nsec_name;
        len = nsec_inverse_name(out_wild_encloser_nsec_name, wild_node->inverse_relative_name);
        *pool += ALIGN16(len);
    }
    
    *out_encloser_nsec_label = node->label;
    *out_wildencloser_nsec_label = wild_node->label;
}

void
nsec_logdump_tree(zdb_zone *zone)
{
    log_debug("dumping zone %{dnsname} nsec tree", zone->origin);

    nsec_iterator iter;
    nsec_iterator_init(&zone->nsec.nsec, &iter);
    while(nsec_iterator_hasnext(&iter))
    {
        nsec_node *node = nsec_iterator_next_node(&iter);

        log_debug("%{dnsname}", node->inverse_relative_name);
    }
    log_debug("done dumping zone %{dnsname} nsec tree", zone->origin);
}

#if HAS_MASTER_SUPPORT

/**
 * marks the zone with private records
 * 
 * @param zone
 * @param status
 * 
 * @return an error code
 */

ya_result
nsec_zone_set_status(zdb_zone *zone, u8 secondary_lock, u8 status)
{
    dynupdate_message dmsg;
    packet_unpack_reader_data reader;
    dynupdate_message_init(&dmsg, zone->origin, CLASS_IN);
    
    u8 prev_status = 0;    
    u8 nsecparamadd_rdata[1];
    
    nsecparamadd_rdata[0] = status;
    
    // look for the matching record
    if(nsec_zone_get_status(zone, &prev_status) == 1)
    {
        // if the record exists, remove it and add it
        dynupdate_message_del_record_set(&dmsg, zone->origin, TYPE_NSECCHAINSTATE);
    }
    dynupdate_message_add_record(&dmsg, zone->origin, TYPE_NSECCHAINSTATE, 0, 1, nsecparamadd_rdata);
    dynupdate_message_set_reader(&dmsg, &reader);
    u16 count = dynupdate_message_get_count(&dmsg);

    packet_reader_skip(&reader, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&reader);
    packet_reader_skip(&reader, 4);
    
    ya_result ret;
    
    ret = dynupdate_diff(zone, &reader, count, secondary_lock, DYNUPDATE_DIFF_RUN);
    
    dynupdate_message_finalize(&dmsg);
    
    if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
    {
        // trigger a background store of the zone
        
        zdb_zone_info_background_store_zone(zone->origin);
    }
        
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

ya_result
nsec_zone_get_status(zdb_zone *zone, u8 *statusp)
{
    // get the TYPE_NSEC3PARAMADD record set
    // search for a record matching the chain
    zdb_packed_ttlrdata *rrset = zdb_record_find(&zone->apex->resource_record_set, TYPE_NSECCHAINSTATE);
    if(rrset != NULL)
    {
        *statusp = rrset->rdata_start[0];
        return 1;
    }
    return 0;
}

/** @} */

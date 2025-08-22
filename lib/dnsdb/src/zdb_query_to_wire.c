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
 * @defgroup query_ex Database top-level query function
 * @ingroup dnsdb
 * @brief Database top-level query function
 *
 *  Database top-level query function
 *
 * @{
 *----------------------------------------------------------------------------*/
#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <stdlib.h>
#define DEBUG_LEVEL 0

#include <dnscore/dnscore.h>
#include <dnscore/format.h>
#include <dnscore/random.h>
#include <dnscore/dnsname_set.h>
#include <dnscore/dns_message.h>
#include <dnscore/thread_pool.h>
#include <dnscore/dns_packet_writer.h>
#include <dnscore/base32hex.h>
#include <dnscore/rfc.h>

#if HAS_RDTSC
#include <dnscore/rdtsc.h>
#endif

#include "dnsdb/zdb_query_to_wire.h"
#include "dnsdb/zdb_query_to_wire_append.h"
#include "dnsdb/zdb_query_to_wire_append_nsec.h"
#include "dnsdb/zdb_query_to_wire_append_nsec3.h"
#include "dnsdb/zdb_query_to_wire_append_soa.h"
#include "dnsdb/zdb_query_to_wire_append_type_rrsigs.h"

#include "dnsdb/zdb.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/dictionary.h"
#if ZDB_HAS_NSEC_SUPPORT
#include "dnsdb/nsec.h"
#endif
#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif
#if ZDB_HAS_DNSSEC_SUPPORT
#include "dnsdb/rrsig.h"
#include "dnscore/nsid.h"
#endif

#include "dnsdb/dnsname_zone_dict.h"

// if set, assumes RCODE is zero in the answer message so there is no need to clear the bits
// also contains optimisations for constant parameters and groups flags in on operation
#define ZDB_QUERY_TO_WIRE_ASSUME_ZERO 0

/**
 * In order to optimise-out the class parameter that is not required if ZDB_RECORDS_CLASS_MAX == 1 ...
 */
#if ZDB_RECORDS_CLASS_MAX != 1
#define DECLARE_ZCLASS_PARAMETER   uint16_t zclass,
#define PASS_ZCLASS_PARAMETER      zclass,
#define PASS_ZONE_ZCLASS_PARAMETER zone->zclass,
#else
#define DECLARE_ZCLASS_PARAMETER
#define PASS_ZCLASS_PARAMETER
#define PASS_ZONE_ZCLASS_PARAMETER
#endif

extern logger_handle_t *g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger
#ifndef HAS_DYNAMIC_PROVISIONING
#error "MISSING HAS_DYNAMIC_PROVISIONING"
#endif

process_flags_t zdb_query_process_flags = ~0;

/**
 * @brief Update a name set with the name found in an RDATA
 *
 * @param source the record rdata containing the name to add
 * @param headp a pointer to the section list
 * @param rtype the type of the record
 * @param set collection where to add the name
 *
 * 10 use
 */
static void zdb_query_to_wire_additionals_dname_set_update_ns(dnsname_set *set, zdb_resource_record_set_t *rrset DECLARE_ZCLASS_PARAMETER)
{
    zdb_resource_record_set_iterator iter;
    zdb_resource_record_set_iterator_init(rrset, &iter);
    while(zdb_resource_record_set_iterator_has_next(&iter))
    {
        zdb_resource_record_data_t *record = zdb_resource_record_set_iterator_next(&iter);

        if(!dnsname_set_insert(set, zdb_resource_record_data_rdata(record)))
        {
            break;
        }
    }
}

static void zdb_query_to_wire_additionals_dname_set_update_mx(dnsname_set *set, zdb_resource_record_set_t *rrset DECLARE_ZCLASS_PARAMETER)
{
    zdb_resource_record_set_iterator iter;
    zdb_resource_record_set_iterator_init(rrset, &iter);
    while(zdb_resource_record_set_iterator_has_next(&iter))
    {
        zdb_resource_record_data_t *record = zdb_resource_record_set_iterator_next(&iter);

        if(!dnsname_set_insert(set, zdb_resource_record_data_rdata(record) + 2))
        {
            break;
        }
    }
}

/**
 * @brief Handles what to do when a record has not been found (NXRRSET)
 *
 * @param zone the zone
 * @param rr_label_info details about the labels on the path of the query
 * @param qname name of the query
 * @param name name of the query (vector)
 * @param sp index of the label in the name (vector)
 * @param top
 * @param type
 * @param zclass (if more than one class is supported in the database)
 * @param ans_auth_add a pointer to the section list
 * @param pool the memory pool
 * @param additionals_dname_set
 *
 * 3 uses
 */
static inline finger_print zdb_query_to_wire_record_not_found(zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, const zdb_rr_label_find_ext_data *rr_label_info, const uint8_t *qname, const dnsname_vector_t *name, int32_t top,
                                                              uint16_t type, bool dnssec, zdb_query_to_wire_append_soa_authority_method *append_soa_authority)
{
    zdb_rr_label_t *rr_label = rr_label_info->answer;

    // NXRRSET

#if ZDB_HAS_NSEC3_SUPPORT
    if(dnssec && ZONE_NSEC3_AVAILABLE(zone))
    {
        int32_t min_ttl;
        zdb_zone_getminttl(zone, &min_ttl);

        if(((type == TYPE_DS) && (zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_UNDERDELEGATION))) || ((type != TYPE_DS) && (zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION | ZDB_RR_LABEL_UNDERDELEGATION))))
        {
            /*
             * Add all the NS and their signature
             */
            zdb_rr_label_t            *authority = rr_label_info->authority;
            zdb_resource_record_set_t *ns_rrset = zdb_resource_record_sets_find(&authority->resource_record_set, TYPE_NS);

            if(ns_rrset != NULL)
            {
                const uint8_t *auth_name = name->labels[rr_label_info->authority_index];

                uint16_t       count = zdb_query_to_wire_append_ns_from_rrset(context, auth_name, ns_rrset);
                count += zdb_query_to_wire_append_type_rrsigs(context, rr_label, auth_name, TYPE_NS, zdb_resource_record_set_ttl(ns_rrset));

                zdb_resource_record_set_t *ds_rrset = zdb_resource_record_sets_find(&authority->resource_record_set, TYPE_DS);

                if(ds_rrset != NULL)
                {
                    count += zdb_query_to_wire_append_from_rrset(context, auth_name, ds_rrset);
                    count += zdb_query_to_wire_append_type_rrsigs(context, rr_label, auth_name, TYPE_DS, zdb_resource_record_set_ttl(ds_rrset));

                    /* ans_auth_add->is_delegation = true; later */

                    context->authority_count += count;

                    zdb_query_to_wire_context_add_ns_rrset(context, ns_rrset, zone);
                    context->additionals_added = true;
                    context->additionals_with_rrsig = dnssec;

                    return FP_BASIC_RECORD_NOTFOUND;
                }

                context->authority_count += count;

                zdb_query_to_wire_context_add_ns_rrset(context, ns_rrset, zone);
            }
        }
        else
        {
            zdb_query_to_wire_append_soa_authority_nttl(context, zone, true);
        }

        if(!context->delegation)
        {
            context->authority_count += zdb_query_to_wire_append_nsec3_nodata(context, zone, rr_label, name, top, type);
        }
        else
        {
            /*
             * If there is an NSEC3 RR that matches the delegation name, then that
             * NSEC3 RR MUST be included in the response.  The DS bit in the type
             * bit maps of the NSEC3 RR MUST NOT be set.
             *
             * If the zone is Opt-Out, then there may not be an NSEC3 RR
             * corresponding to the delegation.  In this case, the closest provable
             * encloser proof MUST be included in the response.  The included NSEC3
             * RR that covers the "next closer" name for the delegation MUST have
             * the Opt-Out flag set to one.  (Note that this will be the case unless
             * something has gone wrong).
             */

            context->authority_count += zdb_query_to_wire_append_nsec3_delegation(context, zone, rr_label_info, name, top);
        }

        context->additionals_added = true;
        context->additionals_with_rrsig = false;

#if DEBUG
        log_debug("zdb_query_ex: FP_NSEC3_RECORD_NOTFOUND (NSEC3)");
#endif
        return FP_NSEC3_RECORD_NOTFOUND;
    }
    else /* We had the label, not the record, it's not NSEC3 : */
#endif
    {
        /** Got label but no record : show the authority
         *  AA
         */

        if(zdb_rr_label_is_not_apex(rr_label_info->authority))
        {
            zdb_resource_record_set_t *ns_rrset;

            if((((type == TYPE_DS) && zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_UNDERDELEGATION)) || ((type != TYPE_DS) && zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION | ZDB_RR_LABEL_UNDERDELEGATION))) &&
               (((ns_rrset = zdb_resource_record_sets_find(&rr_label_info->authority->resource_record_set, TYPE_NS)) != NULL)))
            {
                const uint8_t *auth_name = name->labels[rr_label_info->authority_index];

                zdb_query_to_wire_context_add_ns_rrset(context, ns_rrset, zone);
                context->authority_count += zdb_query_to_wire_append_ns_from_rrset(context, auth_name, ns_rrset);
                /* ans_auth_add->is_delegation = true; later */
            }
            else
            {
                /* append the SOA */

                append_soa_authority(context, zone, dnssec);
            }
        }
        else
        {
            /* append the SOA */

            append_soa_authority(context, zone, dnssec);
        }
#if ZDB_HAS_NSEC_SUPPORT
        if(dnssec && ZONE_NSEC_AVAILABLE(zone))
        {
            zdb_rr_label_t            *rr_label_authority = rr_label_info->authority;
            zdb_resource_record_set_t *delegation_signer = zdb_resource_record_sets_find(&rr_label_authority->resource_record_set, TYPE_DS);

            if(delegation_signer != NULL)
            {
                const uint8_t *authority_qname = zdb_rr_label_info_get_authority_qname(qname, rr_label_info);

                uint16_t       count = zdb_query_to_wire_append_from_rrset(context, authority_qname, delegation_signer);
                count += zdb_query_to_wire_append_type_rrsigs(context, rr_label_authority, authority_qname, TYPE_DS, zdb_resource_record_set_ttl(delegation_signer));

                context->authority_count += count;
            }
            else
            {
                uint8_t *wild_name = (uint8_t *)qname;

                uint8_t  starred_name[256];

                if(IS_WILD_LABEL(rr_label->name))
                {
                    /*
                    starred_name[0] = 1;
                    starred_name[1] = (uint8_t)'*';
                    dnslabel_vector_to_dnsname(&name->labels[name->size - sp_label_index], sp_label_index,
                    &starred_name[2]); wild_name = &starred_name[0];
                    */

                    if(rr_label_info->answer->nsec.nsec.node != NULL)
                    {
                        nsec_inverse_name(&starred_name[0], rr_label_info->answer->nsec.nsec.node->inverse_relative_name);
                        wild_name = &starred_name[0];
                    }
                    else if(rr_label_info->closest->nsec.nsec.node != NULL)
                    {
                        nsec_inverse_name(&starred_name[0], rr_label_info->closest->nsec.nsec.node->inverse_relative_name);
                        wild_name = &starred_name[0];
                    }
                    else
                    {
                        return FP_BASIC_RECORD_NOTFOUND;
                    }
                }

                zdb_resource_record_set_t *nsec_rrset = zdb_resource_record_sets_find(&rr_label->resource_record_set, TYPE_NSEC);

                if(nsec_rrset != NULL)
                {
                    uint16_t count = zdb_query_to_wire_append_from_rrset(context, wild_name, nsec_rrset);
                    count += zdb_query_to_wire_append_type_rrsigs(context, rr_label, wild_name, TYPE_NSEC, zdb_resource_record_set_ttl(nsec_rrset));
                    context->authority_count += count;
                }

                context->authority_count += zdb_query_to_wire_append_nsec_interval(context, zone, name, rr_label);
            }
        }

        context->additionals_added = true;
        context->additionals_with_rrsig = false;
    }
#endif

    return FP_BASIC_RECORD_NOTFOUND;
}

/**
 * @brief Appends all the glue records associated to the names in the set to the message
 *
 * @param set the set with all the fqdns
 * @param context the context of the query
 * @param zone the current zone
 * @param dnssec dnssec enabled or not
 *
 * 10 use
 */
static uint16_t zdb_query_to_wire_additionals_dname_set_append(dnsname_set *set, zdb_query_to_wire_context_t *context, const zdb_zone_t *zone, bool dnssec)
{
    uint16_t             count = 0;

    dnsname_set_iterator iter;

    dnsname_set_iterator_init(set, &iter);

    while(dnsname_set_iterator_hasnext(&iter))
    {
        /* ADD NS "A/AAAA" TO ADDITIONAL  */

        const uint8_t *dns_name = dnsname_set_iterator_next_node(&iter)->key;

        count += zdb_query_to_wire_append_ips(context, zone, dns_name, dnssec);
    }

    return count;
}

/**
 * Builds a dns_message_t answer for a query.
 *
 * Typical usage:
 *
 *  zdb_query_to_wire_context_t context;
 *  zdb_query_to_wire_context_init(&context, mesg);
 *  zdb_query_to_wire(database, &context);
 *  zdb_query_to_wire_finalize(&context);
 *
 *  At this point the message is ready.
 *  TSIG signature could be the next step before answering.
 *
 * NOTE: the parameter order is a remnant and should be swapped
 *
 * @param db the zone database
 * @param context the context to query for
 * @return the query status
 */

finger_print zdb_query_to_wire(zdb_query_to_wire_context_t *context)
{
    dns_message_t *mesg = context->mesg;
    const uint8_t *qname = context->fqdn;
#if ZDB_RECORDS_CLASS_MAX != 1
    const uint16_t zclass = message_get_query_class(mesg);
#endif

    zdb_rr_label_find_ext_data rr_label_info;

    /** Check that we are even allowed to handle that class */
#if ZDB_RECORDS_CLASS_MAX == 1
    if(dns_message_get_query_class(mesg) != CLASS_IN)
    {
#if DEBUG
        log_debug("zdb_query_ex: FP_CLASS_NOTFOUND");
#endif
        dns_message_set_answer(mesg);
        dns_message_set_rcode(mesg, FP_CLASS_NOTFOUND);
        return FP_CLASS_NOTFOUND;
    }
#endif

#if ZDB_RECORDS_CLASS_MAX != 1
    uint16_t host_zclass = ntohs(zclass); /* no choice */
    if(host_zclass > ZDB_RECORDS_CLASS_MAX)
    {
        message_set_answer(mesg);
        message_set_rcode(mesg, FP_CLASS_NOTFOUND);
        return FP_CLASS_NOTFOUND;
    }
#endif

    bool dnssec = dns_message_has_edns0_dnssec(mesg);

    dnsname_vector_t name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(qname, &name);

    /*
     * Find the closest matching label
     * Should return a stack of zones
     */

    zdb_zone_label_pointer_array zone_label_stack;

    int32_t top = zdb_zone_label_match(context->db, &name, zone_label_stack); // value returned >= 0
    /// @note 20230908 edf -- the db cannot be unlocked here : zones in the stack aren't RCed nor locked. Dynamic
    ///                       provisioning could very well drop them while the query is being resolved.
    ///                       Beside, it's the zone label, not the zone that's being stored.
    int32_t sp = top; // top >=0 => sp >= 0

    bool    authority_required = context->flags & PROCESS_FL_AUTHORITY_AUTH;    // This flag means that there HAS to be an authority section
    bool    additionals_required = context->flags & PROCESS_FL_ADDITIONAL_AUTH; // This flag means the names in the authority must be (internally)
                                                                                // resolved if possible

    uint16_t type = dns_message_get_query_type(mesg);

    switch(type)
    {
        case TYPE_A:
        case TYPE_AAAA:
        case TYPE_DNSKEY:
        {
            authority_required = false;
            additionals_required = false;
            break;
        }
        default:
        {
            break;
        }
    }
#if ZDB_HAS_RRCACHE_ENABLED
    bool found_zones = false;
#endif

    // handle the DS case

    if(type == TYPE_DS)         // This is the only type that can only be found outside of the zone
    {                           // In order to avoid to hit said zone, I skip the last label.
        if(name.size == sp - 1) // we have a perfect match (DS for an APEX), try to get outside ...
        {
            int32_t parent_sp = sp;

            while(--parent_sp >= 0)
            {
                /* Get the "bottom" label (top being ".") */

                zdb_zone_label_t *zone_label = zone_label_stack[parent_sp];

                /* Is there a zone file at this level ? If yes, search into it. */

                if(zone_label->zone != NULL)
                {
                    // got it.
                    sp = parent_sp;
                    dns_message_set_authoritative_answer(mesg);
                    break;
                }
            }

            authority_required = false;
        }
    }

    // Got a stack of zone labels with and without zone cuts
    // Search the label on the zone files
    // While we have labels along the path

    while(sp >= 0)
    {
        /* Get the "bottom" label (top being ".") */

        zdb_zone_label_t *zone_label = zone_label_stack[sp];

        /* Is there a zone file at this level ? If yes, search into it. */

        if(zone_label->zone != NULL)
        {
#if ZDB_HAS_RRCACHE_ENABLED
            found_zones = true;
#endif
            zdb_zone_t *zone = zone_label->zone;

            /*
             * lock
             */

            zdb_zone_read_lock(zone);
            context->locked_zones[context->locked_zones_count++] = zone;
#if DEBUG
            log_debug("zdb_query_ex: zone %{dnsname}, flags=%x", zone->origin, zdb_rr_label_flag_get(zone->apex));
#endif
            // We know the zone, and its extension here ...

            /*
             * Filter handling (ACL)
             * NOTE: the return code has to be fingerprint-based
             */

            if(FAIL(zone->query_access_filter(mesg, zone->acl)))
            {
#if DEBUG
                log_debug("zdb_query_ex: FP_ACCESS_REJECTED");
#endif
                dns_message_set_status(mesg, FP_ACCESS_REJECTED);
#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
                dns_message_set_answer(mesg);
                dns_message_set_rcode(mesg, FP_ACCESS_REJECTED);
#else
                    dns_message_or_answer_rcode(mesg, FP_ACCESS_REJECTED);
#endif
                return FP_ACCESS_REJECTED;
            }

            /**
             * The ACL have been passed so ... now check that the zone is valid
             */

            if(zdb_zone_invalid(zone))
            {
                /**
                 * @note the blocks could be reversed and jump if the zone is invalid (help the branch prediction)
                 */
#if DEBUG
                log_debug("zdb_query_ex: FP_INVALID_ZONE");
#endif
#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
                dns_message_set_answer(mesg);
                dns_message_set_rcode(mesg, FP_INVALID_ZONE);
#else
                dns_message_or_answer_rcode(mesg, FP_INVALID_ZONE);
#endif
                return FP_INVALID_ZONE;
            }

            dnssec &= zdb_zone_is_dnssec(zone);

            // In one call, get the authority and the closest (longest) path to the domain we are looking for.

            zdb_rr_label_t *rr_label = zdb_rr_label_find_ext(zone->apex, name.labels, name.size - sp, &rr_label_info);

            // Has a label been found ?
#if DNSCORE_HAS_RRL_SUPPORT
            context->fqdn_label = rr_label;
#endif
            if(rr_label != NULL)
            {
                /*
                 * Got the label.  I will not find anything relevant by going
                 * up to another zone file.
                 *
                 * We set the AA bit iff we are not at or under a delegation.
                 *
                 * The ZDB_RR_LABEL_DELEGATION flag means the label is a delegation.
                 * This means that it only contains NS & DNSSEC records + may have sub-labels for glues
                 *
                 * ZDB_RR_LABEL_UNDERDELEGATION means we are below a ZDB_RR_LABEL_DELEGATION label
                 *
                 */

                ////////////////////////////////////////////////////////////////////////////////////////////////////////
                //
                // CNAME handling : begin
                //
                ////////////////////////////////////////////////////////////////////////////////////////////////////////

                // CNAME alias handling

                if(((zdb_rr_label_flag_get(rr_label) & (ZDB_RR_LABEL_HASCNAME | ZDB_RR_LABEL_DELEGATION | ZDB_RR_LABEL_UNDERDELEGATION)) == ZDB_RR_LABEL_HASCNAME) && (type != TYPE_CNAME) && (type != TYPE_ANY) && (type != TYPE_RRSIG))
                {
                    // The label is an alias : add the CNAME and restart the query from the alias

                    if(context->cname_count >= ZDB_CNAME_LOOP_MAX)
                    {
                        // CNAME max loop depth reached

                        log_warn("CNAME depth at %{dnsname} is bigger than allowed %d>=%d", qname, context->cname_count, ZDB_CNAME_LOOP_MAX);

                        dns_message_set_status(mesg, FP_CNAME_MAXIMUM_DEPTH);
#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
                        dns_message_set_authoritative_answer(mesg);
                        dns_message_set_rcode(mesg, FP_CNAME_MAXIMUM_DEPTH);
#else
                            dns_message_or_authoritative_answer_rcode(mesg, FP_CNAME_MAXIMUM_DEPTH);
#endif

                        return FP_CNAME_MAXIMUM_DEPTH;
                    }

                    /// @note 2.4.2 was incrementing the depth here

                    zdb_resource_record_set_t *cname_rrset;

                    if((cname_rrset = zdb_resource_record_sets_find(&rr_label->resource_record_set, TYPE_CNAME)) != NULL)
                    {
                        const zdb_resource_record_data_t *cname_rr = zdb_resource_record_set_record_get_const(cname_rrset, 0);

                        /* The RDATA in answer is the fqdn to a label with an A record (list) */
                        /* There can only be one CNAME for a given owner */
                        /* Append all A/AAAA records associated to the CNAME AFTER the CNAME record */

                        // check the CNAME doesn't match a previous CNAME (loop)

                        for(uint_fast8_t i = 0; i < context->cname_count; ++i)
                        {
                            if(dnsname_compare(context->cname_list[i], zdb_resource_record_data_rdata_const(cname_rr)) == 0)
                            {
                                /* LOOP */

                                log_warn("CNAME loop at %{dnsname}", qname);

                                dns_message_set_authoritative_answer(mesg);
                                dns_message_set_rcode(mesg, FP_CNAME_LOOP);
                                return FP_CNAME_LOOP;
                            }
                        }

                        if(context->cname_count == 0)
                        {
                            dnsname_copy(context->original_canonised_fqdn, dns_message_get_canonised_fqdn(mesg));
                        }

                        dnsname_copy(context->last_cname_fqdn, context->fqdn);
                        context->cname_list[context->cname_count] = zdb_resource_record_data_rdata_const(cname_rr);
                        ++context->cname_count;

                        /* ONE record */

                        const uint8_t *cname_owner = qname;

                        dns_packet_writer_add_fqdn(&context->pw, cname_owner);
                        dns_packet_writer_add_u16(&context->pw, TYPE_CNAME);
                        dns_packet_writer_add_u16(&context->pw, CLASS_IN);
                        dns_packet_writer_add_u32(&context->pw, htonl(zdb_resource_record_set_ttl(cname_rrset)));
                        uint16_t offset = context->pw.packet_offset;
                        context->pw.packet_offset += 2;
                        dns_packet_writer_add_fqdn(&context->pw, zdb_resource_record_data_rdata_const(cname_rr));
                        dns_packet_writer_set_u16(&context->pw, htons(context->pw.packet_offset - offset - 2), offset);

                        ++context->answer_count;
#if ZDB_HAS_DNSSEC_SUPPORT
                        if(dnssec)
                        {
                            context->answer_count += zdb_query_to_wire_append_type_rrsigs(context, rr_label, cname_owner, TYPE_CNAME, zdb_resource_record_set_ttl(cname_rrset));
                        }
#endif
                        dns_message_set_answer_count(mesg, context->answer_count);
                        dns_message_set_canonised_fqdn(mesg, zdb_resource_record_data_rdata_const(cname_rr));
                        context->fqdn = cname_owner;
                        context->flags = 0;
                        zdb_query_to_wire(context);

#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
                        dns_message_set_authoritative_answer(mesg);

                        if(dns_message_get_rcode(mesg) == RCODE_REFUSED)
                        {
                            if(dnssec && IS_WILD_LABEL(rr_label->name))
                            {
                                if(ZONE_NSEC3_AVAILABLE(zone))
                                {
                                    nsec3_zone_t *n3 = zone->nsec.nsec3;
                                    const uint8_t               *salt = NSEC3_ZONE_SALT(n3);
                                    int32_t       min_ttl;
                                    uint16_t                     iterations = nsec3_zone_get_iterations(n3);
                                    uint8_t                      salt_len = NSEC3_ZONE_SALT_LEN(n3);
                                    uint8_t digest[64 + 1];
                                    zdb_zone_getminttlsoa(zone, &min_ttl);

                                    nsec3_hash_function_t *const digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3)); /// @note 20150917 edf -- do not use nsec3_compute_digest_from_fqdn_with_len
                                    const uint8_t *fqdn = context->last_cname_fqdn;
                                    digestname(fqdn, dnsname_len(fqdn), salt, salt_len, iterations, &digest[1], false);
                                    digest[0] = SHA_DIGEST_LENGTH;
                                    const nsec3_zone_item_t *nsec3_node = nsec3_zone_item_find_encloser_start(n3, digest); // get the interval covering the next closer
                                    nsec3_zone_item_to_new_zdb_resource_record_data_parm cname_target_nsec3_parm = {n3, nsec3_node, zone->origin, NULL, min_ttl};
                                    context->authority_count += zdb_query_to_wire_append_nsec3_record(context, &cname_target_nsec3_parm);
                                    dns_message_set_authority_count(mesg, context->authority_count);
                                }
                                else if(ZONE_NSEC_AVAILABLE(zone))
                                {
                                    uint8_t dname_inverted[DOMAIN_LENGTH_MAX + 2];
                                    nsec_inverse_name(dname_inverted, context->last_cname_fqdn);
                                    nsec_node_t *cname_node = nsec_find_interval_start(&zone->nsec.nsec, dname_inverted);
                                    nsec_inverse_name(dname_inverted, cname_node->inverse_relative_name);
                                    zdb_resource_record_sets_node_t *cname_nsec_rrset_node = zdb_resource_record_sets_set_find(&cname_node->label->resource_record_set, TYPE_NSEC);
                                    context->authority_count += zdb_query_to_wire_append_from_rrset(context, dname_inverted, &cname_nsec_rrset_node->value);
                                    context->authority_count += zdb_query_to_wire_append_type_rrsigs(context, cname_node->label, dname_inverted, TYPE_NSEC, zdb_resource_record_set_ttl(&cname_nsec_rrset_node->value));
                                    dns_message_set_authority_count(mesg, context->authority_count);
                                }
                            }

                            dns_message_set_rcode(mesg, RCODE_NOERROR);
                        }
                        else if(dns_message_get_rcode(mesg) == RCODE_NXDOMAIN)
                        {
                            if(dnssec && IS_WILD_LABEL(rr_label->name))
                            {
                                if(ZONE_NSEC3_AVAILABLE(zone))
                                {
                                    nsec3_zone_t *n3 = zone->nsec.nsec3;
                                    const uint8_t               *salt = NSEC3_ZONE_SALT(n3);
                                    int32_t       min_ttl;
                                    uint16_t                     iterations = nsec3_zone_get_iterations(n3);
                                    uint8_t                      salt_len = NSEC3_ZONE_SALT_LEN(n3);
                                    uint8_t digest[64 + 1];
                                    zdb_zone_getminttlsoa(zone, &min_ttl);

                                    nsec3_hash_function_t *const digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3)); /// @note 20150917 edf -- do not use nsec3_compute_digest_from_fqdn_with_len
                                    const uint8_t *fqdn = context->last_cname_fqdn;
                                    digestname(fqdn, dnsname_len(fqdn), salt, salt_len, iterations, &digest[1], false);
                                    digest[0] = SHA_DIGEST_LENGTH;
                                    const nsec3_zone_item_t *nsec3_node = nsec3_zone_item_find_encloser_start(n3, digest); // get the interval covering the next closer
                                    nsec3_zone_item_to_new_zdb_resource_record_data_parm cname_target_nsec3_parm = {n3, nsec3_node, zone->origin, NULL, min_ttl};
                                    context->authority_count += zdb_query_to_wire_append_nsec3_record(context, &cname_target_nsec3_parm);
                                    dns_message_set_authority_count(mesg, context->authority_count);
                                }
                            }
                        }
                        else if(dns_message_get_rcode(mesg) == RCODE_NOERROR)
                        {
                            if(dnssec && IS_WILD_LABEL(rr_label->name))
                            {
                                if(ZONE_NSEC3_AVAILABLE(zone))
                                {
                                    nsec3_zone_t *n3 = zone->nsec.nsec3;
                                    const uint8_t               *salt = NSEC3_ZONE_SALT(n3);
                                    int32_t       min_ttl;
                                    uint16_t                     iterations = nsec3_zone_get_iterations(n3);
                                    uint8_t                      salt_len = NSEC3_ZONE_SALT_LEN(n3);
                                    uint8_t digest[64 + 1];
                                    zdb_zone_getminttlsoa(zone, &min_ttl);
                                    nsec3_hash_function_t *const digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3)); /// @note 20150917 edf -- do not use nsec3_compute_digest_from_fqdn_with_len
                                    const uint8_t *fqdn = context->last_cname_fqdn;
                                    for(int i = 0; i < rr_label_info.wildcard_index; ++i)
                                    {
                                        fqdn += *fqdn + 1;
                                    }
                                    // find the provable encloser
                                    digestname(fqdn, dnsname_len(fqdn), salt, salt_len, iterations, &digest[1], false);
                                    digest[0] = SHA_DIGEST_LENGTH;
                                    const nsec3_zone_item_t *nsec3_node = nsec3_zone_item_find_encloser_start(n3, digest); // get the interval covering the next closer
                                    nsec3_zone_item_to_new_zdb_resource_record_data_parm cname_target_nsec3_parm = {n3, nsec3_node, zone->origin, NULL, min_ttl};
                                    context->authority_count += zdb_query_to_wire_append_nsec3_record(context, &cname_target_nsec3_parm);
                                    dns_message_set_authority_count(mesg, context->authority_count);
                                }
                                else if(ZONE_NSEC_AVAILABLE(zone))
                                {
                                    uint8_t dname_inverted[DOMAIN_LENGTH_MAX + 2];
                                    nsec_inverse_name(dname_inverted, context->last_cname_fqdn);
                                    nsec_node_t *cname_node = nsec_find_interval_start(&zone->nsec.nsec, dname_inverted);
                                    nsec_inverse_name(dname_inverted, cname_node->inverse_relative_name);
                                    zdb_resource_record_sets_node_t *cname_nsec_rrset_node = zdb_resource_record_sets_set_find(&cname_node->label->resource_record_set, TYPE_NSEC);
                                    context->authority_count += zdb_query_to_wire_append_from_rrset(context, dname_inverted, &cname_nsec_rrset_node->value);
                                    context->authority_count += zdb_query_to_wire_append_type_rrsigs(context, cname_node->label, dname_inverted, TYPE_NSEC, zdb_resource_record_set_ttl(&cname_nsec_rrset_node->value));
                                    dns_message_set_authority_count(mesg, context->authority_count);
                                }
                            }

                            context->additionals_added = true;
                            context->additionals_with_rrsig = false;
                        }

#else
                            dns_message_set_authoritative_answer(mesg);
                            // dns_message_or_authoritative_answer_rcode(mesg, FP_RCODE_NOERROR);
#endif

                        return FP_RCODE_NOERROR;
                    }
                    else
                    {
                        /*
                         * We expected a CNAME record but found none.
                         * This is NOT supposed to happen.
                         */

#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
                        dns_message_set_authoritative_answer(mesg);
                        dns_message_set_rcode(mesg, FP_CNAME_BROKEN);
#else
                            dns_message_or_authoritative_answer_rcode(mesg, FP_CNAME_BROKEN);
#endif

                        return FP_CNAME_BROKEN;
                    }
                }

                ////////////////////////////////////////////////////////////////////////////////////////////////////////
                //
                // CNAME handling : end
                //
                ////////////////////////////////////////////////////////////////////////////////////////////////////////

                if(zdb_rr_label_flag_isclear(rr_label, ZDB_RR_LABEL_DELEGATION | ZDB_RR_LABEL_UNDERDELEGATION))
                {
                    dns_message_set_authoritative_answer(mesg);
                    authority_required = false;
                }
                else
                {
                    /*
                     * we are AT or UNDER a delegation
                     * We can only find (show) NS, DS, RRSIG, NSEC records from the query
                     *
                     * The answer WILL be a referral ...
                     */

                    switch(type)
                    {
                        // for these ones : give the rrset for the type and clear AA
                        case TYPE_DS:
                        {
                            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                            {
                                dns_message_set_authoritative_answer(mesg);
                            }
                            else if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_UNDERDELEGATION))
                            {
                                dns_message_clear_authoritative(mesg);
                            }
                            context->delegation = true;
                            authority_required = false;
                            break;
                        }
                        case TYPE_NSEC:
                        {
                            // no answer, and we will answer with NS (as at or under delegation)

                            if(zdb_rr_label_flag_isclear(rr_label, ZDB_RR_LABEL_UNDERDELEGATION))
                            {
                                dns_message_set_authoritative_answer(mesg);
                            }
                            break;
                        }
                        // for these ones : give the rrset for the type
                        case TYPE_NS:
                            context->delegation = true; // no answer, and we will answer with NS (as at or under delegation)
                            break;
                        // for this one : present the delegation
                        case TYPE_ANY:
                            context->delegation = true; // no answer, and we will answer with NS (as at or under delegation)
                            authority_required = false;
                            break;
                        default:
                            context->delegation = true;

                            /*
                             * do not try to look for it
                             *
                             * faster: go to label but no record, but let's avoid gotos ...
                             */

                            type = TYPE_NONE;
                            break;
                    }
                }

                // First let's handle "simple" cases.  ANY will be handled in another part of the code.

                if(type != TYPE_ANY)
                {
                    // From the label that has been found, get the RRSET for the required type
                    // (zdb_resource_record_data_t*)

                    zdb_resource_record_set_t *type_rrset;

                    if((type_rrset = zdb_resource_record_sets_find(&rr_label->resource_record_set, type)) != NULL)
                    {
                        // A match has been found

                        // NS case

                        if(type == TYPE_NS)
                        {
                            /* If the label is a delegation, the NS have to be added into authority,
                             * else they have to be added into answer.
                             */

                            // Add the NS records in random order in the right section

                            uint16_t *target_section_countp;

                            if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                            {
                                target_section_countp = &context->authority_count;
                            }
                            else
                            {
                                target_section_countp = &context->answer_count;
                            }

                            zdb_query_to_wire_context_add_ns_rrset(context, type_rrset, zone);

                            *target_section_countp += zdb_query_to_wire_append_ns_from_rrset(context, qname, type_rrset);
#if ZDB_HAS_DNSSEC_SUPPORT
                            // Append all the RRSIG of NS from the label

                            if(dnssec)
                            {
                                *target_section_countp += zdb_query_to_wire_append_type_rrsigs(context, rr_label, qname, TYPE_NS, zdb_resource_record_set_ttl(type_rrset));

                                if(zdb_rr_label_flag_isset(rr_label, ZDB_RR_LABEL_DELEGATION))
                                {
                                    uint16_t                   count = 0;

                                    zdb_resource_record_set_t *ds_rrset = zdb_resource_record_sets_find(&rr_label->resource_record_set, TYPE_DS);

                                    if(ds_rrset != NULL)
                                    {
                                        count += zdb_query_to_wire_append_from_rrset(context, qname, ds_rrset);
                                        count += zdb_query_to_wire_append_type_rrsigs(context, rr_label, qname, TYPE_DS, zdb_resource_record_set_ttl(ds_rrset));
                                    }
#if ZDB_HAS_NSEC3_SUPPORT
                                    else if(ZONE_NSEC3_AVAILABLE(zone))
                                    {
                                        /**
                                         * If there is an NSEC3 RR that matches the delegation name, then that
                                         * NSEC3 RR MUST be included in the response.  The DS bit in the type
                                         * bit maps of the NSEC3 RR MUST NOT be set.
                                         *
                                         * If the zone is Opt-Out, then there may not be an NSEC3 RR
                                         * corresponding to the delegation.  In this case, the closest provable
                                         * encloser proof MUST be included in the response.  The included NSEC3
                                         * RR that covers the "next closer" name for the delegation MUST have
                                         * the Opt-Out flag set to one.  (Note that this will be the case unless
                                         * something has gone wrong).
                                         *
                                         */

                                        count += zdb_query_to_wire_append_nsec3_delegation(context, zone, &rr_label_info, &name, top);
                                    }
#endif
#if ZDB_HAS_NSEC_SUPPORT
                                    else if(ZONE_NSEC_AVAILABLE(zone))
                                    {
                                        /*
                                         * Append the NSEC of rr_label and all its signatures
                                         */

                                        count += zdb_query_to_wire_append_nsec_records(context, rr_label, qname);
                                    }

                                    context->authority_count += count;
#endif
                                } // else not a delegation
                            } // else not dnssec
#endif

                            /*
                             * authority is never required since we have it already
                             *
                             * fetch all the additional records for the required type (NS and MX types)
                             * add them to the additional section
                             */

                            // for all NS, add the matching IP

                            context->additionals_added = additionals_required;
                            context->additionals_with_rrsig = dnssec;
                        }
                        else // not type NS : general case
                        {
                            // authority_required = false;

                            if(type != TYPE_RRSIG)
                            {
                                // Add the records from the answer in random order to the answer section
                                context->answer_count += zdb_query_to_wire_append_from_rrset(context, qname, type_rrset);
#if ZDB_HAS_DNSSEC_SUPPORT
                                // Append all the RRSIG of NS from the label

                                if(dnssec)
                                {
                                    context->answer_count += zdb_query_to_wire_append_type_rrsigs(context, rr_label, qname, type, zdb_resource_record_set_ttl(type_rrset));

                                    if(IS_WILD_LABEL(rr_label->name))
                                    {
                                        /**
                                         * If there is a wildcard match for QNAME and QTYPE, then, in addition
                                         * to the expanded wildcard RRSet returned in the answer section of the
                                         * response, proof that the wildcard match was valid must be returned.
                                         *
                                         * This proof is accomplished by proving that both QNAME does not exist
                                         * and that the closest encloser of the QNAME and the immediate ancestor
                                         * of the wildcard are the same (i.e., the correct wildcard matched).
                                         *
                                         * To this end, the NSEC3 RR that covers the "next closer" name of the
                                         * immediate ancestor of the wildcard MUST be returned.
                                         * It is not necessary to return an NSEC3 RR that matches the closest
                                         * encloser, as the existence of this closest encloser is proven by
                                         * the presence of the expanded wildcard in the response.
                                         */
#if ZDB_HAS_NSEC3_SUPPORT
                                        if(ZONE_NSEC3_AVAILABLE(zone))
                                        {
                                            context->authority_count += zdb_query_to_wire_append_wild_nsec3_data(context, zone, &name, top);
                                        }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                        else
#endif
                                        if(ZONE_NSEC_AVAILABLE(zone)) // add the NSEC of the wildcard and its signature(s)
                                        {
                                            context->authority_count += zdb_query_to_wire_append_nsec_interval(context, zone, &name, NULL);
                                        }
#endif
                                    }
                                }
#endif
                                // if authority required

                                /*
                                 * fetch all the additional records for the required type (NS and MX types)
                                 * add them to the additional section
                                 */

                                context->additionals_added = additionals_required;
                                context->additionals_with_rrsig = false;
                            }
                            else // TYPE = RRSIG
                            {
                                context->answer_count += dns_packet_writer_add_rrsig_rrset(&context->pw, qname, type_rrset);
#if ZDB_HAS_DNSSEC_SUPPORT
                                if(dnssec)
                                {
                                    // don't add RRSIG's RRSIGs : context->answer_count +=
                                    // zdb_query_to_wire_append_type_rrsigs(context, rr_label, qname, type,
                                    // zdb_resource_record_set_ttl(type_rrset));

                                    if(IS_WILD_LABEL(rr_label->name))
                                    {
                                        /**
                                         * If there is a wildcard match for QNAME and QTYPE, then, in addition
                                         * to the expanded wildcard RRSet returned in the answer section of the
                                         * response, proof that the wildcard match was valid must be returned.
                                         *
                                         * This proof is accomplished by proving that both QNAME does not exist
                                         * and that the closest encloser of the QNAME and the immediate ancestor
                                         * of the wildcard are the same (i.e., the correct wildcard matched).
                                         *
                                         * To this end, the NSEC3 RR that covers the "next closer" name of the
                                         * immediate ancestor of the wildcard MUST be returned.
                                         * It is not necessary to return an NSEC3 RR that matches the closest
                                         * encloser, as the existence of this closest encloser is proven by
                                         * the presence of the expanded wildcard in the response.
                                         */
#if ZDB_HAS_NSEC3_SUPPORT
                                        if(ZONE_NSEC3_AVAILABLE(zone))
                                        {
                                            context->authority_count += zdb_query_to_wire_append_wild_nsec3_data(context, zone, &name, top);
                                        }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                        else
#endif
                                        if(ZONE_NSEC_AVAILABLE(zone))
                                        {
                                            context->authority_count += zdb_query_to_wire_append_nsec_interval(context, zone, &name, NULL);
                                        }
#endif
                                    }
                                }
#endif
                            }
                        }
#if DEBUG
                        log_debug("zdb_query_ex: FP_BASIC_RECORD_FOUND");
#endif
                        dns_message_set_answer(mesg);
                        dns_message_set_answer_count(mesg, context->answer_count);
                        dns_message_set_authority_count(mesg, context->authority_count);
                        dns_message_set_size(mesg, context->pw.packet_offset);

                        return FP_BASIC_RECORD_FOUND;
                    } // if found the record of the requested type
                    else // no record found
                    {
                        // label but no record

                        /**
                         * Got the label, but not the record.
                         * This should branch to NSEC3 if it is supported.
                         */

                        finger_print fp = (finger_print)zdb_query_to_wire_record_not_found(context, zone, &rr_label_info, qname, &name, top, type, dnssec, zdb_query_to_wire_append_soa_authority_nttl);
#if DEBUG
                        log_debug("zdb_query_ex: FP_BASIC_RECORD_NOTFOUND (done)");
#endif

#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
                        dns_message_set_answer(mesg);
                        dns_message_set_rcode(mesg, fp);
#else
                            dns_message_or_answer_rcode_var(mesg, fp);
#endif

                        dns_message_set_authority_count(context->mesg, context->authority_count);
                        dns_message_set_size(context->mesg, context->pw.packet_offset);

                        return fp;
                    }
                }
                else /* We got the label BUT type == TYPE_ANY */
                {
                    if(zdb_rr_label_flag_isclear(rr_label, ZDB_RR_LABEL_DELEGATION | ZDB_RR_LABEL_UNDERDELEGATION))
                    {
#if ZDB_HAS_DNSSEC_SUPPORT
                        zdb_resource_record_set_t *rrsig_rrset = zdb_resource_record_sets_find(&rr_label->resource_record_set, TYPE_RRSIG);
#endif

                        bool answers = false;

                        /* We do iterate on ALL the types of the label */

                        zdb_resource_record_sets_set_iterator_t iter;
                        zdb_resource_record_sets_set_iterator_init(&rr_label->resource_record_set, &iter);
                        while(zdb_resource_record_sets_set_iterator_hasnext(&iter))
                        {
                            zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_iterator_next_node(&iter);
                            uint16_t                         type = zdb_resource_record_set_type(&rrset_node->value);

                            answers = true;

                            zdb_resource_record_set_t *rrset = &rrset_node->value;

                            /**
                             * @note: doing the list once may be faster ...
                             *        And YES maybe, because of the jump and because the list is supposed to
                             *        be VERY small (like 1-3)
                             */

                            if(zdb_resource_record_set_isempty(rrset))
                            {
                                continue;
                            }

                            switch(type)
                            {
                                case TYPE_SOA:
                                {
                                    // soa = zdb_resource_record_set_record_get_const(rrset, 0);
                                    authority_required = false;
                                    break;
                                }
                                case TYPE_NS:
                                {
                                    /* NO NEED FOR AUTHORITY */
                                    authority_required = false;
                                    if(additionals_required)
                                    {
                                        zdb_query_to_wire_context_add_ns_rrset(context, rrset, zone);
                                    }
                                    break;
                                }
                                case TYPE_CNAME:
                                {
                                    if(additionals_required)
                                    {
                                        switch(zdb_resource_record_set_type(rrset))
                                        {
                                            case TYPE_NS:
                                                zdb_query_to_wire_context_add_ns_rrset(context, rrset, zone);
                                                break;
                                            case TYPE_MX:
                                                zdb_query_to_wire_context_add_mx_rrset(context, rrset, zone);
                                                break;
                                            default:
                                                break;
                                        }
                                    }
                                    break;
                                }
                                case TYPE_MX:
                                {
                                    if(additionals_required)
                                    {
                                        zdb_query_to_wire_context_add_mx_rrset(context, rrset, zone);
                                    }
                                    break;
                                }
                                case TYPE_RRSIG:
                                {
                                    // signatures will be added by type
                                    continue;
                                }
                                default:
                                {
                                    break;
                                }
                            }

                            context->answer_count += zdb_query_to_wire_append_from_rrset(context, qname, rrset);
#if ZDB_HAS_DNSSEC_SUPPORT
                            if(rrsig_rrset != NULL)
                            {
                                context->answer_count += zdb_query_to_wire_append_type_rrsigs(context, rr_label, qname, type, zdb_resource_record_set_ttl(rrset));
                            }
#endif
                        }

                        if(answers)
                        {
                            if(authority_required) // not at or under a delegation
                            {
                                context->authority_count += zdb_query_to_wire_append_authority(context, qname, &rr_label_info, zone, dnssec);

                            } /* if authority required */
#if ZDB_HAS_DNSSEC_SUPPORT
                            if(dnssec && IS_WILD_LABEL(rr_label->name))
                            {
                                /**
                                 * If there is a wildcard match for QNAME and QTYPE, then, in addition
                                 * to the expanded wildcard RRSet returned in the answer section of the
                                 * response, proof that the wildcard match was valid must be returned.
                                 *
                                 * This proof is accomplished by proving that both QNAME does not exist
                                 * and that the closest encloser of the QNAME and the immediate ancestor
                                 * of the wildcard are the same (i.e., the correct wildcard matched).
                                 *
                                 * To this end, the NSEC3 RR that covers the "next closer" name of the
                                 * immediate ancestor of the wildcard MUST be returned.
                                 * It is not necessary to return an NSEC3 RR that matches the closest
                                 * encloser, as the existence of this closest encloser is proven by
                                 * the presence of the expanded wildcard in the response.
                                 */
#if ZDB_HAS_NSEC3_SUPPORT
                                if(ZONE_NSEC3_AVAILABLE(zone))
                                {
                                    context->authority_count += zdb_query_to_wire_append_wild_nsec3_data(context, zone, &name, top);
                                }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                else
#endif
                                if(ZONE_NSEC_AVAILABLE(zone))
                                {
                                    // add the NSEC of the wildcard and its signature(s)

                                    context->authority_count += zdb_query_to_wire_append_nsec_interval(context, zone, &name, NULL);
                                }
#endif
                            }
#endif // ZDB_HAS_DNSSEC_SUPPORT
                            context->additionals_added = additionals_required;
                            context->additionals_with_rrsig = false;
#if DEBUG
                            log_debug("zdb_query_ex: FP_BASIC_RECORD_FOUND (any)");
#endif
                            dns_message_set_authoritative_answer(mesg);
                            dns_message_set_answer_count(mesg, context->answer_count);
                            dns_message_set_authority_count(mesg, context->authority_count);
                            dns_message_set_size(mesg, context->pw.packet_offset);

                            return FP_BASIC_RECORD_FOUND;
                        }
                        else
                        {
                            // no records found ...

                            finger_print fp = (finger_print)zdb_query_to_wire_record_not_found(context, zone, &rr_label_info, qname, &name, top, type, dnssec, zdb_query_to_wire_append_soa_authority_nttl);

#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
                            dns_message_set_authoritative_answer(mesg);
                            dns_message_set_rcode(mesg, fp);
#else
                                dns_message_or_authoritative_answer_rcode_var(mesg, fp);
#endif
                            dns_message_set_authority_count(context->mesg, context->authority_count);
                            dns_message_set_size(context->mesg, context->pw.packet_offset);
                            return fp;
                        }
                    }
                    else // ANY, at or under a delegation
                    {
                        zdb_query_to_wire_record_not_found(context, zone, &rr_label_info, qname, &name, top, 0, dnssec, zdb_query_to_wire_append_soa_authority);

                        dns_message_set_answer(mesg);
                        dns_message_set_authority_count(context->mesg, context->authority_count);
                        dns_message_set_size(context->mesg, context->pw.packet_offset);

                        return FP_BASIC_RECORD_FOUND;
                    }
                }
            } /* end of if rr_label != NULL => */
            else /* rr_label == NULL */
            {
                zdb_rr_label_t *rr_label_authority = rr_label_info.authority;

                if(rr_label_authority != zone->apex)
                {
                    dns_message_set_answer(mesg);
                    dns_message_clear_authoritative(mesg);

                    zdb_resource_record_set_t *authority_rrset = zdb_resource_record_sets_find(&rr_label_authority->resource_record_set, TYPE_NS);

                    if(authority_rrset != NULL)
                    {
                        const uint8_t *authority_qname = zdb_rr_label_info_get_authority_qname(qname, &rr_label_info);

                        uint16_t       count = zdb_query_to_wire_append_ns_from_rrset(context, authority_qname, authority_rrset);

                        if(dnssec)
                        {
#if ZDB_HAS_DNSSEC_SUPPORT
                            count += zdb_query_to_wire_append_type_rrsigs(context, rr_label_authority, authority_qname, TYPE_NS, zdb_resource_record_set_ttl(authority_rrset));
#endif
                            zdb_resource_record_set_t *delegation_signer_rrset = zdb_resource_record_sets_find(&rr_label_authority->resource_record_set, TYPE_DS);

                            if(delegation_signer_rrset != NULL)
                            {
                                count += zdb_query_to_wire_append_from_rrset(context, authority_qname, delegation_signer_rrset);
                                count += zdb_query_to_wire_append_type_rrsigs(context, rr_label_authority, authority_qname, TYPE_DS, zdb_resource_record_set_ttl(delegation_signer_rrset));
                            }
                            else
                            {
#if ZDB_HAS_NSEC3_SUPPORT
                                if(ZONE_NSEC3_AVAILABLE(zone))
                                {
                                    // add ... ? it looks like the record that covers the path that has been found in
                                    // the zone is used for the digest, then the interval is shown add apex NSEC3
                                    // (wildcard)

                                    zdb_query_to_wire_append_nsec3_delegation(context, zone, &rr_label_info, &name, top);
                                }
#endif
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
                                else
#endif
                                    if(ZONE_NSEC_AVAILABLE(zone))
                                {
                                    /*
                                     * Append the NSEC of rr_label and all its signatures
                                     */

                                    context->authority_count += zdb_query_to_wire_append_nsec_records(context, rr_label_authority, authority_qname);
                                }
#endif
                            }

                            context->additional_count += zdb_query_to_wire_append_glues_from_ns(context, zone, authority_rrset, false);
                        }
                        else
                        {
                            context->additional_count += zdb_query_to_wire_append_glues_from_ns(context, zone, authority_rrset, false);
                        }
#if DEBUG
                        log_debug("zdb_query_ex: FP_BASIC_LABEL_NOTFOUND (done)");
#endif
                        context->delegation = true; // no answer, NS records in authority : referral
                        context->authority_count += count;

                        dns_message_set_rcode(mesg, FP_BASIC_LABEL_DELEGATION);

                        dns_message_set_answer_count(mesg, context->answer_count);
                        dns_message_set_authority_count(mesg, context->authority_count);
                        dns_message_set_size(mesg, context->pw.packet_offset);

                        return FP_BASIC_LABEL_DELEGATION;
                    }
                }
                else
                {
                    dns_message_set_authoritative_answer(mesg);
                }
            }

            // label not found: We stop the processing and fall through NSEC(3) or the basic case.

            // note: at this point, no authority RRSET have been added to the context so there is
            // no need to keep a lock on the zone

            assert(context->ns_rrset_count + context->mx_rrset_count == 0);
            zdb_zone_read_unlock(zone);
            context->locked_zones_count--;

            break; // stop looking, skip cache

        } /* if(zone!=NULL) */

        sp--;
    } /* while ... */

    /*************************************************
     *                                               *
     * At this point we are not an authority anymore. *
     *                                               *
     *************************************************/
#if ZDB_HAS_RRCACHE_ENABLED
    /* We exhausted the zone files direct matches.
     * We have to fallback on the global (cache) matches.
     * And it's easy because we have the answer already:
     */

    if(!found_zones && (top == name.size))
    {
        /* We found a perfect match label in the global part of the database */

        if((answer = zdb_resource_record_sets_find(&zone_label_stack[top]->global_resource_record_set, type)) != NULL)
        {
            /* *ttlrdata_out for the answer */
            /* How do I find "authority" ? */
            /* From authority, it's easy to find the additionals */

            zdb_query_ex_answer_appendrndlist(answer, qname, PASS_ZCLASS_PARAMETER type, &ans_auth_add->answer, pool);
            /*
            ans_auth_add->authority=NULL;
            ans_auth_add->additional=NULL;
            */
            return FP_BASIC_RECORD_FOUND;
        }
        else
        {
            /// @todo 20140526 edf -- CACHE resolve the name to answer (dns cache)
        }
    }
#endif

    /*if(authority_required) { */
    /*
     * Get the most relevant label (lowest zone).
     * Try to do NSEC3 or NSEC with it.
     */

    zdb_zone_t *zone;

#if DEBUG
    zone = (zdb_zone_t *)~0;
#endif

    sp = top; // top >= 0, so we can enter here and zone is assigned

    yassert(sp >= 0);

    while(sp >= 0) // scan-build false positive: we ALWAYS get into this loop at least once
    {
        zdb_zone_label_t *zone_label = zone_label_stack[sp--];

        if((zone = zone_label->zone) != NULL) // scan-build false positive: one alleged error relies on this being both
                                              // NULL and not NULL at the same time (with zone_label_stack[sp=0]).
        {
            // if type == DS && zone->origin = qname then the return value is NOERROR instead of NXDOMAIN
            break;
        }
    }

    if(zone == NULL) // zone is ALWAYS assigned because top is >= 0 (several false-positive)
    {
#if DEBUG
        log_debug("zdb_query_ex: FP_NOZONE_FOUND (2)");
#endif

#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
        dns_message_set_answer(mesg);
        dns_message_set_rcode(mesg, FP_NOZONE_FOUND);
#else
            dns_message_or_answer_rcode(mesg, FP_NOZONE_FOUND);
#endif

        return FP_NOZONE_FOUND;
    }

    // note: no need to use the stack here: there is no authority requiring additionals beyond this point
    zdb_zone_read_lock(zone);

    if(!zdb_zone_invalid(zone))
    {
        // zone is the most relevant zone
#if DNSCORE_HAS_RRL_SUPPORT
        context->fqdn_label = zone->apex;
#endif
#if ZDB_HAS_DNSSEC_SUPPORT
        if(dnssec)
        {
#if ZDB_HAS_NSEC3_SUPPORT
            if(ZONE_NSEC3_AVAILABLE(zone))
            {
                context->authority_count += zdb_query_to_wire_append_nsec3_name_error(context, zone, &name, top);
                context->authority_count += zdb_query_to_wire_append_soa_rrsig_nodata_nxdomain(context, zone);
                zdb_zone_read_unlock(zone);
#if DEBUG
                log_debug("zdb_query_ex: FP_NSEC3_LABEL_NOTFOUND (done)");
#endif
                dns_message_set_answer_count(mesg, context->answer_count);
                dns_message_set_authority_count(mesg, context->authority_count);
                dns_message_set_size(mesg, context->pw.packet_offset);
#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
                dns_message_set_rcode(mesg, FP_NSEC3_LABEL_NOTFOUND);
#else
                dns_message_or_rcode(mesg, FP_NSEC3_LABEL_NOTFOUND);
#endif
                return FP_NSEC3_LABEL_NOTFOUND;
            }
#endif // ZDB_HAS_NSEC3_SUPPORT != 0
       // NSEC, if possible
#if ZDB_HAS_NSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
            else // Following will be either the NSEC answer or just the SOA added in the authority
#endif
            if(ZONE_NSEC_AVAILABLE(zone))
            {
                // Get the SOA + NSEC + RRIGs for the zone
                context->authority_count += zdb_query_to_wire_append_nsec_name_error(context, zone, &name, rr_label_info.closest_index); // scan-build false positive
                // scan builds says closest_index is uninitialised but goes through a contradiction (not found -> found) reach its conclusion
                context->authority_count += zdb_query_to_wire_append_soa_rrsig_nttl(context, zone);
                zdb_zone_read_unlock(zone);
#if DEBUG
                log_debug("zdb_query_ex: FP_NSEC_LABEL_NOTFOUND (done)");
#endif
                dns_message_set_answer_count(mesg, context->answer_count);
                dns_message_set_authority_count(mesg, context->authority_count);
                dns_message_set_size(mesg, context->pw.packet_offset);
#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
                dns_message_set_rcode(mesg, FP_NSEC_LABEL_NOTFOUND);
#else
                dns_message_or_rcode(mesg, FP_NSEC_LABEL_NOTFOUND);
#endif

                return FP_NSEC_LABEL_NOTFOUND;
            }
#endif // ZDB_HAS_NSEC_SUPPORT
        }
#endif // ZDB_HAS_DNSSEC_SUPPORT

        context->authority_count += zdb_query_to_wire_append_soa_nodata_nxdomain(context, zone);
        zdb_zone_read_unlock(zone);

#if DEBUG
        log_debug("zdb_query_ex: FP_BASIC_LABEL_NOTFOUND (done)");
#endif
        dns_message_set_answer_count(mesg, context->answer_count);
        dns_message_set_authority_count(mesg, context->authority_count);
        dns_message_set_size(mesg, context->pw.packet_offset);

#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
        dns_message_set_rcode(mesg, FP_BASIC_LABEL_NOTFOUND);
#else
            dns_message_or_rcode(mesg, FP_BASIC_LABEL_NOTFOUND);
#endif

        return FP_BASIC_LABEL_NOTFOUND;
    }
    else // if(!zdb_zone_invalid(zone))
    {
#if DEBUG
        log_debug("zdb_query_ex: FP_ZONE_EXPIRED (2)");
#endif
        zdb_zone_read_unlock(zone);

        dns_message_set_answer_count(mesg, context->answer_count);
        dns_message_set_authority_count(mesg, context->authority_count);
        dns_message_set_size(mesg, context->pw.packet_offset);

#if !ZDB_QUERY_TO_WIRE_ASSUME_ZERO
        dns_message_set_rcode(mesg, FP_INVALID_ZONE);
#else
            dns_message_or_rcode(mesg, FP_INVALID_ZONE);
#endif
        return FP_INVALID_ZONE;
    }
}

/**
 * Releases resources and database an zone locks associated to the context.
 * Must ALWAYS be called to conclude a call to zdb_query_to_wire_context_init
 *
 * @param context
 */

void zdb_query_to_wire_finalize(zdb_query_to_wire_context_t *context)
{
    dns_message_t *mesg = context->mesg;
    dns_message_set_referral(mesg, context->delegation);

    if(context->additionals_added && (context->record_type != TYPE_ANY))
    {
        // in a single RRSET there is no chance of duplicates, so
        if(context->ns_rrset_count + context->mx_rrset_count == 1)
        {
            if(context->ns_rrset_count != 0)
            {
                context->additional_count += zdb_query_to_wire_append_glues_from_ns(context, context->ns_rrsets[0].zone, context->ns_rrsets[0].rrset, context->additionals_with_rrsig);
            }
            else
            {
                context->additional_count += zdb_query_to_wire_append_glues_from_mx(context, context->mx_rrsets[0].zone, context->mx_rrsets[0].rrset, context->additionals_with_rrsig);
            }
        }
        else
        {
            // cleanup duplicates
            // note: dnsname_set cannot be used here as the zone associated to the ns_record has to be used;

            struct dnsname_zone_dict_s dnsname_zone_dict;
            dnsname_zone_dict_init(&dnsname_zone_dict);

            // add the FQDNs from the NS rrsets

            for(uint_fast8_t i = 0; i < context->ns_rrset_count; ++i)
            {
                zdb_resource_record_set_const_iterator iter;
                zdb_resource_record_set_const_iterator_init(context->ns_rrsets[i].rrset, &iter);
                while(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    const zdb_resource_record_data_t *ns_record = zdb_resource_record_set_const_iterator_next(&iter);
                    const uint8_t *fqdn = zdb_resource_record_data_rdata_const(ns_record);
                    dnsname_zone_dict_insert(&dnsname_zone_dict, fqdn, context->ns_rrsets[i].zone);
                }
            }

            // add the FQDNs from the MX rrsets

            for(uint_fast8_t i = 0; i < context->mx_rrset_count; ++i)
            {
                zdb_resource_record_set_const_iterator iter;
                zdb_resource_record_set_const_iterator_init(context->mx_rrsets[i].rrset, &iter);
                while(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    const zdb_resource_record_data_t *mx_record = zdb_resource_record_set_const_iterator_next(&iter);
                    const uint8_t *fqdn = zdb_resource_record_data_rdata_const(mx_record) + 2;      // +2 because it's an MX rdata
                    dnsname_zone_dict_insert(&dnsname_zone_dict, fqdn, context->mx_rrsets[i].zone);
                }
            }

            // add the glues from the remaining FQDNs

            for(int i = 0; i < dnsname_zone_dict.count; ++i)
            {
                context->additional_count += zdb_query_to_wire_append_ips(context, dnsname_zone_dict.nodes[i].zone, dnsname_zone_dict.nodes[i].fqdn, context->additionals_with_rrsig);
            }
        }
    }

    // unlock the locked zones

    while(context->locked_zones_count > 0)
    {
        zdb_zone_read_unlock(context->locked_zones[--context->locked_zones_count]);
    }

    // unlock the database

    zdb_unlock(context->db, ZDB_MUTEX_READER);

    if(dns_message_has_edns0(mesg))
    {
        dns_packet_writer_t *pw = &context->pw;
        uint16_t             edns0_maxsize = dns_message_edns0_getmaxsize();
#if ZDB_HAS_NSID_SUPPORT
        switch(dns_message_opt_get(mesg))
        {
            case MESSAGE_OPT_EDNS0:
            {
                if(pw->packet_limit - pw->packet_offset >= EDNS0_RECORD_SIZE)
                {
                    memset(&pw->packet[pw->packet_offset], 0, EDNS0_RECORD_SIZE);
                    pw->packet_offset += 2;
                    pw->packet[pw->packet_offset++] = 0x29;
                    dns_packet_writer_add_u16(pw, htons(edns0_maxsize));
                    dns_packet_writer_add_u32(pw, dns_message_get_edns0_opt_ttl(mesg));
                    pw->packet_offset += 2; // rdata size already set to 0 with the memset above, skip it

                    dns_message_set_additional_count(mesg, context->additional_count + 1);
                }
                else
                {
                    dns_packet_writer_set_truncated(pw);
                }
                break;
            }
            case MESSAGE_OPT_EDNS0 | MESSAGE_OPT_NSID:
            {
                if(pw->packet_limit - pw->packet_offset >= 9 + edns0_rdatasize_nsid_option_wire_size)
                {
                    dns_packet_writer_add_u16(pw, 0);       // fqdn + 1st half of type : 00 0029
                    pw->packet[pw->packet_offset++] = 0x29; // 2nd half of type

                    dns_packet_writer_add_u16(pw, htons(edns0_maxsize));                // e.g. 1000
                    dns_packet_writer_add_u32(pw, dns_message_get_edns0_opt_ttl(mesg)); // rcode (32 bits)

                    dns_packet_writer_add_bytes(pw, edns0_rdatasize_nsid_option_wire, edns0_rdatasize_nsid_option_wire_size); // full NSID rdata

                    dns_message_set_additional_count(mesg, context->additional_count + 1);
                }
                else
                {
                    dns_packet_writer_set_truncated(pw);
                }
                break;
            }
            case MESSAGE_OPT_EDNS0 | MESSAGE_OPT_NSID | MESSAGE_OPT_COOKIE:
            {
                if(pw->packet_limit - pw->packet_offset >= 9 + edns0_rdatasize_nsid_option_wire_size + 20)
                {
                    dns_packet_writer_add_u16(pw, 0);       // fqdn + 1st half of type : 00 0029
                    pw->packet[pw->packet_offset++] = 0x29; // 2nd half of type

                    dns_packet_writer_add_u16(pw, htons(edns0_maxsize));                // e.g. 1000
                    dns_packet_writer_add_u32(pw, dns_message_get_edns0_opt_ttl(mesg)); // rcode (32 bits)

                    dns_packet_writer_add_bytes(pw, edns0_rdatasize_nsid_cookie_option_wire,
                                                edns0_rdatasize_nsid_option_wire_size); // full NSID rdata

                    dns_packet_writer_add_u32(pw, NU32(0x000a0010));
                    dns_packet_writer_add_bytes(pw, mesg->_cookie.bytes, DNS_MESSAGE_COOKIE_CLIENT_SIZE + DNS_MESSAGE_COOKIE_SERVER_SIZE);

                    dns_message_set_additional_count(mesg, context->additional_count + 1);
                }
                else
                {
                    dns_packet_writer_set_truncated(pw);
                }
                break;
            }
            case MESSAGE_OPT_EDNS0 | MESSAGE_OPT_COOKIE:
            {
                if(pw->packet_limit - pw->packet_offset >= 9 + 22)
                {
                    dns_packet_writer_add_u16(pw, 0);       // fqdn + 1st half of type : 00 0029
                    pw->packet[pw->packet_offset++] = 0x29; // 2nd half of type

                    dns_packet_writer_add_u16(pw, htons(edns0_maxsize));                // e.g. 1000
                    dns_packet_writer_add_u32(pw, dns_message_get_edns0_opt_ttl(mesg)); // rcode (32 bits)

                    dns_packet_writer_add_u32(pw, NU32(0x0014000a)); // size of the message + 4, then the code and the
                                                                     // length (the reason of the +4) and the message
                    dns_packet_writer_add_u16(pw, NU16(0x0010));
                    dns_packet_writer_add_bytes(pw, mesg->_cookie.bytes, DNS_MESSAGE_COOKIE_CLIENT_SIZE + DNS_MESSAGE_COOKIE_SERVER_SIZE);

                    dns_message_set_additional_count(mesg, context->additional_count + 1);
                }
                else
                {
                    dns_packet_writer_set_truncated(pw);
                }
                break;
            }
                // there is no other possible value
        }

#else
            dns_message_increase_buffer_size(mesg, EDNS0_RECORD_SIZE); /* edns0 opt record */

            pw->packet_limit += EDNS0_RECORD_SIZE;

            memset(&pw->packet[pw->packet_offset], 0, EDNS0_RECORD_SIZE);
            pw->packet_offset += 2;
            pw->packet[pw->packet_offset++] = 0x29;
            dns_packet_writer_add_u16(pw, htons(edns0_maxsize));
            dns_packet_writer_add_u32(pw, dns_message_get_edns0_opt_ttl(mesg));
            pw->packet_offset += 2; // rdata size already set to 0 with the memset above, skip it
#endif
    }

    dns_message_set_size(mesg, context->pw.packet_offset);

#if DNSCORE_HAS_TSIG_SUPPORT
    if(dns_message_has_tsig(mesg)) /* NOTE: the TSIG information is in mesg */
    {
        tsig_sign_answer(mesg);
    }
#endif
}

/** @} */

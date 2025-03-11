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

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <stdlib.h>

/*
 *  RFC 5155
 *
 *  Server Response to a Run-Time Collision
 *
 *  If the hash of a non-existing QNAME collides with the owner name of
 *  an existing NSEC3 RR, then the server will be unable to return a
 *  response that proves that QNAME does not exist.  In this case, the
 *  server MUST return a response with an RCODE of 2 (server failure).
 *
 *  Note that with the hash algorithm specified in this document, SHA-1,
 *  such collisions are highly unlikely.
 *
 */

#include "dnsdb/zdb_types.h"

#if !ZDB_HAS_NSEC3_SUPPORT
#error nsec3.c should not be compiled when ZDB_HAS_NSEC3_SUPPORT == 0
#endif

#include <dnscore/dnsname.h>
#include <dnscore/base32hex.h>
#include <dnscore/rfc.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/logger.h>
#include <dnscore/dnskey_signature.h>

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/nsec3.h"
#include "dnsdb/nsec_common.h"
#include "dnsdb/nsec3_owner.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/dynupdate_diff.h"
#include "dnsdb/dynupdate_message.h"

#if HAS_PRIMARY_SUPPORT
#include "dnsdb/zdb_zone_path_provider.h"
#endif

#define NSEC3_ZONE_LABEL_UPDATE_CHAIN_LINKS_DEBUG 0

#if NSEC3_UPDATE_ZONE_DEBUG
#pragma message("NSEC3_UPDATE_ZONE_DEBUG enabled, disable this for release builds")
#endif

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle_t *g_dnssec_logger;

#define N3IRRVDT_TAG 0x544456525249334e
#define RRVDATA_TAG  0x41544144565252

/**
 * used by nsec3_label_link
 *
 * It will find if the label has got a matching NSEC3 record (by digest)
 * If so, it will link to it.
 */

static nsec3_zone_item_t *nsec3_label_link_seeknode(nsec3_zone_t *n3, const uint8_t *fqdn, int32_t fqdn_len, uint8_t *digest)
{
    nsec3_compute_digest_from_fqdn_with_len(n3, fqdn, fqdn_len, digest, false);

#if NSEC3_UPDATE_ZONE_DEBUG
    log_debug("nsec3: seeking node for %{dnsname} with %{digest32h}", fqdn, digest);
#endif

    nsec3_zone_item_t *self = nsec3_find(&n3->items, digest);

    return self;
}

/**
 * used by nsec3_label_link
 *
 * It will find if the *.label has got a matching NSEC3 record (by digest)
 * If so, it will link to it.
 */

static nsec3_zone_item_t *nsec3_label_link_seekstar(nsec3_zone_t *n3, const uint8_t *fqdn, int32_t fqdn_len, uint8_t *digest)
{
    nsec3_compute_digest_from_fqdn_with_len(n3, fqdn, fqdn_len, digest, true);

#if NSEC3_UPDATE_ZONE_DEBUG
    log_debug("nsec3: seeking star for %{dnsname} with %{digest32h}", fqdn, digest);
#endif

    nsec3_zone_item_t *star = nsec3_find_interval_start(&n3->items, digest);

    return star;
}

/*
 * This destroy all the NSEC3 structures from the zone, starting from the NSEC3PARAM.
 * The zdb_rr_label are also affected by the call.
 */

void nsec3_destroy_zone(zdb_zone_t *zone)
{
    // Note that from the 'transaction' update, the dnssec zone collections have to be read without checking for the
    // NSEC3 flag

    while(zone->nsec.nsec3 != NULL)
    {
#if DEBUG
        nsec3_zone_t *n3 = zone->nsec.nsec3;
#endif
        nsec3_zone_destroy(zone, zone->nsec.nsec3);
#if DEBUG
        yassert(n3 != zone->nsec.nsec3);
#endif
    }
}

/******************************************************************************
 *
 * NSEC3 - queries
 *
 *****************************************************************************/

/**
 * @brief Finds the provable resource record label matching a path of labels starting from another rr label
 *
 * Finds the resource record label matching a path of labels starting from another rr label
 * Typically the starting label is a zone cut.
 * The starting point MUST be provable (ie: the apex in NSEC and in NSEC3 zones)
 *
 * @param[in] apex the starting label
 * @param[in] path a stack of labels
 * @param[in] path_index the index of the top of the stack
 *
 * @return the matching label or NULL if it has not been found
 */

/* NSEC3: Zone possible */
static int nsec3_get_closest_provable_encloser_match(const void *label, const dictionary_node *node)
{
    zdb_rr_label_t *rr_label = (zdb_rr_label_t *)node;
    return dnslabel_equals(rr_label->name, label);
}

/**
 *
 * Finds what is the closest provable encloser for a label in a zone
 *
 * @param apex
 * @param sections
 * @param sections_topp
 * @return
 */

const zdb_rr_label_t *nsec3_get_closest_provable_encloser_optin(const zdb_rr_label_t *apex, const_dnslabel_vector_reference_t sections, int32_t *sections_topp)
{
    yassert((apex != NULL) && (sections != NULL) && (sections_topp != NULL));

    int32_t               index = *sections_topp;
    const zdb_rr_label_t *rr_label = apex; /* the zone cut */

    const zdb_rr_label_t *provable = apex;

    /*
     * the apex is already known, so we don't loop for it
     */

    index--;

    /* look into the sub level*/

    while(index >= 0)
    {
        const uint8_t *label = sections[index];
        hashcode       hash = hash_dnslabel(label);

        rr_label = (zdb_rr_label_t *)dictionary_find(&rr_label->sub, hash, label, nsec3_get_closest_provable_encloser_match);

        if(rr_label == NULL)
        {
            index++;
            break;
        }

        if(zdb_rr_label_flag_matches(rr_label, ZDB_RR_LABEL_N3COVERED))
        {
            provable = rr_label;
            *sections_topp = index;
        }

        index--;
    }

    return provable;
}

const zdb_rr_label_t *nsec3_get_closest_provable_encloser_optout(const zdb_rr_label_t *apex, const_dnslabel_vector_reference_t sections, int32_t *sections_topp)
{
    yassert(apex != NULL && sections != NULL && sections_topp != NULL);

    int32_t               index = *sections_topp;
    const zdb_rr_label_t *rr_label = apex; /* the zone cut */

    const zdb_rr_label_t *provable = apex;

    /*
     * the apex is already known, so we don't loop for it
     */

    index--;

    /* look into the sub level*/

    while(index >= 0)
    {
        const uint8_t *label = sections[index];
        hashcode       hash = hash_dnslabel(label);

        rr_label = (zdb_rr_label_t *)dictionary_find(&rr_label->sub, hash, label, nsec3_get_closest_provable_encloser_match);

        if(rr_label == NULL)
        {
            index++;
            break;
        }

        if(zdb_rr_label_flag_matches(rr_label, ZDB_RR_LABEL_N3OCOVERED))
        {
            provable = rr_label;
            *sections_topp = index;
        }
        /*
        else if(zdb_rr_label_flag_matches(rr_label, ZDB_RR_LABEL_GOT_WILD))
        {
            dictionary_iterator iter;
            dictionary_iterator_init(&rr_label->sub, &iter);
            if(dictionary_iterator_hasnext(&iter))
            {
                provable =  *(zdb_rr_label**)dictionary_iterator_next(&iter);
                *sections_topp = index - 1;
                break;
            }
        }
        */

        index--;
    }

    return provable;
}

static int zdb_label_wild_match(const void *label, const dictionary_node *node)
{
    (void)label;
    zdb_rr_label_t *rr_label = (zdb_rr_label_t *)node;
    return IS_WILD_LABEL(rr_label->name);
}

void nsec3_get_wild_match_and_closest_provable_encloser_optin(const zdb_rr_label_t *apex, const_dnslabel_vector_reference_t sections, int32_t sections_top, const zdb_rr_label_t **wild_matchp, int32_t *wild_topp,
                                                              const zdb_rr_label_t **provable_matchp, int32_t *provable_topp)
{
    yassert(apex != NULL && sections != NULL && wild_matchp != NULL && wild_topp != NULL && provable_matchp != NULL && provable_topp != NULL);

    int32_t               index = sections_top;
    const zdb_rr_label_t *rr_label = apex; /* the zone cut */
    *wild_matchp = NULL;
    *provable_matchp = apex;
    *provable_topp = sections_top;

    /*
     * the apex is already known, so we don't loop for it
     */

    index--;

    /* look into the sub level*/

    while(index >= 0)
    {
        const uint8_t        *label = sections[index];
        hashcode              hash = hash_dnslabel(label);

        const zdb_rr_label_t *sub_rr_label = (zdb_rr_label_t *)dictionary_find(&rr_label->sub, hash, label, nsec3_get_closest_provable_encloser_match);

        if(sub_rr_label == NULL)
        {
            if(rr_label == apex)
            {
                zdb_rr_label_t *rr_label_sub_wild = (zdb_rr_label_t *)dictionary_find(&rr_label->sub, WILD_LABEL_HASH, NULL, zdb_label_wild_match);
                *wild_matchp = rr_label_sub_wild;
                *wild_topp = sections_top - 1;

                if(zdb_rr_label_flag_matches(rr_label, ZDB_RR_LABEL_N3COVERED))
                {
                    *provable_matchp = rr_label;
                    *provable_topp = index;
                }
            }

            break;
        }

        rr_label = sub_rr_label;

        if(zdb_rr_label_flag_matches(rr_label, ZDB_RR_LABEL_GOT_WILD))
        {
            zdb_rr_label_t *rr_label_sub_wild = (zdb_rr_label_t *)dictionary_find(&rr_label->sub, WILD_LABEL_HASH, NULL, zdb_label_wild_match);
            *wild_matchp = rr_label_sub_wild;
            *wild_topp = index - 1;
        }
        if(zdb_rr_label_flag_matches(rr_label, ZDB_RR_LABEL_N3COVERED))
        {
            *provable_matchp = rr_label;
            *provable_topp = index;
        }

        index--;
    }
}

void nsec3_get_wild_match_and_closest_provable_encloser_optout(const zdb_rr_label_t *apex, const_dnslabel_vector_reference_t sections, int32_t sections_top, const zdb_rr_label_t **wild_matchp, int32_t *wild_topp,
                                                               const zdb_rr_label_t **provable_matchp, int32_t *provable_topp)
{
    yassert(apex != NULL && sections != NULL && wild_matchp != NULL && wild_topp != NULL && provable_matchp != NULL && provable_topp != NULL);

    int32_t               index = sections_top;
    const zdb_rr_label_t *rr_label = apex; /* the zone cut */
    *wild_matchp = NULL;
    *provable_matchp = apex;
    *provable_topp = sections_top;

    --index;

    /* look into the sub level*/

    while(index >= 0)
    {
        const uint8_t        *label = sections[index];
        hashcode              hash = hash_dnslabel(label);

        const zdb_rr_label_t *sub_rr_label = (zdb_rr_label_t *)dictionary_find(&rr_label->sub, hash, label, nsec3_get_closest_provable_encloser_match);

        if(sub_rr_label == NULL)
        {
            if(rr_label == apex)
            {
                zdb_rr_label_t *rr_label_sub_wild = (zdb_rr_label_t *)dictionary_find(&rr_label->sub, WILD_LABEL_HASH, NULL, zdb_label_wild_match);
                *wild_matchp = rr_label_sub_wild;
                *wild_topp = sections_top - 1;

                if(zdb_rr_label_flag_matches(rr_label, ZDB_RR_LABEL_N3OCOVERED))
                {
                    *provable_matchp = rr_label;
                    *provable_topp = index;
                }
            }

            break;
        }

        rr_label = sub_rr_label;

        if(zdb_rr_label_flag_matches(rr_label, ZDB_RR_LABEL_GOT_WILD))
        {
            zdb_rr_label_t *rr_label_sub_wild = (zdb_rr_label_t *)dictionary_find(&rr_label->sub, WILD_LABEL_HASH, NULL, zdb_label_wild_match);
            *wild_matchp = rr_label_sub_wild;
            *wild_topp = index - 1;
        }
        if(zdb_rr_label_flag_matches(rr_label, ZDB_RR_LABEL_N3OCOVERED))
        {
            *provable_matchp = rr_label;
            *provable_topp = index;
        }

        index--;
    }
}

/**
 * Computes the closest closer proof for a name in a zone
 * Results are returned in 3 pointers
 * The last one of them can be set NULL if the information is not needed.
 *
 * @param zone
 * @param qname the fqdn of the query
 * @param apex_index the index of the apex in qname
 * @param encloser_nsec3p will point to the encloser
 * @param closest_provable_encloser_nsec3p will point to the closest provable encloser
 * @param wild_closest_provable_encloser_nsec3p will point to the *.closest provable encloser
 *
 *
 * https://www.ietf.org/rfc/rfc7129.txt
 */

void nsec3_wild_closest_encloser_proof(const zdb_zone_t *zone, const dnsname_vector_t *qname, int32_t apex_index, const nsec3_zone_item_t **wild_encloser_nsec3p, const nsec3_zone_item_t **closest_provable_encloser_nsec3p,
                                       const nsec3_zone_item_t **qname_encloser_nsec3p)
{
    uint8_t tmp_fqdn[DOMAIN_LENGTH_MAX + 1];
    uint8_t digest[64 + 1];
    digest[0] = SHA_DIGEST_LENGTH;

    // wild_closest_provable_encloser_nsec3p can be NULL

    const_dnslabel_vector_reference_t qname_sections = qname->labels;
    // the index of the apex:
    int32_t             closest_encloser_index_limit = qname->size - apex_index + 1; /* note: "+1" because it starts at the apex */

    const nsec3_zone_t *n3 = zone->nsec.nsec3;

#if DEBUG
    if((n3 == NULL) || (n3->items == NULL))
    {
        log_err("zone %{dnsname} has invalid NSEC3 data", zone->origin);
        return;
    }
#endif

    if(closest_encloser_index_limit > 0)
    {
        const zdb_rr_label_t *wild_match;
        const zdb_rr_label_t *provable_match;
        int32_t               wild_top;
        int32_t               provable_top;

        if((zdb_zone_get_flags(zone) & ZDB_ZONE_HAS_OPTOUT_COVERAGE) != 0)
        {
            nsec3_get_wild_match_and_closest_provable_encloser_optout(zone->apex, qname_sections, closest_encloser_index_limit, &wild_match, &wild_top, &provable_match, &provable_top);
        }
        else
        {
            nsec3_get_wild_match_and_closest_provable_encloser_optin(zone->apex, qname_sections, closest_encloser_index_limit, &wild_match, &wild_top, &provable_match, &provable_top);
        }

        /* Get ZONE NSEC3PARAM */
        uint16_t                     iterations = nsec3_zone_get_iterations(n3);
        uint8_t                      salt_len = NSEC3_ZONE_SALT_LEN(n3);
        const uint8_t               *salt = NSEC3_ZONE_SALT(n3);

        nsec3_hash_function_t *const digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3)); /// @note 20150917 edf -- do not use nsec3_compute_digest_from_fqdn_with_len

        /** @note log_* cannot be used here (except yassert because if that one logs it will abort anyway ...) */

        const nsec3_zone_item_t *wild_closest_provable_encloser_nsec3 = NULL;
        const nsec3_zone_item_t *qname_encloser_nsec3 = NULL;

        if((wild_match != NULL) && zdb_rr_label_nsec3_linked(wild_match))
        {
            wild_closest_provable_encloser_nsec3 = nsec3_label_extension_self(wild_match->nsec.nsec3);

            // add the interval for the fqdn at the * level

            dnsname_vector_sub_to_dnsname(qname, wild_top, tmp_fqdn); // wild top here must be 0
            digestname(tmp_fqdn, dnsname_len(tmp_fqdn), salt, salt_len, iterations, &digest[1], false);
            qname_encloser_nsec3 = nsec3_find_interval_start(&n3->items, digest);

            if(qname_encloser_nsec3 != wild_closest_provable_encloser_nsec3)
            {
                *qname_encloser_nsec3p = qname_encloser_nsec3;
            }
        }

        *wild_encloser_nsec3p = wild_closest_provable_encloser_nsec3;

        const nsec3_zone_item_t *closest_provable_encloser_nsec3;

        if(zdb_rr_label_nsec3_linked(provable_match))
        {
            closest_provable_encloser_nsec3 = nsec3_label_extension_self(provable_match->nsec.nsec3);
        }
        else
        {
            digestname(tmp_fqdn, dnsname_len(tmp_fqdn), salt, salt_len, iterations, &digest[1], false);
            closest_provable_encloser_nsec3 = nsec3_find_interval_start(&n3->items, digest);
        }

        if((closest_provable_encloser_nsec3 != wild_closest_provable_encloser_nsec3) && (closest_provable_encloser_nsec3 != qname_encloser_nsec3))
        {
            *closest_provable_encloser_nsec3p = closest_provable_encloser_nsec3;
        }
        else
        {
            *closest_provable_encloser_nsec3p = NULL;
        }
    }
    else // the closest is the item itself ...
    {
        *wild_encloser_nsec3p = nsec3_label_extension_self(zone->apex->nsec.nsec3);
        *closest_provable_encloser_nsec3p = NULL;
    }
}

void nsec3_wild_next_closer_proof(const zdb_zone_t *zone, const dnsname_vector_t *qname, int32_t apex_index, const nsec3_zone_item_t **wild_next_encloser_nsec3p)
{
    const nsec3_zone_t *n3 = zone->nsec.nsec3;
    if(n3 == NULL)
    {
        return;
    }

    const_dnslabel_vector_reference_t qname_sections = qname->labels;
    // the index of the apex:
    int32_t               closest_encloser_index_limit = qname->size - apex_index + 1; /* note: "+1" because it starts at the apex */

    const zdb_rr_label_t *wild_match;
    const zdb_rr_label_t *provable_match;
    int32_t               wild_top;
    int32_t               provable_top;

    if((zdb_zone_get_flags(zone) & ZDB_ZONE_HAS_OPTOUT_COVERAGE) != 0)
    {
        nsec3_get_wild_match_and_closest_provable_encloser_optout(zone->apex, qname_sections, closest_encloser_index_limit, &wild_match, &wild_top, &provable_match, &provable_top);
    }
    else
    {
        nsec3_get_wild_match_and_closest_provable_encloser_optin(zone->apex, qname_sections, closest_encloser_index_limit, &wild_match, &wild_top, &provable_match, &provable_top);
    }

    uint8_t digest[64 + 1];
    uint8_t tmp_fqdn[DOMAIN_LENGTH_MAX + 1];

    digest[0] = SHA_DIGEST_LENGTH;

    /* Get ZONE NSEC3PARAM */
    uint16_t                     iterations = nsec3_zone_get_iterations(n3);
    uint8_t                      salt_len = NSEC3_ZONE_SALT_LEN(n3);
    const uint8_t               *salt = NSEC3_ZONE_SALT(n3);

    nsec3_hash_function_t *const digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3));

    dnsname_vector_sub_to_dnsname(qname, provable_top, tmp_fqdn); // wild top here must be 0
    digestname(tmp_fqdn, dnsname_len(tmp_fqdn), salt, salt_len, iterations, &digest[1], false);
    *wild_next_encloser_nsec3p = nsec3_find_interval_start(&n3->items, digest);
}

/**
 * Computes the closest closer proof for a name in a zone
 * Results are returned in 3 pointers
 * The last one of them can be set NULL if the information is not needed.
 *
 * RFC 5155 7.2.1
 *
 * _ Closest provable encloser
 * _ Next closer name to closest encloser.
 *
 * @param zone
 * @param qname the fqdn of the query
 * @param apex_index the index of the apex in qname
 * @param encloser_nsec3p will point to the encloser
 * @param closest_provable_encloser_nsec3p will point to the closest provable encloser
 * @param wild_closest_provable_encloser_nsec3p will point to the *.closest provable encloser
 *
 */

void nsec3_closest_encloser_proof(const zdb_zone_t *zone, const dnsname_vector_t *qname, int32_t apex_index, const nsec3_zone_item_t **encloser_nsec3p, const nsec3_zone_item_t **closest_provable_encloser_nsec3p,
                                  const nsec3_zone_item_t **wild_closest_provable_encloser_nsec3p)
{
    uint8_t closest_provable_encloser[DOMAIN_LENGTH_MAX + 1];
    uint8_t encloser[DOMAIN_LENGTH_MAX + 1];
    uint8_t digest[64 + 1];
    digest[0] = SHA_DIGEST_LENGTH;

    yassert(encloser_nsec3p != NULL);
    yassert(closest_provable_encloser_nsec3p != NULL);
    // wild_closest_provable_encloser_nsec3p can be NULL

    /*         0 1 2      3
     * labels: a.b.domain.tld
     *             ^--- apex
     * qname->size: 3
     * apex_index: 2
     * limit: 3 - 2 + 1 = 0
     */

    const_dnslabel_vector_reference_t qname_sections = qname->labels;
    // get the index of the apex:
    int32_t             closest_encloser_index_limit = qname->size - apex_index + 1; /* note: "+1" because it starts at the apex */
    const nsec3_zone_t *n3 = zone->nsec.nsec3;

#if DEBUG
    if((n3 == NULL) || (n3->items == NULL))
    {
        log_err("zone %{dnsname} has invalid NSEC3 data", zone->origin);
        return;
    }
#endif

    if(closest_encloser_index_limit > 0)
    {
        const zdb_rr_label_t *closest_provable_encloser_label = ((zdb_zone_get_flags(zone) & ZDB_ZONE_HAS_OPTOUT_COVERAGE) != 0) ? nsec3_get_closest_provable_encloser_optout(zone->apex, qname_sections, &closest_encloser_index_limit)
                                                                                                                                 : nsec3_get_closest_provable_encloser_optin(zone->apex, qname_sections, &closest_encloser_index_limit);

        // log_debug("closest_provable_encloser_label: %{dnslabel}: %{digest32h}",
        // closest_provable_encloser_label->name, closest_provable_encloser_label->nsec.nsec3->self->digest);
        // log_debug("*.closest_provable_encloser_label: %{dnslabel}: %{digest32h}",
        // closest_provable_encloser_label->name, closest_provable_encloser_label->nsec.nsec3->star->digest);

        /*
         * Convert from closest_encloser_label_bottom to name.size into a dnslabel
         */

        /* Get ZONE NSEC3PARAM */
        uint16_t                     iterations = nsec3_zone_get_iterations(n3);
        uint8_t                      salt_len = NSEC3_ZONE_SALT_LEN(n3);
        const uint8_t               *salt = NSEC3_ZONE_SALT(n3);
        const nsec3_zone_item_t     *encloser_nsec3 = NULL;

        nsec3_hash_function_t *const digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3)); /// @note 20150917 edf -- do not use nsec3_compute_digest_from_fqdn_with_len

        /** @note log_* cannot be used here (except yassert because if that one logs it will abort anyway ...) */

        // encloser_nsec3p

        if(closest_encloser_index_limit > 0) // if the closest encloser is itself, we should not be here
        {
            yassert(closest_provable_encloser_label != NULL);
            dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit - 1, encloser); // note: - 1 for the next closer
            digestname(encloser, dnsname_len(encloser), salt, salt_len, iterations, &digest[1], false);
            encloser_nsec3 = nsec3_zone_item_find_encloser_start(n3, digest); // get the interval covering the next closer
            *encloser_nsec3p = encloser_nsec3;
        }
        else
        {
            *encloser_nsec3p = NULL; // the closest is itself (ie: missing type)
        }

        // closest_provable_encloser_nsec3p

        dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit, closest_provable_encloser);

        const nsec3_zone_item_t *closest_provable_encloser_nsec3;

        // if the label isn't linked to an NSEC3

        if(!zdb_rr_label_nsec3_linked(closest_provable_encloser_label))
        {
            // compute the value now

            digestname(closest_provable_encloser, dnsname_len(closest_provable_encloser), salt, salt_len, iterations, &digest[1], false);
            closest_provable_encloser_nsec3 = nsec3_find(&n3->items, digest);
        }
        else
        {
            // else use the linked NSEC3

            closest_provable_encloser_nsec3 = nsec3_label_extension_self(closest_provable_encloser_label->nsec.nsec3);
        }

        if(closest_provable_encloser_nsec3 == encloser_nsec3)
        {
            // duplicate entry : ignore
            closest_provable_encloser_nsec3 = NULL;
        }

        *closest_provable_encloser_nsec3p = closest_provable_encloser_nsec3;

        if(wild_closest_provable_encloser_nsec3p != NULL)
        {
            if(closest_provable_encloser_nsec3 == NULL)
            {
                dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit, closest_provable_encloser);
            }

            const nsec3_zone_item_t *wild_closest_provable_encloser_nsec3;

            // if the label isn't linked to an NSEC3

            if(!zdb_rr_label_nsec3_linked(closest_provable_encloser_label))
            {
                // compute the value now

                digestname(closest_provable_encloser, dnsname_len(closest_provable_encloser), salt, salt_len, iterations, &digest[1], true);
                wild_closest_provable_encloser_nsec3 = nsec3_find_interval_start(&n3->items, digest);
            }
            else
            {
                // else use the linked NSEC3

                wild_closest_provable_encloser_nsec3 = nsec3_label_extension_star(closest_provable_encloser_label->nsec.nsec3);
            }

            if(wild_closest_provable_encloser_nsec3 == encloser_nsec3)
            {
                // duplicate entry : ignore
                wild_closest_provable_encloser_nsec3 = NULL;
            }
            else if(wild_closest_provable_encloser_nsec3 == closest_provable_encloser_nsec3)
            {
                // duplicate entry : ignore
                wild_closest_provable_encloser_nsec3 = NULL;
            }

            *wild_closest_provable_encloser_nsec3p = wild_closest_provable_encloser_nsec3;
        }
    }
    else // the closest is the item itself ...
    {
        *encloser_nsec3p = nsec3_label_extension_self(zone->apex->nsec.nsec3);
        *closest_provable_encloser_nsec3p = nsec3_label_extension_self(zone->apex->nsec.nsec3);
        if(wild_closest_provable_encloser_nsec3p != NULL)
        {
            *wild_closest_provable_encloser_nsec3p = nsec3_label_extension_self(zone->apex->nsec.nsec3);
        }
    }
}

#if NSEC3_UPDATE_ZONE_DEBUG

/**
 * This is an internal integrity check
 *
 * For all owners of the NSEC3 record (aka nsec3_zone_item aka nsec3_node)
 *   Check the label is not under a delegation (log debug only)
 *   Check the label points back to the NSEC3 record
 *
 * @param item the NSEC3 record
 * @param param_index_base the index of the chain of the NSEC3 record
 */

void nsec3_check_item(nsec3_zone_item_t *item, uint32_t param_index_base)
{
    yassert(item != NULL);

    uint16_t n = nsec3_owner_count(item);

    if(n == 0)
    {
        log_err("nsec3_check: %{digest32h} has no owner", item->digest);
        logger_flush();
        abort();
    }

    for(uint_fast16_t i = 0; i < n; i++)
    {
        zdb_rr_label *label = nsec3_item_owner_get(item, i);

        yassert(label != NULL && label->nsec.nsec3 != NULL);

        if(ZDB_LABEL_UNDERDELEGATION(label))
        {
            log_err("nsec3_check: %{digest32h} label nsec3 reference under a delegation (%{dnslabel})", item->digest, label);
        }

        nsec3_label_extension_t *n3le = label->nsec.nsec3;

        uint32_t                 param_index = param_index_base;
        while(param_index > 0)
        {
            yassert(n3le != NULL);

#if DEBUG_VALID_ADDRESS
            yassert(debug_is_valid_address(n3le, sizeof(nsec3_label_extension)));
#endif

            n3le = nsec3_label_extension_next(n3le);

            param_index--;
        }

        yassert(n3le != NULL);

#if DEBUG_VALID_ADDRESS
        yassert(debug_is_valid_address(n3le, sizeof(nsec3_label_extension)));
#endif
        // the nsec3 structure reference to the item linked to the label does not links back to the item
        yassert(n3le->_self == item);
    }

    n = nsec3_star_count(item);

    for(uint_fast16_t i = 0; i < n; i++)
    {
        zdb_rr_label *label = nsec3_item_star_get(item, i);

        if(!((label != NULL) && (label->nsec.nsec3 != NULL)))
        {
            log_err("nsec3_check: %{digest32h} (#self=%d/#star=%d) corrupted", item->digest, item->rc, item->sc);
        }

        yassert(label != NULL && label->nsec.nsec3 != NULL);

        if(ZDB_LABEL_UNDERDELEGATION(label))
        {
            log_err("nsec3_check: %{digest32h} *.label nsec3 reference under a delegation (%{dnslabel})", item->digest, label);
        }

        nsec3_label_extension_t *n3le = label->nsec.nsec3;

        uint32_t                 param_index = param_index_base;
        while(param_index > 0)
        {
            yassert(n3le != NULL);

#if DEBUG_VALID_ADDRESS
            yassert(debug_is_valid_address(n3le, sizeof(nsec3_label_extension)));
#endif

            n3le = nsec3_label_extension_next(n3le);

            param_index--;
        }

        yassert(n3le != NULL);

#if DEBUG_VALID_ADDRESS

        if(!debug_is_valid_address(n3le, sizeof(nsec3_label_extension)))
        {
            log_debug("nsec3_check: %{digest32h} (#self=%d/#star=%d) corrupted", item->digest, item->rc, item->sc);
        }

        yassert(debug_is_valid_address(n3le, sizeof(nsec3_label_extension)));
#endif

        if(nsec3_label_extension_star(n3le) != item)
        {
            if(nsec3_label_extension_star(n3le) != NULL)
            {
                log_err("nsec3_check: %{digest32h} (#self=%d/#star=%d) failing %{dnslabel} expected %{digest32h}", item->digest, item->rc, item->sc, label->name, nsec3_label_extension_star(n3le)->digest);
            }
            else
            {
                log_err("nsec3_check: %{digest32h} (#self=%d/#star=%d) *.%{dnslabel} is NULL", item->digest, item->rc, item->sc, label->name, nsec3_label_extension_star(n3le)->digest);
            }
        }

        if(nsec3_label_extension_self(n3le) == NULL)
        {
            log_err("nsec3_check: %{digest32h} (#self=%d/#star=%d) failing %{dnslabel}: no self", item->digest, item->rc, item->sc, label->name);
        }

        if(nsec3_label_extension_star(n3le) != item)
        {
            log_err("nsec3_check: %{digest32h} *.label nsec3 reference does not point back to the nsec3 item (%{dnslabel})", item->digest, label);
        }
        if(nsec3_label_extension_self(n3le) == NULL)
        {
            log_err("nsec3_check: %{digest32h} *.label nsec3 reference self is NULL (%{dnslabel})", item->digest, label);
        }
    }
}

/**
 * This is an internal integrity check
 *
 * Checks all NSEC3 links to their owners back and forth.
 *
 * @param zone
 */

void nsec3_check(zdb_zone *zone)
{
    log_debug("nsec3_check: %{dnsname}, from the NSEC3's reference", zone->origin);

    const nsec3_zone *n3 = zone->nsec.nsec3;

    if(n3 == NULL)
    {
        log_debug("nsec3_check: %{dnsname}: no NSEC3", zone->origin);

        return;
    }

    /*
     * For each node, check if the owners and stars are coherent
     */

    uint32_t param_index = 0;

    while(n3 != NULL)
    {
        nsec3_iterator_t n3iter;
        nsec3_iterator_init(&n3->items, &n3iter);
        while(nsec3_iterator_hasnext(&n3iter))
        {
            nsec3_zone_item_t *item = nsec3_iterator_next_node(&n3iter);

            nsec3_check_item(item, param_index);
        }

        param_index++;

        n3 = n3->next;
    }

    log_debug("nsec3_check: %{dnsname}: from the label's reference", zone->origin);

    zdb_zone_label_iterator label_iterator;
    uint8_t                 fqdn[DOMAIN_LENGTH_MAX + 1];

    zdb_zone_label_iterator_init(zone, &label_iterator);

    while(zdb_zone_label_iterator_hasnext(&label_iterator))
    {
        zdb_zone_label_iterator_nextname(&label_iterator, fqdn);
        zdb_rr_label            *label = zdb_zone_label_iterator_next(&label_iterator);
        nsec3_label_extension_t *n3le = label->nsec.nsec3;

        while(n3le != NULL)
        {
            if(n3le->_self != NULL)
            {
                int found = 0;

                for(int_fast32_t i = 0; i < n3le->_self->rc; ++i)
                {
                    zdb_rr_label *self = nsec3_item_owner_get(n3le->_self, i);
                    if(self == label)
                    {
                        ++found;
                    }
                }

                if(found == 0)
                {
                    log_err("nsec3_check: %{dnsname}: %{dnsname} => %{digest32h} is one way", zone->origin, fqdn, n3le->_self->digest);
                }
                else if(found > 1)
                {
                    log_err("nsec3_check: %{dnsname}: %{dnsname} => %{digest32h} is referenced back multiple times", zone->origin, fqdn, n3le->_self->digest);
                }
            }

            if(n3le->_star != NULL)
            {
                int found = 0;

                for(int_fast32_t i = 0; i < n3le->_star->sc; ++i)
                {
                    zdb_rr_label *star = nsec3_item_star_get(n3le->_star, i);
                    if(star == label)
                    {
                        ++found;
                    }
                }

                if(found == 0)
                {
                    log_err("nsec3_check: %{dnsname}: *.%{dnsname} => %{digest32h} is one way", zone->origin, fqdn, n3le->_star->digest);
                }
                else if(found > 1)
                {
                    log_err("nsec3_check: %{dnsname}: *.%{dnsname} => %{digest32h} is referenced back multiple times", zone->origin, fqdn, n3le->_star->digest);
                }
            }

            n3le = n3le->_next;
        }
    }

    log_debug("nsec3_check: %{dnsname} : done", zone->origin);
}

#endif

void nsec3_compute_digest_from_fqdn_with_len(const nsec3_zone_t *n3, const uint8_t *fqdn, uint32_t fqdn_len, uint8_t *digest, bool isstar)
{
    digest[0] = nsec3_hash_len(NSEC3_ZONE_ALGORITHM(n3));

    nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3))(fqdn, fqdn_len, NSEC3_ZONE_SALT(n3), NSEC3_ZONE_SALT_LEN(n3), nsec3_zone_get_iterations(n3), &digest[1], isstar);
}

void nsec3_zone_label_detach(zdb_rr_label_t *label)
{
    yassert((label != NULL) && zdb_rr_label_flag_isset(label, (ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT)));

    nsec3_label_extension_t *n3le = label->nsec.nsec3;

    while(n3le != NULL)
    {
        // remove
        if(nsec3_label_extension_self(n3le) != NULL)
        {
#if DEBUG
            nsec3_zone_item_t *node_self = nsec3_label_extension_self(n3le);
#endif
            nsec3_item_remove_owner(nsec3_label_extension_self(n3le), label);
#if DEBUG
            log_debug1("nsec3_zone_label_detach(%{dnslabel}@%p) : nsec3 rc = %i", nsec3_owner_count(node_self));
#endif
        }
        if(nsec3_label_extension_star(n3le) != NULL)
        {
            nsec3_item_remove_star(nsec3_label_extension_star(n3le), label);
        }
        zdb_rr_label_flag_and(label, ~(ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT));
        label->nsec.nsec3 = NULL;

        nsec3_label_extension_t *tmp = n3le;
        n3le = nsec3_label_extension_next(n3le);

        nsec3_label_extension_free(tmp);
    }

    label->nsec.nsec3 = NULL;
}

ya_result nsec3_get_next_digest_from_rdata(const uint8_t *rdata, uint32_t rdata_size, uint8_t *digest, uint32_t digest_size)
{
    if((NSEC3_RDATA_ALGORITHM(rdata) == NSEC3_DIGEST_ALGORITHM_SHA1) && (rdata_size > 5 + 21))
    {
        uint32_t salt_size = rdata[4];
        uint32_t hash_size = rdata[5 + salt_size];
        if((hash_size < digest_size) && (hash_size + salt_size + 5 < rdata_size))
        {
            memcpy(digest, &rdata[5 + salt_size], hash_size + 1);
            return hash_size + 1;
        }
    }

    return ERROR;
}

// frees from back to front

static inline void nsec3_zone_label_extension_remove(zdb_rr_label_t *label, nsec3_label_extension_t *n3le)
{
    if(nsec3_label_extension_next(n3le) != NULL)
    {
        nsec3_zone_label_extension_remove(label, nsec3_label_extension_next(n3le));
        nsec3_label_extension_set_next(n3le, NULL);
    }

    // remove
    if(nsec3_label_extension_self(n3le) != NULL)
    {
        nsec3_item_remove_owner(nsec3_label_extension_self(n3le), label);
    }

    if(nsec3_label_extension_star(n3le) != NULL)
    {
        nsec3_item_remove_star(nsec3_label_extension_star(n3le), label);
    }

    nsec3_label_extension_free(n3le);
}

void nsec3_zone_label_update_chain_links(nsec3_zone_t *n3, zdb_rr_label_t *label, int count, uint16_t coverage_mask, const uint8_t *fqdn)
{
    nsec3_label_extension_t *n3le = label->nsec.nsec3;
    uint8_t                  digest[1 + DIGEST_LENGTH_MAX];

#if NSEC3_ZONE_LABEL_UPDATE_CHAIN_LINKS_DEBUG
    log_info("link: %{dnsname} (DEBUG)", fqdn);
#endif

    // coverage_mask tells what coverage is expected in the zone. It has only one bit set.

    bool    should_be_covered = zdb_rr_label_flag_isset(label, coverage_mask);
    uint8_t expected_optout_flag_value = (coverage_mask & ZDB_RR_LABEL_N3OCOVERED) ? 1 : 0;

    if(should_be_covered) // should be covered
    {
#if NSEC3_ZONE_LABEL_UPDATE_CHAIN_LINKS_DEBUG
        log_info("link: %{dnsname}: should be covered (DEBUG)", fqdn);
#endif

        if(n3le == NULL) // has no extension
        {
            // add the extension list

            n3le = nsec3_label_extension_alloc_list(count);

            label->nsec.nsec3 = n3le;

            if(zdb_rr_label_flag_isset(label, ZDB_RR_LABEL_N3OCOVERED))
            {
                zdb_rr_label_flag_or(label, ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT);
            }
            else
            {
                zdb_rr_label_flag_or(label, ZDB_RR_LABEL_NSEC3);
            }
        }

        do
        {
            // are links missing ?

            if((nsec3_label_extension_self(n3le) == NULL) || (nsec3_label_extension_star(n3le) == NULL))
            {
                // compute the digest(s) and link

                int32_t fqdn_len = dnsname_len(fqdn);

                if(nsec3_label_extension_self(n3le) == NULL)
                {
                    nsec3_zone_item_t *self = nsec3_label_link_seeknode(n3, fqdn, fqdn_len, digest);
                    if(self != NULL)
                    {
                        if(self->flags != expected_optout_flag_value)
                        {
                            log_warn("%{dnsname} NSEC3 coverage flag doesn't match expected value", fqdn);
                        }

                        nsec3_item_add_owner(self, label);
                        nsec3_label_extension_set_self(n3le, self);
#if NSEC3_ZONE_LABEL_UPDATE_CHAIN_LINKS_DEBUG
                        log_info("link: %{dnsname}: self node %{digest32h} bound (DEBUG)", fqdn, digest);
#endif
#if HAS_SUPERDUMP
                        nsec3_superdump_integrity_check_label_nsec3_self_points_back(label, 0);
                        nsec3_superdump_integrity_check_nsec3_owner_self_points_back(self, 0);
#endif
                    }
#if NSEC3_ZONE_LABEL_UPDATE_CHAIN_LINKS_DEBUG
                    else
                    {
                        log_info("link: %{dnsname}: self node %{digest32h} not found (DEBUG)", fqdn, digest);
                    }
#endif
                }

                if(nsec3_label_extension_star(n3le) == NULL)
                {
                    nsec3_zone_item_t *star = nsec3_label_link_seekstar(n3, fqdn, fqdn_len, digest);
                    if(star != NULL)
                    {
                        // nsec3_superdump_integrity_check_label_nsec3_star_points_back(label,0);
                        nsec3_item_add_star(star, label);
                        nsec3_label_extension_set_star(n3le, star);
#if NSEC3_ZONE_LABEL_UPDATE_CHAIN_LINKS_DEBUG
                        log_info("link: %{dnsname}: star node %{digest32h} bound (DEBUG)", fqdn, digest);
#endif
#if HAS_SUPERDUMP
                        nsec3_superdump_integrity_check_label_nsec3_star_points_back(label, 0);
                        nsec3_superdump_integrity_check_nsec3_owner_star_points_back(star, 0);
#endif
                    }

#if NSEC3_ZONE_LABEL_UPDATE_CHAIN_LINKS_DEBUG
                    else
                    {
                        log_info("link: %{dnsname}: star node %{digest32h} not found (DEBUG)", fqdn, digest);
                    }
#endif
                }
            }

            n3 = n3->next;
            nsec3_label_extension_t *next = nsec3_label_extension_next(n3le);

            if((next == NULL) && (n3 != NULL))
            {
                // add
                nsec3_label_extension_set_next(n3le, nsec3_label_extension_alloc_list(1));
            }
            else if((next != NULL) && (n3 == NULL))
            {
                // extensions beyond the chain

                nsec3_label_extension_set_next(n3le, NULL);
                nsec3_zone_label_extension_remove(label, next);
                next = NULL;
            }

            n3le = next;
        } while(n3le != NULL);
    }
    else // should not be covered
    {
#if NSEC3_ZONE_LABEL_UPDATE_CHAIN_LINKS_DEBUG
        log_info("link: %{dnsname}: should not be covered (DEBUG)", fqdn);
#endif
        if(n3le != NULL)
        {
            nsec3_zone_label_extension_remove(label, n3le);

            zdb_rr_label_flag_and(label, ~(ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT));
            label->nsec.nsec3 = NULL;
        }
    }
}

/**
 * Updates links for the first NSEC3 chain of the zone
 * Only links to existing NSEC3 records.
 * Only links label with an extension and self/wild set to NULL
 *
 * @param zone
 */

void nsec3_zone_update_chain0_links(zdb_zone_t *zone)
{
    nsec3_zone_t *n3 = zone->nsec.nsec3;

    if(n3 == NULL)
    {
        return;
    }

    uint16_t coverage_mask;
    uint8_t  maintain_mode = zone_get_maintain_mode(zone);
    if(maintain_mode & ZDB_ZONE_HAS_OPTOUT_COVERAGE)
    {
        coverage_mask = ZDB_RR_LABEL_N3OCOVERED;
    }
    else
    {
        coverage_mask = ZDB_RR_LABEL_N3COVERED;
    }

    log_debug("nsec3_zone_update_chain0_links(%{dnsname}) maintain_mode=%x", zone->origin, maintain_mode);

    int n3_count = 1;
    // u16 structure_mask = (maintain_mode == ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT)?ZDB_RR_LABEL_NSEC3_OPTOUT:((maintain_mode
    // == ZDB_ZONE_MAINTAIN_NSEC3)?ZDB_RR_LABEL_NSEC3:0);

    {
        const nsec3_zone_t *n3 = zone->nsec.nsec3->next;

        while(n3 != NULL)
        {
            ++n3_count;
            n3 = n3->next;
        }
    }

    zdb_zone_label_iterator_t label_iterator;
    uint8_t                   fqdn[DOMAIN_LENGTH_MAX + 1];

    zdb_zone_label_iterator_init(zone, &label_iterator);

    while(zdb_zone_label_iterator_hasnext(&label_iterator))
    {
        zdb_zone_label_iterator_nextname(&label_iterator, fqdn);
        zdb_rr_label_t *label = zdb_zone_label_iterator_next(&label_iterator);
        nsec3_zone_label_update_chain_links(zone->nsec.nsec3, label, n3_count, coverage_mask, fqdn);
    }
}

#if ZDB_HAS_PRIMARY_SUPPORT
/**
 * Sets the NSEC3 maintenance status for a specific chain.
 * Marks the zone using private records.
 *
 * The zone must be double-locked.
 *
 * @param zone
 * @param secondary_lock the secondary lock owner
 * @param algorithm
 * @param optout
 * @param salt
 * @param salt_len
 * @param iterations
 * @param status
 * @return
 */

ya_result nsec3_zone_set_status(zdb_zone_t *zone, uint8_t secondary_lock, uint8_t algorithm, uint8_t optout, uint16_t iterations, const uint8_t *salt, uint8_t salt_len, uint8_t status)
{
    dynupdate_message   dmsg;
    dns_packet_reader_t reader;
    dynupdate_message_init(&dmsg, zone->origin, CLASS_IN);

    uint8_t prev_status = 0;
#if __unix__
    uint8_t nsec3paramadd_rdata[5 + salt_len + 1];
#else
    uint8_t nsec3paramadd_rdata[5 + 255 + 1];
#endif
    nsec3paramadd_rdata[0] = algorithm;
    nsec3paramadd_rdata[1] = optout;
    SET_U16_AT(nsec3paramadd_rdata[2], htons(iterations));
    nsec3paramadd_rdata[4] = salt_len;
    memcpy(&nsec3paramadd_rdata[5], salt, salt_len);
    nsec3paramadd_rdata[5 + salt_len] = status;

    // look for the matching record
    if(nsec3_zone_get_status(zone, algorithm, optout, iterations, salt, salt_len, &prev_status) == 1)
    {
        // if the record exists, remove it and add it
        nsec3paramadd_rdata[5 + salt_len] = prev_status;
        if(prev_status == status)
        {
            dynupdate_message_finalize(&dmsg);

            // already set

            return SUCCESS;
        }
        dynupdate_message_del_record(&dmsg, zone->origin, TYPE_NSEC3CHAINSTATE, 0, 6 + salt_len, nsec3paramadd_rdata);
        nsec3paramadd_rdata[5 + salt_len] = status;
    }

    dynupdate_message_add_record(&dmsg, zone->origin, TYPE_NSEC3CHAINSTATE, 0, 6 + salt_len, nsec3paramadd_rdata);

    dynupdate_message_set_reader(&dmsg, &reader);
    uint16_t count = dynupdate_message_get_count(&dmsg);

    dns_packet_reader_skip(&reader, DNS_HEADER_LENGTH); // checked below
    dns_packet_reader_skip_fqdn(&reader);               // checked below
    dns_packet_reader_skip(&reader, 4);                 // checked below

    ya_result ret;

    if(!dns_packet_reader_eof(&reader))
    {
#if ZDB_HAS_DNSSEC_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT
        if(zone_get_maintain_mode(zone) == 0)
        {
            zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
        }
#endif

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
 * Gets the NSEC3 maintenance status for a specific chain.
 * Get the information from the zone using private records.
 *
 * The zone must be locked.
 *
 * @param zone
 * @param algorithm
 * @param optout
 * @param salt
 * @param salt_len
 * @param iterations
 * @param status
 * @return
 */

ya_result nsec3_zone_get_status(zdb_zone_t *zone, uint8_t algorithm, uint8_t optout, uint16_t iterations, const uint8_t *salt, uint8_t salt_len, uint8_t *statusp)
{
    // get the TYPE_NSEC3PARAMADD record set
    // search for a record matching the chain
    zdb_resource_record_set_t *rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_NSEC3CHAINSTATE);

    if(rrset != NULL)
    {
        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *record = zdb_resource_record_set_const_iterator_next(&iter);

            if(zdb_resource_record_data_rdata_size(record) == 6 + salt_len)
            {
                const uint8_t *rdata = zdb_resource_record_data_rdata_const(record);

                if(rdata[0] == algorithm)
                {
                    if(rdata[1] == optout)
                    {
                        if(GET_U16_AT(rdata[2]) == htons(iterations))
                        {
                            if(rdata[4] == salt_len)
                            {
                                if(memcmp(&rdata[5], salt, salt_len) == 0)
                                {
                                    *statusp = rdata[5 + salt_len];
                                    return 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

/**
 * Gets a copy of the salt bytes from the first matching NSEC3PARAM record.
 *
 * The zone must be locked.
 *
 * @param zone
 * @param algorithm
 * @param optout
 * @param salt_len
 * @param iterations
 * @param salt_buffer
 * @return
 */

ya_result nsec3_zone_get_first_salt_matching(zdb_zone_t *zone, uint8_t algorithm, uint8_t optout, uint16_t iterations, uint8_t salt_len, uint8_t *salt_buffer)
{
    // get the TYPE_NSEC3PARAMADD record set
    // search for a record matching the chain

    zdb_resource_record_set_t *nsec3chainstate_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_NSEC3CHAINSTATE);

    if(nsec3chainstate_rrset != NULL)
    {
        // int32_t ttl = zdb_resource_record_set_ttl(nsec3chainstate_rrset);
        zdb_resource_record_set_iterator iter;
        zdb_resource_record_set_iterator_init(nsec3chainstate_rrset, &iter);
        while(zdb_resource_record_set_iterator_has_next(&iter))
        {
            zdb_resource_record_data_t *nsec3chainstate_rr = zdb_resource_record_set_iterator_next(&iter);

            const uint8_t              *rdata = zdb_resource_record_data_rdata_const(nsec3chainstate_rr);
            uint16_t                    rdata_size = zdb_resource_record_data_rdata_size(nsec3chainstate_rr);

            if(rdata_size == (uint16_t)6 + salt_len)
            {
                if(rdata[0] == algorithm)
                {
                    if(rdata[1] == optout)
                    {
                        if(GET_U16_AT(rdata[2]) == htons(iterations))
                        {
                            if(rdata[4] == salt_len)
                            {
                                if(salt_buffer != NULL)
                                {
                                    memcpy(salt_buffer, &rdata[5], salt_len);
                                }
                                return 1;
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

/**
 * Gets the NSEC3 maintenance status for a specific chain.
 * Get the information from the zone using private records.
 *
 * The zone must be locked.
 *
 * @param zone
 * @param rdata
 * @param rdata_size
 * @param statusp
 * @return
 */

ya_result nsec3_zone_get_status_from_rdata(zdb_zone_t *zone, const uint8_t *rdata, uint16_t rdata_size, uint8_t *statusp)
{
    // get the TYPE_NSEC3PARAMADD record set
    // search for a record matching the chain
    zdb_resource_record_set_t *rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_NSEC3CHAINSTATE);

    if(rrset != NULL)
    {
        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *record = zdb_resource_record_set_const_iterator_next(&iter);

            if(zdb_resource_record_data_rdata_size(record) == rdata_size + 1)
            {
                const uint8_t *rrset_rdata = zdb_resource_record_data_rdata_const(record);

                if(rrset_rdata[0] == rdata[0])
                {
                    if(GET_U16_AT(rrset_rdata[2]) == GET_U16_AT(rdata[2]))
                    {
                        if(rrset_rdata[4] == rdata[4])
                        {
                            if(memcmp(&rrset_rdata[5], &rdata[5], rdata[4]) == 0)
                            {
                                *statusp = rrset_rdata[5 + rdata[4]];
                                return 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // check if the chain has an associated NSEC3PARAM
    rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_NSEC3PARAM);

    if(rrset != NULL)
    {
        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *record = zdb_resource_record_set_const_iterator_next(&iter);

            if(zdb_resource_record_data_rdata_size(record) == rdata_size)
            {
                const uint8_t *rrset_rdata = zdb_resource_record_data_rdata_const(record);

                if(rrset_rdata[0] == rdata[0])
                {
                    if(GET_U16_AT(rrset_rdata[2]) == GET_U16_AT(rdata[2]))
                    {
                        if(rrset_rdata[4] == rdata[4])
                        {
                            if(memcmp(&rrset_rdata[5], &rdata[5], rdata[4]) == 0)
                            {
                                // it's a match
                                *statusp = NSEC3_ZONE_ENABLED;
                                return 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // check if the chain has an associated NSEC3PARAMQUEUED
    rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_NSEC3PARAMQUEUED);

    if(rrset != NULL)
    {
        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *record = zdb_resource_record_set_const_iterator_next(&iter);

            if(zdb_resource_record_data_rdata_size(record) == rdata_size)
            {
                const uint8_t *rrset_rdata = zdb_resource_record_data_rdata_const(record);

                if(rrset_rdata[0] == rdata[0])
                {
                    if(GET_U16_AT(rrset_rdata[2]) == GET_U16_AT(rdata[2]))
                    {
                        if(rrset_rdata[4] == rdata[4])
                        {
                            if(memcmp(&rrset_rdata[5], &rdata[5], rdata[4]) == 0)
                            {
                                // it's a match
                                *statusp = NSEC3_ZONE_GENERATING;
                                return 1;
                            }
                        }
                    }
                }
            }
        }
    }

    *statusp = NSEC3_ZONE_REMOVING;

    return 0;
}

/**
 * Returns the number of known chains in the zone.
 * Inactive chains are also counted.
 * Zone must be locked.
 *
 * @param zone
 * @return
 */

int nsec3_zone_get_chain_count(zdb_zone_t *zone)
{
    int           ret = 0;
    nsec3_zone_t *n3 = zone->nsec.nsec3;
    while(n3 != NULL)
    {
        ++ret;
        n3 = n3->next;
    }
    return ret;
}

/**
 * Returns pointers to the chains from the zone.
 * Inactive chains are also counted.
 * Zone must be locked.
 *
 * @param zone
 * @param n3p
 * @param max_count
 * @return
 */

int nsec3_zone_get_chains(zdb_zone_t *zone, nsec3_zone_t **n3p, int max_count)
{
    int           ret = 0;
    nsec3_zone_t *n3 = zone->nsec.nsec3;
    while(n3 != NULL)
    {
        *n3p++ = n3;
        if(++ret == max_count)
        {
            break;
        }
        n3 = n3->next;
    }
    return ret;
}

struct nsec3_item_rrv_data_s
{
    nsec3_zone_t      *n3;
    nsec3_zone_item_t *item;
    const uint8_t     *origin;
    uint8_t           *rdata;
    uint16_t           rdata_size;
    uint16_t           rdata_buffer_size;
    int32_t            ttl;
    uint8_t            fqdn[256];
};

typedef struct nsec3_item_rrv_data_s nsec3_item_rrv_data_t;

static void                          nsec3_item_resource_record_view_data_item_set(nsec3_item_rrv_data_t *rrv_data, nsec3_zone_item_t *item)
{
    uint32_t required_size = nsec3_zone_item_rdata_size(rrv_data->n3, item);
    if(rrv_data->rdata_buffer_size < required_size)
    {
        free(rrv_data->rdata);
        rrv_data->rdata_buffer_size = (required_size + 128) & ~127;
        MALLOC_OBJECT_ARRAY_OR_DIE(rrv_data->rdata, uint8_t, rrv_data->rdata_buffer_size, RRVDATA_TAG);
    }

    rrv_data->rdata_size = nsec3_zone_item_to_rdata(rrv_data->n3, item, rrv_data->rdata, rrv_data->rdata_buffer_size);
    uint32_t b32_len = base32hex_encode_lc(NSEC3_NODE_DIGEST_PTR(item), NSEC3_NODE_DIGEST_SIZE(item), (char *)&rrv_data->fqdn[1]);
    rrv_data->fqdn[0] = b32_len;
    dnsname_copy(&rrv_data->fqdn[b32_len + 1], rrv_data->origin);
    rrv_data->item = item;
}

static const uint8_t *nsec3_item_rrv_get_fqdn(void *data, const void *p)
{
    nsec3_item_rrv_data_t *rrv_data = (nsec3_item_rrv_data_t *)data;
    if(rrv_data->item != (nsec3_zone_item_t *)p)
    {
        nsec3_item_resource_record_view_data_item_set(rrv_data, (nsec3_zone_item_t *)p);
    }
    return rrv_data->fqdn;
}

static uint16_t nsec3_item_rrv_get_type(void *data, const void *p)
{
    (void)data;
    (void)p;
    return TYPE_NSEC3;
}

static uint16_t nsec3_item_rrv_get_class(void *data, const void *p)
{
    (void)data;
    (void)p;
    return CLASS_IN;
}

static int32_t nsec3_item_rrv_get_ttl(void *data, const void *p)
{
    (void)p;
    nsec3_item_rrv_data_t *rrv_data = (nsec3_item_rrv_data_t *)data;
    return rrv_data->ttl;
}

static uint16_t nsec3_item_rrv_get_rdata_size(void *data, const void *p)
{
    nsec3_item_rrv_data_t *rrv_data = (nsec3_item_rrv_data_t *)data;
    if(rrv_data->item != (nsec3_zone_item_t *)p)
    {
        nsec3_item_resource_record_view_data_item_set(rrv_data, (nsec3_zone_item_t *)p);
    }
    return rrv_data->rdata_size;
}

static const uint8_t *nsec3_item_rrv_get_rdata(void *data, const void *p)
{
    nsec3_item_rrv_data_t *rrv_data = (nsec3_item_rrv_data_t *)data;
    if(rrv_data->item != (nsec3_zone_item_t *)p)
    {
        nsec3_item_resource_record_view_data_item_set(rrv_data, (nsec3_zone_item_t *)p);
    }
    return rrv_data->rdata;
}

static void *nsec3_item_rrv_new_instance(void *data, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, uint16_t rdata_size, const uint8_t *rdata)
{
    (void)data;
    (void)fqdn;
    (void)rtype;
    (void)rclass;
    (void)ttl;
    yassert(rtype == TYPE_RRSIG);
    zdb_resource_record_data_t *ttlrdata = zdb_resource_record_data_new_instance_copy(rdata_size, rdata); // note: TTL value is lost here
    return ttlrdata;
}

static const struct resource_record_view_vtbl nsec3_item_rrv_vtbl = {
    nsec3_item_rrv_get_fqdn, nsec3_item_rrv_get_type, nsec3_item_rrv_get_class, nsec3_item_rrv_get_ttl, nsec3_item_rrv_get_rdata_size, nsec3_item_rrv_get_rdata, nsec3_item_rrv_new_instance};

void nsec3_item_resource_record_view_init(resource_record_view_t *rrv)
{
    ZALLOC_OBJECT_OR_DIE(rrv->data, nsec3_item_rrv_data_t, N3IRRVDT_TAG);
    ZEROMEMORY(rrv->data, sizeof(nsec3_item_rrv_data_t));
    rrv->vtbl = &nsec3_item_rrv_vtbl;
}

void nsec3_item_resource_record_view_origin_set(struct resource_record_view_s *rrv, const uint8_t *origin)
{
    yassert(rrv->vtbl == &nsec3_item_rrv_vtbl);
    nsec3_item_rrv_data_t *rrv_data = (nsec3_item_rrv_data_t *)rrv->data;
    rrv_data->origin = origin;
}

void nsec3_item_resource_record_view_nsec3_zone_set(struct resource_record_view_s *rrv, nsec3_zone_t *n3)
{
    yassert(rrv->vtbl == &nsec3_item_rrv_vtbl);
    nsec3_item_rrv_data_t *rrv_data = (nsec3_item_rrv_data_t *)rrv->data;
    rrv_data->n3 = n3;
}

void nsec3_item_resource_record_view_ttl_set(resource_record_view_t *rrv, int32_t ttl)
{
    yassert(rrv->vtbl == &nsec3_item_rrv_vtbl);
    nsec3_item_rrv_data_t *rrv_data = (nsec3_item_rrv_data_t *)rrv->data;
    rrv_data->ttl = ttl;
}

void nsec3_item_resource_record_finalize(resource_record_view_t *rrv)
{
    yassert(rrv->vtbl == &nsec3_item_rrv_vtbl);
    ZFREE_OBJECT_OF_TYPE(rrv->data, nsec3_item_rrv_data_t);
    rrv->vtbl = NULL;
}

void nsec3_superdump(zdb_zone_t *zone)
{
#if HAS_SUPERDUMP
    uint32_t serial;
    uint8_t  label_name[256];
    uint8_t  digest[1 + DIGEST_LENGTH_MAX];
    uint8_t  digest_star[1 + DIGEST_LENGTH_MAX];

    zdb_zone_getserial(zone, &serial);
    if(serial < 1031434905)
    // if(serial < 1031434844)
    // if(serial < 1031404990)
    // if(serial < 1031387596)//1031387657//1031405085
    {
        return;
    }

    log_debug("SUPERDUMP: %{dnsname}/%d: checking NSEC3 links integrity", zone->origin, serial);

    zdb_zone_label_iterator iter;
    zdb_zone_label_iterator_init(zone, &iter);
    while(zdb_zone_label_iterator_hasnext(&iter))
    {
        uint32_t n = zdb_zone_label_iterator_nextname(&iter, label_name);
        (void)n;

        zdb_rr_label *label = zdb_zone_label_iterator_next(&iter);
#if 0
        if(memcmp(label->name, "\005nnepp", 6) == 0)
        {
            log_debug("HERE");
        }
#endif
        bool self_check = nsec3_superdump_integrity_check_label_nsec3_self_points_back(label, 0);
        bool star_check = nsec3_superdump_integrity_check_label_nsec3_star_points_back(label, 0);

        bool showme = !(self_check & star_check);

        if(showme)
        {
            nsec3_zone *n3 = zone->nsec.nsec3;
            // nsec3_label_extension_t *n3e = label->nsec.nsec3;
            int error_count = 0;

            while(n3 != NULL)
            {
                nsec3_superdump_hash(zone, n3, label, false, digest);
                nsec3_superdump_hash(zone, n3, label, true, digest_star);

                nsec3_zone_item_t *self_node = nsec3_find(&n3->items, digest);

                if(self_node)
                {
                    bool pointed_back = nsec3_superdump_nsec3_item_label_owner_array(self_node, false, "SUPERDUMP");

                    if(!pointed_back)
                    {
                        log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: %{digest32h} did not point back", zone->origin, serial, label_name, label, digest);
                        ++error_count;
                    }
                }

                nsec3_zone_item_t *star_node = nsec3_zone_item_find_encloser_start(n3, digest_star);

                if(star_node != NULL)
                {
                    bool pointed_back = nsec3_superdump_nsec3_item_label_owner_array(star_node, true, "SUPERDUMP");

                    if(!pointed_back)
                    {
                        log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: %{digest32h} did not point back", zone->origin, serial, label_name, label, digest_star);
                        ++error_count;
                    }
                }

                n3 = n3->next;
            }

            if(error_count > 0)
            {
                log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: self: %c star: %c", zone->origin, serial, label_name, label, self_check ? 'Y' : 'N', star_check ? 'Y' : 'N');

                // again, so I can debug it
                nsec3_superdump_integrity_check_label_nsec3_self_points_back(label, 0);
                nsec3_superdump_integrity_check_label_nsec3_star_points_back(label, 0);

                log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: flags=%x #subdomain=%i", zone->origin, serial, label_name, label, label->flags, dictionary_size(&label->sub));

                zdb_resource_record_sets_set_iterator_t iter;
                zdb_resource_record_sets_set_iterator_init(&label->resource_record_set, &iter);
                while(zdb_resource_record_sets_set_iterator_hasnext(&iter))
                {
                    zdb_resource_record_sets_node *node = zdb_resource_record_sets_set_iterator_next_node(&iter);
                    uint16_t                       type = zdb_resource_record_set_type(&node->value);

                    zdb_resource_record_data_t    *record = (zdb_resource_record_data_t *)rr_node->data;

                    if(record == NULL)
                    {
                        log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: %{dnstype} <EMPTY-SET>", zone->origin, serial, label_name, label, &type);
                    }

                    while(record != NULL)
                    {
                        rdata_desc_t rdatadesc = {type, record->rdata_size, record->rdata_start};
                        log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: %{typerdatadesc}", zone->origin, serial, label_name, label, &rdatadesc);
                        record = record->next;
                    }
                }
            }
            else
            {
                showme = false;
            }
        }

        nsec3_zone              *n3 = zone->nsec.nsec3;
        nsec3_label_extension_t *n3e = label->nsec.nsec3;

        while(n3e != NULL)
        {
            nsec3_superdump_hash(zone, n3, label, false, digest);
            nsec3_superdump_hash(zone, n3, label, true, digest_star);

            if(showme)
            {
                log_debug("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: n3e@%p %{digest32h} self@%p %{digest32h} star@%p", zone->origin, serial, label_name, label, n3e, digest, n3e->self, digest_star, n3e->star);
            }

            nsec3_zone_item_t *self = n3e->self;

            if(self != NULL)
            {
                nsec3_zone_item_t *self_next = nsec3_node_mod_next(self);
                nsec3_zone_item_t *self_prev = nsec3_node_mod_prev(self);
                if(showme)
                {
                    log_debug(
                        "SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: %{digest32h} R=%2i *=%2i (-> %{digest32h}) (<- "
                        "%{digest32h})",
                        zone->origin,
                        serial,
                        label_name,
                        label,
                        self->digest,
                        self->rc,
                        self->sc,
                        self_next->digest,
                        self_prev->digest);
                }

                nsec3_superdump_nsec3_item_label_owner_array(self, false, "SUPERDUMP");
                nsec3_superdump_nsec3_item_label_owner_array(self, true, "SUPERDUMP");
            }
            else
            {
                if(showme)
                {
                    log_debug("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: NULL self", zone->origin, serial, label_name, label);
                }
            }

            nsec3_zone_item_t *star = n3e->star;
            if(star != NULL)
            {
                nsec3_zone_item_t *star_next = nsec3_node_mod_next(star);
                nsec3_zone_item_t *star_prev = nsec3_node_mod_prev(star);
                if(showme)
                {
                    log_debug(
                        "SUPERDUMP*: %{dnsname}/%d: %{dnsname}@%p: %{digest32h} R=%2i *=%2i -> %{digest32h} <- "
                        "%{digest32h}",
                        zone->origin,
                        serial,
                        label_name,
                        label,
                        star->digest,
                        star->rc,
                        star->sc,
                        star_next->digest,
                        star_prev->digest);
                }
                nsec3_superdump_nsec3_item_label_owner_array(star, false, "SUPERDUMP*");
                nsec3_superdump_nsec3_item_label_owner_array(star, true, "SUPERDUMP*");
            }
            else
            {
                if(showme)
                {
                    log_debug("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: NULL star", zone->origin, serial, label_name, label);
                }
            }

            n3 = n3->next;
            n3e = n3e->next;
        }
    }

    log_debug("SUPERDUMP: %{dnsname}/%d: checking NSEC3 links integrity checked", zone->origin, serial);
#else
    (void)zone;
#endif
}

/** @} */

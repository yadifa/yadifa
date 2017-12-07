/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2017, EURid. All rights reserved.
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
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnsdb/dnsdb-config.h"
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

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/nsec3.h"
#include "dnsdb/nsec_common.h"
#include "dnsdb/nsec3_owner.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/dynupdate-diff.h"

#ifndef NSEC3_LABEL_DEBUG
#ifdef DEBUG
#define NSEC3_LABEL_DEBUG 1 // set to 1 for debugging ...
#else
#define NSEC3_LABEL_DEBUG 0
#endif
#endif

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;



/**
 * used by nsec3_label_link
 * 
 * It will find if the label has got a matching NSEC3 record (by digest)
 * If so, it will link to it.
 */

static nsec3_zone_item *
nsec3_label_link_seeknode(nsec3_zone* n3, const u8 *fqdn, s32 fqdn_len, u8 *digest)
{
    nsec3_compute_digest_from_fqdn_with_len(n3, fqdn, fqdn_len, digest, FALSE);
    
#if NSEC3_LABEL_DEBUG
    log_debug("nsec3: seeking node for %{dnsname} with %{digest32h}", fqdn, digest);
#endif

    nsec3_zone_item *self = nsec3_avl_find(&n3->items, digest);

    return self;
}

/**
 * used by nsec3_label_link
 * 
 * It will find if the *.label has got a matching NSEC3 record (by digest)
 * If so, it will link to it.
 */

static nsec3_zone_item *
nsec3_label_link_seekstar(nsec3_zone* n3, const u8 *fqdn, s32 fqdn_len, u8 *digest)
{
    nsec3_compute_digest_from_fqdn_with_len(n3, fqdn, fqdn_len, digest, TRUE);
    
#if NSEC3_LABEL_DEBUG
    log_debug("nsec3: seeking star for %{dnsname} with %{digest32h}", fqdn, digest);
#endif

    nsec3_zone_item* star = nsec3_avl_find_interval_start(&n3->items, digest);

    return star;
}

/*
 * This destroy all the NSEC3 structures from the zone, starting from the NSEC3PARAM.
 * The zdb_rr_label are also affected by the call.
 */

void
nsec3_destroy_zone(zdb_zone *zone)
{
     // Note that from the 'transaction' update, the dnssec zone collections have to be read without checking for the NSEC3 flag
#if NSEC3_LABEL_DEBUG 
    nsec3_check(zone);
#endif

    while(zone->nsec.nsec3 != NULL)
    {
#ifdef DEBUG
        nsec3_zone *n3 = zone->nsec.nsec3;
#endif
        nsec3_zone_destroy(zone, zone->nsec.nsec3);
#ifdef DEBUG
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
static int
nsec3_get_closest_provable_encloser_match(const void *label, const dictionary_node *node)
{
    zdb_rr_label* rr_label = (zdb_rr_label*) node;
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

const zdb_rr_label*
nsec3_get_closest_provable_encloser_optin(const zdb_rr_label *apex, const_dnslabel_vector_reference sections, s32 *sections_topp)
{
    yassert(apex != NULL && sections != NULL && sections_topp != NULL);

    s32 index = *sections_topp;
    const zdb_rr_label* rr_label = apex; /* the zone cut */

    const zdb_rr_label* provable = apex;

    /*
     * the apex is already known, so we don't loop for it
     */

    index--;

    /* look into the sub level*/

    while(index >= 0)
    {
        const u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);

        rr_label = (zdb_rr_label*) dictionary_find(&rr_label->sub, hash, label, nsec3_get_closest_provable_encloser_match);

        if(rr_label == NULL)
        {
            index++;
            break;
        }

        if((rr_label->flags & ZDB_RR_LABEL_N3COVERED) == ZDB_RR_LABEL_N3COVERED)
        {
            provable = rr_label;
            *sections_topp = index;
        }

        index--;
    }

    return provable;
}

const zdb_rr_label*
nsec3_get_closest_provable_encloser_optout(const zdb_rr_label *apex, const_dnslabel_vector_reference sections, s32 *sections_topp)
{
    yassert(apex != NULL && sections != NULL && sections_topp != NULL);

    s32 index = *sections_topp;
    const zdb_rr_label* rr_label = apex; /* the zone cut */

    const zdb_rr_label* provable = apex;

    /*
     * the apex is already known, so we don't loop for it
     */

    index--;

    /* look into the sub level*/

    while(index >= 0)
    {
        const u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);

        rr_label = (zdb_rr_label*) dictionary_find(&rr_label->sub, hash, label, nsec3_get_closest_provable_encloser_match);

        if(rr_label == NULL)
        {
            index++;
            break;
        }

        if((rr_label->flags & ZDB_RR_LABEL_N3OCOVERED) == ZDB_RR_LABEL_N3OCOVERED)
        {
            provable = rr_label;
            *sections_topp = index;
        }

        index--;
    }

    return provable;
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
 */

void
nsec3_closest_encloser_proof(
                        const zdb_zone *zone,
                        const dnsname_vector *qname, s32 apex_index,
                        const nsec3_zone_item **encloser_nsec3p,
                        const nsec3_zone_item **closest_provable_encloser_nsec3p,
                        const nsec3_zone_item **wild_closest_provable_encloser_nsec3p
                        )
{
    u8 closest_provable_encloser[MAX_DOMAIN_LENGTH+1];
    u8 encloser[MAX_DOMAIN_LENGTH+1];
    u8 digest[64 + 1];
    digest[0] = 20;
    
    yassert(encloser_nsec3p != NULL);
    yassert(closest_provable_encloser_nsec3p != NULL);
    // wild_closest_provable_encloser_nsec3p can be NULL 

    const_dnslabel_vector_reference qname_sections = qname->labels;
    s32 closest_encloser_index_limit = qname->size - apex_index + 1; /* not "+1'" because it starts at the apex */

    const nsec3_zone* n3 = zone->nsec.nsec3;
    
#ifdef DEBUG
    if((n3 == NULL) || (n3->items == NULL))
    {
        log_err("zone %{dnsname} has invalid NSEC3 data");
        return;
    }
#endif
    
    if(closest_encloser_index_limit > 0)
    {
        const zdb_rr_label* closest_provable_encloser_label = ((zone->_flags & ZDB_ZONE_HAS_OPTOUT_COVERAGE) != 0)?
                nsec3_get_closest_provable_encloser_optout(zone->apex, qname_sections, &closest_encloser_index_limit):
                nsec3_get_closest_provable_encloser_optin(zone->apex, qname_sections, &closest_encloser_index_limit);
        
        //log_debug("closest_provable_encloser_label: %{dnslabel}: %{digest32h}", closest_provable_encloser_label->name, closest_provable_encloser_label->nsec.nsec3->self->digest);
        //log_debug("*.closest_provable_encloser_label: %{dnslabel}: %{digest32h}", closest_provable_encloser_label->name, closest_provable_encloser_label->nsec.nsec3->star->digest);

        /*
         * Convert from closest_encloser_label_bottom to name.size into a dnslabel
         */

        /* Get ZONE NSEC3PARAM */
        u16 iterations = nsec3_zone_get_iterations(n3);
        u8 salt_len = NSEC3_ZONE_SALT_LEN(n3);
        const u8* salt = NSEC3_ZONE_SALT(n3);

        nsec3_hash_function* const digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3)); /// @note 20150917 edf -- do not use nsec3_compute_digest_from_fqdn_with_len

        /** @note log_* cannot be used here (except yassert because if that one logs it will abort anyway ...) */

        // encloser_nsec3p
        
        if(closest_encloser_index_limit > 0) // if the closest encloser is itself, we should not be here
        {
            yassert(closest_provable_encloser_label != NULL); 

            const nsec3_zone_item* encloser_nsec3;
            dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit - 1, encloser);
            digestname(encloser, dnsname_len(encloser), salt, salt_len, iterations, &digest[1], FALSE);
            encloser_nsec3 = nsec3_zone_item_find_encloser_start(n3, digest);
            *encloser_nsec3p = encloser_nsec3;
        }
        else
        {
            *encloser_nsec3p = NULL;
        }

        // closest_provable_encloser_nsec3p

        dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit  , closest_provable_encloser);

        const nsec3_zone_item* closest_provable_encloser_nsec3;
        

            digestname(closest_provable_encloser, dnsname_len(closest_provable_encloser), salt, salt_len, iterations, &digest[1], FALSE);
            closest_provable_encloser_nsec3 = nsec3_avl_find(&n3->items, digest);

        
        *closest_provable_encloser_nsec3p = closest_provable_encloser_nsec3;
        
        if(wild_closest_provable_encloser_nsec3p != NULL)
        {
            if(closest_provable_encloser_nsec3p == NULL)
            {
                dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit  , closest_provable_encloser);
            }

            const nsec3_zone_item* wild_closest_provable_encloser_nsec3;

            if(!zdb_rr_label_nsec3_linked(closest_provable_encloser_label))
            {
                digestname(closest_provable_encloser, dnsname_len(closest_provable_encloser), salt, salt_len, iterations, &digest[1], TRUE);
                wild_closest_provable_encloser_nsec3 = nsec3_avl_find_interval_start(&n3->items, digest);
            }
            else
            {
                wild_closest_provable_encloser_nsec3 = closest_provable_encloser_label->nsec.nsec3->self;
            }

            *wild_closest_provable_encloser_nsec3p = wild_closest_provable_encloser_nsec3;
        }
    }
    else // the closest is the item itself ...
    {
        *encloser_nsec3p = zone->apex->nsec.nsec3->self;
        *closest_provable_encloser_nsec3p = zone->apex->nsec.nsec3->self;
        if(wild_closest_provable_encloser_nsec3p != NULL)
        {
            *wild_closest_provable_encloser_nsec3p = zone->apex->nsec.nsec3->self;
        }
    }
}

#if NSEC3_LABEL_DEBUG

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

void
nsec3_check_item(nsec3_zone_item *item, u32 param_index_base)
{
    yassert(item != NULL);

    u16 n = nsec3_owner_count(item);

    for(u16 i = 0; i < n; i++)
    {
        zdb_rr_label *label = nsec3_owner_get(item, i);

        yassert(label != NULL && label->nsec.nsec3 != NULL);
        
        if(ZDB_LABEL_UNDERDELEGATION(label))
        {
            log_debug("nsec3_check: %{digest32h} label nsec3 reference under a delegation (%{dnslabel})", item->digest, label);
        }

        nsec3_label_extension *n3le = label->nsec.nsec3;

        u32 param_index = param_index_base;
        while(param_index > 0)
        {
            yassert(n3le != NULL);



            n3le = n3le->next;

            param_index--;
        }

        yassert(n3le != NULL);


        // the nsec3 structure reference to the item linked to the label does not links back to the item
#if 0 /* fix */
#else
        yassert(n3le->self == item);
#endif
    }

    n = nsec3_star_count(item);

    for(u16 i = 0; i < n; i++)
    {
        zdb_rr_label *label = nsec3_star_get(item, i);
        
        if(!((label != NULL) && (label->nsec.nsec3 != NULL)))
        {
            log_debug("nsec3_check: %{digest32h} (#self=%d/#star=%d) corrupted", item->digest, item->rc, item->sc);
        }

        yassert(label != NULL && label->nsec.nsec3 != NULL);
        
        if(ZDB_LABEL_UNDERDELEGATION(label))
        {
            log_debug("nsec3_check: %{digest32h} *.label nsec3 reference under a delegation (%{dnslabel})", item->digest, label);
        }

        nsec3_label_extension *n3le = label->nsec.nsec3;

        u32 param_index = param_index_base;
        while(param_index > 0)
        {
            yassert(n3le != NULL);



            n3le = n3le->next;

            param_index--;
        }

        yassert(n3le != NULL);



        if(n3le->star != item)
        {
            if(n3le->star != NULL)
            {
                log_debug("nsec3_check: %{digest32h} (#self=%d/#star=%d) failing %{dnslabel} expected %{digest32h}", item->digest, item->rc, item->sc, label->name, n3le->star->digest);
            }
            else
            {
                log_debug("nsec3_check: %{digest32h} (#self=%d/#star=%d) *.%{dnslabel} is NULL", item->digest, item->rc, item->sc, label->name, n3le->star->digest);
            }
        }

        if(n3le->self == NULL)
        {
            log_debug("nsec3_check: %{digest32h} (#self=%d/#star=%d) failing %{dnslabel}: no self", item->digest, item->rc, item->sc, label->name);
        }
        
        if(n3le->star != item)
        {
            log_debug("nsec3_check: %{digest32h} *.label nsec3 reference does not point back to the nsec3 item (%{dnslabel})", item->digest, label);
        }
        if(n3le->self == NULL)
        {
            log_debug("nsec3_check: %{digest32h} *.label nsec3 reference self is NULL (%{dnslabel})", item->digest, label);
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

void
nsec3_check(zdb_zone *zone)
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

    u32 param_index = 0;

    while(n3 != NULL)
    {
        nsec3_avl_iterator n3iter;
        nsec3_avl_iterator_init(&n3->items, &n3iter);
        while(nsec3_avl_iterator_hasnext(&n3iter))
        {
            nsec3_zone_item* item = nsec3_avl_iterator_next_node(&n3iter);

            nsec3_check_item(item, param_index);
        }

        param_index++;

        n3 = n3->next;
    }
    
    log_debug("nsec3_check: %{dnsname}: from the label's reference", zone->origin);
    
    zdb_zone_label_iterator label_iterator;
    u8 fqdn[MAX_DOMAIN_LENGTH + 1];
    
    zdb_zone_label_iterator_init(&label_iterator, zone);

    while(zdb_zone_label_iterator_hasnext(&label_iterator))
    {
        zdb_zone_label_iterator_nextname(&label_iterator, fqdn);
        zdb_rr_label* label = zdb_zone_label_iterator_next(&label_iterator);
        
        nsec3_label_extension *n3le = label->nsec.nsec3;

        while(n3le != NULL)
        {
            if(n3le->self != NULL)
            {
                int found = 0;

                for(s32 i = 0; i < n3le->self->rc; ++i)
                {
                    zdb_rr_label* self = nsec3_owner_get(n3le->self, i);
                    if(self == label)
                    {
                        ++found;
                    }
                }

                if(found == 0)
                {
                    log_debug("nsec3_check: %{dnsname}: %{dnsname} => %{digest32h} is one way", zone->origin, fqdn, n3le->self->digest);
                }
                else if(found > 1)
                {
                    log_debug("nsec3_check: %{dnsname}: %{dnsname} => %{digest32h} is referenced back multiple times", zone->origin, fqdn, n3le->self->digest);
                }
            }

            if(n3le->star != NULL)
            {
                int found = 0;

                for(s32 i = 0; i < n3le->star->sc; ++i)
                {
                    zdb_rr_label* star = nsec3_star_get(n3le->star, i);
                    if(star == label)
                    {
                        ++found;
                    }
                }

                if(found == 0)
                {
                    log_debug("nsec3_check: %{dnsname}: *.%{dnsname} => %{digest32h} is one way", zone->origin, fqdn, n3le->star->digest);
                }
                else if(found > 1)
                {
                    log_debug("nsec3_check: %{dnsname}: *.%{dnsname} => %{digest32h} is referenced back multiple times", zone->origin, fqdn, n3le->star->digest);
                }
            }
            
            n3le = n3le->next;
        }
    }
    
    log_debug("nsec3_check: %{dnsname} : done", zone->origin);
}

#else 

void
nsec3_check_item(nsec3_zone_item *item, u32 param_index_base)
{
    log_debug("nsec3_check_item(%p, %d) function has been disabled", item, param_index_base);
}

void
nsec3_check(zdb_zone *zone)
{
    log_debug("nsec3_check(%p) function has been disabled", zone);
}

#endif

void
nsec3_compute_digest_from_fqdn_with_len(const nsec3_zone *n3, const u8 *fqdn, u32 fqdn_len, u8 *digest, bool isstar)
{
    digest[0] = nsec3_hash_len(NSEC3_ZONE_ALGORITHM(n3));
    
    nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3))(
                                    fqdn,
                                    fqdn_len,
                                    NSEC3_ZONE_SALT(n3),
                                    NSEC3_ZONE_SALT_LEN(n3),
                                    nsec3_zone_get_iterations(n3),
                                    &digest[1],
                                    isstar);
}

void
nsec3_zone_label_detach(zdb_rr_label *label)
{
    yassert((label != NULL) && (label->flags & (ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT)) != 0);
    
    nsec3_label_extension *n3le = label->nsec.nsec3;

    while(n3le != NULL)
    {
        // remove
        if(n3le->self != NULL)
        {
            nsec3_remove_owner(n3le->self, label);
        }
        if(n3le->star != NULL)
        {
            nsec3_remove_star(n3le->star, label);
        }
        label->flags &= ~(ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT);
        label->nsec.nsec3 = NULL;
        nsec3_label_extension *tmp = n3le;
        n3le = n3le->next;
        nsec3_label_extension_free(tmp);
    }
    
    label->nsec.nsec3 = NULL;
}

ya_result
nsec3_get_next_digest_from_rdata(const u8 *rdata, u32 rdata_size, u8 *digest, u32 digest_size)
{
    if((NSEC3_RDATA_ALGORITHM(rdata) == NSEC3_DIGEST_ALGORITHM_SHA1) && (rdata_size > 5 + 21))
    {
        u8 salt_size = rdata[4];
        u8 hash_size = rdata[5 + salt_size];
        if((hash_size < digest_size) && (hash_size + salt_size + 5 < rdata_size))
        {
            memcpy(digest, &rdata[5 + salt_size], hash_size + 1);
            return hash_size +1;
        }
    }
    
    return ERROR;
}

void
nsec3_zone_label_update_chain0_links(nsec3_zone *n3, zdb_rr_label* label, const u8 *fqdn)
{
    nsec3_label_extension *n3le = label->nsec.nsec3;
    u8 digest[1 + MAX_DIGEST_LENGTH];

    if(label->flags & (ZDB_RR_LABEL_N3OCOVERED|ZDB_RR_LABEL_N3COVERED))
    {
        if(n3le == NULL)
        {
            n3le = nsec3_label_extension_alloc();
            ZEROMEMORY(n3le, sizeof(nsec3_label_extension));
            label->nsec.nsec3 = n3le;
            if(label->flags & ZDB_RR_LABEL_N3OCOVERED)
            {
                label->flags |= ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT;
            }
            else
            {
                label->flags |= ZDB_RR_LABEL_NSEC3;
            }
        }

        if(n3le->self == NULL || n3le->star == NULL)
        {
            s32 fqdn_len = dnsname_len(fqdn);

            if(n3le->self == NULL)
            {
                nsec3_zone_item *self = nsec3_label_link_seeknode(n3, fqdn, fqdn_len, digest);
                if(self != NULL)
                {
                    nsec3_add_owner(self, label);
                    n3le->self = self;
#if HAS_SUPERDUMP
                    nsec3_superdump_integrity_check_label_nsec3_self_points_back(label,0);
                    nsec3_superdump_integrity_check_nsec3_owner_self_points_back(self,0);
#endif
                }
            }
            if(n3le->star == NULL)
            {
                nsec3_zone_item *star = nsec3_label_link_seekstar(n3, fqdn, fqdn_len, digest);
                if(star != NULL)
                {
                    //nsec3_superdump_integrity_check_label_nsec3_star_points_back(label,0);
                    nsec3_add_star(star, label);
                    n3le->star = star;
#if HAS_SUPERDUMP
                    nsec3_superdump_integrity_check_label_nsec3_star_points_back(label,0);
                    nsec3_superdump_integrity_check_nsec3_owner_star_points_back(star,0);
#endif
                }
            }
        }
    }
    else
    {
        if(n3le != NULL)
        {
            // remove
            if(n3le->self != NULL)
            {
                nsec3_remove_owner(n3le->self, label);
            }
            if(n3le->star != NULL)
            {
                nsec3_remove_star(n3le->star, label);
            }
            nsec3_label_extension_free(n3le);
            label->flags &= ~(ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT);
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

void
nsec3_zone_update_chain0_links(zdb_zone *zone)
{
    nsec3_zone *n3 = zone->nsec.nsec3;
    
    if(n3 == NULL)
    {
        return;
    }
    
    u16 coverage_mask;
    u8 maintain_mode = zone_get_maintain_mode(zone);
    if(maintain_mode & ZDB_ZONE_HAS_OPTOUT_COVERAGE)
    {
        coverage_mask = ZDB_RR_LABEL_N3OCOVERED;
    }
    else
    {
        coverage_mask = ZDB_RR_LABEL_N3COVERED;
    }
    
    zdb_zone_label_iterator label_iterator;
    u8 fqdn[MAX_DOMAIN_LENGTH + 1];
    u8 digest[1 + MAX_DIGEST_LENGTH];
    
    zdb_zone_label_iterator_init(&label_iterator, zone);

    while(zdb_zone_label_iterator_hasnext(&label_iterator))
    {
        zdb_zone_label_iterator_nextname(&label_iterator, fqdn);
        zdb_rr_label* label = zdb_zone_label_iterator_next(&label_iterator);
        nsec3_label_extension *n3le = label->nsec.nsec3;
        
        if((label->flags & coverage_mask) != 0)
        {
            if(n3le == NULL)
            {
                n3le = nsec3_label_extension_alloc();
                ZEROMEMORY(n3le, sizeof(nsec3_label_extension));
                label->nsec.nsec3 = n3le;
                if(label->flags & ZDB_RR_LABEL_N3OCOVERED)
                {
                    label->flags |= ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT;
                }
                else
                {
                    label->flags |= ZDB_RR_LABEL_NSEC3;
                }
            }
        
            if(n3le->self == NULL || n3le->star == NULL)
            {
                s32 fqdn_len = dnsname_len(fqdn);
                
                if(n3le->self == NULL)
                {
                    nsec3_zone_item *self = nsec3_label_link_seeknode(n3, fqdn, fqdn_len, digest);
                    if(self != NULL)
                    {
                        nsec3_add_owner(self, label);
                        n3le->self = self;
#if HAS_SUPERDUMP
                        nsec3_superdump_integrity_check_label_nsec3_self_points_back(label,0);
                        nsec3_superdump_integrity_check_nsec3_owner_self_points_back(self,0);
#endif
                    }
                }
                if(n3le->star == NULL)
                {
                    nsec3_zone_item *star = nsec3_label_link_seekstar(n3, fqdn, fqdn_len, digest);
                    if(star != NULL)
                    {
                        //nsec3_superdump_integrity_check_label_nsec3_star_points_back(label,0);
                        nsec3_add_star(star, label);
                        n3le->star = star;
#if HAS_SUPERDUMP
                        nsec3_superdump_integrity_check_label_nsec3_star_points_back(label,0);
                        nsec3_superdump_integrity_check_nsec3_owner_star_points_back(star,0);
#endif
                    }
                }
            }
        }
        else
        {
            if(n3le != NULL)
            {
                // remove
                if(n3le->self != NULL)
                {
                    nsec3_remove_owner(n3le->self, label);
                }
                if(n3le->star != NULL)
                {
                    nsec3_remove_star(n3le->star, label);
                }
                nsec3_label_extension_free(n3le);
                label->flags &= ~(ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT);
                label->nsec.nsec3 = NULL;
            }
        }
    }
}

#if HAS_SUPERDUMP
/*
static int nsicnospb_c = 0;
*/
static bool
nsec3_superdump_integrity_check_nsec3_owner_star_points_back(const nsec3_zone_item *n3i, int depth)
{
    /*
    ++nsicnospb_c;
    if(nsicnospb_c == 37)
    {
        log_debug("");
    }
    */
    u16 n = n3i->sc;
    bool ret = FALSE;
    switch(n)
    {
        case 0:
        {
            // possible
            ret = TRUE;
            break;
        }
        case 1:
        {
            // oopsie
            const zdb_rr_label *label = n3i->star_label.owner;
            nsec3_label_extension *n3e = label->nsec.nsec3;
            while(!ret && n3e != NULL)
            {
                ret = n3e->star == n3i;
                n3e = n3e->next;
            }
            break;
        }
        default:
        {
            for(u16 i = 0; !ret && i < n; ++i)
            {
                const zdb_rr_label *label = n3i->star_label.owners[i];
                nsec3_label_extension *n3e = label->nsec.nsec3;
                while(!ret && n3e != NULL)
                {
                    ret = n3e->star == n3i;
                    n3e = n3e->next;
                }
            }
            break;
        }
    }
    
    if(!ret)
    {
        log_err("star integrity failed on %{digest32h} %hu", n3i->digest, n);
        //logger_flush();
        switch(n)
        {
            case 1:
            {
                // oopsie
                const zdb_rr_label *label = n3i->star_label.owner;
                nsec3_label_extension *n3e = label->nsec.nsec3;
                
                while(n3e != NULL)
                {
                    if(n3e->star != NULL)
                    {
                        log_err("  the label *.%{dnslabel} pointed by %{digest32h} %hu instead points to %{digest32h} @ %p", label->name, n3i->digest, n, n3e->star->digest, n3e->star);
                    }
                    else
                    {
                        log_err("  the label *.%{dnslabel} pointed by %{digest32h} %hu instead points to NULL", label->name, n3i->digest, n);
                    }
                    n3e = n3e->next;
                }
                break;
            }
            default:
            {
                for(u16 i = 0; i < n; ++i)
                {
                    const zdb_rr_label *label = n3i->star_label.owners[i];
                    nsec3_label_extension *n3e = label->nsec.nsec3;
                    while(n3e != NULL)
                    {
                        if(n3e->star != NULL)
                    {
                        log_err("  the label *.%{dnslabel} pointed by %{digest32h} %hu instead points to %{digest32h} @ %p", label->name, n3i->digest, n, n3e->star->digest, n3e->star);
                    }
                    else
                    {
                        log_err("  the label *.%{dnslabel} pointed by %{digest32h} %hu instead points to NULL", label->name, n3i->digest, n);
                    }
                        n3e = n3e->next;
                    }
                }
                break;
            }
        }
        //logger_flush();
    }
    
    return ret;
}

static int nsicnotpb_c = 0;

static bool
nsec3_superdump_integrity_check_nsec3_owner_self_points_back(const nsec3_zone_item *n3i, int depth)
{
    ++nsicnotpb_c;
    if(nsicnotpb_c == 445)
    {
        log_debug("");
    }
    
    u16 n = n3i->rc;
    bool ret = FALSE;
    switch(n)
    {
        case 0:
        {
            // oopsie
            ret = FALSE;
            break;
        }
        case 1:
        {
            // oopsie
            const zdb_rr_label *label = n3i->label.owner;
            nsec3_label_extension *n3e = label->nsec.nsec3;
            while(!ret && n3e != NULL)
            {
                ret = n3e->self == n3i;
                n3e = n3e->next;
            }
            break;
        }
        default:
        {
            for(u16 i = 0; !ret && i < n; ++i)
            {
                const zdb_rr_label *label = n3i->label.owners[i];
                nsec3_label_extension *n3e = label->nsec.nsec3;
                while(!ret && n3e != NULL)
                {
                    ret = n3e->self == n3i;
                    n3e = n3e->next;
                }
            }
            break;
        }
    }
    
    if(!ret)
    {
        log_err("self integrity failed on %{digest32h} %hu", n3i->digest, n);
        //logger_flush();
        switch(n)
        {
            case 1:
            {
                // oopsie
                const zdb_rr_label *label = n3i->star_label.owner;
                nsec3_label_extension *n3e = label->nsec.nsec3;
                
                while(n3e != NULL)
                {
                    log_err("  the label %{dnslabel} pointed by %{digest32h} %hu instead points to %{digest32h} @ %p", label->name, n3i->digest, n, n3e->self->digest, n3e->self);
                    n3e = n3e->next;
                }
                break;
            }
            default:
            {
                for(u16 i = 0; !ret && i < n; ++i)
                {
                    const zdb_rr_label *label = n3i->star_label.owners[i];
                    nsec3_label_extension *n3e = label->nsec.nsec3;
                    while(n3e != NULL)
                    {
                        log_err("  the label %{dnslabel} pointed by %{digest32h} %hu instead points to %{digest32h} @ %p", label->name, n3i->digest, n, n3e->self->digest, n3e->self);
                        n3e = n3e->next;
                    }
                }
                break;
            }
        }
        //logger_flush();
    }
        
    return ret;
}

static bool
nsec3_superdump_integrity_check_label_nsec3_star_points_back(const zdb_rr_label *label, int depth)
{
    struct nsec3_label_extension* n3e = label->nsec.nsec3;
    u16 n = 65535;
    bool ret = (n3e == NULL);
    int n3e_count = 0;
    int self_count = 0;
    int star_count = 0;
    
    while(!ret && n3e != NULL)
    {
        n = 65535;
        
        ++n3e_count;
        
        if(n3e->self != NULL)
        {
            ++self_count;
        }
        
        nsec3_zone_item* star = n3e->star;
                
        if(star != NULL)
        {
            ++star_count;
            
            n = star->sc;
            
            switch(n)
            {
                case 0:
                {
                    ret = FALSE;
                    break;
                }
                case 1:
                {
                    ret = star->star_label.owner == label;
                    break;
                }
                default:
                {
                    for(u16 i = 0; i < n; ++i)
                    {
                        if(star->star_label.owners[i] == label)
                        {
                            ret = TRUE;
                            break;
                        }
                    }
                    break;
                }
            }
        }
        else
        {
            ret = n3e->self == NULL;
        }
        
        n3e = n3e->next;
    }
    
    if(!ret)
    {
        if(label->nsec.nsec3 == NULL)
        {
            log_warn("star integrity failed on %{dnslabel}: there is no nsec3 label extension", label->name);
        }
        else
        {
            if(n != 65535)
            {
                log_warn("star integrity failed on %{dnslabel}: could not find *label->nsec3 link among the %hu known owners (%i: %i & %i)", label->name, n, n3e_count, self_count, star_count);
            }
            else
            {
                log_warn("star integrity failed on %{dnslabel}: could not find *label->nsec3 link (%i: %i & %i)", label->name, n3e_count, self_count, star_count);
            }
        }
    }
    
    return ret;
}

static bool
nsec3_superdump_integrity_check_label_nsec3_self_points_back(const zdb_rr_label *label, int depth)
{
    (void)depth;
    struct nsec3_label_extension* n3e;
    u16 n = ~0;
    bool ret = label->nsec.nsec3 == NULL;
    n3e = label->nsec.nsec3;
    
    while(!ret && n3e != NULL)
    {
        nsec3_zone_item* self = n3e->self;
        if(self != NULL)
        {
            n = self->rc;
            switch(n)
            {
                case 0:
                {
                    ret = FALSE;
                    break;
                }
                case 1:
                {
                    ret = self->label.owner == label;
                    break;
                }
                default:
                {
                    for(u16 i = 0; i < n; ++i)
                    {
                        if(self->label.owners[i] == label)
                        {
                            ret = TRUE;
                            break;
                        }
                    }
                    break;
                }
            }
        }
        else
        {
            ret = n3e->star == NULL;
        }
                
        n3e = n3e->next;
    }
    
    if(!ret)
    {
        log_err("self integrity failed on %{dnslabel} %hu", label->name, n);
        //logger_flush();
    }
            
    return ret;
}
/*
static bool
nsec3_superdump_integrity_check(const zdb_rr_label *label, nsec3_zone_item *self_or_star)
{
    bool ret = (label->nsec.dnssec != NULL) && ((label->nsec.nsec3->self == self_or_star) || (label->nsec.nsec3->star == self_or_star));
    if(!ret)
    {
        log_err("integrity failed!");
        logger_flush();
    }
    return ret;
}
*/
static bool
nsec3_superdump_nsec3_label_pointer_array(nsec3_zone_item *n3i /* or star */, bool star, const char *hdr)
{
    nsec3_label_pointer_array p;
    const char *pfx;
    int n;
    bool self_check;
    
    if(!star)
    {
         p = n3i->label;
         n = n3i->rc;
         pfx = "";
         self_check = nsec3_superdump_integrity_check_nsec3_owner_self_points_back(n3i,0);
    }
    else
    {
        p = n3i->star_label;
        n = n3i->sc;
        pfx = "*.";
        self_check = nsec3_superdump_integrity_check_nsec3_owner_star_points_back(n3i,0);
    }
        
    if(n == 0)
    {
        log_debug3("%s:        [0] <- NULL", hdr);
    }
    else if(n == 1)
    {
        log_debug3("%s:        [%i] <- %s%{dnslabel}@%p (%i)", hdr, n, pfx, p.owner->name, p.owner, self_check);
    }
    else
    {
        for(int i = 0; i < n; ++i)
        {
            log_debug3("%s:        [%i] <- %s%{dnslabel}@%p (%i)", hdr, i, pfx, p.owners[i]->name, p.owners[i], self_check);
        }
    }
    
    return self_check;
}

static void
nsec3_superdump_hash(zdb_zone *zone, nsec3_zone* n3, zdb_rr_label *label, bool star, u8 *digest)
{
    u32 name_len = 0;
    u8 name[MAX_DOMAIN_LENGTH];
    name_len = 0;
    name_len += label->name[0] + 1;
    memcpy(name, label->name, name_len);
    name_len += dnsname_copy(&name[name_len], zone->origin);
    
    digest[0] = nsec3_hash_len(NSEC3_ZONE_ALGORITHM(n3));

            /*
                * Retrieve the NSEC3 hash algorithm function and compute the digest for this fqdn
                */

    nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3))(
            name,
            name_len,
            NSEC3_ZONE_SALT(n3),
            NSEC3_ZONE_SALT_LEN(n3),
            nsec3_zone_get_iterations(n3),
            &digest[1],
            star);
}

#endif

#if HAS_MASTER_SUPPORT
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

ya_result
nsec3_zone_set_status(zdb_zone *zone, u8 secondary_lock, u8 algorithm, u8 optout, u16 iterations, const u8 *salt, u8 salt_len, u8 status)
{
    dynupdate_message dmsg;
    packet_unpack_reader_data reader;
    dynupdate_message_init(&dmsg, zone->origin, CLASS_IN);
    
    u8 prev_status = 0;    
    u8 nsec3paramadd_rdata[5 + salt_len + 1];
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
            // already set
            
            return SUCCESS;
        }
        dynupdate_message_del_record(&dmsg, zone->origin, TYPE_NSEC3CHAINSTATE, 0, 6 + salt_len, nsec3paramadd_rdata);
        nsec3paramadd_rdata[5 + salt_len] = status;
    }
    
    dynupdate_message_add_record(&dmsg, zone->origin, TYPE_NSEC3CHAINSTATE, 0, 6 + salt_len, nsec3paramadd_rdata);
    
    dynupdate_message_set_reader(&dmsg, &reader);
    u16 count = dynupdate_message_get_count(&dmsg);

    packet_reader_skip(&reader, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&reader);
    packet_reader_skip(&reader, 4);
    
    ya_result ret;
    
    ret = dynupdate_diff(zone, &reader, count, secondary_lock, FALSE); // TODO
    
    dynupdate_message_finalise(&dmsg);
        
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

ya_result nsec3_zone_get_status(zdb_zone *zone, u8 algorithm, u8 optout, u16 iterations, const u8 *salt, u8 salt_len, u8 *statusp)
{
    // get the TYPE_NSEC3PARAMADD record set
    // search for a record matching the chain
    zdb_packed_ttlrdata *rrset = zdb_record_find(&zone->apex->resource_record_set, TYPE_NSEC3CHAINSTATE);
    while(rrset != NULL)
    {
        if(rrset->rdata_size == 6 + salt_len)
        {
            if(rrset->rdata_start[0] == algorithm)
            {
                if(rrset->rdata_start[1] == optout)
                {
                    if(GET_U16_AT(rrset->rdata_start[2]) == htons(iterations))
                    {
                        if(rrset->rdata_start[4] == salt_len)
                        {
                            if(memcmp(&rrset->rdata_start[5], salt, salt_len) == 0)
                            {
                                *statusp = rrset->rdata_start[5 + salt_len];
                                return 1;
                            }
                        }
                    }
                }
            }
            rrset = rrset->next;
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

ya_result
nsec3_zone_get_status_from_rdata(zdb_zone *zone, const u8* rdata, u16 rdata_size, u8 *statusp)
{
    // get the TYPE_NSEC3PARAMADD record set
    // search for a record matching the chain
    zdb_packed_ttlrdata *rrset = zdb_record_find(&zone->apex->resource_record_set, TYPE_NSEC3CHAINSTATE);
    while(rrset != NULL)
    {
        if(rrset->rdata_size == rdata_size + 1)
        {
            if(rrset->rdata_start[0] == rdata[0])
            {
                if(GET_U16_AT(rrset->rdata_start[2]) == GET_U16_AT(rdata[2]))
                {
                    if(rrset->rdata_start[4] == rdata[4])
                    {
                        if(memcmp(&rrset->rdata_start[5], &rdata[5], rdata[4]) == 0)
                        {
                            *statusp = rrset->rdata_start[5 + rdata[4]];
                            return 1;
                        }
                    }
                }
            }
            rrset = rrset->next;
        }
    }
    
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

int
nsec3_zone_get_chain_count(zdb_zone *zone)
{
    int ret = 0;
    nsec3_zone *n3 = zone->nsec.nsec3;
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

int
nsec3_zone_get_chains(zdb_zone *zone, nsec3_zone **n3p, int max_count)
{
    int ret = 0;
    nsec3_zone *n3 = zone->nsec.nsec3;
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

void
nsec3_superdump(zdb_zone *zone)
{
#if HAS_SUPERDUMP
    u32 serial;
    u8 label_name[256];
    u8 digest[1 + MAX_DIGEST_LENGTH];
    u8 digest_star[1 + MAX_DIGEST_LENGTH];
    
    zdb_zone_getserial(zone, &serial);
    if(serial < 1031434905)
    //if(serial < 1031434844)
    //if(serial < 1031404990)
    //if(serial < 1031387596)//1031387657//1031405085
    {
        return;
    }
    
    log_debug("SUPERDUMP: %{dnsname}/%d: checking NSEC3 links integrity", zone->origin, serial);
    
    zdb_zone_label_iterator iter;
    zdb_zone_label_iterator_init(&iter, zone);
    while(zdb_zone_label_iterator_hasnext(&iter))
    {
        u32 n = zdb_zone_label_iterator_nextname(&iter, label_name);
        (void)n;
        
        zdb_rr_label *label = zdb_zone_label_iterator_next(&iter);

        bool self_check = nsec3_superdump_integrity_check_label_nsec3_self_points_back(label, 0);
        bool star_check = nsec3_superdump_integrity_check_label_nsec3_star_points_back(label, 0);
        
        bool showme = !(self_check&star_check);
                
        if(showme)
        {
            nsec3_zone* n3 = zone->nsec.nsec3;
            //nsec3_label_extension *n3e = label->nsec.nsec3;
            int error_count = 0;

            while(n3 != NULL)
            {
                nsec3_superdump_hash(zone, n3, label, FALSE, digest);
                nsec3_superdump_hash(zone, n3, label, TRUE, digest_star);
                
                nsec3_zone_item *self_node = nsec3_avl_find(&n3->items, digest);
                
                if(self_node)
                {
                    bool pointed_back = nsec3_superdump_nsec3_label_pointer_array(self_node, FALSE, "SUPERDUMP");
                    
                    if(!pointed_back)
                    {
                        log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: %{digest32h} did not point back",
                                zone->origin, serial, label_name, label,
                                digest);
                        ++error_count;
                    }
                }
                
                nsec3_zone_item *star_node = nsec3_zone_item_find_encloser_start(n3, digest_star);
                
                if(star_node != NULL)
                {
                    bool pointed_back = nsec3_superdump_nsec3_label_pointer_array(star_node, TRUE, "SUPERDUMP");
                    
                    if(!pointed_back)
                    {
                        log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: %{digest32h} did not point back",
                                zone->origin, serial, label_name, label,
                                digest_star);
                        ++error_count;
                    }
                }
                
                n3 = n3->next;
            }
            
            if(error_count > 0)
            {            
                log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: self: %c star: %c",
                        zone->origin, serial, label_name, label,
                        self_check?'Y':'N', star_check?'Y':'N');

                // again, so I can debug it
                nsec3_superdump_integrity_check_label_nsec3_self_points_back(label, 0);
                nsec3_superdump_integrity_check_label_nsec3_star_points_back(label, 0);

                log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: flags=%x #subdomain=%i",
                        zone->origin, serial, label_name, label,
                        label->flags, dictionary_size(&label->sub));

                btree_iterator iter;
                btree_iterator_init(label->resource_record_set, &iter);

                /* Sign only APEX and DS and NSEC records at delegation */

                while(btree_iterator_hasnext(&iter))
                {
                    btree_node *rr_node = btree_iterator_next_node(&iter);
                    u16 type = (u16)rr_node->hash;
                    zdb_packed_ttlrdata *record = (zdb_packed_ttlrdata*)rr_node->data;

                    if(record == NULL)
                    {
                        log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: %{dnstype} <EMPTY-SET>",
                            zone->origin, serial, label_name, label, &type);
                    }

                    while(record != NULL)
                    {
                        rdata_desc rdatadesc = {type, record->rdata_size, record->rdata_start};                
                        log_err("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: %{typerdatadesc}",
                            zone->origin, serial, label_name, label, &rdatadesc);
                        record = record->next;
                    }
                }
            }
            else
            {
                showme = FALSE;
            }
        }
        
        nsec3_zone* n3 = zone->nsec.nsec3;
        nsec3_label_extension *n3e = label->nsec.nsec3;
        
        while(n3e != NULL)
        {
            nsec3_superdump_hash(zone, n3, label, FALSE, digest);
            nsec3_superdump_hash(zone, n3, label, TRUE, digest_star);
            
            if(showme)
            {
                log_debug("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: n3e@%p %{digest32h} self@%p %{digest32h} star@%p",
                        zone->origin, serial, label_name, label,
                        n3e, digest, n3e->self, digest_star, n3e->star);
            }
            
            nsec3_zone_item *self = n3e->self;
            
            if(self != NULL)
            {
                nsec3_zone_item *self_next = nsec3_avl_node_mod_next(self);
                nsec3_zone_item *self_prev = nsec3_avl_node_mod_prev(self);
                if(showme)
                {
                    log_debug("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: %{digest32h} R=%2i *=%2i (-> %{digest32h}) (<- %{digest32h})",
                            zone->origin, serial, label_name, label,
                            self->digest, self->rc, self->sc, self_next->digest, self_prev->digest);
                }
                
                nsec3_superdump_nsec3_label_pointer_array(self, FALSE, "SUPERDUMP");
                nsec3_superdump_nsec3_label_pointer_array(self, TRUE, "SUPERDUMP");
            }
            else
            {
                if(showme)
                {
                    log_debug("SUPERDUMP: %{dnsname}/%d: %{dnsname}@%p: NULL self", zone->origin, serial, label_name, label);
                }
            }
            
            nsec3_zone_item *star = n3e->star;
            if(star != NULL)
            {
                nsec3_zone_item *star_next = nsec3_avl_node_mod_next(star);
                nsec3_zone_item *star_prev = nsec3_avl_node_mod_prev(star);
                if(showme)
                {
                    log_debug("SUPERDUMP*: %{dnsname}/%d: %{dnsname}@%p: %{digest32h} R=%2i *=%2i -> %{digest32h} <- %{digest32h}",
                            zone->origin, serial, label_name, label,
                            star->digest, star->rc, star->sc, star_next->digest, star_prev->digest);
                }
                nsec3_superdump_nsec3_label_pointer_array(star, FALSE, "SUPERDUMP*");
                nsec3_superdump_nsec3_label_pointer_array(star, TRUE, "SUPERDUMP*");
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
#endif
}

/** @} */

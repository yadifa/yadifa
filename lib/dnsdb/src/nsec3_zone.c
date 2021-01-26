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

#include <dnscore/logger.h>

#include "dnsdb/nsec3_item.h"
#include "dnsdb/nsec3_owner.h"
#include "dnsdb/nsec3_zone.h"

#include "dnsdb/zdb_zone_label_iterator.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

extern logger_handle *g_dnssec_logger;

/******************************************************************************
 *
 * NSEC3 - tools : nsec3_zone (nsec3param's alter ego)
 *
 *****************************************************************************/

/*
 * Compares two nsec3_zone (binary compare <0 / = / >0 : less/equal/bigger)
 */

int
nsec3param_compare_by_rdata(const u8 *a_rdata, const u8 *b_rdata)
{
    int c;

    c = a_rdata[0];
    c -= b_rdata[0];

    if(c == 0)
    {
        c = a_rdata[2];
        c -= b_rdata[2];

        if(c == 0)
        {
            c = a_rdata[3];
            c -= b_rdata[3];

            if(c == 0)
            {
                c = a_rdata[4]; // size of the salt
                c -= b_rdata[4];

                if(c == 0)
                {
                    c = memcmp(&a_rdata[5], &b_rdata[5], a_rdata[4]);
                }
            }
        }
    }

    return c;
}

/*
 * Compares two nsec3_zone (binary compare <0 / = / >0 : less/equal/bigger)
 */



int
nsec3_zone_compare(nsec3_zone* a, nsec3_zone* b)
{
    return nsec3param_compare_by_rdata(a->rdata, b->rdata);
}

/*
 * Retrieves the nsec3_zone* (NSEC3PARAM alter-ego) from an item.
 *
 * This is done by looking for the NSEC3 root then looking for which nsec3_zone
 * contains the ptr.  It requires up to 30 moves. (slow)
 *
 * I could also mark the nsec3 records and store the mark on every record but
 * it would be expensive (memory).
 *
 */

nsec3_zone*
nsec3_zone_from_item(const zdb_zone* zone, const nsec3_zone_item* item)
{
    const nsec3_zone_item* root = item;

    while(root->parent != NULL)
    {
        root = root->parent;
    }

    nsec3_zone* n3 = zone->nsec.nsec3;

    while(n3 != NULL)
    {
        if(n3->items == root)
        {
            break;
        }

        n3 = n3->next;
    }

    return n3;
}

/*
 * Recursively empties nsec3_zone_item
 *
 * Does not destroys the nodes, only the payload : owners, stars, bitmap, rrsig
 *
 * This should be followed by the destruction of the items
 */

static void
nsec3_zone_item_empties_recursively(nsec3_zone_item* item)
{
    if(item != NULL)
    {
        nsec3_zone_item_empties(item);

        nsec3_zone_item_empties_recursively(item->children.lr.left);
        nsec3_zone_item_empties_recursively(item->children.lr.right);
    }
}

/**
 * Detaches an nsec3 chain from the zone.
 * 
 * @param zone
 * @param n3
 * @return 
 */

bool
nsec3_zone_detach(zdb_zone *zone, nsec3_zone *n3)
{
    nsec3_zone *first = zone->nsec.nsec3;

    if(first == n3)
    {
        zone->nsec.nsec3 = n3->next;
    }
    else
    {
        while(first->next != n3)
        {
            first = first->next;
            
            if(first == NULL)
            {
                return FALSE;
            }
        }

        first->next = n3->next;
    }
    
    n3->next = NULL;
    
    return TRUE;
}

/*
 * Destroys the nsec3param alter-ego from the database.
 *
 * The zdb_rr_label are also affected by the call.
 *
 * The NSEC3PARAM record is not changed.
 *
 */

void
nsec3_zone_destroy(zdb_zone *zone, nsec3_zone *n3)
{
    int n3_index = 0;
    
    /*
     *
     * Check for existence of n3 into zone
     *
     * For every nsec3 record found in zone:
     *
     *	    Get the self(s), unlink
     *	    Get the star(s), unlink
     *	    Destroy nsec3 record signature
     *	    Destroy nsec3 record
     */

    // get the pointer chaining to n3

    nsec3_zone **n3p = &zone->nsec.nsec3;

    yassert(*n3p != NULL);

    while(*n3p != n3)
    {
        ++n3_index;
        n3p = &(*n3p)->next;

        yassert(*n3p != NULL);
    }

    *n3p = n3->next;
    n3->next = NULL;
    nsec3_zone_item_empties_recursively(n3->items);
    nsec3_destroy(&n3->items);
    nsec3_zone_free(n3);
    
    // Every single label must have its chain updated
    
    zdb_zone_label_iterator label_iterator;
    zdb_zone_label_iterator_init(&label_iterator, zone);
    
    if(n3_index == 0)
    {
        while(zdb_zone_label_iterator_hasnext(&label_iterator))
        {
            zdb_rr_label* label = zdb_zone_label_iterator_next(&label_iterator);
            
            if(label->nsec.nsec3 != NULL)
            {
                struct nsec3_label_extension *n3_ext = label->nsec.nsec3;
                if(n3_ext != NULL)
                {
                    label->nsec.nsec3 = nsec3_label_extension_next(n3_ext);
                    yassert(nsec3_label_extension_self(n3_ext) == NULL && nsec3_label_extension_star(n3_ext) == NULL);
                    nsec3_label_extension_free(n3_ext);
                }
            }
        }
    }
    else
    {
        while(zdb_zone_label_iterator_hasnext(&label_iterator))
        {
#if DEBUG
            u8 fqdn[256];
            zdb_zone_label_iterator_nextname(&label_iterator, fqdn);
#endif

            zdb_rr_label* label = zdb_zone_label_iterator_next(&label_iterator);

            if(label->nsec.nsec3 != NULL)
            {
                struct nsec3_label_extension **n3_extp = nsec3_label_extension_next_ptr(label->nsec.nsec3);
                struct nsec3_label_extension *n3_ext = *n3_extp;
                for(int i = 1; i < n3_index; ++i)
                {
                    n3_extp = nsec3_label_extension_next_ptr(n3_ext);
                    n3_ext = *n3_extp;
                }
                *n3_extp = nsec3_label_extension_next(n3_ext);
                
#if DEBUG
                if(nsec3_label_extension_self(n3_ext) != NULL)
                {
                    log_debug2("%{dnsname} self %{digest32h}", fqdn, nsec3_label_extension_self(n3_ext)->digest);
                }
                if(nsec3_label_extension_star(n3_ext) != NULL)
                {
                    log_debug2("%{dnsname} star %{digest32h}", fqdn, nsec3_label_extension_star(n3_ext)->digest);
                }
#endif
                
                yassert(nsec3_label_extension_self(n3_ext) == NULL && nsec3_label_extension_star(n3_ext) == NULL); // both are expected to be cleared
                nsec3_label_extension_free(n3_ext);
            }
        }
    }
}



/*
 * Adds the nsec3_zone (NSEC3PARAM "alter-ego") to the zone.
 *
 * Updates labels flags + nsec3 item references placeholders
 * using nsec3_insert_empty_nsec3
 *
 * Uses nsec3zone_compare
 *
 * Used by nsec3_add_nsec3param and nsec3_load_add_nsec3param
 *
 */

nsec3_zone*
nsec3_zone_add_from_rdata(zdb_zone* zone, u16 nsec3param_rdata_size, const u8* nsec3param_rdata)
{
    /* Check that the rdata is big enough */
    yassert(nsec3param_rdata_size >= NSEC3PARAM_MINIMUM_LENGTH);

    nsec3_zone* n3 = nsec3_zone_get_from_rdata(zone, nsec3param_rdata_size, nsec3param_rdata);

    if(n3 == NULL)
    {
        n3 = nsec3_zone_new(nsec3param_rdata, nsec3param_rdata_size);
        
        /*
         * Insertion has to be sorted on the Algorithm + Iterations + Salt_len + Salt
         */

        nsec3_zone** current = &zone->nsec.nsec3;
        nsec3_zone* next_n3 = zone->nsec.nsec3;
        u32 n3_pos = 0;

        for(;;)
        {
            /*
            if((next_n3 == NULL) || (nsec3_zone_compare(n3, next_n3) < 0))
            */
            if(next_n3 == NULL)
            {
                n3->next = next_n3;

                *current = n3;

                /*
                 * For every existing label in the database: add a nsec3 node for
                 * the current n3 record (same position in the list).
                 */

                //nsec3_insert_empty_nsec3(zone, n3_pos);

                break;
            }

            current = &next_n3->next;
            next_n3 = next_n3->next;
            n3_pos++;
        }
    }

    return n3;
}

nsec3_zone*
nsec3_zone_new(const u8 *nsec3param_rdata, u16 nsec3param_rdata_size)
{
    nsec3_zone *n3;
    u32 nsec3param_rdata_realsize = NSEC3PARAM_RDATA_SIZE_FROM_RDATA(nsec3param_rdata);
    yassert(nsec3param_rdata_size >= nsec3param_rdata_realsize);
    (void)nsec3param_rdata_size;
    ZALLOC_ARRAY_OR_DIE(nsec3_zone*, n3, sizeof(nsec3_zone) + nsec3param_rdata_realsize, NSEC3_ZONE_TAG);
    n3->next = NULL;
    n3->items = NULL;
    memcpy(n3->rdata, nsec3param_rdata, nsec3param_rdata_realsize);
    
    return n3;
}

void nsec3_zone_free(nsec3_zone *n3)
{
    yassert(nsec3_isempty(&n3->items));
    yassert(n3->next == NULL);
    ZFREE_ARRAY(n3, sizeof(nsec3_zone) + NSEC3PARAM_MINIMUM_LENGTH + n3->rdata[4]);
}

ya_result
nsec3_zone_chain_count(zdb_zone* zone)
{
    ya_result ret = 0;;
    nsec3_zone* n3 = zone->nsec.nsec3;
    while(n3 != NULL)
    {
        ++ret;
        n3 = n3->next;
    }
    return ret;
}


/**
 * 
 * Adds the nsec3_zone (NSEC3PARAM "alter-ego") to the zone.
 *
 * Updates labels flags + nsec3 item references placeholders
 * using nsec3_insert_empty_nsec3
 *
 * Uses nsec3zone_compare
 *
 * Used by nsec3_add_nsec3param and nsec3_load_add_nsec3param
 *
 * @note Does not add the record.
 * 
 * @param zone
 * @param nsec3param_rdata
 * @param nsec3param_rdata_size
 * 
 * @return an error code
 */

ya_result
nsec3_zone_chain_add_with_rdata(zdb_zone* zone, const u8* nsec3param_rdata, u16 nsec3param_rdata_size)
{
    /* Check that the rdata is big enough */
    yassert(nsec3param_rdata_size >= NSEC3PARAM_MINIMUM_LENGTH);
    ya_result ret = 0;
    
    nsec3_zone* n3 = zone->nsec.nsec3;
    nsec3_zone** n3p;
    if(n3 != NULL)
    {
        if(memcmp(n3->rdata, nsec3param_rdata, nsec3param_rdata_size) == 0)
        {
            // duplicate
            return ERROR;
        }
        
        ++ret;
        
        while(n3->next != NULL)
        {
            n3 = n3->next;
            
            if(memcmp(n3->rdata, nsec3param_rdata, nsec3param_rdata_size) == 0)
            {
                // duplicate
                return ERROR;
            }
            
            ++ret;
        }
        // add after n3
        n3p = &n3->next;
    }
    else
    {
        // create n3
        n3p = &zone->nsec.nsec3;
    }
    
    n3 = nsec3_zone_new(nsec3param_rdata, nsec3param_rdata_size);
    *n3p = n3;

    return ret;
}

/**
 * Returns the index of an NSEC3PARAM in the zone, or an error code
 * 
 * @param zone
 * @param nsec3param_rdata
 * @param nsec3param_rdata_size
 * @return 
 */

ya_result
nsec3_zone_chain_get_index_from_rdata(zdb_zone* zone, const u8* nsec3param_rdata, u16 nsec3param_rdata_size)
{
    /* Check that the rdata is big enough */
    yassert(nsec3param_rdata_size >= NSEC3PARAM_MINIMUM_LENGTH);
    ya_result ret = 0;
    
    nsec3_zone* n3 = zone->nsec.nsec3;
    
    while(n3 != NULL)
    {
        if(memcmp(n3->rdata, nsec3param_rdata, nsec3param_rdata_size) == 0)
        {
            // return the index of the match
            return ret;
        }
        
        ++ret;
        
        n3 = n3->next;
    }
    
    return ERROR;
}

/*
 * Returns the zone's matching nsec3_zone* or NULL
 *
 * The rdata can be of an NSEC3PARAM or of an NSEC3
 *
 */

nsec3_zone*
nsec3_zone_get_from_rdata(const zdb_zone* zone, u16 nsec3param_rdata_size, const u8* nsec3param_rdata)
{
    /* Check that the rdata is big enough */
    yassert(nsec3param_rdata_size >= NSEC3PARAM_MINIMUM_LENGTH);
    (void)nsec3param_rdata_size;

    nsec3_zone* n3;

    for(n3 = zone->nsec.nsec3; n3 != NULL; n3 = n3->next)
    {
        /* test the first 32 bits in one go */
        u32 a = GET_U32_AT(n3->rdata[0]);
        u32 b = GET_U32_AT(nsec3param_rdata[0]);

        a &= NU32(0xff00ffff);
        b &= NU32(0xff00ffff);

        if(a == b)
        {
            u8 len = NSEC3_ZONE_SALT_LEN(n3);
            if(NSEC3PARAM_RDATA_SALT_LEN(nsec3param_rdata) == len)
            {
                if(memcmp(NSEC3_ZONE_SALT(n3), NSEC3PARAM_RDATA_SALT(nsec3param_rdata), len) == 0)
                {
                    break;
                }
            }
        }
    }

    return n3;
}

/** @} */

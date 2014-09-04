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
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
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
nsec3_zone_rdata_compare(const u8* a_rdata, const u8* b_rdata)
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
                c = a_rdata[4];
                c -= b_rdata[4];

                c = memcmp(&a_rdata[5], &b_rdata[5], c);
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
    return nsec3_zone_rdata_compare(a->rdata, b->rdata);
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
nsec3_zone_from_item(zdb_zone* zone, nsec3_zone_item* item)
{
    nsec3_zone_item* root = item;

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

/*
 * Destroys the nsec3param alter-ego from the database.
 *
 * The zdb_rr_label are also affected by the call.
 *
 * The NSEC3PARAM record is not changed.
 *
 */

void
nsec3_zone_destroy(zdb_zone* zone, nsec3_zone* n3)
{
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


    nsec3_zone_item_empties_recursively(n3->items);

    nsec3_avl_destroy(&n3->items);

    nsec3_zone* first = zone->nsec.nsec3;

    if(first == n3)
    {
        zone->nsec.nsec3 = n3->next;
    }
    else
    {
        while(first->next != n3)
        {
            first = first->next;
        }

        first->next = n3->next;
    }

    ZFREE_ARRAY(n3, sizeof (nsec3_zone) - 1 + NSEC3PARAM_MINIMUM_LENGTH + n3->rdata[4]);
}

/*
 * Adds the NSEC3 item reference chain (one node for each NSEC3PARAM)
 * to EACH label of the zone
 *
 * Exclusively used by nsec3_zone_add_from_rdata
 */

static void
nsec3_insert_empty_nsec3(zdb_zone* zone, u32 index)
{
    zdb_zone_label_iterator label_iterator;
    zdb_zone_label_iterator_init(zone, &label_iterator);

    while(zdb_zone_label_iterator_hasnext(&label_iterator))
    {
        zdb_rr_label* label = zdb_zone_label_iterator_next(&label_iterator);

        yassert((label->flags & ZDB_RR_LABEL_NSEC) == 0);

        label->flags |= ZDB_RR_LABEL_NSEC3;
        
        /*
         * if label->nsec.nsec3 is NULL and index > 0 => oops
         */

        nsec3_label_extension** current = &label->nsec.nsec3;

        u32 count = index;

        while(count > 0)
        {
            /*
             * If the label lacks previous elements in the chain, they must be added.
             */
            
            if(*current == NULL)
            {
                nsec3_label_extension* n3ext;
                
                ZALLOC_OR_DIE(nsec3_label_extension*, n3ext, nsec3_label_extension, NSEC3_LABELEXT_TAG);                
                n3ext->self = NULL;
                n3ext->star = NULL;

                *current = n3ext;
            }
            
            current = &(*current)->next;
            count--;
        }

        nsec3_label_extension* n3ext;

        ZALLOC_OR_DIE(nsec3_label_extension*, n3ext, nsec3_label_extension, NSEC3_LABELEXT_TAG);

        n3ext->self = NULL;
        n3ext->star = NULL;

        n3ext->next = *current;

        *current = n3ext;
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
        u32 nsec3param_rdata_realsize = NSEC3_ZONE_RDATA_SIZE_FROM_SALT(NSEC3PARAM_RDATA_SALT_LEN(nsec3param_rdata));

        ZALLOC_ARRAY_OR_DIE(nsec3_zone*, n3, sizeof (nsec3_zone) + nsec3param_rdata_realsize - 1, NSEC3_ZONE_TAG);
        n3->items = NULL;

        MEMCOPY(n3->rdata, nsec3param_rdata, nsec3param_rdata_realsize);

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

                nsec3_insert_empty_nsec3(zone, n3_pos);

                break;
            }

            current = &next_n3->next;
            next_n3 = next_n3->next;
            n3_pos++;
        }
    }

    return n3;
}

/*
 * Returns the zone's matching nsec3_zone* or NULL
 *
 * The rdata can be of an NSEC3PARAM or of an NSEC3
 *
 */

nsec3_zone*
nsec3_zone_get_from_rdata(zdb_zone* zone, u16 nsec3param_rdata_size, const u8* nsec3param_rdata)
{
    /* Check that the rdata is big enough */
    yassert(nsec3param_rdata_size >= NSEC3PARAM_MINIMUM_LENGTH);

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

/*----------------------------------------------------------------------------*/


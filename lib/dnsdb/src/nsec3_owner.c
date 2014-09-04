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
 * Owners & Stars
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/nsec3_owner.h"

#define NSEC3_OWNER_DEBUG 0

//#if NSEC3_OWNER_DEBUG != 0
#include <dnscore/logger.h>

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

//#endif

#define OWNER_NAME(owner_) (((owner_) != NULL) && ((owner_) != NSEC3_ZONE_FAKE_OWNER))?(owner_)->name:(u8*)"\004FAKE"
#define ITEM_DIGEST(item__) (((item__) != NULL)?(item__)->digest:NULL)

/******************************************************************************
 *
 * NSEC3 - tools : owners & stars
 *
 *****************************************************************************/

static void
nsec3_label_extension_set_self(nsec3_label_extension* n3ext, nsec3_zone_item* item, nsec3_zone_item* value)
{
    /*
     * This loops should only be run once or twice
     * Still it annoys me a lot.
     *
     * I'll have to find a better, dynamic, way to handle
     * multiple NSEC3PARAM.
     * (And of course memory usage and framentation is the
     * first ennemy)
     */

#if NSEC3_OWNER_DEBUG != 0
    log_debug("nsec3_label_extension_set_self: %p, %{digest32h} @ %p, %{digest32h} @ %p", n3ext, ITEM_DIGEST(item), item, ITEM_DIGEST(value), value);
#endif

    do
    {
        if(n3ext->self == item)
        {
            yassert((value != NULL) || (n3ext->self != NULL));
            
            n3ext->self = value; /* Official way to change the "self" */
            return;
        }

#if NSEC3_OWNER_DEBUG != 0
        log_debug("nsec3_label_extension_set_self: skipped %{digest32h} @ %p", ITEM_DIGEST(n3ext->self), n3ext->self);
#endif

        n3ext = n3ext->next;
    }
    while(n3ext != NULL);

    /* NULL means we didn't found the link back */

#if NSEC3_OWNER_DEBUG != 0
    log_debug("nsec3_label_extension_set_self: reference not found (something is wrong)");
#endif

    exit(-1);
}

static void
nsec3_label_extension_set_star(nsec3_label_extension* n3ext, nsec3_zone_item* item, nsec3_zone_item* value)
{
    /*
     * This loops should only be run once or twice
     * Still it annoys me a lot.
     *
     * I'll have to find a better, dynamic, way to handle
     * multiple NSEC3PARAM.
     * (And of course memory usage and framentation is the
     * first ennemy)
     */

#if NSEC3_OWNER_DEBUG != 0
    log_debug("nsec3_label_extension_set_star: %p, %{digest32h} @ %p, %{digest32h} @ %p", n3ext, ITEM_DIGEST(item), item, ITEM_DIGEST(value), value);
#endif

    do
    {
        if(n3ext->star == item)
        {
            n3ext->star = value;
            return;
        }

#if NSEC3_OWNER_DEBUG != 0
        log_debug("nsec3_label_extension_set_star: skipped %{digest32h} @ %p", ITEM_DIGEST(n3ext->star), n3ext->star);
#endif

        n3ext = n3ext->next;
    }
    while(n3ext != NULL);

    /* NULL means we didn't found the link back */

#if NSEC3_OWNER_DEBUG != 0
    log_debug("nsec3_label_extension_set_star: reference not found (something is wrong)");
#endif

    exit(-1);
}



/*
 * Adds an entry to the "owner" array (of an item)
 */

static void
nsec3_label_add(nsec3_label_pointer_array* ownersp, u16* countp, const zdb_rr_label* owner)
{
    if(*countp == 0)
    {
        (*ownersp).owner = (zdb_rr_label*)owner;
        *countp = 1;
#if NSEC3_OWNER_DEBUG != 0
        log_debug("nsec3_label_add: 1 '%{dnslabel}'", OWNER_NAME(owner));
#endif
    }
    else if(*countp == 1)
    {
        /*
         * We had one item : adding one will require using an array
         */

        *countp = 2;

        nsec3_label_pointer_array owners;

        ZALLOC_ARRAY_OR_DIE(zdb_rr_label**, owners.owners, sizeof (zdb_rr_label*) * 2, NSEC3_LABELPTRARRAY_TAG);

        owners.owners[0] = (*ownersp).owner;
        owners.owners[1] = (zdb_rr_label*)owner;

        (*ownersp).owners = owners.owners;

#if NSEC3_OWNER_DEBUG != 0
        log_debug("nsec3_label_add: 2 '%{dnslabel}' '%{dnslabel}'", OWNER_NAME(owners.owners[0]), OWNER_NAME(owners.owners[1]));
#endif
    }
    else
    {
        /*
         * Just resize the current array to contain ONE more pointer
         */

        u16 count = *countp;

        /** @note ZALLOC_ARRAY_RESIZE does change the value of "count" to "count+1" */
        
        ZALLOC_ARRAY_RESIZE(zdb_rr_label*, (*ownersp).owners, count, count + 1);
        (*ownersp).owners[count-1] = (zdb_rr_label*)owner; /** @note count is already set to count + 1 */
        *countp = count;

#if NSEC3_OWNER_DEBUG != 0
        log_debug("nsec3_label_add: %u ", count);
        u16 i;
        for(i = 0; i < count; i++)
        {
            log_debug(" + '%{dnslabel}'", OWNER_NAME((*ownersp).owners[i]));
        }
#endif
    }
}

/*
 * Removes an entry from the "owner" array (of an item)
 */

static void
nsec3_label_remove(nsec3_label_pointer_array* ownersp, u16* countp, zdb_rr_label* owner)
{
    yassert(*countp > 0);

    if(*countp == 1)
    {
        /*
         * We had one item, We will have none.
         * Set the pointer to NULL and the RC to 0
         *
         * Also, the label's reference will have to be set to NULL
         * If the label's star reference was NULL already, then
         * free the owner->nsec.nsec3
         */

        yassert((*ownersp).owner == owner);

        (*ownersp).owner = NULL;
        *countp = 0;
    }
    else if(*countp == 2)
    {
        /*
         * We had one item, we will get one.
         * Keep the last pointer instead of the array.
         * Destroy the array
         */
        zdb_rr_label* last_owner;

        if((*ownersp).owners[0] == owner)
        {
            last_owner = (*ownersp).owners[1];
        }
        else
        {
            last_owner = (*ownersp).owners[0];
        }

        ZFREE_ARRAY((*ownersp).owners, sizeof (zdb_rr_label*) * 2);

        (*ownersp).owner = last_owner;
        *countp = 1;
    }
    else
    {
        /*
         * We had more than 2
         *
         * Find it,
         * replace it by the last one in the array,
         * shrink the array (resize)
         *
         */

        u32 idx;
        u32 n = *countp;

        /*
         * Look for the owner
         */

        for(idx = 0; idx < n; idx++)
        {
            if((*ownersp).owners[idx] == owner)
            {
                /*
                 * Overwrite it by the next owner.
                 * Move all following owners one step down
                 */
                n--;

                while(idx < n)
                {
                    (*ownersp).owners[idx] = (*ownersp).owners[idx + 1];
                    idx++;
                }
                break;
            }
        }

        /*
         * Reduce the memory used by one count
         * Note : this macro will also set *countp to *countp - 1
         */

        ZALLOC_ARRAY_RESIZE(zdb_rr_label*, (*ownersp).owners, *countp, *countp - 1);
    }
}

/**
 * Returns TRUE if item is owned by owner
 */

bool
nsec3_owned_by(const nsec3_zone_item* item, const zdb_rr_label* owner)
{
    if(item->rc == 1)
    {
        return (item->label.owner == owner);
    }
    else if(item->rc != 0)
    {
        zdb_rr_label* const * ownerp = item->label.owners;
        u16 i = item->rc;
        do
        {
            if(*ownerp++ == owner)
            {
                return TRUE;
            }
        }
        while(--i > 0);
    }

    return FALSE;
}

/*
 * Adds an owner to the NSEC3 item
 */

void
nsec3_add_owner(nsec3_zone_item* item, const zdb_rr_label* owner)
{
#if NSEC3_OWNER_DEBUG != 0
    log_debug("nsec3_add_owner: %{digest32h} @ %p, '%{dnslabel}'", ITEM_DIGEST(item), item, OWNER_NAME(owner));
#endif

    nsec3_label_add(&item->label, &item->rc, owner);
}

/*
 * Removes an owner from the NSEC3 item
 *
 * The entry MUST have been set before
 */

void
nsec3_remove_owner(nsec3_zone_item* item, zdb_rr_label* owner)
{
#if NSEC3_OWNER_DEBUG != 0
    log_debug("nsec3_remove_owner: %{digest32h} @ %p, '%{dnslabel}'", ITEM_DIGEST(item), item, OWNER_NAME(owner));
#endif

    nsec3_label_remove(&item->label, &item->rc, owner);
}

/*
 * Removes all owners from the NSEC3 item
 *
 * The entry MUST have been set before
 */

void
nsec3_remove_all_owners(nsec3_zone_item* item)
{
#if NSEC3_OWNER_DEBUG != 0
    log_debug("nsec3_remove_all_owners: %{digest32h} @ %p", ITEM_DIGEST(item), item);
#endif

    if(item->rc > 0)
    {
        if(item->rc == 1)
        {
            zdb_rr_label* label = item->label.owner;

            if(label != NULL)
            {
                if(label != NSEC3_ZONE_FAKE_OWNER)
                {
#if NSEC3_OWNER_DEBUG != 0
                    log_debug("nsec3_remove_all_owners: 1 : %p '%{dnslabel}'", item, label->name);
#endif
                    if(label->nsec.nsec3 != NULL)
                    {
                        nsec3_label_extension_set_self(label->nsec.nsec3, item, NULL);

                        if(label->nsec.nsec3->star != NULL)
                        {
                            nsec3_remove_star(label->nsec.nsec3->star, label);
                            nsec3_label_extension_set_star(label->nsec.nsec3, label->nsec.nsec3->star, NULL);
                        }

                        /*
                        * Remove the NSEC3 link
                        */

                        ZFREE(label->nsec.nsec3, nsec3_label_extension);
                        label->nsec.nsec3 = NULL;
                    }
                    else
                    {
                        log_warn("nsec3_remove_all_owners: label %{dnslabel} has no NSEC3 (flags=%04x)", label->name, label->flags);
                    }
                    label->flags &= ~ZDB_RR_LABEL_NSEC3;
                }

                item->label.owner = NULL;
            }
        }
        else
        {
            u32 n = item->rc;

#if NSEC3_OWNER_DEBUG != 0
            log_debug("nsec3_remove_all_owners: n : %p (%u)", item, n);
#endif

            for(u32 i = 0; i < n; i++)
            {
                zdb_rr_label* label = item->label.owners[i];

                if(label != NULL)
                {
                    if(label != NSEC3_ZONE_FAKE_OWNER)
                    {

#if NSEC3_OWNER_DEBUG != 0
                        log_debug("nsec3_remove_all_owners: n : %p '%{dnslabel}'", item, label->name);
#endif

                        nsec3_label_extension_set_self(label->nsec.nsec3, item, NULL);
                        nsec3_remove_star(label->nsec.nsec3->star, label);
                        nsec3_label_extension_set_star(label->nsec.nsec3, label->nsec.nsec3->star, NULL);

                        ZFREE(label->nsec.nsec3, nsec3_label_extension);
                        label->nsec.nsec3 = NULL;
                        label->flags &= ~ZDB_RR_LABEL_NSEC3;
                    }

                    item->label.owners[i] = NULL;
                }
            }

            ZFREE_ARRAY(item->label.owners, sizeof (zdb_rr_label*) * n);

            item->label.owners = NULL;
        }

        item->rc = 0;
    }
}

zdb_rr_label* nsec3_owner_get(nsec3_zone_item* item, u16 idx)
{
    if(item->rc == 1)
    {
        return item->label.owner;
    }
    else if(idx < item->rc)
    {
        return item->label.owners[idx];
    }

    return NULL;
}

/*
 * Adds a "star" to the NSEC3 item
 */

void
nsec3_add_star(nsec3_zone_item* item, const zdb_rr_label* owner)
{
#if NSEC3_OWNER_DEBUG != 0
    log_debug("nsec3_add_star: %{digest32h} @ %p, %p '%{dnslabel}'", ITEM_DIGEST(item), item, owner, owner->name);
#endif

    nsec3_label_add(&item->star_label, &item->sc, owner);
}

/*
 * Removes a star from the NSEC3 item
 *
 * The entry MUST have been set before
 */

void
nsec3_remove_star(nsec3_zone_item* item, zdb_rr_label* owner)
{
#if NSEC3_OWNER_DEBUG != 0
    log_debug("nsec3_remove_star: %{digest32h}@ @ %p '%{dnslabel}'", ITEM_DIGEST(item), item, owner->name);
#endif

    /// @note : this is Z-allocated not M-allocated
    //assert_mallocated(item);
    //assert_mallocated(owner);

    nsec3_label_remove(&item->star_label, &item->sc, owner);
}

/*
 * Removes all stars from the NSEC3 item
 *
 * The entry MUST have been set before
 */

void
nsec3_remove_all_star(nsec3_zone_item* item)
{
#if NSEC3_OWNER_DEBUG != 0
    log_debug("nsec3_remove_all_star(%{digest32h} @ %p)", ITEM_DIGEST(item), item);
#endif
    
    if(item->sc > 0)
    {
        if(item->sc == 1)
        {
            zdb_rr_label* label = item->star_label.owner;

            if(label != NULL)
            {
#if NSEC3_OWNER_DEBUG != 0
                log_debug("nsec3_remove_all_star: n = 1 : %p '%{dnslabel}'", label, label->name);
#endif

                if(label->nsec.nsec3 != NULL)
                {
                    if(label != NSEC3_ZONE_FAKE_OWNER)
                    {
                        nsec3_label_extension_set_star(label->nsec.nsec3, item, NULL);
                    }
#if NSEC3_OWNER_DEBUG != 0
                    else
                    {
                        log_debug("nsec3_remove_all_star: n = 1 : FAKE'", label, label->name);
                    }
#endif
                }
                else
                {
                    log_warn("nsec3_remove_all_star: label %{dnslabel} has no NSEC3 (flags=%04x)", label->name, label->flags);
                }
                
                item->star_label.owner = NULL;
            }
        }
        else
        {
            u32 n = item->sc;

#if NSEC3_OWNER_DEBUG != 0
            log_debug("nsec3_remove_all_star: n = %u", n);
            for(u32 i = 0; i < n; i++)
            {
                log_debug("\tlabel[%i] = %p '%{dnslabel}'", i, item->star_label.owners[i], item->star_label.owners[i]->name);
            }
#endif

            for(u32 i = 0; i < n; i++)
            {            
                zdb_rr_label* label = item->star_label.owners[i];

                if(label != NULL)
                {
                    if(label->nsec.nsec3 != NULL)
                    {
                        if(label != NSEC3_ZONE_FAKE_OWNER)
                        {
#if NSEC3_OWNER_DEBUG != 0
                            log_debug("nsec3_remove_all_star: %i/%i %p '%{dnslabel}'", i, n, label, label->name);
#endif

                            nsec3_label_extension_set_star(label->nsec.nsec3, item, NULL);
                        }
#if NSEC3_OWNER_DEBUG != 0
                        else
                        {
                            log_debug("nsec3_remove_all_star: %i/%i : FAKE'", i, n);
                        }
#endif
                    }

                    item->star_label.owners[i] = NULL;
                }
            }

            ZFREE_ARRAY(item->star_label.owners, sizeof (zdb_rr_label*) * n);

            item->star_label.owners = NULL;
        }

        item->sc = 0;
    }
}

/*
 * Moves all stars from one NSEC3 item to another.
 *
 * This is used when an NSEC3 item is removed: All its NSEC3 must be moved
 * to his predecessor.
 */

static u32 nsec3_move_all_star_count = 0;

void
nsec3_move_all_star(nsec3_zone_item* src, nsec3_zone_item* dst)
{
    nsec3_move_all_star_count++;
    
    if(src->sc == 0)
    {
        /* nothing to move */
        
        return;
    }

#if NSEC3_OWNER_DEBUG != 0
    log_debug("nsec3_move_all_star(%{digest32h} @ %p, %{digest32h} @ %p)", ITEM_DIGEST(src), src, ITEM_DIGEST(dst), dst);
#endif

    /* If there were no star in the dest : just move the star collection and update the referrenced labels */

    if(dst->sc == 0)
    {
        dst->star_label.owner = src->star_label.owner;
        dst->sc = src->sc;
        for(u16 i = 0; i < src->sc; i++)
        {
            zdb_rr_label *label = nsec3_star_get(src, i);
            nsec3_label_extension_set_star(label->nsec.nsec3, src, dst);
        }
    }
    else
    {
        nsec3_label_pointer_array owners;
        
        int total = src->sc + dst->sc;

        /*
         * rc > 0 and sc > 0, so total of 2 means rc = 1 and sc = 1
         */

        ZALLOC_ARRAY_OR_DIE(zdb_rr_label**, owners.owners, sizeof (zdb_rr_label*) * total, NSEC3_LABELPTRARRAY_TAG);

        for(u16 i = 0; i < dst->sc; i++)
        {
            zdb_rr_label *label = nsec3_star_get(dst, i);
            owners.owners[i] = label;
        }

        if(dst->sc > 1)
        {
            s32 len = dst->sc * sizeof(zdb_rr_label*);
            ZFREE_ARRAY(dst->star_label.owners, len);
        }

        /* change the star link of each label from src to dst */
        for(u16 i = 0; i < src->sc; i++)
        {
            zdb_rr_label *label = nsec3_star_get(src, i);
            nsec3_label_extension_set_star(label->nsec.nsec3, src, dst);
            owners.owners[dst->sc + i] = label;
        }

        if(src->sc > 1)
        {
            s32 len = src->sc * sizeof(zdb_rr_label*);
            ZFREE_ARRAY(src->star_label.owners, len);
        }

        dst->star_label.owner = owners.owner; // owner when 1 item, owners when multiple. False positives from static analysers.
        dst->sc = total;
    }

    src->star_label.owners = NULL;
    src->sc = 0;
}

zdb_rr_label* nsec3_star_get(const nsec3_zone_item* item, u16 idx)
{
    if(item->sc == 1)
    {
        return item->star_label.owner;
    }
    else if(idx < item->sc)
    {
        return item->star_label.owners[idx];
    }

    return NULL;
}

/** @} */

/*----------------------------------------------------------------------------*/


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
 * Owners & Stars
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/nsec3_owner.h"

#if 0 /* fix */
#else
#define NSEC3_OWNER_DEBUG 0
#endif

//#if NSEC3_OWNER_DEBUG
#include <dnscore/logger.h>

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

//#endif

#define OWNER_NAME(owner_) (((owner_) != NULL))?(owner_)->name:(u8*)"\011NULLOWNER"
#define ITEM_DIGEST(item__) (((item__) != NULL)?(item__)->digest:NULL)

/******************************************************************************
 *
 * NSEC3 - tools : owners & stars
 *
 *****************************************************************************/

/**
 * Changes the value of the nsec3 extension of a label from a value to another.
 * 
 * 
 * @param n3ext the nsec3 extension of the label 
 * @param item the old nsec3 item, CANNOT BE NULL
 * @param value the new nsec3 item, can be NULL
 * 
 * 2 uses
 */

static int
nsec3_label_extension_replace_self(nsec3_label_extension* n3ext, const nsec3_zone_item *item, nsec3_zone_item *value)
{
    yassert(n3ext != NULL);
    yassert(item != NULL);
    // yassert(value != NULL); // can be NULL
    
    /*
     * This loops should only be run once or twice
     * Still it annoys me a lot.
     *
     * I'll have to find a better, dynamic, way to handle
     * multiple NSEC3PARAM.
     * (And of course memory usage and fragmentation is the
     * first enemy)
     */

#if NSEC3_OWNER_DEBUG
    log_debug("nsec3_label_extension_set_self: %p, %{digest32h} @ %p, %{digest32h} @ %p", n3ext, ITEM_DIGEST(item), item, ITEM_DIGEST(value), value);
#endif
    
    int ret = 0;

    do
    {
        if(nsec3_label_extension_self(n3ext) == item)
        {
            yassert((value != NULL) || (nsec3_label_extension_self(n3ext) != NULL));
            
            nsec3_label_extension_set_self(n3ext, value); /* Official way to change the "self" */
            return ret;
        }

#if NSEC3_OWNER_DEBUG
        
        if(value != NULL && nsec3_label_extension_self(n3ext) == value)
        {
            yassert((value != NULL) || (nsec3_label_extension_self(n3ext) != NULL));
            
            log_debug("nsec3_label_extension_set_self: already %{digest32h} @ %p ???", ITEM_DIGEST(nsec3_label_extension_star(n3ext)), nsec3_label_extension_star(n3ext));
            return ret;
        }
        
        log_debug("nsec3_label_extension_set_self: skipped %{digest32h} @ %p", ITEM_DIGEST(nsec3_label_extension_self(n3ext)), nsec3_label_extension_self(n3ext));
#endif

        ++ret;
        n3ext = nsec3_label_extension_next(n3ext);
    }
    while(n3ext != NULL);

    /* NULL means we didn't found the link back */

#if NSEC3_OWNER_DEBUG
    log_debug("nsec3_label_extension_set_self: reference not found (something is wrong)");
#endif

    logger_flush();
    abort();
}

/**
 * Changes the star value of the nsec3 extension of a label from a value to another.
 * 
 * @param n3ext the nsec3 extension of the label 
 * @param item the old nsec3 item, CANNOT BE NULL
 * @param value the new nsec3 item, can be NULL
 * 
 * 6 uses
 */



static void
nsec3_label_extension_replace_star(nsec3_label_extension* n3ext, const nsec3_zone_item *item, nsec3_zone_item* value)
{
    yassert(n3ext != NULL);
    yassert(item != NULL);
    // yassert(value != NULL); @note value can be NULL
    


#if NSEC3_OWNER_DEBUG
    log_debug("nsec3_label_extension_replace_star: %p, %{digest32h} @%p, %{digest32h} @%p", n3ext, ITEM_DIGEST(item), item, ITEM_DIGEST(value), value);
#endif

    do
    {
#if NSEC3_OWNER_DEBUG
        log_debug("nsec3_label_extension_replace_star: %{digest32h} @%p",
                  ITEM_DIGEST(nsec3_label_extension_self(n3ext)),  nsec3_label_extension_self(n3ext), ITEM_DIGEST(nsec3_label_extension_star(n3ext)), nsec3_label_extension_star(n3ext));
#endif
        if(nsec3_label_extension_star(n3ext) == item)
        {
            nsec3_label_extension_set_star(n3ext, value);
            return;
        }

#if NSEC3_OWNER_DEBUG
        
        if(nsec3_label_extension_star(n3ext) == value)
        {
            log_debug("nsec3_label_extension_replace_star: already %{digest32h} @%p ???", ITEM_DIGEST(nsec3_label_extension_star(n3ext)), nsec3_label_extension_star(n3ext));
            return;
        }
        
        log_debug("nsec3_label_extension_replace_star: skipped %{digest32h} @%p", ITEM_DIGEST(nsec3_label_extension_star(n3ext)), nsec3_label_extension_star(n3ext));
#endif

        n3ext = nsec3_label_extension_next(n3ext);
    }
    while(n3ext != NULL);

    /* NULL means we didn't found the link back */
    
    if(value != NULL)
    {
        log_err("nsec3_label_extension_replace_star: did not found %{digest32h} NSEC3, while trying to replace it with (another) %{digest32h} NSEC3", item->digest, value->digest);
    }
    else
    {
        log_err("nsec3_label_extension_replace_star: did not found %{digest32h} NSEC3, while trying to remove it", item->digest);
    }
    
    logger_flush();
    abort();
}

/**
 * Adds an entry to the "owner" array (of an item)
 * 
 * @param ownersp
 * @param countp
 * @param owner
 * 
 * 2 uses
 */

static void
nsec3_item_label_owner_add(nsec3_item_label_owner_array* ownersp, s32* countp, const zdb_rr_label *owner)
{
    yassert(ownersp != NULL);
    yassert(countp != NULL);
    yassert(owner != NULL);
    
    if(*countp == 0)
    {
        (*ownersp).owner = (zdb_rr_label*)owner;
        *countp = 1;
#if NSEC3_OWNER_DEBUG
        log_debug("nsec3_label_add: 1 '%{dnslabel}'", OWNER_NAME(owner));
#endif
    }
    else if(*countp == 1)
    {
        /*
         * We had one item : adding one will require using an array
         */
        if((*ownersp).owner != owner)
        {
            *countp = 2;

            nsec3_item_label_owner_array owners;

            ZALLOC_ARRAY_OR_DIE(zdb_rr_label**, owners.owners, sizeof(zdb_rr_label*) * 2, NSEC3_LABELPTRARRAY_TAG);

            owners.owners[0] = (*ownersp).owner;
            owners.owners[1] = (zdb_rr_label*)owner;

            (*ownersp).owners = owners.owners;

#if NSEC3_OWNER_DEBUG
            log_debug("nsec3_label_add: 2 '%{dnslabel}' '%{dnslabel}'", OWNER_NAME(owners.owners[0]), OWNER_NAME(owners.owners[1]));
#endif
        }
        else
        {
#if NSEC3_OWNER_DEBUG
            log_debug("nsec3_label_add: 1+1 '%{dnslabel}' already owned", OWNER_NAME(owner));
#endif
        }
    }
    else
    {
        /*
         * Just resize the current array to contain ONE more pointer
         */

        s32 count = *countp;

        for(s32 i = 0; i < count; ++i) // count >= 2 so the loop runs at least twice (or returns)
        {
            if((*ownersp).owners[i] == owner)
            {
#if NSEC3_OWNER_DEBUG
                  log_debug("nsec3_label_add: %hi+1 '%{dnslabel}' already owned", count, OWNER_NAME(owner));
#endif
                  return;
            }
        }
        
        /** @note ZALLOC_ARRAY_RESIZE does change the value of "count" to "count+1" */
        
        ZALLOC_ARRAY_RESIZE(zdb_rr_label*, (*ownersp).owners, count, count + 1);
        (*ownersp).owners[count-1] = (zdb_rr_label*)owner; /// @note count is already set to count + 1 by the macro; scan-build false positive, VS false positive
        *countp = count;

#if NSEC3_OWNER_DEBUG
        log_debug("nsec3_label_add: %i", count);
        for(s32 i = 0; i < count; i++)
        {
            log_debug(" + '%{dnslabel}'", OWNER_NAME((*ownersp).owners[i]));
        }
#endif
    }
}

/**
 * Removes an entry from the "owner" array (of an item)
 * Raw collection change, does not propagates.
 * 
 * @param ownersp
 * @param countp
 * @param owner
 * 
 * 2 uses
 */

static void
nsec3_item_label_owner_remove(nsec3_item_label_owner_array* ownersp, s32* countp, const zdb_rr_label *owner)
{
    yassert(ownersp != NULL);
    yassert(countp != NULL);
    yassert(owner != NULL);
    
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

        ZFREE_ARRAY((*ownersp).owners, sizeof(zdb_rr_label*) * 2);

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

        s32 idx;
        s32 n = *countp;

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
 * 
 * @param item
 * @param owner
 * @return 
 * 
 * 1 use
 */

bool
nsec3_item_is_owned_by_label(const nsec3_zone_item *item, const zdb_rr_label *owner)
{
    yassert(item != NULL);
    yassert(owner != NULL);
    yassert(item->rc >= 0);
    
    if(item->rc == 1)
    {
        return (item->label.owner == owner);
    }
    else if(item->rc != 0)
    {
        zdb_rr_label* const * ownerp = item->label.owners;
        s32 i = item->rc;
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

/**
 * Adds an owner to the NSEC3 item
 * 
 * To be absolutely clear: links NSEC3 to LABEL, but does NOT links LABEL to NSEC3
 * The label still has to be updated after this call.
 * 
 * @param item
 * @param owner
 * 
 * 6 uses
 */

void
nsec3_item_add_owner(nsec3_zone_item *item, const zdb_rr_label *owner)
{
    yassert(item != NULL);
    yassert(owner != NULL);

#if NSEC3_OWNER_DEBUG
    log_debug("nsec3_add_owner: %{digest32h} @ %p, '%{dnslabel}' RC=%i", ITEM_DIGEST(item), item, OWNER_NAME(owner), item->rc);
    s32 rc = item->rc;
#endif

    nsec3_item_label_owner_add(&item->label, &item->rc, owner);
    
#if NSEC3_OWNER_DEBUG
    if(item->rc - rc != 1)
    {
        log_debug("nsec3_add_owner: %{digest32h} @ %p, '%{dnslabel}' RC went from %i to %i", ITEM_DIGEST(item), item, OWNER_NAME(owner), rc, item->rc);
    }
#endif    
}

/**
 * Removes an owner from the NSEC3 item
 *
 * The entry MUST have been set before
 * 
 * @param item
 * @param owner
 * 
 * 1 use
 */
void
nsec3_item_remove_owner(nsec3_zone_item *item, const zdb_rr_label *owner)
{
    yassert(item != NULL);
    yassert(owner != NULL);
    yassert(nsec3_owner_count(item) >= 0);
#if NSEC3_OWNER_DEBUG
    log_debug("nsec3_remove_owner: %{digest32h} @ %p, '%{dnslabel}' RC=%i", ITEM_DIGEST(item), item, OWNER_NAME(owner), item->rc);
    s32 rc = item->rc;
#endif
    nsec3_item_label_owner_remove(&item->label, &item->rc, owner);
#if NSEC3_OWNER_DEBUG
    if(rc - item->rc != 1)
    {
        log_debug("nsec3_remove_owner: %{digest32h} @ %p, '%{dnslabel}' RC went from %i to %i", ITEM_DIGEST(item), item, OWNER_NAME(owner), rc, item->rc);
    }
#endif
}

/**
 * Removes all owners from the NSEC3 item
 *
 * The entry MUST have been set before
 * 
 * @param item
 * 
 * 3 uses
 */

void
nsec3_item_remove_all_owners(nsec3_zone_item *item)
{
    yassert(item != NULL);
    
#if NSEC3_OWNER_DEBUG
    log_debug("nsec3_remove_all_owners: %{digest32h} @ %p", ITEM_DIGEST(item), item);
#endif

    if(item->rc > 0)
    {
        if(item->rc == 1)
        {
            zdb_rr_label* label = item->label.owner;

            if(label != NULL)
            {
#if NSEC3_OWNER_DEBUG
                log_debug("nsec3_remove_all_owners: 1 : %p '%{dnslabel}'", item, label->name);
#endif
                // if an nsec3_label_extension is attached to the label

                if(label->nsec.nsec3 != NULL)
                {
                    // replace the self-NSEC3 link to 'item' by NULL, and retrieve the chain index

                    int item_chain_index = nsec3_label_extension_replace_self(label->nsec.nsec3, item, NULL);

                    // grab the nsec3_label_extension for the chain

                    nsec3_label_extension *n3e = nsec3_label_extension_get_from_label(label, item_chain_index);

                    if(nsec3_label_extension_star(n3e) != NULL)
                    {
                        // if there is a star reference, it needs to go

                        // remove the star-reference to the label
                        nsec3_item_remove_star(nsec3_label_extension_star(n3e), label);

                        // and replace the star-reference from the nsec3_label_extension by NULL
                        nsec3_label_extension_replace_star(n3e, nsec3_label_extension_star(n3e), NULL);
                    }
                }
                else
                {
                    log_warn("nsec3_remove_all_owners: label %{dnslabel} has no NSEC3 (flags=%04x)", label->name, zdb_rr_label_flag_get(label));
                }

                // the label has no star reference as far as this is concerned

                // update the NSEC3 flags on the label

                u16 is_still_nsec3_mask = ~ZDB_RR_LABEL_NSEC3;
                struct nsec3_label_extension* n3e = label->nsec.nsec3;
                while(n3e != NULL)
                {
                    if(nsec3_label_extension_self(n3e) != NULL)
                    {
                        is_still_nsec3_mask = ~0;
                        break;
                    }
                    n3e = nsec3_label_extension_next(n3e);
                }

                zdb_rr_label_flag_and(label, is_still_nsec3_mask);

                item->label.owner = NULL;
            }
        }
        else
        {
            s32 n = item->rc;

#if NSEC3_OWNER_DEBUG
            log_debug("nsec3_remove_all_owners: n : %p (%u)", item, n);
#endif
            // for all owner labels
            
            for(s32 i = 0; i < n; i++)
            {
                zdb_rr_label* label = item->label.owners[i];

                if(label != NULL)
                {
#if NSEC3_OWNER_DEBUG
                    log_debug("nsec3_remove_all_owners: n : %p '%{dnslabel}'", item, label->name);
#endif
                    if(label->nsec.nsec3 != NULL)
                    {
                        // replace the self-NSEC3 link to 'item' by NULL, and retrieve the chain index

                        int item_chain_index = nsec3_label_extension_replace_self(label->nsec.nsec3, item, NULL);

                        nsec3_label_extension *n3e = nsec3_label_extension_get_from_label(label, item_chain_index);

                        if(nsec3_label_extension_star(n3e) != NULL)
                        {
                            nsec3_item_remove_star(nsec3_label_extension_star(n3e), label);
                            nsec3_label_extension_replace_star(n3e, nsec3_label_extension_star(label->nsec.nsec3), NULL);
                        }
                    }
                    else
                    {
                        log_warn("nsec3_remove_all_owners: label %{dnslabel} has no NSEC3 (flags=%04x)", label->name, zdb_rr_label_flag_get(label));
                    }

                    // update the NSEC3 flags on the label

                    u16 is_still_nsec3_mask = ~ZDB_RR_LABEL_NSEC3;
                    struct nsec3_label_extension* n3e = label->nsec.nsec3;
                    while(n3e != NULL)
                    {
                        if(nsec3_label_extension_self(n3e) != NULL)
                        {
                            is_still_nsec3_mask = ~0;
                            break;
                        }
                        n3e = nsec3_label_extension_next(n3e);
                    }

                    zdb_rr_label_flag_and(label, is_still_nsec3_mask);

                    item->label.owners[i] = NULL;
                }
            }

            ZFREE_ARRAY(item->label.owners, sizeof(zdb_rr_label*) * n);

            item->label.owners = NULL;
        }

        item->rc = 0;
    }
}

/**
 * 
 * Returns the nth label owner for this item.
 * 
 * @param item an NSEC3 item
 * @param idx the index of the label for this hash (usually 0, except if there are collisions of digest(transform(label))
 * 
 * @return the owner
 * 
 * 1 use
 */

zdb_rr_label*
nsec3_item_owner_get(const nsec3_zone_item *item, s32 idx)
{
    yassert(item != NULL);
    
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
 * 
 * 5 uses
 */

void
nsec3_item_add_star(nsec3_zone_item *item, const zdb_rr_label *owner)
{
    yassert(item != NULL);
    yassert(owner != NULL);
    
#if NSEC3_OWNER_DEBUG
    log_debug("nsec3_add_star: %{digest32h} @ %p, %p '%{dnslabel}' SC=%hu", ITEM_DIGEST(item), item, owner, owner->name, item->sc);
    s32 sc = item->sc;
#endif

    nsec3_item_label_owner_add(&item->star_label, &item->sc, owner);
    
#if NSEC3_OWNER_DEBUG
    if(item->sc - sc != 1)
    {
        log_debug("nsec3_add_star: %{digest32h} @ %p, %p '%{dnslabel}' SC went from %hu to %hu", ITEM_DIGEST(item), item, owner, owner->name, sc, item->sc);
    }
#endif

}

/**
 * Removes a star from the NSEC3 item
 *
 * The entry MUST have been set before
 * 
 * @param item
 * @param owner
 * 3 uses
 */

void
nsec3_item_remove_star(nsec3_zone_item *item, const zdb_rr_label *owner)
{
    yassert(item != NULL);
    yassert(owner != NULL);
    
#if NSEC3_OWNER_DEBUG
    log_debug("nsec3_remove_star: %{digest32h}@ @ %p '%{dnslabel}' SC=%hu", ITEM_DIGEST(item), item, owner->name, item->sc);
    s32 sc = item->sc;
#endif
    nsec3_item_label_owner_remove(&item->star_label, &item->sc, owner);
#if NSEC3_OWNER_DEBUG
    
    if(sc - item->sc != 1)
    {
        log_err("nsec3_remove_star: %{digest32h}@ @ %p '%{dnslabel}' SC went from %hu to %hu", ITEM_DIGEST(item), item, owner->name, sc, item->sc);
    }
#endif
}

/**
 * Removes all stars from the NSEC3 item
 *
 * The entry MUST have been set before
 * 
 * @param item
 * 
 * 5 uses
 */

void
nsec3_item_remove_all_star(nsec3_zone_item *item)
{
    yassert(item != NULL);
    
#if NSEC3_OWNER_DEBUG
    log_debug("nsec3_remove_all_star(%{digest32h} @ %p)", ITEM_DIGEST(item), item);
#endif
    
    if(item->sc > 0)
    {
        if(item->sc == 1)
        {
            zdb_rr_label *label = item->star_label.owner;

            if(label != NULL)
            {
#if NSEC3_OWNER_DEBUG
                log_debug("nsec3_remove_all_star: n = 1 : %p '%{dnslabel}'", label, label->name);
#endif

                if(label->nsec.nsec3 != NULL)
                {
                    nsec3_label_extension_replace_star(label->nsec.nsec3, item, NULL);
                }
                else
                {
                    log_warn("nsec3_remove_all_star: label %{dnslabel} has no NSEC3 (flags=%04x)", label->name, zdb_rr_label_flag_get(label));
                }
                
                item->star_label.owner = NULL;
            }
        }
        else
        {
            u32 n = (u32)item->sc; // sc > 0

#if NSEC3_OWNER_DEBUG
            log_debug("nsec3_remove_all_star: n = %u", n);
            for(u32 i = 0; i < n; i++)
            {
                log_debug("\tlabel[%i] = %p '%{dnslabel}'", i, item->star_label.owners[i], item->star_label.owners[i]->name);
            }
#endif

            for(u32 i = 0; i < n; i++)
            {            
                zdb_rr_label *label = item->star_label.owners[i];

                if(label != NULL)
                {
                    if(label->nsec.nsec3 != NULL)
                    {
#if NSEC3_OWNER_DEBUG
                            log_debug("nsec3_remove_all_star: %i/%i %p '%{dnslabel}'", i, n, label, label->name);
#endif
                            nsec3_label_extension_replace_star(label->nsec.nsec3, item, NULL);
                    }

                    item->star_label.owners[i] = NULL;
                }
            }

            ZFREE_ARRAY(item->star_label.owners, sizeof(zdb_rr_label*) * n);

            item->star_label.owners = NULL;
        }

        item->sc = 0;
    }
}

/**
 * Moves all stars from one NSEC3 item to another.
 *
 * This is used when an NSEC3 item is removed: All its NSEC3 must be moved
 * to his predecessor.
 * 
 * @param src
 * @param dst
 *
 * 3 uses
 */

void
nsec3_item_move_all_star_to_nsec3_item(nsec3_zone_item* src, nsec3_zone_item* dst)
{
    yassert(src != NULL);
    yassert(dst != NULL);
    
#if NSEC3_OWNER_DEBUG
    log_debug("nsec3_move_all_star(%{digest32h} @ %p SC=%i, %{digest32h} @ %p SC=%i)", ITEM_DIGEST(src), src, src->sc, ITEM_DIGEST(dst), dst, dst->sc);
    s32 sum = src->sc + dst->sc;
#endif
    

    
    yassert(src != dst);
    
    if(src->sc == 0)
    {
        /* nothing to move */
        
        return;
    }

    // If there were no star in the dest : just move the star collection and update the referrenced labels

    if(dst->sc == 0)
    {
        dst->star_label.owner = src->star_label.owner;
        dst->sc = src->sc;
        for(s32 i = 0; i < src->sc; i++)
        {
            zdb_rr_label *label = nsec3_item_star_get(src, i);
            nsec3_label_extension_replace_star(label->nsec.nsec3, src, dst);
        }
    }
    else
    {
        // will merge both in dst
        
        nsec3_item_label_owner_array owners;
        
        s64 total = src->sc;
        total += dst->sc;
        
        yassert(total < (s64)(1ULL << (sizeof(src->sc) * 8)));

        /*
         * rc > 0 and sc > 0, so total of 2 means rc = 1 and sc = 1
         */

        ZALLOC_ARRAY_OR_DIE(zdb_rr_label**, owners.owners, sizeof(zdb_rr_label*) * total, NSEC3_LABELPTRARRAY_TAG);

        for(s32 i = 0; i < dst->sc; i++) // VS false positive: dst cannot be NULL
        {
            zdb_rr_label *label = nsec3_item_star_get(dst, i);
            
            log_debug("nsec3_move_all_star: %{digest32h} @%p %{dnslabel} @%p %i -> %i", ITEM_DIGEST(dst), dst, label->name, label, i, i);
            
            owners.owners[i] = label;
        }

        if(dst->sc > 1) // if it's a real array, free it
        {
            s32 len = dst->sc * sizeof(zdb_rr_label*);
            ZFREE_ARRAY(dst->star_label.owners, len);
        }

        /* change the star link of each label from src to dst */
        for(s32 i = 0; i < src->sc; i++) // VS false positive: SRC cannot be NULL
        {
            zdb_rr_label *label = nsec3_item_star_get(src, i);
            
            log_debug("nsec3_move_all_star: %{digest32h} @%p %{dnslabel} @%p %i -> %i", ITEM_DIGEST(src), src, label->name, label, i, dst->sc + i);
            
            nsec3_label_extension_replace_star(label->nsec.nsec3, src, dst);
            owners.owners[dst->sc + i] = label;
        }

        if(src->sc > 1) // if it's a real array, free it
        {
            s32 len = src->sc * sizeof(zdb_rr_label*);
            ZFREE_ARRAY(src->star_label.owners, len);
        }

        dst->star_label.owners = owners.owners; // owner when 1 item, owners when multiple. False positives from static analysers.
        dst->sc = total;
    }
    
    src->star_label.owners = NULL;
    src->sc = 0;
    
#if NSEC3_OWNER_DEBUG
    if(dst->sc != sum)
    {
        log_debug("nsec3_move_all_star(%{digest32h} @ %p, %{digest32h} @ %p SC went %i instead of %i)", ITEM_DIGEST(src), src, ITEM_DIGEST(dst), dst, dst->sc, sum);
    }
#endif
}

/**
 * 
 * Returns the nth star label owner for this item.
 * 
 * @param item an NSEC3 item
 * @param idx the index of the label for this hash (usually 0, except if there are collisions of digest(transform(label))
 * 
 * @return the owner
 *
 * 4 uses
 */

zdb_rr_label *
nsec3_item_star_get(const nsec3_zone_item *item, s32 idx)
{
    yassert(item != NULL);
    
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

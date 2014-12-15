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

#if ZDB_HAS_NSEC3_SUPPORT == 0
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
#include "dnsdb/zdb_listener.h"
#include "dnsdb/rrsig.h"

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

/*
 * Updates an nsec3 record
 * made for dynamic updates
 */

void
nsec3_update_label_update_record(zdb_zone *zone, zdb_rr_label* label, u16 type)
{
    /*
     * For each NSEC3 param (and there better be at least one)
     *
     * Get the types bitmap.
     * Compute if the type is supposed to be enabled or not
     * If the type bitmaps has to be changed
     *	    Update the type bitmap
     *	    Schedule for a signature
     */

    /*
     * These two slots are for the owner label but have to be stored in
     * (and owned by) the NSEC3 item.
     */

    yassert(type != TYPE_ANY);

    if((zone->apex->flags & ZDB_RR_LABEL_NSEC3) == 0)
    {
        return;
    }

    nsec3_label_extension* next_n3_ext = label->nsec.nsec3;

    yassert(next_n3_ext != NULL);

    do
    {
        nsec3_zone_item* self = next_n3_ext->self;

        bool enabled;

        if(self != NULL)
        {
            if(self->rc == 1)
            {
                enabled = (zdb_record_find(&self->label.owner->resource_record_set, type) != NULL);
            }
            else
            {
                /* This handles the HIGHLY unlikely case of digest collisions */

                enabled = FALSE;
                
                for(u16 idx = 0; idx < self->rc; idx++)
                {
                    enabled |= (zdb_record_find(&self->label.owners[idx]->resource_record_set, type) != NULL);
                    /*
                     * Yes: I could test and stop at the first "enabled" set to TRUE.
                     * It does not matter.  A digest collision is almost stochastically impossible.
                     *
                     * => Smaller is better.
                     */
                }
            }

            /* Check it the type status in the bitmap matches enabled */

            if(type_bit_maps_gettypestatus(self->type_bit_maps, self->type_bit_maps_size, type) != enabled)
            {
                /*
                 * The type status has been changed.
                 *
                 * The fastest way from here is to work on the existing bitmap and switch the bit
                 */

                u8* packed_type_bitmap = self->type_bit_maps;
                u32 size = self->type_bit_maps_size;

                u8 window_index = (type >> 8);
                s32 byte_offset = (type >> 3) & 0x1f;

                /* Skip to the right window */

                while(size > 2)
                {
                    u8 current_index = *packed_type_bitmap++;
                    u8 current_size = *packed_type_bitmap++;

                    if(current_index >= window_index)
                    {
                        if(current_index == window_index)
                        {
                            /*
                             * Here, we will be able to know the new size of the window
                             * And thus to allocate a new array if required
                             */

                            if(enabled)
                            {
                                if(byte_offset > current_size)
                                {
                                    /* Stretch
                                     *
                                     * The increase is byte_offset - current_size
                                     *
                                     */

                                    u32 delta_size = byte_offset + 1 - current_size;

                                    u32 new_type_bit_maps_size = self->type_bit_maps_size + delta_size;

                                    /*
                                     * Allocate a new buffer
                                     */

                                    u8* new_type_bit_maps;

                                    ZALLOC_ARRAY_OR_DIE(u8*, new_type_bit_maps, new_type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);

                                    /* Copy the previous windows along with this window type */

                                    u32 prev_offset = packed_type_bitmap - self->type_bit_maps - 1;

                                    u8* p = new_type_bit_maps;

                                    MEMCOPY(p, self->type_bit_maps, prev_offset);

                                    p += prev_offset;

                                    /* Set the window size */

                                    *p++ = byte_offset + 1;

                                    /* Append the previous bitmap of the current window */

                                    MEMCOPY(p, packed_type_bitmap, current_size);

                                    p += current_size;

                                    ZEROMEMORY(p, delta_size - 1);

                                    p += delta_size - 1;

                                    /* Append the byte with the type enabled */

                                    *p++ = (0x80 >> (type & 7));

                                    /* Append the remaining windows */

                                    packed_type_bitmap += current_size;

                                    MEMCOPY(p, packed_type_bitmap, size - 2 - current_size);

                                    /* Free the current buffer */

                                    ZFREE_ARRAY(self->type_bit_maps, self->type_bit_maps_size);

                                    /* Set the new buffer */

                                    self->type_bit_maps = new_type_bit_maps;
                                    self->type_bit_maps_size = new_type_bit_maps_size;
                                }
                                else
                                {
                                    /* Just enable the type */

                                    packed_type_bitmap[byte_offset] |= (0x80 >> (type & 7));
                                }

                                /* This is a trick so I know I don't have to append
                                 * a new window after this loops ends
                                 */

                                enabled = FALSE;
                            }
                            else
                            {
                                /**
                                 * @note 20140523 edf -- check speed.
                                 *
                                 * & (ff7f >> (type & 7)) <=> & ~(0x80 >> (type & 7))
                                 *
                                 * What's the faster one ?
                                 *
                                 * The left one seems promising because he does one operation less,
                                 * but the right one is done with bytes only, it means there should
                                 * be no 32 => 8 operation.  Although on an x86/AMD64 it requires
                                 * no operation.
                                 *
                                 */

                                /* Disables the type AND checks if the byte is set to 0 */

                                if((packed_type_bitmap[byte_offset] &= ~(0x80 >> (type & 7))) == 0)
                                {
                                    /* If the change is made on the last byte,
                                     * the size of the window MUST be decreased to
                                     * the last non-zero byte.
                                     *
                                     * Also if the whole window becomes empty, it
                                     * has to be removed.
                                     */

                                    if(byte_offset + 1 == current_size)
                                    {
                                        /*
                                         * Squeeze
                                         *
                                         * The decrease is at least current_size - byte_offset
                                         *
                                         */

                                        int new_byte_offset = byte_offset;

                                        while((--new_byte_offset > 0) && (packed_type_bitmap[new_byte_offset] == 0));

                                        size -= byte_offset - new_byte_offset;
                                        byte_offset = new_byte_offset;

                                        if(byte_offset < 0)
                                        {
                                            /* Destroy the window
                                             *
                                             * Let p be the current pointer.
                                             *
                                             * Copy the (size - current_size) remaining bytes at
                                             * p[current_size] to p[-2]
                                             *
                                             * NOTE: A "realloc" should be done.
                                             * But since the real buffer size (granularity) could be the same
                                             * for both buffers, the squeeze would be the best one to do it.
                                             *
                                             *
                                             */

                                            MEMCOPY(&packed_type_bitmap[-2], &packed_type_bitmap[current_size], size - 2 - current_size);

                                            ZALLOC_ARRAY_RESIZE(u8, self->type_bit_maps, self->type_bit_maps_size, self->type_bit_maps_size - 2 - current_size);
                                        }
                                        else
                                        {
                                            /* Just resize the window
                                             *
                                             * Let p be the current pointer.
                                             * Let d the size decrease of the window
                                             *
                                             * Set the new size of the window
                                             *
                                             * Copy the (size - d) remaining bytes at
                                             * p[current_size] to p[byte_offset + 1]
                                             *
                                             * NOTE: A "realloc" should be done.
                                             * But since the real buffer size (granularity) could be the same
                                             * for both buffers, the squeeze would be the best one to do it.
                                             *
                                             *
                                             */

                                            /* I need the new window size */

                                            byte_offset++;

                                            packed_type_bitmap[-1] = byte_offset;

                                            u32 delta_size = current_size - (byte_offset);

                                            MEMCOPY(&packed_type_bitmap[byte_offset], &packed_type_bitmap[current_size], size - delta_size);

                                            ZALLOC_ARRAY_RESIZE(u8, self->type_bit_maps, self->type_bit_maps_size, self->type_bit_maps_size - delta_size);
                                        }

                                    } /* endif : squeeze required */

                                } /* endif : clearing the bit has set the byte to 0 */

                            } /* endif : enabled / disabled */

                        } /* endif : found the window*/

                        break;
                    }

                    size -= 2;

                    size -= current_size;
                    packed_type_bitmap += current_size;
                } /* while size (while there are bytes in this window */

                /* Note: I also force "enabled" to false as a trick so I know I don't have to append
                 * a new window after this loops ends
                 */

                if(enabled)
                {
                    /*
                     * Append a new window.
                     *
                     */

                    u8* new_buffer;
                    u32 new_size = self->type_bit_maps_size + 2 + (byte_offset + 1);

                    ZALLOC_ARRAY_OR_DIE(u8*, new_buffer, new_size, NSEC3_TYPEBITMAPS_TAG);
                    MEMCOPY(new_buffer, self->type_bit_maps, self->type_bit_maps_size);
                    new_buffer[self->type_bit_maps_size ] = window_index;
                    new_buffer[self->type_bit_maps_size + 1] = (byte_offset + 1);
                    ZEROMEMORY(&new_buffer[self->type_bit_maps_size + 2], byte_offset);
                    new_buffer[new_size - 1] = (0x80 >> (type & 7));

                    ZFREE_ARRAY(self->type_bit_maps, self->type_bit_maps_size);

                    self->type_bit_maps = new_buffer;
                    self->type_bit_maps_size = new_size;
                }
            }
        }
        
        /* Loop to the next NSEC3PARAM NSEC3 set */

        next_n3_ext = next_n3_ext->next;
    }
    while(next_n3_ext != NULL);
}

bool
nsec3_update_label(zdb_zone *zone, zdb_rr_label* label, dnslabel_vector_reference labels, s32 labels_top)
{

    /*
     * If label has no nsec3 ->  nsec3_add_label
     *
     * Else
     *
     * Check the types, change if required.
     */

    /*
     * NOTE: This could be one of the best places to use the scheduler
     */

    if(label->nsec.nsec3 == NULL)
    {
        nsec3_add_label(zone, label, labels, labels_top);
        
        return TRUE;
    }
    
    nsec3_zone_item *nsec3_item = label->nsec.nsec3->self;

    if(nsec3_item == NULL)
    {
        yassert((label->nsec.nsec3->self == NULL) && (label->nsec.nsec3->star == NULL) && (label->nsec.nsec3->next == NULL));
        ZFREE(label->nsec.nsec3, nsec3_label_extension);
        label->nsec.nsec3 = NULL;
        
        nsec3_add_label(zone, label, labels, labels_top);

        return TRUE;
    }

    type_bit_maps_context type_context;

    u16 type_bit_maps_size = type_bit_maps_initialize(&type_context, label, FALSE, TRUE);
    
    if(type_bit_maps_size > 0)
    {
        u8 *type_bit_maps;
        
        ZALLOC_ARRAY_OR_DIE(u8*, type_bit_maps, type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);
        type_bit_maps_write(type_bit_maps, &type_context);

        /*
         * @TODO check: Why merge ? Why not generate & compare instead ? I don't remember why I did this.
         */

        if(type_bit_maps_merge(&type_context, nsec3_item->type_bit_maps, nsec3_item->type_bit_maps_size, type_bit_maps, type_bit_maps_size))
        {
            /* TRUE : a merge occurred : the bitmap has to be changed, the signature remade */

            /*
             * Try to re-use one of the buffers
             */

            if(type_context.type_bit_maps_size == nsec3_item->type_bit_maps_size)
            {
                ZFREE_ARRAY(type_bit_maps, type_bit_maps_size);
            }
            else if(type_context.type_bit_maps_size == type_bit_maps_size)
            {
                ZFREE_ARRAY(nsec3_item->type_bit_maps, nsec3_item->type_bit_maps_size);

                nsec3_item->type_bit_maps = type_bit_maps;
                nsec3_item->type_bit_maps_size = type_bit_maps_size;
            }
            else
            {
                ZFREE_ARRAY(type_bit_maps, type_bit_maps_size);
                ZFREE_ARRAY(nsec3_item->type_bit_maps, nsec3_item->type_bit_maps_size);

                ZALLOC_ARRAY_OR_DIE(u8*, nsec3_item->type_bit_maps, type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);
                nsec3_item->type_bit_maps_size = type_bit_maps_size;
            }

            type_bit_maps_write(nsec3_item->type_bit_maps, &type_context);

            nsec3_zone_item_rrsig_delete_all(nsec3_item);

            return TRUE;
        }
        else
        {
            /* Nothing to do */

            ZFREE_ARRAY(type_bit_maps, type_bit_maps_size);

            return FALSE;
        }
    }
    else
    {
        /*
         * Empty terminator ...
         * @TODO The NSEC3 should be removed along with its signature.
         */

        log_quit("nsec3_update_label called on an empty terminator.  nsec3_remove_label should have been called instead.");

        return FALSE; /* NEVER REACHED */
    }
}

/*
 * Adds NSEC3 records to a label.  This is NOT an update.
 * We assume that the labels are not a fqdn bigger than MAX_DOMAIN_LENGTH
 */

void
nsec3_add_label(zdb_zone *zone, zdb_rr_label* label, dnslabel_vector_reference labels, s32 labels_top)
{
    /*
     * All the intermediary labels are supposed to be ready, the caller
     * MUST call this function each time it adds a new label
     *
     * Compute the stuff
     * Create/Link the NSEC3
     *	    From the PREVIOUS NSEC3 record, recompute the ones that are now
     *	    supposed to be put in the new one
     * Increase the relevant SC
     * A signature should be ordered for this one and for the previous one
     *
     */

    type_bit_maps_context type_context;

    /*
     * All the labels from (included) the root to the zone have to be added
     */

    u32 name_len;
    u8 name[2 + MAX_DOMAIN_LENGTH];
    u8 digest[1 + MAX_DIGEST_LENGTH];

    name[0] = 1;
    name[1] = '*';

    /* NOTE: the final 0 is taken in account in the returned length */

    /* - 1 because of said final 0 */
    name_len = dnslabel_vector_to_dnsname(labels, labels_top, &name[2])/* - 1*/;

    log_debug("nsec3_add_label: %{dnsname}: adding", &name[2]);

    bool opt_out = ((zone->apex->flags & ZDB_RR_LABEL_NSEC3_OPTOUT) != 0);

    u8 default_flags = (opt_out)?1:0;
    
    bool force_rrsig;
    
    if(ZDB_LABEL_UNDERDELEGATION(label))
    {
        force_rrsig = FALSE;
    }
    else
    {   
        /* opt-in */
        
        if(!opt_out)
        {
            force_rrsig = TRUE;
        }
        else /* opt-out */
        {            
            if(ZDB_LABEL_ATDELEGATION(label))
            {
                force_rrsig =  (zdb_record_find(&label->resource_record_set, TYPE_DS) != NULL);    /* Has NS & DS */
            }
            else
            {
                force_rrsig = TRUE;
            }
        }
    }
    
    /*
     * These two slots are for the owner label but have to be stored in
     * (and owned by) the NSEC3 item.
     */

    u16 type_bit_maps_size = type_bit_maps_initialize(&type_context, label, FALSE, force_rrsig);

    nsec3_zone* n3 = zone->nsec.nsec3;
    
    nsec3_label_extension* next_n3_ext = NULL;

    yassert(n3 != NULL);

    do
    {
        digest[0] = nsec3_hash_len(NSEC3_ZONE_ALGORITHM(n3));

        nsec3_hash_function* digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3));

        digestname(&name[2], name_len, NSEC3_ZONE_SALT(n3), NSEC3_ZONE_SALT_LEN(n3), nsec3_zone_get_iterations(n3), &digest[1], FALSE);

        log_debug("nsec3_add_label: %{dnsname}: NSEC3 name is %{digest32h}", &name[2], digest);

        /*
         * Creates or return the existing nsec3 node for the digest
         *
         */

        nsec3_zone_item *self = nsec3_avl_insert(&n3->items, digest);

        // self->type_bit_maps is NULL => new one

        /*
         * Destroy the previous NSEC3's signature
         */

        nsec3_zone_item *self_prev = nsec3_avl_node_mod_prev(self);

        yassert(self_prev != NULL);

        if(self_prev->rrsig != NULL)
        {
            ZDB_RECORD_ZFREE(self_prev->rrsig);
            self_prev->rrsig = NULL;

        }

        /*
         * Destroy the prev's star references.
         */

#ifdef DEBUG
        if(self_prev->sc > 0)
        {
            log_debug("nsec3_add_label: %{dnsname}: clearing %{digest32h} (predecessor)", &name[2], self_prev->digest);
        }
#endif

        nsec3_remove_all_star(self_prev);

        /** @todo self_prev needs to be signed */

        /*
         *  self -> rc++
         *  self -> owner += label (list + 1 item)
         *
         */

#ifdef DEBUG
        if(self->rc != 0)
        {
            log_debug("nsec3_add_label: %{dnsname}: %{digest32h} has got owner collisions", &name[2], self->digest);
        }
#endif

        nsec3_add_owner(self, label);

        /*
         * Note: the self is edited later
         */
        
        self->flags = default_flags;

        if(self->type_bit_maps_size == 0)
        {
            /*
             * Set the bitmap
             */

            self->type_bit_maps = NULL;
            self->type_bit_maps_size = type_bit_maps_size;

            if(type_bit_maps_size > 0)
            {
                ZALLOC_ARRAY_OR_DIE(u8*, self->type_bit_maps, type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);
                type_bit_maps_write(self->type_bit_maps, &type_context);
            }
        }
        else
        {
            /* Merge the existing bitmap with the new one */

            u8* tmp_type_bit_maps;

            ZALLOC_ARRAY_OR_DIE(u8*, tmp_type_bit_maps, type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);

            /* type_bit_maps_size > 0 */

            type_bit_maps_write(tmp_type_bit_maps, &type_context);

            if(type_bit_maps_merge(&type_context, self->type_bit_maps, self->type_bit_maps_size, tmp_type_bit_maps, type_bit_maps_size))
            {
                /* TRUE : a merge occurred */

                /**
                 * @todo: nsec3_update has got this operation added:
                 *
                 * Check if this is a mistake to have not put it here
                 *
                 * If it was, do the requested factorization (nsec3_update)

                if((node->flags&NSEC3_FLAGS_MARKED_FOR_ICMTL_ADD)==0)
                {
                    zdb_listener_notify_remove_nsec3(node, n3);
                    node->flags|=NSEC3_FLAGS_MARKED_FOR_ICMTL_ADD;
                }
                 */

                yassert(type_bit_maps_size > 0);

                type_bit_maps_size = type_context.type_bit_maps_size;

                ZFREE_ARRAY(self->type_bit_maps, self->type_bit_maps_size);

                ZALLOC_ARRAY_OR_DIE(u8*, self->type_bit_maps, type_bit_maps_size, NSEC3_TYPEBITMAPS_TAG);

                self->type_bit_maps_size = type_bit_maps_size;

                type_bit_maps_write(self->type_bit_maps, &type_context);

                /*
                 * This case does not exist:  A merge of something of size > 0
                 * with anything will always give a size > 0
                 *
                 * else
                 * {
                 *   self->type_bit_maps_size = 0;
                 * }
                 *
                 */
            }

            ZFREE_ARRAY(tmp_type_bit_maps, type_bit_maps_size);
        }

        /* nsec3_set_label_extension */

        if(next_n3_ext == NULL)
        {
            yassert(label->nsec.nsec3 == NULL);

            ZALLOC_OR_DIE(nsec3_label_extension*, next_n3_ext, nsec3_label_extension, NSEC3_LABELEXT_TAG);

#ifdef DEBUG
            memset(next_n3_ext, 0xac, sizeof(nsec3_label_extension));
#endif

            label->nsec.nsec3 = next_n3_ext;
        }
        else
        {
            yassert(next_n3_ext->next == NULL);

            ZALLOC_OR_DIE(nsec3_label_extension*, next_n3_ext->next, nsec3_label_extension, NSEC3_LABELEXT_TAG);

#ifdef DEBUG
            memset(next_n3_ext->next, 0xca, sizeof(nsec3_label_extension));
#endif

            next_n3_ext = next_n3_ext->next;
        }

        /*
         * Are an array (More than one NSEC3PARAM)
         */

        yassert(self != NULL);


        next_n3_ext->self = self;

        /** @todo self needs to be signed */

        digestname(name, name_len + 2, NSEC3_ZONE_SALT(n3), NSEC3_ZONE_SALT_LEN(n3), nsec3_zone_get_iterations(n3), &digest[1], FALSE);

        nsec3_zone_item* star = nsec3_avl_find_interval_start(&n3->items, digest);

        nsec3_add_star(star, label);

        next_n3_ext->star = star;
        next_n3_ext->next = NULL;

        n3 = n3->next;
    }
    while(n3 != NULL);

    label->flags |= ZDB_RR_LABEL_NSEC3;
}

/**
 * This function is for when a label has been added "without intelligence".
 * It will find if the function has got a matching NSEC3 record (by digest)
 * If so, it will link to it.
 */

static nsec3_zone_item *
nsec3_label_link_seeknode(nsec3_zone* n3, const u8 *fqdn, s32 fqdn_len, u8 *digest)
{
    nsec3_hash_function* digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3));

    digest[0] = nsec3_hash_len(NSEC3_ZONE_ALGORITHM(n3));
    digestname(fqdn, fqdn_len, NSEC3_ZONE_SALT(n3), NSEC3_ZONE_SALT_LEN(n3), nsec3_zone_get_iterations(n3), &digest[1], FALSE);

    nsec3_zone_item *self = nsec3_avl_find(&n3->items, digest);

    return self;
}

static nsec3_zone_item *
nsec3_label_link_seekstar(nsec3_zone* n3, const u8 *fqdn, s32 fqdn_len, u8 *digest)
{
    nsec3_hash_function* digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3));

    digest[0] = nsec3_hash_len(NSEC3_ZONE_ALGORITHM(n3));
    digestname(fqdn, fqdn_len, NSEC3_ZONE_SALT(n3), NSEC3_ZONE_SALT_LEN(n3), nsec3_zone_get_iterations(n3), &digest[1], TRUE);

    nsec3_zone_item* star = nsec3_avl_find_interval_start(&n3->items, digest);

    return star;
}
 
void
nsec3_label_link(zdb_zone *zone, zdb_rr_label* label, const u8 *fqdn)
{
    nsec3_zone* n3 = zone->nsec.nsec3;
    
#ifdef DEBUG
    if(n3 == NULL)
    {
        log_err("zone %{dnsname} has invalid NSEC3 data");
        return;
    }
#endif
    
    nsec3_label_extension **n3lep = &label->nsec.nsec3;

    
    u8 digest[1 + MAX_DIGEST_LENGTH];
    
    // yassert(label->nsec.nsec3 == NULL);

    yassert(n3 != NULL);

    s32 fqdn_len = dnsname_len(fqdn);
    s32 add_count = 0;
    bool linked = FALSE;

    do
    {
        nsec3_label_extension *n3le = *n3lep;
        
        if(n3le == NULL)
        {
            nsec3_zone_item *self = nsec3_label_link_seeknode(n3, fqdn, fqdn_len, digest);
            
            if(self == NULL)
            {
                /* no associated node */

                log_debug("nsec3_label_link: %{dnsname} => %{digest32h}: no NSEC3", fqdn, digest);

                break;
            }
            
            /**/

            ZALLOC_OR_DIE(nsec3_label_extension*, *n3lep, nsec3_label_extension, NSEC3_LABELEXT_TAG);
            n3le = *n3lep;            
    #ifdef DEBUG
            memset(n3le, 0xac, sizeof(nsec3_label_extension));
    #endif          
            n3le->next = NULL;
            
            /**/

            nsec3_add_owner(self, label);
            n3le->self = self;

            /**/
            
            nsec3_zone_item* star = nsec3_label_link_seekstar(n3, fqdn, fqdn_len, digest);
            nsec3_add_star(star, label);
            n3le->star = star;
            
            /**/

            add_count++;

            n3lep = &n3le->next;
            
            linked = TRUE;
        }
        else
        {
            nsec3_label_extension *n3le = *n3lep;
            
            /* a node exists already, maybe it's not associated yet */
            
            if(n3le->self == NULL)
            {
                nsec3_zone_item *self = nsec3_label_link_seeknode(n3, fqdn, fqdn_len, digest);
                
                if(self != NULL)
                {
                    nsec3_add_owner(self, label);
                    n3le->self = self;
                    nsec3_zone_item* star = nsec3_label_link_seekstar(n3, fqdn, fqdn_len, digest);
                    
                    assert(star != NULL);

                    nsec3_add_star(star, label);
                    n3le->star = star;
                    
                    linked = TRUE;
                }
            }
            
            n3lep = &n3le->next;
        }
        
        n3 = n3->next;
    }
    while(n3 != NULL);

    /* Partial update = BAD */
    
    yassert((n3 == NULL) || (n3 != NULL  && add_count == 0));

    if(linked)
    {
        label->flags |= ZDB_RR_LABEL_NSEC3;
    }
}

/*
 * Unlink the label from the NSEC3
 *
 * Destroy everything NSEC3 from the label
 */

void
nsec3_remove_label(zdb_zone *zone, zdb_rr_label* label)
{
    /*
     *
     * 1)
     *
     * Decrease the RC
     * Decrease the SC
     *
     * 2)
     *
     * If RC == 0 (most likely)
     *	    Move all star references to the PREVIOUS NSEC3 record
     *	    destroy the NSEC3 record
     */

    nsec3_label_extension* n3le = label->nsec.nsec3;

    yassert(n3le != NULL);

    //assert_mallocated(n3le);

    log_debug("nsec3_remove_label: %{dnslabel} . %{dnsname}", label->name, zone->origin);

    /* 1) */

    do
    {
        nsec3_zone_item *item = n3le->self;

        if(n3le->star != NULL)
        {
            log_debug("nsec3_remove_label: releasing star %{digest32h}", n3le->star->digest);

            nsec3_remove_star(n3le->star, label);
            n3le->star = NULL;
        }

        if(item != NULL)    /* item = n3le->self */
        {
            log_debug("nsec3_remove_label: releasing self %{digest32h}", item->digest);
            
            nsec3_remove_owner(item, label);
            n3le->self = NULL;

            /* 2) */

            if(item->rc == 0)
            {
                if(item->sc > 0)
                {
                    nsec3_zone_item* prev = nsec3_avl_node_mod_prev(item);

                    /*
                     * Take all the star nodes from item
                     *
                     * For each of these nodes, update the NSEC3 reference to "prev"
                     *
                     * Add all the star nodes of item to prev, in one go
                     */

                    nsec3_move_all_star(item, prev);
                }

                yassert(item->rc == 0 && item-> sc == 0 && label->nsec.nsec3->self == NULL);

                /* Destroy item */

                /* First, get the root */

                nsec3_zone* n3 = nsec3_zone_from_item(zone, item);

                yassert(n3 != NULL);

                ZFREE_ARRAY(item->type_bit_maps, item->type_bit_maps_size);
                item->type_bit_maps = NULL;

                nsec3_avl_delete(&n3->items, item->digest);
                
                /** @todo if incremental is on, feedback */
            }
        }

        nsec3_label_extension *n3le_tmp = n3le;

        n3le = n3le->next;

        ZFREE(n3le_tmp, nsec3_label_extension);
    }
    while(n3le != NULL);

    label->nsec.nsec3 = NULL;
}

/**
 * Initializes an RDATA for an NSEC3PARAM using an hash algorithm, flags, iterations, salt length and salt.
 */

static ya_result
nsec3_build_nsec3param_rdata(u8* nsec3param_rdata, const u8* origin, u8 default_hash_alg, u8 default_flags, u16 default_iterations, u8 default_salt_len, const u8* default_salt)
{
    /* Size of the digest in Base32 Hex */

    u32 b32h_hash_len = ((nsec3_hash_len(default_hash_alg) + 4) / 5) << 3;

    if((b32h_hash_len == 0) || (1 + b32h_hash_len + dnsname_len(origin)) > MAX_DOMAIN_LENGTH - 2) /* - 2 for the '*.' */
    {
        return DNSSEC_ERROR_NSEC3_DIGESTORIGINOVERFLOW; /* name would be too big */
    }

    nsec3param_rdata[0] = default_hash_alg;
    nsec3param_rdata[1] = default_flags;
    SET_U16_AT(nsec3param_rdata[2], htons(default_iterations));
    nsec3param_rdata[4] = default_salt_len;
    MEMCOPY(NSEC3PARAM_RDATA_SALT(nsec3param_rdata), default_salt, default_salt_len);
    
    return NSEC3PARAM_MINIMUM_LENGTH + default_salt_len;
}

/**
 * Adds an nsec3param in the zone (both "DB" and "NSEC3" sides).
 *
 * Delegates to nsec3_zone_add_from_rdata
 *
 */

ya_result
nsec3_add_nsec3param(zdb_zone *zone, u8 default_hash_alg, u8 default_flags, u16 default_iterations, u8 default_salt_len, u8* default_salt)
{
    yassert(default_hash_alg == 1);

    ya_result return_code;

    u16 nsec3param_rdata_size;
    
    u8 nsec3param_rdata[NSEC3PARAM_MINIMUM_LENGTH + MAX_SALT_LENGTH];

    if(FAIL(return_code = nsec3_build_nsec3param_rdata(nsec3param_rdata, zone->origin, default_hash_alg, default_flags, default_iterations, default_salt_len, default_salt)))
    {
        return return_code;
    }

    nsec3param_rdata_size = (u16)return_code;

    nsec3_zone* n3 = nsec3_zone_get_from_rdata(zone, nsec3param_rdata_size, nsec3param_rdata);

    if(n3 == NULL)
    {
        /*n3 =*/nsec3_zone_add_from_rdata(zone, nsec3param_rdata_size, nsec3param_rdata);

        zdb_packed_ttlrdata* nsec3param;

        ZDB_RECORD_ZALLOC(nsec3param, NSEC3PARAM_DEFAULT_TTL, nsec3param_rdata_size, nsec3param_rdata); /** @todo: NSEC3PARAM_DEFAULT_TTL : put the real value here*/

        /*
         * Add the NSEC3PARAM to the zone apex
         * Don't do dups
         */

        if(zdb_record_insert_checked(&zone->apex->resource_record_set, TYPE_NSEC3PARAM, nsec3param)) /* FB done (and yes: this returns a boolean) */
        {
#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0

            /*
             * Update ICMTL.
             *
             * NOTE: the zdb_rr_label set of functions are zdb_listener-aware but the zdb_record ones are not.
             * That's why this one needs a call to the listener.
             *
             */

            zdb_ttlrdata unpacked_ttlrdata;
            unpacked_ttlrdata.rdata_pointer = &nsec3param->rdata_start[0];
            unpacked_ttlrdata.rdata_size = nsec3param->rdata_size;
            unpacked_ttlrdata.ttl = nsec3param->ttl;
            u8 * origin_vector[1] = {zone->origin};
            zdb_listener_notify_add_record(origin_vector, 0, TYPE_NSEC3PARAM, &unpacked_ttlrdata);
#endif
        }

        /** @note if we add an nsec3param, we are about to edit the zone.
         *  @todo have an "atomic" way to do all this (mark edit + add param + update nsec3 + update sigs + unmark edit)
         */

        nsec3_edit_zone_start(zone);
    }

    return SUCCESS;
}

/**
 * 
 * Removes an NSEC3PARAM record and its associated structure.
 *
 * @todo: Test nsec3_remove_nsec3param
 */

ya_result
nsec3_remove_nsec3param(zdb_zone *zone, u8 hash_alg, u8 flags, u16 iterations, u8 salt_len, const u8* salt)
{
    ya_result return_code;

    /* Build the wire */

    u16 nsec3param_rdata_size;
    u8 nsec3param_rdata[NSEC3PARAM_MINIMUM_LENGTH + MAX_SALT_LENGTH];

    if(FAIL(return_code = nsec3_build_nsec3param_rdata(nsec3param_rdata, zone->origin, hash_alg, flags, iterations, salt_len, salt)))
    {
        return return_code;
    }

    nsec3param_rdata_size = (u16)return_code;

    /* Remove the NSEC3PARAM record */

    zdb_ttlrdata nsec3param_record;
    nsec3param_record.next = NULL;
    nsec3param_record.rdata_size = nsec3param_rdata_size;
    nsec3param_record.rdata_pointer = nsec3param_rdata;
    nsec3param_record.ttl = NSEC3PARAM_DEFAULT_TTL;

    if(ISOK(zdb_record_delete_exact(&zone->apex->resource_record_set, TYPE_NSEC3PARAM, &nsec3param_record)))
    {
#if ZDB_CHANGE_FEEDBACK_SUPPORT != 0

       /*
        * Update ICMTL.
        *
        * NOTE: the zdb_rr_label set of functions are zdb_listener-aware but the zdb_record ones are not.
        * That's why this one needs a call to the listener.
        *
        */

        zdb_listener_notify_remove_record(zone->origin, TYPE_NSEC3PARAM, &nsec3param_record);
#endif
    }

    /* Retrieve the NSEC3PARAM structure from the zone */

    nsec3_zone* n3 = nsec3_zone_get_from_rdata(zone, nsec3param_rdata_size, nsec3param_rdata);

    if(n3 != NULL)
    {
        /* Destroy said structure and all its associations (NSEC3 item + label's references to it) */

        nsec3_zone_destroy(zone, n3);
    }

    return SUCCESS;
}

/*
 * This destroy all the NSEC3 structures from the zone, starting from the NSEC3PARAM.
 * The zdb_rr_label are also affected by the call.
 */

void
nsec3_destroy_zone(zdb_zone *zone)
{
    if((zone->apex->flags & ZDB_RR_LABEL_NSEC3) != 0)
    {
        while(zone->nsec.nsec3 != NULL)
        {
            nsec3_zone_destroy(zone, zone->nsec.nsec3);
        }
    }
}

/******************************************************************************
 *
 * NSEC3 - queries
 *
 *****************************************************************************/

/**
 * This sets the flags of each NSEC3PARAM of the zone
 *
 */

void
nsec3_set_nsec3param_flags(zdb_zone *zone, u8 flags)
{
    if(zdb_zone_is_nsec3(zone))
    {
        zdb_packed_ttlrdata* rr_sll = zdb_record_find(&zone->apex->resource_record_set, TYPE_NSEC3PARAM);

        while(rr_sll != NULL)
        {
            rr_sll->rdata_start[1] = flags;
            rr_sll = rr_sll->next;
        }
    }
}

/**
 * This sets the flags of each NSEC3PARAM of the zone to 1
 * This should be called before modifying an NSEC3 zone.
 * Note that NSEC3PARAM signature are not affected : the signed version has
 * alsways the flags set to 0
 *
 * If an NSEC3PARAM RR is present at the apex of a zone with a Flags
 * field value of zero, then there MUST be an NSEC3 RR using the same
 * hash algorithm, iterations, and salt parameters present at every
 * hashed owner name in the zone.  That is, the zone MUST contain a
 * complete set of NSEC3 RRs with the same hash algorithm, iterations,
 * and salt parameters.
 */

void
nsec3_edit_zone_start(zdb_zone *zone)
{
    zone->apex->flags |= ZDB_RR_LABEL_DNSSEC_EDIT;

    nsec3_set_nsec3param_flags(zone, 1);
}

/**
 * This sets the flags of each NSEC3PARAM of the zone to 0
 * This should be called after modifying an NSEC3 zone.
 *
 */

void
nsec3_edit_zone_end(zdb_zone *zone)
{
    nsec3_set_nsec3param_flags(zone, 0);

    zone->apex->flags &= ~ZDB_RR_LABEL_DNSSEC_EDIT;
}

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
dnssec_label_zlabel_match(const void *label, const dictionary_node *node)
{
    zdb_rr_label* rr_label = (zdb_rr_label*) node;
    return dnslabel_equals(rr_label->name, label);
}

const zdb_rr_label*
nsec3_get_closest_provable_encloser(const zdb_rr_label *apex, const_dnslabel_vector_reference sections, s32 *sections_topp)
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
        u8* label = sections[index];
        hashcode hash = hash_dnslabel(label);

        rr_label = (zdb_rr_label*) dictionary_find(&rr_label->sub, hash, label, dnssec_label_zlabel_match);

        if(rr_label == NULL)
        {
            index++;
            break;
        }

        if(rr_label->nsec.dnssec != NULL)
        {
            provable = rr_label;
            *sections_topp = index;
        }

        index--;
    }

    return provable;
}

void
nsec3_closest_encloser_proof(
                        const zdb_zone *zone,
                        const dnsname_vector *qname, s32 apex_index,
                        const nsec3_zone_item **encloser_nsec3p,
                        const nsec3_zone_item **closest_provable_encloser_nsec3p,
                        const nsec3_zone_item **wild_closest_provable_encloser_nsec3p
                        )
{
    u8 closest_provable_encloser[MAX_DOMAIN_LENGTH];
    u8 encloser[MAX_DOMAIN_LENGTH];
    u8 digest[64 + 1];
    digest[0] = 20;

    const_dnslabel_vector_reference qname_sections = qname->labels;
    s32 closest_encloser_index_limit = qname->size - apex_index + 1; /* not "+1'" because it starts at the apex */

    nsec3_zone* n3 = zone->nsec.nsec3;
    
#ifdef DEBUG
    if((n3 == NULL) || (n3->items == NULL))
    {
        log_err("zone %{dnsname} has invalid NSEC3 data");
        return;
    }
#endif
    
    if(closest_encloser_index_limit > 0)
    {
        const zdb_rr_label* closest_provable_encloser_label = nsec3_get_closest_provable_encloser(zone->apex, qname_sections, &closest_encloser_index_limit);

        //log_debug("closest_provable_encloser_label: %{dnslabel}: %{digest32h}", closest_provable_encloser_label->name, closest_provable_encloser_label->nsec.nsec3->self->digest);
        //log_debug("*.closest_provable_encloser_label: %{dnslabel}: %{digest32h}", closest_provable_encloser_label->name, closest_provable_encloser_label->nsec.nsec3->star->digest);

        /*
         * Convert from closest_encloser_label_bottom to name.size into a dnslabel
         */

        /* Get ZONE NSEC3PARAM */
        u16 iterations = nsec3_zone_get_iterations(n3);
        u8 salt_len = NSEC3_ZONE_SALT_LEN(n3);
        u8* salt = NSEC3_ZONE_SALT(n3);

        nsec3_hash_function* digestname = nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3));

        /** @note log_* cannot be used here */

        if(encloser_nsec3p != NULL)
        {
            yassert((closest_provable_encloser_label != NULL) && (closest_encloser_index_limit > 0));

            nsec3_zone_item* encloser_nsec3;
            dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit - 1, encloser);
            digestname(encloser, dnsname_len(encloser), salt, salt_len, iterations, &digest[1], FALSE);
            //OSDEBUG("nsec3_closest_encloser_proof: next digest %{dnsname}: %{digest32h}", encloser, encloser_nsec3->digest);
            encloser_nsec3 = nsec3_zone_item_find(n3, digest);
            *encloser_nsec3p = encloser_nsec3;
            //OSDEBUG("nsec3_closest_encloser_proof: next encloser %{dnsname}: %{digest32h}", encloser, encloser_nsec3->digest);
        }

        if(closest_provable_encloser_nsec3p != NULL)
        {
            dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit  , closest_provable_encloser);

            nsec3_zone_item* closest_provable_encloser_nsec3;
            if((closest_provable_encloser_nsec3 = closest_provable_encloser_label->nsec.nsec3->self) == NULL)
            {
                digestname(closest_provable_encloser, dnsname_len(closest_provable_encloser), salt, salt_len, iterations, &digest[1], FALSE);
                closest_provable_encloser_nsec3 = nsec3_avl_find(&n3->items, digest);

                nsec3_add_owner(closest_provable_encloser_nsec3, closest_provable_encloser_label);
                closest_provable_encloser_label->nsec.nsec3->self = closest_provable_encloser_nsec3; /* @TODO check multiples */
            }
            *closest_provable_encloser_nsec3p = closest_provable_encloser_nsec3;
            //OSDEBUG("nsec3_closest_encloser_proof: closest_provable_encloser %{dnsname}: %{digest32h}",closest_provable_encloser,closest_provable_encloser_nsec3->digest);
        }

        if(wild_closest_provable_encloser_nsec3p != NULL)
        {
            if(closest_provable_encloser_nsec3p == NULL)
            {
                dnsname_vector_sub_to_dnsname(qname, closest_encloser_index_limit  , closest_provable_encloser);
            }

            nsec3_zone_item* wild_closest_provable_encloser_nsec3;

            if((wild_closest_provable_encloser_nsec3 = closest_provable_encloser_label->nsec.nsec3->star) == NULL)
            {
                digestname(closest_provable_encloser, dnsname_len(closest_provable_encloser), salt, salt_len, iterations, &digest[1], TRUE);
                wild_closest_provable_encloser_nsec3 = nsec3_avl_find_interval_start(&n3->items, digest);

                nsec3_add_star(wild_closest_provable_encloser_nsec3, closest_provable_encloser_label);
                closest_provable_encloser_label->nsec.nsec3->star = wild_closest_provable_encloser_nsec3; /* @TODO check multiples */
            }

            *wild_closest_provable_encloser_nsec3p = wild_closest_provable_encloser_nsec3;
            //OSDEBUG("nsec3_closest_encloser_proof: *.closest_provable_encloser *.%{dnsname}: %{digest32h}",closest_provable_encloser,wild_closest_provable_encloser_nsec3->digest);
        }
    }
    else
    {
        *encloser_nsec3p = zone->apex->nsec.nsec3->self;
        *closest_provable_encloser_nsec3p = zone->apex->nsec.nsec3->self;
        *wild_closest_provable_encloser_nsec3p = zone->apex->nsec.nsec3->self;
    }
}

void
nsec3_check_item_dump_label(zdb_rr_label *label)
{
    log_debug("%{dnslabel} %04x", label->name, label->flags);

    int n3i = 0;
    
    nsec3_label_extension *n3le = label->nsec.nsec3;
    
    while(n3le != NULL)
    {
        log_debug("NSEC3PARAM #%i", n3i);

        if(n3le->self != NULL)
        {
            log_debug("\tself: %{digest32h}", n3le->self->digest);
        }
        if(n3le->star != NULL)
        {
            log_debug("\tstar: %{digest32h}", n3le->star->digest);
        }

        n3i++;

        n3le = n3le->next;
    }
}

bool
nsec3_check_item(nsec3_zone_item *item, u32 param_index_base)
{
    yassert(item != NULL);

    u16 n = nsec3_owner_count(item);

    for(u16 i = 0; i < n; i++)
    {
        zdb_rr_label *label = nsec3_owner_get(item, i);

        yassert(label != NULL && label->nsec.nsec3 != NULL);

        nsec3_label_extension *n3le = label->nsec.nsec3;

        u32 param_index = param_index_base;
        while(param_index > 0)
        {
            yassert(n3le != NULL);



            n3le = n3le->next;

            param_index--;
        }

        yassert(n3le != NULL);



        yassert(n3le->self == item);
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
            log_debug("nsec3_check: %{digest32h} (#self=%d/#star=%d) failing %{dnsname} expected %{digest32h}", item->digest, item->rc, item->sc, label->name, n3le->star->digest);
        }

        if(n3le->self == NULL)
        {
            log_debug("nsec3_check: %{digest32h} (#self=%d/#star=%d) failing %{dnsname}: no self", item->digest, item->rc, item->sc, label->name);
        }

        yassert(n3le->star == item);

        yassert(n3le->self != NULL);
    }

    return TRUE;
}

bool
nsec3_check(zdb_zone *zone)
{
    log_debug("nesc3_check: %{dnsname}", zone->origin);
    
    const nsec3_zone *n3 = zone->nsec.nsec3;

    if(n3 == NULL)
    {
        log_debug("nesc3_check: %{dnsname} : no NSEC3", zone->origin);
        
        return TRUE;
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
    
    log_debug("nesc3_check: %{dnsname} : done", zone->origin);

    return TRUE;
}

void
nsec3_compute_digest_from_fqdn(const nsec3_zone *n3, const u8 *fqdn, u8 *digest)
{
    digest[0] = nsec3_hash_len(NSEC3_ZONE_ALGORITHM(n3));
    
    nsec3_hash_get_function(NSEC3_ZONE_ALGORITHM(n3))(
                                    fqdn,
                                    dnsname_len(fqdn),
                                    NSEC3_ZONE_SALT(n3),
                                    NSEC3_ZONE_SALT_LEN(n3),
                                    nsec3_zone_get_iterations(n3),
                                    &digest[1],
                                    FALSE);
}

/** @} */

/*----------------------------------------------------------------------------*/


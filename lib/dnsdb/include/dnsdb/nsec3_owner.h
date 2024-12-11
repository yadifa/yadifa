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
 * @defgroup nsec3 NSEC3 functions
 * @ingroup dnsdbdnssec
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnsdb/nsec3_types.h>
#include <dnsdb/nsec3_collection.h>

#ifdef __cplusplus
extern "C"
{
#endif

bool nsec3_item_is_owned_by_label(const nsec3_zone_item_t *item, const zdb_rr_label_t *owner);

/*
 * Adds an owner to the NSEC3 item
 */

void nsec3_item_add_owner(nsec3_zone_item_t *item, const zdb_rr_label_t *owner);

/*
 * Removes an owner from the NSEC3 item
 *
 * The entry MUST have been set before
 */

void nsec3_item_remove_owner(nsec3_zone_item_t *item, const zdb_rr_label_t *owner);

/*
 * Removes all owners from the NSEC3 item
 *
 * The entry MUST have been set before
 */

void                  nsec3_item_remove_all_owners(nsec3_zone_item_t *item);

zdb_rr_label_t       *nsec3_item_owner_get(const nsec3_zone_item_t *item, int32_t index);

static inline int32_t nsec3_owner_count(const nsec3_zone_item_t *item) { return item->rc; }

/*
 * Adds a "star" to the NSEC3 item
 */

void nsec3_item_add_star(nsec3_zone_item_t *item, const zdb_rr_label_t *owner);
/*
 * Removes a star from the NSEC3 item
 *
 * The entry MUST have been set before
 */

void nsec3_item_remove_star(nsec3_zone_item_t *item, const zdb_rr_label_t *owner);

/*
 * Removes all stars from the NSEC3 item
 *
 * The entry MUST have been set before
 */

void nsec3_item_remove_all_star(nsec3_zone_item_t *item);

/*
 * Moves all stars from one NSEC3 item to another.
 *
 * This is used when an NSEC3 item is removed: All its NSEC3 must be moved
 * to his predecessor.
 */

void                  nsec3_item_move_all_star_to_nsec3_item(nsec3_zone_item_t *src, nsec3_zone_item_t *dst);

zdb_rr_label_t       *nsec3_item_star_get(const nsec3_zone_item_t *item, int32_t n);

static inline int32_t nsec3_star_count(const nsec3_zone_item_t *item) { return item->sc; }

#ifdef __cplusplus
}
#endif

/** @} */

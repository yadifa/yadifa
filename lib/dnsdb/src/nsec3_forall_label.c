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

#include "dnsdb/dnsdb_config.h"
#include "dnscore/logger.h"
#include "dnscore/thread_pool.h"

#include "dnsdb/zdb_zone_lock.h"
#include "dnsdb/nsec3_forall_label.h"

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle_t *g_dnssec_logger;

#define USE_RECURSIVE_LOCKS 0

static bool nsec3_forall_label_recursive(nsec3_forall_label_s *ctx)
{
#if USE_RECURSIVE_LOCKS
    if(ctx->zone_lock_owner != 0)
    {
        zdb_zone_lock(ctx->zone, ctx->zone_lock_owner);
    }
#endif
    zdb_rr_label_t *label = nsec3_forall_label_get_label(ctx);

    bool            nsec3_covered = false;
    bool            skip_children = false;
    bool            optout = ctx->optout;
    bool            optin = !optout;

    if(!zdb_rr_label_is_apex(label))
    {
        if(ZDB_LABEL_ATDELEGATION(label))
        {
            skip_children = true;
            if(!optin)
            {
                nsec3_covered |= zdb_resource_record_sets_has_type(&label->resource_record_set, TYPE_DS);
            }
            nsec3_covered |= optin;
        }
        else if(ZDB_LABEL_UNDERDELEGATION(label))
        {
            skip_children = true;
        }
        else
        {
            nsec3_covered = !zdb_resource_record_sets_isempty(&label->resource_record_set);
        }
    }
    else
    {
        nsec3_covered = true;
    }

    if(!skip_children)
    {
        ++ctx->label_stack_level;

        dictionary_iterator_t iter;
        dictionary_iterator_init(&label->sub, &iter);

        while(dictionary_iterator_hasnext(&iter))
        {
            zdb_rr_label_t *sub_label = *(zdb_rr_label_t **)dictionary_iterator_next(&iter);
            /* if a child has been signed, then this one will be too */

            ctx->label_stack[ctx->label_stack_level] = sub_label;

            nsec3_covered |= nsec3_forall_label_recursive(ctx);
        }

        --ctx->label_stack_level;
    }

    if(optout && !nsec3_covered)
    {
#if USE_RECURSIVE_LOCKS
        if(ctx->zone_lock_owner != 0)
        {
            zdb_zone_unlock(ctx->zone, ctx->zone_lock_owner);
        }
#endif
        return false;
    }

    // build the fqdn of the label

    if(ctx->callback_need_fqdn)
    {
        uint8_t *p = ctx->name;

        for(int_fast32_t sp = ctx->label_stack_level; sp > 0; sp--)
        {
            uint8_t *q = ctx->label_stack[sp]->name;
            uint8_t  len = *q + 1;
            memcpy(p, q, len);
            p += len;
        }

        memcpy(p, ctx->zone->origin, ctx->origin_len);

        ctx->name_len = (p - ctx->name) + ctx->origin_len;
    }

    ctx->nsec3_covered = nsec3_covered;

    // the label is nsec3-covered, what happens to it now is the responsibility of the callback

    ctx->callback(ctx);

#if USE_RECURSIVE_LOCKS
    if(ctx->zone_lock_owner != 0)
    {
        zdb_zone_unlock(ctx->zone, ctx->zone_lock_owner);
    }
#endif

    return nsec3_covered;
}

/**
 * Iterates through all labels of the zone and their associated NSEC3 record.
 * Generate NSEC3 data for labels missing it (not linking them together)
 * Calls the callback with that information.
 *
 * Calls the callback once at the end.
 *
 * @param zone
 * @param chain_index
 * @param opt_out
 */

void nsec3_forall_label(zdb_zone_t *zone, int8_t chain_index, bool callback_need_fqdn, bool opt_out, bool can_ignore_signatures, uint8_t lock_owner, uint8_t reserved_owner, nsec3_forall_label_callback *callback, void *callback_args)
{
    yassert(((lock_owner == 0) && (reserved_owner == 0)) || ((lock_owner != 0) && (reserved_owner != 0)));
    nsec3_forall_label_s ctx;
    memset(&ctx, 0, sizeof(nsec3_forall_label_s));
    ctx.zone = zone;
    ctx.callback = callback;
    ctx.callback_args = callback_args;
    ctx.optout = opt_out;
    ctx.chain_index = chain_index;
    // no reader will ever try to read the chain in creation
    // (this is not enough)
    ctx.zone_lock_owner = lock_owner;
    ctx.zone_reserved_owner = reserved_owner;
    ctx.callback_need_fqdn = callback_need_fqdn;
    ctx.can_ignore_signatures = can_ignore_signatures;
    ctx.label_stack[0] = zone->apex;
    ctx.label_stack_level = 0;
    ctx.origin_len = dnsname_len(zone->origin);
    nsec3_forall_label_recursive(&ctx);
    ctx.last_call = true;
    ctx.callback(&ctx);
}

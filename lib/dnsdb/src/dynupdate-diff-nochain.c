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

/** @defgroup dnsdbupdate Dynamic update functions
 *  @ingroup dnsdb
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnsdb/dnsdb-config.h"

#include "dnsdb/dynupdate-diff.h"

static bool dnssec_chain_node_nochain_fqdn_is_covered(const zone_diff_fqdn *diff_fqdn)
{
    (void)diff_fqdn;
    return FALSE;
}

static bool dnssec_chain_node_nochain_fqdn_was_covered(const zone_diff_fqdn *diff_fqdn)
{
    (void)diff_fqdn;
    return FALSE;
}

static dnssec_chain_node_t dnssec_chain_node_nochain_new(const u8 *fqdn, dnssec_chain_head_t chain)
{
    (void)fqdn;
    (void)chain;
    return NULL;
}

static void dnssec_chain_node_nochain_delete(dnssec_chain_node_t node_)
{
    (void)node_;
}

static int dnssec_chain_node_nochain_compare(const void *a_, const void *b_)
{
    (void)a_;
    (void)b_;
    
    return 0;
}

static dnssec_chain_node_t dnssec_chain_node_nochain_prev(const dnssec_chain_node_t node_)
{
    (void)node_;
    return NULL;
}

static dnssec_chain_node_t dnssec_chain_node_nochain_next(const dnssec_chain_node_t node_)
{
    (void)node_;    
    return NULL;
}

static u8 dnssec_chain_node_nochain_state_get(const dnssec_chain_node_t node_)
{
    (void)node_;
    return 0;
}

static void dnssec_chain_node_nochain_state_set(dnssec_chain_node_t node_, u8 value)
{
    (void)node_;
    (void)value;
}

static void dnssec_chain_node_nochain_merge(dnssec_chain_node_t node_, dnssec_chain_node_t with_)
{
    (void)node_;
    (void)with_;
}

static void dnssec_chain_node_nochain_publish_log(dnssec_chain_node_t from_, dnssec_chain_node_t to_)
{
    (void)from_;
    (void)to_;
}

static void dnssec_chain_node_nochain_publish_add(dnssec_chain_head_t chain_, dnssec_chain_node_t from_, dnssec_chain_node_t to_, zone_diff *diff, ptr_vector *collection)
{
    (void)chain_;
    (void)from_;
    (void)to_;
    (void)diff;
    (void)collection;
}

static void dnssec_chain_node_nochain_publish_delete(dnssec_chain_head_t chain_, dnssec_chain_node_t from_, dnssec_chain_node_t to_, zone_diff *diff, ptr_vector *collection)
{
    (void)chain_;
    (void)from_;
    (void)to_;
    (void)diff;
    (void)collection;
}

static bool dnssec_chain_nochain_isempty(dnssec_chain_head_t chain_)
{
    (void)chain_;
    return TRUE;
}

static void dnssec_chain_nochain_finalize_delete_callback(ptr_node *node)
{
    (void)node;
}

static void dnssec_chain_node_nochain_format_writer_init(dnssec_chain_node_t node_, format_writer *outfw)
{
    (void)node_;
    (void)outfw;
}

static bool dnssec_chain_node_rrset_should_be_signed(const zone_diff_fqdn *diff_fqdn, const zone_diff_fqdn_rr_set *rr_set)
{
    (void)diff_fqdn;
    (void)rr_set;
    return FALSE;
}

static dnssec_chain_node_vtbl dnssec_chain_node_nochain_vtbl = 
{
    dnssec_chain_node_nochain_fqdn_is_covered,
    dnssec_chain_node_nochain_fqdn_was_covered,
    dnssec_chain_node_nochain_new,
    dnssec_chain_node_nochain_prev,
    dnssec_chain_node_nochain_merge,
    dnssec_chain_node_nochain_next,
    dnssec_chain_node_nochain_state_set,
    dnssec_chain_node_nochain_state_get,
    dnssec_chain_node_nochain_delete,
    dnssec_chain_node_nochain_publish_delete,
    dnssec_chain_node_nochain_publish_add,
    dnssec_chain_node_nochain_publish_log,
    dnssec_chain_node_nochain_compare,
    dnssec_chain_nochain_finalize_delete_callback,
    dnssec_chain_nochain_isempty,
    dnssec_chain_node_nochain_format_writer_init,
    dnssec_chain_node_rrset_should_be_signed,
    "nosec"
};

const dnssec_chain_node_vtbl *
dynupdate_nosec_chain_get_vtbl()
{
    return &dnssec_chain_node_nochain_vtbl;
}

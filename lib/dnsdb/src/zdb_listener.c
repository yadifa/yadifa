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
/** @defgroup
 *  @ingroup dnsdb
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

#include "dnsdb/zdb_listener.h"

#if HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3_item.h"
#endif

#define MODULE_MSG_HANDLE g_database_logger
extern logger_handle *g_database_logger;

/*
 *
 */

static zdb_listener* g_zdb_listener_sll = NULL;
static group_mutex_t g_zdb_listener_mtx = GROUP_MUTEX_INITIALIZER;

void
zdb_listener_chain(zdb_listener* listener)
{
    group_mutex_lock(&g_zdb_listener_mtx, GROUP_MUTEX_WRITE);
    listener->next = g_zdb_listener_sll;
    g_zdb_listener_sll = listener;
    group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_WRITE);
}

void
zdb_listener_unchain(zdb_listener* listener)
{
    group_mutex_lock(&g_zdb_listener_mtx, GROUP_MUTEX_WRITE);
    if(listener == g_zdb_listener_sll)
    {
        g_zdb_listener_sll = listener->next;
    }
    else
    {
        zdb_listener* item = g_zdb_listener_sll;

        while(item != NULL)
        {
            if(item->next == listener)
            {
                item->next = listener->next;
                break;
            }

            item = item->next;
        }
    }
    group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_WRITE);
}

void
zdb_listener_notify_remove_type(const zdb_zone *zone, const u8* dnsname, const zdb_rr_collection* recordssets, u16 type)
{
#ifdef DEBUG
    if(g_zdb_listener_sll != NULL)
    {
        log_debug2("zdb-listener: rr del: %{dnsname} IN %{dnstype}", dnsname, &type);
    }
#endif
    
    group_mutex_lock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
    
    zdb_listener* listener = g_zdb_listener_sll;

    while(listener != NULL)
    {
        listener->on_remove_record_type(listener, zone, dnsname, recordssets, type);
        listener = listener->next;
    }
    
    group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
}

void
zdb_listener_notify_add_record(const zdb_zone *zone, dnslabel_vector_reference labels, s32 top, u16 type, const zdb_ttlrdata *record)
{
#ifdef DEBUG
    if(g_zdb_listener_sll != NULL)
    {
        rdata_desc rdatadesc = {type, record->rdata_size, record->rdata_pointer};
        u8 dnsname[MAX_DOMAIN_LENGTH];
        dnslabel_vector_to_dnsname(labels, top, dnsname);
        log_debug2("zdb-listener: rr add: %{dnsname} %i IN %{typerdatadesc}", dnsname, record->ttl, &rdatadesc);
    }
#endif
    
    group_mutex_lock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
    
    zdb_listener* listener = g_zdb_listener_sll;
    
    while(listener != NULL)
    {
        listener->on_add_record(listener, zone, labels, top, type, record);
        listener = listener->next;
    }
    
    group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
}

void
zdb_listener_notify_remove_record(const zdb_zone *zone, const u8 *dnsname, u16 type, const zdb_ttlrdata *record)
{
#ifdef DEBUG
    if(g_zdb_listener_sll != NULL)
    {
        const rdata_desc rdatadesc = {type, record->rdata_size, record->rdata_pointer};
        log_debug2("zdb-listener: rr del: %{dnsname} %i IN %{typerdatadesc}", dnsname, record->ttl, &rdatadesc);
    }
#endif
    
    group_mutex_lock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
    
    zdb_listener* listener = g_zdb_listener_sll;

    while(listener != NULL)
    {
        listener->on_remove_record(listener, zone, dnsname, type, record);
        listener = listener->next;
    }
    
    group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
}

bool
zdb_listener_notify_has_changes(const zdb_zone *zone)
{
#ifdef DEBUG
    if(g_zdb_listener_sll != NULL)
    {
        log_debug2("zdb-listener: zone modified: %{dnsname}", zone->origin);
    }
#endif
    
    group_mutex_lock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
    
    zdb_listener* listener = g_zdb_listener_sll;

    while(listener != NULL)
    {
        if(listener->has_changes(listener, zone))
        {
            group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
            
            return TRUE;
        }
        listener = listener->next;
    }
    
    group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
    
    return FALSE;
}

#if ZDB_HAS_NSEC3_SUPPORT != 0

void
zdb_listener_notify_add_nsec3(const zdb_zone *zone, const nsec3_zone_item* nsec3_item, const nsec3_zone* n3, u32 ttl)
{
#ifdef DEBUG
    if(g_zdb_listener_sll != NULL)
    {
        DECLARE_NSEC3_ITEM_FORMAT_WRITER(nsec3_dump, zone->origin, n3, nsec3_item, ttl);
        log_debug2("zdb-listener: rr add: %w", &nsec3_dump);
    }
#endif
    
    group_mutex_lock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
    
    zdb_listener* listener = g_zdb_listener_sll;

    while(listener != NULL)
    {
        listener->on_add_nsec3(listener, zone, nsec3_item, n3, ttl);
        listener = listener->next;
    }
    
    group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
}

void
zdb_listener_notify_remove_nsec3(const zdb_zone *zone, const nsec3_zone_item* nsec3_item, const nsec3_zone* n3, u32 ttl)
{
#ifdef DEBUG
    if(g_zdb_listener_sll != NULL)
    {
        DECLARE_NSEC3_ITEM_FORMAT_WRITER(nsec3_dump, zone->origin, n3, nsec3_item, ttl);
        log_debug2("zdb-listener: rr del: %w", &nsec3_dump);
    }
#endif
    
    group_mutex_lock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
    
    zdb_listener* listener = g_zdb_listener_sll;

    while(listener != NULL)
    {
        listener->on_remove_nsec3(listener, zone, nsec3_item, n3, ttl);
        listener = listener->next;
    }
    
    group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
}

void
zdb_listener_notify_update_nsec3rrsig(const zdb_zone *zone, const zdb_packed_ttlrdata *removed_rrsig_sll, const zdb_packed_ttlrdata *added_rrsig_sll, const nsec3_zone_item* n3item)
{
#ifdef DEBUG
    if(g_zdb_listener_sll != NULL)
    {
        const zdb_packed_ttlrdata *sll;
        log_debug2("zdb-listener: nsec3 rrsig update: %{digest32h}.%{dnsname}.", n3item->digest, zone->origin);
        sll = removed_rrsig_sll;
        int i = 0;
        for(; sll != NULL; sll = sll->next, ++i)
        {
            rdata_desc rrsig_rdata_desc = {TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(sll), ZDB_PACKEDRECORD_PTR_RDATAPTR(sll)};
            log_debug2("zdb-listener: nsec3 rrsig del [%i]: %{digest32h}.%{dnsname}. %{typerdatadesc}", i, n3item->digest, zone->origin, &rrsig_rdata_desc);
        }
        sll = added_rrsig_sll;
        for(; sll != NULL; sll = sll->next, ++i)
        {
            rdata_desc rrsig_rdata_desc = {TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(sll), ZDB_PACKEDRECORD_PTR_RDATAPTR(sll)};
            log_debug2("zdb-listener: nsec3 rrsig add [%i]: %{digest32h}.%{dnsname}. %{typerdatadesc}", i, n3item->digest, zone->origin, &rrsig_rdata_desc);
        }
    }
#endif
    
    group_mutex_lock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
    
    zdb_listener* listener = g_zdb_listener_sll;

    while(listener != NULL)
    {
        listener->on_update_nsec3rrsig(listener, zone, removed_rrsig_sll, added_rrsig_sll, n3item);
        listener = listener->next;
    }
    
    group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
}

#endif

#if ZDB_HAS_DNSSEC_SUPPORT != 0

void
zdb_listener_notify_update_rrsig(const zdb_zone *zone, const zdb_packed_ttlrdata *removed_rrsig_sll, const zdb_packed_ttlrdata *added_rrsig_sll, const zdb_rr_label *label, const dnsname_stack *name)
{
#ifdef DEBUG
    if(g_zdb_listener_sll != NULL)
    {
        const zdb_packed_ttlrdata *sll;
        log_debug2("zdb-listener: rrsig update: %{dnsnamestack}", name);
        sll = removed_rrsig_sll;
        int i = 0;
        for(; sll != NULL; sll = sll->next, ++i)
        {
            rdata_desc rrsig_rdata_desc = {TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(sll), ZDB_PACKEDRECORD_PTR_RDATAPTR(sll)};
            log_debug2("zdb-listener: rrsig del [%i]: %{dnsnamestack} %{typerdatadesc}", i, name, &rrsig_rdata_desc);
        }
        sll = added_rrsig_sll;
        for(; sll != NULL; sll = sll->next, ++i)
        {
            rdata_desc rrsig_rdata_desc = {TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(sll), ZDB_PACKEDRECORD_PTR_RDATAPTR(sll)};
            log_debug2("zdb-listener: rrsig add [%i]: %{dnsnamestack} %{typerdatadesc}", i, name, &rrsig_rdata_desc);
        }
    }
#endif
    
    group_mutex_lock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
    
    zdb_listener* listener = g_zdb_listener_sll;

    while(listener != NULL)
    {
        listener->on_update_rrsig(listener, zone, removed_rrsig_sll, added_rrsig_sll, label, name);
        listener = listener->next;
    }
    
    group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
}

bool
zdb_listener_notify_enabled()
{
    group_mutex_lock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
    bool ret = g_zdb_listener_sll != NULL;
    group_mutex_unlock(&g_zdb_listener_mtx, GROUP_MUTEX_READ);
    return ret;
}

#endif

/** @} */

/*----------------------------------------------------------------------------*/


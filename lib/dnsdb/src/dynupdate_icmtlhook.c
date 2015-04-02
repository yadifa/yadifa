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
/** @defgroup dnsdbupdate Dynamic update functions
 *  @ingroup dnsdb
 *  @brief Generates "IXFR" (ICMTL) streams by registering as a listener to the changes in the database
 *
 *  Generates "IXFR" (ICMTL) streams by registering as a listener to the changes in the database
 *  This is part of the dynupdate/icmtl
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>

#include "dnsdb/zdb_utils.h"
#include <dnscore/logger.h>
#include <dnscore/format.h>

#include "dnsdb/zdb_listener.h"

#if ZDB_HAS_NSEC3_SUPPORT!=0
#include "dnsdb/nsec3_types.h"
#include "dnsdb/nsec3_item.h"
#include "dnsdb/nsec3_collection.h"
#endif

#include <dnscore/output_stream.h>

#include "dnsdb/zdb_record.h"

#include "dnsdb/dynupdate.h"

#include <dnscore/rfc.h>

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define DEBUG_ICMTL_RECORDS 0
#define USE_SET_FOR_OUTPUT 1

#include <dnscore/treeset.h>
#include <dnscore/bytearray_output_stream.h>

typedef struct icmtl_dnssec_listener icmtl_dnssec_listener;
typedef struct icmtl_dnssec_listener icmtl_zdb_listener;

struct icmtl_dnssec_listener
{
    /* matches the dnssec_listener struct */
    zdb_listener_on_remove_type_callback* on_remove_record_type;
    zdb_listener_on_add_record_callback* on_add_record;
    zdb_listener_on_remove_record_callback* on_remove_record;

#if ZDB_HAS_NSEC3_SUPPORT!=0
    zdb_listener_on_add_nsec3_callback* on_add_nsec3;
    zdb_listener_on_remove_nsec3_callback* on_remove_nsec3;
    zdb_listener_on_update_nsec3rrsig_callback* on_update_nsec3rrsig;
#endif
#if ZDB_HAS_DNSSEC_SUPPORT!=0
    zdb_listener_on_update_rrsig_callback* on_update_rrsig;
#endif

    zdb_listener* next;

    /* Proprietary */
    output_stream os_remove;
    output_stream os_add;
    output_stream rr_tmp_stream;
    treeset_tree rr_remove;
    treeset_tree rr_add;
    
    u8* origin;
    u32 origin_len;
};

static void
icmtl_push_record_to_remove(icmtl_zdb_listener* listener)
{
    u32 size = bytearray_output_stream_size(&listener->rr_tmp_stream);
    u8* buffer = bytearray_output_stream_buffer(&listener->rr_tmp_stream);
    if(!treeset_avl_find(&listener->rr_remove, buffer))
    {
        u8 *rr;
        ZALLOC_ARRAY_OR_DIE(u8*, rr, size, GENERIC_TAG);
        memcpy(rr, buffer, size);
        
#ifdef DEBUG
        log_debug1("icmtl: will remove %u@%p", size, rr);
#endif
        
        treeset_avl_insert(&listener->rr_remove, rr)->data = rr;
    }
    bytearray_output_stream_reset(&listener->rr_tmp_stream);
}

static void
icmtl_push_record_to_add(icmtl_zdb_listener* listener)
{
    // T049JP0TTR6PEQMFNFIK0OUIMD4F62PS
    u32 size = bytearray_output_stream_size(&listener->rr_tmp_stream);
    u8* buffer = bytearray_output_stream_buffer(&listener->rr_tmp_stream);
    if(!treeset_avl_find(&listener->rr_add, buffer))
    {
        u8 *rr;
        ZALLOC_ARRAY_OR_DIE(u8*, rr, size, GENERIC_TAG);
        memcpy(rr, buffer, size);
        
#ifdef DEBUG
        log_debug1("icmtl: will add %u@%p", size, rr);
#endif
        
        treeset_avl_insert(&listener->rr_add, rr)->data = rr;
    }
    bytearray_output_stream_reset(&listener->rr_tmp_stream);
}

static void
output_stream_write_wire(output_stream* os, dnslabel_vector_reference labels, s32 top, u16 type, zdb_ttlrdata* record)
{
    output_stream_write_dnslabel_vector(os, labels, top);
    output_stream_write_u16(os, type); /** @note NATIVETYPE */
    output_stream_write_u16(os, CLASS_IN); /** @note NATIVECLASS */
    output_stream_write_nu32(os, record->ttl);
    output_stream_write_nu16(os, record->rdata_size);
    output_stream_write(os, record->rdata_pointer, record->rdata_size);
}

static void
output_stream_write_wire_dnsname(output_stream* os, const u8 *dnsname, u16 type, zdb_ttlrdata* record)
{
    output_stream_write_dnsname(os, dnsname);
    output_stream_write_u16(os, type); /** @note NATIVETYPE */
    output_stream_write_u16(os, CLASS_IN); /** @note NATIVECLASS */
    output_stream_write_nu32(os, record->ttl);
    output_stream_write_nu16(os, record->rdata_size);
    output_stream_write(os, record->rdata_pointer, record->rdata_size);
}

static bool
icmtl_is_my_zone(icmtl_zdb_listener *listener, const zdb_zone *zone)
{
    bool ret = memcmp(zone->origin, listener->origin, listener->origin_len) == 0;
    return ret;
}

static void
icmtl_on_remove_record_type_callback(zdb_listener *base_listener, const zdb_zone *zone, const u8* dnsname, zdb_rr_collection* recordssets, u16 type)
{
    icmtl_zdb_listener *listener = (icmtl_zdb_listener*)base_listener;
    
    if(!icmtl_is_my_zone(listener, zone))
    {
        return;
    }
    
    if(type != TYPE_ANY)
    {
        zdb_packed_ttlrdata* rr_sll = zdb_record_find(recordssets, type);

        while(rr_sll != NULL)
        {           
            zdb_ttlrdata ttlrdata;
            ttlrdata.rdata_pointer = &rr_sll->rdata_start[0];
            ttlrdata.rdata_size = rr_sll->rdata_size;
            ttlrdata.ttl = rr_sll->ttl;
                        
            output_stream_write_wire_dnsname(&listener->os_remove,
                                     dnsname,
                                     type,
                                     &ttlrdata);

            rr_sll = rr_sll->next;
        }
    }
    else
    {
        btree_iterator iter;
        btree_iterator_init(*recordssets, &iter);
        while(btree_iterator_hasnext(&iter))
        {
            btree_node* node = btree_iterator_next_node(&iter);
            u16 node_type = (u16)node->hash;

            zdb_packed_ttlrdata* rr_sll = zdb_record_find(recordssets, node_type);

            while(rr_sll != NULL)
            {
                zdb_ttlrdata ttlrdata;
                ttlrdata.rdata_pointer = &rr_sll->rdata_start[0];
                ttlrdata.rdata_size = rr_sll->rdata_size;
                ttlrdata.ttl = rr_sll->ttl;
                
                output_stream_write_wire_dnsname(&listener->os_remove,
                                         dnsname,
                                         node_type,
                                         &ttlrdata);

                rr_sll = rr_sll->next;
            }
        }
    }
}

static void
icmtl_on_add_record_callback(zdb_listener *base_listener, const zdb_zone *zone, dnslabel_vector_reference labels, s32 top, u16 type, zdb_ttlrdata* record)
{
    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;

    if(!icmtl_is_my_zone(listener, zone))
    {
        return;
    }
    
#if DEBUG_ICMTL_RECORDS
    rdata_desc rdatadesc = {type, record->rdata_size, record->rdata_pointer};
    u8 label[MAX_DOMAIN_LENGTH + 1];
    dnslabel_vector_to_dnsname(labels, top, label);
    log_debug("incremental: add %{dnsname} %d IN %{typerdatadesc}", label, record->ttl, &rdatadesc);
#endif
    
    output_stream_write_wire(&listener->os_add,
                             labels, top,
                             type,
                             record);
}

static void
icmtl_on_remove_record_callback(zdb_listener *base_listener, const zdb_zone *zone, const u8* dnsname, u16 type, zdb_ttlrdata* record)
{
    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;

    if(!icmtl_is_my_zone(listener, zone))
    {
        return;
    }
    
#if DEBUG_ICMTL_RECORDS
    rdata_desc rdatadesc = {type, record->rdata_size, record->rdata_pointer};
    log_debug("incremental: del %{dnsname} %d IN %{typerdatadesc}", dnsname, record->ttl, &rdatadesc);
#endif
    
    output_stream_write_wire_dnsname(&listener->os_remove,
                             dnsname,
                             type,
                             record);
}

#if !USE_SET_FOR_OUTPUT

static void
output_stream_write_rrsig_list_wire(output_stream* os, u8* label, u32 label_len, u8* origin, u32 origin_len, zdb_packed_ttlrdata* sig_sll)
{
    while(sig_sll != NULL)
    {
        output_stream_write(os, label, label_len);
        output_stream_write(os, origin, origin_len);

        output_stream_write_u16(os, TYPE_RRSIG); /** @note NATIVETYPE */
        output_stream_write_u16(os, CLASS_IN); /** @note NATIVECLASS */
        output_stream_write_nu32(os, sig_sll->ttl);
        output_stream_write_nu16(os, sig_sll->rdata_size);
        output_stream_write(os, &sig_sll->rdata_start[0], sig_sll->rdata_size);

#if DEBUG_ICMTL_RECORDS
        rdata_desc rdatadesc = {TYPE_RRSIG, sig_sll->rdata_size, &sig_sll->rdata_start[0]};

        if(origin != NULL)
        {
            log_debug("incremental: %{dnslabel}%{dnsname} %d IN %{typerdatadesc}", label, origin, sig_sll->ttl, &rdatadesc);
        }
        else
        {
            log_debug("incremental: %{dnsname} %d IN %{typerdatadesc}", label, sig_sll->ttl, &rdatadesc);
        }
#endif
        
        sig_sll = sig_sll->next;
    }
}

#else

static void
output_stream_write_rrsig_wire(output_stream* os, u8* label, u32 label_len, u8* origin, u32 origin_len, zdb_packed_ttlrdata* sig_sll)
{
    if(sig_sll != NULL)
    {
        output_stream_write(os, label, label_len);
        output_stream_write(os, origin, origin_len);

        output_stream_write_u16(os, TYPE_RRSIG); /** @note NATIVETYPE */
        output_stream_write_u16(os, CLASS_IN); /** @note NATIVECLASS */
        output_stream_write_nu32(os, sig_sll->ttl);
        output_stream_write_nu16(os, sig_sll->rdata_size);
        output_stream_write(os, &sig_sll->rdata_start[0], sig_sll->rdata_size);

#if DEBUG_ICMTL_RECORDS
        rdata_desc rdatadesc = {TYPE_RRSIG, sig_sll->rdata_size, &sig_sll->rdata_start[0]};

        if(origin != NULL)
        {
            log_debug("incremental: %{dnslabel}%{dnsname} %d IN %{typerdatadesc}", label, origin, sig_sll->ttl, &rdatadesc);
        }
        else
        {
            log_debug("incremental: %{dnsname} %d IN %{typerdatadesc}", label, sig_sll->ttl, &rdatadesc);
        }
#endif
    }
}

#endif

#if ZDB_HAS_NSEC3_SUPPORT != 0

static void
icmtl_on_add_nsec3_callback(zdb_listener *base_listener, const zdb_zone *zone, nsec3_zone_item* nsec3_item, nsec3_zone* n3, u32 ttl)
{
#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: add NSEC3");
#endif

    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;

    if(!icmtl_is_my_zone(listener, zone))
    {
        return;
    }
    
#if USE_SET_FOR_OUTPUT
    nsec3_zone_item_to_output_stream(&listener->rr_tmp_stream,
                                     n3,
                                     nsec3_item,
                                     listener->origin,
                                     ttl);
    icmtl_push_record_to_add(listener);
#else    
    nsec3_zone_item_to_output_stream(&listener->os_add,
                                     n3,
                                     nsec3_item,
                                     listener->origin,
                                     ttl);
#endif
}

static void
icmtl_on_remove_nsec3_callback(zdb_listener *base_listener, const zdb_zone *zone, nsec3_zone_item* nsec3_item, nsec3_zone* n3, u32 ttl)
{
#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: del NSEC3");
#endif

    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;
   
    if(!icmtl_is_my_zone(listener, zone))
    {
        return;
    }
    
#if USE_SET_FOR_OUTPUT
    nsec3_zone_item_to_output_stream(&listener->rr_tmp_stream,
                                     n3,
                                     nsec3_item,
                                     listener->origin,
                                     ttl);
    icmtl_push_record_to_remove(listener);
#else  
    nsec3_zone_item_to_output_stream(&listener->os_remove,
                                     n3,
                                     nsec3_item,
                                     listener->origin,
                                     ttl);
#endif
}

static void
icmtl_on_update_nsec3rrsig_callback(zdb_listener *base_listener, const zdb_zone *zone, zdb_packed_ttlrdata* removed_rrsig_sll, zdb_packed_ttlrdata* added_rrsig_sll, nsec3_zone_item* item)
{
    u8 label[MAX_DOMAIN_LENGTH];

    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;

    if(!icmtl_is_my_zone(listener, zone))
    {
        return;
    }

    u32 label_len = nsec3_zone_item_get_label(item, label, sizeof (label));

#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: del RRSIG: (NSEC3)");
#endif
    
#if USE_SET_FOR_OUTPUT
    while(removed_rrsig_sll != NULL)
    {
        output_stream_write_rrsig_wire(&listener->rr_tmp_stream, label, label_len, listener->origin, listener->origin_len, removed_rrsig_sll);
        icmtl_push_record_to_remove(listener);
        removed_rrsig_sll = removed_rrsig_sll->next;
    }
#else
    output_stream_write_rrsig_list_wire(&listener->os_remove, label, label_len, listener->origin, listener->origin_len, removed_rrsig_sll);
#endif
    
    
    
#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: add RRSIG: (NSEC3)");
#endif
    
#if USE_SET_FOR_OUTPUT
    while(added_rrsig_sll != NULL)
    {
        output_stream_write_rrsig_wire(&listener->rr_tmp_stream, label, label_len, listener->origin, listener->origin_len, added_rrsig_sll);
        icmtl_push_record_to_add(listener);
        added_rrsig_sll = added_rrsig_sll->next;
    }
#else
    output_stream_write_rrsig_list_wire(&listener->os_add, label, label_len, listener->origin, listener->origin_len, added_rrsig_sll);
#endif
}

#endif

static void
icmtl_on_update_rrsig_callback(zdb_listener *base_listener, const zdb_zone *zone, zdb_packed_ttlrdata* removed_rrsig_sll, zdb_packed_ttlrdata* added_rrsig_sll, zdb_rr_label* label, dnsname_stack* name)
{
    u8 fqdn[MAX_DOMAIN_LENGTH];

    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;

    if(!icmtl_is_my_zone(listener, zone))
    {
        return;
    }
    
    u32 fqdn_len = dnsname_stack_to_dnsname(name, fqdn);

#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: del RRSIG:");
#endif
    
#if USE_SET_FOR_OUTPUT
    while(removed_rrsig_sll != NULL)
    {
        output_stream_write_rrsig_wire(&listener->rr_tmp_stream, fqdn, fqdn_len, NULL, 0, removed_rrsig_sll);
        icmtl_push_record_to_remove(listener);
        removed_rrsig_sll = removed_rrsig_sll->next;
    }
#else
    output_stream_write_rrsig_list_wire(&listener->os_remove, fqdn, fqdn_len, NULL, 0, removed_rrsig_sll);
#endif
    
#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: add RRSIG:");
#endif
    
#if USE_SET_FOR_OUTPUT
    while(added_rrsig_sll != NULL)
    {
        output_stream_write_rrsig_wire(&listener->rr_tmp_stream, fqdn, fqdn_len, NULL, 0, added_rrsig_sll);
        icmtl_push_record_to_add(listener);
        added_rrsig_sll = added_rrsig_sll->next;
    }
#else
    output_stream_write_rrsig_list_wire(&listener->os_add, fqdn, fqdn_len, NULL, 0, added_rrsig_sll);
#endif
}

static mutex_t icmtl_listener_mtx = MUTEX_INITIALIZER;
static treeset_tree icmtl_listener_set = TREESET_DNSNAME_EMPTY;

static struct icmtl_dnssec_listener icmtl_listener =
{
    icmtl_on_remove_record_type_callback,
    icmtl_on_add_record_callback,
    icmtl_on_remove_record_callback,
#if ZDB_HAS_NSEC3_SUPPORT != 0
    icmtl_on_add_nsec3_callback,
    icmtl_on_remove_nsec3_callback,
    icmtl_on_update_nsec3rrsig_callback,
#endif
#if ZDB_HAS_DNSSEC_SUPPORT != 0
    icmtl_on_update_rrsig_callback,
#endif
    NULL,
    {NULL,NULL},
    {NULL,NULL},
    {NULL,NULL},
    {NULL,NULL},
    {NULL,NULL},
    NULL,
    0
};

/*
 * Initializes and hook the spy that will build the icmtl
 */

static int dynupdate_icmtlhook_treeset_rr_wire_size(const u8 *wire)
{
    int fqdn_len = dnsname_len(wire);
    struct type_class_ttl_rdlen* tctr = (struct type_class_ttl_rdlen*)&wire[fqdn_len];
    return fqdn_len + 10 + ntohs(tctr->rdlen);
}

static int dynupdate_icmtlhook_treeset_rr_wire_compare(const void *node_a, const void *node_b)
{
    const u8 *rr_a = (const u8 *)node_a;
    const u8 *rr_b = (const u8 *)node_b;
    int rr_a_size = dynupdate_icmtlhook_treeset_rr_wire_size(rr_a);
    int rr_b_size = dynupdate_icmtlhook_treeset_rr_wire_size(rr_b);
    
    if(rr_a_size != rr_b_size)
    {
        return rr_a_size - rr_b_size;
    }
    
    int ret = memcmp(rr_a, rr_b, rr_a_size);
    
    return ret;
}

ya_result
dynupdate_icmtlhook_enable(u8* origin, output_stream* os_remove, output_stream* os_add)
{
    yassert(icmtl_listener.next == NULL);

#ifdef DEBUG
    log_debug("incremental: enabled %{dnsname} for updates", origin);
#endif
    
    icmtl_dnssec_listener* listener;
    
    mutex_lock(&icmtl_listener_mtx);
    treeset_node *node = treeset_avl_insert(&icmtl_listener_set, origin);
    if(node->data != NULL)
    {
        mutex_unlock(&icmtl_listener_mtx);
        return ERROR; // already set
    }
        
    ZALLOC_OR_DIE(icmtl_dnssec_listener*, listener, icmtl_dnssec_listener, GENERIC_TAG);
    memcpy(listener, &icmtl_listener, sizeof(icmtl_dnssec_listener));

    listener->os_remove.data = os_remove->data;
    listener->os_remove.vtbl = os_remove->vtbl;
    listener->os_add.data = os_add->data;
    listener->os_add.vtbl = os_add->vtbl;
    bytearray_output_stream_init_ex(&listener->rr_tmp_stream, NULL, 2048, BYTEARRAY_DYNAMIC);
    listener->rr_remove.root = NULL;
    listener->rr_remove.compare = dynupdate_icmtlhook_treeset_rr_wire_compare;
    listener->rr_add.root = NULL;
    listener->rr_add.compare = dynupdate_icmtlhook_treeset_rr_wire_compare;
    listener->origin = origin;
    listener->origin_len = dnsname_len(origin);
    
    zdb_listener_chain((zdb_listener*)listener);
    
    node->data = listener;
    
    mutex_unlock(&icmtl_listener_mtx);

    return SUCCESS;
}

ya_result
dynupdate_icmtlhook_disable(u8 *origin)
{
    icmtl_dnssec_listener* listener = NULL;
    
    mutex_lock(&icmtl_listener_mtx);
    treeset_node *node = treeset_avl_find(&icmtl_listener_set, origin);
    if(node != NULL)
    {
        listener = (icmtl_dnssec_listener*)node->data;
        treeset_avl_delete(&icmtl_listener_set, origin);
    }
    mutex_unlock(&icmtl_listener_mtx);
    
    if(listener == NULL)
    {
        return ERROR;
    }
    
    zdb_listener_unchain((zdb_listener*)listener);
    output_stream_close(&listener->rr_tmp_stream);
    
    treeset_avl_iterator iter;
    
    treeset_avl_iterator_init(&listener->rr_remove, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *node = treeset_avl_iterator_next_node(&iter);
        int size = dynupdate_icmtlhook_treeset_rr_wire_size(node->key);
        
#ifdef DEBUG
        log_debug1("icmtl: removing %u@%p", size, node->key);
#endif
        
        output_stream_write(&listener->os_remove, node->key, size);
        ZFREE_ARRAY(node->key, size);
    }
    
    treeset_avl_destroy(&listener->rr_remove);
    
    treeset_avl_iterator_init(&listener->rr_add, &iter);
    
    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *node = treeset_avl_iterator_next_node(&iter);
        int size = dynupdate_icmtlhook_treeset_rr_wire_size(node->key);
        
#ifdef DEBUG
        log_debug1("icmtl: adding %u@%p", size, node->key);
#endif
        
        output_stream_write(&listener->os_add, node->key, size);
        ZFREE_ARRAY(node->key, size);
    }
    
    treeset_avl_destroy(&listener->rr_add);
    
    ZFREE(listener, icmtl_dnssec_listener);
    
#ifdef DEBUG
    log_debug("incremental: disabled %{dnsname} for updates", icmtl_listener.origin);
#endif
    
    return SUCCESS;
}

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/

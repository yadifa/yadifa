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
    u8* origin;
    u32 origin_len;
};

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

static void
icmtl_on_remove_record_type_callback(zdb_listener* base_listener, const u8* dnsname, zdb_rr_collection* recordssets, u16 type)
{
    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;

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
icmtl_on_add_record_callback(zdb_listener* base_listener, dnslabel_vector_reference labels, s32 top, u16 type, zdb_ttlrdata* record)
{
    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;

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
icmtl_on_remove_record_callback(zdb_listener* base_listener, const u8* dnsname, u16 type, zdb_ttlrdata* record)
{
    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;

#if DEBUG_ICMTL_RECORDS
    rdata_desc rdatadesc = {type, record->rdata_size, record->rdata_pointer};
    log_debug("incremental: del %{dnsname} %d IN %{typerdatadesc}", dnsname, record->ttl, &rdatadesc);
#endif
    
    output_stream_write_wire_dnsname(&listener->os_remove,
                             dnsname,
                             type,
                             record);
}

static void
output_stream_write_rrsig_wire(output_stream* os, u8* label, u32 label_len, u8* origin, u32 origin_len, zdb_packed_ttlrdata* sig_sll)
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

#if ZDB_HAS_NSEC3_SUPPORT!=0

static void
icmtl_on_add_nsec3_callback(zdb_listener* base_listener, nsec3_zone_item* nsec3_item, nsec3_zone* n3, u32 ttl)
{
#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: add NSEC3");
#endif

    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;

    nsec3_zone_item_to_output_stream(&listener->os_add,
                                     n3,
                                     nsec3_item,
                                     listener->origin,
                                     ttl);
}

static void
icmtl_on_remove_nsec3_callback(zdb_listener* base_listener, nsec3_zone_item* nsec3_item, nsec3_zone* n3, u32 ttl)
{
#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: del NSEC3");
#endif

    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;
   
    nsec3_zone_item_to_output_stream(&listener->os_remove,
                                     n3,
                                     nsec3_item,
                                     listener->origin,
                                     ttl);
}

static void
icmtl_on_update_nsec3rrsig_callback(zdb_listener* base_listener, zdb_packed_ttlrdata* removed_rrsig_sll, zdb_packed_ttlrdata* added_rrsig_sll, nsec3_zone_item* item)
{
    u8 label[MAX_DOMAIN_LENGTH];

    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;

    u32 origin_len = dnsname_len(listener->origin);

    u32 label_len = nsec3_zone_item_get_label(item, label, sizeof (label));

#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: del RRSIG: (NSEC3)");
#endif
    
    output_stream_write_rrsig_wire(&listener->os_remove, label, label_len, listener->origin, origin_len, removed_rrsig_sll);
    
#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: add RRSIG: (NSEC3)");
#endif
    
    output_stream_write_rrsig_wire(&listener->os_add, label, label_len, listener->origin, origin_len, added_rrsig_sll);
}

#endif

static void
icmtl_on_update_rrsig_callback(zdb_listener* base_listener, zdb_packed_ttlrdata* removed_rrsig_sll, zdb_packed_ttlrdata* added_rrsig_sll, zdb_rr_label* label, dnsname_stack* name)
{
    u8 fqdn[MAX_DOMAIN_LENGTH];

    icmtl_zdb_listener* listener = (icmtl_zdb_listener*)base_listener;

    u32 fqdn_len = dnsname_stack_to_dnsname(name, fqdn);

#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: del RRSIG:");
#endif
    
    output_stream_write_rrsig_wire(&listener->os_remove, fqdn, fqdn_len, NULL, 0, removed_rrsig_sll);
    
#if DEBUG_ICMTL_RECORDS
    log_debug("incremental: add RRSIG:");
#endif
    
    output_stream_write_rrsig_wire(&listener->os_add, fqdn, fqdn_len, NULL, 0, added_rrsig_sll);
}

static struct icmtl_dnssec_listener icmtl_listener ={
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
    NULL,
    0
};

/*
 * Initializes and hook the spy that will build the icmtl
 */

ya_result
dynupdate_icmtlhook_enable(u8* origin, output_stream* os_remove, output_stream* os_add)
{
    yassert(icmtl_listener.next == NULL);

#ifdef DEBUG
    log_debug("incremental: enabled %{dnsname} for updates", origin);
#endif

    icmtl_listener.os_remove.data = os_remove->data;
    icmtl_listener.os_remove.vtbl = os_remove->vtbl;
    icmtl_listener.os_add.data = os_add->data;
    icmtl_listener.os_add.vtbl = os_add->vtbl;
    icmtl_listener.origin = origin;
    icmtl_listener.origin_len = dnsname_len(origin);
    
    zdb_listener_chain((zdb_listener*) & icmtl_listener);

    return SUCCESS;
}

ya_result
dynupdate_icmtlhook_disable()
{
    zdb_listener_unchain((zdb_listener*) & icmtl_listener);

#ifdef DEBUG
    log_debug("incremental: disabled %{dnsname} for updates", icmtl_listener.origin);
#endif
    
    return SUCCESS;
}

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/

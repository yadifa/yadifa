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
/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#include <dnscore/dnsname.h>

#include "dnsdb/dictionary.h"
#include "dnsdb/nsec3_types.h"
#include "dnsdb/nsec3_item.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_process.h"

static ya_result
zdb_zone_process_label_children(zdb_zone_process_label_callback_parms *parms)
{
    ya_result return_code = SUCCESS;
    
    dictionary_iterator iter;
    dictionary_iterator_init(&parms->rr_label->sub, &iter);
    while(dictionary_iterator_hasnext(&iter))
    {
        zdb_rr_label** sub_labelp = (zdb_rr_label**)dictionary_iterator_next(&iter);

        dnsname_stack_push_label(&parms->fqdn_stack, &(*sub_labelp)->name[0]);
        
        parms->rr_label = *sub_labelp;
        
        return_code = parms->cb(parms);
            
        if((FAIL(return_code) || return_code == ZDB_ZONE_PROCESS_STOP))
        {
            break;
        }

        return_code = zdb_zone_process_label_children(parms);
        
        if((FAIL(return_code) || return_code == ZDB_ZONE_PROCESS_STOP))
        {
            break;
        }
        
        dnsname_stack_pop_label(&parms->fqdn_stack);
    }
    
    return return_code;
}

ya_result
zdb_zone_process_all_labels_from_zone(zdb_zone *zone, zdb_zone_process_label_callback *cb, void *args)
{
    ya_result return_code = ERROR;
    
    if(zone != NULL && zone->apex != NULL)
    {
        zdb_zone_process_label_callback_parms parms;
        parms.cb = cb;
        parms.zone = zone;
        parms.args = args;
        
        if(ISOK(dnsname_to_dnsname_stack(zone->origin, &parms.fqdn_stack)))
        {   
            parms.rr_label = zone->apex;
            
            return_code = cb(&parms);
            
            if(!(FAIL(return_code) || return_code == ZDB_ZONE_PROCESS_STOP))
            {
                zdb_zone_process_label_children(&parms);
            }
        }
    }
    
    return return_code;
}

static ya_result
zdb_zone_process_nsec3_records(zdb_zone_process_rrset_callback_parms *parms)
{
    const zdb_rr_label *real_label = parms->rr_label;
    
    nsec3_zone *n3 = parms->zone->nsec.nsec3;
    nsec3_label_extension *n3ext = parms->rr_label->nsec.nsec3;
    zdb_rr_label *nsec3_label;
    zdb_packed_ttlrdata *nsec3_packed_ttl_rdata;
    const zdb_packed_ttlrdata *out_nsec3_rrsig;
    
    u8 zdb_packed_ttlrdata_buffer[sizeof(zdb_packed_ttlrdata) - 1 + TMP_NSEC3_TTLRDATA_SIZE];
    u8 zdb_rr_label_buffer[sizeof(zdb_rr_label) - 1 + MAX_DOMAIN_LENGTH];
    
    nsec3_label = (zdb_rr_label*)zdb_rr_label_buffer;
    nsec3_packed_ttl_rdata = (zdb_packed_ttlrdata*)zdb_packed_ttlrdata_buffer;
    
    ZEROMEMORY(zdb_rr_label_buffer, sizeof(zdb_rr_label) - 1);
    
    nsec3_label->nsec = real_label->nsec;
    nsec3_label->flags = real_label->flags | ZDB_RR_LABEL_VIRTUAL;
    
    ya_result return_code = SUCCESS;
    
    while((n3 != NULL) && (n3ext != NULL))
    {
        out_nsec3_rrsig = NULL;
        
        nsec3_zone_item_to_zdb_packed_ttlrdata(
                n3,
                n3ext->self,
                parms->zone->origin,
                &nsec3_label->name[0], /* dnsname */
                parms->zone->min_ttl,
                nsec3_packed_ttl_rdata,
                TMP_NSEC3_TTLRDATA_SIZE,
                &out_nsec3_rrsig);
        
        parms->rrset = nsec3_packed_ttl_rdata;
        return_code = parms->cb(parms);
        
        if((FAIL(return_code) || return_code != ZDB_ZONE_PROCESS_CONTINUE))
        {
            break;
        }
        
        parms->rrset = out_nsec3_rrsig;
        return_code = parms->cb(parms);
        
        if((FAIL(return_code) || return_code != ZDB_ZONE_PROCESS_CONTINUE))
        {
            break;
        }
        
        n3ext = n3ext->next;
        n3 = n3->next;
    }
    
    parms->rr_label = real_label;
    
    return return_code;
}

static ya_result
zdb_zone_process_rrset_records(zdb_zone_process_rrset_callback_parms *parms)
{
    ya_result return_code = SUCCESS;
    
    btree_iterator iter;
    btree_iterator_init(parms->rr_label->resource_record_set, &iter);

    while(btree_iterator_hasnext(&iter))
    {
        btree_node* rr_node = btree_iterator_next_node(&iter);
        parms->rrset = (zdb_packed_ttlrdata*)rr_node->data;
        parms->record_type = (u16)rr_node->hash;
        
        return_code = parms->cb(parms);
        
        if(return_code != ZDB_ZONE_PROCESS_CONTINUE)
        {
            break;
        }
    }
    
    if(return_code == ZDB_ZONE_PROCESS_CONTINUE)
    {
        if(zdb_zone_is_nsec3(parms->zone))
        {
            return_code = zdb_zone_process_nsec3_records(parms);
        }
    }
    
    return return_code;
}

static ya_result
zdb_zone_process_rrset_children(zdb_zone_process_rrset_callback_parms *parms)
{
    ya_result return_code = SUCCESS;
    
    dictionary_iterator iter;
    dictionary_iterator_init(&parms->rr_label->sub, &iter);
    while(dictionary_iterator_hasnext(&iter))
    {
        zdb_rr_label** sub_labelp = (zdb_rr_label**)dictionary_iterator_next(&iter);

        dnsname_stack_push_label(&parms->fqdn_stack, &(*sub_labelp)->name[0]);
        
        parms->rr_label = *sub_labelp;
        
        return_code = zdb_zone_process_rrset_records(parms);
            
        if((FAIL(return_code) || return_code != ZDB_ZONE_PROCESS_CONTINUE))
        {
            break;
        }

        return_code = zdb_zone_process_rrset_children(parms);
        
        if((FAIL(return_code) || return_code != ZDB_ZONE_PROCESS_CONTINUE))
        {
            break;
        }
        
        dnsname_stack_pop_label(&parms->fqdn_stack);
    }
    
    return return_code;
}

ya_result
zdb_zone_process_all_rrsets_from_all_labels_from_zone(zdb_zone *zone, zdb_zone_process_rrset_callback *cb, void *args)
{
    ya_result return_code = ERROR;
        
    if(zone != NULL && zone->apex != NULL)
    {
        zdb_zone_process_rrset_callback_parms parms;
        parms.cb = cb;
        parms.zone = zone;
        parms.args = args;
        
        if(ISOK(dnsname_to_dnsname_stack(zone->origin, &parms.fqdn_stack)))
        {
            parms.rr_label = zone->apex;
            
            return_code = zdb_zone_process_rrset_records(&parms);
            
            if(!(FAIL(return_code) || return_code != ZDB_ZONE_PROCESS_CONTINUE))
            {
                return_code = zdb_zone_process_rrset_children(&parms);
            }
        }
    }
    
    return return_code;
}


/**
  @}
 */

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
/** @defgroup 
 *  @ingroup dnsdb
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _ZDB_LISTENER_H
#define	_ZDB_LISTENER_H

#include <dnsdb/zdb_types.h>
#include <dnscore/dnsname.h>

#if ZDB_HAS_NSEC3_SUPPORT!=0
#include <dnsdb/nsec3_types.h>
#endif

#ifdef	__cplusplus
extern "C"
{
#endif

typedef struct dnssec_listener dnssec_listener;
typedef struct dnssec_listener zdb_listener;

typedef void zdb_listener_on_remove_type_callback(zdb_listener *listener, const u8 *dnsname, zdb_rr_collection *recordssets, u16 type);
typedef void zdb_listener_on_add_record_callback(zdb_listener *listener, dnslabel_vector_reference labels, s32 top, u16 type, zdb_ttlrdata *record);
typedef void zdb_listener_on_remove_record_callback(zdb_listener *listener, const u8 *dnsname, u16 type, zdb_ttlrdata *record);
#if ZDB_HAS_NSEC3_SUPPORT!=0
typedef void zdb_listener_on_add_nsec3_callback(zdb_listener *listener, nsec3_zone_item *nsec3_item, nsec3_zone *n3, u32 ttl);
typedef void zdb_listener_on_remove_nsec3_callback(zdb_listener *listener, nsec3_zone_item *nsec3_item, nsec3_zone *n3, u32 ttl);
typedef void zdb_listener_on_update_nsec3rrsig_callback(zdb_listener *listener, zdb_packed_ttlrdata *removed_rrsig_sll, zdb_packed_ttlrdata *added_rrsig_sll, nsec3_zone_item *item);
#endif
#if ZDB_HAS_DNSSEC_SUPPORT!=0
typedef void zdb_listener_on_update_rrsig_callback(zdb_listener *listener, zdb_packed_ttlrdata *removed_rrsig_sll, zdb_packed_ttlrdata *added_rrsig_sll, zdb_rr_label *label, dnsname_stack *name);
#endif

struct dnssec_listener
{
    zdb_listener_on_remove_type_callback *on_remove_record_type;
    zdb_listener_on_add_record_callback *on_add_record;
    zdb_listener_on_remove_record_callback *on_remove_record;
#if ZDB_HAS_NSEC3_SUPPORT!=0
    zdb_listener_on_add_nsec3_callback *on_add_nsec3;
    zdb_listener_on_remove_nsec3_callback *on_remove_nsec3;
    zdb_listener_on_update_nsec3rrsig_callback *on_update_nsec3rrsig;
#endif
#if ZDB_HAS_DNSSEC_SUPPORT!=0
    zdb_listener_on_update_rrsig_callback *on_update_rrsig;
#endif
    zdb_listener *next;
};

void zdb_listener_chain(zdb_listener *listener);
void zdb_listener_unchain(zdb_listener *listener);

void zdb_listener_notify_remove_type(const u8 *dnsname, zdb_rr_collection *recordssets, u16 type);
void zdb_listener_notify_add_record(dnslabel_vector_reference labels, s32 top, u16 type, zdb_ttlrdata *record);
void zdb_listener_notify_remove_record(const u8 *dnsname, u16 type, zdb_ttlrdata *record);
#if ZDB_HAS_NSEC3_SUPPORT!=0
void zdb_listener_notify_add_nsec3(nsec3_zone_item *nsec3_item, nsec3_zone *n3, u32 ttl);
void zdb_listener_notify_remove_nsec3(nsec3_zone_item *nsec3_item, nsec3_zone *n3, u32 ttl);
void zdb_listener_notify_update_nsec3rrsig(zdb_packed_ttlrdata *removed_rrsig_sll, zdb_packed_ttlrdata *added_rrsig_sll, nsec3_zone_item *item);
#endif
#if ZDB_HAS_DNSSEC_SUPPORT!=0
void zdb_listener_notify_update_rrsig(zdb_packed_ttlrdata *removed_rrsig_sll, zdb_packed_ttlrdata *added_rrsig_sll, zdb_rr_label *label, dnsname_stack *name);
#endif

bool zdb_listener_notify_enabled();

#ifdef	__cplusplus
}
#endif

#endif	/* _zdb_listener_H */

/** @} */

/*----------------------------------------------------------------------------*/


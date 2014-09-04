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
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>

#include "dnsdb/zdb_listener.h"

/*
 *
 */

static zdb_listener* first = NULL;

void
zdb_listener_chain(zdb_listener* listener)
{
    listener->next = first;
    first = listener;
}

void
zdb_listener_unchain(zdb_listener* listener)
{
    if(listener == first)
    {
        first = listener->next;
    }
    else
    {
        zdb_listener* item = first;

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
}

void
zdb_listener_notify_remove_type(const u8* dnsname, zdb_rr_collection* recordssets, u16 type)
{
    zdb_listener* item = first;

    while(item != NULL)
    {
        item->on_remove_record_type(item, dnsname, recordssets, type);
        item = item->next;
    }
}

void
zdb_listener_notify_add_record(dnslabel_vector_reference labels, s32 top, u16 type, zdb_ttlrdata* record)
{
    zdb_listener* item = first;

    while(item != NULL)
    {
        item->on_add_record(item, labels, top, type, record);
        item = item->next;
    }
}

void
zdb_listener_notify_remove_record(const u8 *dnsname, u16 type, zdb_ttlrdata* record)
{
    zdb_listener* item = first;

    while(item != NULL)
    {
        item->on_remove_record(item, dnsname, type, record);
        item = item->next;
    }
}

#if ZDB_HAS_NSEC3_SUPPORT != 0

void
zdb_listener_notify_add_nsec3(nsec3_zone_item* nsec3_item, nsec3_zone* n3, u32 ttl)
{
    zdb_listener* item = first;

    while(item != NULL)
    {
        item->on_add_nsec3(item, nsec3_item, n3, ttl);
        item = item->next;
    }
}

void
zdb_listener_notify_remove_nsec3(nsec3_zone_item* nsec3_item, nsec3_zone* n3, u32 ttl)
{
    zdb_listener* item = first;

    while(item != NULL)
    {
        item->on_remove_nsec3(item, nsec3_item, n3, ttl);
        item = item->next;
    }
}

void
zdb_listener_notify_update_nsec3rrsig(zdb_packed_ttlrdata* removed_rrsig_sll, zdb_packed_ttlrdata* added_rrsig_sll, nsec3_zone_item* n3item)
{
    zdb_listener* item = first;

    while(item != NULL)
    {
        item->on_update_nsec3rrsig(item, removed_rrsig_sll, added_rrsig_sll, n3item);
        item = item->next;
    }
}

#endif

#if ZDB_HAS_DNSSEC_SUPPORT != 0

void
zdb_listener_notify_update_rrsig(zdb_packed_ttlrdata* removed_rrsig_sll, zdb_packed_ttlrdata* added_rrsig_sll, zdb_rr_label* label, dnsname_stack* name)
{
    zdb_listener* item = first;

    while(item != NULL)
    {
        item->on_update_rrsig(item, removed_rrsig_sll, added_rrsig_sll, label, name);
        item = item->next;
    }
}

bool
zdb_listener_notify_enabled()
{
    return first != NULL;
}

#endif

/** @} */

/*----------------------------------------------------------------------------*/


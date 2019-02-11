/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2019, EURid vzw. All rights reserved.
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
/** @defgroup rrsig RRSIG functions
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
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#include <dnscore/sys_types.h>
#include <dnscore/logger.h>
#include <dnscore/dnsname.h>
#include <dnscore/random.h>
#include <dnscore/dnskey.h>
#include <dnscore/thread_pool.h>
#include <dnscore/dnskey-signature.h>

#include "dnsdb/dnsrdata.h"
#include "dnsdb/dnssec.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/rr_canonize.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb-zone-dnssec.h"
#include "dnsdb/zdb-packed-ttlrdata.h"

#include "dnsdb/nsec.h"


#define MODULE_MSG_HANDLE g_dnssec_logger

/*
 * 0 : no dump
 * 1 : dump
 * 2 : more dump ...
 */

#define RRSIG_DUMP 0 // 5

#define RRSIG_AUTOMATIC_ALARM_REFRESH 0

/**
 * 
 * Returns the first RRSIG record that applies to the give type.
 * 
 * @param label        the label where to do the search
 * @param covered_type the type covered by the RRSIG
 * 
 * @return the first RRSIG covering the type or NULL
 */

zdb_packed_ttlrdata*
rrsig_find_first(const zdb_rr_label* label, u16 type)
{
    zdb_packed_ttlrdata* rrsig = zdb_record_find(&label->resource_record_set, TYPE_RRSIG);

    while(rrsig != NULL)
    {
        if(RRSIG_TYPE_COVERED(rrsig) == type)
        {
            return rrsig;
        }

        rrsig = rrsig->next;
    }

    return NULL;
}

/**
 * 
 * Returns the next RRSIG record that applies to the give type.
 * 
 * @param rrsig        the previous RRSIG covering the type
 * @param covered_type the type covered by the RRSIG
 * 
 * @return  covered_type the next RRSIG covering the type or NULL
 */
 
zdb_packed_ttlrdata*
rrsig_find_next(const zdb_packed_ttlrdata* rrsig, u16 type)
{
    rrsig = rrsig->next;
    
    while(rrsig != NULL)
    {
        if(RRSIG_TYPE_COVERED(rrsig) == type)
        {
            return (zdb_packed_ttlrdata*)rrsig;
        }

        rrsig = rrsig->next;
    }

    return NULL;
}

/**
 * 
 * Removes all the RRSIG covering the type
 * 
 * @param dname         the fqdn of the label
 * @param label         the label
 * @param covered_type  the type covered by the RRSIG
 */

void
rrsig_delete(const zdb_zone *zone, const u8 *dname, zdb_rr_label* label, u16 type)
{
    /*
     * zdb_packed_ttlrdata** prev = zdb_record_findp(&label->resource_record_set, TYPE_RRSIG);
     *
     * =>
     *
     */

    zdb_packed_ttlrdata** first = (zdb_packed_ttlrdata**)btree_findp(&label->resource_record_set, TYPE_RRSIG);

    if(first == NULL)
    {
        return;
    }

    zdb_packed_ttlrdata** prev = first;

    zdb_packed_ttlrdata* rrsig = *prev;

    while(rrsig != NULL)
    {
        if(RRSIG_TYPE_COVERED(rrsig) == type)
        {
#if ZDB_CHANGE_FEEDBACK_SUPPORT
            if(zdb_listener_notify_enabled())
            {
                zdb_ttlrdata unpacked_ttlrdata;

                unpacked_ttlrdata.ttl = rrsig->ttl;
                unpacked_ttlrdata.rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig);
                unpacked_ttlrdata.rdata_pointer = ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig);

                zdb_listener_notify_remove_record(zone, dname, TYPE_RRSIG, &unpacked_ttlrdata);
            }
#endif   
            /* */
                
            if(prev == first && rrsig->next == NULL) /* Only one RRSIG: proper removal and delete */
            {
                zdb_record_delete(&label->resource_record_set, TYPE_RRSIG);
                break;
            }
            else
            {
                *prev = rrsig->next; /* More than one RRSIG: unchain and delete */

                ZDB_RECORD_ZFREE(rrsig);                
                rrsig = *prev;
                
                if(rrsig == NULL)
                {
                    break;
                }
            }
        }

        prev = &(*prev)->next;
        rrsig = rrsig->next;
    }
}

void
rrsig_delete_by_tag(const zdb_zone *zone, u16 tag)
{
    /*
     * zdb_packed_ttlrdata** prev = zdb_record_findp(&label->resource_record_set, TYPE_RRSIG);
     *
     * =>
     *
     */

    zdb_packed_ttlrdata** first = (zdb_packed_ttlrdata**)btree_findp(&zone->apex->resource_record_set, TYPE_RRSIG);

    if(first == NULL)
    {
        return;
    }

    zdb_packed_ttlrdata** prev = first;

    zdb_packed_ttlrdata* rrsig = *prev;

    while(rrsig != NULL)
    {
        if(RRSIG_KEY_TAG(rrsig) == tag)
        {
#if ZDB_CHANGE_FEEDBACK_SUPPORT
            if(zdb_listener_notify_enabled())
            {
                zdb_ttlrdata unpacked_ttlrdata;

                unpacked_ttlrdata.ttl = rrsig->ttl;
                unpacked_ttlrdata.rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig);
                unpacked_ttlrdata.rdata_pointer = ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig);

                zdb_listener_notify_remove_record(zone, zone->origin, TYPE_RRSIG, &unpacked_ttlrdata);
            }
#endif
            /* */
                
            if(prev == first && rrsig->next == NULL) /* Only one RRSIG: proper removal and delete */
            {
                zdb_record_delete(&zone->apex->resource_record_set, TYPE_RRSIG);
                break;
            }
            else
            {
                *prev = rrsig->next; /* More than one RRSIG: unchain and delete */

                ZDB_RECORD_ZFREE(rrsig);                
                rrsig = *prev;
                
                if(rrsig == NULL)
                {
                    break;
                }
            }
        }

        prev = &(*prev)->next;
        rrsig = rrsig->next;
    }
}

bool
rrsig_should_label_be_signed(zdb_zone *zone, const u8 *fqdn, zdb_rr_label *rr_label)
{
    (void)zone;
    (void)fqdn;
    if(LABEL_HAS_RECORDS(rr_label))
    {
        if(ZDB_LABEL_ISAPEX(rr_label))
        {
            return TRUE;
        }
        else
        {
            if(ZDB_LABEL_ATDELEGATION(rr_label))
            {
                return TRUE;
            }
            else
            {
                // not under a delegation: sign

                if(!ZDB_LABEL_UNDERDELEGATION(rr_label))
                {
                    return TRUE;
                }
                else
                {
                    return FALSE;
                }
            }
        }
    }
    else
    {
        return FALSE;
    }
}

/** @} */

/*----------------------------------------------------------------------------*/


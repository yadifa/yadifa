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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to iterate through the labels of a zone
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <dnsdb/avl.h>

#include "dnscore/logger.h"
#include "dnsdb/zdb_types.h"
#include "dnsdb/nsec3_item.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_zone_label_iterator_ex.h"
#include "dnsdb/zdb_zone_label_iterator.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

/**
 * @brief Initializes a zone label iterator
 *
 * Initializes a zone label iterator (iterates zdb_rr_label)
 *
 * @param[in] zone The zone to explore
 * @param[in] iter a pointer to the iterator to initialize
 *
 */


#define ZLI_DEBUG 0

void
zdb_zone_label_iterator_ex_init(zdb_zone_label_iterator_ex* iter, const zdb_zone* zone)
{
    memset(iter, 0, sizeof(zdb_zone_label_iterator_ex));

    //iter->mode = ZDB_ZONE_LABEL_ITERATOR_ZONE_RECORDS; // set by the memset
    iter->min_ttl = zone->min_ttl;
    iter->zone = zone;
    iter->n3 = zone->nsec.nsec3;
    iter->pool = &iter->pool_buffer[0];
    //iter->nsec3_owner = NULL;

    //iter->nsec3_label.next = NULL;
    //iter->nsec3_label.sub.count = 0;

    iter->nsec3_label.resource_record_set = &iter->nsec3_label_nsec3;

    iter->nsec3_label_nsec3.hash = TYPE_NSEC3;
    iter->nsec3_label_rrsig.hash = TYPE_RRSIG;

    zdb_zone_label_iterator_init(&iter->iter.label_iter, zone);
}

/**
 * @brief Checks if there is still data available from an iterator
 *
 * Checks if there is still data available from an iterator
 *
 * @param[in] iter a pointer to the iterator
 *
 * @return TRUE if data is available, FALSE otherwise.
 *
 */

bool
zdb_zone_label_iterator_ex_hasnext(zdb_zone_label_iterator_ex* iter)
{
    bool ret;
    switch(iter->mode)
    {
        case ZDB_ZONE_LABEL_ITERATOR_ZONE_RECORDS:
        {
            ret = zdb_zone_label_iterator_hasnext(&iter->iter.label_iter);
            if(ret)
            {
                return ret;
            }

            // end of the labels, prepare the NSEC3 if any

            if(iter->n3 == NULL)
            {
                return FALSE;
            }

            nsec3_iterator_init(&iter->n3->items, &iter->iter.nsec3_iter);

            iter->mode = ZDB_ZONE_LABEL_ITERATOR_NSEC3_CHAIN; // falls through on purpose

            FALLTHROUGH // fallthrough
        }
        case ZDB_ZONE_LABEL_ITERATOR_NSEC3_CHAIN:
        {
            ret = nsec3_iterator_hasnext(&iter->iter.nsec3_iter);

            if(ret)
            {
                iter->pool = &iter->pool_buffer[0];
                // get the record and convert it to an zdb_rr_label

                nsec3_node *nsec3_node = nsec3_iterator_next_node(&iter->iter.nsec3_iter);

                nsec3_zone_item_to_new_zdb_packed_ttlrdata_parm nsec3_parms =
                    {
                        iter->n3,
                        nsec3_node,         /// note:  in an iterator, if used properly, the returned node cannot be NULL
                        iter->zone->origin,
                        &iter->pool,
                        iter->min_ttl
                    };

                nsec3_zone_item_to_new_zdb_packed_ttlrdata(
                    &nsec3_parms,
                    &iter->nsec3_owner,
                    (zdb_packed_ttlrdata**)&iter->nsec3_label_nsec3.data,
                    (const zdb_packed_ttlrdata**)&iter->nsec3_label_rrsig.data);

                // craft an zdb_rr_label that suits our needs

                if(iter->nsec3_label_rrsig.data != NULL)
                {
                    iter->nsec3_label_nsec3.balance = -1;
                    iter->nsec3_label_nsec3.children.lr.left = &iter->nsec3_label_rrsig;
                }
                else
                {
                    iter->nsec3_label_nsec3.balance = 0;
                    iter->nsec3_label_nsec3.children.lr.left = NULL;
                }

                return TRUE;
            }
            else
            {
                iter->mode = ZDB_ZONE_LABEL_ITERATOR_END_OF_ITERATION;

                FALLTHROUGH // fallthrough
            }
        }
    }

    return FALSE;
}

/**
 * @brief Copies the full name of the next label returned by the "next" call.
 *
 * Copies the full name of the next label returned by the "next" call.
 *
 * @param[in] iter a pointer to the iterator
 * @param[in] buffer256 a pointer to a buffer that will hold the full dns name
 *
 * @return the size of the dns name
 *
 */

u32
zdb_zone_label_iterator_ex_nextname_to_cstr(zdb_zone_label_iterator_ex* iter, char* buffer256)
{
    u32 ret;

    switch(iter->mode)
    {
        case ZDB_ZONE_LABEL_ITERATOR_ZONE_RECORDS:
        {
            ret = zdb_zone_label_iterator_nextname_to_cstr(&iter->iter.label_iter, buffer256);
            return ret;
        }
        case ZDB_ZONE_LABEL_ITERATOR_NSEC3_CHAIN:
        {
            ret = dnsname_to_cstr(buffer256, iter->nsec3_owner);
            return ret;
        }
    }
    
    return 0;
}

u32
zdb_zone_label_iterator_ex_nextname(zdb_zone_label_iterator_ex* iter, u8* buffer256)
{ /* TOP-DOWN stack */
    u32 ret;

    switch(iter->mode)
    {
        case ZDB_ZONE_LABEL_ITERATOR_ZONE_RECORDS:
        {
            ret = zdb_zone_label_iterator_nextname(&iter->iter.label_iter, buffer256);
            return ret;
        }
        case ZDB_ZONE_LABEL_ITERATOR_NSEC3_CHAIN:
        {
            ret = dnsname_copy(buffer256, iter->nsec3_owner);
            return ret;
        }
    }

    return 0;
}

/**
 * @brief Returns the next data available from an iterator
 *
 * Returns the next data available from an iterator
 *
 * @param[in] iter a pointer to the iterator
 *
 * @return a pointer to the next label
 *
 */

zdb_rr_label*
zdb_zone_label_iterator_ex_next(zdb_zone_label_iterator_ex* iter)
{
    zdb_rr_label *ret;

    switch(iter->mode)
    {
        case ZDB_ZONE_LABEL_ITERATOR_ZONE_RECORDS:
        {
            ret = zdb_zone_label_iterator_next(&iter->iter.label_iter);
            return ret;
        }
        case ZDB_ZONE_LABEL_ITERATOR_NSEC3_CHAIN:
        {
            ret = &iter->nsec3_label;

            return ret;
        }
    }

    return NULL;
}

/** @} */

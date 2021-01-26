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
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <dnscore/dnsname.h>

#include "dnsdb/dictionary.h"

#if HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3_types.h"
#include "dnsdb/nsec3_item.h"
#endif

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
    yassert(zdb_zone_islocked(zone));
    
    ya_result ret;
    
    if(zone != NULL)
    {
        if(zone->apex != NULL)
        {
            zdb_zone_process_label_callback_parms parms;
            parms.cb = cb;
            parms.zone = zone;
            parms.args = args;

            if(ISOK(ret = dnsname_to_dnsname_stack(zone->origin, &parms.fqdn_stack)))
            {
                parms.rr_label = zone->apex;

                ret = cb(&parms);

                if(!(FAIL(ret) || ret == ZDB_ZONE_PROCESS_STOP))
                {
                    zdb_zone_process_label_children(&parms);
                }
            }
        }
        else
        {
            ret = INVALID_STATE_ERROR;
        }
    }
    else
    {
        ret = UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    return ret;
}

/**
  @}
 */

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
/** @defgroup server
 *  @ingroup yadifad
 *  @brief server
 *
 *  Handles queries made in the CH class (ie: version.*)
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#include "server-config.h"
#include "config.h"

#include <dnscore/file_output_stream.h>
#include <dnscore/logger.h>
#include <dnscore/rfc.h>
#include <dnscore/ctrl-rfc.h>
#include <dnscore/threaded_queue.h>

#include <dnscore/format.h>
#include <dnscore/packet_writer.h>
#include <dnscore/packet_reader.h>

#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb-zone-find.h>

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "confs.h"
#include "signals.h"
#include "acl.h"



#include "database-service.h"

#ifdef HAS_CTRL
extern logger_handle* g_server_logger;

extern zone_data_set database_zone_desc;



ya_result
ctrl_zone_freeze(zone_desc_s *zone_desc, bool dolock)
{
    ya_result return_value;
    
    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }
    
    return_value = MAKE_DNSMSG_ERROR(RCODE_SERVFAIL);
   
    if(zdb_zone_exists_from_dnsname(g_config->database, zone_desc->origin))
    {
        return_value = SUCCESS;
        
#ifdef DEBUG
        log_debug("ctrl: zone freeze for %{dnsname}", zone_desc->origin);
#endif
        
        database_zone_freeze(zone_desc->origin);
    }
    
    /* add the zone to the database */

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }
    
    return return_value;
}

ya_result
ctrl_zone_freeze_all()
{
    zone_set_lock(&database_zone_desc);
    
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_avl_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->value;
        
        ctrl_zone_freeze(zone_desc, FALSE);
    }

    zone_set_unlock(&database_zone_desc);
    
    return SUCCESS;
}

ya_result
ctrl_zone_unfreeze(zone_desc_s *zone_desc, bool dolock)
{
    ya_result return_value;
    
    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }
    
    return_value = MAKE_DNSMSG_ERROR(RCODE_SERVFAIL);

    if(zdb_zone_exists_from_dnsname(g_config->database, zone_desc->origin))
    {
        return_value = SUCCESS;
        
#ifdef DEBUG
        log_debug("ctrl: zone unfreeze for %{dnsname}", zone_desc->origin);
#endif
        
        database_zone_unfreeze(zone_desc->origin);
    }
    
    /* add the zone to the database */

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }
    
    return return_value;
}

ya_result
ctrl_zone_unfreeze_all()
{
    zone_set_lock(&database_zone_desc);
    
    ptr_set_avl_iterator iter;
    ptr_set_avl_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_avl_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->value;
        
        ctrl_zone_unfreeze(zone_desc, FALSE);
    }

    zone_set_unlock(&database_zone_desc);
    
    return SUCCESS;
}


#endif

/** @} */

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
#include <dnscore/acl.h>



#include "database-service.h"
#include "notify.h"

#ifdef HAS_CTRL
extern logger_handle* g_server_logger;

extern zone_data_set database_zone_desc;



ya_result
ctrl_zone_freeze(zone_desc_s *zone_desc, bool dolock)
{
    ya_result ret;
    
    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }

    ret = MAKE_DNSMSG_ERROR(RCODE_SERVFAIL);
   
    if(zdb_zone_exists_from_dnsname(g_config->database, zone_origin(zone_desc)))
    {
        ret = SUCCESS;
        
#if DEBUG
        log_debug("ctrl: zone freeze for %{dnsname}", zone_origin(zone_desc));
#endif
        
        database_zone_freeze(zone_origin(zone_desc));
    }
    
    /* add the zone to the database */

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }
    
    return ret;
}

ya_result
ctrl_zone_unfreeze(zone_desc_s *zone_desc, bool dolock)
{
    ya_result ret;
    
    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }

    ret = MAKE_DNSMSG_ERROR(RCODE_SERVFAIL);

    if(zdb_zone_exists_from_dnsname(g_config->database, zone_origin(zone_desc)))
    {
        ret = SUCCESS;
        
#if DEBUG
        log_debug("ctrl: zone unfreeze for %{dnsname}", zone_origin(zone_desc));
#endif
        
        database_zone_unfreeze(zone_origin(zone_desc));
    }
    
    /* add the zone to the database */

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }
    
    return ret;
}

ya_result
ctrl_zone_sync(zone_desc_s *zone_desc, bool dolock, bool clear_journal)
{
    ya_result ret;
    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }

    ret = MAKE_DNSMSG_ERROR(RCODE_SERVFAIL);

    if(zdb_zone_exists_from_dnsname(g_config->database, zone_origin(zone_desc)))
    {
        if(zone_desc->loaded_zone != NULL)
        {
            ret = SUCCESS;
            database_zone_store_ex(zone_origin(zone_desc), clear_journal);
        }
        else
        {
            ret = MAKE_DNSMSG_ERROR(RCODE_SERVFAIL);
        }
    }

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }

    return ret;
}

ya_result
ctrl_zone_sync_doclean(zone_desc_s *zone_desc, bool dolock)
{
    ya_result ret = ctrl_zone_sync(zone_desc, dolock, TRUE);
    return ret;
}

ya_result
ctrl_zone_sync_noclean(zone_desc_s *zone_desc, bool dolock)
{
    ya_result ret = ctrl_zone_sync(zone_desc, dolock, FALSE);
    return ret;
}

ya_result
ctrl_zone_notify(zone_desc_s *zone_desc, bool dolock)
{
    ya_result ret;
    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }

    ret = MAKE_DNSMSG_ERROR(RCODE_REFUSED);

    if(zdb_zone_exists_from_dnsname(g_config->database, zone_origin(zone_desc)))
    {
        if(zone_desc->loaded_zone != NULL)
        {
            ret = SUCCESS;
            notify_slaves(zone_origin(zone_desc));
        }
        else
        {
            ret = MAKE_DNSMSG_ERROR(RCODE_SERVFAIL);
        }
    }

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }

    return ret;
}

ya_result
ctrl_zone_reload(zone_desc_s *zone_desc, bool dolock)
{
    ya_result ret;
    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }

    ret = MAKE_DNSMSG_ERROR(RCODE_SERVFAIL);

    if(zdb_zone_exists_from_dnsname(g_config->database, zone_origin(zone_desc)))
    {
        ret = SUCCESS;
        database_zone_load(zone_origin(zone_desc));
    }

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }

    return ret;
}


#endif

/** @} */

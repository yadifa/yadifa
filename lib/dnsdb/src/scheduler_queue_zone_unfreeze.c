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
* DOCUMENTATION */
/** @defgroup dnsdbscheduler Scheduled tasks of the database
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

#include <unistd.h>
#include <limits.h>

#include <dnscore/logger.h>

#include <dnscore/scheduler.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_zone.h"

#define MODULE_MSG_HANDLE g_database_logger

extern logger_handle* g_database_logger;

/*
 *
 */

static ya_result
scheduler_queue_zone_unfreeze_callback(void* data_)
{
    zdb_zone *zone = (zdb_zone*)data_;

    log_info("zone unfreeze: %{dnsname} done", zone->origin);

    return SCHEDULER_TASK_FINISHED; /* Mark the end of the writer job */
}

static void*
scheduler_queue_zone_unfreeze_thread(void* data_)
{
    zdb_zone *zone = (zdb_zone*)data_;
    
    log_info("zone unfreeze: unfreezing %{dnsname}", zone->origin);
    
    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_UNFREEZE);

    zone->apex->flags &= ~ZDB_RR_APEX_LABEL_FROZEN;
    
    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_UNFREEZE);

    log_info("zone unfreeze: %{dnsname} unfrozen", zone->origin);
    
    scheduler_schedule_task(scheduler_queue_zone_unfreeze_callback, zone);

    /* WARNING: From this point forward, 'zwp' cannot be used anymore */

    return NULL;
}

ya_result
scheduler_queue_zone_unfreeze(zdb_zone* zone)
{
    log_info("zone unfreeze: queueing %{dnsname}", zone->origin);

    scheduler_schedule_thread(NULL, scheduler_queue_zone_unfreeze_thread, zone, "scheduler_queue_zone_unfreeze");

    return SUCCESS;
}
/** @} */

/*----------------------------------------------------------------------------*/


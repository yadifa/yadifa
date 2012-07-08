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

#include <dnscore/logger.h>

#include <dnscore/scheduler.h>
#include "dnsdb/dnssec.h"
#include "dnsdb/nsec3.h"
#include "dnsdb/zdb_zone_write.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

/*
 *
 */

static ya_result
scheduler_queue_nsec3_update_callback(void* data_)
{
    zdb_zone *zone = (zdb_zone*)data_;

    log_info("nsec3: update %{dnsname} done", zone->origin);

    nsec3_edit_zone_end(zone);

    return SCHEDULER_TASK_FINISHED; /* Mark the end of the writer job */
}

static void*
scheduler_queue_nsec3_update_thread(void* data_)
{
    zdb_zone *zone = (zdb_zone*)data_;

    log_info("nsec3: update %{dnsname} NSEC3", zone->origin);

    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_NSEC3_UPDATER);
    nsec3_update_zone(zone);
    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_NSEC3_UPDATER);

    log_info("nsec3: update %{dnsname} RRSIG", zone->origin);

    //zdb_zone_lock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER|0x80);
    zdb_update_zone_signatures(zone, FALSE);
    //zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER|0x80);

    //zdb_zone_write_text_file(zone, "eu-zone.txt.signed", FALSE);

    scheduler_schedule_task(scheduler_queue_nsec3_update_callback, zone);

    /* WARNING: From this point forward, 'zone' cannot be used anymore */
    
    return NULL;
}

static ya_result
scheduler_queue_nsec3_update_init(void* data_)
{
    zdb_zone *zone = (zdb_zone*)data_;

    /*
     * This MUST be done ST because the flags are tested
     */

    log_info("nsec3: update %{dnsname} init", zone->origin);

    nsec3_edit_zone_start(zone);

    return SCHEDULER_TASK_PROGRESS;
}

void
scheduler_queue_nsec3_update(zdb_zone* zone)
{
    log_info("nsec3: queueing %{dnsname} update", zone->origin);

    scheduler_schedule_thread(scheduler_queue_nsec3_update_init, scheduler_queue_nsec3_update_thread, zone, "scheduler_queue_nsec3_update");
}

/** @} */

/*----------------------------------------------------------------------------*/


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
#include "dnsdb/zdb_types.h"
#include <dnscore/scheduler.h>
#include "dnsdb/rrsig.h"

/*
 * 
 */

#define MODULE_MSG_HANDLE g_database_logger
extern logger_handle* g_database_logger;

typedef struct schedule_rrsig_update schedule_rrsig_update;
struct schedule_rrsig_update
{
    zdb_packed_ttlrdata* removed_rrsig_sll;
    zdb_packed_ttlrdata* added_rrsig_sll;
    zdb_rr_label*        label;
    zdb_zone*            zone;
    dnsname_stack*       name;
    void*                context;
};

static ya_result
scheduler_task_rrsig_update_commit_task(void* data_)
{
    schedule_rrsig_update *rrsig_update = (schedule_rrsig_update*)data_;

#if DNSSEC_DEBUGLEVEL >= 1
    log_debug("scheduler_task_rrsig_update_commit_task: %{dnsnamestack}", rrsig_update->name);
#endif

    zdb_zone_lock(rrsig_update->zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
    rrsig_update_commit(rrsig_update->removed_rrsig_sll, rrsig_update->added_rrsig_sll, rrsig_update->label, rrsig_update->zone, rrsig_update->name);
    zdb_zone_unlock(rrsig_update->zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER);

#if DNSSEC_DEBUGLEVEL >= 1
    log_debug("scheduler_task_rrsig_update_commit_task: %{dnsnamestack} done", rrsig_update->name);
#endif

    if(rrsig_update->context != NULL)
    {
        free(rrsig_update->context);
    }

    free(rrsig_update);

    return SCHEDULER_TASK_PROGRESS;
}

void
scheduler_task_rrsig_update_commit(zdb_packed_ttlrdata* removed_rrsig_sll, zdb_packed_ttlrdata* added_rrsig_sll, zdb_rr_label* label, zdb_zone* zone, dnsname_stack* name, void* context_to_destroy)
{
    schedule_rrsig_update *rrsig_update;
    
    MALLOC_OR_DIE(schedule_rrsig_update*, rrsig_update, sizeof(schedule_rrsig_update), GENERIC_TAG);

    rrsig_update->removed_rrsig_sll = removed_rrsig_sll;    /* owned (to destroy) */
    rrsig_update->added_rrsig_sll   = added_rrsig_sll;      /* owned (to destroy) */
    rrsig_update->label             = label;                /* owned by the zone */
    rrsig_update->zone              = zone;                 /* the zone */
    rrsig_update->name              = name;                 /* this has to be handled somehow ... */
    rrsig_update->context           = context_to_destroy;   /* ... and that's how */

    scheduler_schedule_task(scheduler_task_rrsig_update_commit_task, rrsig_update);

    /* WARNING: From this point forward, 'rrsig_update' cannot be used anymore */
}

/** @} */

/*----------------------------------------------------------------------------*/


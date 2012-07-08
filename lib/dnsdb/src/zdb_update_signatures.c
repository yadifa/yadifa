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

#include <dnscore/dnscore.h>

#include <dnscore/logger.h>

#include "dnsdb/zdb_types.h"

#include "dnsdb/dnssec.h"
#include "dnsdb/dnssec_task.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

extern dnssec_task_descriptor dnssec_updater_task_descriptor;
extern dnssec_task_descriptor dnssec_updater_task_descriptor_scheduled;

#if ZDB_NSEC3_SUPPORT != 0
extern dnssec_task_descriptor dnssec_nsec3_updater_task_descriptor;
extern dnssec_task_descriptor dnssec_nsec3_updater_task_descriptor_scheduled;
#endif

typedef struct zdb_update_zone_signatures_thread_args zdb_update_zone_signatures_thread_args;

struct zdb_update_zone_signatures_thread_args
{
    zdb_zone* zone;
    bool scheduled;
};

static ya_result
zdb_update_zone_signatures_final_callback(void* args)
{
    free(args);

    return SCHEDULER_TASK_FINISHED;
}

static void *
zdb_update_zone_signatures_thread(void* args_)
{
    zdb_update_zone_signatures_thread_args *args = (zdb_update_zone_signatures_thread_args*) args_;
    
    zdb_update_zone_signatures(args->zone, args->scheduled);

    scheduler_schedule_task(zdb_update_zone_signatures_final_callback, args);

    return NULL;
}

ya_result
zdb_update_zone_signatures_schedule(zdb_zone *zone)
{
    if(zone == NULL)
    {
        return ERROR;
    }

    zdb_update_zone_signatures_thread_args *args;

    MALLOC_OR_DIE(zdb_update_zone_signatures_thread_args*, args, sizeof(zdb_update_zone_signatures_thread_args), 1);
    args->zone = zone;
    args->scheduled = TRUE;

    scheduler_schedule_thread(NULL, zdb_update_zone_signatures_thread, args, "zdb_update_zone_signatures");

    return SUCCESS;
}

ya_result
zdb_update_zone_signatures_alarm(void *zone)
{
    return zdb_update_zone_signatures_schedule((zdb_zone*)zone);
}

ya_result
zdb_update_zone_signatures(zdb_zone* zone, bool scheduled)
{
    log_debug("zdb_update_zone_signatures(%p, %i) [lock=%x]", zone, scheduled, zone->mutex_owner);
    
    if(!zdb_zone_is_dnssec(zone))
    {
        log_debug("zdb_update_zone_signatures(%p, %i) [lock=%x]: not dnssec", zone, scheduled, zone->mutex_owner);
        return ZDB_ERROR_ZONE_IS_NOT_SIGNED; /* @TODO set a new code for "zone is neither NSEC nor NSEC3" */
    }

    if(!zdb_zone_trylock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER|0x80))
    {
        log_debug("zdb_update_zone_signatures(%p, %i) [lock=%x]: already locked", zone, scheduled, zone->mutex_owner);
        
        return ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED;
    }

    ya_result ret;

    dnssec_task task;

    /* alloc */

    if(ISOK(ret = dnssec_process_initialize(&task, (scheduled)?&dnssec_updater_task_descriptor_scheduled:&dnssec_updater_task_descriptor)))
    {
        /* work */

        ret = dnssec_process_zone(zone, &task);

        /* release */
    }

    dnssec_process_finalize(&task);
    
    if(dnscore_shuttingdown())
    {
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER|0x80);

        return STOPPED_BY_APPLICATION_SHUTDOWN;
    }

#if ZDB_NSEC3_SUPPORT != 0
    if(ISOK(ret))
    {
        if(zdb_zone_is_nsec3(zone))
        {
            /** @note: the scheduled one was not used here ... */
            if(ISOK(ret = dnssec_process_initialize(&task, (scheduled)?&dnssec_nsec3_updater_task_descriptor_scheduled:&dnssec_nsec3_updater_task_descriptor)))
            {
                /* work */
                ret = dnssec_process_zone_nsec3(zone, &task);
            }

            /* release */
            dnssec_process_finalize(&task);
        }
    }

#endif

    log_debug("zdb_update_zone_signatures(%p, %i) [lock=%x] done", zone, scheduled, zone->mutex_owner);

    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER|0x80);



    return ret;
}

/**
 * Signs all the zones of the DB.
 * Uses a generated key ... for now.
 *
 */
ya_result
zdb_update_signatures(zdb* db, bool scheduled)
{
    dnssec_task task;

    /* alloc */

    dnssec_process_initialize(&task, (scheduled)?&dnssec_updater_task_descriptor_scheduled:&dnssec_updater_task_descriptor);

    /* work */

    dnssec_process_database(db, &task);

    /* release */

    dnssec_process_finalize(&task);

#if ZDB_NSEC3_SUPPORT != 0
    dnssec_process_initialize(&task, &dnssec_nsec3_updater_task_descriptor);

    /* work */
    dnssec_process_database(db, &task);

    /* release */
    dnssec_process_finalize(&task);
#endif

    return SUCCESS;
}

/** @} */

/*----------------------------------------------------------------------------*/


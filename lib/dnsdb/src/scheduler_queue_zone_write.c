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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

#include <dnscore/format.h>
#include <dnscore/logger.h>

#include "dnsdb/zdb_zone.h"

#include <dnscore/scheduler.h>
#include "dnsdb/zdb_zone_write.h"

#define MODULE_MSG_HANDLE g_database_logger

extern logger_handle* g_database_logger;

#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

/*
 *
 */

#define ZONE_FORMAT "%s/%{dnsname}-zone.txt"	/* requires path and origin */
#define ZONE_TMP_SUFFIX ".$y$"

typedef struct zone_write_param zone_write_param;

struct zone_write_param
{
    zdb_zone *zone;
    char *file_path;
    callback_function *callback;
    void *callback_args;
};


static ya_result
scheduler_queue_zone_write_callback(void* data_)
{
    zone_write_param *zwp = (zone_write_param*)data_;

    log_info("zone %{dnsname} write done", zwp->zone->origin);

    if(zwp->callback != NULL)
    {
        zwp->callback(zwp->callback_args);
    }
    
    free(zwp->file_path);
    free(zwp);

    return SCHEDULER_TASK_FINISHED; /* Mark the end of the writer job */
}

static void*
scheduler_queue_zone_write_thread(void* data_)
{
    char fullname_tmp[MAX_PATH];

    zone_write_param *zwp = (zone_write_param*)data_;
    zdb_zone *zone = zwp->zone;
    u32 serial;

    log_info("zone write text: writing %{dnsname} zone file", zone->origin);
    
    if(ZDB_ZONE_INVALID(zone))
    {
        log_err("zone write text: zone %{dnsname} marked as invalid", zone->origin);
 
        scheduler_schedule_task(scheduler_queue_zone_write_callback, zwp);

        return NULL;
    }

    if(FAIL(zdb_zone_getserial(zone, &serial)))
    {
        log_err("zone write text: no SOA in %{dnsname}", zone->origin);

        scheduler_schedule_task(scheduler_queue_zone_write_callback, zwp);

        return NULL;
    }
    
    if(FAIL(snformat(fullname_tmp, sizeof (fullname_tmp), "%s.%d.tmp", zwp->file_path, serial)))
    {
        log_err("zone write text: path '%s.%d.tmp' is too big", zwp->file_path, serial);

        scheduler_schedule_task(scheduler_queue_zone_write_callback, zwp);

        /* WARNING: From this point forward, 'zone' cannot be used anymore */

        return NULL;
    }
    
    /**
     * @todo check there is not already a zone file writer working here ...
     * 
     */

    /*
     * delete the temp file if it exists already
     */
    
    if(unlink(fullname_tmp) < 0)
    {
        int err = errno;
        
        if(err != ENOENT)
        {
            log_err("zone write text: cannot cleanup '%s': %r", MAKE_ERRNO_ERROR(err));
            
            scheduler_schedule_task(scheduler_queue_zone_write_callback, zwp);

            /* WARNING: From this point forward, 'zone' cannot be used anymore */

            return NULL;
        }
    }
    
    log_info("zone write text: writing '%s'", fullname_tmp);
    
    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    zdb_zone_write_text_file(zone, fullname_tmp, FALSE);
    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
      
    log_info("zone write text: renaming '%s' to '%s'", fullname_tmp, zwp->file_path);
    
    if(rename(fullname_tmp, zwp->file_path) < 0)
    {
        log_err("zone write text: unable to rename tmp zone file into '%s': %r", zwp->file_path, ERRNO_ERROR);
        
        scheduler_schedule_task(scheduler_queue_zone_write_callback, zwp);

        /** @note Calling this so the scheduler gets a SCHEDULER_TASK_FINISHED is mandatory. */

        return NULL;
    }
    
    log_info("zone write text: %{dnsname} zone file written", zone->origin);

    scheduler_schedule_task(scheduler_queue_zone_write_callback, zwp);

    /* WARNING: From this point forward, 'zwp' cannot be used anymore */

    return NULL;
}

ya_result
scheduler_queue_zone_write(zdb_zone* zone, const char* path, callback_function *cb, void *cb_args)
{
    log_info("zone write text: queueing %{dnsname}", zone->origin);

    zone_write_param* zwp;

    MALLOC_OR_DIE(zone_write_param*, zwp, sizeof (zone_write_param), GENERIC_TAG);

    zwp->zone = zone;
    zwp->file_path = strdup(path);
    zwp->callback = cb;
    zwp->callback_args = cb_args;

    scheduler_schedule_thread(NULL, scheduler_queue_zone_write_thread, zwp, "scheduler_queue_zone_write");

    return SUCCESS;
}
/** @} */

/*----------------------------------------------------------------------------*/


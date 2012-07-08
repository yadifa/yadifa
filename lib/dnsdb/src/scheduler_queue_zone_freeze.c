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

#include <dnscore/scheduler.h>

#include "dnsdb/zdb_zone.h"

#include "dnsdb/zdb_zone_write.h"

#define MODULE_MSG_HANDLE g_database_logger

extern logger_handle* g_database_logger;

#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

/*
 *
 */

#define ZONE_TMP_SUFFIX ".$y$"

typedef struct zone_write_param zone_write_param;

struct zone_write_param
{
    zdb_zone* zone;
    char* path;
};

static ya_result
scheduler_queue_zone_freeze_callback(void* data_)
{
    zone_write_param *zwp = (zone_write_param*)data_;

    log_info("zone freeze: %{dnsname} frozen", zwp->zone->origin);

    free(zwp->path);

    return SCHEDULER_TASK_FINISHED; /* Mark the end of the writer job */
}

static void*
scheduler_queue_zone_freeze_thread(void* data_)
{
    char fullname_tmp[MAX_PATH];
    char fullname[MAX_PATH];
    
    zone_write_param *zwp = (zone_write_param*)data_;
    zdb_zone *zone = zwp->zone;
    
    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    if((zone->apex->flags & ZDB_RR_APEX_LABEL_FROZEN) != 0)
    {
        log_err("zone freeze: %{dnsname} already frozen", zone->origin);
        
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

        scheduler_schedule_task(scheduler_queue_zone_freeze_callback, zone);

        /* WARNING: From this point forward, 'zone' cannot be used anymore */
        
        return NULL;
    }
    
    zone->apex->flags |= ZDB_RR_APEX_LABEL_FROZEN;
    
    log_info("zone freeze: storing the file for %{dnsname}", zone->origin);
    
    if(FAIL(snformat(fullname, sizeof(fullname), "%s", zwp->path)))
    {
        log_err("zone freeze: path %s is too big", zwp->path, zone->origin);
        
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

        scheduler_schedule_task(scheduler_queue_zone_freeze_callback, zone);

        /* WARNING: From this point forward, 'zone' cannot be used anymore */
        
        return NULL;
    }
    
    if(FAIL(snformat(fullname_tmp, sizeof(fullname_tmp), "%s" ZONE_TMP_SUFFIX, zwp->path)))
    {
        log_err("zone freeze: path %s" ZONE_TMP_SUFFIX " is too big for %{dnsname}", zwp->path, zone->origin);
        
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

        scheduler_schedule_task(scheduler_queue_zone_freeze_callback, zone);

        /* WARNING: From this point forward, 'zone' cannot be used anymore */
        
        return NULL;
    }
    
    /* test that fullname exists AND is a simple file that CAN be removed */
    
    /**
     * @todo
     * 
     * If the file exists already, check its serial number.
     *      If it's the same stop the task now.
     *      If it is not then delete it and proceed
     * 
     */

    /* delete the temp file if it exists already */
    
    log_info("zone freeze: writing '%s'", fullname_tmp);
    
    unlink(fullname_tmp);
       
    if(ISOK(zdb_zone_write_text_file(zone, fullname_tmp, FALSE)))
    {
        unlink(fullname);
        
        if(rename(fullname_tmp, fullname) >= 0)
        {
            log_info("zone freeze: wrote '%s'", fullname);
        }
        else
        {
            log_err("zone freeze: unable to rename old zone file into %s (%i)", fullname, errno);
        }
    }
    
    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
     
    scheduler_schedule_task(scheduler_queue_zone_freeze_callback, zwp);

    /* WARNING: From this point forward, 'zwp' cannot be used anymore */

    return NULL;
}

ya_result
scheduler_queue_zone_freeze(zdb_zone* zone, const char* path, const char* filename)
{
    log_info("zone freeze: queueing %{dnsname}", zone->origin);

    
    if(*filename == '\0')
    {
		return ZDB_ERROR_CANTOPENFILE;
    }
 


    char fullname[MAX_PATH];

    if(FAIL(snformat(fullname, sizeof (fullname), "%s/%s", path, filename)))
    {
        log_err("zone freeze: path %s/%s is too big", path, filename);

        return ZDB_ERROR_FILEPATH_TOOLONG;
    }

    zone_write_param* zwp;

    MALLOC_OR_DIE(zone_write_param*, zwp, sizeof (zone_write_param), GENERIC_TAG);
    
    zwp->zone = zone;
    zwp->path = strdup(fullname);

    scheduler_schedule_thread(NULL, scheduler_queue_zone_freeze_thread, zwp, "scheduler_queue_zone_freeze");

    return SUCCESS;
}
/** @} */

/*----------------------------------------------------------------------------*/


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
/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

#include <stdio.h>
#include <stdlib.h>

#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/dnssec_scheduler.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/zdb_types.h>

#include <dnsdb/zdb_zone_load.h>
#include <dnszone/zone_axfr_reader.h>

#include <dnscore/host_address.h>

#include "confs.h"

#include "database.h"

#include "axfr.h"
#include "ixfr.h"

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

typedef struct xfr_query_schedule_param xfr_query_schedule_param;

struct xfr_query_schedule_param
{
    database_t *db;
    host_address *servers;
    u8 *origin;
    u64 serial_start_offset;
    u32 loaded_serial;
    u16 type;
    ya_result return_value;
    callback_function *callback;
    void *callback_args;
};

typedef struct axfr_query_axfr_load_param axfr_query_axfr_load_param;

struct axfr_query_axfr_load_param
{
    zone_reader zr;
    database_t *db;
    zdb_zone *old_zone;
    zdb_zone *new_zone;
	u8 *origin;
};

static ya_result scheduler_axfr_query_alarm(void* xqspp);

/*
 * Called after the load of a zone (AXFR/IXFR)
 * Updates expired/refreshed/retried timers
 * Set/unsets the INVALID flag of the zone
 * 
 * Arm the next mainenance for the zone
 * 
 */

static void
xfr_query_mark_zone_loaded(zdb* db, const u8 *origin, u32 refreshed_time, u32 retried_time)
{
    zone_data *zone = zone_getbydnsname(origin);
    
    bool refresh = TRUE;
    
    if(zone != NULL)
    {
        zone_setloading(zone, FALSE);
        
        if(refreshed_time != 0)
        {
            zone->refresh.refreshed_time = refreshed_time;
        }
        if(retried_time != 0)
        {
            zone->refresh.retried_time = retried_time;
        }
        
        zdb_zone *dbzone = zdb_zone_find_from_dnsname(db, origin, CLASS_IN);
        
        if(dbzone != NULL)
        {
            soa_rdata soa;
            
            zdb_zone_lock(dbzone, ZDB_ZONE_MUTEX_XFR);
                    
            if(ISOK(zdb_zone_getsoa(dbzone, &soa)))
            {
                u32 now = time(NULL);
                if(zone->refresh.refreshed_time >= now + soa.expire)
                {
                    log_info("slave: zone %{dnsname} has expired", origin);
                    
                    dbzone->apex->flags |= ZDB_RR_LABEL_INVALID_ZONE;
                    
                    refresh = FALSE;
                }
            }
            
            zdb_zone_unlock(dbzone, ZDB_ZONE_MUTEX_XFR);
        }
        
        log_info("slave: zone %{dnsname} load operation done", origin);
    }
    else
    {
        log_err("slave: expected to find zone '%{dnsname}' in the database", origin);
    }
    
    if(refresh)
    {
        database_zone_refresh_maintenance(g_config->database, origin);
    }
}

static ya_result
xfr_query_final_callback(void* data)
{
    axfr_query_axfr_load_param *aqalp = (axfr_query_axfr_load_param*) data;
    
    zone_data *zone_desc = zone_getbydnsname(aqalp->origin);    

    if(zone_desc != NULL) /* the zone may have been dropped in the mean time */
    {
        /*
         * Get the label
         * Set the zone
         * Destroy the placeholder
         */
        
        if(aqalp->new_zone != NULL)
        {
            dnsname_vector name;
            DEBUG_RESET_dnsname(name);

            dnsname_to_dnsname_vector(aqalp->origin, &name);

            zdb_zone_label *zone_label = zdb_zone_label_add((zdb*)aqalp->db, &name,  zone_desc->qclass);

            zdb_zone *placeholder_zone = zone_label->zone;

            zone_label->zone = aqalp->new_zone;

            log_info("slave: %{dnsname} zone mounted", aqalp->origin);

            aqalp->new_zone->extension = &zone_desc->ac;
            aqalp->new_zone->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);

            u32 now = time(NULL);

            zone_desc->refresh.refreshed_time = now;
            zone_desc->refresh.retried_time = now;
            
            zdb_zone_unlock(placeholder_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
            zdb_zone_destroy(placeholder_zone);
        }
        
        zone_setloading(zone_desc, FALSE);

        database_zone_refresh_maintenance(g_config->database, aqalp->origin);
    }
    
	free(aqalp->origin);
    free(aqalp);
    
    return SCHEDULER_TASK_FINISHED;
}

static void*
xfr_query_axfr_load_thread(void *data)
{
    axfr_query_axfr_load_param *aqalp = (axfr_query_axfr_load_param*) data;
    ya_result return_value;

    /*
     * Now that the access has been cut, this could be done in background, with the loading
     */


    /*
     * Load the zone again
     * (other thread, with no zone visible until the very end)
     */

    zdb_zone *newzone = NULL;

    log_info("slave: zone %{dnsname} transferred", aqalp->origin);
    
    /**
     * Behaviour change : loading an zone file (axfr file) into memory will now drop (invalidate) the zone before
     * loading it.  Else loading a zone like .com would lead to potentially twice the amount of memory made readily
     * available to yadifa when most of it will remain untouched.
     * 
     * so:
     * 
     * invalidate the zone
     * drop the zone
     * load the zone
     */

    if(ISOK(return_value = zdb_zone_load((zdb*)aqalp->db, &aqalp->zr, &newzone, g_config->xfr_path, aqalp->origin, ZDB_ZONE_DESTROY_JOURNAL|ZDB_ZONE_IS_SLAVE)))
    {
        zassert(newzone != NULL);
        
        log_info("slave: zone %{dnsname} loaded", aqalp->origin);
        
        aqalp->new_zone = newzone;       
    }
    else
    {
        log_err("slave: zone %{dnsname} failed to load: %r", aqalp->origin, return_value);
        
        if(return_value == DNSSEC_ERROR_NSEC3_INVALIDZONESTATE)
        {
            /** @todo don't try for a while */
        }
    }

    zone_reader_close(&aqalp->zr);

    /*
     * At this point, since we are a slave, we need to start the alarm again.
     */

    scheduler_schedule_task(xfr_query_final_callback, aqalp);

    return NULL;
}

/*
 * slave : the xfr file is on disk ... or not.
 */

static ya_result
xfr_query_callback(void* data)
{
    xfr_query_schedule_param *xqsp = (xfr_query_schedule_param*)data;
    ya_result return_value;
	ya_result scheduler_status;
    u32 refreshed_time = 0;
    u32 retried_time = time(NULL);
    
    /*
     * Zone refresh will be enabled (again) here.
     * 
     * xfr_query_mark_zone_loaded
     * 
     */

    
    if(ISOK(xqsp->return_value))
    {
        /* success but type == 0 => transfer done */
        
        if(xqsp->type != 0)
        {
            log_info("slave: %{dnstype}: proceeding with transfer of %{dnsname}", &xqsp->type, xqsp->origin);
        }
    }
    else
    {
        log_err("slave: %{dnstype}: transfer of %{dnsname} failed: %r", &xqsp->type, xqsp->origin, xqsp->return_value);
        
        /*
         * Here (?) put the invalid zone placeholder if it is not there yet
         */
    }

    switch(xqsp->type)
    {
        case TYPE_AXFR:
        {
            /*
             * Load the axfr
             */
            
            if(ISOK(xqsp->return_value))
            {
                axfr_query_axfr_load_param *aqalp;
                MALLOC_OR_DIE(axfr_query_axfr_load_param*, aqalp, sizeof(axfr_query_axfr_load_param), GENERIC_TAG);
                
                log_info("slave: opening AXFR for %{dnsname} %d", xqsp->origin, xqsp->loaded_serial);

                if(ISOK(return_value = zone_axfr_reader_open_with_serial(g_config->xfr_path, xqsp->origin, xqsp->loaded_serial, &aqalp->zr)))
                {
                    /*
                     * The system is ready to load an AXFR
                     * A zone is already in place (by design), there may be an old zone that is now irrelevant.
                     * At this point ...
                     * 
                     * If the serial are not the same
                     *      MT the old zone must be destroyed (if it exist)
                     *       then
                     *      MT The new zone has to be created (loaded from the AXFR file)
                     * Else
                     *      ST The new zone is actually the old zone, and the old zone is non-existent
                     * EndIf
                     * 
                     * then
                     * 
                     * ST The new zone and the placeholder zone have to be swapped, then the placeholder has to be destroyed
                     * 
                     */
                    
                    zdb_zone *zone = zdb_zone_find_from_dnsname((zdb*)xqsp->db, xqsp->origin, CLASS_IN);

                    if(zone != NULL)
                    {
                        zdb_zone_truncate_invalidate(zone);
                    }                    

                    /**
                     * schedule the axfr load
                     */

                    aqalp->old_zone = NULL; /* old zone */
                    aqalp->new_zone = NULL;
                    aqalp->db = xqsp->db;
                    aqalp->origin = dnsname_dup(xqsp->origin);

                    scheduler_status = SCHEDULER_TASK_PROGRESS;

                    thread_pool_schedule_job(xfr_query_axfr_load_thread, aqalp, NULL, "axfr load");
                    
                    break;
                }
            }
            
            /**
             * @todo If the "old_zone" exists, then ... (destroy ? swap back ? expired ?)
             * 
             */
            
            /*
             * An issue occurred (AXFR transfer, load)
             */
			
            log_err("slave: unable to load the axfr (retry set in %d seconds)", g_config->axfr_retry_delay);

            alarm_event_node *event = alarm_event_alloc();

            event->epoch = time(NULL) + g_config->axfr_retry_delay;

            if(g_config->axfr_retry_jitter > 0)
            {
                random_ctx rndctx = thread_pool_get_random_ctx();
                u32 jitter = random_next(rndctx) % g_config->axfr_retry_jitter;
                event->epoch += jitter;
            }

            event->function = scheduler_axfr_query_alarm;
            event->args = xqsp;
            event->key = ALARM_KEY_ZONE_AXFR_QUERY;
            event->flags = ALARM_DUP_NOP;
            event->text = "scheduler_axfr_query_alarm";

            zdb *db = (zdb*)xqsp->db;
            alarm_set(db->alarm_handle, event);

            /* DO NOT FREE xqsp, SO DO NOT BREAK : return now */
            
            return SCHEDULER_TASK_FINISHED;
        }
        
        case TYPE_IXFR:
        {
            /**
             * Load the ixfr (single thread, zone locked)
             */

			scheduler_status = SCHEDULER_TASK_FINISHED;

            if(ISOK(xqsp->return_value))
            {
                zdb_zone *dbzone = zdb_zone_find_from_dnsname((zdb*)xqsp->db, xqsp->origin, CLASS_IN);

                if(dbzone == NULL)
                {
                    log_err("slave: zone %{dnsname} journal has vanished", xqsp->origin);
                    break;
                }
                
                log_info("slave: opening journal for '%{dnsname}'", xqsp->origin);

                zdb_zone_lock(dbzone, ZDB_ZONE_MUTEX_XFR);
                
                if(ISOK(return_value = zdb_icmtl_replay(dbzone, g_config->xfr_path, xqsp->serial_start_offset, xqsp->loaded_serial, ZDB_ICMTL_REPLAY_SERIAL_OFFSET|ZDB_ICMTL_REPLAY_SERIAL_LIMIT)))
                {
                    log_info("slave: replayed %d records changes", return_value);
                    
                    dbzone->apex->flags &= ~ZDB_RR_LABEL_INVALID_ZONE;
                    
                    refreshed_time = time(NULL);
                }
                else
                {
                    log_err("slave: replay error: %r this is bad: invalidate the zone and ask for an AXFR", return_value);
                    
                    /** @todo INVALIDATE AND AXFR */
                }
                
                /** @todo invalitate if retried_time > expired_time */

                zdb_zone_unlock(dbzone, ZDB_ZONE_MUTEX_XFR);
            }
            
            log_info("slave: journal transfer done");

            xfr_query_mark_zone_loaded((zdb*)g_config->database, xqsp->origin, refreshed_time, retried_time);
            
			scheduler_status = SCHEDULER_TASK_FINISHED;
            break;            
        }
        default:
        {
            refreshed_time = time(NULL);
            
            log_info("slave: transfer done");

            xfr_query_mark_zone_loaded((zdb*)g_config->database, xqsp->origin, refreshed_time, retried_time);
            
			scheduler_status = SCHEDULER_TASK_FINISHED;
            break;
        }
    }   /* switch return_value */
    
    free(xqsp->origin);
    free(xqsp);

	return scheduler_status;
}

static void*
xfr_query_thread(void *data)
{
    ya_result return_value;
    xfr_query_schedule_param *xqsp = (xfr_query_schedule_param*)data;

    switch(xqsp->type)
    {
        case TYPE_IXFR:
        {
            log_info("slave: %{dnsname} IXFR query to the master", xqsp->origin);

            zdb_zone *zone = zdb_zone_find_from_dnsname((zdb*)xqsp->db, xqsp->origin, CLASS_IN);

            if(zone == NULL)
            {
                log_err("slave: zone %{dnsname} is not in the database", xqsp->origin);

                return_value = ERROR;
                break;
            }

            //random_ctx rndctx = thread_pool_get_random_ctx();

            if(ISOK(return_value = ixfr_query(xqsp->servers, zone, &xqsp->loaded_serial, &xqsp->serial_start_offset)))
            {
                u16 type = (u16)return_value;
                xqsp->type = type;

                if(type != 0)
                {
                    log_info("slave: loaded %{dnstype} for domain %{dnsname} from master at %{hostaddr}, new serial is %d", &type, xqsp->origin, xqsp->servers, xqsp->loaded_serial);
                }
            }
            else
            {
                log_err("slave: query error for domain %{dnsname} from master at %{hostaddr}: %r", xqsp->origin, xqsp->servers, return_value);
            }
            break;
        }
        case TYPE_AXFR:
        {
            log_info("slave: %{dnsname} AXFR query to the master", xqsp->origin);

            if(ISOK(return_value = axfr_query(xqsp->servers, xqsp->origin, &xqsp->loaded_serial)))
            {
                u16 type = (u16)return_value;
                xqsp->type = type;
                
                if(type != 0)
                {
                    log_info("slave: loaded %{dnstype} for domain %{dnsname} from master at %{hostaddr}, serial is %d", &type, xqsp->origin, xqsp->servers, xqsp->loaded_serial);
                }
            }
            else
            {
                log_err("slave: query error for domain %{dnsname} from master at %{hostaddr}: %r", xqsp->origin, xqsp->servers, return_value);
            }
            break;
        }
        default:
        {
            return_value = xqsp->return_value;
            log_err("slave: query error %{dnstype} for domain %{dnsname} from master at %{hostaddr}: %r", &xqsp->type, xqsp->origin, xqsp->servers, return_value);
            break;
        }
    }

    /*
     * Switch to phase 2
     */

    xqsp->return_value = return_value;

    scheduler_schedule_task(xfr_query_callback, xqsp);

    return NULL;
}

/**
 * 
 * Schedule for an incremental update of a zone
 * 
 * @param db the database
 * @param address_list the address of the master(s)
 * @param origin the zone domain
 * 
 * @return an error code
 */

ya_result
scheduler_ixfr_query(database_t *db, host_address *address_list, u8 *origin)
{
    xfr_query_schedule_param* xqsp;
    
    log_info("slave: queueing %{dnsname} IXFR query", origin);

    if(address_list == NULL)
    {
        return ERROR;
    }
    
    MALLOC_OR_DIE(xfr_query_schedule_param*, xqsp, sizeof (xfr_query_schedule_param), GENERIC_TAG);

    xqsp->db = db;
    xqsp->servers = address_list;
    xqsp->origin = dnsname_dup(origin);
    xqsp->loaded_serial = 0;
    xqsp->type = TYPE_IXFR;
    xqsp->callback = NULL;
    xqsp->callback_args = NULL;
    
    /*
     * Disable refresh
     */

    scheduler_schedule_thread(NULL, xfr_query_thread, xqsp, "scheduler_ixfr_query");

    return SUCCESS;
}


/**
 * 
 * Schedule for the full download of a zone
 * 
 * @param db the database
 * @param address_list the address of the master(s)
 * @param origin the zone domain
 * 
 * @return an error code
 */

ya_result
scheduler_axfr_query(database_t *db, host_address *address_list, u8 *origin)
{
    xfr_query_schedule_param* xqsp;
    
    log_info("slave: queueing %{dnsname} AXFR query", origin);

    if(address_list == NULL)
    {
        return ERROR;
    }
        
    /* TODO ?
     * 
     * Mark the zone invalid
     * Close alarms
     * Drop the zone content
     */
    
    MALLOC_OR_DIE(xfr_query_schedule_param*, xqsp, sizeof (xfr_query_schedule_param), GENERIC_TAG);

    xqsp->db = db;
    xqsp->servers = address_list;
    xqsp->origin = dnsname_dup(origin); /* malloc with fast dnsname len */
    xqsp->loaded_serial = 0;
    xqsp->type = TYPE_AXFR;
    xqsp->callback = NULL;
    xqsp->callback_args = NULL;
    
    /*
     * Disable refresh
     */

    scheduler_schedule_thread(NULL, xfr_query_thread, xqsp, "scheduler_axfr_query");

    return SUCCESS;
}

static ya_result
scheduler_axfr_query_alarm(void *xqspp)
{
    xfr_query_schedule_param *xqsp = (xfr_query_schedule_param*)xqspp;
    
    log_debug("slave: setting alarm for %{dnsname} AXFR query", xqsp->origin);
    
    /*
     * Disable refresh
     */

    scheduler_schedule_thread(NULL, xfr_query_thread, xqsp, "scheduler_axfr_query_alarm");
    
    return SUCCESS;
}


/** @} */

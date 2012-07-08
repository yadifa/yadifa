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

#include <dnscore/thread_pool.h>

#include "dnsdb/dnssec.h"

#include <dnscore/scheduler.h>
#include "dnsdb/dnssec_keystore.h"

#define MODULE_MSG_HANDLE g_dnssec_logger

/*
 *
 */

typedef struct scheduler_dnskey_create scheduler_dnskey_create;

struct scheduler_dnskey_create
{
    dnssec_key* key;
    zdb_zone* zone;
    u16 flags;
    u8 algorithm;
    u16 size;
};

/**
 * This call is made in a thread
 * Since the DB is still read, it cannot modify it.
 * If any modification has to be made, it has to schedule said modification.
 */

static ya_result
scheduler_queue_dnskey_create_callback(void* data_)
{
    scheduler_dnskey_create *data = (scheduler_dnskey_create*)data_;
    
    if(data->key != NULL)
    {
        dnssec_key_addrecord(data->zone, data->key);

        log_info("dnssec: key ready (%{dnsname} %hd %hhd %hd)", data->zone->origin, data->flags, data->algorithm, data->size);
    }
    else
    {
        log_err("dnssec: key creation failure (%{dnsname} %hd %hhd %hd)", data->zone->origin, data->flags, data->algorithm, data->size);
    }

    free(data);

    return SCHEDULER_TASK_FINISHED; /* Notify the end of the writer job */
}

static void*
scheduler_queue_dnskey_create_thread(void* data_)
{
    scheduler_dnskey_create *data = (scheduler_dnskey_create*)data_;
    ya_result return_value;
    
    log_info("dnssec: key create (%{dnsname} %hd %hhd %hd)", data->zone->origin, data->flags, data->algorithm, data->size);

    char origin[MAX_DOMAIN_LENGTH];

    dnsname_to_cstr(origin, data->zone->origin);

    dnssec_key* key;
    
    if(ISOK(return_value = dnssec_key_createnew(DNSKEY_ALGORITHM_RSASHA1_NSEC3, data->size, data->flags, origin, &key)))
    {
        if(ISOK(return_value = dnssec_key_store_private(key)))
        {
            if(ISOK(return_value = dnssec_key_store_dnskey(key)))
            {
                log_info("dnssec: key created (%{dnsname} %hd %hhd %hd)", data->zone->origin, data->flags, data->algorithm, data->size);    
            }
            else
            {
                log_err("dnssec: key store public (%{dnsname} %hd %hhd %hd): %r", data->zone->origin, data->flags, data->algorithm, data->size, return_value);
            }
        }
        else
        {
            log_err("dnssec: key store private (%{dnsname} %hd %hhd %hd): %r", data->zone->origin, data->flags, data->algorithm, data->size, return_value);
        }
    }
    else
    {
        log_err("dnssec: key create failed (%{dnsname} %hd %hhd %hd): %r", data->zone->origin, data->flags, data->algorithm, data->size, return_value);
    }

    if(ISOK(return_value))
    {
        data->key = key;
    }
    else
    {
        dnssec_key_free(key);
        
        data->key = NULL;
    }
    
    scheduler_schedule_task(scheduler_queue_dnskey_create_callback, data);

    /* WARNING: From this point forward, 'data' cannot be used anymore */

    /*
     * The key is still in the keystore.
     *
     */

    return NULL;
}

void
scheduler_queue_dnskey_create(zdb_zone* zone, u16 flags, u8 algorithm, u16 size)
{
    zassert(zone != NULL);

    scheduler_dnskey_create* data;

    log_info("dnssec: queueing key creation %{dnsname} %hd %hhd %hd", zone->origin, flags, algorithm, size);

    MALLOC_OR_DIE(scheduler_dnskey_create*, data, sizeof (scheduler_dnskey_create), GENERIC_TAG);

    data->key = NULL;
    data->zone = zone;
    data->flags = flags;
    data->algorithm = algorithm;
    data->size = size;

    scheduler_schedule_thread(NULL, scheduler_queue_dnskey_create_thread, data, "scheduler_queue_dnskey_create");
}

/** @} */

/*----------------------------------------------------------------------------*/


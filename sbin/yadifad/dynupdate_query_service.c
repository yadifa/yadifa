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

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "server-config.h"

#if HAS_PTHREAD_SETNAME_NP
#if DEBUG
#define _GNU_SOURCE 1
#endif
#endif

#include <dnscore/thread.h>

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/threaded_queue.h>
#include <dnscore/thread.h>
#include <dnscore/thread_pool.h>
#include <dnscore/message.h>
#include <dnsdb/zdb_types.h>

#include "database.h"
#include "server.h"

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

#define MODULE_MSG_HANDLE g_server_logger

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** @brief Function ...
 *
 *  ...
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */

/**
 * 
 * The dynupdate service loads the next update from the queue and runs it.
 */

static threaded_queue dynupdate_query_service_queue = THREADED_QUEUE_EMPTY;
static volatile thread_t dynupdate_query_service_thread_id = 0;
static volatile bool dynupdate_query_service_thread_run = FALSE;

typedef struct dynupdate_query_service_args dynupdate_query_service_args;

#define DYNUPQSA_TAG 0x41535150554e5944

struct dynupdate_query_service_args
{
    zdb            *db;
    message_data   *mesg;
    u32             timestamp;
    int             sockfd;
};

static const u32 dynupdate_query_timeout_seconds = 2;

static noreturn void*
dynupdate_query_service_thread(void *args)
{
    (void)args;
    thread_pool_setup_random_ctx();
    
    log_debug("dynupdate_query_service_thread: service started");

    thread_set_name("dynupdate-query", 0, 0);
    
#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_set_thread_tag("dynupdte");
#endif
    
    for(;;)
    {
dynupdate_query_service_thread_main_loop:

        if(dnscore_shuttingdown())
        {
            break;
        }
                
        /**
         * 
         * Needs all the parameters for UDP answer.
         * Needs the time of the query.  If it's too old (> 3s) forget it.
         * 
         */
        
        dynupdate_query_service_args* parms = (dynupdate_query_service_args*)threaded_queue_dequeue(&dynupdate_query_service_queue);
        
        if(parms == NULL)
        {
            log_debug("dynupdate_query_service_thread: stopping (M)");
            break;
        }
        
        if(!dynupdate_query_service_thread_run)
        {
            log_debug("dynupdate_query_service_thread: stopping (S)");
            break;
        }
        
        message_data *mesg = parms->mesg;
        
        u32 now = time(NULL);
        
        if((now - parms->timestamp) <= dynupdate_query_timeout_seconds)
        {
            /* process */

            zdb *database = parms->db;

            /* clone the message */
            /* use the same scheduling mechanism as for TCP */

            log_info("update (%04hx) %{dnsname} %{dnstype} (%{sockaddr})",
                                        ntohs(message_get_id(mesg)),
                                        message_get_canonised_fqdn(mesg),
                                        message_get_query_type_ptr(mesg),
                                        message_get_sender_sa(mesg));

            ya_result ret = database_update(database, mesg);

            if(FAIL(ret))
            {
                if(message_get_query_type(mesg) == TYPE_SOA)
                {
                    if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                    {
                        log_info("update (%04hx) %{dnsname} temporary failure: zone file must be stored: %r",
                                 ntohs(message_get_id(mesg)),
                                 message_get_canonised_fqdn(mesg),
                                 ret);
                    }
                    else
                    {
                        log_warn("update (%04hx) %{dnsname} failed: %r",
                                 ntohs(message_get_id(mesg)),
                                 message_get_canonised_fqdn(mesg),
                                 ret);
                    }
                }
                else
                {
                    if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                    {
                        log_info("update (%04hx) %{dnsname} %{dnstype} temporary failure: zone file must be stored: %r",
                                 ntohs(message_get_id(mesg)),
                                 message_get_canonised_fqdn(mesg),
                                 message_get_query_type_ptr(mesg),
                                 ret);
                    }
                    else
                    {
                        log_warn("update (%04hx) %{dnsname} %{dnstype} failed: %r",
                                ntohs(message_get_id(mesg)),
                                message_get_canonised_fqdn(mesg),
                                message_get_query_type_ptr(mesg),
                                ret);
                    }
                }
            }

            //local_statistics->udp_fp[message_get_status(mesg)]++;

#if !HAS_DROPALL_SUPPORT

            ssize_t sent;

#if DEBUG
            log_debug("dynupdate_query_service_thread: sendto(%d, %p, %d, %d, %{sockaddr}, %d)",
                    parms->sockfd, message_get_buffer_const(mesg), message_get_size(mesg), 0,
                    message_get_sender_sa(mesg), message_get_sender_size(mesg));
            log_memdump_ex(g_server_logger, MSG_DEBUG5, message_get_buffer_const(mesg), message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif
            
            while( (sent = message_send_udp(mesg, parms->sockfd)) < 0)
            {
                int error_code = errno;

                if(error_code != EINTR)
                {
                    /** @warning server_st_process_udp needs to be modified */
                    
                    log_err("update (%04hx) %{dnsname} %{dnstype} send failed: %r",
                        ntohs(message_get_id(mesg)),
                        message_get_canonised_fqdn(mesg),
                        message_get_query_type_ptr(mesg),
                        MAKE_ERRNO_ERROR(error_code));

                    free(parms);
                    message_free(mesg);

                    /**********************************************************
                     * GOTO !
                     * 
                     * This one is meant to break both loops to avoid the test
                     * following this while {}
                     * 
                     *********************************************************/
                    
                    goto dynupdate_query_service_thread_main_loop; 
                    
                    /**********************************************************
                     * GOTO !
                     *********************************************************/
                }
            }
            
            //local_statistics->udp_output_size_total += sent;

            if((size_t)sent != message_get_size(mesg))
            {
                /** @warning server_st_process_udp needs to be modified */
                log_err("short byte count sent (%lli instead of %i)", sent, message_get_size(mesg));
            }
#else
            log_debug("dynupdate_query_service_thread: drop all");
#endif

        }

        free(parms);
        message_free(mesg);
    }
    
    log_debug("dynupdate_query_service_thread: service stopped");
    
    thread_pool_destroy_random_ctx();
    
#if DNSCORE_HAS_LOG_THREAD_TAG
    logger_handle_clear_thread_tag();
#endif
    
    thread_exit(NULL); /* not from the pool, so it's the way */

    // unreachable
    // return NULL;
}

ya_result
dynupdate_query_service_start()
{
    log_debug("dynupdate_query_service_start: starting service");
    
    if(dynupdate_query_service_thread_id != 0)
    {
        log_debug("dynupdate_query_service_start: already running");
        
        return SERVICE_ALREADY_RUNNING;
    }
    
    dynupdate_query_service_thread_run = TRUE;
    
    threaded_queue_init(&dynupdate_query_service_queue, 256);
    
    thread_t id;
    if(thread_create(&id, dynupdate_query_service_thread, NULL) != 0)
    {
        log_crit("failed to start dynamic query service thread");
        
        dynupdate_query_service_thread_run = FALSE;
        
        return THREAD_CREATION_ERROR;
    }
    
    dynupdate_query_service_thread_id = id;
    
    return SUCCESS;
}

ya_result
dynupdate_query_service_stop()
{
    log_debug("dynupdate_query_service_stop: stopping dynamic update service");
    
    if(dynupdate_query_service_thread_id == 0)
    {
        return SUCCESS;
    }
    
    dynupdate_query_service_thread_run = FALSE;
    
    threaded_queue_enqueue(&dynupdate_query_service_queue, NULL);
    
    thread_join(dynupdate_query_service_thread_id, NULL);
    
    log_debug("emptying dynamic update queue");
    
    while(threaded_queue_size(&dynupdate_query_service_queue) > 0)
    {
        dynupdate_query_service_args* parms = (dynupdate_query_service_args*)threaded_queue_try_dequeue(&dynupdate_query_service_queue);
        
        if(parms != NULL)
        {
            free(parms->mesg);
            free(parms);
        }
    }
    
    threaded_queue_finalize(&dynupdate_query_service_queue);
    
    dynupdate_query_service_thread_id = 0;
    
    log_debug("dynamic update service stopped");
    
    return SUCCESS;
}

ya_result
dynupdate_query_service_enqueue(zdb *db, message_data *mesg, int sockfd)
{
    if(dynupdate_query_service_thread_id == 0)
    {
        return SERVICE_NOT_RUNNING;
    }
    // ensure the original message cannot be used anymore
    struct dynupdate_query_service_args *parms;
    MALLOC_OBJECT_OR_DIE(parms, dynupdate_query_service_args, DYNUPQSA_TAG);
    parms->db = db;
    parms->mesg = message_dup(mesg);
    parms->timestamp = time(NULL);
    parms->sockfd = sockfd;
    
    threaded_queue_enqueue(&dynupdate_query_service_queue, parms);

#if DNSCORE_HAS_TSIG_SUPPORT
    message_tsig_clear_key(mesg);
#endif
    message_set_size(mesg, 0);  // resets the message size

    return SUCCESS;
}

/** @} */

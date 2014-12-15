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
#ifdef DEBUG
#define _GNU_SOURCE 1
#endif
#endif

#include <pthread.h>

#include "config.h"

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/threaded_queue.h>
#include <dnscore/thread_pool.h>
#include <dnsdb/zdb_types.h>

#include "server_context.h"

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
 * Move this into YADIFAD
 * 
 * The dynupdate service loads the next update from the queue and runs it.
 */

static threaded_queue dynupdate_query_service_queue = THREADED_QUEUE_NULL;
static volatile pthread_t dynupdate_query_service_thread_id = 0;
static volatile bool dynupdate_query_service_thread_run = FALSE;

typedef struct dynupdate_query_service_args dynupdate_query_service_args;

struct dynupdate_query_service_args
{
    zdb            *db;
    message_data   *mesg;
#if UDP_USE_MESSAGES != 0
    struct iovec    udp_iovec;
    struct msghdr   udp_msghdr;
#endif
    u32             timestamp;
};

static void*
dynupdate_query_service_thread(void *args)
{
    thread_pool_setup_random_ctx();
    
    log_debug("dynupdate_query_service_thread: service started");

#if HAS_PTHREAD_SETNAME_NP
#ifdef DEBUG
    pthread_setname_np(pthread_self(), "dynupdate-query");
#endif
#endif
    
    for(;;)
    {
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
        
        if((now - parms->timestamp) <= 3) /** @todo set this as a configuration parameter (dynupdate-processing-timeout or something) */
        {
            /* process */

            zdb *database = parms->db;

            /* clone the message */
            /* use the same scheduling mechanism as for TCP */

            log_info("update (%04hx) %{dnsname} %{dnstype} (%{sockaddr})",
                                        ntohs(MESSAGE_ID(mesg->buffer)),
                                        mesg->qname,
                                        &mesg->qtype,
                                        &mesg->other.sa);

            finger_print return_code = database_update(database, mesg);

            if(FAIL(return_code))
            {
                log_err("update (%04hx) %{dnsname} %{dnstype} failed: %r",
                        ntohs(MESSAGE_ID(mesg->buffer)),
                        mesg->qname,
                        &mesg->qtype,
                        return_code);
            }

            //local_statistics->udp_fp[mesg->status]++;

#if !HAS_DROPALL_SUPPORT

            s32 sent;

#ifdef DEBUG
            log_debug("dynupdate_query_service_thread: sendto(%d, %p, %d, %d, %{sockaddr}, %d)", mesg->sockfd, mesg->buffer, mesg->send_length, 0, (struct sockaddr*)&mesg->other.sa, mesg->addr_len);
            log_memdump_ex(g_server_logger, MSG_DEBUG5, mesg->buffer, mesg->send_length, 16, OSPRINT_DUMP_HEXTEXT);
#endif
            
#if UDP_USE_MESSAGES == 0
            while((sent = sendto(mesg->sockfd, mesg->buffer, mesg->send_length, 0, (struct sockaddr*)&mesg->other.sa, mesg->addr_len)) < 0)
            {
                int error_code = errno;

                if(error_code != EINTR)
                {
                    /** @warning server_st_process_udp needs to be modified */
                    //log_err("sendto: %r", MAKE_ERRNO_ERROR(error_code));

                    free(parms);
                    free(mesg);

                    return NULL/*ERROR*/;
                }
            }
#else
            parms->udp_iovec.iov_len = mesg->send_length;

#ifdef DEBUG
            log_debug("sendmsg(%d, %p, %d", mesg->sockfd, &parms->udp_msghdr, 0);
#endif
            while( (sent = sendmsg(mesg->sockfd, &parms->udp_msghdr, 0)) < 0)
            {
                int error_code = errno;

                if(error_code != EINTR)
                {
                    /** @warning server_st_process_udp needs to be modified */
                    
                    log_err("update (%04hx) %{dnsname} %{dnstype} send failed: %r",
                        ntohs(MESSAGE_ID(mesg->buffer)),
                        mesg->qname,
                        &mesg->qtype,
                        MAKE_ERRNO_ERROR(error_code));
                    
                    free(parms);
                    free(mesg);

                    return NULL/*ERROR*/;
                }
            }
#endif
            //local_statistics->udp_output_size_total += sent;

            if(sent != mesg->send_length)
            {
                /** @warning server_st_process_udp needs to be modified */
                log_err("short byte count sent (%i instead of %i)", sent, mesg->send_length);

                /*return ERROR*/;
            }
#else
            log_debug("dynupdate_query_service_thread: drop all");
#endif

        }
#if UDP_USE_MESSAGES != 0
        free(parms->udp_msghdr.msg_control);
#endif
        free(parms);
        free(mesg);
    }
    
    log_debug("dynupdate_query_service_thread: service stopped");
    
    thread_pool_destroy_random_ctx();
    
    pthread_exit(NULL); /* not from the pool, so it's the way */
    
    return NULL;
}

ya_result
dynupdate_query_service_start()
{
    log_debug("dynupdate_query_service_start: starting service");
    
    if(dynupdate_query_service_thread_id != 0)
    {
        log_debug("dynupdate_query_service_start: already running");
        
        return ERROR;
    }
    
    dynupdate_query_service_thread_run = TRUE;
    
    threaded_queue_init(&dynupdate_query_service_queue, 256);
    
    pthread_t id;
    if(pthread_create(&id, NULL, dynupdate_query_service_thread, NULL) != 0)
    {
        log_crit("failed to start dynamic query service thread");
        
        dynupdate_query_service_thread_run = FALSE;
        
        return ERROR;
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
    
    pthread_join(dynupdate_query_service_thread_id, NULL);
    
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
dynupdate_query_service_enqueue(zdb *db, message_data *msg, struct msghdr *udp_msghdr)
{
    if(dynupdate_query_service_thread_id == 0)
    {
        return ERROR;
    }
    
    message_data *mesg_clone;
    MALLOC_OR_DIE(message_data*, mesg_clone, sizeof(message_data), MESGDATA_TAG);
    memcpy(mesg_clone, msg, sizeof(message_data));
    // ensure the original message cannot be used anymore
#if HAS_TSIG_SUPPORT
    msg->tsig.tsig = NULL;
#endif
    msg->received = 0;
    msg->send_length = 0;
    
    struct dynupdate_query_service_args *parms;
    MALLOC_OR_DIE(struct dynupdate_query_service_args *, parms, sizeof(dynupdate_query_service_args), GENERIC_TAG);
    parms->db = db;
    parms->mesg = mesg_clone;
    
#if UDP_USE_MESSAGES != 0
    
    /*
     * Clone the message parameters.
     * The iovec points into the buffer
     * The header uses the cloned iovec, a cloned anciliary buffer and the cloned sender (other) address from the message
     */
    
    parms->udp_iovec.iov_base = &mesg_clone->buffer[0];
    parms->udp_iovec.iov_len = sizeof(mesg_clone->buffer);
    
    memcpy(&parms->udp_msghdr, udp_msghdr, sizeof(struct msghdr)); // copy the whole content
    parms->udp_msghdr.msg_name = &mesg_clone->other.sa;
    // DO NOT : parms->udp_msghdr.msg_namelen = ...
    parms->udp_msghdr.msg_iov = &parms->udp_iovec;
    // DO NOT : parms->udp_msghdr.msg_iovlen = ...
    MALLOC_OR_DIE(struct msghdr*, parms->udp_msghdr.msg_control, ANCILIARY_BUFFER_SIZE, MSGHDR_TAG);
    memcpy(parms->udp_msghdr.msg_control, udp_msghdr->msg_control, ANCILIARY_BUFFER_SIZE);
    // DO NOT : parms->udp_msghdr.msg_controllen = ANCILIARY_BUFFER_SIZE;
    // DO NOT : parms->udp_msghdr.msg_flags = 0;
#endif
    
    parms->timestamp = time(NULL);
    
    threaded_queue_enqueue(&dynupdate_query_service_queue, parms);
    
    return SUCCESS;
}

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/


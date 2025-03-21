/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup
 * @ingroup
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "server_config.h"

#if HAS_PTHREAD_SETNAME_NP
#if DEBUG
#define _GNU_SOURCE 1
#endif
#endif

#include <dnscore/thread.h>

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/threaded_queue.h>
#include <dnscore/service.h>
#include <dnscore/dns_message.h>
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

#if ZDB_HAS_PRIMARY_SUPPORT && ZDB_HAS_DYNUPDATE_SUPPORT

static threaded_queue                       dynupdate_query_service_queue = THREADED_QUEUE_EMPTY;
static uint32_t                             g_dynupdate_query_service_queue_size = 4096;

typedef struct dynupdate_query_service_args dynupdate_query_service_args;

#define DYNUPQSA_TAG 0x41535150554e5944

struct dynupdate_query_service_args
{
    zdb_t         *db;
    dns_message_t *mesg;
    int64_t        timestamp;
    int            sockfd;
};

static const int64_t dynupdate_query_timeout_us = ONE_SECOND_US * 3;

static void          dynupdate_query_service_queue_clear()
{
    dynupdate_query_service_args *parms;
    while((parms = (dynupdate_query_service_args *)threaded_queue_try_dequeue(&dynupdate_query_service_queue)) != NULL)
    {
        dns_message_delete(parms->mesg);
        free(parms);
    }
}

static void dynupdate_query_service_wakeup(struct service_s *desc)
{
    (void)desc;
    threaded_queue_enqueue(&dynupdate_query_service_queue, NULL);
}

static int dynupdate_query_service_thread(struct service_worker_s *worker)
{
    log_info("dynupdate: service started");

    service_set_servicing(worker);

    for(;;)
    {
        if(service_should_reconfigure_or_stop(worker))
        {
            if(!service_should_run(worker))
            {
                break;
            }

            // reconfiguring ...

            dynupdate_query_service_queue_clear();

            service_clear_reconfigure(worker);
            continue;
        }

        /**
         *
         * Needs all the parameters for UDP answer.
         * Needs the time of the query.  If it's too old (> 3s) forget it.
         *
         */

        dynupdate_query_service_args *parms = (dynupdate_query_service_args *)threaded_ringbuffer_cw_dequeue(&dynupdate_query_service_queue);

        if(parms == NULL)
        {
#if DEBUG
            log_debug("dynupdate_query_service_thread: woken up by an empty message");
#endif
            continue;
        }

        dns_message_t *mesg = parms->mesg;

        int64_t        now = timeus();

        if((now - parms->timestamp) <= dynupdate_query_timeout_us)
        {
            /* process */

            zdb_t *database = parms->db;

            /* clone the message */
            /* use the same scheduling mechanism as for TCP */

            log_info("update (%04hx) %{dnsname} %{dnstype} (%{sockaddr})", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg), dns_message_get_sender_sa(mesg));

            ya_result ret = database_update(database, mesg);

            if(ISOK(ret))
            {
                dns_message_set_authoritative_answer(mesg);
            }
            else
            {
                if(dns_message_get_status(mesg) != RCODE_NOTZONE)
                {
                    dns_message_set_authoritative_answer(mesg);
                }
                else
                {
                    dns_message_set_answer(mesg);
                }

                if(dns_message_get_query_type(mesg) == TYPE_SOA)
                {
                    if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                    {
                        log_info("update (%04hx) %{dnsname} temporary failure: zone file must be stored: %r", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), ret);
                    }
                    else
                    {
                        log_warn("update (%04hx) %{dnsname} failed: %r", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), ret);
                    }
                }
                else
                {
                    if(ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY)
                    {
                        log_info("update (%04hx) %{dnsname} %{dnstype} temporary failure: zone file must be stored: %r", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg), ret);
                    }
                    else
                    {
                        log_warn("update (%04hx) %{dnsname} %{dnstype} failed: %r", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg), ret);
                    }
                }
            }

            // local_statistics->udp_fp[message_get_status(mesg)]++;

#if !HAS_DROPALL_SUPPORT

            int32_t sent;

#if DEBUG
            log_debug("dynupdate_query_service_thread: sendto(%d, %p, %d, %d, %{sockaddr}, %d)",
                      parms->sockfd,
                      dns_message_get_buffer_const(mesg),
                      dns_message_get_size(mesg),
                      0,
                      dns_message_get_sender_sa(mesg),
                      dns_message_get_sender_size(mesg));
            log_memdump_ex(g_server_logger, MSG_DEBUG5, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif

            if(FAIL(sent = dns_message_send_udp(mesg, parms->sockfd)))
            {
                ya_result err = sent;

                /** @warning server_st_process_udp needs to be modified */

                log_err("update (%04hx) %{dnsname} %{dnstype} send failed: %r", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg), err);

                dns_message_delete(mesg);
                free(parms);
                continue;
            }

            // local_statistics->udp_output_size_total += sent;

            if(sent != (int32_t)dns_message_get_size(mesg))
            {
                /** @warning server_st_process_udp needs to be modified */
                log_err("short byte count sent (%lli instead of %i)", sent, dns_message_get_size(mesg));
            }
#else
            log_debug("dynupdate_query_service_thread: drop all");
#endif
        }

        dns_message_delete(mesg);
        free(parms);
    }

    service_set_stopping(worker);

    log_info("dynupdate: service stopped");

    return SUCCESS;
}

static struct service_s dynupdate_query_service_handler = UNINITIALIZED_SERVICE;

ya_result               dynupdate_query_service_init()
{
    /// @TODO 20230517 edf -- use initialiser mechanic

    ya_result ret;
    if(ISOK(ret = service_init_ex2(&dynupdate_query_service_handler, dynupdate_query_service_thread, dynupdate_query_service_wakeup, "svrudpdu", 1)))
    {
        threaded_queue_init(&dynupdate_query_service_queue, g_dynupdate_query_service_queue_size);

        log_info("dynupdate: service initialised");
    }
    else
    {
        log_err("dynupdate: failed to initialise service: %r", ret);
    }
    return ret;
}

ya_result dynupdate_query_service_start()
{
    ya_result ret;
    log_debug("dynupdate_query_service_start: starting service");
    ret = service_start(&dynupdate_query_service_handler);
    return ret;
}

ya_result dynupdate_query_service_stop()
{
    ya_result ret = SUCCESS;

    if(service_initialised(&dynupdate_query_service_handler) && service_started(&dynupdate_query_service_handler))
    {
        log_debug("dynupdate_query_service_stop: stopping dynamic update service");

        threaded_queue_try_enqueue(&dynupdate_query_service_queue, NULL); // to wake up the service

        ret = service_stop(&dynupdate_query_service_handler);

        log_debug("dynupdate_query_service_stop: emptying dynamic update queue");

        dynupdate_query_service_queue_clear();

        log_debug("dynamic update service stopped");
    }

    return ret;
}

void dynupdate_query_service_finalise()
{
    if(service_initialised(&dynupdate_query_service_handler))
    {
        dynupdate_query_service_stop();
        service_finalise(&dynupdate_query_service_handler);
        dynupdate_query_service_queue_clear();
        threaded_queue_finalize(&dynupdate_query_service_queue);
    }
}

ya_result dynupdate_query_service_enqueue(zdb_t *db, dns_message_t *mesg, int sockfd)
{
    if(!service_started(&dynupdate_query_service_handler))
    {
        return SERVICE_NOT_RUNNING;
    }

    if(threaded_queue_size(&dynupdate_query_service_queue) == g_dynupdate_query_service_queue_size)
    {
        return MAKE_RCODE_ERROR(RCODE_SERVFAIL); // it will not be used as is, but that's what needs to be said
    }

    dns_message_t *clone = dns_message_dup(mesg);
    if(clone == NULL)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    // ensure the original message cannot be used anymore
    struct dynupdate_query_service_args *parms;
    MALLOC_OBJECT_OR_DIE(parms, dynupdate_query_service_args, DYNUPQSA_TAG);
    parms->db = db;
    parms->mesg = clone;
    parms->timestamp = timeus();
    parms->sockfd = sockfd;

    threaded_queue_enqueue(&dynupdate_query_service_queue, parms);

#if DNSCORE_HAS_TSIG_SUPPORT
    dns_message_tsig_clear_key(mesg);
#endif
    dns_message_set_size(mesg, 0); // resets the message size

    return SUCCESS;
}

void dynupdate_query_service_reset()
{
    if(service_initialised(&dynupdate_query_service_handler) && service_started(&dynupdate_query_service_handler))
    {
        service_reconfigure(&dynupdate_query_service_handler);
        threaded_queue_enqueue(&dynupdate_query_service_queue, NULL); // to wake up the service
    }
}

#endif

/** @} */

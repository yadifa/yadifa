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
 * @defgroup server
 * @ingroup yadifad
 * @brief server
 *
 *  Handles queries made in the CH class (ie: version.*)
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * @note: here we define the variable that is holding the default logger handle for the current source file
 *         Such a handle should NEVER been set in an include file.
 *
 *----------------------------------------------------------------------------*/

#include "server_config.h"
#include "server_config.h"

#if HAS_PTHREAD_SETNAME_NP
#if DEBUG
#define _GNU_SOURCE 1
#endif
#endif

#include <dnscore/thread.h>

#include "server_config.h"

#include <dnscore/file_output_stream.h>
#include <dnscore/logger.h>
#include <dnscore/rfc.h>
#include <dnscore/ctrl_rfc.h>
#include <dnscore/threaded_queue.h>

#include <dnsdb/zdb_zone.h>
#include <dnscore/format.h>
#include <dnscore/dns_packet_writer.h>
#include <dnscore/thread.h>

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "confs.h"
#include "signals.h"
#include <dnscore/acl.h>

#include "zone_desc.h"

#include "ctrl_query_axfr.h"
#include "ctrl_query_message.h"

#include "ctrl.h"
#include "ctrl_zone.h"

#include "database_service.h"

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING

extern logger_handle_t *g_server_logger;

#define CTAXFRQP_TAG 0x5051524658415443

struct ctrl_query_axfr_queue_parm
{
    uint8_t     *origin;
    host_address master;
    uint32_t     tries_count;
};

typedef struct ctrl_query_axfr_queue_parm ctrl_query_axfr_queue_parm;

static threaded_queue                     ctrl_query_axfr_queue = THREADED_QUEUE_EMPTY;
static thread_t                           ctrl_query_axfr_thread_id = 0;
static bool                               ctrl_query_axfr_queue_ready = false;

#if 0
void ctrl_query_axfr_make_query(dns_message_t *mesg)
{    
    dnsname_vector fqdn_vector;
    dnsname_to_dnsname_vector(message_get_canonised_fqdn(mesg), &fqdn_vector);

    log_debug("ctrl: axfr: ctrl_query_axfr_make_query %{dnsname}", message_get_canonised_fqdn(mesg));

    zone_desc_s *zone_desc = zone_getbydnsname(message_get_canonised_fqdn(mesg));

    if(zone_desc_s != NULL)   /**/
    {
        if(host_address_list_contains_ip(zone_desc->primaries, message_get_sender(mesg)))
        {
            dns_packet_writer pw;
            dns_packet_writer_init_from_message(&pw, mesg);
            dns_packet_writer_add_fqdn(&pw, zone_origin(zone_desc));
            dns_packet_writer_add_u16(&pw, TYPE_AXFR);
            dns_packet_writer_add_u16(&pw, CLASS_CTRL);

            ctrl_query_message_add_soa(&pw, zone_desc_s);
            
            MESSAGE_QD(mesg->buffer) = NETWORK_ONE_16;
            
            mesg->send_length = pw.packet_offset;

#if DNSCORE_HAS_TSIG_SUPPORT
            if(message_has_tsig(mesg))  /* NOTE: the TSIG information is in mseg */
            {
                tsig_sign_query(mesg);
            }
            else
            {
                log_err("ctrl: axfr: no TSIG key in query message");
            }
#endif
        }
        else
        {
            log_err("ctrl: axfr: host %{sockaddr} not in the secondaries list", message_get_sender_sa(mesg));

            message_make_error(mesg, RCODE_REFUSED);
        }
    }
    else
    {
        log_err("ctrl: axfr: no such zone");
        
        message_make_error(mesg, RCODE_SERVFAIL);
    }
}
#endif

void ctrl_query_axfr_make_answer(dns_message_t *mesg)
{
    dnsname_vector fqdn_vector;
    dnsname_to_dnsname_vector(message_get_canonised_fqdn(mesg), &fqdn_vector);

    log_debug("ctrl: axfr: ctrl_query_axfr_make_answer of zone %{dnsname}", message_get_canonised_fqdn(mesg));

    zone_desc_s *zone_desc = zone_acquirebydnsname(message_get_canonised_fqdn(mesg));

    if(zone_desc == NULL)
    {
        log_err("ctrl: axfr: no such zone %{dnsname}", message_get_canonised_fqdn(mesg));

        message_make_error(mesg, RCODE_SERVFAIL);

        return;
    }

    if(zone_desc->file_name == NULL)
    {
        log_err("ctrl: axfr: no file name for the zone %{dnsname}", message_get_canonised_fqdn(mesg));

        zone_release(zone_desc);

        message_make_error(mesg, RCODE_SERVFAIL);

        return;
    }

    if(!host_address_list_contains_ip(zone_desc->secondaries, message_get_sender(mesg)))
    {
        log_err("ctrl: axfr: %{sockaddr} not in the secondary list of zone %{dnsname}", message_get_sender(mesg), message_get_canonised_fqdn(mesg));

        zone_release(zone_desc);

        message_make_error(mesg, RCODE_REFUSED);

        return;
    }

    dns_packet_writer pw;
    dns_packet_writer_create(&pw, mesg->buffer, MIN(sizeof(mesg->buffer), U16_MAX));

    dns_packet_writer_add_fqdn(&pw, zone_origin(zone_desc));
    dns_packet_writer_add_u16(&pw, TYPE_AXFR);
    dns_packet_writer_add_u16(&pw, CLASS_CTRL);

    uint16_t an_count = 12;

    // 0
    ctrl_query_message_add_soa(&pw, zone_desc);
    ctrl_query_message_add_u8(&pw, zone_origin(zone_desc), TYPE_ZONE_TYPE, zone_desc->type);
    ctrl_query_message_add_utf8(&pw, zone_origin(zone_desc), TYPE_ZONE_FILE, zone_desc->file_name);

    if(zone_desc->notifies != NULL)
    {
        ctrl_query_message_add_hosts(&pw, zone_origin(zone_desc), TYPE_ZONE_NOTIFY, zone_desc->notifies);
        an_count++;
    }
    // 4
    ctrl_query_message_add_u8(&pw, zone_origin(zone_desc), TYPE_ZONE_DNSSEC, zone_desc->dnssec_mode);

    if(zone_desc->primaries != NULL)
    {
        ctrl_query_message_add_hosts(&pw, zone_origin(zone_desc), TYPE_ZONE_PRIMARY, zone_desc->primaries);
        an_count++;
    }
    if(zone_desc->secondaries != NULL)
    {
        ctrl_query_message_add_hosts(&pw, zone_origin(zone_desc), TYPE_ZONE_SECONDARIES, zone_desc->secondaries);
        an_count++;
    }
    ctrl_query_message_add_u32(&pw, zone_origin(zone_desc), TYPE_SIGINTV, zone_desc->signature.sig_validity_interval);
    // 8
    ctrl_query_message_add_u32(&pw, zone_origin(zone_desc), TYPE_SIGREGN, zone_desc->signature.sig_validity_regeneration);
    ctrl_query_message_add_u32(&pw, zone_origin(zone_desc), TYPE_SIGJITR, zone_desc->signature.sig_validity_jitter);
    ctrl_query_message_add_u32(&pw, zone_origin(zone_desc), TYPE_NTFRC, zone_desc->notify.retry_count);
    ctrl_query_message_add_u32(&pw, zone_origin(zone_desc), TYPE_NTFRP, zone_desc->notify.retry_period);
    // 12
    ctrl_query_message_add_u32(&pw, zone_origin(zone_desc), TYPE_NTFRPI, zone_desc->notify.retry_period_increase);
    ctrl_query_message_add_u8(&pw, zone_origin(zone_desc), TYPE_NTFAUTO, (zone_is_auto_notify(zone_desc)) ? 1 : 0);
    ctrl_query_message_add_soa(&pw, zone_desc);
    // 15

    MESSAGE_SET_QD(mesg->buffer, NETWORK_ONE_16);
    message_set_answer_count(mesg->buffer, an_count);

    mesg->send_length = pw.packet_offset;

    zone_release(zone_desc);

#if DNSCORE_HAS_TSIG_SUPPORT
    if(message_has_tsig(mesg)) /* NOTE: the TSIG information is in mseg */
    {
        tsig_sign_answer(mesg);
    }
    else
    {
        log_err("ctrl: axfr: no TSIG key in query message");
    }
#endif
}

void         ctrl_query_axfr_read_answer(dns_message_t *mesg) { ctrl_zone_generate_from_message(mesg); }

static void *ctrl_query_axfr_thread(void *args)
{
    /*
     * Service model
     *
     * connect to the primary with an AXFR (signed)
     * download the records
     * apply the records (using process_class_ctrl_update)
     * ensure we are a secondary
     */

    thread_set_name("ctrl-query-axfr", 0, 0);

    dns_message_t *mesg = message_newinstance()

        random_ctx rndctx = random_init_auto();

    for(;;)
    {
        if(dnscore_shuttingdown())
        {
            break;
        }

        /* try to read from the queue */

        ctrl_query_axfr_queue_parm *parm = threaded_queue_dequeue(&ctrl_query_axfr_queue);

        if(parm == NULL)
        {
            break;
        }

        /* open the zone_data for origin */

        zone_desc_s *zone_desc = zone_acquirebydnsname(parm->origin);

        if(zone_desc != NULL)
        {
            /*zone_desc->*/

            /*zone_desc->primaries;*/

            /* open the connection */

            /* download the stream */

            /* in case of unspecific error (timeout, unreachable) requeue */

            zone_release(zone_desc);
        }

        uint16_t id = (uint16_t)random_next(rndctx);

        message_make_query(mesg, id, parm->origin, TYPE_AXFR, CLASS_CTRL);

        if(parm->master.tsig != NULL)
        {
            message_sign_query(mesg, parm->master.tsig);
        }

        ya_result return_value;

        if(ISOK(return_value = message_query_tcp(mesg, &parm->master))) /* full query to retrieve ONE TCP message/packet */
        {
            if(message_get_rcode(mesg) == RCODE_OK)
            {
                log_info("ctrl: axfr: updating zone");

                ya_result return_code;

                if(ISOK(return_code = ctrl_zone_generate_from_message(mesg)))
                {
                    ctrl_zone_config_merge_all();
                }
                else
                {
                    log_err("ctrl: axfr: failed: %r", return_code);
                }
            }
            else
            {
                log_err("ctrl: axfr: answer failed: %r", MAKE_RCODE_ERROR(message_get_rcode(mesg)));
            }
        }
        else
        {
            log_err("ctrl: axfr: query failed with: %r", return_value);
        }
    }

    message_free(mesg);

    random_finalize(rndctx);

    return NULL;
}

void ctrl_query_axfr_start()
{
    if(ctrl_query_axfr_thread_id == 0)
    {
        if(!ctrl_query_axfr_queue_ready)
        {
            threaded_queue_init(&ctrl_query_axfr_queue, 65536 /*4096*/);
            ctrl_query_axfr_queue_ready = true;
        }

        if(thread_create(&ctrl_query_axfr_thread_id, ctrl_query_axfr_thread, NULL) != 0)
        {
            /*
             * The system should be able to make a thread at the start of the program.
             */

            exit(EXIT_CODE_THREADCREATE_ERROR);
        }
    }
}

void ctrl_query_axfr_enqueue(uint8_t *origin, host_address *host)
{
    ctrl_query_axfr_queue_parm *parm;

    MALLOC_OBJECT_OR_DIE(parm, ctrl_query_axfr_queue_parm, CTAXFRQP_TAG);
    parm->origin = dnsname_dup(origin);
    memcpy(&parm->master, host, sizeof(host_address));
    parm->master.next = NULL;
    parm->tries_count = 0;
    threaded_queue_enqueue(&ctrl_query_axfr_queue, parm);
}

void ctrl_query_axfr_enqueue_from_message(dns_message_t *mesg)
{
    host_address host;
#if DEBUG
    memset(&host, 0xff, sizeof(host));
#endif
    host.next = NULL;
    host_address_set_with_sockaddr(&host, message_get_sender(mesg));
    host.tsig = message_tsig_get_key(mesg);
    ctrl_query_axfr_enqueue(message_get_canonised_fqdn(mesg), &host);
}

void ctrl_query_axfr_stop()
{
    if(ctrl_query_axfr_thread_id != 0)
    {
        threaded_queue_enqueue(&ctrl_query_axfr_queue, NULL);
        thread_join(ctrl_query_axfr_thread_id, NULL);
        threaded_queue_finalize(&ctrl_query_axfr_queue);
        ctrl_query_axfr_thread_id = 0;
    }
}

#endif // HAS_CTRL_DYNAMIC_PROVISIONING

/** @} */

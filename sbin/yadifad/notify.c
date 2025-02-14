/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @ingroup yadifad
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "server_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

#include <dnscore/rfc.h>
#include <dnscore/logger.h>
#include <dnscore/serial.h>
#include <dnscore/format.h>
#include <dnscore/service.h>
#include <dnscore/async.h>
#include <dnscore/dns_packet_reader.h>
#include <dnscore/tcp_io_stream.h>

#include <dnsdb/zdb.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/zdb_record.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb_zone_load.h>

#include <dnscore/zone_reader_axfr.h>

#include <dnscore/ptr_treemap.h>

#include "notify.h"
#include "zone.h"
#include "database_service.h"
#include "server.h"
#include "server_error.h"

#define NOTIFY_DETAILED_LOG            0
#define NOTIFY_CLEANUP_DUMP            0

#define NOTIFY_RECEIVE_TIMEOUT_SECONDS 2

#ifndef NOTIFY_DETAILED_LOG
#if DEBUG
#define NOTIFY_DETAILED_LOG 1
#else
#define NOTIFY_DETAILED_LOG 0
#endif
#endif

#if NOTIFY_DETAILED_LOG
#pragma message("WARNING: NOTIFY_DETAILED_LOG is not set to 0")
#endif

#if HAS_CTRL
#include "ctrl.h"
#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING
#include "ctrl_query_axfr.h"
#endif
#endif

#define NOTFYMSG_TAG 0x47534d5946544f4e
#define MESGDATA_TAG 0x415441444753454d

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE          g_server_logger

#define NOTIFY_MESSAGE_TYPE_NOTIFY 1
#define NOTIFY_MESSAGE_TYPE_ANSWER 2
#define NOTIFY_MESSAGE_TYPE_DOMAIN 3
#define NOTIFY_MESSAGE_TYPE_CLEAR  4

#define MESSAGE_QUERY_TIMEOUT      3
#define MESSAGE_QUERY_TRIES        3

#define MESSAGE_QUERY_TIMEOUT_US   (MESSAGE_QUERY_TIMEOUT * 1000000)

static struct thread_pool_s *notify_thread_pool = NULL;

static int                   send_socket4 = -1;
static int                   send_socket6 = -1;

static struct service_s      notify_handler = UNINITIALIZED_SERVICE;
static async_queue_t         notify_handler_queue;
static initialiser_state_t   notify_service_init_state = INITIALISE_STATE_INIT;

#if __windows__
static atomic_int notify_replies_expected_v4 = 0;
static atomic_int notify_replies_expected_v6 = 0;
#endif

typedef struct message_query_summary message_query_summary;

#define MSGQSUMR_TAG 0x524d55535147534d

struct message_query_summary
{
    host_address_t        *host;
    message_query_summary *next; /* this pointer is used to list the items, ie: for deletion */
    // to discard
    int64_t expire_epoch_us;
    // for answers, id has to be kept
    uint16_t id;
    // for answers, ip/port should be kept but they are already in the host list (sa.sa4,sa.sa6,addrlen)
    // times we send the udp packet before giving up
    int8_t tries;
    // for signed answers, these have to be kept
    uint8_t mac_size; // mesg->tsig.mac_size;
    uint8_t fqdn[256];
    uint8_t mac[64]; // mesg->tsig.mac;
};

static void message_query_summary_init(message_query_summary *mqs, uint16_t id, host_address_t *host, const dns_message_t *mesg)
{
    yassert(mqs != NULL);

    // key
    mqs->host = host_address_copy(host);
    mqs->next = NULL;
    mqs->expire_epoch_us = timeus() + MESSAGE_QUERY_TIMEOUT_US;
    mqs->id = id;
    // payload
    mqs->tries = MESSAGE_QUERY_TRIES;

    dnsname_copy(mqs->fqdn, dns_message_get_canonised_fqdn(mesg));

#if DNSCORE_HAS_TSIG_SUPPORT

    mqs->mac_size = dns_message_tsig_mac_get_size(mesg);

    if(mqs->mac_size > 0)
    {
        dns_message_tsig_mac_copy(mesg, mqs->mac);
    }
#endif
}

static void message_query_summary_clear(message_query_summary *mqs)
{
#if DEBUG
    log_debug("notify: clearing query for %{hostaddr}", mqs->host);
#endif
    host_address_delete(mqs->host);
#if DEBUG
    memset(mqs, 0xfe, sizeof(message_query_summary));
#endif
}

static void message_query_summary_delete(message_query_summary *mqs)
{
#if DEBUG
    log_debug("notify: deleting query for %{hostaddr}", mqs->host);
#endif
    message_query_summary_clear(mqs);
    ZFREE_OBJECT(mqs);
}

static int32_t message_query_summary_compare(const void *va, const void *vb)
{
    message_query_summary *a = (message_query_summary *)va;
    message_query_summary *b = (message_query_summary *)vb;

    int32_t                d;

    d = (int32_t)a->id - (int32_t)b->id;

    if(d == 0)
    {
        d = host_address_compare(a->host, b->host);

        if(d == 0)
        {
            d = dnsname_compare(a->fqdn, b->fqdn);
        }
    }

    return d;
}

typedef struct notify_message notify_message;

struct notify_message_domain
{
    uint8_t type;
};

struct notify_message_clear
{
    uint8_t type;
};

struct notify_message_notify
{
    uint8_t         type;
    uint8_t         repeat_countdown;
    uint8_t         repeat_period;
    uint8_t         repeat_period_increase;
    uint32_t        epoch;
    host_address_t *hosts_list; /* 64 bits aligned */
#if DNSCORE_HAS_TSIG_SUPPORT
    message_tsig_t tsig;
#endif
    uint16_t ztype;
    uint16_t zclass;
};

struct notify_message_answer
{
    uint8_t         type;
    uint8_t         rcode;
    bool            aa;
    uint8_t         r2;
    host_address_t *host;
    dns_message_t  *message; /* only used if the message is signed */
};

struct notify_message
{
    uint8_t *origin;

    union
    {
        uint8_t                      type;
        struct notify_message_notify notify;
        struct notify_message_answer answer;
        struct notify_message_domain domain;
        struct notify_message_clear  clear;
    } payload;
};

static bool notify_secondaries_convert_domain_to_notify(notify_message *notifymsg);

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

static notify_message *notify_message_newinstance(const uint8_t *origin, uint8_t type)
{
    notify_message *notifymsg;
    ZALLOC_OBJECT_OR_DIE(notifymsg, notify_message, NOTFYMSG_TAG);
    notifymsg->origin = dnsname_zdup(origin);
    notifymsg->payload.type = type;

#if DEBUG
    log_debug("notify_message_newinstance({%{dnsname}@%p, %i}@%p)", notifymsg->origin, notifymsg->origin, notifymsg->payload.type, notifymsg);
#endif

    return notifymsg;
}

/**
 *
 * Queue a message telling a secondary has answered to a notify
 *
 * @param origin the domain of the zone
 * @param sa the address of the source
 * @param rcode rcode part of the query
 * @param aa aa flag value in the query
 */

static void notify_secondaryanswer(const dns_message_t *mesg)
{
#if NOTIFY_DETAILED_LOG
    log_debug("notify_secondaryanswer(%{dnsname} %{sockaddr})", message_get_canonised_fqdn(mesg), message_get_sender_sa(mesg));
#endif

    if(dnscore_shuttingdown())
    {
        return;
    }

    if(initialise_state_initialised(&notify_service_init_state))
    {
#if DNSCORE_HAS_TSIG_SUPPORT
        const struct tsig_key_s *mesg_tsig_key = dns_message_tsig_get_key(mesg); // pointer to the structure used for TSIG, to be used in relevant cases
        dns_message_t           *clone = NULL;
        if(mesg_tsig_key != NULL)
        {
            clone = dns_message_dup(mesg);
            if(clone == NULL)
            {
                return; // BUFFER_WOULD_OVERFLOW;
            }
        }
#endif

        const uint8_t         *origin = dns_message_get_canonised_fqdn(mesg);
        const socketaddress_t *sa = dns_message_get_sender(mesg);
        uint8_t                rcode = dns_message_get_rcode(mesg);
        bool                   aa = dns_message_is_authoritative(mesg);

        notify_message        *notifymsg = notify_message_newinstance(origin, NOTIFY_MESSAGE_TYPE_ANSWER);

        notifymsg->payload.answer.rcode = rcode;
        notifymsg->payload.answer.aa = aa;
        notifymsg->payload.answer.host = host_address_new_instance_socketaddress(sa);

#if DNSCORE_HAS_TSIG_SUPPORT

        // if there is a TSIG ...

        if(dns_message_tsig_get_key(mesg) != NULL)
        {
            notifymsg->payload.answer.message = clone;
            notifymsg->payload.answer.host->tsig = mesg_tsig_key;
        }
        else
        {
            notifymsg->payload.answer.message = NULL;
            notifymsg->payload.answer.host->tsig = NULL;
        }
#endif

        async_message_t *async = async_message_new_instance();
        async->id = 0;
        async->args = notifymsg;
        async->handler = NULL;
        async->handler_args = NULL;
        async_message_call(&notify_handler_queue, async);
    }
    else
    {
        log_err("notify: service not initialised");
    }
}

static bool notify_primaryquery_read_soa(const uint8_t *origin, dns_packet_reader_t *reader, uint32_t *serial)
{
    ya_result return_value;

    uint8_t   tmp[DOMAIN_LENGTH_MAX];

    /* read and expect an SOA */

    if(ISOK(dns_packet_reader_read_fqdn(reader, tmp, sizeof(tmp))))
    {
        if(dnsname_equals(tmp, origin))
        {
            struct type_class_ttl_rdlen_s tctr;

            if(dns_packet_reader_read(reader, &tctr, 10) == 10) // exact
            {
                if((tctr.rtype == TYPE_SOA) && (tctr.rclass == CLASS_IN))
                {
                    if(ISOK(return_value = dns_packet_reader_skip_fqdn(reader)))
                    {
                        if(ISOK(return_value = dns_packet_reader_skip_fqdn(reader)))
                        {
                            if(dns_packet_reader_read(reader, tmp, 4) == 4) // exact
                            {
                                *serial = ntohl(GET_U32_AT_P(tmp));

                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    return false;
}

#define NTFYMQTA_TAG 0x4154514d5946544e

struct notify_primaryquery_thread_args
{
    uint8_t *origin;
    uint32_t serial;
    bool     serial_set;
};

typedef struct notify_primaryquery_thread_args notify_primaryquery_thread_args;

static void                                    notify_primaryquery_thread(void *args_)
{
    notify_primaryquery_thread_args *args = (notify_primaryquery_thread_args *)args_;

    /* get the zone descriptor for that domain */

    zone_desc_t *zone_desc = zone_acquirebydnsname(args->origin);

    ya_result    return_value;

    if(zone_desc == NULL)
    {
        log_err("notify: secondary: %{dnsname}: zone not configured", args->origin);
        dnsname_zfree(args->origin);
        ZFREE_OBJECT(args);
        return;
    }

    mutex_lock(&zone_desc->lock);
    zone_clear_status(zone_desc, ZONE_STATUS_NOTIFIED);
    mutex_unlock(&zone_desc->lock);

    log_debug("notify: secondary: %{dnsname}: processing notify from primary", args->origin);

    /* do an SOA query to the primary to retrieve the serial (wait) */

    if(!args->serial_set)
    {
        log_debug("notify: secondary: %{dnsname}: querying the primary at %{hostaddr} for SOA", args->origin, zone_desc->primaries);

        zone_lock(zone_desc, ZONE_LOCK_READONLY);
        host_address_t *zone_desc_primaries = host_address_copy_list(zone_desc->primaries);
        zone_unlock(zone_desc, ZONE_LOCK_READONLY);

        return_value = dns_message_query_serial(args->origin, zone_desc_primaries, &args->serial);

        host_address_delete_list(zone_desc_primaries);

        if(ISOK(return_value)) // multi-primary
        {
            args->serial_set = true;

            log_debug("notify: secondary: %{dnsname}: the primary at %{hostaddr} has serial %u", args->origin, zone_desc->primaries, args->serial);
        }
        else
        {
            /* we didn't got the serial */

            log_debug("notify: secondary: %{dnsname}: SOA query to the primary at %{hostaddr} failed: %r", args->origin, zone_desc->primaries, return_value);

            // this will fall-back to doing an XFR
        }
    }
    else
    {
        log_debug("notify: secondary: %{dnsname}: the primary at %{hostaddr} has serial %u", args->origin, zone_desc->primaries, args->serial);
    }

    uint32_t current_serial;

    /* get the zone of the domain */

    zdb_zone_t *dbzone = zdb_acquire_zone_read_from_fqdn(g_config->database, args->origin);

    if(dbzone != NULL)
    {
        /* lock it for the XFR (it's a writer, so no other writer allowed) */

        log_debug("notify: secondary: %{dnsname}: trying to lock for a transfer", args->origin);

        if(zdb_zone_trylock(dbzone, ZDB_ZONE_MUTEX_XFR))
        {
            /* get the current serial of the zone */

            if(ISOK(zdb_zone_getserial(dbzone, &current_serial))) // zone is locked
            {
                log_debug("notify: secondary: %{dnsname}: current serial is %u", args->origin, current_serial);

                /*
                 * If the serial on the "primary" is lower,
                 * nothing has to be done except a note on the log.
                 *
                 * If we didn't got the serial of course, we can only ask the primary.
                 */

                if(args->serial_set)
                {
                    if(serial_lt(args->serial, current_serial))
                    {
                        /* do nothing at all */

                        log_debug(
                            "notify: secondary: %{dnsname}: serial on this secondary is higher (%u) than on the "
                            "notification from primary (%u)",
                            zone_origin(zone_desc),
                            current_serial,
                            args->serial);
                    }
                    else if(serial_gt(args->serial, current_serial))
                    {
                        /* download (and apply) the incremental change  */

                        log_info("notify: secondary: %{dnsname}: scheduling an IXFR from %u", zone_origin(zone_desc), current_serial);

                        database_zone_ixfr_query(zone_origin(zone_desc));
                    }
                    else
                    {
                        /* nothing to do but mark the zone as being refreshed */

                        log_info("notify: secondary: %{dnsname}: serial matches the primaries' (%u)", zone_origin(zone_desc), current_serial);

                        zdb_zone_clear_invalid(dbzone);
                        zone_desc->refresh.refreshed_time = zone_desc->refresh.retried_time = time(NULL);

                        zdb_zone_release_unlock(dbzone, ZDB_ZONE_MUTEX_XFR);                              /* MUST be unlocked here because ... */
                        database_zone_refresh_maintenance(g_config->database, zone_origin(zone_desc), 0); /* ... this will try to lock */

                        dnsname_zfree(args->origin);
                        ZFREE_OBJECT(args);

                        log_debug("notify: secondary: %{dnsname}: primary notify processing done", zone_origin(zone_desc));

                        zone_release(zone_desc);

                        return;
                    }
                }
                else
                {
                    log_warn(
                        "notify: secondary: %{dnsname}: the serial of the primary has not been obtained, trying an "
                        "incremental transfer",
                        zone_origin(zone_desc));

                    database_zone_ixfr_query(zone_origin(zone_desc));
                }
            }
            else // no soa at apex ... zone needs to be downloaded ...
            {
                // the zone is a placeholder

                if((zone_get_status(zone_desc) & (ZONE_STATUS_LOAD | ZONE_STATUS_LOADING | ZONE_STATUS_DOWNLOADED)) == 0)
                {
                    log_debug("notify: secondary: %{dnsname}: downloading a new copy of the zone", args->origin);
                    database_zone_axfr_query(zone_origin(zone_desc));
                }
                else
                {
                    log_debug("notify: secondary: %{dnsname}: still busy loading the zone", args->origin);
                }
            }

            zdb_zone_release_unlock(dbzone, ZDB_ZONE_MUTEX_XFR);
        }
        else // could not lock with ZDB_ZONE_MUTEX_XFR
        {
            /*
             * The zone has been locked already ? give up ...
             */

            mutex_lock(&dbzone->lock_mutex);
            uint8_t dbzone_lock_owner = dbzone->lock_owner;
            mutex_unlock(&dbzone->lock_mutex);

            log_info("notify: secondary: %{dnsname}: already locked (%x)", args->origin, dbzone_lock_owner);

            zdb_zone_release(dbzone);

            database_zone_refresh_maintenance(g_config->database, args->origin, time(NULL) + 5);
        }
    }
    else
    {
        /*
         * Ask for an AXFR of the zone
         */

        log_info("notify: secondary: %{dnsname}: scheduling an AXFR", zone_origin(zone_desc));

        database_zone_axfr_query(zone_origin(zone_desc));
    } /* AXFR */

    dnsname_zfree(args->origin);
    ZFREE_OBJECT(args);

    log_debug("notify: secondary: %{dnsname}: primary notify processing done", zone_origin(zone_desc));

    zone_release(zone_desc);
}

/**
 * The purely network part of the sending of a notify udp packet
 *
 * @param ha        destination, TSIG supported
 * @param msgdata   a message to be used for message construction
 * @param id        the message id
 * @param origin    origin
 * @param ntype     type
 * @param nclass    class
 * @return
 */

static ya_result notify_send(host_address_t *ha, dns_message_t *mesg, uint16_t id, const uint8_t *origin, uint16_t ntype, uint16_t nclass)
{
    if((ha == NULL) || (mesg == NULL) || (origin == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

#if DEBUG
    log_debug("notify: send(%{hostaddr}, %p, %hx, %{dnsname}, %{dnstype}, %{dnsclass})", ha, mesg, id, origin, &ntype, &nclass);
#endif

    socketaddress_t sa;

    ya_result       return_code;

    dns_message_make_notify(mesg, id, origin, ntype, nclass);

#if DNSCORE_HAS_TSIG_SUPPORT
    if((ha->tsig != NULL) && (ha->tsig->name != NULL))
    {
        // log_info("notify: %{dnsname}: signing message for %{sockaddr} with key %{dnsname}", origin, &sa,
        // ha->tsig->name);
        if(FAIL(return_code = dns_message_sign_query(mesg, ha->tsig)))
        {
            log_err("notify: %{dnsname}: unable to sign message for %{sockaddr} with key %{dnsname}: %r", FQDNNULL(origin), &sa, FQDNNULL(ha->tsig->name), return_code);

            return return_code;
        }
    }
#endif

    if(ISOK(return_code = host_address2sockaddr(ha, &sa)))
    {

#if DNSCORE_HAS_TSIG_SUPPORT
        if(ha->tsig == NULL)
        {
#endif

#if !DEBUG
            log_debug("notify: %{dnsname}: notifying %{sockaddr}", origin, &sa.sa);
#else
        log_info("notify: %{dnsname}: notifying %{sockaddr} with %{dnstype} %{dnsclass} (debug)", origin, &sa.sa, &ntype, &nclass);
#endif

#if DNSCORE_HAS_TSIG_SUPPORT
        }
        else
        {
#if !DEBUG
            log_debug("notify: %{dnsname}: notifying %{sockaddr} (key=%{dnsname})", origin, &sa.sa, ha->tsig->name);
#else
            log_info("notify: %{dnsname}: notifying %{sockaddr} (key=%{dnsname}) with (%{dnstype} %{dnsclass}) (debug)", origin, &sa.sa, ha->tsig->name, &ntype, &nclass);
#endif
        }
#endif

        int s = -1;
        int addrlen;

        switch(sa.sa.sa_family)
        {
            case AF_INET:
            {
                s = send_socket4;
                addrlen = sizeof(sa.sa4);
                break;
            }
            case AF_INET6:
            {
                s = send_socket6;
                addrlen = sizeof(sa.sa6);
                break;
            }
        }

        if(s >= 0)
        {
            // s >= 0 => addrlen is initialised
#if DEBUG
            log_debug("notify: sendto(%d, %p, %d, %d, %{sockaddr}, %d)", s, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0, &sa.sa, addrlen);
            log_memdump_ex(g_server_logger, MSG_DEBUG5, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif
            if(ISOK(return_code = sendto(s, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 0, &sa.sa, addrlen)))
            {
                log_debug("notify: %{dnsname}: sent %i bytes to %{sockaddr}", origin, dns_message_get_size(mesg), &sa.sa);
            }
            else
            {
                int err = errno;

                if(err != ENOTSOCK)
                {
                    log_err("notify: %{dnsname}: failed to send notify to %{sockaddr}: %r", origin, &sa.sa, MAKE_ERRNO_ERROR(err));
                }
            }
        }
        else
        {
            return_code = MAKE_ERRNO_ERROR(ENOTSOCK); // wrong socket

            // if we cannot get the reply, no point trying to send the query

            log_err("notify: %{dnsname}: no listening interface can receive from %{sockaddr}", origin, &sa.sa);
        }
    }
    else
    {
        log_err("notify: %{dnsname}: unable to convert '%{hostaddr}' to an address", origin, ha);
    }

    return return_code;
}

/**
 *
 * Uses a thread to handle the notify from the primary (notify_primaryquery_thread)
 *
 * The message is a NOTIFY SOA IN
 * The reader points into the buffer of the message and is exactly after the Q section.
 *
 *
 * @param database the database
 * @param mesg the message
 * @param reader packet reader into the above message, positioned right after the Q section
 *
 * @return an error code
 */

static ya_result notify_process_primaryquery_in_enqueue(const dns_message_t *mesg, dns_packet_reader_t *reader)
{
    ya_result return_value;

    uint32_t  serial = 0; // to silence gcc : this was not a bug
    bool      serial_set = false;

    if(dns_message_get_answer_count_ne(mesg) != 0)
    {
        serial_set = notify_primaryquery_read_soa(dns_message_get_canonised_fqdn(mesg), reader, &serial);
    }

    notify_primaryquery_thread_args *args;

    ZALLOC_OBJECT_OR_DIE(args, notify_primaryquery_thread_args, NTFYMQTA_TAG);

    args->origin = dnsname_zdup(dns_message_get_canonised_fqdn(mesg));
    args->serial = serial;
    args->serial_set = serial_set;

    return_value = thread_pool_enqueue_call(notify_thread_pool, notify_primaryquery_thread, args, NULL, "notify: secondary");

    return return_value;
}

static ya_result notify_process_primaryquery_in(dns_message_t *mesg, dns_packet_reader_t *reader)
{
    zone_desc_t *zone_desc;
    ya_result    return_value = SUCCESS;

    zone_desc = zone_acquirebydnsname(dns_message_get_canonised_fqdn(mesg));

    if(zone_desc != NULL)
    {
        dns_message_set_authoritative_answer(mesg);

        if(zone_desc->type == ZT_SECONDARY)
        {
            if(dns_message_has_tsig(mesg))
            {
                log_info(
                    "notify: secondary: %{dnsname}: %{sockaddr} sent a notification query, class %{dnsclass}, key "
                    "%{dnsname}",
                    dns_message_get_canonised_fqdn(mesg),
                    dns_message_get_sender_sa(mesg),
                    dns_message_get_query_class_ptr(mesg),
                    dns_message_tsig_get_name(mesg));
            }
            else
            {
                log_info("notify: secondary: %{dnsname}: %{sockaddr} sent a notification query, class %{dnsclass}", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender_sa(mesg), dns_message_get_query_class_ptr(mesg));
            }

#if ZDB_HAS_ACL_SUPPORT
            if(ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_notify)))
            {
                /* notauth */

                if(dns_message_has_tsig(mesg))
                {
                    log_notice("notify: secondary: %{dnsname}: %{sockaddr} key %{dnsname}: not authorised", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender_sa(mesg), dns_message_tsig_get_name(mesg));
                }
                else
                {
                    log_notice("notify: secondary: %{dnsname}: %{sockaddr}: not authorised", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender_sa(mesg));
                }

                dns_message_set_status(mesg, FP_NOTIFY_REJECTED);
                dns_message_update_answer_status(mesg);

                zone_release(zone_desc);

                return ACL_NOTIFY_REJECTED;
            }
#endif
            if(!zone_isfrozen(zone_desc))
            {
                mutex_lock(&zone_desc->lock);
                uint32_t zone_status_notified = zone_get_set_status(zone_desc, ZONE_STATUS_NOTIFIED);
                mutex_unlock(&zone_desc->lock);

                if(zone_status_notified == 0)
                {
                    return_value = notify_process_primaryquery_in_enqueue(mesg, reader); // thread-safe
                }
                // else it's already enqueued for notification
            }
            else
            {
                log_info("notify: secondary: %{dnsname}: %{sockaddr}: zone is frozen", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender_sa(mesg));
            }
        } /* type = SECONDARY */
        else
        {
            /* type = PRIMARY ? */

            // note: a secondary can also be a primary ... do not cut this

            log_info("notify: %{dnsname}: %{sockaddr}: host sent a notification query for primary zone ", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender_sa(mesg));

            dns_message_set_status(mesg, FP_SECONDARY_NOTIFIES_PRIMARY);

            return_value = NOTIFY_QUERY_TO_PRIMARY;
        }
    }
    else
    {
        log_notice("notify: %{dnsname}: %{sockaddr}: host sent a notification query for an unknown zone", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender_sa(mesg));

        dns_message_set_status(mesg, FP_NOTIFY_UNKNOWN_ZONE);

        return_value = NOTIFY_QUERY_TO_UNKNOWN;
    }

    dns_message_update_answer_status(mesg);

    zone_release(zone_desc);

    return return_value;
}

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING
#error "zone_isidle must be enhanced like here above"
static ya_result notify_process_primaryquery_ctrl(zdb *database, dns_message_t *mesg, dns_packet_reader_t *reader)
{
    zone_desc_s *zone_desc;
    ya_result    return_value;

    // the query MUST be signed with one of the primaries keys

    if(message_tsig_get_key(mesg) == NULL)
    {
#if DEBUG
        log_err("ctrl: notify: message is not signed");
#endif
        // not signed
        message_set_answer(mesg);
        message_set_status(mesg, RCODE_REFUSED);
        return ERROR; // dynamic provisioning
    }

    // message_tsig_get_key(mesg) must be one of the primaries

    if(!ctrl_is_ip_tsig_primary(message_get_sender(mesg), message_tsig_get_key(mesg)))
    {
        // unallowed signature
#if DEBUG
        log_err("ctrl: notify: not from a known primary");
#endif
        message_set_answer(mesg);
        message_set_status(mesg, RCODE_REFUSED);
        return RCODE_ERROR_CODE(RCODE_REFUSED);
    }

    zone_desc = zone_acquirebydnsname(message_get_canonised_fqdn(mesg));

    if(zone_desc == NULL)
    {
        ctrl_query_axfr_enqueue_from_message(mesg);

        message_set_answer(mesg);

        return mesg->send_length;
    }

    message_set_authoritative(mesg);

    if(zone_desc->type == ZT_SECONDARY)
    {
        log_info("notify: notification query for secondary zone %{dnsname}", message_get_canonised_fqdn(mesg));

#if ZDB_HAS_ACL_SUPPORT
        if(ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_notify)))
        {
            /* notauth */

            log_warn("notify: not authorised");

            message_set_status(mesg, FP_NOTIFY_REJECTED);

            return ACL_NOTIFY_REJECTED;
        }
#endif
        if(host_address_list_contains_ip(zone_desc->primaries, message_get_sender(mesg)))
        {
            message_set_authoritative_answer(mesg) | AA_BITS;

            if(zone_isidle(zone_desc))
            {
                return_value = notify_primaryquery(mesg, reader); // thread-safe

                return return_value;
            }
            else
            {
                log_info("notify: secondary: zone %{dnsname} is busy", zone_origin(zone_desc));
                /* or not */
                database_zone_refresh_maintenance(g_config->database, zone_origin(zone_desc), 0); // thread-safe

                return SUCCESS;
            }
        }
        else
        {
            log_warn("notify: secondary: notification from %{sockaddr}: not in the primary list for zone %{dnsname}", message_get_sender_sa(mesg), message_get_canonised_fqdn(mesg));

            message_set_status(mesg, FP_NONPRIMARY_NOTIFIES_SECONDARY);
            return_value = NOTIFY_QUERY_FROM_UNKNOWN;
        }
    } /* type = SECONDARY */
    else
    {
        /* type = PRIMARY ? */

        log_warn("notify: notification query for primary zone %{dnsname}", message_get_canonised_fqdn(mesg));

        message_set_status(mesg, FP_SECONDARY_NOTIFIES_PRIMARY);
        return_value = NOTIFY_QUERY_TO_PRIMARY;
    }

    zone_release(zone_desc);

    return return_value;
}

#endif // HAS_CTRL_DYNAMIC_PROVISIONING

/** @brief Handle a notify from the primary (or another secondary)
 *
 *  @param database : the database
 *  @param mesg     : the input message
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result notify_process(dns_message_t *mesg)
{
    /* rfc1996
     * 3.7:
     *  A NOTIFY request has QDCOUNT>0, ANCOUNT>=0, AUCOUNT>=0,
     *  ADCOUNT>=0.  If ANCOUNT>0, then the answer section represents an
     *  unsecure hint at the new RRset for this <QNAME,QCLASS,QTYPE>
     */

    if(!dns_message_is_query(mesg))
    {
        /*
         * It's an answer from a secondary (we are the primary)
         * It works if we are the primary for the zone AND we sent a notify.
         * Else we discard.
         */

        log_debug1("notify: %{dnsname}: %{sockaddr}: processing notification reply", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender_sa(mesg));

        notify_secondaryanswer(mesg); // thread-safe

        return SUCCESS;
    }
    else
    {
        /*
         * It's a notification by the "primary" ... (or in the case of an AXFR/CTRL a request to be notified of all
         * dynamic zones) It works if we are a secondary for the zone. Else we discard.
         */

        ya_result return_value;

        log_debug1("notify: %{dnsname}: %{sockaddr}: processing notification", dns_message_get_canonised_fqdn(mesg), dns_message_get_sender_sa(mesg));

        dns_message_set_answer(mesg);

        dns_packet_reader_t pr;
        dns_packet_reader_init_from_message(&pr, mesg);

        uint8_t tmp[DOMAIN_LENGTH_MAX];

        if(ISOK(return_value = dns_packet_reader_read_fqdn(&pr, tmp, sizeof(tmp))))
        {
            uint16_t rtype;

            if(ISOK(return_value = dns_packet_reader_read_u16(&pr, &rtype)))
            {
                uint16_t rclass;

                if(ISOK(return_value = dns_packet_reader_read_u16(&pr, &rclass)))
                {
                    switch(rclass)
                    {
                        case CLASS_IN:
                        {
                            /*
                             * Master sent an notify for the IN class
                             */

                            notify_process_primaryquery_in(mesg, &pr);

                            break;
                        }

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING
                        case CLASS_CTRL:
                        {
                            switch(message_get_query_type(mesg))
                            {
                                case TYPE_SOA:
                                {
                                    if((g_config->server_flags & SERVER_FL_DYNAMIC_PROVISIONING) != 0)
                                    {
                                        notify_process_primaryquery_ctrl(database, mesg, &pr);
                                    }
                                    else
                                    {
                                        log_err("notify: dynamic provisioning disabled");
                                        message_set_status(mesg, RCODE_NOTIMP);
                                    }
                                    break;
                                }
                                case TYPE_AXFR:
                                {
                                    message_set_authoritative_answer(mesg) | AA_BITS;

                                    host_address secondary;
#if DEBUG
                                    memset(&secondary, 0xff, sizeof(secondary));
#endif
                                    secondary.next = NULL;
                                    secondary.tsig = message_tsig_get_key(mesg);
                                    if(ISOK(return_value = host_address_set_with_sockaddr(&secondary, message_get_sender(mesg))))
                                    {
                                        ctrl_notify_secondary(&secondary);
                                        message_set_status(mesg, RCODE_NOERROR);
                                    }
                                    else
                                    {
                                        log_err("notify: unsupported address: %r", return_value);
                                        message_set_status(mesg, RCODE_SERVFAIL);
                                    }
                                    break;
                                }
                                default:
                                {
                                    /* unsupported protocol */
                                    log_err("notify: protocol not supported: %r", return_value);
                                    message_set_status(mesg, RCODE_NOTIMP);
                                    break;
                                }
                            }

                            message_transform_to_error(mesg);
                            break;
                        }
#endif // HAS_CTRL_DYNAMIC_PROVISIONING
                        default:
                        {
                            dns_message_make_error(mesg, FP_NOT_SUPP_CLASS);
                            break;
                        }
                    }
                }
            }
        }

#if DNSCORE_HAS_TSIG_SUPPORT
        if(dns_message_has_tsig(mesg)) /* NOTE: the TSIG information is in mseg */
        {
            tsig_sign_answer(mesg);
        }
#endif

        return return_value;
    }
}

static void notify_message_free(notify_message *notifymsg)
{
    if(notifymsg == NULL)
    {
        return;
    }

#if DEBUG
    log_debug("notify_message_free({%{dnsname}@%p, %i}@%p)", notifymsg->origin, notifymsg->origin, notifymsg->payload.type, notifymsg);
#endif

    if(notifymsg->origin != NULL)
    {
        dnsname_zfree(notifymsg->origin);
        notifymsg->origin = NULL;
    }

    switch(notifymsg->payload.type)
    {
        case NOTIFY_MESSAGE_TYPE_NOTIFY:
        {
            host_address_delete_list(notifymsg->payload.notify.hosts_list);
            break;
        }
        case NOTIFY_MESSAGE_TYPE_ANSWER:
        {
#if DEBUG
            log_debug("notify_message_free(%p) host_address_delete(%p)", notifymsg, notifymsg->payload.answer.host);
            debug_log_stacktrace(g_server_logger, MSG_DEBUG7, "notify_message_free:host_address_delete");
#endif
            host_address_delete(notifymsg->payload.answer.host);
            if(notifymsg->payload.answer.message != NULL)
            {
                dns_message_delete(notifymsg->payload.answer.message); // message_data => message_free
            }
            break;
        }
        case NOTIFY_MESSAGE_TYPE_DOMAIN:
        {
            break;
        }
        case NOTIFY_MESSAGE_TYPE_CLEAR:
        {
            break;
        }
        default:
        {
            log_debug("notify_message_free(%p) invalid notify message type %x", notifymsg, notifymsg->payload.type);
            debug_log_stacktrace(g_server_logger, MSG_DEBUG7, "notify_message_free:host_address_delete");

            break;
        }
    }
#if DEBUG
    memset(notifymsg, 0xff, sizeof(notify_message));
#endif
    ZFREE_OBJECT(notifymsg);
}

static int notify_process_dnsname_compare(const void *node_a, const void *node_b)
{
    const uint8_t *m_a = (const uint8_t *)node_a;
    const uint8_t *m_b = (const uint8_t *)node_b;

    return dnsname_compare(m_a, m_b);
}

static void notify_ipv4_receiver_service(struct service_worker_s *worker)
{
    log_info("notify: notification service IPv4 receiver started (socket %i)", send_socket4);

    dns_message_t *mesg = dns_message_new_instance();
    tcp_set_recvtimeout(send_socket4, NOTIFY_RECEIVE_TIMEOUT_SECONDS, 0); /* half a second for UDP is a lot ... */

    while(service_should_run(worker))
    {
        ya_result ret;
#if __windows__
        int are_notify_replies_expected = atomic_load(&notify_replies_expected_v4);

        if(are_notify_replies_expected == 0)
        {
            sleep(1);
            continue;
        }
#endif
        dns_message_recv_udp_reset(mesg);
        dns_message_reset_control_size(mesg);

        ret = dns_message_recv_udp(mesg, send_socket4);

        if(ret > 0)
        {
            // process secondary answer
            if(ISOK(ret = dns_message_process_lenient(mesg)))
            {
#if NOTIFY_DETAILED_LOG
                log_debug("notify_ipv4_receiver_service(%{dnsname} %{sockaddr})", message_get_canonised_fqdn(mesg), message_get_sender_sa(mesg));
#endif
                notify_secondaryanswer(mesg);
            }
            else
            {
                log_err("notify_ipv4_receiver_service: processing message: %r", ret);
            }
        }
        else
        {
            ret = ERRNO_ERROR;
            if((ret == MAKE_ERRNO_ERROR(EAGAIN)) || (ret == MAKE_ERRNO_ERROR(EINTR)))
            {
#if NOTIFY_DETAILED_LOG
                log_debug("notify_ipv4_receiver_service: %r", ret);
#endif
            }
            else
            {
                log_err("notify_ipv4_receiver_service: %r", ret);
                sleep(1);
            }
        }
    }

    dns_message_delete(mesg);

    log_info("notify: notification service IPv4 receiver stopped");
}

static void notify_ipv6_receiver_service(struct service_worker_s *worker)
{
    log_info("notify: notification service IPv6 receiver started (socket %i)", send_socket6);

    dns_message_t *mesg = dns_message_new_instance();
    tcp_set_recvtimeout(send_socket6, NOTIFY_RECEIVE_TIMEOUT_SECONDS, 0); /* half a second for UDP is a lot ... */

    while(service_should_run(worker))
    {
        ya_result ret;
#if __windows__
        int are_notify_replies_expected = atomic_load(&notify_replies_expected_v6);

        if(are_notify_replies_expected == 0)
        {
            sleep(1);
            continue;
        }
#endif

        dns_message_recv_udp_reset(mesg);
        if(dns_message_recv_udp(mesg, send_socket6) > 0)
        {
            // process secondary answer

            if(ISOK(ret = dns_message_process_lenient(mesg)))
            {
#if NOTIFY_DETAILED_LOG
                log_debug("notify_ipv6_receiver_service(%{dnsname} %{sockaddr})", message_get_canonised_fqdn(mesg), message_get_sender_sa(mesg));
#endif
                notify_secondaryanswer(mesg);
            }
            else
            {
                log_err("notify_ipv6_receiver_service: processing message: %r", ret);
            }
        }
        else
        {
            ret = ERRNO_ERROR;
            if((ret == MAKE_ERRNO_ERROR(EAGAIN)) || (ret == MAKE_ERRNO_ERROR(EINTR)))
            {
#if NOTIFY_DETAILED_LOG
                log_debug("notify_ipv6_receiver_service: %r", ret);
#endif
            }
            else
            {
                log_err("notify_ipv6_receiver_service: %r", ret);
                sleep(1);
            }
        }
    }

    dns_message_delete(mesg);

    log_info("notify: notification service IPv6 receiver stopped");
}

struct notify_service_context
{
    ptr_treemap_t  notifications_being_sent;
    ptr_treemap_t  notify_queries_not_answered_yet;
    ptr_vector_t   todelete;
    random_ctx_t   rnd;
    dns_message_t *mesg;
    int64_t        last_current_queries_cleanup_epoch_us;
    int64_t        service_loop_begin_us;
};

static void notify_service_context_init(struct notify_service_context *ctx)
{
#if NOTIFY_DETAILED_LOG
    log_debug("notify_service_context_init(%p)", ctx);
#endif

    ctx->mesg = dns_message_new_instance();
    ctx->rnd = thread_pool_get_random_ctx();
    ctx->notifications_being_sent.root = NULL;
    ctx->notifications_being_sent.compare = notify_process_dnsname_compare;
    ctx->notify_queries_not_answered_yet.root = NULL;
    ctx->notify_queries_not_answered_yet.compare = message_query_summary_compare;
    ctx->last_current_queries_cleanup_epoch_us = 0;
    ptr_vector_init_empty(&ctx->todelete);
    ctx->service_loop_begin_us = timeus();
}

static void notify_service_context_manage_pending_notifications(struct notify_service_context *ctx)
{
    // cleanup start

#if NOTIFY_DETAILED_LOG
    log_debug("notify_service_context_manage_pending_notifications(%p)", ctx);
#endif

    // what happens in here should not interfere with the rest of the function

    int64_t tus = ctx->service_loop_begin_us;

    bool    there_are_no_notify_queries_not_answered_yet = ptr_treemap_isempty(&ctx->notify_queries_not_answered_yet);

    if(!there_are_no_notify_queries_not_answered_yet && (tus >= ctx->last_current_queries_cleanup_epoch_us))
    {
        /* create a list of expired message_query_summary */

#if NOTIFY_CLEANUP_DUMP
        log_debug("notify: cleaning up expired notifications");
#endif

        message_query_summary head;
        head.next = NULL;
        message_query_summary *current_queries_to_clear = &head;
        ctx->last_current_queries_cleanup_epoch_us = tus;

        if(ptr_treemap_isempty(&ctx->notify_queries_not_answered_yet))
        {
            /* find them using an iterator */

            ptr_treemap_iterator_t current_queries_iter;
            ptr_treemap_iterator_init(&ctx->notify_queries_not_answered_yet, &current_queries_iter);
            while(ptr_treemap_iterator_hasnext(&current_queries_iter))
            {
                ptr_treemap_node_t    *node = ptr_treemap_iterator_next_node(&current_queries_iter);
                message_query_summary *mqs = (message_query_summary *)node->value;

#if NOTIFY_DETAILED_LOG
                log_debug("notify: domain=%{dnsname} secondary=%{hostaddr} expires=%llT tries=%i", mqs->fqdn, mqs->host, mqs->expire_epoch_us, mqs->tries);
#endif
                if(ctx->last_current_queries_cleanup_epoch_us > mqs->expire_epoch_us)
                {
#if NOTIFY_DETAILED_LOG
                    log_debug("notify: domain=%{dnsname} secondary=%{hostaddr} expires=%llT tries=%i: current try expired", mqs->fqdn, mqs->host, mqs->expire_epoch_us, mqs->tries);
#endif

#if DEBUG
                    double expired_since = ctx->last_current_queries_cleanup_epoch_us - mqs->expire_epoch_us;
                    expired_since /= ONE_SECOND_US_F;
#endif
                    if(--mqs->tries <= 0)
                    {
#if NOTIFY_DETAILED_LOG
                        log_debug("notify: domain=%{dnsname} secondary=%{hostaddr} expires=%llT tries=%i: expired", mqs->fqdn, mqs->host, mqs->expire_epoch_us, mqs->tries);
#endif
                        bool        give_up = true;
                        zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(g_config->database, mqs->fqdn); // RC++
                        if(zone != NULL)
                        {
                            if((zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_WILL_NOTIFY_AGAIN) != 0)
                            {
#if DEBUG
                                log_debug(
                                    "notify: query (%hx) %{dnsname} to %{hostaddr} expired %f seconds ago but was "
                                    "re-armed",
                                    mqs->id,
                                    mqs->fqdn,
                                    mqs->host,
                                    expired_since);
#endif
                                give_up = false;
                                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY_AGAIN);
                                mqs->expire_epoch_us = tus + MESSAGE_QUERY_TIMEOUT_US;
                                mqs->tries = MESSAGE_QUERY_TRIES;
                                notify_send(mqs->host, ctx->mesg, mqs->id, mqs->fqdn, TYPE_SOA, CLASS_IN);
                            }
                            else
                            {
#if NOTIFY_DETAILED_LOG
                                log_debug(
                                    "notify: domain=%{dnsname} secondary=%{hostaddr} expires=%llT tries=%i: "
                                    "notification status cleared",
                                    mqs->fqdn,
                                    mqs->host,
                                    mqs->expire_epoch_us,
                                    mqs->tries);
#endif
                                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY);
                            }

                            zdb_zone_release(zone);
                        }

                        if(give_up)
                        {
#if DEBUG
                            log_debug("notify: query (%hx) %{dnsname} to %{hostaddr} expired %f seconds ago, giving up", mqs->id, mqs->fqdn, mqs->host, expired_since);
#endif
                            current_queries_to_clear->next = mqs;
                            current_queries_to_clear = mqs;
                        }
                    }
                    else
                    {
#if NOTIFY_DETAILED_LOG
                        log_debug("notify: domain=%{dnsname} secondary=%{hostaddr} expires=%llT tries=%i: will try again", mqs->fqdn, mqs->host, mqs->expire_epoch_us, mqs->tries);
#endif

#if DEBUG
                        log_debug(
                            "notify: query (%hx) %{dnsname} to %{hostaddr} expired %f seconds ago retrying (%i times "
                            "remaining)",
                            mqs->id,
                            mqs->fqdn,
                            mqs->host,
                            expired_since,
                            mqs->tries);
#endif
                        mqs->expire_epoch_us = tus + MESSAGE_QUERY_TIMEOUT_US;

                        // send the message again

                        notify_send(mqs->host, ctx->mesg, mqs->id, mqs->fqdn, TYPE_SOA, CLASS_IN);
                    }
                }
#if DEBUG
                else
                {
                    log_debug("notify: query (%hx) %{dnsname} to %{hostaddr} still in flight", mqs->id, mqs->fqdn, mqs->host);
                }
#endif
            }

            /* once the tree has been scanned, destroy every node listed */

            current_queries_to_clear = head.next;
            if(current_queries_to_clear != NULL)
            {
                do
                {
                    message_query_summary *mqs = current_queries_to_clear;
#if DEBUG
                    log_debug("notify: clearing query (%hx) %{dnsname} to %{hostaddr}", mqs->id, mqs->fqdn, mqs->host);
#endif
                    current_queries_to_clear = current_queries_to_clear->next;
                    ptr_treemap_delete(&ctx->notify_queries_not_answered_yet, mqs);

                    zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(g_config->database, mqs->fqdn); // RC++
                    if(zone != NULL)
                    {
                        zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY);
                        zdb_zone_release(zone);
                    }

                    message_query_summary_delete(mqs);
                } while(current_queries_to_clear != NULL);
            }
#if DEBUG
            else
            {
#if NOTIFY_CLEANUP_DUMP
                log_debug("notify: no queries to clear");
#endif
            }
#endif

        } // if !ptr_treemap_isempty(&current_queries)
#if DEBUG
        else
        {
#if NOTIFY_CLEANUP_DUMP
            log_debug("notify: no unanswered queries");
#endif
        }
#endif
    }
#if DEBUG
    else
    {
        if(ptr_treemap_isempty(&ctx->notify_queries_not_answered_yet))
        {
#if NOTIFY_CLEANUP_DUMP
            log_debug("notify: no notification queries needs to be answered");
#endif
        }

        if(tus < ctx->last_current_queries_cleanup_epoch_us)
        {
#if NOTIFY_CLEANUP_DUMP
            float dt = (ctx->last_current_queries_cleanup_epoch_us - tus) / 1000LL;
            dt /= 1000.0f;
            log_debug("notify: still %.3fus before cleaning up times out", dt);
#endif
        }

#if NOTIFY_CLEANUP_DUMP
        if(ctx->last_current_queries_cleanup_epoch_us > 0)
        {
            log_debug("notify: no timeout to handle (expect next at %llT)", ctx->last_current_queries_cleanup_epoch_us);
        }
        else
        {
            log_debug("notify: no timeout to handle");
        }
#endif
    }
#endif
    if((ctx->last_current_queries_cleanup_epoch_us < tus) && (ctx->last_current_queries_cleanup_epoch_us > 0))
    {
        ctx->last_current_queries_cleanup_epoch_us += MESSAGE_QUERY_TIMEOUT_US;
    }

    // cleanup end
}

static void notify_service_context_process_next_message(struct notify_service_context *ctx, notify_message *notifymsg)
{
    switch(notifymsg->payload.type)
    {
        case NOTIFY_MESSAGE_TYPE_CLEAR:
        {
            ptr_treemap_node_t *node = ptr_treemap_find(&ctx->notifications_being_sent, notifymsg->origin);
            if(node != NULL)
            {
#if NOTIFY_DETAILED_LOG
                log_debug("notify_service_context_process_next_message(%{dnsname} : clear)", notifymsg->origin);
#endif
                notify_message *zone_message = (notify_message *)node->value;
                if(zone_message != NULL)
                {
#if !DEBUG
                    log_debug("notify: %{dnsname}: removing secondaries notifications", notifymsg->origin);
#else
                    log_info("notify: %{dnsname}: removing secondaries notifications (%p) (debug)", notifymsg->origin, notifymsg);
#endif
                    zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(g_config->database, notifymsg->origin); // RC++
                    if(zone != NULL)
                    {
#if DEBUG
                        log_debug("notify: %{dnsname}: clearing notification status for zone", notifymsg->origin);
#endif
                        zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY | ZDB_ZONE_STATUS_WILL_NOTIFY_AGAIN);
                        zdb_zone_release(zone);
                    }
                    else
                    {
                        log_err("notify: %{dnsname}: could not un-mark zone as queue for notification: zone not found ?", notifymsg->origin);
                    }

                    ptr_treemap_delete(&ctx->notifications_being_sent, notifymsg->origin);
                    notify_message_free(zone_message);
                }
                else
                {
#if NOTIFY_DETAILED_LOG
                    log_debug("notify_service_context_process_next_message(%{dnsname} : nothing to clear)", notifymsg->origin);
#endif
                }
            }
            notify_message_free(notifymsg);

            break;
        }
        case NOTIFY_MESSAGE_TYPE_DOMAIN:
        {
#if !DEBUG
            log_debug("notify: %{dnsname}: notifying secondaries by domain", notifymsg->origin);
#else
            log_info("notify: %{dnsname}: notifying secondaries by domain (%p) (debug)", notifymsg->origin, notifymsg);
#endif
            if(!notify_secondaries_convert_domain_to_notify(notifymsg))
            {
#if !DEBUG
                log_debug("notify: %{dnsname}: failed to notify secondaries by domain", notifymsg->origin);
#else
                log_info("notify: %{dnsname}: failed to notify secondaries by domain (%p) (debug)", notifymsg->origin, notifymsg);
#endif
                zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(g_config->database, notifymsg->origin); // RC++
                if(zone != NULL)
                {
#if DEBUG
                    log_debug("notify: %{dnsname}: clearing notification status for zone", notifymsg->origin);
#endif
                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY | ZDB_ZONE_STATUS_WILL_NOTIFY_AGAIN);
                    zdb_zone_release(zone);
                }
                else
                {
                    log_err("notify: %{dnsname}: could not un-mark zone as queue for notification: zone not found ?", notifymsg->origin);
                }

                // failed
                notify_message_free(notifymsg);
                break;
            }
        }
        FALLTHROUGH // fall through
            case NOTIFY_MESSAGE_TYPE_NOTIFY:
        {
#if !DEBUG
            log_debug("notify: %{dnsname}: notifying secondaries", notifymsg->origin);
#else
            log_info("notify: %{dnsname}: notifying secondaries with %{dnstype} %{dnsclass} (debug)", notifymsg->origin, &notifymsg->payload.notify.ztype, &notifymsg->payload.notify.zclass);
#endif
            host_address_t **ha_prev = &notifymsg->payload.notify.hosts_list;
            host_address_t  *ha = *ha_prev;

            while(ha != NULL) // resolve all domain names in the list, replace them with the resolved address
            {
                if(ha->version == HOST_ADDRESS_DNAME)
                {
                    /* resolve */
                    char name[DOMAIN_LENGTH_MAX + 1];

                    cstr_init_with_dnsname(name, ha->ip.dname.dname);

                    socketaddress_t sa;

                    ya_result       ret = gethostaddr(name, g_config->server_port_value, &sa.sa, 0);

                    if(ISOK(ret))
                    {
#if DEBUG
                        log_info("notify: %{dnsname}: notifying secondary %{hostaddr} (debug)", notifymsg->origin, ha);
#endif
                        host_address_t ha;
                        host_address_set_with_socketaddress(&ha, &sa);
                        host_address_append_host_address(notifymsg->payload.notify.hosts_list, &ha);
                    }
                    else
                    {
                        log_warn("notify: %{dnsname}: unable to resolve %{dnsname}: %r", notifymsg->origin, ha->ip.dname.dname, ret);
                    }

                    *ha_prev = ha->next;

                    host_address_delete(ha);
                }
                else
                {
                    ha_prev = &ha->next;
                }

                ha = *ha_prev;
            }

            /*
             * The current queue has been resolved.
             */

            /**
             * The list has to replace the current one for message->origin (because it's starting again)
             */
#if DEBUG
            log_debug("notify: queuing notifications for %{dnsname}", notifymsg->origin);
#endif
            ptr_treemap_node_t *node = ptr_treemap_insert(&ctx->notifications_being_sent, notifymsg->origin);

            if(node->value != NULL)
            {
#if DEBUG
                log_info("notify: %{dnsname}: notifying secondary %{hostaddr}: replacing previous message (debug)", notifymsg->origin, notifymsg->payload.notify.hosts_list);
#endif
                notify_message *old_message = (notify_message *)node->value; // get the old value
                node->key = notifymsg->origin;                               // (same key but the old pointer is about to be deleted)
                node->value = notifymsg;                                     // set the new value
                notify_message_free(old_message);                            // destroy the old value.  notify_zones does not contains it anymore
            }
            else
            {
                node->value = notifymsg;
            }

            // ready to send

            zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(g_config->database, notifymsg->origin); // RC++
            if(zone != NULL)
            {
#if DEBUG
                log_debug("notify: %{dnsname}: clearing notification status for zone", notifymsg->origin);
#endif
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY);
                zdb_zone_release(zone);
            }
            else
            {
                log_err("notify: %{dnsname}: could not un-mark zone as queue for notification: zone not found ?", notifymsg->origin);
            }

            notifymsg->payload.notify.epoch = time(NULL);

            break;
        }
        case NOTIFY_MESSAGE_TYPE_ANSWER:
        {
            log_debug("notify: %{dnsname}: answer from secondary at %{hostaddr}", notifymsg->origin, notifymsg->payload.answer.host);

            ptr_treemap_node_t *node = ptr_treemap_find(&ctx->notifications_being_sent, notifymsg->origin);

            if(node != NULL)
            {
                notify_message *notify_zones_notifymsg = (notify_message *)node->value;

                if(notify_zones_notifymsg != NULL)
                {
                    /*
                     * Look for the entry and remove it
                     */

                    /* notifymsg->payload.answer.tsig ... */

                    /* all's good so remove the notify query from the list */

                    if(host_address_list_contains_host(notify_zones_notifymsg->payload.notify.hosts_list, notifymsg->payload.answer.host))
                    {
                        host_address_t *ha;
#if DNSCORE_HAS_TSIG_SUPPORT
                        ha = notifymsg->payload.answer.host;

                        message_query_summary tmp;

                        if(ha->tsig != NULL)
                        {
                            uint16_t id = dns_message_get_id(notifymsg->payload.answer.message);
                            message_query_summary_init(&tmp, id, ha, notifymsg->payload.answer.message);
                            // try to find the exact match
                            ptr_treemap_node_t *node = ptr_treemap_find(&ctx->notify_queries_not_answered_yet, &tmp);
                            message_query_summary_clear(&tmp);
                            if(node == NULL)
                            {
                                /* most likely a timeout */

                                log_notice(
                                    "notify: %{dnsname}: %{hostaddr}: unexpected answer: could not find a matching "
                                    "query for notification answer with id %04hx",
                                    notifymsg->origin,
                                    notifymsg->payload.answer.host,
                                    id);
                                // delete notifymsg
                                notify_message_free(notifymsg);

                                break;
                            }

                            message_query_summary *mqs = (message_query_summary *)node->value;

                            if(mqs != NULL)
                            {
                                // verify the signature

                                ya_result return_value;

                                if(FAIL(return_value = tsig_verify_answer(notifymsg->payload.answer.message, mqs->mac, mqs->mac_size)))
                                {
                                    // if everything is good, then proceed

                                    log_notice("notify: %{dnsname}: %{hostaddr}: TSIG signature verification failed: %r", notifymsg->origin, notifymsg->payload.answer.host, return_value);
                                    // delete notifymsg
                                    notify_message_free(notifymsg);
                                    break;
                                }

                                dns_message_delete(notifymsg->payload.answer.message); // message_data => message_free
                                notifymsg->payload.answer.message = NULL;
                                ptr_treemap_delete(&ctx->notify_queries_not_answered_yet, mqs);
                                message_query_summary_delete(mqs);
                            }
                            else // this should never happen
                            {
                                log_err("notify: %{dnsname}: %{hostaddr}: invalid internal state", notifymsg->origin, notifymsg->payload.answer.host);
                                ptr_treemap_delete(&ctx->notify_queries_not_answered_yet, &tmp);
                            }
                        } /* end of TSIG verification, with success*/
#endif
                        ha = host_address_remove_host_address(&notify_zones_notifymsg->payload.notify.hosts_list, notifymsg->payload.answer.host);
                        host_address_delete(ha);

                        if(notifymsg->payload.answer.rcode == RCODE_OK)
                        {
                            if(notifymsg->payload.answer.aa) /// @note 20190712 edf -- this 8383
                            {
                                log_debug("notify: %{dnsname}: answer from secondary at %{hostaddr} confirmed", notifymsg->origin, notifymsg->payload.answer.host);

                                zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(g_config->database, notifymsg->origin); // RC++
                                if(zone != NULL)
                                {
#if DEBUG
                                    log_debug("notify: %{dnsname}: clearing notification status for zone", notifymsg->origin);
#endif
                                    if((zdb_zone_get_status(zone) & ZDB_ZONE_STATUS_WILL_NOTIFY_AGAIN) != 0)
                                    {
                                        // resend
                                    }

                                    zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY | ZDB_ZONE_STATUS_WILL_NOTIFY_AGAIN);

                                    zdb_zone_release(zone);
                                }
                                else
                                {
                                    log_err(
                                        "notify: %{dnsname}: could not un-mark zone as queue for notification: zone "
                                        "not found ?",
                                        notifymsg->origin);
                                }
                            }

                            else
                            {
                                log_notice("notify: %{dnsname}: %{hostaddr}: no AA in answer", notifymsg->origin, notifymsg->payload.answer.host);
                            }
                        }
                        else
                        {
                            log_warn("notify: %{dnsname}: %{hostaddr}: answered with %r", notifymsg->origin, notifymsg->payload.answer.host, MAKE_RCODE_ERROR(notifymsg->payload.answer.rcode));
                            // will re-send the notification to that host
                        }
                    }
                    else
                    {
                        log_notice(
                            "notify: %{dnsname}: %{hostaddr}: unexpected answer: host is not on the currently notified "
                            "list",
                            notifymsg->origin,
                            notifymsg->payload.answer.host);
                    }

                    if(notify_zones_notifymsg->payload.notify.hosts_list == NULL)
                    {
                        ptr_treemap_delete(&ctx->notifications_being_sent, notify_zones_notifymsg->origin);
                        notify_message_free(notify_zones_notifymsg);
                    }
                }
                else // msg = NULL
                {
                    log_notice("notify: %{dnsname}: %{hostaddr}: unexpected answer", notifymsg->origin, notifymsg->payload.answer.host);
                    ptr_treemap_delete(&ctx->notifications_being_sent, notifymsg->origin);
                }
            }
            else
            {
                log_debug("notify: %{dnsname}: %{hostaddr}: unexpected answer: no pending notifications for the zone", notifymsg->origin, notifymsg->payload.answer.host);
            }

            // delete notifymsg
            notify_message_free(notifymsg);

            break;
        }
#if DEBUG
        default:
        {
            log_err("notify: unknown notifymsg type %i", notifymsg->payload.type);
            break;
        }
#endif
    } /* switch notifymsg type */
}

#if DEBUG
atomic_bool notify_no_notification_notified = false;
#endif

static void notify_service_context_send_notifications(struct notify_service_context *ctx)
{
#if DEBUG
    if(ptr_treemap_isempty(&ctx->notifications_being_sent))
    {
        if(!atomic_load(&notify_no_notification_notified))
        {
            log_debug("notify: no notification to send");
            atomic_store(&notify_no_notification_notified, true);
        }
        return;
    }
    else
    {
        log_debug("notify: sending notifications");
        atomic_store(&notify_no_notification_notified, false);
    }
#endif

    time_t now = time(NULL);
#if DEBUG
    int total_sent = 0;
#endif
    ptr_treemap_iterator_t notifications_being_sent_iter;
    ptr_treemap_iterator_init(&ctx->notifications_being_sent, &notifications_being_sent_iter);
    while(ptr_treemap_iterator_hasnext(&notifications_being_sent_iter))
    {
        ptr_treemap_node_t *notify_zone_node = ptr_treemap_iterator_next_node(&notifications_being_sent_iter);
        notify_message     *notifymsg = notify_zone_node->value;

        if(notifymsg->payload.notify.epoch > (uint64_t)now)
        {
#if DEBUG
            log_debug(
                "notify: notify_send(<secondaries>, %p, <id>, %{dnsname}, %{dnstype}, %{dnsclass}) should happen after "
                "%T",
                ctx->mesg,
                notifymsg->origin,
                &notifymsg->payload.notify.ztype,
                &notifymsg->payload.notify.zclass,
                notifymsg->payload.notify.epoch);
#endif
            continue;
        }

        if(dnscore_shuttingdown())
        {
            ptr_vector_append(&ctx->todelete, notifymsg);
            continue;
        }

        bool had_failures = false;

        for(host_address_t *ha = notifymsg->payload.notify.hosts_list; ha != NULL;) // for all secondaries to be notified
        {
            /*
             * Send an UDP packet to the ha
             */

            uint16_t id = random_next(ctx->rnd);
#if DEBUG
            log_debug(
                "notify: notify_send(%{hostaddr}, %p, %hx, %{dnsname}, %{dnstype}, %{dnsclass}) repeat=%i, "
                "repeat-increase=%i",
                ha,
                ctx->mesg,
                id,
                notifymsg->origin,
                &notifymsg->payload.notify.ztype,
                &notifymsg->payload.notify.zclass,
                (int)notifymsg->payload.notify.repeat_countdown,
                (int)notifymsg->payload.notify.repeat_period_increase);
#endif

            ya_result ret;

            if((ha->tsig == NULL) || ((ha->tsig != NULL) && (ha->tsig->name != NULL))) // ! ((tsig != NULL) && (tsig->name == NULL))
            {
                ret = notify_send(ha, ctx->mesg, id, notifymsg->origin, notifymsg->payload.notify.ztype, notifymsg->payload.notify.zclass);
            }
            else // tsig != NULL && tsig->name == NULL
            {
                ret = INVALID_STATE_ERROR;
            }

            host_address_t *ha_next = ha->next;

            if(ISOK(ret))
            {
#if DEBUG
                ++total_sent;
#endif

                message_query_summary *mqs;
                ZALLOC_OBJECT_OR_DIE(mqs, message_query_summary, MSGQSUMR_TAG);
                message_query_summary_init(mqs, id, ha, ctx->mesg);

                ptr_treemap_node_t *node = ptr_treemap_insert(&ctx->notify_queries_not_answered_yet, mqs);
#if __windows__
                if(ha->version == HOST_ADDRESS_IPV4)
                {
                    atomic_store(&notify_replies_expected_v4, 1);
                }
                else
                {
                    atomic_store(&notify_replies_expected_v6, 1);
                }
#endif
                if(node->value != NULL)
                {
                    // destroy this mqs
#if DEBUG
                    log_debug("notify: node %{hostaddr}[%04x] already exists, replacing", mqs->host, mqs->id);
#endif
                    message_query_summary_delete(node->value);
                    node->key = mqs;
                }
#if DEBUG
                else
                {
                    log_debug("notify: node %{hostaddr}[%04x] added to current queries", mqs->host, mqs->id);
                }
#endif
                node->value = mqs;
            }
            else // remove it
            {
                log_warn("notify: %{dnsname} could not send notification to %{hostaddr}", notifymsg->origin, ha);

                host_address_t *rem_ha = host_address_remove_host_address(&notifymsg->payload.notify.hosts_list, ha);
                host_address_delete(rem_ha);

                had_failures = true;
            }

            ha = ha_next;
        }

        if(had_failures)
        {
#if DEBUG
            log_debug(
                "notify: notify_send(<secondaries>, %p, <id>, %{dnsname}, %{dnstype}, %{dnsclass}) did not fully "
                "succeed",
                ctx->mesg,
                notifymsg->origin,
                &notifymsg->payload.notify.ztype,
                &notifymsg->payload.notify.zclass);
#endif

            zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(g_config->database, notifymsg->origin); // RC++
            if(zone == NULL)
            {
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY);
                zdb_zone_release(zone);
            }

            // try later
        }
        else
        {
#if DEBUG
            log_debug(
                "notify: notify_send(<secondaries>, %p, <id>, %{dnsname}, %{dnstype}, %{dnsclass}) all notifications "
                "sent",
                ctx->mesg,
                notifymsg->origin,
                &notifymsg->payload.notify.ztype,
                &notifymsg->payload.notify.zclass);
#endif
        }

        /* decrease the countdown or remove it from the collection */

        if(notifymsg->payload.notify.repeat_countdown > 0)
        {
            --notifymsg->payload.notify.repeat_countdown;

            /* ensure there is no overload */

            uint32_t rp = (uint32_t)notifymsg->payload.notify.repeat_period + (uint32_t)notifymsg->payload.notify.repeat_period_increase;

            if(rp > 255) /* minutes, 8 bits */
            {
                rp = 255;
            }

            notifymsg->payload.notify.repeat_period = (uint8_t)rp;
            notifymsg->payload.notify.epoch = now + 60U * notifymsg->payload.notify.repeat_period; // repeat_period is minutes
        }
        else
        {
            ptr_vector_append(&ctx->todelete, notifymsg);
        }
    }

    notify_message **notifymsgp = (notify_message **)ctx->todelete.data;

    for(int_fast32_t idx = 0; idx <= ctx->todelete.offset; idx++)
    {
        notify_message *notifymsg = notifymsgp[idx];
        ptr_treemap_delete(&ctx->notifications_being_sent, notifymsg->origin);
        notify_message_free(notifymsg);
    }

    ptr_vector_clear(&ctx->todelete);

#if DEBUG
    if(total_sent > 0)
    {
        log_debug("notify: %i notifications sent", total_sent);
    }
#endif
}

static void notify_service_context_wait(struct notify_service_context *ctx)
{
    for(;;)
    {
        int64_t service_loop_end_us = timeus();

        if(service_loop_end_us < ctx->service_loop_begin_us)
        {
            service_loop_end_us = ctx->service_loop_begin_us;
        }

        int64_t remaining = ONE_SECOND_US - (service_loop_end_us - ctx->service_loop_begin_us);

        if(remaining <= 0)
        {
            break;
        }

        usleep(service_loop_end_us - ctx->service_loop_begin_us);
    }
}

static void notify_service_context_finalize(struct notify_service_context *ctx)
{
    ptr_treemap_iterator_t iter;

    uint32_t               total_count;
    uint32_t               count;

    total_count = 0;
    count = 0;
    ptr_treemap_iterator_init(&ctx->notifications_being_sent, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *node = ptr_treemap_iterator_next_node(&iter);
        // host_address *ha = (host_address*)node->key;

        notify_message *message = (notify_message *)node->value; // get the old value
        if(message != NULL)
        {
            notify_message_free(message); // destroy the message
            node->key = NULL;             // (same key but the old pointer is about to be deleted)
            node->value = NULL;           // set the new value
            count++;
        }
        total_count++;
    }
    log_debug("notify: cleared %u messages", count);
    if(count != total_count)
    {
        log_notice("notify: %u messages were empty", total_count - count);
    }
    ptr_treemap_finalise(&ctx->notifications_being_sent);

    total_count = 0;
    count = 0;
    ptr_treemap_iterator_init(&ctx->notify_queries_not_answered_yet, &iter);
    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t    *node = ptr_treemap_iterator_next_node(&iter);
        message_query_summary *mqs = (message_query_summary *)node->value;
        if(mqs != NULL)
        {
            message_query_summary_delete(mqs);
            count++;
        }
        total_count++;
    }
    log_debug("notify: cleared %u summaries", count);
    if(count != total_count)
    {
        log_notice("notify: %u summaries were empty", total_count - count);
    }
    ptr_treemap_finalise(&ctx->notify_queries_not_answered_yet);

    ptr_vector_finalise(&ctx->todelete);

    if(ctx->mesg != NULL)
    {
        dns_message_delete(ctx->mesg); // message_data
        ctx->mesg = NULL;
    }
}

static int notify_service(struct service_worker_s *worker)
{
    /*
     * Resolve the names and replace them by their IP
     *
     * Remove the sender
     *
     * Remove myself
     *
     * Store (merge?) the queue for the current serial, replace an existing one.
     *
     * Update the serial on the queue for each answer ?
     *
     *
     */

    if(worker->worker_index == 1)
    {
        notify_ipv4_receiver_service(worker);
        return SUCCESS;
    }

    if(worker->worker_index == 2)
    {
        notify_ipv6_receiver_service(worker);
        return SUCCESS;
    }

    log_info("notify: notification service started");

    struct notify_service_context ctx;

    notify_service_context_init(&ctx);

    /*
     */

    log_debug("notify: notification service main loop reached");

    while(service_should_run(worker) || !async_queue_empty(&notify_handler_queue))
    {
        ctx.service_loop_begin_us = timeus();

        notify_service_context_manage_pending_notifications(&ctx);

#if DEBUG
        if(dnscore_shuttingdown())
        {
            log_info("notify: dnscore is shutting down. should_run: %i, queue_empty: %i (debug)", service_should_run(worker), async_queue_empty(&notify_handler_queue));
        }
#endif

        int64_t loop_start = timeus();
        int64_t loop_now = loop_start;
        int64_t loop_count = 0;
        bool    long_accumulation = false;
#if NOTIFY_CLEANUP_DUMP
        bool no_message_in_queue = false;
#endif
        bool is_shutting_down = !service_should_run(worker);

        // the loop will always enter at least once once

        do
        {
            /* current_queries tree cleanup */

            async_message_t *async = async_message_next(&notify_handler_queue);

            if(async == NULL) /*if no message is in the queue, proceed to next step */
            {
#if NOTIFY_CLEANUP_DUMP
                no_message_in_queue = true;
#endif
                break;
            }

            notify_message *notifymsg = (notify_message *)async->args;

            if(notifymsg == NULL) /*if no message is in the queue, proceed to next step (probably irrelevant) */
            {
                async_message_release(async);
#if NOTIFY_CLEANUP_DUMP
                no_message_in_queue = true;
#endif
                break;
            }

            // if dnscore is shutting down, release the message

            if(is_shutting_down || dnscore_shuttingdown())
            {
#if DEBUG
                log_info("notify: releasing messages (debug)");
#endif
                notify_message_free(notifymsg);
                async_message_release(async);
                is_shutting_down = true;
                loop_start = loop_now;
                continue;
            }

            ++loop_count;

            notify_service_context_process_next_message(&ctx, notifymsg);

            async_message_release(async);
        } // for(;;)
        while((long_accumulation = (((loop_now = timeus()) - loop_start) >= ONE_SECOND_US)));

        /*
         * For all entries in the queue, send a notify to the ones that need to be repeated
         */

        if(long_accumulation)
        {
            log_debug("notify: notification service accumulated queries for %fms (%lli queries)", ((1.0 * (loop_now - loop_start)) / 1000.0), loop_count);
        }

#if NOTIFY_CLEANUP_DUMP
        if(no_message_in_queue)
        {
            log_debug1("notify: notification service has no more messages queued");
        }
#endif

        if(is_shutting_down)
        {
            log_debug("notify: notification service will shutdown");
            break;
        }

        notify_service_context_send_notifications(&ctx);
        notify_service_context_wait(&ctx);
    }

    service_set_stopping(worker);

    notify_service_context_finalize(&ctx);

    log_info("notify: notification service stopped");

    return 0;
}

/**
 * Sends a notify to all the secondary for a given domain name:
 *
 * _ Get the zone
 * _ Create an empty list
 * _ If notify-auto, add all the IPs of all the NS at the apex of the zone to the list.
 * _ Add all the also-notify IPs to the list
 * _ Queue the list to the notify service
 *
 * @param origin
 */

void notify_secondaries(const uint8_t *origin)
{
    if(dnscore_shuttingdown())
    {
        return;
    }

    if(!initialise_state_initialised(&notify_service_init_state))
    {
        log_warn("notify: %{dnsname}: notification service has not been initialised", origin);

        return;
    }

    zdb_t      *db = g_config->database;
    zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(db, origin); // RC++

    if((zone == NULL) || zdb_zone_invalid(zone))
    {
        if(zone != NULL)
        {
            zdb_zone_release(zone);
        }

        log_warn("notify: %{dnsname}: notify called on an invalid zone", origin);

        return;
    }

    // zdb_zone_set_status returns the status before the parameter is added

    if((zdb_zone_set_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY) & ZDB_ZONE_STATUS_WILL_NOTIFY) != 0)
    {
        // zone was already marked for notification

        log_debug("notify: %{dnsname}: already marked for notification", origin);

        zdb_zone_set_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY_AGAIN);

        zdb_zone_release(zone); // the release should only be done now as 'origin' may be passed from the zone

        return;
    }

    log_debug("notify: %{dnsname}: secondaries notifications will be sent", origin);

    notify_message *notifymsg = notify_message_newinstance(origin, NOTIFY_MESSAGE_TYPE_DOMAIN);

    zdb_zone_release(zone); // RC--

    async_message_t *async = async_message_new_instance();
    async->id = 0;
    async->args = notifymsg;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&notify_handler_queue, async);
}

static ya_result notify_secondaries_alarm(void *args_, bool cancel)
{
    uint8_t *origin = (uint8_t *)args_;

    if(!dnscore_shuttingdown())
    {
        if(initialise_state_initialised(&notify_service_init_state) && !cancel)
        {
            log_debug("notify: %{dnsname}: delayed retry", origin);

            notify_message  *notifymsg = notify_message_newinstance(origin, NOTIFY_MESSAGE_TYPE_DOMAIN);

            async_message_t *async = async_message_new_instance();
            async->id = 0;
            async->args = notifymsg;
            async->handler = NULL;
            async->handler_args = NULL;
            async_message_call(&notify_handler_queue, async);
        }
        else
        {
            zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(g_config->database, origin); // RC++

            if(zone != NULL)
            {
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY);
                zdb_zone_release(zone);
            }
            else
            {
                log_err(
                    "notify: %{dnsname}: alarm-cancel: could not un-mark zone as queue for notification: zone not "
                    "found ?",
                    origin);
            }
        }
    }

    dnsname_zfree(origin);

    return SUCCESS;
}

bool notify_has_candidates_for_zone(zone_desc_t *zone_desc) { return (zone_is_primary(zone_desc) && zone_is_auto_notify(zone_desc)) || (zone_desc->notifies != NULL); }

/**
 *
 * @param origin
 */

static bool notify_secondaries_convert_domain_to_notify(notify_message *message)
{
    if(message->payload.type == NOTIFY_MESSAGE_TYPE_NOTIFY)
    {
        return true;
    }

    if(initialise_state_initialised(&notify_service_init_state) && (message->payload.type != NOTIFY_MESSAGE_TYPE_DOMAIN))
    {
        return false;
    }

    /*
     * Build a list of IPs to contact
     * The primary in the SOA must not be in this list
     * The current server must not be in this list
     *
     * Once the list is done, launch a thread that will periodically retry anybody in this list until the list is empty
     *
     * The list should be mutexed
     * The list should be in a by-origin collection
     * The list should be rebuild for each new notification (because the zone could have changed)
     */

    zdb_t      *db = g_config->database;

    zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(db, message->origin); // RC++

    if((zone == NULL) || zdb_zone_invalid(zone) || !initialise_state_initialised(&notify_service_init_state))
    {
        if(zone != NULL)
        {
            zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY);
            zdb_zone_release(zone);
        }

        if(initialise_state_initialised(&notify_service_init_state))
        {
            log_debug("notify: %{dnsname}: zone temporarily unavailable", message->origin);
        }

        return false;
    }

    zone_desc_t *zone_desc = zone_acquirebydnsname(message->origin);
    if(zone_desc == NULL)
    {
        zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY);
        zdb_zone_release(zone);
        log_err("notify: %{dnsname}: zone not configured", message->origin);
        return false;
    }

    host_address_t list;
#if DEBUG
    memset(&list, 0xff, sizeof(list));
#endif
    list.next = NULL;
    list.version = HOST_ADDRESS_NONE;

    bool lock_failed = false;

    /* no need to set TSIG */

    if(zone_is_primary(zone_desc) && zone_is_auto_notify(zone_desc))
    {
        if(zdb_zone_trylock_wait(zone, ONE_SECOND_US, ZDB_ZONE_MUTEX_SIMPLEREADER))
        // if(zdb_zone_trylock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER))
        {
            // get the NS
            zdb_resource_record_set_t *ns_rrset = zdb_resource_record_sets_find(&zone->apex->resource_record_set, TYPE_NS); // zone is locked

            if(ns_rrset != NULL)
            {
                // get the SOA
                zdb_resource_record_data_t *soa_rr = zdb_resource_record_sets_find_soa(&zone->apex->resource_record_set); // zone is locked

                // get the IPs for each NS but the one in the SOA

                uint8_t *soa_mname = zdb_resource_record_data_rdata(soa_rr);
                uint32_t soa_mname_size = dnsname_len(soa_mname);
                /*
                uint8_t *soa_rname = soa_mname + soa_mname_size;
                uint8_t *serial_ptr = soa_rname + dnsname_len(soa_rname);
                uint32_t serial = *((uint32_t*)serial_ptr);
                serial = ntohl(serial);
                */

                zdb_resource_record_set_const_iterator iter;
                zdb_resource_record_set_const_iterator_init(ns_rrset, &iter);
                while(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    const zdb_resource_record_data_t *nsp = zdb_resource_record_set_const_iterator_next(&iter);

                    uint32_t                          ns_dname_size = zdb_resource_record_data_rdata_size(nsp);
                    const uint8_t                    *ns_dname = zdb_resource_record_data_rdata_const(nsp);

                    if(ns_dname_size == soa_mname_size)
                    {
                        if(memcmp(ns_dname, soa_mname, soa_mname_size) == 0) // scan-build false positive: soa_mname cannot be NULL
                        {
                            continue;
                        }
                    }

                    // valid candidate : get its IP, later

                    if(zdb_append_ip_records_with_port_ne(db, ns_dname, &list, htons(g_config->server_port_value)) <= 0)
                    {
                        // If no IP has been found, they will have to be resolved using the system ... later

                        host_address_append_dname(&list, ns_dname, htons(g_config->server_port_value));
                    }
                }
            }

            zdb_zone_release_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        }
        else
        {
            log_debug("notify: %{dnsname}: zone already locked", message->origin);

            lock_failed = true;
            zdb_zone_release(zone);
        }
    }
    else
    {
        zdb_zone_release(zone);
    }

    // at this point I have the list of every IP I could find along with names I cannot resolve.
    // note that we don't need to care about the changes in the database : it would mean a new
    // notify and this one would be discarded

    if(!lock_failed && ISOK(zone_try_lock_wait(zone_desc, ONE_SECOND_US, ZONE_LOCK_READONLY)))
    {
        log_debug("notify: %{dnsname}: preparing notification", message->origin);

        const host_address_t *also_notifies = zone_desc->notifies;

        while(also_notifies != NULL)
        {
            host_address_append_host_address(&list, also_notifies); // copy made

            also_notifies = also_notifies->next;
        }

        // It's separate from the DB push the lot thread from the pool

        if(list.next != NULL)
        {
            message->payload.type = NOTIFY_MESSAGE_TYPE_NOTIFY;
            message->payload.notify.hosts_list = list.next;
            message->payload.notify.repeat_countdown = zone_desc->notify.retry_count;                 /* 10 times */
            message->payload.notify.repeat_period = zone_desc->notify.retry_period;                   /* 1 minute */
            message->payload.notify.repeat_period_increase = zone_desc->notify.retry_period_increase; /* 1 minute */
            message->payload.notify.ztype = TYPE_SOA;
            message->payload.notify.zclass = CLASS_IN;
        }
        else
        {
            log_debug("notify: %{dnsname}: preparing notification: host list empty", message->origin);
        }

        zone_unlock(zone_desc, ZONE_LOCK_READONLY);
    }
    else
    {
        // could not lock the zone right away : delay a bit
        log_debug("notify: %{dnsname}: delaying notification", message->origin);

        zdb_zone_t *zone = zdb_acquire_zone_read_from_fqdn(db, message->origin); // RC++
        if(zone != NULL)
        {
            if(!zdb_zone_invalid(zone))
            {
                alarm_event_node_t *event = alarm_event_new( // secondary notification
                    time(NULL),
                    ALARM_KEY_ZONE_NOTIFY_SECONDARIES,
                    notify_secondaries_alarm,
                    dnsname_zdup(message->origin),
                    ALARM_DUP_REMOVE_LATEST,
                    "notify secondaries");

                alarm_set(zone->alarm_handle, event);
            }
            else
            {
                // if the message is ignored, will-notify status must be cleared
                zdb_zone_clear_status(zone, ZDB_ZONE_STATUS_WILL_NOTIFY);

                log_warn("notify: %{dnsname}: (temporarily) invalid zone, notify secondaries request will remain ignored", message->origin);
            }

            zdb_zone_release(zone);
        }
        else
        {
            // could not get the zone anymore

            log_warn("notify: %{dnsname}: could not acquire the zone, notify secondaries request will remain ignored", message->origin);
        }
    }

    zone_release(zone_desc);

    return message->payload.type == NOTIFY_MESSAGE_TYPE_NOTIFY;
}

/**
 * Stops all notification for zone with origin
 *
 * @param origin
 */

void notify_clear(const uint8_t *origin)
{
    notify_message  *notifymsg = notify_message_newinstance(origin, NOTIFY_MESSAGE_TYPE_CLEAR);

    async_message_t *async = async_message_new_instance();
    async->id = 0;
    async->args = notifymsg;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&notify_handler_queue, async);
}

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING

void notify_host_list(zone_desc_s *zone_desc, host_address *hosts, uint16_t zclass)
{
    notify_message *notifymsg = notify_message_newinstance(zone_origin(zone_desc), NOTIFY_MESSAGE_TYPE_NOTIFY);

    notifymsg->payload.notify.hosts_list = hosts;
    notifymsg->payload.notify.repeat_countdown = zone_desc->notify.retry_count;                 /* 10 times */
    notifymsg->payload.notify.repeat_period = zone_desc->notify.retry_period;                   /* 1 minute */
    notifymsg->payload.notify.repeat_period_increase = zone_desc->notify.retry_period_increase; /* 1 minute */
    notifymsg->payload.notify.ztype = TYPE_SOA;
    notifymsg->payload.notify.zclass = zclass;

    async_message_s *async = async_message_alloc();
    async->id = 0;
    async->args = notifymsg;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&notify_handler_queue, async);
}

void notify_primaries_list(host_address *hosts)
{
    static const uint8_t dot[1] = {0};
    notify_message      *message = notify_message_newinstance(dot, NOTIFY_MESSAGE_TYPE_NOTIFY);

    message->payload.notify.hosts_list = hosts;
    message->payload.notify.repeat_countdown = 50;       /* 50 times */
    message->payload.notify.repeat_period = 60;          /* 1 minute */
    message->payload.notify.repeat_period_increase = 60; /* 1 minute */
    message->payload.notify.ztype = TYPE_AXFR;
    message->payload.notify.zclass = CLASS_CTRL;

    async_message_s *async = async_message_alloc();
    async->id = 0;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&notify_handler_queue, async);
}

#endif // HAS_CTRL_DYNAMIC_PROVISIONING

ya_result notify_service_init()
{
    int err = SUCCESS;
    if(initialise_state_begin(&notify_service_init_state))
    {
        int workers = 2;

        if((send_socket4 = socket(AF_INET, SOCK_DGRAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_DGRAM))) < 0)
        {
            initialise_state_cancel(&notify_service_init_state);
            log_err("notify: no usable IPv4 socket bound");
            return ERRNO_ERROR;
        }

        fd_setcloseonexec(send_socket4);

        if((send_socket6 = socket(AF_INET6, SOCK_DGRAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_DGRAM))) < 0)
        {
            log_warn("notify: no usable IPv6 socket bound");
        }
        else
        {
            fd_setcloseonexec(send_socket6);
            ++workers;
        }

        if(notify_thread_pool == NULL)
        {
            if((notify_thread_pool = thread_pool_init_ex(10, 4096, "notify-tp")) == NULL)
            {
                initialise_state_cancel(&notify_service_init_state);
                close_ex(send_socket4);
                send_socket4 = -1;
                close_ex(send_socket6);
                send_socket6 = -1;
                return THREAD_CREATION_ERROR;
            }
        }

        if(ISOK(err = service_init_ex(&notify_handler, notify_service, "yadifad-notify", workers)))
        {
            async_queue_init(&notify_handler_queue, 10000000, 1, 1, "notify"); // note: it's implemented as a linked list

            initialise_state_ready(&notify_service_init_state);
        }
    }

    return err;
}

/**
 * Starts the notify service thread
 */

ya_result notify_service_start()
{
    int err = SERVICE_NOT_INITIALISED;

    if(initialise_state_initialised(&notify_service_init_state))
    {
        if(service_stopped(&notify_handler))
        {
            err = service_start(&notify_handler);
        }
    }

    return err;
}

void notify_wait_servicing()
{
    if(initialise_state_initialised(&notify_service_init_state))
    {
        if(!service_stopped(&notify_handler))
        {
            service_wait_servicing(&notify_handler);
        }
    }
}

/**
 * Stops the notify service thread
 */

ya_result notify_service_stop()
{
    int err = SERVICE_NOT_INITIALISED;

    if(initialise_state_initialised(&notify_service_init_state))
    {
        if(!service_stopped(&notify_handler))
        {
            err = service_stop(&notify_handler);
            service_wait(&notify_handler);
        }
    }

    return err;
}

ya_result notify_service_finalize()
{
    int err = SUCCESS;

    if(initialise_state_unready(&notify_service_init_state))
    {
        if(send_socket4 >= 0)
        {
            shutdown(send_socket4, SHUT_RDWR);
        }

        if(send_socket6 >= 0)
        {
            shutdown(send_socket6, SHUT_RDWR);
        }

        err = notify_service_stop();

        service_finalise(&notify_handler);

        /* once the tree has been scanned, destroy every node listed */

        while(!async_queue_empty(&notify_handler_queue))
        {
            async_message_t *async = async_message_next(&notify_handler_queue);

            if(async == NULL) /* if no message is in the queue, proceed to next step */
            {
                break;
            }

            notify_message *msg = (notify_message *)async->args;

            /* if no message is in the queue, proceed to next step (probably irrelevant) */
            notify_message_free(msg);

            async_message_release(async);
        }

        async_queue_finalize(&notify_handler_queue);

        if(notify_thread_pool != NULL)
        {
            thread_pool_destroy(notify_thread_pool);
            notify_thread_pool = NULL;
        }

        if(send_socket4 >= 0)
        {
            close_ex(send_socket4);
            send_socket4 = -1;
        }

        if(send_socket6 >= 0)
        {
            close_ex(send_socket6);
            send_socket6 = -1;
        }

        initialise_state_end(&notify_service_init_state);
    }

    return err;
}

/** @} */

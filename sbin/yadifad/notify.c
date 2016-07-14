/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2016, EURid. All rights reserved.
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
 *  @ingroup yadifad
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include "server-config.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>

#include <dnscore/rfc.h>
#include <dnscore/logger.h>
#include <dnscore/serial.h>
#include <dnscore/format.h>
#include <dnscore/service.h>
#include <dnscore/async.h>

#include <dnsdb/zdb.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/zdb_record.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb_zone_load.h>

#include <dnszone/dnszone.h>
#include <dnszone/zone_axfr_reader.h>

#include <dnscore/ptr_set.h>

#include "notify.h"
#include "zone.h"
#include "database-service.h"
#include "server.h"
#include "server_error.h"

#if HAS_CTRL
#include "ctrl.h"

#endif

#define NOTFYMSG_TAG 0x47534d5946544f4e
#define MESGDATA_TAG 0x415441444753454d


/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#define NOTIFY_MESSAGE_TYPE_NOTIFY  1
#define NOTIFY_MESSAGE_TYPE_ANSWER  2
#define NOTIFY_MESSAGE_TYPE_DOMAIN  3

#define MESSAGE_QUERY_TIMEOUT 5
#define MESSAGE_QUERY_TRIES   1

#define MESSAGE_QUERY_TIMEOUT_US (MESSAGE_QUERY_TIMEOUT * 1000000)

static struct thread_pool_s *notify_thread_pool = NULL;

static int send_socket4 = -1;
static int send_socket6 = -1;

static struct service_s notify_handler = UNINITIALIZED_SERVICE;
static async_queue_s notify_handler_queue;
static volatile bool notify_service_initialised = FALSE;

typedef struct message_query_summary message_query_summary;

#define MSGQSUMR_TAG 0x524d55535147534d

struct message_query_summary
{
    host_address *host;
    message_query_summary *next;    /* this pointer is used to list the items, ie: for deletion */
    // to discard
    u64 expire_epoch_us;
    // for answers, id has to be kept
    u16 id;
    // for answers, ip/port should be kept but they are already in the host list (sa.sa4,sa.sa6,addrlen)
    // times we send the udp packet before giving up
    s8 tries;     
    // for signed answers, these have to be kept
    u8 mac_size;    // mesg->tsig.mac_size;
    u8 mac[64];     // mesg->tsig.mac;    
};

static void
message_query_summary_init(message_query_summary *mqs, u16 id, host_address *host, const u8 *mac, u8 mac_size)
{
    yassert(mqs != NULL);
#if HAS_TSIG_SUPPORT
    yassert((mac != NULL) || (mac_size == 0));
#else
    (void)mac;
    (void)mac_size;
#endif

    // key
    mqs->host = host_address_copy(host);
    mqs->next = NULL;
    mqs->expire_epoch_us = timeus() + MESSAGE_QUERY_TIMEOUT_US;
    mqs->id = id;
    // payload
    mqs->tries = MESSAGE_QUERY_TRIES;
    
#if HAS_TSIG_SUPPORT
    if(mac_size > 0)
    {
        yassert(mac != NULL);
        mqs->mac_size = mac_size;
        memcpy(mqs->mac, mac, mac_size);
    }
#endif
}

static void
message_query_summary_clear(message_query_summary *mqs)
{
#ifdef DEBUG
    log_debug("notify: clearing query for %{hostaddr}", mqs->host);
#endif
    host_address_delete(mqs->host);
#ifdef DEBUG
    memset(mqs, 0xfe, sizeof(message_query_summary));
#endif
}

static void
message_query_summary_delete(message_query_summary *mqs)
{
#ifdef DEBUG
    log_debug("notify: deleting query for %{hostaddr}", mqs->host);
#endif
    message_query_summary_clear(mqs);
    ZFREE(mqs, message_query_summary);
}

static s32
message_query_summary_compare(const void* va, const void* vb)
{
    message_query_summary *a = (message_query_summary*)va;
    message_query_summary *b = (message_query_summary*)vb;
    
    s32 d;
    
    d = (s32)a->id - (s32)b->id;
    
    if(d == 0)
    {    
        d = host_address_compare(a->host, b->host);
    }
    
    return d;
}

typedef struct notify_message notify_message;

struct notify_message_domain
{
    u8 type;
};

struct notify_message_notify
{
    u8 type;
    u8 repeat_countdown;
    u8 repeat_period;
    u8 repeat_period_increase;
    u32 epoch;
    host_address *hosts_list;   /* 64 bits aligned */
#if HAS_TSIG_SUPPORT
    message_tsig tsig;
#endif
    u16 ztype;
    u16 zclass;
};

struct notify_message_answer
{
    u8   type;
    u8   rcode;
    bool aa;
    u8   r2;
    host_address *host;
    message_data *message;  /* only used if the message is signed */
};

struct notify_message
{
    u8 *origin;

    union
    {
        u8 type;
        struct notify_message_notify notify;
        struct notify_message_answer answer;
        struct notify_message_domain domain;
    } payload;
};

static bool notify_slaves_convert_domain_to_notify(notify_message *message);

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/**
 * 
 * Queue a message telling a slave has answered to a notify
 * 
 * @param origin the domain of the zone
 * @param sa the address of the source
 * @param rcode rcode part of the query
 * @param aa aa flag value in the query
 */

static void
notify_slaveanswer(message_data *mesg)
{
    notify_message *message;

    if(notify_service_initialised)
    {
        u8 *origin = mesg->qname;
        socketaddress *sa = &mesg->other;
        u8 rcode = MESSAGE_RCODE(mesg->buffer);
        bool aa = MESSAGE_AA(mesg->buffer)!=0;
                
        ZALLOC_OR_DIE(notify_message*, message, notify_message, NOTFYMSG_TAG);

        message->origin = dnsname_zdup(origin);
        message->payload.type = NOTIFY_MESSAGE_TYPE_ANSWER;
        message->payload.answer.rcode = rcode;
        message->payload.answer.aa = aa;
        ZALLOC_OR_DIE(host_address*, message->payload.answer.host, host_address, HOSTADDR_TAG);
        host_address_set_with_sockaddr(message->payload.answer.host, sa);
        
#if HAS_TSIG_SUPPORT
        
        // if there is a TSIG ...
        
        if(mesg->tsig.tsig != NULL)
        {
            message->payload.answer.message = message_dup(mesg);
            message->payload.answer.host->tsig = mesg->tsig.tsig;
        }
        else
        {
            message->payload.answer.message = NULL;
            message->payload.answer.host->tsig = NULL;
        }
#endif
        
        async_message_s *async = async_message_alloc();
        async->id = 0;
        async->args = message;
        async->handler = NULL;
        async->handler_args = NULL;
        async_message_call(&notify_handler_queue, async);
    }
    else
    {
        log_err("notify: service not initialised");
    }
}

static bool
notify_masterquery_read_soa(u8 *origin, packet_unpack_reader_data *reader, u32 *serial)
{
    ya_result return_value;
    
    u8 tmp[MAX_DOMAIN_LENGTH];
    
    /* read and expect an SOA */
    
    packet_reader_read_fqdn(reader, tmp, sizeof(tmp));

    if(dnsname_equals(tmp, origin))
    {
        struct type_class_ttl_rdlen tctr;

        if(packet_reader_read(reader, &tctr, 10) == 10)
        {
            if((tctr.qtype == TYPE_SOA) && (tctr.qclass == CLASS_IN))
            {
                if(ISOK(return_value = packet_reader_skip_fqdn(reader)))
                {
                    if(ISOK(return_value = packet_reader_skip_fqdn(reader)))
                    {
                        if(packet_reader_read(reader, tmp, 4) == 4)
                        {
                            
                            *serial = ntohl(GET_U32_AT_P(tmp));
                            
                            return TRUE;
                        }
                    }
                }
            }
        }
    }
    
    return FALSE;
}

#define NTFYMQTA_TAG 0x4154514d5946544e

struct notify_masterquery_thread_args
{
    u8 *origin;
    u32 serial;
    bool serial_set;
};

typedef struct notify_masterquery_thread_args notify_masterquery_thread_args;

static void *
notify_masterquery_thread(void *args_)
{
    notify_masterquery_thread_args *args = (notify_masterquery_thread_args*)args_;
    
    /* get the zone descriptor for that domain */
    
    zone_desc_s *zone_desc = zone_acquirebydnsname(args->origin);
    
    ya_result return_value;
    
    if(zone_desc == NULL)
    {
        log_err("notify: slave: %{dnsname}: zone not configured", args->origin);
        dnsname_zfree(args->origin);
        ZFREE(args, notify_masterquery_thread_args);
        
        return NULL;
    }
    
    /* do an SOA query to the master to retrieve the serial (wait) */
    
    zone_lock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
    host_address *zone_desc_masters = host_address_copy_list(zone_desc->masters);
    zone_unlock(zone_desc, ZONE_LOCK_DOWNLOAD_DESC);
    
    if(!args->serial_set)
    {
        if(ISOK(return_value = message_query_serial(args->origin, zone_desc_masters, &args->serial))) // multi-master
        {
            args->serial_set = TRUE;
        }
        else
        {
            /* we didn't got the serial */
            
            log_debug("notify: slave: %{dnsname}: SOA query to the master at %{hostaddr} failed: %r", args->origin, zone_desc->masters, return_value);
            
            /// @todo 20160607 edf -- after some time, decide to switch the master : (drop the zone?), load it anew
        }
    }
    
    host_address_delete_list(zone_desc_masters);
    
    u32 current_serial;

    /* get the zone of the domain */

    zdb_zone *dbzone = zdb_acquire_zone_read_from_fqdn(g_config->database, args->origin);

    if(dbzone != NULL)
    {
        /* lock it for the XFR (it's a writer, so no other writer allowed) */
        
        if(zdb_zone_trylock(dbzone, ZDB_ZONE_MUTEX_XFR))
        {
            /* get the current serial of the zone */
            
            if(ISOK(zdb_zone_getserial(dbzone, &current_serial)))
            {
               /*
                * If the serial on the "master" is lower,
                * nothing has to be done except a note on the log.
                * 
                * If we didn't got the serial of course, we can only ask to the master.
                */

                if(args->serial_set)
                {
                    if(serial_lt(args->serial, current_serial))
                    {
                        /* do nothing at all */
                        
                        log_warn("notify: slave: %{dnsname}: serial number on this slave is higher (%u) than on the notifier (%u)", zone_desc->origin, current_serial, args->serial);
                    }
                    else if(serial_gt(args->serial, current_serial))
                    {
                        /* download (and apply) the incremental change  */

                        log_info("notify: slave: %{dnsname}: scheduling an IXFR from %u", zone_desc->origin, current_serial);
                        
                        database_zone_ixfr_query(zone_desc->origin);
                    }
                    else
                    {
                        /* nothing to do but mark the zone as being refreshed */

                        log_info("notify: slave: %{dnsname}: already the last version (%u)", zone_desc->origin, current_serial);

                        dbzone->apex->flags &= ~ZDB_RR_LABEL_INVALID_ZONE;
                        zone_desc->refresh.refreshed_time = zone_desc->refresh.retried_time = time(NULL);
                        
                        zdb_zone_release_unlock(dbzone, ZDB_ZONE_MUTEX_XFR);                         /* MUST be unlocked here because ... */
                        database_zone_refresh_maintenance(g_config->database, zone_desc->origin, 0); /* ... this will try to lock */
                        
                        dnsname_zfree(args->origin);
                        ZFREE(args, notify_masterquery_thread_args);
                        
                        zone_release(zone_desc);
                        
                        return NULL;
                    }
                }
                else
                {
                    log_warn("notify: slave: %{dnsname}: the serial of the master has not been obtained", zone_desc->origin);

                    database_zone_ixfr_query(zone_desc->origin);
                }
            }
            else // no soa at apex ... zone needs to be downloaded ...
            {
                database_zone_axfr_query(zone_desc->origin);
            }

            zdb_zone_release_unlock(dbzone, ZDB_ZONE_MUTEX_XFR);
        }
        else
        {
           /*
            * The zone has been locked already ? give up ...
            */

            log_info("notify: slave: %{dnsname}: already locked (%x)", args->origin, dbzone->lock_owner);

            zdb_zone_release(dbzone);
            
            database_zone_refresh_maintenance(g_config->database, args->origin, time(NULL) + 5);
        }
    }
    else
    {
        /*
         * Ask for an AXFR of the zone
         */

        log_info("notify: slave: %{dnsname}: scheduling an AXFR", zone_desc->origin);

        database_zone_axfr_query(zone_desc->origin);
    }   /* AXFR */
    
    dnsname_zfree(args->origin);
    ZFREE(args, notify_masterquery_thread_args);
    
    zone_release(zone_desc);
    
    return NULL;
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

static ya_result
notify_send(host_address* ha, message_data *msgdata, u16 id, const u8 *origin, u16 ntype, u16 nclass)
{
    socketaddress sa;
    
    ya_result return_code;
               
    /** @todo 20130506 edf -- check if adding the SOA helps bind to update faster */

    message_make_notify(msgdata, id, origin, ntype, nclass);
    
#if HAS_TSIG_SUPPORT
    if(ha->tsig != NULL)
    {
        if(FAIL(return_code = message_sign_query(msgdata, ha->tsig)))
        {
            log_err("notify: %{dnsname}: unable to sign message for %{sockaddr} with key %{dnsname}: %r", origin, &sa, ha->tsig->name, return_code);
            
            return return_code;
        }
    }
#endif
    
    if(ISOK(return_code = host_address2sockaddr(&sa, ha)))
    {
        
#if HAS_TSIG_SUPPORT
        if(ha->tsig == NULL)
        {
#endif
            
#ifndef DEBUG
            log_info("notify: %{dnsname}: notifying %{sockaddr}", origin, &sa.sa);
#else
            log_info("notify: %{dnsname}: notifying %{sockaddr} with %{dnstype} %{dnsclass}", origin, &sa.sa, &ntype, &nclass);
#endif
            
#if HAS_TSIG_SUPPORT
        }
        else
        {
#ifndef DEBUG
            log_info("notify: %{dnsname}: notifying %{sockaddr} (key=%{dnsname})", origin, &sa.sa, ha->tsig->name);
#else
            log_info("notify: %{dnsname}: notifying %{sockaddr} (key=%{dnsname}) with (%{dnstype} %{dnsclass})", origin, &sa.sa, ha->tsig->name, &ntype, &nclass);
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
#ifdef DEBUG
            log_debug("notify_send: sendto(%d, %p, %d, %d, %{sockaddr}, %d)", s, msgdata->buffer, msgdata->send_length, 0, (struct sockaddr*)&sa.sa, addrlen);
            log_memdump_ex(g_server_logger, MSG_DEBUG5, msgdata->buffer, msgdata->send_length, 16, OSPRINT_DUMP_HEXTEXT);
#endif
            if(ISOK(return_code = sendto(s, msgdata->buffer, msgdata->send_length, 0, &sa.sa, addrlen)))
            {
                log_debug("notify: %{dnsname}: sent %i bytes to %{sockaddr}", origin, msgdata->send_length, &sa.sa);
            }
            else
            {
                log_err("notify: %{dnsname}: failed to send notify to %{sockaddr}: %r", origin, &sa.sa, ERRNO_ERROR);
            }
        }
        else
        {
            return_code = ERROR; // wrong socket
            
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
 * Uses a thread to handle the notify from the master (notify_masterquery_thread)
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

static ya_result
notify_masterquery(message_data *mesg, packet_unpack_reader_data *reader)
{
    ya_result return_value;
        
    u32 serial = 0; // to silence gcc : this was not a bug
    bool serial_set = FALSE;
    
    if(MESSAGE_AN(mesg->buffer) != 0)
    {
        serial_set = notify_masterquery_read_soa(mesg->qname, reader, &serial);
    }
    
    notify_masterquery_thread_args *args;
    
    ZALLOC_OR_DIE(notify_masterquery_thread_args*, args, notify_masterquery_thread_args, NTFYMQTA_TAG);
    
    args->origin = dnsname_zdup(mesg->qname);
    args->serial = serial;
    args->serial_set = serial_set;
    
    return_value = thread_pool_enqueue_call(notify_thread_pool, notify_masterquery_thread, args, NULL, "notify: slave");
    
    return return_value;
}

static ya_result
notify_process_masterquery_in(message_data *mesg, packet_unpack_reader_data *reader)
{
    zone_desc_s *zone_desc;
    ya_result return_value = SUCCESS;
    
    zone_desc = zone_acquirebydnsname(mesg->qname);

    if(zone_desc != NULL)
    {
        MESSAGE_HIFLAGS(mesg->buffer) |= QR_BITS|AA_BITS;

        if(zone_desc->type == ZT_SLAVE)
        {
            log_info("notify: slave: %{dnsname}: %{sockaddr} sent a notification query, class  %{dnsclass}", mesg->qname, &mesg->other.sa, &mesg->qclass);

#if ZDB_HAS_ACL_SUPPORT
            if(ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_notify)))
            {
                /* notauth */

                log_warn("notify: slave: %{dnsname}: %{sockaddr}: not authorised", mesg->qname, &mesg->other.sa);

                mesg->status = FP_NOTIFY_REJECTED;
                mesg->send_length = mesg->received;
                
                zone_release(zone_desc);

                return ACL_NOTIFY_REJECTED;
            }
#endif
            
#if OBSOLETE
            if(host_address_list_contains_ip(zone_desc->masters, &mesg->other))
            {
                if(zone_isidle(zone_desc) && !zone_isfrozen(zone_desc) && !zone_is_obsolete(zone_desc))
                {
                    return_value = notify_masterquery(mesg, reader); // thread-safe
                    
                    zone_release(zone_desc);
                    
                    return return_value;
                }
                else
                {
                    log_info("notify: slave: zone %{dnsname} is busy", zone_desc->origin);
                    /* or not */
                    database_zone_refresh_maintenance(g_config->database, zone_desc->origin, time(NULL) + 5); // thread-safe
                    
                    zone_release(zone_desc);

                    return SUCCESS;
                }
            }
            else
            {
                log_warn("notify: slave: notification from %{sockaddr}: not in the master list for zone %{dnsname}",
                        &mesg->other.sa, mesg->qname);

                mesg->status = FP_NONMASTER_NOTIFIES_SLAVE;
                mesg->send_length = mesg->received;
                return_value = NOTIFY_QUERY_FROM_UNKNOWN;
            }
#else
            if(!zone_isfrozen(zone_desc))
            {
                return_value = notify_masterquery(mesg, reader); // thread-safe
            }
            else
            {
                log_info("notify: slave: %{dnsname}: %{sockaddr}: zone is frozen", mesg->qname, &mesg->other.sa);
            }
#endif
        }   /* type = SLAVE */
        else
        {
            /* type = MASTER ? */

            // note: a slave can also be a master ... do not cut this
            
            log_warn("notify: %{dnsname}: %{sockaddr}: host sent a notification query for master zone ", mesg->qname, &mesg->other.sa);

            mesg->status = FP_SLAVE_NOTIFIES_MASTER;
            mesg->send_length = mesg->received;
            return_value = NOTIFY_QUERY_TO_MASTER;
        }
    }
    else
    {
        log_warn("notify: %{dnsname}: %{sockaddr}: host sent a notification query for an unknown zone", mesg->qname, &mesg->other.sa);

        MESSAGE_HIFLAGS(mesg->buffer) |= QR_BITS;
        mesg->status = FP_NOTIFY_UNKNOWN_ZONE;
        mesg->send_length = mesg->received;
        return_value = NOTIFY_QUERY_TO_UNKNOWN;
    }
    
    zone_release(zone_desc);
    
    return return_value;
}



/** @brief Handle a notify from the master (or another slave)
 *
 *  @param database : the database
 *  @param mesg     : the input message
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result
notify_process(message_data *mesg)
{
    ya_result return_value = ERROR;

    /* rfc1996
     * 3.7:
     *  A NOTIFY request has QDCOUNT>0, ANCOUNT>=0, AUCOUNT>=0,
     *  ADCOUNT>=0.  If ANCOUNT>0, then the answer section represents an
     *  unsecure hint at the new RRset for this <QNAME,QCLASS,QTYPE>
     */
        
    if(MESSAGE_QR(mesg->buffer))
    {
        /*
         * It's an answer from a slave (we are the master)
         * It works if we are the master for the zone AND we sent a notify.
         * Else we discard.
         */
        
        log_debug1("notify: %{dnsname}: %{sockaddr}: notification answer", mesg->qname, &mesg->other.sa);
        
        notify_slaveanswer(mesg);  // thread-safe
        
        return SUCCESS;
    }
    else
    {
        /*
         * It's a notification by the "master" ... (or in the case of an AXFR/CTRL a request to be notified of all dynamic zones)
         * It works if we are a slave for the zone.
         * Else we discard.
         */

        log_debug1("notify: %{dnsname}: %{sockaddr}: notification query", mesg->qname, &mesg->other.sa);

        packet_unpack_reader_data reader;
        packet_reader_init(&reader, mesg->buffer, mesg->received);
        reader.offset =  DNS_HEADER_LENGTH;
        
        u8 tmp[MAX_DOMAIN_LENGTH];

        if(ISOK(return_value = packet_reader_read_fqdn(&reader, tmp, sizeof(tmp))))
        {
            u16 qtype;
            
            if(ISOK(return_value = packet_reader_read_u16(&reader, &qtype)))
            {
                u16 qclass;
                
                if(ISOK(return_value = packet_reader_read_u16(&reader, &qclass)))
                {
                    switch(qclass)
                    {
                        case CLASS_IN:
                        {
                            /*
                             * Master sent an notify for the IN class
                             */
                            
                            notify_process_masterquery_in(mesg, &reader);
                            message_transform_to_error(mesg);
                            break;
                        }
                        

                        default:
                        {
                            mesg->status = FP_NOT_SUPP_CLASS;
                            message_make_error(mesg, mesg->status);
                            break;
                        }
                    }
                }
            }
        }

#if HAS_TSIG_SUPPORT
        if(TSIG_ENABLED(mesg))  /* NOTE: the TSIG information is in mseg */
        {
            tsig_sign_answer(mesg);
        }
#endif

        return return_value; /** @todo 20110616 edf -- give a specific error code */
    }
}

static void
notify_message_free(notify_message *msg)
{
    if(msg == NULL)
    {
        return;
    }
    
    if(msg->origin != NULL)
    {
        dnsname_zfree(msg->origin);
        msg->origin = NULL;
    }
    
    switch(msg->payload.type)
    {
        case NOTIFY_MESSAGE_TYPE_NOTIFY:
        {
            host_address_delete_list(msg->payload.notify.hosts_list);
            break;
        }
        case NOTIFY_MESSAGE_TYPE_ANSWER:
        {
#ifdef DEBUG
            log_debug("notify_message_free(%p) host_address_delete(%p)", msg, msg->payload.answer.host);
            debug_log_stacktrace(g_server_logger, MSG_DEBUG7, "notify_message_free:host_address_delete");
#endif
            host_address_delete(msg->payload.answer.host);
            if(msg->payload.answer.message != NULL)
            {
                free(msg->payload.answer.message); // message_data (free, not ZFREE)
            }
            break;
        }
        case NOTIFY_MESSAGE_TYPE_DOMAIN:
        {
            break;
        }
    }
#ifdef DEBUG
    memset(msg, 0xff, sizeof(notify_message));
#endif
    ZFREE(msg, notify_message);
}

static int
notify_process_dnsname_compare(const void *node_a, const void *node_b)
{
    const u8 *m_a = (const u8*)node_a;
    const u8 *m_b = (const u8*)node_b;

    return dnsname_compare(m_a, m_b);
}

static int
notify_service(struct service_worker_s *worker)
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
   
    log_info("notify: notification service started");

    message_data *msgdata;
    MALLOC_OR_DIE(message_data *,msgdata, sizeof(message_data), MESGDATA_TAG);
    ZEROMEMORY(msgdata, sizeof(message_data));

    random_ctx rnd = thread_pool_get_random_ctx();
    
    ptr_set notify_zones = PTR_SET_EMPTY;
    notify_zones.compare = notify_process_dnsname_compare;
    
    ptr_set current_queries = PTR_SET_EMPTY;
    current_queries.compare = message_query_summary_compare;
    u32 last_current_queries_cleanup_epoch_us = 0;

    /**
     * @todo 20111216 edf -- the idea here is to get the right interface.
     *       This loop breaking at the first result is of course wrong.
     */

    const addressv6 localhost6 = {.bytes = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}};
    socketaddress *sa4 = NULL;
    socketaddress *sa6 = NULL;
    
    bool send_socket4_is_localhost = FALSE;

    for(int i = 0; i < server_context.udp_interface_count; ++i)
    {
        int ai_family = server_context.udp_interface[i]->ai_family;
        
        if((( send_socket4 < 0) || send_socket4_is_localhost) && (ai_family == AF_INET))
        {
            socketaddress *sa = (socketaddress*)server_context.udp_interface[i]->ai_addr;
            
            u32 ipv4 = (u32)sa->sa4.sin_addr.s_addr;
            
            // avoid bad ones : filter out addresses that are not likely to be routed out
            
            if(
                ((ipv4 & NU32(0xf0000000)) != NU32(0xe0000000) ) && // 224.0.0.0/4
                ((ipv4 & NU32(0xffffffff)) != NU32(0xffffffff) ) )  // 255.255.255.255/32
            {
                int sockfd_index = i;
                
                if(server_context.reuse)
                {
                    sockfd_index *= server_context.udp_unit_per_interface;
                }
                
                // if the socket is localhost, mark it so it can be overwritten by a non-localhost
                send_socket4_is_localhost = ((ipv4 & NU32(0xff000000)) == NU32(0x7f000000) ); // 127.0.0.0/8
                
                send_socket4 = server_context.udp_socket[sockfd_index];
                sa4 = sa;
            }
            else
            {
                log_info("notify: %{sockaddr} cannot be used for notification", sa);
            }
        }
                
        if(( send_socket6 < 0) && (ai_family == AF_INET6))
        {
            socketaddress *sa = (socketaddress*)server_context.udp_interface[i]->ai_addr;
            addressv6 ipv6;
            memcpy(&ipv6, &sa->sa6.sin6_addr, 16);
            if(memcmp(&ipv6, &localhost6, 16) != 0) // ::1/128
            {
                int sockfd_index = i;
                if(server_context.reuse) sockfd_index *= server_context.udp_unit_per_interface;
                
                send_socket6 = server_context.udp_socket[sockfd_index];
                sa6 = sa;
            }
            else
            {
                log_info("notify: %{sockaddr} cannot be used for notification", sa);
            }
        }
    }

    if((send_socket4 >= 0))
    {
        log_info("notify: IPv4 notifications will be sent through %{sockaddr}", &sa4->sa);
    }
    else
    {
        log_warn("notify: no usable IPv4 socket bound");
    }
    
    if((send_socket6 >= 0))
    {
        log_info("notify: IPv6 notifications will be sent through %{sockaddr}", &sa6->sa);
    }
    else
    {
        log_warn("notify: no usable IPv6 socket bound");
        
        logger_flush();
        
        if(send_socket4 < 0)
        {
            log_warn("notify: no usable socket bound");
        }
    }
    
    /*
     */

    log_debug("notify: notification service main loop reached");

    while(service_shouldrun(worker) || !async_queue_emtpy(&notify_handler_queue))
    {
        {   /* what happens in here should not interfere with the rest of the function */
                
            u64 tus = timeus();

            if(!ptr_set_avl_isempty(&current_queries) && (tus > last_current_queries_cleanup_epoch_us))
            {
                /* create a list of expired message_query_summary */
                
                log_debug("notify: cleaning up expired notifications");

                message_query_summary head;
                head.next = NULL;
                message_query_summary *current = &head;
                last_current_queries_cleanup_epoch_us = tus;

                /* find them using an iterator */

                ptr_set_avl_iterator current_queries_iter;
                ptr_set_avl_iterator_init(&current_queries, &current_queries_iter);
                while(ptr_set_avl_iterator_hasnext(&current_queries_iter))
                {
                    ptr_node *node = ptr_set_avl_iterator_next_node(&current_queries_iter);
                    message_query_summary* mqs = (message_query_summary*)node->value;
                    if(last_current_queries_cleanup_epoch_us > mqs->expire_epoch_us)
                    {
#ifdef DEBUG
                        double expired_since = last_current_queries_cleanup_epoch_us - mqs->expire_epoch_us;
                        expired_since /= 1000000.0;
                        log_debug("notify: query (%hx) to %{hostaddr} expired %f seconds ago", mqs->id, mqs->host, expired_since);
#endif                  
                        if(--mqs->tries <= 0)
                        {
                            current->next = mqs;
                            current = mqs;
                        }
                        else
                        {
#ifdef DEBUG
                            log_debug("notify: query (%hx) to %{hostaddr} got %hhi tries left (NOT IMPLEMENTED)", mqs->id, mqs->host, mqs->tries);
#endif                  
                            mqs->expire_epoch_us = tus + MESSAGE_QUERY_TIMEOUT_US;
                            
                            // send the message again
                            
                            // notify_send(mqs->host, msgdata, mqs->id, origin, ztype, zclass);
                        }
                    }
                }

                /* once the tree has been scanned, destroy every node listed */

                current = head.next;
                while(current != NULL)
                {
                    message_query_summary* mqs = current;
                    current = current->next;
                    ptr_set_avl_delete(&current_queries, mqs);
                    message_query_summary_delete(mqs);
                }
            }
        }
        
        for(;;)
        {
            /* current_queries tree cleanup */
            
            async_message_s *async = async_message_next(&notify_handler_queue);

            if(async == NULL)   /* if no message is in the queue, proceed to next step */
            {
                break;
            }
            
            notify_message *message = (notify_message*)async->args;

            if(message == NULL) /* if no message is in the queue, proceed to next step (probably irrelevant) */
            {
                async_message_release(async);
                
                break;
            }

            switch(message->payload.type)
            {
                case NOTIFY_MESSAGE_TYPE_DOMAIN:
                {
                    if(!notify_slaves_convert_domain_to_notify(message))
                    {
                        // failed
                        break;
                    }
                    // fallthrough
                }
                case NOTIFY_MESSAGE_TYPE_NOTIFY:
                {
#ifndef DEBUG
                    log_info("notify: %{dnsname}: notifying slaves", message->origin);
#else
                    log_info("notify: %{dnsname}: notifying slaves with %{dnstype} %{dnsclass}", message->origin, &message->payload.notify.ztype, &message->payload.notify.zclass);
#endif
                    host_address **ha_prev = &message->payload.notify.hosts_list;
                    host_address *ha = *ha_prev;
                    
                    while(ha != NULL) // resolve all domain names in the list, replace them with the resolved address
                    {
                        if(ha->version == HOST_ADDRESS_DNAME)
                        {
                            /* resolve */
                            char name[MAX_DOMAIN_LENGTH + 1];

                            dnsname_to_cstr(name, ha->ip.dname.dname);

                            struct hostent *he = gethostbyname(name);
                            
                            if(he != NULL)
                            {
                                host_address_append_hostent(message->payload.notify.hosts_list, he, NU16(DNS_DEFAULT_PORT));
                            }
                            else
                            {
                                log_warn("notify: %{dnsname}: unable to resolve %{dnsname}", message->origin, ha->ip.dname.dname);
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

                    /*
                     * @todo 20111216 edf -- remove myself
                     */

                    /**
                     * The list has to replace the current one for message->origin (because it's starting again)
                     */

                    ptr_node *node = ptr_set_avl_insert(&notify_zones, message->origin);

                    if(node->value != NULL)
                    {
                        notify_message* old_message = (notify_message*)node->value; // get the old value
                        node->key = message->origin;                                // (same key but the old pointer is about to be deleted)
                        node->value = message;                                      // set the new value
                        notify_message_free(old_message);                           // destroy the old value.  notify_zones does not contains it anymore
                    }
                    else
                    {
                        node->value = message;
                    }

                    message->payload.notify.epoch = time(NULL);

                    break;
                }
                case NOTIFY_MESSAGE_TYPE_ANSWER:
                {
                    log_info("notify: %{dnsname}: answer from slave at %{hostaddr}", message->origin, message->payload.answer.host);
                    
                    ptr_node *node = ptr_set_avl_find(&notify_zones, message->origin);
                    
                    if(node != NULL)
                    {
                        notify_message *msg = (notify_message*)node->value;

                        if(msg != NULL)
                        {
                            /*
                             * Look for the entry and remove it
                             */
                            
                            /**
                             * @todo 20121130 edf -- VERIFY THE TSIG HERE
                             * 
                             * The possible TSIG in the message has to be verified here
                             */
                         
                            /* message->payload.answer.tsig ... */
                            
                            /* all's good so remove the notify query from the list */
                            
                            if(host_address_list_contains_host(msg->payload.notify.hosts_list, message->payload.answer.host))
                            {
                                host_address *ha;
#if HAS_TSIG_SUPPORT
                                ha = message->payload.answer.host;
                                
                                message_query_summary tmp;
                                
                                if(ha->tsig != NULL)
                                {
                                    u16 id = MESSAGE_ID(message->payload.answer.message->buffer);
                                    message_query_summary_init(&tmp, id, ha, NULL, 0);
                                    // try to find the exact match
                                    ptr_node *node = ptr_set_avl_find(&current_queries, &tmp);
                                    message_query_summary_clear(&tmp);
                                    if(node == NULL)
                                    {
                                        /* most likely a timeout */
                                        
                                        log_err("notify: %{dnsname}: %{hostaddr}: unexpected answer: could not find a matching query for notification answer with id %04hx",
                                                message->origin, message->payload.answer.host, id);
                                        // delete message
                                        notify_message_free(message);

                                        break;
                                    }
                                    
                                    message_query_summary *mqs = (message_query_summary*)node->value;
                                    
                                    yassert(mqs != NULL);
                                    
                                    // verify the signature
                                    
                                    message_data *mesg = message->payload.answer.message;
                                    ya_result return_value;
                                    
                                    if(FAIL(return_value = tsig_verify_answer(mesg, mqs->mac, mqs->mac_size)))
                                    {
                                        // if everything is good, then proceed
                                        
                                        log_err("notify: %{dnsname}: %{hostaddr}: TSIG signature verification failed: %r",
                                                message->origin, message->payload.answer.host, return_value);
                                        // delete message
                                        notify_message_free(message);
                                        
                                        break;
                                    }
                                    
                                    free(message->payload.answer.message); // message_data, free, not ZFREE
                                    message->payload.answer.message = NULL;
                                    ptr_set_avl_delete(&current_queries, mqs);
                                    message_query_summary_delete(mqs);
                                } /* end of TSIG verification, with success*/
#endif
                                ha = host_address_remove_host_address(&msg->payload.notify.hosts_list, message->payload.answer.host);
                                host_address_delete(ha);

                                if(message->payload.answer.rcode == RCODE_OK)
                                {
                                    if(!message->payload.answer.aa)
                                    {
                                        log_err("notify: %{dnsname}: %{hostaddr}: no AA in answer",
                                                    message->origin, message->payload.answer.host);
                                    }
                                }
                                else
                                {
                                    log_err("notify: %{dnsname}: %{hostaddr}: answered with error %r",
                                                message->origin, message->payload.answer.host, MAKE_DNSMSG_ERROR(message->payload.answer.rcode));
                                }
                            }
                            else
                            {
                                log_err("notify: %{dnsname}: %{hostaddr}: unexpected answer: host is not on the currently notified list", message->origin, message->payload.answer.host);
                            }
                            
                            if(msg->payload.notify.hosts_list == NULL) /// @todo 20150616 edf -- there was a clear NULL dereference. test the fix
                            {
                                ptr_set_avl_delete(&notify_zones, msg->origin);
                                notify_message_free(msg);
                            }
                        }
                        else // msg = NULL
                        {
                            log_err("notify: %{dnsname}: %{hostaddr}: unexpected answer", message->origin, message->payload.answer.host);
                            ptr_set_avl_delete(&notify_zones, message->origin); /// @todo 20150616 edf -- there was a clear NULL reference. test the fix
                        }
                    }
                    else
                    {
                        log_err("notify: %{dnsname}: %{hostaddr}: unexpected answer: no pending notifications for the zone", message->origin, message->payload.answer.host);
                    }
                    
                    // delete message
                    notify_message_free(message);

                    break;
                }
#ifdef DEBUG
                default:
                {
                    log_err("notify: unknown message type %i", message->payload.type);
                    break;
                }
#endif
            } /* switch message type */
            
            async_message_release(async);
        } // for(;;)

        /*
         * For all entries in the queue, send a notify to the ones that need to be repeated
         */

        time_t now = time(NULL);

        ptr_vector todelete = EMPTY_PTR_VECTOR;
        ptr_set_avl_iterator zones_iter;
        ptr_set_avl_iterator_init(&notify_zones, &zones_iter);

        while(ptr_set_avl_iterator_hasnext(&zones_iter))
        {
            ptr_node *zone_node = ptr_set_avl_iterator_next_node(&zones_iter);

            notify_message *message = zone_node->value;

            if(message->payload.notify.epoch > now)
            {
                continue;
            }

            host_address *ha = message->payload.notify.hosts_list;

            while(ha != NULL)
            {
                /*
                 * Send an UDP packet to the ha
                 */

                u16 id = random_next(rnd);
                
                ya_result err = notify_send(ha, msgdata, id, message->origin, message->payload.notify.ztype, message->payload.notify.zclass);
                
                host_address *ha_next = ha->next;
                
                if(ISOK(err))
                {
                    message_query_summary* mqs;
                    ZALLOC_OR_DIE(message_query_summary*, mqs, message_query_summary, MSGQSUMR_TAG);

#if HAS_TSIG_SUPPORT
                    message_query_summary_init(mqs, id, ha, msgdata->tsig.mac, msgdata->tsig.mac_size);
#else
                    message_query_summary_init(mqs, id, ha, NULL, 0);
#endif
                    ptr_node *node = ptr_set_avl_insert(&current_queries, mqs);

                    if(node->value != NULL)
                    {
                        // destroy this mqs
#ifdef DEBUG
                        log_debug("notify: node %{hostaddr}[%04x] already exists, replacing", mqs->host, mqs->id);
#endif
                        message_query_summary_delete(node->value);
                        node->key = mqs;
                    }

                    node->value = mqs;
                }
                else // remove it
                {
                    host_address *rem_ha = host_address_remove_host_address(&message->payload.notify.hosts_list, ha);
                    
                    if(rem_ha != NULL)
                    {
                        host_address_delete(rem_ha);
                    }
                }
                
                ha = ha_next;
            }

            /* decrease the countdown or remove it from the collection */

            if(message->payload.notify.repeat_countdown != 0)
            {
                message->payload.notify.repeat_countdown--;
                
                /* ensure there is no overload */
                
                u16 rp = message->payload.notify.repeat_period + message->payload.notify.repeat_period_increase;
                
                if(rp > 255) /* minutes, 8 bits */
                {
                    rp = 255;
                }
                
                message->payload.notify.repeat_period = (u8)rp;
                
                message->payload.notify.epoch = now + message->payload.notify.repeat_period * 60; // repeat_period is minutes
            }
            else
            {
                ptr_vector_append(&todelete, message);
            }
        }

        notify_message **msgs = (notify_message**)todelete.data;
        
        for(s32 idx = 0; idx <= todelete.offset; idx++)
        {
            notify_message *msg = msgs[idx];
            ptr_set_avl_delete(&notify_zones, msg->origin);
            notify_message_free(msg);
        }

        sleep(1);
    }
    
    service_set_stopping(worker);
    
    ptr_set_avl_iterator iter;
    
    u32 total_count;
    u32 count;
    
    total_count = 0;
    count = 0;
    ptr_set_avl_iterator_init(&notify_zones, &iter);
    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        //host_address *ha = (host_address*)node->key;
        
        notify_message* message = (notify_message*)node->value;  // get the old value
        if(message != NULL)
        {
            notify_message_free(message);                           // destroy the message
            node->key = NULL;                                       // (same key but the old pointer is about to be deleted)
            node->value = NULL;                                      // set the new value
            count++;
        }
        total_count++;
    }
    log_debug("notify: cleared %u messages", count);
    if(count != total_count)
    {
        log_err("notify: %u messages were empty", total_count - count);
    }
    ptr_set_avl_destroy(&notify_zones);
    
    total_count = 0;
    count = 0;
    ptr_set_avl_iterator_init(&current_queries, &iter);
    while(ptr_set_avl_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_avl_iterator_next_node(&iter);
        message_query_summary* mqs = (message_query_summary*)node->value;
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
        log_err("notify: %u summaries were empty", total_count - count);
    }
    ptr_set_avl_destroy(&current_queries);
    
    if(msgdata != NULL)
    {
        free(msgdata); // message_data
    }
    
    log_info("notify: notification service stopped");
    
    return 0;
}

/**
 * Sends a notify to all the slave for a given domain name:
 * 
 * _ Get the zone
 * _ Create an empty list
 * _ If notify-auto, add all the IPs of all the NS at the apex of the zone to the list.
 * _ Add all the also-notify IPs to the list
 * _ Queue the list to the notify service
 * 
 * @param origin
 */

void
notify_slaves(const u8 *origin)
{
    if(!notify_service_initialised)
    {
        return;
    }
    
    notify_message *message;
    ZALLOC_OR_DIE(notify_message*, message, notify_message, NOTFYMSG_TAG);

    message->origin = dnsname_zdup(origin);
    message->payload.domain.type = NOTIFY_MESSAGE_TYPE_DOMAIN;

    async_message_s *async = async_message_alloc();
    async->id = 0;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&notify_handler_queue, async);
}

/**
 * 
 * @param origin
 */

static bool
notify_slaves_convert_domain_to_notify(notify_message *message)
{
    if(!notify_service_initialised)
    {
        return FALSE;
    }

    /*
     * Build a list of IPs to contact
     * The master in the SOA must not be in this list
     * The current server must not be in this list
     *
     * Once the list is done, launch a thread that will periodically retry anybody in this list until the list is empty
     *
     * The list should be mutexed
     * The list should be in a by-origin collection
     * The list should be rebuild for each new notification (because the zone could have changed)
     */

    zdb *db = g_config->database;

    zdb_zone *zone = zdb_acquire_zone_read_from_fqdn(db, message->origin); // RC++
    
    if((zone == NULL) || ZDB_ZONE_INVALID(zone))
    {
        if(zone != NULL)
        {
            zdb_zone_release(zone);
        }
        
        log_debug("notify: %{dnsname}: zone temporarily unavailable", message->origin);
        
        return FALSE;
    }
    
    zone_desc_s *zone_desc = zone_acquirebydnsname(message->origin);
    if(zone_desc == NULL)
    {
        zdb_zone_release(zone);
        log_err("notify: %{dnsname}: zone not configured", message->origin);
        return FALSE;
    }
    
    host_address list;
#ifdef DEBUG
    memset(&list, 0xff, sizeof(list));
#endif
    list.next = NULL;
    /* no need to set TSIG */
    
    if(zone_ismaster(zone_desc) && zone_is_auto_notify(zone_desc))
    {
        zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        
        // get the SOA
        zdb_packed_ttlrdata *soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);
        // get the NS
        zdb_packed_ttlrdata *ns = zdb_record_find(&zone->apex->resource_record_set, TYPE_NS);    
        // get the IPs for each NS but the one in the SOA

        u8 *soa_mname = ZDB_PACKEDRECORD_PTR_RDATAPTR(soa);
        u32 soa_mname_size = dnsname_len(soa_mname);
        u8 *soa_rname = soa_mname + soa_mname_size;
        u8 *serial_ptr = soa_rname + dnsname_len(soa_rname);
        u32 serial = *((u32*)serial_ptr);
        serial = ntohl(serial);

        for(zdb_packed_ttlrdata *nsp = ns; nsp != NULL; nsp = nsp->next)
        {
            u32 ns_dname_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(nsp);
            u8 *ns_dname = ZDB_PACKEDRECORD_PTR_RDATAPTR(nsp);

            if(ns_dname_size == soa_mname_size)
            {
                if(memcmp(ns_dname, soa_mname, soa_mname_size) == 0)
                {
                    continue;
                }
            }

            /* valid candidate : get its IP, later */
            
#if 1
            if(zdb_append_ip_records(db, ns_dname, &list) <= 0)
            {
                // If no IP has been found, they will have to be resolved using the system ... later

                host_address_append_dname(&list, ns_dname, NU16(DNS_DEFAULT_PORT));
            }
#else
            zdb_packed_ttlrdata *a_records = NULL;
            zdb_packed_ttlrdata *aaaa_records = NULL;

            zdb_query_ip_records(db, ns_dname, &a_records, &aaaa_records);

            // If there is any bit set in the returned pointers ...

            if(((intptr)a_records|(intptr)aaaa_records) != 0)
            {
                // Add these IPs to the list.

                while(a_records != NULL)
                {
                    host_address_append_ipv4(&list, ZDB_PACKEDRECORD_PTR_RDATAPTR(a_records), NU16(DNS_DEFAULT_PORT));
                    a_records = a_records->next;
                }
                while(aaaa_records != NULL)
                {
                    host_address_append_ipv6(&list, ZDB_PACKEDRECORD_PTR_RDATAPTR(aaaa_records), NU16(DNS_DEFAULT_PORT));
                    aaaa_records = aaaa_records->next;
                }
            }
            else
            {
                // If no IP has been found, they will have to be resolved using the system ... later

                host_address_append_dname(&list, ns_dname, NU16(DNS_DEFAULT_PORT));
            }
#endif
        }
        
        zdb_zone_release_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    }
    else
    {
        zdb_zone_release(zone);
    }

    // at this point I have the list of every IP I could find along with names I cannot resolve.
    // note that we don't need to care about the changes in the database : it would mean a new
    // notify and this one would be discarded

    host_address *also_notifies = zone_desc->notifies;

    while(also_notifies != NULL)
    {
        host_address_append_host_address(&list, also_notifies); //copy made

        also_notifies = also_notifies->next;
    }

    // It's separate from the DB push the lot

    // thread from the pool

    if(list.next != NULL)
    {

        message->payload.type = NOTIFY_MESSAGE_TYPE_NOTIFY;
        message->payload.notify.hosts_list = list.next;
        message->payload.notify.repeat_countdown = zone_desc->notify.retry_count; /* 10 times */
        message->payload.notify.repeat_period = zone_desc->notify.retry_period; /* 1 minute */
        message->payload.notify.repeat_period_increase = zone_desc->notify.retry_period_increase; /* 1 minute */
        message->payload.notify.ztype = TYPE_SOA;
        message->payload.notify.zclass = CLASS_IN;

    }
    
    zone_release(zone_desc);
    
    return message->payload.type == NOTIFY_MESSAGE_TYPE_NOTIFY;
}


/**
 * Stops all notification for zone with origin
 * 
 * @param origin
 */

void
notify_clear(const u8 *origin)
{
    (void)origin;

}

void
notify_host_list(zone_desc_s *zone_desc, host_address *hosts, u16 zclass)
{
    notify_message *message;

    ZALLOC_OR_DIE(notify_message*, message, notify_message, NOTFYMSG_TAG);

    message->origin = dnsname_zdup(zone_desc->origin);
    message->payload.type = NOTIFY_MESSAGE_TYPE_NOTIFY;
    message->payload.notify.hosts_list = hosts;
    message->payload.notify.repeat_countdown = zone_desc->notify.retry_count; /* 10 times */
    message->payload.notify.repeat_period = zone_desc->notify.retry_period; /* 1 minute */
    message->payload.notify.repeat_period_increase = zone_desc->notify.retry_period_increase; /* 1 minute */
    message->payload.notify.ztype = TYPE_SOA;
    message->payload.notify.zclass = zclass;

    async_message_s *async = async_message_alloc();
    async->id = 0;
    async->args = message;
    async->handler = NULL;
    async->handler_args = NULL;
    async_message_call(&notify_handler_queue, async);
}



ya_result
notify_service_init()
{
    int err = SUCCESS;
    if(!notify_service_initialised)
    {
        if(notify_thread_pool == NULL)
        {
            if((notify_thread_pool = thread_pool_init_ex(10, 4096, "notify-tp")) == NULL)
            {
                return ERROR;
            }
        }
        
        if(ISOK(err = service_init_ex(&notify_handler, notify_service, "yadifad-notify", 1)))
        {
            async_queue_init(&notify_handler_queue, 4096, 1, 1000000, "yadifad-notify");
            
            notify_service_initialised = TRUE;
        }
    }
    
    return err;
}

/**
 * Starts the notify service thread
 */

ya_result
notify_service_start()
{
    int err = ERROR;
    
    if(notify_service_initialised)
    {
        if(service_stopped(&notify_handler))
        {
            err = service_start(&notify_handler);
        }
    }
    
    return err;
}

/**
 * Stops the notify service thread
 */

ya_result
notify_service_stop()
{
    int err = ERROR;
    
    if(notify_service_initialised)
    {
        if(!service_stopped(&notify_handler))
        {
            err = service_stop(&notify_handler);
            service_wait(&notify_handler);
        }
    }
    
    return err;
}

ya_result
notify_service_finalise()
{
    int err = SUCCESS;
    
    if(notify_service_initialised)
    {
        err = notify_service_stop();
        
        service_finalize(&notify_handler);

        async_queue_finalize(&notify_handler_queue);
        
        if(notify_thread_pool != NULL)
        {
            thread_pool_destroy(notify_thread_pool);
            notify_thread_pool = NULL;
        }

        notify_service_initialised = FALSE;
    }

    return err;
}


/** @} */

/*----------------------------------------------------------------------------*/

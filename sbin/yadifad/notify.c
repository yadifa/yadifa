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
/** @defgroup 
 *  @ingroup yadifad
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>

#include <dnscore/rfc.h>
#include <dnscore/logger.h>
#include <dnscore/serial.h>
#include <dnscore/format.h>
#include <dnscore/threaded_queue.h>
#include <dnscore/thread_pool.h>

#include <dnsdb/zdb.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/zdb_record.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb_zone_load.h>

#include <dnszone/dnszone.h>
#include <dnszone/zone_axfr_reader.h>

#include <dnscore/treeset.h>

#include "notify.h"

#include "zone.h"

#include "scheduler_xfr.h"

#include "server.h"

#include "server_error.h"

#define NOTFYMSG_TAG 0x47534d5946544f4e
#define MESGDATA_TAG 0x415441444753454d


/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#define NOTIFY_MESSAGE_TYPE_STOP    0
#define NOTIFY_MESSAGE_TYPE_NOTIFY  1
#define NOTIFY_MESSAGE_TYPE_ANSWER  2

typedef struct notify_message notify_message;

struct notify_message_notify
{
    u8 type;
    u8 repeat_countdown;
    u8 repeat_period;
    u8 repeat_period_increase;
    u32 epoch;
    host_address *hosts_list;
};

struct notify_message_answer
{
    u8   type;
    u8   rcode;
    bool aa;
    u8   r2;
    host_address host;
};

struct notify_message
{
    u8 *origin;

    union
    {
        u8 type;
        struct notify_message_notify notify;
        struct notify_message_answer answer;
    } payload;
};

static pthread_t notify_process_thread_id = 0;
static threaded_queue notify_message_queue;


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
notify_slaveanswer(u8 *origin, socketaddress *sa, u8 rcode, bool aa)
{
    notify_message *message;

    if(notify_process_thread_id != 0)
    {
        MALLOC_OR_DIE(notify_message*, message, sizeof(notify_message), NOTFYMSG_TAG);

        message->origin = dnsname_dup(origin);
        message->payload.type = NOTIFY_MESSAGE_TYPE_ANSWER;
        message->payload.answer.rcode = rcode;
        message->payload.answer.aa = aa;

        host_address_set_with_sockaddr(&message->payload.answer.host, sa);

        threaded_queue_enqueue(&notify_message_queue, message);
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

        if(packet_reader_read(reader, (u8*)&tctr, 10) == 10)
        {
            if((tctr.qtype == TYPE_SOA) && (tctr.qclass == CLASS_IN))
            {
                if(ISOK(return_value = packet_reader_skip_fqdn(reader)))
                {
                    if(ISOK(return_value = packet_reader_skip_fqdn(reader)))
                    {
                        if(packet_reader_read(reader, tmp, 4) == 4)
                        {
                            *serial = ntohl(*((u32*)tmp));
                            
                            return TRUE;
                        }
                    }
                }
            }
        }
    }
    
    return FALSE;
}

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
    
    zone_data *zone = zone_getbydnsname(args->origin);
    
    ya_result return_value;
    
    if(zone == NULL)
    {
        log_err("notify: slave: zone %{dnsname} has been dropped", args->origin);
        
        free(args);
        
        return NULL;
    }
    
    /* do an SOA query to the master to retrieve the serial (wait) */
    
    if(!args->serial_set)
    {
        if(ISOK(return_value = message_query_serial(args->origin, zone->masters, &args->serial)))
        {
            args->serial_set = TRUE;
        }
        else
        {
            /* we didn't got the serial */
            
            log_debug("notify: slave: %{dnsname} SOA query to the master failed: %r", args->origin, return_value);
        }
    }
    
    u32 current_serial;

    /* get the zone of the domain */

    zdb_zone *dbzone = zdb_zone_find_from_dnsname((zdb*)g_config->database, args->origin, CLASS_IN);

    if(dbzone != NULL)
    {
        /* lock it for the XFR (it's a writer, so no other writer allowed) */
        
        if(zdb_zone_trylock(dbzone, ZDB_ZONE_MUTEX_XFR))
        {
            /* get the current serial of the zone */
            
            if(ISOK(zdb_zone_getserial(dbzone, &current_serial)))
            {
               /*
                * Ok, just to avoid weird stuff : if the serial on the "master" is lower,
                * nothing has to be done except a note on the log.
                * 
                * If we didn't got the serial of course, we can only ask to the master.
                */

                if(args->serial_set)
                {
                    if(serial_lt(args->serial, current_serial))
                    {
                        /* do nothing at all */
                        
                        log_warn("notify: slave: serial number on this slave is higher (%u) than on the notifier (%u)", current_serial, args->serial);
                    }
                    else if(serial_gt(args->serial, current_serial))
                    {
                        /* download (and apply) the incremental change  */

                        log_info("notify: slave: scheduling an IXFR for %{dnsname}", zone->origin);

                        zone_setloading(zone, TRUE);
                        scheduler_ixfr_query(g_config->database, zone->masters, zone->origin);
                    }
                    else
                    {
                        /* nothing to do but mark the zone as being refreshed */

                        log_info("notify: slave: already the last version");

                        dbzone->apex->flags &= ~ZDB_RR_LABEL_INVALID_ZONE;
                        zone->refresh.refreshed_time = zone->refresh.retried_time = time(NULL);
                        
                        zdb_zone_unlock(dbzone, ZDB_ZONE_MUTEX_XFR);                         /* MUST be unlocked here because ... */
                        database_zone_refresh_maintenance(g_config->database, zone->origin); /* ... this will try to lock */
                        
                        free(args);                        
                        return NULL;
                    }
                }
                else
                {
                    log_warn("notify: slave: the serial of the master has not been obtained");

                    zone_setloading(zone, TRUE);
                    scheduler_ixfr_query(g_config->database, zone->masters, zone->origin);
                }
            }

            zdb_zone_unlock(dbzone, ZDB_ZONE_MUTEX_XFR);
        }
        else
        {
           /*
            * The zone has been locked already ? give up ...
            */

            log_info("notify: slave: zone %{dnsname} is locked already (%x)", args->origin, dbzone->mutex_owner);

            database_zone_refresh_maintenance(g_config->database, args->origin);
        }
    }
    else
    {
        /*
         * Ask for an AXFR of the zone
         */

        log_info("notify: slave: scheduling an AXFR for %{dnsname}", zone->origin);

        zone_setloading(zone, TRUE);
        scheduler_axfr_query(g_config->database, zone->masters, zone->origin);
    }   /* AXFR */
    
    free(args);
    
    return NULL;
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
notify_masterquery(database_t *database, message_data *mesg, packet_unpack_reader_data *reader)
{
    ya_result return_value;
        
    u32 serial = 0; // to silence gcc : this was not a bug
    bool serial_set = FALSE;
    
    if(MESSAGE_AN(mesg->buffer) != 0)
    {
        serial_set = notify_masterquery_read_soa(mesg->qname, reader, &serial);
    }
    
    notify_masterquery_thread_args *args;
    
    MALLOC_OR_DIE(notify_masterquery_thread_args*, args, sizeof(notify_masterquery_thread_args), GENERIC_TAG);
    
    args->origin = dnsname_dup(mesg->qname);
    args->serial = serial;
    args->serial_set = serial_set;
    
    return_value = thread_pool_schedule_job(notify_masterquery_thread, args, NULL, "notify: slave");
    
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
notify_process(database_t *database, message_data *mesg)
{
    ya_result return_value = ERROR;
    u8 tmp[512];

    /* rfc1996
     * 3.7:
     *  A NOTIFY request has QDCOUNT>0, ANCOUNT>=0, AUCOUNT>=0,
     *  ADCOUNT>=0.  If ANCOUNT>0, then the answer section represents an
     *  unsecure hint at the new RRset for this <QNAME,QCLASS,QTYPE>
     */
    
    if(MESSAGE_QR(mesg->buffer))
    {
        /*
         * It's an answer.
         * It works if we are the master for the zone AND we sent a notify.
         * Else we discard.
         */
        
        notify_slaveanswer(mesg->qname, &mesg->other, MESSAGE_RCODE(mesg->buffer), MESSAGE_AA(mesg->buffer)!=0);  // thread-safe

        //mesg->status = RCODE_NOTIMP;
        //return ERROR;
        return SUCCESS;
    }
    else
    {
        /*
         * It's a notification by the master.
         * It works if we are a slave for the zone.
         * Else we discard.
         */

        log_debug("notify: notification query");

        packet_unpack_reader_data reader;
        packet_reader_init(mesg->buffer, mesg->received, &reader);
        reader.offset =  DNS_HEADER_LENGTH;

        if(ISOK(return_value = packet_reader_read_fqdn(&reader, tmp, sizeof(tmp))))
        {
            zone_data *zone_config = zone_getbydnsname(tmp);

            if(zone_config != NULL)
            {
                MESSAGE_HIFLAGS(mesg->buffer) |= AA_BITS;
                
                if(zone_config->type == ZT_SLAVE)
                {
                    log_info("notify: notification query for slave zone %{dnsname}", tmp);
                    
#if HAS_ACL_SUPPORT == 1
                    if(ACL_REJECTED(acl_check_access_filter(mesg, &zone_config->ac.allow_notify)))
                    {
                        /* notauth */

                        log_warn("notify: not authorised");
                        
                        mesg->status = FP_NOTIFY_REJECTED;

                        return ACL_NOTIFY_REJECTED;
                    }
#endif
                    if(host_address_list_contains_ip(zone_config->masters, &mesg->other))
                    {
                        MESSAGE_HIFLAGS(mesg->buffer) |= QR_BITS|AA_BITS;
                        mesg->send_length = mesg->received;
                        message_transform_to_error(mesg);
                        udp_send_message_data(mesg);

                        if(zone_isidle(zone_config))
                        {
                            return notify_masterquery(database, mesg, &reader); // thread-safe
                        }
                        else
                        {
                            log_info("notify: slave: zone %{dnsname} is loading already", zone_config->origin);
                            /* or not */
                            database_zone_refresh_maintenance(g_config->database, zone_config->origin); // thread-safe

                            return SUCCESS;
                        }
                    }
                    else
                    {
                        log_warn("notify: slave: notification from %{sockaddr}: not in the master list for zone %{dnsname}", &mesg->other.sa, tmp);
                    
                        mesg->status = FP_NONMASTER_NOTIFIES_SLAVE;
                        return_value = NOTIFY_QUERY_FROM_UNKNOWN;
                    }
                }   /* type = SLAVE */
                else
                {
                    /* type = MASTER ? */

                    log_warn("notify: notification query for master zone %{dnsname}", tmp);

                    mesg->status = FP_SLAVE_NOTIFIES_MASTER;
                    return_value = NOTIFY_QUERY_TO_MASTER;
                }
            }
            else
            {
                log_warn("notify: notification query for unknown zone %{dnsname}", tmp);

                mesg->status = FP_NOTIFY_UNKNOWN_ZONE;
                return_value = NOTIFY_QUERY_TO_UNKNOWN;
            }
        }

        /* drop */

        return return_value; /** @todo give a specific error code */
    }
}

static void
notify_message_free(notify_message *msg)
{
    if(msg->origin != NULL)
    {
        free(msg->origin);
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
            host_address_delete(&msg->payload.answer.host);
            break;
        }
    }
    free(msg);
}

static int
notify_process_dnsname_compare(const void *node_a, const void *node_b)
{
    const u8 *m_a = (const u8*)node_a;
    const u8 *m_b = (const u8*)node_b;

    return dnsname_compare(m_a, m_b);
}

static void*
notify_process_thread(void *list_)
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

    message_data *msgdata;
    MALLOC_OR_DIE(message_data *,msgdata, sizeof(message_data), MESGDATA_TAG);
    ZEROMEMORY(msgdata, sizeof(message_data));

    thread_pool_setup_random_ctx();
    random_ctx rnd = thread_pool_get_random_ctx();
    
    treeset_tree notify_zones = TREESET_EMPTY;
    notify_zones.compare = notify_process_dnsname_compare;

    int send_socket4 = -1;
    int send_socket6 = -1;

    /**
     * @todo the idea here is to get the right interface.
     *       This loop breaking at the first result is of course wrong.
     */

    for(interface *intf = g_config->interfaces; intf < g_config->interfaces_limit; intf++)
    {
        if(( send_socket4 < 0) && (intf->udp.addr->ai_family == AF_INET))
        {
            send_socket4 = intf->udp.sockfd;
        }
        if(( send_socket6 < 0) && (intf->udp.addr->ai_family == AF_INET6))
        {
            send_socket6 = intf->udp.sockfd;
        }
    }

    /*
     */

    log_info("notify: notification service started");

    for(;;)
    {
        for(;;)
        {
            notify_message *message = (notify_message*)threaded_queue_try_dequeue(&notify_message_queue);

            if(message == NULL)
            {
                break;
            }

            switch(message->payload.type)
            {
                case NOTIFY_MESSAGE_TYPE_STOP:
                {
                    /**
                     * @todo cleanup the collection
                     *      (not really needed since we are about to shutdown)
                     */

                    log_info("notify: notification service stopped");
                    
                    notify_message_free(message);
                    
                    free(msgdata);

                    return NULL;
                }
                case NOTIFY_MESSAGE_TYPE_NOTIFY:
                {
                    log_info("notify: notifying slaves for %{dnsname}", message->origin);

                    host_address **ha_prev = &message->payload.notify.hosts_list;
                    host_address *ha = *ha_prev;
                    
                    while(ha != NULL)
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
                                log_warn("notify: unable to resolve %{dnsname}", ha->ip.dname.dname);
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
                     * @todo remove myself
                     */

                    /**
                     * The list has to replace the current one for message->origin
                     */

                    treeset_node *node = treeset_avl_insert(&notify_zones, message->origin);

                    if(node->data != NULL)
                    {
                        notify_message* old_message = (notify_message*)node->data;
                        node->key = message->origin;
                        node->data = message;
                        notify_message_free(old_message);
                    }
                    else
                    {
                        node->data = message;
                    }

                    message->payload.notify.epoch = time(NULL);
                    

                    break;
                }
                case NOTIFY_MESSAGE_TYPE_ANSWER:
                {
                    treeset_node *node = treeset_avl_find(&notify_zones, message->origin);
                    
                    if(node != NULL)
                    {
                        notify_message *msg = (notify_message*)node->data;

                        if(msg != NULL)
                        {
                            /*
                             * Look for the entry and remove it
                             */
                            
                            host_address *ha = host_address_remove_host_address(&msg->payload.notify.hosts_list, &message->payload.answer.host);

                            if(ha != NULL)
                            {
                                host_address_delete(ha);
                            
                                if(message->payload.answer.rcode == RCODE_OK)
                                {                                                                
                                    if(!message->payload.answer.aa)
                                    {
                                        log_err("notify: answer from %{hostaddr} for %{dnsname}: no AA", &message->payload.answer.host, message->origin);
                                    }
                                }
                                else
                                {
                                    log_err("notify: error from %{hostaddr} for %{dnsname}: %r", &message->payload.answer.host, message->origin, MAKE_DNSMSG_ERROR(message->payload.answer.rcode));
                                }
                            }
                            else
                            {
                                log_err("notify: unexpected answer from %{hostaddr} for %{dnsname}", &message->payload.answer.host, message->origin);
                            }
                        }
                        else
                        {
                            log_err("notify: unexpected answer by %{hostaddr} for %{dnsname}", &message->payload.answer.host, message->origin);
                        }
                        
                        if(msg->payload.notify.hosts_list == NULL)
                        {
                            treeset_avl_delete(&notify_zones, msg->origin);
                            notify_message_free(msg);
                        }
                    }
                    else
                    {
                        log_err("notify: unexpected answer by %{hostaddr} for %{dnsname}", &message->payload.answer.host, message->origin);
                    }

                    break;
                }
            }
        }

        /*
         * For all entries in the queue, send a notify to the ones that need to be repeated
         */

        time_t now = time(NULL);

        ptr_vector todelete = EMPTY_PTR_VECTOR;
        treeset_avl_iterator zones_iter;
        treeset_avl_iterator_init(&notify_zones, &zones_iter);

        while(treeset_avl_iterator_hasnext(&zones_iter))
        {
            treeset_node *zone_node = treeset_avl_iterator_next_node(&zones_iter);

            notify_message *message = zone_node->data;

            if(message->payload.notify.epoch < now)
            {
                continue;
            }

            host_address *ha = message->payload.notify.hosts_list;

            while(ha != NULL)
            {
                /*
                 * Send an UDP packet to the ha
                 */

                socketaddress sa;
                
                u16 id = random_next(rnd);
                
                message_make_notify(msgdata, id, message->origin); /** @todo check if adding the SOA helps bind to update faster */
                
                if(ha->tsig != NULL)
                {
                    ya_result return_code;
                    
                    if(FAIL(return_code = message_sign_query(msgdata, ha->tsig)))
                    {
                        log_err("notify: unable to sign message for %{sockaddr} with key %{dnsname}: %r", &sa, ha->tsig->name, return_code);
                        ha = ha->next;

                        continue;
                    }
                }
                
                bool remove_it = FALSE;

                if(ISOK(host_address2sockaddr(&sa, ha)))
                {
                    log_info("notify: notifying %{sockaddr} about %{dnsname}", &sa.sa, message->origin);
                    
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
                        if(FAIL(sendto(s, msgdata->buffer, msgdata->send_length, 0, &sa.sa, addrlen)))
                        {
                            log_err("notify: unable to send notify to %{sockaddr}: %r", &sa.sa, ERRNO_ERROR);
                            remove_it = TRUE;
                        }
                    }
                    else
                    {
                        log_err("notify: no listening interface can send to %{sockaddr}", &sa.sa);
                        remove_it = TRUE;
                    }
                }
                else
                {
                    log_err("notify: unable to convert '%{hostaddr}' to an address", ha);
                    remove_it = TRUE;
                }
                
                host_address *ha_next = ha->next;
                
                if(remove_it)
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
                
                if(rp > 255)
                {
                    rp = 255;
                }
                
                message->payload.notify.repeat_period = (u8)rp;
                
                message->payload.notify.epoch = now + message->payload.notify.repeat_period * 60;
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
            treeset_avl_delete(&notify_zones, msg->origin);
            notify_message_free(msg);
        }

        sleep(1);
    }
}

/**
 * Sends a notify to all the slave for a given domain name
 * 
 * @param origin
 */

void
notify_slaves(u8 *origin)
{
    if(notify_process_thread_id == 0)
    {
        return;
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

    zdb *db = (zdb*)g_config->database;

    zdb_zone *zone = zdb_zone_find_from_dnsname(db, origin, CLASS_IN);
    
    if(ZDB_ZONE_INVALID(zone))
    {
        log_debug("notify: zone temporarily unavailable");
        
        return;
    }
    
    zone_data *zone_desc = zone_getbydnsname(origin);
    
    host_address list;
    list.next = NULL;
    list.version = 0xff;
    
    if((zone_desc->notify_flags) & ZONE_NOTIFY_AUTO)
    {
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

            zdb_packed_ttlrdata *a_records = NULL;
            zdb_packed_ttlrdata *aaaa_records = NULL;

            zdb_query_ip_records(db, ns_dname, CLASS_IN, &a_records, &aaaa_records);

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
        }
    }

    // at this point I have the list of every IP I could find along with names I cannot resolve.
    // note that we don't need to care about the changes in the database : it would mean a new
    // notify and this one would be discarded

    host_address *also_notifies = zone_desc->notifies;

    while(also_notifies != NULL)
    {
        host_address_append_host_address(&list, also_notifies);

        also_notifies = also_notifies->next;
    }

    // It's separate from the DB push the lot

    // thread from the pool

    if(list.next != NULL)
    {
        notify_message *message;

        MALLOC_OR_DIE(notify_message*, message, sizeof(notify_message), NOTFYMSG_TAG);

        message->origin = dnsname_dup(origin);
        message->payload.type = NOTIFY_MESSAGE_TYPE_NOTIFY;
        message->payload.notify.hosts_list = list.next;
        message->payload.notify.repeat_countdown = zone_desc->notify.retry_count; /* 10 times */
        message->payload.notify.repeat_period = zone_desc->notify.retry_period; /* 1 minute */
        message->payload.notify.repeat_period_increase = zone_desc->notify.retry_period_increase; /* 1 minute */

        threaded_queue_enqueue(&notify_message_queue, message);
    }
}

/**
 * Starts the notify service thread
 */

void
notify_startup()
{
    if(notify_process_thread_id == 0)
    {
        log_info("notify: service start");
        
        threaded_queue_init(&notify_message_queue, 4096);   /* maximum updates total per 30 seconds ... */

        if(pthread_create(&notify_process_thread_id, NULL, notify_process_thread, NULL) != 0)
        {
            exit(EXIT_CODE_THREADCREATE_ERROR);
        }
    }
}

/**
 * Stops the notify service thread
 */

void
notify_shutdown()
{
    notify_message *message;

    if(notify_process_thread_id != 0)
    {
        log_info("notify: service stop");
        
        MALLOC_OR_DIE(notify_message*, message, sizeof(notify_message), NOTFYMSG_TAG);
        ZEROMEMORY(message, sizeof(notify_message));
        message->payload.type = NOTIFY_MESSAGE_TYPE_STOP;

        threaded_queue_enqueue(&notify_message_queue, message);
        
        pthread_join(notify_process_thread_id, NULL);
        
        for(;;)
        {
            notify_message *message = (notify_message*)threaded_queue_try_dequeue(&notify_message_queue);

            if(message == NULL)
            {
                break;
            }
            
            notify_message_free(message);
        }
        
        threaded_queue_finalize(&notify_message_queue);
        
        notify_process_thread_id = 0;
    }
}


/** @} */

/*----------------------------------------------------------------------------*/


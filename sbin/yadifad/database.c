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
/** @defgroup server
 *  @ingroup yadifad
 *  @brief database functions
 *
 *  Implementation of routines for the database
 *   - add zone file(s)
 *   - clear zone file(s)
 *   - print zone files(s)
 *   - load db
 *   - unload db
 *   - lookup database result of a message
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include "config.h"

#include <dnscore/packet_reader.h>

#include <dnscore/dnsname.h>
#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/alarm.h>
#include <dnscore/chroot.h>
#include <dnscore/timeformat.h>

#include <dnscore/threaded_ringbuffer.h>

#include <dnsdb/dnssec.h>

#include <dnsdb/zdb.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_icmtl.h>
#if HAS_DYNUPDATE_SUPPORT
#include <dnsdb/dynupdate.h>
#endif
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb_zone_load.h>
#include <dnsdb/journal.h>

#include <dnszone/dnszone.h>
#include <dnszone/zone_file_reader.h>
#include <dnszone/zone_axfr_reader.h>

#include "server.h"
#include "database.h"
#include "database-service.h"

#include "server_error.h"
#include "config_error.h"

#include "notify.h"

#include "zone.h"
#include "zone_desc.h"

#if HAS_RRL_SUPPORT
#include "rrl.h"
#endif

#define DBSCHEDP_TAG 0x5044454843534244
#define DBUPSIGP_TAG 0x5047495350554244
#define DBREFALP_TAG 0x504c414645524244

#define MODULE_MSG_HANDLE g_server_logger

typedef struct database_zone_refresh_alarm_args database_zone_refresh_alarm_args;

struct database_zone_refresh_alarm_args
{
    const u8 *origin;
};

/* Zone file variables */
extern zone_data_set database_zone_desc;

/*------------------------------------------------------------------------------
 * FUNCTIONS */

static dnslib_fingerprint server_getfingerprint()
{
    dnslib_fingerprint ret = (dnslib_fingerprint)(0
#if HAS_TSIG_SUPPORT != 0
    | DNSLIB_TSIG
#endif
#if HAS_ACL_SUPPORT != 0
    | DNSLIB_ACL
#endif
#if HAS_NSEC_SUPPORT != 0
    | DNSLIB_NSEC
#endif
#if HAS_NSEC3_SUPPORT != 0
    | DNSLIB_NSEC3
#endif
    );

    return ret;
}

/**
 * Initialises the database.
 * Ensures the libraries features are matched.
 * 
 */

void
database_init()
{
    dnslib_fingerprint dbfp = dnsdb_getfingerprint();
    dnslib_fingerprint svrfp = server_getfingerprint();

    if(dbfp != svrfp)
    {
        fprintf(stderr,"mismatched fingerprint\n");
        log_err("mismatched fingerprint");
        exit(EXIT_FAILURE);
    }
    
    zdb_init();
    dnszone_init();
    dnscore_reset_timer();
}

void
database_finalize()
{
    zdb_finalize();
}

/** @brief Remove the zones from the database, but do not remove the database
 *  file
 *
 *  @param[in] database
 *  @param[in] zone
 *
 *  @retval OK
 */
ya_result
database_clear_zones(zdb *database, zone_data_set *dset)
{
    dnsname_vector fqdn_vector;
    
    zone_set_lock(dset);

    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&dset->set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s*)zone_node->data;

        dnsname_to_dnsname_vector(zone_desc->origin, &fqdn_vector);
        
        zdb_zone *myzone = zdb_zone_find(database, &fqdn_vector, zone_desc->qclass);

        if(myzone != NULL)
        {
            zdb_zone_destroy(myzone);
        }
    }
    
    zone_set_unlock(dset);

    return OK;
}

/** @brief Creates the (IN) database
 * 
 *  Starts to load the content.
 *
 *  @param[out] database pointer to a pointer to the database 
 * 
 *  @return an error code
 */

/**
 * @NOTE THIS IS SUPPOSED TO BE RUN BEFORE THE SERVER STARTS !
 */

ya_result
database_startup(zdb **database)
{
    ya_result return_code;
    zdb* db;

    /*    ------------------------------------------------------------    */

    if(g_config->data_path == NULL)
    {
        return CONFIG_ZONE_ERR;
    }

    *database = NULL;
    
    database_init(); /* Inits the db, starts the threads of the pool, resets the timer */

    MALLOC_OR_DIE(zdb*, db, sizeof (zdb), GENERIC_TAG);
    zdb_create(db);
    
    // add all the registered zones as invalid
    
    *database = db;
    
    database_service_create_invalid_zones();
       
    if(ISOK(return_code = database_service_start()))
    {
        database_load_all_zones();
    }
    
    return return_code;
}

/****************************************************************************/

/** \brief Get dns answer from database
 *
 *  Get dns answer from database
 *  CANNOT FAIL
 * 
 *  @param mesg
 *
 *  @return status of message is written in mesg->status
 */

#if HAS_RRL_SUPPORT
ya_result
#else
void
#endif
database_query(zdb *db, message_data *mesg)
{
    finger_print query_fp;
    zdb_query_ex_answer ans_auth_add;

    /*    ------------------------------------------------------------    */

    mesg->send_length = mesg->received;
    
    zdb_query_ex_answer_create(&ans_auth_add);

    query_fp = zdb_query_ex(db, mesg, &ans_auth_add, mesg->pool_buffer);

    /**
     * @todo : do it when it's true only
     */

    mesg->status = query_fp;
    
    // RRL should be computed here
    
#if HAS_RRL_SUPPORT
    ya_result rrl = rrl_process(mesg, &ans_auth_add);

    switch(rrl)
    {
        case RRL_PROCEED:
        {
            mesg->send_length = zdb_query_message_update(mesg, &ans_auth_add);
            mesg->referral = ans_auth_add.delegation;
            break;
        }
        case RRL_SLIP:
        {
            log_debug("rrl: slip");
            mesg->referral = ans_auth_add.delegation;
            break;
        }
        case RRL_DROP:
        {
            // DON'T PROCEED AT ALL
            log_debug("rrl: drop");
            break;
        }
    }
#else
    
    mesg->send_length = zdb_query_message_update(mesg, &ans_auth_add);
    mesg->referral = ans_auth_add.delegation;

#endif
    
    zdb_query_ex_answer_destroy(&ans_auth_add);

#if HAS_TSIG_SUPPORT
    if(TSIG_ENABLED(mesg))  /* NOTE: the TSIG information is in mesg */
    {
        tsig_sign_answer(mesg);
    }
#endif
    
#if HAS_RRL_SUPPORT
    return rrl;
#endif
}

/****************************************************************************/


#if HAS_DYNUPDATE_SUPPORT

/** @todo  icmtl, checks, fp, soa, ...
 *   - dynupdate_icmtlhook_enable must be called if there are some slave name severs
 *   - check the functions, which is not tested yet
 *   - fingerprint instead of ya_result for return_code
 *   - soa has to be called
 *   - check BUFFER_OVERRUN
 */

finger_print
database_update(zdb *database, message_data *mesg)
{
    ya_result return_code;

    u16 count;
    /*    u16    qdcount; */
    packet_unpack_reader_data reader;
    dnsname_vector name;
    zdb_zone *zone;
    
    u8 wire[MAX_DOMAIN_LENGTH + 10 + 65535];

    return_code = FP_NOZONE_FOUND;
    
    mesg->send_length = mesg->received;

    zone_desc_s *zone_desc = zone_acquirebydnsname(mesg->qname);

    if(zone_desc != NULL)
    {
        zone_lock(zone_desc, ZONE_LOCK_DYNUPDATE);
        switch(zone_desc->type)
        {
            case ZT_MASTER:
            {
                /*    ------------------------------------------------------------    */
                
                MESSAGE_HIFLAGS(mesg->buffer) |= QR_BITS;

                /*
                 * Unpack the query
                 */
                packet_reader_init(&reader, mesg->buffer, mesg->received);
                reader.offset = DNS_HEADER_LENGTH;

                /*    qdcount = MESSAGE_QD(mesg->buffer); */

                dnsname_to_dnsname_vector(mesg->qname, &name);

                zone = zdb_zone_find((zdb *)database, &name, mesg->qclass);

                if(zone != NULL && !ZDB_ZONE_INVALID(zone))
                {
                    /*
                     * If the zone is marked as:
                     * _ frozen
                     * _ updating
                     * _ signing
                     * _ dumping
                     * => don't do it
                     */
                    if((zone->apex->flags & ZDB_RR_APEX_LABEL_FROZEN) == 0)
                    {
#if HAS_ACL_SUPPORT
                        if(ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_update)))
                        {
                            /* notauth */

                            log_info("database: update: not authorised");
                            
                            mesg->status = FP_ACCESS_REJECTED;
                            
                            zone_unlock(zone_desc, ZONE_LOCK_DYNUPDATE);
                            
                            zone_release(zone_desc);
                            
                            return (finger_print)ACL_UPDATE_REJECTED;
                        }
#endif
                        
                        /*
                         * If the zone is DNSSEC and we don't have all the keys or don't know how to use them : SERVFAIL
                         */
                        
                        return_code = SUCCESS;
                        
                        if(zdb_zone_is_dnssec(zone))
                        {
                            /*
                             * Fetch all private keys
                             */
                            
                            log_debug("database: update: checking DNSKEY availability");
                            
                            const zdb_packed_ttlrdata *dnskey = zdb_zone_get_dnskey_rrset(zone);
                                                        
                            if(dnskey != NULL)
                            {
                                char origin[MAX_DOMAIN_LENGTH];
                                
                                dnsname_to_cstr(origin, zone->origin);
                            
                                do
                                {
                                    u16 flags = DNSKEY_FLAGS(*dnskey);
                                    //u8  protocol = DNSKEY_PROTOCOL(*dnskey);
                                    u8  algorithm = DNSKEY_ALGORITHM(*dnskey);
                                    u16 tag = DNSKEY_TAG(*dnskey);                  // note: expensive
                                    dnssec_key *key = NULL;

                                    if(FAIL(return_code = dnssec_key_load_private(algorithm, tag, flags, origin, &key)))
                                    {
                                        log_err("database: update: unable to load private key 'K%{dnsname}+%03d+%05d': %r", zone->origin, algorithm, tag, return_code);
                                        break;
                                    }

                                    dnskey = dnskey->next;
                                }
                                while(dnskey != NULL);
                            }
                            else
                            {
                                log_err("database: update: there are no private keys in the zone %{dnsname}", zone->origin);
                                
                                return_code = DNSSEC_ERROR_RRSIG_NOZONEKEYS;
                            }
                        }

                        if(ISOK(return_code))   // 
                        {
                            /* The reader is positioned after the header : read the QR section */
                            
                            if(ISOK(return_code = packet_reader_read_zone_record(&reader, wire, sizeof(wire))))
                            {
                                /*
                                * The zone is known with the previous record.
                                * Since I'm just testing the update per se, I'll ignore this.
                                */

                                count = ntohs(MESSAGE_PR(mesg->buffer));
                                
                                /* The reader is positioned after the QR section, read AN section */

                                u64 start = timeus();
                                u64 now;
                                u64 locktimeout = 2000000; // 2 seconds
                                bool locked;
                                
                                do
                                {
                                    if((locked = zdb_zone_trylock(zone, ZDB_ZONE_MUTEX_DYNUPDATE)))
                                    {
                                        break;
                                    }
                                    usleep(1000);
                                    now = timeus();
                                }
                                while(now - start < locktimeout);
                                
                                if(locked)
                                {
                                    log_debug("database: update: processing %d prerequisites", count);

                                    if(ISOK(return_code = dynupdate_check_prerequisites(zone, &reader, count)))
                                    {
                                        count = ntohs(MESSAGE_UP(mesg->buffer));

                                        u32 reader_up_offset = reader.offset;
                                        /*
                                         * Dry run the update for the section
                                         * (so the DB will not be broken if the query is bogus)
                                         */

                                        log_debug("database: update: dryrun of %d updates", count);

                                        if(ISOK(return_code = dynupdate_update(zone, &reader, count, DYNUPDATE_UPDATE_DRYRUN)))
                                        {
                                            /*
                                             * Really run the update for the section
                                             */

                                            reader.offset = reader_up_offset;

                                            /**
                                             * @todo At this point it should not fail anymore.
                                             */

                                            log_debug("database: update: opening journal page");

                                            zdb_icmtl icmtl;

                                            if(ISOK(return_code = zdb_icmtl_begin(zone, &icmtl, g_config->xfr_path)))
                                            {
                                                log_debug("database: update: run of %d updates", count);

                                                ya_result len = dynupdate_update(zone, &reader, count, DYNUPDATE_UPDATE_RUN);

                                                if(ISOK(len))
                                                {
                                                    //mesg->send_length = mesg->received;

                                                    /** @TODO I have to be able to cancel the icmtl if it failed */
                                                    
                                                    log_info("database: update: update of zone '%{dnsname}' succeeded", zone->origin);
                                                }
                                                else
                                                {
                                                    log_err("database: update: update of zone '%{dnsname}' failed even if the dryrun succeeded: %r", zone->origin, len);
                                                }

                                                
                                                len = zdb_icmtl_end(&icmtl, g_config->xfr_path);

                                                if(len != 0)
                                                {
                                                    zone_desc->status_flags |= ZONE_STATUS_MODIFIED;
                                                }
                                                
                                                log_debug("database: update: closed journal page");

                                                /**
                                                 * 
                                                 * @todo postponed after 1.0.0
                                                 * 
                                                 * The journal file may exceed limits ...
                                                 * 
                                                 * In that case the server will want to:
                                                 * 
                                                 * _ disable dynamic updates
                                                 * _ update the zone file on disk to the current version
                                                 * _ cut the journal up to the last few serials
                                                 * _ enable dynamic updates
                                                 * 
                                                 * How to define limits:
                                                 * 
                                                 * _ size on disk (easy)
                                                 * _ number of records (hard to keep track in the current journal format so : no)
                                                 * _ relative size on disk (proportional to the size of zone axfr/text) (easy too)
                                                 * _ serial range of the incremental file is too big; too big being at most 2^30 but
                                                 *   practically 2^17 increments of serial is very expensive already.
                                                 * 
                                                 * These limits must be made available to the server so it can take measures to
                                                 * fix them.
                                                 * 
                                                 */

                                                mesg->status = FP_MESG_OK; /* @TODO handle error codes too */

                                                notify_slaves(zone->origin);
                                            }
                                            else
                                            {
                                                mesg->status = (finger_print)RCODE_SERVFAIL;
                                            }
                                        }
                                        else
                                        {
                                            /*
                                             * ZONE CANNOT BE UPDATED (internal error or rejected)
                                             */

                                            mesg->status = (finger_print)RCODE_SERVFAIL;
                                        }

                                    }
                                    else
                                    {
                                        /*
                                         * ZONE CANNOT BE UPDATED (prerequisites not met)
                                         */
                                        
                                        log_warn("database: update: prerequisites not met updating %{dnsname}", mesg->qname);

                                        mesg->status = (finger_print)RCODE_SERVFAIL;
                                    }
                                    
                                    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_DYNUPDATE);
                                    
                                } // lock timeout
                                else
                                {
                                    log_warn("database: update: timeout trying to lock the zone %{dnsname}", mesg->qname);
                                    
                                    mesg->status = (finger_print)RCODE_SERVFAIL;
                                }
                            }
                            else
                            {
                                mesg->status = (finger_print)RCODE_FORMERR;
                            }
                        }
                        else
                        {
                            /*
                             * ZONE CANNOT BE UPDATED (missing private keys)                             
                             */
                            
                            mesg->status = FP_CANNOT_DYNUPDATE;
                        }
                    }
                    else
                    {
                        /*
                         * ZONE CANNOT BE UPDATED (frozen)
                         */

                        mesg->status = FP_CANNOT_DYNUPDATE;
                    }
                }
                else
                {
                    /**
                     * 2136:
                     *
                     * if any RR's NAME is not
                     * within the zone specified in the Zone Section, signal NOTZONE to the
                     * requestor.
                     *
                     */

                    if(zone == NULL)
                    {
                        mesg->status = FP_UPDATE_UNKNOWN_ZONE;
                    }
                    else
                    {
                        mesg->status = FP_INVALID_ZONE;
                    }
                }
                
                break;
            }
            /**
             * @todo : dynamic update forwarding ...
             */
            case ZT_SLAVE:
            {
                /*
                 * UPDATE FORWARDING
                 * 
                 * TCP -> TCP
                 * UDP -> TCP or UDP
                 * 
                 * So this implementation will always to TCP
                 * 
                 * Open a connection to the master.
                 * Create a duplicate of the message changing only the ID
                 * I CANNOT EDIT THE SAME MESSAGE BECAUSE OF THE POSSIBLE TSIG
                 * TSIG if needed.
                 * Send the message.
                 * Wait for the answer and retry if needed.
                 * Forward back the answer to the caller.
                 */
                
#if HAS_ACL_SUPPORT
                if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_update_forwarding)))
                {
                    random_ctx rndctx = thread_pool_get_random_ctx();
                    u16 id = (u16)random_next(rndctx);

                    message_data forward;
                    message_make_query(&forward, id, (const u8*)"", 0, 0);  /* just initialise a basic query */

                    memcpy(forward.buffer, mesg->buffer, mesg->received);
                    forward.send_length = mesg->received;
                    
                    // if no TSIG or succeeded in TSIGing the message ...
                    
#if HAS_TSIG_SUPPORT
                    if((zone_desc->masters->tsig == NULL) || ISOK(return_code = message_sign_query(&forward, zone_desc->masters->tsig)))
                    {
#endif
                        // send a TCP query to the master
                        
                        if(ISOK(return_code = message_query_tcp(&forward, zone_desc->masters)))
                        {
                            memcpy(mesg->buffer, forward.buffer, forward.received);
                            mesg->send_length = forward.received;
                            mesg->status = forward.status;
                        }
#if HAS_TSIG_SUPPORT
                    }
#endif
                }
                else
#endif
                {
                    mesg->status = FP_CANNOT_DYNUPDATE;
                    return_code = FP_CANNOT_DYNUPDATE;
                    
                    message_make_error(mesg, return_code);
                }
                
                break;
            }
            default:
            {
                mesg->status = FP_CANNOT_DYNUPDATE;
                return_code = FP_CANNOT_DYNUPDATE;
                
                message_make_error(mesg, return_code);
                
                break;
            }
        }
        
        zone_unlock(zone_desc, ZONE_LOCK_DYNUPDATE);
        zone_release(zone_desc);
    }
    else
    {
        /* zone is not even known by the configuration  */

        mesg->status = FP_UPDATE_UNKNOWN_ZONE;
    }

    MESSAGE_LOFLAGS(mesg->buffer) = (MESSAGE_LOFLAGS(mesg->buffer)&~RCODE_BITS) | mesg->status;

#if HAS_TSIG_SUPPORT
    if(TSIG_ENABLED(mesg))
    {
        log_debug("database: update: signing reply");
        
        tsig_sign_answer(mesg);
    }
#endif

    return (finger_print)return_code;
}

#endif

/** @brief Close the database
 *
 *  @param[in] database
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result
database_shutdown(zdb *database)
{
    database_service_stop();
    
#ifdef DEBUG
    if(database != NULL)
    {
        zdb_destroy(database);
        free(database);
    }
#endif
    
    database_finalize();
    g_config->database = NULL;
    
        
    journal_finalise();

    return OK;
}

static ya_result
database_zone_refresh_alarm(void *args)
{
    database_zone_refresh_alarm_args *sszra = (database_zone_refresh_alarm_args*)args;
    const u8 *origin = sszra->origin;
    zdb *db = g_config->database;
    zdb_zone *zone;
    ya_result return_value;
    u32 now = 0;
    u32 next_alarm_epoch = 0;
    soa_rdata soa;

    log_info("database: refresh: zone %{dnsname}", origin);

    zone_desc_s *zone_desc = zone_acquirebydnsname(origin);

    if(zone_desc == NULL)
    {
        log_err("database: refresh: zone %{dnsname}: not found", origin);
        free((char*)sszra->origin);
        free(sszra);
        
        return ERROR;
    }

    zone = zdb_zone_find_from_name(db, zone_desc->domain, CLASS_IN);
    
    if(zone != NULL)
    {
        /**
         * check if the zone is locked. postpone if it is
         */

        if(zdb_zone_trylock(zone, ZDB_ZONE_MUTEX_REFRESH))
        {
            if(FAIL(return_value = zdb_zone_getsoa(zone, &soa)))
            {
                /*
                 * No SOA ? It's critical
                 */

                free(sszra);

                log_quit("database: refresh: zone %{dnsname}: get soa: %r", origin, return_value);
                
                return ERROR;
            }
            
            now = time(NULL);
            
            // defines 3 epoch printers (to be used with %w)
            u32 rf = zone_desc->refresh.refreshed_time;
            u32 rt = zone_desc->refresh.retried_time;
            u32 un = zone_desc->refresh.zone_update_next_time;
            EPOCH_DEF(rf);
            EPOCH_DEF(rt);
            EPOCH_DEF(un);
            log_debug("database: refresh: zone %{dnsname}: refreshed=%w retried=%w next=%w refresh=%i retry=%i expire=%i",
                    origin,
                    EPOCH_REF(rf),
                    EPOCH_REF(rt),
                    EPOCH_REF(un),
                    soa.refresh,
                    soa.retry,
                    soa.expire
                    );
            
            // if the last time refreshed is at or after the last time we retried

            if(zone_desc->refresh.refreshed_time >= zone_desc->refresh.retried_time)
            {
                // then we are not retrying ...
                
                // if now is after the last refreshed time + the refresh time
                
                if(now >= zone_desc->refresh.refreshed_time + soa.refresh)
                {
                     // then do a refresh

                    log_info("database: refresh: zone %{dnsname}: refresh", origin);

                    zone_desc->refresh.retried_time = zone_desc->refresh.refreshed_time + 1;

                    // next time we will check for the refresh status will be now + retry ...
                    next_alarm_epoch = now + soa.retry;
                    
                    database_zone_ixfr_query(zone_desc->origin);
                }
                else
                {
                    // next time we will check for the refresh status will be now + refresh ...
                    
                    log_info("database: refresh: zone %{dnsname}: refresh in %d seconds", origin, zone_desc->refresh.refreshed_time + soa.refresh - now);
                    
                    next_alarm_epoch = zone_desc->refresh.refreshed_time + soa.refresh;
                }
            }
            else
            {
                // else we are retrying ...
                
                if(now < zone_desc->refresh.refreshed_time + soa.expire)                {
                    // then we have not expired yet ...
                    
                    // next time we will check for the refresh status will be now + retry ...
                    next_alarm_epoch = now + soa.retry;
                    
                    if(now >= zone_desc->refresh.retried_time + soa.retry)
                    {
                        // then do a retry ...

                        log_info("database: refresh: zone %{dnsname}: retry", origin);

                        database_zone_ixfr_query(zone_desc->origin);
                    }
                    else
                    {
                        log_debug("database: refresh: zone %{dnsname}: not retry time yet", origin);
                    }
                }
                else
                {
                    // else the zone is not authoritative anymore

                    log_warn("database: refresh: zone %{dnsname}: expired", origin);
                    
                    zone->apex->flags |= ZDB_RR_LABEL_INVALID_ZONE;
                }
            }

            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_REFRESH);
        }
        else
        {
            log_info("database: refresh: zone %{dnsname}: has already been locked, will retry layer", origin);
            next_alarm_epoch = time(NULL) + 2;
        }
    }
    else
    {
        log_err("database: refresh: zone %{dnsname}: not mounted", origin);
    }

    if(next_alarm_epoch != 0)
    {
        /*
         * The alarm rang but nothing has been done
         */
        
        EPOCH_DEF(next_alarm_epoch);        
        log_warn("database: refresh: zone %{dnsname}: re-arming the alarm for %w", origin, EPOCH_REF(next_alarm_epoch));

        database_zone_refresh_maintenance(db, origin, next_alarm_epoch);
    }
    else
    {
        log_warn("database: refresh: zone %{dnsname}: alarm will not be re-armed", origin);
    }

    free((char*)sszra->origin);
    
#ifdef DEBUG
    memset(sszra, 0xff, sizeof(database_zone_refresh_alarm_args));
#endif
    
    free(sszra);
    
    zone_release(zone_desc);

    return SUCCESS;
}

ya_result
database_zone_refresh_maintenance_wih_zone(zdb_zone* zone, u32 next_alarm_epoch)
{
    if((zone != NULL) && ZDB_ZONE_VALID(zone))
    {
        /*
         * Get the SOA from the zone
         */

        /*
         * Check the last refresh time
         * If we need to refresh, then do it
         * If we failed, check when the next time to do it is
         * If we failed too much, check if we still are authoritative
         */

        zdb_zone_lock(zone, ZDB_ZONE_MUTEX_REFRESH); /* here ! */
        u32 now = time(NULL);

        ya_result return_value;
        soa_rdata soa;

        if(next_alarm_epoch == 0)
        {
            if(FAIL(return_value = zdb_zone_getsoa(zone, &soa)))
            {
                /*
                 * No SOA ? It's critical
                 */

                zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_REFRESH); /* here ! */

                log_err("database_zone_refresh_maintenance: get soa: %r", return_value);
                exit(EXIT_FAILURE);
            }
            
            next_alarm_epoch = now + soa.refresh;
        }

        database_zone_refresh_alarm_args *sszra;

        MALLOC_OR_DIE(database_zone_refresh_alarm_args*, sszra, sizeof(database_zone_refresh_alarm_args), DBREFALP_TAG);

        sszra->origin = dnsname_dup(zone->origin);

        alarm_event_node *event = alarm_event_alloc();
        event->epoch = next_alarm_epoch;
        event->function = database_zone_refresh_alarm;
        event->args = sszra;
        event->key = ALARM_KEY_ZONE_REFRESH;
        event->flags = ALARM_DUP_REMOVE_LATEST;
        event->text = "database_zone_refresh_alarm";

        alarm_set(zone->alarm_handle, event);

        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_REFRESH);
    }
    else
    {
        /*
         * The zone has not been loaded (yet)
         */
        
        if(zone != NULL)
        {
            log_debug("database_zone_refresh_maintenance: called on an invalid zone: %{dnsname}", zone->origin);
        }
        else
        {
            log_debug("database_zone_refresh_maintenance: called on a NULL zone");
        }
    }
    
    return SUCCESS;
}

ya_result
database_zone_refresh_maintenance(zdb *database, const u8 *origin, u32 next_alarm_epoch)
{
    log_debug("database: refresh: database_zone_refresh_maintenance for zone %{dnsname} at %u", origin, next_alarm_epoch);

    zdb_zone *zone = zdb_zone_find_from_dnsname(database, origin, CLASS_IN);

    ya_result ret = database_zone_refresh_maintenance_wih_zone(zone, next_alarm_epoch);

    return ret;
}



ya_result
database_save_zone_to_disk(zone_desc_s *zone_desc)
{
    database_zone_save(zone_desc->origin);
    return SUCCESS;
}

ya_result
database_save_all_zones_to_disk()
{
    /*
     * for all zones
     * put them in an array
     * while the array is not empty
     *     for every zone in the array
     *         try to freeze zone (lock)
     *         if it worked, wait that it is frozen, then unfreeze it and remove it from the array
     * 
     */
    
    ya_result batch_return_value = 0;
    
    if(g_config->database == NULL)
    {
        return ERROR;
    }
    
    zone_set_lock(&database_zone_desc);
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&database_zone_desc.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        
        zone_desc_s *zone_desc = (zone_desc_s*)zone_node->data;
        
        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }
                        
        database_save_zone_to_disk(zone_desc);
    }
    
    zone_set_unlock(&database_zone_desc);
    
    return batch_return_value;
}

bool
database_are_all_zones_saved_to_disk()
{
    bool can_unload;  
    
    can_unload = TRUE;
    
    zone_set_lock(&database_zone_desc);
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&database_zone_desc.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);

        zone_desc_s *zone_desc = (zone_desc_s*)zone_node->data;

        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }
        
        if(zone_issavingfile(zone_desc))
        {
            can_unload = FALSE;
            break;
        }
    }
    
    zone_set_unlock(&database_zone_desc);
    
    return can_unload;
}

void
database_wait_all_zones_saved_to_disk()
{
    while(!database_are_all_zones_saved_to_disk())
    {        
        log_info("database: still busy writing zone files: shutdown postponed");
        sleep(1);
    }
}

void
database_disable_all_zone_save_to_disk()
{
    zone_set_lock(&database_zone_desc);
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&database_zone_desc.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        
        zone_desc_s *zone_desc = (zone_desc_s*)zone_node->data;
        
        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }
        
        zone_setsavingfile(zone_desc, FALSE);
    }
    
    zone_set_unlock(&database_zone_desc);
}

/** @} */

/*----------------------------------------------------------------------------*/

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
#include <dnscore/packet_reader.h>

#include <dnscore/dnsname.h>
#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/alarm.h>

#include <dnscore/threaded_ringbuffer.h>

#include <dnsdb/zdb.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/dnssec.h>
#include <dnsdb/dynupdate.h>
#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb_zone_load.h>

#include <dnszone/dnszone.h>
#include <dnszone/zone_file_reader.h>
#include <dnszone/zone_axfr_reader.h>

#include "server.h"
#include "database.h"
#include "scheduler_xfr.h"
#include "scheduler_database_load_zone.h"

#include "server_error.h"
#include "config_error.h"

#include "notify.h"

#include "zone.h"

#define DBSCHEDP_TAG 0x5044454843534244
#define DBUPSIGP_TAG 0x5047495350554244
#define DBREFALP_TAG 0x504c414645524244

#define MODULE_MSG_HANDLE g_server_logger

typedef struct database_zone_refresh_alarm_args database_zone_refresh_alarm_args;

struct database_zone_refresh_alarm_args
{
    u8 *origin;
    database_t *db;
};

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

void
database_init()
{
    dnslib_fingerprint dbfp = dnsdb_getfingerprint();
    dnslib_fingerprint svrfp = server_getfingerprint();
    ya_result return_code;

    if(dbfp != svrfp)
    {
        fprintf(stderr,"mismatched fingerprint\n");
        log_err("mismatched fingerprint");
        exit(EXIT_FAILURE);
    }

    if(FAIL(return_code = thread_pool_init(g_config->thread_count + 4)))
    {
        log_err("thread pool initialisation: %r", return_code);
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
 *  @param[in] database_type
 *  @param[in] zone
 *
 *  @retval OK
 */
ya_result
database_clear_zones(database_t *database, zone_data_set *dset)
{
    dnsname_vector fqdn_vector;
    
    zone_set_lock(dset);

    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&dset->set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_data *zone_desc = (zone_data*)zone_node->data;

        dnsname_to_dnsname_vector(zone_desc->origin, &fqdn_vector);
        
        zdb_zone *myzone = zdb_zone_find((zdb*)database, &fqdn_vector, zone_desc->qclass);

        if(myzone != NULL)
        {
            zdb_zone_destroy(myzone);
        }
    }
    
    zone_set_unlock(dset);

    return OK;
}

/** @brief Open the database for reading and writing
 *
 *  @param[out] database descriptor
 *  @param[in]  data_path path to the zone file
 *  @param[in]  database_type type of database to be used
 7*
 *  @retval OK
 *  @retval NOK
 */

/**
 * @NOTE THIS IS SUPPOSED TO BE RUN BEFORE THE SERVER STARTS !
 */

ya_result
database_load(database_t **database, zone_data_set *dset)
{
    zdb* db;

    /*    ------------------------------------------------------------    */

    if(g_config->data_path == NULL)
    {
        return CONFIG_ZONE_ERR;
    }

    *database = NULL;

    MALLOC_OR_DIE(zdb*, db, sizeof (zdb), GENERIC_TAG);
    zdb_create(db);
    
    *database = (database_t *)db;
    
    database_load_startup();
    
    zone_set_lock(dset);

    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&dset->set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_data *zone_desc = (zone_data*)zone_node->data;

        if(zone_desc->origin == NULL)
        {
            log_crit("zone load: no domain defined for zone section");  /* will ultimately lead to the end of the program */
            
            return ERROR;
        }
        
        log_debug("zone load: invalidating domain '%s'", zone_desc->domain);
        
        zdb_zone_xchg_with_invalid((zdb*)g_config->database, zone_desc->origin, zone_desc->qclass, ZDB_RR_APEX_LABEL_FROZEN);
    }
    
    treeset_avl_iterator_init(&dset->set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_data *zone_desc = (zone_data*)zone_node->data;
        
        log_info("zone load: queueing domain '%s'", zone_desc->domain);

        database_load_zone_load(zone_desc->origin);
    }
    
    zone_set_unlock(dset);
        
    return SUCCESS;
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

void
database_query(database_t *database, message_data *mesg)
{
    finger_print query_fp;
    zdb_query_ex_answer ans_auth_add;

    zdb* db = (zdb*)database;

    /*    ------------------------------------------------------------    */

    mesg->send_length = mesg->received;
    
    zdb_query_ex_answer_create(&ans_auth_add);

    query_fp = zdb_query_ex(db, mesg, &ans_auth_add, mesg->pool_buffer);

    /**
     * @todo : do it when it's true only
     */

    mesg->status = query_fp;
    mesg->send_length = zdb_query_message_update(mesg, &ans_auth_add);
    mesg->referral = ans_auth_add.delegation;

    zdb_query_ex_answer_destroy(&ans_auth_add);

#if HAS_TSIG_SUPPORT
    if(TSIG_ENABLED(mesg))  /* NOTE: the TSIG information is in mesg */
    {
        tsig_sign_answer(mesg);
    }
#endif
}

/****************************************************************************/

/**
 * A task is a function called in the main thread loop
 * A delegate is a task we are waiting for
 */

struct database_delegate_query_task_args
{
    database_t *database;
    message_data *mesg;
    threaded_ringbuffer* sync;
};

static ya_result
database_delegate_query_task(void* parms_)
{
    struct database_delegate_query_task_args *parms = (struct database_delegate_query_task_args*)parms_;
    database_query(parms->database, parms->mesg);
    threaded_ringbuffer_enqueue(parms->sync, NULL);
    return SCHEDULER_TASK_FINISHED;
}

void
database_delegate_query(database_t *database, message_data *mesg)
{
    struct database_delegate_query_task_args parms;
    threaded_ringbuffer sync;
    parms.database = database;
    parms.mesg = mesg;
    parms.sync = &sync;
    
    threaded_ringbuffer_init(&sync, 1);
    scheduler_schedule_task(database_delegate_query_task, &parms);
    threaded_ringbuffer_dequeue(&sync);
    log_debug("database: query delegated");
    threaded_ringbuffer_finalize(&sync);
}

/****************************************************************************/

static inline ya_result
database_dynupdate_readsection(packet_unpack_reader_data *reader, u16 count)
{
    ya_result return_code = SUCCESS;
    u16 i;
    s32 total = 0;
    u8 wire[MAX_DOMAIN_LENGTH + 10 + 65536];

    for(i = 0; i < count; i++)
    {
        if(FAIL(return_code = packet_reader_read_record(reader, wire, sizeof(wire))))
        {
            if(return_code == UNSUPPORTED_TYPE)
            {
                return_code = SUCCESS;
                
                continue;
            }

            return return_code;
        }
        
        total += return_code;
    }

    return total;
}

/** @todo  icmtl, checks, fp, soa, ...
 *   - dynupdate_icmtlhook_enable must be called if there are some slave name severs
 *   - check the functions, which is not tested yet
 *   - fingerprint instead of ya_result for return_code
 *   - soa has to be called
 *   - check BUFFER_OVERRUN
 */
finger_print
database_update(database_t *database, message_data *mesg)
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

    zone_data *zone_config = zone_getbydnsname(mesg->qname);

    if(zone_config != NULL)
    {       
        switch(zone_config->type)
        {
            case ZT_MASTER:
            {
                /*    ------------------------------------------------------------    */
                
                MESSAGE_HIFLAGS(mesg->buffer) |= QR_BITS;

                /*
                 * Unpack the query
                 */
                packet_reader_init(mesg->buffer, mesg->received, &reader);
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
#if HAS_ACL_SUPPORT == 1
                        if(ACL_REJECTED(acl_check_access_filter(mesg, &zone_config->ac.allow_update)))
                        {
                            /* notauth */

                            log_info("database: update: not authorised");
                            
                            mesg->status = FP_ACCESS_REJECTED;
                            
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

                                zdb_zone_lock(zone, ZDB_ZONE_MUTEX_DYNUPDATE);
                                
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
                                                mesg->send_length = mesg->received;

                                                /* @TODO I have to be able to cancel the icmtl if it failed */
                                            }
                                            else
                                            {
                                                log_err("database: update: update of zone '%{dnsname}' failed even if the dryrun succeeded: %r", zone->origin, len);
                                            }

                                            zdb_icmtl_end(&icmtl, g_config->xfr_path);
                                            
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
                                            mesg->send_length = mesg->received;
                                        }
                                    }
                                    else
                                    {
                                        /*
                                         * ZONE CANNOT BE UPDATED (internal error or rejected)
                                         */

                                        mesg->status = (finger_print)RCODE_SERVFAIL;
                                        mesg->send_length = mesg->received;
                                    }

                                }
                                else
                                {
                                    /*
                                     * ZONE CANNOT BE UPDATED (prerequisites not met)
                                     */

                                    mesg->status = (finger_print)RCODE_SERVFAIL;
                                    mesg->send_length = mesg->received;
                                }

                                zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_DYNUPDATE);
                            }
                            else
                            {
                                mesg->status = (finger_print)RCODE_FORMERR;
                                mesg->send_length = mesg->received;
                            }
                        }
                        else
                        {
                            /*
                             * ZONE CANNOT BE UPDATED (missing private keys)                             
                             */
                            
                            mesg->status = FP_CANNOT_DYNUPDATE;
                            mesg->send_length = mesg->received;
                        }
                    }
                    else
                    {
                        /*
                         * ZONE CANNOT BE UPDATED (frozen)
                         */

                        mesg->status = FP_CANNOT_DYNUPDATE;

                        mesg->send_length = mesg->received;
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
                
                if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_config->ac.allow_update_forwarding)))
                {
                    random_ctx rndctx = thread_pool_get_random_ctx();
                    u16 id = (u16)random_next(rndctx);

                    message_data forward;
                    message_make_query(&forward, id, (const u8*)"", 0, 0);  /* just initialise a basic query */

                    memcpy(forward.buffer, mesg->buffer, mesg->received);
                    forward.send_length = mesg->received;
                    
                    if(ISOK(return_code = message_sign_query(&forward, zone_config->masters->tsig)))
                    {
                        if(ISOK(return_code = message_query_tcp(&forward, zone_config->masters)))
                        {
                            memcpy(mesg->buffer, forward.buffer, forward.received);
                            mesg->send_length = forward.received;
                            mesg->status = forward.status;
                        }
                    }
                }
                else
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

struct database_delegate_update_args
{
    database_t *database;
    message_data *mesg;
    threaded_ringbuffer *sync;
    finger_print return_value;
};

typedef struct database_schedule_update_param database_schedule_update_param;

static ya_result
database_delegate_update_task(void* parms_)
{
    struct database_delegate_update_args *parms = (struct database_delegate_update_args*)parms_;
    parms->return_value = database_update(parms->database, parms->mesg);
    threaded_ringbuffer_enqueue(parms->sync, NULL);
   
    return SCHEDULER_TASK_FINISHED; /* Mark the end of the writer job */
}

finger_print
database_delegate_update(database_t *database, message_data *mesg)
{
    /**
     * @todo check that the server can be updated right now, else send servfail
     * 
     * The task "database_schedule_update_task" will be started on the main thread
     * with exclusive access.
     * The queue is used to know when the result is available.
     */
    
    struct database_delegate_update_args parms;
    threaded_ringbuffer sync;
    parms.database = database;
    parms.mesg = mesg;
    parms.sync = &sync;
    
    threaded_ringbuffer_init(&sync, 1);
    scheduler_schedule_task(database_delegate_update_task, &parms);
    threaded_ringbuffer_dequeue(&sync);
    log_debug("database: update delegated");
    threaded_ringbuffer_finalize(&sync);
    
    return parms.return_value;
}

/** @brief Close the database
 *
 *  @param[in] database sqlite3 file descriptor
 *  @param[in] database_type type of database to be used
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result
database_unload(database_t *database)
{

#if 0 // #ifndef NDEBUG
    zdb_destroy((zdb*)database);
    free(database);
#endif
    
    return OK;
}

/**
 * It MUST be the name of the zone and not the zone itself.
 */

struct database_update_signatures_parm
{
    zdb *db;
    char *domain;
    u16 zclass;
};

typedef struct database_update_signatures_parm database_update_signatures_parm;

/**
 * called by the alarm
 * 
 * Gets the zone and update its signatures
 */

static ya_result
database_update_signatures_alarm(void *parmp)
{
    ya_result return_code;
    
    database_update_signatures_parm *parm = (database_update_signatures_parm*)parmp;

    /*
     * I look at it by name because ANYTHING could happen to the zone (it could be destroyed)
     */
    
    zdb_zone *dbz = zdb_zone_find_from_name(parm->db, parm->domain, parm->zclass);

    log_info("database: update signature: processing zone '%s'", parm->domain);

    if(dbz == NULL)
    {
        log_warn("database: update signature: zone '%s' expected but not found in the database", parm->domain);

        free(parm->domain);
        free(parm);

        return DATABASE_ZONE_NOT_FOUND;
    }

    if((return_code = zdb_update_zone_signatures(dbz, TRUE)) == ZDB_ERROR_ZONE_IS_ALREADY_BEING_SIGNED)
    {
        return_code = ALARM_REARM;
    }
    else
    {
        free(parm->domain);
        free(parm);
    }

    return return_code;
}

ya_result
database_signature_maintenance(database_t *database)
{
    zdb *db = (zdb*)database;
    
    zone_set_lock(&g_config->zones);

    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&g_config->zones.set, &iter);
   
    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_data *zone_desc = (zone_data *)zone_node->data;
        
        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }
        
        if(zone_desc->type == ZT_MASTER)
        {
        
#if ZDB_RECORDS_MAX_CLASS == 1
            if(TRUE)
#else
            if(zone_desc->qclass == CLASS_IN)
#endif
            {
                zdb_zone* zone = zdb_zone_find_from_name(db, zone_desc->domain, CLASS_IN);

                /*
                 * If the zone exists
                 */

                if((zone != NULL) && ZDB_ZONE_VALID(zone))
                {
                    /**
                     * If the zone's scheduled invalidation time is after the zone's database (and thus real) invalidation time
                     * 
                     * zdb_zone_is_dnssec(zone) for zdb_zone* ...
                     */

                    if((zone_desc->scheduled_sig_invalid_first >= zone->sig_invalid_first) && (zone->sig_invalid_first != MAX_U32))
                    {
                        log_info("database: scheduling signature update for '%s' at %d (%d)", zone_desc->domain, zone->sig_invalid_first, zone_desc->scheduled_sig_invalid_first);

                        database_update_signatures_parm *parm;
                        MALLOC_OR_DIE(database_update_signatures_parm*, parm, sizeof(database_update_signatures_parm), DBUPSIGP_TAG);
                        parm->db = db;
                        parm->domain = strdup(zone_desc->domain);
                        parm->zclass = zone_desc->qclass;

                        /*
                         * Sets the alarm to be called at the time the first signature will be invalidated
                         * The first time the alarm will be called for the zone is reset to the new, earlier, value
                         */

                        alarm_event_node *event = alarm_event_alloc();
                        event->epoch = zone->sig_invalid_first;
                        event->function = database_update_signatures_alarm;
                        event->args = parm;
                        event->key = ALARM_KEY_ZONE_SIGNATURE_UPDATE;
                        event->flags = ALARM_DUP_REMOVE_LATEST;
                        event->text = "database_update_signatures_alarm";

                        alarm_set(zone->alarm_handle, event);

                        zone_desc->scheduled_sig_invalid_first = zone->sig_invalid_first;
                    }
                }
                else
                {
                    if(zone == NULL)
                    {
                        log_warn("database signature maintenance: zone '%s' expected but not found in the database", zone_desc->domain);
                    }
                }
            }
        }
    }
    
    zone_set_unlock(&g_config->zones);
    
    return SUCCESS;
}

/*
 * Note: there are probably better (faster) ways to iterate through the zones.
 *
 *          ie: going through the zone tree from the database.
 *
 * It would avoid doing a search in the same tree for EACH zone.
 *
 * Right now this will do.
 *
 */

static ya_result
database_zone_refresh_alarm(void *args)
{
    database_zone_refresh_alarm_args *sszra = (database_zone_refresh_alarm_args*)args;
    u8 *origin = sszra->origin;
    database_t *db = sszra->db;
    ya_result return_value;
    bool active = FALSE;

    log_info("database: refresh: zone %{dnsname}", origin);

    zone_data *zone = zone_getbydnsname(origin);

    if(zone == NULL)
    {
        log_err("database: refresh: zone %{dnsname}: not found", origin);
        free(sszra);
        
        return ERROR;
    }

    zdb_zone* dbz = zdb_zone_find_from_name((zdb*)db, zone->domain, CLASS_IN);
    
    if(dbz != NULL)
    {

        /**
         * check if the zone is locked. postpone if it is
         */

        if(zdb_zone_trylock(dbz, ZDB_ZONE_MUTEX_REFRESH))
        {
            u32 now = time(NULL);

            soa_rdata soa;

            if(FAIL(return_value = zdb_zone_getsoa(dbz, &soa)))
            {
                /*
                 * No SOA ? It's critical
                 */

                free(sszra);

                log_quit("database: refresh: zone %{dnsname}: get soa: %r", origin, return_value);
                return ERROR;
            }

            if(zone->refresh.refreshed_time >= zone->refresh.retried_time)
            {
                if(now >= zone->refresh.refreshed_time + soa.refresh)
                {
                    /*
                     * Do a refresh
                     */

                    log_info("database: refresh: zone %{dnsname}: refresh", origin);

                    zone->refresh.retried_time = zone->refresh.refreshed_time + 1;

                    scheduler_ixfr_query((database_t *)db, zone->masters, zone->origin);

                    active = TRUE;
                }
            }
            else
            {
                if(now < zone->refresh.refreshed_time + soa.expire)
                {
                    if(now >= zone->refresh.retried_time + soa.retry)
                    {
                        /*
                        * Do a retry
                        */

                        log_info("database: refresh: zone %{dnsname}: retry", origin);

                        zone->refresh.retried_time = now;

                        scheduler_ixfr_query((database_t *)db, zone->masters, zone->origin);

                        active = TRUE;
                    }
                }
                else
                {
                    /*
                     * The zone is not authoritative anymore
                     */

                    log_warn("database: refresh: zone %{dnsname}: expired", origin);
                    
                    dbz->apex->flags |= ZDB_RR_LABEL_INVALID_ZONE;
                }
            }

            zdb_zone_unlock(dbz, ZDB_ZONE_MUTEX_REFRESH);
        }
        else
        {
            log_info("database: refresh: zone %{dnsname}: has already been locked", origin);
        }
    }

    if(active)
    {
        /*
         * The alarm rang but nothing has been done
         */
        log_warn("database: refresh: zone %{dnsname}: nothing to do, re-arming the alarm", origin);

        database_zone_refresh_maintenance(db, origin);
    }

    free(sszra);

    return SUCCESS;
}

static ya_result
database_zone_refresh_maintenance_internal(database_t *db, zdb_zone* zone)
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

        if(FAIL(return_value = zdb_zone_getsoa(zone, &soa)))
        {
            /*
             * No SOA ? It's critical
             */
            
            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_REFRESH); /* here ! */

            log_err("database_zone_refresh_maintenance: get soa: %r", return_value);
            exit(EXIT_FAILURE);
        }

        database_zone_refresh_alarm_args *sszra;

        MALLOC_OR_DIE(database_zone_refresh_alarm_args*, sszra, sizeof(database_zone_refresh_alarm_args), DBREFALP_TAG);

        sszra->origin = dnsname_dup(zone->origin);
        sszra->db = db;

        alarm_event_node *event = alarm_event_alloc();
        event->epoch = now + soa.refresh;
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
database_zone_refresh_maintenance(database_t *database, const u8 *origin)
{
    log_info("database: refresh: database_zone_refresh_maintenance for zone %{dnsname}", origin);

    zdb_zone *dbzone = zdb_zone_find_from_dnsname((zdb*)database, origin, CLASS_IN);

    return database_zone_refresh_maintenance_internal(g_config->database, dbzone);
}

ya_result
database_initialise_refresh_maintenance(database_t *database)
{
    ya_result return_value = SUCCESS;
    
    zone_set_lock(&g_config->zones);

    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&g_config->zones.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_data *zone = (zone_data *)zone_node->data;
        
        if(zone_is_obsolete(zone))
        {
            continue;
        }
        
        if(zone->type == ZT_SLAVE)    /** @TODO remove or put into defines */
        {
            log_info("database: refresh: database_initialise_refresh_maintenance for zone %{dnsname}", zone->domain);

            zdb_zone* dbz = zdb_zone_find_from_name((zdb*)database, zone->domain, CLASS_IN);

            if(FAIL(return_value = database_zone_refresh_maintenance_internal(g_config->database, dbz)))
            {
                break;
            }
        }
    }
    
    zone_set_unlock(&g_config->zones);

    return return_value;
}

ya_result
database_freeze_zone(zone_data *zone_config)
{
    ya_result return_value = ERROR;

    if(zone_config->file_name != NULL)
    {
        zdb_zone *zone;
        dnsname_vector fqdn_vector;
        dnsname_to_dnsname_vector(zone_config->origin, &fqdn_vector);

        if((zone = zdb_zone_find((zdb*)g_config->database, &fqdn_vector, CLASS_IN)) != NULL)
        {
            return_value = scheduler_queue_zone_freeze(zone, g_config->data_path, zone_config->file_name);
        }
    }
    
    return return_value;
}

ya_result
database_unfreeze_zone(zone_data *zone_config)
{
    ya_result return_value = ERROR;
    
    if(zone_config->file_name != NULL)
    {
        zdb_zone *zone;
        dnsname_vector fqdn_vector;
        dnsname_to_dnsname_vector(zone_config->origin, &fqdn_vector);

        if((zone = zdb_zone_find((zdb*)g_config->database, &fqdn_vector, CLASS_IN)) != NULL)
        {
            return_value = scheduler_queue_zone_unfreeze(zone);
        }
    }
    
    return return_value;
}

static void
database_save_zone_to_disk_callback(void *parms)
{
    zone_data *zone_desc = (zone_data*)parms;
    smp_int_setifequal(&zone_desc->is_saving_as_text, 1, 0);
    log_info("database: %{dnsname} zone file written", zone_desc->origin);
}

ya_result
database_save_zone_to_disk(zone_data *zone_desc)
{
    ya_result return_value = ERROR;
    
    if(zone_desc->file_name != NULL)
    {
        if(smp_int_setifequal(&zone_desc->is_saving_as_text, 0, 1))
        {
            log_info("database: queueing %{dnsname} zone file write", zone_desc->origin);
            
            zdb_zone *zone;
            dnsname_vector fqdn_vector;
            dnsname_to_dnsname_vector(zone_desc->origin, &fqdn_vector);

            if((zone = zdb_zone_find((zdb*)g_config->database, &fqdn_vector, CLASS_IN)) != NULL)
            {
                char file_path[PATH_MAX];
                
                if(ISOK(return_value = snformat(file_path, sizeof(file_path), "%s/%s", g_config->data_path, zone_desc->file_name)))
                {                
                    /* If the zone write is not scheduled, then the system will never know it */
                    return_value = scheduler_queue_zone_write(zone, file_path, database_save_zone_to_disk_callback, zone_desc);
                    
                    return return_value;
                }

                log_err("database: zone file path %s/%s issue: %r", g_config->data_path, zone_desc->file_name, return_value);
            }
            
            smp_int_setifequal(&zone_desc->is_saving_as_text, 1, 0);
        }
    }
    
    return return_value;
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
    
    zone_set_lock(&g_config->zones);
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&g_config->zones.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        
        zone_data *zone_desc = (zone_data*)zone_node->data;
        
        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }
                        
        database_save_zone_to_disk(zone_desc);
    }
    
    zone_set_unlock(&g_config->zones);
    
    return batch_return_value;
}

bool
database_are_all_zones_saved_to_disk()
{
    bool can_unload;  
    
    can_unload = TRUE;
    
    zone_set_lock(&g_config->zones);
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&g_config->zones.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);

        zone_data *zone_desc = (zone_data*)zone_node->data;

        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }
        
        if(smp_int_get(&zone_desc->is_saving_as_text) == 1)
        {
            can_unload = FALSE;
            break;
        }
    }
    
    zone_set_unlock(&g_config->zones);
    
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
    zone_set_lock(&g_config->zones);
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&g_config->zones.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        
        zone_data *zone_desc = (zone_data*)zone_node->data;
        
        if(zone_is_obsolete(zone_desc))
        {
            continue;
        }
                        
        smp_int_set(&zone_desc->is_saving_as_text, -1);
    }
    
    zone_set_unlock(&g_config->zones);
}

/** @} */

/*----------------------------------------------------------------------------*/

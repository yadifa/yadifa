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
/** @defgroup database Routines for database manipulations
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

#include <dnscore/format.h>
#include <dnscore/scheduler.h>
#include <dnscore/serial.h>
#include <dnscore/threaded_queue.h>
#include <dnscore/thread_pool.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/fdtools.h>
#include <dnscore/xfr_copy.h>
#include <dnscore/tcp_io_stream.h>

#include <dnsdb/zdb_zone_label.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_record.h>
#include <dnsdb/zdb_zone_write.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/zdb_utils.h>

#include <dnsdb/zdb_zone_load.h>
#include <dnszone/zone_file_reader.h>
#include <dnszone/zone_axfr_reader.h>

#include "scheduler_database_load_zone.h"

#include "scheduler_xfr.h"
#include "server.h"
#include "notify.h"
#include "ixfr.h"

#include "server_error.h"

#define MODULE_MSG_HANDLE g_server_logger

#define DBLOADQ_TAG 0x5144414f4c4244

typedef struct scheduler_database_load_zone_args scheduler_database_load_zone_args;

struct scheduler_database_load_zone_args
{
    zdb         *database;
    zone_data   *zone_desc;
    zdb_zone    *old_zone;
    zdb_zone    *new_zone;
    ya_result    return_value;
    bool         replace_zone_desc;
    bool         load_zone;
};

static database_message *
database_load_message_alloc(const u8 *origin, u8 type)
{
    database_message *message;
    
    MALLOC_OR_DIE(database_message*, message, sizeof(database_message), DBLOADQ_TAG);
    ZEROMEMORY(message, sizeof(database_message));
    
    message->origin = dnsname_dup(origin);
    message->payload.type = type;
    
    return message;
}

static void
database_load_message_free(database_message *message)
{
    free(message->origin);    
    free(message);
}

/**********************************************************************************************************************/

static ya_result
scheduler_database_replace_zone_finalize(void *data_)
{
    scheduler_database_load_zone_args *args = (scheduler_database_load_zone_args *)data_;
    
    log_debug("scheduler_database_replace_zone_finalize: %{dnsname}", args->zone_desc->origin);
    
    if(args->zone_desc->type == ZT_MASTER)
    {
        notify_slaves(args->zone_desc->origin);
    }
    else if(args->zone_desc->type == ZT_SLAVE)
    {        
        scheduler_ixfr_query(g_config->database, args->zone_desc->masters, args->zone_desc->origin);
    }
    
    free(args);

    return SCHEDULER_TASK_FINISHED;
}

static ya_result
scheduler_database_replace_zone_init(void *data_)
{
    scheduler_database_load_zone_args *args = (scheduler_database_load_zone_args *)data_;
    
    log_debug("scheduler_database_replace_zone_init: %{dnsname}", args->zone_desc->origin);
    
    zone_data *zone_desc = args->zone_desc;
    
    if(args->replace_zone_desc)
    {
        zone_register(&g_config->zones, zone_desc);
    }
    
    dnsname_vector name;
    DEBUG_RESET_dnsname(name);

    dnsname_to_dnsname_vector(zone_desc->origin, &name);

    zdb_zone_label *zone_label = zdb_zone_label_add(args->database, &name,  zone_desc->qclass);

    zdb_zone *placeholder_zone = zone_label->zone;
    
    args->new_zone->extension = &zone_desc->ac;
    args->new_zone->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);

    zone_label->zone = args->new_zone;

    log_info("master: %{dnsname} zone mounted", zone_desc->origin);

    u32 now = time(NULL);

    zone_desc->refresh.refreshed_time = now;
    zone_desc->refresh.retried_time = now;

    zdb_zone_unlock(placeholder_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    zdb_zone_destroy(placeholder_zone);
    
    return SCHEDULER_TASK_FINISHED;
}

static void*
scheduler_database_replace_zone_thread(void *data_)
{
    scheduler_database_load_zone_args *args = (scheduler_database_load_zone_args *)data_;
    
    log_debug("scheduler_database_replace_zone_thread: %{dnsname}", args->zone_desc->origin);
    
    scheduler_schedule_task(scheduler_database_replace_zone_finalize, data_);
    
    return NULL;
}

void
scheduler_database_replace_zone(zdb *db, zone_data *zone_desc, zdb_zone *zone)
{
    scheduler_database_load_zone_args *args;
    
    MALLOC_OR_DIE(scheduler_database_load_zone_args*, args, sizeof(scheduler_database_load_zone_args), GENERIC_TAG);
    ZEROMEMORY(args, sizeof(scheduler_database_load_zone_args));
    
    args->database = (zdb*)db;
    args->zone_desc = zone_desc;
    args->new_zone = zone;
    
    log_debug("scheduler_database_replace_zone: %{dnsname}", args->zone_desc->origin);
    
    scheduler_schedule_thread(scheduler_database_replace_zone_init, scheduler_database_replace_zone_thread, args, "scheduler_database_replace_zone");
}

/**********************************************************************************************************************/

static ya_result
scheduler_database_invalidate_zone_finalize(void *data_)
{    
    scheduler_database_load_zone_args *args = (scheduler_database_load_zone_args *)data_;
 
    log_debug("scheduler_database_invalidate_zone_finalize: %{dnsname}", args->zone_desc->origin);
    
    if(args->load_zone)
    {
        database_load_zone_load(args->zone_desc->origin);
    }
    
    free(args);
    
    return SCHEDULER_TASK_FINISHED;
}

static ya_result
scheduler_database_invalidate_zone_init(void *data_)
{
    scheduler_database_load_zone_args *args = (scheduler_database_load_zone_args *)data_;
    
    log_debug("scheduler_database_invalidate_zone_init: %{dnsname}", args->zone_desc->origin);
    
    args->old_zone = zdb_zone_xchg_with_invalid((zdb*)g_config->database, args->zone_desc->origin, args->zone_desc->qclass, 0);
    
    return SCHEDULER_TASK_PROGRESS;
}

static void*
scheduler_database_invalidate_zone_thread(void *data_)
{
    scheduler_database_load_zone_args *args = (scheduler_database_load_zone_args *)data_;
    
    log_debug("scheduler_database_invalidate_zone_thread: %{dnsname}", args->zone_desc->origin);
    
    if(args->old_zone != NULL)
    {
        zdb_zone_unlock(args->old_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        zdb_zone_destroy(args->old_zone);
        args->old_zone = NULL;
    }
    
    scheduler_schedule_task(scheduler_database_invalidate_zone_finalize, args);
    
    return NULL;
}

void
scheduler_database_invalidate_zone(zdb *db, zone_data *zone_desc, bool load_after_invalid)
{
    scheduler_database_load_zone_args *args;
    
    MALLOC_OR_DIE(scheduler_database_load_zone_args*, args, sizeof(scheduler_database_load_zone_args), GENERIC_TAG);
    ZEROMEMORY(args, sizeof(scheduler_database_load_zone_args));
    
    args->database = (zdb*)db;
    args->zone_desc = zone_desc;
    args->load_zone = load_after_invalid;
    
    log_debug("scheduler_database_invalidate_zone_thread: %{dnsname}", args->zone_desc->origin);
    
    scheduler_schedule_thread(scheduler_database_invalidate_zone_init, scheduler_database_invalidate_zone_thread, args, "scheduler_database_invalidate_zone");
}

/**********************************************************************************************************************/

/**
 * Loads a MASTER zone file from disc into memory.
 * Returns a pointer to the zone structure.
 * The zone still has to be "mounted" in the database
 * 
 * @param db            a pointer to the database
 * @param zone_desc     the zone configuration
 * @param zone          pointer to a zone pointer that will hold the loaded zone structure
 * @return 
 */

static ya_result
scheduler_database_load_zone_master(zdb *db, zone_data *zone_desc, zdb_zone **zone)
{
    if(zone_desc->type != ZT_MASTER)
    {
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
        
        return ZONE_LOAD_MASTER_TYPE_EXPECTED;
    }
    
    if(zone_desc->file_name == NULL)
    {
        log_crit("zone load: no file defined for master zone section (not loaded)"); /* will ultimately lead to the end of the program */
        
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);

        return ZONE_LOAD_SLAVE_TYPE_EXPECTED;
    }

    /*
     * _ Open the zone file/source
     * _ Load the zone
     *   (do the NSEC/NSEC3 pre-processing)
     * _ Close the zone file/source
     * _ Apply the ACLs
     * _ Schedule an NSEC/NSEC3 verify/update. (Here ?)
     */

    /* Avoid cpy & cat : overrun potential */
    
    zone_reader zr;
    zdb_zone *zone_pointer_out;
    ya_result return_value;
    char file_name[1024];
        
    snformat(file_name, sizeof(file_name), "%s%s", g_config->data_path, zone_desc->file_name);

    log_info("zone load: loading '%s'", file_name);
 
    if(ISOK(return_value = zone_file_reader_open(file_name, &zr)))
    {
        return_value = zdb_zone_load(db, &zr, &zone_pointer_out, g_config->xfr_path, zone_desc->origin, ZDB_ZONE_REPLAY_JOURNAL|(zone_desc->dnssec_mode << ZDB_ZONE_DNSSEC_SHIFT));

        zone_reader_close(&zr);

        /* If the zone load failed for any reason but "loaded already" ... */

        if(!(FAIL(return_value) && (return_value != ZDB_READER_ALREADY_LOADED)))
        {
            /*
             * zone_pointer_out must be mounted
             */

#if HAS_ACL_SUPPORT != 0

            /*
             * Setup the ACL filter function & configuration
             */

            zone_pointer_out->extension = &zone_desc->ac; /* The extension points to the ACL */
            zone_pointer_out->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);
#endif

#if HAS_DNSSEC_SUPPORT != 0

            /*
             * Setup the validity period and the jitter
             */

            zone_pointer_out->sig_validity_regeneration_seconds = zone_desc->sig_validity_regeneration * SIGNATURE_VALIDITY_INTERVAL_S;
            zone_pointer_out->sig_validity_interval_seconds = zone_desc->sig_validity_interval * SIGNATURE_VALIDITY_REGENERATION_S;
            zone_pointer_out->sig_validity_jitter_seconds = zone_desc->sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S;
#endif
            u32 now = time(NULL);

            zone_desc->refresh.refreshed_time = now;
            zone_desc->refresh.retried_time = now;
            
            // switch back with the invalid (schedule that ST)
            
            log_info("zone load: '%s' loaded", zone_desc->domain);
            
            *zone = zone_pointer_out;
            
            scheduler_database_replace_zone((zdb*)g_config->database, zone_desc, zone_pointer_out);
            
            zone_unlock(zone_desc, ZONE_LOCK_LOAD);
            
            return SUCCESS;
        }
        else
        {
            log_err("zone load: cannot parse master zone file '%s': %r (not loaded)", file_name, return_value);
        }
    }
    else
    {
        log_err("zone load: cannot open master zone file '%s': %r (not loaded)", file_name, return_value);
    }
    
    zone_unlock(zone_desc, ZONE_LOCK_LOAD);
    
    return return_value;
}

static ya_result
scheduler_database_get_ixfr_answer_type(zone_data *zone_desc, u32 ttl, u16 soa_rdata_size, const u8* soa_rdata)
{
   /*
    * Start an IXFR query
    */

    input_stream is;
    output_stream os;
    
    ya_result return_value;
    
    message_data ixfr_query;

#ifdef DEBUG
    memset(&ixfr_query,0xff,sizeof(ixfr_query));
#endif

    log_debug("zone load: incremental change query to the master of %{dnsname}", zone_desc->origin);
    
    u32 answer_serial[2];
    u32 answer_idx = 0;
    u32 current_serial;
    
    if(FAIL(return_value = rr_soa_get_serial(soa_rdata, soa_rdata_size, &current_serial)))
    {
        return return_value;
    }

    if(ISOK(return_value = ixfr_start_query(zone_desc->masters, zone_desc->origin, ttl, soa_rdata, soa_rdata_size, &is, &os, &ixfr_query)))
    {       
        u8 record_wire[1024];
        
        /*
        * Read the answer (first message anyway)
        * Look for the answer type in it.
        */

        u16 query_id = MESSAGE_ID(ixfr_query.buffer);

        int fd = fd_input_stream_get_filedescriptor(&is);

        tcp_set_recvtimeout(fd, 3, 0);  /* 3 seconds read timeout */

        do
        {
            if(FAIL(return_value = readfully_limited(fd, &ixfr_query.buffer_tcp_len[0], 2, 1.0)))
            {
                break;
            }
            
            if(return_value != 2)
            {
                return_value = ANSWER_UNEXPECTED_EOF;
                
                break;
            }
            
            if(FAIL(return_value = readfully_limited(fd, &ixfr_query.buffer[0], message_get_tcp_length(&ixfr_query), 512.0)))
            {
                break;
            }

            if(return_value < DNS_HEADER_LENGTH + 1 + 4)
            {
                return_value = ANSWER_NOT_ACCEPTABLE;
                
                break;
            }
            
            return_value = ANSWER_NOT_ACCEPTABLE;
                        
            /**
             * check the ID, check the error code
             * 
             */

            u16 answer_id = MESSAGE_ID(ixfr_query.buffer);

            if(query_id != answer_id)
            {
                log_err("zone load: master answer ID does not match query ID (q:%hd != a:%hd)", query_id, answer_id);
                
                break;
            }

            u16 answer_count = ntohs(MESSAGE_AN(ixfr_query.buffer));

            if(answer_count == 0)
            {
                break;
            }
                        
            u8 error_code = MESSAGE_RCODE(ixfr_query.buffer);
            
            if(error_code != RCODE_OK)
            {
                return_value = MAKE_DNSMSG_ERROR(error_code);
                
                log_err("zone load: master answered with error code: %r", return_value);
                
                break;
            }

            /* read the query record */

            packet_unpack_reader_data reader;

            packet_reader_init(&ixfr_query.buffer[0], return_value, &reader);
            reader.offset = DNS_HEADER_LENGTH;

            u16 query_count = ntohs(MESSAGE_QD(ixfr_query.buffer));
            
            if(query_count > 1)
            {
                return_value = ANSWER_NOT_ACCEPTABLE;
                break;
            }
            else if(query_count == 1) /* a good compiler will combine the > 1 and the == 1 using 1 cmp and 2 jumps */
            {
                if(FAIL(return_value = packet_reader_read_zone_record(&reader, record_wire, sizeof(record_wire))))
                {
                    break;
                }
            }

            /** @todo add checks */

            /* read the next answer */

            for(;(answer_count > 0) && (answer_idx < 2); answer_count--)
            {                            
                if(FAIL(return_value = packet_reader_read_record(&reader, record_wire, sizeof(record_wire))))
                {
                    break;
                }

                u8 *p = record_wire + dnsname_len(record_wire);
                u16 rtype = GET_U16_AT(*p);

                if(rtype != TYPE_SOA)
                {
                    break;
                }

                p += 8;
                u16 rdata_size = ntohs(GET_U16_AT(*p));
                p += 2;
                
                u32 serial;
                
                if(FAIL(return_value = rr_soa_get_serial(p, rdata_size, &serial)))
                {
                    return return_value;
                }
                
                answer_serial[answer_idx] = serial;
                
                p += rdata_size;
                
                answer_idx++;
            }
            
            if((answer_idx == 1) && (answer_serial[0] == current_serial))
            {
                break;
            }
        }
        while(answer_idx < 2);
        
        input_stream_close(&is);
        output_stream_close(&os);
    }
    
    if(FAIL(return_value))
    {
        answer_idx = 0;
    }
    
    switch(answer_idx)
    {
        case 0:
        {
            /* no SOA returned */
            
            log_info("zone load: query to the master failed: %r", return_value);
            
            break;
        }
        case 1:
        {
            /* one AXFR returned */
            
            if(serial_gt(answer_serial[0], current_serial))
            {
                log_info("zone load: master offers full zone transfer with serial %u", answer_serial[0]);
                
                return_value = TYPE_AXFR;
            }
            else
            {
                log_info("zone load: master has the same serial %u", answer_serial[0]);
                
                return_value = SUCCESS;
                return_value = TYPE_IXFR; /** @todo remove: this is wrong and this is to test xfr_copy */
            }
            
            break;
        }
        case 2:
        {
            if(answer_serial[0] != answer_serial[0])
            {
                log_info("zone load: master offers an empty zone with serial %u", answer_serial[0]);
                
                return_value = TYPE_AXFR;
            }
            else
            {
                log_info("zone load: master offers incremental changes from serial %u to serial %u", answer_serial[1], answer_serial[0]);
                
                return_value = TYPE_IXFR;
            }
            
            break;
        }
    }
    
    return return_value;
}

static ya_result
scheduler_database_load_zone_slave(zdb *db, zone_data *zone_desc, zdb_zone **zone)
{
    if(zone_desc->type != ZT_SLAVE)
    {
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
        
        return ZONE_LOAD_SLAVE_TYPE_EXPECTED;
    }
    
    /**
     * Load only the SOA
     * ask for an IXFR
     * If the answer is IXFR store it as an incremental (so it will be loaded later)
     * If the answer is an AXFR the current files are irrelevant : destroy and load the axfr:w
     *
     */

    zdb_zone *zone_pointer_out;
    u32  file_serial;
    u32  axfr_serial;
    u32  zone_serial;
    ya_result return_value;
    bool zone_file_available = FALSE;
    bool axfr_file_available = FALSE;
    
    zone_reader zr;
    
    u32 ttl = 0;
    u16 rdata_size = 0;
    
    u8  rdata[1024];    
    char file_name[1024];

    /*
     * FILE
     */
    
    log_debug("zone load: loading slave '%s'", zone_desc->domain);

    if(zone_desc->file_name != NULL)
    {
        snformat(file_name, sizeof (file_name), "%s%s", g_config->data_path, zone_desc->file_name);

        log_debug("zone load: opening '%s'", file_name);

        if(ISOK(return_value = zone_file_reader_open(file_name, &zr)))
        {
            log_debug("zone load: checking serial in cached copy '%s'", file_name);
            
            if(ISOK(return_value = zdb_zone_get_soa(&zr, &rdata_size, rdata)))
            {
                if(ISOK(rr_soa_get_serial(rdata, rdata_size, &file_serial)))
                {
                    zone_file_available = TRUE;
                    zone_serial = file_serial;
                    
                    log_debug("zone load: serial in cached copy '%s' is %u", file_name, file_serial);
                }
            }

            zone_reader_close(&zr);
        }
    }

    /*
     * AXFR : the serial returned here does not takes the journal into account if the boolean is set to FALSE
     */

    if(ISOK(return_value = zone_axfr_reader_open_last(g_config->xfr_path, zone_desc->origin, &zr)))
    {
        log_debug("zone load: found an AXFR image for %{dnsname}", zone_desc->origin);
        
        if(ISOK(return_value = zdb_zone_get_soa(&zr, &rdata_size, rdata)))
        {
            if(ISOK(rr_soa_get_serial(rdata, rdata_size, &axfr_serial)))
            {
                axfr_file_available = TRUE;
                zone_serial = axfr_serial;
                
                log_debug("zone load: serial in AXFR image is %u", axfr_serial);
            }
        }

        zone_reader_close(&zr);
    }

    /*
     * check if both types are available
     * 
     * disable the lowest serial or the AXFR one if they are equal
     * 
     */
    
    u32 zone_journal_serial = 0;

    if(axfr_file_available && zone_file_available)
    {
        /* choose one */
        
        if(serial_gt(axfr_serial, file_serial))
        {
            log_debug("zone load: using AXFR image");
            
            zone_file_available = FALSE;
            zone_serial = axfr_serial;
        }
        else
        {
            log_debug("zone load: using cached zone file");
            
            axfr_file_available = FALSE;
            zone_serial = file_serial;
        }
    }

    if(axfr_file_available || zone_file_available)
    {
        /*
        * Now we know the best (local) base for the file, but we need to know up to where we can go (journal)
        * 
        * Afterward, since we are a slave we need as for an IXFR and see the answer.
        * If it's an IXFR we will load the zone then replay then download the IXFR.
        * If it's an AXFR we will delete everything then download the zone.
        * 
        */
        
        log_debug("zone load: parsing journal for last serial");

        if(FAIL(return_value = zdb_icmtl_get_last_soa_from(zone_serial, zone_desc->origin, g_config->xfr_path, &zone_journal_serial, &ttl, &rdata_size, rdata))) // false positive: zone_serial IS initialised. It's the only way to enter here.
        {
            if(return_value == ZDB_ERROR_ICMTL_NOTFOUND)
            {
                log_debug("zone load: no journal");
                
                return_value = SUCCESS;
            }
        }
        
        if(ISOK(return_value))
        {
            log_debug("zone load: poking the master of %{dnsname} with an SOA query", zone_desc->origin);
            
            u32 master_serial = (zone_journal_serial - 2)|1; /* default to less but avoid 0 */
            
            if(ISOK(return_value = message_query_serial(zone_desc->origin, zone_desc->masters, &master_serial)))
            {
                log_debug("zone load: serial of %{dnsname} on the master is %d\n", zone_desc->origin, master_serial);
            }
            
            if(ISOK(return_value) && (zone_journal_serial != master_serial))
            {
                return_value = scheduler_database_get_ixfr_answer_type(zone_desc, ttl, rdata_size, rdata);

                if((return_value != TYPE_IXFR) && (return_value != SUCCESS))
                {
                    /* axfr or error */

                    if(return_value != TYPE_AXFR)
                    {                                            
                        log_err("zone load: unexpected answer from the master (will query for a full zone transfer)");
                    }

                    char data_path[PATH_MAX]; 

                    xfr_copy_get_data_path(g_config->xfr_path, zone_desc->origin, data_path, sizeof(data_path));

                    xfr_delete_axfr(zone_desc->origin, data_path);
                    xfr_delete_ix(zone_desc->origin, data_path);

                    axfr_file_available = zone_file_available = FALSE;
                }
            }
        }
        
        if(FAIL(return_value))
        {
            log_err("zone load: unable to download zone from master: %r", return_value);
        }                
    }
    
    /*
     * Now ask to the master for an IXFR that we will interrupt.
     * After a few retries, load the current zone.
     */

    if(axfr_file_available)
    {
        log_info("zone load: loading %{dnsname} axfr in '%s'", zone_desc->origin, g_config->xfr_path);

        if(FAIL(return_value = zone_axfr_reader_open_last(g_config->xfr_path, zone_desc->origin, &zr)))
        {
            log_err("zone load: unexpectedly unable to load an axfr for %{dnsname}", zone_desc->origin);

            axfr_file_available = FALSE;
        }
    }

    if(zone_file_available)
    {
        log_info("zone load: loading %{dnsname} file '%s'", zone_desc->origin, file_name);

        if(FAIL(return_value = zone_file_reader_open(file_name, &zr)))
        {
            log_err("zone load: unexpectedly unable to load '%s' when it had just been found earlier", file_name);

            zone_file_available = FALSE;
        }
    }
    
    /*
     * _ Open the zone file/source
     * _ Load the zone
     *   (do the NSEC/NSEC3 pre-processing)
     * _ Close the zone file/source
     * _ Apply the ACLs
     * _ Schedule an NSEC/NSEC3 verify/update. (Here ?)
     */

    if(axfr_file_available || zone_file_available)
    {
        /* Avoid cpy & cat : overrun potential */

        return_value = zdb_zone_load(db, &zr, &zone_pointer_out, g_config->xfr_path, zone_desc->origin, ZDB_ZONE_REPLAY_JOURNAL|ZDB_ZONE_IS_SLAVE);

        zone_reader_handle_error(&zr, return_value);

        zone_reader_close(&zr);

        u32 now = time(NULL);

        zone_desc->refresh.refreshed_time = now;
        zone_desc->refresh.retried_time = now;

        /* If the zone load failed for any reason but "loaded already" ... */

        if(ISOK(return_value))
        {
            
#if HAS_ACL_SUPPORT != 0

           /*
            * Setup the ACL filter function & configuration
            */

            zone_pointer_out->extension = &zone_desc->ac; /* The extension points to the ACL */
            zone_pointer_out->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);
#endif

#if HAS_DNSSEC_SUPPORT != 0

           /*
            * Setup the validity period and the jitter
            */

            zone_pointer_out->sig_validity_interval_seconds = MAX_S32;/*zone->sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S */;
            zone_pointer_out->sig_validity_jitter_seconds = 0;/*zone->sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S */;
#endif
            *zone = zone_pointer_out;
            
            scheduler_database_replace_zone((zdb*)g_config->database, zone_desc, zone_pointer_out);
            
            zone_unlock(zone_desc, ZONE_LOCK_LOAD);
            
            return return_value;
        }
        else
        {
            switch(return_value)
            {
                case ZDB_READER_ALREADY_LOADED:
                {
                    log_warn("zone load: failed because it was loaded already");
                    break;
                }
                case ZDB_ERROR_ICMTL_NOTFOUND:
                {
                    log_info("zone load: no journal to replay");
                    return_value = SUCCESS;
                    break;
                }
                case UNABLE_TO_COMPLETE_FULL_READ:
                {
                    log_err("zone load: the zone file or the journal are likely corrupted for zone %{dnsname}: %r", zone_desc->origin, return_value);

                    axfr_file_available = zone_file_available = FALSE;
                    break;
                }
                default:
                {
                    log_err("zone load: an error occurred while loading the zone or journal for %{dnsname}: %r", zone_desc->origin, return_value);

                    axfr_file_available = zone_file_available = FALSE;
                    break;
                }
            }
        }
    }

    if(!(axfr_file_available || zone_file_available))
    {
       /**
        * Set a placeholder zone.  Marked as invalid.
        * 
        * The AXFR mechanism is as follow:
        * 
        * There is MUST ALWAYS be a zone for an existing config.
        * That zone can be a fake one marked as invalid, or a real one that requires some processing.
        * Here we have a fake one so it will be straightforward:
        * The fake is set in place.
        * The AXFR will be tried and made.
        * When it succeeds, since the zone is invalid, the AXFR will be loaded and will be scheduled for a swap & destroy
        * On other cases, the AXFR would first be tested for serial THEN ignored and the invalid zone would be scheduled for a swap-back
        *                                                                OR
        *                                                                the invalid zone will be scheduled for a multiple-stage delete (ST)
        *                                                                then the AXFR will be loaded and will be scheduled for a swap & destroy
        * 
        */

        /**
         * Mark the zone descriptor (config) as "loading"
         */

        zone_setloading(zone_desc, TRUE);

        /**
         * Schedule an AXFR transfer from the master(s)
         */

        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
        
        scheduler_axfr_query((database_t *)db, zone_desc->masters, zone_desc->origin);
    }
    
    return return_value;
}

void
database_load_message_free(database_message *message);

static pthread_t database_load_thread_id = 0;
static threaded_queue database_load_queue;

static void *
database_load_thread(void *args_)
{
    /*
     * while the program is running
     */
    
    thread_pool_setup_random_ctx();
    
    for(;;)
    {
        /*
         * dequeue command
         */
        
        database_message *message = (database_message*)threaded_queue_try_dequeue(&database_load_queue);

        if(message == NULL)
        {
            sleep(1);
            
            if(dnscore_shuttingdown())
            {
                break;
            }
            
            continue;
        }
        
        log_debug("database_load_thread: dequeued operation %d on %{dnsname}", message->payload.type, message->origin);
        
        /*
         * NULL => shutdown the thread
         */
        
        /*
         * load command ?
         */
        
        switch(message->payload.type)
        {
            case DATABASE_LOAD_LOAD_ZONE:
            {
                ya_result return_value;
                
                /*
                 * Invalidate the zone
                 * Empty the current zone if any
                 */
                
                zone_data *zone_desc = zone_getbydnsname(message->origin);
                
                /*
                 * If the zone descriptor (config) exists and it can be locked by the loader ...
                 */
                
                if((zone_desc != NULL) && ISOK(zone_lock(zone_desc, ZONE_LOCK_LOAD)))
                {
                    if(!zdb_zone_isinvalid((zdb*)g_config->database, zone_desc->origin, zone_desc->qclass))
                    {
                        scheduler_database_invalidate_zone((zdb*)g_config->database, zone_desc, TRUE);
                        
                        zone_unlock(zone_desc, ZONE_LOCK_LOAD);

                        break;
                    }

                    // wait

                    if(zone_desc->type == ZT_MASTER)
                    {
                        /*
                         * load master ?
                         * => load the file
                         * => schedule the xchg with the invalidated zone
                         */
                        
                        zdb_zone *zone;

                        if(FAIL(return_value = scheduler_database_load_zone_master((zdb*)g_config->database, zone_desc, &zone)))
                        {
                            log_err("database_load_thread: error loading master %{dnsname}: %r", zone_desc->origin, return_value);
                        }
                    }
                    else if(zone_desc->type == ZT_SLAVE)
                    {
                        /*
                         * load slave
                         * 
                         * if no file/axfr is available => axfr (responsible to requeue the load) and continue
                         * 
                         * if file/axfr is available => load the file/axfr
                         * 
                         * => schedule the xchg with the invalidated zone
                         * 
                         */

                        zdb_zone *zone;

                        if(FAIL(return_value = scheduler_database_load_zone_slave((zdb*)g_config->database, zone_desc, &zone)))
                        {
                            log_err("database_load_thread: error loading slave %{dnsname}: %r", zone_desc->origin, return_value);
                        }
                    }
                    else /* not master nor slave */
                    {
                        /* other types */
                        
                        zone_unlock(zone_desc, ZONE_LOCK_LOAD);

                        log_err("zone load: unknown zone type");
                        
                        break;
                    }
                }
                
                zone_setstartingup(zone_desc, FALSE);
                
                break;
            }
            case DATABASE_LOAD_UNLOAD_ZONE:
            {
                /*
                 * Invalidate the zone
                 * Empty the current zone if any
                 */
                
                zone_data *zone_desc = zone_getbydnsname(message->origin);
                
                if((zone_desc != NULL) && ISOK(zone_lock(zone_desc, ZONE_LOCK_UNLOAD)))
                {
                    scheduler_database_invalidate_zone((zdb*)g_config->database, zone_desc, FALSE);
                    
                    zone_unlock(zone_desc, ZONE_LOCK_UNLOAD);
                }
                
                // wait
            }

            default:
            {
                break;
            }
        }
        
        database_load_message_free(message);
    }
    
    log_info("zone load: service stopped");
    
    return NULL;
}

void
database_load_startup()
{
    if(database_load_thread_id == 0)
    {
        log_info("zone load: service start");
        
        /** for 1M zones, this should be increased */
        
        threaded_queue_init(&database_load_queue, 4096);   /* maximum updates total per 30 seconds ... */

        if(pthread_create(&database_load_thread_id, NULL, database_load_thread, NULL) != 0)
        {
            exit(EXIT_CODE_THREADCREATE_ERROR);
        }
    }
}

void
database_load_shutdown()
{
    if(database_load_thread_id != 0)
    {
        log_info("zone load: service stop");
        
        database_message *message = database_load_message_alloc((u8*)"", DATABASE_LOAD_STOP);
        
        threaded_queue_enqueue(&database_load_queue, message);
        
        pthread_join(database_load_thread_id, NULL);
        
        for(;;)
        {
            database_message *message = (database_message*)threaded_queue_try_dequeue(&database_load_queue);

            if(message == NULL)
            {
                break;
            }
            
            database_load_message_free(message);
        }
        
        threaded_queue_finalize(&database_load_queue);
        
        database_load_thread_id = 0;
    }
}

void
database_load_zone_load(const u8 *origin)
{
    database_message *message = database_load_message_alloc(origin, DATABASE_LOAD_LOAD_ZONE);

    threaded_queue_enqueue(&database_load_queue, message);
}

void
database_load_zone_unload(const u8 *origin)
{
    database_message *message = database_load_message_alloc(origin, DATABASE_LOAD_UNLOAD_ZONE);

    threaded_queue_enqueue(&database_load_queue, message);
}


/**
 * @}
 */


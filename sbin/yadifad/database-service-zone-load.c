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

#include "config.h"

#include <dnscore/logger.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/fdtools.h>
#include <dnscore/xfr_copy.h>

#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_utils.h>

#include <dnsdb/zdb_zone_load.h>
#include <dnsdb/journal.h>
#include <dnsdb/zdb_record.h>
#include <dnsdb/zdb_zone_write.h>

#include <dnszone/zone_file_reader.h>
#include <dnszone/zone_axfr_reader.h>

#include "database-service.h"
#include "ixfr.h"

#if HAS_CTRL
#include "ctrl.h"
#endif

#define MODULE_MSG_HANDLE g_server_logger

#define DBLOADQ_TAG 0x5144414f4c4244

/**********************************************************************************************************************/

typedef ya_result database_zone_load_loader(zdb *db, zone_desc_s *zone_desc, zdb_zone **zone);

struct database_service_zone_load_parms_s
{
        zdb *db;
        zone_desc_s *zone_desc;
        zdb_zone *zone;
        database_zone_load_loader *loader;
};

typedef struct database_service_zone_load_parms_s database_service_zone_load_parms_s;

static database_service_zone_load_parms_s*
database_zone_load_parms_alloc(zdb *db, zone_desc_s *zone_desc, database_zone_load_loader *loader)
{
    database_service_zone_load_parms_s *parm;
    
    ZALLOC_OR_DIE(database_service_zone_load_parms_s*, parm, database_service_zone_load_parms_s, GENERIC_TAG);
    parm->db = db;
    parm->zone_desc = zone_desc;
    parm->zone = NULL;
    parm->loader = loader;
    
    return parm;
}

void
database_zone_load_parms_free(database_service_zone_load_parms_s *parm)
{
#ifdef DEBUG
    memset(parm, 0xff, sizeof(database_service_zone_load_parms_s));
#endif
    ZFREE(parm, database_service_zone_load_parms_s);
}

#if HAS_MASTER_SUPPORT

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
database_load_zone_master(zdb *db, zone_desc_s *zone_desc, zdb_zone **zone)
{
#ifdef DEBUG
    log_debug("database_load_zone_master(%p,%p,%p)", db, zone_desc, zone);
#endif
    
    zone_lock(zone_desc, ZONE_LOCK_LOAD);
    
    if(zone_desc->type != ZT_MASTER)
    {
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
        
        log_err("zone load: tried to load a non-master zone as a master");
        
        return ZONE_LOAD_MASTER_TYPE_EXPECTED;
    }
    
    if(zone_desc->file_name == NULL)
    {
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
        
        log_err("zone load: no file defined for master zone section (not loaded)");

        return ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED;
    }
    
    if(zone == NULL)
    {
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
        
        log_err("zone load: invalid use");
        
        return ERROR;
    }
    
    zone_reader zr;
    zdb_zone *zone_pointer_out;
    ya_result return_value;
    
    u32 zone_desc_dnssec_mode;
    bool is_drop_before_load;
    bool zr_opened = FALSE;
    u8 zone_desc_origin[MAX_DOMAIN_LENGTH];
    char file_name[PATH_MAX];
    char zone_desc_file_name[PATH_MAX];
    
    zone_desc_dnssec_mode = zone_desc->dnssec_mode;
    is_drop_before_load = zone_is_drop_before_load(zone_desc);
    dnsname_copy(zone_desc_origin, zone_desc->origin);
    strcpy(zone_desc_file_name, zone_desc-> file_name);
    
    zone_unlock(zone_desc, ZONE_LOCK_LOAD);
    
    /*
     * _ Open the zone file/source
     * _ Load the zone
     *   (do the NSEC/NSEC3 pre-processing)
     * _ Close the zone file/source
     * _ Apply the ACLs
     * _ Schedule an NSEC/NSEC3 verify/update. (Here ?)
     */

    /* Avoid cpy & cat : overrun potential */
            
    snformat(file_name, sizeof(file_name), "%s%s", g_config->data_path, zone_desc->file_name);
    
    /** @todo get the serial number from the file to avoid useless work */
    
    *zone = zdb_zone_find_from_dnsname(db, zone_desc_origin, CLASS_IN);

    if(*zone != NULL)
    {
        log_info("zone load: preparing to load '%s'", file_name);

        u32 zone_file_soa_serial;

        if(ISOK(return_value = zone_file_reader_open(file_name, &zr)))
        {
            resource_record rr;
            zone_file_reader_set_origin(&zr, zone_desc_origin);
            
            zr_opened = TRUE;
            
            resource_record_init(&rr);

            if(ISOK(return_value = zone_reader_read_record(&zr, &rr)))
            {
                if(dnsname_equals(zone_desc_origin, rr.name))
                {
                    if(rr.type == TYPE_SOA)
                    {
                        return_value = rr_soa_get_serial(zone_reader_rdata(rr),
                                                zone_reader_rdata_size(rr),
                                                &zone_file_soa_serial);
                        
                        zone_reader_unread_record(&zr, &rr); // no need to open the file/stream again
                    }
                    else
                    {
                        return_value = ZDB_READER_FIRST_RECORD_NOT_SOA;
                    }
                }
                else
                {
                    return_value = ZDB_READER_ANOTHER_DOMAIN_WAS_EXPECTED;
                }
                
                resource_record_freecontent(&rr);   /// @todo get rid of the os_rdata
            }
        }
        
        if(FAIL(return_value)) // if return_value is NOT an error, zone_file_soa_serial is set
        {
            if(zr_opened)
            {
                zone_reader_close(&zr);
            }
            
            log_err("zone load: cannot read master zone file '%s': %r", file_name, return_value);

            return return_value;
        }
        
        // at this point zr HAS been opened
        
        // from here, zone_file_soa_serial can only be set
        u32 zone_serial = ~0;

        zdb_zone_lock(*zone, ZDB_ZONE_MUTEX_LOAD);
        
        if(ZDB_ZONE_VALID(*zone))
        {
            return_value = zdb_zone_getserial(*zone, &zone_serial);
                    
            zdb_zone_unlock(*zone, ZDB_ZONE_MUTEX_LOAD);
                    
            if(ISOK(return_value))
            {
                if(serial_ge(zone_serial, zone_file_soa_serial)) /// @note cppcheck false positive on zone_file_soa_serial
                {
                    log_info("zone load: serial of loaded zone %{dnsname} >= serial from file '%s' (%u >= %u): no need to load",
                            zone_desc_origin, file_name, zone_serial, zone_file_soa_serial);

                    zone_reader_close(&zr);
                    
                    return SUCCESS;
                }
            }
            else
            {
                log_err("zone load: unable to retrieve the serial of the loaded zone: %r", return_value);
            }
        }
        else
        {
            zdb_zone_unlock(*zone, ZDB_ZONE_MUTEX_LOAD);
            
            log_debug1("zone load: instance of the zone in the database is invalid: %r", return_value);
        }

        /// @todo invalidate zone if "drop-before-load"

        
        // at this point, the file is about to be loaded.  It is the right time to test the drop-before-load flag
    
        if(is_drop_before_load)
        {
            // the zone is loaded and is valid, we need to drop it
            // so we unmount it (replacing it by the dummy)
            // then we ask for loading it again
            
            zone_lock(zone_desc, ZONE_LOCK_LOAD);
            
            zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_UNMOUNT, NULL, TRUE);
            zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_LOAD, NULL, TRUE);
            
            zone_unlock(zone_desc, ZONE_LOCK_LOAD);
            
            zone_reader_close(&zr);
         
            return SUCCESS;
        }
    }
    else
    {
        if(FAIL(return_value = zone_file_reader_open(file_name, &zr)))
        {
            return return_value;
        }
    }
        
    log_info("zone load: loading '%s'", file_name);    
 
    //
    if(TRUE)
    {
        /// @note edf: DO NOT USE the flag "MOUNT ON LOAD" HERE
        
        zone_file_reader_set_origin(&zr, zone_desc_origin);
        
        return_value = zdb_zone_load(db, &zr, &zone_pointer_out, g_config->xfr_path, zone_desc_origin, ZDB_ZONE_REPLAY_JOURNAL|(zone_desc_dnssec_mode << ZDB_ZONE_DNSSEC_SHIFT));

        zone_reader_close(&zr);

        /* If the zone load failed for any reason but "loaded already" ... */

        if(!(FAIL(return_value) && (return_value != ZDB_READER_ALREADY_LOADED)))
        {
            /*
             * zone_pointer_out must be mounted
             */
            
            zone_lock(zone_desc, ZONE_LOCK_LOAD);

#if ZDB_HAS_ACL_SUPPORT

            /*
             * Setup the ACL filter function & configuration
             */

            zone_pointer_out->extension = &zone_desc->ac; /* The extension points to the ACL */
            zone_pointer_out->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);
#endif

#if HAS_RRSIG_MANAGEMENT_SUPPORT && HAS_DNSSEC_SUPPORT

            /*
             * Setup the validity period and the jitter
             */

            zone_pointer_out->sig_validity_regeneration_seconds = zone_desc->signature.sig_validity_regeneration * SIGNATURE_VALIDITY_REGENERATION_S;
            zone_pointer_out->sig_validity_interval_seconds = zone_desc->signature.sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S;
            zone_pointer_out->sig_validity_jitter_seconds = zone_desc->signature.sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S;
#endif
            u32 now = time(NULL);

            zone_desc->refresh.refreshed_time = now;
            zone_desc->refresh.retried_time = now;
            
            // switch back with the invalid (schedule that ST)
            
            log_info("zone load: '%s' loaded", zone_desc->domain);
            
            zone_unlock(zone_desc, ZONE_LOCK_LOAD);
            
            *zone = zone_pointer_out;
           
            //database_replace_zone(g_config->database, zone_desc, zone_pointer_out);
            
            
            return_value = SUCCESS;
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
    
    return return_value;
}

#endif

static ya_result
database_get_ixfr_answer_type(const u8 *zone_desc_origin, const host_address *zone_desc_masters, u32 ttl, u16 soa_rdata_size, const u8* soa_rdata)
{
   /*
    * Start an IXFR query
    */

    input_stream is;
    output_stream os;
    
    ya_result return_value;
    
    message_data ixfr_query;

#ifdef DEBUG
    memset(&ixfr_query,0x5a,sizeof(ixfr_query));
#endif

    log_debug("zone load: incremental change query to the master of %{dnsname}", zone_desc_origin);
    
    //u16 answer_type[2];
    u32 answer_serial[2];
    u32 answer_idx = 0;
    u32 current_serial;
    
#ifdef DEBUG
    //memset(answer_type,0x5a,sizeof(answer_type));
    memset(answer_serial,0x5a,sizeof(answer_serial));
    memset(&current_serial,0x5a,sizeof(current_serial));
#endif
    
    if(FAIL(return_value = rr_soa_get_serial(soa_rdata, soa_rdata_size, &current_serial)))
    {
        return return_value;
    }
    
    if(ISOK(return_value = ixfr_start_query(zone_desc_masters, zone_desc_origin, ttl, soa_rdata, soa_rdata_size, &is, &os, &ixfr_query)))
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
            if(FAIL(return_value = readfully_limited(fd, &ixfr_query.buffer_tcp_len[0], 2, g_config->tcp_query_min_rate_us)))
            {
                break;
            }
            
            if(return_value != 2)
            {
                return_value = ANSWER_UNEXPECTED_EOF;
                
                break;
            }
            
            if(FAIL(return_value = readfully_limited(fd, &ixfr_query.buffer[0], message_get_tcp_length(&ixfr_query), g_config->tcp_query_min_rate_us)))
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

            packet_reader_init(&reader, &ixfr_query.buffer[0], return_value);
            reader.offset = DNS_HEADER_LENGTH;

            u16 query_count = ntohs(MESSAGE_QD(ixfr_query.buffer));
            
            if(query_count == 1)
            {
                if(FAIL(return_value = packet_reader_read_zone_record(&reader, record_wire, sizeof(record_wire))))
                {
                    break;
                }
            }
            else
            {
                return_value = ANSWER_NOT_ACCEPTABLE;
                //break;
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
                //answer_type[answer_idx] = rtype;

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
                
                // p += rdata_size;
                
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
database_load_zone_slave(zdb *db, zone_desc_s *zone_desc, zdb_zone **zone)
{
#ifdef DEBUG
    log_debug("database_load_zone_slave(%p,%p,%p)", db, zone_desc, zone);
#endif
    
    zone_lock(zone_desc, ZONE_LOCK_LOAD);
    
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

    zone_reader zr;
    zdb_zone *current_zone;
    zdb_zone *zone_pointer_out;
    host_address *zone_desc_masters;
    u32  file_serial;
    u32  axfr_serial;
    //u32  zone_serial;
    ya_result return_value;
    
    u32 current_serial = 0;
    
    u32 ttl = 0;
    u16 rdata_size = 0;
    bool zone_file_available = FALSE;
    bool axfr_file_available = FALSE;
    bool is_drop_before_load;
    bool has_file_name;
    u8 zone_desc_origin[MAX_DOMAIN_LENGTH];
    u8  rdata[MAX_SOA_RDATA_LENGTH];    
    char file_name[PATH_MAX];
    char zone_desc_file_name[PATH_MAX];
    
    is_drop_before_load = zone_is_drop_before_load(zone_desc);
    zone_desc_masters = host_address_copy_list(zone_desc->masters);
    dnsname_copy(zone_desc_origin, zone_desc->origin);
    
    has_file_name = (zone_desc->file_name != NULL);
    
    if(has_file_name)
    {
        strcpy(zone_desc_file_name, zone_desc->file_name);
    }
    
    current_zone = zdb_zone_find_from_dnsname(db, zone_desc_origin, CLASS_IN);
    
    zone_unlock(zone_desc, ZONE_LOCK_LOAD);
    
    if(current_zone != NULL)
    {
        if(!ZDB_ZONE_INVALID(current_zone))
        {
            zdb_zone_lock(current_zone, ZDB_ZONE_MUTEX_LOAD);
            return_value = zdb_zone_getserial(current_zone, &current_serial);
            zdb_zone_unlock(current_zone, ZDB_ZONE_MUTEX_LOAD);
            
            if(FAIL(return_value))
            {
                log_err("zone load: unable to get current serial of '%{dnsname}': %r", zone_desc_origin, return_value);

                current_zone = NULL;
            }
        }
        else
        {
            current_zone = NULL;
        }
    }
    
#ifdef DEBUG
    memset(&zr, 0x5a, sizeof(zr));
    memset(rdata, 0x5a, sizeof(rdata));
    memset(file_name, 0x5a, sizeof(file_name));
#endif
    
    /*
     * FILE
     */
    
    log_debug("zone load: loading slave '%{dnsname}'", zone_desc_origin);

    if(has_file_name && (zone_desc_file_name != NULL) && (zone_desc_file_name[0] != '\0'))
    {
        snformat(file_name, sizeof(file_name), "%s%s", g_config->data_path, zone_desc_file_name);

        log_debug("zone load: zone file is '%s'", file_name);
        
        if(ISOK(return_value = zone_file_reader_open(file_name, &zr)))
        {
            log_debug("zone load: checking serial in local copy '%s'", file_name);
            
            if(ISOK(return_value = zdb_zone_get_soa(&zr, &rdata_size, rdata)))
            {
                if(ISOK(rr_soa_get_serial(rdata, rdata_size, &file_serial)))
                {
                    zone_file_available = ((current_zone == NULL) || serial_lt(current_serial, file_serial));
                    //zone_serial = file_serial;
                    
                    log_debug("zone load: serial in local copy '%s' is %u", file_name, file_serial);
                    
                    bool template_zone = !zone_reader_canwriteback(&zr);
                    
                    // if template_zone, the file CANNOT be written back to disk
                    
                    if(template_zone)
                    {
                        zone_lock(zone_desc, ZONE_LOCK_LOAD);
                        zone_desc->status_flags |= ZONE_STATUS_TEMPLATE_SOURCE_FILE;
                        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
                    }
                }
            }

            zone_reader_close(&zr);
        }
        else
        {
            if(zone_desc->type != ZT_SLAVE)
            {
                log_err("zone load: could not open zone file '%s': %r", file_name, return_value);
            }
        }
    }

    /*
     * AXFR : the serial returned here does not takes the journal into account if the boolean is set to FALSE
     */

    if(ISOK(return_value = zone_axfr_reader_open_last(g_config->xfr_path, zone_desc_origin, &zr)))
    {
        log_debug("zone load: found an AXFR image for %{dnsname}", zone_desc_origin);
        
        if(ISOK(return_value = zdb_zone_get_soa(&zr, &rdata_size, rdata)))
        {
            if(ISOK(rr_soa_get_serial(rdata, rdata_size, &axfr_serial)))
            {
                axfr_file_available = ((current_zone == NULL) || serial_lt(current_serial, axfr_serial));
                //zone_serial = axfr_serial;
                
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
    
    if(axfr_file_available && zone_file_available)
    {
        /* choose one */
        
        if(serial_gt(axfr_serial, file_serial))
        {
            // serial of AXFR is bigger
            
            log_debug("zone load: using AXFR image");
            
            zone_file_available = FALSE;
            //zone_serial = axfr_serial;
        }
        else
        {
            // serial of file is bigger
            
            log_debug("zone load: using local zone file");
            
            axfr_file_available = FALSE;
            //zone_serial = file_serial;
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

        u32 zone_journal_serial = 0;
        
        if(FAIL(return_value = journal_last_soa(zone_desc_origin, g_config->xfr_path, &zone_journal_serial, &ttl, rdata, &rdata_size)))
        {
            if(return_value == ZDB_ERROR_ICMTL_NOTFOUND)
            {
                log_debug("zone load: no journal");               
                
                return_value = SUCCESS;
            }
        }
        
        if((zone_desc->flags & ZONE_FLAG_NO_MASTER_UPDATES) == 0)
        {
            if(ISOK(return_value))
            {
                log_debug("zone load: poking the master of %{dnsname} with an SOA query", zone_desc_origin);

                u32 master_serial = (zone_journal_serial - 2)|1; /* default to less but avoid 0 */

                if(ISOK(return_value = message_query_serial(zone_desc_origin, zone_desc_masters, &master_serial)))
                {
                    log_debug("zone load: serial of %{dnsname} on the master is %d\n", zone_desc_origin, master_serial);
                }

                if(ISOK(return_value) && (zone_journal_serial != master_serial))
                {
                    return_value = database_get_ixfr_answer_type(zone_desc_origin, zone_desc_masters, ttl, rdata_size, rdata);

                    if((return_value != TYPE_IXFR) && (return_value != SUCCESS))
                    {
                        /* axfr or error */

                        if(return_value != TYPE_AXFR)
                        {                                            
                            log_err("zone load: unexpected answer from the master (will query for a full zone transfer)");
                        }

                        char data_path[PATH_MAX]; 
#ifdef DEBUG
                        memset(data_path, 0x5a, sizeof(data_path));
#endif
                        xfr_copy_get_data_path(data_path, sizeof(data_path), g_config->xfr_path, zone_desc_origin);

                        xfr_delete_axfr(zone_desc_origin, data_path);

                        journal_truncate(zone_desc_origin, g_config->xfr_path);

                        axfr_file_available = zone_file_available = FALSE;
                    }
                }
            }
        }
        
        if(FAIL(return_value))
        {
            log_err("zone load: unable to download %{dnsname} from master: %r", zone_desc_origin, return_value);
        }                
    }
    
    /*
     * Now ask to the master for an IXFR that we will interrupt.
     * After a few retries, load the current zone.
     */

    if(axfr_file_available)
    {
        log_info("zone load: loading %{dnsname} axfr in '%s'", zone_desc_origin, g_config->xfr_path);

        if(FAIL(return_value = zone_axfr_reader_open_last(g_config->xfr_path, zone_desc_origin, &zr)))
        {
            log_err("zone load: unexpectedly unable to load an axfr for %{dnsname}", zone_desc_origin);

            axfr_file_available = FALSE;
        }
        else
        {
            zone_file_available = FALSE;
        }
    }

    if(zone_file_available)
    {
        log_info("zone load: loading %{dnsname} file '%s'", zone_desc_origin, file_name);

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
        // at this point, the file is about to be loaded.  It is the right time to test the drop-before-load flag
    
        if(!((current_zone != NULL) && is_drop_before_load))
        {
            /* Avoid cpy & cat : overrun potential */

            return_value = zdb_zone_load(db, &zr, &zone_pointer_out, g_config->xfr_path, zone_desc_origin, ZDB_ZONE_REPLAY_JOURNAL|ZDB_ZONE_IS_SLAVE);

            zone_reader_handle_error(&zr, return_value);

            zone_reader_close(&zr);
            
            if(axfr_file_available)
            {
                // if we didn't load the zone file ...
                zone_desc->status_flags |= ZONE_STATUS_MODIFIED;
            }

            u32 now = time(NULL);

            zone_lock(zone_desc, ZONE_LOCK_LOAD);
            
            zone_desc->refresh.refreshed_time = now;
            zone_desc->refresh.retried_time = now;

            /* If the zone load failed for any reason but "loaded already" ... */

            if(ISOK(return_value))
            {

#if ZDB_HAS_ACL_SUPPORT

               /*
                * Setup the ACL filter function & configuration
                */

                zone_pointer_out->extension = &zone_desc->ac; /* The extension points to the ACL */
                zone_pointer_out->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);
#endif

#if HAS_DNSSEC_SUPPORT

               /*
                * Setup the validity period and the jitter
                */

                zone_pointer_out->sig_validity_interval_seconds = MAX_S32;/*zone->sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S */;
                zone_pointer_out->sig_validity_jitter_seconds = 0;/*zone->sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S */;
#endif
                *zone = zone_pointer_out;

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
                        log_err("zone load: the zone file or the journal are likely corrupted for zone %{dnsname}: %r", zone_desc_origin, return_value);

                        axfr_file_available = zone_file_available = FALSE;
                        break;
                    }
                    default:
                    {
                        log_err("zone load: an error occurred while loading the zone or journal for %{dnsname}: %r", zone_desc_origin, return_value);

                        axfr_file_available = zone_file_available = FALSE;
                        break;
                    }
                }
            }
            
            zone_unlock(zone_desc, ZONE_LOCK_LOAD);
        }
        else
        {
            // the zone is loaded and is valid, we need to drop it
            // so we unmount it (replacing it by the dummy)
            // then we ask for loading it again
            
            zone_lock(zone_desc, ZONE_LOCK_LOAD);
            zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_UNMOUNT, NULL, TRUE);
            zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_LOAD, NULL, TRUE);
            zone_unlock(zone_desc, ZONE_LOCK_LOAD);
         
            return SUCCESS;
        }
    }
    else if(current_zone != NULL)
    {
        // update some parts
        
        /// ALREADY LOCKED : zone_lock(current_zone, ZONE_LOCK_LOAD);
        
#if ZDB_HAS_ACL_SUPPORT

       /*
        * Setup the ACL filter function & configuration
        */

        zone_lock(zone_desc, ZONE_LOCK_LOAD);
        current_zone->extension = &zone_desc->ac; /* The extension points to the ACL */
        current_zone->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
#endif

#if HAS_DNSSEC_SUPPORT != 0

       /*
        * Setup the validity period and the jitter
        */

        current_zone->sig_validity_interval_seconds = MAX_S32;/*zone->sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S */;
        current_zone->sig_validity_jitter_seconds = 0;/*zone->sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S */;
#endif
        /// ALREADY LOCKED : zone_unlock(current_zone, ZONE_LOCK_LOAD);
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
         * Schedule an AXFR transfer from the master(s)
         */
        
        if((zone_desc->flags & ZONE_FLAG_NO_MASTER_UPDATES) == 0)
        {
            database_zone_axfr_query(zone_desc_origin);
        }
        
        return_value = ZRE_NO_VALID_FILE_FOUND;
    }
    
    return return_value;
}



/**
 * 
 * The thread loads the zone in the background then notifies the service that the zone has been loaded (or failed to load)
 * 
 * @param parms
 * @return 
 */

static void*
database_service_zone_load_thread(void *parms)
{
    database_service_zone_load_parms_s *database_zone_load_parms = (database_service_zone_load_parms_s *)parms;
    
    const u32 must_be_off = ZONE_STATUS_DROP | ZONE_STATUS_DROPPING | \
                            ZONE_STATUS_SAVING_ZONE_FILE | ZONE_STATUS_SAVING_AXFR_FILE   | \
                            ZONE_STATUS_SIGNATURES_UPDATING | ZONE_STATUS_DYNAMIC_UPDATE  | \
                            ZONE_STATUS_DYNAMIC_UPDATING;
    
    zone_desc_s *zone_desc = database_zone_load_parms->zone_desc;
#ifdef DEBUG
    log_debug1("database_service_zone_load_thread(%{dnsname}@%p=%i)", zone_desc->origin, zone_desc, zone_desc->rc);
#endif
    
    yassert(zone_desc != NULL);
    
    if((zone_desc->status_flags & must_be_off) != 0)
    {
        log_err("zone load: conflicting status: %08x instead of 0", (zone_desc->status_flags & must_be_off));
    
        database_zone_load_parms_free(database_zone_load_parms);
        zone_release(zone_desc);
        
        return NULL;
    }
    
    zone_desc->status_flags |= ZONE_STATUS_LOADING;
    
    ya_result return_code = database_zone_load_parms->loader(database_zone_load_parms->db,
                                                             zone_desc,
                                                             &database_zone_load_parms->zone);
    // notify the fact that the zone has been loaded (or not)
    
    zone_lock(zone_desc, ZONE_LOCK_LOAD);
    
    if(ISOK(return_code))
    {
        log_debug7("%{dnsname}@%p: loaded_zone@%p (was %p)",
                zone_desc->origin,
                zone_desc,
                database_zone_load_parms->zone,
                zone_desc->loaded_zone);
        zone_desc->loaded_zone = database_zone_load_parms->zone;
    }
    else
    {
        if(!((return_code == ZRE_NO_VALID_FILE_FOUND) && (zone_desc->type == ZT_SLAVE)))
        {
            log_err("zone load: error loading %{dnsname}: %r", zone_desc->origin, return_code);
        }
        else
        {
            log_notice("zone load: slave zone %{dnsname} requires download from the master", zone_desc->origin);
        }
    }
    
    // database fire zone loaded
    
    database_fire_zone_loaded(zone_desc, database_zone_load_parms->zone, return_code);
    
    zone_desc->status_flags &= ~(ZONE_STATUS_LOAD|ZONE_STATUS_LOADING|ZONE_STATUS_PROCESSING);
    
    zone_unlock(zone_desc, ZONE_LOCK_LOAD);
    
    database_zone_load_parms_free(database_zone_load_parms);
    zone_release(zone_desc);
    
    return NULL;
}

ya_result
database_service_zone_load(zone_desc_s *zone_desc)
{
    if(zone_desc == NULL)
    {
        log_err("database_service_zone_load(NULL)");
        return ERROR;
    }
    
    log_debug1("database_service_zone_load(%{dnsname}@%p=%i)", zone_desc->origin, zone_desc, zone_desc->rc);
    
    log_debug1("database_service_zone_load: locking zone '%{dnsname}' for loading", zone_desc->origin);
    
    if(FAIL(zone_lock(zone_desc, ZONE_LOCK_LOAD)))
    {
        log_err("database_service_zone_load: failed to lock zone settings for '%{dnsname}'", zone_desc->origin);
        return ERROR;
    }
    
    const u8 *origin = zone_desc->origin;
    
    log_info("zone load: %{dnsname}", origin);
                    
    /*
     * Invalidate the zone
     * Empty the current zone if any
     */

    /*
     * If the zone descriptor (config) exists and it can be locked by the loader ...
     */
    
    // locks the descriptor with the loader identity
    
    if(zone_desc->status_flags & (ZONE_STATUS_LOAD|ZONE_STATUS_LOADING))
    {
        // already loading
        
        zone_desc_log(MODULE_MSG_HANDLE, MSG_DEBUG1, zone_desc, "database_service_zone_load");
        
        log_err("database_service_zone_load: '%{dnsname}' already loading", origin);
        
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
                        
        return ERROR;
    }

    zdb *db = g_config->database;

    // wait
    
#if HAS_MASTER_SUPPORT

    if(zone_desc->type == ZT_MASTER)
    {
        /*
         * load master ?
         * => load the file
         * => schedule the xchg with the invalidated zone
         */


        
        zone_desc->status_flags &= ~ZONE_STATUS_STARTING_UP;
        zone_desc->status_flags |= ZONE_STATUS_LOAD;
        
        zone_acquire(zone_desc);
        database_service_zone_load_parms_s *database_zone_load_parms = database_zone_load_parms_alloc(db, zone_desc, database_load_zone_master);
        database_service_zone_load_queue_thread(database_service_zone_load_thread, database_zone_load_parms, NULL, "database_zone_load_thread");
    }
    else
#endif  
    if(zone_desc->type == ZT_SLAVE)
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
        
        zone_desc->status_flags &= ~ZONE_STATUS_STARTING_UP;
        zone_desc->status_flags |= ZONE_STATUS_LOAD;
        
        zone_acquire(zone_desc);
        database_service_zone_load_parms_s *database_zone_load_parms = database_zone_load_parms_alloc(db, zone_desc, database_load_zone_slave);
        database_service_zone_load_queue_thread(database_service_zone_load_thread, database_zone_load_parms, NULL, "database_zone_load_thread");
    }
    else /* not master nor slave */
    {
        /* other types */

        log_err("zone load: unknown zone type");
        
        zone_desc->status_flags &= ~(ZONE_STATUS_LOAD|ZONE_STATUS_LOADING|ZONE_STATUS_PROCESSING);
    }
    
    log_debug1("database_service_zone_load: unlocking zone '%{dnsname}' for loading", origin);
    
    zone_unlock(zone_desc, ZONE_LOCK_LOAD);
    
    return SUCCESS;
}

/**
 * @}
 */

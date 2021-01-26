/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
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

#define ZDB_JOURNAL_CODE 1

#include "server-config.h"

#include <dnscore/logger.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/tcp_io_stream.h>
#include <dnscore/fdtools.h>
#include <dnscore/packet_reader.h>
#include <dnscore/zone_reader_text.h>
#include <dnscore/zone_reader_axfr.h>

#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_utils.h>

#include <dnsdb/zdb_zone_load.h>

#include <dnsdb/zdb_record.h>
#include <dnsdb/zdb_zone_write.h>
#include <dnsdb/journal.h>
#include <dnsdb/xfr_copy.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/zdb-zone-maintenance.h>
#include <dnsdb/zdb-zone-path-provider.h>

#if ZDB_HAS_DNSSEC_SUPPORT
#include <dnsdb/dnssec.h>
#endif


#include "database-service.h"
#include "ixfr.h"
#include "zone-source.h"
#include "notify.h"

#include <dnsdb/zdb_zone_label_iterator.h>

#if HAS_CTRL
#include "ctrl.h"
#endif

#define MODULE_MSG_HANDLE g_server_logger

#define DBLOADQ_TAG 0x5144414f4c4244

/**********************************************************************************************************************/

#define DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS 0
#if DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS
#pragma message("WARNING: DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS enabled !")
#endif

typedef ya_result database_zone_load_loader(zdb *db, zone_desc_s *zone_desc, struct zdb_zone_load_parms *zone_load_parms);

#define DSZLDPRM_TAG 0x4d5250444c5a5344

struct database_service_zone_load_parms_s
{
        zdb *db;
        zone_desc_s *zone_desc;
        database_zone_load_loader *loader;
        bool start_maintenance_asap;
};

typedef struct database_service_zone_load_parms_s database_service_zone_load_parms_s;

static database_service_zone_load_parms_s*
database_zone_load_parms_alloc(zdb *db, zone_desc_s *zone_desc, database_zone_load_loader *loader)
{
    database_service_zone_load_parms_s *parm;
    
    ZALLOC_OBJECT_OR_DIE( parm, database_service_zone_load_parms_s, DSZLDPRM_TAG);
    parm->db = db;
    parm->zone_desc = zone_desc;
    parm->loader = loader;
    
    return parm;
}

void
database_zone_load_parms_free(database_service_zone_load_parms_s *parm)
{
#if DEBUG
    memset(parm, 0xff, sizeof(database_service_zone_load_parms_s));
#endif
    ZFREE_OBJECT(parm);
}

#if HAS_MASTER_SUPPORT

/**
 * Loads a MASTER zone file from disc into memory.
 * Returns a pointer to the zone structure.
 * The zone still has to be "mounted" in the database
 * 
 * @param db            a pointer to the database
 * @param zone_desc     the zone configuration
 * @param zone_load_parms pointer to a uninitialised struct zdb_zone_load_parms
 * @return 
 */

static ya_result
database_load_zone_master(zdb *db, zone_desc_s *zone_desc, struct zdb_zone_load_parms *zone_load_parms) // returns with RC++
{
#if DEBUG
    log_debug("database_load_zone_master(%p,%p,%p)", db, zone_desc, zone_load_parms);
#endif
    
    if(dnscore_shuttingdown())
    {
        log_debug("zone load: master zone load cancelled by shutdown");
        zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_PROCESSED, NULL, TRUE);
        return STOPPED_BY_APPLICATION_SHUTDOWN;
    }
    
    s64 zone_load_begin = timeus();
    
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
    
    if(zone_load_parms == NULL)
    {
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
        
        log_err("zone load: invalid use");
        
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    zone_reader zr;
    zdb_zone *zone_pointer_out;
    ya_result return_value;
    u32 zone_file_soa_serial;
#if ZDB_HAS_DNSSEC_SUPPORT
    u32 zone_desc_dnssec_mode;
#endif
    bool is_drop_before_load;
    bool zr_opened = FALSE;
    bool zone_file_soa_serial_set = FALSE;
    bool rrsig_push_allowed = FALSE;
    u8 zone_desc_origin[MAX_DOMAIN_LENGTH];
    char file_name[PATH_MAX];
    char zone_desc_file_name[PATH_MAX];
    
#if ZDB_HAS_DNSSEC_SUPPORT
    zone_desc_dnssec_mode = zone_desc->dnssec_mode << ZDB_ZONE_DNSSEC_SHIFT;
#endif
    is_drop_before_load = zone_is_drop_before_load(zone_desc);
    
    rrsig_push_allowed = zone_rrsig_nsupdate_allowed(zone_desc);
    
    dnsname_copy(zone_desc_origin, zone_origin(zone_desc));
    strcpy_ex(zone_desc_file_name, zone_desc->file_name, sizeof(zone_desc_file_name));
    
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

    if(zone_desc->file_name[0] != '/')
    {
        snformat(file_name, sizeof(file_name), "%s%s", g_config->data_path, zone_desc->file_name);
    }
    else
    {
        strcpy_ex(file_name, zone_desc->file_name, sizeof(file_name));
    }
    
    // get the serial number from the file to avoid useless work
    
    zdb_zone *zone = zdb_acquire_zone_read_from_fqdn(db, zone_desc_origin); // ACQUIRES

    if(zone != NULL)
    {
        if(!zdb_zone_isinvalid(zone))
        {
            log_debug("zone load: preparing to load '%s'", file_name);

            // first, get the serial of the zone file
            
            if(ISOK(return_value = zone_reader_text_open(file_name, &zr)))
            {
                resource_record rr;
                zone_reader_text_set_origin(&zr, zone_desc_origin);

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
                            
                            if(ISOK(return_value))
                            {
                                zone_file_soa_serial_set = TRUE;
                                log_debug("zone load: '%s' serial from file is %u", zone_domain(zone_desc), zone_file_soa_serial);
                            }

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

                    resource_record_freecontent(&rr);
                }
            }

            if(FAIL(return_value)) // if return_value is NOT an error, zone_file_soa_serial is set
            {
                zdb_zone_release(zone);    // undo zdb_acquire_zone_read_from_fqdn
                zone = NULL;

                if(zr_opened)
                {
                    zone_reader_close(&zr);
                }

                s64 zone_load_end = timeus();
                double load_time = zone_load_end - zone_load_begin;
                load_time /= ONE_SECOND_US_F;
                log_err("zone load: cannot read master zone file '%s': %r (%9.6fs)", file_name, return_value, load_time);

                return return_value;
            }
            
            // at this point the zone reader is opened and zone_file_soa_serial is set

            // from here, zone_file_soa_serial can only be set
            u32 zone_serial = ~0;

            zdb_zone_lock(zone, ZDB_ZONE_MUTEX_LOAD);

            if(!zdb_zone_isinvalid(zone))
            {
                return_value = zdb_zone_getserial(zone, &zone_serial); // zone is locked

                zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_LOAD);

                if(ISOK(return_value))
                {
                    if(serial_ge(zone_serial, zone_file_soa_serial)) /// @note cppcheck false positive on zone_file_soa_serial
                    {
                        zone_reader_close(&zr);

                        s64 zone_load_end = timeus();
                        double load_time = zone_load_end - zone_load_begin;
                        load_time /= ONE_SECOND_US_F;
                        log_debug("zone load: %{dnsname}: db serial >= file serial '%s' (%u >= %u): no need to load (%9.6fs)",
                                zone_desc_origin, file_name, zone_serial, zone_file_soa_serial, load_time);

                        zdb_zone_load_parms_init(zone_load_parms, NULL, zone_origin(zone_desc), 0);
                        zone_load_parms->out_zone = zone;

                        return SUCCESS; // zone is not NULL
                    }
                }
                else
                {
                    log_err("zone load: unable to retrieve the serial of the loaded zone: %r", return_value);
                }

                zdb_zone_release(zone);
                zone = NULL;
            }
            else
            {
                zdb_zone_release_unlock(zone, ZDB_ZONE_MUTEX_LOAD);

                log_debug1("zone load: instance of the zone in the database is invalid: %r", return_value);
            }

            zone = NULL;

            // from this point zone cannot be read

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

                s64 zone_load_end = timeus();
                double load_time = zone_load_end - zone_load_begin;
                load_time /= ONE_SECOND_US_F;
                log_info("zone load: '%s' load requires the zone to be dropped first (%9.6fs)", zone_domain(zone_desc), load_time);

                zdb_zone_load_parms_init(zone_load_parms, NULL, zone_origin(zone_desc), 0);

                return ZDB_READER_ALREADY_LOADED;
            }
        }
        else // zone in db is the invalid placeholder, simply open the file
        {
            log_debug1("zone load: '%s' zone@%p in the database is a placeholder", zone_domain(zone_desc), zone);
            zdb_zone_release(zone);

            zone = NULL;

            if(FAIL(return_value = zone_reader_text_open(file_name, &zr)))
            {
                s64 zone_load_end = timeus();
                double load_time = zone_load_end - zone_load_begin;
                load_time /= ONE_SECOND_US_F;
                log_err("zone load: '%s' could not open file '%s': %r (%9.6fs)", zone_domain(zone_desc), file_name, return_value, load_time);

                return return_value;
            }
        }
    }
    else
    {
        // *zone == NULL, simply open the file
        
        if(FAIL(return_value = zone_reader_text_open(file_name, &zr)))
        {
            s64 zone_load_end = timeus();
            double load_time = zone_load_end - zone_load_begin;
            load_time /= ONE_SECOND_US_F;
            log_err("zone load: '%s' could not open file '%s': %r (%9.6fs)", zone_domain(zone_desc), file_name, return_value, load_time);
        
            return return_value;
        }
    }
        
    log_info("zone load: loading '%s'", file_name);    
 
    /// @note  edf : DO NOT USE the flag "MOUNT ON LOAD" HERE

    zone_reader_text_set_origin(&zr, zone_desc_origin);

    // the journal MUST be closed, else we way have a situation where
    // the journal is linked to another instance of the zone
    
#if ZDB_ZONE_HAS_JNL_REFERENCE
    if(zone_desc->loaded_zone != NULL)
    {
        if(zone_desc->loaded_zone->journal != NULL)
        {
            journal_close(zone_desc->loaded_zone->journal);
        }
    }
#endif
    
    u16 zone_load_flags = ZDB_ZONE_REPLAY_JOURNAL;
    
#if ZDB_HAS_DNSSEC_SUPPORT
    if(zone_maintains_dnssec(zone_desc))
    {
        zone_load_flags |= zone_desc_dnssec_mode;
    }
    else
    {
        zone_load_flags |= ZDB_ZONE_NO_MAINTENANCE;
    }
#endif

    zdb_zone_load_parms_init(zone_load_parms, &zr, zone_desc_origin, zone_load_flags);
    return_value = zdb_zone_load_ex(zone_load_parms);
    zone_reader_close(&zr);

    if(ISOK(return_value))
    {
    }
    else
    {
        zone_pointer_out = NULL;
    }

    if(ISOK(return_value))
    {
        zone_pointer_out = zdb_zone_load_parms_zone_get(zone_load_parms);

        zdb_zone_set_rrsig_push_allowed(zone_pointer_out, rrsig_push_allowed);

        if(rrsig_push_allowed)
        {
            log_info("zone load: '%s' allows RRSIG pushing", zone_domain(zone_desc));
        }
        
#if ZDB_HAS_DNSSEC_SUPPORT
        u32 real_dnssec_mode;

        if(zdb_zone_has_nsec3_optout_chain(zone_pointer_out))
        {
            real_dnssec_mode = ZDB_ZONE_NSEC3_OPTOUT;
        }
        else if(zdb_zone_has_nsec3_chain(zone_pointer_out))
        {
            real_dnssec_mode = ZDB_ZONE_NSEC3;
        }
        else if(zdb_zone_has_nsec_chain(zone_pointer_out))
        {
            real_dnssec_mode = ZDB_ZONE_NSEC;
        }
        else
        {
            real_dnssec_mode = ZDB_ZONE_NOSEC;
        }

        if(real_dnssec_mode != zone_desc_dnssec_mode)
        {
            log_debug("zone load: dnssec mode set to %i", real_dnssec_mode);
            zone_load_flags &= ~zone_desc_dnssec_mode;
            zone_desc_dnssec_mode = real_dnssec_mode;
            zone_load_flags |= zone_desc_dnssec_mode;            
        }
#endif
        if(!zone_file_soa_serial_set)
        {
            // zone is locked (technically needlessly) else integrity checks would abort
            zdb_zone_lock(zone_pointer_out, ZDB_ZONE_MUTEX_LOAD);
            return_value = zdb_zone_getserial(zone_pointer_out, &zone_file_soa_serial); // zone is locked
            zdb_zone_unlock(zone_pointer_out, ZDB_ZONE_MUTEX_LOAD);
                    
            if(ISOK(return_value))
            {
                //log_err("zone load: could not get the zone serial from the loaded zone '%s': %r", zone_domain(zone_desc), return_value);
                log_debug("zone load: '%s' serial from file is %u", zone_domain(zone_desc), zone_file_soa_serial);
            }
            else
            {
                log_err("zone load: could not get the zone serial from the loaded zone '%s': %r", zone_domain(zone_desc), return_value);
                zone_file_soa_serial = 0;
            }
        }
        /*
         * zone_pointer_out must be mounted
         */

        zone_lock(zone_desc, ZONE_LOCK_LOAD);

        zone_desc->stored_serial = zone_file_soa_serial;

#if ZDB_HAS_ACL_SUPPORT

        /*
         * Setup the ACL filter function & configuration
         */

        zone_pointer_out->acl = &zone_desc->ac; /* The extension points to the ACL */
        zone_pointer_out->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);

#endif

#if ZDB_HAS_DNSSEC_SUPPORT
#if HAS_RRSIG_MANAGEMENT_SUPPORT
        if((zone_load_flags & ZDB_ZONE_DNSSEC_MASK) != ZDB_ZONE_NOSEC)
        {
            /*
             * Setup the validity period and the jitter
             */
            zone_pointer_out->sig_validity_regeneration_seconds = zone_desc->signature.sig_validity_regeneration * SIGNATURE_VALIDITY_REGENERATION_S;
            zone_pointer_out->sig_validity_interval_seconds = zone_desc->signature.sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S;
            zone_pointer_out->sig_validity_jitter_seconds = zone_desc->signature.sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S;

#if DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS
            zone_pointer_out->sig_validity_regeneration_seconds = 90;
            zone_pointer_out->sig_validity_interval_seconds = 180;
            zone_pointer_out->sig_validity_jitter_seconds = 5;
#endif
            static const u8 dnssec_flag_to_maintain_mode[4] = {0, ZDB_ZONE_MAINTAIN_NSEC, ZDB_ZONE_MAINTAIN_NSEC3, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT};
            
            u8 maintain_mode = 0;

            if(zone_maintains_dnssec(zone_desc))
            {
                if(zone_desc->dnssec_mode != ZONE_DNSSEC_FL_NOSEC)
                {
                    maintain_mode = dnssec_flag_to_maintain_mode[zone_desc->dnssec_mode];
                }
                else
                {
                    if(zdb_zone_has_nsec_chain(zone_pointer_out))
                    {
                        maintain_mode = ZDB_ZONE_MAINTAIN_NSEC;
                    }
                    else if(zdb_zone_has_nsec3_optout_chain(zone_pointer_out))
                    {
                        maintain_mode = ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT;
                    }
                    else if(zdb_zone_has_nsec3_chain(zone_pointer_out))
                    {
                        maintain_mode = ZDB_ZONE_MAINTAIN_NSEC3;
                    }
                }
                zone_set_maintain_mode(zone_pointer_out, maintain_mode);
                zdb_zone_set_maintained(zone_pointer_out, TRUE);

                if(maintain_mode != 0)
                {
                    if(zone_pointer_out->progressive_signature_update.earliest_signature_expiration < MAX_S32)
                    {
                        database_zone_update_signatures(zone_pointer_out->origin, zone_desc, zone_pointer_out);
                    }
                }
            }
            
            // all keys for the zone have already been loaded into the keystore
            // at this point, these keys have to be compared to the ones in the zone file
            zdb_zone_double_lock(zone_pointer_out, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
            // SMART SIGNING
            zdb_zone_update_keystore_keys_from_zone(zone_pointer_out, ZDB_ZONE_MUTEX_DYNUPDATE);

            zdb_zone_double_unlock(zone_pointer_out, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);

            if(zdb_sanitize_is_good(zone_load_parms, real_dnssec_mode))
            {
                // there is no need to do a maintenance
                log_info("zone load: %{dnsname}: maintenance not required", zone_origin(zone_desc));
            }
            else
            {
                log_info("zone load: %{dnsname}: maintenance may be required", zone_origin(zone_desc));

                zdb_zone_set_flags(zone_pointer_out, ZDB_ZONE_MAINTENANCE_ON_MOUNT);
            }

            if(zone_load_parms->state & ZDB_ZONE_LOAD_STATE_SANITIZE_SUMMARY_NSEC3_CHAIN_FIXED)
            {
                zdb_zone_set_store_clear_journal_after_mount(zone_pointer_out);
            }

            u32 now = time(NULL);

            zone_desc->refresh.refreshed_time = now;
            zone_desc->refresh.retried_time = now;

            // switch back with the invalid (schedule that ST)

            s64 zone_load_end = timeus();
            double load_time = zone_load_end - zone_load_begin;
            load_time /= ONE_SECOND_US_F;

            log_info("zone load: '%s' loaded (%9.6fs)", zone_domain(zone_desc), load_time);

            zone_unlock(zone_desc, ZONE_LOCK_LOAD);

            return_value = SUCCESS;
        }
        else // not a DNSSEC zone
        {
            zone_pointer_out->sig_validity_regeneration_seconds = zone_desc->signature.sig_validity_regeneration * SIGNATURE_VALIDITY_REGENERATION_S;
            zone_pointer_out->sig_validity_interval_seconds = zone_desc->signature.sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S;
            zone_pointer_out->sig_validity_jitter_seconds = zone_desc->signature.sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S;
            zone_unlock(zone_desc, ZONE_LOCK_LOAD);
            return_value = SUCCESS;
        }
#else // !HAS_RRSIG_MANAGEMENT_SUPPORT
	#pragma message("EDF: zone_pointer_out->sig_validity_regeneration_seconds  should not exist")
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
	return_value = SUCCESS;
#endif // HAS_RRSIG_MANAGEMENT_SUPPORT

#else // ! ZDB_HAS_DNSSEC_SUPPORT
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
	return_value = SUCCESS;
#endif // ZDB_HAS_DNSSEC_SUPPORT
    }
    else
    {
        zone_pointer_out = NULL;

        s64 zone_load_end = timeus();
        double load_time = zone_load_end - zone_load_begin;
        load_time /= ONE_SECOND_US_F;
            
        if(return_value == ZDB_READER_ALREADY_LOADED)
        {
            log_info("zone load: '%s' loaded already (%9.6fs)", zone_domain(zone_desc), load_time);
        }
        else
        {
            if(return_value != STOPPED_BY_APPLICATION_SHUTDOWN)
            {
                log_err("zone load: '%s' not loaded: %r (%9.6fs)", zone_domain(zone_desc), return_value, load_time);
            }
            else
            {
                log_debug("zone load: '%s' load cancelled by shutdown", zone_domain(zone_desc), return_value, load_time);
            }
        }
    }

    if(FAIL(return_value))
    {
        log_info("zone load: '%s' finalizing because of %r", zone_domain(zone_desc), return_value);
        zdb_zone_load_parms_finalize(zone_load_parms);
    }

    return return_value;
}

#endif

ya_result
database_zone_reader_axfr_open_with_fqdn(zone_reader *dst, const u8 *origin)
{
    ya_result ret;
    
    char file_path[PATH_MAX];
    
    if(ISOK(ret = zdb_zone_path_get_provider()(
                origin, 
                file_path, sizeof(file_path) - 6,
                ZDB_ZONE_PATH_PROVIDER_AXFR_FILE|ZDB_ZONE_PATH_PROVIDER_MKDIR)))
    {
        log_debug("opening '%s' for reading", file_path);
        
        ret = zone_reader_axfr_open(dst, file_path);
    }
    
    return ret;
}

static ya_result
database_get_ixfr_answer_type(const u8 *zone_desc_origin, const host_address *zone_desc_masters, u32 ttl, u16 soa_rdata_size, const u8* soa_rdata)
{
   /*
    * Start an IXFR query
    */

    input_stream is;
    output_stream os;
    
    ya_result return_value;

    message_data_with_buffer ixfr_query_buff;
    message_data *ixfr_query = message_data_with_buffer_init(&ixfr_query_buff);

    log_debug("zone load: %{dnsname}: incremental change query to the master", zone_desc_origin);
    
    //u16 answer_type[2];
    u32 answer_serial[2];
    u32 answer_idx = 0;
    u32 current_serial;
    
#if DEBUG
    //memset(answer_type,0x5a,sizeof(answer_type));
    memset(answer_serial,0x5a,sizeof(answer_serial));
    memset(&current_serial,0x5a,sizeof(current_serial));
#endif
    
    if(FAIL(return_value = rr_soa_get_serial(soa_rdata, soa_rdata_size, &current_serial)))
    {
        return return_value;
    }
    
    if(ISOK(return_value = ixfr_start_query(zone_desc_masters, zone_desc_origin, ttl, soa_rdata, soa_rdata_size, &is, &os, ixfr_query)))
    {
        u8 record_wire[1024];
        
        /*
        * Read the answer (first message anyway)
        * Look for the answer type in it.
        */

        u16 query_id = message_get_id(ixfr_query);

        int fd = fd_input_stream_get_filedescriptor(&is);

        tcp_set_recvtimeout(fd, 3, 0);  /* 3 seconds read timeout */

        do // loop that reads TCP messages
        {
            u16 tcp_len;

            // no speed rate limitation from the master !
            if(FAIL(return_value = readfully(fd, &tcp_len, 2)))
            {
                break;
            }
            
            if(return_value != 2)
            {
                if(answer_idx == 0)
                {
                    if(return_value == 0)
                    {
                        return_value = ANSWER_UNEXPECTED_EOF; // the master closed the stream before answering anything
                    }
                    else
                    {
                        log_warn("zone load: %{dnsname}: %{hostaddr}: answered %i bytes when 2 were expected", zone_desc_origin, zone_desc_masters, return_value);
                    }
                }
                else
                {
                    if(return_value > 0)
                    {
                        log_warn("zone load: %{dnsname}: %{hostaddr}: answered %i bytes when either 2 or none were expected", zone_desc_origin, zone_desc_masters, return_value);
                    }
                }
                
                break;
            }

            tcp_len = ntohs(tcp_len);
            
            if(FAIL(return_value = readfully(fd, message_get_buffer(ixfr_query), tcp_len)))
            {
                log_err("zone load: %{dnsname}: %{hostaddr}: failed to read next TCP message (%u bytes): %r", zone_desc_origin, zone_desc_masters, tcp_len, return_value);
                break;
            }
            
            message_set_size(ixfr_query, return_value);

            if(return_value < DNS_HEADER_LENGTH + 1 + 4)
            {
                return_value = ANSWER_NOT_ACCEPTABLE;
                log_err("zone load: %{dnsname}: %{hostaddr}: master answer is too short: %r", zone_desc_origin, zone_desc_masters, return_value);
                break;
            }
            
            /**
             * check the ID, check the error code
             * 
             */

            u16 answer_id = message_get_id(ixfr_query);

            if(query_id != answer_id)
            {
                return_value = ANSWER_NOT_ACCEPTABLE;
                
                log_err("zone load: %{dnsname}: %{hostaddr}: master answer ID does not match query ID (q:%hd != a:%hd)", zone_desc_origin, zone_desc_masters, query_id, answer_id);
                break;
            }
            
            if(message_get_rcode(ixfr_query) != RCODE_NOERROR)
            {
                return_value = MAKE_DNSMSG_ERROR(message_get_rcode(ixfr_query));
                log_err("zone load: %{dnsname}: %{hostaddr}: master answer with error: %r", zone_desc_origin, zone_desc_masters, return_value);
                break;
            }

            u16 answer_count = message_get_answer_count(ixfr_query);

            if(answer_count == 0)
            {
                return_value = ANSWER_NOT_ACCEPTABLE;
                log_err("zone load: %{dnsname}: %{hostaddr}: master gave empty answer: %r", zone_desc_origin, zone_desc_masters, return_value);
                break;
            }
                        
            u8 error_code = message_get_rcode(ixfr_query);
            
            if(error_code != RCODE_OK)
            {
                return_value = MAKE_DNSMSG_ERROR(error_code);
                
                log_err("zone load: %{dnsname}: %{hostaddr}: master answered with error code: %r", zone_desc_origin, zone_desc_masters, return_value);
                
                break;
            }

            /* read the query record */

            packet_unpack_reader_data pr;

            packet_reader_init_from_message_at(&pr, ixfr_query, DNS_HEADER_LENGTH);

            u16 query_count = message_get_query_count(ixfr_query);
            
            if(query_count == 1)
            {
                if(FAIL(return_value = packet_reader_read_zone_record(&pr, record_wire, sizeof(record_wire))))
                {
                    log_err("zone load: %{dnsname}: %{hostaddr}: failed to read next zone record: %r", zone_desc_origin, zone_desc_masters, return_value);
                    
                    break;
                }
            }
            else
            {
                return_value = ANSWER_NOT_ACCEPTABLE;
                //break;
            }

            /* read the next answer */

            for(;(answer_count > 0) && (answer_idx < 2); answer_count--)
            {
                if(FAIL(return_value = packet_reader_read_record(&pr, record_wire, sizeof(record_wire))))
                {
                    log_err("zone load: %{dnsname}: %{hostaddr}: failed to read next record: %r", zone_desc_origin, zone_desc_masters, return_value);
                    
                    break;
                }

                u8 *p = record_wire + dnsname_len(record_wire);
                u16 rtype = GET_U16_AT(*p);

                if(rtype != TYPE_SOA)
                {
                    if(answer_idx == 0) // first record should be an SOA (AXFR or IXFR)
                    {
                        // not an XFR
                        log_err("zone load: %{dnsname}: %{hostaddr}: master did not answer with an XFR (expected SOA, got %{dnstype})",
                                zone_desc_origin, zone_desc_masters, &rtype);
                        return_value = ANSWER_NOT_ACCEPTABLE;
                        break;
                    }
                    
                    if(answer_idx == 1) // second record may be an SOA (IXFR, or a limit case of an AXFR with two SOA)
                    {
                        // not an IXFR (but most likely an AXFR)
                        log_debug("zone load: %{dnsname}: %{hostaddr}: master did not answer with an IXFR (expected SOA, got %{dnstype})",
                                zone_desc_origin, zone_desc_masters, &rtype);
                        return_value = SUCCESS;
                        break;
                    }
                }

                p += 8;
                u16 rdata_size = ntohs(GET_U16_AT(*p));
                p += 2;
                
                u32 serial;
                
                if(FAIL(return_value = rr_soa_get_serial(p, rdata_size, &serial)))
                {
                    log_err("zone load: %{dnsname}: %{hostaddr}: failed to get serial from SOA record: %r", zone_desc_origin, zone_desc_masters, return_value);
                    
                    break;
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
        while((answer_idx < 2) && ISOK(return_value));
        
        input_stream_close(&is);
        output_stream_close(&os);
    }
    
    if(FAIL(return_value))
    {
        log_err("zone load: %{dnsname}: %{hostaddr}: failed to get update from the master: %r", zone_desc_origin, zone_desc_masters, return_value);
        answer_idx = 0;
    }
    
    switch(answer_idx)
    {
        case 0:
        {
            /* no SOA returned */
            
            log_info("zone load: %{dnsname}: %{hostaddr}: query to the master failed: %r", zone_desc_origin, zone_desc_masters, return_value);
            
            break;
        }
        case 1:
        {
            /* one AXFR returned */
            
            if(serial_gt(answer_serial[0], current_serial))
            {
                log_info("zone load: %{dnsname}: %{hostaddr}: master offers full zone transfer with serial %d", zone_desc_origin, zone_desc_masters, answer_serial[0]);
                
                return_value = TYPE_AXFR;
            }
            else
            {
                log_info("zone load: %{dnsname}: %{hostaddr}: master has the same serial %d", zone_desc_origin, zone_desc_masters, answer_serial[0]);
                
                return_value = SUCCESS;
            }
            
            break;
        }
        case 2:
        {
            if(answer_serial[0] == answer_serial[1]) // limit case
            {
                log_info("zone load: %{dnsname}: %{hostaddr}: master offers an empty zone with serial %d", zone_desc_origin, zone_desc_masters, answer_serial[0]);
                
                return_value = TYPE_AXFR;
            }
            else
            {
                log_info("zone load: %{dnsname}: %{hostaddr}: master offers incremental changes from serial %u to serial %d", zone_desc_origin, zone_desc_masters, answer_serial[1], answer_serial[0]);
                
                return_value = TYPE_IXFR;
            }
            
            break;
        }
    }
    
    return return_value;
}

static ya_result
database_load_zone_slave(zdb *db, zone_desc_s *zone_desc, struct zdb_zone_load_parms *zone_load_parms) // returns with RC++
{
#if DEBUG
    log_debug("database_load_zone_slave(%p,%p,%p)", db, zone_desc, zone_load_parms);
#endif
    
    if(dnscore_shuttingdown())
    {
        log_debug("zone load: %{dnsname}: slave zone load cancelled by shutdown", zone_origin(zone_desc));
        zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_PROCESSED, NULL, TRUE);
        return STOPPED_BY_APPLICATION_SHUTDOWN;
    }
    
    zone_lock(zone_desc, ZONE_LOCK_LOAD);
    
    if(zone_desc->type != ZT_SLAVE)
    {
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
        log_debug("zone load: %{dnsname}: zone is not slave", zone_origin(zone_desc));
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
    s64 zone_load_begin = timeus();
    
    zone_source file_source = ZONE_SOURCE_INIT("file");
    zone_source axfr_source = ZONE_SOURCE_INIT("axfr");
    zone_source db_source = ZONE_SOURCE_INIT("db");
    zone_source master_source = ZONE_SOURCE_INIT("master");
    
    //bool journal_available = FALSE;
    bool file_opened = FALSE;
    
    zone_source *best_source = &master_source;
  
    ya_result return_value;
          
    u32 ttl = 0;
    //u16 rdata_size = 0;
    bool is_drop_before_load;
    bool has_file_name;
    
    u8 zone_desc_origin[MAX_DOMAIN_LENGTH];
    //u8  rdata[MAX_SOA_RDATA_LENGTH];    
    char file_name[PATH_MAX];
    char zone_desc_file_name[PATH_MAX];

    zdb_zone_load_parms_init(zone_load_parms, NULL, zone_origin(zone_desc), 0);
    zdb_zone **zone = &zone_load_parms->out_zone;
    *zone = NULL;

    is_drop_before_load = zone_is_drop_before_load(zone_desc);
    zone_desc_masters = host_address_copy_list(zone_desc->masters);
    dnsname_copy(zone_desc_origin, zone_origin(zone_desc));
    
    log_debug("zone load: %{dnsname}: loading slave zone", zone_desc_origin);
    
    has_file_name = (zone_desc->file_name != NULL);
    
    if(has_file_name)
    {
        strcpy_ex(zone_desc_file_name, zone_desc->file_name, sizeof(zone_desc_file_name));
    }
    
    bool force_load = (zone_desc->flags & ZONE_FLAG_DROP_CURRENT_ZONE_ON_LOAD) != 0;
    
    current_zone = zdb_acquire_zone_read_from_fqdn(db, zone_desc_origin); // ACQUIRES

    zone_unlock(zone_desc, ZONE_LOCK_LOAD);
    
    if(!force_load)
    {
        if(current_zone != NULL)
        {
            if(!zdb_zone_invalid(current_zone))
            {
                u32 current_serial;

                zdb_zone_lock(current_zone, ZDB_ZONE_MUTEX_LOAD);
                return_value = zdb_zone_getserial(current_zone, &current_serial); // zone is locked
                zdb_zone_unlock(current_zone, ZDB_ZONE_MUTEX_LOAD);

                if(ISOK(return_value))
                {
                    log_debug("zone load: %{dnsname}: in database with serial %d", zone_desc_origin, current_serial);

                    zone_source_set(&db_source, ZONE_SOURCE_EXISTS|ZONE_SOURCE_LOADED);
                    zone_source_set_serial(&db_source, current_serial);

                    best_source = &db_source;
                }
                else
                {
                    log_err("zone load: %{dnsname}: unable to get current serial: %r", zone_desc_origin, return_value);

                    zdb_zone_release(current_zone);
                    current_zone = NULL;
                }
            }
            else
            {
                log_debug("zone load: %{dnsname}: invalid in database", zone_desc_origin);
                zdb_zone_release(current_zone);
                current_zone = NULL;
            }
        }
    }

#if DEBUG
    memset(&zr, 0x5a, sizeof(zr));
    //memset(rdata, 0x5a, sizeof(rdata));
    memset(file_name, 0x5a, sizeof(file_name));
#endif

    /*
     * FILE
     * This part is supposed to see if there is a RELEVANT text file
     */

    if(has_file_name && (zone_desc_file_name[0] != '\0'))
    {
        snformat(file_name, sizeof(file_name), "%s%s", g_config->data_path, zone_desc_file_name);

        log_debug("zone load: %{dnsname}: zone file is '%s'", zone_desc_origin, file_name);

        if(ISOK(return_value = zone_reader_text_open(file_name, &zr)))
        {
            log_debug("zone load: %{dnsname}: checking serial in '%s'", zone_desc_origin, file_name);

            if(ISOK(return_value = zdb_zone_get_soa(&zr, &file_source.rdata_size, &file_source.rdata[0])))
            {
                if(ISOK(zone_source_update_serial_from_soa(&file_source)))
                {
                    zone_source_set(&file_source, ZONE_SOURCE_EXISTS | ZONE_SOURCE_LOCALE);

                    log_debug("zone load: %{dnsname}: serial in local copy '%s' is %u", zone_desc_origin, file_name, file_source.serial);

                    // if template_zone, the file CANNOT be written back to disk

                    if(!zone_reader_canwriteback(&zr))
                    {
                        zone_source_set(&file_source, ZONE_SOURCE_TEMPLATE);
                    }
                }
                else
                {
                    log_err("zone load: %{dnsname}: could not get the serial of the SOA from '%s': %r", zone_desc_origin, file_name, return_value);
                }
            }
            else
            {
                const char *message = zone_reader_get_last_error_message(&zr);

                if(message == NULL)
                {
                    log_err("zone load: %{dnsname}: could not get SOA from '%s': %r", zone_desc_origin, file_name, return_value);
                }
                else
                {
                    log_err("zone load: %{dnsname}: could not get SOA from '%s': %s: %r", zone_desc_origin, file_name, message, return_value);
                }
            }

            zone_reader_close(&zr);
        }
        else
        {
            if(zone_desc->type != ZT_SLAVE)
            {
                log_err("zone load: %{dnsname}: could not open zone file '%s': %r", zone_desc_origin, file_name, return_value);
            }
            else
            {
                log_debug("zone load: %{dnsname}: could not open zone file '%s': %r", zone_desc_origin, file_name, return_value);
            }
        }
    }
    else
    {
        log_debug("zone load: %{dnsname}: no file name set for zone file", zone_desc_origin);
    }

    /*
     * AXFR : the serial returned here does not takes the journal into account if the boolean is set to FALSE
     * This part is supposed to see if there is a RELEVANT axfr file
     */


    if(ISOK(return_value = database_zone_reader_axfr_open_with_fqdn(&zr, zone_desc_origin)))
    {
        log_debug("zone load: %{dnsname}: found an AXFR image", zone_desc_origin);

        if(ISOK(return_value = zdb_zone_get_soa(&zr, &axfr_source.rdata_size, &axfr_source.rdata[0])))
        {
            if(ISOK(zone_source_update_serial_from_soa(&axfr_source)))
            {
                zone_source_set(&axfr_source, ZONE_SOURCE_EXISTS | ZONE_SOURCE_LOCALE);

                log_debug("zone load: %{dnsname}: serial in AXFR image is %u", zone_desc_origin, axfr_source.serial);
            }
        }
        else
        {
            const char *message = zone_reader_get_last_error_message(&zr);

            if(message == NULL)
            {
                log_err("zone load: %{dnsname}: could not get SOA from AXFR file: %r", zone_desc_origin, return_value);
            }
            else
            {
                log_err("zone load: %{dnsname}: could not get SOA from AXFR file: %s: %r", zone_desc_origin, message, return_value);
            }
        }

        zone_reader_close(&zr);
    }
    else
    {
        log_debug("zone load: %{dnsname}: could not open AXFR file: %r", zone_desc_origin, return_value);
    }

    /*
     * check if both types are relevant
     * 
     * disable the lowest serial or the AXFR one if they are equal
     * 
     */

    if(zone_source_exists(&axfr_source) || zone_source_exists(&file_source))
    {
        /* choose the best one */

        best_source = zone_source_get_best(&axfr_source, &file_source);

        if(!force_load)
        {
            log_debug("zone load: %{dnsname}: so far, best source is %s", zone_desc_origin, best_source->type_name);

            u32 serial_from = 0;
            u32 serial_to = 0;

            ya_result ret;

            if(ISOK(ret = journal_serial_range(zone_desc_origin, &serial_from, &serial_to)))
            {
                log_debug("zone load: %{dnsname}: journal covers serials %u to %u", zone_desc_origin, serial_from, serial_to);

                if(serial_ge(best_source->serial, serial_from))
                {
                    if(serial_lt(best_source->serial, serial_to))
                    {
                        // the best source must be local, let's update the serial to what it should reach using the journal

                        best_source->serial = serial_to;
                    }
                    else
                    {
                        // the journal is useless : delete it
                        
                        journal_truncate(zone_desc_origin);
                    }
                }
                else
                {
                    // the journal is in the future, and useless : delete it and take an axfr
                    journal_truncate(zone_desc_origin);
                }
            }
            else if(ZDB_JOURNAL_SHOULD_NOT_BE_USED(ret))
            {
                log_err("zone load: %{dnsname}: journal wasn't usable", zone_desc_origin, serial_from, serial_to);
            }
        
            // compare the db (the loaded zone) with the best source
            // parameter order is important, if they are equal, the left one is returned

#if DEBUG
            log_info("zone load: %{dnsname}: best external source is %s (%i)", zone_desc_origin, best_source->type_name, best_source->serial);
#endif
            best_source = zone_source_get_best(&db_source, best_source);
#if DEBUG
            log_info("zone load: %{dnsname}: best overall source is %s (%i)", zone_desc_origin, best_source->type_name, best_source->serial);
#endif
        }
        else
        {
#if DEBUG
            log_info("zone load: %{dnsname}: forced load", zone_desc_origin);
#endif
        }
    }
    else
    {
        log_debug("zone load: %{dnsname}: no local source available", zone_desc_origin);

        // note: the best_source is pointing to the master
    }

#if DEBUG
    log_info("zone load: %{dnsname}: source %s: base=%i serial=%i", zone_desc_origin, file_source.type_name, file_source.base_serial, file_source.serial);
    log_info("zone load: %{dnsname}: source %s: base=%i serial=%i", zone_desc_origin, axfr_source.type_name, axfr_source.base_serial, axfr_source.serial);
    log_info("zone load: %{dnsname}: source %s: base=%i serial=%i", zone_desc_origin, db_source.type_name, db_source.base_serial, db_source.serial);
    log_info("zone load: %{dnsname}: source %s: base=%i serial=%i", zone_desc_origin, master_source.type_name, master_source.base_serial, master_source.serial);
#endif

    // Retrieve the serial on the master, if we are allowed to
    
    if(((zone_desc->flags & ZONE_FLAG_NO_MASTER_UPDATES) == 0) && zone_source_has_flags(best_source, ZONE_SOURCE_LOCALE))
    {
        // a fail here would mean something horribly wrong is going on with the journal ...
        
        u32 master_serial;
        
        if(ISOK(return_value = message_query_serial(zone_desc_origin, zone_desc_masters, &master_serial)))
        {
            log_debug("zone load: %{dnsname}: master %{hostaddr} has serial %u", zone_desc_origin, zone_desc_masters, master_serial);
            
            zone_source_set(&master_source, ZONE_SOURCE_EXISTS | ZONE_SOURCE_REMOTE);
            zone_source_set_serial(&master_source, master_serial);
        }
        else
        {
            log_err("zone load: %{dnsname}: unable to get the serial from the master at %{hostaddr}: %r", zone_desc_origin, zone_desc_masters, return_value);
        }

        if(zone_source_compare(best_source, &master_source) >= 0)
        {
            // we can reach locally at least what the master is giving us

            log_debug("zone load: %{dnsname}: no need to download the zone from the master", zone_desc_origin);
        }
        else
        {
            // see how the master would give us the incremental changes

            if(ISOK(return_value = database_get_ixfr_answer_type(zone_desc_origin, zone_desc_masters, ttl, best_source->rdata_size, &best_source->rdata[0])))
            {
                if(return_value == TYPE_AXFR)
                {
                    // the zone we have is a wrong start

                    log_debug("zone load: %{dnsname}: the master answered to the IXFR by an AXFR", zone_desc_origin);

                    zone_source_unset(&axfr_source, ZONE_SOURCE_EXISTS);
                    zone_source_unset(&file_source, ZONE_SOURCE_EXISTS);
                    best_source = &master_source;

                    xfr_delete_axfr(zone_desc_origin);
                    journal_truncate(zone_desc_origin);
                }
                else
                {
#if DEBUG
                    log_info("zone load: %{dnsname}: the master answered with an IXFR", zone_desc_origin, best_source->type_name, best_source->serial);
#endif
                }

                // else we did got an IXFR. Starting by loading the local zone file + journal should be more efficient.
            }
            else
            {
                log_err("zone load: %{dnsname}: IXFR query to %{hostaddr} failed with: %r", zone_desc_origin, zone_desc_masters, return_value);
            }
        }
    }
    
    /*
     * Now ask to the master for an IXFR that we will interrupt.
     * After a few retries, load the current zone.
     */
     
    if(best_source == &axfr_source)
    {
        log_info("zone load: %{dnsname}: loading AXFR file in '%s'", zone_desc_origin, g_config->xfr_path);
        file_opened = TRUE;
        if(FAIL(return_value = database_zone_reader_axfr_open_with_fqdn(&zr, zone_desc_origin)))
        {
            log_err("zone load: %{dnsname}: unexpectedly unable to load AXFR file in '%s'", zone_desc_origin, g_config->xfr_path);
            zone_source_unset(&axfr_source, ZONE_SOURCE_EXISTS);
            file_opened = FALSE;
            
            // cleanup
            
            xfr_delete_axfr(zone_desc_origin);
            journal_truncate(zone_desc_origin);
        }
    }
    else if(best_source == &file_source)
    {
        log_info("zone load: %{dnsname}: loading file '%s'", zone_desc_origin, file_name);
        file_opened = TRUE;
        if(FAIL(return_value = zone_reader_text_open(file_name, &zr)))
        {
            log_err("zone load: %{dnsname}: unexpectedly unable to load '%s'", zone_desc_origin, file_name);
            zone_source_unset(&file_source, ZONE_SOURCE_EXISTS);
            file_opened = FALSE;
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

    if(file_opened)
    {
        // at this point, the file is about to be loaded.  It is the right time to test the drop-before-load flag
        
        if(!((current_zone != NULL) && is_drop_before_load))
        {
            /* Avoid cpy & cat : overrun potential */
            
            // the journal MUST be closed, else we way have a situation where
            // the journal is linked to another instance of the zone

#if ZDB_ZONE_HAS_JNL_REFERENCE
            if(zone_desc->loaded_zone != NULL)
            {
                if(zone_desc->loaded_zone->journal != NULL)
                {
                    journal_close(zone_desc->loaded_zone->journal);
                }
            }
#endif

            return_value = zdb_zone_load(db, &zr, &zone_pointer_out, zone_desc_origin, ZDB_ZONE_REPLAY_JOURNAL|ZDB_ZONE_IS_SLAVE);

            zone_reader_handle_error(&zr, return_value);

            zone_reader_close(&zr);
            
            u32 now = time(NULL);
            
            zone_lock(zone_desc, ZONE_LOCK_LOAD);
            
            // if the source base serial is different from the source serial, then the journal has been played and the zone is "dirty"

            if(zone_source_has_flags(best_source, ZONE_SOURCE_TEMPLATE))
            {
                log_info("zone load: %{dnsname}: source is marked as a template (%s)", zone_desc_origin, best_source->type_name);

                zone_set_status(zone_desc, ZONE_STATUS_TEMPLATE_SOURCE_FILE);
            }
            
            zone_desc->refresh.refreshed_time = now;
            zone_desc->refresh.retried_time = now;

            if(ISOK(return_value))
            {
                if((best_source->base_serial != best_source->serial) || (best_source == &axfr_source))
                {
                    // if we didn't load the zone file, so mark it so a dump will actually dump its content into a text zone file
                    //zone_set_modified(zone_desc); // candidate for removal (probably, although the AXFR case must be handled)

                    zdb_zone_set_status(zone_pointer_out, ZDB_ZONE_STATUS_MODIFIED);
                }

                zone_desc->flags &= ~ZONE_FLAG_DROP_CURRENT_ZONE_ON_LOAD;
                
#if ZDB_HAS_ACL_SUPPORT
               /*
                * Setup the ACL filter function & configuration
                */

                zone_pointer_out->acl = &zone_desc->ac; /* The extension points to the ACL */
                zone_pointer_out->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);
#endif

#if HAS_DNSSEC_SUPPORT
               /*
                * Setup the validity period and the jitter
                */

                zone_pointer_out->sig_validity_interval_seconds = MAX_S32;/*zone->sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S */;
                zone_pointer_out->sig_validity_jitter_seconds = 0;/*zone->sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S */;
#endif
                zone_desc->stored_serial = best_source->base_serial;
                
                *zone = zone_pointer_out;
                zone_unlock(zone_desc, ZONE_LOCK_LOAD);
                host_address_delete_list(zone_desc_masters);
                
                if(current_zone != NULL)
                {
                    zdb_zone_release(current_zone);
                    // current_zone = NULL ...
                }
                
                s64 zone_load_end = timeus();
                double load_time = zone_load_end - zone_load_begin;
                load_time /= ONE_SECOND_US_F;
                log_info("zone load: %{dnsname}: loaded: %r (%9.6fs)", zone_desc_origin, return_value, load_time);

                return return_value;
            }
            else
            {
                switch(return_value)
                {
                    case ZDB_READER_ALREADY_LOADED:
                    {
                        log_warn("zone load: %{dnsname}: failed because it was loaded already", zone_desc_origin);
                        break;
                    }
                    case ZDB_ERROR_ICMTL_NOTFOUND:
                    {
                        log_info("zone load: %{dnsname}: no journal to replay", zone_desc_origin);
                        return_value = SUCCESS;
                        break;
                    }
                    case UNABLE_TO_COMPLETE_FULL_READ:
                    {
                        log_err("zone load: %{dnsname}: the zone file or the journal are likely corrupted: %r", zone_desc_origin, return_value);
                        
                        if(best_source == &file_source)
                        {
                            log_info("zone load: %{dnsname}: deleting local copy of the zone (%s)", zone_desc_origin, file_name);
                            unlink(file_name);
                            log_info("zone load: %{dnsname}: deleting journal", zone_desc_origin);
                            journal_truncate(zone_desc_origin);
                            //file_opened = FALSE;
                        }
                        else if(best_source == &axfr_source)
                        {
                            log_info("zone load: %{dnsname}: deleting local image of the zone", zone_desc_origin);
                            xfr_delete_axfr(zone_desc_origin);
                            log_info("zone load: %{dnsname}: deleting journal", zone_desc_origin);
                            journal_truncate(zone_desc_origin);
                        }
                        
                        best_source = &master_source;
                        break;
                    }
                    default:
                    {
                        if(return_value != STOPPED_BY_APPLICATION_SHUTDOWN)
                        {
                            log_err("zone load: %{dnsname}: an error occurred while loading the zone or journal: %r", zone_desc_origin, return_value);
                        }
                        
                        if(best_source == &file_source)
                        {
                            log_info("zone load: %{dnsname}: deleting local copy of the zone (%s)", zone_desc_origin, file_name);
                            unlink(file_name);
                            log_info("zone load: %{dnsname}: deleting journal", zone_desc_origin);
                            journal_truncate(zone_desc_origin);
                            //file_opened = FALSE;
                        }
                        else if(best_source == &axfr_source)
                        {
                            log_info("zone load: %{dnsname}: deleting local image of the zone", zone_desc_origin);
                            xfr_delete_axfr(zone_desc_origin);
                            log_info("zone load: %{dnsname}: deleting journal", zone_desc_origin);
                            journal_truncate(zone_desc_origin);
                        }
                        
                        best_source = &master_source;
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
            
            zone_reader_close(&zr);
            
            zone_lock(zone_desc, ZONE_LOCK_LOAD);
            zone_set_status(zone_desc, ZONE_STATUS_LOAD_AFTER_DROP);
            zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_UNMOUNT, NULL, TRUE);
            //zone_enqueue_command(zone_desc, DATABASE_SERVICE_ZONE_LOAD, NULL, TRUE);
            zone_unlock(zone_desc, ZONE_LOCK_LOAD);
            
            host_address_delete_list(zone_desc_masters);
            
            if(current_zone != NULL)
            {
                zdb_zone_release(current_zone);
                // current_zone = NULL ...
            }
            
            s64 zone_load_end = timeus();
            double load_time = zone_load_end - zone_load_begin;
            load_time /= ONE_SECOND_US_F;
            log_info("zone load: %{dnsname}: load requires the zone to be dropped first (%9.6fs)", zone_desc_origin, load_time);

            return ZDB_READER_ALREADY_LOADED;
        }
    }
    else if(current_zone != NULL)
    {
        zdb_zone_lock(current_zone, ZDB_ZONE_MUTEX_LOAD);
        
#if ZDB_HAS_ACL_SUPPORT

       /*
        * Setup the ACL filter function & configuration
        */
        
        current_zone->acl = &zone_desc->ac; /* The extension points to the ACL */
        current_zone->query_access_filter = acl_get_query_access_filter(&zone_desc->ac.allow_query);
#endif

#if HAS_DNSSEC_SUPPORT

       /*
        * Setup the validity period and the jitter (slave)
        */

        current_zone->sig_validity_interval_seconds = MAX_S32;/*zone->sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S */;
        current_zone->sig_validity_jitter_seconds = 0;/*zone->sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S */;
#endif
        zdb_zone_unlock(current_zone, ZDB_ZONE_MUTEX_LOAD);
        
        *zone = current_zone;
        
        s64 zone_load_end = timeus();
        double load_time = zone_load_end - zone_load_begin;
        load_time /= ONE_SECOND_US_F;
        log_info("zone load: %{dnsname}: keeping the already loaded zone (%9.6fs)", zone_desc_origin, load_time);
        return_value = SUCCESS;
        current_zone = NULL;        
    }

    if(current_zone != NULL)
    {
        zdb_zone_release(current_zone);
        current_zone = NULL;
    }
    
    if(best_source == &master_source)
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

        s64 zone_load_end = timeus();
        double load_time = zone_load_end - zone_load_begin;
        load_time /= ONE_SECOND_US_F;
        
        if((zone_desc->flags & ZONE_FLAG_NO_MASTER_UPDATES) == 0)
        {
            if(!file_opened)
            {
                log_info("zone load: %{dnsname}: asking for an AXFR from %{hostaddr} (%9.6fs)", zone_desc_origin, zone_desc_masters, load_time);
                database_zone_axfr_query(zone_desc_origin);
            }
            else
            {
                time_t axfr_epoch = time(NULL);
                axfr_epoch += g_config->axfr_retry_delay;
                axfr_epoch += rand() % (g_config->axfr_retry_jitter|1);
                log_info("zone load: %{dnsname}: will ask for an AXFR from %{hostaddr} (%9.6fs) at %T", zone_desc_origin, zone_desc_masters, load_time, axfr_epoch);
                database_zone_axfr_query_at(zone_desc_origin, axfr_epoch);
            }
        }
        else
        {
            log_info("zone load: %{dnsname}: prevented by configuration to ask an AXFR from %{hostaddr} (%9.6fs)", zone_desc_origin, zone_desc_masters, load_time);
        }
        
        return_value = ZRE_NO_VALID_FILE_FOUND;
        
        if(*zone != NULL)
        {
            zdb_zone_release(*zone);
            *zone = NULL;
        }
    }
    else
    {
        s64 zone_load_end = timeus();
        double load_time = zone_load_end - zone_load_begin;
        load_time /= ONE_SECOND_US_F;
        log_info("zone load: %{dnsname}: load done: %r (%9.6fs)", zone_desc_origin, return_value, load_time);
    }
    
    host_address_delete_list(zone_desc_masters);
    
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
                            ZONE_STATUS_DYNAMIC_UPDATING| ZONE_STATUS_LOAD_AFTER_DROP;
    
    zone_desc_s *zone_desc = database_zone_load_parms->zone_desc;
#if DEBUG
    log_debug1("database_service_zone_load_thread(%{dnsname}@%p=%i)", zone_origin(zone_desc), zone_desc, zone_desc->rc);
#endif
    
    yassert(zone_desc != NULL);
    
    zone_lock(zone_desc, ZONE_LOCK_LOAD);
    
    if((zone_get_status(zone_desc) & must_be_off) != 0)
    {
        log_err("zone load: conflicting status: %08x instead of 0", (zone_get_status(zone_desc) & must_be_off));
    
        database_zone_load_parms_free(database_zone_load_parms);
        
        database_fire_zone_processed(zone_desc);
        zone_release(zone_desc);
        return NULL;
    }
    
    zone_set_status(zone_desc, ZONE_STATUS_LOADING);
    
    zone_unlock(zone_desc, ZONE_LOCK_LOAD);
    
    struct zdb_zone_load_parms zone_load_parms;
    memset(&zone_load_parms, 0, sizeof(zone_load_parms));

    ya_result return_code = database_zone_load_parms->loader(database_zone_load_parms->db,
                                                             zone_desc,
                                                             &zone_load_parms); // RC = 1
    // notify the fact that the zone has been loaded (or not)
    
    if(ISOK(return_code))
    {
        zdb_zone *zone = zdb_zone_load_parms_zone_detach(&zone_load_parms);
        yassert(zone != NULL);

        // in the zone settings, replace the one in the loaded field by the new one
                
        zone_lock(zone_desc, ZONE_LOCK_LOAD);
        zdb_zone *old_zone = zone_set_loaded_zone(zone_desc, zone); // RC = 1 ++ (2)
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
        
        if(old_zone == zone)
        {
            log_debug7("%{dnsname}@%p: zone@%p was already loaded",
                    zone_origin(zone_desc),
                    zone_desc,
                    zone);
            return_code = 0;
        }
        else
        {
            log_debug7("%{dnsname}@%p: loaded zone@%p (was %p)",
                    zone_origin(zone_desc),
                    zone_desc,
                    zone,
                    old_zone);
            return_code = 1;
        }
        
        if(old_zone != NULL)
        {
            zdb_zone_release(old_zone);
            old_zone = NULL;
        }

        zone_lock(zone_desc, ZONE_LOCK_LOAD);
        zone_clear_status(zone_desc, ZONE_STATUS_LOAD|ZONE_STATUS_LOADING|ZONE_STATUS_DOWNLOADED|ZONE_STATUS_PROCESSING);
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);
        
        database_fire_zone_loaded(zone_desc, zone, return_code);

        /// @note 20190917 edf -- Patch submitted through github by kolbma
        ///                       This avoids a crash that would happen if the loader would
        ///                       returns a successful code but with a NULL zone.
        ///                       Altough the real issue is in the loader, keeping this safeguard here is worth it.

        if(zone != NULL)
        {
            zdb_zone_release(zone);
        }

        zdb_zone_load_parms_finalize(&zone_load_parms);

#if DEBUG
        zone = NULL;
#endif
    }
    else
    {
        if(!((return_code == ZRE_NO_VALID_FILE_FOUND) && (zone_desc->type == ZT_SLAVE)))
        {
            if(return_code != STOPPED_BY_APPLICATION_SHUTDOWN)
            {
                log_err("zone load: %{dnsname}: error loading: %r", zone_origin(zone_desc), return_code);
            }
            else
            {
                log_debug("zone load: %{dnsname}: loading cancelled by shutdown", zone_origin(zone_desc));
            }
        }
        else
        {
            log_info("zone load: %{dnsname}: slave zone requires download from the master", zone_origin(zone_desc));
        }

#if DEBUG
        if(zone_load_parms.out_zone != NULL)
        {
            log_err("zone load: %{dnsname}: zone_load_parms is not expected to be set when an error is returned", zone_origin(zone_desc));
        }
#endif

        zone_lock(zone_desc, ZONE_LOCK_LOAD);
        zone_clear_status(zone_desc, ZONE_STATUS_LOAD|ZONE_STATUS_LOADING|ZONE_STATUS_DOWNLOADED|ZONE_STATUS_PROCESSING);
        zone_unlock(zone_desc, ZONE_LOCK_LOAD);

        database_fire_zone_loaded(zone_desc, NULL, return_code);

        zdb_zone_load_parms_finalize(&zone_load_parms);
    }

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
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    log_debug1("database_service_zone_load(%{dnsname}@%p=%i)", zone_origin(zone_desc), zone_desc, zone_desc->rc);
    
    log_debug1("database_service_zone_load: locking zone '%{dnsname}' for loading", zone_origin(zone_desc));
    
    if(FAIL(zone_lock(zone_desc, ZONE_LOCK_LOAD)))
    {
        log_err("database_service_zone_load: failed to lock zone settings for '%{dnsname}'", zone_origin(zone_desc));
        return INVALID_STATE_ERROR; // this happens when the zone is on its way out
    }
    
    const u8 *origin = zone_origin(zone_desc);
                        
    /*
     * Invalidate the zone
     * Empty the current zone if any
     */

    /*
     * If the zone descriptor (config) exists and it can be locked by the loader ...
     */
    
    // locks the descriptor with the loader identity
    
    if(zone_get_status(zone_desc) & (ZONE_STATUS_LOAD|ZONE_STATUS_LOADING))
    {
        // already loading
#if DEBUG
        zone_desc_log(MODULE_MSG_HANDLE, MSG_DEBUG1, zone_desc, "database_service_zone_load");
#endif
        
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


        
        zone_set_status(zone_desc, ZONE_STATUS_LOAD);
        zone_clear_status(zone_desc, ZONE_STATUS_STARTING_UP);
        
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
        
        zone_set_status(zone_desc, ZONE_STATUS_LOAD);
        zone_clear_status(zone_desc, ZONE_STATUS_STARTING_UP|ZONE_STATUS_DOWNLOADED);
        
        zone_acquire(zone_desc);
        database_service_zone_load_parms_s *database_zone_load_parms = database_zone_load_parms_alloc(db, zone_desc, database_load_zone_slave);
        database_service_zone_load_queue_thread(database_service_zone_load_thread, database_zone_load_parms, NULL, "database_zone_load_thread");
    }
    else /* not master nor slave */
    {
        /* other types */

        log_err("zone load: unknown zone type");
        
        zone_clear_status(zone_desc, ZONE_STATUS_LOAD|ZONE_STATUS_LOADING|ZONE_STATUS_DOWNLOADED|ZONE_STATUS_PROCESSING);
    }
    
    log_debug1("database_service_zone_load: unlocking zone '%{dnsname}' for loading", origin);
    
    zone_unlock(zone_desc, ZONE_LOCK_LOAD);
    
    return SUCCESS;
}

/**
 * @}
 */

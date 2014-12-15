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
/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/dnsname.h>
#include <dnscore/bytearray_output_stream.h>

#if ZDB_HAS_DNSSEC_SUPPORT != 0
#include <dnscore/dnskey.h>
#endif

#include "dnsdb/journal.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_icmtl.h"
#include "dnsdb/zdb_sanitize.h"
#include "dnsdb/zdb_utils.h"

#include "dnsdb/zdb_zone_write.h"

#include "dnsdb/zdb_zone_label_iterator.h"

#if ZDB_HAS_DNSSEC_SUPPORT != 0
#include "dnsdb/dnssec_keystore.h"
#include "dnsdb/dnssec.h"
#endif

#if ZDB_HAS_NSEC3_SUPPORT != 0
#include "dnsdb/nsec3.h"
#endif

#if ZDB_HAS_NSEC_SUPPORT != 0
#include "dnsdb/nsec.h"
#endif

#include "dnsdb/zdb_zone_load.h"

extern logger_handle *g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

void
resource_record_init(resource_record* entry)
{
#ifdef RR_OS_RDATA
    /* Initialize "os" stream */
    bytearray_output_stream_init(&entry->os_rdata, NULL, 0);
#endif

    entry->next    = NULL;
    entry->ttl     = 0;
    entry->type    = 0;
    entry->class   = 0;

#ifndef RR_OS_RDATA
    entry->rdata_size = 0;
#endif



    entry->name[0] = 0;
    entry->name[1] = 0;
}

void
resource_record_freecontent(resource_record* entry)
{
    yassert(entry != NULL);

#ifdef RR_OS_RDATA
    /* free the record  */
    output_stream_close(&entry->os_rdata);
#endif
}

void
resource_record_resetcontent(resource_record* entry)
{
    yassert(entry != NULL);

    /* Resets the RDATA output stream so we can fill it again */

#ifdef RR_OS_RDATA
    bytearray_output_stream_reset(&entry->os_rdata);
#else
    entry->rdata_size = 0;
#endif
}


/**
 * @brief Load a zone in the database.
 *
 * Load a zone in the database.
 * This is clearly MASTER oriented.
 *
 * @param[in] db a pointer to the database
 * @param[in] zone_data a pointer to an opened zone_reader
 * @param[out] zone_pointer_out will contains a pointer to the loaded zone if the call is successful
 *
 * @return an error code.
 *
 */
ya_result
zdb_zone_load(zdb *db, zone_reader *zone_data, zdb_zone **zone_pointer_out, const char *data_path, const u8 *expected_origin, u16 flags)
{
    u8* rdata;
    size_t rdata_len;
    ya_result return_code;
    resource_record entry;
    u32 soa_min_ttl = 0;
    u32 soa_serial = 0;
#if ZDB_HAS_DNSSEC_SUPPORT != 0    
    u32 has_optout = 0;
    u32 has_optin = 0;
    bool nsec3_keys = FALSE;
    bool nsec_keys = FALSE;
    bool has_nsec3 = FALSE;
    bool has_nsec = FALSE;
    bool has_nsec3param = FALSE;
    bool has_dnskey = FALSE;
    bool has_rrsig = FALSE;
#endif
    bool dynupdate_forbidden = FALSE;
    //bool modified = FALSE;
    
#if ZDB_HAS_NSEC3_SUPPORT != 0
    nsec3_load_context nsec3_context;
#endif
    
    char origin_ascii[MAX_DOMAIN_TEXT_LENGTH + 1];
    
    /*    ------------------------------------------------------------    */

    resource_record_init(&entry);

    if(FAIL(return_code = zone_reader_read_record(zone_data, &entry)))
    {
        resource_record_freecontent(&entry); /* destroys */

        log_err("zone load: loading %{dnsname} failed on first record", expected_origin);

        return return_code;
    }
    
    if(entry.type != TYPE_SOA)
    {
        /* bad */

        resource_record_freecontent(&entry); /* destroys */

        log_err("zone load: first record expected to be an SOA");

        return ZDB_READER_FIRST_RECORD_NOT_SOA;
    }
    
    if(!(dnsname_locase_verify_charspace(entry.name) && dnsname_equals(entry.name, expected_origin)))
    {
        resource_record_freecontent(&entry); /* destroys */

        log_err("zone load: zone is for domain %{dnsname} but %{dnsname} was expected", entry.name, expected_origin);

        return ZDB_READER_ANOTHER_DOMAIN_WAS_EXPECTED;
    }

    /*    ------------------------------------------------------------    */

    dnsname_vector name;
    DEBUG_RESET_dnsname(name);
    u16 zclass = entry.class;

    dnsname_to_dnsname_vector(entry.name, &name);

    /*    ------------------------------------------------------------    */

    /* A Create a non-existing label */
    /* B insert new zone */
    /* C load file into the new zone */

    /* A */

    zdb_zone_label *zone_label = zdb_zone_label_add(db, &name, zclass);

    if(((flags & ZDB_ZONE_MOUNT_ON_LOAD) != 0) && (zone_label->zone != NULL))
    {
        /* Already loaded */

        log_err("zone load: zone %{dnsnamevector} already loaded ", &name);

        resource_record_freecontent(&entry); /** destroys */

        return ZDB_READER_ALREADY_LOADED;
    }
    
    rr_soa_get_minimumttl(zone_reader_rdata(entry), zone_reader_rdata_size(entry), &soa_min_ttl);
    rr_soa_get_serial(zone_reader_rdata(entry), zone_reader_rdata_size(entry), &soa_serial);
    
    dnsname_to_cstr(origin_ascii, entry.name);

    dynupdate_forbidden = FALSE;
    
#if ZDB_HAS_DNSSEC_SUPPORT != 0    
    has_dnskey = FALSE;
    has_nsec3 = FALSE;
    has_nsec = FALSE;
    nsec3_keys = FALSE;
    nsec_keys = FALSE;
    has_nsec3param = FALSE;
    has_optout = 0;
    has_optin = 0;
#endif

    /* B */

    zdb_zone* zone;

    zone = zdb_zone_create(entry.name, zclass);
    
    if(zone == NULL)
    {
        log_err("zone load: unable to load zone %{dnsname} %{dnsclass}", entry.name, &zclass);
        
        return ZDB_ERROR_NOSUCHCLASS;
    }
    
    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_LOAD);
    
    zone->min_ttl = soa_min_ttl;
    zone->axfr_serial = soa_serial - 1; /* ensure that the axfr on disk is not automatically taken in account later */

    dnsname_to_dnsname_vector(zone->origin, &name);
    /*rr_entry_freecontent(&entry);*/

    /* C */

#if ZDB_HAS_NSEC3_SUPPORT != 0
    nsec3_load_init(&nsec3_context, zone);
#endif

    zone->apex->flags |= ZDB_RR_APEX_LABEL_LOADING;

    zdb_packed_ttlrdata* ttlrdata;

    u32 loop_count;

    for(loop_count = 1;; loop_count++)
    {
        /* Add the entry */
        
        if(dnscore_shuttingdown())
        {
            return_code = STOPPED_BY_APPLICATION_SHUTDOWN;
            break;
        }

        dnsname_vector entry_name;

        DEBUG_RESET_dnsname(entry_name);
        dnsname_to_dnsname_vector(entry.name, &entry_name);

        s32 a_i, b_i;

        if((a_i = name.size) > (b_i = entry_name.size))
        {
            // error

            return_code = ZDB_READER_WRONGNAMEFORZONE;

            log_err("zone load: domain name %{dnsnamestack} is too big", &entry_name);

            break;
        }
        
        /* ZONE ENTRY CHECK */

        while(a_i >= 0)
        {
            u8* a = name.labels[a_i--];
            u8* b = entry_name.labels[b_i--];

            if(!dnslabel_equals(a, b))
            {
                log_warn("zone load: bad domain name %{dnsnamestack} for zone %{dnsnamestack}", &entry_name, &name);

                //rr_entry_freecontent(&entry);

                goto zdb_zone_load_loop;
            }
        }

        if(FAIL(return_code))
        {
            break;
        }

        rdata_len = zone_reader_rdata_size(entry);
        rdata = zone_reader_rdata(entry);
        
#if ZDB_HAS_NSEC3_SUPPORT != 0

        /*
         * SPECIAL NSEC3 support !!!
         *
         * If the record is an RRSIG(NSEC3), an NSEC3, or an NSEC3PARAM then
         * it cannot be handled the same way as the others.
         *
         */

        if(entry.type == TYPE_NSEC3PARAM)
        {
            if(FAIL(return_code = nsec3_load_add_nsec3param(&nsec3_context, rdata, rdata_len)))
            {
                break;
            }
            
            ZDB_RECORD_ZALLOC(ttlrdata, /*entry.ttl*/0, rdata_len, rdata);
            zdb_zone_record_add(zone, entry_name.labels, (entry_name.size - name.size) - 1, entry.type, ttlrdata);

            has_nsec3param = TRUE;
        }
        else if(entry.type == TYPE_NSEC3)
        {
            bool rdata_optout = NSEC3_RDATA_IS_OPTOUT(rdata);
            if(rdata_optout)
            {
                has_optout++;
            }
            else
            {
                has_optin++;
            }
            
            if(FAIL(return_code = nsec3_load_add_nsec3(&nsec3_context, entry.name, entry.ttl, rdata, rdata_len)))
            {
                break;
            }
            
            has_nsec3 = TRUE;
        }
        else if(entry.type == TYPE_RRSIG && ((GET_U16_AT(*rdata)) == TYPE_NSEC3)) /** @note : NATIVETYPE */
        {
            if(FAIL(return_code = nsec3_load_add_rrsig(&nsec3_context, entry.name, /*entry.ttl*/soa_min_ttl, rdata, rdata_len)))
            {
                break;
            }
        }
        else
        {
#endif
            /*
             * This is the general case
             * It happen with NSEC3 support if the type is neither NSEC3PARAM, NSEC3 nor RRSIG(NSEC3)
             */
            switch(entry.type)
            {
                case TYPE_DNSKEY:
                {
#if ZDB_HAS_DNSSEC_SUPPORT != 0
                    /*
                     * Check if we have access to the private part of the key
                     */

                    u16 tag = dnskey_getkeytag(rdata, rdata_len);
                    u16 key_flags = ntohs(GET_U16_AT(rdata[0]));
                    u8 algorithm = rdata[3];

                    switch(algorithm)
                    {
                        case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
                        case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
                        case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
                        case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
                        {
                            nsec3_keys = TRUE;
                            break;
                        }
                        case DNSKEY_ALGORITHM_DSASHA1:
                        case DNSKEY_ALGORITHM_RSASHA1:
                        {
                            nsec_keys = TRUE;
                            break;
                        }
                        default:
                        {
                            log_info("zone load: unknown key algorithm for K%{dnsname}+%03d+%05hd", zone->origin, algorithm, tag);
                            break;
                        }
                    }

                    dnssec_key *key = NULL;
                    
                    if((flags & ZDB_ZONE_IS_SLAVE) == 0)
                    {
                        /* @TODO use defines */
                        if(ISOK(return_code = dnssec_key_load_private(algorithm, tag, key_flags, origin_ascii, &key)))
                        {
                            log_info("zone load: loaded private key K%{dnsname}+%03d+%05hd", zone->origin, algorithm, tag);

                            has_dnskey = TRUE;
                        }
                        else
                        {
                            log_warn("zone load: unable to load private key K%{dnsname}+%03d+%05hd: %r", zone->origin, algorithm, tag, return_code);
                        }
                    }

                    if(key == NULL)
                    {
                        /*
                         * Either:
                         * 
                         * _ The private key is not available (error)
                         * _ The private key should not be loaded (slave)
                         * 
                         * Get the public key for signature verifications.
                         */

                        if(ISOK(return_code = dnskey_load_public(rdata, rdata_len, origin_ascii, &key)))
                        {
                            log_info("zone load: loaded public key K%{dnsname}+%03d+%05hd", zone->origin, algorithm, tag);
                            
                            has_dnskey = TRUE;
                        }
                        else
                        {
                            /* the key is wrong */
                            log_warn("zone load: unable to load public key K%{dnsname}+%03d+%05hd: %r", zone->origin, algorithm, tag, return_code);
                        }
                    }
#else
                    /* DNSKEY not supported */
#endif
                    ZDB_RECORD_ZALLOC(ttlrdata, entry.ttl, rdata_len, rdata);
                    zdb_zone_record_add(zone, entry_name.labels, (entry_name.size - name.size) - 1, entry.type, ttlrdata); /* class is implicit */
                    break;
                }
#if ZDB_HAS_NSEC_SUPPORT != 0
                case TYPE_NSEC:
                {
                    has_nsec = TRUE;
                    ZDB_RECORD_ZALLOC(ttlrdata, entry.ttl, rdata_len, rdata);
                    zdb_zone_record_add(zone, entry_name.labels, (entry_name.size - name.size) - 1, entry.type, ttlrdata); /* class is implicit */
                    break;
                }
#endif
                case TYPE_RRSIG:
                {
#if ZDB_HAS_DNSSEC_SUPPORT == 0
                    if(!has_rrsig)
                    {
                        log_warn("zone load: type %{dnstype} is not supported", &entry.type);
                    }
#else
                    has_rrsig = TRUE;
#endif
                    if((GET_U16_AT(*rdata)) == TYPE_NSEC3PARAM) // RRSIG covered type
                    {
                        entry.ttl = 0;
                    }
                    
                    /* falltrough */
                }
                default:
                {
                    ZDB_RECORD_ZALLOC(ttlrdata, entry.ttl, rdata_len, rdata);
                    zdb_zone_record_add(zone, entry_name.labels, (entry_name.size - name.size) - 1, entry.type, ttlrdata); /* class is implicit */
                    break;
                }
#if ZDB_HAS_NSEC3_SUPPORT == 0
                case TYPE_NSEC3PARAM:
                {
                    if(!has_nsec3param)
                    {
                        log_warn("zone load: type %{dnstype} is not supported", &entry.type);
                    }
                    has_nsec3param = TRUE;
                    break;
                }
                case TYPE_NSEC3:
                {
                    if(!has_nsec3)
                    {
                        log_warn("zone load: type %{dnstype} is not supported", &entry.type);
                    }
                    has_nsec3 = TRUE;
                    break;
                }
#endif
#if ZDB_HAS_NSEC_SUPPORT == 0
                case TYPE_NSEC:
                {
                    if(!has_nsec)
                    {
                        log_warn("zone load: type %{dnstype} is not supported", &entry.type);
                    }
                    has_nsec = TRUE;
                    break;
                }
#endif
            }

#if ZDB_HAS_NSEC3_SUPPORT != 0
        }
#endif

zdb_zone_load_loop:

        resource_record_resetcontent(&entry); /* "next" */

        /**
         * Note : Return can be
         *
         * OK:		got a record
         * 1:		end of zone file
         * error code:	failure
         */

        if(OK != (return_code = zone_reader_read_record(zone_data, &entry)))
        {
            if(FAIL(return_code))
            {
                log_err("zone load: reading record #%d of zone %{dnsname}: %r", loop_count, zone->origin, return_code);
            }
            break;
        }

        if(!dnsname_locase_verify_charspace(entry.name))
        {
            /** @todo handle this issue*/
            log_warn("zone load: DNS character space error on '%{dnsname}'", entry.name);
        }
    }

    resource_record_freecontent(&entry); /* destroys, not "next" */

#if ZDB_HAS_DNSSEC_SUPPORT != 0
    log_debug7("zone load: has_rrsig=%i has_dnskey=%i", has_rrsig, has_dnskey);
#endif
    
    zone->apex->flags &= ~ZDB_RR_APEX_LABEL_LOADING;

    if(dynupdate_forbidden)
    {
        log_info("zone load: freezing zone %{dnsname}", zone->origin);
        
        zone->apex->flags |= ZDB_RR_APEX_LABEL_FROZEN;
    }

    if(ISOK(return_code))
    {
        log_info("zone load: sanity check for %{dnsname}", zone->origin);

        if(FAIL(return_code = zdb_sanitize_zone(zone)))
        {
            log_err("zone load: impossible to sanitise %{dnsname}, dropping zone", zone->origin);
        }
        else
        {
            log_info("zone load: sanity check for %{dnsname} done", zone->origin);
        }
    }

#if ZDB_HAS_DNSSEC_SUPPORT != 0

    if(ISOK(return_code))
    {
        if(has_nsec3 & !has_nsec3param)
        {
            log_err("zone load: zone %{dnsname} has NSEC3 but no NSEC3PARAM", zone->origin);
            
            return_code = ZDB_READER_NSEC3WITHOUTNSEC3PARAM;
        }
        
        if(has_nsec3param & !has_nsec3)
        {
            log_warn("zone load: zone %{dnsname} has NSEC3PARAM but no NSEC3", zone->origin);
            
            /* force it for generation */
            
            if((flags & ZDB_ZONE_IS_SLAVE) == 0)
            {
                has_nsec3 = true;
            }
            else
            {
                log_err("zone load: slave zone %{dnsname} has NSEC3PARAM but no NSEC3", zone->origin);
                
                return_code = ZDB_READER_NSEC3PARAMWITHOUTNSEC3;
            }
        }
        
        if(has_nsec && has_nsec3)
        {
            log_err("zone load: zone %{dnsname} has both NSEC and NSEC3 records !", zone->origin);
            
            return_code = ZDB_READER_MIXED_DNSSEC_VERSIONS;
            
            /**
             * 
             * @todo DROP NSEC (?)
             * 
             */
            
        }
        if((flags & ZDB_ZONE_IS_SLAVE) == 0)
        {
            if(has_nsec3 && !nsec3_keys)
            {
                log_err("zone load: zone %{dnsname} is NSEC3 but there are no NSEC3 keys available", zone->origin);

            }
            if(has_nsec && !nsec_keys)
            {
                log_err("zone load: zone %{dnsname} is NSEC but there are no NSEC keys available", zone->origin);
            }
        }
    }

    if(ISOK(return_code))
    {
        if(!(has_nsec || has_nsec3))
        {
            switch(flags & ZDB_ZONE_DNSSEC_MASK)
            {
                case ZDB_ZONE_NSEC:
                {
                    log_warn("zone load: zone is configured as NSEC but no NSEC records have been found");
                    if((flags & ZDB_ZONE_IS_SLAVE) == 0)
                    {
                        has_nsec = TRUE;
                    }
                    break;
                }
                case ZDB_ZONE_NSEC3:
                case ZDB_ZONE_NSEC3_OPTOUT:
                {
                    log_warn("zone load: zone is configured as NSEC3 but no NSEC3 records have been found");
                    if((flags & ZDB_ZONE_IS_SLAVE) == 0)
                    {
                        has_nsec3 = TRUE;
                    }
                    break;
                }
                default:
                {
                    break;
                }
            }
        }
        
        if(has_nsec3)
        {

#if ZDB_HAS_NSEC3_SUPPORT != 0
            /**
             * @todo Check if there is both NSEC & NSEC3.  Reject if yes. (LATER On hold until NSEC is back in)
             *       compile NSEC if any
             *   compile NSEC3 if any
             *
             * I'm only doing NSEC3 here.
             */
            
            if((flags & ZDB_ZONE_DNSSEC_MASK) == ZDB_ZONE_NSEC)
            {
                log_warn("zone load: zone %{dnsname} was set to NSEC but is NSEC3", zone->origin);
            }
            
            if(has_optin > 0)
            {
                if(has_optout > 0)
                {
                    log_warn("zone load: zone %{dnsname} has got both OPT-OUT and OPT-IN records (%u and %u)", zone->origin, has_optout, has_optin);
                }
                
                nsec3_context.opt_out = FALSE;
                
                if((flags & ZDB_ZONE_DNSSEC_MASK) == ZDB_ZONE_NSEC3_OPTOUT)
                {
                    log_warn("zone load: zone %{dnsname} was set to OPT-OUT but is OPT-IN", zone->origin);
                }
            }
            else if(has_optout > 0)
            {
                /* has_optin is false and has_optout is true */
                
                if((flags & ZDB_ZONE_DNSSEC_MASK) == ZDB_ZONE_NSEC3)
                {
                    log_warn("zone load: zone %{dnsname} was set to OPT-IN but is OPT-OUT (%u)", zone->origin, has_optout);
                }
            }
            else /* use the configuration */
            {
                nsec3_context.opt_out = ((flags & ZDB_ZONE_DNSSEC_MASK) == ZDB_ZONE_NSEC3_OPTOUT)?TRUE:FALSE;
            }
            
            log_info("zone load: zone %{dnsname} is %s", zone->origin, (nsec3_context.opt_out)?"OPT-OUT":"OPT-IN");
            
            /* If there is something in the NSEC3 context ... */

            if(
                    (has_nsec3param  & ((flags & ZDB_ZONE_IS_SLAVE) == 0)) ||  // MASTER  with NSEC3PARAM
                    !nsec3_load_is_context_empty(&nsec3_context)               // SLAVE with NSEC3
                    )
            {
                /* ... do it. */

                log_debug("zone load: zone %{dnsname}: NSEC3 post-processing.", zone->origin);

                return_code = nsec3_load_compile(&nsec3_context);
                
                if(((flags & ZDB_ZONE_IS_SLAVE) != 0) && (nsec3_context.nsec3_rejected > 0))
                {
                    return_code = DNSSEC_ERROR_NSEC3_INVALIDZONESTATE;
                }
                
                if(ISOK(return_code))
                {
                    log_debug("zone load: zone %{dnsname}: NSEC3 post-processing done", zone->origin);
                }
                else
                {
                    log_debug("zone load: zone %{dnsname}: error %r: NSEC3 post-processing failed", zone->origin, return_code);
                }
            }
            else
            {
                log_debug("zone load: zone %{dnsname}: NSEC3 context is empty", zone->origin);
                has_nsec3 = FALSE;
            }

#ifdef DEBUG
            if(ISOK(return_code)) { nsec3_check(zone); /* this is an euristic check */ }
#endif

#else
            log_err("zone load: zone %{dnsname} has NSEC3* record(s) but the server has been compiled without NSEC support", zone->origin);
#endif
        }
        else if(has_nsec)
        {
            /**
             * @TODO build the nsec chain
             */
            
            if((flags & ZDB_ZONE_DNSSEC_MASK) >= ZDB_ZONE_NSEC3)
            {
                log_warn("zone load: zone %{dnsname} was set to NSEC3 but is NSEC", zone->origin);
            }

#if ZDB_HAS_NSEC_SUPPORT != 0

            log_debug("zone load: zone %{dnsname}: NSEC post-processing.", zone->origin);

            if(ISOK(return_code = nsec_update_zone(zone, (flags & ZDB_ZONE_IS_SLAVE) != 0)))
            {
            }

#else
            log_err("zone load: zone %{dnsname} has NSEC record(s) but the server has been compiled without NSEC support", zone->origin);
#endif
        }
    }
#endif

#if ZDB_HAS_NSEC3_SUPPORT != 0
    nsec3_load_destroy(&nsec3_context);
#endif
    
    if(ISOK(return_code))
    {
        log_info("zone load: zone %{dnsname} has been loaded (%d record(s) parsed)", zone->origin, loop_count);
        
        /**
         * @todo remove the expired placeholder here
         */
        
        *zone_pointer_out = zone;

        if((flags & ZDB_ZONE_MOUNT_ON_LOAD) != 0)
        {
            log_info("zone load: zone %{dnsname} has been mounted", zone->origin);
            
            zone_label->zone = zone;
        }
    }
    else
    {
        log_err("zone load: zone %{dnsname}: error %r (%d record(s) parsed)", zone->origin, return_code, loop_count);
        
        /**
         * @note: Used to call zdb_zone_label_delete(db, &name, zclass);
         * 
         * This is wrong.  This is a direct manipulator (a killer without business logic !)
         * 
         * ex:  database with it.eurid.eu & eu
         *      if you ask to delete eu it will take the eu node and destroy EVERYTHING on it.
         * 
         * Intead use: zdb_zone_unload(db, &name, zclass);
         *
         */
        
        *zone_pointer_out = NULL;
    }

    if(ISOK(return_code) && ((flags & ZDB_ZONE_REPLAY_JOURNAL) != 0))
    {
        /*
         * The zone file has been read.
         * NSEC structures have been created
         *
         * At this point, the incremental journal should be replayed.
         *
         */

#ifdef DEBUG
        log_debug("zone load: replaying changes from journal");
#endif
        if(FAIL(return_code = zdb_icmtl_replay(zone, data_path)))
        {
            log_err("zone load: journal replay returned %r", return_code);
        }
        else
        {
            if(return_code > 0)
            {
                log_info("zone load: replayed %d changes from journal", return_code);
                //modified = TRUE;
            }

#ifdef DEBUG
            log_debug("zone load: post-replay sanity check for %{dnsname}", zone->origin);
#endif
            if(FAIL(return_code = zdb_sanitize_zone(zone)))
            {
                log_err("zone load: impossible to sanitise %{dnsname}, dropping zone", zone->origin);
            }
            else
            {
                log_info("zone load: post-replay sanity check for %{dnsname} done", zone->origin);
                
                // zdb_update_zone_signatures(zone, MAX_S32); /// @todo instead clear the signatures without keys
            }
        }

        /*
         * End of the incremental replay
         */
    }

#ifdef DEBUG
    if(ISOK(return_code))
    {
        if(has_nsec3)
        {
            /* Check the AVL collection */

            nsec3_zone *n3 = zone->nsec.nsec3;


            while(n3 != NULL)
            {
                int depth;

                if((depth = nsec3_avl_check(&n3->items)) < 0)
                {
                    puts("oops"); /* debug-only block */
                    exit(-1);
                }

                n3 = n3->next;
            }

            /* Check the correlations between the two databases (zone + zone.nsec3) */
            
            nsec3_check(zone);

            /* Check there are no left alone domains that should have been linked to the nsec3 collections */

            {
                u32 issues_count = 0;
                
                zdb_rr_label *label;
                u8 fqdn[MAX_DOMAIN_LENGTH];
                zdb_zone_label_iterator iter;
           
                zdb_zone_label_iterator_init(zone, &iter);

                while(zdb_zone_label_iterator_hasnext(&iter))
                {
                    zdb_zone_label_iterator_nextname(&iter, fqdn);

                    label = zdb_zone_label_iterator_next(&iter);
                    
                    u16 flags = label->flags;

                    u32 last_issues_count = issues_count;

                    if((flags & ZDB_RR_LABEL_UNDERDELEGATION) == 0) /** @todo !zdb_rr_label_is_glue(label) */
                    {
                        /* APEX or NS+DS */

                        if( ((flags & ZDB_RR_LABEL_APEX) != 0) || (((flags & ZDB_RR_LABEL_DELEGATION) != 0) && (zdb_record_find(&label->resource_record_set, TYPE_DS) != NULL) ) )
                        {
                            /* should be linked */
                            if(label->nsec.nsec3 != NULL)
                            {
                                if(label->nsec.nsec3->self == NULL)
                                {
                                    log_debug2("zone load: HEURISTIC DEBUG NOTE: NSEC3: expected self '%{dnsname}'", fqdn);
                                    issues_count++;
                                }
                                if(label->nsec.nsec3->star == NULL)
                                {
                                    log_debug2("zone load: HEURISTIC DEBUG NOTE: NSEC3: expected star '%{dnsname}'", fqdn);
                                    issues_count++;
                                }
                            }
                            else
                            {
                                log_debug2("zone load: HEURISTIC DEBUG NOTE: NSEC3: expected link '%{dnsname}'", fqdn);
                                issues_count++;
                            }
                        }
                        else
                        {
                            if(label->nsec.nsec3 != NULL)
                            {
                                if(label->nsec.nsec3->self != NULL && label->nsec.nsec3->star != NULL)
                                {
                                    log_debug2("zone load: HEURISTIC DEBUG NOTE: NSEC3: not expected! '%{dnsname}'", fqdn);
                                }
                                else if(label->nsec.nsec3->self == NULL && label->nsec.nsec3->star == NULL)
                                {
                                    log_debug2("zone load: HEURISTIC DEBUG NOTE: NSEC3: needs removal '%{dnsname}'", fqdn);
                                }
                                else
                                {
                                    log_debug("zone load: database loading HEURISTIC DEBUG NOTE: NSEC3: is unclean '%{dnsname}'", fqdn);
                                }
                                issues_count++;
                            }
                        }
                    }
                    else
                    {
                        if(label->nsec.nsec3 != NULL)
                        {
                            if(label->nsec.nsec3->self != NULL && label->nsec.nsec3->star != NULL)
                            {
                                log_debug2("zone load: HEURISTIC DEBUG NOTE: NSEC3: not expected! '%{dnsname}'", fqdn);
                            }
                            else if(label->nsec.nsec3->self == NULL && label->nsec.nsec3->star == NULL)
                            {
                                log_debug2("zone load: HEURISTIC DEBUG NOTE: NSEC3: needs removal '%{dnsname}'", fqdn);
                            }
                            else
                            {
                                log_debug("zone load: database loading HEURISTIC DEBUG NOTE: NSEC3: is unclean '%{dnsname}'", fqdn);
                            }
                            issues_count++;
                        }
                    }

                    if(last_issues_count != issues_count)
                    {
                        nsec3_zone *n3 = zone->nsec.nsec3;

                        while(n3 != NULL)
                        {
                            u8 digest[MAX_DIGEST_LENGTH];

                            nsec3_compute_digest_from_fqdn(n3, fqdn, digest);

                            log_debug2("zone load: HEURISTIC DEBUG NOTE: NSEC3:        check %{digest32h}", digest);

                            n3 = n3->next;
                        }
                    }
                }
            }
        } // has nsec3
    }
#endif

    // zdb_zone_write_text_file(zone, "/tmp/ars.txt", FALSE);
    
    if(zone != NULL)
    {
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_LOAD);
        
        if(FAIL(return_code))
        {
            zdb_zone_destroy(zone);
        }
    }
    
    return return_code;
}

/**
 * @brief Load the zone SOA.
 *
 * Load the zone SOA record
 * This is meant mainly for the slave that could choose between, ie: zone file or axfr zone file
 * The SOA MUST BE the first record
 *
 * @param[in] db a pointer to the database
 * @param[in] zone_data a pointer to an opened zone_reader at its start
 * @param[out] zone_pointer_out will contains a pointer to the loaded zone if the call is successful
 *
 * @return an error code.
 *
 */
ya_result
zdb_zone_get_soa(zone_reader *zone_data, u16 *rdata_size, u8 *rdata)
{
    ya_result return_value;
    resource_record entry;
    
    resource_record_init(&entry);

    if(ISOK(return_value = zone_reader_read_record(zone_data, &entry)))
    {
        if(entry.type == TYPE_SOA)
        {
            s32 soa_rdata_len = zone_reader_rdata_size(entry);
            u8 *soa_rdata = zone_reader_rdata(entry);
            
            if(soa_rdata_len < MAX_SOA_RDATA_LENGTH)
            {
                memcpy(rdata, soa_rdata, soa_rdata_len);
                *rdata_size = soa_rdata_len;
            }
            else
            {
                return_value = ERROR;
            }
        }
        else
        {
            return_value = ERROR;
        }
    }
    
    return return_value;
}


/**
 * @brief Load the zone serial.
 *
 * Load the zone serial.
 * This is meant mainly for the slave that could choose between, ie: zone file or axfr zone file
 *
 * @param[in] db a pointer to the database (not used, it's part of the signature)
 * @param[in] zone_data a pointer to an opened zone_reader at its start
 * @param[out] zone_pointer_out will contains a pointer to the loaded zone if the call is successful
 *
 * @return an error code.
 *
 */
ya_result
zdb_zone_read_serial(zdb *db, zone_reader *zr, const char *data_path, u32 *serialp, bool withjournal)
{
    ya_result return_value;
    resource_record entry;
    
    resource_record_init(&entry);

    if(ISOK(return_value = zone_reader_read_record(zr, &entry)))
    {
        if(entry.type == TYPE_SOA)
        {
            s32 rdata_len = zone_reader_rdata_size(entry);
            u8 *rdata = zone_reader_rdata(entry);

            for(u8 i = 2; i > 0; i--)
            {
                for(;;)
                {
                    u8 l = *rdata;

                    rdata_len--;
                    rdata++;

                    if(l == 0)
                    {
                        break;
                    }

                    if(l > rdata_len)
                    {
                        break;
                    }

                    rdata += l;
                    rdata_len -= l;
                }
            }

            if(rdata_len == 20)
            {
                *serialp = ntohl(GET_U32_AT(rdata[0]));
                
                /*
                 * we got a serial
                 * 
                 * Now, maybe, we want to know up to when it will replay
                 */
                
                if(withjournal)
                {

#ifdef DEBUG
                    log_debug("zone load: getting last serial for zone using journal");
#endif
                    if(ISOK(return_value = journal_last_serial(entry.name, data_path, serialp)))
                    {
#ifdef DEBUG
                        log_debug("zone load: got serial");
#endif
                    }
                    else
                    {
                        log_err("zone load: journal seek: %r", return_value);
                    }
                }
            }
            else
            {
                return_value = ERROR;
            }
        }
        else
        {
            return_value = ERROR;
        }
    }
    
    return return_value;
}

/**
  @}
 */

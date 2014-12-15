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
/** @defgroup
 *  @ingroup dnsdb
 *  @brief
 *
 * ICMTL is actually INCREMENTAL.
 *
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include <dnscore/xfr_copy.h>
#include <dnscore/format.h>

#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/concat_input_stream.h>
#include <dnscore/clone_input_output_stream.h>
#include <dnscore/dns_resource_record.h>

#include "dnsdb/zdb_icmtl.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/icmtl_input_stream.h"
#include "dnsdb/dynupdate.h"
#include "dnscore/treeset.h"
#include "dnsdb/journal.h"

#if ZDB_HAS_DNSSEC_SUPPORT != 0
#include "dnsdb/nsec.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/dnssec.h"
#endif

#define ICMTLNSA_TAG 0x41534e4c544d4349

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define ICMTL_BUFFER_SIZE    4096
#define ICMTL_FILE_MODE      0600
#define ICMTL_SOA_INCREMENT  1

#define ICMTL_REMOVE_TMP_FILE_FORMAT  "%s/%{dnsname}%08x.ir.tmp"
#define ICMTL_ADD_TMP_FILE_FORMAT     "%s/%{dnsname}%08x.ia.tmp"

static u32 icmtl_index_base = 0;

/*
 * With this, I can ensure (in DEBUG builds) that there are no conflicting calls to the (badly named, mea culpa)
 * icmtl mechanism that registers changes to the DB (so the ICMTL protocol can use it).
 * 
 * This means than every writer uses this at some point, so what we actually detect is the conflicting writers.
 * 
 */

UNICITY_DEFINE(icmtl)



static ya_result
zdb_icmtl_unlink_file(const char* name)
{
    ya_result err = SUCCESS;
    
    if(unlink(name) < 0)
    {
     
        err = ERRNO_ERROR;
        
        log_err("journal: unable to delete '%s' : %r", name, err);
    }
    
    return err;
}

/*
 * Replay the incremental stream
 */

ya_result
zdb_icmtl_replay(zdb_zone *zone, const char *directory)
{
    journal *jh;
    ya_result return_value;
    u32 serial;
    s32 changes = 0;
    zdb_ttlrdata ttlrdata;
    dnslabel_vector labels;

    if(FAIL(return_value = zdb_zone_getserial(zone, &serial)))
    {
        log_err("journal: %{dnsname}: error reading serial for zone: %r",zone->origin, return_value);
        
        return return_value;
    }

    bool is_nsec3 = zdb_zone_is_nsec3(zone);

    bool is_nsec = zdb_zone_is_nsec(zone);
    
    input_stream is;
    
#ifdef DEBUG
    log_debug("journal: zdb_icmtl_replay(%{dnsname}, %s)", zone->origin, directory);
#endif
    
    if(FAIL(return_value = journal_open(&jh, zone, directory, FALSE))) // does close
    {
        if(return_value == ZDB_ERROR_ICMTL_NOTFOUND)
        {
            return_value = SUCCESS;
        }
        else
        {
            log_err("journal: %{dnsname}: error opening journal for zone: %r",zone->origin, return_value);
        }
        
        return return_value;
    }
    else
    {
        u32 first_serial;
        u32 last_serial;
        
        return_value = journal_get_serial_range(jh, &first_serial, &last_serial);
        
        if(ISOK(return_value))
        {
            if(last_serial == serial)
            {
                journal_close(jh);
                return 0;           // nothing to replay
            }
            
            if(serial < first_serial)
            {
                journal_close(jh);
                // journal after zone (oops)
                
                return 0;
            }
            
            if(serial > last_serial)
            {
                journal_close(jh);
                // journal obsolete
                
                return 0;
            }
            
            return_value = journal_get_ixfr_stream_at_serial(jh, serial, &is, NULL);
        }
        
        journal_close(jh);
    
        if(FAIL(return_value))
        {
            log_err("journal: %{dnsname}: error reading journal from serial %d: %r",zone->origin, serial, return_value);

            return return_value;
        }
    }
    
    log_info("journal: %{dnsname}: replaying from serial %u (%s)",zone->origin, serial, directory);
           
    buffer_input_stream_init(&is, &is, 4096);

    /* 
     * At this point : the next record, if it exists AND is not an SOA , has to be deleted
     * 
     */
    
    bool did_remove_soa = FALSE;

    log_info("journal: %{dnsname}: applying changes", zone->origin);

    /*
     * 0: DELETE, 1: ADD
     * The mode is switched every time an SOA is found.
     */
    
    u8 mode = 1;

    /*
     * The plan for NSEC3 :
     * Store the fqdn + type class ttl rdata in collections
     * => the delete collection
     * => the add collection
     * Then there is the NSEC3 covered labels: keep a reference to them for later
     *
     * When a pass of SOA-/SOA+ has finished:
     * _ replace the NSEC3 in both collections (reading from delete)
     * _ delete NSEC3 to delete
     * _ add NSEC3 to add
     *
     * _ and finally update the NSEC3 for the labels kept above
     */

#if ZDB_HAS_NSEC3_SUPPORT != 0
    nsec3_icmtl_replay nsec3replay;
    nsec3_icmtl_replay_init(&nsec3replay, zone);
#endif
    
#if ZDB_HAS_NSEC_SUPPORT != 0
    nsec_icmtl_replay nsecreplay;
    nsec_icmtl_replay_init(&nsecreplay, zone);
#endif
    
    dns_resource_record rr;
    dns_resource_record_init(&rr);
    
    u8 *fqdn = rr.name;

    ttlrdata.next = NULL;

    u16 shutdown_test_countdown = 1000;
    
    u32 current_serial = serial;
    
    for(;;)
    {
        if(--shutdown_test_countdown == 0)
        {
            if(dnscore_shuttingdown())
            {
                changes = STOPPED_BY_APPLICATION_SHUTDOWN;
                break;
            }
            
            shutdown_test_countdown = 1000;
        }
        
        /*
         * read the full record
         * 
         * == 0 : no record (EOF)
         *  < 0 : failed
         */
        
        if((return_value = dns_resource_record_read(&rr, &is)) <= 0)
        {
            log_info("journal: reached the end of the journal file");
            
            break;
        }
        
        ttlrdata.ttl = ntohl(rr.tctr.ttl);
        ttlrdata.rdata_pointer = rr.rdata;
        ttlrdata.rdata_size = rr.rdata_size;

        /*
         * Stop at the SOA
         */

        if(rr.tctr.qtype == TYPE_SOA)
        {
            mode ^= 1;

            if(mode == 0)
            {
                /* ADD */

#if ZDB_HAS_NSEC3_SUPPORT != 0                
                if(is_nsec3)
                {
                    return_value = nsec3_icmtl_replay_execute(&nsec3replay);
                    
                    if(FAIL(return_value))
                    {
                        dns_resource_record_clear(&rr);
                        input_stream_close(&is);
                        
                        nsec3_icmtl_replay_destroy(&nsec3replay);
#if ZDB_HAS_NSEC_SUPPORT != 0
                        nsec_icmtl_replay_destroy(&nsecreplay);
#endif            
                        return return_value;
                    }                    
                }
                else
#endif
#if ZDB_HAS_NSEC_SUPPORT != 0
                if(is_nsec)
                {
                    nsec_icmtl_replay_execute(&nsecreplay);
                }
#endif
            }
        }
        
        if(!did_remove_soa)
        {
            log_info("journal: %{dnsname}: removing obsolete SOA", zone->origin);

            if(FAIL(return_value = zdb_record_delete(&zone->apex->resource_record_set, TYPE_SOA)))
            {
                /**
                * complain
                */

                log_err("journal: removing current SOA gave an error: %r", return_value);

                /* That's VERY bad ... */

                changes = return_value;

                break;
            }
            
            did_remove_soa = TRUE;
        }

        s32 top = dnsname_to_dnslabel_vector(fqdn, labels);

        if(mode == 0)
        {
            /*
             * "TO DEL" record
             */

#ifdef DEBUG
            rdata_desc type_len_rdata = {rr.tctr.qtype, rr.rdata_size, rr.rdata };
            log_debug("journal: del %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
#endif

            switch(rr.tctr.qtype)
            {
#if ZDB_HAS_NSEC3_SUPPORT != 0
                case TYPE_NSEC3PARAM:
                {
#ifdef DEBUG
                    rdata_desc type_len_rdata = {TYPE_NSEC3PARAM, ttlrdata.rdata_size, ttlrdata.rdata_pointer };
                    log_debug("journal: del %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
#endif
                    nsec3_icmtl_replay_nsec3param_del(&nsec3replay, &ttlrdata);
                    
                    break;
                }
                case TYPE_NSEC3:
                {
//                    nsec3_zone_item *item = nsec3_get_nsec3_by_name(zone, fqdn, tmprdata);
                    
                    log_debug("journal: NSEC3: queue %{dnsname} for delete", fqdn);

                    nsec3_icmtl_replay_nsec3_del(&nsec3replay, fqdn, &ttlrdata);

                    break;
                }
#endif
#if ZDB_HAS_NSEC_SUPPORT != 0
                case TYPE_NSEC:
                {
                    if(FAIL(return_value = zdb_rr_label_delete_record_exact(zone, labels, (top - zone->origin_vector.size) - 1, rr.tctr.qtype, &ttlrdata)))
                    {
                        log_err("journal: NSEC: %r", return_value);
                    }

                    if(is_nsec)
                    {
                        /*
                         * Set the record as "removed", so if it's not added later it will need to be removed from the NSEC chain
                         */

                        nsec_icmtl_replay_nsec_del(&nsecreplay, fqdn);
                    }
                   
                    break;
                }
#endif
                case TYPE_SOA:
                {
                    rdata_desc rdata = {TYPE_SOA, ttlrdata.rdata_size, ttlrdata.rdata_pointer};
                    log_info("journal: SOA: del %{dnsname} %{typerdatadesc}", fqdn, &rdata);
                    
                    s32 m1 = (top - zone->origin_vector.size) - 1;
                    
                    if(m1 == -1)
                    {
                        if(FAIL(return_value = zdb_record_delete_exact(&zone->apex->resource_record_set, TYPE_SOA, &ttlrdata))) /* FB done, APEX : no delegation */
                        {
                            if(!did_remove_soa)
                            {
                                log_err("journal: SOA: %r", return_value);
                            }
                        }
                    }
                    else
                    {
                        if(FAIL(return_value = zdb_rr_label_delete_record_exact(zone, labels, (top - zone->origin_vector.size) - 1, rr.tctr.qtype, &ttlrdata)))
                        {
                            if(!did_remove_soa)
                            {
                                log_err("journal: SOA: (2) %r", return_value);
                            }
                        }
                    }
                    break;
                }
#if ZDB_HAS_DNSSEC_SUPPORT != 0
                case TYPE_RRSIG:
                {
                    if(is_nsec3 && (RRSIG_RDATA_TO_TYPE_COVERED(rr.rdata[0]) == TYPE_NSEC3))
                    {
                        /*
                         * Get the NSEC3 node
                         * Remove the signature
                         */
                        nsec3_icmtl_replay_nsec3_rrsig_del(&nsec3replay, fqdn, &ttlrdata);

                        break;
                    }
                    
                    // THERE IS A FALLTROUGH TO default: HERE.  IT MUST BE PRESERVED.
                }
#endif
                default:
                {
                    if(FAIL(return_value = zdb_rr_label_delete_record_exact(zone, labels, (top - zone->origin_vector.size) - 1, rr.tctr.qtype, &ttlrdata)))
                    {
                        log_err("journal: %{dnstype}: %r", &rr.tctr.qtype, return_value);
                    }
                }
            }
        }
        else
        {
            /*
             * "TO ADD" record
             */

            switch(rr.tctr.qtype)
            {
#if ZDB_HAS_NSEC3_SUPPORT != 0
                case TYPE_NSEC3PARAM:
                {
                    /*
                     * The "change" could be the NSEC3PARAM flag changing ?
                     */
                    
                    if(is_nsec)
                    {
                        log_err("journal: NSEC3PARAM changes on the NSEC %{dnsname} zone", fqdn);
                        
                        nsec3_icmtl_replay_destroy(&nsec3replay);
                        nsec_icmtl_replay_destroy(&nsecreplay);
                        
                        dns_resource_record_clear(&rr);
                        
                        return ZDB_JOURNAL_NSEC3_ADDED_IN_NSEC;
                    }

                    if(NSEC3_RDATA_ALGORITHM(ttlrdata.rdata_pointer) != DNSSEC_DIGEST_TYPE_SHA1)
                    {
                        log_err("journal: NSEC3PARAM algorithm %d is not supported", NSEC3_RDATA_ALGORITHM(ttlrdata.rdata_pointer));
                        
                        nsec3_icmtl_replay_destroy(&nsec3replay);
                        nsec_icmtl_replay_destroy(&nsecreplay);
                        
                        dns_resource_record_clear(&rr);
                        
                        return ZDB_JOURNAL_NSEC3_HASH_NOT_SUPPORTED;
                    }
#ifdef DEBUG
                    rdata_desc type_len_rdata = {TYPE_NSEC3PARAM, ttlrdata.rdata_size, ttlrdata.rdata_pointer };
                    log_debug("journal: add %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
#endif
                    nsec3_icmtl_replay_nsec3param_add(&nsec3replay, &ttlrdata);
                    
                    break;
                }
                case TYPE_NSEC3:
                {
                    if(is_nsec)
                    {
                        log_err("journal: NSEC3 changes on the dnssec1 %{dnsname} zone", fqdn);
                        
                        nsec3_icmtl_replay_destroy(&nsec3replay);
                        nsec_icmtl_replay_destroy(&nsecreplay);
                        
                        dns_resource_record_clear(&rr);
                        
                        return ERROR;
                    }
                    
                    log_debug("journal: NSEC3: queue %{dnsname} for add", fqdn);

                    if(NSEC3_RDATA_ALGORITHM(ttlrdata.rdata_pointer) != DNSSEC_DIGEST_TYPE_SHA1)
                    {
                        log_err("journal: NSEC3 algorithm %d is not supported", NSEC3_RDATA_ALGORITHM(ttlrdata.rdata_pointer));
                        
                        nsec3_icmtl_replay_destroy(&nsec3replay);
                        nsec_icmtl_replay_destroy(&nsecreplay);
                        
                        dns_resource_record_clear(&rr);
                        
                        return ERROR;
                    }

                    nsec3_icmtl_replay_nsec3_add(&nsec3replay, fqdn, &ttlrdata);
                
                    break;
                }
#endif
#if ZDB_HAS_NSEC_SUPPORT != 0
                case TYPE_NSEC:
                {
                    if(is_nsec3)
                    {
                        log_err("journal: NSEC changes on the dnssec3 %{dnsname} zone", fqdn);
                        
                        nsec3_icmtl_replay_destroy(&nsec3replay);
                        nsec_icmtl_replay_destroy(&nsecreplay);
                        
                        dns_resource_record_clear(&rr);
                        
                        return ERROR;
                    }
                    
                    zdb_packed_ttlrdata *packed_ttlrdata;

                    ZDB_RECORD_ZALLOC_EMPTY(packed_ttlrdata, ttlrdata.ttl, rr.rdata_size);
                    packed_ttlrdata->next = NULL;
                    MEMCOPY(ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata), rr.rdata, rr.rdata_size);
#ifdef DEBUG
                    rdata_desc type_len_rdata = {rr.tctr.qtype, rr.rdata_size, ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata) };
                    log_debug("journal: add %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
#endif

                    s32 rr_label_top = top - zone->origin_vector.size;
                    zdb_zone_record_add(zone, labels, rr_label_top - 1, rr.tctr.qtype, packed_ttlrdata); /* class is implicit */

                    if(is_nsec)
                    {
                        /*
                         * Set the record as "add", so if it's not added later it will need to be removed from the NSEC chain
                         */

                        nsec_icmtl_replay_nsec_add(&nsecreplay, fqdn);
                    }
                    
                    break;
                }
#endif
                default:
                {
                    zdb_packed_ttlrdata *packed_ttlrdata;

                    ZDB_RECORD_ZALLOC_EMPTY(packed_ttlrdata, ttlrdata.ttl, rr.rdata_size);
                    packed_ttlrdata->next = NULL;
                    MEMCOPY(ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata), rr.rdata, rr.rdata_size);
#ifdef DEBUG
                    rdata_desc type_len_rdata = {rr.tctr.qtype, rr.rdata_size, ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata) };
                    log_debug("journal: add %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
#endif
#if ZDB_HAS_NSEC3_SUPPORT != 0
                    if(is_nsec3)
                    {
                        /*
                         * If it's a signature AND if we are on an nsec3 zone AND the type covered is NSEC3 THEN it should be put on hold.
                         */
      
                        if(rr.tctr.qtype == TYPE_RRSIG)
                        {
                            u8 *rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata);

                            if(RRSIG_RDATA_TO_TYPE_COVERED(*rdata) == TYPE_NSEC3)
                            {
                                nsec3_icmtl_replay_nsec3_rrsig_add(&nsec3replay, fqdn, packed_ttlrdata);

                                break;
                            }
                        }
                    }
#endif
                    if(rr.tctr.qtype == TYPE_SOA)
                    {
                        rr_soa_get_serial(ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(packed_ttlrdata), &current_serial);
                        rdata_desc rdata = {TYPE_SOA, ZDB_PACKEDRECORD_PTR_RDATASIZE(packed_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata)};
                        log_info("journal: SOA: add %{dnsname} %{typerdatadesc}", fqdn, &rdata);
                    }

                    s32 rr_label_top = top - zone->origin_vector.size;
                    zdb_zone_record_add(zone, labels, rr_label_top - 1, rr.tctr.qtype, packed_ttlrdata); /* class is implicit */

#if ZDB_HAS_NSEC3_SUPPORT != 0
                    if(is_nsec3)
                    {
                        nsec3_icmtl_replay_label_add(&nsec3replay, fqdn, labels, rr_label_top - 1);
                    }
#endif
                }
            }            
        } // end if ADD

        changes++;
    }
    
    /*
     * Yes, I know.  If 2^32 changes (add batch + del batch) occurs then it will be seen as an error ...
     */
            
    if(ISOK(changes))
    {
#if ZDB_HAS_NSEC3_SUPPORT != 0
        if(is_nsec3)
        {
            nsec3_icmtl_replay_execute(&nsec3replay);
        }
        else
#endif
#if ZDB_HAS_NSEC_SUPPORT != 0
        if(is_nsec)
        {
            nsec_icmtl_replay_execute(&nsecreplay);
        }
#endif
    }
    
#if ZDB_HAS_NSEC3_SUPPORT != 0
    nsec3_icmtl_replay_destroy(&nsec3replay);
#endif
#if ZDB_HAS_NSEC_SUPPORT != 0
    nsec_icmtl_replay_destroy(&nsecreplay);
#endif
    
    dns_resource_record_clear(&rr);

    input_stream_close(&is);

    log_info("journal: %{dnsname}: done", zone->origin);

#ifdef DEBUG
    if(is_nsec)
    {
        nsec_logdump_tree(zone);
    }
#endif

    return changes;
}

ya_result
zdb_icmtl_get_last_serial_from(zdb_zone *zone, const char *directory, u32 *last_serial)
{
    ya_result return_value;
    u32 icmtl_last_serial = ~0;
    journal *jh;

    if(ISOK(return_value = journal_open(&jh, zone, directory, FALSE))) // does close
    {
        return_value = journal_get_last_serial(jh, &icmtl_last_serial);
        
        journal_close(jh);
    }
        
    if(last_serial != NULL)
    {
        *last_serial = icmtl_last_serial;
    }

    return return_value;
}

ya_result
zdb_icmtl_begin(zdb_zone *zone, zdb_icmtl *icmtl, const char* folder)
{
    ya_result return_code;

    UNICITY_ACQUIRE(icmtl);

    char remove_name[1024];
    char add_name[1024];
    
    char data_path[PATH_MAX];
    
    if(FAIL(return_code = xfr_copy_mkdir_data_path(data_path, sizeof(data_path), folder, zone->origin)))
    {
        log_err("journal: unable to create directory '%s' for %{dnsname}: %r", data_path, zone->origin, return_code);
        
        return return_code;
    }
    
    folder = data_path;

    if(icmtl_index_base == 0)
    {
        icmtl_index_base = time(NULL);
    }

    icmtl->patch_index = icmtl_index_base++;

    if(ISOK(return_code = snformat(remove_name, sizeof(remove_name), ICMTL_REMOVE_TMP_FILE_FORMAT, folder, zone->origin, icmtl->patch_index)))
    {
        if(ISOK(return_code = file_output_stream_create(remove_name, ICMTL_FILE_MODE, &icmtl->os_remove_)))
        {
            zdb_icmtl_unlink_file(remove_name);
            
            buffer_output_stream_init(&icmtl->os_remove_, &icmtl->os_remove_, ICMTL_BUFFER_SIZE);
            counter_output_stream_init(&icmtl->os_remove_, &icmtl->os_remove, &icmtl->os_remove_stats);

            if(ISOK(return_code = snformat(add_name, sizeof(add_name), ICMTL_ADD_TMP_FILE_FORMAT, folder, zone->origin, icmtl->patch_index)))
            {
                if(ISOK(return_code = file_output_stream_create(add_name, ICMTL_FILE_MODE, &icmtl->os_add_)))
                {
                    zdb_icmtl_unlink_file(add_name);
                    
                    buffer_output_stream_init(&icmtl->os_add_, &icmtl->os_add_, ICMTL_BUFFER_SIZE);
                    counter_output_stream_init(&icmtl->os_add_, &icmtl->os_add, &icmtl->os_add_stats);

                    dynupdate_icmtlhook_enable(zone->origin, &icmtl->os_remove, &icmtl->os_add);

                    icmtl->zone = zone;

                    /* After this call, the database can be edited. */
                    
                    zdb_packed_ttlrdata* soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);    
                    
                    if(soa != NULL)
                    {
                        icmtl->soa_ttl = soa->ttl;                    
                        icmtl->soa_rdata_size  = ZDB_PACKEDRECORD_PTR_RDATASIZE(soa);
                        memcpy(icmtl->soa_rdata, ZDB_PACKEDRECORD_PTR_RDATAPTR(soa), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa));
                    }
                    else
                    {
                        output_stream_close(&icmtl->os_remove);
                        output_stream_close(&icmtl->os_add);

                        log_err("journal: no soa found at %{dnsname}", zone->origin);
                        
                        return_code = ZDB_ERROR_NOSOAATAPEX;
                    }
                }
                else
                {
                    output_stream_close(&icmtl->os_remove);
                }
            }
        }
    }

    if(FAIL(return_code))
    {
        UNICITY_RELEASE(icmtl);
    }

    return return_code;
}

static void
zdb_icmtl_output_stream_write_packed_ttlrdata(output_stream* os, u8* origin, u16 type, zdb_packed_ttlrdata* record)
{
    output_stream_write_dnsname(os, origin);
    output_stream_write_u16(os, type); /** @note NATIVETYPE */
    output_stream_write_u16(os, CLASS_IN); /** @note NATIVECLASS */
    output_stream_write_nu32(os, record->ttl);
    output_stream_write_nu16(os, record->rdata_size);
    output_stream_write(os, &record->rdata_start[0], record->rdata_size);
}

static ya_result
zdb_icmtl_close(zdb_icmtl *icmtl)
{
    dynupdate_icmtlhook_disable();
    
    output_stream_close(&icmtl->os_remove);
    output_stream_close(&icmtl->os_remove_);
    output_stream_close(&icmtl->os_add);
    output_stream_close(&icmtl->os_add_);
    
    UNICITY_RELEASE(icmtl);
    
    return SUCCESS;
}

ya_result
zdb_icmtl_cancel(zdb_icmtl *icmtl)
{
    ya_result return_code = zdb_icmtl_close(icmtl);
    
    return return_code;
}

ya_result
zdb_icmtl_end(zdb_icmtl *icmtl, const char* folder)
{
    ya_result return_value;

    icmtl->file_size_before_append = 0;
    icmtl->file_size_after_append = 0;
    
    zdb_rr_label* apex = icmtl->zone->apex;
    zdb_packed_ttlrdata* soa = zdb_record_find(&apex->resource_record_set, TYPE_SOA);        
    
    if(soa == NULL)
    {
        zdb_icmtl_close(icmtl);

        return ZDB_ERROR_NOSOAATAPEX;
    }
    
    bool soa_changed = FALSE;
    
    if((soa->ttl != icmtl->soa_ttl) ||
       (ZDB_PACKEDRECORD_PTR_RDATASIZE(soa) != icmtl->soa_rdata_size) ||
       (memcmp(ZDB_PACKEDRECORD_PTR_RDATAPTR(soa), icmtl->soa_rdata, icmtl->soa_rdata_size) != 0))
    {
        soa_changed = TRUE;
    }
    
    /* Increment the SOA's serial number ? */
    
    // soa changed => no
    // no bytes written => no
    
    u32 written = icmtl->os_add_stats.writed_count + icmtl->os_remove_stats.writed_count;
    
    bool must_increment_serial;
    
    if(soa_changed)
    {
        must_increment_serial = FALSE;
    }
    else
    {
        if(written == 0)
        {
            zdb_icmtl_close(icmtl);

            return SUCCESS;
        }
        
        must_increment_serial = TRUE;
    }
    
    if(must_increment_serial)
    {
        rr_soa_increase_serial(&soa->rdata_start[0], soa->rdata_size, ICMTL_SOA_INCREMENT);
    }

#if ZDB_HAS_DNSSEC_SUPPORT != 0
    /* Build new signatures */
   
    if(icmtl->zone->apex->nsec.dnssec != NULL)
    {
        rrsig_context_s context;

        u32 sign_from = time(NULL);

        if(ISOK(return_value = rrsig_context_initialize(&context, icmtl->zone, DEFAULT_ENGINE_NAME, sign_from, NULL)))
        {
            rrsig_context_push_label(&context, icmtl->zone->apex);
            rrsig_update_label_rrset(&context, icmtl->zone->apex, TYPE_SOA);

           /*
            * Retrieve the old signatures (to be deleted)
            * Retrieve the new signatures (to be added)
            *
            * This has to be injected as an answer query.
            */

            dnsname_stack namestack;
            dnsname_to_dnsname_stack(icmtl->zone->origin, &namestack);

            /* Store the signatures */

            zdb_packed_ttlrdata* rrsig_sll;

            rrsig_sll = context.removed_rrsig_sll;

            while(rrsig_sll != NULL)
            {
                if(RRSIG_TYPE_COVERED(rrsig_sll) == TYPE_SOA)
                {
                    zdb_icmtl_output_stream_write_packed_ttlrdata(&icmtl->os_remove, icmtl->zone->origin, TYPE_RRSIG, rrsig_sll);
                }

                rrsig_sll = rrsig_sll->next;
            }

            rrsig_sll = context.added_rrsig_sll;

            while(rrsig_sll != NULL)
            {
                if(RRSIG_TYPE_COVERED(rrsig_sll) == TYPE_SOA)
                {
                    zdb_icmtl_output_stream_write_packed_ttlrdata(&icmtl->os_add, icmtl->zone->origin, TYPE_RRSIG, rrsig_sll);
                }

                rrsig_sll = rrsig_sll->next;
            }
            
            rrsig_update_commit(context.removed_rrsig_sll, context.added_rrsig_sll, icmtl->zone->apex, icmtl->zone, &namestack);

            rrsig_context_pop_label(&context);

            rrsig_context_destroy(&context);
        }
        else
        {
            log_err("incremental: rrsig of the soa failed: %r", return_value);
        }
    }
#endif
    
    dynupdate_icmtlhook_disable();
    
    /*
     * flush the streams, rewind them (because the undelying layer is a file stream)
     * this is faster an allow to delete the file just after creation
     */
    
    output_stream_flush(&icmtl->os_remove);
    output_stream_flush(&icmtl->os_add);
    
    output_stream *fos_remove = buffer_output_stream_get_filtered(&icmtl->os_remove_);
    output_stream *fos_add = buffer_output_stream_get_filtered(&icmtl->os_add_);

    input_stream remove_rr_is;    
    int fd_remove = fd_output_stream_get_filedescriptor(fos_remove);
    fd_output_stream_detach(fos_remove); /* take from inside the buffer stream, so it's OK */
    lseek(fd_remove, 0, SEEK_SET);
    fd_input_stream_attach(fd_remove, &remove_rr_is);
    output_stream_close(&icmtl->os_remove_);
    
    input_stream add_rr_is;
    int fd_add = fd_output_stream_get_filedescriptor(fos_add);
    fd_output_stream_detach(fos_add); /* take from inside the buffer stream, so it's OK */
    lseek(fd_add, 0, SEEK_SET);
    fd_input_stream_attach(fd_add, &add_rr_is);
    output_stream_close(&icmtl->os_add_);
    
    /* current SOA */
    
    input_stream remove_soa_is;
    input_stream add_soa_is;
    
    bytearray_output_stream_context soa_os_context;
    
    u8 remove_soa_buffer[256+10+256+256+32];
    u8 add_soa_buffer[256+10+256+256+32];
    
    output_stream soa_os;
    bytearray_output_stream_init_ex_static(&soa_os, remove_soa_buffer, sizeof(remove_soa_buffer), 0, &soa_os_context);
    output_stream_write_dnsname(&soa_os, icmtl->zone->origin);
    output_stream_write_u16(&soa_os, TYPE_SOA); /** @note NATIVETYPE */
    output_stream_write_u16(&soa_os, CLASS_IN); /** @note NATIVECLASS */
    output_stream_write_nu32(&soa_os, icmtl->soa_ttl);
    output_stream_write_nu16(&soa_os, icmtl->soa_rdata_size);
    output_stream_write(&soa_os, icmtl->soa_rdata, icmtl->soa_rdata_size);    
    bytearray_input_stream_init(remove_soa_buffer, bytearray_output_stream_size(&soa_os), &remove_soa_is, FALSE);
    output_stream_close(&soa_os);

    /* new SOA */

    rr_soa_get_minimumttl(&soa->rdata_start[0], soa->rdata_size, &icmtl->zone->min_ttl);
    
    bytearray_output_stream_init_ex_static(&soa_os, add_soa_buffer, sizeof(add_soa_buffer), 0, &soa_os_context);    
    zdb_icmtl_output_stream_write_packed_ttlrdata(&soa_os, icmtl->zone->origin, TYPE_SOA, soa);    
    bytearray_input_stream_init(add_soa_buffer, bytearray_output_stream_size(&soa_os), &add_soa_is, FALSE);
    output_stream_close(&soa_os);
    
    input_stream cis;
    concat_input_stream_init(&cis);
    concat_input_stream_add(&cis, &remove_soa_is);
    concat_input_stream_add(&cis, &remove_rr_is);
    concat_input_stream_add(&cis, &add_soa_is);
    concat_input_stream_add(&cis, &add_rr_is);
    
    buffer_input_stream_init(&cis, &cis, BUFFER_INPUT_STREAM_DEFAULT_BUFFER_SIZE);
    
    journal *jh;
    
    if(ISOK(return_value = journal_open(&jh, icmtl->zone, folder, TRUE))) // does close
    {
        return_value = journal_append_ixfr_stream(jh, &cis);
        
        journal_close(jh);
    }
    
    input_stream_close(&cis);

    UNICITY_RELEASE(icmtl);

    return return_value;
}

/** @} */

/*----------------------------------------------------------------------------*/


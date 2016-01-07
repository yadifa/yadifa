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
#include "dnsdb/dnsdb-config.h"
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

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
#include "dnscore/ptr_set.h"
#include "dnsdb/zdb-zone-journal.h"
#include "dnsdb/zdb-zone-path-provider.h"
#include "dnsdb/zdb_listener.h"

#define ZDB_ICMTL_REPLAY_GATHER 0
#define ZDB_ICMTL_REPLAY_COMMIT 1
#define ZDB_ICMTL_REPLAY_COMMIT_AND_STOP 3
#define ZDB_ICMTL_REPLAY_STOP 4
#define ZDB_ICMTL_REPLAY_SHUTDOWN_POLL_PERIOD 1000
#define ZDB_ICMTL_REPLAY_BUFFER_SIZE 4096

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

#define ICMTL_TMP_FILE_ENABLED 0

#define ICMTL_REMOVE_TMP_FILE_FORMAT  "%s/%{dnsname}%08x.ir.tmp"
#define ICMTL_ADD_TMP_FILE_FORMAT     "%s/%{dnsname}%08x.ia.tmp"

#ifdef DEBUG
#define ICMTL_DUMP_JOURNAL_RECORDS  0 // awfully slow, only enable when debugging it
#else
#define ICMTL_DUMP_JOURNAL_RECORDS  0
#endif

static smp_int icmtl_index_base = SMP_INT_INITIALIZER;

/*
 * With this, I can ensure (in DEBUG builds) that there are no conflicting calls to the (badly named, mea culpa)
 * icmtl mechanism that registers changes to the DB (so the ICMTL protocol can use it).
 * 
 * This means than every writer uses this at some point, so what we actually detect is the conflicting writers.
 */


static ya_result
zdb_icmtl_replay_commit(zdb_zone *zone, input_stream *is, u32 *current_serialp)
{
    ya_result ret;
    /*
     * 0: DELETE, 1: ADD
     * The mode is switched every time an SOA is found.
     */

    const bool is_nsec3 = zdb_zone_is_nsec3(zone);
    const bool is_nsec = zdb_zone_is_nsec(zone);
    
    u8 mode = 1; // the first SOA will switch the mode to delete
    s32 changes = 0;
    
    zdb_ttlrdata ttlrdata;
    dns_resource_record rr;
    dns_resource_record_init(&rr);
    const u8 *fqdn = rr.name;
    dnslabel_vector labels;

    ttlrdata.next = NULL;

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
    
    ptr_set downed_fqdn = PTR_SET_DNSNAME_EMPTY;
    const bool keep_downed_fqdn = is_nsec3;

    /* 
     * At this point : the next record, if it exists AND is not an SOA , has to be deleted
     * 
     */
    
    bool did_remove_soa = FALSE;

    // something has to be committed

    for(;;)
    {
        /*
         * read the full record
         * 
         * == 0 : no record (EOF)
         *  < 0 : failed
         */

        if((ret = dns_resource_record_read(&rr, is)) <= 0)
        {
            if(ISOK(ret))
            {
                log_info("journal: reached the end of the journal file");
            }
            else
            {
                log_err("journal: broken journal: %r", ret);
                logger_flush(); // broken journal (bad, keep me)
            }

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

#if ZDB_HAS_NSEC3_SUPPORT
                if(is_nsec3)
                {
                    ret = nsec3_icmtl_replay_execute(&nsec3replay);

                    if(FAIL(ret))
                    {
                        dns_resource_record_clear(&rr);
                        // DO NOT: input_stream_close(is);

                        nsec3_icmtl_replay_destroy(&nsec3replay);
#if ZDB_HAS_NSEC_SUPPORT
                        nsec_icmtl_replay_destroy(&nsecreplay);
#endif            
                        return ret;
                    }
                }
                else
#endif
#if ZDB_HAS_NSEC_SUPPORT
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

            if(FAIL(ret = zdb_record_delete(&zone->apex->resource_record_set, TYPE_SOA)))
            {
                /**
                * complain
                */

                log_err("journal: removing current SOA gave an error: %r", ret);

                /* That's VERY bad ... */

                changes = ret;

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

#if ICMTL_DUMP_JOURNAL_RECORDS
            rdata_desc type_len_rdata = {rr.tctr.qtype, rr.rdata_size, rr.rdata };
            log_debug("journal: del %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
            logger_flush();
#endif

            switch(rr.tctr.qtype)
            {
#if ZDB_HAS_NSEC3_SUPPORT != 0
                case TYPE_NSEC3PARAM:
                {
#if ICMTL_DUMP_JOURNAL_RECORDS
                    rdata_desc type_len_rdata = {TYPE_NSEC3PARAM, ttlrdata.rdata_size, ttlrdata.rdata_pointer };
                    log_debug("journal: del %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
                    logger_flush();
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
                    if(FAIL(ret = zdb_rr_label_delete_record_exact(zone, labels, (top - zone->origin_vector.size) - 1, rr.tctr.qtype, &ttlrdata)))
                    {
                        log_err("journal: NSEC: %r", ret);
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
                        if(FAIL(ret = zdb_record_delete_exact(&zone->apex->resource_record_set, TYPE_SOA, &ttlrdata))) /* FB done, APEX : no delegation */
                        {
                            if(!did_remove_soa)
                            {
                                log_err("journal: SOA: %r", ret);
                            }
                        }
                    }
                    else
                    {
                        if(FAIL(ret = zdb_rr_label_delete_record_exact(zone, labels, (top - zone->origin_vector.size) - 1, rr.tctr.qtype, &ttlrdata)))
                        {
                            if(!did_remove_soa)
                            {
                                log_err("journal: SOA: (2) %r", ret);
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
                    if(keep_downed_fqdn)
                    {
                        if(ptr_set_avl_find(&downed_fqdn, fqdn) == NULL)
                        {
                            ptr_set_avl_insert(&downed_fqdn, dnsname_dup(fqdn));
                        }
                    }

                    if(FAIL(ret = zdb_rr_label_delete_record_exact(zone, labels, (top - zone->origin_vector.size) - 1, rr.tctr.qtype, &ttlrdata)))
                    {
                        log_err("journal: del %{dnsrr}", &rr);
                        log_err("journal: %{dnstype}: %r", &rr.tctr.qtype, ret);
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
#if ICMTL_DUMP_JOURNAL_RECORDS
                    rdata_desc type_len_rdata = {TYPE_NSEC3PARAM, ttlrdata.rdata_size, ttlrdata.rdata_pointer };
                    log_debug("journal: add %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
                    logger_flush();
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
#if ICMTL_DUMP_JOURNAL_RECORDS
                    rdata_desc type_len_rdata = {rr.tctr.qtype, rr.rdata_size, ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata) };
                    log_debug("journal: add %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
                    logger_flush();
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

#if ICMTL_DUMP_JOURNAL_RECORDS
                    rdata_desc type_len_rdata = {rr.tctr.qtype, rr.rdata_size, ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata) };
                    log_debug("journal: add %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
                    logger_flush();
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
                        rr_soa_get_serial(ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(packed_ttlrdata), current_serialp);
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
    
    if(keep_downed_fqdn)
    {
        ptr_set_avl_iterator downed_fqdn_iter;
        dnslabel_vector labels;
        ptr_set_avl_iterator_init(&downed_fqdn, &downed_fqdn_iter);

        while(ptr_set_avl_iterator_hasnext(&downed_fqdn_iter))
        {
            ptr_node *node = ptr_set_avl_iterator_next_node(&downed_fqdn_iter);
            // get the label, check if relevant, delete if not
            const u8 *fqdn = (const u8*) node->key;
            s32 labels_top = dnsname_to_dnslabel_vector(fqdn, labels);
            
            zdb_rr_label* rr_label = zdb_rr_label_find_exact(zone->apex, labels, labels_top);
            if((rr_label != NULL) && RR_LABEL_IRRELEVANT(rr_label))
            {
                log_debug("journal: clearing %{dnsname}", fqdn);
                
                ya_result err;
                
                if(FAIL(err = zdb_rr_label_delete_record(zone, labels, labels_top, TYPE_ANY)))
                {
                    log_err("journal: failed to clear %{dnsname}${dnsname}: %r", fqdn, zone->origin, err);
                }
            }
            
            free(node->key);
            node->key = NULL;
        }
        
        ptr_set_avl_destroy(&downed_fqdn);
    }
    
    return changes;
}

/*
 * Replay the incremental stream
 */

ya_result
zdb_icmtl_replay(zdb_zone *zone)
{
    ya_result return_value;
    u32 serial;
    
    zdb_zone_double_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);

    return_value = zdb_zone_getserial(zone, &serial);
    
    if(FAIL(return_value))
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);
        
        log_err("journal: %{dnsname}: error reading serial for zone: %r",zone->origin, return_value);
        
        return return_value;
    }

    input_stream is;
    
#if ICMTL_DUMP_JOURNAL_RECORDS
    log_debug("journal: zdb_icmtl_replay(%{dnsname})", zone->origin);
    logger_flush();
#endif
    
    u32 first_serial;
    u32 last_serial;
        
    if(FAIL(return_value = zdb_zone_journal_get_serial_range(zone, &first_serial, &last_serial)))
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);
        
        if(return_value == ZDB_ERROR_ICMTL_NOTFOUND)
        {
            return_value = SUCCESS;
        }
        else
        {
            log_err("journal: %{dnsname}: error opening journal for zone: %r", zone->origin, return_value);
        }
                
        return return_value;
    }
    
    log_debug("journal: %{dnsname}: zone serial is %i, journal covers serials from %i to %i", zone->origin, serial, first_serial, last_serial);
    
    if(last_serial == serial)
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);
        
        log_debug("journal: %{dnsname}: nothing to read from the journal", zone->origin);
        return 0;
    }
    
    if(serial_lt(serial, first_serial))
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);
        
        log_warn("journal: %{dnsname}: first serial from the journal is after the zone", zone->origin);
        // should invalidate the journal
        zdb_zone_journal_delete(zone);
        return 0;
    }
    
    if(serial_gt(serial, last_serial))
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);
        
        log_warn("journal: %{dnsname}: last serial from the journal is before the zone", zone->origin);
        // should invalidate the journal
        zdb_zone_journal_delete(zone);
        return 0;
    }
    
    if(FAIL(return_value = zdb_zone_journal_get_ixfr_stream_at_serial(zone, serial, &is, NULL)))
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);
        
        log_err("journal: %{dnsname}: error reading journal from serial %d: %r",zone->origin, serial, return_value);

        return return_value;
    }
    
    log_info("journal: %{dnsname}: replaying from serial %u",zone->origin, serial);

    buffer_input_stream_init(&is, &is, ZDB_ICMTL_REPLAY_BUFFER_SIZE);    

    u16 shutdown_test_countdown = ZDB_ICMTL_REPLAY_SHUTDOWN_POLL_PERIOD;
    
    u32 current_serial = serial;
    
    /*
     * Read all records from [ SOA ... SOA ... [ SOA in memory
     */
    
    output_stream baos;
    input_stream bais;
    dns_resource_record rr;
    
    int baos_rr_count = 0;
    int baos_soa_count = 0;

    bytearray_output_stream_init_ex(&baos, NULL, ZDB_ICMTL_REPLAY_BUFFER_SIZE, BYTEARRAY_DYNAMIC);
    dns_resource_record_init(&rr);    
           
    // 0: gather, 1: commit, 2: commit & stop
    
    for(int replay_state = ZDB_ICMTL_REPLAY_GATHER; replay_state != ZDB_ICMTL_REPLAY_COMMIT_AND_STOP;)
    {
        // ensure it's not supposed to shutdown (every few iterations)
        
        if(--shutdown_test_countdown <= 0)
        {
            if(dnscore_shuttingdown())
            {
                return_value = STOPPED_BY_APPLICATION_SHUTDOWN;
                break;
            }
            
            shutdown_test_countdown = ZDB_ICMTL_REPLAY_SHUTDOWN_POLL_PERIOD;
        }
        
        // read the next record
        
        if((return_value = dns_resource_record_read(&rr, &is)) <= 0)
        {
            if(ISOK(return_value))
            {
                log_info("journal: reached the end of the journal file");
                replay_state = ZDB_ICMTL_REPLAY_COMMIT_AND_STOP;
            }
            else
            {
                log_err("journal: broken journal: %r", return_value);
                logger_flush(); // broken journal (flush is slow, but this is bad, so : keep it)
                replay_state = ZDB_ICMTL_REPLAY_STOP;
            }
        }
        else // first record must be an SOA (or it's wrong)        
        if(baos_rr_count == 0) // first record ?
        {
            if(rr.tctr.qtype != TYPE_SOA) // must be SOA
            {
                // expected an SOA
                return_value = ERROR;
                break;
            }
            
            ++baos_soa_count; // 0 -> 1 // this is not mandatory but clearer to read
        }
        else // the page ends with an SOA or end of stream
        if(rr.tctr.qtype == TYPE_SOA)
        {
            if(baos_soa_count == 2)
            {
                // this record is the start of the next stream, keep it for the next iteration
                replay_state = ZDB_ICMTL_REPLAY_COMMIT;
            }
            
            ++baos_soa_count;
        }
        
        ++baos_rr_count;
        
        if((replay_state & ZDB_ICMTL_REPLAY_COMMIT) != 0)
        {
            log_info("journal: %{dnsname}: commiting changes", zone->origin);
            u64 ts_start = timeus();
            zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);
            bytearray_input_stream_init_const(&bais, bytearray_output_stream_buffer(&baos), bytearray_output_stream_size(&baos));
            zdb_icmtl_replay_commit(zone, &bais, &current_serial);
            zdb_zone_exchange_locks(zone, ZDB_ZONE_MUTEX_LOAD, ZDB_ZONE_MUTEX_SIMPLEREADER);
            input_stream_close(&bais);
            u64 ts_stop = timeus();
            if(ts_stop < ts_start) // time change
            {
                ts_stop = ts_start;
            }
            
            u64 ts_delta = ts_stop - ts_start;
            
            if(ts_delta < 1000)
            {            
                log_info("journal: %{dnsname}: commited changes (%lluus)", zone->origin, ts_delta);
            }
            else if(ts_delta < 1000000)
            {
                double ts_delta_s = ts_delta;
                ts_delta_s /= 1000.0;
                log_info("journal: %{dnsname}: commited changes (%5.2fms)", zone->origin, ts_delta_s);
            }
            else
            {
                double ts_delta_s = ts_delta;
                ts_delta_s /= 1000000.0;
                log_info("journal: %{dnsname}: commited changes (%5.2fs)", zone->origin, ts_delta_s);
            }
                    
            // the current page has been processed
            
            if(replay_state == ZDB_ICMTL_REPLAY_COMMIT_AND_STOP)
            {
                // no more page to read
                break;
            }
            
            // reset the state for the next page
            // note: the next written record will be the last read SOA
                        
            baos_rr_count = 1;
            baos_soa_count = 1;
            replay_state = ZDB_ICMTL_REPLAY_GATHER;
            bytearray_output_stream_reset(&baos);
                       
        } // end if replay_state != ZDB_ICMTL_REPLAY_GATHER
                
        dns_resource_record_write(&rr, &baos);
    }
   
    input_stream_close(&is);
    output_stream_close(&baos);
    dns_resource_record_clear(&rr);
    
    if(FAIL(return_value = zdb_zone_getserial(zone, &serial)))
    {
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);
        
        log_err("journal: %{dnsname}: error reading confirmation serial for zone: %r",zone->origin, return_value);
                
        return return_value;
    }
    
    if(serial != last_serial)
    {
        log_warn("journal: %{dnsname}: expected serial to be %i but it is %i instead",zone->origin, last_serial, serial);
    }

    log_info("journal: %{dnsname}: done", zone->origin);
    
    zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_LOAD);

#if ICMTL_DUMP_JOURNAL_RECORDS
    if(is_nsec)
    {
        nsec_logdump_tree(zone);
        logger_flush();
    }
#endif

    return return_value;
}

ya_result
zdb_icmtl_get_last_serial_from(zdb_zone *zone, u32 *last_serial)
{
    ya_result return_value;
    
    return_value = zdb_zone_journal_get_serial_range(zone, NULL, last_serial);
    
    return return_value;
}

ya_result
zdb_icmtl_begin(zdb_icmtl *icmtl, zdb_zone *zone)
{
#if ICMTL_TMP_FILE_ENABLED
    const char* folder;
#endif
    
    ya_result return_code;


    if(smp_int_get(&icmtl_index_base) == 0)
    {
        smp_int_set(&icmtl_index_base, time(NULL));
    }

    icmtl->patch_index = smp_int_inc_get(&icmtl_index_base);

    bytearray_output_stream_init_ex(&icmtl->os_add_, NULL, 65536, BYTEARRAY_DYNAMIC);
    counter_output_stream_init(&icmtl->os_add_, &icmtl->os_add, &icmtl->os_add_stats);
    bytearray_output_stream_init_ex(&icmtl->os_remove_, NULL, 65536, BYTEARRAY_DYNAMIC);
    counter_output_stream_init(&icmtl->os_remove_, &icmtl->os_remove, &icmtl->os_remove_stats);
    
    if(ISOK(return_code = dynupdate_icmtlhook_enable_wait(zone->origin, &icmtl->os_remove, &icmtl->os_add)))
    {
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
        output_stream_close(&icmtl->os_add);

        log_warn("journal: already editing zone %{dnsname}", zone->origin);

        return_code = ZDB_ERROR_ICMTL_STATUS_INVALID;
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
    dynupdate_icmtlhook_disable(icmtl->zone->origin);
    
    output_stream_close(&icmtl->os_remove);
    output_stream_close(&icmtl->os_remove_);
    output_stream_close(&icmtl->os_add);
    output_stream_close(&icmtl->os_add_);
    
    return SUCCESS;
}

ya_result
zdb_icmtl_cancel(zdb_icmtl *icmtl)
{
    ya_result return_code = zdb_icmtl_close(icmtl);
    
    return return_code;
}

ya_result
zdb_icmtl_end(zdb_icmtl *icmtl)
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
    
    bool written_on = zdb_listener_notify_has_changes(icmtl->zone);
    
    bool must_increment_serial;
    
    if(soa_changed)
    {
        must_increment_serial = FALSE;
    }
    else
    {
        if(!written_on)
        {
            zdb_icmtl_close(icmtl);

            return SUCCESS;
        }
        
        must_increment_serial = TRUE;
    }
    
    if(must_increment_serial)
    {
        rr_soa_increase_serial(&soa->rdata_start[0], soa->rdata_size, ICMTL_SOA_INCREMENT);

#if ZDB_HAS_DNSSEC_SUPPORT
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
    }
    
    // Disable cannot be done before
    
    dynupdate_icmtlhook_disable(icmtl->zone->origin);
    
    input_stream remove_rr_is;
    bytearray_input_stream_init(bytearray_output_stream_buffer(&icmtl->os_remove_), bytearray_output_stream_size(&icmtl->os_remove_), &remove_rr_is, TRUE);
    bytearray_output_stream_detach(&icmtl->os_remove_);
    output_stream_close(&icmtl->os_remove_);
    output_stream_close(&icmtl->os_remove);    
    input_stream add_rr_is;
    bytearray_input_stream_init(bytearray_output_stream_buffer(&icmtl->os_add_), bytearray_output_stream_size(&icmtl->os_add_), &add_rr_is, TRUE);
    bytearray_output_stream_detach(&icmtl->os_add_);
    output_stream_close(&icmtl->os_add_);
    output_stream_close(&icmtl->os_add);    
    
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
    
    return_value = zdb_zone_journal_append_ixfr_stream(icmtl->zone, &cis);
    
    input_stream_close(&cis);

    return return_value;
}

/** @} */

/*----------------------------------------------------------------------------*/


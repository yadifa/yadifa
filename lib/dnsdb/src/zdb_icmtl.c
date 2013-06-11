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

#include "dnsdb/zdb_icmtl.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_utils.h"


#include <dnscore/xfr_copy.h>
#include <dnscore/format.h>

#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/buffer_output_stream.h>

#include <dnscore/clone_input_output_stream.h>

#include <dnscore/treeset.h>

#include "dnsdb/icmtl_input_stream.h"

#include "dnsdb/dynupdate.h"

#include "dnsdb/nsec.h"


#include <dnscore/scheduler.h>

#if ZDB_DNSSEC_SUPPORT != 0
#include "dnsdb/rrsig.h"
#endif

#define ICMTLNSA_TAG 0x41534e4c544d4349

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define ICMTL_REMOVE_TMP_FILE_FORMAT  "%s/%{dnsname}%08x.ir.tmp"
#define ICMTL_ADD_TMP_FILE_FORMAT     "%s/%{dnsname}%08x.ia.tmp"
#define ICMTL_SUMMARY_TMP_FILE_FORMAT "%s/%{dnsname}%08x.is.tmp"

#define ICMTL_BUFFER_SIZE    4096
#define ICMTL_FILE_MODE      0600
#define ICMTL_SOA_INCREMENT  1

static u32 icmtl_index_base = 0;

static const u8 SOA_IN[4] = {0,6,0,1};


/*
 * With this, I can ensure (in DEBUG builds) that there are no conflicting calls to the (badly named, mea culpa)
 * icmtl mechanism that registers changes to the DB (so the ICMTL protocol can use it).
 * 
 * This means than every writer uses this at some point, so what we actually detect is the conflicting writers.
 * 
 */

UNICITY_DEFINE(icmtl)

static ya_result
zdb_icmtl_read_tctr(input_stream *is, struct type_class_ttl_rdlen *tctr)
{
    return input_stream_read_fully(is, (u8*)tctr, 10);
}

static ya_result
zdb_icmtl_read_rdata(input_stream *is, u8 *buffer, u32 len)
{
    return input_stream_read_fully(is, buffer, len);
}

static ya_result
zdb_icmtl_rename_file(zdb_icmtl* icmtl, const char* fromf, const char* tof, const char* folder, u32 old_serial, u32 new_serial)
{
    ya_result return_code = SUCCESS;
    
    char old_name[1024];
    char new_name[1024];

    snformat(old_name, sizeof (old_name), fromf, folder, icmtl->zone->origin, icmtl->patch_index);
    snformat(new_name, sizeof (new_name), tof, folder, icmtl->zone->origin, old_serial, new_serial);

    /** @todo: unlink */
    if(rename(old_name, new_name) < 0)
    {
        /** @todo: log */
        return_code = ERRNO_ERROR;
    }

    return return_code;
}

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

static ya_result
zdb_icmtl_unlink(zdb_icmtl* icmtl, const char* fmt, const char* folder, u32 old_serial, u32 new_serial)
{
    char new_name[1024];
    
    snformat(new_name, sizeof (new_name), fmt, folder, icmtl->zone->origin, old_serial, new_serial);

    return zdb_icmtl_unlink_file(new_name);
}

/**
 * 
 * Seek for the "ix" file that ends where the caller wants to start.
 * Renames the file, if found, to match its new content.
 * Opens the file for append.
 *
 */

static ya_result
zdb_icmtl_find_ix(zdb_icmtl* icmtl, const char* folder, u32 end_at_serial, u32 new_end_at_serial, output_stream* target_os)
{
    struct dirent entry;
    struct dirent *result;
    u32 from;
    u32 to;
    ya_result return_code = ERROR;

    char name[1024];
    char fqdn[MAX_DOMAIN_LENGTH + 1];

    /* returns the number of bytes = strlen(x) + 1 */

    s32 fqdn_len = dnsname_to_cstr(fqdn, icmtl->zone->origin);
    
    DIR* dir = opendir(folder);
    if(dir != NULL)
    {
        for(;;)
        {
            readdir_r(dir, &entry, &result);

            if(result == NULL)
            {
                break;
            }

            u8 d_type = dirent_get_file_type(folder, result);

            if(d_type == DT_REG)
            {
                if(memcmp(result->d_name, fqdn, fqdn_len) == 0)
                {
                    const char* serials = &result->d_name[fqdn_len];

                    /*
                     * at serials [ 8+1+8 ] we MUST have a '.'
                     * followed by 'i' 'x' '\0'
                     */

                    if(strlen(serials) == 8 + 1 + 8 + 1 + ICMTL_EXT_STRLEN)
                    {
                        if(strcmp(&serials[8+1+8], "." ICMTL_EXT) == 0)
                        {
                            int converted = sscanf(serials, "%08x-%08x", &from, &to);

                            if(converted == 2)
                            {
                                if(to == end_at_serial)
                                {
                                    snprintf(name, sizeof(name), "%s/%s", folder, result->d_name);

                                    return_code = file_output_stream_open_ex(name, O_WRONLY|O_APPEND, ICMTL_FILE_MODE, target_os);

                                    if(ISOK(return_code))
                                    {
                                        char new_name[1024];

                                        snformat(new_name, sizeof (new_name), ICMTL_WIRE_FILE_FORMAT, folder, icmtl->zone->origin, from, new_end_at_serial);

                                        if(rename(name, new_name) < 0)
                                        {
                                            output_stream_close(target_os);
                                            
                                            /** @todo: log */

                                            return_code = ERRNO_ERROR;
                                        }
                                        
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
     
        closedir(dir);
    }
    
    return return_code;
}

ya_result
zdb_icmtl_open_ix(const u8 *origin, const char *folder, u32 serial, input_stream *target_is, u32 *serial_limit, char** out_file_name)
{
    struct dirent entry;
    struct dirent *result;
    DIR* dir;
    u32 from;
    u32 to;
    u32 fqdn_len;
    ya_result return_code = ERROR;
    char name[1024];

#ifndef NDEBUG
    log_debug("journal: zdb_icmtl_open_ix(%{dnsname}, %s, %08x, %p, &%x, %p)", origin, folder, serial, target_is, (serial_limit!=NULL)?*serial_limit:0, out_file_name);
#endif

    if(out_file_name != NULL)
    {
        *out_file_name = NULL;
    }

    dir = opendir(folder);
    
    if(dir != NULL)
    {
        fqdn_len = dnsname_to_cstr(name, origin);

        for(;;)
        {
            readdir_r(dir, &entry, &result);

            if(result == NULL)
            {
                return_code = ZDB_ERROR_ICMTL_NOTFOUND;

                break;
            }

            u8 d_type = dirent_get_file_type(folder, result);

            if(d_type == DT_REG )
            {
                /*log_info("%s", result->d_name);*/
                
                if(memcmp(result->d_name, name, fqdn_len) == 0)
                {
                    const char* serials = &result->d_name[fqdn_len];

                    /*
                     * at serials [ 8+1+8 ] we MUST have a '.'
                     * followed by 'i' 'x' '\0'
                     */

                    if(strlen(serials) == 8 + 1 + 8 + 1 + ICMTL_EXT_STRLEN)
                    {
                        if(strcmp(&serials[8+1+8], "." ICMTL_EXT) == 0)
                        {
                            int converted = sscanf(serials, "%08x-%08x", &from, &to);

                            if(converted == 2)
                            {
                                /*
                                 * check if from <= serial <= to
                                 */

                                if(serial_ge(serial, from) && serial_lt(serial, to))
                                {
                                    /*
                                     * We are in range
                                     */
                                    snprintf(name, sizeof(name), "%s/%s", folder, result->d_name);

                                    return_code = file_input_stream_open(name, target_is);

                                    if(ISOK(return_code))
                                    {
                                        if(serial_limit != NULL)
                                        {
                                            *serial_limit = to;
                                        }
                                        
                                        if(out_file_name != NULL)
                                        {
                                            *out_file_name = strdup(name);
                                        }

                                        break;
                                    }
                                }
                                else
                                {
                                    if(serial_ge(serial, to))
                                    {
                                        char filename[1024];

                                        snprintf(filename, sizeof(filename), "%s/%s", folder, result->d_name);

                                        log_debug("journal: found & deleted obsolete %s", filename);

                                        zdb_icmtl_unlink_file(filename);
                                    }
                                    else
                                    {
                                        log_warn("journal: skipped %s, may be obsolete", result->d_name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        closedir(dir);
    }
    else
    {
        return_code = ZDB_ERROR_ICMTL_NOTFOUND;
    }

    return return_code;
}


ya_result
zdb_icmtl_skip_until(input_stream *is, zdb_zone *zone)
{
    ya_result return_code;
    struct type_class_ttl_rdlen tctr;
    soa_rdata soa;
    
    u8 mode = 0;
    u8 fqdn[MAX_DOMAIN_LENGTH + 1];

    if(FAIL(return_code = zdb_zone_getsoa(zone, &soa)))
    {
        return return_code;
    }

    for(;;)
    {
        if(FAIL(return_code = input_stream_read_dnsname(is, fqdn)))
        {
            break;
        }

        if(return_code == 0)
        {
            /* EOF : we skipped everything */

            return_code = ZDB_ERROR_ICMTL_NOTFOUND;
            
            break;
        }

        /** @TODO: check that the fqdn matches the origin */

        if(FAIL(return_code = zdb_icmtl_read_tctr(is, &tctr)))
        {
            break;
        }

        if(tctr.qtype == TYPE_SOA)
        {
            if(mode == 0)
            {
                u32 is_serial;
                u8 mname[MAX_DOMAIN_LENGTH + 1];
                u8 rname[MAX_DOMAIN_LENGTH + 1];

                mode = 1;

                if(FAIL(return_code = input_stream_read_dnsname(is, mname)))
                {
                    break;
                }

                if(FAIL(return_code = input_stream_read_rname(is, rname)))
                {
                    break;
                }

                if(FAIL(return_code = input_stream_read_nu32(is, &is_serial)))
                {
                    break;
                }

                if(is_serial == soa.serial)
                {
                    u32 tmp;

                    /* ensure a full match */

                    if(!(dnsname_equals(mname, soa.mname) && dnsname_equals(rname, soa.rname)))
                    {
                        return_code = ZDB_ERROR_ICMTL_SOADONTMATCH;
                        break;
                    }

                    if(FAIL(return_code = input_stream_read_nu32(is, &tmp)))
                    {
                        break;
                    }
                    if(soa.refresh != tmp)
                    {
                        return_code = ZDB_ERROR_ICMTL_SOADONTMATCH;
                        break;
                    }

                    if(FAIL(return_code = input_stream_read_nu32(is, &tmp)))
                    {
                        break;
                    }
                    if(soa.retry != tmp)
                    {
                        return_code = ZDB_ERROR_ICMTL_SOADONTMATCH;
                        break;
                    }

                    if(FAIL(return_code = input_stream_read_nu32(is, &tmp)))
                    {
                        break;
                    }
                    if(soa.expire != tmp)
                    {
                        return_code = ZDB_ERROR_ICMTL_SOADONTMATCH;
                        break;
                    }

                    if(FAIL(return_code = input_stream_read_nu32(is, &tmp)))
                    {
                        break;
                    }
                    if(soa.minimum != tmp)
                    {
                        return_code = ZDB_ERROR_ICMTL_SOADONTMATCH;
                        break;
                    }

                    return_code = SUCCESS;
                    break;
                }

                if(FAIL(input_stream_skip_fully(is, 4 * 4)))
                {
                    break;
                }

            }
            else    /* mode 1 : skip the whole record */
            {
                mode = 0;

                if(FAIL(input_stream_skip_fully(is, ntohs(tctr.rdlen))))
                {
                    break;
                }
            }
        }
        else
        {
            if(FAIL(input_stream_skip_fully(is, ntohs(tctr.rdlen))))
            {
                break;
            }
        }
    }   /* loop */

    return return_code;
}

ya_result
zdb_icmtl_get_soa_with_serial(input_stream *is, u32 serial, u8 *out_dname, struct type_class_ttl_rdlen *out_tctr, u8 *out_soa_rdata_780)
{
    zassert(is != NULL && out_dname != NULL && out_tctr != NULL && out_soa_rdata_780 != NULL);
    ya_result return_code;

    u8 mode = 0;    /* 0 : DEL, 1 : ADD */

    for(;;)
    {
        if(FAIL(return_code = input_stream_read_dnsname(is, out_dname)))
        {
            break;
        }

        /** @TODO: check that the fqdn matches the origin */

        if(FAIL(return_code = zdb_icmtl_read_tctr(is, out_tctr)))
        {
            break;
        }

        u32 len = ntohs(out_tctr->rdlen);

        if(out_tctr->qtype == TYPE_SOA)
        {
            if(mode == 0)
            {
                u32 is_serial;

                if(len > 780)
                {
                    /*
                     * Broken
                     */
                    
                    break;
                }

                if(FAIL(return_code = zdb_icmtl_read_rdata(is, out_soa_rdata_780, len)))
                {
                    break;
                }

                if(FAIL(return_code = rr_soa_get_serial(out_soa_rdata_780, return_code, &is_serial)))
                {
                    break;
                }

                mode = 1;

                if(is_serial == serial)
                {
                    return_code = SUCCESS;

                    return return_code;
                }
            }
            else    /* mode 1 : skip the whole record */
            {
                mode = 0;

                if(FAIL(input_stream_skip_fully(is, len)))
                {
                    break;
                }
            }
        }
        else
        {
            if(FAIL(input_stream_skip_fully(is, len)))
            {
                break;
            }
        }
    }   /* loop */

    /*
     * Not found
     */

    return_code = ZDB_ERROR_ICMTL_SOANOTFOUND;

    return return_code;
}

ya_result
zdb_icmtl_open_ix_get_soa(const u8 *origin, const char *directory, u32 serial, input_stream *is, struct type_class_ttl_rdlen *tctrp, u8 *rdata_buffer_780, u32 *rdata_sizep)
{
    ya_result return_code;
    
    u8 fqdn[256];
    
    if(FAIL(return_code = zdb_icmtl_open_ix(origin, directory, serial, is, NULL, NULL)))
    {
        return return_code;
    }

    /*
     * This is for the next step : synchronize on the right SOA in the middle of the journal file.
     */

    /*
     * Get the SOA matching the serial we want
     */

    if(FAIL(return_code = zdb_icmtl_get_soa_with_serial(is, serial, fqdn, tctrp, rdata_buffer_780)))
    {
        input_stream_close(is);
        
        return return_code;
    }

    *rdata_sizep = ntohl(tctrp->rdlen);

    if(!dnsname_equals(origin, fqdn))
    {
        return ZDB_ERROR_ICMTL_SOADONTMATCH;
    }

    return return_code;
}

ya_result
zdb_icmtl_read_fqdn(input_stream *is, u8 *dst256bytes)
{
    u32 avail = MAX_DOMAIN_LENGTH;

    do
    {
        ya_result return_code;

        avail--;

        if(FAIL(return_code = input_stream_read_fully(is, dst256bytes, 1)))
        {
            return return_code;
        }

        if(*dst256bytes == 0)
        {
            break;
        }

        u32 len = *dst256bytes;

        dst256bytes++;

        s32 n = input_stream_read_fully(is, dst256bytes, len);

        if(n != len)
        {
            return ERROR;
        }

        dst256bytes += len;
        avail -= len;
    }
    while(avail > 0);

    return MAX_DOMAIN_LENGTH - avail;
}


/*
 * Replay the incremental stream
 */

ya_result
zdb_icmtl_replay(zdb_zone *zone, const char* directory, u64 serial_offset, u32 until_serial, u8 flags)
{
    ya_result return_code;
    u32 serial;
    s32 changes = 0;
    zdb_ttlrdata ttlrdata;
    dnslabel_vector labels;
    bool use_serial_limit = (flags & ZDB_ICMTL_REPLAY_SERIAL_LIMIT) != 0;
    u8 tmprdata[RDATA_MAX_LENGTH + 1];

    if(FAIL(return_code = zdb_zone_getserial(zone, &serial)))
    {
        return return_code;
    }

    bool is_nsec3 = zdb_zone_is_nsec3(zone);

    bool is_nsec = zdb_zone_is_nsec(zone);
    
    input_stream is;
    
    char data_path[1024];
    
    if(FAIL(return_code = xfr_copy_get_data_path(directory, zone->origin, data_path, sizeof(data_path))))
    {
        return return_code;
    }
    
    directory = data_path;
    
    if(use_serial_limit)
    {
        log_info("journal: %{dnsname}: trying to replay from serial %u to serial %u (%s)",zone->origin, serial, until_serial, directory);
        
        if(serial == until_serial)
        {
            log_err("journal %{dnsname}: no operation needed", zone->origin);
            
            return SUCCESS; /* nothing to do */
        }
    }
    else
    {
        log_info("journal: %{dnsname}: trying to replay from serial %u (%s)",zone->origin, serial, directory);
    }
           
    if(FAIL(return_code = zdb_icmtl_open_ix(zone->origin, directory, serial , &is, NULL, NULL)))
    {
        /*
         * This error code only means there were no relevant IX files.
         */

        if(return_code == ZDB_ERROR_ICMTL_NOTFOUND)
        {
            /** do not complain about it */

#ifndef NDEBUG
            log_debug("journal: %{dnsname}: nothing to replay : %r",zone->origin, return_code);
#endif

            return_code = SUCCESS;
        }
        else
        {
            log_info("journal: %{dnsname}: will not replay : %r",zone->origin, return_code);
        }

        return return_code;
    }
    
    if((flags & ZDB_ICMTL_REPLAY_SERIAL_OFFSET) != 0)
    {
        if(is_fd_input_stream(&is))
        {
            fd_input_stream_seek(&is, serial_offset);
        }
    }

    buffer_input_stream_init(&is, &is, 4096);

    /* Reads until a DEL SOA record has the SAME serial */

    log_debug("journal: %{dnsname}: skipping past records", zone->origin);

    if(FAIL(return_code = zdb_icmtl_skip_until(&is, zone)))
    {
        input_stream_close(&is);

        if(return_code != ZDB_ERROR_ICMTL_NOTFOUND)
        {
            /**
             * complain
             */

            /* That's bad ... */

            log_err("journal: forwarding to the start of the replay gave an error: %r", return_code);
        }

        /**
         * the file is obsolete
         *
         * @todo the file is not always obsolete.  I have to fix this.
         */

        /*
         * obsolete replay is not an issue.  There should only be one .ix file but I retry again anyway
         */

        return return_code;
    }

    /* 
     * At this point : the next record, if it exists AND is not an SOA , has to be deleted
     * 
     */
    
    bool did_remove_soa = FALSE;

    log_info("journal: %{dnsname}: applying changes", zone->origin);

    u8 mode = 0;

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

    nsec3_icmtl_replay nsec3replay;
    nsec3_icmtl_replay_init(&nsec3replay, zone);

    nsec_icmtl_replay nsecreplay;
    nsec_icmtl_replay_init(&nsecreplay, zone);

    ttlrdata.next = NULL;
    ttlrdata.rdata_pointer = tmprdata;

    u16 shutdown_test_countdown = 1000;
    
    u32 current_serial = serial;
    
    for(;;)
    {
        struct type_class_ttl_rdlen tctr;
        u8 fqdn[MAX_DOMAIN_LENGTH + 1];
        
        if(--shutdown_test_countdown == 0)
        {
            if(dnscore_shuttingdown())
            {
                changes = STOPPED_BY_APPLICATION_SHUTDOWN;
                break;
            }
            
            shutdown_test_countdown = 1000;
        }

        return_code = zdb_icmtl_read_fqdn(&is, fqdn);

        if(return_code <= 0)
        {
            /* last record ... */
            
            log_info("journal: reached the end of the journal file");
            
            break;
        }

        zdb_icmtl_read_tctr(&is, &tctr);

        /*
         * Stop at the SOA
         */

        tctr.rdlen = ntohs(tctr.rdlen);
        tctr.ttl = ntohl(tctr.ttl);

        if(tctr.qtype == TYPE_SOA)
        {
            if(use_serial_limit && (until_serial == current_serial))
            {
                /* the last added SOA had the serial we expected stop here */
                
                log_info("journal: reached the expected serial");
                
                break;
            }
            
            mode ^= 1;

            //zdb_icmtl_skip_rdata(&is, tctr.rdlen);

            /* continue; */

            /**
             * @TODO: I'm here : check that the SOA matches ?
             */

            if(mode == 0)
            {
                if(is_nsec3)
                {
                    return_code = nsec3_icmtl_replay_execute(&nsec3replay);
                    
                    if(FAIL(return_code))
                    {
                        input_stream_close(&is);
                        
                        nsec3_icmtl_replay_destroy(&nsec3replay);
                        nsec_icmtl_replay_destroy(&nsecreplay);
                        
                        return ERROR;
                    }                    
                }
                else if(is_nsec)
                {
                    nsec_icmtl_replay_execute(&nsecreplay);
                }
            }
        }
        
        if(!did_remove_soa)
        {
            log_info("journal: %{dnsname}: removing obsolete SOA", zone->origin);

            if(FAIL(return_code = zdb_record_delete(&zone->apex->resource_record_set, TYPE_SOA)))
            {
                /**
                * complain
                */

                log_err("journal: removing current SOA gave an error: %r", return_code);

                /* That's VERY bad ... */

                changes = return_code;

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
            
            zdb_icmtl_read_rdata(&is, tmprdata, tctr.rdlen);

#ifndef NDEBUG
            rdata_desc type_len_rdata = {tctr.qtype, tctr.rdlen, tmprdata };
            log_debug("journal: del %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
#endif

            switch(tctr.qtype)
            {
                case TYPE_NSEC3PARAM:
                {
                    ttlrdata.ttl = tctr.ttl;
                    ttlrdata.rdata_size = tctr.rdlen;
                    zdb_icmtl_read_rdata(&is, ttlrdata.rdata_pointer, ttlrdata.rdata_size);
                    
#ifndef NDEBUG
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
                    
                    ttlrdata.ttl = tctr.ttl;
                    ttlrdata.rdata_size = tctr.rdlen;

                    nsec3_icmtl_replay_nsec3_del(&nsec3replay, fqdn, &ttlrdata);

                    break;
                }
                case TYPE_NSEC:
                {
                    ttlrdata.ttl = tctr.ttl;
                    ttlrdata.rdata_size = tctr.rdlen;

                    if(FAIL(return_code = zdb_rr_label_delete_record_exact(zone, labels, (top - zone->origin_vector.size) - 1, tctr.qtype, &ttlrdata)))
                    {
                        log_err("journal: NSEC: %r", return_code);
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
                case TYPE_SOA:
                {
                    ttlrdata.ttl = tctr.ttl;
                    ttlrdata.rdata_size = tctr.rdlen;
                    
                    rdata_desc rdata = {TYPE_SOA, ttlrdata.rdata_size, ttlrdata.rdata_pointer};
                    log_info("journal: SOA: del %{dnsname} %{typerdatadesc}", fqdn, &rdata);
                    
                    s32 m1 = (top - zone->origin_vector.size) - 1;
                    
                    if(m1 == -1)
                    {
                        if(FAIL(return_code = zdb_record_delete_exact(&zone->apex->resource_record_set, TYPE_SOA, &ttlrdata))) /* FB done, APEX : no delegation */
                        {
                            log_err("journal: SOA: %r", return_code);
                        }
                    }
                    else
                    {
                        if(FAIL(return_code = zdb_rr_label_delete_record_exact(zone, labels, (top - zone->origin_vector.size) - 1, tctr.qtype, &ttlrdata)))
                        {
                            log_err("journal: SOA: %r", return_code);
                        }
                    }
                    break;
                }
                case TYPE_RRSIG:
                {
                    if(is_nsec3 && (RRSIG_RDATA_TO_TYPE_COVERED(tmprdata[0]) == TYPE_NSEC3))
                    {
                        /*
                         * Get the NSEC3 node
                         * Remove the signature
                         */

                        ttlrdata.ttl = tctr.ttl;
                        ttlrdata.rdata_size = tctr.rdlen;
        
                        nsec3_icmtl_replay_nsec3_rrsig_del(&nsec3replay, fqdn, &ttlrdata);

                        break;
                    }
                    
                    // THERE IS A FALLTROUGH TO default: HERE.  IT MUST BE PRESERVED.
                }
                default:
                {
                    ttlrdata.ttl = tctr.ttl;
                    ttlrdata.rdata_size = tctr.rdlen;
                    
                    if(FAIL(return_code = zdb_rr_label_delete_record_exact(zone, labels, (top - zone->origin_vector.size) - 1, tctr.qtype, &ttlrdata)))
                    {
                        log_err("journal: %{dnstype}: %r", &tctr.qtype, return_code);
                    }
                }
            }
        }
        else
        {
            /*
             * "TO ADD" record
             */

            switch(tctr.qtype)
            {
                case TYPE_NSEC3PARAM:
                {
                    /*
                     * The "change" could be the NSEC3PARAM flag changing ?
                     */
                    
                    if(is_nsec)
                    {
                        log_err("journal: NSEC3PARAM changes on the dnssec1 %{dnsname} zone", fqdn);
                        
                        nsec3_icmtl_replay_destroy(&nsec3replay);
                        nsec_icmtl_replay_destroy(&nsecreplay);
                        
                        return ERROR;
                    }
                    
                    ttlrdata.ttl = tctr.ttl;
                    ttlrdata.rdata_size = tctr.rdlen;
                    zdb_icmtl_read_rdata(&is, ttlrdata.rdata_pointer, ttlrdata.rdata_size);
                    
                    if(NSEC3_RDATA_ALGORITHM(ttlrdata.rdata_pointer) != DNSSEC_DIGEST_TYPE_SHA1)
                    {
                        log_err("journal: NSEC3PARAM algorithm %d is not supported", NSEC3_RDATA_ALGORITHM(ttlrdata.rdata_pointer));
                        
                        nsec3_icmtl_replay_destroy(&nsec3replay);
                        nsec_icmtl_replay_destroy(&nsecreplay);
                        
                        return ERROR;
                    }
                    
#ifndef NDEBUG
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
                        
                        return ERROR;
                    }
                    
                    log_debug("journal: NSEC3: queue %{dnsname} for add", fqdn);

                    ttlrdata.ttl = tctr.ttl;
                    ttlrdata.rdata_size = tctr.rdlen;
                    zdb_icmtl_read_rdata(&is, ttlrdata.rdata_pointer, ttlrdata.rdata_size);

                    if(NSEC3_RDATA_ALGORITHM(ttlrdata.rdata_pointer) != DNSSEC_DIGEST_TYPE_SHA1)
                    {
                        log_err("journal: NSEC3 algorithm %d is not supported", NSEC3_RDATA_ALGORITHM(ttlrdata.rdata_pointer));
                        
                        nsec3_icmtl_replay_destroy(&nsec3replay);
                        nsec_icmtl_replay_destroy(&nsecreplay);
                        
                        return ERROR;
                    }

                    nsec3_icmtl_replay_nsec3_add(&nsec3replay, fqdn, &ttlrdata);
                
                    break;
                }
                case TYPE_NSEC:
                {
                    if(is_nsec3)
                    {
                        log_err("journal: NSEC changes on the dnssec3 %{dnsname} zone", fqdn);
                        
                        nsec3_icmtl_replay_destroy(&nsec3replay);
                        nsec_icmtl_replay_destroy(&nsecreplay);
                        
                        return ERROR;
                    }
                    
                    zdb_packed_ttlrdata *packed_ttlrdata;

                    ZDB_RECORD_ZALLOC_EMPTY(packed_ttlrdata, tctr.ttl, tctr.rdlen);
                    packed_ttlrdata->next = NULL;
                    zdb_icmtl_read_rdata(&is, ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(packed_ttlrdata));

#ifndef NDEBUG
                    rdata_desc type_len_rdata = {tctr.qtype, tctr.rdlen, ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata) };
                    log_debug("journal: add %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
#endif

                    s32 rr_label_top = top - zone->origin_vector.size;
                    zdb_zone_record_add(zone, labels, rr_label_top - 1, tctr.qtype, packed_ttlrdata); /* class is implicit */

                    if(is_nsec)
                    {
                        /*
                         * Set the record as "add", so if it's not added later it will need to be removed from the NSEC chain
                         */

                        nsec_icmtl_replay_nsec_add(&nsecreplay, fqdn);
                    }
                    
                    break;
                }
                default:
                {
                    zdb_packed_ttlrdata *packed_ttlrdata;

                    ZDB_RECORD_ZALLOC_EMPTY(packed_ttlrdata, tctr.ttl, tctr.rdlen);
                    packed_ttlrdata->next = NULL;
                    zdb_icmtl_read_rdata(&is, ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(packed_ttlrdata));
#ifndef NDEBUG
                    rdata_desc type_len_rdata = {tctr.qtype, tctr.rdlen, ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata) };
                    log_debug("journal: add %{dnsname} %{typerdatadesc}", fqdn, &type_len_rdata);
#endif
                    if(is_nsec3)
                    {
                        /*
                         * If it's a signature AND if we are on an nsec3 zone AND the type covered is NSEC3 THEN it should be put on hold.
                         */
                        
                        if(tctr.qtype == TYPE_RRSIG)
                        {
                            u8 *rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata);

                            if(RRSIG_RDATA_TO_TYPE_COVERED(*rdata) == TYPE_NSEC3)
                            {
                                nsec3_icmtl_replay_nsec3_rrsig_add(&nsec3replay, fqdn, packed_ttlrdata);

                                break;
                            }
                        }
                    }
                    
                    if(tctr.qtype == TYPE_SOA)
                    {
                        rr_soa_get_serial(ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATASIZE(packed_ttlrdata), &current_serial);
                        rdata_desc rdata = {TYPE_SOA, ZDB_PACKEDRECORD_PTR_RDATASIZE(packed_ttlrdata), ZDB_PACKEDRECORD_PTR_RDATAPTR(packed_ttlrdata)};
                        log_info("journal: SOA: add %{dnsname} %{typerdatadesc}", fqdn, &rdata);
                    }

                    s32 rr_label_top = top - zone->origin_vector.size;
                    zdb_zone_record_add(zone, labels, rr_label_top - 1, tctr.qtype, packed_ttlrdata); /* class is implicit */

                    if(is_nsec3)
                    {
                        nsec3_icmtl_replay_label_add(&nsec3replay, fqdn, labels, rr_label_top - 1);
                    }
                }
            }            
        } // end if ADD

        changes++;
    }
    
    if(use_serial_limit && (until_serial != current_serial))
    {
        log_err("journal: expected to read the journal up to serial %d, got to %d.  This is BAD.", until_serial, current_serial);
    }
    
    /*
     * Yes, I know.  If 2^32 changes (add batch + del batch) occurs then it will be seen as an error ...
     */
            
    if(ISOK(changes))
    {
        if(is_nsec3)
        {
            nsec3_icmtl_replay_execute(&nsec3replay);
        }
        else if(is_nsec)
        {
            nsec_icmtl_replay_execute(&nsecreplay);
        }
    }
    
    nsec3_icmtl_replay_destroy(&nsec3replay);
    nsec_icmtl_replay_destroy(&nsecreplay);

    input_stream_close(&is);

    log_info("journal: %{dnsname}: done", zone->origin);

#ifndef NDEBUG
    if(is_nsec)
    {
        nsec_logdump_tree(zone);
    }
#endif

    return changes;
}

ya_result
zdb_icmtl_get_last_serial_from(u32 serial, u8 *origin, const char* directory, u32 *last_serial)
{
    ya_result return_code;
    u32 icmtl_last_serial = ~0;

    input_stream is;
    
    char data_path[1024];
    
    if(FAIL(return_code = xfr_copy_get_data_path(directory, origin, data_path, sizeof(data_path))))
    {
        return return_code;
    }
    
    directory = data_path;

    log_info("journal: %{dnsname}: fast forwarding in %s from serial %u",origin, directory, serial);

    if(FAIL(return_code = zdb_icmtl_open_ix(origin, directory, serial , &is, &icmtl_last_serial, NULL)))
    {
        /*
         * This error code only means there were no relevant IX files.
         */

        /*log_info("journal: %{dnsname}: will not fast forward : %r", origin, return_code);*/

        if(return_code == ZDB_ERROR_ICMTL_NOTFOUND)
        {
            icmtl_last_serial = serial;
            
            if(last_serial != NULL)
            {
                *last_serial = icmtl_last_serial;
            }
            
            return_code = SUCCESS;
        }
        
        return return_code;
    }

    if(last_serial != NULL)
    {
        *last_serial = icmtl_last_serial;
    }

    log_info("journal: %{dnsname}: fast forward done", origin);

    input_stream_close(&is);

    return return_code;
}

static ya_result
zdb_icmtl_unlink_remove(zdb_icmtl* icmtl, const char* folder)
{
    char tmp_name[1024];
    
    ya_result return_code;
    
    if(FAIL(return_code = snformat(tmp_name, sizeof (tmp_name), ICMTL_REMOVE_TMP_FILE_FORMAT, folder, icmtl->zone->origin, icmtl->patch_index)))
    {
        log_err("incremental: error making 'remove' tmp file name: %r", return_code);
    }

    unlink(tmp_name);
    
    return return_code;
}

static ya_result
zdb_icmtl_unlink_add(zdb_icmtl* icmtl, const char* folder)
{
    char tmp_name[1024];
    
    ya_result return_code;
    
    if(FAIL(return_code = snformat(tmp_name, sizeof (tmp_name), ICMTL_ADD_TMP_FILE_FORMAT, folder, icmtl->zone->origin, icmtl->patch_index)))
    {
        log_err("incremental: error making 'remove' tmp file name: %r", return_code);
    }

    unlink(tmp_name);
    
    return return_code;
}

ya_result
zdb_icmtl_get_last_soa_from(u32 serial, u8 *origin, const char* directory, u32 *last_serial, u32 *ttl, u16 *rdata_size, u8 *rdata)
{
    ya_result return_code;
    u32 icmtl_last_serial = ~0;
    u32 origin_len = dnsname_len(origin);

    input_stream is;
    
    char data_path[1024];
    
    if(FAIL(return_code = xfr_copy_get_data_path(directory, origin, data_path, sizeof(data_path))))
    {
        return return_code;
    }
    
    directory = data_path;

    log_info("journal: %{dnsname}: loading last locally stored SOA from serial %u", origin, serial);

    if(ISOK(return_code = zdb_icmtl_open_ix(origin, directory, serial , &is, &icmtl_last_serial, NULL)))
    {
        /*
         * The input stream is on a file so I can cheat a bit, grab its fd, seek to the end minus 1K and
         * reverse-read the SOA
         * 
         * => rewind 20 bytes, rewind two fqdns, rewind rdata size, rewind ttl rewind class (00 01),
         * rewind type (00 06), rewind origin.
         * 
         * This can be simplified: rewind 20 bytes then scan for (00 06 00 01) which is an impossible pattern
         * on the mname and rname then rewind the exact size of the origin. and as long as there is no dnsname
         * match, rewind 1 byte
         * 
         * 
         */
        
        u8 *buffer;
        MALLOC_OR_DIE(u8*, buffer, 65536, GENERIC_TAG);
        
        int fd = fd_input_stream_get_filedescriptor(&is);
        off_t fd_size;
        
        if((fd_size = lseek(fd, 0, SEEK_END)) < 0)
        {
            input_stream_close(&is);
            
            free(buffer);
            
            return ERRNO_ERROR;
        }
            
        if(fd_size > 65536)
        {
            if(lseek(fd, -65536, SEEK_END) < 0)
            {
                input_stream_close(&is);
                
                free(buffer);
            
                return ERRNO_ERROR;
            }
            
            fd_size = 65536;
        }
        else
        {
            lseek(fd, 0, SEEK_SET);
        }
        
        input_stream_read(&is, buffer, fd_size);

        u8 *record_start_match = (u8*)data_path;
        u32 record_start_match_len = origin_len + 4;
        
        memcpy(record_start_match, origin, origin_len);
        memcpy(&record_start_match[origin_len], SOA_IN, 4);
        
        u8 *record_start = buffer;
        u8 *limit = &buffer[fd_size - record_start_match_len - 20 - 2 - 6];

        return_code = ERROR;
        
        /*
        * look for what could be the SOA+IN fields
        */

        while(record_start < limit)
        {
            if(memcmp(record_start, record_start_match, record_start_match_len) == 0)
            {
                u8* serialp = &record_start[record_start_match_len + 6];
                serialp += dnsname_len(serialp);
                serialp += dnsname_len(serialp);
                u32 soa_serial = htonl(GET_U32_AT(*serialp));
                
                if(soa_serial == icmtl_last_serial)
                {
                    if(ttl != NULL)
                    {
                        *ttl = GET_U32_AT(record_start[record_start_match_len]);
                    }
                    
                    *rdata_size = ntohs(GET_U16_AT(record_start[record_start_match_len + 4]));

                    memcpy(rdata, &record_start[record_start_match_len + 6], *rdata_size);

                    return_code = SUCCESS;
                    
                    break;
                }
                
                record_start += record_start_match_len + 6 + ntohs(GET_U16_AT(record_start[record_start_match_len + 4]));
            }
            else
            {            
                record_start++;
            }
        }
        
        input_stream_close(&is);
        
        free(buffer);
    }

    return return_code;
}

ya_result
zdb_icmtl_begin(zdb_zone* zone, zdb_icmtl* icmtl, const char* folder)
{
    ya_result return_code;

    UNICITY_ACQUIRE(icmtl);

    char remove_name[1024];
    char add_name[1024];
    
    char data_path[1024];
    
    if(FAIL(return_code = xfr_copy_make_data_path(folder, zone->origin, data_path, sizeof(data_path))))
    {
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
            buffer_output_stream_init(&icmtl->os_remove_, &icmtl->os_remove_, ICMTL_BUFFER_SIZE);
            counter_output_stream_init(&icmtl->os_remove_, &icmtl->os_remove, &icmtl->os_remove_stats);

            if(ISOK(return_code = snformat(add_name, sizeof(add_name), ICMTL_ADD_TMP_FILE_FORMAT, folder, zone->origin, icmtl->patch_index)))
            {
                if(ISOK(return_code = file_output_stream_create(add_name, ICMTL_FILE_MODE, &icmtl->os_add_)))
                {
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
                        
                        unlink(remove_name);
                        unlink(add_name);
                        
                        log_err("journal: no soa found at %{dnsname}", zone->origin);
                        
                        return_code = ZDB_ERROR_NOSOAATAPEX;
                    }
                }
                else
                {
                    output_stream_close(&icmtl->os_remove);
                    unlink(remove_name);
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
output_stream_write_packed_ttlrdata(output_stream* os, u8* origin, u16 type, zdb_packed_ttlrdata* record)
{
    output_stream_write_dnsname(os, origin);
    output_stream_write_u16(os, type); /** @note NATIVETYPE */
    output_stream_write_u16(os, CLASS_IN); /** @note NATIVECLASS */
    output_stream_write_nu32(os, record->ttl);
    output_stream_write_nu16(os, record->rdata_size);
    output_stream_write(os, &record->rdata_start[0], record->rdata_size);
}

static ya_result
zdb_icmtl_close(zdb_icmtl* icmtl, const char* folder)
{
    ya_result return_code;
    char data_path[1024];
    
    dynupdate_icmtlhook_disable();
    
    output_stream_close(&icmtl->os_remove);
    output_stream_close(&icmtl->os_remove_);
    output_stream_close(&icmtl->os_add);
    output_stream_close(&icmtl->os_add_);
    
    if(FAIL(return_code = xfr_copy_get_data_path(folder, icmtl->zone->origin, data_path, sizeof(data_path))))
    {
        return return_code;
    }

    folder = data_path;
    
    zdb_icmtl_unlink_remove(icmtl, folder);
    zdb_icmtl_unlink_add(icmtl, folder);

    UNICITY_RELEASE(icmtl);
    
    return SUCCESS;
}

ya_result
zdb_icmtl_end(zdb_icmtl* icmtl, const char* folder)
{
    output_stream icmtl_out;

    ya_result return_code;

    char remove_tmp_name[1024];
    char add_tmp_name[1024];
    char summary_tmp_name[1024];
    char wire_name[1024];
    char buffer[1024];
    char data_path[1024];
    
    icmtl->file_size_before_append = 0;
    icmtl->file_size_after_append = 0;
    
    zdb_rr_label* apex = icmtl->zone->apex;
    zdb_packed_ttlrdata* soa = zdb_record_find(&apex->resource_record_set, TYPE_SOA);        
    
    if(soa == NULL)
    {
        /** @todo: files are useless: remove the icmtlr & icmtla files that have just been closed */
        
        zdb_icmtl_close(icmtl, folder);

        return ZDB_ERROR_NOSOAATAPEX;
    }
    
    if(FAIL(return_code = xfr_copy_get_data_path(folder, icmtl->zone->origin, data_path, sizeof(data_path))))
    {
        dynupdate_icmtlhook_disable();
    
        output_stream_close(&icmtl->os_remove);
        output_stream_close(&icmtl->os_remove_);
        output_stream_close(&icmtl->os_add);
        output_stream_close(&icmtl->os_add_);
    
        return return_code;
    }
    
    folder = data_path;
    
    bool soa_changed = FALSE;
    
    if((soa->ttl != icmtl->soa_ttl) ||
       (ZDB_PACKEDRECORD_PTR_RDATASIZE(soa) != icmtl->soa_rdata_size) ||
       (memcmp(ZDB_PACKEDRECORD_PTR_RDATAPTR(soa), icmtl->soa_rdata, icmtl->soa_rdata_size) != 0))
    {
        soa_changed = TRUE;
    }

    output_stream_flush(&icmtl->os_remove);
    output_stream_flush(&icmtl->os_add);
    
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
            // remove .tmp files
            zdb_icmtl_unlink_add(icmtl, folder);
            zdb_icmtl_unlink_remove(icmtl, folder);
            zdb_icmtl_close(icmtl, folder);

            return return_code;
        }
        
        must_increment_serial = TRUE;
    }
    
    if(must_increment_serial)
    {
        rr_soa_increase_serial(&soa->rdata_start[0], soa->rdata_size, ICMTL_SOA_INCREMENT);
    }

#if ZDB_DNSSEC_SUPPORT != 0
    /* Build new signatures */
   
    if(icmtl->zone->apex->nsec.dnssec != NULL)
    {
        rrsig_context context;

        u32 sign_from = time(NULL);

        if(ISOK(return_code = rrsig_initialize_context(icmtl->zone, &context, DEFAULT_ENGINE_NAME, sign_from)))
        {
            rrsig_update_context_push_label(&context, icmtl->zone->apex);
            rrsig_update_label_type(&context, icmtl->zone->apex, TYPE_SOA, FALSE);

           /*
            * Retrieve the old signatures (to be deleted)
            * Retrieve the new signatures (to be added)
            *
            * This has to be injected as an answer query.
            */

#if RRSIG_UPDATE_SCHEDULED == 0
            dnsname_stack namestack;
            dnsname_to_dnsname_stack(icmtl->zone->origin, &namestack);
#else
            dnsname_stack* namestackp;
            MALLOC_OR_DIE(dnsname_stack*,namestackp,sizeof(dnsname_stack), ICMTLNSA_TAG);
            dnsname_to_dnsname_stack(icmtl->zone->origin, namestackp);
#endif

            /* Store the signatures */

            zdb_packed_ttlrdata* rrsig_sll;

            rrsig_sll = context.removed_rrsig_sll;

            while(rrsig_sll != NULL)
            {
                if(RRSIG_TYPE_COVERED(rrsig_sll) == TYPE_SOA)
                {
                    output_stream_write_packed_ttlrdata(&icmtl->os_remove, icmtl->zone->origin, TYPE_RRSIG, rrsig_sll);
                }

                rrsig_sll = rrsig_sll->next;
            }

            rrsig_sll = context.added_rrsig_sll;

            while(rrsig_sll != NULL)
            {
                if(RRSIG_TYPE_COVERED(rrsig_sll) == TYPE_SOA)
                {
                    output_stream_write_packed_ttlrdata(&icmtl->os_add, icmtl->zone->origin, TYPE_RRSIG, rrsig_sll);
                }

                rrsig_sll = rrsig_sll->next;
            }

#if RRSIG_UPDATE_SCHEDULED == 0
            rrsig_update_commit(context.removed_rrsig_sll, context.added_rrsig_sll, icmtl->zone->apex, &namestack);
#else
           /**
            *  The last parameter is a pointer to a context to destroy (optional but actually always used)
            */
            scheduler_task_rrsig_update_commit(context.removed_rrsig_sll, context.added_rrsig_sll, icmtl->zone->apex, icmtl->zone, namestackp, namestackp);
#endif
            rrsig_update_context_pop_label(&context);

            rrsig_destroy_context(&context);
        }
        else
        {
            log_err("incremental: rrsig of the soa failed: %r", return_code);
        }
    }
#endif
    
    dynupdate_icmtlhook_disable();

    output_stream_close(&icmtl->os_remove);
    output_stream_close(&icmtl->os_remove_);
    output_stream_close(&icmtl->os_add);
    output_stream_close(&icmtl->os_add_);

    /*
     * The main work is done.
     *
     * I have yet to store the previous (current) SOA and all its signatures
     * Then I have to increment the serial, store the new SOA, sign it in this
     * very thread and store the signature(s)
     *
     * This last storage part has to be done in the file called "tmp_name"
     */
    
    if(FAIL(return_code = snformat(remove_tmp_name, sizeof(remove_tmp_name), ICMTL_REMOVE_TMP_FILE_FORMAT, folder, icmtl->zone->origin, icmtl->patch_index)))
    {
        log_err("incremental: error making 'remove' tmp file name: %r", return_code);

        UNICITY_RELEASE(icmtl);

        return return_code;
    }
    
    struct stat file_stat;
    if(stat(remove_tmp_name, &file_stat) < 0)
    {
        log_err("incremental: unable to stat '%s': %r", remove_tmp_name, return_code);

        UNICITY_RELEASE(icmtl);

        return ERRNO_ERROR;
    }

    /**/
    
    if(FAIL(return_code = snformat(add_tmp_name, sizeof(add_tmp_name), ICMTL_ADD_TMP_FILE_FORMAT, folder, icmtl->zone->origin, icmtl->patch_index)))
    {
        log_err("incremental: error making 'add' tmp file name: %r", return_code);

        UNICITY_RELEASE(icmtl);

        return return_code;
    }

    off_t total_size = file_stat.st_size;

    if(stat(add_tmp_name, &file_stat) < 0)
    {
        log_err("incremental: unable to stat '%s': %r", add_tmp_name, return_code);

        UNICITY_RELEASE(icmtl);

        return ERRNO_ERROR;
    }

    total_size += file_stat.st_size;    /* size of the incremental 'added' and 'removed' files */

    if(!soa_changed && (total_size == 0))
    {
        log_info("incremental: no change registered.");

        zdb_icmtl_unlink_file(remove_tmp_name);
        zdb_icmtl_unlink_file(add_tmp_name);

        UNICITY_RELEASE(icmtl);

        return SUCCESS;
    }

    if(FAIL(return_code = snformat(summary_tmp_name, sizeof(summary_tmp_name), ICMTL_SUMMARY_TMP_FILE_FORMAT, folder, icmtl->zone->origin, icmtl->patch_index)))
    {
        log_err("incremental: error making summary file name: %r", return_code);

        UNICITY_RELEASE(icmtl);

        return return_code;
    }

    if(FAIL(return_code = file_output_stream_create(summary_tmp_name, ICMTL_FILE_MODE, &icmtl_out)))
    {
        log_err("incremental: error creating file '%s': %r", summary_tmp_name, return_code);
        
        UNICITY_RELEASE(icmtl);

        return return_code;
    }

    if(FAIL(return_code = buffer_output_stream_init(&icmtl_out, &icmtl_out, ICMTL_BUFFER_SIZE)))
    {
        output_stream_close(&icmtl_out);
        unlink(summary_tmp_name);
        UNICITY_RELEASE(icmtl);

        return return_code;
    }

    /* Store current SOA */

    u32 old_serial;

    rr_soa_get_serial(icmtl->soa_rdata, icmtl->soa_rdata_size, &old_serial);

    output_stream_write_dnsname(&icmtl_out, icmtl->zone->origin);
    output_stream_write_u16(&icmtl_out, TYPE_SOA); /** @note NATIVETYPE */
    output_stream_write_u16(&icmtl_out, CLASS_IN); /** @note NATIVECLASS */
    output_stream_write_nu32(&icmtl_out, icmtl->soa_ttl);
    output_stream_write_nu16(&icmtl_out, icmtl->soa_rdata_size);
    output_stream_write(&icmtl_out, icmtl->soa_rdata, icmtl->soa_rdata_size);
    
    u32 new_serial;

    rr_soa_get_serial(&soa->rdata_start[0], soa->rdata_size, &new_serial);
    rr_soa_get_minimumttl(&soa->rdata_start[0], soa->rdata_size, &icmtl->zone->min_ttl);

    /* Store new SOA */

    output_stream_write_packed_ttlrdata(&icmtl_out, icmtl->zone->origin, TYPE_SOA, soa);
    
    output_stream_close(&icmtl_out);

    /**
     * Now rename the files to their final names
     *
     * @todo: The add/remove files should not be required anymore at this point.
     *
     */

    if(ISOK(return_code = zdb_icmtl_rename_file(icmtl, ICMTL_REMOVE_TMP_FILE_FORMAT  , ICMTL_REMOVE_FILE_FORMAT, folder, old_serial, new_serial)))
    {
        if(ISOK(return_code = zdb_icmtl_rename_file(icmtl, ICMTL_ADD_TMP_FILE_FORMAT , ICMTL_ADD_FILE_FORMAT, folder, old_serial, new_serial)))
        {
            return_code = zdb_icmtl_rename_file(icmtl, ICMTL_SUMMARY_TMP_FILE_FORMAT , ICMTL_SUMMARY_FILE_FORMAT, folder, old_serial, new_serial);
        }
    }

    if(ISOK(return_code))
    {
        /*
         * convert into a standard I(xfr) file
         */

        snformat(wire_name, sizeof(wire_name), ICMTL_WIRE_FILE_FORMAT, folder, icmtl->zone->origin, old_serial, new_serial);

#ifndef NDEBUG
        log_debug("incremental: building wire: '%s'", wire_name);
#endif

        /*
         * Try to find the previous "ix" file that ends with the old_serial
         */
        
        output_stream wire_os;
        input_stream icmtl_is;

        bool append_ix = FALSE;
        
        if(ISOK(return_code = icmtl_input_stream_open(icmtl->zone->origin, old_serial, new_serial, &icmtl_is, folder)))
        {
            /*
             * The first and last records are meaningless.
             * They are just a repeat of the last recorded SOA
             */

            icmtl_input_stream_skip_headtail(&icmtl_is);

            append_ix = TRUE;

            if(FAIL(return_code = zdb_icmtl_find_ix(icmtl, folder, old_serial, new_serial, &wire_os)))
            {
                /**
                 * @Note: it is the right place to make icmtl optimization (if we ever support this, which is a bad idea IMHO)
                 *
                 */

                /**
                 * @Note: if the original serial from the zone file is older than the start of the returned file,
                 *        we MUST store the zone on disk ASAP and cut the journal.
                 */

                append_ix = FALSE;

                return_code = file_output_stream_create(wire_name, ICMTL_FILE_MODE, &wire_os);
            }
            
            if(ISOK(return_code))
            {
                /* at this point wire_os is supposed to be a file_output_stream with the file pointer set at the end of the file */
                
                if(is_fd_output_stream(&wire_os))
                {
                    int fd = fd_output_stream_get_filedescriptor(&wire_os);
                    icmtl->file_size_before_append = lseek(fd, 0, SEEK_CUR);
                    icmtl->file_size_after_append = icmtl->file_size_before_append;
                }
                
                /* append ... */
                
                ya_result n;

                while((n = input_stream_read(&icmtl_is, (u8*)buffer, sizeof(buffer))) > 0)
                {
                    if(FAIL(n = output_stream_write(&wire_os, (u8*)buffer,n)))
                    {
                        break;
                    }
                    
                    icmtl->file_size_after_append += n;
                }

                /*
                 * If no error occurred, we can remove the source.
                 */

                if(ISOK(n))
                {
                    zdb_icmtl_unlink(icmtl, ICMTL_REMOVE_FILE_FORMAT, folder, old_serial, new_serial);
                    zdb_icmtl_unlink(icmtl, ICMTL_ADD_FILE_FORMAT, folder, old_serial, new_serial);
                    zdb_icmtl_unlink(icmtl, ICMTL_SUMMARY_FILE_FORMAT, folder, old_serial, new_serial);
                }

                output_stream_close(&wire_os);
                input_stream_close(&icmtl_is);

                return_code = n;
            }
        }

        if(FAIL(return_code))
        {
            log_err("incremental: building wire: '%s' %s failed: %r",
                    wire_name,
                    (append_ix)?"(append)":"",
                    return_code);
            
            if(icmtl->file_size_after_append > icmtl->file_size_before_append)
            {
                log_err("incremental: current journal has been partially modified and should be cut at size %lld", icmtl->file_size_before_append);
            }

            /*
             * We can only remove the file if it is a new one.  Else we loose past changes.
             * Oh, and if we were doing an append we are now in a critical state.
             * We have to start a recovery:
             *      _ remove the broken records
             *      _ redo
             * 
             * But the problem is that the issue is most likely a resource issue (disk full ?)
             * So we can only complain and disable dynamic updates.
             * 
             * @TODO: disable dynamic updates globally: SERVFAIL
             */

            if(append_ix)
            {
                log_err("incremental: CRITICAL ERROR. UPDATES DISABLED. UNABLE TO UPDATE ANYMORE: INVESTIGATE, FIX, RESTART.");
            }
            else
            {
                zdb_icmtl_unlink_file(wire_name);
            }
        }
    }

    UNICITY_RELEASE(icmtl);

    return return_code;
}

/** @} */

/*----------------------------------------------------------------------------*/


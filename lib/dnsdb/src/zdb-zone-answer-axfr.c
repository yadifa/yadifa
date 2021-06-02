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

/** @defgroup dnsdbscheduler Scheduled tasks of the database
 *  @ingroup dnsdb
 *  @brief
 *
 *
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>

#include "dnsdb/zdb-config-features.h"

#include <dnscore/logger.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/counter_output_stream.h>
#include <dnscore/empty-input-stream.h>
#include <dnscore/format.h>
#include <dnscore/packet_writer.h>
#include <dnscore/rfc.h>
#include <dnscore/serial.h>
#include <dnscore/fdtools.h>
#include <dnscore/tcp_io_stream.h>
#if DNSCORE_HAS_TCP_MANAGER
#include <dnscore/tcp_manager.h>
#endif

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb-zone-arc.h"
#include "dnsdb/zdb-zone-journal.h"
#include "dnsdb/zdb_zone_axfr_input_stream.h"

#include "dnsdb/zdb-zone-answer-axfr.h"
#include "dnsdb/zdb-zone-path-provider.h"

#define MODULE_MSG_HANDLE g_database_logger

#define DEBUG_AXFR_MESSAGES 0

/**
 *
 * dig -p 8053 @172.20.1.69 eu AXFR +time=3600 > eu.axfr
 *
 * Max dns packet size / Max number of records in each packet / RDATA Compression enabled
 *
 * 65535 1 1
 *
 * ;; Query time: 150452 msec
 * ;; SERVER: 172.20.1.69#8053(172.20.1.69)
 * ;; WHEN: Thu Dec 24 09:17:57 2009
 * ;; XFR size: 6657358 records (messages 6657358, bytes 417268730)
 *
 * 65535 65535 0
 *
 * ;; Query time: 82347 msec
 * ;; SERVER: 172.20.1.69#8053(172.20.1.69)
 * ;; WHEN: Wed Dec 23 15:31:23 2009
 * ;; XFR size: 6657358 records (messages 4141, bytes 271280613)
 *
 * 4096 65535 1
 *
 * ;; Query time: 78042 msec
 * ;; SERVER: 172.20.1.69#8053(172.20.1.69)
 * ;; WHEN: Thu Dec 24 09:04:54 2009
 * ;; XFR size: 6657358 records (messages 44940, bytes 182745973)
 *
 * 65535 65535 1
 *
 * ;; Query time: 88954 msec
 * ;; SERVER: 172.20.1.69#8053(172.20.1.69)
 * ;; WHEN: Thu Dec 24 09:08:47 2009
 * ;; XFR size: 6657358 records (messages 3133, bytes 205197880)
 *
 * So it was obvious but the best system is 4K packets without any record count limit and with compression enabled:
 *
 * 4096 because compression only covers the first 4K of the packet
 * no limit because there is no point (1 is supposed to be nicer but at what cost !)
 * compression enabled because it reduces the bandwidth AND the time
 *
 *  With buffering enabled this increases to:
 *
 * ;; Query time: 20130 msec
 * ;; SERVER: 172.20.1.69#8053(172.20.1.69)
 * ;; WHEN: Thu Dec 24 09:48:39 2009
 * ;; XFR size: 6657358 records (messages 44940, bytes 182745973)
 *
 * The same transfer to another computer (Nicolas') took only 13 seconds with a release build.
 *
 */

#define TCP_BUFFER_SIZE 4096
#define FILE_BUFFER_SIZE 4096

#if DEBUG
#define ZDB_ZONE_AXFR_MINIMUM_DUMP_PERIOD 1 // seconds
#else
#define ZDB_ZONE_AXFR_MINIMUM_DUMP_PERIOD 60 // seconds
#endif

extern logger_handle* g_database_logger;

#ifndef PATH_MAX
#error "PATH_MAX not defined"
#endif

typedef struct zdb_zone_answer_axfr_thread_args zdb_zone_answer_axfr_thread_args;

#define SHDQZWAA_TAG 0x4141575a51444853

struct zdb_zone_answer_axfr_thread_args
{
    zdb_zone *zone;
    message_data *mesg;
    struct thread_pool_s *disk_tp;
#if DNSCORE_HAS_TCP_MANAGER
    tcp_manager_socket_context_t *sctx;
#else
    int sockfd;
#endif
    ya_result return_code;
    u32 packet_size_limit;
    u32 packet_records_limit;
    u32 journal_from;
    u32 journal_to;
    bool compress_dname_rdata;
};

typedef struct zdb_zone_answer_axfr_write_file_args zdb_zone_answer_axfr_write_file_args;

#define ZAAXFRWF_TAG 0x465752465841415a

struct zdb_zone_answer_axfr_write_file_args
{
    output_stream os;   // (file) output stream to the AXFR file
    char *path;
    char *pathpart;
    zdb_zone *zone;
    u32 serial;
    ya_result return_code;
};

static void
zdb_zone_answer_axfr_thread_exit(zdb_zone_answer_axfr_thread_args* data)
{
    log_debug("zone write axfr: %{dnsname}: ended with: %r", data->zone->origin, data->return_code);
    
    zdb_zone_release(data->zone);
    
    //free(data->directory);
    free(data);
}

static void*
zdb_zone_answer_axfr_write_file_thread(void* data_)
{
    zdb_zone_answer_axfr_write_file_args* storage = (zdb_zone_answer_axfr_write_file_args*)data_;
    
    // os
    // zone
    // serial
    // *return_code
    /*-----------------------------------------------------------------------*/

    buffer_output_stream_init(&storage->os, &storage->os, 4096);
    
    // ALEADY LOCKED BY THE CALLER SO NO NEED TO zdb_zone_lock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
#if ZDB_ZONE_KEEP_RAW_SIZE
    u64 write_start = timeus();
    
    output_stream counter_stream;
    counter_output_stream_data counter_data;
    counter_output_stream_init(&storage->os, &counter_stream, &counter_data);

    storage->return_code = zdb_zone_store_axfr(storage->zone, &counter_stream); // zone is locked
    
    zdb_zone_unlock(storage->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    output_stream_flush(&counter_stream);
    output_stream_close(&counter_stream);
    output_stream_close(&storage->os);
    
    storage->zone->wire_size = counter_data.written_count;
    storage->zone->write_time_elapsed = timeus() - write_start;
    
#else
    storage->return_code = zdb_zone_store_axfr(storage->data->zone, &storage->os);
    zdb_zone_unlock(storage->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    output_stream_close(&storage->os);
#endif

    if(ISOK(storage->return_code))
    {
        log_info("zone write axfr: %{dnsname}: stored %d", storage->zone->origin, storage->serial);

        if(rename(storage->pathpart, storage->path) >= 0)
        {
            storage->zone->axfr_timestamp = time(NULL);
            storage->zone->axfr_serial = storage->serial;
            
            // here, the zone exists as persistent storage on an .axfr file
        }
        else
        {
            // cannot rename error : SERVFAIL

            storage->zone->axfr_timestamp = 1;
            storage->return_code = ERRNO_ERROR;

            log_err("zone write axfr: %{dnsname}: error renaming '%s' into '%s': %r", storage->zone->origin, storage->pathpart, storage->path, storage->return_code);
        }
    }
    else
    {
        log_err("zone write axfr: %{dnsname}: error writing '%s': %r", storage->zone->origin, storage->pathpart, storage->return_code);

        // cannot create error : SERVFAIL
        
        storage->zone->axfr_timestamp = 1;
        storage->zone->axfr_serial = storage->serial - 1;
    }
    
    zdb_zone_clear_dumping_axfr(storage->zone);
    
    zdb_zone_release(storage->zone);
    storage->zone = NULL;
    free(storage->path);
    free(storage->pathpart);
    free(storage);

    return NULL;
}

static void*
zdb_zone_answer_axfr_thread(void* data_)
{
    zdb_zone_answer_axfr_thread_args* data = (zdb_zone_answer_axfr_thread_args*)data_;
    message_data *mesg = data->mesg;
    zdb_zone *data_zone = data->zone; // already RCed ...
    output_stream os;
    input_stream fis;
    u64 total_bytes_sent = 0;
    ya_result ret;
    u32 serial = 0;
    u32 now = time(NULL);
    u32 journal_from = data->journal_from;
    u32 journal_to = data->journal_to;
    int path_len;
    u8   data_zone_origin[MAX_DOMAIN_LENGTH];
    char buffer[PATH_MAX + 8];

#if DNSCORE_HAS_TCP_MANAGER
    if(!tcp_manager_is_valid(data->sctx))
    {
        data->return_code = MAKE_ERRNO_ERROR(ENOTSOCK);
        log_err("zone write axfr: %{dnsname}: invalid connection", data->zone->origin);
        zdb_zone_answer_axfr_thread_exit(data);
        message_free(mesg);
        return NULL;
    }

    tcp_manager_socket_context_t *sctx = data->sctx;

#if DEBUG
    log_debug("zone write axfr: %{dnsname}: socket is %d", data->zone->origin, tcp_manager_socket(sctx));
#endif
#else
    int tcpfd = data->sockfd;
    data->sockfd = -1;
    if(tcpfd < 0)
    {
        data->return_code = MAKE_ERRNO_ERROR(ENOTSOCK);
        log_err("zone write axfr: %{dnsname}: invalid socket", data->zone->origin);
        zdb_zone_answer_axfr_thread_exit(data);
        message_free(mesg);
        return NULL;
    }
#if DEBUG
    log_debug("zone write axfr: %{dnsname}: socket is %d", data->zone->origin, tcpfd);
#endif

#endif

    /**
     * The zone could already be dumping in the disk.
     * If it's the case, then the dump file needs to be read and sent until marked as "done".
     */
    
    /* locks the zone for a reader */
        
    message_set_additional_count_ne(mesg, 0);
    
#if DEBUG
    log_debug("zone write axfr: %{dnsname}: locking for AXFR", data->zone->origin);
#endif

    zdb_zone_lock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    if(zdb_zone_invalid(data_zone))
    {
        zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        
        log_err("zone write axfr: %{dnsname}: marked as invalid", data_zone->origin);

#if DNSCORE_HAS_TCP_MANAGER
        if(ISOK(ret = message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcp_manager_socket(sctx))))
        {
            tcp_manager_write_update(sctx, ret);
        }
        tcp_manager_close(sctx);
#else
        message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcpfd);
#endif
        zdb_zone_answer_axfr_thread_exit(data);

#if !DNSCORE_HAS_TCP_MANAGER
        tcp_set_abortive_close(tcpfd);
        close_ex(tcpfd);
#endif
        message_free(mesg);
        return NULL;
    }
    
#if DEBUG
    log_debug("zone write axfr: %{dnsname}: checking serial number", data_zone->origin);
#endif
    
    if(FAIL(zdb_zone_getserial(data_zone, &serial))) // zone is locked
    {
        zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

        log_err("zone write axfr: %{dnsname}: no SOA", data_zone->origin);

#if DNSCORE_HAS_TCP_MANAGER
        if(ISOK(ret = message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcp_manager_socket(sctx))))
        {
            tcp_manager_write_update(sctx, ret);
        }
        tcp_manager_close(sctx);
#else
        message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcpfd);
#endif
        zdb_zone_answer_axfr_thread_exit(data);

#if !DNSCORE_HAS_TCP_MANAGER
        tcp_set_abortive_close(tcpfd);
        close_ex(tcpfd);
#endif
        message_free(mesg);
        return NULL;
    }
    
    u32 packet_size_limit = data->packet_size_limit;

    if(packet_size_limit < message_get_buffer_size_max(mesg))
    {
        packet_size_limit = message_get_buffer_size_max(mesg);
    }
    
    u32 packet_records_limit = data->packet_records_limit;

    /* If it is set to 0, it means there is no limit. */

    if(packet_records_limit == 0)
    {
        packet_records_limit = 0xffffffff;
    }
    
    bool compress_dname_rdata = data->compress_dname_rdata;

    dnsname_copy(data_zone_origin, data_zone->origin);
    
    empty_input_stream_init(&fis);
    
    /*
     * The zone could be being written to the disk right now.
     *    axfr_timestamp = 0, file exists as a .part (or as a normal file, if race)
     * 
     * The file could not being written to the disk
     *    axfr_timestamp != 0, file exists as a normal file
     *    axfr_timestamp = 1, no idea of the status
     * 
     *    Whatever of these two, the file existence should be tested
     *    If the file does not exists, it should be dumped
     * 
     * The file serial on disk may be too old, in that case it should be written again
     * (too old: time and/or serial increment and/or journal size)
     * 
     */

    for(int countdown = 5; countdown >= 0; --countdown)
    {
        if(countdown == 0)
        {
            // tried to many times: servfail
            
            zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

            data->return_code = ZDB_ERROR_COULDNOTOOBTAINZONEIMAGE; // AXFR file creation failed
            log_warn("zone write axfr: %{dnsname}: could not prepare file", data_zone_origin);
            
            message_make_error(mesg, FP_CANNOT_HOLD_AXFR_DATA);
            if(message_has_tsig(mesg))
            {
                tsig_sign_answer(mesg);
            }

#if DEBUG_AXFR_MESSAGES
            LOGGER_EARLY_CULL_PREFIX(MSG_DEBUG) message_log(MODULE_MSG_HANDLE, MSG_DEBUG, mesg);
#endif

            #if DNSCORE_HAS_TCP_MANAGER
            if(ISOK(ret = message_send_tcp(mesg, tcp_manager_socket(sctx))))
            {
                tcp_manager_write_update(sctx, ret);
            }
            else
            {
                log_warn("zone write axfr: %{dnsname}: tcp write error: %r", data_zone_origin, ret);
                tcp_set_abortive_close(tcp_manager_socket(sctx));
            }
            tcp_manager_close(sctx);
#else
            if(FAIL(ret = message_send_tcp(mesg, tcpfd)))
            {
                log_warn("zone write axfr: %{dnsname}: tcp write error: %r", data_zone_origin, ret);

                tcp_set_abortive_close(tcpfd);
            }

            tcp_set_abortive_close(tcpfd);
            close_ex(tcpfd);
#endif
            zdb_zone_answer_axfr_thread_exit(data);
            message_free(mesg);

            return NULL;
        }
        
        if(dnscore_shuttingdown())
        {
            /* Yes, it means there will be a "leak" but the app is shutting down anyway ... */
            
            ret = STOPPED_BY_APPLICATION_SHUTDOWN;
            zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
            log_warn("zone write axfr: %{dnsname}: %r", data_zone_origin, ret);

            data->return_code = ret;
            data_zone->axfr_timestamp = 1;

#if DNSCORE_HAS_TCP_MANAGER
            if(ISOK(ret = message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcp_manager_socket(sctx))))
            {
                tcp_manager_write_update(sctx, ret);
            }
            tcp_manager_close(sctx);
#else
            message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcpfd);
#endif
            zdb_zone_answer_axfr_thread_exit(data);

#if !DNSCORE_HAS_TCP_MANAGER
            tcp_set_abortive_close(tcpfd);
        close_ex(tcpfd);
#endif
            message_free(mesg);
            return NULL;
        }
                
        // get the file path and name
        
        if(FAIL(ret = zdb_zone_path_get_provider()(
                data_zone_origin, 
                buffer, sizeof(buffer),
                ZDB_ZONE_PATH_PROVIDER_AXFR_FILE|ZDB_ZONE_PATH_PROVIDER_MKDIR)))
        {
            // failed to get the name
            
            zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER); // RC decremented
            log_err("zone write axfr: %{dnsname}: unable to get path: %r", data_zone_origin, ret);
            data->return_code = ret;

#if DNSCORE_HAS_TCP_MANAGER
            if(ISOK(ret = message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcp_manager_socket(sctx))))
            {
                tcp_manager_write_update(sctx, ret);
            }
            tcp_manager_close(sctx);
#else
            message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcpfd);
#endif
            zdb_zone_answer_axfr_thread_exit(data);

#if !DNSCORE_HAS_TCP_MANAGER
            tcp_set_abortive_close(tcpfd);
        close_ex(tcpfd);
#endif
            message_free(mesg);
            return NULL;
        }
        
        path_len = ret;
        
        u32 axfr_dump_age = (now >= data_zone->axfr_timestamp)?now - data_zone->axfr_timestamp:0;
        
        // try to set the dumping axfr status

        bool have_writing_rights = !zdb_zone_get_set_dumping_axfr(data_zone);
        
        // if status didn't had the flag, we have ownership

        bool too_old = (axfr_dump_age > ZDB_ZONE_AXFR_MINIMUM_DUMP_PERIOD);
        bool different_serial = (data_zone->axfr_serial != serial);
        bool cannot_be_followed = FALSE;
        
        // the too_old rule should be instant if the zone on disk cannot be followed by the journal
        
        if(journal_from != journal_to)
        {
            if(serial_lt(data_zone->axfr_serial, journal_from))
            {
                log_debug("zone write axfr: %{dnsname}: serial of axfr image older than journal start (%u lt %u)", data_zone_origin, data_zone->axfr_serial, journal_from);
                cannot_be_followed = TRUE;
            }
        }
        else
        {
            cannot_be_followed = TRUE;
        }
        
        bool should_write = have_writing_rights && (different_serial && (too_old || cannot_be_followed));
        
        if(!should_write && have_writing_rights)
        {
            should_write = access(buffer, R_OK | F_OK) < 0;
        }
        
        if(should_write)
        {
            // the serial on disk is not the one in memory AND
            // it has been written a sufficient long time ago ...
            // it is not being written
            
            log_debug("zone write axfr: %{dnsname}: serial = %d, zone serial = %d; AXFR timestamp = %d; last written %d seconds ago",
                      data_zone_origin,
                      data_zone->axfr_serial,
                      serial,
                      data_zone->axfr_timestamp,
                      axfr_dump_age);
            
            // trigger a new update : delete the old files
            
            unlink(buffer);

            yassert((path_len > 0) && ((u32)path_len < sizeof(buffer) - 6));
            
            memcpy(&buffer[path_len], ".part", 6);
            unlink(buffer); // trigger a new update
            
            // create a new file (pathpart)
            
            log_info("zone write axfr: %{dnsname}: storing at serial %d", data_zone_origin, serial);

            if(FAIL(ret = file_output_stream_create_excl(&os, buffer, 0644)))
            {
                zdb_zone_clear_dumping_axfr(data_zone);
                
                log_debug("zone write axfr: %{dnsname}: could not exclusively create '%s': %r", data_zone_origin, buffer, ret);
                
                if(ret == MAKE_ERRNO_ERROR(EEXIST))
                {
                    log_err("zone write axfr: %{dnsname}: file unexpectedly exists '%s': %r", data_zone_origin, buffer, ret);
                    // race condition creating the file : try again
                    
                    continue;
                }
                
                zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER); // RC decremented
                
                log_err("zone write axfr: %{dnsname}: file create error for '%s': %r", data_zone_origin, buffer, serial, ret);
                
                data->return_code = ret;

#if DNSCORE_HAS_TCP_MANAGER
                if(ISOK(ret = message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcp_manager_socket(sctx))))
                {
                    tcp_manager_write_update(sctx, ret);
                }
                tcp_manager_close(sctx);
#else
                message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcpfd);
#endif
                zdb_zone_answer_axfr_thread_exit(data);

#if !DNSCORE_HAS_TCP_MANAGER
                tcp_set_abortive_close(tcpfd);
                close_ex(tcpfd);
#endif
                message_free(mesg);
                return NULL;
            }

            /*
             * Return value check irrelevant here.  It can only fail if the filtered stream has a NULL vtbl
             * This is not the case here since we just opened successfully the file stream.
             */
            
            data_zone->axfr_timestamp = 0;

            /*
             * Now that the file has been created, the background writing thread can be called
             * the readers will wait "forever" that the file is written but they need the file to exist
             */

            zdb_zone_answer_axfr_write_file_args *store_axfr_args;
            MALLOC_OR_DIE(zdb_zone_answer_axfr_write_file_args*, store_axfr_args, sizeof(zdb_zone_answer_axfr_write_file_args), ZAAXFRWF_TAG);
            store_axfr_args->os = os;
            
            store_axfr_args->pathpart = strdup(buffer);
            
            buffer[path_len] = '\0';
            store_axfr_args->path = strdup(buffer);
            
            store_axfr_args->zone = data->zone;
            store_axfr_args->serial = serial;
            store_axfr_args->return_code = SUCCESS;

            /*
             * This is how it is supposed to be.  Double lock, unlocked when the file has been stored.
             * Again: do not try to remove this lock.
             */

            zdb_zone_acquire(data_zone);
            zdb_zone_lock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER); // RC was already + 1 by the (async) caller

            log_debug("zone write axfr: %{dnsname}: zone with serial %d is being written on disk", data_zone_origin, serial);
            
            // the ZDB_ZONE_STATUS_DUMPING_AXFR status will be cleared in the thread
            
            if(data->disk_tp != NULL)
            {
                thread_pool_enqueue_call(data->disk_tp, zdb_zone_answer_axfr_write_file_thread, store_axfr_args, NULL, "zone-writer-axfr");
            }
            else
            {
                zdb_zone_answer_axfr_write_file_thread(store_axfr_args);
            }
            
            // the file seems ok, let's start streaming it
            ret = zdb_zone_axfr_input_stream_open_with_path(&fis, data_zone, buffer);
            
            if(FAIL(ret))
            {
                // opening failed but it should not have : try again
                if(countdown > 0)
                {
                    log_debug("zone write axfr: %{dnsname}: after write, could not open %s: %r", data_zone_origin, buffer, ret);
                }
                else
                {
                    log_warn("zone write axfr: %{dnsname}: after write, could not open %s: %r", data_zone_origin, buffer, ret);
                }
                continue;
            }
            
            data->return_code = SUCCESS;
            
            log_debug("zone write axfr: %{dnsname}: zone with serial %d is being written on disk", data_zone_origin, serial);
            
            zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
            data_zone = NULL;
#if DNSCORE_HAS_TCP_MANAGER
            sctx = tcp_manager_context_acquire(sctx); // because it will be release zdb_zone_answer_axfr_thread_exit
#endif
            zdb_zone_answer_axfr_thread_exit(data);
            data = NULL; // This ensures a crash if data is used
            break;
        }
        else
        {
            // if !have_writing_rights, somebody is writing the part file,
            // that's the one that should be followed
            
            if(!have_writing_rights)
            {
                memcpy(&buffer[path_len], ".part", 6);
                
                if(access(buffer, R_OK | F_OK) >= 0)
                {
                    // file exists and the file seems usable, let's start streaming it

                    ret = zdb_zone_axfr_input_stream_open_with_path(&fis, data_zone, buffer);

                    if(FAIL(ret))
                    {
                        // opening failed but it should not have: try again
                        log_warn("zone write axfr: %{dnsname}: could not open %s: %r", data_zone_origin, buffer, ret);
                        
                        // or servfail ?
                        
                        continue;
                    }

                    data->return_code = SUCCESS;

                    log_info("zone write axfr: %{dnsname}: releasing implicit write lock, serial is %d", data_zone_origin, serial);
                    zdb_zone_acquire(data_zone);
#if DNSCORE_HAS_TCP_MANAGER
                    sctx = tcp_manager_context_acquire(sctx); // because it will be release zdb_zone_answer_axfr_thread_exit
#endif
                    zdb_zone_answer_axfr_thread_exit(data); // WARNING: From this point forward, 'data' cannot be used anymore 
                    data = NULL;                            //          This ensures a crash if data is used
                    zdb_zone_release_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                    data_zone = NULL;

                    break;
                }
                
                // file could not be properly accessed, maybe it just finished
                buffer[path_len] = '\0';
            }
            
            if(access(buffer, R_OK | F_OK) >= 0)
            {
                // file exists and the file seems usable, let's start streaming it

                ret = zdb_zone_axfr_input_stream_open_with_path(&fis, data_zone, buffer);

                if(have_writing_rights)
                {
                    zdb_zone_clear_dumping_axfr(data_zone);
                }

                if(FAIL(ret))
                {
                    // opening failed but it should not have: try again
                    
                    log_warn("zone write axfr: %{dnsname}: could not open %s: %r", data_zone_origin, buffer, ret);

                    continue;
                }

                data->return_code = SUCCESS;

                log_info("zone write axfr: %{dnsname}: releasing implicit write lock, serial is %d", data_zone_origin, serial);
                zdb_zone_acquire(data_zone);
#if DNSCORE_HAS_TCP_MANAGER
                sctx = tcp_manager_context_acquire(sctx); // because it will be release zdb_zone_answer_axfr_thread_exit
#endif
                zdb_zone_answer_axfr_thread_exit(data); // WARNING: From this point forward, 'data' cannot be used anymore 
                data = NULL;                            //          This ensures a crash if data is used
                zdb_zone_release_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                data_zone = NULL;

                break;
            }
                            
            // file does not exist, or there is an error accessing the file
            
            if(have_writing_rights)
            {
                zdb_zone_clear_dumping_axfr(data_zone);
            }

            if(errno != ENOENT)
            {
                // the error is not that the file does not exists : give up

                if(have_writing_rights)
                {
                    zdb_zone_clear_dumping_axfr(data_zone);
                }

                ret = ERRNO_ERROR;
                zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER); // RC decremented
                log_err("zone write axfr: %{dnsname}: error accessing '%s': %r", data_zone_origin, buffer, ret);

                data->return_code = ret;

                data_zone->axfr_timestamp = 1;

#if DNSCORE_HAS_TCP_MANAGER
                if(ISOK(ret = message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcp_manager_socket(sctx))))
                {
                    tcp_manager_write_update(sctx, ret);
                }
                tcp_manager_close(sctx);
#else
                message_make_error_and_reply_tcp(mesg, RCODE_SERVFAIL, tcpfd);
#endif
                zdb_zone_answer_axfr_thread_exit(data);

#if !DNSCORE_HAS_TCP_MANAGER
                tcp_set_abortive_close(tcpfd);
        close_ex(tcpfd);
#endif
                message_free(mesg);
                return NULL;
            }
            
            // could not access any of the two expected files, try again
        }
    } // for(;;)

    /******************************************************************************************************************
     *
     * data pointer cannot be used beyond this point
     *
     ******************************************************************************************************************/
    
    message_set_buffer_size(mesg, 0x8000); // limit to 32KB, knowing perfectly well the buffer is actually 64KB

    log_info("zone write axfr: %{dnsname}: sending AXFR with serial %d", data_zone_origin, serial);
    
#if DEBUG
    if(fis.data == NULL)
    {
        log_err("zone write axfr: %{dnsname}: empty stream", data_zone_origin);
        goto scheduler_queue_zone_write_axfr_thread_exit;
    }
#endif

#define USE_TCPOS 0
    
#if USE_TCPOS    
    output_stream tcpos;
    fd_output_stream_attach(&tcpos, tcpfd);
    buffer_output_stream_init(&tcpos, &tcpos, TCP_BUFFER_SIZE);
#endif
    
    buffer_input_stream_init(&fis, &fis, FILE_BUFFER_SIZE);

    // The correct AXFR answer sets authoritative
    message_set_authoritative_answer(mesg);
    // Microsoft DNS server do not set the authoritative flag
    //message_set_answer(mesg);

    message_set_answer_count_ne(mesg, NETWORK_ONE_16);

    packet_writer pw;
    u32 packet_count = 0;
    u16 an_count = 0;

    // @note 20091223 edf -- With TSIG enabled this limit will be dynamic and change to a lower bound for every 100th packet
#if ZDB_HAS_TSIG_SUPPORT
    tsig_tcp_message_position pos = TSIG_NOWHERE;
#endif
    
    yassert(message_get_size(mesg) <= packet_size_limit); // should have already been tested by the caller
    
    size_t message_base_size = message_get_size(mesg);

    packet_writer_init(&pw, message_get_buffer(mesg), message_base_size, packet_size_limit);

    for(;; packet_count--) /* using path as the buffer */
    {
        struct type_class_ttl_rdlen tctrl;
        ya_result qname_len;
        ya_result n;

        if(dnscore_shuttingdown())
        {
            log_info("zone write axfr: %{dnsname}: stopping transfer to %{sockaddr} because of application shutdown", data_zone_origin, message_get_sender_sa(mesg));
            break;
        }

        /* Read the next DNAME from the stored AXFR */

        if(FAIL(qname_len = input_stream_read_dnsname(&fis, (u8*)buffer))) // length checked
        {
            /* qname_len is an error code */
            log_err("zone write axfr: %{dnsname}: error reading next record domain: %r", data_zone_origin, qname_len);
            break;
        }

        /*
         * NOTE: There cannot be an "EMPTY" AXFR.  There is always the origin.  So I don't have to
         *       check TSIG for an empty message because there aren't any.
         */

        /* If there are no records anymore */
        if(qname_len == 0)
        {
            /* If records are still to be sent */
            if(an_count > 0)
            {
                /* write them */

                message_set_authoritative_answer(mesg);
                message_set_size(mesg, packet_writer_get_offset(&pw));
                message_set_answer_count(mesg, an_count);
                
#if ZDB_HAS_TSIG_SUPPORT
                if(message_has_tsig(mesg))
                {
                    message_set_additional_section_ptr(mesg, packet_writer_get_next_u8_ptr(&pw));
                    message_reset_buffer_size(mesg);
                    
                    if(pos != TSIG_START)
                    {
                        ret = tsig_sign_tcp_message(mesg, pos);
                    }
                    else
                    {
                        ret = tsig_sign_answer(mesg);
                    }

                    if(FAIL(ret))
                    {
                        log_err("zone write axfr: %{dnsname}: failed to sign the answer: %r", data_zone_origin, ret);
                        break;
                    }
                
                    packet_writer_set_offset(&pw, message_get_size(mesg));
                    
                } /* if message_has_tsig */
#endif

#if DEBUG_AXFR_MESSAGES
                LOGGER_EARLY_CULL_PREFIX(MSG_DEBUG) message_log(MODULE_MSG_HANDLE, MSG_DEBUG, mesg);
#endif

#if DNSCORE_HAS_TCP_MANAGER
                if(ISOK(n = message_send_tcp(mesg, tcp_manager_socket(sctx))))
                {
                    tcp_manager_write_update(sctx, n);
                }
                else
                {
                    log_err("zone write axfr: %{dnsname}: error sending AXFR packet to %{sockaddr}: %r", data_zone_origin, message_get_sender_sa(mesg), n);
                }
#else
#if USE_TCPOS
                if(ISOK(n = message_write_tcp(mesg, &tcpos)))
#else
                if(ISOK(n = message_send_tcp(mesg, tcpfd)))
#endif
                {
                }
                else
                {
                    log_err("zone write axfr: %{dnsname}: error sending AXFR packet to %{sockaddr}: %r", data_zone_origin, message_get_sender_sa(mesg), n);
                }
#endif
                total_bytes_sent += message_get_size(mesg);
                
                message_set_buffer_size(mesg, 0x8000); // limit to 32KB, knowing perfectly well the buffer is actually 64KB

                // in effect, an_records_count = 0;
            }

            break; /* done */
        }

        /* read the next type+class+ttl+rdatalen from the stored AXFR */

        if(FAIL(n = input_stream_read_fully(&fis, &tctrl, 10)))
        {
            log_err("zone write axfr: %{dnsname}: error reading record: %r", data_zone_origin, n);
            break;
        }

        u16 rdata_len = ntohs(tctrl.rdlen);
        
        // if for any reason the rdata_len is bigger than the 4K buffer size (not supposed to happen as even keys are not bigger than 1K)
        
        if(rdata_len > sizeof(buffer))
        {
            log_err("zone write axfr: %{dnsname}: record data length is too big (%i)", data_zone_origin, rdata_len);
#if DEBUG
            log_memdump(g_database_logger, MSG_DEBUG, &tctrl, 10, 16);
#endif
            break;
        }

        s32 record_len = qname_len + 10 + rdata_len;

        /* Check if we have enough room available for the next record */
        
        s32 remaining_capacity = (packet_writer_get_limit(&pw) / 2) - packet_writer_get_offset(&pw);
        
        if((an_count >= packet_records_limit) || (remaining_capacity < record_len))
        {
            // not enough room
            
            if(an_count == 0)
            {
                log_err("zone write axfr: %{dnsname}: error preparing packet: next record is too big (%d)", data_zone_origin, record_len);

                break;
            }

            message_set_authoritative_answer(mesg);
            message_set_answer_count(mesg, an_count);
            message_set_size(mesg, packet_writer_get_offset(&pw));

#if ZDB_HAS_TSIG_SUPPORT
            if(message_has_tsig(mesg))
            {
                message_reset_buffer_size(mesg);
                
                message_set_additional_section_ptr(mesg, packet_writer_get_next_u8_ptr(&pw));

                if(FAIL(ret = tsig_sign_tcp_message(mesg, pos)))
                {
                    log_err("zone write axfr: %{dnsname}: failed to sign the answer: %r", data_zone_origin, ret);
                    break;
                }
                
                packet_writer_set_offset(&pw, message_get_size(mesg));
            }
#endif
            /* Flush the packet. */

#if DEBUG_AXFR_MESSAGES
            LOGGER_EARLY_CULL_PREFIX(MSG_DEBUG) message_log(MODULE_MSG_HANDLE, MSG_DEBUG, mesg);
#endif

#if DNSCORE_HAS_TCP_MANAGER
            if(ISOK(n = message_send_tcp(mesg, tcp_manager_socket(sctx))))
            {
                tcp_manager_write_update(sctx, n);
            }
            else
            {
                log_err("zone write axfr: %{dnsname}: error sending packet to %{sockaddr}: %r", data_zone_origin, message_get_sender_sa(mesg), n);
                break;
            }
#else
#if USE_TCPOS
            if(FAIL(n = message_write_tcp(mesg, &tcpos)))
#else
            if(FAIL(n = message_send_tcp(mesg, tcpfd)))
#endif
            {
                log_err("zone write axfr: %{dnsname}: error sending packet to %{sockaddr}: %r", data_zone_origin, message_get_sender_sa(mesg), n);
                break;
            }
#endif
            total_bytes_sent += message_get_size(mesg);

#if ZDB_HAS_TSIG_SUPPORT
            pos = TSIG_MIDDLE;
#endif
            an_count = 0;

            // Packet flushed ...
            // Reset the packet

            // Remove the TSIG.

            message_set_authoritative_answer(mesg);
            message_set_query_answer_authority_additional_counts_ne(mesg, NU16(1), 0, 0, 0);
            message_set_buffer_size(mesg, 0x8000); // limit to 32KB, knowing perfectly well the buffer is actually 64KB
            packet_writer_init(&pw, message_get_buffer(mesg), message_base_size, packet_size_limit);
        }

        /** NOTE: if tctrl.qtype == TYPE_SOA, then we are at the beginning OR the end of the AXFR stream */

#if ZDB_HAS_TSIG_SUPPORT
        if(tctrl.qtype == TYPE_SOA)
        {
            /* First SOA will make the pos move from NOWHERE to BEGIN */
            /* Second SOA will make the pos move from MIDDLE to END */
            /* EXCEPT that if there is only 1 packet for the whole zone the value must be TSIG_START */
            if(pos != TSIG_START)
            {
                pos++;
            }
        }
#endif
        an_count++;

        packet_writer_add_fqdn(&pw, (const u8*)buffer);

        packet_writer_add_bytes(&pw, (const u8*)&tctrl, 10);

        if(compress_dname_rdata != 0)
        {
            u16 rdata_offset = packet_writer_get_offset(&pw);

            switch(tctrl.qtype)
            {
                case TYPE_MX:
                {
                    if(FAIL(n = input_stream_read_fully(&fis, buffer, rdata_len)))
                    {
                        log_err("zone write axfr: %{dnsname}: error reading MX record: %r", data_zone_origin, n);

                        /*
                         * GOTO !!! (thread carefully)
                         */
                        
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    
                    // verify fqdn
                    u32 len = dnsname_len((const u8*)&buffer[2]);
                    if(len > MAX_DOMAIN_LENGTH)
                    {
                        log_err("zone write axfr: %{dnsname}: rdata fqdn is too long", data_zone_origin);
                        
                        /*
                         * GOTO !!! (thread carefully)
                         */
                        
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    if(len + 2 != rdata_len)
                    {
                        log_err("zone write axfr: %{dnsname}: expected rdata of %i bytes but got %i", data_zone_origin, n,
                                rdata_len, len + 2);
                        
                        /*
                         * GOTO !!! (thread carefully)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_bytes(&pw, (const u8*)buffer, 2);
                    packet_writer_add_fqdn(&pw, (const u8*)&buffer[2]);
                    SET_U16_AT(pw.packet[rdata_offset - 2], htons(pw.packet_offset - rdata_offset)); // set RDATA size
                    
                    continue;
                }

                case TYPE_NS:
                case TYPE_CNAME:
                case TYPE_DNAME:
                case TYPE_PTR:
                case TYPE_MB:
                case TYPE_MD:
                case TYPE_MF:
                case TYPE_MG:
                case TYPE_MR:
                {
                    if(FAIL(n = input_stream_read_fully(&fis, buffer, rdata_len))) // rdata_len < sizeof(buffer)
                    {
                        log_err("zone write axfr: %{dnsname}: error reading %{dnstype} record: %r", data_zone_origin, &tctrl.qtype, n);
                        
                        /*
                         * GOTO !!! (thread carefully)
                         */
                        
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    
                    // verify fqdn
                    u32 len = dnsname_len((const u8*)buffer);
                    if(len > MAX_DOMAIN_LENGTH)
                    {
                        log_err("zone write axfr: %{dnsname}: rdata fqdn is too long", data_zone_origin);
                        
                        /*
                         * GOTO !!! (thread carefully)
                         */
                        
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    if(len != rdata_len)
                    {
                        log_err("zone write axfr: %{dnsname}: expected rdata of %i bytes but got %i", data_zone_origin, n,
                                rdata_len, len);
                        
                        /*
                         * GOTO !!! (thread carefully)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    // the write buffer is bigger than the limit and the fqdn size has been verified
                    packet_writer_add_fqdn(&pw, (const u8*)buffer);
                    SET_U16_AT(pw.packet[rdata_offset - 2], htons(pw.packet_offset - rdata_offset)); // set RDATA size

                    continue;
                }
                case TYPE_SOA:
                {
                    if(FAIL(n = input_stream_read_fully(&fis, buffer, rdata_len))) // rdata_len < sizeof(buffer)
                    {
                        log_err("zone write axfr: %{dnsname}: error reading SOA record: %r", data_zone_origin, n);
                        
                        /*
                         * GOTO !!! (thread carefully)
                         */
                        
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    
                    // verify fqdn
                    const u8 *m = (const u8*)buffer;
                    u32 mlen = dnsname_len(m);
                    
                    if(mlen > MAX_DOMAIN_LENGTH)
                    {
                        log_err("zone write axfr: %{dnsname}: mname is too long", data_zone_origin);
                        
                        /*
                         * GOTO !!! (thread carefully)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    
                    const u8 *r = &m[mlen];
                    
                    u32 rlen = dnsname_len(r);
                    
                    if(rlen > MAX_DOMAIN_LENGTH)
                    {
                        log_err("zone write axfr: %{dnsname}: rname is too long", data_zone_origin);
                        
                        /*
                         * GOTO !!! (thread carefully)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    if(mlen + rlen + 20 != rdata_len)
                    {
                        log_err("zone write axfr: %{dnsname}: expected rdata of %i bytes but got %i", data_zone_origin, n,
                                rdata_len, mlen + rlen + 20);
                        
                        /*
                         * GOTO !!! (thread carefully)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    
                    // the write buffer is bigger than the limit and the fqdn size has been verified
                    packet_writer_add_fqdn(&pw, m);
                    // the write buffer is bigger than the limit and the fqdn size has been verified
                    packet_writer_add_fqdn(&pw, r);
                    packet_writer_add_bytes(&pw, &r[rlen], 20);

                    SET_U16_AT(pw.packet[rdata_offset - 2], htons(pw.packet_offset - rdata_offset)); // set RDATA size
                    
                    continue;
                }

                case TYPE_RRSIG:
                {
                    if(FAIL(n = input_stream_read_fully(&fis, buffer, rdata_len))) // rdata_len < sizeof(buffer)
                    {
                        log_err("zone write axfr: %{dnsname}: error reading RRSIG record: %r", data_zone_origin, n);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    
                    s32 remaining = rdata_len;
                    remaining -= RRSIG_RDATA_HEADER_LEN;
                    
                    if(remaining < 0)
                    {
                        log_err("zone write axfr: %{dnsname}: error reading RRSIG record: rdata is too short", data_zone_origin);

                        /*
                         * GOTO !!! (thread carefully )
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_bytes(&pw, (const u8*)buffer, RRSIG_RDATA_HEADER_LEN);
                    
                    const u8 *o = (const u8*)&buffer[18];
                    u32 olen = dnsname_len(o);
                    remaining -= olen;
                    
                    if(remaining < 0)
                    {
                        log_err("zone write axfr: %{dnsname}: error reading RRSIG record: rdata is too short", data_zone_origin);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_fqdn(&pw, o);
                    
                    packet_writer_add_bytes(&pw, &o[olen], remaining);

                    SET_U16_AT(pw.packet[rdata_offset - 2], htons(pw.packet_offset - rdata_offset)); // set RDATA size

                    continue;
                }
            } // switch
        } // if

        // not a case handled with compression : raw copy
        
        while(rdata_len > 0)
        {
            if((n = input_stream_read(&fis, (u8*)buffer, MIN(rdata_len, sizeof(buffer)))) <= 0)
            {
                if(n == 0)
                {
                    break;
                }

                log_err("zone write axfr: %{dnsname}: error reading %{dnstype} rdata: %r", data_zone_origin, &tctrl.qtype, n);

                /*
                 * GOTO !!! (thread carefully)
                 */

                goto scheduler_queue_zone_write_axfr_thread_exit;
            }
            
#if DEBUG
            if(packet_writer_get_remaining_capacity(&pw) < n)
            {
                log_err("zone write axfr: %{dnsname}: would store %i bytes when %i were expected and %i remaining, from %i",
                        data_zone_origin,
                        n,
                        rdata_len,
                        packet_writer_get_remaining_capacity(&pw),
                        remaining_capacity
                        );
                
                /*
                 * GOTO !!! (thread carefully)
                 */

                goto scheduler_queue_zone_write_axfr_thread_exit;
            }
#endif

            packet_writer_add_bytes(&pw, (const u8*)buffer, n);

            rdata_len -= n;
        }
    } // for

    /**
     * GOTO !!!
     */

scheduler_queue_zone_write_axfr_thread_exit:

#if DNSCORE_HAS_TCP_MANAGER
    if(sctx != NULL)
    {
        tcp_manager_context_release(sctx);
    }
#endif

    log_info("zone write axfr: %{dnsname}: closing file, %llu bytes sent to %{sockaddr}", data_zone_origin, total_bytes_sent, message_get_sender_sa(mesg));

#if DNSCORE_HAS_TCP_MANAGER
#if DEBUG
    log_debug("zone write axfr: %{dnsname}: closing socket %i", data_zone_origin, tcp_manager_socket(sctx));
#endif
#else
#if DEBUG
    log_debug("zone write axfr: %{dnsname}: closing socket %i", data_zone_origin, tcpfd);
#endif
    
#if USE_TCPOS
    output_stream_close(&tcpos);
#else
    close_ex(tcpfd);
#endif
#endif
    if(input_stream_valid(&fis))
    {
        input_stream_close(&fis);
    }

    message_free(mesg);

    return NULL;
}

#if DNSCORE_HAS_TCP_MANAGER
void
zdb_zone_answer_axfr(zdb_zone *zone, message_data *mesg, tcp_manager_socket_context_t *sctx, struct thread_pool_s *network_tp, struct thread_pool_s *disk_tp, u16 max_packet_size, u16 max_record_by_packet, bool compress_packets)
#else
void
zdb_zone_answer_axfr(zdb_zone *zone, message_data *mesg, int sockfd, struct thread_pool_s *network_tp, struct thread_pool_s *disk_tp, u16 max_packet_size, u16 max_record_by_packet, bool compress_packets)
#endif
{
    zdb_zone_answer_axfr_thread_args* args;
    
    log_info("zone write axfr: %{dnsname}: queueing", zone->origin);
    
    if(message_get_size(mesg) >= max_packet_size)
    {
        log_err("zone write axfr: %{dnsname}: received message is already bigger than maximum message size in answer: cancelled",
                zone->origin);
        return;
    }
        
    MALLOC_OBJECT_OR_DIE(args, zdb_zone_answer_axfr_thread_args, SHDQZWAA_TAG);

    ya_result ret;
    if(FAIL(ret = zdb_zone_journal_get_serial_range(zone, &args->journal_from, &args->journal_to)))
    {
        log_debug("zone write axfr: %{dnsname}: could not get the serial range of the journal: %r", zone->origin, ret);
        // ZDB_ERROR_ICMTL_NOTFOUND
        args->journal_from = 0;
        args->journal_to = 0;
    }

    zdb_zone_acquire(zone);
    args->zone = zone;
    args->disk_tp = disk_tp;
#if DNSCORE_HAS_TCP_MANAGER
    args->sctx = sctx;
#else
    args->sockfd = sockfd;
#endif
    args->mesg = message_dup(mesg);
    args->packet_size_limit = max_packet_size;
    args->packet_records_limit = max_record_by_packet;
    args->compress_dname_rdata = compress_packets;
    
    if(network_tp != NULL)
    {
        thread_pool_enqueue_call(network_tp, zdb_zone_answer_axfr_thread, args, NULL, "zone-answer-axfr");
    }
    else
    {
        zdb_zone_answer_axfr_thread(args);
    }
}

/** @} */

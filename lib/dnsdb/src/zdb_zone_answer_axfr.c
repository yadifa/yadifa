/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup dnsdbscheduler Scheduled tasks of the database
 * @ingroup dnsdb
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>

#include "dnsdb/zdb_config_features.h"

#include <dnscore/logger.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/counter_output_stream.h>
#include <dnscore/empty_input_stream.h>
#include <dnscore/format.h>
#include <dnscore/dns_packet_writer.h>
#include <dnscore/rfc.h>
#include <dnscore/serial.h>
#include <dnscore/fdtools.h>
#include <dnscore/tcp_io_stream.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_zone_arc.h"
#include "dnsdb/zdb_zone_journal.h"
#include "dnsdb/zdb_zone_axfr_input_stream.h"

#include "dnsdb/zdb_zone_answer_axfr.h"
#include "dnsdb/zdb_zone_path_provider.h"
#include <dnscore/dns_packet_reader.h>

#define MODULE_MSG_HANDLE                    g_database_logger

#define DEBUG_AXFR_MESSAGES                  0

#define ZDB_ZONE_AXFR_MEMFILE_SIZE_THRESHOLD 65536

#define TCP_BUFFER_SIZE                      4096
#define FILE_BUFFER_SIZE                     4096

#if DEBUG
#define ZDB_ZONE_AXFR_MINIMUM_DUMP_PERIOD 1 // seconds
#else
#define ZDB_ZONE_AXFR_MINIMUM_DUMP_PERIOD 60 // seconds
#endif

extern logger_handle_t *g_database_logger;

#ifndef PATH_MAX
#error "PATH_MAX not defined"
#endif

typedef struct zdb_zone_answer_axfr_thread_args zdb_zone_answer_axfr_thread_args;

#define SHDQZWAA_TAG 0x4141575a51444853

struct zdb_zone_answer_axfr_thread_args
{
    zdb_zone_t            *zone;
    dns_message_t         *mesg;
    struct thread_pool_s  *disk_tp;
    tcp_manager_channel_t *tmc;
    ya_result              return_code;
    uint32_t               packet_size_limit;
    uint32_t               packet_records_limit;
    uint32_t               journal_from;
    uint32_t               journal_to;
    bool                   compress_dname_rdata;
    bool                   threaded;
};

typedef struct zdb_zone_answer_axfr_write_file_args zdb_zone_answer_axfr_write_file_args;

#define ZAAXFRWF_TAG 0x465752465841415a

struct zdb_zone_answer_axfr_write_file_args
{
    output_stream_t os; // (file) output stream to the AXFR file
    char           *path;
    char           *pathpart;
    zdb_zone_t     *zone;
    uint32_t        serial;
    ya_result       return_code;
};

#ifdef ZDB_ZONE_AXFR_MEMFILE_SIZE_THRESHOLD
static uint32_t g_zdb_zone_answer_axfr_memfile_size_threshold = ZDB_ZONE_AXFR_MEMFILE_SIZE_THRESHOLD;

uint32_t        zdb_zone_answer_axfr_memfile_size_threshold() { return g_zdb_zone_answer_axfr_memfile_size_threshold; }

uint32_t        zdb_zone_answer_axfr_memfile_size_threshold_set(uint32_t new_threshold)
{
    uint32_t old_threshold = g_zdb_zone_answer_axfr_memfile_size_threshold;
    g_zdb_zone_answer_axfr_memfile_size_threshold = new_threshold;
    return old_threshold;
}

#endif

static void zdb_zone_answer_axfr_thread_release_data(zdb_zone_answer_axfr_thread_args *data)
{
    log_debug("zone write axfr: %{dnsname}: finalised: %r", data->zone->origin, data->return_code);
    zdb_zone_release(data->zone);
    // free(data->directory);
    free(data);
}

static void zdb_zone_answer_axfr_thread_exit(zdb_zone_answer_axfr_thread_args *data)
{
    log_debug("zone write axfr: %{dnsname}: ended with: %r", data->zone->origin, data->return_code);

    // tcp_manager_channel_t *tmc = data->tmc;

    zdb_zone_answer_axfr_thread_release_data(data);
}

static void zdb_zone_answer_axfr_write_file_thread(void *data_)
{
    zdb_zone_answer_axfr_write_file_args *storage = (zdb_zone_answer_axfr_write_file_args *)data_;

    // os
    // zone
    // serial
    // *return_code
    /*-----------------------------------------------------------------------*/

    buffer_output_stream_init(&storage->os, &storage->os, 4096);

    // ALEADY LOCKED BY THE CALLER SO NO NEED TO zdb_zone_lock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

#if ZDB_ZONE_KEEP_RAW_SIZE
    int64_t                         write_start_time = timeus();

    output_stream_t                 counter_stream;
    counter_output_stream_context_t counter_data;
    counter_output_stream_init(&counter_stream, &storage->os, &counter_data);

    storage->return_code = zdb_zone_store_binary(storage->zone, &counter_stream); // zone is locked

    zdb_zone_unlock(storage->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

    output_stream_flush(&counter_stream);
    output_stream_close(&counter_stream);
    output_stream_close(&storage->os);

    storage->zone->wire_size = counter_data.written_count;
    storage->zone->write_time_elapsed = timeus() - write_start_time;
#else
    storage->return_code = zdb_zone_store_axfr(storage->data->zone, &storage->os);
    zdb_zone_unlock(storage->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    output_stream_close(&storage->os);
#endif

    if(ISOK(storage->return_code))
    {
        log_info("zone write axfr: %{dnsname}: stored %d", storage->zone->origin, storage->serial);

        if((storage->pathpart != NULL) && (storage->path != NULL))
        {
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
            storage->zone->axfr_timestamp = 1;
            storage->zone->axfr_serial = storage->serial;
        }
    }
    else
    {
        log_err("zone write axfr: %{dnsname}: error writing '%s': %r", storage->zone->origin, storage->pathpart, storage->return_code);

        // cannot create error : SERVFAIL

        if(storage->pathpart != NULL)
        {
            // do not keep a broken file
            unlink(storage->pathpart);
        }

        if(storage->path != NULL)
        {
            // do not keep a broken file
            unlink(storage->path);
        }

        storage->zone->axfr_timestamp = 1;
        storage->zone->axfr_serial = storage->serial - 1;
    }

    zdb_zone_clear_dumping_axfr(storage->zone);

    zdb_zone_release(storage->zone);
    storage->zone = NULL;
    free(storage->path);
    free(storage->pathpart);
    free(storage);
}

static void zdb_zone_answer_axfr_write(zdb_zone_t *data_zone, output_stream_t *os, uint32_t serial, const char *path, const char *pathpart, struct thread_pool_s *disk_tp)
{
    zdb_zone_answer_axfr_write_file_args *store_axfr_args;
    MALLOC_OR_DIE(zdb_zone_answer_axfr_write_file_args *, store_axfr_args, sizeof(zdb_zone_answer_axfr_write_file_args), ZAAXFRWF_TAG);
    store_axfr_args->os = *os;

    store_axfr_args->pathpart = strdup(pathpart);
    store_axfr_args->path = strdup(path);

    store_axfr_args->zone = data_zone;
    store_axfr_args->serial = serial;
    store_axfr_args->return_code = SUCCESS;

    /*
     * This is how it is supposed to be.  Double lock, unlocked when the file has been stored.
     * Again: do not try to remove this lock.
     */

    zdb_zone_acquire(data_zone);
    zdb_zone_lock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER); // RC was already + 1 by the (async) caller

    log_debug("zone write axfr: %{dnsname}: zone with serial %d is being written on disk", data_zone->origin, serial);

    // the ZDB_ZONE_STATUS_DUMPING_AXFR status will be cleared in the thread

    if(disk_tp != NULL)
    {
        thread_pool_enqueue_call(disk_tp, zdb_zone_answer_axfr_write_file_thread, store_axfr_args, NULL, "zone-writer-axfr");
    }
    else
    {
        zdb_zone_answer_axfr_write_file_thread(store_axfr_args);
    }
}

static void zdb_zone_answer_axfr_thread(void *data_)
{
    zdb_zone_answer_axfr_thread_args *data = (zdb_zone_answer_axfr_thread_args *)data_;
    dns_message_t                    *mesg = data->mesg;
    zdb_zone_t                       *data_zone = data->zone; // already RCed ...
    output_stream_t                   os;
    input_stream_t                    fis;
    uint64_t                          total_bytes_sent = 0;
    char                             *buffer;
    size_t                            buffer_size;
    ya_result                         ret;
    uint32_t                          serial = 0;
    uint32_t                          now = time(NULL);
    uint32_t                          journal_from = data->journal_from;

    uint32_t                          journal_to = data->journal_to;
    int                               path_len;

    char                             *fis_filename = NULL;

    bool                              call_is_threaded = data->threaded;
    bool                              read_error = false;

    uint8_t                           data_zone_origin[DOMAIN_LENGTH_MAX];
    char                              buffer_static[PATH_MAX + 8];
    buffer = buffer_static;
    buffer_size = sizeof(buffer_static);

    tcp_manager_channel_t *tmc = data->tmc;

#if DEBUG
    log_debug("zone write axfr: %{dnsname}: socket is %d", data->zone->origin, tcp_manager_channel_socket(tmc));
#endif

    /**
     * The zone could already be dumping in the disk.
     * If it's the case, then the dump file needs to be read and sent until marked as "done".
     */

    /* locks the zone for a reader */

    dns_message_set_additional_count_ne(mesg, 0);

#if DEBUG
    log_debug("zone write axfr: %{dnsname}: locking for AXFR", data->zone->origin);
#endif

    zdb_zone_lock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

    if(zdb_zone_invalid(data_zone))
    {
        zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

        log_err("zone write axfr: %{dnsname}: marked as invalid", data_zone->origin);

        ret = tcp_manager_channel_make_error_and_send(tmc, mesg, RCODE_SERVFAIL);

        if(FAIL(ret))
        {
            log_err("zone write axfr: %{dnsname}: error sending error message: %r", data_zone->origin, ret);
        }

        zdb_zone_answer_axfr_thread_exit(data);
        dns_message_delete(mesg);
        return;
    }

#if DEBUG
    log_debug("zone write axfr: %{dnsname}: checking serial number", data_zone->origin);
#endif

    if(FAIL(zdb_zone_getserial(data_zone, &serial))) // zone is locked
    {
        zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

        log_err("zone write axfr: %{dnsname}: no SOA", data_zone->origin);

        dns_message_make_signed_error(mesg, RCODE_SERVFAIL);

        ret = tcp_manager_channel_send(tmc, mesg);

        if(FAIL(ret))
        {
            log_err("zone write axfr: %{dnsname}: error sending error message: %r", data_zone->origin, ret);
        }

        zdb_zone_answer_axfr_thread_exit(data);
        dns_message_delete(mesg);
        return;
    }

    uint32_t packet_size_limit = data->packet_size_limit;

    if(packet_size_limit < dns_message_get_buffer_size_max(mesg))
    {
        packet_size_limit = dns_message_get_buffer_size_max(mesg);
    }

    uint32_t packet_records_limit = data->packet_records_limit;

    /* If it is set to 0, it means there is no limit. */

    if(packet_records_limit == 0)
    {
        packet_records_limit = 0xffffffff;
    }

    bool compress_dname_rdata = data->compress_dname_rdata;

    dnsname_copy(data_zone_origin, data_zone->origin);

    empty_input_stream_init(&fis);

#ifdef ZDB_ZONE_AXFR_MEMFILE_SIZE_THRESHOLD
    /*
     * @note 20220209 edf -- If the zone is relatively small, there is no need to prepare an image on the disk.
     *                       Instead, snapshot to memory.
     *                       The treshold is set to 64KB (way more than the needs of 99% of use-cases)
     *                       TLDs will still use the through-storage branch of the code.
     */

    if(data->zone->wire_size < g_zdb_zone_answer_axfr_memfile_size_threshold)
    {
        output_stream_t                 counter_stream;
        counter_output_stream_context_t counter_data;
        output_stream_t                 os;
        int64_t                         write_start_ts = timeus();
        bytearray_output_stream_init_ex(&os, NULL, (data->zone->wire_size * 3) / 2, BYTEARRAY_DYNAMIC);
        counter_output_stream_init(&counter_stream, &os, &counter_data);

        if(ISOK(ret = zdb_zone_store_binary(data_zone, &counter_stream)))
        {
            output_stream_flush(&counter_stream);

            size_t   stream_size = bytearray_output_stream_size(&os);
            uint8_t *stream_buffer = bytearray_output_stream_detach(&os);
            bytearray_input_stream_init(&fis, stream_buffer, stream_size, true);

            output_stream_close(&counter_stream); // NOTE: this does virtually nothing. Counter streams do not hold
                                                  // memory nor close their filtered stream
            output_stream_close(&os);

            data_zone->wire_size = counter_data.written_count;
            data_zone->write_time_elapsed = timeus() - write_start_ts;

            data->return_code = SUCCESS;

            log_debug("zone write axfr: %{dnsname}: zone with serial %d is being written on disk", data_zone_origin, serial);
        }
        else
        {
            data_zone->wire_size = counter_data.written_count;
            data_zone->write_time_elapsed = timeus() - write_start_ts;

            data->return_code = ret;

            log_err("zone write axfr: %{dnsname}: zone with serial %d could not be written on disk: %r", data_zone_origin, serial, ret);
        }

        zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        data_zone = NULL;
        zdb_zone_answer_axfr_thread_release_data(data);
        data = NULL; // This ensures a crash if data is used
    }
    else
    {
#endif
        /*
         * The zone could be being written to the disk right now.
         *    axfr_timestamp = 0, file exists as a .part (or as a normal file, if race)
         *
         * The file could not being written to the disk
         *    axfr_timestamp != 0, file exists as a normal file
         *    axfr_timestamp = 1, no idea of the status yet
         *
         *    Whatever of these two, the file existence should be tested
         *    If the file does not exists, it should be dumped
         *
         * The file serial on disk may be too old, in that case it should be written again
         * (too old: time and/or serial increment and/or journal size)
         *
         */

        for(int_fast32_t countdown = 5; countdown >= 0; --countdown)
        {
            if(countdown == 0)
            {
                // tried to many times: servfail

                zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

                data->return_code = ZDB_ERROR_COULDNOTOOBTAINZONEIMAGE; // AXFR file creation failed
                log_warn("zone write axfr: %{dnsname}: could not prepare file", data_zone_origin);

                dns_message_make_error(mesg, FP_CANNOT_HOLD_AXFR_DATA);
                if(dns_message_has_tsig(mesg))
                {
                    tsig_sign_answer(mesg);
                }

#if DEBUG_AXFR_MESSAGES
                LOGGER_EARLY_CULL_PREFIX(MSG_DEBUG) message_log(MODULE_MSG_HANDLE, MSG_DEBUG, mesg);
#endif

                ret = tcp_manager_channel_send(tmc, mesg);

                if(FAIL(ret))
                {
                    log_warn("zone write axfr: %{dnsname}: tcp write error: %r", data_zone_origin, ret);
                    tcp_set_abortive_close(tcp_manager_channel_socket(tmc));
                }
                zdb_zone_answer_axfr_thread_exit(data);
                dns_message_delete(mesg);
                return;
            }

            if(dnscore_shuttingdown())
            {
                /* Yes, it means there will be a "leak" but the app is shutting down anyway ... */

                ret = STOPPED_BY_APPLICATION_SHUTDOWN;
                zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                log_warn("zone write axfr: %{dnsname}: %r", data_zone_origin, ret);

                data->return_code = ret;
                data_zone->axfr_timestamp = 1;

                ret = tcp_manager_channel_make_error_and_send(tmc, mesg, RCODE_SERVFAIL);

                if(FAIL(ret))
                {
                    log_err("zone write axfr: %{dnsname}: error sending error message: %r", data_zone->origin, ret);
                }

                zdb_zone_answer_axfr_thread_exit(data);
                dns_message_delete(mesg);
                return;
            }

            // get the file path and name

            if(FAIL(ret = zdb_zone_path_get_provider()(data_zone_origin, buffer, buffer_size, ZDB_ZONE_PATH_PROVIDER_AXFR_FILE | ZDB_ZONE_PATH_PROVIDER_MKDIR)))
            {
                // failed to get the name

                zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER); // RC decremented
                log_err("zone write axfr: %{dnsname}: unable to get path: %r", data_zone_origin, ret);
                data->return_code = ret;

                ret = tcp_manager_channel_make_error_and_send(tmc, mesg, RCODE_SERVFAIL);

                if(FAIL(ret))
                {
                    log_err("zone write axfr: %{dnsname}: error sending error message: %r", data_zone->origin, ret);
                }

                zdb_zone_answer_axfr_thread_exit(data);
                dns_message_delete(mesg);
                return;
            }

            path_len = ret;

            uint32_t axfr_dump_age = (now >= data_zone->axfr_timestamp) ? now - data_zone->axfr_timestamp : 0;

            // try to set the dumping axfr status

            bool have_writing_rights = !zdb_zone_get_set_dumping_axfr(data_zone);

            // if status didn't have the flag, we have ownership

            bool too_old = (axfr_dump_age > ZDB_ZONE_AXFR_MINIMUM_DUMP_PERIOD);
            bool different_serial = (data_zone->axfr_serial != serial);
            bool cannot_be_followed = false;

            // the too_old rule should be instant if the zone on disk cannot be followed by the journal

            if(journal_from != journal_to)
            {
                if(serial_lt(data_zone->axfr_serial, journal_from))
                {
                    log_debug("zone write axfr: %{dnsname}: serial of axfr image older than journal start (%u lt %u)", data_zone_origin, data_zone->axfr_serial, journal_from);
                    cannot_be_followed = true;
                }
            }
            else
            {
                cannot_be_followed = true;
            }

            bool should_write = have_writing_rights && (different_serial && (too_old || cannot_be_followed));

            if(!should_write && have_writing_rights)
            {
                // if the file cannot be read (most likely doesn't exist) then it should be written
                should_write = FAIL(access_check(buffer, ACCESS_CHECK_READ));
            }

            if(should_write)
            {
                // the serial on disk is not the one in memory AND
                // it has been written a sufficient long time ago ...
                // it is not being written

                log_debug(
                    "zone write axfr: %{dnsname}: serial = %d, zone serial = %d; AXFR timestamp = %d; last written %d "
                    "seconds ago",
                    data_zone_origin,
                    data_zone->axfr_serial,
                    serial,
                    data_zone->axfr_timestamp,
                    axfr_dump_age);

                // trigger a new update : delete the old files

                unlink(buffer);

                yassert((path_len > 0) && ((uint32_t)path_len < buffer_size - 6));

                memcpy(&buffer[path_len], ".part", 6);
                unlink(buffer); // trigger a new update

                // create a new file (pathpart)

                log_info("zone write axfr: %{dnsname}: storing at serial %d", data_zone_origin, serial);

                if(FAIL(ret = file_output_stream_create_excl(&os, buffer, 0644)))
                {
                    // clear the "dumping" flag
                    zdb_zone_clear_dumping_axfr(data_zone);

                    log_debug("zone write axfr: %{dnsname}: could not exclusively create '%s': %r", data_zone_origin, buffer, ret);

                    if(ret == MAKE_ERRNO_ERROR(EEXIST))
                    {
                        log_err("zone write axfr: %{dnsname}: file unexpectedly exists '%s': %r", data_zone_origin, buffer, ret);
                        // race condition creating the file : try again

                        continue;
                    }

                    zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER); // RC decremented

                    log_err("zone write axfr: %{dnsname}: file create error for '%s': %r", data_zone_origin, buffer, ret);

                    data->return_code = ret;

                    ret = tcp_manager_channel_make_error_and_send(tmc, mesg, RCODE_SERVFAIL);

                    if(FAIL(ret))
                    {
                        log_err("zone write axfr: %{dnsname}: error sending error message: %r", data_zone->origin, ret);
                    }

                    zdb_zone_answer_axfr_thread_exit(data);
                    dns_message_delete(mesg);
                    return;
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

                char *pathpart = strdup(buffer);
                buffer[path_len] = '\0';
                const char *path = buffer;
                zdb_zone_answer_axfr_write(data_zone, &os, serial, path, pathpart, data->disk_tp);
                free(pathpart);

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

                fis_filename = strdup(buffer);
                data->return_code = SUCCESS;

                log_debug("zone write axfr: %{dnsname}: zone with serial %d is being written on disk", data_zone_origin, serial);

                zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                data_zone = NULL;
                zdb_zone_answer_axfr_thread_release_data(data);
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

                        fis_filename = strdup(buffer);
                        data->return_code = SUCCESS;

                        log_info("zone write axfr: %{dnsname}: releasing implicit write lock, serial is %d", data_zone_origin, serial);
                        zdb_zone_acquire(data_zone);
                        zdb_zone_answer_axfr_thread_release_data(data); // WARNING: From this point forward, 'data' cannot be used anymore
                        data = NULL;                                    //          This ensures a crash if data is used
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

                    fis_filename = strdup(buffer);
                    data->return_code = SUCCESS;

                    log_info("zone write axfr: %{dnsname}: releasing implicit write lock, serial is %d", data_zone_origin, serial);
                    zdb_zone_acquire(data_zone);
                    zdb_zone_answer_axfr_thread_release_data(data); // WARNING: From this point forward, 'data' cannot be used anymore
                    data = NULL;                                    //          This ensures a crash if data is used
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

                    ret = tcp_manager_channel_make_error_and_send(tmc, mesg, RCODE_SERVFAIL);

                    if(FAIL(ret))
                    {
                        log_err("zone write axfr: %{dnsname}: error sending error message: %r", data_zone->origin, ret);
                    }

                    zdb_zone_answer_axfr_thread_exit(data);
                    dns_message_delete(mesg);
                    return;
                }

                // could not access any of the two expected files, try again
            }
        } // for(;;)
#if ZDB_ZONE_AXFR_MEMFILE_SIZE_THRESHOLD
    }
#endif

    /******************************************************************************************************************
     *
     * data pointer cannot be used beyond this point
     *
     ******************************************************************************************************************/

    dns_message_set_buffer_size(mesg, 0x8000); // limit to 32KB, knowing perfectly well the buffer is actually 64KB

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
    output_stream_t tcpos;
    fd_output_stream_attach(&tcpos, tcpfd);
    buffer_output_stream_init(&tcpos, &tcpos, TCP_BUFFER_SIZE);
#endif

    if(!bytearray_input_stream_is_instance_of(&fis))
    {
        buffer_input_stream_init(&fis, &fis, FILE_BUFFER_SIZE);
    }

    // The correct AXFR answer sets authoritative
    dns_message_set_authoritative_answer(mesg);
    // Microsoft DNS server do not set the authoritative flag
    // message_set_answer(mesg);

    dns_message_set_answer_count_ne(mesg, NETWORK_ONE_16);

#if ZDB_HAS_TSIG_SUPPORT
    tsig_tcp_message_position pos = TSIG_NOWHERE;
#endif
    uint16_t            an_count = 0;

    dns_packet_writer_t pw;
    dns_packet_reader_t purd;

    // @note 20091223 edf -- With TSIG enabled this limit will be dynamic and change to a lower bound for every 100th
    // packet

    yassert(dns_message_get_size(mesg) <= packet_size_limit); // should have already been tested by the caller

    dns_message_set_authority_additional_counts_ne(mesg, 0, 0);

    dns_packet_reader_init(&purd, dns_message_get_buffer(mesg), dns_message_get_size(mesg));
    dns_packet_reader_set_position(&purd, DNS_HEADER_LENGTH);
    if(FAIL(ret = dns_packet_reader_skip_query_section(&purd)))
    {
        log_warn("zone write axfr: %{dnsname}: failed to parse query from %{sockaddr}", data_zone_origin, dns_message_get_sender_sa(mesg));
        read_error = true;
        goto scheduler_queue_zone_write_axfr_thread_exit;
    }

    dns_message_set_size(mesg, dns_packet_reader_position(&purd));
    dns_message_set_answer_count_ne(mesg, 0);

    size_t message_base_size = dns_message_get_size(mesg);
    dns_packet_writer_init(&pw, dns_message_get_buffer(mesg), message_base_size, packet_size_limit);

    for(;;) /* using path as the buffer */
    {
        struct type_class_ttl_rdlen_s tctrl;
        ya_result                     qname_len;
        ya_result                     n;

        if(dnscore_shuttingdown())
        {
            log_info("zone write axfr: %{dnsname}: stopping transfer to %{sockaddr} because of application shutdown", data_zone_origin, dns_message_get_sender_sa(mesg));
            break;
        }

        /* Read the next DNAME from the stored AXFR */

        if(FAIL(qname_len = input_stream_read_dnsname(&fis, (uint8_t *)buffer))) // length checked
        {
            /* qname_len is an error code */
            log_err("zone write axfr: %{dnsname}: error reading next record domain: %r", data_zone_origin, qname_len);
            read_error = true;
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

                dns_message_set_authoritative_answer(mesg);
                dns_message_set_size(mesg, dns_packet_writer_get_offset(&pw));
                dns_message_set_answer_count(mesg, an_count);

#if ZDB_HAS_TSIG_SUPPORT
                if(dns_message_has_tsig(mesg))
                {
                    dns_message_set_additional_section_ptr(mesg, dns_packet_writer_get_next_u8_ptr(&pw));
                    dns_message_reset_buffer_size(mesg);

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

                    dns_packet_writer_set_offset(&pw, dns_message_get_size(mesg));

                } /* if message_has_tsig */
#endif

#if DEBUG_AXFR_MESSAGES
                LOGGER_EARLY_CULL_PREFIX(MSG_DEBUG) message_log(MODULE_MSG_HANDLE, MSG_DEBUG, mesg);
#endif

                n = tcp_manager_channel_send(tmc, mesg);
                if(FAIL(n))
                {
                    log_err("zone write axfr: %{dnsname}: error sending AXFR packet to %{sockaddr}: %r", data_zone_origin, dns_message_get_sender_sa(mesg), n);
                }
                total_bytes_sent += dns_message_get_size(mesg);

                dns_message_set_buffer_size(mesg, 0x8000); // limit to 32KB, knowing perfectly well the buffer is actually 64KB

                // in effect, an_records_count = 0;
            }

            break; /* done */
        }

        /* read the next type+class+ttl+rdatalen from the stored AXFR */

        if(FAIL(n = input_stream_read_fully(&fis, &tctrl, TYPE_CLASS_TTL_RDLEN_SIZE)))
        {
            log_err("zone write axfr: %{dnsname}: error reading record: %r", data_zone_origin, n);
            read_error = true;
            break;
        }

        uint16_t rdata_len = ntohs(tctrl.rdlen);

        // if for any reason the rdata_len is bigger than the 4K buffer size (not supposed to happen as even keys are
        // not bigger than 1K)

        if(rdata_len > buffer_size)
        {
            // implicitly, buffer_size < UINT16_MAX
            // rdata_len always in [0; UINT16_MAX]

            char *tmp_buffer = (char *)malloc(UINT16_MAX);
            if(tmp_buffer == NULL)
            {
                log_err(
                    "zone write axfr: %{dnsname}: %{dnstype} record data length is too big (%i > %i) and failed to "
                    "allocate a bigger buffer",
                    data_zone_origin,
                    &tctrl.rtype,
                    rdata_len,
                    buffer_size);
#if DEBUG
                log_memdump(g_database_logger, MSG_DEBUG, &tctrl, 10, 16);
#endif
                break;
            }

            memcpy(tmp_buffer, buffer, qname_len);
            buffer = tmp_buffer;
            buffer_size = UINT16_MAX;
        }

        int32_t record_len = qname_len + TYPE_CLASS_TTL_RDLEN_SIZE + rdata_len;

        /* Check if we have enough room available for the next record */

        int32_t remaining_capacity = (dns_packet_writer_get_limit(&pw) / 2) - dns_packet_writer_get_offset(&pw);

        if((an_count >= packet_records_limit) || (remaining_capacity < record_len))
        {
            // not enough room

            if(an_count == 0)
            {
                log_err("zone write axfr: %{dnsname}: error preparing packet: next record is too big (%d)", data_zone_origin, record_len);
                break;
            }

            dns_message_set_authoritative_answer(mesg);
            dns_message_set_answer_count(mesg, an_count);
            dns_message_set_size(mesg, dns_packet_writer_get_offset(&pw));

#if ZDB_HAS_TSIG_SUPPORT
            if(dns_message_has_tsig(mesg))
            {
                dns_message_reset_buffer_size(mesg);

                dns_message_set_additional_section_ptr(mesg, dns_packet_writer_get_next_u8_ptr(&pw));

                if(FAIL(ret = tsig_sign_tcp_message(mesg, pos)))
                {
                    log_err("zone write axfr: %{dnsname}: failed to sign the answer: %r", data_zone_origin, ret);
                    break;
                }

                dns_packet_writer_set_offset(&pw, dns_message_get_size(mesg));
            }
#endif
            /* Flush the packet. */

#if DEBUG_AXFR_MESSAGES
            LOGGER_EARLY_CULL_PREFIX(MSG_DEBUG) message_log(MODULE_MSG_HANDLE, MSG_DEBUG, mesg);
#endif

            n = tcp_manager_channel_send(tmc, mesg);
            if(FAIL(n))
            {
                log_err("zone write axfr: %{dnsname}: error sending packet to %{sockaddr}: %r", data_zone_origin, dns_message_get_sender_sa(mesg), n);
                break;
            }
            total_bytes_sent += dns_message_get_size(mesg);

#if ZDB_HAS_TSIG_SUPPORT
            pos = TSIG_MIDDLE;
#endif
            an_count = 0;

            // Packet flushed ...
            // Reset the packet

            // Remove the TSIG.

            dns_message_set_authoritative_answer(mesg);
            dns_message_set_query_answer_authority_additional_counts_ne(mesg, NU16(1), 0, 0, 0);
            dns_message_set_buffer_size(mesg,
                                        0x8000); // limit to 32KB, knowing perfectly well the buffer is actually 64KB
            dns_packet_writer_init(&pw, dns_message_get_buffer(mesg), message_base_size, packet_size_limit);
        }

        /** NOTE: if tctrl.qtype == TYPE_SOA, then we are at the beginning OR the end of the AXFR stream */

#if ZDB_HAS_TSIG_SUPPORT
        if(tctrl.rtype == TYPE_SOA)
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

        dns_packet_writer_add_fqdn(&pw, (const uint8_t *)buffer);

        dns_packet_writer_add_bytes(&pw, (const uint8_t *)&tctrl, TYPE_CLASS_TTL_RDLEN_SIZE);

        if(compress_dname_rdata != 0)
        {
            uint16_t rdata_offset = dns_packet_writer_get_offset(&pw);

            switch(tctrl.rtype)
            {
                case TYPE_MX:
                {
                    if(FAIL(n = input_stream_read_fully(&fis, buffer, rdata_len)))
                    {
                        log_err("zone write axfr: %{dnsname}: error reading MX record: %r", data_zone_origin, n);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    // verify fqdn
                    uint32_t len = dnsname_len((const uint8_t *)&buffer[2]);
                    if(len > DOMAIN_LENGTH_MAX)
                    {
                        log_err("zone write axfr: %{dnsname}: rdata fqdn is too long", data_zone_origin);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    if(len + 2 != rdata_len)
                    {
                        log_err("zone write axfr: %{dnsname}: expected rdata of %i bytes but got %i", data_zone_origin, rdata_len, len + 2);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    dns_packet_writer_add_bytes(&pw, (const uint8_t *)buffer, 2);
                    dns_packet_writer_add_fqdn(&pw, (const uint8_t *)&buffer[2]);
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
                        log_err("zone write axfr: %{dnsname}: error reading %{dnstype} record: %r", data_zone_origin, &tctrl.rtype, n);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    // verify fqdn
                    uint32_t len = dnsname_len((const uint8_t *)buffer);
                    if(len > DOMAIN_LENGTH_MAX)
                    {
                        log_err("zone write axfr: %{dnsname}: rdata fqdn is too long", data_zone_origin);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    if(len != rdata_len)
                    {
                        log_err("zone write axfr: %{dnsname}: expected rdata of %i bytes but got %i", data_zone_origin, rdata_len, len);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }
                    // the write buffer is bigger than the limit and the fqdn size has been verified
                    dns_packet_writer_add_fqdn(&pw, (const uint8_t *)buffer);
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

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    // verify fqdn
                    const uint8_t *m = (const uint8_t *)buffer;
                    uint32_t       mlen = dnsname_len(m);

                    if(mlen > DOMAIN_LENGTH_MAX)
                    {
                        log_err("zone write axfr: %{dnsname}: mname is too long", data_zone_origin);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    const uint8_t *r = &m[mlen];

                    uint32_t       rlen = dnsname_len(r);

                    if(rlen > DOMAIN_LENGTH_MAX)
                    {
                        log_err("zone write axfr: %{dnsname}: rname is too long", data_zone_origin);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    if(mlen + rlen + 20 != rdata_len)
                    {
                        log_err("zone write axfr: %{dnsname}: expected rdata of %i bytes but got %i", data_zone_origin, rdata_len, mlen + rlen + 20);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    // the write buffer is bigger than the limit and the fqdn size has been verified
                    dns_packet_writer_add_fqdn(&pw, m);
                    // the write buffer is bigger than the limit and the fqdn size has been verified
                    dns_packet_writer_add_fqdn(&pw, r);
                    dns_packet_writer_add_bytes(&pw, &r[rlen], 20);

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

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    int32_t remaining = rdata_len;
                    remaining -= RRSIG_RDATA_HEADER_LEN;

                    if(remaining < 0)
                    {
                        log_err("zone write axfr: %{dnsname}: error reading RRSIG record: rdata is too short", data_zone_origin);

                        /*
                         * GOTO !!! (thread carefully )
                         */

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    dns_packet_writer_add_bytes(&pw, (const uint8_t *)buffer, RRSIG_RDATA_HEADER_LEN);

                    const uint8_t *o = (const uint8_t *)&buffer[18];
                    uint32_t       olen = dnsname_len(o);
                    remaining -= olen;

                    if(remaining < 0)
                    {
                        log_err("zone write axfr: %{dnsname}: error reading RRSIG record: rdata is too short", data_zone_origin);

                        /*
                         * GOTO !!! (thread carefully)
                         */

                        read_error = true;
                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    dns_packet_writer_add_fqdn(&pw, o);

                    dns_packet_writer_add_bytes(&pw, &o[olen], remaining);

                    SET_U16_AT(pw.packet[rdata_offset - 2], htons(pw.packet_offset - rdata_offset)); // set RDATA size

                    continue;
                }
            } // switch
        } // if

        // not a case handled with compression : raw copy

        while(rdata_len > 0)
        {
            if((n = input_stream_read(&fis, (uint8_t *)buffer, MIN(rdata_len, sizeof(buffer)))) <= 0)
            {
                if(n == 0)
                {
                    break;
                }

                log_err("zone write axfr: %{dnsname}: error reading %{dnstype} rdata: %r", data_zone_origin, &tctrl.rtype, n);

                /*
                 * GOTO !!! (thread carefully)
                 */

                read_error = true;
                goto scheduler_queue_zone_write_axfr_thread_exit;
            }

#if DEBUG
            if(dns_packet_writer_get_remaining_capacity(&pw) < n)
            {
                log_err("zone write axfr: %{dnsname}: would store %i bytes when %i were expected and %i remaining, from %i", data_zone_origin, n, rdata_len, dns_packet_writer_get_remaining_capacity(&pw), remaining_capacity);

                /*
                 * GOTO !!! (thread carefully)
                 */

                read_error = true;
                goto scheduler_queue_zone_write_axfr_thread_exit;
            }
#endif

            dns_packet_writer_add_bytes(&pw, (const uint8_t *)buffer, n);

            rdata_len -= n;
        }
    } // for

    /**
     * GOTO !!!
     */

scheduler_queue_zone_write_axfr_thread_exit:

    if(buffer != buffer_static)
    {
        free(buffer);
    }

    if(fis_filename != NULL)
    {
        // corruption ?

        if(read_error) // scan-build false positive: from its definition, every single use of read_error is set to a
                       // constant
        {
            log_info("zone write axfr: %{dnsname}: error reading the AXFR stream of file '%s'", data_zone_origin, fis_filename);
            unlink(fis_filename);
        }

        free(fis_filename);
        fis_filename = NULL;
    }

    log_info("zone write axfr: %{dnsname}: closing file, %llu bytes sent to %{sockaddr}", data_zone_origin, total_bytes_sent, dns_message_get_sender_sa(mesg));

#if DEBUG
    log_debug("zone write axfr: %{dnsname}: closing socket %i", data_zone_origin, tcp_manager_channel_socket(tmc));
#endif

    if(call_is_threaded)
    {
        tcp_manager_channel_release(tmc);
    }

    if(input_stream_valid(&fis))
    {
        input_stream_close(&fis);
    }

    dns_message_delete(mesg);
}

void zdb_zone_answer_axfr(zdb_zone_t *zone, dns_message_t *mesg, tcp_manager_channel_t *tmc, struct thread_pool_s *network_tp, struct thread_pool_s *disk_tp, uint16_t max_packet_size, uint16_t max_record_by_packet, bool compress_packets)
{
    zdb_zone_answer_axfr_thread_args *args;

    log_info("zone write axfr: %{dnsname}: queueing", zone->origin);

    if(dns_message_get_size(mesg) >= max_packet_size)
    {
        log_err(
            "zone write axfr: %{dnsname}: received message is already bigger than maximum message size in answer: "
            "cancelled",
            zone->origin);
        return;
    }

    dns_message_t *clone = dns_message_dup(mesg);
    if(clone == NULL)
    {
        log_err("zone write axfr: %{dnsname}: received message : cancelled", zone->origin);
        return; // BUFFER_WOULD_OVERFLOW;
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
    args->tmc = tmc;
    args->mesg = clone;
    args->packet_size_limit = max_packet_size;
    args->packet_records_limit = max_record_by_packet;
    args->compress_dname_rdata = compress_packets;

    if(network_tp != NULL)
    {
        args->threaded = true;
        // add a worker to the sctx
        tcp_manager_channel_acquire(tmc);
        thread_pool_enqueue_call(network_tp, zdb_zone_answer_axfr_thread, args, NULL, "zone-answer-axfr");
    }
    else
    {
        args->threaded = false;
        zdb_zone_answer_axfr_thread(args);
    }
}

/** @} */

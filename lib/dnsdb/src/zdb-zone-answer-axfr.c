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
#include <dnscore/format.h>
#include <dnscore/packet_writer.h>
#include <dnscore/rfc.h>
#include <dnscore/serial.h>
#include <dnscore/xfr_copy.h>
#include <dnscore/fdtools.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/journal.h"
#include "dnsdb/zdb_zone_axfr_input_stream.h"

#include "dnsdb/zdb-zone-answer-axfr.h"

#define MODULE_MSG_HANDLE g_database_logger

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

extern logger_handle* g_database_logger;

#define AXFR_FORMAT "%s/%{dnsname}%08x.axfr"

#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

typedef struct scheduler_queue_zone_write_axfr_args scheduler_queue_zone_write_axfr_args;

struct scheduler_queue_zone_write_axfr_args
{
    zdb_zone *zone;
    char *directory;
    message_data *mesg;
    struct thread_pool_s *disk_tp;
    ya_result return_code;

    u32 packet_size_limit;
    u32 packet_records_limit;
    bool compress_dname_rdata;
};

/*
 * NOTE: THIS IS NOT A BACKGROUND TASK
 */

static void
zdb_zone_write_axfr_clean_older(const char *directory, zdb_zone* zone, u32 serial)
{    
    char fqdn[MAX_DOMAIN_LENGTH + 1];
    char path[1024];

    s32 fqdn_len = dnsname_to_cstr(fqdn, zone->origin);

    struct dirent entry;
    struct dirent *result;

    DIR* dir = opendir(directory);

    if(dir != NULL)
    {
        for(;;)
        {
            readdir_r(dir, &entry, &result);

            if(result == NULL)
            {
                break;
            }
            
#ifdef _DIRENT_HAVE_D_TYPE
            if( (result->d_type & DT_REG) != 0 )
#else
            if(dirent_get_file_type(directory, &entry) == DT_REG)
#endif
            {
                if(memcmp(result->d_name, fqdn, fqdn_len) == 0)
                {
                    const char* serials = &result->d_name[fqdn_len];

                    if(strlen(serials) >= 8 + 1 + 4)
                    {
                        if(strcmp(&serials[8], ".axfr") == 0)
                        {
                            u32 fileserial;
                            
                            int converted = sscanf(serials,"%08x", &fileserial);

                            if(converted == 1)
                            {
                                if(serial_lt(fileserial, serial))
                                {
                                    if(ISOK(snformat(path, sizeof (path), "%s/%s", directory, result->d_name)))
                                    {
                                        log_info("zone write axfr: removing obsolete '%s' (%d)", path, serial);

                                        if(unlink(path) < 0)
                                        {
                                            log_err("zone write axfr: remove failed: %r", ERRNO_ERROR);
                                        }
                                    }
                                }
                                else
                                {
                                    log_debug("zone write axfr: found bigger or equal serial %d >= %d", fileserial, serial);
                                }
                            }
                        }
                    }
                }
            }
        }

        closedir(dir);
    }
    
    /* if the journal does not contains the serial, then it's useless/obsolete */
    
    journal *jh = NULL;
    if(ISOK(journal_open(&jh, zone, directory, FALSE))) // does close
    {
        if(jh != NULL)
        {
            u32 from;
            u32 to;
            
            if(ISOK(journal_get_serial_range(jh, &from, &to)))
            {
                if(serial_lt(serial, from) || serial_gt(serial, to))
                {
                    journal_truncate_to_size(jh, 0);
                }
            }
        }
        
        journal_close(jh);
    }
}

typedef struct scheduler_queue_zone_write_axfr_storage_args scheduler_queue_zone_write_axfr_storage_args;

struct scheduler_queue_zone_write_axfr_storage_args
{
    output_stream os;   // (file) output stream to the AXFR file
    char *data_path;
    char *path;
    char *pathpart;
    scheduler_queue_zone_write_axfr_args *data;
    u32 serial;
};


static void
zdb_zone_answer_axfr_thread_exit(scheduler_queue_zone_write_axfr_args* data)
{
    log_debug("zone write axfr: ended with: %r", data->return_code);
    
    free(data->directory);
    free(data);
}

static void*
zdb_zone_answer_axfr_write_file_thread(void* data_)
{
    scheduler_queue_zone_write_axfr_storage_args* storage = (scheduler_queue_zone_write_axfr_storage_args*)data_;
    
    // os
    // zone
    // serial
    // *return_code
    /*-----------------------------------------------------------------------*/
    
    /*
     * And I do the cleaning here: seek for and destroy all axfr files with an older serial.
     */

    zdb_zone_write_axfr_clean_older(storage->data_path, storage->data->zone, storage->serial);
    
    buffer_output_stream_init(&storage->os, &storage->os, 4096);
    
    // ALEADY LOCKED BY THE CALLER SO NO NEED TO zdb_zone_lock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    storage->data->return_code = zdb_zone_store_axfr(storage->data->zone, &storage->os);
    
    zdb_zone_unlock(storage->data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    output_stream_close(&storage->os);

    if(ISOK(storage->data->return_code))
    {
        log_info("zone write axfr: stored %{dnsname} %d", storage->data->zone->origin, storage->serial);

        if(rename(storage->pathpart, storage->path) >= 0)
        {
            storage->data->zone->axfr_timestamp = time(NULL);
        }
        else
        {
            // cannot rename error : SERVFAIL

            storage->data->return_code = ERRNO_ERROR;

            log_err("zone write axfr: error renaming '%s' into '%s': %r", storage->pathpart, storage->path, storage->data->return_code);
        }
    }
    else
    {
        log_err("zone write axfr: write error %r for '" AXFR_FORMAT "'", storage->data->return_code, storage->data_path, storage->data->zone->origin, storage->serial);

        // cannot create error : SERVFAIL
        
        storage->data->zone->axfr_timestamp = 1;
        storage->data->zone->axfr_serial = storage->serial - 1;
    }
    
    zdb_zone_answer_axfr_thread_exit(storage->data);
    /* WARNING: From this point forward, 'data' cannot be used anymore */
    storage->data = NULL;
    free(storage->path);
    free(storage->pathpart);
    free(storage->data_path);
    free(storage);
    
    /*-----------------------------------------------------------------------*/ 
    
    return NULL;
}

static void*
zdb_zone_answer_axfr_thread(void* data_)
{
    scheduler_queue_zone_write_axfr_args* data = (scheduler_queue_zone_write_axfr_args*)data_;
    message_data *mesg = data->mesg;
    zdb_zone *data_zone = data->zone;
    output_stream os;
    u32 serial = 0;
    u32 now = time(NULL);
    int tcpfd = data->mesg->sockfd;
    data->mesg->sockfd = -1;
    
    u64 total_bytes_sent = 0;
    
    u8   data_zone_origin[MAX_DOMAIN_LENGTH];
    char path[MAX_PATH];
    char data_path[MAX_PATH];
    char data_directory[MAX_PATH];
       
    /**
     * The zone could already be dumping in the disk.
     * If it's the case, then the dump file needs to be read and sent until marked as "done".
     */
    
    /* locks the zone for a reader */
    
#ifdef DEBUG
    log_debug("zone write axfr: locking for AXFR");
    log_debug("zone write axfr: socket is %d", tcpfd);
#endif
    
    if(tcpfd < 0)
    {
        data->return_code = ERROR;
        log_err("zone write axfr: %{dnsname}: invalid socket", data->zone->origin);
        zdb_zone_answer_axfr_thread_exit(data);
        free(mesg);
        return NULL;
    }
    
    MESSAGE_SET_AR(mesg->buffer, 0);

    zdb_zone_lock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    if(ZDB_ZONE_INVALID(data_zone))
    {
        zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        
        log_err("zone write axfr: %{dnsname}: marked as invalid", data_zone->origin);
        
        /* @todo send a servfail answer ... */
        
        zdb_zone_answer_axfr_thread_exit(data);
        close_ex(tcpfd);
        free(mesg);        
        return NULL;
    }
    
#ifdef DEBUG
    log_debug("zone write axfr: checking serial number");
#endif
    
    if(FAIL(zdb_zone_getserial(data_zone, &serial)))
    {
        /** @todo error other than "does not exists" : SERVFAIL */
        zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

        log_err("zone write axfr: no SOA in %{dnsname}", data_zone->origin);
        
        /* @todo send a servfail answer ... */

        zdb_zone_answer_axfr_thread_exit(data);
        close_ex(tcpfd);
        free(mesg);
        return NULL;
    }
    
    u32 packet_size_limit = data->packet_size_limit;

    if(packet_size_limit < UDPPACKET_MAX_LENGTH)
    {
        packet_size_limit = UDPPACKET_MAX_LENGTH;
    }
    
    u32 packet_records_limit = data->packet_records_limit;

    /* If it is set to 0, it means there is no limit. */

    if(packet_records_limit == 0)
    {
        packet_records_limit = 0xffffffff;
    }

    bool compress_dname_rdata = data->compress_dname_rdata;

    strcpy(data_directory, data->directory);
    dnsname_copy(data_zone_origin, data_zone->origin);
    
    /*  serial on disk is NOT same one         serial is NOT being written          it has been long enough since last write */
    if((data_zone->axfr_serial != serial) && (data_zone->axfr_timestamp != 0) && (now - data_zone->axfr_timestamp > 60))
    {
        /* has changed AND not currently being written AND has been written a (long) time ago */
        
        u32 old_axfr_timestamp = data_zone->axfr_timestamp;
        u32 old_axfr_serial = data_zone->axfr_serial;
        data_zone->axfr_timestamp = 0;
        data_zone->axfr_serial = serial;
                
        /* write a new one */
                
#ifdef DEBUG
        log_debug("zone write axfr: preparing source");
#endif

        /* file directory path */
        
        if(FAIL(data->return_code = xfr_copy_mkdir_data_path(data_path, sizeof(data_path), data_directory, data_zone_origin)))
        {
            zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
            
            log_err("zone write axfr: unable to create directory '%s' for %{dnsname}: %r", data_path, data_zone_origin, data->return_code);

/*
            data_zone->axfr_timestamp = old_axfr_timestamp;
*/
            data_zone->axfr_serial = old_axfr_serial;
            
            /* @todo send a servfail answer ... */
            
            zdb_zone_answer_axfr_thread_exit(data);
            close_ex(tcpfd);
            free(mesg);
            return NULL;
        }

        log_info("zone write axfr: begin %{dnsname} %d", data_zone_origin, serial);
        
        /* final name */

        if(FAIL(data->return_code = snformat(path, sizeof (path), AXFR_FORMAT, data_path, data_zone_origin, serial)))
        {
            zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

            log_err("zone write axfr: path '" AXFR_FORMAT "' is too big", data_path, data_zone_origin, serial);

            data_zone->axfr_timestamp = old_axfr_timestamp;
            data_zone->axfr_serial = old_axfr_serial;
            
            /* @todo send a servfail answer ... */
            
            zdb_zone_answer_axfr_thread_exit(data);
            close_ex(tcpfd);
            free(mesg);
            return NULL;
        }

#ifdef DEBUG
        log_debug("zone write axfr: checking if '%s' needs to be generated", path);
#endif

        /* test if the name does exist */
        
        if(access(path, R_OK | F_OK) < 0)
        {
            if(errno != ENOENT)
            {
                zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

                /** @todo error other than "does not exists" : SERVFAIL */

                data->return_code = ERRNO_ERROR;
                log_err("zone write axfr: error accessing '%s': %r", path, data->return_code);

                data_zone->axfr_timestamp = old_axfr_timestamp;
                data_zone->axfr_serial = old_axfr_serial;
                
                /* @todo send a servfail answer ... */
                
                zdb_zone_answer_axfr_thread_exit(data);
                close_ex(tcpfd);
                free(mesg);
                return NULL;
            }

            /* check for part */

            char pathpart[MAX_PATH];

            memcpy(pathpart, path, data->return_code);
            memcpy(&pathpart[data->return_code], ".part", 6);

            /* write part */

            log_info("zone write axfr: storing %{dnsname} %d", data_zone_origin, serial);

            if(FAIL(data->return_code = file_output_stream_create(pathpart, 0644, &os)))
            {
                zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
                
                log_err("zone write axfr: file create error for '" AXFR_FORMAT "': %r",
                        data_path, data_zone_origin, serial, data->return_code);

                /** @todo cannot create error : SERVFAIL ? */

                data_zone->axfr_timestamp = old_axfr_timestamp;
                data_zone->axfr_serial = old_axfr_serial;
                
                /* @todo send a servfail answer ... */
                
                zdb_zone_answer_axfr_thread_exit(data);
                close_ex(tcpfd);
                free(mesg);
                return NULL;
            }

            /*
            * Return value check irrelevant here.  It can only fail if the filtered stream has a NULL vtbl
            * This is not the case here since we just opened successfully the file stream.
            */
            
            /*
             * Now that the file has been created, the background writing thread can be called
             * the readers will wait "forever" that the file is written but the yneed the file to exist
             */
            
            scheduler_queue_zone_write_axfr_storage_args *storage;
            MALLOC_OR_DIE(scheduler_queue_zone_write_axfr_storage_args*, storage, sizeof(scheduler_queue_zone_write_axfr_storage_args), GENERIC_TAG);
            storage->os = os;
            storage->data_path = strdup(data_path);
            storage->path = strdup(path);
            storage->pathpart = strdup(pathpart);
            storage->data = data;
            storage->serial = serial;
            
            /*
             * This is how it is supposed to be.  Double lock, unlocked when the file has been stored.
             */
            
            zdb_zone_lock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
            
            if(data->disk_tp != NULL)
            {
                thread_pool_enqueue_call(data->disk_tp, zdb_zone_answer_axfr_write_file_thread, storage, NULL, "zone-writer-axfr");
            }
            else
            {
                zdb_zone_answer_axfr_write_file_thread(storage);
            }
            
            /* The thread will unlock the the scheduler lock and ONE reader lock */
            /* WARNING: From this point forward, 'data' cannot be used anymore */
            data = NULL;    /* WITH THIS I ENSURE A CRASH IF I DO NOT RESPECT THE ABOVE COMMENT */
        }
        else
        {
            /* the file is already available, let's fix this */
            
            data_zone->axfr_serial = serial;
            data_zone->axfr_timestamp = now;
            
            data->return_code = SUCCESS;
            
            // no need to wait anymore (the zone will be unlocked after opening the file
        
            log_info("zone write axfr: releasing implicit write lock %{dnsname} %d (already)", data_zone_origin, serial);            
            zdb_zone_answer_axfr_thread_exit(data);
            /* WARNING: From this point forward, 'data' cannot be used anymore */
            data = NULL;    /* WITH THIS I ENSURE A CRASH IF I DO NOT RESPECT THE ABOVE COMMENT */
        }
    }
    else
    {
        // no need to wait anymore (the zone will be unlocked after opening the file)
        
        data->return_code = SUCCESS;
        
        log_info("zone write axfr: releasing implicit write lock %{dnsname} %d (should be)", data_zone_origin, serial);
        zdb_zone_answer_axfr_thread_exit(data);
        /* WARNING: From this point forward, 'data' cannot be used anymore */
        data = NULL;    /* WITH THIS I ENSURE A CRASH IF I DO NOT RESPECT THE ABOVE COMMENT */
    }
    
    /* open an xfr stream on it and stream it up to the client */
    
    mesg->size_limit = 0x8000;

    /**
     * I should open the file BEFORE releasing the lock.
     * So every AXFR write request could cleanup the old files without any risk of race
     * (given that an opened file can be deleted and continue to exist until last accessor
     * has closed it)
     */

    /* pool for path */

    input_stream fis;
    ya_result ret;
    
    ret = zdb_zone_axfr_input_stream_open(&fis, data_zone, data_directory);
            
    zdb_zone_unlock(data_zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

    if(FAIL(ret)) /* replaces: if(FAIL(ret = file_input_stream_open(path, &fis))) */
    {
        /** @todo cannot open error : SERVFAIL */

        log_err("zone write axfr: error opening '%s': %r", path, ret);

        close_ex(tcpfd);
        free(mesg);
        return NULL;
    }

    /* Sends the "Write unlocked" notification */

    log_info("zone write axfr: sending AXFR %{dnsname} %d", data_zone_origin, serial);

    output_stream tcpos;
    fd_output_stream_attach(tcpfd, &tcpos);
    buffer_input_stream_init(&fis, &fis, FILE_BUFFER_SIZE);
    buffer_output_stream_init(&tcpos, &tcpos, TCP_BUFFER_SIZE);
    
    MESSAGE_HIFLAGS(mesg->buffer) |= AA_BITS|QR_BITS;
    MESSAGE_SET_AN(mesg->buffer, NETWORK_ONE_16);

    packet_writer pw;
    u32 packet_count = 0;
    u16 an_records_count = 0;

    // @TODO: With TSIG enabled this limit will be dynamic and change to a lower bound for every 100th packet
#if ZDB_HAS_TSIG_SUPPORT
    tsig_tcp_message_position pos = TSIG_NOWHERE;
#endif
    packet_writer_init(&pw, mesg->buffer, mesg->received, packet_size_limit);

    for(;; packet_count--) /* using path as the buffer */
    {
        struct type_class_ttl_rdlen tctrl;
        ya_result qname_len;
        ya_result n;

        /* Read the next DNAME from the stored AXFR */

        if(FAIL(qname_len = input_stream_read_dnsname(&fis, (u8*)path)))
        {
            log_err("zone write axfr: error reading AXFR qname: %r", qname_len); /* qname_len is an error code */

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
            if(an_records_count > 0)
            {
                /* Then write them */

                if(packet_count == 0)
                {
                    /* TODO: TSIG: sign the packet*/

                    packet_count = AXFR_TSIG_PERIOD; // why ?
                }

                mesg->send_length = pw.packet_offset; /** @todo: I need to put this in a packet_writer function */

                /** @TODO: if we only have 1 packet then we still need to cleanup  the message
                 *	   So a better way to do this is to check if pos is TSIG_START and if it does do the standard TSIG signature.
                 */

                MESSAGE_SET_AN(mesg->buffer, htons(an_records_count));
#if ZDB_HAS_TSIG_SUPPORT
                if(TSIG_ENABLED(mesg))
                {
                    mesg->ar_start = &pw.packet[pw.packet_offset];

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
                        log_err("zone write axfr: failed to sign the answer: %r", ret);
                        break;
                    }
                } /* if TSIG_ENABLED */
#endif
                pw.packet_offset = mesg->send_length; /** @todo: I need to put this in a packet_writer function */

                total_bytes_sent += mesg->send_length;
                
                if(FAIL(n = write_tcp_packet(&pw, &tcpos)))
                {
                    log_err("zone write axfr: error sending AXFR packet: %r", n);
                }

                an_records_count = 0;
            }

            break; /* done */
        }

        /* read the next type+class+ttl+rdatalen from the stored AXFR */

        if(FAIL(n = input_stream_read_fully(&fis, &tctrl, 10)))
        {
            log_err("zone write axfr: error reading AXFR record: %r", n);
            break;
        }

        u16 rdata_len = ntohs(tctrl.rdlen);

        u32 record_len = qname_len + 10 + rdata_len;

        /* Check if we have enough room available for the next record */

        if((an_records_count >= packet_records_limit) || (pw.packet_limit - pw.packet_offset) < record_len)
        {
            if(an_records_count == 0)
            {
                log_err("zone write axfr: error writing AXFR packet: next record is too big (%d)", record_len);

                break;
            }

            MESSAGE_SET_AN(mesg->buffer, htons(an_records_count));

            mesg->send_length = pw.packet_offset; /** @todo: I need to put this in a packet_writer function */

#if ZDB_HAS_TSIG_SUPPORT
            if(TSIG_ENABLED(mesg))
            {
                mesg->ar_start = &pw.packet[pw.packet_offset];

                if(FAIL(ret = tsig_sign_tcp_message(mesg, pos)))
                {
                    log_err("zone write axfr: failed to sign the answer: %r", ret);
                    break;
                }
            }
#endif
            /* Flush the packet. */

            pw.packet_offset = mesg->send_length; /** @todo: I need to put this in a packet_writer function */
            
            total_bytes_sent += mesg->send_length;
            
            if(FAIL(n = write_tcp_packet(&pw, &tcpos)))
            {
                log_err("zone write axfr: error sending AXFR packet: %r", n);
                break;
            }

#if ZDB_HAS_TSIG_SUPPORT
            pos = TSIG_MIDDLE;
#endif
            an_records_count = 0;

            // Packet flushed ...
            // Reset the packet
            // @TODO: reset the counts (?)
            // @TODO: TSIG enabled means the limit changes every 100th packet

            /* Remove the TSIG. */
            /** @todo: Keep the AR count instead of setting it to 0  */
            MESSAGE_SET_AR(mesg->buffer, 0);
            packet_writer_init(&pw, mesg->buffer, mesg->received, packet_size_limit);
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
        
        an_records_count++;

        packet_writer_add_fqdn(&pw, (const u8*)path);

        packet_writer_add_bytes(&pw, (const u8*)&tctrl, 10);

        if(compress_dname_rdata != 0)
        {
            u16 rdata_offset = pw.packet_offset;

            switch(tctrl.qtype)
            {
                case TYPE_MX:

                    if(FAIL(n = input_stream_read_fully(&fis, path, 2)))
                    {
                        log_err("zone write axfr: error reading AXFR record: %r", n);

                        /*
                         * GOTO !!! (I hate this)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_bytes(&pw, (const u8*)path, 2);

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
                    if(FAIL(qname_len = input_stream_read_dnsname(&fis, (u8*)path)))
                    {
                        log_err("zone write axfr: error reading AXFR rdata dname: %r", qname_len);

                        /*
                         * GOTO !!! (I hate this)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_fqdn(&pw, (const u8*)path);
                    SET_U16_AT(pw.packet[rdata_offset - 2], htons(pw.packet_offset - rdata_offset));

                    continue;
                }
                case TYPE_SOA:
                {
                    if(FAIL(qname_len = input_stream_read_dnsname(&fis, (u8*)path)))
                    {
                        log_err("zone write axfr: error reading AXFR rdata dname: %r", qname_len);

                        /*
                         * GOTO !!! (I hate this)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_fqdn(&pw, (const u8*)path);
                    
                    if(FAIL(qname_len = input_stream_read_rname(&fis, (u8*)path)))
                    {
                        log_err("zone write axfr: error reading AXFR rdata dname: %r", qname_len);

                        /*
                         * GOTO !!! (I hate this)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_fqdn(&pw, (const u8*)path);

                    if(FAIL(n = input_stream_read_fully(&fis, path, 20)))
                    {
                        log_err("zone write axfr: error reading AXFR record: %r", n);

                        /*
                         * GOTO !!! (I hate this)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_bytes(&pw, (const u8*)path, 20);

                    SET_U16_AT(pw.packet[rdata_offset - 2], htons(pw.packet_offset - rdata_offset));
                    
                    continue;
                }

                case TYPE_RRSIG:
                {
                    if(FAIL(n = input_stream_read_fully(&fis, path, 18)))
                    {
                        log_err("zone write axfr: error reading AXFR record: %r", n);

                        /*
                         * GOTO !!! (I hate this)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    rdata_len -= 18;

                    packet_writer_add_bytes(&pw, (const u8*)path, 18);

                    if(FAIL(qname_len = input_stream_read_dnsname(&fis, (u8*)path)))
                    {
                        log_err("zone write axfr: error reading AXFR rdata dname: %r", qname_len);

                        /*
                         * GOTO !!! (I hate this)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_fqdn(&pw, (const u8*)path);

                    rdata_len -= qname_len;

                    if(FAIL(n = input_stream_read_fully(&fis, path, rdata_len)))
                    {
                        log_err("zone write axfr: error reading AXFR record: %r", n);

                        /*
                         * GOTO !!! (I hate this)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_bytes(&pw, (const u8*)path, rdata_len);

                    SET_U16_AT(pw.packet[rdata_offset - 2], htons(pw.packet_offset - rdata_offset));

                    continue;
                }

                case TYPE_NSEC:
                {
                    if(FAIL(qname_len = input_stream_read_dnsname(&fis, (u8*)path)))
                    {
                        log_err("zone write axfr: error reading AXFR rdata dname: %r", qname_len);

                        /*
                         * GOTO !!! (I hate this)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_fqdn(&pw, (const u8*)path);

                    rdata_len -= qname_len;

                    if(FAIL(n = input_stream_read_fully(&fis, path, rdata_len)))
                    {
                        log_err("zone write axfr: error reading AXFR record: %r", n);

                        /*
                         * GOTO !!! (I hate this)
                         */

                        goto scheduler_queue_zone_write_axfr_thread_exit;
                    }

                    packet_writer_add_bytes(&pw, (const u8*)path, rdata_len);

                    SET_U16_AT(pw.packet[rdata_offset - 2], htons(pw.packet_offset - rdata_offset));

                    continue;
                }
                case TYPE_NSEC3PARAM:
                {
                    break;
                }
            }
        }

        while(rdata_len > 0)
        {
            if((n = input_stream_read(&fis, (u8*)path, MIN(rdata_len, sizeof (path)))) <= 0)
            {
                if(n == 0)
                {
                    break;
                }

                log_err("zone write axfr: error reading AXFR rdata: %r", n);

                /*
                 * GOTO !!! (I hate this)
                 */

                goto scheduler_queue_zone_write_axfr_thread_exit;
            }

            packet_writer_add_bytes(&pw, (const u8*)path, n);

            rdata_len -= n;
        }
    }

    /**
     * GOTO !!!
     */

scheduler_queue_zone_write_axfr_thread_exit:

    log_info("zone write axfr: closing file for %{dnsname}, %llu bytes sent", data_zone_origin, total_bytes_sent);

#ifdef DEBUG
    log_debug("zone write axfr: closing socket %i", tcpfd);
#endif
    
    output_stream_close(&tcpos);
    input_stream_close(&fis);

    free(mesg);

    return NULL;
}

void
zdb_zone_answer_axfr(zdb_zone *zone, message_data *mesg, struct thread_pool_s *network_tp, struct thread_pool_s *disk_tp, const char *xfrpath, u16 max_packet_size, u16 max_record_by_packet, bool compress_packets)
{
    scheduler_queue_zone_write_axfr_args* args;
    
    log_info("zone write axfr: queueing %{dnsname}", zone->origin);
        
    MALLOC_OR_DIE(scheduler_queue_zone_write_axfr_args*, args, sizeof(scheduler_queue_zone_write_axfr_args), GENERIC_TAG);
    args->zone = zone;
    args->directory = strdup(xfrpath);
    args->disk_tp = disk_tp;
    
    message_data *mesg_clone;
    MALLOC_OR_DIE(message_data*, mesg_clone, sizeof (message_data), MESGDATA_TAG);
    memcpy(mesg_clone, mesg, sizeof (message_data));

    args->mesg = mesg_clone;
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

/*----------------------------------------------------------------------------*/

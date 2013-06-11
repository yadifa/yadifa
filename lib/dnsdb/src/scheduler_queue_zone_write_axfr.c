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

#include <dnscore/logger.h>
#include <dnscore/thread_pool.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/scheduler.h>
#include <dnscore/format.h>
#include <dnscore/packet_writer.h>
#include <dnscore/rfc.h>
#include <dnscore/serial.h>
#include <dnscore/xfr_copy.h>
#include <dnscore/fdtools.h>

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_types.h"

#define MODULE_MSG_HANDLE g_database_logger



/**
 *
 * dig -p 8053 @191.0.2.53 eu AXFR +time=3600 > eu.axfr
 *
 * Max dns packet size / Max number of records in each packet / RDATA Compression enabled
 *
 * 65535 1 1
 *
 * ;; Query time: 150452 msec
 * ;; SERVER: 191.0.2.53#8053(191.0.2.53)
 * ;; WHEN: Thu Dec 24 09:17:57 2009
 * ;; XFR size: 6657358 records (messages 6657358, bytes 417268730)
 *
 * 65535 65535 0
 *
 * ;; Query time: 82347 msec
 * ;; SERVER: 191.0.2.53#8053(191.0.2.53)
 * ;; WHEN: Wed Dec 23 15:31:23 2009
 * ;; XFR size: 6657358 records (messages 4141, bytes 271280613)
 *
 * 4096 65535 1
 *
 * ;; Query time: 78042 msec
 * ;; SERVER: 191.0.2.53#8053(191.0.2.53)
 * ;; WHEN: Thu Dec 24 09:04:54 2009
 * ;; XFR size: 6657358 records (messages 44940, bytes 182745973)
 *
 * 65535 65535 1
 *
 * ;; Query time: 88954 msec
 * ;; SERVER: 191.0.2.53#8053(191.0.2.53)
 * ;; WHEN: Thu Dec 24 09:08:47 2009
 * ;; XFR size: 6657358 records (messages 3133, bytes 205197880)
 *
 * So it was obvious but the best system is 4K packets without any record count limit and with compression enabled:
 *
 * 4096 because compression only covers the first 4K of the packet
 * no limit because there is no point (1 is supposed to be nicer but at what cost !)
 * compression enabled because it reduces the bandwith AND the time
 *
 *  With buffering enabled this increases to:
 *
 * ;; Query time: 20130 msec
 * ;; SERVER: 191.0.2.53#8053(191.0.2.53)
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
    ya_result return_code;

    u32 packet_size_limit;
    u32 packet_records_limit;
    bool compress_dname_rdata;
};

static void
scheduler_queue_zone_write_axfr_clean_older(const char *directory, const u8 *origin, u32 serial)
{    
    char fqdn[MAX_DOMAIN_LENGTH + 1];
    char path[1024];

    s32 fqdn_len = dnsname_to_cstr(fqdn, origin) ;

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

            if( (result->d_type & DT_REG) != 0 )
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
                    else if(strlen(serials) == 8 + 1 + 8 + XFR_INCREMENTAL_EXT_STRLEN)
                    {
                        if(strcmp(&serials[8 + 1 + 8], XFR_INCREMENTAL_EXT) == 0)
                        {
                            u32 from;
                            u32 to;
                            
                            int converted = sscanf(serials, "%08x-%08x", &from, &to);

                            if(converted == 2)
                            {
                                /* got one */
                                
                                if(ISOK(snformat(path, sizeof (path), "%s/%s", directory, result->d_name)))
                                {
                                    log_info("zone write axfr: removing obsolete '%s' (%d)", path, serial);

                                    if(unlink(path) < 0)
                                    {
                                        log_err("zone write axfr: remove failed: %r", ERRNO_ERROR);
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
}

static ya_result
scheduler_queue_zone_write_axfr_callback(void* data_)
{
    scheduler_queue_zone_write_axfr_args* data = (scheduler_queue_zone_write_axfr_args*)data_;

    log_debug("zone write axfr: ended with: %r", data->return_code);

    /*free(data->mesg);*/
    free(data->directory);
    free(data);

    return SCHEDULER_TASK_FINISHED; /* Notify the end of the writer job */
}

static void*
scheduler_queue_zone_write_axfr_thread(void* data_)
{
    scheduler_queue_zone_write_axfr_args* data = (scheduler_queue_zone_write_axfr_args*)data_;
    message_data *mesg = data->mesg;
    output_stream os;
    u32 serial = 0;

    char path[MAX_PATH];
    char data_path[MAX_PATH];
    u8 origin[MAX_DOMAIN_LENGTH];

    zdb_zone_lock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    
    if(ZDB_ZONE_INVALID(data->zone))
    {
        log_err("zone write axfr: zone %{dnsname} marked as invalid", data->zone->origin);
        
        zdb_zone_unlock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
 
        scheduler_schedule_task(scheduler_queue_zone_write_axfr_callback, data); /** @todo: Check I must release the lock */

        close_ex(mesg->sockfd);
       
        free(mesg);

        return NULL;
    }

    if(FAIL(zdb_zone_getserial(data->zone, &serial)))
    {
        /** @todo error other than "does not exists" : SERVFAIL */

        log_err("zone write axfr: no SOA in %{dnsname}", data->zone->origin);

        zdb_zone_unlock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

        scheduler_schedule_task(scheduler_queue_zone_write_axfr_callback, data); /** @todo: Check I must release the lock */

        close_ex(mesg->sockfd);
       
        free(mesg);

        return NULL;
    }
    
    if(FAIL(data->return_code = xfr_copy_make_data_path(data->directory, data->zone->origin, data_path, sizeof(data_path))))
    {
        log_err("zone write axfr: %{dnsname} file path issue: %r", data->zone->origin, data->return_code);

        zdb_zone_unlock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

        scheduler_schedule_task(scheduler_queue_zone_write_axfr_callback, data); /** @todo: Check I must release the lock */

        close_ex(mesg->sockfd);       
        free(mesg);

        return NULL;
    }

    zdb_zone_unlock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

    log_info("zone write axfr: begin %{dnsname} %d", data->zone->origin, serial);

    if(FAIL(data->return_code = snformat(path, sizeof (path), AXFR_FORMAT, data_path, data->zone->origin, serial)))
    {
        log_err("zone write axfr: path '" AXFR_FORMAT "' is too big", data_path, data->zone->origin, serial);

        scheduler_schedule_task(scheduler_queue_zone_write_axfr_callback, data); /** @todo: Check I must release the lock */

        /* WARNING: From this point forward, 'data' cannot be used anymore */

        close_ex(mesg->sockfd);
        free(mesg);
        return NULL;
    }

    if(access(path, R_OK | F_OK) < 0)
    {
        if(errno != ENOENT)
        {
            /** @todo error other than "does not exists" : SERVFAIL */

            data->return_code = ERRNO_ERROR;
            
            log_err("zone write axfr: error accessing '%s': %r", path, data->return_code);

            scheduler_schedule_task(scheduler_queue_zone_write_axfr_callback, data); /* TODO: Check I must release the lock */

            /* WARNING: From this point forward, 'data' cannot be used anymore */

            close_ex(mesg->sockfd);
            free(mesg);
            return NULL;
        }

        /* check for part */

        char pathpart[MAX_PATH];

        memcpy(pathpart, path, data->return_code);
        memcpy(&pathpart[data->return_code], ".part", 6);

        /* write part */

        log_info("zone write axfr: storing %{dnsname} %d", data->zone->origin, serial);

        if(FAIL(data->return_code = file_output_stream_create(pathpart, 0644, &os)))
        {
            log_err("zone write axfr: file create error for '" AXFR_FORMAT "': %r",
                    data_path, data->zone->origin, serial, data->return_code);

            /** @todo cannot create error : SERVFAIL ? */

            scheduler_schedule_task(scheduler_queue_zone_write_axfr_callback, data); /* TODO: Check I must release the lock */

            /* WARNING: From this point forward, 'data' cannot be used anymore */

            close_ex(mesg->sockfd);
            free(mesg);
            return NULL;
        }

        log_info("zone write axfr: stored %{dnsname} %d", data->zone->origin, serial);
        
        /*
         * Return value check irrelevant here.  It can only fail if the filtered stream has a NULL vtbl
         * This is not the case here since we just opened successfully the file stream.
         */

        buffer_output_stream_init(&os, &os, 4096);

        zdb_zone_lock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        data->return_code = zdb_zone_store_axfr(data->zone, &os);
        zdb_zone_unlock(data->zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

        output_stream_close(&os);

        if(ISOK(data->return_code))
        {
            data->return_code = SCHEDULER_TASK_FINISHED;
        }
        else
        {
            log_err("zone write axfr: write error %r for '" AXFR_FORMAT "'", data->return_code, data_path, data->zone->origin, serial);

            /** @todo cannot create error : SERVFAIL */

            scheduler_schedule_task(scheduler_queue_zone_write_axfr_callback, data); /* TODO: Check I must release the lock */

            /* WARNING: From this point forward, 'data' cannot be used anymore */

            close_ex(mesg->sockfd);
            free(mesg);
            
            return NULL;
        }

        if(rename(pathpart, path) < 0)
        {
            /** @todo cannot rename error : SERVFAIL */

            data->return_code = MAKE_ERRNO_ERROR(errno);
            log_err("zone write axfr: error renaming '%s' into '%s': %r", pathpart, path, data->return_code);

            scheduler_schedule_task(scheduler_queue_zone_write_axfr_callback, data); /* TODO: Check I must release the lock */

            /* WARNING: From this point forward, 'data' cannot be used anymore */

            close_ex(mesg->sockfd);
            free(mesg);
            return NULL;
        }
    }

    u32 packet_size_limit = data->packet_size_limit;

    if(packet_size_limit < UDPPACKET_MAX_LENGTH)
    {
        packet_size_limit = UDPPACKET_MAX_LENGTH;
    }

    mesg->size_limit = 32768;

    u32 packet_records_limit = data->packet_records_limit;

    /* If it is set to 0, it means there is no limit. */

    if(packet_records_limit == 0)
    {
        packet_records_limit = 0xffffffff;
    }

    bool compress_dname_rdata = data->compress_dname_rdata;

    int tcpfd = data->mesg->sockfd;
    data->mesg->sockfd = -1;

    dnsname_copy(origin, data->zone->origin);

    /**
     * I should open the file BEFORE releasing the lock.
     * So every AXFR write request could cleanup the old files without any risk of race.
     */

    /* pool for path */

    input_stream fis;
    ya_result ret;

    if(FAIL(ret = file_input_stream_open(path, &fis)))
    {
        /** @todo cannot open error : SERVFAIL */

        close_ex(tcpfd);

        log_err("zone write axfr: error opening '%s': %r", path, ret);

        scheduler_schedule_task(scheduler_queue_zone_write_axfr_callback, data);

        /* WARNING: From this point forward, 'data' cannot be used anymore */

        free(mesg);
        return NULL;
    }

    /*
     * And I do the cleaning here: seek for and destroy all axfr files with an older serial.
     */

    scheduler_queue_zone_write_axfr_clean_older(data_path, data->zone->origin, serial);

    /* Sends the "Write unlocked" notification */

    log_info("zone write axfr: releasing implicit write lock %{dnsname} %d", data->zone->origin, serial);

    ya_result return_code = data->return_code;

    scheduler_schedule_task(scheduler_queue_zone_write_axfr_callback, data);

    /* WARNING: From this point forward, 'data' cannot be used anymore */

    data = NULL;    /* WITH THIS I ENSURE A CRASH IF I DO NOT RESPECT THE ABOVE COMMENT */

    if(tcpfd < 0)
    {
        log_err("zone write axfr: no tcp: done %{dnsname} %r", path, return_code);

        free(mesg);
        return NULL;
    }

    log_info("zone write axfr: sending AXFR %{dnsname} %d", origin, serial);

    output_stream tcpos;

    fd_output_stream_attach(tcpfd, &tcpos);

    buffer_input_stream_init(&fis, &fis, FILE_BUFFER_SIZE);
    buffer_output_stream_init(&tcpos, &tcpos, TCP_BUFFER_SIZE);

    MESSAGE_HIFLAGS(mesg->buffer) |= AA_BITS|QR_BITS;
    MESSAGE_AN(mesg->buffer) = NETWORK_ONE_16;

    packet_writer pw;
    u32 packet_count = 0;

    u16 an_records_count = 0;

    // @TODO: With TSIG enabled this limit will be dynamic and change to a lower bound for every 100th packet

    tsig_tcp_message_position pos = TSIG_NOWHERE;

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

                    packet_count = AXFR_TSIG_PERIOD;
                }

                mesg->send_length = pw.packet_offset; /** @todo: I need to put this in a packet_writer function */

                /** @TODO: if we only have 1 packet then we still need to cleanup  the message
                 *	   So a better way to do this is to check if pos is TSIG_START and if it does do the standard TSIG signature.
                 */

                MESSAGE_AN(mesg->buffer) = htons(an_records_count);

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

                pw.packet_offset = mesg->send_length; /** @todo: I need to put this in a packet_writer function */

                if(FAIL(n = write_tcp_packet(&pw, &tcpos)))
                {
                    log_err("zone write axfr: error sending AXFR packet: %r", n);
                }

                an_records_count = 0;
            }

            break; /* done */
        }

        /* read the next type+class+ttl+rdatalen from the stored AXFR */

        if(FAIL(n = input_stream_read_fully(&fis, (u8*) & tctrl, 10)))
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

            MESSAGE_AN(mesg->buffer) = htons(an_records_count);

            mesg->send_length = pw.packet_offset; /** @todo: I need to put this in a packet_writer function */

            if(TSIG_ENABLED(mesg))
            {
                mesg->ar_start = &pw.packet[pw.packet_offset];

                if(FAIL(ret = tsig_sign_tcp_message(mesg, pos)))
                {
                    log_err("zone write axfr: failed to sign the answer: %r", ret);
                    break;
                }
            }

            /* Flush the packet. */

            pw.packet_offset = mesg->send_length; /** @todo: I need to put this in a packet_writer function */
            
            if(FAIL(n = write_tcp_packet(&pw, &tcpos)))
            {
                log_err("zone write axfr: error sending AXFR packet: %r", n);
                break;
            }

            pos = TSIG_MIDDLE;

            an_records_count = 0;

            // Packet flushed ...
            // Reset the packet
            // @TODO: reset the counts (?)
            // @TODO: TSIG enabled means the limit changes every 100th packet

            /* Remove the TSIG. */
            /** @todo: Keep the AR count instead of setting it to 0  */
            MESSAGE_AR(mesg->buffer) = 0;
            packet_writer_init(&pw, mesg->buffer, mesg->received, packet_size_limit);
        }

        /** NOTE: if tctrl.qtype == TYPE_SOA, then we are at the beginning OR the end of the AXFR stream */

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

        an_records_count++;

        packet_writer_add_fqdn(&pw, (const u8*)path);

        packet_writer_add_bytes(&pw, (const u8*)&tctrl, 10);

        if(compress_dname_rdata != 0)
        {
            n = 0;

            u16 rdata_offset = pw.packet_offset;

            switch(tctrl.qtype)
            {
                case TYPE_MX:

                    if(FAIL(n = input_stream_read_fully(&fis, (u8*)path, 2)))
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

                    if(FAIL(n = input_stream_read_fully(&fis, (u8*)path, 20)))
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
                    if(FAIL(n = input_stream_read_fully(&fis, (u8*)path, 18)))
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

                    if(FAIL(n = input_stream_read_fully(&fis, (u8*)path, rdata_len)))
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

                    if(FAIL(n = input_stream_read_fully(&fis, (u8*)path, rdata_len)))
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

    log_info("zone write axfr: closing file for %{dnsname}", origin);

    output_stream_close(&tcpos);
    input_stream_close(&fis);

    free(mesg);

    return NULL;
}

/*
 * This requires that the scheduler calls the AXFR write zone file
 */

void
scheduler_queue_zone_write_axfr(zdb_zone* zone, const char* directory, u32 packet_size_limit, u32 packet_records_limit, bool compress_dname_rdata)
{
    scheduler_queue_zone_write_axfr_args* args;
    
    log_info("zone write axfr: queueing %{dnsname}", zone->origin);

    MALLOC_OR_DIE(scheduler_queue_zone_write_axfr_args*, args, sizeof(scheduler_queue_zone_write_axfr_args), GENERIC_TAG);
    args->zone = zone;
    args->directory = strdup(directory);
    args->mesg = NULL;
    args->packet_size_limit = packet_size_limit;
    args->packet_records_limit = packet_records_limit;
    args->compress_dname_rdata = compress_dname_rdata;
    
    scheduler_schedule_thread(NULL, scheduler_queue_zone_write_axfr_thread, args, "scheduler_queue_zone_write_axfr");
}

/*
 * This requires that the scheduler answers to an AXFR query
 */

void
scheduler_queue_zone_send_axfr(zdb_zone* zone, const char* directory, u32 packet_size_limit, u32 packet_records_limit, bool compress_dname_rdata, message_data *mesg)
{
    scheduler_queue_zone_write_axfr_args* args;
    
    log_info("zone write axfr: queueing %{dnsname}", zone->origin);
    
    MALLOC_OR_DIE(scheduler_queue_zone_write_axfr_args*, args, sizeof (scheduler_queue_zone_write_axfr_args), GENERIC_TAG);
    args->zone = zone;
    args->directory = strdup(directory);

    message_data *mesg_clone;

    MALLOC_OR_DIE(message_data*, mesg_clone, sizeof (message_data), GENERIC_TAG);
    memcpy(mesg_clone, mesg, sizeof (message_data));

    args->mesg = mesg_clone;
    args->packet_size_limit = packet_size_limit;
    args->packet_records_limit = packet_records_limit;
    args->compress_dname_rdata = compress_dname_rdata;
    scheduler_schedule_thread(NULL, scheduler_queue_zone_write_axfr_thread, args, "scheduler_queue_zone_send_axfr");
}

/** @} */

/*----------------------------------------------------------------------------*/

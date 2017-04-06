/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2017, EURid. All rights reserved.
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
/** @defgroup zoneaxfr AXFR file loader module
 *  @ingroup dnszone
 *  @brief zone functions
 *
 *  Implementation of routines for the zone_data struct
 *   - add
 *   - adjust
 *   - init
 *   - parse
 *   - print
 *   - remove database
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnszone/dnszone-config.h"

#include <string.h>
#include <arpa/inet.h>		/* or netinet/in.h */
#include <dirent.h>
#include <unistd.h>
#include <stddef.h>

#include <dnscore/logger.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/serial.h>

#include "dnsdb/zdb-zone-path-provider.h"

#include "dnszone/zone_axfr_reader.h"

#define AXREADER_TAG 0x5245444145525841

extern logger_handle *g_zone_logger;
#define MODULE_MSG_HANDLE g_zone_logger

typedef struct zone_axfr_reader zone_axfr_reader;
struct zone_axfr_reader
{
    input_stream is;                    /* LOAD */
    char* file_path;
    resource_record* unread_next;
    bool soa_found;                     /* LOAD */
};

static ya_result
zone_axfr_reader_unread_record(zone_reader *zr, resource_record *entry)
{
    zone_axfr_reader *zone = (zone_axfr_reader*)zr->data;
    resource_record *rr;
    u32 required = offsetof(resource_record,rdata) + entry->rdata_size;
    MALLOC_OR_DIE(resource_record*, rr, required, DNSRR_TAG);
    memcpy(rr, entry, required);
    rr->next = zone->unread_next;
    zone->unread_next = rr;
    
    return SUCCESS;
}

static ya_result
zone_axfr_reader_read_record(zone_reader *zr, resource_record *entry)
{
    yassert((zr != NULL) && (entry != NULL));

    zone_axfr_reader *zone = (zone_axfr_reader*)zr->data;
    
    if(zone->unread_next != NULL)
    {
        resource_record *top = zone->unread_next;
        u32 required = offsetof(resource_record,rdata) + top->rdata_size;
        memcpy(entry, top, required);
        zone->unread_next = top->next;
        free(top);
        
        return 0;
    }
    
    ya_result return_value;
    u16 rdata_len;

    if(ISOK(return_value = input_stream_read_dnsname(&zone->is, entry->name)))
    {
        if(ISOK(return_value = input_stream_read_u16(&zone->is, &entry->type)))
        {
            if(ISOK(return_value = input_stream_read_u16(&zone->is, &entry->class)))
            {
                if(ISOK(return_value = input_stream_read_nu32(&zone->is, (u32*)&entry->ttl)))
                {
                    if(ISOK(return_value = input_stream_read_nu16(&zone->is, &rdata_len)))
                    {
                        if(ISOK(return_value = input_stream_read_fully(&zone->is, entry->rdata, rdata_len)))
                        {
                            entry->rdata_size = return_value;

                            if(entry->type == TYPE_SOA)
                            {
                                if(zone->soa_found)
                                {
                                    return 1;   /* done */
                                }

                                zone->soa_found = TRUE;
                            }

                            return 0;
                        }
                    }
                }
            }
        }
    }

    return return_value;
}

static ya_result
zone_axfr_reader_free_record(zone_reader *zone, resource_record *entry)
{
    return OK;
}

static void
zone_axfr_reader_close(zone_reader *zr)
{
    yassert(zr != NULL);

    zone_axfr_reader *zone = (zone_axfr_reader*)zr->data;

    free(zone->file_path);

    input_stream_close(&zone->is);
    
    resource_record *rr = zone->unread_next;
    while(rr != NULL)
    {
        resource_record *tmp = rr;
        rr = rr->next;
        free(tmp);
    }

    free(zone);

    zr->data = NULL;
    zr->vtbl = NULL;
}

static bool
zone_axfr_reader_canwriteback(zone_reader *zr)
{
    yassert(zr != NULL);
    return TRUE;
}

static void
zone_axfr_reader_handle_error(zone_reader *zr, ya_result error_code)
{
    /*
     * If an error occurred loading the axfr : delete it
     * 
     * More subtle tests on the error code could also be done.
     */

    yassert(zr != NULL);

    if(FAIL(error_code))
    {
        zone_axfr_reader *zone = (zone_axfr_reader*)zr->data;

#ifdef DEBUG
        log_debug("zone axfr: deleting broken AXFR file: %s", zone->file_path);
#endif

        if(unlink(zone->file_path) < 0)
        {
            log_err("zone axfr: unlink(%s): %r", zone->file_path, ERRNO_ERROR);
        }
    }
}

static const char*
zone_axfr_reader_get_last_error_message(zone_reader *zr)
{
    // not supported yet
    (void)zr;
    return NULL;
}

static zone_reader_vtbl zone_axfr_reader_vtbl =
{
    zone_axfr_reader_read_record,
    zone_axfr_reader_unread_record,
    zone_axfr_reader_free_record,
    zone_axfr_reader_close,
    zone_axfr_reader_handle_error,
    zone_axfr_reader_canwriteback,
    zone_axfr_reader_get_last_error_message,
    "zone_axfr_reader"
};

ya_result zone_axfr_reader_open(zone_reader *dst, const char *file_path)
{
    zone_axfr_reader *zone;
    ya_result return_value;
    
    input_stream is;
    if(FAIL(return_value = file_input_stream_open(&is, file_path)))
    {
            return return_value;
    }

    /*    ------------------------------------------------------------    */
    
    MALLOC_OR_DIE(zone_axfr_reader*, zone, sizeof(zone_axfr_reader), AXREADER_TAG);
    ZEROMEMORY(zone, sizeof(zone_axfr_reader));

    /* Initialize the new zone data */

    buffer_input_stream_init(&zone->is, &is, 4096);

    zone->file_path = strdup(file_path);
    zone->soa_found = FALSE;

    dst->data = zone;
    dst->vtbl = &zone_axfr_reader_vtbl;

    return SUCCESS;
}


ya_result
zone_axfr_reader_open_with_fqdn(zone_reader *dst, const u8 *origin)
{
    ya_result ret;
    
    char file_path[PATH_MAX];
    
    if(ISOK(ret = zdb_zone_path_get_provider()(
                origin, 
                file_path, sizeof(file_path) - 6,
                ZDB_ZONE_PATH_PROVIDER_AXFR_FILE|ZDB_ZONE_PATH_PROVIDER_MKDIR)))
    {
        log_debug("opening '%s' for reading", file_path);
        
        ret = zone_axfr_reader_open(dst, file_path);
    }
    
    return ret;
}

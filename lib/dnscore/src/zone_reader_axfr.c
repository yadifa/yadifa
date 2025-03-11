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
 * @defgroup zoneaxfr AXFR file loader module
 * @ingroup dnscore
 * @brief zone functions
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
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"
#include "dnscore/parser.h"

#include <string.h>
#include <arpa/inet.h> /* or netinet/in.h */
#include <dirent.h>
#include <unistd.h>
#include <stddef.h>

#include <dnscore/logger.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/serial.h>

#include <dnscore/zone_reader_axfr.h>

#define AXREADER_TAG 0x5245444145525841

extern logger_handle_t *g_zone_logger;
#define MODULE_MSG_HANDLE g_zone_logger

struct zone_reader_axfr_s
{
    input_stream_t     is; /* LOAD */
    char              *file_path;
    resource_record_t *unread_next;
    bool               soa_found; /* LOAD */
};

typedef struct zone_reader_axfr_s zone_reader_axfr_t;

static ya_result                  zone_reader_axfr_unread_record(zone_reader_t *zr, resource_record_t *entry)
{
    zone_reader_axfr_t *zone = (zone_reader_axfr_t *)zr->data;
    resource_record_t  *rr;
    uint32_t            required = offsetof(resource_record_t, rdata) + entry->rdata_size;
    MALLOC_OR_DIE(resource_record_t *, rr, required, DNSRR_TAG);
    memcpy(rr, entry, required);
    rr->next = zone->unread_next;
    zone->unread_next = rr;

    return SUCCESS;
}

static ya_result zone_reader_axfr_read_record(zone_reader_t *zr, resource_record_t *entry)
{
    yassert((zr != NULL) && (entry != NULL));

    zone_reader_axfr_t *zone = (zone_reader_axfr_t *)zr->data;

    if(zone->unread_next != NULL)
    {
        resource_record_t *top = zone->unread_next;
        uint32_t           required = offsetof(resource_record_t, rdata) + top->rdata_size;
        memcpy(entry, top, required);
        zone->unread_next = top->next;
        free(top);

        return 1;
    }

    ya_result ret;
    uint16_t  rdata_len;

    if((ret = input_stream_read_dnsname(&zone->is, entry->name)) > 0)
    {
        if(ISOK(ret = input_stream_read_u16(&zone->is, &entry->type)))
        {
            if(ISOK(ret = input_stream_read_u16(&zone->is, &entry->class)))
            {
                if(ISOK(ret = input_stream_read_nu32(&zone->is, (uint32_t *)&entry->ttl)))
                {
                    if(ISOK(ret = input_stream_read_nu16(&zone->is, &rdata_len)))
                    {
                        if(ISOK(ret = input_stream_read_fully(&zone->is, entry->rdata, rdata_len)))
                        {
                            entry->rdata_size = ret;

                            if(entry->type == TYPE_SOA)
                            {
                                if(zone->soa_found)
                                {
                                    return 1; /* done */
                                }

                                zone->soa_found = true;
                            }

                            return 1;
                        }
                    }
                }
            }
        }
    }

    return ret;
}

static ya_result zone_reader_axfr_free_record(zone_reader_t *zone, resource_record_t *entry)
{
    (void)zone;
    (void)entry;
    return OK;
}

static void zone_reader_axfr_close(zone_reader_t *zr)
{
    yassert(zr != NULL);

    zone_reader_axfr_t *zone = (zone_reader_axfr_t *)zr->data;

    free(zone->file_path);

    input_stream_close(&zone->is);

    resource_record_t *rr = zone->unread_next;
    while(rr != NULL)
    {
        resource_record_t *tmp = rr;
        rr = rr->next;
        free(tmp);
    }

    free(zone);

    zr->data = NULL;
    zr->vtbl = NULL;
}

static bool zone_reader_axfr_canwriteback(zone_reader_t *zr)
{
    yassert(zr != NULL);
    (void)zr;
    return true;
}

static void zone_reader_axfr_handle_error(zone_reader_t *zr, ya_result error_code)
{
    /*
     * If an error occurred loading the axfr : delete it
     *
     * More subtle tests on the error code could also be done.
     */

    yassert(zr != NULL);

    if(FAIL(error_code))
    {
        zone_reader_axfr_t *zone = (zone_reader_axfr_t *)zr->data;

#if DEBUG
        log_debug("zone axfr: deleting broken AXFR file: %s", zone->file_path);
#endif

        if(unlink(zone->file_path) < 0)
        {
            log_err("zone axfr: unlink(%s): %r", zone->file_path, ERRNO_ERROR);
        }
    }
}

static const char *zone_reader_axfr_get_last_error_message(zone_reader_t *zr)
{
    // not supported yet
    (void)zr;
    return NULL;
}

static const zone_reader_vtbl zone_reader_axfr_vtbl = {zone_reader_axfr_read_record,
                                                       zone_reader_axfr_unread_record,
                                                       zone_reader_axfr_free_record,
                                                       zone_reader_axfr_close,
                                                       zone_reader_axfr_handle_error,
                                                       zone_reader_axfr_canwriteback,
                                                       zone_reader_axfr_get_last_error_message,
                                                       "zone_reader_axfr"};

ya_result                     zone_reader_axfr_open(zone_reader_t *dst, const char *file_path)
{
    zone_reader_axfr_t *zone;
    ya_result           return_value;

    input_stream_t      is;
    if(FAIL(return_value = file_input_stream_open(&is, file_path)))
    {
        return return_value;
    }

    /*    ------------------------------------------------------------    */

    MALLOC_OBJECT_OR_DIE(zone, zone_reader_axfr_t, AXREADER_TAG);
    ZEROMEMORY(zone, sizeof(zone_reader_axfr_t));

    /* Initialize the new zone data */

    buffer_input_stream_init(&zone->is, &is, 4096);

    zone->file_path = strdup(file_path);
    zone->soa_found = false;

    dst->data = zone;
    dst->vtbl = &zone_reader_axfr_vtbl;

    return SUCCESS;
}

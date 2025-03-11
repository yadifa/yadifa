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
 * @defgroup dnscore
 * @ingroup dnscore
 * @brief zone reader czf
 *
 * Obsolete
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"

#include <string.h>
#include <arpa/inet.h> /* or netinet/in.h */
#include <dirent.h>
#include <unistd.h>
#include <stddef.h>

#include <dnscore/logger.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/serial.h>

#include <dnscore/zone_reader_czf.h>

#define AXREADER_TAG 0x5245444145525841

/*
 * MAGIC // F0 C Z F
 * class (2 bytes)
 * Size (5 bytes)
 * domain-size (1 bytes)
 * DOMAIN
 *     0 TTL (compact)
 *     Type (compact) count (compact)
 *       rdata_len (compact) rdata (bytes)
 *
 * label (go down)
 *     0 TTL (compact)
 *     Type (compact) count (compact)
 *       rdata_len (compact) rdata (bytes)
 * 0 (byte) go up
 *
 * MAGIC // F1 E N D
 *
 */

extern logger_handle_t *g_zone_logger;
#define MODULE_MSG_HANDLE g_zone_logger

typedef struct zone_reader_czf zone_reader_czf;
struct zone_reader_czf
{
    input_stream_t     is; /* LOAD */
    char              *file_path;
    resource_record_t *unread_next;
    int32_t            domain_depth;
    int32_t            ttl;
    int32_t            rdata_count;
    uint16_t           rtype;
    uint16_t           zclass;
    bool               soa_found; /* LOAD */
    dnsname_stack_t    domain;
};

static ya_result zone_reader_czf_unread_record(zone_reader_t *zr, resource_record_t *entry)
{
    zone_reader_czf   *zone = (zone_reader_czf *)zr->data;
    resource_record_t *rr;
    uint32_t           required = offsetof(resource_record_t, rdata) + entry->rdata_size;
    MALLOC_OR_DIE(resource_record_t *, rr, required, DNSRR_TAG);
    memcpy(rr, entry, required);
    rr->next = zone->unread_next;
    zone->unread_next = rr;

    return SUCCESS;
}

static ya_result zone_reader_czf_read_record_entry(zone_reader_czf *zone, resource_record_t *entry)
{
    if(zone->rdata_count > 0)
    {
        ya_result ret;
        uint32_t  rdata_size;

        if(ISOK(ret = input_stream_read_pu32(&zone->is, &rdata_size)))
        {
            dnsname_stack_to_dnsname(&zone->domain, entry->name);
            entry->type = zone->rtype;
            entry->class = zone->zclass;
            entry->ttl = zone->ttl;
            entry->rdata_size = rdata_size;

            ret = input_stream_read_fully(&zone->is, entry->rdata, rdata_size);
        }
        --zone->rdata_count;
        return ret;
    }
    else
    {
        return DATA_FORMAT_ERROR;
    }
}

static ya_result zone_reader_czf_read_record(zone_reader_t *zr, resource_record_t *entry)
{
    yassert((zr != NULL) && (entry != NULL));

    zone_reader_czf *zone = (zone_reader_czf *)zr->data;

    ya_result        ret;

    if(zone->unread_next != NULL)
    {
        resource_record_t *top = zone->unread_next;
        uint32_t           required = offsetof(resource_record_t, rdata) + top->rdata_size;
        memcpy(entry, top, required);
        zone->unread_next = top->next;
        free(top);

        return 0;
    }

    for(;;)
    {
        if(zone->rdata_count > 0)
        {
            ret = zone_reader_czf_read_record_entry(zone, entry);
            return ret;
        }

        for(;;)
        {
            uint32_t rtype;
            input_stream_read_pu32(&zone->is, &rtype);

            if(rtype == 0)
            {
                input_stream_read_pu32(&zone->is, (uint32_t *)&zone->ttl);
                continue;
            }

            if(rtype == NU16(TYPE_OPT))
            {
                break;
            }

            input_stream_read_pu32(&zone->is, (uint32_t *)&zone->rdata_count);

            // read rdata_count

            ret = zone_reader_czf_read_record_entry(zone, entry);
            return ret;
        }

        // no more entries : expect a label or 0

        uint8_t label[LABEL_LENGTH_MAX];

        for(;;)
        {
            ret = input_stream_read_u8(&zone->is, &label[0]);
            if(ISOK(ret))
            {
                if(label[0] != 0) // a label
                {
                    if(ISOK(ret = input_stream_read_fully(&zone->is, &label[1], label[0])))
                    {
                        dnsname_stack_push_label(&zone->domain, dnslabel_zdup(label));
                        ++zone->domain_depth;
                        break;
                    }

                    return ret; // error
                }
                else // moving up
                {
                    uint8_t *peek_label = (uint8_t *)dnsname_stack_peek_label(&zone->domain);
                    dnsname_stack_pop_label(&zone->domain);
                    if(zone->domain_depth-- > 0)
                    {
                        dnslabel_zfree(peek_label);
                    }
                    else
                    {
                        // EOF (end magic should follow)
                        return 0;
                    }
                }
            }
            else
            {
                return ret;
            }
        }
    }
}

static ya_result zone_reader_czf_free_record(zone_reader_t *zone, resource_record_t *entry)
{
    (void)zone;
    (void)entry;
    return OK;
}

static void zone_reader_czf_close(zone_reader_t *zr)
{
    yassert(zr != NULL);

    zone_reader_czf *zone = (zone_reader_czf *)zr->data;

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

static bool zone_reader_czf_canwriteback(zone_reader_t *zr)
{
    yassert(zr != NULL);
    (void)zr;
    return true;
}

static void zone_reader_czf_handle_error(zone_reader_t *zr, ya_result error_code)
{
    /*
     * If an error occurred loading the axfr : delete it
     *
     * More subtle tests on the error code could also be done.
     */

    yassert(zr != NULL);

    if(FAIL(error_code))
    {
        zone_reader_czf *zone = (zone_reader_czf *)zr->data;

#if DEBUG
        log_debug("zone axfr: deleting broken AXFR file: %s", zone->file_path);
#endif

        if(unlink(zone->file_path) < 0)
        {
            log_err("zone axfr: unlink(%s): %r", zone->file_path, ERRNO_ERROR);
        }
    }
}

static const char *zone_reader_czf_get_last_error_message(zone_reader_t *zr)
{
    // not supported yet
    (void)zr;
    return NULL;
}

static const zone_reader_vtbl zone_reader_czf_vtbl = {
    zone_reader_czf_read_record, zone_reader_czf_unread_record, zone_reader_czf_free_record, zone_reader_czf_close, zone_reader_czf_handle_error, zone_reader_czf_canwriteback, zone_reader_czf_get_last_error_message, "zone_reader_czf"};

struct zone_reader_czf_header_s
{
    uint32_t magic;
    uint16_t zclass;
    uint8_t  size[5];
    uint8_t  origin_size;
};

ya_result zone_reader_czf_open(zone_reader_t *dst, const char *file_path)
{
    zone_reader_czf *zone;
    ya_result        return_value;

    input_stream_t   is;
    if(FAIL(return_value = file_input_stream_open(&is, file_path)))
    {
        return return_value;
    }

    buffer_input_stream_init(&is, &is, 4096);

    struct zone_reader_czf_header_s header;
    if(input_stream_read_fully(&is, &header, sizeof(header)) == sizeof(header))
    {
        if(header.magic == MAGIC4('C', 'Z', 'F', '\0'))
        {
            uint64_t size = 0;

            for(int_fast32_t i = 0; i < (int)sizeof(header.size); ++i)
            {
                size <<= 8;
                size |= header.size[i];
            }

            // TODO: check the size

            uint8_t origin[DOMAIN_LENGTH_MAX];
            return_value = input_stream_read_dnsname(&is, origin);
            if(ISOK(return_value) && (return_value == header.origin_size))
            {
                MALLOC_OBJECT_OR_DIE(zone, zone_reader_czf, AXREADER_TAG);
                ZEROMEMORY(zone, sizeof(zone_reader_czf));

                zone->is = is;

                zone->file_path = strdup(file_path);
                zone->zclass = header.zclass;
                zone->soa_found = false;

                dnsname_to_dnsname_stack(origin, &zone->domain);

                dst->data = zone;
                dst->vtbl = &zone_reader_czf_vtbl;

                return SUCCESS;
            }
        }
    }

    input_stream_close(&is);

    return DATA_FORMAT_ERROR;
}

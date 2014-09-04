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
#include <string.h>
#include <arpa/inet.h>		/* or netinet/in.h */
#include <dirent.h>
#include <unistd.h>
#include <stddef.h>

#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/serial.h>
#include <dnscore/xfr_copy.h>

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
    MALLOC_OR_DIE(resource_record*, rr, required, GENERIC_TAG);
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
                if(ISOK(return_value = input_stream_read_nu32(&zone->is, &entry->ttl)))
                {
                    if(ISOK(return_value = input_stream_read_nu16(&zone->is, &rdata_len)))
                    {
                        if(ISOK(return_value = input_stream_read_fully(&zone->is, entry->rdata, rdata_len)))
                        {
#ifdef RR_OS_RDATA
                            return_value = output_stream_write(&entry->os_rdata, (u8*)entry->rdata, rdata_len);
#else
                            entry->rdata_size = return_value;
#endif
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

static zone_reader_vtbl zone_axfr_reader_vtbl =
{
    zone_axfr_reader_read_record,
    zone_axfr_reader_unread_record,
    zone_axfr_reader_free_record,
    zone_axfr_reader_close,
    zone_axfr_reader_handle_error,
    zone_axfr_reader_canwriteback,
    "zone_axfr_reader"
};

ya_result zone_axfr_reader_open(const char* axfrpath, zone_reader *dst)
{
    zone_axfr_reader *zone;
    ya_result return_value;
    
    input_stream is;
    if(FAIL(return_value = file_input_stream_open(axfrpath, &is)))
    {
            return return_value;
    }

    /*    ------------------------------------------------------------    */
    
    MALLOC_OR_DIE(zone_axfr_reader*, zone, sizeof (zone_axfr_reader), AXREADER_TAG);
    ZEROMEMORY(zone, sizeof (zone_axfr_reader));

    /* Initialize the new zone data */

    buffer_input_stream_init(&is, &zone->is, 4096);

    zone->file_path = strdup(axfrpath);
    zone->soa_found = FALSE;

    dst->data = zone;
    dst->vtbl = &zone_axfr_reader_vtbl;

    return SUCCESS;
}

static void
zone_axfr_delete(const char* axfrpath, const u8 *origin, u32 serial)
{
    char file_path[1024];
    
    snformat(file_path, sizeof(file_path), "%s/%{dnsname}%08x.axfr", axfrpath, origin, serial); // all uses of this function have serial set

    if(unlink(file_path) >= 0)
    {
        log_info("zone axfr: deleted obsolete axfr file '%s'", file_path);
    }
    else
    {
        log_warn("zone axfr: unable to delete obsolete axfr file '%s': %r", file_path, ERRNO_ERROR);
    }
}

/**
 * Opens the axfr with the highest serial
 */

ya_result
zone_axfr_reader_open_last(const char* axfrpath, u8 *origin, zone_reader *dst)
{
    struct dirent entry;
    struct dirent *result;
    DIR* dir;
    u32 serial;
    ya_result return_code;
    bool got_one = FALSE;
    char fqdn[MAX_DOMAIN_LENGTH + 1];
    char file_path[1024];

    /* returns the number of bytes = strlen(x) + 1 */
    
    char data_path[PATH_MAX];
    
    if(FAIL(return_code = xfr_copy_mkdir_data_path(data_path, sizeof(data_path), axfrpath, origin)))
    {
        log_err("axfr: unable to create directory '%s' for %{dnsname}: %r", data_path, origin, return_code);
        
        return return_code;
    }
    
    axfrpath = data_path;

    dir = opendir(axfrpath);

    if(dir != NULL)
    {
        return_code = ZRE_AXFR_FILE_NOT_FOUND;
        
        s32 fqdn_len = dnsname_to_cstr(fqdn, origin);

        for(;;)
        {
            readdir_r(dir, &entry, &result);

            if(result == NULL)
            {
                break;
            }

            if(memcmp(result->d_name, fqdn, fqdn_len) == 0)
            {
                const char* serial_txt = &result->d_name[fqdn_len];
                size_t serial_len = strlen(serial_txt);
                
                if((serial_len == 8 + 6 - 1) && (memcmp(&serial_txt[8],".axfr",6) == 0))
                {
                    u32 tmp;
                    int converted = sscanf(serial_txt, "%08x.axfr", &tmp);
                        
                    if(converted == 1)
                    {
                        /*
                         * our first one, or a better one that the previous one
                         * 
                         * got_one = FALSE on first iteration, so serial is initialised for the next iteration. (false positive from GCC)
                         */
                        
                        if( !got_one || (got_one && serial_gt(tmp, serial)))
                        {
                            if(got_one)
                            {
                                /* the previous one is obsolete */

                                zone_axfr_delete(axfrpath, origin, serial); // serial IS initialised
                            }

                            serial = tmp;

                            got_one = TRUE;

                            return_code = SUCCESS;
                        }
                        else    /* we got one already and it has a higher serial */
                        {
                            zone_axfr_delete(axfrpath, origin, tmp); // tmp (serial) IS initialised
                        }
                    }
                }
            }
        }
        
        closedir(dir);
    }
    else
    {
        return_code = ERROR;
    }

    if(got_one)
    {
        snformat(file_path, sizeof(file_path), "%s/%{dnsname}%08x.axfr", axfrpath, origin, serial);

        return_code = zone_axfr_reader_open(file_path, dst);
    }

    return return_code;
}

ya_result
zone_axfr_reader_open_with_serial(const char* xfr_path, u8 *origin, u32 loaded_serial, zone_reader *dst)
{
    ya_result return_code;
    
    struct dirent entry;
    struct dirent *result;
    DIR* dir;
    
    char file_name[1024];    
    char data_path[PATH_MAX];
    
    if(FAIL(return_code = xfr_copy_get_data_path(data_path, sizeof(data_path), xfr_path, origin)))
    {
        return return_code;
    }
    
    xfr_path = data_path;
    
    dir = opendir(xfr_path);

    if(dir != NULL)
    {
        char fqdn[MAX_DOMAIN_LENGTH + 1];
        return_code = ERROR;
        
        s32 fqdn_len = dnsname_to_cstr(fqdn, origin);

        for(;;)
        {
            readdir_r(dir, &entry, &result);

            if(result == NULL)
            {
                break;
            }

            if(memcmp(result->d_name, fqdn, fqdn_len) == 0)
            {
                const char* serial_txt = &result->d_name[fqdn_len];
                size_t serial_len = strlen(serial_txt);
                
                if((serial_len == 8 + 6 - 1) && (memcmp(&serial_txt[8],".axfr",6) == 0))
                {
                    u32 tmp;
                    int converted = sscanf(serial_txt, "%08x.axfr", &tmp);

                    if(converted == 1)
                    {
                        /*
                         * our first one, or a better one that the previous one
                         */

                        if(tmp != loaded_serial)
                        {
                            if(serial_lt(tmp, loaded_serial))
                            {
                                /* the previous one is obsolete */

                                zone_axfr_delete(xfr_path, origin, tmp); // tmp (serial) IS initialised
                            }
                            else
                            {
                                log_warn("zone axfr: found axfr file for zone %{dnsname} with bigger serial %x in '%s'", origin, tmp, xfr_path);
                            }
                        }
                    }
                }
            }
        }
        
        closedir(dir);
    }
    
    if(ISOK(return_code = snformat(file_name, sizeof(file_name), "%s/%{dnsname}%08x.axfr", data_path, origin, loaded_serial)))
    {
        return_code = zone_axfr_reader_open(file_name, dst);
    }
    
    return return_code;
}

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

#include "dnsdb/dnsdb-config.h"
#include <unistd.h>

#include "dnscore/file_input_stream.h"
#include "dnscore/format.h"
#include "dnscore/logger.h"
#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_zone_axfr_input_stream.h"

#include "dnsdb/zdb-zone-path-provider.h"

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define AXFRIS_TAG  0x534952465841

/*------------------------------------------------------------------------------
 * STATIC PROTOTYPES */

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** @brief Function ...
 *
 *  ...
 *
 *  @param ...
 *
 *  @retval OK
 *  @retval NOK
 */

typedef struct zdb_zone_axfr_input_stream_data zdb_zone_axfr_input_stream_data;

struct zdb_zone_axfr_input_stream_data
{
    input_stream filtered;
    zdb_zone* zone;
    u32 serial;
};

static ya_result
zdb_zone_axfr_input_stream_read(input_stream* stream_, void* buffer_, u32 len)
{
    zdb_zone_axfr_input_stream_data* stream = (zdb_zone_axfr_input_stream_data*)stream_->data;
    u8 *buffer = (u8*)buffer_;
    bool first_chance_eof = FALSE;
    
    for(;;)
    {    
        ya_result n = input_stream_read(&stream->filtered, buffer, len);
        
        // ERROR or SUCCESS
        
        if(n != 0)
        {
            /* log_debug("zdb_zone_axfr_input_stream_read: got %d", n); */
            
            return n;
        }
        
        // EOF ... or is it ?

        if(first_chance_eof)
        {
            // already broken once : EOF
            
            /* log_debug("zdb_zone_axfr_input_stream_read: final EOF"); */

            return 0;
        }

        if((stream->zone->axfr_timestamp != 0) || (stream->zone->axfr_serial != stream->serial))
        {
            // file written OR file written and a new one starts to be written => done
            
            /* log_debug("zdb_zone_axfr_input_stream_read: first chance EOF"); */

            first_chance_eof = TRUE;
        }
        else
        {
            // just wait
            
            /* log_debug("zdb_zone_axfr_input_stream_read: wait"); */
        }

        usleep(100000); // 10ms
    }
}

static ya_result
zdb_zone_axfr_input_stream_skip(input_stream* stream_, u32 len)
{
    // Yes, this is not the usual pattern : skip will simply read from the stream into
    // a buffer so the call is simply forwarded to the reader.
    //zdb_zone_axfr_input_stream_data* stream = (zdb_zone_axfr_input_stream_data*)stream_;
    ya_result total = 0;
        
    u8 tmp[512];
    
    while(len > 0)
    {
        // Yes, I meant to use stream_ and not "stream"
        ya_result n = zdb_zone_axfr_input_stream_read(stream_, tmp, MIN(len, sizeof(tmp)));
        
        if(FAIL(n))
        {
            return n;
        }
        
        if(n == 0)
        {
            break;
        }
        
        total += n;
    }
    
    return total;
}

static void
zdb_zone_axfr_input_stream_close(input_stream* is)
{
    zdb_zone_axfr_input_stream_data* data = (zdb_zone_axfr_input_stream_data*)is->data;
    
    input_stream_close(&data->filtered);
    
    free(data);
    
    input_stream_set_void(is);
}

static input_stream_vtbl zdb_zone_axfr_input_stream_vtbl =
{
    zdb_zone_axfr_input_stream_read,
    zdb_zone_axfr_input_stream_skip,
    zdb_zone_axfr_input_stream_close,
    "zdb_zone_axfr_input_stream"
};

ya_result
zdb_zone_axfr_input_stream_open_with_path(input_stream *is, zdb_zone *zone, const char *filepath)
{
    ya_result ret;
    u32 serial;
    //u32 timestamp;
    
    serial    = zone->axfr_serial;
    //timestamp = zone->axfr_timestamp; 
    
    if(ISOK(ret = file_input_stream_open(is, filepath)))
    {
        zdb_zone_axfr_input_stream_data* data;
        MALLOC_OBJECT_OR_DIE(data, zdb_zone_axfr_input_stream_data, AXFRIS_TAG);
        data->filtered.data = is->data;
        data->filtered.vtbl = is->vtbl;
        data->serial = serial;
        data->zone = zone;

        is->data = data;
        is->vtbl = &zdb_zone_axfr_input_stream_vtbl;
    }
    
    return ret;
}

ya_result
zdb_zone_axfr_input_stream_open(input_stream *is, zdb_zone *zone)
{
    ya_result ret;
    u32 serial;
    u32 timestamp;
    char path[PATH_MAX];

    serial    = zone->axfr_serial;
    timestamp = zone->axfr_timestamp;    
        
        
    while(timestamp == 0)
    {
       /* 
        * being written : try to open the axfr.part file
        * in the event of a success, a stream waiting for the completion of the file will be returned
        */

        if(ISOK(ret = zdb_zone_path_get_provider()(
            zone->origin, 
            path, sizeof(path) - 6,
            ZDB_ZONE_PATH_PROVIDER_AXFR_FILE|ZDB_ZONE_PATH_PROVIDER_MKDIR)))
        {
            memcpy(&path[ret], ".part", 6);

            if(ISOK(ret = file_input_stream_open(is, path)))
            {
                zdb_zone_axfr_input_stream_data* data;
                MALLOC_OBJECT_OR_DIE(data, zdb_zone_axfr_input_stream_data, AXFRIS_TAG);
                data->filtered.data = is->data;
                data->filtered.vtbl = is->vtbl;
                data->serial = serial;
                data->zone = zone;

                is->data = data;
                is->vtbl = &zdb_zone_axfr_input_stream_vtbl;

                return ret;
            }
        }
        
        if(dnscore_shuttingdown())
        {
            return STOPPED_BY_APPLICATION_SHUTDOWN;
        }

        usleep(10000);

        serial    = zone->axfr_serial;
        timestamp = zone->axfr_timestamp;
    }

    /*
     * already written : try to open the axfr file
     * in the event of a success, a simple file input stream will be returned
     */

    if(ISOK(ret = zdb_zone_path_get_provider()(
        zone->origin, 
        path, sizeof(path) - 6,
        ZDB_ZONE_PATH_PROVIDER_AXFR_FILE|ZDB_ZONE_PATH_PROVIDER_MKDIR)))
    {
        ret = file_input_stream_open(is, path);
    }

    return ret;
}

/** @} */

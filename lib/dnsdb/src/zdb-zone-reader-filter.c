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

/** @defgroup dnsdbzone
 *  @ingroup dnsdb
 *  @brief Functions used to load a zone
 *
 *  Functions used to load a zone
 *
 * @{
 */

#include <dnscore/zalloc.h>

#include "dnsdb/dnsdb-config.h"
#include "dnsdb/zdb-zone-reader-filter.h"

#define ZFRFDATA_TAG 0x415441444652465a

struct zone_reader_text_filter_data
{
    zone_reader *zr;
    zone_file_reader_filter_callback *callback;
    void *callback_data;
};

typedef struct zone_reader_text_filter_data zone_reader_text_filter_data;

static ya_result
zone_reader_filter_read_record(zone_reader *zr, resource_record *rr)
{
    zone_reader_text_filter_data *data = (zone_reader_text_filter_data*)zr->data;
    
    for(;;)
    {
        ya_result ret = zone_reader_read_record(data->zr, rr);

        if(ret != 0)    // failure or end of input
        {
            return ret;
        }
        
        ya_result cb_ret = data->callback(data->zr, rr, data->callback_data);

        switch(cb_ret)
        {
            case ZONE_READER_FILTER_ACCEPT:
                return ret;
            case ZONE_READER_FILTER_REJECT:
                break;
            default:
                return cb_ret;
        }
    }
}

static ya_result
zone_reader_filter_unread_record(zone_reader *zr, resource_record *rr)
{
    zone_reader_text_filter_data *data = (zone_reader_text_filter_data*)zr->data;
    return zone_reader_unread_record(data->zr, rr);
}

static ya_result
zone_reader_filter_free_record(zone_reader *zr, resource_record *rr)
{
    zone_reader_text_filter_data *data = (zone_reader_text_filter_data*)zr->data;
    return zone_reader_free_record(data->zr, rr);
}

static void
zone_reader_filter_close(zone_reader *zr)
{
    zone_reader_text_filter_data *data = (zone_reader_text_filter_data*)zr->data;
    zone_reader_close(data->zr);
    ZFREE(data, zone_reader_text_filter_data);
    zr->data = NULL;
    zr->vtbl = NULL;
}

static bool
zone_reader_filter_canwriteback(zone_reader *zr)
{
    zone_reader_text_filter_data *data = (zone_reader_text_filter_data*)zr->data;
    yassert(zr != data->zr);
    bool b = zone_reader_canwriteback(data->zr);
    return b;
}

static void
zone_reader_filter_handle_error(zone_reader *zr, ya_result error_code)
{
    zone_reader_text_filter_data *data = (zone_reader_text_filter_data*)zr->data;
    zone_reader_handle_error(data->zr, error_code);
}

static const char*
zone_reader_filter_get_last_error_message(zone_reader *zr)
{
    zone_reader_text_filter_data *data = (zone_reader_text_filter_data*)zr->data;
    const char *ret = zone_reader_get_last_error_message(data->zr);
    return ret;
}

static const zone_reader_vtbl zone_reader_filter_vtbl =
{
    zone_reader_filter_read_record,
    zone_reader_filter_unread_record,
    zone_reader_filter_free_record,
    zone_reader_filter_close,
    zone_reader_filter_handle_error,
    zone_reader_filter_canwriteback,
    zone_reader_filter_get_last_error_message,
    "zone_reader_filter"
};

/**
 * 
 * Wraps a zone_reader to a filter that skips records using a callback
 * 
 * @param filtering_reader  the filter
 * @param filtered_reader   the filtered
 * @param callback          the callback function
 * @param callback_data     parameter given to the callback function
 */

void
zone_reader_text_filter(zone_reader *filtering_reader,
                        zone_reader *filtered_reader,
                        zone_file_reader_filter_callback *callback,
                        void *callback_data)
{
    zone_reader_text_filter_data *data;
    ZALLOC_OBJECT_OR_DIE( data, zone_reader_text_filter_data, ZFRFDATA_TAG);
    data->zr = filtered_reader;
    data->callback = callback;
    data->callback_data = callback_data;
    
    filtering_reader->data = data;
    filtering_reader->vtbl = &zone_reader_filter_vtbl;
}

/**
 * @}
 */

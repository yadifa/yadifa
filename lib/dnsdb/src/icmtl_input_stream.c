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
/** @defgroup ### #######
 *  @ingroup dnsdb
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "dnsdb/zdb_icmtl.h"
#include <dnscore/input_stream.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/format.h>
#include <dnscore/rfc.h>

/*
 *
 */

#define ICMTL_INPUT_STREAM_TAG 0x53494c544d4349 /* ICMTLIS */

#define ICMTL_IS_STATUS_PREFIX	    0
#define ICMTL_IS_STATUS_OLDSOA	    1
#define ICMTL_IS_STATUS_REMOVING	2
#define ICMTL_IS_STATUS_NEWSOA	    3
#define ICMTL_IS_STATUS_ADDING	    4
#define ICMTL_IS_STATUS_SUFFIX	    5
#define ICMTL_IS_STATUS_DONE	    6
#define ICMTL_IS_STATUS_EOF         7

#define ICMTL_BUFFER_SIZE	    4096

static u32 icmtl_read = 0;
static u32 icmtl_copied = 0;

typedef struct zdb_icmtl_input_stream_data zdb_icmtl_input_stream_data;

struct zdb_icmtl_input_stream_data
{
    input_stream icmtls_bis;
    input_stream icmtla_bis;
    input_stream icmtlr_bis;

    u32 from;
    u32 to;

    u32 buffer_size;
    u32 buffer_offset;

    u8 status;
    bool skip_first_and_last;
    char folder[1024];
    u8 origin[MAX_DOMAIN_LENGTH];
    u8 buffer[MAX_DOMAIN_LENGTH + 10 + 65536];

};

static ya_result
zdb_icmtl_input_stream_next_record(input_stream* is, zdb_icmtl_input_stream_data* data)
{
    ya_result ret;
    u32 size = 0;
    u16 rtype = 0;

    if(FAIL(ret = input_stream_read_dnsname(is, data->buffer)))
    {
        return ret;
    }

    if(ret > 0)
    {
        size += ret;

        if(FAIL(ret = input_stream_read(is, &data->buffer[size], 10)))
        {
            return ret;
        }

        rtype = (GET_U16_AT(data->buffer[size])); /** @note : NATIVETYPE */

        u16 rdata_size = ntohs(GET_U16_AT(data->buffer[size + 8]));

        size += ret;

        yassert(ret == 10);

        if(FAIL(ret = input_stream_read(is, &data->buffer[size], rdata_size)))
        {
            return ret;
        }

        yassert(ret == rdata_size);

        size += ret;
    }

    data->buffer_size = size;
    data->buffer_offset = 0;

    return rtype;
}

static ya_result
zdb_icmtl_input_stream_reset_icmtls(zdb_icmtl_input_stream_data* data)
{
    char name[1024];

    ya_result err;

    output_stream_close(&data->icmtls_bis);

    snformat(name, sizeof (name), ICMTL_SUMMARY_FILE_FORMAT, data->folder, data->origin, data->from, data->to);

    input_stream icmtls_is;

    if(ISOK(err = file_input_stream_open(name, &icmtls_is)))
    {
        buffer_input_stream_init(&icmtls_is, &data->icmtls_bis, ICMTL_BUFFER_SIZE);
    }

    return err;
}

static ya_result
zdb_icmtl_input_stream_fillbuffer(zdb_icmtl_input_stream_data* data)
{
    ya_result err = ZDB_ERROR_ICMTL_STATUS_INVALID;

    switch(data->status)
    {
        case ICMTL_IS_STATUS_PREFIX:
            data->status = ICMTL_IS_STATUS_OLDSOA;

        case ICMTL_IS_STATUS_OLDSOA:
        {
            /* reset the stream */

            if(ISOK(err = zdb_icmtl_input_stream_reset_icmtls(data)))
            {
                if(ISOK(err = zdb_icmtl_input_stream_next_record(&data->icmtls_bis, data)))
                {
                    data->status = ICMTL_IS_STATUS_REMOVING;
                }
            }

            break;
        }
        case ICMTL_IS_STATUS_REMOVING:
        {
            err = zdb_icmtl_input_stream_next_record(&data->icmtlr_bis, data);

            /* 0 => found a record type or an error occurred */

            if(err != 0)
            {
                break;
            }

            data->status = ICMTL_IS_STATUS_NEWSOA;

            /* Falltrough */
        }
        case ICMTL_IS_STATUS_NEWSOA:
        {
            if(ISOK(err = zdb_icmtl_input_stream_next_record(&data->icmtls_bis, data)))
            {
                data->status = ICMTL_IS_STATUS_ADDING;
            }

            break;
        }
        case ICMTL_IS_STATUS_ADDING:
        {
            err = zdb_icmtl_input_stream_next_record(&data->icmtla_bis, data);

            /* 0 => found a record type or an error occurred */

            if(err != 0)
            {
                break;
            }

            data->status = ICMTL_IS_STATUS_SUFFIX;

            err = SUCCESS;

            data->buffer_size = 0;
            data->buffer_offset = 0;

            break;
        }

        case ICMTL_IS_STATUS_SUFFIX:
            data->status = ICMTL_IS_STATUS_DONE;

        case ICMTL_IS_STATUS_DONE:
        {
            err = SUCCESS;

            data->buffer_size = 0;
            data->buffer_offset = 0;

            break;
        }
        default:
        {
            break;
        }
    }

    return err;
}

static ya_result
zdb_icmtl_input_stream_read(input_stream* stream, u8* buffer_start, u32 len)
{
    zdb_icmtl_input_stream_data* data = (zdb_icmtl_input_stream_data*)stream->data;
    u8* buffer = buffer_start;
    ya_result err;

    while(len > 0)
    {
        if(data->buffer_offset >= data->buffer_size)
        {
            /* refill */

            if(FAIL(err = zdb_icmtl_input_stream_fillbuffer(data)))
            {
                return err;
            }

            icmtl_read += data->buffer_size;
        }

        u32 n = MIN(len, data->buffer_size - data->buffer_offset);

        if(n == 0)
        {
            break;
        }

        icmtl_copied += n;

        MEMCOPY(buffer, &data->buffer[data->buffer_offset], n);

        len -= n;
        data->buffer_offset += n;
        buffer += n;
    }

    return buffer - buffer_start;
}

static ya_result
zdb_icmtl_input_stream_skip(input_stream* stream, u32 len)
{
    return input_stream_skip(stream, len);
}

static void
zdb_icmtl_input_stream_close(input_stream* stream)
{
    zdb_icmtl_input_stream_data* data = (zdb_icmtl_input_stream_data*)stream->data;
    input_stream_close(&data->icmtls_bis);
    input_stream_close(&data->icmtlr_bis);
    input_stream_close(&data->icmtla_bis);

    free(data);

    stream->data = NULL;
    stream->vtbl = NULL;
}

static input_stream_vtbl zdb_icmtl_input_stream_vtbl ={
    zdb_icmtl_input_stream_read,
    zdb_icmtl_input_stream_skip,
    zdb_icmtl_input_stream_close,
    "zdb_icmtl_input_stream"
};

ya_result
icmtl_input_stream_open(u8* origin, u32 from, u32 to, input_stream* out_is, const char* folder)
{
    char name[1024];

    ya_result err;
    
    size_t folder_len = strlen(folder) + 1;

    if(folder_len > 1024)
    {
        return ZDB_ERROR_ICMTL_FOLDERPATHTOOLONG;
    }

    zdb_icmtl_input_stream_data* data;
    MALLOC_OR_DIE(zdb_icmtl_input_stream_data*, data, sizeof (zdb_icmtl_input_stream_data), ICMTL_INPUT_STREAM_TAG);

    snformat(name, sizeof (name), ICMTL_SUMMARY_FILE_FORMAT, folder, origin, from, to);

    input_stream icmtls_is; /* I could use the same temp var for the 3 input_streams but I think it's cleared this way */

    if(FAIL(err = file_input_stream_open(name, &icmtls_is)))
    {
        free(data);
        return err;
    }

    buffer_input_stream_init(&icmtls_is, &data->icmtls_bis, ICMTL_BUFFER_SIZE);

    snformat(name, sizeof (name), ICMTL_ADD_FILE_FORMAT, folder, origin, from, to);

    input_stream icmtla_is; /* I could use the same temp var for the 3 input_streams but I think it's cleared this way */

    if(FAIL(err = file_input_stream_open(name, &icmtla_is)))
    {
        output_stream_close(&data->icmtls_bis);
        free(data);
        return err;
    }

    buffer_input_stream_init(&icmtla_is, &data->icmtla_bis, ICMTL_BUFFER_SIZE);

    snformat(name, sizeof (name), ICMTL_REMOVE_FILE_FORMAT, folder, origin, from, to);

    input_stream icmtlr_is; /* I could use the same temp var for the 3 input_streams but I think it's cleared this way */

    if(FAIL(err = file_input_stream_open(name, &icmtlr_is)))
    {
        output_stream_close(&data->icmtla_bis);
        output_stream_close(&data->icmtls_bis);
        free(data);
        return err;
    }

    buffer_input_stream_init(&icmtlr_is, &data->icmtlr_bis, ICMTL_BUFFER_SIZE);

    data->from = from;
    data->to = to;

    data->buffer_size = 0;
    data->buffer_offset = 0;

    data->status = ICMTL_IS_STATUS_PREFIX;

    memcpy(data->folder, folder, folder_len);

    dnsname_copy(data->origin, origin);

    data->skip_first_and_last = FALSE;

    out_is->data = data;
    out_is->vtbl = &zdb_icmtl_input_stream_vtbl;

    return SUCCESS;
}

void
icmtl_input_stream_skip_headtail(input_stream* stream)
{
    zdb_icmtl_input_stream_data* data = (zdb_icmtl_input_stream_data*)stream->data;

    data->skip_first_and_last = TRUE;
}

/** @} */

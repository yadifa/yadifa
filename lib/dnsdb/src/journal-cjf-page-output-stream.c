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

#define JOURNAL_CJF_BASE 1

#include "dnsdb/dnsdb-config.h"

#define ZDB_JOURNAL_CODE 1

#include "dnsdb/journal.h"

#if JOURNAL_CJF_ENABLED

#include <dnscore/buffer_output_stream.h>
#include <dnscore/file_output_stream.h>

#include "dnsdb/journal-cjf-page.h"
#include "dnsdb/journal-cjf-idxt.h"
#include "dnsdb/journal-cjf-page-cache.h"
#include "dnsdb/zdb_utils.h"

#define JCJFPOSD_TAG 0x44534f50464a434a

struct journal_cjf_page_output_stream_data
{
    output_stream filtered;
    journal_cjf *jnl;
    u32 serial_from;
    u32 serial_to;
    u32 soa_to_offset;
    u32 start_offset;
    u32 size;
    u8  flags;
};

static ya_result journal_cjf_page_output_stream_write(output_stream* stream, const u8* buffer, u32 len);
static ya_result journal_cjf_page_output_stream_flush(output_stream* stream);
static void journal_cjf_page_output_stream_close(output_stream *stream);

static const output_stream_vtbl journal_cjf_page_output_stream_vtbl =
{
    journal_cjf_page_output_stream_write,
    journal_cjf_page_output_stream_flush,
    journal_cjf_page_output_stream_close,
    "journal_cjf_page_output_stream",
};

typedef struct journal_cjf_page_output_stream_data journal_cjf_page_output_stream_data;

static ya_result
journal_cjf_page_output_stream_write(output_stream* stream, const u8* buffer, u32 len)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;

    ya_result ret = output_stream_write(&data->filtered, buffer, len);
    
    if(ISOK(ret))
    {
        data->size += ret;
    }
    
    return ret;
}

static ya_result
journal_cjf_page_output_stream_flush(output_stream* stream)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;

    ya_result ret = output_stream_flush(&data->filtered);
    
    return ret;
}

/**
 * 
 * 
 * 
 * @param jnl the journal
 * @param os the current output for the records (SOA --- SOA +++)
 * @param size amount of bytes taken by the records
 * @param last_serial (the one of the SOA+++)
 */

void
journal_cjf_page_output_stream_next(output_stream *stream)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;
    journal_cjf *jnl = data->jnl;
    
    // if the stream is not empty
    
    if(data->size > 0)
    {
        yassert(data->flags == 7);
        
        log_debug2("cjf: updating PAGE stream of size %u, ending at position %u (%08x), with serial %u",
               data->size, jnl->last_page.records_limit + data->size, jnl->last_page.records_limit + data->size, data->serial_to);
        
        journal_cjf_page_tbl_item item;
        journal_cjf_page_tbl_header head;
        
        item.ends_with_serial = data->serial_to;
        item.stream_file_offset = jnl->last_page.records_limit;
        
        // CFJ_PAGE_CACHE ->
        log_debug3("cjf: updating PAGE item at %u[(1 + %u) * 8]", jnl->last_page.file_offset, jnl->last_page.count);

        journal_cjf_page_cache_read_header(jnl->file, jnl->last_page.file_offset, &head);
        head.stream_end_offset = item.stream_file_offset + data->size;
        head.count = jnl->last_page.count + 1;
        journal_cjf_page_cache_write_header(jnl->file, jnl->last_page.file_offset, &head);
        
        journal_cjf_page_cache_write_item(jnl->file, jnl->last_page.file_offset, jnl->last_page.count, &item);
        // CFJ_PAGE_CACHE <-
        
        if(jnl->last_page.count == 0)
        {
            jnl->last_page.serial_start = data->serial_from;
        }
        
        jnl->last_page.serial_end =  data->serial_to;
        journal_cjf_idxt_update_last_serial(jnl, data->serial_to);
        jnl->serial_end = data->serial_to;
        
        jnl->last_page.records_limit += data->size;
        
        jnl->last_page.count = head.count;
        jnl->last_soa_offset = data->soa_to_offset;
        
        if(journal_cjf_isempty(jnl))
        {
            jnl->serial_begin = data->serial_from;
        }
        jnl->serial_end = data->serial_to;
        
        journal_cjf_set_dirty(jnl);
        journal_cjf_clear_empty(jnl);
        
        // reset the stream data
        
        data->start_offset += data->size;
        data->size = 0;
        data->serial_from = data->serial_to;
        data->soa_to_offset = 0;
        data->flags = 1;
        
        log_debug_jnl(jnl, "cjf: journal_cjf_page_next_output_stream: AFTER");
    }
    else
    {
        log_debug2("cjf: PAGE stream is empty");
    }
}

/**
 * 
 * 
 * 
 * @param jnl the journal
 * @param os the current output for the records (SOA --- SOA +++)
 * @param size amount of bytes taken by the records
 * @param last_serial (the one of the SOA+++)
 */

static void
journal_cjf_page_output_stream_close(output_stream *stream)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;
    
    log_debug2("cjf: finishing PAGE stream");
       
    if(stream->vtbl == &journal_cjf_page_output_stream_vtbl)
    {
        // the stream must be empty (else we are losing stuff)
        
        yassert(data->size == 0);
        
        journal_cjf *jnl = data->jnl;
            
        if(is_buffer_output_stream(&data->filtered))
        {
            log_debug3("cjf: flushing PAGE item");
            
            journal_cjf_page_output_stream_flush(stream);
            file_pool_file_output_stream_detach(buffer_output_stream_get_filtered(&data->filtered));
            output_stream_close(&data->filtered);
        }
        else
        {
            log_debug3("cjf: no PAGE item to flush");
        }
        
        journal_cjf_page_cache_flush(jnl->file);
        
        log_debug3("cjf: closing PAGE item");
        ZFREE(data, journal_cjf_page_output_stream_data);
        output_stream_set_void(stream);
    }
    else
    {
        log_debug3("cjf: there are no opened PAGE stream to close");
    }
}

/**
 * 
 * Closes the stream and do not update the current PAGE
 * 
 * @param jnl
 * @param os
 */

void
journal_cjf_page_output_stream_cancel(output_stream *stream)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;
    
    if(stream->vtbl == &journal_cjf_page_output_stream_vtbl)
    {
        log_debug2("cjf: cancelling PAGE stream, ending at position %u (%08x)",
                   data->jnl->last_page.records_limit, data->jnl->last_page.records_limit);

        journal_cjf_page_output_stream_flush(stream);
        file_pool_file_output_stream_detach(buffer_output_stream_get_filtered(&data->filtered));
        output_stream_close(&data->filtered);
        output_stream_set_void(&data->filtered);
        data->size = 0;
        data->serial_from = 0;
        data->serial_to = 0;
        data->soa_to_offset = 0;
        data->flags = 0;

        log_debug3("cjf: cancelling PAGE item");

        log_debug_jnl(data->jnl, "cjf: journal_cjf_page_cancel_output_stream: AFTER");
    }
    else
    {
        log_debug3("cjf: there are no opened PAGE stream to cancel");
    }
}

void
journal_cjf_page_output_stream_set_serial_from(output_stream *stream, u32 serial)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;
    data->serial_from = serial;
    data->flags |= 1;
}

void
journal_cjf_page_output_stream_set_serial_to(output_stream *stream, u32 serial)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;
    data->serial_to = serial;
    data->flags |= 2;
}

void
journal_cjf_page_output_stream_set_soa_to_offset(output_stream *stream, u32 offset)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;
    data->soa_to_offset = offset;
    data->flags |= 4;
}

ya_result
journal_cfj_page_output_stream_write_resource_record(output_stream *stream, dns_resource_record *rr)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;

    yassert(dnsname_is_subdomain(rr->name, data->jnl->origin));
    
    ya_result ret;
    
    if(rr->tctr.qtype == TYPE_SOA)
    {
        u32 serial;
        
        if(FAIL(ret = rr_soa_get_serial(rr->rdata, rr->rdata_size, &serial)))
        {
            return ret;
        }
        
        if(data->size == 0)
        {
            if((data->flags & 1) == 1)
            {
                // test that it matches the from
            }
            
            journal_cjf_page_output_stream_set_serial_from(stream, serial);
        }
        else
        {
            yassert((data->flags & 2) == 0);
            journal_cjf_page_output_stream_set_serial_to(stream, serial);
            journal_cjf_page_output_stream_set_soa_to_offset(stream, data->start_offset + data->size);
        }
    }
    
    ret = dns_resource_record_write(rr, stream);
    
    return ret;
}

u32
journal_cjf_page_output_stream_reopen(output_stream *out_os, journal_cjf *jnl)
{
    // get the current page
    
    if((jnl->last_page.count == 0) && (jnl->last_page.file_offset == CJF_HEADER_SIZE) && (jnl->first_page_offset == CJF_HEADER_SIZE))
    {
        // CFJ_PAGE_CACHE ->
        journal_cjf_page_cache_write_new_header(jnl->file, jnl->last_page.file_offset);
        // CFJ_PAGE_CACHE <-

        log_debug_jnl(jnl, "journal_cjf_page_open_next_output_stream: INIT");
    }
     
    if(out_os->vtbl == &journal_cjf_page_output_stream_vtbl)
    {
        if(journal_cjf_page_is_full(jnl))
        {
            // if there no room left, append a new page, it becomes the current pag
            // flush the stream
            journal_cjf_page_output_stream_flush(out_os);
            journal_cjf_idxt_append_page(jnl);
            // reposition the stream
            if(file_pool_seek(jnl->file, jnl->last_page.records_limit, SEEK_SET) < 0)
            {
                log_err("cjf: %{dnsname}: cannot move into journal at new page (file=%p, pos=%llu): %r", jnl->origin, jnl->file, jnl->last_page.records_limit, ERRNO_ERROR);
                logger_flush();
                return ERRNO_ERROR;
            }
        }
        
        log_debug2("cjf: continuing next PAGE stream at position %u (%08x)", jnl->last_page.records_limit, jnl->last_page.records_limit);
#ifndef NDEBUG
        journal_cjf_page_output_stream_data *data = (journal_cjf_page_output_stream_data*)out_os->data;
        yassert(data->size == 0);
#endif // NDEBUG
    }
    else
    {
        if(journal_cjf_page_is_full(jnl))
        {
            // if there no room left, append a new page, it becomes the current pag
            journal_cjf_idxt_append_page(jnl);
        }
        
        log_debug2("cjf: opening next PAGE stream at position %u (%08x)", jnl->last_page.records_limit, jnl->last_page.records_limit);
    
        if(file_pool_seek(jnl->file, jnl->last_page.records_limit, SEEK_SET) < 0)
        {
            log_err("cjf: %{dnsname}: cannot move into journal at next page (file=%p, pos=%llu): %r", jnl->origin, jnl->file, jnl->last_page.records_limit, ERRNO_ERROR);
            logger_flush();
            return ERRNO_ERROR;
        }
        
        journal_cjf_page_output_stream_data *data;
        ZALLOC_OBJECT_OR_DIE( data, journal_cjf_page_output_stream_data, JCJFPOSD_TAG);
        ZEROMEMORY(data, sizeof(journal_cjf_page_output_stream_data));  // false positive: data cannot be NULL
        file_pool_file_output_stream_init(&data->filtered, jnl->file);              // this initialises the stream
        file_output_stream_set_full_writes(&data->filtered, TRUE);      // this makes the stream "write fully"
        buffer_output_stream_init(&data->filtered, &data->filtered, 512);
        data->jnl = jnl;
        data->start_offset = jnl->last_page.records_limit;
        
        out_os->data = data;
        out_os->vtbl = &journal_cjf_page_output_stream_vtbl;
    }
    
    return jnl->last_page.records_limit;
}

u32
journal_cfj_page_output_stream_get_size(output_stream *stream)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;
    return data->size;
}

u32
journal_cfj_page_output_stream_get_start_offset(output_stream *stream)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;
    return data->start_offset;
}

u32
journal_cfj_page_output_stream_get_current_offset(output_stream *stream)
{
    journal_cjf_page_output_stream_data* data = (journal_cjf_page_output_stream_data*)stream->data;
    return data->start_offset + data->size;
}

#endif

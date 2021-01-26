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

/*******************************************************************************
 * 
 * Indexes table handling functions
 *
 * These are the tables containing offsets to a serial
 * They are linked together
 * They are often referenced by an unique table of indexes
 * 
 ******************************************************************************/

#define JOURNAL_CJF_BASE 1

#include "dnsdb/dnsdb-config.h"

#define ZDB_JOURNAL_CODE 1

#include "dnsdb/journal.h"

#if JOURNAL_CJF_ENABLED

#include "dnsdb/journal-cjf-page-cache.h"
#include "dnsdb/journal-cjf-idxt.h"
#include "dnsdb/journal-cjf-common.h"

#include <dnscore/logger.h>
#include <dnscore/file_input_stream.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/buffer_output_stream.h>
#include <dnscore/fdtools.h>
#include <dnscore/serial.h>

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define CJF_IDXT_SLOT_SIZE 8


const journal_cjf_idxt_tbl_item*
journal_cjf_idxt_get_entry(const journal_cjf *jnl, s16 index)
{
    yassert(index >= 0);yassert(jnl->idxt.first >= 0);
    
    journal_cjf_idxt_tbl_item *entry;
    entry = &jnl->idxt.entries[(jnl->idxt.first + index) % jnl->idxt.size];
    return entry;
}

s16
journal_cjf_idxt_size(const journal_cjf *jnl)
{
    return jnl->idxt.count;
}

s16
journal_cjf_idxt_size_max(const journal_cjf *jnl)
{
    return jnl->idxt.size;
}

/**
 * 
 * Returns the file offset value at index in the current IDXT
 * 
 * @param jnl
 * @param index
 * @return 
 */

u32
journal_cjf_idxt_get_file_offset(const journal_cjf *jnl, s16 index)
{
    u32 file_offset = journal_cjf_idxt_get_entry(jnl, index)->file_offset;
    return file_offset;
}

u32
journal_cjf_idxt_get_last_file_offset(const journal_cjf *jnl)
{
    if(jnl->idxt.count > 0)
    {
        u32 n = journal_cjf_idxt_get_file_offset(jnl, jnl->idxt.count - 1);
        return n;
    }
    else
    {
        return 0;
    }
}

/**
 * 
 * Returns the last serial number value at index in the IDXT
 * 
 * @param jnl
 * @param index
 * @return 
 */

u32
journal_cjf_idxt_get_last_serial(const journal_cjf *jnl, s16 index)
{
    u32 last_serial = journal_cjf_idxt_get_entry(jnl, index)->last_serial;
    return last_serial;
}

/**
 * Creates an empty table of indexes (IDXT) for the journal, with a minimum number of entries.
 * Nothing is written to disk.
 * 
 * @param jnl
 * @param entries
 */

void
journal_cjf_idxt_create(journal_cjf *jnl, s16 entries)
{
    yassert(jnl->idxt.size == 0);
    yassert(entries >= 0);
    
    jnl->idxt.count = 1;
    jnl->idxt.first = 0;
    jnl->idxt.size = entries + 1;
    jnl->idxt.dirty = TRUE;
    jnl->idxt.marked = 0;
    
    MALLOC_OR_DIE(journal_cjf_idxt_tbl_item*, jnl->idxt.entries, sizeof(journal_cjf_idxt_tbl_item) * jnl->idxt.size, JCJFITI_TAG);
    ZEROMEMORY(jnl->idxt.entries, sizeof(journal_cjf_idxt_tbl_item) * jnl->idxt.size);
    
    jnl->idxt.entries[0].last_serial = jnl->serial_begin;
    jnl->idxt.entries[0].file_offset = jnl->last_page.file_offset;
    jnl->first_page_offset = jnl->last_page.file_offset;
}

/**
 * Verifies the page table chain
 * To be used for small discrepancies between the header and the page table (idxt)
 * 
 * @param jnl
 * @return 
 */

static ya_result
journal_cjf_idxt_verify(journal_cjf *jnl)
{
    // check the values of the pages
    // serials have to be ordered in serial arithmetics
    // pages are supposed to start after each other except a looping ones that goes after the header
    
    // if the verify fails, a scan may be needed (other procedure)
    
    journal_cjf_page_tbl_header page_hdr;
    u32 previous_page_offset;
    u32 stream_end_offset;
    u32 next_page_offset; // uninitialised false positive: either size is <= 0, skipping for & if, either it's >= 0 and page_hrd is set and initialises next_page_offset
    u32 prev_serial = jnl->serial_begin;
    int loops = 0;
    bool error = FALSE;
    bool has_page_after_header = FALSE;
    
    s16 size = journal_cjf_idxt_size(jnl);
    
    for(int page = 0; page < size; ++page)
    {
        const journal_cjf_idxt_tbl_item* entry = journal_cjf_idxt_get_entry(jnl, page);
        
        has_page_after_header |= entry->file_offset == CJF_HEADER_SIZE;
        
        if(page > 0)
        {
            if(entry->file_offset != next_page_offset) // gcc false positive: next_page_offset is initialised when page == 0
            {
                // page do not start at the expected position
                log_err("cjf: %{dnsname}: page[%i] starts at an unexpected position (%u != expected %u)", jnl->origin, page, entry->file_offset, next_page_offset);
                error = TRUE;
            }
            
            if(entry->file_offset == previous_page_offset)
            {
                // broken chain
                log_err("cjf: %{dnsname}: page[%i] is a duplicate at position %u", jnl->origin, page, entry->file_offset);
                error = TRUE;
            }
            
            if(entry->file_offset > previous_page_offset)
            {
                if(entry->file_offset != stream_end_offset)
                {
                    // suspicious hole in the file
                    log_err("cjf: %{dnsname}: page[%i] is %u bytes after the expected position", jnl->origin, page, entry->file_offset - stream_end_offset);
                    error = TRUE;
                }
            }
            else
            {
                // just looped ...
                
                if(loops == 0)
                {
                    if(entry->file_offset > CJF_HEADER_SIZE)
                    {
                        // looped at an unexpected position
                        log_err("cjf: %{dnsname}: page[%i] looped at an unexpected position (%u != expected %u)", jnl->origin, page, entry->file_offset, CJF_HEADER_SIZE);
                        error = TRUE;
                    }
                    else if(entry->file_offset > CJF_HEADER_SIZE)
                    {
                        // looped at an unexpected position
                        log_err("cjf: %{dnsname}: page[%i] looped into the header position (%u < %u)", jnl->origin, page, entry->file_offset, CJF_HEADER_SIZE);
                        error = TRUE;
                    }
                    
                    loops = 1;
                }
                else
                {
                    // should only have looped once
                    log_err("cjf: %{dnsname}: page[%i] looped for a second time", jnl->origin, page);
                    error = TRUE;
                }
            }
            
            if(error)
            {
                // got at least one error
                return ERROR;
            }
        }
        
        ssize_t pos = file_pool_seek(jnl->file, entry->file_offset, SEEK_SET);
        
        if(pos < 0)
        {
            // invalid position (as EBADF should not happen)
            ya_result ret = ERRNO_ERROR;
            
            log_err("cjf: %{dnsname}: page[%i] seek at %u returned %r", jnl->origin, page, ret);
            
            return ret;
        }

        int len = file_pool_readfully(jnl->file, &page_hdr, CJF_SECTION_INDEX_SLOT_HEAD);
        
        if(len != CJF_SECTION_INDEX_SLOT_HEAD)
        {
            if(len >= 0)
            {
                log_err("cjf: %{dnsname}: page[%i] short count reading the header (%u < %u)", jnl->origin, page, len, CJF_SECTION_INDEX_SLOT_HEAD);
                return ERROR; // short
            }
            else
            {
                log_err("cjf: %{dnsname}: page[%i] error reading the header: %r", jnl->origin, page, len);
                return len; // other error
            }
        }
        
        if(page_hdr.magic != CJF_PAGE_MAGIC)
        {
            // page is corrupted
            log_err("cjf: %{dnsname}: page[%i] corrupted magic", jnl->origin, page);
            return ERROR;
        }
        if(page_hdr.count > page_hdr.size)
        {
            // page is corrupted
            log_err("cjf: %{dnsname}: page[%i] says to contain more than allowed", jnl->origin, page, page_hdr.count, page_hdr.size);
            return ERROR;
        }
        
        if(page_hdr.count == 0)
        {
            // empty page (warning)
            log_warn("cjf: %{dnsname}: page[%i] is empty", jnl->origin, page);
        }
        
        if(serial_gt(prev_serial, entry->last_serial))
        {
            // suspicious serial backward jump
            log_err("cjf: %{dnsname}: page[%i] serial jumped back from %u to %u", jnl->origin, page, prev_serial, entry->last_serial);
        }
        else if(serial_eq(prev_serial, entry->last_serial))
        {
            // suspicious serial standstill
            log_err("cjf: %{dnsname}: page[%i] serial didn't changed from %u", jnl->origin, page, prev_serial);
        }
        
        previous_page_offset = entry->file_offset;
        next_page_offset = page_hdr.next_page_offset; // next page, 0 for the last one
        stream_end_offset = page_hdr.stream_end_offset; // start of next page, start of page table, or 0 for the last in the chain
    }
    
    if(size > 0)
    {
        if(next_page_offset != 0) // gcc false positive: size > 0 => next_page_offset has been set to page_hdr.next_page_offset (read from the disk)
        {
            // chain end was not marked
            log_err("cjf: %{dnsname}: page[%i] is last but points to a next at %u", jnl->origin, size - 1, next_page_offset);
            return ERROR;
        }
        if(!has_page_after_header)
        {
            // no page at an obvious position
            log_err("cjf: %{dnsname}: page table has no page at position %u", jnl->origin, CJF_HEADER_SIZE);
            return ERROR;
        }
    }
    else
    {
        // table is empty
        log_err("cjf: %{dnsname}: page table is empty", jnl->origin);
        return ERROR;
    }
    
    return SUCCESS;
}

/**
 * Loads (or rebuilds) the table of indexes (IDXT)
 * 
 * @param jnl
 */

void
journal_cjf_idxt_load(journal_cjf *jnl)
{
    if(jnl->idxt.entries != NULL)
    {
        // already loaded ...
        return;
    }
    
    // the file is opened
    
    if(jnl->page_table_file_offset != 0)
    {
        log_debug1("journal_cjf_idxt_load: loading stored IDXT from '%s'", jnl->journal_file_name);
        
        // load
        file_pool_seek(jnl->file, jnl->page_table_file_offset, SEEK_SET);
        
        input_stream fis;
        input_stream bis;
        file_pool_file_input_stream_init(&fis, jnl->file);
        
        buffer_input_stream_init(&bis, &fis, 512);
        u8 magic[4];
        input_stream_read(&bis, magic, 4);
        u32 *magic_u32p = (u32*)&magic[0];
        if(*magic_u32p == CJF_IDXT_MAGIC)
        {
            s16 count;
            input_stream_read(&bis, (u8*)&count , 2);

            journal_cjf_idxt_create(jnl, count + 1);
            
            input_stream_read(&bis, (u8*)&jnl->idxt.entries[0], count * CJF_IDXT_SLOT_SIZE);
            
            file_pool_file_input_stream_detach(buffer_input_stream_get_filtered(&bis));
            input_stream_close(&bis);
            
            jnl->idxt.count = count;
            
            u32 first_page_offset = journal_cjf_idxt_get_file_offset(jnl, 0);
            
            if(jnl->first_page_offset != first_page_offset)
            {
                // discrepancy : check the IDXT is valid
                
                if(ISOK(journal_cjf_idxt_verify(jnl)))
                {
                    // the header is wrong, update it
                    
                    jnl->first_page_offset = first_page_offset;
                }
            }
            
            return;
        }
        
        file_pool_file_input_stream_detach(buffer_input_stream_get_filtered(&bis));
        input_stream_close(&bis);
        
        // ERROR, need to rebuild
    }
    
    log_debug1("journal_cjf_idxt_load: rebuilding IDXT from '%s', following the PAGE", jnl->journal_file_name);

    // rebuild
    
    journal_cjf_page_tbl_item *tbl;
    u32 size = 512;
    journal_cjf_page_tbl_item tmp_tbl[512];
    tbl = tmp_tbl;
    
    if(jnl->first_page_offset < JOURNAL_CJF_PAGE_HEADER_SIZE)
    {
        // the PAGE chain has been lost : start from HEAD and follow the chain
        // then after the 0, scan from the furthest known byte for PAGE+offset
        // and follow until the chain points back to offset sizeof(head)
    }
    
    // read the PAGE chain from the file (no caching)
    
    u32 index_offset = jnl->first_page_offset;
    //u32 current_serial = jnl->serial_begin;
    journal_cjf_page_tbl_header page_header;
    journal_cjf_page_tbl_item page_last_item;
    s16 idx = 0;
    u32 page_serial = 0;
    bool page_read = FALSE;
    
    do
    {
        // move to the page offset and read the header
        
        log_debug2("journal_cjf_idxt_load: reading '%s' PAGE header at %x", jnl->journal_file_name, index_offset);
        
        file_pool_seek(jnl->file, index_offset, SEEK_SET);
        if(file_pool_readfully(jnl->file, &page_header, JOURNAL_CJF_PAGE_HEADER_SIZE) != JOURNAL_CJF_PAGE_HEADER_SIZE) // next offset
        {
            log_err("journal_cjf_idxt_load: '%s' is too corrupt to go on further reading PAGE header at %x", jnl->journal_file_name, index_offset);
            break;
        }
        /*
        if(page_header.magic != CJF_PAGE_MAGIC)
        {
            // corrupt
        }
        */
        if(page_header.count > 0)
        {
            u32 tail_offset = (page_header.count - 1) * CJF_SECTION_INDEX_SLOT_SIZE;

            log_debug2("journal_cjf_idxt_load: reading '%s' PAGE tail at %x", jnl->journal_file_name, index_offset + tail_offset);

            // the last serial is on the last slot

            file_pool_seek(jnl->file, tail_offset, SEEK_CUR);
            if(file_pool_readfully(jnl->file, &page_last_item, JOURNAL_CJF_PAGE_ITEM_SIZE) != JOURNAL_CJF_PAGE_ITEM_SIZE)
            {
                log_err("journal_cjf_idxt_load: '%s' is too corrupt to go on further reading PAGE tail at %x", jnl->journal_file_name, index_offset + CJF_SECTION_INDEX_SIZE - CJF_SECTION_INDEX_SLOT_HEAD - CJF_SECTION_INDEX_SLOT_SIZE);
                break;
            }
            
            // if there is a next page ...
        
            if(idx == size)
            {
                log_debug2("journal_cjf_idxt_load: growing IDXT table from %i to %i", size, size * 2);

                journal_cjf_page_tbl_item *tmp;
                MALLOC_OR_DIE(journal_cjf_page_tbl_item*, tmp, JOURNAL_CJF_PAGE_ITEM_SIZE * size * 2, JCJFTI_TAG);
                memcpy(tmp, tbl, JOURNAL_CJF_PAGE_ITEM_SIZE * size);
                if(tbl != tmp_tbl)
                {
                    free(tbl);
                }
                tbl = tmp;
                size *= 2;
            }

            tbl[idx].stream_file_offset = index_offset;
            tbl[idx].ends_with_serial = page_last_item.ends_with_serial;

            log_debug2("journal_cjf_idxt_load: IDXT[%3i] = {%8x, %u}", idx, index_offset, page_last_item.ends_with_serial);
            
            page_serial = page_last_item.ends_with_serial;
            page_read = TRUE;
            
            ++idx;
        
            index_offset = page_header.next_page_offset;
        }
        else
        {
            // an empty page should not exist
            
            if(page_read)
            {
                if(serial_eq(page_serial, jnl->serial_end))
                {
                    log_info("journal_cjf_idxt_load: got up to expected serial %i", page_serial);
                }
                else if(serial_lt(page_serial, jnl->serial_end))
                {
                    log_err("journal_cjf_idxt_load: got up to serial %i, before the expected %i", page_serial, jnl->serial_end);
                }
                else if(serial_gt(page_serial, jnl->serial_end))
                {
                    log_err("journal_cjf_idxt_load: got up to serial %i, after the expected %i", page_serial, jnl->serial_end);
                }
            }
            else
            {
                log_err("journal_cjf_idxt_load: could not read the content of the journal");
            }
            
            break;
        }
    }
    while(index_offset != 0);
    
    log_debug1("journal_cjf_idxt_load: IDXT table has size %i", idx + 1);
    
    // scan for an SOA record
    
    journal_cjf_idxt_create(jnl, idx + 1);
    memcpy(jnl->idxt.entries, tbl, JOURNAL_CJF_PAGE_ITEM_SIZE * idx);
    jnl->idxt.count = idx;
}

/**
 * 
 * Writes the indexes table (IDXT) to the disk, if needed.
 * Updates the header on disk accordingly.
 * Clears the "dirty" and "makred" flags.
 * 
 * @param jnl
 */

void
journal_cjf_idxt_flush(journal_cjf *jnl)
{
    // write the table on disk if not done already
    if(!jnl->idxt.dirty)
    {
        return;
    }
    
    if(jnl->page_table_file_offset == 0)
    {
        log_debug("cjf: %{dnsname}: table index not set", jnl->origin);
        return;
    }
    
    // write the table at the end
    
    off_t end = file_pool_seek(jnl->file, jnl->page_table_file_offset, SEEK_SET);
    
    if(end < 0)
    {
        int err = ERRNO_ERROR;
        
        log_err("cjf: forward to end of PAGE chain failed: %r", err);
        
        if(err == EBADF)
        {
            log_err("cjf: file has been closed before writing the summary");
        }
        
        logger_flush();
        
        return;
    }
    
    output_stream fos;
    output_stream bos;
    
    journal_cjf_set_dirty(jnl);
    
    log_debug3("cjf: flushing IDXT %u indexes at %08x", jnl->idxt.count, jnl->page_table_file_offset);
    
    file_pool_file_output_stream_init(&fos, jnl->file);
    file_pool_file_output_stream_set_full_writes(&fos, TRUE);      // this makes the stream "write fully"
    buffer_output_stream_init(&bos, &fos, 512);
    output_stream_write(&bos, (const u8*)"IDXT", 4);
    output_stream_write(&bos, (const u8*)&jnl->idxt.count , 2);
    for(s16 idx = 0; idx < jnl->idxt.count; idx++)
    {
        output_stream_write(&bos, (const u8*)&jnl->idxt.entries[(jnl->idxt.first + idx) % jnl->idxt.size], CJF_IDXT_SLOT_SIZE);
    }
    output_stream_write(&bos, (const u8*)"END", 4); // yes, with the '\0' at the end
    output_stream_flush(&bos);
    file_pool_file_output_stream_detach(buffer_output_stream_get_filtered(&bos));
    output_stream_close(&bos);
    
    // write the table offset
    
    journal_cjf_header_flush(jnl);
    
#if DO_SYNC
    log_debug3("cjf: syncing to disk");
    
    file_pool_flush(jnl->file);
#endif
    
    jnl->idxt.dirty = FALSE;
    jnl->idxt.marked = FALSE;
    
#if _BSD_SOURCE || _XOPEN_SOURCE >= 500 || _XOPEN_SOURCE && _XOPEN_SOURCE_EXTENDED || /* Since glibc 2.3.5: */ _POSIX_C_SOURCE >= 200112L
    u32 file_size = jnl->page_table_file_offset + 4 + 2 + 4 + jnl->idxt.count * CJF_IDXT_SLOT_SIZE;
    file_pool_resize(jnl->file, file_size);
#endif
}

/**
 * 
 * Flushes the IDXT to disk if needed, then destroys the structure content.
 * 
 * @param jnl
 */

void
journal_cjf_idxt_destroy(journal_cjf *jnl)
{
    journal_cjf_idxt_flush(jnl);
    
    free(jnl->idxt.entries);
    jnl->idxt.entries = NULL;
    
    jnl->idxt.size = 0;
    jnl->idxt.first = 0;
    jnl->idxt.count = 0;
}

/**
 * Updates the value of the last serial at current position in the PAGE
 * 
 * @param jnl
 * @param last_serial
 */

void
journal_cjf_idxt_update_last_serial(journal_cjf *jnl, u32 last_serial)
{
    yassert(jnl->idxt.size > 0);
    journal_cjf_idxt_tbl_item *entry;
    
    entry = &jnl->idxt.entries[(jnl->idxt.first + jnl->idxt.count - 1) % jnl->idxt.size];
    
    log_debug2("cjf: IDXT current (%i) PAGE serial from %08x to %08x", jnl->idxt.count - 1, entry->last_serial, last_serial);
    
    entry->last_serial = last_serial;
    
    jnl->idxt.dirty = TRUE;
}

/**
 * Appends an PAGE table after the current one
 * 
 * @param jcs
 * @param size_hint
 */

static void
journal_cjf_idxt_append_page_nogrow(journal_cjf *jnl)
{
    yassert(jnl->idxt.size > 0);
    journal_cjf_idxt_tbl_item *entry;
    
    jnl_page *page = &jnl->last_page; // last logical page on the (cycling) stream
    
    u32 page_offset = page->file_offset; // physical position of the page
    
    log_debug_jnl(jnl, "cjf: journal_cjf_idxt_append_page_nogrow: BEFORE");
    
    yassert(page->count <= page->size);
    
    page->size = page->count; // we are forcing the change of page (adding but not growing, thus losing the first page if needed)

    if(jnl->idxt.count < jnl->idxt.size)
    {
        // there is still room left in the file : no need to grow, so no problem here
        
        log_debug2("cjf: append PAGE at [%i] offset %u (%08x)", jnl->idxt.count, page->records_limit, page->records_limit);
        // the entry is the next one (at position 'count'), modulo the size of the table
        entry = &jnl->idxt.entries[(jnl->idxt.first + jnl->idxt.count) % jnl->idxt.size];
        jnl->idxt.count++;
                
        entry->last_serial = page->serial_end;
        entry->file_offset = page->records_limit;        
    }
    else
    {
        // there is no room left thus we will replace the first page (increasing the first slot position)
        // overwrite of the start of the cyclic data, update the journal
        
        /*
         * No grow happens when the file is too big and we are about to loop
         */
        
        u32 first_page_offset = journal_cjf_idxt_get_file_offset(jnl, 0);
        
        log_debug2("cjf: append PAGE at [%i] offset %u (%08x), losing first PAGE", jnl->idxt.count, first_page_offset, first_page_offset);
        
        entry = &jnl->idxt.entries[(jnl->idxt.first) % jnl->idxt.size];
        
        yassert(jnl->first_page_offset == entry->file_offset);        
        
        // removes first page, adjusts current PAGE offset_limit
        
        journal_cjf_remove_first_page(jnl); // will decrease the count and move the first
        
        jnl->idxt.count++;
        
        entry->last_serial = page->serial_end;
        entry->file_offset = first_page_offset;
        
        // update the section with the values for the next one
    }
    
    // update the section with the values for the next one
        
    page->file_offset = entry->file_offset;
    page->count = 0;
    page->size = CJF_SECTION_INDEX_SLOT_COUNT;
    page->records_limit = page->file_offset + CJF_SECTION_INDEX_SIZE;   

    if(page->file_offset >= jnl->first_page_offset)
    {
        page->file_offset_limit = jnl->file_maximum_size;
    }
    else
    {
        page->file_offset_limit = jnl->first_page_offset;
    }

    page->serial_start = entry->last_serial;
    page->serial_end = entry->last_serial;
    
    // update the next pointer of the previous PAGE

    // CFJ_PAGE_CACHE ->
    log_debug3("cjf: updating PAGE chain (@%08x = %08x)", page_offset, page->file_offset);
    
    journal_cjf_page_tbl_header current_page_header;
    journal_cjf_page_cache_read_header(jnl->file, page_offset, &current_page_header);
    current_page_header.next_page_offset = page->file_offset;
    journal_cjf_page_cache_write_header(jnl->file, page_offset, &current_page_header);
    
    // writes an empty PAGE table for the current (new) PAGE
    
    log_debug3("cjf: writing new empty PAGE");
    
    journal_cjf_page_cache_write_new_header(jnl->file, page->file_offset);
    // CFJ_PAGE_CACHE <-

    // the IDXT had some changes that need flushing
    
    jnl->idxt.dirty = TRUE;
    
    // only mark the file about its changes once
    
    if(!jnl->idxt.marked)
    {
        jnl->idxt.marked = TRUE;
    }
    
    journal_cjf_page_cache_flush(jnl->file);
    journal_cjf_header_flush(jnl);
    
#if DO_SYNC
    log_debug3("cjf: syncing to disk");
    
    file_pool_flush(jnl->file);
#endif
    
    log_debug_jnl(jnl, "cjf: journal_cjf_idxt_append_page_nogrow: AFTER");
}

/**
 * 
 * Grows the IDTX table by one slot
 * 
 * @param jnl
 */

static void
journal_cjf_idxt_grow(journal_cjf *jnl)
{
    yassert(jnl->idxt.size > 0);
    
    log_debug2("cjf: growing IDXT table to %u slots", jnl->idxt.size + 1);
    
    journal_cjf_idxt_tbl_item *tmp;
    MALLOC_OR_DIE(journal_cjf_idxt_tbl_item*, tmp, sizeof(journal_cjf_idxt_tbl_item) * (jnl->idxt.size + 1), JCJFITI_TAG);
    
    for(s16 idx = 0; idx < jnl->idxt.count; idx++)
    {
        tmp[idx] = jnl->idxt.entries[(jnl->idxt.first + idx) % jnl->idxt.size];
    }
    
    ++jnl->idxt.size;
    
    for(s16 idx = jnl->idxt.count; idx < jnl->idxt.size; idx++)
    {
        tmp[idx].last_serial = 0;
        tmp[idx].file_offset = 0;    
    }
    
    log_debug_jnl(jnl, "cjf: journal_cjf_idxt_grow: BEFORE");
    
    free(jnl->idxt.entries);
    jnl->idxt.entries = tmp;
    jnl->idxt.first = 0;
    
    log_debug_jnl(jnl, "cjf: journal_cjf_idxt_grow: AFTER");
    
}

/**
 * Ensures there is at least one empty available PAGE slot in the IDTX
 * 
 * @param jnl
 */

static void
journal_cjf_idxt_ensure_growth(journal_cjf *jnl)
{
    log_debug2("cjf: ensuring IDXT growth");
    
    if(jnl->idxt.count == jnl->idxt.size)
    {
        journal_cjf_idxt_grow(jnl);
    }
}

/**
 * 
 * Prevent the IDXT table from growing further
 * 
 * @param jnl
 */

static void
journal_cjf_idxt_fix_size(journal_cjf *jnl)
{
    yassert(jnl->idxt.size > 0);
    yassert(jnl->idxt.size >= jnl->idxt.count);
    
    if(jnl->idxt.size != jnl->idxt.count)
    {    
        log_debug2("cjf: fixing IDXT size from %u to %u", jnl->idxt.size, jnl->idxt.count);

        journal_cjf_idxt_tbl_item *tmp;
        MALLOC_OR_DIE(journal_cjf_idxt_tbl_item*, tmp, sizeof(journal_cjf_idxt_tbl_item) * jnl->idxt.count, JCJFITI_TAG);

        for(s16 i = 0; i < jnl->idxt.count; ++i)
        {
            tmp[i] = jnl->idxt.entries[(jnl->idxt.first + i) % jnl->idxt.size];
        }

#if DEBUG
        memset(jnl->idxt.entries, 0xfe, sizeof(journal_cjf_idxt_tbl_item) * jnl->idxt.size);
#endif
        free(jnl->idxt.entries);

        jnl->idxt.entries = tmp;

        jnl->idxt.first = 0;
        jnl->idxt.size = jnl->idxt.count;
    }
    else
    {
        log_debug2("cjf: fixing IDXT size to %u (nothing to do)", jnl->idxt.count);
    }
}

/**
 * Appends an PAGE after this one
 * 
 * @param jnl
 */

void
journal_cjf_idxt_append_page(journal_cjf *jnl)
{
    // where are we in the file ?
    
    log_debug2("cjf: PAGE: @%08x -> %08x ... %08x [%08x; %08x]",
               jnl->last_page.file_offset, jnl->last_page.records_limit, jnl->last_page.file_offset_limit, jnl->last_page.serial_start, jnl->last_page.serial_end);
    
    // if the PAGE (offset) is before the first PAGE (offset)

    if(jnl->last_page.file_offset < jnl->first_page_offset)
    {
        log_debug2("cjf: IDXT adding PAGE (middle of the file)");
        
        // we are in the middle of the physical file (meaning, physically before the first PAGE in the logical order)
        
        yassert(jnl->last_page.records_limit <= jnl->first_page_offset);
        
        // ensure there is enough room after us
        // while there is not enough room, remove one page
        
        while(jnl->first_page_offset - jnl->last_page.records_limit < CJF_SECTION_INDEX_SIZE + CJF_PAGE_ARBITRARY_UPDATE_SIZE)
        {            
            journal_cjf_remove_first_page(jnl);
            
            if(jnl->last_page.file_offset >= jnl->first_page_offset)
            {
                break;
            }
        }
        
        // we made room or we reached a limit before we got enough
        
        yassert(jnl->first_page_offset - jnl->last_page.records_limit >= CJF_SECTION_INDEX_SIZE + CJF_PAGE_ARBITRARY_UPDATE_SIZE);
        
        // make the IDXT grow if it full already
        
        journal_cjf_idxt_ensure_growth(jnl);
        
        // create a new page at jnl->page.offset_next
    }
    else
    {
        // we are at the end of the physical file
        
        log_debug2("cjf: IDXT adding PAGE (end of the file)");
        
        /// @note 20150210 edf -- A journal cannot loop with only one PAGE
        // if it is expected to go beyond the maximum size with the next update, prevent the growth of the idtx table
        // if we don't have at least two PAGE, then continue to grow the IDXT
        
        const bool has_at_least_two_pages = (jnl->idxt.count > 1);
        
        const bool too_close_to_the_file_size_limit = (jnl->last_page.records_limit  + CJF_SECTION_INDEX_SIZE + CJF_PAGE_ARBITRARY_UPDATE_SIZE > jnl->file_maximum_size);
        
        if(has_at_least_two_pages && too_close_to_the_file_size_limit)
        {
            journal_cjf_idxt_fix_size(jnl);
        }
        else
        {
            journal_cjf_idxt_ensure_growth(jnl);
        }
        
        // create a new page in the idxt
    }

    journal_cjf_idxt_append_page_nogrow(jnl);
}

/*
 scans all the PAGE entries from the IDXT and get the one that contains the serial
 */

ya_result
journal_cjf_idxt_get_page_index_from_serial(const journal_cjf *jnl, u32 serial)
{
    u32 prev = jnl->serial_begin;
    
    if(serial_lt(serial, prev))
    {
        return ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
    }
    
    u32 prev_serial = jnl->serial_begin;
    
    s16 n = jnl->idxt.count;
    for(s16 i = 0; i < n; i++)
    {
        journal_cjf_idxt_tbl_item *entry;
        entry = &jnl->idxt.entries[(jnl->idxt.first + i) % jnl->idxt.size];
        // the last serial of an entry is the one of the last SOA added on it
        // we want to start after that one
        if(serial_lt(serial, entry->last_serial))
        {
            log_debug1("journal_cjf_idxt_get_page_index_from_serial(%s, %d) returning %i (%i -> %i)", jnl->journal_file_name, serial, i, prev_serial, entry->last_serial);
            return i;
        }
        prev_serial = entry->last_serial;
    }
    
    return ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
}

u32
journal_cjf_idxt_get_page_serial_from_index(const journal_cjf *jnl, int idx)
{
    if(idx > 0)
    {
        journal_cjf_idxt_tbl_item *prev_entry;
        prev_entry = &jnl->idxt.entries[(jnl->idxt.first + idx - 1) % jnl->idxt.size];
        return prev_entry->last_serial;
    }
    else
    {
        return jnl->serial_begin;
    }
}

/**
 * Returns the page index containing the serial, and optionally its position in the file.
 * 
 * @param jnl
 * @param serial
 * @param file_offset
 * @return 
 */

ya_result
journal_cjf_idxt_get_page_offset_from_serial(const journal_cjf *jnl, u32 serial, u32 *file_offset)
{
    u32 prev_serial = jnl->serial_begin;
    
    // ensure the journal starts at least from the serial we are looking for
    
    if(serial_lt(serial, prev_serial))
    {
        return ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
    }
    
    s16 n = jnl->idxt.count;
    for(s16 i = 0; i < n; i++)
    {
        journal_cjf_idxt_tbl_item *entry;
        entry = &jnl->idxt.entries[(jnl->idxt.first + i) % jnl->idxt.size];
        
        // entry->last_serial is the last_serial TO, so the start of the next page
        
        if(serial_lt(serial, entry->last_serial))
        {
            log_debug1("journal_cjf_idxt_get_page_index_from_serial(%s, %d) returning %i (%i -> %i)",
                    jnl->journal_file_name, serial, i, prev_serial, entry->last_serial);
            if(file_offset != NULL)
            {
                *file_offset = entry->file_offset;
            }
            return i;
        }
        
        prev_serial = entry->last_serial;
    }
    
    // too far ...
    
    return ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE;
}

ya_result
journal_cjf_idxt_get_page_serial_to(const journal_cjf *jnl, int idx)
{
    journal_cjf_idxt_tbl_item *entry;
    entry = &jnl->idxt.entries[(jnl->idxt.first + idx) % jnl->idxt.size];
    return entry->last_serial;
}

u32
journal_cjf_idxt_get_page_offset(const journal_cjf *jnl, int idx)
{
    journal_cjf_idxt_tbl_item *entry;
    entry = &jnl->idxt.entries[(jnl->idxt.first + idx) % jnl->idxt.size];
    return entry->file_offset;
}

#endif

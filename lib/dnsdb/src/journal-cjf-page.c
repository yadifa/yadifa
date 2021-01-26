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

#include "dnsdb/journal-cjf-page-output-stream.h"

#include "dnsdb/journal-cjf-page.h"
#include "dnsdb/journal-cjf-idxt.h"
#include "dnsdb/journal-cjf-page-cache.h"

/**
 * Search from the offset of the stream for a serial, looking in an PAGE referenced by index
 * 
 * @param jnl
 * @param idx
 * @param serial
 * @param out_offset
 * @return 
 */

ya_result
journal_cjf_page_get_stream_offset_from_serial(journal_cjf *jnl, int idx, u32 serial, u32 *out_offset)
{    
    u32 file_offset = journal_cjf_idxt_get_page_offset(jnl, idx);
    journal_cjf_page_tbl_item value;
       
    if(journal_cjf_idxt_get_page_serial_from_index(jnl, idx) == serial)
    {
        // the first one
        
        journal_cjf_page_cache_read_item(jnl->file, file_offset, 0, &value);
        *out_offset = value.stream_file_offset;
        
        return SUCCESS;
    }
    
    // read how much items are in the PAGE
    
    journal_cjf_page_tbl_header hdr;
    journal_cjf_page_cache_read_header(jnl->file, file_offset, &hdr);
    
    if(hdr.magic == CJF_PAGE_MAGIC)
    {    
        //for(int i = 1; i <= CJF_SECTION_INDEX_SLOT_COUNT - 1; i++)
        for(int i = 0; i < hdr.count - 1; i++)
        {
            journal_cjf_page_cache_read_item(jnl->file, file_offset, i, &value);

            if(value.ends_with_serial == serial)
            {
                // we found the item that ends with the requested serial,
                // the next item is the one that starts from the requested serial

                journal_cjf_page_cache_read_item(jnl->file, file_offset, i + 1, &value);
                *out_offset = value.stream_file_offset;

                return SUCCESS;
            }
        }
    
        //this is the wrong idx

    }
    else
    {
        // invalid
    }
    
    return ERROR;
}


/**
 * 
 * Returns true iff the current PAGE table is full
 * 
 * @param jnl
 * @return 
 */

bool
journal_cjf_page_is_full(journal_cjf *jnl)
{
    yassert(jnl->last_page.size > 0);
    
    return jnl->last_page.count == jnl->last_page.size;
}

bool
journal_cjf_page_line_count(journal_cjf *jnl)
{
    return jnl->last_page.count;
}

/**
 * 
 * Returns the file offset value at index in the current PAGE
 * 
 * @param jnl
 * @param index
 * @return 
 */

u32
journal_cjf_page_get_file_offset(journal_cjf *jnl)
{
    return jnl->last_page.file_offset;
}

u32
journal_cjf_page_get_stream_file_offset(journal_cjf *jnl)
{
    return jnl->last_page.records_limit;
}

/**
 * 
 * Returns the last serial number value at index in the PAGE
 * 
 * @param jnl
 * @param index
 * @return 
 */

u32
journal_cjf_page_get_last_serial(journal_cjf *jnl, s16 index)
{
    journal_cjf_idxt_tbl_item *entry;
    entry = &jnl->idxt.entries[(jnl->idxt.first + index) % jnl->idxt.size];
    return entry->last_serial;
}

#endif

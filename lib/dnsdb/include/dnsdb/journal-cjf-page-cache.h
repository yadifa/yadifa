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

#pragma once

#include <dnscore/sys_types.h>
#include <dnscore/file-pool.h>

#if !JOURNAL_CJF_BASE
#error "internal include for the CJF journal, don't use include it"
#endif

#ifdef	__cplusplus
extern "C" {
#endif
    
#define CJF_SECTION_INDEX_SLOT_HEAD  16
#define CJF_SECTION_INDEX_SLOT_SIZE  8
#define CJF_SECTION_INDEX_SLOT_COUNT 510
#define CJF_SECTION_INDEX_SIZE       (CJF_SECTION_INDEX_SLOT_HEAD + CJF_SECTION_INDEX_SLOT_SIZE * CJF_SECTION_INDEX_SLOT_COUNT) // 4KB

#define CJF_PAGE_SIZE_IN_BYTE       (CJF_SECTION_INDEX_SLOT_HEAD + (CJF_SECTION_INDEX_SLOT_COUNT * CJF_SECTION_INDEX_SLOT_SIZE))

#define CJF_PAGE_ARBITRARY_UPDATE_SIZE      512
    
#define CJF_PAGE_MAGIC MAGIC4('P','A','G','E')

struct journal_cjf_page_tbl_header
{
    u32 magic;
    u32 next_page_offset;
    u16 count;
    u16 size;
    u32 stream_end_offset;
    u8 __end_of_struct__;
};

typedef struct journal_cjf_page_tbl_header journal_cjf_page_tbl_header;

#define JOURNAL_CJF_PAGE_HEADER_SIZE offsetof(journal_cjf_page_tbl_header,__end_of_struct__)

#define JCJFTI_TAG 0x4954464a434a

struct journal_cjf_page_tbl_item
{
    u32 ends_with_serial; // the last SOA on the stream for this item has this serial
    u32 stream_file_offset;
    /// @note THIS MUST BE EXACTLY 8 BYTES LONG !
};

typedef struct journal_cjf_page_tbl_item journal_cjf_page_tbl_item;

#define JOURNAL_CJF_PAGE_ITEM_SIZE 8

void journal_cjf_page_cache_init();
void journal_cjf_page_cache_flush(file_pool_file_t file);
void journal_cjf_page_cache_close(file_pool_file_t file);
void journal_cjf_page_cache_write_item(file_pool_file_t file, u64 file_offset, s16 offset, const journal_cjf_page_tbl_item *value);
void journal_cjf_page_cache_read_item(file_pool_file_t file, u64 file_offset, s16 offset, journal_cjf_page_tbl_item *value);
void journal_cjf_page_cache_write_new_header(file_pool_file_t file, u64 file_offset);
void journal_cjf_page_cache_write_header(file_pool_file_t file, u64 file_offset,  const journal_cjf_page_tbl_header *value);
void journal_cjf_page_cache_read_header(file_pool_file_t file, u64 file_offset,  journal_cjf_page_tbl_header *value);
void journal_cjf_page_cache_flush_page(file_pool_file_t file, u64 file_offset);
void journal_cjf_page_cache_clear(file_pool_file_t file, u64 file_offset);
void journal_cjf_page_cache_finalize();

#ifdef	__cplusplus
}
#endif

/** @} */

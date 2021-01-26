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

#define ZDB_JOURNAL_CODE 1

#define JOURNAL_CJF_BASE 1

#include "dnsdb/dnsdb-config.h"
#include "dnsdb/journal-cjf-page-cache.h"
#include "dnsdb/journal-cjf-common.h"
#include "dnsdb/journal-cjf.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#include <dnscore/limited_input_stream.h>
#include <dnscore/mutex.h>
#include <dnscore/serial.h>
#include <dnscore/dns_resource_record.h>

#include <dnscore/ptr_set.h>
#include <dnscore/fdtools.h>

#include <dnscore/ptr_set.h>
#include <dnscore/u64_set.h>
#include <dnscore/list-dl.h>
#include <dnscore/list-sl.h>

#include <dnscore/ctrl-rfc.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/journal.h"
#include "dnsdb/zdb_types.h"
#include "dnsdb/xfr_copy.h"
#include "dnsdb/zdb-zone-path-provider.h"

#if JOURNAL_CJF_ENABLED

#define DEBUG_JOURNAL 0
#if !DEBUG
#undef DEBUG_JOURNAL
#define DEBUG_JOURNAL 0
#endif

#define LOCK_NONE   0
#define LOCK_READ   1
#define LOCK_WRITE  2

#define CJF_EXT "cjf"
#define CJF_EXT_STRLEN 3

#define SOA_RDATA_SIZE_MAX 532

#define DO_SYNC 1

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define JRNLCJF_TAG 0x58494c4e524a

/*
 * Contains the journal (almost: not the matching start and end SOA)
 */


#define CJF_SECTION_INDEX_SLOT_HEAD  16
#define CJF_SECTION_INDEX_SLOT_SIZE  8
#define CJF_SECTION_INDEX_SLOT_COUNT 510
#define CJF_SECTION_INDEX_SIZE       (CJF_SECTION_INDEX_SLOT_HEAD + CJF_SECTION_INDEX_SLOT_SIZE * CJF_SECTION_INDEX_SLOT_COUNT) // 4KB

#define CJF_PAGE_SIZE_IN_BYTE        (CJF_SECTION_INDEX_SLOT_HEAD + (CJF_SECTION_INDEX_SLOT_COUNT * CJF_SECTION_INDEX_SLOT_SIZE))
#define CJF_PAGE_ARBITRARY_UPDATE_SIZE      512

#define CJF_SECTION_INDEX_SLOT_HEAD_SLOT (CJF_SECTION_INDEX_SLOT_HEAD / CJF_SECTION_INDEX_SLOT_SIZE)

//#define log_cjf_page_debug log_debug5
#define log_cjf_page_debug log_debug

/*
 * PAGE
 * 
 * Serial Number Stream Offset
 * 
 * The table of serials streams (IXFR) and their offset
 * The value stored is of the serial ending the IXFR
 */

#define PAGE_INITIALIZER {CJF_PAGE_MAGIC, 0, 0, CJF_SECTION_INDEX_SLOT_COUNT, 0, 0}

static bool empty_page_tbl_header_and_zeroes_initialised = FALSE;
static u8 empty_page_tbl_header_and_zeroes[CJF_SECTION_INDEX_SIZE];
static u32 journal_cfj_page_mru_size = 64;

//

struct journal_cjf_page_tbl
{
    journal_cjf_page_tbl_header hdr;
    journal_cjf_page_tbl_item items[CJF_SECTION_INDEX_SLOT_COUNT];
};

// PAGE are all over the place, going back to write into or read from one is a drag
// the first idea would be to have the current PAGE along with the journal, and it would solve MOST problems
// but PAGE may be needed at more than one place.
// So the idea is to have them cached:

// An PAGE cache entry is:
// _ maybe a reference count
// _ a file descriptor
// _ a file position
// _ a dirty flag, or a last_written offset
// _ maybe a count
// _ a 4K buffer
// _ maybe an MRU entry ?
// _ maybe a mutex
// the key ...
//
// one should be able to
// _ load an PAGE from the disk
// _ flush an PAGE back to the disk
// _ flush all PAGE linked to a file descriptor to the disk (KEY!)
// _ update the PAGE of a given position in a file to the disk (KEY!)
//
// there should not be a lot of PAGE per file descriptor, and PAGE should be flushed back at key times
// ie: closing the file descriptor, too many PAGE flush the least used ones, ...
//
// they should be pooled, I think

#define JCJFPCI_TAG 0x494350464a434a

struct journal_cjf_page_cache_item
{
    u64 file_offset;
    journal_cjf_page_tbl_item *buffer;
    file_pool_file_t file;
    s16 first_written_entry;
    s16 last_written_entry; // set to the end means not dirty
};

typedef struct journal_cjf_page_cache_item journal_cjf_page_cache_item;

// fd => list_dl(page_cache_item)

static ptr_set page_cache_item_by_file = PTR_SET_PTR_EMPTY;
static list_dl_s page_cache_mru = {{NULL, NULL}, {NULL, NULL}, 0};
static group_mutex_t page_cache_mtx = GROUP_MUTEX_INITIALIZER;

static void journal_cjf_page_cache_free(journal_cjf_page_cache_item *page_cache);

void
journal_cjf_page_cache_init()
{
    if(empty_page_tbl_header_and_zeroes_initialised)
    {
        return;
    }
    
    journal_cjf_page_tbl_header head = PAGE_INITIALIZER;
    ZEROMEMORY(empty_page_tbl_header_and_zeroes, sizeof(empty_page_tbl_header_and_zeroes));
    memcpy(empty_page_tbl_header_and_zeroes, &head, CJF_SECTION_INDEX_SLOT_HEAD);
    
    list_dl_init(&page_cache_mru);
    
    empty_page_tbl_header_and_zeroes_initialised = TRUE;
}

static void
journal_cjf_page_cache_remove_from_mru(journal_cjf_page_cache_item *page_cache)
{
    if(list_dl_size(&page_cache_mru) > 0)
    {
        list_dl_remove(&page_cache_mru, page_cache);
    }
}

static void
journal_cjf_page_cache_add_to_mru(journal_cjf_page_cache_item *page_cache)
{
    list_dl_insert(&page_cache_mru, page_cache);
}

/*
void
journal_cjf_page_cache_finalize()
{
}
*/

/**
 * called undirty because clear and clean are too similar
 * 
 * @param page_cache
 */

static void
journal_cjf_page_cache_item_undirty(journal_cjf_page_cache_item *page_cache)
{
    page_cache->first_written_entry = (1 + CJF_SECTION_INDEX_SLOT_COUNT);
    page_cache->last_written_entry = -1;
}

static void
journal_cjf_page_cache_item_flush_internal(journal_cjf_page_cache_item *page_cache)
{
    file_pool_file_t file = page_cache->file;
    
    // at file_offset, write from first to last entries

    off_t first_offset = page_cache->file_offset + (page_cache->first_written_entry * CJF_SECTION_INDEX_SLOT_SIZE);
    size_t size = ((page_cache->last_written_entry - page_cache->first_written_entry) + 1) * CJF_SECTION_INDEX_SLOT_SIZE;

    log_cjf_page_debug("cjf: %s: flush page @%lli=%llx size=%i", file_pool_filename(file), first_offset, first_offset, size);
    
    for(;;)
    {
        file_pool_seek(file, first_offset, SEEK_SET);

        ya_result ret = file_pool_writefully(file, &page_cache->buffer[page_cache->first_written_entry], size);

        if(ret == (s32)size)
        {
            break;
        }

        // should no be reached, but if an issue occur, better not hammer the logs

        log_err("cjf: %s: flush page @%lli=%llx size=%i failed with: %r", file_pool_filename(file), first_offset, first_offset, size, ret);

        sleep(1);
    }

    // mark the entry as not being used

    journal_cjf_page_cache_item_undirty(page_cache);
}

/**
 * @param page_cache
 * @return 
 */

static void
journal_cjf_page_cache_item_flush(journal_cjf_page_cache_item *page_cache)
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    if(page_cache != NULL)
    {
        if(page_cache->first_written_entry <= page_cache->last_written_entry)
        {
            file_pool_file_t file = page_cache->file;
            size_t here;
                        
            file_pool_tell(file, &here);
            
            journal_cjf_page_cache_item_flush_internal(page_cache);

            file_pool_seek(file, (ssize_t)here, SEEK_SET);
        }
    }
    else
    {
        log_err("cjf: journal_cjf_page_cache_flush_item(NULL)");
    }
}

static void
journal_cjf_page_cache_cull()
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    // culls a cache entry at the end of the MRU
    
    log_cjf_page_debug("cjf: cull pages");
    
    while(list_dl_size(&page_cache_mru) > journal_cfj_page_mru_size)
    {
        // get the tail one
        journal_cjf_page_cache_item *page_cache = (journal_cjf_page_cache_item*)list_dl_remove_last(&page_cache_mru);
        // flush it
        journal_cjf_page_cache_item_flush(page_cache);
        // free it
    }
    
    log_cjf_page_debug("cjf: cull pages done");
}

static void
journal_cjf_page_mru_clear()
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    // culls a cache entry at the end of the MRU
    
    log_cjf_page_debug("cjf: clear pages");
    
    while(list_dl_size(&page_cache_mru) > 0)
    {
        // get the tail one
        journal_cjf_page_cache_item *page_cache = (journal_cjf_page_cache_item*)list_dl_remove_last(&page_cache_mru);
        // flush it
        journal_cjf_page_cache_item_flush(page_cache);
        // free it
        journal_cjf_page_cache_free(page_cache);
    }
    
    log_cjf_page_debug("cjf: clear pages done");
}

static journal_cjf_page_cache_item *
journal_cjf_page_cache_new(file_pool_file_t file, u32 file_offset)
{
    journal_cjf_page_cache_item *page_cache;
    
    log_cjf_page_debug("cjf: %s: new page cache for offset %i", file_pool_filename(file), file_offset);
    
    ZALLOC_OBJECT_OR_DIE(page_cache, journal_cjf_page_cache_item, JCJFPCI_TAG);
    page_cache->file_offset = file_offset;
    MALLOC_OR_DIE(journal_cjf_page_tbl_item*, page_cache->buffer, CJF_PAGE_SIZE_IN_BYTE , JCJFTI_TAG);
    page_cache->file = file;
    journal_cjf_page_cache_item_undirty(page_cache);
    
#if DEBUG
    memset(page_cache->buffer, 0xfe, CJF_PAGE_SIZE_IN_BYTE);
#endif
    
    return page_cache;
}

static void
journal_cjf_page_cache_free(journal_cjf_page_cache_item *page_cache)
{
#if DEBUG
    memset(page_cache->buffer, 0xfd, CJF_PAGE_SIZE_IN_BYTE);
#endif
    
    free(page_cache->buffer);
    ZFREE_OBJECT(page_cache);
}

static inline u64_set*
journal_cjf_page_cache_set_from_file(file_pool_file_t file)
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    ptr_node *file_node = ptr_set_find(&page_cache_item_by_file, file);
    if(file_node != NULL)
    {
        return (u64_set*)&file_node->value;
    }
    else
    {
        log_warn("cjf: %s: file is not cached", file_pool_filename(file));
        return NULL;
    }
}

static inline journal_cjf_page_cache_item*
journal_cjf_page_cache_from_set(u64_set* page_cache_set, u32 file_offset)
{
    u64_node *file_offset_node = u64_set_find(page_cache_set, file_offset);
    
    if(file_offset_node != NULL)
    {
        return (journal_cjf_page_cache_item*)file_offset_node->value;
    }
    else
    {
        log_err("cjf: page is not cached");
    }
    
    return NULL;
}

static inline journal_cjf_page_cache_item*
journal_cjf_page_cache_from_file(file_pool_file_t file, u32 file_offset)
{
    u64_set* page_cache_set = journal_cjf_page_cache_set_from_file(file);
    
    if(page_cache_set != NULL)
    {
        journal_cjf_page_cache_item *page_cache = journal_cjf_page_cache_from_set(page_cache_set, file_offset);
        
        return page_cache;
    }
    
    return NULL;
}

static void
journal_cjf_page_cache_delete_from_file_and_offset(const file_pool_file_t file, u32 file_offset)
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    log_cjf_page_debug("cjf: %s: dropping page at offset %i", file_pool_filename(file), file_offset);
    
    u64_set* page_cache_set = journal_cjf_page_cache_set_from_file(file);
            
    if(page_cache_set != NULL)
    {
        // get the PAGE cache at the file_offset

        journal_cjf_page_cache_item *page_cache = journal_cjf_page_cache_from_set(page_cache_set, file_offset);

        if(page_cache != NULL)
        {
            u64_set_delete(page_cache_set, file_offset);

            journal_cjf_page_cache_item_flush(page_cache);

            journal_cjf_page_cache_remove_from_mru(page_cache);

            journal_cjf_page_cache_free(page_cache);
        }
    }
}

static journal_cjf_page_cache_item*
journal_cjf_page_cache_get_for_rw(file_pool_file_t file, u64 file_offset)
{
    // get or create a node for the fd
    
    ptr_node *file_node = ptr_set_insert(&page_cache_item_by_file, file);
    
    // make some room, if needed
    
    journal_cjf_page_cache_cull();
    
    // get or create an PAGE cache at the file_offset
    
    u64_node *file_offset_node = u64_set_insert((u64_set*)&file_node->value, file_offset);
    
    journal_cjf_page_cache_item *page_cache;
    
    if(file_offset_node->value != NULL)
    {
        // already got that one
        
        page_cache = (journal_cjf_page_cache_item*)file_offset_node->value;
    }
    else
    {
        // have to create it
        page_cache = journal_cjf_page_cache_new(file, file_offset);
        
        // if the file is big enough: load it
        
        size_t the_file_size;
        
        if(ISOK(file_pool_get_size(file, &the_file_size)))
        {
            if(file_offset + CJF_PAGE_SIZE_IN_BYTE <= the_file_size)
            {
                size_t here = ~0ULL;
                file_pool_tell(file, &here);
                yassert(here != ~0ULL);

#ifndef NDEBUG
                ssize_t there =
#endif
                file_pool_seek(file, file_offset, SEEK_SET);
                yassert(there == (ssize_t)file_offset);
                // it is a READ, because to write the cache, it must first be loaded
                ssize_t size = file_pool_readfully(file, page_cache->buffer, CJF_PAGE_SIZE_IN_BYTE);
#if DEBUG
                log_memdump_ex(g_database_logger, MSG_DEBUG6, page_cache->buffer, size, 32, OSPRINT_DUMP_ADDRESS|OSPRINT_DUMP_HEX);
#endif                
                yassert(size == CJF_PAGE_SIZE_IN_BYTE);
                (void)size;
#ifndef NDEBUG                
                there = 
#endif
file_pool_seek(file, here, SEEK_SET);
#ifndef NDEBUG
                yassert(there == (ssize_t)here);
                (void)size;
                (void)there;
                (void)here;
#endif
            }
        }
        
        file_offset_node->value = page_cache;
        
#if DEBUG
        log_debug("test");
#endif
    }
    
    return page_cache;
}

static void
journal_cjf_page_cache_write(file_pool_file_t file, u64 file_offset, s16 offset, const void *value, u32 value_len)
{
    log_cjf_page_debug("cjf: %s: writing slot %i from page at offset %llu", file_pool_filename(file), offset, file_offset);
    
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    // get or create a node for the fd
    
    journal_cjf_page_cache_item *page_cache = journal_cjf_page_cache_get_for_rw(file, file_offset);
    
    // update the last written entry to keep the highest value
    
    if(offset > page_cache->last_written_entry)
    {
        s16 value_len_slots = ((value_len + 7) >> 3) - 1;
        
        yassert(value_len_slots >= 0);
        
        page_cache->last_written_entry = offset + value_len_slots;
    }
    
    // update the last written entry to keep the smallest value
    
    if(offset < page_cache->first_written_entry)
    {
        page_cache->first_written_entry = offset;
    }
    
    // update the entry
    
    memcpy(&page_cache->buffer[offset], value, value_len);
    
    // move at the head of the MRU
    
    journal_cjf_page_cache_remove_from_mru(page_cache);
    journal_cjf_page_cache_add_to_mru(page_cache);
    
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

static void
journal_cjf_page_cache_read(file_pool_file_t file, u64 file_offset, s16 offset, void *value, u32 value_len)
{
    log_cjf_page_debug("cjf: %s: reading slot %i from page at offset %llu", file_pool_filename(file), offset, file_offset);
    
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    // get or create a node for the fd
    
    journal_cjf_page_cache_item *page_cache = journal_cjf_page_cache_get_for_rw(file, file_offset);
    
    yassert(offset + value_len <= CJF_PAGE_SIZE_IN_BYTE);
    
    memcpy(value, &page_cache->buffer[offset], value_len);
    
    // move at the head of the MRU
    
    journal_cjf_page_cache_remove_from_mru(page_cache);
    journal_cjf_page_cache_add_to_mru(page_cache);
    
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

/**
 * @param file
 * @param file_offset
 * @param offset in slot size units (8 bytes)
 * @param value
 */

void
journal_cjf_page_cache_write_item(file_pool_file_t file, u64 file_offset, s16 offset, const journal_cjf_page_tbl_item *value)
{
    yassert(file_offset >= CJF_HEADER_SIZE);
    log_cjf_page_debug("cjf: %s: %lli=%llx [ %i ] write {%08x,%08x}", file_pool_filename(file), file_offset, file_offset, offset, value->ends_with_serial, value->stream_file_offset);
    
    journal_cjf_page_cache_write(file, file_offset, offset + CJF_SECTION_INDEX_SLOT_HEAD_SLOT, value, sizeof(journal_cjf_page_tbl_item));
}

void
journal_cjf_page_cache_read_item(file_pool_file_t file, u64 file_offset, s16 offset, journal_cjf_page_tbl_item *value)
{
    yassert(file_offset >= CJF_HEADER_SIZE);
    journal_cjf_page_cache_read(file, file_offset, offset + CJF_SECTION_INDEX_SLOT_HEAD_SLOT, value, sizeof(journal_cjf_page_tbl_item));
    log_cjf_page_debug("cjf: %s: %lli=%llx [ %i ] read {%08x,%08x}", file_pool_filename(file), file_offset, file_offset, offset, value->ends_with_serial, value->stream_file_offset);
}

void
journal_cjf_page_cache_write_header(file_pool_file_t file, u64 file_offset,  const journal_cjf_page_tbl_header *value)
{
    yassert(file_offset >= CJF_HEADER_SIZE);
    yassert(value->count <= value->size);
    yassert(((value->count <= value->size) && (value->next_page_offset < file_offset)) || (value->next_page_offset > file_offset) || (value->next_page_offset == 0));
    yassert(value->stream_end_offset != 0);
    
    log_cjf_page_debug("cjf: %s: %lli=%llx update header {%08x,%3d,%3d,%08x}", file_pool_filename(file), file_offset, file_offset, value->next_page_offset, value->count, value->size, value->stream_end_offset);
    
    journal_cjf_page_cache_write(file, file_offset, 0, value, CJF_SECTION_INDEX_SLOT_HEAD);
}

void
journal_cjf_page_cache_write_new_header(file_pool_file_t file, u64 file_offset)
{
    static const journal_cjf_page_tbl_header new_page_header = PAGE_INITIALIZER;
    static const journal_cjf_page_tbl_item empty_item = {0,0};
    const journal_cjf_page_tbl_header *value = &new_page_header;
    yassert(file_offset >= CJF_HEADER_SIZE);
    yassert(value->count <= value->size);
    yassert(((value->count <= value->size) && (value->next_page_offset < file_offset)) || (value->next_page_offset > file_offset) || (value->next_page_offset == 0));
    
    log_cjf_page_debug("cjf: %s: %lli=%llx write header {%08x,%3d,%3d,%08x}", file_pool_filename(file), file_offset, file_offset, value->next_page_offset, value->count, value->size, value->stream_end_offset);
    
    journal_cjf_page_cache_write(file, file_offset, 0, value, CJF_SECTION_INDEX_SLOT_HEAD);
    
    for(int i = 0; i < CJF_SECTION_INDEX_SLOT_COUNT; ++i)
    {
        journal_cjf_page_cache_write_item(file, file_offset, i, &empty_item);
    }
}

void
journal_cjf_page_cache_read_header(file_pool_file_t file, u64 file_offset,  journal_cjf_page_tbl_header *value)
{
    yassert(file_offset >= CJF_HEADER_SIZE);
    journal_cjf_page_cache_read(file, file_offset, 0, value, CJF_SECTION_INDEX_SLOT_HEAD);
    
    log_cjf_page_debug("cjf: %s: %lli=%llx read header {%08x,%3d,%3d,%08x}", file_pool_filename(file), file_offset, file_offset, value->next_page_offset, value->count, value->size, value->stream_end_offset);
}

static void
journal_cjf_page_cache_items_flush(u64_set *page_cache_set)
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    size_t here;
    file_pool_file_t file = NULL;
    u64_set_iterator iter;
    u64_set_iterator_init(page_cache_set, &iter);
    while(u64_set_iterator_hasnext(&iter))
    {
        u64_node *file_offset_node = u64_set_iterator_next_node(&iter);
        journal_cjf_page_cache_item *page_cache = (journal_cjf_page_cache_item*)file_offset_node->value;
        if(page_cache->first_written_entry <= page_cache->last_written_entry)
        {
            if(file == NULL)
            {
                file = page_cache->file;
                yassert(file != NULL);
                file_pool_tell(file, &here); // can only fail if &here is NULL
            }
            
            yassert(file == page_cache->file);
            
            journal_cjf_page_cache_item_flush_internal(page_cache);

            // do not move in the MRU : it will naturally fall down if not used anymore
            // (yup, nothing to do)
        }
    }

    if(file != NULL)
    {
        file_pool_seek(file, here, SEEK_SET);
    }
}

static void
journal_cjf_page_cache_items_close(u64_set *page_cache_set)
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    /*
    list_sl_s delete_list;
    list_sl_init(&delete_list);
    */      
    size_t here;
    file_pool_file_t file = NULL;
    u64_set_iterator iter;
    u64_set_iterator_init(page_cache_set, &iter);
    while(u64_set_iterator_hasnext(&iter))
    {
        u64_node *file_offset_node = u64_set_iterator_next_node(&iter);
        journal_cjf_page_cache_item *page_cache = (journal_cjf_page_cache_item*)file_offset_node->value;
        
        if(page_cache->first_written_entry <= page_cache->last_written_entry) // page needs to be flushed ?
        {
            if(file == NULL)
            {
                file = page_cache->file;
                yassert(file != NULL);
                file_pool_tell(file, &here); // remember the position
            }
            
            yassert(file == page_cache->file);
            
            journal_cjf_page_cache_item_flush_internal(page_cache);
            /*
            // delete the item
            list_sl_push(&delete_list, page_cache);
            */
            file_offset_node->value = NULL;
        }
        
        journal_cjf_page_cache_remove_from_mru(page_cache);
        journal_cjf_page_cache_free(page_cache);
    }

    if(file != NULL)
    {
        file_pool_seek(file, here, SEEK_SET); // go back to the position
        
        // delete pages
        /*
        journal_cjf_page_cache_item *page_cache;
        while((page_cache = (journal_cjf_page_cache_item*)list_sl_pop(&delete_list)) != NULL)
        {
            journal_cjf_page_cache_remove_from_mru(page_cache);
            
            journal_cjf_page_cache_free(page_cache);
        }
        */
    }
    
    u64_set_destroy(page_cache_set);
}

void
journal_cjf_page_cache_flush(file_pool_file_t file)
{
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    u64_set* page_cache_set = journal_cjf_page_cache_set_from_file(file);
    if(page_cache_set != NULL)
    {
        journal_cjf_page_cache_items_flush(page_cache_set);
    }
    else
    {
        log_warn("cjf: %s: is not cached", file_pool_filename(file));
    }
    
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

void
journal_cjf_page_cache_flush_page(file_pool_file_t file, u64 file_offset)
{
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    
    journal_cjf_page_cache_item *page_cache = journal_cjf_page_cache_from_file(file, file_offset);

    if(page_cache != NULL)
    {
        journal_cjf_page_cache_item_flush(page_cache);
    }
        
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

void
journal_cjf_page_cache_clear(file_pool_file_t file, u64 file_offset)
{
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    
    journal_cjf_page_cache_delete_from_file_and_offset(file, file_offset);
    
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

void
journal_cjf_page_cache_close(file_pool_file_t file)
{
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    
    u64_set *page_cache_set = journal_cjf_page_cache_set_from_file(file);
    
    if(page_cache_set != NULL)
    {
        // destroy the u64_set content
        journal_cjf_page_cache_items_close(page_cache_set);
        
        // delete the file_node
        ptr_set_delete(&page_cache_item_by_file, file);
    }
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

static void
journal_cjf_page_cache_finalize_cb(ptr_node *file_node)
{
    u64_set *page_cache_set = (u64_set*)&file_node->value;
    journal_cjf_page_cache_items_close(page_cache_set);
}

void
journal_cjf_page_cache_finalize()
{
    group_mutex_write_lock(&page_cache_mtx);
    ptr_set_callback_and_destroy(&page_cache_item_by_file, journal_cjf_page_cache_finalize_cb);
    journal_cjf_page_mru_clear();
    group_mutex_write_unlock(&page_cache_mtx);
}

#endif

/** @} */

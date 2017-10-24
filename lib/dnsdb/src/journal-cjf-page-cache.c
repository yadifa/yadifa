/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2017, EURid. All rights reserved.
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

#include <dnscore/u32_set.h>
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

#define DEBUG_JOURNAL 1
#ifndef DEBUG
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
    int fd;
    s16 first_written_entry;
    s16 last_written_entry; // set to the end means not dirty
};

typedef struct journal_cjf_page_cache_item journal_cjf_page_cache_item;

// fd => list_dl(page_cache_item)

static u32_set page_cache_item_by_fd = U32_SET_EMPTY;
static list_dl_s page_cache_mru = {{NULL, NULL}, {NULL, NULL}, 0};
static group_mutex_t page_cache_mtx = GROUP_MUTEX_INITIALIZER;

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
    //page_cache_mru.size
}

static void
journal_cjf_page_cache_item_undirty(journal_cjf_page_cache_item *sci)
{
    sci->first_written_entry = (1 + CJF_SECTION_INDEX_SLOT_COUNT);
    sci->last_written_entry = -1;
}

/**
 * @param sci
 * @return 
 */

static void
journal_cjf_page_cache_item_flush(journal_cjf_page_cache_item *sci)
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    if(sci != NULL)
    {
        if(sci->first_written_entry <= sci->last_written_entry)
        {
            int fd = sci->fd;
            u64 here = lseek(fd, 0, SEEK_CUR);

            // at file_offset, write from first to last entries

            off_t first_offset = sci->file_offset + (sci->first_written_entry * CJF_SECTION_INDEX_SLOT_SIZE);

            log_debug5("journal_cjf_page_cache_flush_item fd=%i offset=%lli=%llx size=%i)", fd, first_offset, first_offset, (sci->last_written_entry - sci->first_written_entry) * CJF_SECTION_INDEX_SLOT_SIZE);

            lseek(fd, first_offset, SEEK_SET);
            writefully(fd, &sci->buffer[sci->first_written_entry], ((sci->last_written_entry - sci->first_written_entry) + 1) * CJF_SECTION_INDEX_SLOT_SIZE);

            // mark the entry as not being used

            journal_cjf_page_cache_item_undirty(sci);

            lseek(fd, here, SEEK_SET);
        }
    }
    else
    {
        log_warn("cjf: journal_cjf_page_cache_flush_item(NULL)");
    }
}

static void
journal_cjf_page_cache_cull()
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    // culls a cache entry at the end of the MRU
    
    if(list_dl_size(&page_cache_mru) > journal_cfj_page_mru_size)
    {
        log_debug6("journal_cjf_page_cache_cull() %i > %i, removing and flushing last",
                list_dl_size(&page_cache_mru) > journal_cfj_page_mru_size);
        // get the tail one
        journal_cjf_page_cache_item *sci = (journal_cjf_page_cache_item*)list_dl_remove_last(&page_cache_mru);
        // flush it
        journal_cjf_page_cache_item_flush(sci);
        // free it
    }
}

static journal_cjf_page_cache_item *
journal_cjf_page_cache_new(int fd, u32 file_offset)
{
    /// @todo 20150113 edf -- make a rule that culls a cache entry at the end of the MRU
    /// @todo 20150114 edf -- use a pool
    
    journal_cjf_page_cache_item *sci;
    
    MALLOC_OR_DIE(journal_cjf_page_cache_item*, sci, sizeof(journal_cjf_page_cache_item), JCJFPCI_TAG);
    sci->file_offset = file_offset;
    MALLOC_OR_DIE(journal_cjf_page_tbl_item*, sci->buffer, CJF_PAGE_SIZE_IN_BYTE , JCJFTI_TAG);
    sci->fd = fd;
    journal_cjf_page_cache_item_undirty(sci);
    
#ifdef DEBUG
    memset(sci->buffer, 0xfe, CJF_PAGE_SIZE_IN_BYTE);
#endif
    
    return sci;
}

static void
journal_cjf_page_cache_delete(int fd, u32 file_offset)
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    u32_node *fd_node = u32_set_avl_find(&page_cache_item_by_fd, (u32)fd);
    
    if(fd_node != NULL)
    {
        // get the PAGE cache at the file_offset

        u64_node *file_offset_node = u64_set_avl_find((u64_set*)&fd_node->value, file_offset);

        if(file_offset_node != NULL)
        {
            journal_cjf_page_cache_item *sci = (journal_cjf_page_cache_item*)file_offset_node->value;
            u64_set_avl_delete((u64_set*)&fd_node->value, file_offset);
            
            journal_cjf_page_cache_item_flush(sci);
    
            if(list_dl_size(&page_cache_mru) > 0)
            {
                list_dl_remove(&page_cache_mru, sci);
            }

            free(sci->buffer);
            free(sci);
        }
        else
        {
            log_warn("cjf: %i:%x page is not cached", fd, file_offset);
        }
    }
    else
    {
        log_warn("cjf: %i:%x has no page cache", fd, file_offset);
    }
}

static void
journal_cjf_page_cache_item_delete(journal_cjf_page_cache_item *sci)
{
    journal_cjf_page_cache_delete(sci->fd, sci->file_offset);
}

static void
journal_cjf_page_cache_write(int fd, u64 file_offset, s16 offset, const void *value, u32 value_len)
{
    log_debug6("journal_cjf_page_cache_write(%i, %lli=%llx, %i, %p, %i)", fd, file_offset, file_offset, offset, value, value_len);
    
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    // get or create a node for the fd
    
    u32_node *fd_node = u32_set_avl_insert(&page_cache_item_by_fd, (u32)fd);
    
    // make some room, if needed
    
    journal_cjf_page_cache_cull();
    
    // get or create an PAGE chache at the file_offset
    
    u64_node *file_offset_node = u64_set_avl_insert((u64_set*)&fd_node->value, file_offset);
    
    journal_cjf_page_cache_item *sci;
    
    if(file_offset_node->value != NULL)
    {
        // already got that one
        
        sci = (journal_cjf_page_cache_item*)file_offset_node->value;
    }
    else
    {
        // have to create it
        sci = journal_cjf_page_cache_new(fd, file_offset);
        
        // if the file is big enough: load it
        
        struct stat st;
        if(fstat(fd, &st) == 0)
        {
            if(file_offset + CJF_PAGE_SIZE_IN_BYTE <= st.st_size)
            {
                off_t here = lseek(fd, 0, SEEK_CUR);
                yassert(here != (off_t)-1);
                
                off_t there = lseek(fd, file_offset, SEEK_SET);
                yassert(there == file_offset);
                // it is a READ, because to write the cache, it must first be loaded
                ssize_t size = readfully(fd, sci->buffer, CJF_PAGE_SIZE_IN_BYTE);
#ifdef DEBUG
                log_memdump_ex(g_database_logger, MSG_DEBUG6, sci->buffer, size, 32, OSPRINT_DUMP_ADDRESS|OSPRINT_DUMP_HEX);
#endif                
                yassert(size == CJF_PAGE_SIZE_IN_BYTE);
                
                there = lseek(fd, here, SEEK_SET);
                yassert(there == here);
                
                (void)size;
                (void)there;
                (void)here;
            }
        }
        
        file_offset_node->value = sci;
    }
    
    if(offset > sci->last_written_entry)
    {
        s16 value_len_slots = ((value_len + 7) >> 3) - 1;
        
        yassert(value_len_slots >= 0);
        
        sci->last_written_entry = offset + value_len_slots;
    }
    
    if(offset < sci->first_written_entry)
    {
        sci->first_written_entry = offset;
    }
    
    memcpy(&sci->buffer[offset], value, value_len);
    
    // move at the head of the MRU
    
    if(list_dl_size(&page_cache_mru) > 0)
    {
        list_dl_remove(&page_cache_mru, sci);
    }
    list_dl_insert(&page_cache_mru, sci);
    
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

static void
journal_cjf_page_cache_read(int fd, u64 file_offset, s16 offset, void *value, u32 value_len)
{
    // get or create a node for the fd
    
    log_debug6("journal_cjf_page_cache_read(%i, %lli=%llx, %i, %p, %i)", fd, file_offset, file_offset, offset, value, value_len);
    
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    
    u32_node *fd_node = u32_set_avl_insert(&page_cache_item_by_fd, (u32)fd);
    
    // make some room, if needed
    
    journal_cjf_page_cache_cull();
    
    // get or create an PAGE cache at the file_offset
    
    u64_node *file_offset_node = u64_set_avl_insert((u64_set*)&fd_node->value, file_offset);
    
    journal_cjf_page_cache_item *sci;
    
    if(file_offset_node->value != NULL)
    {
        // already got that one
        
        sci = (journal_cjf_page_cache_item*)file_offset_node->value;
    }
    else
    {
        // have to create it
        sci = journal_cjf_page_cache_new(fd, file_offset);
        
        // if the file is big enough: load it
        
        struct stat st;
        if(fstat(fd, &st) == 0)
        {
            if(file_offset + CJF_PAGE_SIZE_IN_BYTE <= st.st_size)
            {
                off_t here = lseek(fd, 0, SEEK_CUR);
                yassert(here != (off_t)-1);
                
                off_t there = lseek(fd, file_offset, SEEK_SET);
                yassert(there == file_offset);
                
                ssize_t size = readfully(fd, sci->buffer, CJF_PAGE_SIZE_IN_BYTE);                
#ifdef DEBUG
                log_memdump_ex(g_database_logger, MSG_DEBUG6, sci->buffer, size, 32, OSPRINT_DUMP_ADDRESS|OSPRINT_DUMP_HEX);
#endif
                yassert(size == CJF_PAGE_SIZE_IN_BYTE);
                
                there = lseek(fd, here, SEEK_SET);
                yassert(there == here);
                (void)size;
                (void)there;
                (void)here;
            }
        }
        
        file_offset_node->value = sci;
    }
    
    memcpy(value, &sci->buffer[offset], value_len);
    
    // move at the head of the MRU
    
    if(list_dl_size(&page_cache_mru) > 0)
    {
        list_dl_remove(&page_cache_mru, sci);
    }
    list_dl_insert(&page_cache_mru, sci);
    
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

void
journal_cjf_page_cache_write_item(int fd, u64 file_offset, s16 offset, const journal_cjf_page_tbl_item *value)
{
    yassert(file_offset >= CJF_HEADER_SIZE);
    log_debug5("journal_cjf_page_cache_write_item(%i, %lli=%llx, %i, {%08x,%08x})", fd, file_offset, file_offset, offset, value->ends_with_serial, value->stream_file_offset);
    journal_cjf_page_cache_write(fd, file_offset, offset + 2, value, sizeof(journal_cjf_page_tbl_item));
}

void
journal_cjf_page_cache_read_item(int fd, u64 file_offset, s16 offset, journal_cjf_page_tbl_item *value)
{
    yassert(file_offset >= CJF_HEADER_SIZE);
    journal_cjf_page_cache_read(fd, file_offset, offset + 2, value, sizeof(journal_cjf_page_tbl_item));
    log_debug5("journal_cjf_page_cache_read_item(%i, %lli=%llx, %i, {%08x,%08x})", fd, file_offset, file_offset, offset, value->ends_with_serial, value->stream_file_offset);
}

void
journal_cjf_page_cache_write_header(int fd, u64 file_offset,  const journal_cjf_page_tbl_header *value)
{
    yassert(file_offset >= CJF_HEADER_SIZE);
    yassert(value->count <= value->size);
    yassert(((value->count <= value->size) && (value->next_page_offset < file_offset)) || (value->next_page_offset > file_offset) || (value->next_page_offset == 0));
    yassert(value->stream_end_offset != 0);
    log_debug5("journal_cjf_page_cache_write_header(%i, %lli=%llx, {%08x,%3d,%3d,%08x})", fd, file_offset, file_offset, value->next_page_offset, value->count, value->size, value->stream_end_offset);
    journal_cjf_page_cache_write(fd, file_offset, 0, value, CJF_SECTION_INDEX_SLOT_HEAD);
}

void
journal_cjf_page_cache_write_new_header(int fd, u64 file_offset)
{
    static const journal_cjf_page_tbl_header new_page_header = PAGE_INITIALIZER;
    static const journal_cjf_page_tbl_item empty_item = {0,0};
    const journal_cjf_page_tbl_header *value = &new_page_header;
    yassert(file_offset >= CJF_HEADER_SIZE);
    yassert(value->count <= value->size);
    yassert(((value->count <= value->size) && (value->next_page_offset < file_offset)) || (value->next_page_offset > file_offset) || (value->next_page_offset == 0));
    log_debug5("journal_cjf_page_cache_write_new_header(%i, %lli=%llx, {%08x,%3d,%3d,%08x})", fd, file_offset, file_offset, value->next_page_offset, value->count, value->size, value->stream_end_offset);
    journal_cjf_page_cache_write(fd, file_offset, 0, value, CJF_SECTION_INDEX_SLOT_HEAD);
    
    for(int i = 0; i < CJF_SECTION_INDEX_SLOT_COUNT; ++i)
    {
        journal_cjf_page_cache_write_item(fd, file_offset, i, &empty_item);
    }
}

void
journal_cjf_page_cache_read_header(int fd, u64 file_offset,  journal_cjf_page_tbl_header *value)
{
    yassert(file_offset >= CJF_HEADER_SIZE);
    journal_cjf_page_cache_read(fd, file_offset, 0, value, CJF_SECTION_INDEX_SLOT_HEAD);
    log_debug5("journal_cjf_page_cache_read_header(%i, %lli=%llx, {%08x,%3d,%3d,%08x})", fd, file_offset, file_offset, value->next_page_offset, value->count, value->size, value->stream_end_offset);
}

static void
journal_cjf_page_cache_items_flush(u64_set *sci_set)
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    off_t here = -1;
    int fd = -1;
    u64_set_avl_iterator iter;
    u64_set_avl_iterator_init(sci_set, &iter);
    while(u64_set_avl_iterator_hasnext(&iter))
    {
        u64_node *file_offset_node = u64_set_avl_iterator_next_node(&iter);
        journal_cjf_page_cache_item *sci = (journal_cjf_page_cache_item*)file_offset_node->value;
        if(sci->first_written_entry <= sci->last_written_entry)
        {
            if(here < 0)
            {
                fd = sci->fd;
                here = lseek(fd, 0, SEEK_CUR);
            }

            // at file_offset, write from first to last entries

            off_t first_offset = sci->file_offset + (sci->first_written_entry * CJF_SECTION_INDEX_SLOT_SIZE);
            //off_t last_offset = sci->file_offset + (sci->last_written_entry * CJF_SECTION_INDEX_SLOT_SIZE);
            
            // +1 because it memorises the offsets, the length of the last one has to be taken into account
            int size = (sci->last_written_entry - sci->first_written_entry + 1) * CJF_SECTION_INDEX_SLOT_SIZE;

            log_debug5("journal_cjf_page_cache_items_flush fd=%i offset=%lli=%llx size=%i)", fd, first_offset, first_offset, size);
            
            lseek(fd, first_offset, SEEK_SET);
            writefully(fd, &sci->buffer[sci->first_written_entry], size);

            // mark the entry as not being used

            journal_cjf_page_cache_item_undirty(sci);

            // do not move in the MRU : it will naturally fall down if not used anymore
            // (yup, nothing to do)
        }
    }

    if(here >= 0)
    {
        lseek(fd, here, SEEK_SET);
    }
}

static void
journal_cjf_page_cache_items_close(u64_set *sci_set)
{
    yassert(group_mutex_islocked(&page_cache_mtx));
    
    list_sl_s delete_list;
    list_sl_init(&delete_list);
            
    off_t here = -1;
    int fd = -1;
    u64_set_avl_iterator iter;
    u64_set_avl_iterator_init(sci_set, &iter);
    while(u64_set_avl_iterator_hasnext(&iter))
    {
        u64_node *file_offset_node = u64_set_avl_iterator_next_node(&iter);
        journal_cjf_page_cache_item *sci = (journal_cjf_page_cache_item*)file_offset_node->value;
        if(sci->first_written_entry <= sci->last_written_entry)
        {
            if(here < 0)
            {
                fd = sci->fd;
                here = lseek(fd, 0, SEEK_CUR);
            }

            // at file_offset, write from first to last entries

            off_t first_offset = sci->file_offset + (sci->first_written_entry * CJF_SECTION_INDEX_SLOT_SIZE);
            //off_t last_offset = sci->file_offset + (sci->last_written_entry * CJF_SECTION_INDEX_SLOT_SIZE);

            log_debug5("journal_cjf_page_cache_items_close fd=%i offset=%lli=%llx size=%i)", fd, first_offset, first_offset, (sci->last_written_entry - sci->first_written_entry) * CJF_SECTION_INDEX_SLOT_SIZE);
            
            lseek(fd, first_offset, SEEK_SET);
            writefully(fd, &sci->buffer[sci->first_written_entry], (sci->last_written_entry - sci->first_written_entry) * CJF_SECTION_INDEX_SLOT_SIZE);

            // mark the entry as not being used

            journal_cjf_page_cache_item_undirty(sci);

            // delete the item
            list_sl_push(&delete_list, sci);
            
            file_offset_node->value = NULL;
        }
        
        if(list_dl_size(&page_cache_mru) > 0)
        {
            list_dl_remove(&page_cache_mru, sci);
        }
    }

    if(here >= 0)
    {
        lseek(fd, here, SEEK_SET);
        journal_cjf_page_cache_item *sci;
        while((sci = (journal_cjf_page_cache_item*)list_sl_pop(&delete_list)) != NULL)
        {
            journal_cjf_page_cache_item_delete(sci);
        }
    }
    
    u64_set_avl_destroy(sci_set);
}

void
journal_cjf_page_cache_flush(int fd)
{
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    u32_node *fd_node = u32_set_avl_find(&page_cache_item_by_fd, (u32)fd);
    
    if(fd_node != NULL)
    {
        journal_cjf_page_cache_items_flush((u64_set*)&fd_node->value);
    }
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

void
journal_cjf_page_cache_flush_page(int fd, u64 file_offset)
{
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    u32_node *fd_node = u32_set_avl_find(&page_cache_item_by_fd, (u32)fd);
    
    if(fd_node != NULL)
    {
        // get the PAGE cache at the file_offset

        u64_node *file_offset_node = u64_set_avl_find((u64_set*)&fd_node->value, file_offset);

        if(file_offset_node != NULL)
        {
            journal_cjf_page_cache_item *sci = (journal_cjf_page_cache_item*)file_offset_node->value;
            journal_cjf_page_cache_item_flush(sci);
        }
        else
        {
            log_warn("cjf: %i:%x page is not cached", fd, file_offset);
        }
    }
    else
    {
        log_warn("cjf: %i:%x has no page cache", fd, file_offset);
    }
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

void
journal_cjf_page_cache_clear(int fd, u64 file_offset)
{
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    u32_node *fd_node = u32_set_avl_find(&page_cache_item_by_fd, (u32)fd);
    
    if(fd_node != NULL)
    {
        // get the PAGE cache at the file_offset

        u64_node *file_offset_node = u64_set_avl_find((u64_set*)&fd_node->value, file_offset);

        if(file_offset_node != NULL)
        {
            journal_cjf_page_cache_item *sci = (journal_cjf_page_cache_item*)file_offset_node->value;
            if(sci != NULL)
            {
                journal_cjf_page_cache_item_delete(sci);
            }
            else
            {
                log_warn("cjf: %i:%x page is NULL", fd, file_offset);
            }
        }
        else
        {
            log_warn("cjf: %i:%x page is not cached", fd, file_offset);
        }
    }
    else
    {
        log_warn("cjf: %i:%x has no page cache", fd, file_offset);
    }
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

void
journal_cjf_page_cache_close(int fd)
{
    group_mutex_lock(&page_cache_mtx, GROUP_MUTEX_WRITE);
    u32_node *fd_node = u32_set_avl_find(&page_cache_item_by_fd, (u32)fd);
    
    if(fd_node != NULL)
    {
        journal_cjf_page_cache_items_close((u64_set*)&fd_node->value);
        // @todo 20150113 edf -- close the content
        // destroy the u64_set content
        // delete the fd_node
        u32_set_avl_delete(&page_cache_item_by_fd, (u32)fd);
    }
    group_mutex_unlock(&page_cache_mtx, GROUP_MUTEX_WRITE);
}

/** @} */


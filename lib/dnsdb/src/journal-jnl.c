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

#define JOURNAL_JNL_BASE 1

#include "dnsdb/dnsdb-config.h"
#include "dnsdb/journal-jnl.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#include <dnscore/file_input_stream.h>
#include <dnscore/empty-input-stream.h>
#include <dnscore/mutex.h>
#include <dnscore/serial.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/format.h>

#include <dnscore/ptr_set.h>
#include <dnscore/fdtools.h>

#include <dnscore/u32_set.h>
#include <dnscore/list-dl.h>

#include <dnscore/ctrl-rfc.h>

#include <dnscore/bytearray_output_stream.h>
#include <dnscore/bytearray_input_stream.h>
#include <dnscore/zalloc.h>
#include <dnscore/circular-file.h>
#include <dnscore/packet_reader.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/journal.h"
#include "dnsdb/zdb_types.h"
#include "dnsdb/xfr_copy.h"
#include "dnsdb/zdb-zone-path-provider.h"
#include "dnsdb/zdb_zone.h"

#include "dnsdb/journal-cjf.h"

#define JNLJNLPG_TAG 0x47504c4e4a4c4e4a
#define JNLRNGLK_TAG 0x4b4c474e524c4e4a
#define JNLCHPTE_TAG 0x45545048434c4e4a
#define JNLISDBF_TAG 0x46424453494c4e4a
#define JNLISDTA_TAG 0x41544453494c4e4a

#define JNL_JNL0_MAGIC MAGIC4('J','N','L', 0)

static const u8 jnl_magic[4] = {'J','N','L',0};

#define PAGE_MAGIC MAGIC4('P','A','G','E')
#define CHPT_MAGIC MAGIC4('C','H','P','T')

#define CHPT_SIZE_THRESHOLD 16384

#define JOURNAL_JNL_FLAGS_OTHER_ENDIAN  0x80000000  // journal endian is different
#define JOURNAL_JNL_FLAGS_MY_ENDIAN     0x00000080  // journal endian is the same
#define JOURNAL_JNL_FLAGS_INITIALISED   0x00000001

#define JOURNAL_JNL_PAGE_FROM_SET_SIZE_MAX  16

struct journal_jnl_header
{
    u32 serial_begin;
    u32 serial_end;
    u32 last_soa_offset;
    u32 flags;
};

typedef struct journal_jnl_header journal_jnl_header;

struct journal_jnl_chapter
{
    u32 magic;
    u32 relative_prev;
    u32 relative_next;
    u32 serial_from;
    u32 serial_to;
};

typedef struct journal_jnl_chapter journal_jnl_chapter;

struct journal_jnl_chapter_entry
{
    s32 position;
    journal_jnl_chapter chapter;
};

typedef struct journal_jnl_chapter_entry journal_jnl_chapter_entry;

struct journal_jnl_page
{
    u32 magic;
    u32 serial_from;
    u32 serial_to;
    u32 size;
};

typedef struct journal_jnl_page journal_jnl_page;

struct journal_jnl_entry_base
{
    u32 magic;
    u32 data;
};

typedef struct journal_jnl_entry_base journal_jnl_entry_base;

union journal_jnl_entry
{
    u32 magic;
    journal_jnl_entry_base base;
    journal_jnl_chapter chapter;
    journal_jnl_page page;
};

struct journal_range_lock
{
    u32 serial_from;
    u32 serial_to;
};

typedef struct journal_range_lock journal_range_lock;

struct journal_jnl_page_header_cache
{
    ptr_set page_from_set;  // keeps only a given amount, needs to be updated with each shift
    list_dl_s page_mru;
};

typedef struct journal_jnl_page_header_cache journal_jnl_page_header_cache;

struct journal_jnl
{
    volatile struct journal_vtbl *vtbl;
    volatile list_dl_node_s mru_node;
    volatile int rc;
    volatile unsigned int _forget:1,_mru:1;

    /* The journal is not like a stream, it's a full standalone entity always returned as a pointer.
     * So the handler can do whatever it wants after "mru"
     */

    circular_file_t file;
    u8 *origin; // to not rely on zone
    shared_group_mutex_t mtx;
    journal_jnl_header hdr;
    list_dl_s chapters;
    list_dl_s range_lock;
    
    journal_jnl_page_header_cache page_cache;
        
    u32 safe_serial;        // the first serial that cannot be discarded without losing data
    u32 size_limit;
    bool dirty;
};

typedef struct journal_jnl journal_jnl;

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define DEBUG_JOURNAL 0
#if !DEBUG
#undef DEBUG_JOURNAL
#define DEBUG_JOURNAL 0
#endif

#define JOURNAL_FORMAT_NAME "circular"
#define VERSION_HI 0
#define VERSION_LO 1
#define JOURNAL_CLASS_NAME "journal_jnl"

#define LOCK_NONE   0
#define LOCK_READ   1
#define LOCK_WRITE  2

#define JNL_EXT "cjf"
#define JNL_EXT_STRLEN 3

#define SOA_RDATA_SIZE_MAX 532

#define DO_SYNC 1

#define JRNLJNL_TAG 0x58494c4e524a

/*
 * Contains the journal (almost: not the matching start and end SOA)
 */

#define JNL_WIRE_FILE_FORMAT "%s/%{dnsname}." JNL_EXT
#define JNL_WIRE_ROOT_NAME "root_zone"
#define JNL_WIRE_ROOT_ZONE_FORMAT "%s/" JNL_WIRE_ROOT_NAME "." JNL_EXT
#define FIRST_FROM_END  (JNL_EXT_STRLEN + (1 + 8 + 1 + 8))
#define LAST_FROM_END   (JNL_EXT_STRLEN + (1 + 8))

static shared_group_shared_mutex_t journal_shared_mtx = SHARED_GROUP_SHARED_MUTEX_INTIALIZER;
static bool journal_initialized = FALSE;
static file_pool_t journal_file_pool = 0;
static u32 journal_file_pool_size = 512;

static void journal_jnl_log_dump_nolock(journal *jh);
static void journal_jnl_log_dump(journal *jh);

static void
journal_jnl_writelock(journal_jnl *jnl)
{
#if DEBUG
    log_debug4("jnl: %s,%p: write lock", circular_file_name(jnl->file), jnl->file);
#endif
    shared_group_mutex_lock(&jnl->mtx, GROUP_MUTEX_WRITE);
}

static void
journal_jnl_writeunlock(journal_jnl *jnl)
{
#if DEBUG
    log_debug4("jnl: %s,%p: write unlock", circular_file_name(jnl->file), jnl->file);
#endif
    shared_group_mutex_unlock(&jnl->mtx, GROUP_MUTEX_WRITE);
}

static void
journal_jnl_readlock(journal_jnl *jnl)
{
#if DEBUG
    log_debug4("jnl: %s,%p: read lock", circular_file_name(jnl->file), jnl->file);
#endif
    shared_group_mutex_lock(&jnl->mtx, GROUP_MUTEX_READ);
}

static void
journal_jnl_readunlock(journal_jnl *jnl)
{
#if DEBUG
    log_debug4("jnl: %s,%p: read unlock", circular_file_name(jnl->file), jnl->file);
#endif
    shared_group_mutex_unlock(&jnl->mtx, GROUP_MUTEX_READ);
}

bool
journal_jnl_isreadlocked(journal_jnl *jnl)
{
    bool ret = shared_group_mutex_islocked_by(&jnl->mtx, GROUP_MUTEX_READ);
    return ret;
}

bool
journal_jnl_iswritelocked(journal_jnl *jnl)
{
    bool ret = shared_group_mutex_islocked_by(&jnl->mtx, GROUP_MUTEX_WRITE);
    return ret;
}

static inline bool
journal_jnl_is_dirty_nolock(const journal_jnl *jnl)
{
    return jnl->dirty;
}

#if UNUSED

static inline bool
journal_jnl_is_dirty(journal_jnl *jnl)
{
    journal_jnl_readlock(jnl);
    bool ret = journal_jnl_is_dirty_nolock(jnl);
    journal_jnl_readunlock(jnl);
    return ret;
}

#endif

static inline void
journal_jnl_set_dirty_nolock(journal_jnl *jnl)
{
    jnl->dirty = TRUE;
}

static inline void
journal_jnl_clear_dirty_nolock(journal_jnl *jnl)
{
    jnl->dirty = FALSE;
}

#if UNUSED
static inline void
journal_jnl_clear_dirty(journal_jnl *jnl)
{
    journal_jnl_writelock(jnl);
    journal_jnl_clear_dirty_nolock(jnl);
    journal_jnl_writeunlock(jnl);
}
#endif
/*
void
log_debug_jnl(journal_jnl *jnl, const char *text)
{
    (void)jnl;
    (void)text;
}
*/
void
journal_jnl_release(journal_jnl *jnl)
{
    journal_release((journal*)jnl);
}

static int journal_jnl_page_cache_node_compare(const void *key_a, const void *key_b)
{
    intptr a = (intptr)key_a;
    intptr b = (intptr)key_b;
    return a - b;
}

static void
journal_jnl_page_cache_init(journal_jnl *jnl)
{
    ptr_set_init(&jnl->page_cache.page_from_set);                                   // set of pages
    jnl->page_cache.page_from_set.compare = journal_jnl_page_cache_node_compare;    // comparator for set
    list_dl_init(&jnl->page_cache.page_mru);                                        //  empty list of pages
}

static void
journal_jnl_page_cache_add_nolock(journal_jnl *jnl, const journal_jnl_page *page, u32 page_offset)
{
    journal_jnl_page *cached_page;
#if DEBUG
    log_debug3("jnl: %s,%p: cache add page [%u; %u] of size %u at %u", circular_file_name(jnl->file), jnl->file, page->serial_from, page->serial_to, page->size, page_offset);
#endif
    ptr_node *node = ptr_set_find(&jnl->page_cache.page_from_set, (void*)(intptr)page->serial_from);
    if(node != NULL)
    {
        list_dl_node_s *list_node = (list_dl_node_s*)node->value;
        if(list_node != list_dl_first_node(&jnl->page_cache.page_mru))
        {
            // move node from its current position to the first position

            list_dl_remove_node(&jnl->page_cache.page_mru, list_node);
            //list_dl_insert(&jnl->page_cache.page_mru, list_node);
            list_dl_insert_node(&jnl->page_cache.page_mru, list_node);
        }
        return;
    }
    
    if(list_dl_size(&jnl->page_cache.page_mru) == JOURNAL_JNL_PAGE_FROM_SET_SIZE_MAX)
    {
        // clear the last page

        list_dl_move_last_to_first(&jnl->page_cache.page_mru);
        cached_page = (journal_jnl_page*)list_dl_peek_first(&jnl->page_cache.page_mru);
        ptr_set_delete(&jnl->page_cache.page_from_set, (void*)(intptr)cached_page->serial_from);
    }
    else
    {
        // there is still room: add a new page

        ZALLOC_OBJECT_OR_DIE(cached_page, journal_jnl_page, JNLJNLPG_TAG);
        list_dl_insert(&jnl->page_cache.page_mru, cached_page);
    }

    // update the new or cleared page

    cached_page->magic = page_offset;
    cached_page->serial_from = page->serial_from;
    cached_page->serial_to = page->serial_to;
    cached_page->size = page->size;

    // create an entry in the set (we know the entry doesn't exist)
    // the set contains list_dl_node_s as data
    
    node = ptr_set_insert(&jnl->page_cache.page_from_set, (void*)(intptr)page->serial_from);
    node->value = list_dl_first_node(&jnl->page_cache.page_mru);
}

static bool
journal_jnl_page_cache_get_from_serial_nolock(journal_jnl *jnl, u32 serial_from, journal_jnl_page *page_out, u32 *page_offset_out)
{
    journal_jnl_page *cached_page;
    
    ptr_node *node = ptr_set_find(&jnl->page_cache.page_from_set, (void*)(intptr)serial_from);
    
    if(node == NULL)
    {
        return FALSE;
    }
    
    list_dl_node_s *cached_page_node = (list_dl_node_s*)node->value;
    
    cached_page = (journal_jnl_page*)cached_page_node->data;
    
    if(page_out != NULL)
    {
        page_out->magic = PAGE_MAGIC;
        page_out->serial_from = cached_page->serial_from;
        page_out->serial_to = cached_page->serial_to;
        page_out->size = cached_page->size;
    }
    
    if(page_offset_out != NULL)
    {
        *page_offset_out = cached_page->magic; // magic holds the offset
    }

    return TRUE;
}

static void
journal_jnl_page_cache_shift_nolock(journal_jnl* jnl, u32 offset)
{
    list_dl_iterator_s iter;
    
    list_dl_iterator_init(&iter, &jnl->page_cache.page_mru);
    
    while(list_dl_iterator_has_next(&iter))
    {
        journal_jnl_page *page = (journal_jnl_page*)list_dl_iterator_next(&iter);
        if(page->magic > offset)
        {
#if DEBUG
            log_debug3("jnl: %s,%p: page cache [%u, %u] (%u bytes) shift from %u to %u", circular_file_name(jnl->file), jnl->file, page->serial_from, page->serial_to, page->size, page->magic, page->magic - offset);
#endif
            page->magic -= offset;
        }
        else
        {
#if DEBUG
            log_debug3("jnl: %s,%p: page cache [%u, %u] (%u bytes) shift out from %u to void", circular_file_name(jnl->file), jnl->file, page->serial_from, page->serial_to, page->size, page->magic);
#endif
            ptr_node *node = ptr_set_find(&jnl->page_cache.page_from_set, (void*)(intptr)page->serial_from);
            
            assert(node != NULL);
            
            list_dl_node_s *list_node = (list_dl_node_s*)node->value;
            ptr_set_delete(&jnl->page_cache.page_from_set, (void*)(intptr)page->serial_from);
            list_dl_iterator_remove(&iter);
            list_dl_node_free(list_node);
            ZFREE_OBJECT(page);
        }
    }
}

static journal_jnl *
journal_jnl_alloc_default(const u8 *origin, const char *filename);

static void journal_jnl_free_default(journal_jnl* jnl);

static journal_range_lock*
journal_jnl_lock_range_add_nolock(journal_jnl* jnl, u32 serial)
{
#if DEBUG
    log_debug3("jnl: %s,%p: lock range [%u; %u] add", circular_file_name(jnl->file), jnl->file, serial, jnl->hdr.serial_end);
#endif

    if(serial_le(jnl->hdr.serial_begin, serial) && serial_gt(jnl->hdr.serial_end, serial))
    {
        journal_range_lock* lock;
        ZALLOC_OBJECT_OR_DIE(lock, journal_range_lock, JNLRNGLK_TAG);
        lock->serial_from = serial;
        lock->serial_to = jnl->hdr.serial_end;
        
#if DEBUG
        if(serial_gt(lock->serial_from, lock->serial_to))
        {
            abort();
        }
#endif
        
        list_dl_append(&jnl->range_lock, lock);
        
#if DEBUG
        journal_jnl_log_dump_nolock((journal*)jnl);
#endif
        return lock;
    }
    else
    {
        return NULL;
    }
}

static void
journal_jnl_lock_range_remove_nolock(journal_jnl* jnl, journal_range_lock *lock)
{
#if DEBUG
    log_debug3("jnl: %s,%p: lock range [%u; %u] remove", circular_file_name(jnl->file), jnl->file, lock->serial_from, lock->serial_to);
#endif
    bool ret = list_dl_remove(&jnl->range_lock, lock);
    
    if(!ret)
    {
        log_err("jnl: %s,%p: lock range [%u; %u] not set", circular_file_name(jnl->file), jnl->file, lock->serial_from, lock->serial_to);
        abort();
    }
    
    ZFREE_OBJECT(lock);
    
#if DEBUG
    journal_jnl_log_dump_nolock((journal*)jnl);
#endif
}

static bool
journal_jnl_lock_get_serial_range_nolock(journal_jnl* jnl, u32 *serial_fromp, u32 *serial_top)
{
#if DEBUG
    log_debug3("jnl: %s,%p: [%u; %u] lock serial range get",
        circular_file_name(jnl->file), jnl->file,
        jnl->hdr.serial_begin, jnl->hdr.serial_end
        );
#endif

    if(list_dl_size(&jnl->range_lock) > 0)
    {
        u32 serial_from = jnl->hdr.serial_end;
        u32 serial_to = jnl->hdr.serial_begin;
        
        list_dl_iterator_s iter;
        list_dl_iterator_init(&iter, &jnl->range_lock);

        while(list_dl_iterator_has_next(&iter))
        {
            journal_range_lock *lock = (journal_range_lock*)list_dl_iterator_next(&iter);
            
#if DEBUG
            log_debug3("jnl: %s,%p: [%u; %u]     locked for [%d; %d]",
                circular_file_name(jnl->file), jnl->file,
                jnl->hdr.serial_begin, jnl->hdr.serial_end,
                lock->serial_from, lock->serial_to
                );
#endif

#if DEBUG
            if(serial_gt(lock->serial_from, lock->serial_to))
            {
                abort();
            }
#endif            
            if(serial_lt(lock->serial_from, serial_from))
            {
                serial_from = lock->serial_from;
            }
            
            if(serial_gt(lock->serial_to, serial_to))
            {
                serial_to = lock->serial_to;
            }
        }
        
#if DEBUG
        if(serial_gt(serial_from, serial_to))
        {
            abort();
        }
#endif  
        
        *serial_fromp = serial_from;
        *serial_top = serial_to;
        
        return TRUE;
    }
    else
    {
//#if DEBUG
        *serial_fromp = jnl->hdr.serial_end;
        *serial_top = jnl->hdr.serial_end;
//#endif
        
        return FALSE;
    }
}

static int
journal_jnl_create_file(journal_jnl **jnlp, const u8 *origin, const char *filename)
{
    log_debug3("jnl: %{dnsname}: creating %s", origin, filename);

    circular_file_t file;
    ya_result ret;

    if(ISOK(ret = circular_file_create(&file, journal_file_pool, jnl_magic, filename, 65536, sizeof(journal_jnl_header))))
    {
        journal_jnl *jnl = journal_jnl_alloc_default(origin, filename);
        jnl->file = file;

        jnl->hdr.serial_begin = 0;
        jnl->hdr.serial_end = 0;
        jnl->hdr.last_soa_offset = 0;
        jnl->hdr.flags = JOURNAL_JNL_FLAGS_MY_ENDIAN;

        if(ISOK(ret = circular_file_write_reserved_header(file, &jnl->hdr, sizeof(journal_jnl_header))))
        {
            *jnlp = jnl;
        }
        else
        {
            journal_jnl_free_default(jnl); // does circular_file_close(file);
        }
    }
    else
    {
        log_err("jnl: %s: failed to create %s: %r", origin, filename, ret);

        *jnlp = NULL;
    }

    return ret;
}

static int
journal_jnl_scan(journal_jnl* jnl)
{
#if EXPERIMENTAL
    union journal_jnl_entry last_good_entry = { 0 };
    u64 last_good_position = 0;
#endif
    union journal_jnl_entry entry;
    ya_result ret = SUCCESS;

    journal_jnl_chapter_entry *current_chapter = NULL;

    u64 prev_pos = 0;

    while(circular_file_get_read_available(jnl->file) > 0)
    {
        u64 position = circular_file_tell(jnl->file);
        entry.magic = 0;

        if(ISOK(ret = circular_file_read(jnl->file, &entry.magic, sizeof(u32))))
        {
            switch(entry.magic)
            {
                case CHPT_MAGIC:
                {
                    if(ISOK(ret = circular_file_read(jnl->file, &entry.base.data, sizeof(journal_jnl_chapter) - sizeof(u32))))
                    {
#if DEBUG
                        log_debug3("jnl: %s,%p: scan: read chapter header [%u, %u] size %u", circular_file_name(jnl->file), jnl->file,
                                entry.chapter.serial_from, entry.chapter.serial_to, entry.chapter.relative_next);
#endif
                        if(ISOK(ret = circular_file_seek_relative(jnl->file, entry.chapter.relative_next)))
                        {
                            // store the chapter
                            // read the next entry

                            journal_jnl_chapter_entry *chapter_entry;
                            ZALLOC_OBJECT_OR_DIE(chapter_entry, journal_jnl_chapter_entry, JNLCHPTE_TAG);
                            chapter_entry->position = position;
                            chapter_entry->chapter = entry.chapter;
                            list_dl_append(&jnl->chapters, chapter_entry);
                            prev_pos = position;
                        }
                        else
                        {
                            log_err("jnl: %s,%p: scan: failed to seek right after the chapter: %r", circular_file_name(jnl->file), jnl->file, ret);
                        }
                    }
                    else
                    {
                        log_err("jnl: %s,%p: scan: failed to read chapter header: %r", circular_file_name(jnl->file), jnl->file, ret);
                    }
                    break;
                }
                case PAGE_MAGIC:
                {
                    if(ISOK(ret = circular_file_read(jnl->file, &entry.base.data, sizeof(journal_jnl_page) - sizeof(u32))))
                    {
#if DEBUG
                        log_debug3("jnl: %s,%p: scan: read page header [%u, %u] size %u", circular_file_name(jnl->file), jnl->file,
                                entry.page.serial_from, entry.page.serial_to, entry.page.size);
#endif
                        if(ISOK(ret = circular_file_seek_relative(jnl->file, entry.page.size)))
                        {
                            // add to the current virtual chapter (create it if needed)
                            // if the current virtual chapter is "big enough", store it and clear it as "current"
                            // read the next entry
#if EXPERIMENTAL
                            last_good_entry = entry;
                            last_good_position = position;
#endif
                            journal_jnl_page_cache_add_nolock(jnl, &entry.page, position);

                            if(current_chapter == NULL)
                            {
                                journal_jnl_chapter_entry *chatper_entry;
                                ZALLOC_OBJECT_OR_DIE(chatper_entry, journal_jnl_chapter_entry, JNLCHPTE_TAG);
                                chatper_entry->position = position - sizeof(journal_jnl_chapter);
                                chatper_entry->chapter.magic = 0; // fake one
                                chatper_entry->chapter.relative_prev = prev_pos;
                                chatper_entry->chapter.relative_next = sizeof(journal_jnl_page) + entry.page.size - sizeof(journal_jnl_chapter);
                                chatper_entry->chapter.serial_from = entry.page.serial_from;
                                chatper_entry->chapter.serial_to = entry.page.serial_to;

                                current_chapter = chatper_entry;
                                prev_pos = chatper_entry->position;
                            }
                            else
                            {
                                current_chapter->chapter.relative_next += sizeof(journal_jnl_page) + entry.page.size;
                                current_chapter->chapter.serial_to = entry.page.serial_to;
                            }

                            if(current_chapter->chapter.relative_next >= CHPT_SIZE_THRESHOLD)
                            {
                                list_dl_append(&jnl->chapters, current_chapter);
                                current_chapter = NULL;
                            }
                        }
                        else
                        {
                            log_err("jnl: %s,%p: scan: failed to seek right after the page: %r", circular_file_name(jnl->file), jnl->file, ret);
                        }
                    }
                    else
                    {
                        log_err("jnl: %s,%p: scan: failed to read page header: %r", circular_file_name(jnl->file), jnl->file, ret);
                    }
                    break;
                }
                default:
                {
                    log_err("jnl: %s,%p: scan: unknown magic %08x", circular_file_name(jnl->file), jnl->file, entry.magic);
                    ret = ZDB_JOURNAL_UNEXPECTED_MAGIC;
                    break;
                }
            }

            if(FAIL(ret))
            {
                log_err("jnl: %s,%p: failed to scan file: %r", circular_file_name(jnl->file), jnl->file, ret);
                break;
            }
        }
        else
        {
            if(ISOK(ret))
            {
                // short read, probable corruption

                log_err("jnl: %s,%p: failed to scan magic: got only %i bytes", circular_file_name(jnl->file), jnl->file, ret);

                ret = ZDB_JOURNAL_SHORT_READ;
            }
            else
            {
                log_err("jnl: %s,%p: failed to scan next magic: %r", circular_file_name(jnl->file), jnl->file, ret);
#if EXPERIMENTAL
                if(ret == CIRCULAR_FILE_SHORT)
                {
                    // the journal has been corrupted, the current page is lost
                    if(last_good_entry.magic == PAGE_MAGIC)
                    {
                        // rollback

                        jnl->hdr.serial_end = last_good_entry.page.serial_to;

                        ssize_t records_position = circular_file_seek(jnl->file, last_good_position + 16);
                        if(ISOK(records_position))
                        {
                            // read records until the 2nd SOA is found

                            u8 *update_message_records = (u8*)malloc(last_good_entry.page.size);
                            if(update_message_records != NULL)
                            {
                                ya_result update_message_size = circular_file_read(jnl->file, update_message_records, last_good_entry.page.size);
                                if(update_message_size == last_good_entry.page.size)
                                {
                                    packet_unpack_reader_data pr;
                                    dns_resource_record *rr = dns_resource_record_new_instance();
                                    packet_reader_init(&pr, update_message_records, update_message_size);

                                    int soa_count = 0;
                                    for(;;)
                                    {
                                        u32 rr_position = pr.offset;
                                        if(packet_reader_read_dns_resource_record(&pr, rr) <= 0)
                                        {
                                            break;
                                        }
                                        if(rr->tctr.qtype == TYPE_SOA)
                                        {
                                            if(soa_count++ > 0)
                                            {
                                                jnl->hdr.last_soa_offset = records_position + rr_position;
                                                circular_file_set_size(jnl->file, circular_file_tell(jnl->file));
                                                break;
                                            }
                                        }
                                    }

                                    dns_resource_record_free(rr);
                                    free(update_message_records);
                                }
                                else
                                {
                                    free(update_message_records);

                                    if(ISOK(update_message_size))
                                    {
                                        // short read?
                                    }
                                    else
                                    {
                                        return ZDB_JOURNAL_SHORT_READ;
                                    }
                                }
                            }
                        }
                    }
                }
#endif // EXPERIMENTAL
            }
            
            break;
        }
    }

    if(current_chapter != NULL)
    {
        list_dl_append(&jnl->chapters, current_chapter);
        current_chapter = NULL;
    }

    return ret;
}

/**
 *
 * MUST return -1 in case of error
 *
 * @param jnl
 * @param create
 * @return the file descriptor or an error code
 */

static int
journal_jnl_init_from_file(journal_jnl **jnlp, const u8 *origin, const char *filename, bool create)
{
    log_debug3("jnl: %{dnsname}: opening%s %s", origin, (create)?"/creating":"", filename);

    circular_file_t file;
    ya_result ret;

    if(ISOK(ret = circular_file_open(&file, journal_file_pool, jnl_magic, filename)))
    {
        journal_jnl *jnl = journal_jnl_alloc_default(origin, filename);
        jnl->file = file;

        if(ISOK(ret = circular_file_read_reserved_header(file, &jnl->hdr, sizeof(journal_jnl_header))))
        {
            // scan the file

            ret = journal_jnl_scan(jnl);

            *jnlp = jnl;
            return ret;
        }

        journal_jnl_free_default(jnl); // does circular_file_close(file);
    }
    else if(ret == DATA_FORMAT_ERROR)
    {
        // journal is either corrupted, either in an older format
        // _ open the journal file
        // _ read the magic
        // _ if it's a CJF read it ...
        //   ... with a specialised version that can only read and will scream about "journal full" whenever it's being written on
        // _ also, ensure the journal has been read completely before being written
        // _ at the moment we know the zone has been saved, destroy the file and create a new journal with the most recent features

#if JOURNAL_CJF_ENABLED
        ret = journal_cjf_open_file((journal**)jnlp, filename, origin, FALSE);
#else
        ret = journal_cjf_ro_open_file((journal**)jnlp, filename, origin, FALSE);

        if(ISOK(ret) && create)
        {
            (*jnlp)->vtbl->close((journal*)*jnlp);
            (*jnlp)->vtbl->destroy((journal*)*jnlp);
            file_pool_unlink_from_pool_and_filename(journal_file_pool, filename);
            ret = journal_jnl_init_from_file(jnlp, origin, filename, create);
        }
#endif
    }
    else if(create)
    {
        ret = journal_jnl_create_file(jnlp, origin, filename);
    }

    return ret;
}

static ya_result
journal_jnl_header_flush_nolock(journal_jnl *jnl)
{
    ya_result ret = SUCCESS;
    if(journal_jnl_is_dirty_nolock(jnl))
    {
        if(ISOK(ret = circular_file_write_reserved_header(jnl->file, &jnl->hdr, sizeof(journal_jnl_header))))
        {
            if(ISOK(circular_file_flush(jnl->file)))
            {
                journal_jnl_clear_dirty_nolock(jnl);
            }
        }
    }
    return ret;
}

/*****************************************************************************/

static void journal_jnl_writelock(journal_jnl *jnl);
static void journal_jnl_writeunlock(journal_jnl *jnl);

static void journal_jnl_readlock(journal_jnl *jnl);
static void journal_jnl_readunlock(journal_jnl *jnl);

static const char *
journal_jnl_get_format_name() // vtbl
{
    return JOURNAL_FORMAT_NAME;
}

static u32
journal_jnl_get_format_version() // vtbl
{
    return VERSION_U32(VERSION_HI,VERSION_LO);
}



static s32
journal_jnl_get_position_for_serial_nolock(journal_jnl *jnl, u32 serial)
{
    s32 ret = -1;
    s32 position = -1;
    journal_jnl_page page;
    
    if(serial_le(jnl->hdr.serial_begin, serial) && serial_gt(jnl->hdr.serial_end, serial))
    {
        if(journal_jnl_page_cache_get_from_serial_nolock(jnl, serial, &page, (u32*)&position))
        {
            // it was recently used
#if DEBUG
            log_debug("jnl: %s,%p: page for serial %u cached position is %u", circular_file_name(jnl->file), jnl->file, serial, position);
#endif
            return position;
        }

        // follow the list of pages
                
        // first ensure known chapter covers

        journal_jnl_chapter_entry *first = (journal_jnl_chapter_entry*)list_dl_peek_first(&jnl->chapters);
        journal_jnl_chapter_entry *last = (journal_jnl_chapter_entry*)list_dl_peek_last(&jnl->chapters);
        if( ((((intptr)first)|((intptr)last)) != 0) && serial_ge(serial, first->chapter.serial_from) && serial_le(serial, last->chapter.serial_from))
        {
            list_dl_iterator_s iter;
            list_dl_iterator_init(&iter, &jnl->chapters);

            bool found = FALSE;

            while(list_dl_iterator_has_next(&iter))
            {
                journal_jnl_chapter_entry *entry = (journal_jnl_chapter_entry *)list_dl_iterator_next(&iter);

                if(serial_le(entry->chapter.serial_from, serial) && serial_gt(entry->chapter.serial_to, serial))
                {
                    // found the containing chapter
                    // look from that position
                    position = entry->position + sizeof(journal_jnl_chapter);

#if DEBUG
                    log_debug("jnl: %s,%p: page for serial %u position is %u (%u + %u)", circular_file_name(jnl->file), jnl->file, serial, position,
                             entry->position, sizeof(journal_jnl_chapter));
#endif
                    found = TRUE;
                    break;
                }
            }

            if(!found)
            {
                log_err("jnl: %s,%p: failed to read page for serial %u: position was not found (serial range is [%u; %u]", circular_file_name(jnl->file), jnl->file, serial, position,
                        jnl->hdr.serial_begin, jnl->hdr.serial_end);

                return ERROR;
            }
        }
        else
        {
            // the covering chapter may have been destroyed during a shift
            // look from 0
            
            position = 0;
        }
        
        //u64 org_position = circular_file_tell(jnl->file);
        
        journal_jnl_page page;

        u32 prev_serial_from;
        bool prev_serial_from_ready = FALSE;

        for(;;)
        {        
            ssize_t resulting_position = circular_file_seek(jnl->file, position);

            if(resulting_position != position)
            {
                if(FAIL(resulting_position))
                {
                    log_err("jnl: %s,%p: looking for %u at position %u: seek failed with %r", circular_file_name(jnl->file), jnl->file, serial, position, (ya_result)resulting_position);
                }
                else
                {
                    log_err("jnl: %s,%p: looking for %u at position %u: seek gave position %llu", circular_file_name(jnl->file), jnl->file, serial, position, resulting_position);
                }

                log_err("jnl: %s,%p: trying to recover by marking the journal as corrupted", circular_file_name(jnl->file), jnl->file);

                ret = ZDB_JOURNAL_LOOKS_CORRUPTED;
                break;
            }

            if((ret = circular_file_read(jnl->file, &page, sizeof(journal_jnl_page))) == sizeof(journal_jnl_page))
            {
                if(page.magic == PAGE_MAGIC)
                {
                    if(prev_serial_from_ready && serial_ge(prev_serial_from, page.serial_from))
                    {
                        log_err("jnl: %s,%p: looking for %u at position %u: page serial did not increment: previous was %u, current is %u", circular_file_name(jnl->file), jnl->file, serial, position, ret, prev_serial_from, page.serial_from);

                        ret = ZDB_JOURNAL_LOOKS_CORRUPTED; // something is fishy
                        break;
                    }

                    if(page.serial_from == serial)
                    {
                        // got it
                        ret = position;
                        break;
                    }
                    else if(serial_gt(page.serial_from, serial))
                    {
                        log_err("jnl: %s,%p: looking for %u at position %u: serial not found, current is %u, which is after it", circular_file_name(jnl->file), jnl->file, serial, position, ret, page.serial_from);

                        ret = ZDB_JOURNAL_LOOKS_CORRUPTED; // serial jumping the wrong way: probable corruption
                        break;
                    }
                    else // next ...
                    {
                        position += sizeof(journal_jnl_page) + page.size;
                    }

                    prev_serial_from = page.serial_from;
                    prev_serial_from_ready = TRUE;
                }
                else
                {
                    log_err("jnl: %s,%p: failed to read page for serial %u at position %u: bad magic: expected %08x, got %08x", circular_file_name(jnl->file), jnl->file, serial, position, ret, PAGE_MAGIC, page.magic);
                    
                    ret = ZDB_JOURNAL_UNEXPECTED_MAGIC; // bad magic
                    
                    break;
                }
            }
            else
            {
                if(ISOK(ret))
                {
                    // short read, probable corruption

                    log_err("jnl: %s,%p: failed to read page for serial %u at position %u: got %i bytes instead of %i", circular_file_name(jnl->file), jnl->file,
                            serial, position, ret, sizeof(journal_jnl_page));

                    ret = ZDB_JOURNAL_SHORT_READ;
                }
                else
                {
                    log_err("jnl: %s,%p: failed to read page for serial %u at position %u: %r", circular_file_name(jnl->file), jnl->file, serial, position, ret);
                }
                
                break;
            }
        }
        
        //circular_file_seek(jnl->file, org_position);
    }
    else
    {
        return -1;
    }
    
    return ret;
}

static void
journal_jnl_adjust_chapters_nolock(journal_jnl *jnl, s64 offset)
{
    if(offset == 0)
    {
        return;
    }
    
#if DEBUG
        log_debug("jnl: %s,%p: shifting out chapters by %u bytes", circular_file_name(jnl->file), jnl->file, offset);
#endif
    
    list_dl_iterator_s iter;
    
    list_dl_iterator_init(&iter, &jnl->chapters);
    while(list_dl_iterator_has_next(&iter))
    {
        journal_jnl_chapter_entry *entry = (journal_jnl_chapter_entry *)list_dl_iterator_next(&iter);
        
        if(entry->position < offset)
        {
#if DEBUG
            log_debug("jnl: %s,%p: shifting out chapter [%u, %u] (%u bytes) from %u to void", circular_file_name(jnl->file), jnl->file,
                    entry->chapter.serial_from, entry->chapter.serial_to, entry->chapter.relative_next + sizeof(journal_jnl_chapter), entry->position);
#endif      
            list_dl_iterator_remove(&iter);
            // free it
            ZFREE_OBJECT(entry);
        }
        else
        {
#if DEBUG
            log_debug("jnl: %s,%p: shifting out chapter [%u, %u] (%u bytes) from %u to %u", circular_file_name(jnl->file), jnl->file,
                    entry->chapter.serial_from, entry->chapter.serial_to, entry->chapter.relative_next + sizeof(journal_jnl_chapter),
                    entry->position, entry->position - offset);
#endif
            entry->position -= offset;
        }
    }
}

static ya_result
journal_jnl_shift_nolock_grow_empty(journal_jnl *jnl, s64 required)
{
    // if the file is empty, then try to grow it ... if allowed

    s64 file_maximum_size = (s64)circular_file_get_maximum_size(jnl->file);
    // jnl->size_limit
    // required

    if(required > file_maximum_size)
    {
        if(required < (s64)jnl->size_limit)
        {
            // grow instead
            // try to grow at twice the size if possible

            s64 new_size = MIN((s64)required * 2, (s64)jnl->size_limit);

            ya_result  ret = circular_file_grow(jnl->file, new_size);

            if(ISOK(ret))
            {
                log_debug("jnl: %s,%p: journal [%u, %u] shift triggered a regrow to %llu bytes", circular_file_name(jnl->file), jnl->file,
                          jnl->hdr.serial_begin, jnl->hdr.serial_end, circular_file_get_size(jnl->file));
            }
            else
            {
                ret = CIRCULAR_FILE_SHORT;
            }

            return ret;
        }
        else
        {
            return ZDB_JOURNAL_SIZE_LIMIT_TOO_SMALL;
        }
    }
    else
    {
        // there is nothing to shift, this should not have been called

        return SUCCESS;
    }
}

/**
 *  Tries to make room on the journal by shifting the oldest page.
 *
 */

static ya_result
journal_jnl_shift_nolock(journal_jnl *jnl, s64 required)
{
    ya_result ret;
    ya_result serial_error;
    u32 serial_from;
    u32 serial_to;

    bool has_lock = journal_jnl_lock_get_serial_range_nolock(jnl, &serial_from, &serial_to);

#if DEBUG
    log_debug("jnl: %s,%p: journal [%u, %u] must shift out at least %lli bytes, safe serial is %u, locked is [%u, %u], current size is %u, locked=%i",
              circular_file_name(jnl->file), jnl->file,
              jnl->hdr.serial_begin, jnl->hdr.serial_end,
              required,
              jnl->safe_serial,
              serial_from, serial_to,
              circular_file_get_size(jnl->file),
              has_lock);
#endif

    if(has_lock)
    {
#if DEBUG
        log_debug("jnl: %s,%p: range [%u; %u] locked", circular_file_name(jnl->file), jnl->file, serial_from, serial_to);
#endif

        yassert(circular_file_get_size(jnl->file) > 0);
    
        if(serial_lt(jnl->safe_serial, serial_from))
        {
            serial_from = jnl->safe_serial;
            serial_error = ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY; // in shift code
        }
        else
        {
            serial_error = ZDB_JOURNAL_SERIAL_RANGE_LOCKED;
        }
    }
    else
    {
        // there may be no locked range because the file is empty

        if(circular_file_get_size(jnl->file) > 0)
        {
            serial_from = jnl->safe_serial;
            serial_to = jnl->hdr.serial_end;
            serial_error = ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY; // in shift code
        }
        else
        {
            ret = journal_jnl_shift_nolock_grow_empty(jnl, required);

            return ret;
        }
    }
    
    if(serial_lt(jnl->hdr.serial_begin, serial_from))
    {
        u64 position = circular_file_tell(jnl->file);
        s64 offset = 0;
        union journal_jnl_entry entry;
        u32 serial_begin; //  = jnl->hdr.serial_begin;
        ret = SUCCESS;

        s64 originally_required = required;

        while(required > 0)
        {
            if(ISOK(ret = circular_file_seek(jnl->file, 0)))
            {
                // read what we got

                if((ret = circular_file_read(jnl->file, &entry.magic, sizeof(u32))) == sizeof(u32))
                {
                    switch(entry.magic)
                    {
                        case CHPT_MAGIC:
                        {
                            if(ISOK(ret = circular_file_read(jnl->file, &entry.base.data, sizeof(journal_jnl_chapter) - sizeof(u32))))
                            {
                                if(serial_le(entry.chapter.serial_to, serial_from))
                                {
                                    // the whole chapter can be dropped
                                    
                                    offset = sizeof(journal_jnl_chapter) + entry.chapter.relative_next;

                                    // offset > 0
#if DEBUG
                                    log_debug("jnl: %s,%p: journal [%u, %u] shifting out chapter [%u, %u] (%u bytes)", circular_file_name(jnl->file), jnl->file, jnl->hdr.serial_begin, jnl->hdr.serial_end,
                                            entry.chapter.serial_from, entry.chapter.serial_to, offset);
#endif
                                    if(ISOK(ret = circular_file_shift(jnl->file, offset)))
                                    {
                                        // adjust the indexes to reflect the removal of this entry

                                        required -= offset;
                                        
                                        // do the indexes adjustments
                                        
                                        jnl->hdr.last_soa_offset -= offset;
                                        journal_jnl_adjust_chapters_nolock(jnl, offset);
                                        journal_jnl_page_cache_shift_nolock(jnl, (u32)offset);
                                        
                                        serial_begin = entry.chapter.serial_to;
                                        jnl->hdr.serial_begin = serial_begin;

                                        journal_jnl_set_dirty_nolock(jnl);
                                        journal_jnl_header_flush_nolock(jnl);
                                    }
                                }
                                else if(serial_ge(entry.chapter.serial_from, serial_from))
                                {
                                    // remove the chunk itself, then proceed scanning the pages

                                    offset = sizeof(journal_jnl_chapter);
#if DEBUG
                                    log_debug("jnl: %s,%p: journal [%u, %u] shifting out head of chapter [%u, %u] (%u bytes)", circular_file_name(jnl->file), jnl->file, jnl->hdr.serial_begin, jnl->hdr.serial_end,
                                            entry.chapter.serial_from, entry.chapter.serial_to, offset);
#endif
                                    if(ISOK(ret = circular_file_shift(jnl->file, offset)))
                                    {
                                        // adjust the indexes to reflect the removal of this entry

                                        required -= offset;
                                        
                                        // do the indexes adjustments
                                        
                                        jnl->hdr.last_soa_offset -= offset;
                                        journal_jnl_adjust_chapters_nolock(jnl, offset);
                                        journal_jnl_page_cache_shift_nolock(jnl, offset);

                                        journal_jnl_set_dirty_nolock(jnl);
                                        journal_jnl_header_flush_nolock(jnl);
                                    }
                                }
                                else
                                {
                                    // there is no continuity between the stored zone and the journal
                                    
                                    ret = serial_error;
                                }
                            }
                            break;
                        }
                        case PAGE_MAGIC:
                        {
                            if(ISOK(ret = circular_file_read(jnl->file, &entry.base.data, sizeof(journal_jnl_page) - sizeof(u32))))
                            {
                                if(serial_le(entry.page.serial_to, serial_from))
                                {
                                    // the page can be dropped

                                    offset = sizeof(journal_jnl_page) + entry.page.size;
#if DEBUG
                                    log_debug("jnl: %s,%p: journal [%u, %u] shifting out page [%u, %u] (%u bytes)", circular_file_name(jnl->file), jnl->file, jnl->hdr.serial_begin, jnl->hdr.serial_end,
                                            entry.page.serial_from, entry.page.serial_to, offset);
#endif
                                    if(ISOK(ret = circular_file_shift(jnl->file, offset)))
                                    {
                                        // adjust the indexes to reflect the removal of this page

                                        required -= offset;
                                        
                                        // do the indexes adjustments
                                        
                                        jnl->hdr.last_soa_offset -= offset;
                                        journal_jnl_adjust_chapters_nolock(jnl, offset);
                                        journal_jnl_page_cache_shift_nolock(jnl, offset);

                                        serial_begin = entry.page.serial_to;
                                        jnl->hdr.serial_begin = serial_begin;

                                        journal_jnl_set_dirty_nolock(jnl);
                                        journal_jnl_header_flush_nolock(jnl);
                                    }
                                }
                                else
                                {
                                    // we reached the limit (and obviously failed reaching our quota)

                                    ret = serial_error;

                                    break;
                                }
                            }
                            break;
                        }
                        default:
                        {
                            ret = ZDB_JOURNAL_UNEXPECTED_MAGIC;
                            break;
                        }
                    } // switch

                    if(FAIL(ret))
                    {
                        log_debug("jnl: %s,%p: journal [%u, %u] failed to shift: %r", circular_file_name(jnl->file), jnl->file,
                                jnl->hdr.serial_begin, jnl->hdr.serial_end, ret);
                        break;
                    }
                }
                else // read error reading magic
                {
                    if(ret == CIRCULAR_FILE_SHORT)
                    {
                        log_err("jnl: %s,%p: journal [%u, %u] failed to shift: failed to read next magic at %llu/%llu: %r", circular_file_name(jnl->file), jnl->file,
                                    jnl->hdr.serial_begin, jnl->hdr.serial_end, circular_file_tell(jnl->file), circular_file_get_size(jnl->file), ret);
                    }
                    else
                    {
                        // nothing follows

                        log_debug("jnl: %s,%p: journal [%u, %u] failed to shift: current size is of %llu is too small, trying to grow the file", circular_file_name(jnl->file), jnl->file,
                                jnl->hdr.serial_begin, jnl->hdr.serial_end, circular_file_get_size(jnl->file));

                        if(ISOK(journal_jnl_shift_nolock_grow_empty(jnl, originally_required)))
                        {
                            if(circular_file_get_size(jnl->file) > 0)
                            {
                                ret = ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY; // in shift code
                            }
                            else
                            {
                                ret = SUCCESS;
                            }
                        }
                        else
                        {
                            // could not grow : file is too small

                            ret = ZDB_JOURNAL_SIZE_LIMIT_TOO_SMALL;
                        }
                    }

                    break;
                }
            }
            else
            {
                // seek error ? (unlikely)
                
                log_err("jnl: %s,%p: journal [%u, %u] failed to shift: failed to move to the beginning of the file: %r", circular_file_name(jnl->file), jnl->file,
                                jnl->hdr.serial_begin, jnl->hdr.serial_end, ret);
                break;
            }
        } // for
        
        circular_file_seek(jnl->file, position - offset);
    }
    else
    {
        // the journal is already following right after the stored zone
        
        ret = serial_error;
    }
    
    return ret;
}

static void
journal_jnl_page_cache_clear_cb(ptr_node *node)
{
    list_dl_node_s *cached_page_node = (list_dl_node_s*)node->value;
    journal_jnl_page *cached_page = (journal_jnl_page*)cached_page_node->data;
    ZFREE_OBJECT(cached_page);
    cached_page_node->data = NULL;
}

static void
journal_jnl_page_cache_clear(journal_jnl *jnl)
{
    ptr_set_callback_and_destroy(&jnl->page_cache.page_from_set, journal_jnl_page_cache_clear_cb);
    list_dl_clear(&jnl->page_cache.page_mru);
}

/**
 * 
 * 
 * @param jnl
 * @param baos MUST be a byte array output stream, full with the content of a single journal page
 * @param last_soa_relative_offset
 * @return 
 */

static ya_result
journal_jnl_append_ixfr_stream_write_page(journal_jnl *jnl, output_stream *baos, u32 last_soa_relative_offset)
{
    journal_jnl_page *page = (journal_jnl_page*)bytearray_output_stream_buffer(baos);
    page->size = bytearray_output_stream_size(baos) - sizeof(journal_jnl_page);
    ya_result ret;
    
    journal_jnl_writelock(jnl);
    
#if DEBUG
    log_debug("jnl: %s: writing journal page of %u bytes with last SOA relative offset of %u", circular_file_name(jnl->file), page->size, last_soa_relative_offset);
#endif
    
    u32 page_offset = circular_file_get_size(jnl->file);
    
    circular_file_seek(jnl->file, page_offset);
        
    for(;;)
    {
        ret = circular_file_write(jnl->file, page, bytearray_output_stream_size(baos));

        if(ISOK(ret))
        {
            if(!(jnl->hdr.flags & JOURNAL_JNL_FLAGS_INITIALISED))
            {
                // this is a new journal: initialise the base fields
                
                jnl->hdr.flags |= JOURNAL_JNL_FLAGS_INITIALISED;
                jnl->hdr.serial_begin = page->serial_from;
            }

            jnl->hdr.serial_end = page->serial_to;
            jnl->hdr.last_soa_offset = page_offset + last_soa_relative_offset;
            journal_jnl_set_dirty_nolock(jnl);
            
            // keep the page in the cache
            
            journal_jnl_page_cache_add_nolock(jnl, page, page_offset);
        }
        else if(ret == CIRCULAR_FILE_FULL)
        {
            // get the first chunk
            // see if it covers the safe serial
            // if not, drop it
            
            if(ISOK(ret = journal_jnl_shift_nolock(jnl, page->size)))
            {
                if( ((jnl->hdr.serial_end - jnl->hdr.serial_begin) <= 1) &&
                    (jnl->safe_serial == jnl->hdr.serial_end) && 
                    (circular_file_get_maximum_size(jnl->file) < circular_file_get_pending_size(jnl->file)) )
                {
                    // the journal is too small and is allowed to grow: tabula rasa will fix this:
                    log_info("jnl: %s: file is locked too tight but is allowed to expand: clearing it.", circular_file_name(jnl->file));
                    
                    if(ISOK(ret = journal_jnl_shift_nolock(jnl, circular_file_get_size(jnl->file))))
                    {
                        log_info("jnl: %s: file is locked too tight but is allowed to expand: cleared it.", circular_file_name(jnl->file));
                        // done
                    }
                    else
                    {
                        log_err("jnl: %s: file is locked too tight and cannot be cleared.", circular_file_name(jnl->file));
                    }
                }
                
                page_offset = circular_file_get_size(jnl->file);
                circular_file_seek(jnl->file, page_offset);
                
                continue;
            }
            
            // else we cannot continue shifting: it would break continuity
            // or a page is (temporarily) locked
        }
        
        break;
    }
    
    journal_jnl_writeunlock(jnl);

    return ret;
}

/**
 * The caller will take action that will end up removing the first page.
 * Either explicitly, either overwriting it (ie: looping).
 *
 * This function ensures that it's OK to do so.
 *
 * Returns:
 *
 * 0 if it's OK to do so, and no actions were taken,
 * 1 if it's OK to do so, but the zone needed to be stored
 * or an error code.
 *
 * @param jnl
 *
 * @return the state of the operation
 *
 */

static const journal_jnl_page empty_page = {PAGE_MAGIC, 0, 0, 0};

static ya_result
journal_jnl_append_ixfr_stream(journal *jh, input_stream *ixfr_wire_is) // vtbl
{
    journal_jnl *jnl = (journal_jnl*)jh;
    output_stream baos;
    dns_resource_record rr;
    ya_result ret;
    int soa_count = 0;
    int pages_written = 0;
    u32 soa_serial;
    u32 last_soa_relative_offset = 0;
    u8 tmp[4096];

    bytearray_output_stream_init_ex(&baos, tmp, sizeof(tmp), BYTEARRAY_DYNAMIC);

    output_stream_write(&baos, &empty_page, sizeof(journal_jnl_page));
    
    dns_resource_record_init(&rr);

    for(;;)
    {
        if((ret = dns_resource_record_read(&rr, ixfr_wire_is)) <= 0)
        {
            // EOF or ERROR

            if(ret == 0)
            {
                if(soa_count == 2)
                {
                    // ...

                    // If the journal maximum size is to small then there will be a performance hit or worse:
                    //   it will be impossible to push the next page to the journal.

                    u32 journal_size_max = (u32)MIN(circular_file_get_maximum_size(jnl->file), (u64)MAX_U32);
                    u32 baos_size = bytearray_output_stream_size(&baos);

                    bool possible_journal_overflow = (baos_size > (journal_size_max >> 1));

                    for(;;)
                    {
                        if(ISOK(ret = journal_jnl_append_ixfr_stream_write_page(jnl, &baos, last_soa_relative_offset)))
                        {
                            ++pages_written;
                            break;
                        }

                        if(((ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY) || (ret == CIRCULAR_FILE_FULL)) && possible_journal_overflow) // after trying to append a page
                        {
                            // the journal size should be set to be MAX(current + baos_size, baos_size * 2)

                            u32 try_grow = MAX(baos_size * 2, journal_size_max + baos_size);
                            try_grow = MIN(try_grow, jnl->size_limit);

                            if(try_grow < journal_size_max)
                            {
                                log_err("jnl: %s: journal size may be too small: tried to write a page of %u bytes into a %u bytes journal",
                                          circular_file_name(jnl->file), baos_size, journal_size_max);
                                break;
                            }

                            log_debug("jnl: %s: journal size may be too small: tried to write a page of %u bytes into a %u bytes journal. Growing to %u",
                                    circular_file_name(jnl->file), baos_size, journal_size_max, try_grow);

                            circular_file_grow(jnl->file, try_grow);

                            possible_journal_overflow = FALSE; // only try to do this once
                        }
                        else
                        {
                            break;
                        }
                    }
                }
                else // e.g.: the master did a shutdown mid-transmission
                {
                    log_warn("jnl: %s: journal page is incomplete: dropping it",
                            circular_file_name(jnl->file));

                    ret = 0;    // it's not an error per se
                }
            }
            else
            {
                log_warn("jnl: %s: could not read next record on the stream: %r",
                         circular_file_name(jnl->file), ret);
            }

            bytearray_output_stream_reset(&baos);
            break;
        }

        u16 rtype = rr.tctr.qtype;

        if(rtype == TYPE_SOA)
        {
            if(FAIL(ret = rr_soa_get_serial(rr.rdata, rr.rdata_size, &soa_serial)))
            {
                break;
            }

            if(soa_count == 0)
            {
                // start of the page
                
                if(jnl->hdr.flags & JOURNAL_JNL_FLAGS_INITIALISED)
                {
                    if(jnl->hdr.serial_end != soa_serial)
                    {
                        ret = ZDB_JOURNAL_SERIAL_OUT_OF_KNOWN_RANGE; // serial do not follow
                        break;
                    }
                }
                
                dns_resource_record_write(&rr, &baos);

                journal_jnl_page *page = (journal_jnl_page*)bytearray_output_stream_buffer(&baos);
                page->serial_from = soa_serial;
            }
            else if(soa_count == 1)
            {
                // second half of page
                
                last_soa_relative_offset = bytearray_output_stream_size(&baos);
                
                dns_resource_record_write(&rr, &baos);

                journal_jnl_page *page = (journal_jnl_page*)bytearray_output_stream_buffer(&baos);

                page->serial_to = soa_serial;
            }
            else // soa_count == 2
            {
                // end of page: store and continue from here

                // ...

                // If the journal maximum size is to small then there will be a performance hit or worse:
                //   it will be impossible to push the next page to the journal.

                u32 journal_size_max = (u32)MIN(circular_file_get_maximum_size(jnl->file), (u64)MAX_U32);
                u32 baos_size = bytearray_output_stream_size(&baos);

                bool possible_journal_overflow = (baos_size > (journal_size_max >> 1));

                for(;;)
                {
                    if(ISOK(ret = journal_jnl_append_ixfr_stream_write_page(jnl, &baos, last_soa_relative_offset)))
                    {
                        ++pages_written;
                        break;
                    }

                    if(((ret == ZDB_JOURNAL_MUST_SAFEGUARD_CONTINUITY) || (ret == CIRCULAR_FILE_FULL)) && possible_journal_overflow) // after trying to append a page
                    {
                        // the journal size should be set to be MAX(current + baos_size, baos_size * 2)

                        u32 try_grow = MAX(baos_size * 2, journal_size_max + baos_size);
                        try_grow = MIN(try_grow, jnl->size_limit);

                        if(try_grow < journal_size_max)
                        {
                            log_err("jnl: %s: journal size may be too small: tried to write a page of %u bytes into a %u bytes journal",
                                    circular_file_name(jnl->file), baos_size, journal_size_max);
                            break;
                        }

                        log_debug("jnl: %s: journal size may be too small: tried to write a page of %u bytes into a %u bytes journal. Growing to %u",
                                  circular_file_name(jnl->file), baos_size, journal_size_max, try_grow);

                        circular_file_grow(jnl->file, try_grow);

                        possible_journal_overflow = FALSE; // only try to do this once
                    }
                    else
                    {
                        break;
                    }
                }

                bytearray_output_stream_reset(&baos);

                if(FAIL(ret))
                {
                    break;
                }

                soa_count = 0;
                
                output_stream_write(&baos, &empty_page, sizeof(journal_jnl_page));
                
                dns_resource_record_write(&rr, &baos);

                journal_jnl_page *page = (journal_jnl_page*)bytearray_output_stream_buffer(&baos);
                page->serial_from = soa_serial;
            }

            ++soa_count;
        }
        else
        {
            dns_resource_record_write(&rr, &baos);
        }
    }

    dns_resource_record_finalize(&rr);

    output_stream_close(&baos);
    
    return ret;
}

/******************************************************************************
 *
 * Journal Input Stream
 * This one returns and IXFR stream
 *
 ******************************************************************************/

#define JJNLISDT_TAG 0x54445349464a434a

struct journal_jnl_input_stream_data
{
    journal_jnl *jnl;
    journal_range_lock *lock;
    input_stream buffer_in;
    u8 *buffer;
    u8 *soa_record;
    u32 buffer_size;
    u16 soa_record_size;
};

typedef struct journal_jnl_input_stream_data journal_jnl_input_stream_data;

static ya_result
journal_jnl_input_stream_read(input_stream* stream, void *buffer_, u32 len)
{
    journal_jnl_input_stream_data *data = (journal_jnl_input_stream_data*)stream->data;
    u8 *buffer = (u8*)buffer_;
    
    ya_result total_bytes_read = 0;
    
    for(;;)
    {
        int n = input_stream_read(&data->buffer_in, buffer, len);
        
        if(FAIL(n))
        {
            if(total_bytes_read == 0)
            {
                total_bytes_read = n;
            }
            break;
        }
        
        total_bytes_read += n;
        
        if(n == (s32)len)
        {
            break;
        }
        
        buffer += n;
        len -= n;
        
        // read the next page
        
        if(data->lock == NULL)
        {
            break;
        }
        
        journal_jnl *jnl = data->jnl;
        
        journal_jnl_writelock(jnl);
        
        s32 position = journal_jnl_get_position_for_serial_nolock(jnl, data->lock->serial_from);

        if(position < 0)
        {
#if DEBUG
            log_debug("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: could not obtain position of first serial %u, data@%p",
                      circular_file_name(jnl->file), jnl->file, data->lock->serial_from, data);
#endif
            break;
        }

        circular_file_seek(jnl->file, position);

        journal_jnl_page page;

        if((n = circular_file_read(jnl->file, &page, sizeof(journal_jnl_page))) == sizeof(journal_jnl_page))
        {
            if(page.magic == PAGE_MAGIC)
            {
                // expected

                if(serial_ge(page.serial_from, data->lock->serial_to))
                {
                    // we reached the end (short read)
#if DEBUG
                    log_debug("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: stopped at page [%u; %u] of %u bytes, data@%p", circular_file_name(jnl->file), jnl->file, page.serial_from, page.serial_to, page.size, data);
#endif
                    journal_jnl_writeunlock(jnl);

                    break;
                }
#if DEBUG
                log_debug("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: added page [%u; %u] of %u bytes, data@%p ...", circular_file_name(jnl->file), jnl->file, page.serial_from, page.serial_to, page.size, data);
#endif
                if(data->buffer_size < page.size)
                {
                    if(data->buffer != NULL)
                    {
                        free(data->buffer);
                    }

                    data->buffer_size = (page.size + 4095) & ~4095;
                    MALLOC_OR_DIE(u8*, data->buffer, data->buffer_size, JNLISDBF_TAG);
                }

                if((n = circular_file_read(jnl->file, data->buffer, page.size)) == (s32)page.size)
                {
                    bytearray_input_stream_update(&data->buffer_in, data->buffer, page.size, FALSE);
                    bytearray_input_stream_reset(&data->buffer_in);

                    // update the locked range

                    data->lock->serial_from = page.serial_to;

                    if(data->lock->serial_from == data->lock->serial_to)
                    {
                        // this is the last page we needed to read

                        journal_jnl_lock_range_remove_nolock(jnl, data->lock);
                        data->lock = NULL;
                    }
                }
                else
                {
                    if(ISOK(n))
                    {
                        // short read, probable corruption

                        log_err("jnl: %s,%p: failed to read journal page: got %i bytes instead of %i", circular_file_name(jnl->file), jnl->file, n, page.size);
                        n = ZDB_JOURNAL_SHORT_READ;
                    }
                    else
                    {
                        log_err("jnl: %s,%p: failed to read journal page: bad magic number", circular_file_name(jnl->file), jnl->file);
                    }

                    if(total_bytes_read == 0)
                    {
                        total_bytes_read = n;
                    }

                    journal_jnl_writeunlock(jnl);
                    
                    break;
                }
            }
            else // bad magic
            {
                log_err("jnl: %s,%p: failed to read journal page header: bad magic number", circular_file_name(jnl->file), jnl->file);

                if(total_bytes_read == 0)
                {
                    total_bytes_read = ZDB_JOURNAL_SHORT_READ;
                }
                
                journal_jnl_writeunlock(jnl);

                break;
            }
        }
        else // wrong read header return value
        {
            if(ISOK(n))
            {
                // short read, probable corruption

                log_err("jnl: %s,%p: failed to read journal page header: got %i bytes instead of %i", circular_file_name(jnl->file), jnl->file, n, sizeof(journal_jnl_page));

                n = ZDB_JOURNAL_SHORT_READ;
            }
            else
            {
                log_err("jnl: %s,%p: failed to read journal page header: %r", circular_file_name(jnl->file), jnl->file, n);
            }

            if(total_bytes_read == 0)
            {
                total_bytes_read = n;
            }

            journal_jnl_writeunlock(jnl);

            break;
        }
        
        journal_jnl_writeunlock(jnl);
    }
    
    return total_bytes_read;
}

static ya_result
journal_jnl_input_stream_skip(input_stream* stream, u32 len)
{
    //journal_jnl_input_stream_data *data = (journal_jnl_input_stream_data*)stream->data;
    ya_result ret = 0;
    u8 tmp[512];
    
    while(len > 0)
    {
        int n = journal_jnl_input_stream_read(stream, tmp, MAX(len, sizeof(tmp)));
        
        if(FAIL(n))
        {
            if(ret == 0)
            {
                ret = n;
            }
            
            break;
        }
        
        ret += n;
        len -= n;
    }
    
    return ret;
}

static void
journal_jnl_input_stream_close(input_stream* stream)
{
    journal_jnl_input_stream_data *data = (journal_jnl_input_stream_data*)stream->data;
    
    input_stream_close(&data->buffer_in);
    free(data->buffer);
    if(data->lock != NULL)
    {
        journal_jnl_writelock(data->jnl);
        journal_jnl_lock_range_remove_nolock(data->jnl, data->lock);
        journal_jnl_writeunlock(data->jnl);
    }
    
    journal_release((journal*)data->jnl);
    
    ZFREE_OBJECT(data);
    
    input_stream_set_void(stream);
}

journal*
journal_jnl_input_stream_get_journal(input_stream* stream)
{
    journal_jnl_input_stream_data *data = (journal_jnl_input_stream_data*)stream->data;
    return (journal*)data->jnl;
}

static const input_stream_vtbl journal_jnl_input_stream_vtbl =
{
    journal_jnl_input_stream_read,
    journal_jnl_input_stream_skip,
    journal_jnl_input_stream_close,
    "journal_jnl_input_stream"
};

/*
 * The last_soa_rr is used for IXFR transfers (it has to be a prefix & suffix to the returned stream)
 */

static ya_result
journal_jnl_get_ixfr_stream_at_serial(journal *jh, u32 serial_from, input_stream *out_input_stream, dns_resource_record *out_last_soa_rr) // vtbl
{
    journal_jnl *jnl = (journal_jnl*)jh;
    (void)jnl;
    
    // lock the journal from the serial_from until the current serial_to
    
    journal_jnl_writelock(jnl);
    
    journal_range_lock* lock = journal_jnl_lock_range_add_nolock(jnl, serial_from);
    
    if(lock == NULL)
    {
#if DEBUG
        log_err("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: lock range [%u; %u] not in the journal (actually a debug info that I needed clearly visible)", circular_file_name(jnl->file), jnl->file, serial_from, jnl->hdr.serial_end);
#endif
        journal_jnl_writeunlock(jnl);
        return ERROR;
    }
    
    s32 position = journal_jnl_get_position_for_serial_nolock(jnl, serial_from);

#if DEBUG
    log_debug("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: lock range [%u; %u], position=%i", circular_file_name(jnl->file), jnl->file, serial_from, jnl->hdr.serial_end, position);
    debug_log_stacktrace(MODULE_MSG_HANDLE, MSG_DEBUG, "jnl");
#endif
    
    if(position < 0)
    {
#if DEBUG
        log_err("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: could not get position for serial %u", circular_file_name(jnl->file), jnl->file, serial_from);
#endif
        journal_jnl_lock_range_remove_nolock(jnl, lock);
        journal_jnl_writeunlock(jnl);
        return ERROR;
    }
    
    // start reading ...
    
    journal_jnl_input_stream_data *data;
    
    ZALLOC_OBJECT_OR_DIE(data, journal_jnl_input_stream_data, JNLISDTA_TAG);
    journal_acquire((journal*)jnl);
    data->jnl = jnl;
    data->lock = lock;
    
    bytearray_input_stream_init(&data->buffer_in, NULL, 0, FALSE);
    data->buffer = NULL;
    data->buffer_size = 0;
    data->soa_record = NULL;
    data->soa_record_size = 0;
    
    out_input_stream->data = data;
    out_input_stream->vtbl = &journal_jnl_input_stream_vtbl;
    
    circular_file_seek(jnl->file, position);
    
    journal_jnl_page page;
    
    ya_result ret;
    
    if(ISOK(ret = circular_file_read(jnl->file, &page, sizeof(journal_jnl_page))))
    {
        if(page.magic == PAGE_MAGIC)
        {
            // expected
            
            assert(page.serial_from == serial_from);
            
            if(data->buffer_size < page.size)
            {
                if(data->buffer != NULL)
                {
                    free(data->buffer);
                }
                
                data->buffer_size = (page.size + 4095) & ~4095;
                MALLOC_OR_DIE(u8*, data->buffer, data->buffer_size, JNLISDBF_TAG);
            }
            
            if((ret = circular_file_read(jnl->file, data->buffer, page.size)) == (s32)page.size)
            {
                bytearray_input_stream_update(&data->buffer_in, data->buffer, page.size, FALSE);
                bytearray_input_stream_reset(&data->buffer_in); // puts the read pointer at the beginning
                data->buffer_size = page.size;

#if DEBUG
                log_debug("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: added page [%u; %u] of %u bytes, data@%p", circular_file_name(jnl->file), jnl->file, page.serial_from, page.serial_to, page.size, data);
#endif
            
                if(out_last_soa_rr != NULL)
                {
                    // read the SOA

                    input_stream is;
                    circular_file_seek(jnl->file, jnl->hdr.last_soa_offset);
                    circular_file_input_stream_noclose_init(&is, jnl->file);
                    ret = dns_resource_record_read(out_last_soa_rr, &is);
                    input_stream_close(&is);

                    if(FAIL(ret))
                    {
#if DEBUG
                        log_err("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: could not read last SOA: %r", circular_file_name(jnl->file), jnl->file, ret);
#endif
                        // annoying goto to the error handling
                        goto journal_jnl_get_ixfr_stream_at_serial_error;
                    }
                }
            
                // update the locked range

                data->lock->serial_from = page.serial_to;

                if(data->lock->serial_from == data->lock->serial_to)
                {
                    // this is the last page we needed to read

                    journal_jnl_lock_range_remove_nolock(jnl, data->lock);
                    data->lock = NULL;
                }
#if DEBUG
                log_debug("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: success", circular_file_name(jnl->file), jnl->file);
#endif
                journal_jnl_writeunlock(jnl);

                return SUCCESS;
            }
            else
            {
                if(ISOK(ret))
                {
                    // short read, probable corruption

                    log_err("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: got %i bytes instead of %i", circular_file_name(jnl->file), jnl->file, ret, page.size);
                    //ret = /**/ ERROR;
                }
                else
                {
                    log_err("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: error reading page: %r", circular_file_name(jnl->file), jnl->file, ret);
                }
            }
        }
#if DEBUG
        else
        {
            log_err("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: unexpected magic %08x", circular_file_name(jnl->file), jnl->file, position, page.magic);
        }
#endif
    }
#if DEBUG
    else
    {
        log_err("jnl: %s,%p: journal_jnl_get_ixfr_stream_at_serial: could not read page at position %u: %r", circular_file_name(jnl->file), jnl->file, position, ret);
    }
#endif
    
journal_jnl_get_ixfr_stream_at_serial_error:
    input_stream_close(&data->buffer_in);
    free(data->buffer);
    journal_jnl_lock_range_remove_nolock(jnl, data->lock);
    ZFREE_OBJECT(data);
    
    journal_jnl_writeunlock(jnl);
    journal_release((journal*)jnl);
    
    return ERROR;
}

static ya_result
journal_jnl_get_first_serial(journal *jh, u32 *serial) // vtbl
{
    ya_result ret = ZDB_JOURNAL_NOT_INITIALISED;
    journal_jnl *jnl = (journal_jnl*)jh;
    
    journal_jnl_readlock(jnl);

    if(jnl->hdr.flags & JOURNAL_JNL_FLAGS_INITIALISED)
    {
        if(serial != NULL)
        {
            *serial = jnl->hdr.serial_begin;
            ret = SUCCESS;
        }
    }
    
#if DEBUG
    log_debug("jnl: %s,%p: returning first serial as %u", circular_file_name(jnl->file), jnl->file, jnl->hdr.serial_begin);
#endif
    
    journal_jnl_readunlock(jnl);

    return ret;
}

static ya_result
journal_jnl_get_last_serial(journal *jh, u32 *serial) // vtbl
{
    ya_result ret = ZDB_JOURNAL_NOT_INITIALISED;
    journal_jnl *jnl = (journal_jnl*)jh;
    
    journal_jnl_readlock(jnl);

    if(jnl->hdr.flags & JOURNAL_JNL_FLAGS_INITIALISED)
    {
        if(serial != NULL)
        {
            *serial = jnl->hdr.serial_end;
            ret = SUCCESS;
        }
    }
    
#if DEBUG
    log_debug("jnl: %s,%p: returning last serial as %u", circular_file_name(jnl->file), jnl->file, jnl->hdr.serial_end);
#endif
    
    journal_jnl_readunlock(jnl);

    return ret;
}

static ya_result
journal_jnl_get_serial_range(journal *jh, u32 *serial_start, u32 *serial_end) // vtbl
{
    ya_result ret = ZDB_JOURNAL_NOT_INITIALISED;
    journal_jnl *jnl = (journal_jnl*)jh;
    
    journal_jnl_readlock(jnl);

    if(jnl->hdr.flags & JOURNAL_JNL_FLAGS_INITIALISED)
    {
        if(serial_start != NULL)
        {
            *serial_start = jnl->hdr.serial_begin;
            ret = SUCCESS;
        }

        if(serial_end != NULL)
        {
            *serial_end = jnl->hdr.serial_end;
            ret = SUCCESS;
        }
    }
    
#if DEBUG
    log_debug("jnl: %s,%p: returning serial range %u to %u", circular_file_name(jnl->file), jnl->file, jnl->hdr.serial_begin, jnl->hdr.serial_end);
#endif
    
    journal_jnl_readunlock(jnl);

    return ret;
}

static ya_result
journal_jnl_truncate_to_size(journal *jh, u32 size_) // vtbl
{
    journal_jnl *jnl = (journal_jnl*)jh;
    (void)jnl;
    
    if(size_ == 0)
    {
        journal_jnl_writelock(jnl);
        
#if DEBUG
        log_debug("jnl: %s,%p: truncating to 0", circular_file_name(jnl->file), jnl->file);
#endif
        
        if(list_dl_size(&jnl->range_lock) == 0)
        {
            // change range
            // clear lists
            // delete file
            /*
            volatile struct journal_vtbl *vtbl;
            volatile list_dl_node_s mru_node;
            volatile int rc;
            volatile unsigned int _forget:1,_mru:1;
            */
            /* The journal is not like a stream, it's a full standalone entity always returned as a pointer.
             * So the handler can do whatever it wants after "mru"
             */
            
            circular_file_unlink(jnl->file);
        }

        journal_jnl_writeunlock(jnl);

        return SUCCESS;
    }
    else
    {
#if DEBUG
        log_info("jnl: %s,%p: truncating to %u not supported (only 0 is)", circular_file_name(jnl->file), jnl->file, size_);
#endif
        return ZDB_JOURNAL_FEATURE_NOT_SUPPORTED;
    }
}

static ya_result
journal_jnl_truncate_to_serial(journal *jh, u32 serial_) // vtbl
{
    journal_jnl *jnl = (journal_jnl*)jh;
    union journal_jnl_entry entry;
    ya_result ret = SUCCESS;
        
    journal_jnl_writelock(jnl);
    
#if DEBUG
    log_debug("jnl: %s,%p: truncating to serial %u", circular_file_name(jnl->file), jnl->file, serial_);
#endif
    
    while(serial_lt(jnl->hdr.serial_begin, serial_))
    {
        circular_file_seek(jnl->file, 0);
        
        if(ISOK(ret = circular_file_read(jnl->file, &entry, sizeof(u32))))
        {
            switch(entry.magic)
            {
                case CHPT_MAGIC:   
                {
                    if(ISOK(ret = circular_file_read(jnl->file, &entry, sizeof(entry.chapter) - sizeof(u32))))
                    {
                        if(serial_le(entry.chapter.serial_to, serial_))
                        {                        
                            if(ISOK(ret = journal_jnl_shift_nolock(jnl, entry.chapter.relative_next + sizeof(entry.chapter))))
                            {
                            }
                        }
                        else
                        {
                            if(ISOK(ret = journal_jnl_shift_nolock(jnl, sizeof(entry.chapter))))
                            {
                            }
                        }
                    }
                    
                    break;
                }
                case PAGE_MAGIC:
                {
                    if(ISOK(ret = circular_file_read(jnl->file, &entry, sizeof(entry.page) - sizeof(u32))))
                    {
                        if(ISOK(ret = journal_jnl_shift_nolock(jnl, entry.page.size + sizeof(entry.page))))
                        {
                        }
                    }
                    break;
                }
                default:
                {
                    break;
                }
            }
        }
        
        if(FAIL(ret))
        {
            break;
        }
    }
    
#if DEBUG
    if(FAIL(ret))
    {
        log_err("jnl: %s,%p: truncating to serial %u failed: %r", circular_file_name(jnl->file), jnl->file, serial_, ret);
    }
#endif
    
    journal_jnl_writeunlock(jnl);
        
    return ret;
}

/**
 *
 * @param jnl
 * @return
 */

static ya_result
journal_jnl_reopen(journal *jh) // vtbl
{
#if DEBUG
    journal_jnl *jnl = (journal_jnl*)jh;
    journal_jnl_writelock(jnl);
    log_debug("jnl: %s,%p: reopen (no operation)", circular_file_name(jnl->file), jnl->file);
    journal_jnl_writeunlock(jnl);
#else
    (void)jh;
#endif
    
    return SUCCESS;
}

static void
journal_jnl_flush(journal *jh) // vtbl
{
    journal_jnl *jnl = (journal_jnl*)jh;

    journal_jnl_writelock(jnl);
#if DEBUG
    log_debug("jnl: %s,%p: flush", circular_file_name(jnl->file), jnl->file);
#endif    
    journal_jnl_header_flush_nolock(jnl);
    
    journal_jnl_writeunlock(jnl);
}

static ya_result
journal_jnl_close(journal *jh) // vtbl
{
    journal_jnl *jnl = (journal_jnl*)jh;

    log_debug("jnl: %s,%p: close", circular_file_name(jnl->file), jnl->file);

    if(jnl->file != NULL)
    {
        journal_jnl_writelock(jnl);
        
        yassert(jnl->file != NULL);
        
        journal_jnl_header_flush_nolock(jnl);
        circular_file_close(jnl->file);
        jnl->file = NULL;
        
        journal_jnl_writeunlock(jnl);
    }
#if DEBUG
    else
    {
        log_err("jnl: %s,%p: close of an already closed file", circular_file_name(jnl->file), jnl->file);
    }
#endif

    return SUCCESS;
}

static void
journal_jnl_log_dump_nolock(journal *jh) // vtbl
{
    journal_jnl *jnl = (journal_jnl*)jh;
    
    u32 sf = 0;
    u32 st = 0;
    
    journal_jnl_lock_get_serial_range_nolock(jnl, &sf, &st);
    
    log_debug3("jnl: %s,%p: [%u; %u] '%s' (%p) lck=%i rc=%i, %u locks: {%u, %u}",
            circular_file_name(jnl->file), jnl->file,
            jnl->hdr.serial_begin, jnl->hdr.serial_end,
            circular_file_name(jnl->file), jnl->file,
            jnl->mtx.owner, jnl->mtx.count,
            list_dl_size(&jnl->range_lock), sf, st
            );
}

static void
journal_jnl_log_dump(journal *jh) // vtbl
{
    journal_jnl *jnl = (journal_jnl*)jh;
    journal_jnl_readlock(jnl);
    journal_jnl_log_dump_nolock(jh);
    journal_jnl_readunlock(jnl);
}


static ya_result
journal_jnl_get_domain(journal *jh, u8 *out_domain) // vtbl
{
    journal_jnl *jnl = (journal_jnl*)jh;

    // don't: journal_jnl_readlock(jnl); as the field is constant until the destruction of the journal

    dnsname_copy(out_domain, jnl->origin);
    return SUCCESS;
}

static const u8 *
journal_jnl_get_domain_const(const journal *jh)
{
    const journal_jnl *jnl = (const journal_jnl*)jh;
    return jnl->origin;
}

static void
journal_jnl_destroy(journal *jh) // vtbl
{
    journal_jnl *jnl = (journal_jnl*)jh;
    journal_jnl_free_default(jnl);
}

static void
journal_jnl_minimum_serial_update(journal *jh, u32 stored_serial)
{
    journal_jnl *jnl = (journal_jnl*)jh;
    
    journal_jnl_writelock(jnl);
    
#if DEBUG
    log_debug3("jnl: %s,%p: setting minimal safe serial to %u", circular_file_name(jnl->file), jnl->file, stored_serial);
#endif
    
    jnl->safe_serial = stored_serial;
    
    journal_jnl_writeunlock(jnl);
}

static void
journal_jnl_maximum_size_update(journal *jh, u32 maximum_size)
{
    journal_jnl *jnl = (journal_jnl*)jh;
    journal_jnl_writelock(jnl);
    
#if DEBUG
    log_debug3("jnl: %s,%p: allowing file to grow up to %u bytes", circular_file_name(jnl->file), jnl->file, maximum_size);
#endif
    
    circular_file_grow(jnl->file, maximum_size);
    
    journal_jnl_writeunlock(jnl);
}

static void
journal_jnl_limit_size_update(journal *jh, u32 limit_size)
{
    journal_jnl *jnl = (journal_jnl*)jh;
    journal_jnl_writelock(jnl);

#if DEBUG
    log_debug3("jnl: %s,%p: limiting file to grow up to %u bytes", circular_file_name(jnl->file), jnl->file, limit_size);
#endif

    jnl->size_limit = limit_size;

    journal_jnl_writeunlock(jnl);
}

/*******************************************************************************
 *
 * vtbl handling functions
 *
 ******************************************************************************/

struct journal_vtbl journal_jnl_vtbl =
{
    journal_jnl_get_format_name,
    journal_jnl_get_format_version,
    journal_jnl_reopen,
    journal_jnl_flush,
    journal_jnl_close,
    journal_jnl_append_ixfr_stream,
    journal_jnl_get_ixfr_stream_at_serial,
    journal_jnl_get_first_serial,
    journal_jnl_get_last_serial,
    journal_jnl_get_serial_range,
    journal_jnl_truncate_to_size,
    journal_jnl_truncate_to_serial,
    journal_jnl_log_dump,
    journal_jnl_get_domain,
    journal_jnl_destroy,
    journal_jnl_get_domain_const,
    journal_jnl_minimum_serial_update,
    journal_jnl_maximum_size_update,
    journal_jnl_limit_size_update,
    JOURNAL_CLASS_NAME
};

static journal_jnl*
journal_jnl_alloc_default(const u8 *origin, const char *filename)
{
    (void)filename;

    journal_jnl *jnl;
    ZALLOC_OBJECT_OR_DIE(jnl, journal_jnl, JRNLJNL_TAG);
    ZEROMEMORY(jnl, sizeof(journal_jnl));
    jnl->vtbl = &journal_jnl_vtbl;
    jnl->mru_node.data = jnl;
    jnl->file = NULL;
    jnl->origin = dnsname_zdup(origin);
    jnl->size_limit = MAX_U32;
    list_dl_init(&jnl->chapters);
    list_dl_init(&jnl->range_lock);
    shared_group_mutex_init(&jnl->mtx, &journal_shared_mtx, "journal-jnl");
    journal_jnl_page_cache_init(jnl);
    
    return jnl;
}

static void
journal_jnl_free_default(journal_jnl* jnl)
{
#if DEBUG
    journal_jnl_writelock(jnl);
    yassert(jnl->rc == 0);
    log_debug3("jnl: %s,%p: destroy", circular_file_name(jnl->file), jnl->file);
    journal_jnl_writeunlock(jnl);
#endif

    for(;;)
    {
        journal_jnl_chapter_entry *data = (journal_jnl_chapter_entry*)list_dl_remove_first(&jnl->chapters);

        if(data == NULL)
        {
            break;
        }

        ZFREE_OBJECT(data);
    }

    journal_jnl_page_cache_clear(jnl);

    if(jnl->file != NULL)
    {
        circular_file_close(jnl->file);
        jnl->file = NULL;
    }

    dnsname_zfree(jnl->origin);
    shared_group_mutex_destroy(&jnl->mtx);

#if DEBUG
    memset(jnl, 0xfe, sizeof(journal_jnl));
    jnl->_mru = FALSE;
#endif

    ZFREE_OBJECT(jnl);
}

/**
 * The caller guarantees not to call this on an already opened journal
 *
 * Should not be called directly (only by journal_* functions.
 *
 * Opens or create a journal handling structure.
 * If the journal did not exist, the structure is returned without a file opened
 *
 * @param jh
 * @param origin
 * @param workingdir
 * @param create
 *
 * @return
 */

ya_result
journal_jnl_open_file(journal **jhp, const char *filename, const u8* origin, bool create)
{
    // CFJ_PAGE_CACHE ->
    if(!journal_initialized)
    {
        journal_file_pool = file_pool_init_ex("jnl-journal-file-pool", journal_file_pool_size, 65536);

        if(journal_file_pool == NULL)
        {
            return INVALID_STATE_ERROR;
        }

        shared_group_shared_mutex_init_recursive(&journal_shared_mtx);

        journal_initialized = TRUE;
    }

    journal_jnl *jnl = NULL;
    ya_result ret;

    if(file_exists(filename) || create)
    {
        // instantiate and open the journal

        ret = journal_jnl_init_from_file(&jnl, origin, filename, create);

        if(ISOK(ret))
        {
            log_debug("jnl: %{dnsname}: opened %s", origin, filename);
        }
        else
        {
            if(ZDB_JOURNAL_SHOULD_NOT_BE_USED(ret))
            {
                log_err("jnl: %{dnsname}: the journal file %s appears to be corrupted: %r", origin, filename, ret);
//#if DEBUG
                char tmp[PATH_MAX];
                snformat(tmp, sizeof(tmp), "%s.%llu.bad", filename, timeus());
                log_err("jnl: %{dnsname}: putting aside as %s (DEBUG)", origin, filename);
                if(rename(filename, tmp) < 0)
                {
                    log_err("jnl: %{dnsname}: failed to preserve the corrupted journal by renaming '%s' to '%s': %r", origin, filename, tmp, ERRNO_ERROR);
                    if(unlink(filename) < 0)
                    {
                        int err = ERRNO_ERROR;
                        log_err("jnl: %{dnsname}: failed to delete the corrupted journal: %r", origin, filename, err);
                        return err;
                    }
                }
//#else
                // destroying journal
                //log_err("jnl: %{dnsname}: deleting %s", origin, filename);
                //unlink(filename);
//#endif
            }

            if(create)
            {
                log_err("jnl: %{dnsname}: failed to open %s: %r", origin, filename, ret);
            }
            else
            {
                log_debug("jnl: %{dnsname}: failed to open %s: %r", origin, filename, ret);
            }

            if(jnl != NULL)
            {
                journal_jnl_destroy((journal*)jnl);
#if DEBUG
                log_debug("jnl: %{dnsname}: journal file cannot be opened/created", origin);
#endif
            }

            return ZDB_ERROR_ICMTL_NOTFOUND;
        }

#if DEBUG
        log_debug("jnl: %{dnsname}: journal opened", origin);
#endif
        *jhp = (journal*)jnl;

        return SUCCESS;
    }
    else
    {
#if DEBUG
        log_debug("jnl: %{dnsname}: journal file not found", origin);
#endif
        return ZDB_ERROR_ICMTL_NOTFOUND;
    }
}

/**
 * The caller guarantees not to call this on an already opened journal
 *
 * Should not be called directly (only by journal_* functions.
 *
 * Opens or create a journal handling structure.
 * If the journal did not exist, the structure is returned without a file opened
 *
 * @param jh
 * @param origin
 * @param workingdir
 * @param create
 *
 * @return
 */

ya_result
journal_jnl_open(journal **jhp, const u8* origin, const char *workingdir, bool create)
{
    // CFJ_PAGE_CACHE <-

    ya_result ret;

    *jhp = NULL;

    // generate the file name

    char filename[PATH_MAX];

    if((jhp == NULL) || (origin == NULL) || (workingdir == NULL))
    {
        return ZDB_JOURNAL_WRONG_PARAMETERS;
    }

#if DEBUG
    log_debug("jnl: trying to open journal for %{dnsname} in '%s'", origin, workingdir);
#endif

    /* get the soa of the loaded zone */

    if(origin[0] != '\0')
    {
        if(FAIL(ret = snformat(filename, sizeof(filename), JNL_WIRE_FILE_FORMAT, workingdir, origin)))
        {
#if DEBUG
            log_debug("jnl: %{dnsname}: journal file name is too long", origin);
#endif
            return ret;
        }
    }
    else
    {
        if(FAIL(ret = snformat(filename, sizeof(filename), JNL_WIRE_ROOT_ZONE_FORMAT, workingdir)))
        {
#if DEBUG
            log_debug("jnl: %{dnsname}: journal file name is too long", JNL_WIRE_ROOT_NAME);
#endif
            return ret;
        }
    }

    ret = journal_jnl_open_file(jhp, filename, origin, create);

    return ret;
}

void
journal_jnl_finalize()
{
    file_pool_finalize(journal_file_pool);
    journal_file_pool = 0;
}

/** @} */

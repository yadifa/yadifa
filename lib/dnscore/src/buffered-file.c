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

/** @defgroup streaming Streams
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#define __BUFFERED_FILE_C__ 1

#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include "dnscore/ptr_set.h"
#include "dnscore/mutex.h"
#include "dnscore/list-dl.h"
#include "dnscore/fdtools.h"
#include "dnscore/logger.h"
#include "dnscore/file.h"
#include "dnscore/u64_set.h"
#include "dnscore/timems.h"

#define BUFFERED_STATISTICS_ON_STDOUT 0
#define IGNORE_COST 0

#if BUFFERED_STATISTICS_ON_STDOUT
#include "dnscore/format.h"
#endif

#define MODULE_MSG_HANDLE g_system_logger

#define BUFFERED_FILE_TAG           0x454c4946524642    // BFRFILE_TAG
#define BUFFERED_FILE_PAGE_TAG     0x50454c4946524642   // BFRFILEP_TAG
#define BUFFERED_FILE_CACHE_TAG     0x43454c4946524642   // BFRFILEC_TAG

#define PAGE_USE_OLD_ENOUGH_VALUE_US 500000LL // 0.5s

struct buffered_file_t_;

typedef struct buffered_file_t_* buffered_file_t;

struct buffered_file_page
{
    struct list_dl_node_s *next;
    struct list_dl_node_s *prev;
    
    buffered_file_t file;
    u8 *buffer;
    s64 position;   // position of the page in the file (multiple of page granularity)
    s64 timestamp;  // last use (so it does fnot exit the MRU too fast except to be given to the same id)
    s64 cost;       // the time in us that was required to build that page (IOs)
    s32 size;
    s32 written_from; // if written_from <= written_to then the page needs to be written
    s32 written_to_plus_one;
    s32 read_to;    // number of bytes in that page (usually = size unless it's the last one of the file)
    int index;      // for sorting
    bool in_mru;
};

typedef struct buffered_file_page buffered_file_page;

typedef struct buffered_file_page* buffered_file_page_t;

struct buffered_file_page_set
{
    group_mutex_t mtx;
    u64_set offset_to_page;
};

typedef struct buffered_file_page_set buffered_file_page_set;

struct buffered_file_cache_t_
{
    group_mutex_t mtx;
    ptr_set id_to_page_set;
    void *page_pool;
    size_t page_pool_size;
    s64 granularity_mask;
    list_dl_s mru;
    list_dl_s avail;
    const char * name;
    s32 rc;
    u8 log2_page_size;
    bool source_is_mmap;
    
#if BUFFERED_STATISTICS_ON_STDOUT
    u32 cache_acquired;
    u32 cache_released;
    u32 cache_reclaimed;
    u32 cache_denied;
    u32 cache_denied_nolock;
    u32 cache_denied_cost;
    u32 cache_denied_writefail;
#endif
};

typedef struct buffered_file_cache_t_* buffered_file_cache_t;

struct buffered_file_t_
{
    const struct file_vtbl *vtbl;
    file_t buffered_file;               // the file covered by the cache
    buffered_file_cache_t page_cache;            // the cache used for this file
    buffered_file_page_set page_set;    // the set of pages covering the file (offset -> page)
    s64 position_current;               // the position where the file pointer really is
    s64 position_requested;             // the position where the file pointer is supposed to be
    s64 size;                           // the size of the file
};

#include <dnscore/buffered-file.h>      // just to match the function signatures

static void
buffered_file_cache_page_init(buffered_file_page_t page, buffered_file_t f, u8 *buffer, s32 size, int index)
{
    assert((buffer != NULL) && (size > 0));
        
    page->file = f;
    page->buffer = buffer;
    page->position = 0;
    page->timestamp = 0;
    page->cost = 0;
    page->written_from = size;
    page->written_to_plus_one = 0;
    page->read_to = 0;
    page->size = size;
    page->index = index;
    page->in_mru = FALSE;
}

static buffered_file_page_t
buffered_file_cache_page_new_instance(u8 *buffer, s32 size, int index)
{
    buffered_file_page_t page;
    ZALLOC_OBJECT_OR_DIE(page, struct buffered_file_page, BUFFERED_FILE_PAGE_TAG);
    buffered_file_cache_page_init(page, NULL, buffer, size, index);
    return page;
}

static void
buffered_file_cache_page_update(buffered_file_page_t page, buffered_file_t f, s64 position)
{
    page->file = f;
    page->position = position;
    page->timestamp = 0;
    page->cost = 0;
    page->written_from = page->size;
    page->written_to_plus_one = 0;
    page->read_to = 0;
}

buffered_file_cache_t
buffered_file_cache_new_instance(const char* name, u32 count, u8 log2_granularity, bool use_mmap)
{
    if((log2_granularity < 4) || (log2_granularity > 20)) // 16 bytes to 1 MB
    {
        return NULL;
    }
    
    size_t page_size = 1LLU << log2_granularity;
    size_t total_size = page_size * count;
    u8 *pages;
    
    if(use_mmap)
    {
        pages = (u8*)mmap(NULL, total_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        
        if(pages == (u8*)MAP_FAILED)
        {
            return NULL;
        }
    }
    else
    {
        MALLOC_OBJECT_ARRAY(pages, u8, total_size, BUFFERED_FILE_CACHE_TAG);
        //pages = (u8*)malloc(total_size);
        
        if(pages == NULL)
        {
            return NULL;
        }
    }
    
    buffered_file_cache_t fc;
    
    ZALLOC_OBJECT_OR_DIE(fc, struct buffered_file_cache_t_, FILE_CACHE_TAG);
    
#if BUFFERED_STATISTICS_ON_STDOUT
    memset(fc, 0, sizeof(*fc));
#endif
    
    group_mutex_init(&fc->mtx);
    fc->page_pool = pages;
    fc->page_pool_size = total_size;
    fc->granularity_mask = page_size - 1;
    list_dl_init(&fc->mru);
    list_dl_init(&fc->avail);
    fc->name = strdup(name);
    fc->source_is_mmap = use_mmap;
    fc->log2_page_size = log2_granularity;
    fc->rc = 1;
    
    for(u32 i = 0; i < count; ++i)
    {
        list_dl_append_node(&fc->avail, (list_dl_node_s*)buffered_file_cache_page_new_instance(&pages[page_size * i], page_size, i));
    }

#if DEBUG
    log_info("buffered_file_cache_new_instance('%s', %u, %hhu, %i) = %p", STRNULL(name), count, log2_granularity, use_mmap, fc);
#endif
    
    return fc;
}

static void
buffered_file_cache_acquire(buffered_file_cache_t fc)
{
    group_mutex_lock(&fc->mtx, GROUP_MUTEX_WRITE);
    ++fc->rc;
#if DEBUG
    log_info("buffered_file_cache_acquire(%p '%s') = %i", fc, STRNULL(fc->name), fc->rc);
#endif
    group_mutex_unlock(&fc->mtx, GROUP_MUTEX_WRITE);
}

static void
buffered_file_cache_release(buffered_file_cache_t fc)
{
    group_mutex_lock(&fc->mtx, GROUP_MUTEX_WRITE);
    s32 n = --fc->rc;
    group_mutex_unlock(&fc->mtx, GROUP_MUTEX_WRITE);

#if DEBUG
    log_info("buffered_file_cache_release(%p '%s') = %i", fc, STRNULL(fc->name), n);
#endif
    
#if BUFFERED_STATISTICS_ON_STDOUT
    formatln("cache: acquired=%u released=%u reclaimed=%u denied=%u denied-nolock=%u denied-cost=%u denied-writefail=%u",
            fc->cache_acquired, fc->cache_released, fc->cache_reclaimed, fc->cache_denied,
            fc->cache_denied_nolock, fc->cache_denied_cost, fc->cache_denied_writefail);
    flushout();
#endif
    
    if(n == 0)
    {
        // the mru should be empty
        // the avail should be full
        
        if(fc->source_is_mmap)
        {
            munmap(fc->page_pool, fc->page_pool_size);
        }
        else
        {
            free(fc->page_pool);
        }
    }
}

void
buffered_file_cache_delete(buffered_file_cache_t fc)
{
#if DEBUG
    group_mutex_lock(&fc->mtx, GROUP_MUTEX_READ);
    if(fc->rc > 1)
    {
        log_warn("buffered_file_cache_delete(%p '%s') rc=%i", fc, STRNULL(fc->name), fc->rc);
    }
    group_mutex_unlock(&fc->mtx, GROUP_MUTEX_READ);
#endif
    buffered_file_cache_release(fc);
}

/**
 * Looks for a victim page among the ones available.
 * If there are none, tries to take the last page of the MRU from the file using it (flushing it if needed).
 * This last step can fail if the page is too young based on it's IO cost, or if the page set is locked.
 * 
 * @param fc
 * 
 * @return a page or NULL if none were available
 */

static buffered_file_page_t
buffered_file_cache_reclaim_page_nolock(buffered_file_cache_t fc)
{
    // if the least recently used has been used more than (e.g.) 0.5 seconds ago, try to reclaim it
    // if it cannot (locked) give up
    // it it can, flush it, take it from its current user and return it
    
    buffered_file_page_t page = (buffered_file_page_t)list_dl_last_node(&fc->mru);
    
    if(page == NULL)
    {
        return NULL;
    }
    
    if(group_mutex_trylock(&page->file->page_set.mtx, GROUP_MUTEX_WRITE))
    {
        s64 now = timeus();
#if !IGNORE_COST
        if(now - page->timestamp > page->cost)
#else
        if(TRUE)
#endif
        {
            s32 page_content = page->written_to_plus_one - page->written_from;
            
            if(page_content > 0)
            {
                // flush page
                /*
                s64 stored_position = page->file->position_current;
                */
                s64 write_position = page->position + page->written_from;
                write_position = page->file->buffered_file->vtbl->seek(page->file->buffered_file, write_position, SEEK_SET);
                if(ISOK(write_position))
                {
                    page->file->position_current = write_position;
                    
                    s32 ret = page->file->buffered_file->vtbl->write(page->file->buffered_file, &page->buffer[page->written_from], page_content);
                    if(ISOK(ret) && (ret == page_content))
                    {
                        page->file->position_current += ret;
                        
                        // page flushed
                        u64_set_delete(&page->file->page_set.offset_to_page, page->position);
                        
                        if(page->in_mru)
                        {
                            list_dl_remove_node(&fc->mru, (list_dl_node_s*)page);
                            page->in_mru = FALSE;
                        }
                        
#if BUFFERED_STATISTICS_ON_STDOUT
                        ++fc->cache_reclaimed;
#endif
                        /*
                        s64 restored_position = page->file->buffered_file->vtbl->seek(page->file->buffered_file, stored_position, SEEK_SET);
                        assert(restored_position == stored_position);
                        */
                        
                        group_mutex_unlock(&page->file->page_set.mtx, GROUP_MUTEX_WRITE);
                    }
                    else // could not properly write it
                    {
#if BUFFERED_STATISTICS_ON_STDOUT
                        ++fc->cache_denied_writefail;
#endif
                        /*
                        s64 restored_position = page->file->buffered_file->vtbl->seek(page->file->buffered_file, stored_position, SEEK_SET);
                        assert(restored_position == stored_position);
                        */
                        
                        group_mutex_unlock(&page->file->page_set.mtx, GROUP_MUTEX_WRITE);
                        
                        page = NULL;
                    }
                }
                else
                {
                    group_mutex_unlock(&page->file->page_set.mtx, GROUP_MUTEX_WRITE);
                    page = NULL;
                }
            }
            else
            {
                // page does not need to be flushed
                u64_set_delete(&page->file->page_set.offset_to_page, page->position);
                group_mutex_unlock(&page->file->page_set.mtx, GROUP_MUTEX_WRITE);
            }
        }
        else
        {
#if BUFFERED_STATISTICS_ON_STDOUT
            ++fc->cache_denied_cost;
#endif
            group_mutex_unlock(&page->file->page_set.mtx, GROUP_MUTEX_WRITE);
            page = NULL;
        }
    }
#if BUFFERED_STATISTICS_ON_STDOUT
    else
    {
        ++fc->cache_denied_nolock;
    }
#endif
    
    return page;
}




/**
 * 
 * Returns one page set for a file at a given position
 * 
 * @param fc
 * @param file
 * @param position
 * @return 
 */

static buffered_file_page_t
buffered_file_cache_acquire_page(buffered_file_cache_t fc, buffered_file_t file, s64 position)
{
    buffered_file_page_t page;
    
    group_mutex_lock(&fc->mtx, GROUP_MUTEX_WRITE);
        
    if(list_dl_size(&fc->avail) == 0)
    {
        // find a victim
        
        if((page = buffered_file_cache_reclaim_page_nolock(fc)) != NULL)
        {
            buffered_file_cache_page_update(page, file, position);
        }
    }
    else
    {
        // take the first available one
        
        page = (buffered_file_page_t)list_dl_remove_first_node(&fc->avail);
        buffered_file_cache_page_update(page, file, position);
    }
    
#if BUFFERED_STATISTICS_ON_STDOUT
    if(page != NULL)
    {
        ++fc->cache_acquired;
    }
    else
    {
        ++fc->cache_denied;
    }
#endif
    
    group_mutex_unlock(&fc->mtx, GROUP_MUTEX_WRITE);
    
    return page;
}

void
buffered_file_cache_release_page(buffered_file_cache_t fc, buffered_file_page_t page)
{
    //u64_set_delete(page->file->page_set.offset_to_page, page->position);
    group_mutex_lock(&fc->mtx, GROUP_MUTEX_WRITE);
    
#if BUFFERED_STATISTICS_ON_STDOUT
    ++fc->cache_released;
#endif
    
    if(page->in_mru)
    {
        list_dl_remove_node(&fc->mru, (list_dl_node_s*)page);
        page->in_mru = FALSE;
    }
    page->file = NULL;
    list_dl_insert_node(&fc->avail, (list_dl_node_s*)page);
    group_mutex_unlock(&fc->mtx, GROUP_MUTEX_WRITE);
}

void
buffered_file_cache_set_page_as_most_recently_used(buffered_file_cache_t fc, buffered_file_page_t page)
{
    group_mutex_lock(&fc->mtx, GROUP_MUTEX_WRITE);
    if(page->in_mru)
    {
        list_dl_remove_node(&fc->mru, (list_dl_node_s*)page);
    }
    list_dl_insert_node(&fc->mru, (list_dl_node_s*)page);
    page->in_mru = TRUE;
    group_mutex_unlock(&fc->mtx, GROUP_MUTEX_WRITE);
}

struct io_range
{
    s64 from;
    s64 to;
    buffered_file_page_t page;
};

typedef struct io_range io_range;


static ssize_t
buffered_file_read(file_t f, void *buffer_, ssize_t size)
{
    buffered_file_t bf = (buffered_file_t)f;
    
    if(bf->buffered_file == NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    // see if wanted position (which is where we will be reading from) page is in the cache
    // if not, move to position, acquire the page and update its content with the file
    //   if page acquisition is not possible, do a direct read
    // from the page, copy the bytes to the buffer
    
    u8 *buffer = (u8*)buffer_;
    u8* buffer_org = buffer;
    
    buffered_file_page_t page = NULL;
    
    s64 page_position = bf->position_requested & ~bf->page_cache->granularity_mask;
    s64 in_page_from = bf->position_requested & bf->page_cache->granularity_mask;
    
    // we know the page_position and the position in the page
    
    group_mutex_lock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
    
    for(;;) // until there are no more bytes to read
    {
        // see if the page is cached
        
        u64_node *node = u64_set_find(&bf->page_set.offset_to_page, page_position);

        if(node == NULL)
        {
            // the page is not cached
            
            group_mutex_unlock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
            
            // acquire a page to use for caching
            
            page = buffered_file_cache_acquire_page(bf->page_cache, bf, page_position);
            
            if(page == NULL)
            {
                // case where the cache is over used so taking a page would be counter-productive by making the cache a glorified intermediary buffer
                
                if(bf->position_current != bf->position_requested)
                {
                    // move into the file at the requested position

                    ssize_t ret = bf->buffered_file->vtbl->seek(bf->buffered_file, bf->position_requested, SEEK_SET);

                    if(FAIL(ret))
                    {
                        ssize_t total = buffer - buffer_org;

                        if(total > 0)
                        {
                            ret = total;
                        }

                        return ret;
                    }

                    bf->position_current = ret;
                }
                
                // read until the next cached page
                
                s64 to_read = size;
                s64 next_page_position = page_position;
                
                for(;;)
                {
                    next_page_position += bf->page_cache->granularity_mask + 1;
                    
                    if(next_page_position >= bf->position_current + size)
                    {
                        break;
                    }
                    
                    if(u64_set_find(&bf->page_set.offset_to_page, next_page_position) != NULL)
                    {
                        // a page exists at that position
                        to_read = next_page_position - bf->position_current;
                        break;
                    }
                }
                
                ssize_t ret = bf->buffered_file->vtbl->read(bf->buffered_file, buffer, to_read);
                
                if(ISOK(ret))
                {
                    bf->position_current += ret;
                    bf->position_requested = bf->position_current;
                    buffer += ret;
                    size -= ret;
                    
                    if((size == 0) && (ret == to_read))
                    {
                        ssize_t total = buffer - buffer_org;

                        return total;
                    }
                    
                    page_position = next_page_position;
                    in_page_from = 0;
                    
                    group_mutex_lock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
                                        
                    continue;
                }
                else
                {
                    // handle the error so read bytes are not ignored
                    
                    ssize_t total = buffer - buffer_org;
                    if(total > 0)
                    {
                        ret = total;
                    }
                    
                    return ret;
                }
            }
            
            s64 cost_computation_begin = timeus();

            s64 end_avail = bf->size - page_position;
            
            if(end_avail > 0)
            {            
                if(bf->position_current != page_position)
                {
                    // move into the file at the requested position

                    ssize_t ret = bf->buffered_file->vtbl->seek(bf->buffered_file, page_position, SEEK_SET);

                    if(FAIL(ret))
                    {
                        buffered_file_cache_release_page(bf->page_cache, page);

                        ssize_t total = buffer - buffer_org;

                        if(total > 0)
                        {
                            ret = total;
                        }

                        return ret;
                    }

                    bf->position_current = ret;
                }

                // fill the page
                
                size_t expected_size = MIN(end_avail, page->size);

                ssize_t ret = bf->buffered_file->vtbl->read(bf->buffered_file, page->buffer, expected_size);

                if(FAIL(ret))
                {
                    buffered_file_cache_release_page(bf->page_cache, page);

                    ssize_t total = buffer - buffer_org;

                    if(total > 0)
                    {
                        ret = total;
                    }

                    return ret;
                }

                bf->position_current += ret;
                page->read_to = ret;
            }
            else
            {
                page->read_to = 0;
            }
            
            s64 cost_computation_end = timeus();
            
            // update the cost
            
            page->cost = (cost_computation_end - cost_computation_begin) * 2;
            
            group_mutex_lock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
            
            page->timestamp = MAX_S64;
            u64_node *page_node = u64_set_insert(&bf->page_set.offset_to_page, page->position);
            page_node->value = page;
        }
        else
        {
            page = (buffered_file_page_t)node->value;
        }

        // copy from the page

        ssize_t available_in_page = page->read_to - in_page_from;

        ssize_t n = MIN(available_in_page, size);
        memcpy(buffer, &page->buffer[in_page_from], n);
        
        bf->position_requested += n;
        page->timestamp = timeus();
        
        size -= n;

        // move the page at the top of the MRU

        buffered_file_cache_set_page_as_most_recently_used(bf->page_cache, page);
        
        buffer += n;

        // if size == 0 the job is done
        // if page->read_to != page->size this is the end of the file

        if((size == 0) || (page->read_to != page->size))
        {
            group_mutex_unlock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
            break;
        }

        // at this point, bf->position_requested & bf->page_cache->granularity_mask should be 0
        
        assert((bf->position_requested & bf->page_cache->granularity_mask) == 0);

        page_position += page->size;
        in_page_from = 0;
        page = NULL;
    }
    
    ssize_t total = buffer - buffer_org;
        
    return total;
}

static ssize_t
buffered_file_write(file_t f, const void *buffer_, ssize_t size)
{
    buffered_file_t bf = (buffered_file_t)f;
    
    if(bf->buffered_file == NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    // see if wanted position (which is where we will be reading from) page is in the cache
    // if not, move to position, acquire the page and update its content with the file (if the position is outside the file, just fill with zeroes)
    //   if page acquisition is not possible, do a direct write
    // from the buffer, copy the bytes to the page and update the written range
    
    const u8 *buffer = (const u8*)buffer_;
    const u8* buffer_org = buffer;
    
    buffered_file_page_t page = NULL;
    
    s64 page_position = bf->position_requested & ~bf->page_cache->granularity_mask;
    s64 in_page_from = bf->position_requested & bf->page_cache->granularity_mask;
    
    // we know the page_position and the position in the page
    
    group_mutex_lock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
    
    for(;;) // until there are no more bytes to read
    {
        // see if the page is cached
        
        u64_node *node = u64_set_find(&bf->page_set.offset_to_page, page_position);

        if(node == NULL)
        {
            // the page is not cached
            
            group_mutex_unlock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
            
            // acquire a page to use for caching
            
            page = buffered_file_cache_acquire_page(bf->page_cache, bf, page_position);
            
            if(page == NULL)
            {
                // case where the cache is over used so taking a page would be counter-productive by making the cache a glorified intermediary buffer
                
                if(bf->position_current != bf->position_requested)
                {
                    // move into the file at the requested position

                    ssize_t ret = bf->buffered_file->vtbl->seek(bf->buffered_file, bf->position_requested, SEEK_SET);

                    if(FAIL(ret))
                    {
                        buffered_file_cache_release_page(bf->page_cache, page);
                        
                        if(bf->position_requested > bf->size)
                        {
                            bf->size = bf->position_requested;
                        }

                        ssize_t total = buffer - buffer_org;

                        if(total > 0)
                        {
                            ret = total;
                        }

                        return ret;
                    }

                    bf->position_current = ret;
                }
                
                // write until the next cached page
                
                s64 to_write = size;
                s64 next_page_position = page_position;
                
                for(;;)
                {
                    next_page_position += bf->page_cache->granularity_mask + 1;
                    
                    if(next_page_position >= bf->position_current + size)
                    {
                        break;
                    }
                    
                    if(u64_set_find(&bf->page_set.offset_to_page, next_page_position) != NULL)
                    {
                        // a page exists at that position
                        to_write = next_page_position - bf->position_current;
                        break;
                    }
                }
                
                ssize_t ret = bf->buffered_file->vtbl->write(bf->buffered_file, buffer, to_write);
                
                if(ISOK(ret))
                {
                    bf->position_current += ret;
                    bf->position_requested = bf->position_current;
                    buffer += ret;
                    size -= ret;
                    
                    if(bf->position_requested > bf->size)
                    {
                        bf->size = bf->position_requested;
                    }

                    if((size == 0) && (ret == to_write))
                    {                    
                        ssize_t total = buffer - buffer_org;
                        
                        return total;
                    }
                    
                    page_position = next_page_position;
                    in_page_from = 0;
                    
                    group_mutex_lock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
                    
                    continue;
                }
                else
                {
                    // handle the error so read bytes are not ignored
                    
                    if(bf->position_current > bf->size)
                    {
                        bf->size = bf->position_current;
                    }
                    
                    ssize_t total = buffer - buffer_org;
                    if(total > 0)
                    {
                        ret = total;
                    }
                    
                    return ret;
                }
            }
            
            s64 cost_computation_begin = timeus();
            
            s64 end_avail = bf->size - page_position;
            
            if(end_avail > 0)
            {
                if(bf->position_current != page_position)
                {
                    // move into the file at the requested position

                    ssize_t ret = bf->buffered_file->vtbl->seek(bf->buffered_file, page_position, SEEK_SET);

                    if(FAIL(ret))
                    {
                        if(bf->position_current > bf->size)
                        {
                            bf->size = bf->position_current;
                        }

                        buffered_file_cache_release_page(bf->page_cache, page);

                        ssize_t total = buffer - buffer_org;

                        if(total > 0)
                        {
                            ret = total;
                        }

                        return ret;
                    }

                    bf->position_current = ret;
                }

                // fill the page
                
                size_t expected_size = MIN(end_avail, page->size);

                ssize_t ret = bf->buffered_file->vtbl->read(bf->buffered_file, page->buffer, expected_size);

                if(FAIL(ret))
                {
                    if(bf->position_current > bf->size)
                    {
                        bf->size = bf->position_current;
                    }

                    buffered_file_cache_release_page(bf->page_cache, page);

                    ssize_t total = buffer - buffer_org;

                    if(total > 0)
                    {
                        ret = total;
                    }

                    return ret;
                }

                page->read_to = ret;
            }
            else
            {
                page->read_to = 0;
            }
            
            s64 cost_computation_end = timeus();
            
            // update the cost
            
            page->cost = (cost_computation_end - cost_computation_begin) * 2;
            
            group_mutex_lock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
            
            page->timestamp = MAX_S64;
            u64_node *page_node = u64_set_insert(&bf->page_set.offset_to_page, page->position);
            page_node->value = page;
        }
        else
        {
            page = (buffered_file_page_t)node->value;
        }

        // copy from the page

        ssize_t available_in_page = page->size - in_page_from; // it's size and not read_to

        ssize_t n = MIN(available_in_page, size);
        memcpy(&page->buffer[in_page_from], buffer, n);
        
        if(page->written_from > in_page_from)
        {
            page->written_from = in_page_from;
        }
        
        if(page->written_to_plus_one < in_page_from + n)
        {
            page->written_to_plus_one = in_page_from + n;
        }
        
        if(page->read_to < in_page_from + n)
        {
            page->read_to = in_page_from + n;
        }
        
        bf->position_requested += n;
        page->timestamp = timeus();
        
        size -= n;

        // move the page at the top of the MRU

        buffered_file_cache_set_page_as_most_recently_used(bf->page_cache, page);
        
        buffer += n;

        // if size == 0 the job is done
        // if page->read_to != page->size this is the end of the file

        if((size == 0) || (page->read_to != page->size))
        {
            if(bf->position_requested > bf->size)
            {
                bf->size = bf->position_requested;
            }

            group_mutex_unlock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
            break;
        }

        // at this point, bf->position_requested & bf->page_cache->granularity_mask should be 0
        
        assert((bf->position_requested & bf->page_cache->granularity_mask) == 0);

        page_position += page->size;
        in_page_from = 0;
        page = NULL;
    }
    
    ssize_t total = buffer - buffer_org;
        
    return total;
}

static ssize_t
buffered_file_seek(file_t f, ssize_t position, int whence)
{
    buffered_file_t bf = (buffered_file_t)f;
    
    if(bf->buffered_file == NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    switch(whence)
    {
        case SEEK_SET:
        {
            bf->position_requested = position;
            return position;
        }
        case SEEK_CUR:
        {
            if(bf->position_requested + position >= 0)
            {
                bf->position_requested += position;
                return bf->position_requested;
            }
            else
            {
                bf->position_requested = 0;
                return 0;
            }
        }
        case SEEK_END:
        {
            if(bf->size + position >= 0)
            {
                bf->position_requested = bf->size + position;
                return bf->position_requested;
            }
            else
            {
                bf->position_requested = 0;
                return 0;
            }
        }
        default:
        {
            return INVALID_ARGUMENT_ERROR;
        }
    }
}

static ssize_t
buffered_file_tell(file_t f)
{
    buffered_file_t bf = (buffered_file_t)f;
    
    if(bf->buffered_file == NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    return bf->position_requested;
}

static ya_result
buffered_file_flush(file_t f)
{
    buffered_file_t bf = (buffered_file_t)f;
    
    if(bf->buffered_file == NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    ssize_t ret = 0;
    bool moved = FALSE;
    
    group_mutex_lock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
    
    u64_set_iterator iter;
    u64_set_iterator_init(&bf->page_set.offset_to_page, &iter);
    while(u64_set_iterator_hasnext(&iter))
    {
        u64_node *node = u64_set_iterator_next_node(&iter);
        buffered_file_page* page = (buffered_file_page*)node->value;
        if(page->written_from <= page->written_to_plus_one)
        {
            // move at the position
            // write the bytes
            
            ssize_t target = page->position + page->written_from;
            ret = bf->buffered_file->vtbl->seek(bf->buffered_file, target, SEEK_SET);
            if(ret != target)
            {
                if(ret >= 0)    // the returned value does not match the expected position
                {
                    ret = INVALID_STATE_ERROR;
                }
                
                break;
            }
            
            size_t size = (size_t)page->written_to_plus_one - page->written_from;
            
            ret =  bf->buffered_file->vtbl->write(bf->buffered_file, &page->buffer[page->written_from], size);
            
            if(ret != (ssize_t)size)
            {
                if(ret >= 0)    // the number of bytes do not match the expected written amount
                {
                    ret = INVALID_STATE_ERROR;
                }
                
                break;
            }
            
            page->written_from = size;
            page->written_to_plus_one = 0;
            
            moved = TRUE;
        }
    }
    
    group_mutex_unlock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
    
    if(moved)
    {
        bf->position_current = bf->buffered_file->vtbl->seek(bf->buffered_file, bf->position_requested, SEEK_SET);
    }
    
    return ret;
}

static int
buffered_file_close(file_t f)
{
    buffered_file_t bf = (buffered_file_t)f;
    
    if(bf->buffered_file == NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    buffered_file_flush(f);
    
    group_mutex_lock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
    
    u64_set_iterator iter;
    u64_set_iterator_init(&bf->page_set.offset_to_page, &iter);
    while(u64_set_iterator_hasnext(&iter))
    {
        u64_node *node = u64_set_iterator_next_node(&iter);
        buffered_file_page* page = (buffered_file_page*)node->value;
        
        buffered_file_cache_release_page(bf->page_cache, page);
    }
    u64_set_destroy(&bf->page_set.offset_to_page);
    
    group_mutex_unlock(&bf->page_set.mtx, GROUP_MUTEX_WRITE);
    
    bf->buffered_file->vtbl->close(bf->buffered_file);
    
    buffered_file_cache_release(bf->page_cache);
    
    bf->page_cache = NULL;
    bf->vtbl = NULL;
    ZFREE_OBJECT(bf);
    return SUCCESS;
}

static ssize_t
buffered_file_size(file_t f)
{
    buffered_file_t bf = (buffered_file_t)f;
    
    if(bf->buffered_file == NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    return bf->size;
}

static int
buffered_file_resize(file_t f, ssize_t size)
{
    buffered_file_t bf = (buffered_file_t)f;
    
    if(bf->buffered_file == NULL)
    {
        return INVALID_STATE_ERROR;
    }
    
    if(size < 0)
    {
        return INVALID_ARGUMENT_ERROR;
    }
    
    int ret = file_resize(bf->buffered_file, size);
    
    if(ret >= 0)
    {
        bf->size = size;
    }
    
    return ret;
}

static const struct file_vtbl buffered_file_vtbl =
{
    buffered_file_read,
    buffered_file_write,
    buffered_file_seek,
    buffered_file_tell,
    buffered_file_flush,
    buffered_file_close,
    buffered_file_size,
    buffered_file_resize
};

ya_result
buffered_file_init(file_t *fp, file_t file_to_buffer_, buffered_file_cache_t fc)
{
    if(fp == NULL || file_to_buffer_ == NULL || fc == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }
    
    file_t file_to_buffer = file_to_buffer_;
    
    buffered_file_t bf;
    ZALLOC_OBJECT_OR_DIE(bf,struct buffered_file_t_, BUFFERED_FILE_TAG);
    bf->vtbl = &buffered_file_vtbl;
    bf->buffered_file = file_to_buffer;
    buffered_file_cache_acquire(fc);
    bf->page_cache = fc;
    group_mutex_init(&bf->page_set.mtx);
    bf->page_set.offset_to_page = NULL;
    bf->position_current = file_to_buffer->vtbl->tell(file_to_buffer);
    bf->position_requested = bf->position_current;
    bf->size = file_to_buffer->vtbl->size(file_to_buffer);
    
    *fp = (file_t)bf;
    
    return SUCCESS;
}

/** @} */

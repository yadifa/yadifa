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

/** @defgroup zalloc very fast, no-overhead specialised memory allocation functions
 *  @ingroup dnscore
 *  @brief no-overhead specialised allocation functions
 *
 * These memory allocations are using memory mapping to allocate blocks.
 * 
 * One difficulty is that to free a block, its size has to be known first.
 * Which is not an issue for most of our uses.
 * 
 * One drawback is that once allocated, the memory is never released to the system
 * (but is still available to be allocated again by the program)
 * 
 * Much faster than malloc, and no overhead.
 * 
 * Allocated memory is always aligned to at least 64 bits
 * 
 * The granularity of the size of a block is 8 bytes
 * 
 * The base alignment is always 4096 + real size of the block
 *  *
 * @{
 */

#include "dnscore/dnscore-config.h"
#include "dnscore/dnscore-config-features.h"

#include "dnscore/thread.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#define _ZALLOC_C

#include "dnscore/sys_types.h"
#include "dnscore/logger.h"
#include "dnscore/format.h"
#include "dnscore/zalloc.h"
#include "dnscore/mutex.h"

extern logger_handle* g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#if HAS_ZALLOC_DEBUG_SUPPORT

#include "dnscore/ptr_set_debug.h"

#define ZALLOC_DEBUG                 1
#define DNSCORE_DEBUG_ZALLOC_TRASHMEMORY 1
#else
#define ZALLOC_DEBUG                 0
#define DNSCORE_DEBUG_ZALLOC_TRASHMEMORY 0
#endif

#if HAS_ZALLOC_STATISTICS_SUPPORT
#define ZALLOC_STATISTICS            1
#else
#define ZALLOC_STATISTICS            0
#endif

/*
 *
 */

#if DNSCORE_HAS_ZALLOC_SUPPORT

#define ZMALLOC_TAG 0x434f4c4c414d5a

//#define ZALLOC_MMAP_BLOC_SIZE  0x20000  // 128K : for small usages
//#define ZALLOC_MMAP_BLOC_SIZE  0x300000 //   3M : not enough to be in a 4M page, still a lot

// This setting should stay as it is.
// The one exception is for hardware 
#ifndef ZALLOC_MMAP_BLOC_SIZE
#define ZALLOC_MMAP_BLOC_SIZE 0x1000000 //  16M : enough for lots of records, but too much for smaller setups
                                           //        except if the LAZY define is set ...
#endif

#define ZALLOC_LAZY 1        /// @note edf -- do NOT disable this

#if !ZALLOC_LAZY
# pragma message("zalloc: there is no reason to disable the ZALLOC_LAZY variant beside for testing.")
#endif

#ifndef MAP_ANONYMOUS

/*
 * MAP_ANON is the deprecated synonym of MAP_ANONYMOUS
 * Mac OS X has MAP_ANON but not MAP_ANONYMOUS
 */

#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
#error MMAP MAP_ANONYMOUS not supported.  Please disable zalloc usage until an alternative way is implemented.
#endif
#endif

typedef u8* page;

// least common multiple

static u32 lcm(u32 a, u32 b)
{
    int i = a;
    int j = b;

    while(a != b)
    {
        if(a < b)
        {
            a += i;
        }
        else
        {
            b += j;
        }
    }
    
    return a;
}

/**
 * Page size by slot size, PLEASE do not edit this.
 *
 * page_size[n] / 4096 MUST be a positive integer.
 *
 * The values are calibrated for the database memory usage distribution.
 *
 */

#ifndef ZALLOC_DEBUG
#define ADJUSTED_ALLOC_PG_SIZE_COUNT ZALLOC_PG_SIZE_COUNT
#else
#define ADJUSTED_ALLOC_PG_SIZE_COUNT (ZALLOC_PG_SIZE_COUNT + 1)
#endif

static u32 page_size[ADJUSTED_ALLOC_PG_SIZE_COUNT];
static void* line_sll[ADJUSTED_ALLOC_PG_SIZE_COUNT];
static s32 line_count[ADJUSTED_ALLOC_PG_SIZE_COUNT];
static s32 heap_total[ADJUSTED_ALLOC_PG_SIZE_COUNT];
#if ZALLOC_LAZY
static u8* lazy_next[ADJUSTED_ALLOC_PG_SIZE_COUNT];
static u32 lazy_count[ADJUSTED_ALLOC_PG_SIZE_COUNT];
static u32 smallest_size[ADJUSTED_ALLOC_PG_SIZE_COUNT];
#endif

static mutex_t line_mutex[ADJUSTED_ALLOC_PG_SIZE_COUNT];

#if ZALLOC_STATISTICS
static volatile u64 zalloc_memory_allocated = 0;
static volatile u32 mmap_count = 0;
static mutex_t zalloc_statistics_mtx = MUTEX_INITIALIZER;
#endif

static int system_page_size = 0;
static volatile bool zalloc_init_done = FALSE;

static inline void* zalloc_line_head_get(u32 page_index)
{
    void* ret = line_sll[page_index];
    return ret;
}

static inline void zalloc_line_head_set(u32 page_index, void *ptr)
{
    yassert(ptr != NULL);
    line_sll[page_index] = ptr;
}


#if HAS_ZALLOC_DEBUG_SUPPORT

struct zalloc_range_s
{
    intptr from;
    intptr to;
};
typedef struct zalloc_range_s zalloc_range_s;

static int
zalloc_ptr_set_debug_range_compare(const void *node_a, const void *node_b)
{
    zalloc_range_s *ra = (zalloc_range_s*)node_a;
    zalloc_range_s *rb = (zalloc_range_s*)node_b;
    if(ra->to < rb->from)
    {
        return 1;
    }
    if(rb->to < ra->from)
    {
        return -1;
    }
    return 0;
}

ptr_set_debug zalloc_pages_set = { NULL, zalloc_ptr_set_debug_range_compare};
mutex_t zalloc_pages_set_mtx = MUTEX_INITIALIZER;
#endif

int
zalloc_init()
{
    if(zalloc_init_done)
    {
        return SUCCESS;
    }
    
    zalloc_init_done = TRUE;
    
    // lcm is in this file
#ifndef WIN32
    system_page_size = getpagesize();
#else
    system_page_size = 4096;
#endif
    
    if(system_page_size > ZALLOC_MMAP_BLOC_SIZE)
    {
        fprintf(stderr, "System page size bigger than the internal allocation size (%d > %d)\n", system_page_size, ZALLOC_MMAP_BLOC_SIZE);
        fprintf(stderr, "Please reduce the page size to a smaller value or rebuild disabling the internal allocation using --disable-zalloc\n");
        fflush(stderr);
        abort();
    }
    
    yassert(system_page_size > 0);

    for(u32 i = 0; i < ADJUSTED_ALLOC_PG_SIZE_COUNT; i++)
    {
        u32 lcm_page_chunk = lcm(system_page_size, (i + 1) * 8);
        u32 chosen_size = ((ZALLOC_MMAP_BLOC_SIZE + lcm_page_chunk - 1) / lcm_page_chunk) * lcm_page_chunk;
        
        page_size[i] = chosen_size;
        line_sll[i] = NULL;
        line_count[i] = 0;
        heap_total[i] = 0;
        
#if ZALLOC_LAZY
        lazy_next[i] = NULL;
        lazy_count[i] = 0;
        smallest_size[i] = lcm_page_chunk;
#endif
        mutex_init(&line_mutex[i]);
    }
    
    return SUCCESS;
}

void
zalloc_finalize()
{
}

/**
 * INTERNAL
 *
 * Allocates a bunch of memory for a page_index
 *
 * page2 has a lazy initialisation feature supposed to be enabled at compile time (can be off for testing & debugging)
 *
 * zalloc_lines is as nice with the memory than zalloc_lines with --enable-tiny-footprint set in ./configure but can handle
 * much more memory (the 3.8M test is not a problem)
 */

static void
zalloc_lines(u32 page_index)
{
    page map_pointer;
    
    u32 chunk_size = (page_index + 1) << 3; // size of one bloc
    
#if ZALLOC_LAZY
    if(lazy_next[page_index] == NULL)
    {
#endif
        u32 size = page_size[page_index];

        map_pointer = (page)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        
#if HAS_ZALLOC_DEBUG_SUPPORT
        zalloc_range_s *range = malloc(sizeof(zalloc_range_s));
        range->from = (intptr)map_pointer;
        range->to = range->from + size - 1;
        mutex_lock(&zalloc_pages_set_mtx);
        ptr_node_debug *node = ptr_set_debug_insert(&zalloc_pages_set, range);
        node->value = (void*)(intptr)page_index;
        mutex_unlock(&zalloc_pages_set_mtx);
#endif
       
#if ZALLOC_STATISTICS
        mutex_lock(&zalloc_statistics_mtx);
        mmap_count++;
        mutex_unlock(&zalloc_statistics_mtx);
#endif
    
        if(map_pointer == MAP_FAILED)
        {
            osformatln(termerr, "zalloc_lines(%u,%u) mmap failed with %r", size, chunk_size, ERRNO_ERROR);
            DIE(ZALLOC_ERROR_MMAPFAILED);
        }

#ifdef MADV_NOHUGEPAGE
        if(madvise(map_pointer, size, MADV_NOHUGEPAGE) < 0)
        {
            int err = errno;
            if(err != EINVAL)
            {
                osformatln(termerr, "zalloc_lines(%u,%u) madvise(%p,%x,%i) failed with %r", size, chunk_size, map_pointer, size, MADV_NOHUGEPAGE, ERRNO_ERROR);
            }
#if DEBUG
            else
            {
                osformatln(termout, "zalloc_lines(%u,%u) madvise(%p,%x,%i) failed with %r", size, chunk_size, map_pointer, size, MADV_NOHUGEPAGE, ERRNO_ERROR);
            }
#endif
        }
#endif
        /*
         * current issue: the new memory allocation does not take advantage of the lazy mechanism
         * I should only prepare one part = lcm(system_page_size,chunk_size) at a time.
         * when the page is filled, I fill another one.
         */
        
#if ZALLOC_LAZY
        // give the page to the (supposedly empty) lazy handling
    
        lazy_count[page_index] = size / smallest_size[page_index];
        lazy_next[page_index] = map_pointer;
    }
    else
    {
        map_pointer = lazy_next[page_index];
    }
    
    // lazy_next[i] is set, only prepare it
    
    if(--lazy_count[page_index] > 0)
    {
        lazy_next[page_index] += smallest_size[page_index];
    }
    else
    {
        lazy_next[page_index] = NULL;
    }
    
    u32 count = (smallest_size[page_index] / chunk_size);
    
#else // old mechanism : setup the whole mapped memory at once
    // next data
    // count

    u32 count = (size / chunk_size);
#endif
    
    line_count[page_index] += count;
    heap_total[page_index] += count;

    /* Builds the block chain for the new page set */

    u8* data = map_pointer;
    void** header = (void**)map_pointer;

    while(--count > 0)
    {
        data += chunk_size;
        *header = data;
        header = (void**)data;
    }

    *header = (void*)(~0); // the last header points to an impossible address    

    zalloc_line_head_set(page_index, map_pointer);
}

/**
 * @brief Allocates one slot in a memory set
 *
 * Allocates one slot in a memory set.
 *
 * The size of a slot is page_index*8
 *
 * @param[in] page_index the index of the memory set
 *
 * @return a pointer to the allocated memory
 */

void*
zalloc_line(u32 page_index)
{
    yassert(page_index < ZALLOC_PG_SIZE_COUNT);

#if ZALLOC_DEBUG
    page_index++;               // debug requires 8 more bytes
#endif
    
    mutex_lock(&line_mutex[page_index]);

    if(line_count[page_index] == 0)
    {
        zalloc_lines(page_index);
    }

    line_count[page_index]--;

    yassert(line_count[page_index] >= 0);
    // get the first free slot as a pointer to the next free slot
    void **ret = zalloc_line_head_get(page_index);

    yassert(ret != NULL);   // it should not be NULL
                            // the next free slot can be NULL iff page_index == 0
    yassert((page_index == 0) || ((page_index > 0) && (*ret != NULL)));

    zalloc_line_head_set(page_index, *ret);

    *ret = NULL; /* erases ZALLOC pointer */

#if ZALLOC_DEBUG
    u64* hdr = (u64*)ret;       // the allocated memory is at hdr
    *hdr = (page_index - 1) | 0x2a110c0000000000LL;      // the allocated slot number (offset by DEBUG)
    
    ret = (void**)(hdr + 1);    // the address returned (without the DEBUG header)
#endif

#if DNSCORE_DEBUG_ZALLOC_TRASHMEMORY
    memset(ret, 0xac, ((page_index + 1) << 3) - sizeof(u64));
#endif

#if ZALLOC_STATISTICS
    mutex_lock(&zalloc_statistics_mtx);
    zalloc_memory_allocated += (page_index + 1) << 3;
    mutex_unlock(&zalloc_statistics_mtx);
#endif
    
    mutex_unlock(&line_mutex[page_index]);

    return ret;
}

/**
 * @brief Frees one slot in a memory set
 *
 * Frees one slot in a memory set
 *
 * The size of a slot is page_index*8
 *
 * @param[in] ptr a pointer to the memory to free
 * @param[in] page_index the index of the memory set
 *
 */

static void
zfree_line_report(int page_index)
{
    log_err("zfree_line: page #%d count (%d) > total (%d)", page_index, line_count[page_index], heap_total[page_index]);
    logger_flush();
    s32 count = line_count[page_index];
    if(count > 0)
    {
        void** ret = zalloc_line_head_get(page_index);
        
        for(s32 i = 0; i < count; i++)
        {
            if(ret != NULL)
            {
                log_err("[%3x][%6x] %p", page_index, i, ret);
                void **old = ret;
                (void) old;
                ret = (void**)*ret;
                // do not: *old = NULL;
            }
            else
            {
                log_err("[%3x][%6x] NULL", page_index, i);
                break;
            }
        }
        
        logger_flush();
    }
#ifndef NDEBUG
    bool zalloc_memory_allocations_have_been_corrupted = FALSE;
    assert(zalloc_memory_allocations_have_been_corrupted);
#endif
}

void
zfree_line(void* ptr, u32 page_index)
{
    yassert(page_index < ZALLOC_PG_SIZE_COUNT);
    
    if(ptr != NULL)
    {
#if ZALLOC_DEBUG
        page_index++;
#endif
        
        mutex_lock(&line_mutex[page_index]);
        
#if ZALLOC_DEBUG
        u64* hdr = (u64*)ptr;
        hdr--;
        
#if HAS_ZALLOC_DEBUG_SUPPORT
        zalloc_range_s range = {(intptr)hdr,(intptr)hdr};
        ptr_node_debug *node;
        mutex_lock(&zalloc_pages_set_mtx);
        node = ptr_set_debug_find(&zalloc_pages_set, &range);
        mutex_unlock(&zalloc_pages_set_mtx);
        
        if(node == NULL)
        {
            fprintf(stderr, "address %p is not part of any of our allocated pages",
                    ptr);
            fflush(stderr);
            abort(); // memory not part of the zalloc pages
        }
        
        if(node->value != (void*)(intptr)page_index)
        {
            int real_page_index = (int)(intptr)page_index;
            fprintf(stderr, "address %p is not part of pool %i (%i bytes) but of pool %i (%i bytes)",
                    ptr,
                    page_index - 1, (page_index - 1) << 3,
                    real_page_index, real_page_index << 3
                    );
            fflush(stderr);
            abort(); // memory not of the right size
        }
#endif
        
        u64 magic = *hdr;
        
        if((magic & 0xffffffff00000000LL) != 0x2a110c0000000000LL)
        {
            fprintf(stderr, "address %p has wrong magic (buffer overrun symptom)",ptr);
            fflush(stderr);
            abort();
        }
        magic &= 0xffffffffLL;

        if(magic != page_index - 1)
        {
            fprintf(stderr, "address %p was tagged with the wrong index (buffer overrun symptom)",ptr);
            fflush(stderr);
            abort();
        }
        
        ptr = hdr;
#endif

#if DNSCORE_DEBUG_ZALLOC_TRASHMEMORY
        memset(ptr, 0xfe, (page_index + 1) << 3);
#endif

#if ZALLOC_STATISTICS
        mutex_lock(&zalloc_statistics_mtx);
        zalloc_memory_allocated -= (page_index + 1) << 3;
        mutex_unlock(&zalloc_statistics_mtx);
#endif

        void** ret = (void**)ptr;
        // get the pointer from the first free cell and put it in the newly freed block (thus making a new link in the chain)
        *ret = zalloc_line_head_get(page_index);
        // put the newly made link at the head of the line
        zalloc_line_head_set(page_index, ret);

        line_count[page_index]++;
  
        if(line_count[page_index] > heap_total[page_index])
        {
            zfree_line_report(page_index);
        }
        
        mutex_unlock(&line_mutex[page_index]);
    }
}

/**
 * DEBUG
 */

u64
zheap_line_total(u32 page_index)
{
    if(page_index < ADJUSTED_ALLOC_PG_SIZE_COUNT)
    {
        mutex_lock(&line_mutex[page_index]);

        u64 return_value = heap_total[page_index];
        
        mutex_unlock(&line_mutex[page_index]);
        
        return return_value;
        
    }

    return 0;
}

u64
zheap_line_avail(u32 page_index)
{
    if(page_index < ADJUSTED_ALLOC_PG_SIZE_COUNT)
    {
        mutex_lock(&line_mutex[page_index]);
        
        u64 return_value = line_count[page_index];
        
        mutex_unlock(&line_mutex[page_index]);
        
        return return_value;

    }

    return 0;
}

s64
zallocatedtotal()
{
#if ZALLOC_STATISTICS
    
    u64 return_value = zalloc_memory_allocated;

    return return_value;
    
#else
    return -1;
#endif
}

/**
 * @brief Allocates unaligned memory of an arbitrary size using zalloc_line and malloc
 *
 * Allocates unaligned memory of an arbitrary size using zalloc_line and malloc
 *
 * @param[in] size the size to allocated
 *
 * @return a pointer to the allocated memory
 */

void*
zalloc_unaligned(u32 size)
{
    yassert(size > 0);

    u8* p;
    size++;
    if(size <= 254)
    {
        u8 page_index = (size - 1) >> 3;
        p = (u8*) zalloc_line(page_index);
        *p = page_index;
    }
    else
    {
#if !DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
        p = (u8*)malloc(size);
#else
        
#if !DNSCORE_DEBUG_HAS_BLOCK_TAG
        p = (u8*)debug_malloc(size, __FILE__, __LINE__);
#else
        p = (u8*)debug_malloc(size, __FILE__, __LINE__, ZMALLOC_TAG);
#endif
        
#endif // DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
                
        if(p == NULL)
        {
            DIE(ZALLOC_ERROR_OUTOFMEMORY);
        }
        
        *p = 0xff;
#if DNSCORE_DEBUG_ZALLOC_TRASHMEMORY
        memset(p + 1, 0xca, size);
#endif
    }

    return ++p;
}

/**
 * @brief Frees unaligned memory of an arbitrary size using zfree_line and free
 *
 * Allocates unaligned memory of an arbitrary size using zalloc_line and malloc
 *
 * @param[in] ptr a pointer to the memory to free
 *
 */

void
zfree_unaligned(void* ptr)
{
    if(ptr != NULL)
    {
        u8* p = (u8*)ptr;
        u8 idx = *--p;
        if(idx <= 254)
        {
            zfree_line(p, idx);
        }
        else
        {
            free(p);
        }
    }
}

void
zalloc_print_stats(output_stream *os)
{
#if ZALLOC_STATISTICS
    osformatln(os, "zdb alloc: page-sizes=%u (max %u bytes) allocated=%llu bytes mmap=%u", ADJUSTED_ALLOC_PG_SIZE_COUNT, (ADJUSTED_ALLOC_PG_SIZE_COUNT << 3), zalloc_memory_allocated, mmap_count);
    
    if(zalloc_init_done)
    {
        osprintln(os, "[ size ] blocsize -remain- -total-- -alloc-- --bytes--");
        
        for(int i = 0; i < ADJUSTED_ALLOC_PG_SIZE_COUNT; i++)
        {
            osformatln(os, "[%6i] %-8u %-8u %-8u %-8u %-9u", (i + 1) << 3, page_size[i], line_count[i], heap_total[i], heap_total[i] - line_count[i], (heap_total[i] - line_count[i]) * (i + 1) << 3);
        }
    }
#else
    osprintln(os, "zdb alloc: statistics not compiled in");
#endif
}

#else

void*
malloc_string_or_die(size_t len, u64 tag)
{
    u8 *ret;
    MALLOC_OR_DIE(u8*,ret,len + 1,tag);
    *ret = (u8)MIN(255,len);
    ++ret;
    (void)tag;
    return ret;    
}

void
mfree_string(void *ptr_)
{
    u8 *ptr = (u8*)ptr_;
    --ptr;
    yassert((((intptr)ptr)&1) == 0);
    free(ptr);
}

/**
 * ZALLOC NOT BUILT-IN : DOES NOTHING WORTH MENTIONNING
 */

int
zalloc_init()
{
    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

/**
 * ZALLOC NOT BUILT-IN : DOES NOTHING WORTH MENTIONNING
 */

s64
zallocatedtotal()
{
    return -1;
}

/**
 * ZALLOC NOT BUILT-IN : DOES NOTHING WORTH MENTIONNING
 */

void
zalloc_print_stats(output_stream *os)
{
    (void)os;
}

#endif

/** @} */

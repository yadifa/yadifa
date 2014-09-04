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
/** @defgroup zmalloc The database specialized allocation function
 *  @ingroup dnsdb
 *  @brief The database specialized allocation function
 *
 * @{
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>

#define _ZALLOC_C

pthread_t zalloc_owner;

#include <dnscore/sys_types.h>
#include <dnscore/mutex.h>
#include <dnscore/logger.h>
#include <dnscore/format.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_alloc.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#if ZDB_ZALLOC_THREAD_SAFE == 0
#error "ZDB_ZALLOC_THREAD_SAFE used to be experimental. Now it MUST be set to 1."
#endif

/*
 *
 */

#if ZDB_USES_ZALLOC!=0

#define ZMALLOC_TAG 0x434f4c4c414d5a

//#define ZDB_ALLOC_MMAP_BLOC_SIZE  0x20000  // 128K : for small usages
//#define ZDB_ALLOC_MMAP_BLOC_SIZE  0x300000 //   3M : not enough to be in a 4M page, still a lot
#define ZDB_ALLOC_MMAP_BLOC_SIZE 0x1000000 //  16M : enough for lots of records, but too much for smaller setups
                                           //        except if the LAZY define is set ...

#define ZDB_ALLOC_LAZY 1        // this should be much better with lazy enabled

#if ZDB_ALLOC_LAZY == 0
#pragma message("ZDB_ALLOC_LAZY there is no reason beside testing to disable the ZDB_ALLOC_LAZY algorithm.")
#endif

void
zdb_set_zowner(pthread_t owner)
{
    zalloc_owner = owner;
}

#define ZDB_ZALLOC_DEBUG 1

#ifndef DEBUG
#undef ZDB_ZALLOC_DEBUG
#define ZDB_ZALLOC_DEBUG 1
#endif

#ifndef MAP_ANONYMOUS

/*
 * MAP_ANON is the deprecated synonym of MAP_ANONYMOUS
 * Mac OS X has MAP_ANON but not MAP_ANONYMOUS
 */

#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
#error MMAP MAP_ANONYMUS not supported.  Please disable zalloc usage until an alternative way is implemented.
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

static u32 page_size[ZDB_ALLOC_PG_SIZE_COUNT];
static void* line_sll[ZDB_ALLOC_PG_SIZE_COUNT];
static s32 line_count[ZDB_ALLOC_PG_SIZE_COUNT];
static s32 heap_total[ZDB_ALLOC_PG_SIZE_COUNT];
#if ZDB_ALLOC_LAZY
static u8* lazy_next[ZDB_ALLOC_PG_SIZE_COUNT];
static u32 lazy_count[ZDB_ALLOC_PG_SIZE_COUNT];
static u32 smallest_size[ZDB_ALLOC_PG_SIZE_COUNT];
#endif

#if ZDB_ZALLOC_THREAD_SAFE != 0
static mutex_t line_mutex[ZDB_ALLOC_PG_SIZE_COUNT];

#endif

#if ZDB_ZALLOC_STATISTICS!=0
static volatile u64 zalloc_memory_allocated = 0;
static volatile u32 mmap_count = 0;
static mutex_t zalloc_statistics_mtx = MUTEX_INITIALIZER;
#endif

static int system_page_size = 0;
static volatile bool zdb_alloc_init_done = FALSE;

int
zdb_alloc_init()
{
    if(zdb_alloc_init_done)
    {
        return SUCCESS;
    }
    
    zdb_alloc_init_done = TRUE;
    
    // lcm is in this file
    
    system_page_size = getpagesize();
    
    yassert(system_page_size > 0);

    for(u32 i = 0; i < ZDB_ALLOC_PG_SIZE_COUNT; i++)
    {
        u32 lcm_page_chunk = lcm(system_page_size, (i + 1) * 8);
        u32 chosen_size = ((ZDB_ALLOC_MMAP_BLOC_SIZE + lcm_page_chunk - 1) / lcm_page_chunk) * lcm_page_chunk;
        
        page_size[i] = chosen_size;
        line_sll[i] = NULL;
        line_count[i] = 0;
        heap_total[i] = 0;
        
#if ZDB_ALLOC_LAZY
        lazy_next[i] = NULL;
        lazy_count[i] = 0;
        smallest_size[i] = lcm_page_chunk;
#endif
        mutex_init(&line_mutex[i]);
    }
    
    return SUCCESS;
}

void
zdb_alloc_finalise()
{
}

/**
 * INTERNAL
 *
 * Allocates a bunch of memory for a page_index
 *
 * page2 has a lazy initialisation feature supposed to be enabled at compile time (can be off for testing & debugging)
 *
 * zalloc_page2 is as nice with the memory than zalloc_page with --enable-tiny-footprint set in ./configure but can handle
 * much more memory (the 3.8M test is not a problem)
 */

static void
zdb_alloc_page(u32 page_index)
{
    page map_pointer;
    
    u32 chunk_size = (page_index + 1) << 3; // size of one bloc
    
#if ZDB_ALLOC_LAZY
    if(lazy_next[page_index] == NULL)
    {
#endif
        u32 size = page_size[page_index];

        map_pointer = (page)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

#if ZDB_ZALLOC_STATISTICS
        mutex_lock(&zalloc_statistics_mtx);
        mmap_count++;
        mutex_unlock(&zalloc_statistics_mtx);
#endif
    
        if(map_pointer == MAP_FAILED)
        {
            osformatln(termerr, "zalloc_page2(%u,%u) mmap failed with %r", size, chunk_size, ERRNO_ERROR);
            DIE(ZDB_ERROR_MMAPFAILED);
        }

#ifdef MADV_NOHUGEPAGE
        if(madvise(map_pointer, size, MADV_NOHUGEPAGE) < 0)
        {
            osformatln(termerr, "zalloc_page2(%u,%u) madvise failed with %r", size, chunk_size, ERRNO_ERROR);
        }
#endif
        /*
         * current issue: the new memory allocation does not take advantage of the lazy mechanism
         * I should only prepare one part = lcm(system_page_size,chunk_size) at a time.
         * when the page is filled, I fill another one.
         */
        
#if ZDB_ALLOC_LAZY
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

    line_sll[page_index] = map_pointer;
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
zdb_malloc(u32 page_index)
{
    yassert(page_index < ZDB_ALLOC_PG_SIZE_COUNT);

#if ZDB_ZALLOC_DEBUG!=0
    page_index++;               // debug requires 8 more bytes
#endif
    
#if ZDB_ZALLOC_THREAD_SAFE != 0
    mutex_lock(&line_mutex[page_index]);
#endif

    if(line_count[page_index] == 0)
    {
        zdb_alloc_page(page_index);
    }

    line_count[page_index]--;

    yassert(line_count[page_index] >= 0);
    
    void **ret = line_sll[page_index];
    line_sll[page_index] = *ret;

    *ret = NULL; /* erases ZALLOC pointer */

#if ZDB_ZALLOC_DEBUG!=0
    u64* hdr = (u64*)ret;       // the allocated memory is at hdr
    *hdr = page_index - 1;      // the allocated slot number (offset by DEBUG)
    ret = (void**)(hdr + 1);    // the address returned (without the DEBUG header)
#endif

#if ZDB_DEBUG_ZALLOC_TRASHMEMORY!=0
    memset(ret, 0xac, ((page_index + 1) << 3) - sizeof(u64));
#endif

#if ZDB_ZALLOC_STATISTICS!=0
    mutex_lock(&zalloc_statistics_mtx);
    zalloc_memory_allocated += (page_index + 1) << 3;
    mutex_unlock(&zalloc_statistics_mtx);
#endif
    
#if ZDB_ZALLOC_THREAD_SAFE != 0
    mutex_unlock(&line_mutex[page_index]);
#endif

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

void
zdb_mfree(void* ptr, u32 page_index)
{
    yassert(page_index < ZDB_ALLOC_PG_SIZE_COUNT);
    
    if(ptr != NULL)
    {
#if ZDB_ZALLOC_DEBUG!=0
        page_index++;
#endif
        
#if ZDB_ZALLOC_THREAD_SAFE != 0
        mutex_lock(&line_mutex[page_index]);
#endif
        
#if ZDB_ZALLOC_DEBUG!=0
        u64* hdr = (u64*)ptr;
        hdr--;

        if(*hdr != page_index - 1)
        {
            abort();
        }
        
        ptr = hdr;
#endif

#if ZDB_DEBUG_ZALLOC_TRASHMEMORY!=0
        memset(ptr, 0xfe, (page_index + 1) << 3);
#endif

#if ZDB_ZALLOC_STATISTICS!=0
        mutex_lock(&zalloc_statistics_mtx);
        zalloc_memory_allocated -= (page_index + 1) << 3;
        mutex_unlock(&zalloc_statistics_mtx);
#endif

        void** ret = (void**)ptr;
        *ret = line_sll[page_index];
        line_sll[page_index] = ret;

        line_count[page_index]++;

        if(line_count[page_index] > heap_total[page_index])
        {
            log_err("zdb_mfree: page #%d count (%d) > total (%d)", page_index, line_count[page_index], heap_total[page_index]);
        }
        
#if ZDB_ZALLOC_THREAD_SAFE != 0
        mutex_unlock(&line_mutex[page_index]);
#endif
    }
}

#ifdef zdb_mused
#undef zdb_mused
#endif

/**
 * DEBUG
 */

u64
zdb_mheap(u32 page_index)
{
    if(page_index < ZDB_ALLOC_PG_SIZE_COUNT)
    {
        
#if ZDB_ZALLOC_THREAD_SAFE != 0
        mutex_lock(&line_mutex[page_index]);
#endif

        u64 return_value = heap_total[page_index];
        
#if ZDB_ZALLOC_THREAD_SAFE != 0
        mutex_unlock(&line_mutex[page_index]);
#endif
        
        return return_value;
        
    }

    return 0;
}

u64
zdb_mavail(u32 page_index)
{
    if(page_index < ZDB_ALLOC_PG_SIZE_COUNT)
    {
#if ZDB_ZALLOC_THREAD_SAFE != 0
        mutex_lock(&line_mutex[page_index]);
#endif
        
        u64 return_value = line_count[page_index];
        
#if ZDB_ZALLOC_THREAD_SAFE != 0
        mutex_unlock(&line_mutex[page_index]);
#endif
        
        return return_value;

    }

    return 0;
}

u64
zdb_mused()
{
#if ZDB_ZALLOC_STATISTICS!=0
    
    u64 return_value = zalloc_memory_allocated;

    return return_value;
    
#else
    return 0;
#endif
}

/**
 * @brief Allocates unaligned memory of an arbitrary size using zdb_malloc and malloc
 *
 * Allocates unaligned memory of an arbitrary size using zdb_malloc and malloc
 *
 * @param[in] size the size to allocated
 *
 * @return a pointer to the allocated memory
 */

void*
zdb_malloc_unaligned(u32 size)
{
    yassert(size > 0);

    u8* p;
    size++;
    if(size <= 254)
    {
        u8 page_index = (size - 1) >> 3;
        p = (u8*)zdb_malloc(page_index);
        *p = page_index;
    }
    else
    {
#if ZDB_DEBUG_MALLOC == 0
        p = (u8*)malloc(size);
#else
        
#if ZDB_DEBUG_TAG_BLOCKS == 0
        p = (u8*)debug_malloc(size, __FILE__, __LINE__);
#else
        p = (u8*)debug_malloc(size, __FILE__, __LINE__, ZMALLOC_TAG);
#endif
        
#endif // ZDB_DEBUG_MALLOC
                
        if(p == NULL)
        {
            DIE(ZDB_ERROR_OUTOFMEMORY);
        }
        
        *p = 0xff;
#if ZDB_DEBUG_ZALLOC_TRASHMEMORY!=0
        memset(p + 1, 0xca, size);
#endif
    }

    return ++p;
}

/**
 * @brief Frees unaligned memory of an arbitrary size using zdb_mfree and free
 *
 * Allocates unaligned memory of an arbitrary size using zdb_malloc and malloc
 *
 * @param[in] ptr a pointer to the memory to free
 *
 */

void
zdb_mfree_unaligned(void* ptr)
{
    if(ptr != NULL)
    {
        u8* p = (u8*)ptr;
        u8 idx = *--p;
        if(idx <= 254)
        {
            zdb_mfree(p, idx);
        }
        else
        {
            free(p);
        }
    }
}

void
zdb_alloc_print_stats(output_stream *os)
{
#if ZDB_ZALLOC_STATISTICS
    osformatln(os, "zdb alloc: page-sizes=%u (max %u bytes) allocated=%llu bytes mmap=%u", ZDB_ALLOC_PG_SIZE_COUNT, (ZDB_ALLOC_PG_SIZE_COUNT << 3), zalloc_memory_allocated, mmap_count);
    
    if(zdb_alloc_init_done)
    {
        osprintln(os, "[ size ] blocsize -remain- -total-- -alloc-- --bytes--");
        
        for(int i = 0; i < ZDB_ALLOC_PG_SIZE_COUNT; i++)
        {
            osformatln(os, "[%6i] %-8u %-8u %-8u %-8u %-9u", (i + 1) << 3, page_size[i], line_count[i], heap_total[i], heap_total[i] - line_count[i], (heap_total[i] - line_count[i]) * (i + 1) << 3);
        }
    }
#else
    osprintln(os, "zdb alloc: statistics not compiled in");
#endif
}

#else

int zdb_alloc_init()
{
    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

#endif

/** @} */

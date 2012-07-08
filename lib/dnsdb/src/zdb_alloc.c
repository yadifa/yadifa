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
* DOCUMENTATION */
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

#include "dnsdb/zdb_error.h"
#include "dnsdb/zdb_alloc.h"

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

/*
 *
 */

#if ZDB_USES_ZALLOC!=0

void
zdb_set_zowner(pthread_t owner)
{
    zalloc_owner = owner;
}

#define ZDB_ZALLOC_DEBUG 0

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

#define _128K   0x020000
#define _1M     0x100000
#define _2M     0x200000
#define _4M     0x400000

typedef u8* page;

/**
 * Page size by slot size, PLEASE do not edit this.
 *
 * page_size[n] / 4096 MUST be a positive integer.
 *
 * The values are calibrated for the database memory usage distribution.
 *
 */

#if defined(HAS_TINY_FOOTPRINT) && (HAS_TINY_FOOTPRINT == 1)
static u32 page_size[ZDB_ALLOC_PG_SIZE_COUNT] = {

    4096, /*  8 */
    4096, /* 16 */
    12288, /* 24 LCM = 12288 */
    _2M, /* 32 */

    20480 * 192, /* 40 LCM = 20480 */
    12288 * 325, /* 48 LCM = 12288 */
    28672 * 5, /* 56 LCM = 28672 */
    _128K, /* 64 */
    36864, /* 72 LCM = 36864 */
    20480, /* 80 LCM = 20480 */
    45056, /* 88 LCM = 45056 */
    12288, /* 96 LCM = 12288 */
    53248, /* 104 LCM = 53248 */
    28672, /* 112 LCM = 28672 */
    61440, /* 120 LCM = 61440 */
    4096, /* 128 */
    69632,
    36864, /* 144 LCM =  */
    77824, /* 152 LCM =  */
    20480, /* 160 LCM =  */
    86016, /* 168 LCM =  */
    45056, /* 176 LCM =  */
    94208, /* 184 LCM =  */
    12288, /* 192 LCM =  */
    102400, /* 200 LCM =  */
    53248, /* 208 LCM =  */
    110592, /* 216 LCM =  */
    28672, /* 224 LCM =  */
    118784, /* 232 LCM =  */
    61440, /* 240 LCM =  */
    126976, /* 248 LCM =  */
    4096 /* 256 LCM =  */
};
#else
static u32 page_size[ZDB_ALLOC_PG_SIZE_COUNT] = {

    4096, /*  8 */
    4096, /* 16 */
    12288, /* 24 LCM = 12288 */
    4096, /* 32 */
    20480 * 192, /* 40 LCM = 20480 */
    12288 * 325, /* 48 LCM = 12288 */
    28672 * 5, /* 56 LCM = 28672 */
    4096, /* 64 */
    36864, /* 72 LCM = 36864 */
    20480, /* 80 LCM = 20480 */
    45056, /* 88 LCM = 45056 */
    12288, /* 96 LCM = 12288 */
    53248, /* 104 LCM = 53248 */
    28672, /* 112 LCM = 28672 */
    61440, /* 120 LCM = 61440 */
    4096, /* 128 */
    69632,
    36864, /* 144 LCM =  */
    77824, /* 152 LCM =  */
    20480, /* 160 LCM =  */
    86016, /* 168 LCM =  */
    45056, /* 176 LCM =  */
    94208, /* 184 LCM =  */
    12288, /* 192 LCM =  */
    102400, /* 200 LCM =  */
    53248, /* 208 LCM =  */
    110592, /* 216 LCM =  */
    28672, /* 224 LCM =  */
    118784, /* 232 LCM =  */
    61440, /* 240 LCM =  */
    126976, /* 248 LCM =  */
    4096 /* 256 LCM =  */
};
#endif

static void* line_sll[ZDB_ALLOC_PG_SIZE_COUNT] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

static s32 line_count[ZDB_ALLOC_PG_SIZE_COUNT] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

static s32 heap_total[ZDB_ALLOC_PG_SIZE_COUNT] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

#if ZDB_ZALLOC_THREAD_SAFE != 0
static mutex_t line_mutex[ZDB_ALLOC_PG_SIZE_COUNT] =
{
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER,
    MUTEX_INITIALIZER
};

#endif

#if ZDB_ZALLOC_STATISTICS!=0
static u64 zalloc_memory_allocated = 0;
#endif

/**
 * INTERNAL
 *
 * Allocates a set of a given size for slot size
 *
 * size mod slot-size MUST be 0
 *
 * That's what static u32 page_size[ZDB_ALLOC_PG_SIZE_COUNT] is all about.
 *
 */

static page
zalloc_page(u32 size, u32 chunk_size)
{
    zassert((size % chunk_size) == 0);

    page map_pointer = (page)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(map_pointer == MAP_FAILED)
    {
        perror("zalloc_page");
        DIE(ZDB_ERROR_MMAPFAILED);
    }

    u32 count = (size / chunk_size) - 1;

    /* Builds the block chain for the new page set */

    u8* data = map_pointer;
    void** header = (void**)map_pointer;

    while(count > 0)
    {
        data += chunk_size;
        *header = data;
        header = (void**)data;
        count--;
    }

    *header = (void*)(~0);

    return map_pointer;
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
    zassert(page_index < ZDB_ALLOC_PG_SIZE_COUNT);
    
#if ZDB_ZALLOC_THREAD_SAFE != 0
    mutex_lock(&line_mutex[page_index]);
#endif

#if ZDB_ZALLOC_DEBUG!=0
    page_index++;
#endif

    if(line_count[page_index] == 0)
    {
        u32 size = (page_index + 1) << 3;
        void* next = zalloc_page(page_size[page_index], size);
        u32 count = page_size[page_index] / size;
        line_count[page_index] += count;
        heap_total[page_index] += count;

        line_sll[page_index] = next;
    }

    line_count[page_index]--;

    zassert(line_count[page_index] >= 0);
    
    void** ret = line_sll[page_index];
    line_sll[page_index] = *ret;

    *ret = NULL; /* erases ZALLOC pointer */

#if ZDB_ZALLOC_DEBUG!=0
    u64* hdr = (u64*)ret;
    *hdr = --page_index;
    ret = (void**)(hdr + 1);
#endif

#if ZDB_DEBUG_ZALLOC_TRASHMEMORY!=0
    memset(ret, 0xac, (page_index + 1) << 3);
#endif

#if ZDB_ZALLOC_STATISTICS!=0
    zalloc_memory_allocated += (page_index + 1) << 3;
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
    zassert(page_index < ZDB_ALLOC_PG_SIZE_COUNT);
    
    if(ptr != NULL)
    {

#if ZDB_ZALLOC_THREAD_SAFE != 0
        mutex_lock(&line_mutex[page_index]);
#endif
        
#if ZDB_ZALLOC_DEBUG!=0
        u64* hdr = (u64*)ptr;
        hdr--;

        zassert(*hdr == page_index);
        
        ptr = hdr;
        page_index++;
#endif

#if ZDB_DEBUG_ZALLOC_TRASHMEMORY!=0
        memset(ptr, 0xfe, (page_index + 1) << 3);
#endif

#if ZDB_ZALLOC_STATISTICS!=0
        zalloc_memory_allocated -= (page_index + 1) << 3;
#endif

        void** ret = (void**)ptr;
        *ret = line_sll[page_index];
        line_sll[page_index] = ret;

        line_count[page_index]++;

        if(line_count[page_index] > heap_total[page_index])
        {
            log_err("zdb_mfree: page #%d count (%d) > total (%d)", page_index, line_count[page_index] > heap_total[page_index]);
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
    
#if ZDB_ZALLOC_THREAD_SAFE != 0
    mutex_lock(&line_mutex[page_index]);
#endif

    u64 return_value = zalloc_memory_allocated;

#if ZDB_ZALLOC_THREAD_SAFE != 0
    mutex_unlock(&line_mutex[page_index]);
#endif

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
    zassert(size > 0);

    u8* p;
    size++;
    if(size <= ZDB_ALLOC_PG_PAGEABLE_MAXSIZE)
    {
        u8 s = (size - 1) >> 3;
        p = (u8*)zdb_malloc(s);
        *p = s;
    }
    else
    {
        p = (u8*)malloc(size
#if ZDB_DEBUG_MALLOC!=0 && ZDB_DEBUG_TAG_BLOCKS!=0
                , 0 /* TAG */
#endif
                );
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
        if(idx < ZDB_ALLOC_PG_SIZE_COUNT)
        {
            zdb_mfree(p, idx);
        }
        else
        {
            free(p);
        }
    }
}

#endif

/** @} */

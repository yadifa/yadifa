/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2023, EURid vzw. All rights reserved.
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

/** @defgroup debug Debug functions
 *  @ingroup dnscore
 *  @brief Debug functions.
 *
 *  Definitions of debug functions/hooks, mainly memory related.
 *
 * @{
 */
#include "dnscore/dnscore-config.h"
#include "dnscore/debug_config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include <malloc.h>
#endif

#include <unistd.h>
#include <sys/mman.h>

#include "dnscore/thread.h"
#include "dnscore/timems.h"

#if defined(__GLIBC__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <execinfo.h>
#include <dnscore/shared-heap.h>
#include <dnscore/debug_config.h>
#include <pthread.h>
#endif

#include "dnscore/sys_types.h"
#include "dnscore/format.h"
#include "dnscore/debug.h"
#include "dnscore/mutex.h"
#include "dnscore/logger.h"
#include "dnscore/ptr_set_debug.h"
#include "dnscore/u64_set_debug.h"
#include "dnscore/list-sl-debug.h"

#undef malloc
#undef free
#undef realloc
#undef calloc
#undef debug_mtest
#undef debug_stat
#undef debug_mallocated

#if defined(__GLIBC__) || defined(__APPLE__)
#define DNSCORE_DEBUG_STACKTRACE 1
#else /* __FreeBSD__ or unknown */
#define DNSCORE_DEBUG_STACKTRACE 0
#endif

#if defined(__GLIBC__)
void *__libc_malloc(size_t);
void *__libc_realloc (void *__ptr, size_t __size);
void __libc_free(void*);
void *__libc_memalign(size_t,size_t);
#endif

#if defined(__linux__)
#define DNSCORE_DEBUG_MMAP 1
#endif

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#if DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT

static pthread_mutex_t malloc_hook_mtx = PTHREAD_MUTEX_INITIALIZER;
static ptr_set_debug malloc_hook_tracked_set = PTR_SET_DEBUG_PTR_EMPTY;
static ptr_set_debug malloc_hook_caller_set = PTR_SET_DEBUG_PTR_EMPTY;
volatile size_t malloc_hook_total = 0;
volatile size_t malloc_hook_malloc = 0;
volatile size_t malloc_hook_free = 0;
volatile size_t malloc_hook_realloc = 0;
volatile size_t malloc_hook_memalign = 0;

struct malloc_hook_header_t
{
    u64 begin;
    u32 magic;
    u32 size;
    stacktrace caller_stacktrace;
#if __SIZEOF_POINTER__ == 4
    u32 padding;
#endif
    u64 end;
};

typedef struct malloc_hook_header_t malloc_hook_header_t;

void debug_malloc_hook_tracked_dump();
void debug_malloc_hook_caller_dump();

#endif

/**
 * These are to ensure I get trashed memory at alloc and on a free.
 * =>
 * No "lucky" inits.
 * No "lucky" destroyed uses.
 *
 */

#define DB_MALLOC_MAGIC 0xd1a2e81c
#define DB_MFREED_MAGIC 0xe81cd1a2

#define MALLOC_PADDING  8
#define MALLOC_REALSIZE(mr_size_) ((mr_size_+(MALLOC_PADDING-1))&(-MALLOC_PADDING))

struct debug_memory_by_tag_info_s
{
    s64 allocated_bytes_peak;
    s64 allocated_count_total;
    s64 freed_count_total;

    s64 allocated_count_peak;
    s64 allocated_bytes_total;
    s64 freed_bytes_total;

    s64 size;
};

typedef struct debug_memory_by_tag_info_s debug_memory_by_tag_info_t;

struct debug_memory_by_tag_context_s
{
    u64_set_debug info_set;
    pthread_mutex_t mtx;

    s64 allocated_bytes_peak;
    s64 allocated_count_total;
    s64 freed_count_total;

    s64 allocated_count_peak;
    s64 allocated_bytes_total;
    s64 freed_bytes_total;

    const char *name;
};

typedef struct debug_memory_by_tag_context_s debug_memory_by_tag_context_t;

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_HAS_BLOCK_TAG
static debug_memory_by_tag_context_t malloc_debug_memory_by_tag_ctx;
#endif

#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
static debug_memory_by_tag_context_t *debug_memory_by_tag_contexts[8] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
static pthread_mutex_t debug_memory_by_tag_contexts_mtx = PTHREAD_MUTEX_INITIALIZER;
#endif

struct db_header
{
    u32 magic;
    u32 size;

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
#define HEADER_TAG_SIZE 8
    u64 tag;
#else
#define HEADER_TAG_SIZE 0
#endif

#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
    u64 serial;
#endif

#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
#define HEADER_SIZE_CHAIN (8+(2*__SIZEOF_POINTER__))
    struct db_header* next;
    struct db_header* previous;
#else
#define HEADER_SIZE_CHAIN 0
#endif

#if DNSCORE_DEBUG_STACKTRACE
    intptr* _trace;
#endif
};

typedef struct db_header db_header;

#define HEADER_SIZE sizeof(db_header)

#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
static db_header db_mem_first = {
    DB_MALLOC_MAGIC, 0,
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    0xffffffffffffffffLL,
#endif
#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
    0,
#endif
#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
    &db_mem_first, &db_mem_first,
#endif
#if DNSCORE_DEBUG_STACKTRACE
    NULL,
#endif
};

#define REAL_SIZE(rs_size_) MALLOC_REALSIZE((rs_size_)+HEADER_SIZE)

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_ENHANCED_STATISTICS


/* [  0]   1..  8
 * [  1]   9.. 16
 * [  2]  17.. 24
 * ...
 * [ 15] 121..128
 * [ 31] 248..256
 * [ 32] 257..2^31
 */

static u64 db_alloc_count_by_size[(DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE / 8) + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0
};

static u64 db_alloc_peak_by_size[(DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE / 8) + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0
};

static u64 db_total_allocated = 0;
static u64 db_total_freed = 0;
static u64 db_current_allocated = 0;
static u64 db_current_blocks = 0;
static u64 db_peak_allocated = 0;

#endif

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
static u64 db_next_block_serial = 0;
#endif

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT || DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT
static bool db_showallocs = DNSCORE_DEBUG_SHOW_ALLOCS;
static pthread_mutex_t alloc_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

void debug_bench_malloc_init()
{
#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
    {
        pthread_mutexattr_t   mta;
        pthread_mutexattr_init(&mta);
        pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&alloc_mutex, &mta);
    }

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    debug_memory_by_tag_init(&malloc_debug_memory_by_tag_ctx, "malloc");
#endif

#endif
}

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT || DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT

void debug_malloc_mutex_lock()
{
    pthread_mutex_lock(&alloc_mutex);
}

void debug_malloc_mutex_unlock()
{
    pthread_mutex_unlock(&alloc_mutex);
}

#endif

static void
debug_memory_by_tag_context_register(debug_memory_by_tag_context_t* ctx)
{
    pthread_mutex_lock(&debug_memory_by_tag_contexts_mtx);
    for(int i = 0; i < (int)(sizeof(debug_memory_by_tag_contexts) / sizeof(debug_memory_by_tag_context_t*)); ++i)
    {
        if(debug_memory_by_tag_contexts[i] == NULL)
        {
            debug_memory_by_tag_contexts[i] = ctx;
            break;
        }

        if(debug_memory_by_tag_contexts[i] == ctx)
        {
            break;
        }
    }
    pthread_mutex_unlock(&debug_memory_by_tag_contexts_mtx);
}

static void
debug_memory_by_tag_context_unregister(debug_memory_by_tag_context_t* ctx)
{
    pthread_mutex_lock(&debug_memory_by_tag_contexts_mtx);
    for(int i = 0; i < (int)(sizeof(debug_memory_by_tag_contexts) / sizeof(debug_memory_by_tag_context_t*)); ++i)
    {
        if(debug_memory_by_tag_contexts[i] == ctx)
        {
            for(;i < (int)(sizeof(debug_memory_by_tag_contexts) / sizeof(debug_memory_by_tag_context_t*)) - 1; ++i)
            {
                debug_memory_by_tag_contexts[i] = debug_memory_by_tag_contexts[i + 1];
            }
            debug_memory_by_tag_contexts[sizeof(debug_memory_by_tag_contexts) / sizeof(debug_memory_by_tag_context_t*) - 1] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&debug_memory_by_tag_contexts_mtx);
}

debug_memory_by_tag_context_t*
debug_memory_by_tag_new_instance(const char* name)
{
    debug_memory_by_tag_context_t *ctx = (debug_memory_by_tag_context_t*)debug_malloc_unmonitored(sizeof(debug_memory_by_tag_context_t));
    if(ctx != NULL)
    {
        debug_memory_by_tag_init(ctx, name);
    }
    return ctx;
}

void
debug_memory_by_tag_delete(debug_memory_by_tag_context_t *ctx)
{
    if(ctx != NULL)
    {
        debug_memory_by_tag_finalize(ctx);
        debug_free_unmonitored(ctx);
    }
}

void
debug_memory_by_tag_init(debug_memory_by_tag_context_t *ctx, const char* name)
{
    ZEROMEMORY(ctx, sizeof(debug_memory_by_tag_context_t));
    u64_set_debug_init(&ctx->info_set);
    pthread_mutex_init(&ctx->mtx, NULL);
    ctx->name = name;
    debug_memory_by_tag_context_register(ctx);
}

static void
debug_memory_by_tag_finalize_cb(u64_node_debug *node)
{
    debug_free_unmonitored(node->value);
    node->value = NULL;
}

void
debug_memory_by_tag_finalize(debug_memory_by_tag_context_t *ctx)
{
    debug_memory_by_tag_context_unregister(ctx);
    pthread_mutex_lock(&ctx->mtx);
    u64_set_debug_callback_and_destroy(&ctx->info_set, debug_memory_by_tag_finalize_cb);
    pthread_mutex_unlock(&ctx->mtx);
    pthread_mutex_destroy(&ctx->mtx);
}
#define ZDB_RECORD_TAG      0x4443455242445a    /** "ZDBRECD" */

void break_here()
{

}

void
debug_memory_by_tag_alloc_notify(debug_memory_by_tag_context_t *ctx, u64 tag, s64 size)
{
    if(tag == ZDB_RECORD_TAG)
    {
        break_here();
    }

    pthread_mutex_lock(&ctx->mtx);
    debug_memory_by_tag_info_t *info;
    u64_node_debug *node = u64_set_debug_insert(&ctx->info_set, tag);
    if(node->value != NULL)
    {
        info = (debug_memory_by_tag_info_t *)node->value;
    }
    else
    {
        info = (debug_memory_by_tag_info_t*)debug_malloc_unmonitored(sizeof(debug_memory_by_tag_info_t));
        ZEROMEMORY(info, sizeof(debug_memory_by_tag_info_t));
        info->size = size;
        node->value = info;
    }

    ++info->allocated_count_total;
    info->allocated_bytes_total += (s64)size;
    info->allocated_count_peak = MAX(info->allocated_count_peak, info->allocated_count_total - info->freed_count_total);
    info->allocated_bytes_peak = MAX(info->allocated_bytes_peak, info->allocated_bytes_total - info->freed_bytes_total);

    ++ctx->allocated_count_total;
    ctx->allocated_bytes_total += (s64)size;
    ctx->allocated_count_peak = MAX(ctx->allocated_count_peak, ctx->allocated_count_total - ctx->freed_count_total);
    ctx->allocated_bytes_peak = MAX(ctx->allocated_bytes_peak, ctx->allocated_bytes_total - ctx->freed_bytes_total);
    
    
    pthread_mutex_unlock(&ctx->mtx);
}

void
debug_memory_by_tag_free_notify(debug_memory_by_tag_context_t *ctx, u64 tag, s64 size)
{
    pthread_mutex_lock(&ctx->mtx);
    debug_memory_by_tag_info_t *info;
    u64_node_debug *node = u64_set_debug_insert(&ctx->info_set, tag);
    if(node->value != NULL)
    {
        info = (debug_memory_by_tag_info_t *)node->value;
    }
    else
    {
        info = (debug_memory_by_tag_info_t*)debug_malloc_unmonitored(sizeof(debug_memory_by_tag_info_t));
        ZEROMEMORY(info, sizeof(debug_memory_by_tag_info_t));
        node->value = info;
    }

    ++info->freed_count_total;
    info->freed_bytes_total += size;

    ++ctx->freed_count_total;
    ctx->freed_bytes_total += size;

    pthread_mutex_unlock(&ctx->mtx);
}

void
debug_memory_by_tag_print(debug_memory_by_tag_context_t *ctx, output_stream *os)
{
    pthread_mutex_lock(&ctx->mtx);
    s64 now = timeus();

    osformatln(os,"debug_memory: %s set: %llT %lli", ctx->name, now, now);

    u64_set_debug_iterator iter;
    u64_set_debug_iterator_init(&ctx->info_set, &iter);

    osprintln(os,"    ________ | ALLOCATED_ | FREED_____ | CURRENT___ | PEAK______ | alloc c  | freed c  | current c| peak c   | mean");
    while(u64_set_debug_iterator_hasnext(&iter))
    {
        u64_node_debug *node = u64_set_debug_iterator_next_node(&iter);
        debug_memory_by_tag_info_t *info = (debug_memory_by_tag_info_t*)node->value;
        char tag_name[sizeof(node->key)];
        u64 *tag_namep = (u64*)&tag_name[0];    // pointing to tag_name
        *tag_namep = node->key;                 // setting-up 64 bits of tag_name in one operation
        for(int i = 0; i < (int)sizeof(node->key); ++i)
        {
            if(tag_name[i] == '\0') // scan-build false positive: tag_name has been fully initialised 3 lines above.
            {
                tag_name[i] = 32; // space character
            }
        }

        output_stream_write(os, "TAG ", 4);
        output_stream_write(os, tag_name, sizeof(tag_name));
        osformatln(os, " | %10lli | %10lli | %10lli | %10lli | %8lli | %8lli | %8lli | %8lli | %8lli",
                 info->allocated_bytes_total,
                 info->freed_bytes_total,
                 info->allocated_bytes_total - info->freed_bytes_total,
                 info->allocated_bytes_peak,

                 info->allocated_count_total,
                 info->freed_count_total,
                 info->allocated_count_total - info->freed_count_total,
                 info->allocated_count_peak,
                 info->allocated_bytes_total / MAX(info->allocated_count_total, 1));
    }
    //                  TAG XXXXXXXX
    osformatln(os, "    TOTAL    | %10lli | %10lli | %10lli | %10lli | %8lli | %8lli | %8lli | %8lli | %8lli",
               ctx->allocated_bytes_total,
               ctx->freed_bytes_total,
               ctx->allocated_bytes_total - ctx->freed_bytes_total,
               ctx->allocated_bytes_peak,

               ctx->allocated_count_total,
               ctx->freed_count_total,
               ctx->allocated_count_total - ctx->freed_count_total,
               ctx->allocated_count_peak,

               ctx->allocated_bytes_total / MAX(ctx->allocated_count_total, 1));

    osprintln(os,"    ________ | ALLOCATED_ | FREED_____ | CURRENT___ | PEAK______ | alloc c  | freed c  | current c| peak c   | mean");

    pthread_mutex_unlock(&ctx->mtx);
}

#endif // DNSCORE_DEBUG_HAS_BLOCK_TAG

/**
 * These functions allow to add information to an allocation (e.g. file, line, tag)
 */

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT

void*
debug_malloc(
             size_t size_,
             const char* file, int line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
        , u64 tag
#endif
        )
{
    size_t size = MALLOC_REALSIZE(size_);

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    assert((tag != 0) && (tag != ~0ULL));
#endif

    pthread_mutex_lock(&alloc_mutex);

    u64 current_allocated = db_current_allocated;

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    debug_memory_by_tag_alloc_notify(&malloc_debug_memory_by_tag_ctx, tag, size);
#endif

    pthread_mutex_unlock(&alloc_mutex);

    if(current_allocated + size > DNSCORE_DEBUG_ALLOC_MAX)
    {
        if(__termout__.vtbl != NULL)
        {
            format("DB_MAX_ALLOC reached !!! (%u)", DNSCORE_DEBUG_ALLOC_MAX);
        }

        abort();
    }

    db_header* ptr = (db_header*)debug_malloc_unmonitored(size + HEADER_SIZE); /* Header */

    if(ptr == NULL)
    {
        perror("debug_malloc");

        fflush(NULL);

        abort();
    }

    pthread_mutex_lock(&alloc_mutex);

#if DNSCORE_DEBUG_STACKTRACE
    ptr->_trace = debug_stacktrace_get();
#endif

    ptr->magic = DB_MALLOC_MAGIC;
    ptr->size = size;

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    ptr->tag = tag;
#endif

#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
    ptr->serial = ++db_next_block_serial;

    if(ptr->serial == 0x01cb || ptr->serial == 0x01d0)
    {
        time(NULL);
    }
#endif

#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
    ptr->next = &db_mem_first;
    ptr->previous = db_mem_first.previous;

    db_mem_first.previous->next = ptr;
    db_mem_first.previous = ptr;

#endif

    db_total_allocated += size;
    db_current_allocated += size;
    db_peak_allocated = MAX(db_current_allocated, db_peak_allocated);
    db_current_blocks++;

#if DNSCORE_DEBUG_ENHANCED_STATISTICS
    if(size_ < DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE)
    {
        db_alloc_count_by_size[(size_ - 1) >> 3]++;
        db_alloc_peak_by_size[(size_ - 1) >> 3]++;
    }
    else
    {
        db_alloc_count_by_size[DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]++;
        db_alloc_peak_by_size[DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]++;
    }
#endif

    pthread_mutex_unlock(&alloc_mutex);

    if(db_showallocs)
    {
        if(__termout__.vtbl != NULL)
        {
            format("[%08x] malloc(%3x", thread_self(), (u32)size);
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
            print(" | ");
            debug_dump((u8*) & ptr->tag, 8, 8, FALSE, TRUE);
#endif
#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
            format(" | #%08llx", ptr->serial);
#endif
            formatln(")=%p (%s:%i)", ptr + 1, file, line);
        }
    }

    ptr++;

    /* ensure the memory is not initialized "by chance" */

#if DNSCORE_DEBUG_MALLOC_TRASHMEMORY
    memset(ptr, 0xac, size_); /* AC : AlloCated */
    memset(((u8*)ptr) + size_, 0xca, size - size_); /* CA : AlloCated for padding */
#endif

    return ptr;
}

void*
debug_calloc(
             size_t size_,
             const char* file, int line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
        , u64 tag
#endif
        )
{
    void* p = debug_malloc(size_, file, line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
            , tag
#endif
            );

    if(p != NULL)
    {
        ZEROMEMORY(p, size_);
    }

    return p;
}

void
debug_free(void* ptr_, const char* file, int line)
{
    if(ptr_ == NULL)
    {
        return;
    }

    db_header* ptr = (db_header*)ptr_;

    ptr--;

    if(ptr->magic != DB_MALLOC_MAGIC)
    {
        fflush(NULL);

        if(__termout__.vtbl != NULL)
        {
            if(ptr->magic == DB_MFREED_MAGIC)
            {
                formatln("DOUBLE FREE @ %p (%s:%i)", ptr, file, line);
            }
            else
            {
                formatln("MEMORY CORRUPTED @%p (%s:%i)", ptr, file, line);
            }
        }
        
        stacktrace trace = debug_stacktrace_get();
        debug_stacktrace_print(termout, trace);

        debug_dump(ptr, 64, 32, TRUE, TRUE);
        
        flushout();

        abort();
    }

    size_t size = ptr->size;

    if(db_showallocs)
    {
        if(__termout__.vtbl != NULL)
        {
            format("[%08x] free(%p [%3x]", thread_self(), ptr + 1, (u32)size);

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
            print(" | ");
            debug_dump((u8*) & ptr->tag, 8, 8, FALSE, TRUE);
#endif
#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
            format(" | #%08llx", ptr->serial);
#endif
            formatln(") (%s:%i)", file, line);
        }
    }

    pthread_mutex_lock(&alloc_mutex);

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    debug_memory_by_tag_free_notify(&malloc_debug_memory_by_tag_ctx, ptr->tag, size);
#endif

#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
    ptr->previous->next = ptr->next;
    ptr->next->previous = ptr->previous;
    ptr->next = (void*)~0;
    ptr->previous = (void*)~0;
#endif

    db_total_freed += size;
    db_current_allocated -= size;
    db_current_blocks--;

#if DNSCORE_DEBUG_ENHANCED_STATISTICS

    if(size < DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE)
    {
        db_alloc_count_by_size[(size - 1) >> 3]--;
    }
    else
    {
        db_alloc_count_by_size[DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]--;
    }

#endif

    pthread_mutex_unlock(&alloc_mutex);

    ptr->magic = DB_MFREED_MAGIC; /* This is destroyed AFTER free */

    memset(ptr + 1, 0xfe, size); /* FE : FrEed */

    debug_free_unmonitored(ptr);
}

void
*
debug_realloc(void* ptr, size_t size, const char* file, int line)

{
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    u64 tag = 0x4c554e4152;
#endif

    db_header* hdr;

    if(ptr != NULL)
    {
        hdr = (db_header*)ptr;
        hdr--;
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
        tag = hdr->tag;
#endif
    }

    void* newptr = debug_malloc(size, file, line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
            , tag
#endif
            );

    if(ptr != NULL)
    {
        if(hdr->size < size)
        {
            size = hdr->size;
        }

        MEMCOPY(newptr, ptr, size);
        debug_free(ptr, file, line);
    }

    return newptr;
}

#endif

void
debug_mtest(void* ptr_)
{
    if(ptr_ == NULL)
    {
        return;
    }

    db_header* ptr = (db_header*)ptr_;

    ptr--;
    if(ptr->magic != DB_MALLOC_MAGIC)
    {
        if(__termout__.vtbl != NULL)
        {
            if(ptr->magic == DB_MFREED_MAGIC)
            {
                formatln("DOUBLE FREE @ %p", ptr);
            }
            else
            {
                formatln("MEMORY CORRUPTED @%p", ptr);
            }
        }

        stacktrace trace = debug_stacktrace_get();
        debug_stacktrace_print(termout, trace);
        
        debug_dump(ptr, 64, 32, TRUE, TRUE);

        abort();
    }
}

u32
debug_get_block_count()
{
#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_ENHANCED_STATISTICS
    return db_current_blocks;
#else
    return 0;
#endif
}

bool
debug_mallocated(void* ptr)
{
    if(ptr == NULL)
    {
        /* NULL is ok */

        return TRUE;
    }

    db_header* hdr = (db_header*)ptr;
    hdr--;

    if(hdr->magic == DB_MALLOC_MAGIC)
    {
        return TRUE;
    }
    else if(hdr->magic == DB_MFREED_MAGIC)
    {
        if(__termout__.vtbl != NULL)
        {
            if(hdr->magic == DB_MFREED_MAGIC)
            {
                formatln("DOUBLE FREE @ %p", ptr);
                debug_dump_page(ptr);
            }
        }
        return FALSE;
    }
    else
    {
        if(__termout__.vtbl != NULL)
        {
            formatln("MEMORY CORRUPTED @%p", ptr);
            debug_dump_page(ptr);
        }
        assert(FALSE);

        return FALSE;
    }
}

#if DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT

#define DEBUG_MALLOC_HOOK_DUMP 0

/**
 * Returns true iff the ptr is a tracked memory bloc
 */

static bool debug_malloc_istracked(void* ptr)
{
    bool ret; 
    pthread_mutex_lock(&malloc_hook_mtx);
    ptr_node_debug *node = ptr_set_debug_find(&malloc_hook_tracked_set, ptr);
    ret = (node != NULL);
    pthread_mutex_unlock(&malloc_hook_mtx);
    return ret;
}

/**
 * Adds the ptr to tracked memory bloc set
 */

static void debug_malloc_track_alloc_nolock(void* ptr)
{
    //formatln("track alloc %p", ptr);
    
    ptr_node_debug *node = ptr_set_debug_insert(&malloc_hook_tracked_set, ptr);
    
    intptr flags = (intptr)node->value;
    if(flags != 0)
    {
        // track bug
        pthread_mutex_unlock(&malloc_hook_mtx);
        abort();
    }
    flags |= 1;
    node->value = (void*)flags;
}

/**
 * Removes the ptr to tracked memory bloc set
 */

static void debug_malloc_track_free_nolock(void* ptr)
{
    //formatln("track free  %p", ptr);
    
    ptr_node_debug *node = ptr_set_debug_find(&malloc_hook_tracked_set, ptr);
    
    if(node == NULL)
    {
        // free of non-existing
        pthread_mutex_unlock(&malloc_hook_mtx);
        abort();
    }
    
    intptr flags = (intptr)node->value;
    if((flags & 1) != 1)
    {
        // double free
        pthread_mutex_unlock(&malloc_hook_mtx);
        abort();
    }
    
    flags &= ~1;
    node->value = (void*)flags;
}

/**
 * Lists all the tracked memory blocs to stdout
 */

void debug_malloc_hook_tracked_dump()
{
    pthread_mutex_lock(&malloc_hook_mtx);
    ptr_set_debug_iterator iter;
    ptr_set_debug_iterator_init(&malloc_hook_tracked_set, &iter);
    while(ptr_set_debug_iterator_hasnext(&iter))
    {
        const ptr_node_debug *node = ptr_set_debug_iterator_next_node(&iter);
        if(((intptr)node->value) == 1)
        {
            const malloc_hook_header_t *hdr =  (const malloc_hook_header_t*)node->key;
            --hdr;
            formatln("%p : size=%llu caller=%p", node->key, hdr->size, hdr->caller_stacktrace);
        }
    }
    pthread_mutex_unlock(&malloc_hook_mtx);
}

struct malloc_hook_caller_t
{
    ssize_t count;
    ssize_t size;
    ssize_t peak;
};

typedef struct malloc_hook_caller_t malloc_hook_caller_t;

/**
 * Adds size bytes to the caller_address (to track memory usage)
 */

static void debug_malloc_caller_add(const void* caller_stacktrace, ssize_t size)
{
    ptr_node_debug *node = ptr_set_debug_insert(&malloc_hook_caller_set, (void*)caller_stacktrace);
    malloc_hook_caller_t *caller = (malloc_hook_caller_t*)node->value;
    if(caller == NULL)
    {
        caller = (malloc_hook_caller_t*)debug_malloc_unmonitored(sizeof(malloc_hook_caller_t));
        memset(caller, 0, sizeof(malloc_hook_caller_t));
        node->value = caller;
    }
 
    if(size > 0)
    {
        ++caller->count;
    }
    else if(size < 0)
    {
        --caller->count;
    }
    caller->size += size;
    if(caller->size > caller->peak)
    {
        caller->peak = caller->size;
    }
}

void debug_malloc_hook_caller_dump()
{
    formatln("debug_malloc_hook_caller_dump(): begin");
    ssize_t count_total = 0;
    ssize_t size_total = 0;
    pthread_mutex_lock(&malloc_hook_mtx);
    ptr_set_debug_iterator iter;
    ptr_set_debug_iterator_init(&malloc_hook_caller_set, &iter);
    while(ptr_set_debug_iterator_hasnext(&iter))
    {
        const ptr_node_debug *node = ptr_set_debug_iterator_next_node(&iter);
        stacktrace st = (stacktrace)node->key;
        const malloc_hook_caller_t *caller = (malloc_hook_caller_t*)node->value;
        ssize_t count = caller->count;
        if(count == 0)
        {
            continue;
        }
        ssize_t mean = 0;
        ssize_t size = caller->size;
        if(count != 0)
        {
            mean = size / count;
        }
        debug_stacktrace_print(termout, st);
        formatln("**************** count=%lli size=%lli peak=%lli (mean bloc size=%lli)", caller->count, caller->size, caller->peak, mean);
        
        count_total += caller->count;
        size_total += caller->size;
    }
    pthread_mutex_unlock(&malloc_hook_mtx);
    formatln("COUNT TOTAL : %lli", count_total);
    formatln("SIZE TOTAL  : %lli", size_total);
    formatln("debug_malloc_hook_caller_dump(): end");
}

/**
 * Allocates memory with a few added information.
 */

static void *debug_malloc_hook(size_t size, const stacktrace caller_stacktrace)
{
    void *ret = debug_malloc_unmonitored(size + sizeof(malloc_hook_header_t));
    if(ret != NULL)
    {        
        malloc_hook_header_t *hdr = (malloc_hook_header_t*)ret;
        hdr->begin = 0x4242424242424242;
        hdr->magic = 0xd1a27344;
        hdr->size = size;
        hdr->caller_stacktrace = caller_stacktrace;
        hdr->end = 0x4545454545454545;
        ++hdr;
        
        pthread_mutex_lock(&malloc_hook_mtx);
        malloc_hook_total += size;
        malloc_hook_malloc++;
        debug_malloc_caller_add(caller_stacktrace, size);
        debug_malloc_track_alloc_nolock(hdr);
        pthread_mutex_unlock(&malloc_hook_mtx);
#if DEBUG_MALLOC_HOOK_DUMP
        formatln("malloc(%llu) = %p", size, hdr);
#endif
        
        return hdr;
    }
    else
    {
        return ret;
    }
}

/**
 * Reallocates memory with a few added information.
 */

static void *debug_realloc_hook(void *ptr, size_t size, const stacktrace caller_stacktrace)
{
    if(ptr != NULL)
    {
        if(!debug_malloc_istracked(ptr))
        {
#if DEBUG_MALLOC_HOOK_DUMP
            formatln("realloc(%p, %llu) untracked", ptr, size);
#endif
            return debug_realloc_unmonitored(ptr, size);
        }
        
        malloc_hook_header_t *hdr = (malloc_hook_header_t*)ptr;
        --hdr;
        if(hdr->magic != 0xd1a27344)
        {
            abort();
        }
        malloc_hook_header_t *old_hdr = hdr;
        hdr->begin = 0x6262626262626262; // trashes the memory in case the ptr moves
        hdr->magic = 0xbad15bad;
        hdr->end = 0x6565656565656565;
        
        const void* old_caller = hdr->caller_stacktrace;
        ssize_t old_size = hdr->size;

        void *ret = debug_realloc_unmonitored(hdr, size + sizeof(malloc_hook_header_t));
        
        if(ret != NULL)
        {
            hdr = (malloc_hook_header_t*)ret;
            hdr->begin = 0x4242424242424242;
            hdr->magic = 0xd1a27344;
            hdr->size = size;
            hdr->caller_stacktrace = caller_stacktrace;
            hdr->end = 0x4545454545454545;
            ++hdr;
            
            pthread_mutex_lock(&malloc_hook_mtx);
            
            debug_malloc_caller_add(old_caller, -old_size);
            debug_malloc_track_free_nolock(ptr);
            
            malloc_hook_total += size - old_size;
            malloc_hook_realloc++;
            
            debug_malloc_caller_add(caller_stacktrace, size);
            debug_malloc_track_alloc_nolock(hdr);
            
            pthread_mutex_unlock(&malloc_hook_mtx);
#if DEBUG_MALLOC_HOOK_DUMP
            formatln("realloc(%p, %llu) = %p", ptr, size, hdr);
#endif
            return hdr;
        }
        else
        {
            old_hdr->begin = 0x4242424242424242;
            hdr->magic = 0xd1a27344;
            old_hdr->end = 0x4545454545454545;
            return ret;
        }
    }
    else
    {
        ptr = debug_malloc_hook(size, caller_stacktrace);
        return ptr;
    }
}

/**
 * Frees memory with a few added information.
 */

static void debug_free_hook(void *ptr)
{
    if(ptr != NULL)
    {
        if(!debug_malloc_istracked(ptr))
        {
#if DEBUG_MALLOC_HOOK_DUMP
            formatln("free(%p) untracked", ptr);
#endif
            debug_free_unmonitored(ptr);
            return;
        }
        
        malloc_hook_header_t *hdr = (malloc_hook_header_t*)ptr;
        --hdr;
        if(hdr->magic != 0xd1a27344)
        {
            abort();
        }
        hdr->begin = 0x6262626262626262;
        hdr->end = 0x6565656565656565;
        
        ssize_t size = hdr->size;
        
        pthread_mutex_lock(&malloc_hook_mtx);
        malloc_hook_total -= size;
        malloc_hook_free++;
        
        debug_malloc_caller_add(hdr->caller_stacktrace, -size);
        debug_malloc_track_free_nolock(ptr);
        
        pthread_mutex_unlock(&malloc_hook_mtx);

        debug_free_unmonitored(hdr);
#if DEBUG_MALLOC_HOOK_DUMP
        formatln("free(%p)", ptr);
#endif
    }
}

/**
 * Allocates memory-aligned memory with a few added information.
 */

static void *debug_memalign_hook(size_t alignment, size_t size, const stacktrace caller_stacktrace)
{
    void *ret = debug_memalign_unmonitored(alignment, size + sizeof(malloc_hook_header_t));
    if(ret != NULL)
    {
        malloc_hook_header_t *hdr = (malloc_hook_header_t*)ret;
        hdr->begin = 0x4242424242424242;
        hdr->magic = 0xd1a27344;
        hdr->size = size;
        hdr->caller_stacktrace = caller_stacktrace;
        hdr->end = 0x4545454545454545;
        ++hdr;
        
        pthread_mutex_lock(&malloc_hook_mtx);
        malloc_hook_total += size;
        malloc_hook_memalign++;
        debug_malloc_caller_add(caller_stacktrace, size);
        debug_malloc_track_alloc_nolock(hdr);
        pthread_mutex_unlock(&malloc_hook_mtx);
#if DEBUG_MALLOC_HOOK_DUMP
        formatln("memalign(%llu, %llu) = %p", alignment, size, hdr);
#endif
        return hdr;
    }
    else
    {
        return ret;
    }
}

void debug_malloc_hooks_init()
{
}

void debug_malloc_hooks_finalize()
{
}

static thread_local int g_malloc_busy = 0;

void malloc_busy_acquire()
{
    ++g_malloc_busy;
}

void malloc_busy_release()
{
    --g_malloc_busy;
}

void *malloc(size_t size)
{
    void *ret;
    if(g_malloc_busy == 0)
    {
        ++g_malloc_busy;
        stacktrace st = debug_stacktrace_get_ex(2);
        ret = debug_malloc_hook(size, st);
        --g_malloc_busy;
    }
    else
    {
        ret = debug_malloc_unmonitored(size);
    }
    return ret;
}

void *realloc (void *ptr, size_t size)
{
    void *ret;
    if(!g_malloc_busy)
    {
        stacktrace st = debug_stacktrace_get_ex(2);
        ret = debug_realloc_hook(ptr, size, st);
    }
    else
    {
        ret = debug_realloc_unmonitored(ptr, size);
    }
    return ret;
}

void free(void* ptr)
{
    debug_free_hook(ptr);
}

void *memalign(size_t aligned,size_t size)
{
    void *ret;
    if(!g_malloc_busy)
    {
        stacktrace st = debug_stacktrace_get_ex(2);
        ret = debug_memalign_hook(aligned, size, st);
    }
    else
    {
        ret = debug_memalign_unmonitored(aligned, size);
    }
    return ret;
}

void *debug_malloc_unmonitored(size_t size)
{
    return __libc_malloc(size);
}

void *debug_realloc_unmonitored(void* ptr, size_t size)
{
    return __libc_realloc(ptr, size);
}

void debug_free_unmonitored(void* ptr)
{
    __libc_free(ptr);
}

void *debug_memalign_unmonitored(size_t alignment, size_t size)
{
    return __libc_memalign(alignment, size);
}

#else

void debug_malloc_hooks_init()
{
}

void debug_malloc_hooks_finalize()
{
}

void *debug_malloc_unmonitored(size_t size)
{
    void *ptr = malloc(size);
    if(ptr == NULL)
    {
        abort();
    }
    return ptr;
}

void debug_free_unmonitored(void* ptr)
{
    free(ptr);
}

void debug_malloc_hook_tracked_dump()
{
}

#endif


/**
 * Prints various statistics on stdout
 */

void
debug_memory_stat(int mask)
{
    if(__termout__.vtbl == NULL)
    {
        return;
    }

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_ENHANCED_STATISTICS
    pthread_mutex_lock(&alloc_mutex);

    formatln("%16llx | DB: MEM: Total Allocated=%llu", timeus(), db_total_allocated);
    formatln("%16llx | DB: MEM: Total Freed=%llu", timeus(), db_total_freed);
    formatln("%16llx | DB: MEM: Peak Usage=%llu", timeus(), db_peak_allocated);
    formatln("%16llx | DB: MEM: Allocated=%llu", timeus(), db_current_allocated);
    formatln("%16llx | DB: MEM: Blocks=%llu", timeus(), db_current_blocks);
    formatln("%16llx | DB: MEM: Monitoring Overhead=%llu (%i)", timeus(), (u64)(db_current_blocks * HEADER_SIZE), (int)HEADER_SIZE);
#if DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT
    formatln("%16llx | C ALLOC: total: %llu malloc=%llu free=%llu realloc=%llu memalign=%llu",
             timeus(),
             malloc_hook_total,
             malloc_hook_malloc,
             malloc_hook_free,
             malloc_hook_realloc,
             malloc_hook_memalign);
#endif
#else
    if(mask == 0)
    {
        return;
    }
#endif

#if DNSCORE_HAS_MMAP_DEBUG_SUPPORT
    if(mask & DEBUG_STAT_MMAP)
    {
        debug_mmap_stat();
    }
#endif

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_ENHANCED_STATISTICS
    if(mask & DEBUG_STAT_SIZES)
    {
        formatln("%16llx | DB: MEM: Block sizes: ([size/8]={current / peak}", timeus());

        format("%16llx | ", timeus());

        int i;

        for(i = 0; i < (DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3); i++)
        {
            format("[%4i]={%8llu / %8llu} ;", (i + 1) << 3, db_alloc_count_by_size[i], db_alloc_peak_by_size[i]);

            if((i & 3) == 3)
            {
                format("\n%16llx | ", timeus());
            }
        }

        println("");

        formatln("%16llx | [++++]={%8llu / %8llu}", timeus(),
                 db_alloc_count_by_size[DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3],
                 db_alloc_peak_by_size[DNSCORE_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]);
    }
#endif

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
    if(mask & DEBUG_STAT_TAGS)
    {
        output_stream *os = termout;
        s64 allocated_bytes_peak = 0;
        s64 allocated_count_total = 0;
        s64 freed_count_total = 0;

        s64 allocated_count_peak = 0;
        s64 allocated_bytes_total = 0;
        s64 freed_bytes_total = 0;

        for(int i = 0; i < (int)(sizeof(debug_memory_by_tag_contexts) / sizeof(debug_memory_by_tag_context_t*)); ++i)
        {
            debug_memory_by_tag_context_t *ctx = debug_memory_by_tag_contexts[i];
            if(ctx == NULL)
            {
                break;
            }

            debug_memory_by_tag_print(ctx, os);

            allocated_bytes_peak += ctx->allocated_bytes_peak;
            allocated_count_total += ctx->allocated_count_total;
            freed_count_total += ctx->freed_count_total;
            allocated_count_peak += ctx->allocated_count_peak;
            allocated_bytes_total += ctx->allocated_bytes_total;
            freed_bytes_total += ctx->freed_bytes_total;
        }

        osformatln(os, " GRAND TOTAL | %10lli | %10lli | %10lli | %10lli | %8lli | %8lli | %8lli | %8lli",
                   allocated_bytes_total,
                   freed_bytes_total,
                   allocated_bytes_total - freed_bytes_total,
                   allocated_bytes_peak,

                   allocated_count_total,
                   freed_count_total,
                   allocated_count_total - freed_count_total,
                   allocated_count_peak);

        osprintln(os,"    ________ | ALLOCATED_ | FREED_____ | CURRENT___ | PEAK______ | alloc c  | freed c  | current c| peak c   |");
    }
#endif

#if DNSCORE_DEBUG_CHAIN_ALLOCATED_BLOCKS
    if(mask & DEBUG_STAT_WALK)
    {
        db_header *ptr;

        u64 mintag = MAX_U64;
        u64 nexttag;

        // find the minimum

        for(ptr = db_mem_first.next; ptr != &db_mem_first; ptr = ptr->next)
        {
            u64 tag = ptr->tag;
            if(tag < mintag)
            {
                mintag = tag;
            }
        }

        formatln("%16llx | ", timeus());

        //        0123456789ABCDEF   012345678   012345678   012345678   012345678   012345678
        formatln("%16llx | [-----TAG------] :   COUNT    :    MIN     :    MAX     :    MEAN    :   TOTAL", timeus());

        for(; mintag != MAX_U64; mintag = nexttag)
        {
            nexttag = MAX_U64;
            u32 count = 0;
            u32 minsize = MAX_U32;
            u32 maxsize = 0;
            u64 totalsize = 0;

            for(ptr = db_mem_first.next; ptr != &db_mem_first; ptr = ptr->next)
            {
                u64 tag = ptr->tag;

                if((tag > mintag) && (tag < nexttag))
                {
                    nexttag = tag;
                    continue;
                }

                if(tag != mintag)
                {
                    continue;
                }

                count++;
                totalsize += ptr->size;

                if(ptr->size < minsize)
                {
                    minsize = ptr->size;
                }

                if(ptr->size > maxsize)
                {
                    maxsize = ptr->size;
                }
            }

            char tag_text[9];
            SET_U64_AT(tag_text[0], mintag);
            tag_text[8] = '\0';
            if(count > 0)
            {
                formatln("%16llx | %16s : %10u : %10u : %10u : %10u : %12llu", timeus(), tag_text, count, minsize, maxsize, totalsize / count, totalsize);
            }
            else
            {
                formatln("%16llx | %16s : %10u : %10u : %10u : ---------- : %12llu", timeus(), tag_text, count, minsize, maxsize, totalsize);
            }
        }

        formatln("%16llx | ", timeus());
    }

    flushout();

    if(mask & DEBUG_STAT_DUMP)
    {
        db_header* ptr = db_mem_first.next;
        int index = 0;

        while(ptr != &db_mem_first)
        {
            formatln("block #%04x %16p [%08x]\nBLOCK ", index, (void*)& ptr[1], ptr->size);

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
            debug_dump((u8*) & ptr->tag, 8, 8, FALSE, TRUE);
            formatln(" | ");
#endif

#if DNSCORE_DEBUG_STACKTRACE
            int n = 0;
            intptr *st = ptr->_trace;
            if(st != NULL)
            {
                while(st[n] != 0)
                {
                    ++n;
                }

                char **trace_strings = (char**)st[n + 1];
                for(int i = 0; i < n; i++)
                {
                    formatln("%p %s", (void*)st[i], (trace_strings != NULL) ? trace_strings[i] : "???");
                }
            }
#endif

#if DNSCORE_DEBUG_SERIALNUMBERIZE_BLOCKS
            formatln("#%08llx | ", ptr->serial);
#endif
            osprint_dump(termout, & ptr[1], MIN(ptr->size, 128), 32, OSPRINT_DUMP_ALL);

            formatln("\n");
            ptr = ptr->next;
            index++;
        }

        flushout();
        flusherr();
        //malloc_stats();
        //malloc_info(0, stdout);
    }
#endif

#if DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT
    debug_malloc_hook_caller_dump();
#endif

#if DEBUG
    debug_bench_print_all(termout);
#endif

#if defined(__GLIBC__) || defined(__APPLE__) || defined(__FreeBSD__)
    shared_heap_print_map(0, NULL, NULL);
#endif

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT || DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT
    pthread_mutex_unlock(&alloc_mutex);
#endif
}


/** @} */

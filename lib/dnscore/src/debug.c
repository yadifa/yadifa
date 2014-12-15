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
/** @defgroup debug Debug functions
 *  @ingroup dnscore
 *  @brief Debug functions.
 *
 *  Definitions of debug functions/hooks, mainly memory related.
 *
 * @{
 */
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include <unistd.h>
#include <sys/mman.h>

#if defined(__linux__) || defined(__APPLE__)
#include <execinfo.h>
#endif

#include "dnscore/sys_types.h"
#include "dnscore/format.h"
#include "dnscore/debug.h"
#include "dnscore/mutex.h"
#include "dnscore/logger.h"

#undef malloc
#undef free
#undef realloc
#undef calloc
#undef debug_mtest
#undef debug_stat
#undef debug_mallocated

#if defined(__linux__) || defined(__APPLE__)
#define ZDB_DEBUG_STACKTRACE 1
#else /* __FreeBSD__ or unknown */
#define ZDB_DEBUG_STACKTRACE 0
#endif

#undef ZDB_DEBUG_STACKTRACE
#define ZDB_DEBUG_STACKTRACE 0

#ifdef	__cplusplus
extern "C" output_stream __termout__;
extern "C" output_stream __termerr__;
#else
extern output_stream __termout__;
extern output_stream __termerr__;
#endif

extern logger_handle *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger




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

typedef struct db_header db_header;

struct db_header
{
    u32 magic;
    u32 size;

#if ZDB_DEBUG_TAG_BLOCKS!=0
#define HEADER_SIZE_TAG 8
    u64 tag;
#else
#define HEADER_SIZE_TAG 0
#endif

#if ZDB_DEBUG_SERIALNUMBERIZE_BLOCKS!=0
    u64 serial;
#endif

#if ZDB_DEBUG_CHAIN_ALLOCATED_BLOCKS!=0
#define HEADER_SIZE_CHAIN (8+(2*__SIZEOF_POINTER__))
    db_header* next;
    db_header* previous;
#else
#define HEADER_SIZE_CHAIN 0
#endif

#if ZDB_DEBUG_STACKTRACE != 0
    void** trace;
    char** trace_strings;
#endif
};

#define HEADER_SIZE sizeof(db_header)

#if ZDB_DEBUG_CHAIN_ALLOCATED_BLOCKS!=0
static db_header db_mem_first = {
    DB_MALLOC_MAGIC, 0,
#if ZDB_DEBUG_TAG_BLOCKS!=0
    0xffffffffffffffffLL,
#endif
#if ZDB_DEBUG_SERIALNUMBERIZE_BLOCKS!=0
    0,
#endif
#if ZDB_DEBUG_CHAIN_ALLOCATED_BLOCKS!=0
    &db_mem_first, &db_mem_first
#endif
};
#endif

#define REAL_SIZE(rs_size_) MALLOC_REALSIZE((rs_size_)+HEADER_SIZE)

#if ZDB_DEBUG_ENHANCED_STATISTICS!=0


/* [  0]   1..  8
 * [  1]   9.. 16
 * [  2]  17.. 24
 * ...
 * [ 15] 121..128
 * [ 31] 248..256
 * [ 32] 257..2^31
 */

static u64 db_alloc_count_by_size[(ZDB_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE / 8) + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0
};

static u64 db_alloc_peak_by_size[(ZDB_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE / 8) + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0
};

#endif

static u64 db_total_allocated = 0;
static u64 db_total_freed = 0;
static u64 db_current_allocated = 0;
static u64 db_current_blocks = 0;
static u64 db_peak_allocated = 0;

#if ZDB_DEBUG_SERIALNUMBERIZE_BLOCKS!=0
static u64 db_next_block_serial = 0;
#endif

static bool db_showallocs = ZDB_DEBUG_SHOW_ALLOCS;

static pthread_mutex_t alloc_mutex = PTHREAD_MUTEX_INITIALIZER;

/****************************************************************************/

void
debug_dump(void* data_pointer_, size_t size_, size_t line_size, bool hex, bool text)
{
    debug_dump_ex(data_pointer_, size_, line_size, hex, text, FALSE);
}

/****************************************************************************/

void
debug_dump_ex(void* data_pointer_, size_t size_, size_t line_size, bool hex, bool text, bool address)
{
    if(__termout__.vtbl == NULL)
    {
        return;
    }
    
    osprint_dump(termout, data_pointer_, size_, line_size,
        (address)?OSPRINT_DUMP_ADDRESS:0    |
        (hex)?OSPRINT_DUMP_HEX:0            |
        (text)?OSPRINT_DUMP_TEXT:0);
}

/****************************************************************************/

/****************************************************************************/

#if defined(__linux__)

void
debug_log_stacktrace(logger_handle *handle, u32 level, const char *prefix)
{
    void* addresses[1024];

    int n = backtrace(addresses, sizeof (addresses) / sizeof (void*));
    
    if(n > 0)
    {
        char **symbols = backtrace_symbols(addresses, n);
    
        if(symbols != NULL)
        {
            for(int i = 0; i < n; i++)
            {
                logger_handle_msg(handle, level, "%s: %p: %s", prefix, addresses[i], symbols[i]);
            }

            free(symbols);
        }
        else
        {
            for(int i = 0; i < n; i++)
            {
                logger_handle_msg(handle, level, "%s: %p: ?", prefix, addresses[i]);
            }
        }
    }
    else
    {
        logger_handle_msg(handle, level, "%s: ?: ?", prefix);
    }
}

#else

void debug_log_stacktrace(logger_handle *handle, u32 level, const char *prefix)
{
    (void)handle;
    (void)level;
    (void)prefix;
}

#endif

void*
debug_malloc(
             size_t size_,
             const char* file, int line
#if ZDB_DEBUG_TAG_BLOCKS!=0
        , u64 tag
#endif
        )
{
    size_t size = MALLOC_REALSIZE(size_);

#if ZDB_DEBUG_TAG_BLOCKS != 0
    assert((tag != 0) && (tag != ~0));
#endif

    pthread_mutex_lock(&alloc_mutex);

    u64 current_allocated = db_current_allocated;

    pthread_mutex_unlock(&alloc_mutex);


    if(current_allocated + size > ZDB_DEBUG_ALLOC_MAX)
    {
        if(__termout__.vtbl != NULL)
        {
            format("DB_MAX_ALLOC reached !!! (%u)", ZDB_DEBUG_ALLOC_MAX);
        }

        exit(EXIT_CODE_SELFCHECK_ERROR);
    }

    db_header* ptr = (db_header*)malloc(size + HEADER_SIZE); /* Header */

    if(ptr == NULL)
    {
        perror("");

        fflush(NULL);

        exit(EXIT_CODE_SELFCHECK_ERROR);
    }

    pthread_mutex_lock(&alloc_mutex);

#if ZDB_DEBUG_STACKTRACE != 0
    void* buffer[1024];

    int n = backtrace(buffer, sizeof (buffer) / sizeof (void*));

    ptr->trace = malloc((n + 1) * sizeof (void*));
    memcpy(ptr->trace, buffer, n * sizeof (void*));
    ptr->trace[n] = NULL;

    ptr->trace_strings = backtrace_symbols(buffer, n);
#endif

    ptr->magic = DB_MALLOC_MAGIC;
    ptr->size = size;

#if ZDB_DEBUG_TAG_BLOCKS != 0
    ptr->tag = tag;
#endif

#if ZDB_DEBUG_SERIALNUMBERIZE_BLOCKS != 0
    ptr->serial = ++db_next_block_serial;

    if(ptr->serial == 0x01cb || ptr->serial == 0x01d0)
    {
        time(NULL);
    }

#endif

#if ZDB_DEBUG_CHAIN_ALLOCATED_BLOCKS != 0

    ptr->next = &db_mem_first;
    ptr->previous = db_mem_first.previous;

    db_mem_first.previous->next = ptr;
    db_mem_first.previous = ptr;

#endif

    db_total_allocated += size;
    db_current_allocated += size;
    db_peak_allocated = MAX(db_current_allocated, db_peak_allocated);
    db_current_blocks++;


#if ZDB_DEBUG_ENHANCED_STATISTICS!=0

    if(size_ < ZDB_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE)
    {
        db_alloc_count_by_size[(size_ - 1) >> 3]++;
        db_alloc_peak_by_size[(size_ - 1) >> 3]++;
    }
    else
    {
        db_alloc_count_by_size[ZDB_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]++;
        db_alloc_peak_by_size[ZDB_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]++;
    }

#endif

    pthread_mutex_unlock(&alloc_mutex);

    if(db_showallocs)
    {
        if(__termout__.vtbl != NULL)
        {
            format("[%08x] malloc(%3x", pthread_self(), (u32)size);
#if ZDB_DEBUG_TAG_BLOCKS!=0
            print(" | ");
            debug_dump((u8*) & ptr->tag, 8, 8, FALSE, TRUE);
#endif
#if ZDB_DEBUG_SERIALNUMBERIZE_BLOCKS!=0
            format(" | #%08llx", ptr->serial);
#endif
            formatln(")=%p (%s:%i)", ptr + 1, file, line);
        }
    }

    ptr++;

    /* ensure the memory is not initialized "by chance" */

#if ZDB_DEBUG_MALLOC_TRASHMEMORY != 0
    memset(ptr, 0xac, size_); /* AC : AlloCated */
    memset(((u8*)ptr) + size_, 0xca, size - size_); /* CA : AlloCated for padding */
#endif

    return ptr;
}

void*
debug_calloc(
             size_t size_,
             const char* file, int line
#if ZDB_DEBUG_TAG_BLOCKS!=0
        , u64 tag
#endif
        )
{
    void* p = debug_malloc(size_, file, line
#if ZDB_DEBUG_TAG_BLOCKS!=0
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

        debug_dump(ptr, 64, 32, TRUE, TRUE);

        exit(EXIT_CODE_SELFCHECK_ERROR);
    }

    size_t size = ptr->size;

    if(db_showallocs)
    {
        if(__termout__.vtbl != NULL)
        {
            format("[%08x] free(%p [%3x]", pthread_self(), ptr + 1, (u32)size);

#if ZDB_DEBUG_TAG_BLOCKS!=0
            print(" | ");
            debug_dump((u8*) & ptr->tag, 8, 8, FALSE, TRUE);
#endif
#if ZDB_DEBUG_SERIALNUMBERIZE_BLOCKS!=0
            format(" | #%08llx", ptr->serial);
#endif
            formatln(") (%s:%i)", file, line);
        }
    }

#if ZDB_DEBUG_STACKTRACE != 0
    free(ptr->trace);
    free(ptr->trace_strings);
#endif

    pthread_mutex_lock(&alloc_mutex);

#if ZDB_DEBUG_CHAIN_ALLOCATED_BLOCKS!=0
    ptr->previous->next = ptr->next;
    ptr->next->previous = ptr->previous;
    ptr->next = (void*)~0;
    ptr->previous = (void*)~0;
#endif

    db_total_freed += size;
    db_current_allocated -= size;
    db_current_blocks--;

#if ZDB_DEBUG_ENHANCED_STATISTICS!=0

    if(size < ZDB_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE)
    {
        db_alloc_count_by_size[(size - 1) >> 3]--;
    }
    else
    {
        db_alloc_count_by_size[ZDB_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]--;
    }

#endif

    pthread_mutex_unlock(&alloc_mutex);

    ptr->magic = DB_MFREED_MAGIC; /* This is destroyed AFTER free */

    memset(ptr + 1, 0xfe, size); /* FE : FrEed */

    free(ptr);
}

void
*
debug_realloc(void* ptr, size_t size, const char* file, int line)

{
#if ZDB_DEBUG_TAG_BLOCKS!=0
    u64 tag = 0x4c554e4152;
#endif

    db_header* hdr;

    if(ptr != NULL)
    {
        hdr = (db_header*)ptr;
        hdr--;
#if ZDB_DEBUG_TAG_BLOCKS!=0
        tag = hdr->tag;
#endif
    }

    void* newptr = debug_malloc(size, file, line
#if ZDB_DEBUG_TAG_BLOCKS!=0
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

char
*
debug_strdup(const char* str)
{
    int l = strlen(str) + 1;
    char* out;
    MALLOC_OR_DIE(char*, out, l, ZDB_STRDUP_TAG); /* ZALLOC IMPOSSIBLE */
    MEMCOPY(out, str, l);
    return out;
}

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

        debug_dump(ptr, 64, 32, TRUE, TRUE);

        exit(EXIT_CODE_SELFCHECK_ERROR);
    }

}

u32
debug_get_block_count()
{
    return db_current_blocks;
}

void
debug_stat(bool dump)
{
    if(__termout__.vtbl == NULL)
    {
        return;
    }

    formatln("DB: MEM: Total Allocated=%llu", db_total_allocated);
    formatln("DB: MEM: Total Freed=%llu", db_total_freed);
    formatln("DB: MEM: Peak Usage=%llu", db_peak_allocated);
    formatln("DB: MEM: Allocated=%llu", db_current_allocated);
    formatln("DB: MEM: Blocks=%llu", db_current_blocks);
    formatln("DB: MEM: Monitoring Overhead=%llu (%i)", (u64)(db_current_blocks * HEADER_SIZE), (int)HEADER_SIZE);

#if ZDB_DEBUG_ENHANCED_STATISTICS!=0

    println("DB: MEM: Block sizes:");

    int i;

    for(i = 0; i < (ZDB_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3); i++)
    {
        format("[%3i]={%8llu / %8llu} ;", (i + 1) << 3, db_alloc_count_by_size[i], db_alloc_peak_by_size[i]);

        if((i & 1) == 1)
        {
            println("");
        }
    }

    formatln("[+++]={%8llu / %8llu}",
             db_alloc_count_by_size[ZDB_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3],
             db_alloc_peak_by_size[ZDB_DEBUG_ENHANCED_STATISTICS_MAX_MONITORED_SIZE >> 3]);
#endif

#if ZDB_DEBUG_CHAIN_ALLOCATED_BLOCKS!=0
    if(dump)
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
        
        println("");
        
        //        0123456789ABCDEF   012345678   012345678   012345678   012345678   012345678
        println("[-----TAG------] :   COUNT   :    MIN    :    MAX    :    MEAN    :   TOTAL");
        
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

            formatln("%16s : %9u : %9u : %9u : %9u : %12llu", tag_text, count, minsize, maxsize, totalsize / count, totalsize);
            flushout();
        }
        
        println("");
    }
    
    if(dump)
    {
        db_header* ptr = db_mem_first.next;
        int index = 0;
        
        while(ptr != &db_mem_first)
        {
            formatln("%04x %16p [%08x]", index, (void*)& ptr[1], ptr->size);

#if ZDB_DEBUG_TAG_BLOCKS!=0
            debug_dump((u8*) & ptr->tag, 8, 8, FALSE, TRUE);
            formatln(" | ");
#endif

#if ZDB_DEBUG_STACKTRACE != 0
            for(int sp = 0; ptr->trace[sp] != NULL; sp++)
            {
                formatln("%p %s", ptr->trace[sp], (ptr->trace_strings != NULL) ? ptr->trace_strings[sp] : "???");
            }
#endif

#if ZDB_DEBUG_SERIALNUMBERIZE_BLOCKS!=0
            formatln("#%08llx | ", ptr->serial);
#endif
            osprint_dump(termout, & ptr[1], ptr->size, 32, OSPRINT_DUMP_ALL);

            formatln("\n");
            ptr = ptr->next;
            index++;
        }
    }
#endif
}

void
debug_dump_page(void* ptr)
{
    if(__termout__.vtbl != NULL)
    {
        formatln("Page for %p:\n", ptr);

        if(ptr != NULL)
        {
            intptr p = (intptr)ptr;
            p = p & (~4095);
            debug_dump_ex((void*)p, 4096, 32, TRUE, TRUE, TRUE);
        }
    }
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

#ifdef DEBUG

static mutex_t debug_bench_mtx = MUTEX_INITIALIZER;
static debug_bench_s *debug_bench_first = NULL;

void
debug_bench_register(debug_bench_s *bench, const char *name)
{
    mutex_lock(&debug_bench_mtx);
    
    debug_bench_s *b = debug_bench_first;
    while((b != bench) && (b != NULL))
    {
        b = b->next;
    }
    
    if(b == NULL)
    {
        bench->next = debug_bench_first;
        bench->name = strdup(name);
        bench->time_min = MAX_U64;
        bench->time_max = 0;
        bench->time_total = 0;
        bench->time_count = 0;
        debug_bench_first = bench;
    }
    else
    {
        log_debug("debug_bench_register(%p,%s): duplicate", bench, name);
    }
    mutex_unlock(&debug_bench_mtx);
}

void
debug_bench_commit(debug_bench_s *bench, u64 delta)
{
    mutex_lock(&debug_bench_mtx);
    bench->time_min = MIN(bench->time_min, delta);
    bench->time_max = MAX(bench->time_max, delta);
    bench->time_total += delta;
    bench->time_count++;
    mutex_unlock(&debug_bench_mtx);
}

void debug_bench_logdump_all()
{
    debug_bench_s *p = debug_bench_first;
    while(p != NULL)
    {
        double min = p->time_min;
        min /= 1000000.0;
        double max = p->time_max;
        max /= 1000000.0;
        double total = p->time_total;
        total /= 1000000.0;
        u32 count = p->time_count;
        log_info("bench: %12s: [%9.6fs:%9.6fs] total=%9.6fs mean=%9.6fs rate=%-12.3f/s calls=%9u", p->name, min, max, total, total / count, count / total, count);
        p = p->next;
    }
}

#endif


#ifdef DEBUG

void debug_unicity_init(debug_unicity *dus)
{
    assert(dus != NULL);

    pthread_mutex_init(&dus->mutex, NULL);
    dus->counter = 0;
}

void debug_unicity_acquire(debug_unicity *dus)
{
    assert(dus != NULL);

    pthread_mutex_lock(&dus->mutex);
    dus->counter++;
    assert(dus->counter == 1);
    pthread_mutex_unlock(&dus->mutex);
}

void debug_unicity_release(debug_unicity *dus)
{
    assert(dus != NULL);

    pthread_mutex_lock(&dus->mutex);
    dus->counter--;
    assert(dus->counter == 0);
    pthread_mutex_unlock(&dus->mutex);
}


void debug_vg(const void* b, int len)
{
    const char* s = (const char*)b;
    for(int i = 0; i < len; i++)
    {
        if((s[i] >= ' ') && (s[i] < 127))
        {
            putchar(s[i]);
        }
        else
        {
            putchar('.');
        }
    }
}


#endif

/** @} */

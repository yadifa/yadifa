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

#ifdef	__cplusplus
extern "C" output_stream __termout__;
extern "C" output_stream __termerr__;
#else
extern output_stream __termout__;
extern output_stream __termerr__;
#endif

#if defined(DEBUG_VALID_ADDRESS)
bool debug_is_valid_address(void* ptr, size_t len)
{
    assert(len <= 0x1000000);
    
    unsigned char v[0x1000000/0x1000];  /* enough memory for 16MB */
    intptr addr = (intptr)ptr;
    addr &= ~0xfff;
    int r = mincore((void*)addr, len, v);
    
    return r == 0;
}
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

    u8* data_pointer = (u8*)data_pointer_;
    s32 size = size_;


    int dump_size;
    int i;

    do
    {
        dump_size = MIN(line_size, size);

        u8* data;

        if(address)
        {
            format("%p ", data_pointer);
        }

        if(hex)
        {
            data = data_pointer;
            for(i = 0; i < dump_size; i++)
            {
                format("%02x", *data++);
                if((i & 3) == 3)
                {
                    print(" ");
                }
            }

            for(; i < line_size; i++)
            {
                print("  ");
                if((i & 3) == 0)
                {
                    print(" ");
                }
            }
        }

        if(hex & text)
        {
            print(" | ");
        }

        if(text)
        {
            data = data_pointer;
            for(i = 0; i < dump_size; i++)
            {
                char c = *data++;
                if(c < ' ')
                {
                    c = '.';
                }
                format("%c", c);
            }
        }

        data_pointer += dump_size;
        size -= dump_size;

        if(size != 0)
        {
            println("");
        }
    }
    while(size > 0);

    if(size_ > line_size)
    {
        println("");
    }
}

/****************************************************************************/

/****************************************************************************/

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
            debug_dump((u8*) & ptr[1], ptr->size, 32, TRUE, TRUE);

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

#ifndef NDEBUG

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

#endif

/** @} */

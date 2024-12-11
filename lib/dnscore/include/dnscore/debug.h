/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup debug Debug functions
 * @ingroup dnscore
 * @brief Debug functions.
 *
 *  Definitions of debug functions/hooks, mainly memory related.
 *
 *  THIS MEMORY DEBUGGER MUST BE INCLUDED WITH EVERY SINGLE (C) FILE.
 *  IF DEBUGGING MEMORY ALLOCATION IS USED, IT HAS TO BE ENABLED EVERYWHERE OR NOWHERE.
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _DEBUG_H
#define _DEBUG_H

#include <dnscore/dnscore_config_features.h>

#ifndef _SYSTYPES_H
#error PLEASE DO NOT INCLUDE debug.h DIRECTLY.  USE sys_types.h.
#endif

#define DEBUG_STAT_SIZES 1 // Common
#define DEBUG_STAT_TAGS  2 // Usefull
#define DEBUG_STAT_DUMP  4 // USE WITH CARE
#define DEBUG_STAT_WALK  8
#define DEBUG_STAT_MMAP  16

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
/** @note : DO NOT INCLUDE THIS HERE WITHOUT SOME KIND OF PROTECTION #include <dnscore/format.h> */

#include <dnscore/debug_config.h>

#if DNSCORE_HAS_MMAP_DEBUG_SUPPORT
// MUST be included before else the defines will break the build
#include <sys/mman.h>

// #pragma message("MMAP REROUTED")
void *debug_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
int   debug_munmap(void *addr, size_t len);
void  debug_mmap_stat();

#define mmap(addr__, len__, prot__, flags__, fildes__, off__) debug_mmap((addr__), (len__), (prot__), (flags__), (fildes__), (off__))
#define munmap(addr__, len__)                                 debug_munmap((addr__), (len__))
#endif

#if DEBUG
#include <dnscore/thread.h>
#endif

#if !DEBUG
#define yassert(x)
#else
void log_assert__(bool b, const char *txt, const char *file, int line);
#if !__clang_analyzer__
#define yassert(cond__)                                                                                                                                                                                                                        \
    log_assert__((cond__), #cond__, __FILE__, __LINE__);                                                                                                                                                                                       \
    assert((cond__))
#else
#define yassert(cond__) assert(cond__)
#endif
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#define GENERIC_TAG    0x434952454e4547 /* GENERIC */
#define ZDB_STRDUP_TAG 0x505544525453   /* "STRDUP" */

void debug_dump(void *data_pointer_, size_t size, size_t line_size, bool hex, bool text);
void debug_dump_ex(void *data_pointer_, size_t size_, size_t line_size, bool hex, bool text, bool address);

struct logger_handle_s;

bool debug_log_stacktrace(struct logger_handle_s *handle, uint32_t level, const char *prefix);

#if DEBUG
/*
 * DO NOT FORGET THAT THE "L" FUNCTIONS DO REQUIRE A DEBUG_LEVEL #define
 * BEFORE THE "debug.h" INCLUDE !
 */
#define DEBUGLNF(...)      osformatln(termerr, __VA_ARGS__)
#define DEBUGF(...)        osformat(termerr, __VA_ARGS__)
#define OSDEBUG(term, ...) osformat((term), __VA_ARGS__)
#define LDEBUG(level, ...)                                                                                                                                                                                                                     \
    if(DEBUG_LEVEL >= (level))                                                                                                                                                                                                                 \
    osformat(termerr, __VA_ARGS__)
#define OSLDEBUG(term, level, ...)                                                                                                                                                                                                             \
    if(DEBUG_LEVEL >= (level))                                                                                                                                                                                                                 \
    osformat((term), __VA_ARGS__)
#else
#define DEBUGLNF(...)
#define DEBUGF(...)
#define OSDEBUG(...)
#define LDEBUG(...)
#define OSLDEBUG(...)
#endif

#ifndef DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
#error "bogus include sequence"
#endif

void debug_stat(int mask);

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT

#ifndef MALLOC_OR_DIE
#error "something fishy is happening.  MALLOC_OR_DIE has not been defined yet."
#endif

#ifndef REALLOC_OR_DIE
#error "something fishy is happening.  REALLOC_OR_DIE has not been defined yet."
#endif

#undef MALLOC_OR_DIE
#undef REALLOC_OR_DIE

void *debug_malloc(size_t size_, const char *file, int line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
                   ,
                   uint64_t tag
#endif
);

void *debug_calloc(size_t size_, const char *file, int line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
                   ,
                   uint64_t tag
#endif
);

void *debug_realloc(void *ptr_, size_t size_, const char *file, int line);

bool  debug_mallocated(void *ptr);

#define assert_mallocated(ptr) yassert(debug_mallocated(ptr))

void     debug_free(void *ptr, const char *file, int line);
void     debug_mtest(void *ptr);

char    *debug_strdup(const char *);

uint32_t debug_get_block_count();

#ifdef strdup
#undef strdup
#endif

#define strdup debug_strdup

#if !DNSCORE_DEBUG_HAS_BLOCK_TAG

#undef MALLOC_OR_DIE
#undef MALLOC_OBJECT_OR_DIE
#undef MALLOC_OBJECT_ARRAY_OR_DIE
#undef MALLOC_OBJECT_ARRAY

#define malloc(len__)       debug_malloc((len__), __FILE__, __LINE__)
#define calloc(len__)       debug_calloc((len__), __FILE__, __LINE__)
#define free(p__)           debug_free((p__), __FILE__, __LINE__)
#define realloc(p__, len__) debug_realloc((p__), (len__), __FILE__, __LINE__)

#define REALLOC_OR_DIE(cast, src_and_target, newsize, tag)                                                                                                                                                                                     \
    if(((src_and_target) = (cast)debug_realloc((src_and_target), (newsize), __FILE__, __LINE__)) == NULL)                                                                                                                                      \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        abort(); /* NOT TAGGED */                                                                                                                                                                                                              \
    }

#define MALLOC_OR_DIE(cast_, target_, size_, tag_)                                                                                                                                                                                             \
    if(((target_) = (cast_)debug_malloc(size, __FILE__, __LINE__)) != NULL)                                                                                                                                                                    \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target_), 0xac, (size_));                                                                                                                                                                                              \
    }                                                                                                                                                                                                                                          \
    else                                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_OR_DIE(target__, object__, tag__)                                                                                                                                                                                        \
    if(((target__) = (object__ *)debug_malloc(sizeof(object__), __FILE__, __LINE__)) != NULL)                                                                                                                                                  \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target__), 0xac, (sizeof(object__)));                                                                                                                                                                                  \
    }                                                                                                                                                                                                                                          \
    else                                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_ARRAY_OR_DIE(target__, object__, count__, tag__)                                                                                                                                                                         \
    if(((target__) = (object__ *)debug_malloc(sizeof(object__) * (count__), __FILE__, __LINE__)) != NULL)                                                                                                                                      \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target__), 0xac, (sizeof(object__) * (count__)));                                                                                                                                                                      \
    }                                                                                                                                                                                                                                          \
    else                                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_ARRAY(target__, object__, count__, tag__)                                                                                                                                                                                \
    if(((target__) = (object__ *)debug_malloc(sizeof(object__) * (count__), __FILE__, __LINE__)) != NULL)                                                                                                                                      \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target__), 0xac, (sizeof(object__) * (count__)));                                                                                                                                                                      \
    }

#else

#define DBGALLOC_TAG 0x434f4c4c41474244

#undef MALLOC_OR_DIE
#undef MALLOC_OBJECT_OR_DIE
#undef MALLOC_OBJECT_ARRAY_OR_DIE
#undef MALLOC_OBJECT_ARRAY

#define malloc(len__)       debug_malloc((len__), __FILE__, __LINE__, DBGALLOC_TAG)
#define free(p__)           debug_free((p__), __FILE__, __LINE__)
#define realloc(p__, len__) debug_realloc((p__), (len__), __FILE__, __LINE__)

// #define MALLOC_OR_DIE(cast,target,size,tag)
// if(((target)=(cast)debug_malloc(size,__FILE__,__LINE__,(tag)))==NULL){perror(__FILE__);abort(); /* TAGGED */} #define
// REALLOC_OR_DIE(cast,src_and_target,newsize,tag)
// if(((src_and_target)=(cast)debug_realloc((src_and_target),(newsize),__FILE__,__LINE__))==NULL){perror(__FILE__);abort();
// /* NOT TAGGED */ }

#define MALLOC_OR_DIE(cast_, target_, size_, tag__)                                                                                                                                                                                            \
    if(((target_) = (cast_)debug_malloc(size_, __FILE__, __LINE__, (tag__))) != NULL)                                                                                                                                                          \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target_), 0xac, (size_));                                                                                                                                                                                              \
    }                                                                                                                                                                                                                                          \
    else                                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_OR_DIE(target__, object__, tag__)                                                                                                                                                                                        \
    if(((target__) = (object__ *)debug_malloc(sizeof(object__), __FILE__, __LINE__, (tag__))) != NULL)                                                                                                                                         \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target__), 0xac, (sizeof(object__)));                                                                                                                                                                                  \
    }                                                                                                                                                                                                                                          \
    else                                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_ARRAY_OR_DIE(target__, object__, count__, tag__)                                                                                                                                                                         \
    if(((target__) = (object__ *)debug_malloc(sizeof(object__) * (count__), __FILE__, __LINE__, (tag__))) != NULL)                                                                                                                             \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target__), 0xac, (sizeof(object__) * (count__)));                                                                                                                                                                      \
    }                                                                                                                                                                                                                                          \
    else                                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_ARRAY(target__, object__, count__, tag__)                                                                                                                                                                                \
    if(((target__) = (object__ *)debug_malloc(sizeof(object__) * (count__), __FILE__, __LINE__, (tag__))) != NULL)                                                                                                                             \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target__), 0xac, (sizeof(object__) * (count__)));                                                                                                                                                                      \
    }

#endif

#else

#define debug_mtest(x)
#define debug_mallocated(x) true
#define assert_mallocated(x)

#if !(DNSCORE_HAS_MALLOC_DEBUG_SUPPORT || DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT || DNSCORE_HAS_ZALLOC_STATISTICS_SUPPORT || DNSCORE_HAS_MMAP_DEBUG_SUPPORT)
#define debug_stat(x)
#endif

/*
 * MALLOC_OR_DIE and REALLOC_OR_DIE have already been defined in sys_types.h
 */

#endif

struct debug_bench_s
{
    struct debug_bench_s *next;
    const char           *name;
    uint64_t              time_min;
    uint64_t              time_max;
    uint64_t              time_total;
    uint64_t              time_count;
};

typedef struct debug_bench_s debug_bench_t;

struct output_stream_s;

struct logger_handle;

// declares timeus()

int64_t timeus();

void    debug_bench_init();

void    debug_bench_register(debug_bench_t *bench, const char *name);

#define debug_bench_start(bench__)        timeus()

#define debug_bench_stop(bench__, from__) debug_bench_commit((bench__), timeus() - (from__));

void              debug_bench_commit(debug_bench_t *bench, uint64_t delta);
void              debug_bench_logdump_all();
void              debug_bench_print_all(struct output_stream_s *os);

void              debug_bench_unregister_all();

typedef intptr_t *stacktrace;
stacktrace        debug_stacktrace_get_ex(int index);
stacktrace        debug_stacktrace_get(); // debug_stacktrace_get_ex(1)
void              debug_stacktrace_log(struct logger_handle_s *handle, uint32_t level, stacktrace trace);
void              debug_stacktrace_log_with_prefix(struct logger_handle_s *handle, uint32_t level, stacktrace trace, const char *prefix);
void              debug_stacktrace_try_log(struct logger_handle_s *handle, uint32_t level, stacktrace trace);
void              debug_stacktrace_print(struct output_stream_s *os, stacktrace trace);
/**
 * clears all stacktraces from memory
 * should only be called at shutdown
 */
void debug_stacktrace_clear();

#define UNICITY_DEFINE(x)
#define UNICITY_ACQUIRE(x)
#define UNICITY_RELEASE(x)

#if DNSCORE_HAS_LIBC_MALLOC_DEBUG_SUPPORT

extern volatile size_t malloc_hook_total;
extern volatile size_t malloc_hook_malloc;
extern volatile size_t malloc_hook_free;
extern volatile size_t malloc_hook_realloc;
extern volatile size_t malloc_hook_memalign;

#endif

void  debug_malloc_hooks_init();
void  debug_malloc_hooks_finalize();

void *debug_malloc_unmonitored(size_t size);
void *debug_realloc_unmonitored(void *ptr, size_t size);
void  debug_free_unmonitored(void *ptr);
void *debug_memalign_unmonitored(size_t alignment, size_t size);

void  debug_malloc_hook_tracked_dump();
void  debug_malloc_hook_caller_dump();
void *debug_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);

void  debug_dump_page(void *ptr);

#define DBGMEMBY_TAG 0x59424d454d474244

struct debug_memory_by_tag_context_s;
typedef struct debug_memory_by_tag_context_s debug_memory_by_tag_context_t;

#if DNSCORE_DEBUG_HAS_BLOCK_TAG
debug_memory_by_tag_context_t *debug_memory_by_tag_new_instance(const char *name);
void                           debug_memory_by_tag_delete(debug_memory_by_tag_context_t *ctx);
void                           debug_memory_by_tag_init(debug_memory_by_tag_context_t *ctx, const char *name);
void                           debug_memory_by_tag_finalize(debug_memory_by_tag_context_t *ctx);
void                           debug_memory_by_tag_alloc_notify(debug_memory_by_tag_context_t *ctx, uint64_t tag, int64_t size);
void                           debug_memory_by_tag_free_notify(debug_memory_by_tag_context_t *ctx, uint64_t tag, int64_t size);
void                           debug_memory_by_tag_print(debug_memory_by_tag_context_t *ctx, struct output_stream_s *os);
#endif

void debug_memory_stat(int mask);

#ifdef __cplusplus
}
#endif

#endif /* _DEBUG_H */

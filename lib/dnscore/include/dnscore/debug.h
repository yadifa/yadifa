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

/** @defgroup debug Debug functions
 *  @ingroup dnscore
 *  @brief Debug functions.
 *
 *  Definitions of debug functions/hooks, mainly memory related.
 *
 *  THIS MEMORY DEBUGGER MUST BE INCLUDED WITH EVERY SINGLE (C) FILE.
 *  IF DEBUGGING MEMORY ALLOCATION IS USED, IT HAS TO BE ENABLED EVERYWHERE OR NOWHERE.
 *
 * @{
 */
#ifndef _DEBUG_H
#define	_DEBUG_H

#ifndef _SYSTYPES_H
#error PLEASE DO NOT INCLUDE debug.h DIRECTLY.  USE sys_types.h.
#endif

#define DEBUG_STAT_SIZES 1 // Common
#define DEBUG_STAT_TAGS  2 // Usefull
#define DEBUG_STAT_DUMP  4 // USE WITH CARE

#if DEBUG
#include <dnscore/thread.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
/** @note : DO NOT INCLUDE THIS HERE WITHOUT SOME KIND OF PROTECTION #include <dnscore/format.h> */



#include <dnscore/debug_config.h>

#if !DEBUG
#define yassert(x)
#else
void log_assert__(bool b, const char *txt, const char *file, int line);
#if !__clang_analyzer__
    #define yassert(cond__) log_assert__((cond__), #cond__, __FILE__, __LINE__);assert((cond__))
#else
    #define yassert(cond__) assert(cond__)
#endif
#endif

#ifdef	__cplusplus
extern "C" {
#endif
    
#define GENERIC_TAG 0x434952454e4547 /* GENERIC */
#define ZDB_STRDUP_TAG  0x505544525453 /* "STRDUP" */

void debug_dump(void* data_pointer_,size_t size,size_t line_size,bool hex,bool text);
void debug_dump_ex(void* data_pointer_, size_t size_, size_t line_size, bool hex, bool text, bool address);

struct logger_handle;

bool debug_log_stacktrace(struct logger_handle *handle, u32 level, const char *prefix);

#if DEBUG
/*
 * DO NOT FORGET THAT THE "L" FUNCTIONS DO REQUIRE A DEBUG_LEVEL #define
 * BEFORE THE "debug.h" INCLUDE !
 */
#define DEBUGLNF(...) osformatln(termerr,__VA_ARGS__)
#define DEBUGF(...) osformat(termerr,__VA_ARGS__)
#define OSDEBUG(term, ...) osformat((term),__VA_ARGS__)
#define LDEBUG(level, ...) if(DEBUG_LEVEL>=(level)) osformat(termerr,__VA_ARGS__)
#define OSLDEBUG(term, level, ...) if(DEBUG_LEVEL>=(level)) osformat((term),__VA_ARGS__)
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

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT

#ifndef MALLOC_OR_DIE
#error "something fishy is happening.  MALLOC_OR_DIE has not been defined yet."
#endif

#ifndef REALLOC_OR_DIE
#error "something fishy is happening.  REALLOC_OR_DIE has not been defined yet."
#endif

#undef MALLOC_OR_DIE
#undef REALLOC_OR_DIE

void* debug_malloc(
                    size_t size_,const char* file, int line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
                    ,u64 tag
#endif
                );

void* debug_calloc(
                    size_t size_,const char* file, int line
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
                    ,u64 tag
#endif
                );

void* debug_realloc(
		    void* ptr_,
                    size_t size_,
		    const char* file,
		    int line
                );

bool debug_mallocated(void* ptr);

#define assert_mallocated(ptr) yassert(debug_mallocated(ptr))

void debug_free(void* ptr,const char* file, int line);
void debug_mtest(void* ptr);

void debug_stat(int mask);
char* debug_strdup(const char*);

u32 debug_get_block_count();

#ifdef strdup
#undef strdup
#endif

#define strdup debug_strdup

#if !DNSCORE_DEBUG_HAS_BLOCK_TAG

#define malloc(len) debug_malloc((len),__FILE__,__LINE__)
#define calloc(len) debug_calloc((len),__FILE__,__LINE__)
#define free(p) debug_free((p),__FILE__,__LINE__)
#define realloc(p,len) debug_realloc((p),(len),__FILE__,__LINE__)

#define MALLOC_OR_DIE(cast,target,size,tag) if(((target)=(cast)debug_malloc(size,__FILE__,__LINE__))==NULL){perror(__FILE__);abort(); /* NOT TAGGED*/ }
#define REALLOC_OR_DIE(cast,src_and_target,newsize,tag) if(((src_and_target)=(cast)debug_realloc((src_and_target),(newsize),__FILE__,__LINE__))==NULL){perror(__FILE__);abort(); /* NOT TAGGED */ }
#else

#define ZDB_MALLOC_TAG	0x434f4c4c414d

#define malloc(len__) debug_malloc((len__),__FILE__,__LINE__,ZDB_MALLOC_TAG)
#define free(p__) debug_free((p__),__FILE__,__LINE__)
#define realloc(p__,len__) debug_realloc((p__),(len__),__FILE__,__LINE__)

#define MALLOC_OR_DIE(cast,target,size,tag) if(((target)=(cast)debug_malloc(size,__FILE__,__LINE__,(tag)))==NULL){perror(__FILE__);abort(); /* TAGGED */}
#define REALLOC_OR_DIE(cast,src_and_target,newsize,tag) if(((src_and_target)=(cast)debug_realloc((src_and_target),(newsize),__FILE__,__LINE__))==NULL){perror(__FILE__);abort(); /* NOT TAGGED */ }
#endif

#else

#define debug_mtest(x)
#define debug_stat(x)
#define debug_mallocated(x) TRUE
#define assert_mallocated(x)

/*
 * MALLOC_OR_DIE and REALLOC_OR_DIE have already been defined in sys_types.h
 */

#endif

struct debug_bench_s
{
    struct debug_bench_s *next;
    const char *name;
    u64 time_min;
    u64 time_max;
    u64 time_total;
    u64 time_count;
};

typedef struct debug_bench_s debug_bench_s;

// declares timeus()

s64 timeus();

void debug_bench_init();

void debug_bench_register(debug_bench_s *bench, const char *name);

#define debug_bench_start(bench__) timeus()

#define debug_bench_stop(bench__, from__) debug_bench_commit((bench__), timeus() - (from__));

void debug_bench_commit(debug_bench_s *bench, u64 delta);

void debug_bench_logdump_all();

void debug_bench_unregister_all();

typedef intptr* stacktrace;
struct output_stream;
struct logger_handle;
stacktrace debug_stacktrace_get();
void debug_stacktrace_log(struct logger_handle *handle, u32 level, stacktrace trace);
void debug_stacktrace_log_with_prefix(struct logger_handle* handle, u32 level, stacktrace trace, const char *prefix);
void debug_stacktrace_try_log(struct logger_handle *handle, u32 level, stacktrace trace);
void debug_stacktrace_print(struct output_stream *os, stacktrace trace);
/**
 * clears all stacktraces from memory
 * should only be called at shutdown
 */
void debug_stacktrace_clear();

#define UNICITY_DEFINE(x)
#define UNICITY_ACQUIRE(x)
#define UNICITY_RELEASE(x)

extern volatile size_t malloc_hook_total;
extern volatile size_t malloc_hook_malloc;
extern volatile size_t malloc_hook_free;
extern volatile size_t malloc_hook_realloc;
extern volatile size_t malloc_hook_memalign;

void debug_malloc_hooks_init();
void debug_malloc_hooks_finalize();
void *debug_malloc_unmonitored(size_t size);
void debug_free_unmonitored(void* ptr);
void debug_malloc_hook_tracked_dump();
void debug_malloc_hook_caller_dump();

void debug_nop_hook(); // meant

#ifdef	__cplusplus
}
#endif

#endif	/* _DEBUG_H */

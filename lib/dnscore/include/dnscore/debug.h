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

#ifdef DEBUG
#include <pthread.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
/** @note : DO NOT INCLUDE THIS HERE WITHOUT SOME KIND OF PROTECTION #include <dnscore/format.h> */



#include <dnscore/debug_config.h>

#if !defined(DEBUG)
#define yassert(x)
#else
void log_assert__(bool b, const char *txt, const char *file, int line);
#define yassert(cond__) log_assert__((cond__), #cond__, __FILE__, __LINE__);assert((cond__))
#endif

#ifdef	__cplusplus
extern "C" {
#endif
    
#define GENERIC_TAG 0x434952454e4547 /* GENERIC */
#define ZDB_STRDUP_TAG  0x505544525453 /* "STRDUP" */

void debug_dump(void* data_pointer_,size_t size,size_t line_size,bool hex,bool text);
void debug_dump_ex(void* data_pointer_, size_t size_, size_t line_size, bool hex, bool text, bool address);

struct logger_handle;

void debug_log_stacktrace(struct logger_handle *handle, u32 level, const char *prefix);

#ifdef DEBUG
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

#if ZDB_DEBUG_MALLOC!=0

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
#if ZDB_DEBUG_TAG_BLOCKS!=0
                    ,u64 tag
#endif
                );

void* debug_calloc(
                    size_t size_,const char* file, int line
#if ZDB_DEBUG_TAG_BLOCKS!=0
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
void debug_stat(bool dump);
char* debug_strdup(const char*);

u32 debug_get_block_count();

#ifdef strdup
#undef strdup
#endif

#define strdup debug_strdup

#if ZDB_DEBUG_TAG_BLOCKS == 0

#define malloc(len) debug_malloc((len),__FILE__,__LINE__)
#define calloc(len) debug_calloc((len),__FILE__,__LINE__)
#define free(p) debug_free((p),__FILE__,__LINE__)
#define realloc(p,len) debug_realloc((p),(len),__FILE__,__LINE__)

#define MALLOC_OR_DIE(cast,target,size,tag) if(((target)=(cast)debug_malloc(size,__FILE__,__LINE__))==NULL){perror(__FILE__);exit(EXIT_CODE_OUTOFMEMORY_ERROR); /* NOT TAGGED*/ }
#define REALLOC_OR_DIE(cast,src_and_target,newsize,tag) if(((src_and_target)=(cast)debug_realloc((src_and_target),(newsize),__FILE__,__LINE__))==NULL){perror(__FILE__);exit(EXIT_CODE_OUTOFMEMORY_ERROR); /* NOT TAGGED */ }
#else

#define ZDB_MALLOC_TAG	0x434f4c4c414d

#define malloc(len) debug_malloc((len),__FILE__,__LINE__,ZDB_MALLOC_TAG)
#define free(p) debug_free((p),__FILE__,__LINE__)
#define realloc(p,len) debug_realloc((p),(len),__FILE__,__LINE__)

#define MALLOC_OR_DIE(cast,target,size,tag) if(((target)=(cast)debug_malloc(size,__FILE__,__LINE__,(tag)))==NULL){perror(__FILE__);exit(EXIT_CODE_OUTOFMEMORY_ERROR); /* TAGGED */}
#define REALLOC_OR_DIE(cast,src_and_target,newsize,tag) if(((src_and_target)=(cast)debug_realloc((src_and_target),(newsize),__FILE__,__LINE__))==NULL){perror(__FILE__);exit(EXIT_CODE_OUTOFMEMORY_ERROR); /* NOT TAGGED */ }
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

#ifdef DEBUG

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

u64 timeus();

void debug_bench_register(debug_bench_s *bench, const char *name);

#define debug_bench_start(bench__) timeus()

#define debug_bench_stop(bench__, from__) debug_bench_commit((bench__), timeus() - (from__));

void debug_bench_commit(debug_bench_s *bench, u64 delta);

void debug_bench_logdump_all();

#endif

#ifdef DEBUG

/*
 * These debugging tools ensure that ONE and only ONE thread is working on the structure.
 * It detects race issues.
 */

typedef struct debug_unicity debug_unicity;

struct debug_unicity
{
    pthread_mutex_t mutex;
    u8 counter;
};

void debug_unicity_init(debug_unicity *dus);
void debug_unicity_acquire(debug_unicity *dus);
void debug_unicity_release(debug_unicity *dus);
/* No, they are never destroyed */


#define UNICITY_DEFINE(x)   static debug_unicity debug_unicity##x = {PTHREAD_MUTEX_INITIALIZER, 0};
#define UNICITY_ACQUIRE(x)  debug_unicity_acquire(&debug_unicity##x);
#define UNICITY_RELEASE(x)  debug_unicity_release(&debug_unicity##x);

#else

#define UNICITY_DEFINE(x)
#define UNICITY_ACQUIRE(x)
#define UNICITY_RELEASE(x)

#endif

/*
 * This is a helper for valgrind
 * Reads the bytes and prints them using putchar
 * Called to hunt unintialised bytes
 */

void debug_vg(const void* b, int len);

#ifdef	__cplusplus
}
#endif

#endif	/* _DEBUG_H */


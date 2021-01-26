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
 * 
 * @{
 */

#pragma once

#include <dnscore/dnscore-config-features.h>
#include <dnscore/thread.h>
#include <dnscore/config_settings.h>
#include <dnscore/sys_types.h>
#include <dnscore/debug.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef DNSCORE_HAS_ZALLOC_SUPPORT
#error "DNSCORE_HAS_ZALLOC_SUPPORT should be set to 1 or 0"
#endif
        
#if !DNSCORE_HAS_ZALLOC_SUPPORT

/**
 * Uses malloc to mimmick zalloc_unaligned.  Source is in zalloc.c.
 * 
 * @param len
 * @param tag
 * @return 
 */
    
void *malloc_string_or_die(size_t len, u64 tag);

/**
 * Uses malloc to mimmick zfree_unaligned.  Source is in zalloc.c.
 * 
 * @param ptr
 */

void mfree_string(void *ptr);

/* 8 bytes aligned */

static inline size_t zalloc_memory_block_size(size_t size)
{
    return size;
}

static inline void free_erases(void *ptr, size_t size)
{
    if(ptr != NULL)
    {
        memset(ptr, 0xfe, size);
    }
    free(ptr);
}

#if DEBUG
#define ZFREE(label,object) free_erases(label, sizeof(object))
#else
#define ZFREE(label,object) free(label)
#endif

#define ZALLOC_ARRAY_OR_DIE(cast_,label_,size_,tag_) MALLOC_OR_DIE(cast_,label_,size_,tag_);assert((label_) != NULL)
#if DEBUG
#define ZFREE_ARRAY(ptr_,size_) free_erases((ptr_),(size_))
#else
#define ZFREE_ARRAY(ptr_,size_) free(ptr_)
#endif

// preferred way of allocating one instance of a type (struct, ...)
#define ZALLOC_OBJECT_OR_DIE(label__,object__,tag__) MALLOC_OBJECT_OR_DIE(label__, object__, tag__);assert((label__) != NULL)
#define ZALLOC_OBJECT_ARRAY_OR_DIE(label__,object__, count__,tag__) MALLOC_OBJECT_ARRAY_OR_DIE(label__, object__, count__, tag__);assert((label__) != NULL)

#define ZALLOC_ARRAY_RESIZE(type_,array_,count_,newcount_)		    \
    {									    \
	int zalloc_new_count = (newcount_);				    \
	(array_) = (type_*)realloc((array_),zalloc_new_count*sizeof(type_));\
	(count_) = zalloc_new_count;					    \
    }

#define ZFREE_OBJECT(label__) free((label__))
#define ZFREE_OBJECT_OF_TYPE(label__,type__) free(label__)

#else

/**
 * ZALLOC_PG_SIZE_COUNT tells how many memory sizes are supported, with 8 bytes increments.
 * Setting this up involves some computation and bigger numbers may lead to unmanagable amounts of memory.
 * The current setting (256 = 2K) should be enough for most structures.
 * Exceptions like message_data should be on stack or mallocated any maybe in a pool too.
 * 
 * I feel more and more that this allocator could and should be put in the core.
 * The logger could benefit greatly from it. (although I don't know if I'd use
 * it like this or by forcing an higher granularity like 32 or 64 to avoid mapping too many slots.)
 * 
 */
   
#define ZALLOC_PG_SIZE_COUNT         256 // 2K
#define ZALLOC_PG_PAGEABLE_MAXSIZE   (ZALLOC_PG_SIZE_COUNT * 8) /* x 8 because we are going by 8 increments */
#define ZALLOC_SIZE_TO_PAGE(size_)  ((s32)(((size_)-1)>>3))
#define ZALLOC_CANHANDLE(size_)      (((s32)(size_))<=ZALLOC_PG_PAGEABLE_MAXSIZE)

// prepares the zalloc tables
    
int zalloc_init();

// actually does nothing, just there for symmetry

void zalloc_finalize();
    
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

void* zalloc_line(u32 page_index);

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

void zfree_line(void* ptr, u32 page_index);

/**
 * DEBUG
 */

u64 zheap_line_total(u32 page);
u64 zheap_line_avail(u32 page);

/**
 * zalloc_set_owner_thread made sense when it was not thread-safe.
 * Now this does nothing
 */

static inline void zalloc_set_owner_thread(thread_t owner) {(void)owner;}

static inline void* zalloc(s32 size)
{
    u32 page = ZALLOC_SIZE_TO_PAGE(size);
    void* ptr;

    if(page < ZALLOC_PG_SIZE_COUNT)
    {
        ptr = zalloc_line(ZALLOC_SIZE_TO_PAGE(size));
    }
    else
    {
        ptr = malloc(size);
    }

    return ptr;
}

static inline void zfree(void* ptr, s32 size)
{
    u32 page = ZALLOC_SIZE_TO_PAGE(size);

    if(page < ZALLOC_PG_SIZE_COUNT)
    {
        zfree_line(ptr,ZALLOC_SIZE_TO_PAGE(size));
    }
    else
    {
        free(ptr);
    }
}

/**
 * 
 * Only works if --enable-zalloc-statistics has been set with ./configure
 * 
 * @return the number of bytes allocated in the zalloc memory system, or -1 if the statistics are not enabled
 */

s64 zallocatedtotal();

/**
 * @brief Allocates unaligned memory of an arbitrary size using zalloc_line and malloc
 *
 * Allocates unaligned memory of an arbitrary size using zalloc_line and malloc
 *
 * @param[in] size the size to allocated
 *
 * @return a pointer to the allocated memory
 */

void* zalloc_unaligned(u32 size);

/**
 * @brief Frees unaligned memory of an arbitrary size using zfree_line and free
 *
 * Allocates unaligned memory of an arbitrary size using zalloc_line and malloc
 *
 * @param[in] ptr a pointer to the memory to free
 *
 */

void zfree_unaligned(void* ptr);

/* 
 * THIS SHOULD BE OPTIMIZED BY THE COMPILER AS ONE AND ONLY ONE CALL
 */

static inline size_t zalloc_memory_block_size(size_t size)
{
    return (size + 7) & ~7;
}

void* zalloc_line(u32 page_index);

#define ZALLOC_OBJECT(object__) ((((sizeof(object__) + 7) >> 3)-1) < ZALLOC_PG_SIZE_COUNT)?zalloc_line(((sizeof(object__) + 7) >> 3)-1):malloc(sizeof(object__))
#define ZFREE(ptr,object__) ((((sizeof(object__) + 7) >> 3)-1) < ZALLOC_PG_SIZE_COUNT)?zfree_line(ptr,(((sizeof(object__) + 7) >> 3)-1)):free(ptr)

#define ZALLOC_BYTES(size__) ((((((size__) + 7) >> 3)-1) < ZALLOC_PG_SIZE_COUNT)?zalloc_line((((size__) + 7) >> 3)-1):malloc((size__)))
#define ZALLOC_ARRAY_OR_DIE(cast,label,size_,tag) if((label = (cast)zalloc(size_)) == NULL) {DIE(ZALLOC_ERROR_OUTOFMEMORY); } assert((label) != NULL)
#define ZFREE_ARRAY(ptr,size_) zfree(ptr,size_)
// preferred way of allocating one instance of a type (struct, ...)
#define ZALLOC_OBJECT_OR_DIE(label__,object__,tag__) if((label__=(object__*)ZALLOC_OBJECT(object__))==NULL) {DIE(ZALLOC_ERROR_OUTOFMEMORY); } assert((label__) != NULL)
#define ZALLOC_OBJECT_ARRAY_OR_DIE(label__,object__,count__,tag__) if((label__=(object__*)ZALLOC_BYTES(sizeof(object__)*(count__)))==NULL) {DIE(ZALLOC_ERROR_OUTOFMEMORY); } assert((label__) != NULL)
#define ZFREE_OBJECT(label__) zfree((label__), sizeof(*(label__)))
#define ZFREE_OBJECT_OF_TYPE(label__,type__) zfree((label__), sizeof(type__))
/**
 * (Z)Allocates a new array of count type elements so it can hold
 * newcount type elements. (It takes granularity into account to avoid
 * unnecessary work)
 * 
 * If the array is smaller, the end is truncated
 * If the new count is zero the array is deleted.
 *
 * After the macro, array_ and count_ are changed so don't use consts.
 *
 * This helper is meant to be used by NSEC3 structures
 */

#define ZALLOC_ARRAY_RESIZE_TAG 0x44455a49534552 /* RESIZED */

#define ZALLOC_ARRAY_RESIZE(type_,array_,count_,newcount_)			\
{										\
    u32 zalloc_new_count = (u32)(newcount_);					\
    if(((u32)(count_)) != zalloc_new_count)			                \
    {							                        \
	if( ZALLOC_SIZE_TO_PAGE(sizeof(type_)*((u32)(count_))) !=               \
	    ZALLOC_SIZE_TO_PAGE(sizeof(type_)*zalloc_new_count))		\
	{									\
	    type_* __tmp__;							\
										\
	    if(zalloc_new_count > 0)						\
	    {									\
		ZALLOC_ARRAY_OR_DIE(type_*,__tmp__,sizeof(type_)*zalloc_new_count, ZALLOC_ARRAY_RESIZE_TAG); \
		MEMCOPY(__tmp__,(array_),sizeof(type_)*MIN((u32)(count_),zalloc_new_count)); \
	    }									\
	    else								\
	    {									\
		__tmp__ = NULL;							\
	    }									\
										\
	    ZFREE_ARRAY((array_),sizeof(type_)*((u32)(count_)));		\
	    array_ = __tmp__;							\
	    count_ = newcount_;							\
	}									\
    }										\
    assert(array_ != NULL);                                                     \
}

#endif

struct output_stream;
void zalloc_print_stats(struct output_stream *os);

#ifdef	__cplusplus
}
#endif

/** @} */

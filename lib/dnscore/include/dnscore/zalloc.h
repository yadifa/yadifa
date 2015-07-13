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
 * The database specialized allocation function
 * Which basically mean either I find a (very fast) way to use different memory pools
 * (one for each thread) either I can only use these allocations with the core
 * database : not the signer.
 *
 * Its no big deal, but its very important to remember this.
 *
 * @{
 */

#pragma once

#include <pthread.h>
#include <dnscore/dnscore-config-features.h>
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

/* 8 bytes aligned */
#define ZALLOC_OR_DIE(cast,label,object,tag) MALLOC_OR_DIE(cast,label,sizeof(object),tag);assert((label) != NULL)
#define ZFREE(label,object) free(label)

#define ZALLOC_ARRAY_OR_DIE(cast,label,size,tag) MALLOC_OR_DIE(cast,label,size,tag);assert((label) != NULL)
#define ZFREE_ARRAY(ptr,size_) (void)(size_);free(ptr)

/* not aligned, max size 256 */
#define ZALLOC_STRING_OR_DIE(cast,label,size,tag) MALLOC_OR_DIE(cast,label,size,tag);assert((label) != NULL)
#define ZFREE_STRING(label) free(label)

#define ZALLOC_ARRAY_RESIZE(type_,array_,count_,newcount_)		    \
    {									    \
	int zalloc_new_count = (newcount_);				    \
	(array_) = (type_*)realloc((array_),zalloc_new_count*sizeof(type_));\
	(count_) = zalloc_new_count;					    \
    }

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

void zalloc_finalise();
    
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

static inline void zalloc_set_owner_thread(pthread_t owner) {(void)owner;}

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

#define ZALLOC_STRING_OR_DIE(cast,label,size,tag) label=(cast)zalloc_unaligned(size)
#define ZFREE_STRING(label) zfree_unaligned(label)

/* 
 * THIS SHOULD BE OPTIMIZED BY THE COMPILER AS ONE AND ONLY ONE CALL
 */

#define ZALLOC(object) ((((sizeof(object) + 7) >> 3)-1) < ZALLOC_PG_SIZE_COUNT)?zalloc_line(((sizeof(object) + 7) >> 3)-1):malloc(sizeof(object))
#define ZFREE(ptr,object) ((((sizeof(object) + 7) >> 3)-1) < ZALLOC_PG_SIZE_COUNT)?zfree_line(ptr,(((sizeof(object) + 7) >> 3)-1)):free(ptr)
#define ZALLOC_OR_DIE(cast,label,object,tag) if((label=(cast)ZALLOC(object))==NULL) {DIE(ZALLOC_ERROR_OUTOFMEMORY); } assert((label) != NULL)
#define ZALLOC_ARRAY_OR_DIE(cast,label,size_,tag) if((label = (cast)zalloc(size_)) == NULL) {DIE(ZALLOC_ERROR_OUTOFMEMORY); } assert((label) != NULL)
#define ZFREE_ARRAY(ptr,size_) zfree(ptr,size_)

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

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
 * The database specialized allocation function
 *
 * NOTE: THIS IS NOT THREAD-SAFE
 * NOTE: THIS IS NOT THREAD-SAFE
 * NOTE: THIS IS NOT THREAD-SAFE
 * NOTE: THIS IS NOT THREAD-SAFE
 * NOTE: THIS IS NOT THREAD-SAFE
 *
 * Which basically mean either I find a (very fast) way to use different memory pools
 * (one for each thread) either I can only use these allocations with the core
 * database : not the signer.
 *
 * Its no big deal, but its very important to remember this.
 *
 * @{
 */

#ifndef _ZALLOC_H
#define	_ZALLOC_H

#include <pthread.h>
#include <dnscore/sys_types.h>
#include <dnsdb/zdb_config.h>
#include <dnsdb/zdb_error.h>
#include <dnscore/debug.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if ZDB_USES_ZALLOC==0

/* 8 bytes aligned */
#define ZALLOC_OR_DIE(cast,label,object,tag) MALLOC_OR_DIE(cast,label,sizeof(object),tag)
#define ZFREE(label,object) free(label)

#define ZALLOC_ARRAY_OR_DIE(cast,label,size,tag) MALLOC_OR_DIE(cast,label,size,tag)
#define ZFREE_ARRAY(ptr,size_) free(ptr);(void)(size_)

/* not aligned, max size 256 */
#define ZALLOC_STRING_OR_DIE(cast,label,size,tag) MALLOC_OR_DIE(cast,label,size,tag)
#define ZFREE_STRING(label) free(label)

#define ZALLOC_ARRAY_RESIZE(type_,array_,count_,newcount_)		    \
    {									    \
	int zalloc_new_count = (newcount_);				    \
	(array_) = (type_*)realloc((array_),zalloc_new_count*sizeof(type_));\
	(count_) = zalloc_new_count;					    \
    }

#else

#define ZDB_ALLOC_PG_SIZE_COUNT         32
#define ZDB_ALLOC_PG_PAGEABLE_MAXSIZE   (ZDB_ALLOC_PG_SIZE_COUNT * 8) /* x 8 because we are going by 8 increments */
#define ZDB_MALLOC_SIZE_TO_PAGE(size_)  (((size_)-1)>>3)
#define ZDB_ALLOC_CANHANDLE(size_)      ((size_)<=ZDB_ALLOC_PG_PAGEABLE_MAXSIZE)

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

void* zdb_malloc(u32 page_index);

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

void zdb_mfree(void* ptr, u32 page_index);

/**
 * DEBUG
 */

u64 zdb_mheap(u32 page);
u64 zdb_mavail(u32 page);

#ifndef _ZALLOC_C
extern pthread_t zalloc_owner;
#endif

void zdb_set_zowner(pthread_t owner);

static inline void* zalloc(s32 size)
{
#if ZDB_ZALLOC_THREAD_SAFE == 0
    zassert(pthread_self() == zalloc_owner);
#endif

    u32 page = ZDB_MALLOC_SIZE_TO_PAGE(size);
    void* ptr;

    if(page < ZDB_ALLOC_PG_SIZE_COUNT)
    {
	ptr = zdb_malloc(ZDB_MALLOC_SIZE_TO_PAGE(size));
    }
    else
    {
	ptr = malloc(size);
    }

    return ptr;
}

static inline void zfree(void* ptr, s32 size)
{
#if ZDB_ZALLOC_THREAD_SAFE == 0
    zassert(pthread_self() == zalloc_owner);
#endif
    
    u32 page = ZDB_MALLOC_SIZE_TO_PAGE(size);

    if(page < ZDB_ALLOC_PG_SIZE_COUNT)
    {
	zdb_mfree(ptr,ZDB_MALLOC_SIZE_TO_PAGE(size));
    }
    else
    {
	free(ptr);
    }
}

#if ZDB_ZALLOC_STATISTICS!=0
u64 zdb_mused();
#else
#define zdb_mused() 0
#endif

/**
 * @brief Allocates unaligned memory of an arbitrary size using zdb_malloc and malloc
 *
 * Allocates unaligned memory of an arbitrary size using zdb_malloc and malloc
 *
 * @param[in] size the size to allocated
 *
 * @return a pointer to the allocated memory
 */

void* zdb_malloc_unaligned(u32 size);

/**
 * @brief Frees unaligned memory of an arbitrary size using zdb_mfree and free
 *
 * Allocates unaligned memory of an arbitrary size using zdb_malloc and malloc
 *
 * @param[in] ptr a pointer to the memory to free
 *
 */

void zdb_mfree_unaligned(void* ptr);

#define ZALLOC_STRING_OR_DIE(cast,label,size,tag) label=(cast)zdb_malloc_unaligned(size)
#define ZFREE_STRING(label) zdb_mfree_unaligned(label)

/* 
 * THIS WILL BE OPTIMIZED BY THE COMPILER AS ONE AND ONLY ONE CALL
 *
 */

#define ZALLOC(object)                            \
    (sizeof(object)<= 8)?zdb_malloc(0):           \
    (sizeof(object)<=16)?zdb_malloc(1):           \
    (sizeof(object)<=24)?zdb_malloc(2):           \
    (sizeof(object)<=32)?zdb_malloc(3):           \
    (sizeof(object)<=40)?zdb_malloc(4):           \
    (sizeof(object)<=48)?zdb_malloc(5):           \
    (sizeof(object)<=56)?zdb_malloc(6):           \
    (sizeof(object)<=64)?zdb_malloc(7):           \
    (sizeof(object)<=72)?zdb_malloc(8):           \
    (sizeof(object)<=80)?zdb_malloc(9):           \
    (sizeof(object)<=88)?zdb_malloc(10):          \
    (sizeof(object)<=96)?zdb_malloc(11):          \
    (sizeof(object)<=104)?zdb_malloc(12):         \
    (sizeof(object)<=112)?zdb_malloc(13):         \
    (sizeof(object)<=120)?zdb_malloc(14):         \
    (sizeof(object)<=128)?zdb_malloc(15):         \
    (sizeof(object)<=136)?zdb_malloc(16):         \
    (sizeof(object)<=144)?zdb_malloc(17):         \
    (sizeof(object)<=152)?zdb_malloc(18):         \
    (sizeof(object)<=160)?zdb_malloc(19):         \
    (sizeof(object)<=168)?zdb_malloc(20):         \
    (sizeof(object)<=176)?zdb_malloc(21):         \
    (sizeof(object)<=184)?zdb_malloc(22):         \
    (sizeof(object)<=192)?zdb_malloc(23):         \
    (sizeof(object)<=200)?zdb_malloc(24):         \
    (sizeof(object)<=208)?zdb_malloc(25):         \
    (sizeof(object)<=216)?zdb_malloc(26):         \
    (sizeof(object)<=224)?zdb_malloc(27):         \
    (sizeof(object)<=232)?zdb_malloc(28):         \
    (sizeof(object)<=240)?zdb_malloc(29):         \
    (sizeof(object)<=248)?zdb_malloc(30):         \
    (sizeof(object)<=256)?zdb_malloc(31):         \
    malloc(sizeof(object));

#define ZFREE(ptr,object)                         \
    (sizeof(object)<= 8)?zdb_mfree(ptr,0):        \
    (sizeof(object)<=16)?zdb_mfree(ptr,1):        \
    (sizeof(object)<=24)?zdb_mfree(ptr,2):        \
    (sizeof(object)<=32)?zdb_mfree(ptr,3):        \
    (sizeof(object)<=40)?zdb_mfree(ptr,4):        \
    (sizeof(object)<=48)?zdb_mfree(ptr,5):        \
    (sizeof(object)<=56)?zdb_mfree(ptr,6):        \
    (sizeof(object)<=64)?zdb_mfree(ptr,7):        \
    (sizeof(object)<=72)?zdb_mfree(ptr,8):        \
    (sizeof(object)<=80)?zdb_mfree(ptr,9):        \
    (sizeof(object)<=88)?zdb_mfree(ptr,10):       \
    (sizeof(object)<=96)?zdb_mfree(ptr,11):       \
    (sizeof(object)<=104)?zdb_mfree(ptr,12):      \
    (sizeof(object)<=112)?zdb_mfree(ptr,13):      \
    (sizeof(object)<=120)?zdb_mfree(ptr,14):      \
    (sizeof(object)<=128)?zdb_mfree(ptr,15):      \
    (sizeof(object)<=136)?zdb_mfree(ptr,16):      \
    (sizeof(object)<=144)?zdb_mfree(ptr,17):      \
    (sizeof(object)<=152)?zdb_mfree(ptr,18):      \
    (sizeof(object)<=160)?zdb_mfree(ptr,19):      \
    (sizeof(object)<=168)?zdb_mfree(ptr,20):      \
    (sizeof(object)<=176)?zdb_mfree(ptr,21):      \
    (sizeof(object)<=184)?zdb_mfree(ptr,22):      \
    (sizeof(object)<=192)?zdb_mfree(ptr,23):      \
    (sizeof(object)<=200)?zdb_mfree(ptr,24):      \
    (sizeof(object)<=208)?zdb_mfree(ptr,25):      \
    (sizeof(object)<=216)?zdb_mfree(ptr,26):      \
    (sizeof(object)<=224)?zdb_mfree(ptr,27):      \
    (sizeof(object)<=232)?zdb_mfree(ptr,28):      \
    (sizeof(object)<=240)?zdb_mfree(ptr,29):      \
    (sizeof(object)<=248)?zdb_mfree(ptr,30):      \
    (sizeof(object)<=256)?zdb_mfree(ptr,31):      \
    free(ptr);

#define ZALLOC_OR_DIE(cast,label,object,tag)                     \
    if(sizeof(object)<=  8) { label=(cast)zdb_malloc( 0); } else \
    if(sizeof(object)<= 16) { label=(cast)zdb_malloc( 1); } else \
    if(sizeof(object)<= 24) { label=(cast)zdb_malloc( 2); } else \
    if(sizeof(object)<= 32) { label=(cast)zdb_malloc( 3); } else \
    if(sizeof(object)<= 40) { label=(cast)zdb_malloc( 4); } else \
    if(sizeof(object)<= 48) { label=(cast)zdb_malloc( 5); } else \
    if(sizeof(object)<= 56) { label=(cast)zdb_malloc( 6); } else \
    if(sizeof(object)<= 64) { label=(cast)zdb_malloc( 7); } else \
    if(sizeof(object)<= 72) { label=(cast)zdb_malloc( 8); } else \
    if(sizeof(object)<= 80) { label=(cast)zdb_malloc( 9); } else \
    if(sizeof(object)<= 88) { label=(cast)zdb_malloc(10); } else \
    if(sizeof(object)<= 96) { label=(cast)zdb_malloc(11); } else \
    if(sizeof(object)<=104) { label=(cast)zdb_malloc(12); } else \
    if(sizeof(object)<=112) { label=(cast)zdb_malloc(13); } else \
    if(sizeof(object)<=120) { label=(cast)zdb_malloc(14); } else \
    if(sizeof(object)<=128) { label=(cast)zdb_malloc(15); } else \
    if(sizeof(object)<=136) { label=(cast)zdb_malloc(16); } else \
    if(sizeof(object)<=144) { label=(cast)zdb_malloc(17); } else \
    if(sizeof(object)<=152) { label=(cast)zdb_malloc(18); } else \
    if(sizeof(object)<=160) { label=(cast)zdb_malloc(19); } else \
    if(sizeof(object)<=168) { label=(cast)zdb_malloc(20); } else \
    if(sizeof(object)<=176) { label=(cast)zdb_malloc(21); } else \
    if(sizeof(object)<=184) { label=(cast)zdb_malloc(22); } else \
    if(sizeof(object)<=192) { label=(cast)zdb_malloc(23); } else \
    if(sizeof(object)<=200) { label=(cast)zdb_malloc(24); } else \
    if(sizeof(object)<=208) { label=(cast)zdb_malloc(25); } else \
    if(sizeof(object)<=216) { label=(cast)zdb_malloc(26); } else \
    if(sizeof(object)<=224) { label=(cast)zdb_malloc(27); } else \
    if(sizeof(object)<=232) { label=(cast)zdb_malloc(28); } else \
    if(sizeof(object)<=240) { label=(cast)zdb_malloc(29); } else \
    if(sizeof(object)<=248) { label=(cast)zdb_malloc(30); } else \
    if(sizeof(object)<=256) { label=(cast)zdb_malloc(31); } else \
    if((label=(cast)malloc(sizeof(object)))==NULL) {DIE(ZDB_ERROR_OUTOFMEMORY); }

#define ZALLOC_ARRAY_OR_DIE(cast,label,size_,tag) \
    if((label = (cast)zalloc(size_)) == NULL) {DIE(ZDB_ERROR_OUTOFMEMORY); }

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

#define ZALLOC_ARRAY_RESIZE(type_,array_,count_,newcount_)			                                            \
{										                                                                        \
    u32 zalloc_new_count = (newcount_);						                                                    \
    if((count_) != zalloc_new_count)						                                                    \
    {										                                                                    \
    	if( ZDB_MALLOC_SIZE_TO_PAGE(sizeof(type_)*(count_)) !=                                                  \
	        ZDB_MALLOC_SIZE_TO_PAGE(sizeof(type_)*zalloc_new_count))		                                    \
    	{									                                                                    \
	        type_* __tmp__;							                                                            \
										                                                                        \
    	    if(zalloc_new_count > 0)						                                                    \
	        {									                                                                \
        		ZALLOC_ARRAY_OR_DIE(type_*,__tmp__,sizeof(type_)*zalloc_new_count, ZALLOC_ARRAY_RESIZE_TAG);    \
		        MEMCOPY(__tmp__,(array_),sizeof(type_)*MIN((count_),zalloc_new_count));	                        \
    	    }									                                                                \
	        else								                                                                \
	        {									                                                                \
    		    __tmp__ = NULL;							                                                        \
	        }									                                                                \
    										                                                                    \
	        ZFREE_ARRAY((array_),sizeof(type_)*(count_));			                                            \
	        array_ = __tmp__;							                                                        \
    	    count_ = newcount_;							                                                        \
    	}									                                                                    \
    }										                                                                    \
}

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _ZALLOC_H */

/** @} */

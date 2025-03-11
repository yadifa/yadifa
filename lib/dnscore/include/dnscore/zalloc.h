/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 * @defgroup zalloc very fast, no-overhead specialised memory allocation functions
 * @ingroup dnscore
 * @brief no-overhead specialised allocation functions
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
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/dnscore_config_features.h>
#include <dnscore/thread.h>
#include <dnscore/sys_types.h>
#include <dnscore/debug.h>

#ifdef __cplusplus
extern "C"
{
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

void *malloc_string_or_die(size_t len, uint64_t tag);

/**
 * Uses malloc to mimmick zfree_unaligned.  Source is in zalloc.c.
 *
 * @param ptr
 */

void mfree_string(void *ptr);

/* 8 bytes aligned */

static inline size_t zalloc_memory_block_size(size_t size) { return size; }

static inline void   free_erases(void *ptr, size_t size)
{
    if(ptr != NULL)
    {
        memset(ptr, 0xfe, size);
    }
    free(ptr);
}

#if DEBUG
#define ZFREE(label, object) free_erases(label, sizeof(object))
#else
#define ZFREE(label, object) free(label)
#endif

#define ZALLOC_ARRAY_OR_DIE(cast_, label_, size_, tag_)                                                                                                                                                                                        \
    MALLOC_OR_DIE(cast_, label_, size_, tag_);                                                                                                                                                                                                 \
    assert((label_) != NULL)
#if DEBUG
#define ZFREE_ARRAY(ptr_, size_) free_erases((ptr_), (size_))
#else
static inline void free_ignored_size(void *ptr, size_t size)
{
    (void)size;
    free(ptr);
}
#define ZFREE_ARRAY(ptr_, size_) free_ignored_size(ptr_, size_)
#endif

// preferred way of allocating one instance of a type (struct, ...)
#define ZALLOC_OBJECT_OR_DIE(label__, object__, tag__)                                                                                                                                                                                         \
    MALLOC_OBJECT_OR_DIE(label__, object__, tag__);                                                                                                                                                                                            \
    assert((label__) != NULL)
#define ZALLOC_OBJECT_ARRAY_OR_DIE(label__, object__, count__, tag__)                                                                                                                                                                          \
    MALLOC_OBJECT_ARRAY_OR_DIE(label__, object__, count__, tag__);                                                                                                                                                                             \
    assert((label__) != NULL)

#define ZALLOC_ARRAY_RESIZE(type_, array_, count_, newcount_)                                                                                                                                                                                  \
    {                                                                                                                                                                                                                                          \
        int zalloc_new_count = (newcount_);                                                                                                                                                                                                    \
        (array_) = (type_ *)realloc((array_), zalloc_new_count * sizeof(type_));                                                                                                                                                               \
        (count_) = zalloc_new_count;                                                                                                                                                                                                           \
    }

#define ZFREE_OBJECT(label__)                 free((label__))
#define ZFREE_OBJECT_OF_TYPE(label__, type__) free(label__)

static inline void *zalloc_bytes_malloc(size_t size, uint64_t tag)
{
    (void)tag;
    void *ret = malloc(size);
    return ret;
}

static inline void zfree_bytes_free(void *ptr, size_t size)
{
    (void)size;
    free(ptr);
}

#define ZALLOC_BYTES(size__, tag__) zalloc_bytes_malloc((size__), (tag__))
#define ZFREE_BYTES(ptr__, size__)  zfree_bytes_free((ptr__), (size__))

#else // DNSCORE_HAS_ZALLOC_SUPPORT

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

#define ZALLOC_PG_SIZE_COUNT 256 // 2K

#if DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT
#if DNSCORE_DEBUG_HAS_BLOCK_TAG
#define ZALLOC_PG_SIZE_COUNT_EFFECTIVE (ZALLOC_PG_SIZE_COUNT - 2)
#else
#define ZALLOC_PG_SIZE_COUNT_EFFECTIVE (ZALLOC_PG_SIZE_COUNT - 1)
#endif
#else
#define ZALLOC_PG_SIZE_COUNT_EFFECTIVE ZALLOC_PG_SIZE_COUNT
#endif

#define ZALLOC_PG_PAGEABLE_MAXSIZE (ZALLOC_PG_SIZE_COUNT_EFFECTIVE * 8) /* x 8 because we are going by 8 increments */
#define ZALLOC_SIZE_TO_PAGE(size_) ((int32_t)(((size_) - 1) >> 3))
#define ZALLOC_CANHANDLE(size_)    (((int32_t)(size_)) <= ZALLOC_PG_PAGEABLE_MAXSIZE)

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

void *zalloc_line(uint32_t page_index
#if DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_HAS_BLOCK_TAG
                  ,
                  uint64_t tag
#endif
);

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

void zfree_line(void *ptr, uint32_t page_index);

/**
 * DEBUG
 */

uint64_t zheap_line_total(uint32_t page);
uint64_t zheap_line_avail(uint32_t page);

/**
 * zalloc_set_owner_thread made sense when it was not thread-safe.
 * Now this does nothing
 */

static inline void  zalloc_set_owner_thread(thread_t owner) { (void)owner; }

static inline void *zalloc(int32_t size
#if DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_HAS_BLOCK_TAG
                           ,
                           uint64_t tag
#endif
)
{
    uint32_t page = ZALLOC_SIZE_TO_PAGE(size);
    void    *ptr;

    if(page < ZALLOC_PG_SIZE_COUNT_EFFECTIVE)
    {
        ptr = zalloc_line(ZALLOC_SIZE_TO_PAGE(size)
#if DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_HAS_BLOCK_TAG
                              ,
                          tag
#endif
        );
    }
    else
    {
        ptr = malloc(size);
    }

    return ptr;
}

static inline void zfree(void *ptr, int32_t size)
{
    uint32_t page = ZALLOC_SIZE_TO_PAGE(size);

#if DEBUG
#if DNSCORE_DEBUG_MALLOC_TRASHMEMORY
    memset(ptr, 0xfe, size);
#endif
#endif

    if(page < ZALLOC_PG_SIZE_COUNT_EFFECTIVE)
    {
        zfree_line(ptr, ZALLOC_SIZE_TO_PAGE(size));
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

int64_t zallocatedtotal();

/**
 * @brief Allocates unaligned memory of an arbitrary size using zalloc_line and malloc
 *
 * Allocates unaligned memory of an arbitrary size using zalloc_line and malloc
 *
 * @param[in] size the size to allocated
 *
 * @return a pointer to the allocated memory
 */

void *zalloc_unaligned(uint32_t size
#if DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_HAS_BLOCK_TAG
                       ,
                       uint64_t tag
#endif
);

/**
 * @brief Frees unaligned memory of an arbitrary size using zfree_line and free
 *
 * Allocates unaligned memory of an arbitrary size using zalloc_line and malloc
 *
 * @param[in] ptr a pointer to the memory to free
 *
 */

void zfree_unaligned(void *ptr);

/*
 * THIS SHOULD BE OPTIMIZED BY THE COMPILER AS ONE AND ONLY ONE CALL
 */

static inline size_t zalloc_memory_block_size(size_t size) { return (size + 7) & ~7; }

#define ZALLOC_SIZE_TO_LINE(size__)    ((uint32_t)((((size__) + 7) >> 3) - 1))
#define ZALLOC_TYPE_TO_LINE(object__)  ZALLOC_SIZE_TO_LINE(sizeof(object__))
#define ZALLOC_TYPE_HAS_LINE(object__) (ZALLOC_TYPE_TO_LINE(object__) < ZALLOC_PG_SIZE_COUNT_EFFECTIVE)
#define ZALLOC_SIZE_HAS_LINE(size__)   (ZALLOC_SIZE_TO_LINE((size__)) < ZALLOC_PG_SIZE_COUNT_EFFECTIVE)

#if DNSCORE_HAS_ZALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_HAS_BLOCK_TAG

#if DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
void *debug_malloc(size_t size_, const char *file, int line, uint64_t tag);
#define ZALLOC_OBJECT(object__, tag__) ZALLOC_TYPE_HAS_LINE(object__) ? zalloc_line(ZALLOC_TYPE_TO_LINE(object__), (tag__)) : debug_malloc(sizeof(object__), __FILE__, __LINE__, (tag__))
#define ZALLOC_BYTES(size__, tag__)    (ZALLOC_SIZE_HAS_LINE(size__) ? zalloc_line(ZALLOC_SIZE_TO_LINE(size__), (tag__)) : debug_malloc((size__), __FILE__, __LINE__, (tag__)))
#define ZFREE_BYTES(ptr__, size__)                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                          \
        if(ZALLOC_SIZE_HAS_LINE(size__))                                                                                                                                                                                                       \
            zfree_line((ptr__), ZALLOC_SIZE_TO_LINE(size__));                                                                                                                                                                                  \
        else                                                                                                                                                                                                                                   \
            debug_free((ptr__), __FILE__, __LINE__);                                                                                                                                                                                           \
    }
#else // DNSCORE_HAS_MALLOC_DEBUG_SUPPORT
#define ZALLOC_OBJECT(object__, tag__) ZALLOC_TYPE_HAS_LINE(object__) ? zalloc_line(ZALLOC_TYPE_TO_LINE(object__), (tag__)) : malloc(sizeof(object__))
#define ZALLOC_BYTES(size__, tag__)    (ZALLOC_SIZE_HAS_LINE(size__) ? zalloc_line(ZALLOC_SIZE_TO_LINE(size__), (tag__)) : malloc((size__)))
#define ZFREE_BYTES(ptr__, size__)                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                          \
        if(ZALLOC_SIZE_HAS_LINE(size__))                                                                                                                                                                                                       \
            zfree_line((ptr__), ZALLOC_SIZE_TO_LINE(size__));                                                                                                                                                                                  \
        else                                                                                                                                                                                                                                   \
            free((ptr__));                                                                                                                                                                                                                     \
    }
#endif // DNSCORE_HAS_MALLOC_DEBUG_SUPPORT

#define ZALLOC_ARRAY_OR_DIE(cast__, label__, size__, tag__)                                                                                                                                                                                    \
    if((label__ = (cast__)zalloc((size__), (tag__))) == NULL)                                                                                                                                                                                  \
    {                                                                                                                                                                                                                                          \
        DIE(ZALLOC_ERROR_OUTOFMEMORY);                                                                                                                                                                                                         \
    }                                                                                                                                                                                                                                          \
    assert((label__) != NULL)
// preferred way of allocating one instance of a type (struct, ...)
#define ZALLOC_OBJECT_OR_DIE(label__, object__, tag__)                                                                                                                                                                                         \
    if((label__ = (object__ *)ZALLOC_OBJECT(object__, (tag__))) == NULL)                                                                                                                                                                       \
    {                                                                                                                                                                                                                                          \
        DIE(ZALLOC_ERROR_OUTOFMEMORY);                                                                                                                                                                                                         \
    }                                                                                                                                                                                                                                          \
    assert((label__) != NULL)
#define ZALLOC_OBJECT_ARRAY_OR_DIE(label__, object__, count__, tag__)                                                                                                                                                                          \
    if((label__ = (object__ *)ZALLOC_BYTES(sizeof(object__) * (count__), (tag__))) == NULL)                                                                                                                                                    \
    {                                                                                                                                                                                                                                          \
        DIE(ZALLOC_ERROR_OUTOFMEMORY);                                                                                                                                                                                                         \
    }                                                                                                                                                                                                                                          \
    assert((label__) != NULL)
#else // HAS_ZALLOC_DEBUG_SUPPORT && DNSCORE_DEBUG_HAS_BLOCK_TAG
#define ZALLOC_OBJECT(object__, tag__) ZALLOC_TYPE_HAS_LINE(object__) ? zalloc_line(ZALLOC_TYPE_TO_LINE(object__)) : malloc(sizeof(object__))
#define ZALLOC_BYTES(size__, tag__)    (ZALLOC_SIZE_HAS_LINE(size__) ? zalloc_line(ZALLOC_SIZE_TO_LINE(size__)) : malloc((size__)))
#define ZFREE_BYTES(ptr__, size__)                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                          \
        if(ZALLOC_SIZE_HAS_LINE(size__))                                                                                                                                                                                                       \
            zfree_line((ptr__), ZALLOC_SIZE_TO_LINE(size__));                                                                                                                                                                                  \
        else                                                                                                                                                                                                                                   \
            free((ptr__));                                                                                                                                                                                                                     \
    }
#define ZALLOC_ARRAY_OR_DIE(cast, label, size_, tag__)                                                                                                                                                                                         \
    if((label = (cast)zalloc(size_)) == NULL)                                                                                                                                                                                                  \
    {                                                                                                                                                                                                                                          \
        DIE(ZALLOC_ERROR_OUTOFMEMORY);                                                                                                                                                                                                         \
    }                                                                                                                                                                                                                                          \
    assert((label) != NULL)
// preferred way of allocating one instance of a type (struct, ...)
#define ZALLOC_OBJECT_OR_DIE(label__, object__, tag__)                                                                                                                                                                                         \
    if((label__ = (object__ *)ZALLOC_OBJECT(object__, tag__)) == NULL)                                                                                                                                                                         \
    {                                                                                                                                                                                                                                          \
        DIE(ZALLOC_ERROR_OUTOFMEMORY);                                                                                                                                                                                                         \
    }                                                                                                                                                                                                                                          \
    assert((label__) != NULL)
#define ZALLOC_OBJECT_ARRAY_OR_DIE(label__, object__, count__, tag__)                                                                                                                                                                          \
    if((label__ = (object__ *)ZALLOC_BYTES(sizeof(object__) * (count__), (tag__))) == NULL)                                                                                                                                                    \
    {                                                                                                                                                                                                                                          \
        DIE(ZALLOC_ERROR_OUTOFMEMORY);                                                                                                                                                                                                         \
    }                                                                                                                                                                                                                                          \
    assert((label__) != NULL)
#endif

#define ZFREE(ptr, object__)                  ZALLOC_TYPE_HAS_LINE(object__) ? zfree_line(ptr, ZALLOC_TYPE_TO_LINE(object__)) : free(ptr)
#define ZFREE_ARRAY(ptr, size_)               zfree(ptr, size_)
#define ZFREE_OBJECT(label__)                 zfree((label__), sizeof(*(label__)))
#define ZFREE_OBJECT_OF_TYPE(label__, type__) zfree((label__), sizeof(type__))
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

#define ZALLOC_ARRAY_RESIZE_TAG               0x44455a49534552 /* RESIZED */

#define ZALLOC_ARRAY_RESIZE(type_, array_, count_, newcount_)                                                                                                                                                                                  \
    {                                                                                                                                                                                                                                          \
        uint32_t zalloc_new_count = (uint32_t)(newcount_);                                                                                                                                                                                     \
        if(((uint32_t)(count_)) != zalloc_new_count)                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                      \
            if(ZALLOC_SIZE_TO_PAGE(sizeof(type_) * ((uint32_t)(count_))) != ZALLOC_SIZE_TO_PAGE(sizeof(type_) * zalloc_new_count))                                                                                                             \
            {                                                                                                                                                                                                                                  \
                type_ *__tmp__;                                                                                                                                                                                                                \
                                                                                                                                                                                                                                               \
                if(zalloc_new_count > 0)                                                                                                                                                                                                       \
                {                                                                                                                                                                                                                              \
                    ZALLOC_ARRAY_OR_DIE(type_ *, __tmp__, sizeof(type_) * zalloc_new_count, ZALLOC_ARRAY_RESIZE_TAG);                                                                                                                          \
                    MEMCOPY(__tmp__, (array_), sizeof(type_) * MIN((uint32_t)(count_), zalloc_new_count));                                                                                                                                     \
                }                                                                                                                                                                                                                              \
                else                                                                                                                                                                                                                           \
                {                                                                                                                                                                                                                              \
                    __tmp__ = NULL;                                                                                                                                                                                                            \
                }                                                                                                                                                                                                                              \
                                                                                                                                                                                                                                               \
                ZFREE_ARRAY((array_), sizeof(type_) * ((uint32_t)(count_)));                                                                                                                                                                   \
                array_ = __tmp__;                                                                                                                                                                                                              \
                count_ = newcount_;                                                                                                                                                                                                            \
            }                                                                                                                                                                                                                                  \
        }                                                                                                                                                                                                                                      \
        assert(array_ != NULL);                                                                                                                                                                                                                \
    }

#endif

struct output_stream;
void zalloc_print_stats(struct output_stream_s *os);

#define MEMORY_POOL_BIN_COUNT 128

struct memory_pool_s
{
    void *bins[MEMORY_POOL_BIN_COUNT];
};

typedef struct memory_pool_s memory_pool_t;

static inline void           memory_pool_init(memory_pool_t *mp) { ZEROMEMORY(mp->bins, sizeof(mp->bins)); }

static inline void           memory_pool_finalize(memory_pool_t *mp)
{
    for(int_fast32_t i = 0; i < MEMORY_POOL_BIN_COUNT; ++i)
    {
        ZFREE_BYTES(mp->bins[i], i << 3);
    }
}

static inline void *memory_pool_alloc(memory_pool_t *mp, size_t size)
{
    void *ptr;
    size = (size + 7) & ~7;
    size_t index = size >> 3;
    if((index < MEMORY_POOL_BIN_COUNT) && (mp->bins[index] != NULL))
    {
        ptr = mp->bins[index];
        mp->bins[index] = *(void **)ptr;
    }
    else
    {
        ptr = ZALLOC_BYTES(size, GENERIC_TAG); // generic is fine
    }
    return ptr;
}

static inline void memory_pool_free(memory_pool_t *mp, void *ptr, size_t size)
{
    size = (size + 7) & ~7;
    size_t index = size >> 3;
    if((index < MEMORY_POOL_BIN_COUNT) && (mp->bins[index] == NULL))
    {
        *(void **)ptr = mp->bins[index];
        mp->bins[index] = ptr;
    }
    else
    {
        ZFREE_BYTES(ptr, size);
    }
}

#ifdef __cplusplus
}
#endif

/** @} */

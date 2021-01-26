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

/** @defgroup streaming Streams
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnscore/file.h>

#ifdef	__cplusplus
extern "C" {
#endif
    
#if !__BUFFERED_FILE_C__
struct buffered_file_cache_t_ { int dummy; };
typedef struct buffered_file_cache_t_* buffered_file_cache_t;
#endif

#define BUFFERED_FILE_CACHE_PAGE_SIZE_512    9
#define BUFFERED_FILE_CACHE_PAGE_SIZE_1K    10
#define BUFFERED_FILE_CACHE_PAGE_SIZE_4K    12
#define BUFFERED_FILE_CACHE_PAGE_SIZE_64K   16
#define BUFFERED_FILE_CACHE_PAGE_SIZE_1024K 20

/**
 * Creates a new instance of a cache meant to be used with a buffered_file.
 * The cache can be shared between several files and several cache can exist (depending on the needs)
 * 
 * @param name the name is only for logging/tracking/debugging
 * @param count the number of pages in the cache
 * @param log2_granularity the size of the page expressed as an exponent for 2 (e.g.: 12 means 2^12 = 4096 bytes) Values range 4 to 20.
 * @param use_mmap the buffer that will hold the pages can be mallocated or mmapped, depending on this boolean.
 * 
 * @return the cache handle or NULL if the operation failed (lack of resources)
 */

buffered_file_cache_t buffered_file_cache_new_instance(const char* name, u32 count, u8 log2_granularity, bool use_mmap);

/**
 * Releases the cache.
 * The cache will only be destroyed once all files using it are closed.
 * 
 * @param fc
 */

void buffered_file_cache_delete(buffered_file_cache_t fc);

/**
 * Creates a file that caches another.
 * 
 * @param fp a pointer to the file header
 * @param file_to_buffer the file to cache
 * @param fc the cache for this file
 * 
 * @return an error code
 */

ya_result buffered_file_init(file_t *fp, file_t file_to_buffer, buffered_file_cache_t fc);
        
#ifdef	__cplusplus
}
#endif

/** @} */

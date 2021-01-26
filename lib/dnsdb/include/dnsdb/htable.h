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

/** @defgroup dnsdbcollection Collections used by the database
 *  @ingroup dnsdb
 *  @brief Hash-Table structure and functions.
 *
 *  Implementation of the Hash-Table structure and functions.
 *  It can be configured to be thread-safe. (4 modes)
 *
 *  It is used in the hash-table of balanced trees structure. (htbt)
 *
 *  Mutex support has been removed the 2009/02/24.
 *
 * @{
 */
#ifndef _HTABLE_H
#define	_HTABLE_H

#define HTABLE_USE_MERSENE

#ifdef	__cplusplus
extern "C"
{
#endif

#define HTABLE_TAG 0x454c42415448 /* "HTABLE" */

typedef struct
{
    void* data; /* 4 or 8 bytes (32 or 64 bits systems)         */
} htable_entry; /* => 12 or 16 bytes (32 or 64 bits systems)    */

/** @brief Allocates an hash table of the pre-defined size
 *
 *  Allocates an hash table of the pre-defined size
 *
 *  @return A pointer to the htable or NULL if an error occurred
 */

htable_entry* htable_alloc();

/** @brief Frees an htable
 *
 *  Frees an htable
 *
 *  @param[in]  table a pointer to the htable to free
 *
 */

void htable_free(htable_entry* table);

#if defined(HTABLE_USE_MERSENE)

#define NOHASHTBL 0
#define MERSENE_1 3
#define MERSENE_2 7
#define MERSENE_3 31
#define MERSENE_4 127
#define MERSENE_5 8191
#define MERSENE_6 131071
#define MERSENE_7 524287
#define MERSENE_8 2147483647    /* This is, of course, not an option */

/* Given the statistics, MERSENE_7 is by far the best choice */

#define DEFAULT_HTABLE_SIZE (MERSENE_7+1)

/** @brief Retrieve the htable entry for a given hash
 *
 *  Retrieve the htable entry for a given hash.
 *  This version uses a bitmask with a mersene prime.
 *
 *  @param[in]  table a pointer to the htable
 *  @param[in]  hash the hash value to look for.
 *
 */

#define htable_get(table,hash) ((table)[(hash)&(DEFAULT_HTABLE_SIZE-1)])

#else /* MODULO */

/* 1061 1063 */
/* 10007 10009 */
#define DEFAULT_HTABLE_SIZE     10007

/** @brief Retrieve the htable entry for a given hash
 *
 *  Retrieve the htable entry for a given hash.
 *  This version uses a modulo with a prime.
 *
 *  @param[in]  table a pointer to the htable
 *  @param[in]  hash the hash value to look for.
 *
 */

#define htable_get(table,hash) ((table)[(hash)%DEFAULT_HTABLE_SIZE])

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _HTABLE_H */

/** @} */

/*----------------------------------------------------------------------------*/


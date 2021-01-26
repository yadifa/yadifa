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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to iterate through the labels of a zone
 *
 * @{
 */

#pragma once

#include <dnsdb/zdb_zone_label_iterator.h>
#if ZDB_HAS_NSEC3_SUPPORT
#include <dnsdb/nsec3_types.h>
#endif

#ifdef	__cplusplus
extern "C"
{
#endif

enum zdb_zone_label_iterator_ex_mode
{
    ZDB_ZONE_LABEL_ITERATOR_ZONE_RECORDS = 0,
    ZDB_ZONE_LABEL_ITERATOR_NSEC3_CHAIN = 1,
    ZDB_ZONE_LABEL_ITERATOR_END_OF_ITERATION = 2
};

struct zdb_zone_label_iterator_ex
{
    s32 mode;
    s32 min_ttl;
    const zdb_zone *zone;
    struct nsec3_zone *n3;
    u8 *pool;
    u8 *nsec3_owner;
    //zdb_packed_ttlrdata *nsec3_record;
    //zdb_packed_ttlrdata *nsec3_rrsig;
    zdb_rr_label nsec3_label;
    avl_node nsec3_label_nsec3;
    avl_node nsec3_label_rrsig;
    union
    {
        struct zdb_zone_label_iterator label_iter;
        struct nsec3_iterator nsec3_iter;
    } iter;
    u8 pool_buffer[TMP_NSEC3_TTLRDATA_SIZE];
};

typedef struct zdb_zone_label_iterator_ex zdb_zone_label_iterator_ex;

/**
 * @brief Initializes a zone label iterator that also iterates through NSEC3
 *
 * Initializes a zone label iterator (iterates zdb_rr_label)
 *
 * @param[in] iter a pointer to the iterator to initialise
 * @param[in] zone The zone to explore
 *
 */

void zdb_zone_label_iterator_ex_init(zdb_zone_label_iterator_ex* iter, const zdb_zone* zone);

/**
 * @brief Checks if there is still data available from an iterator
 *
 * Checks if there is still data available from an iterator
 *
 * @param[in] iter a pointer to the iterator
 *
 * @return TRUE if data is available, FALSE otherwise.
 *
 */

bool zdb_zone_label_iterator_ex_hasnext(zdb_zone_label_iterator_ex* iter);

/**
 * @brief Copies the full name of the next label returned by the "next" call.
 *
 * Copies the full name of the next label returned by the "next" call.
 *
 * CALL IT BEFORE USING zdb_zone_label_iterator_next
 *
 * @param[in] iter a pointer to the iterator
 * @param[in] buffer256 a pointer to a buffer that will hold the full dns name
 *
 * @return the size of the dns name
 *
 */

u32 zdb_zone_label_iterator_ex_nextname_to_cstr(zdb_zone_label_iterator_ex* iter, char* buffer256);
u32 zdb_zone_label_iterator_ex_nextname(zdb_zone_label_iterator_ex* iter, u8* buffer256);

/**
 * @brief Returns the next data available from an iterator
 *
 * Returns the next data available from an iterator
 *
 * @param[in] iter a pointer to the iterator
 *
 * @return a pointer to the next label
 *
 */

zdb_rr_label* zdb_zone_label_iterator_ex_next(zdb_zone_label_iterator_ex* iter);

#ifdef	__cplusplus
}
#endif

/** @} */

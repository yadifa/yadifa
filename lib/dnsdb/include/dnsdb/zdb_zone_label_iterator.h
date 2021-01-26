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

#ifndef _ZDB_ZONE_LABEL_ITERATOR_H
#define	_ZDB_ZONE_LABEL_ITERATOR_H

#include <dnsdb/zdb_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif

/**
 * @brief Initializes a zone label iterator
 *
 * Initializes a zone label iterator (iterates zdb_rr_label)
 *
 * @param[in] iter a pointer to the iterator to initialise
 * @param[in] zone The zone to explore
 *
 */

void zdb_zone_label_iterator_init(zdb_zone_label_iterator* iter, const zdb_zone* zone);

/**
 * @brief Initializes a zone label iterator from a given starting name
 *
 * Initializes a zone label iterator (iterates zdb_rr_label)
 *
 * @param[in] iter a pointer to the iterator to initialise
 * @param[in] zone The zone to explore
 * @param[in] from_name the first name the iterator should start from
 *
 */

void zdb_zone_label_iterator_init_from(zdb_zone_label_iterator* iter, const zdb_zone* zone, const u8 *from_name);
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

bool zdb_zone_label_iterator_hasnext(zdb_zone_label_iterator* iter);

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

u32 zdb_zone_label_iterator_nextname_to_cstr(zdb_zone_label_iterator* iter, char* buffer256);
u32 zdb_zone_label_iterator_nextname(zdb_zone_label_iterator* iter, u8* buffer256);

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

zdb_rr_label* zdb_zone_label_iterator_next(zdb_zone_label_iterator* iter);

#if ZDB_ZONE_LABEL_ITERATOR_CAN_SKIP_CHILDREN

/**
 * @brief Skips the children
 *
 * Skips the children
 *
 * @return
 *
 */

void zdb_zone_label_skip_children(zdb_zone_label_iterator* iter);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _ZDB_ITERATOR_H */

/** @} */

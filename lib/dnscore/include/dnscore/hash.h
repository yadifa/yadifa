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
 *  @brief Functions used to hash a dns formatted string
 *
 *  Implements the functions used to hash a dns formatted string.
 *  There functions require the call to an initialization function (hash_init);
 *
 * @{
 */
#ifndef _HASH_H
#define	_HASH_H

#include <dnscore/sys_types.h>

typedef u32 hashcode;

#include <dnscore/dnsname.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#define DNSCORE_HASH_TABLE_CHAR_SET_SIZE 37

extern const u32 DNSCORE_HASH_TABLE[256][DNSCORE_HASH_TABLE_CHAR_SET_SIZE];
extern const u32 DNSCORE_HASH_TABLE_MAP[256];
extern const u8* WILD_LABEL;
extern const hashcode WILD_HASH;

/** @brief Initializes the hash functions
 *
 *  Initializes the hash function.  This MUST be called at least one before
 *  calling any other hash function.
 *
 */

void hash_init();

/** @brief Compute the hash code of a dns name (concatenation of pascal strings ending with an empty one.)
 *
 *  Compute the hash code of a dns name (concatenation of pascal strings ending with an empty one.)
 *  The function hash_init() MUST be called once first. (This requirement will be lifted later)
 *
 *  @param[in]  dns_name the name in its DNS form
 *
 *  @return the hash code as a 32 bits integer
 */

hashcode hash_dnsname(const u8* dns_name);

/** @brief Compute the hash code of a dns label (one pascal string)
 *
 *  Compute the hash code of a dns name (a pascal string)
 *  The function hash_init() MUST be called once first.
 *
 *  This is one of the most-called functions in the ZDB.  Its speed is critical.
 *
 *  @param[in]  dns_name the name in its DNS form
 *
 *  @return the hash code as a 32 bits integer
 */

static inline hashcode hash_dnslabel(const u8 *dns_label)
{
    u32 len = *dns_label++;
    u32 hash = DNSCORE_HASH_TABLE[len][0];

    const u32 *hash_line = (const u32*) & DNSCORE_HASH_TABLE[1][0];
    const u8 * const limit = &dns_label[len];

    while(dns_label != limit)
    {
        hash += hash_line[DNSCORE_HASH_TABLE_MAP[*dns_label++]];
        hash_line += DNSCORE_HASH_TABLE_CHAR_SET_SIZE;
    }

    return hash;
}

/** @brief Compute the hash code of a pascal name
 *
 *  Compute the hash code of a pascal name.
 *  The function hash_init() MUST be called once first. (This requirement will be lifted later)
 *  An interesting thing about a dnsname label : it's a pascal string.
 *
 *  @param[in]  pascal_name the name in pascal form
 *
 *  @return the hash code as a 32 bits integer
 */

hashcode hash_pascalname(const u8* pascal_name);

/** @brief Compute the hash code of an asciiz name
 *
 *  Compute the hash code of a pascal name from its asciiz form.
 *  The function hash_init() MUST be called once first. (This requirement will be lifted later)
 *
 *  @param[in]  asciiz_name the name in asciiz form
 *
 *  @return the hash code as a 32 bits integer
 */

hashcode hash_asciizname(const char* asciiz_name);


/** @brief Compute the hash code of a char array
 *
 *  Compute the hash code of a pascal name from its asciiz form.
 *  The function hash_init() MUST be called once first. (This requirement will be lifted later)
 *
 *  @param[in]  ascii char array
 *  @param[in]  len number of chars in the array
 *
 *  @return the hash code as a 32 bits integer
 */

hashcode hash_chararray(const char* ascii, size_t len);

#ifdef	__cplusplus

#endif

#endif	/* _HASH_H */

/** @} */

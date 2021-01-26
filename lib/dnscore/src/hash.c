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
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnscore/dnscore-config.h"
#include <stdlib.h>
#include <string.h>
#include "dnscore/hash.h"

#define ZDBHTBL_TAG 0x4c42544842445a

/*
 * [-]
 * [0;9]
 * [a;z]
 *
 * [2D]
 * [30;38]
 * [61;7A]
 *
 */

/**
 *
 * ['0';'9'] + ['A'/'a';'Z'/'z'] + ['-'] = 37
 *
 */

#define DNSCORE_HASH_TABLE_CHAR_SET_SIZE 37

extern const u32 DNSCORE_HASH_TABLE[256][DNSCORE_HASH_TABLE_CHAR_SET_SIZE];

// start of generated tables

const u32 DNSCORE_HASH_TABLE_MAP[256] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x07, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x00, 0x06,
};

const hashcode WILD_HASH = 0xcf6798dc;

// end of generated tables

const u8* WILD_LABEL = (u8*)"\001*";

/** @brief Initializes the hash functions
 *
 *  Initializes the hash function
 */

void
hash_init()
{
    // nothing to do
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

hashcode
hash_pascalname(const u8* pascal_name)
{
    assert(pascal_name != NULL);

    u32 idx = 1; /* idx points into the HASH_TABLE */

    /* I could initialize it to a hiher value (ie: 255) and
     * decrease it instead of the current behaviour.
     * This would allow to put a cpu-cheap limit on the
     * amount of chars taken in account in the hash computation.
     */
    u32 len = *pascal_name++;

    u32 hash = DNSCORE_HASH_TABLE[len][0];

    while(len-- > 0)
    {
        hash += DNSCORE_HASH_TABLE[idx++][DNSCORE_HASH_TABLE_MAP[*pascal_name++]];
    }

    return hash;
}

/** @brief Compute the hash code of an asciiz name
 *
 *  Compute the hash code of a pascal name from its asciiz form.
 *  The function hash_init() MUST be called once first. (This requirement will be lifted later)
 *
 *  @param[in]  asciiz_name the name in asciiz form
 *
 *  @return the hash code as a 32 bits integer
 */

hashcode
hash_asciizname(const char* asciiz_name)
{
    assert(asciiz_name != NULL);

    u32 idx = 1; /* idx points into the HASH_TABLE */

    /* I could initialize it to a hiher value (ie: 255) and
     * decrease it instead of the current behaviour.
     * This would allow to put a cpu-cheap limit on the
     * amount of chars taken in account in the hash computation.
     */
    u32 len = (u32)strlen(asciiz_name);

    u32 hash = DNSCORE_HASH_TABLE[len][0];

    while(len-- > 0)
    {
        hash += DNSCORE_HASH_TABLE[idx++][DNSCORE_HASH_TABLE_MAP[(u8)(*asciiz_name++)]];
    }

    return hash;
}

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

hashcode
hash_chararray(const char* ascii, size_t len)
{
    assert(ascii != NULL);

    u32 idx = 1; /* idx points into the HASH_TABLE */

    /* I could initialize it to a hiher value (ie: 255) and
     * decrease it instead of the current behaviour.
     * This would allow to put a cpu-cheap limit on the
     * amount of chars taken in account in the hash computation.
     */

    u32 hash = DNSCORE_HASH_TABLE[len][0];

    while(len-- > 0)
    {
        hash += DNSCORE_HASH_TABLE[idx++][DNSCORE_HASH_TABLE_MAP[(u8)(*ascii++)]];
    }

    return hash;
}


/** @} */

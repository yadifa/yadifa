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
 * @defgroup dnsdbcollection Collections used by the database
 * @ingroup dnsdb
 * @brief Hash-Table structure and functions.
 *
 *  Implementation of the Hash-Table structure and functions.
 *  It can be configured to be thread-safe. (4 modes)
 *
 *  It is used in the hash-table of balanced trees structure. (htbt)
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnsdb/dnsdb_config.h"
#include <stdlib.h>
#include <stdio.h>
#include <dnscore/sys_types.h>
#include "dnsdb/htable.h"

/** @brief Allocates an hash table of the pre-defined size
 *
 *  Allocates an hash table of the pre-defined size
 *
 *  @return A pointer to the htable or NULL if an error occurred
 */

htable_entry *htable_alloc()
{
    htable_entry *table;

    MALLOC_OR_DIE(htable_entry *, table, sizeof(htable_entry) * DEFAULT_HTABLE_SIZE, HTABLE_TAG);

    uint32_t i;

    for(i = 0; i < DEFAULT_HTABLE_SIZE; i++)
    {
        table[i].data = NULL;
    }

    return table;
}

/** @brief Frees an htable
 *
 *  Frees an htable
 *
 *  @param[in]  table a pointer to the htable to free
 *
 */

void htable_free(htable_entry *table)
{
    yassert(table != NULL);

    free(table);
}

/** @} */

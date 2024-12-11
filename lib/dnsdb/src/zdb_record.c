/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @defgroup records Internal functions for the database: resource records.
 * @ingroup dnsdb
 * @brief Internal functions for the database: resource records.
 *
 *  Internal functions for the database: resource records.
 *
 *  Handling of the class->type->ttl+rdata list.
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <dnscore/format.h>
#include <dnscore/dnscore.h>

#include <arpa/inet.h>

#include "dnsdb/zdb_record.h"

#include "dnsdb/zdb_error.h"

#include "dnsdb/btree.h"

#if HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3_types.h"
#endif

#define TTLRDATA_TAG 0x41544144524c5454
#define ZDBRDATA_TAG 0x415441445242445a
#define TMPRDATA_TAG 0x4154414452504d54

/**
 * @brief Allocated and duplicates the content of the source
 */

zdb_ttlrdata *zdb_ttlrdata_clone(const zdb_ttlrdata *source)
{
    zdb_ttlrdata *rec;
    int           size = ((sizeof(zdb_ttlrdata) + 7) & ~7) + source->rdata_size;
    ZALLOC_ARRAY_OR_DIE(zdb_ttlrdata *, rec, size, TTLRDATA_TAG);
    rec->next = NULL;
    rec->ttl = source->ttl;
    rec->rdata_size = source->rdata_size;
    rec->rdata_pointer = &((uint8_t *)rec)[(sizeof(zdb_ttlrdata) + 7) & ~7];
    memcpy(rec->rdata_pointer, source->rdata_pointer, rec->rdata_size);

    return rec;
}

/**
 * @brief Allocated and duplicates the first bytes of content of the source
 * This is mostly used to clone an NSEC3 record into an NSEC3PARAM
 */

zdb_ttlrdata *zdb_ttlrdata_clone_resized(const zdb_ttlrdata *source, uint32_t rdata_newsize)
{
    zdb_ttlrdata *rec;
    int           size = ((sizeof(zdb_ttlrdata) + 7) & ~7) + rdata_newsize;
    ZALLOC_ARRAY_OR_DIE(zdb_ttlrdata *, rec, size, TTLRDATA_TAG);
    rec->next = NULL;
    rec->ttl = source->ttl;
    rec->rdata_size = rdata_newsize;
    rec->rdata_pointer = &((uint8_t *)rec)[(sizeof(zdb_ttlrdata) + 7) & ~7];
    memcpy(rec->rdata_pointer, source->rdata_pointer, rec->rdata_size);

    return rec;
}

/**
 * @brief Frees the content of the source
 */
void zdb_ttlrdata_delete(zdb_ttlrdata *record)
{
    int size = ((sizeof(zdb_ttlrdata) + 7) & ~7) + record->rdata_size;
    ZFREE_ARRAY(record, size);
    (void)size; // silences warning in some builds setups
}

/** @} */

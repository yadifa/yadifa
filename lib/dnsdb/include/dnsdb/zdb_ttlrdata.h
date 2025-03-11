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
 * @defgroup types The types used in the database
 * @ingroup dnsdb
 * @brief The types used in the database
 *
 * The types used in the database
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnsdb/zdb_config_features.h>

#include <dnscore/sys_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define ZDB_RDATABUF_TAG                  0x4655424154414452
#define ZDB_RECORD_TAG                    0x4443455242445a /** "ZDBRECD" */

#define ZDB_RECORD_PTR_RDATASIZE(record_) ((record_)->rdata_size)
#define ZDB_RECORD_PTR_RDATAPTR(record_)  ((record_)->rdata_pointer)

struct zdb_ttlrdata
{
    struct zdb_ttlrdata *next;       /*  4  8 */
    uint32_t             ttl;        /*  4  4 */
    uint16_t             rdata_size; /*  2  2 */
    uint16_t             padding_reserved;
    void                *rdata_pointer; /*  4  8 */
};

typedef struct zdb_ttlrdata zdb_ttlrdata;

typedef zdb_ttlrdata      **zdb_ttlrdata_pointer_array;

#define ZDB_RECORD_RDATADESC(type_, ttlrdata_) {(type_), ZDB_RECORD_PTR_RDATASIZE(ttlrdata_), ZDB_RECORD_PTR_RDATAPTR(ttlrdata_)}

#ifdef __cplusplus
}
#endif

/** @} */

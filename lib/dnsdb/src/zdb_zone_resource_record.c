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

int zdb_resource_record_data_compare_records(const zdb_resource_record_data_t *rr0, const zdb_resource_record_data_t *rr1)
{
    int s0 = zdb_resource_record_data_rdata_size(rr0);
    int s1 = zdb_resource_record_data_rdata_size(rr1);
    int s = MIN(s0, s1);
    int d;

    if(s > 0)
    {
        d = memcmp(zdb_resource_record_data_rdata_const(rr0), zdb_resource_record_data_rdata_const(rr1), s);
        if(d == 0)
        {
            d = s0 - s1;
        }
    }
    else
    {
        d = s0 - s1;
    }

    return d;
}

/** @brief Checks if two records are equal.
 *
 *  Checks if two records are equal.
 *
 *  @return true if the records are equal, false otherwise.
 */

bool zdb_record_equals_unpacked(const zdb_resource_record_data_t *a, const zdb_ttlrdata *b)
{
    int  len;
    bool ret = false;

    /* The TTL is irrelevant for matches */

    if((len = zdb_resource_record_data_rdata_size(a)) == ZDB_RECORD_PTR_RDATASIZE(b))
    {
        if(memcmp(zdb_resource_record_data_rdata_const(a), ZDB_RECORD_PTR_RDATAPTR(b), len) == 0)
        {
            ret = true;
        }
    }

    return ret;
}

/** @brief Checks if two records are equal.
 *
 *  Checks if two records are equal.
 *
 *  @return true if the records are equal, false otherwise.
 */

bool zdb_record_equals(const zdb_resource_record_data_t *a, const zdb_resource_record_data_t *b)
{
    int  len;
    bool ret = false;

    /* The TTL is irrelevant for matches */

    if((len = zdb_resource_record_data_rdata_size(a)) == zdb_resource_record_data_rdata_size(b))
    {
        if(memcmp(zdb_resource_record_data_rdata_const(a), zdb_resource_record_data_rdata_const(b), len) == 0)
        {
            ret = true;
        }
    }

    return ret;
}

/**
 * @brief Copies the soa rdata to an soa_rdata native structure.
 *
 * Copies the soa of a zone to an soa_rdata structure.
 * No memory is allocated for the soa_rdata.  If the zone is destroyed,
 * the soa_rdata becomes invalid.
 *
 * @param[in] zone a pointer to the zone
 * @param[out] soa_out a pointer to an soa_rdata structure
 */

ya_result zdb_record_getsoa(const zdb_resource_record_data_t *soa, zdb_soa_rdata_t *soa_out)
{
    int32_t        soa_size = zdb_resource_record_data_rdata_size(soa);

    const uint8_t *soa_start = soa->_rdata_start;
    soa_out->mname = soa_start;

    uint32_t len = dnsname_len(soa_start);

    soa_size -= len;

    if(soa_size <= 0)
    {
        return ZDB_ERROR_CORRUPTEDSOA;
    }

    soa_start += len;
    soa_out->rname = soa_start;

    len = dnsname_len(soa_start);

    soa_size -= len;
    if(soa_size != 5 * 4) /* Only the 5 32 bits (should) remain */
    {
        return ZDB_ERROR_CORRUPTEDSOA;
    }

    soa_start += len;

    soa_out->serial = ntohl(GET_U32_AT(*soa_start));
    soa_start += 4;
    soa_out->refresh = ntohl(GET_U32_AT(*soa_start));
    soa_start += 4;
    soa_out->retry = ntohl(GET_U32_AT(*soa_start));
    soa_start += 4;
    soa_out->expire = ntohl(GET_U32_AT(*soa_start));
    soa_start += 4;
    soa_out->minimum = ntohl(GET_U32_AT(*soa_start));
    // soa_start += 4;

    return SUCCESS;
}

/** @} */
